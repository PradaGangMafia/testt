#![cfg(unix)]

//! Coordinator key rotation and binary upgrade against a live agent copy.

use std::{
    fs,
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::OnceLock,
    time::{Duration, Instant},
};

use coordd::Coord;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use sha2::Digest;
use tempfile::TempDir;

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn build(crate_name: &str, binary: &str) -> PathBuf {
    static AGENT: OnceLock<PathBuf> = OnceLock::new();
    static ADMIN: OnceLock<PathBuf> = OnceLock::new();
    static RELAY: OnceLock<PathBuf> = OnceLock::new();
    static CTL: OnceLock<PathBuf> = OnceLock::new();
    let cell = match binary {
        "agentd" => &AGENT,
        "adminctl" => &ADMIN,
        "coordctl" => &CTL,
        _ => &RELAY,
    };
    cell.get_or_init(|| {
        let package = if crate_name == "coordctl" {
            "coordd"
        } else {
            crate_name
        };
        // Several test binaries may build at once; retry on lock contention.
        let mut result = None;
        for _ in 0..3 {
            let output = Command::new(env!("CARGO"))
                .args(["build", "-p", package])
                .current_dir(workspace())
                .output()
                .expect("cargo runs");
            if output.status.success() {
                result = Some(output);
                break;
            }
            result = Some(output);
            std::thread::sleep(std::time::Duration::from_millis(750));
        }
        let output = result.expect("cargo ran");
        assert!(
            output.status.success(),
            "{crate_name} builds: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        workspace().join(format!("target/debug/{binary}"))
    })
    .clone()
}

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool, label: &str) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if condition() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("timed out: {label}");
}

#[test]
fn rotation_and_upgrade_reach_a_live_agent() {
    let root = TempDir::new().unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let relay_root = TempDir::new().unwrap();
    let url = format!("http://127.0.0.1:{port}");
    let _relay = Process(
        Command::new(build("relayd", "relayd"))
            .arg("--bind")
            .arg(format!("127.0.0.1:{port}"))
            .arg(relay_root.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("relay"),
    );
    wait_until(
        Duration::from_secs(10),
        || reqwest::blocking::get(format!("{url}/health")).is_ok_and(|r| r.status().is_success()),
        "relay health",
    );

    // Coordinator keys and relay.
    let coord_state = TempDir::new().unwrap();
    let signing = SigningKey::generate(&mut OsRng);
    let old_pub = *signing.verifying_key().as_bytes();
    fs::write(coord_state.path().join("agent.key"), signing.to_bytes()).unwrap();
    fs::write(coord_state.path().join("enc.key"), [6_u8; 32]).unwrap();
    fs::write(
        coord_state.path().join("relays.conf"),
        format!("0:0:relay:{url}\n"),
    )
    .unwrap();
    let mut coord = Coord::open(coord_state.path()).unwrap();

    // Agent runs from a copy so the upgrade can replace it.
    let agent_binary = root.path().join("agentd");
    fs::copy(build("agentd", "agentd"), &agent_binary).unwrap();
    fs::set_permissions(&agent_binary, fs::Permissions::from_mode(0o755)).unwrap();
    let agent_state = root.path().join("agent");
    fs::create_dir_all(&agent_state).unwrap();
    let agent_key = SigningKey::generate(&mut OsRng);
    fs::write(agent_state.join("agent.key"), agent_key.to_bytes()).unwrap();
    fs::write(agent_state.join("enc.key"), [6_u8; 32]).unwrap();
    fs::write(agent_state.join("coordinator.pub"), old_pub).unwrap();
    fs::write(
        agent_state.join("config.toml"),
        format!("poll_interval_s = 1\nchannel = \"relay\"\nchannel_arg = \"{url}\"\n"),
    )
    .unwrap();
    let fixture = workspace().join("tests/fixtures/hello.wasm");
    let installed = Command::new(build("adminctl", "adminctl"))
        .arg("--state")
        .arg(&agent_state)
        .args(["mod", "add", "hello", "1"])
        .arg(fixture)
        .args(["--abi", "1"])
        .output()
        .unwrap();
    assert!(
        installed.status.success(),
        "{}",
        String::from_utf8_lossy(&installed.stderr)
    );
    let _agent = Process(
        Command::new(&agent_binary)
            .arg("--worker")
            .arg("--state")
            .arg(&agent_state)
            .env("AGENT_FLEET_REPLICA_ROOTS", root.path().join("replicas"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("agent"),
    );
    wait_until(
        Duration::from_secs(40),
        || {
            let _ = coord.pull_once();
            coord.database().agents().unwrap().len() == 1
        },
        "heartbeat",
    );

    // Rotate: the coordinator CLI pushes a new key, the agent adopts it.
    let rotated = Command::new(build("coordctl", "coordctl"))
        .arg("--state")
        .arg(coord_state.path())
        .arg("rotate")
        .output()
        .unwrap();
    assert!(
        rotated.status.success(),
        "{}",
        String::from_utf8_lossy(&rotated.stderr)
    );
    wait_until(
        Duration::from_secs(40),
        || fs::read(agent_state.join("coordinator.pub")).unwrap_or_default() != old_pub,
        "rotation adoption",
    );
    let new_pub = fs::read(agent_state.join("coordinator.pub")).unwrap();
    assert_ne!(new_pub, old_pub);
    assert_eq!(new_pub.len(), 32);

    // A task signed by the new coordinator key is still accepted.
    drop(coord);
    let mut coord = Coord::open(coord_state.path()).unwrap();
    let tag = coord.database().agents().unwrap()[0].route_tag.clone();
    coord
        .database()
        .add_schedule(&tag, "hello", "1", "{}", 60, 0, 0)
        .unwrap();
    assert_eq!(coord.tick(coordd::unix_now()).unwrap(), 1);
    wait_until(
        Duration::from_secs(40),
        || {
            let _ = coord.pull_once();
            coord.database().stats().unwrap().results > 0
        },
        "result under the new key",
    );

    // Upgrade: serve bytes, push, and expect the running copy replaced.
    let body = b"#!/bin/sh\necho upgraded\n".to_vec();
    let sha: [u8; 32] = sha2::Sha256::digest(&body).into();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let file_url = format!("http://{}/agentd", listener.local_addr().unwrap());
    let served = body.clone();
    std::thread::spawn(move || {
        use std::io::Write;
        // Several retries may arrive; serve each on a fresh connection.
        for _ in 0..16 {
            let Ok((mut socket, _)) = listener.accept() else {
                return;
            };
            let mut buffer = [0_u8; 2048];
            let _ = std::io::Read::read(&mut socket, &mut buffer);
            let _ = write!(
                socket,
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                served.len()
            );
            let _ = socket.write_all(&served);
        }
    });
    // hello has no caps; the agent must not need them for the upgrade frame.
    let upgraded = Command::new(build("coordctl", "coordctl"))
        .arg("--state")
        .arg(coord_state.path())
        .args(["upgrade"])
        .arg({
            let path = root.path().join("upgrade.bin");
            fs::write(&path, &body).unwrap();
            path
        })
        .arg("--url")
        .arg(&file_url)
        .arg("--version")
        .arg("9.9.9")
        .output()
        .unwrap();
    assert!(
        upgraded.status.success(),
        "{}",
        String::from_utf8_lossy(&upgraded.stderr)
    );
    let _ = sha;
    let deadline = Instant::now() + Duration::from_secs(40);
    while fs::read(&agent_binary).unwrap_or_default() != body {
        if Instant::now() >= deadline {
            panic!(
                "binary replacement; files={:?} upgrade_state={:?} log=\n{}",
                fs::read_dir(&root).map(|entries| entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.file_name())
                    .collect::<Vec<_>>()),
                fs::read_to_string(agent_state.join("upgrade.state")),
                fs::read_to_string(agent_state.join("agentd.log")).unwrap_or_default()
                    + &fs::read_to_string(agent_state.join("errors.log")).unwrap_or_default()
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
