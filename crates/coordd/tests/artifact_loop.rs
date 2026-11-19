#![cfg(unix)]

//! Full artifact chain: scheduled recon spools a file, agent uploads it,
//! coordinator stores and lists it.

use std::{
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::OnceLock,
    time::{Duration, Instant},
};

use coordd::Coord;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tempfile::TempDir;

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn build(crate_name: &str, binary: &str) -> PathBuf {
    static AGENT: OnceLock<PathBuf> = OnceLock::new();
    static ADMIN: OnceLock<PathBuf> = OnceLock::new();
    static RELAY: OnceLock<PathBuf> = OnceLock::new();
    let cell = match binary {
        "agentd" => &AGENT,
        "adminctl" => &ADMIN,
        _ => &RELAY,
    };
    cell.get_or_init(|| {
        let status = Command::new(env!("CARGO"))
            .args(["build", "-p", crate_name])
            .current_dir(workspace())
            .status()
            .expect("cargo runs");
        assert!(status.success(), "{crate_name} builds");
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

#[test]
fn scheduled_recon_artifact_reaches_the_coordinator() {
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
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if reqwest::blocking::get(format!("{url}/health")).is_ok_and(|r| r.status().is_success()) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Coordinator and artifact server.
    let coord_state = TempDir::new().unwrap();
    let signing = SigningKey::generate(&mut OsRng);
    fs::write(coord_state.path().join("agent.key"), signing.to_bytes()).unwrap();
    fs::write(coord_state.path().join("enc.key"), [5_u8; 32]).unwrap();
    fs::write(
        coord_state.path().join("relays.conf"),
        format!("0:0:relay:{url}\n"),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let artifact_url = format!("http://{}", listener.local_addr().unwrap());
    let artifact_state = coord_state.path().to_path_buf();
    std::thread::spawn(move || {
        coordd::artifact::serve_listener(listener, artifact_state, Some("tok".into()));
    });
    let mut coord = Coord::open(coord_state.path()).unwrap();

    // A file for recon to collect.
    let tree = root.path().join("tree");
    fs::create_dir_all(&tree).unwrap();
    fs::write(tree.join(".env"), b"API_KEY=xyz").unwrap();

    // Agent state with recon installed and artifact upload configured.
    let agent_state = root.path().join("agent");
    fs::create_dir_all(&agent_state).unwrap();
    let agent_key = SigningKey::generate(&mut OsRng);
    fs::write(agent_state.join("agent.key"), agent_key.to_bytes()).unwrap();
    fs::write(agent_state.join("enc.key"), [5_u8; 32]).unwrap();
    fs::write(
        agent_state.join("coordinator.pub"),
        signing.verifying_key().as_bytes(),
    )
    .unwrap();
    fs::write(
        agent_state.join("config.toml"),
        format!(
            "poll_interval_s = 1\nchannel = \"relay\"\nchannel_arg = \"{url}\"\nallow_exec = true\nallow_net = true\nartifact_url = \"{artifact_url}\"\nartifact_token = \"tok\"\nallow_caps.fs_read = [\"{}*\"]\nallow_caps.spool = [\"{}*\"]\nallow_caps.exec = [\"*\"]\nallow_caps.env = [\"OS\"]\nallow_caps.net = [\"http*://*\"]\n",
            tree.display(),
            tree.display()
        ),
    )
    .unwrap();
    let recon = workspace()
        .join("target/test-mods/abi2-target/wasm32-unknown-unknown/release/mod_recon.wasm");
    if !recon.is_file() {
        let status = Command::new(env!("CARGO"))
            .args([
                "build",
                "--release",
                "--target",
                "wasm32-unknown-unknown",
                "--manifest-path",
                "mods/recon/Cargo.toml",
                "--target-dir",
            ])
            .arg(workspace().join("target/test-mods/abi2-target"))
            .current_dir(workspace())
            .status()
            .unwrap();
        assert!(status.success());
    }
    let caps = [
        format!("fs_read:{}*", tree.display()),
        format!("spool:{}*", tree.display()),
        "exec:*".into(),
        "env:OS".into(),
        "net:http*://*".into(),
    ];
    let mut install = Command::new(build("adminctl", "adminctl"));
    install
        .arg("--state")
        .arg(&agent_state)
        .args(["mod", "add", "recon.mod", "1"])
        .arg(&recon)
        .args(["--abi", "2"]);
    for cap in &caps {
        install.arg("--cap").arg(cap);
    }
    let installed = install.output().unwrap();
    assert!(
        installed.status.success(),
        "{}",
        String::from_utf8_lossy(&installed.stderr)
    );

    let _agent = Process(
        Command::new(build("agentd", "agentd"))
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

    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let _ = coord.pull_once();
        if !coord.database().agents().unwrap().is_empty() {
            break;
        }
        assert!(Instant::now() < deadline, "no heartbeat");
        std::thread::sleep(Duration::from_millis(100));
    }
    let tag = coord.database().agents().unwrap()[0].route_tag.clone();
    coord
        .database()
        .add_schedule(
            &tag,
            "recon.mod",
            "1",
            &format!("{{\"roots\":[{}]}}", serde_json::json!(tree)),
            60,
            0,
            0,
        )
        .unwrap();
    assert_eq!(coord.tick(coordd::unix_now()).unwrap(), 1);

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let _ = coord.pull_once();
        if !coord.database().artifacts().unwrap().is_empty() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no artifact; log:\n{}",
            fs::read_to_string(agent_state.join("agentd.log")).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let artifact = &coord.database().artifacts().unwrap()[0];
    assert!(artifact.path.ends_with(".env"), "{}", artifact.path);
    let stored = coord_state.path().join("artifacts").join(&artifact.stored);
    let key = coordd::artifact::load_key(coord_state.path()).unwrap();
    assert_eq!(
        coordd::artifact::read_encrypted(&stored, &key).unwrap(),
        b"API_KEY=xyz"
    );
    // The agent deleted its spool row after the ack.
    let spool = agent_state.join("spool.db");
    if spool.is_file() {
        let connection = rusqlite::Connection::open(spool).unwrap();
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM artifacts", [], |row| row.get(0))
            .unwrap_or(0);
        assert_eq!(count, 0);
    }
}
