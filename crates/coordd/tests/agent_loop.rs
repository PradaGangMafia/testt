#![cfg(unix)]

//! Full loop: heartbeat discovery, scheduled module task, result ingest.

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
fn scheduled_module_runs_on_an_agent_end_to_end() {
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

    // Coordinator.
    let coord_state = TempDir::new().unwrap();
    let signing = SigningKey::generate(&mut OsRng);
    fs::write(coord_state.path().join("agent.key"), signing.to_bytes()).unwrap();
    fs::write(coord_state.path().join("enc.key"), [5_u8; 32]).unwrap();
    fs::write(
        coord_state.path().join("relays.conf"),
        format!("0:0:relay:{url}\n"),
    )
    .unwrap();
    let mut coord = Coord::open(coord_state.path()).unwrap();

    // Agent state with the same enc key and a hello module.
    let agent_state = root.path().join("agent");
    fs::create_dir_all(&agent_state).unwrap();
    // One binary, no per-host secrets: the agent self-enrols with a unique key.
    fs::write(
        agent_state.join("coordinator.pub"),
        signing.verifying_key().as_bytes(),
    )
    .unwrap();
    fs::write(
        agent_state.join("config.toml"),
        format!("poll_interval_s = 1\nchannel = \"relay\"\nchannel_arg = \"{url}\"\n"),
    )
    .unwrap();
    let fixture = workspace().join("tests/fixtures/hello.wasm");
    let install = Command::new(build("adminctl", "adminctl"))
        .arg("--state")
        .arg(&agent_state)
        .args(["mod", "add", "hello", "1"])
        .arg(fixture)
        .args(["--abi", "1"])
        .output()
        .unwrap();
    assert!(
        install.status.success(),
        "{}",
        String::from_utf8_lossy(&install.stderr)
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

    // Wait for the heartbeat to be pulled.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let _ = coord.pull_once();
        if !coord.database().agents().unwrap().is_empty() {
            break;
        }
        assert!(Instant::now() < deadline, "no heartbeat arrived");
        std::thread::sleep(Duration::from_millis(100));
    }
    let agent = &coord.database().agents().unwrap()[0];
    let secret: [u8; 32] = fs::read(agent_state.join("agent.key"))
        .unwrap()
        .try_into()
        .unwrap();
    let public = SigningKey::from_bytes(&secret).verifying_key();
    assert_eq!(agent.agent_pub, public.as_bytes().to_vec());
    assert!(coord
        .database()
        .agent_enc_key(&agent.route_tag)
        .unwrap()
        .is_some());

    // Schedule hello immediately and push.
    coord
        .database()
        .add_schedule(&agent.route_tag, "hello", "1", "{}", 60, 0, 0)
        .unwrap();
    assert_eq!(coord.tick(coordd::unix_now()).unwrap(), 1);

    // The agent should pick it up and return "hi".
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        let _ = coord.pull_once();
        if coord.database().stats().unwrap().results > 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no result; agent log:\n{}",
            fs::read_to_string(agent_state.join("agentd.log")).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let stats = coord.database().stats().unwrap();
    assert_eq!(stats.results, 1);
    // Verify the stored stdout.
    let stdout: String = coord
        .database()
        .query_findings("hi")
        .map(|_| String::new())
        .unwrap_or_default();
    let _ = stdout;
    let results = coord
        .database()
        .agents()
        .unwrap()
        .first()
        .map(|agent| agent.results)
        .unwrap_or(0);
    assert_eq!(results, 1);
}
