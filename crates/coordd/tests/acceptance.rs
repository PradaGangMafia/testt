//! Coordinator acceptance: heartbeat discovery, result ingest, scheduling.

use std::{
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::OnceLock,
    time::{Duration, Instant},
};

use coordd::Coord;
use ed25519_dalek::{SigningKey, VerifyingKey};
use msgfmt::{encode_heartbeat, encode_result, Heartbeat, ResultMessage};
use rand::rngs::OsRng;
use tempfile::TempDir;

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn relayd() -> PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let status = Command::new(env!("CARGO"))
            .args(["build", "-p", "relayd"])
            .current_dir(workspace())
            .status()
            .expect("cargo runs");
        assert!(status.success(), "relayd builds");
        workspace().join("target/debug/relayd")
    })
    .clone()
}

struct Relay {
    child: Child,
    url: String,
    _root: TempDir,
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_relay() -> Relay {
    let root = TempDir::new().unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let child = Command::new(relayd())
        .arg("--bind")
        .arg(format!("127.0.0.1:{port}"))
        .arg(root.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("relay starts");
    let url = format!("http://127.0.0.1:{port}");
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if reqwest::blocking::get(format!("{url}/health")).is_ok_and(|r| r.status().is_success()) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Relay {
        child,
        url,
        _root: root,
    }
}

fn coordinator(relay: &Relay) -> (TempDir, Coord) {
    let state = TempDir::new().unwrap();
    let signing = SigningKey::generate(&mut OsRng);
    fs::write(state.path().join("agent.key"), signing.to_bytes()).unwrap();
    fs::write(state.path().join("enc.key"), [9_u8; 32]).unwrap();
    fs::write(
        state.path().join("relays.conf"),
        format!("0:0:relay:{}\n", relay.url),
    )
    .unwrap();
    let coord = Coord::open(state.path()).unwrap();
    (state, coord)
}

fn put(url: &str, bytes: &[u8]) {
    let status = reqwest::blocking::Client::new()
        .post(format!("{url}/put"))
        .body(bytes.to_vec())
        .send()
        .unwrap()
        .status();
    assert!(status.is_success(), "{status}");
}

#[test]
fn heartbeat_registers_an_agent() {
    let relay = start_relay();
    let (_state, mut coord) = coordinator(&relay);
    let agent = SigningKey::generate(&mut OsRng);
    let heartbeat = Heartbeat {
        agent_pub: *agent.verifying_key().as_bytes(),
        host: "unit-host".into(),
        version: "0.1.0".into(),
        poll_interval_s: 60,
        enc_key: [9_u8; 32],
        epoch: 1,
    };
    let frame = encode_heartbeat(&heartbeat, &msgfmt::BOOTSTRAP_ENC_KEY, &agent).unwrap();
    put(&relay.url, &frame);
    let report = coord.pull_once().unwrap();
    assert_eq!(report.heartbeats, 1);
    let agents = coord.database().agents().unwrap();
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].agent_pub, heartbeat.agent_pub.to_vec());
    assert!(!agents[0].revoked);
    // The cursor advanced, so a second pull does not duplicate.
    assert_eq!(coord.pull_once().unwrap().seen, 0);
}

#[test]
fn result_is_ingested_and_findings_extracted() {
    let relay = start_relay();
    let (_state, mut coord) = coordinator(&relay);
    let agent = SigningKey::generate(&mut OsRng);
    let finding = r#"{"findings":[{"kind":"inventory","dedupe_key":"recon:/etc/hostname","severity":1,"data":{"path":"/etc/hostname"}}]}"#;
    let result = ResultMessage {
        task_epoch: 7,
        agent_pub: *agent.verifying_key().as_bytes(),
        ok: true,
        stdout: finding.into(),
        stderr: String::new(),
        code: 0,
    };
    // Register the per-agent key with a heartbeat first.
    let heartbeat = Heartbeat {
        agent_pub: *agent.verifying_key().as_bytes(),
        host: "h".into(),
        version: "1".into(),
        poll_interval_s: 60,
        enc_key: [9_u8; 32],
        epoch: 1,
    };
    put(
        &relay.url,
        &encode_heartbeat(&heartbeat, &msgfmt::BOOTSTRAP_ENC_KEY, &agent).unwrap(),
    );
    let frame = encode_result(&result, &[9_u8; 32], &agent).unwrap();
    put(&relay.url, &frame);
    let report = coord.pull_once().unwrap();
    assert_eq!(report.results, 1, "{report:?}");
    let stats = coord.database().stats().unwrap();
    assert_eq!(stats.results, 1);
    assert_eq!(stats.findings, 1);
    // Replayed/duplicate frames are no-ops.
    put(&relay.url, &frame);
    coord.pull_once().unwrap();
    assert_eq!(coord.database().stats().unwrap().findings, 1);
}

#[test]
fn schedule_pushes_a_task_and_respects_revocation() {
    let relay = start_relay();
    let (_state, mut coord) = coordinator(&relay);
    let agent = SigningKey::generate(&mut OsRng);
    let tag = msgfmt::route_tag_from_key(agent.verifying_key().as_bytes());
    coord
        .database()
        .upsert_agent(
            agent.verifying_key().as_bytes(),
            &tag,
            "h",
            "1",
            &[9_u8; 32],
        )
        .unwrap();
    let id = coord
        .database()
        .add_schedule(
            &tag,
            "recon.mod",
            "0.1.0",
            "{\"roots\":[\"/etc\"]}",
            60,
            0,
            0,
        )
        .unwrap();
    assert_eq!(coord.tick(coordd::unix_now()).unwrap(), 1);
    let schedule = &coord.database().schedules().unwrap()[0];
    assert!(schedule.next_at > coordd::unix_now());
    assert_eq!(schedule.id, id);

    // The pushed frame decodes as a task for the agent.
    let text = reqwest::blocking::get(format!("{}/list?since=0", relay.url))
        .unwrap()
        .text()
        .unwrap();
    let frames = transport::parse_list(&text).unwrap();
    assert_eq!(frames.len(), 1);
    let public = VerifyingKey::from_bytes(&coord.public_key()).unwrap();
    let task = msgfmt::decode_checked(&frames[0].1, &public, &[9_u8; 32], &mut 0).unwrap();
    match task.task.body {
        msgfmt::TaskBody::Mod {
            mod_id, version, ..
        } => {
            assert_eq!(mod_id, "recon.mod");
            assert_eq!(version, "0.1.0");
        }
        other => panic!("expected a module task: {other:?}"),
    }

    // Revoked agents are skipped.
    coord.database().set_revoked(&tag, true).unwrap();
    coord.database().schedule_next(id, 0).unwrap();
    assert_eq!(coord.tick(coordd::unix_now()).unwrap(), 0);
}

#[test]
fn relay_publish_sends_a_signed_set_to_each_agent() {
    let relay = start_relay();
    let (state, coord) = coordinator(&relay);
    let agent = SigningKey::generate(&mut OsRng);
    let tag = msgfmt::route_tag_from_key(agent.verifying_key().as_bytes());
    coord
        .database()
        .upsert_agent(
            agent.verifying_key().as_bytes(),
            &tag,
            "h",
            "1",
            &[9_u8; 32],
        )
        .unwrap();
    fs::write(
        state.path().join("relays.conf"),
        format!(
            "0:0:relay:{}\n0:0:relay:https://backup.example\n",
            relay.url
        ),
    )
    .unwrap();
    let coordinator_pub = VerifyingKey::from_bytes(&coord.public_key()).unwrap();
    drop(coord);
    let output = Command::new(env!("CARGO_BIN_EXE_coordctl"))
        .arg("--state")
        .arg(state.path())
        .args(["relay", "publish"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = reqwest::blocking::get(format!("{}/list?since=0", relay.url))
        .unwrap()
        .text()
        .unwrap();
    let frames = transport::parse_list(&text).unwrap();
    assert_eq!(frames.len(), 1);
    let mut epoch = 0;
    // Relay sets are signed by the coordinator, not the agent.
    let state_key = SigningKey::from_bytes(
        &fs::read(state.path().join("agent.key"))
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(state_key.verifying_key(), coordinator_pub);
    let decoded = msgfmt::decode_relay_set(
        &frames[0].1,
        &state_key.verifying_key(),
        &[9_u8; 32],
        &mut epoch,
    )
    .unwrap();
    assert!(decoded
        .relay_set
        .add
        .iter()
        .any(|entry| entry.addr == "https://backup.example"));
}

#[test]
fn coordctl_lists_agents() {
    let relay = start_relay();
    let (state, mut coord) = coordinator(&relay);
    let agent = SigningKey::generate(&mut OsRng);
    let heartbeat = Heartbeat {
        agent_pub: *agent.verifying_key().as_bytes(),
        host: "listed".into(),
        version: "0.1.0".into(),
        poll_interval_s: 60,
        enc_key: [9_u8; 32],
        epoch: 1,
    };
    put(
        &relay.url,
        &encode_heartbeat(&heartbeat, &msgfmt::BOOTSTRAP_ENC_KEY, &agent).unwrap(),
    );
    coord.pull_once().unwrap();
    drop(coord);
    let output = Command::new(env!("CARGO_BIN_EXE_coordctl"))
        .arg("--state")
        .arg(state.path())
        .arg("agents")
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("last_seen="), "{text}");
}
