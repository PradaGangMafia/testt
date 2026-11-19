//! P52 lifecycle acceptance: drain, in-flight work, and process-group kill.

#![cfg(unix)]

use ed25519_dalek::{Signer, SigningKey};
use msgfmt::{encode_task, Task, TaskBody};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread::sleep,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use transport::{Channel, MockFsChannel};

fn state(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("agentd-lifecycle-{label}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("state dir");
    fs::write(dir.join("agent.key"), [7_u8; 32]).expect("agent key");
    fs::write(dir.join("enc.key"), [8_u8; 32]).expect("enc key");
    fs::write(
        dir.join("config.toml"),
        "poll_interval_s = 60\nchannel = \"mock-fs\"\n",
    )
    .expect("config");
    dir
}

fn unenrolled_state(label: &str) -> PathBuf {
    let dir = state(label);
    fs::remove_file(dir.join("agent.key")).expect("remove agent key");
    fs::write(
        dir.join("config.toml"),
        "poll_interval_s = 1\nchannel = \"mock-fs\"\n",
    )
    .expect("config");
    dir
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn write_grant(dir: &Path, nonce: &str) {
    let coordinator = SigningKey::from_bytes(&[21_u8; 32]);
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
        + 600;
    let body = format!("grant\t0011223344556677\t{expiry}\t{nonce}");
    let signature = coordinator.sign(body.as_bytes());
    fs::write(
        dir.join("enrolment.grant"),
        format!(
            "{body}\t{}\t{}\n",
            hex(coordinator.verifying_key().as_bytes()),
            hex(&signature.to_bytes())
        ),
    )
    .expect("grant");
}

fn spawn_worker(state: &Path, drain_ms: u64) -> Child {
    // Share one replica root across lifecycle tests: a debug binary is ~100 MiB
    // and three copies per state directory would exhaust a 2 GiB /tmp tmpfs.
    let replicas =
        std::env::temp_dir().join(format!("agentd-lifecycle-replicas-{}", std::process::id()));
    Command::new(env!("CARGO_BIN_EXE_agentd"))
        .arg("--worker")
        .arg("--state")
        .arg(state)
        .env("AGENT_FLEET_DRAIN_MS", drain_ms.to_string())
        .env("AGENT_FLEET_REPLICA_ROOTS", &replicas)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("worker starts")
}

fn wait_for(path: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        assert!(Instant::now() < deadline, "timed out waiting for {path:?}");
        sleep(Duration::from_millis(20));
    }
}

fn wait_for_log(path: &Path, needle: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        let log = fs::read_to_string(path).unwrap_or_default();
        if log.contains(needle) {
            return log;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {needle:?} in {path:?}; log was:\n{log}"
        );
        sleep(Duration::from_millis(20));
    }
}

fn spawn_supervisor(state: &Path, drain_ms: u64) -> Child {
    Command::new(env!("CARGO_BIN_EXE_agentd"))
        .arg("--state")
        .arg(state)
        .env("AGENT_FLEET_DRAIN_MS", drain_ms.to_string())
        .env("AGENT_FLEET_REPLICA_ROOTS", replicas())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("supervisor starts")
}

fn replicas() -> PathBuf {
    // On the workspace disk, not the 2 GiB tmpfs.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!("lifecycle-replicas-{}", std::process::id()))
}

fn worker_pid(log: &str) -> u32 {
    let marker = "\"pid\":\"";
    let start = log.find(marker).expect("worker_started event") + marker.len();
    log[start..]
        .split('"')
        .next()
        .expect("pid value")
        .parse()
        .expect("numeric pid")
}

fn process_alive(pid: u32) -> bool {
    Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn wait_for_exit(pid: u32, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while process_alive(pid) {
        assert!(Instant::now() < deadline, "process {pid} did not exit");
        sleep(Duration::from_millis(20));
    }
}

fn terminate(child: &mut Child) {
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .expect("kill binary");
    assert!(status.success(), "SIGTERM delivery failed");
}

fn wait_with_deadline(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("worker did not exit within {timeout:?}");
        }
        sleep(Duration::from_millis(20));
    }
}

#[test]
fn worker_stays_alive_without_a_signal() {
    let dir = state("alive");
    let mut child = spawn_worker(&dir, 500);
    wait_for(&dir.join("alive"), Duration::from_secs(10));
    // Drain length plus margin: with no signal the worker must still be running.
    sleep(Duration::from_secs(2));
    assert!(
        child.try_wait().expect("try_wait").is_none(),
        "worker exited without a shutdown signal"
    );
    terminate(&mut child);
    let _ = child.wait();
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn sigterm_drains_in_flight_work_then_exits_zero() {
    let dir = state("drain");
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let marker = dir.join("shell-started");
    let frame = encode_task(
        &Task {
            route_tag: [1; 8],
            epoch: 1,
            body: TaskBody::Shell {
                argv: vec![
                    "sh".into(),
                    "-c".into(),
                    format!("touch {}; sleep 30", marker.display()),
                ],
                timeout_s: 60,
                shell: false,
            },
        },
        &[8; 32],
        &key,
    )
    .expect("task frame");
    let channel = MockFsChannel::new(dir.join("queue"));
    runtime
        .block_on(channel.put(&frame))
        .expect("queue the task");

    let drain_ms = 800;
    let mut child = spawn_worker(&dir, drain_ms);
    // Wait until the shell is genuinely in flight: the command writes a marker
    // before sleeping, so a signal sent after this point exercises the drain
    // window and the group kill rather than a pre-start shutdown.
    wait_for(&marker, Duration::from_secs(20));

    let started = Instant::now();
    terminate(&mut child);
    let status = wait_with_deadline(&mut child, Duration::from_secs(10));
    let elapsed = started.elapsed();

    assert!(status.success(), "expected exit 0, got {status:?}");
    assert!(
        elapsed >= Duration::from_millis(500),
        "returned before the drain window: {elapsed:?}"
    );
    assert!(
        elapsed <= Duration::from_secs(7),
        "drain did not terminate the in-flight group: {elapsed:?}"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_drain_window_longer_than_the_grace_is_honoured() {
    // A fixed 5 s grace after the polling loop would truncate this window. The
    // signal task must own the timer, so the configured 6 s is what kills the
    // in-flight group.
    let dir = state("long-drain");
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let marker = dir.join("shell-started");
    let frame = encode_task(
        &Task {
            route_tag: [1; 8],
            epoch: 1,
            body: TaskBody::Shell {
                argv: vec![
                    "sh".into(),
                    "-c".into(),
                    format!("touch {}; sleep 30", marker.display()),
                ],
                timeout_s: 60,
                shell: false,
            },
        },
        &[8; 32],
        &key,
    )
    .expect("task frame");
    let channel = MockFsChannel::new(dir.join("queue"));
    runtime
        .block_on(channel.put(&frame))
        .expect("queue the task");

    let mut child = spawn_worker(&dir, 6000);
    wait_for(&marker, Duration::from_secs(20));

    let started = Instant::now();
    terminate(&mut child);
    let status = wait_with_deadline(&mut child, Duration::from_secs(15));
    let elapsed = started.elapsed();

    assert!(status.success(), "expected exit 0, got {status:?}");
    assert!(
        elapsed >= Duration::from_millis(5500),
        "the drain window was truncated: {elapsed:?}"
    );
    assert!(
        elapsed <= Duration::from_secs(12),
        "drain did not terminate the in-flight group: {elapsed:?}"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn supervisor_forwards_sigterm_and_exits_zero() {
    let dir = state("supervisor-signal");
    let mut child = spawn_supervisor(&dir, 500);
    wait_for(&dir.join("alive"), Duration::from_secs(20));
    let log = wait_for_log(
        &dir.join("agentd.log"),
        "\"message\":\"worker_started\"",
        Duration::from_secs(20),
    );
    let worker = worker_pid(&log);

    terminate(&mut child);
    let status = wait_with_deadline(&mut child, Duration::from_secs(10));
    assert!(
        status.success(),
        "supervisor must exit 0 on SIGTERM, got {status:?}"
    );
    // The supervisor must wait for the worker to drain, not die first and leave
    // it orphaned under init.
    wait_for_exit(worker, Duration::from_secs(10));
    let log = fs::read_to_string(dir.join("agentd.log")).expect("log");
    assert!(log.contains("\"message\":\"drain_complete\""), "{log}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn supervisor_once_propagates_a_worker_failure() {
    let dir = state("supervisor-once-fail");
    fs::write(dir.join("config.toml"), "poll_interval_s = 0\n").expect("config");
    let output = Command::new(env!("CARGO_BIN_EXE_agentd"))
        .arg("--once")
        .arg("--state")
        .arg(&dir)
        .env("AGENT_FLEET_REPLICA_ROOTS", replicas())
        .output()
        .expect("supervisor runs");
    assert!(
        !output.status.success(),
        "a failed one-shot worker must not report success"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn worker_self_enrols_and_exits_zero_on_signal() {
    let dir = unenrolled_state("self-enrol");
    let mut child = spawn_worker(&dir, 500);
    wait_for(&dir.join("alive"), Duration::from_secs(10));
    // Open enrolment: a key is generated without a grant or operator input.
    wait_for(&dir.join("agent.key"), Duration::from_secs(10));
    sleep(Duration::from_secs(3));
    assert!(
        child.try_wait().expect("try_wait").is_none(),
        "a self-enrolled worker must not exit"
    );
    terminate(&mut child);
    let status = wait_with_deadline(&mut child, Duration::from_secs(10));
    assert!(status.success(), "expected exit 0, got {status:?}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn worker_consumes_a_grant_at_startup() {
    let dir = state("grant-startup");
    fs::remove_file(dir.join("agent.key")).expect("remove agent key");
    fs::write(
        dir.join("config.toml"),
        "poll_interval_s = 1\nchannel = \"mock-fs\"\n",
    )
    .expect("config");
    write_grant(&dir, "nonce-startup");
    let mut child = spawn_worker(&dir, 500);
    wait_for(&dir.join("enrol.request"), Duration::from_secs(20));
    assert!(dir.join("agent.key").is_file());
    assert!(dir.join("coordinator.pub").is_file());
    assert!(!dir.join("enrolment.grant").exists(), "grant is single-use");
    terminate(&mut child);
    let status = wait_with_deadline(&mut child, Duration::from_secs(10));
    assert!(status.success(), "expected exit 0, got {status:?}");
    let log = fs::read_to_string(dir.join("agentd.log")).expect("log");
    assert!(!log.contains("\"message\":\"unenrolled\""), "{log}");
    let _ = fs::remove_dir_all(&dir);
}
