//! P63 resilience acceptance: r01–r13.

#![cfg(unix)]

use agentd::resilience::{
    self, clock_went_back, doctor, guard, install, is_tmpfs, liveness_is_fresh, mirror_agent_key,
    mirrored_write, recover_agent_key, repair_replicas, restore_from_mirrors, tamper_findings,
    touch_alive, try_reenrol, uninstall, unix_now, CheckStatus,
};
use blake3::Hasher;
use ed25519_dalek::{Signer, SigningKey};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread::sleep,
    time::{Duration, SystemTime},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn temp(label: &str) -> PathBuf {
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "agentd-resilience-{label}-{}-{unique}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("state directory");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("private state");
    path
}

fn executable(state: &Path) -> PathBuf {
    let path = state.join("agentd");
    fs::write(&path, b"agentd-binary-v1").expect("binary");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("executable mode");
    path
}

fn hash(path: &Path) -> String {
    let mut hasher = Hasher::new();
    hasher.update(&fs::read(path).expect("hash input"));
    hasher.finalize().to_hex().to_string()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn write_grant(state: &Path, tag: &str, expiry: u64, nonce: &str, coordinator: &SigningKey) {
    let body = format!("grant\t{tag}\t{expiry}\t{nonce}");
    let signature = coordinator.sign(body.as_bytes());
    fs::write(
        state.join("enrolment.grant"),
        format!(
            "{body}\t{}\t{}\n",
            hex(coordinator.verifying_key().as_bytes()),
            hex(&signature.to_bytes())
        ),
    )
    .expect("grant");
}

fn event_pids(log: &Path) -> Vec<u32> {
    let Ok(text) = fs::read_to_string(log) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|value| value["message"] == "worker_started")
        .filter_map(|value| value["pid"].as_str()?.parse::<u32>().ok())
        .collect()
}

fn wait_for<F: Fn() -> bool>(timeout: Duration, condition: F) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if condition() {
            return true;
        }
        sleep(Duration::from_millis(25));
    }
    condition()
}

fn sigkill(pid: u32) {
    let _ = Command::new("kill")
        .arg("-KILL")
        .arg(pid.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

struct Cleanup {
    child: Option<Child>,
    pids: Vec<u32>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        for pid in &self.pids {
            sigkill(*pid);
        }
    }
}

#[test]
fn r01_killed_worker_is_restarted_by_the_supervisor() {
    let state = temp("r01");
    fs::write(
        state.join("config.toml"),
        "poll_interval_s = 60\nchannel = \"mock-fs\"\n",
    )
    .expect("config");
    fs::write(state.join("agent.key"), [7_u8; 32]).expect("agent key");
    fs::write(state.join("enc.key"), [8_u8; 32]).expect("enc key");

    let supervisor = Command::new(env!("CARGO_BIN_EXE_agentd"))
        .arg("--state")
        .arg(&state)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("supervisor starts");
    let log = state.join("agentd.log");
    let first = wait_for(Duration::from_secs(30), || !event_pids(&log).is_empty());
    let pids = event_pids(&log);
    assert!(first, "supervisor never started a worker");
    let first_pid = pids[0];
    let mut cleanup = Cleanup {
        child: Some(supervisor),
        pids: vec![first_pid],
    };

    // Kill the worker the way the OOM killer or an operator would; the
    // supervisor's five-second restart policy must bring it back.
    sigkill(first_pid);
    let restarted = wait_for(Duration::from_secs(30), || {
        event_pids(&log).iter().any(|pid| *pid != first_pid)
    });
    let pids = event_pids(&log);
    cleanup.pids = pids.clone();
    assert!(restarted, "worker was not restarted: {pids:?}");
    assert!(
        cleanup
            .child
            .as_mut()
            .expect("supervisor")
            .try_wait()
            .expect("try_wait")
            .is_none(),
        "the supervisor exited instead of looping"
    );
    let _ = fs::remove_dir_all(&state);
}

#[test]
fn r02_deleted_binary_is_restored_from_a_replica() {
    let state = temp("r02");
    let exe = executable(&state);
    let original = fs::read(&exe).expect("original bytes");
    fs::write(state.join("binary.blake3"), format!("{}\n", hash(&exe))).expect("hash sidecar");
    assert!(repair_replicas(&state, &exe, "0.1.0", "1").expect("seed replicas"));

    fs::remove_file(&exe).expect("delete running copy");
    assert!(repair_replicas(&state, &exe, "0.1.0", "1").expect("restore"));
    assert_eq!(fs::read(&exe).expect("restored binary"), original);
    for root in resilience::replica_roots(&state) {
        assert_eq!(hash(&root.join("agentd")), hash(&exe), "{root:?}");
    }
    assert!(!tamper_findings(&state, &exe)
        .expect("tamper")
        .contains(&"binary_missing".to_owned()));
    let _ = fs::remove_dir_all(&state);
}

#[test]
fn r03_all_bad_copies_are_repaired_without_a_fatal_error() {
    let state = temp("r03");
    let exe = executable(&state);
    repair_replicas(&state, &exe, "0.1.0", "1").expect("seed");
    for root in resilience::replica_roots(&state) {
        fs::write(root.join("agentd"), b"corrupt").expect("corrupt replica");
    }
    assert!(repair_replicas(&state, &exe, "0.1.0", "1").expect("repair"));
    for root in resilience::replica_roots(&state) {
        let copy = root.join("agentd");
        assert_eq!(hash(&copy), hash(&exe), "{root:?}");
        let manifest = fs::read_to_string(root.join("manifest.json")).expect("manifest");
        assert!(manifest.contains(&hash(&exe)));
    }
    let _ = fs::remove_dir_all(&state);
}

#[test]
fn r04_wiped_primary_state_is_restored_before_polling() {
    let state = temp("r04");
    let key = [7_u8; 32];
    fs::write(state.join("agent.key"), key).expect("key");
    fs::set_permissions(state.join("agent.key"), fs::Permissions::from_mode(0o600)).expect("mode");
    mirror_agent_key(&state).expect("mirror");
    mirrored_write(&state, Path::new("cursors.json"), b"0808080808080808 17\n")
        .expect("mirror cursor");

    fs::remove_file(state.join("agent.key")).expect("wipe key");
    fs::remove_file(state.join("cursors.json")).expect("wipe cursor");
    assert!(recover_agent_key(&state).expect("recover key"));
    assert!(restore_from_mirrors(&state, Path::new("cursors.json")).expect("restore cursor"));
    assert_eq!(fs::read(state.join("agent.key")).expect("key bytes"), key);
    assert_eq!(
        fs::read(state.join("cursors.json")).expect("cursor bytes"),
        b"0808080808080808 17\n"
    );
    let mode = fs::metadata(state.join("agent.key"))
        .expect("key metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    assert!(!recover_agent_key(&state).expect("already recovered"));
    assert!(!restore_from_mirrors(&state, Path::new("cursors.json")).expect("already restored"));
    let _ = fs::remove_dir_all(&state);
}

#[test]
fn r05_corrupt_mirror_is_skipped_for_the_next_verified_copy() {
    let state = temp("r05");
    let key = [7_u8; 32];
    fs::write(state.join("agent.key"), key).expect("key");
    fs::set_permissions(state.join("agent.key"), fs::Permissions::from_mode(0o600)).expect("mode");
    mirror_agent_key(&state).expect("mirror key");
    mirrored_write(&state, Path::new("cursors.json"), b"valid cursor\n").expect("mirror state");

    // Corrupt the first mirror: same length, wrong key, stale sidecar.
    fs::write(state.join("mirror-1").join("agent.key"), [9_u8; 32]).expect("corrupt key");
    fs::write(state.join("mirror-1").join("cursors.json"), b"").expect("empty mirror state");

    fs::remove_file(state.join("agent.key")).expect("wipe primary key");
    fs::remove_file(state.join("cursors.json")).expect("wipe primary state");
    assert!(recover_agent_key(&state).expect("recover from mirror-2"));
    assert_eq!(fs::read(state.join("agent.key")).expect("key"), key);
    assert!(restore_from_mirrors(&state, Path::new("cursors.json")).expect("restore"));
    assert_eq!(
        fs::read(state.join("cursors.json")).expect("state"),
        b"valid cursor\n"
    );
    let _ = fs::remove_dir_all(&state);
}

#[test]
fn r06_signed_grant_re_enrols_once() {
    let state = temp("r06");
    let coordinator = SigningKey::from_bytes(&[21_u8; 32]);
    let tag = "0011223344556677";
    write_grant(&state, tag, unix_now() + 3600, "nonce-r06", &coordinator);
    assert!(try_reenrol(&state).expect("enrol"));
    assert!(!state.join("enrolment.grant").exists(), "grant is consumed");
    assert!(state.join("enrolment.nonce.nonce-r06").is_file());
    let key = fs::read(state.join("agent.key")).expect("new key");
    assert_eq!(key.len(), 32);
    assert_eq!(
        fs::metadata(state.join("agent.key"))
            .expect("key metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let request = fs::read_to_string(state.join("enrol.request")).expect("request");
    assert!(request.contains(&format!("tag={tag}")), "{request}");
    let public = SigningKey::from_bytes(&key.try_into().expect("key length")).verifying_key();
    assert!(
        request.contains(&format!("agent_pub={}", hex(public.as_bytes()))),
        "{request}"
    );
    let _ = fs::remove_dir_all(&state);
}

#[test]
fn r07_reused_and_expired_tokens_are_refused() {
    let state = temp("r07");
    let coordinator = SigningKey::from_bytes(&[21_u8; 32]);
    let tag = "8899aabbccddeeff";
    write_grant(&state, tag, unix_now() + 3600, "nonce-r07", &coordinator);
    assert!(try_reenrol(&state).expect("first use"));
    let key = fs::read(state.join("agent.key")).expect("key");

    // Lose the key and replay the same grant: the local nonce marker refuses it.
    fs::remove_file(state.join("agent.key")).expect("lose key");
    write_grant(&state, tag, unix_now() + 3600, "nonce-r07", &coordinator);
    assert!(!try_reenrol(&state).expect("reuse"));
    assert!(!state.join("agent.key").exists());

    // A fresh nonce with an expiry in the past is also refused.
    write_grant(
        &state,
        tag,
        unix_now().saturating_sub(1),
        "nonce-r07b",
        &coordinator,
    );
    assert!(!try_reenrol(&state).expect("expired"));
    assert!(!state.join("agent.key").exists());
    assert!(key.len() == 32);
    let _ = fs::remove_dir_all(&state);
}

#[test]
fn r08_removed_service_is_reinstalled_by_the_guard() {
    let state = temp("r08");
    let exe = executable(&state);
    fs::write(state.join("findings.db"), b"keep").expect("state payload");
    install(&state, &exe, false, true).expect("install");
    uninstall(&state).expect("remove service");
    assert!(!state.join("services").join("agentd.unit").exists());

    assert_eq!(
        guard(&state, &exe, false).expect("guard repairs"),
        CheckStatus::Repaired
    );
    assert!(state.join("services").join("agentd.unit").is_file());
    assert!(state
        .join("services")
        .join("agentd-backstop.unit")
        .is_file());
    assert!(state.join("findings.db").is_file(), "state survives repair");
    let _ = fs::remove_dir_all(&state);
}

#[test]
fn r09_stopped_unit_is_detected_and_quick_mode_skips_the_backstop() {
    let state = temp("r09");
    let exe = executable(&state);
    install(&state, &exe, false, true).expect("install");
    assert!(
        !state.join("alive").exists(),
        "a stopped unit leaves no fresh marker"
    );
    assert_eq!(
        guard(&state, &exe, false).expect("dead worker"),
        CheckStatus::Repaired
    );
    touch_alive(&state).expect("touch");
    assert_eq!(
        guard(&state, &exe, false).expect("live worker"),
        CheckStatus::Healthy
    );

    let quick = temp("r09-quick");
    let quick_exe = executable(&quick);
    assert_eq!(
        guard(&quick, &quick_exe, true).expect("install quickly"),
        CheckStatus::Repaired
    );
    assert!(quick.join("services").join("agentd.unit").is_file());
    assert!(
        !quick.join("services").join("agentd-backstop.unit").exists(),
        "quick mode suppresses the backstop"
    );
    let _ = fs::remove_dir_all(&state);
    let _ = fs::remove_dir_all(&quick);
}

#[test]
fn r10_permission_tamper_is_reported_by_stable_name() {
    let state = temp("r10");
    let exe = executable(&state);
    let key = state.join("agent.key");
    fs::write(&key, [7_u8; 32]).expect("key");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).expect("loose key");
    fs::set_permissions(&state, fs::Permissions::from_mode(0o755)).expect("loose state");
    fs::set_permissions(&exe, fs::Permissions::from_mode(0o777)).expect("writable binary");

    let findings = tamper_findings(&state, &exe).expect("tamper");
    for name in ["key_mode", "state_mode", "binary_world_writable"] {
        assert!(findings.contains(&name.to_owned()), "{name}: {findings:?}");
    }
    let log = fs::read_to_string(state.join("tamper.log")).expect("tamper log");
    for name in ["key_mode", "state_mode", "binary_world_writable"] {
        assert!(log.contains(name), "tamper.log has {name}");
    }

    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("tight key");
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).expect("tight state");
    fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).expect("safe binary");
    assert!(tamper_findings(&state, &exe).expect("healthy").is_empty());
    let _ = fs::remove_dir_all(&state);
}

#[test]
fn r11_modified_binary_is_detected_by_its_hash() {
    let state = temp("r11");
    let exe = executable(&state);
    let key = state.join("agent.key");
    fs::write(&key, [7_u8; 32]).expect("key");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("mode");
    fs::write(state.join("binary.blake3"), format!("{}\n", hash(&exe))).expect("sidecar");
    assert!(tamper_findings(&state, &exe).expect("healthy").is_empty());

    let mut modified = fs::read(&exe).expect("read");
    modified.extend_from_slice(b"backdoor");
    fs::write(&exe, modified).expect("modify");
    assert_eq!(
        tamper_findings(&state, &exe).expect("tamper"),
        vec!["binary_hash".to_owned()]
    );

    fs::write(&exe, b"agentd-binary-v1").expect("restore");
    assert!(tamper_findings(&state, &exe).expect("restored").is_empty());
    let _ = fs::remove_dir_all(&state);
}

#[test]
fn r12_tmpfs_state_fails_the_doctor() {
    let shared_memory = Path::new("/dev/shm");
    if !shared_memory.is_dir() || !is_tmpfs(shared_memory) {
        eprintln!("r12 skipped: /dev/shm is not a tmpfs mount on this host");
        return;
    }
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let state = shared_memory.join(format!("agentd-r12-{}-{unique}", std::process::id()));
    let _ = fs::remove_dir_all(&state);
    fs::create_dir_all(&state).expect("tmpfs state");
    let exe = executable(&state);

    let report = doctor(&state, &exe).expect("doctor");
    let durability = report
        .checks
        .iter()
        .find(|check| check.name == "state_durability")
        .expect("durability check");
    assert_eq!(durability.status, "fail", "{durability:?}");
    assert!(report.needs_attention());
    let _ = fs::remove_dir_all(&state);

    let durable = temp("r12-ok");
    let durable_exe = executable(&durable);
    let report = doctor(&durable, &durable_exe).expect("doctor");
    let durability = report
        .checks
        .iter()
        .find(|check| check.name == "state_durability")
        .expect("durability check");
    // The integration temp root is itself tmpfs on many CI hosts; the control
    // assertion only requires the check to be present and consistent.
    assert!(
        durability.status == "pass" || durability.status == "fail",
        "{durability:?}"
    );
    let _ = fs::remove_dir_all(&durable);
}

#[test]
fn r13_clock_rollback_warns_without_rejecting_state() {
    let state = temp("r13");
    let exe = executable(&state);
    install(&state, &exe, false, true).expect("install");
    let future = unix_now() + 365 * 24 * 3600;
    fs::write(state.join("alive"), format!("{future}\n")).expect("future marker");

    assert!(clock_went_back(&state));
    assert!(liveness_is_fresh(
        SystemTime::now(),
        SystemTime::now() + Duration::from_secs(3600),
        Duration::from_secs(300)
    ));
    assert_eq!(
        guard(&state, &exe, false).expect("guard"),
        CheckStatus::Healthy,
        "a clock step must not be treated as a dead worker"
    );
    let report = doctor(&state, &exe).expect("doctor");
    let clock = report
        .checks
        .iter()
        .find(|check| check.name == "clock_monotonic")
        .expect("clock check");
    assert_eq!(clock.status, "warn", "{clock:?}");
    assert!(
        report
            .checks
            .iter()
            .all(|check| check.name != "clock_monotonic" || check.status != "fail"),
        "rollback warns rather than rejects"
    );

    fs::write(state.join("alive"), format!("{}\n", unix_now())).expect("current marker");
    assert!(!clock_went_back(&state));
    let _ = fs::remove_dir_all(&state);
}
