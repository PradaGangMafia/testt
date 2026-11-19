//! SIGTERM drains coordd and exits zero.

#![cfg(unix)]

use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use tempfile::TempDir;

fn state() -> TempDir {
    let state = TempDir::new().unwrap();
    fs::write(state.path().join("agent.key"), [4_u8; 32]).unwrap();
    fs::write(state.path().join("enc.key"), [5_u8; 32]).unwrap();
    fs::write(state.path().join("relays.conf"), "").unwrap();
    state
}

#[test]
fn sigterm_exits_zero() {
    let state = state();
    let mut child = Command::new(env!("CARGO_BIN_EXE_coordd"))
        .arg("--state")
        .arg(state.path())
        .arg("--cycle-ms")
        .arg("200")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // Let the loop start and the handler register.
    std::thread::sleep(Duration::from_millis(500));
    assert!(child.try_wait().unwrap().is_none(), "coordd exited early");
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .unwrap();
    assert!(status.success());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "expected exit 0, got {status:?}");
            break;
        }
        assert!(Instant::now() < deadline, "coordd ignored SIGTERM");
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = fs::metadata(Path::new(&state.path().join("findings.db")));
}
