//! The worker re-executes itself under a random name on every start.

#![cfg(unix)]

use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};

use tempfile::TempDir;

#[test]
fn worker_morphs_on_launch() {
    let root = TempDir::new().unwrap();
    let exe = root.path().join("agentd");
    fs::copy(env!("CARGO_BIN_EXE_agentd"), &exe).unwrap();
    fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
    let state = root.path().join("state");
    fs::create_dir_all(&state).unwrap();
    fs::write(state.join("agent.key"), [7_u8; 32]).unwrap();
    fs::write(state.join("enc.key"), [8_u8; 32]).unwrap();
    fs::write(
        state.join("config.toml"),
        "poll_interval_s = 60\njitter_percent = 50\nchannel = \"mock-fs\"\n",
    )
    .unwrap();

    let status = Command::new(&exe)
        .arg("--worker")
        .arg("--once")
        .arg("--state")
        .arg(&state)
        .env("AGENT_FLEET_REPLICA_ROOTS", root.path().join("replicas"))
        .status()
        .expect("worker runs");
    assert!(status.success(), "{status:?}");

    let log = fs::read_to_string(state.join("agentd.log")).unwrap();
    assert!(log.contains("\"message\":\"morph\""), "{log}");
    let renamed: Vec<PathBuf> = fs::read_dir(root.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(".agentd-"))
        })
        .collect();
    assert!(!renamed.is_empty(), "no morphed copy created");
    // The logged target is one of the copies and is what ran.
    let target = renamed
        .iter()
        .find(|path| log.contains(&path.display().to_string()))
        .expect("morph event names the copy");
    assert_eq!(fs::read(target).unwrap(), fs::read(&exe).unwrap());
}
