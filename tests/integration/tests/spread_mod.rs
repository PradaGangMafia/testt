#![cfg(unix)]

//! Controller-mod wiring for the spread helper.

mod common;

use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    sync::OnceLock,
};

use agentd::plugins::{ModStore, WasmHost};
use common::{install, policy};
use integration_tests::temp;
use serde_json::json;

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn module() -> PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let target = workspace().join("target/test-mods/spread-mod");
        let status = Command::new(env!("CARGO"))
            .args([
                "build",
                "--release",
                "--target",
                "wasm32-unknown-unknown",
                "--manifest-path",
                "mods/spread/Cargo.toml",
                "--target-dir",
            ])
            .arg(&target)
            .current_dir(workspace())
            .status()
            .expect("cargo runs");
        assert!(status.success(), "spread mod builds");
        target.join("wasm32-unknown-unknown/release/mod_spread.wasm")
    })
    .clone()
}

#[tokio::test]
async fn builds_the_helper_argv() {
    let root = temp("spread-mod");
    let helper = root.join("spread.sh");
    std::fs::write(&helper, "#!/bin/sh\nprintf '%s\\n' \"$*\"\n").expect("helper");
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).expect("chmod");

    let policy = policy(&[("exec", "*"), ("env", "OS")], true, false);
    let mut store = ModStore::open(root.join("mods")).expect("store");
    let staged = common::stage_abi(
        &root,
        1,
        "spread.mod",
        "1",
        &std::fs::read(module()).expect("wasm"),
        &["exec:*", "env:OS"],
    );
    install(&mut store, &policy, &staged).await;
    let host = WasmHost::with_state(&root, policy).expect("host");
    let outcome = host
        .run(
            &std::fs::read(module()).expect("wasm"),
            &json!({
                "helper": helper,
                "state": "/var/lib/agent-fleet",
                "payload": "/opt/payload",
                "mode": "usb",
                "mount_roots": ["/media/user"],
                "max_hosts": 5,
                "force": true,
            }),
        )
        .await
        .expect("run");
    assert!(outcome.ok, "{outcome:?}");
    assert!(outcome.stdout.contains("--mode usb"), "{}", outcome.stdout);
    assert!(
        outcome.stdout.contains("--mount-root /media/user"),
        "{}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("--max-hosts 5"),
        "{}",
        outcome.stdout
    );
    assert!(outcome.stdout.contains("--force"), "{}", outcome.stdout);
}
