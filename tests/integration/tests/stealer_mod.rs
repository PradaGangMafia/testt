#![cfg(unix)]

//! Controller-mod wiring for the native harvester and watcher.

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
use serde_json::{json, Value};
use sha2::Digest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn module() -> PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let target = workspace().join("target/test-mods/stealer-mod");
        let status = Command::new(env!("CARGO"))
            .args([
                "build",
                "--release",
                "--target",
                "wasm32-unknown-unknown",
                "--manifest-path",
                "mods/stealer/Cargo.toml",
                "--target-dir",
            ])
            .arg(&target)
            .current_dir(workspace())
            .status()
            .expect("cargo runs");
        assert!(status.success(), "stealer mod builds");
        target.join("wasm32-unknown-unknown/release/mod_stealer.wasm")
    })
    .clone()
}

fn helper(root: &Path) -> PathBuf {
    let path = root.join("helper.sh");
    std::fs::write(&path, "#!/bin/sh\nprintf 'args:%s\\n' \"$*\"\n").expect("helper");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    path
}

#[tokio::test]
async fn run_action_executes_the_helper() {
    let root = temp("stealer-run");
    let glob = format!("{}*", root.display());
    let policy = policy(
        &[
            ("exec", "*"),
            ("fs_write", &glob),
            ("env", "OS"),
            ("net", "http*://127.0.0.1*"),
        ],
        true,
        true,
    );
    let mut store = ModStore::open(root.join("mods")).expect("store");
    let staged = common::stage_abi(
        &root,
        1,
        "stealer.mod",
        "1",
        &std::fs::read(module()).expect("wasm"),
        &[
            "exec:*",
            &format!("fs_write:{glob}"),
            "env:OS",
            "net:http*://127.0.0.1*",
        ],
    );
    install(&mut store, &policy, &staged).await;
    let host = WasmHost::with_state(&root, policy).expect("host");
    let helper = helper(&root);
    let outcome = host
        .run(
            &std::fs::read(module()).expect("wasm"),
            &json!({"action":"run","helper":helper,"args":["--limit","5"]}),
        )
        .await
        .expect("run");
    assert!(outcome.ok, "{outcome:?}");
    assert!(
        outcome.stdout.contains("args:--limit 5"),
        "{}",
        outcome.stdout
    );
}

#[tokio::test]
async fn install_action_concatenates_and_verifies_chunks() {
    let payload = b"#!/bin/sh\necho installed\n";
    let digest = sha2::Sha256::digest(payload);
    let hash: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener");
    let address = listener.local_addr().expect("address");
    let body = payload.to_vec();
    let half = body.len() / 2;
    let server = tokio::spawn(async move {
        for (index, chunk) in [&body[..half], &body[half..]].into_iter().enumerate() {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buf = [0_u8; 1024];
            let _ = socket.read(&mut buf).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                chunk.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.write_all(chunk).await;
            let _ = index;
        }
    });

    let root = temp("stealer-install");
    let glob = format!("{}*", root.display());
    let policy = policy(
        &[
            ("exec", "*"),
            ("fs_write", &glob),
            ("env", "OS"),
            ("net", "http*://127.0.0.1*"),
        ],
        true,
        true,
    );
    let mut store = ModStore::open(root.join("mods")).expect("store");
    let staged = common::stage_abi(
        &root,
        1,
        "stealer.mod",
        "1",
        &std::fs::read(module()).expect("wasm"),
        &[
            "exec:*",
            &format!("fs_write:{glob}"),
            "env:OS",
            "net:http*://127.0.0.1*",
        ],
    );
    install(&mut store, &policy, &staged).await;
    let host = WasmHost::with_state(&root, policy).expect("host");
    let dest = root.join("harvest");
    let outcome = host
        .run(
            &std::fs::read(module()).expect("wasm"),
            &json!({
                "action":"install",
                "dest":dest,
                "sha256":hash,
                "chunks":[format!("http://{address}/a"), format!("http://{address}/b")],
            }),
        )
        .await
        .expect("run");
    assert!(outcome.ok, "{outcome:?}");
    let report: Value = serde_json::from_str(&outcome.stdout).expect("json");
    assert_eq!(report["sha256"], json!(hash));
    assert!(dest.is_file());
    let installed = std::fs::read(&dest).expect("dest");
    assert_eq!(installed.len(), payload.len());
    assert_eq!(&installed[..3], b"#!/");
    server.await.expect("server");
}
