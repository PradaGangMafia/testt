//! R20: examples and template build under the size cap and run on the host.

mod common;

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use agentd::plugins::WasmHost;
use common::{install, policy, stage};
use integration_tests::temp;
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn build_example(name: &str) -> PathBuf {
    let manifest = workspace()
        .join("crates/modsdk/examples")
        .join(name)
        .join("Cargo.toml");
    let status = Command::new(env!("CARGO"))
        .args([
            "build",
            "--release",
            "--target",
            "wasm32-unknown-unknown",
            "--manifest-path",
        ])
        .arg(&manifest)
        .current_dir(workspace())
        .status()
        .expect("cargo runs");
    assert!(status.success(), "example {name} builds");
    let artifact = workspace()
        .join("target/wasm32-unknown-unknown/release")
        .join(format!("mod_{name}.wasm"));
    assert!(artifact.is_file(), "{} is a .wasm", artifact.display());
    assert!(
        std::fs::metadata(&artifact).unwrap().len() < 100 * 1024,
        "{} exceeds 100 KiB",
        artifact.display()
    );
    artifact
}

fn build_template() -> PathBuf {
    let directory = workspace().join("templates/mod");
    let status = Command::new("bash")
        .arg("build.sh")
        .current_dir(&directory)
        .status()
        .expect("template build script runs");
    assert!(status.success(), "template builds");
    let artifact = directory.join("target/wasm32-unknown-unknown/release/mod_template.wasm");
    assert!(artifact.is_file());
    assert!(std::fs::metadata(&artifact).unwrap().len() < 100 * 1024);
    artifact
}

fn findings(stdout: &str) -> Vec<serde_json::Value> {
    let value: serde_json::Value = serde_json::from_str(stdout).expect("findings JSON");
    value["findings"]
        .as_array()
        .expect("findings array")
        .clone()
}

#[tokio::test]
async fn proc_list_runs_and_emits_findings() {
    let wasm = std::fs::read(build_example("proc_list")).unwrap();
    let root = temp("example-proc");
    let policy = policy(&[("fs_read", "/proc/**")], false, false);
    let mut store = agentd::plugins::ModStore::open(root.join("mods")).unwrap();
    let staged = stage(&root, "proc.list", "1.0.0", &wasm, &["fs_read:/proc/**"]);
    install(&mut store, &policy, &staged).await;
    let host = WasmHost::new(policy).unwrap();
    let outcome = host.run(&wasm, &json!({})).await.expect("proc.list runs");
    assert!(outcome.ok, "{outcome:?}");
    let findings = findings(&outcome.stdout);
    assert_eq!(findings.len(), 3);
    assert_eq!(findings[0]["kind"], "inventory");
    assert!(findings
        .iter()
        .all(|finding| finding["dedupe_key"].is_string()));
}

#[tokio::test]
async fn fs_tree_runs_and_emits_findings() {
    let wasm = std::fs::read(build_example("fs_tree")).unwrap();
    let root = temp("example-fs");
    let policy = policy(&[("fs_read", "/etc/**")], false, false);
    let mut store = agentd::plugins::ModStore::open(root.join("mods")).unwrap();
    let staged = stage(&root, "fs.tree", "1.0.0", &wasm, &["fs_read:/etc/**"]);
    install(&mut store, &policy, &staged).await;
    let host = WasmHost::new(policy).unwrap();
    let outcome = host
        .run(&wasm, &json!({"paths": ["/etc/hostname"]}))
        .await
        .expect("fs.tree runs");
    assert!(outcome.ok, "{outcome:?}");
    let findings = findings(&outcome.stdout);
    assert_eq!(findings.len(), 1);
    assert!(findings[0]["data"]["bytes"].as_u64().is_some());
}

#[tokio::test]
async fn net_whoami_runs_against_an_approved_endpoint() {
    let wasm = std::fs::read(build_example("net_whoami")).unwrap();
    let (base, task) = endpoint().await;
    let root = temp("example-net");
    let policy = policy(&[("net", &format!("{base}/**"))], false, true);
    let mut store = agentd::plugins::ModStore::open(root.join("mods")).unwrap();
    let staged = stage(
        &root,
        "net.whoami",
        "1.0.0",
        &wasm,
        &[&format!("net:{base}/**")],
    );
    install(&mut store, &policy, &staged).await;
    let host = WasmHost::new(policy).unwrap();
    let outcome = host
        .run(&wasm, &json!({"url": format!("{base}/whoami")}))
        .await
        .expect("net.whoami runs");
    task.await.unwrap();
    assert!(outcome.ok, "{outcome:?}");
    let findings = findings(&outcome.stdout);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["data"]["observed"], "203.0.113.7");
}

#[tokio::test]
async fn template_builds_and_runs_unmodified() {
    let wasm = std::fs::read(build_template()).unwrap();
    let root = temp("template");
    let policy = policy(&[], false, false);
    let mut store = agentd::plugins::ModStore::open(root.join("mods")).unwrap();
    let staged = stage(&root, "template.mod", "0.1.0", &wasm, &[]);
    install(&mut store, &policy, &staged).await;
    let host = WasmHost::new(policy).unwrap();
    let outcome = host
        .run(&wasm, &json!({"subject": "acceptance"}))
        .await
        .expect("template runs");
    assert!(outcome.ok, "{outcome:?}");
    assert_eq!(findings(&outcome.stdout)[0]["kind"], "health");
}

#[tokio::test]
async fn an_example_without_declared_caps_is_refused_at_install() {
    let wasm = std::fs::read(build_example("proc_list")).unwrap();
    let root = temp("example-undeclared");
    let policy = policy(&[("fs_read", "/proc/**")], false, false);
    let mut store = agentd::plugins::ModStore::open(root.join("mods")).unwrap();
    let staged = stage(&root, "proc.list", "1.0.0", &wasm, &[]);
    let set = msgfmt::ModSet {
        gen: 1,
        add: vec![staged.entry],
        remove: Vec::new(),
    };
    assert!(matches!(
        store.apply(&set, &policy).await,
        Err(agentd::plugins::ModError::UndeclaredCapability(cap)) if cap == "fs_read"
    ));
}

async fn endpoint() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = [0_u8; 1024];
        let _ = stream.read(&mut buffer).await.unwrap();
        let body = b"203.0.113.7";
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(header.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
    });
    (format!("http://{address}"), task)
}
