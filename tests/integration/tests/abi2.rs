//! ABI 2 acceptance: directory listing, stat, ranged reads, spool, HTTP POST.

mod common;

use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::OnceLock,
};

use agentd::plugins::{ModError, ModStore, WasmHost};
use common::{install, policy, stage_abi};
use integration_tests::temp;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Builds the recon module once per test process.
fn recon() -> PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let target = workspace().join("target/test-mods/abi2-target");
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
            .arg(&target)
            .current_dir(workspace())
            .status()
            .expect("cargo runs");
        assert!(status.success(), "recon module builds");
        target.join("wasm32-unknown-unknown/release/mod_recon.wasm")
    })
    .clone()
}

fn tree(root: &Path) -> PathBuf {
    let tree = root.join("tree");
    for directory in ["profiles/Chrome", "wallets"] {
        std::fs::create_dir_all(tree.join(directory)).expect("tree directory");
    }
    std::fs::write(tree.join("profiles/Chrome/Login Data"), b"credential-bytes").expect("login");
    std::fs::write(tree.join("profiles/Chrome/Notes.txt"), b"unrelated").expect("notes");
    std::fs::write(tree.join(".env"), b"API_KEY=secret").expect("env");
    std::fs::write(tree.join("wallets/wallet.dat"), b"seed-bytes").expect("wallet");
    tree
}

fn rules(tree: &Path) -> Vec<(String, String)> {
    let glob = format!("{}*", tree.display());
    vec![
        ("fs_read".into(), glob.clone()),
        ("spool".into(), glob),
        ("exec".into(), "*".into()),
        ("env".into(), "OS".into()),
        ("net".into(), "http*://127.0.0.1*".into()),
    ]
}

async fn run_recon(root: &Path, args: Value) -> (Value, PathBuf) {
    let tree = tree(root);
    let staged_rules = rules(&tree);
    let policy_rules: Vec<(&str, &str)> = staged_rules
        .iter()
        .map(|(cap, rule)| (cap.as_str(), rule.as_str()))
        .collect();
    let host_policy = policy(&policy_rules, true, true);
    let declared: Vec<String> = staged_rules
        .iter()
        .map(|(cap, rule)| format!("{cap}:{rule}"))
        .collect();
    let declared_refs: Vec<&str> = declared.iter().map(String::as_str).collect();
    let staged = stage_abi(
        root,
        2,
        "recon",
        "1",
        &std::fs::read(recon()).expect("wasm"),
        &declared_refs,
    );
    let mut store = ModStore::open(root.join("mods")).expect("store");
    install(&mut store, &host_policy, &staged).await;
    let host = WasmHost::with_state(root, host_policy).expect("host");
    let mut args = args;
    args["roots"] = json!([tree.clone()]);
    let outcome = host
        .run(&std::fs::read(recon()).expect("wasm"), &args)
        .await
        .expect("run");
    assert!(outcome.ok, "{outcome:?}");
    let value: Value = serde_json::from_str(&outcome.stdout).expect("report JSON");
    (value, tree)
}

#[tokio::test]
async fn abi2_walks_spools_and_ranges_files() {
    let root = temp("abi2-walk");
    let (report, tree) = run_recon(&root, json!({"max_depth": 3})).await;
    let findings = report["findings"].as_array().expect("findings");
    let paths: Vec<&str> = findings
        .iter()
        .filter_map(|finding| finding["data"]["path"].as_str())
        .collect();
    assert!(
        paths.iter().any(|path| path.ends_with("Login Data")),
        "{paths:?}"
    );
    assert!(paths.iter().any(|path| path.ends_with(".env")), "{paths:?}");
    assert!(
        paths.iter().any(|path| path.ends_with("wallet.dat")),
        "{paths:?}"
    );
    assert!(
        !paths.iter().any(|path| path.ends_with("Notes.txt")),
        "{paths:?}"
    );
    assert!(report["stored"].as_u64().unwrap_or(0) >= 3);
    // The ranged read really returned the file head, not an empty buffer.
    let login = findings
        .iter()
        .find(|finding| {
            finding["data"]["path"]
                .as_str()
                .is_some_and(|path| path.ends_with("Login Data"))
        })
        .expect("login finding");
    assert_eq!(login["data"]["bytes"], json!(16));
    assert_eq!(login["kind"], json!("inventory"));
    assert_eq!(login["severity"], json!(2));

    let database = rusqlite::Connection::open(root.join("spool.db")).expect("spool db");
    let count: i64 = database
        .query_row("SELECT COUNT(*) FROM artifacts", [], |row| row.get(0))
        .expect("count");
    assert_eq!(count, report["stored"].as_i64().unwrap());
    let (path, data): (String, Vec<u8>) = database
        .query_row(
            "SELECT path, data FROM artifacts WHERE path LIKE '%Login Data'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("row");
    assert!(path.starts_with(tree.to_string_lossy().as_ref()));
    assert_eq!(data, b"credential-bytes");
}

#[tokio::test]
async fn abi2_http_post_delivers_the_report() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener");
    let address = listener.local_addr().expect("address");
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buffer = vec![0_u8; 32 * 1024];
        let read = socket.read(&mut buffer).await.expect("read");
        let _ = socket
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
            .await;
        String::from_utf8_lossy(&buffer[..read]).into_owned()
    });

    let root = temp("abi2-post");
    let tree = tree(&root);
    let glob = format!("{}*", tree.display());
    let host_policy = policy(
        &[
            ("fs_read", &glob),
            ("spool", &glob),
            ("exec", "*"),
            ("env", "OS"),
            ("net", "http*://127.0.0.1*"),
        ],
        true,
        true,
    );
    let declared = [
        format!("fs_read:{glob}"),
        format!("spool:{glob}"),
        "exec:*".into(),
        "env:OS".into(),
        "net:http*://127.0.0.1*".into(),
    ];
    let declared_refs: Vec<&str> = declared.iter().map(String::as_str).collect();
    let staged = stage_abi(
        &root,
        2,
        "recon",
        "1",
        &std::fs::read(recon()).expect("wasm"),
        &declared_refs,
    );
    let mut store = ModStore::open(root.join("mods")).expect("store");
    install(&mut store, &host_policy, &staged).await;
    let host = WasmHost::with_state(&root, host_policy).expect("host");
    let outcome = host
        .run(
            &std::fs::read(recon()).expect("wasm"),
            &json!({
                "roots": [tree],
                "post_url": format!("http://{address}/ingest"),
            }),
        )
        .await
        .expect("run");
    assert!(outcome.ok, "{outcome:?}");
    assert!(
        outcome.stdout.contains("\"post\":\"ok\""),
        "{}",
        outcome.stdout
    );
    let request = server.await.expect("server");
    assert!(request.starts_with("POST /ingest"), "{request}");
    assert!(request.contains("\"findings\""), "{request}");
}

#[tokio::test]
async fn abi2_is_accepted_and_future_abi_is_refused() {
    let root = temp("abi2-store");
    let tree = tree(&root);
    let glob = format!("{}*", tree.display());
    let host_policy = policy(
        &[
            ("fs_read", &glob),
            ("spool", &glob),
            ("exec", "*"),
            ("env", "OS"),
            ("net", "http*://127.0.0.1*"),
        ],
        true,
        true,
    );
    let declared = [
        format!("fs_read:{glob}"),
        format!("spool:{glob}"),
        "exec:*".into(),
        "env:OS".into(),
        "net:http*://127.0.0.1*".into(),
    ];
    let declared_refs: Vec<&str> = declared.iter().map(String::as_str).collect();
    let mut store = ModStore::open(root.join("mods")).expect("store");
    let staged = stage_abi(
        &root,
        2,
        "recon",
        "1",
        &std::fs::read(recon()).expect("wasm"),
        &declared_refs,
    );
    install(&mut store, &host_policy, &staged).await;

    let mut future = stage_abi(
        &root,
        3,
        "future",
        "1",
        &std::fs::read(recon()).expect("wasm"),
        &declared_refs,
    );
    future.entry.abi = 3;
    let set = msgfmt::ModSet {
        gen: 2,
        add: vec![future.entry],
        remove: Vec::new(),
    };
    assert!(matches!(
        store.apply(&set, &host_policy).await,
        Err(ModError::Abi(3))
    ));
}

#[tokio::test]
async fn abi1_entry_cannot_import_abi2() {
    let root = temp("abi2-mismatch");
    let tree = tree(&root);
    let glob = format!("{}*", tree.display());
    let host_policy = policy(
        &[
            ("fs_read", &glob),
            ("spool", &glob),
            ("exec", "*"),
            ("env", "OS"),
            ("net", "http*://127.0.0.1*"),
        ],
        true,
        true,
    );
    let declared = [
        format!("fs_read:{glob}"),
        format!("spool:{glob}"),
        "exec:*".into(),
        "env:OS".into(),
        "net:http*://127.0.0.1*".into(),
    ];
    let declared_refs: Vec<&str> = declared.iter().map(String::as_str).collect();
    let mut store = ModStore::open(root.join("mods")).expect("store");
    let staged = stage_abi(
        &root,
        1,
        "recon",
        "1",
        &std::fs::read(recon()).expect("wasm"),
        &declared_refs,
    );
    let set = msgfmt::ModSet {
        gen: 1,
        add: vec![staged.entry],
        remove: Vec::new(),
    };
    assert!(matches!(
        store.apply(&set, &host_policy).await,
        Err(ModError::AbiImport(name)) if name == "read_dir"
    ));
}
