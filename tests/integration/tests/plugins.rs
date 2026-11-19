//! P40 module acceptance: p01–p13 against the real host and committed fixtures.

mod common;

use std::time::Duration;

use agentd::plugins::{CapError, Limits, ModError, ModStore, WasmHost};
use common::{host_with, install, policy, stage};
use integration_tests::{fixture, temp};
use serde_json::json;

#[tokio::test]
async fn p01_install_and_run_survives_restart() {
    let root = temp("p01");
    let mut store = ModStore::open(root.join("mods")).expect("store");
    let empty = policy(&[], false, false);
    let staged = stage(&root, "hello", "1", &fixture("hello.wasm"), &[]);
    install(&mut store, &empty, &staged).await;
    drop(store);

    let store = ModStore::open(root.join("mods")).expect("reopen");
    assert!(store.get("hello", "1").is_some());
    let host = WasmHost::new(empty).expect("host");
    let outcome = host
        .run(&fixture("hello.wasm"), &json!({}))
        .await
        .expect("hello runs");
    assert!(outcome.ok, "{outcome:?}");
    assert_eq!(outcome.stdout, "hi");
    assert_eq!(outcome.code, 0);
}

#[tokio::test]
async fn p02_hash_mismatch_is_refused() {
    let root = temp("p02");
    let mut store = ModStore::open(root.join("mods")).expect("store");
    let empty = policy(&[], false, false);
    let mut staged = stage(&root, "badhash", "1", &fixture("hello.wasm"), &[]);
    staged.entry.blake3[0] ^= 1;
    let set = msgfmt::ModSet {
        gen: 1,
        add: vec![staged.entry],
        remove: Vec::new(),
    };
    assert!(matches!(
        store.apply(&set, &empty).await,
        Err(ModError::HashMismatch)
    ));
    assert!(store.get("badhash", "1").is_none());
    assert!(!root.join("mods").join("badhash").exists());
}

#[tokio::test]
async fn p03_unknown_abi_is_refused() {
    let root = temp("p03");
    let mut store = ModStore::open(root.join("mods")).expect("store");
    let empty = policy(&[], false, false);
    let mut staged = stage(&root, "future", "1", &fixture("hello.wasm"), &[]);
    staged.entry.abi = 99;
    let set = msgfmt::ModSet {
        gen: 1,
        add: vec![staged.entry],
        remove: Vec::new(),
    };
    assert!(matches!(
        store.apply(&set, &empty).await,
        Err(ModError::Abi(99))
    ));
    assert!(store.get("future", "1").is_none());
}

#[tokio::test]
async fn p04_undeclared_capability_is_refused_at_load() {
    let root = temp("p04");
    let mut store = ModStore::open(root.join("mods")).expect("store");
    let empty = policy(&[], false, false);
    let staged = stage(
        &root,
        "writer",
        "1",
        &fixture("denied.wasm"),
        &["fs_write:/tmp/agent-fleet-denied-target"],
    );
    let set = msgfmt::ModSet {
        gen: 1,
        add: vec![staged.entry],
        remove: Vec::new(),
    };
    assert!(matches!(
        store.apply(&set, &empty).await,
        Err(ModError::Capability(CapError::Denied(_)))
    ));
    assert!(store.get("writer", "1").is_none());
}

#[tokio::test]
async fn p04b_undeclared_import_is_refused_at_load() {
    let root = temp("p04b");
    let mut store = ModStore::open(root.join("mods")).expect("store");
    let policy = policy(&[("fs_write", "/tmp/**")], false, false);
    let staged = stage(&root, "hidden-writer", "1", &fixture("denied.wasm"), &[]);
    let set = msgfmt::ModSet {
        gen: 1,
        add: vec![staged.entry],
        remove: Vec::new(),
    };
    assert!(matches!(
        store.apply(&set, &policy).await,
        Err(ModError::UndeclaredCapability(cap)) if cap == "fs_write"
    ));
    assert!(!root.join("mods").join("hidden-writer").exists());
}

#[tokio::test]
async fn p05_capability_is_enforced_at_call_time() {
    let root = temp("p05");
    let restricted = policy(&[("fs_write", "/tmp/agent-fleet-allowed/**")], false, false);
    let mut store = ModStore::open(root.join("mods")).expect("store");
    // The entry declares an allowed target but the module writes elsewhere.
    let staged = stage(
        &root,
        "liar",
        "1",
        &fixture("denied.wasm"),
        &["fs_write:/tmp/agent-fleet-allowed/report"],
    );
    install(&mut store, &restricted, &staged).await;
    let denied_path = std::path::Path::new("/tmp/agent-fleet-denied-target");
    let _ = std::fs::remove_file(denied_path);
    let host = WasmHost::new(restricted).expect("host");
    let outcome = host
        .run(&fixture("denied.wasm"), &json!({}))
        .await
        .expect("denied module still returns");
    assert!(!outcome.ok);
    assert_eq!(outcome.code, -1);
    assert!(!denied_path.exists(), "denial must not write");
}

#[tokio::test]
async fn p06_fuel_exhaustion_is_minus_two() {
    let (_root, host, _store) = host_with("p06", policy(&[], false, false)).await;
    let host = host.with_limits(Limits {
        fuel: 2_000_000,
        ..Limits::default()
    });
    let outcome = host
        .run(&fixture("bomb.wasm"), &json!({}))
        .await
        .expect("bomb returns a limit result");
    assert_eq!(outcome.code, -2, "{outcome:?}");
    assert!(!outcome.ok);
    assert_eq!(
        host.run(&fixture("hello.wasm"), &json!({}))
            .await
            .expect("next task")
            .code,
        0
    );
}

#[tokio::test]
async fn p07_deadline_is_minus_three() {
    let (_root, host, _store) = host_with("p07", policy(&[], false, false)).await;
    let host = host.with_limits(Limits {
        fuel: 2_000_000,
        memory_bytes: Limits::default().memory_bytes,
        deadline: Duration::from_millis(1),
    });
    let outcome = host
        .run(&fixture("loop.wasm"), &json!({}))
        .await
        .expect("loop returns a limit result");
    assert_eq!(outcome.code, -3, "{outcome:?}");
    assert!(!outcome.ok);
    assert_eq!(
        host.run(&fixture("hello.wasm"), &json!({}))
            .await
            .expect("next task")
            .code,
        0
    );
}

#[tokio::test]
async fn p08_memory_limit_is_minus_four() {
    let (root, host, _store) = host_with("p08", policy(&[], false, false)).await;
    let outcome = host
        .run(&fixture("hog.wasm"), &json!({}))
        .await
        .expect("hog returns a limit result");
    assert_eq!(outcome.code, -4, "{outcome:?}");
    assert!(!outcome.ok);
    let next = host
        .run(&fixture("hello.wasm"), &json!({}))
        .await
        .expect("next task");
    assert!(next.ok, "{next:?}");
    assert_eq!(next.stdout, "hi");
    let _ = root;
}

#[tokio::test]
async fn p09_disable_stops_execution_and_keeps_files() {
    let root = temp("p09");
    let mut store = ModStore::open(root.join("mods")).expect("store");
    let empty = policy(&[], false, false);
    let staged = stage(&root, "hello", "1", &fixture("hello.wasm"), &[]);
    install(&mut store, &empty, &staged).await;
    assert!(store.set_enabled("hello", "1", false));
    assert!(store.get("hello", "1").is_none());
    assert!(root
        .join("mods")
        .join("hello")
        .join("1")
        .join("module.wasm")
        .is_file());
    assert!(store.entries().any(|entry| !entry.entry.enabled));
}

#[tokio::test]
async fn p10_upgrade_runs_the_new_bytes() {
    let root = temp("p10");
    let mut store = ModStore::open(root.join("mods")).expect("store");
    let empty = policy(&[], false, false);
    let v1 = stage(&root, "hello", "1", &fixture("hello.wasm"), &[]);
    install(&mut store, &empty, &v1).await;
    let v2 = stage(&root, "hello", "2", &fixture("bad_code.wasm"), &[]);
    install(&mut store, &empty, &v2).await;
    assert!(store.get("hello", "1").is_some());
    let installed = store.get("hello", "2").expect("v2 installed");
    assert_ne!(installed.entry.blake3, v1.entry.blake3);
    let host = WasmHost::new(empty).expect("host");
    let bytes = fixture("bad_code.wasm");
    let outcome = host.run(&bytes, &json!({})).await.expect("v2 runs");
    assert!(!outcome.ok);
    assert_eq!(outcome.code, 3);
    assert_eq!(outcome.stdout, "out");
}

#[tokio::test]
async fn p11_remove_deletes_the_version() {
    let root = temp("p11");
    let mut store = ModStore::open(root.join("mods")).expect("store");
    let empty = policy(&[], false, false);
    let staged = stage(&root, "hello", "1", &fixture("hello.wasm"), &[]);
    install(&mut store, &empty, &staged).await;
    let dir = root.join("mods").join("hello").join("1");
    assert!(dir.is_dir());
    assert!(store.remove("hello", "1"));
    assert!(store.get("hello", "1").is_none());
    assert!(!dir.exists());
}

#[tokio::test]
async fn p12_invocations_do_not_share_guest_state() {
    let (_root, host, _store) = host_with("p12", policy(&[], false, false)).await;
    let bytes = fixture("isolation.wasm");
    for _ in 0..2 {
        let outcome = host.run(&bytes, &json!({})).await.expect("isolation runs");
        assert!(outcome.ok, "state leaked between runs: {outcome:?}");
        assert_eq!(outcome.stdout, "once");
    }
}

#[tokio::test]
async fn p13_a_trapping_call_does_not_poison_the_host() {
    let (_root, host, _store) = host_with("p13", policy(&[], false, false)).await;
    let trapped = host
        .run(&fixture("oob.wasm"), &json!({}))
        .await
        .expect("oob returns a trap result");
    assert_eq!(trapped.code, -1, "{trapped:?}");
    assert!(
        trapped.stderr.to_ascii_lowercase().contains("oob"),
        "{trapped:?}"
    );
    let next = host
        .run(&fixture("hello.wasm"), &json!({}))
        .await
        .expect("host still works");
    assert!(next.ok, "{next:?}");
    assert_eq!(next.stdout, "hi");
}

#[tokio::test]
async fn result_replacement_and_malformed_json_are_bounded() {
    let (_root, host, _store) = host_with("result-shape", policy(&[], false, false)).await;
    let replaced = host
        .run(&fixture("two_results.wasm"), &json!({}))
        .await
        .expect("two results");
    assert_eq!(replaced.stdout, "second");

    let malformed = host
        .run(&fixture("malformed.wasm"), &json!({}))
        .await
        .expect("malformed");
    assert_eq!(malformed.code, -1);
    assert!(malformed.stderr.contains("malformed module result"));
}

#[tokio::test]
async fn args_are_delivered_byte_identically() {
    let (_root, host, _store) = host_with("args", policy(&[], false, false)).await;
    let args = json!({"ok": true, "stdout": "echo", "stderr": "", "code": 0});
    let outcome = host
        .run(&fixture("echo_args.wasm"), &args)
        .await
        .expect("echo");
    assert!(outcome.ok, "{outcome:?}");
    assert_eq!(outcome.stdout, "echo");
}

#[tokio::test]
async fn dealloc_runs_even_when_the_module_traps() {
    let (_root, host, _store) = host_with("dealloc", policy(&[], false, false)).await;
    let (outcome, logs) = host
        .run_logged(&fixture("dealloc_log.wasm"), &json!({}))
        .await
        .expect("trap result");
    assert_eq!(outcome.code, -1);
    assert!(logs.iter().any(|line| line == "dealloc-called"), "{logs:?}");
}

#[tokio::test]
async fn missing_alloc_is_a_named_instantiation_error() {
    let (_root, host, _store) = host_with("no-alloc", policy(&[], false, false)).await;
    let error = host
        .run(&fixture("no_alloc.wasm"), &json!({}))
        .await
        .expect_err("missing alloc");
    assert!(
        error.to_string().contains("missing export: alloc"),
        "{error}"
    );
}
