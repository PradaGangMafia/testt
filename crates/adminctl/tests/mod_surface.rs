//! R22 adminctl module surface tests.

use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn root(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "agent-fleet-adminctl-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn run(state: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_adminctl"))
        .arg("--state")
        .arg(state)
        .args(args)
        .output()
        .expect("adminctl runs")
}

fn ok(state: &Path, args: &[&str]) -> String {
    let output = run(state, args);
    assert!(
        output.status.success(),
        "adminctl {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("UTF-8 stdout")
}

fn configure(state: &Path, modules: &str) {
    std::fs::write(
        state.join("config.toml"),
        format!("channel = \"mock-fs\"\n[modules]\n{modules}"),
    )
    .unwrap();
}

#[test]
fn add_call_list_disable_remove() {
    let state = root("flow");
    ok(&state, &["keygen"]);
    configure(&state, "");

    let added = ok(
        &state,
        &[
            "mod",
            "add",
            "hello",
            "1",
            fixture("hello.wasm").to_str().unwrap(),
        ],
    );
    let added: serde_json::Value = serde_json::from_str(added.trim()).expect("add JSON");
    assert_eq!(added["id"], "hello");
    assert_eq!(added["enabled"], true);
    assert!(added["size"].as_u64().unwrap() > 0);
    assert_eq!(added["blake3"].as_str().unwrap().len(), 64);

    let listed = ok(&state, &["mod", "list"]);
    let entry: serde_json::Value = serde_json::from_str(listed.trim()).expect("list JSON");
    assert_eq!(entry["version"], "1");
    assert_eq!(entry["abi"], 1);
    assert!(entry["capabilities"].as_array().unwrap().is_empty());

    let called = ok(&state, &["mod", "call", "hello", "1"]);
    let called: serde_json::Value = serde_json::from_str(called.trim()).expect("call JSON");
    assert_eq!(called["ok"], true);
    assert_eq!(called["stdout"], "hi");
    assert_eq!(called["code"], 0);

    ok(&state, &["mod", "disable", "hello", "1"]);
    let disabled = run(&state, &["mod", "call", "hello", "1"]);
    assert!(!disabled.status.success(), "disabled modules do not run");
    let module = state.join("mods/hello/1/module.wasm");
    assert!(module.is_file(), "disable keeps files");

    ok(&state, &["mod", "enable", "hello", "1"]);
    assert!(run(&state, &["mod", "call", "hello", "1"]).status.success());
    ok(&state, &["mod", "remove", "hello", "1"]);
    assert!(!state.join("mods/hello/1").exists());
}

#[test]
fn bad_id_is_refused_before_publish() {
    let state = root("bad-id");
    ok(&state, &["keygen"]);
    configure(&state, "");
    let output = run(
        &state,
        &[
            "mod",
            "add",
            "../escape",
            "1",
            fixture("hello.wasm").to_str().unwrap(),
        ],
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid module id"));
    assert!(!state.join("mods").join("hello").exists());
    assert!(!state.parent().unwrap().join("escape").exists());
}

#[test]
fn set_replaces_the_enabled_set() {
    let state = root("set");
    ok(&state, &["keygen"]);
    configure(&state, "");
    for (id, module) in [("hello", "hello.wasm"), ("code", "bad_code.wasm")] {
        ok(
            &state,
            &["mod", "add", id, "1", fixture(module).to_str().unwrap()],
        );
    }
    ok(&state, &["mod", "set", "hello@1"]);
    let mut enabled = Vec::new();
    for line in ok(&state, &["mod", "list"]).lines() {
        let value: serde_json::Value = serde_json::from_str(line).expect("list line JSON");
        enabled.push((
            value["id"].as_str().unwrap().to_owned(),
            value["enabled"].as_bool().unwrap(),
        ));
    }
    enabled.sort();
    assert_eq!(
        enabled,
        vec![("code".to_owned(), false), ("hello".to_owned(), true)]
    );
    let output = run(&state, &["mod", "call", "code", "1"]);
    assert!(!output.status.success(), "unset modules are disabled");
}

#[test]
fn declared_capability_must_be_allowed_by_config() {
    let state = root("cap");
    ok(&state, &["keygen"]);
    configure(&state, "");
    let output = run(
        &state,
        &[
            "mod",
            "add",
            "writer",
            "1",
            "--cap",
            "fs_write:/tmp/x",
            fixture("denied.wasm").to_str().unwrap(),
        ],
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("capability"));

    configure(&state, "allow_caps.fs_write = [\"/tmp/**\"]\n");
    ok(
        &state,
        &[
            "mod",
            "add",
            "writer",
            "1",
            "--cap",
            "fs_write:/tmp/x",
            fixture("denied.wasm").to_str().unwrap(),
        ],
    );
}

#[test]
fn undeclared_import_is_refused_at_install() {
    let state = root("hidden");
    ok(&state, &["keygen"]);
    configure(&state, "allow_caps.fs_write = [\"/tmp/**\"]\n");
    let output = run(
        &state,
        &[
            "mod",
            "add",
            "hidden",
            "1",
            fixture("denied.wasm").to_str().unwrap(),
        ],
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("undeclared module capability"));
}
