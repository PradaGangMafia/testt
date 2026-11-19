//! Example module: bounded inventory from `/proc` files.
#![cfg_attr(not(target_arch = "wasm32"), forbid(unsafe_code))]
#![deny(missing_docs)]

//! Emits one inventory finding per readable `/proc` source.

use modsdk::{mod_main, CapError, Ctx};
use serde_json::json;

/// Files read for the inventory finding.
const SOURCES: [(&str, &str); 3] = [
    ("proc.list:uptime", "/proc/uptime"),
    ("proc.list:loadavg", "/proc/loadavg"),
    ("proc.list:version", "/proc/version"),
];

#[mod_main]
fn run(ctx: &Ctx) -> Result<(), CapError> {
    let mut findings = Vec::with_capacity(SOURCES.len());
    for (dedupe_key, path) in SOURCES {
        let bytes = ctx.read_file(path)?;
        let value = String::from_utf8_lossy(&bytes).trim().to_owned();
        findings.push(json!({
            "kind": "inventory",
            "dedupe_key": dedupe_key,
            "severity": 0,
            "data": {"path": path, "value": value},
        }));
    }
    ctx.emit_stdout(&json!({"findings": findings}).to_string());
    Ok(())
}
