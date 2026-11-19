//! Example module: bounded inventory of explicitly named files.
#![cfg_attr(not(target_arch = "wasm32"), forbid(unsafe_code))]
#![deny(missing_docs)]

//! The ABI exposes `read_file` rather than directory listing, so the module
//! takes an explicit `paths` array. Each readable path becomes one finding.

use modsdk::{mod_main, CapError, Ctx};
use serde_json::json;

/// Default inventory target when the task supplies no `paths`.
const DEFAULT_PATH: &str = "/etc/hostname";

#[mod_main]
fn run(ctx: &Ctx) -> Result<(), CapError> {
    let paths: Vec<String> = match ctx.args().get("paths").and_then(|value| value.as_array()) {
        Some(values) => values
            .iter()
            .filter_map(|value| value.as_str().map(str::to_owned))
            .collect(),
        None => vec![DEFAULT_PATH.to_owned()],
    };
    let mut findings = Vec::with_capacity(paths.len());
    for path in paths {
        let bytes = ctx.read_file(&path)?;
        let preview = String::from_utf8_lossy(&bytes)
            .lines()
            .next()
            .unwrap_or_default()
            .to_owned();
        findings.push(json!({
            "kind": "inventory",
            "dedupe_key": format!("fs.tree:{path}"),
            "severity": 0,
            "data": {"path": path, "bytes": bytes.len(), "first_line": preview},
        }));
    }
    ctx.emit_stdout(&json!({"findings": findings}).to_string());
    Ok(())
}
