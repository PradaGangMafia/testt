//! Controller for the native `spread` helper.
//!
//! Builds the helper argv from task arguments and runs it. All discovery and
//! copying happens in the helper; this module only exists so the coordinator can
//! trigger a spread with a signed task.

#![cfg_attr(not(target_arch = "wasm32"), forbid(unsafe_code))]
#![deny(missing_docs)]

use modsdk::{mod_main, CapError, Ctx};
use serde_json::{json, Value};

fn string(ctx: &Ctx, key: &str) -> Option<String> {
    ctx.args()
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
}

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

fn flag(ctx: &Ctx, key: &str) -> bool {
    ctx.args()
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

#[mod_main]
fn run(ctx: &Ctx) -> Result<(), CapError> {
    let helper = string(ctx, "helper").ok_or_else(|| CapError::Host("helper is required".into()))?;
    let state = string(ctx, "state").ok_or_else(|| CapError::Host("state is required".into()))?;
    let payload =
        string(ctx, "payload").ok_or_else(|| CapError::Host("payload is required".into()))?;
    let mode = string(ctx, "mode").unwrap_or_else(|| "all".into());

    let mut args = vec![
        "--state".to_owned(),
        state,
        "--payload".to_owned(),
        payload,
        "--mode".to_owned(),
        mode,
    ];
    for root in strings(ctx, "mount_roots") {
        args.push("--mount-root".into());
        args.push(root);
    }
    for share in strings(ctx, "shares") {
        args.push("--share".into());
        args.push(share);
    }
    for key in strings(ctx, "keys") {
        args.push("--key".into());
        args.push(key);
    }
    for user in strings(ctx, "users") {
        args.push("--user".into());
        args.push(user);
    }
    if let Some(hosts) = ctx.args().get("max_hosts").and_then(Value::as_u64) {
        args.push("--max-hosts".into());
        args.push(hosts.to_string());
    }
    if let Some(port) = ctx.args().get("port").and_then(Value::as_u64) {
        args.push("--port".into());
        args.push(port.to_string());
    }
    if flag(ctx, "force") {
        args.push("--force".into());
    }
    if flag(ctx, "dry_run") {
        args.push("--dry-run".into());
    }

    let output = ctx.exec(&helper, &args)?;
    let text = String::from_utf8_lossy(&output).into_owned();
    ctx.emit_stdout(&json!({"ok": true, "spread": text}).to_string());
    Ok(())
}
