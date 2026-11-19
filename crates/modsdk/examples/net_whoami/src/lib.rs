//! Example module: report the address an approved endpoint observes.
#![cfg_attr(not(target_arch = "wasm32"), forbid(unsafe_code))]
#![deny(missing_docs)]

//! The endpoint defaults to `https://api.ipify.org` and can be overridden
//! with the `url` argument so tests can point at a local server.

use modsdk::{mod_main, CapError, Ctx};
use serde_json::json;

#[mod_main]
fn run(ctx: &Ctx) -> Result<(), CapError> {
    let endpoint = ctx
        .args()
        .get("url")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("https://api.ipify.org");
    let body = ctx.http_get(endpoint)?;
    let observed = String::from_utf8_lossy(&body).trim().to_owned();
    ctx.emit_stdout(
        &json!({
            "findings": [{
                "kind": "inventory",
                "dedupe_key": format!("net.whoami:{endpoint}"),
                "severity": 0,
                "data": {"endpoint": endpoint, "observed": observed},
            }],
        })
        .to_string(),
    );
    Ok(())
}
