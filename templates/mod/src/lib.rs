//! Agent-Fleet module template.
#![cfg_attr(not(target_arch = "wasm32"), forbid(unsafe_code))]
#![deny(missing_docs)]

//! A module with no capabilities that reports one health finding. Replace the
//! body, update `manifest.toml`, and add capabilities only when the code calls
//! the matching `Ctx` method.

use modsdk::{mod_main, CapError, Ctx};
use serde_json::json;

#[mod_main]
fn run(ctx: &Ctx) -> Result<(), CapError> {
    let subject = ctx
        .args()
        .get("subject")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("template");
    ctx.emit_stdout(
        &json!({
            "findings": [{
                "kind": "health",
                "dedupe_key": format!("template.mod:{subject}"),
                "severity": 0,
                "data": {"subject": subject, "message": "template module ran"},
            }],
        })
        .to_string(),
    );
    Ok(())
}
