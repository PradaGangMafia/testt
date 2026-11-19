//! Liveness handler.

use super::{Handler, HandlerOutcome};
use async_trait::async_trait;
use serde_cbor::Value;

/// Answers a liveness probe without touching the host.
#[derive(Debug, Default)]
pub struct PingHandler {
    capabilities: Vec<String>,
}

#[async_trait]
impl Handler for PingHandler {
    fn name(&self) -> &str {
        "ping"
    }

    fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    async fn handle(&self, _args: &Value) -> HandlerOutcome {
        HandlerOutcome {
            ok: true,
            stdout: String::new(),
            stderr: String::new(),
            code: 0,
        }
    }
}
