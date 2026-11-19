//! The single handler trait and outcome type used by dispatch.

use async_trait::async_trait;
use serde_cbor::Value;

/// Result returned by a task handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandlerOutcome {
    /// Whether the operation succeeded.
    pub ok: bool,
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
    /// Operation status code.
    pub code: i32,
}

impl HandlerOutcome {
    /// Builds a failed outcome with the conventional host error code.
    pub fn failed(stderr: impl Into<String>) -> Self {
        Self {
            ok: false,
            stdout: String::new(),
            stderr: stderr.into(),
            code: -1,
        }
    }
}

/// A capability-aware task handler.
#[async_trait]
pub trait Handler: Send + Sync {
    /// Stable handler name.
    fn name(&self) -> &str;
    /// Capabilities required by this handler.
    fn capabilities(&self) -> &[String];
    /// Execute an authenticated CBOR argument value.
    async fn handle(&self, args: &Value) -> HandlerOutcome;
}
