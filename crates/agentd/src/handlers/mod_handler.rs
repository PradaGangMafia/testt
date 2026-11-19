//! Installed-module handler.

use super::{Handler, HandlerOutcome};
use crate::plugins::{cbor_to_json, CapabilityPolicy, Limits, ModStore, WasmHost};
use async_trait::async_trait;
use serde_cbor::Value;
use std::{fs, path::PathBuf, sync::Arc};
use tokio::sync::Mutex;

/// Runs an installed module through the capability-gated Wasm host.
pub struct ModHandler {
    store: Arc<Mutex<ModStore>>,
    policy: CapabilityPolicy,
    limits: Limits,
    state: PathBuf,
    capabilities: Vec<String>,
}

impl ModHandler {
    /// Creates a module handler sharing the daemon's store and policy.
    pub fn new(
        store: Arc<Mutex<ModStore>>,
        policy: CapabilityPolicy,
        limits: Limits,
        state: PathBuf,
    ) -> Self {
        Self {
            store,
            policy,
            limits,
            state,
            capabilities: Vec::new(),
        }
    }
}

#[async_trait]
impl Handler for ModHandler {
    fn name(&self) -> &str {
        "mod"
    }

    fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    async fn handle(&self, args: &Value) -> HandlerOutcome {
        let Value::Map(map) = args else {
            return HandlerOutcome::failed("mod args must be a map");
        };
        let text = |key: &str| match map.get(&Value::Text(key.into())) {
            Some(Value::Text(value)) => Some(value.clone()),
            _ => None,
        };
        let (Some(mod_id), Some(version)) = (text("mod_id"), text("version")) else {
            return HandlerOutcome::failed("mod requires mod_id and version");
        };
        let cbor_args = map
            .get(&Value::Text("args".into()))
            .cloned()
            .unwrap_or(Value::Map(Default::default()));
        let json_args = match cbor_to_json(&cbor_args) {
            Ok(value) => value,
            Err(error) => return HandlerOutcome::failed(error),
        };
        let path = {
            let store = self.store.lock().await;
            match store.get(&mod_id, &version) {
                Some(installed) => installed.path.clone(),
                None => {
                    return HandlerOutcome::failed(format!(
                        "unknown or disabled module {mod_id}@{version}"
                    ))
                }
            }
        };
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) => return HandlerOutcome::failed(error.to_string()),
        };
        let host = match WasmHost::with_state(self.state.clone(), self.policy.clone()) {
            Ok(host) => host.with_limits(self.limits),
            Err(error) => return HandlerOutcome::failed(error.to_string()),
        };
        match host.run(&bytes, &json_args).await {
            Ok(outcome) => outcome,
            Err(error) => HandlerOutcome::failed(error.to_string()),
        }
    }
}
