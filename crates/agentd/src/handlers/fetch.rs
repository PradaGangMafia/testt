//! Bounded fetch handler.

use super::{Handler, HandlerOutcome};
use async_trait::async_trait;
use serde_cbor::Value;
use std::path::Path;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

/// Hard ceiling for one fetch, independent of the free-disk precheck.
const FETCH_CAP: u64 = 512 * 1024 * 1024;

/// Downloads a URL atomically to its destination.
#[derive(Debug, Default)]
pub struct FetchHandler {
    capabilities: Vec<String>,
}

#[async_trait]
impl Handler for FetchHandler {
    fn name(&self) -> &str {
        "fetch"
    }

    fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    async fn handle(&self, args: &Value) -> HandlerOutcome {
        let Value::Map(map) = args else {
            return HandlerOutcome::failed("fetch args must be a map");
        };
        let text = |key: &str| match map.get(&Value::Text(key.into())) {
            Some(Value::Text(value)) => Some(value.clone()),
            _ => None,
        };
        let (Some(url), Some(dest)) = (text("url"), text("dest")) else {
            return HandlerOutcome::failed("fetch requires url and dest");
        };
        run_fetch(&url, &dest).await
    }
}

/// Fetches `url` and atomically renames it to `dest`.
pub async fn run_fetch(url: &str, dest: &str) -> HandlerOutcome {
    let temp = format!("{dest}.new");
    let result: Result<(), Box<dyn std::error::Error + Send + Sync>> = async {
        if let Some(source) = url.strip_prefix("file://") {
            let size = tokio::fs::metadata(source).await?.len();
            precheck(dest, size).await?;
            let mut input = tokio::fs::File::open(source).await?;
            let mut output = tokio::fs::File::create(&temp).await?;
            tokio::io::copy(&mut input, &mut output).await?;
            output.sync_all().await?;
        } else {
            let response =
                tokio::time::timeout(Duration::from_secs(30), reqwest::get(url)).await??;
            if !response.status().is_success() {
                return Err(format!("HTTP status {}", response.status()).into());
            }
            if let Some(size) = response.content_length() {
                precheck(dest, size).await?;
            }
            let mut output = tokio::fs::File::create(&temp).await?;
            let mut stream = response;
            let mut written = 0_u64;
            while let Some(chunk) = stream.chunk().await? {
                written = written.saturating_add(chunk.len() as u64);
                if written > FETCH_CAP {
                    return Err("fetch exceeds the 512 MiB ceiling".into());
                }
                output.write_all(&chunk).await?;
            }
            output.sync_all().await?;
        }
        tokio::fs::rename(&temp, dest).await?;
        Ok(())
    }
    .await;
    match result {
        Ok(()) => HandlerOutcome {
            ok: true,
            stdout: String::new(),
            stderr: String::new(),
            code: 0,
        },
        Err(error) => {
            let _ = tokio::fs::remove_file(&temp).await;
            HandlerOutcome::failed(error.to_string())
        }
    }
}

async fn precheck(
    dest: &str,
    expected: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if expected > FETCH_CAP {
        return Err(format!("fetch exceeds the 512 MiB ceiling: {expected} bytes").into());
    }
    let parent = Path::new(dest)
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let free = crate::limits::free_disk_bytes(parent)?;
    if free < expected.saturating_mul(2) {
        return Err(format!(
            "insufficient disk: need {}, have {free}",
            expected.saturating_mul(2)
        )
        .into());
    }
    Ok(())
}
