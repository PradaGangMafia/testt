//! Bounded shell handler.

use super::{Handler, HandlerOutcome};
use async_trait::async_trait;
use serde_cbor::Value;
use std::time::Duration;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::{Child, Command},
    time::timeout,
};

const OUTPUT_CAP: usize = 64 * 1024;

/// Unregisters a child process group when its handler invocation ends.
struct GroupGuard(Option<u32>);

impl Drop for GroupGuard {
    fn drop(&mut self) {
        if let Some(pgid) = self.0 {
            super::unregister_process_group(pgid);
        }
    }
}

/// Runs bounded process commands.
#[derive(Debug, Default)]
pub struct ShellHandler {
    capabilities: Vec<String>,
}

#[async_trait]
impl Handler for ShellHandler {
    fn name(&self) -> &str {
        "shell"
    }

    fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    async fn handle(&self, args: &Value) -> HandlerOutcome {
        let Value::Map(map) = args else {
            return HandlerOutcome::failed("shell args must be a map");
        };
        let get = |key: &str| map.get(&Value::Text(key.into()));
        let argv = match get("argv") {
            Some(Value::Array(values)) => values
                .iter()
                .map(|value| match value {
                    Value::Text(text) => Some(text.clone()),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>(),
            _ => None,
        };
        let Some(argv) = argv else {
            return HandlerOutcome::failed("shell argv must be an array of strings");
        };
        let timeout_s = match get("timeout_s") {
            Some(Value::Integer(value)) => u16::try_from(*value).unwrap_or(60),
            _ => 60,
        };
        let shell = matches!(get("shell"), Some(Value::Bool(true)));
        run_shell(argv, timeout_s, shell).await
    }
}

async fn read_capped<R: AsyncRead + Unpin>(reader: R) -> (String, bool) {
    let mut bytes = Vec::with_capacity(OUTPUT_CAP + 1);
    let mut limited = reader.take((OUTPUT_CAP + 1) as u64);
    let _ = limited.read_to_end(&mut bytes).await;
    let truncated = bytes.len() > OUTPUT_CAP;
    if truncated {
        bytes.truncate(OUTPUT_CAP);
    }
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if truncated {
        text.push_str("...");
    }
    (text, truncated)
}

async fn finish_child(mut child: Child, timeout_s: u16) -> HandlerOutcome {
    let stdout_task = child
        .stdout
        .take()
        .map(|reader| tokio::spawn(read_capped(reader)));
    let stderr_task = child
        .stderr
        .take()
        .map(|reader| tokio::spawn(read_capped(reader)));
    let status = match timeout(Duration::from_secs(timeout_s.into()), child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(error)) => return HandlerOutcome::failed(error.to_string()),
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return HandlerOutcome::failed("timeout");
        }
    };
    let (stdout, stdout_truncated) = match stdout_task {
        Some(task) => task.await.unwrap_or((String::new(), false)),
        None => (String::new(), false),
    };
    let (stderr, stderr_truncated) = match stderr_task {
        Some(task) => task.await.unwrap_or((String::new(), false)),
        None => (String::new(), false),
    };
    let code = status.code().unwrap_or(-1);
    HandlerOutcome {
        ok: status.success() && !stdout_truncated && !stderr_truncated,
        stdout,
        stderr,
        code,
    }
}

/// Runs a command with a bounded wall-clock timeout and bounded output.
pub async fn run_shell(argv: Vec<String>, timeout_s: u16, shell: bool) -> HandlerOutcome {
    if argv.is_empty() {
        return HandlerOutcome::failed("empty argv");
    }
    let mut command = if shell {
        let mut command = Command::new("sh");
        command.arg("-c").arg(argv.join(" "));
        command
    } else {
        let mut command = Command::new(&argv[0]);
        command.args(&argv[1..]);
        command
    };
    #[cfg(unix)]
    command.process_group(0);
    match command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(child) => {
            let pgid = child.id();
            if let Some(pgid) = pgid {
                super::register_process_group(pgid);
            }
            let _guard = GroupGuard(pgid);
            finish_child(child, timeout_s).await
        }
        Err(error) => HandlerOutcome::failed(error.to_string()),
    }
}
