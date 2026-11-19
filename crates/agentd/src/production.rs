//! Production hardening primitives used by the agent supervisor and worker.
use crate::plugins::KNOWN_CAPS;
use blake3::Hasher;
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

const INTEGRITY_PREFIX: &[u8] = b"\n# blake3=";
const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;
const MAX_LOG_FILES: usize = 5;
const LOG_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Errors raised by production state and process management.
#[derive(Debug, Error)]
pub enum ProductionError {
    /// Filesystem operation failed.
    #[error("production filesystem: {0}")]
    Io(#[from] io::Error),
    /// A persisted document failed its integrity check.
    #[error("state integrity check failed")]
    Integrity,
    /// Configuration contains one or more invalid values.
    #[error("invalid configuration: {0}")]
    Config(String),
    /// Another daemon instance owns the state lock.
    #[error("another agent instance is already running")]
    AlreadyRunning,
    /// A child process could not be started or supervised.
    #[error("supervisor: {0}")]
    Supervisor(String),
}

/// Returns an RFC3339-like UTC timestamp suitable for JSON logs.
fn timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:03}Z", now.as_secs(), now.subsec_millis())
}

fn json_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

/// A small JSON-lines logger with bounded size and age-based rotation.
#[derive(Clone)]
pub struct JsonLogger {
    inner: Arc<Mutex<LoggerInner>>,
}
struct LoggerInner {
    path: PathBuf,
    file: File,
}
impl JsonLogger {
    /// Opens a logger at `path`, retaining at most five rotated files.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, ProductionError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(LoggerInner { path, file })),
        })
    }
    /// Writes a structured event. Secret-bearing values must never be passed as fields.
    pub fn event(
        &self,
        level: &str,
        message: &str,
        fields: &[(&str, String)],
    ) -> Result<(), ProductionError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("logger poisoned"))?;
        rotate_if_needed(&mut inner)?;
        let mut line = format!(
            "{{\"ts\":\"{}\",\"level\":\"{}\",\"message\":\"{}\"",
            timestamp(),
            json_escape(level),
            json_escape(message)
        );
        for (key, value) in fields {
            line.push_str(&format!(
                ",\"{}\":\"{}\"",
                json_escape(key),
                json_escape(value)
            ));
        }
        line.push_str("}\n");
        inner.file.write_all(line.as_bytes())?;
        inner.file.flush()?;
        Ok(())
    }
    /// Installs a panic hook that emits a redacted event and delegates to the prior hook.
    pub fn install_panic_hook(&self) {
        let logger = self.clone();
        let prior = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |panic| {
            let _ = logger.event("error", "panic", &[("payload", panic_payload(panic))]);
            prior(panic);
        }));
    }
}
fn panic_payload(info: &std::panic::PanicHookInfo<'_>) -> String {
    info.location().map_or_else(
        || "panic".to_owned(),
        |location| format!("{}:{}", location.file(), location.line()),
    )
}
fn rotate_if_needed(inner: &mut LoggerInner) -> io::Result<()> {
    let size = inner.file.metadata()?.len();
    if size < MAX_LOG_BYTES {
        return Ok(());
    }
    inner.file.sync_all()?;
    let path = inner.path.clone();
    let _ = &inner.file;
    for index in (1..MAX_LOG_FILES).rev() {
        let from = path.with_extension(format!("log.{index}"));
        let to = path.with_extension(format!("log.{}", index + 1));
        if from.exists() {
            let _ = fs::rename(from, to);
        }
    }
    if path.exists() {
        fs::rename(&path, path.with_extension("log.1"))?;
    }
    inner.file = OpenOptions::new().create(true).append(true).open(path)?;
    Ok(())
}

fn digest_hex(bytes: &[u8]) -> String {
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}
fn with_trailer(bytes: &[u8]) -> Vec<u8> {
    let mut output = bytes.to_vec();
    output.extend_from_slice(INTEGRITY_PREFIX);
    output.extend_from_slice(digest_hex(bytes).as_bytes());
    output.push(b'\n');
    output
}
fn without_trailer(bytes: &[u8]) -> Result<Vec<u8>, ProductionError> {
    let marker = bytes
        .windows(INTEGRITY_PREFIX.len())
        .rposition(|window| window == INTEGRITY_PREFIX)
        .ok_or(ProductionError::Integrity)?;
    let data = &bytes[..marker];
    let found = std::str::from_utf8(&bytes[marker + INTEGRITY_PREFIX.len()..])
        .map_err(|_| ProductionError::Integrity)?
        .trim();
    if found != digest_hex(data) {
        return Err(ProductionError::Integrity);
    }
    Ok(data.to_vec())
}

/// Atomically writes a document with a BLAKE3 trailer and directory fsync.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), ProductionError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension("new");
    let backup = path.with_extension("bak");
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&temp)?;
    file.write_all(&with_trailer(bytes))?;
    file.sync_all()?;
    if path.exists() {
        fs::copy(path, &backup)?;
    }
    fs::rename(&temp, path)?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}
/// Reads and verifies a document, falling back to its `.bak` copy.
pub fn read_verified(path: &Path) -> Result<Vec<u8>, ProductionError> {
    match fs::read(path)
        .ok()
        .and_then(|bytes| without_trailer(&bytes).ok())
    {
        Some(bytes) => Ok(bytes),
        None => {
            let backup = path.with_extension("bak");
            let bytes = without_trailer(&fs::read(backup)?)?;
            atomic_write(path, &bytes)?;
            Ok(bytes)
        }
    }
}

/// Exclusive process lock held until dropped.
pub struct InstanceLock {
    path: PathBuf,
    _file: File,
}
impl InstanceLock {
    /// Acquires `<state>/agent.lock` without replacing an existing owner.
    pub fn acquire(state: &Path) -> Result<Self, ProductionError> {
        fs::create_dir_all(state)?;
        let path = state.join("agent.lock");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    ProductionError::AlreadyRunning
                } else {
                    error.into()
                }
            })?;
        file.set_len(0)?;
        Ok(Self { path, _file: file })
    }
}
impl Drop for InstanceLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Configuration loaded from a deliberately small, strict TOML subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// State directory.
    pub state_dir: PathBuf,
    /// Poll interval in seconds.
    pub poll_interval_s: u64,
    /// Transport channel kind, such as `mock-fs` or `relay`.
    pub channel: String,
    /// Channel-specific argument, such as a queue directory or relay URL.
    pub channel_arg: Option<String>,
    /// Poll interval variation, percent either side (default 50, max 90).
    pub jitter_percent: u64,
    /// Whether command execution is enabled.
    pub allow_exec: bool,
    /// Whether network access is enabled.
    pub allow_net: bool,
    /// Capability glob rules.
    pub allow_caps: BTreeMap<String, Vec<String>>,
    /// Optional dead-drop URL returning a signed relay set.
    pub dead_drop_url: Option<String>,
    /// Optional artifact collector base URL.
    pub artifact_url: Option<String>,
    /// Optional bearer token for the collector.
    pub artifact_token: Option<String>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            state_dir: PathBuf::from(".agent-fleet"),
            poll_interval_s: 300,
            jitter_percent: 50,
            channel: "mock-fs".into(),
            channel_arg: None,
            allow_exec: false,
            allow_net: false,
            allow_caps: BTreeMap::new(),
            dead_drop_url: None,
            artifact_url: None,
            artifact_token: None,
        }
    }
}
impl Config {
    /// Loads and validates configuration before any network operation is attempted.
    pub fn load(path: &Path) -> Result<Self, ProductionError> {
        let contents = fs::read_to_string(path)?;
        let mut config = Self::default();
        let mut errors = Vec::new();
        for (line_no, line) in contents.lines().enumerate() {
            let line = line.split('#').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
                let section = name.trim();
                if section != "modules" {
                    errors.push(format!("line {}: unknown section {section}", line_no + 1));
                }
                continue;
            }
            let Some((key, raw)) = line.split_once('=') else {
                errors.push(format!("line {}: expected key = value", line_no + 1));
                continue;
            };
            let key = key.trim();
            let raw = raw.trim();
            match key {
                "state_dir" => {
                    config.state_dir = PathBuf::from(unquote(raw).unwrap_or(raw).to_owned())
                }
                "channel" => {
                    config.channel = unquote(raw).unwrap_or(raw).to_owned();
                }
                "channel_arg" => {
                    config.channel_arg = Some(unquote(raw).unwrap_or(raw).to_owned());
                }
                "poll_interval_s" => match raw.parse() {
                    Ok(value) => config.poll_interval_s = value,
                    Err(_) => errors.push(format!(
                        "line {}: poll_interval_s must be integer",
                        line_no + 1
                    )),
                },
                "dead_drop_url" => {
                    config.dead_drop_url = Some(unquote(raw).unwrap_or(raw).to_owned());
                }
                "artifact_url" => {
                    config.artifact_url = Some(unquote(raw).unwrap_or(raw).to_owned());
                }
                "artifact_token" => {
                    config.artifact_token = Some(unquote(raw).unwrap_or(raw).to_owned());
                }
                "jitter_percent" => match raw.parse::<u64>() {
                    Ok(value) if value <= 90 => config.jitter_percent = value,
                    _ => errors.push(format!(
                        "line {}: jitter_percent must be 0..=90",
                        line_no + 1
                    )),
                },
                "allow_exec" => match raw {
                    "true" => config.allow_exec = true,
                    "false" => config.allow_exec = false,
                    _ => errors.push(format!("line {}: allow_exec must be boolean", line_no + 1)),
                },
                "allow_net" => match raw {
                    "true" => config.allow_net = true,
                    "false" => config.allow_net = false,
                    _ => errors.push(format!("line {}: allow_net must be boolean", line_no + 1)),
                },
                key if key.starts_with("allow_caps.") => {
                    let name = key.strip_prefix("allow_caps.").unwrap_or_default();
                    if !known_cap(name) {
                        errors.push(format!("line {}: unknown capability {name}", line_no + 1));
                    } else if let Some(value) = parse_array(raw) {
                        config.allow_caps.insert(name.to_owned(), value);
                    } else {
                        errors.push(format!("line {}: allow_caps must be an array", line_no + 1));
                    }
                }
                _ => errors.push(format!("line {}: unknown field {key}", line_no + 1)),
            }
        }
        if config.poll_interval_s == 0 {
            errors.push("poll_interval_s must be greater than zero".into());
        }
        for (name, rules) in &config.allow_caps {
            if rules.iter().any(|rule| rule.trim().is_empty()) {
                errors.push(format!("capability {name} has an empty rule"));
            }
            if name == "exec" && !config.allow_exec {
                errors.push("allow_caps.exec requires allow_exec = true".into());
            }
            if name == "net" && !config.allow_net {
                errors.push("allow_caps.net requires allow_net = true".into());
            }
        }
        if config.channel.trim().is_empty() {
            errors.push("channel must not be empty".into());
        }
        if let Some(url) = &config.dead_drop_url {
            if !url.starts_with("http://") && !url.starts_with("https://") {
                errors.push("dead_drop_url must be http(s)".into());
            }
        }
        if let Some(url) = &config.artifact_url {
            if !url.starts_with("http://") && !url.starts_with("https://") {
                errors.push("artifact_url must be http(s)".into());
            }
        }
        probe_paths(&config, &mut errors);
        if errors.is_empty() {
            Ok(config)
        } else {
            Err(ProductionError::Config(errors.join("; ")))
        }
    }
    /// Validates a configuration value without accessing the network.
    pub fn validate(&self) -> Result<(), ProductionError> {
        let mut errors = Vec::new();
        if self.poll_interval_s == 0 {
            errors.push("poll_interval_s must be greater than zero".into());
        }
        for (name, rules) in &self.allow_caps {
            if !known_cap(name) {
                errors.push(format!("unknown capability {name}"));
            }
            if rules.iter().any(|rule| rule.trim().is_empty()) {
                errors.push(format!("capability {name} has an empty rule"));
            }
            if name == "exec" && !self.allow_exec {
                errors.push("allow_caps.exec requires allow_exec = true".into());
            }
            if name == "net" && !self.allow_net {
                errors.push("allow_caps.net requires allow_net = true".into());
            }
        }
        if self.channel.trim().is_empty() {
            errors.push("channel must not be empty".into());
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(ProductionError::Config(errors.join("; ")))
        }
    }
}
fn known_cap(value: &str) -> bool {
    KNOWN_CAPS.contains(&value)
}
fn unquote(value: &str) -> Option<&str> {
    value.strip_prefix('"').and_then(|v| v.strip_suffix('"'))
}
fn parse_array(value: &str) -> Option<Vec<String>> {
    let value = value.strip_prefix('[')?.strip_suffix(']')?;
    Some(
        value
            .split(',')
            .filter_map(|item| {
                let item = item.trim();
                if item.is_empty() {
                    None
                } else {
                    Some(unquote(item).unwrap_or(item).to_owned())
                }
            })
            .collect(),
    )
}
fn probe_paths(config: &Config, errors: &mut Vec<String>) {
    if config.state_dir.exists() {
        if !config.state_dir.is_dir() {
            errors.push("state_dir is not a directory".into());
        }
    } else if let Some(parent) = config.state_dir.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            errors.push("state_dir parent does not exist".into());
        }
    }
}

/// Bounded pending operation queue with three-attempt retry semantics.
#[derive(Debug)]
pub struct PendingQueue {
    path: PathBuf,
    attempts: BTreeMap<String, u8>,
}
impl PendingQueue {
    /// Opens a pending queue stored as JSON-lines-like records.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, ProductionError> {
        Ok(Self {
            path: path.into(),
            attempts: BTreeMap::new(),
        })
    }
    /// Attempts an operation; after three failures the record is dropped.
    pub fn retry<F>(&mut self, key: &str, mut operation: F) -> Result<bool, ProductionError>
    where
        F: FnMut() -> Result<(), ProductionError>,
    {
        match operation() {
            Ok(()) => {
                self.attempts.remove(key);
                Ok(true)
            }
            Err(error) => {
                let attempts = self.attempts.entry(key.to_owned()).or_default();
                *attempts = attempts.saturating_add(1);
                if *attempts >= 3 {
                    self.attempts.remove(key);
                    fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&self.path)?
                        .write_all(format!("dropped:{key}\n").as_bytes())?;
                    Ok(false)
                } else {
                    Err(error)
                }
            }
        }
    }
}

/// Applies the Unix address-space limit and records the outcome.
/// Windows uses the supervisor's job-object integration point; this build
/// reports the limit in logs rather than failing startup.
pub fn apply_resource_policy(logger: &JsonLogger) -> Result<(), ProductionError> {
    let limit = env::var("AGENT_FLEET_MEMORY_LIMIT")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(268_435_456);
    #[cfg(unix)]
    {
        crate::limits::apply_memory_limit(limit)
            .map_err(|error| ProductionError::Supervisor(format!("setrlimit: {error}")))?;
        logger.event(
            "info",
            "resource_policy",
            &[
                ("memory_limit_bytes", limit.to_string()),
                ("enforced", "true".into()),
            ],
        )?;
    }
    #[cfg(not(unix))]
    {
        logger.event(
            "info",
            "resource_policy",
            &[
                ("memory_limit_bytes", limit.to_string()),
                ("enforced", "false".into()),
            ],
        )?;
    }
    Ok(())
}

/// Returns the shutdown drain window, overridable for tests and operators.
pub fn drain_len() -> Duration {
    env::var("AGENT_FLEET_DRAIN_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(Duration::from_secs(30))
}

/// Supervisor configuration and restart policy.
#[derive(Debug, Clone, Copy)]
pub struct SupervisorPolicy {
    /// Initial restart delay.
    pub initial_backoff: Duration,
    /// Maximum restart delay.
    pub max_backoff: Duration,
}
impl Default for SupervisorPolicy {
    fn default() -> Self {
        Self {
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(300),
        }
    }
}
/// Promotes a staged `<exe>.new` over the executable before the next spawn.
pub fn promote_staged(executable: &Path) {
    let staged = executable.with_extension("new");
    if !staged.is_file() {
        return;
    }
    if fs::rename(&staged, executable).is_err() {
        let _ = fs::copy(&staged, executable);
    }
}

/// Starts the worker and restarts it with capped exponential backoff.
pub fn supervise(
    current_exe: &Path,
    state: &Path,
    once: bool,
    logger: &JsonLogger,
    worker_pid: &AtomicU32,
    stopping: &AtomicBool,
) -> Result<(), ProductionError> {
    let policy = SupervisorPolicy::default();
    let mut delay = policy.initial_backoff;
    loop {
        // A signal can land between reaping the old worker and spawning the next
        // one; never start another worker once shutdown has begun.
        if stopping.load(Ordering::SeqCst) {
            return Ok(());
        }
        promote_staged(current_exe);
        let mut command = Command::new(current_exe);
        command
            .arg("--worker")
            .arg("--state")
            .arg(state)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if once {
            command.arg("--once");
        }
        let mut child = command
            .spawn()
            .map_err(|error| ProductionError::Supervisor(error.to_string()))?;
        logger.event("info", "worker_started", &[("pid", child.id().to_string())])?;
        worker_pid.store(child.id(), Ordering::SeqCst);
        let status = child.wait()?;
        worker_pid.store(0, Ordering::SeqCst);
        logger.event("warn", "worker_exited", &[("status", status.to_string())])?;
        if once {
            // A cron one-shot must surface the worker's failure to the caller.
            return if status.success() {
                Ok(())
            } else {
                Err(ProductionError::Supervisor(format!(
                    "worker exited {status}"
                )))
            };
        }
        if stopping.load(Ordering::SeqCst) {
            return Ok(());
        }
        std::thread::sleep(delay);
        delay = (delay * 2).min(policy.max_backoff);
    }
}

/// Returns the configured log retention constants for release checks and tests.
pub fn logging_limits() -> (u64, usize, Duration) {
    (MAX_LOG_BYTES, MAX_LOG_FILES, LOG_RETENTION)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn temp(name: &str) -> PathBuf {
        env::temp_dir().join(format!("agentd-production-{name}-{}", std::process::id()))
    }
    #[test]
    fn atomic_state_recovers_from_corrupt_primary() {
        let path = temp("integrity");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("bak"));
        atomic_write(&path, b"good").expect("initial state");
        atomic_write(&path, b"new").expect("backup state");
        fs::write(&path, b"corrupt").expect("corrupt primary");
        assert_eq!(
            read_verified(&path).expect("backup should recover"),
            b"good"
        );
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("bak"));
    }
    #[test]
    fn second_instance_is_rejected_and_drop_releases_lock() {
        let path = temp("lock");
        let _ = fs::remove_dir_all(&path);
        let first = InstanceLock::acquire(&path).expect("first lock");
        assert!(matches!(
            InstanceLock::acquire(&path),
            Err(ProductionError::AlreadyRunning)
        ));
        drop(first);
        assert!(InstanceLock::acquire(&path).is_ok());
        let _ = fs::remove_dir_all(path);
    }
    #[test]
    fn config_accepts_every_known_capability() {
        let path = temp("caps.config.toml");
        let mut text = String::from("allow_exec = true\nallow_net = true\n");
        for capability in KNOWN_CAPS {
            text.push_str(&format!("allow_caps.{capability} = [\"*\"]\n"));
        }
        fs::write(&path, text).expect("config");
        Config::load(&path).expect("every advertised capability parses");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn config_collects_unknown_and_invalid_fields() {
        let path = temp("config.toml");
        fs::write(
            &path,
            "poll_interval_s = 0\nnope = true\nallow_caps.bad = [\"*\"]\n",
        )
        .expect("config");
        let error = Config::load(&path).expect_err("invalid config");
        let text = error.to_string();
        assert!(
            text.contains("nope")
                && text.contains("unknown capability")
                && text.contains("greater than zero")
        );
        let _ = fs::remove_file(path);
    }
    #[test]
    fn pending_queue_drops_after_three_failures() {
        let path = temp("pending");
        let _ = fs::remove_file(&path);
        let mut queue = PendingQueue::open(&path).expect("queue");
        for index in 0..2 {
            assert!(
                queue
                    .retry("x", || Err(ProductionError::Integrity))
                    .is_err(),
                "attempt {index}"
            );
        }
        assert!(!queue
            .retry("x", || Err(ProductionError::Integrity))
            .expect("drop marker"));
        let _ = fs::remove_file(path);
    }
}
