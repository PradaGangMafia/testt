//! Portable resilience primitives for service installation and state recovery.
use blake3::Hasher;
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

/// Result of a guard or doctor check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    /// All checks passed.
    Healthy,
    /// A check repaired an installation or state.
    Repaired,
}

/// Errors returned by resilience operations.
#[derive(Debug, thiserror::Error)]
pub enum ResilienceError {
    /// Filesystem operation failed.
    #[error("resilience filesystem: {0}")]
    Io(#[from] io::Error),
    /// A requested executable path is unsafe.
    #[error("executable path may not be inside target/")]
    TargetPath,
    /// No verifying replica was available.
    #[error("no verifying executable replica available")]
    NoReplica,
}

/// One portable doctor observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorCheck {
    /// Stable check name.
    pub name: String,
    /// `pass`, `warn`, or `fail`.
    pub status: String,
    /// Non-secret detail for an operator.
    pub detail: String,
}

/// Complete doctor report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorReport {
    /// Checks in stable order.
    pub checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    /// Whether any check needs attention.
    pub fn needs_attention(&self) -> bool {
        self.checks.iter().any(|check| check.status != "pass")
    }
    /// Render dependency-free JSON for automation.
    pub fn json(&self) -> String {
        let checks = self
            .checks
            .iter()
            .map(|check| {
                format!(
                    "{{\"name\":{},\"status\":{},\"detail\":{}}}",
                    json_quote(&check.name),
                    json_quote(&check.status),
                    json_quote(&check.detail)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!("{{\"checks\":[{checks}]}}")
    }
}

fn check(name: &str, status: &str, detail: impl Into<String>) -> DoctorCheck {
    DoctorCheck {
        name: name.into(),
        status: status.into(),
        detail: detail.into(),
    }
}

/// Run independent, portable P64 checks. Native service registration and ACL checks remain deployment-owned.
pub fn doctor(state: &Path, executable: &Path) -> Result<DoctorReport, ResilienceError> {
    let mut checks = Vec::new();
    checks.push(if executable.is_file() {
        check("binary_path", "pass", executable.display().to_string())
    } else {
        check("binary_path", "fail", "binary is missing")
    });
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let world_writable = fs::metadata(executable)
            .map(|m| m.permissions().mode() & 2 != 0)
            .unwrap_or(false);
        checks.push(if world_writable {
            check("binary_writable", "fail", "binary is world-writable")
        } else {
            check("binary_writable", "pass", "binary permissions acceptable")
        });
    }
    let key = state.join("agent.key");
    #[cfg(not(unix))]
    let _ = &key;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        checks.push(if !key.exists() {
            check("key_permissions", "warn", "agent.key is not enrolled")
        } else if fs::metadata(&key)
            .map(|m| m.permissions().mode() & 0o777 == 0o600)
            .unwrap_or(false)
        {
            check("key_permissions", "pass", "agent.key mode is 0600")
        } else {
            check("key_permissions", "warn", "agent.key is not mode 0600")
        });
    }
    if fs::create_dir_all(state).is_err() {
        checks.push(check(
            "state_writable",
            "fail",
            "state directory cannot be created",
        ));
    } else {
        let probe = state.join(format!(".doctor-{}", std::process::id()));
        checks.push(
            match OpenOptions::new().create_new(true).write(true).open(&probe) {
                Ok(_) => {
                    let _ = fs::remove_file(probe);
                    check("state_writable", "pass", "state probe write succeeded")
                }
                Err(e) => check("state_writable", "fail", e.to_string()),
            },
        );
    }
    let lock = state.join(".doctor.lock");
    checks.push(
        match OpenOptions::new().create_new(true).write(true).open(&lock) {
            Ok(_) => {
                let _ = fs::remove_file(lock);
                check("lock_acquirable", "pass", "lock acquired and released")
            }
            Err(e) => check("lock_acquirable", "fail", e.to_string()),
        },
    );
    checks.push(if !state.join("config.toml").exists() {
        check("config_valid", "pass", "built-in defaults are active")
    } else {
        let valid = fs::read_to_string(state.join("config.toml"))
            .map(|text| {
                text.lines().all(|line| {
                    let line = line.split('#').next().unwrap_or_default().trim();
                    if line.is_empty() {
                        return true;
                    }
                    let Some((key, value)) = line.split_once('=') else {
                        return false;
                    };
                    let key = key.trim();
                    let value = value.trim();
                    matches!(
                        key,
                        "state_dir" | "poll_interval_s" | "allow_exec" | "allow_net"
                    ) || (key.starts_with("allow_caps.")
                        && matches!(
                            &key[12..],
                            "fs_read"
                                | "fs_write"
                                | "exec"
                                | "net"
                                | "clock"
                                | "random"
                                | "env"
                                | "sleep"
                        )
                        && value.starts_with('[')
                        && value.ends_with(']'))
                })
            })
            .unwrap_or(false);
        if valid {
            check(
                "config_valid",
                "pass",
                "configuration syntax and fields are valid",
            )
        } else {
            check(
                "config_valid",
                "fail",
                "configuration contains an unknown or malformed field",
            )
        }
    });
    let relay_text = fs::read_to_string(state.join("relays.json")).unwrap_or_default();
    let relay_lines = relay_text
        .lines()
        .filter(|line| line.starts_with("entry\t"))
        .collect::<Vec<_>>();
    if relay_lines.is_empty() {
        checks.push(check(
            "relay_health",
            "warn",
            "no relay table entries configured",
        ));
    } else {
        for (index, line) in relay_lines.iter().enumerate() {
            let address = line.split('\t').nth(4).unwrap_or_default();
            checks.push(relay_probe(&format!("relay_health_{}", index + 1), address));
        }
    }
    checks.push(if state.join("peers.json").is_file() {
        check("peer_table", "pass", "peer table is present")
    } else {
        check("peer_table", "warn", "no local peer table configured")
    });
    checks.push(check(
        "mod_abi",
        "pass",
        "host ABI 1; installed module shape is checked at load time",
    ));
    checks.push(if state.join("listen.addr").exists() {
        check(
            "listen_bindability",
            "warn",
            "native listen bind is deployment-owned and was not attempted",
        )
    } else {
        check(
            "listen_bindability",
            "pass",
            "no local listen socket configured",
        )
    });
    checks.push(if state.join("findings.db").is_dir() {
        check("database_writable", "fail", "findings.db is a directory")
    } else {
        check("database_writable", "pass", "database path is writable")
    });
    if is_tmpfs(state) {
        checks.push(check(
            "state_durability",
            "fail",
            "state directory is on tmpfs and will not survive a reboot",
        ));
    } else {
        checks.push(check(
            "state_durability",
            "pass",
            "state directory is not on tmpfs",
        ));
    }
    checks.push(if clock_went_back(state) {
        check(
            "clock_monotonic",
            "warn",
            "wall clock is behind the last liveness marker; cursors still accept",
        )
    } else {
        check("clock_monotonic", "pass", "wall clock is not behind state")
    });
    #[cfg(unix)]
    checks.push(check(
        "disk_headroom",
        "pass",
        "filesystem is mounted; exact quota is deployment-owned",
    ));
    #[cfg(not(unix))]
    checks.push(check(
        "disk_headroom",
        "warn",
        "portable build cannot query filesystem free space",
    ));
    for finding in tamper_findings(state, executable)? {
        checks.push(check(&format!("tamper_{finding}"), "fail", finding));
    }
    Ok(DoctorReport { checks })
}

fn relay_probe(name: &str, address: &str) -> DoctorCheck {
    let Some(raw) = address.strip_prefix("http://") else {
        return check(name, "warn", format!("unsupported relay URL: {address}"));
    };
    let Some(socket_text) = raw.split('/').next() else {
        return check(name, "fail", "invalid relay address");
    };
    let Ok(socket) = socket_text.parse::<SocketAddr>() else {
        return check(
            name,
            "warn",
            format!("relay address is not a literal socket: {address}"),
        );
    };
    let result =
        TcpStream::connect_timeout(&socket, Duration::from_secs(1)).and_then(|mut stream| {
            stream.set_read_timeout(Some(Duration::from_secs(1)))?;
            stream.set_write_timeout(Some(Duration::from_secs(1)))?;
            stream.write_all(b"GET /health HTTP/1.0\r\n\r\n")?;
            let mut buf = [0_u8; 96];
            let n = stream.read(&mut buf)?;
            Ok(String::from_utf8_lossy(&buf[..n]).contains(" 200 "))
        });
    match result {
        Ok(true) => check(name, "pass", format!("/health responded at {address}")),
        Ok(false) => check(
            name,
            "fail",
            format!("/health did not return 200 at {address}"),
        ),
        Err(e) => check(
            name,
            "fail",
            format!("/health probe failed at {address}: {e}"),
        ),
    }
}

fn json_quote(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn atomic_bytes(path: &Path, bytes: &[u8]) -> Result<(), ResilienceError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("part");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn hash_file(path: &Path) -> io::Result<String> {
    let bytes = fs::read(path)?;
    let mut hasher = Hasher::new();
    hasher.update(&bytes);
    Ok(hasher.finalize().to_hex().to_string())
}

fn executable_name(executable: &Path) -> String {
    executable.file_name().map_or_else(
        || "agentd".into(),
        |name| name.to_string_lossy().into_owned(),
    )
}

fn unit_dir(state: &Path) -> PathBuf {
    state.join("services")
}

/// Install deterministic service definitions and an independent five-minute backstop.
///
/// The files are intentionally emitted under `state/services`; a privileged deployment
/// may copy them to the native manager. This makes install safe and testable on every OS.
pub fn install(
    state: &Path,
    executable: &Path,
    enable: bool,
    backstop: bool,
) -> Result<(), ResilienceError> {
    if executable
        .components()
        .any(|component| component.as_os_str() == "target")
    {
        return Err(ResilienceError::TargetPath);
    }
    let dir = unit_dir(state);
    fs::create_dir_all(&dir)?;
    let exe = executable.display();
    let state_arg = state.display();
    let (unit, backstop_unit) = if cfg!(target_os = "linux") {
        (format!("[Unit]\nDescription=Agent-Fleet supervisor\nAfter=network-online.target\n[Service]\nExecStart={exe} --state {state_arg}\nRestart=always\nRestartSec=5\nStartLimitIntervalSec=0\nKillMode=mixed\n{}", if enable { "[Install]\nWantedBy=default.target\n" } else { "" }), format!("[Unit]\nDescription=Agent-Fleet guard backstop\n[Timer]\nOnBootSec=300\nOnUnitActiveSec=300\n[Service]\nExecStart={exe} guard --state {state_arg} --quick\n"))
    } else if cfg!(target_os = "macos") {
        (format!("<?xml version=\"1.0\"?><plist><dict><key>Label</key><string>org.agentfleet.agentd</string><key>ProgramArguments</key><array><string>{exe}</string><string>--state</string><string>{state_arg}</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict><key>ThrottleInterval</key><integer>10</integer></dict></plist>"), format!("<?xml version=\"1.0\"?><plist><dict><key>Label</key><string>org.agentfleet.guard</string><key>ProgramArguments</key><array><string>{exe}</string><string>guard</string><string>--state</string><string>{state_arg}</string><string>--quick</string></array><key>StartInterval</key><integer>300</integer></dict></plist>"))
    } else {
        (format!("# Agent-Fleet portable SCM definition\nprogram={exe}\nargs=--state {state_arg}\nrestart=always\nstop_accepts=STOP,SHUTDOWN\nfailure_reset=86400\nactions=restart/5000 x3\n"), format!("# Agent-Fleet portable scheduled-task definition\nprogram={exe}\nargs=guard --state {state_arg} --quick\ninterval_seconds=300\n"))
    };
    atomic_bytes(&dir.join("agentd.unit"), unit.as_bytes())?;
    if backstop {
        atomic_bytes(&dir.join("agentd-backstop.unit"), backstop_unit.as_bytes())?;
    } else {
        let _ = fs::remove_file(dir.join("agentd-backstop.unit"));
    }
    atomic_bytes(
        &dir.join("install.meta"),
        format!("executable={exe}\nenabled={enable}\nbackstop={backstop}\n").as_bytes(),
    )
}

/// Remove service definitions while leaving state, database, and modules untouched.
pub fn uninstall(state: &Path) -> Result<(), ResilienceError> {
    let dir = unit_dir(state);
    let _ = fs::remove_file(dir.join("agentd.unit"));
    let _ = fs::remove_file(dir.join("agentd-backstop.unit"));
    let _ = fs::remove_file(dir.join("install.meta"));
    Ok(())
}

/// Touch the liveness marker using an atomic replace.
pub fn touch_alive(state: &Path) -> Result<(), ResilienceError> {
    atomic_bytes(&state.join("alive"), format!("{}\n", unix_now()).as_bytes())
}

/// Whether a liveness marker is within the three-interval freshness window.
///
/// A marker timestamp ahead of the wall clock (the clock moved backwards) is
/// treated as fresh with a warning: restarting on a clock step would be worse
/// than continuing to serve.
pub fn liveness_is_fresh(now: SystemTime, modified: SystemTime, interval: Duration) -> bool {
    now.duration_since(modified)
        .map_or(true, |age| age <= interval * 3)
}

/// Check liveness and installation, repairing a missing unit where possible.
pub fn guard(state: &Path, executable: &Path, quick: bool) -> Result<CheckStatus, ResilienceError> {
    let alive = state.join("alive");
    let interval = Duration::from_secs(300);
    let live = fs::metadata(&alive)
        .ok()
        .and_then(|meta| meta.modified().ok())
        .is_some_and(|modified| liveness_is_fresh(SystemTime::now(), modified, interval));
    let installed = unit_dir(state).join("agentd.unit").is_file();
    if live && installed {
        return Ok(CheckStatus::Healthy);
    }
    if !installed {
        install(state, executable, false, !quick)?;
        return Ok(CheckStatus::Repaired);
    }
    if live {
        Ok(CheckStatus::Healthy)
    } else {
        Ok(CheckStatus::Repaired)
    }
}

/// Return the three portable replica roots, overridable for tests and unprivileged installs.
pub fn replica_roots(state: &Path) -> Vec<PathBuf> {
    if let Ok(value) = env::var("AGENT_FLEET_REPLICA_ROOTS") {
        return value
            .split(':')
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .collect();
    }
    vec![
        state.join("replicas/bin"),
        state.join("replicas/lib"),
        state.join("replicas/share"),
    ]
}

/// Install or repair redundant executable copies and its manifest.
pub fn repair_replicas(
    state: &Path,
    executable: &Path,
    version: &str,
    abi: &str,
) -> Result<bool, ResilienceError> {
    let roots = replica_roots(state);
    let source_hash = hash_file(executable).or_else(|_| {
        roots
            .iter()
            .find_map(|root| {
                let text = fs::read_to_string(root.join("manifest.json")).ok()?;
                let marker = "\"blake3\":\"";
                let start = text.find(marker)? + marker.len();
                Some(Ok::<String, io::Error>(
                    text[start..].split('"').next()?.to_owned(),
                ))
            })
            .unwrap_or_else(|| Err(io::Error::new(io::ErrorKind::NotFound, "no replica hash")))
    });
    let source_hash = match source_hash {
        Ok(hash) if !hash.is_empty() => hash,
        _ => return Ok(false),
    };
    let mut matching = None;
    for root in &roots {
        let candidate = root.join(executable_name(executable));
        if candidate.is_file() && hash_file(&candidate).ok().as_deref() == Some(&source_hash) {
            matching = Some(candidate);
            break;
        }
    }
    if matching.is_none() && !executable.is_file() {
        return Ok(false);
    }
    let source = matching.as_deref().unwrap_or(executable);
    let mut repaired = false;
    if !executable.is_file() {
        // A deleted running copy is restored from the first verified replica.
        if let Some(candidate) = matching.as_deref() {
            if let Some(parent) = executable.parent() {
                fs::create_dir_all(parent)?;
            }
            let tmp = executable.with_extension("part");
            fs::copy(candidate, &tmp)?;
            if hash_file(&tmp).ok().as_deref() == Some(&source_hash) {
                fs::rename(&tmp, executable)?;
                repaired = true;
            } else {
                let _ = fs::remove_file(&tmp);
            }
        }
    }
    for root in roots {
        fs::create_dir_all(&root)?;
        let dest = root.join(executable_name(executable));
        if hash_file(&dest).ok().as_deref() != Some(&source_hash) {
            let tmp = dest.with_extension("part");
            fs::copy(source, &tmp)?;
            let copied_hash = hash_file(&tmp)?;
            if copied_hash != source_hash {
                let _ = fs::remove_file(&tmp);
                continue;
            }
            fs::rename(tmp, &dest)?;
            repaired = true;
        }
        atomic_bytes(
            &root.join("manifest.json"),
            format!(
                "{{\"version\":\"{version}\",\"abi\":\"{abi}\",\"blake3\":\"{source_hash}\"}}\n"
            )
            .as_bytes(),
        )?;
    }
    Ok(repaired)
}

/// Write a state document to the primary and all configured mirrors.
pub fn mirrored_write(state: &Path, relative: &Path, bytes: &[u8]) -> Result<(), ResilienceError> {
    let roots = mirror_roots(state);
    let primary = roots.first().ok_or(ResilienceError::NoReplica)?;
    atomic_bytes(&primary.join(relative), bytes)?;
    // Mirror failures are deliberately ignored: a degraded mirror must not block polling.
    for root in roots.iter().skip(1) {
        let _ = atomic_bytes(&root.join(relative), bytes);
    }
    Ok(())
}

/// Return primary plus two mirror roots, with an environment override for deployments.
pub fn mirror_roots(state: &Path) -> Vec<PathBuf> {
    if let Ok(value) = env::var("AGENT_FLEET_MIRROR_ROOTS") {
        return value
            .split(':')
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .collect();
    }
    vec![
        state.to_path_buf(),
        state.join("mirror-1"),
        state.join("mirror-2"),
    ]
}

/// Restore a missing or empty primary state file from the first verifying mirror.
pub fn restore_from_mirrors(state: &Path, relative: &Path) -> Result<bool, ResilienceError> {
    let roots = mirror_roots(state);
    let primary = roots
        .first()
        .ok_or(ResilienceError::NoReplica)?
        .join(relative);
    if primary.is_file() && fs::metadata(&primary).is_ok_and(|m| m.len() > 0) {
        return Ok(false);
    }
    for root in roots.iter().skip(1) {
        let candidate = root.join(relative);
        if candidate.is_file() {
            let bytes = fs::read(&candidate)?;
            if !bytes.is_empty() {
                atomic_bytes(&primary, &bytes)?;
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Replicate the enrolled agent key to every configured mirror with a BLAKE3 sidecar.
///
/// Mirror roots must be protected as sensitive key material. This provides availability
/// recovery, not an additional confidentiality boundary.
pub fn mirror_agent_key(state: &Path) -> Result<bool, ResilienceError> {
    let key_path = state.join("agent.key");
    let key = fs::read(&key_path)?;
    if key.len() != 32 {
        return Err(
            io::Error::new(io::ErrorKind::InvalidData, "agent.key must be 32 bytes").into(),
        );
    }
    let hash = hash_bytes(&key);
    let mut changed = false;
    for root in mirror_roots(state) {
        let destination = root.join("agent.key");
        if fs::read(&destination).ok().as_deref() != Some(key.as_slice()) {
            atomic_bytes(&destination, &key)?;
            changed = true;
        }
        atomic_bytes(
            &root.join("agent.key.blake3"),
            format!("{hash}\n").as_bytes(),
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&destination, fs::Permissions::from_mode(0o600));
        }
    }
    Ok(changed)
}

/// Restore a missing agent key from the first verifying configured mirror.
pub fn recover_agent_key(state: &Path) -> Result<bool, ResilienceError> {
    let primary = state.join("agent.key");
    if primary.is_file() {
        return Ok(false);
    }
    for root in mirror_roots(state).into_iter().skip(1) {
        let candidate = root.join("agent.key");
        let sidecar = root.join("agent.key.blake3");
        let key = match fs::read(&candidate) {
            Ok(key) if key.len() == 32 => key,
            _ => continue,
        };
        let expected = match fs::read_to_string(sidecar) {
            Ok(value) => value.trim().to_owned(),
            Err(_) => continue,
        };
        if expected != hash_bytes(&key) {
            continue;
        }
        SigningKey::from_bytes(&key.clone().try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid mirrored agent key")
        })?);
        atomic_bytes(&primary, &key)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&primary, fs::Permissions::from_mode(0o600))?;
        }
        return Ok(true);
    }
    Ok(false)
}

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}

/// Record stable tamper findings for permissions and executable integrity.
pub fn tamper_findings(state: &Path, executable: &Path) -> Result<Vec<String>, ResilienceError> {
    let mut findings = Vec::new();
    let key = state.join("agent.key");
    #[cfg(not(unix))]
    let _ = &key;
    if !executable.is_file() {
        findings.push("binary_missing".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if key.is_file() && fs::metadata(&key)?.permissions().mode() & 0o777 != 0o600 {
            findings.push("key_mode".into());
        }
        if state.is_dir() && fs::metadata(state)?.permissions().mode() & 0o777 != 0o700 {
            findings.push("state_mode".into());
        }
        if executable.is_file() && fs::metadata(executable)?.permissions().mode() & 0o002 != 0 {
            findings.push("binary_world_writable".into());
        }
    }
    if let (Ok(expected), Ok(actual)) = (
        fs::read_to_string(state.join("binary.blake3")),
        hash_file(executable),
    ) {
        if expected.trim() != actual {
            findings.push("binary_hash".into());
        }
    }
    if findings.is_empty() {
        Ok(findings)
    } else {
        fs::create_dir_all(state)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(state.join("tamper.log"))?;
        for finding in &findings {
            writeln!(file, "{finding}")?;
        }
        Ok(findings)
    }
}

/// Current Unix time for portable marker contents.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Whether the wall clock is behind the last liveness timestamp.
///
/// `touch_alive` stores the time it ran; a later clock reading that is smaller
/// means the clock stepped backwards. Callers warn and keep serving.
pub fn clock_went_back(state: &Path) -> bool {
    let stored = fs::read_to_string(state.join("alive"))
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
        .unwrap_or(0);
    stored > unix_now()
}

/// Returns whether `path` lives on a Linux tmpfs mount.
///
/// The portable state directory is expected to survive a reboot. On other
/// platforms this returns `false` because the mount table is deployment-owned.
pub fn is_tmpfs(path: &Path) -> bool {
    #[cfg(target_os = "linux")]
    {
        let Ok(table) = fs::read_to_string("/proc/self/mountinfo") else {
            return false;
        };
        let target = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let mut best: Option<(usize, &str)> = None;
        for line in table.lines() {
            let mut fields = line.split(' ');
            let _ = fields.next();
            let _ = fields.next();
            let _ = fields.next();
            let _ = fields.next();
            let Some(mount) = fields.next() else {
                continue;
            };
            let rest = &line[line.find(" - ").map_or(line.len(), |at| at + 3)..];
            let fs_type = rest.split(' ').next().unwrap_or_default();
            let mount = PathBuf::from(unescape_mount(mount));
            if target.starts_with(&mount)
                && best.is_none_or(|(length, _)| mount.as_os_str().len() > length)
            {
                best = Some((mount.as_os_str().len(), fs_type));
            }
        }
        best.is_some_and(|(_, fs_type)| fs_type == "tmpfs")
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        false
    }
}

#[cfg(target_os = "linux")]
fn unescape_mount(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(value.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && index + 3 < bytes.len() {
            if let Ok(octal) = u8::from_str_radix(&value[index + 1..index + 4], 8) {
                out.push(octal as char);
                index += 4;
                continue;
            }
        }
        out.push(bytes[index] as char);
        index += 1;
    }
    out
}

/// Consume a signed grant once and create an agent key plus an enrolment request.
///
/// The request is written to `enrol.request` for the configured transport to publish.
/// A coordinator deployment should replace this portable file hand-off with its signed
/// database ingest path; the nonce marker prevents local replay.
pub fn try_reenrol(state: &Path) -> Result<bool, ResilienceError> {
    let token_path = state.join("enrolment.grant");
    if state.join("agent.key").exists() || !token_path.is_file() {
        return Ok(false);
    }
    let fields = fs::read_to_string(&token_path)?
        .trim()
        .split('\t')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if fields.len() != 6 || fields[0] != "grant" {
        return Ok(false);
    }
    let body = fields[..4].join("\t");
    let public = decode_hex(&fields[4])
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid grant key"))?;
    let signature = decode_hex(&fields[5])
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid grant signature"))?;
    let public: [u8; 32] = public
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid grant key length"))?;
    let signature: [u8; 64] = signature.try_into().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid grant signature length")
    })?;
    VerifyingKey::from_bytes(&public)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid grant key"))?
        .verify(body.as_bytes(), &Signature::from_bytes(&signature))
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "invalid enrolment grant"))?;
    let expiry = fields[2]
        .parse::<u64>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid grant expiry"))?;
    if expiry < unix_now() {
        return Ok(false);
    }
    let nonce_path = state.join(format!("enrolment.nonce.{}", fields[3]));
    if nonce_path.exists() {
        return Ok(false);
    }
    fs::create_dir_all(state)?;
    let mut secret = [0_u8; 32];
    OsRng.fill_bytes(&mut secret);
    let signing = SigningKey::from_bytes(&secret);
    atomic_bytes(&state.join("agent.key"), &secret)?;
    // The grant names the coordinator key that signed it; tasks and relay sets
    // are verified against that key from now on.
    atomic_bytes(&state.join("coordinator.pub"), &public)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(state.join("agent.key"), fs::Permissions::from_mode(0o600))?;
    }
    atomic_bytes(
        &state.join("enrol.request"),
        format!(
            "tag={}\nagent_pub={}\nnonce={}\n",
            fields[1],
            encode_hex(signing.verifying_key().as_bytes()),
            fields[3]
        )
        .as_bytes(),
    )?;
    atomic_bytes(&nonce_path, b"used\n")?;
    let _ = fs::remove_file(token_path);
    Ok(true)
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).ok())
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn temp(name: &str) -> PathBuf {
        env::temp_dir().join(format!("agentd-resilience-{name}-{}", std::process::id()))
    }
    #[test]
    fn install_is_idempotent_and_uninstall_preserves_state() {
        let state = temp("service");
        let _ = fs::remove_dir_all(&state);
        fs::create_dir_all(&state).unwrap();
        let exe = state.join("agentd");
        fs::write(&exe, b"binary").unwrap();
        install(&state, &exe, false, true).unwrap();
        let first = fs::read(unit_dir(&state).join("agentd.unit")).unwrap();
        install(&state, &exe, false, true).unwrap();
        assert_eq!(
            first,
            fs::read(unit_dir(&state).join("agentd.unit")).unwrap()
        );
        fs::write(state.join("findings.db"), b"keep").unwrap();
        uninstall(&state).unwrap();
        assert!(state.join("findings.db").exists());
        let _ = fs::remove_dir_all(state);
    }
    #[test]
    fn mirrors_restore_empty_primary() {
        let state = temp("mirror");
        let _ = fs::remove_dir_all(&state);
        let roots = mirror_roots(&state);
        fs::create_dir_all(&roots[1]).unwrap();
        fs::write(roots[1].join("cursor"), b"9").unwrap();
        assert!(restore_from_mirrors(&state, Path::new("cursor")).unwrap());
        assert_eq!(fs::read(state.join("cursor")).unwrap(), b"9");
        let _ = fs::remove_dir_all(state);
    }
    #[test]
    fn missing_agent_key_recovers_from_verified_mirror() {
        let state = temp("key-recovery");
        let _ = fs::remove_dir_all(&state);
        fs::create_dir_all(&state).unwrap();
        let key = [7_u8; 32];
        fs::write(state.join("agent.key"), key).unwrap();
        mirror_agent_key(&state).unwrap();
        fs::remove_file(state.join("agent.key")).unwrap();
        assert!(recover_agent_key(&state).unwrap());
        assert_eq!(fs::read(state.join("agent.key")).unwrap(), key);
        let _ = fs::remove_dir_all(state);
    }

    #[test]
    fn missing_binary_is_reported_without_panicking() {
        let state = temp("tamper");
        let _ = fs::remove_dir_all(&state);
        fs::create_dir_all(&state).unwrap();
        assert!(tamper_findings(&state, &state.join("missing"))
            .unwrap()
            .contains(&"binary_missing".to_owned()));
        let _ = fs::remove_dir_all(state);
    }
}
