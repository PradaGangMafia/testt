//! Operator control for the coordinator.

use std::{fs, path::PathBuf};

use clap::{Parser, Subcommand};
use coordd::{unix_now, Coord};
use ed25519_dalek::SigningKey;
use msgfmt::{valid_mod_id, valid_mod_version, ModEntry, ModSet};

#[derive(Parser, Debug)]
#[command(about = "Inspect and control a coordinator state directory")]
struct Cli {
    /// Coordinator state directory.
    #[arg(long, default_value = ".agent-fleet-coord")]
    state: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Counts of agents, results, findings, and schedules.
    Status,
    /// List enrolled agents.
    Agents,
    /// Stop scheduling a route tag.
    Revoke { tag: String },
    /// Resume scheduling a route tag.
    Unrevoke { tag: String },
    /// Pull and ingest once.
    Pull,
    /// Recurring task operations.
    Schedule {
        #[command(subcommand)]
        command: ScheduleCommand,
    },
    /// List stored artifacts.
    Artifacts,
    /// Artifact export and retention.
    Artifact {
        #[command(subcommand)]
        command: ArtifactCommand,
    },
    /// Generate a new coordinator key and push a signed rotation.
    Rotate,
    /// Push a signed binary upgrade.
    Upgrade {
        file: PathBuf,
        #[arg(long)]
        url: String,
        #[arg(long)]
        version: String,
    },
    /// Relay list operations.
    Relay {
        #[command(subcommand)]
        command: RelayCommand,
    },
    /// Publish a module set to the relays.
    Mod {
        #[command(subcommand)]
        command: ModCommand,
    },
}

#[derive(Subcommand, Debug)]
enum ScheduleCommand {
    /// Add a recurring module task.
    Add {
        tag: String,
        mod_id: String,
        version: String,
        /// Period in seconds.
        #[arg(long)]
        every: i64,
        /// Extra random delay in seconds.
        #[arg(long, default_value_t = 30)]
        jitter: i64,
        /// JSON arguments.
        #[arg(long, default_value = "{}")]
        args: String,
        /// First run offset in seconds.
        #[arg(long, default_value_t = 0)]
        after: i64,
    },
    /// List schedules.
    List,
    /// Remove a schedule.
    Remove { id: i64 },
}

#[derive(Subcommand, Debug)]
enum RelayCommand {
    /// List configured relays.
    List,
    /// Push a signed relay set built from the local list to every agent.
    Publish,
}

#[derive(Subcommand, Debug)]
enum ArtifactCommand {
    /// Copy one stored artifact to a file.
    Export {
        id: i64,
        #[arg(long)]
        out: PathBuf,
    },
    /// Delete artifacts older than a cutoff epoch second.
    Prune {
        #[arg(long)]
        before: i64,
    },
}

#[derive(Subcommand, Debug)]
enum ModCommand {
    /// Encode a signed module set and push it to a relay majority.
    Publish {
        id: String,
        version: String,
        file: PathBuf,
        /// HTTP(S) URL the agents fetch the module from.
        #[arg(long)]
        url: String,
        #[arg(long, default_value_t = 1)]
        abi: u32,
        #[arg(long = "cap")]
        caps: Vec<String>,
    },
}

fn tag(value: &str) -> Result<[u8; 8], String> {
    if value.len() != 16 {
        return Err("tag must be 16 hex characters".into());
    }
    let mut bytes = [0_u8; 8];
    for (index, chunk) in value.as_bytes().chunks(2).enumerate() {
        let text = std::str::from_utf8(chunk).map_err(|_| "bad tag")?;
        bytes[index] = u8::from_str_radix(text, 16).map_err(|_| "bad tag")?;
    }
    Ok(bytes)
}

fn main() {
    let cli = Cli::parse();
    if let Err(error) = run(cli) {
        eprintln!("coordctl: {error}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> std::io::Result<()> {
    let mut coord = Coord::open(&cli.state).map_err(std::io::Error::other)?;
    match cli.command {
        Command::Status => {
            let stats = coord.database().stats().expect("stats");
            let schedules = coord.database().schedules().expect("schedules").len();
            println!(
                "agents={} results={} findings={} events={} schedules={schedules}",
                stats.agents, stats.results, stats.findings, stats.events
            );
            Ok(())
        }
        Command::Agents => {
            for agent in coord.database().agents().expect("agents") {
                let tag = agent
                    .route_tag
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                println!(
                    "{tag}\tlast_seen={}\tresults={}\trevoked={}",
                    agent.last_seen, agent.results, agent.revoked
                );
            }
            Ok(())
        }
        Command::Revoke { tag: value } => {
            let bytes = tag(&value).map_err(std::io::Error::other)?;
            println!(
                "revoked={}",
                coord.database().set_revoked(&bytes, true).expect("revoke")
            );
            Ok(())
        }
        Command::Unrevoke { tag: value } => {
            let bytes = tag(&value).map_err(std::io::Error::other)?;
            println!(
                "unrevoked={}",
                coord
                    .database()
                    .set_revoked(&bytes, false)
                    .expect("unrevoke")
            );
            Ok(())
        }
        Command::Pull => {
            let report = coord.pull_once().map_err(std::io::Error::other)?;
            println!(
                "seen={} results={} heartbeats={} skipped={}",
                report.seen, report.results, report.heartbeats, report.skipped
            );
            Ok(())
        }
        Command::Schedule { command } => match command {
            ScheduleCommand::Add {
                tag: value,
                mod_id,
                version,
                every,
                jitter,
                args,
                after,
            } => {
                let bytes = tag(&value).map_err(std::io::Error::other)?;
                if every < 1 {
                    fail("--every must be positive");
                }
                serde_json::from_str::<serde_json::Value>(&args)
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                let id = coord
                    .database()
                    .add_schedule(
                        &bytes,
                        &mod_id,
                        &version,
                        &args,
                        every,
                        jitter,
                        unix_now() + after,
                    )
                    .map_err(std::io::Error::other)?;
                println!("id={id}");
                Ok(())
            }
            ScheduleCommand::List => {
                for schedule in coord.database().schedules().expect("schedules") {
                    let tag = schedule
                        .route_tag
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>();
                    println!(
                        "{}\t{tag}\t{}@{}\tevery={}s\tnext={}\t{}",
                        schedule.id,
                        schedule.mod_id,
                        schedule.version,
                        schedule.every_s,
                        schedule.next_at,
                        schedule.args
                    );
                }
                Ok(())
            }
            ScheduleCommand::Remove { id } => {
                println!(
                    "removed={}",
                    coord.database().remove_schedule(id).expect("remove")
                );
                Ok(())
            }
        },
        Command::Artifacts => {
            for artifact in coord
                .database()
                .artifacts()
                .map_err(std::io::Error::other)?
            {
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    artifact.id, artifact.size, artifact.kind, artifact.sha256, artifact.path
                );
            }
            Ok(())
        }
        Command::Artifact { command } => match command {
            ArtifactCommand::Export { id, out } => {
                let artifact = coord
                    .database()
                    .artifacts()
                    .map_err(std::io::Error::other)?
                    .into_iter()
                    .find(|artifact| artifact.id == id)
                    .ok_or_else(|| std::io::Error::other("unknown artifact"))?;
                let key = coordd::artifact::load_key(&cli.state)?;
                let plain = coordd::artifact::read_encrypted(
                    &cli.state.join("artifacts").join(&artifact.stored),
                    &key,
                )?;
                fs::write(&out, plain)?;
                println!("exported {} bytes to {}", artifact.size, out.display());
                Ok(())
            }
            ArtifactCommand::Prune { before } => {
                let removed = coord
                    .database()
                    .prune_artifacts(before)
                    .map_err(std::io::Error::other)?;
                for artifact in &removed {
                    let _ = fs::remove_file(cli.state.join("artifacts").join(&artifact.stored));
                }
                println!("pruned={}", removed.len());
                Ok(())
            }
        },
        Command::Rotate => {
            use sha2::Digest;
            let _ = sha2::Sha256::new();
            let fresh = SigningKey::generate(&mut rand::rngs::OsRng);
            let rotate = msgfmt::Rotate {
                new_pub: *fresh.verifying_key().as_bytes(),
                generation: coordd::unix_millis(),
            };
            let pushed = coord
                .push_per_agent(|key| msgfmt::encode_rotate(&rotate, key, coord.signing_key()))
                .map_err(std::io::Error::other)?;
            if pushed == 0 {
                fail("no agent received the rotation");
            }
            fs::write(cli.state.join("agent.key"), fresh.to_bytes())?;
            fs::write(
                cli.state.join("agent.prev.key"),
                coord.signing_key().to_bytes(),
            )?;
            println!(
                "rotated to {}",
                fresh
                    .verifying_key()
                    .as_bytes()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            );
            Ok(())
        }
        Command::Upgrade { file, url, version } => {
            use sha2::Digest;
            let bytes = fs::read(&file)?;
            let sha: [u8; 32] = sha2::Sha256::digest(&bytes).into();
            let upgrade = msgfmt::Upgrade {
                version,
                sha256: sha,
                size: bytes.len() as u64,
                url,
                epoch: coordd::unix_millis(),
            };
            let pushed = coord
                .push_per_agent(|key| msgfmt::encode_upgrade(&upgrade, key, coord.signing_key()))
                .map_err(std::io::Error::other)?;
            if pushed == 0 {
                fail("no agent received the upgrade");
            }
            println!("upgrade pushed to {pushed} agents");
            Ok(())
        }
        Command::Relay { command } => match command {
            RelayCommand::List => {
                let text = fs::read_to_string(cli.state.join("relays.conf")).unwrap_or_default();
                print!("{text}");
                Ok(())
            }
            RelayCommand::Publish => {
                let text = fs::read_to_string(cli.state.join("relays.conf"))?;
                let mut add = Vec::new();
                for line in text.lines().filter(|line| !line.trim().is_empty()) {
                    let spec = transport::parse_relay_spec(line)
                        .map_err(|error| std::io::Error::other(error.to_string()))?;
                    add.push(msgfmt::RelayEntry {
                        id: transport::channel_id(&spec.kind, &spec.arg),
                        kind: spec.kind,
                        tier: spec.tier,
                        addr: spec.arg,
                    });
                }
                if add.is_empty() {
                    fail("no relays configured");
                }
                let set = msgfmt::RelaySet {
                    gen: coordd::unix_millis(),
                    add,
                    remove: Vec::new(),
                };
                let pushed = coord
                    .push_per_agent(|key| msgfmt::encode_relay_set(&set, key, coord.signing_key()))
                    .map_err(std::io::Error::other)?;
                println!("relay set pushed to {pushed} agents");
                Ok(())
            }
        },
        Command::Mod {
            command:
                ModCommand::Publish {
                    id,
                    version,
                    file,
                    url,
                    abi,
                    caps,
                },
        } => {
            if !valid_mod_id(&id) || !valid_mod_version(&version) {
                fail("invalid module id or version")
            }
            let bytes = fs::read(&file).map_err(std::io::Error::other)?;
            let entry = ModEntry {
                id: id.clone(),
                version: version.clone(),
                abi,
                blake3: *blake3::hash(&bytes).as_bytes(),
                size: bytes.len() as u64,
                url: url.clone(),
                capabilities: caps,
                enabled: true,
            };
            let set = ModSet {
                gen: unix_now() as u64,
                add: vec![entry],
                remove: Vec::new(),
            };
            let pushed = coord
                .push_per_agent(|key| msgfmt::encode_mod_set(&set, key, coord.signing_key()))
                .map_err(std::io::Error::other)?;
            if pushed == 0 {
                fail("no agent received the module set");
            }
            coord
                .database()
                .record_mod(&id, &version, &url)
                .map_err(std::io::Error::other)?;
            println!("published {id}@{version} to {pushed} agents");
            Ok(())
        }
    }
}

fn fail(message: &str) -> ! {
    eprintln!("coordctl: {message}");
    std::process::exit(2);
}
