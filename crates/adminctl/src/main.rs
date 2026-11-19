#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Administrative CLI for Agent-Fleet key and task operations.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use agentd::plugins::{CapabilityPolicy, Limits, ModStore, WasmHost, MAX_ABI};
use agentd::production::Config;
use clap::{Parser, Subcommand};
use db::{FindingInput, FindingOutcome, ResultFrame};
use ed25519_dalek::{Signer, SigningKey};
use msgfmt::{
    decode, encode_task, route_tag_from_key, valid_mod_id, valid_mod_version, ModEntry, ModSet,
    Task, TaskBody,
};
use rand::{rngs::OsRng, RngCore};
use transport::{channel_id, parse_relay_spec};

/// Agent-Fleet administrative commands.
#[derive(Debug, Parser)]
#[command(name = "adminctl", version)]
struct Cli {
    /// State directory containing keys, configuration, and frames.
    #[arg(long, default_value = ".agent-fleet")]
    state: PathBuf,
    #[command(subcommand)]
    command: Command,
}

/// Supported administrative operations.
#[derive(Debug, Subcommand)]
enum Command {
    /// Create the signing, encryption, and configuration files.
    Keygen,
    /// Display the enrolled public identity and route tag.
    Show,
    /// Write the coordinator public key as raw 32 bytes, or print it as hex.
    Pubkey {
        /// Destination file; stdout hex when omitted.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Write a Ping task frame.
    Ping {
        #[arg(long, default_value_t = 1)]
        epoch: u64,
        #[arg(long, value_parser = parse_tag)]
        tag: Option<[u8; 8]>,
    },
    /// Write a Shell task frame.
    Shell {
        #[arg(long, default_value_t = 60)]
        timeout_s: u16,
        #[arg(long, default_value_t = false)]
        shell: bool,
        #[arg(long, default_value_t = 1)]
        epoch: u64,
        #[arg(long, value_parser = parse_tag)]
        tag: Option<[u8; 8]>,
        #[arg(required = true, trailing_var_arg = true)]
        argv: Vec<String>,
    },
    /// Write a Fetch task frame.
    Fetch {
        url: String,
        dest: String,
        #[arg(long, default_value_t = 1)]
        epoch: u64,
        #[arg(long, value_parser = parse_tag)]
        tag: Option<[u8; 8]>,
    },
    /// Decode result frames from the configured results directory.
    Results,
    /// Manage the local relay set.
    Relay {
        #[command(subcommand)]
        command: RelayCommand,
    },
    /// Manage locally installed modules.
    Mod {
        #[command(subcommand)]
        command: ModCommand,
    },
    /// Manage the coordinator findings database.
    Db {
        #[command(subcommand)]
        command: DbCommand,
    },
    /// Issue a signed, single-use enrolment grant for a wiped agent.
    Agents {
        #[command(subcommand)]
        command: AgentsCommand,
    },
}

/// Enrolment-token operations.
#[derive(Debug, Subcommand)]
enum AgentsCommand {
    /// Create a grant token pinned to a route tag.
    Grant {
        #[arg(long, value_parser = parse_tag)]
        tag: [u8; 8],
        #[arg(long)]
        expires: Option<u64>,
    },
}

/// Database operations.
#[derive(Debug, Subcommand)]
enum DbCommand {
    /// Initialize or migrate the database.
    Init,
    /// Ingest result frames from the local results directory.
    Ingest,
    /// Export findings as JSON, NDJSON, or CSV.
    Export {
        /// Output format.
        format: String,
        /// Optional output file; stdout is used when omitted.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Search findings with SQLite FTS5 MATCH syntax.
    Query { text: String },
    /// Print database row counts.
    Stats,
    /// Delete findings older than an epoch-seconds cutoff.
    Prune { cutoff: i64 },
    /// Checkpoint and vacuum the database.
    Vacuum,
    /// Create a consistent backup outside the state directory.
    Backup { destination: PathBuf },
}

/// Module management operations.
#[derive(Debug, Subcommand)]
enum ModCommand {
    /// Install a module file after validating its identifier.
    Add {
        id: String,
        version: String,
        file: PathBuf,
        /// Declared ABI version; only ABI 1 is served.
        #[arg(long, default_value_t = 1)]
        abi: u32,
        /// Declared capability, either `name` or `name:target`.
        #[arg(long = "cap")]
        caps: Vec<String>,
        /// Source URL recorded in the entry; defaults to a `file://` URL.
        #[arg(long)]
        url: Option<String>,
    },
    /// Remove an installed module version.
    Remove { id: String, version: String },
    /// Enable a module without deleting its files.
    Enable { id: String, version: String },
    /// Disable a module without deleting its files.
    Disable { id: String, version: String },
    /// Replace the enabled module set from `id@version` entries.
    Set { modules: Vec<String> },
    /// Write a task frame that runs an installed module, optionally pushing it.
    Task {
        id: String,
        version: String,
        #[arg(long, value_parser = parse_tag)]
        tag: Option<[u8; 8]>,
        #[arg(long, default_value_t = 1)]
        epoch: u64,
        #[arg(long)]
        args: Option<String>,
        /// Push the frame to a relay majority and delete it on success.
        #[arg(long, default_value_t = false)]
        push: bool,
    },
    /// Invoke a module through the local agent host.
    Call {
        id: String,
        version: String,
        #[arg(long)]
        args: Option<String>,
    },
    /// List installed modules.
    List,
}

/// Relay management operations.
#[derive(Debug, Subcommand)]
enum RelayCommand {
    /// Add a `tier:priority:kind:address` relay.
    Add { spec: String },
    /// Remove a relay by stable identity.
    Remove { id: String },
    /// List configured relays.
    List,
    /// Replace the local relay set from specifications.
    Set { specs: Vec<String> },
    /// Probe relay health; exits successfully if a majority responds.
    Ping { specs: Vec<String> },
    /// Put a frame to a majority of relays.
    Quorum { frame: PathBuf, specs: Vec<String> },
    /// Pull queued frames from relays into a directory.
    Pull {
        /// Relay index to start from.
        #[arg(long, default_value_t = 0)]
        since: u64,
        /// Destination directory; created when missing.
        #[arg(long, default_value = "results")]
        out: PathBuf,
        specs: Vec<String>,
    },
}

fn parse_tag(value: &str) -> Result<[u8; 8], String> {
    if value.len() != 16 {
        return Err("route tag must contain exactly 16 hexadecimal characters".to_owned());
    }
    let bytes = (0..8)
        .map(|index| u8::from_str_radix(&value[index * 2..index * 2 + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    bytes
        .try_into()
        .map_err(|_| "route tag must contain exactly 8 bytes".to_owned())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let temp = path.with_extension("new");
    fs::write(&temp, bytes)?;
    fs::rename(temp, path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn key_paths(state: &Path) -> (PathBuf, PathBuf, PathBuf) {
    (
        state.join("agent.key"),
        state.join("enc.key"),
        state.join("config.toml"),
    )
}

fn load_keys(state: &Path) -> io::Result<(SigningKey, [u8; 32])> {
    let (sign_path, enc_path, _) = key_paths(state);
    let sign =
        SigningKey::from_bytes(&fs::read(sign_path)?.try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "agent.key must be 32 bytes")
        })?);
    let enc = fs::read(enc_path)?
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "enc.key must be 32 bytes"))?;
    Ok((sign, enc))
}

fn write_frame(state: &Path, task: Task) -> io::Result<PathBuf> {
    let (sign, enc) = load_keys(state)?;
    let frame = encode_task(&task, &enc, &sign)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    let dir = state.join("outbox");
    fs::create_dir_all(&dir)?;
    let index = fs::read_dir(&dir)?.filter_map(Result::ok).count() + 1;
    let path = dir.join(format!("{index:012}.bin"));
    fs::write(&path, frame)?;
    Ok(path)
}

fn tag_or_derived(tag: Option<[u8; 8]>, signing: &SigningKey) -> [u8; 8] {
    tag.unwrap_or_else(|| route_tag_from_key(signing.verifying_key().as_bytes()))
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen => {
            fs::create_dir_all(&cli.state)?;
            let (sign_path, enc_path, config_path) = key_paths(&cli.state);
            if sign_path.exists() || enc_path.exists() || config_path.exists() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "key material already exists",
                ));
            }
            let signing = SigningKey::generate(&mut OsRng);
            let mut enc = [0_u8; 32];
            OsRng.fill_bytes(&mut enc);
            write_private(&sign_path, &signing.to_bytes())?;
            write_private(&enc_path, &enc)?;
            fs::write(
                cli.state.join("coordinator.pub"),
                signing.verifying_key().as_bytes(),
            )?;
            write_private(&config_path, b"channel = \"mock-fs\"\n")?;
            println!(
                "{}",
                hex(&route_tag_from_key(signing.verifying_key().as_bytes()))
            );
        }
        Command::Pubkey { out } => {
            let (signing, _) = load_keys(&cli.state)?;
            let public = signing.verifying_key();
            match out {
                Some(path) => {
                    fs::write(&path, public.as_bytes())?;
                    println!("{}", path.display());
                }
                None => println!("{}", hex(public.as_bytes())),
            }
        }
        Command::Show => {
            let (signing, _) = load_keys(&cli.state)?;
            println!(
                "public_key = {}\nroute_tag = {}",
                hex(signing.verifying_key().as_bytes()),
                hex(&route_tag_from_key(signing.verifying_key().as_bytes()))
            );
        }
        Command::Ping { epoch, tag } => {
            let (signing, _) = load_keys(&cli.state)?;
            write_frame(
                &cli.state,
                Task {
                    route_tag: tag_or_derived(tag, &signing),
                    epoch,
                    body: TaskBody::Ping,
                },
            )?;
        }
        Command::Shell {
            timeout_s,
            shell,
            epoch,
            tag,
            argv,
        } => {
            let (signing, _) = load_keys(&cli.state)?;
            write_frame(
                &cli.state,
                Task {
                    route_tag: tag_or_derived(tag, &signing),
                    epoch,
                    body: TaskBody::Shell {
                        argv,
                        timeout_s,
                        shell,
                    },
                },
            )?;
        }
        Command::Fetch {
            url,
            dest,
            epoch,
            tag,
        } => {
            let (signing, _) = load_keys(&cli.state)?;
            write_frame(
                &cli.state,
                Task {
                    route_tag: tag_or_derived(tag, &signing),
                    epoch,
                    body: TaskBody::Fetch { url, dest },
                },
            )?;
        }
        Command::Results => {
            let (_, enc) = load_keys(&cli.state)?;
            let dir = cli.state.join("results");
            if dir.exists() {
                for entry in fs::read_dir(dir)?.filter_map(Result::ok) {
                    let bytes = fs::read(entry.path())?;
                    if let Ok(decoded) = decode(&bytes, &enc) {
                        println!("{:?}", decoded);
                    }
                }
            }
        }
        Command::Relay { command } => relay_command(&cli.state, command).await?,
        Command::Mod { command } => mod_command(&cli.state, command).await?,
        Command::Db { command } => db_command(&cli.state, command)?,
        Command::Agents { command } => agents_command(&cli.state, command)?,
    }
    Ok(())
}

fn agents_command(state: &Path, command: AgentsCommand) -> io::Result<()> {
    match command {
        AgentsCommand::Grant { tag, expires } => {
            fs::create_dir_all(state)?;
            let (signing, _) = load_keys(state)?;
            let expiry = expires.unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |duration| duration.as_secs() + 86_400)
            });
            let mut nonce = [0_u8; 16];
            OsRng.fill_bytes(&mut nonce);
            let body = format!("grant\t{}\t{}\t{}", hex(&tag), expiry, hex(&nonce));
            let signature = signing.sign(body.as_bytes());
            let token = format!(
                "{body}\t{}\t{}\n",
                hex(signing.verifying_key().as_bytes()),
                hex(&signature.to_bytes())
            );
            write_private(&state.join("enrolment.grant"), token.as_bytes())?;
            println!("{}", state.join("enrolment.grant").display());
        }
    }
    Ok(())
}

fn db_command(state: &Path, command: DbCommand) -> io::Result<()> {
    fs::create_dir_all(state)?;
    let mut database =
        coordd::open_database(state).map_err(|error| io::Error::other(error.to_string()))?;
    match command {
        DbCommand::Init => Ok(()),
        DbCommand::Ingest => {
            let (signing, enc) = load_keys(state)?;
            let verifying_key = signing.verifying_key();
            let directory = state.join("results");
            let mut inserted = 0;
            let mut findings = 0;
            if directory.exists() {
                for entry in fs::read_dir(directory)?.filter_map(Result::ok) {
                    let bytes = fs::read(entry.path())?;
                    match database.ingest_frame_id(
                        ResultFrame {
                            bytes: &bytes,
                            verifying_key: &verifying_key,
                        },
                        &enc,
                        route_tag_from_key(verifying_key.as_bytes()),
                    ) {
                        Ok(Some(id)) => {
                            inserted += 1;
                            let stdout = database.result_stdout(id).map_err(db_io)?;
                            for outcome in database
                                .extract_findings(id, &findings_from_stdout(&stdout))
                                .map_err(db_io)?
                            {
                                if matches!(
                                    outcome,
                                    FindingOutcome::Stored | FindingOutcome::Raised
                                ) {
                                    findings += 1;
                                }
                            }
                        }
                        Ok(None) => {}
                        Err(error) => database
                            .record_event("malformed_result", &error.to_string())
                            .map_err(db_io)?,
                    }
                }
            }
            println!("inserted={inserted} findings={findings}");
            Ok(())
        }
        DbCommand::Export { format, output } => {
            match output {
                Some(path) => {
                    let mut file = fs::File::create(path)?;
                    database
                        .export_findings(&format, &mut file)
                        .map_err(db_io)?;
                }
                None => {
                    let stdout = io::stdout();
                    let mut handle = stdout.lock();
                    database
                        .export_findings(&format, &mut handle)
                        .map_err(db_io)?;
                }
            }
            Ok(())
        }
        DbCommand::Query { text } => {
            for finding in database.query_findings(&text).map_err(db_io)? {
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    finding.id, finding.kind, finding.dedupe_key, finding.severity, finding.data
                );
            }
            Ok(())
        }
        DbCommand::Stats => {
            let stats = database.stats().map_err(db_io)?;
            println!(
                "agents={} results={} findings={} events={}",
                stats.agents, stats.results, stats.findings, stats.events
            );
            Ok(())
        }
        DbCommand::Prune { cutoff } => {
            println!("pruned={}", database.prune(cutoff).map_err(db_io)?);
            Ok(())
        }
        DbCommand::Vacuum => database.vacuum().map_err(db_io),
        DbCommand::Backup { destination } => database.backup(destination).map_err(db_io),
    }
}

fn db_io(error: db::Error) -> io::Error {
    io::Error::other(error.to_string())
}

fn relay_specs(state: &Path) -> io::Result<Vec<String>> {
    let path = state.join("relays.conf");
    if !path.exists() {
        return Ok(Vec::new());
    }
    Ok(fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .map(str::to_owned)
        .collect())
}

async fn push_frame(specs: &[String], bytes: &[u8]) -> io::Result<bool> {
    if specs.is_empty() {
        return Err(invalid("no relays configured"));
    }
    let mut ok = 0;
    for spec in specs {
        if let Ok(parsed) = parse_relay_spec(spec) {
            if reqwest::Client::new()
                .post(format!("{}/put", parsed.arg))
                .body(bytes.to_vec())
                .send()
                .await
                .is_ok_and(|response| response.status().is_success())
            {
                ok += 1;
            }
        }
    }
    Ok(ok * 2 > specs.len())
}

async fn relay_command(state: &Path, command: RelayCommand) -> io::Result<()> {
    fs::create_dir_all(state)?;
    let path = state.join("relays.conf");
    let mut lines = if path.exists() {
        fs::read_to_string(&path)?
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    match command {
        RelayCommand::Add { spec } => {
            let parsed = parse_relay_spec(&spec)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
            let id = channel_id(&parsed.kind, &parsed.arg);
            if lines.iter().all(|line| {
                parse_relay_spec(line)
                    .map(|value| channel_id(&value.kind, &value.arg) != id)
                    .unwrap_or(true)
            }) {
                lines.push(spec);
            }
        }
        RelayCommand::Remove { id } => {
            lines.retain(|line| {
                parse_relay_spec(line)
                    .map(|value| format_id(channel_id(&value.kind, &value.arg)) != id)
                    .unwrap_or(true)
            });
        }
        RelayCommand::List => {
            for line in &lines {
                println!("{line}");
            }
            return Ok(());
        }
        RelayCommand::Set { specs } => {
            for spec in &specs {
                parse_relay_spec(spec).map_err(|error| {
                    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
                })?;
            }
            lines = specs;
        }
        RelayCommand::Ping { specs } => {
            let selected = if specs.is_empty() {
                lines.clone()
            } else {
                specs.clone()
            };
            let total = selected.len();
            let mut ok = 0;
            for spec in selected {
                if let Ok(parsed) = parse_relay_spec(&spec) {
                    if reqwest::get(format!("{}/health", parsed.arg))
                        .await
                        .is_ok_and(|response| response.status().is_success())
                    {
                        ok += 1;
                    }
                }
            }
            if ok * 2 <= total.max(1) {
                return Err(io::Error::other("relay quorum unavailable"));
            }
            return Ok(());
        }
        RelayCommand::Quorum { frame, specs } => {
            let bytes = fs::read(frame)?;
            let mut ok = 0;
            for spec in specs {
                if let Ok(parsed) = parse_relay_spec(&spec) {
                    if reqwest::Client::new()
                        .post(format!("{}/put", parsed.arg))
                        .body(bytes.clone())
                        .send()
                        .await
                        .is_ok_and(|response| response.status().is_success())
                    {
                        ok += 1;
                    }
                }
            }
            if ok * 2 <= lines.len().max(1) {
                return Err(io::Error::other("relay quorum unavailable"));
            }
            return Ok(());
        }
        RelayCommand::Pull { since, out, specs } => {
            let selected = if specs.is_empty() {
                lines.clone()
            } else {
                specs
            };
            if selected.is_empty() {
                return Err(invalid("no relays configured"));
            }
            fs::create_dir_all(&out)?;
            let mut pulled = 0;
            for spec in selected {
                let Ok(parsed) = parse_relay_spec(&spec) else {
                    continue;
                };
                let response = reqwest::get(format!("{}/list?since={since}", parsed.arg)).await;
                let Ok(response) = response else { continue };
                if !response.status().is_success() {
                    continue;
                }
                let Ok(text) = response.text().await else {
                    continue;
                };
                let Ok(frames) = transport::parse_list(&text) else {
                    continue;
                };
                for (index, bytes) in frames {
                    let path = out.join(format!("{index:012}.bin"));
                    if path.exists() && fs::read(&path).is_ok_and(|old| old == bytes) {
                        continue;
                    }
                    fs::write(&path, bytes)?;
                    pulled += 1;
                }
            }
            println!("pulled={pulled}");
            return Ok(());
        }
    }
    fs::write(path, lines.join("\n") + "\n")
}

fn format_id(id: [u8; 8]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Extracts the documented `findings` envelope from a module result.
///
/// A missing or malformed envelope yields no findings; the result is retained.
fn findings_from_stdout(stdout: &str) -> Vec<FindingInput> {
    let Ok(serde_json::Value::Object(mut object)) = serde_json::from_str(stdout) else {
        return Vec::new();
    };
    let Some(serde_json::Value::Array(items)) = object.remove("findings") else {
        return Vec::new();
    };
    items
        .into_iter()
        .filter_map(|item| {
            let serde_json::Value::Object(mut item) = item else {
                return None;
            };
            let kind = item.remove("kind")?.as_str()?.to_owned();
            let dedupe_key = item.remove("dedupe_key")?.as_str()?.to_owned();
            let severity = item
                .remove("severity")
                .and_then(|value| value.as_i64())
                .unwrap_or(0);
            let data = match item.remove("data") {
                Some(serde_json::Value::String(text)) => text,
                Some(value) => value.to_string(),
                None => "{}".into(),
            };
            Some(FindingInput {
                kind,
                dedupe_key,
                severity,
                data,
            })
        })
        .collect()
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn policy_for(state: &Path) -> io::Result<CapabilityPolicy> {
    let path = state.join("config.toml");
    let config = if path.exists() {
        Config::load(&path).map_err(|error| io::Error::other(error.to_string()))?
    } else {
        Config::default()
    };
    let policy = CapabilityPolicy {
        allow_caps: config.allow_caps,
        allow_exec: config.allow_exec,
        allow_net: config.allow_net,
    };
    policy
        .validate()
        .map_err(|error| io::Error::other(error.to_string()))?;
    Ok(policy)
}

fn entry_json(entry: &msgfmt::ModEntry) -> serde_json::Value {
    serde_json::json!({
        "id": entry.id,
        "version": entry.version,
        "enabled": entry.enabled,
        "abi": entry.abi,
        "size": entry.size,
        "blake3": hex(&entry.blake3),
        "capabilities": entry.capabilities,
    })
}

async fn mod_command(state: &Path, command: ModCommand) -> io::Result<()> {
    let root = state.join("mods");
    fs::create_dir_all(&root)?;
    let mut store = ModStore::open(&root).map_err(|error| io::Error::other(error.to_string()))?;
    match command {
        ModCommand::Add {
            id,
            version,
            file,
            abi,
            caps,
            url,
        } => {
            if !valid_mod_id(&id) {
                return Err(invalid(format!("invalid module id: {id}")));
            }
            if !valid_mod_version(&version) {
                return Err(invalid(format!("invalid module version: {version}")));
            }
            if abi == 0 || abi > MAX_ABI {
                return Err(invalid(format!("unsupported module ABI: {abi}")));
            }
            let bytes = fs::read(&file)?;
            if bytes.len() as u64 > 4 * 1024 * 1024 {
                return Err(invalid("module exceeds 4 MiB"));
            }
            let source = match url {
                Some(url) => url,
                None => format!("file://{}", fs::canonicalize(&file)?.to_string_lossy()),
            };
            let entry = ModEntry {
                id: id.clone(),
                version: version.clone(),
                abi,
                blake3: *blake3::hash(&bytes).as_bytes(),
                size: bytes.len() as u64,
                url: source,
                capabilities: caps,
                enabled: true,
            };
            let policy = policy_for(state)?;
            let set = ModSet {
                gen: store.generation().saturating_add(1),
                add: vec![entry.clone()],
                remove: Vec::new(),
            };
            store
                .apply(&set, &policy)
                .await
                .map_err(|error| io::Error::other(error.to_string()))?;
            println!("{}", entry_json(&entry));
        }
        ModCommand::Remove { id, version } => {
            if !valid_mod_id(&id) || !valid_mod_version(&version) {
                return Err(invalid("invalid module id or version"));
            }
            if !store.remove(&id, &version) {
                return Err(invalid(format!("module not installed: {id}@{version}")));
            }
        }
        ModCommand::Enable { id, version } => {
            if !valid_mod_id(&id) || !valid_mod_version(&version) {
                return Err(invalid("invalid module id or version"));
            }
            if !store.set_enabled(&id, &version, true) {
                return Err(invalid(format!("module not installed: {id}@{version}")));
            }
        }
        ModCommand::Disable { id, version } => {
            if !valid_mod_id(&id) || !valid_mod_version(&version) {
                return Err(invalid("invalid module id or version"));
            }
            if !store.set_enabled(&id, &version, false) {
                return Err(invalid(format!("module not installed: {id}@{version}")));
            }
        }
        ModCommand::Set { modules } => {
            let mut wanted = Vec::new();
            for spec in &modules {
                let (id, version) = spec
                    .split_once('@')
                    .ok_or_else(|| invalid("module must be id@version"))?;
                if !valid_mod_id(id) || !valid_mod_version(version) {
                    return Err(invalid(format!("invalid module identity: {spec}")));
                }
                if store.get(id, version).is_none()
                    && !store
                        .entries()
                        .any(|entry| entry.entry.id == id && entry.entry.version == version)
                {
                    return Err(invalid(format!("module not installed: {spec}")));
                }
                wanted.push((id.to_owned(), version.to_owned()));
            }
            let installed = store
                .entries()
                .map(|installed| {
                    (
                        installed.entry.id.clone(),
                        installed.entry.version.clone(),
                        installed.entry.enabled,
                    )
                })
                .collect::<Vec<_>>();
            for (id, version, was_enabled) in installed {
                let enabled = wanted.contains(&(id.clone(), version.clone()));
                if enabled != was_enabled && !store.set_enabled(&id, &version, enabled) {
                    return Err(invalid(format!("module not installed: {id}@{version}")));
                }
            }
        }
        ModCommand::Task {
            id,
            version,
            tag,
            epoch,
            args,
            push,
        } => {
            if !valid_mod_id(&id) || !valid_mod_version(&version) {
                return Err(invalid("invalid module id or version"));
            }
            if store.get(&id, &version).is_none() {
                return Err(invalid(format!(
                    "unknown or disabled module {id}@{version}"
                )));
            }
            let args = match args {
                Some(args) => serde_json::from_str(&args)
                    .map_err(|error| invalid(format!("args must be JSON: {error}")))?,
                None => serde_json::json!({}),
            };
            let cbor = serde_cbor::value::to_value(&args)
                .map_err(|error| invalid(format!("args are not CBOR-representable: {error}")))?;
            let (signing, _) = load_keys(state)?;
            let path = write_frame(
                state,
                Task {
                    route_tag: tag_or_derived(tag, &signing),
                    epoch,
                    body: TaskBody::Mod {
                        mod_id: id,
                        version,
                        args: cbor,
                    },
                },
            )?;
            if push {
                let specs = relay_specs(state)?;
                let bytes = fs::read(&path)?;
                if push_frame(&specs, &bytes).await? {
                    fs::remove_file(&path)?;
                    println!("pushed");
                } else {
                    return Err(io::Error::other(format!(
                        "relay quorum unavailable; frame kept at {}",
                        path.display()
                    )));
                }
            } else {
                println!("{}", path.display());
            }
        }
        ModCommand::Call { id, version, args } => {
            if !valid_mod_id(&id) || !valid_mod_version(&version) {
                return Err(invalid("invalid module id or version"));
            }
            let Some(installed) = store.get(&id, &version) else {
                return Err(invalid(format!(
                    "unknown or disabled module {id}@{version}"
                )));
            };
            let bytes = fs::read(&installed.path)?;
            let args = match args {
                Some(args) => serde_json::from_str(&args)
                    .map_err(|error| invalid(format!("args must be JSON: {error}")))?,
                None => serde_json::json!({}),
            };
            let host = WasmHost::with_state(state, policy_for(state)?)
                .map_err(|error| io::Error::other(error.to_string()))?
                .with_limits(Limits::default());
            let outcome = host
                .run(&bytes, &args)
                .await
                .map_err(|error| io::Error::other(error.to_string()))?;
            println!(
                "{}",
                serde_json::json!({
                    "id": id,
                    "version": version,
                    "ok": outcome.ok,
                    "code": outcome.code,
                    "stdout": outcome.stdout,
                    "stderr": outcome.stderr,
                })
            );
        }
        ModCommand::List => {
            for installed in store.entries() {
                println!("{}", entry_json(&installed.entry));
            }
        }
    }
    Ok(())
}
