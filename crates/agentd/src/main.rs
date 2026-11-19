#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Agent polling daemon, durable cursor state, dispatch, and task handlers.

use agentd::{handlers, limits, plugins, production, resilience};

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded.rs"));
}

mod morph;
use ed25519_dalek::{SigningKey, VerifyingKey};
use handlers::{HandlerOutcome, HandlerRegistry, ModHandler};
use msgfmt::{
    decode_checked, decode_relay_set, encode_result, RelayEntry, RelaySet, ResultMessage, TaskBody,
};
use plugins::{CapabilityPolicy, Limits, ModStore};
use serde_cbor::Value;
use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};
use thiserror::Error;
use tokio::{
    sync::{watch, Mutex},
    time::{sleep_until, Instant},
};
use transport::{channel_id, Channel, MockFsChannel, RelayChannel};

/// Errors returned by agent state operations.
#[derive(Debug, Error)]
enum Error {
    #[error("filesystem error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid persisted state")]
    InvalidState,
    #[error("configuration error: {0}")]
    Config(String),
}

/// Durable state used by the polling loop.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct AgentState {
    cursor: u64,
    epoch: u64,
}

impl AgentState {
    fn load(path: &Path) -> Result<Self, Error> {
        match fs::read_to_string(path) {
            Ok(contents) => {
                let mut values = contents.lines().map(str::parse::<u64>);
                let cursor = values
                    .next()
                    .ok_or(Error::InvalidState)?
                    .map_err(|_| Error::InvalidState)?;
                let epoch = values
                    .next()
                    .ok_or(Error::InvalidState)?
                    .map_err(|_| Error::InvalidState)?;
                Ok(Self { cursor, epoch })
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error.into()),
        }
    }

    fn persist(&self, path: &Path) -> Result<(), Error> {
        let bytes = format!("{}\n{}\n", self.cursor, self.epoch);
        let state_dir = path.parent().unwrap_or_else(|| Path::new("."));
        let relative = path
            .file_name()
            .map_or_else(|| PathBuf::from("agent.state"), PathBuf::from);
        resilience::mirrored_write(state_dir, &relative, bytes.as_bytes())
            .map_err(|error| io::Error::other(error.to_string()).into())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct CursorStore {
    cursors: BTreeMap<[u8; 8], u64>,
}

impl CursorStore {
    fn load(state_dir: &Path) -> Result<Self, Error> {
        let path = state_dir.join("cursors.json");
        if path.exists() {
            return Ok(Self {
                cursors: parse_cursor_lines(&fs::read_to_string(path)?)?,
            });
        }
        let legacy = state_dir.join("cursor");
        if legacy.exists() {
            let cursor = fs::read_to_string(&legacy)
                .map_err(|_| Error::InvalidState)?
                .trim()
                .parse()
                .map_err(|_| Error::InvalidState)?;
            fs::rename(legacy, state_dir.join("cursor.migrated"))?;
            return Ok(Self {
                cursors: BTreeMap::from([([0; 8], cursor)]),
            });
        }
        Ok(Self::default())
    }

    fn get(&self, id: [u8; 8]) -> u64 {
        self.cursors.get(&id).copied().unwrap_or(0)
    }

    fn set(&mut self, id: [u8; 8], cursor: u64) {
        self.cursors.insert(id, cursor);
    }

    fn adopt_legacy(&mut self, id: [u8; 8]) {
        if id != [0; 8] {
            if let Some(cursor) = self.cursors.remove(&[0; 8]) {
                self.cursors.entry(id).or_insert(cursor);
            }
        }
    }

    fn persist(&self, state_dir: &Path) -> Result<(), Error> {
        let contents = self
            .cursors
            .iter()
            .map(|(id, cursor)| format!("{} {}", hex_id(id), cursor))
            .collect::<Vec<_>>()
            .join("\n");
        resilience::mirrored_write(
            state_dir,
            Path::new("cursors.json"),
            (contents + "\n").as_bytes(),
        )
        .map_err(|error| io::Error::other(error.to_string()).into())
    }
}

fn hex_id(id: &[u8; 8]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_cursor_lines(contents: &str) -> Result<BTreeMap<[u8; 8], u64>, Error> {
    let mut cursors = BTreeMap::new();
    for line in contents.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split_whitespace();
        let hex = fields.next().ok_or(Error::InvalidState)?;
        let cursor = fields
            .next()
            .ok_or(Error::InvalidState)?
            .parse()
            .map_err(|_| Error::InvalidState)?;
        if hex.len() != 16 {
            return Err(Error::InvalidState);
        }
        let mut id = [0_u8; 8];
        for index in 0..8 {
            id[index] = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
                .map_err(|_| Error::InvalidState)?;
        }
        cursors.insert(id, cursor);
    }
    Ok(cursors)
}

/// Outcome of one polling cycle.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct CycleReport {
    processed: u64,
    skipped: u64,
    cursor: u64,
    dropped: u64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ChannelHealth {
    successes: u64,
    failures: u64,
    last_ok: bool,
    strikes: u8,
    skip_until: u64,
}

impl ChannelHealth {
    fn failure(&mut self) {
        self.failures += 1;
        self.last_ok = false;
        self.strikes = self.strikes.saturating_add(1);
        if self.strikes >= 3 {
            self.skip_until = unix_now().saturating_add(600);
        }
    }

    fn success(&mut self) {
        self.successes += 1;
        self.last_ok = true;
        self.strikes = 0;
        self.skip_until = 0;
    }

    fn eligible(&self) -> bool {
        unix_now() >= self.skip_until
    }
}

#[derive(Debug, Clone, Default)]
struct RelayRegistry {
    generation: u64,
    entries: BTreeMap<[u8; 8], RelayEntry>,
    tombstones: BTreeMap<[u8; 8], u64>,
}

impl RelayRegistry {
    fn load(path: &Path) -> Result<Self, Error> {
        let text = match fs::read_to_string(path) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => return Err(error.into()),
        };
        let mut registry = Self::default();
        for line in text.lines() {
            let mut fields = line.splitn(5, '\t');
            match fields.next() {
                Some("gen") => {
                    registry.generation = fields
                        .next()
                        .ok_or(Error::InvalidState)?
                        .parse()
                        .map_err(|_| Error::InvalidState)?
                }
                Some("entry") => {
                    let id = parse_hex_id(fields.next().ok_or(Error::InvalidState)?)?;
                    let kind = fields.next().ok_or(Error::InvalidState)?.to_owned();
                    let tier = fields
                        .next()
                        .ok_or(Error::InvalidState)?
                        .parse()
                        .map_err(|_| Error::InvalidState)?;
                    let addr = fields.next().ok_or(Error::InvalidState)?.to_owned();
                    registry.entries.insert(
                        id,
                        RelayEntry {
                            id,
                            kind,
                            tier,
                            addr,
                        },
                    );
                }
                Some("remove") => {
                    let id = parse_hex_id(fields.next().ok_or(Error::InvalidState)?)?;
                    let generation = fields
                        .next()
                        .ok_or(Error::InvalidState)?
                        .parse()
                        .map_err(|_| Error::InvalidState)?;
                    registry.tombstones.insert(id, generation);
                }
                _ => return Err(Error::InvalidState),
            }
        }
        Ok(registry)
    }

    fn apply(&mut self, set: RelaySet) -> Result<bool, Error> {
        if set.gen <= self.generation || set.add.len() + self.entries.len() > 32 {
            return Ok(false);
        }
        for entry in &set.add {
            if channel_id(&entry.kind, &entry.addr) != entry.id {
                return Err(Error::InvalidState);
            }
        }
        for id in set.remove {
            self.entries.remove(&id);
            self.tombstones.insert(id, set.gen);
        }
        for entry in set.add {
            if self
                .tombstones
                .get(&entry.id)
                .is_some_and(|generation| *generation >= set.gen)
            {
                continue;
            }
            self.entries.insert(entry.id, entry);
        }
        self.generation = set.gen;
        Ok(true)
    }

    fn persist(&self, path: &Path) -> Result<(), Error> {
        let mut text = format!("gen\t{}\n", self.generation);
        for entry in self.entries.values() {
            text.push_str(&format!(
                "entry\t{}\t{}\t{}\t{}\n",
                hex_id(&entry.id),
                entry.kind,
                entry.tier,
                entry.addr
            ));
        }
        for (id, generation) in &self.tombstones {
            text.push_str(&format!("remove\t{}\t{}\n", hex_id(id), generation));
        }
        let temp = path.with_extension("new");
        fs::write(&temp, text)?;
        fs::rename(temp, path)?;
        Ok(())
    }
}

fn parse_hex_id(value: &str) -> Result<[u8; 8], Error> {
    if value.len() != 16 {
        return Err(Error::InvalidState);
    }
    let mut id = [0_u8; 8];
    for index in 0..8 {
        id[index] = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| Error::InvalidState)?;
    }
    Ok(id)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[derive(Debug, Default)]
struct ResultSeen {
    order: std::collections::VecDeque<String>,
    values: std::collections::HashSet<String>,
}

impl ResultSeen {
    fn load(path: &Path) -> Result<Self, Error> {
        let mut seen = Self::default();
        let contents = match fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(seen),
            Err(error) => return Err(error.into()),
        };
        for value in contents.lines().filter(|line| !line.is_empty()) {
            seen.insert(value.to_owned());
        }
        Ok(seen)
    }

    fn contains(&self, key: &str) -> bool {
        self.values.contains(key)
    }

    fn insert(&mut self, key: String) {
        if !self.values.insert(key.clone()) {
            return;
        }
        self.order.push_back(key);
        while self.order.len() > 4096 {
            if let Some(old) = self.order.pop_front() {
                self.values.remove(&old);
            }
        }
    }

    fn persist(&self, path: &Path) -> Result<(), Error> {
        fs::write(
            path,
            self.order
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join("\n")
                + "\n",
        )?;
        Ok(())
    }
}

/// An agent that polls channels and dispatches authenticated tasks.
struct Agent {
    channels: Vec<Arc<dyn Channel>>,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    coordinator_key: VerifyingKey,
    enc_key: [u8; 32],
    state_path: PathBuf,
    results_path: PathBuf,
    errors_path: PathBuf,
    state: AgentState,
    cursors: CursorStore,
    state_dir: PathBuf,
    health: BTreeMap<[u8; 8], ChannelHealth>,
    results_seen: ResultSeen,
    relay_registry: RelayRegistry,
    mod_store: Arc<Mutex<ModStore>>,
    registry: HandlerRegistry,
    policy: CapabilityPolicy,
    interval: Duration,
    jitter_percent: u64,
    total_failures: u8,
    last_heartbeat: Instant,
    artifact: Option<(String, Option<String>)>,
    rotation_epoch: u64,
    upgrade_epoch: u64,
    upgrade_path: PathBuf,
    restart_requested: bool,
}

impl Agent {
    /// Creates an agent and restores its durable cursor and epoch.
    #[cfg(test)]
    fn new(
        channel: Arc<dyn Channel>,
        signing_key: SigningKey,
        enc_key: [u8; 32],
        state_dir: impl Into<PathBuf>,
    ) -> Result<Self, Error> {
        Self::with_channels(vec![channel], signing_key, enc_key, state_dir)
    }

    #[cfg(test)]
    fn with_channels(
        channels: Vec<Arc<dyn Channel>>,
        signing_key: SigningKey,
        enc_key: [u8; 32],
        state_dir: impl Into<PathBuf>,
    ) -> Result<Self, Error> {
        Self::with_policy(
            channels,
            signing_key,
            enc_key,
            state_dir,
            CapabilityPolicy::default(),
            Duration::from_secs(300),
        )
    }

    #[allow(dead_code)]
    fn with_policy(
        channels: Vec<Arc<dyn Channel>>,
        signing_key: SigningKey,
        enc_key: [u8; 32],
        state_dir: impl Into<PathBuf>,
        policy: CapabilityPolicy,
        interval: Duration,
    ) -> Result<Self, Error> {
        Self::with_coordinator(
            channels,
            signing_key,
            enc_key,
            state_dir,
            policy,
            interval,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn with_coordinator(
        channels: Vec<Arc<dyn Channel>>,
        signing_key: SigningKey,
        enc_key: [u8; 32],
        state_dir: impl Into<PathBuf>,
        policy: CapabilityPolicy,
        interval: Duration,
        coordinator: Option<VerifyingKey>,
    ) -> Result<Self, Error> {
        if channels.is_empty() {
            return Err(Error::InvalidState);
        }
        policy
            .validate()
            .map_err(|error| Error::Config(error.to_string()))?;
        let state_dir = state_dir.into();
        fs::create_dir_all(&state_dir)?;
        let state_path = state_dir.join("agent.state");
        let state = AgentState::load(&state_path)?;
        let mut cursors = CursorStore::load(&state_dir)?;
        cursors.adopt_legacy(channels[0].id());
        cursors.persist(&state_dir)?;
        fs::create_dir_all(state_dir.join("pending_results"))?;
        let results_seen = ResultSeen::load(&state_dir.join("results_seen.json"))?;
        let relay_registry = RelayRegistry::load(&state_dir.join("relays.json"))?;
        let mod_store = Arc::new(Mutex::new(ModStore::open(state_dir.join("mods")).map_err(
            |error| Error::Io(io::Error::other(format!("module store: {error}"))),
        )?));
        let mut registry = HandlerRegistry::new(8);
        registry
            .register_all()
            .map_err(|error| Error::invalid_state_report(error.to_string()))?;
        registry
            .register(Arc::new(ModHandler::new(
                Arc::clone(&mod_store),
                policy.clone(),
                Limits::default(),
                state_dir.clone(),
            )))
            .map_err(|error| Error::invalid_state_report(error.to_string()))?;
        let upgrade_path = fs::read_to_string(state_dir.join("seed.path"))
            .map(|text| PathBuf::from(text.trim()))
            .unwrap_or_else(|_| {
                std::env::current_exe().unwrap_or_else(|_| PathBuf::from("agentd"))
            });
        let verifying_key = signing_key.verifying_key();
        let coordinator = coordinator.or_else(|| {
            fs::read(state_dir.join("coordinator.pub"))
                .ok()
                .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
                .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
        });
        let rotation_epoch = read_u64(&state_dir.join("rotation.state"));
        let upgrade_epoch = read_u64(&state_dir.join("upgrade.state"));
        Ok(Self {
            channels,
            signing_key,
            verifying_key,
            coordinator_key: coordinator.unwrap_or(verifying_key),
            enc_key,
            state_path,
            results_path: state_dir.join("results.log"),
            errors_path: state_dir.join("errors.log"),
            state,
            cursors,
            state_dir,
            health: BTreeMap::new(),
            results_seen,
            relay_registry,
            mod_store,
            registry,
            policy,
            interval,
            jitter_percent: 50,
            total_failures: 0,
            last_heartbeat: Instant::now(),
            artifact: None,
            rotation_epoch,
            upgrade_epoch,
            upgrade_path,
            restart_requested: false,
        })
    }

    /// Sets the poll jitter percentage.
    fn with_jitter(mut self, percent: u64) -> Self {
        self.jitter_percent = percent.min(90);
        self
    }

    /// Overrides the executable path replaced by upgrades (tests).
    #[allow(dead_code)]
    fn with_upgrade_path(mut self, path: PathBuf) -> Self {
        self.upgrade_path = path;
        self
    }

    /// Enables spool upload after each cycle.
    fn with_artifacts(mut self, url: Option<String>, token: Option<String>) -> Self {
        if let Some(url) = url {
            self.artifact = Some((url, token));
        }
        self
    }

    /// Adopts a coordinator key rotation and persists the generation.
    fn apply_rotation(&mut self, rotate: msgfmt::Rotate) -> Result<(), Error> {
        let key = VerifyingKey::from_bytes(&rotate.new_pub)
            .map_err(|error| Error::invalid_state_report(error.to_string()))?;
        write_private(&self.state_dir.join("coordinator.pub"), &rotate.new_pub)?;
        write_u64(&self.state_dir.join("rotation.state"), self.rotation_epoch)?;
        self.coordinator_key = key;
        Ok(())
    }

    /// Downloads, verifies, and stages a new binary, then requests a restart.
    async fn apply_upgrade(&mut self, upgrade: msgfmt::Upgrade) -> Result<(), Error> {
        let debug = self.state_dir.join("upgrade.debug");
        let _ = fs::write(
            &debug,
            format!(
                "version={} epoch={} url={}\n",
                upgrade.version, upgrade.epoch, upgrade.url
            ),
        );
        write_u64(&self.state_dir.join("upgrade.state"), self.upgrade_epoch)?;
        if upgrade.version == env!("CARGO_PKG_VERSION") {
            return Ok(());
        }
        let target = self.upgrade_path.clone();
        let staging = target.with_extension("new");
        let staging_copy = staging.clone();
        let url = upgrade.url.clone();
        let size = upgrade.size as usize;
        let sha = upgrade.sha256;
        let downloaded =
            tokio::task::spawn_blocking(move || download_binary(&url, &staging_copy, size, &sha))
                .await
                .map_err(|error| Error::invalid_state_report(error.to_string()))?;
        if let Err(error) = &downloaded {
            let _ = fs::write(&debug, format!("download error: {error}\n"));
        }
        downloaded?;
        let _ = fs::write(&debug, "downloaded\n");
        // A running binary cannot always be replaced in place (Windows), so keep
        // the staged file and let the next start promote it.
        if fs::rename(&staging, &target).is_err() {
            let _ = fs::copy(&staging, &target);
        }
        self.restart_requested = true;
        Ok(())
    }

    /// Announces identity and liveness on every channel.
    ///
    /// The body repeats the public key so a coordinator can verify first contact,
    /// and the header tag proves the key is the one that signed.
    async fn send_heartbeat(&mut self) -> Result<(), Error> {
        let host = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| "unknown".into());
        let heartbeat = msgfmt::Heartbeat {
            agent_pub: *self.verifying_key.as_bytes(),
            host,
            version: env!("CARGO_PKG_VERSION").into(),
            poll_interval_s: self.interval.as_secs(),
            enc_key: self.enc_key,
            epoch: unix_millis(),
        };
        let bytes =
            msgfmt::encode_heartbeat(&heartbeat, &msgfmt::BOOTSTRAP_ENC_KEY, &self.signing_key)
                .map_err(|error| Error::invalid_state_report(error.to_string()))?;
        for channel in &self.channels {
            let _ = channel.put(&bytes).await;
        }
        self.last_heartbeat = Instant::now();
        Ok(())
    }

    /// Polls all channels concurrently, skipping corrupted frames without terminating the daemon.
    async fn poll_once(&mut self) -> Result<CycleReport, Error> {
        self.poll_all(Duration::from_secs(10)).await
    }

    fn eligible_channels(&self) -> Vec<Arc<dyn Channel>> {
        let mut candidates = self
            .channels
            .iter()
            .filter(|channel| {
                self.health
                    .get(&channel.id())
                    .is_none_or(ChannelHealth::eligible)
            })
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            candidates = self.channels.iter().collect();
        }
        let tier = candidates
            .iter()
            .map(|channel| channel.tier())
            .min()
            .unwrap_or(0);
        candidates
            .into_iter()
            .filter(|channel| channel.tier() == tier)
            .cloned()
            .collect()
    }

    fn restore_bootstrap(&mut self) -> Result<(), Error> {
        self.relay_registry = RelayRegistry::default();
        for line in include_str!("bootstrap_relays.txt")
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        {
            let mut fields = line.splitn(4, ':');
            let tier = fields
                .next()
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            let _priority = fields.next();
            let kind = fields.next().unwrap_or_default().to_owned();
            let addr = fields.next().unwrap_or_default().to_owned();
            let id = channel_id(&kind, &addr);
            self.relay_registry.entries.insert(
                id,
                RelayEntry {
                    id,
                    kind,
                    tier,
                    addr,
                },
            );
        }
        self.relay_registry
            .persist(&self.state_dir.join("relays.json"))
    }

    async fn poll_all(&mut self, budget: Duration) -> Result<CycleReport, Error> {
        let timeout_budget = budget.min(Duration::from_secs(10));
        let eligible = self.eligible_channels();
        let mut jobs = Vec::with_capacity(eligible.len());
        for channel in eligible {
            let id = channel.id();
            let cursor = self.cursors.get(id);
            let channel = Arc::clone(&channel);
            jobs.push(tokio::spawn(async move {
                (
                    id,
                    cursor,
                    tokio::time::timeout(timeout_budget, channel.list_since(cursor)).await,
                )
            }));
        }
        let mut report = CycleReport::default();
        for job in jobs {
            let (channel_id, cursor, result) = job.await.map_err(|_| Error::InvalidState)?;
            let entries = match result {
                Ok(Ok(entries)) => {
                    let health = self.health.entry(channel_id).or_default();
                    health.success();
                    self.total_failures = 0;
                    entries
                }
                Ok(Err(error)) => {
                    let health = self.health.entry(channel_id).or_default();
                    health.failure();
                    self.total_failures = self.total_failures.saturating_add(1);
                    self.record_error(&format!("channel {}: {error}", hex_id(&channel_id)))?;
                    continue;
                }
                Err(_) => {
                    let health = self.health.entry(channel_id).or_default();
                    health.failure();
                    self.total_failures = self.total_failures.saturating_add(1);
                    self.record_error(&format!("channel {}: poll timeout", hex_id(&channel_id)))?;
                    continue;
                }
            };
            let mut channel_cursor = cursor;
            for (index, bytes) in entries {
                channel_cursor = channel_cursor.max(index);
                match decode_checked(
                    &bytes,
                    &self.coordinator_key,
                    &self.enc_key,
                    &mut self.state.epoch,
                ) {
                    Ok(decoded) => {
                        self.dispatch(
                            channel_id,
                            decoded.task.route_tag,
                            decoded.task.epoch,
                            decoded.task.body,
                        )
                        .await?;
                        report.processed += 1;
                    }
                    Err(error) => {
                        if error == msgfmt::Error::UnknownMsgType {
                            if let Ok(rotate) = msgfmt::decode_rotate(
                                &bytes,
                                &self.coordinator_key,
                                &self.enc_key,
                                &mut self.rotation_epoch,
                            ) {
                                if let Err(error) = self.apply_rotation(rotate) {
                                    self.record_error(&format!("rotate: {error}"))?;
                                }
                                report.processed += 1;
                                self.cursors.set(channel_id, channel_cursor);
                                continue;
                            }
                            if let Ok(upgrade) = msgfmt::decode_upgrade(
                                &bytes,
                                &self.coordinator_key,
                                &self.enc_key,
                                &mut self.upgrade_epoch,
                            ) {
                                match self.apply_upgrade(upgrade).await {
                                    Ok(()) => report.processed += 1,
                                    Err(error) => {
                                        self.record_error(&format!("upgrade: {error}"))?;
                                        report.skipped += 1;
                                    }
                                }
                                self.cursors.set(channel_id, channel_cursor);
                                continue;
                            }
                            if let Ok(decoded) = decode_relay_set(
                                &bytes,
                                &self.coordinator_key,
                                &self.enc_key,
                                &mut self.state.epoch,
                            ) {
                                if self.relay_registry.apply(decoded.relay_set)? {
                                    self.relay_registry
                                        .persist(&self.state_dir.join("relays.json"))?;
                                }
                                report.processed += 1;
                                self.cursors.set(channel_id, channel_cursor);
                                continue;
                            }
                            if let Ok(decoded) = msgfmt::decode_mod_set(
                                &bytes,
                                &self.coordinator_key,
                                &self.enc_key,
                                &mut self.state.epoch,
                            ) {
                                let applied = {
                                    let mut store = self.mod_store.lock().await;
                                    store.apply(&decoded.mod_set, &self.policy).await.is_ok()
                                };
                                if applied {
                                    report.processed += 1;
                                    self.cursors.set(channel_id, channel_cursor);
                                    continue;
                                }
                            }
                        }
                        self.record_error(&error.to_string())?;
                        self.record_pending(channel_id, index, &error.to_string())?;
                        report.skipped += 1;
                    }
                }
                self.cursors.set(channel_id, channel_cursor);
                self.state.cursor = channel_cursor;
                self.state.persist(&self.state_path)?;
                self.cursors.persist(&self.state_dir)?;
            }
            report.cursor = report.cursor.max(channel_cursor);
        }
        self.flush_pending_results().await?;
        if self.total_failures >= 12 {
            self.restore_bootstrap()?;
            self.total_failures = 0;
        }
        report.dropped = self.registry.dropped();
        Ok(report)
    }

    /// Waits until every in-flight handler invocation has finished.
    async fn wait_idle(&self) {
        self.registry.wait_idle().await;
    }

    async fn flush_pending_results(&mut self) -> Result<(), Error> {
        let directory = self.state_dir.join("pending_results");
        let entries = fs::read_dir(&directory)?
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        for entry in entries {
            let key = entry
                .file_name()
                .to_string_lossy()
                .trim_end_matches(".bin")
                .to_owned();
            let bytes = fs::read(entry.path())?;
            let mut delivered = false;
            for channel in &self.channels {
                let id = channel.id();
                if !self.health.get(&id).is_some_and(|health| health.last_ok) {
                    continue;
                }
                if channel.put(&bytes).await.is_ok() {
                    delivered = true;
                    break;
                }
            }
            if delivered {
                self.results_seen.insert(key);
                fs::remove_file(entry.path())?;
            }
        }
        self.results_seen
            .persist(&self.state_dir.join("results_seen.json"))?;
        Ok(())
    }

    fn record_pending(&self, channel_id: [u8; 8], index: u64, error: &str) -> Result<(), Error> {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.state_dir.join("pending.json"))?;
        writeln!(
            file,
            "{{\"channel\":\"{}\",\"index\":{index},\"error\":{:?}}}",
            hex_id(&channel_id),
            error
        )?;
        Ok(())
    }

    async fn dispatch(
        &mut self,
        source_id: [u8; 8],
        route_tag: [u8; 8],
        epoch: u64,
        body: TaskBody,
    ) -> Result<(), Error> {
        let (name, args) = handler_call(&body);
        let outcome = match self.registry.handle(name, &args).await {
            Ok(outcome) => outcome,
            Err(error) => HandlerOutcome::failed(error.to_string()),
        };
        self.audit(&outcome)?;
        let key = format!("{}:{epoch}", hex_id(&route_tag));
        if self.results_seen.contains(&key) {
            return Ok(());
        }
        let result = ResultMessage {
            task_epoch: epoch,
            agent_pub: *self.verifying_key.as_bytes(),
            ok: outcome.ok,
            stdout: outcome.stdout,
            stderr: outcome.stderr,
            code: outcome.code,
        };
        let bytes = encode_result_fitted(result, &self.enc_key, &self.signing_key)
            .map_err(|error| Error::invalid_state_report(format!("result encode: {error}")))?;
        self.fan_out_result(source_id, key, bytes).await
    }

    fn audit(&self, outcome: &HandlerOutcome) -> Result<(), Error> {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.results_path)?;
        writeln!(
            file,
            "ok={} code={} stdout={} stderr={}",
            outcome.ok, outcome.code, outcome.stdout, outcome.stderr
        )?;
        Ok(())
    }

    async fn fan_out_result(
        &mut self,
        source_id: [u8; 8],
        key: String,
        bytes: Vec<u8>,
    ) -> Result<(), Error> {
        let mut targets = Vec::new();
        for channel in &self.channels {
            let id = channel.id();
            if id == source_id || self.health.get(&id).is_some_and(|health| health.last_ok) {
                targets.push(Arc::clone(channel));
            }
        }
        targets.truncate(2);
        let mut jobs = Vec::new();
        for channel in targets {
            let bytes = bytes.clone();
            jobs.push(tokio::spawn(async move { channel.put(&bytes).await }));
        }
        let mut delivered = false;
        for job in jobs {
            if job.await.map_err(|_| Error::InvalidState)?.is_ok() {
                delivered = true;
            }
        }
        if delivered {
            self.results_seen.insert(key);
            self.results_seen
                .persist(&self.state_dir.join("results_seen.json"))?;
        } else {
            self.queue_pending_result(&key, &bytes)?;
        }
        Ok(())
    }

    fn queue_pending_result(&self, key: &str, bytes: &[u8]) -> Result<(), Error> {
        let directory = self.state_dir.join("pending_results");
        let count = fs::read_dir(&directory)?.filter_map(Result::ok).count();
        if count >= 64 {
            return Ok(());
        }
        fs::write(directory.join(format!("{key}.bin")), bytes)?;
        Ok(())
    }

    fn record_error(&self, message: &str) -> Result<(), Error> {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.errors_path)?;
        writeln!(file, "{message}")?;
        Ok(())
    }

    /// Runs polling cycles until shutdown, calling `on_cycle` after each cycle.
    async fn run<F>(
        &mut self,
        max_cycles: Option<u64>,
        mut shutdown: watch::Receiver<bool>,
        mut on_cycle: F,
    ) -> Result<(), Error>
    where
        F: FnMut(&CycleReport) -> Result<(), Error>,
    {
        let mut cycles = 0_u64;
        loop {
            // A signal may have arrived during startup, before the first cycle.
            // Do not start work that the drain timer has already stopped waiting for.
            if *shutdown.borrow() {
                return Ok(());
            }
            match self.poll_once().await {
                Ok(report) => {
                    if self.last_heartbeat.elapsed() >= Duration::from_secs(600) {
                        self.send_heartbeat().await?;
                    }
                    if let Some((url, token)) = &self.artifact {
                        let state = self.state_dir.clone();
                        let url = url.clone();
                        let token = token.clone();
                        let signing = self.signing_key.clone();
                        let tag = msgfmt::route_tag_from_key(self.verifying_key.as_bytes());
                        let _ = tokio::task::spawn_blocking(move || {
                            let _ = agentd::artifacts::upload_pending(
                                &state,
                                &url,
                                &tag,
                                &signing,
                                token.as_deref(),
                                4,
                            );
                        })
                        .await;
                    }
                    on_cycle(&report)?;
                }
                Err(error) => {
                    self.record_error(&format!("poll cycle: {error}"))?;
                    on_cycle(&CycleReport::default())?;
                }
            }
            cycles = cycles.saturating_add(1);
            if self.restart_requested || max_cycles.is_some_and(|limit| cycles >= limit) {
                return Ok(());
            }
            let interval = jittered_interval(self.interval, self.jitter_percent);
            tokio::select! {
                _ = sleep_until(Instant::now() + interval) => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// Returns the handler name and CBOR arguments for a task body.
fn handler_call(body: &TaskBody) -> (&'static str, Value) {
    let mut map = BTreeMap::new();
    match body {
        TaskBody::Ping => ("ping", Value::Map(map)),
        TaskBody::Shell {
            argv,
            timeout_s,
            shell,
        } => {
            map.insert(
                Value::Text("argv".into()),
                Value::Array(argv.iter().cloned().map(Value::Text).collect()),
            );
            map.insert(Value::Text("shell".into()), Value::Bool(*shell));
            map.insert(
                Value::Text("timeout_s".into()),
                Value::Integer(i128::from(*timeout_s)),
            );
            ("shell", Value::Map(map))
        }
        TaskBody::Fetch { url, dest } => {
            map.insert(Value::Text("url".into()), Value::Text(url.clone()));
            map.insert(Value::Text("dest".into()), Value::Text(dest.clone()));
            ("fetch", Value::Map(map))
        }
        TaskBody::Mod {
            mod_id,
            version,
            args,
        } => {
            map.insert(Value::Text("mod_id".into()), Value::Text(mod_id.clone()));
            map.insert(Value::Text("version".into()), Value::Text(version.clone()));
            map.insert(Value::Text("args".into()), args.clone());
            ("mod", Value::Map(map))
        }
    }
}

fn encode_result_fitted(
    mut result: ResultMessage,
    enc_key: &[u8; 32],
    signing_key: &SigningKey,
) -> Result<Vec<u8>, msgfmt::Error> {
    for _ in 0..12 {
        match encode_result(&result, enc_key, signing_key) {
            Ok(bytes) => return Ok(bytes),
            Err(msgfmt::Error::BadLength) => {
                result.ok = false;
                if result.stdout.len() > 256 {
                    result.stdout = truncate_with_ellipsis(&result.stdout, result.stdout.len() / 2);
                } else if result.stdout.len() > 3 {
                    result.stdout = truncate_with_ellipsis(&result.stdout, 2);
                } else if !result.stderr.is_empty() {
                    result.stderr = truncate_with_ellipsis(&result.stderr, result.stderr.len() / 2);
                } else {
                    return Err(msgfmt::Error::BadLength);
                }
            }
            Err(error) => return Err(error),
        }
    }
    Err(msgfmt::Error::BadLength)
}

fn truncate_with_ellipsis(text: &str, limit: usize) -> String {
    let mut end = limit.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut truncated = text[..end].to_owned();
    truncated.push_str("...");
    truncated
}

/// Returns a uniformly random interval within ±`percent` of `base`.
fn jittered_interval(base: Duration, percent: u64) -> Duration {
    use rand::RngCore;
    let spread = percent.min(90) as f64 / 100.0;
    let unit = rand::rngs::OsRng.next_u64() as f64 / u64::MAX as f64;
    let factor = 1.0 - spread + unit * spread * 2.0;
    base.mul_f64(factor).max(Duration::from_millis(1))
}

fn main() {
    // A lone binary carries its own config; default state lives beside $HOME.
    let mut state = std::env::var_os("AF_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|| match std::env::var_os("HOME") {
            Some(home) => PathBuf::from(home).join(".af"),
            None => PathBuf::from(".agent-fleet"),
        });
    let mut worker = false;
    let mut once = false;
    let mut command = None;
    let mut enable = false;
    let mut no_backstop = false;
    let mut quick = false;
    let mut doctor_json = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--worker" => worker = true,
            "--once" => once = true,
            "install" | "uninstall" | "guard" | "doctor" | "recover-key" => command = Some(arg),
            "--enable" => enable = true,
            "--no-backstop" => no_backstop = true,
            "--quick" => quick = true,
            "--json" => doctor_json = true,
            "--state" => {
                state = PathBuf::from(args.next().unwrap_or_else(|| {
                    std::process::exit(2);
                }));
            }
            "--help" | "-h" => {
                println!("agentd [--state DIR] [--worker] [--once] | install | uninstall | guard [--quick] | doctor [--json] | recover-key");
                return;
            }
            _ => {
                std::process::exit(2);
            }
        }
    }
    let _ = fs::create_dir_all(&state);
    if let Some(command) = command {
        let executable = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("agentd"));
        let result = match command.as_str() {
            "install" => resilience::install(&state, &executable, enable, !no_backstop),
            "uninstall" => resilience::uninstall(&state),
            "guard" => resilience::guard(&state, &executable, quick).map(|status| {
                if status != resilience::CheckStatus::Healthy {
                    std::process::exit(1);
                }
            }),
            "doctor" => resilience::doctor(&state, &executable).map(|report| {
                if doctor_json {
                    println!("{}", report.json());
                } else {
                    for check in &report.checks {
                        println!("{}\t{}\t{}", check.status, check.name, check.detail);
                    }
                }
                if report.needs_attention() {
                    std::process::exit(1);
                }
            }),
            "recover-key" => resilience::recover_agent_key(&state).map(|recovered| {
                if recovered {
                    println!("agent key recovered from a verified mirror");
                } else if state.join("agent.key").is_file() {
                    println!("agent key already present");
                } else {
                    eprintln!("no verified mirrored agent key available");
                    std::process::exit(1);
                }
            }),
            _ => unreachable!(),
        };
        if result.is_err() {
            std::process::exit(2);
        }
        return;
    }
    let logger = match production::JsonLogger::open(state.join("agentd.log")) {
        Ok(logger) => logger,
        Err(error) => {
            let _ = error;
            std::process::exit(1);
        }
    };
    logger.install_panic_hook();
    if morph::enabled() {
        if let Ok(exe) = std::env::current_exe() {
            let seed = state.join("seed.path");
            if !seed.is_file() {
                let _ = write_private(&seed, exe.to_string_lossy().as_bytes());
            }
            if let Ok(target) = morph::stage_copy(&exe) {
                let _ = logger.event(
                    "info",
                    "morph",
                    &[
                        ("from", exe.display().to_string()),
                        ("to", target.display().to_string()),
                    ],
                );
                morph::reexec(&target);
            }
        }
    }
    let result = if worker {
        run_worker(state, once, logger)
    } else {
        match production::InstanceLock::acquire(&state) {
            Ok(_lock) => {
                let worker_pid = Arc::new(AtomicU32::new(0));
                let stopping = Arc::new(AtomicBool::new(false));
                {
                    let worker_pid = worker_pid.clone();
                    let stopping = stopping.clone();
                    std::thread::spawn(move || {
                        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                        else {
                            return;
                        };
                        runtime.block_on(async {
                            wait_for_shutdown_signal(None).await;
                            // Publish the stop before dereferencing the pid so the
                            // supervisor does not restart a worker it just reaped.
                            stopping.store(true, Ordering::SeqCst);
                            let pid = worker_pid.load(Ordering::SeqCst);
                            if pid != 0 {
                                limits::terminate_process(pid);
                            }
                        });
                    });
                }
                production::supervise(
                    &std::env::current_exe().unwrap_or_else(|_| PathBuf::from("agentd")),
                    &state,
                    once,
                    &logger,
                    &worker_pid,
                    &stopping,
                )
            }
            Err(error) => Err(error),
        }
    };
    if let Err(error) = result {
        eprintln!("{error}");
        let code = if matches!(error, production::ProductionError::Config(_)) {
            2
        } else {
            1
        };
        std::process::exit(code);
    }
}

fn read_u64(path: &Path) -> u64 {
    fs::read_to_string(path)
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0)
}

fn write_u64(path: &Path, value: u64) -> Result<(), Error> {
    fs::write(path, format!("{value}\n"))?;
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn download_binary(url: &str, staging: &Path, size: usize, sha: &[u8; 32]) -> Result<(), Error> {
    use sha2::Digest;
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|error| Error::Io(io::Error::other(error.to_string())))?;
    let response = client
        .get(url)
        .send()
        .map_err(|error| Error::Io(io::Error::other(format!("{error:?}"))))?;
    if !response.status().is_success() {
        return Err(Error::invalid_state_report(format!(
            "upgrade HTTP {}",
            response.status()
        )));
    }
    let mut bytes = Vec::with_capacity(size.min(1024 * 1024));
    let mut limited = std::io::Read::take(response, size as u64 + 1);
    std::io::Read::read_to_end(&mut limited, &mut bytes)?;
    if bytes.len() != size {
        return Err(Error::invalid_state_report(format!(
            "upgrade size {} != {size}",
            bytes.len()
        )));
    }
    if sha2::Sha256::digest(&bytes).as_slice() != sha.as_slice() {
        return Err(Error::invalid_state_report(
            "upgrade digest mismatch".into(),
        ));
    }
    if let Some(parent) = staging.parent() {
        fs::create_dir_all(parent)?;
    }
    let part = staging.with_extension("part");
    fs::write(&part, &bytes)?;
    fs::rename(&part, staging)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(staging, fs::Permissions::from_mode(0o755));
    }
    Ok(())
}

fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_millis() as u64)
        .unwrap_or(0)
}

/// Loads a key, generating and persisting a fresh one when absent.
fn load_or_create_key(state: &Path, name: &str) -> Result<[u8; 32], production::ProductionError> {
    if state.join(name).is_file() {
        let loaded = load_key(state, name)?;
        return Ok(loaded);
    }
    use rand::RngCore;
    let mut key = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    write_private(&state.join(name), &key)
        .map_err(|error| production::ProductionError::Supervisor(error.to_string()))?;
    Ok(key)
}

fn load_key(state: &Path, name: &str) -> Result<[u8; 32], production::ProductionError> {
    let bytes = fs::read(state.join(name)).map_err(|_| {
        production::ProductionError::Config(format!("missing or unreadable {name}"))
    })?;
    bytes
        .try_into()
        .map_err(|_| production::ProductionError::Config(format!("{name} must be 32 bytes")))
}

fn build_channels(
    state: &Path,
    config: &production::Config,
) -> Result<Vec<Arc<dyn Channel>>, production::ProductionError> {
    match config.channel.as_str() {
        "mock-fs" => {
            let root = config
                .channel_arg
                .as_ref()
                .map(PathBuf::from)
                .unwrap_or_else(|| state.join("queue"));
            Ok(vec![Arc::new(MockFsChannel::new(root))])
        }
        "relay" => {
            let url = config.channel_arg.clone().ok_or_else(|| {
                production::ProductionError::Config("relay channel requires channel_arg".into())
            })?;
            let channel = RelayChannel::new(url)
                .map_err(|error| production::ProductionError::Config(error.to_string()))?;
            Ok(vec![Arc::new(channel)])
        }
        other => Err(production::ProductionError::Config(format!(
            "unknown channel {other}"
        ))),
    }
}

/// Relay channels advertised by the persisted relay registry.
fn registry_channels(state: &Path) -> Vec<Arc<dyn Channel>> {
    let Ok(registry) = RelayRegistry::load(&state.join("relays.json")) else {
        return Vec::new();
    };
    registry
        .entries
        .values()
        .filter(|entry| entry.kind == "relay" || entry.kind == "http")
        .filter_map(|entry| {
            transport::parse_relay_spec(&format!("{}:0:{}:{}", entry.tier, entry.kind, entry.addr))
                .ok()
                .and_then(|spec| RelayChannel::from_spec(&spec).ok())
                .map(|channel| Arc::new(channel) as Arc<dyn Channel>)
        })
        .collect()
}

/// Fetches a signed relay set from a dead-drop URL and applies it.
fn fetch_dead_drop(state: &Path, url: &str, enc: &[u8; 32]) -> Option<()> {
    let public = fs::read(state.join("coordinator.pub")).ok()?;
    let public: [u8; 32] = public.try_into().ok()?;
    let verifying = VerifyingKey::from_bytes(&public).ok()?;
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .ok()?;
    let response = client.get(url).send().ok()?;
    if !response.status().is_success() {
        return None;
    }
    let mut bytes = Vec::new();
    let mut limited = std::io::Read::take(response, 64 * 1024);
    std::io::Read::read_to_end(&mut limited, &mut bytes).ok()?;
    let decoded = msgfmt::decode_relay_set(&bytes, &verifying, enc, &mut 0).ok()?;
    let mut registry = RelayRegistry::load(&state.join("relays.json")).ok()?;
    if registry.apply(decoded.relay_set).ok()? {
        registry.persist(&state.join("relays.json")).ok()?;
    }
    Some(())
}

fn run_worker(
    state: PathBuf,
    once: bool,
    logger: production::JsonLogger,
) -> Result<(), production::ProductionError> {
    production::apply_resource_policy(&logger)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| production::ProductionError::Supervisor(error.to_string()))?;
    runtime.block_on(async move {
        // Register the signal listener before any startup work. Replica repair can
        // copy a large executable, and a SIGTERM during that window must drain
        // rather than take the default, process-killing disposition.
        let (sender, receiver) = watch::channel(false);
        let drain = production::drain_len();
        // `--once` intentionally keeps the default signal disposition: a cron
        // one-shot should die on SIGTERM, not swallow it.
        let signal_task = if once {
            None
        } else {
            let (ready_sender, ready_receiver) = tokio::sync::oneshot::channel();
            let signal_sender = sender.clone();
            let drain_logger = logger.clone();
            let task = tokio::spawn(async move {
                wait_for_shutdown_signal(Some(ready_sender)).await;
                let _ = signal_sender.send(true);
                // The polling loop stops between cycles, so the cycle already in
                // flight gets the drain window to finish. Anything still running
                // after that window is terminated by process group.
                tokio::time::sleep(drain).await;
                let _ = drain_logger.event(
                    "warn",
                    "drain_timeout",
                    &[("drain_ms", drain.as_millis().to_string())],
                );
                handlers::kill_active_process_groups();
            });
            let _ = ready_receiver.await;
            Some(task)
        };

        let startup_state = state.clone();
        let startup = tokio::task::spawn_blocking(move || start_worker(startup_state))
            .await
            .map_err(|error| production::ProductionError::Supervisor(error.to_string()))?;
        let ready = startup?;
        let ReadyStartup {
            config,
            signing_key,
            enc_key,
            policy,
            channels,
            coordinator,
        } = *ready;
        logger.event(
            "info",
            "worker_cycle",
            &[
                ("state", state.display().to_string()),
                ("outcome", "started".into()),
            ],
        )?;
        let mut agent = Agent::with_coordinator(
            channels,
            signing_key,
            enc_key,
            state.clone(),
            policy,
            Duration::from_secs(config.poll_interval_s),
            coordinator,
        )
        .map_err(|error| production::ProductionError::Supervisor(error.to_string()))?
        .with_artifacts(config.artifact_url.clone(), config.artifact_token.clone())
        .with_jitter(config.jitter_percent);
        agent
            .send_heartbeat()
            .await
            .map_err(|error| production::ProductionError::Supervisor(error.to_string()))?;
        if once {
            let report = agent
                .poll_once()
                .await
                .map_err(|error| production::ProductionError::Supervisor(error.to_string()))?;
            println!(
                "processed={} skipped={} cursor={} dropped={}",
                report.processed, report.skipped, report.cursor, report.dropped
            );
            return Ok(());
        }
        let run_result = agent
            .run(None, receiver, |report| {
                resilience::touch_alive(&state)
                    .map_err(|error| Error::Io(io::Error::other(error.to_string())))?;
                let _ = logger.event(
                    "info",
                    "worker_cycle",
                    &[
                        ("processed", report.processed.to_string()),
                        ("skipped", report.skipped.to_string()),
                        ("cursor", report.cursor.to_string()),
                    ],
                );
                Ok(())
            })
            .await;
        run_result.map_err(|error| production::ProductionError::Supervisor(error.to_string()))?;
        if agent.restart_requested {
            logger.event("info", "upgrade_ready", &[])?;
        }

        // The signal task owns the drain window: it kills surviving process
        // groups when the window closes. Exit as soon as handlers are idle, but
        // do not cancel the timer before the configured window has elapsed, or
        // a long AGENT_FLEET_DRAIN_MS would silently collapse to a fixed grace.
        let mut signal_task = signal_task;
        let budget = drain + Duration::from_secs(5);
        let drained = {
            let idle = agent.wait_idle();
            tokio::pin!(idle);
            tokio::time::timeout(budget, async {
                match signal_task.as_mut() {
                    Some(task) => {
                        tokio::select! {
                            _ = &mut idle => task.abort(),
                            _ = &mut *task => idle.await,
                        }
                    }
                    None => idle.await,
                }
            })
            .await
        };
        if drained.is_err() {
            logger.event(
                "warn",
                "drain_incomplete",
                &[("drain_ms", drain.as_millis().to_string())],
            )?;
            handlers::kill_active_process_groups();
            let _ = tokio::time::timeout(Duration::from_secs(5), agent.wait_idle()).await;
        }
        agent
            .flush_pending_results()
            .await
            .map_err(|error| production::ProductionError::Supervisor(error.to_string()))?;
        logger.event(
            "info",
            "drain_complete",
            &[("drain_ms", drain.as_millis().to_string())],
        )?;
        Ok(())
    })
}

/// Resolves when the process receives Ctrl-C or SIGTERM.
///
/// When `ready` is provided it fires once signal registration is complete, so
/// callers can safely continue startup knowing a later signal will be caught.
async fn wait_for_shutdown_signal(ready: Option<tokio::sync::oneshot::Sender<()>>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = match signal(SignalKind::terminate()) {
            Ok(terminate) => terminate,
            Err(_) => {
                if let Some(ready) = ready {
                    let _ = ready.send(());
                }
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        if let Some(ready) = ready {
            let _ = ready.send(());
        }
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        if let Some(ready) = ready {
            let _ = ready.send(());
        }
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Assembled worker state for a successful startup.
struct ReadyStartup {
    config: production::Config,
    signing_key: SigningKey,
    enc_key: [u8; 32],
    policy: CapabilityPolicy,
    channels: Vec<Arc<dyn Channel>>,
    coordinator: Option<VerifyingKey>,
}

/// Performs the synchronous part of worker startup.
///
/// Runs on the blocking pool so the async signal listener stays responsive while
/// replicas and keys are repaired.
fn start_worker(state: PathBuf) -> Result<Box<ReadyStartup>, production::ProductionError> {
    if let Ok(executable) = std::env::current_exe() {
        production::promote_staged(&executable);
    }
    let _ = resilience::recover_agent_key(&state);
    let _ = resilience::restore_from_mirrors(&state, Path::new("cursors.json"));
    let _ = resilience::try_reenrol(&state);
    if state.join("agent.key").is_file() {
        let _ = resilience::mirror_agent_key(&state);
    }

    // Touch liveness before enrolment so guard and doctor can distinguish an
    // unenrolled but running worker from a stopped one.
    resilience::touch_alive(&state)
        .map_err(|error| production::ProductionError::Supervisor(error.to_string()))?;
    if let Ok(executable) = std::env::current_exe() {
        let _ = resilience::repair_replicas(&state, &executable, env!("CARGO_PKG_VERSION"), "1");
        let _ = resilience::tamper_findings(&state, &executable);
    }

    let config_path = state.join("config.toml");
    if !config_path.is_file() && !embedded::CONFIG.is_empty() {
        let _ = fs::write(&config_path, embedded::CONFIG);
    }
    let config = if config_path.is_file() {
        production::Config::load(&config_path)?
    } else {
        production::Config {
            state_dir: state.clone(),
            ..Default::default()
        }
    };
    config.validate()?;
    // No grant and no key: self-enrol. The heartbeat announces the key, so the
    // coordinator learns it on first contact (trust on first use).
    let signing_secret = load_or_create_key(&state, "agent.key")?;
    let signing_key = SigningKey::from_bytes(&signing_secret);
    let policy = CapabilityPolicy {
        allow_caps: config.allow_caps.clone(),
        allow_exec: config.allow_exec,
        allow_net: config.allow_net,
    };
    policy
        .validate()
        .map_err(|error| production::ProductionError::Config(error.to_string()))?;
    let enc_key = load_or_create_key(&state, "enc.key")?;
    if let Some(url) = &config.dead_drop_url {
        let _ = fetch_dead_drop(&state, url, &enc_key);
    }
    let mut channels = build_channels(&state, &config)?;
    for channel in registry_channels(&state) {
        if !channels
            .iter()
            .any(|existing| existing.id() == channel.id())
        {
            channels.push(channel);
        }
    }
    if !state.join("coordinator.pub").is_file() && !embedded::COORD.is_empty() {
        let _ = fs::write(state.join("coordinator.pub"), embedded::COORD);
    }
    let coordinator = fs::read(state.join("coordinator.pub"))
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
        .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok());
    Ok(Box::new(ReadyStartup {
        config,
        signing_key,
        enc_key,
        policy,
        channels,
        coordinator,
    }))
}

impl Error {
    fn invalid_state_report(message: String) -> Self {
        Error::Config(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use msgfmt::{decode_result, encode_task, Task};
    use tokio::time::sleep;
    use transport::{Channel, MockFsChannel};

    fn root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("agentd-{label}-{}", std::process::id()))
    }

    #[tokio::test]
    async fn rotation_swaps_the_coordinator_key_and_rejects_replay() {
        let state = root("rotate");
        let _ = fs::remove_dir_all(&state);
        let channel = Arc::new(MockFsChannel::new(state.join("queue")));
        let agent_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let enc = [3_u8; 32];
        let old = SigningKey::generate(&mut rand::rngs::OsRng);
        let fresh = SigningKey::generate(&mut rand::rngs::OsRng);
        fs::create_dir_all(&state).unwrap();
        fs::write(
            state.join("coordinator.pub"),
            old.verifying_key().as_bytes(),
        )
        .unwrap();
        let mut agent = Agent::new(
            Arc::clone(&channel) as Arc<dyn Channel>,
            agent_key,
            enc,
            &state,
        )
        .unwrap();
        let generation = unix_millis();
        let frame = msgfmt::encode_rotate(
            &msgfmt::Rotate {
                new_pub: *fresh.verifying_key().as_bytes(),
                generation,
            },
            &enc,
            &old,
        )
        .unwrap();
        let rotate = msgfmt::decode_rotate(
            &frame,
            &agent.coordinator_key,
            &enc,
            &mut agent.rotation_epoch,
        )
        .unwrap();
        agent.apply_rotation(rotate).unwrap();
        assert_eq!(
            fs::read(state.join("coordinator.pub")).unwrap(),
            fresh.verifying_key().as_bytes()
        );
        assert_eq!(agent.coordinator_key, fresh.verifying_key());
        // A task signed by the new key is accepted.
        let task = Task {
            route_tag: msgfmt::route_tag_from_key(fresh.verifying_key().as_bytes()),
            epoch: 1,
            body: msgfmt::TaskBody::Ping,
        };
        let signed = encode_task(&task, &enc, &fresh).unwrap();
        let mut epoch = 0;
        assert!(msgfmt::decode_checked(&signed, &agent.coordinator_key, &enc, &mut epoch).is_ok());
        // Replay of the same generation is stale.
        assert!(matches!(
            msgfmt::decode_rotate(
                &frame,
                &old.verifying_key(),
                &enc,
                &mut agent.rotation_epoch
            ),
            Err(msgfmt::Error::StaleEpoch)
        ));
        let _ = fs::remove_dir_all(&state);
    }

    #[tokio::test]
    async fn upgrade_downloads_verifies_and_stages() {
        use ed25519_dalek::Signer;
        use sha2::Digest;
        use std::io::{Read, Write};
        let state = root("upgrade");
        let _ = fs::remove_dir_all(&state);
        fs::create_dir_all(&state).unwrap();
        let target = state.join("agentd");
        fs::write(&target, b"old").unwrap();
        let body = b"new-binary-bytes".to_vec();
        let sha: [u8; 32] = sha2::Sha256::digest(&body).into();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let served = body.clone();
        std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 4096];
            let _ = socket.read(&mut buffer);
            let _ = write!(
                socket,
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                served.len()
            );
            let _ = socket.write_all(&served);
        });
        let agent_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let coordinator = SigningKey::generate(&mut rand::rngs::OsRng);
        let channel = Arc::new(MockFsChannel::new(state.join("queue")));
        let mut agent = Agent::new(
            Arc::clone(&channel) as Arc<dyn Channel>,
            agent_key,
            [4; 32],
            &state,
        )
        .unwrap()
        .with_upgrade_path(target.clone());
        agent.upgrade_epoch = 10;
        let upgrade = msgfmt::Upgrade {
            version: "9.9.9".into(),
            sha256: sha,
            size: body.len() as u64,
            url: format!("http://127.0.0.1:{port}/agentd"),
            epoch: 11,
        };
        agent.apply_upgrade(upgrade).await.unwrap();
        assert!(agent.restart_requested);
        assert_eq!(fs::read(&target).unwrap(), body);
        assert!(!target.with_extension("new").exists());
        let _ = coordinator.sign(b"x");
        let _ = fs::remove_dir_all(&state);
    }

    #[test]
    fn jitter_is_uniform_and_bounded() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let value = jittered_interval(Duration::from_secs(1000), 50);
            assert!(value >= Duration::from_secs(500), "{value:?}");
            assert!(value <= Duration::from_secs(1500), "{value:?}");
            seen.insert(value.as_millis());
        }
        assert!(seen.len() > 150, "jitter is not random: {}", seen.len());
        // Disabled jitter is exact.
        assert_eq!(
            jittered_interval(Duration::from_secs(60), 0),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn morph_stages_random_copies_and_prunes() {
        let state = root("morph");
        let _ = fs::remove_dir_all(&state);
        fs::create_dir_all(&state).unwrap();
        let exe = state.join("agentd");
        fs::write(&exe, b"binary").unwrap();
        let mut names = std::collections::HashSet::new();
        for _ in 0..5 {
            let target = crate::morph::stage_copy(&exe).unwrap();
            assert_eq!(fs::read(&target).unwrap(), b"binary");
            assert!(names.insert(target.file_name().unwrap().to_owned()));
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let copies = fs::read_dir(&state)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(".agentd-"))
            .count();
        assert_eq!(copies, 2, "only two previous copies are kept");
        let _ = fs::remove_dir_all(&state);
    }

    #[test]
    fn dead_drop_relay_set_is_verified_and_persisted() {
        use std::io::{Read, Write};
        let state = root("dead-drop");
        let _ = fs::remove_dir_all(&state);
        fs::create_dir_all(&state).unwrap();
        let coordinator = SigningKey::generate(&mut rand::rngs::OsRng);
        fs::write(
            state.join("coordinator.pub"),
            coordinator.verifying_key().as_bytes(),
        )
        .unwrap();
        let enc = [8_u8; 32];
        let relay_set = msgfmt::RelaySet {
            gen: 4,
            add: vec![msgfmt::RelayEntry {
                id: transport::channel_id("relay", "http://127.0.0.1:9999"),
                kind: "relay".into(),
                tier: 0,
                addr: "http://127.0.0.1:9999".into(),
            }],
            remove: Vec::new(),
        };
        let frame = msgfmt::encode_relay_set(&relay_set, &enc, &coordinator).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let served = frame.clone();
        std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 1024];
            let _ = socket.read(&mut buffer);
            let _ = write!(
                socket,
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                served.len()
            );
            let _ = socket.write_all(&served);
        });
        assert!(
            fetch_dead_drop(&state, &format!("http://127.0.0.1:{port}/relays"), &enc).is_some()
        );
        let persisted = fs::read_to_string(state.join("relays.json")).unwrap();
        assert!(persisted.contains("http://127.0.0.1:9999"), "{persisted}");

        // A frame signed by another key is rejected and the file is unchanged.
        let stranger = SigningKey::generate(&mut rand::rngs::OsRng);
        let forged = msgfmt::encode_relay_set(&relay_set, &enc, &stranger).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 1024];
            let _ = socket.read(&mut buffer);
            let _ = write!(
                socket,
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                forged.len()
            );
            let _ = socket.write_all(&forged);
        });
        assert!(
            fetch_dead_drop(&state, &format!("http://127.0.0.1:{port}/relays"), &enc).is_none()
        );
        assert_eq!(
            fs::read_to_string(state.join("relays.json")).unwrap(),
            persisted
        );
        let _ = fs::remove_dir_all(&state);
    }

    #[test]
    fn legacy_cursor_is_renamed_and_adopted_by_channel() {
        let state = root("cursor-migration");
        let _ = fs::remove_dir_all(&state);
        fs::create_dir_all(&state).expect("state directory should be created");
        fs::write(state.join("cursor"), "17\n").expect("legacy cursor should be written");
        let mut cursors = CursorStore::load(&state).expect("legacy state should load");
        assert!(state.join("cursor.migrated").exists());
        let id = [9; 8];
        cursors.adopt_legacy(id);
        assert_eq!(cursors.get(id), 17);
        cursors.persist(&state).expect("cursor map should persist");
        assert!(fs::read_to_string(state.join("cursors.json"))
            .unwrap()
            .contains("0909090909090909 17"));
        let _ = fs::remove_dir_all(state);
    }

    #[test]
    fn result_seen_is_a_bounded_lru_set() {
        let mut seen = ResultSeen::default();
        seen.insert("first".into());
        seen.insert("first".into());
        assert!(seen.contains("first"));
        for index in 0..4096 {
            seen.insert(format!("key-{index}"));
        }
        assert_eq!(seen.order.len(), 4096);
        assert!(!seen.contains("first"));
    }

    #[tokio::test]
    async fn poll_all_drains_three_channels_without_starvation() {
        let state = root("poll-all-state");
        let queues = (0..3)
            .map(|index| root(&format!("poll-all-{index}")))
            .collect::<Vec<_>>();
        let _ = fs::remove_dir_all(&state);
        for queue in &queues {
            let _ = fs::remove_dir_all(queue);
        }
        let signing = SigningKey::from_bytes(&[8; 32]);
        let mut channels: Vec<Arc<dyn Channel>> = Vec::new();
        for (index, queue) in queues.iter().enumerate() {
            let channel = Arc::new(MockFsChannel::new(queue));
            let frame = encode_task(
                &Task {
                    route_tag: [0; 8],
                    epoch: index as u64 + 1,
                    body: TaskBody::Ping,
                },
                &[6; 32],
                &signing,
            )
            .expect("frame should encode");
            channel.put(&frame).await.expect("frame should be stored");
            channels.push(channel);
        }
        let mut agent =
            Agent::with_channels(channels, signing, [6; 32], &state).expect("agent should load");
        let report = agent
            .poll_all(Duration::from_secs(1))
            .await
            .expect("poll should work");
        assert_eq!(report.processed, 3);
        for queue in queues {
            let _ = fs::remove_dir_all(queue);
        }
        let _ = fs::remove_dir_all(state);
    }

    #[tokio::test]
    async fn ping_produces_signed_result_and_persists_cursor() {
        let queue = root("queue");
        let state = root("state");
        let _ = fs::remove_dir_all(&queue);
        let _ = fs::remove_dir_all(&state);
        let channel = Arc::new(MockFsChannel::new(&queue));
        let signing = SigningKey::from_bytes(&[3; 32]);
        let frame = encode_task(
            &Task {
                route_tag: [7; 8],
                epoch: 1,
                body: TaskBody::Ping,
            },
            &[5; 32],
            &signing,
        )
        .expect("frame should encode");
        channel.put(&frame).await.expect("put should work");
        let mut agent =
            Agent::new(channel, signing.clone(), [5; 32], &state).expect("agent should load");
        let report = agent.poll_once().await.expect("poll should work");
        assert_eq!(report.processed, 1);
        assert!(fs::read_to_string(state.join("results.log"))
            .expect("audit result should exist")
            .contains("ok=true"));
        let mut last = 0;
        let result = decode_result(
            &fs::read(queue.join("000000000002.bin")).expect("result frame"),
            &signing.verifying_key(),
            &[5; 32],
            &mut last,
        )
        .expect("result decodes");
        assert!(result.result.ok);
        assert_eq!(result.result.task_epoch, 1);
        assert_eq!(
            AgentState::load(&state.join("agent.state"))
                .expect("state should reload")
                .cursor,
            1
        );
        let _ = fs::remove_dir_all(queue);
        let _ = fs::remove_dir_all(state);
    }

    #[tokio::test]
    async fn repeated_poll_processes_one_frame_total() {
        let queue = root("replay-queue");
        let state = root("replay-state");
        let _ = fs::remove_dir_all(&queue);
        let _ = fs::remove_dir_all(&state);
        let channel = Arc::new(MockFsChannel::new(&queue));
        let signing = SigningKey::from_bytes(&[3; 32]);
        let frame = encode_task(
            &Task {
                route_tag: [0; 8],
                epoch: 1,
                body: TaskBody::Ping,
            },
            &[5; 32],
            &signing,
        )
        .expect("frame should encode");
        channel.put(&frame).await.expect("put should work");
        let mut agent = Agent::new(channel, signing, [5; 32], &state).expect("agent should load");
        assert_eq!(agent.poll_once().await.expect("first poll").processed, 1);
        assert_eq!(agent.poll_once().await.expect("second poll").processed, 0);
        let _ = fs::remove_dir_all(queue);
        let _ = fs::remove_dir_all(state);
    }

    #[tokio::test]
    async fn large_stdout_is_truncated_and_forced_unsuccessful() {
        let outcome = HandlerOutcome {
            ok: true,
            stdout: "x".repeat(5000),
            stderr: String::new(),
            code: 0,
        };
        let signing = SigningKey::from_bytes(&[3; 32]);
        let bytes = encode_result_fitted(
            ResultMessage {
                task_epoch: 1,
                agent_pub: *signing.verifying_key().as_bytes(),
                ok: outcome.ok,
                stdout: outcome.stdout,
                stderr: outcome.stderr,
                code: outcome.code,
            },
            &[5; 32],
            &signing,
        )
        .expect("fitted result should encode");
        let mut last = 0;
        let decoded = decode_result(&bytes, &signing.verifying_key(), &[5; 32], &mut last)
            .expect("fitted result decodes");
        assert!(!decoded.result.ok);
        assert!(decoded.result.stdout.ends_with("..."));
    }

    #[tokio::test]
    async fn corrupted_frame_is_skipped_and_logged() {
        let queue = root("bad-queue");
        let state = root("bad-state");
        let _ = fs::remove_dir_all(&queue);
        let _ = fs::remove_dir_all(&state);
        let channel = Arc::new(MockFsChannel::new(&queue));
        channel.put(&[1, 2, 3]).await.expect("put should work");
        let signing = SigningKey::from_bytes(&[4; 32]);
        let mut agent = Agent::new(channel, signing, [5; 32], &state).expect("agent should load");
        let report = agent.poll_once().await.expect("poll should continue");
        assert_eq!(report.skipped, 1);
        assert!(fs::read_to_string(state.join("errors.log"))
            .expect("error log should exist")
            .contains("truncated"));
        let _ = fs::remove_dir_all(queue);
        let _ = fs::remove_dir_all(state);
    }

    #[tokio::test]
    async fn shell_echo_timeout_and_output_cap_work() {
        let echo = handlers::run_shell(vec!["printf".into(), "hi".into()], 2, false).await;
        assert_eq!(echo.stdout, "hi");
        assert!(echo.ok);
        let timeout_result = handlers::run_shell(vec!["sleep".into(), "2".into()], 0, false).await;
        assert_eq!(timeout_result.code, -1);
        let large = handlers::run_shell(
            vec!["sh".into(), "-c".into(), "yes x | head -c 70000".into()],
            2,
            false,
        )
        .await;
        assert!(!large.ok);
        assert!(large.stdout.ends_with("..."));
    }

    #[test]
    fn jitter_stays_within_forty_percent() {
        for _ in 0..100 {
            let value = jittered_interval(Duration::from_secs(300), 40);
            assert!((180..=420).contains(&value.as_secs()));
        }
    }

    #[tokio::test]
    async fn run_survives_a_poll_error_and_stops_on_shutdown() {
        let queue = root("shutdown-queue");
        let state = root("shutdown-state");
        let _ = fs::remove_dir_all(&queue);
        let _ = fs::remove_dir_all(&state);
        let channel = Arc::new(MockFsChannel::new(&queue));
        let signing = SigningKey::from_bytes(&[4; 32]);
        let mut agent = Agent::with_policy(
            vec![channel],
            signing,
            [5; 32],
            &state,
            CapabilityPolicy::default(),
            Duration::from_millis(1),
        )
        .expect("agent should load");
        let (sender, receiver) = watch::channel(false);
        let cycles = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let count = std::sync::Arc::clone(&cycles);
        let run = agent.run(Some(3), receiver, move |_report| {
            count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        });
        let stopper = async {
            sleep(Duration::from_millis(10)).await;
            let _ = sender.send(true);
        };
        let (result, ()) = tokio::join!(run, stopper);
        result.expect("run should stop cleanly");
        assert_eq!(cycles.load(std::sync::atomic::Ordering::Relaxed), 3);
        let _ = fs::remove_dir_all(queue);
        let _ = fs::remove_dir_all(state);
    }

    #[tokio::test]
    async fn run_does_not_start_a_cycle_when_shutdown_is_already_set() {
        let queue = root("presignal-queue");
        let state = root("presignal-state");
        let _ = fs::remove_dir_all(&queue);
        let _ = fs::remove_dir_all(&state);
        let channel = Arc::new(MockFsChannel::new(&queue));
        let signing = SigningKey::from_bytes(&[4; 32]);
        let frame = encode_task(
            &Task {
                route_tag: [0; 8],
                epoch: 1,
                body: TaskBody::Ping,
            },
            &[5; 32],
            &signing,
        )
        .expect("frame");
        channel.put(&frame).await.expect("queue the task");
        let mut agent = Agent::with_policy(
            vec![channel],
            signing,
            [5; 32],
            &state,
            CapabilityPolicy::default(),
            Duration::from_millis(1),
        )
        .expect("agent should load");
        let (sender, receiver) = watch::channel(false);
        sender.send(true).expect("pre-signal");
        let cycles = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let count = std::sync::Arc::clone(&cycles);
        let run = agent.run(None, receiver, move |_report| {
            count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        });
        let result = tokio::time::timeout(Duration::from_secs(2), run)
            .await
            .expect("a pre-signaled run returns before the first cycle");
        result.expect("run should stop cleanly");
        assert_eq!(cycles.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(
            fs::read_dir(&queue).expect("queue").count(),
            1,
            "the queued task is untouched"
        );
        let _ = fs::remove_dir_all(queue);
        let _ = fs::remove_dir_all(state);
    }
}
