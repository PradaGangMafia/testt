//! Coordinator core: pull, verify, ingest, and schedule.

#![forbid(unsafe_code)]

pub mod artifact;

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    thread::sleep,
    time::Duration,
};

use db::{Database, VerifiedResult};
use ed25519_dalek::SigningKey;
use msgfmt::{decode_heartbeat, decode_result_any, encode_task, Task, TaskBody};
use serde_cbor::Value as CborValue;
use transport::{channel_id, parse_list, parse_relay_spec};

/// Coordinator errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Filesystem or database failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Database failure.
    #[error("database: {0}")]
    Db(#[from] db::Error),
    /// Key material is missing or malformed.
    #[error("keys: {0}")]
    Keys(String),
    /// A relay could not be reached or rejected a frame.
    #[error("relay: {0}")]
    Relay(String),
    /// Frame or task encoding failed.
    #[error("frame: {0}")]
    Frame(#[from] msgfmt::Error),
}

/// Opens the coordinator database, creating or loading its SQLCipher key and
/// migrating a plaintext database in place.
pub fn open_database(state: &Path) -> Result<Database, Error> {
    fs::create_dir_all(state)?;
    let key_path = state.join("coord.key");
    let key = match fs::read(&key_path) {
        Ok(bytes) => <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| Error::Keys("coord.key must be 32 bytes".into()))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            use rand::rngs::OsRng;
            use rand::RngCore;
            let mut key = [0_u8; 32];
            OsRng.fill_bytes(&mut key);
            fs::write(&key_path, key)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
            }
            key
        }
        Err(error) => return Err(error.into()),
    };
    let database_path = state.join("findings.db");
    if database_path.is_file() && !db::is_encrypted(&database_path) {
        db::encrypt_file(&database_path, &key)?;
    }
    Ok(Database::open_encrypted(&database_path, &key)?)
}

/// Pull summary.
#[derive(Debug, Default, Clone, Copy)]
pub struct PullReport {
    /// Frames examined.
    pub seen: u64,
    /// Results ingested.
    pub results: u64,
    /// Heartbeats registered.
    pub heartbeats: u64,
    /// Frames skipped or malformed.
    pub skipped: u64,
}

/// One coordinator instance.
pub struct Coord {
    database: Database,
    signing: SigningKey,
    enc: [u8; 32],
    state: PathBuf,
    epochs: BTreeMap<[u8; 8], u64>,
}

/// A parsed relay.
#[derive(Debug, Clone)]
pub struct Relay {
    /// URL.
    pub url: String,
    /// Stable id used for cursors.
    pub id: [u8; 8],
}

impl Coord {
    /// Opens a coordinator state directory with its keys and database.
    pub fn open(state: &Path) -> Result<Self, Error> {
        let signing_bytes =
            fs::read(state.join("agent.key")).map_err(|error| Error::Keys(error.to_string()))?;
        let signing_bytes: [u8; 32] = signing_bytes
            .try_into()
            .map_err(|_| Error::Keys("agent.key must be 32 bytes".into()))?;
        let enc: [u8; 32] = fs::read(state.join("enc.key"))
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .unwrap_or(msgfmt::BOOTSTRAP_ENC_KEY);
        let signing = SigningKey::from_bytes(&signing_bytes);
        let database = open_database(state)?;
        Ok(Self {
            database,
            signing,
            enc,
            state: state.to_path_buf(),
            epochs: BTreeMap::new(),
        })
    }

    /// Returns the database.
    pub fn database(&self) -> &Database {
        &self.database
    }

    /// Returns the shared encryption key.
    pub fn enc_key(&self) -> [u8; 32] {
        self.enc
    }

    /// Returns the signing key.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    /// Returns the coordinator public key.
    pub fn public_key(&self) -> [u8; 32] {
        *self.signing.verifying_key().as_bytes()
    }

    /// Returns configured relays.
    pub fn relays(&self) -> Result<Vec<Relay>, Error> {
        let text = match fs::read_to_string(self.state.join("relays.conf")) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut relays = Vec::new();
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            let spec = match parse_relay_spec(line) {
                Ok(spec) => spec,
                Err(error) => return Err(Error::Relay(error.to_string())),
            };
            relays.push(Relay {
                id: channel_id(&spec.kind, &spec.arg),
                url: spec.arg.trim_end_matches('/').to_owned(),
            });
        }
        Ok(relays)
    }

    /// Pushes a frame to a majority of relays.
    pub fn push(&self, bytes: &[u8]) -> Result<bool, Error> {
        let relays = self.relays()?;
        if relays.is_empty() {
            return Err(Error::Relay("no relays configured".into()));
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|error| Error::Relay(error.to_string()))?;
        let mut ok = 0;
        for relay in &relays {
            if client
                .post(format!("{}/put", relay.url))
                .body(bytes.to_vec())
                .send()
                .is_ok_and(|response| response.status().is_success())
            {
                ok += 1;
            }
        }
        Ok(ok * 2 > relays.len())
    }

    /// Encodes one logical frame per known agent and pushes each.
    ///
    /// Used for broadcasts (module sets, rotations, upgrades) because frames are
    /// encrypted per recipient.
    pub fn push_per_agent(
        &self,
        make: impl Fn(&[u8; 32]) -> Result<Vec<u8>, msgfmt::Error>,
    ) -> Result<usize, Error> {
        let mut pushed = 0;
        for agent in self.database.agents()? {
            let Some(key) = self.database.agent_enc_key(&agent.route_tag)? else {
                continue;
            };
            let bytes = make(&key)?;
            if self.push(&bytes)? {
                pushed += 1;
            }
        }
        Ok(pushed)
    }

    /// Pulls and processes queued frames from every relay.
    pub fn pull_once(&mut self) -> Result<PullReport, Error> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|error| Error::Relay(error.to_string()))?;
        let mut report = PullReport::default();
        for relay in self.relays()? {
            let cursor = self.database.relay_cursor(&relay.id)?;
            let response = client
                .get(format!("{}/list?since={cursor}", relay.url))
                .send()
                .map_err(|error| Error::Relay(error.to_string()))?;
            if !response.status().is_success() {
                continue;
            }
            let text = response
                .text()
                .map_err(|error| Error::Relay(error.to_string()))?;
            let frames = match parse_list(&text) {
                Ok(frames) => frames,
                Err(_) => continue,
            };
            let mut highest = cursor;
            for (index, bytes) in frames {
                report.seen += 1;
                match self.process_frame(&bytes) {
                    Ok(Some(kind)) => {
                        if kind {
                            report.results += 1;
                        } else {
                            report.heartbeats += 1;
                        }
                    }
                    Ok(None) => report.skipped += 1,
                    Err(error) => {
                        report.skipped += 1;
                        let _ = self
                            .database
                            .record_event("pull_frame", &format!("{index}: {error}"));
                    }
                }
                highest = highest.max(index);
            }
            if highest > cursor {
                self.database.set_relay_cursor(&relay.id, highest)?;
            }
        }
        Ok(report)
    }

    /// Processes one frame. `Some(true)` is a result, `Some(false)` a heartbeat.
    fn process_frame(&mut self, bytes: &[u8]) -> Result<Option<bool>, Error> {
        let kind = *bytes.get(6).ok_or(msgfmt::Error::Truncated)?;
        match kind {
            1 => {
                let tag: [u8; 8] = bytes
                    .get(7..15)
                    .ok_or(msgfmt::Error::Truncated)?
                    .try_into()
                    .map_err(|_| msgfmt::Error::Truncated)?;
                let mut epoch = self.epochs.get(&tag).copied().unwrap_or(0);
                let heartbeat = decode_heartbeat(bytes, &msgfmt::BOOTSTRAP_ENC_KEY, &mut epoch)?;
                self.epochs.insert(tag, epoch);
                self.database.upsert_agent(
                    &heartbeat.agent_pub,
                    &tag,
                    &heartbeat.host,
                    &heartbeat.version,
                    &heartbeat.enc_key,
                )?;
                Ok(Some(false))
            }
            3 => {
                // Result epochs are task epochs, not a global clock: uniqueness
                // is enforced by the database on (task_epoch, agent_pub).
                let tag: [u8; 8] = bytes[7..15].try_into().unwrap_or([0_u8; 8]);
                // Old result frames carry a zero tag: try every stored key, then
                // the public bootstrap key.
                let mut keys = Vec::new();
                if tag != [0_u8; 8] {
                    if let Some(key) = self.database.agent_enc_key(&tag)? {
                        keys.push(key);
                    }
                } else {
                    for agent in self.database.agents()? {
                        if let Some(key) = self.database.agent_enc_key(&agent.route_tag)? {
                            keys.push(key);
                        }
                    }
                }
                keys.push(msgfmt::BOOTSTRAP_ENC_KEY);
                let mut decoded = None;
                for key in keys {
                    if let Ok(value) = decode_result_any(bytes, &key, &mut 0) {
                        decoded = Some((value, key));
                        break;
                    }
                }
                let Some(((result, public), key)) = decoded else {
                    return Err(msgfmt::Error::BadAead.into());
                };
                let tag = msgfmt::route_tag_from_key(&public);
                let _ = self.database.upsert_agent(&public, &tag, "", "", &key);
                let item = VerifiedResult {
                    agent_pub: public,
                    route_tag: tag,
                    result,
                };
                let Some(id) = self.database.ingest_verified(&item)? else {
                    return Ok(Some(true));
                };
                let stdout = self.database.result_stdout(id)?;
                for outcome in self
                    .database
                    .extract_findings(id, &db::findings_from_stdout(&stdout))?
                {
                    let _ = outcome;
                }
                Ok(Some(true))
            }
            _ => Ok(None),
        }
    }

    /// Pushes every due schedule and advances it.
    pub fn tick(&mut self, now: i64) -> Result<usize, Error> {
        let due = self.database.due_schedules(now)?;
        let mut pushed = 0;
        for schedule in due {
            let args: serde_json::Value =
                serde_json::from_str(&schedule.args).unwrap_or_else(|_| serde_json::json!({}));
            let cbor: CborValue = serde_cbor::value::to_value(args)
                .map_err(|error| Error::Relay(error.to_string()))?;
            let route_tag: [u8; 8] = schedule
                .route_tag
                .as_slice()
                .try_into()
                .map_err(|_| Error::Relay("bad route tag".into()))?;
            let task = Task {
                route_tag,
                epoch: unix_millis(),
                body: TaskBody::Mod {
                    mod_id: schedule.mod_id.clone(),
                    version: schedule.version.clone(),
                    args: cbor,
                },
            };
            let Some(key) = self.database.agent_enc_key(&route_tag)? else {
                self.database.record_event(
                    "schedule_skip",
                    &format!("no key for schedule {}", schedule.id),
                )?;
                continue;
            };
            let bytes = encode_task(&task, &key, &self.signing)?;
            match self.push(&bytes) {
                Ok(true) => {
                    pushed += 1;
                    let jitter =
                        (u64::from(route_tag[0]) % (schedule.jitter_s.max(0) as u64 + 1)) as i64;
                    self.database
                        .schedule_next(schedule.id, now + schedule.every_s + jitter)?;
                }
                Ok(false) | Err(_) => {
                    self.database
                        .record_event("schedule_push", &format!("schedule {}", schedule.id))?;
                }
            }
        }
        Ok(pushed)
    }

    /// Runs pull and schedule loops until `iterations` cycles, `stopping`, or forever.
    pub fn run(
        &mut self,
        iterations: Option<u64>,
        pull_every: Duration,
        stopping: &std::sync::atomic::AtomicBool,
    ) -> Result<(), Error> {
        use std::sync::atomic::Ordering;
        let mut cycles = 0_u64;
        loop {
            if stopping.load(Ordering::SeqCst) {
                return Ok(());
            }
            let _ = self.pull_once();
            let _ = self.tick(unix_now());
            cycles += 1;
            if iterations.is_some_and(|limit| cycles >= limit) {
                return Ok(());
            }
            // Wake early so a signal is observed within a second.
            let mut waited = Duration::ZERO;
            while waited < pull_every && !stopping.load(Ordering::SeqCst) {
                let step = Duration::from_millis(100).min(pull_every - waited);
                sleep(step);
                waited += step;
            }
        }
    }
}

/// Current Unix seconds.
pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0)
}

/// Current Unix milliseconds.
pub fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_millis() as u64)
        .unwrap_or(0)
}
