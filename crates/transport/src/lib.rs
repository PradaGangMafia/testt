#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Transport abstractions and the deterministic filesystem channel.

use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use async_trait::async_trait;
use blake3::Hasher;
use reqwest::Client;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{
    fs,
    io::AsyncWriteExt,
    net::UdpSocket,
    sync::Mutex,
    time::{sleep, Duration},
};

/// Errors produced by a transport channel.
#[derive(Debug, Error)]
pub enum Error {
    /// Filesystem or directory access failed.
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
    /// A queue entry did not have the required numeric filename.
    #[error("invalid queue entry: {0}")]
    InvalidEntry(String),
    /// HTTP transport failed or returned an unsuccessful status.
    #[error("relay error: {0}")]
    Relay(String),
}

/// A result returned by a channel operation.
pub type Result<T> = std::result::Result<T, Error>;

/// Message classes that must be replicated even when a primary relay is healthy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplicationClass {
    /// Ordinary task or heartbeat traffic.
    Ordinary,
    /// Control traffic that is always replicated.
    Control,
    /// Results are always replicated so answers survive relay loss.
    Result,
}

/// Per-peer replication budget: at most 20 frames/minute and 2 MiB/cycle.
#[derive(Debug, Clone)]
pub struct ReplicationBudget {
    minute_started: std::time::Instant,
    sent_in_minute: u32,
    cycle_bytes: usize,
}

impl Default for ReplicationBudget {
    fn default() -> Self {
        Self {
            minute_started: std::time::Instant::now(),
            sent_in_minute: 0,
            cycle_bytes: 0,
        }
    }
}

impl ReplicationBudget {
    /// Starts a new replication cycle.
    pub fn new_cycle(&mut self) {
        self.cycle_bytes = 0;
    }
    /// Returns whether a frame may be sent under the amplification limits.
    pub fn admit(
        &mut self,
        bytes: usize,
        class: ReplicationClass,
        tier_zero_healthy: bool,
    ) -> bool {
        if self.minute_started.elapsed() >= std::time::Duration::from_secs(60) {
            self.minute_started = std::time::Instant::now();
            self.sent_in_minute = 0;
        }
        if tier_zero_healthy && matches!(class, ReplicationClass::Ordinary) {
            return false;
        }
        let peer_cap = if bytes > 4096 { 1 } else { 3 };
        if self.sent_in_minute >= 20 || self.cycle_bytes.saturating_add(bytes) > 2 * 1024 * 1024 {
            return false;
        }
        self.sent_in_minute += peer_cap.min(1);
        self.cycle_bytes += bytes;
        true
    }
}

/// Recovery-mode decision state after all tier-zero channels fail.
#[derive(Debug, Clone, Copy, Default)]
pub struct RecoveryState {
    consecutive_all_down: u8,
    elapsed_s: u32,
}

impl RecoveryState {
    /// Records a cycle and reports whether tier-2 recovery should be polled.
    pub fn record_all_down(&mut self, cycle_seconds: u32) -> bool {
        self.consecutive_all_down = self.consecutive_all_down.saturating_add(1);
        self.elapsed_s = self.elapsed_s.saturating_add(cycle_seconds);
        self.consecutive_all_down >= 3 && self.elapsed_s <= 30 * 60
    }
    /// Ends recovery after the first successful tier-zero cycle.
    pub fn tier_zero_succeeded(&mut self) {
        *self = Self::default();
    }
    /// Returns whether the 30-minute recovery window has expired.
    pub fn expired(&self) -> bool {
        self.elapsed_s > 30 * 60
    }
}

/// Configuration for the opt-in UDP hole-punch probe.
#[derive(Debug, Clone)]
pub struct PunchConfig {
    /// Local bind address.
    pub bind: std::net::SocketAddr,
    /// Candidate peers.
    pub candidates: Vec<std::net::SocketAddr>,
}

/// Result of a successful punch probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PunchResult {
    /// Candidate that replied first.
    pub peer: std::net::SocketAddr,
}

/// Sends authenticated RFC-5389-shaped probes for up to eight seconds.
pub async fn punch(config: PunchConfig) -> Result<PunchResult> {
    let socket = UdpSocket::bind(config.bind).await?;
    let txid = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mut request = [0_u8; 20];
    request[0..2].copy_from_slice(&0x0001_u16.to_be_bytes());
    request[2..4].copy_from_slice(&0u16.to_be_bytes());
    request[4..8].copy_from_slice(&0x2112_A442_u32.to_be_bytes());
    request[8..20].copy_from_slice(&txid.to_be_bytes()[4..16]);
    for candidate in &config.candidates {
        let _ = socket.send_to(&request, candidate).await;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    let mut buf = [0_u8; 512];
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(Error::Relay("hole punch timed out".into()));
        }
        let received = tokio::time::timeout(remaining, socket.recv_from(&mut buf))
            .await
            .map_err(|_| Error::Relay("hole punch timed out".into()))??;
        if received.0 >= 20 && buf[8..20] == request[8..20] && buf[0..2] == 0x0101_u16.to_be_bytes()
        {
            return Ok(PunchResult { peer: received.1 });
        }
    }
}

/// A configured relay specification in `tier:priority:kind:arg` form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySpec {
    /// Polling tier, lower is preferred.
    pub tier: u8,
    /// Priority within a tier, lower is preferred.
    pub priority: u32,
    /// Channel kind.
    pub kind: String,
    /// Kind-specific argument.
    pub arg: String,
}

/// Parses a relay specification while preserving colons in its argument.
pub fn parse_relay_spec(value: &str) -> Result<RelaySpec> {
    let mut fields = value.splitn(4, ':');
    let tier = fields
        .next()
        .ok_or_else(|| Error::Relay("missing tier".into()))?
        .parse()
        .map_err(|_| Error::Relay("invalid tier".into()))?;
    let priority = fields
        .next()
        .ok_or_else(|| Error::Relay("missing priority".into()))?
        .parse()
        .map_err(|_| Error::Relay("invalid priority".into()))?;
    let kind = fields
        .next()
        .ok_or_else(|| Error::Relay("missing kind".into()))?
        .to_owned();
    let arg = fields
        .next()
        .ok_or_else(|| Error::Relay("missing argument".into()))?
        .to_owned();
    if kind.is_empty() || arg.is_empty() {
        return Err(Error::Relay("empty relay field".into()));
    }
    Ok(RelaySpec {
        tier,
        priority,
        kind,
        arg,
    })
}

/// Health state used by tiered polling and failover decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HealthState {
    /// Consecutive failed probes.
    pub strikes: u8,
    /// Unix time until which the relay is skipped.
    pub skip_until: u64,
}

impl HealthState {
    /// Records a success and clears the strike counter.
    pub fn success(&mut self) {
        self.strikes = 0;
        self.skip_until = 0;
    }
    /// Records a failure; three strikes quarantine the relay for ten minutes.
    pub fn failure(&mut self, now: u64) {
        self.strikes = self.strikes.saturating_add(1);
        if self.strikes >= 3 {
            self.skip_until = now.saturating_add(600);
        }
    }
    /// Returns whether this relay may be attempted now.
    pub fn eligible(&self, now: u64) -> bool {
        now >= self.skip_until
    }
}

/// An ordered byte channel with no network-specific assumptions.
#[async_trait]
pub trait Channel: Send + Sync {
    /// Stores one opaque frame and claims its queue index.
    async fn put(&self, bytes: &[u8]) -> Result<()>;

    /// Lists entries whose claimed index is greater than `since`, ascending.
    async fn list_since(&self, since: u64) -> Result<Vec<(u64, Vec<u8>)>>;

    /// Returns the stable channel kind name.
    fn name() -> &'static str
    where
        Self: Sized;

    /// Returns the stable eight-byte identity used for per-channel cursors.
    fn id(&self) -> [u8; 8];

    /// Polling tier, defaulting to the primary tier.
    fn tier(&self) -> u8 {
        0
    }

    /// Priority within the polling tier.
    fn priority(&self) -> u32 {
        0
    }

    /// Host identity used for relay diversity warnings.
    fn host(&self) -> Option<String> {
        None
    }
}

/// Derives a stable channel identity from its kind and argument.
pub fn channel_id(kind: &str, argument: &str) -> [u8; 8] {
    let mut hasher = Hasher::new();
    hasher.update(kind.as_bytes());
    hasher.update(&[0]);
    hasher.update(argument.as_bytes());
    let mut id = [0_u8; 8];
    id.copy_from_slice(&hasher.finalize().as_bytes()[..8]);
    id
}

/// A local channel that stores frames as twelve-digit `.bin` files.
#[derive(Debug)]
pub struct MockFsChannel {
    root: PathBuf,
    next: AtomicU64,
}

impl MockFsChannel {
    /// Creates a channel rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            next: AtomicU64::new(1),
        }
    }

    /// Returns the channel's queue directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    async fn claim_path(&self) -> Result<(u64, fs::File)> {
        fs::create_dir_all(&self.root).await?;
        loop {
            let index = self.next.fetch_add(1, Ordering::Relaxed);
            let path = self.root.join(format!("{index:012}.bin"));
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .await
            {
                Ok(file) => return Ok((index, file)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }
}

#[async_trait]
impl Channel for MockFsChannel {
    async fn put(&self, bytes: &[u8]) -> Result<()> {
        let (_, mut file) = self.claim_path().await?;
        file.write_all(bytes).await?;
        file.sync_all().await?;
        Ok(())
    }

    async fn list_since(&self, since: u64) -> Result<Vec<(u64, Vec<u8>)>> {
        let mut entries = match fs::read_dir(&self.root).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut found = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(stem) = name.strip_suffix(".bin") else {
                continue;
            };
            let index = stem
                .parse::<u64>()
                .map_err(|_| Error::InvalidEntry(name.clone()))?;
            if index > since {
                found.push((index, fs::read(entry.path()).await?));
            }
        }
        found.sort_by_key(|(index, _)| *index);
        Ok(found)
    }

    fn name() -> &'static str {
        "mock-fs"
    }

    fn id(&self) -> [u8; 8] {
        channel_id(Self::name(), &self.root.to_string_lossy())
    }
}

/// An HTTPS relay channel using the Agent-Fleet relay HTTP protocol.
#[derive(Debug, Clone)]
pub struct RelayChannel {
    base_url: String,
    client: Client,
    tier: u8,
    priority: u32,
}

/// A tier-2 peer channel speaking the relay queue HTTP protocol.
#[derive(Debug, Clone)]
pub struct P2pChannel {
    base_url: String,
    client: Client,
    peer_key: [u8; 32],
    priority: u32,
}

impl P2pChannel {
    /// Creates a peer channel with a ten-second request timeout.
    pub fn new(base_url: impl Into<String>, peer_key: [u8; 32]) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|error| Error::Relay(error.to_string()))?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            client,
            peer_key,
            priority: 0,
        })
    }

    /// Sets the priority within tier 2.
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    async fn put_once(&self, bytes: &[u8]) -> Result<()> {
        let response = self
            .client
            .post(format!("{}/put", self.base_url))
            .body(bytes.to_vec())
            .send()
            .await
            .map_err(|error| Error::Relay(error.to_string()))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(Error::Relay(format!("HTTP {}", response.status())))
        }
    }
}

#[async_trait]
impl Channel for P2pChannel {
    async fn put(&self, bytes: &[u8]) -> Result<()> {
        match self.put_once(bytes).await {
            Ok(()) => Ok(()),
            Err(_) => self.put_once(bytes).await,
        }
    }

    async fn list_since(&self, since: u64) -> Result<Vec<(u64, Vec<u8>)>> {
        let response = self
            .client
            .get(format!("{}/list?since={since}", self.base_url))
            .send()
            .await
            .map_err(|error| Error::Relay(error.to_string()))?;
        if !response.status().is_success() {
            return Err(Error::Relay(format!("HTTP {}", response.status())));
        }
        let text = response
            .text()
            .await
            .map_err(|error| Error::Relay(error.to_string()))?;
        let mut values = parse_json_pairs(&text)?;
        values.sort_by_key(|(index, _)| *index);
        Ok(values)
    }

    fn name() -> &'static str {
        "p2p"
    }
    fn id(&self) -> [u8; 8] {
        let mut hasher = Hasher::new();
        hasher.update(b"p2p\0");
        hasher.update(&self.peer_key);
        hasher.finalize().as_bytes()[..8]
            .try_into()
            .expect("fixed digest prefix")
    }
    fn tier(&self) -> u8 {
        2
    }
    fn priority(&self) -> u32 {
        self.priority
    }
    fn host(&self) -> Option<String> {
        self.base_url.split('/').nth(2).map(str::to_owned)
    }
}

/// A priority-ordered channel set that promotes the first successful fallback.
pub struct FailoverChannel {
    channels: Vec<Arc<dyn Channel>>,
    primary: Mutex<usize>,
}

impl FailoverChannel {
    /// Creates a failover set in the supplied priority order.
    pub fn new(channels: Vec<Arc<dyn Channel>>) -> Result<Self> {
        if channels.is_empty() {
            return Err(Error::Relay("at least one channel is required".into()));
        }
        Ok(Self {
            channels,
            primary: Mutex::new(0),
        })
    }
}

#[async_trait]
impl Channel for FailoverChannel {
    async fn put(&self, bytes: &[u8]) -> Result<()> {
        let start = *self.primary.lock().await;
        let mut last = Error::Relay("all channels failed".into());
        for offset in 0..self.channels.len() {
            let index = (start + offset) % self.channels.len();
            match self.channels[index].put(bytes).await {
                Ok(()) => {
                    *self.primary.lock().await = index;
                    return Ok(());
                }
                Err(error) => last = error,
            }
        }
        Err(last)
    }

    async fn list_since(&self, since: u64) -> Result<Vec<(u64, Vec<u8>)>> {
        let start = *self.primary.lock().await;
        let mut last = Error::Relay("all channels failed".into());
        for offset in 0..self.channels.len() {
            let index = (start + offset) % self.channels.len();
            match self.channels[index].list_since(since).await {
                Ok(entries) => {
                    *self.primary.lock().await = index;
                    return Ok(entries);
                }
                Err(error) => last = error,
            }
        }
        Err(last)
    }

    fn name() -> &'static str {
        "failover"
    }

    fn id(&self) -> [u8; 8] {
        channel_id(Self::name(), &self.channels.len().to_string())
    }
}

/// Computes a SHA-256 digest for a local artifact.
pub async fn sha256_file(path: impl AsRef<Path>) -> Result<[u8; 32]> {
    let digest = Sha256::digest(fs::read(path).await?);
    Ok(digest.into())
}

impl RelayChannel {
    /// Creates a relay channel with a 15-second request timeout.
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|error| Error::Relay(error.to_string()))?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            client,
            tier: 0,
            priority: 0,
        })
    }

    /// Creates a relay from a tiered specification.
    pub fn from_spec(spec: &RelaySpec) -> Result<Self> {
        let mut channel = Self::new(&spec.arg)?;
        channel.tier = spec.tier;
        channel.priority = spec.priority;
        Ok(channel)
    }

    /// Probes the relay health endpoint.
    pub async fn health(&self) -> Result<()> {
        let response = self
            .client
            .get(format!("{}/health", self.base_url))
            .send()
            .await
            .map_err(|error| Error::Relay(error.to_string()))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(Error::Relay(format!("HTTP {}", response.status())))
        }
    }

    #[cfg(feature = "onion")]
    fn with_client(base_url: impl Into<String>, client: Client) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            client,
            tier: 0,
            priority: 0,
        }
    }

    async fn request_with_retry(&self, bytes: &[u8]) -> Result<()> {
        let mut last = String::from("relay request failed");
        for attempt in 0..3_u64 {
            match self
                .client
                .post(format!("{}/put", self.base_url))
                .body(bytes.to_vec())
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => return Ok(()),
                Ok(response) => last = format!("HTTP {}", response.status()),
                Err(error) => last = error.to_string(),
            }
            if attempt < 2 {
                sleep(Duration::from_millis(100_u64 << attempt)).await;
            }
        }
        Err(Error::Relay(last))
    }
}

#[async_trait]
impl Channel for RelayChannel {
    async fn put(&self, bytes: &[u8]) -> Result<()> {
        self.request_with_retry(bytes).await
    }

    async fn list_since(&self, since: u64) -> Result<Vec<(u64, Vec<u8>)>> {
        let response = self
            .client
            .get(format!("{}/list?since={since}", self.base_url))
            .send()
            .await
            .map_err(|error| Error::Relay(error.to_string()))?;
        if !response.status().is_success() {
            return Err(Error::Relay(format!("HTTP {}", response.status())));
        }
        let text = response
            .text()
            .await
            .map_err(|error| Error::Relay(error.to_string()))?;
        let mut values = parse_json_pairs(&text)?;
        values.sort_by_key(|(index, _)| *index);
        Ok(values)
    }

    fn name() -> &'static str {
        "relay"
    }

    fn id(&self) -> [u8; 8] {
        channel_id(Self::name(), &self.base_url)
    }

    fn tier(&self) -> u8 {
        self.tier
    }
    fn priority(&self) -> u32 {
        self.priority
    }
    fn host(&self) -> Option<String> {
        self.base_url.split("/").nth(2).map(str::to_owned)
    }
}

/// Parses a relay `/list` response (`[[index,"hex"],...]`) into frames.
pub fn parse_list(input: &str) -> Result<Vec<(u64, Vec<u8>)>> {
    parse_json_pairs(input)
}

fn parse_json_pairs(input: &str) -> Result<Vec<(u64, Vec<u8>)>> {
    let trimmed = input.trim();
    if trimmed == "[]" {
        return Ok(Vec::new());
    }
    let body = trimmed
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or_else(|| Error::Relay("invalid list JSON".into()))?;
    let mut result = Vec::new();
    for item in body.split("],") {
        let item = item.trim().trim_start_matches('[').trim_end_matches(']');
        let mut fields = item.splitn(2, ',');
        let index = fields
            .next()
            .ok_or_else(|| Error::Relay("missing index".into()))?
            .trim()
            .parse()
            .map_err(|_| Error::Relay("invalid index".into()))?;
        let encoded = fields
            .next()
            .ok_or_else(|| Error::Relay("missing data".into()))?
            .trim()
            .trim_matches('"');
        result.push((index, decode_hex(encoded)?));
    }
    Ok(result)
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    if value.len() % 2 != 0 {
        return Err(Error::Relay("invalid hex payload".into()));
    }
    (0..value.len() / 2)
        .map(|index| {
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                .map_err(|_| Error::Relay("invalid hex payload".into()))
        })
        .collect()
}

/// A feature-gated relay channel routed through a SOCKS5 proxy.
#[cfg(feature = "onion")]
#[derive(Debug, Clone)]
pub struct OnionChannel(RelayChannel);

#[cfg(feature = "onion")]
impl OnionChannel {
    /// Creates an onion channel using `proxy`, such as `socks5h://127.0.0.1:9050`.
    pub fn new(base_url: impl Into<String>, proxy: impl AsRef<str>) -> Result<Self> {
        let proxy =
            reqwest::Proxy::all(proxy.as_ref()).map_err(|error| Error::Relay(error.to_string()))?;
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .proxy(proxy)
            .build()
            .map_err(|error| Error::Relay(error.to_string()))?;
        Ok(Self(RelayChannel::with_client(base_url, client)))
    }
}

#[cfg(feature = "onion")]
#[async_trait]
impl Channel for OnionChannel {
    async fn put(&self, bytes: &[u8]) -> Result<()> {
        self.0.put(bytes).await
    }
    async fn list_since(&self, since: u64) -> Result<Vec<(u64, Vec<u8>)>> {
        self.0.list_since(since).await
    }
    fn name() -> &'static str {
        "onion"
    }

    fn id(&self) -> [u8; 8] {
        self.0.id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("agent-fleet-{label}-{}", std::process::id()))
    }

    #[tokio::test]
    async fn put_then_list_round_trips_in_index_order() {
        let root = temp_root("round-trip");
        let _ = fs::remove_dir_all(&root).await;
        let channel = MockFsChannel::new(&root);
        channel.put(b"one").await.expect("put should succeed");
        channel.put(b"two").await.expect("put should succeed");
        let entries = channel.list_since(0).await.expect("list should succeed");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].1, b"one");
        assert_eq!(entries[1].1, b"two");
        fs::remove_dir_all(root)
            .await
            .expect("cleanup should succeed");
    }

    #[tokio::test]
    async fn empty_directory_lists_empty() {
        let root = temp_root("empty");
        let _ = fs::remove_dir_all(&root).await;
        let entries = MockFsChannel::new(&root)
            .list_since(0)
            .await
            .expect("list should succeed");
        assert!(entries.is_empty());
    }
}
