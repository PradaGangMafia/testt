#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Signed and encrypted Agent-Fleet task frames.

use std::collections::BTreeMap;

use blake3::Hasher;
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde_cbor::Value;
use thiserror::Error;

const MAGIC: [u8; 4] = [0x43, 0x32, 0x00, 0x01];
const VERSION: u16 = 1;
const HEADER_LEN: usize = 49;
const SIGNATURE_LEN: usize = 64;
const AEAD_TAG_LEN: usize = 16;
const MAX_PAYLOAD: usize = 3967;
const CLASSES: [usize; 4] = [256, 512, 1024, 4096];

/// A message type carried by a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType {
    /// A liveness message.
    Heartbeat = 1,
    /// A task request.
    Task = 2,
    /// A task result.
    Result = 3,
    /// A key rotation request.
    Rotate = 4,
    /// A binary upgrade request.
    Upgrade = 5,
    /// A signed relay-set update.
    RelaySet = 6,
    /// A signed module-set update.
    ModSet = 7,
    /// A signed peer record.
    PeerRecord = 8,
}

/// One relay advertised by a relay-set update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEntry {
    /// Stable channel identity.
    pub id: [u8; 8],
    /// Channel implementation kind.
    pub kind: String,
    /// Polling tier.
    pub tier: u8,
    /// Channel address or argument.
    pub addr: String,
}

/// An authenticated, monotonically generated relay-set update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySet {
    /// Generation number.
    pub gen: u64,
    /// Entries to add or replace.
    pub add: Vec<RelayEntry>,
    /// Identities to tombstone.
    pub remove: Vec<[u8; 8]>,
}

/// A module advertised by a module-set update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModEntry {
    /// Stable module identifier.
    pub id: String,
    /// Semantic module version.
    pub version: String,
    /// Required host ABI version.
    pub abi: u32,
    /// BLAKE3 digest of the module bytes.
    pub blake3: [u8; 32],
    /// Module byte length.
    pub size: u64,
    /// Download URL.
    pub url: String,
    /// Requested capabilities.
    pub capabilities: Vec<String>,
    /// Whether the module should execute.
    pub enabled: bool,
}

/// An authenticated module-set update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModSet {
    /// Monotonic generation number.
    pub gen: u64,
    /// Modules to add or replace.
    pub add: Vec<ModEntry>,
    /// Module identifiers to remove.
    pub remove: Vec<String>,
}

/// A module invocation task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModTask {
    /// Module identifier.
    pub mod_id: String,
    /// Requested module version.
    pub version: String,
    /// JSON-compatible CBOR arguments.
    pub args: Value,
}

/// A signed peer liveness and reachability record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecord {
    /// Record epoch, monotonically increasing for the peer.
    pub epoch: u64,
    /// Ed25519 public key of the peer.
    pub agent_pub: [u8; 32],
    /// Optional address on which the peer accepts P2P traffic.
    pub listen: Option<String>,
    /// Optional address observed by a relay.
    pub observed: Option<String>,
    /// Relay specifications advertised by the peer.
    pub relays: Vec<String>,
    /// Whether the peer is operating as a supernode.
    pub supernode: bool,
    /// Process uptime in seconds.
    pub uptime_s: u64,
    /// Implementation-defined load value.
    pub load: u16,
    /// Peer software version.
    pub version: String,
}

/// A decoded signed peer record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPeerRecord {
    /// The decoded record.
    pub peer: PeerRecord,
    /// The frame message type.
    pub msg_type: MsgType,
}

/// A task sent to an agent route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Task {
    /// Destination route tag.
    pub route_tag: [u8; 8],
    /// Monotonic route epoch.
    pub epoch: u64,
    /// Task body.
    pub body: TaskBody,
}

/// The supported task bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskBody {
    /// A no-op liveness probe.
    Ping,
    /// A process invocation.
    Shell {
        /// Program arguments.
        argv: Vec<String>,
        /// Maximum execution time in seconds.
        timeout_s: u16,
        /// Whether the command is interpreted by a shell.
        shell: bool,
    },
    /// A download request.
    Fetch {
        /// Source URL.
        url: String,
        /// Destination path.
        dest: String,
    },
    /// An installed module invocation.
    Mod {
        /// Module identifier.
        mod_id: String,
        /// Requested module version.
        version: String,
        /// JSON-compatible CBOR arguments.
        args: Value,
    },
}

/// A decoded frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedTask {
    /// The decoded task envelope.
    pub task: Task,
    /// The decoded message type.
    pub msg_type: MsgType,
}

/// A decoded RelaySet frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedRelaySet {
    /// The decoded update.
    pub relay_set: RelaySet,
    /// The decoded message type.
    pub msg_type: MsgType,
}

/// A decoded ModSet frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedModSet {
    /// The decoded update.
    pub mod_set: ModSet,
    /// The decoded message type.
    pub msg_type: MsgType,
}

/// A task result authenticated by the producing agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultMessage {
    /// Epoch of the task being answered.
    pub task_epoch: u64,
    /// Agent public key that produced this result.
    pub agent_pub: [u8; 32],
    /// Whether the task completed successfully.
    pub ok: bool,
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
    /// Process or handler exit code.
    pub code: i32,
}
/// A decoded signed result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedResult {
    /// The result body.
    pub result: ResultMessage,
    /// The frame message type.
    pub msg_type: MsgType,
}

/// Errors returned while encoding or decoding frames.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// The input does not contain a complete frame.
    #[error("truncated frame")]
    Truncated,
    /// The frame length or payload length is invalid.
    #[error("bad frame length")]
    BadLength,
    /// The frame magic is invalid.
    #[error("bad magic")]
    BadMagic,
    /// The frame version is unsupported.
    #[error("bad version")]
    BadVersion,
    /// The signature is invalid.
    #[error("bad signature")]
    BadSignature,
    /// The header route tag does not match the signed public key.
    #[error("route tag does not match the signing key")]
    BadRoute,
    /// The epoch is not newer than the accepted epoch.
    #[error("stale epoch")]
    StaleEpoch,
    /// Padding contains a non-zero byte.
    #[error("bad padding")]
    BadPadding,
    /// AEAD authentication or decryption failed.
    #[error("bad aead")]
    BadAead,
    /// CBOR is malformed or has an invalid task shape.
    #[error("bad cbor")]
    BadCbor,
    /// The message type is not supported.
    #[error("unknown message type")]
    UnknownMsgType,
    /// CBOR serialization failed.
    #[error("serialization failed")]
    Serialization,
}

/// Returns whether a module identifier is valid under the shared publish rule.
///
/// Identifiers are 1 to 64 ASCII characters drawn from letters, digits, `.`,
/// `-`, and `_`. The agent daemon and `adminctl` both call this function so a
/// module cannot be accepted by one side and refused by the other.
pub fn valid_mod_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// Returns whether a module version string is non-empty and bounded.
pub fn valid_mod_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 64
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+'))
}

/// Derives the eight-byte route tag pinned at enrolment from an agent key.
///
/// The input is hashed as an opaque key byte string. The resulting tag must be
/// stored at enrolment and reused unchanged for the lifetime of that identity.
pub fn route_tag_from_key(key: &[u8]) -> [u8; 8] {
    let mut hasher = Hasher::new();
    hasher.update(key);
    let mut tag = [0_u8; 8];
    tag.copy_from_slice(&hasher.finalize().as_bytes()[..8]);
    tag
}

/// Encodes a task using XChaCha20-Poly1305 and Ed25519.
pub fn encode_task(
    task: &Task,
    enc_key: &[u8; 32],
    signing_key: &SigningKey,
) -> Result<Vec<u8>, Error> {
    let plaintext = encode_body(&task.body)?;
    let mut nonce = [0_u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let payload_len = plaintext
        .len()
        .checked_add(AEAD_TAG_LEN)
        .ok_or(Error::BadLength)?;
    if payload_len > MAX_PAYLOAD {
        return Err(Error::BadLength);
    }
    let frame_size = CLASSES
        .iter()
        .copied()
        .find(|size| *size >= HEADER_LEN + payload_len + SIGNATURE_LEN)
        .ok_or(Error::BadLength)?;
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(&MAGIC);
    header.extend_from_slice(&VERSION.to_le_bytes());
    header.push(MsgType::Task as u8);
    header.extend_from_slice(&task.route_tag);
    header.extend_from_slice(&task.epoch.to_le_bytes());
    header.extend_from_slice(&nonce);
    header.extend_from_slice(&(payload_len as u16).to_le_bytes());
    let cipher = XChaCha20Poly1305::new(enc_key.into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &header,
            },
        )
        .map_err(|_| Error::BadAead)?;
    let mut signed = header;
    signed.extend_from_slice(&ciphertext);
    signed.resize(frame_size - SIGNATURE_LEN, 0);
    let signature = signing_key.sign(&signed);
    signed.extend_from_slice(&signature.to_bytes());
    Ok(signed)
}

/// Encodes a RelaySet using the existing signed and encrypted frame format.
pub fn encode_relay_set(
    relay_set: &RelaySet,
    enc_key: &[u8; 32],
    signing_key: &SigningKey,
) -> Result<Vec<u8>, Error> {
    let mut map = BTreeMap::new();
    let add = relay_set
        .add
        .iter()
        .map(|entry| {
            let mut item = BTreeMap::new();
            item.insert(Value::Text("addr".into()), Value::Text(entry.addr.clone()));
            item.insert(Value::Text("id".into()), Value::Bytes(entry.id.to_vec()));
            item.insert(Value::Text("kind".into()), Value::Text(entry.kind.clone()));
            item.insert(
                Value::Text("tier".into()),
                Value::Integer(i128::from(entry.tier)),
            );
            Value::Map(item)
        })
        .collect();
    map.insert(Value::Text("add".into()), Value::Array(add));
    map.insert(
        Value::Text("gen".into()),
        Value::Integer(i128::from(relay_set.gen)),
    );
    map.insert(
        Value::Text("remove".into()),
        Value::Array(
            relay_set
                .remove
                .iter()
                .map(|id| Value::Bytes(id.to_vec()))
                .collect(),
        ),
    );
    encode_frame(
        MsgType::RelaySet,
        [0; 8],
        relay_set.gen,
        &Value::Map(map),
        enc_key,
        signing_key,
    )
}

/// Decrypts and decodes a RelaySet frame, checking its signature first.
pub fn decode_relay_set(
    bytes: &[u8],
    verifying_key: &VerifyingKey,
    enc_key: &[u8; 32],
    last_epoch: &mut u64,
) -> Result<DecodedRelaySet, Error> {
    verify(bytes, verifying_key)?;
    let epoch = frame_epoch(bytes)?;
    if epoch <= *last_epoch {
        return Err(Error::StaleEpoch);
    }
    let (header, signed, _) = split_frame(bytes)?;
    let payload_len = u16::from_le_bytes([header[47], header[48]]) as usize;
    let nonce: [u8; 24] = header[23..47].try_into().map_err(|_| Error::BadLength)?;
    let plaintext = XChaCha20Poly1305::new(enc_key.into())
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &signed[HEADER_LEN..HEADER_LEN + payload_len],
                aad: header,
            },
        )
        .map_err(|_| Error::BadAead)?;
    if header[6] != MsgType::RelaySet as u8 {
        return Err(Error::UnknownMsgType);
    }
    let relay_set = decode_relay_set_body(&plaintext)?;
    *last_epoch = epoch;
    Ok(DecodedRelaySet {
        relay_set,
        msg_type: MsgType::RelaySet,
    })
}

/// Encodes a signed module-set update using the existing frame format.
pub fn encode_mod_set(
    mod_set: &ModSet,
    enc_key: &[u8; 32],
    signing_key: &SigningKey,
) -> Result<Vec<u8>, Error> {
    let add = mod_set
        .add
        .iter()
        .map(|entry| {
            let mut item = BTreeMap::new();
            item.insert(
                Value::Text("abi".into()),
                Value::Integer(i128::from(entry.abi)),
            );
            item.insert(
                Value::Text("blake3".into()),
                Value::Bytes(entry.blake3.to_vec()),
            );
            item.insert(
                Value::Text("capabilities".into()),
                Value::Array(
                    entry
                        .capabilities
                        .iter()
                        .cloned()
                        .map(Value::Text)
                        .collect(),
                ),
            );
            item.insert(Value::Text("enabled".into()), Value::Bool(entry.enabled));
            item.insert(Value::Text("id".into()), Value::Text(entry.id.clone()));
            item.insert(
                Value::Text("size".into()),
                Value::Integer(i128::from(entry.size)),
            );
            item.insert(Value::Text("url".into()), Value::Text(entry.url.clone()));
            item.insert(
                Value::Text("version".into()),
                Value::Text(entry.version.clone()),
            );
            Value::Map(item)
        })
        .collect();
    let mut map = BTreeMap::new();
    map.insert(Value::Text("add".into()), Value::Array(add));
    map.insert(
        Value::Text("gen".into()),
        Value::Integer(i128::from(mod_set.gen)),
    );
    map.insert(
        Value::Text("remove".into()),
        Value::Array(mod_set.remove.iter().cloned().map(Value::Text).collect()),
    );
    encode_frame(
        MsgType::ModSet,
        [0; 8],
        mod_set.gen,
        &Value::Map(map),
        enc_key,
        signing_key,
    )
}

/// Verifies, decrypts, and decodes a module-set update.
pub fn decode_mod_set(
    bytes: &[u8],
    verifying_key: &VerifyingKey,
    enc_key: &[u8; 32],
    last_epoch: &mut u64,
) -> Result<DecodedModSet, Error> {
    verify(bytes, verifying_key)?;
    let epoch = frame_epoch(bytes)?;
    if epoch <= *last_epoch {
        return Err(Error::StaleEpoch);
    }
    let (header, signed, _) = split_frame(bytes)?;
    if header[6] != MsgType::ModSet as u8 {
        return Err(Error::UnknownMsgType);
    }
    let payload_len = u16::from_le_bytes([header[47], header[48]]) as usize;
    if signed[HEADER_LEN + payload_len..]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(Error::BadPadding);
    }
    let nonce: [u8; 24] = header[23..47].try_into().map_err(|_| Error::BadLength)?;
    let plaintext = XChaCha20Poly1305::new(enc_key.into())
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &signed[HEADER_LEN..HEADER_LEN + payload_len],
                aad: header,
            },
        )
        .map_err(|_| Error::BadAead)?;
    let mod_set = decode_mod_set_body(&plaintext)?;
    *last_epoch = epoch;
    Ok(DecodedModSet {
        mod_set,
        msg_type: MsgType::ModSet,
    })
}

/// Encodes a signed peer record using the frozen frame layout.
pub fn encode_peer_record(
    peer: &PeerRecord,
    enc_key: &[u8; 32],
    signing_key: &SigningKey,
) -> Result<Vec<u8>, Error> {
    let mut map = BTreeMap::new();
    map.insert(
        Value::Text("agent_pub".into()),
        Value::Bytes(peer.agent_pub.to_vec()),
    );
    map.insert(
        Value::Text("epoch".into()),
        Value::Integer(i128::from(peer.epoch)),
    );
    map.insert(
        Value::Text("load".into()),
        Value::Integer(i128::from(peer.load)),
    );
    map.insert(
        Value::Text("listen".into()),
        peer.listen.clone().map_or(Value::Null, Value::Text),
    );
    map.insert(
        Value::Text("observed".into()),
        peer.observed.clone().map_or(Value::Null, Value::Text),
    );
    map.insert(
        Value::Text("relays".into()),
        Value::Array(peer.relays.iter().cloned().map(Value::Text).collect()),
    );
    map.insert(Value::Text("supernode".into()), Value::Bool(peer.supernode));
    map.insert(
        Value::Text("uptime_s".into()),
        Value::Integer(i128::from(peer.uptime_s)),
    );
    map.insert(
        Value::Text("version".into()),
        Value::Text(peer.version.clone()),
    );
    encode_frame(
        MsgType::PeerRecord,
        [0; 8],
        peer.epoch,
        &Value::Map(map),
        enc_key,
        signing_key,
    )
}

/// Verifies, decrypts, checks freshness, and decodes a peer record.
pub fn decode_peer_record(
    bytes: &[u8],
    verifying_key: &VerifyingKey,
    enc_key: &[u8; 32],
    last_epoch: &mut u64,
) -> Result<DecodedPeerRecord, Error> {
    verify(bytes, verifying_key)?;
    let epoch = frame_epoch(bytes)?;
    if epoch <= *last_epoch {
        return Err(Error::StaleEpoch);
    }
    let (header, signed, _) = split_frame(bytes)?;
    if header[6] != MsgType::PeerRecord as u8 {
        return Err(Error::UnknownMsgType);
    }
    let payload_len = u16::from_le_bytes([header[47], header[48]]) as usize;
    if signed[HEADER_LEN + payload_len..]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(Error::BadPadding);
    }
    let nonce: [u8; 24] = header[23..47].try_into().map_err(|_| Error::BadLength)?;
    let plaintext = XChaCha20Poly1305::new(enc_key.into())
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &signed[HEADER_LEN..HEADER_LEN + payload_len],
                aad: header,
            },
        )
        .map_err(|_| Error::BadAead)?;
    let peer = decode_peer_record_body(&plaintext, epoch)?;
    *last_epoch = epoch;
    Ok(DecodedPeerRecord {
        peer,
        msg_type: MsgType::PeerRecord,
    })
}

fn decode_peer_record_body(bytes: &[u8], epoch: u64) -> Result<PeerRecord, Error> {
    let Value::Map(map) = serde_cbor::from_slice(bytes).map_err(|_| Error::BadCbor)? else {
        return Err(Error::BadCbor);
    };
    let integer = |key: &str| match map.get(&Value::Text(key.into())) {
        Some(Value::Integer(value)) => Ok(*value),
        _ => Err(Error::BadCbor),
    };
    let bytes_value = |key: &str| match map.get(&Value::Text(key.into())) {
        Some(Value::Bytes(value)) => value.as_slice().try_into().map_err(|_| Error::BadCbor),
        _ => Err(Error::BadCbor),
    };
    let optional_text = |key: &str| match map.get(&Value::Text(key.into())) {
        Some(Value::Text(value)) => Ok(Some(value.clone())),
        Some(Value::Null) => Ok(None),
        _ => Err(Error::BadCbor),
    };
    let agent_pub = bytes_value("agent_pub")?;
    if u64::try_from(integer("epoch")?).map_err(|_| Error::BadCbor)? != epoch {
        return Err(Error::BadCbor);
    }
    let relays = match map.get(&Value::Text("relays".into())) {
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| match value {
                Value::Text(value) => Ok(value.clone()),
                _ => Err(Error::BadCbor),
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(Error::BadCbor),
    };
    let supernode = match map.get(&Value::Text("supernode".into())) {
        Some(Value::Bool(value)) => *value,
        _ => return Err(Error::BadCbor),
    };
    let version = match map.get(&Value::Text("version".into())) {
        Some(Value::Text(value)) => value.clone(),
        _ => return Err(Error::BadCbor),
    };
    Ok(PeerRecord {
        epoch,
        agent_pub,
        listen: optional_text("listen")?,
        observed: optional_text("observed")?,
        relays,
        supernode,
        uptime_s: u64::try_from(integer("uptime_s")?).map_err(|_| Error::BadCbor)?,
        load: u16::try_from(integer("load")?).map_err(|_| Error::BadCbor)?,
        version,
    })
}

/// Public bootstrap key for first-contact heartbeats.
///
/// Heartbeats carry the agent's fresh per-agent key encrypted under this value,
/// so a stolen fleet key only exposes new heartbeats, not task or result traffic.
pub const BOOTSTRAP_ENC_KEY: [u8; 32] = [
    0x41, 0x47, 0x45, 0x4e, 0x54, 0x46, 0x4c, 0x45, 0x45, 0x54, 0x2d, 0x42, 0x4f, 0x4f, 0x54, 0x53,
    0x54, 0x52, 0x41, 0x50, 0x2d, 0x56, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

/// Self-described liveness and identity record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heartbeat {
    /// Producing agent's public key.
    pub agent_pub: [u8; 32],
    /// Hostname or label.
    pub host: String,
    /// Agent version.
    pub version: String,
    /// Current poll interval.
    pub poll_interval_s: u64,
    /// The agent's per-agent encryption key, announced on first contact.
    pub enc_key: [u8; 32],
    /// Frame epoch.
    pub epoch: u64,
}

/// Encodes a heartbeat. The signature is made by the agent, and the body repeats
/// the public key so a coordinator can verify first contact without prior state.
pub fn encode_heartbeat(
    heartbeat: &Heartbeat,
    enc_key: &[u8; 32],
    signing_key: &SigningKey,
) -> Result<Vec<u8>, Error> {
    let mut map = BTreeMap::new();
    map.insert(
        Value::Text("agent_pub".into()),
        Value::Bytes(heartbeat.agent_pub.to_vec()),
    );
    map.insert(
        Value::Text("host".into()),
        Value::Text(heartbeat.host.clone()),
    );
    map.insert(
        Value::Text("version".into()),
        Value::Text(heartbeat.version.clone()),
    );
    map.insert(
        Value::Text("poll_interval_s".into()),
        Value::Integer(heartbeat.poll_interval_s as i128),
    );
    map.insert(
        Value::Text("epoch".into()),
        Value::Integer(heartbeat.epoch as i128),
    );
    map.insert(
        Value::Text("enc_key".into()),
        Value::Bytes(heartbeat.enc_key.to_vec()),
    );
    encode_frame(
        MsgType::Heartbeat,
        route_tag_from_key(signing_key.verifying_key().as_bytes()),
        heartbeat.epoch,
        &Value::Map(map),
        enc_key,
        signing_key,
    )
}

/// Decodes and self-verifies a heartbeat.
///
/// The signature is checked against the public key carried in the body and the
/// header route tag must equal the tag derived from that key.
pub fn decode_heartbeat(
    bytes: &[u8],
    enc_key: &[u8; 32],
    last_epoch: &mut u64,
) -> Result<Heartbeat, Error> {
    let (plaintext, epoch, signature, route_tag) =
        decrypt_self(bytes, enc_key, MsgType::Heartbeat)?;
    if epoch <= *last_epoch {
        return Err(Error::StaleEpoch);
    }
    let Value::Map(map) = serde_cbor::from_slice(&plaintext).map_err(|_| Error::BadCbor)? else {
        return Err(Error::BadCbor);
    };
    let agent_pub: [u8; 32] = match map.get(&Value::Text("agent_pub".into())) {
        Some(Value::Bytes(value)) => value.as_slice().try_into().map_err(|_| Error::BadCbor)?,
        _ => return Err(Error::BadCbor),
    };
    verify_with(bytes, &agent_pub, &signature)?;
    if route_tag_from_key(&agent_pub) != route_tag {
        return Err(Error::BadRoute);
    }
    let text = |key: &str| match map.get(&Value::Text(key.into())) {
        Some(Value::Text(value)) => Ok(value.clone()),
        _ => Err(Error::BadCbor),
    };
    let poll_interval_s = match map.get(&Value::Text("poll_interval_s".into())) {
        Some(Value::Integer(value)) => u64::try_from(*value).map_err(|_| Error::BadCbor)?,
        _ => return Err(Error::BadCbor),
    };
    let enc_key = match map.get(&Value::Text("enc_key".into())) {
        Some(Value::Bytes(value)) => value.as_slice().try_into().map_err(|_| Error::BadCbor)?,
        _ => return Err(Error::BadCbor),
    };
    let body_epoch = match map.get(&Value::Text("epoch".into())) {
        Some(Value::Integer(value)) => u64::try_from(*value).map_err(|_| Error::BadCbor)?,
        _ => return Err(Error::BadCbor),
    };
    if body_epoch != epoch {
        return Err(Error::BadCbor);
    }
    *last_epoch = epoch;
    Ok(Heartbeat {
        agent_pub,
        host: text("host")?,
        version: text("version")?,
        poll_interval_s,
        enc_key,
        epoch,
    })
}

/// Decodes a result whose signer is not known in advance.
///
/// Returns the result plus the verified public key. Used for first-contact
/// results before the coordinator has an agent row.
pub fn decode_result_any(
    bytes: &[u8],
    enc_key: &[u8; 32],
    last_epoch: &mut u64,
) -> Result<(ResultMessage, [u8; 32]), Error> {
    let (plaintext, epoch, signature, _) = decrypt_self(bytes, enc_key, MsgType::Result)?;
    if epoch <= *last_epoch {
        return Err(Error::StaleEpoch);
    }
    let result = decode_result_body(&plaintext, epoch)?;
    let agent_pub = result.agent_pub;
    verify_with(bytes, &agent_pub, &signature)?;
    *last_epoch = epoch;
    Ok((result, agent_pub))
}

/// A coordinator key rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotate {
    /// New coordinator verifying key.
    pub new_pub: [u8; 32],
    /// Monotonic rotation generation (Unix milliseconds).
    pub generation: u64,
}

/// A binary upgrade request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upgrade {
    /// Target version string.
    pub version: String,
    /// Expected SHA-256 of the bytes.
    pub sha256: [u8; 32],
    /// Size in bytes.
    pub size: u64,
    /// Download URL.
    pub url: String,
    /// Frame epoch.
    pub epoch: u64,
}

/// Encodes a rotation signed by the outgoing coordinator key.
pub fn encode_rotate(
    rotate: &Rotate,
    enc_key: &[u8; 32],
    signing_key: &SigningKey,
) -> Result<Vec<u8>, Error> {
    let map = BTreeMap::from([
        (
            Value::Text("new_pub".into()),
            Value::Bytes(rotate.new_pub.to_vec()),
        ),
        (
            Value::Text("generation".into()),
            Value::Integer(rotate.generation as i128),
        ),
    ]);
    encode_frame(
        MsgType::Rotate,
        route_tag_from_key(signing_key.verifying_key().as_bytes()),
        rotate.generation,
        &Value::Map(map),
        enc_key,
        signing_key,
    )
}

/// Decodes a rotation, verifying it with the current coordinator key.
pub fn decode_rotate(
    bytes: &[u8],
    verifying_key: &VerifyingKey,
    enc_key: &[u8; 32],
    last_generation: &mut u64,
) -> Result<Rotate, Error> {
    verify(bytes, verifying_key)?;
    let generation = frame_epoch(bytes)?;
    if generation <= *last_generation {
        return Err(Error::StaleEpoch);
    }
    let (header, signed, _) = split_frame(bytes)?;
    if header[6] != MsgType::Rotate as u8 {
        return Err(Error::UnknownMsgType);
    }
    let payload_len = u16::from_le_bytes([header[47], header[48]]) as usize;
    let nonce: [u8; 24] = header[23..47].try_into().map_err(|_| Error::BadLength)?;
    let plaintext = XChaCha20Poly1305::new(enc_key.into())
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &signed[HEADER_LEN..HEADER_LEN + payload_len],
                aad: header,
            },
        )
        .map_err(|_| Error::BadAead)?;
    let Value::Map(map) = serde_cbor::from_slice(&plaintext).map_err(|_| Error::BadCbor)? else {
        return Err(Error::BadCbor);
    };
    let new_pub = match map.get(&Value::Text("new_pub".into())) {
        Some(Value::Bytes(value)) => value.as_slice().try_into().map_err(|_| Error::BadCbor)?,
        _ => return Err(Error::BadCbor),
    };
    let body_generation = match map.get(&Value::Text("generation".into())) {
        Some(Value::Integer(value)) => u64::try_from(*value).map_err(|_| Error::BadCbor)?,
        _ => return Err(Error::BadCbor),
    };
    if body_generation != generation {
        return Err(Error::BadCbor);
    }
    *last_generation = generation;
    Ok(Rotate {
        new_pub,
        generation,
    })
}

/// Encodes an upgrade request. Signed by the coordinator.
pub fn encode_upgrade(
    upgrade: &Upgrade,
    enc_key: &[u8; 32],
    signing_key: &SigningKey,
) -> Result<Vec<u8>, Error> {
    let map = BTreeMap::from([
        (
            Value::Text("version".into()),
            Value::Text(upgrade.version.clone()),
        ),
        (
            Value::Text("sha256".into()),
            Value::Bytes(upgrade.sha256.to_vec()),
        ),
        (
            Value::Text("size".into()),
            Value::Integer(upgrade.size as i128),
        ),
        (Value::Text("url".into()), Value::Text(upgrade.url.clone())),
    ]);
    encode_frame(
        MsgType::Upgrade,
        route_tag_from_key(signing_key.verifying_key().as_bytes()),
        upgrade.epoch,
        &Value::Map(map),
        enc_key,
        signing_key,
    )
}

/// Decodes an upgrade, verifying it with the coordinator key.
pub fn decode_upgrade(
    bytes: &[u8],
    verifying_key: &VerifyingKey,
    enc_key: &[u8; 32],
    last_epoch: &mut u64,
) -> Result<Upgrade, Error> {
    verify(bytes, verifying_key)?;
    let epoch = frame_epoch(bytes)?;
    if epoch <= *last_epoch {
        return Err(Error::StaleEpoch);
    }
    let (header, signed, _) = split_frame(bytes)?;
    if header[6] != MsgType::Upgrade as u8 {
        return Err(Error::UnknownMsgType);
    }
    let payload_len = u16::from_le_bytes([header[47], header[48]]) as usize;
    let nonce: [u8; 24] = header[23..47].try_into().map_err(|_| Error::BadLength)?;
    let plaintext = XChaCha20Poly1305::new(enc_key.into())
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &signed[HEADER_LEN..HEADER_LEN + payload_len],
                aad: header,
            },
        )
        .map_err(|_| Error::BadAead)?;
    let Value::Map(map) = serde_cbor::from_slice(&plaintext).map_err(|_| Error::BadCbor)? else {
        return Err(Error::BadCbor);
    };
    let text = |key: &str| match map.get(&Value::Text(key.into())) {
        Some(Value::Text(value)) => Ok(value.clone()),
        _ => Err(Error::BadCbor),
    };
    let sha256 = match map.get(&Value::Text("sha256".into())) {
        Some(Value::Bytes(value)) => value.as_slice().try_into().map_err(|_| Error::BadCbor)?,
        _ => return Err(Error::BadCbor),
    };
    let size = match map.get(&Value::Text("size".into())) {
        Some(Value::Integer(value)) => u64::try_from(*value).map_err(|_| Error::BadCbor)?,
        _ => return Err(Error::BadCbor),
    };
    if size == 0 || size > 64 * 1024 * 1024 {
        return Err(Error::BadLength);
    }
    *last_epoch = epoch;
    Ok(Upgrade {
        version: text("version")?,
        sha256,
        size,
        url: text("url")?,
        epoch,
    })
}

/// Encodes a signed result using the frozen task frame format.
pub fn encode_result(
    result: &ResultMessage,
    enc_key: &[u8; 32],
    signing_key: &SigningKey,
) -> Result<Vec<u8>, Error> {
    let mut map = BTreeMap::new();
    map.insert(
        Value::Text("agent_pub".into()),
        Value::Bytes(result.agent_pub.to_vec()),
    );
    map.insert(
        Value::Text("code".into()),
        Value::Integer(i128::from(result.code)),
    );
    map.insert(Value::Text("ok".into()), Value::Bool(result.ok));
    map.insert(
        Value::Text("stderr".into()),
        Value::Text(result.stderr.clone()),
    );
    map.insert(
        Value::Text("stdout".into()),
        Value::Text(result.stdout.clone()),
    );
    map.insert(
        Value::Text("task_epoch".into()),
        Value::Integer(i128::from(result.task_epoch)),
    );
    encode_frame(
        MsgType::Result,
        route_tag_from_key(&result.agent_pub),
        result.task_epoch,
        &Value::Map(map),
        enc_key,
        signing_key,
    )
}

/// Verifies, decrypts, and decodes a signed result in mandatory receive order.
pub fn decode_result(
    bytes: &[u8],
    verifying_key: &VerifyingKey,
    enc_key: &[u8; 32],
    last_epoch: &mut u64,
) -> Result<DecodedResult, Error> {
    verify(bytes, verifying_key)?;
    let epoch = frame_epoch(bytes)?;
    if epoch <= *last_epoch {
        return Err(Error::StaleEpoch);
    }
    let (header, signed, _) = split_frame(bytes)?;
    let payload_len = u16::from_le_bytes([header[47], header[48]]) as usize;
    if signed[HEADER_LEN + payload_len..]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(Error::BadPadding);
    }
    let nonce: [u8; 24] = header[23..47].try_into().map_err(|_| Error::BadLength)?;
    let plaintext = XChaCha20Poly1305::new(enc_key.into())
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &signed[HEADER_LEN..HEADER_LEN + payload_len],
                aad: header,
            },
        )
        .map_err(|_| Error::BadAead)?;
    if header[6] != MsgType::Result as u8 {
        return Err(Error::UnknownMsgType);
    }
    let result = decode_result_body(&plaintext, epoch)?;
    *last_epoch = epoch;
    Ok(DecodedResult {
        result,
        msg_type: MsgType::Result,
    })
}

fn verify_with(bytes: &[u8], public: &[u8; 32], signature: &Signature) -> Result<(), Error> {
    let key = VerifyingKey::from_bytes(public).map_err(|_| Error::BadSignature)?;
    key.verify(&bytes[..bytes.len() - SIGNATURE_LEN], signature)
        .map_err(|_| Error::BadSignature)
}

/// Splits, decrypts, and returns the signature and route tag without verifying.
fn decrypt_self(
    bytes: &[u8],
    enc_key: &[u8; 32],
    expected: MsgType,
) -> Result<(Vec<u8>, u64, Signature, [u8; 8]), Error> {
    let (header, signed, signature) = split_frame(bytes)?;
    if header[6] != expected as u8 {
        return Err(Error::UnknownMsgType);
    }
    let epoch = frame_epoch(bytes)?;
    let payload_len = u16::from_le_bytes([header[47], header[48]]) as usize;
    if signed[HEADER_LEN + payload_len..]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(Error::BadPadding);
    }
    let nonce: [u8; 24] = header[23..47].try_into().map_err(|_| Error::BadLength)?;
    let plaintext = XChaCha20Poly1305::new(enc_key.into())
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &signed[HEADER_LEN..HEADER_LEN + payload_len],
                aad: header,
            },
        )
        .map_err(|_| Error::BadAead)?;
    let route_tag = header[7..15].try_into().map_err(|_| Error::BadLength)?;
    Ok((plaintext, epoch, signature, route_tag))
}

fn decode_result_body(bytes: &[u8], epoch: u64) -> Result<ResultMessage, Error> {
    let Value::Map(map) = serde_cbor::from_slice(bytes).map_err(|_| Error::BadCbor)? else {
        return Err(Error::BadCbor);
    };
    let bytes_value = |key: &str| match map.get(&Value::Text(key.into())) {
        Some(Value::Bytes(value)) => value.as_slice().try_into().map_err(|_| Error::BadCbor),
        _ => Err(Error::BadCbor),
    };
    let integer = |key: &str| match map.get(&Value::Text(key.into())) {
        Some(Value::Integer(value)) => Ok(*value),
        _ => Err(Error::BadCbor),
    };
    let text = |key: &str| match map.get(&Value::Text(key.into())) {
        Some(Value::Text(value)) => Ok(value.clone()),
        _ => Err(Error::BadCbor),
    };
    let agent_pub = bytes_value("agent_pub")?;
    let task_epoch = u64::try_from(integer("task_epoch")?).map_err(|_| Error::BadCbor)?;
    if task_epoch != epoch {
        return Err(Error::BadCbor);
    }
    let ok = match map.get(&Value::Text("ok".into())) {
        Some(Value::Bool(value)) => *value,
        _ => return Err(Error::BadCbor),
    };
    let code = i32::try_from(integer("code")?).map_err(|_| Error::BadCbor)?;
    Ok(ResultMessage {
        task_epoch,
        agent_pub,
        ok,
        stdout: text("stdout")?,
        stderr: text("stderr")?,
        code,
    })
}

fn decode_mod_set_body(bytes: &[u8]) -> Result<ModSet, Error> {
    let Value::Map(map) = serde_cbor::from_slice(bytes).map_err(|_| Error::BadCbor)? else {
        return Err(Error::BadCbor);
    };
    let integer = |key: &str| match map.get(&Value::Text(key.into())) {
        Some(Value::Integer(value)) => Ok(*value),
        _ => Err(Error::BadCbor),
    };
    let Value::Array(add_values) = map.get(&Value::Text("add".into())).ok_or(Error::BadCbor)?
    else {
        return Err(Error::BadCbor);
    };
    let mut add = Vec::with_capacity(add_values.len());
    for value in add_values {
        let Value::Map(item) = value else {
            return Err(Error::BadCbor);
        };
        let text = |key: &str| match item.get(&Value::Text(key.into())) {
            Some(Value::Text(value)) => Ok(value.clone()),
            _ => Err(Error::BadCbor),
        };
        let Value::Bytes(hash) = item
            .get(&Value::Text("blake3".into()))
            .ok_or(Error::BadCbor)?
        else {
            return Err(Error::BadCbor);
        };
        let blake3 = hash.as_slice().try_into().map_err(|_| Error::BadCbor)?;
        let Value::Array(caps) = item
            .get(&Value::Text("capabilities".into()))
            .ok_or(Error::BadCbor)?
        else {
            return Err(Error::BadCbor);
        };
        let capabilities = caps
            .iter()
            .map(|value| match value {
                Value::Text(value) => Ok(value.clone()),
                _ => Err(Error::BadCbor),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let enabled = match item.get(&Value::Text("enabled".into())) {
            Some(Value::Bool(value)) => *value,
            _ => return Err(Error::BadCbor),
        };
        add.push(ModEntry {
            id: text("id")?,
            version: text("version")?,
            abi: u32::try_from(integer("abi")?).map_err(|_| Error::BadCbor)?,
            blake3,
            size: u64::try_from(integer("size")?).map_err(|_| Error::BadCbor)?,
            url: text("url")?,
            capabilities,
            enabled,
        });
    }
    let Value::Array(remove_values) = map
        .get(&Value::Text("remove".into()))
        .ok_or(Error::BadCbor)?
    else {
        return Err(Error::BadCbor);
    };
    let remove = remove_values
        .iter()
        .map(|value| match value {
            Value::Text(value) => Ok(value.clone()),
            _ => Err(Error::BadCbor),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ModSet {
        gen: u64::try_from(integer("gen")?).map_err(|_| Error::BadCbor)?,
        add,
        remove,
    })
}

fn encode_frame(
    msg_type: MsgType,
    route_tag: [u8; 8],
    epoch: u64,
    body: &Value,
    enc_key: &[u8; 32],
    signing_key: &SigningKey,
) -> Result<Vec<u8>, Error> {
    let plaintext = serde_cbor::to_vec(body).map_err(|_| Error::Serialization)?;
    let mut nonce = [0_u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let payload_len = plaintext
        .len()
        .checked_add(AEAD_TAG_LEN)
        .ok_or(Error::BadLength)?;
    if payload_len > MAX_PAYLOAD {
        return Err(Error::BadLength);
    }
    let frame_size = CLASSES
        .iter()
        .copied()
        .find(|size| *size >= HEADER_LEN + payload_len + SIGNATURE_LEN)
        .ok_or(Error::BadLength)?;
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(&MAGIC);
    header.extend_from_slice(&VERSION.to_le_bytes());
    header.push(msg_type as u8);
    header.extend_from_slice(&route_tag);
    header.extend_from_slice(&epoch.to_le_bytes());
    header.extend_from_slice(&nonce);
    header.extend_from_slice(&(payload_len as u16).to_le_bytes());
    let ciphertext = XChaCha20Poly1305::new(enc_key.into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &header,
            },
        )
        .map_err(|_| Error::BadAead)?;
    let mut signed = header;
    signed.extend_from_slice(&ciphertext);
    signed.resize(frame_size - SIGNATURE_LEN, 0);
    signed.extend_from_slice(&signing_key.sign(&signed).to_bytes());
    Ok(signed)
}

fn decode_relay_set_body(bytes: &[u8]) -> Result<RelaySet, Error> {
    let Value::Map(map) = serde_cbor::from_slice(bytes).map_err(|_| Error::BadCbor)? else {
        return Err(Error::BadCbor);
    };
    let Value::Integer(gen) = map.get(&Value::Text("gen".into())).ok_or(Error::BadCbor)? else {
        return Err(Error::BadCbor);
    };
    let gen = u64::try_from(*gen).map_err(|_| Error::BadCbor)?;
    let Value::Array(add_values) = map.get(&Value::Text("add".into())).ok_or(Error::BadCbor)?
    else {
        return Err(Error::BadCbor);
    };
    let mut add = Vec::with_capacity(add_values.len());
    for value in add_values {
        let Value::Map(item) = value else {
            return Err(Error::BadCbor);
        };
        let Value::Bytes(id) = item.get(&Value::Text("id".into())).ok_or(Error::BadCbor)? else {
            return Err(Error::BadCbor);
        };
        let id: [u8; 8] = id.as_slice().try_into().map_err(|_| Error::BadCbor)?;
        let Value::Text(kind) = item
            .get(&Value::Text("kind".into()))
            .ok_or(Error::BadCbor)?
        else {
            return Err(Error::BadCbor);
        };
        let Value::Integer(tier) = item
            .get(&Value::Text("tier".into()))
            .ok_or(Error::BadCbor)?
        else {
            return Err(Error::BadCbor);
        };
        let tier = u8::try_from(*tier).map_err(|_| Error::BadCbor)?;
        let Value::Text(addr) = item
            .get(&Value::Text("addr".into()))
            .ok_or(Error::BadCbor)?
        else {
            return Err(Error::BadCbor);
        };
        add.push(RelayEntry {
            id,
            kind: kind.clone(),
            tier,
            addr: addr.clone(),
        });
    }
    let Value::Array(remove_values) = map
        .get(&Value::Text("remove".into()))
        .ok_or(Error::BadCbor)?
    else {
        return Err(Error::BadCbor);
    };
    let remove = remove_values
        .iter()
        .map(|value| match value {
            Value::Bytes(id) => id.as_slice().try_into().map_err(|_| Error::BadCbor),
            _ => Err(Error::BadCbor),
        })
        .collect::<Result<Vec<[u8; 8]>, _>>()?;
    Ok(RelaySet { gen, add, remove })
}

/// Verifies a frame signature before any decryption is attempted.
pub fn verify(bytes: &[u8], verifying_key: &VerifyingKey) -> Result<(), Error> {
    let (_, signed, signature) = split_frame(bytes)?;
    verifying_key
        .verify(signed, &signature)
        .map_err(|_| Error::BadSignature)
}

/// Decrypts and decodes a task frame without updating epoch state.
pub fn decode(bytes: &[u8], enc_key: &[u8; 32]) -> Result<DecodedTask, Error> {
    let (header, signed, _) = split_frame(bytes)?;
    if header[..4] != MAGIC {
        return Err(Error::BadMagic);
    }
    if u16::from_le_bytes([header[4], header[5]]) != VERSION {
        return Err(Error::BadVersion);
    }
    let msg_type_byte = header[6];
    let payload_len = u16::from_le_bytes([header[47], header[48]]) as usize;
    let ciphertext = &signed[HEADER_LEN..HEADER_LEN + payload_len];
    if signed[HEADER_LEN + payload_len..]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(Error::BadPadding);
    }
    let nonce: [u8; 24] = header[23..47].try_into().map_err(|_| Error::BadLength)?;
    let cipher = XChaCha20Poly1305::new(enc_key.into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: header,
            },
        )
        .map_err(|_| Error::BadAead)?;
    let msg_type = match msg_type_byte {
        2 => MsgType::Task,
        _ => return Err(Error::UnknownMsgType),
    };
    let body = decode_body(&plaintext)?;
    Ok(DecodedTask {
        task: Task {
            route_tag: header[7..15].try_into().map_err(|_| Error::BadLength)?,
            epoch: u64::from_le_bytes(header[15..23].try_into().map_err(|_| Error::BadLength)?),
            body,
        },
        msg_type,
    })
}

/// Verifies, checks freshness, decrypts, and decodes a task in mandatory order.
pub fn decode_checked(
    bytes: &[u8],
    verifying_key: &VerifyingKey,
    enc_key: &[u8; 32],
    last_epoch: &mut u64,
) -> Result<DecodedTask, Error> {
    verify(bytes, verifying_key)?;
    let epoch = frame_epoch(bytes)?;
    if epoch <= *last_epoch {
        return Err(Error::StaleEpoch);
    }
    let decoded = decode(bytes, enc_key)?;
    *last_epoch = decoded.task.epoch;
    Ok(decoded)
}

fn split_frame(bytes: &[u8]) -> Result<(&[u8], &[u8], Signature), Error> {
    if bytes.len() < HEADER_LEN + SIGNATURE_LEN {
        return Err(Error::Truncated);
    }
    if bytes.len() < CLASSES[0] {
        return Err(Error::Truncated);
    }
    if !CLASSES.contains(&bytes.len()) {
        return Err(Error::BadLength);
    }
    let signed_end = bytes.len() - SIGNATURE_LEN;
    let header = &bytes[..HEADER_LEN];
    let payload_len = u16::from_le_bytes([header[47], header[48]]) as usize;
    if !(AEAD_TAG_LEN..=MAX_PAYLOAD).contains(&payload_len) || HEADER_LEN + payload_len > signed_end
    {
        return Err(Error::BadLength);
    }
    let signature = Signature::from_bytes(
        bytes[signed_end..]
            .try_into()
            .map_err(|_| Error::Truncated)?,
    );
    Ok((header, &bytes[..signed_end], signature))
}

fn frame_epoch(bytes: &[u8]) -> Result<u64, Error> {
    if bytes.len() < HEADER_LEN {
        return Err(Error::Truncated);
    }
    Ok(u64::from_le_bytes(
        bytes[15..23].try_into().map_err(|_| Error::Truncated)?,
    ))
}

fn encode_body(body: &TaskBody) -> Result<Vec<u8>, Error> {
    let mut map = BTreeMap::new();
    match body {
        TaskBody::Ping => {}
        TaskBody::Shell {
            argv,
            timeout_s,
            shell,
        } => {
            map.insert(
                Value::Text("argv".into()),
                Value::Array(argv.iter().map(|arg| Value::Text(arg.clone())).collect()),
            );
            map.insert(Value::Text("shell".into()), Value::Bool(*shell));
            map.insert(
                Value::Text("timeout_s".into()),
                Value::Integer(i128::from(*timeout_s)),
            );
        }
        TaskBody::Fetch { url, dest } => {
            map.insert(Value::Text("dest".into()), Value::Text(dest.clone()));
            map.insert(Value::Text("url".into()), Value::Text(url.clone()));
        }
        TaskBody::Mod {
            mod_id,
            version,
            args,
        } => {
            map.insert(Value::Text("args".into()), args.clone());
            map.insert(Value::Text("mod_id".into()), Value::Text(mod_id.clone()));
            map.insert(Value::Text("version".into()), Value::Text(version.clone()));
        }
    }
    serde_cbor::to_vec(&Value::Map(map)).map_err(|_| Error::Serialization)
}

fn decode_body(bytes: &[u8]) -> Result<TaskBody, Error> {
    let value: Value = serde_cbor::from_slice(bytes).map_err(|_| Error::BadCbor)?;
    let Value::Map(map) = value else {
        return Err(Error::BadCbor);
    };
    if map.is_empty() {
        return Ok(TaskBody::Ping);
    }
    let get = |key: &str| map.get(&Value::Text(key.into())).ok_or(Error::BadCbor);
    if map.contains_key(&Value::Text("argv".into())) {
        let Value::Array(argv) = get("argv")? else {
            return Err(Error::BadCbor);
        };
        let mut strings = Vec::with_capacity(argv.len());
        for value in argv {
            let Value::Text(text) = value else {
                return Err(Error::BadCbor);
            };
            strings.push(text.clone());
        }
        let Value::Integer(timeout) = get("timeout_s")? else {
            return Err(Error::BadCbor);
        };
        let timeout_s = u16::try_from(*timeout).map_err(|_| Error::BadCbor)?;
        let Value::Bool(shell) = get("shell")? else {
            return Err(Error::BadCbor);
        };
        return Ok(TaskBody::Shell {
            argv: strings,
            timeout_s,
            shell: *shell,
        });
    }
    if map.contains_key(&Value::Text("mod_id".into())) {
        let Value::Text(mod_id) = get("mod_id")? else {
            return Err(Error::BadCbor);
        };
        let Value::Text(version) = get("version")? else {
            return Err(Error::BadCbor);
        };
        let args = get("args")?.clone();
        return Ok(TaskBody::Mod {
            mod_id: mod_id.clone(),
            version: version.clone(),
            args,
        });
    }
    let Value::Text(url) = get("url")? else {
        return Err(Error::BadCbor);
    };
    let Value::Text(dest) = get("dest")? else {
        return Err(Error::BadCbor);
    };
    Ok(TaskBody::Fetch {
        url: url.clone(),
        dest: dest.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn heartbeat_round_trips_and_self_verifies() {
        let agent = SigningKey::generate(&mut OsRng);
        let enc = [7_u8; 32];
        let heartbeat = Heartbeat {
            agent_pub: *agent.verifying_key().as_bytes(),
            host: "h1t3m-box".into(),
            version: "0.1.0".into(),
            poll_interval_s: 300,
            enc_key: [9_u8; 32],
            epoch: 4,
        };
        let frame = encode_heartbeat(&heartbeat, &enc, &agent).unwrap();
        let mut epoch = 0;
        let decoded = decode_heartbeat(&frame, &enc, &mut epoch).unwrap();
        assert_eq!(decoded, heartbeat);
        assert_eq!(epoch, 4);

        let mut tampered = frame.clone();
        let index = tampered.len() - 1;
        tampered[index] ^= 0xff;
        assert!(matches!(
            decode_heartbeat(&tampered, &enc, &mut 0),
            Err(Error::BadSignature)
        ));
        assert!(matches!(
            decode_heartbeat(&frame, &enc, &mut 4),
            Err(Error::StaleEpoch)
        ));
    }

    #[test]
    fn rotate_and_upgrade_round_trip() {
        let coordinator = SigningKey::generate(&mut OsRng);
        let enc = [4_u8; 32];
        let fresh = SigningKey::generate(&mut OsRng);
        let rotate = Rotate {
            new_pub: *fresh.verifying_key().as_bytes(),
            generation: 1000,
        };
        let frame = encode_rotate(&rotate, &enc, &coordinator).unwrap();
        let mut generation = 0;
        let decoded =
            decode_rotate(&frame, &coordinator.verifying_key(), &enc, &mut generation).unwrap();
        assert_eq!(decoded, rotate);
        assert_eq!(generation, 1000);
        assert!(matches!(
            decode_rotate(&frame, &coordinator.verifying_key(), &enc, &mut 1000),
            Err(Error::StaleEpoch)
        ));

        let upgrade = Upgrade {
            version: "9.9.9".into(),
            sha256: [8_u8; 32],
            size: 1234,
            url: "https://files.example/agentd".into(),
            epoch: 2000,
        };
        let frame = encode_upgrade(&upgrade, &enc, &coordinator).unwrap();
        let mut epoch = 0;
        let decoded =
            decode_upgrade(&frame, &coordinator.verifying_key(), &enc, &mut epoch).unwrap();
        assert_eq!(decoded, upgrade);
        let mut tampered = frame.clone();
        let index = tampered.len() - 1;
        tampered[index] ^= 1;
        assert!(matches!(
            decode_upgrade(&tampered, &coordinator.verifying_key(), &enc, &mut 0),
            Err(Error::BadSignature)
        ));
    }

    #[test]
    fn result_any_verifies_the_embedded_key() {
        let agent = SigningKey::generate(&mut OsRng);
        let enc = [3_u8; 32];
        let result = ResultMessage {
            task_epoch: 9,
            agent_pub: *agent.verifying_key().as_bytes(),
            ok: true,
            stdout: "hi".into(),
            stderr: String::new(),
            code: 0,
        };
        let frame = encode_result(&result, &enc, &agent).unwrap();
        let (decoded, public) = decode_result_any(&frame, &enc, &mut 0).unwrap();
        assert_eq!(decoded, result);
        assert_eq!(public, result.agent_pub);

        let other = SigningKey::generate(&mut OsRng);
        let wrong = encode_result(&result, &enc, &other).unwrap();
        assert_eq!(
            decode_result_any(&wrong, &enc, &mut 0).unwrap_err(),
            Error::BadSignature
        );
    }

    fn key() -> ([u8; 32], SigningKey) {
        ([7_u8; 32], SigningKey::generate(&mut OsRng))
    }

    #[test]
    fn every_task_body_fits_the_smallest_frame_class() {
        let (enc, signing) = key();
        let bodies = [
            TaskBody::Ping,
            TaskBody::Shell {
                argv: vec!["echo".into(), "hi".into()],
                timeout_s: 10,
                shell: false,
            },
            TaskBody::Fetch {
                url: "https://example.invalid/a".into(),
                dest: "/tmp/a".into(),
            },
        ];
        for body in bodies {
            let frame = encode_task(
                &Task {
                    route_tag: [0; 8],
                    epoch: 1,
                    body,
                },
                &enc,
                &signing,
            )
            .expect("encoding should work");
            assert_eq!(frame.len(), 256);
        }
    }

    #[test]
    fn round_trip_and_replay_protection_work() {
        let (enc, signing) = key();
        let frame = encode_task(
            &Task {
                route_tag: [1; 8],
                epoch: 1,
                body: TaskBody::Ping,
            },
            &enc,
            &signing,
        )
        .expect("encoding should work");
        let mut last = 0;
        assert_eq!(
            decode_checked(&frame, &signing.verifying_key(), &enc, &mut last)
                .expect("decode should work")
                .task
                .epoch,
            1
        );
        assert_eq!(
            decode_checked(&frame, &signing.verifying_key(), &enc, &mut last),
            Err(Error::StaleEpoch)
        );
    }

    #[test]
    fn signed_result_round_trips_and_rejects_tampering() {
        let (enc, signing) = key();
        let result = ResultMessage {
            task_epoch: 7,
            agent_pub: *signing.verifying_key().as_bytes(),
            ok: false,
            stdout: "out".into(),
            stderr: "err".into(),
            code: -1,
        };
        let frame = encode_result(&result, &enc, &signing).expect("result should encode");
        let mut last = 0;
        let decoded = decode_result(&frame, &signing.verifying_key(), &enc, &mut last)
            .expect("result should decode");
        assert_eq!(decoded.result, result);
        let mut tampered = frame;
        tampered[16] ^= 1;
        assert_eq!(
            decode_result(&tampered, &signing.verifying_key(), &enc, &mut 0),
            Err(Error::BadSignature)
        );
    }

    #[test]
    fn signed_peer_record_round_trips_and_rejects_replay() {
        let (enc, signing) = key();
        let peer = PeerRecord {
            epoch: 9,
            agent_pub: *signing.verifying_key().as_bytes(),
            listen: Some("127.0.0.1:9000".into()),
            observed: None,
            relays: vec!["0:0:relay:https://relay.invalid".into()],
            supernode: true,
            uptime_s: 123,
            load: 7,
            version: "0.1.0".into(),
        };
        let frame = encode_peer_record(&peer, &enc, &signing).expect("peer record should encode");
        let mut last = 0;
        assert_eq!(
            decode_peer_record(&frame, &signing.verifying_key(), &enc, &mut last)
                .expect("peer record should decode")
                .peer,
            peer
        );
        assert_eq!(
            decode_peer_record(&frame, &signing.verifying_key(), &enc, &mut last),
            Err(Error::StaleEpoch)
        );
    }

    #[test]
    fn frozen_wire_format_matches_the_checked_in_contract() {
        let frozen = include_str!("../../../FROZEN");
        let field = |name: &str| {
            frozen
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{name} = ")))
                .unwrap_or_else(|| panic!("FROZEN is missing `{name}`"))
                .trim()
                .to_owned()
        };
        let hex = |bytes: &[u8]| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };

        assert_eq!(field("magic"), hex(&MAGIC));
        assert_eq!(field("version"), VERSION.to_string());
        assert_eq!(field("header_len"), HEADER_LEN.to_string());
        assert_eq!(field("signature_len"), SIGNATURE_LEN.to_string());
        assert_eq!(field("aead_tag_len"), AEAD_TAG_LEN.to_string());
        assert_eq!(field("max_payload"), MAX_PAYLOAD.to_string());
        assert_eq!(
            field("size_classes"),
            CLASSES
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );

        // Encode a real frame and pin every frozen header offset.
        let (enc, signing) = key();
        let route_tag = [1_u8, 2, 3, 4, 5, 6, 7, 8];
        let epoch = 0x0102_0304_0506_0708_u64;
        let frame = encode_task(
            &Task {
                route_tag,
                epoch,
                body: TaskBody::Ping,
            },
            &enc,
            &signing,
        )
        .expect("frame");
        assert_eq!(&frame[..4], &MAGIC, "offset 0: magic");
        assert_eq!(
            u16::from_le_bytes([frame[4], frame[5]]),
            VERSION,
            "offset 4: version"
        );
        assert_eq!(frame[6], MsgType::Task as u8, "offset 6: message type");
        assert_eq!(&frame[7..15], &route_tag, "offset 7: route tag");
        assert_eq!(
            u64::from_le_bytes(frame[15..23].try_into().expect("epoch field")),
            epoch,
            "offset 15: epoch"
        );
        let payload_len = u16::from_le_bytes([frame[47], frame[48]]) as usize;
        assert!(
            (AEAD_TAG_LEN..=MAX_PAYLOAD).contains(&payload_len),
            "offset 47: payload length {payload_len}"
        );
        assert!(CLASSES.contains(&frame.len()), "frame is one class");
        assert!(frame.len() >= HEADER_LEN + payload_len + SIGNATURE_LEN);
        assert!(
            frame[HEADER_LEN + payload_len..frame.len() - SIGNATURE_LEN]
                .iter()
                .all(|byte| *byte == 0),
            "padding is zero"
        );
        verify(&frame, &signing.verifying_key()).expect("signature covers the frozen region");
    }
}
