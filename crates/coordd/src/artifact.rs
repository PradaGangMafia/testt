//! Minimal artifact ingestion endpoint for agents.
//!
//! One POST per artifact (<=1 MiB). The body is verified against the `x-sha256`
//! header and the request is signed with the agent key stored for the route tag,
//! then stored under `<state>/artifacts/<tag>/` and recorded in the database
//! with `(agent, digest)` deduplication. An optional shared token is checked
//! first; nothing is written until both checks pass.

use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    thread,
};

use base64::Engine;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;

const MAX_BODY: usize = 1024 * 1024;
const MAX_HEADERS: usize = 8 * 1024;

/// Loads the artifact key, creating it with 0600 when absent.
pub fn load_key(state: &Path) -> std::io::Result<[u8; 32]> {
    let path = state.join("artifact.key");
    if let Ok(bytes) = fs::read(&path) {
        if let Ok(key) = <[u8; 32]>::try_from(bytes.as_slice()) {
            return Ok(key);
        }
    }
    let mut key = [0_u8; 32];
    OsRng.fill_bytes(&mut key);
    fs::write(&path, key)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(key)
}

/// Encrypts artifact bytes as `nonce || ciphertext`.
fn encrypt(key: &[u8; 32], data: &[u8]) -> std::io::Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0_u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let mut out = nonce.to_vec();
    out.extend_from_slice(
        &cipher
            .encrypt(XNonce::from_slice(&nonce), data)
            .map_err(|_| std::io::Error::other("encrypt"))?,
    );
    Ok(out)
}

/// Decrypts a stored artifact for export.
pub fn read_encrypted(path: &Path, key: &[u8; 32]) -> std::io::Result<Vec<u8>> {
    let bytes = fs::read(path)?;
    if bytes.len() < 25 {
        return Err(std::io::Error::other("short artifact"));
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(XNonce::from_slice(&bytes[..24]), &bytes[24..])
        .map_err(|_| std::io::Error::other("decrypt"))
}

/// Serves artifacts on an existing listener.
pub fn serve_listener(listener: TcpListener, state: PathBuf, token: Option<String>) {
    let key = match load_key(&state) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("artifact: key: {error}");
            return;
        }
    };
    for stream in listener.incoming().flatten() {
        let state = state.clone();
        let token = token.clone();
        thread::spawn(move || {
            let _ = handle(stream, &state, token.as_deref(), &key);
        });
    }
}

/// Binds `bind` and serves artifacts on a background thread.
///
/// Binding happens eagerly so a bad address is reported to the caller, but the
/// accept loop must not run on the calling thread: `coordd` starts this before
/// its pull/schedule loop, which would otherwise never be reached.
pub fn serve(bind: &str, state: PathBuf, token: Option<String>) -> std::io::Result<()> {
    let listener = TcpListener::bind(bind)?;
    thread::spawn(move || serve_listener(listener, state, token));
    Ok(())
}

fn handle(
    mut stream: TcpStream,
    state: &Path,
    token: Option<&str>,
    key: &[u8; 32],
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(20)))?;
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        if buffer.len() > MAX_HEADERS {
            return respond(&mut stream, 431, b"headers too large\n");
        }
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return respond(&mut stream, 400, b"truncated\n");
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(index) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let mut lines = headers.lines();
    let request = lines.next().unwrap_or_default().to_owned();
    if request.starts_with("GET /health ") {
        return respond(&mut stream, 200, b"{\"ok\":true}\n");
    }
    let Some(tag) = request
        .strip_prefix("POST /artifact/")
        .and_then(|rest| rest.split_whitespace().next())
    else {
        return respond(&mut stream, 404, b"not found\n");
    };
    let headers = parse_headers(&headers);
    if let Some(token) = token {
        let provided = headers
            .iter()
            .find(|(name, _)| name == "x-token")
            .map(|(_, value)| value.as_str())
            .or_else(|| {
                headers
                    .iter()
                    .find(|(name, _)| name == "authorization")
                    .and_then(|(_, value)| value.strip_prefix("Bearer "))
            });
        if provided != Some(token) {
            return respond(&mut stream, 401, b"unauthorized\n");
        }
    }
    let length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    if length == 0 || length > MAX_BODY {
        return respond(&mut stream, 413, b"bad length\n");
    }
    let mut body = buffer[header_end..].to_vec();
    while body.len() < length {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    if body.len() != length {
        return respond(&mut stream, 400, b"short body\n");
    }
    let digest = blake3_sha256(&body);
    let expected = headers
        .iter()
        .find(|(name, _)| name == "x-sha256")
        .map(|(_, value)| value.to_ascii_lowercase())
        .unwrap_or_default();
    if digest != expected {
        return respond(&mut stream, 422, b"digest mismatch\n");
    }
    let path = headers
        .iter()
        .find(|(name, _)| name == "x-path")
        .and_then(|(_, value)| base64::engine::general_purpose::STANDARD.decode(value).ok())
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_else(|| "unknown".into());
    let kind = headers
        .iter()
        .find(|(name, _)| name == "x-kind")
        .map(|(_, value)| value.clone())
        .unwrap_or_else(|| "other".into());
    let tag_bytes = match hex(tag) {
        Some(bytes) => bytes,
        None => return respond(&mut stream, 400, b"bad tag\n"),
    };
    let database = match crate::open_database(state) {
        Ok(database) => database,
        Err(_) => return respond(&mut stream, 500, b"database\n"),
    };
    let agent_pub = match database.agent_key(&tag_bytes) {
        Ok(Some(key)) => key,
        Ok(None) => return respond(&mut stream, 403, b"unknown agent\n"),
        Err(_) => return respond(&mut stream, 500, b"database\n"),
    };
    // Per-agent signature over `sha256:tag`; the token is an optional extra gate.
    let signature = headers
        .iter()
        .find(|(name, _)| name == "x-signature")
        .and_then(|(_, value)| base64::engine::general_purpose::STANDARD.decode(value).ok())
        .and_then(|bytes| <[u8; 64]>::try_from(bytes.as_slice()).ok())
        .map(|bytes| Signature::from_bytes(&bytes));
    let Some(signature) = signature else {
        return respond(&mut stream, 401, b"missing signature\n");
    };
    let Ok(verifying) = VerifyingKey::from_bytes(&agent_pub) else {
        return respond(&mut stream, 500, b"bad agent key\n");
    };
    if verifying
        .verify(format!("{digest}:{tag}").as_bytes(), &signature)
        .is_err()
    {
        return respond(&mut stream, 401, b"bad signature\n");
    }

    let directory = state.join("artifacts").join(tag);
    if fs::create_dir_all(&directory).is_err() {
        return respond(&mut stream, 500, b"store\n");
    }
    let stored = format!("{tag}/{}-{}", &digest[..16], flatten(&path));
    let destination = state.join("artifacts").join(&stored);
    let id = database
        .put_artifact(
            &agent_pub,
            &tag_bytes,
            &path,
            &digest,
            body.len() as i64,
            &kind,
            &stored,
        )
        .ok()
        .flatten();
    let Some(id) = id else {
        return respond(&mut stream, 200, b"{\"duplicate\":true}\n");
    };
    let encrypted = match encrypt(key, &body) {
        Ok(encrypted) => encrypted,
        Err(_) => return respond(&mut stream, 500, b"encrypt\n"),
    };
    if fs::write(&destination, &encrypted).is_err() {
        return respond(&mut stream, 500, b"write\n");
    }
    respond(&mut stream, 200, format!("{{\"id\":{id}}}\n").as_bytes())
}

fn parse_headers(raw: &str) -> Vec<(String, String)> {
    raw.lines()
        .skip(1)
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect()
}

fn respond(stream: &mut TcpStream, status: u16, body: &[u8]) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Payload Too Large",
        422 => "Unprocessable Entity",
        431 => "Request Header Fields Too Large",
        _ => "Internal Server Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()
}

fn hex(value: &str) -> Option<[u8; 8]> {
    if value.len() != 16 {
        return None;
    }
    let mut bytes = [0_u8; 8];
    for (index, chunk) in value.as_bytes().chunks(2).enumerate() {
        bytes[index] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(bytes)
}

fn flatten(path: &str) -> String {
    path.trim_start_matches('/')
        .replace(['\\', '/', ':'], "_")
        .chars()
        .take(120)
        .collect()
}

fn blake3_sha256(data: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
