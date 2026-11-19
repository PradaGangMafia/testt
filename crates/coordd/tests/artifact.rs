//! Artifact endpoint: auth, digest, dedupe, storage.

use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    thread,
    time::Duration,
};

use base64::Engine;
use db::Database;
use ed25519_dalek::{Signer, SigningKey};
use sha2::Digest;
use tempfile::TempDir;

fn workspace() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

struct Server {
    port: u16,
    _state: TempDir,
    database: Database,
    signing: SigningKey,
}

fn start(token: Option<&str>) -> Server {
    let state = TempDir::new().unwrap();
    fs::write(state.path().join("agent.key"), [1_u8; 32]).unwrap();
    fs::write(state.path().join("enc.key"), [2_u8; 32]).unwrap();
    let database = coordd::open_database(state.path()).unwrap();
    let signing = SigningKey::from_bytes(&[3_u8; 32]);
    let agent = *signing.verifying_key().as_bytes();
    let tag = msgfmt::route_tag_from_key(&agent);
    database
        .upsert_agent(&agent, &tag, "h", "1", &[2_u8; 32])
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let path = state.path().to_path_buf();
    let token = token.map(str::to_owned);
    thread::spawn(move || coordd::artifact::serve_listener(listener, path, token));
    Server {
        port,
        _state: state,
        database,
        signing,
    }
}

fn post(
    port: u16,
    tag: &str,
    sha: &str,
    path: &str,
    body: &[u8],
    signing: &SigningKey,
    token: Option<&str>,
) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let encoded = base64::engine::general_purpose::STANDARD.encode(path.as_bytes());
    let auth = token
        .map(|token| format!("x-token: {token}\r\n"))
        .unwrap_or_default();
    let signature = base64::engine::general_purpose::STANDARD
        .encode(signing.sign(format!("{sha}:{tag}").as_bytes()).to_bytes());
    let request = format!(
        "POST /artifact/{tag} HTTP/1.1\r\nhost: x\r\nx-sha256: {sha}\r\nx-signature: {signature}\r\nx-kind: browser_password\r\nx-path: {encoded}\r\n{auth}content-length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(request.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let status = response
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    (status, response)
}

fn digest(body: &[u8]) -> String {
    sha2::Sha256::digest(body)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn stores_a_verified_artifact_and_dedupes() {
    let server = start(None);
    let tag = msgfmt::route_tag_from_key(server.signing.verifying_key().as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let body = b"credential-bytes";
    let sha = digest(body);
    let (status, response) = post(
        server.port,
        &tag,
        &sha,
        "/home/a/Login Data",
        body,
        &server.signing,
        None,
    );
    assert_eq!(status, 200, "{response}");
    assert!(response.contains("\"id\""), "{response}");
    let rows = server.database.artifacts().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].path, "/home/a/Login Data");
    assert_eq!(rows[0].size, body.len() as i64);
    let stored: PathBuf = server._state.path().join("artifacts").join(&rows[0].stored);
    let on_disk = fs::read(&stored).unwrap();
    assert_ne!(on_disk, body, "artifact must not be stored in clear");
    let key = coordd::artifact::load_key(server._state.path()).unwrap();
    assert_eq!(
        coordd::artifact::read_encrypted(&stored, &key).unwrap(),
        body
    );

    // Same digest: duplicate, no second row.
    let (status, response) = post(
        server.port,
        &tag,
        &sha,
        "/other/path",
        body,
        &server.signing,
        None,
    );
    assert_eq!(status, 200, "{response}");
    assert!(response.contains("duplicate"), "{response}");
    assert_eq!(server.database.artifacts().unwrap().len(), 1);
}

#[test]
fn rejects_bad_digest_unknown_tag_and_bad_token() {
    let server = start(Some("s3cret"));
    let agent = &server.signing;
    let tag = msgfmt::route_tag_from_key(agent.verifying_key().as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    // Bad digest.
    let (status, _) = post(
        server.port,
        &tag,
        &"0".repeat(64),
        "/a",
        b"x",
        agent,
        Some("s3cret"),
    );
    assert_eq!(status, 422);
    // Bad token.
    let (status, _) = post(
        server.port,
        &tag,
        &digest(b"x"),
        "/a",
        b"x",
        agent,
        Some("wrong"),
    );
    assert_eq!(status, 401);
    // Missing signature.
    let mut stream = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    let sha = digest(b"x");
    let unsigned = format!(
        "POST /artifact/{tag} HTTP/1.1\r\nhost: x\r\nx-sha256: {sha}\r\ncontent-length: 1\r\n\r\nx"
    );
    stream.write_all(unsigned.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.contains(" 401 "), "{response}");
    // Wrong signer: valid key, wrong secret.
    let stranger = SigningKey::from_bytes(&[4_u8; 32]);
    let (status, _) = post(
        server.port,
        &tag,
        &sha,
        "/a",
        b"x",
        &stranger,
        Some("s3cret"),
    );
    assert_eq!(status, 401);
    // Unknown tag.
    let (status, _) = post(
        server.port,
        &"00".repeat(8),
        &sha,
        "/a",
        b"x",
        agent,
        Some("s3cret"),
    );
    assert_eq!(status, 403);
    assert!(server.database.artifacts().unwrap().is_empty());
}

#[test]
fn coordctl_lists_and_exports_an_artifact() {
    let server = start(None);
    let tag = msgfmt::route_tag_from_key(server.signing.verifying_key().as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let body = b"export-me";
    let (status, _) = post(
        server.port,
        &tag,
        &digest(body),
        "/b",
        body,
        &server.signing,
        None,
    );
    assert_eq!(status, 200);
    let state = server._state.path();
    let listed = std::process::Command::new(env!("CARGO_BIN_EXE_coordctl"))
        .arg("--state")
        .arg(state)
        .arg("artifacts")
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let text = String::from_utf8_lossy(&listed.stdout);
    assert!(text.contains("/b"), "{text}");
    let id = server.database.artifacts().unwrap()[0].id;
    let out = TempDir::new().unwrap();
    let destination = out.path().join("copy.bin");
    let exported = std::process::Command::new(env!("CARGO_BIN_EXE_coordctl"))
        .arg("--state")
        .arg(state)
        .args(["artifact", "export"])
        .arg(id.to_string())
        .arg("--out")
        .arg(&destination)
        .output()
        .unwrap();
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    assert_eq!(fs::read(destination).unwrap(), body);
    let _ = workspace();
}

#[test]
fn serve_returns_immediately_and_keeps_accepting() {
    let state = TempDir::new().unwrap();
    fs::write(state.path().join("agent.key"), [1_u8; 32]).unwrap();
    // Reserve a port, then release it for `serve` to bind.
    let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reserved.local_addr().unwrap();
    drop(reserved);

    let started = std::time::Instant::now();
    coordd::artifact::serve(&address.to_string(), state.path().to_path_buf(), None).unwrap();
    // Before the fix this call ran the accept loop and never returned.
    assert!(started.elapsed() < Duration::from_secs(2));

    // Give the background accept loop a moment, then prove it is listening.
    let mut connected = false;
    for _ in 0..50 {
        if TcpStream::connect(address).is_ok() {
            connected = true;
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(connected, "artifact endpoint did not accept connections");
}
