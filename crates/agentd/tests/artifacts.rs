//! Agent spool uploader: acknowledged rows are deleted, failures stay.

use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::Path,
    thread,
};

use agentd::artifacts::upload_pending;
use base64::Engine;
use ed25519_dalek::{Signature, SigningKey};
use rusqlite::Connection;
use sha2::Digest;
use tempfile::TempDir;

fn header(request: &str, name: &str) -> String {
    request
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}: ")))
        .unwrap_or_default()
        .trim()
        .to_owned()
}

fn spool(state: &Path, rows: &[(&str, &[u8], bool)]) {
    let connection = Connection::open(state.join("spool.db")).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE artifacts(id INTEGER PRIMARY KEY, path TEXT, sha256 TEXT, size INTEGER, kind TEXT, captured_at INTEGER, data BLOB);",
        )
        .unwrap();
    for (path, data, _) in rows {
        let sha: String = sha2::Sha256::digest(data)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        connection
            .execute(
                "INSERT INTO artifacts(path,sha256,size,kind,captured_at,data) VALUES (?1,?2,?3,'k',0,?4)",
                rusqlite::params![path, sha, data.len() as i64, data],
            )
            .unwrap();
    }
}

fn server(accept: usize, fail_first: bool) -> (u16, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let mut seen = Vec::new();
        for index in 0..accept {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = vec![0_u8; 8192];
            let mut request = Vec::new();
            loop {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if let Some(position) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..position]).into_owned();
                    let length: usize = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length: "))
                        .and_then(|value| value.trim().parse().ok())
                        .unwrap_or(0);
                    while request.len() < position + 4 + length {
                        let read = stream.read(&mut buffer).unwrap();
                        if read == 0 {
                            break;
                        }
                        request.extend_from_slice(&buffer[..read]);
                    }
                    seen.push(String::from_utf8_lossy(&request).into_owned());
                    let status = if fail_first && index == 0 { 500 } else { 200 };
                    let _ = write!(
                        stream,
                        "HTTP/1.1 {status} X\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"
                    );
                    break;
                }
            }
        }
        seen
    });
    (port, handle)
}

#[test]
fn uploads_then_deletes_acknowledged_rows() {
    let state = TempDir::new().unwrap();
    spool(state.path(), &[("/a", b"one", true), ("/b", b"two", true)]);
    let (port, handle) = server(2, false);
    let signing = SigningKey::from_bytes(&[7_u8; 32]);
    let report = upload_pending(
        state.path(),
        &format!("http://127.0.0.1:{port}"),
        &[9_u8; 8],
        &signing,
        Some("tok"),
        8,
    )
    .unwrap();
    assert_eq!(report.uploaded, 2);
    assert_eq!(report.remaining, 0);
    let requests = handle.join().unwrap();
    assert!(requests[0].contains("x-token: tok"), "{}", requests[0]);
    assert!(
        requests[0].contains("/artifact/0909090909090909"),
        "{}",
        requests[0]
    );
    assert!(requests[1].contains("x-sha256: "), "{}", requests[1]);
    // The signature covers the digest and the destination tag.
    let digest: String = sha2::Sha256::digest(b"one")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let signature: [u8; 64] = base64::engine::general_purpose::STANDARD
        .decode(header(&requests[0], "x-signature"))
        .unwrap()
        .try_into()
        .unwrap();
    signing
        .verifying_key()
        .verify_strict(
            format!("{digest}:0909090909090909").as_bytes(),
            &Signature::from_bytes(&signature),
        )
        .expect("upload signature verifies");
    let connection = Connection::open(state.path().join("spool.db")).unwrap();
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM artifacts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn a_failed_upload_keeps_the_row() {
    let state = TempDir::new().unwrap();
    spool(state.path(), &[("/a", b"one", true)]);
    let (port, handle) = server(1, true);
    let signing = SigningKey::from_bytes(&[7_u8; 32]);
    let report = upload_pending(
        state.path(),
        &format!("http://127.0.0.1:{port}"),
        &[9_u8; 8],
        &signing,
        None,
        4,
    )
    .unwrap();
    assert_eq!(report.failed, 1);
    assert_eq!(report.remaining, 1);
    assert_eq!(
        upload_pending(
            state.path(),
            "http://127.0.0.1:9",
            &[9_u8; 8],
            &signing,
            None,
            4
        )
        .unwrap()
        .remaining,
        1
    );
    handle.join().unwrap();
    let connection = Connection::open(state.path().join("spool.db")).unwrap();
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM artifacts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
    let _ = fs::metadata(state.path().join("spool.db")).unwrap();
}
