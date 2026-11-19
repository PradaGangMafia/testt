#![cfg(unix)]

//! Coordinator database is encrypted at rest and migrates plaintext in place.

use std::{fs, os::unix::fs::PermissionsExt, path::Path, time::Duration};

use db::{Database, VerifiedResult};
use ed25519_dalek::SigningKey;
use msgfmt::ResultMessage;
use rand::rngs::OsRng;
use tempfile::TempDir;

fn plaintext_database(state: &Path) -> u64 {
    let mut db = Database::open(state.join("findings.db")).unwrap();
    let agent = [7_u8; 32];
    let tag = msgfmt::route_tag_from_key(&agent);
    db.ingest(&[VerifiedResult {
        agent_pub: agent,
        route_tag: tag,
        result: ResultMessage {
            task_epoch: 1,
            agent_pub: agent,
            ok: true,
            stdout: "kept".into(),
            stderr: String::new(),
            code: 0,
        },
    }])
    .unwrap();
    db.stats().unwrap().results
}

#[test]
fn coordinator_encrypts_and_reads_an_existing_plaintext_database() {
    let state = TempDir::new().unwrap();
    let signing = SigningKey::generate(&mut OsRng);
    fs::write(state.path().join("agent.key"), signing.to_bytes()).unwrap();
    fs::write(state.path().join("enc.key"), [6_u8; 32]).unwrap();
    let seeded = plaintext_database(state.path());

    // Opening through the coordinator migrates in place.
    let coord = coordd::Coord::open(state.path()).unwrap();
    assert_eq!(coord.database().stats().unwrap().results, seeded);
    let path = state.path().join("findings.db");
    assert!(db::is_encrypted(&path), "database must not stay plaintext");
    let key_mode = fs::metadata(state.path().join("coord.key"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(key_mode & 0o777, 0o600);

    // Raw SQLite cannot read it; SQLCipher with the key can.
    let raw = rusqlite::Connection::open(&path).unwrap();
    assert!(raw
        .query_row("SELECT COUNT(*) FROM sqlite_master", [], |row| row
            .get::<_, i64>(0))
        .is_err());
    drop(raw);
    let key: [u8; 32] = fs::read(state.path().join("coord.key"))
        .unwrap()
        .try_into()
        .unwrap();
    let encrypted = Database::open_encrypted(&path, &key).unwrap();
    assert_eq!(encrypted.stats().unwrap().results, seeded);
}

#[test]
fn fresh_coordinator_state_is_encrypted() {
    let state = TempDir::new().unwrap();
    let signing = SigningKey::generate(&mut OsRng);
    fs::write(state.path().join("agent.key"), signing.to_bytes()).unwrap();
    fs::write(state.path().join("enc.key"), [6_u8; 32]).unwrap();
    drop(coordd::Coord::open(state.path()).unwrap());
    let path = state.path().join("findings.db");
    assert!(path.is_file());
    assert!(db::is_encrypted(&path));
    let _ = Duration::from_secs(1);
}
