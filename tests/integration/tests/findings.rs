//! P46 database acceptance: d01–d13.

use db::{Database, Error, FindingInput, FindingOutcome, ResultFrame, VerifiedResult};
use ed25519_dalek::SigningKey;
use msgfmt::{encode_result, ResultMessage};
use std::io::Cursor;

const ENC_KEY: [u8; 32] = [8; 32];
const ROUTE_TAG: [u8; 8] = [1; 8];

fn open(label: &str) -> Database {
    let dir = integration_tests::temp(label);
    Database::open(dir.join("coordinator.db")).expect("database opens")
}

fn agent_key() -> [u8; 32] {
    [7; 32]
}

fn result(epoch: u64) -> VerifiedResult {
    VerifiedResult {
        agent_pub: agent_key(),
        route_tag: ROUTE_TAG,
        result: ResultMessage {
            task_epoch: epoch,
            agent_pub: agent_key(),
            ok: true,
            stdout: format!("out-{epoch}"),
            stderr: String::new(),
            code: 0,
        },
    }
}

fn finding(kind: &str, key: &str, severity: i64, data: &str) -> FindingInput {
    FindingInput {
        kind: kind.into(),
        dedupe_key: key.into(),
        severity,
        data: data.into(),
    }
}

#[test]
fn d01_init_creates_a_v4_database() {
    let dir = integration_tests::temp("d01");
    let path = dir.join("state").join("coordinator.db");
    let db = Database::open(&path).expect("fresh database");
    assert_eq!(db.path(), path);
    assert!(path.is_file(), "database file exists");
    let version: i32 = db
        .connection()
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("user_version");
    assert_eq!(version, 4);
    let stats = db.stats().expect("stats");
    assert_eq!(
        (stats.agents, stats.results, stats.findings, stats.events),
        (0, 0, 0, 0)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "database is private");
    }
}

#[test]
fn d02_reopen_migrates_once_and_refuses_a_newer_schema() {
    let dir = integration_tests::temp("d02");
    let path = dir.join("coordinator.db");
    {
        let mut db = Database::open(&path).expect("create");
        db.ingest(&[result(1)]).expect("seed");
    }
    {
        // Reopening a current database is a no-op migration and keeps data.
        let db = Database::open(&path).expect("reopen");
        let version: i32 = db
            .connection()
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("version");
        assert_eq!(version, 4);
        assert_eq!(db.stats().expect("stats").results, 1);
        db.connection()
            .pragma_update(None, "user_version", 99)
            .expect("simulate newer schema");
    }
    match Database::open(&path) {
        Err(Error::InvalidInput(message)) => {
            assert!(message.contains("newer than supported"), "{message}");
        }
        Err(other) => panic!("unexpected error: {other}"),
        Ok(_) => panic!("a newer schema must be refused"),
    }
}

#[test]
fn d03_batch_ingest_is_idempotent_and_commits_once() {
    let mut db = open("d03");
    let batch = (1..=1000).map(result).collect::<Vec<_>>();
    assert_eq!(db.ingest(&batch).expect("first batch"), 1000);
    assert_eq!(db.ingest(&batch).expect("replayed batch"), 0);
    let stats = db.stats().expect("stats");
    assert_eq!(stats.results, 1000);
    assert_eq!(stats.agents, 1);
    assert_eq!(stats.events, 0);
}

#[test]
fn d04_unenrolled_result_lands_in_events_only() {
    let mut db = open("d04");
    let enrolled = SigningKey::from_bytes(&[7; 32]);
    let claimed = SigningKey::from_bytes(&[9; 32]);
    let frame = encode_result(
        &ResultMessage {
            task_epoch: 1,
            agent_pub: claimed.verifying_key().to_bytes(),
            ok: true,
            stdout: "spoofed".into(),
            stderr: String::new(),
            code: 0,
        },
        &ENC_KEY,
        &enrolled,
    )
    .expect("frame");
    let error = db
        .ingest_frame(
            ResultFrame {
                bytes: &frame,
                verifying_key: &enrolled.verifying_key(),
            },
            &ENC_KEY,
            ROUTE_TAG,
        )
        .expect_err("identity mismatch is refused");
    assert!(matches!(error, Error::UntrustedResult), "{error}");
    db.record_event("untrusted", "agent is not enrolled")
        .expect("event");
    let stats = db.stats().expect("stats");
    assert_eq!(stats.results, 0, "no result row for an unenrolled agent");
    assert_eq!(stats.agents, 0, "no agent row for an unenrolled agent");
    assert_eq!(stats.events, 1);
}

#[test]
fn d05_malformed_frame_keeps_its_reason_in_events() {
    let mut db = open("d05");
    let enrolled = SigningKey::from_bytes(&[7; 32]);
    let error = db
        .ingest_frame(
            ResultFrame {
                bytes: b"this is not a signed frame",
                verifying_key: &enrolled.verifying_key(),
            },
            &ENC_KEY,
            ROUTE_TAG,
        )
        .expect_err("garbage is rejected");
    assert!(matches!(error, Error::MalformedResult(_)), "{error}");
    db.record_event("malformed", &error.to_string())
        .expect("event");
    let stats = db.stats().expect("stats");
    assert_eq!(stats.results, 0);
    assert_eq!(stats.events, 1);
    let detail: String = db
        .connection()
        .query_row(
            "SELECT detail FROM events ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("detail");
    assert!(!detail.is_empty(), "the rejection reason is retained");
}

#[test]
fn d06_verified_result_is_stored_with_its_agent() {
    let mut db = open("d06");
    let mut item = result(42);
    item.result.stdout = "captured".into();
    item.result.stderr = "warned".into();
    item.result.code = 3;
    item.result.ok = false;
    assert_eq!(db.ingest(&[item]).expect("store"), 1);
    let row: (i64, bool, String, String, i32) = db
        .connection()
        .query_row(
            "SELECT task_epoch,ok,stdout,stderr,code FROM results",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .expect("result row");
    assert_eq!(row, (42, false, "captured".into(), "warned".into(), 3));
    let route: Vec<u8> = db
        .connection()
        .query_row("SELECT route_tag FROM agents", [], |row| row.get(0))
        .expect("agent row");
    assert_eq!(route, ROUTE_TAG.to_vec());
    assert_eq!(db.stats().expect("stats").results, 1);
}

#[test]
fn d07_duplicate_key_raises_severity_without_duplicating() {
    let mut db = open("d07");
    db.ingest(&[result(1)]).expect("result");
    let outcomes = db
        .extract_findings(1, &[finding("security", "dup-key", 2, "first")])
        .expect("first");
    assert_eq!(outcomes, vec![FindingOutcome::Stored]);
    let outcomes = db
        .extract_findings(1, &[finding("security", "dup-key", 5, "second")])
        .expect("raise");
    assert_eq!(outcomes, vec![FindingOutcome::Raised]);
    let outcomes = db
        .extract_findings(1, &[finding("security", "dup-key", 1, "lower")])
        .expect("lower");
    assert_eq!(outcomes, vec![FindingOutcome::Raised]);
    assert_eq!(db.stats().expect("stats").findings, 1, "one row only");
    let rows = db.query_findings("second").expect("search raised data");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].severity, 5, "severity never decreases");
    assert_eq!(rows[0].data, "second");
    assert!(
        db.query_findings("first")
            .expect("search old data")
            .is_empty(),
        "FTS follows the update"
    );
}

#[test]
fn d08_missing_dedupe_key_is_rejected_but_the_result_survives() {
    let mut db = open("d08");
    db.ingest(&[result(1)]).expect("result");
    let outcomes = db
        .extract_findings(
            1,
            &[
                finding("health", "", 1, "empty"),
                finding("health", "   ", 1, "blank"),
                finding("health", "kept", 1, "valid"),
            ],
        )
        .expect("extract");
    assert!(matches!(
        &outcomes[0],
        FindingOutcome::Rejected(reason) if reason.contains("missing dedupe_key")
    ));
    assert!(matches!(
        &outcomes[1],
        FindingOutcome::Rejected(reason) if reason.contains("missing dedupe_key")
    ));
    assert_eq!(outcomes[2], FindingOutcome::Stored);
    let stats = db.stats().expect("stats");
    assert_eq!(stats.results, 1, "the result is still stored");
    assert_eq!(stats.findings, 1);
    assert_eq!(stats.events, 2, "each rejection is recorded");
    let rejected: i64 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM events WHERE kind='finding_rejected'",
            [],
            |row| row.get(0),
        )
        .expect("rejection events");
    assert_eq!(rejected, 2);
}

#[test]
fn d09_unknown_kind_is_rejected_without_losing_the_batch() {
    let mut db = open("d09");
    db.ingest(&[result(1)]).expect("result");
    let outcomes = db
        .extract_findings(
            1,
            &[
                finding("network", "k1", 1, "not vocabulary"),
                finding("compliance", "k2", 1, "accepted"),
            ],
        )
        .expect("extract");
    assert!(matches!(
        &outcomes[0],
        FindingOutcome::Rejected(reason) if reason.contains("unknown kind")
    ));
    assert_eq!(outcomes[1], FindingOutcome::Stored);
    assert_eq!(db.stats().expect("stats").findings, 1);
    assert_eq!(db.query_findings("accepted").expect("query").len(), 1);
}

#[test]
fn d10_csv_and_json_exports_quote_correctly() {
    let mut db = open("d10");
    db.ingest(&[result(1)]).expect("result");
    db.extract_findings(
        1,
        &[finding(
            "inventory",
            "key,with\"quote",
            4,
            "line one\nline two, \"quoted\"",
        )],
    )
    .expect("finding");

    let mut csv = Cursor::new(Vec::new());
    let count = db.export_findings("csv", &mut csv).expect("csv");
    assert_eq!(count, 1);
    let csv = String::from_utf8(csv.into_inner()).expect("utf8");
    assert!(csv.starts_with("id,kind,dedupe_key,severity,data\r\n"));
    assert!(
        csv.contains("\"key,with\"\"quote\""),
        "RFC 4180 quote doubling: {csv}"
    );
    assert!(
        csv.contains("\"line one\nline two, \"\"quoted\"\"\""),
        "newlines and quotes are wrapped: {csv}"
    );

    let mut json = Cursor::new(Vec::new());
    db.export_findings("json", &mut json).expect("json");
    let value: serde_json::Value =
        serde_json::from_slice(&json.into_inner()).expect("valid JSON array");
    let rows = value.as_array().expect("array");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["dedupe_key"], "key,with\"quote");
    assert_eq!(rows[0]["data"], "line one\nline two, \"quoted\"");

    let mut ndjson = Cursor::new(Vec::new());
    db.export_findings("ndjson", &mut ndjson).expect("ndjson");
    let ndjson = String::from_utf8(ndjson.into_inner()).expect("utf8");
    let lines = ndjson.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 1);
    let line: serde_json::Value = serde_json::from_str(lines[0]).expect("valid ndjson");
    assert_eq!(line["severity"], 4);

    let mut unknown = Cursor::new(Vec::new());
    assert!(matches!(
        db.export_findings("yaml", &mut unknown),
        Err(Error::InvalidInput(_))
    ));
}

#[test]
fn d11_prune_is_scoped_to_the_cutoff_and_bounded() {
    let mut db = open("d11");
    db.ingest(&[result(1)]).expect("result");
    db.extract_findings(
        1,
        &[
            finding("security", "old-a", 1, "old a"),
            finding("security", "old-b", 1, "old b"),
            finding("security", "fresh", 1, "fresh"),
        ],
    )
    .expect("findings");
    db.connection()
        .execute(
            "UPDATE findings SET created_at=100 WHERE dedupe_key IN ('old-a','old-b')",
            [],
        )
        .expect("age two rows");
    assert_eq!(db.prune(200).expect("prune"), 2);
    assert_eq!(db.stats().expect("stats").findings, 1);
    assert_eq!(
        db.query_findings("fresh").expect("query").len(),
        1,
        "the newer finding survives"
    );

    // The delete is bounded to 10,000 rows per call.
    db.connection().execute_batch("BEGIN;").expect("begin bulk");
    for index in 0..10_005 {
        db.connection()
            .execute(
                "INSERT INTO findings(kind,dedupe_key,severity,data,result_id,created_at) VALUES ('health',?1,1,'bulk',1,1)",
                [format!("bulk-{index}")],
            )
            .expect("bulk insert");
    }
    db.connection()
        .execute_batch("COMMIT;")
        .expect("commit bulk");
    assert_eq!(db.prune(200).expect("first bounded prune"), 10_000);
    assert_eq!(db.prune(200).expect("second bounded prune"), 5);
    assert_eq!(db.prune(200).expect("third bounded prune"), 0);
    assert_eq!(db.stats().expect("stats").findings, 1);
}

#[test]
fn d12_backup_is_consistent_and_cannot_target_the_state_directory() {
    let dir = integration_tests::temp("d12");
    let path = dir.join("state").join("coordinator.db");
    let mut db = Database::open(&path).expect("open");
    db.ingest(&[result(1)]).expect("result");
    db.extract_findings(1, &[finding("health", "backup-key", 2, "kept")])
        .expect("finding");

    let refusal = db.backup(path.parent().expect("parent").join("copy.db"));
    assert!(
        matches!(&refusal, Err(Error::InvalidInput(message)) if message.contains("state directory")),
        "{refusal:?}"
    );

    let destination = integration_tests::temp("d12-out").join("backup.db");
    db.backup(&destination).expect("backup outside state dir");
    assert!(destination.is_file());
    let restored = Database::open(&destination).expect("backup opens");
    let version: i32 = restored
        .connection()
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("version");
    assert_eq!(version, 4);
    let stats = restored.stats().expect("stats");
    assert_eq!(stats.results, 1);
    assert_eq!(stats.findings, 1);
    let rows = restored.query_findings("kept").expect("findings copied");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].data, "kept");
}

#[test]
fn d13_fts_stays_in_sync_after_deletes() {
    let mut db = open("d13");
    db.ingest(&[result(1)]).expect("result");
    db.extract_findings(1, &[finding("tamper", "t1", 3, "needle alpha")])
        .expect("finding");
    assert_eq!(db.query_findings("needle").expect("before delete").len(), 1);
    assert_eq!(db.prune(i64::MAX).expect("delete"), 1);
    assert!(
        db.query_findings("needle")
            .expect("after delete")
            .is_empty(),
        "deleted rows leave the FTS index"
    );
    db.extract_findings(1, &[finding("tamper", "t2", 3, "needle beta")])
        .expect("reinsert");
    let rows = db.query_findings("needle").expect("after reinsert");
    assert_eq!(rows.len(), 1, "the index is usable after a delete entry");
    assert_eq!(rows[0].dedupe_key, "t2");
    db.connection()
        .execute_batch("INSERT INTO findings_fts(findings_fts) VALUES('integrity-check');")
        .expect("FTS integrity check");
}
