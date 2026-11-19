#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Coordinator-only SQLite storage for verified results and extracted findings.

use ed25519_dalek::VerifyingKey;
use msgfmt::{decode_result, ResultMessage};
use rusqlite::{params, Connection, OptionalExtension};
use std::{
    fmt::Write as _,
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

const SCHEMA_VERSION: i32 = 4;
const FINDING_KINDS: [&str; 5] = ["security", "inventory", "compliance", "health", "tamper"];

/// Database failures.
#[derive(Debug, Error)]
pub enum Error {
    /// SQLite returned an error.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// A filesystem operation failed.
    #[error("filesystem: {0}")]
    Io(#[from] std::io::Error),
    /// A supplied value did not satisfy the database contract.
    #[error("invalid database input: {0}")]
    InvalidInput(String),
    /// A result was not signed by an enrolled identity.
    #[error("untrusted result")]
    UntrustedResult,
    /// A result frame could not be decoded.
    #[error("malformed result: {0}")]
    MalformedResult(String),
}

/// A database handle. The handle is deliberately synchronous and coordinator-only.
pub struct Database {
    connection: Connection,
    path: PathBuf,
}

/// A verified result ready for idempotent insertion.
#[derive(Debug, Clone)]
pub struct VerifiedResult {
    /// Public key of the enrolled producing agent.
    pub agent_pub: [u8; 32],
    /// Pinned route tag for the agent.
    pub route_tag: [u8; 8],
    /// Decoded result body.
    pub result: ResultMessage,
}

/// A result frame supplied to the ingest path.
#[derive(Debug)]
pub struct ResultFrame<'a> {
    /// Signed and encrypted result bytes.
    pub bytes: &'a [u8],
    /// Enrolled public key used to verify the frame.
    pub verifying_key: &'a VerifyingKey,
}

/// A finding emitted by a module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingInput {
    /// Fixed vocabulary finding kind.
    pub kind: String,
    /// Stable key used for deduplication.
    pub dedupe_key: String,
    /// Severity, where larger values are more severe.
    pub severity: i64,
    /// JSON or module-defined data retained as text.
    pub data: String,
}

/// A finding validation or insertion outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingOutcome {
    /// Finding was inserted.
    Stored,
    /// Existing finding was retained and its severity was raised.
    Raised,
    /// Finding was rejected without affecting its result.
    Rejected(String),
}

/// Aggregate counts returned by the stats query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Number of enrolled agents.
    pub agents: u64,
    /// Number of stored results.
    pub results: u64,
    /// Number of stored findings.
    pub findings: u64,
    /// Number of events.
    pub events: u64,
}

/// Extracts the documented `findings` envelope from a result body.
///
/// Missing or malformed envelopes yield no findings; the result is retained.
pub fn findings_from_stdout(stdout: &str) -> Vec<FindingInput> {
    let Ok(serde_json::Value::Object(mut object)) = serde_json::from_str(stdout) else {
        return Vec::new();
    };
    let Some(serde_json::Value::Array(items)) = object.remove("findings") else {
        return Vec::new();
    };
    items
        .into_iter()
        .filter_map(|item| {
            let serde_json::Value::Object(mut item) = item else {
                return None;
            };
            let kind = item.remove("kind")?.as_str()?.to_owned();
            let dedupe_key = item.remove("dedupe_key")?.as_str()?.to_owned();
            let severity = item
                .remove("severity")
                .and_then(|value| value.as_i64())
                .unwrap_or(0);
            let data = match item.remove("data") {
                Some(serde_json::Value::String(text)) => text,
                Some(value) => value.to_string(),
                None => "{}".into(),
            };
            Some(FindingInput {
                kind,
                dedupe_key,
                severity,
                data,
            })
        })
        .collect()
}

/// One stored artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactRow {
    /// Row id.
    pub id: i64,
    /// Source path on the bot.
    pub path: String,
    /// SHA-256 of the bytes.
    pub sha256: String,
    /// Size in bytes.
    pub size: i64,
    /// Artifact kind.
    pub kind: String,
    /// Path relative to the artifact root.
    pub stored: String,
    /// Storage time.
    pub stored_at: i64,
    /// Route tag of the uploader.
    pub route_tag: Vec<u8>,
}

/// One enrolled agent summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRow {
    /// Public key.
    pub agent_pub: Vec<u8>,
    /// Route tag.
    pub route_tag: Vec<u8>,
    /// First contact.
    pub first_seen: i64,
    /// Last result or heartbeat.
    pub last_seen: i64,
    /// Whether scheduling is disabled.
    pub revoked: bool,
    /// Stored result count.
    pub results: u64,
}

/// One recurring task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Schedule {
    /// Row id.
    pub id: i64,
    /// Target route tag.
    pub route_tag: Vec<u8>,
    /// Module id.
    pub mod_id: String,
    /// Module version.
    pub version: String,
    /// JSON arguments.
    pub args: String,
    /// Period in seconds.
    pub every_s: i64,
    /// Extra random delay in seconds.
    pub jitter_s: i64,
    /// Next due time.
    pub next_at: i64,
}

/// One finding row returned by an FTS query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingRow {
    /// Stable database row identifier.
    pub id: i64,
    /// Fixed vocabulary kind.
    pub kind: String,
    /// Stable deduplication key.
    pub dedupe_key: String,
    /// Finding severity.
    pub severity: i64,
    /// Finding data.
    pub data: String,
}

impl Database {
    /// Opens or creates a plaintext database, applies forward-only migrations,
    /// and configures SQLite.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::open_with_key(path, None)
    }

    /// Opens or creates a SQLCipher database encrypted with `key`.
    pub fn open_encrypted(path: impl AsRef<Path>, key: &[u8; 32]) -> Result<Self, Error> {
        Self::open_with_key(path, Some(key))
    }

    fn open_with_key(path: impl AsRef<Path>, key: Option<&[u8; 32]>) -> Result<Self, Error> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(&path)?;
        if let Some(key) = key {
            apply_key(&connection, key)?;
        }
        connection.busy_timeout(std::time::Duration::from_millis(5_000))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;
        migrate(&connection)?;
        set_private_mode(&path)?;
        Ok(Self { connection, path })
    }

    /// Returns the on-disk path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Inserts a batch in exactly one transaction. Duplicate task/agent pairs are no-ops.
    pub fn ingest(&mut self, results: &[VerifiedResult]) -> Result<usize, Error> {
        let tx = self.connection.transaction()?;
        let mut inserted = 0;
        for item in results {
            if item.agent_pub != item.result.agent_pub {
                return Err(Error::UntrustedResult);
            }
            tx.execute(
                "INSERT INTO agents(agent_pub,route_tag,first_seen,last_seen) VALUES (?1,?2,?3,?4)
                 ON CONFLICT(agent_pub) DO UPDATE SET last_seen=excluded.last_seen, route_tag=excluded.route_tag",
                params![
                    item.agent_pub.as_slice(),
                    item.route_tag.as_slice(),
                    now(),
                    now()
                ],
            )?;
            inserted += tx.execute(
                "INSERT OR IGNORE INTO results(task_epoch,agent_pub,ok,stdout,stderr,code,received_at) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    i64::try_from(item.result.task_epoch).map_err(|_| {
                        Error::InvalidInput("task epoch exceeds the SQLite range".into())
                    })?,
                    item.agent_pub.as_slice(),
                    item.result.ok,
                    item.result.stdout,
                    item.result.stderr,
                    item.result.code,
                    now()
                ],
            )?;
        }
        tx.commit()?;
        Ok(inserted)
    }

    /// Decodes and verifies one result, writing malformed frames to events.
    pub fn ingest_frame(
        &mut self,
        frame: ResultFrame<'_>,
        enc_key: &[u8; 32],
        route_tag: [u8; 8],
    ) -> Result<bool, Error> {
        Ok(self.ingest_frame_id(frame, enc_key, route_tag)?.is_some())
    }

    /// Ingests one already-verified result and returns its row id if new.
    pub fn ingest_verified(&mut self, item: &VerifiedResult) -> Result<Option<i64>, Error> {
        if self.ingest(std::slice::from_ref(item))? == 1 {
            Ok(Some(self.connection.last_insert_rowid()))
        } else {
            Ok(None)
        }
    }

    /// As [`ingest_frame`], returning the new result row id when inserted.
    ///
    /// The id lets the caller attach findings extracted from the result.
    pub fn ingest_frame_id(
        &mut self,
        frame: ResultFrame<'_>,
        enc_key: &[u8; 32],
        route_tag: [u8; 8],
    ) -> Result<Option<i64>, Error> {
        let mut epoch = 0;
        let decoded = decode_result(frame.bytes, frame.verifying_key, enc_key, &mut epoch)
            .map_err(|error| Error::MalformedResult(error.to_string()))?;
        let agent_pub = *frame.verifying_key.as_bytes();
        if decoded.result.agent_pub != agent_pub {
            return Err(Error::UntrustedResult);
        }
        if self.ingest(&[VerifiedResult {
            agent_pub,
            route_tag,
            result: decoded.result,
        }])? == 1
        {
            Ok(Some(self.connection.last_insert_rowid()))
        } else {
            Ok(None)
        }
    }

    /// Lists agents with result counts.
    pub fn agents(&self) -> Result<Vec<AgentRow>, Error> {
        let mut statement = self.connection.prepare(
            "SELECT a.agent_pub,a.route_tag,a.first_seen,a.last_seen,a.revoked,
                    (SELECT COUNT(*) FROM results r WHERE r.agent_pub=a.agent_pub)
             FROM agents a ORDER BY a.last_seen DESC",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok(AgentRow {
                    agent_pub: row.get(0)?,
                    route_tag: row.get(1)?,
                    first_seen: row.get(2)?,
                    last_seen: row.get(3)?,
                    revoked: row.get::<_, i64>(4)? != 0,
                    results: row.get::<_, i64>(5)? as u64,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Inserts or refreshes an agent from a heartbeat.
    pub fn upsert_agent(
        &self,
        agent_pub: &[u8],
        route_tag: &[u8],
        host: &str,
        version: &str,
        enc_key: &[u8],
    ) -> Result<(), Error> {
        let metadata = serde_json::json!({"host": host, "version": version}).to_string();
        self.connection.execute(
            "INSERT INTO agents(agent_pub,route_tag,first_seen,last_seen,enc_key) VALUES (?1,?2,?3,?3,?4)
             ON CONFLICT(agent_pub) DO UPDATE SET last_seen=excluded.last_seen, route_tag=excluded.route_tag, enc_key=excluded.enc_key",
            params![agent_pub, route_tag, now(), enc_key],
        )?;
        self.record_event("agent_seen", &metadata)?;
        Ok(())
    }

    /// Records an uploaded artifact, deduplicated by agent and digest.
    #[allow(clippy::too_many_arguments)]
    pub fn put_artifact(
        &self,
        agent_pub: &[u8],
        route_tag: &[u8],
        path: &str,
        sha256: &str,
        size: i64,
        kind: &str,
        stored: &str,
    ) -> Result<Option<i64>, Error> {
        let inserted = self.connection.execute(
            "INSERT OR IGNORE INTO artifacts(agent_pub,route_tag,path,sha256,size,kind,stored,stored_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![agent_pub, route_tag, path, sha256, size, kind, stored, now()],
        )?;
        Ok((inserted == 1).then(|| self.connection.last_insert_rowid()))
    }

    /// Lists artifacts newest first.
    pub fn artifacts(&self) -> Result<Vec<ArtifactRow>, Error> {
        let mut statement = self.connection.prepare(
            "SELECT id,path,sha256,size,kind,stored,stored_at,route_tag FROM artifacts ORDER BY id DESC",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok(ArtifactRow {
                    id: row.get(0)?,
                    path: row.get(1)?,
                    sha256: row.get(2)?,
                    size: row.get(3)?,
                    kind: row.get(4)?,
                    stored: row.get(5)?,
                    stored_at: row.get(6)?,
                    route_tag: row.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Returns the newest findings, capped at `limit`.
    pub fn recent_findings(&self, limit: u32) -> Result<Vec<FindingRow>, Error> {
        let mut statement = self.connection.prepare(
            "SELECT id,kind,dedupe_key,severity,data FROM findings ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = statement
            .query_map([limit], |row| {
                Ok(FindingRow {
                    id: row.get(0)?,
                    kind: row.get(1)?,
                    dedupe_key: row.get(2)?,
                    severity: row.get(3)?,
                    data: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Returns the newest events, capped at `limit`.
    pub fn recent_events(&self, limit: u32) -> Result<Vec<(String, String, i64)>, Error> {
        let mut statement = self
            .connection
            .prepare("SELECT kind,detail,created_at FROM events ORDER BY id DESC LIMIT ?1")?;
        let rows = statement
            .query_map([limit], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Deletes artifacts older than `cutoff` and returns their rows.
    pub fn prune_artifacts(&self, cutoff: i64) -> Result<Vec<ArtifactRow>, Error> {
        let rows: Vec<ArtifactRow> = {
            let mut statement = self.connection.prepare(
                "SELECT id,path,sha256,size,kind,stored,stored_at,route_tag FROM artifacts WHERE stored_at < ?1",
            )?;
            let collected = statement
                .query_map([cutoff], |row| {
                    Ok(ArtifactRow {
                        id: row.get(0)?,
                        path: row.get(1)?,
                        sha256: row.get(2)?,
                        size: row.get(3)?,
                        kind: row.get(4)?,
                        stored: row.get(5)?,
                        stored_at: row.get(6)?,
                        route_tag: row.get(7)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            collected
        };
        self.connection
            .execute("DELETE FROM artifacts WHERE stored_at < ?1", [cutoff])?;
        Ok(rows)
    }

    /// Records a published module version.
    pub fn record_mod(&self, id: &str, version: &str, metadata: &str) -> Result<(), Error> {
        self.connection.execute(
            "INSERT INTO mods(id,version,enabled,metadata) VALUES (?1,?2,1,?3)
             ON CONFLICT(id,version) DO UPDATE SET metadata=excluded.metadata, enabled=1",
            params![id, version, metadata],
        )?;
        Ok(())
    }

    /// Returns the stored per-agent encryption key.
    pub fn agent_enc_key(&self, route_tag: &[u8]) -> Result<Option<[u8; 32]>, Error> {
        match self.connection.query_row(
            "SELECT enc_key FROM agents WHERE route_tag=?1",
            [route_tag],
            |row| row.get::<_, Option<Vec<u8>>>(0),
        ) {
            Ok(Some(bytes)) => Ok(bytes.try_into().ok()),
            Ok(None) | Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Sets the revoked flag for a route tag.
    pub fn set_revoked(&self, route_tag: &[u8], revoked: bool) -> Result<bool, Error> {
        Ok(self.connection.execute(
            "UPDATE agents SET revoked=?1 WHERE route_tag=?2",
            params![i64::from(revoked), route_tag],
        )? > 0)
    }

    /// Returns the public key for a route tag.
    pub fn agent_key(&self, route_tag: &[u8]) -> Result<Option<[u8; 32]>, Error> {
        match self.connection.query_row(
            "SELECT agent_pub FROM agents WHERE route_tag=?1",
            [route_tag],
            |row| row.get::<_, Vec<u8>>(0),
        ) {
            Ok(bytes) => Ok(bytes.try_into().ok()),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Inserts a schedule and returns its id.
    #[allow(clippy::too_many_arguments)]
    pub fn add_schedule(
        &self,
        route_tag: &[u8],
        mod_id: &str,
        version: &str,
        args: &str,
        every_s: i64,
        jitter_s: i64,
        first_at: i64,
    ) -> Result<i64, Error> {
        self.connection.execute(
            "INSERT INTO schedules(route_tag,mod_id,version,args,every_s,jitter_s,next_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![route_tag, mod_id, version, args, every_s, jitter_s, first_at],
        )?;
        Ok(self.connection.last_insert_rowid())
    }

    /// Lists schedules.
    pub fn schedules(&self) -> Result<Vec<Schedule>, Error> {
        let mut statement = self.connection.prepare(
            "SELECT id,route_tag,mod_id,version,args,every_s,jitter_s,next_at
             FROM schedules ORDER BY id",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok(Schedule {
                    id: row.get(0)?,
                    route_tag: row.get(1)?,
                    mod_id: row.get(2)?,
                    version: row.get(3)?,
                    args: row.get(4)?,
                    every_s: row.get(5)?,
                    jitter_s: row.get(6)?,
                    next_at: row.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Returns enabled schedules due at `now` for non-revoked agents.
    pub fn due_schedules(&self, now: i64) -> Result<Vec<Schedule>, Error> {
        let mut statement = self.connection.prepare(
            "SELECT s.id,s.route_tag,s.mod_id,s.version,s.args,s.every_s,s.jitter_s,s.next_at
             FROM schedules s JOIN agents a ON a.route_tag=s.route_tag
             WHERE s.enabled=1 AND s.next_at<=?1 AND a.revoked=0 ORDER BY s.next_at",
        )?;
        let rows = statement
            .query_map([now], |row| {
                Ok(Schedule {
                    id: row.get(0)?,
                    route_tag: row.get(1)?,
                    mod_id: row.get(2)?,
                    version: row.get(3)?,
                    args: row.get(4)?,
                    every_s: row.get(5)?,
                    jitter_s: row.get(6)?,
                    next_at: row.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Sets the next due time for a schedule and returns whether it existed.
    pub fn schedule_next(&self, id: i64, next_at: i64) -> Result<bool, Error> {
        Ok(self.connection.execute(
            "UPDATE schedules SET next_at=?1 WHERE id=?2",
            params![next_at, id],
        )? > 0)
    }

    /// Removes a schedule.
    pub fn remove_schedule(&self, id: i64) -> Result<bool, Error> {
        Ok(self
            .connection
            .execute("DELETE FROM schedules WHERE id=?1", [id])?
            > 0)
    }

    /// Returns the stored cursor for a relay.
    pub fn relay_cursor(&self, relay_id: &[u8]) -> Result<u64, Error> {
        match self.connection.query_row(
            "SELECT cursor FROM relay_cursors WHERE relay_id=?1",
            [relay_id],
            |row| row.get::<_, i64>(0),
        ) {
            Ok(value) => Ok(value.max(0) as u64),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
            Err(error) => Err(error.into()),
        }
    }

    /// Stores a relay cursor.
    pub fn set_relay_cursor(&self, relay_id: &[u8], cursor: u64) -> Result<(), Error> {
        self.connection.execute(
            "INSERT INTO relay_cursors(relay_id,cursor) VALUES (?1,?2)
             ON CONFLICT(relay_id) DO UPDATE SET cursor=excluded.cursor",
            params![relay_id, cursor as i64],
        )?;
        Ok(())
    }

    /// Returns the stored stdout for a result row.
    pub fn result_stdout(&self, result_id: i64) -> Result<String, Error> {
        Ok(self.connection.query_row(
            "SELECT stdout FROM results WHERE id=?1",
            [result_id],
            |row| row.get(0),
        )?)
    }

    /// Records a malformed or untrusted input as an event without aborting a batch.
    pub fn record_event(&self, kind: &str, detail: &str) -> Result<(), Error> {
        self.connection.execute(
            "INSERT INTO events(kind,detail,created_at) VALUES (?1,?2,?3)",
            params![kind, detail, now()],
        )?;
        Ok(())
    }

    /// Validates and stores module findings for a result. Results remain stored on rejection.
    pub fn extract_findings(
        &mut self,
        result_id: i64,
        findings: &[FindingInput],
    ) -> Result<Vec<FindingOutcome>, Error> {
        let tx = self.connection.transaction()?;
        let mut outcomes = Vec::with_capacity(findings.len());
        for finding in findings {
            let outcome = if !FINDING_KINDS.contains(&finding.kind.as_str()) {
                FindingOutcome::Rejected(format!("unknown kind: {}", finding.kind))
            } else if finding.dedupe_key.trim().is_empty() {
                FindingOutcome::Rejected("missing dedupe_key".into())
            } else if finding.severity < 0 {
                FindingOutcome::Rejected("severity must be non-negative".into())
            } else {
                let existing = tx
                    .query_row(
                        "SELECT severity FROM findings WHERE kind=?1 AND dedupe_key=?2",
                        params![finding.kind, finding.dedupe_key],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()?;
                if let Some(previous) = existing {
                    if finding.severity > previous {
                        tx.execute("UPDATE findings SET severity=?1,data=?2,result_id=?3 WHERE kind=?4 AND dedupe_key=?5", params![finding.severity, finding.data, result_id, finding.kind, finding.dedupe_key])?;
                    }
                    FindingOutcome::Raised
                } else {
                    tx.execute("INSERT INTO findings(kind,dedupe_key,severity,data,result_id,created_at) VALUES (?1,?2,?3,?4,?5,?6)", params![finding.kind, finding.dedupe_key, finding.severity, finding.data, result_id, now()])?;
                    FindingOutcome::Stored
                }
            };
            if let FindingOutcome::Rejected(reason) = &outcome {
                tx.execute(
                    "INSERT INTO events(kind,detail,created_at) VALUES ('finding_rejected',?1,?2)",
                    params![reason, now()],
                )?;
            }
            outcomes.push(outcome);
        }
        tx.commit()?;
        Ok(outcomes)
    }

    /// Searches indexed findings using FTS5 MATCH syntax and returns TSV rows.
    pub fn query_findings(&self, query: &str) -> Result<Vec<FindingRow>, Error> {
        let mut statement = self.connection.prepare("SELECT f.id,f.kind,f.dedupe_key,f.severity,f.data FROM findings_fts JOIN findings f ON f.id=findings_fts.rowid WHERE findings_fts MATCH ?1 ORDER BY f.id")?;
        let rows = statement
            .query_map([query], |row| {
                Ok(FindingRow {
                    id: row.get(0)?,
                    kind: row.get(1)?,
                    dedupe_key: row.get(2)?,
                    severity: row.get(3)?,
                    data: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Exports findings as JSON, NDJSON, or RFC 4180 CSV to a writer.
    pub fn export_findings(&self, format: &str, output: &mut impl Write) -> Result<u64, Error> {
        let mut statement = self
            .connection
            .prepare("SELECT id,kind,dedupe_key,severity,data FROM findings ORDER BY id")?;
        let mut rows = statement.query([])?;
        let mut count = 0;
        if format == "csv" {
            output.write_all(b"id,kind,dedupe_key,severity,data\r\n")?;
        }
        if format == "json" {
            output.write_all(b"[")?;
        }
        while let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            let kind: String = row.get(1)?;
            let key: String = row.get(2)?;
            let severity: i64 = row.get(3)?;
            let data: String = row.get(4)?;
            if count > 0 && format == "json" {
                output.write_all(b",")?;
            }
            match format {
                "json" => write!(
                    output,
                    "{{\"id\":{},\"kind\":{},\"dedupe_key\":{},\"severity\":{},\"data\":{}}}",
                    id,
                    json_quote(&kind),
                    json_quote(&key),
                    severity,
                    json_quote(&data)
                )?,
                "ndjson" => writeln!(
                    output,
                    "{{\"id\":{},\"kind\":{},\"dedupe_key\":{},\"severity\":{},\"data\":{}}}",
                    id,
                    json_quote(&kind),
                    json_quote(&key),
                    severity,
                    json_quote(&data)
                )?,
                "csv" => writeln!(
                    output,
                    "{},{},{},{},{}",
                    id,
                    csv_quote(&kind),
                    csv_quote(&key),
                    severity,
                    csv_quote(&data)
                )?,
                other => {
                    return Err(Error::InvalidInput(format!(
                        "unknown export format: {other}"
                    )))
                }
            }
            count += 1;
        }
        if format == "json" {
            output.write_all(b"]")?;
        }
        Ok(count)
    }

    /// Returns table counts.
    pub fn stats(&self) -> Result<Stats, Error> {
        let count = |table: &str| -> Result<u64, rusqlite::Error> {
            self.connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    let value: i64 = row.get(0)?;
                    Ok(u64::try_from(value).unwrap_or(0))
                })
        };
        Ok(Stats {
            agents: count("agents")?,
            results: count("results")?,
            findings: count("findings")?,
            events: count("events")?,
        })
    }

    /// Removes at most 10,000 findings older than the cutoff epoch seconds.
    pub fn prune(&self, cutoff: i64) -> Result<u64, Error> {
        let changed = self.connection.execute("DELETE FROM findings WHERE id IN (SELECT id FROM findings WHERE created_at < ?1 ORDER BY id LIMIT 10000)", [cutoff])?;
        Ok(changed as u64)
    }

    /// Runs SQLite vacuum after checkpointing the WAL.
    pub fn vacuum(&self) -> Result<(), Error> {
        self.connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;")?;
        Ok(())
    }

    /// Creates a consistent backup using SQLite VACUUM INTO.
    pub fn backup(&self, destination: impl AsRef<Path>) -> Result<(), Error> {
        let destination = destination.as_ref();
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let canonical_parent = fs::canonicalize(parent)?;
        let candidate = destination
            .canonicalize()
            .unwrap_or_else(|_| destination.to_path_buf());
        if candidate == canonical_parent || candidate.starts_with(&canonical_parent) {
            return Err(Error::InvalidInput(
                "backup destination must not be the state directory or one of its children".into(),
            ));
        }
        if let Ok(meta) = fs::metadata(self.path.with_extension("db-wal")) {
            if meta.len() > 64 * 1024 * 1024 {
                return Err(Error::InvalidInput(
                    "WAL exceeds 64 MiB; checkpoint before backup".into(),
                ));
            }
        }
        let escaped = destination.to_string_lossy().replace('\'', "''");
        self.connection
            .execute_batch(&format!("VACUUM INTO '{}';", escaped))?;
        set_private_mode(destination)?;
        Ok(())
    }

    /// Returns a raw connection for coordinator-only advanced queries.
    pub fn connection(&self) -> &Connection {
        &self.connection
    }
}

fn apply_key(connection: &Connection, key: &[u8; 32]) -> Result<(), Error> {
    let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
    connection.execute_batch(&format!(
        "PRAGMA key = \"x'{hex}'\"; PRAGMA cipher_memory_security = ON;"
    ))?;
    // Force key validation now rather than at the first real query.
    connection.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
        row.get::<_, i64>(0)
    })?;
    Ok(())
}

/// Returns whether `path` looks like an encrypted (non-plaintext) database.
pub fn is_encrypted(path: &Path) -> bool {
    match fs::read(path) {
        Ok(bytes) => bytes.len() >= 16 && &bytes[..16] != b"SQLite format 3\0",
        Err(_) => false,
    }
}

/// Migrates a plaintext database to SQLCipher under `key`, replacing it.
pub fn encrypt_file(path: &Path, key: &[u8; 32]) -> Result<(), Error> {
    if is_encrypted(path) {
        return Ok(());
    }
    let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
    let temporary = path.with_extension("enc");
    let _ = fs::remove_file(&temporary);
    let connection = Connection::open(path)?;
    connection.pragma_update(None, "wal_checkpoint", "FULL")?;
    connection.execute_batch(&format!(
        "ATTACH DATABASE '{}' AS enc KEY \"x'{hex}'\";
         SELECT sqlcipher_export('enc');
         DETACH DATABASE enc;",
        temporary.display()
    ))?;
    drop(connection);
    for suffix in ["-wal", "-shm"] {
        let _ = fs::remove_file(format!("{}{suffix}", path.display()));
    }
    fs::rename(&temporary, path)?;
    set_private_mode(path)?;
    Ok(())
}

fn migrate(connection: &Connection) -> Result<(), Error> {
    let version: i32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(Error::InvalidInput(format!(
            "database version {version} is newer than supported"
        )));
    }
    if version == 0 {
        let tx = connection.unchecked_transaction()?;
        tx.execute_batch(SCHEMA)?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tx.commit()?;
    } else if version == 1 {
        let tx = connection.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_2)?;
        tx.pragma_update(None, "user_version", 2)?;
        tx.execute_batch(MIGRATION_3)?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tx.commit()?;
    } else if version == 2 {
        let tx = connection.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_3)?;
        tx.pragma_update(None, "user_version", 3)?;
        tx.execute_batch(MIGRATION_4)?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tx.commit()?;
    } else if version == 3 {
        let tx = connection.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_4)?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tx.commit()?;
    }
    Ok(())
}

const MIGRATION_2: &str = r#"
ALTER TABLE agents ADD COLUMN last_seen INTEGER NOT NULL DEFAULT 0;
ALTER TABLE agents ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS schedules(id INTEGER PRIMARY KEY, route_tag BLOB NOT NULL, mod_id TEXT NOT NULL, version TEXT NOT NULL, args TEXT NOT NULL DEFAULT '{}', every_s INTEGER NOT NULL, jitter_s INTEGER NOT NULL DEFAULT 0, next_at INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, last_result_at INTEGER);
CREATE INDEX IF NOT EXISTS schedules_due ON schedules(enabled, next_at);
CREATE TABLE IF NOT EXISTS relay_cursors(relay_id BLOB PRIMARY KEY, cursor INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS artifacts(id INTEGER PRIMARY KEY, agent_pub BLOB NOT NULL, route_tag BLOB NOT NULL, path TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL, kind TEXT NOT NULL, stored TEXT NOT NULL, stored_at INTEGER NOT NULL, UNIQUE(agent_pub, sha256));
CREATE INDEX IF NOT EXISTS artifacts_seen ON artifacts(stored_at);
"#;

const MIGRATION_3: &str = r#"
CREATE TABLE IF NOT EXISTS artifacts(id INTEGER PRIMARY KEY, agent_pub BLOB NOT NULL, route_tag BLOB NOT NULL, path TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL, kind TEXT NOT NULL, stored TEXT NOT NULL, stored_at INTEGER NOT NULL, UNIQUE(agent_pub, sha256));
CREATE INDEX IF NOT EXISTS artifacts_seen ON artifacts(stored_at);
"#;

const MIGRATION_4: &str = r#"
ALTER TABLE agents ADD COLUMN enc_key BLOB;
"#;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS agents(agent_pub BLOB PRIMARY KEY, route_tag BLOB NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0, enc_key BLOB);
CREATE TABLE IF NOT EXISTS tasks(id INTEGER PRIMARY KEY, task_epoch INTEGER NOT NULL, agent_pub BLOB NOT NULL, body BLOB);
CREATE TABLE IF NOT EXISTS results(id INTEGER PRIMARY KEY, task_epoch INTEGER NOT NULL, agent_pub BLOB NOT NULL, ok INTEGER NOT NULL, stdout TEXT NOT NULL, stderr TEXT NOT NULL, code INTEGER NOT NULL, received_at INTEGER NOT NULL, UNIQUE(task_epoch, agent_pub));
CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, dedupe_key TEXT NOT NULL, severity INTEGER NOT NULL, data TEXT NOT NULL, result_id INTEGER NOT NULL, created_at INTEGER NOT NULL, UNIQUE(kind,dedupe_key));
CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5(kind,dedupe_key,data,content='findings',content_rowid='id');
CREATE TABLE IF NOT EXISTS mods(id TEXT NOT NULL, version TEXT NOT NULL, enabled INTEGER NOT NULL, metadata TEXT NOT NULL DEFAULT '', PRIMARY KEY(id,version));
CREATE TABLE IF NOT EXISTS relays(id BLOB PRIMARY KEY, kind TEXT NOT NULL, address TEXT NOT NULL, tier INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, detail TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS schedules(id INTEGER PRIMARY KEY, route_tag BLOB NOT NULL, mod_id TEXT NOT NULL, version TEXT NOT NULL, args TEXT NOT NULL DEFAULT '{}', every_s INTEGER NOT NULL, jitter_s INTEGER NOT NULL DEFAULT 0, next_at INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, last_result_at INTEGER);
CREATE INDEX IF NOT EXISTS schedules_due ON schedules(enabled, next_at);
CREATE TABLE IF NOT EXISTS relay_cursors(relay_id BLOB PRIMARY KEY, cursor INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS artifacts(id INTEGER PRIMARY KEY, agent_pub BLOB NOT NULL, route_tag BLOB NOT NULL, path TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL, kind TEXT NOT NULL, stored TEXT NOT NULL, stored_at INTEGER NOT NULL, UNIQUE(agent_pub, sha256));
CREATE INDEX IF NOT EXISTS artifacts_seen ON artifacts(stored_at);
CREATE TRIGGER IF NOT EXISTS findings_ai AFTER INSERT ON findings BEGIN INSERT INTO findings_fts(rowid,kind,dedupe_key,data) VALUES (new.id,new.kind,new.dedupe_key,new.data); END;
CREATE TRIGGER IF NOT EXISTS findings_ad AFTER DELETE ON findings BEGIN INSERT INTO findings_fts(findings_fts,rowid,kind,dedupe_key,data) VALUES ('delete',old.id,old.kind,old.dedupe_key,old.data); END;
CREATE TRIGGER IF NOT EXISTS findings_au AFTER UPDATE ON findings BEGIN INSERT INTO findings_fts(findings_fts,rowid,kind,dedupe_key,data) VALUES ('delete',old.id,old.kind,old.dedupe_key,old.data); INSERT INTO findings_fts(rowid,kind,dedupe_key,data) VALUES (new.id,new.kind,new.dedupe_key,new.data); END;
"#;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64)
}
fn set_private_mode(path: &Path) -> Result<(), Error> {
    #[cfg(not(unix))]
    let _ = path;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path.exists() {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}
fn json_quote(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(output, "\\u{:04x}", c as u32);
            }
            c => output.push(c),
        }
    }
    output.push('"');
    output
}
fn csv_quote(value: &str) -> String {
    if value.contains([',', '"', '\r', '\n']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("agent-fleet-{name}-{}.db", std::process::id()))
    }
    fn open(name: &str) -> Database {
        let path = temp_path(name);
        let _ = fs::remove_file(&path);
        Database::open(path).expect("database opens")
    }
    fn result() -> VerifiedResult {
        let key = [7_u8; 32];
        VerifiedResult {
            agent_pub: key,
            route_tag: [1; 8],
            result: ResultMessage {
                task_epoch: 1,
                agent_pub: key,
                ok: true,
                stdout: "out".into(),
                stderr: String::new(),
                code: 0,
            },
        }
    }
    #[test]
    fn fresh_init_creates_v4() {
        let db = open("fresh");
        let version: i32 = db
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("version");
        assert_eq!(version, 4);
    }

    #[test]
    fn v1_database_migrates_agents_and_schedules() {
        let path = temp_path("migrate-v1");
        let _ = fs::remove_file(&path);
        {
            let connection = Connection::open(&path).expect("v1");
            connection
                .execute_batch(
                    "CREATE TABLE agents(agent_pub BLOB PRIMARY KEY, route_tag BLOB NOT NULL, first_seen INTEGER NOT NULL);
                     CREATE TABLE events(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, detail TEXT NOT NULL, created_at INTEGER NOT NULL);
                     PRAGMA user_version=1;",
                )
                .expect("v1 schema");
        }
        let db = Database::open(&path).expect("migrates");
        let version: i32 = db
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("version");
        assert_eq!(version, 4);
        let columns: Vec<String> = db
            .connection
            .prepare("PRAGMA table_info(agents)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        assert!(columns.contains(&"last_seen".to_string()));
        assert!(columns.contains(&"revoked".to_string()));
        db.connection
            .query_row("SELECT COUNT(*) FROM schedules", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("schedules table");
    }
    #[test]
    fn encryption_migrates_and_hides_the_file() {
        let path = temp_path("encrypted");
        let _ = fs::remove_file(&path);
        let mut db = Database::open(&path).expect("plaintext");
        db.ingest(&[result()]).expect("seed");
        drop(db);
        let key = [9_u8; 32];
        encrypt_file(&path, &key).expect("migrate");
        assert!(is_encrypted(&path));
        // A keyless open cannot read it.
        let raw = Connection::open(&path).expect("raw open");
        assert!(raw
            .query_row("SELECT COUNT(*) FROM sqlite_master", [], |row| row
                .get::<_, i64>(0))
            .is_err());
        drop(raw);
        let db = Database::open_encrypted(&path, &key).expect("encrypted open");
        assert_eq!(db.stats().expect("stats").results, 1);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn ingest_is_idempotent() {
        let mut db = open("idempotent");
        let item = result();
        assert_eq!(db.ingest(std::slice::from_ref(&item)).expect("insert"), 1);
        assert_eq!(db.ingest(&[item]).expect("duplicate"), 0);
        assert_eq!(db.stats().expect("stats").results, 1);
    }
    #[test]
    fn finding_fts_and_delete_trigger_stay_synced() {
        let mut db = open("fts");
        db.ingest(&[result()]).expect("result");
        let outcome = db
            .extract_findings(
                1,
                &[FindingInput {
                    kind: "security".into(),
                    dedupe_key: "a".into(),
                    severity: 2,
                    data: "needle".into(),
                }],
            )
            .expect("finding");
        assert_eq!(outcome, vec![FindingOutcome::Stored]);
        assert_eq!(db.query_findings("needle").expect("query").len(), 1);
        db.prune(i64::MAX).expect("prune");
        assert!(db
            .query_findings("needle")
            .expect("query after delete")
            .is_empty());
    }
    #[test]
    fn export_quotes_csv_and_json() {
        let mut db = open("export");
        db.ingest(&[result()]).expect("result");
        db.extract_findings(
            1,
            &[FindingInput {
                kind: "health".into(),
                dedupe_key: "k,\n".into(),
                severity: 1,
                data: "a\"b".into(),
            }],
        )
        .expect("finding");
        let mut csv = Cursor::new(Vec::new());
        db.export_findings("csv", &mut csv).expect("csv");
        assert!(String::from_utf8(csv.into_inner())
            .expect("utf8")
            .contains("\"k,\n\""));
    }
}
