//! Uploads spooled artifacts to the coordinator and removes acknowledged rows.
//!
//! One row (at most 1 MiB, enforced by the spool) per request, SHA-256 checked on
//! both sides. Four rows per cycle so a large spool drains gradually.

use std::path::Path;

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::Connection;
use serde::Serialize;

/// Upload result.
#[derive(Debug, Default, Clone, Copy, Serialize)]
pub struct UploadReport {
    /// Rows accepted and deleted.
    pub uploaded: usize,
    /// Rows that failed and stay queued.
    pub failed: usize,
    /// Rows still in the spool.
    pub remaining: usize,
}

/// Uploads up to `limit` pending artifacts to `base`.
pub fn upload_pending(
    state: &Path,
    base: &str,
    tag: &[u8; 8],
    signing: &SigningKey,
    token: Option<&str>,
    limit: usize,
) -> Result<UploadReport, String> {
    let path = state.join("spool.db");
    if !path.is_file() {
        return Ok(UploadReport::default());
    }
    let tag_hex = tag
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let connection = Connection::open(&path).map_err(|error| error.to_string())?;
    let rows: Vec<(i64, String, String, String, Vec<u8>)> = {
        let mut statement = connection
            .prepare("SELECT id,path,sha256,kind,data FROM artifacts ORDER BY id LIMIT ?1")
            .map_err(|error| error.to_string())?;
        let mapped = statement
            .query_map([limit as i64], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        mapped.filter_map(Result::ok).collect::<Vec<_>>()
    };
    let remaining = |connection: &Connection| -> usize {
        connection
            .query_row("SELECT COUNT(*) FROM artifacts", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap_or(0) as usize
    };
    if rows.is_empty() {
        return Ok(UploadReport {
            remaining: remaining(&connection),
            ..UploadReport::default()
        });
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|error| error.to_string())?;
    let mut report = UploadReport::default();
    for (id, source, sha, kind, data) in rows {
        let url = format!("{}/artifact/{tag_hex}", base.trim_end_matches('/'));
        // Authenticate with the agent key: the coordinator verifies against the
        // key stored for this route tag, so no shared upload secret is needed.
        let signature = signing.sign(format!("{sha}:{tag_hex}").as_bytes());
        let mut request = client
            .post(url)
            .header(
                "x-path",
                base64::engine::general_purpose::STANDARD.encode(source.as_bytes()),
            )
            .header("x-sha256", &sha)
            .header("x-kind", &kind)
            .header(
                "x-signature",
                base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
            )
            .body(data);
        if let Some(token) = token {
            request = request.header("x-token", token);
        }
        match request.send() {
            Ok(response) if response.status().is_success() => {
                connection
                    .execute("DELETE FROM artifacts WHERE id=?1", [id])
                    .map_err(|error| error.to_string())?;
                report.uploaded += 1;
            }
            _ => report.failed += 1,
        }
    }
    report.remaining = remaining(&connection);
    Ok(report)
}
