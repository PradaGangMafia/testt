//! Capability policy, durable module storage, and the Wasm host.
//!
//! The host implements ABI 1 as frozen in `docs/MODS.md`. Every guest pointer
//! and length is validated against linear memory before use, every capability
//! is checked at call time, and a guest can never make the host panic.

use crate::handlers::HandlerOutcome;
use msgfmt::{valid_mod_id, valid_mod_version, ModEntry, ModSet};
use rand::{rngs::OsRng, RngCore};
use serde_cbor::Value as CborValue;
use serde_json::{json, Value as JsonValue};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use thiserror::Error;

#[cfg(unix)]
use std::os::unix::process::CommandExt;

/// Capability-policy errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CapError {
    /// The requested capability is not allowed.
    #[error("capability denied: {0}")]
    Denied(String),
    /// A capability name is not known by this runtime.
    #[error("unknown capability: {0}")]
    Unknown(String),
    /// A path or host did not match its capability glob.
    #[error("capability target denied: {0}")]
    TargetDenied(String),
    /// A policy rule is syntactically invalid.
    #[error("invalid capability rule: {0}")]
    Invalid(String),
}

/// Capabilities understood by the host.
pub const KNOWN_CAPS: [&str; 9] = [
    "fs_read", "fs_write", "exec", "net", "clock", "random", "env", "sleep", "spool",
];

/// Highest module ABI this host serves.
pub const MAX_ABI: u32 = 2;

/// Validates and evaluates module capabilities against the daemon policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapabilityPolicy {
    /// Glob rules allowed by configuration.
    pub allow_caps: BTreeMap<String, Vec<String>>,
    /// Hard floor for process execution.
    pub allow_exec: bool,
    /// Hard floor for network access.
    pub allow_net: bool,
}

impl CapabilityPolicy {
    /// Validates capability names, hard floors, and rule syntax.
    pub fn validate(&self) -> Result<(), CapError> {
        for (cap, rules) in &self.allow_caps {
            if !KNOWN_CAPS.contains(&cap.as_str()) {
                return Err(CapError::Unknown(cap.clone()));
            }
            for rule in rules {
                if rule.trim().is_empty() {
                    return Err(CapError::Invalid(cap.clone()));
                }
            }
            if cap == "exec" && !self.allow_exec {
                return Err(CapError::Denied("exec".into()));
            }
            if cap == "net" && !self.allow_net {
                return Err(CapError::Denied("net".into()));
            }
        }
        Ok(())
    }

    /// Checks every requested capability and its optional target glob.
    pub fn check(&self, requested: &[String]) -> Result<(), CapError> {
        for requested_cap in requested {
            let (name, target) = requested_cap
                .split_once(':')
                .map_or((requested_cap.as_str(), "*"), |(n, t)| (n, t));
            self.check_call(name, target)?;
        }
        Ok(())
    }

    /// Checks a capability at an individual host call.
    pub fn check_call(&self, name: &str, target: &str) -> Result<(), CapError> {
        if !KNOWN_CAPS.contains(&name) {
            return Err(CapError::Unknown(name.to_owned()));
        }
        if name == "exec" && !self.allow_exec {
            return Err(CapError::Denied(name.to_owned()));
        }
        if name == "net" && !self.allow_net {
            return Err(CapError::Denied(name.to_owned()));
        }
        let rules = self
            .allow_caps
            .get(name)
            .ok_or_else(|| CapError::Denied(name.to_owned()))?;
        if rules.iter().any(|rule| glob_matches(rule, target)) {
            Ok(())
        } else {
            Err(CapError::TargetDenied(target.to_owned()))
        }
    }
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.replace('\\', "/");
    let value = value.replace('\\', "/");
    let (mut p, mut v, mut star, mut mark) = (0, 0, None, 0);
    let pchars: Vec<char> = pattern.chars().collect();
    let vchars: Vec<char> = value.chars().collect();
    while v < vchars.len() {
        if p < pchars.len() && (pchars[p] == '?' || pchars[p] == vchars[v]) {
            p += 1;
            v += 1;
        } else if p < pchars.len() && pchars[p] == '*' {
            star = Some(p);
            mark = v;
            p += 1;
        } else if let Some(star_pos) = star {
            p = star_pos + 1;
            mark += 1;
            v = mark;
        } else {
            return false;
        }
    }
    while p < pchars.len() && pchars[p] == '*' {
        p += 1;
    }
    p == pchars.len()
}

/// Persistent module store errors.
#[derive(Debug, Error)]
pub enum ModError {
    /// Filesystem failure.
    #[error("module storage: {0}")]
    Io(#[from] io::Error),
    /// Module bytes did not match the advertised digest or size.
    #[error("module hash or size mismatch")]
    HashMismatch,
    /// The module ABI is not supported.
    #[error("unsupported module ABI: {0}")]
    Abi(u32),
    /// A requested capability is not allowed.
    #[error("module capability: {0}")]
    Capability(#[from] CapError),
    /// The module set generation is stale.
    #[error("stale module generation")]
    StaleGeneration,
    /// The module set exceeds configured limits.
    #[error("module set limit exceeded")]
    Limit,
    /// The module entry names an invalid identifier or version.
    #[error("invalid module identity: {0}@{1}")]
    InvalidIdentity(String, String),
    /// The module bytes could not be parsed as WebAssembly.
    #[error("invalid module binary: {0}")]
    Wasm(String),
    /// The module imports a name the host does not define.
    #[error("unknown module import: {0}")]
    UnknownImport(String),
    /// The module imports a function that only exists in ABI 2.
    #[error("import requires ABI 2: {0}")]
    AbiImport(String),
    /// The module imports a capability its entry did not declare.
    #[error("undeclared module capability: {0}")]
    UndeclaredCapability(String),
}

/// Immutable installed module metadata and bytes.
#[derive(Debug, Clone)]
pub struct InstalledMod {
    /// Advertised module entry.
    pub entry: ModEntry,
    /// Installed wasm path.
    pub path: PathBuf,
}

/// Durable module-set store with atomic version directories.
#[derive(Debug)]
pub struct ModStore {
    root: PathBuf,
    generation: u64,
    mods: BTreeMap<(String, String), InstalledMod>,
}

const GENERATION_FILE: &str = "generation";
const ENTRY_FILE: &str = "entry.cbor";
const MODULE_FILE: &str = "module.wasm";
const MAX_MODULE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_MODULES: usize = 32;

impl ModStore {
    /// Opens or creates `<state>/mods` and restores every verified version.
    pub fn open(state: impl Into<PathBuf>) -> Result<Self, ModError> {
        let root = state.into();
        fs::create_dir_all(&root)?;
        let generation = read_generation(&root)?;
        let mut store = Self {
            root,
            generation,
            mods: BTreeMap::new(),
        };
        store.scan()?;
        Ok(store)
    }

    fn scan(&mut self) -> Result<(), ModError> {
        let mut ids = fs::read_dir(&self.root)?
            .filter_map(Result::ok)
            .filter(|entry| entry.path().is_dir())
            .collect::<Vec<_>>();
        ids.sort_by_key(|entry| entry.file_name());
        for id in ids {
            let id_name = id.file_name().to_string_lossy().into_owned();
            let mut versions = fs::read_dir(id.path())?
                .filter_map(Result::ok)
                .filter(|entry| entry.path().is_dir())
                .collect::<Vec<_>>();
            versions.sort_by_key(|entry| entry.file_name());
            for version in versions {
                let version_name = version.file_name().to_string_lossy().into_owned();
                let dir = version.path();
                let entry_path = dir.join(ENTRY_FILE);
                let module_path = dir.join(MODULE_FILE);
                let entry = match fs::read(&entry_path)
                    .map_err(|_| ())
                    .and_then(|bytes| decode_entry(&bytes).map_err(|_| ()))
                {
                    Ok(entry) => entry,
                    Err(()) => {
                        eprintln!(
                            "module scan: dropping {id_name}@{version_name}: missing or bad {ENTRY_FILE}"
                        );
                        continue;
                    }
                };
                if entry.id != id_name || entry.version != version_name {
                    eprintln!("module scan: dropping {id_name}@{version_name}: identity mismatch");
                    continue;
                }
                let bytes = match fs::read(&module_path) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        eprintln!("module scan: dropping {id_name}@{version_name}: missing module");
                        continue;
                    }
                };
                if bytes.len() as u64 != entry.size
                    || *blake3::hash(&bytes).as_bytes() != entry.blake3
                {
                    eprintln!("module scan: dropping {id_name}@{version_name}: digest mismatch");
                    continue;
                }
                self.mods.insert(
                    (entry.id.clone(), entry.version.clone()),
                    InstalledMod {
                        entry,
                        path: module_path,
                    },
                );
            }
        }
        Ok(())
    }

    /// Applies a newer module set after checking ABI, capabilities, size and digest.
    pub async fn apply(&mut self, set: &ModSet, policy: &CapabilityPolicy) -> Result<(), ModError> {
        if set.gen <= self.generation {
            return Err(ModError::StaleGeneration);
        }
        policy.validate()?;
        if set.add.len() + self.mods.len() > MAX_MODULES
            || set.add.iter().any(|entry| entry.size > MAX_MODULE_BYTES)
        {
            return Err(ModError::Limit);
        }
        let mut staged = Vec::new();
        for entry in &set.add {
            if !valid_mod_id(&entry.id) || !valid_mod_version(&entry.version) {
                return Err(ModError::InvalidIdentity(
                    entry.id.clone(),
                    entry.version.clone(),
                ));
            }
            if entry.abi == 0 || entry.abi > MAX_ABI {
                return Err(ModError::Abi(entry.abi));
            }
            policy.check(&entry.capabilities)?;
            let bytes = fetch_module(&entry.url).await?;
            if bytes.len() as u64 != entry.size || *blake3::hash(&bytes).as_bytes() != entry.blake3
            {
                return Err(ModError::HashMismatch);
            }
            let imports = imported_capabilities(&bytes)?;
            if entry.abi == 1 {
                if let Some(name) = imports.abi2.first() {
                    return Err(ModError::AbiImport((*name).to_owned()));
                }
            }
            let declared = entry
                .capabilities
                .iter()
                .map(|capability| capability.split(':').next().unwrap_or(capability))
                .collect::<std::collections::BTreeSet<_>>();
            for capability in imports.capabilities {
                if !declared.contains(capability) {
                    return Err(ModError::UndeclaredCapability(capability.to_owned()));
                }
            }
            let path = self.install_entry(entry, &bytes, None)?;
            staged.push(InstalledMod {
                entry: entry.clone(),
                path,
            });
        }
        for id in &set.remove {
            self.remove_entry(id);
        }
        for installed in staged {
            self.mods.insert(
                (installed.entry.id.clone(), installed.entry.version.clone()),
                installed,
            );
        }
        self.generation = set.gen;
        write_generation(&self.root, set.gen)?;
        Ok(())
    }

    fn install_entry(
        &self,
        entry: &ModEntry,
        bytes: &[u8],
        fail_at: Option<&str>,
    ) -> Result<PathBuf, ModError> {
        let dir = self.root.join(&entry.id).join(&entry.version);
        let final_path = dir.join(MODULE_FILE);
        let part_path = dir.join("module.wasm.part");
        let old_bytes = fs::read(&final_path).ok();
        // The manifest is rewritten late in the sequence. Capture it so a
        // failure after that point cannot leave new metadata against old bytes.
        let old_entry = fs::read(dir.join(ENTRY_FILE)).ok();
        let result = self.install_steps(entry, bytes, &dir, &part_path, &final_path, fail_at);
        if result.is_err() {
            if let Some(old) = old_bytes {
                let _ = fs::write(&final_path, old);
                if let Some(manifest) = old_entry {
                    let _ = fs::write(dir.join(ENTRY_FILE), manifest);
                }
            } else {
                let _ = fs::remove_dir_all(&dir);
                if let Some(parent) = dir.parent() {
                    let _ = fs::remove_dir(parent);
                }
            }
        }
        result.map(|()| final_path)
    }

    fn install_steps(
        &self,
        entry: &ModEntry,
        bytes: &[u8],
        dir: &Path,
        part_path: &Path,
        final_path: &Path,
        fail_at: Option<&str>,
    ) -> Result<(), ModError> {
        fs::create_dir_all(dir)?;
        {
            let mut file = File::create(part_path)?;
            file.write_all(bytes)?;
            file.sync_all()?;
        }
        inject(fail_at, "part")?;
        fs::rename(part_path, final_path)?;
        sync_dir(dir)?;
        if fail_at == Some("rename") {
            return Err(ModError::Io(io::Error::other("injected rename failure")));
        }
        if let Some(id_dir) = dir.parent() {
            sync_dir(id_dir)?;
        }
        let written = fs::read(final_path)?;
        if written.len() as u64 != entry.size || *blake3::hash(&written).as_bytes() != entry.blake3
        {
            return Err(ModError::HashMismatch);
        }
        inject(fail_at, "verify")?;
        let entry_bytes = encode_entry(entry);
        let entry_part = dir.join("entry.cbor.part");
        {
            let mut file = File::create(&entry_part)?;
            file.write_all(&entry_bytes)?;
            file.sync_all()?;
        }
        fs::rename(&entry_part, dir.join(ENTRY_FILE))?;
        sync_dir(dir)?;
        inject(fail_at, "entry")?;
        Ok(())
    }

    fn remove_entry(&mut self, id: &str) {
        let keys = self
            .mods
            .keys()
            .filter(|(module_id, _)| module_id == id)
            .cloned()
            .collect::<Vec<_>>();
        for key in keys {
            if let Some(installed) = self.mods.remove(&key) {
                let _ = fs::remove_dir_all(
                    installed
                        .path
                        .parent()
                        .map_or_else(|| self.root.join(id), Path::to_path_buf),
                );
            }
        }
        let _ = fs::remove_dir_all(self.root.join(id));
    }

    /// Returns an installed module only when it is enabled.
    pub fn get(&self, id: &str, version: &str) -> Option<&InstalledMod> {
        self.mods
            .get(&(id.to_owned(), version.to_owned()))
            .filter(|m| m.entry.enabled)
    }

    /// Returns every installed module, enabled or not.
    pub fn entries(&self) -> impl Iterator<Item = &InstalledMod> {
        self.mods.values()
    }

    /// Enables or disables an installed module without deleting its files.
    pub fn set_enabled(&mut self, id: &str, version: &str, enabled: bool) -> bool {
        let Some(installed) = self.mods.get_mut(&(id.to_owned(), version.to_owned())) else {
            return false;
        };
        installed.entry.enabled = enabled;
        let bytes = encode_entry(&installed.entry);
        let dir = installed
            .path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();
        let part = dir.join("entry.cbor.part");
        let written = fs::write(&part, bytes)
            .and_then(|()| fs::rename(&part, dir.join(ENTRY_FILE)))
            .and_then(|()| File::open(&dir)?.sync_all());
        written.is_ok()
    }

    /// Returns the current module generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Removes one installed version, leaving other versions untouched.
    pub fn remove(&mut self, id: &str, version: &str) -> bool {
        let Some(installed) = self.mods.remove(&(id.to_owned(), version.to_owned())) else {
            return false;
        };
        let dir = installed
            .path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();
        fs::remove_dir_all(&dir).is_ok()
    }
}

/// Imports that only exist in ABI 2.
const ABI2_IMPORTS: [&str; 5] = [
    "read_dir",
    "stat",
    "read_file_range",
    "http_post",
    "spool_put",
];

struct Imports {
    capabilities: Vec<&'static str>,
    abi2: Vec<&'static str>,
}

fn imported_capabilities(wasm: &[u8]) -> Result<Imports, ModError> {
    let engine = wasmi::Engine::default();
    let module =
        wasmi::Module::new(&engine, wasm).map_err(|error| ModError::Wasm(error.to_string()))?;
    let mut capabilities = Vec::new();
    let mut abi2 = Vec::new();
    for import in module.imports() {
        if import.module() != "env" {
            return Err(ModError::UnknownImport(format!(
                "{}::{}",
                import.module(),
                import.name()
            )));
        }
        let capability = match import.name() {
            "log" | "result" => None,
            "read_file" | "read_dir" | "stat" | "read_file_range" => Some("fs_read"),
            "write_file" => Some("fs_write"),
            "exec" => Some("exec"),
            "http_get" | "http_post" => Some("net"),
            "spool_put" => Some("spool"),
            "clock_ms" => Some("clock"),
            "random" => Some("random"),
            "env_get" => Some("env"),
            "sleep_ms" => Some("sleep"),
            other => return Err(ModError::UnknownImport(format!("env::{other}"))),
        };
        if let Some(name) = ABI2_IMPORTS
            .iter()
            .copied()
            .find(|name| *name == import.name())
        {
            abi2.push(name);
        }
        if let Some(capability) = capability {
            if !capabilities.contains(&capability) {
                capabilities.push(capability);
            }
        }
    }
    Ok(Imports { capabilities, abi2 })
}

fn inject(fail_at: Option<&str>, step: &str) -> Result<(), ModError> {
    if fail_at == Some(step) {
        Err(ModError::Io(io::Error::other(format!(
            "injected {step} failure"
        ))))
    } else {
        Ok(())
    }
}

fn sync_dir(path: &Path) -> Result<(), ModError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn read_generation(root: &Path) -> Result<u64, ModError> {
    let path = root.join(GENERATION_FILE);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    let mut lines = text.lines();
    let decimal = lines.next().unwrap_or_default().trim();
    let digest = lines.next().unwrap_or_default().trim();
    let Ok(generation) = decimal.parse::<u64>() else {
        eprintln!("module store: corrupt generation file, treating as 0");
        return Ok(0);
    };
    let expected = format!("blake3:{}", blake3::hash(decimal.as_bytes()).to_hex());
    if digest != expected {
        eprintln!("module store: corrupt generation file, treating as 0");
        return Ok(0);
    }
    Ok(generation)
}

fn write_generation(root: &Path, generation: u64) -> Result<(), ModError> {
    let decimal = generation.to_string();
    let contents = format!(
        "{decimal}\nblake3:{}\n",
        blake3::hash(decimal.as_bytes()).to_hex()
    );
    let part = root.join("generation.part");
    {
        let mut file = File::create(&part)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
    }
    fs::rename(&part, root.join(GENERATION_FILE))?;
    sync_dir(root)?;
    Ok(())
}

async fn fetch_module(url: &str) -> Result<Vec<u8>, ModError> {
    if let Some(path) = url.strip_prefix("file://") {
        let bytes = tokio::fs::read(path).await?;
        if bytes.len() as u64 > MAX_MODULE_BYTES {
            return Err(ModError::Limit);
        }
        return Ok(bytes);
    }
    let response = reqwest::get(url).await.map_err(io::Error::other)?;
    if !response.status().is_success() {
        return Err(ModError::Io(io::Error::other(format!(
            "HTTP {}",
            response.status()
        ))));
    }
    let bytes = response.bytes().await.map_err(io::Error::other)?;
    if bytes.len() as u64 > MAX_MODULE_BYTES {
        return Err(ModError::Limit);
    }
    Ok(bytes.to_vec())
}

fn encode_entry(entry: &ModEntry) -> Vec<u8> {
    let mut map = BTreeMap::new();
    map.insert(
        CborValue::Text("abi".into()),
        CborValue::Integer(i128::from(entry.abi)),
    );
    map.insert(
        CborValue::Text("blake3".into()),
        CborValue::Bytes(entry.blake3.to_vec()),
    );
    map.insert(
        CborValue::Text("capabilities".into()),
        CborValue::Array(
            entry
                .capabilities
                .iter()
                .cloned()
                .map(CborValue::Text)
                .collect(),
        ),
    );
    map.insert(
        CborValue::Text("enabled".into()),
        CborValue::Bool(entry.enabled),
    );
    map.insert(
        CborValue::Text("id".into()),
        CborValue::Text(entry.id.clone()),
    );
    map.insert(
        CborValue::Text("size".into()),
        CborValue::Integer(i128::from(entry.size)),
    );
    map.insert(
        CborValue::Text("url".into()),
        CborValue::Text(entry.url.clone()),
    );
    map.insert(
        CborValue::Text("version".into()),
        CborValue::Text(entry.version.clone()),
    );
    serde_cbor::to_vec(&CborValue::Map(map)).unwrap_or_default()
}

fn decode_entry(bytes: &[u8]) -> Result<ModEntry, ModError> {
    let CborValue::Map(map) = serde_cbor::from_slice(bytes).map_err(|_| ModError::HashMismatch)?
    else {
        return Err(ModError::HashMismatch);
    };
    let text = |key: &str| match map.get(&CborValue::Text(key.into())) {
        Some(CborValue::Text(value)) => Ok(value.clone()),
        _ => Err(ModError::HashMismatch),
    };
    let integer = |key: &str| match map.get(&CborValue::Text(key.into())) {
        Some(CborValue::Integer(value)) => Ok(*value),
        _ => Err(ModError::HashMismatch),
    };
    let CborValue::Bytes(hash) = map
        .get(&CborValue::Text("blake3".into()))
        .ok_or(ModError::HashMismatch)?
    else {
        return Err(ModError::HashMismatch);
    };
    let blake3: [u8; 32] = hash
        .as_slice()
        .try_into()
        .map_err(|_| ModError::HashMismatch)?;
    let CborValue::Array(caps) = map
        .get(&CborValue::Text("capabilities".into()))
        .ok_or(ModError::HashMismatch)?
    else {
        return Err(ModError::HashMismatch);
    };
    let capabilities = caps
        .iter()
        .map(|value| match value {
            CborValue::Text(value) => Ok(value.clone()),
            _ => Err(ModError::HashMismatch),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let enabled = match map.get(&CborValue::Text("enabled".into())) {
        Some(CborValue::Bool(value)) => *value,
        _ => return Err(ModError::HashMismatch),
    };
    Ok(ModEntry {
        id: text("id")?,
        version: text("version")?,
        abi: u32::try_from(integer("abi")?).map_err(|_| ModError::HashMismatch)?,
        blake3,
        size: u64::try_from(integer("size")?).map_err(|_| ModError::HashMismatch)?,
        url: text("url")?,
        capabilities,
        enabled,
    })
}

/// Wasmi host errors.
#[derive(Debug, Error)]
pub enum WasmError {
    /// Module bytes failed to compile or instantiate.
    #[error("wasm error: {0}")]
    Wasm(String),
    /// Capability was denied.
    #[error(transparent)]
    Capability(#[from] CapError),
    /// Fuel, timeout, or memory limit was hit.
    #[error("wasm limit exceeded: {0}")]
    Limit(&'static str),
}

/// Execution limits for one module invocation.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Fuel budget.
    pub fuel: u64,
    /// Maximum linear memory.
    pub memory_bytes: usize,
    /// Wall-clock deadline.
    pub deadline: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            fuel: 50_000_000,
            memory_bytes: 32 * 1024 * 1024,
            deadline: Duration::from_secs(30),
        }
    }
}

const HOST_DENIED: i64 = -1;
const HOST_ERROR: i64 = -2;
const MAX_GUEST_IO: usize = 1024 * 1024;
const MAX_STDOUT: usize = 64 * 1024;
const MAX_DIR_ENTRIES: usize = 2048;
const MAX_SPOOL_BYTES: u64 = 512 * 1024 * 1024;

/// Minimal JSON-argument Wasmi host. Each run creates a fresh store and instance.
pub struct WasmHost {
    policy: CapabilityPolicy,
    limits: Limits,
    state: std::path::PathBuf,
}

impl WasmHost {
    /// Creates a host with policy, default limits, and a temporary spool root.
    pub fn new(policy: CapabilityPolicy) -> Result<Self, CapError> {
        Self::with_state(std::env::temp_dir().join("agent-fleet-spool"), policy)
    }

    /// Creates a host whose artifact spool lives under `state`.
    pub fn with_state(
        state: impl Into<std::path::PathBuf>,
        policy: CapabilityPolicy,
    ) -> Result<Self, CapError> {
        policy.validate()?;
        Ok(Self {
            policy,
            limits: Limits::default(),
            state: state.into(),
        })
    }

    /// Overrides execution limits.
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Returns the policy this host enforces.
    pub fn policy(&self) -> &CapabilityPolicy {
        &self.policy
    }

    /// Executes a module's exported `handle` function and returns its result.
    pub async fn run(&self, wasm: &[u8], args: &JsonValue) -> Result<HandlerOutcome, WasmError> {
        self.run_logged(wasm, args)
            .await
            .map(|(outcome, _logs)| outcome)
    }

    /// Executes a module and returns both its result and host-side log lines.
    pub async fn run_logged(
        &self,
        wasm: &[u8],
        args: &JsonValue,
    ) -> Result<(HandlerOutcome, Vec<String>), WasmError> {
        let wasm = wasm.to_vec();
        let args = serde_json::to_vec(args).map_err(|e| WasmError::Wasm(e.to_string()))?;
        let policy = self.policy.clone();
        let limits = self.limits;
        let state = self.state.clone();
        tokio::task::spawn_blocking(move || run_wasm(&wasm, &args, &policy, limits, &state))
            .await
            .map_err(|e| WasmError::Wasm(e.to_string()))?
    }
}

/// Converts wire-level CBOR arguments into the JSON form the ABI delivers.
pub fn cbor_to_json(value: &CborValue) -> Result<JsonValue, String> {
    match value {
        CborValue::Null => Ok(JsonValue::Null),
        CborValue::Bool(value) => Ok(JsonValue::Bool(*value)),
        CborValue::Integer(value) => i64::try_from(*value)
            .map(JsonValue::from)
            .map_err(|_| "args not JSON-representable".into()),
        CborValue::Float(value) => serde_json::Number::from_f64(*value)
            .map(JsonValue::Number)
            .ok_or_else(|| "args not JSON-representable".into()),
        CborValue::Text(value) => Ok(JsonValue::String(value.clone())),
        CborValue::Bytes(_) => Err("args not JSON-representable".into()),
        CborValue::Array(values) => values
            .iter()
            .map(cbor_to_json)
            .collect::<Result<Vec<_>, _>>()
            .map(JsonValue::Array),
        CborValue::Map(values) => {
            let mut map = serde_json::Map::new();
            for (key, value) in values {
                let CborValue::Text(key) = key else {
                    return Err("args not JSON-representable".into());
                };
                map.insert(key.clone(), cbor_to_json(value)?);
            }
            Ok(JsonValue::Object(map))
        }
        _ => Err("args not JSON-representable".into()),
    }
}

struct HostStatus {
    result: Option<HandlerOutcome>,
    result_calls: u32,
    logs: Vec<String>,
    policy: CapabilityPolicy,
    state: std::path::PathBuf,
    limiter: HostLimiter,
}

struct HostLimiter {
    limit: usize,
    hit: bool,
}

impl wasmi::ResourceLimiter for HostLimiter {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> Result<bool, wasmi::errors::MemoryError> {
        if desired > self.limit {
            self.hit = true;
            Ok(false)
        } else {
            Ok(true)
        }
    }

    fn table_growing(
        &mut self,
        _current: u32,
        _desired: u32,
        _maximum: Option<u32>,
    ) -> Result<bool, wasmi::errors::TableError> {
        Ok(true)
    }
}

fn run_wasm(
    wasm: &[u8],
    args: &[u8],
    policy: &CapabilityPolicy,
    limits: Limits,
    state: &std::path::Path,
) -> Result<(HandlerOutcome, Vec<String>), WasmError> {
    use wasmi::{Config, Engine, Linker, Module, Store};

    let mut config = Config::default();
    config.consume_fuel(true);
    let engine = Engine::new(&config);
    let module = Module::new(&engine, wasm).map_err(|e| WasmError::Wasm(e.to_string()))?;
    let deadline_hit = Arc::new(AtomicBool::new(false));
    let mut store = Store::new(
        &engine,
        HostStatus {
            result: None,
            result_calls: 0,
            logs: Vec::new(),
            policy: policy.clone(),
            state: state.to_path_buf(),
            limiter: HostLimiter {
                limit: limits.memory_bytes,
                hit: false,
            },
        },
    );
    store.limiter(|state| &mut state.limiter);
    store
        .add_fuel(limits.fuel)
        .map_err(|e| WasmError::Wasm(e.to_string()))?;

    let mut linker = Linker::new(&engine);
    link_imports(&mut linker)?;
    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| WasmError::Wasm(e.to_string()))?
        .start(&mut store)
        .map_err(|e| WasmError::Wasm(e.to_string()))?;

    let memory = instance
        .get_memory(&store, "memory")
        .ok_or_else(|| WasmError::Wasm("missing export: memory".into()))?;
    let alloc = instance
        .get_typed_func::<i32, i32>(&store, "alloc")
        .map_err(|_| WasmError::Wasm("missing export: alloc".into()))?;
    let dealloc = instance
        .get_typed_func::<(i32, i32), ()>(&store, "dealloc")
        .ok();
    let handle = instance
        .get_typed_func::<(i32, i32), i32>(&store, "handle")
        .map_err(|_| WasmError::Wasm("missing export: handle".into()))?;

    let mut arg_ptr = 0;
    let mut arg_len = 0;
    if !args.is_empty() {
        match alloc.call(&mut store, args.len() as i32) {
            Ok(ptr) if ptr > 0 => {
                if memory.write(&mut store, ptr as usize, args).is_err() {
                    return Ok(failed("guest allocation failed", -1, Vec::new()));
                }
                arg_ptr = ptr;
                arg_len = args.len() as i32;
            }
            _ => return Ok(failed("guest allocation failed", -1, Vec::new())),
        }
    }

    let started = Instant::now();
    let (finished, finished_rx) = std::sync::mpsc::channel();
    let watchdog = {
        let deadline_hit = Arc::clone(&deadline_hit);
        let deadline = limits.deadline;
        std::thread::spawn(move || {
            if deadline.is_zero() {
                deadline_hit.store(true, Ordering::SeqCst);
                return;
            }
            if finished_rx.recv_timeout(deadline).is_err() {
                deadline_hit.store(true, Ordering::SeqCst);
            }
        })
    };
    let call = handle.call(&mut store, (arg_ptr, arg_len));
    if let Some(dealloc) = dealloc {
        let _ = dealloc.call(&mut store, (arg_ptr, arg_len));
    }
    let _ = finished.send(());
    let _ = watchdog.join();
    let elapsed = started.elapsed();

    let limiter_hit = store.data().limiter.hit;
    let outcome = match call {
        Ok(code) => {
            let status = store.data_mut();
            let mut outcome = status.result.take().unwrap_or(HandlerOutcome {
                ok: code == 0,
                stdout: String::new(),
                stderr: if code == 0 {
                    String::new()
                } else {
                    "module returned nonzero".into()
                },
                code,
            });
            if code != 0 {
                outcome.ok = false;
                if outcome.stderr.is_empty() {
                    outcome.stderr = "module returned nonzero".into();
                }
            }
            outcome
        }
        Err(error) => {
            let text = error.to_string();
            if deadline_hit.load(Ordering::SeqCst) || elapsed >= limits.deadline {
                HandlerOutcome {
                    ok: false,
                    stdout: String::new(),
                    stderr: "deadline".into(),
                    code: -3,
                }
            } else if text.to_ascii_lowercase().contains("fuel") {
                HandlerOutcome {
                    ok: false,
                    stdout: String::new(),
                    stderr: "fuel".into(),
                    code: -2,
                }
            } else {
                HandlerOutcome {
                    ok: false,
                    stdout: String::new(),
                    stderr: format!("trap: {text}"),
                    code: -1,
                }
            }
        }
    };
    if limiter_hit {
        return Ok(failed("memory limit", -4, Vec::new()));
    }
    let logs = store.data().logs.clone();
    Ok((outcome, logs))
}

fn failed(stderr: &str, code: i32, logs: Vec<String>) -> (HandlerOutcome, Vec<String>) {
    (
        HandlerOutcome {
            ok: false,
            stdout: String::new(),
            stderr: stderr.to_owned(),
            code,
        },
        logs,
    )
}

fn link_imports(linker: &mut wasmi::Linker<HostStatus>) -> Result<(), WasmError> {
    linker
        .func_wrap(
            "env",
            "log",
            |mut caller: wasmi::Caller<'_, HostStatus>, ptr: i32, len: i32| {
                let text = read_guest(&caller, ptr, len)?;
                caller
                    .data_mut()
                    .logs
                    .push(String::from_utf8_lossy(&text).into_owned());
                Ok::<(), wasmi::core::Trap>(())
            },
        )
        .map_err(|e| WasmError::Wasm(e.to_string()))?;
    linker
        .func_wrap(
            "env",
            "read_file",
            |mut caller: wasmi::Caller<'_, HostStatus>,
             ptr: i32,
             len: i32|
             -> Result<i64, wasmi::core::Trap> {
                let path = read_text(&caller, ptr, len)?;
                if let Err(error) = caller.data().policy.check_call("fs_read", &path) {
                    caller
                        .data_mut()
                        .logs
                        .push(format!("denied fs_read: {error}"));
                    return Ok(HOST_DENIED);
                }
                let bytes = match read_capped(Path::new(&path), MAX_GUEST_IO) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        caller.data_mut().logs.push(format!("read_file: {error}"));
                        return Ok(HOST_ERROR);
                    }
                };
                return_bytes(&mut caller, &bytes)
            },
        )
        .map_err(|e| WasmError::Wasm(e.to_string()))?;
    linker
        .func_wrap(
            "env",
            "read_dir",
            |mut caller: wasmi::Caller<'_, HostStatus>,
             ptr: i32,
             len: i32|
             -> Result<i64, wasmi::core::Trap> {
                let path = read_text(&caller, ptr, len)?;
                if let Err(error) = caller.data().policy.check_call("fs_read", &path) {
                    caller
                        .data_mut()
                        .logs
                        .push(format!("denied fs_read: {error}"));
                    return Ok(HOST_DENIED);
                }
                match list_dir(Path::new(&path)) {
                    Ok(bytes) => return_bytes(&mut caller, &bytes),
                    Err(error) => {
                        caller.data_mut().logs.push(format!("read_dir: {error}"));
                        Ok(HOST_ERROR)
                    }
                }
            },
        )
        .map_err(|e| WasmError::Wasm(e.to_string()))?;
    linker
        .func_wrap(
            "env",
            "stat",
            |mut caller: wasmi::Caller<'_, HostStatus>,
             ptr: i32,
             len: i32|
             -> Result<i64, wasmi::core::Trap> {
                let path = read_text(&caller, ptr, len)?;
                if let Err(error) = caller.data().policy.check_call("fs_read", &path) {
                    caller
                        .data_mut()
                        .logs
                        .push(format!("denied fs_read: {error}"));
                    return Ok(HOST_DENIED);
                }
                match stat_file(Path::new(&path)) {
                    Ok(bytes) => return_bytes(&mut caller, &bytes),
                    Err(error) => {
                        caller.data_mut().logs.push(format!("stat: {error}"));
                        Ok(HOST_ERROR)
                    }
                }
            },
        )
        .map_err(|e| WasmError::Wasm(e.to_string()))?;
    linker
        .func_wrap(
            "env",
            "read_file_range",
            |mut caller: wasmi::Caller<'_, HostStatus>,
             ptr: i32,
             len: i32,
             offset: i64,
             want: i64|
             -> Result<i64, wasmi::core::Trap> {
                let path = read_text(&caller, ptr, len)?;
                if let Err(error) = caller.data().policy.check_call("fs_read", &path) {
                    caller
                        .data_mut()
                        .logs
                        .push(format!("denied fs_read: {error}"));
                    return Ok(HOST_DENIED);
                }
                let offset = u64::try_from(offset).unwrap_or(0);
                let want = usize::try_from(want)
                    .unwrap_or(MAX_GUEST_IO)
                    .min(MAX_GUEST_IO);
                match read_range(Path::new(&path), offset, want) {
                    Ok(bytes) => return_bytes(&mut caller, &bytes),
                    Err(error) => {
                        caller
                            .data_mut()
                            .logs
                            .push(format!("read_file_range: {error}"));
                        Ok(HOST_ERROR)
                    }
                }
            },
        )
        .map_err(|e| WasmError::Wasm(e.to_string()))?;
    linker
        .func_wrap(
            "env",
            "write_file",
            |mut caller: wasmi::Caller<'_, HostStatus>,
             path_ptr: i32,
             path_len: i32,
             data_ptr: i32,
             data_len: i32|
             -> Result<i32, wasmi::core::Trap> {
                let path = read_text(&caller, path_ptr, path_len)?;
                let data = read_guest(&caller, data_ptr, data_len)?;
                if let Err(error) = caller.data().policy.check_call("fs_write", &path) {
                    caller
                        .data_mut()
                        .logs
                        .push(format!("denied fs_write: {error}"));
                    return Ok(HOST_DENIED as i32);
                }
                match write_capped(Path::new(&path), &data) {
                    Ok(()) => Ok(0),
                    Err(error) => {
                        caller.data_mut().logs.push(format!("write_file: {error}"));
                        Ok(HOST_ERROR as i32)
                    }
                }
            },
        )
        .map_err(|e| WasmError::Wasm(e.to_string()))?;
    linker
        .func_wrap(
            "env",
            "exec",
            |mut caller: wasmi::Caller<'_, HostStatus>,
             cmd_ptr: i32,
             cmd_len: i32,
             args_ptr: i32,
             args_len: i32|
             -> Result<i64, wasmi::core::Trap> {
                let command = read_text(&caller, cmd_ptr, cmd_len)?;
                let raw_args = read_guest(&caller, args_ptr, args_len)?;
                if let Err(error) = caller.data().policy.check_call("exec", &command) {
                    caller.data_mut().logs.push(format!("denied exec: {error}"));
                    return Ok(HOST_DENIED);
                }
                let args = if raw_args.is_empty() {
                    Vec::new()
                } else {
                    match serde_json::from_slice::<Vec<String>>(&raw_args) {
                        Ok(args) => args,
                        Err(error) => {
                            caller.data_mut().logs.push(format!("exec args: {error}"));
                            return Ok(HOST_ERROR);
                        }
                    }
                };
                match run_bounded(&command, &args) {
                    Ok(output) => return_bytes(&mut caller, &output),
                    Err(error) => {
                        caller.data_mut().logs.push(format!("exec: {error}"));
                        Ok(HOST_ERROR)
                    }
                }
            },
        )
        .map_err(|e| WasmError::Wasm(e.to_string()))?;
    linker
        .func_wrap(
            "env",
            "http_get",
            |mut caller: wasmi::Caller<'_, HostStatus>,
             ptr: i32,
             len: i32|
             -> Result<i64, wasmi::core::Trap> {
                let url = read_text(&caller, ptr, len)?;
                if let Err(error) = caller.data().policy.check_call("net", &url) {
                    caller.data_mut().logs.push(format!("denied net: {error}"));
                    return Ok(HOST_DENIED);
                }
                match http_get_bounded(&url) {
                    Ok(bytes) => return_bytes(&mut caller, &bytes),
                    Err(error) => {
                        caller.data_mut().logs.push(format!("http_get: {error}"));
                        Ok(HOST_ERROR)
                    }
                }
            },
        )
        .map_err(|e| WasmError::Wasm(e.to_string()))?;
    linker
        .func_wrap(
            "env",
            "http_post",
            |mut caller: wasmi::Caller<'_, HostStatus>,
             ptr: i32,
             len: i32,
             body_ptr: i32,
             body_len: i32|
             -> Result<i64, wasmi::core::Trap> {
                let url = read_text(&caller, ptr, len)?;
                let body = read_guest(&caller, body_ptr, body_len)?;
                if body.len() > MAX_GUEST_IO {
                    caller
                        .data_mut()
                        .logs
                        .push("http_post: body exceeds 1 MiB".into());
                    return Ok(HOST_ERROR);
                }
                if let Err(error) = caller.data().policy.check_call("net", &url) {
                    caller.data_mut().logs.push(format!("denied net: {error}"));
                    return Ok(HOST_DENIED);
                }
                match http_post_bounded(&url, &body) {
                    Ok(bytes) => return_bytes(&mut caller, &bytes),
                    Err(error) => {
                        caller.data_mut().logs.push(format!("http_post: {error}"));
                        Ok(HOST_ERROR)
                    }
                }
            },
        )
        .map_err(|e| WasmError::Wasm(e.to_string()))?;
    linker
        .func_wrap(
            "env",
            "spool_put",
            |mut caller: wasmi::Caller<'_, HostStatus>,
             path_ptr: i32,
             path_len: i32,
             kind_ptr: i32,
             kind_len: i32,
             data_ptr: i32,
             data_len: i32|
             -> Result<i64, wasmi::core::Trap> {
                let path = read_text(&caller, path_ptr, path_len)?;
                let kind = read_text(&caller, kind_ptr, kind_len)?;
                let data = read_guest(&caller, data_ptr, data_len)?;
                if let Err(error) = caller.data().policy.check_call("spool", &path) {
                    caller
                        .data_mut()
                        .logs
                        .push(format!("denied spool: {error}"));
                    return Ok(HOST_DENIED);
                }
                if data.len() > MAX_GUEST_IO {
                    caller
                        .data_mut()
                        .logs
                        .push("spool_put: body exceeds 1 MiB".into());
                    return Ok(HOST_ERROR);
                }
                let state = caller.data().state.clone();
                match spool_put(&state, &path, &kind, &data) {
                    Ok(id) => Ok(id),
                    Err(error) => {
                        caller.data_mut().logs.push(format!("spool_put: {error}"));
                        Ok(HOST_ERROR)
                    }
                }
            },
        )
        .map_err(|e| WasmError::Wasm(e.to_string()))?;
    linker
        .func_wrap(
            "env",
            "clock_ms",
            |mut caller: wasmi::Caller<'_, HostStatus>| -> Result<i64, wasmi::core::Trap> {
                if let Err(error) = caller.data().policy.check_call("clock", "*") {
                    caller
                        .data_mut()
                        .logs
                        .push(format!("denied clock: {error}"));
                    return Ok(HOST_DENIED);
                }
                let millis = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |duration| duration.as_millis());
                Ok(i64::try_from(millis).unwrap_or(i64::MAX))
            },
        )
        .map_err(|e| WasmError::Wasm(e.to_string()))?;
    linker
        .func_wrap(
            "env",
            "random",
            |mut caller: wasmi::Caller<'_, HostStatus>,
             ptr: i32,
             len: i32|
             -> Result<i32, wasmi::core::Trap> {
                if let Err(error) = caller.data().policy.check_call("random", "*") {
                    caller
                        .data_mut()
                        .logs
                        .push(format!("denied random: {error}"));
                    return Ok(HOST_DENIED as i32);
                }
                let len = usize::try_from(len).map_err(|_| wasmi::core::Trap::new("oob write"))?;
                if len > MAX_GUEST_IO {
                    return Ok(HOST_ERROR as i32);
                }
                let mut bytes = vec![0_u8; len];
                OsRng.fill_bytes(&mut bytes);
                write_guest(&mut caller, ptr, &bytes)?;
                Ok(0)
            },
        )
        .map_err(|e| WasmError::Wasm(e.to_string()))?;
    linker
        .func_wrap(
            "env",
            "env_get",
            |mut caller: wasmi::Caller<'_, HostStatus>,
             ptr: i32,
             len: i32|
             -> Result<i64, wasmi::core::Trap> {
                let key = read_text(&caller, ptr, len)?;
                if let Err(error) = caller.data().policy.check_call("env", &key) {
                    caller.data_mut().logs.push(format!("denied env: {error}"));
                    return Ok(HOST_DENIED);
                }
                match std::env::var(&key) {
                    Ok(value) => return_bytes(&mut caller, value.as_bytes()),
                    Err(std::env::VarError::NotPresent) => Ok(0),
                    Err(error) => {
                        caller.data_mut().logs.push(format!("env_get: {error}"));
                        Ok(HOST_ERROR)
                    }
                }
            },
        )
        .map_err(|e| WasmError::Wasm(e.to_string()))?;
    linker
        .func_wrap(
            "env",
            "sleep_ms",
            |mut caller: wasmi::Caller<'_, HostStatus>,
             millis: i64|
             -> Result<i32, wasmi::core::Trap> {
                if let Err(error) = caller.data().policy.check_call("sleep", "*") {
                    caller
                        .data_mut()
                        .logs
                        .push(format!("denied sleep: {error}"));
                    return Ok(HOST_DENIED as i32);
                }
                let millis = millis.clamp(0, 5000) as u64;
                std::thread::sleep(Duration::from_millis(millis));
                Ok(0)
            },
        )
        .map_err(|e| WasmError::Wasm(e.to_string()))?;
    linker
        .func_wrap(
            "env",
            "result",
            |mut caller: wasmi::Caller<'_, HostStatus>,
             ptr: i32,
             len: i32|
             -> Result<(), wasmi::core::Trap> {
                let bytes = read_guest(&caller, ptr, len)?;
                let status = caller.data_mut();
                status.result_calls = status.result_calls.saturating_add(1);
                if status.result_calls > 1 {
                    status.logs.push("module result replaced".into());
                }
                status.result = Some(parse_result(&bytes));
                Ok(())
            },
        )
        .map_err(|e| WasmError::Wasm(e.to_string()))?;
    Ok(())
}

fn parse_result(bytes: &[u8]) -> HandlerOutcome {
    let value: JsonValue = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(_) => {
            let raw = String::from_utf8_lossy(&bytes[..bytes.len().min(1024)]).into_owned();
            return HandlerOutcome {
                ok: false,
                stdout: String::new(),
                stderr: format!("malformed module result: {raw}"),
                code: -1,
            };
        }
    };
    let ok = value
        .get("ok")
        .and_then(JsonValue::as_bool)
        .unwrap_or(false);
    let stdout = value
        .get("stdout")
        .and_then(JsonValue::as_str)
        .unwrap_or_default()
        .to_owned();
    let stderr = value
        .get("stderr")
        .and_then(JsonValue::as_str)
        .unwrap_or_default()
        .to_owned();
    let code = value
        .get("code")
        .and_then(JsonValue::as_i64)
        .and_then(|code| i32::try_from(code).ok())
        .unwrap_or(-1);
    let (stdout, truncated) = truncate_text(stdout, MAX_STDOUT);
    HandlerOutcome {
        ok: ok && code == 0 && !truncated,
        stdout,
        stderr,
        code,
    }
}

fn truncate_text(text: String, limit: usize) -> (String, bool) {
    if text.len() <= limit {
        return (text, false);
    }
    let mut end = limit;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut truncated = text[..end].to_owned();
    truncated.push_str("...");
    (truncated, true)
}

fn memory_of(caller: &wasmi::Caller<'_, HostStatus>) -> Result<wasmi::Memory, wasmi::core::Trap> {
    caller
        .get_export("memory")
        .and_then(wasmi::Extern::into_memory)
        .ok_or_else(|| wasmi::core::Trap::new("missing export: memory"))
}

fn check_range(
    caller: &wasmi::Caller<'_, HostStatus>,
    ptr: i32,
    len: i32,
) -> Result<usize, wasmi::core::Trap> {
    let memory = memory_of(caller)?;
    let ptr = usize::try_from(ptr).map_err(|_| wasmi::core::Trap::new("oob read"))?;
    let len = usize::try_from(len).map_err(|_| wasmi::core::Trap::new("oob read"))?;
    let end = ptr
        .checked_add(len)
        .ok_or_else(|| wasmi::core::Trap::new("oob read"))?;
    if end > memory.data(caller).len() {
        return Err(wasmi::core::Trap::new("oob read"));
    }
    Ok(ptr)
}

fn read_guest(
    caller: &wasmi::Caller<'_, HostStatus>,
    ptr: i32,
    len: i32,
) -> Result<Vec<u8>, wasmi::core::Trap> {
    let ptr = check_range(caller, ptr, len)?;
    let len = usize::try_from(len).map_err(|_| wasmi::core::Trap::new("oob read"))?;
    let memory = memory_of(caller)?;
    let data = memory.data(caller);
    Ok(data[ptr..ptr + len].to_vec())
}

fn read_text(
    caller: &wasmi::Caller<'_, HostStatus>,
    ptr: i32,
    len: i32,
) -> Result<String, wasmi::core::Trap> {
    Ok(String::from_utf8_lossy(&read_guest(caller, ptr, len)?).into_owned())
}

fn write_guest(
    caller: &mut wasmi::Caller<'_, HostStatus>,
    ptr: i32,
    bytes: &[u8],
) -> Result<(), wasmi::core::Trap> {
    let ptr = check_range(caller, ptr, bytes.len() as i32)?;
    let memory = memory_of(caller)?;
    memory
        .write(caller, ptr, bytes)
        .map_err(|_| wasmi::core::Trap::new("oob write"))
}

fn return_bytes(
    caller: &mut wasmi::Caller<'_, HostStatus>,
    bytes: &[u8],
) -> Result<i64, wasmi::core::Trap> {
    if bytes.is_empty() {
        return Ok(0);
    }
    let alloc = caller
        .get_export("alloc")
        .and_then(wasmi::Extern::into_func)
        .ok_or_else(|| wasmi::core::Trap::new("missing export: alloc"))?
        .typed::<i32, i32>(&*caller)
        .map_err(|_| wasmi::core::Trap::new("missing export: alloc"))?;
    let ptr = alloc
        .call(&mut *caller, bytes.len() as i32)
        .map_err(|_| wasmi::core::Trap::new("guest allocation failed"))?;
    if ptr <= 0 {
        return Ok(HOST_ERROR);
    }
    write_guest(caller, ptr, bytes)?;
    Ok(pack(ptr, bytes.len()))
}

fn pack(ptr: i32, len: usize) -> i64 {
    (i64::from(ptr) << 32) | (len as i64 & 0xffff_ffff)
}

fn read_capped(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut limited = file.take(limit as u64);
    let mut bytes = Vec::with_capacity(limit.min(4096));
    limited.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn write_capped(path: &Path, data: &[u8]) -> io::Result<()> {
    if data.len() > MAX_GUEST_IO {
        return Err(io::Error::other("guest output exceeds 1 MiB"));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, data)
}

/// Lists a directory as a JSON array bounded by `MAX_DIR_ENTRIES`.
///
/// Symlinks are reported, never followed, so a walk cannot loop.
fn list_dir(dir: &Path) -> io::Result<Vec<u8>> {
    let mut items = Vec::new();
    for entry in fs::read_dir(dir)? {
        if items.len() >= MAX_DIR_ENTRIES {
            break;
        }
        let entry = entry?;
        let meta = entry.path().symlink_metadata()?;
        let kind = if meta.file_type().is_symlink() {
            "link"
        } else if meta.is_dir() {
            "dir"
        } else if meta.is_file() {
            "file"
        } else {
            "other"
        };
        items.push(json!({
            "name": entry.file_name().to_string_lossy(),
            "kind": kind,
            "size": if meta.is_file() { meta.len() } else { 0 },
        }));
    }
    items.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    serde_json::to_vec(&items).map_err(io::Error::other)
}

/// Returns JSON metadata for one path without following a symlink.
fn stat_file(path: &Path) -> io::Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    let kind = if meta.file_type().is_symlink() {
        "link"
    } else if meta.is_dir() {
        "dir"
    } else if meta.is_file() {
        "file"
    } else {
        "other"
    };
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode()
    };
    #[cfg(not(unix))]
    let mode = 0_u32;
    serde_json::to_vec(&json!({
        "kind": kind,
        "size": meta.len(),
        "mode": mode,
    }))
    .map_err(io::Error::other)
}

/// Reads up to `want` bytes starting at `offset`, capped at `MAX_GUEST_IO`.
fn read_range(path: &Path, offset: u64, want: usize) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut bytes = Vec::with_capacity(want.min(MAX_GUEST_IO));
    file.take(want.min(MAX_GUEST_IO) as u64)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Appends an artifact to the state SQLite spool and prunes the oldest 10% when
/// the spool exceeds `MAX_SPOOL_BYTES`.
fn spool_put(state: &Path, path: &str, kind: &str, data: &[u8]) -> io::Result<i64> {
    use rusqlite::params;
    fs::create_dir_all(state)?;
    let connection =
        rusqlite::Connection::open(state.join("spool.db")).map_err(io::Error::other)?;
    connection
        .execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS artifacts(
                 id INTEGER PRIMARY KEY,
                 path TEXT NOT NULL,
                 sha256 TEXT NOT NULL,
                 size INTEGER NOT NULL,
                 kind TEXT NOT NULL,
                 captured_at INTEGER NOT NULL,
                 data BLOB NOT NULL
             );
             CREATE INDEX IF NOT EXISTS artifacts_path ON artifacts(path);",
        )
        .map_err(io::Error::other)?;
    let digest = Sha256::digest(data);
    let hash = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0);
    connection
        .execute(
            "INSERT INTO artifacts(path, sha256, size, kind, captured_at, data)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![path, hash, data.len() as i64, kind, now, data],
        )
        .map_err(io::Error::other)?;
    let id = connection.last_insert_rowid();
    let total: i64 = connection
        .query_row("SELECT COALESCE(SUM(size), 0) FROM artifacts", [], |row| {
            row.get(0)
        })
        .map_err(io::Error::other)?;
    if total as u64 > MAX_SPOOL_BYTES {
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM artifacts", [], |row| row.get(0))
            .map_err(io::Error::other)?;
        connection
            .execute(
                "DELETE FROM artifacts WHERE id IN
                 (SELECT id FROM artifacts ORDER BY id LIMIT ?1)",
                [((count / 10).max(1))],
            )
            .map_err(io::Error::other)?;
    }
    Ok(id)
}

fn run_bounded(command: &str, args: &[String]) -> io::Result<Vec<u8>> {
    let mut child = Command::new(command);
    child
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(unix)]
    child.process_group(0);
    let mut child = child.spawn()?;
    let pgid = child.id();
    crate::handlers::register_process_group(pgid);
    let _guard = ActiveGroup(pgid);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output()?;
    let mut stdout = output.stdout;
    if stdout.len() > MAX_GUEST_IO {
        stdout.truncate(MAX_GUEST_IO);
    }
    Ok(stdout)
}

struct ActiveGroup(u32);

impl Drop for ActiveGroup {
    fn drop(&mut self) {
        crate::handlers::unregister_process_group(self.0);
    }
}

fn http_post_bounded(url: &str, body: &[u8]) -> Result<Vec<u8>, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| error.to_string())?;
    let response = client
        .post(url)
        .body(body.to_vec())
        .send()
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()));
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_GUEST_IO as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    Ok(bytes)
}

fn http_get_bounded(url: &str) -> Result<Vec<u8>, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| error.to_string())?;
    let response = client.get(url).send().map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()));
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_GUEST_IO as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("agentd-plugins-{name}-{}", std::process::id()))
    }

    fn entry(id: &str, bytes: &[u8]) -> ModEntry {
        ModEntry {
            id: id.into(),
            version: "1".into(),
            abi: 1,
            blake3: *blake3::hash(bytes).as_bytes(),
            size: bytes.len() as u64,
            url: String::new(),
            capabilities: Vec::new(),
            enabled: true,
        }
    }

    #[test]
    fn glob_matching_is_literal_and_wildcard_aware() {
        assert!(glob_matches("/tmp/*", "/tmp/a"));
        assert!(!glob_matches("/tmp/*", "/var/a"));
        assert!(glob_matches("/etc/**", "/etc/a/b"));
    }

    #[test]
    fn capability_policy_enforces_hard_exec_floor() {
        let policy = CapabilityPolicy {
            allow_exec: false,
            allow_caps: BTreeMap::from([(String::from("exec"), vec![String::from("*")])]),
            ..Default::default()
        };
        assert_eq!(
            policy.check(&[String::from("exec:echo")]),
            Err(CapError::Denied("exec".into()))
        );
    }

    #[test]
    fn policy_validation_rejects_unknown_and_empty_rules() {
        let unknown = CapabilityPolicy {
            allow_caps: BTreeMap::from([("nope".into(), vec!["*".into()])]),
            ..Default::default()
        };
        assert_eq!(unknown.validate(), Err(CapError::Unknown("nope".into())));
        let empty = CapabilityPolicy {
            allow_caps: BTreeMap::from([("clock".into(), vec![String::new()])]),
            ..Default::default()
        };
        assert_eq!(empty.validate(), Err(CapError::Invalid("clock".into())));
    }

    #[test]
    fn store_survives_restart_and_generation_round_trips() {
        let root = temp("restart");
        let _ = fs::remove_dir_all(&root);
        let store = ModStore::open(&root).expect("store opens");
        assert_eq!(store.generation(), 0);
        let bytes = b"module-bytes";
        let installed = entry("demo", bytes);
        store
            .install_entry(&installed, bytes, None)
            .expect("install");
        write_generation(&root, 4).expect("generation");
        drop(store);
        let store = ModStore::open(&root).expect("reopen");
        assert_eq!(store.generation(), 4);
        assert!(store.get("demo", "1").is_some());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn failed_install_leaves_no_directory() {
        let root = temp("rollback");
        let _ = fs::remove_dir_all(&root);
        let store = ModStore::open(&root).expect("store");
        let bytes = b"module-bytes";
        let installed = entry("demo", bytes);
        assert!(store
            .install_entry(&installed, bytes, Some("verify"))
            .is_err());
        assert!(!root.join("demo").join("1").exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn failed_upgrade_keeps_previous_bytes() {
        let root = temp("upgrade");
        let _ = fs::remove_dir_all(&root);
        let store = ModStore::open(&root).expect("store");
        let old = b"old-bytes";
        let installed = entry("demo", old);
        let path = store.install_entry(&installed, old, None).expect("install");
        let new = b"new-bytes";
        assert!(store
            .install_entry(&installed, new, Some("verify"))
            .is_err());
        assert_eq!(fs::read(&path).expect("old bytes"), old);
        let _ = fs::remove_dir_all(root);
    }

    const INSTALL_STEPS: [&str; 4] = ["part", "rename", "verify", "entry"];

    #[test]
    fn install_failure_at_each_step_leaves_no_partial_version() {
        for step in INSTALL_STEPS {
            let root = temp(&format!("fresh-{step}"));
            let _ = fs::remove_dir_all(&root);
            let store = ModStore::open(&root).expect("store");
            let bytes = b"module-bytes";
            let installed = entry("demo", bytes);
            assert!(
                store.install_entry(&installed, bytes, Some(step)).is_err(),
                "{step} should fail"
            );
            assert!(
                !root.join("demo").join("1").exists(),
                "{step} left a partial version directory"
            );
            let reopened = ModStore::open(&root).expect("reopen");
            assert!(reopened.get("demo", "1").is_none(), "{step}");
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn failed_upgrade_at_each_step_keeps_previous_version_verified() {
        for step in INSTALL_STEPS {
            let root = temp(&format!("upgrade-{step}"));
            let _ = fs::remove_dir_all(&root);
            let store = ModStore::open(&root).expect("store");
            let old = b"old-bytes";
            let old_entry = entry("demo", old);
            store
                .install_entry(&old_entry, old, None)
                .expect("install old");
            write_generation(&root, 1).expect("generation");
            let new = b"new-bytes";
            let new_entry = entry("demo", new);
            assert!(
                store.install_entry(&new_entry, new, Some(step)).is_err(),
                "{step} should fail"
            );
            let reopened = ModStore::open(&root).expect("reopen");
            let installed = reopened.get("demo", "1").expect("old version enabled");
            assert_eq!(
                fs::read(&installed.path).expect("old bytes"),
                old,
                "{step} left bytes that disagree with the manifest"
            );
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn truncated_module_is_dropped_on_open() {
        let root = temp("truncated");
        let _ = fs::remove_dir_all(&root);
        let store = ModStore::open(&root).expect("store");
        let bytes = b"complete-module-bytes";
        let installed = entry("demo", bytes);
        let path = store
            .install_entry(&installed, bytes, None)
            .expect("install");
        fs::write(&path, &bytes[..4]).expect("truncate");
        drop(store);
        let reopened = ModStore::open(&root).expect("open survives truncation");
        assert!(reopened.get("demo", "1").is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn corrupt_generation_file_reports_zero() {
        for contents in ["not-a-number\n", "3\nblake3:deadbeef\n"] {
            let root = temp("generation");
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).expect("root");
            fs::write(root.join(GENERATION_FILE), contents).expect("corrupt");
            let store = ModStore::open(&root).expect("open survives corruption");
            assert_eq!(store.generation(), 0, "{contents:?}");
            let _ = fs::remove_dir_all(root);
        }
    }

    #[tokio::test]
    async fn replayed_module_set_is_stale_after_restart() {
        let root = temp("stale");
        let _ = fs::remove_dir_all(&root);
        let store = ModStore::open(&root).expect("store");
        write_generation(&root, 7).expect("generation");
        drop(store);
        let mut store = ModStore::open(&root).expect("reopen");
        assert_eq!(store.generation(), 7);
        let set = msgfmt::ModSet {
            gen: 7,
            add: Vec::new(),
            remove: Vec::new(),
        };
        assert!(matches!(
            store.apply(&set, &CapabilityPolicy::default()).await,
            Err(ModError::StaleGeneration)
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn parse_result_keeps_64k_stdout_and_bounds_malformed_input() {
        let exact = "x".repeat(MAX_STDOUT);
        let payload = serde_json::json!({
            "ok": true, "stdout": exact, "stderr": "", "code": 0
        });
        let outcome = parse_result(payload.to_string().as_bytes());
        assert!(outcome.ok);
        assert_eq!(outcome.stdout.len(), MAX_STDOUT);
        assert!(!outcome.stdout.ends_with("..."));

        let more = "y".repeat(MAX_STDOUT + 32);
        let payload = serde_json::json!({
            "ok": true, "stdout": more, "stderr": "", "code": 0
        });
        let outcome = parse_result(payload.to_string().as_bytes());
        assert!(!outcome.ok);
        assert!(outcome.stdout.ends_with("..."));
        assert_eq!(outcome.stdout.len(), MAX_STDOUT + 3);

        let malformed = "z".repeat(4096);
        let outcome = parse_result(malformed.as_bytes());
        assert_eq!(outcome.code, -1);
        assert!(outcome.stderr.starts_with("malformed module result: "));
        assert_eq!(
            outcome.stderr.len(),
            "malformed module result: ".len() + 1024
        );
    }

    #[test]
    fn non_string_cbor_keys_are_not_json_representable() {
        let map = CborValue::Map(std::collections::BTreeMap::from([(
            CborValue::Integer(1),
            CborValue::Text("value".into()),
        )]));
        assert_eq!(
            cbor_to_json(&map),
            Err("args not JSON-representable".into())
        );
        assert_eq!(
            cbor_to_json(&CborValue::Bytes(vec![1, 2, 3])),
            Err("args not JSON-representable".into())
        );
    }
}
