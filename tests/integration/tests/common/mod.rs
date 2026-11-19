//! Module-store and host helpers shared by the plugin acceptance tests.

#![allow(dead_code)]

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use agentd::plugins::{CapabilityPolicy, ModStore, WasmHost};
use msgfmt::{ModEntry, ModSet};

static NEXT_SOURCE: AtomicU64 = AtomicU64::new(0);

/// Builds a policy from `(capability, rule)` pairs and the two hard floors.
pub fn policy(rules: &[(&str, &str)], allow_exec: bool, allow_net: bool) -> CapabilityPolicy {
    let mut allow_caps: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (cap, rule) in rules {
        allow_caps
            .entry((*cap).to_owned())
            .or_default()
            .push((*rule).to_owned());
    }
    CapabilityPolicy {
        allow_caps,
        allow_exec,
        allow_net,
    }
}

/// A module entry and the on-disk source used by `ModStore::apply`.
pub struct Staged {
    /// Entry advertised to the store.
    pub entry: ModEntry,
    /// Local `file://` source path.
    pub source: PathBuf,
}

/// Writes `bytes` to a fresh source file and builds a matching entry.
pub fn stage(dir: &Path, id: &str, version: &str, bytes: &[u8], caps: &[&str]) -> Staged {
    stage_abi(dir, 1, id, version, bytes, caps)
}

/// As [`stage`], with an explicit ABI.
pub fn stage_abi(
    dir: &Path,
    abi: u32,
    id: &str,
    version: &str,
    bytes: &[u8],
    caps: &[&str],
) -> Staged {
    let source = dir.join(format!(
        "source-{}-{}.wasm",
        NEXT_SOURCE.fetch_add(1, Ordering::Relaxed),
        id.replace('.', "_")
    ));
    std::fs::write(&source, bytes).expect("stage module bytes");
    Staged {
        entry: ModEntry {
            id: id.to_owned(),
            version: version.to_owned(),
            abi,
            blake3: *blake3::hash(bytes).as_bytes(),
            size: bytes.len() as u64,
            url: format!("file://{}", source.display()),
            capabilities: caps.iter().map(|cap| (*cap).to_owned()).collect(),
            enabled: true,
        },
        source,
    }
}

/// Installs one staged module through the durable store.
pub async fn install(store: &mut ModStore, policy: &CapabilityPolicy, staged: &Staged) {
    let set = ModSet {
        gen: store.generation() + 1,
        add: vec![staged.entry.clone()],
        remove: Vec::new(),
    };
    store.apply(&set, policy).await.expect("module install");
}

/// Installs fixtures and returns a host bound to `policy`.
pub async fn host_with(label: &str, policy: CapabilityPolicy) -> (PathBuf, WasmHost, ModStore) {
    let root = integration_tests::temp(label);
    let store = ModStore::open(root.join("mods")).expect("store opens");
    let host = WasmHost::new(policy.clone()).expect("host policy is valid");
    (root, host, store)
}
