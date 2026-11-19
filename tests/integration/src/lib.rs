//! Shared harness for the integration suite.
//!
//! Every test gets its own directory under the system temporary directory, so
//! the suite is parallel-safe and never writes outside its own tree.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

/// Returns a fresh, empty directory for one test.
pub fn temp(label: &str) -> PathBuf {
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "agent-fleet-integration-{label}-{}-{unique}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("temporary test directory");
    path
}

/// Returns the absolute path of `tests/fixtures/<name>`.
pub fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

/// Reads one committed fixture.
pub fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(fixture_path(name)).expect("committed fixture")
}

/// Repository target directory used to locate workspace binaries.
pub fn target_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug")
}
