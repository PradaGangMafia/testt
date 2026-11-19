//! Coordinator daemon: relay pull, verification, ingest, and scheduling.

use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use clap::Parser;
use coordd::Coord;

#[derive(Parser, Debug)]
#[command(about = "Pull results, ingest findings, and push scheduled tasks")]
struct Cli {
    /// Coordinator state directory (keys, relays.conf, findings.db).
    #[arg(long, default_value = ".agent-fleet-coord")]
    state: PathBuf,
    /// Delay between pull/schedule cycles in milliseconds.
    #[arg(long, default_value_t = 2000)]
    cycle_ms: u64,
    /// Run one cycle and exit.
    #[arg(long)]
    once: bool,
    /// Artifact ingest bind address, e.g. 127.0.0.1:8790.
    #[arg(long)]
    artifact_bind: Option<String>,
    /// File containing the artifact token (defaults to `<state>/artifact.token`).
    #[arg(long)]
    artifact_token_file: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();
    let mut coord = match Coord::open(&cli.state) {
        Ok(coord) => coord,
        Err(error) => {
            eprintln!("coordd: {error}");
            std::process::exit(2);
        }
    };
    if let Some(bind) = &cli.artifact_bind {
        let token_file = cli
            .artifact_token_file
            .clone()
            .unwrap_or_else(|| cli.state.join("artifact.token"));
        let token = std::fs::read_to_string(token_file)
            .ok()
            .map(|text| text.trim().to_owned())
            .filter(|text| !text.is_empty());
        if let Err(error) = coordd::artifact::serve(bind, cli.state.clone(), token) {
            eprintln!("coordd: artifact bind: {error}");
            std::process::exit(2);
        }
    }
    let stopping = Arc::new(AtomicBool::new(false));
    spawn_signal_handler(stopping.clone());
    let result = coord.run(
        cli.once.then_some(1),
        Duration::from_millis(cli.cycle_ms.max(200)),
        &stopping,
    );
    if let Err(error) = result {
        eprintln!("coordd: {error}");
        std::process::exit(1);
    }
}

/// Marks the loop stopping on SIGTERM/SIGINT and waits for a clean cycle.
fn spawn_signal_handler(stopping: Arc<AtomicBool>) {
    std::thread::spawn(move || {
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            return;
        };
        runtime.block_on(async {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                let Ok(mut terminate) = signal(SignalKind::terminate()) else {
                    let _ = tokio::signal::ctrl_c().await;
                    stopping.store(true, Ordering::SeqCst);
                    return;
                };
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            #[cfg(not(unix))]
            {
                let _ = tokio::signal::ctrl_c().await;
            }
            stopping.store(true, Ordering::SeqCst);
        });
    });
}
