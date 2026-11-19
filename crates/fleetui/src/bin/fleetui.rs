//! Terminal fleet dashboard.

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(about = "Live terminal dashboard over a coordinator state directory")]
struct Cli {
    /// Coordinator state directory.
    #[arg(long, default_value = ".agent-fleet-coord")]
    state: PathBuf,
}

fn main() {
    let cli = Cli::parse();
    if let Err(error) = fleetui::run(&cli.state) {
        eprintln!("fleetui: {error}");
        std::process::exit(1);
    }
}
