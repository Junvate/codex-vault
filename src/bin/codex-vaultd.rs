use std::{path::PathBuf, process};

use clap::Parser;
use codex_vault::{DaemonConfig, serve_daemon, serve_daemon_once};

#[derive(Parser)]
#[command(name = "codex-vaultd", version, about)]
struct Cli {
    /// Absolute Unix socket path. Defaults to the secure per-user runtime location.
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Serve exactly one request and exit. Intended for integration testing.
    #[arg(long)]
    once: bool,
}

fn main() {
    if let Err(error) = execute(&Cli::parse()) {
        eprintln!("codex-vaultd: {error}");
        process::exit(1);
    }
}

fn execute(cli: &Cli) -> codex_vault::Result<()> {
    let config = DaemonConfig::for_current_user(cli.socket.as_deref())?;
    println!("codex-vaultd starting on {}", config.socket_path.display());
    if cli.once {
        serve_daemon_once(&config)
    } else {
        serve_daemon(&config)
    }
}
