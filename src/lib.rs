mod archive;
mod config;
mod crypto;
mod daemon;
pub mod daemon_protocol;
mod error;
mod manifest;
mod runner;
mod store;

pub use daemon::{
    DaemonConfig, default_daemon_socket, query_daemon_status, serve_daemon, serve_daemon_once,
};
pub use daemon_protocol::{CapabilityState, DaemonCapabilities, DaemonStatus};
pub use error::{Result, VaultError};
pub use runner::{run_codex, run_program};
pub use store::{UnlockedVault, VaultStore};
