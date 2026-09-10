use std::{
    env,
    ffi::OsString,
    io::{self, Write},
    path::PathBuf,
    process,
};

use clap::{Parser, Subcommand};
use codex_vault::{
    CapabilityState, VaultStore, default_daemon_socket, query_daemon_status, run_codex,
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "codex-vault", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize the encrypted state root.
    Init,
    /// Manage application-level users.
    User {
        #[command(subcommand)]
        command: UserCommand,
    },
    /// Inspect the local Codex Vault daemon.
    Daemon {
        #[command(subcommand)]
        command: DaemonCommand,
    },
    /// Unlock a user profile and run the real Codex CLI.
    Run {
        #[arg(long)]
        user: Option<String>,
        #[arg(last = true, allow_hyphen_values = true)]
        codex_arguments: Vec<OsString>,
    },
}

#[derive(Subcommand)]
enum UserCommand {
    /// Create an encrypted user profile.
    Add { username: String },
    /// Replace a user's password without rewriting encrypted Codex state.
    Passwd { username: String },
    /// List configured application-level users.
    List,
}

#[derive(Subcommand)]
enum DaemonCommand {
    /// Verify the versioned protocol and kernel-authenticated peer identity.
    Status {
        /// Absolute Unix socket path.
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Print the structured daemon response as JSON.
        #[arg(long)]
        json: bool,
    },
}

fn main() {
    match execute(Cli::parse()) {
        Ok(code) => process::exit(code),
        Err(error) => {
            eprintln!("codex-vault: {error}");
            process::exit(1);
        }
    }
}

fn execute(cli: Cli) -> codex_vault::Result<i32> {
    let store = VaultStore::from_environment()?;
    match cli.command {
        Command::Init => {
            store.initialize()?;
            println!("Codex Vault initialized.");
            Ok(0)
        }
        Command::User {
            command: UserCommand::Add { username },
        } => {
            let password = Zeroizing::new(rpassword::prompt_password("New password: ")?);
            let confirmation = Zeroizing::new(rpassword::prompt_password("Confirm password: ")?);
            if password.as_bytes() != confirmation.as_bytes() {
                return Err(codex_vault::VaultError::InvalidConfiguration(
                    "passwords do not match".into(),
                ));
            }
            store.add_user(&username, password.as_bytes())?;
            println!("Created encrypted Codex profile for {username}.");
            Ok(0)
        }
        Command::User {
            command: UserCommand::List,
        } => {
            let users = store.list_users()?;
            if users.is_empty() {
                println!("No users.");
            } else {
                for user in users {
                    println!("{user}");
                }
            }
            Ok(0)
        }
        Command::User {
            command: UserCommand::Passwd { username },
        } => {
            let current = Zeroizing::new(rpassword::prompt_password("Current password: ")?);
            let new_password = Zeroizing::new(rpassword::prompt_password("New password: ")?);
            let confirmation =
                Zeroizing::new(rpassword::prompt_password("Confirm new password: ")?);
            if new_password.as_bytes() != confirmation.as_bytes() {
                return Err(codex_vault::VaultError::InvalidConfiguration(
                    "passwords do not match".into(),
                ));
            }
            store.rotate_password(&username, current.as_bytes(), new_password.as_bytes())?;
            println!("Updated password for {username}.");
            Ok(0)
        }
        Command::Daemon {
            command: DaemonCommand::Status { socket, json },
        } => {
            let socket = socket.map_or_else(default_daemon_socket, Ok)?;
            let status = query_daemon_status(&socket)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                println!("Daemon: reachable");
                println!("Socket: {}", socket.display());
                println!("Protocol: {}", status.protocol_version);
                println!("Daemon version: {}", status.daemon_version);
                println!("Daemon UID: {}", status.daemon_uid);
                println!(
                    "Peer credentials: pid={} uid={} gid={}",
                    status.peer.pid, status.peer.uid, status.peer.gid
                );
                println!(
                    "Capabilities: peer-credentials=yes pam={} dedicated-uid={} encrypted-mount={}",
                    capability_label(status.capabilities.pam_authentication),
                    capability_label(status.capabilities.dedicated_uid),
                    capability_label(status.capabilities.encrypted_mount)
                );
            }
            Ok(0)
        }
        Command::Run {
            user,
            codex_arguments,
        } => {
            let username = match user.or_else(|| env::var("CODEX_VAULT_USER").ok()) {
                Some(username) => username,
                None => prompt_username()?,
            };
            let password = Zeroizing::new(rpassword::prompt_password("Password: ")?);
            run_codex(&store, &username, password.as_bytes(), &codex_arguments)
        }
    }
}

const fn capability_label(state: CapabilityState) -> &'static str {
    match state {
        CapabilityState::Enabled => "enabled",
        CapabilityState::Disabled => "disabled",
    }
}

fn prompt_username() -> io::Result<String> {
    print!("Username: ");
    io::stdout().flush()?;
    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    Ok(username.trim().to_owned())
}
