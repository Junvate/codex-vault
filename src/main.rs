use std::{
    env,
    ffi::OsString,
    io::{self, Write},
    process,
};

use clap::{Parser, Subcommand};
use codex_vault::{VaultStore, run_codex};
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

fn prompt_username() -> io::Result<String> {
    print!("Username: ");
    io::stdout().flush()?;
    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    Ok(username.trim().to_owned())
}
