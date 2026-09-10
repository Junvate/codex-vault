use std::io;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, VaultError>;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("invalid username or password")]
    Authentication,

    #[error("vault integrity verification failed: {0}")]
    Integrity(&'static str),

    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),

    #[error("user already exists: {0}")]
    UserExists(String),

    #[error("this user vault is already unlocked")]
    Locked,

    #[error("failed to launch Codex: {0}")]
    Launch(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("cryptographic operation failed: {0}")]
    Cryptography(&'static str),
}
