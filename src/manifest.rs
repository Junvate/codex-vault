use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Result, VaultError};

pub const MANIFEST_VERSION: u32 = 1;
pub const VAULT_FORMAT: &str = "cdxvlt02";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KdfParameters {
    pub algorithm: String,
    pub salt: String,
    pub memory_cost_ki_b: u32,
    pub time_cost: u32,
    pub parallelism: u32,
    pub output_length: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WrappedKey {
    pub algorithm: String,
    pub iv: String,
    pub ciphertext: String,
    pub authentication_tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UserManifest {
    pub version: u32,
    pub id: String,
    pub username: String,
    pub created_at: u64,
    pub kdf: KdfParameters,
    pub wrapped_data_key: WrappedKey,
    pub vault_format: String,
}

impl UserManifest {
    pub fn new_header(username: String, kdf: KdfParameters) -> Result<Self> {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| {
                VaultError::InvalidConfiguration("system clock is before Unix epoch".into())
            })?
            .as_secs();

        Ok(Self {
            version: MANIFEST_VERSION,
            id: Uuid::new_v4().to_string(),
            username,
            created_at,
            kdf,
            wrapped_data_key: WrappedKey {
                algorithm: "aes-256-gcm".into(),
                iv: String::new(),
                ciphertext: String::new(),
                authentication_tag: String::new(),
            },
            vault_format: VAULT_FORMAT.into(),
        })
    }

    pub fn associated_data(&self) -> Result<Vec<u8>> {
        let mut output = Vec::with_capacity(256);
        output.extend_from_slice(b"CDXVAULT-WRAP-AAD-01");
        output.extend_from_slice(&self.version.to_be_bytes());
        push_field(&mut output, self.id.as_bytes())?;
        push_field(&mut output, self.username.as_bytes())?;
        output.extend_from_slice(&self.created_at.to_be_bytes());
        push_field(&mut output, self.kdf.algorithm.as_bytes())?;
        push_field(&mut output, self.kdf.salt.as_bytes())?;
        output.extend_from_slice(&self.kdf.memory_cost_ki_b.to_be_bytes());
        output.extend_from_slice(&self.kdf.time_cost.to_be_bytes());
        output.extend_from_slice(&self.kdf.parallelism.to_be_bytes());
        output.extend_from_slice(&self.kdf.output_length.to_be_bytes());
        push_field(&mut output, self.vault_format.as_bytes())?;
        Ok(output)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != MANIFEST_VERSION
            || Uuid::parse_str(&self.id).is_err()
            || !is_valid_username(&self.username)
            || self.created_at == 0
            || self.vault_format != VAULT_FORMAT
            || self.wrapped_data_key.algorithm != "aes-256-gcm"
        {
            return Err(VaultError::InvalidConfiguration(
                "unsupported or invalid user manifest".into(),
            ));
        }
        Ok(())
    }
}

fn push_field(output: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let length = u32::try_from(value.len()).map_err(|_| {
        VaultError::InvalidConfiguration("manifest field exceeds encoding limit".into())
    })?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

#[must_use]
pub fn is_valid_username(username: &str) -> bool {
    let bytes = username.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 || !bytes[0].is_ascii_alphanumeric() {
        return false;
    }
    bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}
