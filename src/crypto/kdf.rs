use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD};
use zeroize::Zeroizing;

use crate::{
    error::{Result, VaultError},
    manifest::KdfParameters,
};

const SALT_LENGTH: usize = 16;
const KEY_LENGTH: usize = 32;
const KEY_LENGTH_U32: u32 = 32;

pub fn default_kdf_parameters() -> Result<KdfParameters> {
    let mut salt = [0_u8; SALT_LENGTH];
    getrandom::fill(&mut salt)
        .map_err(|_| VaultError::Cryptography("operating-system random source failed"))?;

    Ok(KdfParameters {
        algorithm: "argon2id".into(),
        salt: STANDARD.encode(salt),
        memory_cost_ki_b: 64 * 1024,
        time_cost: 3,
        parallelism: 1,
        output_length: KEY_LENGTH_U32,
    })
}

pub fn derive_key(
    password: &[u8],
    parameters: &KdfParameters,
) -> Result<Zeroizing<[u8; KEY_LENGTH]>> {
    validate_parameters(parameters)?;
    let salt = STANDARD
        .decode(&parameters.salt)
        .map_err(|_| VaultError::InvalidConfiguration("invalid KDF salt encoding".into()))?;
    if salt.len() != SALT_LENGTH {
        return Err(VaultError::InvalidConfiguration(
            "invalid KDF salt length".into(),
        ));
    }

    let params = Params::new(
        parameters.memory_cost_ki_b,
        parameters.time_cost,
        parameters.parallelism,
        Some(usize::try_from(parameters.output_length).map_err(|_| {
            VaultError::InvalidConfiguration("invalid Argon2id output length".into())
        })?),
    )
    .map_err(|_| VaultError::InvalidConfiguration("invalid Argon2id parameters".into()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new([0_u8; KEY_LENGTH]);
    argon2
        .hash_password_into(password, &salt, output.as_mut())
        .map_err(|_| VaultError::Cryptography("Argon2id key derivation failed"))?;
    Ok(output)
}

fn validate_parameters(parameters: &KdfParameters) -> Result<()> {
    if parameters.algorithm != "argon2id"
        || !(16 * 1024..=256 * 1024).contains(&parameters.memory_cost_ki_b)
        || !(1..=10).contains(&parameters.time_cost)
        || !(1..=16).contains(&parameters.parallelism)
        || parameters.output_length != KEY_LENGTH_U32
    {
        return Err(VaultError::InvalidConfiguration(
            "invalid Argon2id parameters in user manifest".into(),
        ));
    }
    Ok(())
}
