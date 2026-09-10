use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use zeroize::Zeroizing;

use crate::{
    error::{Result, VaultError},
    manifest::WrappedKey,
};

const KEY_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;

pub fn wrap_data_key(
    data_key: &[u8; KEY_LENGTH],
    wrapping_key: &[u8; KEY_LENGTH],
    associated_data: &[u8],
) -> Result<WrappedKey> {
    let mut nonce_bytes = [0_u8; NONCE_LENGTH];
    getrandom::fill(&mut nonce_bytes)
        .map_err(|_| VaultError::Cryptography("operating-system random source failed"))?;
    let cipher = Aes256Gcm::new_from_slice(wrapping_key)
        .map_err(|_| VaultError::Cryptography("invalid wrapping key"))?;
    let nonce = Nonce::try_from(nonce_bytes.as_slice())
        .map_err(|_| VaultError::Cryptography("invalid key-wrap nonce"))?;
    let encrypted = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: data_key,
                aad: associated_data,
            },
        )
        .map_err(|_| VaultError::Cryptography("data-key wrapping failed"))?;
    let split = encrypted
        .len()
        .checked_sub(TAG_LENGTH)
        .ok_or(VaultError::Cryptography("invalid wrapped data-key length"))?;

    Ok(WrappedKey {
        algorithm: "aes-256-gcm".into(),
        iv: STANDARD.encode(nonce_bytes),
        ciphertext: STANDARD.encode(&encrypted[..split]),
        authentication_tag: STANDARD.encode(&encrypted[split..]),
    })
}

pub fn unwrap_data_key(
    wrapped: &WrappedKey,
    wrapping_key: &[u8; KEY_LENGTH],
    associated_data: &[u8],
) -> Result<Zeroizing<[u8; KEY_LENGTH]>> {
    let nonce_bytes = STANDARD
        .decode(&wrapped.iv)
        .map_err(|_| VaultError::Authentication)?;
    let ciphertext = STANDARD
        .decode(&wrapped.ciphertext)
        .map_err(|_| VaultError::Authentication)?;
    let tag = STANDARD
        .decode(&wrapped.authentication_tag)
        .map_err(|_| VaultError::Authentication)?;
    if nonce_bytes.len() != NONCE_LENGTH
        || ciphertext.len() != KEY_LENGTH
        || tag.len() != TAG_LENGTH
    {
        return Err(VaultError::Authentication);
    }

    let cipher = Aes256Gcm::new_from_slice(wrapping_key).map_err(|_| VaultError::Authentication)?;
    let nonce = Nonce::try_from(nonce_bytes.as_slice()).map_err(|_| VaultError::Authentication)?;
    let mut combined = Zeroizing::new(ciphertext);
    combined.extend_from_slice(&tag);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: combined.as_slice(),
                    aad: associated_data,
                },
            )
            .map_err(|_| VaultError::Authentication)?,
    );
    let key: [u8; KEY_LENGTH] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::Authentication)?;
    Ok(Zeroizing::new(key))
}
