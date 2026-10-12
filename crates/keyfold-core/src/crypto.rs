//! Thin, audited-crate-only wrappers. No hand-rolled primitives.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::vault::KdfSettings;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const SALT_LEN: usize = 32;

/// Fill an array from the operating system's CSPRNG.
pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|e| Error::Kdf(format!("os rng unavailable: {e}")))?;
    Ok(out)
}

/// Argon2id: password + salt -> 32-byte key encryption key.
pub fn derive_kek(
    password: &[u8],
    salt: &[u8],
    s: &KdfSettings,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let params = Params::new(s.m_cost_kib, s.t_cost, s.p_cost, Some(KEY_LEN))
        .map_err(|e| Error::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password, salt, out.as_mut())
        .map_err(|e| Error::Kdf(e.to_string()))?;
    Ok(out)
}

fn cipher(key: &[u8; KEY_LEN]) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Kdf("bad key length".into()))
}

/// XChaCha20-Poly1305 encrypt with associated data. Returns ciphertext || tag.
pub fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let nonce = XNonce::from(*nonce);
    cipher(key)?
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Tampered)
}

/// XChaCha20-Poly1305 decrypt with associated data. Any failure is `Tampered`;
/// callers map it to `WrongPassword` where that is the likelier cause.
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let nonce = XNonce::from(*nonce);
    cipher(key)?
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Tampered)
}
