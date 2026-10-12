//! On-disk layout. See docs/VAULT_FORMAT.md.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const MAGIC: &[u8; 8] = b"KEYFOLD\0";
pub const VERSION: u16 = 1;
pub const MAX_HEADER: usize = 64 * 1024;
pub const MAX_BODY: usize = 256 * 1024 * 1024;
const FIXED_PREFIX: usize = 8 + 2 + 4;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KdfParams {
    pub algo: String,
    pub version: u32,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    /// base64, 32 bytes
    pub salt: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WrappedKey {
    /// base64, 24 bytes
    pub nonce: String,
    /// base64, 32-byte key + 16-byte tag
    pub ct: String,
}

/// Second wrap of the DEK under a key derived from the Recovery Kit code.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RecoveryHeader {
    /// base64, 32 bytes; HKDF salt
    pub salt: String,
    pub wrapped_dek: WrappedKey,
    pub created_at: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Header {
    pub vault_id: String,
    pub created_at: i64,
    pub kdf: KdfParams,
    pub wrapped_dek: WrappedKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<RecoveryHeader>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hw_key: Option<serde_json::Value>,
}

/// Borrowed view of a parsed file.
pub struct Parsed<'a> {
    pub header: Header,
    /// Exact bytes from the magic through the end of the header JSON.
    /// Used as associated data for the body, so the header is tamper-evident.
    pub prefix: &'a [u8],
    /// nonce || ciphertext || tag
    pub body: &'a [u8],
}

pub fn max_file_len() -> usize {
    FIXED_PREFIX + MAX_HEADER + 8 + MAX_BODY
}

pub fn parse(bytes: &[u8]) -> Result<Parsed<'_>> {
    if bytes.len() < FIXED_PREFIX + 8 || &bytes[..8] != MAGIC {
        return Err(Error::InvalidFormat("missing Keyfold signature"));
    }
    let version = u16::from_le_bytes([bytes[8], bytes[9]]);
    if version != VERSION {
        return Err(Error::UnsupportedVersion(version));
    }
    let hlen = u32::from_le_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]) as usize;
    if hlen == 0 || hlen > MAX_HEADER {
        return Err(Error::InvalidFormat("bad header length"));
    }
    let hend = FIXED_PREFIX + hlen;
    if bytes.len() < hend + 8 {
        return Err(Error::InvalidFormat("truncated header"));
    }
    let header: Header = serde_json::from_slice(&bytes[FIXED_PREFIX..hend])
        .map_err(|_| Error::InvalidFormat("unreadable header"))?;
    let mut blen_bytes = [0u8; 8];
    blen_bytes.copy_from_slice(&bytes[hend..hend + 8]);
    let blen = u64::from_le_bytes(blen_bytes);
    if blen > MAX_BODY as u64 {
        return Err(Error::InvalidFormat("body too large"));
    }
    let bstart = hend + 8;
    let bend = bstart
        .checked_add(blen as usize)
        .ok_or(Error::InvalidFormat("bad body length"))?;
    if bytes.len() != bend {
        return Err(Error::InvalidFormat("truncated or padded body"));
    }
    Ok(Parsed {
        header,
        prefix: &bytes[..hend],
        body: &bytes[bstart..bend],
    })
}

/// magic || version || header_len || header_json
pub fn encode_prefix(header: &Header) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(header)?;
    if json.len() > MAX_HEADER {
        return Err(Error::InvalidFormat("header too large"));
    }
    let mut out = Vec::with_capacity(FIXED_PREFIX + json.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&(json.len() as u32).to_le_bytes());
    out.extend_from_slice(&json);
    Ok(out)
}
