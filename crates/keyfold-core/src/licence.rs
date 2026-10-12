//! Offline licence tokens: `base64url(json) . base64url(ed25519 signature)`.
//! The app embeds the public key; the private key lives only in the
//! Cloudflare Worker that issues tokens after a Dodo Payments webhook.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const PRODUCT: &str = "keyfold";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LicencePlan {
    Lifetime,
    Yearly,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Licence {
    pub product: String,
    pub email: String,
    pub plan: LicencePlan,
    pub issued_at: i64,
    /// unix ms; `None` for lifetime
    #[serde(default)]
    pub expires_at: Option<i64>,
}

/// Verify a token against the embedded public key at time `now` (unix ms).
pub fn verify(token: &str, public_key: &[u8; 32], now: i64) -> Result<Licence> {
    let (payload_b64, sig_b64) = token
        .trim()
        .split_once('.')
        .ok_or(Error::Licence("malformed token"))?;
    let payload = B64
        .decode(payload_b64)
        .map_err(|_| Error::Licence("malformed payload"))?;
    let sig = B64
        .decode(sig_b64)
        .map_err(|_| Error::Licence("malformed signature"))?;
    let sig =
        Signature::try_from(sig.as_slice()).map_err(|_| Error::Licence("bad signature length"))?;
    let vk = VerifyingKey::from_bytes(public_key).map_err(|_| Error::Licence("bad public key"))?;
    vk.verify_strict(&payload, &sig)
        .map_err(|_| Error::Licence("signature does not match"))?;
    let lic: Licence =
        serde_json::from_slice(&payload).map_err(|_| Error::Licence("unreadable payload"))?;
    if lic.product != PRODUCT {
        return Err(Error::Licence("token is for a different product"));
    }
    if let Some(exp) = lic.expires_at {
        if now >= exp {
            return Err(Error::Licence("licence has expired"));
        }
    }
    Ok(lic)
}

/// Issue a token. Only the licence server (and tests) hold `secret_seed`.
pub fn sign(lic: &Licence, secret_seed: &[u8; 32]) -> Result<String> {
    let sk = SigningKey::from_bytes(secret_seed);
    let payload = serde_json::to_vec(lic)?;
    let sig = sk.sign(&payload);
    Ok(format!(
        "{}.{}",
        B64.encode(&payload),
        B64.encode(sig.to_bytes())
    ))
}

/// Public key for a seed, for generating the value to embed in the app.
pub fn public_key_for(secret_seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(secret_seed)
        .verifying_key()
        .to_bytes()
}
