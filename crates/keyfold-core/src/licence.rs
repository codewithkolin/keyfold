//! Offline licence tokens: `base64url(json) . base64url(ed25519 signature)`.
//! The app embeds the public key; the private key lives only in the
//! Cloudflare Worker that issues tokens after a Dodo Payments webhook.
//!
//! Two kinds share the format. A purchase key (what the buyer receives) has no
//! `device`; a computer licence, issued when a computer is activated, adds the
//! computer's code (`device`) and the purchase key's fingerprint (`purchase`).
//! Absent fields are not serialised, so purchase keys keep their exact bytes.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    /// Computer code this licence is bound to; `None` on a purchase key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// Fingerprint of the purchase key a computer licence was issued for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purchase: Option<String>,
}

impl Licence {
    /// A purchase key unlocks nothing by itself; it is exchanged for computer licences.
    pub fn is_purchase_key(&self) -> bool {
        self.device.is_none() && self.purchase.is_none()
    }
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

/// Stable 32-hex-character ID of a token (SHA-256 of its payload), used by the block
/// list and the licence server so neither ever stores an email.
pub fn fingerprint(token: &str) -> Result<String> {
    let (payload_b64, _) = token
        .trim()
        .split_once('.')
        .ok_or(Error::Licence("malformed token"))?;
    let payload = B64
        .decode(payload_b64)
        .map_err(|_| Error::Licence("malformed payload"))?;
    Ok(hex(&Sha256::digest(&payload)[..16]))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Public key for a seed, for generating the value to embed in the app.
pub fn public_key_for(secret_seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(secret_seed)
        .verifying_key()
        .to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [42u8; 32];

    fn purchase_key() -> Licence {
        Licence {
            product: PRODUCT.into(),
            email: "buyer@example.com".into(),
            plan: LicencePlan::Lifetime,
            issued_at: 1_760_000_000_000,
            expires_at: None,
            device: None,
            purchase: None,
        }
    }

    #[test]
    fn purchase_keys_keep_their_bytes_and_computer_licences_round_trip() {
        let key = sign(&purchase_key(), &SEED).unwrap();
        let payload = B64.decode(key.split_once('.').unwrap().0).unwrap();
        assert_eq!(
            payload,
            br#"{"product":"keyfold","email":"buyer@example.com","plan":"lifetime","issued_at":1760000000000,"expires_at":null}"#
        );
        let pk = public_key_for(&SEED);
        assert!(verify(&key, &pk, 0).unwrap().is_purchase_key());

        let fp = fingerprint(&key).unwrap();
        assert_eq!(fp.len(), 32);
        // Pinned: the licence server computes the same value.
        assert_eq!(fp, "bf156ea60fc9bd86bc821e1b016adf2a");
        let computer = Licence {
            device: Some("CHNT-R8JC-JQPP-536J".into()),
            purchase: Some(fp.clone()),
            ..purchase_key()
        };
        let token = sign(&computer, &SEED).unwrap();
        let back = verify(&token, &pk, 0).unwrap();
        assert!(!back.is_purchase_key());
        assert_eq!(back, computer);
        assert_ne!(fingerprint(&token).unwrap(), fp);
        assert!(fingerprint("no-dot").is_err());
    }
}
