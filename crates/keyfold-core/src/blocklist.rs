//! Signed list of blocked licence fingerprints (licences posted publicly, refunded or
//! charged back, or freed from a computer). Same token shape as a licence, but the
//! signature covers `DOMAIN` + the JSON, so a list can never pass as a licence or the
//! other way round. Checked entirely on the computer; nothing is sent anywhere.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::licence::Licence;

pub const DOMAIN: &[u8] = b"keyfold-blocklist-v1\n";
const VERSION: u32 = 1;

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockList {
    pub v: u32,
    /// unix ms when the server built the list; a newer list replaces an older one
    pub generated_at: i64,
    /// licence fingerprints, see [`crate::licence::fingerprint`]
    pub fps: Vec<String>,
}

impl BlockList {
    /// Whether a licence is blocked, by its own fingerprint or the purchase key it came from.
    pub fn blocks(&self, licence_fp: &str, lic: &Licence) -> bool {
        self.fps.iter().any(|f| f == licence_fp)
            || lic
                .purchase
                .as_deref()
                .is_some_and(|p| self.fps.iter().any(|f| f == p))
    }
}

/// Verify a signed list against the licence public key.
pub fn verify(signed: &str, public_key: &[u8; 32]) -> Result<BlockList> {
    let (payload_b64, sig_b64) = signed
        .trim()
        .split_once('.')
        .ok_or(Error::BlockList("malformed"))?;
    let payload = B64
        .decode(payload_b64)
        .map_err(|_| Error::BlockList("malformed payload"))?;
    let sig = B64
        .decode(sig_b64)
        .map_err(|_| Error::BlockList("malformed signature"))?;
    let sig = Signature::try_from(sig.as_slice())
        .map_err(|_| Error::BlockList("bad signature length"))?;
    let vk =
        VerifyingKey::from_bytes(public_key).map_err(|_| Error::BlockList("bad public key"))?;
    let mut msg = DOMAIN.to_vec();
    msg.extend_from_slice(&payload);
    vk.verify_strict(&msg, &sig)
        .map_err(|_| Error::BlockList("signature does not match"))?;
    let list: BlockList =
        serde_json::from_slice(&payload).map_err(|_| Error::BlockList("unreadable payload"))?;
    if list.v != VERSION {
        return Err(Error::BlockList("unsupported version"));
    }
    Ok(list)
}

/// Sign a list. The licence server does this; the app only verifies.
pub fn sign(list: &BlockList, secret_seed: &[u8; 32]) -> Result<String> {
    let payload = serde_json::to_vec(list)?;
    let mut msg = DOMAIN.to_vec();
    msg.extend_from_slice(&payload);
    let sig = SigningKey::from_bytes(secret_seed).sign(&msg);
    Ok(format!(
        "{}.{}",
        B64.encode(&payload),
        B64.encode(sig.to_bytes())
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::licence::{self, LicencePlan};

    const SEED: [u8; 32] = [42u8; 32];

    fn list(fps: &[&str]) -> BlockList {
        BlockList {
            v: 1,
            generated_at: 1_760_000_000_000,
            fps: fps.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn computer_licence(purchase: &str) -> Licence {
        Licence {
            product: "keyfold".into(),
            email: "a@b.c".into(),
            plan: LicencePlan::Lifetime,
            issued_at: 1,
            expires_at: None,
            device: Some("CHNT-R8JC-JQPP-536J".into()),
            purchase: Some(purchase.into()),
        }
    }

    #[test]
    fn signed_list_verifies_and_blocks_by_either_fingerprint() {
        let pk = licence::public_key_for(&SEED);
        let signed = sign(&list(&["aaaa", "pppp"]), &SEED).unwrap();
        let got = verify(&signed, &pk).unwrap();
        assert!(got.blocks("aaaa", &computer_licence("other")));
        assert!(got.blocks("zzzz", &computer_licence("pppp")));
        assert!(!got.blocks("zzzz", &computer_licence("other")));
    }

    #[test]
    fn tampered_wrong_key_and_cross_use_are_refused() {
        let pk = licence::public_key_for(&SEED);
        let signed = sign(&list(&["aaaa"]), &SEED).unwrap();
        let (payload, sig) = signed.split_once('.').unwrap();
        let forged = format!(
            "{}.{sig}",
            B64.encode(br#"{"v":1,"generated_at":1,"fps":[]}"#)
        );
        assert!(verify(&forged, &pk).is_err(), "payload swapped");
        let other = licence::public_key_for(&[7u8; 32]);
        assert!(verify(&signed, &other).is_err(), "wrong key");
        // A licence token is not a list, and a list is not a licence.
        let lic = licence::sign(&computer_licence("p"), &SEED).unwrap();
        assert!(verify(&lic, &pk).is_err());
        assert!(licence::verify(&format!("{payload}.{sig}"), &pk, 0).is_err());
    }
}
