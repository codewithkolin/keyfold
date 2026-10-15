//! Recovery Kit codes: 160 random bits, Crockford base32, HKDF-SHA256 wrapping key.
//! A code is equivalent to a second passphrase with 160 bits of entropy, so a
//! fast KDF is safe and recovery unlock is instant.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::base32;
use crate::crypto::{random_bytes, KEY_LEN};
use crate::error::{Error, Result};

pub const CODE_BYTES: usize = 20;
const CODE_CHARS: usize = 32; // 160 bits / 5
pub const PREFIX: &str = "KFLD";
const INFO: &[u8] = b"keyfold/recovery/v1";

pub struct RecoveryCode(Zeroizing<[u8; CODE_BYTES]>);

impl RecoveryCode {
    pub fn generate() -> Result<Self> {
        Ok(Self(Zeroizing::new(random_bytes::<CODE_BYTES>()?)))
    }

    pub fn from_bytes(bytes: [u8; CODE_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn bytes(&self) -> &[u8; CODE_BYTES] {
        &self.0
    }

    /// `KFLD-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`
    pub fn display(&self) -> Zeroizing<String> {
        let raw = base32::encode(self.0.as_ref());
        let mut out = String::with_capacity(PREFIX.len() + 1 + CODE_CHARS + 7);
        out.push_str(PREFIX);
        for (i, c) in raw.chars().enumerate() {
            if i % 4 == 0 {
                out.push('-');
            }
            out.push(c);
        }
        Zeroizing::new(out)
    }

    /// Forgiving parser: any case, dashes and spaces optional, `KFLD` prefix
    /// optional, `O` read as `0`, `I` and `L` read as `1`.
    pub fn parse(text: &str) -> Result<Self> {
        let mut cleaned: Zeroizing<String> =
            Zeroizing::new(String::with_capacity(PREFIX.len() + CODE_CHARS));
        for c in text.chars() {
            if c == '-' || c.is_whitespace() {
                continue;
            }
            cleaned.push(c.to_ascii_uppercase());
        }
        let body: &str =
            if cleaned.len() == PREFIX.len() + CODE_CHARS && cleaned.starts_with(PREFIX) {
                &cleaned[PREFIX.len()..]
            } else {
                &cleaned
            };
        let mapped: Zeroizing<String> = Zeroizing::new(
            body.chars()
                .map(|c| match c {
                    'O' => '0',
                    'I' | 'L' => '1',
                    c => c,
                })
                .collect(),
        );
        let bytes =
            base32::decode::<CODE_BYTES>(&mapped).ok_or(Error::InvalidFormat("recovery code"))?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// 32-byte wrapping key for this code and salt.
    pub fn derive_key(&self, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        let hk = Hkdf::<Sha256>::new(Some(salt), self.0.as_ref());
        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        hk.expand(INFO, out.as_mut())
            .map_err(|_| Error::Kdf("hkdf expand".into()))?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_forgiving_parse() {
        let code = RecoveryCode::from_bytes([0xA7; 20]);
        let shown = code.display();
        assert!(shown.starts_with("KFLD-"));
        assert_eq!(shown.len(), 4 + 1 + 32 + 7);
        assert_eq!(RecoveryCode::parse(&shown).unwrap().bytes(), code.bytes());
        let messy = shown
            .to_lowercase()
            .replace('-', " ")
            .replace('0', "o")
            .replace('1', "l");
        assert_eq!(RecoveryCode::parse(&messy).unwrap().bytes(), code.bytes());
        let no_prefix = shown[5..].replace('-', "");
        assert_eq!(
            RecoveryCode::parse(&no_prefix).unwrap().bytes(),
            code.bytes()
        );
        assert!(RecoveryCode::parse("KFLD-1234").is_err());
        assert!(
            RecoveryCode::parse(&format!("{}U", &no_prefix[..31])).is_err(),
            "U is not in the alphabet"
        );
    }

    #[test]
    fn random_codes_survive_encoding() {
        for _ in 0..50 {
            let c = RecoveryCode::generate().unwrap();
            assert_eq!(
                RecoveryCode::parse(&c.display()).unwrap().bytes(),
                c.bytes()
            );
        }
    }

    #[test]
    fn key_depends_on_salt_and_code() {
        let a = RecoveryCode::from_bytes([1; 20]);
        let b = RecoveryCode::from_bytes([2; 20]);
        assert_ne!(
            *a.derive_key(b"salt1").unwrap(),
            *a.derive_key(b"salt2").unwrap()
        );
        assert_ne!(
            *a.derive_key(b"salt1").unwrap(),
            *b.derive_key(b"salt1").unwrap()
        );
        assert_eq!(
            *a.derive_key(b"salt1").unwrap(),
            *a.derive_key(b"salt1").unwrap()
        );
    }
}
