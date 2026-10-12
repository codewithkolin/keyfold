//! Time-based one-time passwords (RFC 6238) for saved logins.
//!
//! A login's 2FA secret is either a bare base32 string, as sites show it
//! ("JBSW Y3DP EHPK 3PXP"; spaces, dashes, lowercase and padding are fine), or an
//! `otpauth://totp/...` link with `secret` and optional `digits`, `period` and
//! `algorithm`. Codes are computed on demand; the secret never leaves this module
//! except as the decoded key held in zeroizing memory.
use hmac::{Hmac, KeyInit, Mac};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

/// A parsed 2FA secret.
#[derive(Clone)]
pub struct Totp {
    key: Zeroizing<Vec<u8>>,
    pub digits: u32,
    pub period: u64,
    pub algorithm: Algorithm,
}

impl std::fmt::Debug for Totp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Totp")
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// A code and how long it stays valid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TotpCode {
    pub code: String,
    pub seconds_left: u64,
    pub period: u64,
}

macro_rules! hmac_bytes {
    ($digest:ty, $key:expr, $msg:expr) => {{
        let mut mac =
            <Hmac<$digest> as KeyInit>::new_from_slice($key).expect("HMAC accepts any key length");
        mac.update($msg);
        mac.finalize().into_bytes().to_vec()
    }};
}

impl Totp {
    /// Parse a base32 secret or an `otpauth://totp/` link.
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        if input.len() > 4096 {
            return Err(Error::Totp("secret is too long"));
        }
        if input
            .get(..10)
            .is_some_and(|p| p.eq_ignore_ascii_case("otpauth://"))
        {
            return Self::parse_uri(input);
        }
        Self::from_parts(input, 6, 30, Algorithm::Sha1)
    }

    fn parse_uri(uri: &str) -> Result<Self> {
        let rest = &uri["otpauth://".len()..];
        let (kind, rest) = rest
            .split_once('/')
            .ok_or(Error::Totp("link has no label"))?;
        if !kind.eq_ignore_ascii_case("totp") {
            return Err(Error::Totp("only time-based (totp) links are supported"));
        }
        let query = rest
            .split_once('?')
            .map(|(_, q)| q)
            .ok_or(Error::Totp("link has no secret"))?;
        let (mut secret, mut digits, mut period, mut algorithm) =
            (None, 6u32, 30u64, Algorithm::Sha1);
        for pair in query.split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let v = percent_decode(v);
            match k.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(v),
                "digits" => {
                    digits = v
                        .parse()
                        .map_err(|_| Error::Totp("digits is not a number"))?
                }
                "period" => {
                    period = v
                        .parse()
                        .map_err(|_| Error::Totp("period is not a number"))?
                }
                "algorithm" => {
                    algorithm = match v.to_ascii_uppercase().as_str() {
                        "SHA1" => Algorithm::Sha1,
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        _ => return Err(Error::Totp("unknown algorithm")),
                    }
                }
                _ => {}
            }
        }
        let secret = Zeroizing::new(secret.ok_or(Error::Totp("link has no secret"))?);
        Self::from_parts(&secret, digits, period, algorithm)
    }

    fn from_parts(secret: &str, digits: u32, period: u64, algorithm: Algorithm) -> Result<Self> {
        if !(6..=8).contains(&digits) {
            return Err(Error::Totp("digits must be 6, 7 or 8"));
        }
        if !(1..=300).contains(&period) {
            return Err(Error::Totp("period must be between 1 and 300 seconds"));
        }
        let key = base32_decode(secret)?;
        if key.len() < 10 {
            return Err(Error::Totp("secret is too short"));
        }
        Ok(Self {
            key,
            digits,
            period,
            algorithm,
        })
    }

    /// The code for a moment in time (unix seconds).
    pub fn code_at(&self, unix_secs: u64) -> TotpCode {
        let counter = (unix_secs / self.period).to_be_bytes();
        let mac: Zeroizing<Vec<u8>> = Zeroizing::new(match self.algorithm {
            Algorithm::Sha1 => hmac_bytes!(sha1::Sha1, &self.key, &counter),
            Algorithm::Sha256 => hmac_bytes!(sha2::Sha256, &self.key, &counter),
            Algorithm::Sha512 => hmac_bytes!(sha2::Sha512, &self.key, &counter),
        });
        // RFC 4226 dynamic truncation.
        let offset = (mac[mac.len() - 1] & 0x0f) as usize;
        let bin = u32::from_be_bytes([
            mac[offset] & 0x7f,
            mac[offset + 1],
            mac[offset + 2],
            mac[offset + 3],
        ]);
        let value = bin % 10u32.pow(self.digits);
        TotpCode {
            code: format!("{value:0width$}", width = self.digits as usize),
            seconds_left: self.period - unix_secs % self.period,
            period: self.period,
        }
    }

    /// The code right now.
    pub fn now(&self) -> TotpCode {
        let secs = (crate::time::now_ms().max(0) / 1000) as u64;
        self.code_at(secs)
    }
}

/// RFC 4648 base32 without padding requirements; ignores spaces, dashes and `=`.
fn base32_decode(input: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(input.len() * 5 / 8));
    let (mut buffer, mut bits) = (0u64, 0u32);
    for c in input.chars() {
        let v = match c.to_ascii_uppercase() {
            ' ' | '-' | '=' | '\t' => continue,
            c @ 'A'..='Z' => c as u64 - 'A' as u64,
            c @ '2'..='7' => c as u64 - '2' as u64 + 26,
            _ => return Err(Error::Totp("secret is not valid base32")),
        };
        buffer = (buffer << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

fn percent_decode(s: &str) -> String {
    fn hex(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 appendix B seeds, base32-encoded.
    const SEED_SHA1: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // "12345678901234567890"
    const SEED_SHA256: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
    const SEED_SHA512: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

    fn rfc(seed: &str, algo: &str, t: u64) -> String {
        let uri = format!("otpauth://totp/RFC:test?secret={seed}&digits=8&algorithm={algo}");
        Totp::parse(&uri).unwrap().code_at(t).code
    }

    #[test]
    fn rfc6238_vectors() {
        let cases = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];
        for (t, sha1, sha256, sha512) in cases {
            assert_eq!(rfc(SEED_SHA1, "SHA1", t), sha1, "SHA1 at {t}");
            assert_eq!(rfc(SEED_SHA256, "SHA256", t), sha256, "SHA256 at {t}");
            assert_eq!(rfc(SEED_SHA512, "SHA512", t), sha512, "SHA512 at {t}");
        }
    }

    #[test]
    fn bare_secret_defaults_to_six_digits_every_thirty_seconds() {
        let t = Totp::parse("gezd gnbv gy3t qojq gezd gnbv gy3t qojq").unwrap();
        assert_eq!((t.digits, t.period, t.algorithm), (6, 30, Algorithm::Sha1));
        let c = t.code_at(59);
        assert_eq!(c.code, "287082");
        assert_eq!(c.seconds_left, 1);
        assert_eq!(t.code_at(60).seconds_left, 30);
    }

    #[test]
    fn otpauth_links_with_labels_and_percent_escapes() {
        let t = Totp::parse(
            "otpauth://totp/GitHub%3Asuman?issuer=GitHub&secret=JBSWY3DPEHPK3PXP&period=60&digits=7",
        )
        .unwrap();
        assert_eq!((t.digits, t.period), (7, 60));
        assert_eq!(t.code_at(0).code.len(), 7);
    }

    #[test]
    fn rejects_bad_secrets() {
        for bad in [
            "not base32 !",
            "JBSW",
            "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP",
            "otpauth://totp/x?issuer=nobody",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=4",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
        ] {
            assert!(Totp::parse(bad).is_err(), "{bad} should fail");
        }
    }

    #[test]
    fn debug_output_hides_the_key() {
        let t = Totp::parse("JBSWY3DPEHPK3PXP").unwrap();
        assert!(!format!("{t:?}").contains("72"));
    }
}
