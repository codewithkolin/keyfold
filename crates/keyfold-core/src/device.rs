//! Computer codes: a short, app-specific ID for one computer, used to bind a licence to it.
//! The code is a hash of the operating system's machine ID, so the raw ID never leaves the
//! computer and the code can't be matched with anything another app sees.

use sha2::{Digest, Sha256};

use crate::base32;

const DOMAIN: &[u8] = b"keyfold/device/v1\n";
const CODE_BYTES: usize = 10;

/// `XXXX-XXXX-XXXX-XXXX` for a machine ID (case and surrounding spaces ignored).
pub fn computer_code(machine_id: &str) -> String {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(machine_id.trim().to_ascii_lowercase().as_bytes());
    group(&base32::encode(&h.finalize()[..CODE_BYTES]))
}

/// Canonical form of a typed or pasted code, or `None` if it isn't one.
/// Forgiving like Recovery Kit codes: any case, dashes optional, `O` = `0`, `I`/`L` = `1`.
pub fn normalise_code(text: &str) -> Option<String> {
    let cleaned = base32::forgiving(text);
    base32::decode::<CODE_BYTES>(&cleaned).map(|_| group(&cleaned))
}

fn group(raw: &str) -> String {
    raw.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_formatted_and_case_insensitive() {
        let a = computer_code("4C4C4544-0042-3510-8051-B4C04F4E4D32");
        assert_eq!(a, computer_code("  4c4c4544-0042-3510-8051-b4c04f4e4d32\n"));
        assert_ne!(a, computer_code("4C4C4544-0042-3510-8051-B4C04F4E4D33"));
        assert_eq!(a.len(), 19);
        assert_eq!(a.matches('-').count(), 3);
        // Pinned so the licence server and older builds agree on the same code.
        assert_eq!(computer_code("test-machine"), "CHNT-R8JC-JQPP-536J");
    }

    #[test]
    fn normalises_typed_codes() {
        let c = computer_code("test-machine");
        assert_eq!(
            normalise_code(&c.to_lowercase().replace('-', " ")),
            Some(c.clone())
        );
        assert_eq!(normalise_code(&c.replace('0', "o")), Some(c));
        assert_eq!(normalise_code("not a code"), None);
        assert_eq!(normalise_code("CHNT-R8JC-JQPP-536"), None);
    }
}
