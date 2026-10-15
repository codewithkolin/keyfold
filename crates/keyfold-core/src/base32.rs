//! Crockford base32 (no I, L, O, U), shared by Recovery Kit codes and computer codes.

pub(crate) const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Encode whole bytes; a trailing partial group is padded with zero bits.
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for &b in bytes {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buf >> bits) & 31) as usize] as char);
            buf &= (1 << bits) - 1;
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Decode exactly `N` bytes from canonical upper-case characters, with no padding bits left.
pub(crate) fn decode<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != (N * 8).div_ceil(5) {
        return None;
    }
    let mut out = [0u8; N];
    let mut i = 0;
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        let v = ALPHABET.iter().position(|&a| a == c)? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out[i] = ((buf >> bits) & 0xff) as u8;
            i += 1;
            buf &= (1 << bits) - 1;
        }
    }
    (i == N && buf == 0).then_some(out)
}

/// Upper-case, drop dashes and spaces, read `O` as `0` and `I`/`L` as `1`.
pub(crate) fn forgiving(text: &str) -> String {
    text.chars()
        .filter(|c| *c != '-' && !c.is_whitespace())
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_whole_and_partial_groups() {
        let twenty = [0xA5u8; 20];
        assert_eq!(decode::<20>(&encode(&twenty)), Some(twenty));
        let ten: [u8; 10] = core::array::from_fn(|i| (i as u8).wrapping_mul(29));
        let s = encode(&ten);
        assert_eq!(s.len(), 16);
        assert_eq!(decode::<10>(&s), Some(ten));
        assert_eq!(decode::<10>("0000000000000000"), Some([0u8; 10]));
        assert_eq!(
            decode::<10>("000000000000000U"),
            None,
            "U is not in the alphabet"
        );
        assert_eq!(forgiving("ab-cd ol i"), "ABCD011");
    }
}
