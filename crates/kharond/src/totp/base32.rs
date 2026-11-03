//! RFC 4648 base32 decoding into a zeroizing buffer.
//!
//! Accepts upper or lower case, ignores ASCII whitespace and `-`
//! (authenticator apps group secrets for display) and trailing `=`
//! padding; any other byte is refused rather than skipped, so a
//! mangled secret fails closed instead of yielding a wrong key.

use zeroize::{Zeroize, Zeroizing};

use super::TotpError;

pub(super) fn decode(input: &[u8]) -> Result<Zeroizing<Vec<u8>>, TotpError> {
    let mut out = Zeroizing::new(Vec::with_capacity(input.len() * 5 / 8 + 1));
    let mut acc: u64 = 0;
    let mut bits: u32 = 0;
    let mut padding = false;
    for &c in input {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            b'=' => {
                padding = true;
                continue;
            }
            b' ' | b'\t' | b'\r' | b'\n' | b'-' => continue,
            _ => {
                acc.zeroize();
                return Err(TotpError::InvalidSecret);
            }
        };
        if padding {
            // Data after padding.
            acc.zeroize();
            return Err(TotpError::InvalidSecret);
        }
        acc = (acc << 5) | u64::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    acc.zeroize();
    if out.is_empty() {
        return Err(TotpError::InvalidSecret);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        // RFC 4648 §10.
        for (enc, dec) in [
            ("MY======", "f"),
            ("MZXQ====", "fo"),
            ("MZXW6===", "foo"),
            ("MZXW6YQ=", "foob"),
            ("MZXW6YTB", "fooba"),
            ("MZXW6YTBOI======", "foobar"),
        ] {
            assert_eq!(&*decode(enc.as_bytes()).unwrap(), dec.as_bytes(), "{enc}");
        }
        assert_eq!(&*decode(b"mzxw 6ytb-oi").unwrap(), b"foobar");
        assert_eq!(decode(b""), Err(TotpError::InvalidSecret));
        assert_eq!(decode(b"MZXW1"), Err(TotpError::InvalidSecret));
        assert_eq!(decode(b"MY==MY"), Err(TotpError::InvalidSecret));
        assert_eq!(decode(b"===="), Err(TotpError::InvalidSecret));
    }
}
