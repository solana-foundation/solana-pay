//! Base58 helpers backed by `five8`, Anza's port of Firedancer's fd_base58.
//!
//! The fixed-size 32/64-byte codecs avoid `bs58`'s byte-at-a-time conversion on
//! hot Solana pubkey and signature paths. Variable-length call sites still use
//! `bs58`; tests keep `bs58` as the differential oracle.

/// Encode a 32-byte value (pubkey, hash) to base58.
pub(crate) fn encode_32(bytes: &[u8; 32]) -> String {
    let mut out = [0u8; five8::BASE58_ENCODED_32_MAX_LEN];
    let len = five8::encode_32(bytes, &mut out);
    ascii_to_string(&out[..usize::from(len)])
}

/// Encode a 64-byte value (signature, keypair) to base58.
pub(crate) fn encode_64(bytes: &[u8; 64]) -> String {
    let mut out = [0u8; five8::BASE58_ENCODED_64_MAX_LEN];
    let len = five8::encode_64(bytes, &mut out);
    ascii_to_string(&out[..usize::from(len)])
}

/// Decode base58 that must represent exactly 64 bytes (signature, keypair).
/// Wrong-length input surfaces as `TooShort`/`TooLong`.
pub(crate) fn decode_64(encoded: &str) -> Result<[u8; 64], five8::DecodeError> {
    let mut out = [0u8; 64];
    five8::decode_64(encoded, &mut out)?;
    Ok(out)
}

fn ascii_to_string(bytes: &[u8]) -> String {
    // The base58 alphabet is pure ASCII, so this never fails.
    core::str::from_utf8(bytes)
        .expect("base58 output is ASCII")
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn matches_bs58_on_fixed_sizes() {
        let mut rng = rand::rngs::OsRng;
        for _ in 0..256 {
            let mut key = [0u8; 32];
            rng.fill_bytes(&mut key);
            assert_eq!(encode_32(&key), bs58::encode(key).into_string());

            let mut sig = [0u8; 64];
            rng.fill_bytes(&mut sig);
            let encoded = bs58::encode(sig).into_string();
            assert_eq!(encode_64(&sig), encoded);
            assert_eq!(decode_64(&encoded).unwrap(), sig);
        }
    }

    #[test]
    fn matches_bs58_on_edge_values() {
        for bytes in [[0u8; 32], [0xFF; 32]] {
            assert_eq!(encode_32(&bytes), bs58::encode(bytes).into_string());
        }
        for bytes in [[0u8; 64], [0xFF; 64]] {
            let encoded = bs58::encode(bytes).into_string();
            assert_eq!(encode_64(&bytes), encoded);
            assert_eq!(decode_64(&encoded).unwrap(), bytes);
        }
        // Leading zeros must round-trip as leading '1's.
        let mut bytes = [0u8; 64];
        bytes[63] = 1;
        let encoded = encode_64(&bytes);
        assert!(encoded.starts_with("11"));
        assert_eq!(decode_64(&encoded).unwrap(), bytes);
    }

    #[test]
    fn decode_64_rejects_bad_input() {
        // 32-byte payload: too short for a 64-byte decode.
        let short = bs58::encode([7u8; 32]).into_string();
        assert!(decode_64(&short).is_err());
        // Invalid alphabet chars.
        assert!(decode_64("0OIl").is_err());
        assert!(decode_64("").is_err());
    }
}
