use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

/// Longest accepted multibase string. An uncompressed secp256k1 key with its
/// multicodec prefix is 93 characters; base58 decoding is quadratic in length.
pub(crate) const MAX_MULTIBASE_LEN: usize = 128;

#[derive(Debug, thiserror::Error)]
pub(crate) enum DecodeError {
    #[error("did:key encoding exceeds {MAX_MULTIBASE_LEN} characters")]
    TooLong,
    #[error("unsupported did:key encoding")]
    UnsupportedEncoding,
    #[error("invalid base58btc: {0}")]
    Base58(#[from] bs58::decode::Error),
    #[error("invalid base64url: {0}")]
    Base64(#[from] base64::DecodeError),
}

pub(crate) fn encode(bytes: &[u8]) -> String {
    format!("z{}", bs58::encode(bytes).into_string())
}

/// The `did:key` naming `key` under a multicodec, in base58btc.
pub(crate) fn did(codec: u64, key: &[u8]) -> String {
    let mut buffer = [0u8; 10];
    let mut bytes = unsigned_varint::encode::u64(codec, &mut buffer).to_vec();
    bytes.extend_from_slice(key);
    format!("did:key:{}", encode(&bytes))
}

pub(crate) fn decode(encoded: &str) -> Result<Vec<u8>, DecodeError> {
    if encoded.len() > MAX_MULTIBASE_LEN {
        return Err(DecodeError::TooLong);
    }
    match encoded.as_bytes().first() {
        Some(b'z') => bs58::decode(&encoded[1..]).into_vec().map_err(Into::into),
        Some(b'u') => URL_SAFE_NO_PAD.decode(&encoded[1..]).map_err(Into::into),
        _ => Err(DecodeError::UnsupportedEncoding),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_standard_encodings_and_rejects_invalid_values() {
        let value = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let bytes = decode(value).unwrap();
        assert_eq!(encode(&bytes), value);
        assert_eq!(
            decode(&format!("u{}", URL_SAFE_NO_PAD.encode(&bytes))).unwrap(),
            bytes
        );
        for invalid in ["", "z0", "u_", "uAA=", "f00", "🦀"] {
            assert!(decode(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn rejects_over_long_input_without_decoding_it() {
        for prefix in ['z', 'u'] {
            let longest = format!("{prefix}{}", "1".repeat(MAX_MULTIBASE_LEN - 1));
            assert!(!matches!(decode(&longest), Err(DecodeError::TooLong)));
            let over = format!("{prefix}{}", "1".repeat(MAX_MULTIBASE_LEN));
            assert!(matches!(decode(&over), Err(DecodeError::TooLong)));
        }
        let started = std::time::Instant::now();
        let huge = format!("z{}", "2".repeat(1 << 20));
        assert!(matches!(decode(&huge), Err(DecodeError::TooLong)));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }
}
