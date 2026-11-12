use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

#[derive(Debug, thiserror::Error)]
pub(crate) enum DecodeError {
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
}
