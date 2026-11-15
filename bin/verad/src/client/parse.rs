//! Parsing and rendering shared by the client subcommands.

use alloy_primitives::B256;
use commonware_cryptography::bls12381::primitives::variant::{MinSig, Variant};

/// Public consensus identity that certified reads are verified against.
type ConsensusPublicKey = <MinSig as Variant>::Public;

#[derive(Debug, thiserror::Error)]
pub(super) enum TrustedKeyError {
    #[error("invalid --trusted-key hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("invalid --trusted-key: {0}")]
    Encoding(#[from] commonware_codec::Error),
}

/// Decode hexadecimal with an optional `0x` prefix.
pub(super) fn decode_hex(hex: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(hex.strip_prefix("0x").unwrap_or(hex))
}

pub(super) fn hex_bytes(hex: &str) -> eyre::Result<Vec<u8>> {
    decode_hex(hex).map_err(|e| eyre::eyre!("invalid hex: {e}"))
}

pub(super) fn b256(hex: &str) -> eyre::Result<B256> {
    let bytes = hex_bytes(hex)?;
    B256::try_from(bytes.as_slice())
        .map_err(|_| eyre::eyre!("expected 32 bytes, got {}", bytes.len()))
}

pub(super) fn trusted_key(hex: &str) -> Result<ConsensusPublicKey, TrustedKeyError> {
    let bytes = decode_hex(hex)?;
    Ok(commonware_codec::DecodeExt::decode(
        commonware_codec::Copying(bytes.as_slice()),
    )?)
}

pub(super) fn bls_scalar(hex: &str) -> eyre::Result<ark_bls12_381::Fr> {
    let bytes = decode_hex(hex).map_err(|e| eyre::eyre!("invalid BLS secret key hex: {e}"))?;
    let bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| eyre::eyre!("BLS secret key must be 32 bytes, got {}", bytes.len()))?;
    Ok(<ark_bls12_381::Fr as ark_ff::PrimeField>::from_le_bytes_mod_order(&bytes))
}

/// Module reads return JSON where the record is JSON, and hexadecimal otherwise.
pub(super) fn bytes_to_json(data: &[u8]) -> serde_json::Value {
    serde_json::from_slice(data)
        .unwrap_or_else(|_| serde_json::Value::String(format!("0x{}", hex::encode(data))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hexadecimal_accepts_an_optional_prefix_and_fixed_widths_are_enforced() {
        assert_eq!(hex_bytes("0x0102").unwrap(), [1, 2]);
        assert_eq!(hex_bytes("0102").unwrap(), [1, 2]);
        assert!(hex_bytes("0x0g").is_err());
        assert_eq!(
            b256(&format!("0x{}", "11".repeat(32))).unwrap(),
            B256::repeat_byte(0x11)
        );
        assert!(b256("0x11").is_err());
        assert!(bls_scalar(&"07".repeat(32)).is_ok());
        assert!(bls_scalar(&"07".repeat(31)).is_err());
        assert!(bls_scalar("not-hex").is_err());
    }

    #[test]
    fn trusted_key_distinguishes_hex_from_encoding_failures() {
        assert!(matches!(
            trusted_key("invalid hex"),
            Err(TrustedKeyError::Hex(_))
        ));
        assert!(matches!(
            trusted_key("00"),
            Err(TrustedKeyError::Encoding(_))
        ));
    }

    #[test]
    fn records_render_as_json_or_prefixed_hex() {
        assert_eq!(bytes_to_json(br#"{"a":1}"#), serde_json::json!({ "a": 1 }));
        assert_eq!(bytes_to_json(&[0xff, 0x00]), serde_json::json!("0xff00"));
    }
}
