//! Vera module key prefixes and builders.
//!
//! Each record family sits under a one-byte prefix; the singletons use named keys.

use sha2::{Digest, Sha256};

use crate::key_encoding::len_prefix;

/// Primary JWS token store prefix.
pub const JWS_TOKEN_PREFIX: &[u8] = &[0x01];
/// DID → token_hash secondary index prefix.
pub const JWS_TOKEN_BY_DID_PREFIX: &[u8] = &[0x02];
/// Account → token_hash secondary index prefix.
pub const JWS_TOKEN_BY_ACCOUNT_PREFIX: &[u8] = &[0x03];
/// Ordered expiry deadlines for active tokens.
pub const JWS_TOKEN_EXPIRY_PREFIX: &[u8] = &[0x04];
/// Module parameters key.
pub const PARAMS_KEY: &[u8] = b"p_hub";
/// Write-once chain configuration key.
pub const CHAIN_CONFIG_KEY: &[u8] = b"chain_config";

/// Primary store key: `prefix + token_hash` (raw bytes, no length prefix).
///
/// Token hashes are fixed-length hex strings (64 chars for SHA-256),
/// so no length prefix is needed.
pub fn jws_token_key(token_hash: &str) -> Vec<u8> {
    let mut key = Vec::from(JWS_TOKEN_PREFIX);
    key.extend_from_slice(token_hash.as_bytes());
    key
}

/// DID index key: `prefix + len_prefix(did) + len_prefix(token_hash)`.
pub fn jws_token_by_did_key(did: &str, token_hash: &str) -> Vec<u8> {
    let mut key = Vec::from(JWS_TOKEN_BY_DID_PREFIX);
    key.extend_from_slice(&len_prefix(did.as_bytes()));
    key.extend_from_slice(&len_prefix(token_hash.as_bytes()));
    key
}

/// Account index key: `prefix + len_prefix(account) + len_prefix(token_hash)`.
pub fn jws_token_by_account_key(account: &str, token_hash: &str) -> Vec<u8> {
    let mut key = Vec::from(JWS_TOKEN_BY_ACCOUNT_PREFIX);
    key.extend_from_slice(&len_prefix(account.as_bytes()));
    key.extend_from_slice(&len_prefix(token_hash.as_bytes()));
    key
}

/// Prefix scan key for all tokens belonging to a DID.
pub fn jws_token_did_prefix(did: &str) -> Vec<u8> {
    let mut key = Vec::from(JWS_TOKEN_BY_DID_PREFIX);
    key.extend_from_slice(&len_prefix(did.as_bytes()));
    key
}

/// Prefix scan key for all tokens belonging to an account.
pub fn jws_token_account_prefix(account: &str) -> Vec<u8> {
    let mut key = Vec::from(JWS_TOKEN_BY_ACCOUNT_PREFIX);
    key.extend_from_slice(&len_prefix(account.as_bytes()));
    key
}

/// SHA-256 hash of bearer token, hex-encoded (lowercase, 64 chars).
pub fn hash_jws_token(bearer_token: &str) -> String {
    let digest = Sha256::digest(bearer_token.as_bytes());
    hex::encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jws_token_key_format() {
        let hash = "abcdef1234567890";
        let key = jws_token_key(hash);
        assert_eq!(key[0], 0x01);
        assert_eq!(&key[1..], hash.as_bytes());
    }

    #[test]
    fn jws_token_by_did_key_format() {
        let did = "did:key:z6Mk123";
        let hash = "abc123";
        let key = jws_token_by_did_key(did, hash);
        assert_eq!(key[0], 0x02);
        #[expect(clippy::cast_possible_truncation)]
        {
            assert_eq!(key[1], did.len() as u8);
        }
    }

    #[test]
    fn did_prefix_is_prefix_of_full_key() {
        let did = "did:key:z6Mk123";
        let hash = "tokenhash";
        let prefix = jws_token_did_prefix(did);
        let full = jws_token_by_did_key(did, hash);
        assert!(full.starts_with(&prefix));
        assert!(full.len() > prefix.len());
    }

    #[test]
    fn account_prefix_is_prefix_of_full_key() {
        let account = "0xABCD";
        let hash = "tokenhash";
        let prefix = jws_token_account_prefix(account);
        let full = jws_token_by_account_key(account, hash);
        assert!(full.starts_with(&prefix));
        assert!(full.len() > prefix.len());
    }

    #[test]
    fn hash_jws_token_produces_hex_sha256() {
        let hash = hash_jws_token("test-bearer-token");
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_jws_token_deterministic() {
        let a = hash_jws_token("same-input");
        let b = hash_jws_token("same-input");
        assert_eq!(a, b);
    }

    #[test]
    fn hash_jws_token_different_inputs() {
        let a = hash_jws_token("input-1");
        let b = hash_jws_token("input-2");
        assert_ne!(a, b);
    }

    #[test]
    fn borsh_roundtrip_jws_token_record() {
        use borsh::BorshDeserialize;

        use crate::types::Timestamp;
        use crate::vera::types::{JWSTokenRecord, JWSTokenStatus};

        let record = JWSTokenRecord {
            token_hash: "abc123".into(),
            bearer_token: "eyJ...".into(),
            issuer_did: "did:key:z6Mk".into(),
            authorized_account: "0x1234".into(),
            issued_at: Timestamp {
                seconds: 100,
                block_height: 10,
            },
            expires_at: Timestamp {
                seconds: 200,
                block_height: 20,
            },
            status: JWSTokenStatus::Valid,
            first_used_at: Some(Timestamp {
                seconds: 105,
                block_height: 11,
            }),
            last_used_at: None,
            invalidated_at: None,
            invalidated_by: String::new(),
        };

        let encoded = borsh::to_vec(&record).unwrap();
        let decoded = JWSTokenRecord::try_from_slice(&encoded).unwrap();
        assert_eq!(record, decoded);
    }

    #[test]
    fn borsh_roundtrip_chain_config() {
        use borsh::BorshDeserialize;

        use crate::vera::types::ChainConfig;

        let config = ChainConfig {
            allow_zero_fee_txs: true,
            ignore_bearer_auth: false,
        };
        let encoded = borsh::to_vec(&config).unwrap();
        let decoded = ChainConfig::try_from_slice(&encoded).unwrap();
        assert_eq!(config, decoded);
    }
}
