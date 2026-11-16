//! The policy hash and the policy id.
//!
//! `policy id = hex(SHA-256("acp/policy-id/v2" || policy hash || nonce ||
//! u64be(len) || creator))`. The policy hash is acp's content hash of the
//! processed policy: the 32 bytes of `acp::ppp::policy_id(policy, 0)`, which
//! covers every authored part (names, docs, attributes, specification,
//! relations, permissions and collection rules) and nothing derived.

use std::fmt;
use std::str::FromStr;

use ::acp::domain::ProcessedPolicy;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

/// The policy id's domain tag.
pub const POLICY_ID_DOMAIN: &[u8] = b"acp/policy-id/v2";

/// Bytes in a nonce and in a policy hash.
pub const HASH_LEN: usize = 32;

/// 32 bytes the policy creator chooses, so that one creator can create the
/// same policy more than once under different ids. Written as 64
/// hexadecimal characters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyNonce(pub [u8; HASH_LEN]);

/// The SHA-256 of a policy's authored content. Written as 64 lowercase
/// hexadecimal characters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyHash(pub [u8; HASH_LEN]);

/// Text that is not 32 bytes in hexadecimal.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("expected {} hexadecimal characters", HASH_LEN * 2)]
pub struct HexError;

/// The hash of `policy`'s authored content (its current id is ignored).
pub fn policy_hash(policy: &ProcessedPolicy) -> PolicyHash {
    let id = ::acp::ppp::policy_id(policy, 0);
    PolicyHash(decode_hex(id.as_str()).expect("acp policy ids are 32 bytes in hex"))
}

/// The id of a policy with hash `hash` created by `creator`, in its
/// canonical spelling, with `nonce`.
pub fn policy_id(hash: &PolicyHash, nonce: &PolicyNonce, creator: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(POLICY_ID_DOMAIN);
    digest.update(hash.0);
    digest.update(nonce.0);
    digest.update((creator.len() as u64).to_be_bytes());
    digest.update(creator.as_bytes());
    hex::encode(digest.finalize())
}

fn decode_hex(text: &str) -> Result<[u8; HASH_LEN], HexError> {
    let mut bytes = [0; HASH_LEN];
    hex::decode_to_slice(text, &mut bytes).map_err(|_| HexError)?;
    Ok(bytes)
}

macro_rules! hex_value {
    ($name:ident) => {
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&hex::encode(self.0))
            }
        }

        impl FromStr for $name {
            type Err = HexError;

            fn from_str(text: &str) -> Result<Self, HexError> {
                decode_hex(text).map(Self)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                String::deserialize(deserializer)?
                    .parse()
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}

hex_value!(PolicyNonce);
hex_value!(PolicyHash);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_binds_hash_nonce_and_creator() {
        let policy = ::acp::policy::compile_text("name: p\nresources:\n  - name: file\n", None, 0)
            .unwrap()
            .policy;
        let hash = policy_hash(&policy);
        let id = policy_id(&hash, &PolicyNonce::default(), "did:key:a");
        assert_eq!(id.len(), 64);
        assert_ne!(id, policy_id(&hash, &PolicyNonce([1; 32]), "did:key:a"));
        assert_ne!(id, policy_id(&hash, &PolicyNonce::default(), "did:key:b"));
        let other = ::acp::policy::compile_text("name: q\nresources:\n  - name: file\n", None, 0)
            .unwrap()
            .policy;
        assert_ne!(hash, policy_hash(&other));
        assert_eq!(
            hash.to_string().parse::<PolicyHash>().unwrap(),
            hash,
            "hex round trip"
        );
    }
}
