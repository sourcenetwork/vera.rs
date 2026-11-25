//! The policy hash and the policy id.
//!
//! `policy id = hex(SHA-256("acp/policy-id/v2" || policy hash || nonce ||
//! u64be(len) || creator))`, as `acp::ppp::policy_id` derives it. The policy
//! hash is `acp::ppp::policy_hash`, which covers every authored part (names,
//! docs, attributes, specification, relations, permissions and collection
//! rules) and nothing derived.

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
    PolicyHash(::acp::ppp::policy_hash(policy).0)
}

/// The id of a policy with hash `hash` created by `creator`, in its
/// canonical spelling, with `nonce`. Unlike acp's, it takes any creator
/// string, so a stored record whose owner is not a DID is refused by its
/// id check rather than by a parse.
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
    use ::acp::domain::{Did, PolicyOrigin};

    use super::*;

    fn compiled(text: &str) -> ProcessedPolicy {
        ::acp::policy::compile_text(text, None, None)
            .unwrap()
            .policy
    }

    /// Vectors from acp's `conformance/vectors/policy-id.json`.
    const VECTORS: &[(&str, &str, &str, &str, &str)] = &[
        (
            r#"{"name": "docs", "resources": [{"name": "doc", "relations": [{"name": "reader", "types": ["actor"]}], "permissions": [{"name": "read", "expr": "reader"}]}]}"#,
            "0000000000000000000000000000000000000000000000000000000000000000",
            "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
            "be8e80e54d3b5b355abb5e5575467b36a57f6d4cdb71ab6af36ba78bbf19932b",
            "07882f5b8f69b2a95b6409bee9f3981c8aeae8d6135292e07f9f9a641eb75d0b",
        ),
        (
            r#"{"name": "files", "description": "every construct", "meta": {"team": "storage", "tier": "1"}, "resources": [{"name": "file", "description": "a file", "relations": [{"name": "admin", "doc": "administers", "manages": ["reader", "parent"], "types": ["actor"]}, {"name": "parent", "types": ["dir"]}, {"name": "reader", "doc": "may read", "types": ["actor", "group->member"]}, {"name": "banned", "types": ["actor"]}], "permissions": [{"name": "read", "doc": "read it", "expr": "reader + admin + parent->read - banned"}, {"name": "edit", "expr": "(admin & reader) + parent->edit"}, {"name": "delete"}]}, {"name": "dir", "relations": [{"name": "viewer", "types": ["actor"]}], "permissions": [{"name": "read", "expr": "viewer"}, {"name": "edit"}]}, {"name": "group", "relations": [{"name": "member", "types": ["actor", "group->member"]}]}]}"#,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
            "2c80494b55154f1fe4426a61142986b8fe2881b9fb8337ad8ab8889fcc5d37c0",
            "a0c9cda242310d142bf570e564a0837fd9be847ad85e8ab0054a626ff9cbab8a",
        ),
    ];

    #[test]
    fn reproduces_acp_vectors() {
        for (text, nonce, creator, hash, id) in VECTORS {
            let policy_hash = policy_hash(&compiled(text));
            assert_eq!(policy_hash.to_string(), *hash);
            assert_eq!(
                policy_id(&policy_hash, &nonce.parse().unwrap(), creator),
                *id
            );
        }
    }

    #[test]
    fn id_is_acps_id() {
        let policy = compiled("name: p\nresources:\n  - name: file\n");
        let hash = policy_hash(&policy);
        let nonce = PolicyNonce([7; 32]);
        let creator = "did:key:a";
        let origin = PolicyOrigin {
            creator: Did::parse(creator).unwrap(),
            nonce: ::acp::domain::PolicyNonce(nonce.0),
        };
        let acp_id = ::acp::ppp::policy_id(&::acp::domain::PolicyHash(hash.0), &origin);
        assert_eq!(policy_id(&hash, &nonce, creator), acp_id.as_str());
    }

    #[test]
    fn id_binds_hash_nonce_and_creator() {
        let hash = policy_hash(&compiled("name: p\nresources:\n  - name: file\n"));
        let id = policy_id(&hash, &PolicyNonce::default(), "did:key:a");
        assert_eq!(id.len(), 64);
        assert_ne!(id, policy_id(&hash, &PolicyNonce([1; 32]), "did:key:a"));
        assert_ne!(id, policy_id(&hash, &PolicyNonce::default(), "did:key:b"));
        let other = policy_hash(&compiled("name: q\nresources:\n  - name: file\n"));
        assert_ne!(hash, other);
        assert_eq!(
            hash.to_string().parse::<PolicyHash>().unwrap(),
            hash,
            "hex round trip"
        );
    }
}
