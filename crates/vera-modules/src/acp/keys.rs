//! ACP module key prefixes and builders.
//!
//! Native relationship keys use an explicit canonical format. Auto-increment stores use
//! `objs/` and `counter/` sub-prefixes as defined by the mod.rs
//! storage spec.

/// Policy record prefix (string-keyed by policy ID).
pub const POLICY_PREFIX: &[u8] = b"policy/objs/";
/// Policy autoincrement counter key.
pub const POLICY_COUNTER_KEY: &[u8] = b"policy/counter/id";
/// Relationship prefix: `relationship/ + policy_id + "/" + storage_key`.
pub const RELATIONSHIP_PREFIX: &[u8] = b"relationship/";
/// Access decision prefix (string-keyed objects).
pub const ACCESS_DECISION_PREFIX: &[u8] = b"access_decision/";
/// Registration commitment prefix (auto-increment objects).
pub const COMMITMENT_PREFIX: &[u8] = b"commitment/";
/// Amendment event prefix (auto-increment objects).
pub const AMENDMENT_EVENT_PREFIX: &[u8] = b"amendment_event/";
/// Signed policy command replay cache prefix.
/// Module parameters key.
pub const PARAMS_KEY: &[u8] = b"p_acp";

/// Object storage sub-prefix (within auto-increment stores).
pub const OBJS_SUBPREFIX: &[u8] = b"objs/";
/// Counter sub-prefix (within auto-increment stores).
pub const COUNTER_SUBPREFIX: &[u8] = b"counter/";

/// Policy record key: `"policy/objs/" + policy_id`.
pub fn policy_key(id: &str) -> Vec<u8> {
    let mut key = Vec::from(POLICY_PREFIX);
    key.extend_from_slice(id.as_bytes());
    key
}

/// Canonical native key suffix, independent of the shared engine's storage format.
pub fn relationship_storage_key(relationship: &acp::Relationship) -> String {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"vera/acp-subject/v1\0");
    digest
        .update(serde_json::to_vec(&relationship.subject).expect("serialize relationship subject"));
    format!(
        "{}{}",
        relation_prefix(
            &relationship.resource,
            &relationship.object_id,
            &relationship.relation
        ),
        hex::encode(digest.finalize())
    )
}

/// Exact resource boundary for relationship queries.
pub fn resource_prefix(resource: &str) -> String {
    format!("v2/{}/", hex::encode(resource))
}

/// Exact object boundary, including when identifiers contain path separators.
pub fn object_prefix(resource: &str, object_id: &str) -> String {
    format!("{}{}/", resource_prefix(resource), hex::encode(object_id))
}

/// Exact relation boundary within an object.
pub fn relation_prefix(resource: &str, object_id: &str, relation: &str) -> String {
    format!(
        "{}{}/",
        object_prefix(resource, object_id),
        hex::encode(relation)
    )
}

/// Relationship key: `"relationship/" + policy_id + "/" + storage_key`.
pub fn relationship_key(policy_id: &str, storage_key: &str) -> Vec<u8> {
    let mut key = Vec::from(RELATIONSHIP_PREFIX);
    key.extend_from_slice(policy_id.as_bytes());
    key.push(b'/');
    key.extend_from_slice(storage_key.as_bytes());
    key
}

/// Prefix for scanning all relationships under a policy.
pub fn relationship_policy_prefix(policy_id: &str) -> Vec<u8> {
    let mut key = Vec::from(RELATIONSHIP_PREFIX);
    key.extend_from_slice(policy_id.as_bytes());
    key.push(b'/');
    key
}

/// Prefix for scanning relationships matching a storage key prefix within a policy.
pub fn relationship_storage_prefix(policy_id: &str, storage_prefix: &str) -> Vec<u8> {
    let mut key = relationship_policy_prefix(policy_id);
    key.extend_from_slice(storage_prefix.as_bytes());
    key
}

/// Access decision key: `prefix + decision_id`.
pub fn access_decision_key(decision_id: &str) -> Vec<u8> {
    let mut key = Vec::from(ACCESS_DECISION_PREFIX);
    key.extend_from_slice(decision_id.as_bytes());
    key
}

/// Commitment object key: `"commitment/objs/" + BE(id)`.
pub fn commitment_key(id: u64) -> Vec<u8> {
    let mut key = Vec::from(COMMITMENT_PREFIX);
    key.extend_from_slice(OBJS_SUBPREFIX);
    key.extend_from_slice(&id.to_be_bytes());
    key
}

/// Commitment counter key: `"commitment/counter/id"`.
pub fn commitment_counter_key() -> Vec<u8> {
    let mut key = Vec::from(COMMITMENT_PREFIX);
    key.extend_from_slice(COUNTER_SUBPREFIX);
    key.extend_from_slice(b"id");
    key
}

/// Amendment event object key: `"amendment_event/objs/" + BE(id)`.
pub fn amendment_event_key(id: u64) -> Vec<u8> {
    let mut key = Vec::from(AMENDMENT_EVENT_PREFIX);
    key.extend_from_slice(OBJS_SUBPREFIX);
    key.extend_from_slice(&id.to_be_bytes());
    key
}

/// Amendment event counter key: `"amendment_event/counter/id"`.
pub fn amendment_event_counter_key() -> Vec<u8> {
    let mut key = Vec::from(AMENDMENT_EVENT_PREFIX);
    key.extend_from_slice(COUNTER_SUBPREFIX);
    key.extend_from_slice(b"id");
    key
}

/// Commitment expired-index key: `"commitment/indexes/expired/idx/" + bool_byte + "/" + BE(id)`.
pub fn commitment_expired_index_key(expired: bool, id: u64) -> Vec<u8> {
    let mut key = commitment_expired_index_prefix(expired);
    key.extend_from_slice(&id.to_be_bytes());
    key
}

/// Prefix for scanning commitments with a given expired status.
pub fn commitment_expired_index_prefix(expired: bool) -> Vec<u8> {
    let mut key = Vec::from(COMMITMENT_PREFIX);
    key.extend_from_slice(b"indexes/expired/idx/");
    key.push(u8::from(expired));
    key.push(b'/');
    key
}

/// Commitment-by-root index key: `"commitment/indexes/commitment/idx/" + root_bytes + "/" + BE(id)`.
pub fn commitment_by_commitment_index_key(root: &[u8], id: u64) -> Vec<u8> {
    let mut key = commitment_by_commitment_index_prefix(root);
    key.extend_from_slice(&id.to_be_bytes());
    key
}

/// Prefix for scanning commitments by Merkle root.
pub fn commitment_by_commitment_index_prefix(root: &[u8]) -> Vec<u8> {
    let mut key = Vec::from(COMMITMENT_PREFIX);
    key.extend_from_slice(b"indexes/commitment/idx/");
    key.extend_from_slice(root);
    key.push(b'/');
    key
}

/// Commitment policy-index key: `"commitment/indexes/policy/idx/" + policy_id + "/" + BE(id)`.
pub fn commitment_policy_index_key(policy_id: &str, id: u64) -> Vec<u8> {
    let mut key = commitment_policy_index_prefix(policy_id);
    key.extend_from_slice(&id.to_be_bytes());
    key
}

/// Prefix for scanning all commitments, including expired records, under a policy.
pub fn commitment_policy_index_prefix(policy_id: &str) -> Vec<u8> {
    let mut key = Vec::from(COMMITMENT_PREFIX);
    key.extend_from_slice(b"indexes/policy/idx/");
    key.extend_from_slice(policy_id.as_bytes());
    key.push(b'/');
    key
}

/// Amendment event policy-index key: `"amendment_event/indexes/policy/idx/" + policy_id + "/" + BE(id)`.
pub fn amendment_event_policy_index_key(policy_id: &str, id: u64) -> Vec<u8> {
    let mut key = amendment_event_policy_index_prefix(policy_id);
    key.extend_from_slice(&id.to_be_bytes());
    key
}

/// Prefix for scanning amendment events by policy ID.
pub fn amendment_event_policy_index_prefix(policy_id: &str) -> Vec<u8> {
    let mut key = Vec::from(AMENDMENT_EVENT_PREFIX);
    key.extend_from_slice(b"indexes/policy/idx/");
    key.extend_from_slice(policy_id.as_bytes());
    key.push(b'/');
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_relationship_key_format() {
        let relationship =
            acp::Relationship::new("file", "report/child", "reader", acp::Subject::Wildcard);
        assert_eq!(
            relationship_storage_key(&relationship),
            "v2/66696c65/7265706f72742f6368696c64/726561646572/00414ab1420d5a968b2ab88ef68b22497b031cd04a26bf22380cb3f845fa18b1"
        );
        assert!(
            !relationship_storage_key(&relationship).starts_with(&object_prefix("file", "report"))
        );
        assert!(
            relationship_storage_key(&relationship).starts_with(&relation_prefix(
                "file",
                "report/child",
                "reader"
            ))
        );
        assert_ne!(object_prefix("a/b", "c"), object_prefix("a", "b/c"));
    }

    #[test]
    fn access_decision_key_format() {
        let key = access_decision_key("ABCDEF123");
        assert!(key.starts_with(ACCESS_DECISION_PREFIX));
        assert_eq!(&key[ACCESS_DECISION_PREFIX.len()..], b"ABCDEF123");
    }

    #[test]
    fn commitment_policy_index_has_a_delimited_policy_and_ordered_id() {
        assert_eq!(
            commitment_policy_index_key("policy", 42),
            b"commitment/indexes/policy/idx/policy/\x00\x00\x00\x00\x00\x00\x00\x2a"
        );
        assert!(
            !commitment_policy_index_key("policy-other", 42)
                .starts_with(&commitment_policy_index_prefix("policy"))
        );
        assert!(
            commitment_policy_index_key("policy", 255) < commitment_policy_index_key("policy", 256)
        );
    }

    #[test]
    fn commitment_key_big_endian() {
        let key = commitment_key(42);
        let id_bytes = &key[key.len() - 8..];
        assert_eq!(u64::from_be_bytes(id_bytes.try_into().unwrap()), 42);
    }

    #[test]
    fn commitment_key_includes_objs_subprefix() {
        let key = commitment_key(1);
        let prefix_len = COMMITMENT_PREFIX.len() + OBJS_SUBPREFIX.len();
        let key_str = String::from_utf8_lossy(&key[..prefix_len]);
        assert_eq!(key_str, "commitment/objs/");
    }

    #[test]
    fn counter_keys_are_stable() {
        let ck = commitment_counter_key();
        assert_eq!(ck, b"commitment/counter/id");

        let ak = amendment_event_counter_key();
        assert_eq!(ak, b"amendment_event/counter/id");
    }

    #[test]
    fn amendment_event_key_big_endian() {
        let key = amendment_event_key(256);
        let id_bytes = &key[key.len() - 8..];
        assert_eq!(u64::from_be_bytes(id_bytes.try_into().unwrap()), 256);
    }

    #[test]
    fn borsh_roundtrip_access_decision() {
        use borsh::BorshDeserialize;

        use crate::acp::types::{AccessDecision, DecisionParams, Object, Operation};
        use crate::types::Timestamp;

        let decision = AccessDecision {
            id: "DECISION123".into(),
            policy_id: "pol1".into(),
            creator: "did:key:z6Mk".into(),
            creator_acc_sequence: 5,
            operations: vec![Operation {
                object: Object {
                    resource: "namespace".into(),
                    id: "ns1".into(),
                },
                permission: "create_post".into(),
            }],
            actor: "did:key:z6Mk".into(),
            params: DecisionParams {
                decision_expiration_delta: 100,
                proof_expiration_delta: 50,
                ticket_expiration_delta: 100,
            },
            creation_time: Timestamp {
                seconds: 1000,
                block_height: 42,
            },
            issued_height: 42,
        };
        let encoded = borsh::to_vec(&decision).unwrap();
        let decoded = AccessDecision::try_from_slice(&encoded).unwrap();
        assert_eq!(decision, decoded);
    }

    #[test]
    fn borsh_roundtrip_registrations_commitment() {
        use borsh::BorshDeserialize;

        use crate::acp::types::{RecordMetadata, RegistrationsCommitment};
        use crate::types::{Duration, Timestamp};

        let commitment = RegistrationsCommitment {
            id: 1,
            policy_id: "pol1".into(),
            commitment: vec![0xAB; 32],
            expired: false,
            validity: Duration::Seconds(600),
            metadata: RecordMetadata {
                creation_ts: Timestamp {
                    seconds: 500,
                    block_height: 10,
                },
                tx_hash: vec![0xCD; 32],
                tx_signer: "0x1234".into(),
                owner_did: "did:key:z6Mk".into(),
            },
        };
        let encoded = borsh::to_vec(&commitment).unwrap();
        let decoded = RegistrationsCommitment::try_from_slice(&encoded).unwrap();
        assert_eq!(commitment, decoded);
    }

    #[test]
    fn borsh_roundtrip_amendment_event() {
        use borsh::BorshDeserialize;
        use identity::Did;

        use crate::acp::types::{Actor, AmendmentEvent, Object, RecordMetadata};
        use crate::types::Timestamp;

        let event = AmendmentEvent {
            id: 7,
            policy_id: "pol1".into(),
            object: Object {
                resource: "namespace".into(),
                id: "obj1".into(),
            },
            new_owner: Actor(
                Did::new("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap(),
            ),
            previous_owner: Actor(
                Did::new("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap(),
            ),
            commitment_id: 1,
            hijack_flag: false,
            metadata: RecordMetadata {
                creation_ts: Timestamp {
                    seconds: 500,
                    block_height: 10,
                },
                tx_hash: vec![0xEF; 32],
                tx_signer: "0x5678".into(),
                owner_did: "did:key:z6Mk".into(),
            },
        };
        let encoded = borsh::to_vec(&event).unwrap();
        let decoded = AmendmentEvent::try_from_slice(&encoded).unwrap();
        assert_eq!(event, decoded);
    }
}
