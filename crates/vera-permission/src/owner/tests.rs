use super::*;
use vera_modules::{acp::types::RecordMetadata, types::Timestamp};

fn object() -> Object {
    Object {
        resource: "document".into(),
        id: "report".into(),
    }
}
fn record() -> RelationshipRecord {
    RelationshipRecord {
        supplied_metadata: Default::default(),
        policy_id: "policy".into(),
        relationship: Relationship::with_entity(
            "document",
            "report",
            "owner",
            "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
                .parse()
                .unwrap(),
        ),
        archived: false,
        metadata: RecordMetadata {
            creation_ts: Timestamp {
                seconds: 1,
                block_height: 1,
            },
            tx_hash: vec![],
            tx_signer: String::new(),
            owner_did: String::new(),
        },
    }
}
fn read(records: &[RelationshipRecord]) -> Result<Option<Actor>, PermissionError> {
    let pairs: Vec<_> = records
        .iter()
        .map(|record| {
            (
                keys::relationship_key(
                    &record.policy_id,
                    &keys::relationship_storage_key(&record.relationship),
                ),
                serde_json::to_vec(record).unwrap(),
            )
        })
        .collect();
    owner(
        pairs
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
        "policy",
        &object(),
    )
}

#[test]
fn live_owner_is_distinct_from_archived_or_absent_registration() {
    assert!(read(&[]).unwrap().is_none());
    let record = record();
    let expected = if let Subject::Entity(did) = &record.relationship.subject {
        did.clone()
    } else {
        unreachable!()
    };
    assert_eq!(
        read(std::slice::from_ref(&record)).unwrap(),
        Some(Actor(expected))
    );
    let mut other = record.clone();
    other.relationship.subject = Subject::Entity(
        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            .parse()
            .unwrap(),
    );
    assert!(read(&[record.clone(), other.clone()]).is_err());
    let mut archived = record;
    archived.archived = true;
    assert!(read(std::slice::from_ref(&archived)).unwrap().is_none());
    assert!(read(&[archived, other]).unwrap().is_some());
}

#[test]
fn owner_records_and_queries_cannot_change_the_selected_object() {
    for field in 0..5 {
        let mut record = record();
        match field {
            0 => record.policy_id = "other".into(),
            1 => record.relationship.resource = "other".into(),
            2 => record.relationship.object_id = "other".into(),
            3 => record.relationship.relation = "reader".into(),
            _ => record.relationship.subject = Subject::Wildcard,
        }
        assert!(read(&[record]).is_err());
    }
    let record = record();
    let value = serde_json::to_vec(&record).unwrap();
    assert!(
        owner(
            [(b"wrong-key".as_slice(), value.as_slice())],
            "policy",
            &object()
        )
        .is_err()
    );
    assert!(owner([(b"key".as_slice(), b"{".as_slice())], "policy", &object()).is_err());
    for value in ["", "a/b", "a\\b"] {
        assert!(object_owner_prefix(value, &object()).is_err());
        assert!(
            object_owner_prefix(
                "policy",
                &Object {
                    resource: value.into(),
                    id: "report".into()
                }
            )
            .is_err()
        );
        assert!(
            object_owner_prefix(
                "policy",
                &Object {
                    resource: "document".into(),
                    id: value.into()
                }
            )
            .is_err()
        );
    }
    assert!(
        object_owner_prefix(
            "policy",
            &Object {
                resource: "document".into(),
                id: "x".repeat(MAX_KEY_BYTES)
            }
        )
        .is_err()
    );
}
