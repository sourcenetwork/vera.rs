use super::*;
use vera_modules::{acp::types::RecordMetadata, types::Timestamp};
use vera_zanzibar::Relationship;

fn object() -> Object {
    Object {
        resource: "document".into(),
        id: "report".into(),
    }
}
fn record() -> RelationshipRecord {
    RelationshipRecord {
        incarnation: 0,
        generations: RelationPair {
            target: 0,
            subject: 0,
        },
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
fn read(records: &[RelationshipRecord]) -> Result<ObjectRegistration, PermissionError> {
    let pairs: Vec<_> = records
        .iter()
        .map(|record| {
            (
                keys::relationship_key(
                    &record.policy_id,
                    &keys::relationship_storage_key(&record.relationship, record.incarnation),
                ),
                serde_json::to_vec(record).unwrap(),
            )
        })
        .collect();
    registration(
        pairs
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
        "policy",
        &object(),
    )
}

#[test]
fn live_owner_is_distinct_from_archived_or_absent_registration() {
    assert_eq!(read(&[]).unwrap(), ObjectRegistration::Absent);
    let record = record();
    let expected = if let Subject::Entity(did) = &record.relationship.subject {
        did.clone()
    } else {
        unreachable!()
    };
    assert_eq!(
        read(std::slice::from_ref(&record)).unwrap(),
        ObjectRegistration::Live(Actor(expected))
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
    assert_eq!(
        read(std::slice::from_ref(&archived)).unwrap(),
        ObjectRegistration::Archived
    );
    assert!(matches!(
        read(&[archived, other]).unwrap(),
        ObjectRegistration::Live(_)
    ));
}

#[test]
fn owner_records_and_queries_cannot_change_the_selected_object() {
    for field in 0..7 {
        let mut record = record();
        match field {
            0 => record.policy_id = "other".into(),
            1 => record.relationship.resource = "other".into(),
            2 => record.relationship.object_id = "other".into(),
            3 => record.relationship.relation = "reader".into(),
            4 => record.relationship.subject = Subject::Wildcard,
            5 => record.generations.target = 1,
            _ => record.generations.subject = 1,
        }
        assert!(read(&[record]).is_err());
    }
    let record = record();
    let value = serde_json::to_vec(&record).unwrap();
    assert!(
        registration(
            [(b"wrong-key".as_slice(), value.as_slice())],
            "policy",
            &object()
        )
        .is_err()
    );
    assert!(registration([(b"key".as_slice(), b"{".as_slice())], "policy", &object()).is_err());
    for value in ["", "a/b", "a\\b"] {
        assert!(object_owner_prefix(value, &object()).is_err());
    }
    for (resource, id) in [("", "report"), ("document", "")] {
        let object = Object {
            resource: resource.into(),
            id: id.into(),
        };
        assert!(object_owner_prefix("policy", &object).is_err());
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

#[test]
fn owner_records_cannot_select_a_nonzero_incarnation() {
    let mut record = record();
    record.incarnation = 1;
    assert!(read(&[record]).is_err());
}

#[test]
fn path_like_object_identifiers_have_an_owner() {
    for id in ["report/child", "reports\\2026\\q3"] {
        let object = Object {
            resource: "document".into(),
            id: id.into(),
        };
        let mut record = record();
        record.relationship.object_id = id.into();
        let key = keys::relationship_key(
            "policy",
            &keys::relationship_storage_key(&record.relationship, 0),
        );
        assert!(key.starts_with(&object_owner_prefix("policy", &object).unwrap()));
        assert!(!key.starts_with(&object_owner_prefix("policy", &self::object()).unwrap()));
        let value = serde_json::to_vec(&record).unwrap();
        let ObjectRegistration::Live(owner) =
            registration([(key.as_slice(), value.as_slice())], "policy", &object).unwrap()
        else {
            panic!("expected a live owner");
        };
        assert_eq!(
            owner.0.as_str(),
            "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
        );
    }
}
