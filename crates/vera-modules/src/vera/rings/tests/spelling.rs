//! Rings and threshold objects created under each spelling of one actor key.

use super::*;
use crate::vera::objects::{EncryptedDocument, ObjectKind, ThresholdObject};

/// Compressed and uncompressed points, in Base58BTC and then Base64URL.
fn spellings() -> [String; 4] {
    let bytes = |compressed| {
        let mut bytes = vec![0xe7, 0x01];
        bytes.extend_from_slice(
            secret(1)
                .verifying_key()
                .to_encoded_point(compressed)
                .as_bytes(),
        );
        bytes
    };
    [
        format!("did:key:z{}", bs58::encode(bytes(true)).into_string()),
        format!("did:key:z{}", bs58::encode(bytes(false)).into_string()),
        format!("did:key:u{}", URL_SAFE_NO_PAD.encode(bytes(true))),
        format!("did:key:u{}", URL_SAFE_NO_PAD.encode(bytes(false))),
    ]
}

fn document(ring: &str, policy: &str) -> ThresholdObject {
    ThresholdObject::Document(EncryptedDocument {
        ring_id: ring.into(),
        document: r#"{"enc_cmt":[1],"encrypted_data":[2],"nonce":[3]}"#.into(),
        proof: r#"{"challenge":[4],"response":[5]}"#.into(),
        policy_id: policy.into(),
        resource: "document".into(),
        permission: "read".into(),
        tier: None,
        timestamp: Some(80),
        pet_tag: None,
        pet_tag_proof: None,
    })
}

#[test]
fn a_ring_and_its_objects_have_one_creator_for_every_issuer_spelling() {
    let canonical = actor().to_string();
    assert_eq!(spellings()[0], canonical);
    let mut records = Vec::new();
    for (written, issuer) in spellings().into_iter().enumerate() {
        let other = spellings()[(written + 1) % 4].clone();
        let (mut vera, mut acp, config) = fixture(POLICY);
        let create = RingCommand::Create(config.clone());
        let ring = vera
            .apply_ring_command(
                &mut acp,
                &context(),
                &submission(),
                &spelled_token(
                    DelegatedOperation::RingCommand(&create),
                    1,
                    &context(),
                    &secret(1),
                    issuer,
                ),
                &create,
            )
            .unwrap();
        assert_eq!(ring.creator, canonical);
        assert_eq!(ring.id, config.id().unwrap());
        let owner = acp
            .query_object_owner(
                &config.policy_id,
                &Object {
                    resource: "ring".into(),
                    id: ring.id.clone(),
                },
            )
            .unwrap()
            .1
            .unwrap();
        assert_eq!(owner.metadata.owner_did, canonical);

        let mut cancelled = (vera.clone(), acp.clone());
        let cancel = RingCommand::Cancel {
            ring_id: ring.id.clone(),
        };
        let record = cancelled
            .0
            .apply_ring_command(
                &mut cancelled.1,
                &context(),
                &submission(),
                &spelled_token(
                    DelegatedOperation::RingCommand(&cancel),
                    2,
                    &context(),
                    &secret(1),
                    other.clone(),
                ),
                &cancel,
            )
            .unwrap();
        assert_eq!(
            record.state,
            RingState::Cancelled {
                by: canonical.clone()
            }
        );

        for node in [2, 3] {
            vera.apply_ring_participant_request(&context(), &confirm(&ring.id, node, "aabb"))
                .unwrap();
        }
        let object = document(&ring.id, &config.policy_id);
        let stored = vera
            .store_threshold_object(
                &mut acp,
                &context(),
                &submission(),
                &spelled_token(
                    DelegatedOperation::StoreThresholdObject(&object),
                    3,
                    &context(),
                    &secret(1),
                    other,
                ),
                &object,
            )
            .unwrap();
        let object = vera
            .threshold_object(ObjectKind::Document, &stored.id)
            .unwrap()
            .unwrap();
        assert_eq!(object.creator, canonical);
        records.push((
            serde_json::to_value(&ring).unwrap(),
            serde_json::to_value(&object).unwrap(),
            acp.store().serialize(),
        ));
    }
    assert!(records.windows(2).all(|pair| pair[0] == pair[1]));
}

#[test]
fn stored_records_must_name_their_creator_canonically() {
    let (mut vera, mut acp, config) = fixture(POLICY);
    let ring = apply(&mut vera, &mut acp, &RingCommand::Create(config.clone()), 1).unwrap();
    ring.validate(&ring.id).unwrap();
    for written in &spellings()[1..] {
        let mut respelled = ring.clone();
        respelled.creator.clone_from(written);
        assert!(respelled.validate(&ring.id).is_err());
        respelled = ring.clone();
        respelled.state = RingState::Cancelled {
            by: written.clone(),
        };
        assert!(respelled.validate(&ring.id).is_err());
    }
    for node in [2, 3] {
        vera.apply_ring_participant_request(&context(), &confirm(&ring.id, node, "aabb"))
            .unwrap();
    }
    let object = document(&ring.id, &config.policy_id);
    let token = delegated_token(
        DelegatedOperation::StoreThresholdObject(&object),
        3,
        &context(),
        &secret(1),
    );
    let stored = vera
        .store_threshold_object(&mut acp, &context(), &submission(), &token, &object)
        .unwrap();
    let record = vera
        .threshold_object(ObjectKind::Document, &stored.id)
        .unwrap()
        .unwrap();
    record.validate(ObjectKind::Document, &stored.id).unwrap();
    for written in &spellings()[1..] {
        let mut respelled = record.clone();
        respelled.creator.clone_from(written);
        assert!(
            respelled
                .validate(ObjectKind::Document, &stored.id)
                .is_err()
        );
    }
}
