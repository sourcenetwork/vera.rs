use super::*;
use crate::vera::objects::{EncryptedDocument, MAX_PET_FIELD_BYTES, ObjectKind, ThresholdObject};

const TAG: &str = r#"{"ephemeral_point":[1,1],"masked_fingerprint":[2,2]}"#;
const TAG_PROOF: &str = r#"{"challenge":[3,3],"response":[4,4]}"#;

#[test]
fn document_registration_enforces_immutable_pet_mode_and_preserves_atomicity() {
    for requires_pet in [false, true] {
        let (mut vera, mut acp, mut config) = fixture(POLICY);
        config.requires_pet = requires_pet;
        let ring = apply(&mut vera, &mut acp, &RingCommand::Create(config.clone()), 1).unwrap();
        let keys = RingPublicKeys {
            public_key: "aabb".into(),
            pet_public_key: requires_pet.then(|| "ccdd".into()),
        };
        for node in [2, 3] {
            vera.apply_ring_participant_request(
                &context(),
                &participant(
                    &ring.id,
                    &secret(node),
                    RingParticipantCommand::Confirm(keys.clone()),
                ),
            )
            .unwrap();
        }
        let document = EncryptedDocument {
            ring_id: ring.id,
            document: r#"{"enc_cmt":[1],"encrypted_data":[2],"nonce":[3]}"#.into(),
            proof: r#"{"challenge":[4],"response":[5]}"#.into(),
            policy_id: config.policy_id,
            resource: "document".into(),
            permission: "read".into(),
            tier: None,
            timestamp: Some(80),
            pet_tag: requires_pet.then(|| TAG.into()),
            pet_tag_proof: requires_pet.then(|| TAG_PROOF.into()),
        };
        let mut wrong_mode = document.clone();
        wrong_mode.pet_tag = (!requires_pet).then(|| TAG.into());
        wrong_mode.pet_tag_proof = (!requires_pet).then(|| TAG_PROOF.into());
        let mut tag_only = document.clone();
        tag_only.pet_tag = Some(TAG.into());
        tag_only.pet_tag_proof = None;
        let mut proof_only = document.clone();
        proof_only.pet_tag = None;
        proof_only.pet_tag_proof = Some(TAG_PROOF.into());
        let mut malformed = document.clone();
        malformed.pet_tag = Some(format!("{TAG} trailing"));
        malformed.pet_tag_proof = Some(TAG_PROOF.into());
        let mut oversized = document.clone();
        oversized.pet_tag = Some(" ".repeat(MAX_PET_FIELD_BYTES + 1) + TAG);
        oversized.pet_tag_proof = Some(TAG_PROOF.into());
        for (entropy, rejected) in
            (10u8..).zip([wrong_mode, tag_only, proof_only, malformed, oversized])
        {
            let object = ThresholdObject::Document(rejected);
            let token = delegated_token(
                DelegatedOperation::StoreThresholdObject(&object),
                entropy,
                &context(),
                &secret(1),
            );
            let before = (vera.store().serialize(), acp.store().serialize());
            assert!(
                vera.store_threshold_object(&mut acp, &context(), &submission(), &token, &object)
                    .is_err()
            );
            assert_eq!((vera.store().serialize(), acp.store().serialize()), before);
        }
        let object = ThresholdObject::Document(document.clone());
        let token = delegated_token(
            DelegatedOperation::StoreThresholdObject(&object),
            30,
            &context(),
            &secret(1),
        );
        let stored = vera
            .store_threshold_object(&mut acp, &context(), &submission(), &token, &object)
            .unwrap();
        assert_eq!(stored.id, object.id().unwrap());
        assert_eq!(
            vera.store_threshold_object(&mut acp, &context(), &submission(), &token, &object)
                .unwrap(),
            stored
        );
        let reopened = VeraModule::from_store(
            crate::kv_store::InMemoryKvStore::deserialize(&vera.store().serialize()).unwrap(),
        );
        assert_eq!(
            reopened
                .threshold_object(ObjectKind::Document, &stored.id)
                .unwrap()
                .unwrap()
                .object,
            object
        );

        let mut changed = document;
        if requires_pet {
            changed.pet_tag_proof = Some(r#"{"challenge":[3,3],"response":[4,5]}"#.into());
        } else {
            changed.timestamp = Some(81);
        }
        let changed = ThresholdObject::Document(changed);
        let before = (vera.store().serialize(), acp.store().serialize());
        assert!(
            vera.store_threshold_object(&mut acp, &context(), &submission(), &token, &changed)
                .is_err()
        );
        assert_eq!((vera.store().serialize(), acp.store().serialize()), before);

        let assertion = delegated_token(
            DelegatedOperation::StoreThresholdObject(&changed),
            31,
            &context(),
            &secret(1),
        );
        let mut full = acp.store().clone();
        full.put(b"operation-bytes/v1", (64u64 << 20).to_be_bytes().to_vec());
        let mut full = AcpModule::from_store(full);
        let before = (vera.store().serialize(), full.store().serialize());
        assert!(
            vera.store_threshold_object(&mut full, &context(), &submission(), &assertion, &changed)
                .is_err()
        );
        assert_eq!((vera.store().serialize(), full.store().serialize()), before);
        assert!(
            vera.threshold_object(ObjectKind::Document, &changed.id().unwrap())
                .unwrap()
                .is_none()
        );
    }
}
