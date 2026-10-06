use super::*;
use sha2::{Digest as _, Sha256};

fn pet_keys() -> RingPublicKeys {
    RingPublicKeys {
        public_key: "aabb".into(),
        pet_public_key: Some("ccdd".into()),
    }
}

#[test]
fn paired_confirmations_reject_missing_unexpected_and_noncanonical_keys_without_mutation() {
    for requires_pet in [false, true] {
        let (mut vera, mut acp, mut config) = fixture(POLICY);
        config.requires_pet = requires_pet;
        let record = apply(&mut vera, &mut acp, &RingCommand::Create(config), 1).unwrap();
        let valid = if requires_pet {
            pet_keys()
        } else {
            ring_keys("aabb")
        };
        let wrong_mode = if requires_pet {
            ring_keys("aabb")
        } else {
            pet_keys()
        };
        let mut invalid = vec![wrong_mode];
        for value in ["", "abc", "AABB", "not-hex"] {
            let mut keys = valid.clone();
            keys.public_key = value.into();
            invalid.push(keys);
            if requires_pet {
                let mut keys = valid.clone();
                keys.pet_public_key = Some(value.into());
                invalid.push(keys);
            }
        }
        let mut oversized = valid.clone();
        oversized.public_key = "aa".repeat(4097);
        invalid.push(oversized);
        if requires_pet {
            let mut oversized = valid.clone();
            oversized.pet_public_key = Some("aa".repeat(4097));
            invalid.push(oversized);
        }
        let before = vera.store().serialize();
        for keys in invalid {
            let request = participant(
                &record.id,
                &secret(2),
                RingParticipantCommand::Confirm(keys),
            );
            assert!(
                vera.apply_ring_participant_request(&context(), &request)
                    .is_err()
            );
            assert_eq!(vera.store().serialize(), before);
        }
        let request = participant(
            &record.id,
            &secret(2),
            RingParticipantCommand::Confirm(valid),
        );
        vera.apply_ring_participant_request(&context(), &request)
            .unwrap();
    }
    let maximum = RingPublicKeys {
        public_key: "ab".repeat(4096),
        pet_public_key: Some("cd".repeat(4096)),
    };
    maximum.validate(true).unwrap();
}

#[test]
fn pet_only_disagreement_is_a_terminal_conflict_and_survives_readback() {
    let (mut vera, mut acp, mut config) = fixture(POLICY);
    config.requires_pet = true;
    let command = RingCommand::Create(config);
    let record = apply(&mut vera, &mut acp, &command, 1).unwrap();
    let first = pet_keys();
    let mut second = first.clone();
    second.pet_public_key = Some("eeff".into());
    for (node, keys) in [(2, first.clone()), (3, second.clone())] {
        vera.apply_ring_participant_request(
            &context(),
            &participant(
                &record.id,
                &secret(node),
                RingParticipantCommand::Confirm(keys),
            ),
        )
        .unwrap();
    }
    let expected = RingState::Conflict {
        first_keys: first.clone(),
        conflicting_keys: second,
        by: public(&secret(3)),
    };
    let mut restored = VeraModule::from_store(vera.store().clone());
    assert_eq!(
        restored.threshold_ring(&record.id).unwrap().unwrap().state,
        expected
    );
    let before = restored.store().serialize();
    for command in [
        RingParticipantCommand::Confirm(first),
        RingParticipantCommand::Cancel,
    ] {
        assert!(
            restored
                .apply_ring_participant_request(
                    &context(),
                    &participant(&record.id, &secret(3), command),
                )
                .is_err()
        );
        assert_eq!(restored.store().serialize(), before);
    }
    assert!(apply(&mut restored, &mut acp, &command, 2).is_err());
}

#[test]
fn signed_pair_cannot_be_swapped_or_confirmed_under_the_old_domain() {
    let (mut vera, mut acp, mut config) = fixture(POLICY);
    config.requires_pet = true;
    let record = apply(&mut vera, &mut acp, &RingCommand::Create(config), 1).unwrap();
    let signed = participant(
        &record.id,
        &secret(2),
        RingParticipantCommand::Confirm(pet_keys()),
    );
    let mut swapped = signed.clone();
    swapped.request.command = RingParticipantCommand::Confirm(RingPublicKeys {
        public_key: "ccdd".into(),
        pet_public_key: Some("aabb".into()),
    });
    let mut changed_pet = signed.clone();
    changed_pet.request.command = RingParticipantCommand::Confirm(RingPublicKeys {
        public_key: "aabb".into(),
        pet_public_key: Some("eeff".into()),
    });
    let mut old_domain = signed.clone();
    let mut hash = Sha256::new();
    hash.update(b"vera/orbis/ring-participant/v1\0");
    hash.update(borsh::to_vec(&old_domain.request).unwrap());
    let signature: Signature = secret(2).sign_prehash(&hash.finalize()).unwrap();
    old_domain.signature = hex::encode(signature.to_bytes());
    let before = vera.store().serialize();
    for altered in [swapped, changed_pet, old_domain] {
        assert!(
            vera.apply_ring_participant_request(&context(), &altered)
                .is_err()
        );
        assert_eq!(vera.store().serialize(), before);
    }
    vera.apply_ring_participant_request(&context(), &signed)
        .unwrap();
}

#[test]
fn paired_activation_preserves_retry_cancellation_and_restored_state() {
    let (mut vera, mut acp, mut config) = fixture(POLICY);
    config.requires_pet = true;
    let command = RingCommand::Create(config.clone());
    let record = apply(&mut vera, &mut acp, &command, 1).unwrap();
    assert_eq!(apply(&mut vera, &mut acp, &command, 1).unwrap(), record);
    let first = participant(
        &record.id,
        &secret(2),
        RingParticipantCommand::Confirm(pet_keys()),
    );
    let pending = vera
        .apply_ring_participant_request(&context(), &first)
        .unwrap();
    assert_eq!(
        pending.state,
        RingState::Pending {
            keys: Some(pet_keys()),
            confirmations: vec![public(&secret(2))],
        }
    );
    let mut vera = VeraModule::from_store(vera.store().clone());
    assert_eq!(vera.threshold_ring(&record.id).unwrap(), Some(pending));
    let before = vera.store().serialize();
    assert!(
        vera.apply_ring_participant_request(&context(), &first)
            .is_err()
    );
    assert_eq!(vera.store().serialize(), before);
    let active = vera
        .apply_ring_participant_request(
            &context(),
            &participant(
                &record.id,
                &secret(3),
                RingParticipantCommand::Confirm(pet_keys()),
            ),
        )
        .unwrap();
    assert_eq!(active.state, RingState::Active { keys: pet_keys() });
    assert_eq!(
        VeraModule::from_store(vera.store().clone())
            .threshold_ring(&record.id)
            .unwrap(),
        Some(active)
    );
    let before = vera.store().serialize();
    assert!(
        vera.apply_ring_participant_request(
            &context(),
            &participant(&record.id, &secret(2), RingParticipantCommand::Cancel),
        )
        .is_err()
    );
    assert_eq!(vera.store().serialize(), before);

    config.nonce = [10; 32];
    let command = RingCommand::Create(config);
    let other = apply(&mut vera, &mut acp, &command, 2).unwrap();
    let cancelled = vera
        .apply_ring_participant_request(
            &context(),
            &participant(&other.id, &secret(2), RingParticipantCommand::Cancel),
        )
        .unwrap();
    assert!(matches!(cancelled.state, RingState::Cancelled { .. }));
    assert!(
        vera.apply_ring_participant_request(
            &context(),
            &participant(
                &other.id,
                &secret(3),
                RingParticipantCommand::Confirm(pet_keys())
            ),
        )
        .is_err()
    );
    assert!(apply(&mut vera, &mut acp, &command, 3).is_err());
    assert_eq!(vera.threshold_ring(&other.id).unwrap(), Some(cancelled));
}

#[test]
fn paired_state_readback_rejects_invalid_mode_and_legacy_shapes() {
    let (mut vera, mut acp, mut config) = fixture(POLICY);
    config.requires_pet = true;
    let record = apply(&mut vera, &mut acp, &RingCommand::Create(config.clone()), 1).unwrap();
    let mut missing_mode = serde_json::to_value(&config).unwrap();
    missing_mode.as_object_mut().unwrap().remove("requires_pet");
    assert!(serde_json::from_value::<RingConfig>(missing_mode).is_err());
    assert!(serde_json::from_str::<RingParticipantCommand>(r#"{"Confirm":"aabb"}"#).is_err());
    assert!(serde_json::from_str::<RingState>(r#"{"Active":{"public_key":"aabb"}}"#).is_err());
    assert!(
        serde_json::from_str::<RingPublicKeys>(
            r#"{"public_key":"aabb","pet_public_key":"ccdd","extra":0}"#
        )
        .is_err()
    );
    for state in [
        RingState::Pending {
            keys: Some(ring_keys("aabb")),
            confirmations: vec![public(&secret(2))],
        },
        RingState::Active {
            keys: ring_keys("aabb"),
        },
        RingState::Conflict {
            first_keys: pet_keys(),
            conflicting_keys: ring_keys("aabb"),
            by: public(&secret(3)),
        },
        RingState::Conflict {
            first_keys: pet_keys(),
            conflicting_keys: pet_keys(),
            by: public(&secret(3)),
        },
    ] {
        let mut malformed = record.clone();
        malformed.state = state;
        vera.store.put(
            &ring_key(&record.id).unwrap(),
            serde_json::to_vec(&malformed).unwrap(),
        );
        assert!(vera.threshold_ring(&record.id).is_err());
    }
    let bytes = borsh::to_vec(&pet_keys()).unwrap();
    assert_eq!(
        borsh::from_slice::<RingPublicKeys>(&bytes).unwrap(),
        pet_keys()
    );
}

#[test]
fn v2_ring_and_participant_digests_bind_the_paired_protocol() {
    let node = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let config = RingConfig {
        policy_id: "11".repeat(32),
        peer_node_keys: vec![node.into()],
        threshold: 1,
        pss_interval: 86400,
        current_version: 0,
        requires_pet: true,
        nonce: [9; 32],
        trusted_auth_relay_dids: None,
        reporting: ReportingConfig::default(),
    };
    let id = config.id([7; 32], "did:key:fixture").unwrap();
    assert_eq!(
        id,
        "58b39d87fc52b1e447cef0835a9a11dafcfd97be06424283bdb2cd4eba7ed8b9"
    );
    assert_eq!(
        ring_key(&id).unwrap(),
        format!("orbis/ring/v2/{id}").into_bytes()
    );
    let mut ordinary = config;
    ordinary.requires_pet = false;
    assert_ne!(ordinary.id([7; 32], "did:key:fixture").unwrap(), id);
    let request = RingParticipantRequest {
        deployment_root: [7; 32],
        deployment_id: 9001,
        ring_id: id,
        node_key: node.into(),
        command: RingParticipantCommand::Confirm(pet_keys()),
        expires_at: 200,
    };
    assert_eq!(
        hex::encode(request.signing_digest().unwrap()),
        "73d092c07a65a19a4d1e6c6f1dbcdb61aea7b2345d11cdb81b2d3f5f4da7a505"
    );
}
