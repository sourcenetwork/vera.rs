use super::*;
use orbis_reporting::{InvalidCryptoResponse, PetBlindRevealStatement};
use reports::{ReportEnvelope, SignedReport};

#[test]
fn pet_reports_require_the_right_ring_member_and_valid_aggregate_signature() {
    for requires_pet in [false, true] {
        let (mut vera, mut acp, mut config) = fixture_nodes(POLICY, &[2, 3, 4]);
        config.requires_pet = requires_pet;
        let key = blst::min_pk::SecretKey::key_gen(&[42; 32], &[]).unwrap();
        let keys = RingPublicKeys {
            public_key: hex::encode(key.sk_to_pk().to_bytes()),
            pet_public_key: requires_pet.then(|| "aabb".into()),
        };
        let created = apply(&mut vera, &mut acp, &RingCommand::Create(config), 1).unwrap();
        for node in [2, 3, 4] {
            vera.apply_ring_participant_request(
                &context(),
                &participant(
                    &created.id,
                    &secret(node),
                    RingParticipantCommand::Confirm(keys.clone()),
                ),
            )
            .unwrap();
        }
        let record = vera.threshold_ring(&created.id).unwrap().unwrap();
        let accused = public(&secret(3));
        let node_id = record
            .config
            .peer_node_keys
            .binary_search(&accused)
            .unwrap() as u32
            + 1;
        let statement = PetBlindRevealStatement {
            domain: orbis_reporting::PET_BLIND_REVEAL_RESPONSE_DOMAIN.into(),
            chain_id: ring_deployment_label(context().genesis_id, context().deployment_id),
            ring_id: record.id.clone(),
            ring_pk: keys.public_key.clone(),
            ring_state_sha256: record.report_state_hash().unwrap(),
            protocol_version: 0,
            attempt_id: "pet-attempt".into(),
            context_digest: [1; 32],
            selection_digest: [2; 32],
            responder_node_key: accused.clone(),
            from_node_id: node_id,
            commitment: vec![3; 32],
            blinded_r: vec![4],
            blinded_diff: vec![5],
            commit_salt: [6; 32],
            challenge: vec![7],
            proof: vec![8],
            signed_at: 110,
        };
        let signed = |statement: PetBlindRevealStatement| {
            let report = ReportEnvelope {
                domain: orbis_reporting::REPORT_DOMAIN.into(),
                report_type: orbis_reporting::INVALID_CRYPTO_RESPONSE_REPORT_TYPE.into(),
                chain_id: statement.chain_id.clone(),
                ring_id: record.id.clone(),
                ring_pk: keys.public_key.clone(),
                ring_state_sha256: record.report_state_hash().unwrap(),
                reporter_node_key: public(&secret(2)),
                accused_node_key: accused.clone(),
                accused_peer_id: accused.clone(),
                observed_at: 100,
                expires_at: 220,
                session_id: "pet-attempt".into(),
                payload: InvalidCryptoResponse::PetBlindReveal {
                    statement,
                    response_signature: vec![9; 64],
                }
                .canonical_bytes(),
            };
            SignedReport {
                report_id: report.report_id(),
                signature_scheme: "bls12_381_g1_pk_g2_sig_aug_v1".into(),
                signature: hex::encode(
                    key.sign(
                        &report.canonical_bytes(),
                        b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_",
                        &key.sk_to_pk().to_bytes(),
                    )
                    .to_bytes(),
                ),
                report,
            }
        };
        let before = vera.store().serialize();
        let mut previous_domain = statement.clone();
        previous_domain.domain = "orbis-pet-blind-reveal-response-v1".into();
        assert!(
            vera.submit_ring_report(&context(), &signed(previous_domain))
                .is_err()
        );
        assert_eq!(vera.store().serialize(), before);
        let mut wrong_member = statement.clone();
        wrong_member.from_node_id = node_id % 3 + 1;
        assert!(
            vera.submit_ring_report(&context(), &signed(wrong_member))
                .is_err()
        );
        let mut invalid_signature = signed(statement.clone());
        invalid_signature.signature = "00".repeat(96);
        assert!(
            vera.submit_ring_report(&context(), &invalid_signature)
                .is_err()
        );
        assert_eq!(vera.store().serialize(), before);
        let mut offline = signed(statement.clone());
        offline.report.session_id = "pet-offline-attempt".into();
        offline.report.report_type = orbis_reporting::NODE_OFFLINE_REPORT_TYPE.into();
        offline.report.payload = orbis_reporting::NodeOffline {
            origin_protocol: "pet".into(),
            origin_protocol_version: 0,
            accused_committee_scope: orbis_reporting::CommitteeScope::Current,
            signing_committee_scope: orbis_reporting::CommitteeScope::Current,
        }
        .canonical_bytes();
        offline.report_id = offline.report.report_id();
        offline.signature = hex::encode(
            key.sign(
                &offline.report.canonical_bytes(),
                b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_",
                &key.sk_to_pk().to_bytes(),
            )
            .to_bytes(),
        );
        let mut offline_state = VeraModule::from_store(vera.store().clone());
        if requires_pet {
            assert_eq!(
                offline_state
                    .submit_ring_report(&context(), &offline)
                    .unwrap()
                    .demerits
                    .points,
                record.config.reporting.node_offline_demerits
            );
        } else {
            assert!(
                offline_state
                    .submit_ring_report(&context(), &offline)
                    .is_err()
            );
            assert_eq!(offline_state.store().serialize(), before);
        }
        let report = signed(statement);
        if requires_pet {
            let outcome = vera.submit_ring_report(&context(), &report).unwrap();
            assert_eq!(
                outcome.demerits.points,
                record.config.reporting.invalid_crypto_response_demerits
            );
            let after = vera.store().serialize();
            assert!(vera.submit_ring_report(&context(), &report).is_err());
            assert_eq!(vera.store().serialize(), after);
        } else {
            assert!(vera.submit_ring_report(&context(), &report).is_err());
            assert_eq!(vera.store().serialize(), before);
        }
    }
}
