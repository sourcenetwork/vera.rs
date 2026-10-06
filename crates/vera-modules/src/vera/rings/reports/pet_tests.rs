use super::*;
use orbis_reporting::*;
use serde_json::json;

fn reveal() -> PetBlindRevealStatement {
    serde_json::from_value(json!({
        "domain": PET_BLIND_REVEAL_RESPONSE_DOMAIN,
        "chain_id": "vera:test", "ring_id": "ring", "ring_pk": "key",
        "ring_state_sha256": "state", "protocol_version": 0, "attempt_id": "session",
        "context_digest": vec![1; 32], "selection_digest": vec![2; 32],
        "responder_node_key": "accused", "from_node_id": 1,
        "commitment": vec![3; 32], "blinded_r": [4], "blinded_diff": [5],
        "commit_salt": vec![6; 32], "challenge": [7], "proof": [8], "signed_at": 110
    }))
    .unwrap()
}

fn decrypt() -> PetBlindDecryptStatement {
    serde_json::from_value(json!({
        "domain": PET_BLIND_DECRYPT_RESPONSE_DOMAIN,
        "chain_id": "vera:test", "ring_id": "ring", "ring_pk": "key",
        "ring_state_sha256": "state", "protocol_version": 0, "attempt_id": "session",
        "context_digest": vec![1; 32], "certificate_digest": vec![2; 32],
        "responder_node_key": "accused", "from_node_id": 1,
        "aggregate_r": [3], "aggregate_diff": [4], "partial": [5],
        "challenge": [6], "proof": [7], "signed_at": 110, "public_polynomial": [8]
    }))
    .unwrap()
}

fn envelope(evidence: &InvalidCryptoResponse) -> ReportEnvelope {
    ReportEnvelope {
        domain: REPORT_DOMAIN.into(),
        report_type: INVALID_CRYPTO_RESPONSE_REPORT_TYPE.into(),
        chain_id: "vera:test".into(),
        ring_id: "ring".into(),
        ring_pk: "key".into(),
        ring_state_sha256: "state".into(),
        reporter_node_key: "reporter".into(),
        accused_node_key: "accused".into(),
        accused_peer_id: "peer".into(),
        observed_at: 100,
        expires_at: 220,
        session_id: "session".into(),
        payload: evidence.canonical_bytes(),
    }
}

#[test]
fn pet_evidence_binds_envelope_and_rejects_trailing_or_truncated_bytes() {
    for case in [
        InvalidCryptoResponse::PetBlindReveal {
            statement: reveal(),
            response_signature: vec![9; 64],
        },
        InvalidCryptoResponse::PetBlindDecrypt {
            statement: decrypt(),
            response_signature: vec![9; 64],
        },
    ] {
        let report = envelope(&case);
        let metadata = evidence::validate(&report).unwrap();
        assert_eq!(metadata.origin, "pet");
        assert_eq!(metadata.pet_node_id, Some(1));
        assert_eq!(metadata.accused, CommitteeScope::Current);
        assert_eq!(metadata.signing, CommitteeScope::Current);
        assert_eq!(metadata.attempt, None);
        for field in [
            "chain_id",
            "ring_id",
            "ring_pk",
            "ring_state_sha256",
            "accused_node_key",
            "session_id",
        ] {
            let mut altered = serde_json::to_value(&report).unwrap();
            altered[field] = json!("other");
            assert!(
                evidence::validate(&serde_json::from_value(altered).unwrap()).is_err(),
                "{field}"
            );
        }
        let mut altered = report.clone();
        altered.observed_at += 1;
        assert!(evidence::validate(&altered).is_err());
        altered = report.clone();
        altered.payload.push(0);
        assert!(evidence::validate(&altered).is_err());
        altered = report.clone();
        altered.payload.pop();
        assert!(evidence::validate(&altered).is_err());
        altered = report.clone();
        altered.session_id.push('2');
        assert_ne!(metadata.session_id(&report), metadata.session_id(&altered));
    }
}

#[test]
fn pet_evidence_requires_generation_bound_v2_domains() {
    for (domain, accepted) in [
        ("orbis-pet-blind-reveal-response-v2", true),
        ("orbis-pet-blind-reveal-response-v1", false),
    ] {
        let case = InvalidCryptoResponse::PetBlindReveal {
            statement: PetBlindRevealStatement {
                domain: domain.into(),
                ..reveal()
            },
            response_signature: vec![9; 64],
        };
        assert_eq!(
            evidence::validate(&envelope(&case)).is_ok(),
            accepted,
            "{domain}"
        );
    }
    for (domain, accepted) in [
        ("orbis-pet-blind-decrypt-response-v2", true),
        ("orbis-pet-blind-decrypt-response-v1", false),
    ] {
        let case = InvalidCryptoResponse::PetBlindDecrypt {
            statement: PetBlindDecryptStatement {
                domain: domain.into(),
                ..decrypt()
            },
            response_signature: vec![9; 64],
        };
        assert_eq!(
            evidence::validate(&envelope(&case)).is_ok(),
            accepted,
            "{domain}"
        );
    }
}

#[test]
fn pet_evidence_fields_are_bounded_without_interpreting_private_context() {
    let base = reveal();
    for statement in [
        PetBlindRevealStatement {
            from_node_id: 0,
            ..base.clone()
        },
        PetBlindRevealStatement {
            domain: PET_BLIND_DECRYPT_RESPONSE_DOMAIN.into(),
            ..base.clone()
        },
        PetBlindRevealStatement {
            attempt_id: String::new(),
            ..base.clone()
        },
        PetBlindRevealStatement {
            blinded_r: vec![0; 513],
            ..base.clone()
        },
        PetBlindRevealStatement {
            proof: vec![],
            ..base
        },
    ] {
        assert!(
            evidence::validate(&envelope(&InvalidCryptoResponse::PetBlindReveal {
                statement,
                response_signature: vec![9; 64],
            }))
            .is_err()
        );
    }
    let case = InvalidCryptoResponse::PetBlindDecrypt {
        statement: PetBlindDecryptStatement {
            public_polynomial: vec![0; 64 * 1024 + 1],
            ..decrypt()
        },
        response_signature: vec![9; 64],
    };
    assert!(evidence::validate(&envelope(&case)).is_err());
    let case = InvalidCryptoResponse::PetBlindDecrypt {
        statement: decrypt(),
        response_signature: vec![9; 63],
    };
    assert!(evidence::validate(&envelope(&case)).is_err());
}

#[test]
fn pet_offline_evidence_requires_current_committees() {
    let evidence = InvalidCryptoResponse::PetBlindReveal {
        statement: reveal(),
        response_signature: vec![9; 64],
    };
    let mut report = envelope(&evidence);
    report.report_type = NODE_OFFLINE_REPORT_TYPE.into();
    for accused in [CommitteeScope::Current, CommitteeScope::PendingNew] {
        for signing in [CommitteeScope::Current, CommitteeScope::PendingNew] {
            report.payload = NodeOffline {
                origin_protocol: "pet".into(),
                origin_protocol_version: 0,
                accused_committee_scope: accused,
                signing_committee_scope: signing,
            }
            .canonical_bytes();
            assert_eq!(
                evidence::validate(&report).is_ok(),
                accused == CommitteeScope::Current && signing == CommitteeScope::Current
            );
        }
    }
}
