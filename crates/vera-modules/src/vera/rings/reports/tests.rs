use super::*;
use orbis_reporting::*;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

fn statement<T: DeserializeOwned>(fields: Value) -> T {
    let mut value = json!({
        "domain": "", "chain_id": "vera:test", "ring_id": "ring", "ring_pk": "key",
        "ring_state_sha256": "state", "protocol_version": 0, "request_id": "session",
        "signed_at": 110, "responder_node_key": "accused", "origin_protocol": "pss_refresh",
        "accused_committee_scope": "current", "signing_committee_scope": "current",
        "attempt_id": vec![9; 32], "from_node_id": 1, "crypto_backend": "bls12-381"
    });
    value
        .as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    serde_json::from_value(value).unwrap()
}
fn envelope(payload: Vec<u8>) -> ReportEnvelope {
    ReportEnvelope {
        domain: REPORT_DOMAIN.into(),
        report_type: INVALID_CRYPTO_RESPONSE_REPORT_TYPE.into(),
        chain_id: "vera:test".into(),
        ring_id: "ring".into(),
        ring_pk: "key".into(),
        ring_state_sha256: "state".into(),
        reporter_node_key: "reporter".into(),
        accused_node_key: "accused".into(),
        accused_peer_id: hex::encode([3; 32]),
        observed_at: 100,
        expires_at: 220,
        payload,
        session_id: "session".into(),
    }
}
fn commitment() -> DkgCommitmentStatement {
    statement(
        json!({"domain": DKG_COMMITMENT_DOMAIN, "session_nonce": vec![7;16], "commitment": [1]}),
    )
}
fn contribution() -> EndpointSignedContribution {
    EndpointSignedContribution {
        origin: vec![3; 32],
        signature: vec![4; 64],
        data: vec![1],
    }
}

#[test]
fn all_crypto_evidence_kinds_bind_context_and_reject_truncation() {
    let mut conflicting = commitment();
    conflicting.commitment = vec![2];
    let delivery = json!({"phase":"commitments", "delivery_id_a": vec![1;16], "delivery_id_b": vec![2;16], "delivery_a": contribution(), "delivery_b": contribution()});
    let mut leader: DkgLeaderEquivocationStatement = statement(delivery);
    leader.domain = DKG_LEADER_EQUIVOCATION_DOMAIN.into();
    let mut batch = leader.clone();
    batch.domain = DKG_LEADER_BATCH_MISMATCH_DOMAIN.into();
    let cases = vec![
        InvalidCryptoResponse::Pre {
            statement: statement(json!({
                "domain": PRE_REENCRYPT_RESPONSE_DOMAIN, "origin_protocol": "pre", "object_id":"object",
                "rdr_pk":[1], "share":[2], "challenge":[3], "proof":[4], "derivation":null,
                "timestamp":null, "document_inline":false
            })),
            response_signature: vec![5; 64],
        },
        InvalidCryptoResponse::Sign {
            statement: statement(json!({
                "domain": SIGN_RESPONSE_DOMAIN, "origin_protocol":"sign", "message":[1], "signing_commitments":[],
                "sig_share":[2], "derivation":null, "metadata":null
            })),
            response_signature: vec![5; 64],
        },
        InvalidCryptoResponse::DkgShare {
            statement: Box::new(statement(json!({
                "domain":DKG_SHARE_DOMAIN, "to_node_id":2, "receiver_node_key":"receiver",
                "commitment_statement":commitment(), "commitment_signature":vec![5;64],
                "share_value":[1], "nonce":vec![8;16]
            }))),
            response_signature: vec![5; 64],
        },
        InvalidCryptoResponse::DkgInvalidRefreshCommitment {
            statement: Box::new(commitment()),
            response_signature: vec![5; 64],
        },
        InvalidCryptoResponse::DkgEquivocation {
            commitment_a: Box::new(SignedDkgCommitment {
                statement: commitment(),
                signature: vec![5; 64],
            }),
            commitment_b: Box::new(SignedDkgCommitment {
                statement: conflicting,
                signature: vec![5; 64],
            }),
        },
        InvalidCryptoResponse::DkgPublicOriginFault {
            statement: Box::new(statement(json!({
                "domain":DKG_PUBLIC_ORIGIN_FAULT_DOMAIN, "phase":"commitment_audit", "fault_kind":"invalid_payload",
                "contribution_a":contribution(), "contribution_b":null
            }))),
        },
        InvalidCryptoResponse::DkgLeaderEquivocation {
            statement: Box::new(leader),
        },
        InvalidCryptoResponse::DkgLeaderBatchMismatch {
            statement: Box::new(batch),
        },
        InvalidCryptoResponse::DkgLeaderPublicFault {
            statement: Box::new(statement(json!({
                "domain":DKG_LEADER_PUBLIC_FAULT_DOMAIN, "phase":"commitments", "fault_kind":"invalid_manifest",
                "delivery_id":vec![1;16], "delivery":contribution()
            }))),
        },
        InvalidCryptoResponse::DkgControlMessageFault {
            statement: Box::new(statement(json!({
                "domain":DKG_CONTROL_MESSAGE_FAULT_DOMAIN, "message_kind":"prepare", "fault_kind":"leader_prepare_fault",
                "artifact_a":{"signature":vec![1;64],"data":[1],"signed_at":110}, "artifact_b":null
            }))),
        },
    ];
    for (index, case) in cases.into_iter().enumerate() {
        let report = envelope(case.canonical_bytes());
        let meta = evidence::validate(&report).unwrap_or_else(|err| panic!("kind {index}: {err}"));
        assert_eq!(meta.attempt.is_some(), index >= 2);
        let mut stale = report.clone();
        stale.observed_at += 1;
        assert!(evidence::validate(&stale).is_err(), "kind {index}");
        let mut mixed = report.clone();
        mixed.ring_state_sha256.push('0');
        assert!(evidence::validate(&mixed).is_err(), "kind {index}");
        let mut truncated = report.clone();
        truncated.payload.pop();
        assert!(evidence::validate(&truncated).is_err(), "kind {index}");
        let mut other_attempt = meta;
        let first_session = other_attempt.session_id(&report);
        other_attempt.attempt = Some([8; 32]);
        assert_ne!(first_session, other_attempt.session_id(&report));
    }
}

#[test]
fn relay_evidence_binds_caller_time_and_requires_a_complete_window() {
    let mut payload = UnauthorizedRequestPayload {
        statement: statement(json!({
            "domain":RELAY_REQUEST_DOMAIN, "origin_protocol":"pre", "relayer_node_key":"accused",
            "user_signed_at":110, "actor_id":"actor", "object_id":"object",
            "valid_window_start":null, "valid_window_end":null, "timestamp":null, "document_inline":false
        })),
        relay_signature: vec![5; 64],
    };
    let mut report = envelope(payload.canonical_bytes());
    report.report_type = UNAUTHORIZED_REQUEST_REPORT_TYPE.into();
    evidence::validate(&report).unwrap();
    payload.statement.user_signed_at = 79;
    report.payload = payload.canonical_bytes();
    assert!(evidence::validate(&report).is_err());
    payload.statement.user_signed_at = 110;
    payload.statement.valid_window_start = Some(100);
    report.payload = payload.canonical_bytes();
    assert!(evidence::validate(&report).is_err());
    payload.statement.valid_window_end = Some(110);
    report.payload = payload.canonical_bytes();
    evidence::validate(&report).unwrap();
}
