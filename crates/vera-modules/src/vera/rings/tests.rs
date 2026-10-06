mod jubjub;

use super::*;
use crate::{
    acp::types::PolicyMarshalingType,
    types::Timestamp,
    vera::nodes::{NodeCommand, NodeInfo, NodeRequest, SignedNodeRequest},
};
use acp::Relationship;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use k256::ecdsa::{
    Signature, SigningKey,
    signature::{Signer as _, hazmat::PrehashSigner as _},
};
use vera_crypto::{
    jwt::JwtClaims,
    operation::{OperationClaim, OperationId},
};

const POLICY: &str = "name: rings\nresources:\n  - name: ring_policy\n    relations:\n      - name: creator\n    permissions:\n      - name: create_ring\n        expr: creator\n  - name: ring\n";
fn secret(n: u8) -> SigningKey {
    SigningKey::from_slice(&[n; 32]).unwrap()
}
fn public(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_sec1_bytes())
}
fn actor() -> Did {
    Did::new(
        vera_crypto::secp256k1::did_from_secp256k1_pubkey(
            secret(1).verifying_key().to_sec1_bytes().as_ref(),
        )
        .unwrap(),
    )
    .unwrap()
}
fn context() -> BlockExecCtx {
    BlockExecCtx {
        genesis_id: [1; 32],
        deployment_id: 9001,
        timestamp: Timestamp {
            seconds: 100,
            block_height: 2,
        },
    }
}
fn submission() -> TxExecCtx {
    TxExecCtx {
        signer: "did:key:worker".into(),
        sequence: 0,
        tx_hash: vec![8; 32],
    }
}
fn token(command: &RingCommand, entropy: u8) -> String {
    token_at(command, entropy, &context())
}
fn token_at(command: &RingCommand, entropy: u8, at: &BlockExecCtx) -> String {
    token_from(command, entropy, at, &secret(1))
}
fn token_from(command: &RingCommand, entropy: u8, at: &BlockExecCtx, key: &SigningKey) -> String {
    delegated_token(DelegatedOperation::RingCommand(command), entropy, at, key)
}
fn delegated_token(
    operation: DelegatedOperation<'_>,
    entropy: u8,
    at: &BlockExecCtx,
    key: &SigningKey,
) -> String {
    let mut id = [entropy; 32];
    id[..8].copy_from_slice(&(at.timestamp.seconds + 100).to_be_bytes());
    let claims = JwtClaims {
        iss: vera_crypto::secp256k1::did_from_secp256k1_pubkey(
            key.verifying_key().to_sec1_bytes().as_ref(),
        )
        .unwrap(),
        sub: submission().signer,
        exp: at.timestamp.seconds + 100,
        aud: "vera:9001".into(),
        scope: operation.scope(),
        iat: at.timestamp.seconds,
        nbf: at.timestamp.seconds,
        relay: None,
        request: Some(OperationClaim {
            id: OperationId(id),
            digest: operation.digest().unwrap(),
            genesis_id: context().genesis_id,
        }),
    };
    let message = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256K","typ":"vera-delegation-v1+jwt"}"#),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let signature: Signature = key.sign(message.as_bytes());
    format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}
fn fixture(policy: &str) -> (VeraModule, AcpModule, RingConfig) {
    fixture_nodes(policy, &[2, 3])
}
fn fixture_nodes(policy: &str, nodes: &[u8]) -> (VeraModule, AcpModule, RingConfig) {
    let mut vera = VeraModule::new();
    let mut acp = AcpModule::new();
    let policy_id = acp
        .create_policy(&actor(), policy, PolicyMarshalingType::ShortYaml)
        .unwrap()
        .policy
        .id;
    acp.direct_policy_cmd(
        &actor(),
        &policy_id,
        PolicyCmd::RegisterObject(Object {
            resource: "ring_policy".into(),
            id: policy_id.clone(),
        }),
    )
    .unwrap();
    acp.direct_policy_cmd(
        &actor(),
        &policy_id,
        PolicyCmd::SetRelationship(Relationship::with_entity(
            "ring_policy",
            &policy_id,
            "creator",
            actor(),
        )),
    )
    .unwrap();
    let mut peers = Vec::new();
    for key in nodes.iter().map(|n| secret(*n)) {
        let request = NodeRequest {
            deployment_root: context().genesis_id,
            deployment_id: 9001,
            node_key: public(&key),
            sequence: 0,
            expires_at: 200,
            command: NodeCommand::Register(NodeInfo {
                peer_id: public(&key),
                controller_key: public(&key),
                allowed_policy_ids: vec![policy_id.clone()],
                allowed_ring_ids: vec![],
            }),
        };
        let signature: Signature = key
            .sign_prehash(&request.signing_digest().unwrap())
            .unwrap();
        vera.apply_node_request(
            &context(),
            &SignedNodeRequest {
                request,
                signer_key: public(&key),
                signature: hex::encode(signature.to_bytes()),
            },
        )
        .unwrap();
        peers.push(public(&key));
    }
    peers.sort();
    (
        vera,
        acp,
        RingConfig {
            policy_id,
            peer_node_keys: peers,
            threshold: 2,
            pss_interval: 86400,
            current_version: 0,
            nonce: [9; 32],
            trusted_auth_relay_dids: None,
            reporting: ReportingConfig::default(),
        },
    )
}
fn participant(
    ring: &str,
    key: &SigningKey,
    command: RingParticipantCommand,
) -> SignedRingParticipantRequest {
    let request = RingParticipantRequest {
        deployment_root: context().genesis_id,
        deployment_id: 9001,
        ring_id: ring.into(),
        node_key: public(key),
        command,
        expires_at: 200,
    };
    let signature: Signature = key
        .sign_prehash(&request.signing_digest().unwrap())
        .unwrap();
    SignedRingParticipantRequest {
        request,
        signature: hex::encode(signature.to_bytes()),
    }
}
fn confirm(ring: &str, n: u8, key: &str) -> SignedRingParticipantRequest {
    participant(
        ring,
        &secret(n),
        RingParticipantCommand::Confirm(key.into()),
    )
}
fn apply(
    vera: &mut VeraModule,
    acp: &mut AcpModule,
    command: &RingCommand,
    entropy: u8,
) -> Result<RingRecord> {
    vera.apply_ring_command(
        acp,
        &context(),
        &submission(),
        &token(command, entropy),
        command,
    )
}

#[test]
fn ring_creation_is_atomic_and_confirmations_require_unanimity() {
    let (mut vera, mut acp, config) = fixture(POLICY);
    let create = RingCommand::Create(config.clone());
    let record = apply(&mut vera, &mut acp, &create, 1).unwrap();
    assert!(
        acp.query_object_owner(
            &config.policy_id,
            &Object {
                resource: "ring".into(),
                id: record.id.clone()
            }
        )
        .unwrap()
        .0
    );
    assert_eq!(apply(&mut vera, &mut acp, &create, 1).unwrap(), record);
    assert!(apply(&mut vera, &mut acp, &create, 2).is_err());
    let first = confirm(&record.id, 2, "aabb");
    let pending = vera
        .apply_ring_participant_request(&context(), &first)
        .unwrap();
    assert!(matches!(pending.state, RingState::Pending { .. }));
    let before = vera.store().serialize();
    assert!(
        vera.apply_ring_participant_request(&context(), &confirm(&record.id, 2, "ccdd"))
            .is_err()
    );
    assert_eq!(vera.store().serialize(), before);
    let mut restored = VeraModule::from_store(vera.store().clone());
    let active = restored
        .apply_ring_participant_request(&context(), &confirm(&record.id, 3, "aabb"))
        .unwrap();
    assert_eq!(
        active.state,
        RingState::Active {
            public_key: "aabb".into()
        }
    );
    assert!(
        restored
            .apply_ring_participant_request(
                &context(),
                &participant(&record.id, &secret(2), RingParticipantCommand::Cancel)
            )
            .is_err()
    );
    assert!(
        apply(
            &mut restored,
            &mut acp,
            &RingCommand::Cancel { ring_id: record.id },
            3
        )
        .is_err()
    );

    let (mut vera, mut acp, config) = fixture(&POLICY.replace("  - name: ring\n", ""));
    let before = (vera.store().serialize(), acp.store().serialize());
    assert!(apply(&mut vera, &mut acp, &RingCommand::Create(config), 1).is_err());
    assert_eq!((vera.store().serialize(), acp.store().serialize()), before);
    let (mut vera, acp, config) = fixture(POLICY);
    let mut store = acp.store().clone();
    store.put(b"operation-bytes/v1", (64u64 << 20).to_be_bytes().to_vec());
    let mut acp = AcpModule::from_store(store);
    let before = (vera.store().serialize(), acp.store().serialize());
    let error = apply(&mut vera, &mut acp, &RingCommand::Create(config), 1).unwrap_err();
    assert!(error.to_string().contains("storage budget reached"));
    assert_eq!((vera.store().serialize(), acp.store().serialize()), before);
}

#[test]
fn cancellation_conflict_revocation_and_bad_signatures_cannot_reuse_a_ring() {
    let (mut vera, mut acp, mut config) = fixture(POLICY);
    let create = RingCommand::Create(config.clone());
    let record = apply(&mut vera, &mut acp, &create, 1).unwrap();
    let before = vera.store().serialize();
    let mut altered = confirm(&record.id, 2, "aabb");
    altered.request.deployment_id += 1;
    assert!(
        vera.apply_ring_participant_request(&context(), &altered)
            .is_err()
    );
    let mut altered = confirm(&record.id, 2, "aabb");
    altered.request.command = RingParticipantCommand::Confirm("ccdd".into());
    assert!(
        vera.apply_ring_participant_request(&context(), &altered)
            .is_err()
    );
    assert!(
        vera.apply_ring_participant_request(&context(), &confirm(&record.id, 4, "aabb"))
            .is_err()
    );
    assert_eq!(vera.store().serialize(), before);
    vera.apply_ring_participant_request(&context(), &confirm(&record.id, 2, "aabb"))
        .unwrap();
    let conflict = vera
        .apply_ring_participant_request(&context(), &confirm(&record.id, 3, "ccdd"))
        .unwrap();
    assert!(matches!(conflict.state, RingState::Conflict { .. }));
    assert!(apply(&mut vera, &mut acp, &create, 2).is_err());
    assert!(
        vera.apply_ring_participant_request(&context(), &confirm(&record.id, 3, "aabb"))
            .is_err()
    );

    config.nonce = [10; 32];
    let create = RingCommand::Create(config);
    let record = apply(&mut vera, &mut acp, &create, 3).unwrap();
    let cancel = RingCommand::Cancel { ring_id: record.id };
    vera.revoke_delegation(&context(), &actor(), &token(&cancel, 4))
        .unwrap();
    let before = (vera.store().serialize(), acp.store().serialize());
    assert!(apply(&mut vera, &mut acp, &cancel, 4).is_err());
    assert_eq!((vera.store().serialize(), acp.store().serialize()), before);
    assert!(matches!(
        apply(&mut vera, &mut acp, &cancel, 5).unwrap().state,
        RingState::Cancelled { .. }
    ));
    assert!(apply(&mut vera, &mut acp, &create, 6).is_err());
}

#[test]
fn ring_configuration_and_stored_records_are_bounded_and_validated() {
    let (mut vera, mut acp, config) = fixture(POLICY);
    for bad in [
        RingConfig {
            peer_node_keys: vec![public(&secret(2)); 2],
            ..config.clone()
        },
        RingConfig {
            threshold: 3,
            ..config.clone()
        },
        RingConfig {
            pss_interval: 0,
            ..config.clone()
        },
        RingConfig {
            trusted_auth_relay_dids: Some(vec![actor().to_string()]),
            ..config.clone()
        },
        RingConfig {
            reporting: ReportingConfig {
                kick_threshold: 0,
                ..ReportingConfig::default()
            },
            ..config.clone()
        },
    ] {
        assert!(bad.validate().is_err());
    }
    let mut with_relay = config.clone();
    with_relay.trusted_auth_relay_dids = Some(vec![
        "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH".into(),
    ]);
    with_relay.validate().unwrap();
    let record = apply(&mut vera, &mut acp, &RingCommand::Create(config), 1).unwrap();
    vera.store.put(
        &ring_key(&record.id).unwrap(),
        vec![0; MAX_RING_RECORD_BYTES + 1],
    );
    assert!(vera.threshold_ring(&record.id).is_err());
}

#[test]
fn ring_updates_require_acp_authority_and_reject_stale_commands_within_one_revision() {
    let policy = POLICY.replace("  - name: ring\n", "  - name: ring\n    relations:\n      - name: operator\n    permissions:\n      - name: update_ring\n        expr: operator\n");
    let (mut vera, mut acp, config) = fixture(&policy);
    let initial = apply(&mut vera, &mut acp, &RingCommand::Create(config), 1).unwrap();
    vera.apply_ring_participant_request(&context(), &confirm(&initial.id, 2, "aabb"))
        .unwrap();
    let active = vera
        .apply_ring_participant_request(&context(), &confirm(&initial.id, 3, "aabb"))
        .unwrap();
    let update = |sequence, update| RingCommand::Update {
        ring_id: initial.id.clone(),
        expected_sequence: sequence,
        update,
    };
    let refresh = update(active.sequence, RingUpdate::SetPssInterval(90000));
    let outsider = token_from(&refresh, 2, &context(), &secret(4));
    let before = (vera.store().serialize(), acp.store().serialize());
    assert!(
        vera.apply_ring_command(&mut acp, &context(), &submission(), &outsider, &refresh)
            .is_err()
    );
    assert_eq!((vera.store().serialize(), acp.store().serialize()), before);
    acp.direct_policy_cmd(
        &actor(),
        &initial.config.policy_id,
        PolicyCmd::SetRelationship(Relationship::with_entity(
            "ring",
            &initial.id,
            "operator",
            actor(),
        )),
    )
    .unwrap();
    let changed = apply(&mut vera, &mut acp, &refresh, 3).unwrap();
    assert_eq!(changed.revision, active.revision);
    assert_eq!(changed.sequence, active.sequence + 1);
    assert_eq!(changed.id, initial.id);
    assert_eq!(changed.config, initial.config);
    assert_eq!(changed.current_settings().pss_interval, 90000);
    assert!(apply(&mut vera, &mut acp, &refresh, 4).is_err());
    let schedule = update(
        changed.sequence,
        RingUpdate::ScheduleUpgrade(ScheduledUpgrade {
            version: 1,
            activates_at: 700,
        }),
    );
    let scheduled = apply(&mut vera, &mut acp, &schedule, 5).unwrap();
    assert_eq!(scheduled.current_settings().effective_version(699), 0);
    assert_eq!(scheduled.current_settings().effective_version(700), 1);
    let mut later = context();
    later.timestamp.seconds = 700;
    later.timestamp.block_height = 3;
    let cancel = update(scheduled.sequence, RingUpdate::CancelUpgrade);
    let before = (vera.store().serialize(), acp.store().serialize());
    assert!(
        vera.apply_ring_command(
            &mut acp,
            &later,
            &submission(),
            &token_at(&cancel, 6, &later),
            &cancel
        )
        .is_err()
    );
    assert_eq!((vera.store().serialize(), acp.store().serialize()), before);
    let refresh = update(scheduled.sequence, RingUpdate::SetPssInterval(90001));
    let normalized = vera
        .apply_ring_command(
            &mut acp,
            &later,
            &submission(),
            &token_at(&refresh, 7, &later),
            &refresh,
        )
        .unwrap();
    assert_eq!(normalized.current_settings().current_version, 1);
    assert!(normalized.current_settings().scheduled_upgrade.is_none());
    assert_eq!(normalized.config.current_version, 0);
    let mut old: serde_json::Value = serde_json::to_value(&initial).unwrap();
    old.as_object_mut().unwrap().remove("settings");
    old.as_object_mut().unwrap().remove("sequence");
    let old: RingRecord = serde_json::from_value(old).unwrap();
    old.validate(&old.id).unwrap();
    assert_eq!(
        old.current_settings().pss_interval,
        initial.config.pss_interval
    );
    assert_eq!(old.sequence, 0);
}

#[test]
fn ring_reporting_relays_and_reshare_targets_preserve_controller_constraints() {
    let policy = POLICY.replace("  - name: ring\n", "  - name: ring\n    relations:\n      - name: operator\n    permissions:\n      - name: update_ring\n        expr: operator\n");
    let (mut vera, mut acp, mut config) = fixture(&policy);
    config.trusted_auth_relay_dids = Some(Vec::new());
    let initial = apply(&mut vera, &mut acp, &RingCommand::Create(config), 1).unwrap();
    acp.direct_policy_cmd(
        &actor(),
        &initial.config.policy_id,
        PolicyCmd::SetRelationship(Relationship::with_entity(
            "ring",
            &initial.id,
            "operator",
            actor(),
        )),
    )
    .unwrap();
    let update = |sequence, update| RingCommand::Update {
        ring_id: initial.id.clone(),
        expected_sequence: sequence,
        update,
    };
    let relay = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH".to_string();
    let pending = apply(
        &mut vera,
        &mut acp,
        &update(initial.sequence, RingUpdate::AddRelay(relay.clone())),
        2,
    )
    .unwrap();
    assert_eq!(
        pending.current_settings().trusted_auth_relay_dids,
        Some(vec![relay.clone()])
    );
    assert!(
        apply(
            &mut vera,
            &mut acp,
            &update(pending.sequence, RingUpdate::SetPssInterval(90000)),
            3
        )
        .is_err()
    );
    vera.apply_ring_participant_request(&context(), &confirm(&initial.id, 2, "aabb"))
        .unwrap();
    let active = vera
        .apply_ring_participant_request(&context(), &confirm(&initial.id, 3, "aabb"))
        .unwrap();
    let before = (vera.store().serialize(), acp.store().serialize());
    let bad = [
        RingUpdate::AddRelay(relay.clone()),
        RingUpdate::ScheduleUpgrade(ScheduledUpgrade {
            version: 1,
            activates_at: 699,
        }),
        RingUpdate::StartReshare {
            peer_node_keys: Some(vec![public(&secret(2))]),
            threshold: Some(2),
        },
        RingUpdate::SetReporting(ReportingConfig {
            kick_threshold: 0,
            ..Default::default()
        }),
    ];
    for (index, change) in bad.into_iter().enumerate() {
        assert!(
            apply(
                &mut vera,
                &mut acp,
                &update(active.sequence, change),
                10 + index as u8
            )
            .is_err()
        );
        assert_eq!((vera.store().serialize(), acp.store().serialize()), before);
    }
    let request = NodeRequest {
        deployment_root: context().genesis_id,
        deployment_id: 9001,
        node_key: public(&secret(3)),
        sequence: 1,
        expires_at: 200,
        command: NodeCommand::Disallow(crate::vera::nodes::NodeTarget::Policy(
            initial.config.policy_id.clone(),
        )),
    };
    let signature: Signature = secret(3)
        .sign_prehash(&request.signing_digest().unwrap())
        .unwrap();
    vera.apply_node_request(
        &context(),
        &SignedNodeRequest {
            request,
            signer_key: public(&secret(3)),
            signature: hex::encode(signature.to_bytes()),
        },
    )
    .unwrap();
    assert!(
        apply(
            &mut vera,
            &mut acp,
            &update(
                active.sequence,
                RingUpdate::StartReshare {
                    peer_node_keys: None,
                    threshold: Some(1)
                }
            ),
            20
        )
        .is_err()
    );
    assert!(
        apply(
            &mut vera,
            &mut acp,
            &update(
                active.sequence,
                RingUpdate::SetReporting(ReportingConfig {
                    backup_node_keys: vec![public(&secret(3))],
                    ..Default::default()
                })
            ),
            21
        )
        .is_err()
    );
    let announced = apply(
        &mut vera,
        &mut acp,
        &update(
            active.sequence,
            RingUpdate::StartReshare {
                peer_node_keys: Some(vec![public(&secret(2))]),
                threshold: Some(1),
            },
        ),
        22,
    )
    .unwrap();
    let settings = announced.current_settings();
    assert_eq!(settings.peer_node_keys, initial.config.peer_node_keys);
    assert_eq!(settings.threshold, 2);
    assert_eq!(settings.pending_reshare.unwrap().threshold, 1);
    assert!(
        apply(
            &mut vera,
            &mut acp,
            &update(
                announced.sequence,
                RingUpdate::StartReshare {
                    peer_node_keys: None,
                    threshold: Some(1)
                }
            ),
            23
        )
        .is_err()
    );
    let removed = apply(
        &mut vera,
        &mut acp,
        &update(announced.sequence, RingUpdate::RemoveRelay(relay)),
        24,
    )
    .unwrap();
    assert_eq!(
        removed.current_settings().trusted_auth_relay_dids,
        Some(Vec::new())
    );
    let restored = VeraModule::from_store(vera.store().clone());
    assert_eq!(
        restored.threshold_ring(&initial.id).unwrap().unwrap(),
        removed
    );
}

#[test]
fn reshare_finalization_preserves_key_and_rejects_replay_and_changed_authority() {
    let policy = POLICY.replace("  - name: ring\n", "  - name: ring\n    relations:\n      - name: operator\n    permissions:\n      - name: update_ring\n        expr: operator\n");
    let (mut vera, mut acp, config) = fixture(&policy);
    let key = blst::min_pk::SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let public_key = hex::encode(key.sk_to_pk().to_bytes());
    let ring = apply(&mut vera, &mut acp, &RingCommand::Create(config), 1).unwrap();
    for node in [2, 3] {
        vera.apply_ring_participant_request(&context(), &confirm(&ring.id, node, &public_key))
            .unwrap();
    }
    let active = vera.threshold_ring(&ring.id).unwrap().unwrap();
    let update = |sequence, update| RingCommand::Update {
        ring_id: ring.id.clone(),
        expected_sequence: sequence,
        update,
    };
    let pending = apply(
        &mut vera,
        &mut acp,
        &update(
            active.sequence,
            RingUpdate::StartReshare {
                peer_node_keys: Some(vec![public(&secret(3))]),
                threshold: Some(1),
            },
        ),
        2,
    )
    .unwrap();
    let sign = |record: &RingRecord| RingReshareRequest {
        deployment_root: context().genesis_id,
        deployment_id: context().deployment_id,
        ring_id: record.id.clone(),
        expected_sequence: record.sequence,
        scheme: ThresholdScheme::Bls12381AugV1,
        signature: hex::encode(
            key.sign(
                &record
                    .reshare_signing_bytes(context().deployment_id)
                    .unwrap(),
                b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_",
                &key.sk_to_pk().to_bytes(),
            )
            .to_bytes(),
        ),
    };
    let signed = sign(&pending);
    let mut unsupported = serde_json::to_value(&signed).unwrap();
    unsupported["scheme"] = "bls12_381_g1_pk_g2_sig_nul".into();
    assert!(serde_json::from_value::<RingReshareRequest>(unsupported).is_err());
    let mut legacy = signed.clone();
    legacy.signature = hex::encode(
        key.sign(
            &pending
                .reshare_signing_bytes(context().deployment_id)
                .unwrap(),
            b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_",
            &[],
        )
        .to_bytes(),
    );
    let before = vera.store().serialize();
    assert!(vera.finalize_ring_reshare(&context(), &legacy).is_err());
    assert_eq!(vera.store().serialize(), before);

    for variant in 0..5 {
        let mut bad = signed.clone();
        match variant {
            0 => bad.deployment_root[0] ^= 1,
            1 => bad.deployment_id += 1,
            2 => bad.expected_sequence += 1,
            3 => bad.signature = "00".repeat(96),
            _ => bad.scheme = ThresholdScheme::JubjubFrost,
        }
        let before = vera.store().serialize();
        assert!(vera.finalize_ring_reshare(&context(), &bad).is_err());
        assert_eq!(vera.store().serialize(), before);
    }
    let changed = apply(
        &mut vera,
        &mut acp,
        &update(pending.sequence, RingUpdate::SetPssInterval(90000)),
        3,
    )
    .unwrap();
    let mut stale = signed;
    stale.expected_sequence = changed.sequence;
    assert!(vera.finalize_ring_reshare(&context(), &stale).is_err());
    let signed = sign(&changed);
    let change_permission = |vera: &mut VeraModule, sequence, command| {
        let request = NodeRequest {
            deployment_root: context().genesis_id,
            deployment_id: context().deployment_id,
            node_key: public(&secret(3)),
            sequence,
            expires_at: 200,
            command,
        };
        let signature: Signature = secret(3)
            .sign_prehash(&request.signing_digest().unwrap())
            .unwrap();
        vera.apply_node_request(
            &context(),
            &SignedNodeRequest {
                request,
                signer_key: public(&secret(3)),
                signature: hex::encode(signature.to_bytes()),
            },
        )
        .unwrap();
    };
    let target = crate::vera::nodes::NodeTarget::Policy(ring.config.policy_id.clone());
    change_permission(&mut vera, 1, NodeCommand::Disallow(target.clone()));
    let before = vera.store().serialize();
    assert!(vera.finalize_ring_reshare(&context(), &signed).is_err());
    assert_eq!(vera.store().serialize(), before);
    change_permission(&mut vera, 2, NodeCommand::Allow(target));
    let finalized = vera.finalize_ring_reshare(&context(), &signed).unwrap();
    assert_eq!(finalized.state, active.state);
    assert_eq!(finalized.id, ring.id);
    assert_eq!(finalized.config, ring.config);
    assert_eq!(finalized.sequence, changed.sequence + 1);
    let settings = finalized.current_settings();
    assert_eq!(settings.peer_node_keys, vec![public(&secret(3))]);
    assert_eq!(settings.threshold, 1);
    assert_eq!(settings.pss_interval, 90000);
    assert!(settings.pending_reshare.is_none());
    assert!(vera.finalize_ring_reshare(&context(), &signed).is_err());
    let next = apply(
        &mut vera,
        &mut acp,
        &update(
            finalized.sequence,
            RingUpdate::StartReshare {
                peer_node_keys: Some(ring.config.peer_node_keys.clone()),
                threshold: Some(2),
            },
        ),
        4,
    )
    .unwrap();
    let mut replay = signed;
    replay.expected_sequence = next.sequence;
    assert!(vera.finalize_ring_reshare(&context(), &replay).is_err());
    let restored = vera
        .finalize_ring_reshare(&context(), &sign(&next))
        .unwrap();
    assert_eq!(restored.current_settings().threshold, 2);
    assert_eq!(restored.state, active.state);
}

#[test]
fn reports_deduplicate_expire_and_schedule_replacement_atomically() {
    use orbis_reporting::{CommitteeScope, NodeOffline};
    use reports::*;
    let (mut vera, mut acp, mut config) = fixture_nodes(POLICY, &[2, 3, 4, 5]);
    config
        .peer_node_keys
        .retain(|key| key != &public(&secret(5)));
    config.reporting.backup_node_keys = vec![public(&secret(4)), public(&secret(5))];
    config.reporting.backup_node_keys.sort();
    let key = blst::min_pk::SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let ring_pk = hex::encode(key.sk_to_pk().to_bytes());
    let created = apply(&mut vera, &mut acp, &RingCommand::Create(config), 1).unwrap();
    for node in [2, 3, 4] {
        vera.apply_ring_participant_request(&context(), &confirm(&created.id, node, &ring_pk))
            .unwrap();
    }
    let initial = vera.threshold_ring(&created.id).unwrap().unwrap();
    let report = |record: &RingRecord, session: &str, now, accused: u8, scope| ReportEnvelope {
        domain: orbis_reporting::REPORT_DOMAIN.into(),
        report_type: orbis_reporting::NODE_OFFLINE_REPORT_TYPE.into(),
        chain_id: ring_deployment_label(context().genesis_id, context().deployment_id),
        ring_id: record.id.clone(),
        ring_pk: ring_pk.clone(),
        ring_state_sha256: record.report_state_hash().unwrap(),
        reporter_node_key: public(&secret(2)),
        accused_node_key: public(&secret(accused)),
        accused_peer_id: public(&secret(accused)),
        observed_at: now,
        expires_at: now + 120,
        session_id: session.into(),
        payload: NodeOffline {
            origin_protocol: "pss_reshare".into(),
            origin_protocol_version: 0,
            accused_committee_scope: scope,
            signing_committee_scope: CommitteeScope::Current,
        }
        .canonical_bytes(),
    };
    let sign = |report: ReportEnvelope| SignedReport {
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
    };
    let first = sign(report(
        &initial,
        "session-1",
        100,
        3,
        CommitteeScope::Current,
    ));
    let mut legacy = first.clone();
    legacy.signature_scheme = "bls12_381_g1_pk_g2_sig_nul".into();
    legacy.signature = hex::encode(
        key.sign(
            &legacy.report.canonical_bytes(),
            b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_",
            &[],
        )
        .to_bytes(),
    );
    let before = vera.store().serialize();
    assert!(vera.submit_ring_report(&context(), &legacy).is_err());
    assert_eq!(vera.store().serialize(), before);
    legacy.signature_scheme = first.signature_scheme.clone();
    assert!(vera.submit_ring_report(&context(), &legacy).is_err());
    assert_eq!(vera.store().serialize(), before);
    let outcome = vera.submit_ring_report(&context(), &first).unwrap();
    assert_eq!(outcome.demerits.points, 1);
    assert!(outcome.replacement.is_none());
    let before = vera.store().serialize();
    assert!(vera.submit_ring_report(&context(), &first).is_err());
    let mut another_reporter = first.report.clone();
    another_reporter.reporter_node_key = public(&secret(4));
    assert!(
        vera.submit_ring_report(&context(), &sign(another_reporter))
            .is_err()
    );
    let mut invalid = sign(report(
        &initial,
        "different",
        100,
        3,
        CommitteeScope::Current,
    ));
    invalid.signature = "00".repeat(96);
    assert!(vera.submit_ring_report(&context(), &invalid).is_err());
    assert_eq!(vera.store().serialize(), before);
    let mut later = context();
    later.timestamp.seconds = 221;
    later.timestamp.block_height = 3;
    assert!(vera.submit_ring_report(&later, &first).is_err());
    let second = sign(report(
        &initial,
        "session-1",
        221,
        3,
        CommitteeScope::Current,
    ));
    assert_eq!(
        vera.submit_ring_report(&later, &second)
            .unwrap()
            .demerits
            .points,
        2
    );
    let third = sign(report(
        &initial,
        "session-2",
        221,
        3,
        CommitteeScope::Current,
    ));
    let replaced = vera.submit_ring_report(&later, &third).unwrap();
    assert_eq!(replaced.replacement, Some(public(&secret(5))));
    let pending = vera.threshold_ring(&created.id).unwrap().unwrap();
    assert_eq!(pending.sequence, initial.sequence + 1);
    assert_eq!(pending.state, initial.state);
    let settings = pending.current_settings();
    assert_eq!(settings.peer_node_keys, initial.config.peer_node_keys);
    let target = settings.pending_reshare.unwrap();
    assert!(!target.peer_node_keys.contains(&public(&secret(3))));
    assert!(target.peer_node_keys.contains(&public(&secret(5))));
    assert_eq!(target.threshold, 2);
    let before = vera.store().serialize();
    assert!(
        vera.submit_ring_report(
            &later,
            &sign(report(
                &initial,
                "stale-state",
                221,
                3,
                CommitteeScope::Current
            ))
        )
        .is_err()
    );
    assert!(
        vera.submit_ring_report(
            &later,
            &sign(report(
                &pending,
                "wrong-scope",
                221,
                5,
                CommitteeScope::Current
            ))
        )
        .is_err()
    );
    assert_eq!(vera.store().serialize(), before);
    let new_member = vera
        .submit_ring_report(
            &later,
            &sign(report(
                &pending,
                "new-member",
                221,
                5,
                CommitteeScope::PendingNew,
            )),
        )
        .unwrap();
    assert_eq!(new_member.demerits.points, 1);
    assert!(new_member.replacement.is_none());
    later.timestamp.seconds = 86500;
    later.timestamp.block_height = 4;
    let reset = vera
        .submit_ring_report(
            &later,
            &sign(report(&pending, "reset", 86500, 3, CommitteeScope::Current)),
        )
        .unwrap();
    assert_eq!(reset.demerits.points, 1);
    assert_eq!(reset.demerits.window_started_at, 86500);
    assert_eq!(
        vera.node_demerits(&created.id, &public(&secret(3)))
            .unwrap(),
        Some(reset.demerits)
    );
    vera.store.put(
        format!("orbis/reports/v1/{}/count", created.id).as_bytes(),
        MAX_RETAINED_REPORTS.to_be_bytes().to_vec(),
    );
    let before = vera.store().serialize();
    assert!(
        vera.submit_ring_report(
            &later,
            &sign(report(
                &pending,
                "capacity",
                86500,
                3,
                CommitteeScope::Current
            ))
        )
        .is_err()
    );
    assert_eq!(vera.store().serialize(), before);
}

#[test]
fn threshold_objects_require_active_ring_and_scoped_actor_and_rollback_on_failed_outcome() {
    use crate::vera::objects::{
        EncryptedDocument, KeyDerivation, ObjectKind, ThresholdObject, object_key,
    };
    let (mut vera, mut acp, config) = fixture(POLICY);
    let ring = apply(&mut vera, &mut acp, &RingCommand::Create(config.clone()), 1).unwrap();
    let object = ThresholdObject::Document(EncryptedDocument {
        ring_id: ring.id.clone(),
        document: r#"{"enc_cmt":[1],"encrypted_data":[2],"nonce":[3]}"#.into(),
        proof: r#"{"challenge":[4],"response":[5]}"#.into(),
        policy_id: config.policy_id.clone(),
        resource: "document".into(),
        permission: "read".into(),
        tier: Some("gold".into()),
        timestamp: Some(80),
    });
    let token = |object: &ThresholdObject, entropy| {
        delegated_token(
            DelegatedOperation::StoreThresholdObject(object),
            entropy,
            &context(),
            &secret(1),
        )
    };
    let assertion = token(&object, 5);
    let before = (vera.store().serialize(), acp.store().serialize());
    assert!(
        vera.store_threshold_object(&mut acp, &context(), &submission(), &assertion, &object)
            .is_err()
    );
    assert_eq!((vera.store().serialize(), acp.store().serialize()), before);
    for n in [2, 3] {
        vera.apply_ring_participant_request(&context(), &confirm(&ring.id, n, "aabb"))
            .unwrap();
    }
    let stored = vera
        .store_threshold_object(&mut acp, &context(), &submission(), &assertion, &object)
        .unwrap();
    assert_eq!(stored.id, object.id().unwrap());
    let record = vera
        .threshold_object(ObjectKind::Document, &stored.id)
        .unwrap()
        .unwrap();
    assert_eq!(record.creator, actor().to_string());
    assert_eq!(record.object, object);
    assert_eq!(
        vera.store_threshold_object(&mut acp, &context(), &submission(), &assertion, &object)
            .unwrap(),
        stored
    );
    assert!(
        vera.store_threshold_object(
            &mut acp,
            &context(),
            &submission(),
            &token(&object, 6),
            &object
        )
        .is_err()
    );
    let mut changed = object.clone();
    if let ThresholdObject::Document(d) = &mut changed {
        d.timestamp = None;
    }
    let before = (vera.store().serialize(), acp.store().serialize());
    assert!(
        vera.store_threshold_object(&mut acp, &context(), &submission(), &assertion, &changed)
            .is_err()
    );
    assert_eq!((vera.store().serialize(), acp.store().serialize()), before);
    let mut other_worker = submission();
    other_worker.signer = actor().to_string();
    assert!(
        vera.store_threshold_object(&mut acp, &context(), &other_worker, &assertion, &object)
            .is_err()
    );
    let wrong_scope = delegated_token(
        DelegatedOperation::RingCommand(&RingCommand::Cancel {
            ring_id: ring.id.clone(),
        }),
        7,
        &context(),
        &secret(1),
    );
    assert!(
        vera.store_threshold_object(&mut acp, &context(), &submission(), &wrong_scope, &object)
            .is_err()
    );
    vera.revoke_delegation(&context(), &actor(), &assertion)
        .unwrap();
    assert!(
        vera.store_threshold_object(&mut acp, &context(), &submission(), &assertion, &object)
            .is_err()
    );
    let mut restored = VeraModule::from_store(
        crate::kv_store::InMemoryKvStore::deserialize(&vera.store().serialize()).unwrap(),
    );
    assert_eq!(
        restored
            .threshold_object(ObjectKind::Document, &stored.id)
            .unwrap(),
        Some(record)
    );
    assert!(
        restored
            .threshold_object(ObjectKind::KeyDerivation, &stored.id)
            .unwrap()
            .is_none()
    );
    let derivation = ThresholdObject::KeyDerivation(KeyDerivation {
        ring_id: ring.id,
        derivation: "tenant/key".into(),
        policy_id: config.policy_id,
        resource: "document".into(),
        permission: "sign".into(),
    });
    let assertion = token(&derivation, 8);
    let mut full = acp.store().clone();
    full.put(b"operation-bytes/v1", (64u64 << 20).to_be_bytes().to_vec());
    let mut full = AcpModule::from_store(full);
    let before = (restored.store().serialize(), full.store().serialize());
    assert!(
        restored
            .store_threshold_object(
                &mut full,
                &context(),
                &submission(),
                &assertion,
                &derivation
            )
            .is_err()
    );
    assert_eq!(
        (restored.store().serialize(), full.store().serialize()),
        before
    );
    let stored = restored
        .store_threshold_object(&mut acp, &context(), &submission(), &assertion, &derivation)
        .unwrap();
    assert_eq!(stored.kind, ObjectKind::KeyDerivation);
    let mut corrupt = restored.store().clone();
    corrupt.put(
        &object_key(stored.kind, &stored.id).unwrap(),
        b"{}".to_vec(),
    );
    assert!(
        VeraModule::from_store(corrupt)
            .threshold_object(stored.kind, &stored.id)
            .is_err()
    );
}
