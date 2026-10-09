//! Native ring creation, participant attestation and certified recovery.

use alloy_primitives::{Address, B256, Bytes};
use alloy_sol_types::{SolCall as _, SolEvent as _};
use k256::ecdsa::SigningKey;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use vera_client::threshold_objects::{
    EncryptedDocument, KeyDerivation, ObjectKind, ThresholdObject, encode_threshold_object,
};
use vera_client::{
    ACP_ADDRESS, BlsSigner, DelegationScope, NativeReceipt, VERA_ADDRESS, VeraClient,
    create_scoped_bearer_token,
    nodes::{NodeCommand, NodeInfo, NodeRequest, encode_node_request, sign_node_request},
    rings::*,
};
use vera_domain::{ConsensusPublicKey, NativeTx};
use vera_e2e::cluster::{ConsensusParams, KeySet, TestCluster};
use vera_modules::acp::{
    abi::IAcp,
    types::{Object, PolicyCmd},
};

const POLICY: &str = "name: rings\nresources:\n  - name: ring_policy\n    relations:\n      - name: creator\n    permissions:\n      - name: create_ring\n        expr: creator\n  - name: ring\n    relations:\n      - name: operator\n    permissions:\n      - name: update_ring\n        expr: operator\n";
fn public(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_sec1_bytes())
}

async fn execute(
    writer: &VeraClient,
    reader: &VeraClient,
    worker: &BlsSigner,
    trusted: &ConsensusPublicKey,
    target: Address,
    call: Bytes,
    success: bool,
) -> NativeReceipt {
    let call_bytes = call.len();
    let receipt_deadline = if call_bytes > 8 << 20 {
        vera_e2e::readiness_deadline().max(Duration::from_secs(120))
    } else {
        Duration::from_secs(30)
    };
    let wire = worker.sign_native_tx(target, call).unwrap();
    let id = writer.send_native_tx(&wire).await.unwrap();
    assert_eq!(id, NativeTx::decode_wire(&wire).unwrap().tx_id().0);
    tokio::time::timeout(receipt_deadline, async {
        loop {
            let (local, remote) = tokio::try_join!(
                writer.read_receipt(id, trusted),
                reader.read_receipt(id, trusted)
            )
            .unwrap();
            if let (Some(local), Some(_)) = (local, remote) {
                assert_eq!(local.verify(id, trusted).unwrap().success(), success);
                return writer.get_native_receipt(id).await.unwrap().unwrap();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "native receipt timed out after {receipt_deadline:?}: tx_id={id}, call_bytes={call_bytes}"
        )
    })
}

#[tokio::test]
async fn native_ring_lifecycle_preserves_actor_authority_and_terminal_state() {
    let deployment = 9067;
    let ring_secret = blst::min_pk::SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let ring_public = hex::encode(ring_secret.sk_to_pk().to_bytes());
    let trusted = *KeySet::builder()
        .seed(deployment)
        .build()
        .unwrap()
        .epoch_info()
        .output
        .public()
        .public();
    let mut cluster = TestCluster::builder()
        .nodes(4)
        .seed(deployment)
        .chain_id(deployment)
        // The report larger than 8 MiB must fit inside one consensus round
        // even when validators share a busy runner.
        .consensus_params(ConsensusParams {
            leader_timeout: Duration::from_secs(10),
            notarization_timeout: Duration::from_secs(20),
            nullify_retry: Duration::from_secs(2),
        })
        .build()
        .await
        .unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    cluster
        .observe(Duration::from_millis(100))
        .wait_for_height(3, Duration::from_secs(30))
        .await
        .unwrap();
    let writer = VeraClient::new(cluster.node(0).rpc_url());
    let reader = VeraClient::new(cluster.node(3).rpc_url());
    let first: serde_json::Value = writer
        .rpc_call_typed("eth_getBlockByNumber", serde_json::json!(["0x1", false]))
        .await
        .unwrap();
    let root: B256 = first["parentHash"].as_str().unwrap().parse().unwrap();
    let worker = BlsSigner::new(7u64.into(), deployment).unwrap();
    let issuer = SigningKey::from_slice(&[30; 32]).unwrap();
    let actor = vera_crypto::secp256k1::did_from_secp256k1_pubkey(
        issuer.verifying_key().to_sec1_bytes().as_ref(),
    )
    .unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = |scope| {
        create_scoped_bearer_token(&issuer, worker.did(), deployment, now, now + 300, scope)
            .unwrap()
    };
    let created = execute(
        &writer,
        &reader,
        &worker,
        &trusted,
        ACP_ADDRESS,
        IAcp::bearerCreatePolicyCall {
            bearerToken: token(DelegationScope::CreatePolicy),
            policy: POLICY.as_bytes().to_vec().into(),
            marshalType: 1,
        }
        .abi_encode()
        .into(),
        true,
    )
    .await;
    let log = &created.logs[0];
    let event = IAcp::DelegatedPolicyCreated::decode_raw_log_validate(
        log.topics.iter().copied(),
        &log.data,
    )
    .unwrap();
    assert_eq!(event.creator, actor);
    let policy = hex::encode(event.policyId);
    for cmd in [
        PolicyCmd::RegisterObject(Object {
            resource: "ring_policy".into(),
            id: policy.clone(),
        }),
        PolicyCmd::SetRelationship(acp::Relationship::with_entity(
            "ring_policy",
            &policy,
            "creator",
            identity::Did::new(&actor).unwrap(),
        )),
    ] {
        execute(
            &writer,
            &reader,
            &worker,
            &trusted,
            ACP_ADDRESS,
            IAcp::bearerPolicyCmdCall {
                bearerToken: token(DelegationScope::PolicyCommands),
                policyId: event.policyId,
                cmd: serde_json::to_vec(&cmd).unwrap().into(),
            }
            .abi_encode()
            .into(),
            true,
        )
        .await;
    }
    let nodes = [
        SigningKey::from_slice(&[31; 32]).unwrap(),
        SigningKey::from_slice(&[32; 32]).unwrap(),
        SigningKey::from_slice(&[33; 32]).unwrap(),
        SigningKey::from_slice(&[34; 32]).unwrap(),
    ];
    for key in &nodes {
        let signed = sign_node_request(
            NodeRequest {
                deployment_root: root.0,
                deployment_id: deployment,
                node_key: public(key),
                sequence: 0,
                expires_at: now + 300,
                command: NodeCommand::Register(NodeInfo {
                    peer_id: public(key),
                    controller_key: public(key),
                    allowed_policy_ids: vec![policy.clone()],
                    allowed_ring_ids: vec![],
                }),
            },
            key,
        )
        .unwrap();
        execute(
            &writer,
            &reader,
            &worker,
            &trusted,
            VERA_ADDRESS,
            encode_node_request(&signed).unwrap(),
            true,
        )
        .await;
    }
    let mut peers = nodes[..3].iter().map(public).collect::<Vec<_>>();
    peers.sort();
    let mut config = RingConfig {
        policy_id: policy,
        peer_node_keys: peers,
        threshold: 2,
        pss_interval: 86400,
        current_version: 0,
        requires_pet: false,
        nonce: [1; 32],
        trusted_auth_relay_dids: None,
        reporting: ReportingConfig {
            kick_threshold: 1,
            backup_node_keys: vec![public(&nodes[3])],
            ..Default::default()
        },
    };
    let ring = config.id(root.0, &actor).unwrap();
    let command = RingCommand::Create(config.clone());
    execute(
        &writer,
        &reader,
        &worker,
        &trusted,
        VERA_ADDRESS,
        encode_ring_command(&command, &token(DelegationScope::PolicyCommands)).unwrap(),
        false,
    )
    .await;
    assert!(
        reader
            .read_threshold_ring(&ring, 0, &trusted)
            .await
            .unwrap()
            .record
            .is_none()
    );
    let created = execute(
        &writer,
        &reader,
        &worker,
        &trusted,
        VERA_ADDRESS,
        encode_ring_command(&command, &token(DelegationScope::ManageRings)).unwrap(),
        true,
    )
    .await;
    let record = reader
        .read_threshold_ring(&ring, created.block_number, &trusted)
        .await
        .unwrap()
        .record
        .unwrap();
    assert_eq!(record.creator, actor);
    assert!(matches!(record.state, RingState::Pending { .. }));
    let participant = |id: &str, key: &SigningKey, command| {
        sign_ring_participant_request(
            RingParticipantRequest {
                deployment_root: root.0,
                deployment_id: deployment,
                ring_id: id.into(),
                node_key: public(key),
                command,
                expires_at: now + 300,
            },
            key,
        )
        .unwrap()
    };
    let first = participant(
        &ring,
        &nodes[0],
        RingParticipantCommand::Confirm(RingPublicKeys {
            public_key: ring_public.clone(),
            pet_public_key: None,
        }),
    );
    execute(
        &writer,
        &reader,
        &worker,
        &trusted,
        VERA_ADDRESS,
        encode_ring_participant_request(&first).unwrap(),
        true,
    )
    .await;
    let duplicate = participant(
        &ring,
        &nodes[0],
        RingParticipantCommand::Confirm(RingPublicKeys {
            public_key: "ccdd".into(),
            pet_public_key: None,
        }),
    );
    execute(
        &writer,
        &reader,
        &worker,
        &trusted,
        VERA_ADDRESS,
        encode_ring_participant_request(&duplicate).unwrap(),
        false,
    )
    .await;
    let second = participant(
        &ring,
        &nodes[1],
        RingParticipantCommand::Confirm(RingPublicKeys {
            public_key: ring_public.clone(),
            pet_public_key: None,
        }),
    );
    execute(
        &writer,
        &reader,
        &worker,
        &trusted,
        VERA_ADDRESS,
        encode_ring_participant_request(&second).unwrap(),
        true,
    )
    .await;
    let confirmed = execute(
        &writer,
        &reader,
        &worker,
        &trusted,
        VERA_ADDRESS,
        encode_ring_participant_request(&participant(
            &ring,
            &nodes[2],
            RingParticipantCommand::Confirm(RingPublicKeys {
                public_key: ring_public.clone(),
                pet_public_key: None,
            }),
        ))
        .unwrap(),
        true,
    )
    .await;
    let active = reader
        .read_threshold_ring(&ring, confirmed.block_number, &trusted)
        .await
        .unwrap()
        .record
        .unwrap();
    let document = ThresholdObject::Document(EncryptedDocument {
        ring_id: ring.clone(),
        document: r#"{"enc_cmt":[1],"encrypted_data":[2],"nonce":[3]}"#.into(),
        proof: r#"{"challenge":[4],"response":[5]}"#.into(),
        pet_tag: None,
        pet_tag_proof: None,
        policy_id: config.policy_id.clone(),
        resource: "document".into(),
        permission: "read".into(),
        tier: Some("gold".into()),
        timestamp: Some(now),
    });
    let derivation = ThresholdObject::KeyDerivation(KeyDerivation {
        ring_id: ring.clone(),
        derivation: "tenant/key".into(),
        policy_id: config.policy_id.clone(),
        resource: "document".into(),
        permission: "sign".into(),
    });
    let object_token = token(DelegationScope::StoreThresholdObject);
    for object in [&document, &derivation] {
        let receipt = execute(
            &writer,
            &reader,
            &worker,
            &trusted,
            VERA_ADDRESS,
            encode_threshold_object(object, &object_token).unwrap(),
            true,
        )
        .await;
        let record = reader
            .read_threshold_object(
                object.kind(),
                &object.id().unwrap(),
                receipt.block_number,
                &trusted,
            )
            .await
            .unwrap()
            .record
            .unwrap();
        assert_eq!(&record.object, object);
        assert_eq!(record.creator, actor);
        execute(
            &writer,
            &reader,
            &worker,
            &trusted,
            VERA_ADDRESS,
            encode_threshold_object(object, &object_token).unwrap(),
            false,
        )
        .await;
    }
    assert!(
        reader
            .read_threshold_object(
                ObjectKind::KeyDerivation,
                &document.id().unwrap(),
                confirmed.block_number,
                &trusted
            )
            .await
            .unwrap()
            .record
            .is_none()
    );
    let mut report = ReportEnvelope {
        domain: "orbis-mpc-fault-report".into(),
        report_type: "node_offline".into(),
        chain_id: ring_deployment_label(root.0, deployment),
        ring_id: ring.clone(),
        ring_pk: ring_public.clone(),
        ring_state_sha256: active.report_state_hash().unwrap(),
        reporter_node_key: public(&nodes[0]),
        accused_node_key: public(&nodes[1]),
        accused_peer_id: public(&nodes[1]),
        observed_at: now - 10,
        expires_at: now + 110,
        session_id: "native-ring-report".into(),
        payload: NodeOffline {
            origin_protocol: "pre".into(),
            origin_protocol_version: 0,
            accused_committee_scope: CommitteeScope::Current,
            signing_committee_scope: CommitteeScope::Current,
        }
        .canonical_bytes(),
    };
    report.report_type = "invalid_crypto_response".into();
    report.payload = orbis_reporting::InvalidCryptoResponse::Sign {
        statement: orbis_reporting::SignResponseStatement {
            domain: orbis_reporting::SIGN_RESPONSE_DOMAIN.into(),
            chain_id: report.chain_id.clone(),
            ring_id: ring.clone(),
            ring_pk: ring_public.clone(),
            ring_state_sha256: report.ring_state_sha256.clone(),
            protocol_version: 0,
            request_id: report.session_id.clone(),
            signed_at: now,
            responder_node_key: report.accused_node_key.clone(),
            origin_protocol: "sign".into(),
            accused_committee_scope: CommitteeScope::Current,
            signing_committee_scope: CommitteeScope::Current,
            from_node_id: 2,
            message: vec![255; 1 << 20],
            signing_commitments: vec![255; 1 << 20],
            derivation: None,
            metadata: None,
            sig_share: vec![1],
            crypto_backend: "bls12-381".into(),
        },
        response_signature: vec![5; 64],
    }
    .canonical_bytes();
    let signed = SignedReport {
        report_id: report.report_id(),
        signature_scheme: "bls12_381_g1_pk_g2_sig_aug_v1".into(),
        signature: hex::encode(
            ring_secret
                .sign(
                    &report.canonical_bytes(),
                    b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_",
                    &ring_secret.sk_to_pk().to_bytes(),
                )
                .to_bytes(),
        ),
        report,
    };
    let encoded = encode_ring_report(&signed).unwrap();
    assert!(encoded.len() > 8 << 20);
    assert!(encoded.len() < vera_domain::MAX_TX_BYTES);
    let announced = execute(
        &writer,
        &reader,
        &worker,
        &trusted,
        VERA_ADDRESS,
        encoded.clone(),
        true,
    )
    .await;
    execute(
        &writer,
        &reader,
        &worker,
        &trusted,
        VERA_ADDRESS,
        encoded,
        false,
    )
    .await;
    execute(
        &writer,
        &reader,
        &worker,
        &trusted,
        VERA_ADDRESS,
        encode_ring_command(
            &RingCommand::Update {
                ring_id: ring.clone(),
                expected_sequence: active.sequence,
                update: RingUpdate::SetPssInterval(90000),
            },
            &token(DelegationScope::ManageRings),
        )
        .unwrap(),
        false,
    )
    .await;
    cluster.restart_node(3).unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    let recovered = tokio::time::timeout(vera_e2e::readiness_deadline(), async {
        loop {
            match reader
                .read_threshold_ring(&ring, announced.block_number, &trusted)
                .await
            {
                Ok(read) => break read,
                Err(cause) if cause.is_retryable() => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(cause) => panic!("recovered ring proof failed: {cause}"),
            }
        }
    })
    .await
    .expect("recovered ring proof did not become available before the readiness deadline")
    .record
    .unwrap();
    let report_receipt = reader
        .read_receipt(announced.transaction_hash, &trusted)
        .await
        .unwrap()
        .unwrap();
    assert!(
        report_receipt
            .verify(announced.transaction_hash, &trusted)
            .unwrap()
            .success()
    );
    assert_eq!(
        recovered.state,
        RingState::Active {
            keys: RingPublicKeys {
                public_key: ring_public.clone(),
                pet_public_key: None
            }
        }
    );
    assert_eq!(recovered.config, config);
    assert_eq!(recovered.sequence, active.sequence + 1);
    for object in [&document, &derivation] {
        assert_eq!(
            reader
                .read_threshold_object(
                    object.kind(),
                    &object.id().unwrap(),
                    announced.block_number,
                    &trusted
                )
                .await
                .unwrap()
                .record
                .unwrap()
                .object,
            *object
        );
    }
    let settings = recovered.current_settings();
    assert_eq!(settings.threshold, 2);
    assert_eq!(settings.pss_interval, 86400);
    let mut replacement_peers = config.peer_node_keys.clone();
    replacement_peers.retain(|key| key != &public(&nodes[1]));
    replacement_peers.push(public(&nodes[3]));
    replacement_peers.sort();
    assert_eq!(
        settings.pending_reshare.unwrap(),
        ReshareTarget {
            peer_node_keys: replacement_peers.clone(),
            threshold: 2
        }
    );

    let signature = ring_secret
        .sign(
            &recovered.reshare_signing_bytes(deployment).unwrap(),
            b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_",
            &ring_secret.sk_to_pk().to_bytes(),
        )
        .to_bytes();
    let finalize = encode_ring_reshare(&RingReshareRequest {
        deployment_root: root.0,
        deployment_id: deployment,
        ring_id: ring.clone(),
        expected_sequence: recovered.sequence,
        scheme: ThresholdScheme::Bls12381AugV1,
        signature: hex::encode(signature),
    })
    .unwrap();
    let finalized = execute(
        &writer,
        &reader,
        &worker,
        &trusted,
        VERA_ADDRESS,
        finalize.clone(),
        true,
    )
    .await;
    execute(
        &writer,
        &reader,
        &worker,
        &trusted,
        VERA_ADDRESS,
        finalize,
        false,
    )
    .await;
    cluster.restart_node(3).unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    let final_record = reader
        .read_threshold_ring(&ring, finalized.block_number, &trusted)
        .await
        .unwrap()
        .record
        .unwrap();
    assert_eq!(final_record.state, recovered.state);
    assert_eq!(final_record.config, config);
    assert_eq!(final_record.sequence, recovered.sequence + 1);
    assert_eq!(final_record.current_settings().threshold, 2);
    assert_eq!(
        final_record.current_settings().peer_node_keys,
        replacement_peers
    );
    assert!(final_record.current_settings().pending_reshare.is_none());

    config.nonce = [2; 32];
    let ring = config.id(root.0, &actor).unwrap();
    let create = encode_ring_command(
        &RingCommand::Create(config),
        &token(DelegationScope::ManageRings),
    )
    .unwrap();
    execute(
        &writer,
        &reader,
        &worker,
        &trusted,
        VERA_ADDRESS,
        create.clone(),
        true,
    )
    .await;
    let cancel = participant(&ring, &nodes[0], RingParticipantCommand::Cancel);
    let cancelled = execute(
        &writer,
        &reader,
        &worker,
        &trusted,
        VERA_ADDRESS,
        encode_ring_participant_request(&cancel).unwrap(),
        true,
    )
    .await;
    assert!(matches!(
        reader
            .read_threshold_ring(&ring, cancelled.block_number, &trusted)
            .await
            .unwrap()
            .record
            .unwrap()
            .state,
        RingState::Cancelled { .. }
    ));
    execute(
        &writer,
        &reader,
        &worker,
        &trusted,
        VERA_ADDRESS,
        create,
        false,
    )
    .await;
    execute(
        &writer,
        &reader,
        &worker,
        &trusted,
        VERA_ADDRESS,
        encode_ring_participant_request(&participant(
            &ring,
            &nodes[1],
            RingParticipantCommand::Confirm(RingPublicKeys {
                public_key: ring_public.clone(),
                pet_public_key: None,
            }),
        ))
        .unwrap(),
        false,
    )
    .await;
}
