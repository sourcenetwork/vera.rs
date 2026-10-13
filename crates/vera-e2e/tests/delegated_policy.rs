//! Actor-owned policy lifecycle through independent native signing workers.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy_primitives::Address;
use alloy_sol_types::{SolCall, SolEvent};
use commonware_codec::Encode as _;
use k256::ecdsa::SigningKey;
use vera_client::{
    ACP_ADDRESS, BlsSigner, ClientError, DelegationScope, ModuleId, NativeReceipt,
    RECORD_PROOF_BYTES, VERA_ADDRESS, VeraClient, create_bearer_token, create_scoped_bearer_token,
};
use vera_domain::{ConsensusPublicKey, NativeTx};
use vera_e2e::cluster::{ConsensusPreset, GenesisBuilder, KeySet, TestCluster};
use vera_modules::{
    acp::{abi::IAcp, keys::policy_key, types::PolicyRecord},
    vera::abi::IVera,
};

const POLICY: &str = "name: shared\nresources:\n  - name: document\n";
const EDITED: &str = "name: edited\nresources:\n  - name: document\n";

async fn submit(
    client: &VeraClient,
    trusted: &ConsensusPublicKey,
    signer: &BlsSigner,
    target: Address,
    call: impl SolCall,
) -> NativeReceipt {
    let wire = signer
        .sign_native_tx(target, call.abi_encode().into())
        .unwrap();
    let tx = NativeTx::decode_wire(&wire).unwrap();
    let hash = client.send_native_tx(&wire).await.unwrap();
    assert_eq!(hash, tx.tx_id().0);
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(receipt) = client.get_native_receipt(hash).await.unwrap() {
                assert_eq!(receipt.transaction_hash, hash);
                assert_eq!(receipt.signer_did.as_deref(), Some(signer.did()));
                assert_eq!(receipt.native_nonce, Some(tx.nonce));
                // The receipt index can publish a moment before the height's
                // finalization certificate; retry until the evidence lands.
                let evidence = match client.read_receipt(hash, trusted).await.unwrap() {
                    Some(evidence) => evidence,
                    None => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let verified = evidence.verify(hash, trusted).unwrap();
                assert_eq!(evidence.revision.height, receipt.block_number);
                assert_eq!(verified.success(), receipt.status == 1);
                assert_eq!(verified.logs().len(), receipt.logs.len());
                for (proven, displayed) in verified.logs().iter().zip(&receipt.logs) {
                    assert_eq!(proven.address, displayed.address);
                    assert_eq!(proven.topics(), displayed.topics);
                    assert_eq!(proven.data.data, displayed.data);
                }
                return receipt;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap()
}

fn create(token: &str) -> IAcp::bearerCreatePolicyCall {
    IAcp::bearerCreatePolicyCall {
        bearerToken: token.into(),
        policy: POLICY.as_bytes().to_vec().into(),
        marshalType: 1,
    }
}

fn created_id(receipt: &NativeReceipt, owner: &str) -> String {
    assert_eq!(receipt.status, 1);
    assert_eq!(receipt.logs.len(), 1);
    let log = &receipt.logs[0];
    assert_eq!(log.address, ACP_ADDRESS);
    let event = IAcp::DelegatedPolicyCreated::decode_raw_log_validate(
        log.topics.iter().copied(),
        &log.data,
    )
    .unwrap();
    assert_eq!(event.creator, owner);
    hex::encode(event.policyId)
}

async fn policy(
    client: &VeraClient,
    id: &str,
    minimum: u64,
    trusted: &ConsensusPublicKey,
) -> PolicyRecord {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match client
                .read_current_record(
                    ModuleId::Acp,
                    &policy_key(id),
                    minimum,
                    trusted,
                    RECORD_PROOF_BYTES,
                )
                .await
            {
                Ok(proof) => {
                    return serde_json::from_slice(proof.record.value.as_ref().unwrap()).unwrap();
                }
                // -32002 here is a transient wait: the replica's index has
                // not reached the confirmed revision yet, or its evidence
                // deadline expired while waiting for it.
                Err(ClientError::Rpc { code: -32002, .. }) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(error) => panic!("verified policy read failed: {error}"),
            }
        }
    })
    .await
    .expect("replica must reach the confirmed revision")
}

#[tokio::test]
async fn native_workers_preserve_policy_ownership_results_and_revocation() {
    let deployment = 9059;
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
        .genesis(GenesisBuilder::devnet().simplex(Default::default()))
        .preset(ConsensusPreset::Normal)
        .build()
        .await
        .unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    let client = VeraClient::new(cluster.node(0).rpc_url());
    let actor_key = SigningKey::from_slice(&[42; 32]).unwrap();
    let owner = vera_crypto::secp256k1::did_from_secp256k1_pubkey(
        actor_key.verifying_key().to_encoded_point(true).as_bytes(),
    )
    .unwrap();
    let first = BlsSigner::new(7u64.into(), deployment).unwrap();
    let second = BlsSigner::new(8u64.into(), deployment).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let first_token = create_scoped_bearer_token(
        &actor_key,
        first.did(),
        deployment,
        now,
        now + 300,
        DelegationScope::CreatePolicy,
    )
    .unwrap();
    let second_token = create_scoped_bearer_token(
        &actor_key,
        second.did(),
        deployment,
        now,
        now + 300,
        DelegationScope::CreatePolicy,
    )
    .unwrap();
    let second_edit_token = create_scoped_bearer_token(
        &actor_key,
        second.did(),
        deployment,
        now,
        now + 300,
        DelegationScope::EditPolicy,
    )
    .unwrap();
    let commands_token =
        create_bearer_token(&actor_key, first.did(), deployment, now, now + 300).unwrap();
    let (first_receipt, second_receipt) = tokio::join!(
        submit(&client, &trusted, &first, ACP_ADDRESS, create(&first_token)),
        submit(
            &client,
            &trusted,
            &second,
            ACP_ADDRESS,
            create(&second_token)
        ),
    );
    let first_id = created_id(&first_receipt, &owner);
    let second_id = created_id(&second_receipt, &owner);
    assert_ne!(first_id, second_id);
    let minimum = first_receipt.block_number.max(second_receipt.block_number);
    for (id, receipt, worker) in [
        (&first_id, &first_receipt, &first),
        (&second_id, &second_receipt, &second),
    ] {
        let record = policy(&client, id, minimum, &trusted).await;
        assert_eq!(record.policy.id, *id);
        assert_eq!(record.raw_policy, POLICY);
        assert_eq!(record.metadata.owner_did, owner);
        assert_eq!(record.metadata.tx_signer, worker.did());
        assert_eq!(record.metadata.tx_hash, receipt.transaction_hash.as_slice());
        assert_eq!(
            record.metadata.creation_ts.block_height,
            receipt.block_number
        );
        assert!(record.metadata.creation_ts.seconds >= now);
    }

    let direct = submit(
        &client,
        &trusted,
        &first,
        ACP_ADDRESS,
        IAcp::editPolicyCall {
            policyId: first_id.parse().unwrap(),
            policy: EDITED.as_bytes().to_vec().into(),
            marshalType: 1,
        },
    )
    .await;
    assert_eq!(direct.status, 0);
    let wrong_worker = submit(
        &client,
        &trusted,
        &second,
        ACP_ADDRESS,
        create(&first_token),
    )
    .await;
    assert_eq!(wrong_worker.status, 0);
    assert!(wrong_worker.logs.is_empty());
    let edit = || IAcp::bearerEditPolicyCall {
        bearerToken: second_edit_token.clone(),
        policyId: first_id.parse().unwrap(),
        policy: EDITED.as_bytes().to_vec().into(),
        marshalType: 1,
    };
    let legacy_scope = submit(
        &client,
        &trusted,
        &first,
        ACP_ADDRESS,
        create(&commands_token),
    )
    .await;
    assert_eq!(legacy_scope.status, 0);
    assert!(legacy_scope.logs.is_empty());
    let mut wrong_scope = edit();
    wrong_scope.bearerToken = second_token.clone();
    let wrong_scope = submit(&client, &trusted, &second, ACP_ADDRESS, wrong_scope).await;
    assert_eq!(wrong_scope.status, 0);
    assert!(wrong_scope.logs.is_empty());
    let edited = submit(&client, &trusted, &second, ACP_ADDRESS, edit()).await;
    assert_eq!(edited.status, 1);
    let record = policy(&client, &first_id, edited.block_number, &trusted).await;
    assert_eq!(record.raw_policy, EDITED);
    assert_eq!(record.metadata.owner_did, owner);
    assert_eq!(
        record.metadata.tx_hash,
        first_receipt.transaction_hash.as_slice()
    );

    let revoked_edit = submit(
        &client,
        &trusted,
        &second,
        VERA_ADDRESS,
        IVera::revokeDelegationCall {
            token: second_edit_token.clone(),
        },
    )
    .await;
    assert_eq!(revoked_edit.status, 1);
    let revoked = submit(
        &client,
        &trusted,
        &second,
        VERA_ADDRESS,
        IVera::revokeDelegationCall {
            token: second_token.clone(),
        },
    )
    .await;
    assert_eq!(revoked.status, 1);
    let replica = VeraClient::new(cluster.node(3).rpc_url());
    policy(&replica, &first_id, revoked.block_number, &trusted).await;
    cluster.restart_node(3).unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    for receipt in [&first_receipt, &direct] {
        let proof = replica
            .read_receipt(receipt.transaction_hash, &trusted)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            proof
                .verify(receipt.transaction_hash, &trusted)
                .unwrap()
                .success(),
            receipt.status == 1
        );
    }
    let rejected = submit(&replica, &trusted, &second, ACP_ADDRESS, edit()).await;
    assert_eq!(rejected.status, 0);
    assert!(rejected.logs.is_empty());
    let rejected = submit(
        &replica,
        &trusted,
        &second,
        ACP_ADDRESS,
        create(&second_token),
    )
    .await;
    assert_eq!(rejected.status, 0);
    assert!(rejected.logs.is_empty());
    let record = policy(&replica, &first_id, rejected.block_number, &trusted).await;
    assert_eq!(record.raw_policy, EDITED);
    assert_eq!(record.metadata.owner_did, owner);
    let still_allowed = submit(&client, &trusted, &first, ACP_ADDRESS, create(&first_token)).await;
    let third_id = created_id(&still_allowed, &owner);
    assert_ne!(third_id, first_id);
    assert_ne!(third_id, second_id);
    assert_eq!(
        client.get_native_nonce(first.did()).await.unwrap(),
        first.nonce()
    );
    assert_eq!(
        client.get_native_nonce(second.did()).await.unwrap(),
        second.nonce()
    );
}

#[path = "support/administration.rs"]
mod administration_support;

#[tokio::test]
async fn native_relay_grants_bind_workers_and_survive_revocation_restart() {
    use vera_client::{administration::AdministrativeCommand, create_relay_token};
    use vera_crypto::jwt::{JwtClaims, RelayAssertion};
    use vera_modules::{
        acp::{delegated_operation::DelegatedOperation, types::PolicyMarshalingType},
        vera::relay::RelayGrant,
    };

    let deployment = 9061;
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
        .genesis(
            GenesisBuilder::devnet()
                .operators(administration_support::operators())
                .simplex(Default::default()),
        )
        .preset(ConsensusPreset::Normal)
        .build()
        .await
        .unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    let client = VeraClient::new(cluster.node(0).rpc_url());
    cluster
        .observe(Duration::from_millis(100))
        .wait_for_height(3, Duration::from_secs(30))
        .await
        .unwrap();
    let key = SigningKey::from_slice(&[42; 32]).unwrap();
    let issuer = vera_crypto::secp256k1::did_from_secp256k1_pubkey(
        key.verifying_key().to_encoded_point(true).as_bytes(),
    )
    .unwrap();
    assert!(
        client
            .read_relay_grant(&issuer, 0, &trusted)
            .await
            .unwrap()
            .value
            .is_none()
    );
    let owner = format!("did:opk:{}", "ab".repeat(32));
    let first = BlsSigner::new(7u64.into(), deployment).unwrap();
    let second = BlsSigner::new(8u64.into(), deployment).unwrap();
    let operator_submitter = BlsSigner::new(9u64.into(), deployment).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let grant = RelayGrant {
        issuer: issuer.clone(),
        scopes: vec![DelegationScope::CreatePolicy],
        expires_at: now + 600,
    };
    let approved =
        administration_support::approve(&client, AdministrativeCommand::SetRelay(grant.clone()), 0)
            .await;
    let token = |worker: &BlsSigner, sequence| {
        create_relay_token(
            &key,
            &JwtClaims {
                request: None,
                iss: issuer.clone(),
                sub: worker.did().into(),
                exp: now + 300,
                aud: format!("vera:{deployment}"),
                scope: DelegationScope::CreatePolicy,
                iat: now,
                nbf: now,
                relay: Some(RelayAssertion {
                    actor: owner.clone(),
                    genesis_id: approved.request.genesis_id,
                    grant_sequence: sequence,
                    operation: DelegatedOperation::CreatePolicy(
                        POLICY,
                        &PolicyMarshalingType::ShortYaml,
                    )
                    .digest()
                    .unwrap(),
                }),
            },
        )
        .unwrap()
    };
    let first_token = token(&first, 0);
    let second_token = token(&second, 0);
    let rejected = submit(&client, &trusted, &first, ACP_ADDRESS, create(&first_token)).await;
    assert_eq!(rejected.status, 0);
    assert!(rejected.logs.is_empty());
    let installed = submit(
        &client,
        &trusted,
        &operator_submitter,
        VERA_ADDRESS,
        IVera::applyAdministrationCall {
            request: serde_json::to_vec(&approved).unwrap().into(),
        },
    )
    .await;
    assert_eq!(installed.status, 1);
    let (a, b) = tokio::join!(
        submit(&client, &trusted, &first, ACP_ADDRESS, create(&first_token)),
        submit(
            &client,
            &trusted,
            &second,
            ACP_ADDRESS,
            create(&second_token)
        ),
    );
    let id = created_id(&a, &owner);
    assert_ne!(id, created_id(&b, &owner));
    for receipt in [&a, &b] {
        let id = created_id(receipt, &owner);
        let record = policy(&client, &id, receipt.block_number, &trusted).await;
        assert_eq!(record.metadata.owner_did, owner);
        assert_eq!(
            Some(record.metadata.tx_signer.as_str()),
            receipt.signer_did.as_deref()
        );
        assert_eq!(record.metadata.tx_hash, receipt.transaction_hash.as_slice());
    }
    let wrong_worker = submit(
        &client,
        &trusted,
        &first,
        ACP_ADDRESS,
        create(&second_token),
    )
    .await;
    assert_eq!(wrong_worker.status, 0);
    let mut changed = create(&first_token);
    changed.policy = EDITED.as_bytes().to_vec().into();
    assert_eq!(
        submit(&client, &trusted, &first, ACP_ADDRESS, changed)
            .await
            .status,
        0
    );
    assert_eq!(
        submit(
            &client,
            &trusted,
            &first,
            VERA_ADDRESS,
            IVera::revokeDelegationCall {
                token: first_token.clone()
            }
        )
        .await
        .status,
        1
    );
    assert_eq!(
        submit(&client, &trusted, &first, ACP_ADDRESS, create(&first_token))
            .await
            .status,
        0
    );
    assert_eq!(
        submit(
            &client,
            &trusted,
            &second,
            ACP_ADDRESS,
            create(&second_token)
        )
        .await
        .status,
        1
    );

    let replacement =
        administration_support::approve(&client, AdministrativeCommand::SetRelay(grant.clone()), 1)
            .await;
    assert_eq!(
        submit(
            &client,
            &trusted,
            &operator_submitter,
            VERA_ADDRESS,
            IVera::applyAdministrationCall {
                request: serde_json::to_vec(&replacement).unwrap().into()
            }
        )
        .await
        .status,
        1
    );
    assert_eq!(
        submit(
            &client,
            &trusted,
            &second,
            ACP_ADDRESS,
            create(&second_token)
        )
        .await
        .status,
        0
    );
    let selected = client.read_relay_grant(&issuer, 0, &trusted).await.unwrap();
    let state = selected.value.unwrap();
    let inspected = relay_cli(
        &cluster.node(0).rpc_url(),
        &issuer,
        &trusted,
        selected.revision,
    )
    .await;
    assert_eq!(inspected["grant"], serde_json::to_value(&state).unwrap());

    assert_eq!(state.grant, grant);
    assert_eq!(state.sequence, 1);
    let replacement_token = token(&second, 1);
    assert_eq!(
        submit(
            &client,
            &trusted,
            &second,
            ACP_ADDRESS,
            create(&replacement_token)
        )
        .await
        .status,
        1
    );
    let replica = VeraClient::new(cluster.node(3).rpc_url());
    policy(&replica, &id, selected.revision, &trusted).await;
    let observed = replica
        .read_relay_grant(&issuer, selected.revision, &trusted)
        .await
        .unwrap();
    assert_eq!(observed.value.as_ref(), Some(&state));
    cluster.restart_node(3).unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    assert_eq!(
        replica
            .read_relay_grant(&issuer, observed.revision, &trusted)
            .await
            .unwrap()
            .value,
        Some(state)
    );
    let revoked = administration_support::approve(
        &client,
        AdministrativeCommand::RevokeRelay(issuer.clone()),
        2,
    )
    .await;
    let receipt = submit(
        &client,
        &trusted,
        &operator_submitter,
        VERA_ADDRESS,
        IVera::applyAdministrationCall {
            request: serde_json::to_vec(&revoked).unwrap().into(),
        },
    )
    .await;
    assert_eq!(receipt.status, 1);
    policy(&replica, &id, receipt.block_number, &trusted).await;
    cluster.restart_node(3).unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    let absent = replica
        .read_relay_grant(&issuer, receipt.block_number, &trusted)
        .await
        .unwrap();
    assert!(absent.revision >= receipt.block_number);
    assert!(absent.value.is_none());
    let inspected = relay_cli(
        &cluster.node(3).rpc_url(),
        &issuer,
        &trusted,
        receipt.block_number,
    )
    .await;
    assert!(inspected["grant"].is_null());

    assert_eq!(
        submit(
            &replica,
            &trusted,
            &second,
            ACP_ADDRESS,
            create(&replacement_token)
        )
        .await
        .status,
        0
    );
    assert_eq!(
        policy(&replica, &id, receipt.block_number, &trusted)
            .await
            .metadata
            .owner_did,
        owner
    );
}

async fn relay_cli(
    endpoint: &str,
    issuer: &str,
    trusted: &ConsensusPublicKey,
    minimum: u64,
) -> serde_json::Value {
    let mut command = tokio::process::Command::new(vera_e2e::resolve_binary().unwrap());
    command
        .args([
            "client",
            "--url",
            endpoint,
            "--compact",
            "vera",
            "relay-grant",
            issuer,
            "--trusted-key",
            &hex::encode(trusted.encode()),
            "--minimum-revision",
            &minimum.to_string(),
        ])
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(15), command.output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        output.status.success(),
        "relay CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(value["revision"].as_u64().unwrap() >= minimum);
    value
}
