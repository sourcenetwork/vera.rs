//! Cross-language signing and proof verification against a native cluster.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy_sol_types::SolCall as _;
use commonware_codec::Encode as _;
use k256::ecdsa::SigningKey;
use vera_client::{
    ACP_ADDRESS, BlsSigner, DelegationScope, VERA_ADDRESS, VeraClient,
    administration::{AdministrativeCommand, SignedAdministrativeRequest},
};
use vera_crypto::operation::OperationId;
use vera_domain::{ConsensusPublicKey, NativeTx};
use vera_e2e::cluster::{ConsensusPreset, GenesisBuilder, KeySet, TestCluster};
use vera_modules::{
    acp::{
        delegated_operation::DelegatedOperation,
        operation::{OperationRecord, operation_key},
        types::PolicyMarshalingType,
    },
    vera::{abi::IVera, relay::RelayGrant},
};

#[path = "support/administration.rs"]
mod administration_support;

#[tokio::test]
#[ignore = "requires TRUST_NATIVE_TEST_BINARY built with vera_native and its shared library"]
async fn native_go_workers_verify_policy_creation() {
    native_go_workflow(false).await;
}

#[tokio::test]
#[ignore = "requires TRUST_NATIVE_TEST_BINARY and TRUST_NATIVE_GATEWAY_TEST_BINARY with vera_native"]
async fn native_go_gateway_verifies_pipelined_vera() {
    std::env::var("TRUST_NATIVE_GATEWAY_TEST_BINARY").expect("Go gateway test binary required");
    native_go_workflow(true).await;
}

async fn native_go_workflow(pipelined: bool) {
    let binary = std::env::var("TRUST_NATIVE_TEST_BINARY").expect("Go native test binary required");
    let deployment = 9063;
    let trusted = *KeySet::builder()
        .seed(deployment)
        .build()
        .unwrap()
        .epoch_info()
        .output
        .public()
        .public();
    let genesis = GenesisBuilder::devnet().operators(administration_support::operators());
    let genesis = if pipelined {
        genesis
            .blocks_per_epoch(192)
            .simplex(vera_domain::SimplexParameters::default())
    } else {
        genesis
    };
    let mut cluster = TestCluster::builder()
        .nodes(4)
        .seed(deployment)
        .chain_id(deployment)
        .genesis(genesis)
        .preset(ConsensusPreset::Normal)
        .build()
        .await
        .unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    let client = VeraClient::new(cluster.node(0).rpc_url());
    let key = SigningKey::from_slice(&[42; 32]).unwrap();
    let issuer = vera_crypto::secp256k1::did_from_secp256k1_pubkey(
        key.verifying_key().to_encoded_point(true).as_bytes(),
    )
    .unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let approved = administration_support::approve(
        &client,
        AdministrativeCommand::SetRelay(RelayGrant {
            issuer: issuer.clone(),
            scopes: vec![
                DelegationScope::PolicyCommands,
                DelegationScope::CreatePolicy,
                DelegationScope::EditPolicy,
                DelegationScope::RecordAccessDecision,
            ],
            expires_at: now + 600,
        }),
        0,
    )
    .await;
    let operator = BlsSigner::new(9u64.into(), deployment).unwrap();
    apply(&client, &client, &trusted, &operator, &approved).await;
    let budget = administration_support::approve(
        &client,
        AdministrativeCommand::SetOperationBudget(128 << 20),
        1,
    )
    .await;
    apply(&client, &client, &trusted, &operator, &budget).await;

    let signer = BlsSigner::new(7u64.into(), deployment).unwrap();
    let vector = signer
        .sign_native_tx_with_sequence(ACP_ADDRESS, vec![1, 2, 3].into(), 0)
        .unwrap();
    let definition = "name: shared\nresources:\n  - name: document\n";
    let unicode = "<>&\u{2028}\u{2029}\\u2028\\u2029\n\t\"\\";
    let vectors: Vec<_> = [definition, unicode]
        .into_iter()
        .map(|value| {
            serde_json::json!({
                "definition": value,
                "operation": hex::encode(DelegatedOperation::CreatePolicy(
                    value, &PolicyMarshalingType::ShortYaml,
                ).digest().unwrap()),
            })
        })
        .collect();
    let mut operation_id = [11; 32];
    operation_id[..8].copy_from_slice(&(now + 500).to_be_bytes());
    let operation_id = OperationId(operation_id);
    let outcome_key = operation_key(&format!("did:opk:{}", "ab".repeat(32)), operation_id).unwrap();
    let mut fixture = serde_json::json!({
        "endpoint": cluster.node(0).rpc_url(),
        "worker_journal": cluster.node(0).data_dir.join("trust-native-worker.db"),
        "trusted_key": hex::encode(trusted.encode()),
        "deployment": deployment,
        "genesis": hex::encode(approved.request.genesis_id),
        "issuer": issuer.clone(),
        "wire": hex::encode(&vector),
        "submission": NativeTx::decode_wire(&vector).unwrap().tx_id().0,
        "worker": signer.did(),
        "vectors": vectors,
        "operation_id": hex::encode(operation_id.0),
        "operation_key": hex::encode(&outcome_key),
    });
    run_client(&binary, &fixture).await;
    let outcome = client
        .read_current_record(
            vera_client::ModuleId::Acp,
            &outcome_key,
            0,
            &trusted,
            vera_client::RECORD_PROOF_BYTES,
        )
        .await
        .unwrap();
    let outcome: OperationRecord =
        serde_json::from_slice(outcome.record.value.as_ref().unwrap()).unwrap();
    let replica = VeraClient::new(cluster.node(3).rpc_url());
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(proof) = replica
                .read_receipt(outcome.submission.into(), &trusted)
                .await
                .unwrap()
            {
                assert!(
                    proof
                        .verify(outcome.submission.into(), &trusted)
                        .unwrap()
                        .success()
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    cluster.restart_node(3).unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    fixture["endpoint"] = serde_json::json!(cluster.node(3).rpc_url());
    let budget = replica
        .read_current_record(
            vera_client::ModuleId::Acp,
            b"operation-budget/v1",
            0,
            &trusted,
            vera_client::RECORD_PROOF_BYTES,
        )
        .await
        .unwrap();
    assert_eq!(
        budget.record.value.unwrap().as_ref(),
        (128u64 << 20).to_be_bytes()
    );
    fixture["recover"] = serde_json::json!(true);
    fixture["expected_policy"] = outcome.result["policy"]["id"].clone();
    run_client(&binary, &fixture).await;
    fixture["recover"] = serde_json::json!(false);
    let revoked =
        administration_support::approve(&client, AdministrativeCommand::RevokeRelay(issuer), 2)
            .await;
    apply(&client, &replica, &trusted, &operator, &revoked).await;
    cluster.restart_node(3).unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    fixture["endpoint"] = serde_json::json!(cluster.node(3).rpc_url());
    fixture["revoked"] = serde_json::json!(true);
    run_client(&binary, &fixture).await;
}

async fn apply(
    client: &VeraClient,
    observer: &VeraClient,
    trusted: &ConsensusPublicKey,
    operator: &BlsSigner,
    approved: &SignedAdministrativeRequest,
) {
    let wire = operator
        .sign_native_tx(
            VERA_ADDRESS,
            IVera::applyAdministrationCall {
                request: serde_json::to_vec(approved).unwrap().into(),
            }
            .abi_encode()
            .into(),
        )
        .unwrap();
    let submission = client.send_native_tx(&wire).await.unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(proof) = observer.read_receipt(submission, trusted).await.unwrap() {
                assert!(proof.verify(submission, trusted).unwrap().success());
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
}

async fn run_client(binary: &str, fixture: &serde_json::Value) {
    run_go_test(
        binary,
        "-test.run=^TestNative(Cluster|KeysCluster|CommandsCluster)$",
        fixture,
    )
    .await;
    if let Ok(gateway) = std::env::var("TRUST_NATIVE_GATEWAY_TEST_BINARY") {
        run_go_test(&gateway, "-test.run=^TestNativeGatewayCluster$", fixture).await;
    }
}

async fn run_go_test(binary: &str, selector: &str, fixture: &serde_json::Value) {
    let mut command = tokio::process::Command::new(binary);
    command
        .args([selector, "-test.v", "-test.timeout=120s"])
        .env("VERA_NATIVE_FIXTURE", fixture.to_string())
        .kill_on_drop(true);
    let status = tokio::time::timeout(Duration::from_secs(125), command.status())
        .await
        .expect("Go client must finish within its deadline")
        .expect("launch Go native client test");
    assert!(status.success(), "Go native client failed: {status}");
}

#[tokio::test]
#[ignore = "requires TRUST_NATIVE_TEST_BINARY built with vera_native and its shared library"]
async fn native_go_policy_pages() {
    let binary = std::env::var("TRUST_NATIVE_TEST_BINARY").expect("Go native test binary required");
    let deployment = 9064;
    let trusted = *KeySet::builder()
        .seed(deployment)
        .build()
        .unwrap()
        .epoch_info()
        .output
        .public()
        .public();
    let cluster = TestCluster::builder()
        .nodes(4)
        .seed(deployment)
        .chain_id(deployment)
        .preset(ConsensusPreset::Normal)
        .build()
        .await
        .unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    let client = VeraClient::new(cluster.node(0).rpc_url());
    let signer = BlsSigner::new(7u64.into(), deployment).unwrap();
    let mut minimum = 0;
    for i in 0..3 {
        let data = vera_modules::acp::abi::IAcp::createPolicyCall {
            policy: format!("name: page{i}\nresources:\n  - name: document\n")
                .into_bytes()
                .into(),
            marshalType: 1,
        }
        .abi_encode();
        let wire = signer.sign_native_tx(ACP_ADDRESS, data.into()).unwrap();
        let submission = client.send_native_tx(&wire).await.unwrap();
        minimum = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if let Some(proof) = client.read_receipt(submission, &trusted).await.unwrap() {
                    assert!(proof.verify(submission, &trusted).unwrap().success());
                    break proof.revision.height;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
    }
    let request = vera_permission::PrefixPageRequest {
        module: vera_permission::ModuleId::Acp,
        prefix: b"policy/objs/".to_vec().into(),
        start: b"policy/objs/".to_vec().into(),
        limit: 2,
    };
    let response = client
        .read_current_prefix_page(
            &request,
            minimum,
            &trusted,
            vera_permission::PAGE_PROOF_BYTES,
        )
        .await
        .unwrap();
    let page = response
        .verify(
            &request,
            minimum,
            &trusted,
            vera_permission::PAGE_PROOF_BYTES,
        )
        .unwrap();
    assert_eq!(page.entries.len(), 2);
    assert!(page.continuation.is_some());
    run_go_test(
        &binary,
        "-test.run=^TestNativePolicyPagesCluster$",
        &serde_json::json!({
            "endpoint": cluster.node(0).rpc_url(),
            "trusted_key": hex::encode(trusted.encode()),
            "minimum_revision": minimum,
        }),
    )
    .await;
}
