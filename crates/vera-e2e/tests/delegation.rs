//! Signed delegation, batch rollback and revocation recovery across replicas.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy_primitives::{Address, B256, Bytes};
use alloy_sol_types::SolCall;
use vera_client::Secp256k1SigningKey as SigningKey;
use vera_client::{
    ACP_ADDRESS, BlsSigner, EvmSigner, TransactionReceipt, VERA_ADDRESS, VeraClient,
};
use vera_e2e::cluster::{ConsensusPreset, TestCluster};
use vera_modules::{
    acp::abi::IAcp,
    vera::{
        abi::IVera,
        keys::hash_jws_token,
        types::{JWSTokenRecord, JWSTokenStatus},
    },
};

const OWNER: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const POLL: Duration = Duration::from_millis(50);

fn token(submitter: &str, deployment: u64, now: u64) -> String {
    let key = SigningKey::from_slice(&hex::decode(OWNER).unwrap()).unwrap();
    vera_client::create_bearer_token(&key, submitter, deployment, now, now + 300).unwrap()
}

async fn evm(
    client: &VeraClient,
    signer: &EvmSigner,
    target: Address,
    data: Vec<u8>,
) -> TransactionReceipt {
    let nonce = client.get_nonce(signer.address()).await.unwrap();
    let raw = signer.sign_tx(target, data.into(), nonce).unwrap();
    let hash = client.send_raw_transaction(&raw).await.unwrap();
    client.wait_for_receipt(hash, POLL, 600).await.unwrap()
}

async fn native(client: &VeraClient, signer: &BlsSigner, data: Vec<u8>) -> TransactionReceipt {
    let raw = signer.sign_native_tx(ACP_ADDRESS, data.into()).unwrap();
    let hash = client.send_native_tx(&raw).await.unwrap();
    client.wait_for_receipt(hash, POLL, 600).await.unwrap()
}

fn register(policy: B256, bearer: &str, object: &str) -> Vec<u8> {
    IAcp::bearerPolicyCmdCall {
        policyId: policy,
        bearerToken: bearer.into(),
        cmd: serde_json::to_vec(
            &serde_json::json!({"RegisterObject": {"resource": "file", "id": object}}),
        )
        .unwrap()
        .into(),
    }
    .abi_encode()
}

#[tokio::test]
async fn delegation_revocation_and_failed_batch_survive_restart() {
    let mut cluster = TestCluster::builder()
        .nodes(4)
        .chain_id(9001)
        .preset(ConsensusPreset::Normal)
        .build()
        .await
        .unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    let client = VeraClient::new(cluster.node(0).rpc_url());
    let owner = EvmSigner::from_hex(OWNER, 9001).unwrap();
    let delegate = BlsSigner::new(7u64.into(), 9001).unwrap();
    let stranger = BlsSigner::new(8u64.into(), 9001).unwrap();
    let created = evm(
        &client,
        &owner,
        ACP_ADDRESS,
        IAcp::createPolicyCall {
            policy: Bytes::from_static(b"name: delegation\nresources:\n  - name: file\n"),
            marshalType: 1,
        }
        .abi_encode(),
    )
    .await;
    assert_eq!(created.status, 1);
    let policy: B256 = client.get_policy_ids().await.unwrap()[0].parse().unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let bearer = token(delegate.did(), 9001, now);
    assert_eq!(
        native(
            &client,
            &stranger,
            register(policy, &bearer, "wrong-caller")
        )
        .await
        .status,
        0
    );
    let wrong_deployment = token(delegate.did(), 9002, now);
    assert_eq!(
        native(
            &client,
            &delegate,
            register(policy, &wrong_deployment, "wrong-deployment")
        )
        .await
        .status,
        0
    );
    assert_eq!(
        evm(
            &client,
            &owner,
            ACP_ADDRESS,
            register(policy, &bearer, "wrong-path")
        )
        .await
        .status,
        0
    );

    let batch = IAcp::batchCallsCall {
        calls: vec![
            register(policy, &bearer, "rolled-back").into(),
            Bytes::from_static(&[0xff; 4]),
        ],
    }
    .abi_encode();
    assert_eq!(native(&client, &delegate, batch).await.status, 0);
    assert!(
        !client
            .get_jws_token(&hash_jws_token(&bearer))
            .await
            .unwrap()
            .0
    );
    assert!(
        !client
            .get_object_owner(policy, "file", "rolled-back")
            .await
            .unwrap()
            .0
    );
    assert_eq!(
        native(&client, &delegate, register(policy, &bearer, "kept"))
            .await
            .status,
        1
    );
    let (_, bytes) = client
        .get_jws_token(&hash_jws_token(&bearer))
        .await
        .unwrap();
    let used: JWSTokenRecord = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(used.authorized_account, delegate.did());
    assert!(used.first_used_at.is_some());
    let tokens: Vec<JWSTokenRecord> = serde_json::from_slice(
        &client
            .get_delegations_by_submitter(delegate.did())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].token_hash, used.token_hash);
    let tokens: Vec<JWSTokenRecord> = serde_json::from_slice(
        &client
            .get_delegations_by_submitter(stranger.did())
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(tokens.is_empty());

    let evm_bearer = token(&owner.did(), 9001, now);
    assert_eq!(
        evm(
            &client,
            &owner,
            ACP_ADDRESS,
            register(policy, &evm_bearer, "evm")
        )
        .await
        .status,
        1
    );
    let unused = token(stranger.did(), 9001, now);
    let mut revocations = Vec::new();
    for bearer in [&bearer, &unused] {
        let receipt = evm(
            &client,
            &owner,
            VERA_ADDRESS,
            IVera::revokeDelegationCall {
                token: bearer.clone(),
            }
            .abi_encode(),
        )
        .await;
        assert_eq!(receipt.status, 1);
        revocations.push(receipt.transaction_hash);
    }
    // Establish the same finalized revocation on the replica before restarting it.
    let replica = VeraClient::new(cluster.node(3).rpc_url());
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let (found, bytes) = replica
                .get_jws_token(&hash_jws_token(&unused))
                .await
                .unwrap();
            if found
                && serde_json::from_slice::<JWSTokenRecord>(&bytes)
                    .unwrap()
                    .status
                    == JWSTokenStatus::Invalid
            {
                break;
            }
            tokio::time::sleep(POLL).await;
        }
    })
    .await
    .unwrap();
    cluster.restart_node(3).unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    for hash in revocations {
        replica.wait_for_receipt(hash, POLL, 600).await.unwrap();
    }
    for bearer in [&bearer, &unused] {
        let (found, bytes) = replica
            .get_jws_token(&hash_jws_token(bearer))
            .await
            .unwrap();
        assert!(found);
        assert_eq!(
            serde_json::from_slice::<JWSTokenRecord>(&bytes)
                .unwrap()
                .status,
            JWSTokenStatus::Invalid
        );
    }
    assert_eq!(
        native(&replica, &delegate, register(policy, &bearer, "revoked"))
            .await
            .status,
        0
    );
    assert_eq!(
        native(
            &replica,
            &stranger,
            register(policy, &unused, "revoked-unused")
        )
        .await
        .status,
        0
    );
    assert!(
        !replica
            .get_object_owner(policy, "file", "revoked")
            .await
            .unwrap()
            .0
    );
}
