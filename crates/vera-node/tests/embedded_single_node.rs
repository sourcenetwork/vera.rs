//! A single-validator node hosted in the test process, with no RPC socket.

#![recursion_limit = "256"]

use std::{net::SocketAddr, path::Path, time::Duration};

use alloy_primitives::B256;
use alloy_sol_types::SolCall as _;
use serde_json::json;
use vera_client::{ACP_ADDRESS, BlsSigner};
use vera_domain::ReceiptResponse;
use vera_modules::{acp::abi::IAcp, vera::administration::OperatorPolicy};
use vera_node::{EmbedError, EmbeddedConfig, EmbeddedNode, SoloError, SoloGenesis};

const ACCOUNT_KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const OTHER_ACCOUNT_KEY: &str =
    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const POLICY: &str = "\
name: embedded
resources:
  - name: document
    relations:
      - name: reader
        types: [actor]
    permissions:
      - name: read
        expr: reader
";

fn free_address() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn config(directory: &Path, chain_id: u64, account: &str) -> EmbeddedConfig {
    let genesis = SoloGenesis {
        chain_id,
        operators: OperatorPolicy {
            threshold: 1,
            keys: vec![account.into()],
        },
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    EmbeddedConfig::new(directory, genesis, free_address())
}

async fn create_policy(node: &EmbeddedNode, signer: &BlsSigner, name: &str) -> B256 {
    let call = IAcp::createPolicyCall {
        policy: POLICY.replace("embedded", name).into_bytes().into(),
        marshalType: 1,
    };
    let wire = signer
        .sign_native_tx(ACP_ADDRESS, call.abi_encode().into())
        .unwrap();
    node.rpc()
        .request(
            "vera_sendNativeTx",
            vec![json!(format!("0x{}", hex::encode(wire)))],
        )
        .await
        .unwrap()
}

async fn verified_receipt(node: &EmbeddedNode, submission: B256) -> ReceiptResponse {
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let proof: Option<ReceiptResponse> = node
                .rpc()
                .request("vera_getReceiptProof", vec![json!(submission)])
                .await
                .unwrap();
            if let Some(proof) = proof {
                let receipt = proof.verify(submission, node.consensus_key()).unwrap();
                assert!(receipt.success(), "policy creation must succeed");
                return proof;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("certified receipt deadline")
}

fn height(proof: &ReceiptResponse, trusted: &vera_domain::ConsensusPublicKey) -> u64 {
    vera_domain::verify_finalized_block(&proof.revision, trusted)
        .unwrap()
        .height
}

async fn sequence(node: &EmbeddedNode, signer: &BlsSigner) -> u64 {
    let value: String = node
        .rpc()
        .request("vera_getNativeNonce", vec![json!(signer.did())])
        .await
        .unwrap();
    u64::from_str_radix(value.trim_start_matches("0x"), 16).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn solo_node_finalizes_native_writes_and_recovers_them_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let chain_id = 9401;
    let signer = BlsSigner::new(1u64.into(), chain_id).unwrap();

    let node = EmbeddedNode::start(config(directory.path(), chain_id, ACCOUNT_KEY))
        .await
        .unwrap();
    assert!(
        node.rpc()
            .method_names()
            .any(|name| name == "vera_getReceiptProof")
    );
    let trusted = *node.consensus_key();
    let first = create_policy(&node, &signer, "first").await;
    let proof = verified_receipt(&node, first).await;
    assert_eq!(sequence(&node, &signer).await, 1);
    node.stop().await.unwrap();

    // A different account cannot adopt the deployment.
    let error = EmbeddedNode::start(config(directory.path(), chain_id, OTHER_ACCOUNT_KEY))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        EmbedError::Deployment(SoloError::Mismatch(_))
    ));

    let node = EmbeddedNode::start(config(directory.path(), chain_id, ACCOUNT_KEY))
        .await
        .unwrap();
    assert_eq!(*node.consensus_key(), trusted);
    let recovered = verified_receipt(&node, first).await;
    assert_eq!(height(&recovered, &trusted), height(&proof, &trusted));
    assert_eq!(sequence(&node, &signer).await, 1);
    let second = create_policy(&node, &signer, "second").await;
    let later = verified_receipt(&node, second).await;
    assert!(height(&later, &trusted) > height(&proof, &trusted));
    node.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn two_deployments_share_a_process_without_sharing_trust() {
    let (left_dir, right_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let left = EmbeddedNode::start(config(left_dir.path(), 9402, ACCOUNT_KEY))
        .await
        .unwrap();
    let right = EmbeddedNode::start(config(right_dir.path(), 9403, ACCOUNT_KEY))
        .await
        .unwrap();
    assert_ne!(left.consensus_key(), right.consensus_key());

    let signer = BlsSigner::new(2u64.into(), 9402).unwrap();
    let submission = create_policy(&left, &signer, "left").await;
    let proof = verified_receipt(&left, submission).await;
    assert!(proof.verify(submission, right.consensus_key()).is_err());
    let absent: Option<ReceiptResponse> = right
        .rpc()
        .request("vera_getReceiptProof", vec![json!(submission)])
        .await
        .unwrap();
    assert!(absent.is_none());

    left.stop().await.unwrap();
    right.stop().await.unwrap();
}
