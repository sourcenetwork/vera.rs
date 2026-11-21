//! A lone validator batches requests only while a block is in flight.

use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use alloy_sol_types::SolCall as _;
use serde_json::json;
use vera_client::{ACP_ADDRESS, BlsSigner};
use vera_domain::ReceiptResponse;
use vera_modules::{acp::abi::IAcp, vera::administration::OperatorPolicy};
use vera_node::{EmbeddedConfig, EmbeddedNode, SoloGenesis, SoloPacing};

const ACCOUNT_KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
/// Longer than any commit on a loaded machine, so the two behaviors cannot be confused.
const BATCH: Duration = Duration::from_secs(4);

async fn start(directory: &std::path::Path, chain_id: u64) -> EmbeddedNode {
    let genesis = SoloGenesis {
        policies: Vec::new(),
        chain_id,
        operators: OperatorPolicy {
            threshold: 1,
            keys: vec![ACCOUNT_KEY.into()],
        },
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    let listen = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let mut config = EmbeddedConfig::new(directory, genesis, listen);
    config.pacing = Some(SoloPacing {
        idle: EmbeddedConfig::HEARTBEAT,
        batch: BATCH,
        settled: SoloPacing::SETTLED,
    });
    let node = EmbeddedNode::start(config).await.unwrap();
    // The first block after a start is proposed without waiting; let it finalize.
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let status: vera_jsonrpc::NodeStatus =
                node.rpc().call_empty("vera_nodeStatus").await.unwrap();
            if status.finalized_height.is_some_and(|height| height > 0) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the first block finalizes");
    node
}

async fn submit(node: &EmbeddedNode, signer: &BlsSigner, name: &str) -> B256 {
    let call = IAcp::createPolicyCall {
        policy: format!(
            "name: {name}\nresources:\n  - name: document\n    relations:\n      - name: reader\n        types: [actor]\n    permissions:\n      - name: read\n        expr: reader\n"
        )
        .into_bytes()
        .into(),
        marshalType: 1,
        nonce: vera_client::random_policy_nonce().0.into(),
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

async fn finalized_height(node: &EmbeddedNode, submission: B256) -> u64 {
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let proof: Option<ReceiptResponse> = node
                .rpc()
                .request("vera_getReceiptProof", vec![json!(submission)])
                .await
                .unwrap();
            if let Some(proof) = proof {
                assert!(
                    proof
                        .verify(submission, node.consensus_key())
                        .unwrap()
                        .success()
                );
                return proof.revision.height;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("certified receipt deadline")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_that_finds_nothing_in_flight_is_proposed_at_once() {
    let directory = tempfile::tempdir().unwrap();
    let chain_id = 9421;
    let node = start(directory.path(), chain_id).await;
    let signer = BlsSigner::new(5u64.into(), chain_id).unwrap();
    for name in ["alone_a", "alone_b"] {
        let started = Instant::now();
        let submission = submit(&node, &signer, name).await;
        finalized_height(&node, submission).await;
        let elapsed = started.elapsed();
        assert!(
            elapsed < BATCH,
            "a request on an idle node waited out the batch window: {elapsed:?}"
        );
    }
    node.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn requests_that_arrive_while_a_block_commits_share_the_next_one() {
    let directory = tempfile::tempdir().unwrap();
    let chain_id = 9422;
    let node = start(directory.path(), chain_id).await;
    let mut submissions = Vec::new();
    for writer in 0..6u64 {
        let signer = BlsSigner::new((10 + writer).into(), chain_id).unwrap();
        submissions.push(submit(&node, &signer, &format!("burst_{writer}")).await);
    }
    let mut heights = BTreeSet::new();
    for submission in submissions {
        heights.insert(finalized_height(&node, submission).await);
    }
    // The first request is proposed at once; every later one arrives while
    // its block is in flight and waits for the window.
    assert!(
        heights.len() <= 2,
        "a burst of requests was spread over blocks {heights:?}"
    );
    node.stop().await.unwrap();
}
