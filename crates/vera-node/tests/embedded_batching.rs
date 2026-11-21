//! A lone validator batches requests only while a block is in flight.

use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use alloy_sol_types::SolCall as _;
use serde_json::json;
use vera_client::{ACP_ADDRESS, BlsSigner};
use vera_domain::{GossipHeader, ReceiptResponse};
use vera_jsonrpc::LocalRpc;
use vera_modules::{acp::abi::IAcp, vera::administration::OperatorPolicy};
use vera_node::{EmbeddedConfig, EmbeddedNode, SoloGenesis, SoloPacing};

const ACCOUNT_KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
/// Longer than any commit on a loaded machine, so the two behaviors cannot be confused.
const BATCH: Duration = Duration::from_secs(4);

async fn start(directory: &std::path::Path, chain_id: u64, settled: Duration) -> EmbeddedNode {
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
        settled,
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

fn signed(signer: &BlsSigner, name: &str) -> String {
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
    format!("0x{}", hex::encode(wire))
}

async fn send(rpc: &LocalRpc, wire: String) -> B256 {
    rpc.request("vera_sendNativeTx", vec![json!(wire)])
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
    let node = start(directory.path(), chain_id, SoloPacing::SETTLED).await;
    let signer = BlsSigner::new(5u64.into(), chain_id).unwrap();
    for name in ["alone_a", "alone_b"] {
        let wire = signed(&signer, name);
        let started = Instant::now();
        let submission = send(node.rpc(), wire).await;
        finalized_height(&node, submission).await;
        let elapsed = started.elapsed();
        assert!(
            elapsed < BATCH,
            "a request on an idle node waited out the batch window: {elapsed:?}"
        );
    }
    node.stop().await.unwrap();
}

/// Requests sent a few milliseconds apart, each with when the node accepted it.
///
/// The spread lets a block built without waiting close before the later ones arrive.
async fn spread(rpc: &LocalRpc, wires: Vec<String>) -> Vec<(B256, Instant)> {
    let mut sent = Vec::new();
    for wire in wires {
        sent.push((send(rpc, wire).await, Instant::now()));
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    sent
}

#[tokio::test(flavor = "multi_thread")]
async fn requests_that_arrive_while_a_block_commits_share_the_next_one() {
    let directory = tempfile::tempdir().unwrap();
    let chain_id = 9422;
    // No settled window: the first request's block is built as it arrives,
    // so later requests can only join a block that is still collecting.
    let node = start(directory.path(), chain_id, Duration::ZERO).await;
    let mut headers = node
        .rpc()
        .subscribe("vera_subscribeHeaders", Vec::new(), 64)
        .await
        .unwrap();
    let published: Arc<Mutex<Vec<(u64, Instant)>>> = Arc::default();
    let recording = published.clone();
    let listener = tokio::spawn(async move {
        while let Some(header) = headers.next::<GossipHeader>().await {
            let height = header.unwrap().height;
            recording.lock().unwrap().push((height, Instant::now()));
        }
    });
    let mut covered = 0;
    for round in 0..5u64 {
        let first = BlsSigner::new((100 + round).into(), chain_id).unwrap();
        let wires = (0..8u64)
            .map(|writer| {
                let signer = BlsSigner::new((10 * round + 20 + writer).into(), chain_id).unwrap();
                signed(&signer, &format!("burst_{round}_{writer}"))
            })
            .collect();
        let leading = send(node.rpc(), signed(&first, &format!("lead_{round}"))).await;
        let sent = spread(node.rpc(), wires).await;
        let lead_height = finalized_height(&node, leading).await;
        let lead_published = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let found = published
                    .lock()
                    .unwrap()
                    .iter()
                    .find_map(|(height, at)| (*height == lead_height).then_some(*at));
                match found {
                    Some(at) => return at,
                    None => tokio::time::sleep(Duration::from_millis(1)).await,
                }
            }
        })
        .await
        .expect("the leading block's header");
        // Only requests the node accepted before the leading block was
        // published arrived behind a block in flight; any that missed the
        // leading block must share one block.
        let mut behind = BTreeSet::new();
        for (submission, accepted) in sent {
            let height = finalized_height(&node, submission).await;
            if accepted < lead_published && height != lead_height {
                behind.insert(height);
                covered += 1;
            }
        }
        assert!(
            behind.len() <= 1,
            "requests behind a block in flight were spread over blocks {behind:?}"
        );
    }
    assert!(
        covered > 0,
        "no request ever arrived behind a block in flight"
    );
    listener.abort();
    node.stop().await.unwrap();
}
