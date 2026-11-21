//! Rotating leaders draw each block's `prevrandao` from the threshold VRF seed.
//!
//! Requires `cargo build -p verad` before running.

use std::time::Duration;

use vera_client::VeraClient;
use vera_e2e::cluster::{ConsensusPreset, GenesisBuilder, TestCluster};

#[tokio::test]
async fn rotating_blocks_carry_the_threshold_seed() {
    let chain_id = 9003;
    let cluster = TestCluster::builder()
        .binary(vera_e2e::resolve_binary().expect("resolve verad binary"))
        .nodes(4)
        .seed(chain_id)
        .chain_id(chain_id)
        .genesis(GenesisBuilder::devnet().rotating())
        .preset(ConsensusPreset::Fast)
        .build()
        .await
        .expect("cluster should start");
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .expect("cluster should become healthy");
    cluster
        .observe(Duration::from_millis(200))
        .wait_for_height(3, Duration::from_secs(30))
        .await
        .expect("should reach height 3");

    let client = VeraClient::new(cluster.node(0).rpc_url());
    // The first view of each epoch has a zero seed; check a fixed later block.
    let block = tokio::time::timeout(vera_e2e::readiness_deadline(), async {
        loop {
            let block: Option<serde_json::Value> = client
                .rpc_call_typed("eth_getBlockByNumber", serde_json::json!(["0x3", false]))
                .await
                .expect("block 3 should be readable");
            if let Some(block) = block {
                return block;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("block 3 should become indexed");
    assert_eq!(block["number"].as_str(), Some("0x3"));
    let mix_hash = block["mixHash"]
        .as_str()
        .expect("block 3 should expose prevrandao");
    assert_ne!(
        mix_hash,
        format!("0x{}", "00".repeat(32)),
        "post-genesis prevrandao must come from the threshold VRF seed"
    );
}
