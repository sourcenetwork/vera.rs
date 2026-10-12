use std::time::{Duration, Instant};

use vera_client::{BlsSigner, VeraClient};
use vera_e2e::cluster::{ConsensusPreset, GenesisBuilder, KeySet, TestCluster};

#[path = "netem.rs"]
mod netem;

use super::{
    PHASE_DEADLINE, POLL,
    stalled_validator::{certified_head, certified_receipt, reconcile, submit},
};

#[tokio::test]
#[ignore = "requires an isolated Linux runner with explicitly enabled network fault injection"]
async fn pipelined_delayed_validator_crosses_epoch_and_preserves_work() {
    tokio::time::timeout(Duration::from_secs(360), qualify())
        .await
        .expect("delayed-validator qualification deadline");
}

async fn qualify() {
    let deployment = 9085;
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
        .preset(ConsensusPreset::Normal)
        .genesis(
            GenesisBuilder::devnet()
                .blocks_per_epoch(192)
                .simplex(vera_domain::SimplexParameters::default()),
        )
        .build()
        .await
        .unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    let clients: Vec<_> = cluster
        .rpc_urls()
        .into_iter()
        .map(VeraClient::new)
        .collect();
    let signer = BlsSigner::new(7u64.into(), deployment).unwrap();
    let (first, _) = submit(&clients[0], &signer, 0, &trusted).await;
    certified_receipt(&clients[3], first, &trusted).await;
    let fault = netem::Delayed::install(
        cluster.node(3),
        (0..3).map(|i| cluster.node(i).p2p_port).collect(),
    );
    let initial_packets = fault.assert_active();
    let checkpoint = certified_head(&clients[0], &trusted).await;
    let started = Instant::now();
    let mut next_sequence = 1;
    let (last_id, last) = tokio::time::timeout(PHASE_DEADLINE, async {
        loop {
            assert!(next_sequence < 1024, "delayed-validator workload bound");
            let result = submit(&clients[0], &signer, next_sequence, &trusted).await;
            next_sequence += 1;
            fault.assert_active();
            if started.elapsed() >= Duration::from_secs(30)
                && result.1.revision.epoch > checkpoint.epoch
            {
                break result;
            }
            tokio::time::sleep(POLL).await;
        }
    })
    .await
    .expect("delayed links prevented certified epoch progress");
    assert!(
        fault.assert_active() > initial_packets,
        "no live P2P packets traversed the fault queue"
    );
    fault.restore();
    for client in &clients {
        let proof = certified_receipt(client, last_id, &trusted).await;
        assert_eq!(proof.revision.block_hash, last.revision.block_hash);
    }
    reconcile(
        &clients,
        &signer,
        last.revision.height,
        next_sequence,
        &trusted,
    )
    .await;
    cluster.kill_node(2);
    let (id, required) = submit(&clients[0], &signer, next_sequence, &trusted).await;
    assert!(required.revision.height > last.revision.height);
    let proof = certified_receipt(&clients[3], id, &trusted).await;
    assert_eq!(proof.revision.block_hash, required.revision.block_hash);
}
