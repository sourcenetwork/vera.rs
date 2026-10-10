//! Inject a synchronization syscall error after acknowledged state, then recover.
#![cfg(target_os = "linux")]

use std::time::Duration;

use vera_client::{BlsSigner, VeraClient};
use vera_domain::SimplexParameters;
use vera_e2e::cluster::{ConsensusPreset, GenesisBuilder, KeySet, TestCluster};

#[path = "support/durability.rs"]
mod durability;
#[path = "support/sync_fault.rs"]
mod sync_fault;

use durability::{assert_replicas, create_policy, deadline};

#[tokio::test]
async fn sync_failure_recovers_acknowledged_operations() {
    let deployment = 9072;
    let keys = KeySet::builder().seed(deployment).build().unwrap();
    let trusted = *keys.epoch_info().output.public().public();
    let mut cluster = TestCluster::builder()
        .nodes(4)
        .seed(deployment)
        .chain_id(deployment)
        .genesis(GenesisBuilder::devnet().simplex(SimplexParameters::default()))
        .preset(ConsensusPreset::Normal)
        .build()
        .await
        .unwrap();
    cluster.wait_ready(deadline()).await.unwrap();
    let signer = BlsSigner::random(deployment).unwrap();
    let origin = VeraClient::new(cluster.node(0).rpc_url());
    let mut receipts = vec![create_policy(&origin, &signer, "before-sync-failure").await];
    assert_replicas(&cluster, &signer, &receipts, 4, &trusted, "initial").await;

    let fault = sync_fault::SyncFault::attach(
        cluster.node(3).process.id().unwrap(),
        &cluster.node(3).data_dir,
    )
    .expect("attach privileged tracer to the affected validator only");
    tokio::time::timeout(deadline(), async {
        while cluster.node_mut(3).process.is_running() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("synchronization failure must stop the affected validator");
    let injected = fault
        .finish()
        .await
        .expect("confirm EIO synchronization witness");
    receipts.push(create_policy(&origin, &signer, "during-sync-failure").await);
    assert_replicas(&cluster, &signer, &receipts, 3, &trusted, "survivors").await;

    cluster.restart_node(3).unwrap();
    cluster.wait_ready(deadline()).await.unwrap();
    assert_replicas(&cluster, &signer, &receipts, 4, &trusted, "restored").await;
    cluster.kill_node(2);
    let recovered = VeraClient::new(cluster.node(3).rpc_url());
    receipts.push(create_policy(&recovered, &signer, "after-sync-failure").await);
    cluster.restart_node(2).unwrap();
    cluster.wait_ready(deadline()).await.unwrap();
    assert_replicas(&cluster, &signer, &receipts, 4, &trusted, "renewed-quorum").await;
    eprintln!(
        "sync failure injected_calls={injected} acknowledged_operations={} verified_replicas=4",
        receipts.len()
    );
}
