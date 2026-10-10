//! Real filesystem exhaustion on one validator; no injected persistence error.
#![cfg(target_os = "linux")]

use std::{fs, sync::Arc};

use vera_client::{BlsSigner, VeraClient};
use vera_domain::SimplexParameters;
use vera_e2e::cluster::{ConsensusPreset, GenesisBuilder, KeySet, TestCluster};

#[path = "support/durability.rs"]
mod durability;
use durability::{assert_replicas, create_policy, deadline};

#[path = "support/quota.rs"]
mod quota;

#[tokio::test]
async fn disk_full_validator_recovers_acknowledged_operations() {
    let deployment = 9071;
    let keys = KeySet::builder().seed(deployment).build().unwrap();
    let trusted = *keys.epoch_info().output.public().public();
    let volume = Arc::new(quota::Quota::new().expect("mount private bounded tmpfs"));
    let node_volume = volume.clone();
    let mut cluster = TestCluster::builder()
        .nodes(4)
        .seed(deployment)
        .chain_id(deployment)
        .genesis(GenesisBuilder::devnet().simplex(SimplexParameters::default()))
        .preset(ConsensusPreset::Normal)
        .jmt_seeder(move |directory, _| {
            if directory.file_name().is_some_and(|name| name == "node3") {
                node_volume
                    .bind_node(directory)
                    .expect("isolate validator storage");
            }
        })
        .build()
        .await
        .unwrap();
    cluster.wait_ready(deadline()).await.unwrap();
    let signer = BlsSigner::random(deployment).expect("construct native signer");
    let origin = VeraClient::new(cluster.node(0).rpc_url());
    let mut receipts = vec![create_policy(&origin, &signer, "before-disk-full").await];
    assert_replicas(&cluster, &signer, &receipts, 4, &trusted).await;

    assert!(
        volume.fill().unwrap() > 0,
        "filesystem must actually reach ENOSPC"
    );
    receipts.push(create_policy(&origin, &signer, "during-disk-full").await);
    tokio::time::timeout(deadline(), async {
        // Writes can consume existing file allocation before requiring another filesystem block.
        while cluster.node_mut(3).process.is_running() {
            assert!(
                receipts.len() < 128,
                "bounded writes must expose filesystem exhaustion"
            );
            receipts.push(
                create_policy(&origin, &signer, &format!("disk-full-{}", receipts.len())).await,
            );
        }
    })
    .await
    .expect("persistence failure must stop the affected validator");
    volume
        .confirm_full()
        .expect("independently confirm ENOSPC after validator exit");
    let log_dir = &cluster.node(3).log_dir;
    let logs = ["stdout.log", "stderr.log"]
        .into_iter()
        .map(|name| fs::read_to_string(log_dir.join(name)).unwrap())
        .collect::<String>();
    // Commonware's blob-header writes report WriteFailed without the underlying OS error.
    assert!(
        logs.contains("No space left on device")
            || logs.contains("os error 28")
            || logs.contains("unable to append to journal: Runtime(WriteFailed)"),
        "validator exit must report a storage write failure while the volume reports ENOSPC (log_bytes={}, io_errors={}, panics={})",
        logs.len(),
        logs.matches("I/O error").count() + logs.matches("io error").count(),
        logs.matches("panicked").count()
    );
    assert_replicas(&cluster, &signer, &receipts, 3, &trusted).await;

    volume.release_space().unwrap();
    cluster.restart_node(3).unwrap();
    cluster.wait_ready(deadline()).await.unwrap();
    assert_replicas(&cluster, &signer, &receipts, 4, &trusted).await;
    cluster.kill_node(2);
    let recovered = VeraClient::new(cluster.node(3).rpc_url());
    receipts.push(create_policy(&recovered, &signer, "after-disk-full").await);
    cluster.restart_node(2).unwrap();
    cluster.wait_ready(deadline()).await.unwrap();
    assert_replicas(&cluster, &signer, &receipts, 4, &trusted).await;
    for index in 0..4 {
        cluster.kill_node(index);
    }
    volume
        .close()
        .expect("unmount fixture volumes after reaping validators");
}
