//! Crash after each module-store commit and recover the durable consensus prefix.
//! Requires verad built with --features fault-injection.

use std::{collections::BTreeSet, time::Duration};

use alloy_sol_types::SolCall;
use vera_client::{ACP_ADDRESS, BlsSigner, TransactionReceipt, VeraClient};
use vera_e2e::cluster::{ConsensusPreset, TestCluster};
use vera_modules::acp::abi::IAcp;

const POLL: Duration = Duration::from_millis(50);
fn deadline() -> Duration {
    let scale = std::env::var("VERA_E2E_DEADLINE_SCALE")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(1)
        .max(1);
    Duration::from_secs(30 * scale as u64)
}

async fn create_policy(client: &VeraClient, signer: &BlsSigner, name: &str) -> TransactionReceipt {
    let raw = signer
        .sign_native_tx(
            ACP_ADDRESS,
            IAcp::createPolicyCall {
                policy: format!("name: {name}\nresources:\n  - name: file\n")
                    .into_bytes()
                    .into(),
                marshalType: 1,
                nonce: vera_client::random_policy_nonce().0.into(),
            }
            .abi_encode()
            .into(),
        )
        .unwrap();
    tokio::time::timeout(deadline(), async {
        let hash = client.send_native_tx(&raw).await.unwrap();
        let receipt = client.wait_for_receipt(hash, POLL, 600).await.unwrap();
        assert_eq!(receipt.status, 1);
        receipt
    })
    .await
    .expect("policy confirmation deadline")
}

async fn assert_replicas(cluster: &TestCluster, signer: &BlsSigner, receipt: &TransactionReceipt) {
    tokio::time::timeout(deadline(), async {
        let origin = VeraClient::new(cluster.node(0).rpc_url());
        origin
            .wait_for_receipt(receipt.transaction_hash, POLL, 600)
            .await
            .unwrap();
        let expected: BTreeSet<_> = origin.get_policy_ids().await.unwrap().into_iter().collect();
        for index in 0..4 {
            let client = VeraClient::new(cluster.node(index).rpc_url());
            let actual = client
                .wait_for_receipt(receipt.transaction_hash, POLL, 600)
                .await
                .unwrap();
            assert_eq!(actual.block_hash, receipt.block_hash);
            assert_eq!(actual.status, 1);
            assert_eq!(
                client.get_native_nonce(signer.did()).await.unwrap(),
                signer.nonce()
            );
            let policies: BTreeSet<_> =
                client.get_policy_ids().await.unwrap().into_iter().collect();
            assert_eq!(policies, expected, "replica {index} policy state differs");
            assert_eq!(policies.len(), signer.nonce() as usize);
        }
    })
    .await
    .expect("replica convergence deadline");
}

/// Latest finalized height from a live node's status.
async fn certified_head(client: &VeraClient) -> u64 {
    let status: serde_json::Value = client
        .rpc_call_typed("vera_nodeStatus", serde_json::json!([]))
        .await
        .unwrap();
    status["finalizedCount"].as_u64().unwrap()
}

#[tokio::test]
async fn recover_after_each_module_commit() {
    let mut cluster = TestCluster::builder()
        .nodes(4)
        .chain_id(9001)
        .preset(ConsensusPreset::Normal)
        .build()
        .await
        .unwrap();
    cluster.wait_ready(deadline()).await.unwrap();
    let origin = VeraClient::new(cluster.node(0).rpc_url());
    let signer = BlsSigner::new(7u64.into(), 9001).unwrap();
    let baseline = create_policy(&origin, &signer, "baseline").await;
    assert_replicas(&cluster, &signer, &baseline).await;
    // The crash can precede confirmation of the next submission on another node.
    // Bound it below by the state already verified on the recovering replica.
    let mut floor = baseline.block_number;
    let marker = cluster.node(3).data_dir.join("module-commit-crash");
    let witness = marker.with_extension("hit");

    for store in 0..4 {
        if witness.exists() {
            std::fs::remove_file(&witness).unwrap();
        }
        std::fs::write(&marker, store.to_string()).unwrap();
        let receipt = create_policy(&origin, &signer, &format!("crash-{store}")).await;
        tokio::time::timeout(deadline(), async {
            while !witness.exists() {
                tokio::time::sleep(POLL).await;
            }
        })
        .await
        .expect("crash point did not fire; build verad with fault-injection");
        let observed: Vec<u64> = std::fs::read_to_string(&witness)
            .unwrap()
            .split_whitespace()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(observed[1], store);
        // Module stores commit lazily — gaps of many blocks are normal — so
        // the first commit after arming can land well past the receipt's
        // block. Bound above by the finalized head after the crash instead.
        let head = certified_head(&origin).await;
        assert!(
            observed[0] >= floor && observed[0] <= head,
            "crash witness {observed:?} outside the applied range (head {head})"
        );
        assert!(
            !marker.exists(),
            "crash marker must be consumed before restart"
        );
        cluster.kill_node(3);
        cluster.restart_node(3).unwrap();
        cluster.wait_ready(deadline()).await.unwrap();
        assert_replicas(&cluster, &signer, &receipt).await;

        let recovered = VeraClient::new(cluster.node(3).rpc_url());
        let probe = create_policy(&recovered, &signer, &format!("after-crash-{store}")).await;
        assert_replicas(&cluster, &signer, &probe).await;
        floor = probe.block_number;
        eprintln!(
            "recovered after module store {store} at height {}",
            receipt.block_number
        );
    }
}
