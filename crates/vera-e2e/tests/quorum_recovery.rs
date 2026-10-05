//! A write admitted by a minority completes only after quorum recovers.

use std::time::Duration;

use alloy_sol_types::SolCall;
use vera_client::{BULLETIN_ADDRESS, BlsSigner, VeraClient};
use vera_e2e::cluster::{ConsensusPreset, GenesisBuilder, KeySet, TestCluster};
use vera_modules::bulletin::abi::IBulletin;

#[path = "quorum_recovery/diagnostics.rs"]
mod diagnostics;

#[tokio::test]
async fn minority_write_waits_for_quorum_and_survives_replica_recovery() {
    quorum_recovery(false).await;
}

#[tokio::test]
async fn pipelined_quorum_recovery_crosses_epoch_boundaries() {
    quorum_recovery(true).await;
}

async fn quorum_recovery(pipelined: bool) {
    let deployment = if pipelined { 9082 } else { 9081 };
    let mut genesis = GenesisBuilder::devnet();
    if pipelined {
        genesis = genesis
            .blocks_per_epoch(192)
            .simplex(vera_domain::SimplexParameters::default());
    }
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
        .genesis(genesis)
        .build()
        .await
        .unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    cluster
        .observe(Duration::from_millis(100))
        .wait_for_height(3, Duration::from_secs(30))
        .await
        .unwrap();
    let clients: Vec<_> = (0..4)
        .map(|i| VeraClient::new(cluster.node(i).rpc_url()))
        .collect();
    if pipelined {
        let error = clients[0].send_raw_transaction(&[2]).await.unwrap_err();
        assert!(error.to_string().contains("EVM transactions are disabled"));
    }
    cluster.kill_node(2);
    cluster.kill_node(3);

    let signer = BlsSigner::new(7u64.into(), deployment).unwrap();
    let wire = signer
        .sign_native_tx(
            BULLETIN_ADDRESS,
            IBulletin::registerNamespaceCall {
                namespace: "quorum/recovery".into(),
            }
            .abi_encode()
            .into(),
        )
        .unwrap();
    let id = clients[0].send_native_tx(&wire).await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        for client in &clients[..2] {
            assert!(client.read_receipt(id, &trusted).await.unwrap().is_none());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    cluster.restart_node(2).unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Some(proof) = clients[0]
                .read_receipt(id, &trusted)
                .await
                .map_err(|error| error.to_string())?
            {
                let receipt = proof
                    .verify(id, &trusted)
                    .map_err(|error| error.to_string())?;
                if !receipt.success() {
                    return Err("admitted write finalized with a failed receipt".to_owned());
                }
                break Ok(proof.revision.height);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    let revision = match outcome
        .map_err(|error| error.to_string())
        .and_then(|result| result)
    {
        Ok(revision) => revision,
        Err(cause) => {
            diagnostics::capture(&cluster, id, signer.did(), &trusted, &cause).await;
            panic!("the surviving replicas must retain and finalize the admitted write: {cause}");
        }
    };

    cluster.restart_node(3).unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    if pipelined {
        cluster
            .observe(Duration::from_millis(100))
            .wait_for_height(2 * 192 + 5, Duration::from_secs(240))
            .await
            .unwrap();
    }
    for client in &clients {
        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                if let Some(proof) = client.read_receipt(id, &trusted).await.unwrap() {
                    assert!(proof.verify(id, &trusted).unwrap().success());
                    assert_eq!(proof.revision.height, revision);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("the recovered replica must serve the same certified outcome");
        let namespaces = client
            .list_bulletin_namespaces(None, 2, revision, &trusted)
            .await
            .unwrap();
        assert!(namespaces.continuation.is_none());
        assert_eq!(namespaces.records.len(), 1);
        let namespace = &namespaces.records[0];
        assert_eq!(namespace.id, "bulletin/quorum/recovery");
        assert_eq!(namespace.owner_did, signer.did());
        assert_eq!(namespace.created_at.block_height, revision);
    }
}
