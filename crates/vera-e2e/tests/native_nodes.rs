//! Service-node authority, replay protection and certified recovery through native workers.

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use vera_client::Secp256k1SigningKey as SigningKey;
use vera_client::{
    BlsSigner, VeraClient,
    nodes::{NodeCommand, NodeInfo, NodeRequest, NodeTarget, SignedNodeRequest, sign_node_request},
};
use vera_domain::ConsensusPublicKey;
use vera_e2e::cluster::{ConsensusPreset, KeySet, TestCluster};

fn public(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_sec1_bytes())
}

async fn submit(
    writer: &VeraClient,
    reader: &VeraClient,
    worker: &BlsSigner,
    trusted: &ConsensusPublicKey,
    request: &SignedNodeRequest,
    success: bool,
) -> u64 {
    let id = writer.submit_node_request(worker, request).await.unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let (local, observed) = tokio::try_join!(
                writer.read_receipt(id, trusted),
                reader.read_receipt(id, trusted)
            )
            .unwrap();
            if let (Some(_), Some(proof)) = (local, observed) {
                assert_eq!(proof.verify(id, trusted).unwrap().success(), success);
                break proof.revision.height;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn native_service_node_authority_survives_worker_changes_and_restart() {
    let deployment = 9066;
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
        .build()
        .await
        .unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    let observed = cluster.observe(Duration::from_millis(100));
    observed
        .wait_for_height(3, Duration::from_secs(30))
        .await
        .unwrap();
    let writer = VeraClient::new(cluster.node(0).rpc_url());
    let reader = VeraClient::new(cluster.node(3).rpc_url());
    let first: serde_json::Value = writer
        .rpc_call_typed("eth_getBlockByNumber", serde_json::json!(["0x1", false]))
        .await
        .unwrap();
    let genesis: alloy_primitives::B256 = first["parentHash"].as_str().unwrap().parse().unwrap();
    let node = SigningKey::from_slice(&[31; 32]).unwrap();
    let controller = SigningKey::from_slice(&[32; 32]).unwrap();
    let next = SigningKey::from_slice(&[33; 32]).unwrap();
    let workers = [
        BlsSigner::new(7u64.into(), deployment).unwrap(),
        BlsSigner::new(8u64.into(), deployment).unwrap(),
    ];
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 300;
    let request = |sequence, command| NodeRequest {
        deployment_root: genesis.0,
        deployment_id: deployment,
        node_key: public(&node),
        sequence,
        expires_at,
        command,
    };
    assert!(
        reader
            .read_threshold_node(&public(&node), 0, &trusted)
            .await
            .unwrap()
            .record
            .is_none()
    );
    let create = sign_node_request(
        request(
            0,
            NodeCommand::Register(NodeInfo {
                peer_id: "peer1".into(),
                controller_key: public(&controller),
                allowed_policy_ids: vec!["policy1".into()],
                allowed_ring_ids: vec![],
            }),
        ),
        &node,
    )
    .unwrap();
    let minimum = submit(&writer, &reader, &workers[0], &trusted, &create, true).await;
    let state = reader
        .read_threshold_node(&public(&node), minimum, &trusted)
        .await
        .unwrap()
        .record
        .unwrap();
    assert_eq!(state.node_key, public(&node));
    assert_eq!(state.info.controller_key, public(&controller));
    assert!(state.info.allows_ring("policy1", "ring1"));
    assert_eq!(state.sequence, 1);
    submit(&writer, &reader, &workers[1], &trusted, &create, false).await;
    let forged =
        sign_node_request(request(1, NodeCommand::SetPeer("forged".into())), &node).unwrap();
    submit(&writer, &reader, &workers[0], &trusted, &forged, false).await;
    let transfer = sign_node_request(
        request(1, NodeCommand::TransferController(public(&next))),
        &controller,
    )
    .unwrap();
    submit(&writer, &reader, &workers[1], &trusted, &transfer, true).await;
    let old = sign_node_request(
        request(2, NodeCommand::SetPeer("old-controller".into())),
        &controller,
    )
    .unwrap();
    submit(&writer, &reader, &workers[0], &trusted, &old, false).await;
    let change =
        sign_node_request(request(2, NodeCommand::SetPeer("peer2".into())), &next).unwrap();
    let mut tampered = change.clone();
    tampered.request.command = NodeCommand::SetPeer("tampered".into());
    submit(&writer, &reader, &workers[0], &trusted, &tampered, false).await;
    submit(&writer, &reader, &workers[1], &trusted, &change, true).await;
    let remove = sign_node_request(
        request(
            3,
            NodeCommand::Disallow(NodeTarget::Policy("policy1".into())),
        ),
        &next,
    )
    .unwrap();
    let minimum = submit(&writer, &reader, &workers[1], &trusted, &remove, true).await;
    cluster.restart_node(3).unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    let restored = reader
        .read_threshold_node(&public(&node), minimum, &trusted)
        .await
        .unwrap()
        .record
        .unwrap();
    assert_eq!(restored.sequence, 4);
    assert_eq!(restored.info.peer_id, "peer2");
    assert_eq!(restored.info.controller_key, public(&next));
    assert!(!restored.info.allows_ring("policy1", "ring1"));
    let new_old = sign_node_request(
        request(4, NodeCommand::SetPeer("old-after-restart".into())),
        &controller,
    )
    .unwrap();
    let minimum = submit(&writer, &reader, &workers[0], &trusted, &new_old, false).await;
    assert_eq!(
        reader
            .read_threshold_node(&public(&node), minimum, &trusted)
            .await
            .unwrap()
            .record
            .unwrap(),
        restored
    );

    let directory = tempfile::tempdir().unwrap();
    let keys = std::cell::RefCell::new(std::collections::BTreeMap::<String, Vec<u8>>::new());
    let open = || {
        vera_client::NativeWorker::open(
            directory.path(),
            deployment,
            |name| {
                keys.borrow()
                    .get(name)
                    .cloned()
                    .map(Into::into)
                    .ok_or("missing key")
            },
            |name, bytes| {
                keys.borrow_mut().insert(name.into(), bytes.to_vec());
                Ok::<_, String>(())
            },
        )
    };
    let change = sign_node_request(
        request(4, NodeCommand::SetPeer("durable-peer".into())),
        &next,
    )
    .unwrap();
    let calldata = vera_client::nodes::encode_node_request(&change).unwrap();
    for (sequence, success) in [(0, true), (1, false)] {
        let mut worker = open().unwrap();
        assert_eq!(worker.next_sequence(), sequence);
        let wire = worker
            .prepare(vera_client::VERA_ADDRESS, calldata.clone())
            .unwrap()
            .to_vec();
        let id = writer.send_native_tx(&wire).await.unwrap();
        drop(worker);
        let mut worker = open().unwrap();
        assert_eq!(worker.pending().unwrap(), wire);
        let proof = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if let Some(proof) = writer.read_receipt(id, &trusted).await.unwrap() {
                    break proof;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            worker.acknowledge(&proof, &trusted).unwrap().success(),
            success
        );
        drop(worker);
        let worker = open().unwrap();
        assert!(worker.pending().is_none());
        assert_eq!(worker.next_sequence(), sequence + 1);
    }
}
