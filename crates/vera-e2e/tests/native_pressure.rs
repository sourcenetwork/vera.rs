//! Fill native admission during quorum loss, then recover all admitted work.

use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};

use alloy_sol_types::SolCall;
use vera_client::{BULLETIN_ADDRESS, BlsSigner, ClientError, VeraClient};
use vera_e2e::cluster::{ConsensusPreset, GenesisBuilder, KeySet, TestCluster};
use vera_modules::bulletin::abi::IBulletin;

const CAPACITY: u64 = 4_096;
const POLL: Duration = Duration::from_millis(100);
const PHASE_DEADLINE: Duration = Duration::from_secs(120);

fn namespace(index: u64) -> String {
    format!("admission/limit/{index:04}")
}

fn signed_namespace(signer: &BlsSigner, sequence: u64) -> Vec<u8> {
    signer
        .sign_native_tx_with_sequence(
            BULLETIN_ADDRESS,
            IBulletin::registerNamespaceCall {
                namespace: namespace(sequence),
            }
            .abi_encode()
            .into(),
            sequence,
        )
        .unwrap()
}

#[tokio::test]
async fn pipelined_admission_preserves_work_when_quorum_recovers() {
    let deployment = 9083;
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
    cluster
        .observe(POLL)
        .wait_for_height(3, Duration::from_secs(30))
        .await
        .unwrap();
    let origin = VeraClient::new(cluster.node(0).rpc_url());
    let signer = BlsSigner::new(7u64.into(), deployment).unwrap();
    cluster.kill_node(2);
    cluster.kill_node(3);

    let pending = tokio::time::timeout(PHASE_DEADLINE, async {
        let mut pending = Vec::with_capacity(CAPACITY as usize);
        for sequence in 0..CAPACITY {
            pending.push(
                origin
                    .send_native_tx(&signed_namespace(&signer, sequence))
                    .await
                    .unwrap(),
            );
        }
        pending
    })
    .await
    .expect("pending queue fill deadline");
    let rejected_wire = signed_namespace(&signer, CAPACITY);
    for _ in 0..3 {
        let error = origin.send_native_tx(&rejected_wire).await.unwrap_err();
        assert!(matches!(error, ClientError::ResourceBusy(_)));
    }
    for id in [pending[0], pending[CAPACITY as usize - 1]] {
        assert!(origin.read_receipt(id, &trusted).await.unwrap().is_none());
    }
    assert_eq!(origin.get_native_nonce(signer.did()).await.unwrap(), 0);

    cluster.restart_node(2).unwrap();
    let recovery_started = Instant::now();
    let last = tokio::time::timeout(
        PHASE_DEADLINE,
        origin.wait_for_receipt(*pending.last().unwrap(), POLL, 1_200),
    )
    .await;
    if !matches!(&last, Ok(Ok(_))) {
        for index in 0..3 {
            let client = VeraClient::new(cluster.node(index).rpc_url());
            let nonce = tokio::time::timeout(
                Duration::from_secs(2),
                client.get_native_nonce(signer.did()),
            )
            .await
            .ok()
            .and_then(Result::ok)
            .map_or_else(|| "unavailable".to_owned(), |value| value.to_string());
            eprintln!(
                "native_admission_progress replica={index} nonce={nonce} elapsed_ms={}",
                recovery_started.elapsed().as_millis()
            );
        }
    }
    let last = last.expect("admitted work recovery deadline").unwrap();
    assert_eq!(last.status, 1);

    let retry = tokio::time::timeout(PHASE_DEADLINE, async {
        loop {
            match origin.send_native_tx(&rejected_wire).await {
                Ok(id) => break id,
                Err(ClientError::ResourceBusy(_)) => tokio::time::sleep(POLL).await,
                Err(error) => panic!("rejected wire cannot be admitted after recovery: {error}"),
            }
        }
    })
    .await
    .expect("recovered queue admission deadline");
    let recovered =
        tokio::time::timeout(PHASE_DEADLINE, origin.wait_for_receipt(retry, POLL, 1_200))
            .await
            .expect("rejected wire retry deadline")
            .unwrap();
    assert_eq!(recovered.status, 1);
    cluster.restart_node(3).unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();

    let expected: BTreeSet<_> = (0..=CAPACITY)
        .map(|sequence| format!("bulletin/{}", namespace(sequence)))
        .collect();
    tokio::time::timeout(PHASE_DEADLINE, async {
        for index in 0..4 {
            let client = VeraClient::new(cluster.node(index).rpc_url());
            let mut names = BTreeSet::new();
            let mut cursor = None;
            loop {
                let page = client
                    .list_bulletin_namespaces(cursor, 128, recovered.block_number, &trusted)
                    .await
                    .unwrap();
                for record in page.records {
                    assert_eq!(record.owner_did, signer.did());
                    assert!(
                        names.insert(record.id),
                        "duplicate namespace on replica {index}"
                    );
                }
                cursor = page.continuation;
                if cursor.is_none() {
                    break;
                }
            }
            assert_eq!(
                names, expected,
                "admitted namespace loss on replica {index}"
            );
            assert_eq!(
                client.get_native_nonce(signer.did()).await.unwrap(),
                CAPACITY + 1
            );
            let receipt = client.read_receipt(retry, &trusted).await.unwrap().unwrap();
            assert!(receipt.verify(retry, &trusted).unwrap().success());
            assert_eq!(receipt.revision.height, recovered.block_number);
        }
    })
    .await
    .expect("certified replica reconciliation deadline");
}
