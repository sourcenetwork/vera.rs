use std::{
    collections::BTreeSet,
    fs, io,
    process::Command,
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use vera_client::{BlsSigner, ClientError, VeraClient};
use vera_domain::{ConsensusPublicKey, LightBlock, NativeTx, ReceiptResponse};
use vera_e2e::cluster::{ConsensusPreset, GenesisBuilder, KeySet, TestCluster, TestNode};

use super::{PHASE_DEADLINE, POLL, namespace, signed_namespace};

const BLOCKS_PER_EPOCH: u64 = 192;
const MINIMUM_STALL: Duration = Duration::from_secs(30);

struct Suspended<'a> {
    node: &'a TestNode,
    resume_on_drop: bool,
}

impl<'a> Suspended<'a> {
    async fn stop(node: &'a TestNode) -> Self {
        let guard = Self {
            node,
            resume_on_drop: true,
        };
        guard.signal("-STOP").unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if guard.is_stopped() {
                    break;
                }
                tokio::time::sleep(POLL).await;
            }
        })
        .await
        .expect("validator did not enter the stopped process state");
        guard
    }

    fn signal(&self, signal: &str) -> io::Result<()> {
        let pid = self.node.process.id().expect("managed validator process");
        if Command::new("/bin/kill")
            .args([signal, &pid.to_string()])
            .status()?
            .success()
        {
            Ok(())
        } else {
            Err(io::Error::other("could not signal the managed validator"))
        }
    }

    fn is_stopped(&self) -> bool {
        let pid = self.node.process.id().unwrap();
        fs::read_to_string(format!("/proc/{pid}/status"))
            .unwrap()
            .lines()
            .any(|line| line.starts_with("State:\tT"))
    }

    fn resume(mut self) {
        self.signal("-CONT").unwrap();
        self.resume_on_drop = false;
    }
}

impl Drop for Suspended<'_> {
    fn drop(&mut self) {
        if self.resume_on_drop {
            let _ = self.signal("-CONT");
        }
    }
}

async fn certified_receipt(
    client: &VeraClient,
    id: B256,
    trusted: &ConsensusPublicKey,
) -> ReceiptResponse {
    tokio::time::timeout(PHASE_DEADLINE, async {
        loop {
            match client.read_receipt(id, trusted).await {
                Ok(Some(proof)) => {
                    assert!(proof.verify(id, trusted).unwrap().success());
                    return proof;
                }
                Ok(None) | Err(ClientError::ResourceBusy(_)) => tokio::time::sleep(POLL).await,
                Err(error) => panic!("stalled-validator receipt failed: {error}"),
            }
        }
    })
    .await
    .expect("stalled-validator certified receipt deadline")
}

async fn submit(
    client: &VeraClient,
    signer: &BlsSigner,
    sequence: u64,
    trusted: &ConsensusPublicKey,
) -> (B256, ReceiptResponse) {
    let wire = signed_namespace(signer, sequence);
    let id = NativeTx::decode_wire(&wire).unwrap().tx_id().0;
    assert_eq!(client.send_native_tx(&wire).await.unwrap(), id);
    (id, certified_receipt(client, id, trusted).await)
}

async fn certified_head(client: &VeraClient, trusted: &ConsensusPublicKey) -> LightBlock {
    tokio::time::timeout(PHASE_DEADLINE, async {
        loop {
            let height = client.block_number().await.unwrap();
            match client.read_finalized_revision(height, trusted).await {
                Ok(revision) => return revision,
                Err(ClientError::ResourceBusy(_)) => tokio::time::sleep(POLL).await,
                Err(error) => panic!("stalled-validator checkpoint failed: {error}"),
            }
        }
    })
    .await
    .expect("stalled-validator certified checkpoint deadline")
}

#[tokio::test]
async fn pipelined_stalled_validator_crosses_epoch_and_rejoins_quorum() {
    tokio::time::timeout(Duration::from_secs(360), qualify())
        .await
        .expect("stalled-validator qualification deadline");
}

async fn qualify() {
    let deployment = 9084;
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
                .blocks_per_epoch(BLOCKS_PER_EPOCH)
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
    let (first_id, _) = submit(&clients[0], &signer, 0, &trusted).await;
    certified_receipt(&clients[3], first_id, &trusted).await;

    let suspended = Suspended::stop(cluster.node(3)).await;
    let stopped_head = certified_head(&clients[0], &trusted).await;
    let started = Instant::now();
    let mut next_sequence = 1;
    let (last_id, last) = tokio::time::timeout(PHASE_DEADLINE, async {
        loop {
            assert!(next_sequence < 1_024, "stalled-validator workload bound");
            let result = submit(&clients[0], &signer, next_sequence, &trusted).await;
            next_sequence += 1;
            assert!(
                suspended.is_stopped(),
                "validator resumed before qualification"
            );
            if started.elapsed() >= MINIMUM_STALL && result.1.revision.epoch > stopped_head.epoch {
                break result;
            }
            tokio::time::sleep(POLL).await;
        }
    })
    .await
    .expect("three validators failed to finalize across an epoch");

    for client in &clients[..3] {
        let proof = certified_receipt(client, last_id, &trusted).await;
        assert_eq!(proof.revision.block_hash, last.revision.block_hash);
    }
    suspended.resume();
    let recovered = certified_receipt(&clients[3], last_id, &trusted).await;
    assert_eq!(recovered.revision.block_hash, last.revision.block_hash);

    let expected: BTreeSet<_> = (0..next_sequence)
        .map(|sequence| format!("bulletin/{}", namespace(sequence)))
        .collect();
    for client in &clients {
        let mut names = BTreeSet::new();
        let mut cursor = None;
        let mut minimum = last.revision.height;
        loop {
            let page = tokio::time::timeout(PHASE_DEADLINE, async {
                loop {
                    match client
                        .list_bulletin_namespaces(cursor.clone(), 128, minimum, &trusted)
                        .await
                    {
                        Ok(page) => break page,
                        Err(ClientError::ResourceBusy(_)) => tokio::time::sleep(POLL).await,
                        Err(error) => panic!("stalled-validator reconciliation failed: {error}"),
                    }
                }
            })
            .await
            .expect("stalled-validator reconciliation deadline");
            minimum = page.revision;
            for record in page.records {
                assert_eq!(record.owner_did, signer.did());
                assert!(names.insert(record.id), "duplicate namespace");
            }
            cursor = page.continuation;
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(names, expected, "replica lost certified work");
        assert_eq!(
            client.get_native_nonce(signer.did()).await.unwrap(),
            next_sequence
        );
    }

    // The resumed process must vote: only two other validators remain available.
    cluster.kill_node(2);
    let (required_id, required) = submit(&clients[0], &signer, next_sequence, &trusted).await;
    assert!(required.revision.height > last.revision.height);
    let recovered = certified_receipt(&clients[3], required_id, &trusted).await;
    assert_eq!(recovered.revision.block_hash, required.revision.block_hash);
}
