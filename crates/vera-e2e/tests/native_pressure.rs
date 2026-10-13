//! Qualify native admission and finalization while validators cannot process work.

#[cfg(unix)]
#[path = "../examples/operation_baseline/resources.rs"]
mod resources;

#[cfg(target_os = "linux")]
#[path = "native_pressure/stalled_validator.rs"]
mod stalled_validator;

#[cfg(target_os = "linux")]
#[path = "native_pressure/delayed_validator.rs"]
mod delayed_validator;

use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

use alloy_sol_types::SolCall;
use vera_client::{BULLETIN_ADDRESS, BlsSigner, ClientError, VeraClient};
use vera_e2e::cluster::{ConsensusPreset, GenesisBuilder, KeySet, TestCluster};
use vera_modules::bulletin::abi::IBulletin;

const CAPACITY: u64 = 4_096;
const POLL: Duration = Duration::from_millis(100);
const PHASE_DEADLINE: Duration = Duration::from_secs(120);
const PRESSURE_ROUNDS: usize = 300;
const PRESSURE_CONCURRENCY: usize = 4;

#[cfg(unix)]
fn phase(started: tokio::time::Instant, name: &str) {
    println!(
        "{}",
        serde_json::json!({"kind": "pressure_phase", "phase": name,
            "elapsed_seconds": started.elapsed().as_secs_f64()})
    );
}

async fn reject_full_queue(client: &VeraClient, wire: &[u8]) -> Vec<f64> {
    tokio::time::timeout(PHASE_DEADLINE, async {
        let mut samples = Vec::with_capacity(PRESSURE_ROUNDS * PRESSURE_CONCURRENCY);
        let mut interval = tokio::time::interval(POLL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        for _ in 0..PRESSURE_ROUNDS {
            interval.tick().await;
            let attempts = (0..PRESSURE_CONCURRENCY).map(|_| async {
                let started = Instant::now();
                let error = client.send_native_tx(wire).await.unwrap_err();
                assert!(matches!(error, ClientError::ResourceBusy(_)));
                started.elapsed().as_secs_f64() * 1000.0
            });
            samples.extend(futures::future::join_all(attempts).await);
        }
        samples
    })
    .await
    .expect("full queue rejection deadline")
}

fn namespace(index: u64) -> String {
    format!("admission/limit/{index:04}")
}

#[cfg(target_os = "linux")]
fn signed_namespace(signer: &BlsSigner, sequence: u64) -> Vec<u8> {
    signed_indexed_namespace(signer, sequence, sequence)
}

fn signed_indexed_namespace(signer: &BlsSigner, sequence: u64, index: u64) -> Vec<u8> {
    signer
        .sign_native_tx_with_sequence(
            BULLETIN_ADDRESS,
            IBulletin::registerNamespaceCall {
                namespace: namespace(index),
            }
            .abi_encode()
            .into(),
            sequence,
        )
        .unwrap()
}

fn read_error_kind(error: &ClientError) -> &'static str {
    match error {
        ClientError::ResourceBusy(_) => "server-capacity",
        ClientError::Rpc { code: -32603, .. } => "rpc-internal",
        ClientError::Rpc { .. } => "rpc-rejected",
        ClientError::Permission(vera_permission::PermissionError::Limit) => "proof-limit",
        ClientError::Permission(_) => "proof-invalid",
        ClientError::Finalization(_) => "finality-invalid",
        ClientError::Transport(error) if error.is_timeout() => "transport-timeout",
        ClientError::Transport(_) => "transport",
        ClientError::Json(_) => "json",
        ClientError::ResponseTooLarge(_) => "response-limit",
        ClientError::InvalidResponse(_) | ClientError::MissingResult => "response",
        _ => "other",
    }
}

#[tokio::test]
async fn pipelined_admission_preserves_work_when_quorum_recovers() {
    admission_recovers(1).await;
}

#[tokio::test]
async fn pipelined_multiworker_admission_preserves_each_sequence_when_quorum_recovers() {
    admission_recovers(4).await;
}

#[derive(serde::Serialize)]
struct WorkerRecovery {
    worker: usize,
    confirmed: u64,
    backlog_tail_observed_ms: f64,
}

async fn admission_recovers(workers: usize) {
    assert!(matches!(workers, 1 | 4));
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
    let signers: Vec<_> = (0..workers)
        .map(|worker| BlsSigner::new((7 + worker as u64).into(), deployment).unwrap())
        .collect();
    let per_worker = CAPACITY / workers as u64;
    #[cfg(unix)]
    resources::storage(&cluster, "before_pending").await;
    #[cfg(unix)]
    let (stop_resources, resource_task, resource_started) = resources::start(&cluster);
    #[cfg(unix)]
    phase(resource_started, "filling");
    cluster.kill_node(2);
    cluster.kill_node(3);

    let mut pending_bytes = 0usize;
    let pending = tokio::time::timeout(PHASE_DEADLINE, async {
        let mut pending = Vec::with_capacity(CAPACITY as usize);
        for index in 0..CAPACITY {
            let worker = index as usize % workers;
            let wire = signed_indexed_namespace(&signers[worker], index / workers as u64, index);
            pending_bytes += wire.len();
            pending.push(origin.send_native_tx(&wire).await.unwrap());
        }
        pending
    })
    .await
    .expect("pending queue fill deadline");
    let rejected_wire = signed_indexed_namespace(&signers[0], per_worker, CAPACITY);
    #[cfg(unix)]
    phase(resource_started, "saturated");
    let rejection_ms = reject_full_queue(&origin, &rejected_wire).await;
    for id in [pending[0], pending[CAPACITY as usize - 1]] {
        assert!(origin.read_receipt(id, &trusted).await.unwrap().is_none());
    }
    for signer in &signers {
        assert_eq!(origin.get_native_nonce(signer.did()).await.unwrap(), 0);
    }

    #[cfg(unix)]
    resources::storage(&cluster, "saturated").await;
    #[cfg(unix)]
    phase(resource_started, "recovering");
    let recovery_started = Instant::now();
    cluster.restart_node(2).unwrap();
    let worker_recoveries = futures::future::join_all(signers.iter().enumerate().map(
        |(worker, signer)| {
            let origin = &origin;
            let cluster = &cluster;
            let id = pending[pending.len() - workers + worker];
            async move {
                let last = tokio::time::timeout(
                    PHASE_DEADLINE,
                    origin.wait_for_receipt(id, POLL, 1_200),
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
                            "native_admission_progress replica={index} nonce={nonce} elapsed_ms={} worker={worker}",
                            recovery_started.elapsed().as_millis()
                        );
                    }
                }
                assert_eq!(last.expect("admitted work recovery deadline").unwrap().status, 1);
                let backlog_tail_observed_ms = recovery_started.elapsed().as_secs_f64() * 1000.0;
                let confirmed = origin.get_native_nonce(signer.did()).await.unwrap();
                assert_eq!(confirmed, per_worker);
                WorkerRecovery {
                    worker,
                    confirmed,
                    backlog_tail_observed_ms,
                }
            }
        },
    ))
    .await;

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

    let expected: BTreeMap<_, _> = (0..=CAPACITY)
        .map(|index| {
            (
                format!("bulletin/{}", namespace(index)),
                signers[index as usize % workers].did().to_owned(),
            )
        })
        .collect();
    tokio::time::timeout(PHASE_DEADLINE, async {
        for index in 0..4 {
            let client = VeraClient::new(cluster.node(index).rpc_url());
            let mut names = BTreeSet::new();
            let mut cursor = None;
            let mut minimum = recovered.block_number;
            loop {
                let page = loop {
                    match client
                        .list_bulletin_namespaces(cursor.clone(), 128, minimum, &trusted)
                        .await
                    {
                        Ok(page) => break page,
                        Err(error) => {
                            eprintln!(
                                "recovery_rpc_failure phase=admission-pages kind={} replica={index}",
                                read_error_kind(&error)
                            );
                            if !matches!(error, ClientError::ResourceBusy(_)) {
                                panic!("certified admission page failed on replica {index}");
                            }
                            tokio::time::sleep(POLL).await;
                        }
                    }
                };
                minimum = page.revision;
                for record in page.records {
                    assert_eq!(&record.owner_did, expected.get(&record.id).unwrap());
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
                names, expected.keys().cloned().collect::<BTreeSet<_>>(),
                "admitted namespace loss on replica {index}"
            );
            for (worker, signer) in signers.iter().enumerate() {
                assert_eq!(
                    client.get_native_nonce(signer.did()).await.unwrap(),
                    per_worker + u64::from(worker == 0)
                );
            }
            let receipt = loop {
                match client.read_receipt(retry, &trusted).await {
                    Ok(Some(receipt)) => break receipt,
                    Ok(None) => {}
                    Err(error) => {
                        eprintln!(
                            "recovery_rpc_failure phase=admission-receipts kind={} replica={index}",
                            read_error_kind(&error)
                        );
                        if !matches!(error, ClientError::ResourceBusy(_)) {
                            panic!("certified admission receipt failed on replica {index}");
                        }
                    }
                }
                tokio::time::sleep(POLL).await;
            };
            assert!(receipt.verify(retry, &trusted).unwrap().success());
            assert_eq!(receipt.revision.height, recovered.block_number);
        }
    })
    .await
    .expect("certified replica reconciliation deadline");
    let recovery_ms = recovery_started.elapsed().as_secs_f64() * 1000.0;
    #[cfg(unix)]
    {
        phase(resource_started, "reconciled");
        let _ = stop_resources.send(());
        resource_task.await.expect("resource sampler completion");
        resources::storage(&cluster, "after_reconciliation").await;
    }
    println!(
        "{}",
        serde_json::json!({"kind": "pressure_result", "admitted": pending.len(),
            "workers": workers, "worker_recoveries": worker_recoveries,
            "pending_wire_bytes": pending_bytes, "rejected": rejection_ms.len(),
            "rejection_ms": rejection_ms,
            "recovery_ms": recovery_ms,
            "reconciled_replicas": 4, "confirmed": CAPACITY + 1,
            "final_node_pids": (0..4).map(|index| cluster.node(index).process.id().unwrap()).collect::<Vec<_>>()})
    );
}
