//! Source-bound inclusion/receipt qualification, not a throughput benchmark.

use std::{collections::BTreeMap, io::Write as _, time::Duration};

use alloy_primitives::B256;
use alloy_sol_types::SolCall as _;
use serde_json::json;
use tokio::{sync::oneshot, time::Instant};
use vera_client::{ACP_ADDRESS, BlsSigner, VeraClient};
use vera_domain::{ConsensusPublicKey, NativeTx, ReceiptResponse};
use vera_e2e::cluster::{ConsensusPreset, KeySet, TestCluster};
use vera_modules::acp::abi::IAcp;

const POLL: Duration = Duration::from_millis(50);
const DEADLINE: Duration = Duration::from_secs(30);
const SAMPLES: usize = 24;

/// Observe every new certified height independently of receipt lookup. The receipt
/// selects its height only after verification; an earlier finality observation is
/// retained, never reconstructed from a block's wall-clock timestamp.
async fn finality_observation(
    observer: &VeraClient,
    trusted: &ConsensusPublicKey,
    baseline: u64,
    mut target: oneshot::Receiver<u64>,
) -> Result<(Instant, String), String> {
    let mut next = baseline + 1;
    let mut observations = BTreeMap::new();
    let mut selected = None;
    loop {
        // Status is only a scheduling hint, not proof of finality.
        let latest = observer
            .node_status()
            .await
            .map_err(|e| format!("finality status: {e:?}"))?
            .finalized_height
            .unwrap_or(0);
        for height in next..=latest {
            let revision = observer
                .read_finalized_revision(height, trusted)
                .await
                .map_err(|e| format!("finality evidence at {height}: {e:?}"))?;
            observations.insert(height, (Instant::now(), revision.block_hash));
        }
        next = next.max(latest.saturating_add(1));
        if selected.is_none() {
            match target.try_recv() {
                Ok(height) => selected = Some(height),
                Err(oneshot::error::TryRecvError::Empty) => {}
                Err(error) => return Err(format!("receipt observation cancelled: {error}")),
            }
        }
        if let Some(height) = selected {
            if height <= baseline {
                return Err(format!("submission included before baseline: {height}"));
            }
            if let Some(observation) = observations.remove(&height) {
                return Ok(observation);
            }
        }
        tokio::time::sleep(POLL).await;
    }
}

async fn receipt_observation(
    observer: &VeraClient,
    trusted: &ConsensusPublicKey,
    id: B256,
    target: oneshot::Sender<u64>,
) -> Result<(Instant, ReceiptResponse, usize), String> {
    let mut polls = 0;
    loop {
        polls += 1;
        if let Some(proof) = observer
            .read_receipt(id, trusted)
            .await
            .map_err(|e| format!("receipt evidence: {e:?}"))?
        {
            let observed = Instant::now();
            if !proof
                .verify(id, trusted)
                .map_err(|e| e.to_string())?
                .success()
            {
                return Err(format!(
                    "execution rejected at {}: {proof:?}",
                    proof.revision.height
                ));
            }
            target
                .send(proof.revision.height)
                .map_err(|_| "finality observer cancelled")?;
            return Ok((observed, proof, polls));
        }
        tokio::time::sleep(POLL).await;
    }
}

fn milliseconds(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

#[tokio::test]
async fn single_endpoint_submission_has_cross_endpoint_certified_receipts() {
    let deployment = 9088;
    let trusted = *KeySet::builder()
        .nodes(4)
        .seed(deployment)
        .build()
        .unwrap()
        .epoch_info()
        .output
        .public()
        .public();
    let cluster = TestCluster::builder()
        .binary(vera_e2e::resolve_binary().unwrap())
        .nodes(4)
        .seed(deployment)
        .chain_id(deployment)
        .preset(ConsensusPreset::Normal)
        .build()
        .await
        .unwrap();
    let output = cluster
        .node(0)
        .data_dir
        .parent()
        .unwrap()
        .join("cross-endpoint-receipts.jsonl");
    let mut output = std::fs::File::create(&output).unwrap();
    let configuration = json!({
        "type": "configuration", "version": 1, "environment": "four validators and client on one host",
        "deployment": deployment, "key_seed": deployment, "samples": SAMPLES,
        "preset": "normal", "revisions_per_epoch": 20, "maximum_outstanding": 1, "deadline_ms": DEADLINE.as_millis(), "poll_ms": POLL.as_millis(),
        "submission": "one RPC call to one member; no manual broadcast or retry",
        "latency": "client monotonic observations; signed finality-to-receipt delta; not server publication time",
        "nodes": (0..4).map(|i| json!({"index": i, "config": cluster.node(i).data_dir.join("config.toml"),
            "logs": cluster.node(i).log_dir})).collect::<Vec<_>>()
    });
    println!("{configuration}");
    writeln!(output, "{configuration}").unwrap();
    output.flush().unwrap();
    cluster
        .wait_ready(vera_e2e::readiness_deadline())
        .await
        .unwrap();
    cluster
        .observe(POLL)
        .wait_for_height(3, DEADLINE)
        .await
        .unwrap();
    let clients: Vec<_> = cluster.rpc_urls().iter().map(VeraClient::new).collect();
    let signer = BlsSigner::new(7u64.into(), deployment).unwrap();
    let mut failed = 0;
    let mut finality_latencies = Vec::new();
    let mut receipt_latencies = Vec::new();
    for sample in 0..SAMPLES {
        // Every ordered pair of distinct members, twice. One outstanding operation.
        let writer = sample % 4;
        let reader = (writer + 1 + (sample / 4) % 3) % 4;
        let wire = signer
            .sign_native_tx(
                ACP_ADDRESS,
                IAcp::createPolicyCall {
                    policy: format!("name: cross_endpoint_{sample}\nresources:\n  - name: file\n")
                        .into_bytes()
                        .into(),
                    marshalType: 1,
                }
                .abi_encode()
                .into(),
            )
            .unwrap();
        let id = NativeTx::decode_wire(&wire).unwrap().tx_id().0;
        let started = Instant::now();
        let result = tokio::time::timeout(DEADLINE, async {
            let baseline = clients[reader]
                .node_status()
                .await
                .map_err(|e| format!("baseline: {e:?}"))?
                .finalized_height
                .ok_or("baseline has no finalized revision")?;
            let submitted = Instant::now();
            let (tx, rx) = oneshot::channel();
            let submission_and_receipt = async {
                let returned = clients[writer]
                    .send_native_tx(&wire)
                    .await
                    .map_err(|e| format!("admission: {e:?}"))?;
                if returned != id {
                    return Err("submission ID mismatch".to_string());
                }
                let admitted = Instant::now();
                let (received, proof, polls) =
                    receipt_observation(&clients[reader], &trusted, id, tx).await?;
                Ok((admitted, received, proof, polls))
            };
            let ((finalized, block_hash), (admitted, received, proof, polls)) = tokio::try_join!(
                finality_observation(&clients[reader], &trusted, baseline, rx),
                submission_and_receipt,
            )?;
            if block_hash != proof.revision.block_hash {
                return Err("finality/receipt block mismatch".to_string());
            }
            Ok((submitted, admitted, finalized, received, proof, polls))
        })
        .await
        .map_err(|_| "30-second observation deadline".to_string())
        .and_then(|r| r);
        let mut row = json!({"type": "observation", "sample": sample, "id": id,
            "writer": writer, "reader": reader, "elapsed_ms": milliseconds(started.elapsed())});
        match result {
            Ok((submitted, admitted, finalized, received, proof, polls)) => {
                let finality_ms = milliseconds(finalized.duration_since(submitted));
                let receipt_ms = milliseconds(received.duration_since(submitted));
                finality_latencies.push(finality_ms);
                receipt_latencies.push(receipt_ms);
                row["admission_ms"] = json!(milliseconds(admitted.duration_since(submitted)));
                row["submission_to_observed_finality_ms"] = json!(finality_ms);
                row["submission_to_certified_receipt_ms"] = json!(receipt_ms);
                row["observed_finality_to_receipt_ms"] = json!(receipt_ms - finality_ms);
                row["revision"] = json!(proof.revision.height);
                row["block_hash"] = json!(proof.revision.block_hash);
                row["receipt_polls"] = json!(polls);
                // Reconciliation is outside the measured interval, also bounded.
                let reconciliation = tokio::time::timeout(DEADLINE, async {
                    for (index, client) in clients.iter().enumerate() {
                        loop {
                            let Some(other) = client
                                .read_receipt(id, &trusted)
                                .await
                                .map_err(|e| format!("replica {index}: {e:?}"))?
                            else {
                                tokio::time::sleep(POLL).await;
                                continue;
                            };
                            if other.revision.block_hash != proof.revision.block_hash
                                || serde_json::to_value(
                                    other.verify(id, &trusted).map_err(|e| e.to_string())?,
                                )
                                .unwrap()
                                    != serde_json::to_value(
                                        proof.verify(id, &trusted).map_err(|e| e.to_string())?,
                                    )
                                    .unwrap()
                            {
                                return Err(format!("replica {index} receipt mismatch"));
                            }
                            break;
                        }
                    }
                    Ok::<_, String>(())
                })
                .await;
                match reconciliation {
                    Ok(Ok(())) => row["status"] = json!("verified_on_all_replicas"),
                    other => {
                        failed += 1;
                        row["error"] = json!(format!("replica reconciliation: {other:?}"));
                    }
                }
            }
            Err(error) => {
                failed += 1;
                row["error"] = json!(error);
            }
        }
        if row.get("error").is_some() {
            let mut statuses = Vec::new();
            for client in &clients {
                statuses.push(format!(
                    "{:?}",
                    tokio::time::timeout(Duration::from_secs(3), client.node_status()).await
                ));
            }
            row["node_status_diagnostics"] = json!(statuses);
        }
        println!("{row}");
        writeln!(output, "{row}").unwrap();
        output.flush().unwrap();
        // A missing sequence must not cascade into failures of dependent submissions.
        if failed != 0 {
            break;
        }
    }
    finality_latencies.sort_by(f64::total_cmp);
    receipt_latencies.sort_by(f64::total_cmp);
    let summary = json!({"type": "summary", "planned": SAMPLES, "observed": receipt_latencies.len(),
        "failures": failed, "submission_to_observed_finality_ms": finality_latencies,
        "submission_to_certified_receipt_ms": receipt_latencies});
    println!("{summary}");
    writeln!(output, "{summary}").unwrap();
    assert_eq!(
        failed, 0,
        "cross-endpoint qualification failed; inspect JSONL IDs and node logs"
    );
    assert_eq!(receipt_latencies.len(), SAMPLES);
}
