//! Bounded phase observations and failure evidence for quorum recovery.

use std::{
    fs::File,
    future::Future,
    io::{Read as _, Seek as _, SeekFrom},
    path::Path,
    time::{Duration, SystemTime},
};

use alloy_primitives::B256;
use futures::future::join_all;
use serde_json::{Value, json};
use vera_client::{ClientError, VeraClient};
use vera_domain::ConsensusPublicKey;
use vera_e2e::cluster::TestCluster;

const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_LOG_BYTES: u64 = 256 << 10;

pub(super) async fn capture(
    cluster: &TestCluster,
    submission: B256,
    signer: &str,
    trusted: &ConsensusPublicKey,
    cause: &str,
    context: &Value,
) {
    let failure_observed_at = timestamp_ms();
    let nodes = join_all((0..cluster.node_count()).map(|index| async move {
        let node = cluster.node(index);
        let client = VeraClient::new(node.rpc_url());
        let (height, nonce, receipt, certified) = tokio::join!(
            probe(async { client.block_number().await.map(|height| json!(height)) }),
            probe(async {
                client
                    .get_native_nonce(signer)
                    .await
                    .map(|nonce| json!(nonce))
            }),
            probe(async {
                client.get_native_receipt(submission).await.map(|receipt| {
                    json!(receipt.map(|receipt| json!({
                        "submission": receipt.transaction_hash,
                        "height": receipt.block_number,
                        "status": receipt.status,
                    })))
                })
            }),
            probe(async {
                client.read_receipt(submission, trusted).await.map(|proof| {
                    json!(proof.map(|proof| json!({
                        "height": proof.revision.height,
                        "success": proof.receipts.iter()
                            .find(|receipt| receipt.tx_hash == submission)
                            .map(vera_domain::ExecutionReceipt::success),
                    })))
                })
            }),
        );
        let directory = node.log_dir.clone();
        let logs = tokio::task::spawn_blocking(move || log_tails(&directory)).await;
        json!({
            "node": index,
            "process_id": node.process.id(),
            "indexed_height": height,
            "native_nonce": nonce,
            "indexed_receipt": receipt,
            "certified_receipt": certified,
            "logs": logs.unwrap_or_else(|error| json!({"error": error.to_string()})),
        })
    }))
    .await;
    let report = json!({
        "format_version": 1,
        "kind": "quorum_recovery_failure",
        "phase": "after_third_member_restart",
        "observed_at_unix_ms": failure_observed_at,
        "capture_completed_at_unix_ms": timestamp_ms(),
        "context": context,
        "submission": submission,
        "cause": cause,
        "probe_timeout_ms": PROBE_TIMEOUT.as_millis(),
        "metrics_source": "Timestamped vera_diagnostics log snapshots contain actual Commonware runtime metrics and durable_height; snapshots may precede this failure. Missing samples are not zero values.",
        "nodes": nodes,
    });
    let path = cluster.node(0).data_dir.join("quorum-failure.json");
    let output = path.clone();
    match tokio::task::spawn_blocking(move || std::fs::write(output, report.to_string())).await {
        Ok(Ok(())) => eprintln!("quorum failure evidence: {}", path.display()),
        result => eprintln!(
            "could not write quorum failure evidence to {}: {result:?}",
            path.display()
        ),
    }
}

pub(super) fn timestamp_ms() -> Option<u128> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
        .ok()
}

pub(super) async fn heights(clients: &[VeraClient]) -> Vec<Value> {
    join_all(
        clients
            .iter()
            .enumerate()
            .map(|(index, client)| async move {
                let started_at = timestamp_ms();
                let height =
                    probe(async { client.block_number().await.map(|height| json!(height)) }).await;
                json!({
                    "node": index,
                    "started_at_unix_ms": started_at,
                    "completed_at_unix_ms": timestamp_ms(),
                    "indexed_height": height,
                })
            }),
    )
    .await
}

async fn probe(future: impl Future<Output = Result<Value, ClientError>>) -> Value {
    match tokio::time::timeout(PROBE_TIMEOUT, future).await {
        Ok(Ok(value)) => json!({"ok": value}),
        Ok(Err(error)) => json!({"error": error.to_string()}),
        Err(_) => json!({"error": "probe timed out"}),
    }
}

fn log_tails(directory: &Path) -> Value {
    json!({
        "stdout": log_tail(&directory.join("stdout.log")),
        "stderr": log_tail(&directory.join("stderr.log")),
    })
}

fn log_tail(path: &Path) -> Value {
    let read = || -> std::io::Result<(u64, Vec<u8>)> {
        let mut file = File::open(path)?;
        let length = file.metadata()?.len();
        let offset = length.saturating_sub(MAX_LOG_BYTES);
        file.seek(SeekFrom::Start(offset))?;
        let mut bytes = Vec::new();
        file.take(length - offset).read_to_end(&mut bytes)?;
        Ok((length, bytes))
    };
    match read() {
        Ok((length, bytes)) => {
            let text = String::from_utf8_lossy(&bytes);
            json!({
                "file_bytes": length,
                "truncated": length > MAX_LOG_BYTES,
                "runtime_metrics_present": text.contains("runtime_metrics="),
                "durable_height_present": text.contains("durable_height="),
                "text": text,
            })
        }
        Err(error) => json!({"error": error.to_string()}),
    }
}

#[cfg(test)]
#[path = "diagnostics_tests.rs"]
mod tests;
