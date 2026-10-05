//! Wait for the final measured revision before checking replicas' current state.

use std::time::Duration;

use alloy_primitives::B256;
use futures::future::try_join_all;
use serde_json::{Value, json};
use tokio::time::Instant;
use vera_client::VeraClient;

use super::driver::{POLL_INTERVAL, REQUEST_TIMEOUT};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Anchor {
    pub(super) transaction_hash: B256,
    pub(super) block_hash: B256,
    pub(super) height: u64,
    pub(super) status: u64,
}

pub(super) async fn synchronize(
    clients: &[VeraClient],
    receipts: impl Iterator<Item = Anchor>,
) -> Result<Option<Value>, String> {
    let Some(anchor) = receipts.max_by_key(|receipt| receipt.height) else {
        return Ok(None);
    };
    let started = Instant::now();
    try_join_all(
        clients
            .iter()
            .enumerate()
            .map(|(replica, client)| wait_for_replica(client, replica, anchor, REQUEST_TIMEOUT)),
    )
    .await?;
    Ok(Some(json!({
        "kind": "replica_state_barrier",
        "transaction_hash": anchor.transaction_hash,
        "block_hash": anchor.block_hash,
        "height": anchor.height,
        "status": anchor.status,
        "replicas": clients.len(),
        "elapsed_ms": started.elapsed().as_secs_f64() * 1000.0,
    })))
}

async fn wait_for_replica(
    client: &VeraClient,
    replica: usize,
    anchor: Anchor,
    timeout: Duration,
) -> Result<(), String> {
    let receipt = tokio::time::timeout(
        timeout,
        client.wait_for_receipt(anchor.transaction_hash, POLL_INTERVAL, 600),
    )
    .await
    .map_err(|_| {
        format!("replica {replica} final-state barrier timed out after {timeout:?}: {anchor:?}")
    })?
    .map_err(|error| {
        format!("replica {replica} final-state barrier failed: {anchor:?}: {error}")
    })?;
    let actual = Anchor {
        transaction_hash: receipt.transaction_hash,
        block_hash: receipt.block_hash,
        height: receipt.block_number,
        status: receipt.status,
    };
    if actual != anchor {
        return Err(format!(
            "replica {replica} final-state barrier receipt differs: expected {anchor:?}, actual {actual:?}"
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "replica_barrier_tests.rs"]
mod tests;
