//! Opt-in resource snapshots using existing runtime and storage measurements.

use crate::FinalizedHistory;
use commonware_runtime::{Metrics as _, tokio::Context};
use std::{sync::Arc, time::Duration};
use vera_indexer::{BlockIndex, LightBlockIndex};

pub(crate) async fn run(
    context: Context,
    history: Arc<FinalizedHistory>,
    index: Arc<BlockIndex>,
    proofs: Arc<LightBlockIndex>,
) {
    let context = Arc::new(context);
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let context = context.clone();
        let history = history.clone();
        let index = index.clone();
        let proofs = proofs.clone();
        let result = tokio::task::spawn_blocking(move || {
            Ok::<_, anyhow::Error>((
                context.encode(),
                history.memory_usage()?,
                history.head_height(),
                index.stats(),
                proofs.stats(),
            ))
        })
        .await;
        match result {
            Ok(Ok((metrics, memory, durable_height, index, proofs))) => {
                tracing::debug!(target: "vera_diagnostics", runtime_metrics = %metrics,
                    history_memory_bytes = ?memory, durable_height, index = ?index, proofs = ?proofs, "node resource snapshot");
            }
            Ok(Err(error)) => {
                tracing::warn!(target: "vera_diagnostics", %error, "resource snapshot failed")
            }
            Err(error) => {
                tracing::warn!(target: "vera_diagnostics", %error, "resource snapshot task failed")
            }
        }
    }
}
