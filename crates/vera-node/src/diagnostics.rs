//! Opt-in resource snapshots using existing runtime and storage measurements.

use crate::FinalizedHistory;
use commonware_runtime::{Metrics as _, tokio::Context};
use std::{sync::Arc, time::Duration};
use vera_indexer::{BlockIndex, LightBlockIndex};

pub(crate) fn enabled() -> bool {
    tracing::enabled!(target: "vera_resource_diagnostics", tracing::Level::DEBUG)
        || tracing::enabled!(target: "vera_diagnostics", tracing::Level::DEBUG)
}

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
                crate::allocator_memory::snapshot(),
            ))
        })
        .await;
        match result {
            Ok(Ok((metrics, memory, durable_height, index, proofs, allocator))) => {
                if tracing::enabled!(target: "vera_resource_diagnostics", tracing::Level::DEBUG) {
                    tracing::debug!(target: "vera_resource_diagnostics", runtime_metrics = %metrics,
                    history_memory_bytes = ?memory, durable_height, index = ?index, proofs = ?proofs,
                    allocator_memory_bytes = ?allocator, process_id = std::process::id(),
                    "node resource snapshot");
                } else {
                    tracing::debug!(target: "vera_diagnostics", runtime_metrics = %metrics,
                    history_memory_bytes = ?memory, durable_height, index = ?index, proofs = ?proofs,
                    allocator_memory_bytes = ?allocator, process_id = std::process::id(),
                    "node resource snapshot");
                }
            }
            Ok(Err(error)) => {
                tracing::warn!(target: "vera_resource_diagnostics", %error, "resource snapshot failed")
            }
            Err(error) => {
                tracing::warn!(target: "vera_resource_diagnostics", %error, "resource snapshot task failed")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::{EnvFilter, layer::SubscriberExt};

    #[test]
    fn resource_sampling_does_not_enable_revision_tracing() {
        let subscriber = tracing_subscriber::registry()
            .with(EnvFilter::new("warn,vera_resource_diagnostics=debug"));
        tracing::subscriber::with_default(subscriber, || {
            assert!(enabled());
            assert!(!tracing::enabled!(target: "vera_diagnostics", tracing::Level::DEBUG));
            assert!(
                !tracing::enabled!(target: "vera_publication_diagnostics", tracing::Level::DEBUG)
            );
        });
    }

    #[test]
    fn sampler_follows_explicit_diagnostic_selection() {
        for (filter, expected) in [
            ("warn", false),
            ("warn,vera_publication_diagnostics=debug", false),
            ("warn,vera_diagnostics=debug", true),
        ] {
            let subscriber = tracing_subscriber::registry().with(EnvFilter::new(filter));
            tracing::subscriber::with_default(subscriber, || assert_eq!(enabled(), expected));
        }
    }
}
