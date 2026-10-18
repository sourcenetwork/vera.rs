use super::*;
use commonware_runtime::{Metrics as _, Runner as _, deterministic};

#[test]
fn measured_history_only_counts_batches_after_successful_persistence() {
    deterministic::Runner::default().start(|context| async move {
        let directory = tempfile::tempdir().unwrap();
        let genesis = block(0, BlockId(B256::ZERO));
        let history = FinalizedHistory::open(directory.path(), &genesis)
            .unwrap()
            .with_metrics(Some(Arc::new(
                crate::finalization_metrics::FinalizationMetrics::register(&context),
            )));
        let first = block(1, genesis.id());
        history.append(&first, &[], 100).unwrap();
        let next = block(2, first.id());
        assert!(
            history
                .append_batch_with_write(&next, &[], 100, WriteBatch::default(), |_, _| {
                    anyhow::bail!("injected history failure")
                })
                .is_err()
        );
        assert_eq!(history.head_height(), 1);
        let encoded = context.encode();
        assert!(
            encoded
                .lines()
                .any(|line| line == "history_batch_seconds_count 1")
        );
        assert!(
            encoded
                .lines()
                .any(|line| line == "history_lock_seconds_count 2")
        );
    });
}
