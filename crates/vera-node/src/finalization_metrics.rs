use commonware_runtime::{
    Metrics,
    telemetry::metrics::{Histogram, histogram::duration_histogram},
};

/// Successful finalization stages, observed without per-revision log events.
#[derive(Clone, Debug)]
pub(crate) struct FinalizationMetrics {
    pub callback: Histogram,
    pub lookup: Histogram,
    pub blocking_queue: Histogram,
    pub history_append: Histogram,
    pub history_prepare: Histogram,
    pub history_lock: Histogram,
    pub history_batch: Histogram,
}

impl FinalizationMetrics {
    pub(crate) fn register(context: &impl Metrics) -> Self {
        Self {
            callback: duration_histogram(
                context,
                "callback_seconds",
                "Successful finalized callback elapsed time",
            ),
            lookup: duration_histogram(
                context,
                "lookup_seconds",
                "Finalization artifact lookup elapsed time",
            ),
            blocking_queue: duration_histogram(
                context,
                "blocking_queue_seconds",
                "History task delay before blocking-pool execution",
            ),
            history_append: duration_histogram(
                context,
                "history_append_seconds",
                "Successful finalized history append elapsed time",
            ),
            history_prepare: duration_histogram(
                context,
                "history_prepare_seconds",
                "History validation and encoding before acquiring the head lock",
            ),
            history_lock: duration_histogram(
                context,
                "history_lock_seconds",
                "Finalized history head lock acquisition wait",
            ),
            history_batch: duration_histogram(
                context,
                "history_batch_seconds",
                "Successful synchronous finalized history batch elapsed time",
            ),
        }
    }
}
