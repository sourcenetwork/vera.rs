use super::*;

impl OrderedState {
    pub(super) async fn apply_with_faults(&self, batches: Sealed, height: u64, changed: bool) {
        let native = self.native_databases();
        for (index, (database, batch)) in [native.0, native.1, native.2, native.3]
            .into_iter()
            .zip([batches.0, batches.1, batches.2, batches.3])
            .enumerate()
        {
            database.apply(batch).await;
            assert!(database.finalize().await.durable().await);
            if changed {
                self.executor.after_module_commit(height, index);
            }
        }
        self.databases.4.apply(batches.4).await;
    }
}
