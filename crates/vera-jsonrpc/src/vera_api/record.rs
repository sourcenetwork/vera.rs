use alloy_primitives::B256;
use jsonrpsee::core::RpcResult;
use std::time::Duration;
use vera_domain::{LightBlock, ModuleId};
use vera_indexer::IndexedBlock;
use vera_permission::{
    PermissionError, RECORD_RESPONSE_BYTES, RecordResponse, current::MAX_KEY_BYTES, encoded_size,
};

use super::{
    VeraApiImpl,
    permission::{error, request_error},
};

impl VeraApiImpl {
    pub(super) async fn current_record_proof(
        &self,
        module: ModuleId,
        key: &[u8],
        minimum_height: u64,
    ) -> RpcResult<RecordResponse> {
        if key.len() > MAX_KEY_BYTES {
            return Err(request_error(PermissionError::Limit));
        }
        let key = key.to_vec();
        let (revision, record, _permit) = self
            .capture_current(
                minimum_height,
                "current record evidence deadline exceeded",
                move |databases, root| {
                    let key = key.clone();
                    Box::pin(async move {
                        vera_backend::native::record_proof_at(databases, root, module, &key).await
                    })
                },
            )
            .await?;
        let response = RecordResponse { revision, record };
        encoded_size(&response, RECORD_RESPONSE_BYTES - 1024).map_err(request_error)?;
        Ok(response)
    }

    // Called after releasing storage guards, under the enclosing request deadline.
    pub(super) async fn captured_revision(&self, selected: &IndexedBlock) -> RpcResult<LightBlock> {
        let mut updates = self.state.proof_updates();
        loop {
            if let Some(revision) = self.try_captured_revision(selected).await? {
                return Ok(revision);
            }
            super::record::wait_for_proof_progress(&mut updates).await;
        }
    }

    pub(super) async fn try_captured_revision(
        &self,
        selected: &IndexedBlock,
    ) -> RpcResult<Option<LightBlock>> {
        let Some(revision) = self.certified_light_block(selected.number).await? else {
            return Ok(None);
        };
        if revision.height != selected.number
            || revision.block_hash.parse::<B256>().map_err(error)? != selected.hash
            || revision.module_state_root.parse::<B256>().map_err(error)?
                != selected.module_state_root
        {
            return Err(error("finalization differs from captured revision"));
        }
        revision.check_artifact_limits().map_err(error)?;
        encoded_size(&revision, vera_domain::LIGHT_BLOCK_RESPONSE_BYTES).map_err(request_error)?;
        Ok(Some(revision))
    }
}

// Custom index/history publishers may not emit progress notifications.
pub(super) async fn wait_for_proof_progress(updates: &mut tokio::sync::watch::Receiver<()>) {
    let _ = tokio::time::timeout(Duration::from_millis(50), updates.changed()).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NodeState;
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
    };

    #[tokio::test]
    async fn progress_wakes_all_readers_without_losing_an_early_notification() {
        let state = NodeState::new(1, 0, 1);
        let mut context = Context::from_waker(Waker::noop());
        let mut first = state.proof_updates();
        let mut second = state.proof_updates();
        state.notify_proof_progress();
        for updates in [&mut first, &mut second] {
            let mut waiting = Box::pin(wait_for_proof_progress(updates));
            assert!(matches!(
                waiting.as_mut().poll(&mut context),
                Poll::Ready(())
            ));
        }
        let mut waiting = Box::pin(wait_for_proof_progress(&mut first));
        assert!(matches!(waiting.as_mut().poll(&mut context), Poll::Pending));
        state.notify_proof_progress();
        assert!(matches!(
            waiting.as_mut().poll(&mut context),
            Poll::Ready(())
        ));
        drop(waiting);
        let mut cancelled = Box::pin(wait_for_proof_progress(&mut second));
        assert!(matches!(
            cancelled.as_mut().poll(&mut context),
            Poll::Ready(())
        ));
        drop(cancelled);
        // A cancelled waiter does not consume a later publication.
        let mut cancelled = Box::pin(wait_for_proof_progress(&mut second));
        assert!(matches!(
            cancelled.as_mut().poll(&mut context),
            Poll::Pending
        ));
        drop(cancelled);
        state.notify_proof_progress();
        let mut waiting = Box::pin(wait_for_proof_progress(&mut second));
        assert!(matches!(
            waiting.as_mut().poll(&mut context),
            Poll::Ready(())
        ));
    }

    #[tokio::test]
    async fn publishers_without_notifications_still_get_rechecked() {
        let state = NodeState::new(1, 0, 1);
        let mut updates = state.proof_updates();
        tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_proof_progress(&mut updates),
        )
        .await
        .unwrap();
        assert!(!updates.has_changed().unwrap());
    }
}
