//! Capture of current native evidence at one published finalized revision.

use std::{future::Future, pin::Pin, time::Duration};

use alloy_primitives::B256;
use jsonrpsee::core::RpcResult;
use vera_backend::{BackendError, native::NativeDb};
use vera_domain::LightBlock;
use vera_indexer::BlockIndex;
use vera_permission::PermissionError;

use super::{
    VeraApiImpl,
    permission::{error, request_error, retryable},
    record::wait_for_proof_progress,
};

pub(super) type ProofFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, BackendError>> + Send + 'a>>;

/// Longest a current-evidence request waits for its revision and certificate.
pub(super) const EVIDENCE_DEADLINE: Duration = Duration::from_secs(2);

/// Revisions a caller's minimum may lead the published head and still wait
/// for it. No minimum interval separates revisions, so this is a policy and
/// not a proof that a larger lead is unreachable: covering it inside the
/// deadline takes more than 128 revisions a second.
pub(super) const MINIMUM_HEIGHT_LEAD: u64 = 256;

/// Whether the published head has reached `minimum_height`, read without the
/// partition locks. A minimum beyond the waiting lead is refused at once
/// rather than held in a request slot for the deadline; its caller retries.
pub(super) fn head_reaches(index: &BlockIndex, minimum_height: u64) -> RpcResult<bool> {
    if index.is_empty() {
        return Ok(false);
    }
    let head = index.head_block_number();
    if minimum_height > head.saturating_add(MINIMUM_HEIGHT_LEAD) {
        return Err(retryable(format!(
            "minimum height {minimum_height} is ahead of finalized revision {head}"
        )));
    }
    Ok(head >= minimum_height)
}

impl VeraApiImpl {
    /// Generate evidence under the four partition read locks at the newest
    /// published revision, then wait for that revision's certificate with the
    /// locks released. The returned proof permit covers response encoding.
    pub(super) async fn capture_current<T, F>(
        &self,
        minimum_height: u64,
        deadline: &'static str,
        generate: F,
    ) -> RpcResult<(LightBlock, T, tokio::sync::OwnedSemaphorePermit)>
    where
        T: Send,
        F: for<'a> Fn([&'a NativeDb; 4], B256) -> ProofFuture<'a, T> + Send + Sync,
    {
        let databases = self
            .native_modules
            .as_ref()
            .ok_or_else(|| error("native module storage unavailable"))?;
        let index = self
            .index
            .as_ref()
            .ok_or_else(|| error("finalized revision index unavailable"))?;
        let mut updates = self.state.proof_updates();
        tokio::time::timeout(EVIDENCE_DEADLINE, async {
            let (selected, proof, permit) = loop {
                // The index can trail a just-certified receipt; wait for the
                // next publication instead of failing a read whose minimum is
                // already finalized elsewhere.
                if !head_reaches(index, minimum_height)? {
                    wait_for_proof_progress(&mut updates).await;
                    continue;
                }
                let captured = {
                    let [a, b, h, n] = vera_backend::native::read_partitions([
                        &databases.0,
                        &databases.1,
                        &databases.2,
                        &databases.3,
                    ])
                    .await;
                    let Some(selected) = index.latest_block() else {
                        continue;
                    };
                    // Storage and publication waits must not reserve evidence capacity.
                    let permit = self.state.proof_permit()?;
                    match generate([&a, &b, &h, &n], selected.module_state_root).await {
                        Ok(proof) => Some((selected, proof, permit)),
                        Err(BackendError::Permission(PermissionError::Invalid(
                            "selected module root changed",
                        ))) => None,
                        Err(BackendError::Permission(PermissionError::Limit)) => {
                            return Err(request_error(PermissionError::Limit));
                        }
                        Err(cause) => return Err(error(cause)),
                    }
                };
                if let Some(captured) = captured {
                    break captured;
                }
                // Every read guard is released, so finalization can publish its index.
                wait_for_proof_progress(&mut updates).await;
            };
            let revision = self.captured_revision(&selected).await?;
            Ok((revision, proof, permit))
        })
        .await
        .map_err(|_| retryable(deadline))?
    }
}
