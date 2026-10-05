use jsonrpsee::core::RpcResult;
use std::time::Duration;
use vera_permission::{
    PAGE_RESPONSE_BYTES, PermissionError, PrefixPageRequest, PrefixPageResponse, encoded_size,
};

use super::{
    VeraApiImpl,
    permission::{error, request_error, retryable},
};

impl VeraApiImpl {
    pub(super) async fn current_prefix_page_proof(
        &self,
        request: &PrefixPageRequest,
        minimum_height: u64,
    ) -> RpcResult<PrefixPageResponse> {
        request.validate().map_err(request_error)?;
        let databases = self
            .native_modules
            .as_ref()
            .ok_or_else(|| error("native module storage unavailable"))?;
        let index = self
            .index
            .as_ref()
            .ok_or_else(|| error("finalized revision index unavailable"))?;
        let mut updates = self.state.proof_updates();
        tokio::time::timeout(Duration::from_secs(2), async {
            let (selected, proof) = loop {
                let captured = {
                    let [a, b, h, n] = vera_backend::native::read_partitions([
                        &databases.0,
                        &databases.1,
                        &databases.2,
                        &databases.3,
                    ])
                    .await;
                    let selected = match index.latest_block() {
                        Some(selected) => selected,
                        None => {
                            drop((a, b, h, n));
                            super::record::wait_for_proof_progress(&mut updates).await;
                            continue;
                        }
                    };
                    if selected.number < minimum_height {
                        // The index can trail a just-certified receipt; wait
                        // for the next publication instead of failing a read
                        // whose minimum is already finalized elsewhere.
                        drop((a, b, h, n));
                        super::record::wait_for_proof_progress(&mut updates).await;
                        continue;
                    }
                    match vera_backend::native::prefix_page_at(
                        [&a, &b, &h, &n],
                        selected.module_state_root,
                        request,
                    )
                    .await
                    {
                        Ok(proof) => Some((selected, proof)),
                        Err(vera_backend::BackendError::Permission(PermissionError::Invalid(
                            "selected module root changed",
                        ))) => None,
                        Err(vera_backend::BackendError::Permission(PermissionError::Limit)) => {
                            return Err(request_error(PermissionError::Limit));
                        }
                        Err(cause) => return Err(error(cause)),
                    }
                };
                if let Some(captured) = captured {
                    break captured;
                }
                super::record::wait_for_proof_progress(&mut updates).await;
            };
            let revision = self.captured_revision(&selected).await?;
            let response = PrefixPageResponse {
                revision,
                page: proof,
            };
            encoded_size(&response, PAGE_RESPONSE_BYTES - 1024).map_err(request_error)?;
            Ok(response)
        })
        .await
        .map_err(|_| retryable("current page evidence deadline exceeded"))?
    }
}
