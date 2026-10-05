use jsonrpsee::core::RpcResult;
use std::time::Duration;
use vera_domain::ModuleId;
use vera_permission::{
    PermissionError, PrefixResponse, RECORD_RESPONSE_BYTES, current::MAX_KEY_BYTES, encoded_size,
};

use super::{
    VeraApiImpl,
    permission::{error, request_error, retryable},
};

impl VeraApiImpl {
    pub(super) async fn current_prefix_proof(
        &self,
        module: ModuleId,
        prefix: &[u8],
        minimum_height: u64,
    ) -> RpcResult<PrefixResponse> {
        if prefix.len() > MAX_KEY_BYTES {
            return Err(request_error(PermissionError::Limit));
        }
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
                    match vera_backend::native::prefix_proof_at(
                        [&a, &b, &h, &n],
                        selected.module_state_root,
                        module,
                        prefix,
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
            let response = PrefixResponse {
                revision,
                prefix: proof,
            };
            encoded_size(&response, RECORD_RESPONSE_BYTES - 1024).map_err(request_error)?;
            Ok(response)
        })
        .await
        .map_err(|_| retryable("current prefix evidence deadline exceeded"))?
    }
}
