use std::{future::Future, pin::Pin, time::Duration};

use alloy_primitives::B256;
use jsonrpsee::core::RpcResult;
use vera_backend::{BackendError, native::NativeDb};
use vera_domain::{LightBlock, ModuleId};
use vera_permission::{
    PAGE_RESPONSE_BYTES, PermissionError, PolicyPrefixPageResponse, PolicyPrefixResponse,
    PrefixPageRequest, RECORD_RESPONSE_BYTES, encoded_size, validate_policy_prefix,
};

use super::{
    VeraApiImpl,
    permission::{error, request_error, retryable},
};

type ProofFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, BackendError>> + Send + 'a>>;

impl VeraApiImpl {
    pub(super) async fn current_policy_prefix_proof(
        &self,
        policy: &str,
        prefix: &[u8],
        minimum_height: u64,
    ) -> RpcResult<PolicyPrefixResponse> {
        validate_policy_prefix(policy, prefix).map_err(request_error)?;
        let policy = policy.to_owned();
        let prefix = prefix.to_vec();
        let (revision, proof, _permit) = self
            .capture_policy_proof(minimum_height, move |databases, root| {
                let policy = policy.clone();
                let prefix = prefix.clone();
                Box::pin(async move {
                    vera_backend::native::policy_prefix_proof_at(databases, root, &policy, &prefix)
                        .await
                })
            })
            .await?;
        let response = PolicyPrefixResponse { revision, proof };
        encoded_size(&response, RECORD_RESPONSE_BYTES - 1024).map_err(request_error)?;
        Ok(response)
    }

    pub(super) async fn current_policy_prefix_page_proof(
        &self,
        policy: &str,
        request: &PrefixPageRequest,
        minimum_height: u64,
    ) -> RpcResult<PolicyPrefixPageResponse> {
        validate_policy_prefix(policy, &request.prefix).map_err(request_error)?;
        request.validate().map_err(request_error)?;
        if request.module != ModuleId::Acp {
            return Err(request_error(PermissionError::Invalid(
                "policy page must use ACP storage",
            )));
        }
        let policy = policy.to_owned();
        let request = request.clone();
        let (revision, proof, _permit) = self
            .capture_policy_proof(minimum_height, move |databases, root| {
                let policy = policy.clone();
                let request = request.clone();
                Box::pin(async move {
                    vera_backend::native::policy_prefix_page_at(databases, root, &policy, &request)
                        .await
                })
            })
            .await?;
        let response = PolicyPrefixPageResponse { revision, proof };
        encoded_size(&response, PAGE_RESPONSE_BYTES - 1024).map_err(request_error)?;
        Ok(response)
    }

    async fn capture_policy_proof<T, F>(
        &self,
        minimum_height: u64,
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
        tokio::time::timeout(Duration::from_secs(2), async {
            let (selected, proof, permit) = loop {
                let captured = {
                    let [a, b, h, n] = vera_backend::native::read_partitions([
                        &databases.0,
                        &databases.1,
                        &databases.2,
                        &databases.3,
                    ])
                    .await;
                    let selected = match index.latest_block() {
                        Some(selected) if selected.number >= minimum_height => selected,
                        _ => {
                            drop((a, b, h, n));
                            super::record::wait_for_proof_progress(&mut updates).await;
                            continue;
                        }
                    };
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
                super::record::wait_for_proof_progress(&mut updates).await;
            };
            let revision = self.captured_revision(&selected).await?;
            Ok((revision, proof, permit))
        })
        .await
        .map_err(|_| retryable("current policy evidence deadline exceeded"))?
    }
}

#[cfg(test)]
mod tests;
