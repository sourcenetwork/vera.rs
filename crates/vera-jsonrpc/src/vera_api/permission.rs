use super::{VeraApiImpl, VeraApiServer};
use crate::error::codes;
use alloy_primitives::{B256, U64};
use jsonrpsee::{core::RpcResult, types::ErrorObjectOwned};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};
use vera_permission::{
    AccessRequest, PERMISSION_LIMITS, PERMISSION_RESPONSE_BYTES, PermissionError, PermissionProof,
    PermissionResponse, encoded_size, validate_request,
};

pub(super) fn error(error: impl std::fmt::Display) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(codes::RESOURCE_UNAVAILABLE, error.to_string(), None::<()>)
}

/// Evidence waits are transient: flag them for client retry like admission throttles.
pub(super) fn retryable(error: impl std::fmt::Display) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        codes::RESOURCE_UNAVAILABLE,
        error.to_string(),
        Some(serde_json::json!({"retryable": true})),
    )
}

pub(super) fn request_error(error: PermissionError) -> ErrorObjectOwned {
    let code = if matches!(error, PermissionError::Limit) {
        codes::LIMIT_EXCEEDED
    } else {
        codes::INVALID_PARAMS
    };
    ErrorObjectOwned::owned(code, error.to_string(), None::<()>)
}

impl VeraApiImpl {
    fn permission_snapshot(&self) -> RpcResult<vera_modules::kv_store::InMemoryKvStore> {
        Ok(self
            .modules
            .as_ref()
            .ok_or_else(|| error("module records unavailable"))?
            .read()
            .map_err(|_| error("module lock poisoned"))?
            .acp
            .store()
            .clone())
    }

    pub(super) async fn current_permission_proof(
        &self,
        policy: &str,
        request: &AccessRequest,
        minimum_height: u64,
    ) -> RpcResult<PermissionResponse> {
        validate_request(policy, request, PERMISSION_LIMITS).map_err(request_error)?;
        let databases = self
            .native_modules
            .as_ref()
            .ok_or_else(|| error("native module storage unavailable"))?;
        let index = self
            .index
            .as_ref()
            .ok_or_else(|| error("finalized revision index unavailable"))?;
        let mut updates = self.state.proof_updates();
        static REQUESTS: AtomicU64 = AtomicU64::new(0);
        let started =
            (tracing::enabled!(target: "vera_permission_diagnostics", tracing::Level::DEBUG)
                && REQUESTS.fetch_add(1, Ordering::Relaxed).is_multiple_of(128))
            .then(Instant::now);
        let mut phase = "storage_lock";
        let mut height = 0;
        let mut attempts = 0;
        let mut lock_time = Duration::ZERO;
        let mut proof_time = Duration::ZERO;
        let mut finality_time = Duration::ZERO;
        let result = tokio::time::timeout(Duration::from_secs(2), async {
            let (selected, proof, _permit) = loop {
                attempts += 1;
                let captured = {
                    phase = "storage_lock";
                    let stage = started.map(|_| Instant::now());
                    let [a, b, h, n] = vera_backend::native::read_partitions([
                        &databases.0,
                        &databases.1,
                        &databases.2,
                        &databases.3,
                    ])
                    .await;
                    lock_time += stage.map_or(Duration::ZERO, |s| s.elapsed());
                    let selected = match index.latest_block() {
                        Some(selected) => selected,
                        None => {
                            drop((a, b, h, n));
                            phase = "publication";
                            super::record::wait_for_proof_progress(&mut updates).await;
                            continue;
                        }
                    };
                    if selected.number < minimum_height {
                        // The index can trail a just-certified receipt; wait
                        // for the next publication instead of failing a read
                        // whose minimum is already finalized elsewhere.
                        drop((a, b, h, n));
                        phase = "publication";
                        super::record::wait_for_proof_progress(&mut updates).await;
                        continue;
                    }
                    height = selected.number;
                    // Storage/publication waits must not reserve evidence capacity.
                    // Keep this permit with the proof through finality and encoding.
                    let permit = self.state.proof_permit()?;
                    phase = "proof";
                    let stage = started.map(|_| Instant::now());
                    let snapshot = self.permission_snapshot()?;
                    let proof = vera_backend::native::permission_proof_at(
                        [&a, &b, &h, &n],
                        selected.module_state_root,
                        snapshot,
                        policy,
                        request,
                        PERMISSION_LIMITS,
                    )
                    .await;
                    proof_time += stage.map_or(Duration::ZERO, |s| s.elapsed());
                    match proof {
                        Ok(proof) => Some((selected, proof, permit)),
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
                // Release every read guard so an in-flight finalization can publish its index.
                phase = "publication";
                super::record::wait_for_proof_progress(&mut updates).await;
            };
            phase = "finality";
            let stage = started.map(|_| Instant::now());
            let revision = self.captured_revision(&selected).await?;
            finality_time += stage.map_or(Duration::ZERO, |s| s.elapsed());
            phase = "encoding";
            let response = PermissionResponse { revision, proof };
            encoded_size(&response, PERMISSION_RESPONSE_BYTES - 1024).map_err(request_error)?;
            Ok(response)
        })
        .await
        .map_err(|_| retryable("current permission evidence deadline exceeded"))
        .and_then(std::convert::identity);
        if let Some(started) = started {
            tracing::debug!(target: "vera_permission_diagnostics", height, attempts, phase,
                success = result.is_ok(), elapsed_us = started.elapsed().as_micros(),
                storage_lock_us = lock_time.as_micros(), proof_us = proof_time.as_micros(),
                finality_us = finality_time.as_micros(),
                error = ?result.as_ref().err(), "sampled permission proof stages");
        }
        result
    }

    pub(super) async fn permission_proof(
        &self,
        policy: &str,
        request: &AccessRequest,
        height: u64,
    ) -> RpcResult<PermissionProof> {
        validate_request(policy, request, PERMISSION_LIMITS).map_err(request_error)?;
        let light = self.get_light_block(U64::from(height)).await?;
        let root: B256 = light.module_state_root.parse().map_err(error)?;
        let snapshot = self.permission_snapshot()?;
        let databases = self
            .native_modules
            .as_ref()
            .ok_or_else(|| error("native module storage unavailable"))?;
        vera_backend::native::permission_proof(
            databases,
            root,
            snapshot,
            policy,
            request,
            PERMISSION_LIMITS,
        )
        .await
        .map_err(error)
    }
}
