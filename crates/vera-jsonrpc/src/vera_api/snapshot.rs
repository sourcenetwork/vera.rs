use jsonrpsee::core::RpcResult;
use vera_permission::{
    POLICY_SNAPSHOT_RESPONSE_BYTES, PolicySnapshotResponse, encoded_size, policy_snapshot_prefixes,
    validate_policy_prefix,
};

use super::{VeraApiImpl, permission::request_error};

impl VeraApiImpl {
    pub(super) async fn current_policy_snapshot(
        &self,
        policy: &str,
        minimum_height: u64,
    ) -> RpcResult<PolicySnapshotResponse> {
        validate_policy_prefix(policy, &policy_snapshot_prefixes(policy)[0])
            .map_err(request_error)?;
        let policy = policy.to_owned();
        let (revision, proof, _permit) = self
            .capture_current(
                minimum_height,
                "current policy snapshot deadline exceeded",
                move |databases, root| {
                    let policy = policy.clone();
                    Box::pin(async move {
                        vera_backend::native::policy_snapshot_at(databases, root, &policy).await
                    })
                },
            )
            .await?;
        let response = PolicySnapshotResponse { revision, proof };
        encoded_size(&response, POLICY_SNAPSHOT_RESPONSE_BYTES - 1024).map_err(request_error)?;
        Ok(response)
    }
}
