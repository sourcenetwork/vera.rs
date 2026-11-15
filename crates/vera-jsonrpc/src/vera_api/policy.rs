use jsonrpsee::core::RpcResult;
use vera_domain::ModuleId;
use vera_permission::{
    PAGE_RESPONSE_BYTES, PermissionError, PolicyPrefixPageResponse, PolicyPrefixResponse,
    PrefixPageRequest, RECORD_RESPONSE_BYTES, encoded_size, validate_policy_prefix,
};

use super::{VeraApiImpl, permission::request_error};

const DEADLINE: &str = "current policy evidence deadline exceeded";

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
            .capture_current(minimum_height, DEADLINE, move |databases, root| {
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
            .capture_current(minimum_height, DEADLINE, move |databases, root| {
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
}

#[cfg(test)]
mod tests;
