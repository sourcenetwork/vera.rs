use jsonrpsee::core::RpcResult;
use vera_domain::ModuleId;
use vera_permission::{
    PermissionError, PrefixResponse, RECORD_RESPONSE_BYTES, current::MAX_KEY_BYTES, encoded_size,
};

use super::{VeraApiImpl, permission::request_error};

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
        let prefix = prefix.to_vec();
        let (revision, prefix, _permit) = self
            .capture_current(
                minimum_height,
                "current prefix evidence deadline exceeded",
                move |databases, root| {
                    let prefix = prefix.clone();
                    Box::pin(async move {
                        vera_backend::native::prefix_proof_at(databases, root, module, &prefix)
                            .await
                    })
                },
            )
            .await?;
        let response = PrefixResponse { revision, prefix };
        encoded_size(&response, RECORD_RESPONSE_BYTES - 1024).map_err(request_error)?;
        Ok(response)
    }
}
