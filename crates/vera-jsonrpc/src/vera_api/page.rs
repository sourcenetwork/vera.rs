use jsonrpsee::core::RpcResult;
use vera_permission::{PAGE_RESPONSE_BYTES, PrefixPageRequest, PrefixPageResponse, encoded_size};

use super::{VeraApiImpl, permission::request_error};

impl VeraApiImpl {
    pub(super) async fn current_prefix_page_proof(
        &self,
        request: &PrefixPageRequest,
        minimum_height: u64,
    ) -> RpcResult<PrefixPageResponse> {
        request.validate().map_err(request_error)?;
        let request = request.clone();
        let (revision, page, _permit) = self
            .capture_current(
                minimum_height,
                "current page evidence deadline exceeded",
                move |databases, root| {
                    let request = request.clone();
                    Box::pin(async move {
                        vera_backend::native::prefix_page_at(databases, root, &request).await
                    })
                },
            )
            .await?;
        let response = PrefixPageResponse { revision, page };
        encoded_size(&response, PAGE_RESPONSE_BYTES - 1024).map_err(request_error)?;
        Ok(response)
    }
}
