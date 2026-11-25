use vera_domain::{ConsensusPublicKey, ModuleId};
use vera_permission::{
    PermissionError, RECORD_PROOF_BYTES, RecordResponse, current::MAX_KEY_BYTES,
};

use crate::{ClientError, VeraClient};

impl VeraClient {
    /// Read a native record with verified finality, request binding and a minimum revision.
    /// The caller provides the trusted consensus key and any timestamp/age requirements.
    pub async fn read_current_record(
        &self,
        module: ModuleId,
        key: &[u8],
        minimum_height: u64,
        trusted: &ConsensusPublicKey,
        maximum_bytes: usize,
    ) -> Result<RecordResponse, ClientError> {
        if key.len() > MAX_KEY_BYTES {
            return Err(PermissionError::Limit.into());
        }
        let maximum_bytes = maximum_bytes.min(RECORD_PROOF_BYTES);
        let response: RecordResponse = self
            .rpc_call_bounded(
                "vera_getCurrentRecordProof",
                serde_json::json!([
                    module,
                    alloy_primitives::Bytes::copy_from_slice(key),
                    minimum_height
                ]),
                vera_domain::LIGHT_BLOCK_RESPONSE_BYTES + maximum_bytes + 1024,
            )
            .await?;
        response.verify(
            module,
            key,
            minimum_height,
            &self.established(trusted),
            maximum_bytes,
        )?;
        Ok(response)
    }
}

impl VeraClient {
    /// Read a complete native prefix at a finalized revision with bounded evidence.
    /// The caller supplies consensus trust and any additional freshness requirements.
    pub async fn read_current_prefix(
        &self,
        module: ModuleId,
        prefix: &[u8],
        minimum_height: u64,
        trusted: &ConsensusPublicKey,
        maximum_bytes: usize,
    ) -> Result<vera_permission::PrefixResponse, ClientError> {
        if prefix.len() > MAX_KEY_BYTES {
            return Err(PermissionError::Limit.into());
        }
        let maximum_bytes = maximum_bytes.min(RECORD_PROOF_BYTES);
        let response: vera_permission::PrefixResponse = self
            .rpc_call_bounded(
                "vera_getCurrentPrefixProof",
                serde_json::json!([
                    module,
                    alloy_primitives::Bytes::copy_from_slice(prefix),
                    minimum_height
                ]),
                vera_domain::LIGHT_BLOCK_RESPONSE_BYTES + maximum_bytes + 1024,
            )
            .await?;
        response.verify(
            module,
            prefix,
            minimum_height,
            &self.established(trusted),
            maximum_bytes,
        )?;
        Ok(response)
    }
}

impl VeraClient {
    /// Read one certified page. A continuation selects a lower bound, not a historical snapshot.
    pub async fn read_current_prefix_page(
        &self,
        request: &vera_permission::PrefixPageRequest,
        minimum_height: u64,
        trusted: &ConsensusPublicKey,
        maximum_bytes: usize,
    ) -> Result<vera_permission::PrefixPageResponse, ClientError> {
        let (response, _) = self
            .verified_prefix_page(request, minimum_height, trusted, maximum_bytes)
            .await?;
        Ok(response)
    }

    /// Fetch one page and keep the entries its single verification produced.
    pub(crate) async fn verified_prefix_page(
        &self,
        request: &vera_permission::PrefixPageRequest,
        minimum_height: u64,
        trusted: &ConsensusPublicKey,
        maximum_bytes: usize,
    ) -> Result<
        (
            vera_permission::PrefixPageResponse,
            vera_permission::VerifiedPrefixPage,
        ),
        ClientError,
    > {
        request.validate()?;
        let maximum_bytes = maximum_bytes.min(vera_permission::PAGE_PROOF_BYTES);
        let response: vera_permission::PrefixPageResponse = self
            .rpc_call_bounded(
                "vera_getCurrentPrefixPageProof",
                serde_json::json!([request, minimum_height]),
                vera_domain::LIGHT_BLOCK_RESPONSE_BYTES + maximum_bytes + 1024,
            )
            .await?;
        let page = response.verify(
            request,
            minimum_height,
            &self.established(trusted),
            maximum_bytes,
        )?;
        Ok((response, page))
    }
}
