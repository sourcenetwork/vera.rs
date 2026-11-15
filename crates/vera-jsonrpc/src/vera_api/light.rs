//! Light-block assembly from the finalization cache or durable history.

use commonware_cryptography::Hasher as _;
use jsonrpsee::{core::RpcResult, types::ErrorObjectOwned};
use vera_domain::LightBlock;

use super::VeraApiImpl;
use crate::error::RpcError;

impl VeraApiImpl {
    /// Assemble a light block without admission; callers hold their own permit.
    pub(super) async fn light_block(&self, height: u64) -> RpcResult<LightBlock> {
        self.certified_light_block(height)
            .await?
            .ok_or_else(|| certificate_not_found(height))
    }

    /// As [`Self::light_block`], with `None` while the revision has no certificate yet.
    pub(super) async fn certified_light_block(&self, height: u64) -> RpcResult<Option<LightBlock>> {
        match self.cached_light_block(height)? {
            Some(light) => Ok(Some(light)),
            None => self.archived_light_block(height).await,
        }
    }

    /// Decode, hash and hex-encode the cached block: synchronous work proportional to its size.
    pub(super) fn cached_light_block(&self, height: u64) -> RpcResult<Option<LightBlock>> {
        let Some(light_index) = &self.light_block_index else {
            return Ok(None);
        };
        let finalization = self
            .index
            .as_ref()
            .and_then(|index| index.get_block_by_number(height))
            .and_then(|block| {
                let digest = commonware_cryptography::Sha256::hash(&[block.hash.as_slice()]).0;
                light_index.get_finalization(&digest)
            });
        let Some(finalization) = finalization else {
            return Ok(None);
        };
        let Some(material) = light_index.get_epoch_material(finalization.epoch) else {
            return Ok(None);
        };
        LightBlock::from_encoded_block(&finalization.block, &finalization.bytes, &material.bytes)
            .map(Some)
            .map_err(|error| {
                RpcError::Internal(format!("light block assembly failed: {error}")).into()
            })
    }

    pub(super) async fn archived_light_block(&self, height: u64) -> RpcResult<Option<LightBlock>> {
        let Some(lookup) = self.light_block_lookup.clone() else {
            return Ok(None);
        };
        let permit = self.state.light_lookup_permit()?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            lookup(height)
        })
        .await
        .map_err(|error| RpcError::Internal(format!("light block lookup failed: {error}")))?
        .map_err(|error| RpcError::Internal(error).into())
    }
}

/// Clients match this text to tell pending finality from a failed lookup.
pub(super) fn certificate_not_found(height: u64) -> ErrorObjectOwned {
    RpcError::Internal(format!(
        "finalization certificate not found for height {height} within retained proof limits"
    ))
    .into()
}
