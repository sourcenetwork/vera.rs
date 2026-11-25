//! Reporting and reading the forks an anchoring deployment recorded.

use alloy_primitives::{B256, Bytes};
use alloy_sol_types::SolCall as _;
use vera_domain::{AncestryProof, ConsensusPublicKey, LightBlock, ModuleId};
use vera_modules::vera::anchors::{
    AnchorError, ForkRecord, MAX_ANCHOR_ARTIFACT_BYTES, abi::IAnchor, fork_block_of_key, fork_key,
    fork_prefix,
};
use vera_permission::{MAX_PAGE_RECORDS, PAGE_PROOF_BYTES, PrefixPageRequest};

use super::AnchoringError;
use crate::{BlsSigner, ClientError, VeraClient, client::ANCHOR_ADDRESS};

/// Encode the fork report of `revision`, a revision of the deployment whose
/// consensus key is `key`. `ancestor` is the revision's ancestor at the height
/// of the tip of the deployment's anchors, shown by `proof`; a revision at that
/// height is its own ancestor and needs no proof.
pub fn encode_fork_report(
    revision: &LightBlock,
    key: &ConsensusPublicKey,
    ancestor: B256,
    proof: Option<&AncestryProof>,
) -> Result<Bytes, ClientError> {
    let artifacts = revision.artifacts()?;
    if artifacts.encoded_len() > MAX_ANCHOR_ARTIFACT_BYTES {
        return Err(AnchoringError::TooLarge.into());
    }
    Ok(IAnchor::reportForkCall {
        deployment: super::deployment_id(key),
        block: artifacts.block.into(),
        descendants: artifacts.descendants.into_iter().map(Into::into).collect(),
        finalization: artifacts.finalization.into(),
        epochMaterial: artifacts.epoch_material.into(),
        ancestor: ancestor.0.into(),
        ancestryProof: proof.map(AncestryProof::encode).unwrap_or_default().into(),
    }
    .abi_encode()
    .into())
}

impl VeraClient {
    /// On a device of the deployment with consensus key `own_key` (this
    /// client), report its revision at `height` to `anchoring` as a fork of
    /// `tip`, the tip of the deployment's anchors there
    /// ([`super::Lineage::tip`]). Returns the submission identifier;
    /// [`Self::await_anchor`] waits for its receipt.
    ///
    /// The report is refused unless this device's history differs from the
    /// anchored one at the tip's height.
    pub async fn report_fork(
        &self,
        anchoring: &Self,
        submitter: &BlsSigner,
        height: u64,
        own_key: &ConsensusPublicKey,
        tip: (u64, B256),
    ) -> Result<B256, ClientError> {
        let revision = self.read_finalized_revision(height, own_key).await?;
        let (ancestor, proof) = if height > tip.0 {
            let ancestor = self
                .read_finalized_revision(tip.0, own_key)
                .await?
                .block_hash
                .parse()
                .map_err(|_| ClientError::InvalidResponse("block hash"))?;
            let proof = self.ancestry_proof(tip.0, height).await?;
            (ancestor, Some(proof))
        } else {
            let own = revision
                .block_hash
                .parse()
                .map_err(|_| ClientError::InvalidResponse("block hash"))?;
            (own, None)
        };
        let call = encode_fork_report(&revision, own_key, ancestor, proof.as_ref())?;
        anchoring
            .submit_native(submitter, ANCHOR_ADDRESS, call)
            .await
    }

    /// Read up to `limit` forks of `deployment` this deployment recorded,
    /// ordered by the conflicting block's identifier and starting at `from`
    /// ([`B256::ZERO`] for the first page), verified against its `trusted` key
    /// at a revision of at least `minimum_height`.
    ///
    /// The page's proof shows no fork between its entries. A later page is
    /// read at a later revision, so pass the returned `revision` as its
    /// minimum. A fork recorded between two pages appears in a later one only
    /// when its identifier sorts after the page that was read.
    pub async fn read_forks(
        &self,
        deployment: &B256,
        from: B256,
        limit: u16,
        minimum_height: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<ForkPage, ClientError> {
        let request = PrefixPageRequest {
            module: ModuleId::Vera,
            start: fork_key(deployment, &from).into(),
            prefix: fork_prefix(deployment).into(),
            limit: limit.clamp(1, MAX_PAGE_RECORDS),
        };
        let (response, page) = self
            .verified_prefix_page(&request, minimum_height, trusted, PAGE_PROOF_BYTES)
            .await?;
        let entries = page
            .entries
            .iter()
            .map(|entry| {
                let record = ForkRecord::decode(deployment, &entry.value)?;
                if fork_key(deployment, &record.block_hash) != entry.key {
                    return Err(AnchorError::MalformedRecord);
                }
                Ok(record)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(AnchoringError::from)?;
        let next = page
            .continuation
            .map(|key| {
                fork_block_of_key(deployment, &key)
                    .ok_or(ClientError::InvalidResponse("fork continuation"))
            })
            .transpose()?;
        Ok(ForkPage {
            entries,
            next,
            revision: response.revision.height,
        })
    }
}

/// Forks of one deployment, proven at one finalized revision of the
/// deployment that recorded them.
#[derive(Clone, Debug)]
pub struct ForkPage {
    /// The forks, ordered by the conflicting block's identifier.
    pub entries: Vec<ForkRecord>,
    /// Identifier the next page starts at, or `None` when the deployment had
    /// no later fork at `revision`.
    pub next: Option<B256>,
    /// Height of the revision the page was read at.
    pub revision: u64,
}
