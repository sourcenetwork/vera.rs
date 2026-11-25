//! Reading a deployment's anchors, in order, from the deployment that recorded them.

use alloy_primitives::B256;
use vera_domain::{ConsensusPublicKey, ModuleId};
use vera_modules::vera::anchors::{AnchorEntry, anchor_entry_key, anchor_history_prefix};
use vera_permission::{MAX_PAGE_RECORDS, PAGE_PROOF_BYTES, PrefixPageRequest};

use super::AnchoringError;
use crate::{ClientError, VeraClient};

/// Consecutive anchors of one deployment, proven at one finalized revision of
/// the deployment that recorded them.
#[derive(Clone, Debug)]
pub struct AnchorPage {
    /// The anchors, in sequence order.
    pub entries: Vec<AnchorEntry>,
    /// Sequence the next page starts at, or `None` when the deployment had no
    /// later anchor at `revision`.
    pub next: Option<u64>,
    /// Height of the revision the page was read at.
    pub revision: u64,
}

impl VeraClient {
    /// Read up to `limit` anchors of `deployment`, starting at the anchor
    /// numbered `from` (1 is the first), verified against this deployment's
    /// `trusted` key at a revision of at least `minimum_height`.
    ///
    /// The entries are consecutive: the page's proof shows no anchor between
    /// them. A later page is read at a later revision, so pass the returned
    /// `revision` as its minimum to keep the pages in order.
    pub async fn read_anchor_history(
        &self,
        deployment: &B256,
        from: u64,
        limit: u16,
        minimum_height: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<AnchorPage, ClientError> {
        let prefix = anchor_history_prefix(deployment);
        let request = PrefixPageRequest {
            module: ModuleId::Vera,
            start: anchor_entry_key(deployment, from.max(1)).into(),
            prefix: prefix.clone().into(),
            limit: limit.clamp(1, MAX_PAGE_RECORDS),
        };
        let (response, page) = self
            .verified_prefix_page(&request, minimum_height, trusted, PAGE_PROOF_BYTES)
            .await?;
        let entries = page
            .entries
            .iter()
            .map(|entry| AnchorEntry::decode(deployment, &entry.key, &entry.value))
            .collect::<Result<Vec<_>, _>>()
            .map_err(AnchoringError::from)?;
        let next = page
            .continuation
            .map(|key| {
                key.strip_prefix(prefix.as_slice())
                    .and_then(|sequence| std::str::from_utf8(sequence).ok())
                    .filter(|sequence| sequence.len() == 16)
                    .and_then(|sequence| u64::from_str_radix(sequence, 16).ok())
                    .ok_or(ClientError::InvalidResponse("anchor history continuation"))
            })
            .transpose()?;
        Ok(AnchorPage {
            entries,
            next,
            revision: response.revision.height,
        })
    }
}
