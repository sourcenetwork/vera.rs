use alloy_primitives::{B256, Bytes};
use commonware_codec::Decode as _;
use commonware_cryptography::sha256::Digest;
use serde::{Deserialize, Serialize};
use vera_domain::{
    ConsensusPublicKey, LIGHT_BLOCK_RESPONSE_BYTES, LightBlock, ModuleId, verify_light_block,
};

use crate::{
    PermissionError,
    current::{Entry, MAX_KEY_BYTES, PrefixEvidence},
    encoded_size,
};

/// Maximum records returned by one authenticated page.
pub const MAX_PAGE_RECORDS: u16 = 128;
/// Maximum encoded page proof, including boundary values and request binding.
pub const PAGE_PROOF_BYTES: usize = 8 << 20;
/// Maximum key/value bytes returned in one page.
pub const PAGE_DATA_BYTES: usize = 2 << 20;
/// Maximum page response including finalization artifacts.
pub const PAGE_RESPONSE_BYTES: usize = LIGHT_BLOCK_RESPONSE_BYTES + PAGE_PROOF_BYTES + 1024;

/// A page starts at an inclusive lower bound within an exact prefix.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixPageRequest {
    /// Native partition.
    pub module: ModuleId,
    /// Selection prefix.
    pub prefix: Bytes,
    /// Inclusive starting key; use the prefix for the first page.
    pub start: Bytes,
    /// Maximum number of entries, possibly reduced by the response byte budget.
    pub limit: u16,
}

impl PrefixPageRequest {
    /// Check selection and resource limits before reading storage.
    pub fn validate(&self) -> Result<(), PermissionError> {
        if self.prefix.len() > MAX_KEY_BYTES
            || self.start.len() > MAX_KEY_BYTES
            || self.limit == 0
            || self.limit > MAX_PAGE_RECORDS
        {
            return Err(PermissionError::Limit);
        }
        if !self.start.starts_with(&self.prefix) {
            return Err(PermissionError::Invalid("page start outside prefix"));
        }
        Ok(())
    }
}

/// Ordered entries and their authenticated continuation key.
#[derive(Clone, Debug)]
pub struct VerifiedPrefixPage {
    /// Entries at the captured revision.
    pub entries: Vec<Entry>,
    /// Inclusive start for another page, or no remaining entry in this prefix.
    pub continuation: Option<Bytes>,
}

/// Bounded prefix evidence at one native root.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrefixPageProof {
    /// Exact selection used to generate this evidence.
    pub request: PrefixPageRequest,
    /// Native roots in commitment order.
    pub roots: [B256; 4],
    /// Encoded boundary and consecutive membership proofs.
    pub proof: Bytes,
}

impl PrefixPageProof {
    /// Verify the exact request and uninterrupted coverage up to the continuation.
    pub fn verify(
        &self,
        root: B256,
        request: &PrefixPageRequest,
        maximum_bytes: usize,
    ) -> Result<VerifiedPrefixPage, PermissionError> {
        request.validate()?;
        encoded_size(self, maximum_bytes.min(PAGE_PROOF_BYTES))?;
        if self.request != *request {
            return Err(PermissionError::Invalid("page differs from request"));
        }
        if vera_modules::module_state::combine_module_roots(&self.roots.map(|r| r.0)) != root {
            return Err(PermissionError::Invalid("current-state roots"));
        }
        let evidence = PrefixEvidence::decode_cfg(
            commonware_codec::Copying(self.proof.as_ref()),
            &usize::from(request.limit),
        )
        .map_err(|_| PermissionError::Invalid("page encoding or record limit"))?;
        let mut remaining = PAGE_DATA_BYTES
            .checked_sub(request.prefix.len())
            .and_then(|n| n.checked_sub(request.start.len()))
            .ok_or(PermissionError::Limit)?;
        for entry in &evidence.entries {
            remaining = remaining
                .checked_sub(entry.key.len())
                .and_then(|n| n.checked_sub(entry.value.len()))
                .ok_or(PermissionError::Limit)?;
        }
        let next = evidence.verify_page(
            &request.prefix,
            &request.start,
            &Digest::from(self.roots[request.module.index()].0),
        )?;
        Ok(VerifiedPrefixPage {
            entries: evidence.entries,
            continuation: next.map(Bytes::from),
        })
    }
}

/// One independently certified page; later pages may select newer revisions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrefixPageResponse {
    /// Captured revision and finalization artifacts.
    pub revision: LightBlock,
    /// Page at the captured revision.
    pub page: PrefixPageProof,
}

impl PrefixPageResponse {
    /// Authenticate the page and enforce caller-provided freshness and trust.
    pub fn verify(
        &self,
        request: &PrefixPageRequest,
        minimum_height: u64,
        trusted: &ConsensusPublicKey,
        maximum_bytes: usize,
    ) -> Result<VerifiedPrefixPage, PermissionError> {
        request.validate()?;
        encoded_size(&self.revision, LIGHT_BLOCK_RESPONSE_BYTES)?;
        let (_, root) = verify_light_block(&self.revision, trusted)?;
        if self.revision.height < minimum_height {
            return Err(PermissionError::Invalid(
                "revision precedes required minimum",
            ));
        }
        self.page.verify(root, request, maximum_bytes)
    }
}
