use alloy_primitives::{B256, Bytes};
use commonware_codec::Decode as _;
use commonware_cryptography::sha256::Digest;
use serde::{Deserialize, Serialize};
use vera_domain::{FinalityTrust, LIGHT_BLOCK_RESPONSE_BYTES, LightBlock, ModuleId};

use crate::{
    PERMISSION_LIMITS, PermissionError, RECORD_PROOF_BYTES,
    current::{MAX_KEY_BYTES, PrefixEvidence},
    encoded_size,
};

/// Complete native prefix evidence, including the boundary and authenticated successors.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrefixProof {
    /// Partition containing the requested records.
    pub module: ModuleId,
    /// Exact raw prefix.
    pub prefix: Bytes,
    /// ACP, bulletin, vera and native sequence roots in commitment order.
    pub roots: [B256; 4],
    /// Canonical Commonware complete-prefix evidence.
    pub proof: Bytes,
}

impl PrefixProof {
    /// Verify complete coverage at an independently authenticated root.
    /// Transport must bound the response before deserializing it.
    pub fn verify(
        &self,
        root: B256,
        module: ModuleId,
        prefix: &[u8],
        maximum_bytes: usize,
    ) -> Result<PrefixEvidence, PermissionError> {
        if prefix.len() > MAX_KEY_BYTES {
            return Err(PermissionError::Limit);
        }
        encoded_size(self, maximum_bytes.min(RECORD_PROOF_BYTES))?;
        if self.module != module || self.prefix.as_ref() != prefix {
            return Err(PermissionError::Invalid("prefix differs from request"));
        }
        if vera_modules::module_state::combine_module_roots(&self.roots.map(|r| r.0)) != root {
            return Err(PermissionError::Invalid("current-state roots"));
        }
        let evidence = PrefixEvidence::decode_cfg(
            commonware_codec::Copying(self.proof.as_ref()),
            &PERMISSION_LIMITS.reads.records,
        )
        .map_err(|_| PermissionError::Invalid("prefix encoding or record limit"))?;
        let mut remaining = PERMISSION_LIMITS
            .reads
            .bytes
            .checked_sub(prefix.len())
            .ok_or(PermissionError::Limit)?;
        for entry in &evidence.entries {
            remaining = remaining
                .checked_sub(entry.key.len())
                .and_then(|n| n.checked_sub(entry.value.len()))
                .ok_or(PermissionError::Limit)?;
        }
        evidence.verify(prefix, &Digest::from(self.roots[module.index()].0))?;
        Ok(evidence)
    }
}

/// Complete prefix evidence paired with its captured finalized revision.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrefixResponse {
    /// Canonical revision and independently verifiable finalization artifacts.
    pub revision: LightBlock,
    /// Complete prefix at this revision.
    pub prefix: PrefixProof,
}

impl PrefixResponse {
    /// Authenticate the prefix and enforce the caller's minimum revision.
    /// The caller supplies consensus trust and any additional freshness policy.
    pub fn verify(
        &self,
        module: ModuleId,
        prefix: &[u8],
        minimum_height: u64,
        trusted: &impl FinalityTrust,
        maximum_bytes: usize,
    ) -> Result<PrefixEvidence, PermissionError> {
        encoded_size(&self.revision, LIGHT_BLOCK_RESPONSE_BYTES)?;
        let root = trusted.finalized_block(&self.revision)?.module_state_root;
        if self.revision.height < minimum_height {
            return Err(PermissionError::Invalid(
                "revision precedes required minimum",
            ));
        }
        self.prefix.verify(root, module, prefix, maximum_bytes)
    }
}
