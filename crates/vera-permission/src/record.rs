use alloy_primitives::{B256, Bytes};
use commonware_cryptography::sha256::Digest;
use serde::{Deserialize, Serialize};
use vera_domain::{FinalityTrust, LIGHT_BLOCK_RESPONSE_BYTES, LightBlock, ModuleId};

use crate::{PermissionError, current::verify_point, encoded_size};

/// Serialized record evidence budget, including hex-encoded values and paths.
pub const RECORD_PROOF_BYTES: usize = 4 << 20;
/// Transport budget including finalization artifacts and the RPC envelope.
pub const RECORD_RESPONSE_BYTES: usize = LIGHT_BLOCK_RESPONSE_BYTES + RECORD_PROOF_BYTES + 1024;

/// Membership or absence of one record in native current storage.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecordProof {
    /// Namespace whose partition authenticates this record.
    pub module: ModuleId,
    /// Exact raw record key.
    pub key: Bytes,
    /// Present values use membership evidence; absent values use exclusion evidence.
    pub value: Option<Bytes>,
    /// ACP, bulletin, vera and native sequence roots in commitment order.
    pub roots: [B256; 4],
    /// Canonical Commonware membership or exclusion proof bytes.
    pub proof: Bytes,
}

impl RecordProof {
    /// Bind the requested module and key to an independently authenticated root.
    /// Transport must bound the response before deserializing it.
    pub fn verify(
        &self,
        root: B256,
        module: ModuleId,
        key: &[u8],
        maximum_bytes: usize,
    ) -> Result<(), PermissionError> {
        encoded_size(self, maximum_bytes.min(RECORD_PROOF_BYTES))?;
        if self.module != module || self.key.as_ref() != key {
            return Err(PermissionError::Invalid("record differs from request"));
        }
        if vera_modules::module_state::combine_module_roots(&self.roots.map(|r| r.0)) != root {
            return Err(PermissionError::Invalid("current-state roots"));
        }
        verify_point(
            &Digest::from(self.roots[module.index()].0),
            key,
            self.value.as_ref().map(|v| &v.0),
            &self.proof,
        )
    }
}

/// Record evidence paired with the finalized revision captured with it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecordResponse {
    /// Independently verifiable canonical revision and finalization artifacts.
    pub revision: LightBlock,
    /// Record membership or absence at this revision.
    pub record: RecordProof,
}

impl RecordResponse {
    /// Authenticate a record and enforce the caller's minimum revision.
    /// The caller supplies the trusted key and any additional freshness policy.
    pub fn verify(
        &self,
        module: ModuleId,
        key: &[u8],
        minimum_height: u64,
        trusted: &impl FinalityTrust,
        maximum_bytes: usize,
    ) -> Result<(), PermissionError> {
        encoded_size(&self.revision, LIGHT_BLOCK_RESPONSE_BYTES)?;
        let root = trusted.finalized_block(&self.revision)?.module_state_root;
        if self.revision.height < minimum_height {
            return Err(PermissionError::Invalid(
                "revision precedes required minimum",
            ));
        }
        self.record.verify(root, module, key, maximum_bytes)
    }
}
