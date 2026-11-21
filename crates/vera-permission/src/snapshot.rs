//! The complete state of one policy at one finalized revision.

use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use vera_domain::{FinalityTrust, LIGHT_BLOCK_RESPONSE_BYTES, LightBlock};
use vera_modules::acp::{keys, object_state, relationship_index};

use crate::{
    ModuleId, PERMISSION_LIMITS, PermissionError, PrefixProof, RECORD_PROOF_BYTES,
    RECORD_RESPONSE_BYTES, RecordProof, encoded_size,
    policy::{validate_policy_prefix, verify_policy},
    snapshot_state::PolicyState,
};

/// Transport budget of a policy snapshot response.
pub const POLICY_SNAPSHOT_RESPONSE_BYTES: usize = RECORD_RESPONSE_BYTES;

/// The ACP prefixes holding every record the evaluator reads for `policy`:
/// relationships, relationship indexes and object incarnations.
#[must_use]
pub fn policy_snapshot_prefixes(policy: &str) -> [Vec<u8>; 3] {
    [
        keys::relationship_policy_prefix(policy),
        relationship_index::policy_prefix(policy),
        object_state::policy_prefix(policy),
    ]
}

/// The policy record and the complete contents of its three prefixes, at one root.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySnapshotProof {
    /// The policy record or its certified absence.
    pub policy: RecordProof,
    /// Complete prefixes in [`policy_snapshot_prefixes`] order.
    pub prefixes: [PrefixProof; 3],
}

impl PolicySnapshotProof {
    /// Authenticate every record against `root` and return the policy's state.
    pub fn verify(&self, root: B256, policy: &str) -> Result<PolicyState, PermissionError> {
        let expected = policy_snapshot_prefixes(policy);
        validate_policy_prefix(policy, &expected[0])?;
        encoded_size(self, RECORD_PROOF_BYTES)?;
        if self
            .prefixes
            .iter()
            .any(|prefix| prefix.roots != self.policy.roots)
        {
            return Err(PermissionError::Invalid(
                "policy snapshot proofs have different roots",
            ));
        }
        let record = verify_policy(&self.policy, root, policy, RECORD_PROOF_BYTES)?;
        let mut records = PERMISSION_LIMITS.reads.records;
        let mut bytes = PERMISSION_LIMITS.reads.bytes;
        let mut prefixes = Vec::with_capacity(expected.len());
        for (proof, prefix) in self.prefixes.iter().zip(expected) {
            let evidence = proof.verify(root, ModuleId::Acp, &prefix, RECORD_PROOF_BYTES)?;
            let mut entries = std::collections::BTreeMap::new();
            for entry in evidence.entries {
                records = records.checked_sub(1).ok_or(PermissionError::Limit)?;
                bytes = bytes
                    .checked_sub(entry.key.len() + entry.value.len())
                    .ok_or(PermissionError::Limit)?;
                entries.insert(entry.key, entry.value.to_vec());
            }
            prefixes.push((prefix, entries));
        }
        Ok(PolicyState::new(
            policy.to_owned(),
            self.policy.value.as_ref().map(|value| value.to_vec()),
            record.is_some(),
            prefixes,
        ))
    }
}

/// A policy snapshot paired with the finalized revision it was captured at.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySnapshotResponse {
    /// Canonical revision and its finality artifacts.
    pub revision: LightBlock,
    /// The policy's records at that revision.
    pub proof: PolicySnapshotProof,
}

impl PolicySnapshotResponse {
    /// Authenticate the snapshot against a trusted consensus key and minimum revision.
    pub fn verify(
        &self,
        policy: &str,
        minimum_height: u64,
        trusted: &impl FinalityTrust,
    ) -> Result<PolicyState, PermissionError> {
        encoded_size(&self.revision, LIGHT_BLOCK_RESPONSE_BYTES)?;
        let root = trusted.finalized_block(&self.revision)?.module_state_root;
        if self.revision.height < minimum_height {
            return Err(PermissionError::Invalid(
                "revision precedes required minimum",
            ));
        }
        self.proof.verify(root, policy)
    }
}
