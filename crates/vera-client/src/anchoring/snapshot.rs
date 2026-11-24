//! A relayable policy snapshot and its verification against an anchor.

use alloy_primitives::{B256, keccak256};
use serde::{Deserialize, Serialize};
use vera_domain::{ConsensusPublicKey, LightBlock, ModuleId, verify_finalized_block};
use vera_modules::vera::anchors::{
    AnchorRecord, MAX_ANCHOR_ARTIFACT_BYTES, TermRecord, anchor_key,
};
use vera_permission::{
    AccessRequest, POLICY_SNAPSHOT_RESPONSE_BYTES, PolicySnapshotProof, PolicyState,
    RECORD_PROOF_BYTES, RECORD_RESPONSE_BYTES, RecordResponse, encoded_size,
};

use super::AnchoringError;

/// Largest serialized snapshot: the policy evidence with its revision, and the anchor evidence.
pub const ANCHORED_SNAPSHOT_BYTES: usize = POLICY_SNAPSHOT_RESPONSE_BYTES + RECORD_RESPONSE_BYTES;

/// One policy of a deployment at an anchored revision, with everything needed
/// to verify it against the anchoring deployment's consensus key alone.
///
/// Anyone may hold and relay it; it carries no secret.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchoredSnapshot {
    /// The policy's identifier.
    pub policy: String,
    /// The deployment's revision the policy was captured at.
    pub revision: LightBlock,
    /// The policy's records at that revision.
    pub proof: PolicySnapshotProof,
    /// The anchoring deployment's record of the deployment's latest anchor,
    /// proven at one of its finalized revisions.
    pub anchor: RecordResponse,
}

/// A snapshot that verified, with the anchor it verified against.
#[derive(Clone, Debug)]
pub struct VerifiedSnapshot {
    /// The anchor the snapshot's revision is recorded by.
    pub anchor: AnchorRecord,
    /// Height of the anchoring deployment's revision the anchor was read at.
    pub anchor_revision: u64,
    /// Timestamp of that revision.
    pub anchor_timestamp: u64,
    /// The policy's state at the anchored revision.
    pub state: PolicyState,
}

impl AnchoredSnapshot {
    /// Decode a relayed snapshot, refusing one above [`ANCHORED_SNAPSHOT_BYTES`].
    pub fn decode(bytes: &[u8]) -> Result<Self, AnchoringError> {
        if bytes.len() > ANCHORED_SNAPSHOT_BYTES {
            return Err(AnchoringError::TooLarge);
        }
        serde_json::from_slice(bytes)
            .map_err(|_| vera_permission::PermissionError::Invalid("snapshot encoding").into())
    }

    /// Serialize the snapshot for relaying.
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("snapshots serialize")
    }

    /// Verify the snapshot of `policy` of `deployment` with trust in the anchoring
    /// deployment's consensus key only.
    ///
    /// The anchor evidence must verify against `anchoring` at a revision of at
    /// least `minimum_anchor_revision`, the anchor must name the snapshot's
    /// revision, the revision must be finalized under the key the anchor
    /// records, and the policy's records must match the anchored module root.
    /// The result says which anchor it is; [`VerifiedSnapshot::ensure_current`]
    /// compares it with a later one.
    pub fn verify(
        &self,
        deployment: &B256,
        policy: &str,
        anchoring: &ConsensusPublicKey,
        minimum_anchor_revision: u64,
    ) -> Result<VerifiedSnapshot, AnchoringError> {
        encoded_size(self, ANCHORED_SNAPSHOT_BYTES)?;
        if self.policy != policy {
            return Err(
                vera_permission::PermissionError::Invalid("snapshot of another policy").into(),
            );
        }
        let key = anchor_key(deployment);
        self.anchor.verify(
            ModuleId::Vera,
            &key,
            minimum_anchor_revision,
            anchoring,
            RECORD_PROOF_BYTES,
        )?;
        let value = self
            .anchor
            .record
            .value
            .as_ref()
            .ok_or(AnchoringError::NoAnchor)?;
        let anchor = AnchorRecord::decode(deployment, value)?;

        let artifacts = self.revision.artifacts()?;
        if artifacts.encoded_len() > MAX_ANCHOR_ARTIFACT_BYTES {
            return Err(AnchoringError::TooLarge);
        }
        let block = verify_finalized_block(&self.revision, &super::anchored_key(&anchor)?)?;
        if block.height != anchor.height
            || keccak256(&artifacts.block) != anchor.block_hash
            || block.module_state_root != anchor.module_state_root
        {
            return Err(AnchoringError::NotAnchored {
                revision: block.height,
                anchored: anchor.height,
            });
        }
        let state = self.proof.verify(anchor.module_state_root, policy)?;
        Ok(VerifiedSnapshot {
            anchor,
            anchor_revision: self.anchor.revision.height,
            anchor_timestamp: self.anchor.revision.timestamp,
            state,
        })
    }
}

impl VerifiedSnapshot {
    /// Refuse the snapshot when `latest`, an anchor of the same deployment the
    /// caller verified separately, is newer than the snapshot's anchor.
    /// [`Self::ensure_kept`] tells whether a device switch voided it.
    pub fn ensure_current(&self, latest: &AnchorRecord) -> Result<(), AnchoringError> {
        ensure_not_superseded(&self.anchor, latest)
    }

    /// Refuse the snapshot when one of `terms`, the terms of the same
    /// deployment the caller read separately, voided the snapshot's anchor: it
    /// was recorded before the term, above the term's cut.
    pub fn ensure_kept(&self, terms: &[TermRecord]) -> Result<(), AnchoringError> {
        ensure_kept(&self.anchor, terms)
    }

    /// Whether the request's actor holds every requested permission at the anchored revision.
    pub fn check(&self, request: &AccessRequest) -> Result<bool, AnchoringError> {
        Ok(self.state.check(request)?)
    }
}

pub(super) fn ensure_kept(held: &AnchorRecord, terms: &[TermRecord]) -> Result<(), AnchoringError> {
    for term in terms {
        if term.deployment != held.deployment {
            return Err(vera_modules::vera::anchors::AnchorError::MalformedRecord.into());
        }
        if term.supersedes(held.sequence, held.height, &held.block_hash) {
            return Err(AnchoringError::Superseded {
                held: held.sequence,
                term: term.term,
            });
        }
    }
    Ok(())
}

pub(super) fn ensure_not_superseded(
    held: &AnchorRecord,
    latest: &AnchorRecord,
) -> Result<(), AnchoringError> {
    if latest.deployment != held.deployment {
        return Err(vera_modules::vera::anchors::AnchorError::MalformedRecord.into());
    }
    if latest.sequence > held.sequence {
        return Err(AnchoringError::Stale {
            held: held.sequence,
            latest: latest.sequence,
        });
    }
    if latest.sequence == held.sequence && latest.block_hash != held.block_hash {
        return Err(AnchoringError::Conflict(latest.sequence));
    }
    Ok(())
}
