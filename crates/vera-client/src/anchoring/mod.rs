//! Anchoring a deployment's revisions in another deployment, and policy snapshots
//! verified against those anchors. See `docs/anchoring.md`.

mod error;
mod key;
mod snapshot;
#[cfg(test)]
mod tests;

use std::time::Duration;

use alloy_primitives::{B256, Bytes};
use alloy_sol_types::SolCall as _;
use commonware_codec::Encode as _;
use vera_domain::{ConsensusPublicKey, LightBlock, ModuleId};
pub use vera_modules::vera::anchors::AnchorRecord;
use vera_modules::vera::anchors::{MAX_ANCHOR_ARTIFACT_BYTES, abi::IAnchor, anchor_key};
use vera_permission::{
    POLICY_SNAPSHOT_RESPONSE_BYTES, PolicySnapshotResponse, RECORD_PROOF_BYTES, RecordResponse,
};

pub use error::AnchoringError;
pub use key::{anchored_key, deployment_id};
pub use snapshot::{ANCHORED_SNAPSHOT_BYTES, AnchoredSnapshot, VerifiedSnapshot};

use crate::{BlsSigner, ClientError, VeraClient, client::ANCHOR_ADDRESS};

/// A deployment's latest anchor as read from the anchoring deployment, with its evidence.
#[derive(Clone, Debug)]
pub struct AnchorRead {
    /// The latest anchor, or `None` when the deployment has none.
    pub record: Option<AnchorRecord>,
    /// The record or its absence, proven at a finalized revision of the anchoring deployment.
    pub evidence: RecordResponse,
}

/// Encode the anchor call for `revision` of the deployment whose consensus key is `key`.
pub fn encode_anchor(
    revision: &LightBlock,
    key: &ConsensusPublicKey,
) -> Result<Bytes, ClientError> {
    let artifacts = revision.artifacts()?;
    if artifacts.encoded_len() > MAX_ANCHOR_ARTIFACT_BYTES {
        return Err(AnchoringError::TooLarge.into());
    }
    Ok(IAnchor::anchorRevisionCall {
        consensusKey: key.encode().to_vec().into(),
        block: artifacts.block.into(),
        descendants: artifacts.descendants.into_iter().map(Into::into).collect(),
        finalization: artifacts.finalization.into(),
        epochMaterial: artifacts.epoch_material.into(),
    }
    .abi_encode()
    .into())
}

impl VeraClient {
    /// Capture `policy` and all its relationship, index and object records at
    /// the current finalized revision, verified against this deployment's `trusted` key.
    pub async fn capture_policy_snapshot(
        &self,
        policy: &str,
        minimum_height: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<PolicySnapshotResponse, ClientError> {
        let response: PolicySnapshotResponse = self
            .rpc_call_bounded(
                "vera_getCurrentPolicySnapshot",
                serde_json::json!([policy, minimum_height]),
                POLICY_SNAPSHOT_RESPONSE_BYTES,
            )
            .await?;
        response.verify(policy, minimum_height, &self.established(trusted))?;
        Ok(response)
    }

    /// Submit an anchor of `revision`, a revision of the deployment with consensus
    /// key `key`, to this deployment. Returns the submission identifier.
    pub async fn submit_anchor(
        &self,
        submitter: &BlsSigner,
        revision: &LightBlock,
        key: &ConsensusPublicKey,
    ) -> Result<B256, ClientError> {
        self.submit_native(submitter, ANCHOR_ADDRESS, encode_anchor(revision, key)?)
            .await
    }

    /// Wait up to `timeout` for the certified receipt of an anchor submission.
    /// Returns the height of the revision that recorded it.
    pub async fn await_anchor(
        &self,
        submission: B256,
        trusted: &ConsensusPublicKey,
        timeout: Duration,
    ) -> Result<u64, ClientError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match self.read_receipt(submission, trusted).await {
                Ok(Some(response)) => {
                    let receipt = response.verify(submission, trusted)?;
                    if let Some(refusal) = &receipt.refusal {
                        return Err(AnchoringError::Refused(refusal.clone()).into());
                    }
                    return Ok(response.revision.height);
                }
                Ok(None) => {}
                Err(error) if error.is_throttled() => {}
                Err(error) => return Err(error),
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(AnchoringError::Unconfirmed.into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Read the latest anchor of `deployment` from this deployment, verified
    /// against its `trusted` key at a revision of at least `minimum_height`.
    pub async fn read_latest_anchor(
        &self,
        deployment: &B256,
        minimum_height: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<AnchorRead, ClientError> {
        let evidence = self
            .read_current_record(
                ModuleId::Vera,
                &anchor_key(deployment),
                minimum_height,
                trusted,
                RECORD_PROOF_BYTES,
            )
            .await?;
        let record = evidence
            .record
            .value
            .as_ref()
            .map(|value| AnchorRecord::decode(deployment, value))
            .transpose()
            .map_err(AnchoringError::from)?;
        Ok(AnchorRead { record, evidence })
    }

    /// On the deployment that owns `policy` (this client), capture the policy at
    /// the current revision, anchor that revision in `anchoring`, and return the
    /// relayable snapshot with the anchor's evidence.
    ///
    /// Fails with [`AnchoringError::Refused`] when another anchor at or above the
    /// revision landed first; capturing again then anchors a newer revision.
    pub async fn publish_policy_snapshot(
        &self,
        anchoring: &Self,
        submitter: &BlsSigner,
        policy: &str,
        own_key: &ConsensusPublicKey,
        anchoring_key: &ConsensusPublicKey,
        timeout: Duration,
    ) -> Result<AnchoredSnapshot, ClientError> {
        let captured = self.capture_policy_snapshot(policy, 0, own_key).await?;
        let submission = anchoring
            .submit_anchor(submitter, &captured.revision, own_key)
            .await?;
        let recorded = anchoring
            .await_anchor(submission, anchoring_key, timeout)
            .await?;
        let anchor = anchoring
            .read_latest_anchor(&deployment_id(own_key), recorded, anchoring_key)
            .await?;
        let snapshot = AnchoredSnapshot {
            policy: policy.to_owned(),
            revision: captured.revision,
            proof: captured.proof,
            anchor: anchor.evidence,
        };
        snapshot.verify(&deployment_id(own_key), policy, anchoring_key, recorded)?;
        Ok(snapshot)
    }
}
