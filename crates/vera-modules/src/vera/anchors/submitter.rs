//! The signers this deployment's operators allow to submit anchors of a deployment.

use alloy_primitives::B256;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use super::AnchorError;
use crate::kv_store::ModuleKvStore as _;
use crate::types::BlockExecCtx;
use crate::vera::VeraModule;

const KEY_PREFIX: &[u8] = b"anchor-submitter/v1/";
const SECONDS_PER_DAY: u64 = 86_400;
/// Longest `did:key` of a submitter.
pub const MAX_SUBMITTER_BYTES: usize = 128;
/// Longest stored submitter record, in bytes.
pub const MAX_SUBMITTER_RECORD_BYTES: usize = 512;

/// Prefix of every submitter record of `deployment` in the identity partition.
#[must_use]
pub fn submitter_prefix(deployment: &B256) -> Vec<u8> {
    [KEY_PREFIX, hex::encode(deployment).as_bytes(), b"/"].concat()
}

/// Storage key of the grant of `submitter` for `deployment`.
#[must_use]
pub fn submitter_key(deployment: &B256, submitter: &str) -> Vec<u8> {
    [
        submitter_prefix(deployment).as_slice(),
        submitter.as_bytes(),
    ]
    .concat()
}

/// The right of one native signer to submit anchors, fork reports and term
/// changes of one deployment.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorSubmitterGrant {
    /// The deployment's identifier.
    pub deployment: [u8; 32],
    /// `did:key` of the native signer.
    pub submitter: String,
    /// Submissions the signer may make for the deployment in one day, counted
    /// whether they are recorded or refused.
    pub quota: u32,
}

/// One signer's right to stop submitting for a deployment.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorSubmitterRevocation {
    /// The deployment's identifier.
    pub deployment: [u8; 32],
    /// `did:key` of the native signer.
    pub submitter: String,
}

/// A grant as stored, with the submissions counted against it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitterRecord {
    /// The deployment's identifier.
    pub deployment: B256,
    /// `did:key` of the native signer.
    pub submitter: String,
    /// Submissions allowed in one day.
    pub quota: u32,
    /// The day `used` counts, in days since the Unix epoch by this deployment's block time.
    pub day: u64,
    /// Submissions executed on `day`.
    pub used: u32,
}

impl SubmitterRecord {
    /// Decode a stored record and check it is the grant of `submitter` for `deployment`.
    pub fn decode(deployment: &B256, submitter: &str, bytes: &[u8]) -> Result<Self, AnchorError> {
        if bytes.len() > MAX_SUBMITTER_RECORD_BYTES {
            return Err(AnchorError::MalformedRecord);
        }
        let record: Self =
            serde_json::from_slice(bytes).map_err(|_| AnchorError::MalformedRecord)?;
        if record.deployment != *deployment || record.submitter != submitter || record.quota == 0 {
            return Err(AnchorError::MalformedRecord);
        }
        Ok(record)
    }

    /// Canonical stored encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("submitter records serialize")
    }

    /// Submissions left on the day that contains `seconds`.
    #[must_use]
    pub const fn remaining(&self, seconds: u64) -> u32 {
        if seconds / SECONDS_PER_DAY == self.day {
            self.quota.saturating_sub(self.used)
        } else {
            self.quota
        }
    }
}

fn valid_submitter(submitter: &str) -> bool {
    submitter.len() <= MAX_SUBMITTER_BYTES
        && submitter.strip_prefix("did:key:z").is_some_and(|key| {
            !key.is_empty() && key.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
}

impl VeraModule {
    /// Grant `grant.submitter` the right to submit for a registered
    /// deployment, or change its quota. A changed quota keeps the day's count.
    pub(in crate::vera) fn set_anchor_submitter(
        &mut self,
        grant: &AnchorSubmitterGrant,
    ) -> Result<(), AnchorError> {
        let deployment = B256::from(grant.deployment);
        self.registered_deployment(&deployment)?;
        if grant.quota == 0 || !valid_submitter(&grant.submitter) {
            return Err(AnchorError::InvalidGrant);
        }
        let record = self
            .anchor_submitter(&deployment, &grant.submitter)?
            .map_or_else(
                || SubmitterRecord {
                    deployment,
                    submitter: grant.submitter.clone(),
                    quota: grant.quota,
                    day: 0,
                    used: 0,
                },
                |existing| SubmitterRecord {
                    quota: grant.quota,
                    ..existing
                },
            );
        self.store.put(
            &submitter_key(&deployment, &grant.submitter),
            record.encode(),
        );
        Ok(())
    }

    /// Remove a signer's grant.
    pub(in crate::vera) fn revoke_anchor_submitter(
        &mut self,
        revocation: &AnchorSubmitterRevocation,
    ) -> Result<(), AnchorError> {
        let key = submitter_key(&B256::from(revocation.deployment), &revocation.submitter);
        if !self.store.has(&key) {
            return Err(AnchorError::NotGranted);
        }
        self.store.delete(&key);
        Ok(())
    }

    /// The grant of `submitter` for `deployment`, if it has one.
    pub fn anchor_submitter(
        &self,
        deployment: &B256,
        submitter: &str,
    ) -> Result<Option<SubmitterRecord>, AnchorError> {
        if !valid_submitter(submitter) {
            return Ok(None);
        }
        self.store
            .get(&submitter_key(deployment, submitter))
            .map(|bytes| SubmitterRecord::decode(deployment, submitter, &bytes))
            .transpose()
    }

    /// Count one submission of `submitter` for `deployment` against its grant.
    ///
    /// Fails with [`AnchorError::NotGranted`] for a signer without a grant and
    /// [`AnchorError::QuotaExceeded`] once the day's quota is used.
    pub fn charge_anchor_submission(
        &mut self,
        block_ctx: &BlockExecCtx,
        deployment: &B256,
        submitter: &str,
    ) -> Result<(), AnchorError> {
        let mut record = self
            .anchor_submitter(deployment, submitter)?
            .ok_or(AnchorError::NotGranted)?;
        if record.remaining(block_ctx.timestamp.seconds) == 0 {
            return Err(AnchorError::QuotaExceeded {
                quota: record.quota,
            });
        }
        let day = block_ctx.timestamp.seconds / SECONDS_PER_DAY;
        if record.day != day {
            record.day = day;
            record.used = 0;
        }
        record.used += 1;
        self.store
            .put(&submitter_key(deployment, submitter), record.encode());
        Ok(())
    }
}
