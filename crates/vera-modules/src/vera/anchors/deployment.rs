//! Deployments this deployment's operators registered for anchoring.

use alloy_primitives::{B256, Bytes};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use super::{AnchorError, CONSENSUS_KEY_BYTES, deployment_id};
use crate::kv_store::ModuleKvStore as _;
use crate::vera::VeraModule;
use crate::vera::administration::OperatorPolicy;

const KEY_PREFIX: &[u8] = b"anchor-deployment/v1/";
/// Longest stored deployment record, in bytes: a policy of the most operators
/// in their longest spelling.
pub const MAX_DEPLOYMENT_RECORD_BYTES: usize = 16 << 10;

/// Storage key of a registered deployment in the identity partition.
#[must_use]
pub fn deployment_key(deployment: &B256) -> Vec<u8> {
    [KEY_PREFIX, hex::encode(deployment).as_bytes()].concat()
}

/// What this deployment's operators state about a deployment they admit for
/// anchoring: its consensus key, its genesis block and its operator policy.
///
/// The three are not proven against each other. The operators' approval of
/// the registration is the authority for them, as it is for any
/// administrative change.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentRegistration {
    /// The deployment's consensus key: 96 bytes in lowercase hexadecimal.
    pub consensus_key: String,
    /// Identifier of the deployment's genesis block, which its term certificates name.
    pub genesis_id: [u8; 32],
    /// The deployment's operator policy, which approves its term certificates.
    pub operators: OperatorPolicy,
}

/// A registered deployment as stored and as proven to readers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentRecord {
    /// [`deployment_id`] of `consensus_key`.
    pub deployment: B256,
    /// Canonical encoding of the deployment's consensus key.
    pub consensus_key: Bytes,
    /// Identifier of the deployment's genesis block.
    pub genesis_id: B256,
    /// The deployment's operator policy.
    pub operators: OperatorPolicy,
    /// Block time, in Unix seconds, of the revision of this deployment that first registered it.
    pub registered_at: u64,
    /// The term certified last, whose record holds its cut; 0 until the
    /// deployment's first term change is recorded.
    pub term: u64,
}

impl DeploymentRecord {
    /// Decode a stored record and check it belongs to `deployment`.
    pub fn decode(deployment: &B256, bytes: &[u8]) -> Result<Self, AnchorError> {
        if bytes.len() > MAX_DEPLOYMENT_RECORD_BYTES {
            return Err(AnchorError::MalformedRecord);
        }
        let record: Self =
            serde_json::from_slice(bytes).map_err(|_| AnchorError::MalformedRecord)?;
        if record.deployment != *deployment
            || record.consensus_key.len() != CONSENSUS_KEY_BYTES
            || deployment_id(&record.consensus_key) != *deployment
            || record.operators.validate().is_err()
        {
            return Err(AnchorError::MalformedRecord);
        }
        Ok(record)
    }

    /// Canonical stored encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("deployment records serialize")
    }
}

impl VeraModule {
    /// Register a deployment, or replace the operator policy of one already
    /// registered under the same key and genesis block.
    pub(in crate::vera) fn register_deployment(
        &mut self,
        registration: &DeploymentRegistration,
        now: u64,
    ) -> Result<DeploymentRecord, AnchorError> {
        let consensus_key = hex::decode(&registration.consensus_key)
            .ok()
            .filter(|key| {
                key.len() == CONSENSUS_KEY_BYTES && hex::encode(key) == registration.consensus_key
            })
            .ok_or(AnchorError::InvalidConsensusKey)?;
        if registration.genesis_id == [0; 32] || registration.operators.validate().is_err() {
            return Err(AnchorError::InvalidRegistration);
        }
        let deployment = deployment_id(&consensus_key);
        let genesis_id = B256::from(registration.genesis_id);
        let (registered_at, term) = match self.deployment(&deployment)? {
            Some(existing) if existing.genesis_id != genesis_id => {
                return Err(AnchorError::InvalidRegistration);
            }
            Some(existing) => (existing.registered_at, existing.term),
            None => (now, 0),
        };
        let record = DeploymentRecord {
            deployment,
            consensus_key: consensus_key.into(),
            genesis_id,
            operators: registration.operators.clone(),
            registered_at,
            term,
        };
        self.store
            .put(&deployment_key(&deployment), record.encode());
        Ok(record)
    }

    /// The registration of `deployment`, if this deployment's operators registered it.
    pub fn deployment(&self, deployment: &B256) -> Result<Option<DeploymentRecord>, AnchorError> {
        self.store
            .get(&deployment_key(deployment))
            .map(|bytes| DeploymentRecord::decode(deployment, &bytes))
            .transpose()
    }

    /// As [`Self::deployment`], refusing a deployment that is not registered.
    pub fn registered_deployment(
        &self,
        deployment: &B256,
    ) -> Result<DeploymentRecord, AnchorError> {
        self.deployment(deployment)?
            .ok_or(AnchorError::NotRegistered)
    }
}
