//! Operator approvals and replay protection for administrative changes.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{Result, VeraError, VeraModule, operator_key};
use crate::acp::{AcpModule, types::AcpParams};
use crate::kv_store::ModuleKvStore;

/// Native record key for the current operator policy and administrative sequence.
pub const STATE_KEY: &[u8] = b"admin/v1";
const SIGNING_NAMESPACE: &[u8] = b"vera/admin/v1\0";
/// Maximum number of operator keys in one approval policy.
pub const MAX_OPERATORS: usize = 128;

/// Approval threshold and operator keys.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorPolicy {
    /// Number of distinct approvals required for a change.
    pub threshold: u16,
    /// Operator keys in ascending string order: lowercase hexadecimal
    /// compressed secp256k1 keys, and `did:key` for Ed25519 and P-256 keys.
    pub keys: Vec<String>,
}

impl OperatorPolicy {
    /// Reject impossible thresholds, duplicate keys and noncanonical encodings.
    pub fn validate(&self) -> Result<()> {
        if self.threshold == 0
            || usize::from(self.threshold) > self.keys.len()
            || self.keys.len() > MAX_OPERATORS
            || self.keys.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(invalid("invalid operator threshold or key order"));
        }
        for key in &self.keys {
            operator_key::did(key).map_err(invalid)?;
        }
        Ok(())
    }

    /// The `did:key` of the operator at `signer`, whatever form its entry takes.
    pub fn operator_did(&self, signer: u16) -> Result<String> {
        let key = self
            .keys
            .get(usize::from(signer))
            .ok_or_else(|| invalid("operator index is outside the policy"))?;
        operator_key::did(key).map_err(invalid)
    }

    /// Verify one approval of `digest` against the key at its signer index.
    ///
    /// The signature is 64 bytes of lowercase hexadecimal. ECDSA keys sign the
    /// digest as the prehash with low `s`; Ed25519 signs it as the message.
    pub fn verify_approval(&self, digest: &[u8; 32], approval: &OperatorApproval) -> Result<()> {
        let key = self
            .keys
            .get(usize::from(approval.signer))
            .ok_or_else(|| invalid("operator index is outside the policy"))?;
        if approval.signature.len() != 128 {
            return Err(invalid("operator signature must contain 64 bytes"));
        }
        let signature = hex::decode(&approval.signature).map_err(invalid)?;
        if hex::encode(&signature) != approval.signature {
            return Err(invalid("operator signature must use lowercase hexadecimal"));
        }
        operator_key::verify(key, digest, &signature).map_err(invalid)
    }
}

/// Current approval policy and the sequence expected for the next change.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct AdministrationState {
    /// Operator keys currently authorized to approve changes.
    pub policy: OperatorPolicy,
    /// Monotonic administrative sequence, independent of the submitting identity.
    pub sequence: u64,
    /// Optional ACP policy explicitly selected to manage the membership registry.
    pub membership_policy: Option<[u8; 32]>,
}

/// Changes authorized by the current operator quorum.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AdministrativeCommand {
    /// Replace the operator policy after approval by the existing policy.
    RotateOperators(OperatorPolicy),
    /// Select the existing ACP policy that authorizes membership operations.
    InitializeMembershipPolicy([u8; 32]),
    /// Change access-control parameters.
    SetAcpParameters(AcpParams),
    /// Install or replace scoped relay authority, invalidating its prior assertions.
    SetRelay(super::relay::RelayGrant),
    /// Remove relay authority immediately at this execution revision.
    RevokeRelay(String),
    /// Set the maximum retained encoded operation outcomes, in bytes.
    SetOperationBudget(u64),
}

/// The exact administrative request covered by each operator signature.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdministrativeRequest {
    /// Identifier of the deployment's genesis record.
    pub genesis_id: [u8; 32],
    /// Sequence expected by the committed administrative state.
    pub sequence: u64,
    /// Last valid execution time, in Unix seconds.
    pub expires_at: u64,
    /// Requested change.
    pub command: AdministrativeCommand,
}

impl AdministrativeRequest {
    /// SHA-256 of the signing namespace followed by the Borsh-encoded request.
    pub fn signing_digest(&self) -> Result<[u8; 32]> {
        let mut hash = Sha256::new();
        hash.update(SIGNING_NAMESPACE);
        hash.update(borsh::to_vec(self).map_err(invalid)?);
        Ok(hash.finalize().into())
    }
}

/// One signature from the current operator policy, in its key type's single encoding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorApproval {
    /// Index of the signing key in the committed operator policy.
    pub signer: u16,
    /// Lowercase hexadecimal encoding of the 64-byte signature.
    pub signature: String,
}

/// Administrative request and its independent operator approvals.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAdministrativeRequest {
    /// Request shared by every signer.
    pub request: AdministrativeRequest,
    /// Approvals in ascending signer-index order; duplicates are invalid.
    pub approvals: Vec<OperatorApproval>,
}

impl VeraModule {
    /// Seed operator authority once during initialization; not a public operation.
    pub fn initialize_administration(&mut self, policy: OperatorPolicy) -> Result<()> {
        policy.validate()?;
        if self.store.has(STATE_KEY) {
            return Err(invalid("operator authority is already initialized"));
        }
        let state = AdministrationState {
            policy,
            sequence: 0,
            membership_policy: None,
        };
        self.store
            .put(STATE_KEY, borsh::to_vec(&state).map_err(invalid)?);
        Ok(())
    }

    /// Read the committed approval policy and next sequence.
    pub fn administration(&self) -> Result<Option<AdministrationState>> {
        self.store
            .get(STATE_KEY)
            .map(|bytes| {
                borsh::from_slice(&bytes).map_err(|error| VeraError::State(error.to_string()))
            })
            .transpose()
    }

    /// Verify a quorum and apply one administrative change atomically.
    pub fn apply_administrative_request(
        &mut self,
        acp: &mut AcpModule,
        genesis_id: [u8; 32],
        now: u64,
        signed: &SignedAdministrativeRequest,
    ) -> Result<()> {
        let mut state = self
            .administration()?
            .ok_or_else(|| invalid("operator authority is not configured"))?;
        let request = &signed.request;
        if genesis_id == [0; 32]
            || request.genesis_id != genesis_id
            || request.sequence != state.sequence
            || request.expires_at < now
        {
            return Err(invalid("deployment, sequence or expiration mismatch"));
        }
        if signed.approvals.len() < usize::from(state.policy.threshold)
            || signed.approvals.len() > state.policy.keys.len()
            || signed
                .approvals
                .windows(2)
                .any(|pair| pair[0].signer >= pair[1].signer)
        {
            return Err(invalid("insufficient or duplicate operator approvals"));
        }
        let digest = request.signing_digest()?;
        for approval in &signed.approvals {
            state.policy.verify_approval(&digest, approval)?;
        }
        state.sequence = state
            .sequence
            .checked_add(1)
            .ok_or_else(|| invalid("administrative sequence is exhausted"))?;
        if let AdministrativeCommand::RotateOperators(policy) = &request.command {
            policy.validate()?;
            state.policy = policy.clone();
        }
        if let AdministrativeCommand::InitializeMembershipPolicy(policy_id) = &request.command {
            if state.membership_policy.is_some() || *policy_id == [0; 32] {
                return Err(invalid(
                    "membership policy is already configured or invalid",
                ));
            }
            acp.query_policy(&hex::encode(policy_id)).map_err(invalid)?;
            state.membership_policy = Some(*policy_id);
        }
        let encoded_state = borsh::to_vec(&state).map_err(invalid)?;
        if let AdministrativeCommand::SetAcpParameters(parameters) = &request.command {
            acp.set_params(parameters).map_err(invalid)?;
        }
        if let AdministrativeCommand::SetRelay(grant) = &request.command {
            self.set_relay(grant, request.sequence, now)
                .map_err(invalid)?;
        }
        if let AdministrativeCommand::RevokeRelay(issuer) = &request.command {
            self.revoke_relay(issuer).map_err(invalid)?;
        }
        if let AdministrativeCommand::SetOperationBudget(bytes) = &request.command {
            acp.set_operation_budget(*bytes).map_err(invalid)?;
        }
        self.store.put(STATE_KEY, encoded_state);
        Ok(())
    }
}

fn invalid(error: impl std::fmt::Display) -> VeraError {
    VeraError::InvalidAdministrativeRequest {
        reason: error.to_string(),
    }
}
