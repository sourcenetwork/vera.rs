use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use vera_crypto::operation::OperationId;
use vera_domain::ConsensusPublicKey;
use vera_modules::acp::{
    delegated_operation::DelegatedOperation,
    keys::access_decision_key,
    operation::{OperationRecord, operation_key},
};

use crate::{
    AccessDecision, AccessRequest, DecisionRequest, ModuleId, PERMISSION_LIMITS, PermissionError,
    RECORD_PROOF_BYTES, RecordResponse, Timestamp, validate_request,
};

/// Caller operation identity and exact decision request expected by a recovering consumer.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionOperation {
    /// Independently configured deployment.
    pub deployment_id: u64,
    /// Authenticated caller, distinct from both target actor and submitting worker.
    /// Any accepted spelling of its key selects the outcome recorded for it.
    pub caller: String,
    /// Immutable caller operation identity.
    pub operation_id: B256,
    /// Policy being evaluated.
    pub policy_id: String,
    /// Target actor and ordered operations.
    pub request: AccessRequest,
}

/// Authenticated issuance metadata; expiry is not a current permission evaluation.
#[derive(Clone, Debug, Serialize)]
pub struct DecisionRecord {
    /// Original stored decision.
    pub decision: AccessDecision,
    /// Exclusive expiry revision.
    pub expires_at_revision: u64,
}

/// Original successful issuance recovered independently of a retry's worker and revision.
#[derive(Clone, Debug, Serialize)]
pub struct DecisionOutcome {
    /// Verified decision and its unchanged expiry.
    #[serde(flatten)]
    pub record: DecisionRecord,
    /// Original authenticated submission ID.
    pub submission: B256,
    /// Original execution revision and time.
    pub revision: Timestamp,
}

impl RecordResponse {
    /// Authenticate a decision record's identity and issuance, including an expired record.
    pub fn verify_access_decision(
        &self,
        deployment_id: u64,
        decision_id: &str,
        minimum_height: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<Option<DecisionRecord>, PermissionError> {
        if decision_id.len() != 64
            || !decision_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(PermissionError::Invalid("invalid decision identifier"));
        }
        self.verify(
            ModuleId::Acp,
            &access_decision_key(decision_id),
            minimum_height,
            trusted,
            RECORD_PROOF_BYTES,
        )?;
        let Some(value) = &self.record.value else {
            return Ok(None);
        };
        let decision = AccessDecision::decode_record(value)
            .map_err(|_| PermissionError::Invalid("invalid decision record"))?;
        let at = Timestamp {
            block_height: self.revision.height,
            seconds: self.revision.timestamp,
        };
        let expires_at_revision = decision
            .verify_issuance(deployment_id, decision_id, &at)
            .map_err(|_| PermissionError::Invalid("invalid decision issuance"))?;
        Ok(Some(DecisionRecord {
            decision,
            expires_at_revision,
        }))
    }

    /// Authenticate caller-bound outcome recovery without renewing or requiring an unexpired grant.
    pub fn verify_decision_outcome(
        &self,
        expected: &DecisionOperation,
        minimum_height: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<Option<DecisionOutcome>, PermissionError> {
        validate_request(&expected.policy_id, &expected.request, PERMISSION_LIMITS)?;
        let id = OperationId(expected.operation_id.0);
        if id.expires_at() == 0 || id.0[8..] == [0; 24] {
            return Err(PermissionError::Invalid("invalid operation identity"));
        }
        let key = operation_key(&expected.caller, id)
            .map_err(|_| PermissionError::Invalid("invalid decision caller"))?;
        self.verify(
            ModuleId::Acp,
            &key,
            minimum_height,
            trusted,
            RECORD_PROOF_BYTES,
        )?;
        let Some(value) = &self.record.value else {
            return Ok(None);
        };
        let outcome: OperationRecord = serde_json::from_slice(value)
            .map_err(|_| PermissionError::Invalid("invalid decision outcome"))?;
        let digest = DelegatedOperation::CheckAccess(&expected.policy_id, &expected.request)
            .digest()
            .map_err(|_| PermissionError::Invalid("invalid decision request"))?;
        if outcome.id != id
            || outcome.digest != digest
            || outcome.actor != vera_modules::actor::canonical_str(&expected.caller)
            || outcome.submission == [0; 32]
            || outcome.revision.block_height == 0
            || outcome.revision.block_height > self.revision.height
            || outcome.revision.seconds == 0
            || outcome.revision.seconds > self.revision.timestamp
            || id.validate(outcome.revision.seconds).is_err()
        {
            return Err(PermissionError::Invalid(
                "decision outcome differs from request or revision",
            ));
        }
        let decision: AccessDecision = serde_json::from_value(outcome.result)
            .map_err(|_| PermissionError::Invalid("invalid decision outcome result"))?;
        let request = DecisionRequest {
            deployment_id: expected.deployment_id,
            policy_id: expected.policy_id.clone(),
            creator: outcome.worker,
            creator_sequence: decision.creator_acc_sequence,
            request: expected.request.clone(),
        };
        let expires_at_revision = request
            .verify_issuance(&decision, &outcome.revision)
            .map_err(|_| PermissionError::Invalid("decision outcome does not bind its issuance"))?;
        if decision.issued_height != outcome.revision.block_height
            || decision.creation_time != outcome.revision
        {
            return Err(PermissionError::Invalid(
                "decision outcome has a different issuance revision",
            ));
        }
        Ok(Some(DecisionOutcome {
            record: DecisionRecord {
                decision,
                expires_at_revision,
            },
            submission: outcome.submission.into(),
            revision: outcome.revision,
        }))
    }
}
