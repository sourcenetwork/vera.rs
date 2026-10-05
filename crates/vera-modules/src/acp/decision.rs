//! Request identity and lifetime checks for persisted successful access decisions.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    error::AcpError,
    types::{AccessDecision, AccessRequest},
};
use crate::types::Timestamp;

/// Maximum operations in persisted decisions, access ABI calls and default permission proofs.
pub const MAX_ACCESS_OPERATIONS: usize = 64;

/// Exact operation identity expected by a decision consumer.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct DecisionRequest {
    /// Deployment configured by the consumer.
    pub deployment_id: u64,
    /// Requested policy.
    pub policy_id: String,
    /// Authenticated submitting identity, which may differ from the actor.
    pub creator: String,
    /// Sequence of the submitting operation.
    pub creator_sequence: u64,
    /// Actor and ordered operations being authorized.
    pub request: AccessRequest,
}

impl DecisionRequest {
    /// Canonical, domain-separated identifier; field boundaries and operation order are retained.
    pub fn id(&self) -> Result<String, AcpError> {
        if self.policy_id.is_empty()
            || self.creator.is_empty()
            || self.request.operations.is_empty()
        {
            return Err(invalid("policy, creator and operations must be nonempty"));
        }
        let mut fields = [
            self.policy_id.as_str(),
            self.creator.as_str(),
            self.request.actor.0.as_str(),
        ]
        .into_iter()
        .chain(self.request.operations.iter().flat_map(|op| {
            [
                op.object.resource.as_str(),
                op.object.id.as_str(),
                op.permission.as_str(),
            ]
        }));
        let field_bytes = fields.try_fold(0usize, |size, field| size.checked_add(field.len()));
        if self.request.operations.len() > MAX_ACCESS_OPERATIONS
            || field_bytes.is_none_or(|size| size > 64 << 10)
        {
            return Err(invalid("access decision request exceeds limits"));
        }
        let encoded = borsh::to_vec(self).map_err(|e| AcpError::State(e.to_string()))?;
        if encoded.len() > 64 << 10 {
            return Err(invalid("access decision request exceeds byte limit"));
        }
        let mut hash = Sha256::new();
        hash.update(b"vera/access-decision/v1\0");
        hash.update(encoded);
        Ok(hex::encode(hash.finalize()))
    }

    /// Decode authenticated record bytes and bind the grant to this request and evaluation revision.
    pub fn verify_record(&self, bytes: &[u8], at: &Timestamp) -> Result<AccessDecision, AcpError> {
        let decision = AccessDecision::decode_record(bytes)?;
        let expires = self.verify_issuance(&decision, at)?;
        if at.block_height >= expires {
            return Err(invalid("access decision expired"));
        }
        Ok(decision)
    }

    /// Bind issuance to this request and return its exclusive expiry, without granting current access.
    pub fn verify_issuance(
        &self,
        decision: &AccessDecision,
        at: &Timestamp,
    ) -> Result<u64, AcpError> {
        if decision.id != self.id()?
            || decision.policy_id != self.policy_id
            || decision.creator != self.creator
            || decision.creator_acc_sequence != self.creator_sequence
            || decision.actor != self.request.actor.0.as_str()
            || decision.operations != self.request.operations
        {
            return Err(invalid(
                "access decision differs from the requested operation",
            ));
        }
        if decision.issued_height == 0
            || decision.issued_height > at.block_height
            || decision.creation_time.block_height != decision.issued_height
            || decision.creation_time.seconds == 0
            || decision.creation_time.seconds > at.seconds
        {
            return Err(invalid("invalid access decision issuance revision"));
        }
        let expires = decision
            .issued_height
            .checked_add(decision.params.decision_expiration_delta)
            .ok_or_else(|| invalid("access decision expiry overflow"))?;
        if expires <= decision.issued_height {
            return Err(invalid("invalid access decision lifetime"));
        }
        Ok(expires)
    }
}

impl AccessDecision {
    /// Decode bounded record bytes. Decoding alone does not authenticate a decision.
    pub fn decode_record(bytes: &[u8]) -> Result<Self, AcpError> {
        if bytes.len() > 128 << 10 {
            return Err(invalid("access decision exceeds byte limit"));
        }
        borsh::from_slice(bytes)
            .map_err(|error| AcpError::State(format!("invalid access decision: {error}")))
    }

    /// Verify issuance under the requested deployment and ID, including records past their expiry.
    pub fn verify_issuance(
        &self,
        deployment_id: u64,
        id: &str,
        at: &Timestamp,
    ) -> Result<u64, AcpError> {
        if self.id != id {
            return Err(invalid(
                "access decision ID differs from the requested record",
            ));
        }
        identity::Did::new(&self.creator).map_err(|_| invalid("invalid decision creator"))?;
        let expected = DecisionRequest {
            deployment_id,
            policy_id: self.policy_id.clone(),
            creator: self.creator.clone(),
            creator_sequence: self.creator_acc_sequence,
            request: AccessRequest {
                actor: super::types::Actor(
                    self.actor
                        .parse()
                        .map_err(|_| invalid("invalid decision actor"))?,
                ),
                operations: self.operations.clone(),
            },
        };
        expected.verify_issuance(self, at)
    }
}

fn invalid(reason: &str) -> AcpError {
    AcpError::InvalidAccessRequest {
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acp::types::{Actor, DecisionParams, Object, Operation};

    fn request() -> DecisionRequest {
        DecisionRequest {
            deployment_id: 9001,
            policy_id: "policy".into(),
            creator: "did:key:creator".into(),
            creator_sequence: 7,
            request: AccessRequest {
                actor: Actor("did:key:actor".parse().unwrap()),
                operations: vec![Operation {
                    object: Object {
                        resource: "a".into(),
                        id: "bc".into(),
                    },
                    permission: "read".into(),
                }],
            },
        }
    }

    #[test]
    fn identifiers_bind_field_boundaries_deployment_and_sequence() {
        let request = request();
        let id = request.id().unwrap();
        let mut other = request.clone();
        other.request.operations[0].object.resource = "ab".into();
        other.request.operations[0].object.id = "c".into();
        assert_ne!(id, other.id().unwrap());
        other = request.clone();
        other.creator_sequence += 1;
        assert_ne!(id, other.id().unwrap());
        other = request.clone();
        other.deployment_id += 1;
        assert_ne!(id, other.id().unwrap());
        other.request.operations.clear();
        assert!(other.id().is_err());
        let mut oversized = request.clone();
        oversized.policy_id = "x".repeat((64 << 10) + 1);
        assert!(oversized.id().is_err());
        oversized = request.clone();
        oversized.request.operations = vec![request.request.operations[0].clone(); 65];
        assert!(oversized.id().is_err());
    }

    fn check_stored_decision(decision: &AccessDecision) {
        use crate::{
            acp::{AcpModule, keys},
            kv_store::ModuleKvStore,
        };

        let mut module = AcpModule::new();
        let key = keys::access_decision_key(&decision.id);
        assert!(
            module
                .query_access_decision(&decision.id)
                .unwrap()
                .is_none()
        );
        let bytes = borsh::to_vec(decision).unwrap();
        module.store.put(&key, bytes.clone());
        assert_eq!(
            module.query_access_decision(&decision.id).unwrap().as_ref(),
            Some(decision)
        );
        for length in 0..bytes.len() {
            module.store.put(&key, bytes[..length].to_vec());
            assert!(module.query_access_decision(&decision.id).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        module.store.put(&key, trailing);
        assert!(module.query_access_decision(&decision.id).is_err());
        module.store.put(&key, vec![0; (128 << 10) + 1]);
        assert!(module.query_access_decision(&decision.id).is_err());
        let other_key = keys::access_decision_key("other");
        module.store.put(&other_key, bytes);
        assert!(module.query_access_decision("other").is_err());
    }

    #[test]
    fn decision_contents_and_expiration_are_bound_to_the_request() {
        let request = request();
        let at = Timestamp {
            seconds: 1000,
            block_height: 5,
        };
        let decision = AccessDecision {
            id: request.id().unwrap(),
            policy_id: request.policy_id.clone(),
            creator: request.creator.clone(),
            creator_acc_sequence: request.creator_sequence,
            operations: request.request.operations.clone(),
            actor: request.request.actor.0.to_string(),
            params: DecisionParams {
                decision_expiration_delta: 100,
                proof_expiration_delta: 50,
                ticket_expiration_delta: 100,
            },
            creation_time: at.clone(),
            issued_height: at.block_height,
        };
        check_stored_decision(&decision);
        let verify = |value: &AccessDecision, at: &Timestamp| {
            request.verify_record(&borsh::to_vec(value).unwrap(), at)
        };
        assert_eq!(verify(&decision, &at).unwrap(), decision);
        assert!(
            verify(
                &decision,
                &Timestamp {
                    block_height: 104,
                    ..at
                }
            )
            .is_ok()
        );
        assert!(
            verify(
                &decision,
                &Timestamp {
                    block_height: 105,
                    ..at
                }
            )
            .is_err()
        );
        assert!(
            verify(
                &decision,
                &Timestamp {
                    block_height: 4,
                    ..at
                }
            )
            .is_err()
        );
        assert!(verify(&decision, &Timestamp { seconds: 999, ..at }).is_err());
        let expired = Timestamp {
            block_height: 105,
            ..at
        };
        assert_eq!(
            decision
                .verify_issuance(request.deployment_id, &decision.id, &expired)
                .unwrap(),
            105
        );
        assert!(
            decision
                .verify_issuance(request.deployment_id + 1, &decision.id, &at)
                .is_err()
        );
        assert!(
            decision
                .verify_issuance(request.deployment_id, &"ff".repeat(32), &at)
                .is_err()
        );
        let mut cases = vec![];
        let mut bad = decision.clone();
        bad.id = "legacy".into();
        cases.push(bad);
        let mut bad = decision.clone();
        bad.policy_id.push('x');
        cases.push(bad);
        let mut bad = decision.clone();
        bad.creator.push('x');
        cases.push(bad);
        let mut bad = decision.clone();
        bad.creator_acc_sequence += 1;
        cases.push(bad);
        let mut bad = decision.clone();
        bad.actor.push('x');
        cases.push(bad);
        let mut bad = decision.clone();
        bad.operations.clear();
        cases.push(bad);
        let mut bad = decision.clone();
        bad.issued_height = 0;
        cases.push(bad);
        let mut bad = decision.clone();
        bad.creation_time.block_height += 1;
        cases.push(bad);
        let mut bad = decision.clone();
        bad.creation_time.seconds = 0;
        cases.push(bad);
        let mut bad = decision.clone();
        bad.params.decision_expiration_delta = 0;
        cases.push(bad);
        let mut bad = decision;
        bad.params.decision_expiration_delta = u64::MAX;
        cases.push(bad);
        for bad in cases {
            assert!(verify(&bad, &at).is_err(), "{bad:?}");
        }
        assert!(request.verify_record(&[0; 4], &at).is_err());
        assert!(
            request
                .verify_record(&vec![0; (128 << 10) + 1], &at)
                .is_err()
        );
    }
}
