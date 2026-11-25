#![allow(missing_docs)]

pub use super::policy_id::{PolicyHash, PolicyNonce};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use vera_identity::Did;

pub use ::acp::domain::{ActorSet, ProcessedPolicy, Relationship, Subject};

pub use super::relation_generations::{RelationGenerations, RelationPair};
use crate::types::{Duration, Timestamp};

/// Metadata attached to any stored record.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct RecordMetadata {
    pub creation_ts: Timestamp,
    pub tx_hash: Vec<u8>,
    pub tx_signer: String,
    pub owner_did: String,
}

/// Parameters governing access-decision lifecycle timers.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct DecisionParams {
    pub decision_expiration_delta: u64,
    pub proof_expiration_delta: u64,
    pub ticket_expiration_delta: u64,
}

/// A single operation within an access request.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Operation {
    pub object: Object,
    pub permission: String,
}

/// A specification a policy may be required to meet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicySpecification {
    /// No specification.
    None,
    /// DefraDB's document permissions: `read`, `update` and `delete`.
    Defra,
}

impl From<PolicySpecification> for ::acp::domain::Specification {
    fn from(specification: PolicySpecification) -> Self {
        match specification {
            PolicySpecification::None => Self::None,
            PolicySpecification::Defra => Self::Defra,
        }
    }
}

/// Policy serialization format.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub enum PolicyMarshalingType {
    Unknown,
    ShortYaml,
    ShortJson,
}

/// Reference to an object within a policy resource.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Object {
    pub resource: String,
    pub id: String,
}

impl From<&Object> for ::acp::domain::Object {
    fn from(object: &Object) -> Self {
        Self::new(object.resource.as_str(), object.id.as_str())
    }
}

impl From<&::acp::domain::Object> for Object {
    fn from(object: &::acp::domain::Object) -> Self {
        Self {
            resource: object.resource.to_string(),
            id: object.id.to_string(),
        }
    }
}

/// An actor identity (wraps a DID).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Actor(
    #[borsh(
        serialize_with = "crate::borsh_did::serialize_did",
        deserialize_with = "crate::borsh_did::deserialize_did"
    )]
    pub Did,
);

/// A request to check whether an actor has permissions on objects.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct AccessRequest {
    pub operations: Vec<Operation>,
    pub actor: Actor,
}

/// The result of evaluating an access check.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct AccessDecision {
    pub id: String,
    pub policy_id: String,
    pub creator: String,
    pub creator_acc_sequence: u64,
    pub operations: Vec<Operation>,
    pub actor: String,
    pub params: DecisionParams,
    pub creation_time: Timestamp,
    pub issued_height: u64,
}

/// A command to execute against a policy's relation graph.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PolicyCmd {
    SetRelationship(Relationship),
    DeleteRelationship(Relationship),
    RegisterObject(Object),
    /// Register `object` together with `relationships`, the relationships
    /// the client derived from it (e.g. `book:<id>#author@author:mike`). The
    /// registering actor must pass the resource's collection `create` over
    /// the stored relationships plus these; then the owner relationship and
    /// these are stored in one execution. Each must be on `object` and
    /// admitted by the policy; the owner relation is not one of them.
    /// `RegisterObject(object)` is this command with no relationships.
    RegisterObjectWithRelationships {
        object: Object,
        relationships: Vec<Relationship>,
    },
    TransferObject {
        object: Object,
        new_owner: Actor,
    },
    ArchiveObject(Object),
    UnarchiveObject(Object),
    CommitRegistrations {
        commitment: Vec<u8>,
    },
    RevealRegistration {
        registrations_commitment_id: u64,
        proof: RegistrationProof,
    },
    FlagHijackAttempt {
        event_id: u64,
    },
}

/// The result of executing a policy command (matches Go oneof).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum PolicyCmdResult {
    SetRelationship {
        record_existed: bool,
        record: RelationshipRecord,
    },
    DeleteRelationship {
        record_found: bool,
    },
    RegisterObject {
        record: RelationshipRecord,
    },
    /// The owner relationship's record and the stored derived
    /// relationships' records, in the command's order.
    RegisterObjectWithRelationships {
        record: RelationshipRecord,
        relationships: Vec<RelationshipRecord>,
    },
    TransferObject {
        record: RelationshipRecord,
    },
    ArchiveObject {
        found: bool,
        relationships_removed: u64,
    },
    UnarchiveObject {
        record: RelationshipRecord,
        relationship_modified: bool,
    },
    CommitRegistrations {
        registrations_commitment: RegistrationsCommitment,
    },
    RevealRegistration {
        record: RelationshipRecord,
        event: Option<AmendmentEvent>,
    },
    FlagHijackAttempt {
        event: AmendmentEvent,
    },
}

/// Caller-supplied record attributes, separate from policy semantics.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuppliedMetadata {
    #[serde(default)]
    pub attributes: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub blob: Vec<u8>,
}

/// Policy creation options shared by native and embedded callers.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyCreation {
    pub policy: String,
    pub marshal_type: PolicyMarshalingType,
    /// The creator's nonce, part of the policy id.
    pub nonce: PolicyNonce,
    #[serde(default)]
    pub required_specification: Option<PolicySpecification>,
    #[serde(default)]
    pub metadata: SuppliedMetadata,
}

/// An authenticated command with optional application metadata for the created record.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyCommandRequest {
    pub command: PolicyCmd,
    #[serde(default)]
    pub metadata: SuppliedMetadata,
}

impl SuppliedMetadata {
    pub(crate) fn validate(&self) -> Result<(), super::AcpError> {
        let encoded =
            serde_json::to_vec(self).map_err(|error| super::AcpError::State(error.to_string()))?;
        if encoded.len() > 64 << 10 {
            return Err(super::AcpError::InvalidAccessRequest {
                reason: "metadata exceeds 64 KiB".into(),
            });
        }
        Ok(())
    }
    pub fn is_empty(&self) -> bool {
        self.attributes.is_empty() && self.blob.is_empty()
    }
}

/// A stored policy with metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyRecord {
    /// Current relation incarnations and the next unused identifier.
    pub relations: RelationGenerations,
    #[serde(default, skip_serializing_if = "SuppliedMetadata::is_empty")]
    pub supplied_metadata: SuppliedMetadata,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<Timestamp>,
    pub policy: ProcessedPolicy,
    pub raw_policy: String,
    pub marshal_type: PolicyMarshalingType,
    pub metadata: RecordMetadata,
    /// The creator's nonce the id was derived from.
    pub nonce: PolicyNonce,
    /// The policy hash at creation, which the id was derived from with the
    /// nonce and `metadata.owner_did`; edits keep it.
    pub policy_hash: PolicyHash,
}

impl PolicyRecord {
    /// The id derived from the creation hash, the nonce and the owner; a
    /// well-formed record is stored under it.
    pub fn derived_id(&self) -> String {
        super::policy_id::policy_id(&self.policy_hash, &self.nonce, &self.metadata.owner_did)
    }
}

/// Proof that an object was included in a registration commitment.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct RegistrationProof {
    pub object: Object,
    pub merkle_proof: Vec<Vec<u8>>,
    pub leaf_count: u64,
    pub leaf_index: u64,
}

/// A batch registration commitment submitted by an actor.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct RegistrationsCommitment {
    pub id: u64,
    pub policy_id: String,
    pub commitment: Vec<u8>,
    pub expired: bool,
    pub validity: Duration,
    pub metadata: RecordMetadata,
}

/// Record of an ownership amendment event.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct AmendmentEvent {
    pub id: u64,
    pub policy_id: String,
    pub object: Object,
    pub new_owner: Actor,
    pub previous_owner: Actor,
    pub commitment_id: u64,
    pub hijack_flag: bool,
    pub metadata: RecordMetadata,
}

/// Selects objects within a relationship query.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ObjectSelector {
    Exact(Object),
    Wildcard,
    ResourcePredicate(String),
}

/// Selects relations within a relationship query.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RelationSelector {
    Exact(String),
    Wildcard,
}

/// Selects subjects within a relationship query.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SubjectSelector {
    Exact(Subject),
    Wildcard,
}

/// Filter for querying relationships.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RelationshipSelector {
    pub object_selector: Option<ObjectSelector>,
    pub relation_selector: Option<RelationSelector>,
    pub subject_selector: Option<SubjectSelector>,
}

/// A relationship associated with its policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelationshipRecord {
    /// Target object's physical incarnation; owner records always use zero.
    pub incarnation: u64,
    /// Immutable incarnations of the relationship and referenced userset.
    pub generations: RelationPair,
    #[serde(default, skip_serializing_if = "SuppliedMetadata::is_empty")]
    pub supplied_metadata: SuppliedMetadata,
    pub policy_id: String,
    pub relationship: Relationship,
    pub archived: bool,
    pub metadata: RecordMetadata,
}

/// Result of generating a registration commitment with proofs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenerateCommitmentResult {
    pub commitment: Vec<u8>,
    pub commitment_hex: String,
    pub proofs: Vec<RegistrationProof>,
    pub proofs_json: Vec<String>,
}

/// Module-level parameters.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcpParams {
    pub registrations_commitment_validity: Duration,
}

impl Default for AcpParams {
    fn default() -> Self {
        Self {
            registrations_commitment_validity: Duration::Seconds(10 * 60),
        }
    }
}

#[cfg(test)]
mod incarnation_tests {
    use super::*;

    #[test]
    fn relationship_incarnation_is_required_and_round_trips() {
        let record = RelationshipRecord {
            incarnation: u64::MAX,
            generations: RelationPair {
                target: 1,
                subject: 0,
            },
            supplied_metadata: Default::default(),
            policy_id: "policy-1".into(),
            relationship: Relationship::new(
                ::acp::domain::Object::new("file", "report"),
                "reader",
                Subject::AllActors,
            ),
            archived: false,
            metadata: RecordMetadata {
                creation_ts: Timestamp::default(),
                tx_hash: Vec::new(),
                tx_signer: "actor".into(),
                owner_did: "actor".into(),
            },
        };
        let mut value = serde_json::to_value(&record).unwrap();
        let decoded: RelationshipRecord = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(decoded.incarnation, u64::MAX);
        value.as_object_mut().unwrap().remove("incarnation");
        assert!(serde_json::from_value::<RelationshipRecord>(value.clone()).is_err());
        value["incarnation"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<RelationshipRecord>(value).is_err());
    }
}
