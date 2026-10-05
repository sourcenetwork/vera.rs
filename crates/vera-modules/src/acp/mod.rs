//! ACP module — Zanzibar-style access control policies.

/// Solidity ABI interface for the ACP precompile.
pub mod abi;
mod amendment_history;
pub mod catalogue;
mod command_context;
mod commitment_expiry;
mod commitment_lookup;
mod index_validation;
mod lifecycle;
mod management;
mod metadata;
mod object_archive;
mod object_pairs;
pub mod pages;
mod policy_create;
mod policy_create_budget;
pub use policy_create_budget::PolicyCreateBudget;
mod policy_edit;
mod policy_edit_budget;
pub use policy_edit_budget::PolicyEditBudget;
mod permission_budget;
mod policy_listing;
pub use permission_budget::PermissionBudget;
mod query_budget;
pub use query_budget::QueryBudget;
mod registration_queries;
mod relation_cleanup;
mod relation_edits;
pub mod relation_generations;
mod relation_restoration;
pub mod relationship_index;
mod relationship_mutations;
mod relationship_queries;
mod restoration;
mod retirement;
mod retirement_cleanup;
pub mod theorem;
pub use registration_queries::{MAX_REGISTRATION_LEAF_BYTES, MAX_REGISTRATION_OBJECTS};
pub mod decision;
pub mod delegated_operation;
mod delegation;
/// ACP error types.
pub mod error;
/// Key prefixes and builders for ACP KV storage.
pub mod keys;
pub mod operation;
pub mod read_capture;
pub mod record_store;
/// ACP domain types.
pub mod types;
/// `ZanzibarStore` adapter over vera's module KV store.
pub mod zanzibar_store;

use imbl::OrdMap;
use std::sync::Arc;

use acp::policy_yaml;
use acp::{Policy, Relationship};
use error::AcpError;
use identity::Did;
use sha2::{Digest, Sha256};
use zanzibar::{PermissionEngine, PolicySpecification};
use zanzibar_store::QmdbZanzibarStore;

use crate::kv_store::{InMemoryKvStore, ModuleKvStore};
use crate::types::{BlockExecCtx, Duration, Timestamp, TxExecCtx};
use types::{
    AccessDecision, AccessRequest, AcpParams, Actor, AmendmentEvent, DecisionParams,
    GenerateCommitmentResult, Object, ObjectSelector, PolicyCmd, PolicyCmdResult,
    PolicyMarshalingType, PolicyRecord, RecordMetadata, RegistrationProof, RegistrationsCommitment,
    RelationGenerations, RelationPair, RelationSelector, RelationshipRecord, RelationshipSelector,
    SubjectSelector, SuppliedMetadata,
};

type Result<T> = std::result::Result<T, AcpError>;

/// Maximum encoded source bytes accepted by policy creation and replacement.
pub const MAX_POLICY_DEFINITION_BYTES: usize = 64 << 10;

/// Access Control Policy module.
///
/// Manages Zanzibar-style relation tuples, policy CRUD, object registration,
/// and access checks. Business logic lives here; precompile and native-tx
/// shims are thin wrappers that decode arguments and forward to these methods.
///
/// # KV store layout
///
/// ```text
/// "policy/objs/" + policy_id                           → PolicyRecord (serde_json)
/// "policy/counter/id"                                  → u64 BE
/// "policy/retired/" + policy_id                         → RetiredPolicy (Borsh)
/// "policy/cleanup/queue/" + BE(sequence)                → policy_id
/// "policy/cleanup/counter"                             → u64 BE
/// "relationship/v4/" + policy_id + "/" + pair + storage_key → RelationshipRecord (serde_json)
/// "relation_state/" + policy_id + "/" + index_key       → pair counts, current directories, retired names
/// "relation_cleanup/queue/" + BE(sequence)             → RelationJob (serde_json)
/// "access_decision/" + decision_id                     → AccessDecision (Borsh)
/// "commitment/objs/" + BE(id)                          → RegistrationsCommitment (Borsh)
/// "commitment/counter/id"                              → u64 BE
/// "amendment_event/objs/" + BE(id)                     → AmendmentEvent (Borsh)
/// "amendment_event/counter/id"                         → u64 BE
/// "p_acp"                                              → AcpParams (Borsh)
/// ```
///
/// `zanzibar_policies` is an in-memory cache populated on `create_policy` /
/// `edit_policy`. Forks share immutable policies and unchanged map branches.
#[derive(Clone, Debug)]
pub struct AcpModule {
    store: InMemoryKvStore,
    zanzibar_policies: OrdMap<String, Arc<Policy>>,
}

fn relation_state_error(error: zanzibar::error::Error) -> AcpError {
    AcpError::State(error.to_string())
}

impl Default for AcpModule {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
impl AcpModule {
    /// Create a new ACP module instance.
    pub fn new() -> Self {
        Self {
            store: InMemoryKvStore::default(),
            zanzibar_policies: OrdMap::new(),
        }
    }

    /// Read access to the underlying KV store (for serialization).
    pub const fn store(&self) -> &InMemoryKvStore {
        &self.store
    }

    /// Reconstruct from a deserialized store, rebuilding the zanzibar cache.
    pub fn from_store(store: InMemoryKvStore) -> Self {
        let mut zanzibar_policies = OrdMap::new();
        for (_, value) in store.prefix_iter(keys::POLICY_PREFIX) {
            if let Ok(record) = serde_json::from_slice::<PolicyRecord>(value) {
                zanzibar_policies.insert(record.policy.id.clone(), Arc::new(record.policy));
            }
        }
        Self {
            store,
            zanzibar_policies,
        }
    }

    // ── Msg handlers ────────────────────────────────────────────────────

    /// Evaluate an access check and persist the decision.
    #[allow(unused_variables)]
    pub fn check_access(
        &mut self,
        creator: &Did,
        policy_id: &str,
        access_request: &AccessRequest,
        block: &BlockExecCtx,
        tx: &TxExecCtx,
    ) -> Result<AccessDecision> {
        self.check_access_with_budget(
            creator,
            policy_id,
            access_request,
            block,
            tx,
            &PermissionBudget::new(u64::MAX),
        )
    }

    /// Record a decision after reserving request, evaluation and encoded-write work.
    #[allow(clippy::too_many_arguments)]
    pub fn check_access_with_budget(
        &mut self,
        creator: &Did,
        policy_id: &str,
        access_request: &AccessRequest,
        block: &BlockExecCtx,
        tx: &TxExecCtx,
        budget: &PermissionBudget,
    ) -> Result<AccessDecision> {
        let result =
            self.check_access_metered(creator, policy_id, access_request, block, tx, budget);
        budget.finish(result)
    }

    #[allow(clippy::too_many_arguments)]
    fn check_access_metered(
        &mut self,
        creator: &Did,
        policy_id: &str,
        access_request: &AccessRequest,
        block: &BlockExecCtx,
        tx: &TxExecCtx,
        budget: &PermissionBudget,
    ) -> Result<AccessDecision> {
        if tx.signer != creator.as_str()
            || block.timestamp.block_height == 0
            || block.timestamp.seconds == 0
        {
            return Err(AcpError::InvalidAccessRequest {
                reason: "invalid decision execution context".into(),
            });
        }
        budget.request(policy_id, creator.as_str(), access_request)?;
        let expected = decision::DecisionRequest {
            deployment_id: block.deployment_id,
            policy_id: policy_id.into(),
            creator: creator.to_string(),
            creator_sequence: tx.sequence,
            request: access_request.clone(),
        };
        let decision_id = expected.id()?;
        self.evaluate_permission_request(policy_id, access_request, budget, true)?;

        let decision = AccessDecision {
            id: decision_id,
            policy_id: policy_id.to_string(),
            creator: creator.to_string(),
            creator_acc_sequence: tx.sequence,
            operations: access_request.operations.clone(),
            actor: access_request.actor.0.to_string(),
            params: DecisionParams {
                decision_expiration_delta: 100,
                ticket_expiration_delta: 100,
                proof_expiration_delta: 50,
            },
            creation_time: block.timestamp.clone(),
            issued_height: block.timestamp.block_height,
        };

        let key = keys::access_decision_key(&decision.id);
        let bytes = budget.records.encode_borsh(&key, &decision)?;
        self.store.put(&key, bytes);
        Ok(decision)
    }

    /// Execute context-free command logic. Runtime callers use `execute_policy_cmd`
    /// to retain authenticated submission metadata and registration priority.
    #[allow(unused_variables)]
    pub fn direct_policy_cmd(
        &mut self,
        creator: &Did,
        policy_id: &str,
        cmd: PolicyCmd,
    ) -> Result<PolicyCmdResult> {
        let mut candidate = self.clone();
        let result = candidate.apply_policy_cmd(creator, policy_id, cmd)?;
        *self = candidate;
        Ok(result)
    }

    fn apply_policy_cmd(
        &mut self,
        creator: &Did,
        policy_id: &str,
        cmd: PolicyCmd,
    ) -> Result<PolicyCmdResult> {
        self.query_policy(policy_id)?;
        let object_id = match &cmd {
            PolicyCmd::SetRelationship(rel) | PolicyCmd::DeleteRelationship(rel) => {
                Some(rel.object_id.as_str())
            }
            PolicyCmd::TransferObject { object: obj, .. }
            | PolicyCmd::RegisterObject(obj)
            | PolicyCmd::ArchiveObject(obj)
            | PolicyCmd::UnarchiveObject(obj) => Some(obj.id.as_str()),
            PolicyCmd::RevealRegistration { proof, .. } => Some(proof.object.id.as_str()),
            PolicyCmd::CommitRegistrations { .. } | PolicyCmd::FlagHijackAttempt { .. } => None,
        };
        if object_id == Some("") {
            return Err(AcpError::InvalidAccessRequest {
                reason: "object ID must not be empty".into(),
            });
        }
        match cmd {
            PolicyCmd::SetRelationship(rel) => self.cmd_set_relationship(creator, policy_id, rel),
            PolicyCmd::DeleteRelationship(rel) => {
                self.cmd_delete_relationship(creator, policy_id, rel)
            }
            PolicyCmd::TransferObject { object, new_owner } => self
                .transfer_object(creator, policy_id, &object, &new_owner.0)
                .map(|record| PolicyCmdResult::TransferObject { record }),
            PolicyCmd::RegisterObject(obj) => self.cmd_register_object(creator, policy_id, obj),
            PolicyCmd::ArchiveObject(obj) => self.cmd_archive_object(creator, policy_id, obj),
            PolicyCmd::UnarchiveObject(obj) => self.cmd_unarchive_object(creator, policy_id, obj),
            PolicyCmd::CommitRegistrations { commitment } => {
                self.cmd_commit_registrations(creator, policy_id, commitment)
            }
            PolicyCmd::RevealRegistration {
                registrations_commitment_id,
                proof,
            } => {
                self.cmd_reveal_registration(creator, policy_id, registrations_commitment_id, proof)
            }
            PolicyCmd::FlagHijackAttempt { event_id } => {
                self.cmd_flag_hijack_attempt(creator, policy_id, event_id)
            }
        }
    }

    /// Reject legacy parameter writes without operator approvals.
    pub fn update_params(&mut self, _authority: &Did, _params: AcpParams) -> Result<()> {
        Err(AcpError::Unauthorized {
            reason: "operator approvals are required".into(),
        })
    }

    // ── Query handlers ──────────────────────────────────────────────────

    /// Fetch a policy by ID.
    #[allow(unused_variables)]
    pub fn query_policy(&self, id: &str) -> Result<PolicyRecord> {
        self.get_policy_record(id)?
            .ok_or_else(|| AcpError::PolicyNotFound { id: id.to_string() })
    }

    /// Read and validate a policy after reserving its encoded key/value work.
    pub fn query_policy_with_budget(&self, id: &str, budget: &QueryBudget) -> Result<PolicyRecord> {
        let key = keys::policy_key(id);
        let value = self.store.get_ref(&key);
        budget.read(&key, value)?;
        value
            .map(|bytes| Self::decode_policy_record(id, bytes))
            .transpose()?
            .ok_or_else(|| AcpError::PolicyNotFound { id: id.to_string() })
    }

    /// Verify an access request without recording a decision.
    #[allow(unused_variables)]
    pub fn query_verify_access_request(
        &self,
        policy_id: &str,
        access_request: &AccessRequest,
    ) -> Result<bool> {
        self.query_verify_access_request_with_budget(
            policy_id,
            access_request,
            &PermissionBudget::new(u64::MAX),
        )
    }

    /// Evaluate permissions with one shared allowance across every requested operation.
    pub fn query_verify_access_request_with_budget(
        &self,
        policy_id: &str,
        access_request: &AccessRequest,
        budget: &PermissionBudget,
    ) -> Result<bool> {
        budget.request(policy_id, "", access_request)?;
        let result = self.evaluate_permission_request(policy_id, access_request, budget, false);
        budget.finish(result)
    }

    fn evaluate_permission_request(
        &self,
        policy_id: &str,
        request: &AccessRequest,
        budget: &PermissionBudget,
        decision: bool,
    ) -> Result<bool> {
        let capture = read_capture::ReadCapture::with_budget(
            self.store.clone(),
            read_capture::PERMISSION_READ_LIMITS,
            budget.clone(),
        );
        let engine =
            zanzibar_store::evaluation_engine(capture, policy_id, Some(Arc::new(budget.clone())))
                .map_err(|error| budget.evaluation_error(error))?
                .ok_or_else(|| AcpError::PolicyNotFound {
                    id: policy_id.into(),
                })?;
        for op in &request.operations {
            let granted = engine
                .check_blocking(
                    policy_id,
                    &op.object.resource,
                    &op.object.id,
                    &op.permission,
                    &request.actor.0,
                )
                .map_err(|error| budget.evaluation_error(error))?;
            if !granted {
                if decision {
                    return Err(AcpError::Unauthorized {
                        reason: format!(
                            "actor {} denied {} on {}:{}",
                            request.actor.0, op.permission, op.object.resource, op.object.id
                        ),
                    });
                }
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Validate a policy definition without storing it.
    #[allow(unused_variables)]
    pub fn query_validate_policy(
        &self,
        policy: &str,
        marshal_type: PolicyMarshalingType,
    ) -> Result<(bool, String, Policy)> {
        match Self::validate_policy_definition(policy, marshal_type) {
            Ok(built) => Ok((true, String::new(), built)),
            Err(error) => Ok((false, error.to_string(), Policy::new("", ""))),
        }
    }

    /// Compile a policy definition without reading or changing module state.
    pub fn validate_policy_definition(
        policy: &str,
        marshal_type: PolicyMarshalingType,
    ) -> Result<Policy> {
        Self::compile_policy(policy, &marshal_type, 0, None)
    }

    fn compile_policy(
        policy: &str,
        marshal_type: &PolicyMarshalingType,
        counter: u64,
        original_specification: Option<PolicySpecification>,
    ) -> Result<Policy> {
        if policy.len() > MAX_POLICY_DEFINITION_BYTES {
            return Err(AcpError::InvalidPolicy {
                reason: "policy definition exceeds 64 KiB".into(),
            });
        }
        let mut parsed = match marshal_type {
            PolicyMarshalingType::ShortYaml => policy_yaml::parse_policy_yaml(policy)
                .map_err(|reason| AcpError::InvalidPolicy { reason })?,
            PolicyMarshalingType::ShortJson => {
                serde_json::from_str::<policy_yaml::ParsedPolicy>(policy).map_err(|error| {
                    AcpError::InvalidPolicy {
                        reason: format!("invalid policy JSON: {error}"),
                    }
                })?
            }
            PolicyMarshalingType::Unknown => {
                return Err(AcpError::InvalidPolicy {
                    reason: "unknown policy marshal type".into(),
                });
            }
        };
        if let Some(specification) = original_specification {
            if parsed.spec != PolicySpecification::None && parsed.spec != specification {
                return Err(AcpError::InvalidPolicy {
                    reason: "policy specification differs from the required specification".into(),
                });
            }
            parsed.spec = specification;
        }
        let built = policy_yaml::build_policy(&parsed, counter).map_err(|error| {
            AcpError::InvalidPolicy {
                reason: error.to_string(),
            }
        })?;
        built.validate().map_err(|error| AcpError::InvalidPolicy {
            reason: error.to_string(),
        })?;
        Ok(built)
    }

    /// Fetch a previously recorded access decision by ID.
    #[allow(unused_variables)]
    pub fn query_access_decision(&self, id: &str) -> Result<Option<AccessDecision>> {
        self.get_access_decision(id)
    }

    /// Check if an object is registered and return its owner.
    #[allow(unused_variables)]
    pub fn query_object_owner(
        &self,
        policy_id: &str,
        object: &Object,
    ) -> Result<(bool, Option<RelationshipRecord>)> {
        if self.get_policy_record(policy_id)?.is_none() {
            return Ok((false, None));
        }
        let owner_rec = self.registration_owner_record(policy_id, object)?;

        match owner_rec {
            Some(rec) if !rec.archived => Ok((true, Some(rec))),
            _ => Ok((false, None)),
        }
    }

    /// Fetch a registration commitment by its autoincrement ID.
    #[allow(unused_variables)]
    pub fn query_registrations_commitment(&self, id: u64) -> Result<RegistrationsCommitment> {
        let record = self
            .get_commitment_by_id(id)?
            .ok_or(AcpError::CommitmentNotFound { id })?;
        if self.get_policy_record(&record.policy_id)?.is_none() {
            return Err(AcpError::CommitmentNotFound { id });
        }
        Ok(record)
    }

    /// Find registration commitments matching a commitment byte value.
    #[allow(unused_variables)]
    pub fn query_registrations_commitment_by_commitment(
        &self,
        commitment: &[u8],
    ) -> Result<Vec<RegistrationsCommitment>> {
        self.filter_commitments_by_commitment(commitment)
    }

    /// Generate a Merkle commitment and per-object proofs.
    #[allow(unused_variables)]
    pub fn query_generate_commitment(
        &self,
        policy_id: &str,
        objects: &[Object],
        actor: &types::Actor,
    ) -> Result<GenerateCommitmentResult> {
        Self::validate_commitment_input(policy_id, objects, actor.0.as_str())?;

        if !self.zanzibar_policies.contains_key(policy_id) {
            return Err(AcpError::PolicyNotFound {
                id: policy_id.to_string(),
            });
        }

        for obj in objects {
            self.validate_registration_object(policy_id, obj)?;
            self.ensure_object_unregistered(policy_id, obj)?;
        }

        Self::generate_registration_commitment(policy_id, objects, actor)
    }

    /// List amendment events flagged as hijack attempts for a policy.
    #[allow(unused_variables)]
    pub fn query_hijack_attempts_by_policy(&self, policy_id: &str) -> Result<Vec<AmendmentEvent>> {
        if self.get_policy_record(policy_id)?.is_none() {
            return Ok(Vec::new());
        }
        self.list_hijack_events_by_policy(policy_id)
    }

    /// Return current module parameters.
    pub fn query_params(&self) -> Result<AcpParams> {
        self.get_params()
    }

    // ── Lifecycle hooks ─────────────────────────────────────────────────

    /// End-of-block hook: flag expired registration commitments.
    pub fn end_blocker(
        &mut self,
        block_ctx: &BlockExecCtx,
    ) -> Result<Vec<RegistrationsCommitment>> {
        let mut candidate = self.clone();
        candidate.prune_operations(block_ctx.timestamp.seconds)?;
        let expired = candidate.expire_commitments(&block_ctx.timestamp)?;
        let mut budget = retirement_cleanup::Budget::new();
        if block_ctx.timestamp.block_height.is_multiple_of(2) {
            candidate.collect_retired_policies(&mut budget)?;
            candidate.collect_retired_relations(&mut budget)?;
        } else {
            candidate.collect_retired_relations(&mut budget)?;
            candidate.collect_retired_policies(&mut budget)?;
        }
        *self = candidate;
        Ok(expired)
    }

    // ── Storage access methods ──────────────────────────────────────────

    // ── Storage — Policy records ─────────────────────────────────────────

    fn get_policy_record(&self, id: &str) -> Result<Option<PolicyRecord>> {
        self.store
            .get_ref(&keys::policy_key(id))
            .map(|bytes| Self::decode_policy_record(id, bytes))
            .transpose()
    }

    fn decode_policy_record(id: &str, bytes: &[u8]) -> Result<PolicyRecord> {
        let record: PolicyRecord = serde_json::from_slice(bytes)
            .map_err(|error| AcpError::State(format!("invalid policy record: {error}")))?;
        if record.policy.id != id {
            return Err(AcpError::State("policy record identity mismatch".into()));
        }
        record
            .relations
            .validate(&record.policy)
            .map_err(relation_state_error)?;
        Ok(record)
    }

    fn set_policy_record(&mut self, id: &str, record: &PolicyRecord) {
        let bytes = serde_json::to_vec(record).expect("serialize PolicyRecord");
        self.store.put(&keys::policy_key(id), bytes);
    }

    fn next_policy_counter(&self) -> Result<u64> {
        let counter = self
            .store
            .get(keys::POLICY_COUNTER_KEY)
            .map(|bytes| {
                bytes.try_into().map(u64::from_be_bytes).map_err(|_| {
                    AcpError::State("policy counter must contain exactly 8 bytes".into())
                })
            })
            .transpose()?
            .unwrap_or(0);
        counter
            .checked_add(1)
            .ok_or_else(|| AcpError::State("policy counter exhausted".into()))
    }

    // ── Storage — Relationships ──────────────────────────────────────────

    fn get_relationship(
        &self,
        policy_id: &str,
        relationship: &Relationship,
    ) -> Result<Option<RelationshipRecord>> {
        let Some(policy) = self.get_policy_record(policy_id)? else {
            return Ok(None);
        };
        let Ok(pair) = policy.relations.pair(relationship) else {
            return Ok(None);
        };
        let key = keys::relationship_generation_key(
            policy_id,
            pair,
            &keys::relationship_storage_key(relationship),
        );
        self.store
            .get_ref(&key)
            .map(|bytes| {
                let record: RelationshipRecord = serde_json::from_slice(bytes)
                    .map_err(|e| AcpError::State(format!("invalid relationship record: {e}")))?;
                if record.policy_id != policy_id
                    || record.relationship != *relationship
                    || record.generations != pair
                {
                    return Err(AcpError::State(
                        "relationship record identity mismatch".into(),
                    ));
                }
                Ok(record)
            })
            .transpose()
    }

    fn relationship_pair(&self, policy: &str, relationship: &Relationship) -> Result<RelationPair> {
        self.query_policy(policy)?
            .relations
            .pair(relationship)
            .map_err(relation_state_error)
    }

    fn set_relationship(&mut self, record: &RelationshipRecord) -> Result<()> {
        relationship_mutations::put(&mut self.store, record).map_err(relation_state_error)
    }

    fn remove_relationship_key(&mut self, key: &[u8]) -> Result<()> {
        relationship_mutations::remove(&mut self.store, key).map_err(relation_state_error)
    }

    #[cfg(test)]
    fn has_relationship(&self, policy_id: &str, storage_key: &str) -> bool {
        self.store
            .has(&keys::relationship_key(policy_id, storage_key))
    }

    // ── Storage — Params ─────────────────────────────────────────────────

    fn get_params(&self) -> Result<AcpParams> {
        self.store.get_ref(keys::PARAMS_KEY).map_or_else(
            || Ok(AcpParams::default()),
            |bytes| {
                borsh::from_slice(bytes)
                    .map_err(|e| AcpError::State(format!("invalid ACP parameters: {e}")))
            },
        )
    }

    #[allow(unused_variables)]
    pub(crate) fn set_params(&mut self, params: &AcpParams) -> Result<()> {
        let bytes =
            borsh::to_vec(params).map_err(|e| AcpError::State(format!("serialize params: {e}")))?;
        self.store.put(keys::PARAMS_KEY, bytes);
        Ok(())
    }

    // ── Storage — Replay cache ───────────────────────────────────────────

    // ── Storage — Access decisions ───────────────────────────────────────

    fn get_access_decision(&self, id: &str) -> Result<Option<AccessDecision>> {
        self.store
            .get_ref(&keys::access_decision_key(id))
            .map(|bytes| {
                let decision = AccessDecision::decode_record(bytes)?;
                if decision.id != id {
                    return Err(AcpError::State("access decision identity mismatch".into()));
                }
                Ok(decision)
            })
            .transpose()
    }

    // ── Storage — Commitments ────────────────────────────────────────────

    #[cfg(test)]
    fn commitment_objs_prefix() -> Vec<u8> {
        [keys::COMMITMENT_PREFIX, keys::OBJS_SUBPREFIX].concat()
    }

    #[allow(unused_variables)]
    fn create_commitment(&mut self, commitment: &mut RegistrationsCommitment) -> Result<()> {
        let counter = self
            .store
            .get(&keys::commitment_counter_key())
            .map(|bytes| {
                bytes
                    .try_into()
                    .map(u64::from_be_bytes)
                    .map_err(|_| AcpError::State("invalid record counter".into()))
            })
            .transpose()?
            .unwrap_or(0);
        let next = counter
            .checked_add(1)
            .ok_or_else(|| AcpError::State("record counter exhausted".into()))?;
        if self.store.has(&keys::commitment_key(next)) {
            return Err(AcpError::State(
                "commitment identifier already exists".into(),
            ));
        }
        commitment.id = next;
        self.update_commitment(commitment)?;
        self.store
            .put(&keys::commitment_counter_key(), next.to_be_bytes().to_vec());
        Ok(())
    }

    fn update_commitment(&mut self, commitment: &RegistrationsCommitment) -> Result<()> {
        let bytes = borsh::to_vec(commitment)
            .map_err(|e| AcpError::State(format!("serialize commitment: {e}")))?;
        if let Some(previous) = self.get_commitment_by_id(commitment.id)? {
            self.store.delete(&Self::commitment_expiry_key(&previous));
            self.store.delete(&keys::commitment_by_commitment_index_key(
                &previous.commitment,
                previous.id,
            ));
            self.store.delete(&keys::commitment_policy_index_key(
                &previous.policy_id,
                previous.id,
            ));
        }
        if !commitment.expired {
            self.store
                .put(&Self::commitment_expiry_key(commitment), Vec::new());
        }
        self.store.put(
            &keys::commitment_by_commitment_index_key(&commitment.commitment, commitment.id),
            Vec::new(),
        );
        self.store.put(
            &keys::commitment_policy_index_key(&commitment.policy_id, commitment.id),
            Vec::new(),
        );
        self.store.put(&keys::commitment_key(commitment.id), bytes);
        Ok(())
    }

    fn get_commitment_by_id(&self, id: u64) -> Result<Option<RegistrationsCommitment>> {
        self.store
            .get_ref(&keys::commitment_key(id))
            .map(|bytes| {
                let record: RegistrationsCommitment = borsh::from_slice(bytes)
                    .map_err(|error| AcpError::State(format!("invalid commitment: {error}")))?;
                if id == 0 || record.id != id || record.commitment.len() != 32 {
                    return Err(AcpError::State(
                        "commitment identity or root mismatch".into(),
                    ));
                }
                Ok(record)
            })
            .transpose()
    }

    // ── Storage — Amendment events ───────────────────────────────────────

    fn amendment_event_objs_prefix() -> Vec<u8> {
        [keys::AMENDMENT_EVENT_PREFIX, keys::OBJS_SUBPREFIX].concat()
    }

    #[allow(unused_variables)]
    fn create_amendment_event(&mut self, event: &mut AmendmentEvent) -> Result<()> {
        let counter = self
            .store
            .get(&keys::amendment_event_counter_key())
            .map(|bytes| {
                bytes
                    .try_into()
                    .map(u64::from_be_bytes)
                    .map_err(|_| AcpError::State("invalid record counter".into()))
            })
            .transpose()?
            .unwrap_or(0);
        let next = counter
            .checked_add(1)
            .ok_or_else(|| AcpError::State("record counter exhausted".into()))?;
        if self.store.has(&keys::amendment_event_key(next)) {
            return Err(AcpError::State(
                "amendment identifier already exists".into(),
            ));
        }
        event.id = next;
        let bytes = borsh::to_vec(event)
            .map_err(|e| AcpError::State(format!("serialize amendment event: {e}")))?;
        self.store.put(
            &keys::amendment_event_counter_key(),
            next.to_be_bytes().to_vec(),
        );
        self.store.put(&keys::amendment_event_key(event.id), bytes);
        self.store.put(
            &keys::amendment_event_policy_index_key(&event.policy_id, event.id),
            Vec::new(),
        );
        Ok(())
    }

    #[allow(unused_variables)]
    fn update_amendment_event(&mut self, event: &AmendmentEvent) -> Result<()> {
        let bytes = borsh::to_vec(event)
            .map_err(|e| AcpError::State(format!("serialize amendment event: {e}")))?;
        self.store.put(&keys::amendment_event_key(event.id), bytes);
        Ok(())
    }

    // ── PolicyCmd variant handlers ───────────────────────────────────────

    fn cmd_set_relationship(
        &mut self,
        creator: &Did,
        policy_id: &str,
        rel: Relationship,
    ) -> Result<PolicyCmdResult> {
        let policy = self
            .zanzibar_policies
            .get(policy_id)
            .cloned()
            .ok_or_else(|| AcpError::PolicyNotFound {
                id: policy_id.to_string(),
            })?;

        // Ownership is established at registration; an existing owner cannot mint
        // a second owner via set (matches defradb's owner-reservation guard).
        if rel.relation == "owner" {
            return Err(AcpError::Unauthorized {
                reason: "the owner relation cannot be set".into(),
            });
        }

        rel.validate(&policy)
            .map_err(|error| AcpError::InvalidAccessRequest {
                reason: error.to_string(),
            })?;

        if !self.is_authorized_to_manage(
            creator,
            policy_id,
            &policy,
            &rel.resource,
            &rel.object_id,
            &rel.relation,
        )? {
            return Err(AcpError::Unauthorized {
                reason: format!(
                    "{} is not authorized to set relation '{}' on '{}/{}'",
                    creator, rel.relation, rel.resource, rel.object_id
                ),
            });
        }

        if let Some(record) = self.get_relationship(policy_id, &rel)? {
            return Ok(PolicyCmdResult::SetRelationship {
                record_existed: true,
                record,
            });
        }

        let metadata = RecordMetadata {
            creation_ts: Timestamp::default(),
            tx_hash: Vec::new(),
            tx_signer: String::new(),
            owner_did: creator.to_string(),
        };

        let record = RelationshipRecord {
            generations: self.relationship_pair(policy_id, &rel)?,
            supplied_metadata: Default::default(),
            policy_id: policy_id.to_string(),
            relationship: rel,
            archived: false,
            metadata,
        };

        self.set_relationship(&record)?;

        Ok(PolicyCmdResult::SetRelationship {
            record_existed: false,
            record,
        })
    }

    fn cmd_delete_relationship(
        &mut self,
        creator: &Did,
        policy_id: &str,
        rel: Relationship,
    ) -> Result<PolicyCmdResult> {
        let policy = self
            .zanzibar_policies
            .get(policy_id)
            .cloned()
            .ok_or_else(|| AcpError::PolicyNotFound {
                id: policy_id.to_string(),
            })?;

        // Ownership is established at registration and cannot be stripped via a
        // relationship delete (matches defradb).
        if rel.relation == "owner" {
            return Err(AcpError::Unauthorized {
                reason: "the owner relation cannot be deleted".into(),
            });
        }

        // Revocation requires the same management authority as granting, so an
        // arbitrary signer cannot revoke a grant or strip a cross-object edge.
        if !self.is_authorized_to_manage(
            creator,
            policy_id,
            &policy,
            &rel.resource,
            &rel.object_id,
            &rel.relation,
        )? {
            return Err(AcpError::Unauthorized {
                reason: format!(
                    "{} is not authorized to delete relation '{}' on '{}/{}'",
                    creator, rel.relation, rel.resource, rel.object_id
                ),
            });
        }

        let existing = self.get_relationship(policy_id, &rel)?;
        let record_found = existing.is_some();
        if let Some(record) = existing {
            let key = keys::relationship_generation_key(
                policy_id,
                record.generations,
                &keys::relationship_storage_key(&record.relationship),
            );
            self.remove_relationship_key(&key)?;
        }

        Ok(PolicyCmdResult::DeleteRelationship { record_found })
    }

    fn ensure_object_unregistered(&self, policy_id: &str, obj: &Object) -> Result<()> {
        // Archiving preserves ownership; only unarchive may reactivate it.
        let owner_prefix = keys::relation_prefix(&obj.resource, &obj.id, "owner");
        let scan_prefix = keys::relationship_storage_prefix(policy_id, &owner_prefix);
        if self.store.prefix_iter(&scan_prefix).next().is_some() {
            return Err(AcpError::ObjectAlreadyRegistered {
                resource: obj.resource.clone(),
                object_id: obj.id.clone(),
            });
        }
        Ok(())
    }

    fn validate_registration_object(&self, policy_id: &str, obj: &Object) -> Result<()> {
        let policy =
            self.zanzibar_policies
                .get(policy_id)
                .ok_or_else(|| AcpError::PolicyNotFound {
                    id: policy_id.to_string(),
                })?;

        if policy
            .actor
            .as_ref()
            .is_some_and(|actor| actor.name == obj.resource)
        {
            return Err(AcpError::Unauthorized {
                reason: "actor records cannot be registered as objects".into(),
            });
        }
        if policy.get_resource(&obj.resource).is_none() {
            return Err(AcpError::InvalidAccessRequest {
                reason: format!("resource '{}' not defined in policy", obj.resource),
            });
        }

        Ok(())
    }

    fn cmd_register_object(
        &mut self,
        creator: &Did,
        policy_id: &str,
        obj: Object,
    ) -> Result<PolicyCmdResult> {
        self.validate_registration_object(policy_id, &obj)?;

        self.ensure_object_unregistered(policy_id, &obj)?;

        let owner_rel = Relationship::with_entity(obj.resource, obj.id, "owner", creator.clone());

        let metadata = RecordMetadata {
            creation_ts: Timestamp::default(),
            tx_hash: Vec::new(),
            tx_signer: String::new(),
            owner_did: creator.to_string(),
        };

        let record = RelationshipRecord {
            generations: self.relationship_pair(policy_id, &owner_rel)?,
            supplied_metadata: Default::default(),
            policy_id: policy_id.to_string(),
            relationship: owner_rel,
            archived: false,
            metadata,
        };

        self.set_relationship(&record)?;

        Ok(PolicyCmdResult::RegisterObject { record })
    }

    fn cmd_unarchive_object(
        &mut self,
        creator: &Did,
        policy_id: &str,
        obj: Object,
    ) -> Result<PolicyCmdResult> {
        if !self.zanzibar_policies.contains_key(policy_id) {
            return Err(AcpError::PolicyNotFound {
                id: policy_id.into(),
            });
        }
        let mut rec = self
            .registration_owner_record(policy_id, &obj)?
            .ok_or_else(|| AcpError::ObjectNotRegistered {
                resource: obj.resource.clone(),
                object_id: obj.id.clone(),
            })?;

        if rec.metadata.owner_did != creator.to_string() {
            return Err(AcpError::Unauthorized {
                reason: format!(
                    "{} is not the previous owner of '{}/{}'",
                    creator, obj.resource, obj.id
                ),
            });
        }

        let was_archived = rec.archived;
        rec.archived = false;

        self.set_relationship(&rec)?;

        Ok(PolicyCmdResult::UnarchiveObject {
            record: rec,
            relationship_modified: was_archived,
        })
    }

    fn cmd_commit_registrations(
        &mut self,
        creator: &Did,
        policy_id: &str,
        commitment: Vec<u8>,
    ) -> Result<PolicyCmdResult> {
        if !self.zanzibar_policies.contains_key(policy_id) {
            return Err(AcpError::PolicyNotFound {
                id: policy_id.to_string(),
            });
        }

        if commitment.len() != 32 {
            return Err(AcpError::InvalidProof {
                reason: format!(
                    "commitment must be exactly 32 bytes, got {}",
                    commitment.len()
                ),
            });
        }

        let params = self.get_params()?;

        let metadata = RecordMetadata {
            creation_ts: Timestamp::default(),
            tx_hash: Vec::new(),
            tx_signer: String::new(),
            owner_did: creator.to_string(),
        };

        let mut reg_commitment = RegistrationsCommitment {
            id: 0,
            policy_id: policy_id.to_string(),
            commitment,
            expired: false,
            validity: params.registrations_commitment_validity,
            metadata,
        };

        self.create_commitment(&mut reg_commitment)?;

        Ok(PolicyCmdResult::CommitRegistrations {
            registrations_commitment: reg_commitment,
        })
    }

    fn cmd_reveal_registration(
        &mut self,
        creator: &Did,
        policy_id: &str,
        commitment_id: u64,
        proof: RegistrationProof,
    ) -> Result<PolicyCmdResult> {
        self.validate_registration_object(policy_id, &proof.object)?;
        let commitment = self
            .get_commitment_by_id(commitment_id)?
            .ok_or(AcpError::CommitmentNotFound { id: commitment_id })?;

        if commitment.expired {
            return Err(AcpError::CommitmentExpired { id: commitment_id });
        }

        if commitment.policy_id != policy_id {
            return Err(AcpError::InvalidProof {
                reason: "registration commitment belongs to another policy".into(),
            });
        }

        let leaf_data = Self::registration_leaf(policy_id, &proof.object, creator.as_str())?;
        let valid_proof = Self::verify_merkle_proof(&commitment.commitment, &proof, &leaf_data);
        if !valid_proof {
            return Err(AcpError::InvalidProof {
                reason: "Merkle proof verification failed".into(),
            });
        }

        let (already_registered, existing_owner) =
            self.query_object_owner(policy_id, &proof.object)?;

        let metadata = RecordMetadata {
            creation_ts: Timestamp::default(),
            tx_hash: Vec::new(),
            tx_signer: String::new(),
            owner_did: creator.to_string(),
        };

        if !already_registered {
            self.ensure_object_unregistered(policy_id, &proof.object)?;
            // New registration — creator becomes owner.
            let owner_rel = Relationship::with_entity(
                proof.object.resource.clone(),
                proof.object.id,
                "owner",
                creator.clone(),
            );
            let record = RelationshipRecord {
                generations: self.relationship_pair(policy_id, &owner_rel)?,
                supplied_metadata: Default::default(),
                policy_id: policy_id.to_string(),
                relationship: owner_rel,
                archived: false,
                metadata,
            };
            self.set_relationship(&record)?;

            return Ok(PolicyCmdResult::RevealRegistration {
                record,
                event: None,
            });
        }

        // Object already registered — check if commitment is older than registration.
        let existing = existing_owner.unwrap();
        let registration_height = existing.metadata.creation_ts.block_height;
        let commitment_height = commitment.metadata.creation_ts.block_height;

        if commitment_height > registration_height {
            return Err(AcpError::InvalidProof {
                reason: "commitment is newer than the existing registration; cannot amend".into(),
            });
        }

        // Amend ownership — transfer to creator.
        let previous_owner_did = Did::new(&existing.metadata.owner_did)
            .map_err(|_| AcpError::State("stored owner DID is invalid".into()))?;

        let amended_rel = Relationship::with_entity(
            proof.object.resource.clone(),
            proof.object.id.clone(),
            "owner",
            creator.clone(),
        );
        let record = RelationshipRecord {
            generations: self.relationship_pair(policy_id, &amended_rel)?,
            supplied_metadata: Default::default(),
            policy_id: policy_id.to_string(),
            relationship: amended_rel,
            archived: false,
            metadata: metadata.clone(),
        };

        let mut event = AmendmentEvent {
            id: 0,
            policy_id: policy_id.to_string(),
            object: proof.object,
            new_owner: Actor(creator.clone()),
            previous_owner: Actor(previous_owner_did),
            commitment_id,
            hijack_flag: false,
            metadata,
        };

        self.create_amendment_event(&mut event)?;
        self.remove_relationship_key(&keys::relationship_generation_key(
            policy_id,
            existing.generations,
            &keys::relationship_storage_key(&existing.relationship),
        ))?;
        self.set_relationship(&record)?;

        Ok(PolicyCmdResult::RevealRegistration {
            record,
            event: Some(event),
        })
    }

    fn cmd_flag_hijack_attempt(
        &mut self,
        creator: &Did,
        policy_id: &str,
        event_id: u64,
    ) -> Result<PolicyCmdResult> {
        let mut event = self
            .get_amendment_event_by_id(event_id)?
            .ok_or(AcpError::State(format!(
                "amendment event {event_id} not found"
            )))?;

        if event.policy_id != policy_id {
            return Err(AcpError::Unauthorized {
                reason: "amendment event belongs to another policy".into(),
            });
        }

        if event.new_owner.0.to_string() != creator.to_string() {
            return Err(AcpError::Unauthorized {
                reason: "only the new owner can flag a hijack attempt".into(),
            });
        }

        event.hijack_flag = true;
        self.update_amendment_event(&event)?;

        Ok(PolicyCmdResult::FlagHijackAttempt { event })
    }

    // ── Permission evaluation ────────────────────────────────────────────

    /// Pin one bounded module snapshot for every operation in the request.
    fn permission_engine(
        &self,
        policy: &Policy,
    ) -> PermissionEngine<QmdbZanzibarStore<read_capture::ReadCapture>> {
        let capture = read_capture::ReadCapture::new(
            self.store.clone(),
            read_capture::PERMISSION_READ_LIMITS,
        );
        let mut engine = PermissionEngine::new(Arc::new(QmdbZanzibarStore::new(capture)));
        engine.add_policy(policy);
        engine
    }

    // ── Relationship selector matching ───────────────────────────────────

    fn matches_selector(&self, rec: &RelationshipRecord, sel: &RelationshipSelector) -> bool {
        let rel = &rec.relationship;

        // Object selector.
        if let Some(obj_sel) = &sel.object_selector {
            let matches = match obj_sel {
                ObjectSelector::Exact(obj) => {
                    rel.resource == obj.resource && rel.object_id == obj.id
                }
                ObjectSelector::Wildcard => true,
                ObjectSelector::ResourcePredicate(resource) => &rel.resource == resource,
            };
            if !matches {
                return false;
            }
        }

        // Relation selector.
        if let Some(rel_sel) = &sel.relation_selector {
            let matches = match rel_sel {
                RelationSelector::Exact(name) => &rel.relation == name,
                RelationSelector::Wildcard => true,
            };
            if !matches {
                return false;
            }
        }

        // Subject selector.
        if let Some(subj_sel) = &sel.subject_selector {
            let matches = match subj_sel {
                SubjectSelector::Exact(expected) => &rel.subject == expected,
                SubjectSelector::Wildcard => true,
            };
            if !matches {
                return false;
            }
        }

        true
    }

    // ── RFC 6962 Merkle tree helpers ─────────────────────────────────────

    fn registration_leaf(policy: &str, object: &Object, actor: &str) -> Result<Vec<u8>> {
        let mut data = b"vera/registration-leaf/v1\0".to_vec();
        data.extend(
            borsh::to_vec(&(policy, &object.resource, &object.id, actor))
                .map_err(|error| AcpError::State(error.to_string()))?,
        );
        Ok(data)
    }

    fn compute_leaf_hash(data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([0x00u8]);
        h.update(data);
        h.finalize().into()
    }

    fn compute_inner_hash(left: &[u8], right: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([0x01u8]);
        h.update(left);
        h.update(right);
        h.finalize().into()
    }

    /// Build all levels of a binary Merkle tree (leaf to root).
    fn build_merkle_levels(leaf_hashes: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
        let mut levels: Vec<Vec<[u8; 32]>> = vec![leaf_hashes.to_vec()];

        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let mut next = Vec::new();
            let mut i = 0;
            while i < prev.len() {
                if i + 1 < prev.len() {
                    next.push(Self::compute_inner_hash(&prev[i], &prev[i + 1]));
                    i += 2;
                } else {
                    // Odd node — promote directly.
                    next.push(prev[i]);
                    i += 1;
                }
            }
            levels.push(next);
        }

        levels
    }

    /// Generate a Merkle audit proof (sibling hashes from leaf to root).
    fn generate_merkle_proof(leaf_index: usize, levels: &[Vec<[u8; 32]>]) -> Vec<Vec<u8>> {
        let mut proof = Vec::new();
        let mut idx = leaf_index;

        for level in &levels[..levels.len().saturating_sub(1)] {
            let sibling_idx = if idx.is_multiple_of(2) {
                idx + 1
            } else {
                idx - 1
            };
            if sibling_idx < level.len() {
                proof.push(level[sibling_idx].to_vec());
            }
            idx >>= 1;
        }

        proof
    }

    /// Verify an RFC 6962 Merkle audit proof.
    fn verify_merkle_proof(root: &[u8], proof: &RegistrationProof, leaf_data: &[u8]) -> bool {
        if root.len() != 32
            || proof.leaf_count == 0
            || proof.leaf_index >= proof.leaf_count
            || proof.merkle_proof.len() > 64
            || proof.merkle_proof.iter().any(|sibling| sibling.len() != 32)
        {
            return false;
        }
        let mut current = Self::compute_leaf_hash(leaf_data);
        let mut index = proof.leaf_index;
        let mut width = proof.leaf_count;
        let mut siblings = proof.merkle_proof.iter();
        while width > 1 {
            if !index.is_multiple_of(2) {
                let Some(sibling) = siblings.next() else {
                    return false;
                };
                current = Self::compute_inner_hash(sibling, &current);
            } else if index + 1 < width {
                let Some(sibling) = siblings.next() else {
                    return false;
                };
                current = Self::compute_inner_hash(&current, sibling);
            }
            index /= 2;
            width = width.div_ceil(2);
        }
        siblings.next().is_none() && current.as_slice() == root
    }
}

#[cfg(test)]
mod policy_edit_tests;
#[cfg(test)]
mod policy_validation_tests;
#[cfg(test)]
mod registration_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use identity::Did;

    fn alice() -> Did {
        Did::new("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap()
    }

    fn bob() -> Did {
        Did::new("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH").unwrap()
    }

    const SIMPLE_POLICY: &str = r#"
name: test-policy
description: A simple test policy
resources:
  - name: document
    relations:
      - name: reader
    permissions:
      - name: read
        expr: reader
"#;

    #[test]
    fn create_policy_roundtrip() {
        let mut module = AcpModule::new();
        let creator = alice();

        let record = module
            .create_policy(&creator, SIMPLE_POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();

        assert!(!record.policy.id.is_empty());
        assert_eq!(record.policy.name, "test-policy");
        assert_eq!(record.metadata.owner_did, creator.to_string());

        let fetched = module.query_policy(&record.policy.id).unwrap();
        assert_eq!(fetched.policy.id, record.policy.id);
    }

    #[test]
    fn query_policy_ids_returns_all() {
        let mut module = AcpModule::new();
        let creator = alice();

        let r1 = module
            .create_policy(&creator, SIMPLE_POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();

        let second_policy = r#"
name: second-policy
resources:
  - name: file
    relations:
      - name: reader
    permissions:
      - name: view
        expr: reader
"#;
        let r2 = module
            .create_policy(&creator, second_policy, PolicyMarshalingType::ShortYaml)
            .unwrap();

        let ids = module.query_policy_ids().unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&r1.policy.id));
        assert!(ids.contains(&r2.policy.id));
    }

    #[test]
    fn policy_not_found_error() {
        let module = AcpModule::new();
        let err = module.query_policy("nonexistent").unwrap_err();
        assert!(matches!(err, AcpError::PolicyNotFound { .. }));
    }

    #[test]
    fn relationship_keys_isolate_path_fields() {
        let mut module = AcpModule::new();
        let policy = module
            .create_policy(&alice(), SIMPLE_POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap()
            .policy
            .id;
        for (id, actor) in [("parent", alice()), ("parent/path", bob())] {
            module
                .direct_policy_cmd(
                    &actor,
                    &policy,
                    PolicyCmd::RegisterObject(Object {
                        resource: "document".into(),
                        id: id.into(),
                    }),
                )
                .unwrap();
        }
        let original = Relationship::with_entity("document", "parent/path", "reader", bob());
        let collision = Relationship::with_entity("document", "parent", "path/reader", bob());
        assert_eq!(original.storage_key(), collision.storage_key());
        module
            .direct_policy_cmd(&bob(), &policy, PolicyCmd::SetRelationship(original))
            .unwrap();
        for mut candidate in [
            module.clone(),
            AcpModule::from_store(InMemoryKvStore::deserialize(&module.store.serialize()).unwrap()),
        ] {
            let before = candidate.store.serialize();
            for command in [
                PolicyCmd::SetRelationship(collision.clone()),
                PolicyCmd::DeleteRelationship(collision.clone()),
            ] {
                candidate
                    .direct_policy_cmd(&alice(), &policy, command)
                    .unwrap_err();
            }
            assert_eq!(candidate.store.serialize(), before);
        }
    }

    #[test]
    fn set_relationship_and_filter() {
        let mut module = AcpModule::new();
        let creator = alice();
        let reader = bob();

        let record = module
            .create_policy(&creator, SIMPLE_POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();
        let policy_id = &record.policy.id;

        // Register object so creator has owner relation.
        let obj = Object {
            resource: "document".into(),
            id: "doc1".into(),
        };
        module
            .direct_policy_cmd(&creator, policy_id, PolicyCmd::RegisterObject(obj))
            .unwrap();

        // Set reader relation for bob.
        let rel = Relationship::with_entity("document", "doc1", "reader", reader);
        let result = module
            .direct_policy_cmd(&creator, policy_id, PolicyCmd::SetRelationship(rel))
            .unwrap();

        assert!(matches!(
            result,
            PolicyCmdResult::SetRelationship {
                record_existed: false,
                ..
            }
        ));

        // Filter by exact relation.
        let selector = RelationshipSelector {
            relation_selector: Some(RelationSelector::Exact("reader".into())),
            ..Default::default()
        };
        let rels = module
            .query_filter_relationships(policy_id, &selector)
            .unwrap();
        assert_eq!(rels.len(), 1);
        assert_eq!(rels[0].relationship.relation, "reader");
    }

    #[test]
    fn register_object_and_query_owner() {
        let mut module = AcpModule::new();
        let creator = alice();

        let record = module
            .create_policy(&creator, SIMPLE_POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();
        let policy_id = &record.policy.id;

        let obj = Object {
            resource: "document".into(),
            id: "doc42".into(),
        };

        let result = module
            .direct_policy_cmd(&creator, policy_id, PolicyCmd::RegisterObject(obj.clone()))
            .unwrap();
        assert!(matches!(result, PolicyCmdResult::RegisterObject { .. }));

        let (found, owner) = module.query_object_owner(policy_id, &obj).unwrap();
        assert!(found);
        let owner_rec = owner.unwrap();
        assert_eq!(owner_rec.metadata.owner_did, creator.to_string());
        assert_eq!(owner_rec.relationship.relation, "owner");
    }

    #[test]
    fn register_object_twice_fails() {
        let mut module = AcpModule::new();
        let creator = alice();

        let record = module
            .create_policy(&creator, SIMPLE_POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();
        let policy_id = &record.policy.id;

        let obj = Object {
            resource: "document".into(),
            id: "dup".into(),
        };
        module
            .direct_policy_cmd(&creator, policy_id, PolicyCmd::RegisterObject(obj.clone()))
            .unwrap();

        let err = module
            .direct_policy_cmd(&creator, policy_id, PolicyCmd::RegisterObject(obj))
            .unwrap_err();
        assert!(matches!(err, AcpError::ObjectAlreadyRegistered { .. }));
    }

    fn decision_block() -> BlockExecCtx {
        BlockExecCtx {
            deployment_id: 9001,
            timestamp: Timestamp {
                seconds: 1000,
                block_height: 5,
            },
            ..Default::default()
        }
    }

    fn decision_tx(creator: &Did) -> TxExecCtx {
        TxExecCtx {
            sequence: 7,
            tx_hash: vec![1; 32],
            signer: creator.to_string(),
        }
    }

    #[test]
    fn permission_materialization_errors_do_not_issue_decisions() {
        let mut module = AcpModule::new();
        let creator = alice();
        let policy = module
            .create_policy(&creator, SIMPLE_POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();
        let relationship =
            Relationship::with_entity("document", "large", "reader", creator.clone());
        let generations = policy.relations.pair(&relationship).unwrap();
        let key = keys::relationship_generation_key(
            &policy.policy.id,
            generations,
            &keys::relationship_storage_key(&relationship),
        );
        module
            .set_relationship(&RelationshipRecord {
                generations,
                supplied_metadata: Default::default(),
                policy_id: policy.policy.id.clone(),
                relationship,
                archived: false,
                metadata: policy.metadata.clone(),
            })
            .unwrap();
        let mut request = AccessRequest {
            operations: vec![types::Operation {
                object: Object {
                    resource: "document".into(),
                    id: "large".into(),
                },
                permission: "read".into(),
            }],
            actor: Actor(creator.clone()),
        };
        // No owner record can bypass the reader bucket. Establish that the
        // indexed current-generation grant is reachable before corrupting it.
        assert!(
            module
                .query_verify_access_request(&policy.policy.id, &request)
                .unwrap()
        );
        module.store.put(
            &key,
            vec![b' '; read_capture::PERMISSION_READ_LIMITS.bytes + 1],
        );
        let before = module.store.serialize();
        for result in [
            module
                .query_verify_access_request(&policy.policy.id, &request)
                .map(|_| ()),
            module
                .check_access(
                    &creator,
                    &policy.policy.id,
                    &request,
                    &decision_block(),
                    &decision_tx(&creator),
                )
                .map(|_| ()),
        ] {
            assert!(
                matches!(result, Err(AcpError::State(ref message)) if message.contains("read budget exceeded")),
                "{result:?}"
            );
        }
        request.actor = Actor(bob());
        assert!(
            matches!(module.query_verify_access_request(&policy.policy.id, &request),
            Err(AcpError::State(ref message)) if message.contains("read budget exceeded"))
        );
        assert_eq!(module.store.serialize(), before);
    }

    #[test]
    fn check_access_owner_granted() {
        let mut module = AcpModule::new();
        let creator = alice();

        let record = module
            .create_policy(&creator, SIMPLE_POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();
        let policy_id = &record.policy.id;

        let obj = Object {
            resource: "document".into(),
            id: "docA".into(),
        };
        module
            .direct_policy_cmd(&creator, policy_id, PolicyCmd::RegisterObject(obj.clone()))
            .unwrap();

        let access_request = AccessRequest {
            operations: vec![types::Operation {
                object: obj,
                permission: "read".into(),
            }],
            actor: Actor(creator.clone()),
        };

        let decision = module
            .check_access(
                &creator,
                policy_id,
                &access_request,
                &decision_block(),
                &decision_tx(&creator),
            )
            .unwrap();
        assert_eq!(decision.policy_id, *policy_id);
        assert_eq!(decision.actor, creator.to_string());
        assert_eq!(decision.creator_acc_sequence, 7);
        assert_eq!(decision.issued_height, 5);
        assert_eq!(decision.creation_time, decision_block().timestamp);
        let mut next = decision_tx(&creator);
        next.sequence += 1;
        let renewed = module
            .check_access(
                &creator,
                policy_id,
                &access_request,
                &decision_block(),
                &next,
            )
            .unwrap();
        assert_ne!(renewed.id, decision.id);
        assert_eq!(
            module.query_access_decision(&decision.id).unwrap(),
            Some(decision)
        );
        let before = module.store().clone();
        let empty = AccessRequest {
            actor: access_request.actor.clone(),
            operations: vec![],
        };
        assert!(
            module
                .check_access(&creator, policy_id, &empty, &decision_block(), &next)
                .is_err()
        );
        assert_eq!(module.store().prefix_scan(b""), before.prefix_scan(b""));
    }

    #[test]
    fn check_access_reader_granted() {
        let mut module = AcpModule::new();
        let creator = alice();
        let reader = bob();

        let record = module
            .create_policy(&creator, SIMPLE_POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();
        let policy_id = &record.policy.id;

        let obj = Object {
            resource: "document".into(),
            id: "docB".into(),
        };
        module
            .direct_policy_cmd(&creator, policy_id, PolicyCmd::RegisterObject(obj.clone()))
            .unwrap();

        // Grant reader relation to bob.
        let rel = Relationship::with_entity("document", "docB", "reader", reader.clone());
        module
            .direct_policy_cmd(&creator, policy_id, PolicyCmd::SetRelationship(rel))
            .unwrap();

        let access_request = AccessRequest {
            operations: vec![types::Operation {
                object: obj,
                permission: "read".into(),
            }],
            actor: Actor(reader),
        };

        let result = module
            .query_verify_access_request(policy_id, &access_request)
            .unwrap();
        assert!(result);
    }

    #[test]
    fn check_access_denied_for_unknown_actor() {
        let mut module = AcpModule::new();
        let creator = alice();
        let stranger = bob();

        let record = module
            .create_policy(&creator, SIMPLE_POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();
        let policy_id = &record.policy.id;

        let obj = Object {
            resource: "document".into(),
            id: "docC".into(),
        };
        module
            .direct_policy_cmd(&creator, policy_id, PolicyCmd::RegisterObject(obj.clone()))
            .unwrap();

        let access_request = AccessRequest {
            operations: vec![types::Operation {
                object: obj,
                permission: "read".into(),
            }],
            actor: Actor(stranger),
        };

        let err = module
            .check_access(
                &creator,
                policy_id,
                &access_request,
                &decision_block(),
                &decision_tx(&creator),
            )
            .unwrap_err();
        assert!(matches!(err, AcpError::Unauthorized { .. }));
    }

    #[test]
    fn unauthenticated_parameter_update_is_rejected() {
        let mut module = AcpModule::new();
        let authority = alice();

        let params = AcpParams {
            policy_command_max_expiration_delta: 43200,
            registrations_commitment_validity: crate::types::Duration::Seconds(600),
        };

        assert!(module.update_params(&authority, params).is_err());

        let fetched = module.query_params().unwrap();
        assert_eq!(fetched, AcpParams::default());
    }

    #[test]
    fn end_blocker_flags_expired_commitments() {
        let mut module = AcpModule::new();
        let creator = alice();

        // Create a policy to hold the commitment.
        let record = module
            .create_policy(&creator, SIMPLE_POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();
        let policy_id = &record.policy.id;

        // Commit with 10-second validity.
        let commitment_bytes = vec![0xABu8; 32];
        let mut commitment = RegistrationsCommitment {
            id: 0,
            policy_id: policy_id.clone(),
            commitment: commitment_bytes,
            expired: false,
            validity: Duration::Seconds(10),
            metadata: RecordMetadata {
                creation_ts: Timestamp {
                    seconds: 100,
                    block_height: 5,
                },
                tx_hash: Vec::new(),
                tx_signer: String::new(),
                owner_did: creator.to_string(),
            },
        };
        module.create_commitment(&mut commitment).unwrap();

        // Block context: time = 200 (> 100 + 10).
        let block_ctx = BlockExecCtx {
            genesis_id: [0; 32],
            deployment_id: 9001,
            timestamp: Timestamp {
                seconds: 200,
                block_height: 20,
            },
        };

        let flagged = module.end_blocker(&block_ctx).unwrap();
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].expired);

        // Verify the stored commitment is now expired.
        let stored = module
            .query_registrations_commitment(commitment.id)
            .unwrap();
        assert!(stored.expired);
    }

    #[test]
    fn query_validate_policy_valid() {
        let module = AcpModule::new();
        let (valid, msg, policy) = module
            .query_validate_policy(SIMPLE_POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();
        assert!(valid, "expected valid, got: {msg}");
        assert!(msg.is_empty());
        assert_eq!(policy.name, "test-policy");
    }

    #[test]
    fn query_validate_policy_invalid() {
        let module = AcpModule::new();
        let (valid, msg, _) = module
            .query_validate_policy("not: valid: yaml: policy", PolicyMarshalingType::ShortYaml)
            .unwrap();
        assert!(!valid);
        assert!(!msg.is_empty());
    }

    #[test]
    fn archive_and_unarchive_object() {
        let mut module = AcpModule::new();
        let creator = alice();

        let record = module
            .create_policy(&creator, SIMPLE_POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();
        let policy_id = &record.policy.id;

        let obj = Object {
            resource: "document".into(),
            id: "docD".into(),
        };
        module
            .direct_policy_cmd(&creator, policy_id, PolicyCmd::RegisterObject(obj.clone()))
            .unwrap();

        // Archive.
        let archive_result = module
            .direct_policy_cmd(&creator, policy_id, PolicyCmd::ArchiveObject(obj.clone()))
            .unwrap();
        assert!(matches!(
            archive_result,
            PolicyCmdResult::ArchiveObject { found: true, .. }
        ));

        // Owner query should return false (archived).
        let (found, _) = module.query_object_owner(policy_id, &obj).unwrap();
        assert!(!found);

        // Unarchive.
        let unarchive_result = module
            .direct_policy_cmd(&creator, policy_id, PolicyCmd::UnarchiveObject(obj.clone()))
            .unwrap();
        assert!(matches!(
            unarchive_result,
            PolicyCmdResult::UnarchiveObject {
                relationship_modified: true,
                ..
            }
        ));

        // Owner query should return true again.
        let (found, _) = module.query_object_owner(policy_id, &obj).unwrap();
        assert!(found);
    }

    #[test]
    fn merkle_tree_single_leaf() {
        let leaf = b"policy_idresourcedoc1did:key:alice";
        let leaf_hash = AcpModule::compute_leaf_hash(leaf);
        let levels = AcpModule::build_merkle_levels(&[leaf_hash]);
        assert_eq!(levels.len(), 1);
        assert_eq!(levels[0][0], leaf_hash);
    }

    #[test]
    fn merkle_tree_two_leaves() {
        let leaf1 = AcpModule::compute_leaf_hash(b"leaf1");
        let leaf2 = AcpModule::compute_leaf_hash(b"leaf2");
        let levels = AcpModule::build_merkle_levels(&[leaf1, leaf2]);
        assert_eq!(levels.len(), 2);
        let root = AcpModule::compute_inner_hash(&leaf1, &leaf2);
        assert_eq!(levels[1][0], root);
    }

    #[test]
    fn generate_commitment_roundtrip() {
        let mut module = AcpModule::new();
        let creator = alice();

        let record = module
            .create_policy(&creator, SIMPLE_POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();
        let policy_id = &record.policy.id;

        let objects = vec![
            Object {
                resource: "document".into(),
                id: "obj1".into(),
            },
            Object {
                resource: "document".into(),
                id: "obj2".into(),
            },
        ];

        let result = module
            .query_generate_commitment(policy_id, &objects, &Actor(creator.clone()))
            .unwrap();

        assert_eq!(result.commitment.len(), 32);
        assert_eq!(result.proofs.len(), 2);
        assert_eq!(result.proofs_json.len(), 2);

        // Verify proof for each object.
        for (i, obj) in objects.iter().enumerate() {
            let leaf_data = AcpModule::registration_leaf(policy_id, obj, creator.as_str()).unwrap();
            let valid =
                AcpModule::verify_merkle_proof(&result.commitment, &result.proofs[i], &leaf_data);
            assert!(valid, "proof {i} should be valid");
        }
    }

    const ACTOR_RESTRICTED_POLICY: &str = r#"
name: restricted-policy
resources:
  - name: group
    relations:
      - name: member
    permissions:
      - name: view
        expr: member
  - name: document
    relations:
      - name: reader
        types:
          - actor
    permissions:
      - name: read
        expr: reader
"#;

    fn doc(id: &str) -> Object {
        Object {
            resource: "document".into(),
            id: id.into(),
        }
    }

    #[test]
    fn floor_rejects_entityset_referencing_undeclared_resource() {
        let mut module = AcpModule::new();
        let creator = alice();
        let record = module
            .create_policy(&creator, SIMPLE_POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();
        let policy_id = &record.policy.id;
        // `reader` is declared (unrestricted), but the EntitySet references
        // `group#member`, which SIMPLE_POLICY does not declare.
        let rel = Relationship::new(
            "document",
            "docX",
            "reader",
            acp::Subject::entity_set("group", "g1", "member"),
        );
        let err = module
            .direct_policy_cmd(&creator, policy_id, PolicyCmd::SetRelationship(rel))
            .unwrap_err();
        assert!(
            matches!(err, AcpError::InvalidAccessRequest { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn floor_rejects_subject_restriction_violation() {
        let mut module = AcpModule::new();
        let creator = alice();
        let record = module
            .create_policy(
                &creator,
                ACTOR_RESTRICTED_POLICY,
                PolicyMarshalingType::ShortYaml,
            )
            .unwrap();
        let policy_id = &record.policy.id;
        // `document.reader` is restricted to actors; a userset violates it even
        // though `group#member` is declared.
        let rel = Relationship::new(
            "document",
            "docX",
            "reader",
            acp::Subject::entity_set("group", "g1", "member"),
        );
        let err = module
            .direct_policy_cmd(&creator, policy_id, PolicyCmd::SetRelationship(rel))
            .unwrap_err();
        assert!(
            matches!(err, AcpError::InvalidAccessRequest { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn undeclared_relations_are_rejected_without_mutation() {
        let mut module = AcpModule::new();
        let creator = alice();
        let policy = policy_with_grant(&mut module);
        let before = module.store.serialize();
        let relationship = Relationship::with_entity("document", "docX", "bogus", bob());
        for command in [
            PolicyCmd::SetRelationship(relationship.clone()),
            PolicyCmd::DeleteRelationship(relationship),
        ] {
            assert!(matches!(
                module.direct_policy_cmd(&creator, &policy, command),
                Err(AcpError::InvalidAccessRequest { .. })
            ));
            assert_eq!(module.store.serialize(), before);
        }
    }

    #[test]
    fn floor_allows_entity_on_unrestricted_relation() {
        let mut module = AcpModule::new();
        let creator = alice();
        let record = module
            .create_policy(&creator, SIMPLE_POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();
        let policy_id = &record.policy.id;
        module
            .direct_policy_cmd(&creator, policy_id, PolicyCmd::RegisterObject(doc("docX")))
            .unwrap();
        let rel = Relationship::with_entity("document", "docX", "reader", bob());
        module
            .direct_policy_cmd(&creator, policy_id, PolicyCmd::SetRelationship(rel))
            .expect("entity on an unrestricted relation passes the floor");
    }

    /// Set up `SIMPLE_POLICY` with `docX` registered (and owned) by `alice`, and
    /// a reader grant for `bob`. Returns the policy id.
    fn policy_with_grant(module: &mut AcpModule) -> String {
        let owner = alice();
        let record = module
            .create_policy(&owner, SIMPLE_POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();
        let policy_id = record.policy.id;
        module
            .direct_policy_cmd(&owner, &policy_id, PolicyCmd::RegisterObject(doc("docX")))
            .unwrap();
        let grant = Relationship::with_entity("document", "docX", "reader", bob());
        module
            .direct_policy_cmd(&owner, &policy_id, PolicyCmd::SetRelationship(grant))
            .unwrap();
        policy_id
    }

    #[test]
    fn delete_relationship_rejects_unauthorized_signer() {
        let mut module = AcpModule::new();
        let policy_id = policy_with_grant(&mut module);

        // bob is the grant's subject but neither the policy owner nor docX's
        // owner, so he cannot revoke it.
        let grant = Relationship::with_entity("document", "docX", "reader", bob());
        let err = module
            .direct_policy_cmd(
                &bob(),
                &policy_id,
                PolicyCmd::DeleteRelationship(grant.clone()),
            )
            .unwrap_err();
        assert!(matches!(err, AcpError::Unauthorized { .. }), "got {err:?}");

        // The grant must still be present — the rejected delete is a no-op.
        assert!(
            module
                .get_relationship(&policy_id, &grant)
                .unwrap()
                .is_some(),
            "unauthorized delete must not remove the grant"
        );
    }

    #[test]
    fn delete_relationship_allows_authorized_owner() {
        let mut module = AcpModule::new();
        let policy_id = policy_with_grant(&mut module);

        // alice owns the policy and docX, so she can revoke the grant.
        let grant = Relationship::with_entity("document", "docX", "reader", bob());
        let result = module
            .direct_policy_cmd(&alice(), &policy_id, PolicyCmd::DeleteRelationship(grant))
            .unwrap();
        assert!(matches!(
            result,
            PolicyCmdResult::DeleteRelationship { record_found: true }
        ));
    }

    #[test]
    fn delete_owner_relation_is_blocked() {
        let mut module = AcpModule::new();
        let policy_id = policy_with_grant(&mut module);

        // Even the authorized owner cannot strip the owner relation via delete.
        let owner_rel = Relationship::with_entity("document", "docX", "owner", alice());
        let err = module
            .direct_policy_cmd(
                &alice(),
                &policy_id,
                PolicyCmd::DeleteRelationship(owner_rel),
            )
            .unwrap_err();
        assert!(matches!(err, AcpError::Unauthorized { .. }), "got {err:?}");
    }

    #[test]
    fn set_owner_relation_is_blocked() {
        let mut module = AcpModule::new();
        let policy_id = policy_with_grant(&mut module);

        // An existing owner cannot mint a second owner.
        let second_owner = Relationship::with_entity("document", "docX", "owner", bob());
        let err = module
            .direct_policy_cmd(
                &alice(),
                &policy_id,
                PolicyCmd::SetRelationship(second_owner),
            )
            .unwrap_err();
        assert!(matches!(err, AcpError::Unauthorized { .. }), "got {err:?}");
    }
}
