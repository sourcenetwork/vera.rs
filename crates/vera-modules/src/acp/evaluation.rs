//! Permission evaluation over vera's ACP records with acp's evaluator.
//!
//! acp decides what a policy means; vera serves its stored grants. A grant is
//! stored when its record is in the current relation generations and object
//! incarnation, and is not archived. Every read goes through a
//! [`RecordStore`](crate::acp::record_store::RecordStore), so proof capture and proof replay see the same reads.

use std::sync::Arc;

use ::acp::domain::{
    Actor as AcpActor, Did as AcpDid, OWNER_RELATION, Object as AcpObject, RelationName,
    Relationship, Subject,
};
use std::num::NonZeroUsize;

use ::acp::eval::{EvalError, Evaluator, Grants, Limits, Page};
use ::acp::policy::Compiled;
use vera_identity::Did;

use super::permission_budget::PermissionBudget;
use super::record_error::{RecordError, Result};
use super::record_store::RecordStore;
use super::types::{AccessRequest, Object, PolicyRecord, RelationPair, RelationshipRecord};
use super::{keys, object_state, relationship_index, spelling};

/// Bounds on one permission or management check. Execution and proof replay
/// use the same bounds, so evidence that answers in one answers in the other.
/// Each step is also charged to the caller's [`PermissionBudget`].
///
/// A relation is listed in one page: `page_size` equals `max_records`, so
/// the evaluator never asks for a second page of a listing, and every
/// listing is one scan of the relation's records.
pub const PERMISSION_LIMITS: Limits = Limits {
    max_nodes: 10_000,
    max_queries: 10_000,
    max_depth: 256,
    max_records: MAX_RECORDS,
    page_size: match NonZeroUsize::new(MAX_RECORDS) {
        Some(size) => size,
        None => NonZeroUsize::MIN,
    },
};

/// The most stored grants one evaluation may read.
const MAX_RECORDS: usize = 10_000;

/// Evaluate an access request from fallible policy and relationship records.
/// Missing data and incomplete proof coverage remain errors, including on the
/// subtracting side of an exclusion. Callers must provide one coherent snapshot
/// for the whole evaluation and authenticate proof-backed records.
pub fn evaluate_access_request<S: RecordStore>(
    store: S,
    policy_id: &str,
    request: &AccessRequest,
) -> Result<bool> {
    let Some(evaluation) = evaluation(store, policy_id, None, None)? else {
        return Ok(false);
    };
    for operation in &request.operations {
        if !evaluation.check(&operation.object, &operation.permission, &request.actor.0)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// One policy's evaluator over an immutable record snapshot.
///
/// Every permission evaluation, in execution and in proof replay, enters acp
/// through [`Evaluation::check`], which names actors canonically.
pub(super) struct Evaluation<S: RecordStore> {
    compiled: Arc<Compiled>,
    grants: StoredGrants<S>,
    meter: Option<PermissionBudget>,
}

impl<S: RecordStore> Evaluation<S> {
    /// Whether `actor` holds `permission` on `object`, in any accepted
    /// spelling of the actor or of an actor the object names.
    pub(super) fn check(&self, object: &Object, permission: &str, actor: &Did) -> Result<bool> {
        let (object, actor) = canonical(object, actor)?;
        let permission = RelationName::from(permission);
        let evaluator = Evaluator::new(&self.compiled, &self.grants, PERMISSION_LIMITS);
        match &self.meter {
            Some(meter) => evaluator
                .with_meter(meter)
                .check(&object, &permission, &actor),
            None => evaluator.check(&object, &permission, &actor),
        }
        .map_err(evaluation_error)
    }

    /// Whether `actor` manages `relation` on `object`: holds the owner
    /// relation or a relation the policy lets manage it.
    pub(super) fn check_management(
        &self,
        object: &Object,
        relation: &str,
        actor: &Did,
    ) -> Result<bool> {
        let (object, actor) = canonical(object, actor)?;
        let relation = RelationName::from(relation);
        let evaluator = Evaluator::new(&self.compiled, &self.grants, PERMISSION_LIMITS);
        match &self.meter {
            Some(meter) => evaluator
                .with_meter(meter)
                .check_management(&object, &relation, &actor),
            None => evaluator.check_management(&object, &relation, &actor),
        }
        .map_err(evaluation_error)
    }

    /// Whether `actor` may create `object` under its resource's collection
    /// `create`, over the stored grants plus `derived` (acp's
    /// `check_create`). Nothing is stored. A derived relationship that is
    /// not on `object` or that the policy does not admit is an error.
    pub(super) fn check_create(
        &self,
        object: &Object,
        derived: &[Relationship],
        actor: &Did,
    ) -> std::result::Result<bool, CreateError> {
        let (object, actor) = canonical(object, actor)?;
        let evaluator = Evaluator::new(&self.compiled, &self.grants, PERMISSION_LIMITS);
        match &self.meter {
            Some(meter) => evaluator
                .with_meter(meter)
                .check_create(&object, derived, &actor),
            None => evaluator.check_create(&object, derived, &actor),
        }
        .map_err(|error| match error {
            EvalError::DerivedObject { relationship } => CreateError::Derived(format!(
                "derived relationship `{relationship}` is not on the object being registered"
            )),
            EvalError::DerivedRelationship {
                relationship,
                error,
            } => CreateError::Derived(format!("derived relationship `{relationship}`: {error}")),
            other => CreateError::Record(evaluation_error(other)),
        })
    }
}

/// Why a collection `create` check has no answer.
#[derive(Debug)]
pub(super) enum CreateError {
    /// A derived relationship the registration may not carry.
    Derived(String),
    /// The records or the evaluation failed.
    Record(RecordError),
}

impl From<RecordError> for CreateError {
    fn from(error: RecordError) -> Self {
        Self::Record(error)
    }
}

fn canonical(object: &Object, actor: &Did) -> Result<(AcpObject, AcpActor)> {
    let object = AcpObject::new(
        object.resource.as_str(),
        spelling::object_id(&object.resource, &object.id).into_owned(),
    );
    let actor = crate::actor::canonical(actor);
    let actor = AcpDid::parse(actor.as_str())
        .map(AcpActor::new)
        .map_err(|error| RecordError::Evaluation(format!("actor: {error}")))?;
    Ok((object, actor))
}

fn evaluation_error(error: EvalError<RecordError>) -> RecordError {
    match error {
        EvalError::Host(error) => error,
        EvalError::UnknownResource(resource) => RecordError::UnknownResource(resource.to_string()),
        EvalError::UnknownName { resource, name } => RecordError::UnknownRelation {
            resource: resource.to_string(),
            relation: name.to_string(),
        },
        other => RecordError::Evaluation(other.to_string()),
    }
}

/// An evaluation of `policy_id`, reading its record through `store`; `None`
/// if the policy does not exist. `cached` is reused when it is the stored
/// policy's compilation.
pub(super) fn evaluation<S: RecordStore>(
    store: S,
    policy_id: &str,
    cached: Option<&Arc<Compiled>>,
    meter: Option<PermissionBudget>,
) -> Result<Option<Evaluation<S>>> {
    let Some(record) = read_policy(&store, policy_id)? else {
        return Ok(None);
    };
    evaluation_for_policy(store, record, cached, meter).map(Some)
}

/// An evaluation of an already read policy record.
pub(super) fn evaluation_for_policy<S: RecordStore>(
    store: S,
    record: PolicyRecord,
    cached: Option<&Arc<Compiled>>,
    meter: Option<PermissionBudget>,
) -> Result<Evaluation<S>> {
    let compiled = match cached {
        Some(compiled) if compiled.policy == record.policy => Arc::clone(compiled),
        _ => Arc::new(compile(&record)?),
    };
    Ok(Evaluation {
        compiled,
        grants: StoredGrants {
            store,
            policy_id: record.policy.id.to_string(),
            relations: record.relations,
        },
        meter,
    })
}

/// The compiled model of a stored policy.
pub(super) fn compile(record: &PolicyRecord) -> Result<Compiled> {
    let model = ::acp::mapper::compile(&record.policy).map_err(|diagnostics| {
        RecordError::invalid(format!(
            "stored policy does not compile: {}",
            diagnostics
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        ))
    })?;
    Ok(Compiled {
        hash: ::acp::ppp::policy_hash(&record.policy),
        policy: record.policy.clone(),
        model,
    })
}

/// One policy's stored grants: current generations and incarnations, not
/// archived.
pub(super) struct StoredGrants<S> {
    store: S,
    policy_id: String,
    relations: super::types::RelationGenerations,
}

impl<S: RecordStore> StoredGrants<S> {
    /// The live records on `object#relation`.
    pub(super) fn live_records(
        &self,
        object: &AcpObject,
        relation: &RelationName,
    ) -> Result<Vec<RelationshipRecord>> {
        let policy_id = self.policy_id.as_str();
        let (resource, object_id) = (object.resource.as_str(), object.id.as_str());
        let Some(target) = self.relations.generation(resource, relation.as_str()) else {
            return Ok(vec![]);
        };
        let incarnation = if relation.as_str() == OWNER_RELATION {
            0
        } else {
            object_state::read(&self.store, policy_id, resource, object_id)?
        };
        let suffix = keys::relation_prefix(resource, object_id, relation.as_str(), incarnation);
        let mut records = Vec::new();
        for subject in
            relationship_index::live_pairs(&self.store, policy_id, target, &self.relations)?
        {
            let pair = RelationPair { target, subject };
            let prefix = keys::relationship_generation_prefix(policy_id, pair, &suffix);
            for (key, bytes) in self.store.scan_records(&prefix)? {
                let record = decode_relationship(policy_id, pair, &key, &bytes)?;
                if self.relations.pair(&record.relationship)? != pair {
                    return Err(RecordError::invalid(
                        "relationship generations differ from current policy",
                    ));
                }
                if !record.archived {
                    records.push(record);
                }
            }
        }
        Ok(records)
    }

    /// Whether `relationship` is stored and live.
    pub(super) fn is_live(&self, relationship: &Relationship) -> Result<bool> {
        let policy_id = self.policy_id.as_str();
        let Ok(pair) = self.relations.pair(relationship) else {
            return Ok(false);
        };
        let incarnation = object_state::for_relationship(&self.store, policy_id, relationship)?;
        let key = keys::relationship_generation_key(
            policy_id,
            pair,
            &keys::relationship_storage_key(relationship, incarnation),
        );
        let Some(bytes) = self.store.read_record(&key)? else {
            return Ok(false);
        };
        let record = decode_relationship(policy_id, pair, &key, &bytes)?;
        if record.relationship != *relationship {
            return Err(RecordError::invalid(
                "relationship record does not match the requested identity",
            ));
        }
        Ok(!record.archived)
    }
}

impl<S: RecordStore> Grants for StoredGrants<S> {
    type Error = RecordError;

    fn subjects(
        &self,
        object: &AcpObject,
        relation: &RelationName,
        after: Option<&Subject>,
        limit: NonZeroUsize,
    ) -> Result<Page> {
        let subjects = self
            .live_records(object, relation)?
            .into_iter()
            .map(|record| record.relationship.subject);
        Ok(Page::select(subjects, after, limit))
    }

    fn has(&self, relationship: &Relationship) -> Result<bool> {
        self.is_live(relationship)
    }
}

/// The policy record stored under `policy_id`, checked against its key and
/// its relation generations.
pub(super) fn read_policy<S: RecordStore>(
    store: &S,
    policy_id: &str,
) -> Result<Option<PolicyRecord>> {
    store
        .read_record(&keys::policy_key(policy_id))?
        .map(|bytes| {
            let record: PolicyRecord = serde_json::from_slice(&bytes)?;
            if record.policy.id.as_str() != policy_id {
                return Err(RecordError::invalid(
                    "policy record ID does not match its key",
                ));
            }
            record.relations.validate(&record.policy)?;
            Ok(record)
        })
        .transpose()
}

/// A relationship record read under `key`, checked against the key and its
/// generations.
pub(super) fn decode_relationship(
    policy: &str,
    pair: RelationPair,
    key: &[u8],
    bytes: &[u8],
) -> Result<RelationshipRecord> {
    let record: RelationshipRecord = serde_json::from_slice(bytes)?;
    if record.policy_id != policy
        || (record.relationship.relation.as_str() == OWNER_RELATION && record.incarnation != 0)
        || record.generations != pair
        || keys::relationship_generation_key(
            policy,
            pair,
            &keys::relationship_storage_key(&record.relationship, record.incarnation),
        ) != key
    {
        return Err(RecordError::invalid(
            "relationship record does not match its key or generations",
        ));
    }
    Ok(record)
}

#[cfg(test)]
#[path = "evaluation_tests/mod.rs"]
mod tests;
