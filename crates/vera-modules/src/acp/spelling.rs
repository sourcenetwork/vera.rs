//! Canonical actor spelling inside relationship-graph values.
//!
//! A policy names an actor as an entity subject, as an owner and as an object
//! of its actor resource. Each of them is recorded under
//! [`crate::actor::canonical`], so a grant, a check and a revocation meet at
//! one relationship whichever spelling their callers used.

use std::borrow::Cow;

use vera_acp::{Policy, Relationship, Subject};

use super::types::{
    AccessRequest, Actor, Object, ObjectSelector, PolicyCmd, RelationshipSelector, SubjectSelector,
};
use super::{AcpError, AcpModule, Result};

impl AcpModule {
    /// A relationship as `policy_id` records it, with every actor it names under
    /// the canonical DID. Commands apply the same rewrite before they execute;
    /// callers use this to report what a command changed.
    pub fn recorded_relationship(
        &self,
        policy_id: &str,
        mut relationship: Relationship,
    ) -> Result<Relationship> {
        let policy =
            self.zanzibar_policies
                .get(policy_id)
                .ok_or_else(|| AcpError::PolicyNotFound {
                    id: policy_id.into(),
                })?;
        self::relationship(policy, &mut relationship);
        Ok(relationship)
    }
}

/// An object identifier, canonical when `resource` is the policy's actor resource.
pub(super) fn object_id<'a>(policy: &Policy, resource: &str, id: &'a str) -> Cow<'a, str> {
    if policy
        .actor
        .as_ref()
        .is_some_and(|actor| actor.name == resource)
    {
        crate::actor::canonical_str(id)
    } else {
        Cow::Borrowed(id)
    }
}

fn rewrite_object_id(policy: &Policy, resource: &str, id: &mut String) {
    if let Cow::Owned(canonical) = object_id(policy, resource, id) {
        *id = canonical;
    }
}

fn object(policy: &Policy, object: &mut Object) {
    rewrite_object_id(policy, &object.resource, &mut object.id);
}

fn subject(policy: &Policy, subject: &mut Subject) {
    match subject {
        Subject::Entity(actor) => *actor = crate::actor::canonical(actor),
        Subject::EntitySet {
            resource,
            object_id,
            ..
        } => rewrite_object_id(policy, resource, object_id),
        _ => {}
    }
}

/// Record a relationship's object and subject under their canonical actors.
pub(super) fn relationship(policy: &Policy, relationship: &mut Relationship) {
    rewrite_object_id(policy, &relationship.resource, &mut relationship.object_id);
    subject(policy, &mut relationship.subject);
}

/// Whether a relationship already names every actor canonically.
pub(super) fn is_canonical(policy: &Policy, relationship: &Relationship) -> bool {
    let mut canonical = relationship.clone();
    self::relationship(policy, &mut canonical);
    canonical == *relationship
}

/// Rewrite every actor a command names before it reads or changes state.
pub(super) fn command(policy: &Policy, command: &mut PolicyCmd) {
    match command {
        PolicyCmd::SetRelationship(relationship) | PolicyCmd::DeleteRelationship(relationship) => {
            self::relationship(policy, relationship);
        }
        PolicyCmd::TransferObject {
            object: transferred,
            new_owner,
        } => {
            object(policy, transferred);
            new_owner.0 = crate::actor::canonical(&new_owner.0);
        }
        PolicyCmd::RegisterObject(named)
        | PolicyCmd::ArchiveObject(named)
        | PolicyCmd::UnarchiveObject(named) => object(policy, named),
        PolicyCmd::RevealRegistration { proof, .. } => object(policy, &mut proof.object),
        PolicyCmd::CommitRegistrations { .. } | PolicyCmd::FlagHijackAttempt { .. } => {}
    }
}

/// Rewrite the actors a relationship query selects.
pub(super) fn selector(policy: &Policy, selector: &mut RelationshipSelector) {
    if let Some(ObjectSelector::Exact(selected)) = &mut selector.object_selector {
        object(policy, selected);
    }
    if let Some(SubjectSelector::Exact(selected)) = &mut selector.subject_selector {
        subject(policy, selected);
    }
}

/// A request for its canonical actor. Operations keep the caller's object
/// identifiers: a decision echoes them, and evaluation resolves each one
/// against the policy.
pub(super) fn access_request(request: &AccessRequest) -> Cow<'_, AccessRequest> {
    let actor = crate::actor::canonical(&request.actor.0);
    if actor == request.actor.0 {
        Cow::Borrowed(request)
    } else {
        Cow::Owned(AccessRequest {
            operations: request.operations.clone(),
            actor: Actor(actor),
        })
    }
}

#[cfg(test)]
#[path = "spelling_tests.rs"]
mod tests;
