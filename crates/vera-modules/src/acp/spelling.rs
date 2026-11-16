//! Canonical actor spelling inside relationship-graph values.
//!
//! A policy names an actor as an entity subject, as an owner and as an object
//! of its actor resource. Each of them is recorded under
//! [`crate::actor::canonical`], so a grant, a check and a revocation meet at
//! one relationship whichever spelling their callers used.

use std::borrow::Cow;

use ::acp::domain::{ACTOR_RESOURCE, Actor as AcpActor, Did as AcpDid, Relationship, Subject};

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
        if !self.policies.contains_key(policy_id) {
            return Err(AcpError::PolicyNotFound {
                id: policy_id.into(),
            });
        }
        self::relationship(&mut relationship);
        Ok(relationship)
    }
}

/// An object identifier, canonical when `resource` is the actor resource.
pub(super) fn object_id<'a>(resource: &str, id: &'a str) -> Cow<'a, str> {
    if resource == ACTOR_RESOURCE {
        crate::actor::canonical_str(id)
    } else {
        Cow::Borrowed(id)
    }
}

/// An actor under its canonical DID.
pub(super) fn actor(actor: &AcpActor) -> AcpActor {
    match crate::actor::canonical_str(actor.id.as_str()) {
        Cow::Owned(canonical) => {
            AcpDid::parse(&canonical).map_or_else(|_| actor.clone(), AcpActor::new)
        }
        Cow::Borrowed(_) => actor.clone(),
    }
}

fn acp_object(object: &mut ::acp::domain::Object) {
    if let Cow::Owned(canonical) = object_id(object.resource.as_str(), object.id.as_str()) {
        object.id = canonical.into();
    }
}

fn object(object: &mut Object) {
    if let Cow::Owned(canonical) = object_id(&object.resource, &object.id) {
        object.id = canonical;
    }
}

fn subject(subject: &mut Subject) {
    match subject {
        Subject::Actor(named) => *named = actor(named),
        Subject::ActorSet(set) => acp_object(&mut set.object),
        Subject::Object(named) => acp_object(named),
        Subject::AllActors => {}
    }
}

/// Record a relationship's object and subject under their canonical actors.
pub(super) fn relationship(relationship: &mut Relationship) {
    acp_object(&mut relationship.object);
    subject(&mut relationship.subject);
}

/// Whether a relationship already names every actor canonically.
pub(super) fn is_canonical(relationship: &Relationship) -> bool {
    let mut canonical = relationship.clone();
    self::relationship(&mut canonical);
    canonical == *relationship
}

/// Rewrite every actor a command names before it reads or changes state.
pub(super) fn command(command: &mut PolicyCmd) {
    match command {
        PolicyCmd::SetRelationship(named) | PolicyCmd::DeleteRelationship(named) => {
            self::relationship(named);
        }
        PolicyCmd::TransferObject {
            object: transferred,
            new_owner,
        } => {
            object(transferred);
            new_owner.0 = crate::actor::canonical(&new_owner.0);
        }
        PolicyCmd::RegisterObject(named)
        | PolicyCmd::ArchiveObject(named)
        | PolicyCmd::UnarchiveObject(named) => object(named),
        PolicyCmd::RevealRegistration { proof, .. } => object(&mut proof.object),
        PolicyCmd::CommitRegistrations { .. } | PolicyCmd::FlagHijackAttempt { .. } => {}
    }
}

/// Rewrite the actors a relationship query selects.
pub(super) fn selector(selector: &mut RelationshipSelector) {
    if let Some(ObjectSelector::Exact(selected)) = &mut selector.object_selector {
        object(selected);
    }
    if let Some(SubjectSelector::Exact(selected)) = &mut selector.subject_selector {
        subject(selected);
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
