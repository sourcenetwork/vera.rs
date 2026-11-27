//! vera's actors and objects as acp relationship values, and back.
//!
//! vera admits fewer DIDs than acp (`did:key`, `did:opk` and `did:emailhash`
//! actors), so an actor entering a stored relationship is checked as a vera DID too.

use ::acp::domain::{
    Actor as AcpActor, Did as AcpDid, OWNER_RELATION, Object as AcpObject, Relationship, Subject,
};
use vera_identity::Did;

use super::AcpError;
use super::types::Object;

/// `did` as an acp actor.
pub fn actor(did: &Did) -> Result<AcpActor, AcpError> {
    AcpDid::parse(did.as_str())
        .map(AcpActor::new)
        .map_err(|error| AcpError::InvalidAccessRequest {
            reason: format!("invalid actor {did}: {error}"),
        })
}

/// An acp actor as a vera DID.
pub fn did(actor: &AcpActor) -> Result<Did, AcpError> {
    Did::new(actor.id.as_str()).map_err(|error| AcpError::InvalidAccessRequest {
        reason: format!("invalid actor {}: {error}", actor.id),
    })
}

/// The relationship recording `owner` as the owner of `object`.
pub fn owner(object: &Object, owner: &Did) -> Result<Relationship, AcpError> {
    Ok(Relationship::new(
        AcpObject::from(object),
        OWNER_RELATION,
        Subject::Actor(actor(owner)?),
    ))
}

/// The object a relationship is on.
pub fn object(relationship: &Relationship) -> Object {
    Object::from(&relationship.object)
}

/// Every actor the relationship's subject names is a vera DID.
pub fn check_actors(relationship: &Relationship) -> Result<(), AcpError> {
    if let Subject::Actor(named) = &relationship.subject {
        did(named)?;
    }
    Ok(())
}

/// `resource:id#relation@actor`.
pub fn actor_relationship(
    resource: impl AsRef<str>,
    id: impl AsRef<str>,
    relation: impl AsRef<str>,
    actor: &Did,
) -> Result<Relationship, AcpError> {
    Ok(relationship(
        resource,
        id,
        relation,
        Subject::Actor(self::actor(actor)?),
    ))
}

/// `resource:id#relation@subject`.
pub fn relationship(
    resource: impl AsRef<str>,
    id: impl AsRef<str>,
    relation: impl AsRef<str>,
    subject: Subject,
) -> Relationship {
    Relationship::new(
        AcpObject::new(resource.as_ref(), id.as_ref()),
        relation.as_ref(),
        subject,
    )
}

/// The actors holding `relation` on `resource:id`.
pub fn actor_set(
    resource: impl AsRef<str>,
    id: impl AsRef<str>,
    relation: impl AsRef<str>,
) -> Subject {
    Subject::ActorSet(::acp::domain::ActorSet {
        object: AcpObject::new(resource.as_ref(), id.as_ref()),
        relation: relation.as_ref().into(),
    })
}

/// The object `resource:id` as a subject.
pub fn object_subject(resource: impl AsRef<str>, id: impl AsRef<str>) -> Subject {
    Subject::Object(AcpObject::new(resource.as_ref(), id.as_ref()))
}

/// One actor as a subject.
pub fn actor_subject(did: &Did) -> Result<Subject, AcpError> {
    actor(did).map(Subject::Actor)
}
