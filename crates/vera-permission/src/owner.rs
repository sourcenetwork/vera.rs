use vera_domain::ConsensusPublicKey;
use vera_modules::acp::{
    keys,
    types::{RelationPair, RelationshipRecord},
};
use zanzibar::{Relationship, Subject};

use crate::{
    Actor, Object, PERMISSION_LIMITS, PermissionError, PolicyPrefixResponse, RECORD_PROOF_BYTES,
    current::MAX_KEY_BYTES, encoded_size,
};

/// Build the unambiguous storage prefix for one object's owner relations.
pub fn object_owner_prefix(policy: &str, object: &Object) -> Result<Vec<u8>, PermissionError> {
    encoded_size(&(policy, object), PERMISSION_LIMITS.request_bytes)?;
    if policy.is_empty() || policy.contains(['/', '\\']) {
        return Err(PermissionError::Invalid("invalid policy identifier"));
    }
    Relationship::try_new(&object.resource, &object.id, "owner", Subject::Wildcard)?;
    let prefix = keys::relationship_storage_prefix(
        policy,
        &keys::relation_prefix(&object.resource, &object.id, "owner", 0),
    );
    if prefix.len() > MAX_KEY_BYTES {
        return Err(PermissionError::Limit);
    }
    Ok(prefix)
}

impl PolicyPrefixResponse {
    /// Return the single live owner from complete, finalized evidence.
    /// Archived ownership does not register an object or authorize access.
    pub fn verify_object_owner(
        &self,
        policy: &str,
        object: &Object,
        minimum_height: u64,
        trusted: &ConsensusPublicKey,
    ) -> Result<Option<Actor>, PermissionError> {
        let prefix = object_owner_prefix(policy, object)?;
        let Some(evidence) =
            self.verify(policy, &prefix, minimum_height, trusted, RECORD_PROOF_BYTES)?
        else {
            return Ok(None);
        };
        owner(
            evidence
                .entries
                .iter()
                .map(|entry| (entry.key.as_slice(), entry.value.as_ref())),
            policy,
            object,
        )
    }
}

fn owner<'a>(
    records: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
    policy: &str,
    object: &Object,
) -> Result<Option<Actor>, PermissionError> {
    let mut owner = None;
    for (key, value) in records {
        let record: RelationshipRecord = serde_json::from_slice(value)
            .map_err(|_| PermissionError::Invalid("owner record encoding"))?;
        let relation = &record.relationship;
        if record.incarnation != 0
            || record.policy_id != policy
            || record.generations
                != (RelationPair {
                    target: 0,
                    subject: 0,
                })
            || relation.resource != object.resource
            || relation.object_id != object.id
            || relation.relation != "owner"
            || keys::relationship_key(
                policy,
                &keys::relationship_storage_key(relation, record.incarnation),
            ) != key
        {
            return Err(PermissionError::Invalid(
                "owner record differs from its key",
            ));
        }
        let Subject::Entity(did) = relation.subject.clone() else {
            return Err(PermissionError::Invalid("owner is not an actor"));
        };
        if !record.archived && owner.replace(Actor(did)).is_some() {
            return Err(PermissionError::Invalid("multiple live owners"));
        }
    }
    Ok(owner)
}

#[cfg(test)]
mod tests;
