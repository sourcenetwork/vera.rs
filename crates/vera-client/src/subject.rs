//! Structured relationship subjects for the set/delete-subject ACP precompile
//! methods.

/// A relationship's subject, passed to `setRelationshipSubject` /
/// `deleteRelationshipSubject` as structured fields — never a parsed string,
/// since object IDs are path-like and may be quoted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelationshipSubject {
    /// An actor identified by its DID.
    Actor(String),
    /// Every actor (`actor:*`).
    AllActors,
    /// An object (`resource:object_id`), followed by `->` expressions.
    Object {
        /// The referenced object's resource.
        resource: String,
        /// The referenced object's id.
        object_id: String,
    },
    /// The actors holding `relation` on an object (`resource:object_id#relation`).
    ActorSet {
        /// The referenced object's resource.
        resource: String,
        /// The referenced object's id.
        object_id: String,
        /// The referenced relation on that object.
        relation: String,
    },
}

impl RelationshipSubject {
    /// The `(subjectKind, subjectResource, subjectObjectId, subjectRelation)`
    /// ABI fields for the structured set/delete methods.
    pub(crate) fn to_abi_fields(&self) -> (u8, String, String, String) {
        match self {
            Self::Actor(did) => (0, String::new(), did.clone(), String::new()),
            Self::AllActors => (1, String::new(), String::new(), String::new()),
            Self::Object {
                resource,
                object_id,
            } => (2, resource.clone(), object_id.clone(), String::new()),
            Self::ActorSet {
                resource,
                object_id,
                relation,
            } => (3, resource.clone(), object_id.clone(), relation.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actor_maps_did_to_object_id() {
        let s = RelationshipSubject::Actor("did:key:z6Mk".into());
        assert_eq!(
            s.to_abi_fields(),
            (0, String::new(), "did:key:z6Mk".into(), String::new())
        );
    }

    #[test]
    fn wildcard_has_no_fields() {
        assert_eq!(
            RelationshipSubject::AllActors.to_abi_fields(),
            (1, String::new(), String::new(), String::new())
        );
    }

    #[test]
    fn object_edge_has_empty_relation() {
        let s = RelationshipSubject::Object {
            resource: "collection".into(),
            object_id: "col1".into(),
        };
        assert_eq!(
            s.to_abi_fields(),
            (2, "collection".into(), "col1".into(), String::new())
        );
    }

    #[test]
    fn userset_carries_all_three() {
        let s = RelationshipSubject::ActorSet {
            resource: "collection".into(),
            object_id: "col1".into(),
            relation: "reader".into(),
        };
        assert_eq!(
            s.to_abi_fields(),
            (3, "collection".into(), "col1".into(), "reader".into())
        );
    }
}
