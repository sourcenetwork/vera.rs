mod bounded_yaml;
mod parse;
mod policy_id;
mod schema;

pub use parse::parse_policy_yaml;
pub use policy_id::{
    HASH_LEN, HexError, POLICY_HASH_DOMAIN, POLICY_ID_DOMAIN, PolicyHash, PolicyNonce, policy_hash,
    policy_id,
};

use std::collections::BTreeMap;

use serde::Deserialize;
use vera_zanzibar::{
    CreateRule, Policy, PolicySpecification, Relation, RelationExpression, Resource,
    SubjectRestriction,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParsedPolicy {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, deserialize_with = "parse::deserialize_specification")]
    pub spec: PolicySpecification,
    #[serde(default)]
    pub meta: BTreeMap<String, String>,
    #[serde(default)]
    pub actor: PolicyActor,
    #[serde(default)]
    pub resources: Vec<PolicyResource>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyResource {
    pub name: String,
    pub create: Option<CreateRule>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub permissions: Vec<PolicyPermission>,
    #[serde(default)]
    pub relations: Vec<PolicyRelation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPermission {
    pub name: String,
    #[serde(default)]
    pub doc: String,
    #[serde(default)]
    pub expr: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRelation {
    pub name: String,
    #[serde(default)]
    pub doc: String,
    #[serde(default)]
    pub types: Vec<String>,
    #[serde(default)]
    pub manages: Vec<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyActor {
    #[serde(default)]
    pub relations: Vec<PolicyRelation>,
}

/// Map a relation's declared `types:` to an enforced [`SubjectRestriction`].
///
/// Each type names an allowed subject shape:
/// - `actor`               → an actor DID or the all-actors wildcard `*`
/// - `actor:individual`    → an individual actor DID only
/// - `resource`            → a cross-object edge to an object of `resource`
/// - `resource->relation`  → a userset `resource:obj#relation`
///
/// The userset separator is acp_core's tuple-to-userset operator `->`, not `#`
/// (which is the tuple-subject grammar handled by `parse_target_subject`).
///
/// Multiple types combine as a union. An empty list yields `None` (no
/// restriction), preserving the behaviour of relations that omit `types:`.
fn build_subject_restriction(types: &[String]) -> crate::error::Result<Option<SubjectRestriction>> {
    let mut restrictions = Vec::with_capacity(types.len());
    for ty in types {
        let ty = ty.trim();
        let restriction = if ty == "actor" {
            SubjectRestriction::Actor
        } else if ty == "actor:individual" {
            SubjectRestriction::Entity
        } else if let Some((resource, relation)) = ty.split_once("->") {
            if resource.is_empty() || relation.is_empty() {
                return Err(crate::error::Error::InvalidRelation(format!(
                    "invalid relation type '{}': expected 'actor', 'resource', or 'resource->relation'",
                    ty
                )));
            }
            SubjectRestriction::EntitySet {
                resource: resource.to_string(),
                relation: relation.to_string(),
            }
        } else if ty.is_empty() {
            return Err(crate::error::Error::InvalidRelation(
                "empty relation type".to_string(),
            ));
        } else {
            // A bare resource name authorises a cross-object edge: an EntitySet
            // subject of that resource carrying no relation.
            SubjectRestriction::EntitySet {
                resource: ty.to_string(),
                relation: String::new(),
            }
        };
        restrictions.push(restriction);
    }

    Ok(match restrictions.len() {
        0 => None,
        1 => Some(restrictions.into_iter().next().unwrap()),
        _ => Some(SubjectRestriction::AnyOf(restrictions)),
    })
}

impl ParsedPolicy {
    pub fn find_resource(&self, name: &str) -> Option<&PolicyResource> {
        self.resources.iter().find(|r| r.name == name)
    }
}

impl PolicyResource {
    pub fn has_permission(&self, name: &str) -> bool {
        self.permissions.iter().any(|p| p.name == name)
    }

    pub fn has_relation(&self, name: &str) -> bool {
        self.relations.iter().any(|r| r.name == name)
    }

    /// Get relation names that manage the given relation.
    ///
    /// For example, if "admin" has `manages: [reader]`, then
    /// `get_managers_for_relation("reader")` returns `["admin"]`.
    pub fn get_managers_for_relation(&self, relation: &str) -> Vec<&str> {
        self.relations
            .iter()
            .filter(|r| r.manages.iter().any(|m| m == relation))
            .map(|r| r.name.as_str())
            .collect()
    }
}

/// Build a Zanzibar Policy named `id` from an already-parsed YAML policy.
///
/// A created policy's id is [`policy_id`] of its [`policy_hash`], its
/// creator and the creator's nonce; an edited policy keeps its id.
pub fn build_policy(parsed: &ParsedPolicy, id: String) -> crate::error::Result<Policy> {
    schema::validate(parsed)?;
    if parsed.spec == PolicySpecification::Defra {
        for resource in &parsed.resources {
            for permission in ["read", "write"] {
                if !resource.has_permission(permission) {
                    return Err(crate::error::Error::InvalidPolicy(format!(
                        "Defra specification requires permission '{permission}' on resource '{}'",
                        resource.name
                    )));
                }
            }
        }
    }
    let mut resources = Vec::new();
    for res in &parsed.resources {
        let mut relations = Vec::new();

        // Auto-inject the reserved 'owner' relation (matches Go DefraDB behavior)
        relations.push(
            match res
                .relations
                .iter()
                .find(|relation| relation.name == "owner")
            {
                Some(owner) => build_relation(owner)?,
                None => Relation::direct("owner"),
            },
        );

        for rel in &res.relations {
            if rel.name != "owner" {
                relations.push(build_relation(rel)?);
            }
        }

        for perm in &res.permissions {
            let mut expression = if perm.expr.is_empty() {
                // A permission with no explicit expression is still valid and
                // defaults to owner-only access in Go.
                RelationExpression::computed_userset("owner")
            } else {
                let user_expr = RelationExpression::parse(&perm.expr)?;
                // The owner holds every permission, whatever the expression says.
                RelationExpression::Union(vec![
                    RelationExpression::computed_userset("owner"),
                    user_expr,
                ])
            };
            if parsed.spec == PolicySpecification::Defra && perm.name == "read" {
                expression = RelationExpression::Union(vec![
                    expression,
                    RelationExpression::computed_userset("write"),
                ]);
            }
            let mut relation = Relation::computed(&perm.name, expression);
            relation.description = perm.doc.clone();
            relations.push(relation);
        }

        resources.push(Resource {
            name: res.name.clone(),
            description: res.description.clone(),
            create: res.create.clone(),
            relations,
        });
    }

    let policy = Policy {
        id,
        name: parsed.name.clone(),
        resources,
        attributes: parsed.meta.clone(),
        description: parsed.description.clone(),
        actor: Some(Resource {
            name: "actor".into(),
            create: None,
            description: String::new(),
            relations: parsed
                .actor
                .relations
                .iter()
                .map(build_relation)
                .collect::<crate::error::Result<_>>()?,
        }),
        specification: parsed.spec,
    };
    policy
        .validate()
        .map_err(|error| crate::error::Error::InvalidPolicy(error.to_string()))?;
    Ok(policy)
}

fn build_relation(parsed: &PolicyRelation) -> crate::error::Result<Relation> {
    let mut relation = Relation::direct(&parsed.name);
    relation.description = parsed.doc.clone();
    relation.manages = parsed.manages.clone();
    relation.subject_restriction = build_subject_restriction(&parsed.types)?;
    Ok(relation)
}
