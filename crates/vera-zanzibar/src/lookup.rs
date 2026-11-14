use std::collections::HashMap;

use crate::error::{Error, Result};
use crate::expression::RelationExpression;
use crate::types::Policy;

/// Lookup table for fast access to relation expressions.
///
/// Built from policies, provides O(1) lookup of relation expressions
/// by (policy_id, resource, relation) tuple.
#[derive(Debug, Default)]
pub struct PolicyLookupTable {
    policies: HashMap<String, HashMap<String, HashMap<String, RelationExpression>>>,
    actors: HashMap<String, String>,
}

impl PolicyLookupTable {
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
            actors: HashMap::new(),
        }
    }

    pub fn add_policy(&mut self, policy: &Policy) {
        let mut resources = HashMap::new();

        for resource in policy.resources.iter().chain(policy.actor.iter()) {
            let mut relations = HashMap::new();

            for relation in &resource.relations {
                relations.insert(relation.name.clone(), relation.expression.clone());
            }

            resources.insert(resource.name.clone(), relations);
        }

        self.actors.remove(&policy.id);
        if let Some(actor) = &policy.actor {
            self.actors.insert(policy.id.clone(), actor.name.clone());
        }
        self.policies.insert(policy.id.clone(), resources);
    }

    pub fn remove_policy(&mut self, policy_id: &str) {
        self.policies.remove(policy_id);
        self.actors.remove(policy_id);
    }

    pub fn update_policy(&mut self, policy: &Policy) {
        self.remove_policy(&policy.id);
        self.add_policy(policy);
    }

    pub fn clear(&mut self) {
        self.policies.clear();
        self.actors.clear();
    }

    pub fn is_actor_resource(&self, policy_id: &str, resource: &str) -> bool {
        self.actors
            .get(policy_id)
            .is_some_and(|name| name == resource)
    }

    /// Whether the policy's resource declares the relation.
    pub fn declares(&self, policy_id: &str, resource: &str, relation: &str) -> bool {
        self.policies
            .get(policy_id)
            .and_then(|resources| resources.get(resource))
            .is_some_and(|relations| relations.contains_key(relation))
    }

    pub fn get_expression(
        &self,
        policy_id: &str,
        resource: &str,
        relation: &str,
    ) -> Result<&RelationExpression> {
        self.policies
            .get(policy_id)
            .ok_or_else(|| Error::PolicyNotFound(policy_id.to_string()))?
            .get(resource)
            .ok_or_else(|| Error::ResourceNotFound(resource.to_string()))?
            .get(relation)
            .ok_or_else(|| Error::RelationNotFound {
                resource: resource.to_string(),
                relation: relation.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Relation, Resource};

    fn test_policy() -> Policy {
        Policy::new("policy1", "Test Policy")
            .with_resource(
                Resource::new("document")
                    .with_relation(Relation::direct("owner"))
                    .with_relation(Relation::computed(
                        "reader",
                        RelationExpression::union(vec![
                            RelationExpression::this(),
                            RelationExpression::computed_userset("owner"),
                        ]),
                    )),
            )
            .with_resource(Resource::new("folder").with_relation(Relation::direct("owner")))
    }

    #[test]
    fn test_add_policy() {
        let mut table = PolicyLookupTable::new();
        let policy = test_policy();

        table.add_policy(&policy);

        for (resource, relation) in [
            ("document", "owner"),
            ("document", "reader"),
            ("folder", "owner"),
        ] {
            table.get_expression("policy1", resource, relation).unwrap();
        }
    }

    #[test]
    fn test_get_expression() {
        let mut table = PolicyLookupTable::new();
        let policy = test_policy();

        table.add_policy(&policy);

        let expr = table
            .get_expression("policy1", "document", "owner")
            .unwrap();
        assert!(expr.is_this());

        let expr = table
            .get_expression("policy1", "document", "reader")
            .unwrap();
        match expr {
            RelationExpression::Union(_) => {}
            _ => panic!("expected Union expression"),
        }
    }

    #[test]
    fn test_get_expression_not_found() {
        let mut table = PolicyLookupTable::new();
        let policy = test_policy();

        table.add_policy(&policy);

        let result = table.get_expression("missing", "document", "owner");
        assert!(matches!(result, Err(Error::PolicyNotFound(_))));

        let result = table.get_expression("policy1", "missing", "owner");
        assert!(matches!(result, Err(Error::ResourceNotFound(_))));

        let result = table.get_expression("policy1", "document", "missing");
        assert!(matches!(result, Err(Error::RelationNotFound { .. })));
    }

    #[test]
    fn test_remove_policy() {
        let mut table = PolicyLookupTable::new();
        let policy = test_policy();

        table.add_policy(&policy);
        table.remove_policy("policy1");
        assert!(matches!(
            table.get_expression("policy1", "document", "owner"),
            Err(Error::PolicyNotFound(_))
        ));
    }
}
