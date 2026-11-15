use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::relationship::Relationship;
use super::resource::{Relation, Resource};
use crate::error::{Error, Result};
use crate::expression::{RelationExpression, MAX_EXPRESSION_DEPTH, MAX_EXPRESSION_OPERANDS};

/// Permission rules selected when a policy is created.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicySpecification {
    #[default]
    None,
    Defra,
}

impl PolicySpecification {
    pub const fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<Resource>,
    pub resources: Vec<Resource>,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "PolicySpecification::is_none")]
    pub specification: PolicySpecification,
}

impl Policy {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            actor: None,
            resources: Vec::new(),
            attributes: BTreeMap::new(),
            specification: PolicySpecification::None,
        }
    }

    pub fn with_resource(mut self, resource: Resource) -> Self {
        self.resources.push(resource);
        self
    }

    pub fn get_resource(&self, name: &str) -> Option<&Resource> {
        self.resources
            .iter()
            .find(|r| r.name == name)
            .or_else(|| self.actor.as_ref().filter(|actor| actor.name == name))
    }

    pub fn get_relation(&self, resource: &str, relation: &str) -> Option<&Relation> {
        self.get_resource(resource)
            .and_then(|r| r.get_relation(relation))
    }

    pub fn get_managers_for_relation(&self, resource: &str, relation: &str) -> Vec<&str> {
        self.get_resource(resource)
            .map(|r| {
                r.relations
                    .iter()
                    .filter(|rel| rel.manages.iter().any(|m| m == relation))
                    .map(|rel| rel.name.as_str())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn validate(&self) -> Result<()> {
        for resource in self.resources.iter().chain(self.actor.iter()) {
            for relation in &resource.relations {
                if relation.expression.depth() > MAX_EXPRESSION_DEPTH {
                    return Err(Error::InvalidPolicy(format!(
                        "relation '{}' in resource '{}' nests more than {MAX_EXPRESSION_DEPTH} operators",
                        relation.name, resource.name
                    )));
                }
                if relation.expression.operands() > MAX_EXPRESSION_OPERANDS {
                    return Err(Error::InvalidPolicy(format!(
                        "relation '{}' in resource '{}' names more than {MAX_EXPRESSION_OPERANDS} operands",
                        relation.name, resource.name
                    )));
                }
                self.validate_expression(&resource.name, &relation.expression)?;
            }
        }
        Ok(())
    }

    /// Every resource the tuple relation can point at must declare the
    /// computed relation, or following the tuple fails at evaluation.
    fn validate_computed_relation(
        &self,
        resource_name: &str,
        tuple: &Relation,
        computed_relation: &str,
    ) -> Result<()> {
        let mut targets = Vec::new();
        let unrestricted = tuple
            .subject_restriction
            .as_ref()
            .is_none_or(|restriction| restriction.entity_set_resources(&mut targets));
        let declared = |resource: &str| self.get_relation(resource, computed_relation).is_some();
        let missing = if unrestricted {
            let any = self
                .resources
                .iter()
                .chain(self.actor.iter())
                .any(|resource| declared(&resource.name));
            (!any).then_some("any resource")
        } else {
            targets.into_iter().find(|resource| !declared(resource))
        };
        match missing {
            Some(resource) => Err(Error::InvalidPolicy(format!(
                "TupleToUserset '{}->{}' in resource '{}' references a relation that {} does not declare",
                tuple.name, computed_relation, resource_name, resource
            ))),
            None => Ok(()),
        }
    }

    fn validate_expression(&self, resource_name: &str, expr: &RelationExpression) -> Result<()> {
        match expr {
            RelationExpression::This => Ok(()),
            RelationExpression::ComputedUserset { relation } => {
                if self.get_relation(resource_name, relation).is_none() {
                    return Err(Error::InvalidPolicy(format!(
                        "ComputedUserset references non-existent relation '{}' in resource '{}'",
                        relation, resource_name
                    )));
                }
                Ok(())
            }
            RelationExpression::TupleToUserset {
                tuple_relation,
                computed_relation,
            } => {
                let Some(tuple) = self.get_relation(resource_name, tuple_relation) else {
                    return Err(Error::InvalidPolicy(format!(
                        "TupleToUserset references non-existent tuple relation '{}' in resource '{}'",
                        tuple_relation, resource_name
                    )));
                };
                self.validate_computed_relation(resource_name, tuple, computed_relation)
            }
            RelationExpression::Union(exprs) => {
                for e in exprs {
                    self.validate_expression(resource_name, e)?;
                }
                Ok(())
            }
            RelationExpression::Intersection(exprs) => {
                for e in exprs {
                    self.validate_expression(resource_name, e)?;
                }
                Ok(())
            }
            RelationExpression::Difference { base, subtract } => {
                self.validate_expression(resource_name, base)?;
                self.validate_expression(resource_name, subtract)?;
                Ok(())
            }
        }
    }
}

impl Relationship {
    /// Validate this relationship against a policy.
    pub fn validate(&self, policy: &Policy) -> Result<()> {
        use super::subject::Subject;

        let is_actor = |resource: &str| {
            policy
                .actor
                .as_ref()
                .is_some_and(|actor| actor.name == resource)
        };
        if is_actor(&self.resource) && crate::did::Did::new(&self.object_id).is_err() {
            return Err(Error::InvalidPolicy("actor object must be a DID".into()));
        }
        if let Subject::EntitySet {
            resource,
            object_id,
            ..
        } = &self.subject
        {
            if is_actor(resource) && crate::did::Did::new(object_id).is_err() {
                return Err(Error::InvalidPolicy("actor subject must be a DID".into()));
            }
        }

        let relation_def = policy
            .get_relation(&self.resource, &self.relation)
            .ok_or_else(|| Error::RelationNotFound {
                resource: self.resource.clone(),
                relation: self.relation.clone(),
            })?;

        if let Subject::EntitySet {
            resource, relation, ..
        } = &self.subject
        {
            let reference_exists = if relation.is_empty() {
                // Object-edge (cross-object / TTU target): the subject names an
                // object of `resource` and carries no subject relation, so the
                // referenced *resource* is what must be declared.
                policy.get_resource(resource).is_some()
            } else {
                // Userset: the subject names objects via `resource#relation`, so
                // that relation must be declared.
                policy.get_relation(resource, relation).is_some()
            };
            if !reference_exists {
                return Err(Error::InvalidEntitySetReference {
                    resource: resource.clone(),
                    relation: relation.clone(),
                });
            }
        }

        let terminal_actor = match &self.subject {
            Subject::EntitySet {
                resource,
                object_id,
                relation,
            } if is_actor(resource) && relation.is_empty() => Some(Subject::Entity(
                crate::did::Did::new(object_id)
                    .map_err(|error| Error::InvalidPolicy(error.to_string()))?,
            )),
            _ => None,
        };
        if let Some(restriction) = &relation_def.subject_restriction {
            restriction
                .satisfies(terminal_actor.as_ref().unwrap_or(&self.subject))
                .map_err(|msg| Error::SubjectRestrictionViolation {
                    message: format!(
                        "relation '{}' on resource '{}': {}",
                        self.relation, self.resource, msg
                    ),
                })?;
        }

        Ok(())
    }
}
