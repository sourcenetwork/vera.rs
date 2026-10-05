//! Live object and policy catalogues.
use std::collections::{BTreeMap, BTreeSet};

use super::*;
use serde::{Deserialize, Serialize};

/// Known live objects and relation names, grouped by policy resource.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyCatalogue {
    /// Reserved identity resource.
    pub actor_resource_name: String,
    /// Distinct actor identifiers in live relationships.
    pub actors: Vec<String>,
    /// Declared object resources and their catalogue.
    pub resources: BTreeMap<String, ResourceCatalogue>,
}

/// Known objects and declared names within one resource.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ResourceCatalogue {
    /// Computed permissions in name order.
    pub permissions: Vec<String>,
    /// Direct relations, including ownership.
    pub relations: Vec<String>,
    /// Distinct objects appearing in live relationships.
    pub object_ids: BTreeSet<String>,
}

impl AcpModule {
    /// Enumerate the live relationship graph within the relationship query budget.
    pub fn query_policy_catalogue(&self, policy_id: &str) -> Result<PolicyCatalogue> {
        let policy = self.query_policy(policy_id)?.policy;
        let mut resources = BTreeMap::new();
        for resource in &policy.resources {
            let mut entry = ResourceCatalogue::default();
            for relation in &resource.relations {
                if relation.expression.is_this() {
                    entry.relations.push(relation.name.clone());
                } else {
                    entry.permissions.push(relation.name.clone());
                }
            }
            entry.relations.sort();
            entry.permissions.sort();
            resources.insert(resource.name.clone(), entry);
        }
        let mut actors = BTreeSet::new();
        for record in self.query_filter_relationships(
            policy_id,
            &RelationshipSelector {
                object_selector: None,
                relation_selector: None,
                subject_selector: None,
            },
        )? {
            let relationship = record.relationship;
            let Some(resource) = resources.get_mut(&relationship.resource) else {
                continue;
            };
            resource.object_ids.insert(relationship.object_id);
            if let acp::Subject::Entity(actor) = relationship.subject {
                actors.insert(actor.to_string());
            }
        }
        Ok(PolicyCatalogue {
            actor_resource_name: policy
                .actor
                .map_or_else(|| "actor".into(), |actor| actor.name),
            actors: actors.into_iter().collect(),
            resources,
        })
    }

    /// Return registration state including archived ownership.
    pub fn query_object_registration(
        &self,
        policy_id: &str,
        object: &Object,
    ) -> Result<Option<RelationshipRecord>> {
        self.validate_registration_object(policy_id, object)?;
        self.registration_owner_record(policy_id, object)
    }

    /// Return full policy records in stable identifier order.
    pub fn query_policies(&self) -> Result<Vec<PolicyRecord>> {
        let page = self.query_policies_page(None)?;
        if page.next.is_some() {
            return Err(AcpError::InvalidAccessRequest {
                reason: "policy listing requires pagination".into(),
            });
        }
        Ok(page.records)
    }
}
