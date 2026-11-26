//! Register an object, with the relationships derived from it, under its
//! resource's collection `create` (acp-rs ADR 0028).

use std::collections::BTreeSet;

use super::evaluation::CreateError;
use super::*;

impl AcpModule {
    /// Registers `obj` to `creator` with `derived`, after the collection
    /// `create` check. Returns the owner record and the derived records.
    ///
    /// The check runs for every registration: a resource without `create`
    /// (or with `create: "*"`) passes without evaluating, and a gated one
    /// needs the relationships it follows in `derived`, so a registration
    /// without them is refused. The derived relationships are written
    /// because the check passed, not under the relations' management rules.
    pub(super) fn cmd_register_object(
        &mut self,
        creator: &Did,
        policy: &PolicyRecord,
        obj: Object,
        derived: Vec<Relationship>,
        stamp: &CommandStamp,
        budget: &CommandBudget,
    ) -> Result<(RelationshipRecord, Vec<RelationshipRecord>)> {
        let policy_id = policy.policy.id.as_str();
        self.validate_registration_object(policy_id, &obj)?;
        self.ensure_object_unregistered_with_budget(policy_id, &obj, Some(budget))?;
        let mut distinct = BTreeSet::new();
        for relationship in &derived {
            relationship_values::check_actors(relationship)?;
            if !distinct.insert(relationship) {
                return Err(AcpError::InvalidAccessRequest {
                    reason: format!("derived relationship `{relationship}` is repeated"),
                });
            }
        }
        if !self.passes_create(creator, policy, &obj, &derived, budget)? {
            return Err(AcpError::CreateNotAuthorized {
                actor: creator.to_string(),
                resource: obj.resource,
                object_id: obj.id,
            });
        }

        let owner_rel = relationship_values::owner(&obj, creator)?;
        let record = RelationshipRecord {
            incarnation: 0,
            generations: self.relationship_pair(policy, &owner_rel, budget)?,
            supplied_metadata: stamp.supplied.clone(),
            policy_id: policy_id.to_string(),
            relationship: owner_rel,
            archived: false,
            metadata: stamp.metadata(creator),
        };
        self.set_relationship_with_budget(&record, budget)?;

        let mut records = Vec::with_capacity(derived.len());
        for relationship in derived {
            let record = RelationshipRecord {
                incarnation: self.relationship_incarnation_with_budget(
                    policy_id,
                    &relationship,
                    Some(budget),
                )?,
                generations: self.relationship_pair(policy, &relationship, budget)?,
                supplied_metadata: SuppliedMetadata::default(),
                policy_id: policy_id.to_string(),
                relationship,
                archived: false,
                metadata: stamp.metadata(creator),
            };
            self.set_relationship_with_budget(&record, budget)?;
            records.push(record);
        }
        Ok((record, records))
    }

    /// Whether `creator` passes `obj`'s collection `create` over the stored
    /// relationships plus `derived`, metered against `budget`.
    fn passes_create(
        &self,
        creator: &Did,
        policy: &PolicyRecord,
        obj: &Object,
        derived: &[Relationship],
        budget: &CommandBudget,
    ) -> Result<bool> {
        let policy_id = policy.policy.id.as_str();
        let capture = read_capture::ReadCapture::with_budget(
            self.store.clone(),
            read_capture::PERMISSION_READ_LIMITS,
            budget.permissions.clone(),
        );
        let evaluation = evaluation::evaluation_for_policy(
            capture,
            policy.clone(),
            self.policies.get(policy_id),
            Some(budget.permissions.clone()),
        )
        .map_err(|error| budget.permissions.evaluation_error(error))?;
        let result = evaluation
            .check_create(obj, derived, creator)
            .map_err(|error| match error {
                CreateError::Derived(reason) => AcpError::InvalidAccessRequest { reason },
                CreateError::Record(error) => budget.permissions.evaluation_error(error),
            });
        budget.finish(result)
    }
}

#[cfg(test)]
#[path = "registration_create_tests.rs"]
mod tests;
