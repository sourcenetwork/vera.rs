//! Register a child object under the parent its collection `create` follows.
//!
//! `RegisterUnderParent { object, parent }` is a registration with one
//! derived relationship, `object#<relation>@parent`, where `<relation>` is
//! the one relation the resource's `create` follows (`agent` in
//! `create: agent->start_session`). It is checked and stored as
//! [`PolicyCmd::RegisterObjectWithRelationships`] is.

use ::acp::domain::{Expression, Object as AcpObject, RelationName, ResourceName, Subject};

use super::*;

impl AcpModule {
    pub(super) fn register_under_parent(
        &mut self,
        actor: &Did,
        policy: &PolicyRecord,
        object: Object,
        parent: Object,
        stamp: &CommandStamp,
        budget: &CommandBudget,
    ) -> Result<PolicyCmdResult> {
        let policy_id = policy.policy.id.as_str();
        let compiled =
            self.policies
                .get(policy_id)
                .cloned()
                .ok_or_else(|| AcpError::PolicyNotFound {
                    id: policy_id.to_string(),
                })?;
        let rule = compiled
            .create_rule(&ResourceName::from(object.resource.as_str()))
            .ok_or_else(|| AcpError::InvalidAccessRequest {
                reason: "resource has no create rule".into(),
            })?;
        let relation = followed_relation(rule)?;
        let link = relationship_values::relationship(
            &object.resource,
            &object.id,
            relation.as_str(),
            Subject::Object(AcpObject::new(parent.resource.as_str(), parent.id.as_str())),
        );
        self.cmd_register_object(actor, policy, object, vec![link], stamp, budget)
            .map(|(record, _)| PolicyCmdResult::RegisterObject { record })
    }
}

/// The one relation `rule` follows to a parent.
fn followed_relation(rule: &Expression) -> Result<&RelationName> {
    let mut followed = std::collections::BTreeSet::new();
    tuplesets(rule, &mut followed);
    let reason = match Vec::from_iter(followed).as_slice() {
        [relation] => return Ok(relation),
        [] => "create follows no relation; register the object without a parent",
        _ => "create follows more than one relation; register with its relationships",
    };
    Err(AcpError::InvalidAccessRequest {
        reason: reason.into(),
    })
}

/// The relations `expression`'s tuple to usersets follow.
fn tuplesets<'e>(
    expression: &'e Expression,
    found: &mut std::collections::BTreeSet<&'e RelationName>,
) {
    match expression {
        Expression::TupleToUserset { tupleset, .. } => {
            found.insert(tupleset);
        }
        Expression::Union(left, right)
        | Expression::Intersection(left, right)
        | Expression::Difference(left, right) => {
            tuplesets(left, found);
            tuplesets(right, found);
        }
        Expression::ComputedUserset(_) => {}
    }
}

#[cfg(test)]
#[path = "parent_registration_tests.rs"]
mod tests;
