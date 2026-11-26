use super::*;

impl AcpModule {
    /// Evaluate the policy's management rules for an object's stored relation.
    pub fn check_management_authority(
        &self,
        actor: &Did,
        policy_id: &str,
        object: &Object,
        relation: &str,
    ) -> Result<bool> {
        self.check_management_authority_with_budget(
            actor,
            policy_id,
            object,
            relation,
            &CommandBudget::new(u64::MAX),
        )
    }

    /// Share read and evaluation charges across the owner and every declared manager.
    pub fn check_management_authority_with_budget(
        &self,
        actor: &Did,
        policy_id: &str,
        object: &Object,
        relation: &str,
        budget: &CommandBudget,
    ) -> Result<bool> {
        budget.input(
            actor
                .as_str()
                .len()
                .saturating_add(policy_id.len())
                .saturating_add(object.resource.len())
                .saturating_add(object.id.len())
                .saturating_add(relation.len()),
        )?;
        budget.finish(self.management_authority(actor, policy_id, object, relation, budget))
    }

    fn management_authority(
        &self,
        actor: &Did,
        policy_id: &str,
        object: &Object,
        relation: &str,
        budget: &CommandBudget,
    ) -> Result<bool> {
        if object.id.is_empty() {
            return Err(AcpError::InvalidAccessRequest {
                reason: "object ID must not be empty".into(),
            });
        }
        let actor = &crate::actor::canonical(actor);
        let capture = read_capture::ReadCapture::with_budget(
            self.store.clone(),
            read_capture::PERMISSION_READ_LIMITS,
            budget.permissions.clone(),
        );
        let record = evaluation::read_policy(&capture, policy_id)
            .map_err(relation_state_error)?
            .ok_or_else(|| AcpError::PolicyNotFound {
                id: policy_id.into(),
            })?;
        let unknown = || AcpError::InvalidAccessRequest {
            reason: format!("unknown managed relation '{}/{relation}'", object.resource),
        };
        let resource = record
            .policy
            .resources
            .iter()
            .find(|resource| resource.name.as_str() == object.resource)
            .ok_or_else(unknown)?;
        if resource
            .permissions
            .iter()
            .any(|permission| permission.name.as_str() == relation)
        {
            return Err(AcpError::InvalidAccessRequest {
                reason: "permissions cannot be managed as stored relations".into(),
            });
        }
        if relation != ::acp::domain::OWNER_RELATION
            && !resource
                .relations
                .iter()
                .any(|declared| declared.name.as_str() == relation)
        {
            return Err(unknown());
        }
        if self
            .registration_owner_record_with_budget(policy_id, object, Some(budget))?
            .is_none_or(|owner| owner.archived)
        {
            return Ok(false);
        }
        evaluation::evaluation_for_policy(
            capture,
            record,
            self.policies.get(policy_id),
            Some(budget.permissions.clone()),
        )
        .and_then(|evaluation| evaluation.check_management(object, relation, actor))
        .map_err(|error| AcpError::State(format!("management evaluation failed: {error}")))
    }
}
