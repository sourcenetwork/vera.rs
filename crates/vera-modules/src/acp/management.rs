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
        let capture = read_capture::ReadCapture::with_budget(
            self.store.clone(),
            read_capture::PERMISSION_READ_LIMITS,
            budget.permissions.clone(),
        );
        let record = zanzibar_store::read_policy(&capture, policy_id)
            .map_err(relation_state_error)?
            .ok_or_else(|| AcpError::PolicyNotFound {
                id: policy_id.into(),
            })?;
        let policy = &record.policy;
        let target = policy
            .get_relation(&object.resource, relation)
            .ok_or_else(|| AcpError::InvalidAccessRequest {
                reason: format!("unknown managed relation '{}/{relation}'", object.resource),
            })?;
        if !target.expression.is_this() {
            return Err(AcpError::InvalidAccessRequest {
                reason: "permissions cannot be managed as stored relations".into(),
            });
        }
        // Actor roles have no object registration. Their policy owner controls bootstrap.
        if policy
            .actor
            .as_ref()
            .is_some_and(|definition| definition.name == object.resource)
        {
            return Ok(record.metadata.owner_did == actor.as_str());
        }
        if self
            .registration_owner_record_with_budget(policy_id, object, Some(budget))?
            .is_none_or(|owner| owner.archived)
        {
            return Ok(false);
        }
        let managers: Vec<String> = std::iter::once("owner")
            .chain(policy.get_managers_for_relation(&object.resource, relation))
            .map(str::to_owned)
            .collect();
        let engine = zanzibar_store::evaluation_engine_for_policy(
            capture,
            record,
            Some(Arc::new(budget.permissions.clone())),
        );
        for manager in managers {
            if engine
                .check_blocking(policy_id, &object.resource, &object.id, &manager, actor)
                .map_err(|error| {
                    AcpError::State(format!("management evaluation failed: {error}"))
                })?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
