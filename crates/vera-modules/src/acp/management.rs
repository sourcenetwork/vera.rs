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
        if object.id.is_empty() {
            return Err(AcpError::InvalidAccessRequest {
                reason: "object ID must not be empty".into(),
            });
        }
        let policy =
            self.zanzibar_policies
                .get(policy_id)
                .ok_or_else(|| AcpError::PolicyNotFound {
                    id: policy_id.into(),
                })?;
        self.is_authorized_to_manage(
            actor,
            policy_id,
            policy,
            &object.resource,
            &object.id,
            relation,
        )
    }

    pub(super) fn is_authorized_to_manage(
        &self,
        actor: &Did,
        policy_id: &str,
        policy: &Policy,
        resource: &str,
        object_id: &str,
        relation: &str,
    ) -> Result<bool> {
        self.query_policy(policy_id)?;
        let target = policy.get_relation(resource, relation).ok_or_else(|| {
            AcpError::InvalidAccessRequest {
                reason: format!("unknown managed relation '{resource}/{relation}'"),
            }
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
            .is_some_and(|definition| definition.name == resource)
        {
            return Ok(self.query_policy(policy_id)?.metadata.owner_did == actor.as_str());
        }
        let object = Object {
            resource: resource.into(),
            id: object_id.into(),
        };
        if self
            .registration_owner_record(policy_id, &object)?
            .is_none_or(|owner| owner.archived)
        {
            return Ok(false);
        }
        let engine = self.permission_engine(policy);
        for manager in
            std::iter::once("owner").chain(policy.get_managers_for_relation(resource, relation))
        {
            if engine
                .check_blocking(policy_id, resource, object_id, manager, actor)
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
