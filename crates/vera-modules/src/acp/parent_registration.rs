use super::*;

impl AcpModule {
    pub(super) fn require_ungated(policy: &PolicyRecord, object: &Object) -> Result<()> {
        if policy
            .policy
            .get_resource(&object.resource)
            .is_some_and(|r| r.create.is_some())
        {
            return Err(AcpError::InvalidAccessRequest {
                reason: "registration requires a parent object".into(),
            });
        }
        Ok(())
    }

    pub(super) fn check_parent_link(
        &self,
        actor: &Did,
        policy: &PolicyRecord,
        link: &Relationship,
        budget: &CommandBudget,
    ) -> Result<()> {
        let Some(rule) = policy
            .policy
            .get_resource(&link.resource)
            .and_then(|r| r.create.as_ref())
            .filter(|r| r.parent == link.relation)
        else {
            return Ok(());
        };
        let vera_acp::Subject::EntitySet {
            resource,
            object_id,
            relation,
        } = &link.subject
        else {
            return Err(AcpError::InvalidAccessRequest {
                reason: "parent must be an object".into(),
            });
        };
        if !relation.is_empty() || object_id.is_empty() {
            return Err(AcpError::InvalidAccessRequest {
                reason: "parent must identify a single object".into(),
            });
        }
        let parent = Object {
            resource: resource.clone(),
            id: object_id.clone(),
        };
        let id = policy.policy.id.as_str();
        let owner = self.registration_owner_record_with_budget(id, &parent, Some(budget))?;
        if !owner.is_some_and(|record| !record.archived) {
            return Err(AcpError::Unauthorized {
                reason: "parent is not registered and active".into(),
            });
        }
        let request = AccessRequest {
            actor: types::Actor(actor.clone()),
            operations: vec![types::Operation {
                object: parent,
                permission: rule.requires.clone(),
            }],
        };
        if !self.query_verify_access_request_with_budget(id, &request, &budget.permissions)? {
            return Err(AcpError::Unauthorized {
                reason: format!("parent requires '{}'", rule.requires),
            });
        }
        Ok(())
    }

    pub(super) fn register_under_parent(
        &mut self,
        actor: &Did,
        policy: &PolicyRecord,
        object: Object,
        parent: Object,
        stamp: &CommandStamp,
        budget: &CommandBudget,
    ) -> Result<PolicyCmdResult> {
        let rule = policy
            .policy
            .get_resource(&object.resource)
            .and_then(|r| r.create.as_ref())
            .ok_or_else(|| AcpError::InvalidAccessRequest {
                reason: "resource has no create rule".into(),
            })?;
        let link = Relationship::new(
            object.resource.clone(),
            object.id.clone(),
            rule.parent.clone(),
            vera_acp::Subject::entity_set(parent.resource, parent.id, ""),
        );
        link.validate(&policy.policy)
            .map_err(|error| AcpError::InvalidAccessRequest {
                reason: error.to_string(),
            })?;
        self.check_parent_link(actor, policy, &link, budget)?;
        let result = self.cmd_register_object(actor, policy, object, stamp, budget)?;
        self.insert_authorized_relationship(actor, policy, link, stamp, budget)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_authorized_parent_registration_creates_the_child() {
        let mut module = AcpModule::new();
        let owner = Did::new("did:key:first").unwrap();
        let other = Did::new("did:key:second").unwrap();
        let policy = module.create_policy(
            &owner,
            "name: agents\nresources:\n- name: agent\n- name: session\n  relations: [{name: agent, types: [agent]}]\n  create: {parent: agent, requires: owner}\n",
            PolicyMarshalingType::ShortYaml, Default::default(),
        ).unwrap().policy.id;
        let parent = Object {
            resource: "agent".into(),
            id: "a".into(),
        };
        let child = Object {
            resource: "session".into(),
            id: "s".into(),
        };
        module
            .direct_policy_cmd(&owner, &policy, PolicyCmd::RegisterObject(parent.clone()))
            .unwrap();
        let cmd = PolicyCmd::RegisterUnderParent {
            object: child.clone(),
            parent: parent.clone(),
        };
        let before = module.store.serialize();
        assert!(
            module
                .direct_policy_cmd(&owner, &policy, PolicyCmd::RegisterObject(child.clone()))
                .is_err()
        );
        assert!(matches!(
            module.direct_policy_cmd(&other, &policy, cmd.clone()),
            Err(AcpError::Unauthorized { .. })
        ));
        let reveal = PolicyCmd::RevealRegistration {
            registrations_commitment_id: 1,
            proof: types::RegistrationProof {
                object: child.clone(),
                leaf_count: 1,
                leaf_index: 0,
                merkle_proof: vec![],
            },
        };
        assert!(matches!(
            module.direct_policy_cmd(&owner, &policy, reveal),
            Err(AcpError::InvalidAccessRequest { .. })
        ));
        assert_eq!(before, module.store.serialize());
        module.direct_policy_cmd(&owner, &policy, cmd).unwrap();
        let link = Relationship::new(
            "session",
            "s",
            "agent",
            vera_acp::Subject::entity_set("agent", "a", ""),
        );
        assert!(
            module
                .relationship_in(&module.query_policy(&policy).unwrap(), &link, None)
                .unwrap()
                .is_some()
        );
        let second = Object {
            resource: "agent".into(),
            id: "b".into(),
        };
        module
            .direct_policy_cmd(&other, &policy, PolicyCmd::RegisterObject(second.clone()))
            .unwrap();
        let relink = Relationship::new(
            "session",
            "s",
            "agent",
            vera_acp::Subject::entity_set("agent", "b", ""),
        );
        assert!(matches!(
            module.direct_policy_cmd(&owner, &policy, PolicyCmd::SetRelationship(relink)),
            Err(AcpError::Unauthorized { .. })
        ));
        module
            .direct_policy_cmd(&other, &policy, PolicyCmd::ArchiveObject(second.clone()))
            .unwrap();
        let next = PolicyCmd::RegisterUnderParent {
            object: Object {
                resource: "session".into(),
                id: "next".into(),
            },
            parent: second,
        };
        let before = module.store.serialize();
        assert!(matches!(
            module.direct_policy_cmd(&other, &policy, next),
            Err(AcpError::Unauthorized { .. })
        ));
        assert_eq!(before, module.store.serialize());
    }
}
