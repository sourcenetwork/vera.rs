//! Object-local archive planning over physical generation-pair counts.

use super::*;
use record_store::RecordStore;

impl AcpModule {
    pub(super) fn cmd_archive_object(
        &mut self,
        creator: &Did,
        policy_id: &str,
        obj: Object,
        budget: &CommandBudget,
    ) -> Result<PolicyCmdResult> {
        let policy = self.query_policy(policy_id)?;
        let mut owner = self
            .registration_owner_record_with_budget(policy_id, &obj, Some(budget))?
            .ok_or_else(|| AcpError::ObjectNotRegistered {
                resource: obj.resource.clone(),
                object_id: obj.id.clone(),
            })?;
        if owner.archived {
            return Ok(PolicyCmdResult::ArchiveObject {
                found: true,
                relationships_removed: 0,
            });
        }
        if !self
            .check_management_authority_with_budget(creator, policy_id, &obj, "owner", budget)?
        {
            return Err(AcpError::Unauthorized {
                reason: format!(
                    "{} is not the owner of '{}/{}'",
                    creator, obj.resource, obj.id
                ),
            });
        }
        let owner_key = keys::relationship_generation_key(
            policy_id,
            owner.generations,
            &keys::relationship_storage_key(&owner.relationship),
        );
        let removals = self.archive_relationships(&policy, &obj, &owner_key)?;
        let removed = u64::try_from(removals.len())
            .ok()
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| AcpError::State("archive relationship count overflow".into()))?;
        let changes = relationship_mutations::prepare_removals(&self.store, &removals)
            .map_err(relation_state_error)?;
        self.store
            .apply_records(changes)
            .map_err(relation_state_error)?;
        owner.archived = true;
        self.set_relationship(&owner)?;
        Ok(PolicyCmdResult::ArchiveObject {
            found: true,
            relationships_removed: removed,
        })
    }

    fn archive_relationships(
        &self,
        policy: &PolicyRecord,
        object: &Object,
        owner_key: &[u8],
    ) -> Result<Vec<Vec<u8>>> {
        let prefix = object_pairs::prefix(&policy.policy.id, &object.resource, &object.id);
        let suffix = keys::object_prefix(&object.resource, &object.id);
        let active = policy.relations.active_ids();
        let mut removals = Vec::new();
        let mut owner_found = false;
        for (key, value) in self.store.prefix_iter(&prefix) {
            let pair = object_pairs::parse_pair(&prefix, key).map_err(relation_state_error)?;
            let expected = relationship_index::decode_count(value).map_err(relation_state_error)?;
            if pair.target >= policy.relations.next || pair.subject >= policy.relations.next {
                return Err(AcpError::State(
                    "object pair generation was never allocated".into(),
                ));
            }
            if !active.contains(&pair.target) || !active.contains(&pair.subject) {
                continue;
            }
            let rows = keys::relationship_generation_prefix(&policy.policy.id, pair, &suffix);
            let mut count = 0u64;
            for (key, value) in self.store.prefix_iter(&rows) {
                if key.len() > crate::kv_store::NATIVE_MAX_KEY_BYTES
                    || value.len() > crate::kv_store::NATIVE_MAX_VALUE_BYTES
                {
                    return Err(AcpError::State(
                        "archive relationship exceeds native bounds".into(),
                    ));
                }
                Self::decode_current_relationship(policy, key, value)?;
                count = count
                    .checked_add(1)
                    .ok_or_else(|| AcpError::State("archive relationship count overflow".into()))?;
                if key == owner_key {
                    owner_found = true;
                } else {
                    removals.push(key.to_vec());
                }
            }
            if count != expected {
                return Err(AcpError::State(
                    "object pair count differs from its relationships".into(),
                ));
            }
        }
        if !owner_found {
            return Err(AcpError::State("object owner pair index missing".into()));
        }
        Ok(removals)
    }
}

#[cfg(test)]
#[path = "object_archive_tests.rs"]
mod tests;
