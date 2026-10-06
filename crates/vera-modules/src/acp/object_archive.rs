//! Atomic object archive over current incarnation counters.

use super::*;
use command_storage::CommandRecords;
use record_store::RecordStore;

impl AcpModule {
    pub(super) fn cmd_archive_object(
        &mut self,
        creator: &Did,
        policy_id: &str,
        obj: Object,
        budget: &CommandBudget,
    ) -> Result<PolicyCmdResult> {
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
        let mut records = CommandRecords {
            store: &mut self.store,
            budget,
        };
        let bytes = records
            .read_record(&keys::policy_key(policy_id))
            .map_err(relation_state_error)?
            .ok_or_else(|| AcpError::PolicyNotFound {
                id: policy_id.into(),
            })?;
        let policy = Self::decode_policy_record(policy_id, &bytes)?;
        let current = object_state::read(&records, policy_id, &obj.resource, &obj.id)
            .map_err(relation_state_error)?;
        let active = policy.relations.active_ids();
        let relations = policy
            .relations
            .active
            .get(&obj.resource)
            .ok_or_else(|| AcpError::State("archive resource missing".into()))?;
        let mut removed = 1u64;
        let mut changes = Vec::new();
        for &target in relations.values().filter(|&&target| target != 0) {
            let subjects =
                relationship_index::live_pairs_for_active(&records, policy_id, target, &active)
                    .map_err(relation_state_error)?;
            for subject in subjects {
                budget.permissions.records.pair()?;
                let pair = RelationPair { target, subject };
                let key = object_pairs::pair_key(policy_id, &obj.resource, &obj.id, current, pair);
                let Some(bytes) = records.read_record(&key).map_err(relation_state_error)? else {
                    continue;
                };
                let count =
                    relationship_index::decode_count(&bytes).map_err(relation_state_error)?;
                removed = removed
                    .checked_add(count)
                    .ok_or_else(|| AcpError::State("archive relationship count overflow".into()))?;
                changes.push(
                    relationship_index::prepare_archive_count(&records, policy_id, pair, count)
                        .map_err(relation_state_error)?,
                );
            }
        }
        let owner_count = records
            .read_record(&object_pairs::key(&owner))
            .map_err(relation_state_error)?;
        if owner_count.as_deref() != Some(1u64.to_be_bytes().as_slice()) {
            return Err(AcpError::State(
                "archive owner object counter is not one".into(),
            ));
        }
        owner.archived = true;
        changes.extend(
            relationship_mutations::prepare_put(&records, &owner).map_err(relation_state_error)?,
        );
        let (next, state) =
            object_state::prepare_advance(&records, policy_id, &obj.resource, &obj.id)
                .map_err(relation_state_error)?;
        if next.checked_sub(1) != Some(current) {
            return Err(AcpError::State(
                "archive incarnation changed during preparation".into(),
            ));
        }
        changes.push(state);
        changes.extend(
            object_cleanup::prepare_job(&records, policy_id, &obj, current)
                .map_err(relation_state_error)?,
        );
        records
            .apply_records(changes)
            .map_err(relation_state_error)?;
        Ok(PolicyCmdResult::ArchiveObject {
            found: true,
            relationships_removed: removed,
        })
    }
}

#[cfg(test)]
#[path = "object_archive_tests.rs"]
mod tests;
