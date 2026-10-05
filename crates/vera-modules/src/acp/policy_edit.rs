//! Atomic definition replacement with explicit caller-owned work accounting.

use super::policy_edit_budget::EditRecords;
use super::record_store::RecordStore;
use super::*;

impl AcpModule {
    /// Replace the current definition without an expected-parent check or revision DAG.
    /// Runtime callers use the budgeted variant; this convenience method has no work limit.
    pub fn edit_policy(
        &mut self,
        creator: &Did,
        policy_id: &str,
        policy: &str,
        marshal_type: PolicyMarshalingType,
    ) -> Result<(u64, PolicyRecord)> {
        self.edit_policy_with_budget(
            creator,
            policy_id,
            policy,
            marshal_type,
            None,
            &PolicyEditBudget::new(u64::MAX),
        )
    }

    /// Edit at an authenticated revision within the caller's remaining work allowance.
    /// Exhaustion leaves policy records, indexes and caches unchanged; consumed work
    /// stays in the budget even when an enclosing command or batch rolls back.
    pub fn edit_policy_at_with_budget(
        &mut self,
        creator: &Did,
        policy_id: &str,
        policy: &str,
        marshal_type: PolicyMarshalingType,
        modified_at: &Timestamp,
        budget: &PolicyEditBudget,
    ) -> Result<(u64, PolicyRecord)> {
        self.edit_policy_with_budget(
            creator,
            policy_id,
            policy,
            marshal_type,
            Some(modified_at),
            budget,
        )
    }

    fn edit_policy_with_budget(
        &mut self,
        creator: &Did,
        policy_id: &str,
        policy: &str,
        marshal_type: PolicyMarshalingType,
        modified_at: Option<&Timestamp>,
        budget: &PolicyEditBudget,
    ) -> Result<(u64, PolicyRecord)> {
        let records = EditRecords {
            store: &self.store,
            budget,
        };
        let policy_key = keys::policy_key(policy_id);
        let bytes = records
            .read_record(&policy_key)
            .map_err(|error| {
                if budget.is_exhausted() {
                    AcpError::PolicyEditBudgetExceeded
                } else {
                    relation_state_error(error)
                }
            })?
            .ok_or_else(|| AcpError::PolicyNotFound {
                id: policy_id.into(),
            })?;
        let existing = Self::decode_policy_record(policy_id, &bytes)?;
        if let Some(revision) = modified_at {
            Self::validate_policy_revision(&existing, revision)?;
        }

        if existing.metadata.owner_did != creator.to_string() {
            return Err(AcpError::Unauthorized {
                reason: "only the policy creator can edit it".into(),
            });
        }

        budget.definition(policy.len())?;
        let mut new_zanzibar = Self::compile_policy(
            policy,
            &marshal_type,
            0,
            Some(existing.policy.specification),
        )?;

        let new_resources: std::collections::BTreeSet<_> = new_zanzibar
            .resources
            .iter()
            .map(|resource| resource.name.as_str())
            .collect();
        for resource in &existing.policy.resources {
            if !new_resources.contains(resource.name.as_str()) {
                return Err(AcpError::InvalidPolicy {
                    reason: format!(
                        "resource '{}' cannot be removed from an existing policy",
                        resource.name
                    ),
                });
            }
        }
        if existing.policy.actor.as_ref().map(|actor| &actor.name)
            != new_zanzibar.actor.as_ref().map(|actor| &actor.name)
        {
            return Err(AcpError::InvalidPolicy {
                reason: "actor resource cannot be renamed".into(),
            });
        }
        new_zanzibar.id = policy_id.to_string();
        let (relations, retired) = existing
            .relations
            .updated(&existing.policy, &new_zanzibar)
            .map_err(relation_state_error)?;
        let (removed, changes) = self
            .prepare_relation_edit(policy_id, &existing.relations, &relations, &retired, budget)
            .map_err(|error| {
                if budget.is_exhausted() {
                    AcpError::PolicyEditBudgetExceeded
                } else {
                    error
                }
            })?;
        let new_record = PolicyRecord {
            relations,
            supplied_metadata: existing.supplied_metadata.clone(),
            last_modified: modified_at.cloned().or(existing.last_modified.clone()),
            policy: new_zanzibar.clone(),
            raw_policy: policy.to_string(),
            marshal_type,
            metadata: existing.metadata,
        };
        let encoded = budget.encode(&policy_key, &new_record)?;
        for (key, value) in changes {
            match value {
                Some(value) => self.store.put(&key, value),
                None => self.store.delete(&key),
            }
        }

        self.store.put(&policy_key, encoded);
        self.zanzibar_policies
            .insert(policy_id.to_string(), Arc::new(new_zanzibar));

        Ok((removed, new_record))
    }
}
