//! Atomic commitment records and their lookup/deadline indexes.

use super::{
    record_store::{RecordChange, RecordStore},
    *,
};

impl AcpModule {
    #[cfg(test)]
    pub(super) fn create_commitment(
        &mut self,
        commitment: &mut RegistrationsCommitment,
    ) -> Result<()> {
        self.create_commitment_with_budget(commitment, None)
    }

    pub(super) fn create_commitment_with_budget(
        &mut self,
        commitment: &mut RegistrationsCommitment,
        budget: Option<&CommandBudget>,
    ) -> Result<()> {
        let counter_key = keys::commitment_counter_key();
        let bytes = self.store.get_ref(&counter_key);
        if let Some(budget) = budget {
            budget.permissions.records.read(&counter_key, bytes)?;
        }
        let counter = bytes
            .map(|bytes| {
                bytes
                    .try_into()
                    .map(u64::from_be_bytes)
                    .map_err(|_| AcpError::State("invalid record counter".into()))
            })
            .transpose()?
            .unwrap_or(0);
        let next = counter
            .checked_add(1)
            .ok_or_else(|| AcpError::State("record counter exhausted".into()))?;
        let key = keys::commitment_key(next);
        let previous = self.store.get_ref(&key);
        if let Some(budget) = budget {
            budget.permissions.records.read(&key, previous)?;
        }
        if previous.is_some() {
            return Err(AcpError::State(
                "commitment identifier already exists".into(),
            ));
        }
        commitment.id = next;
        let mut changes = self.prepare_commitment_update(commitment, None, budget)?;
        changes.push(self.prepare_commitment_index(
            &counter_key,
            Some(&next.to_be_bytes()),
            budget,
        )?);
        self.store
            .apply_records(changes)
            .map_err(relation_state_error)
    }

    pub(super) fn update_commitment(&mut self, commitment: &RegistrationsCommitment) -> Result<()> {
        self.update_commitment_with_budget(commitment, None)
    }

    pub(super) fn update_commitment_with_budget(
        &mut self,
        commitment: &RegistrationsCommitment,
        budget: Option<&CommandBudget>,
    ) -> Result<()> {
        let previous = self.get_commitment_by_id_with_budget(commitment.id, budget)?;
        let changes = self.prepare_commitment_update(commitment, previous.as_ref(), budget)?;
        self.store
            .apply_records(changes)
            .map_err(relation_state_error)
    }

    fn prepare_commitment_update(
        &self,
        commitment: &RegistrationsCommitment,
        previous: Option<&RegistrationsCommitment>,
        budget: Option<&CommandBudget>,
    ) -> Result<Vec<RecordChange>> {
        let key = keys::commitment_key(commitment.id);
        let bytes = match budget {
            Some(budget) => budget.permissions.records.encode_borsh(&key, commitment)?,
            None => borsh::to_vec(commitment)
                .map_err(|e| AcpError::State(format!("serialize commitment: {e}")))?,
        };
        let mut changes = Vec::new();
        if let Some(previous) = previous {
            for key in [
                Self::commitment_expiry_key(previous),
                keys::commitment_by_commitment_index_key(&previous.commitment, previous.id),
                keys::commitment_policy_index_key(&previous.policy_id, previous.id),
            ] {
                changes.push(self.prepare_commitment_index(&key, None, budget)?);
            }
        }
        if !commitment.expired {
            changes.push(self.prepare_commitment_index(
                &Self::commitment_expiry_key(commitment),
                Some(&[]),
                budget,
            )?);
        }
        for key in [
            keys::commitment_by_commitment_index_key(&commitment.commitment, commitment.id),
            keys::commitment_policy_index_key(&commitment.policy_id, commitment.id),
        ] {
            changes.push(self.prepare_commitment_index(&key, Some(&[]), budget)?);
        }
        // The streamed record encoding is already paid; only indexes reserve here.
        changes.push((key, Some(bytes)));
        Ok(changes)
    }

    fn prepare_commitment_index(
        &self,
        key: &[u8],
        value: Option<&[u8]>,
        budget: Option<&CommandBudget>,
    ) -> Result<RecordChange> {
        if let Some(budget) = budget {
            budget.permissions.records.write(key, value)?;
        }
        self.store
            .prepare_write(key, value)
            .map_err(relation_state_error)
    }
}

#[cfg(test)]
#[path = "commitment_storage_tests.rs"]
mod tests;
