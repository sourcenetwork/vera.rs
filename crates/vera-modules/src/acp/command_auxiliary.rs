//! Budgeted commitment reads and amendment persistence used by registration reveals.

use super::*;

impl AcpModule {
    /// Fetch a registration commitment by its autoincrement ID.
    #[allow(unused_variables)]
    pub fn query_registrations_commitment(&self, id: u64) -> Result<RegistrationsCommitment> {
        self.query_registrations_commitment_with_budget(id, &CommandBudget::new(u64::MAX))
    }

    /// Locate a reveal's policy while reserving its commitment and liveness reads.
    pub fn query_registrations_commitment_with_budget(
        &self,
        id: u64,
        budget: &CommandBudget,
    ) -> Result<RegistrationsCommitment> {
        budget.finish(self.commitment_for_command(id, budget))
    }

    fn commitment_for_command(
        &self,
        id: u64,
        budget: &CommandBudget,
    ) -> Result<RegistrationsCommitment> {
        let record = self
            .get_commitment_by_id_with_budget(id, Some(budget))?
            .ok_or(AcpError::CommitmentNotFound { id })?;
        let key = keys::policy_key(&record.policy_id);
        budget
            .permissions
            .records
            .read(&key, self.store.get_ref(&key))?;
        if self.get_policy_record(&record.policy_id)?.is_none() {
            return Err(AcpError::CommitmentNotFound { id });
        }
        Ok(record)
    }

    pub(super) fn get_commitment_by_id(&self, id: u64) -> Result<Option<RegistrationsCommitment>> {
        self.get_commitment_by_id_with_budget(id, None)
    }

    pub(super) fn get_commitment_by_id_with_budget(
        &self,
        id: u64,
        budget: Option<&CommandBudget>,
    ) -> Result<Option<RegistrationsCommitment>> {
        let key = keys::commitment_key(id);
        let bytes = self.store.get_ref(&key);
        if let Some(budget) = budget {
            budget.permissions.records.read(&key, bytes)?;
        }
        bytes
            .map(|bytes| {
                let record: RegistrationsCommitment = borsh::from_slice(bytes)
                    .map_err(|error| AcpError::State(format!("invalid commitment: {error}")))?;
                if id == 0 || record.id != id || record.commitment.len() != 32 {
                    return Err(AcpError::State(
                        "commitment identity or root mismatch".into(),
                    ));
                }
                Ok(record)
            })
            .transpose()
    }

    #[cfg(test)]
    pub(super) fn create_amendment_event(&mut self, event: &mut AmendmentEvent) -> Result<()> {
        self.create_amendment_event_with_budget(event, None)
    }

    pub(super) fn create_amendment_event_with_budget(
        &mut self,
        event: &mut AmendmentEvent,
        budget: Option<&CommandBudget>,
    ) -> Result<()> {
        use record_store::RecordStore;
        let counter_key = keys::amendment_event_counter_key();
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
        let key = keys::amendment_event_key(next);
        let previous = self.store.get_ref(&key);
        if let Some(budget) = budget {
            budget.permissions.records.read(&key, previous)?;
        }
        if previous.is_some() {
            return Err(AcpError::State(
                "amendment identifier already exists".into(),
            ));
        }
        event.id = next;
        let encoded = match budget {
            Some(budget) => budget.permissions.records.encode_borsh(&key, event)?,
            None => borsh::to_vec(event)
                .map_err(|e| AcpError::State(format!("serialize amendment event: {e}")))?,
        };
        let index = keys::amendment_event_policy_index_key(&event.policy_id, event.id);
        if let Some(budget) = budget {
            budget
                .permissions
                .records
                .write(&counter_key, Some(&next.to_be_bytes()))?;
            budget.permissions.records.write(&index, Some(&[]))?;
        }
        // The Borsh record and both small writes are fully reserved before publication.
        let changes = vec![
            self.store
                .prepare_write(&counter_key, Some(&next.to_be_bytes()))
                .map_err(relation_state_error)?,
            (key, Some(encoded)),
            self.store
                .prepare_write(&index, Some(&[]))
                .map_err(relation_state_error)?,
        ];
        self.store
            .apply_records(changes)
            .map_err(relation_state_error)
    }

    pub(super) fn update_amendment_event(&mut self, event: &AmendmentEvent) -> Result<()> {
        self.update_amendment_event_with_budget(event, None)
    }

    pub(super) fn update_amendment_event_with_budget(
        &mut self,
        event: &AmendmentEvent,
        budget: Option<&CommandBudget>,
    ) -> Result<()> {
        let key = keys::amendment_event_key(event.id);
        let bytes = match budget {
            Some(budget) => budget.permissions.records.encode_borsh(&key, event)?,
            None => borsh::to_vec(event)
                .map_err(|e| AcpError::State(format!("serialize amendment event: {e}")))?,
        };
        self.store.put(&key, bytes);
        Ok(())
    }
}
