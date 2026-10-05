//! Explicit prepaid point mutations for one command's candidate state.

use super::{
    AcpModule, CommandBudget, RelationshipRecord, Result,
    record_store::{RecordChange, RecordStore},
    relation_state_error, relationship_mutations,
};
use crate::kv_store::InMemoryKvStore;

/// Kept private to command persistence: planners prepare every change through
/// this adapter before passing the complete plan back to its atomic apply.
/// Direct writes remain rejected by RecordStore's defaults.
struct CommandRecords<'a> {
    store: &'a mut InMemoryKvStore,
    budget: &'a CommandBudget,
}

impl RecordStore for CommandRecords<'_> {
    fn read_record(&self, key: &[u8]) -> zanzibar::error::Result<Option<Vec<u8>>> {
        let value = self.store.get_ref(key);
        self.budget
            .permissions
            .records
            .read(key, value)
            .map_err(|error| zanzibar::error::Error::Serialization(error.to_string()))?;
        Ok(value.map(<[u8]>::to_vec))
    }

    fn scan_records(&self, _prefix: &[u8]) -> zanzibar::error::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        Err(zanzibar::error::Error::Serialization(
            "command storage requires point reads".into(),
        ))
    }

    fn prepare_write(
        &self,
        key: &[u8],
        value: Option<&[u8]>,
    ) -> zanzibar::error::Result<RecordChange> {
        self.budget
            .permissions
            .records
            .write(key, value)
            .map_err(|error| zanzibar::error::Error::Serialization(error.to_string()))?;
        Ok((key.to_vec(), value.map(<[u8]>::to_vec)))
    }

    fn prepare_json<T: serde::Serialize>(
        &self,
        key: &[u8],
        value: &T,
    ) -> zanzibar::error::Result<RecordChange> {
        let encoded = self
            .budget
            .permissions
            .records
            .encode(key, value)
            .map_err(|error| zanzibar::error::Error::Serialization(error.to_string()))?;
        Ok((key.to_vec(), Some(encoded)))
    }

    fn apply_records(&mut self, changes: Vec<RecordChange>) -> zanzibar::error::Result<()> {
        // Only the private central planners call this adapter with prepaid changes.
        // No fallible work or second reservation is allowed after publication starts.
        self.store.apply_records(changes)
    }
}

impl AcpModule {
    pub(super) fn set_relationship_with_budget(
        &mut self,
        record: &RelationshipRecord,
        budget: &CommandBudget,
    ) -> Result<()> {
        budget.finish(
            relationship_mutations::put(
                &mut CommandRecords {
                    store: &mut self.store,
                    budget,
                },
                record,
            )
            .map_err(relation_state_error),
        )
    }

    pub(super) fn remove_relationship_key_with_budget(
        &mut self,
        key: &[u8],
        budget: &CommandBudget,
    ) -> Result<()> {
        budget.finish(
            relationship_mutations::remove(
                &mut CommandRecords {
                    store: &mut self.store,
                    budget,
                },
                key,
            )
            .map_err(relation_state_error),
        )
    }
}

#[cfg(test)]
#[path = "command_storage_tests.rs"]
mod tests;
