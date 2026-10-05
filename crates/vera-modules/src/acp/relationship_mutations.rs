//! Physical relationship writes after caller validation and mutation preparation.

use super::{keys, record_store::RecordStore, types::RelationshipRecord};
use zanzibar::error::Result;

pub(super) fn put<S: RecordStore>(store: &mut S, record: &RelationshipRecord) -> Result<()> {
    let key = keys::relationship_key(
        &record.policy_id,
        &keys::relationship_storage_key(&record.relationship),
    );
    store.write_record(&key, serde_json::to_vec(record)?)
}

pub(super) fn remove<S: RecordStore>(store: &mut S, key: &[u8]) -> Result<()> {
    store.remove_record(key)
}
