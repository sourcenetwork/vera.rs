use alloy_primitives::B256;
use vera_modules::acp::{
    keys,
    types::{PolicyRecord, RelationshipRecord},
};

use crate::{ModuleId, PermissionError, RecordProof, current::MAX_KEY_BYTES};

/// Validate a policy-scoped relationship selection before storage or proof work.
pub fn validate_policy_prefix(policy: &str, prefix: &[u8]) -> Result<(), PermissionError> {
    if policy.len() != 64
        || !policy
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PermissionError::Invalid("invalid policy identifier"));
    }
    if prefix.len() > MAX_KEY_BYTES {
        return Err(PermissionError::Limit);
    }
    if !prefix.starts_with(&keys::relationship_policy_prefix(policy)) {
        return Err(PermissionError::Invalid(
            "relationship prefix belongs to another policy",
        ));
    }
    Ok(())
}

pub(super) fn verify_policy(
    proof: &RecordProof,
    root: B256,
    policy: &str,
    maximum_bytes: usize,
) -> Result<Option<PolicyRecord>, PermissionError> {
    proof.verify(
        root,
        ModuleId::Acp,
        &keys::policy_key(policy),
        maximum_bytes,
    )?;
    let Some(value) = &proof.value else {
        return Ok(None);
    };
    let record: PolicyRecord = serde_json::from_slice(value)
        .map_err(|_| PermissionError::Invalid("policy record encoding"))?;
    if record.policy.id != policy {
        return Err(PermissionError::Invalid(
            "policy record differs from its key",
        ));
    }
    record.relations.validate(&record.policy)?;
    Ok(Some(record))
}

/// Decode a physical row and bind every stamp to its storage key.
pub(super) fn relationship_record(
    policy: &str,
    key: &[u8],
    value: &[u8],
) -> Result<RelationshipRecord, PermissionError> {
    let record: RelationshipRecord = serde_json::from_slice(value)
        .map_err(|_| PermissionError::Invalid("relationship record encoding"))?;
    if record.policy_id != policy
        || (record.relationship.relation == "owner" && record.incarnation != 0)
        || keys::relationship_generation_key(
            &record.policy_id,
            record.generations,
            &keys::relationship_storage_key(&record.relationship, record.incarnation),
        ) != key
    {
        return Err(PermissionError::Invalid(
            "relationship record differs from its generation key",
        ));
    }
    Ok(record)
}

/// Check a canonical physical row against authenticated policy and object state.
pub(super) fn current_relationship(
    policy: &PolicyRecord,
    record: &RelationshipRecord,
    incarnation: u64,
) -> Result<bool, PermissionError> {
    if record.incarnation > incarnation {
        return Err(PermissionError::Invalid(
            "relationship incarnation exceeds object state",
        ));
    }
    if record.incarnation < incarnation
        || !policy.relations.contains(record.generations.target)
        || !policy.relations.contains(record.generations.subject)
    {
        return Ok(false);
    }
    if policy.relations.pair(&record.relationship)? != record.generations {
        return Err(PermissionError::Invalid(
            "relationship generations differ from policy",
        ));
    }
    Ok(true)
}

#[cfg(test)]
mod tests;
