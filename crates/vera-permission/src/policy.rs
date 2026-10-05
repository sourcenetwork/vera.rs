use alloy_primitives::B256;
use vera_modules::acp::{keys, types::PolicyRecord};

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
) -> Result<bool, PermissionError> {
    proof.verify(
        root,
        ModuleId::Acp,
        &keys::policy_key(policy),
        maximum_bytes,
    )?;
    let Some(value) = &proof.value else {
        return Ok(false);
    };
    let record: PolicyRecord = serde_json::from_slice(value)
        .map_err(|_| PermissionError::Invalid("policy record encoding"))?;
    if record.policy.id != policy {
        return Err(PermissionError::Invalid(
            "policy record differs from its key",
        ));
    }
    Ok(true)
}

#[cfg(test)]
mod tests;
