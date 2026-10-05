use alloy_primitives::B256;
use commonware_codec::Encode as _;
use vera_modules::acp::keys;
use vera_permission::{
    ModuleId, PAGE_PROOF_BYTES, PERMISSION_LIMITS, PermissionError, PolicyPrefixPageProof,
    PolicyPrefixProof, PrefixPageProof, PrefixPageRequest, PrefixProof, RECORD_PROOF_BYTES,
    encoded_size, validate_policy_prefix,
};

use super::{BackendError, NativeDb, record_proof_at};

/// Capture policy liveness and a relationship prefix under the same partition guards.
pub async fn policy_prefix_proof_at(
    databases: [&NativeDb; 4],
    expected: B256,
    policy: &str,
    prefix: &[u8],
) -> Result<PolicyPrefixProof, BackendError> {
    validate_policy_prefix(policy, prefix)?;
    let record = record_proof_at(
        databases,
        expected,
        ModuleId::Acp,
        &keys::policy_key(policy),
    )
    .await?;
    let mut remaining = PERMISSION_LIMITS.reads;
    remaining.records = remaining
        .records
        .checked_sub(1)
        .ok_or(PermissionError::Limit)?;
    remaining.bytes = remaining
        .bytes
        .checked_sub(record.key.len())
        .and_then(|n| n.checked_sub(record.value.as_ref().map_or(0, |v| v.len())))
        .ok_or(PermissionError::Limit)?;
    let mut proof = PolicyPrefixProof {
        prefix: PrefixProof {
            module: ModuleId::Acp,
            prefix: prefix.to_vec().into(),
            roots: record.roots,
            proof: Default::default(),
        },
        policy: record,
    };
    let overhead = encoded_size(&proof, RECORD_PROOF_BYTES)?;
    let evidence = super::permission::prefix_proof(
        databases[ModuleId::Acp.index()],
        prefix,
        &mut remaining,
        (RECORD_PROOF_BYTES - overhead) / 2,
    )
    .await?;
    proof.prefix.proof = evidence.encode().into();
    proof.verify(expected, policy, prefix, RECORD_PROOF_BYTES)?;
    Ok(proof)
}

/// Capture policy liveness and one relationship page under the same partition guards.
pub async fn policy_prefix_page_at(
    databases: [&NativeDb; 4],
    expected: B256,
    policy: &str,
    request: &PrefixPageRequest,
) -> Result<PolicyPrefixPageProof, BackendError> {
    validate_policy_prefix(policy, &request.prefix)?;
    request.validate()?;
    if request.module != ModuleId::Acp {
        return Err(PermissionError::Invalid("policy page must use ACP storage").into());
    }
    let record = record_proof_at(
        databases,
        expected,
        ModuleId::Acp,
        &keys::policy_key(policy),
    )
    .await?;
    let mut proof = PolicyPrefixPageProof {
        page: PrefixPageProof {
            request: request.clone(),
            roots: record.roots,
            proof: Default::default(),
        },
        policy: record,
    };
    let overhead = encoded_size(&proof, PAGE_PROOF_BYTES)?;
    let evidence = super::permission::page_proof(
        databases[ModuleId::Acp.index()],
        request,
        (PAGE_PROOF_BYTES - overhead) / 2,
    )
    .await?;
    proof.page.proof = evidence.encode().into();
    proof.verify(expected, policy, request, PAGE_PROOF_BYTES)?;
    Ok(proof)
}
