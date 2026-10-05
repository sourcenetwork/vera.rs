use std::collections::BTreeSet;

use alloy_primitives::B256;
use commonware_codec::Encode as _;
use vera_modules::acp::keys;
use vera_permission::{
    ModuleId, PAGE_DATA_BYTES, PAGE_PROOF_BYTES, PERMISSION_LIMITS, PermissionError,
    PolicyPrefixPageProof, PolicyPrefixProof, PrefixPageProof, PrefixPageRequest, PrefixProof,
    RECORD_PROOF_BYTES, ReadLimits, RecordProof, current::Entry, encoded_size,
    relationship_object_key, validate_policy_prefix,
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
    remaining.reads -= 2;
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
        objects: Vec::new(),
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
    let mut bytes = RECORD_PROOF_BYTES - encoded_size(&proof, RECORD_PROOF_BYTES)?;
    proof.objects = capture_objects(
        databases,
        expected,
        policy,
        &evidence.entries,
        &mut remaining,
        &mut bytes,
    )
    .await?;
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
        objects: Vec::new(),
    };
    let overhead = encoded_size(&proof, PAGE_PROOF_BYTES)?;
    let evidence = super::permission::page_proof(
        databases[ModuleId::Acp.index()],
        request,
        (PAGE_PROOF_BYTES - overhead) / 2,
    )
    .await?;
    proof.page.proof = evidence.encode().into();
    let mut remaining = ReadLimits {
        bytes: PAGE_DATA_BYTES,
        ..PERMISSION_LIMITS.reads
    };
    remaining.reads -= 2;
    charge(
        &mut remaining.records,
        usize::from(proof.policy.value.is_some()),
    )?;
    charge(
        &mut remaining.bytes,
        proof.policy.key.len() + proof.policy.value.as_ref().map_or(0, |value| value.len()),
    )?;
    charge(
        &mut remaining.bytes,
        request.prefix.len() + request.start.len(),
    )?;
    for entry in &evidence.entries {
        charge(&mut remaining.records, 1)?;
        charge(&mut remaining.bytes, entry.key.len() + entry.value.len())?;
    }
    let mut bytes = PAGE_PROOF_BYTES - encoded_size(&proof, PAGE_PROOF_BYTES)?;
    proof.objects = capture_objects(
        databases,
        expected,
        policy,
        &evidence.entries,
        &mut remaining,
        &mut bytes,
    )
    .await?;
    proof.verify(expected, policy, request, PAGE_PROOF_BYTES)?;
    Ok(proof)
}

async fn capture_objects(
    databases: [&NativeDb; 4],
    root: B256,
    policy: &str,
    entries: &[Entry],
    remaining: &mut ReadLimits,
    bytes: &mut usize,
) -> Result<Vec<RecordProof>, BackendError> {
    let mut keys = BTreeSet::new();
    for entry in entries {
        if let Some(key) = relationship_object_key(policy, &entry.key, &entry.value)?
            && !keys.contains(&key)
        {
            charge(&mut remaining.reads, 1)?;
            charge(&mut remaining.bytes, key.len())?;
            keys.insert(key);
        }
    }
    let mut objects = Vec::with_capacity(keys.len());
    for key in keys {
        let proof = record_proof_at(databases, root, ModuleId::Acp, &key).await?;
        if let Some(value) = &proof.value {
            charge(&mut remaining.records, 1)?;
            charge(&mut remaining.bytes, value.len())?;
        }
        charge(
            bytes,
            encoded_size(&proof, *bytes)? + usize::from(!objects.is_empty()),
        )?;
        objects.push(proof);
    }
    Ok(objects)
}

fn charge(remaining: &mut usize, amount: usize) -> Result<(), PermissionError> {
    *remaining = remaining
        .checked_sub(amount)
        .ok_or(PermissionError::Limit)?;
    Ok(())
}
