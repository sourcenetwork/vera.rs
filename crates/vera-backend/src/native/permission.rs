use alloy_primitives::B256;
use commonware_codec::{Encode as _, EncodeSize as _};
use vera_permission::{
    AccessRequest, PermissionError, PermissionLimits, PermissionProof, PermissionRead, ReadLimits,
    RecordRead, capture_reads,
    current::{Entry, Exclusion, PrefixEvidence, successor},
    encoded_size, verify_permission_proof,
};

use super::{BackendError, InMemoryKvStore, NativeDb, NativeStateSet, combine_module_roots};

/// Capture permission evidence at the selected current-state root.
///
/// Acquisition releases partial guards before waiting on a busy partition.
/// All namespace read locks remain held through generation. The snapshot selects
/// candidate reads only; authenticated replay must succeed before returning them.
/// Historical roots unavailable in the live databases return an error.
pub async fn permission_proof(
    set: &NativeStateSet,
    expected: B256,
    snapshot: InMemoryKvStore,
    policy: &str,
    request: &AccessRequest,
    limits: PermissionLimits,
) -> Result<PermissionProof, BackendError> {
    let [a, b, h, n] = super::read_partitions([&set.0, &set.1, &set.2, &set.3]).await;
    permission_proof_at(
        [&a, &b, &h, &n],
        expected,
        snapshot,
        policy,
        request,
        limits,
    )
    .await
}

/// Generate evidence from immutable partition borrows held at one selected revision.
/// Shared database callers must retain their read guards until this call returns.
pub async fn permission_proof_at(
    [a, b, h, n]: [&NativeDb; 4],
    expected: B256,
    snapshot: InMemoryKvStore,
    policy: &str,
    request: &AccessRequest,
    limits: PermissionLimits,
) -> Result<PermissionProof, BackendError> {
    let roots = [a.root().0, b.root().0, h.root().0, n.root().0];
    if combine_module_roots(&roots) != expected {
        return Err(PermissionError::Invalid("selected module root changed").into());
    }
    let reads = capture_reads(snapshot, policy, request, limits)?;
    let mut proof = PermissionProof {
        roots: Some(roots.map(B256::from)),
        reads: Vec::new(),
    };
    let mut bytes = limits.proof_bytes - encoded_size(&proof, limits.proof_bytes)?;
    let mut records = limits.reads;
    for read in reads {
        let read = match read {
            RecordRead::Key(key) => {
                charge(&mut records.bytes, key.len())?;
                let value = a.get(&key).await.map_err(storage)?;
                if let Some(value) = &value {
                    charge(&mut records.records, 1)?;
                    charge(&mut records.bytes, value.len())?;
                }
                let evidence = if value.is_some() {
                    let evidence = a.key_value_proof(key.clone()).await.map_err(storage)?;
                    if evidence.encode_size() > bytes / 2 {
                        return Err(PermissionError::Limit.into());
                    }
                    evidence.encode()
                } else {
                    let evidence = a.exclusion_proof(&key).await.map_err(storage)?;
                    if evidence.encode_size() > bytes / 2 {
                        return Err(PermissionError::Limit.into());
                    }
                    evidence.encode()
                };
                PermissionRead::CurrentPoint {
                    key: key.into(),
                    value: value.map(Into::into),
                    proof: evidence.into(),
                }
            }
            RecordRead::Prefix(prefix) => {
                let evidence = prefix_proof(a, &prefix, &mut records, bytes / 2).await?;
                PermissionRead::CurrentPrefix {
                    prefix: prefix.into(),
                    proof: evidence.encode().into(),
                }
            }
        };
        let size = encoded_size(&read, bytes)?;
        charge(&mut bytes, size + usize::from(!proof.reads.is_empty()))?;
        proof.reads.push(read);
    }
    // Current-state evidence is bound to the supplied root; it has no separate height field.
    verify_permission_proof(expected, 0, policy, request, &proof, limits)?;
    Ok(proof)
}

fn charge(remaining: &mut usize, amount: usize) -> Result<(), PermissionError> {
    *remaining = remaining
        .checked_sub(amount)
        .ok_or(PermissionError::Limit)?;
    Ok(())
}

fn storage(error: impl std::fmt::Display) -> BackendError {
    BackendError::Storage(error.to_string())
}

pub(super) async fn prefix_proof(
    db: &NativeDb,
    prefix: &[u8],
    remaining: &mut ReadLimits,
    mut bytes: usize,
) -> Result<PrefixEvidence, BackendError> {
    charge(&mut remaining.bytes, prefix.len())?;
    let key = prefix.to_vec();
    let boundary = if db.get(&key).await.map_err(storage)?.is_some() {
        None
    } else {
        Some(db.exclusion_proof(&key).await.map_err(storage)?)
    };
    charge(&mut bytes, boundary.encode_size() + 0_usize.encode_size())?;
    let mut next = match &boundary {
        None => Some(key),
        Some(Exclusion::KeyValue(_, record)) => {
            successor(prefix, &record.next_key, prefix).map(<[u8]>::to_vec)
        }
        Some(Exclusion::Commit(..)) => None,
    };
    let mut entries = Vec::new();
    while let Some(key) = next {
        charge(&mut remaining.records, 1)?;
        charge(&mut remaining.bytes, key.len())?;
        let value = db
            .get(&key)
            .await
            .map_err(storage)?
            .ok_or(PermissionError::Invalid("prefix successor unavailable"))?;
        charge(&mut remaining.bytes, value.len())?;
        let proof = db.key_value_proof(key.clone()).await.map_err(storage)?;
        next = successor(&key, &proof.next_key, prefix).map(<[u8]>::to_vec);
        let entry = Entry { key, value, proof };
        charge(
            &mut bytes,
            entry.encode_size() + (entries.len() + 1).encode_size() - entries.len().encode_size(),
        )?;
        entries.push(entry);
    }
    Ok(PrefixEvidence { boundary, entries })
}

pub(super) async fn page_proof(
    db: &NativeDb,
    request: &vera_permission::PrefixPageRequest,
    mut bytes: usize,
) -> Result<PrefixEvidence, BackendError> {
    request.validate()?;
    let mut data = vera_permission::PAGE_DATA_BYTES;
    charge(&mut data, request.prefix.len() + request.start.len())?;
    let start = request.start.to_vec();
    let boundary = if db.get(&start).await.map_err(storage)?.is_some() {
        None
    } else {
        Some(db.exclusion_proof(&start).await.map_err(storage)?)
    };
    charge(&mut bytes, boundary.encode_size() + 0_usize.encode_size())?;
    let mut next = match &boundary {
        None => Some(start),
        Some(Exclusion::KeyValue(_, record)) => {
            successor(&start, &record.next_key, &request.prefix).map(<[u8]>::to_vec)
        }
        Some(Exclusion::Commit(..)) => None,
    };
    let mut entries = Vec::new();
    while entries.len() < usize::from(request.limit) {
        let Some(key) = next else { break };
        let value = db
            .get(&key)
            .await
            .map_err(storage)?
            .ok_or(PermissionError::Invalid("page successor unavailable"))?;
        let data_size = key.len() + value.len();
        if data_size > data {
            if entries.is_empty() {
                return Err(PermissionError::Limit.into());
            }
            break;
        }
        let proof = db.key_value_proof(key.clone()).await.map_err(storage)?;
        let entry = Entry { key, value, proof };
        let size =
            entry.encode_size() + (entries.len() + 1).encode_size() - entries.len().encode_size();
        if size > bytes {
            if entries.is_empty() {
                return Err(PermissionError::Limit.into());
            }
            break;
        }
        charge(&mut data, data_size)?;
        charge(&mut bytes, size)?;
        next = successor(&entry.key, &entry.proof.next_key, &request.prefix).map(<[u8]>::to_vec);
        entries.push(entry);
    }
    Ok(PrefixEvidence { boundary, entries })
}

#[cfg(test)]
mod tests;
