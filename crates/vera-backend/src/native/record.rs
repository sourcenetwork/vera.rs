use alloy_primitives::B256;
use vera_permission::{ModuleId, PermissionError, RECORD_PROOF_BYTES, RecordProof};

use super::{
    BackendError, MAX_KEY_BYTES, NativeDb, combine_module_roots,
    evidence::{point_evidence, storage},
};

/// Prove a current record while the caller retains all four partition read guards.
pub async fn record_proof_at(
    databases: [&NativeDb; 4],
    expected: B256,
    module: ModuleId,
    key: &[u8],
) -> Result<RecordProof, BackendError> {
    if key.len() > MAX_KEY_BYTES {
        return Err(PermissionError::Limit.into());
    }
    let roots = databases.map(|db| db.root().0);
    if combine_module_roots(&roots) != expected {
        return Err(PermissionError::Invalid("selected module root changed").into());
    }
    let db = databases[module.index()];
    let key = key.to_vec();
    let value = db.get(&key).await.map_err(storage)?;
    let proof = point_evidence(db, &key, value.is_some(), RECORD_PROOF_BYTES / 2).await?;
    let record = RecordProof {
        module,
        key: key.into(),
        value: value.map(Into::into),
        roots: roots.map(B256::from),
        proof: proof.into(),
    };
    record.verify(expected, module, &record.key, RECORD_PROOF_BYTES)?;
    Ok(record)
}
