use alloy_primitives::B256;
use commonware_codec::Encode as _;
use vera_modules::acp::keys;
use vera_permission::{
    ModuleId, PERMISSION_LIMITS, PolicySnapshotProof, PrefixProof, RECORD_PROOF_BYTES,
    encoded_size, policy_snapshot_prefixes, validate_policy_prefix,
};

use super::{BackendError, NativeDb, evidence::charge, record_proof_at};

/// Capture a policy record and its complete prefixes under the same partition guards.
/// The records share one record and byte budget, and the proofs one proof-byte budget.
pub async fn policy_snapshot_at(
    databases: [&NativeDb; 4],
    expected: B256,
    policy: &str,
) -> Result<PolicySnapshotProof, BackendError> {
    let prefixes = policy_snapshot_prefixes(policy);
    validate_policy_prefix(policy, &prefixes[0])?;
    let record = record_proof_at(
        databases,
        expected,
        ModuleId::Acp,
        &keys::policy_key(policy),
    )
    .await?;
    let empty = |prefix: &[u8]| PrefixProof {
        module: ModuleId::Acp,
        prefix: prefix.to_vec().into(),
        roots: record.roots,
        proof: Default::default(),
    };
    let mut proof = PolicySnapshotProof {
        prefixes: [
            empty(&prefixes[0]),
            empty(&prefixes[1]),
            empty(&prefixes[2]),
        ],
        policy: record,
    };
    let mut remaining = PERMISSION_LIMITS.reads;
    // Hex doubles each proof byte in the serialized response.
    let mut bytes = (RECORD_PROOF_BYTES - encoded_size(&proof, RECORD_PROOF_BYTES)?) / 2;
    for (slot, prefix) in proof.prefixes.iter_mut().zip(&prefixes) {
        let evidence = super::permission::prefix_proof(
            databases[ModuleId::Acp.index()],
            prefix,
            &mut remaining,
            bytes,
        )
        .await?;
        let encoded = evidence.encode();
        charge(&mut bytes, encoded.len())?;
        slot.proof = encoded.to_vec().into();
    }
    proof.verify(expected, policy)?;
    Ok(proof)
}
