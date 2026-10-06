use std::collections::BTreeMap;

use alloy_primitives::B256;
use vera_modules::acp::{object_state, types::RelationshipRecord};

use crate::{
    ModuleId, PermissionError, ReadLimits, RecordProof, current::Entry, policy::relationship_record,
};

/// Select the required object-state witness after validating a physical row's key.
/// Owner records always use incarnation zero and need no object-state witness.
pub fn relationship_object_key(
    policy: &str,
    key: &[u8],
    value: &[u8],
) -> Result<Option<Vec<u8>>, PermissionError> {
    Ok(object_key(&relationship_record(policy, key, value)?))
}

fn object_key(record: &RelationshipRecord) -> Option<Vec<u8>> {
    (record.relationship.relation != "owner").then(|| {
        object_state::key(
            &record.policy_id,
            &record.relationship.resource,
            &record.relationship.object_id,
        )
    })
}

pub(super) struct ObjectEvidence(BTreeMap<Vec<u8>, u64>);

impl ObjectEvidence {
    pub(super) fn verify(
        root: B256,
        policy: &RecordProof,
        policy_id: &str,
        objects: &[RecordProof],
        entries: &[Entry],
        mut remaining: ReadLimits,
        maximum_bytes: usize,
    ) -> Result<Self, PermissionError> {
        charge_point(&mut remaining, policy)?;
        charge(&mut remaining.reads, 1)?;
        for entry in entries {
            charge(&mut remaining.records, 1)?;
            charge(&mut remaining.bytes, entry.key.len())?;
            charge(&mut remaining.bytes, entry.value.len())?;
        }
        // Charge all witnesses before allocating the decoded selection or verifying paths.
        for proof in objects {
            charge_point(&mut remaining, proof)?;
        }
        let mut required: BTreeMap<Vec<u8>, u64> = BTreeMap::new();
        for entry in entries {
            let record = relationship_record(policy_id, &entry.key, &entry.value)?;
            if let Some(key) = object_key(&record) {
                required
                    .entry(key)
                    .and_modify(|incarnation| {
                        *incarnation = (*incarnation).max(record.incarnation);
                    })
                    .or_insert(record.incarnation);
            }
        }
        let mut values = BTreeMap::new();
        for proof in objects {
            let maximum_incarnation =
                required
                    .remove(proof.key.as_ref())
                    .ok_or(PermissionError::Invalid(
                        "extra or duplicate object witness",
                    ))?;
            if proof.roots != policy.roots {
                return Err(PermissionError::Invalid(
                    "object and policy have different roots",
                ));
            }
            proof.verify(root, ModuleId::Acp, &proof.key, maximum_bytes)?;
            let incarnation = proof
                .value
                .as_deref()
                .map(|value| object_state::decode(value))
                .transpose()?
                .unwrap_or(0);
            if maximum_incarnation > incarnation {
                return Err(PermissionError::Invalid(
                    "relationship incarnation exceeds object state",
                ));
            }
            values.insert(proof.key.to_vec(), incarnation);
        }
        if !required.is_empty() {
            return Err(PermissionError::Invalid("missing object witness"));
        }
        Ok(Self(values))
    }

    pub(super) fn incarnation(&self, record: &RelationshipRecord) -> Result<u64, PermissionError> {
        let Some(key) = object_key(record) else {
            return Ok(0);
        };
        self.0
            .get(&key)
            .copied()
            .ok_or(PermissionError::Invalid("missing object witness"))
    }
}

fn charge_point(remaining: &mut ReadLimits, proof: &RecordProof) -> Result<(), PermissionError> {
    charge(&mut remaining.reads, 1)?;
    charge(&mut remaining.bytes, proof.key.len())?;
    if let Some(value) = &proof.value {
        charge(&mut remaining.records, 1)?;
        charge(&mut remaining.bytes, value.len())?;
    }
    Ok(())
}

fn charge(remaining: &mut usize, amount: usize) -> Result<(), PermissionError> {
    *remaining = remaining
        .checked_sub(amount)
        .ok_or(PermissionError::Limit)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_witnesses_share_point_prefix_and_record_budgets() {
        let policy = RecordProof {
            module: ModuleId::Acp,
            key: b"policy".as_slice().into(),
            value: Some(b"value".as_slice().into()),
            roots: [B256::ZERO; 4],
            proof: Default::default(),
        };
        let exact = ReadLimits {
            reads: 2,
            records: 1,
            bytes: 11,
        };
        assert!(
            ObjectEvidence::verify(B256::ZERO, &policy, "policy", &[], &[], exact, usize::MAX)
                .is_ok()
        );
        for limits in [
            ReadLimits { reads: 1, ..exact },
            ReadLimits {
                records: 0,
                ..exact
            },
            ReadLimits { bytes: 10, ..exact },
        ] {
            assert!(matches!(
                ObjectEvidence::verify(B256::ZERO, &policy, "policy", &[], &[], limits, usize::MAX),
                Err(PermissionError::Limit)
            ));
        }
        let witness = RecordProof {
            key: b"object".as_slice().into(),
            value: None,
            ..policy.clone()
        };
        for limits in [
            ReadLimits {
                reads: 2,
                bytes: 17,
                ..exact
            },
            ReadLimits {
                reads: 3,
                bytes: 16,
                ..exact
            },
        ] {
            assert!(matches!(
                ObjectEvidence::verify(
                    B256::ZERO,
                    &policy,
                    "policy",
                    std::slice::from_ref(&witness),
                    &[],
                    limits,
                    usize::MAX
                ),
                Err(PermissionError::Limit)
            ));
        }
        assert!(matches!(
            ObjectEvidence::verify(
                B256::ZERO,
                &policy,
                "policy",
                &[witness],
                &[],
                ReadLimits {
                    reads: 3,
                    bytes: 17,
                    ..exact
                },
                usize::MAX
            ),
            Err(PermissionError::Invalid(
                "extra or duplicate object witness"
            ))
        ));
    }
}
