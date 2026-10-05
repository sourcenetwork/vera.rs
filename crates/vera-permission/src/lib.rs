//! Native permission evidence replayed with the shared ACP evaluator.

use std::{collections::BTreeMap, sync::Mutex};

use alloy_primitives::{B256, Bytes};
use serde::{Deserialize, Serialize};
use vera_domain::{
    ModuleStateProof, RelationPrefixProof, RelationProofLimits, verify_module_state_proof,
    verify_relation_prefix_proof,
};
use vera_modules::acp::{record_store::RecordStore, zanzibar_store::evaluate_access_request};
use zanzibar::error::{Error as EvaluationError, Result as EvaluationResult};

pub use vera_domain::ModuleId;

pub use vera_modules::acp::{
    decision::DecisionRequest,
    read_capture::{ReadCapture, ReadLimits, RecordRead},
    types::{AccessDecision, AccessRequest, Actor, Object, Operation},
};
pub use vera_modules::types::Timestamp;

/// Current-state point and complete-prefix evidence over Commonware storage.
pub mod current;
mod decision;
mod encoded_size;
pub use decision::{DecisionOperation, DecisionOutcome, DecisionRecord};
pub use encoded_size::encoded_size;
mod object_evidence;
pub use object_evidence::relationship_object_key;
mod owner;
pub use owner::object_owner_prefix;
mod page;
mod policy;
mod policy_page;
mod policy_prefix;
mod prefix;
pub use page::{
    MAX_PAGE_RECORDS, PAGE_DATA_BYTES, PAGE_PROOF_BYTES, PAGE_RESPONSE_BYTES, PrefixPageProof,
    PrefixPageRequest, PrefixPageResponse, VerifiedPrefixPage,
};
pub use policy::validate_policy_prefix;
pub use policy_page::{PolicyPrefixPageProof, PolicyPrefixPageResponse};
pub use policy_prefix::{PolicyPrefixProof, PolicyPrefixResponse};
pub use prefix::{PrefixProof, PrefixResponse};
mod record;
pub use record::{RECORD_PROOF_BYTES, RECORD_RESPONSE_BYTES, RecordProof, RecordResponse};
mod response;
pub use response::{PERMISSION_RESPONSE_BYTES, PermissionResponse};

/// Shared service limits; consumers may impose tighter limits.
pub const PERMISSION_LIMITS: PermissionLimits = PermissionLimits {
    reads: vera_modules::acp::read_capture::PERMISSION_READ_LIMITS,
    proof_bytes: 4 << 20,
    operations: vera_modules::acp::decision::MAX_ACCESS_OPERATIONS,
    request_bytes: 64 << 10,
};

/// Aggregate limits for one request, proof and evaluation.
#[derive(Debug, Clone, Copy)]
pub struct PermissionLimits {
    /// Repeated evaluation reads, returned records and copied bytes.
    pub reads: ReadLimits,
    /// Maximum serialized proof bytes before verification.
    pub proof_bytes: usize,
    /// Maximum number of requested operations.
    pub operations: usize,
    /// Maximum serialized policy ID and request bytes.
    pub request_bytes: usize,
}

/// Evidence for one point or complete-prefix read.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PermissionRead {
    /// Current-state record membership or absence.
    CurrentPoint {
        /// Raw record key.
        key: Bytes,
        /// A value selects membership; absence selects an exclusion proof.
        value: Option<Bytes>,
        /// Bounded canonical Commonware proof bytes.
        proof: Bytes,
    },
    /// Current-state complete ordered prefix.
    CurrentPrefix {
        /// Exact raw prefix.
        prefix: Bytes,
        /// Bounded canonical complete-prefix evidence.
        proof: Bytes,
    },
    /// Proven record value or absence.
    Point {
        /// Record evidence at the selected revision.
        proof: ModuleStateProof,
    },
    /// Every relationship record under a prefix.
    Prefix {
        /// Exact raw prefix, encoded as hex bytes.
        prefix: Bytes,
        /// Complete enumeration evidence.
        proof: Box<RelationPrefixProof>,
    },
}

/// Read evidence; the consumer computes its own permission result.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PermissionProof {
    /// Current-state namespace roots in ACP, bulletin, vera and sequence order.
    /// Omitted for the original proof format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roots: Option<[B256; 4]>,
    /// Distinct point and prefix reads used by the evaluator.
    pub reads: Vec<PermissionRead>,
}

/// Invalid, unavailable or excessive evidence never becomes a permission result.
#[derive(Debug, thiserror::Error)]
pub enum PermissionError {
    /// The selected revision failed finalization verification.
    #[error(transparent)]
    Finalization(#[from] vera_domain::LightBlockError),
    /// A request or response exceeded a caller limit.
    #[error("permission limit exceeded")]
    Limit,
    /// Invalid request or read coverage.
    #[error("invalid permission evidence: {0}")]
    Invalid(&'static str),
    /// An individual record proof failed verification.
    #[error(transparent)]
    Record(#[from] vera_domain::ProofError),
    /// Complete-prefix verification failed.
    #[error(transparent)]
    Prefix(#[from] vera_domain::RelationProofError),
    /// Policy evaluation failed, including missing read coverage.
    #[error(transparent)]
    Evaluation(#[from] EvaluationError),
}

/// Validate a native request before evaluation or proof generation.
pub fn validate_request(
    policy: &str,
    request: &AccessRequest,
    limits: PermissionLimits,
) -> Result<(), PermissionError> {
    if policy.is_empty() || request.operations.is_empty() {
        return Err(PermissionError::Invalid(
            "policy and operations must be nonempty",
        ));
    }
    if request.operations.len() > limits.operations {
        return Err(PermissionError::Limit);
    }
    encoded_size(&(policy, request), limits.request_bytes).map(|_| ())
}

/// Verify all evidence at a trusted revision and evaluate the caller's request.
///
/// The root and height must come from an independently verified finalized
/// revision. Transport must bound the response before deserializing this type.
pub fn verify_permission_proof(
    root: B256,
    height: u64,
    policy: &str,
    request: &AccessRequest,
    proof: &PermissionProof,
    limits: PermissionLimits,
) -> Result<bool, PermissionError> {
    validate_request(policy, request, limits)?;
    if proof.reads.len() > limits.reads.reads {
        return Err(PermissionError::Limit);
    }
    encoded_size(proof, limits.proof_bytes)?;
    if let Some(roots) = proof.roots {
        return current::verify(root, roots, policy, request, proof, limits);
    }
    let mut store = VerifiedRecords {
        points: BTreeMap::new(),
        prefixes: BTreeMap::new(),
        remaining: Mutex::new(limits.reads),
    };
    let mut records = limits.reads.records;
    for read in &proof.reads {
        match read {
            PermissionRead::CurrentPoint { .. } | PermissionRead::CurrentPrefix { .. } => {
                return Err(PermissionError::Invalid("current-state roots missing"));
            }
            PermissionRead::Point { proof } => {
                records = records
                    .checked_sub(usize::from(proof.value.is_some()))
                    .ok_or(PermissionError::Limit)?;
                if proof.module != ModuleId::Acp || proof.height != height {
                    return Err(PermissionError::Invalid(
                        "point belongs to another module or height",
                    ));
                }
                verify_module_state_proof(root, proof)?;
                let key = decode(&proof.key)?;
                let value = proof.value.as_deref().map(decode).transpose()?;
                if store.points.insert(key, value).is_some() {
                    return Err(PermissionError::Invalid("duplicate point read"));
                }
            }
            PermissionRead::Prefix { prefix, proof } => {
                records = records
                    .checked_sub(proof.records.len())
                    .ok_or(PermissionError::Limit)?;
                let entries = verify_relation_prefix_proof(
                    root,
                    height,
                    prefix,
                    proof,
                    RelationProofLimits {
                        records: limits.reads.records,
                        bytes: limits.proof_bytes,
                    },
                )?;
                if store.prefixes.insert(prefix.to_vec(), entries).is_some() {
                    return Err(PermissionError::Invalid("duplicate prefix read"));
                }
            }
        }
    }
    Ok(evaluate_access_request(store, policy, request)?)
}

fn decode(value: &str) -> Result<Vec<u8>, PermissionError> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|_| PermissionError::Invalid("invalid record hex"))
}

type Entries = Vec<(Vec<u8>, Vec<u8>)>;
struct VerifiedRecords {
    points: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    prefixes: BTreeMap<Vec<u8>, Entries>,
    remaining: Mutex<ReadLimits>,
}

impl VerifiedRecords {
    fn charge(
        &self,
        key: &[u8],
        entries: impl Iterator<Item = (usize, usize)>,
    ) -> EvaluationResult<()> {
        let mut budget = self.remaining.lock().map_err(|_| unavailable())?;
        let result = (|| {
            budget.reads = budget.reads.checked_sub(1).ok_or_else(unavailable)?;
            budget.bytes = budget
                .bytes
                .checked_sub(key.len())
                .ok_or_else(unavailable)?;
            for (key_bytes, value_bytes) in entries {
                budget.records = budget.records.checked_sub(1).ok_or_else(unavailable)?;
                budget.bytes = budget
                    .bytes
                    .checked_sub(key_bytes)
                    .and_then(|n| n.checked_sub(value_bytes))
                    .ok_or_else(unavailable)?;
            }
            Ok(())
        })();
        if result.is_err() {
            budget.reads = 0;
        }
        result
    }
}

impl RecordStore for VerifiedRecords {
    fn read_record(&self, key: &[u8]) -> EvaluationResult<Option<Vec<u8>>> {
        let value = self.points.get(key).ok_or_else(unavailable)?;
        self.charge(key, value.iter().map(|value| (0, value.len())))?;
        Ok(value.clone())
    }
    fn scan_records(&self, prefix: &[u8]) -> EvaluationResult<Entries> {
        let entries = self.prefixes.get(prefix).ok_or_else(unavailable)?;
        self.charge(
            prefix,
            entries.iter().map(|(key, value)| (key.len(), value.len())),
        )?;
        Ok(entries.clone())
    }
}

fn unavailable() -> EvaluationError {
    EvaluationError::Serialization("permission read unavailable or budget exhausted".into())
}

/// Capture required reads from one immutable module snapshot.
pub fn capture_reads(
    snapshot: vera_modules::kv_store::InMemoryKvStore,
    policy: &str,
    request: &AccessRequest,
    limits: PermissionLimits,
) -> Result<Vec<RecordRead>, PermissionError> {
    validate_request(policy, request, limits)?;
    let capture = ReadCapture::new(snapshot, limits.reads);
    evaluate_access_request(capture.clone(), policy, request)?;
    Ok(capture.requests()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> AccessRequest {
        AccessRequest {
            actor: Actor(
                "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
                    .parse()
                    .unwrap(),
            ),
            operations: vec![Operation {
                object: Object {
                    resource: "document".into(),
                    id: "report".into(),
                },
                permission: "read".into(),
            }],
        }
    }

    #[test]
    fn encoded_limits_match_wire_bytes_and_reject_empty_requests() {
        assert_eq!(
            serde_json::to_string(&PermissionProof::default()).unwrap(),
            r#"{"reads":[]}"#
        );
        assert!(
            serde_json::from_str::<PermissionProof>(r#"{"reads":[]}"#)
                .unwrap()
                .roots
                .is_none()
        );
        let request = request();
        let bytes = serde_json::to_vec(&("policy", &request)).unwrap();
        assert_eq!(
            encoded_size(&("policy", &request), bytes.len()).unwrap(),
            bytes.len()
        );
        assert!(matches!(
            encoded_size(&("policy", &request), bytes.len() - 1),
            Err(PermissionError::Limit)
        ));
        assert!(validate_request("policy", &request, PERMISSION_LIMITS).is_ok());
        assert!(validate_request("", &request, PERMISSION_LIMITS).is_err());
        let mut empty = request.clone();
        empty.operations.clear();
        assert!(validate_request("policy", &empty, PERMISSION_LIMITS).is_err());
        let mut limits = PERMISSION_LIMITS;
        limits.operations = 0;
        assert!(matches!(
            validate_request("policy", &request, limits),
            Err(PermissionError::Limit)
        ));
    }

    #[test]
    fn missing_evidence_is_an_error_even_for_a_denied_request() {
        assert!(matches!(
            verify_permission_proof(
                B256::ZERO,
                1,
                "policy",
                &request(),
                &PermissionProof::default(),
                PERMISSION_LIMITS
            ),
            Err(PermissionError::Evaluation(_))
        ));
    }

    #[test]
    fn replay_limits_include_repeated_reads_and_reject_partial_scans() {
        let store = VerifiedRecords {
            points: BTreeMap::from([(b"key".to_vec(), Some(vec![1]))]),
            prefixes: BTreeMap::from([(
                b"p/".to_vec(),
                vec![(b"p/a".to_vec(), vec![2]), (b"p/b".to_vec(), vec![3])],
            )]),
            remaining: Mutex::new(ReadLimits {
                reads: 8,
                records: 2,
                bytes: 100,
            }),
        };
        assert_eq!(store.read_record(b"key").unwrap(), Some(vec![1]));
        assert!(store.scan_records(b"p/").is_err());
        assert!(store.read_record(b"key").is_err());
        assert!(store.scan_records(b"p/").is_err());
        *store.remaining.lock().unwrap() = ReadLimits {
            reads: 8,
            records: 2,
            bytes: 100,
        };
        assert_eq!(store.read_record(b"key").unwrap(), Some(vec![1]));
        assert_eq!(store.read_record(b"key").unwrap(), Some(vec![1]));
        assert!(store.read_record(b"key").is_err());
    }
}
