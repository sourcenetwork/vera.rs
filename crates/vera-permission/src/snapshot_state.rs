//! Access decisions over a verified policy snapshot, with the shared evaluator.

use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicUsize, Ordering},
};

use vera_modules::acp::{keys, record_store::RecordStore, zanzibar_store::evaluate_access_request};
use vera_zanzibar::error::{Error as EvaluationError, Result as EvaluationResult};

use crate::{AccessRequest, PERMISSION_LIMITS, PermissionError, validate_request};

type Entries = BTreeMap<Vec<u8>, Vec<u8>>;

/// Every record of one policy at one authenticated revision.
#[derive(Clone, Debug)]
pub struct PolicyState {
    policy: String,
    record: Option<Vec<u8>>,
    live: bool,
    prefixes: Vec<(Vec<u8>, Entries)>,
}

impl PolicyState {
    pub(crate) const fn new(
        policy: String,
        record: Option<Vec<u8>>,
        live: bool,
        prefixes: Vec<(Vec<u8>, Entries)>,
    ) -> Self {
        Self {
            policy,
            record,
            live,
            prefixes,
        }
    }

    /// The policy's identifier.
    pub fn policy(&self) -> &str {
        &self.policy
    }

    /// Whether the policy exists at this revision.
    pub const fn exists(&self) -> bool {
        self.live
    }

    /// Number of relationship, index and object records held.
    pub fn records(&self) -> usize {
        self.prefixes.iter().map(|(_, entries)| entries.len()).sum()
    }

    /// Whether the request's actor holds every requested permission at this revision.
    pub fn check(&self, request: &AccessRequest) -> Result<bool, PermissionError> {
        validate_request(&self.policy, request, PERMISSION_LIMITS)?;
        let reader = Reader {
            state: self,
            reads: AtomicUsize::new(PERMISSION_LIMITS.reads.reads),
        };
        Ok(evaluate_access_request(reader, &self.policy, request)?)
    }
}

struct Reader<'a> {
    state: &'a PolicyState,
    reads: AtomicUsize,
}

impl Reader<'_> {
    fn charge(&self) -> EvaluationResult<()> {
        self.reads
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
            .map(|_| ())
            .map_err(|_| unavailable())
    }

    fn covering(&self, key: &[u8]) -> EvaluationResult<&Entries> {
        self.state
            .prefixes
            .iter()
            .find(|(prefix, _)| key.starts_with(prefix))
            .map(|(_, entries)| entries)
            .ok_or_else(unavailable)
    }
}

impl RecordStore for Reader<'_> {
    fn read_record(&self, key: &[u8]) -> EvaluationResult<Option<Vec<u8>>> {
        self.charge()?;
        if key == keys::policy_key(&self.state.policy) {
            return Ok(self.state.record.clone());
        }
        Ok(self.covering(key)?.get(key).cloned())
    }

    fn scan_records(&self, prefix: &[u8]) -> EvaluationResult<Vec<(Vec<u8>, Vec<u8>)>> {
        self.charge()?;
        Ok(self
            .covering(prefix)?
            .range(prefix.to_vec()..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect())
    }
}

fn unavailable() -> EvaluationError {
    EvaluationError::Serialization(
        "record outside the policy snapshot or read budget exhausted".into(),
    )
}
