//! Shared work accounting for permission traversal and recorded decisions.

use std::sync::Arc;

use super::{
    AcpError, PolicyEditBudget, Result, decision::MAX_ACCESS_OPERATIONS, types::AccessRequest,
};

/// Caller-owned permission allowance retained outside rollback snapshots.
/// Clones share read/write accounting and 32 units per evaluation step. Request
/// processing costs eight units per 16 bytes; reads and writes use the same
/// encoded-byte prices as policy edits. Hard permission limits remain separate.
#[derive(Clone, Debug)]
pub struct PermissionBudget {
    pub(super) records: Arc<PolicyEditBudget>,
}

impl PermissionBudget {
    /// Establish an allowance after subtracting the dispatch base cost.
    pub fn new(limit: u64) -> Self {
        Self {
            records: Arc::new(PolicyEditBudget::new(limit)),
        }
    }

    /// Completed work, including when a decision fails or is rolled back.
    pub fn consumed(&self) -> u64 {
        self.records.consumed()
    }

    /// Whether any reservation failed; exhaustion is shared and permanent.
    pub fn is_exhausted(&self) -> bool {
        self.records.is_exhausted()
    }

    pub(super) fn finish<T>(&self, result: Result<T>) -> Result<T> {
        if self.is_exhausted() {
            Err(AcpError::PermissionBudgetExceeded)
        } else {
            result
        }
    }

    pub(super) fn request(
        &self,
        policy: &str,
        creator: &str,
        request: &AccessRequest,
    ) -> Result<()> {
        if request.operations.len() > MAX_ACCESS_OPERATIONS {
            return Err(AcpError::InvalidAccessRequest {
                reason: "access request exceeds limits".into(),
            });
        }
        let mut fields = [policy, creator, request.actor.0.as_str()]
            .into_iter()
            .chain(request.operations.iter().flat_map(|op| {
                [
                    op.object.resource.as_str(),
                    op.object.id.as_str(),
                    op.permission.as_str(),
                ]
            }));
        let bytes = fields.try_fold(0usize, |n, field| n.checked_add(field.len()));
        if bytes.is_none_or(|n| n > 64 << 10) {
            return Err(AcpError::InvalidAccessRequest {
                reason: "access request exceeds limits".into(),
            });
        }
        self.finish(
            self.records.definition(
                bytes
                    .unwrap()
                    .saturating_add(request.operations.len().saturating_mul(24)),
            ),
        )
    }

    pub(super) fn evaluation_error(&self, error: zanzibar::error::Error) -> AcpError {
        if self.is_exhausted() {
            AcpError::PermissionBudgetExceeded
        } else {
            AcpError::State(format!("permission evaluation failed: {error}"))
        }
    }
}

impl zanzibar::engine::EvaluationMeter for PermissionBudget {
    fn charge_step(&self) -> zanzibar::error::Result<()> {
        self.records
            .pair()
            .map_err(|error| zanzibar::error::Error::Serialization(error.to_string()))
    }
}

#[cfg(test)]
#[path = "permission_budget_tests.rs"]
mod tests;
