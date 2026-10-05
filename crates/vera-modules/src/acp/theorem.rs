//! Bounded authorization and delegation assertions over one policy snapshot.
mod parser;

use super::types::Operation;
use super::*;
use serde::{Deserialize, Serialize};

/// Kind of assertion in the policy theorem language.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TheoremKind {
    /// An actor's access to an object.
    Authorization,
    /// An actor's authority to manage a stored relation.
    Delegation,
}

/// An assertion and its UTF-8 byte range in the submitted source.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Theorem {
    /// Access or management authorization.
    pub kind: TheoremKind,
    /// Identity whose authority is evaluated.
    pub actor: Actor,
    /// Object and relation or permission.
    pub operation: Operation,
    /// False for a negated assertion.
    pub assert_true: bool,
    /// Inclusive byte offset.
    pub start: usize,
    /// Exclusive byte offset.
    pub end: usize,
}

/// Outcome of a valid assertion, or a rejected assertion input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TheoremStatus {
    /// The decision matches the assertion.
    Accept,
    /// The decision contradicts the assertion.
    Reject,
    /// The assertion cannot be evaluated.
    Error,
}

/// Result for one source assertion.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TheoremResult {
    /// The assertion, including its source range.
    pub theorem: Theorem,
    /// Whether the assertion matches the observed decision.
    pub status: TheoremStatus,
    /// Input error, if evaluation could not start.
    pub message: Option<String>,
}

/// Aggregate assertion results. This report is not a permission grant or a proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TheoremReport {
    /// True only when every assertion was accepted.
    pub ok: bool,
    /// Number of assertions evaluated.
    pub theorem_count: usize,
    /// Number of rejected or invalid assertions.
    pub failures: usize,
    /// Results in source order.
    pub results: Vec<TheoremResult>,
}

impl AcpModule {
    /// Evaluate the ACP v1 `Authorizations` and `Delegations` theorem language.
    pub fn evaluate_theorem(&self, policy_id: &str, source: &str) -> Result<TheoremReport> {
        let policy = self.query_policy(policy_id)?.policy;
        let theorems = parser::parse(source)?;
        let mut results = Vec::with_capacity(theorems.len());
        for theorem in theorems {
            let object = &theorem.operation.object;
            let relation = &theorem.operation.permission;
            let outcome = if policy.get_relation(&object.resource, relation).is_none() {
                Err(AcpError::InvalidAccessRequest {
                    reason: "unknown theorem resource or relation".into(),
                })
            } else {
                match theorem.kind {
                    TheoremKind::Authorization => self.query_verify_access_request(
                        policy_id,
                        &AccessRequest {
                            actor: theorem.actor.clone(),
                            operations: vec![theorem.operation.clone()],
                        },
                    ),
                    TheoremKind::Delegation => self.check_management_authority(
                        &theorem.actor.0,
                        policy_id,
                        object,
                        relation,
                    ),
                }
            };
            let (status, message) = match outcome {
                Ok(actual) => (
                    if actual == theorem.assert_true {
                        TheoremStatus::Accept
                    } else {
                        TheoremStatus::Reject
                    },
                    None,
                ),
                Err(error @ AcpError::State(_)) => return Err(error),
                Err(error) => (TheoremStatus::Error, Some(error.to_string())),
            };
            results.push(TheoremResult {
                theorem,
                status,
                message,
            });
        }
        let failures = results
            .iter()
            .filter(|result| result.status != TheoremStatus::Accept)
            .count();
        Ok(TheoremReport {
            ok: failures == 0,
            theorem_count: results.len(),
            failures,
            results,
        })
    }
}
