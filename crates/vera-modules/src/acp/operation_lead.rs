//! Operator-selected lead allowed to operation identities on policy commands.

use vera_crypto::{
    jwt::DelegationScope,
    operation::{DEFAULT_OPERATION_LEAD, MAX_OPERATION_LEAD},
};

use super::{AcpError, AcpModule, PolicyEditBudget, Result};
use crate::kv_store::ModuleKvStore as _;

/// Native ACP key of the policy-command lead, an eight-byte big-endian count of seconds.
pub const POLICY_OPERATION_LEAD_KEY: &[u8] = b"policy-operation-lead/v1";

impl AcpModule {
    /// Longest lead, in seconds, an operation identity on a policy command may
    /// carry: the operator-selected value, or the default before configuration.
    pub fn policy_operation_lead(&self) -> Result<u64> {
        self.store
            .get_ref(POLICY_OPERATION_LEAD_KEY)
            .map_or(Ok(DEFAULT_OPERATION_LEAD), decode)
    }

    pub(crate) fn set_policy_operation_lead(&mut self, seconds: u64) -> Result<()> {
        if !(DEFAULT_OPERATION_LEAD..=MAX_OPERATION_LEAD).contains(&seconds) {
            return Err(AcpError::State(format!(
                "policy operation lead must lie between {DEFAULT_OPERATION_LEAD} and {MAX_OPERATION_LEAD} seconds"
            )));
        }
        self.store
            .put(POLICY_OPERATION_LEAD_KEY, seconds.to_be_bytes().to_vec());
        Ok(())
    }

    /// Lead allowed to an operation identity authorizing `scope`.
    pub(super) fn operation_lead(
        &self,
        scope: DelegationScope,
        budget: Option<&PolicyEditBudget>,
    ) -> Result<u64> {
        if scope != DelegationScope::PolicyCommands {
            return Ok(DEFAULT_OPERATION_LEAD);
        }
        if let Some(budget) = budget {
            budget.read(
                POLICY_OPERATION_LEAD_KEY,
                self.store.get_ref(POLICY_OPERATION_LEAD_KEY),
            )?;
        }
        self.policy_operation_lead()
    }
}

fn decode(bytes: &[u8]) -> Result<u64> {
    let seconds = bytes
        .try_into()
        .map(u64::from_be_bytes)
        .map_err(|_| AcpError::State("invalid policy operation lead".into()))?;
    if !(DEFAULT_OPERATION_LEAD..=MAX_OPERATION_LEAD).contains(&seconds) {
        return Err(AcpError::State("invalid policy operation lead".into()));
    }
    Ok(seconds)
}
