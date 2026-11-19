//! Delegated policy commands applied in order, all or none, under one authorization.

use super::delegated_operation::DelegatedOperation;
use super::types::{PolicyCmd, PolicyCmdResult};
use super::{AcpError, AcpModule, CommandBudget, Result};
use crate::types::{BlockExecCtx, TxExecCtx};
use crate::vera::VeraModule;

/// Maximum commands in one delegated command list.
pub const MAX_POLICY_COMMAND_LIST: usize = 64;

impl AcpModule {
    /// Apply an ordered list of delegated commands, all or none.
    pub fn bearer_policy_cmds(
        &mut self,
        vera: &mut VeraModule,
        context: &BlockExecCtx,
        submission: &TxExecCtx,
        token: &str,
        commands: &[(String, PolicyCmd)],
    ) -> Result<Vec<PolicyCmdResult>> {
        self.bearer_policy_cmds_with_budget(
            vera,
            context,
            submission,
            token,
            commands,
            &CommandBudget::new(u64::MAX),
        )
    }

    /// Authorize the whole list once, then execute each command in order within one
    /// caller-owned allowance. Any refusal restores the state before the list.
    pub fn bearer_policy_cmds_with_budget(
        &mut self,
        vera: &mut VeraModule,
        context: &BlockExecCtx,
        submission: &TxExecCtx,
        token: &str,
        commands: &[(String, PolicyCmd)],
        budget: &CommandBudget,
    ) -> Result<Vec<PolicyCmdResult>> {
        if commands.is_empty() || commands.len() > MAX_POLICY_COMMAND_LIST {
            return Err(AcpError::InvalidCommandList {
                reason: format!("a list holds 1 to {MAX_POLICY_COMMAND_LIST} commands"),
            });
        }
        budget.input(token.len().saturating_add(submission.signer.len()))?;
        budget.encoded_input(&commands)?;
        if let Some((policy_id, _)) = commands.iter().find(|(id, _)| !is_policy_id(id)) {
            return Err(AcpError::InvalidCommandList {
                reason: format!("invalid policy identifier {policy_id:?}"),
            });
        }
        let operation = DelegatedOperation::PolicyCommandList(commands);
        let result = self.with_delegation_with_budget(
            vera,
            context,
            submission,
            token,
            (operation.scope(), operation.digest()?),
            Some(&budget.permissions.records),
            |module, _hub, actor| {
                commands
                    .iter()
                    .map(|(policy_id, command)| {
                        module.execute_policy_cmd_with_budget(
                            actor,
                            policy_id,
                            command.clone(),
                            context,
                            submission,
                            budget,
                        )
                    })
                    .collect()
            },
        );
        budget.finish(result)
    }
}

fn is_policy_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
