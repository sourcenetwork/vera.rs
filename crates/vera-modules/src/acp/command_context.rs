//! Execution metadata for policy commands and registration priority.

use super::*;

impl AcpModule {
    /// Execute an authenticated actor's command at the supplied finalized-order context.
    /// Delegated callers provide the authenticated worker separately from the actor.
    pub fn execute_policy_cmd(
        &mut self,
        actor: &Did,
        policy_id: &str,
        command: PolicyCmd,
        block: &BlockExecCtx,
        submission: &TxExecCtx,
    ) -> Result<PolicyCmdResult> {
        self.execute_policy_cmd_with_budget(
            actor,
            policy_id,
            command,
            block,
            submission,
            &CommandBudget::new(u64::MAX),
        )
    }

    /// Publish the command and authenticated metadata together, retaining spent work on failure.
    pub fn execute_policy_cmd_with_budget(
        &mut self,
        actor: &Did,
        policy_id: &str,
        command: PolicyCmd,
        block: &BlockExecCtx,
        submission: &TxExecCtx,
        budget: &CommandBudget,
    ) -> Result<PolicyCmdResult> {
        let mut candidate = self.clone();
        let result = budget
            .finish(candidate.apply_contextual_policy_cmd(
                actor, policy_id, command, block, submission, budget,
            ))?;
        *self = candidate;
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_contextual_policy_cmd(
        &mut self,
        actor: &Did,
        policy_id: &str,
        command: PolicyCmd,
        block: &BlockExecCtx,
        submission: &TxExecCtx,
        budget: &CommandBudget,
    ) -> Result<PolicyCmdResult> {
        budget.input(
            actor
                .as_str()
                .len()
                .saturating_add(submission.signer.len())
                .saturating_add(submission.tx_hash.len()),
        )?;
        if block.timestamp.block_height == 0
            || submission.tx_hash.len() != 32
            || submission.signer.is_empty()
        {
            return Err(AcpError::State(
                "invalid policy command execution context".into(),
            ));
        }
        let mut metadata = RecordMetadata {
            creation_ts: block.timestamp.clone(),
            tx_hash: submission.tx_hash.clone(),
            tx_signer: submission.signer.clone(),
            owner_did: actor.to_string(),
        };
        let event_metadata = metadata.clone();
        if let PolicyCmd::RevealRegistration {
            registrations_commitment_id,
            ..
        } = &command
        {
            let commitment = self
                .get_commitment_by_id(*registrations_commitment_id)?
                .ok_or(AcpError::CommitmentNotFound {
                    id: *registrations_commitment_id,
                })?;
            let issued = &commitment.metadata.creation_ts;
            if issued.block_height == 0
                || issued.block_height > block.timestamp.block_height
                || issued.seconds > block.timestamp.seconds
            {
                return Err(AcpError::State(
                    "invalid registration commitment revision".into(),
                ));
            }
            let expired = match commitment.validity {
                Duration::Seconds(delta) => {
                    block.timestamp.seconds > issued.seconds.saturating_add(delta)
                }
                Duration::Blocks(delta) => {
                    block.timestamp.block_height > issued.block_height.saturating_add(delta)
                }
            };
            if commitment.expired || expired {
                return Err(AcpError::CommitmentExpired { id: commitment.id });
            }
            metadata.creation_ts = issued.clone();
        }
        let mut result = self.direct_policy_cmd_with_budget(actor, policy_id, command, budget)?;
        match &mut result {
            PolicyCmdResult::RegisterObject { record }
            | PolicyCmdResult::SetRelationship {
                record_existed: false,
                record,
            } => {
                record.metadata = metadata;
                self.set_relationship(record)?;
            }
            PolicyCmdResult::CommitRegistrations {
                registrations_commitment,
            } => {
                registrations_commitment.metadata = metadata;
                self.update_commitment(registrations_commitment)?;
            }
            PolicyCmdResult::RevealRegistration { record, event } => {
                record.metadata = metadata;
                self.set_relationship(record)?;
                if let Some(event) = event {
                    event.metadata = event_metadata;
                    self.update_amendment_event(event)?;
                }
            }
            _ => {}
        }
        Ok(result)
    }
}
