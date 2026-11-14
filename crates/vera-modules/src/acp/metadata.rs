use super::*;

impl AcpModule {
    /// Edit a definition at an authenticated execution revision, preserving supplied metadata.
    pub fn edit_policy_at(
        &mut self,
        actor: &Did,
        policy_id: &str,
        policy: &str,
        marshal_type: PolicyMarshalingType,
        modified_at: &Timestamp,
    ) -> Result<(u64, PolicyRecord)> {
        self.edit_policy_at_with_budget(
            actor,
            policy_id,
            policy,
            marshal_type,
            modified_at,
            &PolicyEditBudget::new(u64::MAX),
        )
    }

    pub(super) fn validate_policy_revision(
        record: &PolicyRecord,
        revision: &Timestamp,
    ) -> Result<()> {
        let previous = record
            .last_modified
            .as_ref()
            .unwrap_or(&record.metadata.creation_ts);
        if revision.block_height == 0
            || revision.seconds == 0
            || revision.block_height < previous.block_height
            || revision.seconds < previous.seconds
        {
            return Err(AcpError::InvalidAccessRequest {
                reason: "invalid policy revision".into(),
            });
        }
        Ok(())
    }

    /// Attach application metadata to a newly created grant or registration.
    /// Repeated grants return the original record, including its original metadata.
    pub fn execute_policy_cmd_with_metadata(
        &mut self,
        actor: &Did,
        policy_id: &str,
        request: types::PolicyCommandRequest,
        block: &BlockExecCtx,
        submission: &TxExecCtx,
    ) -> Result<PolicyCmdResult> {
        self.execute_policy_cmd_with_metadata_and_budget(
            actor,
            policy_id,
            request,
            block,
            submission,
            &CommandBudget::new(u64::MAX),
        )
    }

    /// Account for supplied input and publish the command with its final metadata atomically.
    pub fn execute_policy_cmd_with_metadata_and_budget(
        &mut self,
        actor: &Did,
        policy_id: &str,
        request: types::PolicyCommandRequest,
        block: &BlockExecCtx,
        submission: &TxExecCtx,
        budget: &CommandBudget,
    ) -> Result<PolicyCmdResult> {
        budget.metadata(&request.metadata)?;
        if !request.metadata.is_empty()
            && !matches!(
                request.command,
                PolicyCmd::SetRelationship(_)
                    | PolicyCmd::RegisterObject(_)
                    | PolicyCmd::RevealRegistration { .. }
            )
        {
            return Err(AcpError::InvalidAccessRequest {
                reason: "this command does not accept supplied metadata".into(),
            });
        }
        self.execute_stamped_policy_cmd(
            actor,
            policy_id,
            request.command,
            request.metadata,
            block,
            submission,
            budget,
        )
    }
}
