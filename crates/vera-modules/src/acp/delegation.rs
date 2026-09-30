use identity::Did;
use serde::{Serialize, de::DeserializeOwned};
use vera_crypto::jwt::DelegationScope;

use super::delegated_operation::DelegatedOperation;
use super::operation::OperationRecord;
use super::{AcpError, AcpModule, Result};
use crate::acp::types::{
    AccessDecision, AccessRequest, PolicyCmd, PolicyCmdResult, PolicyMarshalingType, PolicyRecord,
    RecordMetadata,
};
use crate::types::{BlockExecCtx, Timestamp, TxExecCtx};
use crate::vera::VeraModule;

impl AcpModule {
    /// Create a policy owned by the actor authorizing the submitting worker.
    pub fn bearer_create_policy(
        &mut self,
        vera: &mut VeraModule,
        context: &BlockExecCtx,
        submission: &TxExecCtx,
        token: &str,
        policy: &str,
        marshal_type: PolicyMarshalingType,
    ) -> Result<PolicyRecord> {
        if submission.tx_hash.len() != 32 {
            return Err(AcpError::State(
                "missing authenticated submission identifier".into(),
            ));
        }
        self.with_delegation(
            vera,
            context,
            submission,
            token,
            (
                DelegationScope::CreatePolicy,
                DelegatedOperation::CreatePolicy(policy, &marshal_type).digest()?,
            ),
            |module, _hub, actor| {
                module.create_policy_with_metadata(
                    policy,
                    marshal_type,
                    RecordMetadata {
                        creation_ts: context.timestamp.clone(),
                        tx_hash: submission.tx_hash.clone(),
                        tx_signer: submission.signer.clone(),
                        owner_did: actor.to_string(),
                    },
                )
            },
        )
    }

    /// Edit a policy using the actor's ownership and the worker's delegation.
    #[allow(clippy::too_many_arguments)]
    pub fn bearer_edit_policy(
        &mut self,
        vera: &mut VeraModule,
        context: &BlockExecCtx,
        submission: &TxExecCtx,
        token: &str,
        policy_id: &str,
        policy: &str,
        marshal_type: PolicyMarshalingType,
    ) -> Result<(u64, PolicyRecord)> {
        self.with_delegation(
            vera,
            context,
            submission,
            token,
            (
                DelegationScope::EditPolicy,
                DelegatedOperation::EditPolicy(policy_id, policy, &marshal_type).digest()?,
            ),
            |module, _hub, actor| {
                module.edit_policy_at(actor, policy_id, policy, marshal_type, &context.timestamp)
            },
        )
    }

    /// Execute a caller-bound delegation and record usage only on success.
    pub fn bearer_policy_cmd(
        &mut self,
        vera: &mut VeraModule,
        context: &BlockExecCtx,
        submission: &TxExecCtx,
        token: &str,
        policy_id: &str,
        cmd: PolicyCmd,
    ) -> Result<PolicyCmdResult> {
        self.with_delegation(
            vera,
            context,
            submission,
            token,
            (
                DelegationScope::PolicyCommands,
                DelegatedOperation::PolicyCommand(policy_id, &cmd).digest()?,
            ),
            |module, _hub, actor| {
                module.execute_policy_cmd(actor, policy_id, cmd, context, submission)
            },
        )
    }

    /// Record a decision with caller-bound recovery and the original submitting worker identity.
    pub fn bearer_check_access(
        &mut self,
        vera: &mut VeraModule,
        context: &BlockExecCtx,
        submission: &TxExecCtx,
        token: &str,
        policy_id: &str,
        request: &AccessRequest,
    ) -> Result<AccessDecision> {
        let worker =
            Did::new(&submission.signer).map_err(|error| AcpError::InvalidBearerToken {
                reason: error.to_string(),
            })?;
        self.with_delegation(
            vera,
            context,
            submission,
            token,
            (
                DelegationScope::RecordAccessDecision,
                DelegatedOperation::CheckAccess(policy_id, request).digest()?,
            ),
            |module, _hub, _caller| {
                module.check_access(&worker, policy_id, request, context, submission)
            },
        )
    }

    pub(crate) fn with_delegation<T: Serialize + DeserializeOwned>(
        &mut self,
        vera: &mut VeraModule,
        context: &BlockExecCtx,
        submission: &TxExecCtx,
        token: &str,
        delegated: (DelegationScope, [u8; 32]),
        operation: impl FnOnce(&mut Self, &mut VeraModule, &Did) -> Result<T>,
    ) -> Result<T> {
        let invalid = |error: crate::vera::error::VeraError| AcpError::InvalidBearerToken {
            reason: error.to_string(),
        };
        let caller =
            Did::new(&submission.signer).map_err(|error| AcpError::InvalidBearerToken {
                reason: error.to_string(),
            })?;
        let claims = vera
            .authorize_delegation(context, &caller, token, delegated.0, delegated.1)
            .map_err(invalid)?;
        let actor = Did::new(claims.actor()).map_err(|error| AcpError::InvalidBearerToken {
            reason: error.to_string(),
        })?;
        let issuer = Did::new(&claims.iss).map_err(|error| AcpError::InvalidBearerToken {
            reason: error.to_string(),
        })?;
        if let Some(request) = &claims.request {
            if submission.tx_hash.len() != 32 {
                return Err(AcpError::State(
                    "missing authenticated submission identifier".into(),
                ));
            }
            if let Some(record) = self.operation(actor.as_ref(), request.id)? {
                if record.id != request.id || record.digest != delegated.1 {
                    return Err(AcpError::InvalidBearerToken {
                        reason: "operation identity was used for different arguments".into(),
                    });
                }
                return serde_json::from_value(record.result)
                    .map_err(|error| AcpError::State(error.to_string()));
            }
        }
        let before = (self.clone(), vera.clone());
        let result = operation(self, vera, &actor).and_then(|result| {
            if let Some(request) = &claims.request {
                self.complete_operation(
                    actor.as_ref(),
                    &OperationRecord {
                        id: request.id,
                        digest: delegated.1,
                        actor: actor.to_string(),
                        submission: submission.tx_hash.as_slice().try_into().map_err(|_| {
                            AcpError::State("missing authenticated submission identifier".into())
                        })?,
                        worker: submission.signer.clone(),
                        revision: context.timestamp.clone(),
                        result: serde_json::to_value(&result)
                            .map_err(|error| AcpError::State(error.to_string()))?,
                    },
                )?;
            }
            vera.store_or_update_jws_token(
                context,
                token,
                &issuer,
                &claims.sub,
                Timestamp {
                    seconds: claims.iat,
                    block_height: 0,
                },
                Timestamp {
                    seconds: claims.exp,
                    block_height: 0,
                },
            )
            .map_err(invalid)?;
            Ok(result)
        });
        if result.is_err() {
            (*self, *vera) = before;
        }
        result
    }
}
