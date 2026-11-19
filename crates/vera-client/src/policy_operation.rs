//! Delegated policy operations an actor signs once under an operation identity.

use alloy_sol_types::SolCall;
use vera_crypto::jwt::{DelegationScope, JwtClaims};
use vera_crypto::operation::{
    DEFAULT_OPERATION_LEAD, MAX_OPERATION_LEAD, OperationClaim, OperationId,
};
use vera_modules::acp::{
    MAX_POLICY_COMMAND_LIST, POLICY_OPERATION_LEAD_KEY, abi::IAcp,
    delegated_operation::DelegatedOperation, types::PolicyCmd,
};

use crate::bls_signer::BlsSigner;
use crate::client::{ACP_ADDRESS, VeraClient, parse_policy_id};
use crate::error::ClientError;
use crate::types::TransactionReceipt;

/// One graph command, or an ordered list applied in order, all or none.
///
/// Policy identifiers are held as the node spells them, lowercase hexadecimal
/// without a prefix, so the signed digest matches the executed request.
#[derive(Clone, Debug)]
pub enum PolicyOperation {
    /// One command, submitted through `bearerPolicyCmd`.
    Command(String, PolicyCmd),
    /// Ordered commands, submitted through `bearerPolicyCmds`.
    List(Vec<(String, PolicyCmd)>),
}

impl PolicyOperation {
    /// One command on the policy `policy_id`.
    pub fn command(policy_id: &str, command: PolicyCmd) -> Result<Self, ClientError> {
        Ok(Self::Command(policy(policy_id)?, command))
    }

    /// An ordered list of one to [`MAX_POLICY_COMMAND_LIST`] commands.
    pub fn list(commands: Vec<(String, PolicyCmd)>) -> Result<Self, ClientError> {
        if commands.is_empty() || commands.len() > MAX_POLICY_COMMAND_LIST {
            return Err(ClientError::Signing(format!(
                "a command list holds 1 to {MAX_POLICY_COMMAND_LIST} commands"
            )));
        }
        commands
            .into_iter()
            .map(|(policy_id, command)| Ok((policy(&policy_id)?, command)))
            .collect::<Result<_, _>>()
            .map(Self::List)
    }

    fn delegated(&self) -> DelegatedOperation<'_> {
        match self {
            Self::Command(policy_id, command) => {
                DelegatedOperation::PolicyCommand(policy_id, command)
            }
            Self::List(commands) => DelegatedOperation::PolicyCommandList(commands),
        }
    }

    /// The operation digest an operation claim binds.
    pub fn digest(&self) -> Result<[u8; 32], ClientError> {
        self.delegated()
            .digest()
            .map_err(|e| ClientError::Signing(e.to_string()))
    }

    /// Claims binding this operation to the operation identity `id`, valid from
    /// `issued_at` until the identity's deadline. Sign them with
    /// [`crate::UnsignedToken::operation_with_lead`] or
    /// [`crate::create_operation_token_with_lead`].
    pub fn claims(
        &self,
        issuer: &str,
        worker: &str,
        deployment_id: u64,
        genesis_id: [u8; 32],
        id: OperationId,
        issued_at: u64,
    ) -> Result<JwtClaims, ClientError> {
        Ok(JwtClaims {
            iss: issuer.into(),
            sub: worker.into(),
            exp: id.expires_at(),
            aud: format!("vera:{deployment_id}"),
            scope: DelegationScope::PolicyCommands,
            iat: issued_at,
            nbf: issued_at,
            relay: None,
            request: Some(OperationClaim {
                id,
                digest: self.digest()?,
                genesis_id,
            }),
        })
    }

    /// ACP precompile calldata submitting this operation under `token`.
    pub fn calldata(&self, token: &str) -> Result<Vec<u8>, ClientError> {
        Ok(match self {
            Self::Command(policy_id, command) => IAcp::bearerPolicyCmdCall {
                bearerToken: token.into(),
                policyId: parse_policy_id(policy_id)?,
                cmd: serde_json::to_vec(command)?.into(),
            }
            .abi_encode(),
            Self::List(commands) => IAcp::bearerPolicyCmdsCall {
                bearerToken: token.into(),
                commands: serde_json::to_vec(commands)?.into(),
            }
            .abi_encode(),
        })
    }
}

fn policy(policy_id: &str) -> Result<String, ClientError> {
    parse_policy_id(policy_id).map(hex::encode)
}

fn decode_lead(bytes: &[u8]) -> Result<u64, ClientError> {
    bytes
        .try_into()
        .map(u64::from_be_bytes)
        .ok()
        .filter(|seconds| (DEFAULT_OPERATION_LEAD..=MAX_OPERATION_LEAD).contains(seconds))
        .ok_or(ClientError::InvalidResponse(
            "invalid policy operation lead",
        ))
}

/// The policy-command lead at a finalized revision.
#[derive(Clone, Debug)]
pub struct PolicyOperationLead {
    /// Revision authenticating this value.
    pub revision: u64,
    /// Execution timestamp of that revision.
    pub timestamp: u64,
    /// Longest lead, in seconds, an operation identity on a policy command may carry.
    pub seconds: u64,
}

impl VeraClient {
    /// Read the deployment's policy-command lead from certified state; absence
    /// is the default. Execution compares it with each identity's remaining lead.
    pub async fn read_policy_operation_lead(
        &self,
        minimum: u64,
        trusted: &vera_domain::ConsensusPublicKey,
    ) -> Result<PolicyOperationLead, ClientError> {
        let response = self
            .read_current_record(
                vera_permission::ModuleId::Acp,
                POLICY_OPERATION_LEAD_KEY,
                minimum,
                trusted,
                vera_permission::RECORD_PROOF_BYTES,
            )
            .await?;
        let seconds = response
            .record
            .value
            .as_ref()
            .map_or(Ok(DEFAULT_OPERATION_LEAD), |bytes| decode_lead(bytes))?;
        Ok(PolicyOperationLead {
            revision: response.revision.height,
            timestamp: response.revision.timestamp,
            seconds,
        })
    }

    /// Submit a signed policy operation through a native worker and poll for its receipt.
    pub async fn native_policy_operation(
        &self,
        signer: &BlsSigner,
        token: &str,
        operation: &PolicyOperation,
    ) -> Result<TransactionReceipt, ClientError> {
        self.send_native_precompile_tx(signer, ACP_ADDRESS, operation.calldata(token)?.into())
            .await
    }
}

#[cfg(test)]
#[path = "policy_operation_tests.rs"]
mod tests;
