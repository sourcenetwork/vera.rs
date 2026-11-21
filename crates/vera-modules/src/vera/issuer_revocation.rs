//! Token invalidation by the token's issuer, carried by a worker under a signed operation.

use vera_crypto::jwt::{matches_issuer, verify_bearer_token};
use vera_identity::Did;

use super::{JWSTokenRecord, JWSTokenStatus, Result, VeraError, VeraModule};
use crate::acp::{AcpModule, delegated_operation::DelegatedOperation, error::AcpError};
use crate::types::{BlockExecCtx, TxExecCtx};

impl VeraModule {
    /// Invalidate the recorded token `token_hash` on behalf of its issuer.
    ///
    /// `operation` is a token the issuer signed with scope `vera:token:revoke`
    /// for the submitting worker and this deployment, carrying an operation
    /// identity whose digest is `RevokeToken(token_hash)`. The record names the
    /// issuer as the invalidating identity. A retry under the same identity
    /// returns the original record without invalidating again.
    pub fn invalidate_jws_by_issuer(
        &mut self,
        acp: &mut AcpModule,
        context: &BlockExecCtx,
        submission: &TxExecCtx,
        operation: &str,
        token_hash: &str,
    ) -> Result<JWSTokenRecord> {
        if verify_bearer_token(operation)
            .map_err(invalid)?
            .request
            .is_none()
        {
            return Err(invalid("issuer revocation requires an operation identity"));
        }
        let revocation = DelegatedOperation::RevokeToken(token_hash);
        let digest = revocation
            .digest()
            .map_err(|error| VeraError::State(error.to_string()))?;
        let mut refusal = None;
        let result = acp.with_delegation(
            self,
            context,
            submission,
            operation,
            (revocation.scope(), digest),
            |_, vera, issuer| {
                vera.invalidate_as_issuer(context, issuer, token_hash)
                    .map_err(|error| {
                        let reason = AcpError::State(error.to_string());
                        refusal = Some(error);
                        reason
                    })
            },
        );
        result.map_err(|error| refusal.take().unwrap_or_else(|| from_acp(error)))
    }

    fn invalidate_as_issuer(
        &mut self,
        context: &BlockExecCtx,
        issuer: &Did,
        token_hash: &str,
    ) -> Result<JWSTokenRecord> {
        let record = self
            .get_jws_token(token_hash)?
            .ok_or_else(|| VeraError::TokenNotFound {
                token_hash: token_hash.to_string(),
            })?;
        if !matches_issuer(&record.issuer_did, issuer.as_ref()) {
            return Err(VeraError::Unauthorized {
                reason: "operation signer is not the token's issuer".into(),
            });
        }
        if record.status == JWSTokenStatus::Invalid {
            return Err(VeraError::TokenAlreadyInvalidated {
                token_hash: token_hash.to_string(),
            });
        }
        self.update_jws_token_status(
            context,
            token_hash,
            JWSTokenStatus::Invalid,
            issuer.as_ref(),
        )
    }
}

fn invalid(error: impl std::fmt::Display) -> VeraError {
    VeraError::InvalidJws {
        reason: error.to_string(),
    }
}

fn from_acp(error: AcpError) -> VeraError {
    match error {
        AcpError::InvalidBearerToken { reason } => VeraError::InvalidJws { reason },
        AcpError::Unauthorized { reason } => VeraError::Unauthorized { reason },
        other => VeraError::State(other.to_string()),
    }
}

#[cfg(test)]
#[path = "issuer_revocation_tests.rs"]
mod tests;
