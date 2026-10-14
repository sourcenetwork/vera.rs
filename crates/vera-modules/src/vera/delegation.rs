use vera_crypto::jwt::{DelegationScope, JwtClaims, matches_issuer, verify_bearer_token};
use vera_identity::Did;

use super::{JWSTokenRecord, JWSTokenStatus, Result, VeraError, VeraModule};
use crate::types::{BlockExecCtx, Timestamp};

impl VeraModule {
    /// Verify a delegation against the authenticated caller and current revocations.
    pub fn authorize_delegation(
        &self,
        context: &BlockExecCtx,
        caller: &Did,
        token: &str,
        scope: DelegationScope,
        operation: [u8; 32],
    ) -> Result<JwtClaims> {
        let claims = verify_bearer_token(token).map_err(invalid)?;
        if claims.scope != scope {
            return Err(invalid("delegation does not authorize this operation"));
        }
        claims
            .authorize(
                caller.as_ref(),
                context.deployment_id,
                context.timestamp.seconds,
            )
            .map_err(invalid)?;
        self.authorize_relay(&claims, operation, context)?;
        if let Some(request) = &claims.request {
            request
                .id
                .validate(context.timestamp.seconds)
                .map_err(invalid)?;
            if context.genesis_id == [0; 32]
                || request.genesis_id != context.genesis_id
                || request.digest != operation
                || claims.exp > request.id.expires_at()
            {
                return Err(invalid("operation identity does not bind this request"));
            }
        }
        if self
            .get_jws_token(&Self::hash_jws_token(token))?
            .is_some_and(|record| record.status != JWSTokenStatus::Valid)
        {
            return Err(invalid("token has been revoked"));
        }
        Ok(claims)
    }

    /// Revoke a signed delegation, including one that has never been used.
    pub fn revoke_delegation(
        &mut self,
        context: &BlockExecCtx,
        caller: &Did,
        token: &str,
    ) -> Result<JWSTokenRecord> {
        let claims = verify_bearer_token(token).map_err(invalid)?;
        let caller = caller.to_string();
        if claims.aud != format!("vera:{}", context.deployment_id)
            || claims.relay.as_ref().is_some_and(|relay| {
                context.genesis_id == [0; 32] || relay.genesis_id != context.genesis_id
            })
            || claims.request.as_ref().is_some_and(|request| {
                context.genesis_id == [0; 32] || request.genesis_id != context.genesis_id
            })
            || (!matches_issuer(&claims.iss, &caller) && caller != claims.sub)
        {
            return Err(VeraError::Unauthorized {
                reason: "delegation revocation is not authorized".into(),
            });
        }
        let hash = Self::hash_jws_token(token);
        let mut record = self
            .get_jws_token(&hash)?
            .unwrap_or_else(|| JWSTokenRecord {
                token_hash: hash,
                bearer_token: token.into(),
                issuer_did: claims.iss,
                authorized_account: claims.sub,
                issued_at: Timestamp {
                    seconds: claims.iat,
                    block_height: 0,
                },
                expires_at: Timestamp {
                    seconds: claims.exp,
                    block_height: 0,
                },
                status: JWSTokenStatus::Valid,
                first_used_at: None,
                last_used_at: None,
                invalidated_at: None,
                invalidated_by: String::new(),
            });
        if record.status == JWSTokenStatus::Invalid {
            return Err(VeraError::TokenAlreadyInvalidated {
                token_hash: record.token_hash,
            });
        }
        record.status = JWSTokenStatus::Invalid;
        record.invalidated_at = Some(context.timestamp.clone());
        record.invalidated_by = caller;
        self.set_jws_token(&record)?;
        Ok(record)
    }
}

fn invalid(error: impl std::fmt::Display) -> VeraError {
    VeraError::InvalidJws {
        reason: error.to_string(),
    }
}
