use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use vera_crypto::jwt::{DelegationScope, JwtClaims, canonical_issuer};

use super::{Result, VeraError, VeraModule};
use crate::kv_store::ModuleKvStore;

/// Longest lifetime of a relay assertion, in seconds.
pub const MAX_RELAY_TOKEN_TTL: u64 = 600;

/// Authority delegated to a relay by the deployment's operators.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayGrant {
    /// Canonical compressed secp256k1 DID of the relay signing key.
    pub issuer: String,
    /// Allowed scopes in ascending order, without duplicates.
    pub scopes: Vec<DelegationScope>,
    /// Last allowed assertion expiry, in Unix seconds.
    pub expires_at: u64,
}

/// Active grant and the administrative sequence that installed it.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct RelayState {
    /// Operator-approved authority.
    pub grant: RelayGrant,
    /// Prevents assertions from an earlier grant becoming valid after reauthorization.
    pub sequence: u64,
}

/// Native record key for a canonical relay issuer.
pub fn relay_key(issuer: &str) -> Result<Vec<u8>> {
    if issuer.len() > 128 || canonical_issuer(issuer).map_err(invalid)? != issuer {
        return Err(invalid(
            "relay issuer must use a canonical compressed key DID",
        ));
    }
    let mut key = b"relay/v1/".to_vec();
    key.extend_from_slice(issuer.as_bytes());
    Ok(key)
}

impl VeraModule {
    /// Read a relay grant from committed module state.
    pub fn relay(&self, issuer: &str) -> Result<Option<RelayState>> {
        self.store
            .get(&relay_key(issuer)?)
            .map(|bytes| {
                borsh::from_slice(&bytes).map_err(|error| VeraError::State(error.to_string()))
            })
            .transpose()
    }

    pub(super) fn set_relay(&mut self, grant: &RelayGrant, sequence: u64, now: u64) -> Result<()> {
        let key = relay_key(&grant.issuer)?;
        if grant.scopes.is_empty()
            || grant.scopes.len() > 4
            || grant.scopes.windows(2).any(|pair| pair[0] >= pair[1])
            || grant.expires_at <= now
        {
            return Err(invalid("invalid relay scopes or expiration"));
        }
        let state = RelayState {
            grant: grant.clone(),
            sequence,
        };
        let bytes = borsh::to_vec(&state).map_err(invalid)?;
        self.store.put(&key, bytes);
        Ok(())
    }

    pub(super) fn revoke_relay(&mut self, issuer: &str) -> Result<()> {
        let key = relay_key(issuer)?;
        if !self.store.has(&key) {
            return Err(invalid("relay grant does not exist"));
        }
        self.store.delete(&key);
        Ok(())
    }

    pub(super) fn authorize_relay(
        &self,
        claims: &JwtClaims,
        operation: [u8; 32],
        context: &crate::types::BlockExecCtx,
    ) -> Result<()> {
        let Some(assertion) = &claims.relay else {
            return Ok(());
        };
        let state = self
            .relay(&claims.iss)?
            .ok_or_else(|| invalid("relay is not authorized"))?;
        if context.genesis_id == [0; 32]
            || assertion.genesis_id != context.genesis_id
            || assertion.grant_sequence != state.sequence
            || assertion.operation != operation
            || !state.grant.scopes.contains(&claims.scope)
            || claims.exp > state.grant.expires_at
            || context.timestamp.seconds >= claims.exp
            || claims.exp.saturating_sub(claims.iat) > MAX_RELAY_TOKEN_TTL
            || claims.nbf != claims.iat
            || !assertion.actor.starts_with("did:opk:")
            || vera_identity::Did::new(&assertion.actor).is_err()
        {
            return Err(invalid("relay assertion exceeds its grant or operation"));
        }
        Ok(())
    }
}

fn invalid(error: impl std::fmt::Display) -> VeraError {
    VeraError::InvalidJws {
        reason: error.to_string(),
    }
}
