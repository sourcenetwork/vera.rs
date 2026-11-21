//! Token revocation an issuer signs once for a native worker to submit.

use alloy_primitives::B256;
use alloy_sol_types::SolCall;
use k256_native::ecdsa::SigningKey;
use vera_crypto::jwt::JwtClaims;
use vera_crypto::operation::{OperationClaim, OperationId};
use vera_modules::acp::delegated_operation::DelegatedOperation;
use vera_modules::vera::{abi::IVera, keys};

use crate::bls_signer::BlsSigner;
use crate::client::{VERA_ADDRESS, VeraClient};
use crate::error::ClientError;
use crate::types::TransactionReceipt;

/// Invalidation of one recorded token, authorized by the token's issuer.
///
/// The issuer signs [`Self::claims`] under an operation identity, with
/// [`Self::sign`] for a secp256k1 key or [`crate::UnsignedToken::operation`]
/// for an Ed25519, P-256 or externally held key. Any worker the claims name
/// submits the result with [`VeraClient::native_invalidate_jws_by_issuer`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenRevocation {
    token_hash: String,
}

impl TokenRevocation {
    /// Revocation of the token whose SHA-256 hash is `token_hash`.
    pub fn new(token_hash: B256) -> Self {
        Self {
            token_hash: hex::encode(token_hash),
        }
    }

    /// Revocation of `token`, a bearer token the issuer signed earlier.
    pub fn of_token(token: &str) -> Self {
        Self {
            token_hash: keys::hash_jws_token(token),
        }
    }

    /// The token hash as the node's token record spells it.
    pub fn token_hash(&self) -> &str {
        &self.token_hash
    }

    fn delegated(&self) -> DelegatedOperation<'_> {
        DelegatedOperation::RevokeToken(&self.token_hash)
    }

    /// The operation digest an operation claim binds.
    pub fn digest(&self) -> Result<[u8; 32], ClientError> {
        self.delegated()
            .digest()
            .map_err(|e| ClientError::Signing(e.to_string()))
    }

    /// Claims binding this revocation to `issuer`, `worker`, the deployment and
    /// the operation identity `id`, valid from `issued_at` until its deadline.
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
            scope: self.delegated().scope(),
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

    /// Sign this revocation with the issuer's secp256k1 key for `worker`.
    pub fn sign(
        &self,
        signing_key: &SigningKey,
        worker: &str,
        deployment_id: u64,
        genesis_id: [u8; 32],
        id: OperationId,
        issued_at: u64,
    ) -> Result<String, ClientError> {
        let issuer = vera_crypto::secp256k1::did_from_secp256k1_pubkey(
            signing_key.verifying_key().to_sec1_point(true).as_bytes(),
        )
        .map_err(|e| ClientError::Signing(format!("DID derivation: {e}")))?;
        crate::create_operation_token(
            signing_key,
            &self.claims(&issuer, worker, deployment_id, genesis_id, id, issued_at)?,
        )
    }

    /// Vera module calldata submitting this revocation under the signed `operation`.
    pub fn calldata(&self, operation: &str) -> Vec<u8> {
        IVera::invalidateJWSByIssuerCall {
            tokenHash: self.token_hash.clone(),
            operation: operation.into(),
        }
        .abi_encode()
    }
}

impl VeraClient {
    /// Submit an issuer-signed token revocation as the worker it names and poll for its receipt.
    pub async fn native_invalidate_jws_by_issuer(
        &self,
        signer: &BlsSigner,
        revocation: &TokenRevocation,
        operation: &str,
    ) -> Result<TransactionReceipt, ClientError> {
        self.send_native_precompile_tx(signer, VERA_ADDRESS, revocation.calldata(operation).into())
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer as _;
    use vera_crypto::jwt::{DelegationScope, verify_bearer_token};

    fn id() -> OperationId {
        OperationId::new(600, [5; 24])
    }

    #[test]
    fn a_secp256k1_issuer_signs_the_exact_revocation() {
        let key = SigningKey::from_slice(&[42; 32]).unwrap();
        let revocation = TokenRevocation::of_token("issued");
        assert_eq!(
            revocation,
            TokenRevocation::new(B256::from_slice(
                &hex::decode(revocation.token_hash()).unwrap()
            ))
        );
        let token = revocation
            .sign(&key, "did:key:worker", 9001, [7; 32], id(), 100)
            .unwrap();
        let claims = verify_bearer_token(&token).unwrap();
        assert_eq!(claims.scope, DelegationScope::RevokeToken);
        assert_eq!(claims.exp, 600);
        let request = claims.request.unwrap();
        assert_eq!(request.digest, revocation.digest().unwrap());
        assert_ne!(
            request.digest,
            TokenRevocation::of_token("other").digest().unwrap()
        );
        let call =
            IVera::invalidateJWSByIssuerCall::abi_decode(&revocation.calldata(&token)).unwrap();
        assert_eq!(call.tokenHash, revocation.token_hash());
        assert_eq!(call.operation, token);
        assert!(
            revocation
                .sign(&key, "did:key:worker", 9001, [0; 32], id(), 100)
                .is_err()
        );
    }

    #[test]
    fn an_ed25519_issuer_signs_the_claims_itself() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        let issuer = vera_crypto::actor::ed25519_did(&key.verifying_key().to_bytes()).unwrap();
        let revocation = TokenRevocation::of_token("issued");
        let claims = revocation
            .claims(&issuer, "did:key:worker", 9001, [7; 32], id(), 100)
            .unwrap();
        let unsigned = crate::UnsignedToken::operation(&claims).unwrap();
        let signature = key.sign(unsigned.signing_input()).to_bytes();
        let verified = verify_bearer_token(&unsigned.finish(&signature).unwrap()).unwrap();
        assert_eq!(verified.iss, issuer);
        assert_eq!(
            verified.request.unwrap().digest,
            revocation.digest().unwrap()
        );
    }
}
