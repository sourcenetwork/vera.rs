//! Term certificates: approving a switch of the active device and checking one.

use alloy_primitives::{B256, FixedBytes};
use k256_native::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner as _};

pub use vera_domain::{TermApproval, TermCertificate, TermChange, TermCut, TermError};
pub use vera_permission::verify_term_certificate;

use crate::{ClientError, VeraClient, administration::OperatorPolicy};

/// Approve `change` with a secp256k1 operator key, at its index in the operator policy.
pub fn approve_term(
    change: &TermChange,
    signer: u16,
    key: &SigningKey,
) -> Result<TermApproval, ClientError> {
    let signature: Signature = key
        .sign_prehash(&change.signing_digest())
        .map_err(|error| ClientError::Signing(error.to_string()))?;
    Ok(TermApproval {
        signer,
        signature: FixedBytes::from_slice(&signature.to_bytes()),
        webauthn: None,
    })
}

/// Build an approval of `change` from a signature made outside this library.
///
/// The operator signs [`TermChange::signing_digest`]: ECDSA keys (secp256k1,
/// P-256) as the prehash, Ed25519 keys as the message. `signature` is the raw
/// 64 bytes; either ECDSA `s` is accepted. A signature the key at `signer` in
/// `policy` did not make over this change is an error.
pub fn external_term_approval(
    change: &TermChange,
    policy: &OperatorPolicy,
    signer: u16,
    signature: &[u8],
) -> Result<TermApproval, ClientError> {
    let signing = |error: &dyn std::fmt::Display| ClientError::Signing(error.to_string());
    let operator = policy.operator_did(signer).map_err(|e| signing(&e))?;
    let signature =
        vera_crypto::actor::canonical_signature(&operator, signature).map_err(|e| signing(&e))?;
    checked(change, policy, signer, &signature)
}

/// Build an approval of `change` from an ASN.1 DER ECDSA signature, as
/// platform key stores return it. See [`external_term_approval`].
pub fn external_der_term_approval(
    change: &TermChange,
    policy: &OperatorPolicy,
    signer: u16,
    signature: &[u8],
) -> Result<TermApproval, ClientError> {
    let signing = |error: &dyn std::fmt::Display| ClientError::Signing(error.to_string());
    let operator = policy.operator_did(signer).map_err(|e| signing(&e))?;
    let signature = vera_crypto::actor::canonical_der_signature(&operator, signature)
        .map_err(|e| signing(&e))?;
    checked(change, policy, signer, &signature)
}

fn checked(
    change: &TermChange,
    policy: &OperatorPolicy,
    signer: u16,
    signature: &[u8],
) -> Result<TermApproval, ClientError> {
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| ClientError::Signing("operator signature must contain 64 bytes".into()))?;
    if !policy.verifies(signer, &change.signing_digest(), &signature, None) {
        return Err(ClientError::Signing(
            "signature is not the operator's approval of this term change".into(),
        ));
    }
    Ok(TermApproval {
        signer,
        signature: FixedBytes::from(signature),
        webauthn: None,
    })
}

impl VeraClient {
    /// Fetch the certificate of the newest term the node holds, or `None`
    /// when the deployment's active device never changed.
    ///
    /// The response is not authenticated. Check it with
    /// [`Self::verify_term_certificate`] before acting on it.
    pub async fn term_certificate(&self) -> Result<Option<TermCertificate>, ClientError> {
        self.rpc_call_typed("vera_getTermCertificate", serde_json::json!([]))
            .await
    }

    /// Verify `certificate` against the operator policy in certified state
    /// and return the revision the policy was read at.
    ///
    /// The policy is read at `minimum` or later and authenticated against
    /// `trusted`, as [`Self::read_administration`] does. `genesis_id` is the
    /// identifier of the deployment's genesis block, which the caller holds
    /// independently of the node it asks.
    pub async fn verify_term_certificate(
        &self,
        certificate: &TermCertificate,
        genesis_id: &B256,
        minimum: u64,
        trusted: &vera_domain::ConsensusPublicKey,
    ) -> Result<u64, ClientError> {
        let administration = self.read_administration(minimum, trusted).await?;
        let state = administration.value.ok_or(ClientError::InvalidResponse(
            "operator authority is not configured",
        ))?;
        verify_term_certificate(certificate, genesis_id, &state.policy)?;
        Ok(administration.revision)
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::Signer as _;

    use super::*;

    const GENESIS: B256 = B256::repeat_byte(7);

    fn change() -> TermChange {
        TermChange {
            genesis_id: GENESIS,
            term: 1,
            holder: B256::repeat_byte(2),
            cut: TermCut {
                height: 12,
                block: B256::repeat_byte(3),
            },
        }
    }

    struct Operators {
        account: SigningKey,
        device: ed25519_dalek::SigningKey,
        policy: OperatorPolicy,
    }

    /// A secp256k1 account key and an Ed25519 device key, as a personal deployment lists them.
    fn operators(threshold: u16) -> Operators {
        let account = SigningKey::from_bytes((&[11u8; 32]).into()).unwrap();
        let device = ed25519_dalek::SigningKey::from_bytes(&[12; 32]);
        let mut keys = vec![
            hex::encode(account.verifying_key().to_sec1_bytes()),
            vera_crypto::actor::ed25519_did(&device.verifying_key().to_bytes()).unwrap(),
        ];
        keys.sort();
        let policy = OperatorPolicy { threshold, keys };
        policy.validate().unwrap();
        Operators {
            account,
            device,
            policy,
        }
    }

    impl Operators {
        fn index(&self, did: bool) -> u16 {
            let found = self
                .policy
                .keys
                .iter()
                .position(|key| key.starts_with("did:key:") == did);
            found.unwrap() as u16
        }

        fn account(&self, change: &TermChange) -> TermApproval {
            approve_term(change, self.index(false), &self.account).unwrap()
        }

        fn device(&self, change: &TermChange) -> TermApproval {
            let signature = self.device.sign(&change.signing_digest()).to_bytes();
            external_term_approval(change, &self.policy, self.index(true), &signature).unwrap()
        }
    }

    #[test]
    fn one_operator_approves_at_threshold_one() {
        let operators = operators(1);
        let change = change();
        for approval in [operators.account(&change), operators.device(&change)] {
            let certificate = TermCertificate {
                change,
                approvals: vec![approval],
            };
            verify_term_certificate(&certificate, &GENESIS, &operators.policy).unwrap();
        }
    }

    #[test]
    fn a_threshold_of_two_needs_both_operators() {
        let operators = operators(2);
        let change = change();
        let alone = TermCertificate {
            change,
            approvals: vec![operators.device(&change)],
        };
        assert_eq!(
            verify_term_certificate(&alone, &GENESIS, &operators.policy),
            Err(TermError::Approvals { threshold: 2 })
        );
        let mut approvals = vec![operators.account(&change), operators.device(&change)];
        approvals.sort_by_key(|approval| approval.signer);
        let both = TermCertificate { change, approvals };
        verify_term_certificate(&both, &GENESIS, &operators.policy).unwrap();
    }

    #[test]
    fn an_approval_of_another_change_does_not_verify() {
        let operators = operators(1);
        let mut other = change();
        other.holder = B256::repeat_byte(9);
        let approval = operators.device(&other);
        let certificate = TermCertificate {
            change: change(),
            approvals: vec![approval.clone()],
        };
        assert_eq!(
            verify_term_certificate(&certificate, &GENESIS, &operators.policy),
            Err(TermError::Signature(approval.signer))
        );
        let moved = TermCertificate {
            change: other,
            approvals: vec![approval],
        };
        verify_term_certificate(&moved, &GENESIS, &operators.policy).unwrap();
        assert_eq!(
            verify_term_certificate(&moved, &B256::ZERO, &operators.policy),
            Err(TermError::Deployment)
        );
    }

    #[test]
    fn a_signature_made_outside_the_library_is_checked_against_its_operator() {
        let operators = operators(1);
        let change = change();
        let own = operators.account(&change);
        let signature: k256::ecdsa::Signature =
            k256::ecdsa::signature::hazmat::PrehashSigner::sign_prehash(
                &k256::ecdsa::SigningKey::from_slice(&[11; 32]).unwrap(),
                &change.signing_digest(),
            )
            .unwrap();
        let low = signature.normalize_s().unwrap_or(signature);
        let high = k256::ecdsa::Signature::from_scalars(low.r(), -*low.s()).unwrap();
        for raw in [low.to_vec(), high.to_vec()] {
            assert_eq!(
                external_term_approval(&change, &operators.policy, own.signer, &raw).unwrap(),
                own
            );
        }
        assert_eq!(
            external_der_term_approval(
                &change,
                &operators.policy,
                own.signer,
                low.to_der().as_bytes()
            )
            .unwrap(),
            own
        );
        let device = operators.index(true);
        assert!(external_term_approval(&change, &operators.policy, device, &low.to_vec()).is_err());
        assert!(external_term_approval(&change, &operators.policy, 2, &low.to_vec()).is_err());
    }
}
