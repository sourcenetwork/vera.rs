//! Operator approvals signed with a passkey.
//!
//! A host asks the operator's platform authenticator for an assertion whose
//! challenge is the digest the approval covers:
//! [`AdministrativeRequest::signing_digest`] or [`TermChange::signing_digest`].
//! It passes the 32 digest bytes as the `challenge` of
//! `navigator.credentials.get`, or the platform equivalent, with user
//! verification required, and hands the assertion's authenticator data,
//! client data JSON and DER signature to these functions.
//!
//! The credential must be dedicated to these approvals. A credential that
//! also signs challenges a server chooses, such as a web login, lets that
//! server obtain an approval of any digest.

use alloy_primitives::{Bytes, FixedBytes};
use vera_crypto::webauthn::Assertion;
use vera_domain::{TermApproval, TermChange, TermPasskeyAssertion};
use vera_modules::vera::administration::{
    AdministrativeRequest, OperatorApproval, OperatorPolicy, PasskeyAssertion,
};

use crate::ClientError;

/// Build an approval of `request` from a passkey assertion by the P-256
/// operator at `signer` in `policy`. An assertion that does not approve this
/// request is an error.
pub fn webauthn_approval(
    request: &AdministrativeRequest,
    policy: &OperatorPolicy,
    signer: u16,
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
) -> Result<OperatorApproval, ClientError> {
    let signature = raw_signature(policy, signer, signature)?;
    let digest = request
        .signing_digest()
        .map_err(|error| ClientError::Signing(error.to_string()))?;
    let approval = OperatorApproval {
        signer,
        signature: hex::encode(signature),
        webauthn: Some(PasskeyAssertion::new(authenticator_data, client_data_json)),
    };
    policy
        .verify_approval(&digest, &approval)
        .map_err(|error| ClientError::Signing(error.to_string()))?;
    Ok(approval)
}

/// Build an approval of `change` from a passkey assertion by the P-256
/// operator at `signer` in `policy`. An assertion that does not approve this
/// change is an error.
pub fn webauthn_term_approval(
    change: &TermChange,
    policy: &OperatorPolicy,
    signer: u16,
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
) -> Result<TermApproval, ClientError> {
    let signature = raw_signature(policy, signer, signature)?;
    let assertion = Assertion {
        authenticator_data,
        client_data_json,
    };
    if !policy.verifies(
        signer,
        &change.signing_digest(),
        &signature,
        Some(&assertion),
    ) {
        return Err(ClientError::Signing(
            "assertion is not the operator's approval of this term change".into(),
        ));
    }
    Ok(TermApproval {
        signer,
        signature: FixedBytes::from(signature),
        webauthn: Some(TermPasskeyAssertion {
            authenticator_data: Bytes::copy_from_slice(authenticator_data),
            client_data_json: Bytes::copy_from_slice(client_data_json),
        }),
    })
}

/// The raw low-S form of the DER signature an authenticator returns.
fn raw_signature(
    policy: &OperatorPolicy,
    signer: u16,
    signature: &[u8],
) -> Result<[u8; 64], ClientError> {
    let signing = |error: &dyn std::fmt::Display| ClientError::Signing(error.to_string());
    let operator = policy.operator_did(signer).map_err(|e| signing(&e))?;
    vera_crypto::actor::canonical_der_signature(&operator, signature)
        .map_err(|e| signing(&e))?
        .try_into()
        .map_err(|_| ClientError::Signing("operator signature must contain 64 bytes".into()))
}

#[cfg(test)]
#[path = "passkey_approval_tests.rs"]
mod tests;
