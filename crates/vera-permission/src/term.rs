//! Term certificates checked against a deployment's operator policy.

use alloy_primitives::B256;
use vera_crypto::webauthn::Assertion;
use vera_domain::{MAX_TERM_CERTIFICATE_BYTES, TermApproval, TermCertificate, TermError};
use vera_modules::vera::administration::OperatorPolicy;

/// Verify that `certificate` records a switch of the active device of the
/// deployment `genesis_id`, approved under `policy`.
///
/// `policy` must come from state the caller has verified: the certificate
/// carries no key, so a policy taken from an unverified source lets its author
/// approve any switch. A certificate that verifies says who may propose from
/// its term on; it does not say that its cut is a finalized block.
///
/// A certificate whose JSON encoding exceeds [`MAX_TERM_CERTIFICATE_BYTES`]
/// does not verify, so a device never holds or sends one that a chain
/// recording terms would refuse.
pub fn verify_term_certificate(
    certificate: &TermCertificate,
    genesis_id: &B256,
    policy: &OperatorPolicy,
) -> Result<(), TermError> {
    if serde_json::to_vec(certificate).map_or(true, |json| json.len() > MAX_TERM_CERTIFICATE_BYTES)
    {
        return Err(TermError::TooLarge);
    }
    certificate.verify(
        genesis_id,
        policy.threshold,
        policy.keys.len(),
        |approval, digest| approves_term(policy, approval, digest),
    )
}

/// Whether `approval` is the approval of `digest` by the operator it names in
/// `policy`: its signature of the digest, or, when it carries a passkey
/// assertion, its signature of that assertion.
#[must_use]
pub fn approves_term(policy: &OperatorPolicy, approval: &TermApproval, digest: &[u8; 32]) -> bool {
    let assertion = approval.webauthn.as_ref().map(|webauthn| Assertion {
        authenticator_data: &webauthn.authenticator_data,
        client_data_json: &webauthn.client_data_json,
    });
    policy.verifies(
        approval.signer,
        digest,
        &approval.signature.0,
        assertion.as_ref(),
    )
}

#[cfg(test)]
#[path = "term_tests.rs"]
mod tests;
