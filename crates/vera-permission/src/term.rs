//! Term certificates checked against a deployment's operator policy.

use alloy_primitives::B256;
use vera_domain::{TermCertificate, TermError};
use vera_modules::vera::administration::OperatorPolicy;

/// Verify that `certificate` records a switch of the active device of the
/// deployment `genesis_id`, approved under `policy`.
///
/// `policy` must come from state the caller has verified: the certificate
/// carries no key, so a policy taken from an unverified source lets its author
/// approve any switch. A certificate that verifies says who may propose from
/// its term on; it does not say that its cut is a finalized block.
pub fn verify_term_certificate(
    certificate: &TermCertificate,
    genesis_id: &B256,
    policy: &OperatorPolicy,
) -> Result<(), TermError> {
    certificate.verify(
        genesis_id,
        policy.threshold,
        policy.keys.len(),
        |signer, digest, signature| policy.verifies(signer, digest, signature),
    )
}
