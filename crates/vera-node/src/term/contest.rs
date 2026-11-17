//! Another device validating beside this one.

use alloy_primitives::B256;
use vera_domain::{PublicKey, TermCertificate};

/// What another device answered when this one asked where it stands.
///
/// Only a device that runs as the deployment's validator answers, so an
/// answer means two devices are active. This device holds no certificate
/// that settles it: the answer carried none, or one it could not verify
/// against the operator policy in its own state, or one of a term it already
/// holds. It proposes nothing while the other device keeps answering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contest {
    /// The configured device whose address answered.
    pub device: PublicKey,
    /// Height of that device's newest block.
    pub height: u64,
    /// Identifier of that block.
    pub block: B256,
    /// The newest certificate that device holds. It is not verified.
    pub certificate: Option<TermCertificate>,
}
