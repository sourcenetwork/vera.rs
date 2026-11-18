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

/// Whether a device that answered as the validator stops this one.
///
/// A device that proposes stops any device that asks it. One that holds its
/// proposals back stops only a device that holds back too and has the
/// higher key, so two devices that wait for each other end with one
/// proposing, and a device that proposes is never stopped by one that waits.
pub(crate) fn stands(waits: bool, this: B256, other_waits: bool, other: B256) -> bool {
    !other_waits || (waits && other < this)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOW: B256 = B256::repeat_byte(1);
    const HIGH: B256 = B256::repeat_byte(2);

    #[test]
    fn a_device_that_proposes_stops_whoever_asks() {
        for waits in [false, true] {
            assert!(stands(waits, LOW, false, HIGH));
            assert!(stands(waits, HIGH, false, LOW));
        }
    }

    #[test]
    fn a_device_that_waits_does_not_stop_one_that_proposes() {
        assert!(!stands(false, LOW, true, HIGH));
        assert!(!stands(false, HIGH, true, LOW));
    }

    #[test]
    fn of_two_devices_that_wait_the_lower_key_goes_on() {
        assert!(!stands(true, LOW, true, HIGH));
        assert!(stands(true, HIGH, true, LOW));
    }
}
