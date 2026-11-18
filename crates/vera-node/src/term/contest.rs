//! Another device validating beside this one.

use alloy_primitives::B256;
use vera_domain::{PublicKey, TermCertificate};

use super::wire::Status;

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

/// Whether the answer `answer` of device `answerer` stops device `asker`,
/// which asked with `question`.
///
/// Both devices of one exchange hold the same two statuses: the asker once
/// the answer arrives, the answerer when it answers. Each applies this to
/// them, so both reach one verdict, however their heights move afterwards.
/// An answer in a lower term than the certificate the asker holds, or one
/// that holds that same certificate, comes from a device the asker replaced
/// and does not stop it. Otherwise [`stands`] decides.
pub(crate) fn stops(asker: B256, question: &Status, answerer: B256, answer: &Status) -> bool {
    let holding = question
        .certificate
        .as_ref()
        .filter(|certificate| certificate.change.holder == asker)
        .map_or(0, |certificate| certificate.change.term);
    let (term, names_asker) = answer
        .certificate
        .as_ref()
        .map_or((0, false), |certificate| {
            (certificate.change.term, certificate.change.holder == asker)
        });
    // A device that holds the asker's own term follows it, or was replaced
    // by it and has not followed yet.
    let follows = holding > 0 && term == holding && names_asker;
    term >= holding && !follows && stands(Rank::of(asker, question), Rank::of(answerer, answer))
}

/// Where a device stands in one exchange of a wake check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Rank {
    /// Whether the device proposes nothing for now.
    pub waits: bool,
    /// Height of its newest finalized block, as the exchange carries it.
    pub height: u64,
    /// Its transport key's identifier.
    pub device: B256,
}

impl Rank {
    pub(crate) const fn of(device: B256, status: &Status) -> Self {
        Self {
            waits: status.waiting,
            height: status.height,
            device,
        }
    }

    /// Whether this device goes on before `other` when both hold back: it
    /// has the higher finalized height, or the same height and the lower key.
    fn precedes(&self, other: &Self) -> bool {
        (self.height, std::cmp::Reverse(self.device))
            > (other.height, std::cmp::Reverse(other.device))
    }
}

/// Whether a device that answered as the validator stops this one.
///
/// A device that proposes stops any device that asks it. One that holds its
/// proposals back stops only a device that holds back too and that it
/// precedes: it has the higher finalized height, or the same height and the
/// lower key, whether or not the two hold the same block at that height.
/// Two devices that wait for each other therefore end with one proposing,
/// the one with more history when their heights differ, and a device that
/// proposes is never stopped by one that waits.
pub(crate) fn stands(this: Rank, other: Rank) -> bool {
    !other.waits || (this.waits && other.precedes(&this))
}

#[cfg(test)]
mod tests {
    use vera_domain::{TermChange, TermCut};

    use super::*;

    const LOW: B256 = B256::repeat_byte(1);
    const HIGH: B256 = B256::repeat_byte(2);

    fn rank(waits: bool, height: u64, device: B256) -> Rank {
        Rank {
            waits,
            height,
            device,
        }
    }

    fn status(waiting: bool, height: u64, certificate: Option<(u64, B256)>) -> Status {
        Status {
            height,
            block: B256::repeat_byte(9),
            certificate: certificate.map(|(term, holder)| TermCertificate {
                change: TermChange {
                    genesis_id: B256::ZERO,
                    term,
                    holder,
                    cut: TermCut {
                        height: 0,
                        block: B256::ZERO,
                    },
                },
                approvals: Vec::new(),
            }),
            waiting,
        }
    }

    #[test]
    fn a_device_that_proposes_stops_whoever_asks() {
        for waits in [false, true] {
            for (this, other) in [(0, 5), (5, 0), (3, 3)] {
                assert!(stands(rank(waits, this, LOW), rank(false, other, HIGH)));
                assert!(stands(rank(waits, this, HIGH), rank(false, other, LOW)));
            }
        }
    }

    #[test]
    fn a_device_that_waits_does_not_stop_one_that_proposes() {
        for (this, other) in [(0, 5), (5, 0), (3, 3)] {
            assert!(!stands(rank(false, this, LOW), rank(true, other, HIGH)));
            assert!(!stands(rank(false, this, HIGH), rank(true, other, LOW)));
        }
    }

    #[test]
    fn of_two_devices_that_wait_the_higher_one_goes_on_whatever_their_keys() {
        for (lower, higher) in [(LOW, HIGH), (HIGH, LOW)] {
            assert!(stands(rank(true, 3, lower), rank(true, 7, higher)));
            assert!(!stands(rank(true, 7, higher), rank(true, 3, lower)));
        }
    }

    #[test]
    fn of_two_devices_that_wait_at_one_height_the_lower_key_goes_on() {
        assert!(!stands(rank(true, 4, LOW), rank(true, 4, HIGH)));
        assert!(stands(rank(true, 4, HIGH), rank(true, 4, LOW)));
    }

    #[test]
    fn both_sides_of_an_exchange_name_one_device_to_go_on() {
        for (asker, answerer) in [(LOW, HIGH), (HIGH, LOW)] {
            for (asked, answered) in [(0, 5), (5, 0), (4, 4)] {
                let question = status(true, asked, None);
                let answer = status(true, answered, None);
                assert_eq!(
                    stops(asker, &question, answerer, &answer),
                    Rank::of(answerer, &answer).precedes(&Rank::of(asker, &question)),
                    "{asked} {answered}"
                );
            }
        }
    }

    #[test]
    fn a_device_the_asker_replaced_does_not_stop_it_whatever_its_height() {
        let question = status(true, 0, Some((2, LOW)));
        // A lower term than the asker's own, or none.
        assert!(!stops(
            LOW,
            &question,
            HIGH,
            &status(true, 50, Some((1, HIGH)))
        ));
        assert!(!stops(LOW, &question, HIGH, &status(false, 50, None)));
        // The asker's own certificate.
        assert!(!stops(
            LOW,
            &question,
            HIGH,
            &status(false, 50, Some((2, LOW)))
        ));
        // The same term number held by another device is a contest.
        assert!(stops(
            LOW,
            &question,
            HIGH,
            &status(true, 50, Some((2, HIGH)))
        ));
    }
}
