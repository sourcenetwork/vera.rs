//! What devices say to each other about the term.

use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use vera_domain::{MAX_TERM_CERTIFICATE_BYTES, TermCertificate};

/// Bytes a status takes besides its certificate: its kind, height, block and
/// flag.
const STATUS_BYTES: usize = 256;

/// Largest message accepted: a status carrying the largest certificate that
/// verifies. A device holds and sends only certificates that verify, and an
/// answer naming [`MAX_HEIGHTS`] blocks is smaller.
const MAX_BYTES: usize = MAX_TERM_CERTIFICATE_BYTES + STATUS_BYTES;

/// Most heights one question about blocks names.
pub(crate) const MAX_HEIGHTS: usize = 256;

/// A message on the term channel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Message {
    /// Asks a device where it stands, and says where the asker does.
    Query(Status),
    /// Where the sender stands.
    Status(Status),
    /// Asks for the identifiers of the sender's finalized blocks at these heights.
    Ancestry { heights: Vec<u64> },
    /// The identifiers asked for, at the heights the sender holds a block,
    /// and the oldest block the sender's history retains: it leaves out the
    /// heights below it.
    Blocks {
        floor: u64,
        blocks: Vec<(u64, B256)>,
    },
}

/// The newest block a device has and the newest term it holds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Status {
    /// Height of the newest finalized block when the message was made.
    pub height: u64,
    /// Identifier of that block; zero when the device has none.
    pub block: B256,
    /// The newest certificate the device verified.
    pub certificate: Option<TermCertificate>,
    /// Whether the device proposes nothing for now: a proposal waits for the
    /// others' answers, the device was answered, or it has yet to ask. A
    /// device that waits stops no device that proposes; of two that wait,
    /// the one with the higher `height` goes on, and at equal heights the
    /// one with the lower transport key.
    pub waiting: bool,
}

impl Message {
    pub(crate) fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("term messages serialize")
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        (bytes.len() <= MAX_BYTES)
            .then(|| serde_json::from_slice(bytes).ok())
            .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_round_trip_and_oversized_or_unknown_ones_are_dropped() {
        let standing = Status {
            height: 9,
            block: B256::repeat_byte(4),
            certificate: None,
            waiting: true,
        };
        for message in [
            Message::Query(standing.clone()),
            Message::Status(standing.clone()),
            Message::Ancestry {
                heights: vec![1, 5],
            },
            Message::Blocks {
                floor: 1,
                blocks: vec![(5, B256::repeat_byte(2))],
            },
        ] {
            assert_eq!(Message::decode(&message.encode()), Some(message));
        }
        assert_eq!(Message::decode(b"{\"kind\":\"vote\"}"), None);
        assert_eq!(Message::decode(b"{\"kind\":\"status\"}"), None);
        let mut padded = Message::Query(standing).encode();
        padded.resize(MAX_BYTES + 1, b' ');
        assert_eq!(Message::decode(&padded), None);
    }

    #[test]
    fn the_largest_messages_fit() {
        let status = Status {
            height: u64::MAX,
            block: B256::repeat_byte(0xff),
            certificate: None,
            waiting: false,
        };
        for message in [Message::Query(status.clone()), Message::Status(status)] {
            let without = message.encode().len() - "null".len();
            assert!(
                without + MAX_TERM_CERTIFICATE_BYTES <= MAX_BYTES,
                "{without}"
            );
        }
        let blocks = Message::Blocks {
            floor: u64::MAX,
            blocks: vec![(u64::MAX, B256::repeat_byte(0xff)); MAX_HEIGHTS],
        };
        assert!(blocks.encode().len() <= MAX_BYTES);
        let ancestry = Message::Ancestry {
            heights: vec![u64::MAX; MAX_HEIGHTS],
        };
        assert!(ancestry.encode().len() <= MAX_BYTES);
    }
}
