//! What devices say to each other about the term.

use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use vera_domain::TermCertificate;

/// Largest message accepted. A certificate holds at most one approval for
/// each of the 128 operators a policy may list.
const MAX_BYTES: usize = 64 * 1024;

/// A message on the term channel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Message {
    /// Asks a device where it stands.
    Query,
    /// Where the sender stands.
    Status(Status),
}

/// The newest block a device has and the newest term it holds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Status {
    /// Height of the newest finalized block.
    pub height: u64,
    /// Identifier of that block; zero when the device has none.
    pub block: B256,
    /// The newest certificate the device verified.
    pub certificate: Option<TermCertificate>,
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
        let status = Message::Status(Status {
            height: 9,
            block: B256::repeat_byte(4),
            certificate: None,
        });
        for message in [Message::Query, status] {
            assert_eq!(Message::decode(&message.encode()), Some(message));
        }
        assert_eq!(Message::decode(b"{\"kind\":\"vote\"}"), None);
        let mut padded = Message::Query.encode();
        padded.resize(MAX_BYTES + 1, b' ');
        assert_eq!(Message::decode(&padded), None);
    }
}
