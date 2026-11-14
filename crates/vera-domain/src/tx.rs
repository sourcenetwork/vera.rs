//! Transactions

use alloy_primitives::{Bytes, Keccak256};
use bytes::BufMut;
use commonware_codec::{Encode as _, EncodeSize, Error as CodecError, RangeCfg, Read, Write};

use super::TxId;

#[derive(Clone, Copy, Debug)]
/// Configuration used when decoding transactions from bytes.
pub struct TxCfg {
    /// Maximum encoded transaction size accepted by the codec.
    pub max_tx_bytes: usize,
}

/// Raw request bytes: a native request or a signed Ethereum transaction envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tx {
    /// Encoded transaction bytes.
    pub bytes: Bytes,
}

impl Tx {
    /// Compute the transaction identifier from its encoded contents.
    pub fn id(&self) -> TxId {
        // The encoding is the length prefix followed by the bytes; hashing the two
        // parts in turn avoids copying the request.
        let mut hasher = Keccak256::new();
        hasher.update(self.bytes.len().encode());
        hasher.update(&self.bytes);
        TxId(hasher.finalize())
    }

    /// Whether the bytes carry the native request type rather than an Ethereum envelope.
    pub fn is_native(&self) -> bool {
        self.bytes
            .first()
            .is_some_and(|byte| crate::NativeTx::is_native_tx(*byte))
    }

    /// Create a new transaction from encoded bytes.
    #[must_use]
    pub const fn new(bytes: Bytes) -> Self {
        Self { bytes }
    }
}

impl Write for Tx {
    fn write(&self, buf: &mut impl BufMut) {
        self.bytes.as_ref().write(buf);
    }
}

impl EncodeSize for Tx {
    fn encode_size(&self) -> usize {
        self.bytes.as_ref().encode_size()
    }
}

impl Read for Tx {
    type Cfg = TxCfg;

    fn read_cfg(buf: &mut impl commonware_codec::Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let data = Vec::<u8>::read_cfg(
            buf,
            &(
                RangeCfg::new(0..=cfg.max_tx_bytes.min(crate::MAX_TX_BYTES)),
                (),
            ),
        )?;
        Ok(Self {
            bytes: Bytes::from(data),
        })
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::keccak256;
    use commonware_codec::{Decode, Encode};

    use super::*;

    fn default_tx_cfg() -> TxCfg {
        TxCfg {
            max_tx_bytes: 131072,
        }
    }

    #[test]
    fn tx_id_is_deterministic() {
        let tx = Tx::new(Bytes::from_static(&[0x01, 0x02, 0x03]));
        let id1 = tx.id();
        let id2 = tx.id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn tx_id_is_the_hash_of_the_encoding() {
        for len in [0usize, 1, 127, 128, 300, 20_000] {
            let tx = Tx::new(Bytes::from(vec![0xa5; len]));
            assert_eq!(tx.id(), TxId(keccak256(tx.encode())), "length {len}");
        }
    }

    #[test]
    fn native_requests_are_told_apart_by_their_first_byte() {
        assert!(Tx::new(Bytes::from_static(&[crate::NATIVE_TX_TYPE, 1])).is_native());
        assert!(!Tx::new(Bytes::from_static(&[0x02, 1])).is_native());
        assert!(!Tx::new(Bytes::new()).is_native());
    }

    #[test]
    fn tx_id_differs_by_content() {
        let tx1 = Tx::new(Bytes::from_static(&[0x01, 0x02]));
        let tx2 = Tx::new(Bytes::from_static(&[0x01, 0x03]));
        assert_ne!(tx1.id(), tx2.id());
    }

    #[test]
    fn tx_encode_decode_roundtrip() {
        let tx = Tx::new(Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]));
        let encoded = tx.encode();
        let decoded = Tx::decode_cfg(encoded, &default_tx_cfg()).expect("decode");
        assert_eq!(tx, decoded);
    }

    #[test]
    fn tx_encode_size_matches_encoded() {
        let tx = Tx::new(Bytes::from_static(&[0x01, 0x02, 0x03, 0x04, 0x05]));
        assert_eq!(tx.encode_size(), tx.encode().len());
    }

    #[test]
    fn empty_tx_roundtrip() {
        let tx = Tx::new(Bytes::new());
        let encoded = tx.encode();
        let decoded = Tx::decode_cfg(encoded, &default_tx_cfg()).expect("decode");
        assert_eq!(tx, decoded);
    }

    #[test]
    fn large_tx_roundtrip() {
        let data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let tx = Tx::new(Bytes::from(data));
        let encoded = tx.encode();
        let decoded = Tx::decode_cfg(encoded, &default_tx_cfg()).expect("decode");
        assert_eq!(tx, decoded);
    }
}
