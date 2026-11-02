//! Block types

use alloy_evm::revm::primitives::{B256, keccak256};
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};
use commonware_consensus::types::{Epoch, Round, View};
use commonware_cryptography::{
    Committable, Digestible, Hasher as _, Sha256, bls12381::primitives::variant::MinSig, ed25519,
};
use commonware_glue::dkg::types::Payload;
use commonware_utils::{NZU32, sequence::Unit};
use std::fmt;
use std::num::NonZeroU32;

use crate::{BlockId, ConsensusContext, DbTarget, DbTargets, Idents, StateRoot, Tx, TxCfg};

/// BLS variant used by the DKG reshare payload.
pub type DkgVariant = MinSig;

/// Signer type used by the DKG reshare payload.
pub type DkgSigner = ed25519::PrivateKey;

/// Transport directory type carried by the block's epoch artifacts.
pub type DkgDirectory = Unit;

/// Reshare payload a block may carry for the DKG epoch transition.
pub type DkgPayload = Payload<DkgVariant, ed25519::PublicKey, DkgDirectory>;

/// Maximum entries accepted in each DKG participant set.
pub const MAX_DKG_PARTICIPANTS: NonZeroU32 = NZU32!(64);

/// Codec configuration used when decoding a block's DKG payload.
pub type DkgPayloadCfg = (
    NonZeroU32,
    commonware_cryptography::bls12381::primitives::sharing::ModeVersion,
);

/// Codec configuration used when decoding a block's DKG payload.
pub const DKG_PAYLOAD_CFG: DkgPayloadCfg = (
    MAX_DKG_PARTICIPANTS,
    commonware_cryptography::bls12381::primitives::sharing::ModeVersion::v0(),
);

#[derive(Clone, Copy, Debug)]
/// Configuration used when decoding blocks and their transactions.
pub struct BlockCfg {
    /// Maximum number of transactions that can be encoded in a block.
    pub max_txs: usize,
    /// Per-transaction codec configuration.
    pub tx: TxCfg,
}

#[derive(Clone, PartialEq, Eq)]
/// Block type agreed on by consensus (via its digest).
pub struct Block {
    /// Consensus context from the proposing round.
    pub context: ConsensusContext,
    /// Identifier of the parent block.
    pub parent: BlockId,
    /// Block height (number of committed ancestors).
    pub height: u64,
    /// Wall-clock timestamp (unix seconds), set by proposer.
    pub timestamp: u64,
    /// Seed-derived randomness used for future prevrandao.
    pub prevrandao: B256,
    /// State commitment resulting from this block (pre-commit QMDB root).
    pub state_root: StateRoot,
    /// Module state root (combined hash of ACP, Bulletin, Vera, NativeNonce state).
    pub module_state_root: B256,
    /// Transactions included in the block.
    pub txs: Vec<Tx>,
    /// Optional DKG reshare payload (dealer log or next-epoch info).
    pub payload: Option<DkgPayload>,
    /// Per-partition QMDB targets after this block.
    pub db_targets: DbTargets,
    /// Ordered module log targets in ACP, bulletin, vera and sequence order.
    /// Presence selects the native commitment encoding; legacy blocks omit them.
    pub native_targets: Option<[DbTarget; 4]>,
    /// Commitment to ordered execution receipts and the execution gas limit.
    /// Legacy encodings omit this field; native execution requires it.
    pub receipt_commitment: Option<B256>,
}

impl Block {
    /// Check wire budgets before proposing or executing an in-memory block.
    #[must_use]
    pub fn fits_wire_limits(&self) -> bool {
        self.txs.len() <= crate::MAX_BLOCK_TXS
            && self
                .txs
                .iter()
                .all(|tx| tx.bytes.len() <= crate::MAX_TX_BYTES)
            && self.txs.encode_size() <= crate::MAX_BLOCK_TX_BYTES
            && self.encode_size() <= crate::MAX_BLOCK_BYTES
    }

    /// Compute the block identifier from its encoded contents.
    pub fn id(&self) -> BlockId {
        BlockId(keccak256(self.encode()))
    }

    /// Create a consensus context suitable for genesis blocks and tests.
    pub fn genesis_context() -> ConsensusContext {
        use commonware_cryptography::{Signer as _, ed25519, sha256};
        let leader = ed25519::PrivateKey::from_seed(0).public_key();
        ConsensusContext {
            round: Round::new(Epoch::new(0), View::new(0)),
            leader,
            parent: (View::new(0), sha256::Digest([0u8; 32])),
        }
    }

    /// Attach a DKG reshare payload without touching other fields.
    pub fn with_payload(mut self, payload: DkgPayload) -> Self {
        self.payload = Some(payload);
        self
    }
}

fn digest_for_block_id(id: &BlockId) -> crate::ConsensusDigest {
    Sha256::hash(&[id.0.as_slice()])
}

impl Digestible for Block {
    type Digest = crate::ConsensusDigest;

    fn digest(&self) -> Self::Digest {
        digest_for_block_id(&self.id())
    }
}

impl Committable for Block {
    type Commitment = crate::ConsensusDigest;

    fn commitment(&self) -> Self::Commitment {
        digest_for_block_id(&self.id())
    }
}

impl commonware_consensus::Heightable for Block {
    fn height(&self) -> commonware_consensus::types::Height {
        commonware_consensus::types::Height::new(self.height)
    }
}

impl commonware_consensus::Block for Block {
    fn parent(&self) -> Self::Digest {
        digest_for_block_id(&self.parent)
    }
}

impl commonware_consensus::CertifiableBlock for Block {
    type Context = ConsensusContext;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }
}

impl Write for Block {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        self.parent.write(buf);
        self.height.write(buf);
        self.timestamp.write(buf);
        Idents::write_b256(&self.prevrandao, buf);
        self.state_root.write(buf);
        Idents::write_b256(&self.module_state_root, buf);
        self.txs.write(buf);
        if let Some(commitment) = &self.receipt_commitment {
            3_u8.write(buf);
            self.payload.write(buf);
            self.native_targets.write(buf);
            Idents::write_b256(commitment, buf);
        } else if let Some(targets) = &self.native_targets {
            2_u8.write(buf);
            self.payload.write(buf);
            targets.write(buf);
        } else {
            self.payload.write(buf);
        }
        self.db_targets.write(buf);
    }
}

impl EncodeSize for Block {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + self.timestamp.encode_size()
            + 32
            + self.state_root.encode_size()
            + 32
            + self.txs.encode_size()
            + if self.receipt_commitment.is_some() {
                1 + self.payload.encode_size() + self.native_targets.encode_size() + 32
            } else {
                self.payload.encode_size()
                    + self
                        .native_targets
                        .as_ref()
                        .map_or(0, |targets| 1 + targets.encode_size())
            }
            + self.db_targets.encode_size()
    }
}

impl Read for Block {
    type Cfg = BlockCfg;

    fn read_cfg(buf: &mut impl commonware_codec::Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let buf = &mut buf.take(crate::MAX_BLOCK_BYTES);
        let context = ConsensusContext::read(buf)?;
        let parent = BlockId::read(buf)?;
        let height = u64::read(buf)?;
        let timestamp = u64::read(buf)?;
        let prevrandao = Idents::read_b256(buf)?;
        let state_root = StateRoot::read(buf)?;
        let module_state_root = Idents::read_b256(buf)?;
        let txs = Vec::<Tx>::read_cfg(
            &mut (&mut *buf).take(crate::MAX_BLOCK_TX_BYTES),
            &(
                RangeCfg::new(0..=cfg.max_txs.min(crate::MAX_BLOCK_TXS)),
                cfg.tx,
            ),
        )?;
        // Tags 0 and 1 retain the original optional DKG payload encoding.
        let (payload, native_targets, receipt_commitment) = match u8::read(buf)? {
            0 => (None, None, None),
            1 => (
                Some(DkgPayload::read_cfg(buf, &DKG_PAYLOAD_CFG)?),
                None,
                None,
            ),
            2 => (
                Option::<DkgPayload>::read_cfg(buf, &DKG_PAYLOAD_CFG)?,
                Some(<[DbTarget; 4]>::read(buf)?),
                None,
            ),
            3 => (
                Option::<DkgPayload>::read_cfg(buf, &DKG_PAYLOAD_CFG)?,
                Option::<[DbTarget; 4]>::read(buf)?,
                Some(Idents::read_b256(buf)?),
            ),
            _ => return Err(CodecError::Invalid("Block", "unknown commitment encoding")),
        };
        let db_targets = DbTargets::read(buf)?;
        Ok(Self {
            context,
            parent,
            height,
            timestamp,
            prevrandao,
            state_root,
            module_state_root,
            txs,
            payload,
            db_targets,
            native_targets,
            receipt_commitment,
        })
    }
}

impl commonware_glue::dkg::ReshareBlock for Block {
    type Variant = DkgVariant;
    type PublicKey = ed25519::PublicKey;
    type Directory = DkgDirectory;

    fn payload(&self) -> Option<DkgPayload> {
        self.payload.clone()
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Block")
            .field("context", &self.context)
            .field("parent", &self.parent)
            .field("height", &self.height)
            .field("timestamp", &self.timestamp)
            .field("prevrandao", &self.prevrandao)
            .field("state_root", &self.state_root)
            .field("module_state_root", &self.module_state_root)
            .field("txs", &self.txs.len())
            .field("payload", &self.payload.is_some())
            .field("db_targets", &self.db_targets)
            .field("native_targets", &self.native_targets)
            .field("receipt_commitment", &self.receipt_commitment)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::Bytes;
    use commonware_codec::Decode;
    use commonware_cryptography::bls12381::dkg::feldman_desmedt::deal;
    use commonware_cryptography::bls12381::primitives::sharing::Mode;
    use commonware_cryptography::{Signer as _, ed25519};
    use commonware_glue::dkg::types::{EpochInfo, EpochOutcome};
    use commonware_utils::{N3f1, TestRng, ordered::Set, sequence::Unit};

    use super::*;

    #[test]
    fn block_transaction_count_respects_protocol_and_caller_limits() {
        let mut block = sample_block();
        block.txs = vec![block.txs[0].clone(); crate::MAX_BLOCK_TXS];
        let mut cfg = default_block_cfg();
        cfg.max_txs = usize::MAX;
        assert!(block.fits_wire_limits());
        assert_eq!(Block::decode_cfg(block.encode(), &cfg).unwrap(), block);
        cfg.max_txs = crate::MAX_BLOCK_TXS - 1;
        assert!(Block::decode_cfg(block.encode(), &cfg).is_err());
        cfg.max_txs = usize::MAX;
        block.txs.push(block.txs[0].clone());
        assert!(!block.fits_wire_limits());
        assert!(Block::decode_cfg(block.encode(), &cfg).is_err());
    }

    #[test]
    fn large_block_transaction_budget() {
        let cfg = BlockCfg {
            max_txs: crate::MAX_BLOCK_TXS,
            tx: TxCfg {
                max_tx_bytes: crate::MAX_TX_BYTES,
            },
        };
        let mut block = sample_block();
        block.txs = vec![Tx::new(vec![255; crate::MAX_TX_BYTES].into())];
        assert_eq!(Block::decode_cfg(block.encode(), &cfg).unwrap(), block);
        block.txs.push(block.txs[0].clone());
        assert!(Block::decode_cfg(block.encode(), &cfg).is_err());
        block.txs = vec![Tx::new(vec![255; crate::MAX_TX_BYTES + 1].into())];
        assert!(Block::decode_cfg(block.encode(), &cfg).is_err());
    }

    fn default_block_cfg() -> BlockCfg {
        BlockCfg {
            max_txs: 100,
            tx: TxCfg {
                max_tx_bytes: 131072,
            },
        }
    }

    fn sample_block() -> Block {
        Block {
            context: Block::genesis_context(),
            parent: BlockId(B256::repeat_byte(0x01)),
            height: 42,
            timestamp: 1_700_000_000,
            prevrandao: B256::repeat_byte(0xab),
            state_root: StateRoot(B256::repeat_byte(0xcd)),
            module_state_root: B256::ZERO,
            txs: vec![Tx::new(Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]))],
            payload: None,
            native_targets: None,
            receipt_commitment: None,
            db_targets: crate::DbTargets::default(),
        }
    }

    fn sample_epoch_info() -> EpochInfo<DkgVariant, ed25519::PublicKey, DkgDirectory> {
        let players = Set::from_iter_dedup(
            (0..4).map(|seed| ed25519::PrivateKey::from_seed(seed).public_key()),
        );
        let (output, _) =
            deal::<DkgVariant, _, N3f1>(TestRng::new(1), Mode::NonZeroCounter, players.clone())
                .expect("trusted deal");
        EpochInfo {
            outcome: EpochOutcome::Success,
            epoch: Epoch::new(1),
            output,
            players: players.clone(),
            next_players: players,
            directory: Unit,
        }
    }

    fn sample_block_with_payload() -> Block {
        sample_block().with_payload(DkgPayload::EpochInfo(sample_epoch_info()))
    }

    #[test]
    fn block_id_is_deterministic() {
        let block = sample_block();
        let id1 = block.id();
        let id2 = block.id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn block_id_differs_by_height() {
        let block1 = sample_block();
        let mut block2 = sample_block();
        block2.height = 100;
        assert_ne!(block1.id(), block2.id());
    }

    #[test]
    fn block_id_differs_by_parent() {
        let block1 = sample_block();
        let mut block2 = sample_block();
        block2.parent = BlockId(B256::repeat_byte(0xff));
        assert_ne!(block1.id(), block2.id());
    }

    #[test]
    fn block_id_differs_by_txs() {
        let block1 = sample_block();
        let mut block2 = sample_block();
        block2.txs = vec![];
        assert_ne!(block1.id(), block2.id());
    }

    #[test]
    fn block_commitment_matches_digest() {
        let block = sample_block();
        assert_eq!(block.commitment(), block.digest());
    }

    #[test]
    fn block_encode_decode_roundtrip() {
        let block = sample_block();
        let encoded = block.encode();
        let decoded = Block::decode_cfg(encoded, &default_block_cfg()).expect("decode");
        assert_eq!(block, decoded);
    }

    #[test]
    fn block_encode_size_matches_encoded() {
        let block = sample_block();
        assert_eq!(block.encode_size(), block.encode().len());
    }

    #[test]
    fn native_commitment_encoding_is_tagged_bounded_and_streamable() {
        for legacy in [sample_block(), sample_block_with_payload()] {
            let original = legacy.encode();
            let offset =
                original.len() - legacy.db_targets.encode_size() - legacy.payload.encode_size();
            assert_eq!(original[offset], u8::from(legacy.payload.is_some()));
            let mut native = legacy.clone();
            native.native_targets = Some(std::array::from_fn(|i| DbTarget {
                root: commonware_cryptography::sha256::Digest::from([u8::try_from(i).unwrap(); 32]),
                floor: 0,
                tip: 1,
            }));
            let bytes = native.encode();
            assert_eq!(bytes[offset], 2);
            assert_eq!(bytes.len(), native.encode_size());
            assert_eq!(
                Block::decode_cfg(bytes.clone(), &default_block_cfg()).unwrap(),
                native
            );
            assert_ne!(native.id(), legacy.id());
            let mut changed = native.clone();
            changed.native_targets.as_mut().unwrap()[3].tip += 1;
            assert_ne!(native.id(), changed.id());
            let mut concatenated = bytes.to_vec();
            concatenated.extend_from_slice(&original);
            let mut input = commonware_codec::Copying(concatenated.as_slice());
            assert_eq!(
                Block::read_cfg(&mut input, &default_block_cfg()).unwrap(),
                native
            );
            assert_eq!(
                Block::read_cfg(&mut input, &default_block_cfg()).unwrap(),
                legacy
            );
            assert!(input.0.is_empty());
            let mut invalid = bytes.to_vec();
            invalid[offset] = 4;
            assert!(
                Block::decode_cfg(
                    commonware_codec::Copying(invalid.as_slice()),
                    &default_block_cfg()
                )
                .is_err()
            );
            for end in offset..bytes.len() {
                assert!(
                    Block::decode_cfg(
                        commonware_codec::Copying(&bytes[..end]),
                        &default_block_cfg()
                    )
                    .is_err()
                );
            }
            native.native_targets = None;
            assert_eq!(native.encode(), original);
        }
    }

    #[test]
    fn receipt_commitment_is_canonical_bound_and_streamable() {
        for legacy in [sample_block(), sample_block_with_payload()] {
            for targets in [None, Some([DbTarget::default(); 4])] {
                let offset = legacy.encode_size()
                    - legacy.db_targets.encode_size()
                    - legacy.payload.encode_size();
                let mut block = legacy.clone();
                block.native_targets = targets;
                let previous = block.encode();
                block.receipt_commitment = Some(B256::repeat_byte(7));
                let encoded = block.encode();
                assert_eq!(encoded[offset], 3);
                assert_eq!(encoded.len(), block.encode_size());
                assert_eq!(
                    Block::decode_cfg(encoded.clone(), &default_block_cfg()).unwrap(),
                    block
                );
                let mut changed = block.clone();
                changed.receipt_commitment = Some(B256::repeat_byte(8));
                assert_ne!(block.id(), changed.id());
                let mut concatenated = encoded.to_vec();
                concatenated.extend_from_slice(&previous);
                let mut input = commonware_codec::Copying(concatenated.as_slice());
                assert_eq!(
                    Block::read_cfg(&mut input, &default_block_cfg()).unwrap(),
                    block
                );
                block.receipt_commitment = None;
                assert_eq!(block.encode(), previous);
                assert_eq!(
                    Block::read_cfg(&mut input, &default_block_cfg()).unwrap(),
                    block
                );
                assert!(input.0.is_empty());
                for end in offset..encoded.len() {
                    assert!(
                        Block::decode_cfg(
                            commonware_codec::Copying(&encoded[..end]),
                            &default_block_cfg()
                        )
                        .is_err()
                    );
                }
            }
        }
    }

    #[test]
    fn empty_block_roundtrip() {
        let block = Block {
            context: Block::genesis_context(),
            parent: BlockId(B256::ZERO),
            height: 0,
            timestamp: 0,
            prevrandao: B256::ZERO,
            state_root: StateRoot(B256::ZERO),
            module_state_root: B256::ZERO,
            txs: vec![],
            payload: None,
            native_targets: None,
            receipt_commitment: None,
            db_targets: crate::DbTargets::default(),
        };
        let encoded = block.encode();
        let decoded = Block::decode_cfg(encoded, &default_block_cfg()).expect("decode");
        assert_eq!(block, decoded);
    }

    #[test]
    fn block_with_payload_roundtrip() {
        let block = sample_block_with_payload();
        let encoded = block.encode();
        let decoded = Block::decode_cfg(encoded.clone(), &default_block_cfg()).expect("decode");
        assert_eq!(block, decoded);
        assert_eq!(decoded.id(), BlockId(keccak256(encoded)));
    }

    #[test]
    fn payload_changes_block_id() {
        let plain = sample_block();
        let with_payload = sample_block_with_payload();
        assert_ne!(plain.id(), with_payload.id());
    }

    #[test]
    fn reshare_block_payload_accessor() {
        use commonware_glue::dkg::ReshareBlock as _;

        let plain = sample_block();
        assert!(plain.payload().is_none());
        let with_payload = sample_block_with_payload();
        assert!(with_payload.payload().is_some());
        assert_eq!(
            with_payload.payload().unwrap().encode(),
            with_payload.payload.as_ref().unwrap().encode()
        );
    }
    #[test]
    fn payload_encoding_is_canonical() {
        let block = sample_block_with_payload();
        let encoded = block.encode();
        let decoded = Block::decode_cfg(encoded.clone(), &default_block_cfg()).expect("decode");
        assert_eq!(decoded.encode(), encoded);
    }

    #[test]
    fn payload_rejects_non_canonical_presence_byte() {
        let block = sample_block_with_payload();
        let mut encoded = block.encode().to_vec();
        let payload_start =
            encoded.len() - block.db_targets.encode_size() - block.payload.encode_size();
        encoded[payload_start] = 4;
        assert!(
            Block::decode_cfg(
                commonware_codec::Copying(encoded.as_slice()),
                &default_block_cfg()
            )
            .is_err()
        );
    }

    #[test]
    fn block_heightable() {
        use commonware_consensus::Heightable as _;
        let block = sample_block();
        assert_eq!(block.height().get(), 42);
    }

    #[test]
    fn block_parent_commitment() {
        use commonware_consensus::Block as _;
        let block = sample_block();
        let parent_commitment = block.parent();
        let expected = digest_for_block_id(&block.parent);
        assert_eq!(parent_commitment, expected);
    }
}
