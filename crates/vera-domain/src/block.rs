//! Block types

use alloy_primitives::{B256, keccak256};
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

use crate::{
    Ancestry, AncestryProof, BlockId, ConsensusContext, DbTarget, Idents, Tx, TxCfg,
    UnsupportedVersion,
};

/// Version of the block encoding, written as a block's first byte and covered
/// by its identifier. A block carrying any other version is refused on decode.
pub const BLOCK_FORMAT_VERSION: u8 = 2;

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
    /// Commitment to the identifiers of every ancestor, the genesis block first.
    pub ancestry: Ancestry,
    /// Wall-clock timestamp (unix seconds), set by proposer.
    pub timestamp: u64,
    /// Term of the device that proposed the block. It never decreases along
    /// a chain; a switch of the active device raises it.
    pub term: u64,
    /// Module state root (combined hash of ACP, Bulletin, Vera, NativeNonce state).
    pub module_state_root: B256,
    /// Transactions included in the block.
    pub txs: Vec<Tx>,
    /// Optional DKG reshare payload (dealer log or next-epoch info).
    pub payload: Option<DkgPayload>,
    /// Operation-log targets of the ACP, bulletin, vera and sequence
    /// partitions after this block, in that order.
    pub native_targets: [DbTarget; 4],
    /// Commitment to ordered execution receipts and the execution gas limit.
    pub receipt_commitment: B256,
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

    /// Whether `proof` shows that the block with identifier `id` at height
    /// `height` is an ancestor of this block.
    #[must_use]
    pub fn has_ancestor(&self, height: u64, id: &BlockId, proof: &AncestryProof) -> bool {
        self.ancestry.includes(self.height, height, id, proof)
    }

    /// Whether this block's ancestry is that of a child of `parent`.
    #[must_use]
    pub fn extends_ancestry(&self, parent: &Self) -> bool {
        self.height == parent.height.wrapping_add(1)
            && parent
                .ancestry
                .extended(parent.height, &parent.id())
                .is_ok_and(|ancestry| ancestry == self.ancestry)
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

impl BlockId {
    /// The consensus digest of the block this identifier names.
    pub fn digest(&self) -> crate::ConsensusDigest {
        Sha256::hash(&[self.0.as_slice()])
    }
}

impl Digestible for Block {
    type Digest = crate::ConsensusDigest;

    fn digest(&self) -> Self::Digest {
        self.id().digest()
    }
}

impl Committable for Block {
    type Commitment = crate::ConsensusDigest;

    fn commitment(&self) -> Self::Commitment {
        self.id().digest()
    }
}

impl commonware_consensus::Heightable for Block {
    fn height(&self) -> commonware_consensus::types::Height {
        commonware_consensus::types::Height::new(self.height)
    }
}

impl commonware_consensus::Block for Block {
    fn parent(&self) -> Self::Digest {
        self.parent.digest()
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
        BLOCK_FORMAT_VERSION.write(buf);
        self.context.write(buf);
        self.parent.write(buf);
        self.height.write(buf);
        self.ancestry.write(buf);
        self.timestamp.write(buf);
        self.term.write(buf);
        Idents::write_b256(&self.module_state_root, buf);
        self.txs.write(buf);
        self.payload.write(buf);
        self.native_targets.write(buf);
        Idents::write_b256(&self.receipt_commitment, buf);
    }
}

impl EncodeSize for Block {
    fn encode_size(&self) -> usize {
        BLOCK_FORMAT_VERSION.encode_size()
            + self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + self.ancestry.encode_size()
            + self.timestamp.encode_size()
            + self.term.encode_size()
            + 32
            + self.txs.encode_size()
            + self.payload.encode_size()
            + self.native_targets.encode_size()
            + 32
    }
}

impl Read for Block {
    type Cfg = BlockCfg;

    fn read_cfg(buf: &mut impl commonware_codec::Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let buf = &mut buf.take(crate::MAX_BLOCK_BYTES);
        UnsupportedVersion::check("block format", u8::read(buf)?, BLOCK_FORMAT_VERSION)
            .map_err(|error| CodecError::Wrapped("Block", Box::new(error)))?;
        let context = ConsensusContext::read(buf)?;
        let parent = BlockId::read(buf)?;
        let height = u64::read(buf)?;
        let ancestry = Ancestry::read(buf)?;
        if !ancestry.fits(height) {
            return Err(CodecError::Invalid(
                "Block",
                "ancestry does not fit the height",
            ));
        }
        let timestamp = u64::read(buf)?;
        let term = u64::read(buf)?;
        let module_state_root = Idents::read_b256(buf)?;
        let txs = Vec::<Tx>::read_cfg(
            &mut (&mut *buf).take(crate::MAX_BLOCK_TX_BYTES),
            &(
                RangeCfg::new(0..=cfg.max_txs.min(crate::MAX_BLOCK_TXS)),
                cfg.tx,
            ),
        )?;
        let payload = Option::<DkgPayload>::read_cfg(buf, &DKG_PAYLOAD_CFG)?;
        let native_targets = <[DbTarget; 4]>::read(buf)?;
        let receipt_commitment = Idents::read_b256(buf)?;
        Ok(Self {
            context,
            parent,
            height,
            ancestry,
            timestamp,
            term,
            module_state_root,
            txs,
            payload,
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
            .field("ancestry", &self.ancestry.peaks().len())
            .field("timestamp", &self.timestamp)
            .field("term", &self.term)
            .field("module_state_root", &self.module_state_root)
            .field("txs", &self.txs.len())
            .field("payload", &self.payload.is_some())
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
            ancestry: crate::testing::ancestry(42),
            timestamp: 1_700_000_000,
            term: 0,
            module_state_root: B256::ZERO,
            txs: vec![Tx::new(Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]))],
            payload: None,
            native_targets: [DbTarget::default(); 4],
            receipt_commitment: B256::repeat_byte(7),
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
    fn the_term_is_encoded_and_changes_the_block_id() {
        let block = sample_block();
        let mut later = sample_block();
        later.term = 7;
        assert_ne!(block.id(), later.id());
        assert_eq!(later.encode_size(), later.encode().len());
        let decoded = Block::decode_cfg(later.encode(), &default_block_cfg()).unwrap();
        assert_eq!(decoded.term, 7);
        assert_eq!(decoded, later);
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
    fn the_format_version_leads_the_encoding_and_changes_the_block_id() {
        let block = sample_block();
        let encoded = block.encode();
        assert_eq!(encoded[0], BLOCK_FORMAT_VERSION);
        let mut later = encoded.to_vec();
        later[0] = BLOCK_FORMAT_VERSION + 1;
        assert_ne!(BlockId(keccak256(&later)), block.id());
    }

    #[test]
    fn another_format_version_is_refused_with_a_typed_error() {
        let encoded = sample_block().encode();
        for found in [0, BLOCK_FORMAT_VERSION + 1, u8::MAX] {
            let mut other = encoded.to_vec();
            other[0] = found;
            let error = Block::decode_cfg(
                commonware_codec::Copying(other.as_slice()),
                &default_block_cfg(),
            )
            .unwrap_err();
            let CodecError::Wrapped("Block", source) = error else {
                panic!("expected a version refusal, got {error:?}");
            };
            assert_eq!(
                source.downcast_ref::<UnsupportedVersion>(),
                Some(&UnsupportedVersion {
                    format: "block format",
                    found,
                    supported: BLOCK_FORMAT_VERSION,
                })
            );
        }
    }

    #[test]
    fn block_encode_size_matches_encoded() {
        let block = sample_block();
        assert_eq!(block.encode_size(), block.encode().len());
    }

    #[test]
    fn commitments_are_bound_by_the_block_id_and_every_field_is_required() {
        for block in [sample_block(), sample_block_with_payload()] {
            let bytes = block.encode();
            assert_eq!(bytes.len(), block.encode_size());
            let mut retargeted = block.clone();
            retargeted.native_targets[3].tip += 1;
            assert_ne!(block.id(), retargeted.id());
            let mut recommitted = block.clone();
            recommitted.receipt_commitment = B256::repeat_byte(8);
            assert_ne!(block.id(), recommitted.id());

            let mut concatenated = bytes.to_vec();
            concatenated.extend_from_slice(&retargeted.encode());
            let mut input = commonware_codec::Copying(concatenated.as_slice());
            assert_eq!(
                Block::read_cfg(&mut input, &default_block_cfg()).unwrap(),
                block
            );
            assert_eq!(
                Block::read_cfg(&mut input, &default_block_cfg()).unwrap(),
                retargeted
            );
            assert!(input.0.is_empty());
            for end in 0..bytes.len() {
                assert!(
                    Block::decode_cfg(
                        commonware_codec::Copying(&bytes[..end]),
                        &default_block_cfg()
                    )
                    .is_err(),
                    "a block cut at {end} bytes must not decode"
                );
            }
        }
    }

    #[test]
    fn a_block_commits_to_its_ancestry_and_refuses_one_that_does_not_fit() {
        let genesis = Block {
            height: 0,
            ancestry: Ancestry::genesis(),
            ..sample_block()
        };
        let mut child = sample_block();
        child.height = 1;
        child.parent = genesis.id();
        child.ancestry = genesis.ancestry.extended(0, &genesis.id()).unwrap();
        assert!(child.extends_ancestry(&genesis));
        let decoded = Block::decode_cfg(child.encode(), &default_block_cfg()).unwrap();
        assert_eq!(decoded, child);
        assert_eq!(child.encode_size(), child.encode().len());

        let mut other = child.clone();
        other.ancestry = crate::testing::ancestry(1);
        assert_ne!(other.id(), child.id());
        assert!(!other.extends_ancestry(&genesis));
        let mut skipped = child.clone();
        skipped.height = 2;
        assert!(!skipped.extends_ancestry(&genesis));
        // One peak cannot be the ancestry of a block at height 2 or 3.
        assert!(Block::decode_cfg(skipped.encode(), &default_block_cfg()).is_ok());
        skipped.height = 3;
        assert!(Block::decode_cfg(skipped.encode(), &default_block_cfg()).is_err());

        let proof = genesis.ancestry.prove(0, &[genesis.id()], 0).unwrap();
        assert!(child.has_ancestor(0, &genesis.id(), &proof));
        assert!(!child.has_ancestor(0, &child.id(), &proof));
    }

    #[test]
    fn empty_block_roundtrip() {
        let block = Block {
            context: Block::genesis_context(),
            parent: BlockId(B256::ZERO),
            height: 0,
            ancestry: Ancestry::genesis(),
            timestamp: 0,
            term: 0,
            module_state_root: B256::ZERO,
            txs: vec![],
            payload: None,
            native_targets: [DbTarget::default(); 4],
            receipt_commitment: B256::repeat_byte(7),
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
            encoded.len() - 32 - block.native_targets.encode_size() - block.payload.encode_size();
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
        let expected = block.parent.digest();
        assert_eq!(parent_commitment, expected);
    }
}
