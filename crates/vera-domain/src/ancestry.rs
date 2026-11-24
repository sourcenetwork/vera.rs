//! A block's commitment to its ancestors.
//!
//! The block at height `h` carries the peaks of a Merkle mountain range over
//! the identifiers of the blocks at heights `0..h`, the genesis block first.
//! A block's ancestry follows from its parent's by appending the parent's
//! identifier, and an [`AncestryProof`] shows that the block at one height is
//! an ancestor with a number of digests logarithmic in the chain's length.
//! The structure, hashing and proofs are Commonware's.

use bytes::BufMut;
use commonware_codec::{
    Decode as _, Encode as _, EncodeSize, Error as CodecError, RangeCfg, Read, Write,
};
use commonware_cryptography::Sha256;
use commonware_storage::merkle::{
    Bagging, MAX_PROOF_DIGESTS_PER_ELEMENT,
    hasher::{Hasher as _, Standard},
    mmr::{Location, Proof, mem::Mmr},
};

use crate::{BlockId, ConsensusDigest};

/// Most peaks a mountain range over 64-bit heights can have.
const MAX_PEAKS: usize = 64;

/// Longest encoding of an [`AncestryProof`], in bytes.
pub const MAX_ANCESTRY_PROOF_BYTES: usize = 32 * MAX_PROOF_DIGESTS_PER_ELEMENT + 32;

const fn hasher() -> Standard<Sha256> {
    Standard::new(Bagging::ForwardFold)
}

/// Why an ancestry or a proof of it cannot be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AncestryError {
    /// The peaks are not those of a range over the block's ancestors.
    #[error("ancestry does not have the peaks of {0} ancestors")]
    Peaks(u64),
    /// The ancestor lies below the height the blocks at hand start at, or at or above the block.
    #[error("no ancestor at height {ancestor} can be proven from blocks {from}..{to}")]
    Range {
        /// Height of the ancestor asked for.
        ancestor: u64,
        /// Height of the first block at hand.
        from: u64,
        /// Height of the block the proof is for.
        to: u64,
    },
}

/// The peaks of the mountain range over a block's ancestors, oldest first.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ancestry(Vec<ConsensusDigest>);

impl Ancestry {
    /// An ancestry with the given peaks, oldest first.
    #[must_use]
    pub const fn from_peaks(peaks: Vec<ConsensusDigest>) -> Self {
        Self(peaks)
    }

    /// The ancestry of a genesis block, which has no ancestor.
    #[must_use]
    pub const fn genesis() -> Self {
        Self(Vec::new())
    }

    /// The peaks, oldest first.
    #[must_use]
    pub fn peaks(&self) -> &[ConsensusDigest] {
        &self.0
    }

    /// Whether this can be the ancestry of a block at `height`: a range over
    /// `height` leaves has one peak for each set bit of `height`.
    #[must_use]
    pub const fn fits(&self, height: u64) -> bool {
        self.0.len() == height.count_ones() as usize
    }

    fn range(&self, height: u64) -> Result<Mmr<ConsensusDigest>, AncestryError> {
        Mmr::from_components(Vec::new(), Location::new(height), self.0.clone())
            .map_err(|_| AncestryError::Peaks(height))
    }

    /// The ancestry of the child of the block at `height` with identifier
    /// `id`, when this is that block's ancestry.
    pub fn extended(&self, height: u64, id: &BlockId) -> Result<Self, AncestryError> {
        let mut range = self.range(height)?;
        append(&mut range, core::slice::from_ref(id));
        Ok(Self(peaks(&range)))
    }

    /// The root an [`AncestryProof`] verifies against, for a block at `height`.
    pub fn root(&self, height: u64) -> Result<ConsensusDigest, AncestryError> {
        if !self.fits(height) {
            return Err(AncestryError::Peaks(height));
        }
        hasher()
            .root(Location::new(height), 0, self.0.iter())
            .map_err(|_| AncestryError::Peaks(height))
    }

    /// Prove that the block at height `ancestor` is an ancestor of the block
    /// at height `from + ids.len()`, when this is the ancestry of the block at
    /// `from` and `ids` are the identifiers of the blocks from `from` up to,
    /// and not including, the block the proof is for.
    pub fn prove(
        &self,
        from: u64,
        ids: &[BlockId],
        ancestor: u64,
    ) -> Result<AncestryProof, AncestryError> {
        let to = from.saturating_add(ids.len() as u64);
        let out_of_range = AncestryError::Range { ancestor, from, to };
        if ancestor < from || ancestor >= to {
            return Err(out_of_range);
        }
        let mut range = self.range(from)?;
        append(&mut range, ids);
        range
            .proof(&hasher(), Location::new(ancestor), 0)
            .map(AncestryProof)
            .map_err(|_| out_of_range)
    }

    /// Whether `proof` shows that the block with identifier `id` at height
    /// `ancestor` is an ancestor of the block at `height` with this ancestry.
    #[must_use]
    pub fn includes(
        &self,
        height: u64,
        ancestor: u64,
        id: &BlockId,
        proof: &AncestryProof,
    ) -> bool {
        let Ok(root) = self.root(height) else {
            return false;
        };
        ancestor < height
            && proof.0.leaves == Location::new(height)
            && proof.0.verify_element_inclusion(
                &hasher(),
                id.0.as_slice(),
                Location::new(ancestor),
                &root,
            )
    }
}

fn append(range: &mut Mmr<ConsensusDigest>, ids: &[BlockId]) {
    let hasher = hasher();
    let mut batch = range.new_batch();
    for id in ids {
        batch = batch.add(&hasher, id.0.as_slice());
    }
    let batch = batch.merkleize(range, &hasher);
    range
        .apply_batch(&batch)
        .expect("a batch applies to the range it was built on");
}

fn peaks(range: &Mmr<ConsensusDigest>) -> Vec<ConsensusDigest> {
    range
        .peak_iterator()
        .map(|(position, _)| range.get_node(position).expect("a range holds its peaks"))
        .collect()
}

impl Write for Ancestry {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl EncodeSize for Ancestry {
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }
}

impl Read for Ancestry {
    type Cfg = ();

    fn read_cfg(buf: &mut impl commonware_codec::Buf, (): &Self::Cfg) -> Result<Self, CodecError> {
        Vec::<ConsensusDigest>::read_cfg(buf, &(RangeCfg::new(0..=MAX_PEAKS), ())).map(Self)
    }
}

/// A proof that one block is an ancestor of another, checked with
/// [`Ancestry::includes`] or [`crate::Block::has_ancestor`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AncestryProof(Proof<ConsensusDigest>);

impl AncestryProof {
    /// Decode a proof, refusing one longer than [`MAX_ANCESTRY_PROOF_BYTES`].
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() > MAX_ANCESTRY_PROOF_BYTES {
            return Err(CodecError::Invalid("AncestryProof", "too long"));
        }
        let proof = Proof::<ConsensusDigest>::decode_cfg(
            commonware_codec::Copying(bytes),
            &MAX_PROOF_DIGESTS_PER_ELEMENT,
        )?;
        Ok(Self(proof))
    }

    /// The proof's encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }

    /// Number of digests the proof carries.
    #[must_use]
    pub fn digests(&self) -> usize {
        self.0.digests.len()
    }
}

impl serde::Serialize for AncestryProof {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("0x{}", hex::encode(self.encode())))
    }
}

impl<'de> serde::Deserialize<'de> for AncestryProof {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let text = String::deserialize(deserializer)?;
        if text.len() > 2 * MAX_ANCESTRY_PROOF_BYTES + 2 {
            return Err(D::Error::custom("ancestry proof is too long"));
        }
        let bytes =
            hex::decode(text.strip_prefix("0x").unwrap_or(&text)).map_err(D::Error::custom)?;
        Self::decode(&bytes).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;

    use super::*;

    fn id(height: u64) -> BlockId {
        BlockId(B256::left_padding_from(&height.to_be_bytes()))
    }

    /// The ancestry of the block at each height of a chain of `length` blocks.
    fn chain(length: u64) -> Vec<Ancestry> {
        let mut ancestries = vec![Ancestry::genesis()];
        for height in 0..length - 1 {
            let next = ancestries[height as usize]
                .extended(height, &id(height))
                .unwrap();
            ancestries.push(next);
        }
        ancestries
    }

    #[test]
    fn an_ancestry_has_one_peak_for_each_set_bit_of_the_height() {
        for (height, ancestry) in chain(70).iter().enumerate() {
            assert!(ancestry.fits(height as u64), "height {height}");
            assert_eq!(ancestry.peaks().len(), height.count_ones() as usize);
            ancestry.root(height as u64).unwrap();
        }
        assert_eq!(
            crate::testing::ancestry(1).extended(3, &id(3)),
            Err(AncestryError::Peaks(3))
        );
        assert_eq!(Ancestry::genesis().root(1), Err(AncestryError::Peaks(1)));
    }

    #[test]
    fn every_ancestor_is_proven_from_the_blocks_since_it() {
        let chain = chain(41);
        let ids: Vec<_> = (0..40).map(id).collect();
        let tip = &chain[40];
        for ancestor in 0..40u64 {
            // Only the ancestor's own block and the identifiers after it are needed.
            let proof = chain[ancestor as usize]
                .prove(ancestor, &ids[ancestor as usize..], ancestor)
                .unwrap();
            assert!(tip.includes(40, ancestor, &id(ancestor), &proof));
            assert!(!tip.includes(40, ancestor, &id(ancestor + 1), &proof));
            assert!(!tip.includes(40, (ancestor + 1) % 40, &id(ancestor), &proof));
            assert!(!chain[39].includes(39, ancestor, &id(ancestor), &proof));
            assert_eq!(AncestryProof::decode(&proof.encode()).unwrap(), proof);
            let json = serde_json::to_string(&proof).unwrap();
            assert_eq!(serde_json::from_str::<AncestryProof>(&json).unwrap(), proof);
        }
    }

    #[test]
    fn another_history_does_not_include_the_ancestor() {
        let honest = chain(21);
        let ids: Vec<_> = (0..20).map(id).collect();
        let proof = honest[10].prove(10, &ids[10..], 10).unwrap();
        assert!(honest[20].includes(20, 10, &id(10), &proof));

        // A history that left the honest one at height 10.
        let mut forked = honest[10].clone();
        let mut fork_ids = Vec::new();
        for height in 10..20u64 {
            let block = BlockId(B256::repeat_byte(height as u8));
            forked = forked.extended(height, &block).unwrap();
            fork_ids.push(block);
        }
        assert!(!forked.includes(20, 10, &id(10), &proof));
        let own = honest[10].prove(10, &fork_ids, 10).unwrap();
        assert!(forked.includes(20, 10, &fork_ids[0], &own));
        assert!(!forked.includes(20, 10, &id(10), &own));
        // Both histories still include the blocks they share.
        let shared = honest[5]
            .prove(5, &[&ids[5..10], &fork_ids[..]].concat(), 5)
            .unwrap();
        assert!(forked.includes(20, 5, &id(5), &shared));
    }

    #[test]
    fn a_proof_is_refused_outside_the_blocks_at_hand_and_when_too_long() {
        let chain = chain(9);
        let ids: Vec<_> = (0..8).map(id).collect();
        assert_eq!(
            chain[4].prove(4, &ids[4..], 3),
            Err(AncestryError::Range {
                ancestor: 3,
                from: 4,
                to: 8
            })
        );
        assert!(chain[4].prove(4, &ids[4..], 8).is_err());
        assert!(AncestryProof::decode(&vec![0; MAX_ANCESTRY_PROOF_BYTES + 1]).is_err());
        let mut trailing = chain[4].prove(4, &ids[4..], 4).unwrap().encode();
        trailing.push(0);
        assert!(AncestryProof::decode(&trailing).is_err());
    }
}
