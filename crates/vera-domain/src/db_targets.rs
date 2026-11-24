//! The sync target of one partition, carried by every block.
//!
//! The stateful actor checks a block's merkleized batches against these
//! targets, and state sync uses them to know which operation range and root
//! each partition must reach.

use bytes::BufMut;
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};

use commonware_cryptography::sha256::Digest;

use crate::ConsensusDigest;

/// Root and operation range of one QMDB partition after a block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DbTarget {
    /// Root of the partition's authenticated log.
    pub root: ConsensusDigest,
    /// First live operation (inactivity floor).
    pub floor: u64,
    /// Size of the log after the block.
    pub tip: u64,
}

impl Default for DbTarget {
    fn default() -> Self {
        Self {
            root: Digest([0u8; 32]),
            floor: 0,
            tip: 0,
        }
    }
}

impl Write for DbTarget {
    fn write(&self, buf: &mut impl BufMut) {
        self.root.write(buf);
        self.floor.write(buf);
        self.tip.write(buf);
    }
}

impl FixedSize for DbTarget {
    const SIZE: usize = ConsensusDigest::SIZE + u64::SIZE + u64::SIZE;
}

impl Read for DbTarget {
    type Cfg = ();

    fn read_cfg(buf: &mut impl commonware_codec::Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            root: ConsensusDigest::read(buf)?,
            floor: u64::read(buf)?,
            tip: u64::read(buf)?,
        })
    }
}
