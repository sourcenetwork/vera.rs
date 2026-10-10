use super::*;
use alloy_primitives::B256;
use commonware_codec::{EncodeSize, Error, Read, ReadExt as _, Write};
use commonware_cryptography::sha256::Digest;
use commonware_storage::{
    merkle::{Location, MAX_PROOF_DIGESTS_PER_ELEMENT, Proof},
    qmdb::{self, current::proof::OpsRootWitness, sync::Target},
};
use commonware_utils::{bitmap::Prunable, non_empty_range};

/// Evidence deriving native log targets from one trusted combined current-state root.
#[derive(Clone, Debug)]
pub struct SyncProof([PartitionProof; 4]);

#[derive(Clone, Debug)]
struct PartitionProof {
    ops_root: Digest,
    witness: OpsRootWitness<mmr::Family, Digest>,
    proof: Proof<mmr::Family, Digest>,
    commit: p2p::WireOperation,
}

impl SyncProof {
    /// Capture the selected state while holding read locks over all four partitions.
    /// Acquisition releases partial guards before waiting on a busy partition.
    /// A stale selection fails instead of returning evidence for a different revision.
    pub async fn capture(set: &NativeStateSet, expected: B256) -> Result<Self, BackendError> {
        let [a, b, h, n] = super::read_partitions([&set.0, &set.1, &set.2, &set.3]).await;
        if combine_module_roots(&[a.root().0, b.root().0, h.root().0, n.root().0]) != expected {
            return Err(BackendError::InvalidSyncProof(
                "selected module root changed",
            ));
        }
        let (a, b, h, n) = futures::try_join!(
            PartitionProof::capture(&a),
            PartitionProof::capture(&b),
            PartitionProof::capture(&h),
            PartitionProof::capture(&n),
        )?;
        Ok(Self([a, b, h, n]))
    }

    /// Verify every terminal commit and derive targets in ACP, bulletin, vera, sequence order.
    /// The caller must authenticate `expected` independently, for example through finality.
    pub fn verify(&self, expected: B256) -> Result<NativeTargets, BackendError> {
        let roots = self
            .0
            .each_ref()
            .map(|p| p.witness.root::<Sha256>(&p.ops_root).0);
        if combine_module_roots(&roots) != expected {
            return Err(BackendError::InvalidSyncProof("module root mismatch"));
        }
        Ok((
            self.0[0].target()?,
            self.0[1].target()?,
            self.0[2].target()?,
            self.0[3].target()?,
        ))
    }
}

impl PartitionProof {
    async fn capture(db: &NativeDb) -> Result<Self, BackendError> {
        let tip = db.bounds().end;
        let last = tip
            .checked_sub(1)
            .ok_or(BackendError::InvalidSyncProof("missing commit"))?;
        let witness = db
            .ops_root_witness()
            .await
            .map_err(|e| BackendError::Storage(e.to_string()))?;
        let (proof, mut operations) = db
            .ops_historical_proof(tip, last, NZU64!(1))
            .await
            .map_err(|e| BackendError::Storage(e.to_string()))?;
        let commit = operations
            .pop()
            .ok_or(BackendError::InvalidSyncProof("missing commit"))?;
        Ok(Self {
            ops_root: db.ops_root(),
            witness,
            proof,
            commit: crate::p2p::WireOperation(commit),
        })
    }

    fn target(&self) -> Result<Target<mmr::Family, Digest>, BackendError> {
        let tip = self.proof.leaves;
        let last = tip
            .checked_sub(1)
            .ok_or(BackendError::InvalidSyncProof("missing commit"))?;
        if !qmdb::verify_proof::<Sha256, _, _>(
            &self.proof,
            last,
            std::slice::from_ref(&self.commit.0),
            &self.ops_root,
        ) {
            return Err(BackendError::InvalidSyncProof("terminal commit proof"));
        }
        let Operation::CommitFloor(_, floor) = &self.commit.0 else {
            return Err(BackendError::InvalidSyncProof(
                "log does not end in a commit",
            ));
        };
        if *floor > last {
            return Err(BackendError::InvalidSyncProof("commit floor exceeds log"));
        }
        // MMR sync starts at the inactivity floor rounded down to a whole bitmap chunk.
        let chunk = Prunable::<32>::CHUNK_SIZE_BITS;
        let start = Location::new(**floor / chunk * chunk);
        Ok(Target::new(self.ops_root, non_empty_range!(start, tip)))
    }
}

impl Write for PartitionProof {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.ops_root.write(buf);
        self.witness.write(buf);
        self.proof.write(buf);
        self.commit.write(buf);
    }
}

impl EncodeSize for PartitionProof {
    fn encode_size(&self) -> usize {
        self.ops_root.encode_size()
            + self.witness.encode_size()
            + self.proof.encode_size()
            + self.commit.encode_size()
    }
}

impl Read for PartitionProof {
    type Cfg = ();
    fn read_cfg(buf: &mut impl commonware_codec::Buf, _: &()) -> Result<Self, Error> {
        Ok(Self {
            ops_root: Digest::read(buf)?,
            witness: OpsRootWitness::read(buf)?,
            proof: Proof::read_cfg(buf, &MAX_PROOF_DIGESTS_PER_ELEMENT)?,
            commit: p2p::WireOperation::read(buf)?,
        })
    }
}

impl Write for SyncProof {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.0.write(buf);
    }
}

impl EncodeSize for SyncProof {
    fn encode_size(&self) -> usize {
        self.0.iter().map(EncodeSize::encode_size).sum()
    }
}

impl Read for SyncProof {
    type Cfg = ();
    fn read_cfg(buf: &mut impl commonware_codec::Buf, _: &()) -> Result<Self, Error> {
        Ok(Self(<[PartitionProof; 4]>::read(buf)?))
    }
}

#[cfg(test)]
mod tests;
