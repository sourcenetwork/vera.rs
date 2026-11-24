//! Self-contained BLS light blocks and standalone finality verification.

use alloy_evm::revm::primitives::{B256, keccak256};
use bytes::BufMut;
use commonware_codec::{
    Decode as _, DecodeExt as _, Encode as _, EncodeSize, Error as CodecError, RangeCfg, Read,
    Write,
};
use commonware_consensus::simplex::{
    scheme::bls12381_threshold::vrf,
    types::{Finalization, Proposal},
};
use commonware_cryptography::{
    Hasher as _, Sha256,
    bls12381::primitives::{
        sharing::{ModeVersion, Sharing},
        variant::{MinSig, Variant},
    },
};
use commonware_parallel::Sequential;
use commonware_utils::{NZU32, ordered::Set};
use serde::{Deserialize, Serialize};

use crate::{Block, BlockCfg, ConsensusDigest, PublicKey, TxCfg};

mod artifacts;
pub use artifacts::FinalizedArtifacts;

mod trust;
pub use trust::FinalityTrust;

/// Simplex namespace shared with validator nodes.
pub const LIGHT_BLOCK_NAMESPACE: &[u8] = b"_COMMONWARE_VERA_SIMPLEX";
/// Maximum participant count accepted from an untrusted light-block response.
pub const LIGHT_BLOCK_MAX_PARTICIPANTS: u32 = 64;
pub(crate) const LIGHT_BLOCK_MAX_TXS: usize = crate::MAX_BLOCK_TXS;
const LIGHT_BLOCK_MAX_TX_BYTES: usize = crate::MAX_TX_BYTES;
/// Maximum descendants linking a requested revision to a direct certificate.
pub const LIGHT_BLOCK_MAX_DESCENDANTS: usize = 64;
/// Combined decoded byte budget for blocks, finalization and epoch material.
pub const LIGHT_BLOCK_MAX_ARTIFACT_BYTES: usize = 2 * crate::MAX_BLOCK_BYTES + (1 << 20);
/// HTTP response budget including hex encoding and JSON metadata.
pub const LIGHT_BLOCK_RESPONSE_BYTES: usize = 2 * LIGHT_BLOCK_MAX_ARTIFACT_BYTES + (64 << 10);

/// The threshold VRF scheme whose recovered certificate finalizes Vera blocks.
pub type LightConsensusScheme = vrf::Scheme<PublicKey, MinSig>;

/// Public consensus identity, retained across resharing epochs.
pub type ConsensusPublicKey = <MinSig as Variant>::Public;

/// Public verifier material for one consensus epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochMaterial {
    /// Ordered ed25519 peer identities that received shares.
    pub participants: Set<PublicKey>,
    /// Public BLS group polynomial produced by DKG.
    pub sharing: Sharing<MinSig>,
}

impl EpochMaterial {
    /// Construct public material from a DKG output.
    #[must_use]
    pub const fn new(participants: Set<PublicKey>, sharing: Sharing<MinSig>) -> Self {
        Self {
            participants,
            sharing,
        }
    }

    /// Decode verifier material using the protocol's participant and sharing bounds.
    pub fn decode_bounded(bytes: &[u8]) -> Result<Self, LightBlockError> {
        Ok(Self::decode_cfg(
            commonware_codec::Copying(bytes),
            &(LIGHT_BLOCK_MAX_PARTICIPANTS, ModeVersion::v0()),
        )?)
    }
}

impl Write for EpochMaterial {
    fn write(&self, buf: &mut impl BufMut) {
        self.participants.write(buf);
        self.sharing.write(buf);
    }
}

impl EncodeSize for EpochMaterial {
    fn encode_size(&self) -> usize {
        self.participants.encode_size() + self.sharing.encode_size()
    }
}

impl Read for EpochMaterial {
    type Cfg = (u32, ModeVersion);

    fn read_cfg(
        buf: &mut impl commonware_codec::Buf,
        (max_participants, max_mode): &Self::Cfg,
    ) -> Result<Self, CodecError> {
        let participants =
            Set::read_cfg(buf, &(RangeCfg::new(1..=*max_participants as usize), ()))?;
        let sharing = Sharing::read_cfg(buf, &(NZU32!(*max_participants), *max_mode))?;
        Ok(Self {
            participants,
            sharing,
        })
    }
}

/// A finalized block and a direct or descendant certificate, checked against a trusted key.
///
/// Binary fields use `0x`-prefixed hex so the type remains directly usable over JSON-RPC.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightBlock {
    /// Block ID: keccak256 of the canonical Vera block encoding.
    pub block_hash: String,
    /// Parent block ID.
    pub parent_hash: String,
    /// Block height.
    pub height: u64,
    /// Unix timestamp in seconds.
    pub timestamp: u64,
    /// Combined native-module state root.
    pub module_state_root: String,
    /// Consensus epoch.
    pub epoch: u64,
    /// Consensus view.
    pub view: u64,
    /// Consensus view of the parent proposal.
    pub parent_view: u64,
    /// Canonical encoded [`Block`], which binds every displayed header field.
    pub block: String,
    /// Canonical descendants in ascending height order, ending at the certified block.
    /// Empty when the requested block has a direct certificate.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "read_descendants"
    )]
    pub descendants: Vec<String>,
    /// Canonical encoded `Finalization<LightConsensusScheme, ConsensusDigest>`.
    pub finalization: String,
    /// Canonical encoded [`EpochMaterial`].
    pub epoch_material: String,
}

fn read_descendants<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<String>, D::Error> {
    struct Descendants;
    impl<'de> serde::de::Visitor<'de> for Descendants {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "at most {LIGHT_BLOCK_MAX_DESCENDANTS} descendants")
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut values = Vec::new();
            while values.len() < LIGHT_BLOCK_MAX_DESCENDANTS {
                let Some(value) = seq.next_element()? else {
                    return Ok(values);
                };
                values.push(value);
            }
            if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom("too many light block descendants"));
            }
            Ok(values)
        }
    }
    deserializer.deserialize_seq(Descendants)
}

impl LightBlock {
    /// Construct the JSON-facing light block from canonical node artifacts.
    #[must_use]
    pub fn from_parts(block: &Block, finalization: &[u8], epoch_material: &[u8]) -> Self {
        Self::from_canonical(block, &block.encode(), finalization, epoch_material)
    }

    /// Construct from canonical block bytes retained alongside the finalization.
    ///
    /// The block hash is the digest of `block` as given, and the same bytes are
    /// published, so the two agree by construction.
    pub fn from_encoded_block(
        block: &[u8],
        finalization: &[u8],
        epoch_material: &[u8],
    ) -> Result<Self, LightBlockError> {
        let decoded = decode_block(block)?;
        Ok(Self::from_canonical(
            &decoded,
            block,
            finalization,
            epoch_material,
        ))
    }

    fn from_canonical(
        block: &Block,
        encoded: &[u8],
        finalization: &[u8],
        epoch_material: &[u8],
    ) -> Self {
        Self {
            block_hash: encode_hex(keccak256(encoded).as_slice()),
            parent_hash: encode_hex(block.parent.0.as_slice()),
            height: block.height,
            timestamp: block.timestamp,
            module_state_root: encode_hex(block.module_state_root.as_slice()),
            epoch: block.context.round.epoch().get(),
            view: block.context.round.view().get(),
            parent_view: block.context.parent.0.get(),
            block: encode_hex(encoded),
            descendants: Vec::new(),
            finalization: encode_hex(finalization),
            epoch_material: encode_hex(epoch_material),
        }
    }

    /// Decode the canonical artifacts after checking their count and size.
    pub fn artifacts(&self) -> Result<FinalizedArtifacts, LightBlockError> {
        self.check_artifact_limits()?;
        Ok(FinalizedArtifacts {
            block: decode_hex("block", &self.block)?,
            descendants: self
                .descendants
                .iter()
                .map(|value| decode_hex("descendant", value))
                .collect::<Result<_, _>>()?,
            finalization: decode_hex("finalization", &self.finalization)?,
            epoch_material: decode_hex("epoch_material", &self.epoch_material)?,
        })
    }

    /// Reject excessive artifact count or size before decoding untrusted hex.
    pub fn check_artifact_limits(&self) -> Result<(), LightBlockError> {
        if self.descendants.len() > LIGHT_BLOCK_MAX_DESCENDANTS {
            return Err(LightBlockError::LimitExceeded);
        }
        let mut remaining = LIGHT_BLOCK_MAX_ARTIFACT_BYTES * 2;
        for value in [&self.block, &self.finalization, &self.epoch_material]
            .into_iter()
            .chain(self.descendants.iter())
        {
            let digits = value.strip_prefix("0x").unwrap_or(value).len();
            remaining = remaining
                .checked_sub(digits)
                .ok_or(LightBlockError::LimitExceeded)?;
        }
        Ok(())
    }
}

/// Errors returned by [`verify_light_block`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LightBlockError {
    /// The proof exceeds the artifact byte or descendant count budget.
    #[error("light block proof exceeds artifact limits")]
    LimitExceeded,
    /// A descendant does not extend the preceding block at the next height.
    #[error("light block descendant ancestry is not contiguous")]
    AncestryMismatch,
    /// A JSON hex field could not be decoded.
    #[error("invalid {field} hex: {message}")]
    Hex {
        /// Name of the malformed JSON field.
        field: &'static str,
        /// Decoder detail.
        message: String,
    },
    /// A Commonware or Vera artifact could not be decoded.
    #[error("artifact decode failed: {0}")]
    Codec(String),
    /// Canonical block bytes do not hash to the advertised block ID.
    #[error("canonical block bytes do not match block_hash")]
    BlockHashMismatch,
    /// A displayed field differs from the authenticated canonical block.
    #[error("authenticated block field does not match: {0}")]
    BlockFieldMismatch(&'static str),
    /// Finalization proposal metadata or payload differs from the block.
    #[error("finalization proposal does not match the authenticated block")]
    ProposalMismatch,
    /// Epoch material is structurally inconsistent.
    #[error("invalid epoch material: {0}")]
    EpochMaterial(String),
    /// The response names a different consensus identity from the trusted deployment.
    #[error("light block consensus key does not match the trusted key")]
    UntrustedConsensusKey,
    /// The aggregate threshold finalization certificate is invalid.
    #[error("BLS threshold finalization certificate verification failed")]
    InvalidCertificate,
}

impl From<CodecError> for LightBlockError {
    fn from(error: CodecError) -> Self {
        Self::Codec(error.to_string())
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn decode_hex(field: &'static str, value: &str) -> Result<Vec<u8>, LightBlockError> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value)).map_err(|error| LightBlockError::Hex {
        field,
        message: error.to_string(),
    })
}

fn decode_b256(field: &'static str, value: &str) -> Result<B256, LightBlockError> {
    if value.strip_prefix("0x").unwrap_or(value).len() != 64 {
        return Err(LightBlockError::Hex {
            field,
            message: "expected 32 bytes".into(),
        });
    }
    let bytes = decode_hex(field, value)?;
    B256::try_from(bytes.as_slice()).map_err(|_| LightBlockError::Hex {
        field,
        message: format!("expected 32 bytes, got {}", bytes.len()),
    })
}

fn decode_block(bytes: &[u8]) -> Result<Block, LightBlockError> {
    Ok(Block::decode_cfg(
        commonware_codec::Copying(bytes),
        &BlockCfg {
            max_txs: LIGHT_BLOCK_MAX_TXS,
            tx: TxCfg {
                max_tx_bytes: LIGHT_BLOCK_MAX_TX_BYTES,
            },
        },
    )?)
}

/// Verify a block's finalization against an independently trusted consensus key.
///
/// Obtain `trusted_key` from the deployment's authenticated bootstrap configuration,
/// never from the response being verified. The identity remains constant across
/// resharing epochs. Epoch material in the response cannot establish trust.
/// Returns the authenticated module state root on success.
pub fn verify_light_block(
    light: &LightBlock,
    trusted_key: &ConsensusPublicKey,
) -> Result<B256, LightBlockError> {
    Ok(verify_finalized_block(light, trusted_key)?.module_state_root)
}

/// Return the requested canonical revision after validating direct or descendant finality.
/// The consensus key must come from independently provisioned trust.
pub fn verify_finalized_block(
    light: &LightBlock,
    trusted_key: &ConsensusPublicKey,
) -> Result<Block, LightBlockError> {
    verify_finalized_block_unless(light, trusted_key, |_, _| false).map(|(block, _)| block)
}

/// Validate a light block like [`verify_finalized_block`], skipping the
/// certificate check when `established` says the block with this hash is one
/// whose finality the caller has verified under `trusted_key` before.
///
/// The block bytes are hashed and every displayed field is compared with the
/// decoded block either way, so a response cannot attach other fields to an
/// established block. Returns the block with its hash.
pub fn verify_finalized_block_unless(
    light: &LightBlock,
    trusted_key: &ConsensusPublicKey,
    established: impl FnOnce(&Block, B256) -> bool,
) -> Result<(Block, B256), LightBlockError> {
    let artifacts = light.artifacts()?;
    let block_hash = decode_b256("block_hash", &light.block_hash)?;
    if keccak256(&artifacts.block) != block_hash {
        return Err(LightBlockError::BlockHashMismatch);
    }
    let block = decode_block(&artifacts.block)?;

    let checks = [
        (
            block.parent.0 == decode_b256("parent_hash", &light.parent_hash)?,
            "parent_hash",
        ),
        (block.height == light.height, "height"),
        (block.timestamp == light.timestamp, "timestamp"),
        (
            block.module_state_root == decode_b256("module_state_root", &light.module_state_root)?,
            "module_state_root",
        ),
        (block.context.round.epoch().get() == light.epoch, "epoch"),
        (block.context.round.view().get() == light.view, "view"),
        (
            block.context.parent.0.get() == light.parent_view,
            "parent_view",
        ),
    ];
    if let Some((_, field)) = checks.into_iter().find(|(matches, _)| !matches) {
        return Err(LightBlockError::BlockFieldMismatch(field));
    }
    if !established(&block, block_hash) {
        verify_certified(&block, block_hash, &artifacts, trusted_key)?;
    }
    Ok((block, block_hash))
}

/// Verify canonical finality artifacts and return the requested block with its identifier.
///
/// This is [`verify_finalized_block`] over decoded bytes, for callers that
/// carry the artifacts without the JSON header fields.
pub fn verify_finalized_artifacts(
    artifacts: &FinalizedArtifacts,
    trusted_key: &ConsensusPublicKey,
) -> Result<(Block, B256), LightBlockError> {
    artifacts.check_limits()?;
    let block_hash = keccak256(&artifacts.block);
    let block = decode_block(&artifacts.block)?;
    verify_certified(&block, block_hash, artifacts, trusted_key)?;
    Ok((block, block_hash))
}

fn verify_certified(
    block: &Block,
    block_hash: B256,
    artifacts: &FinalizedArtifacts,
    trusted_key: &ConsensusPublicKey,
) -> Result<(), LightBlockError> {
    let material = EpochMaterial::decode_bounded(&artifacts.epoch_material)?;
    if material.participants.is_empty()
        || material.sharing.total().get() as usize != material.participants.len()
    {
        return Err(LightBlockError::EpochMaterial(
            "participant set and sharing polynomial disagree".into(),
        ));
    }

    if material.sharing.public() != trusted_key {
        return Err(LightBlockError::UntrustedConsensusKey);
    }

    let mut certified_epoch_end = is_epoch_end(block);
    let mut certified_context = block.context.clone();
    let mut certified_height = block.height;
    let mut certified_hash = block_hash;
    for bytes in &artifacts.descendants {
        let descendant = decode_block(bytes)?;
        if descendant.parent.0 != certified_hash
            || certified_height.checked_add(1) != Some(descendant.height)
        {
            return Err(LightBlockError::AncestryMismatch);
        }
        certified_hash = keccak256(bytes);
        certified_height = descendant.height;
        certified_epoch_end = is_epoch_end(&descendant);
        certified_context = descendant.context;
    }
    let expected = Proposal::new(
        certified_context.round,
        certified_context.parent.0,
        Sha256::hash(&[certified_hash.as_slice()]),
    );
    let finalization: Finalization<LightConsensusScheme, ConsensusDigest> =
        Finalization::decode(commonware_codec::Copying(artifacts.finalization.as_slice()))?;
    // Commonware may re-propose the same epoch-ending block in a later view.
    // Its signed payload remains the digest of the original canonical block.
    let proposal = &finalization.proposal;
    let reproposal = certified_epoch_end
        && proposal.payload == expected.payload
        && proposal.round.epoch() == expected.round.epoch()
        && proposal.round.view() > expected.round.view()
        && proposal.parent >= expected.round.view()
        && proposal.parent < proposal.round.view();
    if *proposal != expected && !reproposal {
        return Err(LightBlockError::ProposalMismatch);
    }

    let verifier = LightConsensusScheme::certificate_verifier(LIGHT_BLOCK_NAMESPACE, *trusted_key);
    // The vote and seed signatures are checked as one random combination, which
    // is sound only when the weights cannot be predicted.
    let mut rng = commonware_utils::sys_rng();
    if !finalization.verify(&mut rng, &verifier, &Sequential) {
        return Err(LightBlockError::InvalidCertificate);
    }
    Ok(())
}

fn is_epoch_end(block: &Block) -> bool {
    matches!(
        &block.payload,
        Some(crate::DkgPayload::EpochInfo(info))
            if block.context.round.epoch().get().checked_add(1) == Some(info.epoch.get())
    )
}

#[cfg(test)]
mod tests;
