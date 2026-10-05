use std::{collections::BTreeMap, sync::Mutex};

use alloy_primitives::B256;
use bytes::Bytes;
use vera_modules::acp::zanzibar_store::evaluate_access_request;

use super::{
    AccessRequest, PermissionError, PermissionLimits, PermissionProof, PermissionRead,
    VerifiedRecords,
};
use commonware_codec::{Decode as _, EncodeSize, Error as CodecError, RangeCfg, Read, Write};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_storage::{
    merkle::{MAX_PROOF_DIGESTS_PER_ELEMENT, mmr},
    qmdb::{
        any::{
            ordered::variable::{Operation as StoredOperation, Update},
            value::VariableEncoding,
        },
        current::ordered::proof::constant::{ExclusionProof, KeyValueProof},
    },
};

pub use vera_modules::kv_store::{
    NATIVE_MAX_KEY_BYTES as MAX_KEY_BYTES, NATIVE_MAX_VALUE_BYTES as MAX_VALUE_BYTES,
};
/// Current-state membership evidence, including the authenticated successor key.
pub type Membership = KeyValueProof<mmr::Family, Vec<u8>, Digest, 32>;
/// Current-state absence evidence, including the surrounding ordered span.
pub type Exclusion = ExclusionProof<mmr::Family, Vec<u8>, VariableEncoding<Bytes>, Digest, 32>;
type Operation = StoredOperation<mmr::Family, Vec<u8>, Bytes>;

/// One authenticated entry in a complete prefix.
#[derive(Clone, Debug)]
pub struct Entry {
    /// Raw key.
    pub key: Vec<u8>,
    /// Raw value.
    pub value: Bytes,
    /// Membership and successor proof.
    pub proof: Membership,
}

/// A prefix boundary followed by every authenticated successor inside the prefix.
#[derive(Clone, Debug)]
pub struct PrefixEvidence {
    /// Absence proof for the literal prefix, unless that exact key is present.
    pub boundary: Option<Exclusion>,
    /// Complete ordered entries, including the literal prefix when present.
    pub entries: Vec<Entry>,
}

fn key_config() -> <Vec<u8> as Read>::Cfg {
    (RangeCfg::new(0..=MAX_KEY_BYTES), ())
}

/// Decode one membership proof with native field and Merkle limits.
pub fn membership(bytes: &[u8]) -> Result<Membership, PermissionError> {
    Membership::decode_cfg(
        commonware_codec::Copying(bytes),
        &(MAX_PROOF_DIGESTS_PER_ELEMENT, key_config()),
    )
    .map_err(|_| PermissionError::Invalid("membership encoding"))
}

/// Decode one absence proof with native field and Merkle limits.
pub fn exclusion(bytes: &[u8]) -> Result<Exclusion, PermissionError> {
    Exclusion::decode_cfg(commonware_codec::Copying(bytes), &exclusion_config())
        .map_err(|_| PermissionError::Invalid("exclusion encoding"))
}

fn exclusion_config() -> <Exclusion as Read>::Cfg {
    (
        MAX_PROOF_DIGESTS_PER_ELEMENT,
        (key_config(), RangeCfg::new(0..=MAX_VALUE_BYTES)),
        RangeCfg::new(0..=MAX_VALUE_BYTES),
    )
}

fn included(key: &[u8], value: &Bytes, proof: &Membership, root: &Digest) -> bool {
    proof.proof.verify::<Sha256, _>(
        Operation::Update(Update {
            key: key.to_vec(),
            value: value.clone(),
            next_key: proof.next_key.clone(),
        }),
        root,
    )
}

fn excluded(key: &[u8], proof: &Exclusion, root: &Digest) -> bool {
    match proof {
        Exclusion::KeyValue(proof, record) => {
            let start = record.key.as_slice();
            let end = record.next_key.as_slice();
            let within = if start < end {
                key > start && key < end
            } else {
                key > start || key < end
            };
            within && proof.verify::<Sha256, _>(Operation::Update(record.clone()), root)
        }
        Exclusion::Commit(proof, metadata) => {
            proof.verify::<Sha256, _>(Operation::CommitFloor(metadata.clone(), proof.loc), root)
        }
    }
}

/// Verify bounded native membership or absence at an authenticated partition root.
pub fn verify_point(
    root: &Digest,
    key: &[u8],
    value: Option<&Bytes>,
    proof: &[u8],
) -> Result<(), PermissionError> {
    if key.len() > MAX_KEY_BYTES || value.is_some_and(|v| v.len() > MAX_VALUE_BYTES) {
        return Err(PermissionError::Limit);
    }
    let valid = match value {
        Some(value) => included(key, value, &membership(proof)?, root),
        None => excluded(key, &exclusion(proof)?, root),
    };
    if !valid {
        return Err(PermissionError::Invalid("current-state point"));
    }
    Ok(())
}

/// Next in-prefix key; crossing the maximum key wraps and terminates enumeration.
pub fn successor<'a>(key: &[u8], next: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    (next > key && next.starts_with(prefix)).then_some(next)
}

impl PrefixEvidence {
    /// Verify complete ordered coverage against an independently authenticated partition root.
    pub fn verify(&self, prefix: &[u8], root: &Digest) -> Result<(), PermissionError> {
        if self.verify_span(prefix, prefix, root)?.is_some() {
            return Err(PermissionError::Invalid("incomplete prefix"));
        }
        Ok(())
    }

    /// Verify consecutive page entries without treating a partial page as complete coverage.
    pub fn verify_page(
        &self,
        prefix: &[u8],
        start: &[u8],
        root: &Digest,
    ) -> Result<Option<Vec<u8>>, PermissionError> {
        if prefix.len() > MAX_KEY_BYTES || start.len() > MAX_KEY_BYTES || !start.starts_with(prefix)
        {
            return Err(PermissionError::Invalid("page selection"));
        }
        let next = self.verify_span(prefix, start, root)?;
        if next.is_some() && self.entries.is_empty() {
            return Err(PermissionError::Invalid("empty nonterminal page"));
        }
        Ok(next)
    }

    fn verify_span(
        &self,
        prefix: &[u8],
        start: &[u8],
        root: &Digest,
    ) -> Result<Option<Vec<u8>>, PermissionError> {
        let mut next = match &self.boundary {
            None => Some(start),
            Some(boundary) => {
                if !excluded(start, boundary, root) {
                    return Err(PermissionError::Invalid("prefix boundary"));
                }
                match boundary {
                    Exclusion::KeyValue(_, record) => successor(start, &record.next_key, prefix),
                    Exclusion::Commit(..) => None,
                }
            }
        };
        for entry in &self.entries {
            if next != Some(entry.key.as_slice())
                || !included(&entry.key, &entry.value, &entry.proof, root)
            {
                return Err(PermissionError::Invalid("prefix successor"));
            }
            next = successor(&entry.key, &entry.proof.next_key, prefix);
        }
        Ok(next.map(<[u8]>::to_vec))
    }
}

pub(super) fn verify(
    root: B256,
    roots: [B256; 4],
    policy: &str,
    request: &AccessRequest,
    proof: &PermissionProof,
    limits: PermissionLimits,
) -> Result<bool, PermissionError> {
    if vera_modules::module_state::combine_module_roots(&roots.map(|root| root.0)) != root {
        return Err(PermissionError::Invalid("current-state roots"));
    }
    let root = Digest::from(roots[0].0);
    let mut store = VerifiedRecords {
        points: BTreeMap::new(),
        prefixes: BTreeMap::new(),
        remaining: Mutex::new(limits.reads),
    };
    let mut remaining = limits.reads.records;
    for read in &proof.reads {
        match read {
            PermissionRead::CurrentPoint { key, value, proof } => {
                remaining = remaining
                    .checked_sub(usize::from(value.is_some()))
                    .ok_or(PermissionError::Limit)?;
                verify_point(&root, key, value.as_ref().map(|v| &v.0), proof)?;
                if store
                    .points
                    .insert(key.to_vec(), value.as_ref().map(|v| v.to_vec()))
                    .is_some()
                {
                    return Err(PermissionError::Invalid("duplicate point read"));
                }
            }
            PermissionRead::CurrentPrefix { prefix, proof } => {
                if prefix.len() > MAX_KEY_BYTES {
                    return Err(PermissionError::Limit);
                }
                let evidence = PrefixEvidence::decode_cfg(
                    commonware_codec::Copying(proof.as_ref()),
                    &remaining,
                )
                .map_err(|_| PermissionError::Invalid("prefix encoding or record limit"))?;
                remaining -= evidence.entries.len();
                evidence.verify(prefix, &root)?;
                let entries = evidence
                    .entries
                    .into_iter()
                    .map(|entry| (entry.key, entry.value.to_vec()))
                    .collect();
                if store.prefixes.insert(prefix.to_vec(), entries).is_some() {
                    return Err(PermissionError::Invalid("duplicate prefix read"));
                }
            }
            _ => return Err(PermissionError::Invalid("mixed proof formats")),
        }
    }
    Ok(evaluate_access_request(store, policy, request)?)
}

impl Write for Entry {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.key.write(buf);
        self.value.write(buf);
        self.proof.write(buf);
    }
}
impl EncodeSize for Entry {
    fn encode_size(&self) -> usize {
        self.key.encode_size() + self.value.encode_size() + self.proof.encode_size()
    }
}
impl Read for Entry {
    type Cfg = ();
    fn read_cfg(buf: &mut impl commonware_codec::Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            key: Vec::read_cfg(buf, &key_config())?,
            value: Bytes::read_cfg(buf, &RangeCfg::new(0..=MAX_VALUE_BYTES))?,
            proof: Membership::read_cfg(buf, &(MAX_PROOF_DIGESTS_PER_ELEMENT, key_config()))?,
        })
    }
}
impl Write for PrefixEvidence {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.boundary.write(buf);
        self.entries.write(buf);
    }
}
impl EncodeSize for PrefixEvidence {
    fn encode_size(&self) -> usize {
        self.boundary.encode_size() + self.entries.encode_size()
    }
}
impl Read for PrefixEvidence {
    type Cfg = usize;
    fn read_cfg(buf: &mut impl commonware_codec::Buf, records: &usize) -> Result<Self, CodecError> {
        Ok(Self {
            boundary: Option::<Exclusion>::read_cfg(buf, &exclusion_config())?,
            entries: Vec::read_cfg(buf, &(RangeCfg::new(0..=*records), ()))?,
        })
    }
}
