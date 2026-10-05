//! Exact physical relationship counts for one target object and generation pair.

use super::{
    keys,
    record_store::{RecordChange, RecordStore},
    relationship_index::{self, invalid},
    types::{RelationPair, RelationshipRecord},
};
use zanzibar::error::Result;

fn policy_prefix(policy: &str) -> Vec<u8> {
    let mut prefix = relationship_index::policy_prefix(policy);
    prefix.extend_from_slice(b"object/");
    prefix
}

pub(super) fn prefix(policy: &str, resource: &str, object: &str) -> Vec<u8> {
    let mut prefix = policy_prefix(policy);
    prefix.extend_from_slice(keys::object_prefix(resource, object).as_bytes());
    prefix
}

pub(super) fn key(record: &RelationshipRecord) -> Vec<u8> {
    let mut key = prefix(
        &record.policy_id,
        &record.relationship.resource,
        &record.relationship.object_id,
    );
    append_pair(&mut key, record.generations);
    key
}

fn append_pair(key: &mut Vec<u8>, pair: RelationPair) {
    key.extend_from_slice(format!("{:016x}/{:016x}", pair.target, pair.subject).as_bytes());
}

pub(super) fn parse_pair(prefix: &[u8], key: &[u8]) -> Result<RelationPair> {
    let suffix = key
        .strip_prefix(prefix)
        .filter(|suffix| suffix.len() == 33 && suffix[16] == b'/')
        .ok_or_else(|| invalid("invalid object relationship count key"))?;
    Ok(RelationPair {
        target: generation(&suffix[..16])?,
        subject: generation(&suffix[17..])?,
    })
}

fn generation(bytes: &[u8]) -> Result<u64> {
    if !lower_hex(bytes) {
        return Err(invalid("noncanonical object relationship generation"));
    }
    u64::from_str_radix(
        std::str::from_utf8(bytes)
            .map_err(|_| invalid("invalid object relationship generation"))?,
        16,
    )
    .map_err(|_| invalid("invalid object relationship generation"))
}

/// Derive the counter from a canonical primary key without decoding its record.
/// The mutation planner separately validates the primary value against that key.
pub(super) fn key_from_relationship(
    policy: &str,
    pair: RelationPair,
    key: &[u8],
) -> Result<Vec<u8>> {
    if key.len() > crate::kv_store::NATIVE_MAX_KEY_BYTES {
        return Err(invalid("relationship key exceeds native storage bounds"));
    }
    let primary = keys::relationship_generation_prefix(policy, pair, "");
    let suffix = key
        .strip_prefix(primary.as_slice())
        .and_then(|suffix| suffix.strip_prefix(b"v2/"))
        .ok_or_else(|| invalid("relationship key has another policy or generation"))?;
    let mut fields = suffix.split(|byte| *byte == b'/');
    let resource = fields
        .next()
        .ok_or_else(|| invalid("missing relationship resource"))?;
    let object = fields
        .next()
        .ok_or_else(|| invalid("missing relationship object"))?;
    let relation = fields
        .next()
        .ok_or_else(|| invalid("missing relationship relation"))?;
    let subject = fields
        .next()
        .ok_or_else(|| invalid("missing relationship subject"))?;
    if fields.next().is_some() || subject.len() != 64 || !lower_hex(subject) {
        return Err(invalid("invalid relationship subject key"));
    }
    for field in [resource, object, relation] {
        if !lower_hex(field) || field.len() % 2 != 0 {
            return Err(invalid("noncanonical relationship key field"));
        }
        let decoded = hex::decode(field).map_err(|_| invalid("invalid relationship key field"))?;
        std::str::from_utf8(&decoded)
            .map_err(|_| invalid("relationship key field is not UTF-8"))?;
    }
    let mut output = policy_prefix(policy);
    output.extend_from_slice(b"v2/");
    output.extend_from_slice(resource);
    output.push(b'/');
    output.extend_from_slice(object);
    output.push(b'/');
    append_pair(&mut output, pair);
    Ok(output)
}

fn lower_hex(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

pub(super) fn prepare_change<S: RecordStore>(
    store: &S,
    key: Vec<u8>,
    increase: bool,
    amount: u64,
) -> Result<Option<RecordChange>> {
    let previous = store
        .read_record(&key)?
        .as_deref()
        .map(relationship_index::decode_count)
        .transpose()?
        .unwrap_or(0);
    if amount == 0 && previous == 0 {
        return Err(invalid("stored relationship has no object pair count"));
    }
    let next = if increase {
        previous.checked_add(amount)
    } else {
        previous.checked_sub(amount)
    }
    .ok_or_else(|| invalid("object relationship count overflow or underflow"))?;
    Ok((next != previous).then(|| (key, (next > 0).then(|| next.to_be_bytes().to_vec()))))
}

#[cfg(test)]
#[path = "object_pair_tests.rs"]
mod tests;
