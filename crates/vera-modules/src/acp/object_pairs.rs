//! Exact physical relationship counts for one target object and generation pair.

use super::{
    keys,
    record_store::{RecordChange, RecordStore},
    relationship_index::{self, invalid},
    types::{RelationPair, RelationshipRecord},
};
use zanzibar::error::Result;

pub(super) fn policy_prefix(policy: &str) -> Vec<u8> {
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
    pair_key(
        &record.policy_id,
        &record.relationship.resource,
        &record.relationship.object_id,
        record.incarnation,
        record.generations,
    )
}

pub(super) fn incarnation_prefix(
    policy: &str,
    resource: &str,
    object: &str,
    incarnation: u64,
) -> Vec<u8> {
    let mut prefix = prefix(policy, resource, object);
    prefix.extend_from_slice(format!("{incarnation:016x}/").as_bytes());
    prefix
}

pub(super) fn pair_key(
    policy: &str,
    resource: &str,
    object: &str,
    incarnation: u64,
    pair: RelationPair,
) -> Vec<u8> {
    let mut key = incarnation_prefix(policy, resource, object, incarnation);
    append_pair(&mut key, pair);
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
        .and_then(|suffix| suffix.strip_prefix(b"v3/"))
        .ok_or_else(|| invalid("relationship key has another policy or generation"))?;
    let mut fields = suffix.split(|byte| *byte == b'/');
    let resource = fields
        .next()
        .ok_or_else(|| invalid("missing relationship resource"))?;
    let object = fields
        .next()
        .ok_or_else(|| invalid("missing relationship object"))?;
    let incarnation = fields
        .next()
        .ok_or_else(|| invalid("missing relationship incarnation"))?;
    if incarnation.len() != 16 {
        return Err(invalid("invalid relationship incarnation"));
    }
    generation(incarnation)?;
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
    output.extend_from_slice(b"v3/");
    output.extend_from_slice(resource);
    output.push(b'/');
    output.extend_from_slice(object);
    output.push(b'/');
    output.extend_from_slice(incarnation);
    output.push(b'/');
    append_pair(&mut output, pair);
    Ok(output)
}

/// State key for a non-owner row, derived before owned primary decoding.
pub(super) fn state_key_from_relationship(
    policy: &str,
    pair: RelationPair,
    key: &[u8],
) -> Result<Option<Vec<u8>>> {
    if pair.target == 0 {
        return Ok(None);
    }
    let counter = key_from_relationship(policy, pair, key)?;
    let prefix = policy_prefix(policy);
    let mut fields = counter
        .strip_prefix(prefix.as_slice())
        .unwrap()
        .split(|b| *b == b'/');
    if fields.next() != Some(b"v3".as_slice()) {
        return Err(invalid("invalid object key version"));
    }
    let decode = |bytes: &[u8]| -> Result<String> {
        String::from_utf8(hex::decode(bytes).map_err(|_| invalid("invalid object key"))?)
            .map_err(|_| invalid("invalid object key UTF-8"))
    };
    let resource = decode(fields.next().unwrap())?;
    let object = decode(fields.next().unwrap())?;
    Ok(Some(super::object_state::key(policy, &resource, &object)))
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
    if next == previous {
        return Ok(None);
    }
    let encoded = next.to_be_bytes();
    store
        .prepare_write(&key, (next > 0).then_some(encoded.as_slice()))
        .map(Some)
}

#[cfg(test)]
#[path = "object_pair_tests.rs"]
mod tests;
