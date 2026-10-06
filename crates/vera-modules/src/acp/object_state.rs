//! Canonical target-object incarnation points, independent of registration.

use acp::Relationship;
use zanzibar::error::{Error, Result};

use super::record_store::{RecordChange, RecordStore};
use crate::kv_store::NATIVE_MAX_KEY_BYTES;

/// Namespace for monotonic object-incarnation points.
pub const PREFIX: &[u8] = b"object_state/";

/// All incarnation points belonging to a policy.
pub fn policy_prefix(policy: &str) -> Vec<u8> {
    [PREFIX, policy.as_bytes(), b"/"].concat()
}

/// Canonical point key. Resource and object boundaries preserve arbitrary UTF-8.
/// Readers and mutation planners validate the native key bound before allocating it.
pub fn key(policy: &str, resource: &str, object: &str) -> Vec<u8> {
    let mut key = policy_prefix(policy);
    key.extend_from_slice(hex::encode(resource).as_bytes());
    key.push(b'/');
    key.extend_from_slice(hex::encode(object).as_bytes());
    key
}

fn invalid(reason: &str) -> Error {
    Error::Serialization(reason.into())
}

/// Validate identifiers and the encoded native key bound before allocating a key.
pub fn validate_key(policy: &str, resource: &str, object: &str) -> Result<()> {
    if policy.is_empty() || policy.contains('/') {
        return Err(invalid("invalid object incarnation policy key"));
    }
    let length = PREFIX
        .len()
        .saturating_add(policy.len())
        .saturating_add(2)
        .saturating_add(resource.len().saturating_mul(2))
        .saturating_add(object.len().saturating_mul(2));
    if length > NATIVE_MAX_KEY_BYTES {
        return Err(invalid(
            "object incarnation key exceeds native storage bounds",
        ));
    }
    Ok(())
}

/// Decode a canonical point key for restoration or proof validation.
/// Low-level policy identifiers need not be native 64-character policy hashes.
pub fn decode_key(key: &[u8]) -> Result<(String, String, String)> {
    if key.len() > NATIVE_MAX_KEY_BYTES {
        return Err(invalid(
            "object incarnation key exceeds native storage bounds",
        ));
    }
    let mut fields = key
        .strip_prefix(PREFIX)
        .ok_or_else(|| invalid("invalid object incarnation namespace"))?
        .split(|byte| *byte == b'/');
    let policy = std::str::from_utf8(fields.next().unwrap_or_default())
        .map_err(|_| invalid("invalid object incarnation policy key"))?;
    let mut decode_field = || {
        let field = fields
            .next()
            .ok_or_else(|| invalid("missing object incarnation key field"))?;
        if field.len() % 2 != 0
            || !field
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err(invalid("noncanonical object incarnation key field"));
        }
        String::from_utf8(
            hex::decode(field).map_err(|_| invalid("invalid object incarnation key field"))?,
        )
        .map_err(|_| invalid("object incarnation key field is not UTF-8"))
    };
    let resource = decode_field()?;
    let object = decode_field()?;
    if fields.next().is_some() {
        return Err(invalid("extra object incarnation key field"));
    }
    validate_key(policy, &resource, &object)?;
    Ok((policy.into(), resource, object))
}

/// Decode a canonical incarnation key belonging to the requested policy.
pub fn parse_key(policy: &str, key: &[u8]) -> Result<(String, String)> {
    let (stored_policy, resource, object) = decode_key(key)?;
    if stored_policy != policy {
        return Err(invalid("object incarnation key belongs to another policy"));
    }
    Ok((resource, object))
}

/// Decode a stored incarnation. Initial zero is represented only by absence.
pub fn decode(bytes: &[u8]) -> Result<u64> {
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| invalid("invalid object incarnation encoding"))?;
    let value = u64::from_be_bytes(bytes);
    if value == 0 {
        return Err(invalid("stored object incarnation must be positive"));
    }
    Ok(value)
}

/// Read the current incarnation. Only proven absence means initial zero;
/// unavailable proof coverage remains an error and absence does not imply ownership.
pub fn read<S: RecordStore>(store: &S, policy: &str, resource: &str, object: &str) -> Result<u64> {
    validate_key(policy, resource, object)?;
    read_key(store, &key(policy, resource, object))
}

fn read_key<S: RecordStore>(store: &S, key: &[u8]) -> Result<u64> {
    store
        .read_record(key)?
        .as_deref()
        .map(decode)
        .transpose()
        .map(|value| value.unwrap_or(0))
}

/// Owners have stable incarnation zero; other relationships select current state.
pub fn for_relationship<S: RecordStore>(
    store: &S,
    policy: &str,
    relationship: &Relationship,
) -> Result<u64> {
    if relationship.relation == "owner" {
        return Ok(0);
    }
    read(
        store,
        policy,
        &relationship.resource,
        &relationship.object_id,
    )
}

/// Reserve the next counter write without changing state. The caller includes
/// this already-paid write in its complete atomic mutation plan.
pub(super) fn prepare_advance<S: RecordStore>(
    store: &S,
    policy: &str,
    resource: &str,
    object: &str,
) -> Result<(u64, RecordChange)> {
    validate_key(policy, resource, object)?;
    let key = key(policy, resource, object);
    let next = read_key(store, &key)?
        .checked_add(1)
        .ok_or_else(|| invalid("object incarnation overflow"))?;
    let change = store.prepare_write(&key, Some(&next.to_be_bytes()))?;
    Ok((next, change))
}

#[cfg(test)]
#[path = "object_state_tests.rs"]
mod tests;
