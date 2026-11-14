//! Markers for actors whose ownership of an object ended by transfer.

use super::*;

pub(super) const PREFIX: &[u8] = b"relinquished/";

const ACTOR_DOMAIN: &[u8] = b"vera/acp-relinquished/v1\0";

pub(super) fn policy_prefix(policy: &str) -> Vec<u8> {
    [PREFIX, policy.as_bytes(), b"/"].concat()
}

/// The actor is hashed so that the key stays shorter than the object's owner
/// record key, whatever the length of the DID.
pub(super) fn key(policy: &str, object: &Object, actor: &str) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(ACTOR_DOMAIN);
    digest.update(actor.as_bytes());
    let mut key = policy_prefix(policy);
    key.extend_from_slice(hex::encode(&object.resource).as_bytes());
    key.push(b'/');
    key.extend_from_slice(hex::encode(&object.id).as_bytes());
    key.push(b'/');
    key.extend_from_slice(hex::encode(digest.finalize()).as_bytes());
    key
}

fn invalid() -> AcpError {
    AcpError::State("invalid relinquishment marker".into())
}

fn lower_hex(field: &[u8]) -> bool {
    field
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

/// Decode the policy and object of a canonical marker with an empty value.
pub(super) fn parse(key: &[u8], value: &[u8]) -> Result<(String, Object)> {
    let fields: Vec<&[u8]> = key
        .strip_prefix(PREFIX)
        .ok_or_else(invalid)?
        .split(|byte| *byte == b'/')
        .collect();
    let [policy, resource, object, actor] = fields.as_slice() else {
        return Err(invalid());
    };
    if !value.is_empty() || policy.is_empty() || actor.len() != 64 || !lower_hex(actor) {
        return Err(invalid());
    }
    let text = |field: &[u8]| {
        if !lower_hex(field) {
            return Err(invalid());
        }
        String::from_utf8(hex::decode(field).map_err(|_| invalid())?).map_err(|_| invalid())
    };
    Ok((
        String::from_utf8(policy.to_vec()).map_err(|_| invalid())?,
        Object {
            resource: text(resource)?,
            id: text(object)?,
        },
    ))
}

impl AcpModule {
    pub(super) fn relinquish_with_budget(
        &mut self,
        policy: &str,
        object: &Object,
        actor: &str,
        budget: &CommandBudget,
    ) -> Result<()> {
        let key = key(policy, object, actor);
        budget.finish(budget.permissions.records.write(&key, Some(&[])))?;
        self.store.put(&key, Vec::new());
        Ok(())
    }

    pub(super) fn relinquished_with_budget(
        &self,
        policy: &str,
        object: &Object,
        actor: &str,
        budget: &CommandBudget,
    ) -> Result<bool> {
        let key = key(policy, object, actor);
        let value = self.store.get_ref(&key);
        budget.finish(budget.permissions.records.read(&key, value))?;
        match value {
            None => Ok(false),
            Some([]) => Ok(true),
            Some(_) => Err(invalid()),
        }
    }

    /// A live policy keeps markers only for registered objects; a retired policy
    /// keeps them until their cleanup phase, after the owner records are gone.
    pub(super) fn validate_relinquishments(&self) -> Result<()> {
        let orphan = || AcpError::State("orphan relinquishment marker".into());
        let mut current: Option<(String, bool, RelationGenerations)> = None;
        for (key, value) in self.store.prefix_iter(PREFIX) {
            let (policy, object) = parse(key, value)?;
            if current.as_ref().is_none_or(|(id, ..)| *id != policy) {
                let (live, relations) = match self.get_policy_record(&policy)? {
                    Some(record) => (true, record.relations),
                    None => self
                        .retired_policy(&policy)?
                        .filter(|retired| retired.phase <= retirement::Phase::Relinquishments)
                        .map(|retired| (false, retired.relations))
                        .ok_or_else(orphan)?,
                };
                current = Some((policy.clone(), live, relations));
            }
            let (_, live, relations) = current.as_ref().ok_or_else(orphan)?;
            if !relations.active.contains_key(&object.resource)
                || (*live && self.registration_owner_record(&policy, &object)?.is_none())
            {
                return Err(orphan());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "relinquishment_tests.rs"]
mod tests;
