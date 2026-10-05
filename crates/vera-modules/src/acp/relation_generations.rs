//! Immutable relation identities across policy definition edits.

use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
};

use acp::{Policy, Relationship, Subject};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{MapAccess, Visitor},
};
use zanzibar::error::{Error, Result};

/// The target and optional userset dependency of a stored relationship.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
)]
#[serde(deny_unknown_fields)]
pub struct RelationPair {
    /// Target relation generation; object ownership uses zero.
    pub target: u64,
    /// Subject relation generation; zero denotes no revocable dependency.
    pub subject: u64,
}

/// Active relation names and the next unused positive generation.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
)]
#[serde(deny_unknown_fields)]
pub struct RelationGenerations {
    /// Next unused positive generation; checked allocation never reuses an ID.
    pub next: u64,
    /// Resource names mapped to their active relation generations.
    #[serde(deserialize_with = "deserialize_active")]
    pub active: BTreeMap<String, BTreeMap<String, u64>>,
}

impl RelationGenerations {
    /// Assign identities to a policy's compiled relations, including actor roles.
    pub fn new(policy: &Policy) -> Result<Self> {
        let mut state = Self {
            next: 1,
            active: BTreeMap::new(),
        };
        for (resource, relations) in names(policy)? {
            let mut ids = BTreeMap::new();
            for (relation, permanent) in relations {
                ids.insert(relation, if permanent { 0 } else { state.allocate()? });
            }
            state.active.insert(resource, ids);
        }
        Ok(state)
    }

    /// Preserve surviving names and retire removed identities atomically.
    pub fn updated(&self, old: &Policy, new: &Policy) -> Result<(Self, BTreeSet<u64>)> {
        self.validate(old)?;
        let new_names = names(new)?;
        if old.actor.as_ref().map(|actor| &actor.name)
            != new.actor.as_ref().map(|actor| &actor.name)
        {
            return Err(invalid("actor resource cannot be renamed"));
        }
        for resource in &old.resources {
            if !new
                .resources
                .iter()
                .any(|candidate| candidate.name == resource.name)
            {
                return Err(invalid("existing resources cannot be removed"));
            }
        }
        let mut updated = Self {
            next: self.next,
            active: BTreeMap::new(),
        };
        for (resource, relations) in new_names {
            let mut ids = BTreeMap::new();
            for (relation, permanent) in relations {
                let id = match self.generation(&resource, &relation) {
                    Some(id) => id,
                    None if permanent => 0,
                    None => updated.allocate()?,
                };
                ids.insert(relation, id);
            }
            updated.active.insert(resource, ids);
        }
        let removed = self
            .active_ids()
            .difference(&updated.active_ids())
            .copied()
            .collect();
        Ok((updated, removed))
    }

    /// Reject metadata that differs from the compiled policy or reuses an identity.
    pub fn validate(&self, policy: &Policy) -> Result<()> {
        if self.next == 0 {
            return Err(invalid("zero next relation generation"));
        }
        let expected = names(policy)?;
        if self.active.len() != expected.len() {
            return Err(invalid("relation generation resources differ from policy"));
        }
        let mut used = BTreeSet::new();
        for (resource, relations) in expected {
            let actual = self
                .active
                .get(&resource)
                .ok_or_else(|| invalid("relation generation resource missing"))?;
            if actual.len() != relations.len() {
                return Err(invalid("relation generation names differ from policy"));
            }
            for (relation, permanent) in relations {
                let id = *actual
                    .get(&relation)
                    .ok_or_else(|| invalid("relation generation missing"))?;
                if permanent {
                    if id != 0 {
                        return Err(invalid("owner generation must be zero"));
                    }
                } else if id == 0 || id >= self.next || !used.insert(id) {
                    return Err(invalid("invalid or reused relation generation"));
                }
            }
        }
        Ok(())
    }

    /// Resolve one exact compiled relation name.
    pub fn generation(&self, resource: &str, relation: &str) -> Option<u64> {
        self.active.get(resource)?.get(relation).copied()
    }

    /// Bind a relationship to its current target and userset identities.
    pub fn pair(&self, relationship: &Relationship) -> Result<RelationPair> {
        let lookup = |resource: &str, relation: &str| {
            self.generation(resource, relation)
                .ok_or_else(|| Error::RelationNotFound {
                    resource: resource.into(),
                    relation: relation.into(),
                })
        };
        let target = lookup(&relationship.resource, &relationship.relation)?;
        let subject = match &relationship.subject {
            Subject::EntitySet {
                resource, relation, ..
            } if !relation.is_empty() => lookup(resource, relation)?,
            Subject::EntitySet { resource, .. } if !self.active.contains_key(resource) => {
                return Err(Error::ResourceNotFound(resource.clone()));
            }
            _ => 0,
        };
        Ok(RelationPair { target, subject })
    }

    /// Whether an identity is current; zero is the permanent dependency sentinel.
    pub fn contains(&self, generation: u64) -> bool {
        generation == 0
            || self
                .active
                .values()
                .any(|relations| relations.values().any(|id| *id == generation))
    }

    /// Current identities, including the permanent zero dependency sentinel.
    pub fn active_ids(&self) -> BTreeSet<u64> {
        self.active
            .values()
            .flat_map(|relations| relations.values().copied())
            .chain([0])
            .collect()
    }

    fn allocate(&mut self) -> Result<u64> {
        let id = self.next;
        self.next = id
            .checked_add(1)
            .ok_or_else(|| invalid("relation generation counter exhausted"))?;
        Ok(id)
    }
}

fn invalid(message: &str) -> Error {
    Error::Serialization(message.into())
}

fn names(policy: &Policy) -> Result<BTreeMap<String, BTreeMap<String, bool>>> {
    let mut names = BTreeMap::new();
    for (resource, object) in policy
        .resources
        .iter()
        .map(|r| (r, true))
        .chain(policy.actor.iter().map(|r| (r, false)))
    {
        if resource.name.is_empty() || names.contains_key(&resource.name) {
            return Err(invalid("empty or duplicate generation resource"));
        }
        let mut relations = BTreeMap::new();
        for relation in &resource.relations {
            if relation.name.is_empty()
                || relations
                    .insert(relation.name.clone(), object && relation.name == "owner")
                    .is_some()
            {
                return Err(invalid("empty or duplicate generation relation"));
            }
            if !object && relation.name == "owner" {
                return Err(invalid("actor roles cannot declare owner"));
            }
        }
        if object && !relations.contains_key("owner") {
            return Err(invalid("object resource is missing owner"));
        }
        names.insert(resource.name.clone(), relations);
    }
    Ok(names)
}

#[derive(Deserialize)]
#[serde(transparent)]
struct RelationMap(#[serde(deserialize_with = "unique_map")] BTreeMap<String, u64>);

fn deserialize_active<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, BTreeMap<String, u64>>, D::Error> {
    let resources: BTreeMap<String, RelationMap> = unique_map(deserializer)?;
    Ok(resources
        .into_iter()
        .map(|(name, RelationMap(relations))| (name, relations))
        .collect())
}

fn unique_map<'de, D: Deserializer<'de>, V: Deserialize<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, V>, D::Error> {
    struct Unique<V>(PhantomData<V>);
    impl<'de, V: Deserialize<'de>> Visitor<'de> for Unique<V> {
        type Value = BTreeMap<String, V>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a map with unique names")
        }
        fn visit_map<A: MapAccess<'de>>(
            self,
            mut map: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut result = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, V>()? {
                if result.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate generation name"));
                }
            }
            Ok(result)
        }
    }
    deserializer.deserialize_map(Unique(PhantomData))
}

#[cfg(test)]
#[path = "relation_generations_tests.rs"]
mod tests;
