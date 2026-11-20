//! The policy hash and the policy id, as acp derives them (acp
//! `wiki/acp/policy-id.md`, `crates/acp/src/ppp/id.rs`).
//!
//! `policy id = hex(SHA-256("acp/policy-id/v2" || policy hash || nonce ||
//! u64be(len) || creator))`. The policy hash is a SHA-256 over
//! `"acp/policy-hash/v1"` and an order-independent, length-prefixed encoding
//! of the authored policy. `tests/vectors/policy-id.json`, a copy of acp's
//! vectors, proves the two derivations equal on policies both engines accept.
//!
//! Policies only this engine accepts keep distinct hashes: relations without
//! `types` encode an empty type set (acp reads them as `[actor]`), `_this`
//! is tag 5, and actor relations follow the resources when present.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use vera_zanzibar::{PolicySpecification, RelationExpression};

use super::{ParsedPolicy, PolicyRelation};
use crate::error::{Error, Result};

/// The policy hash's domain tag.
pub const POLICY_HASH_DOMAIN: &[u8] = b"acp/policy-hash/v1";

/// The policy id's domain tag.
pub const POLICY_ID_DOMAIN: &[u8] = b"acp/policy-id/v2";

/// Bytes in a nonce and in a policy hash.
pub const HASH_LEN: usize = 32;

/// 32 bytes the policy creator chooses, so that one creator can create the
/// same policy more than once under different ids. Written as 64
/// hexadecimal characters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyNonce(pub [u8; HASH_LEN]);

/// The SHA-256 of a policy's canonical content encoding. Written as 64
/// lowercase hexadecimal characters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyHash(pub [u8; HASH_LEN]);

/// Text that is not 32 bytes in hexadecimal.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("expected {} hexadecimal characters", HASH_LEN * 2)]
pub struct HexError;

/// The hash of `policy`'s authored content.
///
/// # Errors
/// A permission expression that does not parse.
pub fn policy_hash(policy: &ParsedPolicy) -> Result<PolicyHash> {
    let mut e = Encoder(POLICY_HASH_DOMAIN.to_vec());
    e.str(&policy.name);
    e.str(&policy.description);
    e.len(policy.meta.len());
    for (key, value) in &policy.meta {
        e.str(key);
        e.str(value);
    }
    e.0.push(match policy.spec {
        PolicySpecification::None => 0,
        PolicySpecification::Defra => 1,
    });
    e.str("");
    let mut resources: Vec<_> = policy.resources.iter().collect();
    resources.sort_by(|a, b| a.name.cmp(&b.name));
    e.len(resources.len());
    for resource in resources {
        e.str(&resource.name);
        e.str(&resource.description);
        e.relations(&resource.relations);
        let mut permissions: Vec<_> = resource.permissions.iter().collect();
        permissions.sort_by(|a, b| a.name.cmp(&b.name));
        e.len(permissions.len());
        for permission in permissions {
            e.str(&permission.name);
            e.str(&permission.doc);
            if permission.expr.is_empty() {
                e.0.push(0);
            } else {
                e.0.push(1);
                e.expression(&RelationExpression::parse(&permission.expr)?)?;
            }
        }
    }
    if !policy.actor.relations.is_empty() {
        e.relations(&policy.actor.relations);
    }
    Ok(PolicyHash(Sha256::digest(&e.0).into()))
}

/// The id of a policy with hash `hash` created by `creator`, in its
/// canonical spelling, with `nonce`.
pub fn policy_id(hash: &PolicyHash, nonce: &PolicyNonce, creator: &str) -> String {
    let mut e = Encoder(POLICY_ID_DOMAIN.to_vec());
    e.0.extend_from_slice(&hash.0);
    e.0.extend_from_slice(&nonce.0);
    e.str(creator);
    lower_hex(&Sha256::digest(&e.0))
}

struct Encoder(Vec<u8>);

impl Encoder {
    fn len(&mut self, len: usize) {
        self.0.extend_from_slice(&(len as u64).to_be_bytes());
    }

    fn str(&mut self, value: &str) {
        self.len(value.len());
        self.0.extend_from_slice(value.as_bytes());
    }

    fn set(&mut self, mut encoded: Vec<Vec<u8>>) {
        encoded.sort();
        self.len(encoded.len());
        for item in encoded {
            self.0.extend_from_slice(&item);
        }
    }

    fn relations(&mut self, relations: &[PolicyRelation]) {
        let mut relations: Vec<_> = relations.iter().collect();
        relations.sort_by(|a, b| a.name.cmp(&b.name));
        self.len(relations.len());
        for relation in relations {
            self.str(&relation.name);
            self.str(&relation.doc);
            self.set(
                relation
                    .manages
                    .iter()
                    .map(|name| encoded_str(name))
                    .collect(),
            );
            self.set(relation.types.iter().map(|ty| encoded_type(ty)).collect());
        }
    }

    fn expression(&mut self, expression: &RelationExpression) -> Result<()> {
        match expression {
            RelationExpression::ComputedUserset { relation } => {
                self.0.push(0);
                self.str(relation);
            }
            RelationExpression::TupleToUserset {
                tuple_relation,
                computed_relation,
            } => {
                self.0.push(1);
                self.str(tuple_relation);
                self.str(computed_relation);
            }
            RelationExpression::Union(_) => {
                self.0.push(2);
                self.chain(expression, union_operands)?;
            }
            RelationExpression::Intersection(_) => {
                self.0.push(3);
                self.chain(expression, intersection_operands)?;
            }
            RelationExpression::Difference { base, subtract } => {
                self.0.push(4);
                self.expression(base)?;
                self.expression(subtract)?;
            }
            RelationExpression::This => self.0.push(5),
            _ => {
                return Err(Error::InvalidPolicy(
                    "permission expression has no policy hash encoding".into(),
                ))
            }
        }
        Ok(())
    }

    fn chain(&mut self, expression: &RelationExpression, split: Split) -> Result<()> {
        let mut operands = Vec::new();
        flatten(expression, split, &mut operands);
        let encoded = operands
            .into_iter()
            .map(|operand| {
                let mut e = Self(Vec::new());
                e.expression(operand).map(|()| e.0)
            })
            .collect::<Result<_>>()?;
        self.set(encoded);
        Ok(())
    }
}

type Split = fn(&RelationExpression) -> Option<&[RelationExpression]>;

fn union_operands(expression: &RelationExpression) -> Option<&[RelationExpression]> {
    match expression {
        RelationExpression::Union(operands) => Some(operands),
        _ => None,
    }
}

fn intersection_operands(expression: &RelationExpression) -> Option<&[RelationExpression]> {
    match expression {
        RelationExpression::Intersection(operands) => Some(operands),
        _ => None,
    }
}

/// The operands of a chain of one operator, nested chains flattened.
fn flatten<'a>(
    expression: &'a RelationExpression,
    split: Split,
    operands: &mut Vec<&'a RelationExpression>,
) {
    match split(expression) {
        Some(inner) => inner
            .iter()
            .for_each(|operand| flatten(operand, split, operands)),
        None => operands.push(expression),
    }
}

fn encoded_str(value: &str) -> Vec<u8> {
    let mut e = Encoder(Vec::new());
    e.str(value);
    e.0
}

/// `"*"`, `actor`, `resource` or `resource->relation`, as acp reads them.
fn encoded_type(text: &str) -> Vec<u8> {
    let mut e = Encoder(Vec::new());
    if text == "*" {
        e.0.push(3);
        return e.0;
    }
    match text.split_once("->").unwrap_or((text, "")) {
        ("actor", "") => e.0.push(0),
        (resource, "") => {
            e.0.push(1);
            e.str(resource);
        }
        (resource, relation) => {
            e.0.push(2);
            e.str(resource);
            e.str(relation);
        }
    }
    e.0
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(text: &str) -> std::result::Result<[u8; HASH_LEN], HexError> {
    let text = text.as_bytes();
    if text.len() != HASH_LEN * 2 {
        return Err(HexError);
    }
    let mut bytes = [0; HASH_LEN];
    for (byte, pair) in bytes.iter_mut().zip(text.chunks_exact(2)) {
        let digit = |c: u8| char::from(c).to_digit(16).ok_or(HexError);
        *byte = (digit(pair[0])? << 4 | digit(pair[1])?) as u8;
    }
    Ok(bytes)
}

macro_rules! hex_value {
    ($name:ident) => {
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&lower_hex(&self.0))
            }
        }

        impl FromStr for $name {
            type Err = HexError;

            fn from_str(text: &str) -> std::result::Result<Self, HexError> {
                decode_hex(text).map(Self)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(
                deserializer: D,
            ) -> std::result::Result<Self, D::Error> {
                String::deserialize(deserializer)?
                    .parse()
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}

hex_value!(PolicyNonce);
hex_value!(PolicyHash);
