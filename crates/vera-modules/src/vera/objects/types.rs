use super::{Result, invalid};
use crate::types::Timestamp;
use orbis_reporting::codec::{
    write_bytes, write_optional_string, write_optional_u64, write_string,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const MAX_OBJECT_REQUEST_BYTES: usize = 512 << 10;
pub const MAX_OBJECT_RECORD_BYTES: usize = 1 << 20;
pub const MAX_PET_FIELD_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    Document,
    KeyDerivation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedDocument {
    pub ring_id: String,
    pub document: String,
    pub proof: String,
    pub policy_id: String,
    pub resource: String,
    pub permission: String,
    pub tier: Option<String>,
    pub timestamp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pet_tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pet_tag_proof: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyDerivation {
    pub ring_id: String,
    pub derivation: String,
    pub policy_id: String,
    pub resource: String,
    pub permission: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "payload",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ThresholdObject {
    Document(EncryptedDocument),
    KeyDerivation(KeyDerivation),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectRecord {
    pub id: String,
    pub deployment_root: [u8; 32],
    pub creator: String,
    pub revision: Timestamp,
    pub object: ThresholdObject,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredObject {
    pub id: String,
    pub kind: ObjectKind,
    pub revision: Timestamp,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Secret {
    enc_cmt: Vec<u8>,
    encrypted_data: Vec<u8>,
    nonce: Vec<u8>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PetTag {
    ephemeral_point: Vec<u8>,
    masked_fingerprint: Vec<u8>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    challenge: Vec<u8>,
    response: Vec<u8>,
}

fn identifier(id: &str) -> Result<()> {
    if id.len() != 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("invalid object or policy identifier"));
    }
    Ok(())
}
fn text(value: &str, limit: usize) -> Result<()> {
    if value.is_empty() || value.len() > limit || value.contains('\0') {
        return Err(invalid("empty or oversized object field"));
    }
    Ok(())
}
pub fn object_key(kind: ObjectKind, id: &str) -> Result<Vec<u8>> {
    identifier(id)?;
    let namespace = match kind {
        ObjectKind::Document => "document",
        ObjectKind::KeyDerivation => "derivation",
    };
    Ok(format!("orbis/{namespace}/v1/{id}").into_bytes())
}

impl ThresholdObject {
    pub const fn kind(&self) -> ObjectKind {
        match self {
            Self::Document(_) => ObjectKind::Document,
            Self::KeyDerivation(_) => ObjectKind::KeyDerivation,
        }
    }
    pub fn ring_id(&self) -> &str {
        match self {
            Self::Document(d) => &d.ring_id,
            Self::KeyDerivation(d) => &d.ring_id,
        }
    }
    pub fn validate(&self) -> Result<()> {
        if serde_json::to_vec(self).map_err(invalid)?.len() > MAX_OBJECT_REQUEST_BYTES {
            return Err(invalid("object request exceeds byte limit"));
        }
        identifier(self.ring_id())?;
        let (policy, resource, permission) = match self {
            Self::Document(d) => {
                text(&d.document, MAX_OBJECT_REQUEST_BYTES)?;
                text(&d.proof, 4096)?;
                if let Some(tier) = &d.tier {
                    text(tier, 256)?;
                }
                (&d.policy_id, &d.resource, &d.permission)
            }
            Self::KeyDerivation(d) => {
                text(&d.derivation, 4096)?;
                (&d.policy_id, &d.resource, &d.permission)
            }
        };
        identifier(policy)?;
        text(resource, 256)?;
        text(permission, 256)?;
        self.id()?;
        Ok(())
    }

    /// Canonical identity used by current Rust Orbis consumers, independent of JSON whitespace.
    pub fn id(&self) -> Result<String> {
        let mut bytes = Vec::new();
        match self {
            Self::Document(d) => {
                if d.document.len() > MAX_OBJECT_REQUEST_BYTES || d.proof.len() > 4096 {
                    return Err(invalid("document or proof exceeds byte limit"));
                }
                let secret: Secret = serde_json::from_str(&d.document).map_err(invalid)?;
                let proof: Proof = serde_json::from_str(&d.proof).map_err(invalid)?;
                write_string(&mut bytes, "orbis/document/v1");
                write_string(&mut bytes, &d.ring_id);
                for field in [
                    &secret.enc_cmt,
                    &secret.encrypted_data,
                    &secret.nonce,
                    &proof.challenge,
                    &proof.response,
                ] {
                    if field.is_empty() {
                        return Err(invalid("empty ciphertext or proof field"));
                    }
                    write_bytes(&mut bytes, field);
                }
                write_string(&mut bytes, &d.policy_id);
                write_string(&mut bytes, &d.resource);
                write_string(&mut bytes, &d.permission);
                write_optional_string(&mut bytes, d.tier.as_deref());
                write_optional_u64(&mut bytes, d.timestamp);
                d.write_pet_attachment(&mut bytes)?;
            }
            Self::KeyDerivation(d) => {
                write_string(&mut bytes, "orbis/key_derivation/v1");
                for field in [
                    &d.ring_id,
                    &d.derivation,
                    &d.policy_id,
                    &d.resource,
                    &d.permission,
                ] {
                    write_string(&mut bytes, field);
                }
            }
        }
        Ok(hex::encode(Sha256::digest(bytes)))
    }
}

impl EncryptedDocument {
    fn write_pet_attachment(&self, bytes: &mut Vec<u8>) -> Result<()> {
        match (self.pet_tag.as_deref(), self.pet_tag_proof.as_deref()) {
            (None, None) => Ok(()),
            (Some(tag), Some(proof)) => {
                text(tag, MAX_PET_FIELD_BYTES)?;
                text(proof, MAX_PET_FIELD_BYTES)?;
                let tag: PetTag = serde_json::from_str(tag).map_err(invalid)?;
                let proof: Proof = serde_json::from_str(proof).map_err(invalid)?;
                for field in [
                    &tag.ephemeral_point,
                    &tag.masked_fingerprint,
                    &proof.challenge,
                    &proof.response,
                ] {
                    if field.is_empty() {
                        return Err(invalid("empty PET tag or proof field"));
                    }
                    write_bytes(bytes, field);
                }
                Ok(())
            }
            _ => Err(invalid("PET tag and proof must be present together")),
        }
    }
}

impl ObjectRecord {
    pub fn validate(&self, kind: ObjectKind, id: &str) -> Result<()> {
        self.object.validate()?;
        identity::Did::new(&self.creator).map_err(invalid)?;
        if self.id != id
            || self.object.id()? != id
            || self.object.kind() != kind
            || self.deployment_root == [0; 32]
            || self.revision.block_height == 0
        {
            return Err(invalid("object record identity or revision mismatch"));
        }
        Ok(())
    }
}
