//! Custom borsh serialization for `vera_identity::Did`.
//!
//! `Did` has no native borsh support. We serialize through the
//! `String` representation and reconstruct on deserialization.
//! Handles both `did:key:` DIDs (via `Did::new()`) and the wildcard
//! `"*"` (via `Did::wildcard()`).

use borsh::io::{Read, Write};
use borsh::{BorshDeserialize, BorshSerialize};
use vera_identity::Did;

pub(crate) fn serialize_did<W: Write>(did: &Did, writer: &mut W) -> borsh::io::Result<()> {
    let s: &str = did.as_ref();
    s.serialize(writer)
}

pub(crate) fn deserialize_did<R: Read>(reader: &mut R) -> borsh::io::Result<Did> {
    let s = String::deserialize_reader(reader)?;
    if s == "*" {
        return Ok(Did::wildcard());
    }
    Did::new(s).map_err(|e| borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_borsh_roundtrip() {
        let did = Did::new("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap();

        let mut buf = Vec::new();
        serialize_did(&did, &mut buf).unwrap();

        let mut reader = &buf[..];
        let decoded = deserialize_did(&mut reader).unwrap();

        assert_eq!(did, decoded);
    }

    #[test]
    fn did_borsh_wildcard_roundtrip() {
        let did = Did::wildcard();

        let mut buf = Vec::new();
        serialize_did(&did, &mut buf).unwrap();

        let mut reader = &buf[..];
        let decoded = deserialize_did(&mut reader).unwrap();
        assert!(decoded.is_wildcard());
    }

    #[test]
    fn did_borsh_invalid_rejects() {
        let invalid = "not-a-did";
        let mut buf = Vec::new();
        invalid.serialize(&mut buf).unwrap();

        let mut reader = &buf[..];
        let result = deserialize_did(&mut reader);
        assert!(result.is_err());
    }
}
