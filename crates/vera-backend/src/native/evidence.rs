//! Budget and storage helpers shared by the native proof generators.

use bytes::Bytes;
use commonware_codec::{Encode as _, EncodeSize as _};
use vera_permission::PermissionError;

use super::{BackendError, NativeDb};

pub(super) fn charge(remaining: &mut usize, amount: usize) -> Result<(), PermissionError> {
    *remaining = remaining
        .checked_sub(amount)
        .ok_or(PermissionError::Limit)?;
    Ok(())
}

pub(super) fn storage(error: impl std::fmt::Display) -> BackendError {
    BackendError::Storage(error.to_string())
}

/// Encode membership evidence for a present key, or exclusion evidence for an
/// absent one, refusing evidence larger than `max_bytes`.
pub(super) async fn point_evidence(
    db: &NativeDb,
    key: &[u8],
    present: bool,
    max_bytes: usize,
) -> Result<Bytes, BackendError> {
    let key = key.to_vec();
    let (size, encoded) = if present {
        let evidence = db.key_value_proof(key).await.map_err(storage)?;
        (evidence.encode_size(), evidence.encode())
    } else {
        let evidence = db.exclusion_proof(&key).await.map_err(storage)?;
        (evidence.encode_size(), evidence.encode())
    };
    if size > max_bytes {
        return Err(PermissionError::Limit.into());
    }
    Ok(encoded)
}
