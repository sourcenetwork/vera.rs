//! The format marker of a finalized-history store.

/// Store key holding the format marker.
pub(super) const FORMAT: &[u8] = b"format";
/// Layout of a store that has only appended its own execution.
pub(super) const FORMAT_APPENDED: [u8; 1] = [1];
/// Layout of a store that has begun importing history; recovery keeps its certified suffix.
pub(super) const FORMAT_IMPORTED: [u8; 1] = [3];

/// A finalized-history store carries a format marker this build does not
/// read. The store is left as it is.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unsupported finalized history format {found:?}")]
pub struct UnsupportedHistoryFormat {
    /// The marker the store carries.
    pub found: Vec<u8>,
}

/// Accept only the markers this build writes.
pub(super) fn check(found: &[u8]) -> Result<(), UnsupportedHistoryFormat> {
    if found == FORMAT_APPENDED || found == FORMAT_IMPORTED {
        Ok(())
    } else {
        Err(UnsupportedHistoryFormat {
            found: found.to_vec(),
        })
    }
}
