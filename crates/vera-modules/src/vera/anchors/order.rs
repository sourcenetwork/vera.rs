//! The running count of anchors this deployment recorded, across every deployment.
//!
//! Each recorded anchor takes the next number, so two anchors of different
//! deployments, even ones recorded in the same block, compare by it in the
//! order they executed.

use super::AnchorError;
use crate::kv_store::ModuleKvStore as _;
use crate::vera::VeraModule;

/// Storage key of the count in the identity partition.
pub const ANCHOR_ORDER_KEY: &[u8] = b"anchor-order/v1";

impl VeraModule {
    /// How many anchors this deployment recorded, across every deployment;
    /// the order of the latest one, or 0 before the first.
    pub fn anchors_recorded(&self) -> Result<u64, AnchorError> {
        self.store
            .get(ANCHOR_ORDER_KEY)
            .map_or(Ok(0), |bytes| decode_order(&bytes))
    }

    /// Take the order of the anchor being recorded and count it.
    pub(super) fn next_anchor_order(&mut self) -> Result<u64, AnchorError> {
        let order = self
            .anchors_recorded()?
            .checked_add(1)
            .ok_or(AnchorError::MalformedRecord)?;
        self.store
            .put(ANCHOR_ORDER_KEY, order.to_be_bytes().to_vec());
        Ok(order)
    }
}

/// Decode the stored count: eight big-endian bytes, never zero.
pub fn decode_order(bytes: &[u8]) -> Result<u64, AnchorError> {
    let order = u64::from_be_bytes(bytes.try_into().map_err(|_| AnchorError::MalformedRecord)?);
    if order == 0 {
        return Err(AnchorError::MalformedRecord);
    }
    Ok(order)
}
