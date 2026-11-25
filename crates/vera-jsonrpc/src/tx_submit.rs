//! The node's admission entry point for submitted requests.

use std::{future::Future, pin::Pin, sync::Arc};

use alloy_primitives::Bytes;

/// Request submission callback type.
///
/// Called when a native request is submitted via `vera_sendNativeTx`.
/// Returns acceptance, duplicate status, or a classified admission failure.
pub type TxSubmitCallback = Arc<
    dyn Fn(Bytes) -> Pin<Box<dyn Future<Output = Result<bool, crate::TxSubmitError>> + Send>>
        + Send
        + Sync,
>;
