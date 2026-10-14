//! DID identity types.
//!
//! Vendored from defradb.rs at 8d34d9c (trimmed to the `Did` surface vera
//! uses). The upstream crate additionally carries key management, raw
//! identities and JWT token material; vera implements those in vera-crypto.

mod did;
mod error;

pub use did::{Did, DID_KEY_PREFIX, DID_OPK_PREFIX};
pub use error::{Error, Result};
