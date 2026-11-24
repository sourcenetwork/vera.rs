//! Stored member records and their keys.

use alloy_primitives::Address;
use borsh::{BorshDeserialize, BorshSerialize};

use super::error::ValidatorRegistryError;
use crate::kv_store::ModuleKvStore as _;
use crate::vera::VeraModule;

const MEMBER_PREFIX: &[u8] = b"registry/member/";

/// Longest network address a record stores, in bytes. Every IPv4 and IPv6
/// socket address without a zone fits.
pub const MAX_P2P_ADDRESS_LEN: usize = 64;

/// One member of the registry, stored under its address.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MemberRecord {
    /// Ed25519 consensus key.
    pub consensus_key: [u8; 32],
    /// Socket address peers dial.
    pub p2p_address: String,
    /// Whether the member is selected into future committees.
    pub active: bool,
    /// Sequence the member's next signed address update must carry.
    pub address_sequence: u64,
}

fn member_key(address: Address) -> Vec<u8> {
    [MEMBER_PREFIX, address.as_slice()].concat()
}

/// Check that `address` is a socket address a record can hold.
pub fn validate_p2p_address(address: &str) -> Result<(), ValidatorRegistryError> {
    if address.is_empty() {
        return Err(ValidatorRegistryError::InvalidP2PAddress("empty".into()));
    }
    if address.len() > MAX_P2P_ADDRESS_LEN {
        return Err(ValidatorRegistryError::InvalidP2PAddress(format!(
            "exceeds {MAX_P2P_ADDRESS_LEN} bytes"
        )));
    }
    address
        .parse::<std::net::SocketAddr>()
        .map_err(|error| ValidatorRegistryError::InvalidP2PAddress(error.to_string()))?;
    Ok(())
}

fn decode(key: &[u8], value: &[u8]) -> Result<(Address, MemberRecord), ValidatorRegistryError> {
    let corrupt = |reason: &str| ValidatorRegistryError::Corrupt(reason.into());
    let address = key
        .strip_prefix(MEMBER_PREFIX)
        .filter(|bytes| bytes.len() == Address::len_bytes())
        .map(Address::from_slice)
        .filter(|address| *address != Address::ZERO)
        .ok_or_else(|| corrupt("member key is not an address"))?;
    let record: MemberRecord =
        borsh::from_slice(value).map_err(|_| corrupt("member record does not decode"))?;
    if validate_p2p_address(&record.p2p_address).is_err() {
        return Err(corrupt("member record holds an invalid network address"));
    }
    Ok((address, record))
}

impl VeraModule {
    /// Every member in address order.
    pub fn registry_members(&self) -> Result<Vec<(Address, MemberRecord)>, ValidatorRegistryError> {
        self.store
            .prefix_iter(MEMBER_PREFIX)
            .map(|(key, value)| decode(key, value))
            .collect()
    }

    /// The member registered at `address`.
    pub fn registry_member(
        &self,
        address: Address,
    ) -> Result<Option<MemberRecord>, ValidatorRegistryError> {
        let key = member_key(address);
        self.store
            .get_ref(&key)
            .map(|value| decode(&key, value).map(|(_, record)| record))
            .transpose()
    }

    pub(super) fn put_member(&mut self, address: Address, record: &MemberRecord) {
        let value = borsh::to_vec(record).expect("member records serialize");
        self.store.put(&member_key(address), value);
    }

    pub(super) fn delete_member(&mut self, address: Address) {
        self.store.delete(&member_key(address));
    }
}
