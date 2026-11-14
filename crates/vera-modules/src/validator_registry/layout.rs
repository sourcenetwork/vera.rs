//! Storage layout of the registry account, shared by execution and genesis.
//!
//! Slot 0 holds the managing policy identifier, slot 1 the member count, slot 2
//! the member address array and slot 3 the address-to-record mapping. A record
//! occupies five consecutive slots: packed address and active flag, consensus
//! key, array index, network address length and network address bytes.

use alloy_primitives::{Address, U256, keccak256};

/// Account whose storage holds the registry.
pub const ADDRESS: Address = {
    let mut bytes = [0u8; 20];
    bytes[18] = 0x08;
    bytes[19] = 0x13;
    Address::new(bytes)
};

/// Longest network address a record stores, in bytes: one storage slot.
pub const MAX_P2P_ADDRESS_LEN: usize = 32;

/// Slot of the managing policy identifier.
pub const SLOT_POLICY_ID: U256 = U256::ZERO;
/// Slot of the member count.
pub const SLOT_VALIDATOR_COUNT: U256 = U256::from_limbs([1, 0, 0, 0]);
/// Base slot of the member address array.
pub const SLOT_VALIDATORS_ARRAY_BASE: U256 = U256::from_limbs([2, 0, 0, 0]);
/// Base slot of the address-to-record mapping.
pub const SLOT_VALIDATORS_MAPPING_BASE: U256 = U256::from_limbs([3, 0, 0, 0]);

/// First slot of the record `key` maps to under `base`.
pub fn mapping_slot(key: Address, base: U256) -> U256 {
    let mut buf = [0u8; 64];
    buf[12..32].copy_from_slice(key.as_slice());
    buf[32..64].copy_from_slice(&base.to_be_bytes::<32>());
    U256::from_be_bytes(keccak256(buf).0)
}

/// Slot of element `index` in the array rooted at `base`.
pub fn array_element_slot(base: U256, index: u64) -> U256 {
    let hash = keccak256(base.to_be_bytes::<32>());
    U256::from_be_bytes(hash.0).wrapping_add(U256::from(index))
}

/// A record's first slot: the address followed by its active flag.
pub fn pack_address_active(addr: Address, active: bool) -> U256 {
    let mut bytes = [0u8; 32];
    bytes[..20].copy_from_slice(addr.as_slice());
    bytes[20] = u8::from(active);
    U256::from_be_bytes(bytes)
}

/// The address and active flag held in a record's first slot.
pub fn unpack_address_active(val: U256) -> (Address, bool) {
    let bytes = val.to_be_bytes::<32>();
    (Address::from_slice(&bytes[..20]), bytes[20] != 0)
}

/// An array element: the address left-padded to a slot.
pub fn address_to_padded_u256(addr: Address) -> U256 {
    let mut buf = [0u8; 32];
    buf[12..32].copy_from_slice(addr.as_slice());
    U256::from_be_bytes(buf)
}

/// The address held in an array element.
pub fn u256_to_address(val: U256) -> Address {
    Address::from_slice(&val.to_be_bytes::<32>()[12..32])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_of_different_addresses_do_not_share_slots() {
        let a = mapping_slot(Address::repeat_byte(0x01), SLOT_VALIDATORS_MAPPING_BASE);
        let b = mapping_slot(Address::repeat_byte(0x02), SLOT_VALIDATORS_MAPPING_BASE);
        assert_ne!(a, b);
    }

    #[test]
    fn array_elements_are_consecutive() {
        let first = array_element_slot(SLOT_VALIDATORS_ARRAY_BASE, 0);
        let second = array_element_slot(SLOT_VALIDATORS_ARRAY_BASE, 1);
        assert_eq!(second, first.wrapping_add(U256::from(1)));
    }

    #[test]
    fn packed_slots_read_back() {
        let addr = Address::repeat_byte(0xAB);
        assert_eq!(
            unpack_address_active(pack_address_active(addr, true)),
            (addr, true)
        );
        assert_eq!(
            unpack_address_active(pack_address_active(addr, false)),
            (addr, false)
        );
        assert_eq!(u256_to_address(address_to_padded_u256(addr)), addr);
    }
}
