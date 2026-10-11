//! Shared module state container for block-scoped execution.

use std::sync::{Arc, RwLock};

use alloy_primitives::{B256, keccak256};

use crate::{
    acp::AcpModule, bulletin::BulletinModule, kv_store::InMemoryKvStore,
    native_account::NativeNonceStore, vera::VeraModule,
};

const MODULE_ROOT_NAMESPACE: &[u8] = b"_HUB_MODULE_ROOT";

/// Logical record changes in ACP, bulletin, identity and native sequence order.
/// Each module's keys are unique and sorted; `None` deletes a record.
pub type ModuleChanges = [Vec<(Vec<u8>, Option<Vec<u8>>)>; 4];

/// All four mutable module instances for a single block execution.
#[derive(Clone, Debug, Default)]
pub struct ModuleState {
    /// Access Control Policy module.
    pub acp: AcpModule,
    /// Bulletin module.
    pub bulletin: BulletinModule,
    /// Vera module.
    pub vera: VeraModule,
    /// Native account nonce store.
    pub nonces: NativeNonceStore,
}

impl ModuleState {
    /// Compare logical records across snapshots, including mutations before intermediate clones.
    pub fn diff_from(&self, parent: &Self) -> ModuleChanges {
        let stores = [
            self.acp.store(),
            self.bulletin.store(),
            self.vera.store(),
            self.nonces.store(),
        ];
        let parents = [
            parent.acp.store(),
            parent.bulletin.store(),
            parent.vera.store(),
            parent.nonces.store(),
        ];
        std::array::from_fn(|i| stores[i].diff_from(parents[i]))
    }

    /// Compute a deterministic state root from all module stores.
    ///
    /// Uses keccak256-based hashing of serialized stores. Native deployments
    /// combine the four authenticated QMDB roots with `combine_module_roots` instead.
    pub fn state_root(&self) -> B256 {
        let acp_bytes = self.acp.store().serialize();
        let bulletin_bytes = self.bulletin.store().serialize();
        let vera_bytes = self.vera.store().serialize();
        let nonce_bytes = self.nonces.store().serialize();

        let mut buf = Vec::with_capacity(MODULE_ROOT_NAMESPACE.len() + 128);
        buf.extend_from_slice(MODULE_ROOT_NAMESPACE);
        buf.extend_from_slice(keccak256(&acp_bytes).as_slice());
        buf.extend_from_slice(keccak256(&bulletin_bytes).as_slice());
        buf.extend_from_slice(keccak256(&vera_bytes).as_slice());
        buf.extend_from_slice(keccak256(&nonce_bytes).as_slice());
        keccak256(buf)
    }

    /// Serialize each module's store for persistence.
    pub fn serialize_stores(&self) -> [Vec<u8>; 4] {
        [
            self.acp.store().serialize(),
            self.bulletin.store().serialize(),
            self.vera.store().serialize(),
            self.nonces.store().serialize(),
        ]
    }

    /// Reconstruct from deserialized stores.
    pub fn from_stores(stores: [InMemoryKvStore; 4]) -> Self {
        let [acp_store, bulletin_store, vera_store, nonce_store] = stores;
        Self {
            acp: AcpModule::from_store(acp_store),
            bulletin: BulletinModule::from_store(bulletin_store),
            vera: VeraModule::from_store(vera_store),
            nonces: NativeNonceStore::from_store(nonce_store),
        }
    }
}

/// Compute the combined module state root from pre-computed per-module roots.
///
/// `keccak256(namespace || roots[0] || roots[1] || roots[2] || roots[3])`
///
/// Root order: `[acp, bulletin, vera, nonces]`.
pub fn combine_module_roots(roots: &[[u8; 32]; 4]) -> B256 {
    let mut buf = Vec::with_capacity(MODULE_ROOT_NAMESPACE.len() + 128);
    buf.extend_from_slice(MODULE_ROOT_NAMESPACE);
    for root in roots {
        buf.extend_from_slice(root);
    }
    keccak256(buf)
}

/// Thread-safe shared module state for use across block executions.
pub type SharedModuleState = Arc<RwLock<ModuleState>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_state_root_is_deterministic() {
        let s1 = ModuleState::default();
        let s2 = ModuleState::default();
        assert_eq!(s1.state_root(), s2.state_root());
        assert_ne!(s1.state_root(), B256::ZERO);
    }

    #[test]
    fn state_root_changes_with_data() {
        let s1 = ModuleState::default();
        let root_empty = s1.state_root();

        let mut s2 = ModuleState::default();
        s2.nonces
            .check_and_increment("did:key:z6MkAlice", 0)
            .unwrap();
        let root_with_nonce = s2.state_root();

        assert_ne!(root_empty, root_with_nonce);
    }

    #[test]
    fn combine_module_roots_deterministic() {
        let roots = [[0xAAu8; 32], [0xBBu8; 32], [0xCCu8; 32], [0xDDu8; 32]];
        let r1 = combine_module_roots(&roots);
        let r2 = combine_module_roots(&roots);
        assert_eq!(r1, r2);
        assert_ne!(r1, B256::ZERO);
    }

    #[test]
    fn combine_module_roots_sensitive_to_order() {
        let roots_a = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let roots_b = [[2u8; 32], [1u8; 32], [3u8; 32], [4u8; 32]];
        assert_ne!(
            combine_module_roots(&roots_a),
            combine_module_roots(&roots_b)
        );
    }

    #[test]
    fn serialize_and_from_stores_roundtrip() {
        let mut state = ModuleState::default();
        state
            .nonces
            .check_and_increment("did:key:z6MkAlice", 0)
            .unwrap();

        let stores = state.serialize_stores();
        let deserialized = [
            InMemoryKvStore::deserialize(&stores[0]).unwrap(),
            InMemoryKvStore::deserialize(&stores[1]).unwrap(),
            InMemoryKvStore::deserialize(&stores[2]).unwrap(),
            InMemoryKvStore::deserialize(&stores[3]).unwrap(),
        ];
        let restored = ModuleState::from_stores(deserialized);

        assert_eq!(state.state_root(), restored.state_root());
        assert_eq!(restored.nonces.get_nonce("did:key:z6MkAlice").unwrap(), 1);
    }
}
