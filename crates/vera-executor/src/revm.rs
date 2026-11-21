//! State changes recorded by the journal that hosts registry storage.

use std::collections::BTreeMap;

use alloy_primitives::U256;
use revm::{
    bytecode::Bytecode,
    state::{EvmState, EvmStorageSlot},
};
use vera_qmdb::{AccountUpdate, ChangeSet};

/// The revision of the journal that hosts registry storage.
pub use revm::primitives::hardfork::SpecId;

/// Extract the state changes a journal recorded.
pub fn extract_changes(state: &EvmState) -> ChangeSet {
    let mut changes = ChangeSet::new();

    for (address, account) in state {
        // Skip untouched accounts
        if !account.is_touched() {
            continue;
        }

        // A slot that was only read keeps its stored value and needs no write.
        let storage: BTreeMap<U256, U256> = account
            .storage
            .iter()
            .filter(|(_, slot)| slot.is_changed())
            .map(|(k, v): (&U256, &EvmStorageSlot)| (*k, v.present_value()))
            .collect();

        // REVM pads analyzed bytecode; the deployed bytes are the ones that hash to `code_hash`.
        let code = account
            .info
            .code
            .as_ref()
            .map(|c: &Bytecode| c.original_bytes().to_vec());

        let update = AccountUpdate {
            created: account.is_created(),
            selfdestructed: account.is_selfdestructed(),
            nonce: account.info.nonce,
            balance: account.info.balance,
            code_hash: account.info.code_hash,
            code,
            storage,
        };

        changes.insert(*address, update);
    }

    changes
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, Bytes, KECCAK256_EMPTY};
    use revm::state::Account;
    use revm::state::TransactionId;

    use super::*;

    #[test]
    fn extract_changes_empty() {
        let state = EvmState::default();
        let changes = extract_changes(&state);
        assert!(changes.is_empty());
    }

    #[test]
    fn extract_changes_touched_account() {
        use revm::state::AccountStatus;

        let mut state = EvmState::default();

        let mut account = Account::default();
        account.info.nonce = 1;
        account.info.balance = U256::from(1000);
        account.info.code_hash = KECCAK256_EMPTY;
        account.status = AccountStatus::Touched;

        // Add a storage change
        account.storage.insert(
            U256::from(1),
            EvmStorageSlot::new_changed(U256::ZERO, U256::from(42), TransactionId::ZERO),
        );

        state.insert(Address::ZERO, account);

        let changes = extract_changes(&state);
        assert_eq!(changes.len(), 1);

        let update = changes.accounts.get(&Address::ZERO).unwrap();
        assert_eq!(update.nonce, 1);
        assert_eq!(update.balance, U256::from(1000));
        assert_eq!(update.storage.get(&U256::from(1)), Some(&U256::from(42)));
    }

    #[test]
    fn extract_changes_skips_slots_that_were_only_read() {
        let mut account = Account::default();
        account.mark_touch();
        account.storage.insert(
            U256::from(1),
            EvmStorageSlot::new(U256::from(7), TransactionId::ZERO),
        );
        account.storage.insert(
            U256::from(2),
            EvmStorageSlot::new_changed(U256::from(7), U256::ZERO, TransactionId::ZERO),
        );
        let mut state = EvmState::default();
        state.insert(Address::ZERO, account);

        let changes = extract_changes(&state);

        let update = changes.accounts.get(&Address::ZERO).unwrap();
        assert_eq!(
            update.storage,
            BTreeMap::from([(U256::from(2), U256::ZERO)])
        );
    }

    #[test]
    fn extract_changes_keeps_deployed_code_unpadded() {
        let deployed = Bytes::from_static(&[0x60, 0x2a, 0x60, 0x00, 0x55]);
        let code = Bytecode::new_raw(deployed.clone());
        assert_ne!(code.bytes(), deployed);

        let mut account = Account::default();
        account.mark_touch();
        account.info.code_hash = code.hash_slow();
        account.info.code = Some(code);
        let mut state = EvmState::default();
        state.insert(Address::ZERO, account);

        let changes = extract_changes(&state);

        let update = changes.accounts.get(&Address::ZERO).unwrap();
        assert_eq!(update.code.as_deref(), Some(deployed.as_ref()));
        assert_eq!(
            alloy_primitives::keccak256(update.code.as_ref().unwrap()),
            update.code_hash
        );
    }

    #[test]
    fn extract_changes_untouched_skipped() {
        use revm::state::AccountStatus;

        let mut state = EvmState::default();

        let mut account = Account::default();
        account.info.nonce = 1;
        account.info.balance = U256::from(1000);
        account.status = AccountStatus::empty(); // Not touched

        state.insert(Address::ZERO, account);

        let changes = extract_changes(&state);
        assert!(changes.is_empty());
    }

    #[test]
    fn extract_changes_created_account() {
        let mut state = EvmState::default();

        // Created accounts also need to be touched to be processed
        let mut account = Account::default();
        account.mark_created();
        account.mark_touch();

        state.insert(Address::ZERO, account);

        let changes = extract_changes(&state);
        assert_eq!(changes.len(), 1);

        let update = changes.accounts.get(&Address::ZERO).unwrap();
        assert!(update.created);
    }

    #[test]
    fn extract_changes_selfdestructed() {
        use revm::state::AccountStatus;

        let mut state = EvmState::default();

        let mut account = Account::default();
        account.info.nonce = 5;
        account.info.balance = U256::from(100);
        // SelfDestructed accounts also need to be touched to be processed
        account.status = AccountStatus::SelfDestructed | AccountStatus::Touched;

        state.insert(Address::ZERO, account);

        let changes = extract_changes(&state);
        assert_eq!(changes.len(), 1);

        let update = changes.accounts.get(&Address::ZERO).unwrap();
        assert!(update.selfdestructed);
    }
}
