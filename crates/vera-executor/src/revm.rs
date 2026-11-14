//! Conversions between signed EVM transactions, REVM and execution results.

use std::collections::BTreeMap;

use alloy_primitives::{B256, Bytes, U256};
use revm::{
    bytecode::Bytecode,
    context::result::{ExecutionResult, Output},
    context_interface::transaction::{AccessList, AccessListItem},
    primitives::TxKind,
    state::{EvmState, EvmStorageSlot},
};
use vera_qmdb::{AccountUpdate, ChangeSet};

/// The EVM specification revision used for execution.
pub use revm::primitives::hardfork::SpecId;

use crate::{ExecutionError, ExecutionReceipt};

/// Decode EVM transaction bytes, returning both the REVM TxEnv and the signer's `did:key:`.
///
/// Single decode + EC recovery pass: builds the TxEnv for REVM execution and
/// recovers the secp256k1 public key for `did:key:` construction. Only the
/// canonical EIP-2718 encoding of a replay-protected transaction is accepted.
pub fn decode_evm_tx(tx_bytes: &Bytes) -> Result<(revm::context::TxEnv, String), ExecutionError> {
    use alloy_consensus::TxEnvelope;

    let envelope = crate::envelope::decode_envelope(tx_bytes)?;

    let mut builder = revm::context::TxEnv::builder();

    match &envelope {
        TxEnvelope::Legacy(signed) => {
            let tx = signed.tx();
            let caller = signed
                .recover_signer()
                .map_err(|e| ExecutionError::TxDecode(format!("failed to recover signer: {e}")))?;

            builder = builder
                .caller(caller)
                .gas_limit(tx.gas_limit)
                .gas_price(tx.gas_price)
                .value(tx.value)
                .data(tx.input.clone())
                .nonce(tx.nonce)
                .chain_id(tx.chain_id)
                .kind(convert_tx_kind(tx.to));
        }
        TxEnvelope::Eip2930(signed) => {
            let tx = signed.tx();
            let caller = signed
                .recover_signer()
                .map_err(|e| ExecutionError::TxDecode(format!("failed to recover signer: {e}")))?;

            builder = builder
                .caller(caller)
                .gas_limit(tx.gas_limit)
                .gas_price(tx.gas_price)
                .value(tx.value)
                .data(tx.input.clone())
                .nonce(tx.nonce)
                .chain_id(Some(tx.chain_id))
                .kind(convert_tx_kind(tx.to))
                .access_list(convert_access_list(&tx.access_list));
        }
        TxEnvelope::Eip1559(signed) => {
            let tx = signed.tx();
            let caller = signed
                .recover_signer()
                .map_err(|e| ExecutionError::TxDecode(format!("failed to recover signer: {e}")))?;

            builder = builder
                .caller(caller)
                .gas_limit(tx.gas_limit)
                .gas_price(tx.max_fee_per_gas)
                .gas_priority_fee(Some(tx.max_priority_fee_per_gas))
                .value(tx.value)
                .data(tx.input.clone())
                .nonce(tx.nonce)
                .chain_id(Some(tx.chain_id))
                .kind(convert_tx_kind(tx.to))
                .access_list(convert_access_list(&tx.access_list));
        }
        TxEnvelope::Eip4844(signed) => {
            let tx = signed.tx().tx();
            let caller = signed
                .recover_signer()
                .map_err(|e| ExecutionError::TxDecode(format!("failed to recover signer: {e}")))?;

            builder = builder
                .caller(caller)
                .gas_limit(tx.gas_limit)
                .gas_price(tx.max_fee_per_gas)
                .gas_priority_fee(Some(tx.max_priority_fee_per_gas))
                .value(tx.value)
                .data(tx.input.clone())
                .nonce(tx.nonce)
                .chain_id(Some(tx.chain_id))
                .kind(TxKind::Call(tx.to))
                .access_list(convert_access_list(&tx.access_list))
                .max_fee_per_blob_gas(tx.max_fee_per_blob_gas)
                .blob_hashes(tx.blob_versioned_hashes.clone());
        }
        TxEnvelope::Eip7702(signed) => {
            let tx = signed.tx();
            let caller = signed
                .recover_signer()
                .map_err(|e| ExecutionError::TxDecode(format!("failed to recover signer: {e}")))?;

            builder = builder
                .caller(caller)
                .gas_limit(tx.gas_limit)
                .gas_price(tx.max_fee_per_gas)
                .gas_priority_fee(Some(tx.max_priority_fee_per_gas))
                .value(tx.value)
                .data(tx.input.clone())
                .nonce(tx.nonce)
                .chain_id(Some(tx.chain_id))
                .kind(TxKind::Call(tx.to))
                .access_list(convert_access_list(&tx.access_list))
                .authorization_list(convert_authorization_list(&tx.authorization_list));
        }
    }

    let tx_env = builder
        .build()
        .map_err(|e| ExecutionError::TxDecode(format!("failed to build tx env: {e:?}")))?;

    let signer_did =
        vera_crypto::secp256k1::recover_did(envelope.signature(), &envelope.signature_hash())
            .map_err(|e| ExecutionError::SignerDidRecovery(e.to_string()))?;

    Ok((tx_env, signer_did))
}

/// Convert alloy TxKind to revm TxKind.
pub const fn convert_tx_kind(kind: alloy_primitives::TxKind) -> TxKind {
    match kind {
        alloy_primitives::TxKind::Call(addr) => TxKind::Call(addr),
        alloy_primitives::TxKind::Create => TxKind::Create,
    }
}

/// Convert alloy AccessList to revm AccessList.
pub fn convert_access_list(access_list: &alloy_eips::eip2930::AccessList) -> AccessList {
    AccessList(
        access_list
            .iter()
            .map(|item| AccessListItem {
                address: item.address,
                storage_keys: item.storage_keys.clone(),
            })
            .collect(),
    )
}

/// Convert alloy authorization list to revm authorization list.
pub fn convert_authorization_list(
    auth_list: &[alloy_eips::eip7702::SignedAuthorization],
) -> Vec<
    revm::context_interface::either::Either<
        revm::context_interface::transaction::SignedAuthorization,
        revm::context_interface::transaction::RecoveredAuthorization,
    >,
> {
    use alloy_eips::eip7702::RecoveredAuthority;

    auth_list
        .iter()
        .map(|auth| {
            // Build the inner authorization
            let inner = revm::context_interface::transaction::Authorization {
                chain_id: *auth.chain_id(),
                address: *auth.address(),
                nonce: auth.nonce(),
            };

            // Convert to recovered authorization - use Valid if recovery succeeds, Invalid otherwise
            let recovered_authority = auth
                .recover_authority()
                .map_or(RecoveredAuthority::Invalid, RecoveredAuthority::Valid);

            revm::context_interface::either::Either::Right(
                revm::context_interface::transaction::RecoveredAuthorization::new_unchecked(
                    inner,
                    recovered_authority,
                ),
            )
        })
        .collect()
}

/// Build a transaction receipt from execution result.
pub fn build_receipt(
    result: &ExecutionResult,
    tx_hash: B256,
    gas_used: u64,
    cumulative_gas_used: u64,
) -> ExecutionReceipt {
    let (success, logs, contract_address) = match result {
        ExecutionResult::Success { logs, output, .. } => {
            let contract_addr = match output {
                Output::Create(_, addr) => *addr,
                Output::Call(_) => None,
            };
            // REVM logs are already alloy_primitives::Log, just clone them
            (true, logs.clone(), contract_addr)
        }
        ExecutionResult::Revert { .. } => (false, Vec::new(), None),
        ExecutionResult::Halt { .. } => (false, Vec::new(), None),
    };

    ExecutionReceipt::new(
        tx_hash,
        success,
        gas_used,
        cumulative_gas_used,
        logs,
        contract_address,
    )
}

/// Extract state changes from REVM execution state.
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
    use alloy_primitives::{Address, KECCAK256_EMPTY};
    use revm::context::result::ResultGas;
    use revm::state::Account;
    use revm::state::TransactionId;

    use super::*;

    #[test]
    fn build_receipt_success() {
        let result = ExecutionResult::Success {
            reason: revm::context::result::SuccessReason::Stop,
            gas: ResultGas::default().with_total_gas_spent(21000),
            logs: vec![],
            output: Output::Call(Bytes::new()),
        };

        let receipt = build_receipt(&result, B256::ZERO, 21000, 21000);
        assert!(receipt.success());
        assert_eq!(receipt.gas_used, 21000);
        assert_eq!(receipt.cumulative_gas_used(), 21000);
        assert!(receipt.logs().is_empty());
        assert!(receipt.contract_address.is_none());
    }

    #[test]
    fn build_receipt_revert() {
        let result = ExecutionResult::Revert {
            gas: ResultGas::default().with_total_gas_spent(21000),
            logs: vec![],
            output: Bytes::new(),
        };

        let receipt = build_receipt(&result, B256::ZERO, 21000, 21000);
        assert!(!receipt.success());
        assert_eq!(receipt.gas_used, 21000);
    }

    #[test]
    fn build_receipt_halt() {
        let result = ExecutionResult::Halt {
            reason: revm::context::result::HaltReason::OutOfGas(
                revm::context::result::OutOfGasError::Basic,
            ),
            gas: ResultGas::default().with_total_gas_spent(21000),
            logs: vec![],
        };

        let receipt = build_receipt(&result, B256::ZERO, 21000, 21000);
        assert!(!receipt.success());
        assert_eq!(receipt.gas_used, 21000);
    }

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
