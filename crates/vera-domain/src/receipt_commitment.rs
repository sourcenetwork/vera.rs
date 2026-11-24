use alloy_primitives::{B256, Keccak256};

use crate::ExecutionReceipt;

/// Commit the execution limit and ordered receipt fields using the v3 encoding.
/// Integers and collection lengths are big-endian u64; presence and status use one byte.
/// A refusal contributes its module and kind codes; its message is not committed.
/// Logs include their address, ordered topics and length-prefixed data, without copying.
pub fn receipt_commitment(gas_limit: u64, receipts: &[ExecutionReceipt]) -> B256 {
    let mut hash = Keccak256::new();
    hash.update(b"vera/receipts/v3");
    hash.update(gas_limit.to_be_bytes());
    hash.update((receipts.len() as u64).to_be_bytes());
    for receipt in receipts {
        hash.update(receipt.tx_hash);
        hash.update(receipt.gas_used.to_be_bytes());
        hash.update(receipt.cumulative_gas_used().to_be_bytes());
        hash.update([u8::from(receipt.success())]);
        match &receipt.refusal {
            Some(refusal) => hash.update([1, refusal.module.code(), refusal.kind.code()]),
            None => hash.update([0]),
        }
        hash.update((receipt.logs().len() as u64).to_be_bytes());
        for log in receipt.logs() {
            hash.update(log.address);
            hash.update((log.topics().len() as u64).to_be_bytes());
            for topic in log.topics() {
                hash.update(topic);
            }
            hash.update((log.data.data.len() as u64).to_be_bytes());
            hash.update(&log.data.data);
        }
    }
    hash.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, Log, keccak256};

    use crate::{Refusal, RefusalKind, RefusingModule};

    #[test]
    fn encoding_binds_every_receipt_field_and_collection_boundary() {
        let receipt = ExecutionReceipt::new(
            B256::repeat_byte(1),
            true,
            2,
            3,
            vec![Log::new_unchecked(
                Address::repeat_byte(4),
                vec![B256::repeat_byte(5)],
                vec![6, 7].into(),
            )],
        );
        let expected = [
            b"vera/receipts/v3".as_slice(),
            &9_u64.to_be_bytes(),
            &1_u64.to_be_bytes(),
            &[1; 32],
            &2_u64.to_be_bytes(),
            &3_u64.to_be_bytes(),
            &[1, 0],
            &1_u64.to_be_bytes(),
            &[4; 20],
            &1_u64.to_be_bytes(),
            &[5; 32],
            &2_u64.to_be_bytes(),
            &[6, 7],
        ]
        .concat();
        let root = receipt_commitment(9, std::slice::from_ref(&receipt));
        assert_eq!(root, keccak256(expected));
        assert_ne!(root, receipt_commitment(10, std::slice::from_ref(&receipt)));
        assert_ne!(root, receipt_commitment(9, &[]));
        for mutation in 0..11 {
            let mut changed = receipt.clone();
            match mutation {
                0 => changed.tx_hash.0[0] ^= 1,
                1 => changed.gas_used += 1,
                2 => changed.cumulative_gas_used += 1,
                3 => changed.success = false,
                4 => changed.logs[0].address = Address::ZERO,
                5 => {
                    changed.logs[0].data = alloy_primitives::LogData::new_unchecked(
                        vec![B256::ZERO],
                        vec![6, 7].into(),
                    )
                }
                6 => changed.logs[0].data.data = vec![6].into(),
                7 => changed.logs.clear(),
                8 => changed.logs.push(changed.logs[0].clone()),
                9 => changed = changed.with_refusal(Some(refusal(RefusalKind::InvalidPolicy, ""))),
                10 => {
                    changed.refusal = Some(Refusal::new(
                        RefusingModule::Bulletin,
                        RefusalKind::InvalidPolicy,
                        "",
                    ))
                }
                _ => unreachable!(),
            }
            assert_ne!(root, receipt_commitment(9, std::slice::from_ref(&changed)));
            assert_ne!(
                receipt_commitment(9, &[receipt.clone(), changed.clone()]),
                receipt_commitment(9, &[changed, receipt.clone()]),
            );
        }
    }

    fn refusal(kind: RefusalKind, message: &str) -> Refusal {
        Refusal::new(RefusingModule::Acp, kind, message)
    }

    #[test]
    fn refusal_kind_is_committed_and_its_message_is_not() {
        let failed = |refusal| {
            ExecutionReceipt::new(B256::repeat_byte(1), false, 5_000, 5_000, vec![])
                .with_refusal(refusal)
        };
        let policy = failed(Some(refusal(RefusalKind::InvalidPolicy, "first")));
        let root = receipt_commitment(9, std::slice::from_ref(&policy));
        let expected = [
            b"vera/receipts/v3".as_slice(),
            &9_u64.to_be_bytes(),
            &1_u64.to_be_bytes(),
            &[1; 32],
            &5_000_u64.to_be_bytes(),
            &5_000_u64.to_be_bytes(),
            &[0, 1, 1, 5, 0],
            &0_u64.to_be_bytes(),
        ]
        .concat();
        assert_eq!(root, keccak256(expected));
        let reworded = failed(Some(refusal(RefusalKind::InvalidPolicy, "second")));
        assert_eq!(root, receipt_commitment(9, &[reworded]));
        for other in [
            failed(None),
            failed(Some(refusal(RefusalKind::OutOfGas, "first"))),
            failed(Some(Refusal::new(
                RefusingModule::Vera,
                RefusalKind::InvalidPolicy,
                "first",
            ))),
        ] {
            assert_ne!(root, receipt_commitment(9, &[other]));
        }
    }
}
