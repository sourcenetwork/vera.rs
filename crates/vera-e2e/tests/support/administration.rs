use std::time::{SystemTime, UNIX_EPOCH};

use vera_client::Secp256k1SigningKey as SigningKey;
use vera_client::{
    VeraClient,
    administration::{
        AdministrativeCommand, AdministrativeRequest, OperatorPolicy, SignedAdministrativeRequest,
        approve_administration,
    },
};

fn keys() -> Vec<SigningKey> {
    let mut keys: Vec<_> = [1, 2]
        .into_iter()
        .map(|byte| SigningKey::from_bytes(&[byte; 32].into()).unwrap())
        .collect();
    keys.sort_by_key(|key| key.verifying_key().to_sec1_bytes().to_vec());
    keys
}

pub(super) fn operators() -> OperatorPolicy {
    OperatorPolicy {
        threshold: 2,
        keys: keys()
            .iter()
            .map(|key| hex::encode(key.verifying_key().to_sec1_bytes()))
            .collect(),
    }
}

pub(super) async fn approve(
    client: &VeraClient,
    command: AdministrativeCommand,
    sequence: u64,
) -> SignedAdministrativeRequest {
    let genesis = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let first: serde_json::Value = client
                .rpc_call_typed("eth_getBlockByNumber", serde_json::json!(["0x1", false]))
                .await
                .unwrap();
            if let Some(parent) = first["parentHash"].as_str() {
                return parent.parse::<alloy_primitives::B256>().unwrap();
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    let request = AdministrativeRequest {
        genesis_id: genesis.0,
        sequence,
        expires_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 300,
        command,
    };
    let approvals = keys()
        .iter()
        .enumerate()
        .map(|(index, key)| approve_administration(&request, index as u16, key).unwrap())
        .collect();
    SignedAdministrativeRequest { request, approvals }
}
