//! Fixed keys in every accepted spelling, and certified submission helpers.

use std::{future::Future, time::Duration};

use alloy_sol_types::SolCall;
use k256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use vera_client::{
    ACP_ADDRESS, AccessRequest, Actor, BlsSigner, ClientError, Object, Operation, UnsignedToken,
    VeraClient,
};
use vera_domain::ConsensusPublicKey;

/// The key `[42; 32]`: its canonical DID, then its uncompressed Base58BTC,
/// compressed Base64URL and uncompressed Base64URL spellings.
pub(super) const OWNER: [&str; 4] = [
    "did:key:zQ3shkpqZaRR4P8KsTE1vXHRtjAAjKPfHFeu5B8vmPnW79A51",
    "did:key:z7r8oqKHB4AwqvHNsPgHdGic7GYAWgVjrWsKwwazb9epJXZ3wBwVMJd5xrWTvrmDBFLJ1RZAx13earK9RyJzj8nqWbvG6",
    "did:key:u5wEDW-XpR4IJZ0qW5g8fA39hdlQP0AH6HWRpR3DFancJxCw",
    "did:key:u5wEEW-XpR4IJZ0qW5g8fA39hdlQP0AH6HWRpR3DFancJxCwDWojDhD2_ixDVLMceJszhceGqHjL44ZPJ9qa9jwe4vw",
];
/// The key `[43; 32]` in the same four spellings.
pub(super) const READER: [&str; 4] = [
    "did:key:zQ3sha27TCd9ZLUkTh7LxLHkCJxWf4c2MApPp49bHQmQL4BmB",
    "did:key:z7r8osDxmBLQ4Er8KhXzFsf7KHex3LaFJKB7diJCiUGrfGuTD8FNQYYR2x8LaZ6DV1AjdHriEzv7a5VfocXiHPPXGWv4X",
    "did:key:u5wECu1i1_spQXHTtwADYKC_FVuUaECT8jn1-Vsb4h8XI1fI",
    "did:key:u5wEEu1i1_spQXHTtwADYKC_FVuUaECT8jn1-Vsb4h8XI1fIC929QilesJJGvGcjmflUTP44c0_nuI1AHFJcIX3NW-A",
];
pub(super) const STRANGER: &str = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
pub(super) const POLICY: &str = "\
name: one_actor
resources:
  - name: file
    relations:
      - name: reader
        types: [actor]
    permissions:
      - name: read
        expr: reader
";

pub(super) fn sign(key: &SigningKey, unsigned: UnsignedToken) -> String {
    let signature: Signature = key.sign(unsigned.signing_input());
    unsigned.finish(&signature.to_bytes()).unwrap()
}

pub(super) async fn submit(
    client: &VeraClient,
    signer: &BlsSigner,
    trusted: &ConsensusPublicKey,
    call: impl SolCall,
) -> u64 {
    submit_to(ACP_ADDRESS, client, signer, trusted, call).await
}

pub(super) async fn submit_to(
    module: alloy_primitives::Address,
    client: &VeraClient,
    signer: &BlsSigner,
    trusted: &ConsensusPublicKey,
    call: impl SolCall,
) -> u64 {
    let wire = signer
        .sign_native_tx(module, call.abi_encode().into())
        .unwrap();
    let id = client.send_native_tx(&wire).await.unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(response) = client.read_receipt(id, trusted).await.unwrap() {
                assert!(response.verify(id, trusted).unwrap().success());
                return response.revision.height;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap()
}

/// Repeat a certified read until the node has published the required revision.
pub(super) async fn certified<T, F: Future<Output = Result<T, ClientError>>>(
    read: impl Fn() -> F,
) -> T {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match read().await {
                Ok(value) => return value,
                Err(error)
                    if error.is_throttled()
                        || matches!(error, ClientError::Rpc { code: -32002, .. }) =>
                {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(error) => panic!("certified read failed: {error}"),
            }
        }
    })
    .await
    .expect("the node reaches the required revision")
}

pub(super) fn report() -> Object {
    Object {
        resource: "file".into(),
        id: "report".into(),
    }
}

pub(super) fn read(actor: &str) -> AccessRequest {
    AccessRequest {
        actor: Actor(actor.parse().unwrap()),
        operations: vec![Operation {
            object: report(),
            permission: "read".into(),
        }],
    }
}
