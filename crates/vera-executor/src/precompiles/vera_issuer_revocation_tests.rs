use super::*;
use alloy_sol_types::SolEvent;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use k256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use vera_crypto::{
    jwt::JwtClaims,
    operation::{OperationClaim, OperationId},
};
use vera_domain::RefusalKind;
use vera_modules::acp::delegated_operation::DelegatedOperation;
use vera_modules::{
    types::Timestamp,
    vera::{keys::hash_jws_token, types::JWSTokenRecord, types::JWSTokenStatus},
};

const WORKER: &str = "did:key:z6MkmjY8GnV5iJjM2BXSVn4MoDbZZbLffKHsygxC4BLd5v8P";

fn did(seed: u8) -> String {
    let key = SigningKey::from_slice(&[seed; 32]).unwrap();
    vera_crypto::secp256k1::did_from_secp256k1_pubkey(key.verifying_key().to_sec1_bytes().as_ref())
        .unwrap()
}

fn operation(seed: u8, deployment: u64, entropy: u8, token_hash: &str) -> String {
    let revocation = DelegatedOperation::RevokeToken(token_hash);
    let claims = JwtClaims {
        iss: did(seed),
        sub: WORKER.into(),
        exp: 200,
        aud: format!("vera:{deployment}"),
        scope: revocation.scope(),
        iat: 90,
        nbf: 90,
        relay: None,
        request: Some(OperationClaim {
            id: OperationId::new(200, [entropy; 24]),
            digest: revocation.digest().unwrap(),
            genesis_id: [7; 32],
        }),
    };
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256K","typ":"vera-delegation-v1+jwt"}"#);
    let input = format!(
        "{header}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let signature: Signature = SigningKey::from_slice(&[seed; 32])
        .unwrap()
        .sign(input.as_bytes());
    let signature = signature.normalize_s().unwrap_or(signature);
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

struct Fixture {
    vera: VeraModule,
    acp: AcpModule,
    block: BlockExecCtx,
    tx: TxExecCtx,
    hash: String,
}

impl Fixture {
    fn new() -> Self {
        let block = BlockExecCtx {
            genesis_id: [7; 32],
            deployment_id: 9001,
            timestamp: Timestamp {
                seconds: 100,
                block_height: 5,
            },
        };
        let mut vera = VeraModule::new();
        vera.store_or_update_jws_token(
            &block,
            "issued-token",
            &did_from_signer(&did(42)).unwrap(),
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            Timestamp::default(),
            Timestamp {
                seconds: 1_000,
                block_height: 0,
            },
        )
        .unwrap();
        Self {
            vera,
            acp: AcpModule::new(),
            block,
            tx: TxExecCtx {
                sequence: 0,
                tx_hash: vec![3; 32],
                signer: WORKER.into(),
            },
            hash: hash_jws_token("issued-token"),
        }
    }

    fn submit(&mut self, operation: &str) -> DispatchReturn {
        let call = IVera::invalidateJWSByIssuerCall {
            tokenHash: self.hash.clone(),
            operation: operation.into(),
        };
        dispatch(
            &mut self.vera,
            &mut self.acp,
            &self.block,
            &self.tx,
            &call.abi_encode(),
            WRITE_GAS,
        )
    }

    fn refusal(&mut self, operation: &str) -> Option<RefusalKind> {
        let before = (self.vera.store().serialize(), self.acp.store().serialize());
        let result = self.submit(operation).unwrap();
        assert!(result.output.status.is_revert());
        assert_eq!(
            (self.vera.store().serialize(), self.acp.store().serialize()),
            before
        );
        result.refusal
    }
}

#[test]
fn a_worker_carries_the_issuers_revocation_and_the_event_names_the_issuer() {
    let mut fixture = Fixture::new();
    let hash = fixture.hash.clone();
    let result = fixture.submit(&operation(42, 9001, 1, &hash)).unwrap();
    assert!(!result.output.status.is_revert());
    assert_eq!(result.refusal, None);
    let output =
        IVera::invalidateJWSByIssuerCall::abi_decode_returns(&result.output.bytes).unwrap();
    let returned: JWSTokenRecord = serde_json::from_slice(&output).unwrap();
    let stored = fixture.vera.get_jws_token(&hash).unwrap().unwrap();
    assert_eq!(returned, stored);
    assert_eq!(stored.status, JWSTokenStatus::Invalid);
    assert_eq!(stored.invalidated_by, did(42));
    let event = IVera::JWSTokenInvalidated::decode_log(&result.logs[0]).unwrap();
    assert_eq!(event.data.issuerDid, did(42));
    assert_eq!(
        event.data.tokenHash,
        alloy_primitives::keccak256(hash.as_bytes())
    );

    let retried = fixture.submit(&operation(42, 9001, 1, &hash)).unwrap();
    assert!(!retried.output.status.is_revert());
    assert_eq!(retried.output.bytes, result.output.bytes);
}

#[test]
fn refusals_name_their_kind() {
    let mut fixture = Fixture::new();
    let hash = fixture.hash.clone();
    assert_eq!(
        fixture.refusal(&operation(43, 9001, 1, &hash)),
        Some(RefusalKind::Unauthorized)
    );
    assert_eq!(
        fixture.refusal(&operation(42, 9002, 1, &hash)),
        Some(RefusalKind::InvalidToken)
    );
    let other = hash_jws_token("other-token");
    assert_eq!(
        fixture.refusal(&operation(42, 9001, 1, &other)),
        Some(RefusalKind::InvalidToken)
    );
    fixture.submit(&operation(42, 9001, 1, &hash)).unwrap();
    assert_eq!(
        fixture.refusal(&operation(42, 9001, 1, &other)),
        Some(RefusalKind::InvalidToken)
    );
    assert_eq!(
        fixture.refusal(&operation(42, 9001, 2, &hash)),
        Some(RefusalKind::InvalidToken)
    );
    fixture.tx.signer.clear();
    assert!(fixture.submit(&operation(42, 9001, 3, &hash)).is_err());
}
