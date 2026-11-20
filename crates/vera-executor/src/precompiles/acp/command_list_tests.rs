use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use k256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use revm::precompile::{PrecompileHalt, PrecompileStatus};
use vera_crypto::{
    jwt::{DelegationScope, JwtClaims},
    operation::{OperationClaim, OperationId},
};
use vera_domain::RefusalKind;
use vera_modules::acp::delegated_operation::DelegatedOperation;
use vera_modules::types::Timestamp;

const READERS: &str = "name: files\nresources:\n  - name: file\n    relations:\n      - name: reader\n        types: [actor]\n";

struct Fixture {
    acp: AcpModule,
    vera: VeraModule,
    block: BlockExecCtx,
    tx: TxExecCtx,
    policy: String,
}

impl Fixture {
    fn new() -> Self {
        let actor = Did::new(issuer()).unwrap();
        let mut acp = AcpModule::new();
        let policy = acp
            .create_policy(
                &actor,
                READERS,
                PolicyMarshalingType::ShortYaml,
                Default::default(),
            )
            .unwrap()
            .policy
            .id;
        Self {
            acp,
            vera: VeraModule::new(),
            block: BlockExecCtx {
                timestamp: Timestamp {
                    seconds: 10,
                    block_height: 1,
                },
                deployment_id: 9001,
                genesis_id: [7; 32],
            },
            tx: TxExecCtx {
                signer: actor.to_string(),
                tx_hash: vec![1; 32],
                sequence: 0,
            },
            policy,
        }
    }

    fn commands(&self) -> Vec<(String, PolicyCmd)> {
        vec![
            (
                self.policy.clone(),
                PolicyCmd::RegisterObject(Object {
                    resource: "file".into(),
                    id: "report".into(),
                }),
            ),
            (
                self.policy.clone(),
                PolicyCmd::SetRelationship(vera_acp::Relationship::with_entity(
                    "file",
                    "report",
                    "reader",
                    Did::new("did:key:reader").unwrap(),
                )),
            ),
        ]
    }

    fn token(&self, commands: &[(String, PolicyCmd)]) -> String {
        let mut id = [17; 32];
        id[..8].copy_from_slice(&100u64.to_be_bytes());
        let claims = JwtClaims {
            iss: issuer(),
            sub: self.tx.signer.clone(),
            exp: 100,
            aud: "vera:9001".into(),
            scope: DelegationScope::PolicyCommands,
            iat: 0,
            nbf: 0,
            relay: None,
            request: Some(OperationClaim {
                id: OperationId(id),
                genesis_id: self.block.genesis_id,
                digest: DelegatedOperation::PolicyCommandList(commands)
                    .digest()
                    .unwrap(),
            }),
        };
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256K","typ":"vera-delegation-v1+jwt"}"#);
        let message = format!(
            "{header}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        );
        let signature: Signature = SigningKey::from_slice(&[42; 32])
            .unwrap()
            .sign(message.as_bytes());
        format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    fn call(token: String, commands: &[u8]) -> Vec<u8> {
        IAcp::bearerPolicyCmdsCall {
            bearerToken: token,
            commands: commands.to_vec().into(),
        }
        .abi_encode()
    }

    fn signed(&self) -> Vec<u8> {
        let commands = self.commands();
        Self::call(
            self.token(&commands),
            &serde_json::to_vec(&commands).unwrap(),
        )
    }

    fn dispatch(&mut self, input: &[u8], gas: u64) -> DispatchResult {
        dispatch(
            &mut self.acp,
            &mut self.vera,
            &self.block,
            &self.tx,
            input,
            gas,
        )
        .unwrap()
    }

    fn clone_state_dispatch(&self, input: &[u8], gas: u64) -> u64 {
        let (mut acp, mut vera) = (self.acp.clone(), self.vera.clone());
        dispatch(&mut acp, &mut vera, &self.block, &self.tx, input, gas)
            .unwrap()
            .precompile
            .gas_used
    }

    fn state(&self) -> (Vec<u8>, Vec<u8>) {
        (self.acp.store().serialize(), self.vera.store().serialize())
    }
}

fn issuer() -> String {
    let key = SigningKey::from_slice(&[42; 32]).unwrap();
    vera_crypto::secp256k1::did_from_secp256k1_pubkey(key.verifying_key().to_sec1_bytes().as_ref())
        .unwrap()
}

#[test]
fn a_signed_list_applies_every_command_and_its_replay_returns_the_same_bytes() {
    let mut fixture = Fixture::new();
    let input = fixture.signed();
    let applied = fixture.dispatch(&input, 10_000_000);
    assert!(applied.precompile.status.is_success());
    assert!(applied.precompile.gas_used > 2 * WRITE_GAS);
    let results: Vec<vera_modules::acp::types::PolicyCmdResult> = serde_json::from_slice(
        &IAcp::bearerPolicyCmdsCall::abi_decode_returns(&applied.precompile.bytes).unwrap(),
    )
    .unwrap();
    assert_eq!(results.len(), 2);
    let before = fixture.state();
    let replayed = fixture.dispatch(&input, 10_000_000);
    assert!(replayed.precompile.status.is_success());
    assert_eq!(replayed.precompile.bytes, applied.precompile.bytes);
    assert_eq!(fixture.state(), before);
}

#[test]
fn an_altered_or_undecodable_list_is_a_refusal_that_changes_nothing() {
    let mut fixture = Fixture::new();
    let commands = fixture.commands();
    let reversed: Vec<_> = commands.iter().rev().cloned().collect();
    let cases = [
        (
            Fixture::call(
                fixture.token(&commands),
                &serde_json::to_vec(&reversed).unwrap(),
            ),
            RefusalKind::InvalidToken,
        ),
        (
            Fixture::call(
                fixture.token(&commands),
                &serde_json::to_vec(&commands[..1]).unwrap(),
            ),
            RefusalKind::InvalidToken,
        ),
        (
            Fixture::call(fixture.token(&commands), b"[[\"x\""),
            RefusalKind::UndecodableInput,
        ),
    ];
    let before = fixture.state();
    for (input, kind) in cases {
        let refused = fixture.dispatch(&input, 10_000_000);
        assert!(refused.precompile.status.is_revert());
        assert_eq!(refused.refusal, Some(kind));
        assert_eq!(fixture.state(), before);
    }
}

#[test]
fn each_further_command_pays_the_write_base_and_exhaustion_changes_nothing() {
    let single = {
        let mut fixture = Fixture::new();
        let commands = &fixture.commands()[..1];
        let input = Fixture::call(
            fixture.token(commands),
            &serde_json::to_vec(commands).unwrap(),
        );
        fixture.dispatch(&input, 10_000_000).precompile.gas_used
    };
    let mut fixture = Fixture::new();
    let input = fixture.signed();
    let measured = fixture.clone_state_dispatch(&input, 10_000_000);
    assert!(measured > single + WRITE_GAS);
    let before = fixture.state();
    let exhausted = fixture.dispatch(&input, measured - 1);
    assert!(matches!(
        exhausted.precompile.status,
        PrecompileStatus::Halt(PrecompileHalt::OutOfGas)
    ));
    assert_eq!(fixture.state(), before);
    assert!(
        fixture
            .dispatch(&input, measured)
            .precompile
            .status
            .is_success()
    );
}

#[test]
fn an_enclosing_batch_revert_leaves_no_list_effect_or_outcome() {
    let mut fixture = Fixture::new();
    let failing = IAcp::archiveObjectCall {
        policyId: fixture.policy.parse().unwrap(),
        resource: "file".into(),
        objectId: "missing".into(),
    }
    .abi_encode();
    let input = IAcp::batchCallsCall {
        calls: vec![fixture.signed().into(), failing.into()],
    }
    .abi_encode();
    let before = fixture.state();
    let reverted = fixture.dispatch(&input, 10_000_000);
    assert!(reverted.precompile.status.is_revert());
    assert_eq!(fixture.state(), before);
}
