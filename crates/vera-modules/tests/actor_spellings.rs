//! A secp256k1 key is one actor, whichever spelling of its `did:key` a token,
//! a command, a check or a query uses.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use k256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use vera_acp::{Relationship, Subject};
use vera_crypto::{
    jwt::{DelegationScope, JwtClaims},
    operation::{OperationClaim, OperationId},
};
use vera_identity::Did;
use vera_modules::{
    acp::{
        AcpModule,
        delegated_operation::DelegatedOperation,
        types::{AccessRequest, Actor, Object, Operation, PolicyCmd, PolicyMarshalingType},
    },
    types::{BlockExecCtx, Timestamp, TxExecCtx},
    vera::VeraModule,
};

#[path = "support/actor_spelling_actor_objects.rs"]
mod actor_objects;
#[path = "support/actor_spelling_graph.rs"]
mod graph;
#[path = "support/actor_spelling_records.rs"]
mod records;
#[path = "support/actor_spelling_tokens.rs"]
mod tokens;

const FORMAT: PolicyMarshalingType = PolicyMarshalingType::ShortYaml;

const GENESIS: [u8; 32] = [7; 32];

struct Key(SigningKey);

impl Key {
    fn new(seed: u8) -> Self {
        Self(SigningKey::from_slice(&[seed; 32]).unwrap())
    }

    fn bytes(&self, compressed: bool) -> Vec<u8> {
        let mut bytes = vec![0xe7, 0x01];
        bytes.extend_from_slice(
            self.0
                .verifying_key()
                .to_encoded_point(compressed)
                .as_bytes(),
        );
        bytes
    }

    /// Compressed and uncompressed points, in Base58BTC and then Base64URL.
    /// The first spelling is the canonical one.
    fn spellings(&self) -> [String; 4] {
        let base58 = |bytes: Vec<u8>| format!("did:key:z{}", bs58::encode(bytes).into_string());
        let base64 = |bytes: Vec<u8>| format!("did:key:u{}", URL_SAFE_NO_PAD.encode(bytes));
        [
            base58(self.bytes(true)),
            base58(self.bytes(false)),
            base64(self.bytes(true)),
            base64(self.bytes(false)),
        ]
    }

    fn canonical(&self) -> String {
        self.spellings()[0].clone()
    }

    fn dids(&self) -> [Did; 4] {
        self.spellings().map(|spelling| Did::new(spelling).unwrap())
    }

    fn sign(&self, claims: &JwtClaims) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256K","typ":"vera-delegation-v1+jwt"}"#);
        let input = format!(
            "{header}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap())
        );
        let signature: Signature = self.0.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    /// A delegation to `worker` that names this key as `issuer`.
    fn token(&self, issuer: &str, worker: &TxExecCtx, scope: DelegationScope) -> String {
        self.sign(&claims(issuer, &worker.signer, scope, None))
    }

    /// A delegation bound to one operation identity and its exact arguments.
    fn operation_token(
        &self,
        issuer: &str,
        worker: &TxExecCtx,
        id: OperationId,
        operation: &DelegatedOperation<'_>,
    ) -> String {
        self.sign(&claims(
            issuer,
            &worker.signer,
            operation.scope(),
            Some(OperationClaim {
                id,
                digest: operation.digest().unwrap(),
                genesis_id: GENESIS,
            }),
        ))
    }

    /// A delegation whose subject names the worker in a chosen spelling.
    fn token_for(&self, subject: &str, scope: DelegationScope) -> String {
        self.sign(&claims(&self.canonical(), subject, scope, None))
    }
}

fn claims(
    issuer: &str,
    subject: &str,
    scope: DelegationScope,
    request: Option<OperationClaim>,
) -> JwtClaims {
    JwtClaims {
        iss: issuer.into(),
        sub: subject.into(),
        exp: 200,
        aud: "vera:9001".into(),
        scope,
        iat: 90,
        nbf: 90,
        relay: None,
        request,
    }
}

fn operation_id(entropy: u8) -> OperationId {
    let mut bytes = [entropy; 32];
    bytes[..8].copy_from_slice(&200u64.to_be_bytes());
    OperationId(bytes)
}

fn worker(seed: u8) -> TxExecCtx {
    TxExecCtx {
        signer: format!("did:key:worker-{seed}"),
        tx_hash: vec![seed; 32],
        sequence: u64::from(seed),
    }
}

const fn context(now: u64) -> BlockExecCtx {
    BlockExecCtx {
        genesis_id: GENESIS,
        deployment_id: 9001,
        timestamp: Timestamp {
            seconds: now,
            block_height: now,
        },
    }
}

const POLICY: &str = "name: files
actor:
  relations:
    - name: member
      types: [actor]
resources:
  - name: file
    relations:
      - name: reader
        types: [actor, actor->member]
      - name: viewer
    permissions:
      - name: read
        expr: reader
";

fn file(id: &str) -> Object {
    Object {
        resource: "file".into(),
        id: id.into(),
    }
}

fn read(actor: &Did, object: Object) -> AccessRequest {
    AccessRequest {
        actor: Actor(actor.clone()),
        operations: vec![Operation {
            object,
            permission: "read".into(),
        }],
    }
}

fn reader(subject: Subject) -> Relationship {
    Relationship::new("file", "report", "reader", subject)
}

/// A policy owned by `owner` with one registered file.
fn fixture(owner: &Key) -> (AcpModule, String) {
    let mut acp = AcpModule::new();
    let owner = &owner.dids()[0];
    let policy = acp.create_policy(owner, POLICY, FORMAT).unwrap().policy.id;
    acp.direct_policy_cmd(owner, &policy, PolicyCmd::RegisterObject(file("report")))
        .unwrap();
    (acp, policy)
}

fn all_equal(states: &[Vec<u8>]) -> bool {
    states.windows(2).all(|pair| pair[0] == pair[1])
}
