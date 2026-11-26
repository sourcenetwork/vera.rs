//! A passkey assertion approves only the digest of its own kind: an
//! administrative request, a term change or a delegation token.

use alloy_primitives::{B256, Bytes, FixedBytes};
use vera_client::UnsignedToken;
use vera_client::administration::{
    AdministrativeCommand, AdministrativeRequest, OperatorApproval, OperatorPolicy,
    PasskeyAssertion,
};
use vera_client::term::{
    TermApproval, TermCertificate, TermChange, TermCut, TermPasskeyAssertion,
    verify_term_certificate,
};
use vera_crypto::jwt::DelegationScope;
use vera_crypto::webauthn::testing::{Authenticator, Signed};

const GENESIS: [u8; 32] = [7; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Use {
    Administrative,
    Term,
    Token,
}

const USES: [Use; 3] = [Use::Administrative, Use::Term, Use::Token];

struct Operator {
    passkey: Authenticator,
    policy: OperatorPolicy,
}

impl Operator {
    fn new() -> Self {
        let passkey = Authenticator::new([5; 32]);
        let policy = OperatorPolicy {
            threshold: 1,
            keys: vec![passkey.did()],
        };
        Self { passkey, policy }
    }

    const fn request() -> AdministrativeRequest {
        AdministrativeRequest {
            genesis_id: GENESIS,
            sequence: 0,
            expires_at: 100,
            command: AdministrativeCommand::SetPolicyOperationLead(1200),
        }
    }

    fn change() -> TermChange {
        TermChange {
            genesis_id: B256::from(GENESIS),
            term: 1,
            holder: B256::repeat_byte(2),
            cut: TermCut {
                height: 12,
                block: B256::repeat_byte(3),
            },
        }
    }

    fn token(&self) -> UnsignedToken {
        UnsignedToken::delegation(
            &self.passkey.did(),
            "did:key:worker",
            9001,
            50,
            100,
            DelegationScope::CreatePolicy,
        )
        .unwrap()
    }

    fn digest(&self, use_: Use) -> [u8; 32] {
        match use_ {
            Use::Administrative => Self::request().signing_digest().unwrap(),
            Use::Term => Self::change().signing_digest(),
            Use::Token => self.token().webauthn_challenge().unwrap(),
        }
    }

    /// Whether `signed` is accepted where an approval of kind `use_` is.
    fn accepts(&self, use_: Use, signed: &Signed) -> bool {
        match use_ {
            Use::Administrative => {
                let approval = OperatorApproval {
                    signer: 0,
                    signature: hex::encode(signed.signature),
                    webauthn: Some(PasskeyAssertion::new(
                        &signed.authenticator_data,
                        &signed.client_data_json,
                    )),
                };
                self.policy
                    .verify_approval(&self.digest(use_), &approval)
                    .is_ok()
            }
            Use::Term => {
                let certificate = TermCertificate {
                    change: Self::change(),
                    approvals: vec![TermApproval {
                        signer: 0,
                        signature: FixedBytes::from(signed.signature),
                        webauthn: Some(TermPasskeyAssertion {
                            authenticator_data: Bytes::copy_from_slice(&signed.authenticator_data),
                            client_data_json: Bytes::copy_from_slice(&signed.client_data_json),
                        }),
                    }],
                };
                verify_term_certificate(&certificate, &B256::from(GENESIS), &self.policy).is_ok()
            }
            Use::Token => self
                .token()
                .finish_webauthn(
                    &signed.authenticator_data,
                    &signed.client_data_json,
                    &signed.der,
                )
                .is_ok(),
        }
    }
}

#[test]
fn an_assertion_is_accepted_only_for_the_use_it_approves() {
    let operator = Operator::new();
    for made in USES {
        let signed = operator.passkey.assert(&operator.digest(made));
        for used in USES {
            assert_eq!(
                operator.accepts(used, &signed),
                made == used,
                "an assertion made for {made:?} used as {used:?}"
            );
        }
    }
}
