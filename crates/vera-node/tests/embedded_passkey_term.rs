//! A backup takes over under a term certificate approved by the account's passkey.

#[path = "support/devices.rs"]
mod devices;
#[path = "support/short_epochs.rs"]
mod short_epochs;
mod support;

use std::time::Duration;

use devices::{pair, takeover_change};
use short_epochs::{height, run_until};
use support::{await_certified_receipt, block_on, finalize_a_write};
use vera_client::{
    BlsSigner,
    administration::OperatorPolicy,
    term::{TermCertificate, TermChange, webauthn_term_approval},
};
use vera_crypto::webauthn::testing::Authenticator;
use vera_node::{EmbedError, EmbeddedNode, TermRefusal};

fn certify(
    passkey: &Authenticator,
    policy: &OperatorPolicy,
    change: TermChange,
) -> TermCertificate {
    let signed = passkey.assert(&change.signing_digest());
    TermCertificate {
        change,
        approvals: vec![
            webauthn_term_approval(
                &change,
                policy,
                0,
                &signed.authenticator_data,
                &signed.client_data_json,
                &signed.der,
            )
            .unwrap(),
        ],
    }
}

#[test]
fn a_passkey_approves_the_takeover_of_the_active_role() {
    let passkey = Authenticator::new([31; 32]);
    let policy = OperatorPolicy {
        threshold: 1,
        keys: vec![passkey.did()],
    };
    let directories = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let chain_id = 9_531;
    let dealt = short_epochs::deployment_under(chain_id, 131, policy.clone());
    let [first, second] = pair(
        [directories[0].path(), directories[1].path()],
        &dealt,
        Duration::from_secs(30),
    );
    let laptop = block_on(EmbeddedNode::start(first.active)).unwrap();
    let mut phone = block_on(EmbeddedNode::start(second.backup)).unwrap();
    let signer = BlsSigner::new(76u64.into(), chain_id).unwrap();
    let before = finalize_a_write(&laptop, &signer);
    let reached = height(&laptop);
    run_until(&phone, |height| height >= reached);
    block_on(laptop.stop()).unwrap();
    std::thread::sleep(Duration::from_secs(1));

    let change = takeover_change(&phone);
    let mut forged = certify(&passkey, &policy, change);
    let other = Authenticator::new([32; 32]).assert(&change.signing_digest());
    forged.approvals[0].signature = other.signature.into();
    assert!(matches!(
        block_on(phone.take_over(dealt.keys().clone(), forged)),
        Err(EmbedError::Term(TermRefusal::Certificate(_)))
    ));
    block_on(phone.take_over(dealt.keys().clone(), certify(&passkey, &policy, change))).unwrap();
    assert_eq!(phone.term(), 1);
    let after = finalize_a_write(&phone, &signer);
    await_certified_receipt(&phone, before);
    await_certified_receipt(&phone, after);
    block_on(phone.stop()).unwrap();
}
