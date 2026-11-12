//! A relay token may spell its issuer in any accepted way.

use super::*;

#[test]
fn a_relay_is_one_issuer_in_every_spelling_of_its_key() {
    let spelled = |compressed, base64: bool| {
        let mut bytes = vec![0xe7, 0x01];
        bytes.extend_from_slice(
            key()
                .verifying_key()
                .to_encoded_point(compressed)
                .as_bytes(),
        );
        if base64 {
            format!("did:key:u{}", URL_SAFE_NO_PAD.encode(bytes))
        } else {
            format!("did:key:z{}", bs58::encode(bytes).into_string())
        }
    };
    let mut policies = Vec::new();
    for (compressed, base64) in [(true, false), (false, false), (true, true), (false, true)] {
        let (mut vera, mut acp) = modules();
        let mut claims = claims(&DelegatedOperation::CreatePolicy(POLICY, &FORMAT));
        claims.iss = spelled(compressed, base64);
        let token = sign(&claims);
        let created = create(&mut vera, &mut acp, &token).unwrap();
        assert_eq!(created.metadata.owner_did, actor());
        let record = vera
            .get_jws_token(&vera_modules::vera::keys::hash_jws_token(&token))
            .unwrap()
            .unwrap();
        assert_eq!(record.issuer_did, issuer());
        policies.push(acp.store().serialize());

        let mut grant = grant();
        grant.issuer = claims.iss;
        if grant.issuer != issuer() {
            assert!(
                admin(&mut vera, &mut acp, AdministrativeCommand::SetRelay(grant)).is_err(),
                "a grant names its relay canonically"
            );
        }
    }
    assert!(policies.windows(2).all(|pair| pair[0] == pair[1]));
}
