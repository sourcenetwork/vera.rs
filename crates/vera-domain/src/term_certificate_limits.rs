use super::*;

fn change() -> TermChange {
    TermChange {
        genesis_id: B256::repeat_byte(0xff),
        term: u64::MAX,
        holder: B256::repeat_byte(0xff),
        cut: TermCut {
            height: u64::MAX,
            block: B256::repeat_byte(0xff),
        },
    }
}

fn raw(signer: u16) -> TermApproval {
    TermApproval {
        signer,
        signature: FixedBytes::repeat_byte(0xff),
        webauthn: None,
    }
}

fn passkey(signer: u16, client_data: usize) -> TermApproval {
    TermApproval {
        webauthn: Some(TermPasskeyAssertion {
            authenticator_data: Bytes::from(vec![0xff; AUTHENTICATOR_DATA_BYTES]),
            client_data_json: Bytes::from(vec![b'{'; client_data]),
        }),
        ..raw(signer)
    }
}

fn encoded(approvals: Vec<TermApproval>) -> usize {
    serde_json::to_vec(&TermCertificate {
        change: change(),
        approvals,
    })
    .unwrap()
    .len()
}

#[test]
fn every_operator_signing_raw_fits() {
    let approvals = (u16::MAX - 127..=u16::MAX).map(raw).collect();
    assert!(encoded(approvals) <= MAX_TERM_CERTIFICATE_BYTES);
}

#[test]
fn thirteen_passkey_approvals_with_the_longest_client_data_fit() {
    let approvals = |count: u16| {
        (u16::MAX - count + 1..=u16::MAX)
            .map(|signer| passkey(signer, MAX_CLIENT_DATA_BYTES))
            .collect()
    };
    assert!(encoded(approvals(13)) <= MAX_TERM_CERTIFICATE_BYTES);
    assert!(encoded(approvals(14)) > MAX_TERM_CERTIFICATE_BYTES);
}

#[test]
fn passkey_fields_outside_their_bounds_do_not_decode() {
    let decode = |approval: &TermApproval| {
        serde_json::from_value::<TermApproval>(serde_json::to_value(approval).unwrap())
    };
    let longest = passkey(0, MAX_CLIENT_DATA_BYTES);
    assert_eq!(decode(&longest).unwrap(), longest);
    assert!(decode(&passkey(0, MAX_CLIENT_DATA_BYTES + 1)).is_err());
    for length in [0, 36, 38] {
        let mut approval = passkey(0, 16);
        approval.webauthn.as_mut().unwrap().authenticator_data = Bytes::from(vec![5; length]);
        assert!(decode(&approval).is_err(), "{length}");
    }
}
