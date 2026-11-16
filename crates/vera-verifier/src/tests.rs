use super::*;

#[test]
fn policy_validation_selects_json_or_yaml_without_fallback() {
    for (definition, format, expected) in [
        (
            r#"{"name":"sample","resources":[{"name":"file"}]}"#,
            "JSON",
            true,
        ),
        ("name: sample\nresources:\n  - name: file\n", "yaml", true),
        ("name: sample\nresources:\n  - name: file\n", "json", false),
        (r#"{"name":"sample","extra":true}"#, "json", false),
        ("{}", "unknown", false),
    ] {
        let input = serde_json::to_vec(
            &json!({"kind":"validate_policy", "definition":definition, "format":format}),
        )
        .unwrap();
        let output = unsafe { vera_verify(input.as_ptr(), input.len()) };
        let bytes = unsafe { std::slice::from_raw_parts(output.data, output.len) };
        let response: Value = serde_json::from_slice(bytes).unwrap();
        unsafe { vera_buffer_free(output) };
        assert_eq!(response["result"]["valid"], expected, "{response}");
    }
}

#[test]
fn invalid_foreign_inputs_return_owned_errors() {
    for (input, len) in [
        (std::ptr::null(), 0),
        (b"x".as_ptr(), MAX_REQUEST_BYTES + 1),
        (b"x".as_ptr(), 1),
    ] {
        // Valid readable memory is supplied whenever the length passes the boundary checks.
        let output = unsafe { vera_verify(input, len) };
        let bytes = unsafe { std::slice::from_raw_parts(output.data, output.len) };
        let json: Value = serde_json::from_slice(bytes).unwrap();
        assert!(json["error"].is_string());
        assert!(json.get("result").is_none());
        unsafe { vera_buffer_free(output) };
    }
}

#[test]
fn object_owner_requires_policy_scoped_evidence() {
    let policy = "ab".repeat(32);
    let revision = json!({
        "block_hash": "", "parent_hash": "", "height": 1, "timestamp": 1,
        "state_root": "", "module_state_root": "", "epoch": 0, "view": 0,
        "parent_view": 0, "block": "", "finalization": "", "epoch_material": ""
    });
    let prefix = vera_permission::PrefixProof {
        module: ModuleId::Acp,
        prefix: vera_modules::acp::keys::relationship_policy_prefix(&policy).into(),
        roots: [B256::ZERO; 4],
        proof: Bytes::new(),
    };
    let policy_record = vera_permission::RecordProof {
        module: ModuleId::Acp,
        key: vera_modules::acp::keys::policy_key(&policy).into(),
        value: None,
        roots: [B256::ZERO; 4],
        proof: Bytes::new(),
    };
    let mut request = json!({
        "kind": "object_owner", "trusted_key": "", "policy_id": policy,
        "object": {"resource": "file", "id": "report"}, "minimum_height": 1,
        "proof": {"revision": revision, "proof": {"policy": policy_record, "objects": [], "prefix": prefix}}
    });
    assert!(matches!(
        serde_json::from_value::<Request>(request.clone()),
        Ok(Request::ObjectOwner { .. })
    ));
    let mut missing_objects = request.clone();
    missing_objects["proof"]["proof"]
        .as_object_mut()
        .unwrap()
        .remove("objects");
    assert!(serde_json::from_value::<Request>(missing_objects).is_err());
    request["proof"] = json!({"revision": revision, "prefix": prefix});
    assert!(serde_json::from_value::<Request>(request.clone()).is_err());
    let output = verify(&serde_json::to_vec(&request).unwrap()).unwrap_err();
    assert!(output.contains("unknown field `prefix`"), "{output}");
}

fn term_certificate(approvals: Value) -> vera_domain::TermCertificate {
    serde_json::from_value(json!({
        "change": {
            "genesis_id": B256::repeat_byte(1), "term": 1, "holder": B256::repeat_byte(2),
            "cut": {"height": 9, "block": B256::repeat_byte(3)}
        },
        "approvals": approvals
    }))
    .unwrap()
}

#[test]
fn a_term_certificate_is_checked_against_the_certified_operator_policy() {
    // The Borsh form of an operator policy of one key at threshold 1, at sequence 0.
    let key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let mut stored = vec![1, 0, 1, 0, 0, 0, 66, 0, 0, 0];
    stored.extend_from_slice(key.as_bytes());
    stored.extend_from_slice(&[0; 9]);
    let genesis = B256::repeat_byte(1);
    let unsigned = term_certificate(json!([]));
    assert_eq!(
        verify_term(Some(&stored), &genesis, &unsigned).unwrap_err(),
        "term certificate needs 1 approvals in ascending signer order"
    );
    let forged = term_certificate(json!([
        {"signer": 0, "signature": format!("0x{}", "11".repeat(64))}
    ]));
    assert_eq!(
        verify_term(Some(&stored), &genesis, &forged).unwrap_err(),
        "term approval by operator 0 does not verify"
    );
    assert_eq!(
        verify_term(Some(&stored), &B256::ZERO, &forged).unwrap_err(),
        "term certificate names another deployment"
    );
    assert_eq!(
        verify_term(None, &genesis, &forged).unwrap_err(),
        "operator authority is not configured"
    );
    assert!(verify_term(Some(&stored[..stored.len() - 1]), &genesis, &forged).is_err());
}

#[test]
fn a_term_certificate_request_requires_a_certified_operator_record() {
    let revision = json!({
        "block_hash": "", "parent_hash": "", "height": 1, "timestamp": 1,
        "state_root": "", "module_state_root": "", "epoch": 0, "view": 0,
        "parent_view": 0, "block": "", "finalization": "", "epoch_material": ""
    });
    let record = vera_permission::RecordProof {
        module: ModuleId::Vera,
        key: vera_modules::vera::administration::STATE_KEY
            .to_vec()
            .into(),
        value: None,
        roots: [B256::ZERO; 4],
        proof: Bytes::new(),
    };
    let input = serde_json::to_vec(&json!({
        "kind": "term_certificate", "trusted_key": "00".repeat(96),
        "genesis_id": B256::repeat_byte(1), "minimum_height": 0,
        "proof": {"revision": revision, "record": record},
        "certificate": term_certificate(json!([]))
    }))
    .unwrap();
    assert!(matches!(
        serde_json::from_slice::<Request>(&input),
        Ok(Request::TermCertificate { .. })
    ));
    assert!(verify(&input).is_err());
}
