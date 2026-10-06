use super::*;

fn document() -> EncryptedDocument {
    EncryptedDocument {
        ring_id: "ring-1".into(),
        document:
            r#"{"enc_cmt":[1,2,3],"encrypted_data":[4,5,6],"nonce":[0,0,0,0,0,0,0,0,0,0,0,0]}"#
                .into(),
        proof: r#"{"challenge":[7,8],"response":[9,10]}"#.into(),
        policy_id: "policy-b".into(),
        resource: "document".into(),
        permission: "read".into(),
        tier: Some("gold".into()),
        timestamp: Some(1_700_000_000),
        pet_tag: None,
        pet_tag_proof: None,
    }
}

#[test]
fn threshold_object_ids_match_rust_orbis_and_bind_optional_metadata() {
    let document = document();
    let id = ThresholdObject::Document(document.clone()).id().unwrap();
    assert_eq!(
        id,
        "e555cfcb145edf3d4cd8acbae93e05dc3a48eb0162b3af90f42064ab837c9a06"
    );
    let mut changed = document.clone();
    changed.document =
        r#"{ "nonce": [0,0,0,0,0,0,0,0,0,0,0,0], "encrypted_data": [4,5,6], "enc_cmt": [1,2,3] }"#
            .into();
    assert_eq!(ThresholdObject::Document(changed.clone()).id().unwrap(), id);
    changed.timestamp = None;
    assert_ne!(ThresholdObject::Document(changed.clone()).id().unwrap(), id);
    changed.timestamp = document.timestamp;
    changed.tier = None;
    assert_ne!(ThresholdObject::Document(changed).id().unwrap(), id);
    for field in ["enc_cmt", "ENC_CMT", "extra"] {
        let mut changed = document.clone();
        changed.document.pop();
        changed.document.push_str(&format!(",\"{field}\":[9]}}"));
        assert!(ThresholdObject::Document(changed).id().is_err());
    }
    let mut changed = document;
    changed.proof = r#"{"challenge":[],"response":[9,10]}"#.into();
    assert!(ThresholdObject::Document(changed).id().is_err());
}

const TAG: &str = r#"{"ephemeral_point":[1,1],"masked_fingerprint":[2,2]}"#;
const TAG_PROOF: &str = r#"{"challenge":[3,3],"response":[4,4]}"#;

#[test]
fn pet_document_id_matches_orbis_and_binds_every_decoded_attachment_field() {
    let mut document = document();
    document.pet_tag = Some(TAG.into());
    document.pet_tag_proof = Some(TAG_PROOF.into());
    let id = ThresholdObject::Document(document.clone()).id().unwrap();
    assert_eq!(
        id,
        "653ff17ab40e4b9a38c9af9da3454d16e01ddb95765329215d8d0ca55c720c7e"
    );
    let mut normalized = document.clone();
    normalized.pet_tag =
        Some(r#"{ "masked_fingerprint": [2, 2], "ephemeral_point": [1, 1] }"#.into());
    normalized.pet_tag_proof = Some(r#"{ "response": [4, 4], "challenge": [3, 3] }"#.into());
    assert_eq!(ThresholdObject::Document(normalized).id().unwrap(), id);
    for (proof, field) in [
        (false, "ephemeral_point"),
        (false, "masked_fingerprint"),
        (true, "challenge"),
        (true, "response"),
    ] {
        let mut changed = document.clone();
        let attachment = if proof {
            &mut changed.pet_tag_proof
        } else {
            &mut changed.pet_tag
        };
        let mut json: serde_json::Value =
            serde_json::from_str(attachment.as_ref().unwrap()).unwrap();
        json[field][0] = 9.into();
        *attachment = Some(json.to_string());
        assert_ne!(
            ThresholdObject::Document(changed).id().unwrap(),
            id,
            "{field}"
        );
    }
}

#[test]
fn pet_attachment_decoding_is_paired_bounded_and_has_one_byte_array_schema() {
    let mut document = document();
    for (tag, proof) in [(Some(TAG), None), (None, Some(TAG_PROOF))] {
        document.pet_tag = tag.map(str::to_owned);
        document.pet_tag_proof = proof.map(str::to_owned);
        assert!(ThresholdObject::Document(document.clone()).id().is_err());
    }
    for (is_proof, valid, fields) in [
        (false, TAG, ["ephemeral_point", "masked_fingerprint"]),
        (true, TAG_PROOF, ["challenge", "response"]),
    ] {
        let mut malformed = vec![
            "not json".into(),
            format!("{valid} trailing"),
            " ".repeat(MAX_PET_FIELD_BYTES + 1) + valid,
        ];
        for field in fields {
            for invalid in [
                serde_json::json!([]),
                serde_json::Value::Null,
                serde_json::json!([null]),
                serde_json::json!([256]),
                serde_json::json!([-1]),
                serde_json::json!([1.0]),
                serde_json::json!("AQ=="),
            ] {
                let mut json: serde_json::Value = serde_json::from_str(valid).unwrap();
                json[field] = invalid;
                malformed.push(json.to_string());
            }
            for extra in [field.to_owned(), field.to_uppercase(), "extra".into()] {
                malformed.push(format!("{},\"{extra}\":[1]}}", &valid[..valid.len() - 1]));
            }
            let mut json: serde_json::Value = serde_json::from_str(valid).unwrap();
            json.as_object_mut().unwrap().remove(field);
            malformed.push(json.to_string());
        }
        for value in malformed {
            document.pet_tag = Some(TAG.into());
            document.pet_tag_proof = Some(TAG_PROOF.into());
            if is_proof {
                document.pet_tag_proof = Some(value);
            } else {
                document.pet_tag = Some(value);
            }
            assert!(ThresholdObject::Document(document.clone()).id().is_err());
        }
    }
}
