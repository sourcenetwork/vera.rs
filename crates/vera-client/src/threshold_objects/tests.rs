use super::*;
use vera_modules::acp::delegated_operation::DelegatedOperation;

fn document() -> EncryptedDocument {
    EncryptedDocument {
        ring_id: "00".repeat(32),
        document:
            r#"{"enc_cmt":[1,2,3],"encrypted_data":[4,5,6],"nonce":[0,0,0,0,0,0,0,0,0,0,0,0]}"#
                .into(),
        proof: r#"{"challenge":[7,8],"response":[9,10]}"#.into(),
        policy_id: "11".repeat(32),
        resource: "document".into(),
        permission: "read".into(),
        tier: Some("gold".into()),
        timestamp: Some(1_700_000_000),
        pet_tag: None,
        pet_tag_proof: None,
    }
}

#[test]
fn object_calldata_preserves_ordinary_delegation_bytes_and_pet_attachment_binding() {
    let ordinary = ThresholdObject::Document(document());
    assert_eq!(
        hex::encode(
            DelegatedOperation::StoreThresholdObject(&ordinary)
                .digest()
                .unwrap()
        ),
        "d049df9b40ecb074db891f1ca4f578eb572f6c6e1969a30a605117f3fa4854c2"
    );
    let json = serde_json::to_string(&ordinary).unwrap();
    assert!(!json.contains("pet_tag"));
    let mut pet = document();
    pet.pet_tag = Some(r#"{"ephemeral_point":[1,1],"masked_fingerprint":[2,2]}"#.into());
    pet.pet_tag_proof = Some(r#"{"challenge":[3,3],"response":[4,4]}"#.into());
    for object in [ordinary.clone(), ThresholdObject::Document(pet.clone())] {
        let bytes = encode_threshold_object(&object, "signed-delegation").unwrap();
        let call = IVera::storeThresholdObjectCall::abi_decode(&bytes).unwrap();
        assert_eq!(call.bearerToken, "signed-delegation");
        let received: ThresholdObject = serde_json::from_slice(&call.request).unwrap();
        assert_eq!(received, object);
        assert_eq!(
            DelegatedOperation::StoreThresholdObject(&received)
                .digest()
                .unwrap(),
            DelegatedOperation::StoreThresholdObject(&object)
                .digest()
                .unwrap()
        );
        assert_eq!(received.id().unwrap(), object.id().unwrap());
    }
    assert_ne!(
        DelegatedOperation::StoreThresholdObject(&ordinary)
            .digest()
            .unwrap(),
        DelegatedOperation::StoreThresholdObject(&ThresholdObject::Document(pet.clone()))
            .digest()
            .unwrap()
    );
    pet.pet_tag_proof = None;
    assert!(encode_threshold_object(&ThresholdObject::Document(pet), "signed-delegation").is_err());
}
