use super::*;

fn native(block: &mut Block) {
    block.native_targets = Some(Default::default());
    block.txs = (0..3u8)
        .map(|index| crate::Tx::new(Bytes::from(vec![index; 40])))
        .collect();
}

#[test]
fn encoded_native_block_matches_construction_from_the_decoded_block() {
    let (block, finalization, material) = artifacts(42, native);
    let encoded = block.encode();

    let light = LightBlock::from_encoded_block(&encoded, &finalization, &material).unwrap();

    let expected = LightBlock {
        block_hash: encode_hex(block.id().0.as_slice()),
        parent_hash: encode_hex(block.parent.0.as_slice()),
        height: block.height,
        timestamp: block.timestamp,
        state_root: encode_hex(block.state_root.0.as_slice()),
        module_state_root: encode_hex(block.module_state_root.as_slice()),
        epoch: block.context.round.epoch().get(),
        view: block.context.round.view().get(),
        parent_view: block.context.parent.0.get(),
        block: encode_hex(&block.encode()),
        descendants: Vec::new(),
        finalization: encode_hex(&finalization),
        epoch_material: encode_hex(&material),
    };
    assert_eq!(light, expected);
    assert_eq!(
        light,
        LightBlock::from_parts(&block, &finalization, &material)
    );
    assert_eq!(
        verify_finalized_block(&light, &trusted_key()).unwrap(),
        block
    );
}

#[test]
fn undecodable_block_bytes_are_rejected() {
    let (block, finalization, material) = artifacts(42, native);
    let mut encoded = block.encode().to_vec();
    encoded.push(0);

    assert!(matches!(
        LightBlock::from_encoded_block(&encoded, &finalization, &material),
        Err(LightBlockError::Codec(_))
    ));
}
