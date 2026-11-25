use alloy_primitives::B256;
use vera_domain::{FinalityTrust as _, LightBlock, LightBlockError, testing::TestDeployment};

use super::{Remembered, RevisionCache};

/// Whether `light`, with the evidence it carries, would answer from the record.
fn remembered(
    cache: &RevisionCache,
    key: &vera_domain::ConsensusPublicKey,
    light: &LightBlock,
) -> bool {
    let artifacts = light.artifacts().unwrap();
    let (block, hash) = vera_domain::verify_finalized_block_unless(light, key, |_, _, _| true)
        .expect("the displayed fields match the block");
    cache.holds(
        key,
        &block,
        Remembered {
            block: hash,
            evidence: artifacts.finality_digest(),
        },
    )
}

/// A light block whose block is `light`'s and whose certificate is another block's.
fn with_certificate_of(light: &LightBlock, other: &LightBlock) -> LightBlock {
    LightBlock {
        finalization: other.finalization.clone(),
        ..light.clone()
    }
}

fn revision(deployment: &TestDeployment, height: u64, term: u64, root: u8) -> LightBlock {
    deployment.light_block(&deployment.block(
        height,
        B256::repeat_byte(0x10),
        term,
        B256::repeat_byte(root),
    ))
}

#[test]
fn a_verified_revision_answers_from_the_record_only_with_the_evidence_it_verified() {
    let deployment = TestDeployment::new(7);
    let key = deployment.key();
    let cache = RevisionCache::new(8);
    let first = revision(&deployment, 5, 0, 1);
    let unrelated = revision(&deployment, 6, 0, 2);
    let uncertified = with_certificate_of(&first, &unrelated);

    assert!(matches!(
        cache.under(&key).finalized_block(&uncertified),
        Err(LightBlockError::ProposalMismatch)
    ));
    assert_eq!(cache.len(), 0);

    let block = cache.under(&key).finalized_block(&first).unwrap();
    assert_eq!(block.module_state_root, B256::repeat_byte(1));
    assert_eq!(cache.len(), 1);
    assert!(remembered(&cache, &key, &first));
    // A remembered block served with another certificate is verified in
    // full, and refused.
    assert!(!remembered(&cache, &key, &uncertified));
    assert!(matches!(
        cache.under(&key).finalized_block(&uncertified),
        Err(LightBlockError::ProposalMismatch)
    ));
    assert_eq!(cache.under(&key).finalized_block(&first).unwrap(), block);
    assert_eq!(cache.len(), 1);
}

#[test]
fn a_remembered_revision_still_binds_every_displayed_field() {
    let deployment = TestDeployment::new(7);
    let key = deployment.key();
    let cache = RevisionCache::new(8);
    let first = revision(&deployment, 5, 0, 1);
    cache.under(&key).finalized_block(&first).unwrap();

    let mut restated = first;
    restated.timestamp += 1;
    assert!(matches!(
        cache.under(&key).finalized_block(&restated),
        Err(LightBlockError::BlockFieldMismatch("timestamp"))
    ));
}

#[test]
fn a_different_block_at_a_remembered_height_is_verified_and_empties_the_record() {
    let deployment = TestDeployment::new(7);
    let key = deployment.key();
    let cache = RevisionCache::new(8);
    let lower = revision(&deployment, 4, 0, 3);
    let first = revision(&deployment, 5, 0, 1);
    let second = revision(&deployment, 5, 0, 2);
    cache.under(&key).finalized_block(&lower).unwrap();
    cache.under(&key).finalized_block(&first).unwrap();

    let uncertified = with_certificate_of(&second, &first);
    assert!(matches!(
        cache.under(&key).finalized_block(&uncertified),
        Err(LightBlockError::ProposalMismatch)
    ));
    assert_eq!(cache.len(), 2);

    cache.under(&key).finalized_block(&second).unwrap();
    assert_eq!(cache.len(), 1);
    // Neither the replaced block nor its neighbours answer from the record.
    for stale in [&first, &lower] {
        assert!(matches!(
            cache
                .under(&key)
                .finalized_block(&with_certificate_of(stale, &second)),
            Err(LightBlockError::ProposalMismatch)
        ));
    }
}

#[test]
fn a_later_term_empties_the_record_and_earlier_terms_are_not_remembered() {
    let deployment = TestDeployment::new(7);
    let key = deployment.key();
    let cache = RevisionCache::new(8);
    let before = revision(&deployment, 5, 0, 1);
    let after = revision(&deployment, 6, 1, 2);
    cache.under(&key).finalized_block(&before).unwrap();

    cache.under(&key).finalized_block(&after).unwrap();
    assert_eq!(cache.len(), 1);
    let uncertified = with_certificate_of(&before, &after);
    assert!(matches!(
        cache.under(&key).finalized_block(&uncertified),
        Err(LightBlockError::ProposalMismatch)
    ));

    // A block of the earlier term verifies with its certificate every time.
    cache.under(&key).finalized_block(&before).unwrap();
    assert_eq!(cache.len(), 1);
    assert!(cache.under(&key).finalized_block(&uncertified).is_err());
    // The later term's block is still remembered, with its own certificate.
    assert!(remembered(&cache, &key, &after));
    assert!(
        cache
            .under(&key)
            .finalized_block(&with_certificate_of(&after, &before))
            .is_err()
    );
}

#[test]
fn another_consensus_key_shares_no_remembered_revision() {
    let deployment = TestDeployment::new(7);
    let other = TestDeployment::new(900);
    let cache = RevisionCache::new(8);
    let first = revision(&deployment, 5, 0, 1);
    cache
        .under(&deployment.key())
        .finalized_block(&first)
        .unwrap();

    assert!(matches!(
        cache.under(&other.key()).finalized_block(&first),
        Err(LightBlockError::UntrustedConsensusKey)
    ));
}

#[test]
fn the_record_keeps_the_newest_revisions_within_its_bound() {
    let deployment = TestDeployment::new(7);
    let key = deployment.key();
    let cache = RevisionCache::new(2);
    let revisions: Vec<_> = (1..=3)
        .map(|height| revision(&deployment, height, 0, height as u8))
        .collect();
    for light in &revisions {
        cache.under(&key).finalized_block(light).unwrap();
    }
    assert_eq!(cache.len(), 2);
    let oldest = with_certificate_of(&revisions[0], &revisions[2]);
    assert!(cache.under(&key).finalized_block(&oldest).is_err());
    assert!(!remembered(&cache, &key, &revisions[0]));
    assert!(remembered(&cache, &key, &revisions[2]));
    let newest = with_certificate_of(&revisions[2], &revisions[0]);
    assert!(cache.under(&key).finalized_block(&newest).is_err());

    let disabled = RevisionCache::new(0);
    disabled.under(&key).finalized_block(&revisions[0]).unwrap();
    assert_eq!(disabled.len(), 0);
}
