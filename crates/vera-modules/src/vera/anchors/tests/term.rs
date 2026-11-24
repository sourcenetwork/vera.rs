//! Certified terms move the tip to their cut and supersede the anchors above it.

use super::*;

fn term(term: u64, cut_height: u64, cut: u8) -> VerifiedTerm {
    VerifiedTerm {
        term,
        holder: B256::repeat_byte(0xd0),
        cut_height,
        cut_block: B256::repeat_byte(cut),
    }
}

#[test]
fn a_term_above_the_certified_one_is_refused_until_its_certificate_is_recorded() {
    let key = key(4);
    let deployment = deployment_id(&key);
    let mut module = registered(&[&key]);
    // Whoever holds the key can mint a block of any term; it anchors nothing.
    assert_eq!(
        module.record_anchor(&context(1), &deployment, &revision(20, 2, 1)),
        Err(AnchorError::TermNotCertified {
            certified: 0,
            term: 2
        })
    );
    module
        .record_anchor(&context(1), &deployment, &revision(20, 0, 1))
        .unwrap();
    assert_eq!(
        module.record_anchor(&context(2), &deployment, &descendant(30, 1, 3, 20, 1)),
        Err(AnchorError::TermNotCertified {
            certified: 0,
            term: 1
        })
    );

    // Term 1 builds on the anchored block.
    let recorded = module
        .record_term(&context(3), &deployment, &term(1, 20, 1))
        .unwrap();
    assert_eq!(
        (
            recorded.term,
            recorded.cut_height,
            recorded.sequence,
            recorded.recorded_at
        ),
        (1, 20, 1, 3)
    );
    assert_eq!(recorded.holder, B256::repeat_byte(0xd0));
    assert_eq!(
        module.term_record(&deployment, 1).unwrap(),
        Some(recorded.clone())
    );
    assert_eq!(module.deployment(&deployment).unwrap().unwrap().term, 1);
    assert_eq!(
        TermRecord::decode(&deployment, &term_key(&deployment, 1), &recorded.encode()).unwrap(),
        recorded
    );
    assert_eq!(
        TermRecord::decode(&deployment, &term_key(&deployment, 2), &recorded.encode()),
        Err(AnchorError::MalformedRecord)
    );
    // A block above the cut in the replaced term is void, and one of a later term uncertified.
    assert_eq!(
        module.record_anchor(&context(4), &deployment, &descendant(30, 0, 3, 20, 1)),
        Err(AnchorError::LowerTerm { latest: 1, term: 0 })
    );
    assert_eq!(
        module.record_anchor(&context(4), &deployment, &descendant(30, 2, 3, 20, 1)),
        Err(AnchorError::TermNotCertified {
            certified: 1,
            term: 2
        })
    );
    let anchored = module
        .record_anchor(&context(4), &deployment, &descendant(30, 1, 3, 20, 1))
        .unwrap();
    assert_eq!((anchored.record.sequence, anchored.record.term), (2, 1));

    // A term is recorded once, and only above the one recorded last.
    for stale in [1, 0] {
        assert_eq!(
            module.record_term(&context(5), &deployment, &term(stale, 30, 3)),
            Err(AnchorError::TermNotNewer {
                certified: 1,
                term: stale
            })
        );
    }
    assert_eq!(
        module.record_term(&context(5), &B256::ZERO, &term(2, 30, 3)),
        Err(AnchorError::NotRegistered)
    );
    // A registration that replaces the operator policy keeps the term.
    module.register_deployment(&registration(&key), 9).unwrap();
    assert_eq!(module.deployment(&deployment).unwrap().unwrap().term, 1);
}

#[test]
fn a_term_whose_cut_is_below_the_latest_anchor_supersedes_the_anchors_above_it() {
    let key = key(16);
    let deployment = deployment_id(&key);
    let mut module = registered(&[&key]);
    let first = module
        .record_anchor(&context(1), &deployment, &revision(10, 0, 1))
        .unwrap()
        .record;
    let second = module
        .record_anchor(&context(2), &deployment, &descendant(20, 0, 2, 10, 1))
        .unwrap()
        .record;
    let third = module
        .record_anchor(&context(3), &deployment, &descendant(30, 0, 3, 20, 2))
        .unwrap()
        .record;

    // The device that took over held the chain up to height 15.
    let taken = module
        .record_term(&context(4), &deployment, &term(1, 15, 9))
        .unwrap();
    assert_eq!(taken.sequence, 3);
    let superseded = |record: &AnchorRecord| {
        taken.supersedes(record.sequence, record.height, &record.block_hash)
    };
    assert!(!superseded(&first));
    assert!(superseded(&second));
    assert!(superseded(&third));
    // Another block at the cut's height is void too; the cut itself is kept.
    assert!(taken.supersedes(2, 15, &B256::repeat_byte(8)));
    assert!(!taken.supersedes(2, 15, &B256::repeat_byte(9)));

    // The latest anchor recorded is still the third, and the chain continues from the cut.
    let registered = module.deployment(&deployment).unwrap().unwrap();
    let lineage = module.lineage(&registered).unwrap();
    assert_eq!(lineage.latest.as_ref(), Some(&third));
    assert_eq!(lineage.tip(), Some((15, B256::repeat_byte(9))));
    assert_eq!(lineage.certified_term(), 1);
    assert!(lineage.voids(16, 0));
    assert!(!lineage.voids(15, 0));
    assert!(!lineage.voids(16, 1));

    // The next anchor proves the cut, not the superseded anchor, and may be below it.
    assert_eq!(
        module.record_anchor(&context(5), &deployment, &descendant(40, 1, 4, 30, 3)),
        Err(AnchorError::NotDescendant {
            latest: 15,
            height: 40
        })
    );
    assert_eq!(
        module.record_anchor(&context(5), &deployment, &descendant(15, 1, 9, 10, 1)),
        Err(AnchorError::NotNewer {
            latest: 15,
            height: 15
        })
    );
    // Resubmitting the superseded anchor records nothing.
    assert_eq!(
        module.record_anchor(&context(5), &deployment, &descendant(30, 0, 3, 20, 2)),
        Err(AnchorError::LowerTerm { latest: 1, term: 0 })
    );
    let fourth = module
        .record_anchor(&context(5), &deployment, &descendant(25, 1, 4, 15, 9))
        .unwrap()
        .record;
    assert_eq!((fourth.sequence, fourth.height), (4, 25));
    assert!(
        !superseded(&fourth),
        "an anchor of the term is not superseded by it"
    );
    // From then on the chain extends its own anchors again.
    module
        .record_anchor(&context(6), &deployment, &descendant(26, 1, 5, 25, 4))
        .unwrap();
    assert!(
        !module
            .record_anchor(&context(7), &deployment, &descendant(26, 1, 5, 25, 4))
            .unwrap()
            .recorded
    );
}

#[test]
fn a_term_can_be_recorded_before_the_first_anchor() {
    let key = key(17);
    let deployment = deployment_id(&key);
    let mut module = registered(&[&key]);
    let taken = module
        .record_term(&context(1), &deployment, &term(3, 50, 5))
        .unwrap();
    assert_eq!(taken.sequence, 0);
    assert_eq!(
        module.record_anchor(&context(2), &deployment, &revision(60, 3, 6)),
        Err(AnchorError::NotDescendant {
            latest: 50,
            height: 60
        })
    );
    let first = module
        .record_anchor(&context(2), &deployment, &descendant(60, 3, 6, 50, 5))
        .unwrap();
    assert_eq!(first.record.sequence, 1);
}

#[test]
fn a_block_the_certified_term_voids_is_no_fork_and_one_that_leaves_the_cut_is() {
    let key = key(18);
    let deployment = deployment_id(&key);
    let mut module = registered(&[&key]);
    module
        .record_anchor(&context(1), &deployment, &revision(10, 0, 1))
        .unwrap();
    module
        .record_term(&context(2), &deployment, &term(1, 20, 2))
        .unwrap();
    // The replaced device went on above the cut: void, not a fork.
    assert_eq!(
        module.record_fork(&context(3), &deployment, &descendant(25, 0, 7, 20, 8)),
        Err(AnchorError::NotAFork {
            latest: 20,
            height: 25
        })
    );
    // A block of the term whose ancestor at the cut is another block is a fork of the cut.
    let fork = module
        .record_fork(&context(3), &deployment, &descendant(25, 1, 7, 20, 8))
        .unwrap();
    assert_eq!(
        (fork.sequence, fork.anchored_height, fork.anchored_block),
        (1, 20, B256::repeat_byte(2))
    );
}

#[test]
fn a_block_of_an_uncertified_term_is_no_fork_until_its_certificate_explains_it() {
    let key = key(19);
    let deployment = deployment_id(&key);
    let mut module = registered(&[&key]);
    // Device A anchored up to 80 in term 0.
    module
        .record_anchor(&context(1), &deployment, &revision(50, 0, 5))
        .unwrap();
    module
        .record_anchor(&context(2), &deployment, &descendant(80, 0, 8, 50, 5))
        .unwrap();
    // Device B's block at 90 in term 1, whose cut is at 50, is reported before
    // the term's certificate lands.
    let switched = descendant(90, 1, 9, 80, 7);
    assert_eq!(
        module.record_fork(&context(3), &deployment, &switched),
        Err(AnchorError::TermNotCertified {
            certified: 0,
            term: 1
        })
    );
    assert!(module.forks(&deployment).unwrap().is_empty());

    // Once term 1 is recorded the block descends from its cut: a
    // supersession, not a fork.
    module
        .record_term(&context(4), &deployment, &term(1, 50, 5))
        .unwrap();
    assert_eq!(
        module.record_fork(&context(5), &deployment, &descendant(90, 1, 9, 50, 5)),
        Err(AnchorError::NotAFork {
            latest: 50,
            height: 90
        })
    );
    module
        .record_anchor(&context(5), &deployment, &descendant(90, 1, 9, 50, 5))
        .unwrap();
    assert!(module.forks(&deployment).unwrap().is_empty());
}

#[test]
fn a_page_cursor_reads_back_only_canonical_term_and_fork_keys() {
    let deployment = B256::repeat_byte(4);
    let other = B256::repeat_byte(5);
    assert_eq!(
        term_of_key(&deployment, &term_key(&deployment, 0x2a)),
        Some(0x2a)
    );
    assert_eq!(term_of_key(&deployment, &term_key(&other, 0x2a)), None);
    let upper = [term_prefix(&deployment).as_slice(), b"000000000000002A"].concat();
    assert_eq!(term_of_key(&deployment, &upper), None);
    assert_eq!(term_of_key(&deployment, &term_prefix(&deployment)), None);

    let block = B256::repeat_byte(0xab);
    assert_eq!(
        fork_block_of_key(&deployment, &fork_key(&deployment, &block)),
        Some(block)
    );
    assert_eq!(
        fork_block_of_key(&deployment, &fork_key(&other, &block)),
        None
    );
    let upper = [
        fork_prefix(&deployment).as_slice(),
        "AB".repeat(32).as_bytes(),
    ]
    .concat();
    assert_eq!(fork_block_of_key(&deployment, &upper), None);
}
