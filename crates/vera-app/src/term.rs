//! The term a node proposes in and the lowest term it accepts.

use std::sync::{Arc, RwLock};

/// The newest term a node holds and the height that term starts above.
///
/// A switch of the active device raises the term above a cut: the last block
/// of the term before. A node that holds a term builds its blocks in it and
/// refuses a block above the cut that carries a lower one. A node that holds
/// none proposes in term 0 and accepts whatever term its parent allows.
#[derive(Clone, Debug, Default)]
pub struct TermGuard(Arc<RwLock<Held>>);

#[derive(Clone, Copy, Debug, Default)]
struct Held {
    term: u64,
    cut: u64,
    /// Height and term of the newest finalized block seen.
    tip: Option<(u64, u64)>,
}

impl TermGuard {
    /// Hold `term`, which starts above the block at height `cut`. A lower
    /// term than the one held is ignored.
    pub fn raise(&self, term: u64, cut: u64) {
        let mut held = self.0.write().expect("term lock poisoned");
        if term > held.term {
            held.term = term;
            held.cut = cut;
        }
    }

    /// The term held.
    #[must_use]
    pub fn term(&self) -> u64 {
        self.0.read().expect("term lock poisoned").term
    }

    /// The height the held term starts above.
    #[must_use]
    pub fn cut(&self) -> u64 {
        self.0.read().expect("term lock poisoned").cut
    }

    /// Whether a block at `height` may carry `term`.
    #[must_use]
    pub fn admits(&self, height: u64, term: u64) -> bool {
        let held = *self.0.read().expect("term lock poisoned");
        height <= held.cut || term >= held.term
    }
}

impl TermGuard {
    /// Height and term of the newest finalized block recorded.
    #[must_use]
    pub fn tip(&self) -> Option<(u64, u64)> {
        self.0.read().expect("term lock poisoned").tip
    }

    /// Record a finalized block. An older one than the newest seen is ignored.
    pub fn observe(&self, height: u64, term: u64) {
        let mut held = self.0.write().expect("term lock poisoned");
        if held.tip.is_none_or(|(seen, _)| height > seen) {
            held.tip = Some((height, term));
        }
    }

    /// Whether a finalized block at `height` may carry `term`, judged without
    /// its parent: a finalized block is replayed where the parent may be gone.
    ///
    /// The parent's term is known only when the block before was observed.
    #[must_use]
    pub fn admits_finalized(&self, height: u64, term: u64) -> bool {
        let held = *self.0.read().expect("term lock poisoned");
        let follows = held.tip.is_none_or(|(seen, parent)| {
            seen.checked_add(1) != Some(height) || vera_domain::term_extends(parent, term)
        });
        follows && (height <= held.cut || term >= held.term)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_held_term_is_required_above_its_cut_only() {
        let guard = TermGuard::default();
        assert!(guard.admits(9, 0));
        guard.raise(2, 40);
        assert_eq!((guard.term(), guard.cut()), (2, 40));
        assert!(guard.admits(40, 1));
        assert!(!guard.admits(41, 1));
        assert!(guard.admits(41, 2));
        assert!(guard.admits(41, 3));
    }

    #[test]
    fn a_lower_term_does_not_replace_the_one_held() {
        let guard = TermGuard::default();
        guard.raise(3, 10);
        guard.raise(2, 99);
        guard.raise(3, 50);
        assert_eq!((guard.term(), guard.cut()), (3, 10));
    }

    #[test]
    fn a_finalized_block_is_judged_against_the_block_observed_before_it() {
        let guard = TermGuard::default();
        assert!(guard.admits_finalized(8, 0));
        guard.observe(7, 2);
        guard.observe(6, 5);
        assert!(guard.admits_finalized(8, 2));
        assert!(guard.admits_finalized(8, 3));
        assert!(!guard.admits_finalized(8, 1));
        // The block before height 10 was not observed.
        assert!(guard.admits_finalized(10, 1));
        guard.raise(4, 7);
        assert!(!guard.admits_finalized(8, 3));
        assert!(guard.admits_finalized(8, 4));
    }
}
