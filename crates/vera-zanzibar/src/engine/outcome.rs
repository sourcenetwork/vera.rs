/// Trail positions whose revisit was cut short as `false`.
///
/// The trail holds at most one node per active evaluation, so its positions
/// fit one word.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Assumed(u64);

impl Assumed {
    pub(crate) const POSITIONS: usize = u64::BITS as usize;

    pub(crate) fn position(position: usize) -> Self {
        Self(1 << position)
    }

    pub(crate) fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub(crate) fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub(crate) fn without(self, position: usize) -> Self {
        Self(self.0 & !Self::position(position).0)
    }

    /// The deepest position, which is the first to close.
    pub(crate) fn innermost(self) -> Option<usize> {
        self.0.checked_ilog2().map(|position| position as usize)
    }
}

/// Result of evaluating one expression for one subject.
///
/// A grant is exact. A denial names the open trail nodes it assumed to be
/// false. While that set is non-empty the denial holds only until one of
/// those nodes closes, so it is never negated.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Outcome {
    Granted,
    Denied(Assumed),
}

impl Outcome {
    pub(crate) fn denied() -> Self {
        Self::Denied(Assumed::default())
    }

    pub(crate) fn truncated(position: usize) -> Self {
        Self::Denied(Assumed::position(position))
    }

    pub(crate) fn exact(value: bool) -> Self {
        if value {
            Self::Granted
        } else {
            Self::denied()
        }
    }

    /// The decision, when it does not depend on a truncation.
    pub(crate) fn as_exact(&self) -> Option<bool> {
        match self {
            Self::Granted => Some(true),
            Self::Denied(assumed) => assumed.is_empty().then_some(false),
        }
    }

    /// Close the evaluation of the node at `position`. A denial that assumed
    /// only that node to be false is the node's least fixed point, because a
    /// node never reaches itself through an exclusion.
    pub(crate) fn settle(self, position: usize) -> Self {
        match self {
            Self::Granted => Self::Granted,
            Self::Denied(assumed) => Self::Denied(assumed.without(position)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_innermost_assumption_is_the_deepest_position() {
        let assumed = Assumed::position(3)
            .union(Assumed::position(Assumed::POSITIONS - 1))
            .union(Assumed::position(0));
        assert_eq!(assumed.innermost(), Some(Assumed::POSITIONS - 1));
        let assumed = assumed.without(Assumed::POSITIONS - 1);
        assert_eq!(assumed.innermost(), Some(3));
        assert_eq!(assumed.without(3).without(0).innermost(), None);
    }
}
