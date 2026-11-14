use std::collections::HashSet;

use super::cache::NodeId;

/// Result of evaluating one expression for one subject.
///
/// A grant is exact. A denial names the trail nodes whose revisit was cut
/// short as `false`. While that set is non-empty the denial holds only for
/// the trail that produced it, so it is neither memoized nor negated.
#[derive(Debug)]
pub(crate) enum Outcome {
    Granted,
    Denied(HashSet<NodeId>),
}

impl Outcome {
    pub(crate) fn denied() -> Self {
        Self::Denied(HashSet::new())
    }

    pub(crate) fn truncated(node: NodeId) -> Self {
        Self::Denied(HashSet::from([node]))
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
            Self::Denied(truncated) => truncated.is_empty().then_some(false),
        }
    }

    /// Close the evaluation of `node`. A denial that assumed only `node`
    /// itself to be false is the node's least fixed point, because a node
    /// never reaches itself through an exclusion.
    pub(crate) fn settle(mut self, node: &NodeId) -> Self {
        if let Self::Denied(truncated) = &mut self {
            truncated.remove(node);
        }
        self
    }
}
