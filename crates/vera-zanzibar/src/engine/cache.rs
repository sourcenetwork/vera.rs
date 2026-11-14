use std::collections::HashMap;

use async_lock::RwLock;

use super::outcome::{Assumed, Outcome};
use crate::did::Did;
use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct NodeId(String, String, String);

impl NodeId {
    pub(crate) fn new(resource: &str, object_id: &str, relation: &str) -> Self {
        Self(
            resource.to_owned(),
            object_id.to_owned(),
            relation.to_owned(),
        )
    }
}

/// The nodes still being evaluated, each at the position it was opened in.
#[derive(Debug, Clone, Default)]
pub(crate) struct NodeTrail {
    open: HashMap<NodeId, usize>,
}

impl NodeTrail {
    pub(crate) fn position(&self, node: &NodeId) -> Option<usize> {
        self.open.get(node).copied()
    }

    /// Open `node` beneath this trail, returning the trail and its position.
    pub(crate) fn with_node(&self, node: NodeId) -> Result<(Self, usize)> {
        let position = self.open.len();
        if position >= Assumed::POSITIONS {
            return Err(Error::EvaluationLimitExceeded("depth"));
        }
        let mut trail = self.clone();
        trail.open.insert(node, position);
        Ok((trail, position))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CheckKey(String, NodeId, Did);

impl CheckKey {
    pub(crate) fn new(policy: &str, node: NodeId, subject: &Did) -> Self {
        Self(policy.to_owned(), node, subject.clone())
    }
}

/// Outcomes of the nodes closed so far in one check.
///
/// A denial that assumed open trail nodes to be false is kept for as long as
/// they stay open, filed under the innermost of them. When that node closes
/// denied, its own assumptions replace it; when it closes granted, the denial
/// is forgotten. A dense cycle is therefore walked once rather than once per
/// path through it.
#[derive(Debug, Default)]
struct Memo {
    known: HashMap<CheckKey, Outcome>,
    waiting: HashMap<usize, Vec<CheckKey>>,
}

impl Memo {
    fn close(&mut self, key: CheckKey, position: usize, outcome: Outcome) {
        let dependents = self.waiting.remove(&position).unwrap_or_default();
        match outcome {
            Outcome::Granted => {
                for dependent in dependents {
                    self.known.remove(&dependent);
                }
            }
            Outcome::Denied(assumed) => {
                for dependent in dependents {
                    let Some(Outcome::Denied(resting)) = self.known.get_mut(&dependent) else {
                        continue;
                    };
                    *resting = resting.without(position).union(assumed);
                    let resting = *resting;
                    self.file(dependent, resting);
                }
                self.file(key.clone(), assumed);
            }
        }
        self.known.insert(key, outcome);
    }

    fn file(&mut self, key: CheckKey, assumed: Assumed) {
        if let Some(innermost) = assumed.innermost() {
            self.waiting.entry(innermost).or_default().push(key);
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct CheckCache {
    pub(crate) budget: super::limits::EvaluationBudget,
    memo: RwLock<Memo>,
}

impl CheckCache {
    pub(crate) fn new(meter: Option<std::sync::Arc<dyn super::EvaluationMeter>>) -> Self {
        Self {
            budget: super::limits::EvaluationBudget::new(meter),
            ..Self::default()
        }
    }

    pub(crate) async fn get(&self, key: &CheckKey) -> Option<Outcome> {
        self.memo.read().await.known.get(key).copied()
    }

    /// Record the settled outcome of the node that was open at `position`.
    pub(crate) async fn close(&self, key: CheckKey, position: usize, outcome: Outcome) {
        self.memo.write().await.close(key, position, outcome);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(object: &str) -> CheckKey {
        CheckKey::new(
            "policy",
            NodeId::new("group", object, "member"),
            &Did::new("did:key:actor").unwrap(),
        )
    }

    #[test]
    fn node_identity_keeps_delimited_fields_separate() {
        let first = NodeId::new("resource", "object#nested", "relation");
        let second = NodeId::new("resource", "object", "nested#relation");
        assert_ne!(first, second);
        let (trail, position) = NodeTrail::default().with_node(first.clone()).unwrap();
        assert_eq!(trail.position(&first), Some(position));
        assert_eq!(trail.position(&second), None);
        assert_ne!(NodeId::new("a/b", "c", "d"), NodeId::new("a", "b/c", "d"));
    }

    #[test]
    fn the_trail_holds_no_more_nodes_than_an_assumption_can_name() {
        let mut trail = NodeTrail::default();
        for index in 0..Assumed::POSITIONS {
            trail = trail
                .with_node(NodeId::new("group", &index.to_string(), "member"))
                .unwrap()
                .0;
        }
        assert!(trail
            .with_node(NodeId::new("group", "last", "member"))
            .is_err());
    }

    #[test]
    fn a_denial_becomes_exact_once_every_node_it_assumed_closes_denied() {
        let mut memo = Memo::default();
        memo.close(
            key("c"),
            2,
            Outcome::Denied(Assumed::position(0).union(Assumed::position(1))),
        );
        assert_eq!(memo.known[&key("c")].as_exact(), None);

        memo.close(key("b"), 1, Outcome::truncated(0));
        assert_eq!(memo.known[&key("c")].as_exact(), None);

        memo.close(key("a"), 0, Outcome::denied());
        for object in ["a", "b", "c"] {
            assert_eq!(memo.known[&key(object)].as_exact(), Some(false));
        }
        assert!(memo.waiting.is_empty());
    }

    #[test]
    fn a_denial_is_forgotten_when_a_node_it_assumed_is_granted() {
        let mut memo = Memo::default();
        memo.close(key("c"), 2, Outcome::truncated(1));
        memo.close(key("b"), 1, Outcome::Granted);
        assert!(!memo.known.contains_key(&key("c")));
        assert_eq!(memo.known[&key("b")].as_exact(), Some(true));
    }
}
