//! Property tests for relation-expression evaluation semantics.
//!
//! Generated expression trees over direct-relation atoms are evaluated both by
//! the engine and by a direct reference evaluator; the two must agree for
//! union, intersection and fail-closed difference. Algebraic laws are pinned
//! on top of the same generator.

use std::sync::Arc;

use proptest::prelude::*;
use zanzibar::{
    store::{MemoryZanzibarStore, ZanzibarStore},
    Did, PermissionEngine, Policy, Relation, RelationExpression, Relationship, Resource,
};

/// Direct relations forming the ground atoms of every generated expression.
const ATOMS: [&str; 4] = ["r0", "r1", "r2", "r3"];

fn atom() -> impl Strategy<Value = RelationExpression> {
    prop::sample::select(&ATOMS[..]).prop_map(RelationExpression::computed_userset)
}

fn tree(depth: u32) -> BoxedStrategy<RelationExpression> {
    if depth == 0 {
        atom().boxed()
    } else {
        prop_oneof![
            3 => atom(),
            2 => (tree(depth - 1), tree(depth - 1))
                .prop_map(|(l, r)| RelationExpression::Union(vec![l, r])),
            2 => (tree(depth - 1), tree(depth - 1))
                .prop_map(|(l, r)| RelationExpression::Intersection(vec![l, r])),
            2 => (tree(depth - 1), tree(depth - 1))
                .prop_map(|(base, subtract)| RelationExpression::difference(base, subtract)),
        ]
        .boxed()
    }
}

/// Ground-truth membership of one actor in the direct relations.
type Membership = [bool; ATOMS.len()];

/// Reference evaluator mirroring the engine's semantics over direct atoms:
/// union is disjunction, intersection is conjunction, and difference is
/// fail-closed subtraction (definite over direct atoms).
fn reference(expression: &RelationExpression, membership: &Membership) -> bool {
    match expression {
        RelationExpression::This => false,
        RelationExpression::ComputedUserset { relation } => ATOMS
            .iter()
            .position(|atom| atom == relation)
            .is_some_and(|index| membership[index]),
        RelationExpression::TupleToUserset { .. } => false,
        RelationExpression::Union(exprs) => exprs.iter().any(|e| reference(e, membership)),
        RelationExpression::Intersection(exprs) => exprs.iter().all(|e| reference(e, membership)),
        RelationExpression::Difference { base, subtract } => {
            reference(base, membership) && !reference(subtract, membership)
        }
        _ => false,
    }
}

fn policy_for(expression: &RelationExpression) -> Policy {
    let mut resource = Resource::new("document");
    for atom in ATOMS {
        resource = resource.with_relation(Relation::direct(atom));
    }
    resource = resource.with_relation(Relation::computed("permission", expression.clone()));
    Policy::new("property", "expression properties").with_resource(resource)
}

fn engine_check(expression: &RelationExpression, membership: &Membership, actor: &Did) -> bool {
    let store = Arc::new(MemoryZanzibarStore::new());
    let mut engine = PermissionEngine::new(store.clone());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    for (index, granted) in membership.iter().enumerate() {
        if *granted {
            runtime
                .block_on(store.store_relationship(
                    "property",
                    &Relationship::with_entity("document", "report", ATOMS[index], actor.clone()),
                ))
                .unwrap();
        }
    }
    engine.add_policy(&policy_for(expression));
    engine
        .check_blocking("property", "document", "report", "permission", actor)
        .expect("direct atoms keep evaluation definite")
}

fn membership() -> impl Strategy<Value = Membership> {
    prop::collection::vec(any::<bool>(), ATOMS.len()).prop_map(|bits| bits.try_into().unwrap())
}

fn actor() -> Did {
    Did::new("did:key:actor").unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn engine_agrees_with_the_reference_evaluator(
        expression in tree(3),
        membership in membership(),
    ) {
        let expected = reference(&expression, &membership);
        prop_assert_eq!(engine_check(&expression, &membership, &actor()), expected);
    }

    #[test]
    fn union_is_commutative(
        left in tree(2),
        right in tree(2),
        membership in membership(),
    ) {
        let forward = RelationExpression::union(vec![left.clone(), right.clone()]);
        let backward = RelationExpression::union(vec![right, left]);
        prop_assert_eq!(
            engine_check(&forward, &membership, &actor()),
            engine_check(&backward, &membership, &actor()),
        );
    }

    #[test]
    fn intersection_is_commutative(
        left in tree(2),
        right in tree(2),
        membership in membership(),
    ) {
        let forward = RelationExpression::intersection(vec![left.clone(), right.clone()]);
        let backward = RelationExpression::intersection(vec![right, left]);
        prop_assert_eq!(
            engine_check(&forward, &membership, &actor()),
            engine_check(&backward, &membership, &actor()),
        );
    }

    #[test]
    fn union_is_idempotent(
        atom in prop::sample::select(&ATOMS[..]),
        membership in membership(),
    ) {
        let single = RelationExpression::computed_userset(atom);
        let doubled = RelationExpression::union(vec![single.clone(), single.clone()]);
        prop_assert_eq!(
            engine_check(&doubled, &membership, &actor()),
            engine_check(&single, &membership, &actor()),
        );
    }

    #[test]
    fn difference_of_an_expression_with_itself_never_grants(
        expression in tree(2),
        membership in membership(),
    ) {
        let self_subtracted = RelationExpression::difference(expression.clone(), expression);
        prop_assert!(!engine_check(&self_subtracted, &membership, &actor()));
    }

    #[test]
    fn display_parse_preserves_semantics(expression in tree(3)) {
        let text = expression.to_string();
        let parsed = RelationExpression::parse(&text).unwrap();
        for bits in 0..(1 << ATOMS.len()) {
            let membership: Membership = (0..ATOMS.len())
                .map(|index| bits >> index & 1 == 1)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            prop_assert_eq!(
                reference(&parsed, &membership),
                reference(&expression, &membership),
            );
        }
    }
}

#[test]
fn a_parenthesized_single_expression_parses_to_its_element() {
    let parsed = RelationExpression::parse("(r0)").unwrap();
    assert_eq!(parsed, RelationExpression::computed_userset("r0"));
}
