use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use vera_zanzibar::{
    engine::EvaluationMeter,
    error::{Error, Result},
    store::MemoryZanzibarStore,
    Did, PermissionEngine, Policy, Relation, RelationExpression, Resource,
};

#[derive(Debug)]
struct Meter(AtomicUsize);

impl EvaluationMeter for Meter {
    fn charge_step(&self) -> Result<()> {
        self.0
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
            .map(|_| ())
            .map_err(|_| Error::EvaluationLimitExceeded("caller allowance"))
    }
}

fn engine(steps: usize) -> (PermissionEngine<MemoryZanzibarStore>, Arc<Meter>) {
    let meter = Arc::new(Meter(AtomicUsize::new(steps)));
    let mut engine = PermissionEngine::new(Arc::new(MemoryZanzibarStore::new()))
        .with_evaluation_meter(meter.clone());
    engine.add_policy(
        &Policy::new("p", "p").with_resource(
            Resource::new("group")
                .with_relation(Relation::direct("member"))
                .with_relation(Relation::computed(
                    "twice",
                    RelationExpression::parse("member + member").unwrap(),
                )),
        ),
    );
    (engine, meter)
}

#[test]
fn caller_allowance_survives_separate_blocking_checks() {
    let (engine, meter) = engine(2);
    let actor = Did::new("did:key:actor").unwrap();
    assert!(!engine
        .check_blocking("p", "group", "a", "member", &actor)
        .unwrap());
    assert!(!engine
        .check_blocking("p", "group", "b", "member", &actor)
        .unwrap());
    assert_eq!(meter.0.load(Ordering::Relaxed), 0);
    assert!(matches!(
        engine.check_blocking("p", "group", "a", "member", &actor),
        Err(Error::EvaluationLimitExceeded("caller allowance"))
    ));
}

/// The union, its two operands and the first `member` lookup each take a
/// step; the second operand is answered from the cache and still charged.
const TWICE_STEPS: usize = 5;

#[test]
fn a_cached_revisit_charges_the_caller_allowance() {
    let actor = Did::new("did:key:actor").unwrap();
    let (engine, meter) = engine(TWICE_STEPS);
    assert!(!engine
        .check_blocking("p", "group", "a", "twice", &actor)
        .unwrap());
    assert_eq!(meter.0.load(Ordering::Relaxed), 0);

    let (engine, _) = self::engine(TWICE_STEPS - 1);
    assert!(matches!(
        engine.check_blocking("p", "group", "a", "twice", &actor),
        Err(Error::EvaluationLimitExceeded("caller allowance"))
    ));
}
