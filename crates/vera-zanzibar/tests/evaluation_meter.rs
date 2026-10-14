use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use zanzibar::{
    engine::EvaluationMeter,
    error::{Error, Result},
    store::MemoryZanzibarStore,
    Did, PermissionCheckRequest, PermissionEngine, Policy, Relation, Resource,
};

#[derive(Debug)]
struct Meter(AtomicUsize);

impl EvaluationMeter for Meter {
    fn charge_step(&self) -> Result<()> {
        self.0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
            .map(|_| ())
            .map_err(|_| Error::EvaluationLimitExceeded("caller allowance"))
    }
}

fn engine(steps: usize) -> (PermissionEngine<MemoryZanzibarStore>, Arc<Meter>) {
    let meter = Arc::new(Meter(AtomicUsize::new(steps)));
    let mut engine = PermissionEngine::new(Arc::new(MemoryZanzibarStore::new()))
        .with_evaluation_meter(meter.clone());
    engine.add_policy(
        &Policy::new("p", "p")
            .with_resource(Resource::new("group").with_relation(Relation::direct("member"))),
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

#[tokio::test]
async fn cached_batch_checks_charge_the_same_caller_allowance() {
    let (engine, meter) = engine(2);
    let actor = Did::new("did:key:actor").unwrap();
    let requests = vec![PermissionCheckRequest::new("p", "group", "a", "member", &actor); 3];
    let results = engine.check_many(&requests).await;
    assert!(matches!(results[0], Ok(false)));
    assert!(matches!(results[1], Ok(false)));
    assert!(matches!(
        results[2],
        Err(Error::EvaluationLimitExceeded("caller allowance"))
    ));
    assert_eq!(meter.0.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn explanations_propagate_caller_exhaustion_instead_of_denial() {
    let (engine, meter) = engine(1);
    let actor = Did::new("did:key:actor").unwrap();
    assert!(
        !engine
            .explain("p", "group", "a", "member", &actor)
            .await
            .unwrap()
            .granted
    );
    assert_eq!(meter.0.load(Ordering::Relaxed), 0);
    assert!(matches!(
        engine.explain("p", "group", "a", "member", &actor).await,
        Err(Error::EvaluationLimitExceeded("caller allowance"))
    ));
}
