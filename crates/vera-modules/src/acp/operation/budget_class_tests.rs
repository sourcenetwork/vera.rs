//! Short-lived and long-lived outcomes count against separate budgets.

use vera_crypto::operation::DEFAULT_OPERATION_LEAD;

use super::*;

const NOW: u64 = 100;
const HOUR: u64 = 3600;

struct Fixture {
    acp: AcpModule,
    vera: VeraModule,
    policy: String,
}

impl Fixture {
    fn new() -> Self {
        let mut acp = AcpModule::new();
        let policy = acp
            .create_policy(
                &vera_identity::Did::new(issuer()).unwrap(),
                POLICY,
                FORMAT,
                Default::default(),
            )
            .unwrap()
            .policy
            .id;
        acp.set_policy_operation_lead(2 * HOUR).unwrap();
        Self {
            acp,
            vera: VeraModule::new(),
            policy,
        }
    }

    fn fill(&mut self, class: OutcomeClass) {
        let floor = MAX_OPERATION_RECORD_BYTES as u64;
        self.acp.set_class_budget(class, floor).unwrap();
        self.acp
            .store
            .put(class.bytes_key(), floor.to_be_bytes().to_vec());
    }

    fn claim(&mut self, entropy: u8, deadline: u64) -> Result<PolicyCmdResultValue> {
        let worker = submission(7);
        let command = PolicyCmd::RegisterObject(Object {
            resource: "file".into(),
            id: format!("object-{entropy}"),
        });
        let call = DelegatedOperation::PolicyCommand(&self.policy, &command);
        let identity = id(entropy, deadline);
        self.acp
            .bearer_policy_cmd(
                &mut self.vera,
                &context(NOW),
                &worker,
                &token(&worker, identity, &call),
                &self.policy,
                command,
            )
            .map(|result| serde_json::to_value(result).unwrap())
    }

    fn state(&self) -> (Vec<u8>, Vec<u8>) {
        (self.acp.store().serialize(), self.vera.store().serialize())
    }
}

type PolicyCmdResultValue = serde_json::Value;

const SHORT: u64 = NOW + DEFAULT_OPERATION_LEAD;
const LONG: u64 = NOW + DEFAULT_OPERATION_LEAD + 1;

#[test]
fn an_identity_is_long_lived_only_beyond_the_default_lead_at_its_claim() {
    assert_eq!(OutcomeClass::of(id(1, SHORT), NOW), OutcomeClass::Short);
    assert_eq!(OutcomeClass::of(id(1, LONG), NOW), OutcomeClass::Long);
    assert_eq!(OutcomeClass::of(id(1, LONG), NOW + 1), OutcomeClass::Short);
}

#[test]
fn a_full_long_budget_refuses_long_outcomes_but_not_short_ones() {
    let mut fixture = Fixture::new();
    fixture.fill(OutcomeClass::Long);
    let before = fixture.state();
    assert!(fixture.claim(1, LONG).is_err());
    assert_eq!(fixture.state(), before);
    fixture.claim(2, SHORT).unwrap();
    assert!(fixture.acp.operation_bytes(OutcomeClass::Short).unwrap() > 0);
}

#[test]
fn a_full_short_budget_refuses_short_outcomes_but_not_long_ones() {
    let mut fixture = Fixture::new();
    fixture.fill(OutcomeClass::Short);
    let before = fixture.state();
    assert!(fixture.claim(1, SHORT).is_err());
    assert_eq!(fixture.state(), before);
    fixture.claim(2, NOW + 2 * HOUR).unwrap();
    assert!(fixture.acp.operation_bytes(OutcomeClass::Long).unwrap() > 0);
}

#[test]
fn cleanup_releases_each_class_even_after_the_lead_is_lowered() {
    let mut fixture = Fixture::new();
    fixture.claim(1, SHORT).unwrap();
    fixture.claim(2, NOW + 2 * HOUR).unwrap();
    let short = fixture.acp.operation_bytes(OutcomeClass::Short).unwrap();
    let long = fixture.acp.operation_bytes(OutcomeClass::Long).unwrap();
    assert!(short > 0 && long > 0);
    fixture
        .acp
        .set_policy_operation_lead(DEFAULT_OPERATION_LEAD)
        .unwrap();
    fixture.acp.end_blocker(&context(SHORT)).unwrap();
    assert_eq!(fixture.acp.operation_bytes(OutcomeClass::Short).unwrap(), 0);
    assert_eq!(
        fixture.acp.operation_bytes(OutcomeClass::Long).unwrap(),
        long
    );
    fixture.acp.end_blocker(&context(NOW + 2 * HOUR)).unwrap();
    assert_eq!(fixture.acp.operation_bytes(OutcomeClass::Long).unwrap(), 0);
}

#[test]
fn an_unknown_class_in_the_expiry_index_is_a_state_error() {
    let mut fixture = Fixture::new();
    fixture.claim(1, SHORT).unwrap();
    let (index, mut value) = fixture
        .acp
        .store
        .prefix_iter(EXPIRY_PREFIX)
        .map(|(index, value)| (index.to_vec(), value.to_vec()))
        .next()
        .unwrap();
    *value.last_mut().unwrap() = 2;
    fixture.acp.store.put(&index, value);
    let before = fixture.acp.store().serialize();
    assert!(matches!(
        fixture.acp.prune_operations(SHORT),
        Err(AcpError::State(_))
    ));
    assert_eq!(fixture.acp.store().serialize(), before);
}

#[test]
fn each_budget_cannot_fall_below_its_own_retained_usage() {
    let mut acp = AcpModule::new();
    let usage = 2 * MAX_OPERATION_RECORD_BYTES as u64;
    for class in [OutcomeClass::Short, OutcomeClass::Long] {
        acp.store
            .put(class.bytes_key(), usage.to_be_bytes().to_vec());
        let before = acp.store().serialize();
        assert!(acp.set_class_budget(class, usage - 1).is_err());
        assert_eq!(acp.store().serialize(), before);
        acp.set_class_budget(class, usage).unwrap();
        acp.store
            .put(class.bytes_key(), 0u64.to_be_bytes().to_vec());
    }
    assert_eq!(acp.operation_budget().unwrap(), usage);
    assert_eq!(acp.long_operation_budget().unwrap(), usage);
}
