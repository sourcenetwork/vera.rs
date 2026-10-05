use super::*;
use crate::acp::*;

fn fixture(rows: usize, metadata_bytes: usize) -> (AcpModule, String) {
    let mut module = AcpModule::new();
    let owner = Did::new("did:key:owner").unwrap();
    let policy = module
        .create_policy(
            &owner,
            "name: queries\nresources:\n  - name: file\n    relations:\n      - name: reader\n",
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap();
    for index in 0..rows {
        let mut metadata = SuppliedMetadata::default();
        metadata
            .attributes
            .insert("padding".into(), "x".repeat(metadata_bytes));
        metadata.validate().unwrap();
        module
            .set_relationship(&RelationshipRecord {
                policy_id: policy.policy.id.clone(),
                generations: RelationPair {
                    target: 0,
                    subject: 0,
                },
                relationship: Relationship::with_entity(
                    "file",
                    format!("{index:04}"),
                    "owner",
                    owner.clone(),
                ),
                archived: false,
                supplied_metadata: metadata,
                metadata: policy.metadata.clone(),
            })
            .unwrap();
    }
    (module, policy.policy.id)
}

fn selector() -> RelationshipSelector {
    RelationshipSelector {
        object_selector: None,
        relation_selector: None,
        subject_selector: None,
    }
}

fn request(selector: RelationshipSelector) -> pages::RelationshipPageRequest {
    pages::RelationshipPageRequest {
        selector,
        after: None,
    }
}

#[test]
fn every_collection_query_accepts_exact_work_and_rejects_one_less_without_mutation() {
    let (module, policy) = fixture(2, 4096);
    let before = module.store.serialize();
    for route in 0..7 {
        let run = |budget: &QueryBudget| -> Result<serde_json::Value> {
            let value = match route {
                0 => serde_json::to_value(module.query_policy_with_budget(&policy, budget)?),
                1 => serde_json::to_value(module.query_policy_ids_with_budget(budget)?),
                2 => serde_json::to_value(module.query_policies_with_budget(budget)?),
                3 => serde_json::to_value(module.query_policies_page_with_budget(None, budget)?),
                4 => serde_json::to_value(module.query_filter_relationships_with_budget(
                    &policy,
                    &selector(),
                    budget,
                )?),
                5 => serde_json::to_value(module.query_relationships_page_with_budget(
                    &policy,
                    &request(selector()),
                    budget,
                )?),
                6 => serde_json::to_value(
                    module.query_policy_catalogue_with_budget(&policy, budget)?,
                ),
                _ => unreachable!(),
            };
            Ok(value.unwrap())
        };
        let measured = QueryBudget::new(u64::MAX);
        let expected = run(&measured).unwrap();
        assert!(measured.consumed() > 0);
        let exact = QueryBudget::new(measured.consumed());
        assert_eq!(run(&exact).unwrap(), expected, "route {route}");
        assert!(!exact.is_exhausted());
        let short = QueryBudget::new(measured.consumed() - 1);
        assert!(
            matches!(run(&short), Err(AcpError::QueryBudgetExceeded)),
            "route {route}"
        );
        assert!(short.is_exhausted());
        assert_eq!(module.store.serialize(), before);
    }
}

#[test]
fn empty_filtered_results_charge_all_inspected_metadata_and_preserve_page_continuation() {
    let (module, policy) = fixture(16, 60 << 10);
    let mut excluded = selector();
    excluded.subject_selector = Some(SubjectSelector::Exact(acp::Subject::entity(
        Did::new("did:key:absent").unwrap(),
    )));
    let budget = QueryBudget::new(u64::MAX);
    assert!(
        module
            .query_filter_relationships_with_budget(&policy, &excluded, &budget)
            .unwrap()
            .is_empty()
    );
    assert!(budget.consumed() >= (16 * (60 << 10)) / 16);
    let short = QueryBudget::new(budget.consumed() - 1);
    assert!(matches!(
        module.query_filter_relationships_with_budget(&policy, &excluded, &short),
        Err(AcpError::QueryBudgetExceeded)
    ));

    let (module, policy) = fixture(130, 0);
    let visible_budget = QueryBudget::new(u64::MAX);
    let visible = module
        .query_relationships_page_with_budget(&policy, &request(selector()), &visible_budget)
        .unwrap();
    assert_eq!(visible.records.len(), 128);
    let excluded_budget = QueryBudget::new(u64::MAX);
    let mut request = request(excluded);
    let first = module
        .query_relationships_page_with_budget(&policy, &request, &excluded_budget)
        .unwrap();
    assert!(first.records.is_empty());
    assert_eq!(first.next, visible.next);
    assert!(first.next.is_some());
    assert_eq!(excluded_budget.consumed(), visible_budget.consumed());
    request.after = first.next;
    let next = module
        .query_relationships_page_with_budget(&policy, &request, &QueryBudget::new(u64::MAX))
        .unwrap();
    assert!(next.records.is_empty());
    assert!(next.next.is_none());
}

#[test]
fn long_empty_page_cursors_are_charged_before_the_seek() {
    let (module, policy) = fixture(1, 0);
    let mut cursor = keys::POLICY_PREFIX.to_vec();
    cursor.resize(64 << 10, b'z');
    let measured = QueryBudget::new(u64::MAX);
    assert!(
        module
            .query_policies_page_with_budget(Some(&cursor), &measured)
            .unwrap()
            .records
            .is_empty()
    );
    assert!(measured.consumed() > 4096);
    let short = QueryBudget::new(measured.consumed() - 1);
    assert!(matches!(
        module.query_policies_page_with_budget(Some(&cursor), &short),
        Err(AcpError::QueryBudgetExceeded)
    ));
    let mut request = request(selector());
    let mut cursor = keys::relationship_generation_prefix(
        &policy,
        RelationPair {
            target: 0,
            subject: 0,
        },
        "",
    );
    cursor.resize(64 << 10, b'z');
    request.after = Some(cursor);
    let measured = QueryBudget::new(u64::MAX);
    assert!(
        module
            .query_relationships_page_with_budget(&policy, &request, &measured)
            .unwrap()
            .records
            .is_empty()
    );
    assert!(measured.consumed() > 4096);
    let short = QueryBudget::new(measured.consumed() - 1);
    assert!(matches!(
        module.query_relationships_page_with_budget(&policy, &request, &short),
        Err(AcpError::QueryBudgetExceeded)
    ));
}

#[test]
fn empty_directories_and_prefixes_are_charged_before_suffix_materialization() {
    let (module, policy) = fixture(1, 0);
    let selected = |id: &str, relation: &str| RelationshipSelector {
        object_selector: Some(ObjectSelector::Exact(Object {
            resource: "file".into(),
            id: id.into(),
        })),
        relation_selector: Some(RelationSelector::Exact(relation.into())),
        subject_selector: None,
    };
    let long = "x".repeat(16 << 10);
    for relation in ["owner", "reader"] {
        let short_budget = QueryBudget::new(u64::MAX);
        assert!(
            module
                .query_filter_relationships_with_budget(
                    &policy,
                    &selected("missing", relation),
                    &short_budget
                )
                .unwrap()
                .is_empty()
        );
        let long_budget = QueryBudget::new(u64::MAX);
        let selection = selected(&long, relation);
        assert!(
            module
                .query_filter_relationships_with_budget(&policy, &selection, &long_budget)
                .unwrap()
                .is_empty()
        );
        if relation == "owner" {
            assert!(long_budget.consumed() > short_budget.consumed() + 1900);
        } else {
            assert_eq!(long_budget.consumed(), short_budget.consumed());
        }
        let short = QueryBudget::new(long_budget.consumed() - 1);
        assert!(matches!(
            module.query_filter_relationships_with_budget(&policy, &selection, &short),
            Err(AcpError::QueryBudgetExceeded)
        ));
    }
    let module = AcpModule::new();
    let budget = QueryBudget::new(0);
    assert!(matches!(
        module.query_policy_ids_with_budget(&budget),
        Err(AcpError::QueryBudgetExceeded)
    ));
    assert!(budget.is_exhausted());
}

#[test]
fn policy_directory_and_row_corruption_remain_errors_after_read_charges() {
    let (original, policy) = fixture(1, 0);
    let row = original
        .store
        .prefix_iter(&keys::relationship_policy_prefix(&policy))
        .next()
        .unwrap()
        .0
        .to_vec();
    for key in [
        keys::policy_key(&policy),
        relationship_index::active_key(&policy, 0),
        row,
    ] {
        let mut module = original.clone();
        module.store.put(&key, vec![b'!'; 32 << 10]);
        let before = module.store.serialize();
        let unlimited = QueryBudget::new(u64::MAX);
        assert!(matches!(
            module.query_filter_relationships_with_budget(&policy, &selector(), &unlimited),
            Err(AcpError::State(_))
        ));
        assert!(unlimited.consumed() > 0);
        assert!(!unlimited.is_exhausted());
        let short = QueryBudget::new(unlimited.consumed() - 1);
        assert!(matches!(
            module.query_filter_relationships_with_budget(&policy, &selector(), &short),
            Err(AcpError::QueryBudgetExceeded)
        ));
        assert!(short.is_exhausted());
        assert_eq!(module.store.serialize(), before);
    }
}
