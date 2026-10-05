use super::*;

fn fixture() -> (AcpModule, Did, String, Object) {
    let mut module = AcpModule::new();
    let owner = Did::new("did:key:owner").unwrap();
    let policy = module.create_policy(&owner, "name: incarnations\nresources:\n  - name: file\n    relations:\n      - name: reader\n", PolicyMarshalingType::ShortYaml).unwrap().policy.id;
    let object = Object {
        resource: "file".into(),
        id: "report".into(),
    };
    module
        .direct_policy_cmd(&owner, &policy, PolicyCmd::RegisterObject(object.clone()))
        .unwrap();
    (module, owner, policy, object)
}

fn selector(object: Option<Object>) -> RelationshipSelector {
    RelationshipSelector {
        object_selector: object.map(ObjectSelector::Exact),
        relation_selector: None,
        subject_selector: None,
    }
}

fn grant(module: &mut AcpModule, owner: &Did, policy: &str, index: usize) {
    module
        .direct_policy_cmd(
            owner,
            policy,
            PolicyCmd::SetRelationship(Relationship::with_entity(
                "file",
                "report",
                "reader",
                Did::new(format!("did:key:reader{index}")).unwrap(),
            )),
        )
        .unwrap();
}

#[test]
fn exact_queries_skip_retired_incarnations_while_broad_pages_keep_physical_progress() {
    let (mut module, owner, policy, object) = fixture();
    for index in 0..130 {
        grant(&mut module, &owner, &policy, index);
    }
    module
        .direct_policy_cmd(&owner, &policy, PolicyCmd::ArchiveObject(object.clone()))
        .unwrap();
    module
        .direct_policy_cmd(&owner, &policy, PolicyCmd::UnarchiveObject(object.clone()))
        .unwrap();
    grant(&mut module, &owner, &policy, 0);
    let exact = module
        .query_filter_relationships(&policy, &selector(Some(object)))
        .unwrap();
    assert_eq!(exact.len(), 2);
    assert!(
        exact
            .iter()
            .all(|record| record.incarnation == u64::from(record.relationship.relation != "owner"))
    );
    let broad = selector(None);
    assert!(module.query_filter_relationships(&policy, &broad).is_err());
    let mut request = pages::RelationshipPageRequest {
        selector: broad,
        after: None,
    };
    let first = module.query_relationships_page(&policy, &request).unwrap();
    assert_eq!(first.records.len(), 1);
    assert_eq!(first.records[0].relationship.relation, "owner");
    assert!(first.next.is_some());
    request.after = first.next;
    let last = module.query_relationships_page(&policy, &request).unwrap();
    assert!(last.next.is_none());
    assert_eq!(last.records.len(), 1);
    assert_eq!(last.records[0].incarnation, 1);
}

#[test]
fn incarnation_reads_are_reserved_before_decode_and_future_stamps_fail_closed() {
    let (mut module, owner, policy, object) = fixture();
    grant(&mut module, &owner, &policy, 0);
    let exact = selector(Some(object.clone()));
    let measured = QueryBudget::new(u64::MAX);
    module
        .query_filter_relationships_with_budget(&policy, &exact, &measured)
        .unwrap();
    let exact_budget = QueryBudget::new(measured.consumed());
    assert_eq!(
        module
            .query_filter_relationships_with_budget(&policy, &exact, &exact_budget)
            .unwrap()
            .len(),
        2
    );
    assert!(matches!(
        module.query_filter_relationships_with_budget(
            &policy,
            &exact,
            &QueryBudget::new(measured.consumed() - 1)
        ),
        Err(AcpError::QueryBudgetExceeded)
    ));
    let state_key = object_state::key(&policy, &object.resource, &object.id);
    module.store.put(&state_key, vec![0]);
    let no_allowance = QueryBudget::new(0);
    assert!(matches!(
        module.query_object_incarnation(&policy, &object.resource, &object.id, &no_allowance),
        Err(AcpError::QueryBudgetExceeded)
    ));
    let metered = QueryBudget::new(u64::MAX);
    assert!(
        module
            .query_object_incarnation(&policy, &object.resource, &object.id, &metered)
            .is_err()
    );
    assert_eq!(
        metered.consumed(),
        100 + (state_key.len() as u64 + 1).div_ceil(16)
    );
    module.store.delete(&state_key);
    let mut record = module
        .query_filter_relationships(&policy, &exact)
        .unwrap()
        .into_iter()
        .find(|record| record.relationship.relation == "reader")
        .unwrap();
    let old_key = keys::relationship_generation_key(
        &policy,
        record.generations,
        &keys::relationship_storage_key(&record.relationship, record.incarnation),
    );
    module.store.delete(&old_key);
    record.incarnation = 1;
    let future_key = keys::relationship_generation_key(
        &policy,
        record.generations,
        &keys::relationship_storage_key(&record.relationship, record.incarnation),
    );
    module
        .store
        .put(&future_key, serde_json::to_vec(&record).unwrap());
    assert!(
        module
            .query_filter_relationships(&policy, &selector(None))
            .is_err()
    );
    assert!(
        module
            .query_relationships_page(
                &policy,
                &pages::RelationshipPageRequest {
                    selector: selector(None),
                    after: None
                }
            )
            .is_err()
    );
}
