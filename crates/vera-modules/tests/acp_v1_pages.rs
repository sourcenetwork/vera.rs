//! Bounded policy and relationship pagination.
use identity::Did;
use vera_modules::{
    acp::{
        AcpModule,
        pages::RelationshipPageRequest,
        types::{Object, PolicyCmd, PolicyMarshalingType, RelationshipSelector, SubjectSelector},
    },
    kv_store::InMemoryKvStore,
};

const POLICY: &str = "name: files\nresources:\n  - name: file\n";

#[test]
fn enumeration_resumes_without_duplicates_and_bounds_empty_filtered_pages() {
    let owner = Did::new("did:key:owner").unwrap();
    let mut module = AcpModule::new();
    for _ in 0..130 {
        module
            .create_policy(&owner, POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();
    }
    let first = module.query_policies_page(None).unwrap();
    assert_eq!(first.records.len(), 128);
    let second = module.query_policies_page(first.next.as_deref()).unwrap();
    assert_eq!(second.records.len(), 2);
    assert!(second.next.is_none());
    assert!(
        first
            .records
            .iter()
            .all(|a| second.records.iter().all(|b| a.policy.id != b.policy.id))
    );
    assert!(module.query_policies().is_err());
    let policy = &first.records[0].policy.id;
    for i in 0..260 {
        module
            .direct_policy_cmd(
                &owner,
                policy,
                PolicyCmd::RegisterObject(Object {
                    resource: "file".into(),
                    id: format!("{i:04}"),
                }),
            )
            .unwrap();
    }
    let mut request = RelationshipPageRequest {
        selector: RelationshipSelector {
            object_selector: None,
            relation_selector: None,
            subject_selector: None,
        },
        after: None,
    };
    let mut ids = std::collections::BTreeSet::new();
    loop {
        let page = module.query_relationships_page(policy, &request).unwrap();
        for record in page.records {
            assert!(ids.insert(record.relationship.object_id));
        }
        request.after = page.next;
        if request.after.is_none() {
            break;
        }
    }
    assert_eq!(ids.len(), 260);
    request.selector.subject_selector = Some(SubjectSelector::Exact(acp::Subject::Entity(
        Did::new("did:key:nobody").unwrap(),
    )));
    let page = module.query_relationships_page(policy, &request).unwrap();
    assert!(page.records.is_empty());
    assert!(page.next.is_some());
    request.after = page.next;
    let restored =
        AcpModule::from_store(InMemoryKvStore::deserialize(&module.store().serialize()).unwrap());
    assert!(
        restored
            .query_relationships_page(policy, &request)
            .unwrap()
            .next
            .is_some()
    );
    request.after = Some(b"relationship/another-policy/".to_vec());
    assert!(module.query_relationships_page(policy, &request).is_err());
    assert!(
        module
            .query_policies_page(Some(b"relationship/".as_slice()))
            .is_err()
    );
    request.after = None;
    request.selector.subject_selector = None;
    request.selector.object_selector =
        Some(vera_modules::acp::types::ObjectSelector::Exact(Object {
            resource: "file".into(),
            id: "0100".into(),
        }));
    let page = module.query_relationships_page(policy, &request).unwrap();
    assert_eq!(page.records.len(), 1);
    assert!(page.next.is_none());
    assert_eq!(
        module
            .query_filter_relationships(policy, &request.selector)
            .unwrap()
            .len(),
        1
    );
    assert!(
        module
            .query_filter_relationships("missing", &request.selector)
            .is_err()
    );
}
