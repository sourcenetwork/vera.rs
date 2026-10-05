use super::*;
use std::collections::BTreeSet;

const RESOURCES: usize = 64;

fn definition(remove_even_readers: bool, reverse: bool) -> String {
    let mut result = String::from("name: many_resources\nresources:\n");
    for index in 0..RESOURCES {
        let index = if reverse {
            RESOURCES - 1 - index
        } else {
            index
        };
        let reader = !remove_even_readers || index % 2 != 0;
        result.push_str(&format!(
            "  - name: resource_{index:03}\n    relations:\n{}      - name: writer\n    permissions:\n      - name: read\n        expr: {}\n",
            if reader { "      - name: reader\n" } else { "" },
            if reader { "reader" } else { "owner" },
        ));
    }
    result
}

fn reader_resources(module: &AcpModule, policy: &str) -> BTreeSet<String> {
    module
        .query_filter_relationships(
            policy,
            &RelationshipSelector {
                relation_selector: Some(RelationSelector::Exact("reader".into())),
                ..Default::default()
            },
        )
        .unwrap()
        .into_iter()
        .map(|record| record.relationship.resource)
        .collect()
}

fn restore(module: &AcpModule) -> AcpModule {
    let restored =
        AcpModule::from_store(InMemoryKvStore::deserialize(&module.store.serialize()).unwrap());
    restored.validate_restored_state().unwrap();
    restored
}

#[test]
fn reordered_schema_keeps_resource_identities_and_recreated_relations_revoked() {
    let mut module = AcpModule::new();
    let owner = Did::new("did:key:owner").unwrap();
    let reader = Did::new("did:key:reader").unwrap();
    let policy = module
        .create_policy(
            &owner,
            &definition(false, false),
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap()
        .policy
        .id;
    for index in 0..RESOURCES {
        let resource = format!("resource_{index:03}");
        module
            .direct_policy_cmd(
                &owner,
                &policy,
                PolicyCmd::RegisterObject(Object {
                    resource: resource.clone(),
                    id: "report".into(),
                }),
            )
            .unwrap();
        module
            .direct_policy_cmd(
                &owner,
                &policy,
                PolicyCmd::SetRelationship(Relationship::with_entity(
                    resource,
                    "report",
                    "reader",
                    reader.clone(),
                )),
            )
            .unwrap();
    }
    let original = module.query_policy(&policy).unwrap();
    let physical = module
        .store
        .prefix_scan(&keys::relationship_policy_prefix(&policy));
    assert_eq!(physical.len(), 2 * RESOURCES);
    assert_eq!(reader_resources(&module, &policy).len(), RESOURCES);

    let removed = module
        .edit_policy(
            &owner,
            &policy,
            &definition(true, true),
            PolicyMarshalingType::ShortYaml,
        )
        .unwrap()
        .0;
    assert_eq!(removed, (RESOURCES / 2) as u64);
    assert_eq!(
        module
            .store
            .prefix_scan(&keys::relationship_policy_prefix(&policy)),
        physical
    );
    module = restore(&module);
    let edited = module.query_policy(&policy).unwrap();
    let expected: BTreeSet<_> = (0..RESOURCES)
        .filter(|index| index % 2 != 0)
        .map(|index| format!("resource_{index:03}"))
        .collect();
    assert_eq!(reader_resources(&module, &policy), expected);
    assert_eq!(
        module
            .query_filter_relationships(&policy, &Default::default())
            .unwrap()
            .len(),
        3 * RESOURCES / 2
    );
    for index in 0..RESOURCES {
        let resource = format!("resource_{index:03}");
        assert_eq!(edited.relations.generation(&resource, "owner"), Some(0));
        assert_eq!(
            edited.relations.generation(&resource, "writer"),
            original.relations.generation(&resource, "writer")
        );
        let generation = original.relations.generation(&resource, "reader").unwrap();
        let retired =
            relation_edits::load_retired_relation(&module.store, &policy, generation).unwrap();
        if index % 2 == 0 {
            assert_eq!(edited.relations.generation(&resource, "reader"), None);
            let retired = retired.unwrap();
            assert_eq!(retired.resource, resource);
            assert_eq!(retired.relation, "reader");
        } else {
            assert_eq!(
                edited.relations.generation(&resource, "reader"),
                Some(generation)
            );
            assert!(retired.is_none());
        }
        assert_eq!(
            module
                .query_object_owner(
                    &policy,
                    &Object {
                        resource,
                        id: "report".into()
                    }
                )
                .unwrap()
                .1
                .unwrap()
                .metadata
                .owner_did,
            owner.to_string()
        );
    }

    assert_eq!(
        module
            .edit_policy(
                &owner,
                &policy,
                &definition(false, false),
                PolicyMarshalingType::ShortYaml
            )
            .unwrap()
            .0,
        0
    );
    module = restore(&module);
    assert_eq!(reader_resources(&module, &policy), expected);
    let recreated = module.query_policy(&policy).unwrap();
    for index in 0..RESOURCES {
        let resource = format!("resource_{index:03}");
        let generation = recreated.relations.generation(&resource, "reader").unwrap();
        if index % 2 == 0 {
            assert!(generation >= original.relations.next);
        } else {
            assert_eq!(
                Some(generation),
                original.relations.generation(&resource, "reader")
            );
        }
    }
    module
        .direct_policy_cmd(
            &owner,
            &policy,
            PolicyCmd::SetRelationship(Relationship::with_entity(
                "resource_000",
                "report",
                "reader",
                reader,
            )),
        )
        .unwrap();
    module = restore(&module);
    let mut expected = expected;
    expected.insert("resource_000".into());
    assert_eq!(reader_resources(&module, &policy), expected);
    assert_eq!(
        module
            .query_filter_relationships(&policy, &Default::default())
            .unwrap()
            .len(),
        3 * RESOURCES / 2 + 1
    );
}
