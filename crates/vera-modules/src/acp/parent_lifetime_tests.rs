use super::*;

#[test]
fn registered_parent_cannot_be_removed_or_replaced() {
    let mut module = AcpModule::new();
    let owner = Did::new("did:key:first").unwrap();
    let policy = module.create_policy(
        &owner,
        "name: agents\nresources:\n- name: agent\n- name: session\n  relations: [{name: agent, types: [agent]}]\n  create: {parent: agent, requires: owner}\n",
        PolicyMarshalingType::ShortYaml, Default::default(),
    ).unwrap().policy.id;
    let parent = Object {
        resource: "agent".into(),
        id: "a".into(),
    };
    let other = Object {
        resource: "agent".into(),
        id: "b".into(),
    };
    let child = Object {
        resource: "session".into(),
        id: "s".into(),
    };
    for object in [&parent, &other] {
        module
            .direct_policy_cmd(&owner, &policy, PolicyCmd::RegisterObject(object.clone()))
            .unwrap();
    }
    module
        .direct_policy_cmd(
            &owner,
            &policy,
            PolicyCmd::RegisterUnderParent {
                object: child,
                parent,
            },
        )
        .unwrap();
    let link = Relationship::new(
        "session",
        "s",
        "agent",
        vera_acp::Subject::entity_set("agent", "a", ""),
    );
    let other_link = Relationship::new(
        "session",
        "s",
        "agent",
        vera_acp::Subject::entity_set("agent", "b", ""),
    );
    let before = module.store.serialize();
    assert!(matches!(
        module.direct_policy_cmd(&owner, &policy, PolicyCmd::DeleteRelationship(link.clone())),
        Err(AcpError::InvalidAccessRequest { .. })
    ));
    assert!(matches!(
        module.direct_policy_cmd(&owner, &policy, PolicyCmd::SetRelationship(other_link)),
        Err(AcpError::InvalidAccessRequest { .. })
    ));
    assert_eq!(before, module.store.serialize());
    assert!(
        module
            .relationship_in(&module.query_policy(&policy).unwrap(), &link, None)
            .unwrap()
            .is_some()
    );
    let without_rule = "name: agents\nresources:\n- name: agent\n- name: session\n  relations: [{name: agent, types: [agent]}]\n";
    assert!(matches!(
        module.edit_policy(
            &owner,
            &policy,
            without_rule,
            PolicyMarshalingType::ShortYaml
        ),
        Err(AcpError::InvalidPolicy { .. })
    ));
}
