//! Main's (#367, #368) registration-under-a-parent tests, on acp-rs's
//! collection `create`: `create: {parent: P, requires: R}` is written
//! `collection: {create: P->R}`.

use super::*;
use crate::acp::relationship_values::{actor_relationship, relationship};

const AGENTS: &str = "name: agents
resources:
  - name: agent
  - name: session
    relations:
      - name: agent
        types: [agent]
    collection:
      create: agent->owner
";

const DEVICES: &str = "name: devices
resources:
  - name: node
    relations:
      - name: publisher
  - name: record
    relations:
      - name: parent
        types: [node]
    collection:
      create: parent->publisher
";

fn did(name: &str) -> Did {
    Did::new(format!("did:key:{name}")).unwrap()
}

fn object(resource: &str, id: &str) -> Object {
    Object {
        resource: resource.into(),
        id: id.into(),
    }
}

fn create(module: &mut AcpModule, owner: &Did, policy: &str) -> String {
    module
        .create_policy(
            owner,
            policy,
            PolicyMarshalingType::ShortYaml,
            Default::default(),
        )
        .unwrap()
        .policy
        .id
        .to_string()
}

fn under(child: Object, parent: Object) -> PolicyCmd {
    PolicyCmd::RegisterUnderParent {
        object: child,
        parent,
    }
}

#[test]
fn parent_relation_requires_an_explicit_grant() {
    let mut module = AcpModule::new();
    let owner = did("first");
    let publisher = did("second");
    let policy = create(&mut module, &owner, DEVICES);
    let parent = object("node", "a");
    module
        .direct_policy_cmd(&owner, &policy, PolicyCmd::RegisterObject(parent.clone()))
        .unwrap();
    let cmd = under(object("record", "s"), parent);
    // `publisher` is a relation, not `owner + ..`, so the node's owner
    // holds it only through an explicit grant, as in main.
    let before = module.store.serialize();
    assert!(matches!(
        module.direct_policy_cmd(&owner, &policy, cmd.clone()),
        Err(AcpError::CreateNotAuthorized { .. })
    ));
    assert!(matches!(
        module.direct_policy_cmd(&publisher, &policy, cmd.clone()),
        Err(AcpError::CreateNotAuthorized { .. })
    ));
    assert_eq!(before, module.store.serialize());
    module
        .direct_policy_cmd(
            &owner,
            &policy,
            PolicyCmd::SetRelationship(
                actor_relationship("node", "a", "publisher", &publisher).unwrap(),
            ),
        )
        .unwrap();
    module.direct_policy_cmd(&publisher, &policy, cmd).unwrap();
}

#[test]
fn only_an_authorized_parent_registration_creates_the_child() {
    let mut module = AcpModule::new();
    let owner = did("first");
    let other = did("second");
    let policy = create(&mut module, &owner, AGENTS);
    let parent = object("agent", "a");
    let child = object("session", "s");
    module
        .direct_policy_cmd(&owner, &policy, PolicyCmd::RegisterObject(parent.clone()))
        .unwrap();
    let cmd = under(child.clone(), parent);
    let before = module.store.serialize();
    assert!(matches!(
        module.direct_policy_cmd(&owner, &policy, PolicyCmd::RegisterObject(child)),
        Err(AcpError::CreateNotAuthorized { .. })
    ));
    assert!(matches!(
        module.direct_policy_cmd(&other, &policy, cmd.clone()),
        Err(AcpError::CreateNotAuthorized { .. })
    ));
    assert_eq!(before, module.store.serialize());
    let PolicyCmdResult::RegisterObject { record } =
        module.direct_policy_cmd(&owner, &policy, cmd).unwrap()
    else {
        panic!("not a registration result");
    };
    assert_eq!(record.metadata.owner_did, owner.to_string());
    let link = relationship(
        "session",
        "s",
        "agent",
        Subject::Object(::acp::domain::Object::new("agent", "a")),
    );
    assert!(
        module
            .relationship_in(&module.query_policy(&policy).unwrap(), &link, None)
            .unwrap()
            .is_some()
    );

    // An unregistered or archived parent has no owner, so nobody passes.
    let second = object("agent", "b");
    let next = || under(object("session", "next"), second.clone());
    assert!(matches!(
        module.direct_policy_cmd(&other, &policy, next()),
        Err(AcpError::CreateNotAuthorized { .. })
    ));
    module
        .direct_policy_cmd(&other, &policy, PolicyCmd::RegisterObject(second.clone()))
        .unwrap();
    module
        .direct_policy_cmd(&other, &policy, PolicyCmd::ArchiveObject(second.clone()))
        .unwrap();
    let before = module.store.serialize();
    assert!(matches!(
        module.direct_policy_cmd(&other, &policy, next()),
        Err(AcpError::CreateNotAuthorized { .. })
    ));
    assert_eq!(before, module.store.serialize());
}

#[test]
fn a_resource_without_one_followed_relation_takes_explicit_relationships() {
    let mut module = AcpModule::new();
    let owner = did("first");
    let policy = create(
        &mut module,
        &owner,
        "name: shapes
resources:
  - name: agent
  - name: team
  - name: open
  - name: session
    relations:
      - name: agent
        types: [agent]
      - name: team
        types: [team]
    collection:
      create: agent->owner & team->owner
",
    );
    for parent in ["agent", "team"] {
        module
            .direct_policy_cmd(
                &owner,
                &policy,
                PolicyCmd::RegisterObject(object(parent, "a")),
            )
            .unwrap();
    }
    let before = module.store.serialize();
    for cmd in [
        under(object("session", "s"), object("agent", "a")),
        under(object("open", "o"), object("agent", "a")),
    ] {
        assert!(matches!(
            module.direct_policy_cmd(&owner, &policy, cmd),
            Err(AcpError::InvalidAccessRequest { .. })
        ));
    }
    assert_eq!(before, module.store.serialize());
    let link = |relation: &str, resource: &str| {
        relationship(
            "session",
            "s",
            relation,
            Subject::Object(::acp::domain::Object::new(resource, "a")),
        )
    };
    module
        .direct_policy_cmd(
            &owner,
            &policy,
            PolicyCmd::RegisterObjectWithRelationships {
                object: object("session", "s"),
                relationships: vec![link("agent", "agent"), link("team", "team")],
            },
        )
        .unwrap();
}
