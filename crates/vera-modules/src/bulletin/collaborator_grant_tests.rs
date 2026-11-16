//! Collaborator grants the namespace owner changes directly through ACP.

use super::*;
use crate::acp::AcpModule;

fn did(name: &str) -> Did {
    Did::new(format!("did:key:{name}")).unwrap()
}

fn tx() -> TxExecCtx {
    TxExecCtx {
        sequence: 0,
        tx_hash: vec![],
        signer: did("owner").to_string(),
    }
}

fn grant(namespace_id: &str, writer: &Did) -> Relationship {
    crate::acp::relationship_values::actor_relationship(
        "namespace",
        namespace_id,
        "collaborator",
        writer,
    )
    .unwrap()
}

fn registered() -> (BulletinModule, AcpModule, Namespace, String) {
    let mut module = BulletinModule::new();
    let mut acp = AcpModule::new();
    let namespace = module
        .register_namespace(
            &mut acp,
            &BlockExecCtx::default(),
            &tx(),
            &did("owner"),
            "ns",
        )
        .unwrap();
    let policy = module.get_policy_id().unwrap().unwrap();
    (module, acp, namespace, policy)
}

#[test]
fn a_grant_set_through_acp_can_be_removed_through_bulletin() {
    let (mut module, mut acp, namespace, policy) = registered();
    let (owner, writer) = (did("owner"), did("writer"));
    acp.direct_policy_cmd(
        &owner,
        &policy,
        PolicyCmd::SetRelationship(grant(&namespace.id, &writer)),
    )
    .unwrap();
    module
        .create_post(&acp, &tx(), &writer, "ns", b"first", &[], "")
        .unwrap();
    assert!(
        module
            .query_namespace_collaborators("ns")
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        module.remove_collaborator(&mut acp, &tx(), &writer, "ns", writer.as_str()),
        Err(BulletinError::Unauthorized { .. })
    ));
    module
        .remove_collaborator(&mut acp, &tx(), &owner, "ns", writer.as_str())
        .unwrap();
    assert!(matches!(
        module.create_post(&acp, &tx(), &writer, "ns", b"second", &[], ""),
        Err(BulletinError::NotCollaborator { .. })
    ));
    let before = (module.store().serialize(), acp.store().serialize());
    assert!(matches!(
        module.remove_collaborator(&mut acp, &tx(), &owner, "ns", writer.as_str()),
        Err(BulletinError::CollaboratorNotFound { .. })
    ));
    assert_eq!(
        (module.store().serialize(), acp.store().serialize()),
        before
    );
}

#[test]
fn a_grant_deleted_through_acp_can_be_restored_through_bulletin() {
    let (mut module, mut acp, namespace, policy) = registered();
    let (owner, writer) = (did("owner"), did("writer"));
    module
        .add_collaborator(&mut acp, &tx(), &owner, "ns", writer.as_str())
        .unwrap();
    acp.direct_policy_cmd(
        &owner,
        &policy,
        PolicyCmd::DeleteRelationship(grant(&namespace.id, &writer)),
    )
    .unwrap();
    assert!(matches!(
        module.create_post(&acp, &tx(), &writer, "ns", b"first", &[], ""),
        Err(BulletinError::NotCollaborator { .. })
    ));
    assert_eq!(module.query_namespace_collaborators("ns").unwrap().len(), 1);
    module
        .add_collaborator(&mut acp, &tx(), &owner, "ns", writer.as_str())
        .unwrap();
    module
        .create_post(&acp, &tx(), &writer, "ns", b"first", &[], "")
        .unwrap();
    assert_eq!(module.query_namespace_collaborators("ns").unwrap().len(), 1);
    let before = (module.store().serialize(), acp.store().serialize());
    assert!(matches!(
        module.add_collaborator(&mut acp, &tx(), &owner, "ns", writer.as_str()),
        Err(BulletinError::CollaboratorAlreadyExists { .. })
    ));
    assert_eq!(
        (module.store().serialize(), acp.store().serialize()),
        before
    );
}

#[test]
fn a_grant_set_through_acp_is_listed_once_added_through_bulletin() {
    let (mut module, mut acp, namespace, policy) = registered();
    let (owner, writer) = (did("owner"), did("writer"));
    acp.direct_policy_cmd(
        &owner,
        &policy,
        PolicyCmd::SetRelationship(grant(&namespace.id, &writer)),
    )
    .unwrap();
    module
        .add_collaborator(&mut acp, &tx(), &owner, "ns", writer.as_str())
        .unwrap();
    let listed = module.query_namespace_collaborators("ns").unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].did, writer.as_str());
}
