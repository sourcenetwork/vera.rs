use alloy_primitives::{B256, Bytes};
use alloy_sol_types::SolCall;
use vera_client::{BlsSigner, Object};
use vera_modules::acp::abi::IAcp;

pub(super) const DEPLOYMENT: u64 = 9182;
pub(super) const POLICY: &str = "name: mixed-policy
resources:
  - name: group
    relations:
      - name: member
        types: [actor, group->member]
    permissions:
      - name: read
        expr: member
  - name: folder
    relations:
      - name: reader
        types: [group->member]
    permissions:
      - name: read
        expr: reader
  - name: document
    relations:
      - name: parent
        types: [folder]
      - name: blocked
        types: [actor]
    permissions:
      - name: read
        expr: parent->read - blocked
";

pub(super) fn without_member() -> String {
    POLICY
        .replace(
            "    relations:\n      - name: member\n        types: [actor, group->member]\n",
            "",
        )
        .replace("expr: member", "expr: owner")
        .replace("types: [group->member]", "types: [actor]")
}

pub(super) struct Graph {
    pub(super) index: usize,
    pub(super) owner: BlsSigner,
    pub(super) objects: [Object; 4],
}

impl Graph {
    pub(super) fn new(index: usize) -> Self {
        Self {
            index,
            owner: BlsSigner::new(((index + 1) as u64).into(), DEPLOYMENT).unwrap(),
            objects: [
                ("group", "members"),
                ("group", "team"),
                ("folder", "folder"),
                ("document", "document"),
            ]
            .map(|(resource, suffix)| Object {
                resource: resource.into(),
                id: format!("workflow-{index}-{suffix}"),
            }),
        }
    }

    pub(super) fn registrations(&self, policy: B256, readers: &[String; 3]) -> Vec<Bytes> {
        let mut calls: Vec<_> = self
            .objects
            .iter()
            .map(|object| {
                IAcp::registerObjectCall {
                    policyId: policy,
                    resource: object.resource.clone(),
                    objectId: object.id.clone(),
                }
                .abi_encode()
                .into()
            })
            .collect();
        calls.extend(self.grants(policy, readers));
        calls.push(subject(
            policy,
            &self.objects[3],
            "parent",
            &self.objects[2],
            "",
        ));
        calls
    }

    pub(super) fn grants(&self, policy: B256, readers: &[String; 3]) -> Vec<Bytes> {
        vec![
            self.member(policy, &readers[0], false),
            self.member(policy, &readers[1], false),
            subject(
                policy,
                &self.objects[1],
                "member",
                &self.objects[0],
                "member",
            ),
            subject(
                policy,
                &self.objects[2],
                "reader",
                &self.objects[1],
                "member",
            ),
        ]
    }

    pub(super) fn member(&self, policy: B256, reader: &str, remove: bool) -> Bytes {
        actor(policy, &self.objects[0], "member", reader, remove)
    }

    pub(super) fn blocked(&self, policy: B256, reader: &str, remove: bool) -> Bytes {
        actor(policy, &self.objects[3], "blocked", reader, remove)
    }
}

fn actor(policy: B256, object: &Object, relation: &str, actor: &str, remove: bool) -> Bytes {
    if remove {
        IAcp::deleteRelationshipCall {
            policyId: policy,
            resource: object.resource.clone(),
            objectId: object.id.clone(),
            relation: relation.into(),
            actor: actor.into(),
        }
        .abi_encode()
        .into()
    } else {
        IAcp::setRelationshipCall {
            policyId: policy,
            resource: object.resource.clone(),
            objectId: object.id.clone(),
            relation: relation.into(),
            actor: actor.into(),
        }
        .abi_encode()
        .into()
    }
}

fn subject(
    policy: B256,
    object: &Object,
    relation: &str,
    target: &Object,
    target_relation: &str,
) -> Bytes {
    IAcp::setRelationshipSubjectCall {
        policyId: policy,
        resource: object.resource.clone(),
        objectId: object.id.clone(),
        relation: relation.into(),
        subjectKind: if target_relation.is_empty() { 2 } else { 3 },
        subjectResource: target.resource.clone(),
        subjectObjectId: target.id.clone(),
        subjectRelation: target_relation.into(),
    }
    .abi_encode()
    .into()
}
