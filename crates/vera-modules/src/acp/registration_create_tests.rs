//! Registration under a collection `create` (acp-rs ADR 0028).

use super::*;
use crate::acp::relationship_values::{actor_relationship, relationship};
use crate::acp::types::{Operation, Subject};

const POLICY: &str = "name: library
resources:
  - name: author
    relations:
      - name: publisher
    permissions:
      - name: publish
        expr: publisher
  - name: artist
    relations:
      - name: fan
  - name: book
    relations:
      - name: author
        types: [author]
      - name: reader
    permissions:
      - name: read
        expr: reader + author->publish
    collection:
      create: author->publish
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

fn authored_by(book: &str, author: &str) -> Relationship {
    relationship(
        "book",
        book,
        "author",
        Subject::Object(::acp::domain::Object::new("author", author)),
    )
}

fn json(value: impl serde::Serialize) -> serde_json::Value {
    serde_json::to_value(value).unwrap()
}

fn register(object: Object, relationships: Vec<Relationship>) -> PolicyCmd {
    PolicyCmd::RegisterObjectWithRelationships {
        object,
        relationships,
    }
}

/// `author:mike`, owned by mike, with bob as its publisher.
fn library() -> (AcpModule, String) {
    let mut module = AcpModule::new();
    let policy = module
        .create_policy(
            &did("librarian"),
            POLICY,
            PolicyMarshalingType::ShortYaml,
            Default::default(),
        )
        .unwrap()
        .policy
        .id
        .to_string();
    module
        .direct_policy_cmd(
            &did("mike"),
            &policy,
            PolicyCmd::RegisterObject(object("author", "mike")),
        )
        .unwrap();
    module
        .direct_policy_cmd(
            &did("mike"),
            &policy,
            PolicyCmd::SetRelationship(
                actor_relationship("author", "mike", "publisher", &did("bob")).unwrap(),
            ),
        )
        .unwrap();
    (module, policy)
}

fn can_read(module: &AcpModule, policy: &str, actor: &str, book: &str) -> bool {
    module
        .query_verify_access_request(
            policy,
            &AccessRequest {
                operations: vec![Operation {
                    object: object("book", book),
                    permission: "read".into(),
                }],
                actor: Actor(did(actor)),
            },
        )
        .unwrap()
}

fn refused(module: &mut AcpModule, policy: &str, actor: &str, cmd: PolicyCmd) -> AcpError {
    let before = module.store.serialize();
    let error = module
        .direct_policy_cmd(&did(actor), policy, cmd)
        .unwrap_err();
    assert_eq!(module.store.serialize(), before, "a refusal stores nothing");
    error
}

#[test]
fn an_open_collection_registers_with_or_without_relationships() {
    let (mut module, policy) = library();
    let PolicyCmdResult::RegisterObject { record } = module
        .direct_policy_cmd(
            &did("eve"),
            &policy,
            PolicyCmd::RegisterObject(object("artist", "a1")),
        )
        .unwrap()
    else {
        panic!("not a registration result");
    };
    assert_eq!(record.metadata.owner_did, did("eve").to_string());
    let fan = actor_relationship("artist", "a2", "fan", &did("carol")).unwrap();
    let PolicyCmdResult::RegisterObjectWithRelationships {
        record,
        relationships,
    } = module
        .direct_policy_cmd(
            &did("eve"),
            &policy,
            register(object("artist", "a2"), vec![fan.clone()]),
        )
        .unwrap()
    else {
        panic!("not a registration result");
    };
    assert_eq!(record.relationship.relation.as_str(), "owner");
    assert_eq!(relationships.len(), 1);
    assert_eq!(relationships[0].relationship, fan);
    assert_eq!(
        json(module.get_relationship(&policy, &fan).unwrap()),
        json(Some(&relationships[0]))
    );
}

#[test]
fn a_publisher_registers_a_book_with_its_author_and_later_checks_follow_it() {
    let (mut module, policy) = library();
    let author = authored_by("b1", "mike");
    assert!(!can_read(&module, &policy, "mike", "b1"));
    let PolicyCmdResult::RegisterObjectWithRelationships {
        record,
        relationships,
    } = module
        .direct_policy_cmd(
            &did("bob"),
            &policy,
            register(object("book", "b1"), vec![author.clone()]),
        )
        .unwrap()
    else {
        panic!("not a registration result");
    };
    assert_eq!(record.metadata.owner_did, did("bob").to_string());
    assert_eq!(record.relationship.relation.as_str(), "owner");
    assert_eq!(relationships.len(), 1);
    assert_eq!(relationships[0].relationship, author);
    assert_eq!(relationships[0].metadata.owner_did, did("bob").to_string());
    assert_eq!(
        json(module.get_relationship(&policy, &author).unwrap()),
        json(Some(&relationships[0]))
    );
    assert_eq!(
        json(
            module
                .query_object_owner(&policy, &object("book", "b1"))
                .unwrap()
                .1
        ),
        json(Some(&record))
    );
    // mike owns author:mike and so publishes for it; he reads book:b1 only
    // through the stored author relationship.
    assert!(can_read(&module, &policy, "mike", "b1"));
    assert!(!can_read(&module, &policy, "carol", "b1"));
    module
        .direct_policy_cmd(
            &did("mike"),
            &policy,
            PolicyCmd::SetRelationship(
                actor_relationship("author", "mike", "publisher", &did("carol")).unwrap(),
            ),
        )
        .unwrap();
    assert!(can_read(&module, &policy, "carol", "b1"));
    // The author's owner may create books by mike as well.
    module
        .direct_policy_cmd(
            &did("mike"),
            &policy,
            register(object("book", "b2"), vec![authored_by("b2", "mike")]),
        )
        .unwrap();
}

#[test]
fn an_actor_who_may_not_publish_for_the_author_is_refused_and_nothing_is_stored() {
    let (mut module, policy) = library();
    for (actor, author) in [("eve", "mike"), ("bob", "jane")] {
        let error = refused(
            &mut module,
            &policy,
            actor,
            register(object("book", "b1"), vec![authored_by("b1", author)]),
        );
        assert!(
            matches!(&error, AcpError::CreateNotAuthorized { actor: denied, resource, object_id }
                if *denied == did(actor).to_string() && resource == "book" && object_id == "b1"),
            "{error:?}"
        );
    }
    assert!(
        !module
            .query_object_owner(&policy, &object("book", "b1"))
            .unwrap()
            .0
    );
}

#[test]
fn a_plain_registration_in_a_gated_collection_is_refused() {
    let (mut module, policy) = library();
    for actor in ["bob", "mike"] {
        for cmd in [
            PolicyCmd::RegisterObject(object("book", "b1")),
            register(object("book", "b1"), Vec::new()),
        ] {
            assert!(matches!(
                refused(&mut module, &policy, actor, cmd),
                AcpError::CreateNotAuthorized { .. }
            ));
        }
    }
}

#[test]
fn derived_relationships_must_be_on_the_object_and_admitted_whatever_the_collection() {
    let (mut module, policy) = library();
    let owner = relationship_values::owner(&object("book", "b1"), &did("bob")).unwrap();
    let on_another_book = authored_by("b2", "mike");
    let undeclared = actor_relationship("book", "b1", "editor", &did("bob")).unwrap();
    let mistyped = actor_relationship("book", "b1", "author", &did("mike")).unwrap();
    for derived in [
        vec![owner],
        vec![on_another_book.clone()],
        vec![authored_by("b1", "mike"), on_another_book],
        vec![undeclared],
        vec![mistyped],
        vec![authored_by("b1", "mike"), authored_by("b1", "mike")],
    ] {
        let error = refused(
            &mut module,
            &policy,
            "bob",
            register(object("book", "b1"), derived.clone()),
        );
        assert!(
            matches!(error, AcpError::InvalidAccessRequest { .. }),
            "{derived:?}: {error:?}"
        );
    }
    let fan_elsewhere = actor_relationship("artist", "a2", "fan", &did("carol")).unwrap();
    let artist_owner = relationship_values::owner(&object("artist", "a1"), &did("eve")).unwrap();
    for derived in [fan_elsewhere, artist_owner] {
        assert!(matches!(
            refused(
                &mut module,
                &policy,
                "eve",
                register(object("artist", "a1"), vec![derived]),
            ),
            AcpError::InvalidAccessRequest { .. }
        ));
    }
}

#[test]
fn registration_does_not_overwrite_an_existing_object() {
    let (mut module, policy) = library();
    let cmd = || register(object("book", "b1"), vec![authored_by("b1", "mike")]);
    module
        .direct_policy_cmd(&did("bob"), &policy, cmd())
        .unwrap();
    for actor in ["bob", "mike"] {
        assert!(matches!(
            refused(&mut module, &policy, actor, cmd()),
            AcpError::ObjectAlreadyRegistered { .. }
        ));
    }
}

#[test]
fn the_create_check_is_metered_and_an_exhausted_allowance_stores_nothing() {
    let (module, policy) = library();
    let measure = |cmd: PolicyCmd| {
        let mut candidate = module.clone();
        let budget = CommandBudget::new(u64::MAX);
        candidate
            .direct_policy_cmd_with_budget(&did("bob"), &policy, cmd, &budget)
            .unwrap();
        budget.consumed()
    };
    let gated = || register(object("book", "b1"), vec![authored_by("b1", "mike")]);
    let open = || register(object("artist", "a1"), vec![]);
    let gated_cost = measure(gated());
    // Pinned: the gated check's reads and its 10 search steps at 32 units
    // each (6,328 without the steps); the open one evaluates nothing. acp
    // answers the new object's relations from the derived relationships
    // without reading them.
    assert_eq!((gated_cost, measure(open())), (6648, 2792));
    let before = module.store.serialize();
    for limit in [gated_cost - 1, gated_cost / 2] {
        let mut candidate = module.clone();
        assert!(matches!(
            candidate.direct_policy_cmd_with_budget(
                &did("bob"),
                &policy,
                gated(),
                &CommandBudget::new(limit)
            ),
            Err(AcpError::CommandBudgetExceeded)
        ));
        assert_eq!(candidate.store.serialize(), before);
    }
    let mut candidate = module.clone();
    candidate
        .direct_policy_cmd_with_budget(
            &did("bob"),
            &policy,
            gated(),
            &CommandBudget::new(gated_cost),
        )
        .unwrap();
}

#[test]
fn a_registration_names_its_derived_actors_canonically() {
    let (mut module, policy) = library();
    let key = k256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
    let mut bytes = vec![0xe7, 0x01];
    bytes.extend_from_slice(key.verifying_key().to_encoded_point(false).as_bytes());
    let uncompressed = format!("did:key:z{}", bs58::encode(bytes).into_string());
    let fan = actor_relationship("artist", "a1", "fan", &Did::new(uncompressed).unwrap()).unwrap();
    let PolicyCmdResult::RegisterObjectWithRelationships { relationships, .. } = module
        .direct_policy_cmd(
            &did("eve"),
            &policy,
            register(object("artist", "a1"), vec![fan.clone()]),
        )
        .unwrap()
    else {
        panic!("not a registration result");
    };
    let mut canonical = fan.clone();
    spelling::relationship(&mut canonical);
    assert_ne!(
        canonical, fan,
        "the test names the actor in another spelling"
    );
    assert_eq!(relationships[0].relationship, canonical);
}

#[test]
fn the_new_command_has_its_own_wire_form_and_the_old_one_is_unchanged() {
    assert_eq!(
        serde_json::to_value(PolicyCmd::RegisterObject(object("book", "b1"))).unwrap(),
        serde_json::json!({"RegisterObject": {"resource": "book", "id": "b1"}})
    );
    let cmd = register(object("book", "b1"), vec![authored_by("b1", "mike")]);
    let wire = serde_json::to_value(&cmd).unwrap();
    assert_eq!(
        wire,
        serde_json::json!({"RegisterObjectWithRelationships": {
            "object": {"resource": "book", "id": "b1"},
            "relationships": [serde_json::to_value(authored_by("b1", "mike")).unwrap()],
        }})
    );
    let decoded: PolicyCmd = serde_json::from_value(wire).unwrap();
    assert!(matches!(
        decoded,
        PolicyCmd::RegisterObjectWithRelationships { relationships, .. }
            if relationships == vec![authored_by("b1", "mike")]
    ));
}
