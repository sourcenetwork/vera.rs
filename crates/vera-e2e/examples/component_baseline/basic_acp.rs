use identity::Did;
use vera_client::BlsSigner;
use vera_modules::{
    acp::{
        AcpModule,
        types::{
            AccessRequest, Actor, Object, Operation, PolicyCmd, PolicyCmdResult, PolicyCreation,
            PolicyMarshalingType, PolicyRecord,
        },
    },
    kv_store::InMemoryKvStore,
    types::{BlockExecCtx, Timestamp, TxExecCtx},
};

const POLICY: &str = "name: basic-component\nresources:\n  - name: file\n    permissions:\n      - name: read\n        expr: owner\n";

struct Fixture {
    owner: Did,
    block: BlockExecCtx,
    submission: TxExecCtx,
    request: PolicyCreation,
    object: Object,
}

impl Fixture {
    fn new() -> Self {
        let owner: Did = BlsSigner::new(42_u64.into(), 9001)
            .unwrap()
            .did()
            .parse()
            .unwrap();
        Self {
            submission: TxExecCtx {
                signer: owner.to_string(),
                tx_hash: vec![42; 32],
                sequence: 1,
            },
            owner,
            block: BlockExecCtx {
                genesis_id: [42; 32],
                deployment_id: 9001,
                timestamp: Timestamp {
                    seconds: 1_700_000_000,
                    block_height: 1,
                },
            },
            request: PolicyCreation {
                policy: POLICY.into(),
                marshal_type: PolicyMarshalingType::ShortYaml,
                required_specification: None,
                metadata: Default::default(),
            },
            object: Object {
                resource: "file".into(),
                id: "report".into(),
            },
        }
    }

    fn create(&self, module: &mut AcpModule) -> PolicyRecord {
        module
            .execute_create_policy(&self.owner, &self.request, &self.block, &self.submission)
            .unwrap()
    }

    fn command(&self, module: &mut AcpModule, policy: &str, command: PolicyCmd) -> PolicyCmdResult {
        module
            .execute_policy_cmd(&self.owner, policy, command, &self.block, &self.submission)
            .unwrap()
    }

    fn allowed(&self, module: &AcpModule, policy: &str) -> bool {
        module
            .query_verify_access_request(
                policy,
                &AccessRequest {
                    actor: Actor(self.owner.clone()),
                    operations: vec![Operation {
                        object: self.object.clone(),
                        permission: "read".into(),
                    }],
                },
            )
            .unwrap()
    }
}

pub(super) fn run() {
    let fixture = Fixture::new();
    let mut created = AcpModule::new();
    let policy = fixture.create(&mut created);
    assert_eq!(policy.metadata.owner_did, fixture.owner.as_str());
    assert_eq!(policy.metadata.creation_ts, fixture.block.timestamp);
    assert_eq!(policy.metadata.tx_hash, fixture.submission.tx_hash);
    let id = &policy.policy.id;
    assert!(!fixture.allowed(&created, id));
    let original = created.store().serialize();
    let mut registered = created.clone();
    fixture.command(
        &mut registered,
        id,
        PolicyCmd::RegisterObject(fixture.object.clone()),
    );
    assert!(fixture.allowed(&registered, id));
    let mut archived = registered.clone();
    fixture.command(
        &mut archived,
        id,
        PolicyCmd::ArchiveObject(fixture.object.clone()),
    );
    assert!(!fixture.allowed(&archived, id));
    let mut restored = archived.clone();
    fixture.command(
        &mut restored,
        id,
        PolicyCmd::UnarchiveObject(fixture.object.clone()),
    );
    let bytes = restored.store().serialize();
    let restored = AcpModule::from_store(InMemoryKvStore::deserialize(&bytes).unwrap());
    restored.validate_restored_state().unwrap();
    assert!(fixture.allowed(&restored, id));
    assert_eq!(created.store().serialize(), original);

    super::measure_prepared("acp_policy_create", AcpModule::new, |module| {
        fixture.create(module)
    });
    for (name, state, command) in [
        (
            "acp_object_register",
            &created,
            PolicyCmd::RegisterObject(fixture.object.clone()),
        ),
        (
            "acp_object_archive",
            &registered,
            PolicyCmd::ArchiveObject(fixture.object.clone()),
        ),
        (
            "acp_object_unarchive",
            &archived,
            PolicyCmd::UnarchiveObject(fixture.object.clone()),
        ),
    ] {
        super::measure_prepared(
            name,
            || (state.clone(), Some(command.clone())),
            |(module, command)| fixture.command(module, id, command.take().unwrap()),
        );
    }
}
