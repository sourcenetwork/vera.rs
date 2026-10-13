use identity::Did;
use vera_client::BlsSigner;
use vera_modules::{
    acp::AcpModule,
    bulletin::{BulletinModule, error::BulletinError, types::Namespace},
    kv_store::InMemoryKvStore,
    types::{BlockExecCtx, Timestamp, TxExecCtx},
};

const NAMESPACE: &str = "component";

#[derive(Clone, Default)]
struct State {
    bulletin: BulletinModule,
    acp: AcpModule,
}

struct Fixture {
    owner: Did,
    publisher: Did,
    block: BlockExecCtx,
    owner_submission: TxExecCtx,
    publisher_submission: TxExecCtx,
    proof: Vec<u8>,
    state: State,
}

impl Fixture {
    fn new() -> Self {
        let owner: Did = BlsSigner::new(42_u64.into(), 9001)
            .unwrap()
            .did()
            .parse()
            .unwrap();
        let publisher: Did = BlsSigner::new(43_u64.into(), 9001)
            .unwrap()
            .did()
            .parse()
            .unwrap();
        let mut fixture = Self {
            owner_submission: TxExecCtx {
                signer: owner.to_string(),
                tx_hash: vec![42; 32],
                sequence: 1,
            },
            publisher_submission: TxExecCtx {
                signer: publisher.to_string(),
                tx_hash: vec![43; 32],
                sequence: 1,
            },
            owner,
            publisher,
            block: BlockExecCtx {
                genesis_id: [42; 32],
                deployment_id: 9001,
                timestamp: Timestamp {
                    seconds: 1_700_000_000,
                    block_height: 1,
                },
            },
            proof: vec![7; 64],
            state: State::default(),
        };
        let mut state = State::default();
        fixture.register(&mut state, NAMESPACE);
        assert!(matches!(
            fixture.publish(&mut state, b"denied"),
            Err(BulletinError::NotCollaborator { .. })
        ));
        state
            .bulletin
            .add_collaborator(
                &mut state.acp,
                &fixture.owner_submission,
                &fixture.owner,
                NAMESPACE,
                fixture.publisher.as_str(),
            )
            .unwrap();
        fixture.state = state;
        fixture
    }

    fn register(&self, state: &mut State, namespace: &str) -> Namespace {
        state
            .bulletin
            .register_namespace(
                &mut state.acp,
                &self.block,
                &self.owner_submission,
                &self.owner,
                namespace,
            )
            .unwrap()
    }

    fn publish(&self, state: &mut State, payload: &[u8]) -> Result<String, BulletinError> {
        state.bulletin.create_post(
            &state.acp,
            &self.publisher_submission,
            &self.publisher,
            NAMESPACE,
            payload,
            &self.proof,
            "",
        )
    }

    fn verify_post(&self, payload: &[u8]) -> (State, String) {
        let original = self.state.bulletin.store().serialize();
        let original_acp = self.state.acp.store().serialize();
        let mut posted = self.state.clone();
        let id = self.publish(&mut posted, payload).unwrap();
        let bytes = posted.bulletin.store().serialize();
        let restored = BulletinModule::from_store(InMemoryKvStore::deserialize(&bytes).unwrap());
        let post = restored.query_post(NAMESPACE, &id).unwrap();
        assert_eq!(post.payload, payload);
        assert_eq!(post.proof, self.proof);
        assert_eq!(post.creator_did, self.publisher.as_str());
        assert_eq!(
            post.namespace,
            restored.query_namespace(NAMESPACE).unwrap().id
        );
        let mut revoked = self.state.clone();
        revoked
            .bulletin
            .remove_collaborator(
                &mut revoked.acp,
                &self.owner_submission,
                &self.owner,
                NAMESPACE,
                self.publisher.as_str(),
            )
            .unwrap();
        assert!(matches!(
            self.publish(&mut revoked, payload),
            Err(BulletinError::NotCollaborator { .. })
        ));
        assert_eq!(self.state.bulletin.store().serialize(), original);
        assert_eq!(self.state.acp.store().serialize(), original_acp);
        (posted, id)
    }
}

pub(super) fn run() {
    let fixture = Fixture::new();
    for (name, state) in [
        ("bulletin_namespace_cold", State::default()),
        ("bulletin_namespace_warm", fixture.state.clone()),
    ] {
        let mut registered = state.clone();
        assert_eq!(fixture.register(&mut registered, "new").id, "bulletin/new");
        assert_eq!(
            registered
                .bulletin
                .query_namespace("new")
                .unwrap()
                .owner_did,
            fixture.owner.as_str()
        );
        registered.acp.validate_restored_state().unwrap();
        super::measure_prepared(
            name,
            || state.clone(),
            |state| fixture.register(state, "new"),
        );
    }
    for (suffix, size) in [("1k", 1024), ("64k", 64 * 1024)] {
        let payload = vec![42; size];
        let (posted, id) = fixture.verify_post(&payload);
        super::measure_prepared(
            &format!("bulletin_post_create_{suffix}"),
            || fixture.state.clone(),
            |state| fixture.publish(state, &payload).unwrap(),
        );
        super::measure(&format!("bulletin_post_read_{suffix}"), || {
            std::hint::black_box(posted.bulletin.query_post(NAMESPACE, &id).unwrap());
        });
    }
}
