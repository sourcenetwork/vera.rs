//! Validator assembly: start every commonware actor around the vera application
//! and run until one of them stops.

use std::{
    marker::PhantomData,
    sync::{Arc, OnceLock},
    time::Duration,
};

use commonware_broadcast::buffered;
use commonware_codec::Encode as _;
use commonware_consensus::{
    Reporters,
    marshal::{
        self, Identifier, core::Actor as MarshalActor, resolver::p2p as marshal_resolver,
        standard::Deferred,
    },
    simplex::{
        SkipBudget,
        config::{ForwardPolicy, SkipPolicy},
    },
    types::{Epoch, FixedEpocher, Height, ViewDelta},
};
use commonware_cryptography::ChaCha20Poly1305;
use commonware_cryptography::{Digestible as _, Signer as _};
use commonware_glue::{
    dkg::{
        SecretStore as _,
        fence::Fence,
        orchestrator, probe, reshare,
        state_sync::{Config as StateSyncConfig, Plan as StateSyncPlan, StateSync},
        types::Payload,
    },
    stateful::{
        Config as StatefulConfig, Stateful, SyncPlan,
        db::{Shared, SyncEngineConfig, p2p as state_p2p},
    },
};
use commonware_p2p::{Ingress, Provider as _, authenticated::discovery};
use commonware_parallel::{Rayon, Sequential};
use commonware_runtime::{Handle, Spawner as _, Supervisor as _, buffer::paged::CacheRef, tokio};
use commonware_storage::{archive::prunable, translator::TwoCap};
use commonware_stream::{
    cups::{self, Cups},
    sake::{self, Sake},
};
use commonware_utils::{NZDuration, NZU64, NZUsize, sequence::Unit};
use tracing::{error, info};
use vera_app::{
    ConsensusScheme, StatefulVeraApp,
    ordered_state::{OrderedState, ordered_config},
};
use vera_backend::{
    AccountsDb, CodeDb, StorageDb,
    native::{self, NativeDb},
    p2p::{MAX_FETCH_OPS, Resolver as StateResolver, WireDatabase},
    state_set_config,
};
use vera_consensus::components::InMemoryMempool;
use vera_domain::EpochMaterial;
use vera_executor::{ExecutionConfig, MempoolValidator, VeraExecutor};
use vera_indexer::{BlockIndex, LightBlockIndex, StoredEpochMaterial};
use vera_jsonrpc::{IndexedStateProvider, NodeState, RpcServer, TxSubmitCallback};

use crate::{
    BACKFILL_CHANNEL, BROADCAST_CHANNEL, CERTIFICATE_CHANNEL, CommittedState, DKG_CHANNEL,
    DKG_PROBE_CHANNEL, DynamicProvider, FileSecretStore, IO_BUFFER_SIZE, MAILBOX_SIZE,
    MAX_BLOCK_TXS, MAX_MESSAGE_SIZE, MAX_PARTICIPANTS, MAX_SUPPORTED_MODE, MAX_TX_BYTES,
    MEMPOOL_CHANNEL, MESSAGE_RATE, NAMESPACE, NodeSettings, P2P_SUFFIX, PAGE_CACHE_SIZE, PAGE_SIZE,
    RESOLVER_CHANNEL, REVEAL, Registrar, RegistryParticipants, SHARING_MODE, TxGossip,
    VOTE_CHANNEL, VrfElectorConfig, rejoin,
    sink::{FinalizationArtifacts, FinalizationLookup, NodeSink, SinkParts},
    spawn_tx_receiver,
    tx_gossip::SharedValidator,
};

pub(super) const PARTITION_PREFIX: &str = "vera";

/// Run a validator until one of its actors stops.
pub async fn run_node(context: tokio::Context, settings: NodeSettings) -> anyhow::Result<()> {
    let NodeSettings {
        config,
        genesis,
        peers,
        secrets_path,
        rpc_addr,
        leader_timeout,
        certification_timeout,
        timeout_retry,
    } = settings;
    let chain_id = config.chain_id;
    anyhow::ensure!(
        chain_id == genesis.chain_id,
        "config chain_id {chain_id} does not match genesis chain_id {}; fix the config",
        genesis.chain_id
    );
    let gas_limit = config.execution.gas_limit;
    let snapshot = config.snapshot.clone().unwrap_or_default();
    anyhow::ensure!(
        snapshot.record_bytes > 0
            && snapshot.peer_timeout_ms > 0
            && snapshot.initialization_timeout_ms > 0
            && snapshot.logs > 0,
        "snapshot byte limit, log limit and deadlines must be positive"
    );
    if let Some(parameters) = genesis.simplex {
        parameters.validate().map_err(anyhow::Error::msg)?;
    }
    let term_length = std::num::NonZeroU64::new(
        genesis
            .simplex
            .map_or(1, |parameters| parameters.term_length),
    )
    .expect("validated leader term length");
    let blocks_per_epoch = std::num::NonZeroU64::new(genesis.blocks_per_epoch)
        .ok_or_else(|| anyhow::anyhow!("genesis blocks_per_epoch must be non-zero"))?;
    let prune_config = config
        .pruning
        .as_ref()
        .map(|pruning| {
            pruning
                .validate(blocks_per_epoch)
                .map_err(anyhow::Error::msg)?;
            Ok::<_, anyhow::Error>(commonware_glue::stateful::PruneConfig {
                maintenance_interval: pruning.maintenance_interval,
                retained_marshal_blocks: pruning.retained_consensus_revisions,
                retained_qmdb_blocks: pruning.retained_state_revisions,
            })
        })
        .transpose()?;
    let signing_key = config.validator_key()?;
    let local = signing_key.public_key();
    let validator_index = peers
        .participants
        .iter()
        .position(|pk| *pk == local)
        .ok_or_else(|| anyhow::anyhow!("validator key is not in peers.json"))?;
    let epoch_info = genesis
        .decode_epoch_info()?
        .ok_or_else(|| anyhow::anyhow!("genesis.json is missing epoch_info"))?;
    let players = epoch_info.output.players().clone();
    let capacity = vera_domain::max_epoch_participants(blocks_per_epoch, term_length);
    for (set, count) in [
        ("voting participants", players.len()),
        ("DKG players", epoch_info.players.len()),
        ("next DKG players", epoch_info.next_players.len()),
        ("registry validators", genesis.validators.len()),
    ] {
        anyhow::ensure!(
            count <= capacity as usize,
            "genesis has {count} {set}, but epoch length {blocks_per_epoch} and leader term {term_length} support at most {capacity}",
        );
    }
    let listen: std::net::SocketAddr = config.network.listen_addr.parse()?;
    let dial: std::net::SocketAddr = config
        .network
        .dialable_addr
        .as_deref()
        .map_or(Ok(listen), str::parse)?;
    let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);

    // Network.
    let bootstrappers = peers
        .bootstrappers
        .iter()
        .filter(|(pk, _)| *pk != local)
        .map(|(pk, addr)| (pk.clone(), Ingress::Socket(*addr)))
        .collect();
    let max_peers_per_set = NZUsize!(MAX_PARTICIPANTS.get() as usize);
    let mut p2p_config = discovery::Config::local(
        Cups::<_, ChaCha20Poly1305>::new(
            Sake {
                signer: signing_key.clone(),
                synchrony_bound: std::time::Duration::from_secs(5),
                max_handshake_age: std::time::Duration::from_secs(10),
                version: sake::Version::V1,
            },
            cups::Version::V1,
        ),
        &[NAMESPACE, P2P_SUFFIX].concat(),
        listen,
        dial,
        bootstrappers,
        max_peers_per_set,
        MAX_MESSAGE_SIZE,
    );
    p2p_config.mailbox_size = MAILBOX_SIZE;
    let (mut p2p, oracle) = discovery::Network::new(context.child("network"), p2p_config);
    let vote_network = p2p.register(VOTE_CHANNEL, MESSAGE_RATE);
    let certificate_network = p2p.register(CERTIFICATE_CHANNEL, MESSAGE_RATE);
    let resolver_network = p2p.register(RESOLVER_CHANNEL, MESSAGE_RATE);
    let backfill_network = p2p.register(BACKFILL_CHANNEL, MESSAGE_RATE);
    let broadcast_network = p2p.register(BROADCAST_CHANNEL, MESSAGE_RATE);
    let dkg_network = p2p.register(DKG_CHANNEL, MESSAGE_RATE);
    let dkg_probe_network = p2p.register(DKG_PROBE_CHANNEL, MESSAGE_RATE);
    let (mempool_sender, mempool_receiver) = p2p.register(MEMPOOL_CHANNEL, MESSAGE_RATE);
    let history_network = p2p.register(crate::HISTORY_CHANNEL, MESSAGE_RATE);
    let mut state_resolver_handles = Vec::new();
    macro_rules! state_channel {
        ($id:literal, $db:ty) => {{
            let (actor, mailbox) = state_p2p::Actor::new(
                context.child(concat!("state_resolver_", stringify!($id))),
                state_p2p::Config {
                    peer_provider: oracle.clone(),
                    blocker: oracle.clone(),
                    database: None::<Shared<WireDatabase<$db>>>,
                    mailbox_size: NZUsize!(16),
                    me: Some(local.clone()),
                    timeout: Duration::from_secs(2),
                    fetch_retry_timeout: Duration::from_millis(100),
                    max_serve_ops: MAX_FETCH_OPS,
                    priority_requests: false,
                    priority_responses: false,
                },
            );
            state_resolver_handles
                .push(actor.start(p2p.register(crate::QMDB_CHANNELS[$id], MESSAGE_RATE)));
            StateResolver::<$db>::new(mailbox)
        }};
    }
    let state_resolvers = (
        state_channel!(0, AccountsDb),
        state_channel!(1, StorageDb),
        state_channel!(2, CodeDb),
        state_channel!(3, NativeDb),
        state_channel!(4, NativeDb),
        state_channel!(5, NativeDb),
        state_channel!(6, NativeDb),
        (),
    );
    let p2p_handle = p2p.start();

    // Epoch-0 certificate scheme.
    let provider = DynamicProvider::default();
    let mut store = FileSecretStore::load(&secrets_path)?;
    let sharing = epoch_info.output.public().clone();
    match store.get_share(Epoch::zero()).await {
        Some(share) => provider.register(
            Epoch::zero(),
            ConsensusScheme::signer(NAMESPACE, players.clone(), sharing.clone(), share)
                .ok_or_else(|| anyhow::anyhow!("epoch-0 share does not match genesis"))?,
        ),
        None => provider.register(
            Epoch::zero(),
            ConsensusScheme::verifier(NAMESPACE, players.clone(), sharing.clone()),
        ),
    }

    let verification_threads = std::thread::available_parallelism()
        .unwrap_or(NZUsize!(1))
        .min(NZUsize!(4));
    let executor = VeraExecutor::new(chain_id)
        .with_membership_epochs(blocks_per_epoch, term_length)
        .with_native_verification_strategy(Rayon::new(verification_threads)?);
    let executor_spec = executor.spec_id();
    #[cfg(feature = "fault-injection")]
    let executor = executor.with_crash_marker(config.data_dir.join("module-commit-crash"));
    let modules = executor.modules().clone();
    let genesis_block =
        crate::native_genesis::load_or_create(&context, &config.data_dir, &genesis, &page_cache)
            .await?
            .with_payload(Payload::EpochInfo(epoch_info.clone()));
    let executor = executor.with_genesis_id(genesis_block.id().0.0);

    // Marshal, broadcast, archives.
    let resolver = marshal_resolver::init(
        context.child("marshal_resolver"),
        marshal_resolver::Config {
            public_key: local.clone(),
            peer_provider: oracle.clone(),
            blocker: oracle.clone(),
            mailbox_size: MAILBOX_SIZE,
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        },
        backfill_network,
    );
    let (broadcast_engine, buffer) = buffered::Engine::new(
        context.child("broadcast"),
        buffered::Config {
            public_key: local.clone(),
            mailbox_size: MAILBOX_SIZE,
            deque_size: 16,
            priority: false,
            codec_config: block_cfg(),
            peer_provider: oracle.clone(),
        },
    );
    let broadcast_handle = broadcast_engine.start(broadcast_network);
    let finalizations_by_height = prunable::Archive::init(
        context.child("finalizations_by_height"),
        archive_config("finalizations", page_cache.clone(), ()),
    )
    .await?;
    let finalized_blocks = prunable::Archive::init(
        context.child("finalized_blocks"),
        archive_config("blocks", page_cache.clone(), block_cfg()),
    )
    .await?;

    let stateful_startup = context.child("stateful_startup");
    let mut plan = SyncPlan::init(stateful_startup.child("plan"), PARTITION_PREFIX).await;
    let (probe_actor, probe_mailbox) = probe::Actor::new(probe::Config {
        floor: plan.floor().cloned(),
        context: context.child("dkg_probe"),
        manager: oracle.clone(),
        bootstrap: probe::Bootstrap {
            epoch: Epoch::zero(),
            participants: epoch_info.participants(),
            directory: Unit,
        },
        verifier: ConsensusScheme::certificate_verifier(NAMESPACE, *sharing.public()),
        genesis: epoch_info.clone(),
        strategy: Sequential,
        blocker: oracle.clone(),
        blocks_per_epoch,
        retry_timeout: NZDuration!(Duration::from_millis(500)),
        mailbox_size: MAILBOX_SIZE,
        block_codec_config: block_cfg(),
    });
    let probe_handle = probe_actor.start(dkg_probe_network);

    let history = Arc::new(crate::FinalizedHistory::open(
        config.data_dir.join("history"),
        &genesis_block,
    )?);
    let completed_sync_height = plan.completed();
    let mut snapshot_sync = plan.should_sync(config.snapshot.is_some());
    let mut probe_artifact = None;
    if !snapshot_sync && history.head_height() > 0 && peers.participants.len() > 1 {
        // A completed state sync skips peer synchronization forever, which
        // strands a restart that fell too far behind to follow reshare
        // ceremonies forward. Ask the network for its epoch before
        // proceeding; a bounded wait keeps peerless cluster restarts on the
        // plain backfill path.
        let our_epoch = history.head_height() / blocks_per_epoch.get();
        match ::tokio::time::timeout(Duration::from_secs(30), probe_mailbox.subscribe()).await {
            Ok(Ok(artifact))
                if rejoin::stranded(our_epoch, artifact.floor.proposal.round.epoch().get()) =>
            {
                tracing::warn!(
                    our_epoch,
                    network_epoch = artifact.floor.proposal.round.epoch().get(),
                    "durable state predates reachable reshare ceremonies; re-arming state sync"
                );
                drop(plan);
                rejoin::reset_sync_bookkeeping(&config.data_dir)?;
                plan = SyncPlan::init(stateful_startup.child("plan"), PARTITION_PREFIX).await;
                snapshot_sync = true;
                probe_artifact = Some(artifact);
            }
            _ => {}
        }
    }
    let probe_artifact = match probe_artifact {
        artifact @ Some(_) => artifact,
        // Fresh or resumed joins need the probe artifact to sync, but waiting
        // forever hides a committee that can never answer (rotated past
        // genesis, or every bootstrapper down): fail fast with an actionable
        // error instead of hanging before consensus starts.
        None if snapshot_sync => {
            let wait = Duration::from_secs(300);
            match ::tokio::time::timeout(wait, probe_mailbox.subscribe()).await {
                Ok(Ok(artifact)) => Some(artifact),
                Ok(Err(e)) => {
                    return Err(anyhow::anyhow!(
                        "dkg probe stopped before state sync: {e:?}"
                    ));
                }
                Err(_) => {
                    return Err(anyhow::anyhow!(
                        "no peers answered the epoch probe within {}s; check peers.json                          bootstrappers and network reachability",
                        wait.as_secs()
                    ));
                }
            }
        }
        None => None,
    };
    if let Some(artifact) = &probe_artifact {
        #[cfg(feature = "fault-injection")]
        {
            let pause = config.data_dir.join("snapshot-probe-pause");
            if pause.try_exists()? {
                std::fs::write(config.data_dir.join("snapshot-probe-ready"), [])?;
                while pause.try_exists()? {
                    ::tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
        provider.register(
            artifact.info.epoch,
            ConsensusScheme::verifier(
                NAMESPACE,
                artifact.info.output.players().clone(),
                artifact.info.output.public().clone(),
            ),
        );
        plan = plan.set_floor(artifact.floor.clone()).await;
    }

    let (marshal_actor, marshal, floor) = MarshalActor::init(
        context.child("marshal"),
        finalizations_by_height,
        finalized_blocks,
        marshal::Config {
            provider: provider.clone(),
            epocher: FixedEpocher::new(blocks_per_epoch),
            start: plan.marshal_start(Arc::new(genesis_block.clone())),
            partition_prefix: PARTITION_PREFIX.to_string(),
            mailbox_size: MAILBOX_SIZE,
            view_retention: ViewDelta::new(10),
            prunable_items_per_section: NZU64!(256),
            page_cache: page_cache.clone(),
            replay_buffer: IO_BUFFER_SIZE,
            key_write_buffer: IO_BUFFER_SIZE,
            value_write_buffer: IO_BUFFER_SIZE,
            block_codec_config: block_cfg(),
            max_repair: NZUsize!(10),
            max_pending_acks: NZUsize!(1),
            strategy: Sequential,
        },
    )
    .await;

    // DKG / reshare.
    let fence_epoch = probe_artifact
        .as_ref()
        .map_or_else(Epoch::zero, |artifact| artifact.info.epoch);
    let state_sync = probe_artifact.map(|artifact| StateSync {
        info: artifact.info,
        floor: plan
            .floor()
            .cloned()
            .expect("state sync startup carries a floor"),
    });
    let state_sync = StateSyncPlan::init(
        context.child("dkg_state_sync_plan"),
        StateSyncConfig {
            partition_prefix: PARTITION_PREFIX.to_string(),
            max_participants: MAX_PARTICIPANTS,
            max_supported_mode: MAX_SUPPORTED_MODE,
        },
        state_sync,
    )
    .await;
    let (fence, gate) = Fence::new(fence_epoch);
    let participants_provider = RegistryParticipants::new(
        modules.clone(),
        players.clone(),
        history.clone(),
        blocks_per_epoch,
    )
    .with_marshal(marshal.clone());
    let (reshare_actor, reshare_mailbox) = reshare::Actor::new(
        context.child("reshare"),
        reshare::Config {
            signer: signing_key.clone(),
            manager: oracle.clone(),
            blocker: oracle.clone(),
            participants_provider: participants_provider.clone(),
            secret_store: store,
            strategy: Sequential,
            registrar: Registrar::new(provider.clone()),
            marshal: marshal.clone(),
            state_sync: state_sync.clone(),
            fence,
            namespace: NAMESPACE,
            sharing_mode: SHARING_MODE,
            reveal: REVEAL,
            mailbox_size: MAILBOX_SIZE,
            partition_prefix: format!("{PARTITION_PREFIX}-reshare"),
            page_cache: page_cache.clone(),
            write_buffer: IO_BUFFER_SIZE,
            replay_buffer: IO_BUFFER_SIZE,
            muxer_size: 128,
            max_participants: MAX_PARTICIPANTS,
            blocks_per_epoch,
            batch_verifier: PhantomData::<commonware_cryptography::ed25519::Batch>,
        },
    );

    // Mempool, RPC plumbing, and the application.
    let mempool = InMemoryMempool::default();
    let block_index = Arc::new(BlockIndex::new());
    let light_block_index = Arc::new(LightBlockIndex::new(blocks_per_epoch));
    let initial_material = EpochMaterial::new(
        epoch_info.output.players().clone(),
        epoch_info.output.public().clone(),
    );
    light_block_index.insert_epoch_material(
        epoch_info.epoch.get(),
        StoredEpochMaterial {
            bytes: initial_material.encode().into(),
        },
    );
    let (history_peer, history_peer_handle) = crate::start_history_peer(
        context.child("history_peer"),
        history.clone(),
        light_block_index.clone(),
        oracle.clone(),
        oracle.clone(),
        local.clone(),
        history_network,
    );
    let history_peer = Arc::new(::tokio::sync::Mutex::new(history_peer));
    let node_state = NodeState::new(
        chain_id,
        validator_index as u32,
        peers.participants.len() as u32,
    );
    // The watchdog runs before any blocking startup await: the state-sync
    // handoff below can itself stall, and that stall must be recoverable.
    if config.watchdog_stall_seconds > 0 {
        let stall = Duration::from_secs(config.watchdog_stall_seconds);
        let watchdog_state = node_state.clone();
        let has_durable_history = history.head_height() > 0;
        state_resolver_handles.push(context.child("watchdog").spawn(move |_| async move {
            crate::run_watchdog(watchdog_state, stall, has_durable_history).await;
        }));
    }
    if let Some(height) = completed_sync_height {
        node_state.set_snapshot_revision(height.get());
    }
    let (heads_tx, _) = ::tokio::sync::broadcast::channel(64);
    let (logs_tx, _) = ::tokio::sync::broadcast::channel(256);
    let (headers_tx, _) = ::tokio::sync::broadcast::channel(64);

    let validator: SharedValidator = Arc::new(OnceLock::new());
    let finalization_marshal = marshal.clone();
    let finalization_lookup: FinalizationLookup = Arc::new(move |height| {
        let marshal = finalization_marshal.clone();
        Box::pin(async move {
            // Marshal dispatches only after its finalized archive is durable.
            // Ancestors finalized by a descendant need not have a certificate.
            marshal
                .get_finalization(Height::new(height))
                .await
                .map(|finalization| FinalizationArtifacts {
                    epoch: finalization.proposal.round.epoch().get(),
                    certificate: finalization.certificate.encode().to_vec(),
                    finalization: finalization.encode().to_vec(),
                })
        })
    });
    let sink = NodeSink::new(SinkParts {
        history: history.clone(),
        index: block_index.clone(),
        light_index: light_block_index.clone(),
        heads: heads_tx.clone(),
        logs: logs_tx.clone(),
        headers: headers_tx.clone(),
        node_state: node_state.clone(),
        finalization_lookup: finalization_lookup.clone(),
        chain_id,
        publisher_index: validator_index as u32,
        gas_limit,
        executor: executor.clone(),
        mempool: mempool.clone(),
        validator: validator.clone(),
    });
    let participant_addresses = peers
        .participants
        .iter()
        .cloned()
        .zip(genesis.to_genesis_state()?.participant_addresses)
        .collect();
    let application = StatefulVeraApp::<_, OrderedState>::new(
        executor.clone(),
        genesis_block.clone(),
        mempool.clone(),
        sink.clone(),
        MAX_BLOCK_TXS,
        gas_limit,
    )
    .with_participant_addresses(participant_addresses)
    .with_native_pipeline(
        genesis.simplex.is_some(),
        (leader_timeout / 4).min(Duration::from_millis(100)),
    );
    let vrf_elector = VrfElectorConfig::new(application.vrf_seed_cache(), genesis.simplex);

    let snapshot_history = crate::history::SnapshotHistory {
        history: history.clone(),
        genesis: genesis_block.clone(),
        index: block_index.clone(),
        epochs: light_block_index.clone(),
        trusted: *sharing.public(),
        lookup: finalization_lookup.clone(),
        limits: crate::HistoryLimits {
            record_bytes: snapshot.record_bytes,
            logs: snapshot.logs,
        },
        deadline: Duration::from_millis(snapshot.peer_timeout_ms),
        #[cfg(feature = "fault-injection")]
        crash_marker: config.data_dir.join("snapshot-import-crash"),
    };
    let sync_marshal = marshal.clone();
    let mut sync_peers = oracle.clone();
    let sync_local = local.clone();
    let sync_history_peer = history_peer.clone();
    let sync_status = node_state.clone();
    let (stateful_actor, stateful_mailbox) = Stateful::new(
        context.child("stateful"),
        StatefulConfig {
            application,
            db_config: ordered_config(
                state_set_config(PARTITION_PREFIX, page_cache.clone()),
                native::state_config(PARTITION_PREFIX, page_cache.clone()),
                executor.clone(),
            )
            .recover_from_marshal()
            .with_sync_handoff(move |anchor| async move {
                let selected: Arc<vera_domain::Block> = sync_marshal
                    .get_block(Identifier::Height(anchor.height))
                    .await
                    .ok_or_else(|| "missing synchronized history anchor".to_string())?;
                if selected.digest() != anchor.digest || selected.context.round != anchor.round {
                    return Err("synchronized history anchor mismatch".into());
                }
                let mut updates = sync_peers.subscribe().await;
                let peers = updates
                    .recv()
                    .await
                    .ok_or_else(|| "history peer subscription closed".to_string())?;
                let peers: Vec<_> = peers
                    .all
                    .primary
                    .into_iter()
                    .filter(|peer| *peer != sync_local)
                    .collect();
                let mut client = sync_history_peer.lock().await;
                snapshot_history
                    .recover(&mut client, &peers, &selected)
                    .await
                    .map_err(|e| e.to_string())?;
                sync_status.set_snapshot_revision(anchor.height.get());
                sync_status.record_finalized(
                    selected.height,
                    selected.context.round.epoch().get(),
                    selected.context.round.view().get(),
                );
                Ok(())
            }),
            provider: mempool.clone(),
            marshal: (marshal.clone(), floor),
            mailbox_size: MAILBOX_SIZE,
            plan,
            resolvers: state_resolvers,
            sync_config: sync_config(),
            prune_config,
        },
    );

    let (application, application_ready) =
        crate::ready_application::ReadyApplication::new(reshare::Application::new(
            stateful_mailbox.clone(),
            reshare_mailbox.clone(),
            blocks_per_epoch,
        ));
    let deferred = Deferred::new(
        context.child("deferred"),
        application,
        marshal.clone(),
        FixedEpocher::new(blocks_per_epoch),
    );
    let skip_timeout = Duration::from_secs(5)
        .max(certification_timeout.saturating_add(Duration::from_millis(1)))
        .max(timeout_retry.saturating_add(Duration::from_millis(1)));
    let (orchestrator_actor, orchestrator_mailbox) = orchestrator::Actor::new(
        context.child("orchestrator"),
        orchestrator::Config {
            oracle: oracle.clone(),
            manager: oracle.clone(),
            provider: provider.clone(),
            marshal: marshal.clone(),
            application: deferred,
            strategy: Sequential,
            simplex: orchestrator::SimplexConfig {
                elector: vrf_elector,
                mailbox_size: NZUsize!(3),
                replay_buffer: IO_BUFFER_SIZE,
                write_buffer: IO_BUFFER_SIZE,
                page_cache: page_cache.clone(),
                leader_timeout,
                certification_timeout,
                timeout_retry,
                fetch_timeout: Duration::from_secs(2),
                view_retention: ViewDelta::new(10),
                skip: SkipPolicy::Enabled {
                    timeout: skip_timeout,
                    budget: SkipBudget::Participants,
                },
                forward: ForwardPolicy::Disabled,
                track_historical_votes: false,
            },
            gate,
            state_sync,
            blocks_per_epoch,
            muxer_size: 128,
            mailbox_size: MAILBOX_SIZE,
            partition_prefix: format!("{PARTITION_PREFIX}-orchestrator"),
        },
    );
    let orchestrator_handle =
        orchestrator_actor.start(vote_network, certificate_network, resolver_network);

    let reporters = Reporters::from((
        stateful_mailbox.clone(),
        Reporters::from((orchestrator_mailbox, reshare_mailbox)),
    ));
    let marshal_handle = marshal_actor.start(reporters, buffer, resolver);
    probe_mailbox.attach(marshal.clone());
    if !snapshot_sync {
        let processed_height = marshal
            .get_processed()
            .await
            .map(|processed| processed.height());
        let recovered_height = processed_height
            .into_iter()
            .chain(completed_sync_height)
            .max()
            .unwrap_or_else(Height::zero);
        let recovered = match marshal
            .get_block(Identifier::Height(recovered_height))
            .await
        {
            Some(block) => block,
            None if processed_height == Some(recovered_height) => marshal
                .get_block(Identifier::Height(recovered_height.next()))
                .await
                .ok_or_else(|| anyhow::anyhow!("missing recovered module anchor"))?,
            None => anyhow::bail!("missing recovered module anchor"),
        };
        history
            .recover(
                &genesis_block,
                &recovered,
                &block_index,
                &light_block_index,
                &finalization_lookup,
            )
            .await?;
        node_state.record_finalized(
            recovered.height,
            recovered.context.round.epoch().get(),
            recovered.context.round.view().get(),
        );
    }
    let reshare_handle = reshare_actor.start(dkg_network);
    let stateful_handle = stateful_actor.start();
    state_resolver_handles.extend([
        p2p_handle,
        broadcast_handle,
        probe_handle,
        orchestrator_handle,
        marshal_handle,
        stateful_handle,
        reshare_handle,
        history_peer_handle,
    ]);
    let startup_actors = Handle::select(std::mem::take(&mut state_resolver_handles));
    ::tokio::pin!(startup_actors);

    // Transaction gossip and RPC over the live committed state.
    let subscribe_databases = stateful_mailbox.subscribe_databases();
    ::tokio::pin!(subscribe_databases);
    let databases = if snapshot_sync {
        let mut refresh = crate::snapshot_refresh::FloorRefresh::new(Duration::from_secs(
            snapshot.floor_stall_seconds,
        ));
        let deadline = ::tokio::time::Instant::now()
            + Duration::from_millis(snapshot.initialization_timeout_ms);
        loop {
            let stalled = async {
                if refresh.enabled() {
                    ::tokio::time::sleep(refresh.stall()).await;
                    refresh.observe(&marshal).await;
                } else {
                    ::std::future::pending::<()>().await;
                }
            };
            ::tokio::select! {
                biased;
                result = &mut startup_actors => {
                    anyhow::bail!("validator actor stopped during startup: {result:?}");
                }
                databases = &mut subscribe_databases => break databases,
                _ = stalled => {}
                _ = ::tokio::time::sleep_until(deadline) => {
                    anyhow::bail!(
                        "snapshot initialization deadline exceeded; restart to discover a fresh certified target"
                    );
                }
            }
        }
    } else {
        ::tokio::select! {
            biased;
            result = &mut startup_actors => {
                anyhow::bail!("validator actor stopped during startup: {result:?}");
            }
            databases = &mut subscribe_databases => databases,
        }
    };
    let native_databases = databases.native_databases();
    let state_set = databases.execution_databases();
    let committed_state = CommittedState::new(state_set.clone());
    sink.attach_state(state_set.clone());
    {
        // Hold the module read lock through publication so finalization cannot
        // advance nonces between loading them and enabling admission.
        let recovered_modules = modules.read().expect("module state lock poisoned");
        let mut admission =
            MempoolValidator::new(committed_state.clone(), ExecutionConfig::new(chain_id), 0)
                .with_native_only(genesis.simplex.is_some());
        admission.reset(committed_state.clone(), recovered_modules.nonces.clone());
        let _ = validator.set(::tokio::sync::Mutex::new(admission));
    }
    application_ready.send_replace(true);
    let gossip = TxGossip::new(
        context.child("tx_clock"),
        mempool.clone(),
        validator.clone(),
        chain_id,
        mempool_sender,
    );
    state_resolver_handles.push(context.child("tx_reannouncement").spawn({
        let gossip = gossip.clone();
        move |context| crate::tx_reannouncement::run(context, gossip)
    }));
    state_resolver_handles.push(spawn_tx_receiver(
        context.child("tx_receiver"),
        mempool_receiver,
        mempool.clone(),
        validator.clone(),
        chain_id,
    ));
    let tx_submit: TxSubmitCallback = Arc::new(move |bytes| {
        let gossip = gossip.clone();
        Box::pin(async move { gossip.submit(bytes).await })
    });
    let archive = vera_jsonrpc::ArchiveReader::new(node_state.clone(), {
        let history = history.clone();
        Arc::new(move |query, remaining_bytes| {
            let Some(execution) =
                history
                    .execution_bounded(query, remaining_bytes)
                    .map_err(|error| {
                        if error.downcast_ref::<vera_indexer::IndexerError>().is_some() {
                            vera_jsonrpc::RpcError::LimitExceeded(error.to_string())
                        } else {
                            vera_jsonrpc::RpcError::StateError(error.to_string())
                        }
                    })?
            else {
                return Ok(None);
            };
            let index = Arc::new(BlockIndex::new());
            let gas_used = execution
                .receipts
                .iter()
                .map(|receipt| receipt.gas_used)
                .sum();
            crate::index_finalized_block(
                &index,
                &execution.block,
                execution.gas_limit,
                &execution.receipts,
                gas_used,
            );
            if let vera_indexer::IndexQuery::Submission(hash) = query
                && (index.get_receipt(&hash).is_none() || index.get_transaction(&hash).is_none())
            {
                return Err(vera_jsonrpc::RpcError::StateError(
                    "historical submission cannot be indexed".into(),
                ));
            }
            Ok(Some(index))
        })
    });
    let state_provider = IndexedStateProvider::new(
        block_index.clone(),
        committed_state,
        chain_id,
        executor_spec,
        gas_limit,
        modules.clone(),
    )
    .with_archive(archive.clone());
    if tracing::enabled!(target: "vera_diagnostics", tracing::Level::DEBUG) {
        let history = history.clone();
        let index = block_index.clone();
        let proofs = light_block_index.clone();
        state_resolver_handles.push(
            context
                .child("diagnostics")
                .spawn(move |context| crate::diagnostics::run(context, history, index, proofs)),
        );
    }
    if let Some(pruning) = prune_config {
        let marshal = marshal.clone();
        state_resolver_handles.push(context.child("marshal_floor").spawn(
            move |context| async move {
                crate::marshal_floor::run(context, marshal, pruning).await;
            },
        ));
    }

    let rpc_handle = RpcServer::with_state_provider(node_state, rpc_addr, chain_id, state_provider)
        .with_max_connections(config.rpc.max_connections.get())
        .with_tx_submit(tx_submit)
        .with_subscriptions(heads_tx, logs_tx)
        .with_headers_subscription(headers_tx)
        .with_vera_index_and_modules(block_index, modules.clone())
        .with_vera_native_modules(native_databases, modules)
        .with_vera_archive(archive)
        .with_vera_receipt_proof_lookup({
            let history = history.clone();
            let epochs = light_block_index.clone();
            Arc::new(move |hash| {
                history
                    .receipt_proof(hash, &epochs)
                    .map_err(|error| error.to_string())
            })
        })
        .with_vera_light_block_lookup({
            let epochs = light_block_index.clone();
            Arc::new(move |height| {
                history
                    .light_block(height, &epochs)
                    .map_err(|error| error.to_string())
            })
        })
        .with_vera_light_block_index(light_block_index)
        .start();
    context.child("rpc").spawn(move |_| async move {
        rpc_handle.stopped().await;
        error!("RPC server stopped unexpectedly");
    });
    info!(validator_index, %rpc_addr, "vera validator started");

    ::tokio::select! {
        result = &mut startup_actors => result,
        result = Handle::select(state_resolver_handles) => result,
    }
    .map_err(|e| anyhow::anyhow!("validator actor failed: {e:?}"))
}

pub(crate) const fn block_cfg() -> vera_domain::BlockCfg {
    vera_domain::BlockCfg {
        max_txs: MAX_BLOCK_TXS,
        tx: vera_domain::TxCfg {
            max_tx_bytes: MAX_TX_BYTES,
        },
    }
}

const fn sync_config() -> SyncEngineConfig {
    SyncEngineConfig {
        fetch_batch_size: MAX_FETCH_OPS,
        apply_batch_size: NZU64!(64),
        max_outstanding_requests: 8,
        update_channel_size: NZUsize!(256),
        max_retained_roots: 8,
    }
}

fn archive_config<C>(
    name: &str,
    page_cache: CacheRef,
    codec_config: C,
) -> prunable::Config<TwoCap, C> {
    prunable::Config {
        translator: TwoCap,
        metadata_partition: format!("{PARTITION_PREFIX}-{name}-metadata"),
        key_partition: format!("{PARTITION_PREFIX}-{name}-key"),
        key_page_cache: page_cache,
        value_partition: format!("{PARTITION_PREFIX}-{name}-value"),
        compression: None,
        codec_config,
        items_per_section: NZU64!(256),
        key_write_buffer: IO_BUFFER_SIZE,
        value_write_buffer: IO_BUFFER_SIZE,
        replay_buffer: IO_BUFFER_SIZE,
    }
}
