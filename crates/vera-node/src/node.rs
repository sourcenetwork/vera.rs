//! Validator assembly: start every commonware actor around the vera application
//! and run until one of them stops.

use std::{
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
use commonware_cryptography::{Digested, Digestible as _, Signer as _};
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
use commonware_storage::{
    archive::{Archive as _, prunable},
    translator::TwoCap,
};
use commonware_utils::{NZDuration, NZU64, NZUsize, sequence::Unit};
use tracing::{error, info};
use vera_app::{
    ConsensusScheme, StatefulVeraApp,
    ordered_state::{OrderedState, ordered_config},
};
use vera_backend::{
    native::{self, NativeDb},
    p2p::{MAX_FETCH_OPS, Resolver as StateResolver, WireDatabase},
};
use vera_consensus::components::InMemoryMempool;
use vera_domain::EpochMaterial;
use vera_executor::{ExecutionConfig, MempoolValidator, VeraExecutor};
use vera_indexer::{BlockIndex, LightBlockIndex, StoredEpochMaterial};
use vera_jsonrpc::{IndexedStateProvider, NodeState, RpcServer, TxSubmitCallback};

use crate::{
    BACKFILL_CHANNEL, BROADCAST_CHANNEL, CERTIFICATE_CHANNEL, DKG_CHANNEL, DKG_PROBE_CHANNEL,
    DynamicProvider, FileSecretStore, IO_BUFFER_SIZE, MAILBOX_SIZE, MAX_BLOCK_TXS,
    MAX_PARTICIPANTS, MAX_SUPPORTED_MODE, MAX_TX_BYTES, MEMPOOL_CHANNEL, NAMESPACE, NodeOptions,
    NodeSettings, PAGE_SIZE, RESOLVER_CHANNEL, REVEAL, Registrar, RegistryParticipants, RpcMode,
    SHARING_MODE, TxGossip, VOTE_CHANNEL,
    peer_capacity::PeerCapacity,
    rejoin,
    secret_store::{HeldSecretStore, NodeSecretStore, ObserverSecretStore},
    sink::{FinalizationArtifacts, FinalizationLookup, NodeSink, SinkParts},
    spawn_tx_receiver,
    tx_admission::Admission,
    tx_gossip::SharedValidator,
};

pub(super) const PARTITION_PREFIX: &str = "vera";

/// Run a validator until one of its actors stops.
pub async fn run_node(context: tokio::Context, settings: NodeSettings) -> anyhow::Result<()> {
    run_node_with_rpc_listener(context, settings, None).await
}

/// Run with an optional prebound RPC listener; P2P still binds its configured address.
pub async fn run_node_with_rpc_listener(
    context: tokio::Context,
    settings: NodeSettings,
    rpc_listener: Option<std::net::TcpListener>,
) -> anyhow::Result<()> {
    run_node_with_options(context, settings, NodeOptions::daemon(rpc_listener)).await
}

/// Run a validator hosted by another program until one of its actors stops.
pub async fn run_node_with_options(
    context: tokio::Context,
    settings: NodeSettings,
    options: NodeOptions,
) -> anyhow::Result<()> {
    settings.genesis.validate_timestamp()?;
    settings
        .genesis
        .simplex
        .validate()
        .map_err(anyhow::Error::msg)?;
    let NodeOptions {
        rpc,
        watchdog,
        ready,
        solo_pacing,
        verification_threads,
        history_memory,
        sizing,
        hold,
        keys,
        backup,
        devices,
        switching,
        term: seat,
    } = options;
    let hold = hold.unwrap_or_default();
    if let RpcMode::Network(Some(listener)) = &rpc {
        anyhow::ensure!(
            listener.local_addr()? == settings.rpc_addr,
            "inherited RPC listener does not match configured address"
        );
    }
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
    crate::consensus_timeouts::validate(
        leader_timeout,
        certification_timeout,
        timeout_retry,
        Duration::from_millis(genesis.simplex.stall_timeout_ms),
    )
    .map_err(|error| {
        anyhow::anyhow!(
            "{error}; check --leader-timeout-ms, --notarization-timeout-ms and --nullify-retry-ms"
        )
    })?;
    let mut term_record = crate::term::TermRecord::load(&config.data_dir)?;
    let data_dir = config.data_dir.clone();
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
    let term_length = std::num::NonZeroU64::new(genesis.simplex.term_length)
        .expect("validated leader term length");
    let blocks_per_epoch = std::num::NonZeroU64::new(genesis.blocks_per_epoch)
        .ok_or_else(|| anyhow::anyhow!("genesis blocks_per_epoch must be non-zero"))?;
    let peer_capacity = PeerCapacity::new(blocks_per_epoch, term_length)?;
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
    let history_retention = config
        .history_retention
        .map(|retained| {
            crate::check_history_retention(retained, blocks_per_epoch)?;
            let interval =
                config
                    .pruning
                    .as_ref()
                    .map_or(crate::HISTORY_MAINTENANCE_INTERVAL, |pruning| {
                        std::num::NonZeroU64::new(pruning.maintenance_interval.get() as u64)
                            .expect("nonzero maintenance interval")
                    });
            Ok::<_, anyhow::Error>(crate::history::HistoryRetention {
                retained,
                interval,
                epoch_length: blocks_per_epoch,
            })
        })
        .transpose()?;
    // A validator's network identity is its consensus identity: peers accept
    // its votes and its replies to the epoch probe by that key. A backup is in
    // no committee and runs under a key of its own.
    let is_backup = backup.is_some();
    let signing_key = match (&backup, &keys) {
        (Some(device), _) => device.signer(),
        (None, Some(keys)) => keys.signer(),
        (None, None) => config.validator_key()?,
    };
    let local = signing_key.public_key();
    let validator_index = match peers.participants.iter().position(|pk| *pk == local) {
        Some(_) if is_backup => anyhow::bail!("a backup cannot run under a validator key"),
        Some(index) => index,
        // A backup reports the validator it follows.
        None if is_backup => 0,
        None => anyhow::bail!("validator key is not in peers.json"),
    };
    let devices: Vec<_> = devices.into_iter().filter(|key| *key != local).collect();
    let has_peers = peers.participants.len() > 1 || is_backup || !devices.is_empty();
    let epoch_info = genesis
        .decode_epoch_info()?
        .ok_or_else(|| anyhow::anyhow!("genesis.json is missing epoch_info"))?;
    let players = epoch_info.output.players().clone();
    let capacity = peer_capacity.participants();
    for (set, count) in [
        ("voting participants", players.len()),
        ("DKG players", epoch_info.players.len()),
        ("next DKG players", epoch_info.next_players.len()),
        ("registry validators", genesis.validators.len()),
    ] {
        anyhow::ensure!(
            count <= capacity,
            "genesis has {count} {set}, but epoch length {blocks_per_epoch} and leader term {term_length} support at most {capacity}",
        );
    }
    // The last block of every epoch reads the next participants from the registry.
    anyhow::ensure!(
        !genesis.validators.is_empty(),
        "genesis.json lists no registry validators"
    );
    let listen: std::net::SocketAddr = config.network.listen_addr.parse()?;
    let dial: std::net::SocketAddr = config
        .network
        .dialable_addr
        .as_deref()
        .map_or(Ok(listen), str::parse)?;
    let page_cache = CacheRef::new(PAGE_SIZE, sizing.page_cache_pages);

    // Network.
    let bootstrappers = peers
        .bootstrappers
        .iter()
        .filter(|(pk, _)| *pk != local)
        .map(|(pk, addr)| (pk.clone(), Ingress::Socket(*addr)))
        .collect();
    let max_peers_per_set = peer_capacity.tracked();
    // The backups join every tracked set, and Commonware refuses a set
    // larger than the one its queues were sized for.
    let tracked: std::collections::HashSet<_> = players
        .iter()
        .chain(epoch_info.players.iter())
        .chain(epoch_info.next_players.iter())
        .chain(devices.iter())
        .chain(std::iter::once(&local))
        .collect();
    anyhow::ensure!(
        tracked.len() <= max_peers_per_set.get(),
        "{} backup devices and the committee exceed the {max_peers_per_set} peers an epoch of {blocks_per_epoch} blocks tracks",
        devices.len(),
    );
    let p2p_config = crate::peer_discovery::config(
        signing_key.clone(),
        listen,
        dial,
        bootstrappers,
        max_peers_per_set,
        &config.network.discovery,
    )?;
    let channel_rate = sizing.channel_rate();
    let (mut p2p, oracle) = discovery::Network::new(context.child("network"), p2p_config);
    let manager = crate::devices::DeviceManager::new(oracle.clone(), devices);
    let vote_network = p2p.register(VOTE_CHANNEL, channel_rate);
    let certificate_network = p2p.register(CERTIFICATE_CHANNEL, channel_rate);
    let resolver_network = p2p.register(RESOLVER_CHANNEL, channel_rate);
    let backfill_network = p2p.register(
        BACKFILL_CHANNEL,
        if has_peers {
            sizing.backfill_rate()
        } else {
            channel_rate
        },
    );
    let broadcast_network = p2p.register(BROADCAST_CHANNEL, channel_rate);
    let dkg_network = p2p.register(DKG_CHANNEL, channel_rate);
    let dkg_probe_network = p2p.register(DKG_PROBE_CHANNEL, channel_rate);
    let (mempool_sender, mempool_receiver) = p2p.register(MEMPOOL_CHANNEL, channel_rate);
    let transfer_rate = if has_peers {
        sizing.transfer_rate()
    } else {
        channel_rate
    };
    let history_network = p2p.register(crate::HISTORY_CHANNEL, transfer_rate);
    let term_network = p2p.register(crate::TERM_CHANNEL, channel_rate);
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
                    fetch_timeout: commonware_utils::NZDuration!(Duration::from_secs(2)),
                    fetch_retry_delay: Duration::from_millis(100),
                    max_serve_ops: MAX_FETCH_OPS,
                    priority_requests: false,
                    priority_responses: false,
                },
            );
            state_resolver_handles
                .push(actor.start(p2p.register(crate::QMDB_CHANNELS[$id], transfer_rate)));
            StateResolver::<$db>::new(mailbox)
        }};
    }
    let state_resolvers = (
        state_channel!(0, NativeDb),
        state_channel!(1, NativeDb),
        state_channel!(2, NativeDb),
        state_channel!(3, NativeDb),
        (),
    );
    let p2p_handle = p2p.start();

    // Epoch-0 certificate scheme.
    let provider = DynamicProvider::default();
    let held_share = keys
        .as_ref()
        .filter(|_| !is_backup)
        .map(crate::SoloKeys::consensus_share);
    let mut store = match keys {
        _ if is_backup => NodeSecretStore::Observer(ObserverSecretStore::default()),
        Some(keys) => NodeSecretStore::Held(HeldSecretStore::new(&local, keys.consensus_share())),
        None => NodeSecretStore::File(FileSecretStore::load(&secrets_path)?),
    };
    let sharing = epoch_info.output.public().clone();
    match store.get_share(Epoch::zero()).await {
        Some(share) => provider.register(
            Epoch::zero(),
            crate::provider::signer_scheme(&local, players.clone(), sharing.clone(), share)?,
        ),
        None => provider.register(
            Epoch::zero(),
            ConsensusScheme::verifier(NAMESPACE, players.clone(), sharing.clone()),
        ),
    }

    let verification_strategy = Rayon::new(
        verification_threads.unwrap_or_else(crate::options::default_verification_threads),
    )?;
    let executor = VeraExecutor::new(chain_id)
        .with_membership_epochs(blocks_per_epoch, term_length)
        .with_native_verification_strategy(verification_strategy.clone());
    #[cfg(feature = "fault-injection")]
    let executor = executor.with_crash_marker(config.data_dir.join("module-commit-crash"));
    let modules = executor.modules().clone();
    let genesis_block =
        crate::native_genesis::load_or_create(&context, &config.data_dir, &genesis, &page_cache)
            .await?
            .with_payload(Payload::EpochInfo(epoch_info.clone()));
    let executor = executor.with_genesis_id(genesis_block.id().0.0);
    let execution_config = executor.config().clone();

    // Marshal, broadcast, archives.
    let resolver = marshal_resolver::init(
        context.child("marshal_resolver"),
        marshal_resolver::Config {
            public_key: local.clone(),
            peer_provider: oracle.clone(),
            blocker: oracle.clone(),
            mailbox_size: MAILBOX_SIZE,
            fetch_timeout: commonware_utils::NZDuration!(Duration::from_secs(2)),
            fetch_retry_delay: Duration::from_millis(100),
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
            strategy: verification_strategy.clone(),
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
        manager: manager.clone(),
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

    let finalization_metrics = crate::diagnostics::enabled().then(|| {
        Arc::new(crate::finalization_metrics::FinalizationMetrics::register(
            &context.child("finalization"),
        ))
    });
    let history = Arc::new(
        crate::FinalizedHistory::open_with(
            config.data_dir.join("history"),
            &genesis_block,
            history_memory,
        )?
        .with_metrics(finalization_metrics.clone()),
    );
    // An embedded node changes role between starts; marshal and consensus
    // have not opened their storage yet.
    let finalizations_by_height = if seat.is_some() {
        #[cfg(feature = "fault-injection")]
        let finalizations_by_height = crate::term::fault::orphan(
            &config.data_dir,
            finalizations_by_height,
            finalized_blocks.last_index(),
            &genesis_block.id().0,
            history_memory,
        )
        .await?;
        let settled = crate::term::settle_seating(
            context.child("seating"),
            &config.data_dir,
            crate::term::Start {
                this: switching
                    .as_ref()
                    .map(|switching| crate::term::device_id(&switching.device_key.public_key())),
                backup: is_backup,
                newest_block: finalized_blocks.last_index(),
                executed: history.head_height(),
            },
            finalizations_by_height,
            archive_config("finalizations", page_cache.clone(), ()),
        )
        .await?;
        term_record = crate::term::TermRecord::load(&config.data_dir)?;
        settled
    } else {
        finalizations_by_height
    };
    let completed_sync_height = plan.completed();
    let mut snapshot_sync = plan.should_sync(config.snapshot.is_some());
    let mut probe_artifact = None;
    if !snapshot_sync && history.head_height() > 0 && (peers.participants.len() > 1 || is_backup) {
        // A completed state sync skips peer synchronization forever, which
        // strands a restart that fell too far behind to follow reshare
        // ceremonies forward. Ask the network for its epoch before
        // proceeding; a bounded wait keeps peerless cluster restarts on the
        // plain backfill path.
        let our_epoch = history.head_height() / blocks_per_epoch.get();
        match ::tokio::time::timeout(Duration::from_secs(30), probe_mailbox.subscribe()).await {
            Ok(Ok(artifact))
                if rejoin::stranded(our_epoch, artifact.floor.proposal.round.epoch().get())
                    || (is_backup
                        && rejoin::beyond_retention(
                            our_epoch,
                            artifact.floor.proposal.round.epoch().get(),
                            blocks_per_epoch,
                            config
                                .pruning
                                .as_ref()
                                .map(|pruning| pruning.retained_consensus_revisions),
                        )) =>
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
            let wait = Duration::from_millis(snapshot.initialization_timeout_ms);
            match ::tokio::time::timeout(wait, probe_mailbox.subscribe()).await {
                Ok(Ok(artifact)) => Some(artifact),
                Ok(Err(e)) => {
                    return Err(anyhow::anyhow!(
                        "dkg probe stopped before state sync: {e:?}"
                    ));
                }
                Err(_) => {
                    return Err(anyhow::anyhow!(
                        "no peers answered the epoch probe within {}s; check peers.json bootstrappers and network reachability",
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

    let consensus_floor = if seat.is_some() && !snapshot_sync {
        crate::term::seat(
            &history,
            &finalizations_by_height,
            &finalized_blocks,
            &epoch_info,
            blocks_per_epoch,
        )
        .await?
    } else {
        None
    };
    let (marshal_actor, marshal, floor) = MarshalActor::init(
        context.child("marshal"),
        finalizations_by_height,
        finalized_blocks,
        marshal::Config {
            provider: provider.clone(),
            epocher: FixedEpocher::new(blocks_per_epoch),
            start: plan.marshal_start(
                Digested::compute(genesis_block.clone(), &verification_strategy).await,
            ),
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
    // The reshare actor reads an epoch's ceremony from the blocks it holds.
    // Only Simplex is told where the node stands.
    let consensus_start = match consensus_floor {
        Some(seat) => {
            StateSyncPlan::init(
                context.child("consensus_seat"),
                StateSyncConfig {
                    partition_prefix: format!("{PARTITION_PREFIX}-seat"),
                    max_participants: MAX_PARTICIPANTS,
                    max_supported_mode: MAX_SUPPORTED_MODE,
                },
                Some(seat),
            )
            .await
        }
        None => state_sync.clone(),
    };
    let (fence, gate) = Fence::new();
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
            manager: manager.clone(),
            blocker: oracle.clone(),
            participants_provider: participants_provider.clone(),
            secret_store: store,
            strategy: Sequential,
            registrar: Registrar::new(provider.clone(), local.clone()).with_held_share(held_share),
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
            max_participants: MAX_PARTICIPANTS,
            blocks_per_epoch,
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
    // A lone validator without backups never has a peer to count, so it skips the sampling work.
    if has_peers {
        let state = node_state.clone();
        state_resolver_handles.push(
            context
                .child("connectivity")
                .spawn(move |context| crate::connectivity::run(context, state)),
        );
    }
    if let Some(height) = completed_sync_height {
        node_state.set_snapshot_revision(height.get());
    }
    let (headers_tx, _) = ::tokio::sync::broadcast::channel(64);

    let validator: SharedValidator = Arc::new(OnceLock::new());
    let term = seat
        .as_ref()
        .map(|seat| seat.view.guard.clone())
        .unwrap_or_default();
    let finalization_marshal = marshal.clone();
    let finalization_term = term.clone();
    let finalization_lookup: FinalizationLookup = Arc::new(move |height| {
        let marshal = finalization_marshal.clone();
        let lookup_term = finalization_term.clone();
        Box::pin(async move {
            // Marshal dispatches only after its finalized archive is durable.
            // Ancestors finalized by a descendant need not have a certificate.
            let finalization = marshal.get_finalization(Height::new(height)).await?;
            // A device that took the deployment over may hold the certificate
            // of a block of the term before whose block never arrived. The
            // archive keeps the first certificate it stored for a height.
            if lookup_term.term() > 0 {
                let block = marshal
                    .get_block(Identifier::Height(Height::new(height)))
                    .await?;
                if block.digest() != finalization.proposal.payload {
                    return None;
                }
            }
            Some(finalization).map(|finalization| FinalizationArtifacts {
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
        headers: headers_tx.clone(),
        node_state: node_state.clone(),
        finalization_lookup: finalization_lookup.clone(),
        chain_id,
        publisher_index: validator_index as u32,
        gas_limit,
        executor: executor.clone(),
        mempool: mempool.clone(),
        validator: validator.clone(),
    })
    .with_metrics(finalization_metrics)
    .with_history_retention(history_retention);
    #[cfg(feature = "fault-injection")]
    let sink = sink.with_crash_directory(config.data_dir.clone());
    hold.attach({
        let index = block_index.clone();
        move || index.head_block_number()
    });
    // A device that announced a handover and now follows refuses the blocks
    // it would itself have built above the final one.
    if let (true, Some(change)) = (is_backup, &term_record.handed_over) {
        term.raise(change.term, change.cut.height);
    }
    if is_backup && let Some(certificate) = &term_record.certificate {
        term.raise(certificate.change.term, certificate.change.cut.height);
    }
    let wake = match (&switching, &seat) {
        (Some(switching), Some(seat)) if !is_backup => {
            crate::term::WakeGate::new(switching.freshness, seat.sender.clone())
        }
        _ => crate::term::WakeGate::default(),
    };
    let application = StatefulVeraApp::<_, OrderedState>::new(
        executor.clone(),
        genesis_block.clone(),
        mempool.clone(),
        sink.clone(),
        MAX_BLOCK_TXS,
        gas_limit,
    )
    .with_proposal_batch_wait(solo_pacing.map_or_else(
        || (leader_timeout / 4).min(Duration::from_millis(100)),
        |pacing| pacing.batch,
    ))
    .with_settled_batch_wait(solo_pacing.map(|pacing| pacing.settled))
    .with_timestamp_step(
        genesis
            .timestamp_step_secs
            .unwrap_or(vera_app::MAX_TIMESTAMP_STEP_SECS),
    )
    .with_term(term.clone());

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
    let sync_term = term.clone();
    let handing_off = crate::snapshot_refresh::HandingOff::default();
    let sync_handing_off = handing_off.clone();
    let (term_refused, mut term_refusals) = ::tokio::sync::mpsc::unbounded_channel();
    let sync_refused = term_refused.clone();
    let applied = crate::term::Applied::default();
    let sync_applied = applied.clone();
    let (stateful_actor, stateful_mailbox) = Stateful::new(
        context.child("stateful"),
        StatefulConfig {
            application,
            strategy: verification_strategy.clone(),
            db_config: ordered_config(
                native::state_config(PARTITION_PREFIX, page_cache.clone()),
                executor.clone(),
            )
            .recover_from_marshal()
            .with_sync_handoff(move |anchor| {
                let running = sync_handing_off.enter();
                async move {
                    let _running = running;
                    let selected = sync_marshal
                        .get_block(Identifier::Height(anchor.height))
                        .await
                        .ok_or_else(|| "missing synchronized history anchor".to_string())?;
                    if selected.digest() != anchor.digest
                        || selected.inner().context.round != anchor.round
                    {
                        return Err("synchronized history anchor mismatch".into());
                    }
                    let selected = selected.inner();
                    // A snapshot does not pass through execution, so the term of
                    // the block it is taken at is checked here.
                    if !sync_term.admits(selected.height, selected.term) {
                        let _ = sync_refused.send(crate::TermRefusal::LowerTerm {
                            height: selected.height,
                            term: selected.term,
                            held: sync_term.term(),
                        });
                        return std::future::pending().await;
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
                    if let Err(error) = snapshot_history
                        .recover(&mut client, &peers, selected)
                        .await
                    {
                        let error = format!("{error:#}");
                        // The history this device kept is not an ancestor of the
                        // block it synchronized to: it left the deployment's
                        // history below a cut it never learned of.
                        if error.contains(crate::history::DISCONNECTED) {
                            let _ = sync_refused.send(crate::TermRefusal::Diverged {
                                height: selected.height,
                            });
                            return std::future::pending().await;
                        }
                        return Err(error);
                    }
                    sync_applied.seed(selected.height, selected.digest());
                    sync_status.set_snapshot_revision(anchor.height.get());
                    sync_term.observe(selected.height, selected.term);
                    sync_status.record_finalized(
                        selected.height,
                        selected.context.round.epoch().get(),
                        selected.context.round.view().get(),
                    );
                    Ok(())
                }
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

    let (application, application_ready) = crate::ready_application::ReadyApplication::new(
        crate::idle_pacing::IdlePacing::new(
            reshare::Application::new(
                stateful_mailbox.clone(),
                reshare_mailbox.clone(),
                blocks_per_epoch,
            ),
            mempool.clone(),
            solo_pacing.map_or(Duration::ZERO, |pacing| pacing.idle),
            {
                let index = block_index.clone();
                move || index.head_block_number()
            },
        ),
        hold.clone(),
        wake.clone(),
    );
    #[cfg(feature = "fault-injection")]
    let application = application.with_stall(config.data_dir.clone());
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
            manager,
            provider: provider.for_consensus(),
            marshal: marshal.clone(),
            application: deferred,
            strategy: Sequential,
            simplex: orchestrator::SimplexConfig {
                elector: crate::term_elector::term_elector(genesis.simplex),
                mailbox_size: NZUsize!(3),
                replay_buffer: IO_BUFFER_SIZE,
                write_buffer: IO_BUFFER_SIZE,
                page_cache: page_cache.clone(),
                leader_timeout,
                certification_timeout,
                timeout_retry,
                fetch_timeout: commonware_utils::NZDuration!(Duration::from_secs(2)),
                fetch_retry_delay: Duration::from_millis(100),
                view_retention: ViewDelta::new(10),
                skip: SkipPolicy::Enabled {
                    timeout: skip_timeout,
                    budget: SkipBudget::Participants,
                },
                forward: ForwardPolicy::Disabled,
                track_historical_votes: false,
            },
            gate,
            state_sync: consensus_start,
            blocks_per_epoch,
            mailbox_size: MAILBOX_SIZE,
            // A backup journals apart, so it leaves the votes of the
            // validator this device may have been untouched.
            partition_prefix: format!(
                "{PARTITION_PREFIX}{}",
                crate::term::Role::of(is_backup).journals()
            ),
        },
    );
    let certificate_network = (
        certificate_network.0,
        if is_backup {
            let marshal = marshal.clone();
            crate::epoch_replay::EpochReplay::keeping(
                certificate_network.1,
                FixedEpocher::new(blocks_per_epoch),
                Arc::new(move || {
                    let marshal = marshal.clone();
                    Box::pin(async move {
                        marshal
                            .get_processed()
                            .await
                            .map(|processed| processed.height().get())
                    })
                }),
            )
        } else {
            crate::epoch_replay::EpochReplay::passing(certificate_network.1)
        },
    );
    let vote_network = (
        vote_network.0,
        crate::epoch_replay::EpochReplay::passing(vote_network.1),
    );
    let resolver_network = (
        resolver_network.0,
        crate::epoch_replay::EpochReplay::passing(resolver_network.1),
    );
    let orchestrator_handle =
        orchestrator_actor.start(vote_network, certificate_network, resolver_network);

    let term_reporter = crate::term::TermReporter::new(
        crate::finalization_diagnostics::Reporter::new(stateful_mailbox.clone()),
        term.clone(),
        applied.clone(),
        term_refused,
    );
    let reporters = Reporters::from((
        term_reporter,
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
                recovered.inner(),
                &block_index,
                &light_block_index,
                &finalization_lookup,
            )
            .await?;
        node_state.record_finalized(
            recovered.inner().height,
            recovered.inner().context.round.epoch().get(),
            recovered.inner().context.round.view().get(),
        );
        term.observe(recovered.inner().height, recovered.inner().term);
        if recovered.inner().height == recovered_height.get() {
            applied.seed(recovered_height.get(), recovered.digest());
        }
        if !is_backup {
            // A device taking the deployment over starts on the cut. Seating
            // refused a start away from it before clearing anything; a block
            // above it, or its certificate, found here arrived from the device
            // being replaced since, and the takeover is abandoned: its
            // certificate would void a block this device already holds.
            if let Some(certificate) = term_record.taking_over.take() {
                let cut = certificate.change.cut;
                let above = crate::term::archived(marshal.clone(), cut.height + 1).await;
                if above != crate::term::Archived::Nothing || recovered.inner().height != cut.height
                {
                    term_record.store(&config.data_dir)?;
                    return Err(crate::TermRefusal::NotAtCut {
                        head: recovered
                            .inner()
                            .height
                            .max(cut.height + u64::from(above != crate::term::Archived::Nothing)),
                        cut: cut.height,
                    }
                    .into());
                }
                term_record.certificate = Some(certificate);
                term_record.handed_over = None;
                term_record.followed = false;
                term_record.store(&config.data_dir)?;
            }
            if let Some(certificate) = &term_record.certificate {
                term.raise(certificate.change.term, certificate.change.cut.height);
            }
            // A validator builds in the term it holds. Blocks of a later term
            // mean another device was certified since, and this one must follow it.
            if recovered.inner().term > term.term() {
                return Err(crate::TermRefusal::Behind {
                    seen: recovered.inner().term,
                    held: term.term(),
                }
                .into());
            }
            if recovered.inner().height > 0 {
                wake.seed(recovered.inner().timestamp);
            }
        }
    }
    if let Some(certificate) = &term_record.certificate {
        node_state.set_term_certificate(certificate.clone());
        if let Some(seat) = &seat {
            *seat.view.certificate.write() = Some(certificate.clone());
        }
    }
    // The stall clock starts after the history scan, which finalizes nothing
    // however long it runs, and before the stateful actor, whose state-sync
    // handoff can itself stall and must stay recoverable.
    if config.watchdog_stall_seconds > 0 {
        let stall = Duration::from_secs(config.watchdog_stall_seconds);
        let watchdog_state = node_state.clone();
        let has_durable_history = history.head_height() > 0;
        // A backup can only stall while a peer is there to follow.
        let needed_peers = if is_backup {
            1
        } else {
            crate::watchdog::peers_for_quorum(peers.participants.len())
        };
        state_resolver_handles.push(context.child("watchdog").spawn(move |_| async move {
            crate::run_watchdog(
                watchdog_state,
                stall,
                has_durable_history,
                needed_peers,
                watchdog,
            )
            .await;
        }));
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
        let mut refresh = crate::snapshot_refresh::FloorRefresh::new(
            Duration::from_secs(snapshot.floor_stall_seconds),
            handing_off,
        );
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
                Some(refusal) = term_refusals.recv() => {
                    return Err(crate::term::resync_after(&data_dir, refusal));
                }
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
            Some(refusal) = term_refusals.recv() => {
                return Err(crate::term::resync_after(&data_dir, refusal));
            }
        }
    };
    let native_databases = databases.native_databases();
    {
        // Hold the module read lock through publication so finalization cannot
        // advance nonces between loading them and enabling admission.
        let recovered_modules = modules.read().expect("module state lock poisoned");
        let mut admission = MempoolValidator::new(ExecutionConfig::new(chain_id))
            .with_committed_modules(modules.clone());
        admission.reset(recovered_modules.nonces.clone());
        let _ = validator.set(::tokio::sync::Mutex::new(Admission::new(admission)));
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
    // A backup builds no block, so it admits nothing it would have to hold.
    let tx_submit: TxSubmitCallback = if is_backup {
        state_resolver_handles.push(crate::tx_gossip::spawn_tx_discard(
            context.child("tx_receiver"),
            mempool_receiver,
        ));
        Arc::new(|_| Box::pin(async { Err(vera_jsonrpc::TxSubmitError::Backup) }))
    } else {
        state_resolver_handles.push(spawn_tx_receiver(
            context.child("tx_receiver"),
            mempool_receiver,
            mempool.clone(),
            validator.clone(),
            chain_id,
        ));
        Arc::new(move |bytes| {
            let gossip = gossip.clone();
            Box::pin(async move { gossip.submit(bytes).await })
        })
    };
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
                            crate::history::rpc_error(&error, vera_jsonrpc::RpcError::StateError)
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
                execution.block.id().0,
                execution.gas_limit,
                &execution.receipts,
                gas_used,
            );
            if let vera_indexer::IndexQuery::Submission { hash, .. } = query
                && index.get_receipt(&hash).is_none()
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
        execution_config,
        gas_limit,
        modules.clone(),
    );
    if crate::diagnostics::enabled() {
        let history = history.clone();
        let index = block_index.clone();
        let proofs = light_block_index.clone();
        state_resolver_handles.push(
            context
                .child("diagnostics")
                .spawn(move |context| crate::diagnostics::run(context, history, index, proofs)),
        );
    }

    if let Some(seat) = seat {
        let probe = switching.as_ref().map(|switching| crate::term::Probe {
            signer: switching.device_key.signer(),
            validator: peers.participants[0].clone(),
            max_peers: max_peers_per_set,
            rate: channel_rate,
            timeout: switching.answer_timeout,
        });
        let parts = crate::term::Parts {
            seat,
            record: term_record,
            data_dir: config.data_dir.clone(),
            switching,
            backup: is_backup,
            genesis_id: genesis_block.id().0,
            hold,
            index: block_index.clone(),
            finalized: {
                let marshal = marshal.clone();
                Arc::new(move |height| {
                    let marshal = marshal.clone();
                    Box::pin(crate::term::archived(marshal, height))
                })
            },
            blocks: {
                let history = history.clone();
                Arc::new(move |height| Ok(history.stored_block(height)?.map(|block| block.id().0)))
            },
            history_floor: {
                let history = history.clone();
                Arc::new(move || history.floor_height())
            },
            modules: modules.clone(),
            status: node_state.clone(),
            network: term_network,
            probe,
            gate: wake.clone(),
        };
        state_resolver_handles.push(
            context
                .child("term")
                .spawn(move |context| crate::term::run(context, parts)),
        );
    }

    let stored = crate::replay::stored_tip(marshal.clone()).await;
    ::tokio::select! {
        biased;
        result = &mut startup_actors => {
            anyhow::bail!("validator actor stopped during startup: {result:?}");
        }
        Some(refusal) = term_refusals.recv() => {
            return Err(crate::term::resync_after(&data_dir, refusal));
        }
        () = crate::replay::replayed(&block_index, stored, crate::replay::LIMIT) => {}
    }

    let rpc_server = RpcServer::with_state_provider(node_state, rpc_addr, state_provider)
        .with_max_connections(config.rpc.max_connections.get())
        .with_tx_submit(tx_submit)
        .with_headers_subscription(headers_tx)
        .with_vera_index_and_modules(block_index, modules.clone())
        .with_vera_native_modules(native_databases, modules)
        .with_vera_archive(archive)
        .with_vera_receipt_proof_lookup({
            let history = history.clone();
            let epochs = light_block_index.clone();
            Arc::new(move |hash, after| {
                history
                    .receipt_proof(hash, after, &epochs)
                    .map_err(|error| {
                        crate::history::rpc_error(&error, vera_jsonrpc::RpcError::Internal)
                    })
            })
        })
        .with_vera_ancestry_proof_lookup({
            let history = history.clone();
            Arc::new(move |ancestor, height| {
                history
                    .ancestry_proof(ancestor, height)
                    .map_err(|error| crate::history::ancestry_rpc_error(&error))
            })
        })
        .with_vera_light_block_lookup({
            let epochs = light_block_index.clone();
            Arc::new(move |height| {
                history
                    .certified_light_block(height, &epochs)
                    .map_err(|error| {
                        crate::history::rpc_error(&error, vera_jsonrpc::RpcError::Internal)
                    })
            })
        })
        .with_vera_light_block_index(light_block_index);
    let local = match rpc {
        RpcMode::Network(listener) => {
            let (rpc_handle, local) = rpc_server.start_with_local(listener)?;
            let rpc_addr = rpc_handle.local_addr();
            context.child("rpc").spawn(move |_| async move {
                rpc_handle.stopped().await;
                error!("RPC server stopped unexpectedly");
            });
            info!(validator_index, %rpc_addr, "vera validator started");
            local
        }
        RpcMode::Local => {
            info!(
                validator_index,
                "vera validator started without an RPC listener"
            );
            rpc_server.into_local()?
        }
    };
    if let Some(ready) = ready {
        // A host that stopped waiting no longer needs the method table.
        let _ = ready.send(local);
    }

    ::tokio::select! {
        result = &mut startup_actors => result,
        result = Handle::select(state_resolver_handles) => result,
        Some(refusal) = term_refusals.recv() => {
            return Err(crate::term::resync_after(&data_dir, refusal));
        }
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
        max_outstanding_requests: std::num::NonZeroUsize::new(
            crate::sizing::TRANSFER_REQUESTS.get() as usize,
        )
        .unwrap(),
    }
}

pub(crate) fn archive_config<C>(
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
