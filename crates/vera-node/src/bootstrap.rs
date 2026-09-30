//! Epoch-0 DKG bootstrap and trusted setup for local test networks.

use std::{num::NonZeroU64, path::PathBuf};

use commonware_codec::Encode as _;
use commonware_consensus::types::Epoch;
use commonware_cryptography::ChaCha20Poly1305;
use commonware_cryptography::{
    Signer as _,
    bls12381::{
        dkg::feldman_desmedt::{Output, deal},
        primitives::{group::Share, variant::MinSig},
    },
};
use commonware_glue::dkg::{
    bootstrap,
    types::{EpochInfo, EpochOutcome},
};
use commonware_p2p::{Ingress, authenticated::discovery};
use commonware_parallel::Sequential;
use commonware_runtime::{Supervisor as _, tokio};
use commonware_stream::{
    cups::{self, Cups},
    sake::{self, Sake},
};
use commonware_utils::{
    N3f1, NZU64, NZUsize, TestRng,
    ordered::{Map, Set},
    sequence::Unit,
};
use vera_config::NodeConfig;
use vera_domain::PublicKey;
use vera_genesis::VeraGenesis;

use crate::{
    BACKFILL_CHANNEL, BROADCAST_CHANNEL, CERTIFICATE_CHANNEL, DKG_CHANNEL, FileSecretStore,
    IO_BUFFER_SIZE, MAILBOX_SIZE, MAX_MESSAGE_SIZE, MAX_PARTICIPANTS, MAX_SUPPORTED_MODE,
    MESSAGE_RATE, NAMESPACE, P2P_SUFFIX, PAGE_CACHE_SIZE, PAGE_SIZE, PeerSet, RESOLVER_CHANNEL,
    REVEAL, SHARING_MODE, VOTE_CHANNEL,
};

/// Epoch-0 artifact carried by the genesis block.
pub type GenesisEpochInfo = EpochInfo<MinSig, PublicKey, Unit>;

/// Inputs for the distributed epoch-0 DKG ceremony.
#[derive(Clone, Debug)]
pub struct BootstrapSettings {
    /// Node config containing the validator identity and network addresses.
    pub config: NodeConfig,
    /// Genesis document that receives the completed epoch artifact.
    pub genesis: VeraGenesis,
    /// Validators participating in the ceremony.
    pub peers: PeerSet,
    /// Secret store that receives this validator's DKG share.
    pub secrets_path: PathBuf,
}

/// Run Commonware's one-shot bootstrap DKG and persist the local result.
pub async fn run_bootstrap(
    context: tokio::Context,
    mut settings: BootstrapSettings,
) -> anyhow::Result<GenesisEpochInfo> {
    let signing_key = settings.config.validator_key()?;
    let local = signing_key.public_key();
    let participants = Set::from_iter_dedup(settings.peers.participants.iter().cloned());
    if participants.is_empty() {
        anyhow::bail!("bootstrap DKG requires at least one participant");
    }
    if participants.position(&local).is_none() {
        anyhow::bail!("validator key is not listed in peers.json");
    }

    let listen = settings.config.network.listen_addr.parse()?;
    let dial = settings
        .config
        .network
        .dialable_addr
        .as_deref()
        .map_or(Ok(listen), str::parse)?;
    let bootstrappers = settings
        .peers
        .bootstrappers
        .iter()
        .filter(|(key, _)| *key != local)
        .map(|(key, address)| (key.clone(), Ingress::Socket(*address)))
        .collect();
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
        NZUsize!(MAX_PARTICIPANTS.get() as usize),
        MAX_MESSAGE_SIZE,
    );
    p2p_config.mailbox_size = MAILBOX_SIZE;
    let (mut p2p, oracle) = discovery::Network::new(context.child("network"), p2p_config);
    let votes = p2p.register(VOTE_CHANNEL, MESSAGE_RATE);
    let certificates = p2p.register(CERTIFICATE_CHANNEL, MESSAGE_RATE);
    let resolver = p2p.register(RESOLVER_CHANNEL, MESSAGE_RATE);
    let backfill = p2p.register(BACKFILL_CHANNEL, MESSAGE_RATE);
    let broadcast = p2p.register(BROADCAST_CHANNEL, MESSAGE_RATE);
    let dkg = p2p.register(DKG_CHANNEL, MESSAGE_RATE);

    let store = FileSecretStore::load(&settings.secrets_path)?;
    let blocks_per_epoch = NonZeroU64::new(settings.genesis.blocks_per_epoch)
        .ok_or_else(|| anyhow::anyhow!("genesis blocks_per_epoch must be non-zero"))?;
    let engine = bootstrap::Engine::<_, MinSig, _, _, _, _, _>::new(
        context.child("bootstrap"),
        bootstrap::Config {
            signer: signing_key,
            manager: oracle.clone(),
            blocker: oracle,
            secret_store: store,
            strategy: Sequential,
            namespace: NAMESPACE,
            sharing_mode: SHARING_MODE,
            reveal: REVEAL,
            max_supported_mode: MAX_SUPPORTED_MODE,
            partition_prefix: "bootstrap".to_owned(),
            page_cache: commonware_runtime::buffer::paged::CacheRef::from_pooler(
                &context,
                PAGE_SIZE,
                PAGE_CACHE_SIZE,
            ),
            write_buffer: IO_BUFFER_SIZE,
            replay_buffer: IO_BUFFER_SIZE,
            mailbox_size: MAILBOX_SIZE,
            muxer_size: 128,
            items_per_section: NZU64!(256),
            participants: participants.clone(),
            directory: Unit,
            blocks_per_epoch,
        },
    );

    let p2p_handle = p2p.start();
    let (engine_handle, completion) =
        engine.start(votes, certificates, resolver, backfill, broadcast, dkg);
    let result = completion
        .await
        .map_err(|_| anyhow::anyhow!("bootstrap DKG completion channel closed"))?;
    engine_handle.abort();
    p2p_handle.abort();

    let mut info = result
        .info
        .ok_or_else(|| anyhow::anyhow!("bootstrap DKG failed"))?;
    info.outcome = EpochOutcome::Success;
    info.next_players = participants;
    settings.genesis.epoch_info = Some(epoch_info_hex(&info));
    let genesis_path = settings.config.data_dir.join("genesis.json");
    std::fs::write(
        genesis_path,
        serde_json::to_string_pretty(&settings.genesis)?,
    )?;
    Ok(info)
}

/// Deal an epoch-0 sharing among `participants` deterministically from `seed`.
pub fn trusted_setup(
    seed: u64,
    participants: impl IntoIterator<Item = PublicKey>,
) -> anyhow::Result<(GenesisEpochInfo, Map<PublicKey, Share>)> {
    let players: Set<PublicKey> = Set::from_iter_dedup(participants);
    let (output, shares): (Output<MinSig, PublicKey>, Map<PublicKey, Share>) =
        deal::<MinSig, _, N3f1>(TestRng::new(seed), SHARING_MODE, players.clone())
            .map_err(|e| anyhow::anyhow!("trusted deal failed: {e:?}"))?;
    let info = EpochInfo {
        outcome: EpochOutcome::Success,
        epoch: Epoch::zero(),
        output,
        players: players.clone(),
        next_players: players,
        directory: Unit,
    };
    Ok((info, shares))
}

/// Hex encoding of `info` as stored in `genesis.json`.
pub fn epoch_info_hex(info: &GenesisEpochInfo) -> String {
    format!("0x{}", hex::encode(info.encode()))
}
