# Commonware 2026.9.0 clean break

Date: 2026-09-04. Tracking issue: see the stack issue linked from #23.

## Goal

Move vera.rs from commonware 2026.2.0 to 2026.9.0 in one clean break, replace the
kora-derived consensus and storage wrappers with commonware's `glue` crate, and
switch consensus from ed25519 multisig to BLS12-381 threshold signing with
commonware's on-chain DKG and per-epoch resharing. Validator membership comes
from the ValidatorRegistry precompile. Every existing vera-e2e test keeps passing
at the end of the stack, with assertions updated where the wire shape changes.

## Non-goals

- Data migration or mixed-version clusters. There are no users. Data dirs are
  throwaway.
- Preserving the kora crate layout for its own sake.
- State sync and fresh-node probe. Follow-up issue.
- Fee and economics work (#57, #58, #71, #72).

## Why BLS threshold plus glue DKG

Issue #75 chose ed25519 multisig to avoid DKG complexity and then stalled on the
"Muxer gap": no Simplex engine is ever started for epoch 1. `glue::dkg::orchestrator`
closes exactly that gap, but it requires blocks to implement `ReshareBlock` and
carry BLS `EpochInfo`. Taking it gives us per-epoch engines, DKG, resharing, a
real VRF for prevrandao, one group key per epoch for light clients (#79, #80),
and the state-sync plumbing, all maintained upstream.

## Target architecture

```
verad validator
  |
  vera-node (new): assembles the commonware actors
    authenticated discovery p2p  <- glue::dkg::network::Manager
    marshal (standard, Deferred)
    glue::stateful::Stateful     <- DatabaseSet over the three QMDB partitions
    glue::dkg::orchestrator      <- one simplex engine per epoch
    glue::dkg::reshare           <- dealings + EpochInfo in boundary blocks
    DynamicProvider + Registrar  <- bls12381_threshold::vrf::Scheme per epoch
    RegistryParticipants         <- ParticipantsProvider over ValidatorRegistry
    FileSecretStore              <- DKG shares under data_dir/secrets
  |
  vera-executor / vera-modules / vera-state: unchanged business logic
  vera-jsonrpc: unchanged method names, new certificate shapes
```

Consensus scheme: `simplex::scheme::bls12381_threshold::vrf::Scheme<ed25519::PublicKey, MinSig>`.
Peer identity stays ed25519 (transport handshake). Threshold shares are BLS.

Block: `vera-domain::Block` gains an optional reshare `Payload` and implements
`ReshareBlock`. Encoding must be canonical (9.0 requirement).

Genesis: carries `EpochInfo` for epoch 0 produced by `glue::dkg::bootstrap`.
`verad genesis` runs the bootstrap DKG for the initial validator set and writes
each node's share. The `--seed` derivation path is deleted.

Epoch length: genesis `epoch_length` in blocks, used for both marshal's
`FixedEpocher` and the orchestrator's `blocks_per_epoch`. Marshal retention is
set to at least one epoch.

Validator registry: `consensusPubkey` becomes the ed25519 peer key (32 bytes,
unchanged ABI type). BLS shares are dealt to whoever is in the set, so the
registry never needs to hold BLS keys. `RegistryParticipants::participants(epoch)`
reads the active set from finalized state at the height the orchestrator asks
for, deterministically.

Randomness: prevrandao is the threshold VRF seed of the parent round.

Light blocks: `LightBlock` carries the BLS threshold certificate and the epoch's
group public key. `verify_light_block` verifies one aggregate signature.
`GossipHeader.signature` becomes the 96-byte MinSig signature.

Transaction forwarding: forward to all validators. Leader prediction is deleted.

## Test harness

`vera-harness` lives in sourcenetwork/backbone and derives ed25519 keys from
`--seed`. It is vendored into `crates/vera-harness` in the first stack PR so the
stack is self-contained, then changed in place as the shapes change. backbone
is untouched.

## PR stack

Every PR keeps `cargo check --workspace`, clippy, and fmt green. The canonical
e2e is red between PR 1 and PR 5 by design and green from PR 5 onward. All nine
e2e tests are green at PR 10.

| # | Branch | Content | Gate |
|---|--------|---------|------|
| 1 | `stack/01-delete-dead-code` | Vendor vera-harness. Delete `ProductionRunner`, `LegacyNodeService`, `ConsensusConfig::build_validator_set`, `NetworkTransportProvider`, `TransportBundle`, `NetworkControl`, commonware-stream pin. This spec. | full, all e2e |
| 2 | `stack/02-demolition` | Remove vera-simplex, vera-marshal, vera-service, vera-transport, vera-runner, vera-reporters, the seed tracker in vera-consensus, vera-overlay, vera-qmdb-ledger. `verad validator` and `devnet` return an error. Still on 2026.2.0. | check, clippy, unit tests |
| 3 | `stack/03-commonware-2026-9` | Bump pins to 2026.9.0, add commonware-glue. Fix vera-domain, vera-backend, vera-config, vera-crypto, vera-jsonrpc, vera-indexer, vera-harness. | check, clippy, unit tests |
| 4 | `stack/04-reshare-block` | `Block` implements `ReshareBlock`, canonical encoding tests, genesis `EpochInfo`. | unit tests |
| 5 | `stack/05-stateful` | Additive: `VeraStateSet` over the QMDB partitions, `BatchState` as the executor's `StateDb` over pending batches, per-partition `DbTargets` in the block, and the `vera-app` crate with the glue `Application` around `VeraExecutor`. The old snapshot path stays until PR 6 switches the node over. | tokio-runtime tests |
| 6 | `stack/06-vera-node` | New vera-node crate: full actor assembly, BLS threshold scheme, static participants from genesis, file secret store, tx forwarding to all validators. `verad validator`, `devnet`, and `testnet` wired; the trusted-dealer bootstrap lives in vera-node and vera-harness reuses it. Deletes vera-ledger, vera-qmdb-ledger, vera-handlers, and the old per-partition stores. Peer state sync is stubbed (#99). | canonical e2e green |
| 7 | `stack/07-registry-participants` | `RegistryParticipants`. Delete validator-change detection. `validator_epoch_transition` e2e rewritten to assert the engine actually enters the next epoch. Closes #75. | epoch e2e green |
| 8 | `stack/08-vrf-light-blocks` | Prevrandao from VRF. `LightBlock`, `GossipHeader`, vera_api certificate endpoints on BLS. `light_client` and `gossip_headers` e2e updated. | those e2e green |
| 9 | `stack/09-tx-forwarding` | Forward to all validators, delete leader prediction and view tracker. `node_restart` e2e green. | all e2e green |
| 10 | `stack/10-docs` | CLAUDE.md crate table and architecture, vera-e2e README, remove kora READMEs. | all e2e green |

Independent of the stack, against main:

- `chore/evm-deps`: revm 43, alloy-evm 0.39, alloy 1.7, jsonrpsee 0.26.
- `chore/repin-defradb`: defradb.rs main. Coordinated with the on-chain TTU thread.

## e2e contract changes

Surfaces the tests pin today and what changes:

| Surface | Today | After |
|---------|-------|-------|
| `GossipHeader.signature` | 64-byte array | 96-byte array |
| `LightBlock` | `signer_indices`, per-validator `signatures`, `validators` | `certificate`, `group_public_key`, `epoch` |
| `vera_nodeStatus.currentView` | Finalized view mislabeled as current | null until the active engine exposes entered-view telemetry; finalized height/epoch/view are explicit fields |
| `vera_nodeStatus.backfilling` | marshal backfill flag | unchanged |
| log `entered epoch` | EpochManager | orchestrator start of epoch N |
| log `validator set change detected` | FinalizedReporter | deleted; test asserts `entered epoch` count instead |
| `validator.key` | ed25519 seed file | unchanged, plus `secrets/` for BLS shares |
| `peers.json` `participants` | ed25519 hex keys | unchanged |
| `verad validator --seed` | derives all keys | deleted; harness writes keys and genesis `EpochInfo` |
| registry `consensusPubkey` | arbitrary bytes32 | ed25519 peer key |

Everything else the suite pins (RPC method names, precompile addresses, receipt
shapes, ABI events, config keys, log line format for built and verified blocks,
the ERROR whitelist) is unchanged.

## Deleted

| What | Approx lines |
|------|--------------|
| Dead code (PR 1) | 900 |
| Kora infra wrappers (PR 2) | 8,000 |
| Typestate and overlay layer (PR 5) | 1,900 |
| Leader prediction, reporters, epoch manager | 2,200 |

## Follow-up issues

- State sync and fresh-node probe through glue (#99): glue's p2p resolver only serves fixed-value QMDB operations.
- Stable-leader term length as a genesis parameter.
- Minimum validator count enforced in the registry.
- Light client cross-epoch verification on `EpochInfo` chains (#80).
