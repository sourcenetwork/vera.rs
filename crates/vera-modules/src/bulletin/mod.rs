//! Bulletin module — namespace-scoped posts for DKG coordination and messaging.

/// Solidity ABI interface for the Bulletin precompile.
pub mod abi;
mod collections;
/// Bulletin error types.
pub mod error;
/// Key prefixes and builders for Bulletin KV storage.
pub mod keys;
mod storage;
/// Bulletin domain types.
pub mod types;

use error::BulletinError;
use types::{BulletinParams, Collaborator, Namespace, Post};
use vera_acp::{Relationship, Subject};
use vera_identity::Did;

use crate::acp::types::{AccessRequest, Actor, Object, Operation, PolicyCmd, PolicyMarshalingType};
use crate::kv_store::{InMemoryKvStore, ModuleKvStore};
use crate::types::{BlockExecCtx, TxExecCtx};

type Result<T> = std::result::Result<T, BulletinError>;

const BULLETIN_POLICY_YAML: &str = "\
name: bulletin-module-policy
resources:
  - name: namespace
    relations:
      - name: owner
      - name: collaborator
    permissions:
      - name: create_post
        expr: owner + collaborator
";

const MODULE_DID: &str = "did:key:bulletin";

/// Maximum accepted post payload; keeps any single post far below the
/// per-namespace read budget so reads cannot be bricked by one write.
const MAX_POST_PAYLOAD_BYTES: usize = 64 * 1024;

/// Bulletin module.
///
/// Manages namespaces, posts, and collaborator access. Authorization
/// flows through ACP — a lazy policy is created on first namespace
/// registration. Business logic lives here; precompile and native-tx
/// shims are thin wrappers that decode arguments and forward to these methods.
///
/// # ACP integration
///
/// The module lazily creates a single ACP policy on the first
/// `register_namespace` call (stored as `"policy_id"` in the KV store).
/// The policy defines one resource type `namespace` with one relation
/// `collaborator` and one permission `create_post = collaborator`.
///
/// Cross-module calls use direct parameter passing — the caller
/// (application/executor) passes `&mut AcpModule` to methods that
/// need it. Rust's partial borrow rules allow this since modules
/// are disjoint fields in the parent struct.
///
/// | Bulletin method | ACP method | Mutability |
/// |---|---|---|
/// | `register_namespace` | `acp.create_policy()` (first call), `acp.direct_policy_cmd(RegisterObject)` | `&mut AcpModule` |
/// | `create_post` | `acp.query_verify_access_request()` | `&AcpModule` |
/// | `add_collaborator` | `acp.direct_policy_cmd(SetRelationship)` | `&mut AcpModule` |
/// | `remove_collaborator` | `acp.direct_policy_cmd(DeleteRelationship)` | `&mut AcpModule` |
///
/// # KV store layout
///
/// ```text
/// "policy_id"                                          → policy ID string
/// "namespace/" + namespaceId                           → Namespace
/// "collaborator/" + sanitize(namespaceId) + "/" + sanitize(did) → Collaborator
/// "post/" + sanitize(namespaceId) + "/" + sanitize(postId)     → Post
/// "p_bulletin"                                         → BulletinParams
/// ```
///
/// Component encoding escapes `%` and literal `|`, then replaces `/` with `|`.
/// Namespace IDs are always prefixed: user `"ns1"` → stored `"bulletin/ns1"`.
/// Post IDs are deterministic: `hex(sha256(namespaceId + payload))`.
#[derive(Clone, Debug, Default)]
pub struct BulletinModule {
    store: InMemoryKvStore,
}

#[allow(dead_code)]
impl BulletinModule {
    /// Create a new Bulletin module instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read access to the underlying KV store (for serialization).
    pub const fn store(&self) -> &InMemoryKvStore {
        &self.store
    }

    /// Reconstruct from a deserialized store.
    pub const fn from_store(store: InMemoryKvStore) -> Self {
        Self { store }
    }

    // ── Msg handlers ────────────────────────────────────────────────────

    /// Register a new namespace owned by the creator.
    ///
    /// # Flow
    ///
    /// 1. Call `ensure_policy(acp)` — on first call, invokes
    ///    `acp.create_module_policy(BULLETIN_POLICY_YAML,
    ///    PolicyMarshalingType_YAML, "bulletin")` and stores the
    ///    returned policy ID under `"policy_id"` key. Subsequent
    ///    calls read the stored ID.
    /// 2. Compute `namespace_id = "bulletin/" + namespace`.
    /// 3. Read `"namespace/" + namespace_id` — if present, return
    ///    `NamespaceAlreadyExists`.
    /// 4. Resolve `owner_did` from `tx_ctx.signer` via
    ///    `acp.get_actor_did(msg.Creator)` (Go: `GetActorDID`).
    ///    The shim layer pre-resolves this and passes it as `creator`.
    /// 5. Call `acp.module_policy_cmd(policy_cap, RegisterObject(
    ///    Object { resource: "namespace", id: namespace_id }),
    ///    owner_did, signer)` (Go: `ModulePolicyCmdForActorDID` —
    ///    requires both the DID and the original signer address,
    ///    plus a policy capability fetched from the scoped keeper).
    ///    This registers the namespace as an ACP object with the creator
    ///    as owner (granting implicit manager rights over `collaborator`).
    /// 6. Build `Namespace`:
    ///    ```text
    ///    id           = namespace_id
    ///    creator      = tx_ctx.signer
    ///    owner_did    = creator.to_string()
    ///    created_at   = block_ctx.timestamp
    ///    ```
    /// 7. Write namespace to `"namespace/" + namespace_id`.
    /// 8. Return the created `Namespace`.
    ///
    /// # Reads
    /// - `"policy_id"` (ensure_policy check)
    /// - `"namespace/" + namespace_id` (existence check)
    ///
    /// # Writes
    /// - `"policy_id"` (first call only — ensure_policy)
    /// - `"namespace/" + namespace_id`
    /// - ACP via `acp.create_module_policy()` (first call) + `acp.module_policy_cmd(RegisterObject)`
    ///
    /// # Ctx
    /// `block_ctx.timestamp` for created_at, `tx_ctx.signer` for creator.
    /// Go resolves `owner_did` from `msg.Creator` via `GetActorDID` —
    /// vera.rs expects the shim layer to pre-resolve and pass as `creator`.
    ///
    /// # Errors
    /// - `PolicyInitFailed` — ACP policy creation failed
    /// - `NamespaceAlreadyExists` — namespace already registered
    /// - ACP errors from `module_policy_cmd`
    pub fn register_namespace(
        &mut self,
        acp: &mut super::acp::AcpModule,
        block_ctx: &BlockExecCtx,
        tx_ctx: &TxExecCtx,
        creator: &Did,
        namespace: &str,
    ) -> Result<Namespace> {
        validate_namespace(namespace)?;
        let policy_id = self.ensure_policy(acp)?;
        let namespace_id = keys::namespace_id(namespace);

        if self.has_namespace(&namespace_id)? {
            return Err(BulletinError::NamespaceAlreadyExists {
                namespace: namespace.to_string(),
            });
        }

        acp.direct_policy_cmd(
            creator,
            &policy_id,
            PolicyCmd::RegisterObject(Object {
                resource: "namespace".into(),
                id: namespace_id.clone(),
            }),
        )
        .map_err(|e| BulletinError::PolicyInitFailed(e.to_string()))?;

        let ns = Namespace {
            id: namespace_id,
            creator: tx_ctx.signer.clone(),
            owner_did: creator.to_string(),
            created_at: block_ctx.timestamp.clone(),
        };
        self.set_namespace(&ns);
        Ok(ns)
    }

    /// Store a nonempty payload after checking the creator's ACP permission.
    /// Optional proof bytes are preserved for application-level verification.
    #[allow(clippy::too_many_arguments)]
    pub fn create_post(
        &mut self,
        acp: &super::acp::AcpModule,
        _tx_ctx: &TxExecCtx,
        creator: &Did,
        namespace: &str,
        payload: &[u8],
        proof: &[u8],
        _artifact: &str,
    ) -> Result<String> {
        validate_namespace(namespace)?;
        let policy_id = self
            .get_policy_id()?
            .ok_or(BulletinError::PolicyNotInitialized)?;
        let namespace_id = keys::namespace_id(namespace);

        if !self.has_namespace(&namespace_id)? {
            return Err(BulletinError::NamespaceNotFound {
                namespace: namespace.to_string(),
            });
        }

        if payload.len() > MAX_POST_PAYLOAD_BYTES {
            return Err(BulletinError::PostPayloadTooLarge(MAX_POST_PAYLOAD_BYTES));
        }
        if payload.is_empty() {
            return Err(BulletinError::InvalidPostPayload);
        }

        let access_request = AccessRequest {
            operations: vec![Operation {
                object: Object {
                    resource: "namespace".into(),
                    id: namespace_id.clone(),
                },
                permission: "create_post".into(),
            }],
            actor: Actor(creator.clone()),
        };

        let allowed = acp
            .query_verify_access_request(&policy_id, &access_request)
            .map_err(|e| BulletinError::State(e.to_string()))?;

        if !allowed {
            return Err(BulletinError::NotCollaborator {
                namespace: namespace.to_string(),
            });
        }

        let post_id = Self::generate_post_id(&namespace_id, payload);

        if self.get_post(&namespace_id, &post_id)?.is_some() {
            return Err(BulletinError::PostAlreadyExists {
                namespace: namespace.to_string(),
                id: post_id,
            });
        }

        let post = Post {
            id: post_id,
            namespace: namespace_id,
            creator_did: creator.to_string(),
            payload: payload.to_vec(),
            proof: proof.to_vec(),
        };
        self.set_post(&post);
        Ok(post.id)
    }

    /// Add a collaborator to a namespace.
    ///
    /// The `collaborator_did` must be a proper `did:key:zQ3s...` string
    /// matching the format produced by secp256k1 public key recovery.
    /// The caller (precompile shim or native tx shim) is responsible for
    /// passing the DID in the correct format.
    pub fn add_collaborator(
        &mut self,
        acp: &mut super::acp::AcpModule,
        _tx_ctx: &TxExecCtx,
        creator: &Did,
        namespace: &str,
        collaborator_did: &str,
    ) -> Result<String> {
        validate_namespace(namespace)?;
        let policy_id = self
            .get_policy_id()?
            .ok_or(BulletinError::PolicyNotInitialized)?;
        let namespace_id = keys::namespace_id(namespace);

        if !self.has_namespace(&namespace_id)? {
            return Err(BulletinError::NamespaceNotFound {
                namespace: namespace.to_string(),
            });
        }

        if self
            .get_collaborator(&namespace_id, collaborator_did)?
            .is_some()
        {
            return Err(BulletinError::CollaboratorAlreadyExists {
                namespace: namespace.to_string(),
                did: collaborator_did.to_string(),
            });
        }

        let collab_did_parsed = Did::new(collaborator_did)
            .map_err(|e| BulletinError::State(format!("invalid collaborator DID: {}", e)))?;

        acp.direct_policy_cmd(
            creator,
            &policy_id,
            PolicyCmd::SetRelationship(Relationship {
                resource: "namespace".into(),
                object_id: namespace_id.clone(),
                relation: "collaborator".into(),
                subject: Subject::Entity(collab_did_parsed),
            }),
        )
        .map_err(|e| BulletinError::Unauthorized {
            reason: e.to_string(),
        })?;

        let record = Collaborator {
            did: collaborator_did.to_string(),
            namespace: namespace_id,
        };
        self.set_collaborator(&record);
        Ok(collaborator_did.to_string())
    }

    /// Remove a collaborator from a namespace.
    ///
    /// Same DID format requirements as [`add_collaborator`](Self::add_collaborator).
    pub fn remove_collaborator(
        &mut self,
        acp: &mut super::acp::AcpModule,
        _tx_ctx: &TxExecCtx,
        creator: &Did,
        namespace: &str,
        collaborator_did: &str,
    ) -> Result<String> {
        validate_namespace(namespace)?;
        let policy_id = self
            .get_policy_id()?
            .ok_or(BulletinError::PolicyNotInitialized)?;
        let namespace_id = keys::namespace_id(namespace);

        if !self.has_namespace(&namespace_id)? {
            return Err(BulletinError::NamespaceNotFound {
                namespace: namespace.to_string(),
            });
        }

        if self
            .get_collaborator(&namespace_id, collaborator_did)?
            .is_none()
        {
            return Err(BulletinError::CollaboratorNotFound {
                namespace: namespace.to_string(),
                did: collaborator_did.to_string(),
            });
        }

        let collab_did_parsed = Did::new(collaborator_did)
            .map_err(|e| BulletinError::State(format!("invalid collaborator DID: {}", e)))?;

        acp.direct_policy_cmd(
            creator,
            &policy_id,
            PolicyCmd::DeleteRelationship(Relationship {
                resource: "namespace".into(),
                object_id: namespace_id.clone(),
                relation: "collaborator".into(),
                subject: Subject::Entity(collab_did_parsed),
            }),
        )
        .map_err(|e| BulletinError::Unauthorized {
            reason: e.to_string(),
        })?;

        self.delete_collaborator(&namespace_id, collaborator_did);
        Ok(collaborator_did.to_string())
    }

    /// Reject legacy parameter writes without operator approvals.
    pub fn update_params(&mut self, _authority: &Did, _params: BulletinParams) -> Result<()> {
        Err(BulletinError::Unauthorized {
            reason: "operator approvals are required".into(),
        })
    }

    // ── Query handlers ──────────────────────────────────────────────────

    /// Look up a namespace by name.
    ///
    /// # Flow
    ///
    /// 1. Compute `namespace_id = "bulletin/" + namespace`.
    /// 2. Read `"namespace/" + namespace_id`.
    /// 3. Return the `Namespace` or `NamespaceNotFound`.
    ///
    /// # Reads
    /// - `"namespace/" + namespace_id`
    pub fn query_namespace(&self, namespace: &str) -> Result<Namespace> {
        let namespace_id = keys::namespace_id(namespace);
        self.get_namespace(&namespace_id)?
            .ok_or(BulletinError::NamespaceNotFound {
                namespace: namespace.to_string(),
            })
    }

    /// List namespaces within the collection work budget.
    pub fn query_namespaces(&self) -> Result<Vec<Namespace>> {
        self.collect_records(
            keys::NAMESPACE_PREFIX,
            |_| true,
            |record: &Namespace| keys::namespace_key(&record.id),
        )
    }

    /// List namespace collaborators within the collection work budget.
    pub fn query_namespace_collaborators(&self, namespace: &str) -> Result<Vec<Collaborator>> {
        let namespace_id = keys::namespace_id(namespace);
        if !self.has_namespace(&namespace_id)? {
            return Err(BulletinError::NamespaceNotFound {
                namespace: namespace.to_string(),
            });
        }
        self.collect_records(
            &keys::collaborator_prefix(&namespace_id),
            |_| true,
            |record: &Collaborator| keys::collaborator_key(&record.namespace, &record.did),
        )
    }

    /// List namespace posts within the collection work budget.
    pub fn query_namespace_posts(&self, namespace: &str) -> Result<Vec<Post>> {
        let namespace_id = keys::namespace_id(namespace);
        if !self.has_namespace(&namespace_id)? {
            return Err(BulletinError::NamespaceNotFound {
                namespace: namespace.to_string(),
            });
        }
        self.collect_records(
            &keys::post_prefix(&namespace_id),
            |_| true,
            |record: &Post| keys::post_key(&record.namespace, &record.id),
        )
    }

    /// Look up a post by namespace and ID.
    ///
    /// # Flow
    ///
    /// 1. Compute `namespace_id = "bulletin/" + namespace`.
    /// 2. Verify namespace exists — read `"namespace/" + namespace_id`,
    ///    return `NamespaceNotFound` if absent.
    /// 3. Read `"post/" + sanitize(namespace_id) + "/" + sanitize(id)`.
    /// 4. Return the `Post` or `PostNotFound`.
    ///
    /// # Reads
    /// - `"namespace/" + namespace_id`
    /// - `"post/" + sanitize(namespace_id) + "/" + sanitize(id)`
    ///
    /// # Errors
    /// - `NamespaceNotFound` — namespace does not exist
    /// - `PostNotFound` — post not found at that key
    pub fn query_post(&self, namespace: &str, id: &str) -> Result<Post> {
        let namespace_id = keys::namespace_id(namespace);
        if !self.has_namespace(&namespace_id)? {
            return Err(BulletinError::NamespaceNotFound {
                namespace: namespace.to_string(),
            });
        }
        self.get_post(&namespace_id, id)?
            .ok_or(BulletinError::PostNotFound {
                namespace: namespace.to_string(),
                id: id.to_string(),
            })
    }

    /// List posts within the collection work budget.
    pub fn query_posts(&self) -> Result<Vec<Post>> {
        self.collect_records(
            keys::POST_PREFIX,
            |_| true,
            |record: &Post| keys::post_key(&record.namespace, &record.id),
        )
    }

    /// Match namespace post IDs with `*`, within the collection work budget.
    pub fn query_iterate_glob(&self, namespace: &str, glob: &str) -> Result<Vec<Post>> {
        if namespace.is_empty() {
            return Err(BulletinError::InvalidGlob {
                pattern: "empty namespace".to_string(),
            });
        }

        let namespace_id = keys::namespace_id(namespace);
        let scan_prefix = keys::post_prefix(&namespace_id);

        if glob.len() > 4096 {
            return Err(BulletinError::QueryLimit);
        }
        self.collect_records(
            &scan_prefix,
            |post: &Post| glob_match(glob, &post.id),
            |post| keys::post_key(&post.namespace, &post.id),
        )
    }

    /// Query current module parameters.
    ///
    /// # Flow
    ///
    /// 1. Read `"p_bulletin"` from the KV store.
    /// 2. Deserialize and return `BulletinParams`.
    ///    If not set, return `BulletinParams::default()`.
    ///
    /// # Reads
    /// - `"p_bulletin"`
    pub fn query_params(&self) -> Result<BulletinParams> {
        self.get_params()
    }

    // ── Storage access methods ──────────────────────────────────────────
    //
    // Bulletin uses raw Cosmos SDK prefix stores — no raccoondb, no
    // secondary indexes. Three prefix namespaces (`namespace/`,
    // `collaborator/`, `post/`), one singleton (`policy_id`), and one
    // params key (`p_bulletin`).
    //
    // Key sanitization: `/` in component parts is replaced with `|` to
    // prevent path collisions. Reversed on read (`|` → `/`).

    // ── Storage — Policy ID (singleton) ────────────────────────────────

    /// Read the module's ACP policy ID.
    fn get_policy_id(&self) -> Result<Option<String>> {
        self.store
            .get_ref(keys::POLICY_ID_KEY)
            .map(|bytes| {
                let id = std::str::from_utf8(bytes).map_err(|e| {
                    BulletinError::State(format!("invalid bulletin policy ID: {e}"))
                })?;
                if id.is_empty() {
                    return Err(BulletinError::State("empty bulletin policy ID".into()));
                }
                Ok(id.to_owned())
            })
            .transpose()
    }

    /// Write the module's ACP policy ID.
    fn set_policy_id(&mut self, policy_id: &str) {
        self.store
            .put(keys::POLICY_ID_KEY, policy_id.as_bytes().to_vec());
    }

    /// Lazily initialize the module's ACP policy.
    fn ensure_policy(&mut self, acp: &mut super::acp::AcpModule) -> Result<String> {
        if let Some(id) = self.get_policy_id()? {
            return Ok(id);
        }

        let module_did =
            Did::new(MODULE_DID).map_err(|e| BulletinError::PolicyInitFailed(e.to_string()))?;

        let record = acp
            .create_policy(
                &module_did,
                BULLETIN_POLICY_YAML,
                PolicyMarshalingType::ShortYaml,
            )
            .map_err(|e| BulletinError::PolicyInitFailed(e.to_string()))?;

        let policy_id = record.policy.id;
        self.set_policy_id(&policy_id);
        Ok(policy_id)
    }

    // ── Storage — Params ───────────────────────────────────────────────

    fn get_params(&self) -> Result<BulletinParams> {
        self.store.get_ref(keys::PARAMS_KEY).map_or_else(
            || Ok(BulletinParams::default()),
            |bytes| {
                borsh::from_slice(bytes)
                    .map_err(|e| BulletinError::State(format!("invalid bulletin parameters: {e}")))
            },
        )
    }

    fn set_params(&mut self, params: &BulletinParams) -> Result<()> {
        let bytes = borsh::to_vec(params)
            .map_err(|e| BulletinError::State(format!("serialize params: {e}")))?;
        self.store.put(keys::PARAMS_KEY, bytes);
        Ok(())
    }

    // ── Storage — Namespaces ───────────────────────────────────────────

    fn set_namespace(&mut self, namespace: &Namespace) {
        let bytes = borsh::to_vec(namespace).expect("serialize Namespace");
        self.store.put(&keys::namespace_key(&namespace.id), bytes);
    }

    fn get_namespace(&self, namespace_id: &str) -> Result<Option<Namespace>> {
        self.get_record(&keys::namespace_key(namespace_id), |record: &Namespace| {
            keys::namespace_key(&record.id)
        })
    }

    fn has_namespace(&self, namespace_id: &str) -> Result<bool> {
        Ok(self.get_namespace(namespace_id)?.is_some())
    }

    // ── Storage — Collaborators ────────────────────────────────────────

    fn set_collaborator(&mut self, collaborator: &Collaborator) {
        let key = keys::collaborator_key(&collaborator.namespace, &collaborator.did);
        let bytes = borsh::to_vec(collaborator).expect("serialize Collaborator");
        self.store.put(&key, bytes);
    }

    fn get_collaborator(
        &self,
        namespace_id: &str,
        collaborator_did: &str,
    ) -> Result<Option<Collaborator>> {
        self.get_record(
            &keys::collaborator_key(namespace_id, collaborator_did),
            |record: &Collaborator| keys::collaborator_key(&record.namespace, &record.did),
        )
    }

    fn delete_collaborator(&mut self, namespace_id: &str, collaborator_did: &str) {
        self.store
            .delete(&keys::collaborator_key(namespace_id, collaborator_did));
    }

    // ── Storage — Posts ────────────────────────────────────────────────

    fn set_post(&mut self, post: &Post) {
        let key = keys::post_key(&post.namespace, &post.id);
        let bytes = borsh::to_vec(post).expect("serialize Post");
        self.store.put(&key, bytes);
    }

    fn get_post(&self, namespace_id: &str, post_id: &str) -> Result<Option<Post>> {
        self.get_record(&keys::post_key(namespace_id, post_id), |record: &Post| {
            keys::post_key(&record.namespace, &record.id)
        })
    }

    // ── Storage — Utility ──────────────────────────────────────────────

    fn generate_post_id(namespace_id: &str, payload: &[u8]) -> String {
        keys::generate_post_id(namespace_id, payload)
    }
}

/// Simple glob match where `*` matches any sequence of characters including `/`.
fn glob_match(pattern: &str, value: &str) -> bool {
    let Some((prefix, rest)) = pattern.split_once('*') else {
        return pattern == value;
    };
    let Some(value) = value.strip_prefix(prefix) else {
        return false;
    };
    let (middle, suffix) = rest.rsplit_once('*').unwrap_or(("", rest));
    let Some(mut remaining) = value.strip_suffix(suffix) else {
        return false;
    };
    for literal in middle.split('*').filter(|literal| !literal.is_empty()) {
        let Some(position) = remaining.find(literal) else {
            return false;
        };
        remaining = &remaining[position + literal.len()..];
    }
    true
}

const fn validate_namespace(namespace: &str) -> Result<()> {
    if namespace.is_empty() {
        return Err(BulletinError::InvalidNamespace);
    }
    Ok(())
}

#[cfg(test)]
mod glob_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Timestamp;

    #[test]
    fn empty_namespace_writes_leave_bulletin_and_acp_unchanged() {
        for initialized in [false, true] {
            let mut module = BulletinModule::new();
            let mut acp = super::super::acp::AcpModule::new();
            let owner = make_did("did:key:owner");
            let block = make_block_ctx(100, 10);
            let tx = make_tx_ctx(owner.as_str());
            if initialized {
                module
                    .register_namespace(&mut acp, &block, &tx, &owner, "valid")
                    .unwrap();
            }
            let before = (module.store().serialize(), acp.store().serialize());
            assert!(matches!(
                module.register_namespace(&mut acp, &block, &tx, &owner, ""),
                Err(BulletinError::InvalidNamespace)
            ));
            assert!(matches!(
                module.create_post(&acp, &tx, &owner, "", b"payload", b"proof", ""),
                Err(BulletinError::InvalidNamespace)
            ));
            assert!(matches!(
                module.add_collaborator(&mut acp, &tx, &owner, "", owner.as_str()),
                Err(BulletinError::InvalidNamespace)
            ));
            assert!(matches!(
                module.remove_collaborator(&mut acp, &tx, &owner, "", owner.as_str()),
                Err(BulletinError::InvalidNamespace)
            ));
            assert_eq!(
                (module.store().serialize(), acp.store().serialize()),
                before
            );
        }
    }

    fn make_did(s: &str) -> Did {
        Did::new(s).expect("valid did")
    }

    fn make_block_ctx(seconds: u64, height: u64) -> BlockExecCtx {
        BlockExecCtx {
            genesis_id: [0; 32],
            deployment_id: 9001,
            timestamp: Timestamp {
                seconds,
                block_height: height,
            },
        }
    }

    fn make_tx_ctx(signer: &str) -> TxExecCtx {
        TxExecCtx {
            sequence: 0,
            tx_hash: vec![],
            signer: signer.to_string(),
        }
    }

    fn populated_module() -> BulletinModule {
        let mut m = BulletinModule::default();
        let ns = Namespace {
            id: "bulletin/ns1".into(),
            creator: "0xABCD".into(),
            owner_did: "did:key:z6Mkowner".into(),
            created_at: Timestamp {
                seconds: 100,
                block_height: 10,
            },
        };
        m.set_namespace(&ns);

        let post = Post {
            id: "abc123".into(),
            namespace: "bulletin/ns1".into(),
            creator_did: "did:key:z6Mkcreator".into(),
            payload: vec![1, 2, 3],
            proof: vec![4, 5, 6],
        };
        m.set_post(&post);

        let collab = Collaborator {
            did: "did:key:z6Mkcollab".into(),
            namespace: "bulletin/ns1".into(),
        };
        m.set_collaborator(&collab);
        m
    }

    #[test]
    fn unauthenticated_parameter_update_is_rejected() {
        let mut m = BulletinModule::default();
        let did = make_did("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        assert!(m.update_params(&did, BulletinParams {}).is_err());
        let p = m.query_params().unwrap();
        assert_eq!(p, BulletinParams {});
    }

    #[test]
    fn query_namespace_found() {
        let m = populated_module();
        let ns = m.query_namespace("ns1").unwrap();
        assert_eq!(ns.id, "bulletin/ns1");
    }

    #[test]
    fn query_namespace_not_found() {
        let m = populated_module();
        let err = m.query_namespace("missing").unwrap_err();
        assert!(matches!(err, BulletinError::NamespaceNotFound { .. }));
    }

    #[test]
    fn query_namespaces_returns_all() {
        let m = populated_module();
        let list = m.query_namespaces().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "bulletin/ns1");
    }

    #[test]
    fn query_namespace_posts_found() {
        let m = populated_module();
        let posts = m.query_namespace_posts("ns1").unwrap();
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0].id, "abc123");
    }

    #[test]
    fn query_namespace_posts_namespace_not_found() {
        let m = populated_module();
        let err = m.query_namespace_posts("missing").unwrap_err();
        assert!(matches!(err, BulletinError::NamespaceNotFound { .. }));
    }

    #[test]
    fn query_post_found() {
        let m = populated_module();
        let post = m.query_post("ns1", "abc123").unwrap();
        assert_eq!(post.id, "abc123");
    }

    #[test]
    fn query_post_not_found() {
        let m = populated_module();
        let err = m.query_post("ns1", "nope").unwrap_err();
        assert!(matches!(err, BulletinError::PostNotFound { .. }));
    }

    #[test]
    fn query_post_namespace_not_found() {
        let m = populated_module();
        let err = m.query_post("missing", "abc123").unwrap_err();
        assert!(matches!(err, BulletinError::NamespaceNotFound { .. }));
    }

    #[test]
    fn query_posts_returns_all() {
        let m = populated_module();
        let posts = m.query_posts().unwrap();
        assert_eq!(posts.len(), 1);
    }

    #[test]
    fn query_namespace_collaborators_found() {
        let m = populated_module();
        let collabs = m.query_namespace_collaborators("ns1").unwrap();
        assert_eq!(collabs.len(), 1);
        assert_eq!(collabs[0].did, "did:key:z6Mkcollab");
    }

    #[test]
    fn query_namespace_collaborators_namespace_not_found() {
        let m = populated_module();
        let err = m.query_namespace_collaborators("missing").unwrap_err();
        assert!(matches!(err, BulletinError::NamespaceNotFound { .. }));
    }

    #[test]
    fn query_iterate_glob_star_matches_all() {
        let m = populated_module();
        let posts = m.query_iterate_glob("ns1", "*").unwrap();
        assert_eq!(posts.len(), 1);
    }

    #[test]
    fn query_iterate_glob_exact_match() {
        let m = populated_module();
        let posts = m.query_iterate_glob("ns1", "abc123").unwrap();
        assert_eq!(posts.len(), 1);
    }

    #[test]
    fn query_iterate_glob_no_match() {
        let m = populated_module();
        let posts = m.query_iterate_glob("ns1", "zzz*").unwrap();
        assert!(posts.is_empty());
    }

    #[test]
    fn query_iterate_glob_empty_namespace_errors() {
        let m = populated_module();
        let err = m.query_iterate_glob("", "*").unwrap_err();
        assert!(matches!(err, BulletinError::InvalidGlob { .. }));
    }

    #[test]
    fn register_namespace_initializes_policy() {
        let mut m = BulletinModule::default();
        let mut acp = crate::acp::AcpModule::new();
        let block_ctx = make_block_ctx(100, 10);
        let tx_ctx = make_tx_ctx("0xABCD");
        let did = make_did("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        let namespace = m
            .register_namespace(&mut acp, &block_ctx, &tx_ctx, &did, "ns1")
            .unwrap();
        assert!(m.get_policy_id().unwrap().is_some());
        assert_eq!(m.query_namespace("ns1").unwrap(), namespace);
        assert_eq!(namespace.owner_did, did.to_string());
    }

    #[test]
    fn create_post_empty_payload_fails() {
        let mut m = populated_module();
        m.set_policy_id("some-policy-id");
        let acp = crate::acp::AcpModule::new();
        let tx_ctx = make_tx_ctx("0xABCD");
        let did = make_did("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        let err = m
            .create_post(&acp, &tx_ctx, &did, "ns1", &[], b"proof", "artifact")
            .unwrap_err();
        assert!(matches!(err, BulletinError::InvalidPostPayload));
    }

    #[test]
    fn create_post_accepts_payload_without_optional_proof() {
        let mut m = BulletinModule::default();
        let mut acp = crate::acp::AcpModule::new();
        let tx_ctx = make_tx_ctx("0xABCD");
        let block_ctx = make_block_ctx(100, 10);
        let did = make_did("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        m.register_namespace(&mut acp, &block_ctx, &tx_ctx, &did, "ns1")
            .unwrap();
        m.create_post(&acp, &tx_ctx, &did, "ns1", b"payload", &[], "artifact")
            .unwrap();
        let posts = m.query_namespace_posts("ns1").unwrap();
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0].payload, b"payload");
        assert!(posts[0].proof.is_empty());
        let stranger = make_did("did:key:z6MkmjY8GnV5iJjM2BXSVn4MoDbZZbLffKHsygxC4BLd5v8P");
        assert!(matches!(
            m.create_post(&acp, &tx_ctx, &stranger, "ns1", b"other", &[], "artifact"),
            Err(BulletinError::NotCollaborator { .. })
        ));
        assert_eq!(m.query_namespace_posts("ns1").unwrap().len(), 1);
    }

    #[test]
    fn returned_namespace_ids_support_collaboration_and_restored_revocation() {
        let mut module = BulletinModule::new();
        let mut acp = crate::acp::AcpModule::new();
        let owner = make_did("did:key:owner");
        let writer = make_did("did:key:writer");
        let stranger = make_did("did:key:stranger");
        let tx = make_tx_ctx(owner.as_str());
        let block = make_block_ctx(100, 10);
        let ns = module
            .register_namespace(&mut acp, &block, &tx, &owner, "group/notes")
            .unwrap();
        assert_eq!(module.query_namespace(&ns.id).unwrap(), ns);
        let before = (module.store().serialize(), acp.store().serialize());
        assert!(matches!(
            module.register_namespace(&mut acp, &block, &tx, &owner, &ns.id),
            Err(BulletinError::NamespaceAlreadyExists { .. })
        ));
        assert!(matches!(
            module.add_collaborator(&mut acp, &tx, &stranger, &ns.id, writer.as_str()),
            Err(BulletinError::Unauthorized { .. })
        ));
        assert_eq!(
            (module.store().serialize(), acp.store().serialize()),
            before
        );
        module
            .add_collaborator(&mut acp, &tx, &owner, &ns.id, writer.as_str())
            .unwrap();
        let before = (module.store().serialize(), acp.store().serialize());
        assert!(matches!(
            module.add_collaborator(&mut acp, &tx, &owner, "group/notes", writer.as_str()),
            Err(BulletinError::CollaboratorAlreadyExists { .. })
        ));
        assert!(matches!(
            module.remove_collaborator(&mut acp, &tx, &stranger, &ns.id, writer.as_str()),
            Err(BulletinError::Unauthorized { .. })
        ));
        assert_eq!(
            (module.store().serialize(), acp.store().serialize()),
            before
        );
        let id = module
            .create_post(&acp, &tx, &writer, &ns.id, b"first", b"proof", "")
            .unwrap();
        assert_eq!(
            module.query_post(&ns.id, &id).unwrap(),
            module.query_post("group/notes", &id).unwrap()
        );
        assert_eq!(
            module.query_namespace_posts(&ns.id).unwrap(),
            module.query_iterate_glob("group/notes", "*").unwrap()
        );
        assert_eq!(
            module.query_namespace_collaborators(&ns.id).unwrap().len(),
            1
        );
        module
            .remove_collaborator(&mut acp, &tx, &owner, &ns.id, writer.as_str())
            .unwrap();
        module = BulletinModule::from_store(
            crate::kv_store::InMemoryKvStore::deserialize(&module.store().serialize()).unwrap(),
        );
        acp = crate::acp::AcpModule::from_store(
            crate::kv_store::InMemoryKvStore::deserialize(&acp.store().serialize()).unwrap(),
        );
        let before = (module.store().serialize(), acp.store().serialize());
        assert!(matches!(
            module.create_post(&acp, &tx, &writer, &ns.id, b"second", &[], ""),
            Err(BulletinError::NotCollaborator { .. })
        ));
        assert!(matches!(
            module.remove_collaborator(&mut acp, &tx, &owner, &ns.id, writer.as_str()),
            Err(BulletinError::CollaboratorNotFound { .. })
        ));
        assert_eq!(
            (module.store().serialize(), acp.store().serialize()),
            before
        );
        assert!(
            module
                .query_namespace_collaborators(&ns.id)
                .unwrap()
                .is_empty()
        );
        assert_eq!(module.query_post(&ns.id, &id).unwrap().payload, b"first");
        module
            .create_post(&acp, &tx, &owner, &ns.id, b"second", &[], "")
            .unwrap();
    }

    #[test]
    fn create_post_namespace_not_found() {
        let mut m = BulletinModule::default();
        m.set_policy_id("some-policy-id");
        let acp = crate::acp::AcpModule::new();
        let tx_ctx = make_tx_ctx("0xABCD");
        let did = make_did("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        let err = m
            .create_post(
                &acp, &tx_ctx, &did, "missing", b"payload", b"proof", "artifact",
            )
            .unwrap_err();
        assert!(matches!(err, BulletinError::NamespaceNotFound { .. }));
    }

    #[test]
    fn create_post_policy_not_initialized() {
        let mut m = populated_module();
        let acp = crate::acp::AcpModule::new();
        let tx_ctx = make_tx_ctx("0xABCD");
        let did = make_did("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        let err = m
            .create_post(&acp, &tx_ctx, &did, "ns1", b"payload", b"proof", "artifact")
            .unwrap_err();
        assert!(matches!(err, BulletinError::PolicyNotInitialized));
    }

    #[test]
    fn glob_match_star_wildcard() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", "path/with/slashes"));
        assert!(glob_match("prefix*", "prefix-value"));
        assert!(glob_match("*suffix", "some-suffix"));
        assert!(!glob_match("prefix*", "other"));
    }

    #[test]
    fn glob_match_exact() {
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "other"));
    }

    #[test]
    fn storage_roundtrip_namespace() {
        let mut m = BulletinModule::default();
        let ns = Namespace {
            id: "bulletin/test".into(),
            creator: "0xABCD".into(),
            owner_did: "did:key:z6Mk".into(),
            created_at: Timestamp {
                seconds: 1,
                block_height: 1,
            },
        };
        m.set_namespace(&ns);
        assert!(m.has_namespace("bulletin/test").unwrap());
        assert_eq!(m.get_namespace("bulletin/test").unwrap().unwrap(), ns);
        assert!(m.get_namespace("missing").unwrap().is_none());
    }

    #[test]
    fn storage_roundtrip_collaborator() {
        let mut m = BulletinModule::default();
        let c = Collaborator {
            did: "did:key:z6Mkabc".into(),
            namespace: "bulletin/ns1".into(),
        };
        m.set_collaborator(&c);
        let got = m
            .get_collaborator("bulletin/ns1", "did:key:z6Mkabc")
            .unwrap()
            .unwrap();
        assert_eq!(got, c);
        m.delete_collaborator("bulletin/ns1", "did:key:z6Mkabc");
        assert!(
            m.get_collaborator("bulletin/ns1", "did:key:z6Mkabc")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn storage_roundtrip_post() {
        let mut m = BulletinModule::default();
        let post = Post {
            id: "post1".into(),
            namespace: "bulletin/ns1".into(),
            creator_did: "did:key:z6Mk".into(),
            payload: vec![1],
            proof: vec![2],
        };
        m.set_post(&post);
        let got = m.get_post("bulletin/ns1", "post1").unwrap().unwrap();
        assert_eq!(got, post);
    }
}
