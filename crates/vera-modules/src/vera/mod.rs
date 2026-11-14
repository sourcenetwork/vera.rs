//! Vera module — identity management, JWS token lifecycle, and chain configuration.

/// Solidity ABI interface for the Vera precompile.
pub mod abi;
/// Operator approvals and administrative state transitions.
pub mod administration;
mod delegation;
/// Vera error types.
pub mod error;
/// Key prefixes and builders for Vera KV storage.
pub mod keys;
/// Finalized rosters selected for future consensus epochs.
pub mod membership;
/// Threshold-service node registration and controller authority.
pub mod nodes;
/// Encrypted documents and signing derivations.
pub mod objects;
mod operator_key;
/// Operator-authorized relay grants.
pub mod relay;
mod restoration;
/// Ring lifecycle and participant attestations.
pub mod rings;
mod token_expiry;
mod token_queries;
/// Vera domain types.
pub mod types;

use error::VeraError;
use types::{ChainConfig, JWSTokenRecord, JWSTokenStatus, VeraParams};
use vera_identity::Did;

use crate::kv_store::{InMemoryKvStore, ModuleKvStore};
use crate::types::{BlockExecCtx, Timestamp, TxExecCtx};

type Result<T> = std::result::Result<T, VeraError>;

/// Vera module.
///
/// Manages JWS token invalidation, token lifecycle tracking, and
/// chain configuration.
///
/// # KV store layout
///
/// ```text
/// 0x01 || token_hash                                 → JWSTokenRecord (primary)
/// 0x02 || len_prefix(did) || len_prefix(token_hash)  → 0x01 (DID index)
/// 0x03 || len_prefix(acct) || len_prefix(token_hash) → 0x01 (account index)
/// "p_hub"                                            → VeraParams
/// "chain_config"                                     → ChainConfig (write-once)
/// ```
///
/// Token hash: `hex(sha256(raw_bearer_jws_string))`.
///
/// DID and account indices (0x02, 0x03) use length-prefixed composite
/// keys because they encode two variable-length components.
///
/// DID and account indices are presence markers (value=0x01);
/// the full record lives only in the primary 0x01 store.
#[derive(Clone, Debug, Default)]
pub struct VeraModule {
    store: InMemoryKvStore,
}

impl VeraModule {
    /// Create a new Vera module instance.
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

    /// Invalidate a token by its hash.
    ///
    /// The caller must be the token issuer or the token's authorized account.
    pub fn invalidate_jws(
        &mut self,
        block_ctx: &BlockExecCtx,
        tx_ctx: &TxExecCtx,
        creator: &Did,
        token_hash: &str,
    ) -> Result<JWSTokenRecord> {
        let record = self
            .get_jws_token(token_hash)?
            .ok_or_else(|| VeraError::TokenNotFound {
                token_hash: token_hash.to_string(),
            })?;
        if record.status == JWSTokenStatus::Invalid {
            return Err(VeraError::TokenAlreadyInvalidated {
                token_hash: token_hash.to_string(),
            });
        }
        let is_issuer = vera_crypto::jwt::matches_issuer(&record.issuer_did, creator.as_ref());
        let is_authorized_account = !record.authorized_account.is_empty()
            && record.authorized_account == crate::actor::canonical_str(&tx_ctx.signer);
        if !is_issuer && !is_authorized_account {
            return Err(VeraError::Unauthorized {
                reason: "caller is neither issuer DID nor authorized account".to_string(),
            });
        }
        self.update_jws_token_status(
            block_ctx,
            token_hash,
            JWSTokenStatus::Invalid,
            &tx_ctx.signer,
        )
    }

    /// Reject legacy parameter writes without operator approvals.
    pub fn update_params(&mut self, _authority: &Did, _params: VeraParams) -> Result<()> {
        Err(VeraError::Unauthorized {
            reason: "operator approvals are required".into(),
        })
    }

    // ── Query handlers ──────────────────────────────────────────────────

    /// Query current module parameters; defaults apply when none are stored.
    pub fn query_params(&self) -> Result<VeraParams> {
        self.get_params()
    }

    // ── Internal keeper methods ─────────────────────────────────────────

    /// Record a token on first use, or refresh its usage time when already stored.
    ///
    /// A new token that has already expired at block time is rejected; a zero
    /// expiry means the token does not expire.
    pub fn store_or_update_jws_token(
        &mut self,
        block_ctx: &BlockExecCtx,
        bearer_token: &str,
        issuer_did: &Did,
        authorized_account: &str,
        issued_at: Timestamp,
        expires_at: Timestamp,
    ) -> Result<()> {
        let token_hash = Self::hash_jws_token(bearer_token);
        if self.get_jws_token(&token_hash)?.is_some() {
            return self.record_jws_token_usage(block_ctx, &token_hash);
        }
        let zero = Timestamp::default();
        if expires_at != zero && expires_at.seconds < block_ctx.timestamp.seconds {
            return Err(VeraError::InvalidJws {
                reason: "token already expired at block time".to_string(),
            });
        }
        let record = JWSTokenRecord {
            token_hash,
            bearer_token: bearer_token.to_string(),
            issuer_did: crate::actor::canonical(issuer_did).to_string(),
            authorized_account: crate::actor::canonical_str(authorized_account).into_owned(),
            issued_at,
            expires_at,
            status: JWSTokenStatus::Valid,
            first_used_at: Some(block_ctx.timestamp.clone()),
            last_used_at: Some(block_ctx.timestamp.clone()),
            invalidated_at: None,
            invalidated_by: String::new(),
        };
        self.set_jws_token(&record)
    }

    /// Update the usage timestamps of a valid, unexpired token.
    pub fn record_jws_token_usage(
        &mut self,
        block_ctx: &BlockExecCtx,
        token_hash: &str,
    ) -> Result<()> {
        let mut record =
            self.get_jws_token(token_hash)?
                .ok_or_else(|| VeraError::TokenNotFound {
                    token_hash: token_hash.to_string(),
                })?;
        if record.status != JWSTokenStatus::Valid
            || (record.expires_at.seconds != 0
                && record.expires_at.seconds < block_ctx.timestamp.seconds)
        {
            return Err(VeraError::InvalidJws {
                reason: "token is invalid or expired".into(),
            });
        }
        if record.first_used_at.is_none() {
            record.first_used_at = Some(block_ctx.timestamp.clone());
        }
        record.last_used_at = Some(block_ctx.timestamp.clone());
        self.set_jws_token(&record)
    }

    /// Look up a token record by hash, rejecting a record stored under another hash.
    pub fn get_jws_token(&self, token_hash: &str) -> Result<Option<JWSTokenRecord>> {
        self.store
            .get(&keys::jws_token_key(token_hash))
            .map(|bytes| {
                let record: JWSTokenRecord = borsh::from_slice(&bytes)
                    .map_err(|e: std::io::Error| VeraError::State(e.to_string()))?;
                if record.token_hash != token_hash {
                    return Err(VeraError::State("token record key mismatch".into()));
                }
                Ok(record)
            })
            .transpose()
    }

    /// List the tokens issued by a DID, within the token query budget.
    pub fn get_jws_tokens_by_did(&self, did: &Did) -> Result<Vec<JWSTokenRecord>> {
        Self::validate_token_selector(did.as_str())?;
        let did = &crate::actor::canonical(did);
        self.collect_tokens(&keys::jws_token_did_prefix(did.as_str()), |record| {
            keys::jws_token_by_did_key(&record.issuer_did, &record.token_hash)
        })
    }

    /// List the tokens authorized for an account, within the token query budget.
    pub fn get_jws_tokens_by_account(&self, account: &str) -> Result<Vec<JWSTokenRecord>> {
        Self::validate_token_selector(account)?;
        let account = &*crate::actor::canonical_str(account);
        self.collect_tokens(&keys::jws_token_account_prefix(account), |record| {
            keys::jws_token_by_account_key(&record.authorized_account, &record.token_hash)
        })
    }

    /// Set a token's status. Invalidation records the block time and, when given,
    /// who invalidated the token.
    pub fn update_jws_token_status(
        &mut self,
        block_ctx: &BlockExecCtx,
        token_hash: &str,
        status: JWSTokenStatus,
        invalidated_by: &str,
    ) -> Result<JWSTokenRecord> {
        let mut record =
            self.get_jws_token(token_hash)?
                .ok_or_else(|| VeraError::TokenNotFound {
                    token_hash: token_hash.to_string(),
                })?;
        record.status = status;
        if record.status == JWSTokenStatus::Invalid {
            record.invalidated_at = Some(block_ctx.timestamp.clone());
            if !invalidated_by.is_empty() {
                record.invalidated_by = crate::actor::canonical_str(invalidated_by).into_owned();
            }
        }
        self.set_jws_token(&record)?;
        Ok(record)
    }

    /// Set the chain configuration; it can be written once.
    pub fn set_chain_config(&mut self, config: ChainConfig) -> Result<()> {
        if self.store.has(keys::CHAIN_CONFIG_KEY) {
            return Err(VeraError::ChainConfigAlreadySet);
        }
        let bytes = borsh::to_vec(&config).map_err(|e| VeraError::State(e.to_string()))?;
        self.store.put(keys::CHAIN_CONFIG_KEY, bytes);
        Ok(())
    }

    /// Read the chain configuration; both settings default to false.
    pub fn get_chain_config(&self) -> Result<ChainConfig> {
        self.store.get(keys::CHAIN_CONFIG_KEY).map_or(
            Ok(ChainConfig {
                allow_zero_fee_txs: false,
                ignore_bearer_auth: false,
            }),
            |bytes| {
                borsh::from_slice(&bytes)
                    .map_err(|e: std::io::Error| VeraError::State(e.to_string()))
            },
        )
    }

    // ── Storage — JWS Token (primary + indexes) ────────────────────────

    /// Write a token record together with its issuer, account and expiry index entries.
    fn set_jws_token(&mut self, record: &JWSTokenRecord) -> Result<()> {
        Self::validate_token_selector(&record.token_hash)?;
        Self::validate_token_selector(&record.issuer_did)?;
        if !record.authorized_account.is_empty() {
            Self::validate_token_selector(&record.authorized_account)?;
        }
        let config = self.get_chain_config()?;
        if !config.ignore_bearer_auth && record.authorized_account.is_empty() {
            return Err(VeraError::InvalidJws {
                reason: "authorized_account required when bearer auth is enforced".to_string(),
            });
        }
        let bytes = borsh::to_vec(record).map_err(|e| VeraError::State(e.to_string()))?;
        if let Some(previous) = self.get_jws_token(&record.token_hash)?
            && let Some(key) = Self::token_expiry_key(&previous)
        {
            self.store.delete(&key);
        }
        if let Some(key) = Self::token_expiry_key(record) {
            self.store.put(&key, Vec::new());
        }
        self.store
            .put(&keys::jws_token_key(&record.token_hash), bytes);
        let did_key = keys::jws_token_by_did_key(&record.issuer_did, &record.token_hash);
        self.store.put(&did_key, vec![0x01]);
        if !record.authorized_account.is_empty() {
            let acct_key =
                keys::jws_token_by_account_key(&record.authorized_account, &record.token_hash);
            self.store.put(&acct_key, vec![0x01]);
        }
        Ok(())
    }

    // ── Storage — Params ───────────────────────────────────────────────

    fn get_params(&self) -> Result<VeraParams> {
        self.store.get_ref(keys::PARAMS_KEY).map_or_else(
            || Ok(VeraParams::default()),
            |bytes| {
                borsh::from_slice(bytes)
                    .map_err(|e| VeraError::State(format!("invalid vera parameters: {e}")))
            },
        )
    }

    // ── Storage — Utility ──────────────────────────────────────────────

    /// `hex(sha256(bearer_token))`, the key of a token record.
    fn hash_jws_token(bearer_token: &str) -> String {
        keys::hash_jws_token(bearer_token)
    }
}

/// Parse a `len_prefix(token_hash)` suffix from a secondary index key.
///
/// The secondary index keys end with `len_prefix(token_hash)`:
/// `[hash_len_byte, hash_bytes...]`. Returns `None` if the suffix is
/// malformed (too short, or non-UTF-8 hash bytes).
fn extract_hash_from_index_suffix(suffix: &[u8]) -> Option<String> {
    if suffix.is_empty() {
        return None;
    }
    let hash_len = suffix[0] as usize;
    if hash_len == 0 || suffix.len() != 1 + hash_len {
        return None;
    }
    std::str::from_utf8(&suffix[1..1 + hash_len])
        .ok()
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Timestamp;

    fn block_ctx(seconds: u64) -> BlockExecCtx {
        BlockExecCtx {
            genesis_id: [0; 32],
            deployment_id: 9001,
            timestamp: Timestamp {
                seconds,
                block_height: seconds,
            },
        }
    }

    fn make_did(s: &str) -> Did {
        s.parse().expect("valid DID")
    }

    fn sample_record(vera: &mut VeraModule, block_ctx: &BlockExecCtx) -> String {
        let did = make_did("did:key:z6MkTest");
        vera.store_or_update_jws_token(
            block_ctx,
            "bearer-token-abc",
            &did,
            "0xAccount1",
            Timestamp {
                seconds: 1,
                block_height: 1,
            },
            Timestamp::default(),
        )
        .unwrap();
        keys::hash_jws_token("bearer-token-abc")
    }

    #[test]
    fn set_and_get_chain_config() {
        let mut vera = VeraModule::new();
        let config = ChainConfig {
            allow_zero_fee_txs: true,
            ignore_bearer_auth: false,
        };
        vera.set_chain_config(config.clone()).unwrap();
        assert_eq!(vera.get_chain_config().unwrap(), config);
    }

    #[test]
    fn chain_config_write_once() {
        let mut vera = VeraModule::new();
        let config = ChainConfig {
            allow_zero_fee_txs: false,
            ignore_bearer_auth: true,
        };
        vera.set_chain_config(config.clone()).unwrap();
        let err = vera.set_chain_config(config).unwrap_err();
        assert!(matches!(err, VeraError::ChainConfigAlreadySet));
    }

    #[test]
    fn chain_config_default_when_absent() {
        let vera = VeraModule::new();
        let config = vera.get_chain_config().unwrap();
        assert!(!config.allow_zero_fee_txs);
        assert!(!config.ignore_bearer_auth);
    }

    #[test]
    fn malformed_parameters_return_errors() {
        let mut vera = VeraModule::default();
        vera.store.put(keys::PARAMS_KEY, vec![0]);
        assert!(vera.query_params().is_err());
    }

    #[test]
    fn absent_and_stored_params_are_read() {
        let mut vera = VeraModule::new();
        assert_eq!(vera.get_params().unwrap(), VeraParams::default());
        let params = VeraParams {};
        vera.store
            .put(keys::PARAMS_KEY, borsh::to_vec(&params).unwrap());
        assert_eq!(vera.get_params().unwrap(), params);
    }

    #[test]
    fn store_token_and_retrieve() {
        let _hub = VeraModule::new();
        let mut hub2 = VeraModule::new();
        hub2.set_chain_config(ChainConfig {
            allow_zero_fee_txs: false,
            ignore_bearer_auth: true,
        })
        .unwrap();
        let ctx = block_ctx(100);
        let did = make_did("did:key:z6MkAlice");
        hub2.store_or_update_jws_token(
            &ctx,
            "my-bearer",
            &did,
            "",
            Timestamp {
                seconds: 50,
                block_height: 5,
            },
            Timestamp::default(),
        )
        .unwrap();
        let hash = keys::hash_jws_token("my-bearer");
        let record = hub2.get_jws_token(&hash).unwrap().unwrap();
        assert_eq!(record.bearer_token, "my-bearer");
        assert_eq!(record.issuer_did, did.to_string());
        assert_eq!(record.status, JWSTokenStatus::Valid);
        assert_eq!(record.first_used_at, Some(ctx.timestamp.clone()));
        assert_eq!(record.last_used_at, Some(ctx.timestamp));
        drop(_hub);
    }

    #[test]
    fn store_token_requires_account_when_bearer_auth_enforced() {
        let mut vera = VeraModule::new();
        let ctx = block_ctx(100);
        let did = make_did("did:key:z6MkBob");
        let err = vera
            .store_or_update_jws_token(
                &ctx,
                "bearer",
                &did,
                "",
                Timestamp::default(),
                Timestamp::default(),
            )
            .unwrap_err();
        assert!(matches!(err, VeraError::InvalidJws { .. }));
    }

    #[test]
    fn store_token_rejects_pre_expired() {
        let mut vera = VeraModule::new();
        vera.set_chain_config(ChainConfig {
            allow_zero_fee_txs: false,
            ignore_bearer_auth: true,
        })
        .unwrap();
        let ctx = block_ctx(200);
        let did = make_did("did:key:z6MkCarol");
        let err = vera
            .store_or_update_jws_token(
                &ctx,
                "expired-bearer",
                &did,
                "",
                Timestamp {
                    seconds: 100,
                    block_height: 10,
                },
                Timestamp {
                    seconds: 100,
                    block_height: 10,
                },
            )
            .unwrap_err();
        assert!(matches!(err, VeraError::InvalidJws { .. }));
    }

    #[test]
    fn record_usage_updates_timestamps() {
        let mut vera = VeraModule::new();
        vera.set_chain_config(ChainConfig {
            allow_zero_fee_txs: false,
            ignore_bearer_auth: true,
        })
        .unwrap();
        let ctx1 = block_ctx(100);
        let did = make_did("did:key:z6MkDave");
        vera.store_or_update_jws_token(
            &ctx1,
            "token-dave",
            &did,
            "",
            Timestamp::default(),
            Timestamp::default(),
        )
        .unwrap();
        let hash = keys::hash_jws_token("token-dave");
        let ctx2 = block_ctx(200);
        vera.record_jws_token_usage(&ctx2, &hash).unwrap();
        let record = vera.get_jws_token(&hash).unwrap().unwrap();
        assert_eq!(record.first_used_at, Some(ctx1.timestamp));
        assert_eq!(record.last_used_at, Some(ctx2.timestamp));
    }

    #[test]
    fn idempotent_store_updates_usage() {
        let mut vera = VeraModule::new();
        vera.set_chain_config(ChainConfig {
            allow_zero_fee_txs: false,
            ignore_bearer_auth: true,
        })
        .unwrap();
        let ctx1 = block_ctx(100);
        let did = make_did("did:key:z6MkEve");
        vera.store_or_update_jws_token(
            &ctx1,
            "token-eve",
            &did,
            "",
            Timestamp::default(),
            Timestamp::default(),
        )
        .unwrap();
        let ctx2 = block_ctx(200);
        vera.store_or_update_jws_token(
            &ctx2,
            "token-eve",
            &did,
            "",
            Timestamp::default(),
            Timestamp::default(),
        )
        .unwrap();
        let hash = keys::hash_jws_token("token-eve");
        let record = vera.get_jws_token(&hash).unwrap().unwrap();
        assert_eq!(record.last_used_at, Some(ctx2.timestamp));
    }

    #[test]
    fn update_status_to_invalid() {
        let mut vera = VeraModule::new();
        vera.set_chain_config(ChainConfig {
            allow_zero_fee_txs: false,
            ignore_bearer_auth: true,
        })
        .unwrap();
        let ctx = block_ctx(100);
        let hash = sample_record_ignore_bearer(&mut vera, &ctx);
        let ctx2 = block_ctx(200);
        vera.update_jws_token_status(&ctx2, &hash, JWSTokenStatus::Invalid, "0xAdmin")
            .unwrap();
        let record = vera.get_jws_token(&hash).unwrap().unwrap();
        assert_eq!(record.status, JWSTokenStatus::Invalid);
        assert_eq!(record.invalidated_at, Some(ctx2.timestamp));
        assert_eq!(record.invalidated_by, "0xAdmin");
    }

    fn sample_record_ignore_bearer(vera: &mut VeraModule, ctx: &BlockExecCtx) -> String {
        let did = make_did("did:key:z6MkTest2");
        vera.store_or_update_jws_token(
            ctx,
            "bearer-ignore",
            &did,
            "",
            Timestamp::default(),
            Timestamp::default(),
        )
        .unwrap();
        keys::hash_jws_token("bearer-ignore")
    }

    #[test]
    fn get_tokens_by_did() {
        let mut vera = VeraModule::new();
        let ctx = block_ctx(100);
        let _ = sample_record(&mut vera, &ctx);
        let did = make_did("did:key:z6MkTest");
        let tokens = vera.get_jws_tokens_by_did(&did).unwrap();
        assert_eq!(tokens.len(), 1);
    }

    #[test]
    fn get_tokens_by_account() {
        let mut vera = VeraModule::new();
        let ctx = block_ctx(100);
        let _ = sample_record(&mut vera, &ctx);
        let tokens = vera.get_jws_tokens_by_account("0xAccount1").unwrap();
        assert_eq!(tokens.len(), 1);
    }

    #[test]
    fn hash_jws_token_delegates_to_keys() {
        let h1 = VeraModule::hash_jws_token("test");
        let h2 = keys::hash_jws_token("test");
        assert_eq!(h1, h2);
    }

    #[test]
    fn extract_hash_from_index_suffix_empty() {
        assert!(extract_hash_from_index_suffix(&[]).is_none());
    }

    #[test]
    fn extract_hash_from_index_suffix_truncated() {
        assert!(extract_hash_from_index_suffix(&[10, b'a']).is_none());
    }

    #[test]
    fn extract_hash_from_index_suffix_valid() {
        let hash = "abc123";
        let mut suffix = vec![hash.len() as u8];
        suffix.extend_from_slice(hash.as_bytes());
        assert_eq!(extract_hash_from_index_suffix(&suffix).unwrap(), hash);
    }

    // ── Handler tests ────────────────────────────────────────────────

    fn tx_ctx(signer: &str) -> TxExecCtx {
        TxExecCtx {
            sequence: 0,
            tx_hash: vec![0xAA],
            signer: signer.to_string(),
        }
    }

    fn vera_with_token() -> (VeraModule, String) {
        let mut vera = VeraModule::new();
        vera.set_chain_config(ChainConfig {
            allow_zero_fee_txs: false,
            ignore_bearer_auth: true,
        })
        .unwrap();
        let ctx = block_ctx(100);
        let did = make_did("did:key:z6MkTest");
        vera.store_or_update_jws_token(
            &ctx,
            "bearer-token-abc",
            &did,
            "0xAccount1",
            Timestamp {
                seconds: 1,
                block_height: 1,
            },
            Timestamp::default(),
        )
        .unwrap();
        let hash = keys::hash_jws_token("bearer-token-abc");
        (vera, hash)
    }

    #[test]
    fn invalidate_jws_by_issuer_did() {
        let (mut vera, hash) = vera_with_token();
        let bctx = block_ctx(200);
        let tctx = tx_ctx("some-other-account");
        let creator = make_did("did:key:z6MkTest");
        let result = vera.invalidate_jws(&bctx, &tctx, &creator, &hash).unwrap();
        assert_eq!(result.status, JWSTokenStatus::Invalid);
        let record = vera.get_jws_token(&hash).unwrap().unwrap();
        assert_eq!(record.status, JWSTokenStatus::Invalid);
        assert_eq!(record.invalidated_by, "some-other-account");
    }

    #[test]
    fn invalidate_jws_by_authorized_account() {
        let (mut vera, hash) = vera_with_token();
        let bctx = block_ctx(200);
        let tctx = tx_ctx("0xAccount1");
        let creator = make_did("did:key:z6MkOther");
        let result = vera.invalidate_jws(&bctx, &tctx, &creator, &hash).unwrap();
        assert_eq!(result.status, JWSTokenStatus::Invalid);
    }

    #[test]
    fn invalidate_jws_unauthorized() {
        let (mut vera, hash) = vera_with_token();
        let bctx = block_ctx(200);
        let tctx = tx_ctx("0xWrongAccount");
        let creator = make_did("did:key:z6MkWrong");
        let err = vera
            .invalidate_jws(&bctx, &tctx, &creator, &hash)
            .unwrap_err();
        assert!(matches!(err, VeraError::Unauthorized { .. }));
    }

    #[test]
    fn invalidate_jws_already_invalid() {
        let (mut vera, hash) = vera_with_token();
        let bctx = block_ctx(200);
        let tctx = tx_ctx("0xAccount1");
        let creator = make_did("did:key:z6MkTest");
        vera.invalidate_jws(&bctx, &tctx, &creator, &hash).unwrap();
        let err = vera
            .invalidate_jws(&bctx, &tctx, &creator, &hash)
            .unwrap_err();
        assert!(matches!(err, VeraError::TokenAlreadyInvalidated { .. }));
    }

    #[test]
    fn invalidate_jws_not_found() {
        let mut vera = VeraModule::new();
        let bctx = block_ctx(200);
        let tctx = tx_ctx("0xAccount1");
        let creator = make_did("did:key:z6MkTest");
        let err = vera
            .invalidate_jws(&bctx, &tctx, &creator, "nonexistent")
            .unwrap_err();
        assert!(matches!(err, VeraError::TokenNotFound { .. }));
    }

    #[test]
    fn unauthenticated_parameter_update_is_rejected() {
        let mut vera = VeraModule::new();
        let authority = make_did("did:key:z6MkGov");
        assert!(vera.update_params(&authority, VeraParams {}).is_err());
        assert_eq!(vera.get_params().unwrap(), VeraParams {});
    }

    #[test]
    fn check_and_update_expired_tokens_sweeps() {
        let mut vera = VeraModule::new();
        vera.set_chain_config(ChainConfig {
            allow_zero_fee_txs: false,
            ignore_bearer_auth: true,
        })
        .unwrap();
        let ctx = block_ctx(100);
        let did = make_did("did:key:z6MkExpiry");
        vera.store_or_update_jws_token(
            &ctx,
            "expiring-token",
            &did,
            "",
            Timestamp::default(),
            Timestamp {
                seconds: 150,
                block_height: 150,
            },
        )
        .unwrap();
        let hash = keys::hash_jws_token("expiring-token");
        let record = vera.get_jws_token(&hash).unwrap().unwrap();
        assert_eq!(record.status, JWSTokenStatus::Valid);

        let sweep_ctx = block_ctx(200);
        vera.check_and_update_expired_tokens(&sweep_ctx).unwrap();
        let record = vera.get_jws_token(&hash).unwrap().unwrap();
        assert_eq!(record.status, JWSTokenStatus::Invalid);
        assert!(record.invalidated_by.is_empty());
    }

    #[test]
    fn check_and_update_skips_zero_expiry() {
        let mut vera = VeraModule::new();
        vera.set_chain_config(ChainConfig {
            allow_zero_fee_txs: false,
            ignore_bearer_auth: true,
        })
        .unwrap();
        let ctx = block_ctx(100);
        let did = make_did("did:key:z6MkNoExpiry");
        vera.store_or_update_jws_token(
            &ctx,
            "no-expiry-token",
            &did,
            "",
            Timestamp::default(),
            Timestamp::default(),
        )
        .unwrap();
        let hash = keys::hash_jws_token("no-expiry-token");

        let sweep_ctx = block_ctx(999_999);
        vera.check_and_update_expired_tokens(&sweep_ctx).unwrap();
        let record = vera.get_jws_token(&hash).unwrap().unwrap();
        assert_eq!(record.status, JWSTokenStatus::Valid);
    }
}
