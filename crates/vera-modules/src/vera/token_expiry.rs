use super::*;

const EXPIRY_BATCH_SIZE: usize = 128;

impl VeraModule {
    pub(super) fn token_expiry_key(record: &JWSTokenRecord) -> Option<Vec<u8>> {
        if record.status == JWSTokenStatus::Invalid {
            return None;
        }
        Some(
            [
                keys::JWS_TOKEN_EXPIRY_PREFIX,
                &record.expires_at.seconds.to_be_bytes(),
                record.token_hash.as_bytes(),
            ]
            .concat(),
        )
    }

    /// Invalidate due tokens using their persisted ordered deadline index.
    pub fn check_and_update_expired_tokens(&mut self, block_ctx: &BlockExecCtx) -> Result<()> {
        let prefix = keys::JWS_TOKEN_EXPIRY_PREFIX;
        let mut expired = Vec::new();
        for (index, value) in self.store.prefix_iter(prefix).take(EXPIRY_BATCH_SIZE) {
            if index.len() <= prefix.len() + 8 || !value.is_empty() {
                return Err(VeraError::State("invalid token expiry index".into()));
            }
            if &index[prefix.len()..prefix.len() + 8]
                >= block_ctx.timestamp.seconds.to_be_bytes().as_slice()
            {
                break;
            }
            let hash = std::str::from_utf8(&index[prefix.len() + 8..])
                .map_err(|error| VeraError::State(format!("invalid expiry token hash: {error}")))?;
            let record = self
                .get_jws_token(hash)?
                .ok_or_else(|| VeraError::State("expiry token missing".into()))?;
            if Self::token_expiry_key(&record).as_deref() != Some(index) {
                return Err(VeraError::State("token expiry index mismatch".into()));
            }
            expired.push(hash.to_owned());
        }
        for hash in expired {
            self.update_jws_token_status(block_ctx, &hash, JWSTokenStatus::Invalid, "")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(seconds: u64) -> BlockExecCtx {
        BlockExecCtx {
            genesis_id: [0; 32],
            deployment_id: 9001,
            timestamp: Timestamp {
                seconds,
                block_height: seconds,
            },
        }
    }

    fn token(vera: &mut VeraModule, name: &str, expiry: u64) -> String {
        vera.store_or_update_jws_token(
            &context(100),
            name,
            &Did::new("did:key:issuer").unwrap(),
            "account",
            Timestamp::default(),
            Timestamp {
                seconds: expiry,
                block_height: 0,
            },
        )
        .unwrap();
        keys::hash_jws_token(name)
    }

    #[test]
    fn expiry_batches_resume_after_restore_without_extending_token_validity() {
        let mut vera = VeraModule::new();
        for id in 0..(EXPIRY_BATCH_SIZE * 2 + 1) {
            token(&mut vera, &id.to_string(), 150);
        }
        vera.check_and_update_expired_tokens(&context(151)).unwrap();
        assert_eq!(
            vera.store
                .prefix_iter(keys::JWS_TOKEN_EXPIRY_PREFIX)
                .count(),
            EXPIRY_BATCH_SIZE + 1
        );
        let pending = vera
            .store
            .prefix_iter(keys::JWS_TOKEN_EXPIRY_PREFIX)
            .next()
            .unwrap()
            .0;
        let hash = std::str::from_utf8(&pending[keys::JWS_TOKEN_EXPIRY_PREFIX.len() + 8..])
            .unwrap()
            .to_owned();
        assert_eq!(
            vera.get_jws_token(&hash).unwrap().unwrap().status,
            JWSTokenStatus::Valid
        );
        assert!(matches!(
            vera.record_jws_token_usage(&context(151), &hash),
            Err(VeraError::InvalidJws { .. })
        ));
        let mut restored =
            VeraModule::from_store(InMemoryKvStore::deserialize(&vera.store.serialize()).unwrap());
        restored.validate_restored_tokens().unwrap();
        for remaining in [1, 0] {
            restored
                .check_and_update_expired_tokens(&context(152))
                .unwrap();
            assert_eq!(
                restored
                    .store
                    .prefix_iter(keys::JWS_TOKEN_EXPIRY_PREFIX)
                    .count(),
                remaining
            );
        }
        assert_eq!(
            restored.store.prefix_iter(keys::JWS_TOKEN_PREFIX).count(),
            EXPIRY_BATCH_SIZE * 2 + 1
        );
        assert_eq!(
            restored.get_jws_token(&hash).unwrap().unwrap().status,
            JWSTokenStatus::Invalid
        );
    }

    #[test]
    fn token_expiry_retains_history_and_recovers_active_deadlines() {
        let mut vera = VeraModule::new();
        for id in 0..2000 {
            let hash = token(&mut vera, &id.to_string(), 150);
            vera.update_jws_token_status(&context(101), &hash, JWSTokenStatus::Invalid, "operator")
                .unwrap();
        }
        let due = token(&mut vera, "due", 150);
        let future = token(&mut vera, "future", 160);
        let distant = token(&mut vera, "distant", u64::MAX);
        vera.record_jws_token_usage(&context(110), &due).unwrap();
        assert_eq!(
            vera.store
                .prefix_iter(keys::JWS_TOKEN_EXPIRY_PREFIX)
                .count(),
            3
        );
        let mut vera =
            VeraModule::from_store(InMemoryKvStore::deserialize(&vera.store.serialize()).unwrap());
        vera.check_and_update_expired_tokens(&context(150)).unwrap();
        assert_eq!(
            vera.get_jws_token(&due).unwrap().unwrap().status,
            JWSTokenStatus::Valid
        );
        vera.check_and_update_expired_tokens(&context(151)).unwrap();
        let expired = vera.get_jws_token(&due).unwrap().unwrap();
        assert_eq!(expired.status, JWSTokenStatus::Invalid);
        assert_eq!(expired.invalidated_at, Some(context(151).timestamp));
        assert_eq!(
            vera.store
                .prefix_iter(keys::JWS_TOKEN_EXPIRY_PREFIX)
                .count(),
            2
        );
        assert_eq!(vera.store.prefix_iter(keys::JWS_TOKEN_PREFIX).count(), 2003);
        assert_eq!(
            vera.get_jws_token(&future).unwrap().unwrap().status,
            JWSTokenStatus::Valid
        );
        assert_eq!(
            vera.get_jws_token(&distant).unwrap().unwrap().status,
            JWSTokenStatus::Valid
        );
        vera.update_jws_token_status(&context(152), &future, JWSTokenStatus::Invalid, "operator")
            .unwrap();
        assert_eq!(
            vera.store
                .prefix_iter(keys::JWS_TOKEN_EXPIRY_PREFIX)
                .count(),
            1
        );
        vera.check_and_update_expired_tokens(&context(200)).unwrap();
        assert_eq!(
            vera.get_jws_token(&distant).unwrap().unwrap().status,
            JWSTokenStatus::Valid
        );
        assert_eq!(
            vera.get_jws_token(&future).unwrap().unwrap().invalidated_by,
            "operator"
        );
    }

    #[test]
    fn token_expiry_rejects_mismatched_records_before_mutation() {
        let mut vera = VeraModule::new();
        let first = token(&mut vera, "first", 150);
        let second = token(&mut vera, "second", 150);
        let bytes = vera.store.get(&keys::jws_token_key(&first)).unwrap();
        vera.store.put(&keys::jws_token_key(&second), bytes);
        let before = vera.store.serialize();
        assert!(vera.get_jws_token(&second).is_err());
        assert!(vera.check_and_update_expired_tokens(&context(151)).is_err());
        assert_eq!(vera.store.serialize(), before);
    }
}
