use super::*;

impl VeraModule {
    /// Validate token records and both directions of their indexes before recovery publication.
    pub fn validate_restored_tokens(&self) -> Result<()> {
        for (key, bytes) in self.store.prefix_iter(keys::JWS_TOKEN_PREFIX) {
            let record: JWSTokenRecord = borsh::from_slice(bytes)
                .map_err(|e| VeraError::State(format!("invalid restored token: {e}")))?;
            Self::validate_token_selector(&record.token_hash)?;
            Self::validate_token_selector(&record.issuer_did)?;
            if record.authorized_account.is_empty() {
                return Err(VeraError::State(
                    "restored token has no authorized account".into(),
                ));
            }
            Self::validate_token_selector(&record.authorized_account)?;
            if keys::jws_token_key(&record.token_hash) != key {
                return Err(VeraError::State("restored token key mismatch".into()));
            }
            self.require_token_index(
                &keys::jws_token_by_did_key(&record.issuer_did, &record.token_hash),
                &[1],
            )?;
            self.require_token_index(
                &keys::jws_token_by_account_key(&record.authorized_account, &record.token_hash),
                &[1],
            )?;
            if let Some(key) = Self::token_expiry_key(&record) {
                self.require_token_index(&key, &[])?;
            }
        }
        for prefix in [
            keys::JWS_TOKEN_BY_DID_PREFIX,
            keys::JWS_TOKEN_BY_ACCOUNT_PREFIX,
            keys::JWS_TOKEN_EXPIRY_PREFIX,
        ] {
            for (key, value) in self.store.prefix_iter(prefix) {
                let suffix = &key[prefix.len()..];
                let hash = if prefix == keys::JWS_TOKEN_EXPIRY_PREFIX {
                    if !value.is_empty() {
                        return Err(VeraError::State("invalid restored expiry marker".into()));
                    }
                    suffix
                        .get(8..)
                        .and_then(|bytes| std::str::from_utf8(bytes).ok())
                        .map(str::to_owned)
                } else {
                    if value != [1] {
                        return Err(VeraError::State(
                            "invalid restored token index marker".into(),
                        ));
                    }
                    suffix
                        .first()
                        .and_then(|length| suffix.get(1 + usize::from(*length)..))
                        .and_then(extract_hash_from_index_suffix)
                }
                .ok_or_else(|| VeraError::State("invalid restored token index key".into()))?;
                let record = self
                    .get_jws_token(&hash)?
                    .ok_or_else(|| VeraError::State("restored token index has no record".into()))?;
                let expected = if prefix == keys::JWS_TOKEN_BY_DID_PREFIX {
                    Some(keys::jws_token_by_did_key(&record.issuer_did, &hash))
                } else if prefix == keys::JWS_TOKEN_BY_ACCOUNT_PREFIX {
                    Some(keys::jws_token_by_account_key(
                        &record.authorized_account,
                        &hash,
                    ))
                } else {
                    Self::token_expiry_key(&record)
                };
                if expected.as_deref() != Some(key) {
                    return Err(VeraError::State(
                        "restored token index differs from record".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn require_token_index(&self, key: &[u8], marker: &[u8]) -> Result<()> {
        if self.store.get_ref(key) != Some(marker) {
            return Err(VeraError::State(
                "restored token index missing or invalid".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_rejects_missing_orphaned_and_malformed_token_indexes() {
        let mut vera = VeraModule::new();
        let ctx = BlockExecCtx {
            genesis_id: [0; 32],
            deployment_id: 9001,
            timestamp: Timestamp {
                seconds: 100,
                block_height: 1,
            },
        };
        vera.store_or_update_jws_token(
            &ctx,
            "bearer",
            &Did::new("did:key:issuer").unwrap(),
            "account",
            Timestamp::default(),
            Timestamp {
                seconds: 150,
                block_height: 0,
            },
        )
        .unwrap();
        let hash = keys::hash_jws_token("bearer");
        vera.validate_restored_tokens().unwrap();
        let original = vera.store.clone();
        let record = vera.get_jws_token(&hash).unwrap().unwrap();
        let indexes = [
            keys::jws_token_by_did_key(&record.issuer_did, &hash),
            keys::jws_token_by_account_key("account", &hash),
            VeraModule::token_expiry_key(&record).unwrap(),
        ];
        for key in &indexes {
            let mut broken = original.clone();
            broken.delete(key);
            assert!(
                VeraModule::from_store(broken)
                    .validate_restored_tokens()
                    .is_err()
            );
            let mut broken = original.clone();
            broken.put(key, vec![9]);
            assert!(
                VeraModule::from_store(broken)
                    .validate_restored_tokens()
                    .is_err()
            );
        }
        let mut broken = original.clone();
        broken.delete(&keys::jws_token_key(&hash));
        assert!(
            VeraModule::from_store(broken)
                .validate_restored_tokens()
                .is_err()
        );
        for (key, value) in [
            (keys::jws_token_by_did_key("did:key:other", &hash), vec![1]),
            (keys::jws_token_by_account_key("other", &hash), vec![1]),
            (keys::JWS_TOKEN_EXPIRY_PREFIX.to_vec(), vec![]),
            (keys::jws_token_key(&hash), vec![255]),
        ] {
            let mut broken = original.clone();
            broken.put(&key, value);
            let module = VeraModule::from_store(broken);
            let before = module.store.serialize();
            assert!(module.validate_restored_tokens().is_err());
            assert_eq!(module.store.serialize(), before);
        }
        VeraModule::new().validate_restored_tokens().unwrap();
    }
}
