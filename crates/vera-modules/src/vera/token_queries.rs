use super::*;

const MAX_RECORDS: usize = 128;
const MAX_BYTES: usize = 1 << 20;

impl VeraModule {
    pub(super) fn validate_token_selector(value: &str) -> Result<()> {
        if value.is_empty() || value.len() > u8::MAX as usize {
            return Err(VeraError::InvalidJws {
                reason: "token index components must contain 1–255 bytes".into(),
            });
        }
        Ok(())
    }

    pub(super) fn collect_tokens(
        &self,
        prefix: &[u8],
        record_key: impl Fn(&JWSTokenRecord) -> Vec<u8>,
    ) -> Result<Vec<JWSTokenRecord>> {
        let mut records = Vec::new();
        let mut bytes = 0usize;
        for (count, (key, value)) in self
            .store
            .prefix_iter(prefix)
            .take(MAX_RECORDS + 1)
            .enumerate()
        {
            bytes = bytes.saturating_add(key.len()).saturating_add(value.len());
            if count == MAX_RECORDS || bytes > MAX_BYTES {
                return Err(VeraError::State(
                    "token query exceeds limit; use certified prefix pages".into(),
                ));
            }
            let hash = extract_hash_from_index_suffix(&key[prefix.len()..])
                .ok_or_else(|| VeraError::State("invalid token index key".into()))?;
            if value != [1] {
                return Err(VeraError::State("invalid token index value".into()));
            }
            let primary_key = keys::jws_token_key(&hash);
            let value = self
                .store
                .get_ref(&primary_key)
                .ok_or_else(|| VeraError::State("indexed token missing".into()))?;
            bytes = bytes
                .saturating_add(primary_key.len())
                .saturating_add(value.len());
            if bytes > MAX_BYTES {
                return Err(VeraError::State(
                    "token query exceeds byte limit; use certified prefix pages".into(),
                ));
            }
            let record: JWSTokenRecord = borsh::from_slice(value)
                .map_err(|e| VeraError::State(format!("invalid token record: {e}")))?;
            Self::validate_token_selector(&record.token_hash)?;
            Self::validate_token_selector(&record.issuer_did)?;
            if record.authorized_account.is_empty() {
                return Err(VeraError::State(
                    "token record has no authorized account".into(),
                ));
            }
            Self::validate_token_selector(&record.authorized_account)?;
            if record_key(&record) != key {
                return Err(VeraError::State("token index does not match record".into()));
            }
            records.push(record);
        }
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(hash: &str) -> JWSTokenRecord {
        JWSTokenRecord {
            token_hash: hash.into(),
            bearer_token: "token".into(),
            issuer_did: "did:key:issuer".into(),
            authorized_account: "account".into(),
            issued_at: Timestamp::default(),
            expires_at: Timestamp::default(),
            status: JWSTokenStatus::Valid,
            first_used_at: None,
            last_used_at: None,
            invalidated_at: None,
            invalidated_by: String::new(),
        }
    }

    #[test]
    fn selectors_and_writes_reject_overflow_before_mutation() {
        let mut vera = VeraModule::new();
        for account in ["".to_string(), "a".repeat(256)] {
            assert!(vera.get_jws_tokens_by_account(&account).is_err());
        }
        let did = Did::new(format!("did:key:{}", "a".repeat(256))).unwrap();
        assert!(vera.get_jws_tokens_by_did(&did).is_err());
        for field in 0..3 {
            let mut token = record("hash");
            match field {
                0 => token.token_hash = "a".repeat(256),
                1 => token.issuer_did = did.to_string(),
                _ => token.authorized_account = "a".repeat(256),
            }
            let before = vera.store.serialize();
            assert!(vera.set_jws_token(&token).is_err());
            assert_eq!(vera.store.serialize(), before);
        }
    }

    #[test]
    fn token_queries_are_bounded_and_reject_dangling_or_aliased_indexes() {
        let mut vera = VeraModule::new();
        for id in 0..MAX_RECORDS {
            vera.set_jws_token(&record(&format!("hash{id}"))).unwrap();
        }
        assert_eq!(
            vera.get_jws_tokens_by_account("account").unwrap().len(),
            MAX_RECORDS
        );
        vera.set_jws_token(&record("extra")).unwrap();
        assert!(vera.get_jws_tokens_by_account("account").is_err());
        let mut vera = VeraModule::new();
        vera.set_jws_token(&record("hash")).unwrap();
        let primary = keys::jws_token_key("hash");
        vera.store.delete(&primary);
        assert!(vera.get_jws_tokens_by_account("account").is_err());
        vera.set_jws_token(&record("hash")).unwrap();
        let mut alias = keys::jws_token_by_account_key("account", "hash");
        alias.push(0);
        vera.store.put(&alias, vec![1]);
        assert!(vera.get_jws_tokens_by_account("account").is_err());
    }

    #[test]
    fn token_queries_bound_bytes_and_validate_record_index_binding() {
        let mut vera = VeraModule::new();
        let mut token = record("hash");
        token.bearer_token = "a".repeat(MAX_BYTES);
        vera.set_jws_token(&token).unwrap();
        assert!(vera.get_jws_tokens_by_account("account").is_err());
        token.bearer_token.clear();
        token.authorized_account = "other".into();
        vera.store
            .put(&keys::jws_token_key("hash"), borsh::to_vec(&token).unwrap());
        assert!(vera.get_jws_tokens_by_account("account").is_err());
    }

    #[test]
    fn a_token_record_without_an_authorized_account_is_malformed() {
        let mut vera = VeraModule::new();
        let mut token = record("hash");
        vera.set_jws_token(&token).unwrap();
        let issuer = Did::new(token.issuer_did.clone()).unwrap();
        assert_eq!(vera.get_jws_tokens_by_did(&issuer).unwrap().len(), 1);
        token.authorized_account.clear();
        vera.store
            .put(&keys::jws_token_key("hash"), borsh::to_vec(&token).unwrap());
        assert!(matches!(
            vera.get_jws_tokens_by_did(&issuer),
            Err(VeraError::State(reason)) if reason.contains("no authorized account")
        ));
    }
}
