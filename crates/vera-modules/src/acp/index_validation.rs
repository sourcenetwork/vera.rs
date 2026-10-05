use super::*;

fn index_id(key: &[u8]) -> Result<u64> {
    key.get(key.len().saturating_sub(8)..)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_be_bytes)
        .filter(|id| *id != 0)
        .ok_or_else(|| AcpError::State("invalid record index identifier".into()))
}

impl AcpModule {
    pub(super) fn validate_record_indexes(&self) -> Result<()> {
        let objects = [keys::COMMITMENT_PREFIX, keys::OBJS_SUBPREFIX].concat();
        for (key, _) in self.store.prefix_iter(&objects) {
            let id = index_id(key)?;
            let record = self
                .get_commitment_by_id(id)?
                .ok_or_else(|| AcpError::State("commitment index record missing".into()))?;
            if keys::commitment_key(id) != key
                || !self.zanzibar_policies.contains_key(&record.policy_id)
                || self
                    .store
                    .get_ref(&keys::commitment_by_commitment_index_key(
                        &record.commitment,
                        id,
                    ))
                    != Some(&[])
                || self
                    .store
                    .get_ref(&keys::commitment_policy_index_key(&record.policy_id, id))
                    != Some(&[])
                || (!record.expired
                    && self.store.get_ref(&Self::commitment_expiry_key(&record)) != Some(&[]))
            {
                return Err(AcpError::State(
                    "commitment policy or index mismatch".into(),
                ));
            }
        }
        let mut policies = keys::commitment_policy_index_prefix("");
        policies.pop();
        for (key, value) in self.store.prefix_iter(&policies) {
            let id = index_id(key)?;
            let record = self
                .get_commitment_by_id(id)?
                .ok_or_else(|| AcpError::State("commitment policy index record missing".into()))?;
            if !value.is_empty()
                || keys::commitment_policy_index_key(&record.policy_id, id) != key
                || !self.zanzibar_policies.contains_key(&record.policy_id)
            {
                return Err(AcpError::State("commitment policy index mismatch".into()));
            }
        }
        let mut roots = keys::commitment_by_commitment_index_prefix(&[]);
        roots.pop();
        for (key, value) in self.store.prefix_iter(&roots) {
            let id = index_id(key)?;
            let record = self
                .get_commitment_by_id(id)?
                .ok_or_else(|| AcpError::State("commitment root index record missing".into()))?;
            if !value.is_empty()
                || keys::commitment_by_commitment_index_key(&record.commitment, id) != key
            {
                return Err(AcpError::State("commitment root index mismatch".into()));
            }
        }
        for prefix in [
            commitment_expiry::SECONDS_PREFIX,
            commitment_expiry::HEIGHT_PREFIX,
        ] {
            for (key, value) in self.store.prefix_iter(prefix) {
                let record = self
                    .get_commitment_by_id(index_id(key)?)?
                    .ok_or_else(|| AcpError::State("commitment expiry record missing".into()))?;
                if !value.is_empty()
                    || record.expired
                    || Self::commitment_expiry_key(&record) != key
                {
                    return Err(AcpError::State("commitment expiry index mismatch".into()));
                }
            }
        }
        let mut policies = keys::amendment_event_policy_index_prefix("");
        policies.pop();
        for (key, value) in self.store.prefix_iter(&policies) {
            let id = index_id(key)?;
            let event = self
                .get_amendment_event_by_id(id)?
                .ok_or_else(|| AcpError::State("amendment index record missing".into()))?;
            if !value.is_empty()
                || keys::amendment_event_policy_index_key(&event.policy_id, id) != key
                || !self.zanzibar_policies.contains_key(&event.policy_id)
            {
                return Err(AcpError::State("amendment policy index mismatch".into()));
            }
        }
        Ok(())
    }
}
