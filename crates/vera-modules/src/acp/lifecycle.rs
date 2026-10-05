use super::*;

impl AcpModule {
    /// Create a policy with caller metadata and an optional required specification.
    pub fn execute_create_policy(
        &mut self,
        actor: &Did,
        request: &types::PolicyCreation,
        block: &BlockExecCtx,
        submission: &TxExecCtx,
    ) -> Result<PolicyRecord> {
        if submission.signer != actor.as_str()
            || submission.tx_hash.len() != 32
            || block.timestamp.block_height == 0
            || block.timestamp.seconds == 0
        {
            return Err(AcpError::InvalidAccessRequest {
                reason: "invalid policy creation context".into(),
            });
        }
        self.create_policy_with_options(
            &request.policy,
            request.marshal_type.clone(),
            RecordMetadata {
                creation_ts: block.timestamp.clone(),
                tx_hash: submission.tx_hash.clone(),
                tx_signer: submission.signer.clone(),
                owner_did: actor.to_string(),
            },
            request.required_specification,
            request.metadata.clone(),
        )
    }

    /// Transfer a live registration without changing its priority or other grants.
    pub fn transfer_object(
        &mut self,
        actor: &Did,
        policy_id: &str,
        object: &Object,
        new_owner: &Did,
    ) -> Result<RelationshipRecord> {
        self.validate_registration_object(policy_id, object)?;
        let mut record = self
            .registration_owner_record(policy_id, object)?
            .ok_or_else(|| AcpError::ObjectNotRegistered {
                resource: object.resource.clone(),
                object_id: object.id.clone(),
            })?;
        if record.archived {
            return Err(AcpError::Unauthorized {
                reason: "cannot transfer an archived object".into(),
            });
        }
        if !self.check_management_authority(actor, policy_id, object, "owner")? {
            return Err(AcpError::Unauthorized {
                reason: "actor cannot transfer this object".into(),
            });
        }
        let old_key = keys::relationship_storage_key(&record.relationship);
        record.relationship.subject = acp::Subject::Entity(new_owner.clone());
        record.metadata.owner_did = new_owner.to_string();
        self.delete_relationship(policy_id, &old_key);
        self.set_relationship(
            policy_id,
            &keys::relationship_storage_key(&record.relationship),
            &record,
        );
        Ok(record)
    }

    /// Replace caller-supplied policy metadata without changing its definition or grants.
    pub fn edit_policy_metadata(
        &mut self,
        actor: &Did,
        policy_id: &str,
        metadata: SuppliedMetadata,
        modified_at: &Timestamp,
    ) -> Result<PolicyRecord> {
        let mut record = self.query_policy(policy_id)?;
        if record.metadata.owner_did != actor.as_str() {
            return Err(AcpError::Unauthorized {
                reason: "only the policy creator can edit metadata".into(),
            });
        }
        Self::validate_policy_revision(&record, modified_at)?;
        metadata.validate()?;
        record.supplied_metadata = metadata;
        record.last_modified = Some(modified_at.clone());
        self.set_policy_record(policy_id, &record);
        Ok(record)
    }

    /// Delete a policy and its relationship graph. Historical decisions remain auditable.
    pub fn delete_policy(&mut self, actor: &Did, policy_id: &str) -> Result<bool> {
        let Some(record) = self.get_policy_record(policy_id)? else {
            return Ok(false);
        };
        if record.metadata.owner_did != actor.as_str() {
            return Err(AcpError::Unauthorized {
                reason: "only the policy creator can delete it".into(),
            });
        }
        let mut keys: Vec<_> = self
            .store
            .prefix_iter(&keys::relationship_policy_prefix(policy_id))
            .map(|(key, _)| key.to_vec())
            .collect();
        let prefix = keys::commitment_policy_index_prefix(policy_id);
        for (index, value) in self.store.prefix_iter(&prefix) {
            let id = policy_index_id(&prefix, index, value)?;
            let commitment = self
                .get_commitment_by_id(id)?
                .ok_or_else(|| AcpError::State("indexed commitment missing".into()))?;
            if commitment.policy_id != policy_id {
                return Err(AcpError::State("commitment policy index mismatch".into()));
            }
            keys.extend([
                index.to_vec(),
                keys::commitment_key(id),
                Self::commitment_expiry_key(&commitment),
                keys::commitment_by_commitment_index_key(&commitment.commitment, id),
            ]);
        }
        let prefix = keys::amendment_event_policy_index_prefix(policy_id);
        for (index, value) in self.store.prefix_iter(&prefix) {
            let id = policy_index_id(&prefix, index, value)?;
            let event = self
                .get_amendment_event_by_id(id)?
                .ok_or_else(|| AcpError::State("indexed amendment missing".into()))?;
            if event.policy_id != policy_id {
                return Err(AcpError::State("amendment policy index mismatch".into()));
            }
            keys.extend([index.to_vec(), keys::amendment_event_key(id)]);
        }
        for key in keys {
            self.store.delete(&key);
        }
        self.store.delete(&keys::policy_key(policy_id));
        self.zanzibar_policies.remove(policy_id);
        Ok(true)
    }
}

fn policy_index_id(prefix: &[u8], key: &[u8], value: &[u8]) -> Result<u64> {
    let id = key
        .strip_prefix(prefix)
        .and_then(|suffix| suffix.try_into().ok())
        .map(u64::from_be_bytes)
        .filter(|id| *id != 0 && value.is_empty())
        .ok_or_else(|| AcpError::State("invalid policy record index".into()))?;
    Ok(id)
}
