//! Prepare creation records and counter updates before publishing either.

use super::*;
use serde::{Deserialize, Serialize};

/// One genesis-seeded policy: definition text plus its marshaling format.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicySeed {
    /// The policy's source text, in `marshal_type`'s format.
    pub definition: String,
    /// Which format `definition` is written in.
    pub marshal_type: PolicyMarshalingType,
}

impl AcpModule {
    /// Parse, validate, and store a new access control policy.
    pub fn create_policy(
        &mut self,
        creator: &Did,
        policy: &str,
        marshal_type: PolicyMarshalingType,
    ) -> Result<PolicyRecord> {
        self.create_policy_with_budget(
            creator,
            policy,
            marshal_type,
            &PolicyCreateBudget::new(u64::MAX),
        )
    }

    /// Create within a caller-owned allowance, preserving state and ID allocation on failure.
    pub fn create_policy_with_budget(
        &mut self,
        creator: &Did,
        policy: &str,
        marshal_type: PolicyMarshalingType,
        budget: &PolicyCreateBudget,
    ) -> Result<PolicyRecord> {
        budget.input(creator.as_str().len())?;
        let result = self.create_policy_with_options_and_budget(
            policy,
            marshal_type,
            RecordMetadata {
                creation_ts: Timestamp::default(),
                tx_hash: Vec::new(),
                tx_signer: String::new(),
                owner_did: creator.to_string(),
            },
            None,
            &SuppliedMetadata::default(),
            budget,
        );
        budget.finish(result)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn create_policy_with_options_and_budget(
        &mut self,
        policy: &str,
        marshal_type: PolicyMarshalingType,
        mut metadata: RecordMetadata,
        specification: Option<PolicySpecification>,
        supplied: &SuppliedMetadata,
        budget: &PolicyCreateBudget,
    ) -> Result<PolicyRecord> {
        crate::actor::canonicalize(&mut metadata.owner_did);
        if policy.len() > MAX_POLICY_DEFINITION_BYTES {
            return Err(AcpError::InvalidPolicy {
                reason: "policy definition exceeds 64 KiB".into(),
            });
        }
        budget.input(policy.len())?;
        budget.metadata(supplied)?;
        budget.records.read(
            keys::POLICY_COUNTER_KEY,
            self.store.get_ref(keys::POLICY_COUNTER_KEY),
        )?;
        let counter = self.next_policy_counter()?;
        let zanzibar_policy = Self::compile_policy(policy, &marshal_type, counter, specification)?;
        let record = PolicyRecord {
            relations: RelationGenerations::new(&zanzibar_policy).map_err(relation_state_error)?,
            supplied_metadata: supplied.clone(),
            last_modified: None,
            policy: zanzibar_policy.clone(),
            raw_policy: policy.to_string(),
            marshal_type,
            metadata,
        };
        let policy_id = zanzibar_policy.id.clone();
        let key = keys::policy_key(&policy_id);
        budget.records.read(&key, self.store.get_ref(&key))?;
        if self.store.has(&key) {
            return Err(AcpError::State("policy identifier already exists".into()));
        }
        let retired_key = retirement::retired_key(&policy_id);
        budget
            .records
            .read(&retired_key, self.store.get_ref(&retired_key))?;
        if self.retired_policy(&policy_id)?.is_some() {
            return Err(AcpError::State("policy identifier already exists".into()));
        }
        let bytes = budget.records.encode(&key, &record)?;
        budget
            .records
            .write(keys::POLICY_COUNTER_KEY, Some(&counter.to_be_bytes()))?;
        self.store
            .put(keys::POLICY_COUNTER_KEY, counter.to_be_bytes().to_vec());
        self.store.put(&key, bytes);
        self.zanzibar_policies
            .insert(policy_id, Arc::new(zanzibar_policy));
        Ok(record)
    }

    /// Seed policies with caller-assigned counters (1, 2, ... in list order)
    /// instead of `next_policy_counter`'s live read -- only safe at genesis,
    /// where the caller is the sole creator and fully controls the sequence.
    /// Leaves `POLICY_COUNTER_KEY` at the last-assigned counter, so the first
    /// live `create_policy` call afterward continues from there without
    /// colliding with anything seeded here.
    pub fn initialize_policies(
        &mut self,
        creator: &Did,
        policies: &[PolicySeed],
    ) -> Result<Vec<PolicyRecord>> {
        if self.store.has(keys::POLICY_COUNTER_KEY) {
            return Err(AcpError::State(
                "policy counter is already initialized".into(),
            ));
        }
        let metadata = RecordMetadata {
            creation_ts: Timestamp::default(),
            tx_hash: Vec::new(),
            tx_signer: String::new(),
            owner_did: creator.to_string(),
        };
        let mut records = Vec::with_capacity(policies.len());
        let mut counter = 0u64;
        for seed in policies {
            counter = counter
                .checked_add(1)
                .ok_or_else(|| AcpError::State("policy counter exhausted".into()))?;
            let record = self.initialize_one_policy(
                &seed.definition,
                &seed.marshal_type,
                counter,
                &metadata,
            )?;
            records.push(record);
        }
        self.store
            .put(keys::POLICY_COUNTER_KEY, counter.to_be_bytes().to_vec());
        Ok(records)
    }

    /// Predicts the id a genesis-seeded policy at the given list position
    /// (1-based) will get, without mutating any state -- lets a test harness
    /// compute a `RingConfig.policy_id` before genesis exists at all.
    pub fn predict_policy_id(
        policy: &str,
        marshal_type: &PolicyMarshalingType,
        counter: u64,
    ) -> Result<String> {
        Ok(Self::compile_policy(policy, marshal_type, counter, None)?.id)
    }

    fn initialize_one_policy(
        &mut self,
        policy: &str,
        marshal_type: &PolicyMarshalingType,
        counter: u64,
        metadata: &RecordMetadata,
    ) -> Result<PolicyRecord> {
        let zanzibar_policy = Self::compile_policy(policy, marshal_type, counter, None)?;
        let record = PolicyRecord {
            relations: RelationGenerations::new(&zanzibar_policy).map_err(relation_state_error)?,
            supplied_metadata: SuppliedMetadata::default(),
            last_modified: None,
            policy: zanzibar_policy.clone(),
            raw_policy: policy.to_string(),
            marshal_type: marshal_type.clone(),
            metadata: metadata.clone(),
        };
        let policy_id = zanzibar_policy.id.clone();
        let key = keys::policy_key(&policy_id);
        if self.store.has(&key) {
            return Err(AcpError::State("policy identifier already exists".into()));
        }
        let bytes = serde_json::to_vec(&record)
            .map_err(|error| AcpError::State(format!("encode seeded policy: {error}")))?;
        self.store.put(&key, bytes);
        self.zanzibar_policies
            .insert(policy_id, Arc::new(zanzibar_policy));
        Ok(record)
    }
}

#[cfg(test)]
#[path = "policy_create_budget_tests.rs"]
mod tests;
