use super::*;

const MAX_ITEMS: usize = 64;
const MAX_BYTES: usize = 1 << 20;
const CURSOR_KEY: &[u8] = b"decision_cleanup/cursor";

impl AcpModule {
    pub(super) fn decision_cleanup_cursor(&self) -> Result<Option<&[u8]>> {
        self.store
            .get_ref(CURSOR_KEY)
            .map(|cursor| {
                let suffix = cursor.strip_prefix(keys::ACCESS_DECISION_PREFIX);
                if cursor.len() > crate::kv_store::NATIVE_MAX_KEY_BYTES
                    || suffix.is_none_or(|id| id.is_empty() || std::str::from_utf8(id).is_err())
                {
                    return Err(AcpError::State("invalid decision cleanup cursor".into()));
                }
                Ok(cursor)
            })
            .transpose()
    }

    pub(super) fn prune_access_decisions(&mut self, block: &BlockExecCtx) -> Result<()> {
        let mut removed = Vec::new();
        let mut last = None;
        let mut bytes = 0;
        let mut exhausted = true;
        for (count, (key, value)) in self
            .store
            .prefix_iter_after(
                keys::ACCESS_DECISION_PREFIX,
                self.decision_cleanup_cursor()?,
            )
            .enumerate()
        {
            let size = key.len().saturating_add(value.len());
            if count == MAX_ITEMS || size > MAX_BYTES - bytes {
                exhausted = false;
                break;
            }
            bytes += size;
            let id = std::str::from_utf8(&key[keys::ACCESS_DECISION_PREFIX.len()..])
                .map_err(|_| AcpError::State("invalid access decision key".into()))?;
            let decision = AccessDecision::decode_record(value)?;
            if decision.id != id {
                return Err(AcpError::State("access decision identity mismatch".into()));
            }
            // Legacy zero-height placeholders have no usable expiry; retain them for migration.
            let expiry = if decision.issued_height == 0 {
                None
            } else {
                Some(decision.verify_issuance(block.deployment_id, id, &block.timestamp)?)
            };
            if expiry.is_some_and(|expiry| block.timestamp.block_height >= expiry) {
                removed.push(key.to_vec());
            }
            last = Some(key.to_vec());
        }
        for key in removed {
            self.store.delete(&key);
        }
        if exhausted {
            self.store.delete(CURSOR_KEY);
        } else if let Some(last) = last {
            self.store.put(CURSOR_KEY, last);
        } else {
            return Err(AcpError::State(
                "access decision exceeds cleanup byte limit".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "decision_cleanup_tests.rs"]
mod tests;
