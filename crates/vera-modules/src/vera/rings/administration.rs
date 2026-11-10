use super::*;

impl VeraModule {
    pub(super) fn update_ring(
        &self,
        acp: &AcpModule,
        context: &BlockExecCtx,
        actor: &Did,
        id: &str,
        expected_sequence: u64,
        update: &RingUpdate,
    ) -> Result<RingRecord> {
        let mut record = self
            .threshold_ring(id)?
            .ok_or_else(|| invalid("ring not found"))?;
        if record.sequence != expected_sequence {
            return Err(invalid("ring sequence changed"));
        }
        let relay_update = matches!(update, RingUpdate::AddRelay(_) | RingUpdate::RemoveRelay(_));
        if !(matches!(record.state, RingState::Active { .. })
            || relay_update && matches!(record.state, RingState::Pending { .. }))
        {
            return Err(invalid("ring is not active"));
        }
        let access = AccessRequest {
            actor: Actor(actor.clone()),
            operations: vec![Operation {
                object: Object {
                    resource: "ring".into(),
                    id: id.into(),
                },
                permission: "update_ring".into(),
            }],
        };
        if !acp
            .query_verify_access_request(&record.config.policy_id, &access)
            .map_err(invalid)?
        {
            return Err(invalid("actor cannot update this ring"));
        }
        let mut settings = record.current_settings();
        if !matches!(update, RingUpdate::CancelUpgrade) && !relay_update {
            settings.normalize_upgrade(context.timestamp.seconds);
        }
        match update {
            RingUpdate::SetPssInterval(interval) => {
                if *interval < 86400 || *interval == settings.pss_interval {
                    return Err(invalid("refresh interval is invalid or unchanged"));
                }
                settings.pss_interval = *interval;
            }
            RingUpdate::ScheduleUpgrade(upgrade) => {
                let minimum = context
                    .timestamp
                    .seconds
                    .checked_add(600)
                    .ok_or_else(|| invalid("upgrade time overflow"))?;
                if upgrade.version <= settings.current_version
                    || upgrade.activates_at < minimum
                    || settings.scheduled_upgrade.as_ref() == Some(upgrade)
                {
                    return Err(invalid("upgrade is invalid or unchanged"));
                }
                settings.scheduled_upgrade = Some(upgrade.clone());
            }
            RingUpdate::CancelUpgrade => {
                let upgrade = settings
                    .scheduled_upgrade
                    .as_ref()
                    .ok_or_else(|| invalid("upgrade is not scheduled"))?;
                if context.timestamp.seconds >= upgrade.activates_at {
                    return Err(invalid("upgrade is already active"));
                }
                settings.scheduled_upgrade = None;
            }
            RingUpdate::SetReporting(reporting) => {
                if *reporting == settings.reporting {
                    return Err(invalid("reporting settings unchanged"));
                }
                self.require_ring_nodes(&reporting.backup_node_keys, &record)?;
                settings.reporting.clone_from(reporting);
            }
            RingUpdate::AddRelay(relay) | RingUpdate::RemoveRelay(relay) => {
                let relays = settings
                    .trusted_auth_relay_dids
                    .as_mut()
                    .ok_or_else(|| invalid("ring relays permanently disabled"))?;
                match (relays.binary_search(relay), update) {
                    (Err(index), RingUpdate::AddRelay(_)) => relays.insert(index, relay.clone()),
                    (Ok(index), RingUpdate::RemoveRelay(_)) => {
                        relays.remove(index);
                    }
                    _ => return Err(invalid("relay already present or absent")),
                }
            }
            RingUpdate::StartReshare {
                peer_node_keys,
                threshold,
            } => {
                if settings.pending_reshare.is_some() {
                    return Err(invalid("reshare already pending"));
                }
                let peers = peer_node_keys.as_ref().unwrap_or(&settings.peer_node_keys);
                types::keys(peers, false)?;
                let threshold = threshold.unwrap_or(settings.threshold);
                if threshold == 0
                    || threshold as usize > peers.len()
                    || (*peers == settings.peer_node_keys && threshold == settings.threshold)
                {
                    return Err(invalid("reshare target is invalid or unchanged"));
                }
                self.require_ring_nodes(peers, &record)?;
                settings.pending_reshare = Some(ReshareTarget {
                    peer_node_keys: peers.clone(),
                    threshold,
                });
            }
            RingUpdate::CancelReshare => {
                if settings.pending_reshare.is_none() {
                    return Err(invalid("reshare is not pending"));
                }
                settings.pending_reshare = None;
            }
        }
        record.settings = Some(settings);
        Ok(record)
    }

    pub(super) fn require_ring_nodes(&self, keys: &[String], record: &RingRecord) -> Result<()> {
        for key in keys {
            let node = self
                .threshold_node(key)?
                .ok_or_else(|| invalid("ring node not registered"))?;
            if !node.info.allows_ring(&record.config.policy_id, &record.id) {
                return Err(invalid("node controller does not permit this ring"));
            }
        }
        Ok(())
    }
}
