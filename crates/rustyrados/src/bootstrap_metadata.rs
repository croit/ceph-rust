// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use super::{Bootstrap, BootstrapState};
use crate::{ClusterMetadata, MetadataError};
use denc::types::Uuid;
impl Bootstrap {
    /// Required monmap feature union used by ready client service policy.
    pub fn required_monitor_features(&self) -> u64 {
        self.monitor.as_ref().map_or(0, |mon| {
            let map = mon.monmap();
            map.persistent_features | map.optional_features
        })
    }

    /// Active ready monitor identity; None until final messenger readiness.
    pub fn monitor_addresses(&self) -> Result<Option<msgr2::LocalAddresses<'_>>, MetadataError> {
        self.metadata()?;
        Ok(self.monitor.as_ref().and_then(|mon| mon.local_addresses()))
    }
    /// Address nonce of the monitor session, shared by every session of this client instance; `None` for a
    /// follower (it uses the leader's nonce from the shared view).
    pub fn address_nonce(&self) -> Option<u32> {
        self.monitor.as_ref().and_then(|mon| mon.address_nonce())
    }
    /// Lab qualifier: only the final ready active monitor, never a hunt candidate.
    #[cfg(feature = "lab")]
    pub fn lab_monitor_name(&self) -> Option<&str> {
        self.metadata().ok()?;
        let mon = self.monitor.as_ref()?;
        mon.local_addresses()?;
        mon.current_mon()
    }
    pub fn metadata(&self) -> Result<ClusterMetadata<'_>, MetadataError> {
        if self.state != BootstrapState::Ready {
            return Err(MetadataError::Unavailable(self.state));
        }
        let mon = self
            .monitor
            .as_ref()
            .ok_or(MetadataError::Unavailable(self.state))?;
        let map = mon
            .osdmap()
            .filter(|m| m.epoch > 0)
            .ok_or(MetadataError::Unavailable(self.state))?;
        let client_id = self
            .identity
            .filter(|&id| id != 0)
            .ok_or(MetadataError::Identity)?;
        if map.fsid == Uuid::default()
            || self.fsid != Some(map.fsid)
            || mon.monmap().fsid != map.fsid
        {
            return Err(MetadataError::Identity);
        }
        Ok(ClusterMetadata::verified(map, client_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BootstrapConfig, BootstrapError, MessengerMode};
    use std::time::Duration;
    fn fixture() -> Bootstrap {
        let fsid = Uuid([7; 16]);
        let mut b = Bootstrap::new(BootstrapConfig {
            entity: "client.metadata".into(),
            key: cephx::CryptoKey::new(
                cephx::key::KeyType::Aes,
                Default::default(),
                b"1234567890abcdef",
            ),
            monitors: monc::parse_mon_host("v2:127.0.0.1:3300").unwrap(),
            expected_fsid: Some(fsid),
            mode: MessengerMode::Crc,
            startup_timeout: Duration::from_secs(10),
            wall_origin_unix: 100,
        })
        .unwrap();
        let mut cfg = monc::Config::new("client.metadata", None);
        let mut monmap =
            monc::monmap_from_addrs(&monc::parse_mon_host("v2:127.0.0.1:3300").unwrap());
        monmap.fsid = fsid;
        cfg.initial_monmap = Some(monmap);
        let mut mon = monc::MonClient::new(cfg);
        let mut map = osdmap::OsdMap::default();
        map.fsid = fsid;
        map.epoch = 5;
        mon.set_osdmap(map);
        b.monitor = Some(mon);
        b.identity = Some(9);
        b.state = BootstrapState::Ready;
        b // Composition fixture only, not an authentication test.
    }
    #[test]
    fn required_monitor_feature_policy_includes_persistent_and_optional_bits() {
        let fsid = Uuid([7; 16]);
        for (persistent, optional) in [(0, 0), (2, 0), (0, 2), (4, 2)] {
            let mut b = fixture();
            let mut cfg = monc::Config::new("client.metadata", None);
            cfg.initial_monmap = Some(osdmap::MonMap {
                fsid,
                persistent_features: persistent,
                optional_features: optional,
                ..Default::default()
            });
            b.monitor = Some(monc::MonClient::new(cfg));
            assert_eq!(b.required_monitor_features(), persistent | optional);
        }
    }
    #[test]
    fn state_identity_map_and_close_boundaries() {
        let mut b = fixture();
        assert_eq!(b.metadata().unwrap().client_id(), 9);
        assert!(b.monitor_addresses().unwrap().is_none()); // fixture has no ready active transport
        #[cfg(feature = "lab")]
        assert_eq!(b.lab_monitor_name(), None);
        for state in [
            BootstrapState::New,
            BootstrapState::Hunting,
            BootstrapState::AwaitingMaps,
            BootstrapState::Failed(BootstrapError::AuthRejected),
            BootstrapState::Closed,
        ] {
            b.state = state;
            assert_eq!(
                b.monitor_addresses().unwrap_err(),
                MetadataError::Unavailable(state)
            );
            assert_eq!(b.metadata().unwrap_err(), MetadataError::Unavailable(state));
        }
        b.state = BootstrapState::Ready;
        b.identity = None;
        assert_eq!(b.metadata().unwrap_err(), MetadataError::Identity);
        b.identity = Some(0);
        assert_eq!(b.metadata().unwrap_err(), MetadataError::Identity);
        b.identity = Some(9);
        b.fsid = Some(Uuid([8; 16]));
        assert_eq!(b.metadata().unwrap_err(), MetadataError::Identity);
        b.fsid = Some(Uuid([7; 16]));
        let mut map = b.osdmap().unwrap().clone();
        map.epoch = 0;
        b.monitor.as_mut().unwrap().set_osdmap(map);
        assert_eq!(
            b.metadata().unwrap_err(),
            MetadataError::Unavailable(BootstrapState::Ready)
        );
        let mut b = fixture();
        b.close();
        assert_eq!(
            b.metadata().unwrap_err(),
            MetadataError::Unavailable(BootstrapState::Closed)
        );
        let mut b = fixture();
        let mut cfg = monc::Config::new("client.metadata", None);
        cfg.initial_monmap = Some(b.monitor.as_ref().unwrap().monmap().clone());
        b.monitor = Some(monc::MonClient::new(cfg));
        assert_eq!(
            b.metadata().unwrap_err(),
            MetadataError::Unavailable(BootstrapState::Ready)
        );
        let mut b = fixture();
        b.monitor = None;
        assert_eq!(
            b.metadata().unwrap_err(),
            MetadataError::Unavailable(BootstrapState::Ready)
        );
    }
    #[test]
    fn mon_and_osd_fsid_must_both_match_bootstrap_even_in_ready_fixture() {
        let mut b = fixture();
        let mut map = b.osdmap().unwrap().clone();
        map.fsid = Uuid([8; 16]);
        b.monitor.as_mut().unwrap().set_osdmap(map);
        assert_eq!(b.metadata().unwrap_err(), MetadataError::Identity);
        b.fsid = Some(Uuid([8; 16])); // still wrong monmap
        assert_eq!(b.metadata().unwrap_err(), MetadataError::Identity);
        let mut map = b.osdmap().unwrap().clone();
        map.fsid = Uuid::default();
        b.fsid = Some(Uuid::default());
        b.monitor.as_mut().unwrap().set_osdmap(map);
        assert_eq!(b.metadata().unwrap_err(), MetadataError::Identity);
    }
}
