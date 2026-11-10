// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Owned cold authentication/map seed for an independent monitor session, RC189.
use super::*;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MonitorTarget {
    Rank(usize),
    Name(String),
    Ping(String),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorTargetError {
    Invalid,
    MissingRank,
    MissingName,
    NoAddress,
    Randomness,
}
/// Contains private credentials; Debug deliberately omits all authentication data.
pub struct MonitorTargetSeed {
    cfg: Config<Vec<u8>>,
    auth: Option<MonAuthClient>,
    gid: u64,
    name: String,
}
impl std::fmt::Debug for MonitorTargetSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MonitorTargetSeed")
            .field("monitor", &self.name)
            .finish_non_exhaustive()
    }
}
impl MonitorTargetSeed {
    pub fn from_config(cfg: Config, target: MonitorTarget) -> Result<Self, MonitorTargetError> {
        Self::from_byte_config(cfg.into_bytes(), target)
    }
    pub fn from_byte_config(
        cfg: Config<Vec<u8>>,
        target: MonitorTarget,
    ) -> Result<Self, MonitorTargetError> {
        let map = cfg
            .initial_monmap
            .clone()
            .unwrap_or_else(|| monmap_from_addrs(&cfg.mon_host));
        Self::select(cfg, map, target, None, 0)
    }
    fn select(
        mut cfg: Config<Vec<u8>>,
        map: MonMap,
        target: MonitorTarget,
        auth: Option<MonAuthClient>,
        gid: u64,
    ) -> Result<Self, MonitorTargetError> {
        let name = match target {
            MonitorTarget::Rank(rank) => map
                .ranks
                .get(rank)
                .cloned()
                .ok_or(MonitorTargetError::MissingRank)?,
            MonitorTarget::Name(name) => {
                if !map.mon_info.contains_key(&name) {
                    return Err(MonitorTargetError::MissingName);
                }
                name
            }
            MonitorTarget::Ping(name) => {
                if name.is_empty() {
                    return Err(MonitorTargetError::Invalid);
                }
                let synthetic = format!("noname-{name}");
                if map.mon_info.contains_key(&synthetic) {
                    synthetic
                } else if map.mon_info.contains_key(&name) {
                    name
                } else {
                    return Err(MonitorTargetError::MissingName);
                }
            }
        };
        if map
            .mon_info
            .get(&name)
            .and_then(|info| info.public_addrs.v2())
            .is_none()
        {
            return Err(MonitorTargetError::NoAddress);
        }
        if cfg.fsid == Uuid::default() {
            cfg.fsid = map.fsid;
        }
        cfg.initial_monmap = Some(map);
        cfg.default_subs = false;
        cfg.target_rank = None;
        cfg.hunt_parallel = 1;
        cfg.my_addrs = None;
        cfg.seed = cephx::challenge::random_u64().map_err(|_| MonitorTargetError::Randomness)?;
        Ok(Self {
            cfg,
            auth,
            gid,
            name,
        })
    }
    pub fn into_client(self) -> MonClient {
        self.into_client_limits(msgr2::Limits {
            max_segment: 33 * 1024 * 1024,
            max_frame: 34 * 1024 * 1024,
            ..msgr2::Limits::default()
        })
    }
    /// Explicit independently selected hard framing; `into_client` keeps the default limits.
    pub fn into_client_limits(self, limits: msgr2::Limits) -> MonClient {
        let mut c = MonClient::new_bytes(self.cfg);
        let auth = self.auth.or_else(|| c.auth.cephx.borrow().clone());
        c.auth = AuthShared::new_bytes(auth, c.cfg.auth_name(), self.gid, c.clock.clone());
        c.msgr_cfg.limits = limits;
        c.pinned = Some(self.name);
        c
    }
}
impl MonClient {
    pub fn target_seed(
        &self,
        target: MonitorTarget,
    ) -> Result<MonitorTargetSeed, MonitorTargetError> {
        let mut cfg = self.cfg.clone();
        cfg.wall_origin = self.wall_now();
        MonitorTargetSeed::select(
            cfg,
            self.monmap.clone(),
            target,
            self.auth.cephx.borrow().clone(),
            self.auth.global_id(),
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn directed_seed_inherits_current_auth_method_policy() {
        let key = cephx::CryptoKey::new(cephx::KeyType::Aes, Default::default(), &[7; 16]);
        let mut cfg = Config::new_client("client.policy", Some(key));
        cfg.mon_host = crate::parse_mon_host("v2:127.0.0.1:3300").unwrap();
        cfg.methods = vec![cephx::modes::AUTH_NONE, cephx::modes::AUTH_CEPHX];
        let mut source = MonClient::new(cfg);
        for policy in [
            vec![cephx::modes::AUTH_CEPHX],
            vec![],
            vec![cephx::modes::AUTH_NONE],
        ] {
            source.set_methods(&policy);
            let mut directed = source
                .target_seed(MonitorTarget::Rank(0))
                .unwrap()
                .into_client();
            assert_eq!(directed.methods, policy);
            directed.start(Duration::ZERO);
            assert_eq!(directed.num_conns(), usize::from(!policy.is_empty()));
        }
    }
    #[test]
    fn directed_seed_preserves_configured_fsid_with_synthetic_map() {
        let mut cfg = Config::new("client.seed", None);
        cfg.fsid = Uuid([7; 16]);
        cfg.mon_host = crate::parse_mon_host("v2:127.0.0.1:3300").unwrap();
        let mut direct = MonitorTargetSeed::from_config(cfg.clone(), MonitorTarget::Rank(0))
            .unwrap()
            .into_client();
        assert_eq!(direct.fsid(), cfg.fsid);
        let mut foreign = direct.monmap().clone();
        foreign.fsid = Uuid([8; 16]);
        foreign.epoch = 1;
        direct.on_monmap(&foreign.encode_to().unwrap());
        assert_eq!(direct.monmap().epoch, 0);
        assert_eq!(direct.fsid(), cfg.fsid);
        let source = MonClient::new(cfg.clone());
        let inherited = source
            .target_seed(MonitorTarget::Rank(0))
            .unwrap()
            .into_client();
        assert_eq!(inherited.fsid(), cfg.fsid);
    }
    #[test]
    fn known_map_pin_checks_peer_rank_but_synthetic_seed_does_not_invent_rank() {
        let mut cfg = Config::new("client.pin", None);
        cfg.mon_host = crate::parse_mon_host("v2:10.0.0.2:3300").unwrap();
        let mut c = MonitorTargetSeed::from_config(cfg, MonitorTarget::Rank(0))
            .unwrap()
            .into_client();
        assert!(c.pinned_peer_matches(EntityName::new(EntityName::MON, 7)));
        assert!(!c.pinned_peer_matches(EntityName::new(EntityName::OSD, 0)));
        c.monmap.epoch = 1;
        assert!(c.pinned_peer_matches(EntityName::new(EntityName::MON, 0)));
        assert!(!c.pinned_peer_matches(EntityName::new(EntityName::MON, 7)));
    }
    #[test]
    fn seed_preserves_identity_without_shared_mutable_auth_or_losing_fresh_key() {
        let key = cephx::CryptoKey::new(cephx::KeyType::Aes, Default::default(), &[7; 16]);
        let mut cfg = Config::new("client.seed", Some(key));
        cfg.mon_host = crate::parse_mon_host("v2:10.0.0.2:3300").unwrap();
        let client = MonitorTargetSeed::from_config(cfg, MonitorTarget::Rank(0))
            .unwrap()
            .into_client();
        assert!(client.auth.cephx.borrow().is_some());
        let mut cfg = client.cfg.clone();
        cfg.key = None;
        let mut source = MonClient::new_bytes(cfg);
        source.auth = AuthShared::new_bytes(None, source.cfg.auth_name(), 77, source.clock.clone());
        let separate = source
            .target_seed(MonitorTarget::Rank(0))
            .unwrap()
            .into_client();
        assert_eq!(separate.global_id(), 77);
        assert!(!Rc::ptr_eq(&source.auth, &separate.auth));
        assert!(!Rc::ptr_eq(&source.clock, &separate.clock));
    }
    #[test]
    fn directed_seed_keeps_byte_principal_after_source_is_dropped() {
        let mut input = b"mgr.\xff nested.id".to_vec();
        let mut cfg = Config::new_client_bytes(&input, None);
        cfg.mon_host = crate::parse_mon_host("v2:127.0.0.1:3300").unwrap();
        let source = MonitorTargetSeed::from_byte_config(cfg, MonitorTarget::Rank(0))
            .unwrap()
            .into_client();
        input.fill(b'x');
        source.auth.none_gid.set(77);
        let seed = source.target_seed(MonitorTarget::Rank(0)).unwrap();
        drop(source);
        let separate = seed.into_client();
        assert_eq!(separate.cfg.auth_name().id, b"\xff nested.id");
        assert_eq!(separate.global_id(), 77);
        assert_eq!(separate.msgr_cfg.name, EntityName::client(-1));
    }
    #[test]
    fn rank_name_ping_alias_and_independent_seed_are_pinned() {
        fn config() -> Config {
            let mut c = Config::new("client.seed", None);
            c.methods = vec![cephx::modes::AUTH_NONE];
            c.mon_host = crate::parse_mon_host("v2:10.0.0.2:3300,v2:10.0.0.3:3300").unwrap();
            c
        }
        assert!(matches!(
            MonitorTargetSeed::from_config(config(), MonitorTarget::Rank(2)),
            Err(MonitorTargetError::MissingRank)
        ));
        assert!(matches!(
            MonitorTargetSeed::from_config(config(), MonitorTarget::Ping(String::new())),
            Err(MonitorTargetError::Invalid)
        ));
        assert!(matches!(
            MonitorTargetSeed::from_config(config(), MonitorTarget::Name("a".into())),
            Err(MonitorTargetError::MissingName)
        ));
        let seed =
            MonitorTargetSeed::from_config(config(), MonitorTarget::Ping("b".into())).unwrap();
        assert!(!format!("{seed:?}").contains("key"));
        let mut client = seed.into_client();
        client.start(Duration::ZERO);
        assert!(
            matches!(client.poll_io(),Some(IoCmd::Dial{target,..}) if target.ipv4()==Some([10,0,0,3]))
        );
        let seed = client.target_seed(MonitorTarget::Rank(0)).unwrap();
        let mut separate = seed.into_client();
        separate.start(Duration::ZERO);
        assert!(
            matches!(separate.poll_io(),Some(IoCmd::Dial{target,..}) if target.ipv4()==Some([10,0,0,2]))
        );
        assert_eq!(client.pinned.as_deref(), Some("noname-b"));
    }
}
