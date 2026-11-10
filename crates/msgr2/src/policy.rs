// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Connection policies and the per-peer-type table (spec 11).
use denc::types::EntityName;

/// CEPH_FEATUREMASK_MSG_ADDR2: always OR'ed into idents' required features.
pub const MSGR2_REQUIRED: u64 = 0x0800_0000_0000_0000;
/// CEPH_FEATURES_ALL / supported default of Ceph main.
pub const FEATURES_SUPPORTED_DEFAULT: u64 = 0x3f17_ffff_fffd_ffff;
/// osd_required (UID | PGID64 | OSDENC).
pub const OSD_REQUIRED: u64 = 0x0000_0000_0000_2201;
/// OSDREPLYMUX (required by the objecter policy).
pub const OSDREPLYMUX: u64 = 0x0000_0000_0000_1000;

/// Per-connection behaviour flags (spec 11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Lossy: no replay, fault after established = reset.
    pub lossy: bool,
    /// Accept-only; never dials back.
    pub server: bool,
    /// Go idle on fault with an empty queue.
    pub standby: bool,
    /// Detect peer session loss: SESSION_RESET full=resetcheck on cookie mismatch.
    pub resetcheck: bool,
    /// Index lossy server-side connections by peer addrvec (new replaces old).
    pub register_lossy_clients: bool,
    /// CEPH_FEATURE_* the peer must support (msgr2 required bit is added on the wire).
    pub features_required: u64,
    /// Lossless only: a session reset / replacement keeps the frames that never reached the wire (spec 10.3 drops them) and queues
    /// them on the next session; sent-unacked frames are still dropped (never replayed: peer state machines are not duplicate
    /// tolerant). For OSD cluster peers (one session table per core, simultaneous dials), restricted per peer by
    /// `SessionTable::set_keep_owed_peers`.
    pub keep_owed: bool,
}

impl Policy {
    const fn mk(l: bool, s: bool, st: bool, rc: bool, reg: bool, req: u64) -> Self {
        Self {
            lossy: l,
            server: s,
            standby: st,
            resetcheck: rc,
            register_lossy_clients: reg,
            features_required: req,
            keep_owed: false,
        }
    }
    /// lossy_client.
    pub const fn lossy_client(req: u64) -> Self {
        Self::mk(true, false, false, false, true, req)
    }
    /// lossless_client.
    pub const fn lossless_client(req: u64) -> Self {
        Self::mk(false, false, false, true, true, req)
    }
    /// lossless_peer.
    pub const fn lossless_peer(req: u64) -> Self {
        Self::mk(false, false, true, false, true, req)
    }
    /// lossless_peer_reuse.
    pub const fn lossless_peer_reuse(req: u64) -> Self {
        Self::mk(false, false, true, true, true, req)
    }
    /// stateful_server.
    pub const fn stateful_server(req: u64) -> Self {
        Self::mk(false, true, true, true, true, req)
    }
    /// stateless_registered_server.
    pub const fn stateless_registered_server(req: u64) -> Self {
        Self::mk(true, true, false, false, true, req)
    }
    /// stateless_server.
    pub const fn stateless_server(req: u64) -> Self {
        Self::mk(true, true, false, false, false, req)
    }
    /// Same policy, but a reset keeps the queued frames (see `keep_owed`).
    pub const fn keeping_owed(mut self) -> Self {
        self.keep_owed = true;
        self
    }
    /// Required features as sent in idents (policy | msgr2_required).
    pub const fn wire_required(&self) -> u64 {
        self.features_required | MSGR2_REQUIRED
    }
}

/// Policy by peer entity type with a default (spec 11 table).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyTable {
    /// Used for peer types without an entry.
    pub default: Policy,
    /// Per peer-type overrides.
    pub by_type: Vec<(u8, Policy)>,
}

impl PolicyTable {
    /// Policy for a peer of entity type `ty`.
    pub fn get(&self, ty: u8) -> Policy {
        self.by_type
            .iter()
            .find(|(t, _)| *t == ty)
            .map_or(self.default, |(_, p)| *p)
    }

    /// Same policy for every peer type.
    pub fn uniform(p: Policy) -> Self {
        Self {
            default: p,
            by_type: Vec::new(),
        }
    }

    /// OSD public ("client") messenger: accepts clients, talks to mon/mgr.
    pub fn osd_public() -> Self {
        Self {
            default: Policy::stateless_registered_server(0),
            by_type: vec![
                (EntityName::MON, Policy::lossy_client(OSD_REQUIRED)),
                (EntityName::MGR, Policy::lossy_client(OSD_REQUIRED)),
            ],
        }
    }
    /// OSD cluster messenger.
    pub fn osd_cluster() -> Self {
        Self {
            default: Policy::stateless_server(0),
            by_type: vec![
                (
                    EntityName::OSD,
                    Policy::lossless_peer(OSD_REQUIRED).keeping_owed(),
                ),
                (EntityName::MON, Policy::lossy_client(0)),
            ],
        }
    }
    /// OSD heartbeat server messengers (hb_front_server / hb_back_server).
    pub fn osd_hb_server() -> Self {
        Self::uniform(Policy::stateless_server(0))
    }
    /// OSD heartbeat client messengers.
    pub fn osd_hb_client() -> Self {
        Self::uniform(Policy::lossy_client(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_match_spec_table() {
        let p = Policy::stateful_server(0);
        assert_eq!(
            (
                p.lossy,
                p.server,
                p.standby,
                p.resetcheck,
                p.register_lossy_clients
            ),
            (false, true, true, true, true)
        );
        let p = Policy::stateless_server(0);
        assert_eq!(
            (
                p.lossy,
                p.server,
                p.standby,
                p.resetcheck,
                p.register_lossy_clients
            ),
            (true, true, false, false, false)
        );
        let p = Policy::lossless_peer(0);
        assert_eq!(
            (
                p.lossy,
                p.server,
                p.standby,
                p.resetcheck,
                p.register_lossy_clients
            ),
            (false, false, true, false, true)
        );
    }

    #[test]
    fn osd_tables() {
        let t = PolicyTable::osd_cluster();
        assert!(!t.get(EntityName::OSD).lossy);
        assert_eq!(
            t.get(EntityName::OSD).wire_required(),
            OSD_REQUIRED | MSGR2_REQUIRED
        );
        assert!(t.get(EntityName::CLIENT).lossy && t.get(EntityName::CLIENT).server);
        assert!(
            PolicyTable::osd_public()
                .get(EntityName::CLIENT)
                .register_lossy_clients
        );
    }
}
