// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! MOSDPG* messages (spec peering.md 4.1) and the [`PeeringMsg`] dispatcher.

use crate::history::PgHistory;
use crate::info::PgInfo;
use crate::intervals::PastIntervals;
use crate::log::PgLog;
use crate::missing::PgMissing;
use crate::peer::{PgLease, PgLeaseAck, PgNotify, PgQuery};
use denc::types::{Eversion, Hobject, PgShard, PgT, ShardId, SpgT, UTime};
use denc::{Decode, Decoder, Encode, Result};
use messages::{Message, Segments, front_segments as front, meta};
use std::collections::BTreeMap;

/// Message type ids.
pub mod ty {
    pub const PG_LOG: u16 = 83;
    pub const PG_REMOVE: u16 = 84;
    pub const PG_TRIM: u16 = 86;
    pub const PG_RECOVERY_DELETE: u16 = 118;
    pub const PG_RECOVERY_DELETE_REPLY: u16 = 119;
    pub const PG_CREATE2: u16 = 120;
    pub const PG_NOTIFY2: u16 = 130;
    pub const PG_QUERY2: u16 = 131;
    pub const PG_INFO2: u16 = 132;
    pub const PG_LEASE: u16 = 133;
    pub const PG_LEASE_ACK: u16 = 134;
    pub const PG_PCT: u16 = 136;
}

/// `CEPH_MSG_PRIO_HIGH`.
pub const PRIO_HIGH: u16 = 196;
/// `CEPH_MSG_PRIO_DEFAULT`.
pub const PRIO_DEFAULT: u16 = 127;

/// MOSDPGNotify2 (130, hv1/hc1): member -> primary.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MOSDPGNotify2 {
    pub spgid: SpgT,
    pub notify: PgNotify,
}
impl Message for MOSDPGNotify2 {
    meta!(ty::PG_NOTIFY2, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        front(f, |e| {
            self.spgid.encode(e)?;
            self.notify.encode(e)
        })
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MOSDPGNotify2 {
            spgid: SpgT::decode(&mut d)?,
            notify: PgNotify::decode(&mut d)?,
        })
    }
}

/// MOSDPGQuery2 (131, hv1/hc1): primary -> member.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDPGQuery2 {
    pub spgid: SpgT,
    pub query: PgQuery,
}
impl Message for MOSDPGQuery2 {
    meta!(ty::PG_QUERY2, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        front(f, |e| {
            self.spgid.encode(e)?;
            self.query.encode(e)
        })
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MOSDPGQuery2 {
            spgid: SpgT::decode(&mut d)?,
            query: PgQuery::decode(&mut d)?,
        })
    }
}

/// MOSDPGInfo2 (132, hv1/hc1): both directions (activation ack, share_pg_info).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MOSDPGInfo2 {
    pub spgid: SpgT,
    pub epoch_sent: u32,
    pub min_epoch: u32,
    pub info: PgInfo,
    pub lease: Option<PgLease>,
    pub lease_ack: Option<PgLeaseAck>,
}
impl Message for MOSDPGInfo2 {
    meta!(ty::PG_INFO2, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        front(f, |e| {
            self.spgid.encode(e)?;
            e.u32(self.epoch_sent)?;
            e.u32(self.min_epoch)?;
            self.info.encode(e)?;
            self.lease.encode(e)?;
            self.lease_ack.encode(e)
        })
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MOSDPGInfo2 {
            spgid: SpgT::decode(&mut d)?,
            epoch_sent: d.u32()?,
            min_epoch: d.u32()?,
            info: PgInfo::decode(&mut d)?,
            lease: Option::decode(&mut d)?,
            lease_ack: Option::decode(&mut d)?,
        })
    }
}

/// MOSDPGLog (83, hv6/hc6): log + info (+ missing) to/from the primary; carries create info.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MOSDPGLog {
    pub epoch: u32,
    pub info: PgInfo,
    pub log: PgLog,
    pub missing: PgMissing,
    pub query_epoch: u32,
    pub past_intervals: PastIntervals,
    pub to: ShardId,
    pub from: ShardId,
    pub lease: Option<PgLease>,
}
impl MOSDPGLog {
    /// The PG this message addresses: `info.pgid.pgid` + our (`to`) shard.
    pub fn spgid(&self) -> SpgT {
        SpgT {
            pgid: self.info.pgid.pgid,
            shard: self.to,
        }
    }
}
impl Message for MOSDPGLog {
    meta!(ty::PG_LOG, 6, 6);
    fn encode(&self, f: u64) -> Result<Segments> {
        front(f, |e| {
            e.u32(self.epoch)?;
            self.info.encode(e)?;
            self.log.encode(e)?;
            self.missing.encode(e)?;
            e.u32(self.query_epoch)?;
            self.past_intervals.encode(e)?;
            self.to.encode(e)?;
            self.from.encode(e)?;
            self.lease.encode(e)
        })
    }
    fn decode(v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        let epoch = d.u32()?;
        let info = PgInfo::decode(&mut d)?;
        let log = PgLog::decode(&mut d)?;
        let missing = PgMissing::decode(&mut d)?;
        let query_epoch = d.u32()?;
        let past_intervals = if v >= 5 {
            PastIntervals::decode(&mut d)?
        } else {
            PastIntervals::default()
        };
        let (to, from) = if v >= 4 {
            (ShardId::decode(&mut d)?, ShardId::decode(&mut d)?)
        } else {
            Default::default()
        };
        let lease = if v >= 6 {
            Option::decode(&mut d)?
        } else {
            None
        };
        Ok(MOSDPGLog {
            epoch,
            info,
            log,
            missing,
            query_epoch,
            past_intervals,
            to,
            from,
            lease,
        })
    }
}

/// MOSDPGLease (133, hv1/hc1): primary -> replicas.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDPGLease {
    pub epoch: u32,
    pub spgid: SpgT,
    pub lease: PgLease,
}
impl Message for MOSDPGLease {
    meta!(ty::PG_LEASE, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        front(f, |e| {
            e.u32(self.epoch)?;
            self.spgid.encode(e)?;
            self.lease.encode(e)
        })
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MOSDPGLease {
            epoch: d.u32()?,
            spgid: SpgT::decode(&mut d)?,
            lease: PgLease::decode(&mut d)?,
        })
    }
}

/// MOSDPGLeaseAck (134, hv1/hc1): replica -> primary.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDPGLeaseAck {
    pub epoch: u32,
    pub spgid: SpgT,
    pub lease_ack: PgLeaseAck,
}
impl Message for MOSDPGLeaseAck {
    meta!(ty::PG_LEASE_ACK, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        front(f, |e| {
            e.u32(self.epoch)?;
            self.spgid.encode(e)?;
            self.lease_ack.encode(e)
        })
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MOSDPGLeaseAck {
            epoch: d.u32()?,
            spgid: SpgT::decode(&mut d)?,
            lease_ack: PgLeaseAck::decode(&mut d)?,
        })
    }
}

/// MOSDPGPCT (136, hv1/hc1): primary -> replicas, idle `pg_committed_to` update.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDPGPCT {
    pub map_epoch: u32,
    pub min_epoch: u32,
    pub spgid: SpgT,
    pub pg_committed_to: Eversion,
}
impl Message for MOSDPGPCT {
    meta!(ty::PG_PCT, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        front(f, |e| {
            e.u32(self.map_epoch)?;
            e.u32(self.min_epoch)?;
            self.spgid.encode(e)?;
            self.pg_committed_to.encode(e)
        })
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MOSDPGPCT {
            map_epoch: d.u32()?,
            min_epoch: d.u32()?,
            spgid: SpgT::decode(&mut d)?,
            pg_committed_to: Eversion::decode(&mut d)?,
        })
    }
}

/// MOSDPGTrim (86, hv2/hc2). Dual meaning chosen by receiver state (peering.md 4.2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDPGTrim {
    pub epoch: u32,
    pub pgid: PgT,
    pub trim_to: Eversion,
    pub shard: ShardId,
}
impl Message for MOSDPGTrim {
    meta!(ty::PG_TRIM, 2, 2);
    fn encode(&self, f: u64) -> Result<Segments> {
        front(f, |e| {
            e.u32(self.epoch)?;
            self.pgid.encode(e)?;
            self.trim_to.encode(e)?;
            self.shard.encode(e)
        })
    }
    fn decode(v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MOSDPGTrim {
            epoch: d.u32()?,
            pgid: PgT::decode(&mut d)?,
            trim_to: Eversion::decode(&mut d)?,
            shard: if v >= 2 {
                ShardId::decode(&mut d)?
            } else {
                ShardId::NO_SHARD
            },
        })
    }
}

/// MOSDPGRemove (84, hv3/hc3): primary -> stray.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDPGRemove {
    pub epoch: u32,
    pub pgs: Vec<SpgT>,
}
impl Message for MOSDPGRemove {
    meta!(ty::PG_REMOVE, 3, 3);
    fn encode(&self, f: u64) -> Result<Segments> {
        front(f, |e| {
            e.u32(self.epoch)?;
            self.pgs.encode(e)
        })
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MOSDPGRemove {
            epoch: d.u32()?,
            pgs: Vec::decode(&mut d)?,
        })
    }
}

/// MOSDPGCreate2 (120, hv2/hc1): mon -> OSD.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MOSDPGCreate2 {
    pub epoch: u32,
    /// pg -> (epoch created, stamp).
    pub pgs: BTreeMap<SpgT, (u32, UTime)>,
    /// pg -> (history, past intervals); an entry is required for every pg (hv>=2).
    pub pg_extra: BTreeMap<SpgT, (PgHistory, PastIntervals)>,
}
impl Message for MOSDPGCreate2 {
    meta!(ty::PG_CREATE2, 2, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        front(f, |e| {
            e.u32(self.epoch)?;
            self.pgs.encode(e)?;
            self.pg_extra.encode(e)
        })
    }
    fn decode(v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        let epoch = d.u32()?;
        let pgs = BTreeMap::decode(&mut d)?;
        let pg_extra = if v >= 2 {
            BTreeMap::decode(&mut d)?
        } else {
            BTreeMap::new()
        };
        Ok(MOSDPGCreate2 {
            epoch,
            pgs,
            pg_extra,
        })
    }
}

/// MOSDPGRecoveryDelete (118, hv2/hc1): primary -> replica [M5].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDPGRecoveryDelete {
    pub from: PgShard,
    pub pgid: SpgT,
    pub map_epoch: u32,
    pub min_epoch: u32,
    pub cost: u64,
    pub objects: Vec<(Hobject, Eversion)>,
}
impl Message for MOSDPGRecoveryDelete {
    meta!(ty::PG_RECOVERY_DELETE, 2, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        front(f, |e| {
            self.from.encode(e)?;
            self.pgid.encode(e)?;
            e.u32(self.map_epoch)?;
            e.u32(self.min_epoch)?;
            e.u64(self.cost)?;
            self.objects.encode(e)
        })
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MOSDPGRecoveryDelete {
            from: PgShard::decode(&mut d)?,
            pgid: SpgT::decode(&mut d)?,
            map_epoch: d.u32()?,
            min_epoch: d.u32()?,
            cost: d.u64()?,
            objects: Vec::decode(&mut d)?,
        })
    }
}

/// MOSDPGRecoveryDeleteReply (119, hv2/hc1): replica -> primary [M5].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDPGRecoveryDeleteReply {
    pub pgid: PgT,
    pub map_epoch: u32,
    pub min_epoch: u32,
    pub objects: Vec<(Hobject, Eversion)>,
    pub shard: ShardId,
    pub from: PgShard,
}
impl Message for MOSDPGRecoveryDeleteReply {
    meta!(ty::PG_RECOVERY_DELETE_REPLY, 2, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        front(f, |e| {
            self.pgid.encode(e)?;
            e.u32(self.map_epoch)?;
            e.u32(self.min_epoch)?;
            self.objects.encode(e)?;
            self.shard.encode(e)?;
            self.from.encode(e)
        })
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MOSDPGRecoveryDeleteReply {
            pgid: PgT::decode(&mut d)?,
            map_epoch: d.u32()?,
            min_epoch: d.u32()?,
            objects: Vec::decode(&mut d)?,
            shard: ShardId::decode(&mut d)?,
            from: PgShard::decode(&mut d)?,
        })
    }
}

messages::message_enum! {
    /// Any peering message of this crate.
    #[derive(Debug, Clone, PartialEq)]
    pub enum PeeringMsg {
    MOSDPGNotify2 => MOSDPGNotify2,
    MOSDPGQuery2 => MOSDPGQuery2,
    MOSDPGInfo2 => MOSDPGInfo2,
    MOSDPGLog => MOSDPGLog,
    MOSDPGLease => MOSDPGLease,
    MOSDPGLeaseAck => MOSDPGLeaseAck,
    MOSDPGPCT => MOSDPGPCT,
    MOSDPGTrim => MOSDPGTrim,
    MOSDPGRemove => MOSDPGRemove,
    MOSDPGCreate2 => MOSDPGCreate2,
    MOSDPGRecoveryDelete => MOSDPGRecoveryDelete,
    MOSDPGRecoveryDeleteReply => MOSDPGRecoveryDeleteReply,
    }
}

/// Decode a peering message by header type id / header version. `None` = not one of ours.
pub fn decode_peering(msg_type: u16, version: u16, seg: &Segments) -> Option<Result<PeeringMsg>> {
    let front = match seg.front_bytes() {
        Ok(f) => f,
        Err(e) => return Some(Err(e)),
    };
    PeeringMsg::decode_known(msg_type, version, &front, &seg.middle, &seg.data)
}

impl PeeringMsg {
    /// Epoch gating pair `(map_epoch, min_epoch)` (peering.md 4.1 / 4.3).
    pub fn gating(&self) -> (u32, u32) {
        match self {
            PeeringMsg::MOSDPGNotify2(m) => (m.notify.epoch_sent, m.notify.query_epoch),
            PeeringMsg::MOSDPGQuery2(m) => (m.query.epoch_sent, m.query.epoch_sent),
            PeeringMsg::MOSDPGInfo2(m) => (m.epoch_sent, m.min_epoch),
            PeeringMsg::MOSDPGLog(m) => (m.epoch, m.query_epoch),
            PeeringMsg::MOSDPGLease(m) => (m.epoch, m.epoch),
            PeeringMsg::MOSDPGLeaseAck(m) => (m.epoch, m.epoch),
            PeeringMsg::MOSDPGPCT(m) => (m.map_epoch, m.min_epoch),
            PeeringMsg::MOSDPGTrim(m) => (m.epoch, m.epoch),
            PeeringMsg::MOSDPGRemove(m) => (m.epoch, m.epoch),
            PeeringMsg::MOSDPGCreate2(m) => (m.epoch, m.epoch),
            PeeringMsg::MOSDPGRecoveryDelete(m) => (m.map_epoch, m.min_epoch),
            PeeringMsg::MOSDPGRecoveryDeleteReply(m) => (m.map_epoch, m.min_epoch),
        }
    }

    /// Stamp `epoch` (the sender's map epoch at send time) as the message's map epoch. Only the "sent at" fields
    /// move; `min_epoch`/`query_epoch` echoes keep naming the interval they belong to.
    pub fn restamp(&mut self, epoch: u32) {
        match self {
            PeeringMsg::MOSDPGNotify2(m) => {
                if m.notify.query_epoch == m.notify.epoch_sent {
                    m.notify.query_epoch = epoch;
                }
                m.notify.epoch_sent = epoch;
            }
            PeeringMsg::MOSDPGQuery2(m) => m.query.epoch_sent = epoch,
            PeeringMsg::MOSDPGInfo2(m) => m.epoch_sent = epoch,
            PeeringMsg::MOSDPGLog(m) => m.epoch = epoch,
            PeeringMsg::MOSDPGLease(m) => m.epoch = epoch,
            PeeringMsg::MOSDPGLeaseAck(m) => m.epoch = epoch,
            _ => {}
        }
    }

    /// Target PG when the message addresses exactly one (not Remove/Create2).
    pub fn spgid(&self) -> Option<SpgT> {
        Some(match self {
            PeeringMsg::MOSDPGNotify2(m) => m.spgid,
            PeeringMsg::MOSDPGQuery2(m) => m.spgid,
            PeeringMsg::MOSDPGInfo2(m) => m.spgid,
            PeeringMsg::MOSDPGLog(m) => m.spgid(),
            PeeringMsg::MOSDPGLease(m) => m.spgid,
            PeeringMsg::MOSDPGLeaseAck(m) => m.spgid,
            PeeringMsg::MOSDPGPCT(m) => m.spgid,
            PeeringMsg::MOSDPGTrim(m) => SpgT {
                pgid: m.pgid,
                shard: m.shard,
            },
            PeeringMsg::MOSDPGRecoveryDelete(m) => m.pgid,
            PeeringMsg::MOSDPGRecoveryDeleteReply(m) => SpgT {
                pgid: m.pgid,
                shard: m.shard,
            },
            PeeringMsg::MOSDPGRemove(_) | PeeringMsg::MOSDPGCreate2(_) => return None,
        })
    }

    /// Messenger priority the sender sets (HIGH for Notify2/Query2/Info2/PGLog).
    pub fn priority(&self) -> u16 {
        match self {
            PeeringMsg::MOSDPGNotify2(_)
            | PeeringMsg::MOSDPGQuery2(_)
            | PeeringMsg::MOSDPGInfo2(_)
            | PeeringMsg::MOSDPGLog(_) => PRIO_HIGH,
            _ => PRIO_DEFAULT,
        }
    }
}
