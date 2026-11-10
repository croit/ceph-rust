// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Replication data-path messages (spec replication.md 3, 6, 7). Opaque payload pieces owned by
//! `pgwire` (pg_log_entry_t vectors, pg_stat_t, object_stat_collection_t, hit set history) are kept
//! as raw bytes including their own envelope; the osd layer decodes them.

use crate::recovery::{PullOp, PushOp, PushReplyOp};
use crate::txn::Transaction;
use bytes::Bytes;
use denc::types::{Eversion, Hobject, OsdReqId, PgShard, PgT, ShardId, SpgT};
use denc::{Decode, Decoder, Encode, Encoder, Error, Result};
use messages::{Message, Segments, front_with as front, meta};

/// Message type ids.
pub mod ty {
    pub const SCAN: u16 = 94;
    pub const BACKFILL: u16 = 95;
    pub const BACKFILL_REMOVE: u16 = 96;
    pub const BACKFILL_RESERVE: u16 = 99;
    pub const PUSH: u16 = 105;
    pub const PULL: u16 = 106;
    pub const PUSH_REPLY: u16 = 107;
    pub const REPOP: u16 = 112;
    pub const REPOP_REPLY: u16 = 113;
    pub const UPDATE_LOG_MISSING: u16 = 114;
    pub const UPDATE_LOG_MISSING_REPLY: u16 = 115;
    pub const RECOVERY_DELETE: u16 = 118;
    pub const RECOVERY_DELETE_REPLY: u16 = 119;
    pub const PCT: u16 = 136;
    pub const RECOVERY_RESERVE: u16 = 150;
    pub const FORCE_RECOVERY: u16 = 151;
}

/// Check that `b` is exactly one envelope.
fn check_env(b: &[u8]) -> Result<()> {
    let mut d = Decoder::new(b);
    d.envelope_raw()?;
    if d.is_empty() {
        Ok(())
    } else {
        Err(Error::BadValue("opaque envelope blob"))
    }
}

fn check_env_vec(b: &[u8]) -> Result<()> {
    let mut d = Decoder::new(b);
    d.envelope_vec_raw()?;
    if d.is_empty() {
        Ok(())
    } else {
        Err(Error::BadValue("opaque envelope vec blob"))
    }
}

/// An empty `vec<T>` (u32 0) for opaque entry vectors.
pub const EMPTY_VEC: [u8; 4] = [0; 4];

fn put_trace<B: denc::BufMut>(e: &mut Encoder<B>, t: &[i64; 3]) -> Result<()> {
    t.iter().try_for_each(|&x| e.i64(x))
}
fn get_trace(d: &mut Decoder<'_>) -> Result<[i64; 3]> {
    Ok([d.i64()?, d.i64()?, d.i64()?])
}

/// pg_t raw + shard later: shared split-pgid helpers.
fn spg(pg: PgT, shard: i8) -> SpgT {
    SpgT {
        pgid: pg,
        shard: ShardId(shard),
    }
}

type ObjVer = Vec<(Hobject, Eversion)>;

/// Known crc of a transaction blob (fused with its payload copy), owner-bound: see [`crc::CrcHint`].
pub use crc::CrcHint as BlobCrc;

/// MOSDRepOp (112, hv3 hc1). The transaction travels in the middle/data segments.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDRepOp {
    pub map_epoch: u32,
    pub min_epoch: u32,
    pub trace: [i64; 3],
    pub reqid: OsdReqId,
    pub pgid: SpgT,
    pub poid: Hobject,
    pub acks_wanted: u8,
    /// Version of the last log entry = new last_update.
    pub version: Eversion,
    /// Raw `vec<pg_log_entry_t>` (u32 n + enveloped entries); wire form is `bl` around it.
    pub logbl: Bytes,
    /// Raw pg_stat_t envelope.
    pub pg_stats: Bytes,
    pub pg_trim_to: Eversion,
    pub new_temp_oid: Hobject,
    pub discard_temp_oid: Hobject,
    pub from: PgShard,
    /// Raw pg_hit_set_history_t envelope (cache tiering only).
    pub updated_hit_set_history: Option<Vec<u8>>,
    pub pg_committed_to: Eversion,
    /// MIDDLE segment.
    pub txn_middle: Bytes,
    /// DATA segment.
    pub txn_data: Bytes,
    /// Known crc of `txn_data` (see [`BlobCrc`]); never decoded.
    pub txn_data_crc: BlobCrc,
    /// LOCAL only (never decoded): further parts of the DATA segment, which is `txn_data` ++ these (a large write
    /// payload shared with the client request between small encoded pieces, `Transaction::encode_v9_rope`). The
    /// cluster send path moves them into the msgr2 frame by reference; [`Message::encode`] concatenates them (copy).
    pub txn_data_more: Vec<(Bytes, BlobCrc)>,
}

/// msgr2 header `data_off` of a MOSDRepOp: its data segment is the v9 transaction blob, the first write payload at
/// [`crate::txn::PAYLOAD_AT`]; `-PAYLOAD_AT` makes a placing receiver (`msgr2::Decoder::set_rx_place`, spec msgr2.md
/// 3.1) put that payload on a 4 KiB boundary. Classic receivers ignore `data_off` in msgr2 (adr 0061 am. 7).
pub const REPOP_DATA_OFF: u16 = 0u16.wrapping_sub(crate::txn::PAYLOAD_AT as u16);

impl MOSDRepOp {
    pub const ACK_ONDISK: u8 = 4;
    pub const ACK_ACK: u8 = 1;

    /// Store `t` as a v9 transaction in the DATA segment (spec 1.1 win).
    pub fn set_txn(&mut self, t: &Transaction<'_>) -> Result<()> {
        self.txn_middle = Bytes::new();
        self.txn_data = t.encode_v9()?.into();
        Ok(())
    }
    /// Decode the shipped transaction (borrows this message).
    pub fn txn(&self, page: usize) -> Result<Transaction<'_>> {
        Transaction::decode(&self.txn_middle, &self.txn_data, page)
    }
}

impl Message for MOSDRepOp {
    meta!(112, 3, 1, oldest 3);
    fn encode(&self, f: u64) -> Result<Segments> {
        if !self.logbl.is_empty() {
            check_env_vec(&self.logbl)?;
        }
        check_env(&self.pg_stats)?;
        let fr = front(f, |e| {
            e.u32(self.map_epoch)?;
            e.u32(self.min_epoch)?;
            put_trace(e, &self.trace)?;
            self.reqid.encode(e)?;
            self.pgid.encode(e)?;
            self.poid.encode(e)?;
            e.u8(self.acks_wanted)?;
            self.version.encode(e)?;
            e.bytes(&self.logbl)?;
            e.raw(&self.pg_stats)?;
            self.pg_trim_to.encode(e)?;
            self.new_temp_oid.encode(e)?;
            self.discard_temp_oid.encode(e)?;
            self.from.encode(e)?;
            match &self.updated_hit_set_history {
                None => e.u8(0)?,
                Some(h) => {
                    check_env(h)?;
                    e.u8(1)?;
                    e.raw(h)?;
                }
            }
            self.pg_committed_to.encode(e)
        })?;
        Ok(Segments {
            front_zc: Vec::new(),
            front_hints: Default::default(),
            front: fr,
            middle: self.txn_middle.to_vec(),
            data: if self.txn_data_more.is_empty() {
                self.txn_data.clone()
            } else {
                flat_parts(&self.txn_data, &self.txn_data_more)
            },
        })
    }
    fn decode(version: u16, front: &[u8], middle: &[u8], data: &[u8]) -> Result<Self> {
        Self::decode_shared(
            version,
            front,
            Bytes::copy_from_slice(middle),
            Bytes::copy_from_slice(data),
        )
    }
}

impl MOSDRepOp {
    /// The PG of a repop whose data segment has not arrived yet (receiver-side pre-write, adr 0477): the front's
    /// leading fields as [`decode_shared`](Self::decode_shared) parses them. Unverified (the front crc comes with the
    /// frame end): a hint, never a decision.
    pub fn peek_pgid(version: u16, front: &[u8]) -> Result<SpgT> {
        Self::check_version(version)?;
        let mut d = Decoder::new(front);
        d.u32()?;
        d.u32()?;
        get_trace(&mut d)?;
        OsdReqId::decode(&mut d)?;
        SpgT::decode(&mut d)
    }

    /// Decode with the transaction segments kept as shared slices (no copy).
    pub fn decode_shared(version: u16, front: &[u8], middle: Bytes, data: Bytes) -> Result<Self> {
        Self::check_version(version)?;
        let mut d = Decoder::new(front);
        Ok(MOSDRepOp {
            map_epoch: d.u32()?,
            min_epoch: d.u32()?,
            trace: get_trace(&mut d)?,
            reqid: OsdReqId::decode(&mut d)?,
            pgid: SpgT::decode(&mut d)?,
            poid: Hobject::decode(&mut d)?,
            acks_wanted: d.u8()?,
            version: Eversion::decode(&mut d)?,
            logbl: Bytes::copy_from_slice(d.bytes()?),
            pg_stats: Bytes::copy_from_slice(d.envelope_raw()?),
            pg_trim_to: Eversion::decode(&mut d)?,
            new_temp_oid: Hobject::decode(&mut d)?,
            discard_temp_oid: Hobject::decode(&mut d)?,
            from: PgShard::decode(&mut d)?,
            updated_hit_set_history: if d.u8()? != 0 {
                Some(d.envelope_raw()?.to_vec())
            } else {
                None
            },
            pg_committed_to: Eversion::decode(&mut d)?,
            txn_middle: middle,
            txn_data: data,
            txn_data_crc: BlobCrc::default(),
            txn_data_more: Vec::new(),
        })
    }
}

/// MOSDRepOpReply (113, hv2 hc1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDRepOpReply {
    pub map_epoch: u32,
    pub min_epoch: u32,
    pub trace: [i64; 3],
    pub reqid: OsdReqId,
    pub pgid: SpgT,
    /// `CEPH_OSD_FLAG_ONDISK` = 4.
    pub ack_type: u8,
    pub result: i32,
    pub last_complete_ondisk: Eversion,
    pub from: PgShard,
}
impl Message for MOSDRepOpReply {
    meta!(113, 2, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front(f, |e| {
            e.u32(self.map_epoch)?;
            e.u32(self.min_epoch)?;
            put_trace(e, &self.trace)?;
            self.reqid.encode(e)?;
            self.pgid.encode(e)?;
            e.u8(self.ack_type)?;
            e.i32(self.result)?;
            self.last_complete_ondisk.encode(e)?;
            self.from.encode(e)
        })?))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MOSDRepOpReply {
            map_epoch: d.u32()?,
            min_epoch: d.u32()?,
            trace: get_trace(&mut d)?,
            reqid: OsdReqId::decode(&mut d)?,
            pgid: SpgT::decode(&mut d)?,
            ack_type: d.u8()?,
            result: d.i32()?,
            last_complete_ondisk: Eversion::decode(&mut d)?,
            from: PgShard::decode(&mut d)?,
        })
    }
}

/// MOSDPGUpdateLogMissing (114, hv3 hc1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MOSDPGUpdateLogMissing {
    pub map_epoch: u32,
    pub pgid: SpgT,
    pub from: ShardId,
    pub rep_tid: u64,
    /// Raw `vec<pg_log_entry_t>` (u32 n + enveloped entries).
    pub entries: Vec<u8>,
    pub min_epoch: u32,
    pub pg_trim_to: Eversion,
    pub pg_committed_to: Eversion,
}
impl Default for MOSDPGUpdateLogMissing {
    fn default() -> Self {
        MOSDPGUpdateLogMissing {
            map_epoch: 0,
            pgid: SpgT::default(),
            from: ShardId::NO_SHARD,
            rep_tid: 0,
            entries: EMPTY_VEC.to_vec(),
            min_epoch: 0,
            pg_trim_to: Eversion::default(),
            pg_committed_to: Eversion::default(),
        }
    }
}
impl Message for MOSDPGUpdateLogMissing {
    meta!(114, 3, 1, oldest 3);
    fn encode(&self, f: u64) -> Result<Segments> {
        check_env_vec(&self.entries)?;
        Ok(Segments::front(front(f, |e| {
            e.u32(self.map_epoch)?;
            self.pgid.encode(e)?;
            self.from.encode(e)?;
            e.u64(self.rep_tid)?;
            e.raw(&self.entries)?;
            e.u32(self.min_epoch)?;
            self.pg_trim_to.encode(e)?;
            self.pg_committed_to.encode(e)
        })?))
    }
    fn decode(version: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        Self::check_version(version)?;
        let mut d = Decoder::new(front);
        Ok(MOSDPGUpdateLogMissing {
            map_epoch: d.u32()?,
            pgid: SpgT::decode(&mut d)?,
            from: ShardId::decode(&mut d)?,
            rep_tid: d.u64()?,
            entries: d.envelope_vec_raw()?.to_vec(),
            // v3 layout: all three fields are part of the message (spec replication.md 3.4)
            min_epoch: d.u32()?,
            pg_trim_to: Eversion::decode(&mut d)?,
            pg_committed_to: Eversion::decode(&mut d)?,
        })
    }
}

/// MOSDPGUpdateLogMissingReply (115, hv3 hc1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDPGUpdateLogMissingReply {
    pub map_epoch: u32,
    pub pgid: SpgT,
    pub from: ShardId,
    pub rep_tid: u64,
    pub min_epoch: u32,
    pub last_complete_ondisk: Eversion,
}
impl Message for MOSDPGUpdateLogMissingReply {
    meta!(115, 3, 1, oldest 3);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front(f, |e| {
            e.u32(self.map_epoch)?;
            self.pgid.encode(e)?;
            self.from.encode(e)?;
            e.u64(self.rep_tid)?;
            e.u32(self.min_epoch)?;
            self.last_complete_ondisk.encode(e)
        })?))
    }
    fn decode(version: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        Self::check_version(version)?;
        let mut d = Decoder::new(front);
        Ok(MOSDPGUpdateLogMissingReply {
            map_epoch: d.u32()?,
            pgid: SpgT::decode(&mut d)?,
            from: ShardId::decode(&mut d)?,
            rep_tid: d.u64()?,
            // v3 layout: both fields are part of the message (spec replication.md 3.4)
            min_epoch: d.u32()?,
            last_complete_ondisk: Eversion::decode(&mut d)?,
        })
    }
}

/// MOSDPGPCT (136, hv1 hc1; tentacle): primary -> replica "pg committed to" update.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDPGPCT {
    pub map_epoch: u32,
    pub min_epoch: u32,
    pub pgid: SpgT,
    pub pg_committed_to: Eversion,
}
impl Message for MOSDPGPCT {
    meta!(136, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front(f, |e| {
            e.u32(self.map_epoch)?;
            e.u32(self.min_epoch)?;
            self.pgid.encode(e)?;
            self.pg_committed_to.encode(e)
        })?))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MOSDPGPCT {
            map_epoch: d.u32()?,
            min_epoch: d.u32()?,
            pgid: SpgT::decode(&mut d)?,
            pg_committed_to: Eversion::decode(&mut d)?,
        })
    }
}

/// MOSDPGPush (105, hv4 hc2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDPGPush {
    pub pgid: SpgT,
    pub map_epoch: u32,
    pub pushes: Vec<PushOp>,
    /// Local throttle hint; copy but ignore.
    pub cost: u64,
    pub from: PgShard,
    pub min_epoch: u32,
    pub is_repair: bool,
}
impl MOSDPGPush {
    /// Decode from a received shared front segment ([`messages::Segments::front_shared`]): the push payloads stay
    /// slices of the rx buffer, no copy of every recovered byte.
    pub fn decode_shared(version: u16, front: &Bytes) -> Result<Self> {
        Self::decode_inner(version, front, Some(front))
    }

    fn decode_inner(version: u16, front: &[u8], shared: Option<&Bytes>) -> Result<Self> {
        let mut d = Decoder::new(front);
        let pg = PgT::decode(&mut d)?;
        let map_epoch = d.u32()?;
        let n = d.count()?;
        let mut pushes = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            pushes.push(PushOp::decode_in(&mut d, shared)?);
        }
        let cost = d.u64()?;
        let shard = d.i8()?;
        let from = PgShard::decode(&mut d)?;
        Ok(MOSDPGPush {
            pgid: spg(pg, shard),
            map_epoch,
            pushes,
            cost,
            from,
            min_epoch: if version >= 3 { d.u32()? } else { 0 },
            is_repair: if version >= 4 { d.bool()? } else { false },
        })
    }
}

impl Message for MOSDPGPush {
    meta!(105, 4, 2);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front(f, |e| {
            self.pgid.pgid.encode(e)?;
            e.u32(self.map_epoch)?;
            self.pushes.encode(e)?;
            e.u64(self.cost)?;
            self.pgid.shard.encode(e)?;
            self.from.encode(e)?;
            e.u32(self.min_epoch)?;
            e.bool(self.is_repair)
        })?))
    }
    fn decode(v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        Self::decode_inner(v, front, None)
    }
}

/// MOSDPGPushReply (107, hv3 hc2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDPGPushReply {
    pub pgid: SpgT,
    pub map_epoch: u32,
    pub replies: Vec<PushReplyOp>,
    pub cost: u64,
    pub from: PgShard,
    pub min_epoch: u32,
}
impl Message for MOSDPGPushReply {
    meta!(107, 3, 2);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front(f, |e| {
            self.pgid.pgid.encode(e)?;
            e.u32(self.map_epoch)?;
            self.replies.encode(e)?;
            e.u64(self.cost)?;
            self.pgid.shard.encode(e)?;
            self.from.encode(e)?;
            e.u32(self.min_epoch)
        })?))
    }
    fn decode(v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        let pg = PgT::decode(&mut d)?;
        let map_epoch = d.u32()?;
        let replies = Vec::<PushReplyOp>::decode(&mut d)?;
        let cost = d.u64()?;
        let shard = d.i8()?;
        let from = PgShard::decode(&mut d)?;
        Ok(MOSDPGPushReply {
            pgid: spg(pg, shard),
            map_epoch,
            replies,
            cost,
            from,
            min_epoch: if v >= 3 { d.u32()? } else { 0 },
        })
    }
}

/// MOSDPGPull (106, hv3 hc2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDPGPull {
    pub pgid: SpgT,
    pub map_epoch: u32,
    pub pulls: Vec<PullOp>,
    pub cost: u64,
    pub from: PgShard,
    pub min_epoch: u32,
}
impl Message for MOSDPGPull {
    meta!(106, 3, 2);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front(f, |e| {
            self.pgid.pgid.encode(e)?;
            e.u32(self.map_epoch)?;
            self.pulls.encode(e)?;
            e.u64(self.cost)?;
            self.pgid.shard.encode(e)?;
            self.from.encode(e)?;
            e.u32(self.min_epoch)
        })?))
    }
    fn decode(v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        let pg = PgT::decode(&mut d)?;
        let map_epoch = d.u32()?;
        let pulls = Vec::<PullOp>::decode(&mut d)?;
        let cost = d.u64()?;
        let shard = d.i8()?;
        let from = PgShard::decode(&mut d)?;
        Ok(MOSDPGPull {
            pgid: spg(pg, shard),
            map_epoch,
            pulls,
            cost,
            from,
            min_epoch: if v >= 3 { d.u32()? } else { 0 },
        })
    }
}

/// MOSDPGRecoveryDelete (118, hv2 hc1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDPGRecoveryDelete {
    pub from: PgShard,
    pub pgid: SpgT,
    pub map_epoch: u32,
    pub min_epoch: u32,
    pub cost: u64,
    pub objects: ObjVer,
}
impl Message for MOSDPGRecoveryDelete {
    meta!(118, 2, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front(f, |e| {
            self.from.encode(e)?;
            self.pgid.encode(e)?;
            e.u32(self.map_epoch)?;
            e.u32(self.min_epoch)?;
            e.u64(self.cost)?;
            self.objects.encode(e)
        })?))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MOSDPGRecoveryDelete {
            from: PgShard::decode(&mut d)?,
            pgid: SpgT::decode(&mut d)?,
            map_epoch: d.u32()?,
            min_epoch: d.u32()?,
            cost: d.u64()?,
            objects: ObjVer::decode(&mut d)?,
        })
    }
}

/// MOSDPGRecoveryDeleteReply (119, hv2 hc1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDPGRecoveryDeleteReply {
    pub pgid: SpgT,
    pub map_epoch: u32,
    pub min_epoch: u32,
    pub objects: ObjVer,
    pub from: PgShard,
}
impl Message for MOSDPGRecoveryDeleteReply {
    meta!(119, 2, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front(f, |e| {
            self.pgid.pgid.encode(e)?;
            e.u32(self.map_epoch)?;
            e.u32(self.min_epoch)?;
            self.objects.encode(e)?;
            self.pgid.shard.encode(e)?;
            self.from.encode(e)
        })?))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        let pg = PgT::decode(&mut d)?;
        let map_epoch = d.u32()?;
        let min_epoch = d.u32()?;
        let objects = ObjVer::decode(&mut d)?;
        let shard = d.i8()?;
        Ok(MOSDPGRecoveryDeleteReply {
            pgid: spg(pg, shard),
            map_epoch,
            min_epoch,
            objects,
            from: PgShard::decode(&mut d)?,
        })
    }
}

/// MOSDPGScan (94, hv2 hc2). The DIGEST reply carries `map<hobject_t, eversion_t>` in DATA.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDPGScan {
    pub op: u32,
    pub map_epoch: u32,
    pub query_epoch: u32,
    pub pgid: SpgT,
    pub begin: Hobject,
    pub end: Hobject,
    pub from: PgShard,
    /// Sorted (hobject, version) pairs; `None` = empty DATA segment (GET_DIGEST).
    pub digest: Option<ObjVer>,
}
impl MOSDPGScan {
    pub const OP_GET_DIGEST: u32 = 1;
    pub const OP_DIGEST: u32 = 2;
}
impl Message for MOSDPGScan {
    meta!(94, 2, 2);
    fn encode(&self, f: u64) -> Result<Segments> {
        let fr = front(f, |e| {
            e.u32(self.op)?;
            e.u32(self.map_epoch)?;
            e.u32(self.query_epoch)?;
            self.pgid.pgid.encode(e)?;
            self.begin.encode(e)?;
            self.end.encode(e)?;
            self.from.encode(e)?;
            self.pgid.shard.encode(e)
        })?;
        let data = match &self.digest {
            None => Vec::new(),
            Some(m) => front(f, |e| m.encode(e))?,
        };
        Ok(Segments {
            front_zc: Vec::new(),
            front_hints: Default::default(),
            front: fr,
            middle: Vec::new(),
            data: data.into(),
        })
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], data: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        let op = d.u32()?;
        let map_epoch = d.u32()?;
        let query_epoch = d.u32()?;
        let pg = PgT::decode(&mut d)?;
        let begin = Hobject::decode(&mut d)?;
        let end = Hobject::decode(&mut d)?;
        let from = PgShard::decode(&mut d)?;
        let shard = d.i8()?;
        let digest = if data.is_empty() {
            None
        } else {
            Some(denc::from_slice::<ObjVer>(data)?)
        };
        Ok(MOSDPGScan {
            op,
            map_epoch,
            query_epoch,
            pgid: spg(pg, shard),
            begin,
            end,
            from,
            digest,
        })
    }
}

/// MOSDPGBackfill (95, hv3 hc3).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDPGBackfill {
    pub op: u32,
    pub map_epoch: u32,
    pub query_epoch: u32,
    pub pgid: SpgT,
    pub last_backfill: Hobject,
    /// Raw object_stat_collection_t envelope (`stats.stats`, compat copy).
    pub compat_stats: Vec<u8>,
    /// Raw pg_stat_t envelope.
    pub stats: Vec<u8>,
}
impl MOSDPGBackfill {
    pub const OP_PROGRESS: u32 = 2;
    pub const OP_FINISH: u32 = 3;
    pub const OP_FINISH_ACK: u32 = 4;
}
impl Message for MOSDPGBackfill {
    meta!(95, 3, 3);
    fn encode(&self, f: u64) -> Result<Segments> {
        check_env(&self.compat_stats)?;
        check_env(&self.stats)?;
        Ok(Segments::front(front(f, |e| {
            e.u32(self.op)?;
            e.u32(self.map_epoch)?;
            e.u32(self.query_epoch)?;
            self.pgid.pgid.encode(e)?;
            self.last_backfill.encode(e)?;
            e.raw(&self.compat_stats)?;
            e.raw(&self.stats)?;
            self.pgid.shard.encode(e)
        })?))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        let op = d.u32()?;
        let map_epoch = d.u32()?;
        let query_epoch = d.u32()?;
        let pg = PgT::decode(&mut d)?;
        let last_backfill = Hobject::decode(&mut d)?;
        let compat_stats = d.envelope_raw()?.to_vec();
        let stats = d.envelope_raw()?.to_vec();
        let shard = d.i8()?;
        Ok(MOSDPGBackfill {
            op,
            map_epoch,
            query_epoch,
            pgid: spg(pg, shard),
            last_backfill,
            compat_stats,
            stats,
        })
    }
}

/// MOSDPGBackfillRemove (96, hv1 hc1); no reply.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDPGBackfillRemove {
    pub pgid: SpgT,
    pub map_epoch: u32,
    pub ls: ObjVer,
}
impl Message for MOSDPGBackfillRemove {
    meta!(96, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front(f, |e| {
            self.pgid.encode(e)?;
            e.u32(self.map_epoch)?;
            self.ls.encode(e)
        })?))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MOSDPGBackfillRemove {
            pgid: SpgT::decode(&mut d)?,
            map_epoch: d.u32()?,
            ls: ObjVer::decode(&mut d)?,
        })
    }
}

/// MBackfillReserve (99, hv5 hc4).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MBackfillReserve {
    pub pgid: SpgT,
    pub query_epoch: u32,
    pub ty: u32,
    pub priority: u32,
    pub primary_num_bytes: i64,
    pub shard_num_bytes: i64,
}
impl MBackfillReserve {
    pub const REQUEST: u32 = 0;
    pub const GRANT: u32 = 1;
    pub const REJECT_TOOFULL: u32 = 2;
    pub const RELEASE: u32 = 3;
    pub const REVOKE_TOOFULL: u32 = 4;
    pub const REVOKE: u32 = 5;

    /// Every message but a REQUEST (GRANT, REJECT_TOOFULL, RELEASE, REVOKE_TOOFULL, REVOKE): no priority, no sizes.
    pub fn reply(pgid: SpgT, query_epoch: u32, ty: u32) -> Self {
        MBackfillReserve {
            pgid,
            query_epoch,
            ty,
            priority: 0,
            primary_num_bytes: 0,
            shard_num_bytes: 0,
        }
    }
}
impl Message for MBackfillReserve {
    meta!(99, 5, 4);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front(f, |e| {
            self.pgid.pgid.encode(e)?;
            e.u32(self.query_epoch)?;
            e.u32(self.ty)?;
            e.u32(self.priority)?;
            self.pgid.shard.encode(e)?;
            e.i64(self.primary_num_bytes)?;
            e.i64(self.shard_num_bytes)
        })?))
    }
    fn decode(v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        let pg = PgT::decode(&mut d)?;
        let query_epoch = d.u32()?;
        let ty = d.u32()?;
        let priority = d.u32()?;
        let shard = d.i8()?;
        let (a, b) = if v >= 5 { (d.i64()?, d.i64()?) } else { (0, 0) };
        Ok(MBackfillReserve {
            pgid: spg(pg, shard),
            query_epoch,
            ty,
            priority,
            primary_num_bytes: a,
            shard_num_bytes: b,
        })
    }
}

/// MOSDForceRecovery (151, hv2 hc2): mgr -> primary, `ceph pg force-recovery|force-backfill|cancel-*` (spec
/// force-recovery.md 2). A v1 peer (no SERVER_MIMIC) sends `pg_t`s without a shard: decoded as NO_SHARD.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDForceRecovery {
    pub fsid: [u8; 16],
    pub forced_pgs: Vec<SpgT>,
    /// `OFR_*` bits.
    pub options: u8,
}
impl MOSDForceRecovery {
    pub const OFR_RECOVERY: u8 = 1;
    pub const OFR_BACKFILL: u8 = 2;
    pub const OFR_CANCEL: u8 = 4;
}
impl Message for MOSDForceRecovery {
    meta!(151, 2, 2);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front(f, |e| {
            e.raw(&self.fsid)?;
            self.forced_pgs.encode(e)?;
            e.u8(self.options)
        })?))
    }
    fn decode(v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        let fsid = d.array::<16>()?;
        let forced_pgs = if v >= 2 {
            Vec::<SpgT>::decode(&mut d)?
        } else {
            Vec::<PgT>::decode(&mut d)?
                .into_iter()
                .map(|pgid| SpgT {
                    pgid,
                    shard: ShardId::NO_SHARD,
                })
                .collect()
        };
        Ok(MOSDForceRecovery {
            fsid,
            forced_pgs,
            options: d.u8()?,
        })
    }
}

/// MRecoveryReserve (150, hv3 hc2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MRecoveryReserve {
    pub pgid: SpgT,
    pub query_epoch: u32,
    pub ty: u32,
    pub priority: u32,
}
impl MRecoveryReserve {
    pub const REQUEST: u32 = 0;
    pub const GRANT: u32 = 1;
    pub const RELEASE: u32 = 2;
    pub const REVOKE: u32 = 3;

    /// Every message but a REQUEST (GRANT, RELEASE, REVOKE): no priority.
    pub fn reply(pgid: SpgT, query_epoch: u32, ty: u32) -> Self {
        MRecoveryReserve {
            pgid,
            query_epoch,
            ty,
            priority: 0,
        }
    }
}
impl Message for MRecoveryReserve {
    meta!(150, 3, 2);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front(f, |e| {
            self.pgid.pgid.encode(e)?;
            e.u32(self.query_epoch)?;
            e.u32(self.ty)?;
            self.pgid.shard.encode(e)?;
            e.u32(self.priority)
        })?))
    }
    fn decode(v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        let pg = PgT::decode(&mut d)?;
        let query_epoch = d.u32()?;
        let ty = d.u32()?;
        let shard = d.i8()?;
        Ok(MRecoveryReserve {
            pgid: spg(pg, shard),
            query_epoch,
            ty,
            priority: if v >= 3 { d.u32()? } else { 0 },
        })
    }
}

/// `head` ++ the parts (copy): the DATA segment of a MOSDRepOp in rope form.
fn flat_parts(head: &Bytes, more: &[(Bytes, BlobCrc)]) -> Bytes {
    let mut v = Vec::with_capacity(more.iter().fold(head.len(), |n, (b, _)| n + b.len()));
    v.extend_from_slice(head);
    for (b, _) in more {
        v.extend_from_slice(b);
    }
    v.into()
}
