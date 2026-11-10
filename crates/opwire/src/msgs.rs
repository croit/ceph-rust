// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! MOSDOp (42), MOSDOpReply (43), MWatchNotify (44), MOSDBackoff (61) and the [`ClientMsg`] enum.
//! Spec client-ops.md s1, s2, s6, s10.2.

use crate::consts::{self, feat, flag, op, ty};
use crate::osdop::{OsdOp, data_parts, data_segment, get_ops, put_ops};
use crate::payload::RequestRedirect;
use bytes::Bytes;
use denc::features::have;
use denc::types::{
    Eversion, Hobject, ObjectLocator, ObjectLocatorStorage, OsdReqId, PgT, ShardId, SpgT, UTime,
};
use denc::{Decode, Decoder, Encode, Encoder, Error, Result};
use messages::{Message, Segments};

/// blkin trace info (3 x i64), ignored; carried raw for byte-exact round trips.
pub type Blkin = [u8; 24];

/// Wire version of MOSDOp to use towards a peer with connection `features` (s1.1).
pub fn mosdop_version_for(features: u64) -> u16 {
    if have(features, feat::SERVER_SQUID) {
        9
    } else if have(features, feat::RESEND_ON_SPLIT) {
        8
    } else {
        7
    }
}

/// The data segment by reference: its first piece and the pieces after it, in order, empty ones left out, each with
/// its crc hint.
fn split_data_parts(ops: &[OsdOp], reply: bool) -> (Bytes, crc::CrcHint, crate::Pieces) {
    let mut parts = data_parts(ops, reply);
    let (data, hint) = parts
        .next()
        .map_or_else(Default::default, |(b, h)| (b.clone(), h.clone()));
    let more = parts.map(|(b, h)| (b.clone(), h.clone())).collect();
    (data, hint, more)
}

/// The crc hint of the data segment when it is exactly one piece with a known crc.
fn single_part_hint(ops: &[OsdOp], reply: bool) -> crc::CrcHint {
    let mut parts = data_parts(ops, reply);
    match (parts.next(), parts.next()) {
        (Some((_, h)), None) => h.clone(),
        _ => Default::default(),
    }
}

/// otel trace field of MOSDOp v9: `ENV(1,1){ u8 valid; if valid: trace_id[16], span_id[8], flags u8 }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OtelTrace {
    pub valid: Option<([u8; 16], [u8; 8], u8)>,
}

/// Owned MOSDOp (type 42, HEAD 9, COMPAT 3), used by decoding and existing callers.
pub type MOSDOp = MOSDOpStorage<Vec<u8>>;

/// MOSDOp with caller-selected immutable identity storage. Only object,
/// namespace and locator bytes use `B`; operations and snapshots stay owned.
/// Encoding reads these bytes for the duration of the synchronous call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MOSDOpStorage<B> {
    /// Local bounded-input ownership, never encoded.
    pub ingress: ingress::InputGuard,
    /// Local transport admission marker, never encoded. `Some` = the attempt's
    /// retry number, set only by the authenticated attempt owner after retaining
    /// the matching destination grant. It survives PG parking, retries and
    /// cross-core routing with the op and returns with every reply, including
    /// errors.
    pub placement_read: Option<u32>,
    /// Local admission marker, never encoded: the validated source-pull PUT
    /// record (adr 0665) this write carries instead of inline data. The OSD-side
    /// RDMA READ that fills the write data is not implemented; the op executor
    /// refuses such a write with `EOPNOTSUPP` before touching the store.
    pub source_pull: Option<Vec<u8>>,
    /// Local admission marker, never encoded: negative errno explaining why the source-pull READ did not
    /// deliver bytes (transport refusal, short read, crc32c mismatch). The op
    /// executor reports it without touching the store.
    pub source_pull_error: Option<i32>,
    /// Target PG (actual, after pg_num masking). v7 decodes to shard NO_SHARD.
    pub pgid: SpgT,
    /// Object placement hash (`hobject_t.hash`); v7: `pg_t.seed`.
    pub hash: u32,
    pub osdmap_epoch: u32,
    /// CEPH_OSD_FLAG_*.
    pub flags: u32,
    /// Explicit request id (see [`MOSDOp::effective_reqid`]); v7 only: `reassert_version`.
    pub reqid: OsdReqId,
    pub reassert_version: Eversion,
    pub trace: Blkin,
    pub otel: OtelTrace,
    pub client_inc: u32,
    pub mtime: UTime,
    pub oloc: ObjectLocatorStorage<B>,
    pub oid: B,
    pub ops: Vec<OsdOp>,
    pub snapid: u64,
    pub snap_seq: u64,
    pub snaps: Vec<u64>,
    pub retry_attempt: i32,
    pub features: u64,
    /// Declared bytes of a data segment the receiver refused before admission (`msgr2` data probe, spec client-ops
    /// 5.4.1): the ops carry no payload and the message is answered from its front. Never encoded; 0 = all payloads
    /// are present.
    pub refused_data: u32,
    /// Local receive metadata, never encoded: data-segment bytes after the last
    /// op payload. Classic includes these bytes in its whole-message size gate.
    pub trailing_data_len: usize,
}

impl<B: Default> Default for MOSDOpStorage<B> {
    fn default() -> Self {
        MOSDOpStorage {
            ingress: Default::default(),
            placement_read: None,
            source_pull: None,
            source_pull_error: None,
            pgid: SpgT::default(),
            hash: 0,
            osdmap_epoch: 0,
            flags: 0,
            reqid: OsdReqId::default(),
            reassert_version: Eversion::default(),
            trace: [0; 24],
            otel: OtelTrace::default(),
            client_inc: 0,
            mtime: UTime::default(),
            oloc: ObjectLocatorStorage::default(),
            oid: B::default(),
            ops: Vec::new(),
            snapid: consts::NOSNAP,
            snap_seq: 0,
            snaps: Vec::new(),
            retry_attempt: 0,
            features: 0,
            refused_data: 0,
            trailing_data_len: 0,
        }
    }
}

impl MOSDOp {
    /// Exact front size from metadata, without allocating or inspecting payloads.
    /// Checks string widths, the nested locator body, counts and the containing
    /// u32 front independently. Data-segment lengths are a separate envelope.
    /// Before version negotiation, v7 is the minimum for all supported peers.
    pub fn front_len(
        version: u16,
        oid_bytes: usize,
        namespace_bytes: usize,
        locator_bytes: usize,
        ops: usize,
        snapshots: usize,
        otel_valid: bool,
    ) -> Result<usize> {
        let fixed: usize = match version {
            7 => 148,
            8 => 171,
            9 => 178 + if otel_valid { 25 } else { 0 },
            _ => return Err(Error::BadValue("MOSDOp encode version")),
        };
        u32::try_from(oid_bytes).map_err(|_| Error::TooLong)?;
        u32::try_from(namespace_bytes).map_err(|_| Error::TooLong)?;
        u32::try_from(locator_bytes).map_err(|_| Error::TooLong)?;
        u16::try_from(ops).map_err(|_| Error::TooLong)?;
        u32::try_from(snapshots).map_err(|_| Error::TooLong)?;
        // ObjectLocator ENV body: pool8 + preferred4 + two string prefixes8
        // + hash8, followed by key/namespace bytes. ENV itself adds six bytes.
        let locator_body = 28usize
            .checked_add(namespace_bytes)
            .and_then(|n| n.checked_add(locator_bytes))
            .ok_or(Error::TooLong)?;
        u32::try_from(locator_body).map_err(|_| Error::TooLong)?;
        let front = ops
            .checked_mul(crate::OP_LEN)
            .and_then(|n| n.checked_add(snapshots.checked_mul(8)?))
            .and_then(|n| n.checked_add(fixed))
            .and_then(|n| n.checked_add(oid_bytes))
            .and_then(|n| n.checked_add(namespace_bytes))
            .and_then(|n| n.checked_add(locator_bytes))
            .ok_or(Error::TooLong)?;
        u32::try_from(front).map_err(|_| Error::TooLong)?;
        Ok(front)
    }
}

impl<B: AsRef<[u8]>> MOSDOpStorage<B> {
    /// The same message with the identity bytes (oid, namespace, locator key) owned as `Vec<u8>`, i.e. the wire form
    /// [`MOSDOp`] a messenger sends; operations and their `Bytes` payload stay shared (reference bumps, no copy).
    pub fn into_owned_identity(self) -> MOSDOp {
        MOSDOpStorage {
            ingress: self.ingress,
            placement_read: self.placement_read,
            pgid: self.pgid,
            hash: self.hash,
            osdmap_epoch: self.osdmap_epoch,
            flags: self.flags,
            reqid: self.reqid,
            reassert_version: self.reassert_version,
            trace: self.trace,
            otel: self.otel,
            client_inc: self.client_inc,
            mtime: self.mtime,
            oloc: ObjectLocatorStorage {
                pool: self.oloc.pool,
                key: self.oloc.key.as_ref().to_vec(),
                nspace: self.oloc.nspace.as_ref().to_vec(),
                hash: self.oloc.hash,
            },
            oid: self.oid.as_ref().to_vec(),
            ops: self.ops,
            snapid: self.snapid,
            snap_seq: self.snap_seq,
            snaps: self.snaps,
            retry_attempt: self.retry_attempt,
            features: self.features,
            refused_data: self.refused_data,
            trailing_data_len: self.trailing_data_len,
            source_pull: self.source_pull,
            source_pull_error: self.source_pull_error,
        }
    }

    /// ADR 0471's single plain READ candidate for placement. Authentication,
    /// grant capacity and the live RC attempt are transport checks.
    pub fn placement_read_eligible(&self) -> bool {
        self.ops.len() == 1
            && self.ops[0].op == op::READ
            && self.ops[0].indata.is_empty()
            && self.ops[0].extent().length >= 1_048_576
            && self.flags & (flag::EC_DIRECT_READ | flag::FORCE_OSD | flag::PGOP | flag::WRITE) == 0
    }

    /// ADR 0665's single plain WRITE candidate for a source-pull PUT: one WRITE
    /// op with no inline data (the descriptor in the middle segment carries the
    /// length). Whether the session negotiated the extension, whether the record
    /// matches the op and whether the grant is live are transport checks.
    pub fn source_pull_write_eligible(&self) -> bool {
        self.ops.len() == 1
            && self.ops[0].op == op::WRITE
            && self.ops[0].indata.is_empty()
            && self.flags & (flag::WRITE | flag::RWORDERED) == flag::WRITE | flag::RWORDERED
            && self.flags & (flag::EC_DIRECT_READ | flag::FORCE_OSD | flag::PGOP) == 0
    }

    /// Known data CRC only when encoding preserves one exact nonempty input owner.
    pub fn data_crc_hint(&self) -> crc::CrcHint {
        single_part_hint(&self.ops, false)
    }
    /// The request id for dedup/logging (s1.6): the explicit one if set, else
    /// `(peer entity name, client_inc, header tid)`.
    pub fn effective_reqid(&self, peer: denc::types::EntityName, header_tid: u64) -> OsdReqId {
        if self.reqid.name != denc::types::EntityName::new(0, 0) || self.reqid.tid != 0 {
            self.reqid
        } else {
            OsdReqId {
                name: peer,
                tid: header_tid,
                inc: self.client_inc as i32,
            }
        }
    }
    /// Total bytes of the data segment, including trailing receive bytes, or the
    /// declared length refused before admission (then no op carries a payload).
    pub fn data_len(&self) -> usize {
        (self.refused_data as usize)
            .max(self.ops.iter().map(|o| o.indata_len()).sum::<usize>() + self.trailing_data_len)
    }
    /// The raw PG (pool, seed) of the target.
    pub fn pg_t(&self) -> PgT {
        self.pgid.pgid
    }

    fn encode_front_version(&self, v: u16, features: u64) -> Result<Vec<u8>> {
        // The exact front length sizes the buffer once (growing it was a realloc chain per op on the client).
        let len = MOSDOp::front_len(
            v,
            self.oid.as_ref().len(),
            self.oloc.nspace.as_ref().len(),
            self.oloc.key.as_ref().len(),
            self.ops.len(),
            self.snaps.len(),
            self.otel.valid.is_some(),
        )?;
        let mut e = Encoder::with_capacity(len).with_features(features);
        if v >= 8 {
            self.pgid.encode(&mut e)?;
            e.u32(self.hash)?;
            e.u32(self.osdmap_epoch)?;
            e.u32(self.flags)?;
            self.reqid.encode(&mut e)?;
            e.raw(&self.trace)?;
            if v >= 9 {
                e.versioned(1, 1, |e| match &self.otel.valid {
                    None => e.u8(0),
                    Some((t, s, f)) => {
                        e.u8(1)?;
                        e.raw(t)?;
                        e.raw(s)?;
                        e.u8(*f)
                    }
                })?;
            }
            e.u32(self.client_inc)?;
        } else {
            PgT::new(self.pgid.pgid.pool, self.hash).encode(&mut e)?;
            e.u32(self.osdmap_epoch)?;
            e.u32(self.flags)?;
            self.reassert_version.encode(&mut e)?;
            self.reqid.encode(&mut e)?;
            e.u32(self.client_inc)?;
        }
        self.mtime.encode(&mut e)?;
        self.oloc.encode(&mut e)?;
        e.bytes(self.oid.as_ref())?;
        e.u16(u16::try_from(self.ops.len()).map_err(|_| Error::TooLong)?)?;
        put_ops(&mut e, &self.ops, false)?;
        e.u64(self.snapid)?;
        e.u64(self.snap_seq)?;
        self.snaps.encode(&mut e)?;
        e.i32(self.retry_attempt)?;
        e.u64(self.features)?;
        Ok(e.into_vec())
    }

    /// Encode as header version `v` (7, 8 or 9).
    pub fn encode_version(&self, v: u16, features: u64) -> Result<Segments> {
        Ok(Segments {
            front_zc: Vec::new(),
            front_hints: Default::default(),
            front: self.encode_front_version(v, features)?,
            middle: Vec::new(),
            data: data_segment(&self.ops, false),
        })
    }

    /// Encode request data as shared input pieces. `data` is the first
    /// nonempty op payload; the returned list follows it in operation order.
    /// This avoids flattening multiple independent write buffers before the
    /// msgr2 sender, which already supports a scatter data segment.
    pub fn encode_parts_version(
        &self,
        v: u16,
        features: u64,
    ) -> Result<(Segments, crc::CrcHint, crate::Pieces)> {
        let front = self.encode_front_version(v, features)?;
        let (data, hint, more) = split_data_parts(&self.ops, false);
        Ok((
            Segments {
                front_zc: Vec::new(),
                front_hints: Default::default(),
                front,
                middle: Vec::new(),
                data,
            },
            hint,
            more,
        ))
    }
}

impl Message for MOSDOp {
    const MSG_TYPE: u16 = ty::OSD_OP;
    const HEAD_VERSION: u16 = 9;
    const COMPAT_VERSION: u16 = 3;
    const OLDEST_VERSION: u16 = 7;

    /// Picks the encoding from `features` (see [`mosdop_version_for`]); NB the caller must put
    /// that version in the header: use [`ClientMsg::encode`].
    fn encode(&self, features: u64) -> Result<Segments> {
        self.encode_version(mosdop_version_for(features), features)
    }

    fn decode(version: u16, front: &[u8], _middle: &[u8], data: &[u8]) -> Result<Self> {
        Self::decode_shared(version, front, &Bytes::copy_from_slice(data))
    }
}

impl MOSDOp {
    /// Decode with op data as slices of the shared data segment (no copy).
    pub fn decode_shared(version: u16, front: &[u8], data: &Bytes) -> Result<Self> {
        let (mut m, mut d) = Self::decode_head(version, front)?;
        let n = d.u16()? as usize;
        let (ops, consumed) = get_ops(&mut d, n, data, false)?;
        m.ops = ops;
        m.trailing_data_len = data.len() - consumed;
        m.decode_tail(&mut d)?;
        Ok(m)
    }

    /// Decode a front whose data segment was refused before admission (`msgr2` data probe, spec client-ops 5.4.1): the
    /// ops carry no payload, `refused` is their declared total (the data segment's length). Only messages that rule 14
    /// answers from the front alone may take this path ([`MOSDOp::front_may_write`]).
    pub fn decode_refused(version: u16, front: &[u8], refused: u32) -> Result<Self> {
        let (mut m, mut d) = Self::decode_head(version, front)?;
        let n = d.u16()? as usize;
        if n > d.remaining() / crate::OP_LEN {
            return Err(Error::BadLength {
                len: n as u64,
                remaining: d.remaining(),
            });
        }
        let mut ops = Vec::with_capacity(n.min(1024));
        let mut total = 0usize;
        for _ in 0..n {
            let (o, len) = OsdOp::parse_header(d.take(crate::OP_LEN)?)?;
            total = total.checked_add(len as usize).ok_or(Error::TooLong)?;
            ops.push(o);
        }
        if total > refused as usize {
            return Err(Error::BadLength {
                len: total as u64,
                remaining: refused as usize,
            });
        }
        m.ops = ops;
        m.decode_tail(&mut d)?;
        m.refused_data = refused;
        Ok(m)
    }

    fn decode_tail(&mut self, d: &mut Decoder<'_>) -> Result<()> {
        self.snapid = d.u64()?;
        self.snap_seq = d.u64()?;
        self.snaps = Vec::<u64>::decode(d)?;
        self.retry_attempt = d.i32()?;
        self.features = d.u64()?;
        Ok(())
    }

    /// Does rule 14 answer this message from header2 + front alone (spec client-ops 5.4.1)? True when the op vector sets
    /// the WR mode bit (a `watch` PING does not) with `snapid` = `CEPH_NOSNAP`. False when an op needs its payload to
    /// classify (`call`: its class method decides WR), when a pg op decides first (rule 8), and when the front could be
    /// answered by an earlier rule from the front alone (non-NOSNAP snapid, an op without a read/write mode bit): such a
    /// frame is admitted and its pipeline decides exactly as classic.
    pub fn front_may_write(version: u16, front: &[u8]) -> Result<bool> {
        let (_, mut d) = Self::decode_head(version, front)?;
        let n = d.u16()? as usize;
        if n > d.remaining() / crate::OP_LEN {
            return Err(Error::BadLength {
                len: n as u64,
                remaining: d.remaining(),
            });
        }
        let mut may_write = false;
        for _ in 0..n {
            let (o, _len) = OsdOp::parse_header(d.take(crate::OP_LEN)?)?;
            if o.op & (op::MODE_RD | op::MODE_WR) == 0
                || o.op == op::CALL
                || crate::classify::is_pg_op(o.op)
            {
                return Ok(false);
            }
            if o.op == op::WATCH {
                if o.watch().op != consts::watch_op::PING {
                    may_write = true;
                }
                continue;
            }
            may_write |= crate::classify::modifies(o.op);
        }
        let snapid = d.u64()?;
        Ok(may_write && snapid == consts::NOSNAP)
    }

    /// The PG and the single data-carrying op of an op whose data segment has not arrived yet (receiver-side pre-write,
    /// adr 0477): same parse as [`decode_shared`](Self::decode_shared) up to the op headers. The front is unverified at
    /// that point (its crc comes with the frame end): the result is a hint, never a decision.
    pub fn peek_write(version: u16, front: &[u8]) -> Result<WritePeek> {
        let (m, mut d) = Self::decode_head(version, front)?;
        let n = d.u16()? as usize;
        let mut at = 0usize;
        let mut data_ops = 0;
        let mut write = None;
        for _ in 0..n {
            let (o, l) = OsdOp::parse_header(d.take(crate::OP_LEN)?)?;
            let l = l as usize;
            if l > 0 {
                data_ops += 1;
                if matches!(o.op, op::WRITE | op::WRITEFULL) {
                    write = Some(PeekWrite {
                        at,
                        offset: o.extent().offset,
                        len: l,
                    });
                }
            }
            at = at.checked_add(l).ok_or(Error::TooLong)?;
        }
        Ok(WritePeek {
            pgid: m.pgid,
            write: write.filter(|_| data_ops == 1),
        })
    }

    fn decode_head(version: u16, front: &[u8]) -> Result<(Self, Decoder<'_>)> {
        Self::check_version(version)?;
        let mut d = Decoder::new(front);
        let mut m = MOSDOp::default();
        if version >= 8 {
            m.pgid = SpgT::decode(&mut d)?;
            m.hash = d.u32()?;
            m.osdmap_epoch = d.u32()?;
            m.flags = d.u32()?;
            m.reqid = OsdReqId::decode(&mut d)?;
            m.trace = d.array()?;
            if version >= 9 {
                m.otel.valid = d.versioned(1, |d, _| {
                    Ok(if d.u8()? != 0 {
                        Some((d.array::<16>()?, d.array::<8>()?, d.u8()?))
                    } else {
                        None
                    })
                })?;
            }
            m.client_inc = d.u32()?;
        } else {
            let pg = PgT::decode(&mut d)?;
            m.pgid = SpgT {
                pgid: pg,
                shard: ShardId::NO_SHARD,
            };
            m.hash = pg.seed;
            m.osdmap_epoch = d.u32()?;
            m.flags = d.u32()?;
            m.reassert_version = Eversion::decode(&mut d)?;
            m.reqid = OsdReqId::decode(&mut d)?;
            m.client_inc = d.u32()?;
        }
        m.mtime = UTime::decode(&mut d)?;
        m.oloc = ObjectLocator::decode(&mut d)?;
        m.oid = d.bytes()?.to_vec();
        Ok((m, d))
    }
}

/// [`MOSDOp::peek_write`]: the op's PG and, when exactly one op carries data and it is a WRITE / WRITEFULL, where that
/// data lies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WritePeek {
    pub pgid: SpgT,
    pub write: Option<PeekWrite>,
}

/// The data of the write op: bytes `[at, at + len)` of the data segment go to object offset `offset`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeekWrite {
    pub at: usize,
    pub offset: u64,
    pub len: usize,
}

/// MOSDOpReply (type 43, HEAD 8, COMPAT 2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDOpReply {
    pub oid: Vec<u8>,
    pub pgid: PgT,
    /// Encoded as i64 on the wire (verified by capture, spec s14 U1).
    pub flags: u64,
    pub result: i32,
    pub bad_replay_version: Eversion,
    pub osdmap_epoch: u32,
    /// Ops echoed with `outdata` and `rval` filled.
    pub ops: Vec<OsdOp>,
    pub retry_attempt: i32,
    pub replay_version: Eversion,
    pub user_version: u64,
    pub redirect: Option<RequestRedirect>,
    pub trace: Blkin,
}

/// Owned READ source pieces for one placement attempt. Moving this value does
/// not flatten or copy the bytes; the transport owns it until CQ retirement.
#[derive(Debug)]
pub struct PlacedReadPayload {
    pub first: (Bytes, crc::CrcHint),
    pub more: crate::Pieces,
    pub block_crcs: Vec<u32>,
    pub len: u64,
}

impl PlacedReadPayload {
    /// Nonempty source pieces in destination order. EOF produces no pieces.
    /// Cloning a `Bytes` is a reference bump, not a payload copy.
    pub fn pieces(&self) -> Vec<Bytes> {
        if self.first.0.is_empty() && self.more.is_empty() {
            return Vec::new();
        }
        let mut v = Vec::with_capacity(1 + self.more.len());
        if !self.first.0.is_empty() {
            v.push(self.first.0.clone());
        }
        v.extend(
            self.more
                .iter()
                .filter(|(b, _)| !b.is_empty())
                .map(|(b, _)| b.clone()),
        );
        v
    }

    /// Restore the original reply after a preflight refusal, before a WRITE
    /// was posted or a placed result promised. All piece owners move back.
    pub fn restore(self, reply: &mut MOSDOpReply) -> std::result::Result<(), Box<Self>> {
        if reply.result != 0 || reply.ops.len() != 1 {
            return Err(Box::new(self));
        }
        let operation = &mut reply.ops[0];
        if operation.op != op::READ
            || operation.rval != 0
            || operation.extent().length != self.len
            || operation.outdata_len() != 0
            || operation.outdata_block_crcs.is_some()
        {
            return Err(Box::new(self));
        }
        operation.outdata = self.first.0;
        operation.outdata_crc = self.first.1;
        operation.outdata_more = self.more;
        operation.outdata_block_crcs = Some(self.block_crcs);
        Ok(())
    }
}

impl MOSDOpReply {
    /// Exact normal (no redirect) v8 front size, excluding data and msgr2 header.
    pub fn normal_front_len(oid_bytes: usize, ops: usize) -> Option<usize> {
        u32::try_from(oid_bytes).ok()?;
        u32::try_from(ops).ok()?;
        ops.checked_mul(crate::OP_LEN + 4)?
            .checked_add(102)?
            .checked_add(oid_bytes)
    }

    /// Reply skeleton for `req`: echoes oid/pgid/ops (without data)/retry_attempt and sets
    /// flags = (req.flags minus ACK|ONNVRAM|ONDISK) | ACK | ONDISK (s2.1).
    pub fn for_request<B: AsRef<[u8]>>(req: &MOSDOpStorage<B>, osdmap_epoch: u32) -> Self {
        Self::for_request_ops(req, osdmap_epoch, req.ops.iter().map(OsdOp::echo).collect())
    }

    /// [`for_request`](Self::for_request) with the reply ops given (no second ops vector when the caller builds them).
    pub fn for_request_ops<B: AsRef<[u8]>>(
        req: &MOSDOpStorage<B>,
        osdmap_epoch: u32,
        ops: Vec<OsdOp>,
    ) -> Self {
        MOSDOpReply {
            oid: req.oid.as_ref().to_vec(),
            pgid: req.pgid.pgid,
            flags: ((req.flags & !(flag::ACK | flag::ONNVRAM | flag::ONDISK))
                | flag::ACK
                | flag::ONDISK) as u64,
            osdmap_epoch,
            ops,
            retry_attempt: req.retry_attempt,
            ..Default::default()
        }
    }
    /// Set (replay_version, user_version) and the legacy `bad_replay_version` mirror (s2.2):
    /// replay_version with `.version` := user_version, epoch kept.
    pub fn set_versions(&mut self, replay: Eversion, user_version: u64) {
        self.replay_version = replay;
        self.user_version = user_version;
        self.bad_replay_version = Eversion::new(replay.epoch, user_version);
    }
}

impl Message for MOSDOpReply {
    const MSG_TYPE: u16 = ty::OSD_OPREPLY;
    const HEAD_VERSION: u16 = 8;
    const COMPAT_VERSION: u16 = 2;
    const OLDEST_VERSION: u16 = 8;

    fn encode(&self, features: u64) -> Result<Segments> {
        Ok(Segments {
            front_zc: Vec::new(),
            front_hints: Default::default(),
            front: self.encode_front(features)?,
            middle: Vec::new(),
            data: data_segment(&self.ops, true),
        })
    }

    fn decode(version: u16, front: &[u8], _middle: &[u8], data: &[u8]) -> Result<Self> {
        Self::decode_shared(version, front, &Bytes::copy_from_slice(data))
    }
}

impl MOSDOpReply {
    fn encode_front(&self, features: u64) -> Result<Vec<u8>> {
        denc::encode_exact(features, |e| {
            e.bytes(&self.oid)?;
            self.pgid.encode(e)?;
            e.u64(self.flags)?;
            e.i32(self.result)?;
            self.bad_replay_version.encode(e)?;
            e.u32(self.osdmap_epoch)?;
            e.u32(u32::try_from(self.ops.len()).map_err(|_| Error::TooLong)?)?;
            put_ops(e, &self.ops, true)?;
            e.i32(self.retry_attempt)?;
            for o in &self.ops {
                e.i32(o.rval)?;
            }
            self.replay_version.encode(e)?;
            e.u64(self.user_version)?;
            match &self.redirect {
                None => e.u8(0)?,
                Some(r) => {
                    e.u8(1)?;
                    r.encode(e)?;
                }
            }
            e.raw(&self.trace)
        })
    }

    /// Decode with op data as slices of the shared data segment (no copy).
    pub fn decode_shared(version: u16, front: &[u8], data: &Bytes) -> Result<Self> {
        Self::check_version(version)?;
        let mut d = Decoder::new(front);
        let mut m = MOSDOpReply {
            oid: d.bytes()?.to_vec(),
            pgid: PgT::decode(&mut d)?,
            flags: d.u64()?,
            result: d.i32()?,
            bad_replay_version: Eversion::decode(&mut d)?,
            osdmap_epoch: d.u32()?,
            ..Default::default()
        };
        let n = d.u32()? as usize;
        (m.ops, _) = get_ops(&mut d, n, data, true)?;
        m.retry_attempt = d.i32()?;
        for o in &mut m.ops {
            o.rval = d.i32()?;
        }
        m.replay_version = Eversion::decode(&mut d)?;
        m.user_version = d.u64()?;
        if d.u8()? != 0 {
            m.redirect = Some(RequestRedirect::decode(&mut d)?);
        }
        m.trace = d.array()?;
        Ok(m)
    }
}

/// MOSDBackoff (type 61, HEAD 1, COMPAT 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MOSDBackoff {
    pub pgid: SpgT,
    pub map_epoch: u32,
    /// [`consts::backoff`]: BLOCK 1, ACK_BLOCK 2, UNBLOCK 3.
    pub op: u8,
    pub id: u64,
    pub begin: Hobject,
    pub end: Hobject,
}

impl Message for MOSDBackoff {
    const MSG_TYPE: u16 = ty::OSD_BACKOFF;
    const HEAD_VERSION: u16 = 1;
    const COMPAT_VERSION: u16 = 1;

    fn encode(&self, features: u64) -> Result<Segments> {
        let mut e = Encoder::new().with_features(features);
        self.pgid.encode(&mut e)?;
        e.u32(self.map_epoch)?;
        e.u8(self.op)?;
        e.u64(self.id)?;
        self.begin.encode(&mut e)?;
        self.end.encode(&mut e)?;
        Ok(Segments::front(e.into_vec()))
    }

    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MOSDBackoff {
            pgid: SpgT::decode(&mut d)?,
            map_epoch: d.u32()?,
            op: d.u8()?,
            id: d.u64()?,
            begin: Hobject::decode(&mut d)?,
            end: Hobject::decode(&mut d)?,
        })
    }
}

/// MWatchNotify (type 44, HEAD 3, COMPAT 1). `data` = NOTIFY_COMPLETE data segment
/// ([`crate::NotifyCompleteData`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MWatchNotify {
    /// Inner `msg_ver` (1).
    pub msg_ver: u8,
    /// [`consts::notify`]: NOTIFY 1, NOTIFY_COMPLETE 2, DISCONNECT 3.
    pub opcode: u8,
    pub cookie: u64,
    pub ver: u64,
    pub notify_id: u64,
    pub bl: Vec<u8>,
    pub return_code: i32,
    pub notifier_gid: u64,
    pub data: Vec<u8>,
}

impl Message for MWatchNotify {
    const MSG_TYPE: u16 = ty::WATCH_NOTIFY;
    const HEAD_VERSION: u16 = 3;
    const COMPAT_VERSION: u16 = 1;

    fn encode(&self, features: u64) -> Result<Segments> {
        let mut e = Encoder::new().with_features(features);
        e.u8(if self.msg_ver == 0 { 1 } else { self.msg_ver })?;
        e.u8(self.opcode)?;
        e.u64(self.cookie)?;
        e.u64(self.ver)?;
        e.u64(self.notify_id)?;
        e.bytes(&self.bl)?;
        e.i32(self.return_code)?;
        e.u64(self.notifier_gid)?;
        Ok(Segments {
            front_zc: Vec::new(),
            front_hints: Default::default(),
            front: e.into_vec(),
            middle: Vec::new(),
            data: self.data.clone().into(),
        })
    }

    fn decode(_v: u16, front: &[u8], _m: &[u8], data: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        let msg_ver = d.u8()?;
        Ok(MWatchNotify {
            msg_ver,
            opcode: d.u8()?,
            cookie: d.u64()?,
            ver: d.u64()?,
            notify_id: d.u64()?,
            bl: d.bytes()?.to_vec(),
            return_code: d.i32()?,
            notifier_gid: d.u64()?,
            data: data.to_vec(),
        })
    }
}

/// Any client-facing op message, or an unknown type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientMsg {
    Op(MOSDOp),
    OpReply(MOSDOpReply),
    Backoff(MOSDBackoff),
    WatchNotify(MWatchNotify),
    Unknown {
        ty: u16,
        version: u16,
        segments: Segments,
    },
}

impl ClientMsg {
    pub fn msg_type(&self) -> u16 {
        match self {
            ClientMsg::Op(_) => ty::OSD_OP,
            ClientMsg::OpReply(_) => ty::OSD_OPREPLY,
            ClientMsg::Backoff(_) => ty::OSD_BACKOFF,
            ClientMsg::WatchNotify(_) => ty::WATCH_NOTIFY,
            ClientMsg::Unknown { ty, .. } => *ty,
        }
    }

    /// `(type, version, compat_version, segments)` for the msgr2 header. MOSDOp uses the version
    /// chosen by `features`.
    pub fn encode(&self, features: u64) -> Result<(u16, u16, u16, Segments)> {
        Ok(match self {
            ClientMsg::Op(m) => {
                let v = mosdop_version_for(features);
                (
                    MOSDOp::MSG_TYPE,
                    v,
                    MOSDOp::COMPAT_VERSION,
                    m.encode_version(v, features)?,
                )
            }
            ClientMsg::OpReply(m) => (
                MOSDOpReply::MSG_TYPE,
                MOSDOpReply::HEAD_VERSION,
                MOSDOpReply::COMPAT_VERSION,
                m.encode(features)?,
            ),
            ClientMsg::Backoff(m) => (
                MOSDBackoff::MSG_TYPE,
                MOSDBackoff::HEAD_VERSION,
                MOSDBackoff::COMPAT_VERSION,
                m.encode(features)?,
            ),
            ClientMsg::WatchNotify(m) => (
                MWatchNotify::MSG_TYPE,
                MWatchNotify::HEAD_VERSION,
                MWatchNotify::COMPAT_VERSION,
                m.encode(features)?,
            ),
            ClientMsg::Unknown {
                ty,
                version,
                segments,
            } => (*ty, *version, *version, segments.clone()),
        })
    }
}

macro_rules! from_msg {
    ($($t:ident => $v:ident),*) => {$(
        impl From<$t> for ClientMsg { fn from(m: $t) -> Self { ClientMsg::$v(m) } }
    )*};
}
from_msg!(MOSDOp => Op, MOSDOpReply => OpReply, MOSDBackoff => Backoff, MWatchNotify => WatchNotify);

/// Decode a client op message by header type and version from msgr2 segments.
pub fn decode_client(ty: u16, version: u16, segs: &Segments) -> Result<ClientMsg> {
    decode_client_shared_parts(ty, version, &segs.front_bytes()?, &segs.middle, &segs.data)
}

/// Decode borrowed front/middle and an owned shared data segment without copying any of them
/// for known client message types. The returned op data retains the same `Bytes` allocation.
pub fn decode_client_shared_parts(
    ty: u16,
    version: u16,
    front: &[u8],
    middle: &[u8],
    data: &Bytes,
) -> Result<ClientMsg> {
    Ok(match ty {
        ty::OSD_OP => ClientMsg::Op(MOSDOp::decode_shared(version, front, data)?),
        ty::OSD_OPREPLY => ClientMsg::OpReply(MOSDOpReply::decode_shared(version, front, data)?),
        _ => decode_client_parts(ty, version, front, middle, data)?,
    })
}

/// [`decode_client`] on borrowed segments.
pub fn decode_client_parts(
    ty: u16,
    version: u16,
    front: &[u8],
    middle: &[u8],
    data: &[u8],
) -> Result<ClientMsg> {
    Ok(match ty {
        ty::OSD_OP => ClientMsg::Op(MOSDOp::decode(version, front, middle, data)?),
        ty::OSD_OPREPLY => ClientMsg::OpReply(MOSDOpReply::decode(version, front, middle, data)?),
        ty::OSD_BACKOFF => ClientMsg::Backoff(MOSDBackoff::decode(version, front, middle, data)?),
        ty::WATCH_NOTIFY => {
            ClientMsg::WatchNotify(MWatchNotify::decode(version, front, middle, data)?)
        }
        _ => ClientMsg::Unknown {
            ty,
            version,
            segments: Segments {
                front_zc: Vec::new(),
                front_hints: Default::default(),
                front: front.to_vec(),
                middle: middle.to_vec(),
                data: Bytes::copy_from_slice(data),
            },
        },
    })
}

impl MOSDOpReply {
    /// The owned source pieces, store-verified block CRCs and placed length of a successful
    /// plain READ, without moving them out (a reference bump per piece, one small CRC copy).
    /// `None` when the reply is not a successful single READ carrying placement CRCs.
    pub fn placed_read_source(&self) -> Option<(Vec<Bytes>, Vec<u32>, u64)> {
        if self.result != 0 || self.ops.len() != 1 {
            return None;
        }
        let operation = &self.ops[0];
        if operation.op != op::READ || operation.rval != 0 {
            return None;
        }
        let len = operation.outdata_len() as u64;
        let count = len.div_ceil(4096);
        let block_crcs = operation.outdata_block_crcs.as_ref()?.clone();
        if block_crcs.len() != count as usize {
            return None;
        }
        let mut pieces = Vec::with_capacity(1 + operation.outdata_more.len());
        pieces.push(operation.outdata.clone());
        pieces.extend(operation.outdata_more.iter().map(|(b, _)| b.clone()));
        Some((pieces, block_crcs, len))
    }

    /// Local pieces and source-verified CRCs moved out of a successful plain READ.
    /// The first piece may be empty for EOF. The transport must still validate
    /// the live attempt and register every source before posting any WRITE.
    pub fn take_placed_read_payload(&mut self) -> Option<PlacedReadPayload> {
        if self.result != 0 || self.ops.len() != 1 {
            return None;
        }
        let operation = &mut self.ops[0];
        let len = operation.outdata_len();
        let count = len.div_ceil(4096);
        if operation.op != op::READ
            || operation.rval != 0
            || operation.extent().length != len as u64
            || operation.outdata_block_crcs.as_ref()?.len() != count
        {
            return None;
        }
        let (first, first_crc, more, block_crcs) = operation.take_outdata();
        Some(PlacedReadPayload {
            first: (first, first_crc),
            more,
            block_crcs: block_crcs.expect("checked above"),
            len: len as u64,
        })
    }

    /// Encode the front and receipt carrier for an already completed placed plain READ.
    /// The caller must validate the receipt against its authenticated RDMA attempt and
    /// prove all WRITEs retired before calling this method. This enforces the wire
    /// shape: the READ extent is the placed length, while its payload and the entire
    /// msgr2 data segment are empty. It never turns an inline reply into placement.
    pub fn encode_placed_read(
        &self,
        features: u64,
        receipt: Vec<u8>,
        written_len: u64,
    ) -> Result<Segments> {
        if receipt.is_empty()
            || self.result != 0
            || self.ops.len() != 1
            || self.ops[0].op != op::READ
            || self.ops[0].rval != 0
            || self.ops[0].extent().length != written_len
            || self.ops[0].outdata_len() != 0
        {
            return Err(Error::BadValue("placed READ reply shape"));
        }
        Ok(Segments {
            front_zc: Vec::new(),
            front_hints: Default::default(),
            front: self.encode_front(features)?,
            middle: receipt,
            data: Bytes::new(),
        })
    }

    /// Encode an ordered terminal error for an admitted placed READ whose
    /// transport posted no WRITE. The matching RETIRED record is the middle;
    /// source pieces are dropped without flattening or sending them inline.
    /// The caller must establish that no WRITE was accepted and that this
    /// reply follows older output on the same QP.
    pub fn encode_placed_error(
        mut self,
        features: u64,
        retired: [u8; 28],
        fallback_errno: i32,
    ) -> Result<Segments> {
        if self.ops.len() != 1 || self.ops[0].op != op::READ || fallback_errno <= 0 {
            return Err(Error::BadValue("placed READ error shape"));
        }
        let operation = &mut self.ops[0];
        let error = if self.result < 0 {
            self.result
        } else if operation.rval < 0 {
            operation.rval
        } else {
            -fallback_errno
        };
        self.result = error;
        operation.rval = error;
        let _ = operation.take_outdata();
        Ok(Segments {
            front_zc: Vec::new(),
            front_hints: Default::default(),
            front: self.encode_front(features)?,
            middle: retired.to_vec(),
            data: Bytes::new(),
        })
    }

    /// crc32c (seed `!0`) of the encoded data segment when it is known without a pass over the bytes: the segment is one
    /// piece (one op's `outdata`, no further pieces) and a still-valid [`CrcHint`] sits on it.
    pub fn data_crc_hint(&self) -> crc::CrcHint {
        single_part_hint(&self.ops, true)
    }

    /// [`Message::encode`] with the data segment by reference: `segs.data` is its first piece, the returned list the
    /// pieces after it (segment = `data` ++ list), each piece with its crc hint (the first one's is returned first). The
    /// msgr2 sender takes them as `Message::{data, data_crc, data_more}`: no copy of read data into one blob.
    pub fn encode_parts(&self, features: u64) -> Result<(Segments, crc::CrcHint, crate::Pieces)> {
        let front = self.encode_front(features)?;
        let (data, hint, more) = split_data_parts(&self.ops, true);
        Ok((
            Segments {
                front_zc: Vec::new(),
                front_hints: Default::default(),
                front,
                middle: Vec::new(),
                data,
            },
            hint,
            more,
        ))
    }

    /// msgr2 `header2.data_off` hint for this reply (s1.5): offset of the first read
    /// op (whether or not it returned bytes), truncated to 16 bits (0 if none). The receiver treats it as an alignment hint only.
    pub fn data_off_hint(&self) -> u16 {
        self.ops
            .iter()
            .find(|o| matches!(o.op, op::READ | op::SYNC_READ | op::SPARSE_READ))
            .map_or(0, |o| (o.extent().offset & 0xFFFF) as u16)
    }
}

#[cfg(test)]
mod mosdop_front_tests {
    use super::*;

    #[test]
    fn front_metadata_checks_complete_sum_for_each_version_and_otel_state() {
        let max = u32::MAX as usize;
        for (version, valid, fixed) in [
            (7, false, 148),
            (7, true, 148),
            (8, false, 171),
            (8, true, 171),
            (9, false, 178),
            (9, true, 203),
        ] {
            assert_eq!(MOSDOp::front_len(version, 0, 0, 0, 0, 0, valid), Ok(fixed));
            let overhead = fixed + 5 + 9 + 38 * 17 + 8 * 13;
            let object = max - overhead;
            assert_eq!(
                MOSDOp::front_len(version, object, 5, 9, 17, 13, valid),
                Ok(max)
            );
            assert_eq!(
                MOSDOp::front_len(version, object + 1, 5, 9, 17, 13, valid),
                Err(Error::TooLong)
            );
        }
        // A pre-negotiation v9 estimate would wrongly refuse this valid v7
        // envelope. These are lengths only, never fabricated large buffers.
        assert_eq!(MOSDOp::front_len(7, max - 148, 0, 0, 0, 0, false), Ok(max));
        for version in [8, 9] {
            assert_eq!(
                MOSDOp::front_len(version, max - 148, 0, 0, 0, 0, false),
                Err(Error::TooLong)
            );
        }
    }

    #[test]
    fn front_metadata_checks_field_widths_nested_locator_and_arithmetic() {
        let max = u32::MAX as usize;
        assert!(MOSDOp::front_len(7, 0, 0, 0, u16::MAX as usize, 0, false).is_ok());
        assert_eq!(
            MOSDOp::front_len(7, 0, 0, 0, u16::MAX as usize + 1, 0, false),
            Err(Error::TooLong)
        );
        let snapshots = (max - 148) / 8;
        assert_eq!(
            MOSDOp::front_len(7, 0, 0, 0, 0, snapshots, false),
            Ok(148 + snapshots * 8)
        );
        assert_eq!(
            MOSDOp::front_len(7, 0, 0, 0, 0, snapshots + 1, false),
            Err(Error::TooLong)
        );
        for (object, namespace, locator, operations, snaps) in [
            (usize::MAX, 0, 0, 0, 0),
            (0, usize::MAX, 0, 0, 0),
            (0, 0, usize::MAX, 0, 0),
            (0, 0, 0, usize::MAX, 0),
            (0, 0, 0, 0, usize::MAX),
            (0, 0, 0, 0, max),
            (0, max - 28, 1, 0, 0), // locator body exceeds u32
            (0, max - 28, 0, 0, 0), // locator body fits, containing front does not
            (0, max / 2 + 1, max / 2 + 1, 0, 0),
            (max / 2 + 1, max / 2 + 1, 0, 0, 0),
        ] {
            assert_eq!(
                MOSDOp::front_len(7, object, namespace, locator, operations, snaps, false),
                Err(Error::TooLong)
            );
        }
        for version in [0, 6, 10, u16::MAX] {
            assert_eq!(
                MOSDOp::front_len(version, 0, 0, 0, 0, 0, false),
                Err(Error::BadValue("MOSDOp encode version"))
            );
            assert!(matches!(
                MOSDOp::default().encode_version(version, 0),
                Err(Error::BadValue("MOSDOp encode version"))
            ));
        }
    }

    #[test]
    fn calculated_front_matches_actual_encodings_not_just_the_formula() {
        for (object, namespace, key) in [(0, 0, 0), (1, 0, 3), (0, 4, 0), (17, 4, 3)] {
            for count in [0, 1, 3] {
                for snaps in [0, 1, 4] {
                    for valid in [None, Some(([0x91; 16], [0x72; 8], 1))] {
                        for hash in [-1, 7] {
                            let request = MOSDOp {
                                oid: vec![0xff; object],
                                oloc: ObjectLocator {
                                    pool: 42,
                                    nspace: vec![0; namespace],
                                    key: vec![0x80; key],
                                    hash,
                                },
                                ops: (0..count)
                                    .map(|i| {
                                        if i % 2 == 0 {
                                            OsdOp::read(5, 9)
                                        } else {
                                            OsdOp::writefull(vec![0, 255])
                                        }
                                    })
                                    .collect(),
                                snaps: (0..snaps).map(|i| 19 - i as u64).collect(),
                                otel: OtelTrace { valid },
                                ..Default::default()
                            };
                            let locator = denc::to_vec(&request.oloc).unwrap();
                            assert_eq!(locator.len(), 34 + namespace + key);
                            assert_eq!(
                                u32::from_le_bytes(locator[2..6].try_into().unwrap()) as usize,
                                28 + namespace + key
                            );
                            for (version, fixed) in [
                                (7, 148),
                                (8, 171),
                                (9, 178 + if valid.is_some() { 25 } else { 0 }),
                            ] {
                                let expected =
                                    fixed + object + namespace + key + 38 * count + 8 * snaps;
                                assert_eq!(
                                    MOSDOp::front_len(
                                        version,
                                        object,
                                        namespace,
                                        key,
                                        count,
                                        snaps,
                                        valid.is_some()
                                    ),
                                    Ok(expected)
                                );
                                let encoded = request.encode_version(version, 0).unwrap();
                                assert_eq!(encoded.front.len(), expected);
                                assert_eq!(encoded.data.len(), (count / 2) * 2);
                                assert!(encoded.middle.is_empty());
                            }
                            // The native send path must use its selected version,
                            // not the minimum used by early FFI admission.
                            for (features, version) in
                                [(0, 7), (feat::RESEND_ON_SPLIT, 8), (feat::SERVER_SQUID, 9)]
                            {
                                let (_, selected, _, encoded) =
                                    ClientMsg::Op(request.clone()).encode(features).unwrap();
                                assert_eq!(selected, version);
                                assert_eq!(
                                    encoded.front.len(),
                                    MOSDOp::front_len(
                                        version,
                                        object,
                                        namespace,
                                        key,
                                        count,
                                        snaps,
                                        valid.is_some()
                                    )
                                    .unwrap()
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod own_identity_tests {
    use super::*;

    #[test]
    fn into_owned_identity_copies_only_the_identity() {
        let payload = bytes::Bytes::from_static(b"payload-bytes");
        let req = MOSDOpStorage::<bytes::Bytes> {
            oid: bytes::Bytes::from_static(b"rbd_data.abc"),
            oloc: ObjectLocatorStorage {
                pool: 3,
                key: bytes::Bytes::from_static(b"locator"),
                nspace: bytes::Bytes::from_static(b"ns"),
                hash: -1,
            },
            ops: vec![OsdOp::write_bytes(0, payload.clone())],
            snapid: 5,
            snap_seq: 6,
            snaps: vec![7],
            retry_attempt: 2,
            features: 9,
            ..Default::default()
        };
        let owned = req.into_owned_identity();
        assert_eq!(owned.oid, b"rbd_data.abc");
        assert_eq!(owned.oloc.key, b"locator");
        assert_eq!(owned.oloc.nspace, b"ns");
        assert_eq!(owned.oloc.pool, 3);
        assert_eq!(owned.ops[0].indata.as_ptr(), payload.as_ptr());
        assert_eq!(
            (
                owned.snapid,
                owned.snap_seq,
                owned.snaps.as_slice(),
                owned.retry_attempt,
                owned.features
            ),
            (5, 6, &[7u64][..], 2, 9)
        );
    }
}

#[cfg(test)]
mod mosdop_request_parts_tests {
    use super::*;

    #[test]
    fn multiple_write_ops_preserve_input_owners_and_wire_bytes() {
        let first = Bytes::from_static(b"abc");
        let second = Bytes::from_static(b"1234567");
        let request = MOSDOp {
            ops: vec![
                OsdOp::write_bytes(4, first.clone()),
                OsdOp::write_bytes(7, second.clone()),
            ],
            ..Default::default()
        };
        for version in [7, 8, 9] {
            let flat = request.encode_version(version, 0).unwrap();
            let (parts, first_hint, more) = request.encode_parts_version(version, 0).unwrap();
            assert_eq!(parts.front, flat.front);
            assert_eq!(parts.data.as_ptr(), first.as_ptr());
            assert_eq!(parts.data, first);
            assert_eq!(more.len(), 1);
            assert_eq!(more[0].0.as_ptr(), second.as_ptr());
            assert_eq!(more[0].0, second);
            assert!(first_hint.of(&parts.data).is_none());
            assert!(more[0].1.of(&more[0].0).is_none());
            let mut assembled = Vec::new();
            assembled.extend_from_slice(&parts.data);
            assembled.extend_from_slice(&more[0].0);
            assert_eq!(&flat.data[..], assembled);
            let decoded = MOSDOp::decode_shared(version, &parts.front, &flat.data).unwrap();
            assert_eq!(decoded.ops[0].indata, first);
            assert_eq!(decoded.ops[1].indata, second);
        }
    }
}
