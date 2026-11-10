// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! MOSDECSubOpWrite / MOSDECSubOpWriteReply and their payload structs (spec ec.md 6.1).

use crate::{BytesLen, get_trace, put_trace};
use bytes::Bytes;
use denc::types::{Eversion, Hobject, OsdReqId, PgShard, SpgT};
use denc::{Decode, Decoder, Encode, Error, Result};
use messages::{Message, Segments, front_with, meta};
use pgwire::{LogEntry, PgStat};
use std::collections::BTreeSet;

/// ECSubWrite (struct v1..5, compat 1). The transaction is kept as the segments replwire decodes:
/// struct v<=4 = the whole v9 transaction inline (`txn_middle` empty, `txn_data` = its envelope);
/// struct v5 = the v10 p-part in `txn_middle`, the aligned/misaligned bytes in `txn_data`.
#[derive(Clone)]
pub struct ECSubWrite {
    pub from: PgShard,
    pub tid: u64,
    pub reqid: OsdReqId,
    pub soid: Hobject,
    pub stats: PgStat,
    pub txn_middle: Bytes,
    pub txn_data: Bytes,
    /// Shared runs spliced into `txn_data` (encode side only, struct v4: the v9 blob as a rope, zero-copy shard payloads,
    /// `replwire::Transaction::encode_v9_rope`): `(offset in txn_data, run)`, ascending. Decode leaves it empty.
    pub txn_zc: Vec<(usize, Bytes)>,
    /// Known crcs of the `txn_zc` runs (encode side only): the CRC-mode frame joins them instead of a pass over the runs
    /// (`msgr2::Message::front_hints`).
    pub txn_hints: crc::CrcHints,
    /// LOCAL only (never decoded), struct v5: further parts of the DATA segment, which is `txn_data` ++ these (the shard
    /// payloads by reference, [`ECSubWrite::data_segment`]). The cluster send path moves them into the msgr2 frame by
    /// reference; [`Message::encode`] concatenates them (copy).
    pub txn_data_more: Vec<(Bytes, crc::CrcHint)>,
    /// LOCAL only (never decoded), struct v5: offset of the first write payload in the DATA segment
    /// (`replwire::Transaction::payload_at`); [`ECSubWrite::data_segment`] returns its negation as the msgr2 `data_off`.
    pub txn_payload_at: Option<usize>,
    pub at_version: Eversion,
    pub trim_to: Eversion,
    pub log_entries: Vec<LogEntry>,
    pub temp_added: BTreeSet<Hobject>,
    pub temp_removed: BTreeSet<Hobject>,
    /// Raw pg_hit_set_history_t envelope (expected `None`).
    pub updated_hit_set_history: Option<Vec<u8>>,
    pub pg_committed_to: Eversion,
    pub backfill_or_async_recovery: bool,
}

/// `Debug` without the payloads (`txn_middle`, `txn_data`, the `txn_zc` runs and `txn_data_more` hold up to a stripe
/// width per shard). The exhaustive destructuring makes a new field a compile error here until it is shown or
/// summarized on purpose.
impl std::fmt::Debug for ECSubWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ECSubWrite {
            from,
            tid,
            reqid,
            soid,
            stats,
            txn_middle,
            txn_data,
            txn_zc,
            txn_hints,
            txn_data_more,
            txn_payload_at,
            at_version,
            trim_to,
            log_entries,
            temp_added,
            temp_removed,
            updated_hit_set_history,
            pg_committed_to,
            backfill_or_async_recovery,
        } = self;
        let runs: Vec<(usize, BytesLen)> = txn_zc
            .iter()
            .map(|(at, run)| (*at, BytesLen(run.len())))
            .collect();
        let more: Vec<BytesLen> = txn_data_more
            .iter()
            .map(|(b, _)| BytesLen(b.len()))
            .collect();
        f.debug_struct("ECSubWrite")
            .field("from", from)
            .field("tid", tid)
            .field("reqid", reqid)
            .field("soid", soid)
            .field("stats", stats)
            .field("txn_middle", &BytesLen(txn_middle.len()))
            .field("txn_data", &BytesLen(txn_data.len()))
            .field("txn_zc", &runs)
            .field("txn_hints", txn_hints)
            .field("txn_data_more", &more)
            .field("txn_payload_at", txn_payload_at)
            .field("at_version", at_version)
            .field("trim_to", trim_to)
            .field("log_entries", log_entries)
            .field("temp_added", temp_added)
            .field("temp_removed", temp_removed)
            .field(
                "updated_hit_set_history",
                &updated_hit_set_history.as_ref().map(|h| BytesLen(h.len())),
            )
            .field("pg_committed_to", pg_committed_to)
            .field("backfill_or_async_recovery", backfill_or_async_recovery)
            .finish()
    }
}

/// Equality is the wire content: `txn_hints` is send-side metadata (known crcs of runs already in `txn_zc`), excluded.
/// The exhaustive destructuring makes a new field a compile error here until it is compared or excluded on purpose.
impl PartialEq for ECSubWrite {
    fn eq(&self, o: &Self) -> bool {
        let ECSubWrite {
            from,
            tid,
            reqid,
            soid,
            stats,
            txn_middle,
            txn_data,
            txn_zc,
            txn_hints: _,
            txn_data_more,
            txn_payload_at: _,
            at_version,
            trim_to,
            log_entries,
            temp_added,
            temp_removed,
            updated_hit_set_history,
            pg_committed_to,
            backfill_or_async_recovery,
        } = self;
        *from == o.from
            && *tid == o.tid
            && *reqid == o.reqid
            && *soid == o.soid
            && *stats == o.stats
            && *txn_middle == o.txn_middle
            && *txn_data == o.txn_data
            && *txn_zc == o.txn_zc
            && *txn_data_more == o.txn_data_more
            && *at_version == o.at_version
            && *trim_to == o.trim_to
            && *log_entries == o.log_entries
            && *temp_added == o.temp_added
            && *temp_removed == o.temp_removed
            && *updated_hit_set_history == o.updated_hit_set_history
            && *pg_committed_to == o.pg_committed_to
            && *backfill_or_async_recovery == o.backfill_or_async_recovery
    }
}

impl Default for ECSubWrite {
    fn default() -> Self {
        ECSubWrite {
            from: PgShard::default(),
            tid: 0,
            reqid: OsdReqId::default(),
            soid: Hobject::default(),
            stats: PgStat::default(),
            txn_middle: Bytes::new(),
            txn_data: Bytes::new(),
            txn_zc: Vec::new(),
            txn_hints: Default::default(),
            txn_data_more: Vec::new(),
            txn_payload_at: None,
            at_version: Eversion::default(),
            trim_to: Eversion::default(),
            log_entries: Vec::new(),
            temp_added: BTreeSet::new(),
            temp_removed: BTreeSet::new(),
            updated_hit_set_history: None,
            pg_committed_to: Eversion::default(),
            backfill_or_async_recovery: false,
        }
    }
}

/// [`check_env`] of a rope (`b` with the runs `zc` inserted): one whole envelope, runs inside its body.
fn check_env_rope(b: &[u8], zc: &[(usize, Bytes)]) -> Result<()> {
    // struct_v, struct_compat, u32 body length
    const HEAD: usize = 6;
    if zc.is_empty() {
        return check_env(b);
    }
    let ok = b.len() >= HEAD
        && denc::le::rd_u32(b, 2) as usize + HEAD
            == b.len() + zc.iter().map(|(_, r)| r.len()).sum::<usize>()
        && zc.iter().all(|(at, _)| (HEAD..=b.len()).contains(at))
        && zc.windows(2).all(|w| w[0].0 <= w[1].0);
    if ok {
        Ok(())
    } else {
        Err(Error::BadValue("opaque envelope rope"))
    }
}

fn check_env(b: &[u8]) -> Result<()> {
    let mut d = Decoder::new(b);
    d.envelope_raw()?;
    if d.is_empty() {
        Ok(())
    } else {
        Err(Error::BadValue("opaque envelope blob"))
    }
}

impl ECSubWrite {
    /// Struct version we emit for this value.
    fn wire_version(&self) -> u8 {
        if self.txn_middle.is_empty() { 4 } else { 5 }
    }

    /// Turn a struct v4 value (v9 transaction inline, possibly a rope) into struct v5 for a peer with SERVER_TENTACLE
    /// (spec ec.md 6.1): the same transaction as v10 with `data_features` 0 (unsplit, what a classic primary sends): the
    /// p part (op records, tables, features, stream lengths) goes to the front, the misaligned stream to the DATA
    /// segment, its shard payloads by reference (`txn_data_more`, no copy). Returns the msgr2 header `data_off` that
    /// puts the first write payload on a 4 KiB boundary at a placing receiver (spec msgr2.md 3.1), 0 without one. A
    /// value already in v5 form is left as is. Cold-path cost: a copy of the small parts (stream length + op records +
    /// tables).
    pub fn data_segment(&mut self) -> Result<u16> {
        let off = |at: Option<usize>| at.map_or(0, |a| 0u16.wrapping_sub(a as u16));
        if self.wire_version() == 5 {
            return Ok(off(self.txn_payload_at));
        }
        check_env_rope(&self.txn_data, &self.txn_zc)?;
        let b = &self.txn_data;
        // v9: envelope (u8 v, u8 compat, u32 len) + u32 misaligned stream length + the stream + op records + tables
        if b.len() < replwire::txn::V9_STREAM_AT || b[0] != 9 {
            return Err(Error::BadValue("ECSubWrite v5 needs a v9 transaction"));
        }
        let mis = denc::le::rd_u32(b, 6) as usize;
        let spliced: usize = self.txn_zc.iter().map(|(_, r)| r.len()).sum();
        // the stream ends in the inline bytes at `end` (runs lie inside it)
        let end = (replwire::txn::V9_STREAM_AT + mis)
            .checked_sub(spliced)
            .filter(|&e| e <= b.len() && self.txn_zc.iter().all(|(at, _)| *at <= e))
            .ok_or(Error::BadValue("v9 stream length"))?;
        let mut p = Vec::with_capacity(6 + b.len() - end + 16);
        {
            let mut e = denc::Encoder::from_buf(&mut p);
            e.versioned(10, 10, |e| {
                e.raw(&b[end..])?;
                e.u64(0)?; // data_features: unsplit
                e.count(0)?; // aligned stream
                e.count(mis)
            })?;
        }
        let mut pieces: Vec<(Bytes, crc::CrcHint)> = Vec::with_capacity(2 * self.txn_zc.len() + 1);
        let mut pos = replwire::txn::V9_STREAM_AT;
        for (at, r) in std::mem::take(&mut self.txn_zc) {
            pieces.push((b.slice(pos..at), Default::default()));
            let h = self.txn_hints.get(&r).cloned().unwrap_or_default();
            pieces.push((r, h));
            pos = at;
        }
        pieces.push((b.slice(pos..end), Default::default()));
        pieces.retain(|(x, _)| !x.is_empty());
        let (first, _) = if pieces.is_empty() {
            (Bytes::new(), Default::default())
        } else {
            pieces.remove(0)
        };
        self.txn_middle = p.into();
        self.txn_data = first;
        self.txn_data_more = pieces;
        self.txn_hints.clear();
        Ok(off(self.txn_payload_at))
    }

    fn encode_into<B: denc::BufMut>(&self, e: &mut denc::Encoder<B>) -> Result<()> {
        let v = self.wire_version();
        if v == 4 {
            // the transaction is one envelope (v9) inline in the front
            check_env_rope(&self.txn_data, &self.txn_zc)?;
        } else if !self.txn_zc.is_empty() {
            return Err(Error::BadValue("spliced runs need struct v4"));
        } else {
            check_env(&self.txn_middle)?;
        }
        if let Some(h) = &self.updated_hit_set_history {
            check_env(h)?;
        }
        e.versioned(v, 1, |e| {
            self.from.encode(e)?;
            e.u64(self.tid)?;
            self.reqid.encode(e)?;
            self.soid.encode(e)?;
            self.stats.encode(e)?;
            if v == 4 {
                e.raw_rope(&self.txn_data, &self.txn_zc)?;
            } else {
                e.raw(&self.txn_middle)?;
            }
            self.at_version.encode(e)?;
            self.trim_to.encode(e)?;
            self.log_entries.encode(e)?;
            self.temp_added.encode(e)?;
            self.temp_removed.encode(e)?;
            match &self.updated_hit_set_history {
                None => e.u8(0)?,
                Some(h) => {
                    e.u8(1)?;
                    e.raw(h)?;
                }
            }
            self.pg_committed_to.encode(e)?;
            e.bool(self.backfill_or_async_recovery)
        })
    }

    /// `owner`: the buffer the decoder reads (the v9 transaction is kept as a slice of it, no copy).
    fn decode_from(d: &mut Decoder<'_>, data: &Bytes, owner: Option<&Bytes>) -> Result<Self> {
        // struct_v 1..; refused only when the sender's struct_compat exceeds the version this decoder reads (5), the
        // rule of every Ceph decoder: a later struct_v whose compat is <= 5 keeps our fields in place and appends
        d.versioned_min(1, 5, |d, v| {
            let from = PgShard::decode(d)?;
            let tid = d.u64()?;
            let reqid = OsdReqId::decode(d)?;
            let soid = Hobject::decode(d)?;
            let stats = PgStat::decode(d)?;
            let raw = d.envelope_raw()?;
            let txn = match owner {
                Some(o) if contains(o, raw) => o.slice_ref(raw),
                _ => Bytes::copy_from_slice(raw),
            };
            let (txn_middle, txn_data) = if v >= 5 {
                (txn, data.clone())
            } else {
                (Bytes::new(), txn)
            };
            let at_version = Eversion::decode(d)?;
            let trim_to = Eversion::decode(d)?;
            let log_entries = Vec::<LogEntry>::decode(d)?;
            let temp_added = BTreeSet::<Hobject>::decode(d)?;
            let temp_removed = BTreeSet::<Hobject>::decode(d)?;
            let updated_hit_set_history = if v >= 2 && d.u8()? != 0 {
                Some(d.envelope_raw()?.to_vec())
            } else {
                None
            };
            let pg_committed_to = if v >= 3 {
                Eversion::decode(d)?
            } else {
                trim_to
            };
            let backfill_or_async_recovery = if v >= 4 {
                d.bool()?
            } else {
                // Older senders signal log-only/backfill operations by an empty transaction.
                // The page size matters only for v10's split stream; these versions carry v9 inline.
                replwire::Transaction::decode(&txn_middle, &txn_data, 4096)?.is_empty()
            };
            Ok(ECSubWrite {
                from,
                tid,
                reqid,
                soid,
                stats,
                txn_middle,
                txn_data,
                txn_zc: Vec::new(),
                txn_hints: Default::default(),
                txn_data_more: Vec::new(),
                txn_payload_at: None,
                at_version,
                trim_to,
                log_entries,
                temp_added,
                temp_removed,
                updated_hit_set_history,
                pg_committed_to,
                backfill_or_async_recovery,
            })
        })
    }
}

/// MOSDECSubOpWrite (108, head 2, compat 1).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MOSDECSubOpWrite {
    pub pgid: SpgT,
    pub map_epoch: u32,
    pub op: ECSubWrite,
    pub min_epoch: u32,
    pub trace: [i64; 3],
}

impl MOSDECSubOpWrite {
    /// Decode the shipped transaction (borrows this message).
    pub fn txn(&self, page: usize) -> Result<replwire::Transaction<'_>> {
        replwire::Transaction::decode(&self.op.txn_middle, &self.op.txn_data, page)
    }

    /// Decode keeping the DATA segment as a shared slice (struct v5 transactions).
    pub fn decode_shared(version: u16, front: &[u8], data: &Bytes) -> Result<Self> {
        Self::decode_owned(version, front, None, data)
    }

    /// [`Self::decode_shared`]; `owner` = the shared buffer `front` is (a received large front): the struct v4
    /// transaction stays a slice of it (no copy).
    pub fn decode_owned(
        version: u16,
        front: &[u8],
        owner: Option<&Bytes>,
        data: &Bytes,
    ) -> Result<Self> {
        let mut d = Decoder::new(front);
        let pgid = SpgT::decode(&mut d)?;
        let map_epoch = d.u32()?;
        let op = ECSubWrite::decode_from(&mut d, data, owner)?;
        let min_epoch = if version >= 2 { d.u32()? } else { map_epoch };
        let trace = get_trace(&mut d)?;
        Ok(MOSDECSubOpWrite {
            pgid,
            map_epoch,
            op,
            min_epoch,
            trace,
        })
    }
}

impl Message for MOSDECSubOpWrite {
    meta!(108, 2, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        // the shard payloads stay shared (rope): the front copies only the small fields
        let (front, front_zc) = denc::encode_exact_rope(f, |e| {
            self.pgid.encode(e)?;
            e.u32(self.map_epoch)?;
            self.op.encode_into(e)?;
            e.u32(self.min_epoch)?;
            put_trace(e, &self.trace)
        })?;
        Ok(Segments {
            front,
            front_zc,
            front_hints: self.op.txn_hints.clone(),
            middle: Vec::new(),
            data: match self.op.wire_version() {
                5 if self.op.txn_data_more.is_empty() => self.op.txn_data.clone(),
                5 => {
                    let more: usize = self.op.txn_data_more.iter().map(|(b, _)| b.len()).sum();
                    let mut v = Vec::with_capacity(self.op.txn_data.len() + more);
                    v.extend_from_slice(&self.op.txn_data);
                    for (b, _) in &self.op.txn_data_more {
                        v.extend_from_slice(b);
                    }
                    v.into()
                }
                _ => Bytes::new(),
            },
        })
    }
    fn decode(version: u16, front: &[u8], _middle: &[u8], data: &[u8]) -> Result<Self> {
        Self::decode_shared(version, front, &Bytes::copy_from_slice(data))
    }
}

/// ECSubWriteReply (ENCODE 1,1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ECSubWriteReply {
    pub from: PgShard,
    pub tid: u64,
    pub last_complete: Eversion,
    pub committed: bool,
    pub applied: bool,
}

/// MOSDECSubOpWriteReply (109, head 2, compat 1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDECSubOpWriteReply {
    pub pgid: SpgT,
    pub map_epoch: u32,
    pub op: ECSubWriteReply,
    pub min_epoch: u32,
    pub trace: [i64; 3],
}

impl Message for MOSDECSubOpWriteReply {
    meta!(109, 2, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            self.pgid.encode(e)?;
            e.u32(self.map_epoch)?;
            self.op.encode_into(e)?;
            e.u32(self.min_epoch)?;
            put_trace(e, &self.trace)
        })?))
    }
    fn decode(version: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        let pgid = SpgT::decode(&mut d)?;
        let map_epoch = d.u32()?;
        let op = ECSubWriteReply::decode_from(&mut d)?;
        let min_epoch = if version >= 2 { d.u32()? } else { map_epoch };
        let trace = get_trace(&mut d)?;
        Ok(MOSDECSubOpWriteReply {
            pgid,
            map_epoch,
            op,
            min_epoch,
            trace,
        })
    }
}

impl ECSubWrite {
    /// The struct alone as `dencoder` shows it (envelope included). Struct v5 needs the DATA segment for `txn_data`.
    pub fn to_struct_bytes(&self) -> Result<Vec<u8>> {
        let (front, front_zc) = denc::encode_exact_rope(0, |e| self.encode_into(e))?;
        let s = Segments {
            front,
            front_zc,
            ..Default::default()
        };
        Ok(s.front_bytes()?.into_owned())
    }
    /// Decode the struct alone; `data` = the DATA segment (only used by struct v5).
    pub fn from_struct_bytes(buf: &[u8], data: &Bytes) -> Result<Self> {
        Self::decode_from(&mut Decoder::new(buf), data, None)
    }
}

impl ECSubWriteReply {
    fn encode_into<B: denc::BufMut>(&self, e: &mut denc::Encoder<B>) -> Result<()> {
        e.versioned(1, 1, |e| {
            self.from.encode(e)?;
            e.u64(self.tid)?;
            self.last_complete.encode(e)?;
            e.bool(self.committed)?;
            e.bool(self.applied)
        })
    }
    fn decode_from(d: &mut Decoder<'_>) -> Result<Self> {
        // struct_v 1..; refused only when struct_compat exceeds the version this decoder reads (1), as for ECSubWrite
        d.versioned_min(1, 1, |d, _| {
            Ok(ECSubWriteReply {
                from: PgShard::decode(d)?,
                tid: d.u64()?,
                last_complete: Eversion::decode(d)?,
                committed: d.bool()?,
                applied: d.bool()?,
            })
        })
    }
    pub fn to_struct_bytes(&self) -> Result<Vec<u8>> {
        front_with(0, |e| self.encode_into(e))
    }
    pub fn from_struct_bytes(buf: &[u8]) -> Result<Self> {
        Self::decode_from(&mut Decoder::new(buf))
    }
}

/// `s` lies inside `o` (then `o.slice_ref(s)` is valid).
fn contains(o: &Bytes, s: &[u8]) -> bool {
    let (a, b) = (o.as_ptr() as usize, s.as_ptr() as usize);
    b >= a && b + s.len() <= a + o.len()
}
