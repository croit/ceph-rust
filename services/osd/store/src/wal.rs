// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! WAL unit format and replay (design 2.10, 3; ADR 0021 amendment: parallel data+WAL commit).
//!
//! Ring of 4 KiB blocks. A unit = 64 B header + payload (ntxn records back to back), padded to whole blocks,
//! never wrapping the ring end (a PAD unit - header only - marks "continue at block 0").
//!
//! Validity chain (all must hold, first failure ends the log):
//!  * magic, header crc, payload crc, shard id;
//!  * `first_lsn` == previous unit's last lsn + 1 (starts at root.wal_tail_lsn: ckpt_lsn + 1, or older while live omap
//!    runs hold units, adr 0476);
//!  * `epoch` non-decreasing along the chain and <= root.epoch (every mount bumps and persists the epoch
//!    before writing new units, so stale units of an older incarnation can't be revived behind a gap). A unit that
//!    continues the chain with `epoch > root.epoch` does not end the log: its incarnation persisted that epoch in a root
//!    slot first, so the newest root slot is lost and the mount fell back to an older one; replay refuses
//!    (`newer_incarnation`);
//!  * `prev_unit_crc` == header crc of the previous unit (first: root.wal_tail_prev_crc; mkfs seeds it from the
//!    fs uuid so units of an earlier mkfs never match);
//!  * parallel commit: every data block named by every record of the unit has the recorded crc32c on disk.
//!    A unit is atomic for replay: any bad data block invalidates the whole unit and everything after it.
//!    (The writer acks a unit only when all its records' data writes are durable, so no acked txn is in a unit
//!    that fails this check.) This is only sound if data blocks of records in the replay window are never
//!    recycled: the shard keeps blocks freed by a txn unreusable until a checkpoint (release) passes that txn,
//!    not merely until it is acked. Otherwise replay would see a legitimately overwritten block and truncate
//!    the log at an old acked record.

use crate::BLK;
use crate::codec::{Dec, Enc, blk_crc, crc};
use crate::dev::{BlockDev, Clock};
use crate::error::{Result, StoreError};
use crate::layout::{RootSlot, ShardDir};
use crate::olsm::wire::OOp;
use crate::runs::{RunBlob, omap_id};
use crate::sio::Sio;
use crate::state::{Extent, Op, Record, State};
use denc::types::{CollT, Ghobject};
use std::collections::VecDeque;

pub const UNIT_MAGIC: u32 = 0x4c41_5755;
pub const HDR_LEN: usize = 64;
pub const FLAG_PAD: u16 = 1;
/// Non-final part of a multi-unit txn (ADR 0028): payload = a slice of the txn's record encoding, header `ntxn`
/// = part index. All parts carry the txn's lsn as `first_lsn` and consume no lsn.
pub const FLAG_PART: u16 = 2;
/// Final part (index = n_parts - 1); consumes the txn's lsn. The txn applies only if parts 0..=END all validate.
pub const FLAG_END: u16 = 4;
/// Every unit-header flag this build writes. A unit of the current chain carrying another bit was written by a newer
/// build: replay refuses it (`undecodable`), it never reads it as the torn end of the log.
const FLAGS_KNOWN: u16 = FLAG_PAD | FLAG_PART | FLAG_END;

/// A unit of the current chain whose header and payload crcs verify but whose content this build cannot decode (an op tag
/// or header flag of a newer build, or a bug): it was written whole, so it is never a torn tail. Treating it as the end of
/// the log would silently drop it and every acked txn behind it (`acked_beyond` only sees later units); refuse instead.
fn undecodable(dir: &ShardDir, pos: u64, lsn: u64, what: &str) -> StoreError {
    let m = format!(
        "wal shard {} ring block {pos} lsn {lsn}: crc-valid unit with {what} (written by a newer build, or a bug): \
         refusing to replay; downgrade not possible",
        dir.shard
    );
    eprintln!("croit-flashstore-osd: CRITICAL {m}");
    StoreError::Corrupt(m)
}

/// A unit that continues the chain (prev crc and first lsn match) but carries an epoch above the root slot's: the mount
/// that wrote it persisted its epoch in a root slot before its first unit, so that slot is lost (bit rot, a lost write)
/// and `read_root` fell back to an older one. Every txn of that incarnation may have been acked; ending the log here
/// would drop them, and no later unit can prove it when this one is the last. Refuse; `--accept-wal-loss` does not
/// apply (it covers a cut WAL, not a lost root). Review 2026-11-03 #3.
fn newer_incarnation(
    dir: &ShardDir,
    pos: u64,
    lsn: u64,
    epoch: u32,
    root: &RootSlot,
) -> StoreError {
    let m = format!(
        "wal shard {} ring block {pos} lsn {lsn}: unit of incarnation {epoch} continues the chain of root slot seq {} \
         epoch {}: the newest root slot is lost (media corruption); acked txns of that incarnation would be dropped, \
         refusing to replay; recover this OSD from replicas",
        dir.shard, root.seq, root.epoch
    );
    eprintln!("croit-flashstore-osd: CRITICAL {m}");
    StoreError::Corrupt(m)
}

const TAG_PUT: u8 = 1;
const TAG_DEL: u8 = 2;
const TAG_DELR: u8 = 3;
/// Omap runs (adr 0476): `RunPut` (order lsn u64: 0 = a new run, else a re-log of that run; id u64, entries u32,
/// bytes u32, entries; an entry with an empty value is a removal, `FEAT_OMAP_TOMBS`) and `RunMerge` (id u64, upto u64,
/// fin u8, range bounds u16-prefixed).
const TAG_RUN: u8 = 4;
const TAG_RMERGE: u8 = 5;
/// Counted removal / put of an omap key (adr 0476 am. 5, `FEAT_OMAP_BLIND`): as `TAG_DEL` / `TAG_PUT`. Written by builds
/// before `FEAT_OMAP_UNCOUNTED` only; replay reads them as the plain op (their counter part is gone with the counters).
const TAG_ODEL: u8 = 6;
const TAG_OPUT: u8 = 7;
/// Omap LSM ops (adr 0610 (1), store with `FEAT_OMAP_LSM`): batch put / point deletes / range delete of one object.
const TAG_LPUT: u8 = 8;
const TAG_LDEL: u8 = 9;
const TAG_LRANGE: u8 = 10;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitHeader {
    pub epoch: u32,
    pub first_lsn: u64,
    pub ntxn: u32,
    pub nblocks: u16,
    pub flags: u16,
    pub shard: u32,
    pub payload_len: u32,
    pub prev_crc: u32,
    pub payload_crc: u32,
    /// Highest lsn acked (durable, in order) when this unit was sealed (ADR 0021 am. 9): proof that everything <= it
    /// was acked before this unit was written. 0 in units of older builds (zero pad bytes) = no proof.
    pub acked_lsn: u64,
    /// Store identity (`layout::wal_store_id`: fsid + mkfs time + shard): binds the acked_lsn witness to this mkfs
    /// instance, so leftover units of an earlier mkfs on the same device never count. 0 = unbound (older builds).
    pub store_id: u32,
}

impl UnitHeader {
    /// Encode header into `buf[..64]`; returns the header crc (the chain value for the next unit).
    pub fn write(&self, buf: &mut [u8]) -> u32 {
        // fixed little-endian layout (magic, epoch, first_lsn, ntxn, nblocks, flags, shard, payload_len, prev_crc,
        // payload_crc, acked_lsn, zero pad, header crc), built in place
        let h = &mut buf[..HDR_LEN];
        h[0..4].copy_from_slice(&UNIT_MAGIC.to_le_bytes());
        h[4..8].copy_from_slice(&self.epoch.to_le_bytes());
        h[8..16].copy_from_slice(&self.first_lsn.to_le_bytes());
        h[16..20].copy_from_slice(&self.ntxn.to_le_bytes());
        h[20..22].copy_from_slice(&self.nblocks.to_le_bytes());
        h[22..24].copy_from_slice(&self.flags.to_le_bytes());
        h[24..28].copy_from_slice(&self.shard.to_le_bytes());
        h[28..32].copy_from_slice(&self.payload_len.to_le_bytes());
        h[32..36].copy_from_slice(&self.prev_crc.to_le_bytes());
        h[36..40].copy_from_slice(&self.payload_crc.to_le_bytes());
        h[40..48].copy_from_slice(&self.acked_lsn.to_le_bytes());
        h[48..52].copy_from_slice(&self.store_id.to_le_bytes());
        h[52..HDR_LEN - 4].fill(0);
        let c = crc(&h[..HDR_LEN - 4]);
        h[HDR_LEN - 4..].copy_from_slice(&c.to_le_bytes());
        c
    }

    /// PAD shape: no txn, one block, no payload.
    fn is_pad_shape(&self) -> bool {
        self.ntxn == 0 && self.nblocks == 1 && self.payload_len == 0
    }

    /// Bounds of a non-PAD unit at ring block `pos` of a ring of `n_ring` blocks: at least one block, inside the
    /// ring (no wrap), payload behind the header within its blocks. The replay parser and the witness scan both
    /// decide "valid unit" with it.
    fn fits(&self, pos: u64, n_ring: u64) -> bool {
        let nb = u64::from(self.nblocks);
        nb > 0 && pos + nb <= n_ring && self.payload_len as usize + HDR_LEN <= nb as usize * BLK
    }

    /// Decode + verify header crc. Returns (header, header crc).
    pub fn read(b: &[u8]) -> Option<(UnitHeader, u32)> {
        if b.len() < HDR_LEN {
            return None;
        }
        let stored = denc::le::rd_u32(b, HDR_LEN - 4);
        if stored != crc(&b[..HDR_LEN - 4]) {
            return None;
        }
        let mut d = Dec::new(b);
        if d.u32()? != UNIT_MAGIC {
            return None;
        }
        Some((
            UnitHeader {
                epoch: d.u32()?,
                first_lsn: d.u64()?,
                ntxn: d.u32()?,
                nblocks: d.u16()?,
                flags: d.u16()?,
                shard: d.u32()?,
                payload_len: d.u32()?,
                prev_crc: d.u32()?,
                payload_crc: d.u32()?,
                acked_lsn: d.u64()?,
                store_id: d.u32()?,
            },
            stored,
        ))
    }
}

/// Record header bytes: length u32, lsn u64, op / extent / free counts u32.
pub const REC_HDR_LEN: usize = 24;
/// Smallest encoded op: `TAG_DEL` (tag, key length; the key itself may be empty).
const TAG_DEL_LEN: usize = 3;
/// Smallest encoded data extent: block u64, blocks u32 (its crcs follow once per block).
const EXT_LEN: usize = 12;
/// Smallest encoded free run: block u64, blocks u32.
const FREE_LEN: usize = 12;

/// Serialize one record (appends to `e`).
pub fn encode_record(rec: &Record, e: &mut Enc) {
    let start = e.b.len();
    e.u32(0)
        .u64(rec.lsn)
        .u32(rec.ops.len() as u32)
        .u32(rec.data.len() as u32)
        .u32(rec.frees.len() as u32);
    for op in &rec.ops {
        match op {
            Op::Put(k, v) => {
                e.u8(TAG_PUT)
                    .u16(k.len() as u16)
                    .u32(v.len() as u32)
                    .bytes(k)
                    .bytes(v);
            }
            Op::Del(k) => {
                e.u8(TAG_DEL).u16(k.len() as u16).bytes(k);
            }
            Op::DelRange(a, b) => {
                e.u8(TAG_DELR)
                    .u16(a.len() as u16)
                    .u16(b.len() as u16)
                    .bytes(a)
                    .bytes(b);
            }
            Op::RunPut(r) => {
                e.u8(TAG_RUN)
                    .u64(r.ord())
                    .u64(r.id())
                    .u32(r.len() as u32)
                    .u32(r.raw().len() as u32)
                    .bytes(r.raw());
            }
            Op::RunMerge {
                id,
                upto,
                a,
                b,
                fin,
            } => {
                e.u8(TAG_RMERGE)
                    .u64(*id)
                    .u64(*upto)
                    .u8(*fin as u8)
                    .u16(a.len() as u16)
                    .u16(b.len() as u16)
                    .bytes(a)
                    .bytes(b);
            }
            Op::Omap(o) => match o {
                OOp::Put { id, n, blob } => {
                    e.u8(TAG_LPUT)
                        .u64(*id)
                        .u32(*n)
                        .u32(blob.len() as u32)
                        .bytes(blob);
                }
                OOp::Del { id, blob } => {
                    e.u8(TAG_LDEL).u64(*id).u32(blob.len() as u32).bytes(blob);
                }
                OOp::Range { id, first, end } => {
                    e.u8(TAG_LRANGE)
                        .u64(*id)
                        .u8(end.is_some() as u8)
                        .u32(first.len() as u32)
                        .u32(end.as_ref().map_or(0, |x| x.len()) as u32)
                        .bytes(first)
                        .bytes(end.as_deref().unwrap_or_default());
                }
            },
        }
    }
    for x in &rec.data {
        e.u64(x.blk).u32(x.nblk);
        x.crcs.iter().for_each(|&c| {
            e.u32(c);
        });
    }
    for &(b, n) in &rec.frees {
        e.u64(b).u32(n);
    }
    let len = (e.b.len() - start) as u32;
    e.b[start..start + 4].copy_from_slice(&len.to_le_bytes());
}

pub fn decode_record(d: &mut Dec) -> Option<Record> {
    let start = d.pos;
    let len = d.u32()? as usize;
    let lsn = d.u64()?;
    let (nops, ndata, nfree) = (d.u32()?, d.u32()?, d.u32()?);
    // the bytes the elements need at least (op tag + its shortest length field, extent / free entry): reject absurd
    // counts before allocating
    if (nops as usize)
        .saturating_mul(TAG_DEL_LEN)
        .saturating_add((ndata as usize).saturating_mul(EXT_LEN))
        .saturating_add((nfree as usize).saturating_mul(FREE_LEN))
        > d.left()
    {
        return None;
    }
    let mut ops = Vec::with_capacity(nops as usize);
    for _ in 0..nops {
        ops.push(match d.u8()? {
            TAG_PUT => {
                let (kl, vl) = (d.u16()? as usize, d.u32()? as usize);
                Op::Put(d.bytes(kl)?.to_vec(), d.bytes(vl)?.to_vec())
            }
            TAG_DEL => {
                let kl = d.u16()? as usize;
                Op::Del(d.bytes(kl)?.to_vec())
            }
            TAG_ODEL => {
                let kl = d.u16()? as usize;
                let k = d.bytes(kl)?.to_vec();
                omap_id(&k)?;
                Op::Del(k)
            }
            TAG_OPUT => {
                let (kl, vl) = (d.u16()? as usize, d.u32()? as usize);
                let k = d.bytes(kl)?.to_vec();
                omap_id(&k)?;
                Op::Put(k, d.bytes(vl)?.to_vec())
            }
            TAG_DELR => {
                let (al, bl) = (d.u16()? as usize, d.u16()? as usize);
                Op::DelRange(d.bytes(al)?.to_vec(), d.bytes(bl)?.to_vec())
            }
            TAG_RUN => {
                let (ord, id) = (d.u64()?, d.u64()?);
                let (n, len) = (d.u32()? as usize, d.u32()? as usize);
                let buf = bytes::Bytes::copy_from_slice(d.bytes(len)?);
                let r = RunBlob::decode(id, n, buf)?;
                // a re-log names an older run of its object
                if ord >= lsn {
                    return None;
                }
                Op::RunPut(if ord == 0 { r } else { r.with_ord(ord) })
            }
            TAG_RMERGE => {
                let (id, upto, fin) = (d.u64()?, d.u64()?, d.u8()?);
                let (al, bl) = (d.u16()? as usize, d.u16()? as usize);
                if fin > 1 {
                    return None;
                }
                Op::RunMerge {
                    id,
                    upto,
                    a: d.bytes(al)?.to_vec(),
                    b: d.bytes(bl)?.to_vec(),
                    fin: fin == 1,
                }
            }
            TAG_LPUT => {
                let (id, n, len) = (d.u64()?, d.u32()?, d.u32()? as usize);
                let blob = bytes::Bytes::copy_from_slice(d.bytes(len)?);
                let o = OOp::Put { id, n, blob };
                o.validate()?;
                Op::Omap(o)
            }
            TAG_LDEL => {
                let (id, len) = (d.u64()?, d.u32()? as usize);
                let o = OOp::Del {
                    id,
                    blob: bytes::Bytes::copy_from_slice(d.bytes(len)?),
                };
                o.validate()?;
                Op::Omap(o)
            }
            TAG_LRANGE => {
                let (id, has_end) = (d.u64()?, d.u8()?);
                let (fl, el) = (d.u32()? as usize, d.u32()? as usize);
                if has_end > 1 || (has_end == 0 && el != 0) {
                    return None;
                }
                let first = bytes::Bytes::copy_from_slice(d.bytes(fl)?);
                let end = d.bytes(el)?;
                let o = OOp::Range {
                    id,
                    first,
                    end: (has_end == 1).then(|| bytes::Bytes::copy_from_slice(end)),
                };
                o.validate()?;
                Op::Omap(o)
            }
            _ => return None,
        });
    }
    let mut data = Vec::with_capacity(ndata as usize);
    for _ in 0..ndata {
        let (blk, nblk) = (d.u64()?, d.u32()?);
        if (nblk as usize) * 4 > d.left() {
            return None;
        }
        let crcs = (0..nblk).map(|_| d.u32()).collect::<Option<Vec<_>>>()?;
        data.push(Extent { blk, nblk, crcs });
    }
    let mut frees = Vec::with_capacity(nfree as usize);
    for _ in 0..nfree {
        frees.push((d.u64()?, d.u32()?));
    }
    (d.pos - start == len).then_some(Record {
        lsn,
        ops,
        data,
        frees,
    })
}

/// A unit as it sits in the ring (used for space accounting and checkpoint release).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingUnit {
    pub first_lsn: u64,
    /// Last lsn contained; `first_lsn - 1` for PAD units.
    pub last_lsn: u64,
    pub pos: u64,
    /// Ring blocks consumed (for PAD: everything up to the ring end).
    pub blocks: u64,
    /// Header crc = chain value for the next unit.
    pub crc: u32,
    /// Non-final part of a multi-unit txn (not a release boundary, not a PAD).
    pub part: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReplayStats {
    pub units: u64,
    pub pads: u64,
    pub txns: u64,
    pub wal_blocks_read: u64,
    pub data_blocks_checked: u64,
    /// Valid-looking units dropped because a data block failed crc validation.
    pub data_invalid_units: u64,
    /// Records of the omap run window (`floor..=ckpt_lsn`, adr 0476) replayed into the runs only.
    pub run_txns: u64,
    /// Multi-part txns (ADR 0028) replayed / dropped because a part (or its data) was missing or invalid.
    pub multi_txns: u64,
    pub multi_dropped: u64,
    /// Operator override (`accept_loss`) was needed: `(first lost lsn, highest lsn proven acked)`. Acked txns
    /// `first..=acked` are GONE from this shard (ADR 0021 am. 9).
    pub lost: Option<(u64, u64)>,
    /// Last lsn the WAL replay recovered (the root's checkpoint lsn when nothing followed it).
    pub last_lsn: u64,
    /// The log ended at a unit whose data failed validation and no later unit witnessed its ack: replay treated it
    /// as a torn tail. Also what media corruption of the newest acked, not yet checkpointed data looks like (adr 0021
    /// S2 residual, accepted by design, am. 84): logged and reported by fsck/repair, no health alert.
    pub tail_dropped: Option<TailDropped>,
}

/// A WAL tail replay dropped because its data failed validation ([`ReplayStats::tail_dropped`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TailDropped {
    pub shard: u32,
    /// Every record from `first_lsn` on is dropped; `last_lsn` / `txns`: the dropped records the replay read (its
    /// validation batch). Units in flight behind them are dropped too but not read, so not counted.
    pub first_lsn: u64,
    pub last_lsn: u64,
    pub txns: u64,
    /// First block that failed: data crc mismatch, or an extent outside the data region.
    pub blk: u64,
    pub reason: &'static str,
}

impl std::fmt::Display for TailDropped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "lsn {}..{} ({} txns), {} at block {}; dropped as torn tail",
            self.first_lsn, self.last_lsn, self.txns, self.reason, self.blk
        )
    }
}

#[derive(Debug)]
pub struct ReplayOut {
    /// Last valid lsn (ckpt_lsn if the log is empty).
    pub last_lsn: u64,
    /// Ring position where the next unit goes, and the chain crc it must carry.
    pub head_pos: u64,
    pub head_crc: u32,
    pub max_epoch: u32,
    /// Valid units from the tail to the head.
    pub ring: VecDeque<RingUnit>,
    /// Blocks freed by replayed units `(unit last_lsn, blocks)`: must stay unreusable until a checkpoint passes
    /// them, or the next replay would validate a record's data against recycled blocks.
    pub frees: Vec<(u64, Vec<(u64, u32)>)>,
    pub stats: ReplayStats,
}

#[derive(Clone, Copy, Debug)]
pub struct ReplayCfg {
    /// Sequential ring read size in blocks.
    pub chunk_blocks: u32,
    /// Max units parsed before their data is validated; must be nonzero.
    pub batch_units: usize,
    /// Max data blocks pending validation per batch; must be nonzero.
    pub batch_data_blocks: u64,
    /// Blocks scanned past the end of the valid log for proof that the cut is not a torn tail (must cover
    /// `(max_inflight_units + ready_cap) * max_unit_blocks`: the units sealed between the cut unit and the first
    /// unit written after its ack). Parts of multi-part chains sealed after the cut are passed free of charge.
    pub scan_blocks: u64,
    /// Operator override: mount although acked txns were lost (data loss, reported in `ReplayStats::lost`).
    pub accept_loss: bool,
}

static ACCEPT_WAL_LOSS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Process-wide operator override (`--accept-wal-loss`): `ReplayCfg::default()` picks it up.
pub fn set_accept_wal_loss(on: bool) {
    ACCEPT_WAL_LOSS.store(on, std::sync::atomic::Ordering::Relaxed);
}

impl Default for ReplayCfg {
    fn default() -> Self {
        ReplayCfg {
            chunk_blocks: 256,
            batch_units: 256,
            batch_data_blocks: 8192,
            scan_blocks: 8192,
            accept_loss: ACCEPT_WAL_LOSS.load(std::sync::atomic::Ordering::Relaxed),
        }
    }
}

impl ReplayCfg {
    fn validate(&self) -> Result<()> {
        if self.batch_units == 0 || self.batch_data_blocks == 0 {
            return Err(StoreError::Invalid(
                "WAL replay batch limits must be nonzero",
            ));
        }
        Ok(())
    }
}

/// Ring blocks read for replay: `buf` holds the blocks from ring block `start` on.
struct Win {
    start: u64,
    buf: Vec<u8>,
}

impl Win {
    /// Make ring blocks `[blk, blk + n)` present; on a miss read `n.max(chunk)` blocks from `blk` (capped at the ring
    /// end). Returns the blocks read (0: already present).
    fn ensure<D: BlockDev, C: Clock>(
        &mut self,
        io: &mut Sio<D, C>,
        dir: &ShardDir,
        blk: u64,
        n: u64,
        chunk: u64,
    ) -> Result<u64> {
        let have = self.buf.len() as u64 / BLK as u64;
        if blk >= self.start && blk + n <= self.start + have {
            return Ok(0);
        }
        let want = n.max(chunk).min(dir.wal_blocks - blk);
        self.buf = io.read_one(dir.wal_start + blk, want as u32)?;
        self.start = blk;
        Ok(want)
    }

    /// Header bytes of the unit at ring block `pos` (present: [`Win::ensure`]).
    fn header(&self, pos: u64) -> &[u8] {
        let off = ((pos - self.start) as usize) * BLK;
        &self.buf[off..off + HDR_LEN]
    }

    /// Payload of the unit `h` at ring block `pos` (its blocks present: [`Win::ensure`]) when its crc matches.
    fn payload(&self, pos: u64, h: &UnitHeader) -> Option<&[u8]> {
        let off = ((pos - self.start) as usize) * BLK + HDR_LEN;
        let p = &self.buf[off..off + h.payload_len as usize];
        (crc(p) == h.payload_crc).then_some(p)
    }
}

struct Parsed {
    epoch: u32,
    /// Ring units of this logical unit: one, or a whole multi-part chain (+ PADs inside it).
    rings: Vec<RingUnit>,
    recs: Vec<Record>,
    part: Option<PartIn>,
}

struct PartIn {
    idx: u32,
    end: bool,
    bytes: Vec<u8>,
}

/// Multi-part chain being assembled during the header parse.
struct Chain {
    rings: Vec<RingUnit>,
    bytes: Vec<u8>,
    next_idx: u32,
}

/// Replay the WAL of one shard onto `state` (which must be the state as of `root.ckpt_lsn`).
///
/// Omap run window (adr 0476): the ring starts at `root.tail_lsn()`; records below `root.floor()` are
/// skipped, records `floor..=ckpt_lsn` rebuild only the runs (`State::apply_runs_only`: their tree, allocator and data
/// effects are in the checkpoint, their data blocks may be reused, so no data crc check), later records replay fully. A
/// log that ends before `ckpt_lsn` lost acked runs: `Corrupt`.
pub fn replay<D: BlockDev, C: Clock>(
    io: &mut Sio<D, C>,
    dir: &ShardDir,
    root: &RootSlot,
    store_id: u32,
    state: &mut State,
    cfg: &ReplayCfg,
) -> Result<ReplayOut> {
    cfg.validate()?;
    let n_ring = dir.wal_blocks;
    let mut out = ReplayOut {
        last_lsn: root.ckpt_lsn,
        head_pos: root.wal_tail_pos,
        head_crc: root.wal_tail_prev_crc,
        max_epoch: root.epoch,
        ring: VecDeque::new(),
        frees: Vec::new(),
        stats: ReplayStats::default(),
    };
    let mut win = Win {
        start: 0,
        buf: Vec::new(),
    };
    let mut pos = root.wal_tail_pos;
    let mut chain = root.wal_tail_prev_crc;
    let mut expected = root.tail_lsn();
    let (floor, ckpt) = (root.floor(), root.ckpt_lsn);
    // last record lsn seen (replayed, run-only or skipped)
    let mut seen = expected - 1;
    let mut last_epoch = 0u32;
    let mut ended = false;
    if pos >= n_ring {
        return Err(StoreError::Corrupt("wal tail outside ring".into()));
    }

    while !ended {
        // ---- parse phase: header chain only
        let mut batch: Vec<Parsed> = Vec::new();
        let mut pend_data = 0u64;
        let mut acc: Option<Chain> = None;
        // a multi-part chain is parsed to its END before the batch limits apply
        while acc.is_some() || (batch.len() < cfg.batch_units && pend_data < cfg.batch_data_blocks)
        {
            let Some((mut p, next)) = parse_unit(
                io,
                dir,
                root,
                &mut win,
                &mut out.stats,
                cfg,
                pos,
                chain,
                expected,
                last_epoch,
            )?
            else {
                ended = true; // an unfinished chain in `acc` is dropped: all-or-nothing
                break;
            };
            let is_pad = p.recs.is_empty() && p.part.is_none();
            match p.part.take() {
                None if is_pad && acc.is_some() => {
                    // wrap PAD between parts: belongs to the chain
                    acc.as_mut().unwrap().rings.append(&mut p.rings);
                }
                None if acc.is_some() => {
                    ended = true; // a normal unit inside a chain: the chain is broken
                    break;
                }
                None => {
                    pend_data += p
                        .recs
                        .iter()
                        .filter(|r| r.lsn > ckpt)
                        .flat_map(|r| r.data.iter())
                        .map(|e| e.nblk as u64)
                        .sum::<u64>();
                    batch.push(p);
                }
                Some(pi) => {
                    let c = acc.get_or_insert_with(|| Chain {
                        rings: Vec::new(),
                        bytes: Vec::new(),
                        next_idx: 0,
                    });
                    if pi.idx != c.next_idx {
                        ended = true;
                        break;
                    }
                    c.next_idx += 1;
                    c.bytes.extend_from_slice(&pi.bytes);
                    c.rings.append(&mut p.rings);
                    if pi.end {
                        let c = acc.take().unwrap();
                        let first = c.rings.last().unwrap().first_lsn;
                        let mut d = Dec::new(&c.bytes);
                        match decode_record(&mut d) {
                            Some(r) if r.lsn == first && d.left() == 0 => {
                                if r.lsn > ckpt {
                                    pend_data += r.data.iter().map(|e| e.nblk as u64).sum::<u64>();
                                }
                                batch.push(Parsed {
                                    epoch: p.epoch,
                                    rings: c.rings,
                                    recs: vec![r],
                                    part: None,
                                });
                            }
                            // every part verified its crc: the chain was written whole, never a torn tail
                            _ => {
                                let at = c.rings.last().map_or(pos, |r| r.pos);
                                return Err(undecodable(
                                    dir,
                                    at,
                                    first,
                                    "an undecodable multi-part record",
                                ));
                            }
                        }
                    }
                }
            }
            (pos, chain, expected, last_epoch) = next;
        }
        if acc.is_some() {
            out.stats.multi_dropped += 1;
        }

        // ---- validate phase: parallel-commit data crcs, whole-unit granularity. An extent outside the data region
        // invalidates its unit like a bad crc: only a unit that was never acked can name one (a torn tail whose borrowed
        // chunk was returned after the mount that cut the log there, adr 0021 am. 49: an acked record beyond the
        // checkpoint keeps its blocks allocated or held, so its chunk is not returned); an acked one is a lost acked txn
        // (witness check below).
        let mut jobs: Vec<(u64, u32)> = Vec::new();
        let mut owner: Vec<(usize, usize, usize)> = Vec::new(); // (unit, rec, extent)
        let mut bad_unit = batch.len();
        let mut bad_at = (0, ""); // (first failing block of `bad_unit`, reason)
        'units: for (ui, u) in batch.iter().enumerate() {
            for (ri, r) in u.recs.iter().enumerate().filter(|(_, r)| r.lsn > ckpt) {
                for (xi, x) in r.data.iter().enumerate() {
                    if x.nblk == 0 {
                        return Err(StoreError::Corrupt(format!("lsn {}: empty extent", r.lsn)));
                    }
                    if !dir.in_data(x.blk, x.nblk as u64) {
                        bad_unit = ui;
                        bad_at = (x.blk, "extent outside data region");
                        break 'units;
                    }
                    jobs.push((x.blk, x.nblk));
                    owner.push((ui, ri, xi));
                }
            }
        }
        let bufs = io.read(&jobs)?;
        for (&(ui, ri, xi), buf) in owner.iter().zip(bufs.iter()) {
            let x = &batch[ui].recs[ri].data[xi];
            out.stats.data_blocks_checked += x.nblk as u64;
            let bad = buf
                .chunks(BLK)
                .zip(&x.crcs)
                .enumerate()
                .position(|(i, (b, &c))| blk_crc(x.blk + i as u64, b) != c);
            if let Some(i) = bad
                && ui < bad_unit
            {
                bad_unit = ui;
                bad_at = (x.blk + i as u64, "data crc mismatch");
            }
        }
        if bad_unit < batch.len() {
            out.stats.data_invalid_units += 1;
            ended = true;
            let lsns = || {
                batch[bad_unit..]
                    .iter()
                    .flat_map(|u| &u.recs)
                    .map(|r| r.lsn)
                    .filter(|&l| l > ckpt)
            };
            out.stats.tail_dropped = Some(TailDropped {
                shard: dir.shard,
                first_lsn: lsns().next().unwrap_or(0),
                last_lsn: lsns().next_back().unwrap_or(0),
                txns: lsns().count() as u64,
                blk: bad_at.0,
                reason: bad_at.1,
            });
        }
        for u in batch.drain(..bad_unit) {
            let last = u.rings.last().unwrap();
            let fr: Vec<(u64, u32)> = u
                .recs
                .iter()
                .filter(|r| r.lsn > ckpt)
                .flat_map(|r| r.frees.iter().copied())
                .collect();
            if !fr.is_empty() {
                out.frees.push((last.last_lsn, fr));
            }
            for r in &u.recs {
                seen = r.lsn;
                if r.lsn > ckpt {
                    state.apply_blocking(io, r)?;
                    out.last_lsn = r.lsn;
                    out.stats.txns += 1;
                } else if r.lsn >= floor {
                    state.apply_runs_only(r);
                    out.stats.run_txns += 1;
                }
            }
            if u.rings.iter().any(|r| r.part) {
                out.stats.multi_txns += 1;
            }
            for r in &u.rings {
                if r.last_lsn < r.first_lsn && !r.part {
                    out.stats.pads += 1;
                } else {
                    out.stats.units += 1;
                }
            }
            // PAD: pos + blocks == ring end -> 0
            out.head_pos = (last.pos + last.blocks) % n_ring;
            out.max_epoch = out.max_epoch.max(u.epoch);
            out.head_crc = last.crc;
            out.ring.extend(u.rings);
        }
    }
    // the run window must be whole: its records were acked before the checkpoint
    if seen < ckpt {
        return Err(StoreError::Corrupt(format!(
            "wal ends at lsn {seen} inside the omap run window {floor}..={ckpt}"
        )));
    }
    // the log ends here: torn tail (never acked, fine) or lost acked txns (media corruption)?
    let e = out.last_lsn + 1;
    if let Some(acked) = acked_beyond(io, dir, root, store_id, out.head_pos, e, cfg)? {
        if !cfg.accept_loss {
            return Err(StoreError::WalLost {
                shard: dir.shard,
                lsn: e,
                acked_lsn: acked,
            });
        }
        eprintln!(
            "croit-flashstore-osd: CRITICAL shard {}: --accept-wal-loss: acked txns lsn {e}..={acked} LOST (WAL corrupt at ring block {})",
            dir.shard, out.head_pos
        );
        out.stats.lost = Some((e, acked));
        // a lost acked range is reported above, not as a torn tail
        out.stats.tail_dropped = None;
    } else if let Some(t) = &out.stats.tail_dropped {
        // BlueStore / RocksDB point-in-time recovery: the log ends at the first corrupt record, one log line, no alert
        eprintln!(
            "croit-flashstore-osd: WAL replay stopped at lsn {} ({} at block {}, shard {}): tail from lsn {} dropped as torn (unacknowledged in-flight writes or media corruption)",
            t.first_lsn, t.reason, t.blk, t.shard, t.first_lsn
        );
    }
    out.stats.last_lsn = out.last_lsn;
    Ok(out)
}

/// Highest lsn `>= e` proven acked by a unit of the current or a newer incarnation within `cfg.scan_blocks` after
/// `from`. A unit header carries the acked lsn at its seal time, so a valid unit with `acked_lsn >= e` was written after
/// txn `e` was acked: the log must not end before `e` (ADR 0021 am. 9). Units of older incarnations (epoch <
/// root.epoch: leftovers of an earlier torn tail or an accepted loss) and older ring laps (acked < e) never match. Units
/// of a newer incarnation (epoch > root.epoch) exist only when the newest root slot is lost (review 2026-11-03 #3):
/// they prove their acked txns like units of the current one.
/// Unlike [`parse_unit`] the scan ignores the header flags it does not know: it only needs the PAD shape or `fits` plus
/// the payload crc, so a unit written by a newer build still proves what it acked (the parser refuses it and replay
/// stops there; the witness turns that into `WalLost` when txns are missing).
/// The parts of a multi-part chain sealed after the cut (`first_lsn >= e`) do not count against the budget: a chain is
/// sealed at once and may be far longer than the units the budget covers (adr 0028), and the first unit sealed after
/// the cut unit's ack can lie behind it. The scan never covers more than one ring lap.
fn acked_beyond<D: BlockDev, C: Clock>(
    io: &mut Sio<D, C>,
    dir: &ShardDir,
    root: &RootSlot,
    store_id: u32,
    from: u64,
    e: u64,
    cfg: &ReplayCfg,
) -> Result<Option<u64>> {
    Ok(acked_witness(io, dir, root, store_id, from, e, cfg)?.map(|(acked, _)| acked))
}

/// [`acked_beyond`] plus the ring block of the proving unit: `(highest acked lsn, witness block)`.
fn acked_witness<D: BlockDev, C: Clock>(
    io: &mut Sio<D, C>,
    dir: &ShardDir,
    root: &RootSlot,
    store_id: u32,
    from: u64,
    e: u64,
    cfg: &ReplayCfg,
) -> Result<Option<(u64, u64)>> {
    let n_ring = dir.wal_blocks;
    let total = cfg.scan_blocks.min(n_ring);
    let chunk = (cfg.chunk_blocks as u64).max(1);
    let mut best: Option<(u64, u64)> = None;
    // `counted`: blocks charged to the budget; `scanned`: all blocks passed (bounded by the ring)
    let (mut at, mut counted, mut scanned) = (from, 0u64, 0u64);
    let mut win = Win {
        start: 0,
        buf: Vec::new(),
    };
    while counted < total && scanned < n_ring {
        win.ensure(io, dir, at, 1, chunk.min(total - counted))?;
        let mut step = 1;
        let mut part = false;
        if let Some((h, _)) = UnitHeader::read(win.header(at))
            && h.shard == dir.shard
            && h.epoch >= root.epoch
            && h.store_id == store_id
        {
            let witness = h.acked_lsn >= e
                && h.acked_lsn < h.first_lsn
                && !best.is_some_and(|(b, _)| b >= h.acked_lsn);
            if h.flags & FLAG_PAD != 0 {
                if witness && h.is_pad_shape() {
                    best = Some((h.acked_lsn, at));
                }
            } else {
                let nb = u64::from(h.nblocks);
                let sane = h.fits(at, n_ring);
                if sane && h.flags & FLAG_PART != 0 && h.first_lsn >= e {
                    // a chain part sealed after the cut: step over it free of charge
                    step = nb;
                    part = true;
                }
                if sane && witness {
                    win.ensure(io, dir, at, nb, chunk.min(total - counted))?;
                    if win.payload(at, &h).is_some() {
                        best = Some((h.acked_lsn, at));
                    }
                }
            }
        }
        let step = step.min(n_ring - scanned);
        scanned += step;
        if !part {
            counted += step;
        }
        at = (at + step) % n_ring;
    }
    Ok(best)
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn parse_unit<D: BlockDev, C: Clock>(
    io: &mut Sio<D, C>,
    dir: &ShardDir,
    root: &RootSlot,
    win: &mut Win,
    stats: &mut ReplayStats,
    cfg: &ReplayCfg,
    pos: u64,
    chain: u32,
    expected: u64,
    last_epoch: u32,
) -> Result<Option<(Parsed, (u64, u32, u64, u32))>> {
    let n_ring = dir.wal_blocks;
    let chunk = u64::from(cfg.chunk_blocks);
    stats.wal_blocks_read += win.ensure(io, dir, pos, 1, chunk)?;
    let Some((h, hcrc)) = UnitHeader::read(win.header(pos)) else {
        return Ok(None);
    };
    if h.shard != dir.shard
        || h.epoch < last_epoch
        || h.prev_crc != chain
        || h.first_lsn != expected
    {
        return Ok(None);
    }
    if h.epoch > root.epoch {
        return Err(newer_incarnation(dir, pos, h.first_lsn, h.epoch, root));
    }
    if h.flags & !FLAGS_KNOWN != 0 {
        return Err(undecodable(
            dir,
            pos,
            h.first_lsn,
            &format!("unknown header flags {:#x}", h.flags & !FLAGS_KNOWN),
        ));
    }
    if h.flags & FLAG_PAD != 0 {
        if !h.is_pad_shape() {
            return Ok(None);
        }
        let ru = RingUnit {
            first_lsn: h.first_lsn,
            last_lsn: h.first_lsn - 1,
            pos,
            blocks: n_ring - pos,
            crc: hcrc,
            part: false,
        };
        return Ok(Some((
            Parsed {
                epoch: h.epoch,
                rings: vec![ru],
                recs: Vec::new(),
                part: None,
            },
            (0, hcrc, expected, h.epoch),
        )));
    }
    let nb = h.nblocks as u64;
    if h.flags & (FLAG_PART | FLAG_END) != 0 {
        // multi-part txn unit: payload = slice of the record encoding, ntxn = part index
        let end = h.flags & FLAG_END != 0;
        if (h.flags & FLAG_PART != 0 && end) || h.payload_len == 0 || !h.fits(pos, n_ring) {
            return Ok(None);
        }
        stats.wal_blocks_read += win.ensure(io, dir, pos, nb, chunk)?;
        let Some(payload) = win.payload(pos, &h) else {
            return Ok(None);
        };
        let ru = RingUnit {
            first_lsn: h.first_lsn,
            last_lsn: if end { h.first_lsn } else { h.first_lsn - 1 },
            pos,
            blocks: nb,
            crc: hcrc,
            part: !end,
        };
        return Ok(Some((
            Parsed {
                epoch: h.epoch,
                rings: vec![ru],
                recs: Vec::new(),
                part: Some(PartIn {
                    idx: h.ntxn,
                    end,
                    bytes: payload.to_vec(),
                }),
            },
            ((pos + nb) % n_ring, hcrc, expected + end as u64, h.epoch),
        )));
    }
    if h.ntxn == 0 || !h.fits(pos, n_ring) {
        return Ok(None);
    }
    stats.wal_blocks_read += win.ensure(io, dir, pos, nb, chunk)?;
    let Some(payload) = win.payload(pos, &h) else {
        return Ok(None);
    };
    let ntxn = h.ntxn as usize;
    // every record needs at least its header: reject a count the payload cannot hold before reserving it
    if ntxn > payload.len() / REC_HDR_LEN {
        return Err(undecodable(
            dir,
            pos,
            h.first_lsn,
            "a record count beyond the payload",
        ));
    }
    let mut d = Dec::new(payload);
    let mut recs = Vec::with_capacity(ntxn);
    for i in 0..h.ntxn {
        match decode_record(&mut d) {
            Some(r) if r.lsn == h.first_lsn + i as u64 => recs.push(r),
            _ => {
                return Err(undecodable(
                    dir,
                    pos,
                    h.first_lsn + i as u64,
                    "an undecodable record",
                ));
            }
        }
    }
    if d.left() != 0 {
        return Err(undecodable(dir, pos, h.first_lsn, "trailing payload bytes"));
    }
    let ru = RingUnit {
        first_lsn: h.first_lsn,
        last_lsn: h.first_lsn + h.ntxn as u64 - 1,
        pos,
        blocks: nb,
        crc: hcrc,
        part: false,
    };
    let next_pos = (pos + nb) % n_ring;
    Ok(Some((
        Parsed {
            epoch: h.epoch,
            rings: vec![ru],
            recs,
            part: None,
        },
        (next_pos, hcrc, expected + h.ntxn as u64, h.epoch),
    )))
}

// ------------------------------------------------- read-only WAL inspection (croit-flashstore-tool wal-inspect)

/// Read-only WAL decode of one shard (`croit-flashstore-tool wal-inspect`): the decoded ring without mounting and
/// without writing, plus where replay would stop and why.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WalInspect {
    /// The units replay applies, from the tail to the cut, then (torn / foreign stop only) the unit that ends the log.
    pub units: Vec<InspectUnit>,
    /// Where replay stops and why.
    pub stop: InspectStop,
    /// Decodable records a `--accept-wal-loss` cut drops (`WalLost` only): txns with `lsn >= stop.lsn` from the units
    /// behind the cut within the witness scan window. The cut drops every lsn `>= stop.lsn`; records of the unreadable
    /// unit at the cut are unknown and not listed.
    pub dropped: Vec<InspectRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InspectUnit {
    /// Ring block of the unit header (the first part of a multi-part chain).
    pub pos: u64,
    pub epoch: u32,
    pub first_lsn: u64,
    pub last_lsn: u64,
    /// Highest lsn acked (durable, in order) when the unit was sealed; 0 = no proof (older build).
    pub acked_lsn: u64,
    /// Store identity binding the acked witness to this mkfs instance.
    pub store_id: u32,
    /// Ring blocks consumed.
    pub blocks: u64,
    /// Header crc (the chain value for the next unit).
    pub crc: u32,
    /// Multi-part chain member (not a release boundary).
    pub part: bool,
    /// PAD unit (wrap marker, no records).
    pub pad: bool,
    /// Whether the unit decoded into the chain (`ok`) or ended the log (`torn` / `foreign`).
    pub validity: UnitValidity,
    /// Records carried (PAD and non-END parts carry none).
    pub records: Vec<InspectRecord>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnitValidity {
    Ok,
    Torn,
    Foreign,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InspectRecord {
    pub lsn: u64,
    /// Op summaries (collection/PG, object, op kind, payload bytes).
    pub ops: Vec<InspectOp>,
    /// Data extents named by the record (block, blocks; per-block crcs stay internal to the data check).
    pub data: Vec<InspectExtent>,
    /// Blocks freed by the record.
    pub frees: Vec<(u64, u32)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InspectExtent {
    pub blk: u64,
    pub nblk: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InspectOp {
    /// `put` / `del` / `del-range` / `run-put` / `run-merge` / `omap-put` / `omap-del` / `omap-range`.
    pub kind: &'static str,
    /// Collection / PG the op names (a `C` collection key), best effort.
    pub coll: Option<CollT>,
    /// Object the op names (an `N` / `L` name key), best effort.
    pub object: Option<Ghobject>,
    /// Object id the op names (an id-keyed record, an omap run, or an omap LSM op).
    pub id: Option<u64>,
    /// Key the op names (put / del; the lower bound of a del-range / run-merge, the first key of an omap range).
    pub key: Vec<u8>,
    /// Payload bytes (value for a put, run blob for a run-put, second bound for a range, omap blob).
    pub bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopReason {
    /// The ring ends cleanly (no unit continues the chain, no acked txn lost).
    End,
    /// A torn unit (header or payload does not verify) ends the log.
    Torn,
    /// A foreign unit (another shard / store / chain) ends the log.
    Foreign,
    /// A data block of a unit fails its crc; without a later witness this is a torn tail (nothing acked lost).
    DataCrc,
    /// A crc-valid unit this build cannot decode (written by a newer build, or a bug): replay refuses.
    Undecodable,
    /// A unit of a newer incarnation continues the chain (the newest root slot is lost): replay refuses.
    NewerIncarnation,
    /// The log ends inside the omap run window: replay refuses.
    RunWindow,
    /// Acked txns `lsn ..= acked_lsn` are unreadable: replay refuses or `--accept-wal-loss` drops them.
    WalLost,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InspectStop {
    pub reason: StopReason,
    /// Ring block of the unit that ends the log; for `WalLost` / `DataCrc` / `RunWindow` the ring block after the last
    /// applied unit (replay's head, the block its loss report names).
    pub pos: u64,
    /// First lsn after the last applied record (replay's `last_lsn + 1`): the cut point.
    pub lsn: u64,
    /// Highest lsn proven acked (WalLost only).
    pub acked_lsn: Option<u64>,
    /// Ring block of the proving witness unit (WalLost only).
    pub witness: Option<u64>,
    /// Data block whose crc failed (DataCrc only).
    pub blk: Option<u64>,
    /// Human detail (undecodable / newer-incarnation / foreign / run-window).
    pub message: Option<String>,
}

impl Default for InspectStop {
    fn default() -> Self {
        InspectStop {
            reason: StopReason::End,
            pos: 0,
            lsn: 0,
            acked_lsn: None,
            witness: None,
            blk: None,
            message: None,
        }
    }
}

fn torn_stop(pos: u64, lsn: u64, what: &str) -> InspectStop {
    InspectStop {
        reason: StopReason::Torn,
        pos,
        lsn,
        message: Some(what.to_string()),
        ..InspectStop::default()
    }
}

fn data_crc_stop(pos: u64, lsn: u64, blk: u64) -> InspectStop {
    InspectStop {
        reason: StopReason::DataCrc,
        pos,
        lsn,
        blk: Some(blk),
        message: Some(format!(
            "data block {blk} fails its recorded crc or lies outside the data region"
        )),
        ..InspectStop::default()
    }
}

/// Classify why the log ends at ring block `pos` (a [`parse_unit`] that returned `None`): a torn header/payload, or a
/// foreign unit (another shard, store or chain). `win.header(pos)` is present: `parse_unit` read it before returning.
fn end_of_log(
    win: &Win,
    dir: &ShardDir,
    pos: u64,
    chain: u32,
    expected: u64,
    last_epoch: u32,
) -> InspectStop {
    let hdr = win.header(pos);
    if hdr.iter().all(|&b| b == 0) {
        return InspectStop {
            reason: StopReason::End,
            pos,
            lsn: expected,
            message: Some("the ring is empty after this point (clean end)".into()),
            ..InspectStop::default()
        };
    }
    let Some((h, _)) = UnitHeader::read(hdr) else {
        return InspectStop {
            reason: StopReason::Torn,
            pos,
            lsn: expected,
            message: Some(
                "no valid unit header (end of the written log: a stale block, a torn write, or bit rot)".into(),
            ),
            ..InspectStop::default()
        };
    };
    if h.shard != dir.shard {
        return InspectStop {
            reason: StopReason::Foreign,
            pos,
            lsn: expected,
            message: Some(format!(
                "unit of shard {} (this is shard {})",
                h.shard, dir.shard
            )),
            ..InspectStop::default()
        };
    }
    if h.epoch < last_epoch || h.prev_crc != chain || h.first_lsn != expected {
        return InspectStop {
            reason: StopReason::Foreign,
            pos,
            lsn: expected,
            message: Some(
                "unit does not continue the chain (stale, or from another incarnation)".into(),
            ),
            ..InspectStop::default()
        };
    }
    InspectStop {
        reason: StopReason::Torn,
        pos,
        lsn: expected,
        message: Some("unit payload does not verify (torn write or bit rot)".into()),
        ..InspectStop::default()
    }
}

/// Best-effort header of the terminal torn/foreign unit (the one that ended the log), appended to the unit list so the
/// operator sees where and why replay stops. A torn header that does not verify has no fields to show.
fn terminal_unit(win: &Win, stop: &InspectStop) -> InspectUnit {
    let validity = if stop.reason == StopReason::Foreign {
        UnitValidity::Foreign
    } else {
        UnitValidity::Torn
    };
    match UnitHeader::read(win.header(stop.pos)) {
        Some((h, hcrc)) => {
            let pad = h.flags & FLAG_PAD != 0;
            let part = h.flags & (FLAG_PART | FLAG_END) != 0 && h.flags & FLAG_END == 0;
            InspectUnit {
                pos: stop.pos,
                epoch: h.epoch,
                first_lsn: h.first_lsn,
                last_lsn: if pad {
                    h.first_lsn.saturating_sub(1)
                } else {
                    h.first_lsn + u64::from(h.ntxn).saturating_sub(1)
                },
                acked_lsn: h.acked_lsn,
                store_id: h.store_id,
                blocks: u64::from(h.nblocks),
                crc: hcrc,
                part,
                pad,
                validity,
                records: Vec::new(),
            }
        }
        None => InspectUnit {
            pos: stop.pos,
            epoch: 0,
            first_lsn: stop.lsn,
            last_lsn: stop.lsn.saturating_sub(1),
            acked_lsn: 0,
            store_id: 0,
            blocks: 1,
            crc: 0,
            part: false,
            pad: false,
            validity,
            records: Vec::new(),
        },
    }
}

/// [`replay`]'s validate phase over one parsed batch, same order and same checks: the first unit whose data is bad
/// (`(unit index, first bad block)`): a data block failing its crc or an extent outside the data region (adr 0021
/// am. 49). An empty extent is `Corrupt`, as in replay.
fn batch_bad_unit<D: BlockDev, C: Clock>(
    io: &mut Sio<D, C>,
    dir: &ShardDir,
    batch: &[(Parsed, u64, u32)],
    ckpt: u64,
) -> Result<Option<(usize, u64)>> {
    let mut jobs: Vec<(u64, u32)> = Vec::new();
    let mut owner: Vec<(usize, &Extent)> = Vec::new();
    let mut bad: Option<(usize, u64)> = None;
    'units: for (ui, (u, ..)) in batch.iter().enumerate() {
        for r in u.recs.iter().filter(|r| r.lsn > ckpt) {
            for x in &r.data {
                if x.nblk == 0 {
                    return Err(StoreError::Corrupt(format!("lsn {}: empty extent", r.lsn)));
                }
                if !dir.in_data(x.blk, x.nblk as u64) {
                    bad = Some((ui, x.blk));
                    break 'units;
                }
                jobs.push((x.blk, x.nblk));
                owner.push((ui, x));
            }
        }
    }
    let bufs = io.read(&jobs)?;
    for (&(ui, x), buf) in owner.iter().zip(bufs.iter()) {
        if bad.is_some_and(|(b, _)| b <= ui) {
            continue;
        }
        if let Some(i) = buf
            .chunks(BLK)
            .zip(&x.crcs)
            .enumerate()
            .position(|(i, (b, &c))| blk_crc(x.blk + i as u64, b) != c)
        {
            bad = Some((ui, x.blk + i as u64));
        }
    }
    Ok(bad)
}

/// The [`InspectUnit`] of one replayed logical unit (a normal unit, a PAD, or a finished multi-part chain); `acked` /
/// `store_id` from its (sealing) header.
fn inspect_unit(u: &Parsed, acked: u64, store_id: u32) -> InspectUnit {
    let (first, last) = (&u.rings[0], &u.rings[u.rings.len() - 1]);
    InspectUnit {
        pos: first.pos,
        epoch: u.epoch,
        first_lsn: first.first_lsn,
        last_lsn: last.last_lsn,
        acked_lsn: acked,
        store_id,
        blocks: u.rings.iter().map(|r| r.blocks).sum(),
        crc: last.crc,
        part: u.rings.iter().any(|r| r.part),
        pad: u.recs.is_empty(),
        validity: UnitValidity::Ok,
        records: u.recs.iter().map(record_summary).collect(),
    }
}

/// A stop where replay refuses the mount (`Corrupt`).
fn refused(reason: StopReason, pos: u64, lsn: u64, message: String) -> InspectStop {
    InspectStop {
        reason,
        pos,
        lsn,
        message: Some(message),
        ..InspectStop::default()
    }
}

/// Collection/PG and object a key names (best effort): a `C` collection key -> PG, an `N`/`L` name key -> object, an
/// id-keyed object record (`n`/`a`/`h`/`e`/`o`/`p`/`d`/`c`) -> object id.
fn key_owners(k: &[u8]) -> (Option<CollT>, Option<Ghobject>, Option<u64>) {
    use crate::obj::keys::{
        T_COLL, T_LNAME, T_NAME, decode_coll_key, decode_long_key, decode_sort_key, onode_id_of,
    };
    match k.first() {
        Some(&T_COLL) => (decode_coll_key(k), None, None),
        Some(&T_NAME) => (None, k.get(9..).and_then(decode_sort_key), None),
        Some(&T_LNAME) => (None, k.get(9..).and_then(decode_long_key), None),
        Some(b'n' | b'a' | b'h' | b'e' | b'o' | b'p' | b'd' | b'c') => (None, None, onode_id_of(k)),
        _ => (None, None, None),
    }
}

/// Op summary of one record op (kind, collection/PG, object, key, payload bytes).
fn op_summary(op: &Op) -> InspectOp {
    use crate::olsm::wire::OOp;
    match op {
        Op::Put(k, v) => {
            let (coll, object, id) = key_owners(k);
            InspectOp {
                kind: "put",
                coll,
                object,
                id,
                key: k.clone(),
                bytes: v.len(),
            }
        }
        Op::Del(k) => {
            let (coll, object, id) = key_owners(k);
            InspectOp {
                kind: "del",
                coll,
                object,
                id,
                key: k.clone(),
                bytes: 0,
            }
        }
        Op::DelRange(a, b) => {
            let (coll, object, id) = key_owners(a);
            InspectOp {
                kind: "del-range",
                coll,
                object,
                id,
                key: a.clone(),
                bytes: b.len(),
            }
        }
        Op::RunPut(r) => InspectOp {
            kind: "run-put",
            coll: None,
            object: None,
            id: Some(r.id()),
            key: Vec::new(),
            bytes: r.raw().len(),
        },
        Op::RunMerge { id, a, b, .. } => InspectOp {
            kind: "run-merge",
            coll: None,
            object: None,
            id: Some(*id),
            key: a.clone(),
            bytes: b.len(),
        },
        Op::Omap(o) => match o {
            OOp::Put { id, blob, .. } => InspectOp {
                kind: "omap-put",
                coll: None,
                object: None,
                id: Some(*id),
                key: Vec::new(),
                bytes: blob.len(),
            },
            OOp::Del { id, blob } => InspectOp {
                kind: "omap-del",
                coll: None,
                object: None,
                id: Some(*id),
                key: Vec::new(),
                bytes: blob.len(),
            },
            OOp::Range { id, first, end } => InspectOp {
                kind: "omap-range",
                coll: None,
                object: None,
                id: Some(*id),
                key: first.to_vec(),
                bytes: end.as_ref().map_or(0, |e| e.len()),
            },
        },
    }
}

/// One decoded record of the inspection.
fn record_summary(rec: &Record) -> InspectRecord {
    InspectRecord {
        lsn: rec.lsn,
        ops: rec.ops.iter().map(op_summary).collect(),
        data: rec
            .data
            .iter()
            .map(|e| InspectExtent {
                blk: e.blk,
                nblk: e.nblk,
            })
            .collect(),
        frees: rec.frees.clone(),
    }
}

/// Read-only WAL decode of one shard (`croit-flashstore-tool wal-inspect`): walk the ring from the root's tail with
/// [`replay`]'s parse and validate phases (same batches, same checks, same order), but apply nothing and write nothing.
/// Returns the units replay would apply (with their records), where replay stops and why, and — for a `WalLost` stop —
/// the decodable records a `--accept-wal-loss` cut drops. The device is only ever read.
pub fn inspect<D: BlockDev, C: Clock>(
    io: &mut Sio<D, C>,
    dir: &ShardDir,
    root: &RootSlot,
    store_id: u32,
    cfg: &ReplayCfg,
) -> Result<WalInspect> {
    cfg.validate()?;
    let n_ring = dir.wal_blocks;
    let mut out = WalInspect::default();
    let mut win = Win {
        start: 0,
        buf: Vec::new(),
    };
    let mut stats = ReplayStats::default();
    let mut pos = root.wal_tail_pos;
    let mut chain = root.wal_tail_prev_crc;
    let mut expected = root.tail_lsn();
    let (floor, ckpt) = (root.floor(), root.ckpt_lsn);
    let mut seen = expected - 1;
    let mut last_epoch = 0u32;
    // replay's `out.last_lsn` / `out.head_pos`: the last applied lsn and the ring block after the last applied unit
    let (mut last_lsn, mut head_pos) = (root.ckpt_lsn, root.wal_tail_pos);
    if pos >= n_ring {
        return Err(StoreError::Corrupt("wal tail outside ring".into()));
    }

    let stop = loop {
        // ---- parse phase (as replay); each unit keeps its header's acked_lsn / store_id for the report
        let mut batch: Vec<(Parsed, u64, u32)> = Vec::new();
        let mut pend_data = 0u64;
        let mut acc: Option<Chain> = None;
        let mut end: Option<InspectStop> = None;
        while acc.is_some() || (batch.len() < cfg.batch_units && pend_data < cfg.batch_data_blocks)
        {
            let (mut p, next) = match parse_unit(
                io, dir, root, &mut win, &mut stats, cfg, pos, chain, expected, last_epoch,
            ) {
                Ok(Some(x)) => x,
                Ok(None) => {
                    end = Some(end_of_log(&win, dir, pos, chain, expected, last_epoch));
                    break;
                }
                Err(StoreError::Corrupt(m)) => {
                    // a crc-valid unit replay refuses: a newer incarnation (epoch > root.epoch) or undecodable
                    let newer = UnitHeader::read(win.header(pos))
                        .is_some_and(|(h, _)| h.epoch > root.epoch);
                    let reason = if newer {
                        StopReason::NewerIncarnation
                    } else {
                        StopReason::Undecodable
                    };
                    out.stop = refused(reason, pos, expected, m);
                    return Ok(out);
                }
                Err(e) => return Err(e),
            };
            // `parse_unit` just read this header into the window
            let (acked, sid) = UnitHeader::read(win.header(pos))
                .map_or((0, 0), |(h, _)| (h.acked_lsn, h.store_id));
            let is_pad = p.recs.is_empty() && p.part.is_none();
            match p.part.take() {
                None if is_pad && acc.is_some() => {
                    acc.as_mut().unwrap().rings.append(&mut p.rings);
                }
                None if acc.is_some() => {
                    end = Some(torn_stop(
                        pos,
                        expected,
                        "a normal unit inside a multi-part txn chain",
                    ));
                    break;
                }
                None => {
                    pend_data += p
                        .recs
                        .iter()
                        .filter(|r| r.lsn > ckpt)
                        .flat_map(|r| r.data.iter())
                        .map(|e| e.nblk as u64)
                        .sum::<u64>();
                    batch.push((p, acked, sid));
                }
                Some(pi) => {
                    let c = acc.get_or_insert_with(|| Chain {
                        rings: Vec::new(),
                        bytes: Vec::new(),
                        next_idx: 0,
                    });
                    if pi.idx != c.next_idx {
                        end = Some(torn_stop(
                            pos,
                            expected,
                            "a multi-part txn chain part index gap",
                        ));
                        break;
                    }
                    c.next_idx += 1;
                    c.bytes.extend_from_slice(&pi.bytes);
                    c.rings.append(&mut p.rings);
                    if pi.end {
                        let c = acc.take().unwrap();
                        let first = c.rings.last().unwrap().first_lsn;
                        let mut d = Dec::new(&c.bytes);
                        match decode_record(&mut d) {
                            Some(r) if r.lsn == first && d.left() == 0 => {
                                if r.lsn > ckpt {
                                    pend_data += r.data.iter().map(|e| e.nblk as u64).sum::<u64>();
                                }
                                let unit = Parsed {
                                    epoch: p.epoch,
                                    rings: c.rings,
                                    recs: vec![r],
                                    part: None,
                                };
                                batch.push((unit, acked, sid));
                            }
                            _ => {
                                let at = c.rings.last().map_or(pos, |r| r.pos);
                                out.stop = refused(
                                    StopReason::Undecodable,
                                    at,
                                    first,
                                    "an undecodable multi-part record".into(),
                                );
                                return Ok(out);
                            }
                        }
                    }
                }
            }
            (pos, chain, expected, last_epoch) = next;
        }

        // ---- validate phase (as replay): the units before the first one with bad data replay, the log ends there
        let bad = match batch_bad_unit(io, dir, &batch, ckpt) {
            Ok(b) => b,
            Err(StoreError::Corrupt(m)) => {
                out.stop = refused(StopReason::Undecodable, head_pos, last_lsn + 1, m);
                return Ok(out);
            }
            Err(e) => return Err(e),
        };
        let n_ok = bad.map_or(batch.len(), |(ui, _)| ui);
        for (u, acked, sid) in batch.iter().take(n_ok) {
            for r in &u.recs {
                seen = r.lsn;
                if r.lsn > ckpt {
                    last_lsn = r.lsn;
                }
            }
            let last = &u.rings[u.rings.len() - 1];
            head_pos = (last.pos + last.blocks) % n_ring;
            out.units.push(inspect_unit(u, *acked, *sid));
        }
        if let Some((_, blk)) = bad {
            break data_crc_stop(head_pos, last_lsn + 1, blk);
        }
        if let Some(s) = end {
            break s;
        }
    };

    // the terminal torn/foreign unit (best-effort header) shows where and why replay stops
    if matches!(stop.reason, StopReason::Torn | StopReason::Foreign) {
        out.units.push(terminal_unit(&win, &stop));
    }
    if seen < ckpt {
        out.stop = refused(
            StopReason::RunWindow,
            head_pos,
            seen + 1,
            format!("wal ends at lsn {seen} inside the omap run window {floor}..={ckpt}"),
        );
        return Ok(out);
    }
    // the cut point, as replay computes it
    let e = last_lsn + 1;
    out.stop = match acked_witness(io, dir, root, store_id, head_pos, e, cfg)? {
        Some((acked, witness)) => {
            out.dropped = dropped_records(io, dir, root, store_id, head_pos, e, cfg)?;
            InspectStop {
                reason: StopReason::WalLost,
                pos: head_pos,
                lsn: e,
                acked_lsn: Some(acked),
                witness: Some(witness),
                ..stop
            }
        }
        None => InspectStop { lsn: e, ..stop },
    };
    Ok(out)
}

/// Read-only scan of the ring behind the cut over the window [`acked_beyond`] covers (same start, budget and filter:
/// units of this shard and store, current or newer incarnation): the decodable records with `lsn >= e`, i.e. the txns
/// a `--accept-wal-loss` cut drops. Records of an unreadable unit (the one at the cut) or beyond the window are not
/// listed; the cut drops every lsn `>= e` regardless.
fn dropped_records<D: BlockDev, C: Clock>(
    io: &mut Sio<D, C>,
    dir: &ShardDir,
    root: &RootSlot,
    store_id: u32,
    from: u64,
    e: u64,
    cfg: &ReplayCfg,
) -> Result<Vec<InspectRecord>> {
    let n_ring = dir.wal_blocks;
    let total = cfg.scan_blocks.min(n_ring);
    let chunk = (cfg.chunk_blocks as u64).max(1);
    let mut win = Win {
        start: 0,
        buf: Vec::new(),
    };
    let mut out = Vec::new();
    // a multi-part chain being assembled: (next part index, record bytes so far); a wrap PAD may sit between parts
    let mut parts: Option<(u32, Vec<u8>)> = None;
    let (mut at, mut counted, mut scanned) = (from, 0u64, 0u64);
    while counted < total && scanned < n_ring {
        win.ensure(io, dir, at, 1, chunk.min(total - counted))?;
        let (mut step, mut free) = (1u64, false);
        if let Some((h, _)) = UnitHeader::read(win.header(at))
            && h.shard == dir.shard
            && h.epoch >= root.epoch
            && h.store_id == store_id
            && h.flags & FLAG_PAD == 0
            && h.fits(at, n_ring)
        {
            let nb = u64::from(h.nblocks);
            win.ensure(io, dir, at, nb, chunk.min(total - counted))?;
            if let Some(payload) = win.payload(at, &h) {
                step = nb;
                if h.flags & (FLAG_PART | FLAG_END) != 0 {
                    // multi-part txn unit: payload = slice of the record encoding, ntxn = part index
                    if h.ntxn == 0 {
                        parts = Some((0, Vec::new()));
                    }
                    match parts.as_mut() {
                        Some((idx, bytes)) if *idx == h.ntxn => {
                            *idx += 1;
                            bytes.extend_from_slice(payload);
                        }
                        _ => parts = None,
                    }
                    if h.flags & FLAG_END != 0 {
                        if let Some((_, bytes)) = parts.take() {
                            let mut d = Dec::new(&bytes);
                            if let Some(r) = decode_record(&mut d)
                                && r.lsn >= e
                                && d.left() == 0
                            {
                                out.push(record_summary(&r));
                            }
                        }
                    } else {
                        // as in the witness scan: a chain part sealed after the cut is free of charge
                        free = h.first_lsn >= e;
                    }
                } else {
                    parts = None;
                    let mut d = Dec::new(payload);
                    for _ in 0..h.ntxn {
                        let Some(r) = decode_record(&mut d) else {
                            break;
                        };
                        if r.lsn >= e {
                            out.push(record_summary(&r));
                        }
                    }
                }
            }
        }
        let step = step.min(n_ring - scanned);
        scanned += step;
        if !free {
            counted += step;
        }
        at = (at + step) % n_ring;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::olsm::wire::{del_blob, put_blob};

    /// Counted omap removal / put of an earlier build (tags 6 and 7, adr 0476 am. 5): replay reads them as the plain
    /// ops (`FEAT_OMAP_UNCOUNTED`), this build writes the plain tags; a key that is no omap key is refused like any
    /// malformed record.
    #[test]
    fn counted_omap_ops_of_an_earlier_build_replay_as_plain_ops() {
        let rec = |key: &[u8]| {
            let mut e = Enc::new();
            e.u32(0).u64(9).u32(2).u32(0).u32(0);
            e.u8(TAG_ODEL).u16(key.len() as u16).bytes(key);
            e.u8(TAG_OPUT)
                .u16(key.len() as u16)
                .u32(3)
                .bytes(key)
                .bytes(b"val");
            let len = e.b.len() as u32;
            e.b[..4].copy_from_slice(&len.to_le_bytes());
            e.b
        };
        let k = crate::obj::keys::omap_key(5, b"name");
        let r = decode_record(&mut Dec::new(&rec(&k))).expect("an earlier build's record");
        let plain = vec![Op::Del(k.clone()), Op::Put(k, b"val".to_vec())];
        assert_eq!((r.lsn, &r.ops), (9, &plain));
        let mut e = Enc::new();
        encode_record(&r, &mut e);
        assert_eq!(
            e.b[REC_HDR_LEN], TAG_DEL,
            "written back with the plain tags"
        );
        assert_eq!(decode_record(&mut Dec::new(&e.b)), Some(r));
        let not_omap = crate::obj::keys::onode_key(5);
        assert_eq!(decode_record(&mut Dec::new(&rec(&not_omap))), None);
    }

    /// The witness scan (`acked_beyond`) and the replay parser (`parse_unit`) take the same units as valid: a unit the
    /// parser refuses (payload crc, payload past its blocks, no blocks, blocks past the ring end) is never a witness,
    /// and the unit it accepts is one. Normal and multi-part units. Unknown header flags are the one exception (the
    /// parser refuses, the witness takes the unit), asserted at the end.
    #[test]
    fn witness_scan_and_parser_agree_on_unit_validity() {
        use crate::dev::{SimClock, SimConfig, SimDisk};
        const N_RING: u64 = 8;
        const POS: u64 = 3;
        let dir = ShardDir {
            shard: 0,
            region_start: 0,
            region_blocks: 64,
            root_a: 0,
            root_b: 0,
            wal_start: 16,
            wal_blocks: N_RING,
            meta_start: 0,
            meta_blocks: 0,
            data_start: 0,
            data_blocks: 0,
            ext: Vec::new(),
            chunk_blocks: 0,
            #[cfg(feature = "elastic")]
            lent: Vec::new(),
        };
        let root = RootSlot {
            epoch: 1,
            ..Default::default()
        };
        let (first_lsn, acked) = (10u64, 5u64);
        let mut normal = Enc::new();
        encode_record(
            &Record {
                lsn: first_lsn,
                ops: vec![Op::Put(b"k".to_vec(), vec![7u8; 5000])],
                ..Default::default()
            },
            &mut normal,
        );
        let part = vec![9u8; 5000];
        // (flags, ntxn, payload): a two-block unit either way
        let kinds: [(u16, u32, &[u8]); 2] = [(0, 1, &normal.b), (FLAG_PART, 0, &part)];
        // (name, nblocks, payload_len delta, corrupt a payload byte)
        let cases: [(&str, u16, i64, bool); 6] = [
            ("valid", 2, 0, false),
            ("payload crc", 2, 0, true),
            ("payload past its blocks", 1, 0, false),
            ("no blocks", 0, 0, false),
            ("past the ring end", (N_RING - POS + 1) as u16, 0, false),
            ("payload_len past the unit", 2, 2 * BLK as i64, false),
        ];
        for (flags, ntxn, payload) in kinds {
            for (name, nblocks, dlen, corrupt) in cases {
                let disk = SimDisk::new(SimConfig::new(64 * BLK as u64));
                let mut dev = disk.queue();
                let mut clk = SimClock::default();
                let mut io = Sio::new(&mut dev, &mut clk);
                let h = UnitHeader {
                    epoch: 1,
                    first_lsn,
                    ntxn,
                    nblocks,
                    flags,
                    shard: 0,
                    payload_len: (payload.len() as i64 + dlen) as u32,
                    prev_crc: 0x1234,
                    payload_crc: crc(payload),
                    acked_lsn: acked,
                    store_id: 0,
                };
                let mut b = vec![0u8; 2 * BLK];
                b[HDR_LEN..HDR_LEN + payload.len()].copy_from_slice(payload);
                if corrupt {
                    b[HDR_LEN + 100] ^= 1;
                }
                h.write(&mut b);
                io.write_one(dir.wal_start + POS, &b).unwrap();
                let cfg = ReplayCfg::default();
                let mut win = Win {
                    start: 0,
                    buf: Vec::new(),
                };
                let mut stats = ReplayStats::default();
                let parsed = parse_unit(
                    &mut io, &dir, &root, &mut win, &mut stats, &cfg, POS, 0x1234, first_lsn, 1,
                )
                .unwrap()
                .is_some();
                let witness = acked_beyond(&mut io, &dir, &root, 0, POS, acked, &cfg).unwrap();
                assert_eq!(parsed, name == "valid", "{name} flags {flags}: parser");
                assert_eq!(
                    witness,
                    parsed.then_some(acked),
                    "{name} flags {flags}: witness"
                );
            }
        }
        // A unit of a newer build (unknown header flags) is the documented exception: the parser refuses it, the
        // witness scan still takes it (it needs only the header shape / bounds and the payload crc).
        let disk = SimDisk::new(SimConfig::new(64 * BLK as u64));
        let mut dev = disk.queue();
        let mut clk = SimClock::default();
        let mut io = Sio::new(&mut dev, &mut clk);
        let h = UnitHeader {
            epoch: 1,
            first_lsn,
            ntxn: 1,
            nblocks: 2,
            flags: 0x8000,
            shard: 0,
            payload_len: normal.b.len() as u32,
            prev_crc: 0x1234,
            payload_crc: crc(&normal.b),
            acked_lsn: acked,
            store_id: 0,
        };
        let mut b = vec![0u8; 2 * BLK];
        b[HDR_LEN..HDR_LEN + normal.b.len()].copy_from_slice(&normal.b);
        h.write(&mut b);
        io.write_one(dir.wal_start + POS, &b).unwrap();
        let cfg = ReplayCfg::default();
        let mut win = Win {
            start: 0,
            buf: Vec::new(),
        };
        let mut stats = ReplayStats::default();
        let parsed = parse_unit(
            &mut io, &dir, &root, &mut win, &mut stats, &cfg, POS, 0x1234, first_lsn, 1,
        );
        assert!(parsed.is_err(), "unknown flags: parser");
        assert_eq!(
            acked_beyond(&mut io, &dir, &root, 0, POS, acked, &cfg).unwrap(),
            Some(acked),
            "unknown flags: witness"
        );
    }

    /// `ntxn` comes straight from a crc-valid header: a count the payload cannot hold is refused before the record
    /// vector is reserved (before: `Vec::with_capacity(u32::MAX)` aborted the OSD on mount).
    #[test]
    fn record_count_beyond_the_payload_is_refused() {
        use crate::dev::{SimClock, SimConfig, SimDisk};
        let dir = ShardDir {
            shard: 0,
            region_start: 0,
            region_blocks: 64,
            root_a: 0,
            root_b: 0,
            wal_start: 16,
            wal_blocks: 8,
            meta_start: 0,
            meta_blocks: 0,
            data_start: 0,
            data_blocks: 0,
            ext: Vec::new(),
            chunk_blocks: 0,
            #[cfg(feature = "elastic")]
            lent: Vec::new(),
        };
        let root = RootSlot {
            epoch: 1,
            ..Default::default()
        };
        let disk = SimDisk::new(SimConfig::new(64 * BLK as u64));
        let mut dev = disk.queue();
        let mut clk = SimClock::default();
        let mut io = Sio::new(&mut dev, &mut clk);
        let h = UnitHeader {
            epoch: 1,
            first_lsn: 10,
            ntxn: u32::MAX,
            nblocks: 1,
            flags: 0,
            shard: 0,
            payload_len: 0,
            prev_crc: 0x1234,
            payload_crc: crc(&[]),
            acked_lsn: 0,
            store_id: 0,
        };
        let mut b = vec![0u8; BLK];
        h.write(&mut b);
        io.write_one(dir.wal_start + 3, &b).unwrap();
        let cfg = ReplayCfg::default();
        let mut win = Win {
            start: 0,
            buf: Vec::new(),
        };
        let mut stats = ReplayStats::default();
        // the ring window is read before the measurement: only the decoder's own reservations count
        win.ensure(&mut io, &dir, 3, 1, 256).unwrap();
        let bytes = crate::test_alloc::allocated_bytes(|| {
            let r = parse_unit(
                &mut io, &dir, &root, &mut win, &mut stats, &cfg, 3, 0x1234, 10, 1,
            );
            assert!(r.is_err(), "a record count the payload cannot hold");
        });
        // only the diagnostic may allocate
        assert!(
            bytes < BLK,
            "reserved {bytes} B for records the payload cannot hold"
        );
    }

    /// Element counts are checked against the bytes their elements need, before the decoder reserves them: the guard
    /// used "one byte per element", while the smallest extent and free entry take 12 bytes.
    #[test]
    fn element_counts_beyond_the_payload_are_refused_before_reserving() {
        let mut b = vec![0u8; 1 << 20];
        let len = b.len() as u32;
        b[0..4].copy_from_slice(&len.to_le_bytes());
        b[4..12].copy_from_slice(&1u64.to_le_bytes());
        b[12..16].copy_from_slice(&0u32.to_le_bytes()); // ops
        b[16..20].copy_from_slice(&1_000_000u32.to_le_bytes()); // extents
        b[20..24].copy_from_slice(&0u32.to_le_bytes()); // frees
        let left = b.len() - REC_HDR_LEN;
        let bytes = crate::test_alloc::allocated_bytes(|| {
            assert!(decode_record(&mut Dec::new(&b)).is_none());
        });
        assert_eq!(
            bytes, 0,
            "{left} bytes left, the decoder reserved for the rest"
        );
    }

    #[test]
    fn omap_lsm_ops_roundtrip_and_reject_corruption() {
        let (n, blob) = put_blob(&[(&b"a"[..], &b"1"[..]), (b"b", b"22")]);
        let rec = Record {
            lsn: 7,
            ops: vec![
                Op::Omap(OOp::Put { id: 3, n, blob }),
                Op::Omap(OOp::Del {
                    id: 3,
                    blob: del_blob(&[b"x"]),
                }),
                Op::Omap(OOp::Range {
                    id: 4,
                    first: bytes::Bytes::new(),
                    end: None,
                }),
                Op::Omap(OOp::Range {
                    id: 4,
                    first: bytes::Bytes::from_static(b"c"),
                    end: Some(bytes::Bytes::from_static(b"d")),
                }),
            ],
            data: vec![],
            frees: vec![],
        };
        let mut e = Enc::default();
        encode_record(&rec, &mut e);
        let got = decode_record(&mut Dec::new(&e.b)).expect("decodes");
        assert_eq!(got.ops, rec.ops);
        // an entry count that does not match the blob is corrupt
        let mut bad = rec.clone();
        bad.ops[0] = Op::Omap(OOp::Put {
            id: 3,
            n: n + 1,
            blob: put_blob(&[(&b"a"[..], &b"1"[..]), (b"b", b"22")]).1,
        });
        let mut e = Enc::default();
        encode_record(&bad, &mut e);
        assert!(decode_record(&mut Dec::new(&e.b)).is_none());
    }

    /// The op summary decodes a `C` collection key into the PG and an `N` name key into the object (best effort): this
    /// is what `wal-inspect` shows as "collection/PG" and "object".
    #[test]
    fn op_summary_decodes_collection_and_object_keys() {
        use crate::obj::keys::{coll_key, name_key_of};
        use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SnapId, SpgT};
        let c = CollT::Pg(SpgT {
            pgid: PgT::new(3, 0x1f),
            shard: ShardId::NO_SHARD,
        });
        assert_eq!(op_summary(&Op::Put(coll_key(&c), vec![7])).coll, Some(c));
        let g = Ghobject::new(
            Hobject::new(b"o1", SnapId::NOSNAP, 7, 1, b""),
            Ghobject::NO_GEN,
            ShardId::NO_SHARD,
        );
        let s = op_summary(&Op::Put(name_key_of(5, &g), b"v".to_vec()));
        assert_eq!(s.object, Some(g));
        assert_eq!(s.bytes, 1);
    }
}
