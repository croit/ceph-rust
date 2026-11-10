// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! ecback: sans-IO EC primary backend (spec ec.md 3, 4.4, 4.5, 10, 11; adr 0039/0044, doc/ec-phase-b.md).
//!
//! * [`Backend`] = geometry + codec of one pool (legacy modes L0 append-only / L1 overwrites, and mode O).
//! * Write side (`wgen`): the replicated-shape logical transaction the op layer builds -> one transaction per shard
//!   (chunks, stash, hinfo) + the rollback info (`mod_desc`) of every log entry. Whole stripes only; old stripes
//!   needed for read-modify-write are asked with [`WritePlan::reads`] and handed back to [`WritePlan::generate`].
//! * Write side (`owgen`): the optimized-EC generator (`allow_ec_optimizations`, spec ec-optimized-wgen.md): 4 KiB
//!   aligned per-shard extents, `written_shards`, parity-delta option.
//! * Read side: [`Backend::plan_read`] picks the shards to ask, [`Backend::assemble`] interleaves / decodes.
//!
//! No I/O, no Pg state. Buffers are allocated per op; the ceilings are pinned by `tests/allocation.rs`.

mod oext;
mod owgen;
mod wgen;

pub use oext::{Ext, Geo};
pub use owgen::{
    OCtx, OGenerated, OWritePlan, Page, PdwMode, shard_set_contains, version_for_shard,
};
pub use wgen::{Generated, OldObj, Post, SharedTxn, WritePlan};

use ec::Code;
use ec::EcFacts;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;

pub const EIO: i32 = 5;
pub const EINVAL: i32 = 22;
pub const EFBIG: i32 = 27;
pub const EOPNOTSUPP: i32 = 95;

/// Largest logical object size a generator plans: a backstop against a corrupt caller or object info, not a policy
/// limit. Classic bounds every object only by `osd_max_object_size` (128 MiB default), enforced in the op layer.
pub(crate) const MAX_OBJECT_SIZE: u64 = 1 << 40;

/// A denc failure on an object we were handed (never on data we wrote) = invalid input.
pub(crate) fn io<T>(r: denc::Result<T>) -> Result<T, i32> {
    r.map_err(|_| EINVAL)
}

#[cfg(test)]
thread_local! {
    static RECLAIM_SCAN_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Emit a composed shard range of a ZERO or truncate without allocating its zero blocks. Ordinary writes bypass
/// this scan; parity is already composed, so a hole is safe only after checking the complete encoded block.
fn shard_write<'a>(
    t: &mut replwire::txn::Transaction<'a>,
    cx: replwire::txn::Cx,
    oid: replwire::txn::Ox,
    off: u64,
    data: &'a [u8],
    reclaim: bool,
) {
    use replwire::txn::{Data, TxnOp};
    const ZERO: [u8; 4096] = [0; 4096];
    let push = |t: &mut replwire::txn::Transaction<'a>, start: usize, end: usize, zero: bool| {
        t.push(
            cx,
            if zero {
                TxnOp::Zero {
                    oid,
                    off: off + start as u64,
                    len: (end - start) as u64,
                }
            } else {
                TxnOp::Write {
                    oid,
                    off: off + start as u64,
                    data: Data::new(&data[start..end]),
                }
            },
        );
    };
    if !reclaim {
        push(t, 0, data.len(), false);
        return;
    }
    let mut run = None;
    let mut start = 0;
    for (i, block) in data.chunks(4096).enumerate() {
        #[cfg(test)]
        RECLAIM_SCAN_BYTES.with(|n| n.set(n.get() + block.len()));
        let zero = block == &ZERO[..block.len()];
        if let Some(old) = run
            && old != zero
        {
            push(t, start, i * 4096, old);
            start = i * 4096;
        }
        run = Some(zero);
    }
    if let Some(zero) = run {
        push(t, start, data.len(), zero);
    }
}

/// One pool's EC geometry and code.
#[derive(Clone)]
pub struct Backend {
    pub k: usize,
    pub m: usize,
    /// stripe_width S and chunk size C.
    pub s: u64,
    pub c: u64,
    /// raw chunk index -> shard.
    pub mapping: Vec<u32>,
    pub overwrites: bool,
    /// Optimized pool with FLAG_OMAP: omap ops are accepted ([`owgen`](crate::owgen)).
    pub omap: bool,
    codec: Arc<Code>,
}

impl std::fmt::Debug for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Backend(k={} m={} S={} C={} ow={})",
            self.k, self.m, self.s, self.c, self.overwrites
        )
    }
}

impl Backend {
    /// `None` for a plugin/technique we cannot encode (the gate keeps those passive).
    pub fn new(f: &EcFacts) -> Option<Backend> {
        let optimized = f.mode == ec::EcMode::Optimized;
        Backend::from_profile(
            &f.profile,
            (f.stripe_width, f.chunk_size),
            f.chunk_mapping.clone(),
            f.mode == ec::EcMode::L1,
        )?
        .literal_placement(ec::gate::literal_placement(
            f.plugin.name(),
            optimized,
            &f.chunk_mapping,
        ))
    }

    /// `literal` ([`ec::gate::literal_placement`]): the primary runs the classic legacy index sequence of the mapping
    /// (spec ec-parity.md 3.4): raw r = index `mapping[r]` of the code, the encode may rewrite data chunks.
    pub fn literal_placement(self, literal: bool) -> Option<Backend> {
        if !literal {
            return Some(self);
        }
        let codec = self.codec.as_ref().clone().placed(&self.mapping)?;
        Some(Backend {
            codec: Arc::new(codec),
            ..self
        })
    }

    /// Same from plugin + technique only (`k`, `m` explicit; other profile keys default).
    pub fn from_parts(
        plugin: &str,
        technique: &str,
        (k, m): (u32, u32),
        sizes: (u32, u32),
        mapping: Vec<u32>,
        overwrites: bool,
    ) -> Option<Backend> {
        let profile: BTreeMap<String, String> = [
            ("plugin", plugin.to_string()),
            ("technique", technique.to_string()),
            ("k", k.to_string()),
            ("m", m.to_string()),
        ]
        .into_iter()
        .map(|(a, b)| (a.to_string(), b))
        .collect();
        Backend::from_profile(&profile, sizes, mapping, overwrites)
    }

    /// From the pool profile map and the pool geometry `(stripe_width, chunk_size)`.
    pub fn from_profile(
        profile: &BTreeMap<String, String>,
        (stripe_width, chunk_size): (u32, u32),
        mapping: Vec<u32>,
        overwrites: bool,
    ) -> Option<Backend> {
        let mut codec = Code::from_profile(profile).ok()?;
        // clay: primary only for MDS scalars (ec-clay.md 0.6); per-stripe codewords
        if let Code::Clay(c) = &codec
            && !c.profile().primary_capable(chunk_size as usize)
        {
            return None;
        }
        codec.set_chunk(chunk_size as usize);
        let (k, m) = (codec.k() as u32, codec.m() as u32);
        // defensive: the gate (ec::evaluate) already enforces these; a bad pool must never panic the OSD
        if k < 1 || m < 1 || chunk_size == 0 || !(chunk_size as usize).is_multiple_of(codec.unit())
        {
            return None;
        }
        let (k, m) = (k as usize, m as usize);
        if u64::from(stripe_width) != k as u64 * u64::from(chunk_size) {
            return None;
        }
        let n = k + m;
        let mut seen = vec![false; n];
        for &s in &mapping {
            match seen.get_mut(s as usize) {
                Some(b) if !*b => *b = true,
                _ => return None,
            }
        }
        if mapping.len() != n {
            return None;
        }
        Some(Backend {
            k,
            m,
            s: u64::from(stripe_width),
            c: u64::from(chunk_size),
            mapping,
            overwrites,
            omap: false,
            codec: Arc::new(codec),
        })
    }

    pub fn n(&self) -> usize {
        self.k + self.m
    }

    /// Sub-chunk count S of the code (the whole chunk is the range `(0, S)` in ECSubRead).
    pub fn sub_chunks(&self) -> usize {
        self.codec.sub_chunks()
    }

    /// Shard file size of every shard for a logical size (`Err(EINVAL)` when it does not fit in `u64`).
    pub fn shard_size(&self, logical: u64) -> Result<u64, i32> {
        logical.div_ceil(self.s).checked_mul(self.c).ok_or(EINVAL)
    }

    fn raw_of(&self, shard: u32) -> Option<usize> {
        self.mapping.iter().position(|s| *s == shard)
    }

    /// Encode whole stripes (`data.len()` a multiple of S) into one buffer per SHARD (index = shard id), each
    /// `stripes * C` bytes.
    pub fn encode_stripes(&self, data: &[u8]) -> Vec<Vec<u8>> {
        self.encode_stripes_inner(data, None)
    }

    /// [`Self::encode_stripes`] plus the per-4K block crcs of every shard buffer ([`crc::BlockCrcs`], grid from byte 0),
    /// fused with the gather copy (data shards) or taken while the parity chunk is in L1: the hash-info update
    /// (`HashInfo::append_crcs`, [`crc::BlockCrcs::crc`] seed 0), the msgr2 front crc and the store's block crcs need no
    /// second pass.
    pub fn encode_stripes_crc(&self, data: &[u8]) -> (Vec<Vec<u8>>, Vec<crc::BlockCrcs>) {
        let ns = data.len() / self.s as usize;
        let mut crc: Vec<crc::BlockCrcs> = (0..self.n())
            .map(|_| crc::BlockCrcs::with_len(ns * self.c as usize))
            .collect();
        let out = self.encode_stripes_inner(data, Some(&mut crc));
        (out, crc)
    }

    fn encode_stripes_inner(
        &self,
        data: &[u8],
        mut crc: Option<&mut [crc::BlockCrcs]>,
    ) -> Vec<Vec<u8>> {
        if self.codec.rewrites_data() {
            return self.encode_stripes_literal(data, crc);
        }
        let (s, c) = (self.s as usize, self.c as usize);
        debug_assert_eq!(data.len() % s, 0);
        let ns = data.len() / s;
        let mut out: Vec<Vec<u8>> = (0..self.n())
            .map(|sh| {
                let parity = self.raw_of(sh as u32).is_some_and(|r| r >= self.k);
                Vec::with_capacity(if parity { 0 } else { ns * c })
            })
            .collect();
        // parity is encoded in place into its final shard buffer (no per-stripe copy)
        let mut par: Vec<Vec<u8>> = vec![vec![0u8; ns * c]; self.m];
        {
            let mut cols: Vec<std::slice::ChunksExactMut<'_, u8>> =
                par.iter_mut().map(|v| v.chunks_exact_mut(c)).collect();
            let mut d = Vec::with_capacity(self.k);
            let mut p: Vec<&mut [u8]> = Vec::with_capacity(self.m);
            for st in 0..ns {
                let stripe = &data[st * s..(st + 1) * s];
                d.clear();
                d.extend((0..self.k).map(|r| &stripe[r * c..(r + 1) * c]));
                p.clear();
                p.extend(cols.iter_mut().map(|it| it.next().expect("parity column")));
                self.codec.encode(&d, &mut p);
                for (r, chunk) in d.iter().enumerate() {
                    let sh = self.mapping[r] as usize;
                    match crc.as_deref_mut() {
                        Some(cr) => cr[sh].update_extend(chunk, &mut out[sh]),
                        None => out[sh].extend_from_slice(chunk),
                    }
                }
                if let Some(cr) = crc.as_deref_mut() {
                    for (j, pc) in p.iter().enumerate() {
                        let sh = self.mapping[self.k + j] as usize;
                        cr[sh].update(pc);
                    }
                }
            }
        }
        for (j, v) in par.into_iter().enumerate() {
            out[self.mapping[self.k + j] as usize] = v;
        }
        out
    }

    /// [`Self::encode_stripes_inner`] of a code whose classic literal sequence rewrites data chunks (spec
    /// ec-parity.md 3.4, 14.2): every shard comes from [`Code::encode_all`].
    fn encode_stripes_literal(
        &self,
        data: &[u8],
        mut crc: Option<&mut [crc::BlockCrcs]>,
    ) -> Vec<Vec<u8>> {
        let (s, c, n) = (self.s as usize, self.c as usize, self.n());
        let ns = data.len() / s;
        let mut out: Vec<Vec<u8>> = (0..n).map(|_| Vec::with_capacity(ns * c)).collect();
        let mut all = vec![vec![0u8; c]; n];
        for stripe in data.chunks_exact(s) {
            let d: Vec<&[u8]> = stripe.chunks_exact(c).collect();
            let mut o: Vec<&mut [u8]> = all.iter_mut().map(|v| &mut v[..]).collect();
            self.codec.encode_all(&d, &mut o);
            for (r, chunk) in all.iter().enumerate() {
                let sh = self.mapping[r] as usize;
                match crc.as_deref_mut() {
                    Some(cr) => cr[sh].update_extend(chunk, &mut out[sh]),
                    None => out[sh].extend_from_slice(chunk),
                }
            }
        }
        out
    }

    // ---- read side ----------------------------------------------------------------------------------------------

    /// Which shards to ask for the stripes `[s0, s1)` (each shard is read over `[s0*C, s1*C)`), given the shards
    /// that can serve (`avail`, never contains a shard that already failed). `want` = raw data chunks that carry
    /// requested bytes; a raw index outside `0..k+m` is `Err(EINVAL)`. Reads exactly the wanted data shards when all are available, otherwise the read set of the code (MDS: k shards,
    /// wanted data first; shec: the minimum set of its search, any size) and decodes. `Err(EIO)` when `want_raw` cannot
    /// be rebuilt from `avail`.
    pub fn plan_read(
        &self,
        s0: u64,
        s1: u64,
        want_raw: &[usize],
        avail: &[u32],
    ) -> Result<ReadPlan, i32> {
        let mut direct = true;
        for &r in want_raw {
            direct &= avail.contains(self.mapping.get(r).ok_or(EINVAL)?);
        }
        let avail_raw: Vec<usize> = (0..self.n())
            .filter(|r| avail.contains(&self.mapping[*r]))
            .collect();
        let set = self.codec.read_set(want_raw, &avail_raw).ok_or(EIO)?;
        Ok(ReadPlan {
            s0,
            s1,
            shards: set.iter().map(|r| self.mapping[*r]).collect(),
            direct,
            repair: None,
        })
    }

    /// Can every chunk be rebuilt from the chunks held by `shards` (classic ECRecPred: minimum_to_decode of all chunks)?
    /// MDS codes: at least k shards; shec / lrc: the code's own predicate (any k is not enough).
    pub fn recoverable(&self, shards: &[u32]) -> bool {
        let avail: Vec<usize> = (0..self.n())
            .filter(|r| shards.contains(&self.mapping[*r]))
            .collect();
        let all: Vec<usize> = (0..self.n()).collect();
        self.codec.read_set(&all, &avail).is_some()
    }

    /// Repair read of the stripes `[s0, s1)` of shard `lost` from the sub-chunks of `d` helpers (clay); `None` when the
    /// code has no repair path or `avail` does not allow it (the caller then reads and decodes whole chunks).
    pub fn plan_repair(&self, s0: u64, s1: u64, lost: u32, avail: &[u32]) -> Option<ReadPlan> {
        let lost_raw = self.raw_of(lost)?;
        let avail_raw: Vec<usize> = (0..self.n())
            .filter(|r| *r != lost_raw && avail.contains(&self.mapping[*r]))
            .collect();
        let (helpers, ranges) = self.codec.repair_plan(lost_raw, &avail_raw)?;
        Some(ReadPlan {
            s0,
            s1,
            shards: helpers.iter().map(|r| self.mapping[*r]).collect(),
            direct: false,
            repair: Some(RepairSpec {
                lost,
                ranges: ranges.iter().map(|&(a, b)| (a as i32, b as i32)).collect(),
            }),
        })
    }

    /// What a helper sends for a repair read: of every chunk of `full` (whole chunks) the listed sub-chunk ranges.
    pub fn gather_sub(&self, full: &[u8], ranges: &[(i32, i32)]) -> Vec<u8> {
        let c = self.c as usize;
        let sc = c / self.codec.sub_chunks().max(1);
        let mut out = Vec::with_capacity(full.len());
        for chunk in full.chunks(c) {
            for &(a, n) in ranges {
                let (lo, hi) = (a as usize * sc, ((a + n) as usize * sc).min(chunk.len()));
                if lo < hi {
                    out.extend_from_slice(&chunk[lo..hi]);
                }
            }
        }
        out
    }

    /// Bytes every helper of a clay repair plan sends: the asked sub-chunks of each stripe of the plan, gathered
    /// (ec-clay.md 7.1). `None` for a plain read.
    pub fn repair_reply_len(&self, plan: &ReadPlan) -> Option<u64> {
        let spec = plan.repair.as_ref()?;
        let sub: u64 = spec.ranges.iter().map(|r| r.1 as u64).sum();
        Some((plan.s1 - plan.s0) * (self.c / self.codec.sub_chunks().max(1) as u64) * sub)
    }

    /// The lost shard's chunks of the stripes of a repair plan from the helper replies (`got[shard]` = gathered
    /// sub-chunks). `Err(EIO)` on a short or odd reply.
    pub fn repair_shard<B: AsRef<[u8]>>(
        &self,
        plan: &ReadPlan,
        got: &BTreeMap<u32, B>,
    ) -> Result<Vec<u8>, i32> {
        let spec = plan.repair.as_ref().ok_or(EINVAL)?;
        let lost = self.raw_of(spec.lost).ok_or(EINVAL)?;
        let ns = (plan.s1 - plan.s0) as usize;
        let hl = self.repair_reply_len(plan).ok_or(EINVAL)? as usize;
        let mut have: Vec<(usize, &[u8])> = Vec::new();
        for sh in &plan.shards {
            let v = got.get(sh).ok_or(EIO)?.as_ref();
            if v.len() != hl {
                return Err(EIO);
            }
            have.push((self.raw_of(*sh).ok_or(EINVAL)?, v));
        }
        let mut out = vec![0u8; ns * self.c as usize];
        self.codec.repair(lost, &have, &mut out).map_err(|_| EIO)?;
        Ok(out)
    }

    /// Wanted raw data chunks for a logical range `[off, off+len)` (`len == 0`: none, `Err(EINVAL)` when the range
    /// does not fit in `u64`).
    pub fn raw_chunks_of(&self, off: u64, len: u64) -> Result<Vec<usize>, i32> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let end = off.checked_add(len).ok_or(EINVAL)?;
        let (s0, s1) = (off / self.s, end.div_ceil(self.s));
        if s1 - s0 > 1 {
            return Ok((0..self.k).collect());
        }
        let r0 = ((off % self.s) / self.c) as usize;
        let r1 = (((end - 1) % self.s) / self.c) as usize;
        Ok((r0..=r1).collect())
    }

    /// Logical bytes `[off, off+len)` from the shard reads of `plan` (`got[shard]` = bytes of
    /// `[s0*C, s1*C)`; short buffers count as zero padded: mode O sparse shards. Legacy (L0/L1) callers accept only
    /// whole-chunk replies, spec ec.md 10). `off` is absolute, within the stripes of the plan.
    pub fn assemble<B: AsRef<[u8]>>(
        &self,
        plan: &ReadPlan,
        got: &BTreeMap<u32, B>,
        off: u64,
        len: u64,
    ) -> Result<Vec<u8>, i32> {
        self.assemble_crc(plan, got, off, len, false).map(|r| r.0)
    }

    /// [`Self::assemble`]; `crc` = also `crc32c(!0, out)` (the msgr2 data-segment crc of a reply carrying exactly these
    /// bytes), fused into the interleave copy (no second pass).
    pub fn assemble_crc<B: AsRef<[u8]>>(
        &self,
        plan: &ReadPlan,
        got: &BTreeMap<u32, B>,
        off: u64,
        len: u64,
        crc: bool,
    ) -> Result<(Vec<u8>, Option<u32>), i32> {
        let (s, c) = (self.s as usize, self.c as usize);
        let ns = (plan.s1 - plan.s0) as usize;
        let span = ns * c;
        let end = off.checked_add(len).ok_or(EINVAL)?;
        let base = plan.s0 * self.s;
        if off < base || end > base + (ns * s) as u64 {
            return Err(EINVAL);
        }
        let fetch = |shard: u32| -> Cow<'_, [u8]> {
            let bytes = got.get(&shard).map_or(&[][..], AsRef::as_ref);
            if bytes.len() >= span {
                Cow::Borrowed(&bytes[..span])
            } else {
                let mut padded = vec![0; span];
                padded[..bytes.len()].copy_from_slice(bytes);
                Cow::Owned(padded)
            }
        };
        // chunk bytes per raw data index over the whole span
        let mut raw: Vec<Option<Cow<'_, [u8]>>> = vec![None; self.k];
        if plan.direct {
            for sh in &plan.shards {
                if let Some(r) = self.raw_of(*sh).filter(|r| *r < self.k) {
                    raw[r] = Some(fetch(*sh));
                }
            }
        } else {
            let have: Vec<(usize, Cow<'_, [u8]>)> = plan
                .shards
                .iter()
                .map(|sh| self.raw_of(*sh).map(|r| (r, fetch(*sh))).ok_or(EINVAL))
                .collect::<Result<_, _>>()?;
            // only the data chunks the range needs: a non-MDS read set (shec) cannot rebuild the others
            let need = self.raw_chunks_of(off, len)?;
            let missing: Vec<usize> = need
                .into_iter()
                .filter(|r| !have.iter().any(|(h, _)| h == r))
                .collect();
            if !missing.is_empty() {
                let h: Vec<(usize, &[u8])> = have.iter().map(|(r, v)| (*r, &v[..])).collect();
                let mut outs: Vec<Vec<u8>> = vec![vec![0u8; span]; missing.len()];
                {
                    let mut o: Vec<&mut [u8]> = outs.iter_mut().map(|v| &mut v[..]).collect();
                    self.codec
                        .decode_into(&h, &missing, &mut o)
                        .map_err(|_| EIO)?;
                }
                for (r, v) in missing.iter().zip(outs) {
                    raw[*r] = Some(Cow::Owned(v));
                }
            }
            for (r, v) in have {
                if r < self.k {
                    raw[r] = Some(v);
                }
            }
        }
        // interleave
        let mut out = Vec::with_capacity(len as usize);
        let mut sum = !0u32;
        let mut pos = off;
        while pos < end {
            let st = ((pos - base) / self.s) as usize;
            let in_stripe = (pos - base) as usize % s;
            let r = in_stripe / c;
            let in_chunk = in_stripe % c;
            let n = (c - in_chunk).min((end - pos) as usize);
            match &raw[r] {
                Some(v) => {
                    let piece = &v[st * c + in_chunk..st * c + in_chunk + n];
                    if crc {
                        sum = crc::crc32c_extend(sum, piece, &mut out);
                    } else {
                        out.extend_from_slice(piece);
                    }
                }
                None => return Err(EIO),
            }
            pos += n as u64;
        }
        Ok((out, crc.then_some(sum)))
    }

    /// Raw data shard bytes of `want_raw` over one shard range of `len` bytes from the shard reads of `plan`
    /// (`got[shard]`, short = zero padded; decoded when a wanted shard was not read). Mode O RMW.
    pub fn shard_columns<B: AsRef<[u8]>>(
        &self,
        plan: &ReadPlan,
        got: &BTreeMap<u32, B>,
        len: usize,
        want_raw: &[usize],
    ) -> Result<Vec<(usize, Vec<u8>)>, i32> {
        // the decode reads the reply buffers of the plan as they are: only a short reply gets a padded copy
        let fetch = |shard: u32| -> Cow<'_, [u8]> {
            let bytes = got.get(&shard).map_or(&[][..], AsRef::as_ref);
            if bytes.len() >= len {
                Cow::Borrowed(&bytes[..len])
            } else {
                let mut v = vec![0; len];
                v[..bytes.len()].copy_from_slice(bytes);
                Cow::Owned(v)
            }
        };
        let mut out = Vec::with_capacity(want_raw.len());
        let mut missing: Vec<u32> = Vec::new();
        for &r in want_raw {
            let sh = *self.mapping.get(r).ok_or(EINVAL)?;
            if plan.shards.contains(&sh) {
                out.push((r, fetch(sh).into_owned()));
            } else {
                missing.push(sh);
            }
        }
        if !missing.is_empty() {
            let have: Vec<(u32, Cow<'_, [u8]>)> =
                plan.shards.iter().map(|s| (*s, fetch(*s))).collect();
            for (sh, v) in self.rebuild_shards(&have, &missing)? {
                let r = self.raw_of(sh).ok_or(EINVAL)?;
                out.push((r, v));
            }
        }
        Ok(out)
    }

    /// Rebuild the full shard chunks of `want_shards` over a stripe span from surviving shards (recovery /
    /// scrub repair). `have` = `(shard, bytes)` of a read set of the code (k shards for MDS codes), equal length. Returns `(shard, bytes)`.
    pub fn rebuild_shards<V: AsRef<[u8]>>(
        &self,
        have: &[(u32, V)],
        want_shards: &[u32],
    ) -> Result<Vec<(u32, Vec<u8>)>, i32> {
        let len = have.first().map_or(0, |h| h.1.as_ref().len());
        let h: Vec<(usize, &[u8])> = have
            .iter()
            .map(|(sh, v)| self.raw_of(*sh).map(|r| (r, v.as_ref())).ok_or(EINVAL))
            .collect::<Result<_, _>>()?;
        let want: Vec<usize> = want_shards
            .iter()
            .map(|sh| self.raw_of(*sh).ok_or(EINVAL))
            .collect::<Result<_, _>>()?;
        let mut outs: Vec<Vec<u8>> = vec![vec![0u8; len]; want.len()];
        {
            let mut o: Vec<&mut [u8]> = outs.iter_mut().map(|v| &mut v[..]).collect();
            self.codec.decode_into(&h, &want, &mut o).map_err(|_| EIO)?;
        }
        Ok(want_shards.iter().copied().zip(outs).collect())
    }
}

/// Single-shard repair of a sub-chunk code (clay, spec ec-clay.md 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairSpec {
    pub lost: u32,
    pub ranges: Vec<(i32, i32)>,
}

/// Shards to read for a stripe span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadPlan {
    pub s0: u64,
    pub s1: u64,
    pub shards: Vec<u32>,
    /// All wanted data shards are read: no decode.
    pub direct: bool,
    /// Clay repair read: the helpers send only these sub-chunk ranges (ECSubRead.subchunks), the result is the lost shard.
    pub repair: Option<RepairSpec>,
}

impl ReadPlan {
    /// Shard byte range `(offset, len)` every planned shard is asked for.
    pub fn shard_range(&self, chunk: u64) -> (u64, u64) {
        (self.s0 * chunk, (self.s1 - self.s0) * chunk)
    }
}

#[cfg(test)]
mod otests;
#[cfg(test)]
mod tests;
