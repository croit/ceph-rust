// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Staging of one idle recompaction (adr 0533); the walk that finds the candidates is
//! `obj::recompact`.
use super::{Encoding, ExtRaw, Result, Stage};
use crate::BLK;
use crate::compress::{Alg, Codec, CompSpec, bound, sample_incompressible};
use crate::dev::{BlockDev, Clock};
use crate::obj::onode::{CompMeta, F_COMP, F_INLINE, MAX_RUN};
use denc::types::{CollT, Ghobject};

/// What [`Stage::recompact`] did with a cut chunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RcOut {
    /// The range is staged as one fresh compressed chunk of `phys` blocks; `freed` blocks leave with the old records.
    Staged { freed: u64, phys: u64 },
    /// Rewriting would not use fewer blocks than the range holds now.
    NoGain,
    /// Nothing to do: object or chunk gone or no longer cut, the range is not exactly one aligned chunk, a range of
    /// plain records no longer plain or with holes.
    Skip,
}

impl<D: BlockDev, C: Clock> Stage<'_, '_, D, C> {
    /// Idle recompaction of one cut compressed chunk: logical blocks `[cs, cs + raw)` of `oid` hold windows (adr 0059
    /// am. 4) of a compressed chunk whose span is exactly that range, plus what cut it (raw overwrites, holes). The blocks
    /// a rewrite frees (every chunk owned only by records of this range, every unshared plain block) are compared with the
    /// range compressed again; only a rewrite into fewer blocks is staged: the range becomes dirty data with the encoding
    /// computed here, `finish` punches the old records (windows release their chunk through the refcounts, adr 0021 am.
    /// 32) and writes the one new chunk (parallel commit, like any write). A chunk another object shares (a clone) is
    /// not freed by the rewrite and counts nothing. With `pool` (the pool's compression) the range is one of plain
    /// records only, without holes: it is compressed with the pool's algorithm and kept only within its required ratio
    /// (as a write would). Nonblocking callers get `WouldBlock` for a cold page or data read.
    pub(crate) fn recompact(
        &mut self,
        cid: &CollT,
        oid: &Ghobject,
        cs: u64,
        raw: u32,
        pool: Option<CompSpec>,
    ) -> Result<RcOut> {
        let end = cs + raw as u64;
        if !(2..=MAX_RUN).contains(&raw) || !cs.is_multiple_of(raw as u64) {
            return Ok(RcOut::Skip);
        }
        let Some(id) = self.lookup(cid, oid)? else {
            return Ok(RcOut::Skip);
        };
        let flags = self.w(id).on.flags;
        if flags & F_INLINE != 0 || pool.is_none() && flags & F_COMP == 0 {
            return Ok(RcOut::Skip);
        }
        self.extents_set(id, cs, end)?;
        let (mut freed, mut alg, mut plain) = (0u64, None, 0u64);
        // compressed chunks in the range: (pba, physical blocks, shared flag, records of this range)
        let mut chunks: Vec<(u64, u32, bool, u32)> = Vec::new();
        // plain blocks flagged shared (a clone took them, possibly gone since): (first block, blocks)
        let mut shared_plain: Vec<(u64, u64)> = Vec::new();
        for ei in &self.sc.exts {
            let v = &self.sc.ext_raw[ei.off as usize..(ei.off + ei.len) as usize];
            let e = ExtRaw::new(v).expect("validated by extents_set");
            let (s, span) = (ei.lblk, e.span() as u64);
            match e.comp() {
                Some(m) => {
                    // the trailer's skip is validated inside the value only: a record whose window starts before
                    // its own label is outside the range, never a wrapped block below it
                    let Some(c0) = s.checked_sub(u64::from(m.skip)) else {
                        return Ok(RcOut::Skip);
                    };
                    if c0 < cs || c0 + m.raw_blks as u64 > end {
                        return Ok(RcOut::Skip); // a chunk reaching out of the range
                    }
                    if c0 == cs && m.raw_blks as u32 == raw && m.is_view() {
                        alg = Some(m.alg);
                    }
                    match chunks.iter_mut().find(|c| c.0 == e.pba()) {
                        Some(c) => c.3 += 1,
                        None => chunks.push((e.pba(), e.len(), e.shared(), 1)),
                    }
                }
                None => {
                    let (lo, hi) = (s.max(cs), (s + span).min(end));
                    plain += hi - lo;
                    if e.shared() {
                        shared_plain.push((e.pba() + (lo - s), hi - lo));
                    } else {
                        freed += hi - lo;
                    }
                }
            }
        }
        let alg = match pool {
            // plain records only, every block present
            Some(p) if chunks.is_empty() && plain == raw as u64 => p.alg,
            Some(_) => return Ok(RcOut::Skip),
            None => match alg.and_then(Alg::from_u8) {
                Some(a) => a,
                None => return Ok(RcOut::Skip),
            },
        };
        // a rewrite must take fewer blocks than the range holds now and, for a pool's range, meet its required ratio
        let max_phys = pool.map_or(raw as usize - 1, |p| {
            crate::compress::max_phys_blocks(raw as usize, p.ratio_permille)
        });
        for (pba, len, shared, recs) in chunks {
            if !shared || self.ref_owners(pba)? <= recs {
                freed += len as u64;
            }
        }
        for (pba, n) in shared_plain {
            for b in pba..pba + n {
                freed += u64::from(self.ref_owners(b)? == 1);
            }
        }
        if freed < 2 {
            return Ok(RcOut::NoGain); // a chunk takes at least one block
        }
        let d = self.eff_read(id, cs, raw as u64)?;
        if let Some(p) = pool
            && sample_incompressible(&mut self.s.codec, p, &d)
        {
            self.s.stats.comp_sampled_out += 1;
            return Ok(RcOut::NoGain);
        }
        let t0 = std::time::Instant::now();
        let mut cbuf = std::mem::take(&mut self.s.cbuf);
        cbuf.resize(4 + bound(d.len()), 0);
        let clen = self.s.codec.compress(alg, &d, &mut cbuf[4..]);
        self.s.stats.comp_ns += t0.elapsed().as_nanos() as u64;
        let phys = clen.map_or(usize::MAX, |l| (4 + l).div_ceil(BLK));
        if phys as u64 >= freed || phys > max_phys {
            self.s.cbuf = cbuf;
            return Ok(RcOut::NoGain);
        }
        let clen = clen.expect("phys < raw");
        cbuf[..4].copy_from_slice(&(clen as u32).to_le_bytes());
        if cbuf.len() < phys * BLK {
            cbuf.resize(phys * BLK, 0);
        }
        cbuf[4 + clen..phys * BLK].fill(0);
        let meta = CompMeta::whole(alg as u8, raw as u8, crc::crc32c(0, &d));
        self.w(id).runs.set(cs, raw as u64, Some(d));
        self.grows = true;
        // the range is exactly one chunk: `finish` hands it to `write_chunk`, which takes the encoding as computed here
        self.comp = Some(CompSpec {
            alg,
            ratio_permille: 1000,
            min_bytes: raw * BLK as u32,
            chunk_blks: raw as u8,
        });
        self.encoding = Some(Encoding {
            id,
            lblk: cs,
            bytes: cbuf,
            phys,
            raw_bytes: raw as usize * BLK,
            meta,
        });
        Ok(RcOut::Staged {
            freed,
            phys: phys as u64,
        })
    }
}
