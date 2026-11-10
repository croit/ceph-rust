// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Mode O direct reads (adr 0067 am. 3, spec ec-optimized.md 7.3): a client read of one data shard served from OUR shard
//! file, by a nonprimary shard or by the primary acting as shard. Every doubt is `Err(EAGAIN)`: the client then
//! redrives the op through the primary, which is always correct (only slower).
use crate::pg::{PSt, Pg, St};
use crate::store::PgStoreOps;
use crate::types::*;
use denc::types::{Eversion, Hobject, ShardId, SnapId};

/// Client read extent of a direct read (`op.extent`).
#[derive(Debug, Clone, Copy)]
pub struct DirectExtent {
    pub offset: u64,
    pub length: u64,
    pub truncate_seq: u32,
    pub truncate_size: u64,
    /// SPARSE_READ: answer the bytes our shard file holds as logical extents (a short file is a hole, not a refusal).
    pub sparse: bool,
}

/// Result of [`Pg::ec_direct_read`].
#[derive(Debug, Default)]
pub struct DirectRead {
    /// Our shard's bytes of each requested extent (contiguous shard range, no padding: the client assembles).
    pub data: Vec<Vec<u8>>,
    /// SPARSE_READ only (else `None`), per extent: logical `(offset, length)` of each chunk piece of `data`, ascending
    /// (spec ec-optimized-prim.md F.5: our shard range back to the object, split at chunk boundaries).
    pub extents: Vec<Option<Vec<(u64, u64)>>>,
    /// Shard -> object version for GET_INTERNAL_VERSIONS: primary = every shard (`oi.version` overridden by
    /// `shard_versions`), nonprimary = our shard only (our local OI version).
    pub versions: Vec<(ShardId, Eversion)>,
    pub user_version: u64,
}

/// Where our shard's bytes of the logical range `[off, off+len)` lie: shard file range `(start, len)`, `None` when this
/// raw chunk holds none of it. `raw` = our chunk index (< k), `c` = chunk size, `k` data chunks.
pub fn shard_extent(off: u64, len: u64, raw: u64, c: u64, k: u64) -> Option<(u64, u64)> {
    let s = c.checked_mul(k)?;
    let e = off.checked_add(len)?;
    if len == 0 || c == 0 || raw >= k {
        return None;
    }
    // Count this column's bytes before each endpoint. A range may fit u64 while the last stripe's end does not;
    // working within the stripe avoids constructing that unrepresentable boundary.
    let prefix = |x: u64| x / s * c + (x % s).saturating_sub(raw * c).min(c);
    let (a, b) = (prefix(off), prefix(e));
    (a < b).then_some((a, b - a))
}

/// Logical extents of our shard bytes `[so, so+len)` (raw data chunk `raw` of `k`, chunk `c`), one per chunk piece.
pub fn shard_to_logical(so: u64, len: u64, raw: u64, c: u64, k: u64) -> Vec<(u64, u64)> {
    let mut v = Vec::new();
    let (mut off, end) = (so, so.saturating_add(len));
    while off < end && c > 0 {
        let n = (c - off % c).min(end - off);
        v.push(((off / c) * c * k + raw * c + off % c, n));
        off += n;
    }
    v
}

impl Pg {
    /// Serve `reads` (and the versions map when `want_versions`) of the head object `soid` from our shard. `Err(errno)`
    /// is always `EAGAIN` (redrive through the primary) unless the PG is not ours to answer.
    ///
    /// Refused (never stale, never partial): not a served optimized EC PG; primary not readable / replica without a
    /// fresh lease from the primary; interval not active; object missing, beyond `last_backfill`, newer than the
    /// committed point of the log, or with a write in flight; whiteout / non-head; a parity shard; shard bytes not
    /// resident (the warming is started) or shorter than the object says (a hole: the primary zero-fills).
    pub fn ec_direct_read(
        &self,
        now: Mono,
        soid: &Hobject,
        reads: &[DirectExtent],
        want_versions: bool,
        store: &impl PgStoreOps,
    ) -> Result<DirectRead, i32> {
        const EAGAIN: i32 = 11;
        let ctx = self.ec_ctx().filter(|c| c.opt).ok_or(EAGAIN)?;
        let ec = self.pool.ec.as_ref().ok_or(EAGAIN)?;
        let served = if self.is_primary() {
            matches!(self.st, St::Primary(PSt::Active(_)))
        } else {
            self.st == St::ReplicaActive
        };
        let fresh = if self.is_primary() {
            self.is_readable(now) && !self.ec_write_in_flight(soid)
        } else {
            now < self.readable_until()
        };
        if !served || !fresh || self.is_deleting() {
            return Err(EAGAIN);
        }
        if soid.snap != SnapId::NOSNAP
            || *soid > self.info.last_backfill
            || self.missing.contains(soid)
            || self
                .log
                .newest_for(soid)
                .is_some_and(|v| v > self.pg_committed_to)
        {
            return Err(EAGAIN);
        }
        let raw = u64::from(ctx.raw);
        if raw >= u64::from(ec.k) {
            return Err(EAGAIN); // parity shard
        }
        let attrs = store.ec_getattrs(self.spg, soid).map_err(|_| EAGAIN)?;
        let oi = attrs
            .get(b"_".as_slice())
            .and_then(|b| denc::from_slice::<replwire::ObjectInfo>(b).ok())
            .ok_or(EAGAIN)?;
        if oi.is_whiteout() {
            return Err(EAGAIN);
        }
        let mut out = DirectRead {
            user_version: oi.user_version,
            ..Default::default()
        };
        if want_versions {
            if self.is_primary() {
                for s in 0..self.pool.size {
                    let sh = ShardId(s as i8);
                    let v = oi.shard_versions.get(&sh).copied().unwrap_or(oi.version);
                    out.versions.push((sh, v));
                }
            } else {
                out.versions.push((self.me.shard, oi.version));
            }
        }
        for r in reads {
            // size after the truncate rule of the read, then clipped like the op layer does
            let mut size = oi.size;
            if oi.truncate_seq < u64::from(r.truncate_seq)
                && r.offset.saturating_add(r.length) > r.truncate_size
                && size > r.truncate_size
            {
                size = r.truncate_size;
            }
            if r.length == 0 {
                return Err(EAGAIN);
            }
            let len = if r.offset >= size {
                0
            } else {
                r.length.min(size - r.offset)
            };
            let k = u64::from(ec.k);
            let Some((so, sl)) = shard_extent(r.offset, len, raw, ctx.chunk, k) else {
                out.data.push(Vec::new());
                out.extents.push(r.sparse.then(Vec::new));
                continue;
            };
            if !self.ec_range_warm(soid, so, sl, store) {
                return Err(EAGAIN);
            }
            match store.ec_read(self.spg, soid, so, sl) {
                // sparse: what the shard file holds is data, the rest a hole (zeros, never written)
                Ok((d, _)) if r.sparse && d.len() as u64 <= sl => {
                    out.extents.push(Some(shard_to_logical(
                        so,
                        d.len() as u64,
                        raw,
                        ctx.chunk,
                        k,
                    )));
                    out.data.push(d);
                }
                Ok((d, _)) if d.len() as u64 == sl => {
                    out.extents.push(None);
                    out.data.push(d);
                }
                _ => return Err(EAGAIN),
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::shard_extent as se;

    // k=2, C=4096: stripe 8192; shard 0 holds chunks at logical 0, 8192, ...; shard 1 at 4096, 12288, ...
    #[test]
    fn single_chunk() {
        assert_eq!(se(100, 50, 0, 4096, 2), Some((100, 50)));
        assert_eq!(se(100, 50, 1, 4096, 2), None);
        assert_eq!(se(4096 + 8, 16, 1, 4096, 2), Some((8, 16)));
        assert_eq!(se(8192 + 4096, 4096, 1, 4096, 2), Some((4096, 4096)));
    }
    #[test]
    fn multi_stripe() {
        // [100, 3 stripes): shard 0 holds 100..4096, 8192..12288, 16384..(end)
        let (off, len) = (100, 2 * 8192 + 500);
        assert_eq!(
            se(off, len, 0, 4096, 2),
            Some((100, 4096 - 100 + 4096 + 600))
        );
        // shard 1: 4096..8192, 12288..16384 -> shard bytes 0..8192
        assert_eq!(se(off, len, 1, 4096, 2), Some((0, 8192)));
        // ends exactly where the chunk of shard 1 starts: shard 1 holds nothing of the last stripe
        assert_eq!(se(0, 8192 + 4096, 1, 4096, 2), Some((0, 4096)));
        assert_eq!(se(0, 4096, 1, 4096, 2), None);
        assert_eq!(se(0, 0, 0, 4096, 2), None);
    }
    #[test]
    fn shard_bytes_back_to_logical_extents() {
        use super::shard_to_logical as sl;
        // k=2, C=4096: shard 1 bytes 100..8192 = logical 4196..8192 and 12288..16384
        assert_eq!(sl(100, 8092, 1, 4096, 2), vec![(4196, 3996), (12288, 4096)]);
        assert_eq!(sl(0, 10, 0, 4096, 2), vec![(0, 10)]);
        assert!(sl(5, 0, 0, 4096, 2).is_empty());
    }
    #[test]
    fn parity_and_overflow() {
        assert_eq!(se(0, 100, 2, 4096, 2), None);
        assert_eq!(se(u64::MAX - 1, 10, 0, 4096, 2), None);
    }

    #[test]
    fn last_addressable_stripe() {
        // The logical range fits u64, but its stripe's mathematical end does not.
        let off = u64::MAX - 100;
        assert_eq!(
            se(off, 50, 1, 4096, 2),
            Some((off / 8192 * 4096 + 3995, 50))
        );
        assert_eq!(se(off, 50, 0, 4096, 2), None);
        assert_eq!(se(0, 1, 0, u64::MAX, 2), None);
    }
}
