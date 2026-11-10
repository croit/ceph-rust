// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Per-object write overlay of one txn: not-yet-allocated new block contents (`Data`) and punched ranges
//! (`Hole`). Everything is resolved to device blocks only when the txn is flushed (one allocation/free pass per
//! object), so a txn never frees blocks it allocated itself.

use crate::BLK;
use std::borrow::Cow;
use std::collections::BTreeMap;

/// Borrow on the synchronous path; keep immutable owners across a preparation continuation.
#[derive(Debug, Clone)]
pub enum Data<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
    Shared(bytes::Bytes),
}
impl PartialEq for Data<'_> {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}
impl Eq for Data<'_> {}
impl PartialOrd for Data<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Data<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (**self).cmp(&**other)
    }
}
impl AsRef<[u8]> for Data<'_> {
    fn as_ref(&self) -> &[u8] {
        self
    }
}
impl std::ops::Deref for Data<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Self::Borrowed(s) => s,
            Self::Owned(v) => v,
            Self::Shared(b) => b,
        }
    }
}
impl<'a> From<Cow<'a, [u8]>> for Data<'a> {
    fn from(c: Cow<'a, [u8]>) -> Self {
        match c {
            Cow::Borrowed(s) => Self::Borrowed(s),
            Cow::Owned(v) => Self::Owned(v),
        }
    }
}
impl From<Vec<u8>> for Data<'_> {
    fn from(v: Vec<u8>) -> Self {
        Self::Owned(v)
    }
}
impl From<bytes::Bytes> for Data<'_> {
    fn from(b: bytes::Bytes) -> Self {
        Self::Shared(b)
    }
}
impl<'a> From<&'a [u8]> for Data<'a> {
    fn from(s: &'a [u8]) -> Self {
        Self::Borrowed(s)
    }
}
impl Data<'_> {
    pub fn retained(self, owners: &[bytes::Bytes]) -> Data<'static> {
        match self {
            Self::Borrowed(s) => {
                let start = s.as_ptr() as usize;
                let end = start.checked_add(s.len());
                let idx = owners.partition_point(|b| (b.as_ptr() as usize) <= start);
                if idx > 0 {
                    let b = &owners[idx - 1];
                    let base = b.as_ptr() as usize;
                    if end
                        .is_some_and(|e| base.checked_add(b.len()).is_some_and(|limit| e <= limit))
                    {
                        return Data::Shared(b.slice(start - base..start - base + s.len()));
                    }
                }
                // Borrow-only callers already need a private copy when a queue parks.
                Data::Shared(bytes::Bytes::copy_from_slice(s))
            }
            Self::Owned(v) => Data::Shared(bytes::Bytes::from(v)),
            Self::Shared(b) => Data::Shared(b),
        }
    }
}

/// "To infinity" in blocks (truncate holes).
pub const INF: u64 = 1 << 40;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run<'a> {
    pub n: u64,
    /// `None` = hole (zeros), else `n * 4096` bytes (borrowed from the caller's txn for aligned writes: no copy until
    /// the single copy into the DMA buffer).
    pub data: Option<Data<'a>>,
}

#[derive(Debug, Default, Clone)]
pub struct Dirty<'a> {
    pub runs: BTreeMap<u64, Run<'a>>,
}

/// Sub-range `[a, b)` of run data; stays borrowed when it was.
fn sub<'a>(c: &Data<'a>, a: usize, b: usize) -> Data<'a> {
    match c {
        Data::Borrowed(s) => Data::Borrowed(&s[a..b]),
        Data::Owned(v) => Data::Owned(v[a..b].to_vec()),
        Data::Shared(s) => Data::Shared(s.slice(a..b)),
    }
}

impl<'a> Dirty<'a> {
    pub fn is_empty(&self) -> bool {
        self.runs.is_empty()
    }

    /// Remove all coverage of blocks `[s, e)`, keeping the remnants.
    pub fn cut(&mut self, s: u64, e: u64) {
        // from the highest run starting before `e` down; the first one ending at or before `s` ends the walk
        while let Some((&k, r)) = self.runs.range(..e).next_back() {
            if k + r.n <= s {
                break;
            }
            let mut r = self.runs.remove(&k).unwrap();
            let re = k + r.n;
            // The removed run owns its allocation: keep one immutable owner rather than copying
            // every untouched prefix/suffix when a small later operation cuts a large owned run.
            if k < s || re > e {
                r.data = r.data.map(|d| match d {
                    Data::Owned(v) => Data::Shared(bytes::Bytes::from(v)),
                    d => d,
                });
            }
            if k < s {
                self.runs.insert(
                    k,
                    Run {
                        n: s - k,
                        data: r.data.as_ref().map(|d| sub(d, 0, (s - k) as usize * BLK)),
                    },
                );
            }
            if re > e {
                self.runs.insert(
                    e,
                    Run {
                        n: re - e,
                        data: r
                            .data
                            .as_ref()
                            .map(|d| sub(d, (e - k) as usize * BLK, d.len())),
                    },
                );
            }
        }
    }

    pub fn set(&mut self, s: u64, n: u64, data: Option<Vec<u8>>) {
        self.set_cow(s, n, data.map(Cow::Owned));
    }

    pub fn set_cow(&mut self, s: u64, n: u64, data: Option<Cow<'a, [u8]>>) {
        self.set_data(s, n, data.map(Data::from));
    }

    pub fn set_data(&mut self, s: u64, n: u64, data: Option<Data<'a>>) {
        debug_assert!(
            data.as_ref()
                .is_none_or(|d| d.len() as u64 == n * BLK as u64)
        );
        self.cut(s, s + n);
        self.runs.insert(s, Run { n, data });
    }

    pub fn hole(&mut self, s: u64, n: u64) {
        self.set(s, n, None);
    }

    /// `Some(Some(block))` data, `Some(None)` hole, `None` not covered.
    pub fn cover(&self, blk: u64) -> Option<Option<&[u8]>> {
        let (s, r) = self.runs.range(..=blk).next_back()?;
        if blk >= s + r.n {
            return None;
        }
        Some(
            r.data
                .as_ref()
                .map(|d| &d[(blk - s) as usize * BLK..(blk - s + 1) as usize * BLK]),
        )
    }

    /// Paint the overlay of blocks `[blk, blk + n)` onto `out` (`n * 4096` bytes).
    pub fn overlay(&self, blk: u64, n: u64, out: &mut [u8]) {
        let end = blk + n;
        let first = self.runs.range(..=blk).next_back().map_or(blk, |(s, _)| *s);
        for (s, r) in self.runs.range(first..end) {
            let (lo, hi) = (blk.max(*s), end.min(s + r.n));
            if lo >= hi {
                continue;
            }
            let dst = &mut out[(lo - blk) as usize * BLK..(hi - blk) as usize * BLK];
            match &r.data {
                Some(d) => {
                    dst.copy_from_slice(&d[(lo - s) as usize * BLK..(hi - s) as usize * BLK])
                }
                None => dst.fill(0),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blk(v: u8, n: u64) -> Vec<u8> {
        vec![v; n as usize * BLK]
    }

    #[test]
    fn cut_split_overlay() {
        let mut d = Dirty::default();
        d.set(10, 6, Some(blk(1, 6)));
        d.set(12, 2, Some(blk(2, 2)));
        assert_eq!(d.runs.len(), 3);
        let mut out = vec![9u8; 8 * BLK];
        d.overlay(9, 8, &mut out);
        let want = [9, 1, 1, 2, 2, 1, 1, 9];
        for (i, w) in want.iter().enumerate() {
            assert!(
                out[i * BLK..(i + 1) * BLK].iter().all(|b| b == w),
                "blk {i}"
            );
        }
        d.hole(11, INF);
        assert_eq!(d.cover(10).unwrap().unwrap()[0], 1);
        assert!(d.cover(11).unwrap().is_none());
        assert!(d.cover(9).is_none());
        assert!(d.cover(10 + 1000).unwrap().is_none());
        d.set(0, 100, Some(blk(7, 100)));
        assert_eq!(d.runs.len(), 2);
    }

    /// The overlay's cut takes no temporary allocation: a run removed whole leaves nothing to collect.
    #[test]
    fn cut_over_one_run_does_not_allocate() {
        let mut d = Dirty::default();
        d.set(0, 4, None);
        let n = crate::test_alloc::allocations(|| d.cut(0, 4));
        assert_eq!(n, 0, "cut allocated");
        assert!(d.runs.is_empty());
    }

    #[test]
    fn small_cuts_retain_owned_allocation_and_correct_subranges() {
        let data = blk(0x75, 1024);
        let base = data.as_ptr();
        let mut d = Dirty::default();
        d.set(0, 1024, Some(data));
        d.hole(100, 1);
        d.hole(800, 1);
        for (start, end) in [(0u64, 100u64), (101, 800), (801, 1024)] {
            let run = &d.runs[&start];
            let data = run.data.as_ref().unwrap();
            assert!(matches!(data, Data::Shared(_)));
            assert_eq!(data.as_ptr(), base.wrapping_add(start as usize * BLK));
            assert_eq!(data.len(), (end - start) as usize * BLK);
            assert!(data.iter().all(|b| *b == 0x75));
        }
        assert_eq!(d.cover(100), Some(None));
        assert_eq!(d.cover(800), Some(None));
    }
}
