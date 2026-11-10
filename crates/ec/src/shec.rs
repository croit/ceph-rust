// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! shec: shingled, non-MDS erasure code over GF(2^8) (spec ec-shec.md, w=8 only).
//!
//! Parity row r keeps the reed_sol_van values of a cyclic window of data columns, the rest is zero. Recoverability
//! is per erasure pattern; [`ShecCodec::min_set`] is the minimum_to_decode search of the spec (section 5.2) and
//! doubles as the recoverability predicate (want = all chunks).

#![expect(clippy::needless_range_loop)]

use crate::gf::{DecodeError, Kind, Nib, coding_matrix, invert, mul_acc, mul_acc_nib, nib};

/// Spec limits: `k >= m >= c >= 1`, `k <= 12`, `k + m <= 20`.
pub fn params_ok(k: usize, m: usize, c: usize) -> bool {
    c >= 1 && m >= c && k >= m && k <= 12 && k + m <= 20
}

#[derive(Clone, Debug)]
pub struct ShecCodec {
    k: usize,
    m: usize,
    /// (m1, c1) of the chosen split (0, 0 = one group).
    split: (usize, usize),
    mat: Vec<u8>,
    tabs: Vec<Nib>,
}

/// Solve plan of the search: equations `rows` (chunk ids, ascending) over unknown data chunks `cols` (ascending),
/// `inv` = inverse of the square system (row-major `cols x rows`); empty when nothing is to solve.
struct Plan {
    rows: Vec<usize>,
    cols: Vec<usize>,
    inv: Vec<u8>,
}

/// Rows `first..first+mm` of the result take the window of group parameters `(mm, cc)` from `base`.
fn mask_group(mat: &mut [u8], base: &[u8], k: usize, first: usize, mm: usize, cc: usize) {
    for rr in 0..mm {
        let lo = rr * k / mm % k;
        let hi = (rr + cc) * k / mm % k;
        let row = first + rr;
        for j in 0..k {
            let inside = lo == hi || (j + k - lo) % k < (hi + k - lo) % k;
            mat[row * k + j] = if inside { base[row * k + j] } else { 0 };
        }
    }
}

/// Score (integer, spec 3.4) of the split `(m1, c1)`.
fn score(k: usize, m: usize, c: usize, m1: usize, c1: usize) -> usize {
    let mut best = vec![100_000_000usize; k];
    let mut s = 0;
    for (mm, cc) in [(m1, c1), (m - m1, c - c1)] {
        for rr in 0..mm {
            let a = rr * k / mm;
            let b = (rr + cc) * k / mm;
            let span = b - a;
            s += span;
            let (lo, hi) = (a % k, b % k);
            let mut col = lo;
            loop {
                best[col] = best[col].min(span);
                col = (col + 1) % k;
                if col == hi {
                    break;
                }
            }
        }
    }
    s + best.iter().sum::<usize>()
}

/// Valid split candidates `(c1, m1, score)` of technique multiple, in search order.
pub fn split_candidates(k: usize, m: usize, c: usize) -> Vec<(usize, usize, usize)> {
    let mut v = Vec::new();
    for c1 in 0..=c / 2 {
        for m1 in 0..=m {
            let (c2, m2) = (c - c1, m - m1);
            if m1 < c1
                || m2 < c2
                || (m1 == 0 && c1 != 0)
                || (m2 == 0 && c2 != 0)
                || (m1 != 0 && c1 == 0)
                || (m2 != 0 && c2 == 0)
            {
                continue;
            }
            v.push((c1, m1, score(k, m, c, m1, c1)));
        }
    }
    v
}

impl ShecCodec {
    /// `None` outside the spec's parameter rules (or `w != 8`).
    pub fn try_new(k: usize, m: usize, c: usize, single: bool, w: usize) -> Option<ShecCodec> {
        if w != 8 || !params_ok(k, m, c) {
            return None;
        }
        let base = if k == 1 {
            vec![1; m]
        } else {
            coding_matrix(Kind::JerVan, k, m)
        };
        let (m1, c1) = if single {
            (0, 0)
        } else {
            let mut best: Option<(usize, usize, usize)> = None;
            for (c1, m1, s) in split_candidates(k, m, c) {
                if best.is_none_or(|b| s < b.2) {
                    best = Some((c1, m1, s));
                }
            }
            let b = best?;
            (b.1, b.0)
        };
        let mut mat = vec![0u8; m * k];
        if m1 > 0 {
            mask_group(&mut mat, &base, k, 0, m1, c1);
        }
        mask_group(&mut mat, &base, k, m1, m - m1, c - c1);
        let tabs = mat.iter().map(|x| nib(*x)).collect();
        Some(ShecCodec {
            k,
            m,
            split: (m1, c1),
            mat,
            tabs,
        })
    }

    pub fn k(&self) -> usize {
        self.k
    }
    pub fn m(&self) -> usize {
        self.m
    }
    /// Chosen `(m1, c1)`.
    pub fn split(&self) -> (usize, usize) {
        self.split
    }
    /// The m x k coding matrix (zeros outside the shingles).
    pub fn matrix(&self) -> &[u8] {
        &self.mat
    }

    /// parity[r] = sum_j M[r][j] * data[j]; zero coefficients are skipped.
    pub fn encode(&self, data: &[&[u8]], parity: &mut [&mut [u8]]) {
        assert_eq!(data.len(), self.k);
        assert_eq!(parity.len(), self.m);
        const BLK: usize = 16 << 10;
        let len = data.first().map_or(0, |d| d.len());
        let mut off = 0;
        while off < len {
            let end = (off + BLK).min(len);
            for (r, p) in parity.iter_mut().enumerate() {
                let dst = &mut p[off..end];
                dst.fill(0);
                for (j, d) in data.iter().enumerate() {
                    let i = r * self.k + j;
                    match self.mat[i] {
                        0 => {}
                        1 => dst.iter_mut().zip(&d[off..end]).for_each(|(d, s)| *d ^= *s),
                        _ => mul_acc_nib(dst, &d[off..end], &self.tabs[i]),
                    }
                }
            }
            off = end;
        }
    }

    /// Search of spec 5.2 on `want` (expanded in place) and `av` (both length n).
    fn search(&self, want: &mut [bool], av: &[bool]) -> Option<Plan> {
        let (k, m) = (self.k, self.m);
        for r in 0..m {
            if want[k + r] && !av[k + r] {
                for j in 0..k {
                    if self.mat[r * k + j] != 0 {
                        want[j] = true;
                    }
                }
            }
        }
        let (mut mindup, mut minp) = (k + 1, k + 1);
        let mut plan = Plan {
            rows: Vec::new(),
            cols: Vec::new(),
            inv: Vec::new(),
        };
        for pp in 0u32..1 << m {
            let ek = pp.count_ones() as usize;
            if ek > minp || (0..m).any(|r| pp >> r & 1 == 1 && !av[k + r]) {
                continue;
            }
            let mut rows = vec![false; k + m];
            let mut cols = vec![false; k];
            for j in 0..k {
                cols[j] = want[j] && !av[j];
            }
            for r in 0..m {
                if pp >> r & 1 == 0 {
                    continue;
                }
                rows[k + r] = true;
                for j in 0..k {
                    if self.mat[r * k + j] != 0 {
                        cols[j] = true;
                        if av[j] {
                            rows[j] = true;
                        }
                    }
                }
            }
            let rl: Vec<usize> = (0..k + m).filter(|i| rows[*i]).collect();
            let cl: Vec<usize> = (0..k).filter(|j| cols[*j]).collect();
            if rl.len() != cl.len() {
                continue;
            }
            let dup = rl.len();
            if dup == 0 {
                mindup = 0;
                plan = Plan {
                    rows: rl,
                    cols: cl,
                    inv: Vec::new(),
                };
                break;
            }
            if dup < mindup {
                let mut a = vec![0u8; dup * dup];
                for (i, &id) in rl.iter().enumerate() {
                    for (jj, &q) in cl.iter().enumerate() {
                        a[i * dup + jj] = if id < k {
                            u8::from(id == q)
                        } else {
                            self.mat[(id - k) * k + q]
                        };
                    }
                }
                if let Some(inv) = invert(&a, dup) {
                    mindup = dup;
                    minp = ek;
                    plan = Plan {
                        rows: rl,
                        cols: cl,
                        inv,
                    };
                }
            }
        }
        (mindup != k + 1).then_some(plan)
    }

    /// minimum_to_decode (spec 5.2/5.1): the sorted raw chunks to read to obtain `want` from `avail`; `None` when
    /// impossible (or an index is out of range). Never reads a wanted chunk that decoding can recompute.
    pub fn min_set(&self, want: &[usize], avail: &[usize]) -> Option<Vec<usize>> {
        let n = self.k + self.m;
        if want.iter().chain(avail).any(|&i| i >= n) {
            return None;
        }
        let (mut w, mut av) = (vec![false; n], vec![false; n]);
        want.iter().for_each(|&i| w[i] = true);
        avail.iter().for_each(|&i| av[i] = true);
        let orig = w.clone();
        let plan = self.search(&mut w, &av)?;
        let mut set = vec![false; n];
        plan.rows.iter().for_each(|&i| set[i] = true);
        for j in 0..self.k {
            if w[j] && av[j] {
                set[j] = true;
            }
        }
        for r in 0..self.m {
            let p = self.k + r;
            if orig[p] && av[p] && (0..self.k).any(|j| self.mat[r * self.k + j] != 0 && !w[j]) {
                set[p] = true;
            }
        }
        Some((0..n).filter(|i| set[*i]).collect())
    }

    /// Peering predicate: every chunk can be rebuilt from the chunks `avail`.
    pub fn recoverable(&self, avail: &[usize]) -> bool {
        let all: Vec<usize> = (0..self.k + self.m).collect();
        self.min_set(&all, avail).is_some()
    }

    /// Rebuild `want[i]` into `out[i]` from `have` (the set of [`min_set`](Self::min_set), or any set the search
    /// accepts for the erased wanted chunks).
    pub fn decode_into(
        &self,
        have: &[(usize, &[u8])],
        want: &[usize],
        out: &mut [&mut [u8]],
    ) -> Result<(), DecodeError> {
        let (k, n) = (self.k, self.k + self.m);
        if out.len() != want.len() {
            return Err(DecodeError::Unrecoverable);
        }
        let len = have.first().map_or(0, |h| h.1.len());
        if have.iter().any(|h| h.1.len() != len) || out.iter().any(|o| o.len() != len) {
            return Err(DecodeError::BadLen);
        }
        if have
            .iter()
            .map(|h| h.0)
            .chain(want.iter().copied())
            .any(|i| i >= n)
        {
            return Err(DecodeError::Unrecoverable);
        }
        let mut src: Vec<Option<&[u8]>> = vec![None; n];
        have.iter().for_each(|h| src[h.0] = Some(h.1));
        let av: Vec<bool> = src.iter().map(|s| s.is_some()).collect();
        let mut erased = vec![false; n];
        want.iter()
            .filter(|&&w| !av[w])
            .for_each(|&w| erased[w] = true);
        let plan = if erased.iter().any(|e| *e) {
            self.search(&mut erased, &av)
                .ok_or(DecodeError::Unrecoverable)?
        } else {
            Plan {
                rows: Vec::new(),
                cols: Vec::new(),
                inv: Vec::new(),
            }
        };
        let dup = plan.rows.len();
        // recovered data chunks
        let mut rec: Vec<Option<Vec<u8>>> = vec![None; k];
        for (pos, &q) in plan.cols.iter().enumerate() {
            if av[q] {
                continue;
            }
            let mut buf = vec![0u8; len];
            for (i, &id) in plan.rows.iter().enumerate() {
                let s = src[id].ok_or(DecodeError::Unrecoverable)?;
                mul_acc(&mut buf, s, plan.inv[pos * dup + i]);
            }
            rec[q] = Some(buf);
        }
        for (&w, o) in want.iter().zip(out.iter_mut()) {
            if let Some(s) = src[w] {
                o.copy_from_slice(s);
            } else if w < k {
                o.copy_from_slice(rec[w].as_deref().ok_or(DecodeError::Unrecoverable)?);
            } else {
                o.fill(0);
                for j in 0..k {
                    let c = self.mat[(w - k) * k + j];
                    if c == 0 {
                        continue;
                    }
                    let d = src[j]
                        .or(rec[j].as_deref())
                        .ok_or(DecodeError::Unrecoverable)?;
                    mul_acc(o, d, c);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gf::mul;

    fn mk(k: usize, m: usize, c: usize, single: bool) -> ShecCodec {
        ShecCodec::try_new(k, m, c, single, 8).unwrap()
    }

    #[test]
    fn matrices_spec() {
        let cases: &[(usize, usize, usize, bool, &[u8])] = &[
            (
                4,
                3,
                2,
                false,
                &[1, 1, 1, 1, 1, 0xD9, 0, 0, 0, 0, 0x8F, 0xC8],
            ),
            (
                4,
                3,
                2,
                true,
                &[1, 1, 0, 0, 0, 0xD9, 0x5C, 0xAC, 1, 0, 0x8F, 0xC8],
            ),
            (
                6,
                4,
                3,
                false,
                &[
                    1, 1, 1, 0, 0, 0, 0, 0, 0, 0xAC, 0x52, 0xC8, 1, 0xA6, 0xC4, 0xEE, 0x53, 0x92,
                    1, 0x7B, 0xF5, 0x8F, 0xF4, 0x8E,
                ],
            ),
            (
                6,
                4,
                3,
                true,
                &[
                    1, 1, 1, 1, 0, 0, 0, 0xE1, 0x97, 0xAC, 0x52, 0xC8, 1, 0, 0, 0xEE, 0x53, 0x92,
                    1, 0x7B, 0xF5, 0, 0xF4, 0x8E,
                ],
            ),
            (3, 2, 1, false, &[1, 0, 0, 0, 0xF5, 0xF4]),
            (3, 2, 2, false, &[1, 1, 1, 1, 0xF5, 0xF4]),
            (4, 2, 2, false, &[1, 1, 1, 1, 1, 0x46, 0x8F, 0xC8]),
            (5, 2, 1, false, &[1, 1, 0, 0, 0, 0, 0, 0x52, 0xF5, 0xA7]),
            (1, 1, 1, false, &[1]),
            (4, 1, 1, false, &[1, 1, 1, 1]),
        ];
        for (k, m, c, single, want) in cases {
            assert_eq!(
                mk(*k, *m, *c, *single).matrix(),
                *want,
                "{k},{m},{c},{single}"
            );
        }
    }

    #[test]
    fn split_search() {
        let t = |k, m, c| split_candidates(k, m, c);
        assert_eq!(t(4, 3, 2), [(0, 0, 18), (1, 1, 16), (1, 2, 16)]);
        assert_eq!(
            t(6, 4, 3).iter().map(|x| x.2).collect::<Vec<_>>()[..3],
            [42, 42, 36]
        );
        // (k,m,c) -> (m1,c1) chosen
        let table: &[(usize, usize, usize, usize, usize)] = &[
            (1, 1, 1, 0, 0),
            (2, 1, 1, 0, 0),
            (4, 1, 1, 0, 0),
            (3, 2, 1, 0, 0),
            (5, 2, 1, 0, 0),
            (7, 2, 1, 0, 0),
            (3, 2, 2, 0, 0),
            (4, 2, 2, 0, 0),
            (3, 3, 2, 1, 1),
            (4, 3, 2, 1, 1),
            (6, 3, 2, 1, 1),
            (8, 3, 2, 1, 1),
            (6, 4, 2, 1, 1),
            (8, 4, 2, 1, 1),
            (9, 4, 2, 1, 1),
            (6, 4, 3, 2, 1),
            (8, 4, 3, 2, 1),
            (9, 5, 3, 3, 1),
            (12, 7, 4, 4, 1),
        ];
        for &(k, m, c, m1, c1) in table {
            assert_eq!(mk(k, m, c, false).split(), (m1, c1), "{k},{m},{c}");
            assert_eq!(mk(k, m, c, true).split(), (0, 0));
        }
    }

    #[test]
    fn param_rules() {
        let ok = |k, m, c| ShecCodec::try_new(k, m, c, false, 8).is_some();
        assert!(ok(4, 3, 2) && ok(1, 1, 1) && ok(12, 8, 8));
        assert!(!ok(0, 1, 1) && !ok(4, 0, 1) && !ok(4, 3, 0) && !ok(4, 3, 4) && !ok(13, 3, 2));
        assert!(!ok(12, 9, 2) && !ok(3, 4, 2));
        assert!(ShecCodec::try_new(4, 3, 2, false, 16).is_none());
    }

    #[test]
    fn encode_known_answer() {
        // spec 4: data bytes 01,02,03,04 -> parity 04, AE, 8B
        let s = mk(4, 3, 2, false);
        let d: Vec<Vec<u8>> = (1..=4u8).map(|x| vec![x; 40]).collect();
        let dr: Vec<&[u8]> = d.iter().map(|v| &v[..]).collect();
        let mut p = vec![vec![0u8; 40]; 3];
        let mut pr: Vec<&mut [u8]> = p.iter_mut().map(|v| &mut v[..]).collect();
        s.encode(&dr, &mut pr);
        assert_eq!([p[0][39], p[1][0], p[2][17]], [4, 0xAE, 0x8B]);
    }

    #[test]
    fn min_sets_spec() {
        let s = mk(4, 3, 2, false);
        let all = |miss: &[usize]| -> Vec<usize> { (0..7).filter(|i| !miss.contains(i)).collect() };
        let ms = |want: &[usize], miss: &[usize]| s.min_set(want, &all(miss));
        assert_eq!(ms(&[0], &[0]), Some(vec![1, 5]));
        assert_eq!(ms(&[0, 1], &[0, 1]), Some(vec![2, 3, 4, 5]));
        assert_eq!(ms(&[0, 2], &[0, 2]), Some(vec![1, 3, 4, 5]));
        assert_eq!(ms(&[0, 1, 2], &[0, 1, 2]), Some(vec![3, 4, 5, 6]));
        assert_eq!(ms(&[4], &[4]), Some(vec![0, 1, 2, 3]));
        assert_eq!(ms(&[5], &[5]), Some(vec![0, 1]));
        assert_eq!(ms(&[0, 5], &[0, 5]), Some(vec![1, 2, 3, 4]));
        assert_eq!(ms(&[0, 4], &[0]), Some(vec![1, 4, 5]));
        assert_eq!(ms(&[5], &[]), Some(vec![5]));
        assert_eq!(ms(&[0, 1, 5], &[]), Some(vec![0, 1]));
        assert_eq!(ms(&[], &[0]), Some(vec![]));
        // recoverability examples
        assert!(s.recoverable(&all(&[0, 1, 2])));
        assert!(!s.recoverable(&all(&[0, 1, 2, 3])));
        assert!(!s.recoverable(&all(&[0, 1, 4])));
        assert!(!s.recoverable(&all(&[0, 1, 2, 4])));
        assert_eq!(s.min_set(&[7], &[0]), None);
        let s = mk(6, 4, 3, false);
        let all =
            |miss: &[usize]| -> Vec<usize> { (0..10).filter(|i| !miss.contains(i)).collect() };
        assert_eq!(s.min_set(&[0], &all(&[0])), Some(vec![1, 2, 6]));
        assert_eq!(s.min_set(&[3], &all(&[3])), Some(vec![4, 5, 7]));
        assert_eq!(
            s.min_set(&[0, 1], &all(&[0, 1])),
            Some(vec![2, 3, 4, 5, 6, 8])
        );
        assert_eq!(s.min_set(&[6], &all(&[6])), Some(vec![0, 1, 2]));
    }

    /// Independent rank test: all missing data columns determined by the available parity rows.
    fn rank_recoverable(s: &ShecCodec, avail: &[bool]) -> bool {
        let (k, m) = (s.k, s.m);
        let unk: Vec<usize> = (0..k).filter(|j| !avail[*j]).collect();
        let mut rows: Vec<Vec<u8>> = (0..m)
            .filter(|r| avail[k + r])
            .map(|r| unk.iter().map(|&j| s.mat[r * k + j]).collect())
            .collect();
        for (rank, col) in (0..unk.len()).enumerate() {
            let Some(p) = (rank..rows.len()).find(|&i| rows[i][col] != 0) else {
                return false;
            };
            rows.swap(rank, p);
            let iv = crate::gf::inv(rows[rank][col]);
            for i in 0..rows.len() {
                if i != rank && rows[i][col] != 0 {
                    let f = mul(rows[i][col], iv);
                    for x in 0..unk.len() {
                        let t = mul(f, rows[rank][x]);
                        rows[i][x] ^= t;
                    }
                }
            }
        }
        true
    }

    fn rnd(x: &mut u32) -> u8 {
        *x ^= *x << 13;
        *x ^= *x >> 17;
        *x ^= *x << 5;
        (*x >> 8) as u8
    }

    #[test]
    fn all_patterns_roundtrip() {
        let mut seed = 0x1234_5678u32;
        let cfgs = [
            (4, 3, 2),
            (6, 4, 3),
            (5, 2, 1),
            (3, 2, 2),
            (8, 4, 3),
            (6, 3, 2),
            (4, 4, 3),
        ];
        for (k, m, c) in cfgs {
            for single in [false, true] {
                let s = mk(k, m, c, single);
                let n = k + m;
                let len = 48;
                let data: Vec<Vec<u8>> = (0..k)
                    .map(|_| (0..len).map(|_| rnd(&mut seed)).collect())
                    .collect();
                let mut all = data.clone();
                all.extend((0..m).map(|_| vec![0u8; len]));
                {
                    let d: Vec<&[u8]> = data.iter().map(|v| &v[..]).collect();
                    let mut p: Vec<&mut [u8]> = all[k..].iter_mut().map(|v| &mut v[..]).collect();
                    s.encode(&d, &mut p);
                }
                for lost_mask in 0u32..1 << n {
                    let lost: Vec<usize> = (0..n).filter(|i| lost_mask >> i & 1 == 1).collect();
                    let avail: Vec<usize> = (0..n).filter(|i| lost_mask >> i & 1 == 0).collect();
                    let av: Vec<bool> = (0..n).map(|i| lost_mask >> i & 1 == 0).collect();
                    let tag = format!("{k},{m},{c},{single} lost {lost:?}");
                    let ok = rank_recoverable(&s, &av);
                    assert_eq!(s.recoverable(&avail), ok, "{tag}");
                    if lost.len() < c {
                        assert!(ok, "durability {tag}");
                    }
                    let set = s.min_set(&lost, &avail);
                    assert_eq!(set.is_some(), ok, "{tag}");
                    if !ok {
                        continue;
                    }
                    let Some(set) = set else { continue };
                    assert!(set.iter().all(|i| av[*i]), "{tag}");
                    let have: Vec<(usize, &[u8])> = set.iter().map(|&i| (i, &all[i][..])).collect();
                    let mut outs = vec![vec![0u8; len]; lost.len()];
                    let mut o: Vec<&mut [u8]> = outs.iter_mut().map(|v| &mut v[..]).collect();
                    s.decode_into(&have, &lost, &mut o)
                        .unwrap_or_else(|e| panic!("{tag} {set:?} {e:?}"));
                    for (i, l) in lost.iter().enumerate() {
                        assert_eq!(outs[i], all[*l], "{tag} chunk {l}");
                    }
                }
            }
        }
    }

    #[test]
    fn partial_wants_decode() {
        // single data erasure, partial reads: want one chunk, read the minimum set, decode
        let mut seed = 99u32;
        let s = mk(6, 4, 3, false);
        let len = 32;
        let data: Vec<Vec<u8>> = (0..6)
            .map(|_| (0..len).map(|_| rnd(&mut seed)).collect())
            .collect();
        let mut all = data.clone();
        all.extend((0..4).map(|_| vec![0u8; len]));
        {
            let d: Vec<&[u8]> = data.iter().map(|v| &v[..]).collect();
            let mut p: Vec<&mut [u8]> = all[6..].iter_mut().map(|v| &mut v[..]).collect();
            s.encode(&d, &mut p);
        }
        for w in 0..10 {
            let avail: Vec<usize> = (0..10).filter(|i| *i != w).collect();
            let set = s.min_set(&[w], &avail).unwrap();
            assert!(set.len() < 6 || w >= 6, "{w}: {set:?}");
            let have: Vec<(usize, &[u8])> = set.iter().map(|&i| (i, &all[i][..])).collect();
            let mut out = vec![0u8; len];
            s.decode_into(&have, &[w], &mut [&mut out[..]]).unwrap();
            assert_eq!(out, all[w], "{w}");
        }
    }
}
