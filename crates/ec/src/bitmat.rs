// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Jerasure bit-matrix codes (cauchy_orig, cauchy_good, liberation, blaum_roth, liber8tion), spec ec.md 4.3.3 and
//! ec-jerasure-bitmatrix.md. A chunk is a sequence of superblocks of `w * packetsize` bytes (w packets); parity packet
//! (r, l) of a superblock is the XOR of the data packets (j, x) selected by bit `B[r*w+l][j*w+x]`. Pure XOR, every byte
//! depends only on the same offset within its packet. Decode is generic GF(2) elimination: for an MDS code the answer
//! is unique, so only the encode matrix has to match the plugin.

use crate::gf::{DecodeError, PLAN_BYTES, PLAN_COUNT};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitTech {
    CauchyOrig,
    CauchyGood,
    Liberation,
    BlaumRoth,
    Liber8tion,
}

impl BitTech {
    pub fn parse(s: &str) -> Option<BitTech> {
        Some(match s {
            "cauchy_orig" => BitTech::CauchyOrig,
            "cauchy_good" => BitTech::CauchyGood,
            "liberation" => BitTech::Liberation,
            "blaum_roth" => BitTech::BlaumRoth,
            "liber8tion" => BitTech::Liber8tion,
            _ => return None,
        })
    }
}

/// GF(2^w) for matrix construction only (slow bitwise arithmetic, never on a data path).
#[derive(Clone, Copy, Debug)]
pub struct Field {
    pub w: u32,
    /// Reduction polynomial without the leading x^w term.
    low: u64,
}

impl Field {
    /// Primitive polynomials of the plugin (low bits, leading term implicit).
    pub fn new(w: u32) -> Option<Field> {
        let full: u64 = match w {
            2 => 0x7,
            3 => 0xB,
            4 => 0x13,
            5 => 0x25,
            6 => 0x43,
            7 => 0x89,
            8 => 0x11D,
            9 => 0x211,
            10 => 0x409,
            11 => 0x805,
            12 => 0x1053,
            13 => 0x201B,
            14 => 0x4443,
            15 => 0x8003,
            16 => 0x1100B,
            17 => 0x20009,
            18 => 0x40081,
            19 => 0x80027,
            20 => 0x100009,
            21 => 0x200005,
            22 => 0x400003,
            23 => 0x800021,
            24 => 0x1000087,
            25 => 0x2000009,
            26 => 0x4000047,
            27 => 0x8000027,
            28 => 0x10000009,
            29 => 0x20000005,
            30 => 0x40800007,
            31 => 0x80000009,
            32 => 0x1_0040_0007,
            _ => return None,
        };
        Some(Field {
            w,
            low: full & ((1u64 << w) - 1),
        })
    }
    pub fn mul(&self, a: u64, b: u64) -> u64 {
        let (mut a, mut b, mut r) = (a, b, 0u64);
        let top = 1u64 << (self.w - 1);
        while b != 0 {
            if b & 1 == 1 {
                r ^= a;
            }
            let carry = a & top != 0;
            a = (a << 1) & ((1u64 << self.w) - 1);
            if carry {
                a ^= self.low;
            }
            b >>= 1;
        }
        r
    }
    pub fn inv(&self, a: u64) -> u64 {
        // a^(2^w - 2)
        let (mut r, mut base, mut e) = (1u64, a, (1u64 << self.w) - 2);
        while e != 0 {
            if e & 1 == 1 {
                r = self.mul(r, base);
            }
            base = self.mul(base, base);
            e >>= 1;
        }
        r
    }
    /// Ones in the w x w bit matrix of `n` (column x = bits of n * 2^x).
    pub fn ones(&self, n: u64) -> u32 {
        let (mut t, mut c) = (n, 0);
        for _ in 0..self.w {
            c += t.count_ones();
            t = self.mul(t, 2);
        }
        c
    }
}

/// m x k matrix over GF(2^w) of cauchy_orig.
fn cauchy_orig(f: &Field, k: usize, m: usize) -> Vec<u64> {
    let mut out = vec![0u64; m * k];
    for i in 0..m {
        for j in 0..k {
            out[i * k + j] = f.inv((i ^ (m + j)) as u64);
        }
    }
    out
}

/// cauchy_good: cauchy_orig improved to have few ones (spec 4.3.3).
fn cauchy_good(f: &Field, k: usize, m: usize) -> Vec<u64> {
    // m == 2 table path of the library: list of all nonzero elements by (ones, value), exists for w 2..=11
    if m == 2 && k <= cauchy_maxk(f.w as usize) {
        let mut all: Vec<u64> = (1..1u64 << f.w).collect();
        all.sort_by_key(|n| (f.ones(*n), *n));
        let mut out = vec![1u64; 2 * k];
        out[k..].copy_from_slice(&all[..k]);
        return out;
    }
    let mut mat = cauchy_orig(f, k, m);
    for j in 0..k {
        let s = f.inv(mat[j]);
        for i in 0..m {
            mat[i * k + j] = f.mul(mat[i * k + j], s);
        }
    }
    for i in 1..m {
        let row = i * k;
        let mut bno: u32 = (0..k).map(|j| f.ones(mat[row + j])).sum();
        let mut best: Option<usize> = None;
        for j in 0..k {
            if mat[row + j] == 1 {
                continue;
            }
            let s = f.inv(mat[row + j]);
            let tno: u32 = (0..k).map(|x| f.ones(f.mul(mat[row + x], s))).sum();
            if tno < bno {
                bno = tno;
                best = Some(j);
            }
        }
        if let Some(j) = best {
            let s = f.inv(mat[row + j]);
            for x in 0..k {
                mat[row + x] = f.mul(mat[row + x], s);
            }
        }
    }
    mat
}

/// Expand an m x k GF matrix into the (m*w) x (k*w) bit matrix, row-major, one byte per bit.
fn expand(f: &Field, mat: &[u64], k: usize, m: usize) -> Vec<Vec<bool>> {
    let w = f.w as usize;
    let mut b = vec![vec![false; k * w]; m * w];
    for r in 0..m {
        for j in 0..k {
            let mut e = mat[r * k + j];
            for x in 0..w {
                for l in 0..w {
                    b[r * w + l][j * w + x] = e >> l & 1 == 1;
                }
                e = f.mul(e, 2);
            }
        }
    }
    b
}

/// P row = identities, Q row = the supplied w x w blocks (block j for data chunk j).
fn raid6(k: usize, m: usize, w: usize, q: impl Fn(usize) -> Vec<Vec<bool>>) -> Vec<Vec<bool>> {
    let mut b = vec![vec![false; k * w]; m * w];
    for j in 0..k {
        for l in 0..w {
            b[l][j * w + l] = true;
        }
        if m < 2 {
            continue;
        }
        let blk = q(j);
        for l in 0..w {
            for x in 0..w {
                b[w + l][j * w + x] = blk[l][x];
            }
        }
    }
    b
}

fn liberation_block(w: usize, j: usize) -> Vec<Vec<bool>> {
    let mut blk = vec![vec![false; w]; w];
    for (l, row) in blk.iter_mut().enumerate() {
        row[(j + l) % w] = true;
    }
    if j > 0 {
        let i = (j * ((w - 1) / 2)) % w;
        blk[i][(i + j - 1) % w] = true;
    }
    blk
}

fn blaum_roth_block(w: usize, j: usize) -> Vec<Vec<bool>> {
    let p = w + 1;
    let mut blk = vec![vec![false; w]; w];
    if j == 0 {
        for (l, row) in blk.iter_mut().enumerate() {
            row[l] = true;
        }
        return blk;
    }
    for l in 1..=w {
        if l != p - j {
            blk[l - 1][(l + j) % p - 1] = true;
        } else {
            blk[l - 1][j - 1] = true;
            let c = if j.is_multiple_of(2) {
                j / 2
            } else {
                p / 2 + 1 + j / 2
            };
            blk[l - 1][c - 1] = true;
        }
    }
    blk
}

/// Largest k the m == 2 best-list table of the library covers for field width `w` (0 = no table).
fn cauchy_maxk(w: usize) -> usize {
    match w {
        2..=10 => (1usize << w) - 1,
        11 => 1023,
        _ => 0,
    }
}

/// liber8tion Q block j (w = 8): fixed constants (spec ec-jerasure-bitmatrix.md 4): a permutation plus one extra one.
fn liber8tion_block(j: usize) -> Vec<Vec<bool>> {
    // (row, col) pairs, row-ordered permutation; `EXTRA[j]` = the additional one
    const PERM: [[u8; 8]; 8] = [
        [0, 1, 2, 3, 4, 5, 6, 7],
        [7, 3, 0, 2, 6, 1, 5, 4],
        [6, 2, 4, 0, 7, 3, 1, 5],
        [2, 5, 7, 6, 0, 3, 4, 1],
        [5, 6, 1, 7, 2, 4, 3, 0],
        [1, 2, 3, 4, 5, 6, 7, 0],
        [3, 0, 6, 5, 1, 7, 4, 2],
        [4, 7, 1, 5, 3, 2, 0, 6],
    ];
    const EXTRA: [Option<(usize, usize)>; 8] = [
        None,
        Some((4, 7)),
        Some((1, 3)),
        Some((5, 4)),
        Some((2, 0)),
        Some((7, 2)),
        Some((6, 5)),
        Some((3, 1)),
    ];
    let mut blk = vec![vec![false; 8]; 8];
    for (r, row) in blk.iter_mut().enumerate() {
        row[PERM[j][r] as usize] = true;
    }
    if let Some((r, c)) = EXTRA[j] {
        blk[r][c] = true;
    }
    blk
}

fn is_prime(n: usize) -> bool {
    n >= 2
        && (2..n)
            .take_while(|d| d * d <= n)
            .all(|d| !n.is_multiple_of(d))
}

#[derive(Clone, Debug)]
pub struct BitCodec {
    tech: BitTech,
    mds: bool,
    k: usize,
    m: usize,
    w: usize,
    ps: usize,
    /// per parity packet row (m*w): data packet indices (j*w + x) to XOR.
    enc: Vec<Vec<u16>>,
    /// full bit matrix (m*w) x (k*w), rows as bit sets (words of u64) for decode.
    bm: Vec<Vec<u64>>,
}

fn words(n: usize) -> usize {
    n.div_ceil(64)
}

fn xor_into(dst: &mut [u8], src: &[u8]) {
    dst.iter_mut().zip(src).for_each(|(d, s)| *d ^= *s);
}

impl BitCodec {
    /// `None` for parameters the plugin rejects (k, m, w, packetsize out of range for the technique).
    pub fn try_new(tech: BitTech, k: usize, m: usize, w: usize, ps: usize) -> Option<BitCodec> {
        if k == 0 || m == 0 || ps == 0 || k * w > u16::MAX as usize {
            return None;
        }
        let bits = match tech {
            BitTech::CauchyOrig | BitTech::CauchyGood => {
                let f = Field::new(w as u32)?;
                let table_path = tech == BitTech::CauchyGood && m == 2 && k <= cauchy_maxk(w);
                if k + m > 1usize << w.min(30) && !table_path {
                    return None;
                }
                let mat = if tech == BitTech::CauchyOrig {
                    cauchy_orig(&f, k, m)
                } else {
                    cauchy_good(&f, k, m)
                };
                expand(&f, &mat, k, m)
            }
            BitTech::Liberation => {
                if m > 2 || k > w || w <= 2 || w > 257 || !is_prime(w) {
                    return None;
                }
                raid6(k, m, w, |j| liberation_block(w, j))
            }
            BitTech::BlaumRoth => {
                if m > 2 || k > w || w <= 2 || w + 1 > 257 || (!is_prime(w + 1) && w != 7) {
                    return None;
                }
                raid6(k, m, w, |j| blaum_roth_block(w, j))
            }
            BitTech::Liber8tion => {
                if m != 2 || w != 8 || k > 8 {
                    return None;
                }
                raid6(k, m, w, liber8tion_block)
            }
        };
        let enc = bits
            .iter()
            .map(|row| {
                row.iter()
                    .enumerate()
                    .filter(|(_, b)| **b)
                    .map(|(i, _)| i as u16)
                    .collect()
            })
            .collect();
        let bm = bits
            .iter()
            .map(|row| {
                let mut v = vec![0u64; words(k * w)];
                for (i, b) in row.iter().enumerate() {
                    if *b {
                        v[i / 64] |= 1 << (i % 64);
                    }
                }
                v
            })
            .collect();
        Some(BitCodec {
            tech,
            mds: !(tech == BitTech::BlaumRoth && !is_prime(w + 1)),
            k,
            m,
            w,
            ps,
            enc,
            bm,
        })
    }

    pub fn k(&self) -> usize {
        self.k
    }
    /// Any k chunks decode (false for the tolerated blaum_roth w=7: only some k-sets do).
    pub fn is_mds(&self) -> bool {
        self.mds
    }
    pub fn m(&self) -> usize {
        self.m
    }
    /// Chunk lengths must be a multiple of this (one superblock).
    pub fn unit(&self) -> usize {
        self.w * self.ps
    }

    /// Parity chunks from the data chunks (all the same length, a multiple of [`unit`](Self::unit)).
    pub fn encode(&self, data: &[&[u8]], parity: &mut [&mut [u8]]) {
        assert_eq!(data.len(), self.k);
        assert_eq!(parity.len(), self.m);
        let (w, ps) = (self.w, self.ps);
        let sb = w * ps;
        let len = data.first().map_or(0, |d| d.len());
        assert!(len.is_multiple_of(sb));
        for (r, srcs) in self.enc.iter().enumerate() {
            let (pc, pl) = (r / w, r % w);
            let mut off = 0;
            while off < len {
                let dst = &mut parity[pc][off + pl * ps..off + (pl + 1) * ps];
                dst.fill(0);
                for &s in srcs {
                    let (dj, dx) = (s as usize / w, s as usize % w);
                    xor_into(dst, &data[dj][off + dx * ps..off + (dx + 1) * ps]);
                }
                off += sb;
            }
        }
    }

    /// Inverse of the survivors' generator (rows = survivor packets) as bit rows over the augmented columns;
    /// `None` when the survivors do not determine the data (singular).
    fn survivors_inverse(&self, have: &[usize]) -> Option<Vec<Vec<u64>>> {
        let (k, w) = (self.k, self.w);
        let kw = k * w;
        let nw = words(kw);
        let mut a: Vec<Vec<u64>> = Vec::with_capacity(kw);
        for (si, raw) in have.iter().enumerate() {
            for l in 0..w {
                let mut row = self.gen_row(*raw, l);
                row.resize(nw + words(kw), 0);
                let idx = si * w + l;
                row[nw + idx / 64] |= 1 << (idx % 64);
                a.push(row);
            }
        }
        for c in 0..kw {
            let p = (c..kw).find(|&p| a[p][c / 64] >> (c % 64) & 1 == 1)?;
            a.swap(p, c);
            let pivot = a[c].clone();
            for (y, row) in a.iter_mut().enumerate() {
                if y != c && row[c / 64] >> (c % 64) & 1 == 1 {
                    row.iter_mut().zip(&pivot).for_each(|(d, s)| *d ^= *s);
                }
            }
        }
        Some(a.into_iter().map(|r| r[nw..].to_vec()).collect())
    }

    /// Generator row (kw bits) of packet `l` of raw chunk `raw`.
    fn gen_row(&self, raw: usize, l: usize) -> Vec<u64> {
        if raw < self.k {
            let mut v = vec![0u64; words(self.k * self.w)];
            let i = raw * self.w + l;
            v[i / 64] |= 1 << (i % 64);
            v
        } else {
            self.bm[(raw - self.k) * self.w + l].clone()
        }
    }

    /// Decode plan: one survivor packet list per wanted packet (want order, then packet 0..w).
    fn plan(&self, have: Have<'_>, want: &[usize]) -> Result<Plan, DecodeError> {
        let (k, w) = (self.k, self.w);
        let kw = k * w;
        let raws: Vec<usize> = (0..have.len()).map(|i| have.get(i)).collect();
        // inv[i] = row i of G_S^-1: data packet i = XOR of the survivor packets with a set bit
        let inv = self
            .survivors_inverse(&raws)
            .ok_or(DecodeError::Unrecoverable)?;
        let mut plans = Vec::with_capacity(want.len() * w);
        for &raw in want {
            for l in 0..w {
                let g = self.gen_row(raw, l);
                let mut comb = vec![0u64; words(kw)];
                for i in 0..kw {
                    if g[i / 64] >> (i % 64) & 1 == 1 {
                        comb.iter_mut().zip(&inv[i]).for_each(|(d, s)| *d ^= *s);
                    }
                }
                plans.push(
                    (0..kw)
                        .filter(|i| comb[i / 64] >> (i % 64) & 1 == 1)
                        .map(|i| i as u16)
                        .collect(),
                );
            }
        }
        Ok(Plan {
            tech: self.tech,
            k: self.k,
            m: self.m,
            w,
            have: raws,
            want: want.to_vec(),
            plans,
        })
    }

    fn decode_with(&self, plan: &Plan, have: &[(usize, &[u8])], out: &mut [&mut [u8]]) {
        let (w, ps) = (self.w, self.ps);
        let sb = w * ps;
        let len = have[0].1.len();
        for (wi, o) in out.iter_mut().enumerate() {
            for l in 0..w {
                let srcs = &plan.plans[wi * w + l];
                let mut off = 0;
                while off < len {
                    let dst = &mut o[off + l * ps..off + (l + 1) * ps];
                    dst.fill(0);
                    for &s in srcs {
                        let (sj, sx) = (s as usize / w, s as usize % w);
                        xor_into(dst, &have[sj].1[off + sx * ps..off + (sx + 1) * ps]);
                    }
                    off += sb;
                }
            }
        }
    }

    /// Do exactly these k distinct chunks determine all data (always true for an MDS code)?
    pub fn decodable(&self, have: &[usize]) -> bool {
        if have.len() != self.k || have.iter().any(|&r| r >= self.k + self.m) {
            return false;
        }
        // a plan without wanted chunks is the elimination test: cached like every other plan
        DECODE_PLANS.with(|cache| cache.borrow_mut().get(self, Have::Idx(have), &[]).is_ok())
    }

    /// Rebuild the raw chunks `want` from exactly k distinct surviving chunks `have = (raw, bytes)`.
    pub fn decode_into(
        &self,
        have: &[(usize, &[u8])],
        want: &[usize],
        out: &mut [&mut [u8]],
    ) -> Result<(), DecodeError> {
        let k = self.k;
        if have.len() != k || out.len() != want.len() {
            return Err(DecodeError::Unrecoverable);
        }
        let len = have[0].1.len();
        if have.iter().any(|h| h.1.len() != len)
            || out.iter().any(|o| o.len() != len)
            || !len.is_multiple_of(self.w * self.ps)
        {
            return Err(DecodeError::BadLen);
        }
        // out-of-range survivors/wants cannot be rebuilt; duplicate survivors make the survivor matrix singular,
        // which the plan build reports
        if have.iter().any(|h| h.0 >= k + self.m) || want.iter().any(|&r| r >= k + self.m) {
            return Err(DecodeError::Unrecoverable);
        }
        // the XOR plan depends only on (have, want): reuse it
        if Plan::bytes(k, want.len(), self.w) > PLAN_BYTES {
            let plan = self.plan(Have::Slices(have), want)?;
            self.decode_with(&plan, have, out);
            return Ok(());
        }
        DECODE_PLANS.with(|cache| {
            let mut cache = cache.borrow_mut();
            let i = cache.get(self, Have::Slices(have), want)?;
            self.decode_with(&cache.plans[i], have, out);
            Ok(())
        })
    }
}

/// The survivors of a decode, as slices (decode) or raw indexes only (feasibility test).
#[derive(Clone, Copy)]
enum Have<'a> {
    Slices(&'a [(usize, &'a [u8])]),
    Idx(&'a [usize]),
}

impl Have<'_> {
    fn len(&self) -> usize {
        match self {
            Have::Slices(h) => h.len(),
            Have::Idx(h) => h.len(),
        }
    }
    fn get(&self, i: usize) -> usize {
        match self {
            Have::Slices(h) => h[i].0,
            Have::Idx(h) => h[i],
        }
    }
}

/// Cached decode plan of one `(have, want)` pair of a [`BitCodec`].
struct Plan {
    tech: BitTech,
    k: usize,
    m: usize,
    w: usize,
    have: Vec<usize>,
    want: Vec<usize>,
    /// Survivor packet indexes (`j*w + x`) per wanted packet.
    plans: Vec<Vec<u16>>,
}

impl Plan {
    fn matches(&self, c: &BitCodec, have: Have<'_>, want: &[usize]) -> bool {
        self.tech == c.tech
            && self.k == c.k
            && self.m == c.m
            && self.w == c.w
            && self.want == want
            && self.have.len() == have.len()
            && self.have.iter().enumerate().all(|(i, &a)| a == have.get(i))
    }

    fn bytes(k: usize, want: usize, w: usize) -> usize {
        // key + one survivor list of at most k*w u16 per wanted packet
        k.saturating_add(want)
            .saturating_mul(std::mem::size_of::<usize>())
            .saturating_add(want.saturating_mul(w).saturating_mul(k * w * 2))
    }

    fn bytes_now(&self) -> usize {
        Plan::bytes(self.k, self.want.len(), self.w)
    }
}

struct Plans {
    plans: Vec<Plan>,
    bytes: usize,
}

impl Plans {
    /// Index of the plan for `(codec, have, want)`, built on first use (LRU order, bounded size).
    fn get(&mut self, c: &BitCodec, have: Have<'_>, want: &[usize]) -> Result<usize, DecodeError> {
        if let Some(i) = self.plans.iter().position(|p| p.matches(c, have, want)) {
            let plan = self.plans.remove(i);
            self.plans.push(plan);
        } else {
            let plan = c.plan(have, want)?;
            let bytes = Plan::bytes(c.k, want.len(), c.w);
            while self.plans.len() == PLAN_COUNT || self.bytes + bytes > PLAN_BYTES {
                let evicted = self.plans.remove(0);
                self.bytes -= evicted.bytes_now();
            }
            self.bytes += bytes;
            self.plans.push(plan);
        }
        Ok(self.plans.len() - 1)
    }
}

thread_local! {
    static DECODE_PLANS: std::cell::RefCell<Plans> = std::cell::RefCell::new(Plans {
        plans: Vec::with_capacity(PLAN_COUNT), bytes: 0,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(n: usize, seed: u32) -> Vec<u8> {
        let mut x = seed.wrapping_mul(2654435761).wrapping_add(1);
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                (x >> 8) as u8
            })
            .collect()
    }

    #[test]
    fn matrices_known() {
        let f = Field::new(8).unwrap();
        assert_eq!(cauchy_orig(&f, 2, 2), [0x8E, 0xF4, 0xF4, 0x8E]);
        assert_eq!(
            cauchy_orig(&f, 4, 2),
            [0x8E, 0xF4, 0x47, 0xA7, 0xF4, 0x8E, 0xA7, 0x47]
        );
        assert_eq!(cauchy_good(&f, 4, 2), [1, 1, 1, 1, 1, 2, 0x8E, 4]);
        let g = cauchy_good(&f, 8, 3);
        assert_eq!(g[8..16], [1, 0xC4, 0x8F, 0xD2, 0x52, 0xE8, 0xC8, 0xEE]);
        assert_eq!(g[16..], [0xCA, 0x8F, 0x72, 0x65, 0xC8, 0x01, 0x27, 0xD9]);
        assert_eq!(f.ones(1), 8);
        assert_eq!(f.ones(2), 11);
    }

    #[test]
    fn field_matches_gf256() {
        let f = Field::new(8).unwrap();
        for a in 0..=255u8 {
            for b in [0u8, 1, 2, 3, 0x1D, 0x80, 0xFF] {
                assert_eq!(f.mul(a as u64, b as u64), crate::gf::mul(a, b) as u64);
            }
            if a != 0 {
                assert_eq!(f.inv(a as u64), crate::gf::inv(a) as u64);
            }
        }
    }

    /// Every erasure pattern of m losses decodes back, all techniques (blaum_roth only for MDS w=6).
    #[test]
    fn decode_all_erasure_patterns() {
        let cases = [
            (BitTech::CauchyOrig, 3, 2, 8),
            (BitTech::CauchyOrig, 4, 3, 8),
            (BitTech::CauchyGood, 4, 3, 8),
            (BitTech::CauchyGood, 5, 2, 4),
            (BitTech::Liberation, 5, 2, 7),
            (BitTech::BlaumRoth, 5, 2, 6),
        ];
        for (tech, k, m, w) in cases {
            let ps = 8;
            let c = BitCodec::try_new(tech, k, m, w, ps).unwrap();
            let len = w * ps * 3;
            let data: Vec<Vec<u8>> = (0..k).map(|i| pattern(len, i as u32 + 3)).collect();
            let mut par = vec![vec![0u8; len]; m];
            {
                let d: Vec<&[u8]> = data.iter().map(|v| &v[..]).collect();
                let mut p: Vec<&mut [u8]> = par.iter_mut().map(|v| &mut v[..]).collect();
                c.encode(&d, &mut p);
            }
            let all: Vec<Vec<u8>> = data.iter().chain(par.iter()).cloned().collect();
            let n = k + m;
            for mask in 0u32..(1 << n) {
                if mask.count_ones() as usize != m {
                    continue;
                }
                let lost: Vec<usize> = (0..n).filter(|i| mask >> i & 1 == 1).collect();
                let have: Vec<(usize, &[u8])> = (0..n)
                    .filter(|i| mask >> i & 1 == 0)
                    .take(k)
                    .map(|i| (i, &all[i][..]))
                    .collect();
                let mut outs = vec![vec![0u8; len]; lost.len()];
                let mut o: Vec<&mut [u8]> = outs.iter_mut().map(|v| &mut v[..]).collect();
                c.decode_into(&have, &lost, &mut o).unwrap();
                for (i, l) in lost.iter().enumerate() {
                    assert_eq!(outs[i], all[*l], "{tech:?} k{k} m{m} w{w} lost {lost:?}");
                }
            }
        }
    }

    #[test]
    fn parameter_limits() {
        assert!(BitCodec::try_new(BitTech::Liberation, 8, 2, 7, 8).is_none()); // k > w
        assert!(BitCodec::try_new(BitTech::Liberation, 3, 2, 8, 8).is_none()); // w not prime
        assert!(BitCodec::try_new(BitTech::Liberation, 3, 3, 7, 8).is_none()); // m != 2
        assert!(BitCodec::try_new(BitTech::BlaumRoth, 3, 2, 8, 8).is_none()); // w+1 = 9
        assert!(BitCodec::try_new(BitTech::BlaumRoth, 3, 2, 7, 8).is_some()); // tolerated
        assert!(BitCodec::try_new(BitTech::CauchyGood, 3, 2, 8, 6).is_some());
        assert!(BitCodec::try_new(BitTech::CauchyGood, 3, 2, 8, 0).is_none());
    }
}
