// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! jerasure reed_sol_van / reed_sol_r6_op over GF(2^16) (poly 0x1100B) and GF(2^32) (poly 0x400007), spec
//! ec-jerasure-bitmatrix.md 7. A chunk is an array of w-bit words in little-endian byte order; parity word i is
//! the XOR over data chunks j of M[r][j] * word i. Generic but matrix-sized slow field ops; the region kernels use
//! per-coefficient split tables (one 256-entry table per coefficient byte).

use crate::gf::{DecodeError, PLAN_BYTES, PLAN_COUNT};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WideKind {
    Van,
    R6,
}

/// Field of `w` bits (16 or 32): carry-less multiply with reduction by the primitive polynomial.
#[derive(Debug, Clone, Copy)]
struct Field {
    w: u32,
    /// Low bits of the polynomial (x^w term implied).
    poly: u64,
}

impl Field {
    fn new(w: u32) -> Field {
        Field {
            w,
            poly: if w == 16 { 0x100B } else { 0x40_0007 },
        }
    }
    fn mul(&self, a: u32, b: u32) -> u32 {
        let (mut a, mut b, mut r) = (u64::from(a), b, 0u64);
        let top = 1u64 << self.w;
        while b != 0 {
            if b & 1 != 0 {
                r ^= a;
            }
            b >>= 1;
            a <<= 1;
            if a & top != 0 {
                a ^= top | self.poly;
            }
        }
        r as u32
    }
    fn pow(&self, a: u32, n: u32) -> u32 {
        let mut r = 1;
        for _ in 0..n {
            r = self.mul(r, a);
        }
        r
    }
    /// a^(2^w - 2); `inv(0)` = 0.
    fn inv(&self, a: u32) -> u32 {
        let (mut r, mut sq) = (1u32, a);
        // 2^w - 2 = bits 1..w-1 all set
        for _ in 1..self.w {
            sq = self.mul(sq, sq);
            r = self.mul(r, sq);
        }
        if a == 0 { 0 } else { r }
    }
}

/// m x k jerasure coding matrix (row major).
fn coding_matrix(f: &Field, kind: WideKind, k: usize, m: usize) -> Vec<u32> {
    if kind == WideKind::R6 {
        let mut out = vec![1u32; 2 * k];
        let mut p = 1u32;
        for j in 0..k {
            out[k + j] = p;
            p = f.mul(p, 2);
        }
        return out;
    }
    let n = k + m;
    // extended Vandermonde (n x k)
    let mut v = vec![0u32; n * k];
    v[0] = 1;
    v[(n - 1) * k + (k - 1)] = 1;
    for i in 1..n - 1 {
        for j in 0..k {
            v[i * k + j] = f.pow(i as u32, j as u32);
        }
    }
    // top k rows -> identity by column operations
    for i in 1..k {
        let p = (i..n)
            .find(|&p| v[p * k + i] != 0)
            .expect("vandermonde pivot");
        if p != i {
            for c in 0..k {
                v.swap(p * k + c, i * k + c);
            }
        }
        let d = v[i * k + i];
        if d != 1 {
            let id = f.inv(d);
            for r in 0..n {
                v[r * k + i] = f.mul(v[r * k + i], id);
            }
        }
        for j in 0..k {
            let e = v[i * k + j];
            if j != i && e != 0 {
                for r in 0..n {
                    let t = f.mul(e, v[r * k + i]);
                    v[r * k + j] ^= t;
                }
            }
        }
    }
    let mut d: Vec<u32> = v[k * k..].to_vec();
    // first row all ones (scale columns), then every later row's first element 1 (scale rows)
    for j in 0..k {
        let s = f.inv(d[j]);
        if s != 1 {
            for r in 0..m {
                d[r * k + j] = f.mul(d[r * k + j], s);
            }
        }
    }
    for r in 1..m {
        let s = f.inv(d[r * k]);
        if s != 1 {
            for j in 0..k {
                d[r * k + j] = f.mul(d[r * k + j], s);
            }
        }
    }
    d
}

fn invert(f: &Field, a: &[u32], n: usize) -> Option<Vec<u32>> {
    let mut m = a.to_vec();
    let mut inv = vec![0u32; n * n];
    for i in 0..n {
        inv[i * n + i] = 1;
    }
    for c in 0..n {
        let p = (c..n).find(|&r| m[r * n + c] != 0)?;
        if p != c {
            for j in 0..n {
                m.swap(p * n + j, c * n + j);
                inv.swap(p * n + j, c * n + j);
            }
        }
        let s = f.inv(m[c * n + c]);
        for j in 0..n {
            m[c * n + j] = f.mul(m[c * n + j], s);
            inv[c * n + j] = f.mul(inv[c * n + j], s);
        }
        for r in 0..n {
            let e = m[r * n + c];
            if r != c && e != 0 {
                for j in 0..n {
                    let (x, y) = (f.mul(e, m[c * n + j]), f.mul(e, inv[c * n + j]));
                    m[r * n + j] ^= x;
                    inv[r * n + j] ^= y;
                }
            }
        }
    }
    Some(inv)
}

/// Split tables of one coefficient: `t[b][x]` = c * (x << 8b) (b < w/8).
#[derive(Debug, Clone)]
struct Tab(Vec<[u32; 256]>);

fn tab(f: &Field, c: u32) -> Tab {
    let nb = (f.w / 8) as usize;
    let mut t = vec![[0u32; 256]; nb];
    for (b, tb) in t.iter_mut().enumerate() {
        let mut basis = [0u32; 8];
        for (i, x) in basis.iter_mut().enumerate() {
            *x = f.mul(c, 1 << (8 * b + i));
        }
        for x in 1..256usize {
            let low = x.isolate_lowest_one();
            tb[x] = tb[x ^ low] ^ basis[low.trailing_zeros() as usize];
        }
    }
    Tab(t)
}

#[expect(clippy::chunks_exact_to_as_chunks)]
fn acc(dst: &mut [u8], src: &[u8], c: u32, t: &Tab, w: u32) {
    match c {
        0 => {}
        1 => dst.iter_mut().zip(src).for_each(|(d, s)| *d ^= *s),
        _ if w == 16 => {
            for (d, s) in dst.chunks_exact_mut(2).zip(src.chunks_exact(2)) {
                let v = t.0[0][s[0] as usize] ^ t.0[1][s[1] as usize];
                d[0] ^= v as u8;
                d[1] ^= (v >> 8) as u8;
            }
        }
        _ => {
            for (d, s) in dst.chunks_exact_mut(4).zip(src.chunks_exact(4)) {
                let v = t.0[0][s[0] as usize]
                    ^ t.0[1][s[1] as usize]
                    ^ t.0[2][s[2] as usize]
                    ^ t.0[3][s[3] as usize];
                for (i, b) in d.iter_mut().enumerate() {
                    *b ^= (v >> (8 * i)) as u8;
                }
            }
        }
    }
}

/// jerasure reed_sol_van / r6_op, w = 16 or 32.
#[derive(Debug, Clone)]
pub struct WideCodec {
    f: Field,
    kind: WideKind,
    k: usize,
    m: usize,
    mat: Vec<u32>,
    tabs: Vec<Tab>,
}

impl WideCodec {
    /// `None` unless w in {16, 32}, k >= 1, m >= 1, k + m <= 127 (r6: m == 2).
    pub fn try_new(kind: WideKind, k: usize, m: usize, w: u32) -> Option<WideCodec> {
        if !matches!(w, 16 | 32)
            || k == 0
            || m == 0
            || k + m > 127
            || (kind == WideKind::R6 && m != 2)
        {
            return None;
        }
        let f = Field::new(w);
        let mat = coding_matrix(&f, kind, k, m);
        let tabs = mat.iter().map(|&c| tab(&f, c)).collect();
        Some(WideCodec {
            f,
            kind,
            k,
            m,
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
    /// Region lengths must be a multiple of this (bytes per word).
    pub fn unit(&self) -> usize {
        (self.f.w / 8) as usize
    }

    pub fn encode(&self, data: &[&[u8]], parity: &mut [&mut [u8]]) {
        assert_eq!(data.len(), self.k);
        assert_eq!(parity.len(), self.m);
        for (r, p) in parity.iter_mut().enumerate() {
            p.fill(0);
            for (j, d) in data.iter().enumerate() {
                let i = r * self.k + j;
                acc(p, d, self.mat[i], &self.tabs[i], self.f.w);
            }
        }
    }

    /// Generator row of raw chunk `raw` (identity for data, matrix row for parity).
    fn gen_row(&self, raw: usize, out: &mut [u32]) {
        out.fill(0);
        if raw < self.k {
            out[raw] = 1;
        } else {
            out.copy_from_slice(&self.mat[(raw - self.k) * self.k..(raw - self.k + 1) * self.k]);
        }
    }

    /// Decode coefficients of `want` over `have` (exactly k distinct raw indexes) and their split tables.
    fn plan(&self, have: &[(usize, &[u8])], want: &[usize]) -> Result<Plan, DecodeError> {
        let k = self.k;
        let mut sub = vec![0u32; k * k];
        for (i, h) in have.iter().enumerate() {
            self.gen_row(h.0, &mut sub[i * k..(i + 1) * k]);
        }
        let inv = invert(&self.f, &sub, k).ok_or(DecodeError::Unrecoverable)?;
        let mut coef = vec![0u32; want.len() * k];
        let mut g = vec![0u32; k];
        for (wi, &raw) in want.iter().enumerate() {
            self.gen_row(raw, &mut g);
            for j in 0..k {
                let mut c = 0;
                for t in 0..k {
                    c ^= self.f.mul(g[t], inv[t * k + j]);
                }
                coef[wi * k + j] = c;
            }
        }
        let tabs = coef.iter().map(|&c| tab(&self.f, c)).collect();
        Ok(Plan {
            kind: self.kind,
            k: self.k,
            m: self.m,
            w: self.f.w,
            have: have.iter().map(|h| h.0).collect(),
            want: want.to_vec(),
            coef,
            tabs,
        })
    }

    fn decode_with(&self, plan: &Plan, have: &[(usize, &[u8])], out: &mut [&mut [u8]]) {
        let k = self.k;
        for (wi, o) in out.iter_mut().enumerate() {
            o.fill(0);
            for (j, (_, src)) in have.iter().enumerate() {
                let i = wi * k + j;
                acc(o, src, plan.coef[i], &plan.tabs[i], plan.w);
            }
        }
    }

    pub fn decode_into(
        &self,
        have: &[(usize, &[u8])],
        want: &[usize],
        out: &mut [&mut [u8]],
    ) -> Result<(), DecodeError> {
        let (k, w) = (self.k, self.f.w);
        if have.len() != k || out.len() != want.len() {
            return Err(DecodeError::Unrecoverable);
        }
        let len = have[0].1.len();
        if have.iter().any(|h| h.1.len() != len)
            || out.iter().any(|o| o.len() != len)
            || !len.is_multiple_of(self.unit())
        {
            return Err(DecodeError::BadLen);
        }
        // out-of-range survivors/wants cannot be rebuilt; duplicate survivors make the survivor matrix singular,
        // which the plan build reports
        if have.iter().any(|h| h.0 >= k + self.m) || want.iter().any(|&w| w >= k + self.m) {
            return Err(DecodeError::Unrecoverable);
        }
        // the coefficient matrix depends only on (have, want): reuse it (incl. the split tables)
        if Plan::bytes(k, want.len(), w) > PLAN_BYTES {
            let plan = self.plan(have, want)?;
            self.decode_with(&plan, have, out);
            return Ok(());
        }
        DECODE_PLANS.with(|cache| {
            let mut cache = cache.borrow_mut();
            if let Some(i) = cache.plans.iter().position(|p| p.matches(self, have, want)) {
                let plan = cache.plans.remove(i);
                cache.plans.push(plan);
            } else {
                let plan = self.plan(have, want)?;
                let bytes = Plan::bytes(k, want.len(), w);
                while cache.plans.len() == PLAN_COUNT || cache.bytes + bytes > PLAN_BYTES {
                    let evicted = cache.plans.remove(0);
                    cache.bytes -= evicted.bytes_now();
                }
                cache.bytes += bytes;
                cache.plans.push(plan);
            }
            self.decode_with(cache.plans.last().unwrap(), have, out);
            Ok(())
        })
    }
}

/// Cached decode plan of one `(have, want)` pair of a [`WideCodec`] (clone-free rebuild of the survivor inverse).
struct Plan {
    kind: WideKind,
    k: usize,
    m: usize,
    w: u32,
    have: Vec<usize>,
    want: Vec<usize>,
    /// `want.len() x k` coefficients over the survivors (`have` order).
    coef: Vec<u32>,
    /// One split table per coefficient, same order as `coef`.
    tabs: Vec<Tab>,
}

impl Plan {
    fn matches(&self, c: &WideCodec, have: &[(usize, &[u8])], want: &[usize]) -> bool {
        self.kind == c.kind
            && self.k == c.k
            && self.m == c.m
            && self.w == c.f.w
            && self.want == want
            && self.have.len() == have.len()
            && self.have.iter().zip(have).all(|(&a, b)| a == b.0)
    }

    fn bytes(k: usize, want: usize, w: u32) -> usize {
        let tab = (w as usize / 8) * 256 * std::mem::size_of::<u32>();
        k.saturating_add(want)
            .saturating_mul(std::mem::size_of::<usize>())
            .saturating_add(
                k.saturating_mul(want)
                    .saturating_mul(std::mem::size_of::<u32>() + tab),
            )
    }

    fn bytes_now(&self) -> usize {
        Plan::bytes(self.k, self.want.len(), self.w)
    }
}

struct Plans {
    plans: Vec<Plan>,
    bytes: usize,
}

thread_local! {
    static DECODE_PLANS: std::cell::RefCell<Plans> = std::cell::RefCell::new(Plans {
        plans: Vec::with_capacity(PLAN_COUNT), bytes: 0,
    });
}
