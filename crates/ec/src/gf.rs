// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! GF(2^8) (poly 0x11D) arithmetic, generator matrices and region kernels (spec ec.md 4.1-4.5, adr 0048).
//!
//! Sans-IO, no allocation in the region loops. A [`Codec`] is built once per pool (matrix + per-coefficient nibble
//! tables); `encode` / `decode_into` only run kernels over caller buffers.

const POLY: u16 = 0x11D;

const fn build_tables() -> ([u8; 512], [u8; 256]) {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    let mut i = 0;
    while i < 255 {
        exp[i] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= POLY;
        }
        i += 1;
    }
    let mut j = 255;
    while j < 512 {
        exp[j] = exp[j - 255];
        j += 1;
    }
    (exp, log)
}
static TABLES: ([u8; 512], [u8; 256]) = build_tables();

#[inline]
pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    TABLES.0[TABLES.1[a as usize] as usize + TABLES.1[b as usize] as usize]
}

/// Multiplicative inverse; `inv(0)` = 0 (callers never ask).
#[inline]
pub fn inv(a: u8) -> u8 {
    if a == 0 {
        0
    } else {
        TABLES.0[255 - TABLES.1[a as usize] as usize]
    }
}

/// `a^n` in the field (`0^0` = 1).
pub fn pow(a: u8, n: u32) -> u8 {
    if n == 0 {
        return 1;
    }
    if a == 0 {
        return 0;
    }
    TABLES.0[(TABLES.1[a as usize] as u64 * u64::from(n) % 255) as usize]
}

/// How the coding matrix is built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// isa reed_sol_van (row r, col j = 2^(r*j)); falls back to cauchy for m > 4 or m == 4 && k > 21.
    IsaVan,
    /// isa cauchy (row r, col j = inv((k+r) ^ j)).
    IsaCauchy,
    /// jerasure reed_sol_van w=8 (extended Vandermonde, column-reduced, ec.md 4.3.1).
    JerVan,
}

/// m x k coding matrix, row major. `m == 1` is plain XOR for every kind (ec.md 4.2).
pub fn coding_matrix(kind: Kind, k: usize, m: usize) -> Vec<u8> {
    if m == 1 {
        return vec![1; k];
    }
    let kind = match kind {
        Kind::IsaVan if m > 4 || (m == 4 && k > 21) => Kind::IsaCauchy,
        o => o,
    };
    let mut out = vec![0u8; m * k];
    match kind {
        Kind::IsaVan => {
            for r in 0..m {
                for j in 0..k {
                    out[r * k + j] = pow(2, (r * j) as u32);
                }
            }
        }
        Kind::IsaCauchy => {
            for r in 0..m {
                for j in 0..k {
                    out[r * k + j] = inv(((k + r) ^ j) as u8);
                }
            }
        }
        Kind::JerVan => return jerasure_van(k, m),
    }
    out
}

fn jerasure_van(k: usize, m: usize) -> Vec<u8> {
    let n = k + m;
    // extended Vandermonde (n x k)
    let mut v = vec![0u8; n * k];
    v[0] = 1;
    v[(n - 1) * k + (k - 1)] = 1;
    for i in 1..n - 1 {
        for j in 0..k {
            v[i * k + j] = pow(i as u8, j as u32);
        }
    }
    // make the top k rows the identity with column operations
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
            let id = inv(d);
            for r in 0..n {
                v[r * k + i] = mul(v[r * k + i], id);
            }
        }
        for j in 0..k {
            let e = v[i * k + j];
            if j != i && e != 0 {
                for r in 0..n {
                    let t = mul(e, v[r * k + i]);
                    v[r * k + j] ^= t;
                }
            }
        }
    }
    let mut d: Vec<u8> = v[k * k..].to_vec();
    for j in 0..k {
        let s = inv(d[j]);
        if s != 1 {
            for r in 0..m {
                d[r * k + j] = mul(d[r * k + j], s);
            }
        }
    }
    for r in 1..m {
        let s = inv(d[r * k]);
        if s != 1 {
            for j in 0..k {
                d[r * k + j] = mul(d[r * k + j], s);
            }
        }
    }
    d
}

/// Invert a square matrix (`n x n`, row major) over the field; `None` when singular.
pub fn invert(a: &[u8], n: usize) -> Option<Vec<u8>> {
    let mut m = a.to_vec();
    let mut r = vec![0u8; n * n];
    for i in 0..n {
        r[i * n + i] = 1;
    }
    for c in 0..n {
        let p = (c..n).find(|&p| m[p * n + c] != 0)?;
        if p != c {
            for x in 0..n {
                m.swap(p * n + x, c * n + x);
                r.swap(p * n + x, c * n + x);
            }
        }
        let s = inv(m[c * n + c]);
        for x in 0..n {
            m[c * n + x] = mul(m[c * n + x], s);
            r[c * n + x] = mul(r[c * n + x], s);
        }
        for y in 0..n {
            let e = m[y * n + c];
            if y != c && e != 0 {
                for x in 0..n {
                    let t = mul(e, m[c * n + x]);
                    m[y * n + x] ^= t;
                    let t = mul(e, r[c * n + x]);
                    r[y * n + x] ^= t;
                }
            }
        }
    }
    Some(r)
}

/// Split-nibble multiplication tables of one coefficient: `c*x = lo[x & 15] ^ hi[x >> 4]`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Nib {
    lo: [u8; 16],
    hi: [u8; 16],
}

pub(crate) fn nib(c: u8) -> Nib {
    let mut t = Nib {
        lo: [0; 16],
        hi: [0; 16],
    };
    for i in 0..16u8 {
        t.lo[i as usize] = mul(c, i);
        t.hi[i as usize] = mul(c, i << 4);
    }
    t
}

/// `dst ^= c * src` over equal-length regions.
#[inline]
pub fn mul_acc(dst: &mut [u8], src: &[u8], c: u8) {
    debug_assert_eq!(dst.len(), src.len());
    match c {
        0 => {}
        1 => dst.iter_mut().zip(src).for_each(|(d, s)| *d ^= *s),
        _ => mul_acc_nib(dst, src, &nib(c)),
    }
}

/// Portable kernel (also the tail of the SIMD ones).
#[inline]
fn mul_acc_scalar(dst: &mut [u8], src: &[u8], t: &Nib) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= t.lo[(*s & 15) as usize] ^ t.hi[(*s >> 4) as usize];
    }
}

/// AVX2 `vpshufb` split-nibble kernel (32 bytes per step).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn mul_acc_avx2(dst: &mut [u8], src: &[u8], t: &Nib) {
    use std::arch::x86_64::*;
    let n = dst.len().min(src.len());
    let body = n / 32 * 32;
    // SAFETY: `i + 32 <= body <= n` bounds every 32-byte load/store; the tables are 16 bytes.
    unsafe {
        let lo = _mm256_broadcastsi128_si256(_mm_loadu_si128(t.lo.as_ptr() as *const __m128i));
        let hi = _mm256_broadcastsi128_si256(_mm_loadu_si128(t.hi.as_ptr() as *const __m128i));
        let mask = _mm256_set1_epi8(0x0f);
        let (sp, dp) = (src.as_ptr(), dst.as_mut_ptr());
        let mut i = 0;
        while i < body {
            let s = _mm256_loadu_si256(sp.add(i) as *const __m256i);
            let d = _mm256_loadu_si256(dp.add(i) as *const __m256i);
            let l = _mm256_and_si256(s, mask);
            let h = _mm256_and_si256(_mm256_srli_epi64(s, 4), mask);
            let p = _mm256_xor_si256(_mm256_shuffle_epi8(lo, l), _mm256_shuffle_epi8(hi, h));
            _mm256_storeu_si256(dp.add(i) as *mut __m256i, _mm256_xor_si256(d, p));
            i += 32;
        }
    }
    mul_acc_scalar(&mut dst[body..n], &src[body..n], t);
}

/// NEON `tbl` split-nibble kernel (16 bytes per step).
#[cfg(target_arch = "aarch64")]
fn mul_acc_neon(dst: &mut [u8], src: &[u8], t: &Nib) {
    use std::arch::aarch64::*;
    let n = dst.len().min(src.len());
    let body = n / 16 * 16;
    // SAFETY: `i + 16 <= body <= n` bounds every 16-byte load/store; the tables are 16 bytes; NEON is baseline on aarch64.
    unsafe {
        let lo = vld1q_u8(t.lo.as_ptr());
        let hi = vld1q_u8(t.hi.as_ptr());
        let mask = vdupq_n_u8(0x0f);
        let (sp, dp) = (src.as_ptr(), dst.as_mut_ptr());
        let mut i = 0;
        while i < body {
            let s = vld1q_u8(sp.add(i));
            let d = vld1q_u8(dp.add(i));
            let p = veorq_u8(
                vqtbl1q_u8(lo, vandq_u8(s, mask)),
                vqtbl1q_u8(hi, vshrq_n_u8(s, 4)),
            );
            vst1q_u8(dp.add(i), veorq_u8(d, p));
            i += 16;
        }
    }
    mul_acc_scalar(&mut dst[body..n], &src[body..n], t);
}

/// `dst ^= c * src` with the best kernel of this CPU (AVX2 / NEON / portable); `t` = the nibble tables of `c`.
#[inline]
pub(crate) fn mul_acc_nib(dst: &mut [u8], src: &[u8], t: &Nib) {
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("avx2") {
        // SAFETY: the feature was just detected.
        return unsafe { mul_acc_avx2(dst, src, t) };
    }
    #[cfg(target_arch = "aarch64")]
    {
        return mul_acc_neon(dst, src, t);
    }
    #[cfg_attr(target_arch = "aarch64", expect(unreachable_code))]
    mul_acc_scalar(dst, src, t)
}

/// Failure of [`Codec::decode_into`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Fewer than k distinct survivors, a bad index, or a singular submatrix.
    Unrecoverable,
    /// Buffer length mismatch.
    BadLen,
}

/// One pool code: k data + m parity "raw" chunks (raw index = row of the generator; shard mapping is the caller's).
#[derive(Clone, Debug)]
pub struct Codec {
    /// Unique immutable generator identity; clones share plans, different matrices never alias.
    id: u64,
    k: usize,
    m: usize,
    /// m x k coding matrix.
    mat: Vec<u8>,
    /// per coefficient nibble tables (m*k).
    tabs: Vec<Nib>,
}

impl Codec {
    /// Panics outside [`Codec::try_new`]'s bounds (tests / known-good geometries only).
    pub fn new(kind: Kind, k: usize, m: usize) -> Codec {
        Codec::try_new(kind, k, m).expect("codec geometry")
    }

    /// `None` unless `k >= 1`, `m >= 1`, `k + m <= 255` (field elements for the generator rows).
    pub fn try_new(kind: Kind, k: usize, m: usize) -> Option<Codec> {
        if k == 0 || m == 0 || k + m > 255 {
            return None;
        }
        let mat = coding_matrix(kind, k, m);
        let tabs = mat.iter().map(|c| nib(*c)).collect();
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let id = NEXT_ID
            .try_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |n| n.checked_add(1),
            )
            .expect("codec identity exhausted");
        Some(Codec {
            id,
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
    /// The m x k coding matrix.
    pub fn matrix(&self) -> &[u8] {
        &self.mat
    }

    /// parity[r] = sum_j M[r][j] * data[j]; all regions the same length; parity is overwritten.
    pub fn encode(&self, data: &[&[u8]], parity: &mut [&mut [u8]]) {
        assert_eq!(data.len(), self.k);
        assert_eq!(parity.len(), self.m);
        // blocks that stay in L1: every parity row of a block is complete before the next block
        const BLK: usize = 16 << 10;
        let len = data.first().map_or(0, |d| d.len());
        let mut off = 0;
        while off < len {
            let end = (off + BLK).min(len);
            for (r, p) in parity.iter_mut().enumerate() {
                let dst = &mut p[off..end];
                dst.fill(0);
                for (j, d) in data.iter().enumerate() {
                    self.acc(r * self.k + j, dst, &d[off..end]);
                }
            }
            off = end;
        }
    }

    #[inline]
    fn acc(&self, idx: usize, dst: &mut [u8], src: &[u8]) {
        match self.mat[idx] {
            0 => {}
            1 => dst.iter_mut().zip(src).for_each(|(d, s)| *d ^= *s),
            _ => mul_acc_nib(dst, src, &self.tabs[idx]),
        }
    }

    /// Generator row of raw chunk `raw` (identity for data, matrix row for parity).
    fn gen_row(&self, raw: usize, out: &mut [u8]) {
        out.fill(0);
        if raw < self.k {
            out[raw] = 1;
        } else {
            out.copy_from_slice(&self.mat[(raw - self.k) * self.k..(raw - self.k + 1) * self.k]);
        }
    }

    /// Decode coefficients: for each wanted raw chunk the k coefficients over `have` (exactly k distinct raw
    /// indexes). Row-major `want.len() x k`. `None` if unrecoverable.
    pub fn decode_matrix(&self, have: &[usize], want: &[usize]) -> Option<Vec<u8>> {
        let k = self.k;
        if have.len() != k || have.iter().chain(want).any(|&r| r >= k + self.m) {
            return None;
        }
        let mut sub = vec![0u8; k * k];
        for (i, &raw) in have.iter().enumerate() {
            self.gen_row(raw, &mut sub[i * k..(i + 1) * k]);
        }
        let inv = invert(&sub, k)?;
        let mut out = vec![0u8; want.len() * k];
        let mut row = vec![0u8; k];
        for (wi, &w) in want.iter().enumerate() {
            self.gen_row(w, &mut row);
            for j in 0..k {
                let mut acc = 0u8;
                for t in 0..k {
                    acc ^= mul(row[t], inv[t * k + j]);
                }
                out[wi * k + j] = acc;
            }
        }
        Some(out)
    }

    /// Rebuild the raw chunks `want[i]` into `out[i]` from exactly k surviving chunks `have[j] = (raw, bytes)`.
    pub fn decode_into(
        &self,
        have: &[(usize, &[u8])],
        want: &[usize],
        out: &mut [&mut [u8]],
    ) -> Result<(), DecodeError> {
        if have.len() != self.k || out.len() != want.len() {
            return Err(DecodeError::Unrecoverable);
        }
        let len = have[0].1.len();
        if have.iter().any(|h| h.1.len() != len) || out.iter().any(|o| o.len() != len) {
            return Err(DecodeError::BadLen);
        }
        let mut seen = [false; 255];
        for &(raw, _) in have {
            if raw >= self.k + self.m || seen[raw] {
                return Err(DecodeError::Unrecoverable);
            }
            seen[raw] = true;
        }
        if want.iter().any(|&r| r >= self.k + self.m) {
            return Err(DecodeError::Unrecoverable);
        }
        // Very large duplicate wanted lists remain legal, but never grow the bounded cache.
        if DecodePlan::bytes(self.k, want.len()) > PLAN_BYTES {
            let idx: Vec<_> = have.iter().map(|h| h.0).collect();
            let coef = self
                .decode_matrix(&idx, want)
                .ok_or(DecodeError::Unrecoverable)?;
            for (wi, o) in out.iter_mut().enumerate() {
                o.fill(0);
                for (j, (_, src)) in have.iter().enumerate() {
                    mul_acc(o, src, coef[wi * self.k + j]);
                }
            }
            return Ok(());
        }
        DECODE_PLANS.with(|cache| {
            let mut cache = cache.borrow_mut();
            if let Some(i) = cache.plans.iter().position(|p| {
                p.id == self.id && p.want == want && p.have.iter().zip(have).all(|(&a, b)| a == b.0)
            }) {
                let plan = cache.plans.remove(i);
                cache.plans.push(plan);
            } else {
                let idx: Vec<_> = have.iter().map(|h| h.0).collect();
                let coef = self
                    .decode_matrix(&idx, want)
                    .ok_or(DecodeError::Unrecoverable)?;
                let plan = DecodePlan {
                    id: self.id,
                    have: idx,
                    want: want.to_vec(),
                    tabs: coef.iter().map(|&c| nib(c)).collect(),
                    coef,
                };
                let bytes = DecodePlan::bytes(self.k, want.len());
                while cache.plans.len() == PLAN_COUNT || cache.bytes + bytes > PLAN_BYTES {
                    let evicted = cache.plans.remove(0);
                    cache.bytes -= DecodePlan::bytes(evicted.have.len(), evicted.want.len());
                }
                cache.bytes += bytes;
                cache.plans.push(plan);
            }
            let plan = cache.plans.last().unwrap();
            for (wi, o) in out.iter_mut().enumerate() {
                o.fill(0);
                for (j, (_, src)) in have.iter().enumerate() {
                    let i = wi * self.k + j;
                    match plan.coef[i] {
                        0 => {}
                        1 => o.iter_mut().zip(*src).for_each(|(d, s)| *d ^= *s),
                        _ => mul_acc_nib(o, src, &plan.tabs[i]),
                    }
                }
            }
            Ok(())
        })
    }
}

/// Bound of the per-thread decode-plan caches: entries and bytes per cache (LRU, oldest evicted first).
pub(crate) const PLAN_COUNT: usize = 32;
pub(crate) const PLAN_BYTES: usize = 4 << 20;

struct DecodePlan {
    id: u64,
    have: Vec<usize>,
    want: Vec<usize>,
    coef: Vec<u8>,
    tabs: Vec<Nib>,
}

impl DecodePlan {
    fn bytes(k: usize, wants: usize) -> usize {
        k.saturating_add(wants)
            .saturating_mul(std::mem::size_of::<usize>())
            .saturating_add(
                k.saturating_mul(wants)
                    .saturating_mul(1 + std::mem::size_of::<Nib>()),
            )
    }
}

struct DecodePlans {
    plans: Vec<DecodePlan>,
    bytes: usize,
}

thread_local! {
    static DECODE_PLANS: std::cell::RefCell<DecodePlans> = std::cell::RefCell::new(DecodePlans {
        plans: Vec::with_capacity(PLAN_COUNT), bytes: 0,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_cache_lru_is_bounded_and_clones_share_identity() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Codec>();
        DECODE_PLANS.with(|c| {
            let mut c = c.borrow_mut();
            c.plans.clear();
            c.bytes = 0;
        });
        let codes: Vec<_> = (0..=PLAN_COUNT)
            .map(|_| Codec::new(Kind::IsaVan, 2, 2))
            .collect();
        let a = [7; 32];
        let b = [11; 32];
        let p = [12; 32];
        let have = [(1, b.as_slice()), (2, p.as_slice())];
        let mut out = [0; 32];
        for code in &codes[..PLAN_COUNT] {
            code.decode_into(&have, &[0], &mut [&mut out]).unwrap();
            assert_eq!(out, a);
        }
        codes[0]
            .clone()
            .decode_into(&have, &[0], &mut [&mut out])
            .unwrap();
        codes[PLAN_COUNT]
            .decode_into(&have, &[0], &mut [&mut out])
            .unwrap();
        DECODE_PLANS.with(|c| {
            let c = c.borrow();
            assert_eq!(c.plans.len(), PLAN_COUNT);
            assert!(c.bytes <= PLAN_BYTES);
            assert!(c.plans.iter().any(|p| p.id == codes[0].id));
            assert!(!c.plans.iter().any(|p| p.id == codes[1].id));
        });
        assert_eq!(
            codes[0].decode_into(&[(1, &b), (1, &b)], &[0], &mut [&mut out]),
            Err(DecodeError::Unrecoverable)
        );
        assert_eq!(
            codes[0].decode_into(&have, &[4], &mut [&mut out]),
            Err(DecodeError::Unrecoverable)
        );
    }

    #[test]
    fn decode_cache_byte_limit_and_oversized_wants() {
        DECODE_PLANS.with(|c| {
            let mut c = c.borrow_mut();
            c.plans.clear();
            c.bytes = 0;
        });
        let code = Codec::new(Kind::IsaVan, 254, 1);
        let data = [0u8; 1];
        let have: Vec<_> = (0..254).map(|i| (i, data.as_slice())).collect();
        // Distinct ordered wanted keys fill the byte cap before the entry cap.
        for raw in 0..5 {
            let want = vec![raw; 255];
            let mut buffers = vec![[0u8; 1]; want.len()];
            let mut output: Vec<&mut [u8]> = buffers.iter_mut().map(|b| &mut b[..]).collect();
            code.decode_into(&have, &want, &mut output).unwrap();
        }
        DECODE_PLANS.with(|c| {
            let c = c.borrow();
            assert!(c.bytes <= PLAN_BYTES);
            assert!(c.plans.len() < 5);
        });
        let before = DECODE_PLANS.with(|c| c.borrow().bytes);
        let want = vec![0; 600];
        assert!(DecodePlan::bytes(254, want.len()) > PLAN_BYTES);
        let mut buffers = vec![[0u8; 1]; want.len()];
        let mut output: Vec<&mut [u8]> = buffers.iter_mut().map(|b| &mut b[..]).collect();
        code.decode_into(&have, &want, &mut output).unwrap();
        assert!(buffers.iter().all(|b| *b == [0]));
        assert_eq!(DECODE_PLANS.with(|c| c.borrow().bytes), before);
    }

    #[test]
    fn field_basics() {
        assert_eq!(mul(2, 0x80), 0x1D);
        assert_eq!(inv(2), 0x8E);
        for a in 1..=255u8 {
            assert_eq!(mul(a, inv(a)), 1);
        }
        assert_eq!(pow(2, 8), 0x1D);
    }

    #[test]
    fn matrices_known() {
        assert_eq!(coding_matrix(Kind::IsaVan, 2, 2), [1, 1, 1, 2]);
        assert_eq!(coding_matrix(Kind::IsaVan, 4, 2), [1, 1, 1, 1, 1, 2, 4, 8]);
        assert_eq!(
            coding_matrix(Kind::IsaVan, 8, 3)[16..],
            [1, 4, 0x10, 0x40, 0x1D, 0x74, 0xCD, 0x13]
        );
        assert_eq!(
            coding_matrix(Kind::IsaCauchy, 2, 2),
            [0x8E, 0xF4, 0xF4, 0x8E]
        );
        assert_eq!(
            coding_matrix(Kind::IsaCauchy, 4, 2),
            [0x47, 0xA7, 0x7A, 0xBA, 0xA7, 0x47, 0xBA, 0x7A]
        );
        assert_eq!(coding_matrix(Kind::JerVan, 2, 2), [1, 1, 1, 0x8F]);
        assert_eq!(
            coding_matrix(Kind::JerVan, 4, 2),
            [1, 1, 1, 1, 1, 0x46, 0x8F, 0xC8]
        );
        let m83 = coding_matrix(Kind::JerVan, 8, 3);
        assert_eq!(m83[8..16], [1, 0x37, 0x27, 0x49, 0x54, 0xB5, 0xE1, 0xD9]);
        assert_eq!(m83[16..], [1, 0xAC, 0x46, 0xEB, 0x8F, 0x22, 0xC8, 0x65]);
        // m == 1 is XOR for every kind
        assert_eq!(coding_matrix(Kind::IsaCauchy, 3, 1), [1, 1, 1]);
    }

    /// Known answers of ec.md 4.8 (k=2; d0 = 01 02 80 FF, d1 = 03 04 02 1D).
    #[test]
    fn known_answer_parity() {
        let d0 = [0x01u8, 0x02, 0x80, 0xFF];
        let d1 = [0x03u8, 0x04, 0x02, 0x1D];
        let run = |kind, m| {
            let c = Codec::new(kind, 2, m);
            let mut ps = vec![[0u8; 4]; m];
            {
                let mut pr: Vec<&mut [u8]> = ps.iter_mut().map(|p| &mut p[..]).collect();
                c.encode(&[&d0, &d1], &mut pr);
            }
            ps
        };
        let isa = run(Kind::IsaVan, 2);
        assert_eq!(isa[0], [0x02, 0x06, 0x82, 0xE2]);
        assert_eq!(isa[1], [0x07, 0x0A, 0x84, 0xC5]);
        assert_eq!(run(Kind::JerVan, 2)[1], [0x8D, 0x04, 0x83, 0x62]);
        let c = run(Kind::IsaCauchy, 2);
        assert_eq!(c[0], [0x8F, 0xF6, 0xB5, 0xFA]);
        assert_eq!(c[1], [0x7B, 0xF7, 0x8A, 0xD5]);
    }

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

    /// Every erasure pattern of m losses decodes back (all kinds, several geometries).
    #[test]
    fn decode_all_erasure_patterns() {
        for kind in [Kind::IsaVan, Kind::IsaCauchy, Kind::JerVan] {
            for (k, m) in [(2, 1), (2, 2), (3, 2), (4, 2), (4, 3), (6, 3)] {
                let c = Codec::new(kind, k, m);
                let len = 67;
                let data: Vec<Vec<u8>> = (0..k).map(|i| pattern(len, i as u32 + 7)).collect();
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
                        assert_eq!(outs[i], all[*l], "{kind:?} k{k} m{m} lost {lost:?}");
                    }
                }
            }
        }
    }

    /// Throughput of the region kernel (`cargo test -p ec --release -- --ignored --nocapture kernel_speed`).
    #[test]
    #[ignore]
    fn kernel_speed() {
        for (k, m) in [(4usize, 2usize), (8, 3)] {
            let c = Codec::new(Kind::IsaVan, k, m);
            let len = 1 << 20;
            let data: Vec<Vec<u8>> = (0..k).map(|i| pattern(len, i as u32 + 1)).collect();
            let mut par = vec![vec![0u8; len]; m];
            let t = std::time::Instant::now();
            let rounds = 20;
            for _ in 0..rounds {
                let d: Vec<&[u8]> = data.iter().map(|v| &v[..]).collect();
                let mut p: Vec<&mut [u8]> = par.iter_mut().map(|v| &mut v[..]).collect();
                c.encode(&d, &mut p);
            }
            let secs = t.elapsed().as_secs_f64();
            let gb = (rounds * k * len) as f64 / 1e9;
            eprintln!("encode k={k} m={m}: {:.2} GB/s of data", gb / secs);
        }
    }

    /// The SIMD kernels equal the portable one for every coefficient, every length (tails) and unaligned slices.
    #[test]
    fn kernels_match_scalar() {
        for c in 0..=255u8 {
            let t = nib(c);
            for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 63, 64, 100, 257] {
                let src = pattern(len + 3, c as u32 + 11);
                let base = pattern(len + 3, c as u32 + 99);
                let (mut a, mut b) = (base.clone(), base.clone());
                mul_acc_scalar(&mut a[3..], &src[3..], &t);
                mul_acc(&mut b[3..], &src[3..], c);
                assert_eq!(a, b, "c={c} len={len}");
                let want: Vec<u8> = (0..len).map(|i| base[3 + i] ^ mul(c, src[3 + i])).collect();
                assert_eq!(&b[3..], &want[..], "c={c} len={len} vs field mul");
            }
        }
    }

    #[test]
    fn decode_errors() {
        let c = Codec::new(Kind::IsaVan, 2, 2);
        let a = [1u8; 4];
        let mut o = [0u8; 4];
        assert_eq!(
            c.decode_into(&[(0, &a), (0, &a)], &[1], &mut [&mut o]),
            Err(DecodeError::Unrecoverable)
        );
        assert_eq!(
            c.decode_into(&[(0, &a)], &[1], &mut [&mut o]),
            Err(DecodeError::Unrecoverable)
        );
    }

    /// SIMD vs field multiplication with independent src/dst misalignment (offsets 0..64) and random lengths,
    /// incl. lengths around the 16/32/64 byte steps and page sizes.
    #[test]
    fn kernels_unaligned_random() {
        let mut x: u32 = 0x9E37_79B9;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x
        };
        let mut lens: Vec<usize> = (0..=130).collect();
        lens.extend([255, 256, 257, 4095, 4096, 4097, 16383, 16384, 16385]);
        for _ in 0..200 {
            lens.push(rnd() as usize % 5000);
        }
        for len in lens {
            let (so, dof) = (rnd() as usize % 64, rnd() as usize % 64);
            let c = (rnd() % 256) as u8;
            let src = pattern(len + so, rnd());
            let base = pattern(len + dof, rnd());
            let mut d = base.clone();
            mul_acc(&mut d[dof..], &src[so..], c);
            assert_eq!(&d[..dof], &base[..dof], "prefix touched len={len}");
            for i in 0..len {
                assert_eq!(
                    d[dof + i],
                    base[dof + i] ^ mul(c, src[so + i]),
                    "c={c} len={len} so={so} do={dof} i={i}"
                );
            }
        }
    }

    /// Blocked encode (16 KiB blocks) equals the plain matrix-vector product for lengths straddling block edges,
    /// unaligned regions, k = 1 and m = 1 (XOR).
    #[test]
    fn encode_block_edges() {
        for (kind, k, m) in [
            (Kind::IsaCauchy, 3, 2),
            (Kind::IsaVan, 4, 3),
            (Kind::JerVan, 5, 2),
            (Kind::IsaVan, 1, 2),
            (Kind::JerVan, 1, 3),
            (Kind::IsaVan, 3, 1),
        ] {
            let c = Codec::new(kind, k, m);
            for len in [0usize, 1, 33, 16383, 16384, 16385, 32768, 32769 + 64] {
                let data: Vec<Vec<u8>> = (0..k)
                    .map(|i| pattern(len + 1, (i * 31 + len) as u32))
                    .collect();
                let mut par = vec![vec![0xAAu8; len + 1]; m];
                {
                    let d: Vec<&[u8]> = data.iter().map(|v| &v[1..]).collect();
                    let mut p: Vec<&mut [u8]> = par.iter_mut().map(|v| &mut v[1..]).collect();
                    c.encode(&d, &mut p);
                }
                let mat = c.matrix();
                for r in 0..m {
                    assert_eq!(par[r][0], 0xAA);
                    for i in 0..len {
                        let mut want = 0u8;
                        for j in 0..k {
                            want ^= mul(mat[r * k + j], data[j][1 + i]);
                        }
                        assert_eq!(par[r][1 + i], want, "{kind:?} k{k} m{m} len{len} r{r} i{i}");
                    }
                }
            }
        }
    }

    /// Large geometries the gate admits (isa k,m <= 32; k+m <= 127): random m-erasure patterns decode.
    #[test]
    fn decode_large_geometries() {
        let mut x: u32 = 12345;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as usize
        };
        for (kind, k, m) in [
            (Kind::IsaVan, 32, 3),
            (Kind::IsaVan, 21, 4),
            (Kind::IsaVan, 22, 4), // cauchy fallback
            (Kind::IsaVan, 10, 8), // cauchy fallback
            (Kind::IsaCauchy, 32, 32),
            (Kind::JerVan, 100, 27),
            (Kind::JerVan, 2, 125),
        ] {
            let c = Codec::new(kind, k, m);
            let n = k + m;
            let len = 37;
            let data: Vec<Vec<u8>> = (0..k).map(|i| pattern(len, i as u32 + 3)).collect();
            let mut par = vec![vec![0u8; len]; m];
            {
                let d: Vec<&[u8]> = data.iter().map(|v| &v[..]).collect();
                let mut p: Vec<&mut [u8]> = par.iter_mut().map(|v| &mut v[..]).collect();
                c.encode(&d, &mut p);
            }
            let all: Vec<Vec<u8>> = data.iter().chain(par.iter()).cloned().collect();
            for _ in 0..20 {
                let mut ids: Vec<usize> = (0..n).collect();
                for i in (1..n).rev() {
                    ids.swap(i, rnd() % (i + 1));
                }
                let (lost, have) = ids.split_at(m);
                let have: Vec<(usize, &[u8])> =
                    have[..k].iter().map(|&i| (i, &all[i][..])).collect();
                let mut outs = vec![vec![0u8; len]; lost.len()];
                let mut o: Vec<&mut [u8]> = outs.iter_mut().map(|v| &mut v[..]).collect();
                c.decode_into(&have, lost, &mut o).unwrap();
                for (i, l) in lost.iter().enumerate() {
                    assert_eq!(outs[i], all[*l], "{kind:?} k{k} m{m} lost {lost:?}");
                }
            }
        }
    }

    /// Bad decode inputs are errors, never panics.
    #[test]
    fn decode_bad_inputs() {
        let c = Codec::new(Kind::IsaVan, 2, 2);
        let (a, b) = ([1u8; 4], [2u8; 4]);
        let mut o = [0u8; 4];
        let short = [0u8; 3];
        // survivor index out of range
        assert_eq!(
            c.decode_into(&[(0, &a), (9, &b)], &[1], &mut [&mut o]),
            Err(DecodeError::Unrecoverable)
        );
        // wanted index out of range
        assert_eq!(
            c.decode_into(&[(0, &a), (1, &b)], &[4], &mut [&mut o]),
            Err(DecodeError::Unrecoverable)
        );
        // too many survivors, out/want mismatch
        assert_eq!(
            c.decode_into(&[(0, &a), (1, &b), (2, &a)], &[3], &mut [&mut o]),
            Err(DecodeError::Unrecoverable)
        );
        assert_eq!(
            c.decode_into(&[(0, &a), (1, &b)], &[2, 3], &mut [&mut o]),
            Err(DecodeError::Unrecoverable)
        );
        // length mismatch
        assert_eq!(
            c.decode_into(&[(0, &a), (1, &short)], &[2], &mut [&mut o]),
            Err(DecodeError::BadLen)
        );
        let mut os = [0u8; 3];
        assert_eq!(
            c.decode_into(&[(0, &a), (1, &b)], &[2], &mut [&mut os]),
            Err(DecodeError::BadLen)
        );
        // empty regions decode
        let e: [u8; 0] = [];
        let mut oe: [u8; 0] = [];
        assert_eq!(
            c.decode_into(&[(2, &e), (3, &e)], &[0], &mut [&mut oe]),
            Ok(())
        );
        // a singular submatrix is None, not a panic
        assert_eq!(invert(&[1, 1, 1, 1], 2), None);
        assert_eq!(invert(&[0, 0, 0, 0], 2), None);
    }
}
