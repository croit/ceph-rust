// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! x86-64 kernels. All take raw `(seed, src, dst, len)`; `dst` null = crc only, else copy src->dst while hashing.
//! Folding constants K(n) = reflect32(x^n mod P) << 1 (P = crc32c poly); folding a 128-bit lane by D bytes uses
//! (K(8D+32) for the low qword, K(8D-32) for the high qword). The folded 16 B remainder is finished with two `crc32`
//! instructions (raw, zero seed), which keeps the Ceph (no-inversion) semantics: the seed is xored into the first
//! 4 bytes of the message.
use core::arch::x86_64::*;
use std::sync::atomic::{AtomicU8, Ordering};

const POLY: u32 = 0x1EDC_6F41;

const fn k(n: u32) -> u64 {
    let mut r: u32 = 1;
    let mut i = 0;
    while i < n {
        let top = r >> 31;
        r <<= 1;
        if top == 1 {
            r ^= POLY;
        }
        i += 1;
    }
    (r.reverse_bits() as u64) << 1
}
/// (lo, hi) constants to fold by `d` bytes.
const fn kd(d: u32) -> (u64, u64) {
    (k(8 * d + 32), k(8 * d - 32))
}
const K16: (u64, u64) = kd(16);
const K64: (u64, u64) = kd(64);
const K256: (u64, u64) = kd(256);

const L_NONE: u8 = 1;
const L_SSE42: u8 = 2;
const L_PCLMUL: u8 = 3;
const L_AVX512: u8 = 4;

static LEVEL: AtomicU8 = AtomicU8::new(0);

#[cold]
fn detect() -> u8 {
    let l = if !is_x86_feature_detected!("sse4.2") {
        L_NONE
    } else if !is_x86_feature_detected!("pclmulqdq") {
        L_SSE42
    } else if is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("vpclmulqdq") {
        L_AVX512
    } else {
        L_PCLMUL
    };
    LEVEL.store(l, Ordering::Relaxed);
    l
}

#[inline(always)]
fn level() -> u8 {
    match LEVEL.load(Ordering::Relaxed) {
        0 => detect(),
        l => l,
    }
}

/// Highest supported level (for tests/bench).
pub fn max_level() -> u8 {
    level()
}

/// # Safety
/// `src..src+len` readable; `dst` null or `dst..dst+len` writable and not overlapping src.
#[inline]
pub unsafe fn run(seed: u32, src: *const u8, dst: *mut u8, len: usize) -> u32 {
    // SAFETY: forwarded contract; level() <= detected capability.
    unsafe { run_at(level(), seed, src, dst, len) }
}

/// Copy variant with non-temporal stores when the kernel and the 64 B alignment of `dst` allow it (else the plain
/// copy kernel): for destinations the CPU will not read again soon (DMA buffers).
///
/// # Safety
/// `src..src+len` readable; `dst..dst+len` writable, not overlapping src.
#[inline]
pub unsafe fn run_nt(seed: u32, src: *const u8, dst: *mut u8, len: usize) -> u32 {
    // SAFETY: forwarded contract; level() <= detected capability.
    unsafe {
        if level() == L_AVX512 && len >= 256 && (dst as usize).is_multiple_of(64) {
            return k512_copy::<true>(seed, src, dst, len);
        }
        run_at(level(), seed, src, dst, len)
    }
}

/// # Safety
/// As [`run`]; `lvl` must not exceed [`max_level`].
pub unsafe fn run_at(lvl: u8, seed: u32, src: *const u8, dst: *mut u8, len: usize) -> u32 {
    // SAFETY: caller contract + capability checked through `lvl`.
    unsafe {
        let copy = !dst.is_null();
        if lvl == L_NONE {
            if copy {
                core::ptr::copy_nonoverlapping(src, dst, len);
            }
            return super::soft(seed, core::slice::from_raw_parts(src, len));
        }
        match (lvl, copy) {
            (L_AVX512, false) if len >= 256 => k512::<false, false, 0>(seed, src, dst, len),
            (L_AVX512, true) if len >= 256 => k512_copy::<false>(seed, src, dst, len),
            (L_AVX512 | L_PCLMUL, false) if len >= 128 => k128::<false>(seed, src, dst, len),
            (L_AVX512 | L_PCLMUL, true) if len >= 128 => k128::<true>(seed, src, dst, len),
            (_, false) => scalar::<false>(seed, src, dst, len),
            (_, true) => scalar::<true>(seed, src, dst, len),
        }
    }
}

#[inline]
#[target_feature(enable = "sse4.2")]
unsafe fn scalar<const COPY: bool>(
    seed: u32,
    mut s: *const u8,
    mut d: *mut u8,
    mut n: usize,
) -> u32 {
    let mut c = seed as u64;
    // SAFETY: bounds by n.
    unsafe {
        while n >= 8 {
            let v = (s as *const u64).read_unaligned();
            if COPY {
                (d as *mut u64).write_unaligned(v);
                d = d.add(8);
            }
            c = _mm_crc32_u64(c, v);
            s = s.add(8);
            n -= 8;
        }
        let mut c = c as u32;
        while n > 0 {
            let v = *s;
            if COPY {
                *d = v;
                d = d.add(1);
            }
            c = _mm_crc32_u8(c, v);
            s = s.add(1);
            n -= 1;
        }
        c
    }
}

#[inline]
fn kv(c: (u64, u64)) -> __m128i {
    // SAFETY: SSE2 is baseline on x86-64.
    unsafe { _mm_set_epi64x(c.1 as i64, c.0 as i64) }
}

#[inline]
#[target_feature(enable = "sse4.2,pclmulqdq")]
fn fold16(a: __m128i, k: __m128i, data: __m128i) -> __m128i {
    _mm_xor_si128(
        _mm_xor_si128(
            _mm_clmulepi64_si128::<0x00>(a, k),
            _mm_clmulepi64_si128::<0x11>(a, k),
        ),
        data,
    )
}

/// Fold remaining whole 16 B blocks, reduce to 32 bit, finish bytes.
#[inline]
#[target_feature(enable = "sse4.2,pclmulqdq")]
unsafe fn tail<const COPY: bool>(
    mut acc: __m128i,
    mut s: *const u8,
    mut d: *mut u8,
    mut n: usize,
) -> u32 {
    let k16 = kv(K16);
    // SAFETY: bounds by n.
    unsafe {
        while n >= 16 {
            let v = _mm_loadu_si128(s as *const __m128i);
            if COPY {
                _mm_storeu_si128(d as *mut __m128i, v);
                d = d.add(16);
            }
            acc = fold16(acc, k16, v);
            s = s.add(16);
            n -= 16;
        }
        let c = _mm_crc32_u64(0, _mm_cvtsi128_si64(acc) as u64);
        let c = _mm_crc32_u64(c, _mm_extract_epi64::<1>(acc) as u64) as u32;
        scalar::<COPY>(c, s, d, n)
    }
}

/// PCLMULQDQ, 4 xmm accumulators, 64 B/iter. `n >= 128`.
#[target_feature(enable = "sse4.2,pclmulqdq")]
unsafe fn k128<const COPY: bool>(seed: u32, mut s: *const u8, mut d: *mut u8, mut n: usize) -> u32 {
    let k64 = kv(K64);
    let k16 = kv(K16);
    // SAFETY: n >= 128 so first 64 B and then each 64 B step are in bounds.
    unsafe {
        let ld = |p: *const u8, i: usize| _mm_loadu_si128((p as *const __m128i).add(i));
        let mut x = [ld(s, 0), ld(s, 1), ld(s, 2), ld(s, 3)];
        if COPY {
            for (i, v) in x.iter().enumerate() {
                _mm_storeu_si128((d as *mut __m128i).add(i), *v);
            }
            d = d.add(64);
        }
        x[0] = _mm_xor_si128(x[0], _mm_cvtsi32_si128(seed as i32));
        s = s.add(64);
        n -= 64;
        while n >= 64 {
            for (i, xi) in x.iter_mut().enumerate() {
                let v = ld(s, i);
                if COPY {
                    _mm_storeu_si128((d as *mut __m128i).add(i), v);
                }
                *xi = fold16(*xi, k64, v);
            }
            s = s.add(64);
            d = d.wrapping_add(if COPY { 64 } else { 0 });
            n -= 64;
        }
        let mut a = fold16(x[0], k16, x[1]);
        a = fold16(a, k16, x[2]);
        a = fold16(a, k16, x[3]);
        tail::<COPY>(a, s, d, n)
    }
}

#[inline]
#[target_feature(enable = "avx512f,vpclmulqdq")]
fn fold64(a: __m512i, k: __m512i, data: __m512i) -> __m512i {
    _mm512_ternarylogic_epi64::<0x96>(
        _mm512_clmulepi64_epi128::<0x00>(a, k),
        _mm512_clmulepi64_epi128::<0x11>(a, k),
        data,
    )
}

/// VPCLMULQDQ on zmm, 4 accumulators, 256 B/iter. `n >= 256` (and `n >= 256 * (A + 1)` when `A > 0`).
/// Copy: loads lead the stores of the same bytes by `A` blocks of 256 B (`A` = 0: every block is stored right after it
/// is loaded).
#[target_feature(enable = "avx512f,vpclmulqdq,pclmulqdq,sse4.2")]
unsafe fn k512<const COPY: bool, const NT: bool, const A: usize>(
    seed: u32,
    mut s: *const u8,
    mut d: *mut u8,
    mut n: usize,
) -> u32 {
    // SAFETY: n >= 256 * (A + 1) (A > 0) / n >= 256 so every 256 B step is in bounds.
    unsafe {
        let k256 = _mm512_broadcast_i32x4(kv(K256));
        let k64 = _mm512_broadcast_i32x4(kv(K64));
        let ld =
            |p: *const u8, i: usize| _mm512_loadu_si512((p as *const __m512i).add(i) as *const _);
        let st = |p: *mut u8, i: usize, v: __m512i| {
            if NT {
                // non-temporal: the destination (a DMA buffer) is not read again by the CPU, so no read-for-ownership
                // and no cache pollution; caller guarantees 64 B alignment
                _mm512_stream_si512((p as *mut __m512i).add(i), v)
            } else {
                _mm512_storeu_si512((p as *mut __m512i).add(i) as *mut _, v)
            }
        };
        let st4 = |p: *mut u8, v: &[__m512i; 4]| {
            for (i, v) in v.iter().enumerate() {
                st(p, i, *v);
            }
        };
        let ld4 = |p: *const u8| [ld(p, 0), ld(p, 1), ld(p, 2), ld(p, 3)];
        // A == 0: each 64 B store directly follows its load (interleaved); A > 0: ring of loaded, not yet stored
        // blocks, slot j holds block i with i mod A == j
        let mut x = [_mm512_setzero_si512(); 4];
        for (i, xi) in x.iter_mut().enumerate() {
            *xi = ld(s, i);
            if COPY && A == 0 {
                st(d, i, *xi);
            }
        }
        let mut ring = [[_mm512_setzero_si512(); 4]; A];
        if COPY {
            if A == 0 {
                d = d.add(256);
            } else {
                ring[0] = x;
            }
        }
        // `_mm512_castsi128_si512` leaves the upper lanes undefined; zero-extend the seed vector instead.
        x[0] = _mm512_xor_si512(x[0], _mm512_zextsi128_si512(_mm_cvtsi32_si128(seed as i32)));
        s = s.add(256);
        n -= 256;
        let fold4 = |x: &mut [__m512i; 4], v: &[__m512i; 4]| {
            for (xi, vi) in x.iter_mut().zip(v) {
                *xi = fold64(*xi, k256, *vi);
            }
        };
        // prologue: fill the ring
        for slot in ring.iter_mut().skip(1) {
            let v = ld4(s);
            if COPY {
                *slot = v;
            }
            fold4(&mut x, &v);
            s = s.add(256);
            n -= 256;
        }
        let step = 256 * A.max(1);
        while n >= step {
            if A == 0 {
                for (i, xi) in x.iter_mut().enumerate() {
                    let v = ld(s, i);
                    if COPY {
                        st(d, i, v);
                    }
                    *xi = fold64(*xi, k256, v);
                }
            } else {
                for (j, slot) in ring.iter_mut().enumerate() {
                    // per 64 B: load the new vector, then store the one it replaces (1 KiB older)
                    for (i, (xi, si)) in x.iter_mut().zip(slot.iter_mut()).enumerate() {
                        let v = ld(s.add(256 * j), i);
                        if COPY {
                            st(d.add(256 * j), i, *si);
                            *si = v;
                        }
                        *xi = fold64(*xi, k256, v);
                    }
                }
            }
            s = s.add(step);
            d = d.wrapping_add(if COPY { step } else { 0 });
            n -= step;
        }
        if A > 0 {
            // r < A whole blocks left: load them, store the r oldest ring blocks, then drain the ring oldest first
            let r = n / 256;
            for (j, slot) in ring.iter_mut().enumerate() {
                if j < r {
                    let v = ld4(s.add(256 * j));
                    if COPY {
                        st4(d.add(256 * j), slot);
                        *slot = v;
                    }
                    fold4(&mut x, &v);
                }
            }
            s = s.add(256 * r);
            n -= 256 * r;
            if COPY {
                d = d.add(256 * r);
                for (j, slot) in ring.iter().enumerate() {
                    if j >= r {
                        st4(d, slot);
                        d = d.add(256);
                    }
                }
                for (j, slot) in ring.iter().enumerate() {
                    if j < r {
                        st4(d, slot);
                        d = d.add(256);
                    }
                }
            }
        }
        let mut y = fold64(x[0], k64, x[1]);
        y = fold64(y, k64, x[2]);
        y = fold64(y, k64, x[3]);
        let k16 = kv(K16);
        let mut a = fold16(
            _mm512_castsi512_si128(y),
            k16,
            _mm512_extracti32x4_epi32::<1>(y),
        );
        a = fold16(a, k16, _mm512_extracti32x4_epi32::<2>(y));
        a = fold16(a, k16, _mm512_extracti32x4_epi32::<3>(y));
        let r = tail::<COPY>(a, s, d, n);
        if NT {
            _mm_sfence(); // order the streaming stores before the caller submits the buffer to the device
        }
        r
    }
}

/// Copy kernel at AVX-512, shaped against two address effects of a fused load/store stream:
/// - 4 KiB aliasing: a load whose address matches an older, still buffered store in the low 12 bits waits for it.
///   When the destination's page phase `(dst - src) mod 4096` is 1..=LEAD-64 B ahead of the source, each load would
///   match a store issued just before it; then loads lead the stores of the same bytes by LEAD (blocks held in
///   registers), so a load only ever matches stores not issued yet (the 64 B covers the load width). Other phases
///   keep store-after-load order, whose matching stores have drained (a fixed lead would only move the slow window to
///   phases LEAD..2*LEAD: measured on Zen 4).
/// - line splits: the source is brought to 64 B alignment by a scalar head (< 64 B), so each 64 B load reads one
///   cache line; the destination keeps its own alignment (Ice Lake pays more for split loads than for split stores;
///   Zen 4 slightly the reverse).
///   Streaming stores need an aligned destination, so `NT` skips the head (caller guarantees 64 B aligned `dst`).
///
/// # Safety
/// `n >= 256`; `s..s+n` readable, `d..d+n` writable, not overlapping; AVX-512 + VPCLMULQDQ host.
#[target_feature(enable = "avx512f,vpclmulqdq,pclmulqdq,sse4.2")]
unsafe fn k512_copy<const NT: bool>(
    mut seed: u32,
    mut s: *const u8,
    mut d: *mut u8,
    mut n: usize,
) -> u32 {
    // SAFETY: caller contract; the head is < 64 B and leaves n >= 256 for the vector kernel.
    unsafe {
        let h = (s as usize).wrapping_neg() % 64;
        if !NT && n >= h + 256 {
            seed = scalar::<true>(seed, s, d, h);
            s = s.add(h);
            d = d.add(h);
            n -= h;
        }
        const LEAD: usize = 1024; // 16 zmm of the 32
        let phase = (d as usize).wrapping_sub(s as usize) % 4096;
        if (1..=LEAD - 64).contains(&phase) && n >= LEAD + 256 {
            k512::<true, NT, { LEAD / 256 }>(seed, s, d, n)
        } else {
            k512::<true, NT, 0>(seed, s, d, n)
        }
    }
}
