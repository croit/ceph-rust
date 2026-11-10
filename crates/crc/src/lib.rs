// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! crc32c with Ceph seed semantics: raw update, no initial/final inversion (spec/encoding.md 10).
//!
//! Runtime dispatch (portable baseline build): VPCLMULQDQ+AVX-512 folding (256 B/iter, 4 zmm accumulators) ->
//! PCLMULQDQ folding (64 B/iter, 4 xmm) -> `crc32` instruction -> `crc32c` crate (software/other arch). The fused
//! copy+crc variants run the same kernels with a store per loaded vector (one read pass, no re-read).

#![deny(clippy::print_stderr, clippy::print_stdout)]
#![cfg_attr(test, allow(clippy::print_stderr, clippy::print_stdout))]
#[cfg(target_arch = "x86_64")]
mod x86;

pub mod blocks;
mod hint;
mod reblock;
pub use blocks::{BlockCrcs, reseed_4k};
pub use hint::{CrcHint, CrcHints, Payload};
pub use reblock::{ReblockedCrcs, VerifiedBlock, crc32c_reblock};

/// Raw crc32c update starting from `seed`. Chaining: `crc32c(crc32c(s, a), b) == crc32c(s, a ++ b)`.
#[inline]
pub fn crc32c(seed: u32, data: &[u8]) -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: src/len describe `data`; null dst = no copy.
        return unsafe { x86::run(seed, data.as_ptr(), std::ptr::null_mut(), data.len()) };
    }
    #[cfg_attr(target_arch = "x86_64", expect(unreachable_code))]
    soft(seed, data)
}

/// Reference/fallback implementation (crate; hardware on aarch64, tables elsewhere).
#[inline]
pub fn soft(seed: u32, data: &[u8]) -> u32 {
    if data.is_empty() {
        return seed;
    }
    !crc32c::crc32c_append(!seed, data)
}

/// Copy `src` to the end of `dst` and return `crc32c(seed, src)` (single fused pass on x86-64).
#[inline]
pub fn crc32c_extend(seed: u32, src: &[u8], dst: &mut Vec<u8>) -> u32 {
    dst.reserve(src.len());
    let at = dst.len();
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: reserved src.len() spare bytes; src cannot alias dst's spare capacity (&mut borrow).
        let c = unsafe { x86::run(seed, src.as_ptr(), dst.as_mut_ptr().add(at), src.len()) };
        unsafe { dst.set_len(at + src.len()) };
        return c;
    }
    #[cfg_attr(target_arch = "x86_64", expect(unreachable_code))]
    {
        dst.extend_from_slice(src);
        crc32c(seed, &dst[at..])
    }
}

/// Copy `src` into `dst` (same length) and return `crc32c(seed, src)`.
#[inline]
pub fn crc32c_copy(seed: u32, src: &[u8], dst: &mut [u8]) -> u32 {
    assert_eq!(src.len(), dst.len());
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: equal lengths checked; &mut dst cannot alias src.
        return unsafe { x86::run(seed, src.as_ptr(), dst.as_mut_ptr(), src.len()) };
    }
    #[cfg_attr(target_arch = "x86_64", expect(unreachable_code))]
    {
        dst.copy_from_slice(src);
        crc32c(seed, dst)
    }
}

/// [`crc32c_copy`] into possibly uninitialized memory: every byte of `dst` is written (no zero-fill pass first).
#[inline]
pub fn crc32c_copy_uninit(seed: u32, src: &[u8], dst: &mut [std::mem::MaybeUninit<u8>]) -> u32 {
    assert_eq!(src.len(), dst.len());
    // SAFETY: equal lengths checked; `&mut dst` cannot alias `src`; the kernels/copy write all `len` bytes.
    unsafe {
        let d = dst.as_mut_ptr().cast::<u8>();
        #[cfg(target_arch = "x86_64")]
        {
            x86::run(seed, src.as_ptr(), d, src.len())
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            std::ptr::copy_nonoverlapping(src.as_ptr(), d, src.len());
            crc32c(seed, std::slice::from_raw_parts(d, src.len()))
        }
    }
}

/// [`crc32c_copy_uninit`] with non-temporal stores where available: for destinations the CPU does not read again (buffers
/// handed to a device DMA); saves the read-for-ownership of the destination and keeps the caches for other work.
#[inline]
pub fn crc32c_copy_dma_uninit(seed: u32, src: &[u8], dst: &mut [std::mem::MaybeUninit<u8>]) -> u32 {
    assert_eq!(src.len(), dst.len());
    #[cfg(target_arch = "x86_64")]
    // SAFETY: equal lengths checked; `&mut dst` cannot alias `src`; the kernels write all `len` bytes.
    unsafe {
        x86::run_nt(seed, src.as_ptr(), dst.as_mut_ptr().cast::<u8>(), src.len())
    }
    #[cfg(not(target_arch = "x86_64"))]
    crc32c_copy_uninit(seed, src, dst)
}

/// [`crc32c_copy_dma_uninit`] for an initialized destination slice.
#[inline]
pub fn crc32c_copy_dma(seed: u32, src: &[u8], dst: &mut [u8]) -> u32 {
    // SAFETY: `MaybeUninit<u8>` has the layout of `u8`; the callee only writes.
    let d = unsafe {
        std::slice::from_raw_parts_mut(
            dst.as_mut_ptr().cast::<std::mem::MaybeUninit<u8>>(),
            dst.len(),
        )
    };
    crc32c_copy_dma_uninit(seed, src, d)
}

/// Highest kernel level this build can run on this host (see [`crc32c_level`]).
fn max_level() -> u8 {
    #[cfg(target_arch = "x86_64")]
    {
        x86::max_level()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        1
    }
}

/// Test/bench hook: crc at a forced kernel level (1 soft, 2 crc32 insn, 3 pclmul, 4 avx512); `None` if unsupported.
#[doc(hidden)]
pub fn crc32c_level(level: u8, seed: u32, data: &[u8], copy_to: Option<&mut [u8]>) -> Option<u32> {
    // Level 0 names no kernel and would run the sse4.2 fallback on a CPU that may lack sse4.2.
    if level == 0 || level > max_level() {
        return None;
    }
    #[cfg(target_arch = "x86_64")]
    {
        let d = copy_to.map_or(std::ptr::null_mut(), |d| {
            assert_eq!(d.len(), data.len());
            d.as_mut_ptr()
        });
        // SAFETY: lengths checked, level supported.
        return Some(unsafe { x86::run_at(level, seed, data.as_ptr(), d, data.len()) });
    }
    #[cfg_attr(target_arch = "x86_64", expect(unreachable_code))]
    {
        if let Some(d) = copy_to {
            d.copy_from_slice(data);
        }
        Some(soft(seed, data))
    }
}

/// Equivalent to feeding `len` zero bytes (no pass: [`crc32c_shift`]).
pub fn crc32c_zeros(seed: u32, len: usize) -> u32 {
    crc32c_shift(seed, len as u64)
}

/// Reflected crc32c polynomial: one zero input bit maps the raw state `s` to `(s >> 1) ^ (POLY if s & 1)`.
pub(crate) const POLY: u32 = 0x82F6_3B78;

/// Image of `v` under the GF(2) matrix `m` (column `i` = image of bit `i`).
pub(crate) const fn apply(m: &[u32; 32], mut v: u32) -> u32 {
    let mut r = 0;
    while v != 0 {
        r ^= m[v.trailing_zeros() as usize];
        v &= v - 1;
    }
    r
}

/// Multiplication by `x^(8*len)` modulo the crc32c polynomial in the reflected raw domain, i.e. the raw update by `len`
/// zero bytes. One bit of zero input maps the state `s` to `(s >> 1) ^ (POLY if s & 1)`, linear over GF(2); `OPS[k]`
/// is that map applied `8 * 2^k` times, built by squaring (a matrix is `[u32; 32]`, column `i` = image of bit `i`).
/// Applying the set bits of `len` costs <= 64 matrix-vector products of 32 steps: no data pass.
pub fn crc32c_shift(seed: u32, len: u64) -> u32 {
    static OPS: std::sync::OnceLock<[[u32; 32]; 64]> = std::sync::OnceLock::new();
    let ops = OPS.get_or_init(|| {
        let step = |s: u32| (s >> 1) ^ if s & 1 != 0 { POLY } else { 0 };
        let mut m = [0u32; 32];
        // one zero bit, squared 3 times = one zero byte (2^3 bits)
        for (i, c) in m.iter_mut().enumerate() {
            *c = step(1u32 << i);
        }
        let sq = |m: &[u32; 32]| {
            let mut o = [0u32; 32];
            for (i, c) in o.iter_mut().enumerate() {
                *c = apply(m, m[i]);
            }
            o
        };
        for _ in 0..3 {
            m = sq(&m);
        }
        let mut t = [[0u32; 32]; 64];
        for e in &mut t {
            *e = m;
            m = sq(&m);
        }
        t
    });
    let (mut r, mut n, mut k) = (seed, len, 0);
    while n != 0 && r != 0 {
        if n & 1 != 0 {
            r = apply(&ops[k], r);
        }
        n >>= 1;
        k += 1;
    }
    r
}

/// crc32c of `A ++ B` from `crc_a = crc32c(s, A)` and `crc_b0 = crc32c(0, B)` (B hashed from seed 0) and `len(B)`,
/// without touching the data. The raw update is `U(s, B) = shift(s, len B) ^ U(0, B)`, so
/// `crc32c(s, A ++ B) = shift(crc_a, len B) ^ crc_b0`. (With a B hashed from another seed `t`, pass `crc_b ^ shift(t, len B)`.)
pub fn crc32c_combine(crc_a: u32, crc_b0: u32, len_b: u64) -> u32 {
    crc32c_shift(crc_a, len_b) ^ crc_b0
}

/// `crc32c(!0, A ++ B)` from `crc_a = crc32c(!0, A)` and `crc_b = crc32c(!0, B)` (the msgr2 segment crc of a part
/// that was hashed on its own, e.g. a [`CrcHint`]) and `len(B)`, without touching the data.
pub fn crc32c_append_ones(crc_a: u32, crc_b: u32, len_b: u64) -> u32 {
    crc32c_combine(crc_a, crc_b ^ crc32c_shift(!0, len_b), len_b)
}

/// Zero-feeding over one 4096-byte block as four byte tables: `Z(x) = crc32c_zeros(x, BLK)` is linear over GF(2).
fn z4k() -> &'static [[u32; 256]; 4] {
    static T: std::sync::OnceLock<[[u32; 256]; 4]> = std::sync::OnceLock::new();
    T.get_or_init(|| {
        let mut basis = [0u32; 32];
        for (b, v) in basis.iter_mut().enumerate() {
            *v = crc32c_zeros(1 << b, blocks::BLK);
        }
        let mut t = [[0u32; 256]; 4];
        for (k, tk) in t.iter_mut().enumerate() {
            for (x, e) in tk.iter_mut().enumerate() {
                *e = (0..8)
                    .filter(|b| x >> b & 1 != 0)
                    .fold(0, |a, b| a ^ basis[8 * k + b]);
            }
        }
        t
    })
}

/// crc32c of the concatenation of 4096-byte blocks, from the per-block crcs alone (no pass over the data):
/// `blocks` yields `(crc32c(block_seed, block), block_seed)` per block in order; the result equals
/// `crc32c(seed, block_0 ++ block_1 ++ ...)`. With the raw (no inversion) update `U` linear in seed and data,
/// `U(s, B) = Z(s) ^ U(0, B)`, so `r' = Z(r ^ block_seed) ^ block_crc`.
pub fn crc32c_blocks(seed: u32, blocks: impl IntoIterator<Item = (u32, u32)>) -> u32 {
    let t = z4k();
    blocks.into_iter().fold(seed, |r, (c, s)| {
        let x = r ^ s;
        t[0][(x & 0xFF) as usize]
            ^ t[1][(x >> 8 & 0xFF) as usize]
            ^ t[2][(x >> 16 & 0xFF) as usize]
            ^ t[3][(x >> 24) as usize]
            ^ c
    })
}

/// `crc32c(!0, data[a..b])` of a range of `data` (a whole number of 4096-byte blocks) from the per-block crcs of the
/// blocks inside the range plus a pass over the at most two partial blocks at its ends: `block(i)` yields
/// `(crc32c(seed, block_i), seed)` of block `i`, as for [`crc32c_blocks`]. A range inside one block is hashed directly.
pub fn crc32c_range(data: &[u8], block: impl Fn(usize) -> (u32, u32), a: usize, b: usize) -> u32 {
    use blocks::BLK;
    debug_assert!(data.len().is_multiple_of(BLK) && a <= b && b <= data.len());
    let (first, last) = (a.div_ceil(BLK) * BLK, b / BLK * BLK);
    if first > last {
        return crc32c(!0, &data[a..b]);
    }
    let r = crc32c(!0, &data[a..first]);
    let r = crc32c_blocks(r, (first / BLK..last / BLK).map(block));
    crc32c(r, &data[last..b])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dma_copy_matches_plain_copy_for_every_alignment_and_size() {
        let src: Vec<u8> = (0..20_000u32)
            .map(|i| (i.wrapping_mul(2_246_822_519) >> 11) as u8)
            .collect();
        let mut raw = vec![0u8; 20_000 + 256];
        // offsets relative to a 64 B aligned base: 0 / 64 / 128 take the non-temporal kernel (x86 AVX-512), the rest the
        // plain fallback (a Vec is not 64 B aligned by itself)
        let base = raw.as_ptr().align_offset(64);
        for off in [0usize, 1, 8, 64, 100, 128].map(|o| base + o) {
            for len in [0usize, 1, 63, 64, 255, 256, 257, 4096, 4097, 9000, 20_000] {
                let want = crc32c(0x1234, &src[..len]);
                raw.fill(0xEE);
                let dst = &mut raw[off..off + len];
                assert_eq!(
                    crc32c_copy_dma(0x1234, &src[..len], dst),
                    want,
                    "off {off} len {len}"
                );
                assert_eq!(dst, &src[..len], "off {off} len {len}");
                // bytes around the destination untouched
                assert!(
                    raw[..off].iter().all(|&b| b == 0xEE)
                        && raw[off + len..].iter().all(|&b| b == 0xEE)
                );
            }
        }
    }

    #[test]
    fn blocks_combine_matches_direct_crc() {
        let d: Vec<u8> = (0..4096u32 * 37)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let seeds: Vec<u32> = (0..37u32)
            .map(|i| i.wrapping_mul(0x9E37_79B9) ^ 0xA5A5_0000)
            .collect();
        for k in [0usize, 1, 2, 5, 37] {
            let it = d
                .chunks(4096)
                .take(k)
                .zip(&seeds)
                .map(|(b, &s)| (crc32c(s, b), s));
            for seed in [0u32, 0xFFFF_FFFF, 0x1234_5678] {
                assert_eq!(
                    crc32c_blocks(seed, it.clone()),
                    crc32c(seed, &d[..k * 4096]),
                    "k {k} seed {seed:x}"
                );
            }
        }
    }

    /// Reference: feed zero bytes through the data crc.
    fn zeros_slow(seed: u32, len: usize) -> u32 {
        soft(seed, &vec![0u8; len])
    }

    #[test]
    fn range_from_block_crcs_matches_direct_crc() {
        let data: Vec<u8> = (0..5 * 4096u32)
            .map(|i| (i.wrapping_mul(2_246_822_519) >> 13) as u8)
            .collect();
        let seed = |i: usize| 0x1234_5678u32.wrapping_mul(i as u32 + 1);
        let block = |i: usize| (crc32c(seed(i), &data[i * 4096..(i + 1) * 4096]), seed(i));
        for a in [0usize, 1, 100, 4095, 4096, 4097, 9000, 8192] {
            for b in [a, a + 1, a + 4095, 12288, 16383, 16384, 5 * 4096] {
                if b < a || b > data.len() {
                    continue;
                }
                assert_eq!(
                    crc32c_range(&data, block, a, b),
                    crc32c(!0, &data[a..b]),
                    "range {a}..{b}"
                );
            }
        }
    }

    #[test]
    fn shift_matches_zero_feeding() {
        for len in (0..=300usize).chain([4095, 4096, 4097, 65_535, 65_536, 1 << 20, (4 << 20) + 3])
        {
            for seed in [0u32, 1, 0xFFFF_FFFF, 0xDEAD_BEEF, 0x8000_0000] {
                assert_eq!(
                    crc32c_shift(seed, len as u64),
                    zeros_slow(seed, len),
                    "len {len} seed {seed:x}"
                );
            }
        }
        // group property incl. lengths far beyond memory
        let s = 0x1357_9BDF;
        for (a, b) in [
            (1u64, 2),
            (1 << 20, 1 << 33),
            (u64::MAX / 3, 12_345),
            (0, 7),
            (1 << 63, 1 << 62),
        ] {
            assert_eq!(
                crc32c_shift(crc32c_shift(s, a), b),
                crc32c_shift(s, a.wrapping_add(b))
            );
        }
        assert_eq!(crc32c_shift(0, 1 << 40), 0);
    }

    #[test]
    fn combine_every_split_and_seed() {
        let d = data(300);
        for seed in [0u32, 0xFFFF_FFFF, 0x1234_5678] {
            for n in 0..=d.len() {
                let whole = crc32c(seed, &d[..n]);
                for k in 0..=n {
                    let (a, b) = d[..n].split_at(k);
                    assert_eq!(
                        crc32c_combine(crc32c(seed, a), crc32c(0, b), b.len() as u64),
                        whole,
                        "seed {seed:x} n {n} k {k}"
                    );
                }
            }
        }
    }

    #[test]
    fn combine_large_and_chained() {
        let d = data(5 << 20);
        let whole = crc32c(!0, &d);
        // three parts, odd boundaries; b hashed from a foreign seed t: crc_b ^ shift(t, len) is its seed-0 crc
        for (i, j) in [
            (0, 1),
            (1, 4_194_304),
            (4095, 4_194_305),
            (999_999, 5 << 20),
            (5 << 20, 5 << 20),
        ] {
            let (a, b, c) = (&d[..i], &d[i..j], &d[j..]);
            let t = 0xA5A5_5A5A;
            let b0 = crc32c(t, b) ^ crc32c_shift(t, b.len() as u64);
            assert_eq!(b0, crc32c(0, b));
            let r = crc32c_combine(crc32c(!0, a), b0, b.len() as u64);
            let r = crc32c_combine(r, crc32c(0, c), c.len() as u64);
            assert_eq!(r, whole, "i {i} j {j}");
        }
    }

    #[test]
    fn copy_crc_random_sizes_and_alignments() {
        let d = data(70_000);
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        let mut rnd = |m: usize| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 16) as usize % m
        };
        for _ in 0..300 {
            let (off, n, doff) = (rnd(64), rnd(60_000), rnd(64));
            let seed = rnd(1 << 31) as u32 * 2 + 1;
            let s = &d[off..off + n];
            let mut buf = vec![0xEEu8; n + 64 + doff];
            let dst = &mut buf[doff..doff + n];
            assert_eq!(
                crc32c_copy(seed, s, dst),
                soft(seed, s),
                "off {off} n {n} doff {doff}"
            );
            assert_eq!(dst, s);
            assert!(
                buf[..doff].iter().all(|&b| b == 0xEE)
                    && buf[doff + n..].iter().all(|&b| b == 0xEE)
            );
        }
    }

    #[test]
    fn spec_vectors() {
        assert_eq!(crc32c(0, b"123456789"), 0x58E3_FA20);
        assert_eq!(crc32c(0xFFFF_FFFF, b"123456789"), 0x1CF9_6D7C);
        assert_eq!(crc32c(0, b"a"), 0x93AD_1061);
        assert_eq!(crc32c(0xFFFF_FFFF, &[0; 4]), 0xB798_B438);
        assert_eq!(crc32c_zeros(0xFFFF_FFFF, 4), 0xB798_B438);
        assert_eq!(crc32c_zeros(0xFFFF_FFFF, 32), 0x756E_C955);
        assert_eq!(crc32c(1, &[0]), 0xF26B_8303);
        assert_eq!(crc32c(0x1234_5678, &[]), 0x1234_5678);
        assert_eq!(crc32c_zeros(0, 10_000), 0);
    }

    #[test]
    fn copy_variants_match() {
        let d: Vec<u8> = (0..100_000u32).map(|i| (i * 31) as u8).collect();
        for n in [0, 1, 7, 16384, 16385, 40_000, 100_000] {
            let mut v = vec![9u8];
            assert_eq!(crc32c_extend(5, &d[..n], &mut v), crc32c(5, &d[..n]));
            assert_eq!(&v[1..], &d[..n]);
            let mut o = vec![0u8; n];
            assert_eq!(crc32c_copy(5, &d[..n], &mut o), crc32c(5, &d[..n]));
            assert_eq!(o, &d[..n]);
            let mut u = vec![std::mem::MaybeUninit::<u8>::uninit(); n];
            assert_eq!(crc32c_copy_uninit(5, &d[..n], &mut u), crc32c(5, &d[..n]));
            let got: Vec<u8> = u.iter().map(|b| unsafe { b.assume_init() }).collect();
            assert_eq!(got, &d[..n]);
        }
    }

    #[test]
    fn chaining() {
        let a = crc32c(0xFFFF_FFFF, b"1234");
        assert_eq!(crc32c(a, b"56789"), 0x1CF9_6D7C);
    }

    fn data(n: usize) -> Vec<u8> {
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    /// Every `(dst - src) mod 4096` phase class and every length class the copy kernels branch on (head alignment,
    /// look-ahead prologue/remainder/drain, tail) against the soft reference; destination bytes and guard bytes exact.
    #[test]
    fn copy_crc_random_page_phases_match_reference() {
        let d = data(80_000);
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        let mut rnd = |m: usize| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 16) as usize % m
        };
        let mut buf = vec![0u8; 80_000 + 2 * 4096];
        let sbase = d.as_ptr() as usize;
        for i in 0..3000 {
            let soff = rnd(4096);
            let n = match i % 3 {
                0 => rnd(2048),
                1 => rnd(12_288),
                _ => rnd(75_000 - 4096),
            };
            let s = &d[soff..soff + n];
            // destination start with a random page phase relative to the source
            let phase = rnd(4096);
            let b = buf.as_ptr() as usize;
            let doff = (sbase + soff + phase).wrapping_sub(b) % 4096;
            let seed = rnd(1 << 31) as u32 * 2 + 1;
            let want = soft(seed, s);
            buf.fill(0xEE);
            let dst = &mut buf[doff..doff + n];
            assert_eq!(
                crc32c_copy(seed, s, dst),
                want,
                "copy phase {phase} soff {soff} n {n}"
            );
            assert_eq!(dst, s, "copy data phase {phase} n {n}");
            buf.fill(0xEE);
            let dst = &mut buf[doff..doff + n];
            assert_eq!(
                crc32c_copy_dma(seed, s, dst),
                want,
                "dma phase {phase} soff {soff} n {n}"
            );
            assert_eq!(dst, s, "dma data phase {phase} n {n}");
            assert!(
                buf[..doff].iter().all(|&b| b == 0xEE)
                    && buf[doff + n..].iter().all(|&b| b == 0xEE),
                "guard phase {phase} n {n}"
            );
        }
    }

    #[test]
    fn all_levels_match_reference() {
        let d = data(70_000);
        let mut lens: Vec<usize> = (0..=1200).collect();
        lens.extend([4095, 4096, 4097, 8191, 16384, 32768, 65535, 65536, 69_999]);
        for lvl in 1..=4u8 {
            for &seed in &[0u32, 0xFFFF_FFFF, 0xDEAD_BEEF, 1] {
                for &n in &lens {
                    // misaligned start too
                    for off in [0usize, 1, 13] {
                        if off + n > d.len() {
                            continue;
                        }
                        let s = &d[off..off + n];
                        let want = soft(seed, s);
                        let Some(got) = crc32c_level(lvl, seed, s, None) else {
                            continue;
                        };
                        assert_eq!(got, want, "lvl {lvl} seed {seed:x} n {n} off {off}");
                        let mut o = vec![0u8; n];
                        let got = crc32c_level(lvl, seed, s, Some(&mut o)).unwrap();
                        assert_eq!(got, want, "copy lvl {lvl} n {n}");
                        assert_eq!(o, s, "copy data lvl {lvl} n {n}");
                    }
                }
            }
        }
    }

    #[test]
    fn level_hook_rejects_levels_this_host_cannot_run() {
        // 0 names no kernel: it would run the sse4.2 fallback on a CPU without sse4.2
        assert_eq!(crc32c_level(0, 7, b"abc", None), None);
        assert_eq!(crc32c_level(max_level() + 1, 7, b"abc", None), None);
        assert_eq!(crc32c_level(1, 7, b"abc", None), Some(soft(7, b"abc")));
    }

    /// The seed is xored into the first 4 bytes of the first fold: the entry size of the avx-512 kernel and odd seeds.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn avx512_seed_xor_matches_reference() {
        let d = data(1024);
        for n in [256usize, 257, 511, 512, 1023] {
            for seed in [0u32, 1, !0, 0xDEAD_BEEF, 0x8000_0000] {
                let Some(got) = crc32c_level(4, seed, &d[..n], None) else {
                    continue;
                };
                assert_eq!(got, soft(seed, &d[..n]), "n {n} seed {seed:x}");
            }
        }
    }

    #[test]
    fn dispatch_and_extend_match() {
        let d = data(300_000);
        for n in [0, 1, 255, 256, 257, 1000, 100_000, 300_000] {
            assert_eq!(crc32c(77, &d[..n]), soft(77, &d[..n]));
            let mut v = vec![1u8, 2, 3];
            assert_eq!(crc32c_extend(77, &d[..n], &mut v), soft(77, &d[..n]));
            assert_eq!(&v[3..], &d[..n]);
            assert_eq!(&v[..3], &[1, 2, 3]);
        }
    }

    #[test]
    fn append_ones_joins_independently_hashed_runs() {
        // runs of odd lengths, boundaries off any 4K grid, empty runs: the join equals one pass over the concatenation
        let d = data(200_000);
        let cuts: [&[usize]; 5] = [
            &[],
            &[0, 0, 200_000],
            &[1, 4095, 4097, 100_001, 100_001, 199_999],
            &[65_536, 65_537, 131_072],
            &[3, 5, 7, 11, 13, 17, 19, 23],
        ];
        for cs in cuts {
            let mut runs = vec![];
            let mut at = 0;
            for &c in cs.iter().chain(&[d.len()]) {
                runs.push(&d[at..c]);
                at = c;
            }
            let mut r = !0u32;
            for run in &runs {
                r = crc32c_append_ones(r, crc32c(!0, run), run.len() as u64);
            }
            assert_eq!(r, crc32c(!0, &d), "cuts {cs:?}");
        }
    }
}
