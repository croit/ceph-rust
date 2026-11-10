// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Inline per-pool compression (adr 0059 am. 1): algorithms, per-txn parameters, the codec trait and the software
//! codec. The on-disk side (extent flag, chunk layout) lives in `obj::stage` / `obj::onode`.

use crate::BLK;
use bytes::Bytes;

/// Stored in the extent record: never renumber.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Alg {
    Lz4 = 1,
    Zstd = 2,
    Snappy = 3,
    Zlib = 4,
}

impl Alg {
    pub fn from_u8(v: u8) -> Option<Alg> {
        Some(match v {
            1 => Alg::Lz4,
            2 => Alg::Zstd,
            3 => Alg::Snappy,
            4 => Alg::Zlib,
            _ => return None,
        })
    }
    /// Pool option value (`compression_algorithm`); `None` = unknown (the pool stores uncompressed).
    pub fn parse(s: &str) -> Option<Alg> {
        Some(match s {
            "lz4" => Alg::Lz4,
            "zstd" => Alg::Zstd,
            "snappy" => Alg::Snappy,
            "zlib" => Alg::Zlib,
            _ => return None,
        })
    }
}

/// Pool `compression_mode`. The `*Lazy` modes (fork `wip-ifed-dedup`, dedup-reformat.md 9) never compress client writes;
/// they act like their base mode for the deep-scrub reformat rewrites (`PoolComp::resolve_reformat`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    None,
    Passive,
    Aggressive,
    Force,
    PassiveLazy,
    AggressiveLazy,
    ForceLazy,
}

impl Mode {
    pub fn parse(s: &str) -> Mode {
        match s {
            "passive" => Mode::Passive,
            "aggressive" => Mode::Aggressive,
            "force" => Mode::Force,
            "passive_lazy" => Mode::PassiveLazy,
            "aggressive_lazy" => Mode::AggressiveLazy,
            "force_lazy" => Mode::ForceLazy,
            _ => Mode::None,
        }
    }
    fn lazy(self) -> bool {
        matches!(
            self,
            Mode::PassiveLazy | Mode::AggressiveLazy | Mode::ForceLazy
        )
    }
}

/// Client alloc-hint flag bits (`CEPH_OSD_ALLOC_HINT_FLAG_*`).
pub const HINT_COMPRESSIBLE: u32 = 256;
pub const HINT_INCOMPRESSIBLE: u32 = 512;

/// Pool compression settings, resolved once per pool map change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolComp {
    pub mode: Mode,
    pub alg: Alg,
    /// `compression_required_ratio` in permille (875 = keep when the result is at most 87.5 % of the raw size).
    pub ratio_permille: u32,
    /// Writes shorter than this are stored raw (bytes).
    pub min_blob: u32,
    /// Chunk unit in bytes (multiple of 4 KiB, at most 64 blocks): chunks are aligned to it.
    pub max_blob: u32,
}

impl PoolComp {
    /// Default: ratio 0.875, min 8 KiB, max 64 KiB (the ssd defaults).
    pub fn new(mode: Mode, alg: Alg) -> PoolComp {
        PoolComp {
            mode,
            alg,
            ratio_permille: 875,
            min_blob: 8192,
            max_blob: 65536,
        }
    }

    /// Resolve the mode against the txn's alloc hints (OR of the flags of its ops): `Some` = compress this txn's
    /// aligned full chunks.
    pub fn resolve(&self, hint_flags: u32) -> Option<CompSpec> {
        if self.mode.lazy() {
            return None;
        }
        self.resolve_reformat(hint_flags)
    }

    /// The same for a deep-scrub reformat rewrite (dedup-reformat.md 9): lazy modes act like their base mode.
    pub fn resolve_reformat(&self, hint_flags: u32) -> Option<CompSpec> {
        let on = match self.mode {
            Mode::None => false,
            Mode::Passive | Mode::PassiveLazy => hint_flags & HINT_COMPRESSIBLE != 0,
            Mode::Aggressive | Mode::AggressiveLazy => hint_flags & HINT_INCOMPRESSIBLE == 0,
            Mode::Force | Mode::ForceLazy => true,
        };
        if !on {
            return None;
        }
        let chunk = (self.max_blob / BLK as u32).clamp(2, 64);
        Some(CompSpec {
            alg: self.alg,
            ratio_permille: self.ratio_permille.min(1000),
            min_bytes: self.min_blob,
            chunk_blks: chunk as u8,
        })
    }
}

/// What one txn may do: set by the adapter from the pool (`OTxn::comp`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompSpec {
    pub alg: Alg,
    pub ratio_permille: u32,
    pub min_bytes: u32,
    pub chunk_blks: u8,
}

/// Most physical blocks a compressed chunk of `raw_blks` blocks may keep: the ratio bound, never the raw size (a kept
/// chunk always saves at least one block).
pub fn max_phys_blocks(raw_blks: usize, ratio_permille: u32) -> usize {
    (raw_blks * ratio_permille as usize / 1000).min(raw_blks.saturating_sub(1))
}

impl CompSpec {
    /// Chunk size in blocks; `None` = the spec cannot describe a chunk (`chunk_blks == 0`, only a hand-built spec has
    /// it: `PoolComp::resolve` clamps to 2..=64). Consumers take it as "do not compress".
    pub fn chunk_blocks(&self) -> Option<u64> {
        (self.chunk_blks > 0).then_some(self.chunk_blks as u64)
    }
}

/// Physical blocks a compressed chunk of `raw_blks` blocks is kept in when its compressed payload is `clen` bytes (plus the
/// 4-byte length header): it must meet `ratio_permille` and save at least one block. `None` = stored raw.
pub fn kept_blocks(raw_blks: usize, clen: usize, ratio_permille: u32) -> Option<usize> {
    let max_phys = max_phys_blocks(raw_blks, ratio_permille);
    let phys = (4 + clen).div_ceil(BLK);
    (max_phys > 0 && phys <= max_phys).then_some(phys)
}

/// Blocks the bytes `src` of an object, starting at block `first_blk`, would occupy when written with `cs` (deep-scrub
/// recompress estimate, dedup-reformat.md 7.1): split at chunk boundaries like the store's staging, every piece of at least
/// `min_bytes` that the incompressibility sample lets through compressed and kept by [`kept_blocks`], the rest raw.
/// Compresses for real; nothing is kept.
pub fn estimate_blocks<C: Codec>(codec: &mut C, cs: CompSpec, first_blk: u64, src: &[u8]) -> u64 {
    let nblk = src.len().div_ceil(BLK) as u64;
    let Some(c) = cs.chunk_blocks() else {
        return nblk; // a spec without a chunk size writes raw
    };
    let mut buf = vec![0u8; bound(c as usize * BLK)];
    let (mut pos, mut total) = (0u64, 0u64);
    while pos < nblk {
        let next = (first_blk + pos + 1).next_multiple_of(c) - first_blk;
        let stop = next.min(nblk);
        let piece = &src[pos as usize * BLK..(stop as usize * BLK).min(src.len())];
        let raw = (stop - pos) as usize;
        let kept = (piece.len() == raw * BLK
            && piece.len() >= cs.min_bytes as usize
            && kept_blocks(raw, 0, cs.ratio_permille).is_some()
            && !sample_incompressible(codec, cs, piece))
        .then(|| codec.compress(cs.alg, piece, &mut buf))
        .flatten()
        .and_then(|l| kept_blocks(raw, l, cs.ratio_permille));
        total += kept.unwrap_or(raw) as u64;
        pos = stop;
    }
    total
}

/// Output buffer size that always suffices for `n` input bytes (every algorithm's worst case).
pub fn bound(n: usize) -> usize {
    n + n / 4 + 128
}

/// Synchronous compressor. `dst` must be at least `bound(src.len())`; `None` = failed. The caller judges the size.
/// Standard formats only (lz4 block, zstd frame, snappy raw, raw deflate), so any implementation (a hardware
/// offload later) can produce what the software one reads.
pub trait Codec {
    fn compress(&mut self, alg: Alg, src: &[u8], dst: &mut [u8]) -> Option<usize>;
    /// Decompress into `dst`, which must be exactly the raw size.
    fn decompress(&mut self, alg: Alg, src: &[u8], dst: &mut [u8]) -> Option<usize>;
}

#[derive(Default)]
pub struct SoftCodec {
    zc: Option<zstd::bulk::Compressor<'static>>,
    zd: Option<zstd::bulk::Decompressor<'static>>,
    snappy: Option<snap::raw::Encoder>,
    deflate: Option<flate2::Compress>,
    inflate: Option<flate2::Decompress>,
}

impl std::fmt::Debug for SoftCodec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SoftCodec")
    }
}

/// zstd level, fixed at 1 (KISS, adr 0059); the key `compressor_zstd_level` is not honoured.
const ZSTD_LEVEL: i32 = 1;
/// lz4 acceleration (live bench: same ratio as 1 within 1 %, faster on mixed data; adr 0059 am. 2) and raw-deflate level.
const LZ4_ACCEL: i32 = 4;
const ZLIB_LEVEL: u32 = 1;

impl Codec for SoftCodec {
    fn compress(&mut self, alg: Alg, src: &[u8], dst: &mut [u8]) -> Option<usize> {
        match alg {
            Alg::Lz4 => lz4::block::compress_to_buffer(
                src,
                Some(lz4::block::CompressionMode::FAST(LZ4_ACCEL)),
                false,
                dst,
            )
            .ok(),
            Alg::Zstd => {
                if self.zc.is_none() {
                    self.zc = zstd::bulk::Compressor::new(ZSTD_LEVEL).ok();
                }
                self.zc.as_mut()?.compress_to_buffer(src, dst).ok()
            }
            Alg::Snappy => self
                .snappy
                .get_or_insert_with(snap::raw::Encoder::new)
                .compress(src, dst)
                .ok(),
            Alg::Zlib => {
                use flate2::{Compress, Compression, FlushCompress, Status};
                let c = self
                    .deflate
                    .get_or_insert_with(|| Compress::new(Compression::new(ZLIB_LEVEL), false));
                c.reset();
                let st = c.compress(src, dst, FlushCompress::Finish).ok()?;
                (st == Status::StreamEnd && c.total_in() == src.len() as u64)
                    .then_some(c.total_out() as usize)
            }
        }
    }

    fn decompress(&mut self, alg: Alg, src: &[u8], dst: &mut [u8]) -> Option<usize> {
        let n = match alg {
            Alg::Lz4 => {
                let n = dst.len() as i32;
                lz4::block::decompress_to_buffer(src, Some(n), dst).ok()?
            }
            Alg::Zstd => {
                if self.zd.is_none() {
                    self.zd = zstd::bulk::Decompressor::new().ok();
                }
                self.zd.as_mut()?.decompress_to_buffer(src, dst).ok()?
            }
            Alg::Snappy => snap::raw::Decoder::new().decompress(src, dst).ok()?,
            Alg::Zlib => {
                use flate2::{Decompress, FlushDecompress, Status};
                let d = self.inflate.get_or_insert_with(|| Decompress::new(false));
                d.reset(false);
                let st = d.decompress(src, dst, FlushDecompress::Finish).ok()?;
                if st != Status::StreamEnd {
                    return None;
                }
                d.total_out() as usize
            }
        };
        (n == dst.len()).then_some(n)
    }
}

impl SoftCodec {
    /// zstd can initialize Vec capacity directly; slice-only codecs reuse initialized storage.
    pub fn decompress_vec(
        &mut self,
        alg: Alg,
        src: &[u8],
        dst: &mut Vec<u8>,
        raw_len: usize,
    ) -> Option<usize> {
        if alg == Alg::Zstd {
            dst.clear();
            dst.reserve(raw_len);
            if self.zd.is_none() {
                self.zd = zstd::bulk::Decompressor::new().ok();
            }
            let n = self.zd.as_mut()?.decompress_to_buffer(src, dst).ok()?;
            return (n == raw_len).then_some(n);
        }
        dst.resize(raw_len, 0);
        self.decompress(alg, src, dst)
    }
}

/// Sample size of [`sample_incompressible`] (one block).
const SAMPLE: usize = crate::BLK;

/// Cheap pre-check before compressing a chunk (adr 0059 am. 1): compress one block from the start and one from the middle;
/// `true` = both stay above the required ratio (floor 0.95: a block compresses worse than the whole chunk), so the full
/// run would be rejected anyway and is skipped. Chunks under four blocks are not sampled. Costs two block compressions
/// (~1/8 of a 64 KiB chunk) on incompressible data and a little on compressible data.
pub fn sample_incompressible<C: Codec>(codec: &mut C, cs: CompSpec, src: &[u8]) -> bool {
    if src.len() < 4 * SAMPLE {
        return false;
    }
    let limit = cs.ratio_permille.clamp(950, 1000) as usize * SAMPLE / 1000;
    let mut dst = [0u8; SAMPLE + SAMPLE / 4 + 128];
    let mid = (src.len() / 2) / SAMPLE * SAMPLE;
    [0, mid].into_iter().all(|o| {
        codec
            .compress(cs.alg, &src[o..o + SAMPLE], &mut dst)
            .is_none_or(|n| n >= limit)
    })
}

/// Entries of [`DecompCache`] (each at most one chunk, 256 KiB).
pub const DCACHE_ENTRIES: usize = 4;

/// Decompressed chunks of recent reads, one per shard (one core; no locks): a few entries, round-robin replacement, so
/// small reads inside one chunk decompress it once. Keyed by the chunk's physical blocks (+ logical crc). Data extents
/// are never written in place, so a block's content is fixed while it is allocated; every free invalidates the entries it
/// overlaps (`forget`, called when the freeing txn is submitted) before the blocks can be reused. Scrub/fsck bypass it.
/// Entries are shared buffers: a read hands the decoded chunk to its reply by reference (no copy) and the cache keeps its
/// own reference.
#[derive(Debug, Default)]
pub struct DecompCache {
    /// `(pba, physical blocks, logical crc, decompressed bytes)`; zero blocks = invalid.
    ents: Vec<(u64, u32, u32, Bytes)>,
    next: usize,
}

impl DecompCache {
    /// The decoded chunk at `pba` with logical crc `lcrc` and `raw_len` decoded bytes (the length is part of the key:
    /// an all-zero chunk has logical crc 0 at any length).
    pub fn get(&self, pba: u64, lcrc: u32, raw_len: usize) -> Option<&Bytes> {
        self.ents
            .iter()
            .find(|e| e.1 != 0 && e.0 == pba && e.2 == lcrc && e.3.len() == raw_len)
            .map(|e| &e.3)
    }

    /// Take ownership of a decoded chunk (a reference, never a copy of the payload).
    pub fn put(&mut self, pba: u64, n: u32, lcrc: u32, data: Bytes) {
        let i = if let Some(i) = self.ents.iter().position(|e| e.1 == 0) {
            i
        } else if self.ents.len() < DCACHE_ENTRIES {
            self.ents.push((pba, n, lcrc, data));
            return;
        } else {
            let i = self.next % DCACHE_ENTRIES;
            self.next = self.next.wrapping_add(1);
            i
        };
        self.ents[i] = (pba, n, lcrc, data);
    }

    /// Invalidate every overlapping entry and drop its buffer.
    pub fn forget(&mut self, frees: &[(u64, u32)]) {
        if self.ents.is_empty() {
            return;
        }
        for e in &mut self.ents {
            if e.1 != 0
                && frees
                    .iter()
                    .any(|&(b, n)| b < e.0 + e.1 as u64 && e.0 < b + n as u64)
            {
                *e = (0, 0, 0, Bytes::new());
            }
        }
    }

    pub fn len(&self) -> usize {
        self.ents.iter().filter(|e| e.1 != 0).count()
    }

    /// Operator cache drop: invalidate every entry and release its buffer reference. Returns the entries and bytes dropped.
    pub fn clear(&mut self) -> (u64, u64) {
        let mut d = (0, 0);
        for e in &mut self.ents {
            if e.1 != 0 {
                d.0 += 1;
                d.1 += e.3.len() as u64;
            }
        }
        self.ents.clear();
        self.next = 0;
        d
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codec_measurement(require_no_alloc: bool) {
        let src = sample(65536);
        for alg in [Alg::Lz4, Alg::Zstd, Alg::Snappy, Alg::Zlib] {
            let mut c = SoftCodec::default();
            let mut compressed = vec![0; bound(src.len())];
            let mut decoded = vec![0; src.len()];
            let n = c.compress(alg, &src, &mut compressed).unwrap();
            c.decompress(alg, &compressed[..n], &mut decoded).unwrap();
            let start = std::time::Instant::now();
            let allocs = crate::test_alloc::allocations(|| {
                for _ in 0..50 {
                    let n = c.compress(alg, &src, &mut compressed).unwrap();
                    c.decompress(alg, &compressed[..n], &mut decoded).unwrap();
                    assert_eq!(decoded, src);
                }
            });
            let ns = start.elapsed().as_nanos() / 50;
            println!(
                "{alg:?} 64 KiB codec pair: {} Rust allocations/op, {ns} ns/op",
                allocs / 50
            );
            if require_no_alloc {
                assert_eq!(allocs, 0, "steady-state {alg:?} allocates");
            }
        }
    }

    #[test]
    #[ignore = "local debug codec allocation/CPU measurement"]
    fn codec_scratch_bench() {
        codec_measurement(false);
    }

    #[test]
    fn codec_steady_state_does_not_allocate() {
        codec_measurement(true);
    }

    #[test]
    fn decoded_cache_insertion_transfers_payload_ownership() {
        let data = Bytes::from(sample(65536));
        let ptr = data.as_ptr();
        let mut cache = DecompCache::default();
        cache.put(7, 1, 17, data);
        assert_eq!(
            cache.get(7, 17, 65536).unwrap().as_ptr(),
            ptr,
            "cache copied its payload"
        );
    }

    #[test]
    fn decoded_cache_drops_invalidated_entries_and_replaces_round_robin() {
        let data = Bytes::from(sample(4096));
        let mut cache = DecompCache::default();
        for i in 0..DCACHE_ENTRIES as u64 {
            cache.put(i, 1, 17, data.clone());
        }
        assert_eq!(cache.len(), DCACHE_ENTRIES);
        cache.forget(&[(2, 1)]);
        assert!(cache.get(2, 17, 4096).is_none());
        assert_eq!(cache.len(), DCACHE_ENTRIES - 1);
        cache.put(9, 1, 17, data.clone());
        assert!(cache.get(9, 17, 4096).is_some());
        assert_eq!(cache.len(), DCACHE_ENTRIES);
        for i in 20..24 {
            cache.put(i, 1, 17, data.clone());
        }
        assert!(cache.get(9, 17, 4096).is_none(), "round robin replaced it");
        assert!(cache.get(23, 17, 4096).is_some());
    }

    #[test]
    fn reusable_codec_state_handles_sizes_errors_and_existing_raw_deflate() {
        let mut codec = SoftCodec::default();
        let mut decoded = Vec::new();
        for alg in [Alg::Lz4, Alg::Zstd, Alg::Snappy, Alg::Zlib] {
            for n in [0, 4096, 65536, 8192, 262144, 16384] {
                let src = sample(n);
                let mut compressed = vec![0; bound(n)];
                let len = codec.compress(alg, &src, &mut compressed).unwrap();
                assert_eq!(
                    codec.decompress_vec(alg, &compressed[..len], &mut decoded, n),
                    Some(n)
                );
                assert_eq!(decoded, src);
                if alg == Alg::Zlib {
                    let legacy = miniz_oxide::deflate::compress_to_vec(&src, 1);
                    assert_eq!(codec.decompress_vec(alg, &legacy, &mut decoded, n), Some(n));
                    assert_eq!(
                        miniz_oxide::inflate::decompress_to_vec(&compressed[..len]).unwrap(),
                        src
                    );
                }
                let _ = codec.decompress_vec(alg, &[0xff; 8], &mut decoded, n);
                assert_eq!(
                    codec.decompress_vec(alg, &compressed[..len], &mut decoded, n),
                    Some(n)
                );
                assert_eq!(decoded, src, "failed decode poisoned reused {alg:?} state");
            }
        }
    }

    pub(crate) fn sample(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i / 7 % 13) as u8 ^ (i % 3) as u8).collect()
    }

    #[test]
    fn roundtrip_each_alg() {
        let src = sample(65536);
        let mut c = SoftCodec::default();
        for alg in [Alg::Lz4, Alg::Zstd, Alg::Snappy, Alg::Zlib] {
            let mut z = vec![0u8; bound(65536)];
            let n = c
                .compress(alg, &src, &mut z)
                .unwrap_or_else(|| panic!("{alg:?}"));
            assert!(n < 20000, "{alg:?} {n}");
            let mut out = vec![0u8; 65536];
            assert_eq!(c.decompress(alg, &z[..n], &mut out), Some(65536));
            assert_eq!(out, src, "{alg:?}");
            // wrong size / garbage never panics and is refused
            let mut small = vec![0u8; 100];
            assert_eq!(c.decompress(alg, &z[..n], &mut small), None);
            let mut g = z[..n].to_vec();
            g.iter_mut().step_by(5).for_each(|b| *b ^= 0xa5);
            let _ = c.decompress(alg, &g, &mut out);
            assert_eq!(Alg::from_u8(alg as u8), Some(alg));
        }
    }

    #[test]
    fn incompressible_stays_big() {
        let mut x = 0x1234_5678_9abc_def0u64;
        let src: Vec<u8> = (0..65536)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        let mut c = SoftCodec::default();
        for alg in [Alg::Lz4, Alg::Zstd, Alg::Snappy, Alg::Zlib] {
            let mut z = vec![0u8; bound(65536)];
            assert!(
                c.compress(alg, &src, &mut z).unwrap() > 65536 * 99 / 100,
                "{alg:?}"
            );
        }
    }

    #[test]
    fn sampling_skips_only_incompressible_chunks() {
        let mut c = SoftCodec::default();
        let cs = PoolComp::new(Mode::Force, Alg::Lz4).resolve(0).unwrap();
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let rnd: Vec<u8> = (0..65536)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        for alg in [Alg::Lz4, Alg::Zstd, Alg::Snappy, Alg::Zlib] {
            let cs = CompSpec { alg, ..cs };
            assert!(sample_incompressible(&mut c, cs, &rnd), "{alg:?}");
            assert!(
                !sample_incompressible(&mut c, cs, &sample(65536)),
                "{alg:?}"
            );
            // compressible data with an incompressible head block: the middle sample decides
            let mut mixed = sample(65536);
            mixed[..4096].copy_from_slice(&rnd[..4096]);
            assert!(!sample_incompressible(&mut c, cs, &mixed), "{alg:?}");
            // too small to sample
            assert!(!sample_incompressible(&mut c, cs, &rnd[..8192]));
        }
    }

    #[test]
    fn mode_semantics() {
        let mut p = PoolComp::new(Mode::None, Alg::Lz4);
        for h in [0, HINT_COMPRESSIBLE, HINT_INCOMPRESSIBLE] {
            assert!(p.resolve(h).is_none());
        }
        p.mode = Mode::Passive;
        assert!(p.resolve(0).is_none());
        assert!(p.resolve(HINT_INCOMPRESSIBLE).is_none());
        assert!(p.resolve(HINT_COMPRESSIBLE).is_some());
        p.mode = Mode::Aggressive;
        assert!(p.resolve(0).is_some());
        assert!(p.resolve(HINT_COMPRESSIBLE).is_some());
        assert!(p.resolve(HINT_INCOMPRESSIBLE).is_none());
        p.mode = Mode::Force;
        assert!(p.resolve(HINT_INCOMPRESSIBLE).is_some());
        assert_eq!(p.resolve(0).unwrap().chunk_blks, 16);
        assert_eq!(Mode::parse("bogus"), Mode::None);
        assert_eq!(Alg::parse("zstd"), Some(Alg::Zstd));
        assert_eq!(Alg::parse("brotli"), None);
    }

    #[test]
    fn decomp_cache_bounded_and_forgets_overlapping_frees() {
        let mut c = DecompCache::default();
        for i in 0..6u64 {
            c.put(i * 100, 4, i as u32, Bytes::from(vec![i as u8; 8]));
        }
        assert_eq!(c.len(), DCACHE_ENTRIES);
        assert!(
            c.get(0, 0, 8).is_none() && c.get(100, 1, 8).is_none(),
            "oldest replaced"
        );
        assert_eq!(c.get(500, 5, 8).map(|b| &b[..]), Some(&[5u8; 8][..]));
        assert!(c.get(500, 4, 8).is_none(), "logical crc is part of the key");
        assert!(
            c.get(500, 5, 16).is_none(),
            "decoded length is part of the key"
        );
        // a free of the last physical block of the chunk at 403 drops it; a free ending right before 500 does not
        c.forget(&[(403, 1), (496, 4)]);
        assert!(c.get(400, 4, 8).is_none());
        assert!(c.get(500, 5, 8).is_some());
        c.forget(&[(0, 1000)]);
        assert!(c.is_empty());
    }
}

#[cfg(test)]
mod lazy_tests {
    use super::*;

    #[test]
    fn lazy_modes_compress_only_reformat_writes() {
        for (name, client, reformat) in [
            ("none", [false, false, false], [false, false, false]),
            ("passive", [false, true, false], [false, true, false]),
            ("aggressive", [true, true, false], [true, true, false]),
            ("force", [true, true, true], [true, true, true]),
            ("passive_lazy", [false, false, false], [false, true, false]),
            (
                "aggressive_lazy",
                [false, false, false],
                [true, true, false],
            ),
            ("force_lazy", [false, false, false], [true, true, true]),
        ] {
            let p = PoolComp::new(Mode::parse(name), Alg::Lz4);
            // hints: none, COMPRESSIBLE, INCOMPRESSIBLE
            for (i, h) in [0, HINT_COMPRESSIBLE, HINT_INCOMPRESSIBLE]
                .into_iter()
                .enumerate()
            {
                assert_eq!(p.resolve(h).is_some(), client[i], "{name} client hint {h}");
                assert_eq!(
                    p.resolve_reformat(h).is_some(),
                    reformat[i],
                    "{name} reformat hint {h}"
                );
            }
        }
    }

    #[test]
    fn kept_blocks_rule() {
        // 16 blocks, ratio 0.875: at most 14 blocks kept
        assert_eq!(kept_blocks(16, 100, 875), Some(1));
        assert_eq!(kept_blocks(16, 14 * BLK - 4, 875), Some(14));
        assert_eq!(kept_blocks(16, 14 * BLK - 3, 875), None);
        // one block can never save a block
        assert_eq!(kept_blocks(1, 1, 1000), None);
    }
}
