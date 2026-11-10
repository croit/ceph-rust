// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Tree / omap compression measurements (adr 0021 am. 58, doc/perf/compression-20261017.md): realistic omap data sets
//! (RGW bucket index, CephFS dentries, RBD headers, random / compressible values) are built in a store; every leaf is
//! compacted and compressed offline with LZ4 / snappy / zstd -1 to get ratio and ns per page, plus the physical bytes
//! under 4 KiB / 1 KiB allocation granularity; per-value LZ4 is measured on the same values.
//! Run: `cargo test --release -p store --test comp -- --ignored --nocapture --test-threads=1`
//! (env `COMP_N` entries per data set, default 120000; `COMP_ONLY` substring).
#[path = "common/objmodel.rs"]
mod objmodel;

use denc::types::{Ghobject, Hobject, ShardId, SnapId};
use std::time::Instant;
use store::dev::{SimClock, SimConfig, SimDev, SimDisk};
use store::layout::{MkfsParams, mkfs};
use store::obj::{OTxn, Store, StoreCfg};
use store::page;
use store::rng::Rng;

type St = Store<SimDev, SimClock>;

fn g(oid: &[u8]) -> Ghobject {
    Ghobject::new(
        Hobject::new(oid, SnapId::NOSNAP, 7, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}

fn rig(cap_mib: u64) -> St {
    rig_vc(cap_mib, 0)
}

fn rig_vc(cap_mib: u64, vc_min: u32) -> St {
    let mut sim = SimConfig::new(cap_mib << 20);
    sim.seed = 7;
    let disk = SimDisk::new(sim);
    let p = MkfsParams {
        shards: 1,
        wal_blocks: store::layout::wal_blocks_for(cap_mib << 20, 1),
        align_blocks: 256,
        meta_pct: 4,
        ..Default::default()
    };
    mkfs(&mut disk.queue(), &mut SimClock::default(), &p).unwrap();
    let mut cfg = StoreCfg::default();
    cfg.shard.val_comp_min = vc_min;
    cfg.shard.cache_pages = 4 << 20;
    let d2 = disk.clone();
    Store::mount(move || d2.queue(), SimClock::default(), cfg)
        .unwrap()
        .0
}

fn hex(rng: &mut Rng, n: usize) -> Vec<u8> {
    (0..n)
        .map(|_| b"0123456789abcdef"[(rng.next_u64() & 15) as usize])
        .collect()
}

fn lp(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s);
}

/// RGW bucket index entry (`rgw_bucket_dir_entry`-shaped): name repeated, instance, 32 hex etag, size, mtime, owner,
/// content type, storage class, tag, zeros. ~250-300 B.
fn rgw_val(rng: &mut Rng, name: &[u8], i: u64) -> Vec<u8> {
    let mut v = vec![8, 3];
    v.extend_from_slice(&[0, 0, 0, 0]);
    lp(&mut v, name);
    lp(&mut v, b"");
    v.extend_from_slice(&(1u64 + i % 7).to_le_bytes());
    v.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0]);
    v.extend_from_slice(&(1_700_000_000u32 + (i / 3) as u32).to_le_bytes());
    v.extend_from_slice(&((rng.next_u64() as u32) % 1_000_000_000).to_le_bytes());
    lp(&mut v, &hex(rng, 32));
    v.extend_from_slice(&(rng.next_u64() % (64 << 20)).to_le_bytes());
    lp(&mut v, b"testuser-0001");
    lp(&mut v, b"Test User Display Name");
    lp(&mut v, b"application/octet-stream");
    v.extend_from_slice(&(rng.next_u64() % (64 << 20)).to_le_bytes());
    v.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]);
    lp(&mut v, b"STANDARD");
    lp(&mut v, &[b"tag."[..].to_vec(), hex(rng, 28)].concat());
    v.extend_from_slice(&[0u8; 24]);
    v
}

/// CephFS dentry value: 'i' + inode_t (ino, mode, uid/gid, 3 timestamps, size, layout, dirstat/rstat zeros, ...). ~400 B.
fn cfs_val(rng: &mut Rng, i: u64, hdr: bool) -> Vec<u8> {
    // hdr: type byte + fixed struct version / compat / length like the real encoding; without it the (varying) inode number follows
    // the type byte at once (adversarial: a value class taken from the first bytes fragments)
    let mut v = vec![b'i'];
    if hdr {
        v.extend_from_slice(&[2, 1, 0x90, 1, 0, 0]);
    }
    v.extend_from_slice(&(0x10000000000u64 + i * 2 + (rng.next_u64() & 1)).to_le_bytes());
    v.extend_from_slice(&[0u8; 8]);
    v.extend_from_slice(&0o100644u32.to_le_bytes());
    v.extend_from_slice(&1000u32.to_le_bytes());
    v.extend_from_slice(&1000u32.to_le_bytes());
    for t in 0..3u32 {
        v.extend_from_slice(&(1_700_000_000u32 + (i / 50) as u32 + t).to_le_bytes());
        v.extend_from_slice(&((rng.next_u64() as u32) % 1_000_000_000).to_le_bytes());
    }
    v.extend_from_slice(&(rng.next_u64() % (1 << 24)).to_le_bytes());
    v.extend_from_slice(&[0, 0, 0x40, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0x40, 0]);
    v.extend_from_slice(&[0u8; 80]);
    v.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]);
    v.extend_from_slice(&[0u8; 200]);
    v
}

struct Ds {
    name: &'static str,
    /// (key, value) in insertion order
    kv: Vec<(Vec<u8>, Vec<u8>)>,
}

fn shuffle(v: &mut [(Vec<u8>, Vec<u8>)], seed: u64) {
    let mut r = Rng::new(seed);
    for i in (1..v.len()).rev() {
        v.swap(i, (r.next_u64() % (i as u64 + 1)) as usize);
    }
}

fn datasets(n: usize) -> Vec<Ds> {
    let mut rng = Rng::new(1);
    let mut out = Vec::new();
    // RGW: hierarchical object names with long shared prefixes
    let rgw = |rng: &mut Rng| {
        (0..n)
            .map(|i| {
                let name = format!(
                    "backups/2026/{:02}/{:02}/host-{:03}/snapshots/volume-{:05}/chunk-{:010}.bin",
                    1 + i / 40000 % 12,
                    1 + i / 1300 % 28,
                    i / 400 % 100,
                    i / 90 % 1000,
                    i
                );
                let v = rgw_val(rng, name.as_bytes(), i as u64);
                (name.into_bytes(), v)
            })
            .collect::<Vec<_>>()
    };
    out.push(Ds {
        name: "rgw-seq",
        kv: rgw(&mut rng),
    });
    let mut s = rgw(&mut rng);
    shuffle(&mut s, 3);
    out.push(Ds {
        name: "rgw-shuf",
        kv: s,
    });
    // RGW with flat uuid-like names (hash-like order)
    let u: Vec<_> = (0..n)
        .map(|i| {
            let mut r2 = Rng::new(i as u64 + 99);
            let name = String::from_utf8(hex(&mut r2, 40)).unwrap();
            let v = rgw_val(&mut rng, name.as_bytes(), i as u64);
            (name.into_bytes(), v)
        })
        .collect();
    out.push(Ds {
        name: "rgw-hash",
        kv: u,
    });
    // CephFS dirfrag: "<name>_head"; realistic (fixed type byte, struct version, length first) and adversarial (inode number right after the type byte)
    for (name, hdr) in [("cephfs-real", true), ("cephfs-adv", false)] {
        let c: Vec<_> = (0..n)
            .map(|i| {
                let name = format!("file_{i:07}.dat_head");
                (name.into_bytes(), cfs_val(&mut rng, i as u64, hdr))
            })
            .collect();
        out.push(Ds { name, kv: c });
    }
    // RBD-like small values (snapshots / children / metadata): 60-120 B, short keys
    let r: Vec<_> = (0..n)
        .map(|i| {
            let k = format!("snapshot_{:016x}", i);
            let mut v = vec![0u8; 8];
            v[..8].copy_from_slice(&(i as u64).to_le_bytes());
            lp(&mut v, format!("snap-{i}").as_bytes());
            v.extend_from_slice(&(10u64 << 30).to_le_bytes());
            v.extend_from_slice(&[0u8; 40]);
            (k.into_bytes(), v)
        })
        .collect();
    out.push(Ds {
        name: "rbd-small",
        kv: r,
    });
    // random values 100-1000 B and highly compressible text values, short seq keys
    let rv: Vec<_> = (0..n)
        .map(|i| {
            let mut v = vec![0u8; 100 + (rng.next_u64() % 900) as usize];
            rng.fill(&mut v);
            (format!("key_{i:08}").into_bytes(), v)
        })
        .collect();
    out.push(Ds {
        name: "random-100-1000",
        kv: rv,
    });
    let cv: Vec<_> = (0..n)
        .map(|i| {
            let len = 100 + (rng.next_u64() % 900) as usize;
            let v: Vec<u8> = b"The quick brown fox jumps over the lazy dog. "
                .iter()
                .cycle()
                .take(len)
                .copied()
                .collect();
            (format!("key_{i:08}").into_bytes(), v)
        })
        .collect();
    out.push(Ds {
        name: "text-100-1000",
        kv: cv,
    });
    out
}

#[derive(Default)]
struct Acc {
    pages: u64,
    used: u64,
    lz4: u64,
    snap: u64,
    zstd: u64,
    t4k: [u64; 3], // lz4 physical bytes at 4 KiB / 2 KiB / 1 KiB granularity (min = granule, max = raw page)
    ns: [u64; 4],  // compress lz4 / snap / zstd, decompress lz4
}

fn gran(n: usize, g: usize, raw: usize) -> u64 {
    (n.div_ceil(g) * g).min(raw) as u64
}

fn measure(st: &mut St, acc: &mut Acc) {
    let mut zc = zstd::bulk::Compressor::new(1).unwrap();
    let mut sn = snap::raw::Encoder::new();
    for s in &mut st.shards {
        let sh = s.sh.state();
        let mut imgs: Vec<Vec<u8>> = Vec::new();
        sh.tree.leaf_images(&mut |b| {
            // compacted clean image (what a page codec would be given): rebuild from the entries
            let mut e = page::Ents::default();
            e.load(b);
            let mut c = vec![0u8; b.len()];
            page::init(&mut c, page::LEAF, 0, 0, 0);
            assert!(page::build(&mut c, &e, 0, e.len(), 0));
            imgs.push(c);
        });
        for img in &imgs {
            // the used part only: header + prefix + slots, and the heap
            let used = img.len() - page::free_total(img);
            let mut out = vec![0u8; lz4_flex::block::get_maximum_output_size(img.len())];
            let t = Instant::now();
            let l = lz4_flex::block::compress_into(img, &mut out).unwrap();
            acc.ns[0] += t.elapsed().as_nanos() as u64;
            let mut back = vec![0u8; img.len()];
            let t = Instant::now();
            lz4_flex::block::decompress_into(&out[..l], &mut back).unwrap();
            acc.ns[3] += t.elapsed().as_nanos() as u64;
            assert_eq!(&back, img);
            let t = Instant::now();
            let sc = sn.compress_vec(img).unwrap().len();
            acc.ns[1] += t.elapsed().as_nanos() as u64;
            let t = Instant::now();
            let zl = zc.compress(img).unwrap().len();
            acc.ns[2] += t.elapsed().as_nanos() as u64;
            acc.pages += 1;
            acc.used += used as u64;
            acc.lz4 += l as u64;
            acc.snap += sc as u64;
            acc.zstd += zl as u64;
            for (i, gz) in [4096, 2048, 1024].into_iter().enumerate() {
                acc.t4k[i] += gran(l + 8, gz, img.len());
            }
        }
    }
}

#[test]
#[ignore = "measurement"]
fn comp_leaf_ratios() {
    let n: usize = std::env::var("COMP_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(120_000);
    let only = std::env::var("COMP_ONLY").unwrap_or_default();
    for ds in datasets(n) {
        if !ds.name.contains(&only) {
            continue;
        }
        let mut st = rig(8192);
        let cid = objmodel::pgc(1, 0);
        let mut t = OTxn::new();
        t.mkcoll(cid);
        st.commit(&t).unwrap();
        let o = g(b"omapobj");
        let t0 = Instant::now();
        let mut logical = 0u64;
        for ch in ds.kv.chunks(200) {
            let mut t = OTxn::new();
            t.touch(cid, &o);
            for (k, v) in ch {
                t.omap_set(cid, &o, k, v);
                logical += (k.len() + v.len()) as u64;
            }
            st.commit(&t).unwrap();
        }
        let el = t0.elapsed();
        let mut acc = Acc::default();
        let sh0 = st.shards[0].sh.state().tree.shape();
        measure(&mut st, &mut acc);
        // per-value LZ4 (values >= 64 B), ns per value
        let (mut vin, mut vout, mut vns, mut nv) = (0u64, 0u64, 0u64, 0u64);
        let mut buf = vec![0u8; 4096];
        for (_, v) in &ds.kv {
            if v.len() >= 64 {
                let t = Instant::now();
                let l = lz4_flex::block::compress_into(v, &mut buf).unwrap_or(v.len());
                vns += t.elapsed().as_nanos() as u64;
                vin += v.len() as u64;
                vout += (l.min(v.len())) as u64;
                nv += 1;
            }
        }
        let raw = acc.pages * 8192;
        eprintln!(
            "== {}: {} entries, logical {:.1} MiB, build {:.2} s ({:.0} ns/entry)\n   leaves {} fill {:.1}% (used {:.1} MiB of {:.1}) tree bytes/logical {:.3} | sfx {} lcp {} ({:.1}% of key bytes front-codable), vals {}",
            ds.name,
            ds.kv.len(),
            logical as f64 / 1048576.0,
            el.as_secs_f64(),
            el.as_nanos() as f64 / ds.kv.len() as f64,
            acc.pages,
            100.0 * acc.used as f64 / raw as f64,
            acc.used as f64 / 1048576.0,
            raw as f64 / 1048576.0,
            raw as f64 / logical as f64,
            sh0.leaf_sfx,
            sh0.leaf_lcp,
            100.0 * sh0.leaf_lcp as f64 / sh0.leaf_sfx.max(1) as f64,
            sh0.leaf_val
        );
        let p = |x: u64| 100.0 * x as f64 / raw as f64;
        eprintln!(
            "   leaf codec (percent of 8 KiB pages; ns/page): lz4 {:.1}% {} ns (dec {} ns) | snappy {:.1}% {} ns | zstd1 {:.1}% {} ns | lz4 @4K gran {:.1}% @2K {:.1}% @1K {:.1}%",
            p(acc.lz4),
            acc.ns[0] / acc.pages.max(1),
            acc.ns[3] / acc.pages.max(1),
            p(acc.snap),
            acc.ns[1] / acc.pages.max(1),
            p(acc.zstd),
            acc.ns[2] / acc.pages.max(1),
            p(acc.t4k[0]),
            p(acc.t4k[1]),
            p(acc.t4k[2])
        );
        eprintln!(
            "   per-value lz4 (>= 64 B): {} vals, {:.1}% of value bytes, {} ns/val; value bytes are {:.0}% of leaf bytes",
            nv,
            100.0 * vout as f64 / vin.max(1) as f64,
            vns / nv.max(1),
            100.0 * sh0.leaf_val as f64 / acc.used.max(1) as f64
        );
    }
}

fn build(ds: &Ds) -> St {
    let mut st = rig(8192);
    let cid = objmodel::pgc(1, 0);
    let mut t = OTxn::new();
    t.mkcoll(cid);
    st.commit(&t).unwrap();
    let o = g(b"omapobj");
    for ch in ds.kv.chunks(200) {
        let mut t = OTxn::new();
        t.touch(cid, &o);
        for (k, v) in ch {
            t.omap_set(cid, &o, k, v);
        }
        st.commit(&t).unwrap();
    }
    st
}

fn leaf_imgs(st: &mut St) -> Vec<Vec<u8>> {
    let mut imgs = Vec::new();
    for s in &mut st.shards {
        s.sh.state().tree.leaf_images(&mut |b| {
            let mut e = page::Ents::default();
            e.load(b);
            let mut c = vec![0u8; b.len()];
            page::init(&mut c, page::LEAF, 0, 0, 0);
            assert!(page::build(&mut c, &e, 0, e.len(), 0));
            imgs.push(c);
        });
    }
    imgs
}

type Df = Box<dyn Fn(&[u8], usize, &mut [u8]) -> usize>;
type Cf<'a> = Box<dyn FnMut(&[u8], &mut [u8]) -> usize + 'a>;

/// Time `f` over all inputs (best of 3 passes), returns (compressed bytes, ns per input).
fn run_c(inputs: &[&[u8]], out: &mut [u8], f: &mut Cf) -> (u64, u64) {
    let mut best = u64::MAX;
    let mut tot = 0;
    for _ in 0..3 {
        tot = 0;
        let t = Instant::now();
        for i in inputs {
            tot += f(i, out) as u64;
        }
        best = best.min(t.elapsed().as_nanos() as u64);
    }
    (tot, best / inputs.len().max(1) as u64)
}

#[test]
#[ignore = "measurement"]
fn comp_codecs() {
    use lz4::block::{CompressionMode, compress_to_buffer, decompress_to_buffer};
    let n: usize = std::env::var("COMP_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30_000);
    let only = std::env::var("COMP_ONLY").unwrap_or_default();
    for ds in datasets(n) {
        if !ds.name.contains(&only) {
            continue;
        }
        let mut st = build(&ds);
        let imgs = leaf_imgs(&mut st);
        let vals: Vec<&[u8]> = ds
            .kv
            .iter()
            .filter(|(_, v)| v.len() >= 64)
            .map(|(_, v)| &v[..])
            .collect();
        let pages: Vec<&[u8]> = imgs.iter().map(|v| &v[..]).collect();
        eprintln!(
            "== {} ({} pages, {} values)",
            ds.name,
            pages.len(),
            vals.len()
        );
        for (what, inputs) in [("page 8K", &pages), ("value", &vals)] {
            let raw: u64 = inputs.iter().map(|x| x.len() as u64).sum();
            let mut out = vec![0u8; 1 << 16];
            let mut codecs: Vec<(&str, Cf, Df)> = vec![
                (
                    "lz4_flex",
                    Box::new(|i, o| lz4_flex::block::compress_into(i, o).unwrap()),
                    Box::new(|c, n, o| lz4_flex::block::decompress_into(&c[..n], o).unwrap()),
                ),
                (
                    "lz4C def",
                    Box::new(|i, o| {
                        compress_to_buffer(i, Some(CompressionMode::DEFAULT), false, o).unwrap()
                    }),
                    Box::new(|c, n, o| {
                        decompress_to_buffer(&c[..n], Some(o.len() as i32), o).unwrap()
                    }),
                ),
                (
                    "lz4C fast4",
                    Box::new(|i, o| {
                        compress_to_buffer(i, Some(CompressionMode::FAST(4)), false, o).unwrap()
                    }),
                    Box::new(|c, n, o| {
                        decompress_to_buffer(&c[..n], Some(o.len() as i32), o).unwrap()
                    }),
                ),
                (
                    "lz4C fast16",
                    Box::new(|i, o| {
                        compress_to_buffer(i, Some(CompressionMode::FAST(16)), false, o).unwrap()
                    }),
                    Box::new(|c, n, o| {
                        decompress_to_buffer(&c[..n], Some(o.len() as i32), o).unwrap()
                    }),
                ),
                (
                    "snappy",
                    {
                        let mut e = snap::raw::Encoder::new();
                        Box::new(move |i, o| e.compress(i, o).unwrap())
                    },
                    {
                        let mut d = snap::raw::Decoder::new();
                        let d = std::cell::RefCell::new(&mut d as *mut _);
                        let _ = d;
                        Box::new(|c, n, o| {
                            snap::raw::Decoder::new().decompress(&c[..n], o).unwrap()
                        })
                    },
                ),
                (
                    "fastlz1",
                    {
                        let mut e = fastlz_rs::CompressState::new_boxed();
                        Box::new(move |i, o| {
                            e.compress_to_buf(i, o, fastlz_rs::CompressionLevel::Level1)
                                .unwrap()
                        })
                    },
                    Box::new(|c, n, o| fastlz_rs::decompress_to_buf(&c[..n], o).unwrap()),
                ),
                (
                    "zstd-5",
                    {
                        let mut z = zstd::bulk::Compressor::new(-5).unwrap();
                        Box::new(move |i, o| z.compress_to_buffer(i, o).unwrap())
                    },
                    Box::new(|c, n, o| {
                        zstd::bulk::Decompressor::new()
                            .unwrap()
                            .decompress_to_buffer(&c[..n], o)
                            .unwrap()
                    }),
                ),
                (
                    "zstd1",
                    {
                        let mut z = zstd::bulk::Compressor::new(1).unwrap();
                        Box::new(move |i, o| z.compress_to_buffer(i, o).unwrap())
                    },
                    Box::new(|c, n, o| {
                        zstd::bulk::Decompressor::new()
                            .unwrap()
                            .decompress_to_buffer(&c[..n], o)
                            .unwrap()
                    }),
                ),
            ];
            for (name, cf, df) in codecs.iter_mut() {
                let (csz, cns) = run_c(inputs, &mut out, cf);
                // decompress timing: compress all first, then time decodes
                let comp: Vec<(Vec<u8>, usize)> = inputs
                    .iter()
                    .map(|i| {
                        let n = cf(i, &mut out);
                        (out[..n].to_vec(), i.len())
                    })
                    .collect();
                let mut best = u64::MAX;
                let mut buf = vec![0u8; 1 << 16];
                for _ in 0..3 {
                    let t = Instant::now();
                    for (c, l) in &comp {
                        df(c, c.len(), &mut buf[..*l]);
                    }
                    best = best.min(t.elapsed().as_nanos() as u64);
                }
                // size-aware: a value that does not shrink is stored raw
                eprintln!(
                    "   {what:8} {name:12} ratio {:5.1}% comp {:6} ns dec {:6} ns",
                    100.0 * csz as f64 / raw as f64,
                    cns,
                    best / comp.len().max(1) as u64
                );
            }
        }
    }
}

/// End to end value path: build / scan / point-get cost and tree size with `val_comp_min` 0 (off) vs 64 (on).
/// The WAL record carries the compressed value, so the bytes per entry are reported too.
#[test]
#[ignore = "measurement"]
fn comp_value_path() {
    let n: usize = std::env::var("COMP_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60_000);
    let only = std::env::var("COMP_ONLY").unwrap_or_default();
    for ds in datasets(n) {
        if !ds.name.contains(&only) {
            continue;
        }
        let logical: u64 = ds.kv.iter().map(|(k, v)| (k.len() + v.len()) as u64).sum();
        for vc in [0u32, 64] {
            let mut st = rig_vc(8192, vc);
            let cid = objmodel::pgc(1, 0);
            let mut t = OTxn::new();
            t.mkcoll(cid);
            st.commit(&t).unwrap();
            let o = g(b"omapobj");
            let t0 = Instant::now();
            for ch in ds.kv.chunks(200) {
                let mut t = OTxn::new();
                t.touch(cid, &o);
                for (k, v) in ch {
                    t.omap_set(cid, &o, k, v);
                }
                st.commit(&t).unwrap();
            }
            let build = t0.elapsed().as_nanos() as u64 / ds.kv.len() as u64;
            let t0 = Instant::now();
            let all = st.omap_all(&cid, &o).unwrap();
            let scan = t0.elapsed().as_nanos() as u64 / ds.kv.len() as u64;
            assert_eq!(all.len(), ds.kv.len());
            let mut rng = Rng::new(3);
            let m = 20_000usize;
            let t0 = Instant::now();
            for _ in 0..m {
                let (k, v) = &ds.kv[(rng.next_u64() % ds.kv.len() as u64) as usize];
                let got = st.omap_get(&cid, &o, &[k.as_slice()]).unwrap();
                assert_eq!(got.get(k), Some(v));
            }
            let get = t0.elapsed().as_nanos() as u64 / m as u64;
            let sh = st.shards[0].sh.state().tree.shape();
            let stats = &st.shards[0].stats;
            eprintln!(
                "{:16} vc_min {:2}: build {:5} ns/entry, scan {:5} ns/entry, get {:5} ns | tree leaves {:.1} MiB = {:.3} x logical ({:.1} MiB) | comp {} saved {:.1} MiB",
                ds.name,
                vc,
                build,
                scan,
                get,
                (sh.leaves * 8192) as f64 / 1048576.0,
                (sh.leaves * 8192) as f64 / logical as f64,
                logical as f64 / 1048576.0,
                stats.val_comp,
                stats.val_comp_saved as f64 / 1048576.0
            );
        }
    }
}

/// Key as LZ4 dictionary for the value (RGW entries repeat the object name inside the value).
#[test]
#[ignore = "measurement"]
fn comp_key_dict() {
    let n = 30_000;
    for ds in datasets(n) {
        let raw: u64 = ds.kv.iter().map(|(_, v)| v.len() as u64).sum();
        let mut out = vec![0u8; 1 << 16];
        let mut back = vec![0u8; 1 << 16];
        let mut enc = snap::raw::Encoder::new();
        let mut res = vec![];
        // snappy plain
        let t = Instant::now();
        let mut tot = 0u64;
        for (_, v) in &ds.kv {
            tot += enc.compress(v, &mut out).unwrap() as u64;
        }
        res.push(("snappy", tot, t.elapsed().as_nanos() as u64, 0u64));
        let t = Instant::now();
        let mut tot = 0u64;
        for (_, v) in &ds.kv {
            tot += lz4_flex::block::compress_into(v, &mut out).unwrap() as u64;
        }
        res.push(("lz4", tot, t.elapsed().as_nanos() as u64, 0));
        let t = Instant::now();
        let mut tot = 0u64;
        let mut comp = vec![];
        for (k, v) in &ds.kv {
            let l = lz4_flex::block::compress_into_with_dict(v, &mut out, k).unwrap();
            tot += l as u64;
            comp.push(out[..l].to_vec());
        }
        let ct = t.elapsed().as_nanos() as u64;
        let t = Instant::now();
        for ((k, v), c) in ds.kv.iter().zip(&comp) {
            let l = lz4_flex::block::decompress_into_with_dict(c, &mut back[..v.len()], k).unwrap();
            assert_eq!(&back[..l], &v[..]);
        }
        res.push(("lz4+keydict", tot, ct, t.elapsed().as_nanos() as u64));
        for (name, tot, ct, dt) in res {
            eprintln!(
                "{:16} {:12} ratio {:5.1}% comp {:4} ns dec {:4} ns",
                ds.name,
                name,
                100.0 * tot as f64 / raw as f64,
                ct / ds.kv.len() as u64,
                dt / ds.kv.len() as u64
            );
        }
    }
}

/// Dictionary = per-object template value (the first value) + key: potential of a per-omap template.
#[test]
#[ignore = "measurement"]
fn comp_template_dict() {
    for ds in datasets(30_000) {
        let raw: u64 = ds.kv.iter().map(|(_, v)| v.len() as u64).sum();
        let mut out = vec![0u8; 1 << 16];
        let tpl = &ds.kv[ds.kv.len() / 2].1;
        let (mut a, mut b) = (0u64, 0u64);
        let t = Instant::now();
        for (k, v) in &ds.kv {
            let mut d = tpl.clone();
            d.extend_from_slice(k);
            a += lz4_flex::block::compress_into_with_dict(v, &mut out, &d).unwrap() as u64;
        }
        let ns = t.elapsed().as_nanos() as u64 / ds.kv.len() as u64;
        for (k, v) in &ds.kv {
            b += lz4_flex::block::compress_into_with_dict(v, &mut out, k).unwrap() as u64;
        }
        eprintln!(
            "{:16} key-dict {:5.1}%  template+key dict {:5.1}% ({} ns incl. dict build)",
            ds.name,
            100.0 * b as f64 / raw as f64,
            100.0 * a as f64 / raw as f64,
            ns
        );
    }
}

/// Pool-compression space: one 64 KiB chunk of the `oprobe fill --cpct 50` pattern (2 KiB random + 2 KiB repeating text per
/// block) per codec: payload bytes and physical blocks. BlueStore rounds the same payload to 4 KiB units.
#[test]
#[ignore = "measurement"]
fn comp_chunk_sizes() {
    use store::compress::{Alg, Codec, SoftCodec, bound};
    const T: &[u8] = b"the quick brown fox jumps over the lazy dog 0123456789 ABCDEFGH ";
    let mut rng = Rng::new(7);
    let mut src = Vec::new();
    while src.len() < 65536 {
        let blk = src.len();
        for _ in 0..2048 / 8 {
            src.extend_from_slice(&rng.next_u64().to_le_bytes());
        }
        while src.len() < blk + 4096 {
            let k = (blk + 4096 - src.len()).min(T.len());
            src.extend_from_slice(&T[..k]);
        }
    }
    let mut c = SoftCodec::default();
    for alg in [Alg::Lz4, Alg::Snappy, Alg::Zstd, Alg::Zlib] {
        let mut dst = vec![0u8; bound(src.len())];
        let n = c.compress(alg, &src, &mut dst).unwrap();
        eprintln!("{alg:?}: {n} B, {} blocks of 16", (4 + n).div_ceil(4096));
    }
}

/// Per-value coding variants on the RGW-like sets: mean coded value bytes (LZ4 against `template ++ key` as stored today, against
/// `template ++ previous value ++ key`, zstd -1 with a raw-content dictionary) next to the entropy floor of the random fields.
#[test]
#[ignore = "measurement"]
fn comp_value_variants() {
    for ds in datasets(30_000) {
        if !ds.name.starts_with("rgw") {
            continue;
        }
        let tpl = &ds.kv[ds.kv.len() / 2].1[..];
        let raw: u64 = ds.kv.iter().map(|(_, v)| v.len() as u64).sum();
        let mut out = vec![0u8; 1 << 16];
        let (mut a, mut b, mut z) = (0u64, 0u64, 0u64);
        let mut zc = zstd::bulk::Compressor::new(1).unwrap();
        for (i, (k, v)) in ds.kv.iter().enumerate() {
            let mut d = tpl.to_vec();
            d.extend_from_slice(k);
            a += lz4_flex::block::compress_into_with_dict(v, &mut out, &d).unwrap() as u64;
            let mut d = tpl.to_vec();
            if i > 0 {
                d.extend_from_slice(&ds.kv[i - 1].1);
            }
            d.extend_from_slice(k);
            b += lz4_flex::block::compress_into_with_dict(v, &mut out, &d).unwrap() as u64;
            z += zc.compress_to_buffer(v, &mut out[..]).unwrap() as u64;
        }
        for w in [8usize, 24, 48] {
            let (mut l, mut zs, mut cnt) = (0u64, 0u64, 0u64);
            for ch in ds.kv.chunks(w) {
                let mut buf = Vec::new();
                for (k, v) in ch {
                    buf.extend_from_slice(k);
                    buf.extend_from_slice(v);
                }
                l += lz4_flex::block::compress_into(&buf, &mut out).unwrap() as u64;
                zs += zc.compress_to_buffer(&buf, &mut out[..]).unwrap() as u64;
                cnt += ch.len() as u64;
            }
            eprintln!(
                "{:10} window {w}: lz4 {:.1} B/entry (key+value), zstd1 {:.1}",
                ds.name,
                l as f64 / cnt as f64,
                zs as f64 / cnt as f64
            );
        }
        {
            let mut back = vec![0u8; 4096];
            let mut cc = zstd::zstd_safe::CCtx::create();
            let mut dc = zstd::zstd_safe::DCtx::create();
            let (mut zt, mut t_c, mut t_d) = (0u64, 0u128, 0u128);
            for (k, v) in ds.kv.iter() {
                let mut d = tpl.to_vec();
                d.extend_from_slice(k);
                let t = Instant::now();
                cc.set_parameter(zstd::zstd_safe::CParameter::CompressionLevel(1))
                    .unwrap();
                cc.set_parameter(zstd::zstd_safe::CParameter::ChecksumFlag(false))
                    .unwrap();
                cc.set_parameter(zstd::zstd_safe::CParameter::ContentSizeFlag(false))
                    .unwrap();
                let n = cc.compress_using_dict(&mut out[..], v, &d, 1).unwrap();
                t_c += t.elapsed().as_nanos();
                zt += n as u64;
                let t = Instant::now();
                let m = dc
                    .decompress_using_dict(&mut back[..], &out[..n], &d)
                    .unwrap();
                t_d += t.elapsed().as_nanos();
                assert_eq!(&back[..m], &v[..]);
            }
            let c = ds.kv.len() as f64;
            eprintln!(
                "{:10} zstd1 prefix(tpl+key) {:.1} B/value comp {:.0} ns dec {:.0} ns",
                ds.name,
                zt as f64 / c,
                t_c as f64 / c,
                t_d as f64 / c
            );
        }
        let n = ds.kv.len() as f64;
        eprintln!(
            "{:10} raw {:.0} B/value: lz4 tpl+key {:.1}  lz4 tpl+prev+key {:.1}  zstd1 plain {:.1}",
            ds.name,
            raw as f64 / n,
            a as f64 / n,
            b as f64 / n,
            z as f64 / n
        );
    }
}
/// `oprobe fill --structured` shape (many objects x 100 RGW-index-like keys, one op per object): tree bytes per logical byte
/// and the per-entry breakdown of the leaves. `COMP_OBJS` objects (default 2000).
#[test]
#[ignore = "measurement"]
fn comp_fill_like() {
    let objs: u64 = std::env::var("COMP_OBJS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2000);
    let mut rng = Rng::new(5);
    let mut st = rig_vc(8192, 64);
    let cid = objmodel::pgc(1, 0);
    let mut t = OTxn::new();
    t.mkcoll(cid);
    st.commit(&t).unwrap();
    let mut logical = 0u64;
    for idx in 0..objs {
        let o = g(format!("c-{idx:08}").as_bytes());
        let mut kv = Vec::new();
        for i in 0..100u64 {
            let key = format!(
                "backups/2026/{:02}/host-{:03}/snapshots/volume-{:05}/chunk-{:010}.bin",
                1 + idx % 12,
                idx / 12 % 100,
                idx / 7 % 1000,
                idx * 1000 + i
            )
            .into_bytes();
            let name = String::from_utf8(key.clone()).unwrap();
            let v = rgw_val(&mut rng, name.as_bytes(), idx * 100 + i);
            logical += (key.len() + v.len()) as u64;
            kv.push((key, v));
        }
        let mut t = OTxn::new();
        t.touch(cid, &o);
        for (k, v) in &kv {
            t.omap_set(cid, &o, k, v);
        }
        st.commit(&t).unwrap();
    }
    st.checkpoint().unwrap();
    {
        let mut hist = [0u32; 10];
        st.shards[0].sh.state().tree.leaf_images(&mut |b| {
            let used = 8192 - page::free_total(b);
            hist[(used * 10 / 8192).min(9)] += 1;
        });
        eprintln!("leaf fill histogram (deciles): {hist:?}");
    }
    let sh = st.shards[0].sh.state().tree.shape();
    let e = sh.entries as f64;
    eprintln!(
        "{} entries, {} leaves + {} interior of 8 KiB: tree {:.3} x logical | per entry: leaf bytes {:.1} (pages {:.1}), key suffix {:.1} (lcp {:.1}), value {:.1}, interior {:.1}; leaf fill {:.1} %",
        sh.entries,
        sh.leaves,
        sh.interior,
        ((sh.leaves + sh.interior) * 8192) as f64 / logical as f64,
        sh.leaf_used as f64 / e,
        (sh.leaves * 8192) as f64 / e,
        sh.leaf_sfx as f64 / e,
        sh.leaf_lcp as f64 / e,
        sh.leaf_val as f64 / e,
        (sh.interior * 8192) as f64 / e,
        100.0 * sh.leaf_used as f64 / (sh.leaves * 8192) as f64
    );
}

/// zstd with a trained dictionary (entropy tables included) per value, dictionary ID / content size / checksum off: dictionary size
/// and training sample count against the coded bytes per value and ns (the codec of the value path).
#[test]
#[ignore = "measurement"]
fn comp_value_zstd_trained() {
    use zstd::zstd_safe::{CCtx, CDict, CParameter, DCtx, DDict};
    for ds in datasets(30_000) {
        for (dsz, ns) in [
            (1024usize, 64usize),
            (2048, 64),
            (2048, 128),
            (3072, 128),
            (4096, 256),
        ] {
            let samples: Vec<&[u8]> = ds
                .kv
                .iter()
                .step_by(97)
                .take(ns)
                .map(|(_, v)| &v[..])
                .collect();
            if samples.iter().all(|s| s.len() < 64) {
                continue;
            }
            let t = Instant::now();
            let Ok(dict) = zstd::dict::from_samples(&samples, dsz) else {
                eprintln!("{:14} dict {dsz} from {ns}: training failed", ds.name);
                continue;
            };
            let train = t.elapsed();
            let cd = CDict::create(&dict, 1);
            let dd = DDict::create(&dict);
            let mut cc = CCtx::create();
            cc.set_parameter(CParameter::Format(zstd::zstd_safe::FrameFormat::Magicless))
                .unwrap();
            cc.set_parameter(CParameter::CompressionLevel(1)).unwrap();
            cc.ref_cdict(&cd).unwrap();
            cc.set_parameter(CParameter::DictIdFlag(false)).unwrap();
            cc.set_parameter(CParameter::ContentSizeFlag(false))
                .unwrap();
            cc.set_parameter(CParameter::ChecksumFlag(false)).unwrap();
            let mut dc = DCtx::create();
            dc.set_parameter(zstd::zstd_safe::DParameter::Format(
                zstd::zstd_safe::FrameFormat::Magicless,
            ))
            .unwrap();
            dc.ref_ddict(&dd).unwrap();
            let mut out = vec![0u8; 1 << 12];
            let mut back = vec![0u8; 1 << 12];
            let (mut tot, mut tc, mut td) = (0u64, 0u128, 0u128);
            let mut cnt = 0u64;
            for (_, v) in &ds.kv {
                let t = Instant::now();
                let n = cc.compress2(&mut out[..], v).unwrap();
                tc += t.elapsed().as_nanos();
                let t = Instant::now();
                let m = dc.decompress(&mut back[..], &out[..n]).unwrap();
                td += t.elapsed().as_nanos();
                assert_eq!(&back[..m], &v[..]);
                tot += n.min(v.len()) as u64;
                cnt += 1;
            }
            let rawm = ds.kv.iter().map(|(_, v)| v.len() as u64).sum::<u64>() as f64 / cnt as f64;
            eprintln!(
                "{:14} dict {dsz:4} from {ns:3} samples (train {:5.0} us): {:.1} of {rawm:.0} B/value, comp {} ns, dec {} ns",
                ds.name,
                train.as_micros() as f64,
                tot as f64 / cnt as f64,
                tc / cnt as u128,
                td / cnt as u128
            );
        }
    }
}

#[test]
fn zdict_trains_from_few_small_samples() {
    use store::obj::onode::ZDict;
    let mut rng = Rng::new(3);
    for (n, len) in [
        (2usize, 600usize),
        (3, 600),
        (4, 600),
        (6, 600),
        (8, 60),
        (8, 400),
        (8, 3000),
        (64, 300),
    ] {
        let samples: Vec<Vec<u8>> = (0..n)
            .map(|_| {
                let mut v = b"owner-0001 STANDARD application/octet ".repeat(len / 38 + 1);
                v.truncate(len);
                v.extend_from_slice(&rng.next_u64().to_le_bytes());
                v
            })
            .collect();
        eprintln!(
            "{n} samples of {len} B: {}",
            ZDict::train(&samples).is_some()
        );
    }
}

/// The value-dictionary trainer (hash table sized to the samples) codes as well as zstd's default trainer (2^20 table) on every
/// dataset: same samples as the shard takes (its first `DICT_SAMPLES` values of a class), coded bytes over all values. Prints the
/// training time of both (the default one was ~13 ms per dictionary on the PG core, b-mix tail).
#[test]
fn zdict_train_sized_table_codes_like_default() {
    use store::obj::onode::{DICT_MAX, DICT_SAMPLES, ZDict, vcomp_pack};
    for ds in datasets(5_000) {
        let samples: Vec<Vec<u8>> = ds
            .kv
            .iter()
            .take(DICT_SAMPLES)
            .map(|(_, v)| v.clone())
            .collect();
        let t = Instant::now();
        let def = ZDict::new(zstd::dict::from_samples(&samples, DICT_MAX).unwrap());
        let t_def = t.elapsed();
        let t = Instant::now();
        let ours = ZDict::train(&samples).unwrap();
        let t_ours = t.elapsed();
        let mut scratch = Vec::new();
        let mut coded = |d: &ZDict| -> u64 {
            ds.kv
                .iter()
                .map(|(_, v)| vcomp_pack(v, d, 0, &mut scratch) as u64)
                .sum()
        };
        let (b_def, b_ours) = (coded(&def), coded(&ours));
        eprintln!(
            "{:10} train default {:6} us, sized {:6} us; coded default {b_def} B, sized {b_ours} B ({:+.2} %)",
            ds.name,
            t_def.as_micros(),
            t_ours.as_micros(),
            100.0 * (b_ours as f64 / b_def as f64 - 1.0)
        );
        assert!(
            b_ours as f64 <= b_def as f64 * 1.01,
            "{}: sized table codes worse",
            ds.name
        );
    }
}

/// Cost of one merged run value's compression (adr 0476 am. 1, `MergeComp`): `vcomp_pack` of RGW index values against a
/// dictionary trained from 64 of them (as the stage trains a class), ns per value and coded size.
#[test]
#[ignore = "measurement"]
fn comp_merge_value_cost() {
    use store::obj::onode::{ZDict, vcomp_pack};
    let mut rng = Rng::new(9);
    let vals: Vec<Vec<u8>> = (0..20_000u64)
        .map(|i| rgw_val(&mut rng, format!("obj-{i:08}").as_bytes(), i))
        .collect();
    let zd = ZDict::train(&vals[..64]).expect("dictionary");
    let mut cv = Vec::new();
    let (mut raw, mut coded) = (0usize, 0usize);
    let mut best = u128::MAX;
    for _ in 0..3 {
        let t0 = Instant::now();
        (raw, coded) = (0, 0);
        for v in &vals {
            let n = vcomp_pack(v, &zd, 1, &mut cv);
            raw += v.len();
            coded += if n == usize::MAX { v.len() } else { n };
        }
        best = best.min(t0.elapsed().as_nanos() / vals.len() as u128);
    }
    eprintln!(
        "merge value compression: {best} ns/value, {} B -> {} B per value",
        raw / vals.len(),
        coded / vals.len()
    );
    // variants of the same coding (frame without magic / dict id / size / checksum)
    use zstd::zstd_safe::{CParameter, DictAttachPref, ParamSwitch};
    let variants: Vec<(&str, i32, Vec<CParameter>)> = vec![
        ("level 1", 1, vec![]),
        (
            "level 1 force copy",
            1,
            vec![CParameter::ForceAttachDict(DictAttachPref::ForceCopy)],
        ),
        (
            "level 1 literals raw",
            1,
            vec![CParameter::LiteralCompressionMode(ParamSwitch::Disable)],
        ),
        ("level -1", -1, vec![]),
        ("level 3", 3, vec![]),
    ];
    for (name, lvl, ps) in variants {
        let mut c = zstd::bulk::Compressor::with_dictionary(lvl, zd.bytes()).unwrap();
        c.include_magicbytes(false).unwrap();
        c.include_dictid(false).unwrap();
        c.include_contentsize(false).unwrap();
        c.include_checksum(false).unwrap();
        for p in ps {
            c.set_parameter(p).unwrap();
        }
        let mut out = vec![0u8; 1024];
        let mut best = u128::MAX;
        let mut coded = 0usize;
        for _ in 0..3 {
            coded = 0;
            let t0 = Instant::now();
            for v in &vals {
                coded += c.compress_to_buffer(&v[..], &mut out[..]).unwrap();
            }
            best = best.min(t0.elapsed().as_nanos() / vals.len() as u128);
        }
        eprintln!(
            "  {name}: {best} ns/value, {} B per value",
            coded / vals.len()
        );
    }
}
