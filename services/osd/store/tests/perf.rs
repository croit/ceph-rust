// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Replay time of a full WAL (virtual device time + wall) and txn/s microbench. Numbers print with --nocapture.
//! Release mode for meaningful wall numbers: `cargo test --release -p store --test perf -- --nocapture --include-ignored`.
mod common;
use common::*;
use std::time::Instant;
use store::StoreError;
use store::dev::{BlockDev, Clock, CrashPolicy, SimClock, SimDisk};
use store::shard::{Event, Shard, ShardCfg, Txn};
use store::state::Op;

fn drive(s: &mut Shard<store::dev::SimDev>, clk: &mut SimClock, acked: &mut u64) {
    let mut ev = Vec::new();
    s.poll(clk.t, &mut ev);
    for e in ev {
        if let Event::Acked(_) = e {
            *acked += 1;
        }
    }
    let h = s.dev().next_deadline();
    clk.idle(h);
}

/// Fill the whole WAL ring (no releases) with ~190 B KV txns (+ one 4 KiB data block every 64th), return count.
fn fill_wal(env: &Env, disk: &SimDisk, clk: &mut SimClock) -> (u64, f64, u64) {
    let (mut s, _) = mount(env, disk, clk).unwrap();
    let wall = Instant::now();
    let (mut n, mut acked) = (0u64, 0u64);
    let val = vec![0x5au8; 160];
    'outer: loop {
        for _ in 0..32 {
            let mut t = Txn::new(n + 1);
            t.ops.push(Op::Put(
                format!("k/{:06}", n % 20_000).into_bytes(),
                val.clone(),
            ));
            if n % 64 == 0
                && let Ok(b) = s.alloc(1)
            {
                t.data.push((b, s.alloc_buf(1)));
            }
            match s.submit(t) {
                Ok(_) => n += 1,
                Err((StoreError::WalFull, _)) => break 'outer,
                Err((StoreError::Busy, t)) => {
                    t.data.iter().for_each(|(b, _)| s.unreserve(*b, 1));
                    break;
                }
                Err((e, _)) => panic!("{e:?}"),
            }
        }
        drive(&mut s, clk, &mut acked);
    }
    while acked < n {
        drive(&mut s, clk, &mut acked);
    }
    (n, wall.elapsed().as_secs_f64(), s.ring_free_blocks())
}

fn replay_time(wal_blocks: u64, cap_mib: u64) {
    let cfg = ShardCfg {
        auto_ckpt: false,
        ..Default::default()
    };
    let env = make_env(cap_mib, wal_blocks, 1, cfg);
    let disk = SimDisk::from_image(&env.img, env.sim.clone());
    let mut clk = SimClock::default();
    let (n, fill_wall, ring_free) = fill_wal(&env, &disk, &mut clk);
    assert!(ring_free < 40, "ring not actually full: {ring_free} free");
    let img = disk.crash_image(CrashPolicy::DROP_ALL);
    let disk2 = SimDisk::from_image(&img, env.sim.clone());
    let mut clk2 = SimClock::default();
    let wall = Instant::now();
    let (s, st) = mount(&env, &disk2, &mut clk2).unwrap();
    let wall = wall.elapsed();
    assert_eq!(s.state().lsn, n);
    eprintln!(
        "FULL-WAL REPLAY: wal {} MiB, {} txns in {} units (+{} data blocks checked); virtual device time {:.1} ms incl. mount checkpoint (ring {:.2} GB/s); wall {:.1} ms ({:.2} M txn/s apply); fill: {:.2} M txn/s wall",
        wal_blocks * 4 / 1024,
        st.txns,
        st.units,
        st.data_blocks_checked,
        clk2.t as f64 / 1e6,
        wal_blocks as f64 * 4096.0 / clk2.t as f64,
        wall.as_secs_f64() * 1e3,
        st.txns as f64 / wall.as_secs_f64() / 1e6,
        n as f64 / fill_wall / 1e6,
    );
    assert_eq!(
        s.ring_free_blocks(),
        wal_blocks,
        "mount checkpoints the replayed state: WAL empty"
    );
}

#[test]
fn replay_time_full_wal_64mib() {
    replay_time(16_384, 256);
}

#[test]
#[ignore = "1 GiB WAL (design default): ~1.2 GB RAM"]
fn replay_time_full_wal_1gib() {
    replay_time(262_144, 1800);
}

fn bench(name: &str, with_data: bool, total: u64) {
    let env = make_env(512, 16_384, 1, ShardCfg::default());
    let disk = SimDisk::from_image(&env.img, env.sim.clone());
    let mut clk = SimClock::default();
    let (mut s, _) = mount(&env, &disk, &mut clk).unwrap();
    let mut slots: Vec<Option<u64>> = vec![None; 4096];
    let val = vec![0x33u8; 120];
    let (mut n, mut acked) = (0u64, 0u64);
    let wall = Instant::now();
    let t0 = clk.t;
    while acked < total {
        for _ in 0..64 {
            if n >= total {
                break;
            }
            let mut t = Txn::new(n + 1);
            t.ops.push(Op::Put(
                format!("k/{:06}", n % 50_000).into_bytes(),
                val.clone(),
            ));
            let slot = (n % 4096) as usize;
            if with_data {
                let Ok(b) = s.alloc(1) else {
                    break;
                };
                t.data.push((b, s.alloc_buf(1)));
                if let Some(old) = slots[slot] {
                    t.frees.push((old, 1));
                }
                match s.submit(t) {
                    Ok(_) => {
                        slots[slot] = Some(b);
                        n += 1;
                    }
                    Err((_, t)) => {
                        s.unreserve(b, 1);
                        drop(t);
                        break;
                    }
                }
            } else {
                match s.submit(t) {
                    Ok(_) => n += 1,
                    Err(_) => break,
                }
            }
        }
        let mut ev = Vec::new();
        s.poll(clk.t, &mut ev);
        for e in ev {
            if let Event::Acked(_) = e {
                acked += 1;
            }
        }
        let h = s.dev().next_deadline();
        clk.idle(h);
    }
    let w = wall.elapsed().as_secs_f64();
    let v = (clk.t - t0) as f64 / 1e9;
    eprintln!(
        "BENCH {name}: {total} txns: wall {:.2} s = {:.2} M txn/s/core ({:.2} us/txn engine+sim CPU); virtual {:.2} s = {:.0} k txn/s at QD<=16 WAL units; {} units, {} pads",
        w,
        total as f64 / w / 1e6,
        w / total as f64 * 1e6,
        v,
        total as f64 / v / 1e3,
        s.stats.units,
        s.stats.pads
    );
}

#[test]
#[ignore = "microbench: run with --release"]
fn microbench_kv_only_txn_per_sec() {
    bench("kv-only (~150 B record)", false, 1_000_000);
}

#[test]
#[ignore = "microbench: run with --release"]
fn microbench_4k_data_txn_per_sec() {
    bench("4 KiB data block + record", true, 300_000);
}

// ------------------------------------------------------------------ mount time vs tree size

/// Build a tree of `nkeys` keys (16 per txn) with periodic checkpoints, crash (power cut) after a clean
/// checkpoint and measure the mount: virtual device time, pages read.
fn mount_time(nkeys: u64) -> (u64, u64, f64, u64) {
    let cfg = ShardCfg {
        cache_pages: 1 << 16,
        ..Default::default()
    };
    let env = make_env_ext(2048, 4096, 1, cfg, 10, 8192);
    let mut r = Rig::new(&env, 99);
    let val = [0x42u8; 100];
    let mut i = 0;
    while i < nkeys {
        let ops = (0..16)
            .map(|j| {
                Op::Put(
                    format!("n/{:010}", (i + j) * 7919 % nkeys.max(1)).into_bytes(),
                    val.to_vec(),
                )
            })
            .collect();
        r.txn(ops);
        i += 16;
        if i % 4096 == 0 {
            r.sync();
        }
    }
    r.checkpoint();
    let pages = r.fsck(&r.disk.image()).pages;
    // some WAL on top of the checkpoint (bounded replay), then power cut
    for k in 0..500u64 {
        r.txn(vec![Op::Put(
            format!("tail/{k:06}").into_bytes(),
            val.to_vec(),
        )]);
    }
    r.sync();
    let img = r.disk.crash_image(CrashPolicy::DROP_ALL);
    let disk = SimDisk::from_image(&img, env.sim.clone());
    let mut clk = SimClock::default();
    let wall = Instant::now();
    let (s, st) = mount(&env, &disk, &mut clk).unwrap();
    let wall = wall.elapsed().as_secs_f64();
    assert_eq!(st.txns, 500);
    let loads = s.tree_stats().loads;
    eprintln!(
        "MOUNT {nkeys} keys ({pages} tree pages, height {}): {loads} pages read, replayed {} txns, virtual {:.2} ms, wall {:.1} ms",
        s.state().tree.height(),
        st.txns,
        clk.t as f64 / 1e6,
        wall * 1e3
    );
    (pages, loads, clk.t as f64 / 1e6, nkeys)
}

#[test]
fn mount_time_does_not_grow_with_tree_size() {
    let (p1, l1, t1, _) = mount_time(5_000);
    let (p2, l2, t2, _) = mount_time(120_000);
    assert!(p2 > 10 * p1, "tree did not grow: {p1} -> {p2} pages");
    assert!(
        l2 <= l1 + 8,
        "mount read {l2} pages for a {p2}-page tree ({l1} for {p1})"
    );
    assert!(t2 < t1 * 3.0 + 2.0, "mount time {t2} ms vs {t1} ms");
}

#[test]
#[ignore = "large: run with --release"]
fn mount_time_1m_keys() {
    mount_time(1_000_000);
}

// ------------------------------------------------------------------ tree microbench (no device)

#[test]
#[ignore = "microbench: run with --release"]
fn microbench_tree_ops_per_sec() {
    use store::alloc::MetaAlloc;
    use store::layout::{MetaGeom, ShardDir};
    use store::rng::Rng;
    use store::tree::{ScanCursor, Tree, TreeCfg};
    let dir = ShardDir {
        shard: 0,
        region_start: 0,
        region_blocks: 1 << 22,
        root_a: 0,
        root_b: 1,
        wal_start: 2,
        wal_blocks: 64,
        meta_start: 66,
        meta_blocks: 1 << 21,
        data_start: (1 << 21) + 66,
        data_blocks: 1000,
        ext: vec![],
        chunk_blocks: 0,
        #[cfg(feature = "elastic")]
        lent: Vec::new(),
    };
    for (psz, compact) in [4096usize, 8192, 16384]
        .into_iter()
        .flat_map(|p| [(p, false), (p, true)])
    {
        eprintln!(
            "--- interior pages: {}",
            if compact { "compact" } else { "slotted" }
        );
        let geom = MetaGeom::new(&dir, psz as u32).unwrap();
        let meta = MetaAlloc::new(geom.npages);
        let mut t = Tree::new(
            TreeCfg {
                psz,
                shard: 0,
                cache_pages: 1 << 20,
                max_walk: 1 << 20,
                compact_int: compact,
                bg_compact: false,
            },
            geom,
            meta,
            None,
        );
        let n = 1_000_000u64;
        let mut rng = Rng::new(7);
        let key = |i: u64| format!("obj/{:012}/e/{:08}", i / 64, i % 64).into_bytes();
        let val = [0x11u8; 48];
        // sequential insert
        let w = Instant::now();
        for i in 0..n {
            t.put(&key(i), &val).unwrap();
        }
        let seq = w.elapsed().as_secs_f64();
        // random get (all hits)
        let w = Instant::now();
        let mut out = Vec::new();
        for _ in 0..n {
            out.clear();
            assert!(t.get(&key(rng.below(n)), &mut out).unwrap());
        }
        let get = w.elapsed().as_secs_f64();
        // random overwrite (same size)
        let w = Instant::now();
        for _ in 0..n {
            t.put(&key(rng.below(n)), &val).unwrap();
        }
        let upd = w.elapsed().as_secs_f64();
        // random insert of new keys into the populated tree
        let w = Instant::now();
        for i in 0..n / 2 {
            t.put(
                format!("obj/{:012}/x/{:08}", rng.below(n / 64), i).as_bytes(),
                &val,
            )
            .unwrap();
        }
        let rnd = w.elapsed().as_secs_f64();
        // scans: 100-entry ranges
        let w = Instant::now();
        let mut cnt = 0u64;
        for _ in 0..20_000 {
            let s = key(rng.below(n));
            let mut cur = ScanCursor::new(&s, b"\xff");
            t.scan(&mut cur, 100, usize::MAX, &mut |_, _| cnt += 1)
                .unwrap();
        }
        let scan = w.elapsed().as_secs_f64();
        // range delete of 100-key windows
        let w = Instant::now();
        for i in 0..5000u64 {
            let a = key(i * 128);
            let b = key(i * 128 + 100);
            t.probe_range(&a, &b).unwrap();
            t.del_range(&a, &b).unwrap();
            t.finish_txn().unwrap();
        }
        let dr = w.elapsed().as_secs_f64();
        // freeze cost: first all dirty pages (cold start), then ~2000 dirtied by random overwrites
        let d0 = t.dirty_pages();
        let w = Instant::now();
        let fr = t.freeze(1).unwrap();
        let f_all = w.elapsed().as_secs_f64();
        for p in fr.pages.iter().map(|p| p.0) {
            t.page_written(p);
        }
        t.ckpt_complete(&fr.free_after);
        for _ in 0..3000 {
            t.put(&key(rng.below(n)), &val).unwrap();
        }
        let d1 = t.dirty_pages();
        let w = Instant::now();
        let fr = t.freeze(2).unwrap();
        let f_inc = w.elapsed().as_secs_f64();
        eprintln!(
            "FREEZE {psz} B pages: all {d0} dirty pages {:.1} ms ({:.2} us/page); incremental {d1} dirty {:.2} ms ({:.2} us/page); {} pages in arena",
            f_all * 1e3,
            f_all / d0 as f64 * 1e6,
            f_inc * 1e3,
            f_inc / d1 as f64 * 1e6,
            fr.pages.len()
        );
        eprintln!(
            "TREE {psz} B pages: seq insert {:.2} M/s, random get {:.2} M/s, random overwrite {:.2} M/s, random insert {:.2} M/s, scan {:.1} M entries/s ({} entries), delrange(100) {:.0} k/s; height {} pages {} splits {}",
            n as f64 / seq / 1e6,
            n as f64 / get / 1e6,
            n as f64 / upd / 1e6,
            (n / 2) as f64 / rnd / 1e6,
            cnt as f64 / scan / 1e6,
            cnt,
            5000.0 / dr / 1e3,
            t.height(),
            t.resident_pages(),
            t.stats.splits
        );
    }
}

// ------------------------------------------------------------------ multi-part txns (ADR 0028)

/// Throughput of big multi-part txns: `keys` puts of `vlen` bytes per txn, back to back (QD = pipeline depth).
fn bench_big(keys: usize, vlen: usize, ntxn: u64) {
    let env = make_env(
        1024,
        65_536,
        1,
        ShardCfg {
            max_unit_blocks: 64,
            ..Default::default()
        },
    );
    let disk = SimDisk::from_image(&env.img, env.sim.clone());
    let mut clk = SimClock::default();
    let (mut s, _) = mount(&env, &disk, &mut clk).unwrap();
    let val = vec![0x5au8; vlen];
    let (mut n, mut acked) = (0u64, 0u64);
    let wall = Instant::now();
    let t0 = clk.t;
    while acked < ntxn {
        while n < ntxn {
            let mut t = Txn::new(n + 1);
            for i in 0..keys {
                t.ops.push(Op::Put(
                    format!("b/{:03}/{i:06}", n % 20).into_bytes(),
                    val.clone(),
                ));
            }
            match s.submit(t) {
                Ok(_) => n += 1,
                Err((StoreError::Busy | StoreError::WalFull, _)) => break,
                Err((e, _)) => panic!("{e:?}"),
            }
        }
        drive(&mut s, &mut clk, &mut acked);
    }
    let w = wall.elapsed().as_secs_f64();
    let v = (clk.t - t0) as f64 / 1e9;
    let mb = ntxn as f64 * (keys * (vlen + 16)) as f64 / 1e6;
    eprintln!(
        "BENCH big txn ({keys} keys x {vlen} B = {:.0} KiB/txn): {ntxn} txns {mb:.0} MB: wall {w:.2} s = {:.0} MB/s/core ({:.0} us/txn); virtual {v:.2} s = {:.0} MB/s; {} multi, {} parts, {} units",
        (keys * (vlen + 16)) as f64 / 1024.0,
        mb / w,
        w / ntxn as f64 * 1e6,
        mb / v,
        s.stats.multi_txns,
        s.stats.multi_parts,
        s.stats.units,
    );
}

#[test]
#[ignore = "microbench: run with --release"]
fn microbench_big_multi_part_txns() {
    bench_big(300, 1000, 400); // ~300 KiB: 2 parts
    bench_big(2000, 200, 200); // ~430 KiB claim-like
    bench_big(8000, 100, 50); // ~930 KiB
}

/// Tree density for huge omap (adr 0021 am. 13): RGW-index-shaped omap entries (tree key `o` + object id + 0x04 +
/// user key, value = tag + 240 B, ~300 B per entry) inserted in random order (arrival order of PUTs) or sorted into
/// the COW tree; reports leaf/interior page counts and the interior RAM extrapolated to 1e9 entries.
/// `DENSITY_N` (default 400000) entries per run. Release: `cargo test --release -p store --test perf density -- --ignored --nocapture`.
#[test]
#[ignore = "measurement: run with --release"]
fn density_rgw_index_omap() {
    use store::alloc::MetaAlloc;
    use store::layout::{MetaGeom, ShardDir};
    use store::rng::Rng;
    use store::tree::{Tree, TreeCfg};
    let n: u64 = std::env::var("DENSITY_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(400_000);
    let dir = ShardDir {
        shard: 0,
        region_start: 0,
        region_blocks: 1 << 24,
        root_a: 0,
        root_b: 1,
        wal_start: 2,
        wal_blocks: 64,
        meta_start: 66,
        meta_blocks: 1 << 23,
        data_start: (1 << 23) + 66,
        data_blocks: 1000,
        ext: vec![],
        chunk_blocks: 0,
        #[cfg(feature = "elastic")]
        lent: Vec::new(),
    };
    let styles = ["seq", "dirs", "uuid", "versioned"];
    eprintln!(
        "density: {n} entries of ~300 B per run, 8 KiB pages (leaves/interior = pages, fill = bytes in use / page)"
    );
    eprintln!(
        "{:<10} {:<8} {:<7} {:>6} {:>9} {:>9} {:>9} {:>9} {:>9} {:>8} {:>14}",
        "keys",
        "fmt",
        "order",
        "height",
        "leaves",
        "interior",
        "ent/leaf",
        "leaf fill",
        "int fill",
        "B/entry",
        "int RAM/1e9"
    );
    for (compact, style) in [false, true]
        .into_iter()
        .flat_map(|c| styles.iter().map(move |s| (c, *s)))
    {
        for sorted in [false, true] {
            let mut rng = Rng::new(11);
            let mut keys: Vec<Vec<u8>> = (0..n)
                .map(|i| {
                    let h = i.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (i >> 3);
                    let user = match style {
                        "seq" => format!("bucket-data/obj_{i:012}.dat"),
                        "dirs" => format!(
                            "photos/dir{:03}/sub{:03}/IMG_{i:08}.jpg",
                            (h >> 7) % 200,
                            (h >> 23) % 500
                        ),
                        "uuid" => format!("{:016x}{:016x}", h, h.rotate_left(29) ^ i),
                        _ => format!(
                            "logs/2026/{:02}/app{:02}/{i:010}.gz\u{0}v913\u{0}i{:016x}",
                            (h >> 5) % 12 + 1,
                            (h >> 11) % 40,
                            h
                        ),
                    };
                    let mut k = vec![b'o'];
                    k.extend_from_slice(&0x1234_5678u64.to_be_bytes());
                    k.push(4);
                    k.extend_from_slice(user.as_bytes());
                    k
                })
                .collect();
            if sorted {
                keys.sort();
            } else {
                for i in (1..keys.len()).rev() {
                    keys.swap(i, rng.below(i as u64 + 1) as usize);
                }
            }
            let geom = MetaGeom::new(&dir, 8192).unwrap();
            let meta = MetaAlloc::new(geom.npages);
            let mut t = Tree::new(
                TreeCfg {
                    psz: 8192,
                    shard: 0,
                    cache_pages: 1 << 24,
                    max_walk: 1 << 20,
                    compact_int: compact,
                    bg_compact: false,
                },
                geom,
                meta,
                None,
            );
            let mut val = vec![0u8; 241];
            for k in &keys {
                rng.fill(&mut val[1..]);
                t.put(k, &val).unwrap();
            }
            let s = t.shape();
            let per_leaf = s.entries as f64 / s.leaves as f64;
            let leaf_fill = s.leaf_used as f64 / (s.leaves * 8192) as f64;
            let int_fill = s.int_used as f64 / (s.interior * 8192).max(1) as f64;
            let bytes_per = (s.leaves + s.interior) as f64 * 8192.0 / s.entries as f64;
            let ram = s.interior as f64 / s.entries as f64 * 1e9 * 8192.0 / (1u64 << 30) as f64;
            eprintln!(
                "    interior: {:.1} B/child (suffix {:.1}, front-codable {:.1}), {:.0} children/page; leaf: suffix {:.1} B/entry (front-codable {:.1}), value {:.0} B",
                s.int_used as f64 / s.int_entries as f64,
                s.int_sfx as f64 / s.int_entries as f64,
                s.int_lcp as f64 / s.int_entries as f64,
                s.int_entries as f64 / s.interior as f64,
                s.leaf_sfx as f64 / s.entries as f64,
                s.leaf_lcp as f64 / s.entries as f64,
                s.leaf_val as f64 / s.entries as f64,
            );
            eprintln!(
                "{style:<10} {:<8} {:<7} {:>6} {:>9} {:>9} {:>9.1} {:>8.0}% {:>8.0}% {:>8.0} {:>11.2} GiB",
                if compact { "compact" } else { "slotted" },
                if sorted { "sorted" } else { "random" },
                s.height,
                s.leaves,
                s.interior,
                per_leaf,
                leaf_fill * 100.0,
                int_fill * 100.0,
                bytes_per,
                ram
            );
        }
    }
}
