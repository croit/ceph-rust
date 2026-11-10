// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! COW B+tree property tests against a BTreeMap model, through the full shard path (WAL, checkpoints, cold
//! remounts, page cache pressure). Keys never start with `f` (engine bitmap namespace).
mod common;
use common::*;
use store::StoreError;
use store::dev::{BlockDev, CrashPolicy, SimClock, SimDisk};
use store::rng::Rng;
use store::shard::ShardCfg;
use store::sio::Sio;
use store::state::Op;

#[derive(Clone, Copy, Debug)]
enum Style {
    Dense,
    RandomBytes,
    LongPrefix,
    Tricky,
    /// Mixed short and long keys (up to the given tree key limit) over a few shared long prefixes (adr 0021 am. 10).
    Long(usize),
}

fn gen_key(rng: &mut Rng, style: Style, n: u64) -> Vec<u8> {
    let mut k = match style {
        Style::Dense => format!("k{:08}", rng.below(n)).into_bytes(),
        Style::RandomBytes => {
            let mut v = vec![0u8; rng.range(1, 24) as usize];
            rng.fill(&mut v);
            v
        }
        Style::LongPrefix => {
            let mut v = format!("pool/0001/pg/00ff/objects/{:04}/", rng.below(8)).into_bytes();
            let mut tail = vec![0u8; rng.range(0, 10) as usize];
            rng.fill(&mut tail);
            v.extend_from_slice(&tail);
            v
        }
        Style::Long(maxk) => {
            const BASES: u64 = 5;
            let alpha = [0u8, 1, 0xff, b'a'];
            if rng.pct(35) {
                (0..rng.range(1, 9))
                    .map(|_| alpha[rng.below(4) as usize])
                    .collect()
            } else {
                let b = rng.below(BASES);
                let mut base = Rng::new(0x10_0000 + b);
                let len = (maxk as u64 * (b + 1) / BASES).saturating_sub(4).max(1) as usize;
                let mut v = vec![0u8; len];
                base.fill(&mut v);
                if b.is_multiple_of(2) {
                    v.iter_mut().for_each(|x| *x = alpha[(*x % 4) as usize]);
                }
                if rng.pct(30) {
                    let cut = rng.below(len as u64 + 1) as usize;
                    v.truncate(cut.max(1));
                }
                for _ in 0..rng.range(0, 9) {
                    v.push(alpha[rng.below(4) as usize]);
                }
                v.truncate(maxk);
                v
            }
        }
        Style::Tricky => {
            // tiny alphabet incl. 0x00/0xff, many keys are prefixes of others
            let alpha = [0u8, 1, 0xff, b'a'];
            (0..rng.range(1, 7))
                .map(|_| alpha[rng.below(4) as usize])
                .collect()
        }
    };
    if k[0] == b'f' {
        k[0] = b'g';
    }
    k
}

fn gen_val(rng: &mut Rng, max: usize, typical: u64) -> Vec<u8> {
    let n = if rng.pct(3) {
        rng.below(max as u64 + 1) as usize
    } else {
        rng.below(typical) as usize
    };
    let mut v = vec![0u8; n.min(max)];
    rng.fill(&mut v);
    v
}

fn max_val(env: &Env, klen: usize) -> usize {
    let node = env.sb.node_size as usize;
    let soft = (node / 4).saturating_sub(4 + klen);
    // long keys: the entry limit leaves at least KEY_VAL_ROOM for the value
    let hard = store::tree::max_entry_for(node)
        .saturating_sub(4 + klen)
        .min(store::tree::KEY_VAL_ROOM);
    soft.max(hard)
}

struct Params {
    node: u32,
    style: Style,
    nkeys: u64,
    ops: u64,
    cache: usize,
    seed: u64,
    min_height: u8,
    vlen: u64,
    /// Per mille of the ops that are many-op storm txns.
    storm: u64,
}

/// Txns with MANY ops (the shape that hid the emptied-interior-root prune bug): partition wipes (N adjacent
/// DelRanges that together empty the tree, in random order, like remove_pg of many PGs in one txn), many random
/// ranges, big put/del/range mixes, wipe + re-put in one txn.
fn storm_txn(rng: &mut Rng, r: &Rig, p: &Params, env: &Env) -> Vec<Op> {
    let put = |rng: &mut Rng| {
        let k = gen_key(rng, p.style, p.nkeys);
        let v = gen_val(rng, max_val(env, k.len()), p.vlen);
        Op::Put(k, v)
    };
    let sorted_keys = |rng: &mut Rng, n: u64| {
        let mut v: Vec<Vec<u8>> = (0..n).map(|_| gen_key(rng, p.style, p.nkeys)).collect();
        v.sort();
        v.dedup();
        v
    };
    let end = vec![0xffu8; 40];
    let mut ops = Vec::new();
    match rng.below(100) {
        0..=34 => {
            // partition wipe
            let n = rng.range(2, 40);
            let pts = sorted_keys(rng, n);
            let mut bounds = vec![Vec::new()];
            bounds.extend(pts);
            bounds.push(end);
            let mut sl: Vec<Op> = bounds
                .windows(2)
                .map(|w| Op::DelRange(w[0].clone(), w[1].clone()))
                .collect();
            if rng.pct(30) {
                // only part of the space
                let keep = rng.below(sl.len() as u64) as usize;
                sl.truncate(keep.max(1));
            }
            match rng.below(3) {
                0 => sl.reverse(),
                1 => {
                    for i in (1..sl.len()).rev() {
                        sl.swap(i, rng.below(i as u64 + 1) as usize);
                    }
                }
                _ => {}
            }
            ops = sl;
            if rng.pct(30) {
                // a later range over the already emptied tree
                ops.push(Op::DelRange(Vec::new(), vec![0xff; 40]));
            }
            if rng.pct(30) {
                for _ in 0..rng.range(1, 30) {
                    ops.push(put(rng));
                }
            }
        }
        35..=59 => {
            for _ in 0..rng.range(5, 60) {
                let pts = sorted_keys(rng, 2);
                if pts.len() == 2 {
                    ops.push(Op::DelRange(pts[0].clone(), pts[1].clone()));
                }
            }
        }
        60..=84 => {
            for _ in 0..rng.range(50, 400) {
                match rng.below(10) {
                    0..=5 => ops.push(put(rng)),
                    6..=7 => ops.push(Op::Del(gen_key(rng, p.style, p.nkeys))),
                    _ => {
                        let pts = sorted_keys(rng, 2);
                        if pts.len() == 2 {
                            ops.push(Op::DelRange(pts[0].clone(), pts[1].clone()));
                        }
                    }
                }
            }
        }
        _ => {
            // put-then-wipe-then-put in ONE txn
            for _ in 0..rng.range(5, 80) {
                ops.push(put(rng));
            }
            ops.push(Op::DelRange(Vec::new(), end));
            for _ in 0..rng.range(0, 40) {
                ops.push(put(rng));
            }
        }
    }
    let _ = r;
    ops
}
fn run_random(p: Params) {
    let cfg = ShardCfg {
        cache_pages: p.cache,
        dirty_soft_pages: 64,
        ..Default::default()
    };
    let env = make_env_ext(256, 1024, 1, cfg, 10, p.node);
    let mut r = Rig::new(&env, p.seed);
    let mut rng = Rng::new(p.seed);
    for i in 0..p.ops {
        let roll = rng.below(100);
        // grow, shrink, regrow
        let t = if i < p.ops / 2 || i >= p.ops * 8 / 10 {
            [75, 80, 81, 83, 91, 97]
        } else {
            [25, 55, 63, 66, 82, 96]
        };
        if p.storm > 0 && i >= p.ops / 4 && rng.below(1000) < p.storm {
            let ops = storm_txn(&mut rng, &r, &p, &env);
            r.apply(ops);
            if rng.pct(25) {
                r.sync();
                r.verify();
            }
        } else if roll < t[0] {
            let k = gen_key(&mut rng, p.style, p.nkeys);
            let v = gen_val(&mut rng, max_val(&env, k.len()), p.vlen);
            r.put(&k, &v);
        } else if roll < t[1] {
            // delete an existing key most of the time
            let k = if !r.model.is_empty() && rng.pct(75) {
                let i = rng.below(r.model.len() as u64) as usize;
                r.model.keys().nth(i).unwrap().clone()
            } else {
                gen_key(&mut rng, p.style, p.nkeys)
            };
            r.del(&k);
        } else if roll < t[2] {
            // narrow ranges (pg-log trim like), sometimes inverted/empty; one very wide range late in the run
            let wide = i == p.ops * 9 / 10;
            let (a, b) = if !wide && (rng.pct(90) && r.model.len() > 10) {
                let i = rng.below(r.model.len() as u64 - 1) as usize;
                let j = (i + rng.range(1, 60) as usize).min(r.model.len() - 1);
                (
                    r.model.keys().nth(i).unwrap().clone(),
                    r.model.keys().nth(j).unwrap().clone(),
                )
            } else {
                let a = gen_key(&mut rng, p.style, p.nkeys);
                let b = gen_key(&mut rng, p.style, p.nkeys);
                if wide {
                    if a <= b { (a, b) } else { (b, a) }
                } else if a <= b {
                    (a.clone(), a) // empty
                } else {
                    (a, b) // inverted
                }
            };
            r.delrange(&a, &b);
        } else if roll < t[3] {
            // multi-op txn (probe + atomic apply)
            let mut ops = Vec::new();
            for _ in 0..rng.range(2, 12) {
                let k = gen_key(&mut rng, p.style, p.nkeys);
                match rng.below(4) {
                    0 | 1 => ops.push(Op::Put(
                        k.clone(),
                        gen_val(&mut rng, max_val(&env, k.len()), p.vlen),
                    )),
                    2 => ops.push(Op::Del(k)),
                    _ => {
                        let mut b = k.clone();
                        b.push(0xff);
                        ops.push(Op::DelRange(k, b));
                    }
                }
            }
            r.apply(ops);
        } else if roll < t[4] {
            let k = if !r.model.is_empty() && rng.pct(60) {
                let i = rng.below(r.model.len() as u64) as usize;
                r.model.keys().nth(i).unwrap().clone()
            } else {
                gen_key(&mut rng, p.style, p.nkeys)
            };
            assert_eq!(r.get(&k), r.model.get(&k).cloned(), "get {k:?} at op {i}");
        } else if roll < t[5] {
            let a = gen_key(&mut rng, p.style, p.nkeys);
            let b = gen_key(&mut rng, p.style, p.nkeys);
            let (a, b) = if a <= b { (a, b) } else { (b, a) };
            let budget = rng.range(1, 40) as usize;
            assert_eq!(
                r.scan(&a, &b, budget),
                r.model_range(&a, &b),
                "scan at op {i}"
            );
            // one-descent predecessor + range: [greatest key <= a (if reached)] ++ keys in (a, b)
            if let Some(got) = r.scan_pred(&a, &b) {
                let mut want: Vec<(Vec<u8>, Vec<u8>)> = r
                    .model
                    .range(..=a.clone())
                    .next_back()
                    .filter(|(k, _)| *k < &b)
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .into_iter()
                    .collect();
                let from = want
                    .last()
                    .map(|e| e.0.clone())
                    .unwrap_or_else(|| a.clone());
                want.extend(r.model_range(&a, &b).into_iter().filter(|(k, _)| *k > from));
                assert_eq!(got, want, "scan_pred at op {i}");
            }
        } else {
            r.shard.request_checkpoint();
        }
        if i % 64 == 0 {
            r.max_height = r.max_height.max(r.shard.state().tree.height());
        }
        if i % 10000 == 0 {
            eprintln!(
                "  op {i}: {} keys, height {}",
                r.model.len(),
                r.shard.state().tree.height()
            );
        }
        if i % 2500 == 2499 {
            r.sync();
            r.verify();
        }
        if i % 6000 == 5999 {
            r.remount_clean();
            r.verify();
        }
    }
    r.sync();
    r.verify();
    r.remount_clean();
    r.verify();
    let rep = r.fsck(&r.disk.image());
    assert_eq!(rep.keys as usize, r.model.len());
    eprintln!(
        "random {:?} node {}: final {} keys, {} pages ({} leaves, {} empty); max height {}, {:?}",
        p.style, p.node, rep.keys, rep.pages, rep.leaves, rep.empty_leaves, r.max_height, r.acc
    );
    assert!(
        r.acc.splits > 15 && r.acc.pruned > 5 && (p.storm > 0 || r.max_height >= p.min_height),
        "workload too small to exercise the tree: {:?} h{}",
        r.acc,
        r.max_height
    );
    if p.cache < 1000 && p.storm == 0 && !matches!(p.style, Style::Long(_)) {
        assert!(
            r.acc.evictions > 100,
            "cache pressure test without evictions"
        );
    }
}

#[test]
fn tree_random_ops_4k_pages_dense_keys() {
    run_random(Params {
        node: 4096,
        style: Style::Dense,
        nkeys: 40_000,
        ops: 60_000,
        cache: 8192,
        seed: 1,
        min_height: 3,
        vlen: 300,
        storm: 0,
    });
}

#[test]
fn tree_random_ops_8k_pages_random_bytes() {
    run_random(Params {
        node: 8192,
        style: Style::RandomBytes,
        nkeys: 0,
        ops: 40_000,
        cache: 8192,
        seed: 2,
        min_height: 2,
        vlen: 150,
        storm: 0,
    });
}

#[test]
fn tree_random_ops_32k_pages_long_prefix() {
    run_random(Params {
        node: 32768,
        style: Style::LongPrefix,
        nkeys: 0,
        ops: 10_000,
        cache: 8192,
        seed: 3,
        min_height: 2,
        vlen: 150,
        storm: 0,
    });
}

#[test]
fn tree_random_ops_tricky_keys_prefixes_of_each_other() {
    run_random(Params {
        node: 4096,
        style: Style::Tricky,
        nkeys: 0,
        ops: 14_000,
        cache: 8192,
        seed: 4,
        min_height: 2,
        vlen: 150,
        storm: 0,
    });
}

/// The original slotted interior pages (stores made before adr 0021 am. 13) keep working: the same workloads on a
/// tree that has no compact page at all.
#[test]
fn tree_random_ops_legacy_slotted_interior_pages() {
    COMPACT_INT.set(false);
    run_random(Params {
        node: 4096,
        style: Style::Dense,
        nkeys: 40_000,
        ops: 60_000,
        cache: 8192,
        seed: 1,
        min_height: 3,
        vlen: 300,
        storm: 0,
    });
    run_random(Params {
        node: 4096,
        style: Style::Dense,
        nkeys: 30_000,
        ops: 30_000,
        cache: 160,
        seed: 5,
        min_height: 3,
        vlen: 150,
        storm: 0,
    });
    run_random(Params {
        node: 4096,
        style: Style::Tricky,
        nkeys: 0,
        ops: 14_000,
        cache: 8192,
        seed: 4,
        min_height: 2,
        vlen: 150,
        storm: 40,
    });
    COMPACT_INT.set(true);
}

#[test]
fn tree_random_ops_under_cache_pressure() {
    // 12-page cache against a tree of hundreds of pages: constant evictions, page reads, Miss retries
    run_random(Params {
        node: 4096,
        style: Style::Dense,
        nkeys: 30_000,
        ops: 30_000,
        cache: 160,
        seed: 5,
        min_height: 2, // compact interior pages: higher fanout, a lower tree
        vlen: 150,
        storm: 0,
    });
}

#[test]
fn tree_large_values_deep_tree() {
    // values up to the entry limit: 3-4 entries per 4 KiB leaf, splits cascade through many levels
    let env = make_env_ext(256, 1024, 1, ShardCfg::default(), 20, 4096);
    let mut r = Rig::new(&env, 11);
    let mut rng = Rng::new(11);
    for i in 0..3000u64 {
        let k = format!("big/{:06}", rng.below(2500)).into_bytes();
        let mut v = vec![0u8; max_val(&env, k.len()) - rng.below(200) as usize];
        rng.fill(&mut v);
        r.put(&k, &v);
        if i % 700 == 699 {
            r.sync();
            r.verify();
        }
    }
    assert!(
        r.shard.state().tree.height() >= 3,
        "height {}",
        r.shard.state().tree.height()
    );
    r.remount_clean();
    r.verify();
    // exact limit accepted, one byte more rejected atomically
    let k = b"limit".to_vec();
    let lim = store::tree::max_entry_for(4096) - 4 - k.len(); // the hard entry limit (adr 0021 am. 10)
    r.put(&k, &vec![7; lim]);
    let mut t = store::shard::Txn::<Vec<u8>>::new(1);
    t.put(b"zz", b"1").put(&k, &vec![7; lim + 1]);
    let before = r.shard.next_lsn();
    assert!(matches!(
        r.shard.submit(t),
        Err((StoreError::Invalid(_), _))
    ));
    assert_eq!(r.shard.next_lsn(), before);
    assert_eq!(r.get(b"zz"), None);
}

#[test]
fn tree_delrange_everything_frees_pages_and_collapses() {
    let env = make_env_ext(256, 1024, 1, ShardCfg::default(), 10, 4096);
    let mut r = Rig::new(&env, 21);
    for i in 0..8000u64 {
        r.put(format!("log/{i:08}").as_bytes(), &[0x5a; 40]);
    }
    r.checkpoint();
    let used_full = r.shard.statfs().meta_used;
    assert!(r.shard.state().tree.height() >= 2);
    // pg-log style trim in chunks, then drop the rest
    for i in (0..8000u64).step_by(500) {
        r.delrange(
            format!("log/{i:08}").as_bytes(),
            format!("log/{:08}", i + 400).as_bytes(),
        );
    }
    r.verify();
    r.delrange(b"log/", b"log0");
    assert!(r.model.is_empty());
    r.checkpoint();
    r.checkpoint_after_idle();
    let rep = r.fsck(&r.disk.image());
    assert_eq!(rep.keys, 0);
    assert!(
        rep.pages <= 2,
        "pages left after deleting everything: {}",
        rep.pages
    );
    let st = r.shard.statfs();
    // the surviving (empty) root leaf may still carry a delta: its delta page is not a leak
    let dp = r.shard.state().tree.delta_pages() as u64;
    assert!(
        st.meta_used <= 2 + dp,
        "meta pages leaked: {} (was {used_full}, delta pages {dp})",
        st.meta_used
    );
    assert_eq!(r.shard.state().tree.height(), 1);
    // and the tree is usable again
    for i in 0..300u64 {
        r.put(format!("n/{i}").as_bytes(), b"v");
    }
    r.remount_clean();
    r.verify();
}

impl Rig {
    /// A second checkpoint with nothing changed must not leak or loop; frees land one checkpoint later.
    fn checkpoint_after_idle(&mut self) {
        self.put(b"zz-touch", b"1");
        self.del(b"zz-touch");
        self.checkpoint();
    }
}

#[test]
fn tree_scan_budget_resume_with_concurrent_mutation() {
    let env = make_env_ext(256, 1024, 1, ShardCfg::default(), 10, 4096);
    let mut r = Rig::new(&env, 31);
    let mut rng = Rng::new(31);
    for _ in 0..4000 {
        let k = gen_key(&mut rng, Style::Dense, 6000);
        r.put(&k, b"v");
    }
    // full scans with several budgets equal the model
    for budget in [1usize, 2, 3, 7, 64, 100_000] {
        assert_eq!(
            r.scan(b"", b"\xff\xff", budget),
            r.model_range(b"", b"\xff\xff"),
            "budget {budget}"
        );
    }
    // a scan resumed across mutations stays strictly ascending and returns everything that was never touched
    use store::tree::{ScanCursor, ScanStatus};
    let untouched: Vec<Vec<u8>> = r.model.keys().step_by(7).cloned().collect();
    let mut cur = ScanCursor::new(b"", b"\xff\xff");
    let mut seen: Vec<Vec<u8>> = Vec::new();
    loop {
        let res = r
            .shard
            .scan(&mut cur, 25, usize::MAX, &mut |k, _| seen.push(k.to_vec()));
        match res {
            Ok(ScanStatus::Done) => break,
            Ok(ScanStatus::More) => {
                // mutate others (not the untouched set) between steps, incl. inserts ahead and behind
                for _ in 0..5 {
                    let k = gen_key(&mut rng, Style::Dense, 6000);
                    if !untouched.contains(&k) {
                        if rng.pct(50) {
                            r.put(&k, b"w");
                        } else {
                            r.del(&k);
                        }
                    }
                }
            }
            Err(StoreError::Miss) => r.pump(),
            Err(e) => panic!("{e:?}"),
        }
    }
    assert!(
        seen.windows(2).all(|w| w[0] < w[1]),
        "scan output not strictly ascending"
    );
    for k in &untouched {
        assert!(
            seen.binary_search(k).is_ok(),
            "scan lost untouched key {k:?}"
        );
    }
}

/// Range scans step leaf to leaf without a descent and skip the per-key end compare below the fence: random sub-ranges
/// (ends inside leaves, on separators, past the last key), budgets cutting inside and at leaf ends, warm cache, cold
/// remount (misses in the middle of a step) and a small cache (siblings evicted) all equal the model.
#[test]
fn tree_scan_ranges_step_between_leaves() {
    for (seed, style) in [
        (51u64, Style::Dense),
        (52, Style::Tricky),
        (53, Style::LongPrefix),
        (54, Style::Long(200)),
    ] {
        for cache in [16384usize, 24] {
            let cfg = ShardCfg {
                cache_pages: cache,
                ..Default::default()
            };
            let env = make_env_ext(256, 1024, 1, cfg, 10, 4096);
            let mut r = Rig::new(&env, seed);
            let mut rng = Rng::new(seed);
            for _ in 0..6000 {
                let k = gen_key(&mut rng, style, 8000);
                r.put(&k, &k[..k.len().min(9)]);
            }
            let keys: Vec<Vec<u8>> = r.model.keys().cloned().collect();
            let pick = |rng: &mut Rng| -> Vec<u8> {
                let mut k = keys[rng.below(keys.len() as u64) as usize].clone();
                match rng.below(3) {
                    0 => {}
                    1 => k.push(0),
                    _ => {
                        k.pop();
                    }
                }
                k
            };
            for round in 0..3 {
                if round == 1 {
                    r.remount_clean();
                }
                for _ in 0..40 {
                    let (mut a, mut b) = (pick(&mut rng), pick(&mut rng));
                    if a > b {
                        std::mem::swap(&mut a, &mut b);
                    }
                    if rng.pct(10) {
                        b = b"\xff\xff\xff".to_vec();
                    }
                    let budget = [1usize, 3, 31, 32, 33, 100, 100_000][rng.below(7) as usize];
                    assert_eq!(
                        r.scan(&a, &b, budget),
                        r.model_range(&a, &b),
                        "{style:?} cache {cache} round {round} budget {budget} [{a:?}, {b:?})"
                    );
                }
            }
        }
    }
}

#[test]
fn tree_fill_factor_sequential_vs_random() {
    // appends split at the right edge (leaves ~full); random inserts settle around ln 2
    let env = make_env_ext(256, 1024, 1, ShardCfg::default(), 10, 8192);
    let mut r = Rig::new(&env, 41);
    for i in 0..20_000u64 {
        r.put(format!("log/{i:010}").as_bytes(), &[1u8; 24]);
    }
    r.remount_clean();
    let seq = r.fsck(&r.disk.image());
    let raw = 20_000 * (4 + 14 + 24 + 2);
    let seq_fill = raw as f64 / (seq.leaves * 8192) as f64;
    let mut r2 = Rig::new(&env, 42);
    let mut rng = Rng::new(42);
    let mut n = 0;
    while n < 20_000 {
        let k = format!("rnd/{:010}", rng.below(1_000_000_000));
        if !r2.model.contains_key(k.as_bytes()) {
            r2.put(k.as_bytes(), &[1u8; 24]);
            n += 1;
        }
    }
    r2.remount_clean();
    let rnd = r2.fsck(&r2.disk.image());
    let rnd_fill = (n * (4 + 14 + 24 + 2)) as f64 / (rnd.leaves * 8192) as f64;
    eprintln!(
        "fill factor: sequential {seq_fill:.2} ({} leaves), random {rnd_fill:.2} ({} leaves)",
        seq.leaves, rnd.leaves
    );
    assert!(seq_fill > 0.85, "sequential fill {seq_fill}");
    assert!(rnd_fill > 0.5, "random fill {rnd_fill}");
}

#[test]
fn tree_prefix_truncation_saves_space() {
    let env = make_env_ext(256, 1024, 1, ShardCfg::default(), 10, 8192);
    let mut r = Rig::new(&env, 51);
    let prefix = "pool/0007/pg/0000ffff/objects/rbd_data.1234567890abcdef.";
    for i in 0..10_000u64 {
        r.put(format!("{prefix}{i:016x}").as_bytes(), &[3u8; 16]);
    }
    r.remount_clean();
    let rep = r.fsck(&r.disk.image());
    let untruncated = 10_000 * (4 + prefix.len() + 16 + 16 + 2);
    let bytes_used = rep.leaves * 8192;
    eprintln!(
        "prefix-heavy: {} leaves = {} KiB vs {} KiB without truncation",
        rep.leaves,
        bytes_used / 1024,
        untruncated / 1024
    );
    assert!(
        (bytes_used as usize) < untruncated / 2,
        "prefix truncation ineffective"
    );
}

#[test]
fn tree_cold_multi_op_txn_is_atomic_across_page_misses() {
    let cfg = ShardCfg {
        cache_pages: 400,
        ..Default::default()
    };
    let env = make_env_ext(256, 1024, 1, cfg, 10, 4096);
    let mut r = Rig::new(&env, 61);
    let mut rng = Rng::new(61);
    for i in 0..6000u64 {
        r.put(format!("k{i:06}").as_bytes(), &[9u8; 30]);
    }
    r.remount_clean();
    let loads0 = r.shard.tree_stats().loads;
    for round in 0..40 {
        let mut ops = Vec::new();
        for _ in 0..rng.range(5, 30) {
            let i = rng.below(6000);
            let k = format!("k{i:06}").into_bytes();
            match rng.below(5) {
                0 => ops.push(Op::Del(k)),
                1 => {
                    let mut b = format!("k{:06}", (i + rng.below(50)).min(5999)).into_bytes();
                    b.push(0);
                    ops.push(Op::DelRange(k, b));
                }
                _ => ops.push(Op::Put(k, vec![round as u8; rng.below(60) as usize])),
            }
        }
        r.apply(ops);
    }
    r.sync();
    r.verify();
    assert!(
        r.shard.tree_stats().loads > loads0 + 20,
        "no page misses happened"
    );
}

#[test]
fn tree_corrupted_and_misdirected_pages_are_detected() {
    let env = make_env_ext(64, 512, 1, ShardCfg::default(), 10, 4096);
    for variant in 0..3 {
        let mut r = Rig::new(&env, 71);
        for i in 0..3000u64 {
            r.put(format!("k{i:06}").as_bytes(), &[4u8; 30]);
        }
        r.checkpoint();
        let img = r.disk.image();
        let rep = r.fsck(&img);
        assert!(rep.height >= 2);
        let geom = store::layout::MetaGeom::new(&env.dir, 4096).unwrap();
        let (a, b) = (geom.pages_start, geom.pages_start + geom.bpp * 3);
        let mut img2 = img.clone();
        let d = SimDisk::from_image(&img, env.sim.clone());
        match variant {
            0 => {
                // bit flip in the middle of a page
                for page in 0..40u64 {
                    img2.corrupt(a + page * geom.bpp, 1000, 0x04);
                }
            }
            1 => {
                // valid page image at the wrong address (misdirected write): crc ok, self address wrong
                let mut dev = d.queue();
                let mut clk = SimClock::default();
                let mut io = Sio::new(&mut dev, &mut clk);
                let src = io.read_one(a, 1).unwrap();
                for page in 1..40u64 {
                    io.write_one(a + page * geom.bpp, &src).unwrap();
                }
                img2 = d.image();
                let _ = b;
            }
            _ => {
                // lost write: zeroed page
                let mut dev = d.queue();
                let mut clk = SimClock::default();
                let mut io = Sio::new(&mut dev, &mut clk);
                for page in 0..40u64 {
                    io.write_one(a + page * geom.bpp, &vec![0; 4096]).unwrap();
                }
                img2 = d.image();
            }
        }
        let d2 = SimDisk::from_image(&img2, env.sim.clone());
        let (mut dev, mut clk) = (d2.queue(), SimClock::default());
        assert!(
            store::fsck::fsck(&mut dev, &mut clk, None).is_err(),
            "variant {variant}: fsck missed corruption"
        );
        // a cold mount serves reads of the damaged pages as errors (never wrong data)
        let mut env2 = env.clone();
        env2.img = img2;
        let disk3 = SimDisk::from_image(&env2.img, env2.sim.clone());
        let mut clk3 = SimClock::default();
        let mut r2 = match mount(&env2, &disk3, &mut clk3) {
            Ok((shard, _)) => Rig {
                disk: disk3,
                clk: clk3,
                shard,
                ..Rig::new(&env, 72)
            },
            Err(StoreError::Corrupt(_) | StoreError::Io(_)) => continue, // damaged bitmap pages: mount refuses
            Err(e) => panic!("{e:?}"),
        };
        let mut errs = 0;
        for i in (0..3000u64).step_by(7) {
            let k = format!("k{i:06}");
            for _ in 0..100 {
                let mut out = Vec::new();
                match r2.shard.get(k.as_bytes(), &mut out) {
                    Err(StoreError::Miss) => r2.pump(),
                    Err(StoreError::Corrupt(_) | StoreError::Io(_)) => {
                        errs += 1;
                        break;
                    }
                    Ok(true) => {
                        assert_eq!(out, vec![4u8; 30], "wrong data served");
                        break;
                    }
                    Ok(false) => panic!("variant {variant}: key vanished silently"),
                    Err(e) => panic!("{e:?}"),
                }
            }
        }
        assert!(
            errs > 0,
            "variant {variant}: damaged pages served without error"
        );
    }
}

#[test]
fn tree_page_read_error_is_reported_not_retried_forever() {
    let env = make_env_ext(64, 512, 1, ShardCfg::default(), 10, 4096);
    let mut r = Rig::new(&env, 81);
    for i in 0..3000u64 {
        r.put(format!("k{i:06}").as_bytes(), &[4u8; 30]);
    }
    r.remount_clean();
    let geom = store::layout::MetaGeom::new(&env.dir, 4096).unwrap();
    // every page of the meta region becomes unreadable (media error)
    r.disk
        .fail_reads(geom.pages_start, geom.npages as u64 * geom.bpp);
    let mut errs = 0;
    for i in (0..3000u64).step_by(97) {
        for _ in 0..1000 {
            let mut out = Vec::new();
            match r.shard.get(format!("k{i:06}").as_bytes(), &mut out) {
                Err(StoreError::Miss) => r.pump(),
                Err(StoreError::Io(_)) => {
                    errs += 1;
                    break;
                }
                Ok(true) => break, // served from cache
                other => panic!("{other:?}"),
            }
        }
    }
    assert!(errs > 0);
    // writes into the unreadable part fail too (txn refused, shard stays alive)
    let mut t = store::shard::Txn::<Vec<u8>>::new(1);
    t.put(b"k000500", b"x");
    let mut res = None;
    for _ in 0..1000 {
        match r.shard.submit(t) {
            Err((StoreError::Miss, back)) => {
                t = back;
                r.pump();
            }
            other => {
                res = Some(other.map(|_| ()).map_err(|(e, _)| e));
                break;
            }
        }
    }
    assert!(matches!(res, Some(Err(StoreError::Io(_)))), "{res:?}");
    assert!(!r.shard.is_failed());
}

#[test]
fn checkpoint_write_error_fails_the_shard_cleanly() {
    let env = make_env_ext(64, 512, 1, ShardCfg::default(), 10, 4096);
    let mut r = Rig::new(&env, 82);
    for i in 0..500u64 {
        r.put(format!("k{i:06}").as_bytes(), &[4u8; 30]);
    }
    r.sync();
    let geom = store::layout::MetaGeom::new(&env.dir, 4096).unwrap();
    r.disk
        .fail_writes(geom.pages_start, geom.npages as u64 * geom.bpp);
    r.shard.request_checkpoint();
    let mut failed = false;
    for _ in 0..10_000 {
        let mut ev = Vec::new();
        r.shard.poll(r.clk.t, &mut ev);
        failed |= ev
            .iter()
            .any(|e| matches!(e, store::shard::Event::Failed(_)));
        if failed {
            break;
        }
        let h = r.shard.dev().next_deadline();
        store::dev::Clock::idle(&mut r.clk, h);
    }
    assert!(failed && r.shard.is_failed());
    let t = store::shard::Txn::<Vec<u8>>::new(1);
    assert!(matches!(r.shard.submit(t), Err((StoreError::Failed, _))));
    // the durable state is still a consistent older checkpoint + WAL: a fresh mount recovers everything acked
    let img = r.disk.crash_image(store::dev::CrashPolicy::DROP_ALL);
    let mut env2 = env.clone();
    env2.img = img;
    let mut r2 = Rig::new(&env2, 83);
    assert_eq!(r2.get(b"k000499"), Some(vec![4u8; 30]));
    assert_eq!(r2.get(b"k000000"), Some(vec![4u8; 30]));
}

/// One txn with many DelRange ops that together empty a multi-level tree (remove_pg of many PGs): later
/// ranges must prune through an already-emptied interior root.
#[test]
fn tree_multi_range_txn_empties_tree() {
    let env = make_env_ext(256, 1024, 1, ShardCfg::default(), 10, 4096);
    let mut r = Rig::new(&env, 22);
    for pg in 0..32u64 {
        for i in 0..300u64 {
            r.put(format!("c/{pg:04}/{i:08}").as_bytes(), &[0x5a; 40]);
        }
    }
    r.checkpoint();
    assert!(r.shard.state().tree.height() >= 2);
    let mut ops: Vec<Op> = (0..32u64)
        .map(|pg| {
            Op::DelRange(
                format!("c/{pg:04}/").into_bytes(),
                format!("c/{pg:04}0").into_bytes(),
            )
        })
        .collect();
    // a later range hitting the already emptied tree
    ops.push(Op::DelRange(b"c/".to_vec(), b"c0".to_vec()));
    r.apply(ops);
    assert!(r.model.is_empty());
    r.verify();
    r.checkpoint();
    r.remount_clean();
    r.verify();
    assert_eq!(r.shard.state().tree.height(), 1);
}

#[test]
fn tree_random_many_op_txns_small_tree_empties_and_regrows() {
    // storm-heavy: the tree repeatedly collapses to (near) empty and regrows through multi-range txns
    for (seed, node, style, nkeys) in [
        (31u64, 4096u32, Style::Dense, 20000u64),
        (32, 4096, Style::Tricky, 0),
        (33, 8192, Style::RandomBytes, 0),
        (34, 4096, Style::LongPrefix, 0),
    ] {
        run_random(Params {
            node,
            style,
            nkeys,
            ops: 8000,
            cache: 8192,
            seed,
            min_height: 1,
            vlen: 120,
            storm: 12,
        });
    }
}

#[test]
fn tree_random_many_op_txns_under_cache_pressure() {
    run_random(Params {
        node: 4096,
        style: Style::Dense,
        nkeys: 6000,
        ops: 5000,
        cache: 100,
        seed: 35,
        min_height: 2,
        vlen: 120,
        storm: 60,
    });
}

#[test]
#[ignore = "soak"]
fn tree_storm_soak() {
    for seed in 100..160u64 {
        let styles = [
            Style::Dense,
            Style::Tricky,
            Style::RandomBytes,
            Style::LongPrefix,
        ];
        run_random(Params {
            node: [4096, 8192][(seed % 2) as usize],
            style: styles[(seed % 4) as usize],
            nkeys: 1000 + seed * 53 % 6000,
            ops: 12_000,
            cache: [8192, 1200][(seed % 3 == 0) as usize],
            seed,
            min_height: 1,
            vlen: 150,
            storm: 20 + (seed % 7) * 15,
        });
    }
}

/// Grow a multi-level tree, then ONE many-op storm txn, repeat (the failing shape of the prune bug: ranges after
/// the tree was emptied by earlier ranges of the same txn).
fn storm_cycles(seed: u64, node: u32, style: Style, nkeys: u64, cycles: u32) {
    let cfg = ShardCfg {
        dirty_soft_pages: 64,
        ..Default::default()
    };
    let env = make_env_ext(256, 1024, 1, cfg, 10, node);
    let mut r = Rig::new(&env, seed);
    let mut rng = Rng::new(seed);
    let p = Params {
        node,
        style,
        nkeys,
        ops: 0,
        cache: 8192,
        seed,
        min_height: 0,
        vlen: 60,
        storm: 0,
    };
    let (mut tall, mut emptied) = (0u32, 0u32);
    for c in 0..cycles {
        let target = rng.range(150, 1200);
        while (r.model.len() as u64) < target {
            let ops: Vec<Op> = (0..64)
                .map(|_| {
                    let k = gen_key(&mut rng, p.style, p.nkeys);
                    let v = gen_val(&mut rng, max_val(&env, k.len()), p.vlen);
                    Op::Put(k, v)
                })
                .collect();
            r.apply(ops);
        }
        if rng.pct(50) {
            r.shard.request_checkpoint();
        }
        if rng.pct(30) {
            r.sync();
        }
        tall += (r.shard.state().tree.height() >= 2) as u32;
        let ops = storm_txn(&mut rng, &r, &p, &env);
        r.apply(ops);
        emptied += r.model.is_empty() as u32;
        r.sync();
        r.verify();
        if c % 7 == 6 {
            r.remount_clean();
            r.verify();
        }
    }
    r.sync();
    r.remount_clean();
    r.verify();
    let rep = r.fsck(&r.disk.image());
    assert_eq!(rep.keys as usize, r.model.len());
    assert!(tall * 2 > cycles, "trees too small: {tall}/{cycles}");
    eprintln!("storm cycles seed {seed} node {node}: {tall} tall, {emptied} emptied of {cycles}");
}

#[test]
fn tree_storm_cycles_grow_then_many_op_txn() {
    for (seed, node, style, nkeys) in [
        (41u64, 4096u32, Style::Dense, 5000u64),
        (42, 4096, Style::Tricky, 0),
        (43, 8192, Style::RandomBytes, 0),
        (44, 4096, Style::LongPrefix, 0),
    ] {
        storm_cycles(seed, node, style, nkeys, 60);
    }
}

#[test]
#[ignore = "soak"]
fn tree_storm_cycles_soak() {
    for seed in 200..260u64 {
        let styles = [
            Style::Dense,
            Style::Tricky,
            Style::RandomBytes,
            Style::LongPrefix,
        ];
        storm_cycles(
            seed,
            [4096, 8192][(seed % 2) as usize],
            styles[(seed % 4) as usize],
            2000 + seed * 97 % 9000,
            150,
        );
    }
}

fn long_style(node: u32) -> Style {
    Style::Long(store::tree::max_key_for(node as usize))
}

#[test]
fn tree_random_ops_long_keys_4k_pages() {
    // keys up to 1275 B in 4 KiB pages (2-3 entries per page at the extreme): splits of pages whose half-bytes point
    // does not fit, interior pages with 2 children, shared long prefixes, keys that are prefixes of each other
    run_random(Params {
        node: 4096,
        style: long_style(4096),
        nkeys: 0,
        ops: 12_000,
        cache: 8192,
        seed: 21,
        min_height: 2,
        vlen: 200,
        storm: 0,
    });
}

#[test]
fn tree_random_ops_long_keys_8k_pages_small_cache() {
    run_random(Params {
        node: 8192,
        style: long_style(8192),
        nkeys: 0,
        ops: 12_000,
        cache: 64,
        seed: 22,
        min_height: 2,
        vlen: 200,
        storm: 0,
    });
}

#[test]
fn tree_random_ops_long_keys_with_storms() {
    run_random(Params {
        node: 8192,
        style: long_style(8192),
        nkeys: 0,
        ops: 8_000,
        cache: 8192,
        seed: 23,
        min_height: 1,
        vlen: 200,
        storm: 150,
    });
}

#[test]
fn tree_max_size_entries_split_cleanly() {
    // every entry at the limit (longest key + room): each page holds 1-2 entries; ascending, descending and random order
    for node in [4096u32, 8192, 16384] {
        let env = make_env_ext(256, 1024, 1, ShardCfg::default(), 20, node);
        let mut r = Rig::new(&env, 31);
        let mk = store::tree::max_key_for(node as usize);
        let mut rng = Rng::new(31);
        let mut order: Vec<u32> = (0..300).collect();
        for pass in 0..3 {
            match pass {
                1 => order.reverse(),
                2 => {
                    for i in (1..order.len()).rev() {
                        order.swap(i, rng.below(i as u64 + 1) as usize);
                    }
                }
                _ => {}
            }
            for &i in &order {
                let mut k = vec![b'k'; mk - 4];
                k.extend_from_slice(&(i * 3 + pass).to_be_bytes());
                let v = vec![i as u8; max_val(&env, k.len())];
                r.put(&k, &v);
            }
            r.sync();
            r.verify();
        }
        r.remount_clean();
        r.verify();
        let rep = r.fsck(&r.disk.image());
        assert_eq!(rep.keys as usize, r.model.len());
    }
}

/// Compact interior pages (am. 13) under insert/delete churn of long keys that share ~1200 B with their neighbours
/// only (three groups): descending inserts land at one interior position (in-place inserts), removals of emptied
/// leaves drop separators (restarts among them) and merge runs; remounts and verification against the model. The
/// exact page state where a fresh re-encode cannot split is pinned at page level
/// (`page::tests::compact_split_after_churn_keeps_restarts`).
#[test]
fn tree_compact_interior_churn_long_shared_keys() {
    let env = make_env_ext(
        64,
        4096,
        1,
        ShardCfg {
            dirty_soft_pages: 256,
            ..Default::default()
        },
        30,
        8192,
    );
    let mut r = Rig::new(&env, 11);
    let key = |g: u8, i: u64| {
        let mut k = vec![g];
        k.extend(std::iter::repeat_n(b'x', 1200));
        k.extend_from_slice(format!("{i:07}").as_bytes());
        k
    };
    for g in *b"abc" {
        r.put(&key(g, 0), b"head");
    }
    let mut rng = Rng::new(17);
    let mut next = 9_000_000u64;
    for round in 0..120u64 {
        let g = b"abc"[(round % 3) as usize];
        let first = next;
        for _ in 0..400 {
            next -= 1;
            r.put(&key(g, next), &[round as u8; 8]);
        }
        for i in next..first {
            if rng.pct(90) {
                r.del(&key(g, i));
            }
        }
        if round % 20 == 19 {
            r.sync();
            r.verify();
            r.remount_clean();
        }
    }
    r.sync();
    r.verify();
    r.remount_clean();
    r.verify();
}

/// Adr 0021 am. 29: a sweep of deletes that leaves every 5th key must not leave the pages 80% empty: underfull leaves
/// merge into a resident neighbour at the end of the txn that thinned them.
#[test]
fn tree_sparse_sweep_merges_underfull_leaves() {
    let env = make_env_ext(256, 1024, 1, ShardCfg::default(), 10, 8192);
    let mut r = Rig::new(&env, 77);
    let n = 20_000u64;
    for i in 0..n {
        r.put(format!("k/{i:08}").as_bytes(), &[0x5a; 40]);
    }
    r.checkpoint();
    let before = r.fsck(&r.disk.image());
    for i in 0..n {
        if i % 5 != 0 {
            r.del(format!("k/{i:08}").as_bytes());
        }
    }
    r.verify();
    let merged = r.shard.state().tree.stats.merged;
    r.sync();
    // power loss before any checkpoint of the merged tree: the checkpointed older tree + WAL replay (which merges the same
    // way, or differently) must give exactly the acked content
    for (k, pol) in [
        CrashPolicy::DROP_ALL,
        CrashPolicy::MIXED,
        CrashPolicy::PERSIST_ALL,
    ]
    .into_iter()
    .enumerate()
    {
        let img = r.disk.crash_image(pol);
        r.fsck(&img);
        let mut env2 = env.clone();
        env2.img = img;
        let mut r2 = Rig::new(&env2, 90 + k as u64);
        let got = r2.shard.dump_blocking(&mut r2.clk).unwrap();
        assert!(
            got == r.model,
            "crash leg {k}: content differs from the acked model"
        );
    }
    r.checkpoint();
    r.checkpoint_after_idle();
    let after = r.fsck(&r.disk.image());
    eprintln!(
        "merge sweep: leaves {} -> {} (merged {merged}), fill {:.0}% -> {:.0}%",
        before.leaves,
        after.leaves,
        100.0 * before.kv_bytes as f64 / (before.leaves * 8192) as f64,
        100.0 * after.kv_bytes as f64 / (after.leaves * 8192) as f64
    );
    assert!(merged > 0, "no leaf was merged");
    assert!(
        after.leaves * 2 < before.leaves,
        "sparse leaves stayed: {} -> {}",
        before.leaves,
        after.leaves
    );
    assert_eq!(after.keys, n / 5);
    // keep working on the merged tree: refill the holes, delete again, cold remount, everything intact
    for i in 0..n {
        if i % 5 != 0 {
            r.put(format!("k/{i:08}").as_bytes(), &[0x6b; 40]);
        }
    }
    r.remount_clean();
    r.verify();
    let _ = r.fsck(&r.disk.image());
}

/// L1 / G8 (store-durability review): delete-heavy work during a sliced freeze. A pending interior page that is pruned
/// leaves a dead shadow behind in its slab slot; the slot is reused at once (LIFO) by a page loaded from disk, and when
/// that page is retired before the freeze reaches the slot, its address must still be freed (fsck: no leaked meta
/// page).
#[test]
fn sliced_freeze_with_prunes_and_slot_reuse_leaks_nothing() {
    let env = make_env_ext(
        256,
        2048,
        1,
        ShardCfg {
            ckpt_slice: 1,
            ckpt_fz_polls: 0,
            auto_ckpt: false,
            ..Default::default()
        },
        20,
        4096,
    );
    let mut r = Rig::new(&env, 97);
    let key = |g: u64, i: u64| format!("g{g:03}/{i:06}").into_bytes();
    // groups 0..40: rewritten every round; 40..: cold, each loaded and dropped once inside a freeze
    let ncold = 400u64;
    for g in 0..40 + ncold {
        for i in 0..400u64 {
            r.put(&key(g, i), &[g as u8; 60]);
        }
        r.checkpoint();
    }
    r.remount_clean();
    assert!(r.shard.state().tree.height() >= 3);
    let mut rng = Rng::new(97);
    let (mut busy, mut cold) = (0, 40u64);
    for round in 0..30u64 {
        // splits in every hot group: dirty interior pages, pending in the next freeze
        for g in 0..40u64 {
            for i in 0..60u64 {
                let mut k = key(g, i * 7);
                k.extend_from_slice(format!(".{round}").as_bytes());
                r.put(&k, &[2; 60]);
            }
        }
        r.sync();
        r.shard.request_checkpoint();
        r.pump();
        let mut ops = 0;
        while r.shard.ckpt_active() && ops < 12 && cold < 40 + ncold {
            // drop a hot group (prunes pending interior pages: their slots become free), load a cold group into the
            // freed slots and drop it again before the freeze reaches those slots
            let g = rng.below(40);
            r.delrange(&key(g, 0), &key(g, 1_000_000));
            assert!(r.get(&key(cold, 200)).is_some());
            r.delrange(&key(cold, 0), &key(cold, 1_000_000));
            cold += 1;
            for i in 0..400u64 {
                r.put(&key(g, i), &[round as u8; 60]);
            }
            ops += 1;
            r.sync();
            r.pump();
        }
        busy += ops;
        r.checkpoint();
    }
    eprintln!("rounds with work inside the freeze: {busy}");
    assert!(busy > 30, "the freeze never overlapped the deletes");
    r.verify();
    // fsck before and after a cold remount: the meta bitmap must equal the reachable pages
    r.remount_clean();
    r.verify();
}

/// Review store/tree.rs T1: a root slot that references a tree root but records height 0 makes the tree read its page
/// level as `height - 1` (255): the mount refuses the slot as corrupt instead of accepting a tree that cannot route.
#[test]
fn root_slot_with_height_zero_is_refused_at_mount() {
    let env = make_env(16, 128, 1, ShardCfg::default());
    let mut r = Rig::new(&env, 11);
    for i in 0..500u64 {
        r.put(format!("k/{i:08}").as_bytes(), b"v");
    }
    r.checkpoint();
    let img = r.disk.image();
    let blk = newest_root_blk(&env.dir, &img);
    let mut slot = store::layout::RootSlot::decode(&img.read_lba(blk)).expect("root slot");
    assert_ne!(slot.tree_root, 0);
    slot.tree_height = 0;
    let d = SimDisk::from_image(&img, env.sim.clone());
    Sio::new(&mut d.queue(), &mut SimClock::default())
        .write_one(blk, &slot.encode())
        .unwrap();
    let bad = SimDisk::from_image(&d.image(), env.sim.clone());
    match mount(&env, &bad, &mut SimClock::default()) {
        Err(StoreError::Corrupt(m)) => assert!(m.contains("height 0"), "{m}"),
        Err(e) => panic!("expected a corrupt root slot, got {e:?}"),
        Ok(_) => panic!("a root slot with tree root and height 0 was mounted"),
    }
}
