// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
//! GC prefix manifests preserve every unfinished key/version, reader lease and acknowledged transaction.
#![cfg(feature = "lab")]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use store::StoreError;
use store::dev::{BlockDev, Clock, CrashPolicy, SimClock, SimConfig, SimDev, SimDisk, SimImage};
use store::layout::{MkfsParams, mkfs, read_super};
use store::olsm::job::{self, MergeOut};
use store::olsm::labdev::{MemBlocks, SimBlocks};
use store::olsm::manifest::RunDesc;
use store::olsm::read;
use store::olsm::run::load_chunk;
use store::olsm::wire::{OOp, del_blob, put_blob};
use store::olsm::{CHUNK_TARGET, Manifest, Olsm, RunMeta};
use store::rng::Rng;
use store::shard::{Event, Shard, ShardCfg, Txn};
use store::state::Op;

const KEYS: u64 = 4096;
type Model = BTreeMap<Vec<u8>, Vec<u8>>;

fn key(i: u64) -> Vec<u8> {
    format!("key-{i:06}").into_bytes()
}
fn value(i: u64, generation: u8) -> Vec<u8> {
    let mut v = vec![generation; 512];
    v[..8].copy_from_slice(&i.to_le_bytes());
    v
}
fn deletion_order() -> Vec<u64> {
    let mut ids: Vec<_> = (0..KEYS).collect();
    let mut rng = Rng::new(1002);
    for i in (1..ids.len()).rev() {
        let j = rng.below((i + 1) as u64) as usize;
        ids.swap(i, j);
    }
    ids.truncate(KEYS as usize / 2);
    ids
}
fn flush(o: &mut Olsm, dev: &mut MemBlocks) {
    if o.freeze().is_none() {
        return;
    }
    let mem = o.frozen.clone().unwrap();
    let id = o.man.alloc_run_id();
    let (run, _) = job::flush(&mem, id, dev).unwrap().unwrap();
    o.flush_done(run);
}
fn install(o: &mut Olsm, dev: &mut MemBlocks, inputs: &[Arc<RunMeta>], out: MergeOut) -> bool {
    let partial = out.prefix_end.is_some();
    for suffix in &out.residuals {
        let original = inputs.iter().find(|r| r.id == suffix.id).unwrap();
        assert_eq!(
            (suffix.lsn_lo, suffix.lsn_hi),
            (original.lsn_lo, original.lsn_hi)
        );
        if original.place.tier == 0 {
            assert_eq!(suffix.place, original.place);
        }
    }
    let freed = out.freed;
    o.man.install_gc_prefix(inputs, out.runs, out.residuals);
    let live: Vec<_> = o
        .man
        .runs()
        .flat_map(|r| {
            std::iter::once((r.meta_blk, r.meta_nblk))
                .chain(r.fences.iter().map(|f| (f.blk, f.nblk)))
        })
        .collect();
    for (blk, nblk) in freed {
        assert!(
            live.iter()
                .all(|&(b, n)| blk + u64::from(nblk) <= b || b + u64::from(n) <= blk),
            "a GC prefix cannot free a live suffix/output extent: {blk}+{nblk}"
        );
        dev.free(blk, nblk);
    }
    partial
}
fn check_engine(o: &Olsm, dev: &mut MemBlocks, expected: &Model) {
    let got: Model = read::list_from(&o.sources(), dev, 1, b"", false, b"", usize::MAX)
        .unwrap()
        .0
        .into_iter()
        .map(|(k, v)| (k.to_vec(), v.to_vec()))
        .collect();
    assert_eq!(&got, expected);
    for i in (0..KEYS).step_by(97) {
        assert_eq!(
            read::get(&o.sources(), dev, 1, &key(i))
                .unwrap()
                .map(|v| v.to_vec()),
            expected.get(&key(i)).cloned()
        );
    }
    // Every generation of residual metadata must decode with the unchanged RunDesc codec and mount independently.
    let descs: Vec<_> = o
        .man
        .runs()
        .map(|r| RunDesc::decode(&RunDesc::of(r).encode()).unwrap())
        .collect();
    let remounted = Olsm::new(Manifest::mount(o.man.n0, o.man.flushed_lsn, &descs, dev).unwrap());
    let got: Model = read::list_from(&remounted.sources(), dev, 1, b"", false, b"", usize::MAX)
        .unwrap()
        .0
        .into_iter()
        .map(|(k, v)| (k.to_vec(), v.to_vec()))
        .collect();
    assert_eq!(&got, expected);
    for run in remounted.man.runs() {
        for ci in 0..run.fences.len() {
            load_chunk(dev, run, ci).unwrap();
        }
    }
}
fn engine_base() -> (Olsm, MemBlocks, Model, u64) {
    let mut o = Olsm::new(Manifest::new(CHUNK_TARGET as u64));
    let mut dev = MemBlocks::new();
    let mut expected = Model::new();
    let mut lsn = 0;
    for base in (0..KEYS).step_by(512) {
        for i in base..base + 512 {
            lsn += 1;
            o.active.put(lsn, 1, key(i).into(), value(i, 0).into());
            expected.insert(key(i), value(i, 0));
        }
        flush(&mut o, &mut dev);
        while let Some(p) = o.man.pick_sized() {
            let inputs = p.inputs.clone();
            let out = job::merge(p, &mut dev).unwrap();
            install(&mut o, &mut dev, &inputs, out);
        }
    }
    (o, dev, expected, lsn)
}

#[test]
fn gc_prefix_preserves_random_half_deletion_and_newer_flush_across_every_mount() {
    let (mut o, mut dev, mut expected, mut lsn) = engine_base();
    for i in deletion_order() {
        lsn += 1;
        o.active.del(lsn, 1, key(i).into());
        expected.remove(&key(i));
    }
    flush(&mut o, &mut dev);
    let mut prefixes = 0;
    let mut concurrent_flush = false;
    for _ in 0..256 {
        let Some(p) = o.man.pick_merge(false) else {
            break;
        };
        let inputs = p.inputs.clone();
        let out = job::merge(p, &mut dev).unwrap();
        if out.prefix_end.is_some() && !concurrent_flush {
            // The job was picked before these puts. Retaining suffix IDs must leave this younger T0 flush first.
            for i in [0, 1, KEYS / 2, KEYS - 1] {
                lsn += 1;
                o.active.put(lsn, 1, key(i).into(), value(i, 9).into());
                expected.insert(key(i), value(i, 9));
            }
            flush(&mut o, &mut dev);
            concurrent_flush = true;
        }
        prefixes += usize::from(install(&mut o, &mut dev, &inputs, out));
        check_engine(&o, &mut dev, &expected);
    }
    assert!(
        prefixes >= 2 && concurrent_flush,
        "fixture must exercise repeated partial installs, got {prefixes}"
    );
    assert!(
        o.man.pick_merge(false).is_none(),
        "prefix GC must make forward progress, including moved clean prefixes"
    );
    check_engine(&o, &mut dev, &expected);
}

#[test]
fn gc_prefix_range_boundaries_and_empty_output_do_not_resurrect_old_values() {
    for clear_all in [false, true] {
        let (mut o, mut dev, mut expected, mut lsn) = engine_base();
        let (lo, hi) = if clear_all {
            (0, KEYS)
        } else {
            (KEYS / 4 + 3, KEYS * 3 / 4 + 7)
        };
        lsn += 1;
        o.active
            .del_range(lsn, 1, key(lo).into(), Some(key(hi).into()));
        expected.retain(|k, _| *k < key(lo) || *k >= key(hi));
        // Values written after the range survive on both sides of likely chunk/prefix boundaries.
        for i in [lo, lo + 1, hi - 1] {
            lsn += 1;
            o.active.put(lsn, 1, key(i).into(), value(i, 7).into());
            expected.insert(key(i), value(i, 7));
        }
        flush(&mut o, &mut dev);
        let mut jobs = 0;
        for _ in 0..256 {
            let Some(p) = o.man.pick_merge(false) else {
                break;
            };
            let inputs = p.inputs.clone();
            let out = job::merge(p, &mut dev).unwrap();
            install(&mut o, &mut dev, &inputs, out);
            check_engine(&o, &mut dev, &expected);
            jobs += 1;
        }
        assert!(jobs > 0 && o.man.pick_merge(false).is_none());
    }
}

fn shard_cfg() -> ShardCfg {
    ShardCfg {
        cache_pages: 96,
        ..ShardCfg::default()
    }
}
fn mount(image: &SimImage, cfg: &SimConfig) -> (SimDisk, SimClock, Shard<SimDev>) {
    let disk = SimDisk::from_image(image, cfg.clone());
    let mut clk = SimClock::default();
    let mut dev = disk.queue();
    let (sb, dirs) = read_super(&mut dev, &mut clk).unwrap();
    let (s, _) = Shard::mount(dev, &mut clk, &sb, &dirs[0], shard_cfg(), false).unwrap();
    (disk, clk, s)
}
fn descs(s: &Shard<SimDev>) -> BTreeMap<u64, Arc<RunMeta>> {
    s.state()
        .olsm
        .as_ref()
        .unwrap()
        .man
        .runs()
        .map(|r| (r.id, r.clone()))
        .collect()
}
#[derive(Default)]
struct Trace {
    first_prefix_event: Option<u64>,
    retired: Vec<Arc<RunMeta>>,
}
fn poll(
    s: &mut Shard<SimDev>,
    clk: &mut SimClock,
    disk: &SimDisk,
    origin: u64,
    trace: &mut Trace,
) -> Result<Vec<u64>, ()> {
    if disk.crashed() {
        return Err(());
    }
    let before = descs(s);
    let mut ev = Vec::new();
    s.poll(clk.now(), &mut ev);
    if disk.crashed() {
        return Err(());
    }
    let after = descs(s);
    if trace.first_prefix_event.is_none() {
        let retired: Vec<_> = before
            .iter()
            .filter(|(id, old)| after.get(*id).is_some_and(|r| r.meta_blk != old.meta_blk))
            .map(|(_, r)| r.clone())
            .collect();
        if !retired.is_empty() {
            trace.first_prefix_event = Some(disk.events() - origin);
            trace.retired = retired;
        }
    }
    let mut acked = Vec::new();
    for e in ev {
        match e {
            Event::Acked(t) => acked.push(t),
            Event::Failed(e) => panic!("unexpected non-crash failure: {e:?}"),
            _ => {}
        }
    }
    clk.idle(s.dev().next_deadline());
    Ok(acked)
}
fn put_txn(token: u64, lo: u64, hi: u64) -> Txn<Vec<u8>> {
    let pairs: Vec<_> = (lo..hi).map(|i| (key(i), value(i, 0))).collect();
    let (n, blob) = put_blob(&pairs);
    let mut t = Txn::new(token);
    t.ops.push(Op::Omap(OOp::Put { id: 1, n, blob }));
    t
}
fn submit_wait(
    s: &mut Shard<SimDev>,
    clk: &mut SimClock,
    disk: &SimDisk,
    mut t: Txn<Vec<u8>>,
    origin: u64,
    trace: &mut Trace,
) -> Result<(), ()> {
    let token = t.token;
    let mut admitted = false;
    for _ in 0..100_000 {
        match s.submit(t) {
            Ok(_) => {
                admitted = true;
                break;
            }
            Err((StoreError::Busy | StoreError::WalFull | StoreError::Miss, back)) => t = back,
            Err((_, _)) if disk.crashed() => return Err(()),
            Err((e, _)) => panic!("submit: {e:?}"),
        }
        poll(s, clk, disk, origin, trace)?;
    }
    assert!(
        admitted,
        "WARNING TIMEOUT GC-prefix transaction admission exceeded100000 polls"
    );
    for _ in 0..100_000 {
        if poll(s, clk, disk, origin, trace)?.contains(&token) {
            return Ok(());
        }
    }
    panic!("WARNING TIMEOUT GC-prefix transaction ack exceeded100000 polls");
}
fn shard_base() -> (SimImage, SimConfig) {
    let cfg = SimConfig::new(96 << 20);
    let disk = SimDisk::new(cfg.clone());
    let mut dev = disk.queue();
    let mut clk = SimClock::default();
    mkfs(
        &mut dev,
        &mut clk,
        &MkfsParams {
            shards: 1,
            wal_blocks: 2048,
            align_blocks: 1,
            omap_lsm: true,
            ..Default::default()
        },
    )
    .unwrap();
    let (disk, mut clk, mut s) = mount(&disk.image(), &cfg);
    let origin = disk.events();
    let mut trace = Trace::default();
    for (b, lo) in (0..KEYS).step_by(128).enumerate() {
        submit_wait(
            &mut s,
            &mut clk,
            &disk,
            put_txn(b as u64 + 1, lo, lo + 128),
            origin,
            &mut trace,
        )
        .unwrap();
    }
    s.request_checkpoint();
    for _ in 0..512 {
        poll(&mut s, &mut clk, &disk, origin, &mut trace).unwrap();
    }
    (disk.crash_image(CrashPolicy::PERSIST_ALL), cfg)
}
fn delete_half(
    s: &mut Shard<SimDev>,
    clk: &mut SimClock,
    disk: &SimDisk,
    trace: &mut Trace,
) -> (usize, usize) {
    let origin = disk.events();
    let mut acked = 0;
    let mut submitted = 0;
    for (i, batch) in deletion_order().chunks(64).enumerate() {
        let keys: Vec<_> = batch.iter().map(|&i| key(i)).collect();
        let mut t = Txn::new(10_000 + i as u64);
        t.ops.push(Op::Omap(OOp::Del {
            id: 1,
            blob: del_blob(&keys),
        }));
        submitted += 1;
        if submit_wait(s, clk, disk, t, origin, trace).is_err() {
            return (acked, submitted);
        }
        acked += 1;
    }
    for _ in 0..256 {
        if poll(s, clk, disk, origin, trace).is_err() {
            break;
        }
    }
    (acked, submitted)
}
fn shard_contents(s: &mut Shard<SimDev>, clk: &mut SimClock) -> Model {
    let mut result = Model::new();
    let mut from = Vec::new();
    let mut excl = false;
    for _ in 0..100_000 {
        match s.olsm_list(None, 1, &from, excl, b"", 127) {
            Ok((page, more)) => {
                for (k, v) in &page {
                    result.insert(k.to_vec(), v.to_vec());
                }
                if !more {
                    return result;
                }
                from = page.last().unwrap().0.to_vec();
                excl = true;
            }
            Err(StoreError::Miss) => {
                let mut ev = Vec::new();
                s.poll(clk.now(), &mut ev);
                assert!(!ev.iter().any(|e| matches!(e, Event::Failed(_))));
                clk.idle(s.dev().next_deadline());
            }
            Err(e) => panic!("listing recovered GC state: {e:?}"),
        }
    }
    panic!("WARNING TIMEOUT GC-prefix scan exceeded100000 polls");
}

#[test]
fn gc_prefix_retired_inputs_stay_readable_while_reader_epoch_is_pinned() {
    let (img, cfg) = shard_base();
    let (disk, mut clk, mut s) = mount(&img, &cfg);
    let pin = s.read_pin();
    let mut trace = Trace::default();
    assert_eq!(
        delete_half(&mut s, &mut clk, &disk, &mut trace).0,
        KEYS as usize / 128
    );
    assert!(
        trace.first_prefix_event.is_some(),
        "actual shard fixture must install a suffix with its original ID"
    );
    s.request_checkpoint();
    for _ in 0..512 {
        poll(&mut s, &mut clk, &disk, 0, &mut trace).unwrap();
    }
    assert!(s.statfs().data_held > 0);
    let mut rd = SimBlocks::new(disk.queue(), 1, cfg.lba_count);
    for old in &trace.retired {
        store::olsm::run::load_meta(&mut rd, old.meta_blk, old.meta_nblk, old.meta_crc).unwrap();
        for ci in 0..old.fences.len() {
            load_chunk(&mut rd, old, ci).unwrap();
        }
    }
    let held = s.statfs().data_held;
    s.read_unpin(pin);
    assert!(
        s.statfs().data_held < held,
        "reader release must make checkpointed GC frees reusable"
    );
    let dead: BTreeSet<_> = deletion_order().into_iter().collect();
    let expected: Model = (0..KEYS)
        .filter(|i| !dead.contains(i))
        .map(|i| (key(i), value(i, 0)))
        .collect();
    assert_eq!(shard_contents(&mut s, &mut clk), expected);
}

#[test]
fn gc_prefix_real_wal_crash_cuts_recover_an_acknowledged_delete_prefix() {
    let (img, cfg) = shard_base();
    let (disk, mut clk, mut s) = mount(&img, &cfg);
    let mut trace = Trace::default();
    delete_half(&mut s, &mut clk, &disk, &mut trace);
    let event = trace
        .first_prefix_event
        .expect("fixture must reach a partial GC manifest install");
    drop(s);
    let order = deletion_order();
    for delta in [-8i64, -4, -1, 0, 1, 4, 8] {
        for policy in [
            CrashPolicy::DROP_ALL,
            CrashPolicy::PERSIST_ALL,
            CrashPolicy::MIXED,
        ] {
            let (disk, mut clk, mut s) = mount(&img, &cfg);
            let cut = event.saturating_add_signed(delta).max(1);
            disk.arm_crash(disk.events() + cut);
            let (acked, submitted) = delete_half(&mut s, &mut clk, &disk, &mut Trace::default());
            assert!(
                disk.crashed(),
                "cut {cut} must interrupt the calibrated prefix manifest"
            );
            let crash = disk.crash_image(policy);
            drop(s);
            let (_d2, mut c2, mut s2) = mount(&crash, &cfg);
            let got = shard_contents(&mut s2, &mut c2);
            let removed = KEYS as usize - got.len();
            assert_eq!(
                removed % 64,
                0,
                "one manifest/WAL record cannot tear a client batch"
            );
            assert!(
                removed >= acked * 64 && removed <= submitted * 64,
                "cut {cut}: recovered {removed}, acked {acked}, submitted {submitted}"
            );
            let dead: BTreeSet<_> = order[..removed].iter().copied().collect();
            let expected: Model = (0..KEYS)
                .filter(|i| !dead.contains(i))
                .map(|i| (key(i), value(i, 0)))
                .collect();
            assert_eq!(
                got, expected,
                "cut {cut}: prefix GC must neither resurrect nor drop unrelated keys"
            );
        }
    }
}
