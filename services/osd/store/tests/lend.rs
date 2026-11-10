// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Durable grant/return of shared pool chunks (adr 0021 am. 49, elastic shards step 2): grant order, base-first use,
//! return only when unused, cross-shard reuse of a returned chunk, and a power-cut matrix over every IO event of a
//! workload of grants, spills into borrowed chunks, frees, returns and re-grants: after each cut the store mounts
//! (replay), fsck is clean, the lending table matches the completed operations (the one in flight either way, a grant
//! that did not become durable left the chunk free), every acked object reads back.
//!
//! Matrix size: `LEND_CRASH_STRIDE` (default 5: every event inside a grant / return, every 5th elsewhere); the soak
//! `crash_matrix_lend_every_event` (ignored, stride 1) runs from lab/elastic-crash.sh.
#![cfg(feature = "elastic")]
#[path = "common/objmodel.rs"]
mod objmodel;

use denc::types::{CollT, Ghobject, Hobject, ShardId, SnapId};
use objmodel::*;
use std::collections::BTreeMap;
use store::alloc::HOLE;
use store::dev::{CrashPolicy, Persist, SimClock, SimConfig, SimDev, SimDisk, SimImage};
use store::fsck::fsck;
use store::layout::{MkfsParams, mkfs, read_super};
use store::lend::Lending;
use store::obj::onode::fsck_refs;
use store::obj::{OTxn, Store, StoreCfg};

type St = Store<SimDev, SimClock>;
const OBJ: usize = 32 << 10;

fn sim() -> SimConfig {
    // 512 B LBAs: a 4 KiB table block is 8 LBAs, a cut can tear it
    let mut c = SimConfig::new(12 << 20);
    c.lba_size = 512;
    c.lba_count = (12 << 20) / 512;
    c
}

fn params() -> MkfsParams {
    MkfsParams {
        shards: 2,
        wal_blocks: 256,
        align_blocks: 1,
        meta_pct: 4,
        chunked: true,
        chunk_blocks: 256, // 1 MiB
        base_pct: 90,      // small regions: the pool floor (2 chunks per shard) lowers the base
        ..Default::default()
    }
}

fn fresh() -> SimDisk {
    let disk = SimDisk::new(sim());
    mkfs(&mut disk.queue(), &mut SimClock::default(), &params()).unwrap();
    disk
}

fn mount(disk: &SimDisk) -> St {
    let d = disk.clone();
    Store::mount(move || d.queue(), SimClock::default(), StoreCfg::default())
        .unwrap()
        .0
}

fn g(i: u32) -> Ghobject {
    Ghobject::new(
        Hobject::new(format!("o{i}").as_bytes(), SnapId::NOSNAP, i, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}
fn pattern(seed: u32) -> Vec<u8> {
    (0..OBJ)
        .map(|k| (k as u32 * 31 + seed * 17 + (k >> 9) as u32) as u8)
        .collect()
}

/// A PG collection of each shard.
fn colls(st: &St) -> [CollT; 2] {
    let find = |sh: usize| {
        (0..256)
            .map(|s| pgc(1, s))
            .find(|c| st.shard_of(c) == sh)
            .unwrap()
    };
    [find(0), find(1)]
}

/// Completed (or in-flight) operations of a run.
#[derive(Clone, Debug, PartialEq)]
enum Ev {
    Mkcolls,
    /// object -> Some(pattern seed) written / None removed (shard of `coll`)
    Obj(usize, u32, Option<u32>),
    Grant(u32, Option<u64>),
    Return(u32, u64, bool),
    Ckpt,
}

#[derive(Default, Debug)]
struct Log {
    done: Vec<Ev>,
    inflight: Option<Ev>,
    /// IO event ranges `[a, b)` of grant / return calls (relative to the workload start)
    lend_events: Vec<(u64, u64)>,
}

/// The workload. Stops at the first error (the cut); `strict` (no cut) asserts the expected placement.
fn workload(st: &mut St, disk: &SimDisk, log: &mut Log, strict: bool) -> Result<(), ()> {
    let t0 = disk.events();
    let c = colls(st);
    macro_rules! op {
        ($ev:expr, $body:expr) => {{
            log.inflight = Some($ev);
            let r = $body;
            match r {
                Ok(v) => {
                    log.inflight = None;
                    v
                }
                Err(e) => {
                    if !disk.crashed() {
                        eprintln!("op {:?} failed: {e:?}", log.inflight);
                    }
                    return Err(());
                }
            }
        }};
    }
    macro_rules! lend_op {
        ($ev:expr, $body:expr) => {{
            let a = disk.events() - t0;
            log.lend_events.push((a, u64::MAX));
            let v = op!($ev, $body);
            log.lend_events.last_mut().unwrap().1 = disk.events() - t0 + 1;
            v
        }};
    }
    for cc in &c {
        let mut t = OTxn::new();
        t.mkcoll(*cc);
        op!(Ev::Mkcolls, st.commit(&t));
    }
    log.done.push(Ev::Mkcolls);
    let geom = st.lending().unwrap().geom.clone();
    // shard 0: its own two pool chunks (adjacent to its base first), then shard 1's region from the far end
    let mut got = Vec::new();
    for _ in 0..3 {
        let p = lend_op!(Ev::Grant(0, None), st.grant_chunk(0));
        log.done.push(Ev::Grant(0, p));
        got.push(p.unwrap());
    }
    if strict {
        let idx: Vec<u64> = got.iter().map(|&p| geom.index_of(p).unwrap()).collect();
        assert_eq!(
            idx,
            vec![0, 1, 3],
            "grant order: own region up, then the fullest region from the far end"
        );
    }
    // the two own chunks were never used: returned at once (no checkpoint needed), leaving holes in slots 0 and 1
    for &p in &got[..2] {
        let ok = lend_op!(Ev::Return(0, p, true), st.return_chunk(0, p));
        assert!(ok, "an unused chunk returns at once");
        log.done.push(Ev::Return(0, p, true));
    }
    let x = got[2];
    // fill shard 0: the base first, then the borrowed chunk (slot 2, in shard 1's region)
    let busy = |st: &St, sh: u32, p: u64| {
        st.lent_chunks(sh)
            .unwrap()
            .iter()
            .find(|e| e.0 == p)
            .map_or(0, |e| e.1)
    };
    let mut objs0 = Vec::new();
    let mut extra = 3;
    for i in 0..400u32 {
        let mut t = OTxn::new();
        let d = pattern(i);
        t.write(c[0], &g(i), 0, &d);
        op!(Ev::Obj(0, i, Some(i)), st.commit(&t));
        log.done.push(Ev::Obj(0, i, Some(i)));
        objs0.push(i);
        if busy(st, 0, x) > 0 {
            extra -= 1;
            if extra == 0 {
                break;
            }
        }
    }
    assert!(
        busy(st, 0, x) > 0,
        "the workload never reached the borrowed chunk"
    );
    // in use: refused, nothing changes
    let ok = lend_op!(Ev::Return(0, x, false), st.return_chunk(0, x));
    assert!(!ok);
    log.done.push(Ev::Return(0, x, false));
    // remove everything of shard 0, a checkpoint releases the held blocks; then the chunk returns
    for &i in objs0.iter() {
        let mut t = OTxn::new();
        t.remove(c[0], &g(i));
        op!(Ev::Obj(0, i, None), st.commit(&t));
        log.done.push(Ev::Obj(0, i, None));
    }
    // allocated nowhere now, but the freed blocks are held until a checkpoint passes their txns: still refused
    let ok = lend_op!(Ev::Return(0, x, false), st.return_chunk(0, x));
    if strict {
        assert!(!ok, "held blocks keep the chunk");
    }
    if ok {
        log.done.push(Ev::Return(0, x, true));
    } else {
        log.done.push(Ev::Return(0, x, false));
    }
    op!(Ev::Ckpt, st.checkpoint());
    log.done.push(Ev::Ckpt);
    let ok = lend_op!(Ev::Return(0, x, true), st.return_chunk(0, x));
    if !ok {
        // frees of the last txns wait for one more checkpoint
        op!(Ev::Ckpt, st.checkpoint());
        log.done.push(Ev::Ckpt);
        let ok = lend_op!(Ev::Return(0, x, true), st.return_chunk(0, x));
        assert!(ok, "chunk still in use after two checkpoints");
    }
    log.done.push(Ev::Return(0, x, true));
    // shard 1 borrows its own region: k0, then k1 = the chunk shard 0 just used and returned
    let a = lend_op!(Ev::Grant(1, None), st.grant_chunk(1));
    log.done.push(Ev::Grant(1, a));
    let b = lend_op!(Ev::Grant(1, None), st.grant_chunk(1));
    log.done.push(Ev::Grant(1, b));
    if strict {
        assert_eq!(
            b,
            Some(x),
            "the returned chunk is reused by its region's shard"
        );
    }
    let (a, b) = (a.unwrap(), b.unwrap());
    let ok = lend_op!(Ev::Return(1, a, true), st.return_chunk(1, a));
    assert!(ok);
    log.done.push(Ev::Return(1, a, true));
    // shard 1 fills its base and spills into the reused chunk; overwrite / remove a few, checkpoint
    let mut extra = 3;
    let mut objs1 = Vec::new();
    for i in 1000..1400u32 {
        let mut t = OTxn::new();
        let d = pattern(i);
        t.write(c[1], &g(i), 0, &d);
        op!(Ev::Obj(1, i, Some(i)), st.commit(&t));
        log.done.push(Ev::Obj(1, i, Some(i)));
        objs1.push(i);
        if busy(st, 1, b) > 0 {
            extra -= 1;
            if extra == 0 {
                break;
            }
        }
    }
    assert!(busy(st, 1, b) > 0);
    for &i in objs1.iter().rev().take(4) {
        let mut t = OTxn::new();
        if i % 2 == 0 {
            t.remove(c[1], &g(i));
            op!(Ev::Obj(1, i, None), st.commit(&t));
            log.done.push(Ev::Obj(1, i, None));
        } else {
            let d = pattern(i + 7);
            t.write(c[1], &g(i), 0, &d);
            op!(Ev::Obj(1, i, Some(i + 7)), st.commit(&t));
            log.done.push(Ev::Obj(1, i, Some(i + 7)));
        }
    }
    op!(Ev::Ckpt, st.checkpoint());
    log.done.push(Ev::Ckpt);
    Ok(())
}

/// Expected state from the completed operations: objects per shard, owned pool chunks per shard.
type Expected = (BTreeMap<(usize, u32), Option<u32>>, [Vec<u64>; 2]);

fn expect(done: &[Ev]) -> Expected {
    let mut objs = BTreeMap::new();
    let mut own: [Vec<u64>; 2] = [vec![], vec![]];
    for e in done {
        match e {
            Ev::Obj(s, i, v) => {
                objs.insert((*s, *i), *v);
            }
            Ev::Grant(s, Some(p)) => own[*s as usize].push(*p),
            Ev::Return(s, p, true) => own[*s as usize].retain(|q| q != p),
            _ => {}
        }
    }
    own.iter_mut().for_each(|v| v.sort_unstable());
    (objs, own)
}

/// Mount the cut image and check every invariant; then the store keeps working (return the empty chunks, grant,
/// write, remount).
fn verify(img: &SimImage, log: &Log) -> Result<(), String> {
    let disk = SimDisk::from_image(img, sim());
    let mut st = Store::mount(
        {
            let d = disk.clone();
            move || d.queue()
        },
        SimClock::default(),
        StoreCfg::default(),
    )
    .map_err(|e| format!("mount: {e:?}"))?
    .0;
    // replay made the state durable (mount checkpoint): fsck judges the device
    fsck(
        &mut disk.queue(),
        &mut SimClock::default(),
        Some(&fsck_refs),
    )
    .map_err(|e| format!("fsck: {e}"))?;
    let (_, dirs) =
        read_super(&mut disk.queue(), &mut SimClock::default()).map_err(|e| format!("{e:?}"))?;
    // lending table == completed ops, the in-flight one either way
    let (objs, own) = expect(&log.done);
    for s in 0..2u32 {
        let mut got: Vec<u64> = dirs[s as usize]
            .lent
            .iter()
            .copied()
            .filter(|&p| p != HOLE)
            .collect();
        got.sort_unstable();
        let lent = st.lent_chunks(s).unwrap();
        let ok = match &log.inflight {
            _ if got == own[s as usize] => true,
            Some(Ev::Grant(t, _)) if *t == s => {
                // a grant whose write was durable: one more chunk, never used
                let extra: Vec<u64> = got
                    .iter()
                    .copied()
                    .filter(|p| !own[s as usize].contains(p))
                    .collect();
                extra.len() == 1
                    && got.len() == own[s as usize].len() + 1
                    && lent.iter().any(|e| e.0 == extra[0] && e.1 == 0)
            }
            Some(Ev::Return(t, p, _)) if *t == s => {
                let mut w = own[s as usize].clone();
                w.retain(|q| q != p);
                got == w
            }
            _ => false,
        };
        if !ok {
            return Err(format!(
                "shard {s}: lent {got:?}, expected {:?} (in flight {:?})",
                own[s as usize], log.inflight
            ));
        }
    }
    // the in-memory table equals the device
    let l: &Lending = st.lending().unwrap();
    for s in 0..2u32 {
        if l.slots(s) != dirs[s as usize].lent {
            return Err(format!(
                "shard {s}: table slots {:?} != directory {:?}",
                l.slots(s),
                dirs[s as usize].lent
            ));
        }
    }
    // every acked object; the one in flight old or new
    let c = colls(&st);
    if log.done.contains(&Ev::Mkcolls) {
        for (&(s, i), &v) in &objs {
            let alt = match &log.inflight {
                Some(Ev::Obj(t, j, w)) if *t == s && *j == i => Some(*w),
                _ => None,
            };
            let got = match st.read(&c[s], &g(i), 0, OBJ as u64) {
                Ok(d) => Some(d),
                Err(store::obj::ObjError::NoEnt) => None,
                Err(e) => return Err(format!("read o{i}: {e:?}")),
            };
            let want = |v: Option<u32>| v.map(pattern);
            if got != want(v) && alt.is_none_or(|a| got != want(a)) {
                return Err(format!(
                    "object {i} of shard {s}: wrong content (want {v:?}, in flight {alt:?})"
                ));
            }
        }
        // an in-flight write of a new object: absent or complete
        if let Some(Ev::Obj(s, i, Some(w))) = &log.inflight
            && !objs.contains_key(&(*s, *i))
        {
            match st.read(&c[*s], &g(*i), 0, OBJ as u64) {
                Ok(d) if d == pattern(*w) => {}
                Err(store::obj::ObjError::NoEnt) => {}
                r => return Err(format!("in-flight object {i}: {:?}", r.map(|d| d.len()))),
            }
        }
    }
    // still usable: return every empty borrowed chunk, grant again, write, remount, fsck
    st.checkpoint().map_err(|e| format!("checkpoint: {e:?}"))?;
    st.checkpoint().map_err(|e| format!("checkpoint: {e:?}"))?;
    for s in 0..2u32 {
        for (p, busy) in st.lent_chunks(s).unwrap() {
            if p != HOLE
                && busy == 0
                && !st
                    .return_chunk(s, p)
                    .map_err(|e| format!("return: {e:?}"))?
            {
                return Err(format!("empty chunk {p} of shard {s} refused"));
            }
        }
    }
    let p = st
        .grant_chunk(1)
        .map_err(|e| format!("grant: {e:?}"))?
        .ok_or("pool empty after returns")?;
    if log.done.contains(&Ev::Mkcolls) {
        let mut t = OTxn::new();
        let d = pattern(4242);
        t.write(c[1], &g(4242), 0, &d);
        st.commit(&t)
            .map_err(|e| format!("write after recovery: {e:?}"))?;
    }
    drop(st);
    let mut st = mount(&disk);
    if !st.lent_chunks(1).unwrap().iter().any(|e| e.0 == p) {
        return Err("grant after recovery not durable".into());
    }
    if log.done.contains(&Ev::Mkcolls)
        && st.read(&c[1], &g(4242), 0, OBJ as u64).ok() != Some(pattern(4242))
    {
        return Err("object written after recovery lost".into());
    }
    drop(st);
    fsck(
        &mut disk.queue(),
        &mut SimClock::default(),
        Some(&fsck_refs),
    )
    .map_err(|e| format!("final fsck: {e}"))?;
    Ok(())
}

#[test]
fn grant_return_reuse_and_remount() {
    let disk = fresh();
    let mut st = mount(&disk);
    let (_, dirs) = read_super(&mut disk.queue(), &mut SimClock::default()).unwrap();
    let geom = st.lending().unwrap().geom.clone();
    assert_eq!(
        (geom.per, dirs[0].data_blocks / 256),
        (2, geom.base),
        "test geometry: 2 pool chunks per region"
    );
    let cap0 = st.data_blocks();
    let mut log = Log::default();
    workload(&mut st, &disk, &mut log, true).unwrap();
    // capacity follows the lent chunks (shard 1 holds one: its slot 0 is a hole)
    assert_eq!(st.data_blocks(), cap0 + 256);
    assert_eq!(
        st.lent_chunks(1)
            .unwrap()
            .iter()
            .filter(|e| e.0 != HOLE)
            .count(),
        1
    );
    drop(st);
    fsck(
        &mut disk.queue(),
        &mut SimClock::default(),
        Some(&fsck_refs),
    )
    .unwrap();
    verify(&disk.image(), &log).unwrap();
}

#[test]
fn table_copy_corruption_falls_back_and_both_bad_refuse() {
    let disk = fresh();
    let mut st = mount(&disk);
    let p = st.grant_chunk(0).unwrap().unwrap();
    let geom = st.lending().unwrap().geom.clone();
    drop(st);
    // the grant went to copy 1 (gen 2); corrupt it: the mount falls back to gen 1 (chunk free again)
    let lpb = 8;
    let mut img = disk.image();
    img.corrupt(geom.copy_addr(0, 1) * lpb + 3, 7, 0x10);
    let d2 = SimDisk::from_image(&img, sim());
    let st = mount(&d2);
    assert_eq!(
        st.lending().unwrap().entry(geom.index_of(p).unwrap()),
        store::lend::Entry::FREE
    );
    drop(st);
    // both copies bad: refused (never guessed)
    img.corrupt(geom.copy_addr(0, 0) * lpb, 0, 0x01);
    let d3 = SimDisk::from_image(&img, sim());
    assert!(read_super(&mut d3.queue(), &mut SimClock::default()).is_err());
}

#[test]
fn bitmap_bits_in_a_hole_are_refused() {
    // a returned slot must be empty in the persisted bitmap: forge a table that takes a chunk with data away
    let disk = fresh();
    let mut st = mount(&disk);
    let c = colls(&st);
    let mut t = OTxn::new();
    t.mkcoll(c[0]);
    st.commit(&t).unwrap();
    let x = st.grant_chunk(0).unwrap().unwrap();
    let mut i = 0;
    while st.lent_chunks(0).unwrap()[0].1 == 0 {
        let mut t = OTxn::new();
        let d = pattern(i);
        t.write(c[0], &g(i), 0, &d);
        st.commit(&t).unwrap();
        i += 1;
    }
    st.checkpoint().unwrap();
    // second grant: slot 1; then rewrite the table block as if slot 0 had been returned
    let geom = st.lending().unwrap().geom.clone();
    let pidx = geom.index_of(x).unwrap();
    drop(st);
    let mut io_dev = disk.queue();
    let mut clk = SimClock::default();
    let (sb, dirs) = read_super(&mut io_dev, &mut clk).unwrap();
    let mut l =
        Lending::load(&mut store::sio::Sio::new(&mut io_dev, &mut clk), &sb, &dirs).unwrap();
    let s = l.stage(pidx, store::lend::Entry::FREE);
    store::sio::Sio::new(&mut io_dev, &mut clk)
        .write_one(s.addr, &s.buf)
        .unwrap();
    l.commit(&s);
    let d = disk.clone();
    let r = Store::mount(move || d.queue(), SimClock::default(), StoreCfg::default());
    assert!(
        r.is_err(),
        "data in a chunk the table does not lend must refuse the mount"
    );
    assert!(
        fsck(
            &mut disk.queue(),
            &mut SimClock::default(),
            Some(&fsck_refs)
        )
        .is_err()
    );
}

/// Cut policies: the three standard ones plus "tear every in-flight table write" (half old, half new LBAs).
fn cut_image(disk: &SimDisk, pol: usize, table: (u64, u64)) -> SimImage {
    match pol {
        0 => disk.crash_image(CrashPolicy::DROP_ALL),
        1 => disk.crash_image(CrashPolicy::PERSIST_ALL),
        2 => disk.crash_image(CrashPolicy::MIXED),
        _ => disk.crash_image_with(|f, rng| {
            if f.lba >= table.0 && f.lba < table.1 && f.nlba > 1 {
                Persist::Tear((0..f.nlba).map(|j| j < f.nlba / 2).collect())
            } else if rng.pct(50) {
                Persist::Full
            } else {
                Persist::Drop
            }
        }),
    }
}

fn matrix(stride: u64) -> (u64, u64) {
    // reference run: event count and the event ranges of grant / return
    let disk = fresh();
    let mut st = mount(&disk);
    let geom = st.lending().unwrap().geom.clone();
    let table = (
        geom.table_blk * 8,
        (geom.table_blk + 2 * geom.table_blocks) * 8,
    );
    let start = disk.events();
    let mut reference = Log::default();
    workload(&mut st, &disk, &mut reference, false).unwrap();
    let total = disk.events() - start;
    drop(st);
    let in_lend = |k: u64| {
        reference
            .lend_events
            .iter()
            .any(|&(a, b)| k + 2 >= a && k <= b + 2)
    };
    let (mut runs, mut lend_runs) = (0, 0);
    for k in 0..=total {
        if !(in_lend(k) || k % stride == 0) {
            continue;
        }
        for pol in 0..4 {
            let disk = fresh();
            let mut st = mount(&disk);
            disk.arm_crash(disk.events() + k);
            let mut log = Log::default();
            let r = workload(&mut st, &disk, &mut log, false);
            assert!(
                r.is_err() || k >= total - 1 || disk.crashed(),
                "k {k}: workload finished without a cut"
            );
            disk.crash_now();
            let img = cut_image(&disk, pol, table);
            drop(st);
            verify(&img, &log).unwrap_or_else(|m| {
                panic!(
                    "cut at event {k}/{total} policy {pol}: {m}\nin flight {:?}",
                    log.inflight
                )
            });
            runs += 1;
            lend_runs += in_lend(k) as u64;
        }
    }
    eprintln!(
        "lend crash matrix: {total} events, {runs} cuts ({lend_runs} inside grant/return), stride {stride}"
    );
    (runs, lend_runs)
}

#[test]
fn crash_matrix_lend() {
    let stride = std::env::var("LEND_CRASH_STRIDE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);
    let (runs, lend) = matrix(stride);
    assert!(lend >= 4 * 8 * 4, "every grant / return step cut: {lend}");
    assert!(runs > lend);
}

#[test]
#[ignore = "soak: every IO event (lab/elastic-crash.sh)"]
fn crash_matrix_lend_every_event() {
    matrix(1);
}
