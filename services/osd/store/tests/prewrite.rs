// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Receiver-side pre-write (adr 0477 D1/D2): reservation lifecycle (claim, partial claim, release in flight, release of
//! a staged txn's unclaimed pieces, frame failure, shutdown) and a crash matrix over pre-write / claim / record.
//!
//! The safety contract under test: a pre-written block is referenced only by a record of a txn that claimed it, and that
//! txn is acked only after the pre-write landed; an unclaimed piece leaves nothing behind (no record, no extent, its
//! blocks free again, also after a crash at any IO event).

use bytes::Bytes;
use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SnapId, SpgT};
use store::dev::{CrashPolicy, Persist, SimClock, SimConfig, SimDev, SimDisk, SimImage};
use store::fsck::fsck;
use store::layout::{MkfsParams, mkfs};
use store::obj::onode::fsck_refs;
use store::obj::txn::Bytes as TxnBytes;
use store::obj::{OTxn, PreTicket, Store, StoreCfg, TOp};

type St = Store<SimDev, SimClock>;

/// Exercise the DMA staging path even when an immutable receive owner exists.
struct CopyDev(SimDev);
impl store::dev::BlockDev for CopyDev {
    type Buf = Vec<u8>;
    fn geometry(&self) -> store::dev::Geometry {
        self.0.geometry()
    }
    fn alloc_buf(&mut self, len: usize) -> Self::Buf {
        self.0.alloc_buf(len)
    }
    fn queue_space(&self) -> usize {
        self.0.queue_space()
    }
    fn queue_depth(&self) -> usize {
        self.0.queue_depth()
    }
    fn submit_write(
        &mut self,
        lba: u64,
        buf: Self::Buf,
        tag: u64,
    ) -> store::dev::Submit<Self::Buf> {
        self.0.submit_write(lba, buf, tag)
    }
    fn submit_read(&mut self, lba: u64, buf: Self::Buf, tag: u64) -> store::dev::Submit<Self::Buf> {
        self.0.submit_read(lba, buf, tag)
    }
    fn submit_deallocate(
        &mut self,
        ranges: &[(u64, u32)],
        tag: u64,
    ) -> Result<(), store::dev::Rejected<Self::Buf>> {
        self.0.submit_deallocate(ranges, tag)
    }
    fn submit_write_zeroes(
        &mut self,
        lba: u64,
        n: u32,
        tag: u64,
    ) -> Result<(), store::dev::Rejected<Self::Buf>> {
        self.0.submit_write_zeroes(lba, n, tag)
    }
    fn poll(&mut self, now: u64, out: &mut Vec<store::dev::Completion<Self::Buf>>) -> usize {
        self.0.poll(now, out)
    }
}

#[test]
fn copied_receive_payload_reuses_only_matching_block_crcs() {
    let s = sim(51);
    let disk = SimDisk::from_image(&image(&s), s);
    let (mut st, _) = Store::mount(
        || CopyDev(disk.queue()),
        SimClock::default(),
        StoreCfg::default(),
    )
    .unwrap();
    let owner = payload(PIECE + BLK, 51);
    // Grid mismatch and no hints must keep the ordinary fused checksum/copy fallback.
    for (i, start, known) in [(0, 0, true), (1, 1, true), (2, 0, false)] {
        let o = obj(format!("crc-copy-{i}").as_bytes());
        let p = owner.slice(start..start + PIECE);
        let mut t = write_txn(&o, 0, &p, 0..p.len());
        t.payloads.0.clear();
        t.payloads.0.push(crc::Payload {
            owner: owner.clone(),
            blocks: known.then(|| {
                owner
                    .as_chunks::<BLK>()
                    .0
                    .iter()
                    .map(|b| crc::crc32c(0, b))
                    .collect::<Vec<_>>()
                    .into()
            }),
            grid: 0,
        });
        let before = st.shards[0].stats;
        st.commit(&t).unwrap();
        let after = st.shards[0].stats;
        assert_eq!(
            after.staged_data_bytes - before.staged_data_bytes,
            PIECE as u64
        );
        assert_eq!(after.zc_data_bytes - before.zc_data_bytes, 0);
        assert_eq!(
            after.crc_reused_bytes - before.crc_reused_bytes,
            if known && start == 0 { PIECE as u64 } else { 0 }
        );
        assert_eq!(st.read(&coll(), &o, 0, PIECE as u64).unwrap(), p);
    }
}

const BLK: usize = 4096;
/// One receive piece = one extent run (`MAX_RUN` blocks).
const PIECE: usize = 64 * BLK;

fn coll() -> CollT {
    CollT::Pg(SpgT {
        pgid: PgT::new(1, 0),
        shard: ShardId::NO_SHARD,
    })
}

fn obj(name: &[u8]) -> Ghobject {
    Ghobject::new(
        Hobject::new(name, SnapId::NOSNAP, 7, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}

fn sim(seed: u64) -> SimConfig {
    let mut s = SimConfig::new(64 << 20);
    s.seed = seed;
    // completions in any order (pre-writes, data, WAL)
    s.jitter_ns = 40_000;
    s
}

/// Fresh one-shard store with the test collection.
fn image(sim: &SimConfig) -> SimImage {
    let disk = SimDisk::new(sim.clone());
    let mut dev = disk.queue();
    let mut clk = SimClock::default();
    let p = MkfsParams {
        shards: 1,
        wal_blocks: 1024,
        align_blocks: 1,
        ..Default::default()
    };
    mkfs(&mut dev, &mut clk, &p).unwrap();
    let img = disk.image();
    let (disk, mut st) = open(&img, sim);
    let mut t = OTxn::new();
    t.mkcoll(coll());
    st.commit(&t).unwrap();
    st.checkpoint().unwrap();
    disk.image()
}

fn open(img: &SimImage, sim: &SimConfig) -> (SimDisk, St) {
    let disk = SimDisk::from_image(img, sim.clone());
    let d2 = disk.clone();
    let (st, _) =
        Store::mount(move || d2.queue(), SimClock::default(), StoreCfg::default()).unwrap();
    (disk, st)
}

fn payload(len: usize, seed: u64) -> Bytes {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    Bytes::from(
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect::<Vec<u8>>(),
    )
}

/// Write the whole-block pieces of `p[from..from + blocks * 4096)` ahead, cut every `Store::pre_piece` bytes from `from`.
fn pre_pieces(st: &mut St, p: &Bytes, from: usize, blocks: usize) -> Vec<PreTicket> {
    let end = from + blocks * BLK;
    let piece = st.pre_piece();
    (from..end)
        .step_by(piece)
        .filter_map(|a| st.pre_write(&coll(), &p.slice(a..(a + piece).min(end))))
        .collect()
}

/// A write of `p[range]` at `off` whose bytes are the payload's memory (the OSD path: shared, with its owner).
fn write_txn(o: &Ghobject, off: u64, p: &Bytes, range: std::ops::Range<usize>) -> OTxn<'static> {
    let mut t = OTxn::new();
    t.push(TOp::Write {
        cid: coll(),
        oid: o.clone(),
        off,
        data: TxnBytes::Shared(p.slice(range)),
    });
    t.payloads.0.push(crc::Payload::owner(p.clone()));
    t
}

/// Poll until `tok` is acked.
fn drive(st: &mut St, tok: u64) {
    let mut acked = Vec::new();
    for _ in 0..200_000 {
        st.poll(&mut acked).unwrap();
        if acked.contains(&tok) {
            return;
        }
        st.idle();
    }
    panic!("no progress: {}", st.diag());
}

/// Allocated, reserved, free blocks (free includes the runs a deallocate holds, adr 0642).
fn counts(st: &St) -> (u64, u64, u64) {
    let sh = &st.shards[0].sh;
    let a = &sh.state().alloc;
    (
        a.n_alloc(),
        a.n_reserved(),
        a.n_free() + sh.gauges().trim_held,
    )
}

/// Wait until every pre-write slot is finished (all writes landed, released ones returned).
fn settle(st: &mut St) {
    let mut acked = Vec::new();
    for _ in 0..200_000 {
        st.poll(&mut acked).unwrap();
        if st.shards[0].sh.pre_live() == 0 {
            return;
        }
        st.idle();
    }
    panic!(
        "pre-writes do not settle: live {}",
        st.shards[0].sh.pre_live()
    );
}

fn fsck_image(img: &SimImage, sim: &SimConfig) {
    let d = SimDisk::from_image(img, sim.clone());
    let mut dev = d.queue();
    let mut clk = SimClock::default();
    fsck(&mut dev, &mut clk, Some(&fsck_refs)).unwrap();
}

#[test]
fn claimed_pieces_become_the_extents_and_are_not_written_again() {
    let s = sim(1);
    let (disk, mut st) = open(&image(&s), &s);
    let (alloc0, _, _) = counts(&st);
    let p = payload(1 << 20, 1);
    let t = pre_pieces(&mut st, &p, 0, 256);
    assert_eq!(t.len(), 4, "every piece written ahead");
    let o = obj(b"a");
    // committed while the pieces are still in flight: the ack waits for them
    st.commit(&write_txn(&o, 0, &p, 0..p.len())).unwrap();
    let ps = st.shards[0].sh.pre_stats();
    assert_eq!((ps.claimed, ps.claimed_bytes, ps.released), (4, 1 << 20, 0));
    let os = &st.shards[0].stats;
    assert_eq!(
        (os.zc_data_bytes, os.staged_data_bytes),
        (0, 0),
        "claimed runs are neither viewed nor copied again"
    );
    settle(&mut st);
    let (alloc1, res1, _) = counts(&st);
    assert_eq!(res1, 0, "no reservation left");
    assert!(alloc1 >= alloc0 + 256, "the pieces' blocks are allocated");
    assert_eq!(st.read(&coll(), &o, 0, p.len() as u64).unwrap(), &p[..]);
    st.checkpoint().unwrap();
    let img = disk.image();
    fsck_image(&img, &s);
    let (_, mut st2) = open(&img, &s);
    assert_eq!(st2.read(&coll(), &o, 0, p.len() as u64).unwrap(), &p[..]);
}

#[test]
fn a_device_transfer_limit_shortens_the_piece_to_the_run() {
    let mut s = sim(5);
    s.max_xfer_lbas = 16; // 64 KiB: the txn stages runs of 16 blocks
    let (disk, mut st) = open(&image(&s), &s);
    assert_eq!(st.pre_piece(), 16 * BLK);
    let p = payload(1 << 20, 5);
    let t = pre_pieces(&mut st, &p, 0, 256);
    assert_eq!(t.len(), 16, "every piece written ahead");
    let o = obj(b"x");
    st.commit(&write_txn(&o, 0, &p, 0..p.len())).unwrap();
    let ps = st.shards[0].sh.pre_stats();
    assert_eq!(
        (ps.claimed, ps.claimed_bytes, ps.released, ps.skipped),
        (16, 1 << 20, 0, 0),
        "each run claims its piece whole"
    );
    settle(&mut st);
    assert_eq!(counts(&st).1, 0, "no reservation left");
    assert_eq!(st.read(&coll(), &o, 0, p.len() as u64).unwrap(), &p[..]);
    st.checkpoint().unwrap();
    let img = disk.image();
    fsck_image(&img, &s);
    let (_, mut st2) = open(&img, &s);
    assert_eq!(st2.read(&coll(), &o, 0, p.len() as u64).unwrap(), &p[..]);
}

#[test]
fn queued_txn_claims_across_a_parked_preparation() {
    let s = sim(2);
    let (_disk, mut st) = open(&image(&s), &s);
    st.set_prep_allowance(Some(std::time::Duration::ZERO));
    let p = payload(4 << 20, 2);
    let t = pre_pieces(&mut st, &p, 0, 1024);
    assert_eq!(t.len(), 16);
    let o = obj(b"q");
    st.queue(&write_txn(&o, 0, &p, 0..p.len()), 9).unwrap();
    drive(&mut st, 9);
    let ps = st.shards[0].sh.pre_stats();
    assert_eq!(ps.claimed, 16, "claims survive the sliced preparation");
    settle(&mut st);
    assert_eq!(counts(&st).1, 0);
    assert_eq!(st.read(&coll(), &o, 0, p.len() as u64).unwrap(), &p[..]);
}

#[test]
fn released_in_flight_pieces_return_their_blocks_when_the_write_lands() {
    let s = sim(3);
    let (_disk, mut st) = open(&image(&s), &s);
    let (alloc0, res0, free0) = counts(&st);
    let lsn0 = st.shards[0].sh.next_lsn();
    let p = payload(1 << 20, 3);
    let t = pre_pieces(&mut st, &p, 0, 256);
    assert_eq!(counts(&st).1, res0 + 256, "reserved while written ahead");
    // the frame failed (crc / tag / connection lost) before anything was staged
    for x in t {
        st.pre_release(x);
    }
    assert_eq!(
        counts(&st).1,
        res0 + 256,
        "no block returns while its write is in flight"
    );
    settle(&mut st);
    assert_eq!(counts(&st), (alloc0, res0, free0), "all blocks free again");
    assert_eq!(st.shards[0].sh.next_lsn(), lsn0, "no WAL record");
    assert_eq!(st.shards[0].sh.pre_stats().released, 4);
}

#[test]
fn bad_crc_frame_leaves_no_referenced_block_and_no_record() {
    let s = sim(4);
    let img = image(&s);
    let (disk, mut st) = open(&img, &s);
    let (alloc0, _, free0) = counts(&st);
    let lsn0 = st.shards[0].sh.next_lsn();
    let p = payload(2 << 20, 4);
    let t = pre_pieces(&mut st, &p, 0, 512);
    // the pieces land on the device before the frame's crc check fails
    let mut acked = Vec::new();
    for _ in 0..1000 {
        st.poll(&mut acked).unwrap();
        st.idle();
    }
    for x in t {
        st.pre_release(x);
    }
    settle(&mut st);
    assert_eq!(st.shards[0].sh.next_lsn(), lsn0, "no WAL record");
    assert_eq!(counts(&st).0, alloc0, "no block referenced");
    assert_eq!(counts(&st).2, free0);
    assert!(
        st.read(&coll(), &obj(b"never"), 0, 4096).is_err(),
        "no object"
    );
    // the bytes are on the media in free blocks: the crash image mounts with the same free space, fsck clean
    disk.crash_now();
    let cimg = disk.crash_image(CrashPolicy::PERSIST_ALL);
    fsck_image(&cimg, &s);
    let (_, st2) = open(&cimg, &s);
    assert_eq!(counts(&st2).0, alloc0);
}

#[test]
fn unaligned_write_claims_nothing_and_releases_its_pieces_at_staging() {
    let s = sim(5);
    let (_disk, mut st) = open(&image(&s), &s);
    let p = payload(1 << 20, 5);
    let t = pre_pieces(&mut st, &p, 0, 256);
    assert_eq!(t.len(), 4);
    let o = obj(b"u");
    // object offset not on the payload's block grid: every run starts mid-piece
    st.commit(&write_txn(&o, 512, &p, 0..p.len())).unwrap();
    let ps = st.shards[0].sh.pre_stats();
    assert_eq!(
        (ps.claimed, ps.released),
        (0, 4),
        "released when the txn was staged"
    );
    settle(&mut st);
    assert_eq!(counts(&st).1, 0);
    assert_eq!(st.read(&coll(), &o, 512, p.len() as u64).unwrap(), &p[..]);
}

#[test]
fn partial_claim_returns_the_rest_of_the_piece() {
    let s = sim(6);
    let (_disk, mut st) = open(&image(&s), &s);
    let (alloc0, _, _) = counts(&st);
    let p = payload(PIECE, 6);
    let t = pre_pieces(&mut st, &p, 0, 64);
    assert_eq!(t.len(), 1);
    let o = obj(b"p");
    // the first write of a replica blob covers only 40 blocks of the speculative piece
    st.commit(&write_txn(&o, 0, &p, 0..40 * BLK)).unwrap();
    assert_eq!(st.shards[0].sh.pre_stats().claimed_bytes, 40 * BLK as u64);
    settle(&mut st);
    let (alloc1, res1, _) = counts(&st);
    assert_eq!(res1, 0, "the unclaimed 24 blocks are back");
    assert!(alloc1 >= alloc0 + 40 && alloc1 < alloc0 + 64);
    assert_eq!(st.read(&coll(), &o, 0, 40 * 4096).unwrap(), &p[..40 * BLK]);
}

#[test]
fn shutdown_with_pieces_in_flight_leaves_free_space() {
    for pol in [
        CrashPolicy::DROP_ALL,
        CrashPolicy::MIXED,
        CrashPolicy::PERSIST_ALL,
    ] {
        let s = sim(7);
        let img = image(&s);
        let (disk, mut st) = open(&img, &s);
        let (alloc0, _, free0) = counts(&st);
        let p = payload(1 << 20, 7);
        let _t = pre_pieces(&mut st, &p, 0, 256);
        // stop with the pre-writes in flight, never claimed nor released (reservations are volatile)
        disk.crash_now();
        let cimg = disk.crash_image(pol);
        drop(st);
        fsck_image(&cimg, &s);
        let (_, st2) = open(&cimg, &s);
        let (a, r, f) = counts(&st2);
        assert_eq!((a, r, f), (alloc0, 0, free0), "{pol:?}");
    }
}

/// One crash point of the workload: three frames (two objects, one overwritten) each written ahead, claimed by a queued
/// txn, the unclaimed rest released. After the crash: every acked write is there in full, every other object holds
/// either its old or its new content in full, fsck is clean (no block referenced without its data, nothing leaked).
#[derive(Clone, Copy, Debug)]
enum Fate {
    Policy(CrashPolicy),
    /// Every in-flight write persists except the pre-writes (tag kind 9 of the shard).
    DropPre,
}

fn crash_at(k: Option<u64>, fate: Fate, seed: u64) -> (u64, bool, u64) {
    let s = sim(seed);
    let img = image(&s);
    let (disk, mut st) = open(&img, &s);
    let frames = [
        (obj(b"x"), payload(1 << 20, seed + 10)),
        (obj(b"y"), payload(512 << 10, seed + 11)),
        (obj(b"x"), payload(1 << 20, seed + 12)),
    ];
    let start = disk.events();
    if let Some(k) = k {
        disk.arm_crash(start + k);
    }
    let mut acked: Vec<u64> = Vec::new();
    let mut queued = 0;
    'run: for (i, (o, p)) in frames.iter().enumerate() {
        let tickets = pre_pieces(&mut st, p, 0, p.len() / BLK);
        // some pieces land before the frame completes, some do not
        for _ in 0..i {
            if st.poll(&mut acked).is_err() || disk.crashed() {
                break 'run;
            }
        }
        match st.queue(&write_txn(o, 0, p, 0..p.len()), i as u64 + 1) {
            Ok(_) => queued = i + 1,
            Err(_) if disk.crashed() => break,
            Err(e) => panic!("queue: {e:?}"),
        }
        for _ in 0..3000 {
            if st.poll(&mut acked).is_err() || disk.crashed() {
                break 'run;
            }
            if acked.contains(&(i as u64 + 1)) {
                break;
            }
            st.idle();
        }
        for x in tickets {
            st.pre_release(x);
        }
    }
    let events = disk.events() - start;
    let crashed = disk.crashed();
    let claimed = st.shards[0].sh.pre_stats().claimed;
    disk.crash_now();
    let cimg = match fate {
        Fate::Policy(pol) => disk.crash_image(pol),
        // the worst order for a claimed piece: its WAL unit (and everything else) persists, the pre-write does not;
        // replay must find the claimed extent's crcs missing and end the log there (nothing after it was acked)
        Fate::DropPre => disk.crash_image_with(|f, _| {
            if f.tag >> 56 == 9 {
                Persist::Drop
            } else {
                Persist::Full
            }
        }),
    };
    let pol = fate;
    drop(st);
    fsck_image(&cimg, &s);
    let (_, mut st2) = open(&cimg, &s);
    let read = |st: &mut St, o: &Ghobject, len: usize| st.read(&coll(), o, 0, len as u64).ok();
    let x = read(&mut st2, &frames[0].0, 1 << 20);
    let y = read(&mut st2, &frames[1].0, 512 << 10);
    // versions of x in order: none, frame 0, frame 2; the recovered one is a whole version at least as new as the
    // newest acked one and not newer than the newest queued one
    let version = match &x {
        None => Some(0),
        Some(v) if v[..] == frames[0].1[..] => Some(1),
        Some(v) if v[..] == frames[2].1[..] => Some(2),
        Some(_) => None,
    };
    let min = if acked.contains(&3) {
        2
    } else {
        usize::from(acked.contains(&1))
    };
    let max = match queued {
        0 => 0,
        1 | 2 => 1,
        _ => 2,
    };
    assert!(
        version.is_some_and(|v| (min..=max).contains(&v)),
        "object x: version {version:?} outside [{min}, {max}] (k {k:?} {pol:?}, acked {acked:?})"
    );
    match &y {
        Some(v) => assert_eq!(&v[..], &frames[1].1[..], "object y torn (k {k:?} {pol:?})"),
        None => assert!(!acked.contains(&2), "acked object y lost (k {k:?} {pol:?})"),
    }
    // a checkpoint after recovery keeps a consistent image, and the store keeps working
    st2.checkpoint().unwrap();
    (events, crashed, claimed)
}

#[test]
fn crash_matrix_pre_write_claim_record() {
    let (events, crashed, claimed) = crash_at(None, Fate::DropPre, 21);
    assert!(!crashed);
    assert_eq!(claimed, 10, "every piece of the three frames claimed");
    assert!(events > 20, "workload too small: {events}");
    for fate in [
        Fate::Policy(CrashPolicy::DROP_ALL),
        Fate::Policy(CrashPolicy::MIXED),
        Fate::Policy(CrashPolicy::PERSIST_ALL),
        Fate::DropPre,
    ] {
        for k in 0..events {
            crash_at(Some(k), fate, 21);
        }
    }
}

/// Seeds whose device schedules leave claimed pre-writes in flight while the WAL unit lands (an ack that did not wait for
/// them loses data here: checked by a mutation of the commit path, adr 0477 safety evidence).
#[test]
fn crash_matrix_pre_write_more_seeds() {
    for seed in [31, 47, 53] {
        let (events, _, _) = crash_at(None, Fate::DropPre, seed);
        for k in 0..events {
            crash_at(Some(k), Fate::Policy(CrashPolicy::MIXED), seed);
            crash_at(Some(k), Fate::DropPre, seed);
        }
    }
}
