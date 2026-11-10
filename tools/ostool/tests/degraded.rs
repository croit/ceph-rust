// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Shard-isolated degraded read-only mount (`--skip-shard` / `--shards`): a damaged shard's meta region must not stop
//! the export of the healthy shards' PGs, and the degraded session must never write to the device. The store is
//! mounted on [`NoWrite`] (no `CowDev` overlay to hide a write): any write, write-zeroes or deallocate submitted by the
//! mount, the WAL replay, a read-only op or the drop panics.
mod common;
use common::*;
use osd::nvmestore::NvmeMeta;
use ostool::{Ctx, EXIT_DEGRADED, Opts};
use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;
use store::dev::{
    BlockDev, Completion, DeallocLimits, Geometry, Nanos, SimClock, SimDev, SimDisk, Submit,
};
use store::obj::{ShardMountState, Store, StoreCfg};
use storeadapt::StoreAdapter;

/// Test-only queue wrapper: reads pass through, every mutating submission panics (names the op and LBA).
struct NoWrite(SimDev);

impl BlockDev for NoWrite {
    type Buf = <SimDev as BlockDev>::Buf;
    fn geometry(&self) -> Geometry {
        self.0.geometry()
    }
    fn alloc_buf(&mut self, len: usize) -> Self::Buf {
        self.0.alloc_buf(len)
    }
    fn alloc_buf_uninit(&mut self, len: usize) -> Self::Buf {
        self.0.alloc_buf_uninit(len)
    }
    fn try_alloc_buf_uninit(&mut self, len: usize) -> Option<Self::Buf> {
        self.0.try_alloc_buf_uninit(len)
    }
    fn try_alloc_io_uninit(&mut self, len: usize) -> Option<Self::Buf> {
        self.0.try_alloc_io_uninit(len)
    }
    fn release_pooled(&mut self) {
        self.0.release_pooled()
    }
    fn ram_reads(&self) -> bool {
        self.0.ram_reads()
    }
    fn alloc_buf_ram_uninit(&mut self, len: usize) -> Self::Buf {
        self.0.alloc_buf_ram_uninit(len)
    }
    fn trim_ram(&mut self) {
        self.0.trim_ram()
    }
    fn view_buf(&mut self, data: &bytes::Bytes) -> Option<Self::Buf> {
        self.0.view_buf(data)
    }
    fn queue_space(&self) -> usize {
        self.0.queue_space()
    }
    fn queue_depth(&self) -> usize {
        self.0.queue_depth()
    }
    fn submit_write(&mut self, lba: u64, _buf: Self::Buf, _tag: u64) -> Submit<Self::Buf> {
        panic!("read-only mount submitted a write at LBA {lba}")
    }
    fn submit_read(&mut self, lba: u64, buf: Self::Buf, tag: u64) -> Submit<Self::Buf> {
        self.0.submit_read(lba, buf, tag)
    }
    fn submits_at_flush(&self) -> bool {
        self.0.submits_at_flush()
    }
    fn issue(&mut self) {
        self.0.issue()
    }
    fn wait_hint(&mut self) -> Option<std::time::Duration> {
        self.0.wait_hint()
    }
    // the sim's DSM limits: the store's trimmer is armed, so a trim would be submitted (and caught) here
    fn dealloc_limits(&self) -> DeallocLimits {
        self.0.dealloc_limits()
    }
    fn submit_deallocate(&mut self, ranges: &[(u64, u32)], _tag: u64) -> Submit<Self::Buf> {
        panic!("read-only mount submitted a deallocate of {ranges:?}")
    }
    fn deallocate_all(&mut self) -> Result<u64, String> {
        panic!("read-only mount deallocated the whole device")
    }
    fn submit_write_zeroes(&mut self, lba: u64, nlba: u32, _tag: u64) -> Submit<Self::Buf> {
        panic!("read-only mount submitted write-zeroes at LBA {lba} (+{nlba})")
    }
    fn poll(&mut self, now: Nanos, out: &mut Vec<Completion<Self::Buf>>) -> usize {
        self.0.poll(now, out)
    }
    fn next_deadline(&self) -> Option<Nanos> {
        self.0.next_deadline()
    }
    fn is_dead(&self) -> bool {
        self.0.is_dead()
    }
}

/// Run one ostool invocation on an already-mounted read-only store (as `croit-flashstore-tool objectstore` does).
fn run_ro(
    ad: &StoreAdapter<NoWrite, SimClock>,
    meta: &mut NvmeMeta<NoWrite, SimClock>,
    args: &[&str],
) -> Out {
    let a: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let o = Opts::parse(&a).unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = {
        let mut c = Ctx {
            ad,
            meta,
            o: &o,
            out: &mut out,
            err: &mut err,
            input: Some(Box::new(std::io::empty())),
        };
        ostool::run(&mut c)
    };
    Out {
        code,
        out,
        err: String::from_utf8_lossy(&err).into_owned(),
    }
}

/// PGs of pool 1 on a 4-shard store: shard_of_spg = (pool + seed) % 4.
const PGS: [(&str, u32); 7] = [
    ("1.3", 0),
    ("1.0", 1),
    ("1.1", 2),
    ("1.2", 3),
    ("1.5", 2),
    ("1.6", 3),
    ("1.7", 0),
];

/// A 4-shard store whose read-only mount has real work: a checkpointed part, a removed PG (freed blocks: trim and
/// reclaim candidates) and PGs written after the last checkpoint (WAL replay). Returns the disk and the reference
/// export of every PG, taken on the writable mount.
/// `(pgid, device shard, export bytes)` of one PG.
type Export = (&'static str, u32, Vec<u8>);

fn build(dir: &Path) -> (SimDisk, Vec<Export>) {
    let disk = new_disk_shards(256, 4);
    let mut r = mount(&disk);
    seed_maps(&mut r, 6, &[1]);
    for seed in [3, 0, 1, 2, 4] {
        make_pg(&r, spg(1, seed), 4);
    }
    r.ad.with_store(|s| s.checkpoint()).unwrap();
    let o = run(&mut r, &["--op", "remove", "--pgid", "1.4", "--force"], b"");
    assert_eq!(o.code, 0, "remove 1.4: {}", o.err);
    // written after the last checkpoint: the next mount replays them
    for seed in [5, 6, 7] {
        make_pg(&r, spg(1, seed), 4);
    }
    let reference = PGS
        .iter()
        .map(|&(pg, shard)| {
            let f = dir.join(format!("ref-{pg}.export"));
            let o = run(
                &mut r,
                &[
                    "--op",
                    "export",
                    "--pgid",
                    pg,
                    "--file",
                    f.to_str().unwrap(),
                ],
                b"",
            );
            assert_eq!(o.code, 0, "{pg}: {}", o.err);
            (pg, shard, std::fs::read(&f).unwrap())
        })
        .collect();
    drop(r);
    (disk, reference)
}

/// Mount `disk` read-only on [`NoWrite`] queues with the shards `owned` accepts; run every read-only op the degraded
/// mode offers plus the refused writes; check the exports and that the device saw no write.
fn degraded_session(
    disk: &SimDisk,
    dir: &Path,
    reference: &[Export],
    sel: &[&'static str],
    skipped: Option<u32>,
) {
    let before = disk.stats();
    let d = disk.clone();
    let (st, stats, report) = Store::mount_shards_read_only(
        move || NoWrite(d.queue()),
        SimClock::default(),
        StoreCfg::default(),
        |s| Some(s) != skipped,
    )
    .unwrap();
    for (i, s) in report.iter().enumerate() {
        let want = if Some(i as u32) == skipped {
            ShardMountState::Skipped
        } else {
            ShardMountState::Mounted
        };
        assert_eq!(*s, want, "shard {i}");
    }
    assert!(
        stats.iter().map(|s| s.txns).sum::<u64>() > 0,
        "the read-only mount replayed nothing: the WAL path is not exercised"
    );
    let shared = Rc::new(RefCell::new(st));
    let mut meta = NvmeMeta::open_read_only(shared.clone()).unwrap();
    let ad = StoreAdapter::from_shared(shared);
    let args = |extra: &[&'static str]| -> Vec<&'static str> {
        let mut v = extra.to_vec();
        v.extend_from_slice(sel);
        v
    };

    // every PG of a mounted shard exports byte-exact (checkpointed and replayed ones alike)
    for (pg, shard, expected) in reference {
        let f = dir.join(format!("ro-{pg}.export"));
        let fs = f.to_str().unwrap().to_owned();
        let mut a: Vec<&str> = vec!["--op", "export", "--pgid", pg, "--file", &fs];
        a.extend_from_slice(sel);
        let o = run_ro(&ad, &mut meta, &a);
        if Some(*shard) == skipped {
            // a PG on the skipped shard is reported as such, never "not found"
            assert_eq!(o.code, EXIT_DEGRADED, "{pg}: {}", o.err);
            assert!(
                o.err.contains(&format!("shard {shard} skipped")),
                "{}",
                o.err
            );
            continue;
        }
        assert_eq!(o.code, 0, "{pg}: {}", o.err);
        assert_eq!(std::fs::read(&f).unwrap(), *expected, "{pg} export differs");
    }

    // a writable shard would now checkpoint its replayed WAL (requested, interval long past) and trim its free
    // windows (quiet gap long past): the read-only shards must do neither while the ops below poll them
    ad.with_store(|s| {
        s.request_checkpoint();
        s.clk.t += 120_000_000_000;
        let mut acked = Vec::new();
        for _ in 0..200 {
            s.clk.t += 50_000_000;
            s.poll(&mut acked).unwrap();
        }
    });

    // the read-only ops: all succeed and every one names the skipped shard
    let map = dir.join("ro-osdmap");
    let map = map.to_str().unwrap().to_owned();
    let get_map: Vec<&str> = vec!["--op", "get-osdmap", "--file", &map];
    for op in [
        args(&["--op", "list-pgs"]),
        args(&["--op", "list"]),
        args(&["--op", "meta-list"]),
        args(&["--op", "info", "--pgid", "1.3"]),
        args(&["--op", "log", "--pgid", "1.3"]),
        args(&["--op", "fsck"]),
        args(&["--op", "fsck-deep"]),
        args(&["--op", "statfs"]),
        args(&["--op", "dump-super"]),
        [get_map.clone(), sel.to_vec()].concat(),
    ] {
        let o = run_ro(&ad, &mut meta, &op);
        assert_eq!(o.code, 0, "{op:?}: {}", o.err);
        if let Some(s) = skipped {
            assert!(
                o.err.contains(&format!("shard {s} skipped")),
                "{op:?}: {}",
                o.err
            );
        }
    }
    let o = run_ro(&ad, &mut meta, &args(&["--op", "list-pgs"]));
    let listed: Vec<String> = o.text().lines().map(str::to_owned).collect();
    for (pg, shard, _) in reference {
        assert_eq!(
            listed.contains(&pg.to_string()),
            Some(*shard) != skipped,
            "{pg}: {listed:?}"
        );
    }

    // every write op is refused with the documented exit code and a message naming the op
    for op in [
        args(&["--op", "mark-complete", "--pgid", "1.3"]),
        args(&["--op", "remove", "--pgid", "1.3", "--force"]),
        args(&["--op", "import", "--file", "/nonexistent"]),
        args(&["--op", "trim-pg-log", "--pgid", "1.3"]),
        args(&["--op", "set-osdmap", "--file", "/nonexistent"]),
        args(&["--pgid", "1.3", "small", "set-attr", "_k", "/nonexistent"]),
        args(&["--pgid", "1.3", "small", "remove"]),
    ] {
        let o = run_ro(&ad, &mut meta, &op);
        assert_eq!(o.code, EXIT_DEGRADED, "{op:?}: {}", o.err);
        assert!(
            o.err.contains("degraded read-only mount"),
            "{op:?}: {}",
            o.err
        );
    }

    // the store layer refuses a txn and a checkpoint itself (no hang, no write)
    let mut t = store::obj::OTxn::new();
    t.push(store::obj::TOp::MkColl {
        cid: denc::types::CollT::Meta,
        bits: 0,
        exist_ok: true,
    });
    let e = ad.with_store(|s| s.commit(&t)).unwrap_err();
    assert!(e.to_string().contains("read-only"), "{e}");
    assert!(ad.with_store(|s| s.checkpoint()).is_err());

    drop(ad);
    drop(meta);
    let after = disk.stats();
    assert_eq!(
        (after.writes, after.deallocs),
        (before.writes, before.deallocs),
        "the degraded session changed the device"
    );
}

#[test]
fn degraded_read_only_mount_exports_healthy_pgs_and_writes_nothing() {
    let dir = std::env::temp_dir().join(format!("ostool-degraded-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (disk, reference) = build(&dir);

    // corrupt shard 3's meta region (both root slots)
    let (root_a, root_b) = {
        let mut q = disk.queue();
        let (_sb, dirs) = store::layout::read_super(&mut q, &mut SimClock::default()).unwrap();
        assert_eq!(dirs.len(), 4);
        (dirs[3].root_a, dirs[3].root_b)
    };
    disk.corrupt(root_a, 0, 0xff);
    disk.corrupt(root_b, 0, 0xff);

    // a read-only mount that selects the damaged shard reports it failed and still mounts the others
    let d = disk.clone();
    let (_, _, report) = Store::mount_shards_read_only(
        move || NoWrite(d.queue()),
        SimClock::default(),
        StoreCfg::default(),
        |_| true,
    )
    .unwrap();
    assert!(
        matches!(&report[3], ShardMountState::Failed(e) if e.contains("shard 3")),
        "{report:?}"
    );
    assert!(
        report[..3].iter().all(|s| *s == ShardMountState::Mounted),
        "{report:?}"
    );

    let root_a_before = disk.image().read_lba(root_a);
    let root_b_before = disk.image().read_lba(root_b);
    degraded_session(&disk, &dir, &reference, &["--skip-shard", "3"], Some(3));
    assert_eq!(disk.image().read_lba(root_a), root_a_before);
    assert_eq!(disk.image().read_lba(root_b), root_b_before);
    // a normal mount fails and names the damaged shard (last: it checkpoints the healthy shards' replay)
    let d = disk.clone();
    let err =
        Store::mount(move || d.queue(), SimClock::default(), StoreCfg::default()).unwrap_err();
    assert!(err.to_string().contains("shard 3"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn healthy_read_only_mount_of_all_shards_writes_nothing() {
    let dir = std::env::temp_dir().join(format!("ostool-degraded-ok-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (disk, reference) = build(&dir);
    degraded_session(&disk, &dir, &reference, &["--shards", "0,1,2,3"], None);
    // the store is still whole: a normal mount after the read-only session replays the same WAL
    let d = disk.clone();
    let (_, stats) =
        Store::mount(move || d.queue(), SimClock::default(), StoreCfg::default()).unwrap();
    assert!(stats.iter().map(|s| s.txns).sum::<u64>() > 0);
    let _ = std::fs::remove_dir_all(&dir);
}
