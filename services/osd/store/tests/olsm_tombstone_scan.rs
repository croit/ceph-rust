// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Omap listing over a span of deleted keys (rgw index purge, then listing): a deleted key of the LSM omap engine is
//! a tombstone that stays in the runs until a merge consumes it, so a listing from the start has to merge past all of
//! them. The pass must end after bounded work and the request continue where it stopped: never one call over the whole
//! span (a core wedge until the monitor marked the OSD down), never a restart from the first key after a cold run block
//! refused it (more refusals without progress than the executor tolerates before it runs the request blocking).
//! The listing is the contract of `omap_get_vals`: pages of the keys after the resume token, none lost, none twice.
#[path = "common/objmodel.rs"]
mod objmodel;

use denc::types::{CollT, Ghobject, Hobject, ShardId, SnapId};
use objmodel::pgc;
use store::dev::{SimClock, SimConfig, SimDev, SimDisk};
use store::layout::{MkfsParams, mkfs};
use store::obj::txn::Bytes as TxnBytes;
use store::obj::{OTxn, ObjError, Store, StoreCfg, TOp};

type St = Store<SimDev, SimClock>;

fn g(oid: &[u8]) -> Ghobject {
    Ghobject::new(
        Hobject::new(oid, SnapId::NOSNAP, 7, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}
fn coll() -> CollT {
    pgc(1, 0)
}

/// RGW-index-like key of index `i`: `data/<16 bit hash>/<i>`; the hash scatters the insert order over the key order.
fn key(i: u64) -> Vec<u8> {
    let mut x = i.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0x5333_4e41_4d45;
    x ^= x >> 29;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 32;
    format!("data/{:04x}/{:016x}{:016x}", x & 0xffff, i, x).into_bytes()
}

struct Rig {
    disk: SimDisk,
    st: St,
    sim: SimConfig,
    cfg: StoreCfg,
}

impl Rig {
    fn new(disk_mb: u64, omap_lsm: bool) -> Rig {
        let sim = SimConfig::new(disk_mb << 20);
        let disk = SimDisk::new(sim.clone());
        mkfs(
            &mut disk.queue(),
            &mut SimClock::default(),
            &MkfsParams {
                shards: 1,
                wal_blocks: 8192,
                align_blocks: 1,
                omap_lsm,
                ..Default::default()
            },
        )
        .unwrap();
        let cfg = StoreCfg::default();
        let d2 = disk.clone();
        let (st, _) = Store::mount(move || d2.queue(), SimClock::default(), cfg.clone()).unwrap();
        Rig { disk, st, sim, cfg }
    }
    fn remount(&mut self) {
        self.st.checkpoint().unwrap();
        let img = self.disk.image();
        let disk = SimDisk::from_image(&img, self.sim.clone());
        let d2 = disk.clone();
        let (st, _) =
            Store::mount(move || d2.queue(), SimClock::default(), self.cfg.clone()).unwrap();
        self.disk = disk;
        self.st = st;
    }
    fn pump_until_named(&mut self, cause: &store::toks::Toks<8>) {
        let unknown = cause.is_empty() || cause.overflowed();
        for _ in 0..2_000_000 {
            let mut acked = vec![];
            self.st.poll(&mut acked).unwrap();
            let (mut toks, mut all) = (store::toks::Toks::<32>::new(), false);
            if self.st.take_wake_set(&mut toks, &mut all)
                && (all
                    || unknown
                    || toks.overflowed()
                    || toks.as_slice().iter().any(|t| cause.as_slice().contains(t)))
            {
                return;
            }
            self.st.idle();
        }
        panic!("the awaited page load never completed");
    }
}

fn run_request<T>(
    r: &mut Rig,
    tid: u64,
    mut f: impl FnMut(&mut St) -> Result<T, ObjError>,
) -> (T, u32, u32) {
    let (mut refused, mut progressed) = (0u32, 0u32);
    loop {
        r.st.read_session(Some((1, tid)), true);
        r.st.set_nonblock_reads(true);
        r.st.cause_begin();
        let res = f(&mut r.st);
        r.st.set_nonblock_reads(false);
        let blocked = r.st.take_blocked();
        r.st.read_session(None, blocked);
        match res {
            Err(ObjError::WouldBlock) => {
                assert!(blocked, "refusal not latched");
                refused += 1;
                progressed += u32::from(r.st.take_rm_progress());
                assert!(refused < 1_000_000, "listing never finished");
                let mut cause = store::toks::Toks::<8>::new();
                r.st.cause_take(&mut cause);
                r.pump_until_named(&cause);
            }
            Ok(v) => return (v, refused, progressed),
            Err(e) => panic!("{e:?}"),
        }
    }
}

const VALUE: usize = 300;
/// Pass limit of the executor for refusals that made no progress ("MAX_SCAN_TRIES" of crate opexec): past it the
/// request runs blocking and stalls the core on the device.
const EXECUTOR_NO_PROGRESS_LIMIT: u32 = 64;

fn n_keys() -> u64 {
    std::env::var("N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60_000)
}

/// Populate `n` keys in one object, then delete every key below `data/8000/` (about half) with point removals in
/// batches. Returns the live keys, ascending.
fn populate_and_purge(r: &mut Rig, n: u64) -> Vec<Vec<u8>> {
    let (o, c) = (g(b"obj"), coll());
    let mut t = OTxn::new();
    t.mkcoll(c);
    r.st.commit(&t).unwrap();
    for ch in (0..n).collect::<Vec<_>>().chunks(1000) {
        let mut t = OTxn::new();
        t.push(TOp::OmapSetKeys {
            cid: c,
            oid: o.clone(),
            pairs: ch
                .iter()
                .map(|&i| (TxnBytes::Owned(key(i)), TxnBytes::Owned(vec![7u8; VALUE])))
                .collect(),
        });
        r.st.commit(&t).unwrap();
    }
    let mut keys: Vec<Vec<u8>> = (0..n).map(key).collect();
    keys.sort();
    let (dead, live): (Vec<_>, Vec<_>) = keys.into_iter().partition(|k| k[..] < b"data/8000/"[..]);
    for ch in dead.chunks(1000) {
        let mut t = OTxn::new();
        t.push(TOp::OmapRmKeys {
            cid: c,
            oid: o.clone(),
            keys: ch.iter().map(|k| TxnBytes::Owned(k.clone())).collect(),
        });
        r.st.commit(&t).unwrap();
    }
    assert!(dead.len() > 1000 && live.len() > 1000);
    live
}

fn slices(r: &Rig) -> u64 {
    r.st.perf_counters()
        .into_iter()
        .find(|(k, _, _)| *k == "scan_slices")
        .expect("scan_slices counter")
        .2
}

/// One client listing request (`omap_get_vals`: `max` entries after `after`) run the way the executor runs it.
/// Returns the keys, `more`, refused runs, refused runs that kept progress and the slices ended by the CPU budget.
fn get_vals(
    r: &mut Rig,
    tid: u64,
    after: &[u8],
    max: usize,
) -> (Vec<Vec<u8>>, bool, u32, u32, u64) {
    let (o, c) = (g(b"obj"), coll());
    // `omap_range` starts at `from` inclusive: the key after the token is the token plus a zero byte
    let mut from = after.to_vec();
    if !after.is_empty() {
        from.push(0);
    }
    let s0 = slices(r);
    let ((kv, more), refused, progressed) = run_request(r, tid, |st| {
        st.omap_range(&c, &o, &from, b"", max, usize::MAX, true)
    });
    let keys = kv.into_iter().map(|(k, _)| k).collect();
    (keys, more, refused, progressed, slices(r) - s0)
}

/// The whole object through pages of 1000 keys with resume tokens: right after the purge (run blocks cold, the
/// deleted span in the memtable), warm, and after a remount (everything cold). Every page is full until the last, the
/// pages are exactly the live keys, and no request needs as many refused runs without progress as the executor
/// tolerates before it runs the request blocking. Returns the most refused runs without progress of any request, the
/// slices the warm pass ended and the runs the warm first page was refused.
fn page_through(omap_lsm: bool) -> (u32, u64, u32) {
    let n = n_keys();
    let mut r = Rig::new(1024, omap_lsm);
    let live = populate_and_purge(&mut r, n);
    let (mut worst, mut warm_slices, mut warm_first_refused) = (0u32, 0u64, 0u32);
    for phase in ["purged", "warm", "remounted"] {
        if phase == "remounted" {
            r.remount();
        }
        let (mut got, mut after) = (Vec::<Vec<u8>>::new(), Vec::<u8>::new());
        let mut tid = 1 + 10_000 * (phase.len() as u64);
        loop {
            let t0 = std::time::Instant::now();
            let (keys, more, refused, progressed, sl) = get_vals(&mut r, tid, &after, 1000);
            if after.is_empty() {
                eprintln!(
                    "lsm {omap_lsm} {phase}: first page {} keys, {refused} refused runs ({} without progress), {sl} slices, {:?}",
                    keys.len(),
                    refused - progressed,
                    t0.elapsed()
                );
            }
            tid += 1;
            let stuck = refused - progressed;
            worst = worst.max(stuck);
            if phase == "warm" {
                warm_slices += sl;
                if after.is_empty() {
                    warm_first_refused = refused;
                }
            }
            assert!(
                stuck < EXECUTOR_NO_PROGRESS_LIMIT,
                "request {tid} (lsm {omap_lsm}, {phase}): {stuck} of {refused} refused runs without progress"
            );
            if more {
                assert_eq!(keys.len(), 1000, "a page with more after it is full");
            }
            after = keys.last().cloned().unwrap_or(after);
            got.extend(keys);
            if !more {
                break;
            }
        }
        assert!(
            got == live,
            "{phase}: the pages are the live keys, none lost or twice"
        );
    }
    (worst, warm_slices, warm_first_refused)
}

/// LSM engine: the span of deleted keys in front of the first live key is merged in passes of bounded work (a warm
/// listing ends a pass every `LSM_LIST_VISITS` entries; before, one pass ran over the whole span), the listing
/// continues where each pass or refused read stopped, and a refused read is not charged to the request when it only
/// waits for loads in flight. `N` above the run cache (about 100000 keys) keeps the "warm" phase cold: it then ends its
/// passes on refused reads, not on the CPU budget.
#[test]
fn lsm_listing_over_deleted_span_is_sliced_and_resumes_exactly() {
    let (worst, warm_slices, warm_first_refused) = page_through(true);
    eprintln!(
        "lsm: worst refused-without-progress {worst}, warm slices {warm_slices}, warm first page passes {warm_first_refused}"
    );
    assert!(
        warm_first_refused > 1,
        "the warm first page crosses the deleted span in more than one pass"
    );
}

/// B+tree engine (the sibling): a purged range leaves leaves without entries; the first listing after it crosses
/// them, and the refusals of those cold leaves moved the cursor, so they are progress.
#[test]
fn btree_listing_after_purge_resumes_and_makes_progress() {
    let (worst, warm_slices, _) = page_through(false);
    eprintln!("btree: worst refused-without-progress {worst}, warm slices {warm_slices}");
}
