// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Listings on the PG core (adr 0021 S5, S8): scan-resistant tree cache, resumable / sliced omap scans and object
//! listings in non-blocking mode (results identical to a blocking run, refusals cost no repeated work).
#[path = "common/objmodel.rs"]
mod objmodel;

use denc::types::{CollT, Ghobject, Hobject, ShardId, SnapId};
use objmodel::pgc;
use std::collections::BTreeMap;
use store::dev::{SimClock, SimConfig, SimDev, SimDisk};
use store::layout::{MkfsParams, mkfs};
use store::obj::txn::Bytes as TxnBytes;
use store::obj::{OTxn, ObjError, Store, StoreCfg, TOp};
use store::shard::ShardCfg;

type St = Store<SimDev, SimClock>;

struct Rig {
    disk: SimDisk,
    st: St,
    sim: SimConfig,
    cfg: StoreCfg,
}

impl Rig {
    fn new(cache_pages: usize, seed: u64) -> Rig {
        // plain values: leaf counts follow from the sizes
        Rig::with(cache_pages, seed, |c| c.shard.val_comp_min = 0)
    }

    fn with(cache_pages: usize, seed: u64, tune: impl FnOnce(&mut StoreCfg)) -> Rig {
        let mut sim = SimConfig::new(512 << 20);
        sim.seed = seed;
        let disk = SimDisk::new(sim.clone());
        {
            let mut dev = disk.queue();
            let mut clk = SimClock::default();
            let p = MkfsParams {
                shards: 1,
                wal_blocks: 2048,
                align_blocks: 1,
                meta_pct: 12,
                node_size: 8192,
                ..Default::default()
            };
            mkfs(&mut dev, &mut clk, &p).unwrap();
        }
        let mut cfg = StoreCfg {
            shard: ShardCfg {
                cache_pages,
                ..StoreCfg::default().shard
            },
        };
        tune(&mut cfg);
        let d2 = disk.clone();
        let (st, _) = Store::mount(move || d2.queue(), SimClock::default(), cfg.clone()).unwrap();
        Rig { disk, st, sim, cfg }
    }

    /// Checkpoint, remount on the image: every tree page cold.
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

    fn commit(&mut self, t: &OTxn) {
        self.st.commit(t).unwrap();
    }

    /// Poll until a page load completes (the store wake the engine retries on).
    fn pump_until_wake(&mut self) {
        for _ in 0..200_000 {
            let mut acked = vec![];
            self.st.poll(&mut acked).unwrap();
            if self.st.take_wake() {
                return;
            }
            self.st.idle();
        }
        panic!("page load never completed");
    }

    /// Poll until a wake names one of `cause` (or wakes everything; an unknown cause takes any wake).
    fn pump_until_named(&mut self, cause: &store::toks::Toks<8>) {
        let unknown = cause.is_empty() || cause.overflowed();
        for _ in 0..200_000 {
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

    fn loads(&self) -> u64 {
        self.st.tree_stats().loads
    }
}

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

fn key(i: u32) -> Vec<u8> {
    format!("key/{i:08}").into_bytes()
}

fn val(i: u32, len: usize) -> Vec<u8> {
    (0..len).map(|j| (i as usize * 31 + j * 7) as u8).collect()
}

/// `n` keys of `vlen` byte values into `o` (created with the collection when needed).
fn fill(r: &mut Rig, o: &Ghobject, n: u32, vlen: usize) {
    let c = coll();
    if !r.st.coll_exists(&c).unwrap() {
        let mut t = OTxn::new();
        t.mkcoll(c);
        r.commit(&t);
    }
    for ch in (0..n).collect::<Vec<_>>().chunks(1000) {
        let mut t = OTxn::new();
        t.push(TOp::OmapSetKeys {
            cid: c,
            oid: o.clone(),
            pairs: ch
                .iter()
                .map(|&i| (TxnBytes::Owned(key(i)), TxnBytes::Owned(val(i, vlen))))
                .collect(),
        });
        r.commit(&t);
    }
}

/// adr 0021 S5: a long cold listing does not push the point-op working set out of the tree cache. Hot object `h`
/// (~40 leaves) is read one key per leaf between two listing pages (a hot set touched far less often than the
/// listing turns the cache over); after a full listing of `big` (~1500 leaves, cache 256 pages) the hot leaves
/// are still resident: the point gets never miss.
#[test]
fn listing_does_not_evict_the_hot_set() {
    let mut r = Rig::new(256, 3);
    let (big, h) = (g(b"big"), g(b"hot"));
    fill(&mut r, &big, 60_000, 200);
    fill(&mut r, &h, 1_600, 200);
    r.remount();
    let c = coll();
    // warm the hot set (blocking reads)
    assert_eq!(r.st.omap_all(&c, &h).unwrap().len(), 1_600);
    let (mut from, mut pages, mut hot_misses) = (Vec::new(), 0u32, 0u32);
    loop {
        let (kv, more) =
            r.st.omap_range(&c, &big, &from, b"", 1024, usize::MAX, true)
                .unwrap();
        pages += 1;
        // every 4th page: one point get per hot leaf (40 keys per leaf), non-blocking: a refusal = an evicted hot leaf
        if pages % 4 == 0 {
            r.st.set_nonblock_reads(true);
            for i in (0..1_600).step_by(40) {
                let k = key(i);
                match r.st.omap_get(&c, &h, &[&k]) {
                    Ok(m) => assert_eq!(m.len(), 1),
                    Err(ObjError::WouldBlock) => hot_misses += 1,
                    Err(e) => panic!("{e:?}"),
                }
            }
            r.st.set_nonblock_reads(false);
            if r.st.take_blocked() {
                r.st.wait_loads().unwrap();
            }
        }
        let Some((k, _)) = kv.last() else { break };
        from = k.clone();
        from.push(0);
        if !more {
            break;
        }
    }
    assert!(pages > 50);
    assert_eq!(
        hot_misses,
        0,
        "hot leaves evicted by the listing ({} loads)",
        r.loads()
    );
    let ts = r.st.tree_stats();
    assert!(
        ts.scan_loads > 1_000,
        "listing leaves not read as scan pages: {ts:?}"
    );
}

/// One executor request run as the engine does it: non-blocking, inside its read session, re-run after every refusal
/// (cold leaf or CPU slice) once the store woke. Returns the result and (refused runs, runs that made progress).
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
                assert!(refused < 100_000, "listing never finished");
                // as the engine: run again on the wake that names what the run waited for (adr 0043 am. 9)
                let mut cause = store::toks::Toks::<8>::new();
                r.st.cause_take(&mut cause);
                r.pump_until_named(&cause);
            }
            Ok(v) => {
                assert!(!blocked);
                return (v, refused, progressed);
            }
            Err(e) => panic!("{e:?}"),
        }
    }
}

type Page = (Vec<(Vec<u8>, Vec<u8>)>, bool);

fn from_after(after: Option<&[u8]>, prefix: &[u8]) -> Vec<u8> {
    let mut f = after.map_or_else(Vec::new, |a| {
        let mut v = a.to_vec();
        v.push(0);
        v
    });
    if f.as_slice() < prefix {
        f = prefix.to_vec();
    }
    f
}

/// The whole object listed in client pages of `page` entries (each starts after the last key), blocking.
fn list_blocking(r: &mut Rig, o: &Ghobject, prefix: &[u8], page: usize, values: bool) -> Vec<Page> {
    let c = coll();
    let (mut out, mut after): (Vec<Page>, Option<Vec<u8>>) = (Vec::new(), None);
    loop {
        let from = from_after(after.as_deref(), prefix);
        let p =
            r.st.omap_range(&c, o, &from, prefix, page, usize::MAX, values)
                .unwrap();
        after = p.0.last().map(|(k, _)| k.clone());
        let more = p.1;
        out.push(p);
        if !more {
            return out;
        }
    }
}

/// adr 0021 S8: a cold listing in non-blocking executor runs continues where a refusal or a CPU slice stopped it:
/// every page equals the blocking listing, every leaf is read once (no pass starts over), passes are sliced, and a
/// refused run after the first admitted entries reports progress (never charged against the engine's try bound).
#[test]
fn nonblocking_listing_resumes_and_matches_blocking() {
    let mut r = Rig::new(256, 5);
    let big = g(b"big");
    fill(&mut r, &big, 60_000, 200);
    for (prefix, page, values) in [
        (&b""[..], 1024usize, true),
        (&b""[..], 4000, false),
        (&b"key/0001"[..], 1024, true),
    ] {
        r.remount();
        let l0 = r.loads();
        let want = list_blocking(&mut r, &big, prefix, page, values);
        let leaves = r.loads() - l0;
        r.remount();
        let l0 = r.loads();
        let (mut after, mut tid, mut got) = (None::<Vec<u8>>, 1u64, Vec::new());
        let (mut refused, mut progressed) = (0, 0);
        loop {
            let from = from_after(after.as_deref(), prefix);
            let c = coll();
            let (p, rf, pr) = run_request(&mut r, tid, |st| {
                st.omap_range(&c, &big, &from, prefix, page, usize::MAX, values)
            });
            refused += rf;
            progressed += pr;
            tid += 1;
            after = p.0.last().map(|(k, _)| k.clone());
            let more = p.1;
            got.push(p);
            if !more {
                break;
            }
        }
        assert!(
            got == want,
            "prefix {prefix:?} page {page}: pages differ from the blocking listing"
        );
        let loads = r.loads() - l0;
        assert!(
            loads <= leaves + leaves / 20 + 4,
            "prefix {prefix:?}: {loads} page loads, the blocking listing needed {leaves}"
        );
        // per request at most one refusal without progress (its first pass, on a cold leaf)
        assert!(
            refused - progressed < tid as u32,
            "{refused} refusals, {progressed} with progress, {tid} requests"
        );
    }
}

/// adr 0021 S8: a warm listing is cut into CPU slices (one pass admits at most one slice of entries or bytes), each
/// slice continues at the key the previous one stopped at, the result equals the blocking listing (keys, values,
/// `more`, the byte-budget cut), and every sliced run reports progress.
#[test]
fn warm_listing_runs_in_slices() {
    let mut r = Rig::new(8192, 17);
    let big = g(b"big");
    fill(&mut r, &big, 20_000, 300);
    let c = coll();
    // (entry budget, byte budget, values): entry-bound, byte-bound (values), byte-bound (keys: 4 + key per entry)
    for (tid, (max, max_bytes, values)) in [
        (20_000usize, usize::MAX, true),
        (20_000, 2_000_000, true),
        (20_000, 100_000, false),
        (5_000, usize::MAX, false),
    ]
    .into_iter()
    .enumerate()
    {
        let want =
            r.st.omap_range(&c, &big, b"key/00000100", b"", max, max_bytes, values)
                .unwrap();
        let s0 = r.st.shards[0].stats.scan_slices;
        let (got, refused, progressed) = run_request(&mut r, tid as u64 + 1, |st| {
            st.omap_range(&c, &big, b"key/00000100", b"", max, max_bytes, values)
        });
        assert!(
            got == want,
            "max {max} bytes {max_bytes}: sliced listing differs"
        );
        let slices = r.st.shards[0].stats.scan_slices - s0;
        assert_eq!(u64::from(refused), slices, "warm: every refusal is a slice");
        assert_eq!(refused, progressed);
        let bytes: usize = got.0.iter().map(|(k, v)| k.len() + v.len()).sum();
        let lo = (got.0.len() / 256).max(bytes / (256 << 10));
        assert!(
            slices as usize + 1 >= lo,
            "{slices} slices for {} entries {bytes} B",
            got.0.len()
        );
    }
}

/// adr 0021 S8: a mutation of the listed object between two passes drops the request's scan memo: the listing starts
/// over and returns the object as it is now; a mutation of another object leaves the memo alone.
#[test]
fn listing_memo_is_dropped_by_a_mutation_of_its_object() {
    let mut r = Rig::new(4096, 9);
    let (big, other) = (g(b"big"), g(b"other"));
    fill(&mut r, &big, 3_000, 100);
    fill(&mut r, &other, 10, 100);
    let c = coll();
    for mutate_big in [false, true] {
        let tid = 7 + u64::from(mutate_big);
        let res0 = r.st.shards[0].stats.scan_resumes;
        let mut passes = 0;
        let res = loop {
            r.st.read_session(Some((1, tid)), true);
            r.st.set_nonblock_reads(true);
            let res =
                r.st.omap_range(&c, &big, b"", b"", 2_000, usize::MAX, false);
            r.st.set_nonblock_reads(false);
            let blocked = r.st.take_blocked();
            r.st.read_session(None, blocked);
            passes += 1;
            match res {
                Ok(v) => break v,
                Err(ObjError::WouldBlock) => {
                    if passes == 2 {
                        // between two passes: a new key below the walk position and one beyond it
                        let o = if mutate_big { &big } else { &other };
                        let mut t = OTxn::new();
                        t.omap_set(c, o, b"key/00000000a", b"x");
                        t.omap_set(c, o, b"key/00001999a", b"y");
                        r.commit(&t);
                    }
                    r.pump_until_wake();
                }
                Err(e) => panic!("{e:?}"),
            }
        };
        assert!(passes >= 4, "not sliced: {passes} passes");
        let want =
            r.st.omap_range(&c, &big, b"", b"", 2_000, usize::MAX, false)
                .unwrap();
        assert!(
            res == want,
            "mutate_big {mutate_big}: listing differs from the object's current state"
        );
        assert_eq!(
            res.0.iter().any(|(k, _)| k == b"key/00000000a"),
            mutate_big,
            "the key added before the walk position"
        );
        let resumes = r.st.shards[0].stats.scan_resumes - res0;
        assert_eq!(
            resumes as usize,
            passes - 1 - usize::from(mutate_big),
            "mutate_big {mutate_big}: passes continued from the memo"
        );
    }
}

/// A request that ends (or is abandoned) drops its scan memos: the next request with the same parameters starts fresh.
#[test]
fn listing_memo_lives_with_its_request() {
    let mut r = Rig::new(4096, 13);
    let big = g(b"big");
    fill(&mut r, &big, 3_000, 100);
    let c = coll();
    let pass = |r: &mut Rig, tid: u64, keep: bool| {
        r.st.read_session(Some((1, tid)), true);
        r.st.set_nonblock_reads(true);
        let res =
            r.st.omap_range(&c, &big, b"", b"", 2_000, usize::MAX, false);
        r.st.set_nonblock_reads(false);
        let blocked = r.st.take_blocked();
        r.st.read_session(None, blocked && keep);
        res
    };
    let res0 = r.st.shards[0].stats.scan_resumes;
    assert!(matches!(pass(&mut r, 1, true), Err(ObjError::WouldBlock)));
    r.pump_until_wake();
    assert!(matches!(pass(&mut r, 1, true), Err(ObjError::WouldBlock)));
    assert_eq!(
        r.st.shards[0].stats.scan_resumes - res0,
        1,
        "second pass continued"
    );
    // abandoned: the session closes without keep (op dropped), the same tid starts over
    assert!(matches!(pass(&mut r, 1, false), Err(ObjError::WouldBlock)));
    r.pump_until_wake();
    assert!(matches!(pass(&mut r, 1, true), Err(ObjError::WouldBlock)));
    assert_eq!(
        r.st.shards[0].stats.scan_resumes - res0,
        2,
        "a dropped memo was continued"
    );
}

/// A write queued through a builder (the OSD's write path): parks naming its whole collection.
struct Writer {
    c: CollT,
    o: Ghobject,
    data: bytes::Bytes,
}

impl store::obj::QueueBuilder<SimDev, SimClock> for Writer {
    fn build(&mut self, _: &mut St) -> store::obj::Result<Option<OTxn<'_>>> {
        let mut t = OTxn::new();
        t.write(self.c, &self.o, 0, &self.data);
        Ok(Some(t))
    }
    fn retained_bytes(&self) -> usize {
        self.data.len()
    }
}

/// adr 0021 S8: a non-blocking object listing waits for the txns parked when its request first listed, not for txns
/// parked later (a steady write stream would starve it); without a request (blocking caller) it drains them all.
#[test]
fn listing_waits_only_for_txns_parked_before_it() {
    let mut r = Rig::new(4096, 21);
    let c = coll();
    let mut t = OTxn::new();
    t.mkcoll(c);
    for i in 0..10 {
        t.touch(c, &g(format!("o{i}").as_bytes()));
    }
    r.commit(&t);
    r.st.set_prep_allowance(Some(std::time::Duration::ZERO));
    let big = vec![7u8; 1 << 20]; // large writes always park
    // odd tokens: a plain txn (names its object); even: a builder txn as the OSD write path queues it (names the
    // whole collection: `coll_exists` of `ov_list` waits for it too)
    let park = |r: &mut Rig, name: &[u8], tok: u64| {
        if tok % 2 == 1 {
            let mut t = OTxn::new();
            t.write(c, &g(name), 0, &big);
            r.st.queue(&t, tok).unwrap();
        } else {
            let w = Writer {
                c,
                o: g(name),
                data: bytes::Bytes::from(big.clone()),
            };
            r.st.queue_builder(&[c], tok, Box::new(w), false).unwrap();
        }
    };
    park(&mut r, b"w1", 1);
    let n0 = r.st.queued_count();
    assert!(n0 >= 1, "the large write did not park");
    let list = |r: &mut Rig| {
        r.st.read_session(Some((1, 9)), true);
        r.st.set_nonblock_reads(true);
        // as storeadapt `ov_list`: the collection first
        let res =
            r.st.coll_exists(&c)
                .and_then(|_| r.st.list(&c, &Ghobject::default(), None, 100));
        r.st.set_nonblock_reads(false);
        let blocked = r.st.take_blocked();
        r.st.read_session(None, blocked);
        res
    };
    assert!(
        matches!(list(&mut r), Err(ObjError::WouldBlock)),
        "listed past a parked txn"
    );
    // later writes keep parking while the listing waits
    let mut tok = 2;
    let listed = loop {
        park(&mut r, format!("w{tok}").as_bytes(), tok);
        tok += 1;
        let mut acked = vec![];
        r.st.poll(&mut acked).unwrap();
        r.st.idle();
        match list(&mut r) {
            Ok(v) => break v,
            Err(ObjError::WouldBlock) => {
                assert!(tok < 1000, "listing starved by later parked txns")
            }
            Err(e) => panic!("{e:?}"),
        }
    };
    assert!(
        r.st.queued_count() > 0,
        "the listing waited for the later txns too"
    );
    assert!(
        listed.0.iter().any(|o| o.hobj.oid == b"w1"),
        "the txn parked before is listed"
    );
    r.st.drain_queued().unwrap();
}

/// The encoded entries the store must list (`Store::omap_list_enc` rules): keys `>= from` starting with `prefix`, at most
/// `max`; values: stop at `max_bytes` (key + value bytes) after the first entry; keys only: stop at `max_bytes` encoded
/// keys (4 + key length). Returns (entries encoded, count, more).
fn model_enc(
    m: &BTreeMap<Vec<u8>, Vec<u8>>,
    from: &[u8],
    prefix: &[u8],
    max: usize,
    max_bytes: usize,
    values: bool,
) -> (Vec<u8>, usize, bool) {
    let (mut out, mut n, mut bytes) = (Vec::new(), 0usize, 0usize);
    for (k, v) in m.range(from.max(prefix).to_vec()..) {
        if !k.starts_with(prefix) {
            break;
        }
        let full = if values {
            n > 0 && bytes >= max_bytes
        } else {
            bytes >= max_bytes
        };
        if n >= max || full {
            return (out, n, true);
        }
        bytes += if values {
            k.len() + v.len()
        } else {
            4 + k.len()
        };
        n += 1;
        out.extend_from_slice(&(k.len() as u32).to_le_bytes());
        out.extend_from_slice(k);
        if values {
            out.extend_from_slice(&(v.len() as u32).to_le_bytes());
            out.extend_from_slice(v);
        }
    }
    (out, n, false)
}

/// Listing reply encoding (adr 0021 S8): `omap_list_enc` writes exactly the encoded entries of the listing for every value
/// form (inline, zstd-compressed inline, data-block, fragmented), keys only, prefixes, entry and byte budgets; blocking
/// and in non-blocking executor runs on a cold cache (sliced, refused on cold leaves and value fragments, resumed). The
/// buffer starts with the reserved head and has room for the caller's trailer byte.
#[test]
fn encoded_listing_matches_the_model() {
    let mut r = Rig::with(256, 9, |c| {
        c.shard.val_comp_min = 64;
        c.shard.val_dict_samples = 8;
    });
    let o = g(b"mixed");
    let c = coll();
    let mut t = OTxn::new();
    t.mkcoll(c);
    r.commit(&t);
    let sizes = [
        0usize, 1, 40, 120, 300, 1500, 2047, 2048, 5000, 20_000, 70_000,
    ];
    let mut m = BTreeMap::new();
    for i in 0..1500u32 {
        let len = sizes[(i as usize * 7) % sizes.len()];
        // even keys: compressible text (zstd inline once the class dictionary is trained), odd: incompressible
        let v = if i % 2 == 0 {
            let mut v = format!("owner-{:04} STANDARD application/octet-stream ", i % 3)
                .repeat(len / 40 + 1)
                .into_bytes();
            v.truncate(len);
            v
        } else {
            val(i, len)
        };
        m.insert(key(i), v);
    }
    let pairs: Vec<_> = m.iter().collect();
    for ch in pairs.chunks(100) {
        let mut t = OTxn::new();
        t.push(TOp::OmapSetKeys {
            cid: c,
            oid: o.clone(),
            pairs: ch
                .iter()
                .map(|(k, v)| (TxnBytes::Owned(k.to_vec()), TxnBytes::Owned(v.to_vec())))
                .collect(),
        });
        r.commit(&t);
    }
    assert!(
        r.st.shards[0].stats.val_comp > 0,
        "no value stored compressed: the zstd inline form is not covered"
    );
    let after500 = [key(500), vec![0]].concat();
    // (from, prefix, max, max_bytes, values)
    type Case<'a> = (&'a [u8], &'a [u8], usize, usize, bool);
    let cases: [Case; 8] = [
        (b"", b"", 100_000, usize::MAX, true),
        (b"", b"", 100_000, usize::MAX, false),
        (&after500, b"", 333, usize::MAX, true),
        (b"", b"key/000010", 50, usize::MAX, true),
        (b"key/00000999", b"key/000010", 1000, usize::MAX, false),
        (b"", b"", 1000, 100_000, true),
        (b"", b"", 1000, 777, false),
        (b"", b"", 0, usize::MAX, true),
    ];
    for (i, &(from, prefix, max, max_bytes, values)) in cases.iter().enumerate() {
        let (want, wn, wmore) = model_enc(&m, from, prefix, max, max_bytes, values);
        let check = |(buf, n, more): (Vec<u8>, usize, bool), how: &str| {
            assert_eq!(&buf[..4], &[0; 4], "case {i} {how}: head");
            assert!(
                buf[4..] == want[..],
                "case {i} {how}: entries differ ({} vs {} B)",
                buf.len() - 4,
                want.len()
            );
            assert_eq!((n, more), (wn, wmore), "case {i} {how}");
            assert!(
                buf.capacity() > buf.len(),
                "case {i} {how}: no room for the trailer"
            );
        };
        r.remount();
        check(
            r.st.omap_list_enc(&c, &o, from, prefix, max, max_bytes, values, 4)
                .unwrap(),
            "blocking",
        );
        // the pair listing is the same listing decoded
        let (kv, more) =
            r.st.omap_range(&c, &o, from, prefix, max, max_bytes, values)
                .unwrap();
        assert_eq!(more, wmore, "case {i} pairs");
        let mut enc = Vec::new();
        for (k, v) in &kv {
            enc.extend_from_slice(&(k.len() as u32).to_le_bytes());
            enc.extend_from_slice(k);
            if values {
                enc.extend_from_slice(&(v.len() as u32).to_le_bytes());
                enc.extend_from_slice(v);
            }
        }
        assert!(enc == want, "case {i} pairs differ");
        r.remount();
        let (got, refused, _) = run_request(&mut r, 1 + i as u64, |st| {
            st.omap_list_enc(&c, &o, from, prefix, max, max_bytes, values, 4)
        });
        check(got, "non-blocking");
        if i == 0 {
            assert!(
                refused > 3,
                "a cold listing of the whole object ran without refusals ({refused})"
            );
        }
    }
}

/// A compound read of a cold object (sparse read, omap get-by-keys, key and value listings, header, xattrs; values of
/// the data-block size class) run as the executor runs it: a refused run stops at its first refusal, the retry starts
/// over. Every refused run keeps all reads of its request, also those it did not reach: the request finishes after a
/// bounded number of runs and no data block is read twice. Before: a refusal dropped the reads the run had not reached,
/// the value listing (complete in one run, started over in the next) re-read one value per run while that run dropped
/// the next one, and the request never finished.
#[test]
fn a_cold_compound_read_finishes_without_reading_a_block_twice() {
    let mut r = Rig::with(4096, 3, |_| {});
    let (c, o) = (coll(), g(b"compound"));
    let mut t = OTxn::new();
    t.mkcoll(c);
    r.commit(&t);
    // fragmented data: strides of 40..80 KB
    let size = 390_609u64;
    let (mut off, mut i) = (0u64, 0u64);
    while off < size {
        let n = (40_000 + (i * 7919) % 40_000).min(size - off);
        let d = val(i as u32, n as usize);
        let mut t = OTxn::new();
        t.write(c, &o, off, &d);
        r.commit(&t);
        (off, i) = (off + n, i + 1);
    }
    // values below and of the data-block size class (2 KiB and more)
    let vals: Vec<(Vec<u8>, Vec<u8>)> = (0..24u32)
        .map(|k| (key(k), val(100 + k, (k as usize * 677) % 4000)))
        .collect();
    let mut t = OTxn::new();
    t.push(TOp::OmapSetKeys {
        cid: c,
        oid: o.clone(),
        pairs: vals
            .iter()
            .map(|(k, v)| (TxnBytes::Borrowed(k), TxnBytes::Borrowed(v)))
            .collect(),
    });
    t.push(TOp::OmapSetHeader {
        cid: c,
        oid: o.clone(),
        header: TxnBytes::Owned(val(7, 3000)),
    });
    t.push(TOp::SetAttrs {
        cid: c,
        oid: o.clone(),
        attrs: vec![
            (TxnBytes::Borrowed(b"_"), TxnBytes::Owned(val(11, 300))),
            (TxnBytes::Borrowed(b"_big"), TxnBytes::Owned(val(9, 2600))),
        ],
    });
    r.commit(&t);
    let want: Vec<&[u8]> = vals.iter().step_by(3).map(|(k, _)| k.as_slice()).collect();
    let op = |st: &mut St| -> Result<(), ObjError> {
        let d = st.read_shared(&c, &o, 0, size)?;
        assert_eq!(d.iter().map(|p| p.0.len() as u64).sum::<u64>(), size);
        assert_eq!(st.omap_get(&c, &o, &want)?.len(), want.len());
        st.omap_list_enc(&c, &o, b"", b"", 512, 1 << 20, false, 4)?;
        let (_, n, _) = st.omap_list_enc(&c, &o, b"", b"", 512, 1 << 20, true, 4)?;
        assert_eq!(n, vals.len());
        assert_eq!(st.omap_header(&c, &o)?, val(7, 3000));
        assert_eq!(st.getattrs(&c, &o)?.len(), 2);
        Ok(())
    };
    // the blocks one blocking pass reads (values both omap ops return twice: the request reads them once)
    r.remount();
    let b0 = r.st.shards[0].stats.read_blocks;
    op(&mut r.st).unwrap();
    let once = r.st.shards[0].stats.read_blocks - b0;
    r.remount();
    let b0 = r.st.shards[0].stats.read_blocks;
    let mut runs = 0u32;
    loop {
        runs += 1;
        assert!(runs <= 64, "the request never finishes: {}", r.st.diag());
        r.st.read_session(Some((31, 4140)), true);
        r.st.set_nonblock_reads(true);
        r.st.cause_begin();
        let res = op(&mut r.st);
        r.st.set_nonblock_reads(false);
        let blocked = r.st.take_blocked();
        r.st.read_session(None, blocked);
        match res {
            Ok(()) => break,
            Err(ObjError::WouldBlock) => {
                let mut cause = store::toks::Toks::<8>::new();
                r.st.cause_take(&mut cause);
                r.pump_until_named(&cause);
            }
            Err(e) => panic!("{e:?}"),
        }
    }
    let read = r.st.shards[0].stats.read_blocks - b0;
    assert!(
        read <= once,
        "{read} blocks read, one pass reads {once} ({runs} runs)"
    );
}
