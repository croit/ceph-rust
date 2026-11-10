// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Deterministic multi-OSD simulation: N OSDs (PgSet + MemStore), a message bus with per-pair FIFO
//! and random latency, delayed store commits, a miniature mon (epochs, up_thru, pg_temp) and fault
//! injection (kill/restart, partitions). Every message goes through encode + decode.
#![allow(
    clippy::allow_attributes,
    dead_code,
    clippy::large_enum_variant,
    clippy::type_complexity,
    clippy::field_reassign_with_default
)]

pub mod acks;
pub mod classic;
pub mod classic_table;
use denc::types::{
    CollT, Eversion, Ghobject, Hobject, OsdReqId, PgT, ShardId, SnapId, SpgT, UTime,
};
use messages::Segments;
use peering::PgStoreOps;
use peering::synth::SynthMap;
use peering::*;
use pgwire::{MOSDPGCreate2, PastIntervals, PgHistory, PgStat};
use replwire::{ObjectInfo, Transaction, TxnOp};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap};
use std::rc::Rc;

pub const MS: Mono = 1_000_000;
pub const ALL_FEATURES: u64 = u64::MAX;

pub struct Rng(u64);
impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo + 1)
    }
}

enum Ev {
    Deliver {
        to: i32,
        inc: u64,
        from: i32,
        tid: u64,
        ty: u16,
        hv: u16,
        seg: Segments,
        orig: Body,
    },
    Commit {
        osd: i32,
        inc: u64,
        spg: SpgT,
        token: u64,
        txn: StoreTxn,
    },
    MapDeliver {
        osd: i32,
        inc: u64,
        epoch: u32,
    },
    Create2 {
        osd: i32,
        inc: u64,
        msg: MOSDPGCreate2,
    },
    OldMaps {
        osd: i32,
        inc: u64,
        from: u32,
        to: u32,
    },
    MonTick,
    ShardMap {
        osd: i32,
        inc: u64,
        epoch: u32,
    },
    OsdTick {
        osd: i32,
        inc: u64,
    },
    /// The msgr of `osd` reports a fault (`up` false) or READY (`up` true) of its session to `peer`.
    Link {
        osd: i32,
        inc: u64,
        peer: i32,
        up: bool,
    },
}

struct Item {
    at: Mono,
    seq: u64,
    ev: Ev,
}
impl PartialEq for Item {
    fn eq(&self, o: &Self) -> bool {
        (self.at, self.seq) == (o.at, o.seq)
    }
}
impl Eq for Item {}
impl PartialOrd for Item {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Item {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        (self.at, self.seq).cmp(&(o.at, o.seq))
    }
}

pub struct Node {
    pub set: PgSet,
    pub store: MemStore,
    /// `Sim::read_after_queue`: what survives a kill (txns applied at commit); `store` then shows queued txns at once.
    pub durable: Option<MemStore>,
    pub alive: bool,
    pub inc: u64,
    last_commit: Mono,
    pub cfg: Config,
    /// Sim time at which this process clock read 0 (`Sim::fresh_clocks`: a restart starts a new monotonic clock, like a real
    /// process; otherwise every node shares the sim clock).
    pub boot: Mono,
}

impl Node {
    /// This process's monotonic clock at sim time `now`.
    pub fn clock(&self, now: Mono) -> Mono {
        now - self.boot
    }
}

#[derive(Default, Debug)]
pub struct Stats {
    pub msgs: u64,
    pub msgs_by_type: BTreeMap<u16, u64>,
    pub dropped_partition: u64,
    pub roundtrip_mismatch: Vec<String>,
    pub pg_created: u64,
    pub pg_temp_dropped: u64,
    /// pg_temp requests that reached the mon (`Action::PgTemp` not dropped), every pg.
    pub pg_temp_sent: u64,
    /// The OSDs whose pg_temp requests were dropped, in order.
    pub pg_temp_dropped_from: Vec<i32>,
    /// pg_temp requests decided by the periodic tick (`PgSet::tick`) instead of the event that changed the PG.
    pub pg_temp_from_tick: u64,
    pub readable_changes: u64,
}

pub struct Sim {
    pub now: Mono,
    seq: u64,
    pub rng: Rng,
    pub maps: Vec<Rc<SynthMap>>, // index = epoch - 1
    pub nodes: BTreeMap<i32, Node>,
    heap: BinaryHeap<Reverse<Item>>,
    pair_last: HashMap<(i32, i32), Mono>,
    pub up_thru_req: BTreeMap<i32, u32>,
    pub temp_req: BTreeMap<PgT, Vec<i32>>,
    /// Test hook: drop the next N pg_temp CLEAR requests (empty want) before the mon sees them (lost with the mon session:
    /// the test then calls [`Sim::mon_session`] for the sender).
    pub drop_empty_temp: u32,
    /// Percent of peer messages that are delivered a second time later (replay of a session that was reset: duplicates, possibly
    /// after newer messages).
    pub dup_percent: u64,
    /// Test hook: profile map and sub-chunk count `create_pool_ec` uses instead of isa reed_sol_van (clay, lrc, ...).
    pub ec_profile: Option<(BTreeMap<String, String>, u32)>,
    /// Which messages may be duplicated: 0 = all, 1 = peering (query/notify/info/log/lease) only, 2 = replication (repop/push/pull/scrub) only.
    pub dup_kind: u8,
    pub blocked: BTreeSet<(i32, i32)>,
    held: Vec<(i32, i32, Ev)>,
    pub block_all_from: BTreeSet<i32>,
    pub acked: Vec<(SpgT, u64, Eversion)>,
    pub failed: Vec<(SpgT, u64, Eversion)>,
    /// `(osd, incarnation, pg, tid)` of every finished write (tids restart with a PG instance).
    pub acked_full: Vec<(i32, u64, SpgT, u64)>,
    pub failed_full: Vec<(i32, u64, SpgT, u64)>,
    pub removed: Vec<(i32, SpgT)>,
    /// `Action::Fatal`s: the OSD was killed right there (fail-stop, adr 0066); the test restarts it.
    pub fatals: Vec<(i32, SpgT, &'static str)>,
    /// `(peer, its shard, tid)` of the sub-writes primaries aborted unanswered (`Action::SubWritesAborted`).
    pub subwrites_aborted: Vec<(i32, SpgT, u64)>,
    /// `(osd, answer)` of every deferred `mark_unfound_lost` (`Action::LostMarked`).
    pub lost_done: Vec<(i32, peering::LostDone)>,
    /// Extra commit latency of a PG removal txn (`StoreOp::RemovePg`): the PG stays in its delete for this long, other
    /// txns of the OSD do not queue behind it.
    pub remove_commit_delay: Mono,
    /// `(osd, pg, until)`: every txn of that PG copy queued while set commits only after `until` (in order; visible
    /// then too unless `read_after_queue`); other PGs of the OSD do not wait. Models storeadapt's `deferred` queue (a
    /// re-created PG whose old copy's deletion waits for space, OQ 127).
    pub pg_commit_hold: Option<(i32, SpgT, Mono)>,
    held_last: Mono,
    pub pgstats: BTreeMap<SpgT, (i32, PgStat)>,
    pub stats: Stats,
    pub max_latency: Mono,
    pub log: Vec<String>,
    pub verbose: bool,
    /// Store model of the real OSD (storeadapt: a queued txn is visible to reads at once, durable at commit; a kill
    /// loses what was not durable). Default off: visible only at commit (the stricter model most tests were written for).
    /// Set before `add_osd`.
    pub read_after_queue: bool,
    pub dump_lines: usize,
    pub last_version: Eversion,
    pub capture: bool,
    pub captured: Vec<(i32, i32, Body)>,
    pub request_map: u64,
    /// NeedOldMaps requests served / maps at or below this epoch are "trimmed from disk" (answered empty).
    pub old_map_reqs: u64,
    pub maps_gone_below: u32,
    /// OSDs whose map deliveries are held back (a lagging OSD) until [`Sim::release_maps`].
    pub hold_maps: BTreeSet<i32>,
    held_maps: Vec<(i32, u64, u32)>,
    pub submitted: Vec<(SpgT, u64, Eversion)>,
    pending_spg: Option<SpgT>,
    /// MOSDPGReadyToMerge the mon has not processed yet, with the sender.
    pub merge_reports: Vec<(i32, MergeReport)>,
    /// Every report ever sent (osd, report).
    pub merge_report_log: Vec<(i32, MergeReport)>,
    /// Mon behaviour: act on ReadyToMerge (tests that want a stuck merge turn it off).
    pub mon_merges: bool,
    /// Snap trimmer kicks the driver (a test engine) has not served yet.
    pub trim_kicks: BTreeSet<(i32, SpgT)>,
    /// Executable model of classic ceph-osd peers (checks every delivery), see `classic.rs`.
    pub classic: Option<classic::Classic>,
    /// Lost-message injection (adr 0071): the next message `(from, to, type)` is dropped; with `drop_faults` both ends
    /// see a session fault 1 ms later and READY again 5 ms later (otherwise the loss is silent).
    pub drop_next: Vec<(i32, i32, u16)>,
    pub drop_faults: bool,
    pub dropped_lost: u64,
    /// OSDs that are up in the map but unreachable: every message to them is lost and the sender's msgr reports a
    /// fault `dial_timeout` later (one dial at a time per pair).
    pub unreachable: BTreeSet<i32>,
    pub dial_timeout: Mono,
    dialing: BTreeSet<(i32, i32)>,
    /// Messages sent per `(from, to, type)`.
    pub sent: BTreeMap<(i32, i32, u16), u64>,
    /// A restarted process gets a fresh monotonic clock starting at 1 s (real OSDs: mono = time since process start).
    pub fresh_clocks: bool,
    /// Replica ack invariants (`acks.rs`); a violation fails the test when the `Sim` is dropped.
    pub acks: acks::Acks,
}

impl Drop for Sim {
    fn drop(&mut self) {
        if !std::thread::panicking() && !self.acks.violations.is_empty() {
            panic!(
                "replica ack invariants violated ({} of {} acks): {:#?}",
                self.acks.violations.len(),
                self.acks.acks,
                self.acks.violations
            );
        }
    }
}

/// One store op of [`Sim::write_ops`].
#[derive(Debug, Clone)]
pub enum EcOp {
    Touch,
    Write(u64, Vec<u8>),
    Zero(u64, u64),
    Trunc(u64),
    Remove,
    Attr(&'static str, Vec<u8>),
    OmapSet(Vec<(Vec<u8>, Vec<u8>)>),
    OmapRmRange(Vec<u8>, Vec<u8>),
}

pub fn spg(pool: u64, seed: u32) -> SpgT {
    SpgT {
        pgid: PgT::new(pool, seed),
        shard: ShardId::NO_SHARD,
    }
}

pub fn hobj(pool: u64, name: &str) -> Hobject {
    let mut h = 0u32;
    for b in name.bytes() {
        h = h.wrapping_mul(31).wrapping_add(b as u32);
    }
    Hobject::new(name.as_bytes(), SnapId::NOSNAP, h, pool as i64, b"")
}

impl Sim {
    pub fn new(seed: u64) -> Self {
        let mut s = Sim {
            now: 1_000_000_000,
            seq: 0,
            rng: Rng::new(seed),
            maps: vec![Rc::new(SynthMap::new(1))],
            nodes: BTreeMap::new(),
            heap: BinaryHeap::new(),
            pair_last: HashMap::new(),
            up_thru_req: BTreeMap::new(),
            temp_req: BTreeMap::new(),
            drop_empty_temp: 0,
            dup_percent: 0,
            ec_profile: None,
            dup_kind: 0,
            blocked: BTreeSet::new(),
            held: vec![],
            block_all_from: BTreeSet::new(),
            acked: vec![],
            failed: vec![],
            acked_full: vec![],
            failed_full: vec![],
            removed: vec![],
            fatals: vec![],
            subwrites_aborted: vec![],
            lost_done: vec![],
            remove_commit_delay: 0,
            pg_commit_hold: None,
            held_last: 0,
            pgstats: BTreeMap::new(),
            stats: Stats::default(),
            max_latency: 2 * MS,
            log: vec![],
            verbose: false,
            read_after_queue: false,
            dump_lines: std::env::var("DUMP_LINES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(40),
            last_version: Eversion::default(),
            capture: false,
            captured: vec![],
            request_map: 0,
            old_map_reqs: 0,
            maps_gone_below: 0,
            hold_maps: BTreeSet::new(),
            held_maps: Vec::new(),
            submitted: vec![],
            pending_spg: None,
            merge_reports: vec![],
            merge_report_log: vec![],
            mon_merges: true,
            trim_kicks: BTreeSet::new(),
            classic: Some(classic::Classic::new()),
            drop_next: vec![],
            drop_faults: false,
            dropped_lost: 0,
            unreachable: BTreeSet::new(),
            dial_timeout: 3_000 * MS,
            dialing: BTreeSet::new(),
            sent: BTreeMap::new(),
            fresh_clocks: false,
            acks: Default::default(),
        };
        s.schedule_abs(s.now + 20 * MS, Ev::MonTick);
        s
    }

    pub fn epoch(&self) -> u32 {
        self.maps.len() as u32
    }
    pub fn map(&self) -> Rc<SynthMap> {
        self.maps.last().unwrap().clone()
    }
    pub fn map_at(&self, e: u32) -> Rc<SynthMap> {
        self.maps[e as usize - 1].clone()
    }

    fn schedule_abs(&mut self, at: Mono, ev: Ev) {
        self.seq += 1;
        self.heap.push(Reverse(Item {
            at,
            seq: self.seq,
            ev,
        }));
    }

    // ---- cluster setup -----------------------------------------------------------------------------------

    pub fn add_osd(&mut self, osd: i32) {
        self.add_osd_cfg(osd, |_| {});
    }
    pub fn add_osd_cfg(&mut self, osd: i32, f: impl FnOnce(&mut Config)) {
        let mut cfg = Config::new(osd);
        f(&mut cfg);
        let node = Node {
            set: PgSet::new(cfg.clone()),
            store: MemStore::new(),
            durable: self.read_after_queue.then(MemStore::new),
            alive: true,
            inc: 1,
            last_commit: 0,
            cfg,
            boot: 0,
        };
        self.nodes.insert(osd, node);
        self.classic_tell_peers();
        // the OSD learns the whole map history, then boots
        for e in 1..=self.epoch() {
            let m = self.map_at(e);
            self.nodes.get_mut(&osd).unwrap().set.add_map(m);
        }
        self.new_epoch(|m| {
            m.osds.insert(
                osd,
                peering::synth::SOsd {
                    exists: true,
                    up: true,
                    in_: true,
                    up_from: 0,
                    up_thru: 0,
                    lost_at: 0,
                    dead_epoch: 0,
                    full: false,
                },
            );
            let e = m.epoch;
            m.osds.get_mut(&osd).unwrap().up_from = e;
        });
        let inc = self.nodes[&osd].inc;
        self.schedule_abs(self.now + 100 * MS, Ev::OsdTick { osd, inc });
    }

    pub fn new_epoch(&mut self, f: impl FnOnce(&mut SynthMap)) -> u32 {
        let mut m = (*self.map()).clone();
        m.epoch += 1;
        f(&mut m);
        let e = m.epoch;
        {
            let desc: Vec<String> = m
                .osds
                .iter()
                .map(|(o, x)| {
                    format!(
                        "{o}:{}{}t{}",
                        if x.up { "up" } else { "dn" },
                        if x.in_ { "" } else { "-out" },
                        x.up_thru
                    )
                })
                .collect();
            let temp: Vec<String> = m
                .pg_temp
                .iter()
                .map(|(p, v)| format!("{p}={v:?}"))
                .collect();
            self.trace(format!("EPOCH {e} {desc:?} temp={temp:?}"));
        }
        self.maps.push(Rc::new(m));
        let osds: Vec<(i32, u64)> = self
            .nodes
            .iter()
            .filter(|(_, n)| n.alive)
            .map(|(o, n)| (*o, n.inc))
            .collect();
        for (osd, inc) in osds {
            if self.hold_maps.contains(&osd) {
                self.held_maps.push((osd, inc, e));
                continue;
            }
            let lat = self.rng.range(0, 3 * MS);
            let at = self.ordered(-1, osd, lat);
            self.schedule_abs(at, Ev::MapDeliver { osd, inc, epoch: e });
        }
        e
    }

    /// The lagging `osd` gets the maps it missed, in order.
    pub fn release_maps(&mut self, osd: i32) {
        self.hold_maps.remove(&osd);
        let held = std::mem::take(&mut self.held_maps);
        for (o, inc, epoch) in held {
            if o != osd {
                self.held_maps.push((o, inc, epoch));
                continue;
            }
            let lat = self.rng.range(0, 3 * MS);
            let at = self.ordered(-1, osd, lat);
            self.schedule_abs(at, Ev::MapDeliver { osd, inc, epoch });
        }
    }

    /// Create a pool and have the mon ask the primaries to create its PGs.
    pub fn create_pool(&mut self, pool: u64, size: u32, min_size: u32, pg_num: u32) {
        self.create_pool_lat(pool, size, min_size, pg_num, 5 * MS);
    }

    /// [`Self::create_pool`] with the MOSDPGCreate2 delivered `lat` after the map (0: before most OSDs have it).
    pub fn create_pool_lat(&mut self, pool: u64, size: u32, min_size: u32, pg_num: u32, lat: Mono) {
        let e = self.new_epoch(|m| {
            m.pools.insert(
                pool,
                pgwire::PoolParams {
                    size,
                    min_size,
                    pg_num,
                    pg_num_pending: pg_num,
                    ..Default::default()
                },
            );
        });
        let map = self.map_at(e);
        let mut per_osd: BTreeMap<i32, MOSDPGCreate2> = BTreeMap::new();
        for seed in 0..pg_num {
            let pg = PgT::new(pool, seed);
            let mp = peering::PgMapView::pg_mapping(&*map, pg);
            if mp.acting_primary < 0 {
                continue;
            }
            let s = SpgT {
                pgid: pg,
                shard: ShardId::NO_SHARD,
            };
            let m = per_osd
                .entry(mp.acting_primary)
                .or_insert_with(|| MOSDPGCreate2 {
                    epoch: e,
                    ..Default::default()
                });
            m.pgs.insert(s, (e, UTime::new(1, 0)));
            m.pg_extra.insert(
                s,
                (
                    PgHistory::new_pg(e, UTime::new(1, 0)),
                    PastIntervals::default(),
                ),
            );
        }
        for (osd, msg) in per_osd {
            let inc = self.nodes[&osd].inc;
            self.schedule_abs(self.now + lat, Ev::Create2 { osd, inc, msg });
        }
    }

    /// Address of the PG instance that leads `pool.seed` now (EC: the primary's shard = its acting position).
    pub fn lead_spg(&self, pool: u64, seed: u32) -> SpgT {
        let map = self.map();
        let pgid = PgT::new(pool, seed);
        let mp = peering::PgMapView::pg_mapping(&*map, pgid);
        let is_ec = map.pools.get(&pool).is_some_and(|p| p.is_erasure);
        let shard = if is_ec {
            mp.acting
                .iter()
                .position(|o| *o == mp.acting_primary)
                .map_or(ShardId::NO_SHARD, |i| ShardId(i as i8))
        } else {
            ShardId::NO_SHARD
        };
        SpgT { pgid, shard }
    }

    /// Address of the PG instance `osd` holds for `pool.seed` (acting position for EC).
    pub fn spg_on(&self, osd: i32, pool: u64, seed: u32) -> SpgT {
        let map = self.map();
        let pgid = PgT::new(pool, seed);
        let mp = peering::PgMapView::pg_mapping(&*map, pgid);
        let is_ec = map.pools.get(&pool).is_some_and(|p| p.is_erasure);
        let shard = if is_ec {
            mp.acting
                .iter()
                .position(|o| *o == osd)
                .map_or(ShardId::NO_SHARD, |i| ShardId(i as i8))
        } else {
            ShardId::NO_SHARD
        };
        SpgT { pgid, shard }
    }

    /// Optimized EC pool (`allow_ec_optimizations`, mode O): like [`Self::create_pool_ec`], nonprimary = raw 1..k-1.
    pub fn create_pool_ec_opt(
        &mut self,
        pool: u64,
        k: u32,
        m: u32,
        chunk: u32,
        overwrites: bool,
        pg_num: u32,
    ) {
        self.create_pool_ec_mode(pool, k, m, chunk, overwrites, pg_num, true)
    }

    /// EC pool `k+m` (isa reed_sol_van), chunk `chunk` bytes, `min_size = k+1` (k when m == 1).
    pub fn create_pool_ec(
        &mut self,
        pool: u64,
        k: u32,
        m: u32,
        chunk: u32,
        overwrites: bool,
        pg_num: u32,
    ) {
        self.create_pool_ec_mode(pool, k, m, chunk, overwrites, pg_num, false)
    }

    #[allow(clippy::too_many_arguments)]
    fn create_pool_ec_mode(
        &mut self,
        pool: u64,
        k: u32,
        m: u32,
        chunk: u32,
        overwrites: bool,
        pg_num: u32,
        opt: bool,
    ) {
        let size = k + m;
        let min_size = if m >= 2 { k + 1 } else { k };
        let prof = self.ec_profile.clone();
        let e = self.new_epoch(|mp| {
            mp.pools.insert(
                pool,
                pgwire::PoolParams {
                    size,
                    min_size,
                    pg_num,
                    pg_num_pending: pg_num,
                    is_erasure: true,
                    ec_k: k,
                    ec_optimizations: opt,
                    ec: Some(std::sync::Arc::new(pgwire::EcPoolInfo {
                        k,
                        m,
                        stripe_width: k * chunk,
                        chunk_size: chunk,
                        overwrites,
                        supported: true,
                        reason: String::new(),
                        plugin: prof
                            .as_ref()
                            .map_or("isa".into(), |p| p.0["plugin"].clone()),
                        technique: prof.as_ref().map_or("reed_sol_van".into(), |p| {
                            p.0.get("technique").cloned().unwrap_or_default()
                        }),
                        profile: prof.as_ref().map(|p| p.0.clone()).unwrap_or_default(),
                        sub_chunks: prof.as_ref().map_or(1, |p| p.1),
                        chunk_mapping: (0..size).collect(),
                        optimized: opt,
                        nonprimary: if opt { (1..k).collect() } else { Vec::new() },
                        omap: opt,
                        ..Default::default()
                    })),
                    ..Default::default()
                },
            );
        });
        let map = self.map_at(e);
        let mut per_osd: BTreeMap<i32, MOSDPGCreate2> = BTreeMap::new();
        for seed in 0..pg_num {
            let pg = PgT::new(pool, seed);
            let mp = peering::PgMapView::pg_mapping(&*map, pg);
            if mp.acting_primary < 0 {
                continue;
            }
            let shard = mp
                .acting
                .iter()
                .position(|o| *o == mp.acting_primary)
                .map_or(ShardId::NO_SHARD, |i| ShardId(i as i8));
            let s = SpgT { pgid: pg, shard };
            let m = per_osd
                .entry(mp.acting_primary)
                .or_insert_with(|| MOSDPGCreate2 {
                    epoch: e,
                    ..Default::default()
                });
            m.pgs.insert(s, (e, UTime::new(1, 0)));
            m.pg_extra.insert(
                s,
                (
                    PgHistory::new_pg(e, UTime::new(1, 0)),
                    PastIntervals::default(),
                ),
            );
        }
        for (osd, msg) in per_osd {
            let inc = self.nodes[&osd].inc;
            self.schedule_abs(self.now + 5 * MS, Ev::Create2 { osd, inc, msg });
        }
    }

    pub fn mark_down(&mut self, osd: i32) {
        self.new_epoch(|m| {
            m.osds.get_mut(&osd).unwrap().up = false;
        });
    }
    pub fn mark_up(&mut self, osd: i32) {
        self.new_epoch(|m| {
            let e = m.epoch;
            let o = m.osds.get_mut(&osd).unwrap();
            o.up = true;
            o.up_from = e;
        });
    }
    pub fn mark_out(&mut self, osd: i32) {
        self.new_epoch(|m| m.osds.get_mut(&osd).unwrap().in_ = false);
    }
    pub fn mark_in(&mut self, osd: i32) {
        self.new_epoch(|m| m.osds.get_mut(&osd).unwrap().in_ = true);
    }
    pub fn set_up_override(&mut self, pg: PgT, up: Vec<i32>) {
        self.new_epoch(|m| {
            m.up_override.insert(pg, up);
        });
    }
    pub fn clear_up_override(&mut self, pg: PgT) {
        self.new_epoch(|m| {
            m.up_override.remove(&pg);
        });
    }

    // ---- pg_num changes (mon / mgr side of split-merge.md 2.1) -----------------------------------------------

    /// One map: pool pg_num := n (split when larger). pgp_num stays, so children keep the parent's placement.
    pub fn set_pg_num(&mut self, pool: u64, n: u32) -> u32 {
        self.new_epoch(|m| {
            let old = m.pools[&pool].pg_num;
            m.pgp.entry(pool).or_insert(old);
            let p = m.pools.get_mut(&pool).unwrap();
            p.pg_num = n;
            p.pg_num_pending = n;
        })
    }
    pub fn set_pgp_num(&mut self, pool: u64, n: u32) -> u32 {
        self.new_epoch(|m| {
            m.pgp.insert(pool, n);
        })
    }
    /// Prepare a merge: pg_num_pending := pg_num - 1 (pgp_num must be <= that already).
    pub fn begin_merge(&mut self, pool: u64) -> u32 {
        self.new_epoch(|m| {
            let p = m.pools.get_mut(&pool).unwrap();
            p.pg_num_pending = p.pg_num - 1;
        })
    }
    pub fn pool_pg_num(&self, pool: u64) -> u32 {
        self.map().pools[&pool].pg_num
    }
    /// PG seed of an object name at the current pg_num.
    pub fn named_seed(&self, pool: u64, name: &str) -> u32 {
        pgwire::pgmath::object_pg(hobj(pool, name).hash, self.pool_pg_num(pool))
    }
    pub fn write_named(&mut self, pool: u64, name: &str, data: &[u8]) -> Result<u64, WriteErr> {
        let seed = self.named_seed(pool, name);
        self.write_obj(pool, seed, name, data)
    }

    /// Every object of `expect` is stored, with its data, on every acting member of the PG it hashes to; every
    /// stored non-temp object of every PG copy (seed < pg_num) hashes to its PG; no stray extra objects on the
    /// acting members.
    pub fn assert_layout(&self, pool: u64, expect: &BTreeMap<String, Vec<u8>>) {
        let n = self.pool_pg_num(pool);
        for seed in 0..n {
            let want: BTreeMap<String, Vec<u8>> = expect
                .iter()
                .filter(|(k, _)| self.named_seed(pool, k) == seed)
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            self.assert_replicas_equal(pool, seed, &want);
        }
        for (o, node) in &self.nodes {
            for (k, mp) in &node.store.pgs {
                if k.pgid.pool != pool || k.pgid.seed >= n {
                    continue;
                }
                for h in mp.objects.keys().filter(|h| !h.is_temp()) {
                    assert_eq!(
                        pgwire::pgmath::object_pg(h.hash, n),
                        k.pgid.seed,
                        "osd.{o} pg {k} holds foreign object {}\n{}",
                        String::from_utf8_lossy(&h.oid),
                        self.dump()
                    );
                }
            }
        }
    }

    /// Every PG of the pool is clean+active on its primary, none is left over beyond pg_num on a live node.
    pub fn pool_settled(&self, pool: u64) -> bool {
        let n = self.pool_pg_num(pool);
        if !self.pool_clean(pool) {
            return false;
        }
        self.nodes.values().filter(|x| x.alive).all(|x| {
            x.set
                .pgs()
                .all(|(k, _)| k.pgid.pool != pool || k.pgid.seed < n)
        })
    }

    /// Call into one node's `PgSet` (admin / mgr style entry points) and dispatch its actions.
    pub fn call(&mut self, osd: i32, f: impl FnOnce(&mut PgSet, Mono, &MemStore) -> Vec<Action>) {
        let now = self.now;
        let n = self.nodes.get_mut(&osd).expect("node");
        let acts = f(&mut n.set, now - n.boot, &n.store);
        self.dispatch(osd, acts);
    }

    /// kill -9: lose uncommitted transactions and in-flight messages.
    /// Deliver a hand-made message (goes through encode + decode).
    pub fn inject(&mut self, from: i32, to: i32, body: Body) {
        let (ty, hv, _hc, seg) = body.encode(ALL_FEATURES).expect("encode");
        let inc = self.nodes[&to].inc;
        let lat = self.rng.range(100_000, self.max_latency);
        let at = self.ordered(from, to, lat);
        self.schedule_abs(
            at,
            Ev::Deliver {
                to,
                inc,
                from,
                tid: 0,
                ty,
                hv,
                seg,
                orig: body,
            },
        );
    }

    pub fn trace(&mut self, s: String) {
        let t = format!("{:>7}ms {}", self.now / MS, s);
        self.log.push(t);
    }

    pub fn kill(&mut self, osd: i32) {
        self.trace(format!("KILL osd.{osd}"));
        self.held.retain(|h| h.0 != osd);
        let n = self.nodes.get_mut(&osd).unwrap();
        n.alive = false;
        n.inc += 1;
        if let Some(d) = &n.durable {
            n.store = d.clone();
        }
        // residency leases are process memory (adr 0043 am. 18)
        let pgs: Vec<SpgT> = n.store.pgs.keys().copied().collect();
        for spg in pgs {
            n.store.lease_release_pg(spg);
        }
        self.mark_down(osd);
    }

    /// Process restart: fresh PgSet over the surviving store, then boot at the mon.
    pub fn restart(&mut self, osd: i32) {
        self.restart_maps(osd, |_| true);
    }

    /// [`Self::restart`] with only the stored maps `keep` says yes to (holes in the persisted map history).
    pub fn restart_maps(&mut self, osd: i32, keep: impl Fn(u32) -> bool) {
        self.trace(format!("RESTART osd.{osd}"));
        let cfg = self.nodes[&osd].cfg.clone();
        let maps: Vec<_> = (1..=self.epoch())
            .filter(|e| keep(*e))
            .map(|e| self.map_at(e))
            .collect();
        let now = self.now;
        let fresh = self.fresh_clocks;
        {
            let n = self.nodes.get_mut(&osd).unwrap();
            n.set = PgSet::new(cfg);
            n.alive = true;
            n.inc += 1;
            n.last_commit = 0;
            if fresh {
                n.boot = now - SEC;
            }
            for m in maps {
                n.set.add_map(m);
            }
        }
        let acts = {
            let n = self.nodes.get_mut(&osd).unwrap();
            n.set.load_pgs(n.clock(now), &n.store)
        };
        self.classic_on_restart(osd);
        self.classic_tell_peers();
        self.dispatch(osd, acts);
        let inc = self.nodes[&osd].inc;
        self.schedule_abs(self.now + 100 * MS, Ev::OsdTick { osd, inc });
        self.mark_up(osd);
    }

    /// New mon session of `osd` (the old one reset, with whatever it still had to send): it re-sends its pending mon
    /// requests (up_thru, pg_temp, merge reports).
    pub fn mon_session(&mut self, osd: i32) {
        self.trace(format!("MON SESSION osd.{osd}"));
        let acts = match self.nodes.get_mut(&osd) {
            Some(n) if n.alive => n.set.resend_mon_requests(),
            _ => return,
        };
        self.dispatch(osd, acts);
    }

    /// `osd`'s cluster session to `peer` reaches READY (`up`) or faults, now.
    pub fn link_now(&mut self, osd: i32, peer: i32, up: bool) {
        let now = self.now;
        let acts = match self.nodes.get_mut(&osd) {
            Some(n) if n.alive && up => n.set.peer_connected(peer, n.clock(now), &n.store),
            Some(n) if n.alive => n.set.peer_fault(peer, n.clock(now), &n.store),
            _ => return,
        };
        self.dispatch(osd, acts);
    }

    pub fn partition(&mut self, a: i32, b: i32) {
        self.trace(format!("PARTITION {a}<->{b}"));
        self.blocked.insert((a, b));
        self.blocked.insert((b, a));
    }
    pub fn heal(&mut self) {
        self.trace("HEAL".into());
        self.blocked.clear();
        self.block_all_from.clear();
        let held = std::mem::take(&mut self.held);
        self.release_held(held);
    }
    /// Heal the partition of `a` and `b` only: their held messages arrive (in order), other partitions stay.
    pub fn heal_link(&mut self, a: i32, b: i32) {
        self.trace(format!("HEAL {a}<->{b}"));
        self.blocked.remove(&(a, b));
        self.blocked.remove(&(b, a));
        let (go, keep) = std::mem::take(&mut self.held)
            .into_iter()
            .partition(|(f, t, _)| (*f, *t) == (a, b) || (*f, *t) == (b, a));
        self.held = keep;
        self.release_held(go);
    }
    fn release_held(&mut self, held: Vec<(i32, i32, Ev)>) {
        for (from, to, ev) in held {
            let lat = self.rng.range(100_000, self.max_latency);
            let at = self.ordered(from, to, lat);
            self.schedule_abs(at, ev);
        }
    }

    // ---- event plumbing ------------------------------------------------------------------------------------

    /// FIFO per directed pair with random latency.
    fn ordered(&mut self, from: i32, to: i32, lat: Mono) -> Mono {
        let last = self.pair_last.get(&(from, to)).copied().unwrap_or(0);
        let at = (self.now + lat).max(last + 1);
        self.pair_last.insert((from, to), at);
        at
    }

    pub fn dispatch(&mut self, osd: i32, acts: Vec<Action>) {
        self.classic_scan(osd);
        if let Some(n) = self.nodes.get_mut(&osd) {
            for t in n.set.take_trace() {
                self.log
                    .push(format!("{:>7}ms osd.{osd} {t}", self.now / MS));
            }
        }
        for a in acts {
            match a {
                Action::Send(s) => {
                    // instances of one OSD talk through the PgSet loopback (adr 0049 am. 1), never the messenger
                    assert_ne!(s.to, osd, "PG message to its own OSD left the PgSet: {s:?}");
                    self.acks_send(osd, &s);
                    self.classic_observe_send(osd, &s);
                    if self.classic_hold_send(osd, &s) {
                        continue;
                    }
                    let (ty, hv, _hc, seg) = s.body.encode(ALL_FEATURES).expect("encode");
                    self.stats.msgs += 1;
                    if self.capture {
                        self.captured.push((osd, s.to, s.body.clone()));
                    }
                    *self.stats.msgs_by_type.entry(ty).or_default() += 1;
                    *self.sent.entry((osd, s.to, ty)).or_default() += 1;
                    if self.unreachable.contains(&s.to) {
                        self.dropped_lost += 1;
                        if self.dialing.insert((osd, s.to)) {
                            let inc = self.nodes[&osd].inc;
                            let at = self.now + self.dial_timeout;
                            self.schedule_abs(
                                at,
                                Ev::Link {
                                    osd,
                                    inc,
                                    peer: s.to,
                                    up: false,
                                },
                            );
                        }
                        continue;
                    }
                    if let Some(i) = self.drop_next.iter().position(|d| *d == (osd, s.to, ty)) {
                        self.drop_next.remove(i);
                        self.dropped_lost += 1;
                        self.trace(format!("LOST osd.{osd}->osd.{} type {ty}", s.to));
                        if self.drop_faults {
                            for (a, b) in [(osd, s.to), (s.to, osd)] {
                                let Some(inc) = self.nodes.get(&a).map(|n| n.inc) else {
                                    continue;
                                };
                                for (dt, up) in [(MS, false), (5 * MS, true)] {
                                    let at = self.now + dt;
                                    self.schedule_abs(
                                        at,
                                        Ev::Link {
                                            osd: a,
                                            inc,
                                            peer: b,
                                            up,
                                        },
                                    );
                                }
                            }
                        }
                        continue;
                    }
                    if self.block_all_from.contains(&osd) {
                        self.stats.dropped_partition += 1;
                        continue;
                    }
                    let Some(dest) = self.nodes.get(&s.to) else {
                        continue;
                    };
                    if !dest.alive {
                        continue;
                    }
                    let inc = dest.inc;
                    let kind_ok = matches!(
                        (&s.body, self.dup_kind),
                        (_, 0) | (Body::Peering(_), 1) | (Body::Repl(_), 2)
                    );
                    let kind_ok = kind_ok
                        && std::env::var("CHAOS_DUP_TY")
                            .map(|t| format!("{:?}", s.body).contains(&t))
                            .unwrap_or(true);
                    let dup = (kind_ok
                        && self.dup_percent > 0
                        && self.rng.range(0, 99) < self.dup_percent)
                        .then(|| (seg.clone(), s.body.clone()));
                    let ev = Ev::Deliver {
                        to: s.to,
                        inc,
                        from: osd,
                        tid: s.tid,
                        ty,
                        hv,
                        seg,
                        orig: s.body,
                    };
                    if self.blocked.contains(&(osd, s.to)) {
                        // lossless connection: the bytes arrive after the partition heals
                        self.held.push((osd, s.to, ev));
                        continue;
                    }
                    let lat = self.rng.range(100_000, self.max_latency);
                    let at = self.ordered(osd, s.to, lat);
                    self.schedule_abs(at, ev);
                    if let Some((seg2, body2)) = dup {
                        let lat = self.rng.range(100_000, self.max_latency * 8);
                        self.schedule_abs(
                            at + lat,
                            Ev::Deliver {
                                to: s.to,
                                inc,
                                from: osd,
                                tid: s.tid,
                                ty,
                                hv,
                                seg: seg2,
                                orig: body2,
                            },
                        );
                    }
                }
                Action::Persist { spg, token, txn } => {
                    let lat = self.rng.range(50_000, 800_000);
                    let remove = self.remove_commit_delay > 0
                        && txn.ops.iter().any(|o| matches!(o, StoreOp::RemovePg));
                    let held = match self.pg_commit_hold {
                        Some((o, p, until)) if o == osd && p == spg => {
                            let at = (until.max(self.now) + lat).max(self.held_last + 1);
                            self.held_last = at;
                            Some(at)
                        }
                        _ => None,
                    };
                    let n = self.nodes.get_mut(&osd).unwrap();
                    if n.durable.is_some() {
                        n.store.submit(spg, &txn);
                    }
                    let at = if let Some(at) = held {
                        at
                    } else if remove {
                        self.now + lat + self.remove_commit_delay
                    } else {
                        let at = (self.now + lat).max(n.last_commit + 1);
                        n.last_commit = at;
                        at
                    };
                    let inc = n.inc;
                    self.schedule_abs(
                        at,
                        Ev::Commit {
                            osd,
                            inc,
                            spg,
                            token,
                            txn,
                        },
                    );
                }
                Action::NeedUpThru { want } => {
                    let e = self.up_thru_req.entry(osd).or_insert(0);
                    *e = (*e).max(want);
                }
                Action::PgTemp { pgid, want } => {
                    if want.is_empty() && self.drop_empty_temp > 0 {
                        self.drop_empty_temp -= 1;
                        self.stats.pg_temp_dropped += 1;
                        self.stats.pg_temp_dropped_from.push(osd);
                    } else {
                        self.stats.pg_temp_sent += 1;
                        self.temp_req.insert(pgid, want);
                    }
                }
                Action::PgCreated { .. } => self.stats.pg_created += 1,
                Action::PgStats { spg, stat } => {
                    self.pgstats.insert(spg, (osd, *stat));
                }
                Action::RequestMap { .. } => self.request_map += 1,
                Action::NeedOldMaps { from, to } => {
                    self.old_map_reqs += 1;
                    let inc = self.nodes[&osd].inc;
                    self.schedule_abs(self.now + 2 * MS, Ev::OldMaps { osd, inc, from, to });
                }
                Action::WriteDone {
                    spg,
                    tid,
                    version,
                    result,
                } => {
                    self.trace(format!(
                        "WRITEDONE osd.{osd} {spg} tid {tid} v{version} r{result}"
                    ));
                    let inc = self.nodes.get(&osd).map_or(0, |n| n.inc);
                    if result == 0 {
                        self.acked_full.push((osd, inc, spg, tid));
                    } else {
                        self.failed_full.push((osd, inc, spg, tid));
                    }
                    if result == 0 {
                        self.acked.push((spg, tid, version));
                    } else {
                        self.failed.push((spg, tid, version));
                    }
                }
                Action::ReadableChanged { .. } => self.stats.readable_changes += 1,
                Action::Placement { .. } => {}
                Action::SubWritesAborted { keys, .. } => self.subwrites_aborted.extend(keys),
                Action::PgRemoved { spg } => self.removed.push((osd, spg)),
                Action::ReadyToMerge(r) => {
                    self.merge_reports.push((osd, r));
                    self.merge_report_log.push((osd, r));
                }
                Action::SnapTrimKick { spg } => {
                    self.trim_kicks.insert((osd, spg));
                }
                Action::LostMarked(d) => {
                    self.trace(format!("LOST_MARKED osd.{osd} {}: {:?}", d.spg, d.result));
                    self.lost_done.push((osd, *d));
                }
                Action::Fatal { spg, why } => {
                    // the driver exits: nothing after it in this batch runs
                    self.trace(format!("FATAL osd.{osd} {spg}: {why}"));
                    self.fatals.push((osd, spg, why));
                    self.kill(osd);
                    return;
                }
                Action::Resv(_)
                | Action::Slot(_)
                | Action::SlotReply { .. }
                | Action::Ops(_)
                | Action::OpsReply { .. }
                | Action::Latch { .. } => unreachable!("internal"),
            }
        }
    }

    fn step(&mut self) -> bool {
        let Some(Reverse(item)) = self.heap.pop() else {
            return false;
        };
        self.now = self.now.max(item.at);
        let now = self.now;
        match item.ev {
            Ev::OldMaps { osd, inc, from, to } => {
                let lo = from.max(self.maps_gone_below + 1);
                let maps: Vec<MapHandle> = if lo > to {
                    Vec::new()
                } else {
                    (lo..=to).map(|e| -> MapHandle { self.map_at(e) }).collect()
                };
                if let Some(n) = self.nodes.get_mut(&osd)
                    && n.alive
                    && n.inc == inc
                {
                    let acts = n.set.old_maps(n.clock(now), from, maps, &n.store);
                    self.dispatch(osd, acts);
                }
            }
            Ev::MonTick => {
                // ReadyToMerge (split-merge.md 6.3)
                let reports = std::mem::take(&mut self.merge_reports);
                if self.mon_merges {
                    for (_, r) in reports {
                        let map = self.map();
                        let Some(p) = map.pools.get(&r.source.pool) else {
                            continue;
                        };
                        if p.pg_num != r.source.seed + 1 || p.pg_num_pending > r.source.seed {
                            continue;
                        }
                        self.new_epoch(|m| {
                            let e = m.epoch;
                            let p = m.pools.get_mut(&r.source.pool).unwrap();
                            if r.ready {
                                p.pg_num -= 1;
                                p.pg_num_pending = p.pg_num;
                                p.merge_meta = pgwire::MergeMeta {
                                    source_seed: r.source.seed,
                                    ready_epoch: e,
                                    last_epoch_started: r.last_epoch_started,
                                    last_epoch_clean: r.last_epoch_clean,
                                    source_version: r.source_version,
                                    target_version: r.target_version,
                                };
                            } else {
                                p.pg_num_pending = p.pg_num;
                            }
                        });
                    }
                }
                if !self.up_thru_req.is_empty() || !self.temp_req.is_empty() {
                    let ut = std::mem::take(&mut self.up_thru_req);
                    let tmp = std::mem::take(&mut self.temp_req);
                    self.new_epoch(|m| {
                        let e = m.epoch;
                        for (o, want) in ut {
                            if let Some(x) = m.osds.get_mut(&o)
                                && x.up_thru < want.max(e)
                            {
                                x.up_thru = e;
                            }
                        }
                        for (pg, want) in tmp {
                            if want.is_empty() {
                                m.pg_temp.remove(&pg);
                            } else {
                                m.pg_temp.insert(pg, want);
                            }
                        }
                    });
                }
                self.schedule_abs(now + 20 * MS, Ev::MonTick);
            }
            Ev::OsdTick { osd, inc } => {
                if let Some(n) = self.nodes.get_mut(&osd)
                    && n.alive
                    && n.inc == inc
                {
                    let acts = n.set.tick(n.clock(now), &n.store);
                    self.stats.pg_temp_from_tick += acts
                        .iter()
                        .filter(|a| matches!(a, Action::PgTemp { .. }))
                        .count() as u64;
                    self.dispatch(osd, acts);
                    self.schedule_abs(now + 100 * MS, Ev::OsdTick { osd, inc });
                }
            }
            Ev::Link { osd, inc, peer, up } => {
                if !up {
                    self.dialing.remove(&(osd, peer));
                }
                if let Some(n) = self.nodes.get_mut(&osd)
                    && n.alive
                    && n.inc == inc
                {
                    let acts = if up {
                        n.set.peer_connected(peer, n.clock(now), &n.store)
                    } else {
                        n.set.peer_fault(peer, n.clock(now), &n.store)
                    };
                    self.dispatch(osd, acts);
                }
            }
            Ev::MapDeliver { osd, inc, epoch } => {
                let m = self.map_at(epoch);
                if let Some(n) = self.nodes.get_mut(&osd)
                    && n.alive
                    && n.inc == inc
                {
                    let acts = n.set.handle_map(n.clock(now), m, &n.store);
                    self.classic_on_map(osd, epoch);
                    self.dispatch(osd, acts);
                }
            }
            Ev::ShardMap { osd, inc, epoch } => {
                if self
                    .nodes
                    .get(&osd)
                    .is_some_and(|n| n.alive && n.inc == inc)
                {
                    self.classic_on_shard(osd, epoch);
                }
            }
            Ev::Create2 { osd, inc, msg } => {
                if let Some(n) = self.nodes.get_mut(&osd)
                    && n.alive
                    && n.inc == inc
                {
                    let acts = n.set.handle_create(n.clock(now), msg, &n.store);
                    self.dispatch(osd, acts);
                }
            }
            Ev::Commit {
                osd,
                inc,
                spg,
                token,
                txn,
            } => {
                if self
                    .nodes
                    .get(&osd)
                    .is_some_and(|n| n.alive && n.inc == inc)
                {
                    {
                        if self.verbose {
                            let ops: Vec<String> = txn
                                .ops
                                .iter()
                                .map(|o| match o {
                                    StoreOp::PutInfo(_) => "info".into(),
                                    StoreOp::PutPastIntervals(_) => "past".into(),
                                    StoreOp::LogAppend(v) => format!("append{}", v.len()),
                                    StoreOp::ApplyTxn { .. } => "txn".into(),
                                    StoreOp::Missing(m) => format!("missing{}", m.len()),
                                    other => format!("{:?}", other).chars().take(60).collect(),
                                })
                                .collect();
                            self.log.push(format!(
                                "{}ms osd.{osd} commit {spg} {:?}",
                                now / MS,
                                ops
                            ));
                        }
                        let n = self.nodes.get_mut(&osd).unwrap();
                        match n.durable.as_mut() {
                            Some(d) => d.submit(spg, &txn),
                            None => n.store.submit(spg, &txn),
                        }
                        let acts = n.set.on_commit(n.clock(now), spg, token, &n.store);
                        self.dispatch(osd, acts);
                    }
                }
            }
            Ev::Deliver {
                to,
                inc,
                from,
                tid,
                ty,
                hv,
                seg,
                orig,
            } => {
                let Some(n) = self.nodes.get_mut(&to) else {
                    return true;
                };
                if !(n.alive && n.inc == inc) {
                    return true;
                }
                let body = match Body::decode(ty, hv, &seg) {
                    Ok(Some(b)) => b,
                    other => panic!("decode failed for type {ty}: {other:?}"),
                };
                if body != orig
                    && !(matches!(ty, 118 | 119 | 136)
                        && body.encode(ALL_FEATURES).map(|x| x.3)
                            == orig.encode(ALL_FEATURES).map(|x| x.3))
                {
                    self.stats
                        .roundtrip_mismatch
                        .push(format!("type {ty}: {orig:?} != {body:?}"));
                }
                self.classic_check(to, from, &body);
                self.acks_deliver(to, from, tid, &body);
                let n = self.nodes.get_mut(&to).unwrap();
                let acts = n.set.handle_msg(
                    n.clock(now),
                    Inbound {
                        ingress: Default::default(),
                        from,
                        tid,
                        prio: pgwire::msgs::PRIO_DEFAULT,
                        body: Box::new(body),
                    },
                    &n.store,
                );
                self.dispatch(to, acts);
            }
        }
        true
    }

    pub fn run_for(&mut self, dur: Mono) {
        let end = self.now + dur;
        while let Some(Reverse(top)) = self.heap.peek() {
            if top.at > end {
                break;
            }
            self.step();
        }
        self.now = self.now.max(end);
    }

    /// Run until `pred` holds (checked after every event); panic with `why` on timeout.
    pub fn run_until(&mut self, timeout: Mono, why: &str, pred: impl Fn(&Sim) -> bool) {
        let end = self.now + timeout;
        loop {
            if pred(self) {
                return;
            }
            match self.heap.peek() {
                Some(Reverse(top)) if top.at <= end => {
                    self.step();
                }
                _ => break,
            }
        }
        if pred(self) {
            return;
        }
        panic!("timeout waiting for: {why}\n{}", self.dump());
    }

    // ---- introspection -----------------------------------------------------------------------------------------

    /// `osd`'s own monotonic clock now (see [`Sim::fresh_clocks`]).
    pub fn node_now(&self, osd: i32) -> Mono {
        self.nodes[&osd].clock(self.now)
    }

    /// PGs whose past intervals miss classic's required bounds (`check_past_interval_bounds`, oldest map 1): a non-empty
    /// `[max(lec or epoch_pool_created, 1), max(sis, epoch_pool_created))` must lie inside `[first, last + 1)`.
    pub fn past_bounds_violations(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (osd, n) in &self.nodes {
            if !n.alive {
                continue;
            }
            for (k, pg) in n.set.pgs() {
                let h = &pg.info().history;
                let p = pg.past_intervals();
                let lec = if h.last_epoch_clean != 0 {
                    h.last_epoch_clean
                } else {
                    h.epoch_pool_created
                };
                let (rs, re) = (lec.max(1), h.same_interval_since.max(h.epoch_pool_created));
                if rs >= re {
                    continue;
                }
                let (ps, pe) = p.bounds();
                if p.is_empty() || ps > rs || pe < re {
                    out.push(format!(
                        "osd.{osd} {k}: required [{rs},{re}) past {:?}",
                        (ps, pe)
                    ));
                }
            }
        }
        out
    }

    pub fn pg(&self, osd: i32, pg: SpgT) -> Option<&Pg> {
        self.nodes.get(&osd)?.set.pg(pg)
    }

    /// Where does object `name` live, with which data length and log history (debugging aid).
    pub fn object_report(&self, pool: u64, name: &str) -> String {
        let h = hobj(pool, name);
        let mut out = String::new();
        for (o, n) in &self.nodes {
            for (k, p) in n.set.pgs() {
                if k.pgid.pool != pool {
                    continue;
                }
                let have = n
                    .store
                    .pgs
                    .get(k)
                    .and_then(|m| m.objects.get(&h))
                    .map(|x| x.data.len());
                let ents: Vec<String> = p
                    .log()
                    .entries()
                    .iter()
                    .filter(|e| e.soid == h)
                    .map(|e| format!("{}:{}", e.version, e.op.name()))
                    .collect();
                if have.is_some() || !ents.is_empty() || p.missing().contains(&h) {
                    out += &format!(
                        "  osd.{o} pg {k} {} data {have:?} missing {} log {ents:?} lu {} head {}\n",
                        p.state_string(),
                        p.missing().contains(&h),
                        p.info().last_update,
                        p.log().head()
                    );
                }
            }
        }
        out
    }

    /// Trace lines mentioning `needle` (debugging aid).
    pub fn trace_of(&self, needle: &str) -> String {
        self.log
            .iter()
            .filter(|l| l.contains(needle))
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn dump(&self) -> String {
        let mut s = format!("epoch {} now {}ms\n", self.epoch(), self.now / MS);
        s += &self.classic_summary();
        s += "\n";
        for (o, n) in &self.nodes {
            s += &format!("osd.{o} alive={}\n", n.alive);
            for (k, p) in n.set.pgs() {
                s += &format!(
                    "  pg {k} {:?} state={} up={:?} acting={:?} lu={} lc={} tail={} les={} lb={} missing={} lpr={} map={} disc={:?} err={:?}\n",
                    p.machine_state(),
                    p.state_string(),
                    p.up(),
                    p.acting(),
                    p.info().last_update,
                    p.info().last_complete,
                    p.log().tail(),
                    p.info().last_epoch_started,
                    if p.info().last_backfill == Hobject::MAX() {
                        "MAX"
                    } else if p.info().last_backfill == Hobject::MIN() {
                        "MIN"
                    } else {
                        "mid"
                    },
                    p.missing().len(),
                    p.last_peering_reset(),
                    p.map_epoch(),
                    p.counters().discards,
                    p.counters().errors
                );
                for (h, it) in p.missing().iter().take(3) {
                    let have: Vec<String> = self
                        .nodes
                        .iter()
                        .map(|(oo, nn)| {
                            format!(
                                "osd.{oo}={:?}",
                                nn.store.recovery_info(*k, h).map(|r| r.version.to_string())
                            )
                        })
                        .collect();
                    s += &format!(
                        "      missing {} need={} have={} del={} stored: {:?}\n",
                        String::from_utf8_lossy(&h.oid),
                        it.need,
                        it.have,
                        it.is_delete(),
                        have
                    );
                    for (oo, nn) in &self.nodes {
                        if let Some(mp) = nn.store.pgs.get(k) {
                            let rm: Vec<_> =
                                mp.removals.iter().filter(|(n, _)| *n == h.oid).collect();
                            s += &format!("        osd.{oo} removals of it: {rm:?}\n");
                            let ents: Vec<String> =
                                mp.p.log
                                    .log
                                    .iter()
                                    .filter(|e| e.soid == *h)
                                    .map(|e| {
                                        format!(
                                            "{}:{}:prior{}",
                                            e.version,
                                            e.op.name(),
                                            e.prior_version
                                        )
                                    })
                                    .collect();
                            s += &format!("        osd.{oo} log entries: {ents:?}\n");
                        }
                    }
                }
            }
        }
        for l in self.log.iter().rev().take(self.dump_lines).rev() {
            s += l;
            s += "\n";
        }
        s
    }

    /// Primary OSD and PG for the current map.
    pub fn primary_of(&self, pg: PgT) -> i32 {
        peering::PgMapView::pg_mapping(&*self.map(), pg).acting_primary
    }
    pub fn acting_of(&self, pg: PgT) -> Vec<i32> {
        peering::PgMapView::pg_mapping(&*self.map(), pg).acting
    }
    pub fn up_of(&self, pg: PgT) -> Vec<i32> {
        peering::PgMapView::pg_mapping(&*self.map(), pg).up
    }

    /// Every PG of `pool` is `active+clean` on its primary in the current map and all
    /// acting members agree on the map epoch.
    pub fn pool_clean(&self, pool: u64) -> bool {
        let map = self.map();
        let Some(pp) = map.pools.get(&pool) else {
            return false;
        };
        for seed in 0..pp.pg_num {
            let pg = PgT::new(pool, seed);
            let mp = peering::PgMapView::pg_mapping(&*map, pg);
            if mp.acting_primary < 0 {
                return false;
            }
            let s = self.lead_spg(pool, seed);
            let Some(p) = self.pg(mp.acting_primary, s) else {
                return false;
            };
            if p.state_bits() & (pgwire::state::ACTIVE | pgwire::state::CLEAN)
                != (pgwire::state::ACTIVE | pgwire::state::CLEAN)
            {
                return false;
            }
            if p.acting() != mp.acting.as_slice() {
                return false;
            }
        }
        true
    }

    pub fn pool_state_strings(&self, pool: u64) -> Vec<String> {
        let map = self.map();
        let pp = &map.pools[&pool];
        (0..pp.pg_num)
            .map(|seed| {
                let mp = peering::PgMapView::pg_mapping(&*map, PgT::new(pool, seed));
                self.pg(mp.acting_primary, spg(pool, seed))
                    .map_or("absent".to_string(), |p| p.state_string())
            })
            .collect()
    }

    pub fn quiet(&self) -> bool {
        self.nodes
            .values()
            .filter(|n| n.alive)
            .all(|n| n.set.pgs().all(|(_, p)| p.in_flight_persists() == 0))
    }

    // ---- client writes ---------------------------------------------------------------------------------------------

    pub fn write_obj(
        &mut self,
        pool: u64,
        seed: u32,
        name: &str,
        data: &[u8],
    ) -> Result<u64, WriteErr> {
        self.write_obj_op(pool, seed, name, Some(data))
    }
    pub fn delete_obj(&mut self, pool: u64, seed: u32, name: &str) -> Result<u64, WriteErr> {
        self.write_obj_op(pool, seed, name, None)
    }

    fn write_obj_op(
        &mut self,
        pool: u64,
        seed: u32,
        name: &str,
        data: Option<&[u8]>,
    ) -> Result<u64, WriteErr> {
        let s = self.lead_spg(pool, seed);
        self.pending_spg = Some(s);
        let osd = self.primary_of(s.pgid);
        let now = self.now;
        let n = self.nodes.get_mut(&osd).ok_or(WriteErr::NotActive)?;
        if !n.alive {
            return Err(WriteErr::NotActive);
        }
        let pg = n.set.pg(s).ok_or(WriteErr::NotActive)?;
        let version = pg.next_version();
        self.last_version = version;
        let soid = hobj(pool, name);
        let gh = Ghobject::head(soid.clone(), s.shard);
        let mut t = Transaction::new();
        let cx = t.coll(&CollT::Pg(s));
        let ox = t.obj(&gh);
        let oi;
        let op;
        if let Some(d) = data {
            op = pgwire::LogOp::MODIFY;
            oi = ObjectInfo {
                soid: soid.clone(),
                version,
                size: d.len() as u64,
                user_version: version.version,
                ..Default::default()
            };
            let oi_bytes = denc::to_vec(&oi).unwrap();
            t.push(cx, TxnOp::Touch { oid: ox });
            t.push(cx, TxnOp::Truncate { oid: ox, size: 0 });
            t.push(
                cx,
                TxnOp::Write {
                    oid: ox,
                    off: 0,
                    data: replwire::Data::new(d),
                },
            );
            t.push(
                cx,
                TxnOp::SetAttr {
                    oid: ox,
                    name: b"_",
                    value: &oi_bytes,
                },
            );
            let req = WriteReq {
                reqid: OsdReqId::default(),
                entries: vec![WriteEntry {
                    op,
                    soid: soid.clone(),
                    user_version: version.version,
                    mtime: UTime::default(),
                    snaps: vec![],
                    return_code: 0,
                    op_returns: vec![],
                    prior: None,
                }],
                txn_middle: Default::default(),
                txn_data: t.encode_v9().unwrap().into(),
                txn_refs: Vec::new(),
                ..Default::default()
            };

            let r = n.set.submit_write(n.clock(now), s, req, &n.store);
            return self.after_submit(osd, r);
        }
        t.push(cx, TxnOp::Remove { oid: ox });
        let req = WriteReq {
            reqid: OsdReqId::default(),
            entries: vec![WriteEntry {
                op: pgwire::LogOp::DELETE,
                soid,
                user_version: version.version,
                mtime: UTime::default(),
                snaps: vec![],
                return_code: 0,
                op_returns: vec![],
                prior: None,
            }],
            txn_middle: Default::default(),
            txn_data: t.encode_v9().unwrap().into(),
            txn_refs: Vec::new(),
            ..Default::default()
        };

        let r = n.set.submit_write(n.clock(now), s, req, &n.store);
        self.after_submit(osd, r)
    }

    /// Logical (replicated-shape) write of several store ops on one object, like the op layer builds them: the ops in
    /// order, then the object_info attribute with `new_size` (`None` = the object is removed by `ops`).
    pub fn write_ops(
        &mut self,
        pool: u64,
        seed: u32,
        name: &str,
        ops: &[EcOp],
        new_size: Option<u64>,
    ) -> Result<u64, WriteErr> {
        let s = self.lead_spg(pool, seed);
        self.pending_spg = Some(s);
        let osd = self.primary_of(s.pgid);
        let now = self.now;
        let n = self.nodes.get_mut(&osd).ok_or(WriteErr::NotActive)?;
        if !n.alive {
            return Err(WriteErr::NotActive);
        }
        let pg = n.set.pg(s).ok_or(WriteErr::NotActive)?;
        let version = pg.next_version();
        self.last_version = version;
        let soid = hobj(pool, name);
        let gh = Ghobject::head(soid.clone(), s.shard);
        let mut t = Transaction::new();
        let cx = t.coll(&CollT::Pg(s));
        let ox = t.obj(&gh);
        let oi_bytes;
        for op in ops {
            match op {
                EcOp::Write(off, d) => t.push(
                    cx,
                    TxnOp::Write {
                        oid: ox,
                        off: *off,
                        data: replwire::Data::new(d),
                    },
                ),
                EcOp::Zero(off, len) => t.push(
                    cx,
                    TxnOp::Zero {
                        oid: ox,
                        off: *off,
                        len: *len,
                    },
                ),
                EcOp::Trunc(sz) => t.push(cx, TxnOp::Truncate { oid: ox, size: *sz }),
                EcOp::Remove => t.push(cx, TxnOp::Remove { oid: ox }),
                EcOp::Touch => t.push(cx, TxnOp::Touch { oid: ox }),
                EcOp::OmapSet(kv) => t.push(
                    cx,
                    TxnOp::OmapSetKeys {
                        oid: ox,
                        pairs: kv
                            .iter()
                            .map(|(k, v)| (k.as_slice(), v.as_slice()))
                            .collect(),
                    },
                ),
                EcOp::OmapRmRange(a, b) => t.push(
                    cx,
                    TxnOp::OmapRmKeyRange {
                        oid: ox,
                        first: a,
                        last: b,
                    },
                ),
                EcOp::Attr(k, v) => t.push(
                    cx,
                    TxnOp::SetAttr {
                        oid: ox,
                        name: k.as_bytes(),
                        value: v,
                    },
                ),
            }
        }
        let prior = peering::PgStoreOps::object_version(&n.store, s, &soid).unwrap_or_default();
        let lop = match new_size {
            Some(sz) => {
                oi_bytes = denc::to_vec(&ObjectInfo {
                    soid: soid.clone(),
                    version,
                    prior_version: prior,
                    size: sz,
                    user_version: version.version,
                    ..Default::default()
                })
                .unwrap();
                t.push(
                    cx,
                    TxnOp::SetAttr {
                        oid: ox,
                        name: b"_",
                        value: &oi_bytes,
                    },
                );
                pgwire::LogOp::MODIFY
            }
            None => pgwire::LogOp::DELETE,
        };
        let req = WriteReq {
            reqid: OsdReqId::default(),
            entries: vec![WriteEntry {
                op: lop,
                soid,
                user_version: version.version,
                mtime: UTime::default(),
                snaps: vec![],
                return_code: 0,
                op_returns: vec![],
                prior: None,
            }],
            txn_middle: Default::default(),
            txn_data: t.encode_v9().unwrap().into(),
            txn_refs: Vec::new(),
            ..Default::default()
        };

        let r = n.set.submit_write(n.clock(now), s, req, &n.store);
        self.after_submit(osd, r)
    }

    /// Submit a prepared write on the PG's primary (tests that build their own transaction / temp fields).
    /// `last_version` for `wait_writes` is the log head after the call (an unlogged write leaves it where it is).
    pub fn submit_raw(&mut self, pool: u64, seed: u32, req: WriteReq) -> Result<u64, WriteErr> {
        let s = self.lead_spg(pool, seed);
        self.pending_spg = Some(s);
        let osd = self.primary_of(s.pgid);
        let now = self.now;
        let n = self.nodes.get_mut(&osd).ok_or(WriteErr::NotActive)?;
        if !n.alive {
            return Err(WriteErr::NotActive);
        }
        let r = n.set.submit_write(n.clock(now), s, req, &n.store);
        self.last_version = n.set.pg(s).map(|p| p.log().head()).unwrap_or_default();
        self.after_submit(osd, r)
    }

    fn after_submit(
        &mut self,
        osd: i32,
        r: Result<(u64, Vec<Action>), WriteErr>,
    ) -> Result<u64, WriteErr> {
        match r {
            Ok((tid, acts)) => {
                self.trace(format!("WRITE osd.{osd} tid {tid}"));
                if let Some(spg_) = self.pending_spg.take() {
                    self.submitted.push((spg_, tid, self.last_version));
                }
                self.dispatch(osd, acts);
                Ok(tid)
            }
            Err(e) => Err(e),
        }
    }

    /// Object contents of the PG on one OSD (`name -> data`).
    pub fn contents(&self, osd: i32, pool: u64, seed: u32) -> BTreeMap<Vec<u8>, Vec<u8>> {
        let s = spg(pool, seed);
        self.nodes[&osd]
            .store
            .objects(s)
            .into_iter()
            .map(|(h, o)| (h.oid, o.data))
            .collect()
    }

    /// Assert that all acting members hold identical object sets, equal to `expect`.
    pub fn assert_replicas_equal(&self, pool: u64, seed: u32, expect: &BTreeMap<String, Vec<u8>>) {
        let pg = PgT::new(pool, seed);
        let want: BTreeMap<Vec<u8>, Vec<u8>> = expect
            .iter()
            .map(|(k, v)| (k.as_bytes().to_vec(), v.clone()))
            .collect();
        for o in self.acting_of(pg) {
            let c = self.contents(o, pool, seed);
            if c != want {
                let names = |m: &BTreeMap<Vec<u8>, Vec<u8>>| {
                    m.iter()
                        .map(|(k, v)| format!("{}:{}", String::from_utf8_lossy(k), v.len()))
                        .collect::<Vec<_>>()
                };
                let (a, b) = (names(&c), names(&want));
                let extra: Vec<_> = a.iter().filter(|x| !b.contains(x)).collect();
                let lack: Vec<_> = b.iter().filter(|x| !a.contains(x)).collect();
                let rep: String = extra
                    .iter()
                    .chain(lack.iter())
                    .filter_map(|x| x.split(':').next())
                    .map(|n| self.object_report(pool, n))
                    .collect();
                eprintln!("{rep}");
                panic!(
                    "osd.{o} pg {pool}.{seed} contents differ: extra {extra:?} lacking {lack:?}\n{}",
                    self.dump()
                );
            }
        }
    }

    /// The persisted state of every live PG equals its in-memory state (after all commits).
    pub fn assert_persisted_consistent(&self) {
        for (o, n) in &self.nodes {
            assert_eq!(
                n.store.orphan_writes,
                0,
                "osd.{o}: writes to a PG that does not exist: {:?}\n{}",
                n.store.orphan_ops,
                self.dump()
            );
        }
        for (o, n) in &self.nodes {
            if !n.alive {
                continue;
            }
            for (k, p) in n.set.pgs() {
                if p.in_flight_persists() != 0 {
                    continue;
                }
                let Some(ps) = n.store.load_pg(*k) else {
                    panic!("osd.{o} pg {k} not persisted");
                };
                assert_eq!(
                    ps.log.log,
                    p.log().log.log,
                    "osd.{o} pg {k} persisted log entries"
                );
                assert_eq!(
                    ps.log.head,
                    p.log().log.head,
                    "osd.{o} pg {k} persisted head (persisted entries {} lu {} tail {}; mem entries {} lu {} epoch {})\n{}",
                    ps.log.log.len(),
                    ps.info.last_update,
                    ps.log.tail,
                    p.log().log.log.len(),
                    p.info().last_update,
                    ps.epoch,
                    self.trace_of(&format!("{k}"))
                );
                assert_eq!(
                    ps.log.tail,
                    p.log().log.tail,
                    "osd.{o} pg {k} persisted tail"
                );
                assert_eq!(
                    ps.log.dups,
                    p.log().log.dups,
                    "osd.{o} pg {k} persisted dups"
                );
                assert_eq!(
                    ps.info.last_update,
                    p.info().last_update,
                    "osd.{o} pg {k} persisted last_update"
                );
                assert_eq!(
                    ps.info.last_complete,
                    p.info().last_complete,
                    "osd.{o} pg {k} persisted last_complete"
                );
                assert_eq!(
                    ps.info.log_tail,
                    p.info().log_tail,
                    "osd.{o} pg {k} persisted log_tail"
                );
                assert_eq!(
                    ps.info.last_epoch_started,
                    p.info().last_epoch_started,
                    "osd.{o} pg {k} persisted les"
                );
                assert_eq!(
                    ps.info.history,
                    p.info().history,
                    "osd.{o} pg {k} persisted history"
                );
                // the whole info as reloaded (lazy PG info rebuilt from the log) except the stats: a replica takes them
                // from every repop and persists them with its next info write (they are recomputed by the primary)
                let mut want = p.info().clone();
                want.stats = ps.info.stats.clone();
                assert_eq!(ps.info, want, "osd.{o} pg {k} persisted info");
                assert_eq!(
                    &ps.missing.missing,
                    &p.missing().wire().missing,
                    "osd.{o} pg {k} persisted missing"
                );
                assert_eq!(
                    ps.past_intervals,
                    *p.past_intervals(),
                    "osd.{o} pg {k} persisted past intervals"
                );
            }
        }
    }

    /// [`Self::assert_persisted_consistent`] plus the EC rollback cursors (`_loghead` = the in-memory log).
    pub fn assert_ec_persisted_consistent(&self) {
        self.assert_persisted_consistent();
        for (o, n) in &self.nodes {
            if !n.alive {
                continue;
            }
            for (k, p) in n.set.pgs() {
                if p.in_flight_persists() != 0 {
                    continue;
                }
                let ps = n.store.load_pg(*k).expect("persisted");
                let l = &p.log().log;
                assert_eq!(
                    (ps.log.can_rollback_to, ps.log.rollback_info_trimmed_to),
                    (l.can_rollback_to, l.rollback_info_trimmed_to),
                    "osd.{o} pg {k} persisted rollback cursors"
                );
            }
        }
    }

    pub fn assert_no_roundtrip_mismatch(&self) {
        assert!(
            self.stats.roundtrip_mismatch.is_empty(),
            "wire roundtrip mismatches: {:#?}",
            &self.stats.roundtrip_mismatch[..self.stats.roundtrip_mismatch.len().min(3)]
        );
    }

    /// The op layer's EC wake pass on `osd`: the parked client ops ran (a failed read answered them), later ops read
    /// the shards again (`PgSet::take_ec_wake` + `PgSet::ec_read_errors_delivered`, as `pg_post` does).
    pub fn ec_ops_ran(&mut self, osd: i32) {
        let set = &mut self.nodes.get_mut(&osd).expect("node").set;
        set.take_ec_wake(&mut Vec::new());
        set.ec_read_errors_delivered();
    }

    pub fn wait_writes(&mut self, tids: &[u64], spg_: SpgT) {
        // tids are only unique per primary: wait for the exact (tid, version) that was submitted
        let want: Vec<(u64, Eversion)> = tids
            .iter()
            .map(|t| {
                let v = self
                    .submitted
                    .iter()
                    .rev()
                    .find(|(sp, x, _)| *sp == spg_ && x == t)
                    .map(|e| e.2)
                    .expect("submitted");
                (*t, v)
            })
            .collect();
        self.run_until(30_000 * MS, "writes acked", move |s| {
            want.iter().all(|(t, v)| {
                s.acked
                    .iter()
                    .any(|(sp, x, av)| *sp == spg_ && x == t && av == v)
            })
        });
    }

    pub fn is_acked(&self, spg_: SpgT, tid: u64) -> bool {
        let Some(v) = self
            .submitted
            .iter()
            .rev()
            .find(|(sp, x, _)| *sp == spg_ && *x == tid)
            .map(|e| e.2)
        else {
            return false;
        };
        self.acked
            .iter()
            .any(|(s, t, av)| *s == spg_ && *t == tid && *av == v)
    }
}

/// Standard cluster: `n` OSDs, one pool, wait until clean.
pub fn cluster(seed: u64, osds: &[i32], pool: u64, size: u32, min_size: u32, pg_num: u32) -> Sim {
    let mut s = Sim::new(seed);
    for o in osds {
        s.add_osd(*o);
    }
    s.run_for(50 * MS);
    s.create_pool(pool, size, min_size, pg_num);
    s.run_until(60_000 * MS, "pool clean", |s| s.pool_clean(pool));
    s
}

/// Like [`cluster`] with a per-OSD config tweak.
pub fn cluster_cfg(
    seed: u64,
    osds: &[i32],
    pool: u64,
    size: u32,
    min_size: u32,
    pg_num: u32,
    f: impl Fn(&mut Config),
) -> Sim {
    let mut s = Sim::new(seed);
    for o in osds {
        s.add_osd_cfg(*o, &f);
    }
    s.run_for(50 * MS);
    s.create_pool(pool, size, min_size, pg_num);
    s.run_until(60_000 * MS, "pool clean", |s| s.pool_clean(pool));
    s
}
