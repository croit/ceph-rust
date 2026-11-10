// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! The per-PG op engine (client-ops.md s5): checks, per-object ordering, dup detection, execution, submit, replies.

use crate::backoff::Backoffs;
use crate::caps::{self, Caps};
use crate::clsx;
use crate::exec::{Exec, load_state};
use crate::pgop;
use crate::snap::{Target, resolve_snap};
use crate::types::*;
use crate::view::{ObjView, gate_why};
use crate::watch::{Mono, Watches};
use denc::types::{
    EntityAddr, EntityName, Eversion, Hobject, ObjectLocator, OsdReqId, SnapId, SpgT, UTime,
};
use opwire::{
    MOSDBackoff, MOSDOp, MOSDOpReply, MWatchNotify, OpInfo, OsdOp, errno, flag as mflag, op as code,
};
use peering::wake::{Cause, WakeSet};
use peering::{WriteErr, WriteReq};
use replwire::ObjectInfo;
use replwire::SnapContext;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

/// Hash map with a fast, per-map randomly seeded hasher (keys include client-chosen object names: no fixed seed, no SipHash cost).
type FastMap<K, V> = HashMap<K, V, foldhash::fast::RandomState>;

mod copy;
pub use copy::{COPY_CONN, COPY_MEM_BUDGET, CopyBudget};

/// Pseudo connection id of engine-internal requests (watch timeouts): never replied to.
pub const INTERNAL_CONN: u64 = u64::MAX;
const MAX_PARKED: usize = 4096;
/// Store block size (data probes of partial-block writes).
const DATA_BLK: u64 = 4096;
/// Gated ops probed (store residency) per `retry`; also the gate size up to which a warm op may pass cold ones.
const RETRY_PROBES: usize = 64;

/// What [`Engine::cold`] found an op waiting for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cold {
    Ready,
    /// Store residency / admission (named by the store's cause log, or unknown).
    Store,
    /// The PG log head a write appends to (`Env::warm_log`: its pgmeta page, this PG's parked txn, admission). PG-wide:
    /// every later write of the PG is refused the same way until a store wake.
    Log,
    /// EC primary state of the object (`Env::ec_wait`): the client read that covers the op (its wake token) or the
    /// write of the object in flight (the object's token).
    Ec(u64),
}
/// EC pools: bytes of an object a cls call is warmed for (its data reads are served from the decoded cache).
const EC_CLS_WARM: u64 = 4 << 20;
/// Non-blocking executions of one op that may be refused by a cold store page WITHOUT progress before it runs blocking
/// (progress bound: every refused run queued page loads, a hot working set larger than the page cache must still
/// finish). A refused run that made progress (a listing slice or an admitted data wait that continues where it stopped,
/// adr 0021 S8) is not counted: listings never fall back to a blocking run.
const MAX_SCAN_TRIES: u8 = 64;
/// Store wakes a refused op sits out while page loads are still in flight before it runs again anyway.
const MAX_SCAN_WAKES: u8 = 8;
/// Stuck detector of a refused op, counted from its FIRST refused run (a re-park never restarts it): an op still refused
/// this long after it was first refused runs blocking next and says so (`WARNING TIMEOUT`). Its refusals all claimed
/// progress (data waits, listing slices: not counted by `MAX_SCAN_TRIES`) without the op ever finishing.
const SCAN_STUCK_NS: Mono = 30_000_000_000;

/// A gated op whose last non-blocking run was refused (adr 0021 S8).
#[derive(Debug)]
struct Refused {
    /// Refused runs without progress (bounded by `MAX_SCAN_TRIES`).
    tries: u8,
    /// [`Env::mono`] of the op's first refused run (`None`: a deferred listing that has not run yet).
    since: Option<Mono>,
    /// Waiting for the loads its run queued (or the wake of its listing slice).
    waiting: bool,
    /// Wakes seen while loads were still in flight.
    wakes: u8,
    /// The last refused run made progress: it runs again on its next wake.
    progressed: bool,
    /// Another locally scheduled request owns the credit; never block its core.
    local_wait: bool,
    /// A PG listing message: where its next run continues.
    pgls: Option<Box<pgop::PgLsRun>>,
}

/// The PG as the engine sees it.
pub trait Env: ObjView {
    fn spg(&self) -> SpgT;
    fn epoch(&self) -> u32;
    /// `require_osd_release` of the client's map / the PG's pool (osdmap): log entry types an older peer of the
    /// cluster can replay are gated on it (client-ops 16.5).
    fn require_osd_release(&self) -> u8;
    /// OSD wall clock.
    fn wall(&self) -> UTime;
    /// Monotonic ns since start (same clock as `Engine::tick`).
    fn mono(&self) -> Mono;
    /// PG is primary and active.
    fn is_active(&self) -> bool;
    /// Primary lease valid (reads may be served).
    fn is_readable(&self) -> bool;
    /// Version the next log entry gets.
    fn next_version(&self) -> Eversion;
    fn last_update(&self) -> Eversion;
    fn last_user_version(&self) -> u64;
    /// pg log / dup list lookup: `(version, user_version, return_code)`.
    fn find_reqid(&self, r: &OsdReqId) -> Option<(Eversion, u64, i32)>;
    /// Per-op results stored with a RETURNVEC write's log entry or dup record (replayed to resent requests).
    fn dup_op_returns(&self, r: &OsdReqId) -> Vec<pgwire::LogOpReturnItem>;
    /// The head or one of its clones is missing on the primary (not readable here): park the op.
    fn is_missing(&self, soid: &Hobject) -> bool;
    /// The head is missing here and no location can supply it (unfound): an unreadable object that will not recover on
    /// its own, so the client is backed off instead of parked (client-ops 16.6).
    fn is_unfound(&self, head: &Hobject) -> bool;
    /// Get recovery of a client-visible unreadable / degraded object going (client-ops 16.6: an object-level BLOCK
    /// kicks recovery of that object).
    fn kick_recovery(&mut self, head: &Hobject);
    /// The primary's missing objects in `[from, to)` (`to` = `Hobject::MAX()`: to the end), ascending, each with its
    /// "pending delete" flag: a listing (s9) shows the missing ones, hides the ones to be deleted. Return at most
    /// `max` entries; the caller uses an extra entry to bound the merged scan and preserve inclusive continuation.
    fn missing_range(&self, from: &Hobject, to: &Hobject, max: usize) -> Vec<(Hobject, bool)>;
    /// A write of the head must wait (missing here or on a recovery / backfill peer, inside the backfill window):
    /// a write-ordered op parks before its dup lookup (s5.4).
    fn write_degraded(&self, head: &Hobject) -> bool;
    /// A local read of `soid` (head or clone) failed with EIO / its object_info does not decode: ask the PG to repair
    /// the object from a peer (adr 0065). `true` = it is now missing locally, park the op until it is recovered;
    /// `false` = no repair possible (EC pool, not active, deleted, not a store fault): answer the error.
    fn local_damage(&mut self, soid: &Hobject, known: Option<Eversion>) -> bool;
    /// Start of an op execution: forget store read errors seen so far (see [`Env::local_damage`]).
    fn eio_clear(&self);
    /// `PgSet::submit_write` + immediate local apply of the resulting `Persist` actions.
    fn submit_write(&mut self, w: WriteReq) -> Result<u64, WriteErr>;
    /// Send-first window (adr 0008 am. 2): `true` while the engine runs the one fresh client op of [`Engine::on_op`],
    /// whose `submit_write` is its last store access in this call. Inside it the env may hold the local `Persist` back
    /// until the replica messages left; outside it every `Persist` applies at once.
    fn send_first(&mut self, on: bool);
    /// Client io of one executed message (spec pg-io-stats.md 1): add it to the PG's `num_read*` / `num_write*`
    /// stats. Plain counters of the PG this core owns: no lock, no allocation.
    fn note_io(&mut self, io: &pgwire::IoCount);
    /// The engine starts a run of the client op `r` (each run: the first and every re-run after a wait). Op tracing hook.
    fn run_start(&mut self, r: &OsdReqId);
    /// The client op `r` arrived and waits in the PG gate for `why` ([`crate::view::gate_why`]). Op tracing hook.
    fn gate_in(&mut self, r: &OsdReqId, why: u8);
    /// Apply a local txn held back under [`Env::send_first`] now: the engine is about to read the store again.
    fn settle(&mut self);
    fn pg_num(&self) -> u32;
    /// Placement of an object in any pool: `(pgid with NO_SHARD, raw object hash)`; `None` = no such pool (copy-from
    /// source lookup).
    fn locate(&self, name: &[u8], oloc: &ObjectLocator) -> Option<(SpgT, u32)>;
    /// This OSD's id (identity of engine-internal source reads).
    fn whoami(&self) -> i64;
    fn blocklisted(&self, addr: &EntityAddr) -> bool;
    /// Is client connection `conn` still open? A watch that completes after its connection closed starts its
    /// timeout at once (classic `Watch::connect` checks the session); `true` where no connection can close.
    fn conn_open(&self, _conn: u64) -> bool {
        true
    }
    /// Snap ids removed in the pool (`(start, len)` intervals): filtered from write snapcs, hidden from snap reads.
    fn removed_snaps(&self) -> Vec<(u64, u64)>;
    /// Pool-snap mode (`rados mksnap`): the pool's snap context (seq, snaps descending), `None` for pools that are
    /// not in pool-snap mode. Writes use it instead of the client's unless ENFORCE_SNAPC.
    fn pool_snapc(&self) -> Option<SnapContext>;
    /// Admission preflight for a write of about `bytes` payload setting or removing `entries` omap keys / xattrs: false = the local store has no room beyond its
    /// reserves (failsafe full, ADR 0021 amendment 6).
    fn write_room(&self, bytes: usize, entries: usize) -> bool;
    /// Temporary core backpressure. Park without consuming a cold-read fallback budget.
    fn admission_ready(&self) -> bool;
    /// `history.last_epoch_marked_full` of the PG (client-ops 5.4 #11).
    fn marked_full_epoch(&self) -> u32;
    /// `(full, full_quota)` of the pool.
    fn pool_full(&self) -> (bool, bool);
    /// Pool FLAG_EIO: normal object requests must fail or wait for a new map.
    fn pool_eio(&self) -> bool;
    /// The local store is above its failsafe fill (client-ops 5.4 rule 12).
    fn failsafe_full(&self) -> bool;
    /// Osdmap values object classes read for this PG's pool.
    fn cls_map(&self) -> crate::ClsMap;
    /// `rados list-inconsistent-obj|snapset` source (pg op SCRUBLS): `(interval, encoded findings)` or a positive errno.
    fn scrub_ls(&self, arg: &peering::scrubls::LsArg) -> Result<(u32, Vec<Vec<u8>>), i32>;
    /// PG is down, incomplete or peered-but-not-active: clients get a PG-wide BLOCK backoff instead of parking (s5.3 step 2).
    fn pg_blocked(&self) -> bool;
    /// The op was sent before this PG's last split / primary change (`last_epoch_split`, `same_primary_since`): drop it,
    /// the client re-sends against the new map. Checked again when parked ops run: after a split they may belong
    /// to a child.
    fn op_stale(&self, op_epoch: u32) -> bool;
    /// Non-blocking readiness of the store pages an op on `head` over `[off, off+len)` walks (adr 0021 am. 8). false =
    /// the loads were submitted: park the op at the gate, `retry` re-checks (never block the core on a page miss).
    fn warm(&self, head: &Hobject, off: u64, len: u64) -> bool;
    /// [`warm`](Self::warm) for the removal of `head` (adr 0021 am. 33): every store page the remove visits; false = park.
    fn warm_rm(&self, head: &Hobject) -> bool;
    /// Non-blocking readiness of the PG log head a write appends to (adr 0021 am. 30); false = park like `warm`.
    fn warm_log(&self) -> bool;
    /// Should the op gate probe [`warm`](Self::warm) at all? Adaptive (false while the tree cache is warm: the probe walks the
    /// object's paths a second time, ~1.3 us of a ~15 us write); the data probes stay unconditional.
    fn probe_meta(&self) -> bool;
    /// Data prefetch of a read of `head` over `[off, off+len)` (ADR 0043); false = park like `warm`.
    fn warm_data(&self, head: &Hobject, off: u64, len: u64) -> bool;
    /// Decoded object-state cache of this PG (adr 0160 D5): `(object-state generation, capacity in heads)`; `None` or
    /// capacity 0 = no cache. The generation must change whenever a txn other than this engine's replicated client
    /// writes may change an object of the PG, when it is queued and when it commits (`peering::Pg::obj_gen`).
    fn obj_cache(&self) -> Option<(u64, usize)>;
    /// This PG is an erasure-coded pool led here (EC rules for WRITEFULL).
    fn ec_pool(&self) -> bool;
    /// EC pool capabilities of this PG's pool: the SYNC_READ gate and the legacy append-only write forms (client-ops
    /// 16.4). Meaningless for a replicated pool.
    fn ec_caps(&self) -> EcCaps;
    /// Logical stripe width for bounded copy staging (1 for replicated pools).
    fn copy_stripe_width(&self) -> u64;
    /// EC primary: `None` = the logical bytes of `head` over `[off, off+len)` (clipped to the object) are decoded and
    /// ready for `ov_read`; else the op parks like a cold one on the returned wake token (the shard read that covers the
    /// range, started now or in flight, or the write of the object in flight). Replicated: `None`.
    fn ec_wait(&mut self, head: &Hobject, snapid: u64, off: u64, len: u64) -> Option<u64>;
    /// Pool name and application metadata for cap checks.
    fn pool_caps_info(&self) -> (&[u8], Option<&caps::AppMeta>);
    // ---- snap trimmer (spec snaptrim 7)
    /// Gate + slot: what the trimmer may do now (`No` = idle until the PG kicks again).
    fn trim_poll(&mut self) -> peering::TrimPoll;
    fn trim_cfg(&self) -> crate::trim::TrimCfg;
    /// SnapMapper: up to `max` clones mapped to `snap`. `Ok(empty)` = the index has none (the snap is purged);
    /// `Err` = the index could not be read / decoded: SNAPTRIM_ERROR, never "purged".
    fn snap_mapper_next(
        &self,
        snap: u64,
        max: usize,
    ) -> Result<Vec<Hobject>, peering::StoreReadError>;
    /// No clone of `snap` is left: the PG records it as purged.
    fn trim_snap_done(&mut self, snap: u64);
    /// Leave the run (`error` = SNAPTRIM_ERROR).
    fn trim_stop(&mut self, error: bool);
    /// `n` clones / whiteout heads were deleted by trim steps.
    fn trim_counted(&mut self, n: i64);
    /// Drop a stale mapper entry (no clone object, not in the SnapSet).
    fn trim_unmap(&mut self, clone: &Hobject);
    /// Operator-visible error line (cluster log).
    fn trim_note(&mut self, msg: String);
    /// Cost share of the PG core (adr 0522): may a listing that continues where its last run stopped (CPU slice, cold
    /// leaf with progress) run now? `false` = not in this loop iteration (the host runs the PG again in the next one,
    /// [`Engine::runs_again`]). `held`: the listing holds later ops of its object (`Engine::holds_later`): no
    /// background work, always admitted.
    fn list_turn(&mut self, held: bool) -> bool;
    /// The continuation [`Env::list_turn`] admitted has run.
    fn list_ran(&mut self);
}

/// One client message at the PG.
#[derive(Debug)]
pub struct ClientReq {
    /// `Some` = the attempt's retry number, set only after the transport
    /// validated a live placement descriptor.
    pub placement_read: Option<u32>,
    /// Session caps (osdcaps.md); `None` = unrestricted (engine-internal and test requests).
    pub caps: Option<std::sync::Arc<Caps>>,
    /// Opaque connection handle for replies.
    pub conn: u64,
    /// msgr2 header tid.
    pub tid: u64,
    pub op: Box<MOSDOp>,
    pub who: EntityName,
    /// Client-advertised identity (blocklist/watch semantics).
    pub addr: EntityAddr,
    /// Accepted transport source, independent of advertised identity.
    pub peer_addr: EntityAddr,
    /// Connection feature mask.
    pub features: u64,
}

/// A client op the engine dropped without a reply ([`Engine::take_dropped`]). The client resends it (UNBLOCK, new map)
/// or supersedes it with a new tid (linger re-registration); either way this `(conn, tid)` is never answered, so the
/// OSD ends its op-tracker record here and shares its map with the session (a copy read is answered EAGAIN).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dropped {
    pub conn: u64,
    pub tid: u64,
    /// The map epoch the client sent the op with.
    pub epoch: u32,
}

impl Dropped {
    fn of(req: &ClientReq) -> Self {
        Dropped {
            conn: req.conn,
            tid: req.tid,
            epoch: req.op.osdmap_epoch,
        }
    }
}

impl ClientReq {
    /// The client session the op came from; `None` = an engine-internal op ([`INTERNAL_CONN`]: watch timeout /
    /// blocklist UNWATCH): never backed off, no drop notice, never indexed by reqid, never answered.
    pub fn session(&self) -> Option<u64> {
        (self.conn != INTERNAL_CONN).then_some(self.conn)
    }
}

/// Engine output.
#[derive(Debug)]
pub enum Out {
    Reply {
        conn: u64,
        tid: u64,
        /// `Some` = the admitted attempt's retry number: transport admission
        /// follows success and error replies to the link core.
        placement_read: Option<u32>,
        /// Counter class of the request's op codes (spec ops-observability.md 2d).
        class: opwire::OpClass,
        reply: Box<MOSDOpReply>,
    },
    Notify {
        conn: u64,
        msg: MWatchNotify,
    },
    /// MOSDBackoff BLOCK / UNBLOCK.
    Backoff {
        conn: u64,
        msg: MOSDBackoff,
    },
    /// A source read of a copy-from that is not in this PG: send `op` (a read MOSDOp) to the primary of `spg` and
    /// answer with [`Engine::on_copy_reply`] (`step` identifies it).
    CopyRead {
        /// The destination PG that asked (its engine is told the answer).
        origin: SpgT,
        step: u64,
        /// Source PG.
        spg: SpgT,
        op: Box<MOSDOp>,
    },
}

#[derive(Default)]
struct ObjEntry {
    state: Option<ObjState>,
    /// Object-state generation `state` started from (its load or cache hit; 0 = never cache it): the post-write state
    /// goes into the object-state cache when the object becomes idle only while the PG is still at it.
    gen_: u64,
    inflight: u32,
    waiters: VecDeque<ClientReq>,
    /// A copy-from is fetching into this object: other ops wait (copy.md).
    copying: bool,
}

impl ObjEntry {
    /// Nothing in flight, nobody waiting, no copy filling it: the entry has nothing to say any more.
    fn is_idle(&self) -> bool {
        self.inflight == 0 && !self.copying && self.waiters.is_empty()
    }
}

struct Inflight {
    head: Hobject,
    reply: Box<MOSDOpReply>,
    effects: Vec<Effect>,
    final_oi: Option<ObjectInfo>,
    reqid: OsdReqId,
    version: Eversion,
    user_version: u64,
    rc: i32,
    dups: Vec<ClientReq>,
    /// The request itself: re-queued (not dropped) on a new interval, the client does not resend when the primary stays.
    req: ClientReq,
}

/// Counters (diagnostics / tell).
#[derive(Debug, Default, Clone)]
pub struct Counters {
    pub ops: u64,
    pub reads: u64,
    pub writes: u64,
    /// Writes that ran the plain-overwrite executor (`fast`) instead of the general one.
    pub fast_writes: u64,
    pub errors: u64,
    pub dups: u64,
    pub parked_gate: u64,
    pub backoffs: u64,
    pub parked_obj: u64,
    /// Ops parked because a local read hit a damaged object that is being repaired from a peer.
    pub parked_repair: u64,
    pub pg_ops: u64,
    /// Re-queued ops dropped because a split (or primary change) happened after the client sent them.
    pub stale: u64,
    /// Ops dropped without a reply because the pool was full: a growing write at a FULL pool, or a write-ordered op
    /// sent before the epoch that marked the pool full (the client resends after it learns the map).
    pub full_drops: u64,
    /// Snap trim steps submitted / failed steps.
    pub trim_steps: u64,
    pub trim_errors: u64,
    /// Executions refused by a cold store page (omap scan, cls read, ...) and parked until the load finished (ADR 0021 am. 11).
    pub parked_scan: u64,
    /// Object-state cache (adr 0160 D5, only counted while it is on): states served from it / loaded from the store.
    pub obj_hits: u64,
    pub obj_misses: u64,
    /// Copies that waited for the OSD-wide copy memory budget (copy.md 4.6).
    pub copy_waits: u64,
    /// Best-effort removals of copy temp objects (or their txn encoding) the store refused; the temp stays until the
    /// next interval change.
    pub copy_discard_errors: u64,
    /// Gated ops a store wake probed / skipped because its tokens did not name them (or a write behind the PG log head an
    /// earlier write of the same scan found not ready) / wake batches that woke every gated op (an unnamed change, token
    /// overflow, EC or tick wake; adr 0043 am. 9).
    pub wake_probes: u64,
    pub wake_skips: u64,
    /// Work of the gate scans of [`Engine::retry`] (ops noted and ordering queries answered): linear in the gate.
    pub gate_scan_steps: u64,
    /// Op-vector classifications run on the message path (a `CALL` op allocates its class/method names there): tests
    /// assert one per run, never one per precheck plus one per execution.
    pub classify_calls: u64,
    /// Lookups of the first parked op of an object (tests: the per-object index keeps each one O(1)).
    pub parked_probes: u64,
    /// Gated replicated reads a wake hit ran straight away (no second probe of data the wake says arrived).
    pub wake_direct: u64,
    pub wake_all: u64,
    /// Listing continuations `Env::list_turn` left for the next loop iteration (adr 0522).
    pub list_deferred: u64,
}

/// Causes of the gated ops (adr 0043 am. 9) plus a token index: "does this wake name any of them" is a few lookups, not a
/// walk of the gate.
#[derive(Default)]
struct Waits {
    m: FastMap<(u64, u64), Cause>,
    /// token -> number of causes naming it
    idx: FastMap<u64, u32>,
}

impl Waits {
    fn get(&self, k: &(u64, u64)) -> Option<&Cause> {
        self.m.get(k)
    }
    fn len(&self) -> usize {
        self.m.len()
    }
    fn insert(&mut self, k: (u64, u64), c: Cause) {
        self.remove(&k);
        for t in c.tokens() {
            *self.idx.entry(*t).or_insert(0) += 1;
        }
        self.m.insert(k, c);
    }
    fn remove(&mut self, k: &(u64, u64)) {
        if let Some(c) = self.m.remove(k) {
            for t in c.tokens() {
                if let Some(n) = self.idx.get_mut(t) {
                    *n -= 1;
                    if *n == 0 {
                        self.idx.remove(t);
                    }
                }
            }
        }
    }
    fn clear(&mut self) {
        if !self.m.is_empty() {
            self.m.clear();
            self.idx.clear();
        }
    }
    /// Does `w` name a token some cause waits for?
    fn named(&self, w: &WakeSet) -> bool {
        w.tokens().iter().any(|t| self.idx.contains_key(t))
    }
}

/// Snap trimmer state of the engine (spec snaptrim 7.3).
#[derive(Debug, Default)]
struct TrimRun {
    /// Earliest time of the next round (pacing sleep / retry); 0 = none.
    wake_at: Mono,
    /// A step failed while others were in flight: stop with SNAPTRIM_ERROR when they finish.
    error: bool,
    /// A round was aborted (interval change, not active): stop quietly when the steps finish.
    aborted: bool,
    /// The current wait for a refused step (not active / object degraded) was reported to the operator; cleared when
    /// a step is submitted again.
    blocked_noted: bool,
}

pub struct Engine {
    spg: SpgT,
    limits: Limits,
    /// Class load/default lists of this OSD (cls.md 2.1).
    classes: clsx::ClassPolicy,
    objs: FastMap<Hobject, ObjEntry>,
    /// Decoded state of idle heads (adr 0160 D5).
    cache: crate::objcache::ObjCache,
    inflight: BTreeMap<u64, Inflight>,
    by_reqid: FastMap<OsdReqId, u64>,
    gate: VecDeque<ClientReq>,
    /// Resume a budget-limited gate sweep; Some(0) schedules its wrapped prefix.
    retry_from: Option<usize>,
    /// A wake or insertion before the cursor needs a wrapped prefix pass.
    retry_wrap: bool,
    /// The last `retry` left the gate non-empty only because of store misses (PG active + readable, nothing else
    /// parked): only a store wake (or a state change, checked by the caller) can make a gated op runnable.
    cold_only: bool,
    /// The last retry left a listing continuation for the next loop iteration (`Env::list_turn`).
    list_deferred: bool,
    /// Ops waiting for their object (degraded / missing / scrubbed / repaired), in arrival order per object.
    parked_obj: Vec<Parked>,
    /// First parked op per head: its `write_gate`, so "is an op of this object parked, and may a read pass it" is one
    /// lookup, not a walk of `parked_obj` (arrival order is the push order; cleared with every take of the list).
    parked_head: FastMap<Hobject, bool>,
    out: Vec<Out>,
    /// Every client op dropped WITHOUT a reply (inside a backoff, stale after a split, gate full, PG torn down): the
    /// OSD ends its tracker record and shares its map with these clients, otherwise a client that learns nothing waits
    /// for its own tick (10 s).
    dropped: Vec<Dropped>,
    watch: Watches,
    backoffs: Backoffs,
    /// Gate bound for NEW ops: MAX_PARKED, raised to what a reset re-queued (those must never be dropped).
    gate_cap: usize,
    /// Arrival order of the gated ops and of the dups waiting on an in-flight write (`stamp`): a failed write puts its
    /// dups back among the gated ops by it. Pruned to the live ops when it outgrows the gate.
    stamps: FastMap<(u64, u64), u64>,
    arrival: u64,
    /// Scratch of the gate scan (capacity kept between wakes).
    ahead: Ahead,
    last_epoch: u32,
    internal_tid: u64,
    /// Trim steps in flight: write tid -> head.
    trims: BTreeMap<u64, Hobject>,
    trim: TrimRun,
    /// Ops whose last run was refused by a cold page or a listing slice: `(conn, tid)` -> [`Refused`].
    scan: FastMap<(u64, u64), Refused>,
    /// What a gated op waited for at its last probe (store tokens, adr 0043 am. 9): `(conn, tid)` -> cause. Only ops whose
    /// last cold probe named a cause are here; every other gated op is probed on every wake. Dropped whenever the gate loop
    /// cannot probe (not active, admission, probe cap), so a consumed wake never leaves an op behind.
    waits: Waits,
    pub c: Counters,
    /// Copies in flight (copy.rs), by id; fetched sources waiting for their message to run; copies over the cap.
    copies: BTreeMap<u64, copy::CopyState>,
    copy_id: u64,
    copy_step: u64,
    copy_done: FastMap<(u64, u64), std::sync::Arc<CopySrc>>,
    /// Writes of staged copy chunks in flight: write tid -> copy id.
    stage_tids: FastMap<u64, u64>,
    /// Temp objects of finished copies whose message did not use them: removed at the next entry point.
    temp_garbage: Vec<Hobject>,
    copy_queue: VecDeque<ClientReq>,
    in_copy_poll: bool,
    /// Memory budget shared by the copies of the whole OSD; time queued copies try for it again (0 = none).
    copy_budget: std::sync::Arc<copy::CopyBudget>,
    copy_wake: Mono,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("spg", &self.spg)
            .field("inflight", &self.inflight.len())
            .finish_non_exhaustive()
    }
}

/// Debug builds: an object-state cache hit must equal what the store holds (adr 0160 D5). A store read error is no
/// verdict (the cache then serves the last good state, like a store-level cache would).
#[cfg(debug_assertions)]
fn verify_hit<E: Env>(env: &E, spg: SpgT, head: &Hobject, hit: &ObjState) {
    let stored = load_state(env, spg, head);
    env.eio_clear();
    if let Ok(s) = stored {
        assert_eq!(
            &s, hit,
            "pg {spg}: stale object-state cache entry for {head:?}"
        );
    }
}

/// Only reads the object: no state change, no effect (watch / notify / cls), no read-ordering flag. Two such messages on
/// one object give the same replies in either order, so neither waits for the other at the gate, whatever their sessions
/// (spec client-ops 5.5: reads share the object lock; 5.7 step 9: replies of different ops are not ordered, the client
/// matches them by tid; 5.12: no reply-order contract on EC or replicated pools). A cold page or an EC shard read of one
/// read holds no other read of the object: a sequential reader's queue of small reads does not wait for the slowest read
/// ahead of it (adr 0043 am. 21). Every other pair keeps its order.
fn pure_read(m: &MOSDOp) -> bool {
    m.flags & opwire::consts::flag::RWORDERED == 0
        && !m.oid.is_empty()
        && m.ops.iter().all(|o| {
            matches!(
                o.op,
                code::READ
                    | code::SYNC_READ
                    | code::SPARSE_READ
                    | code::STAT
                    | code::GETXATTR
                    | code::GETXATTRS
                    | code::CMPXATTR
                    | code::OMAP_GET_KEYS
                    | code::OMAP_GET_VALS
                    | code::OMAP_GET_HEADER
                    | code::OMAP_GET_VALS_BY_KEYS
                    | code::OMAP_CMP
                    | code::CHECKSUM
                    | code::CMPEXT
            )
        })
}

/// An op waiting for its object in `Engine::parked_obj` (client-ops 5.4 #15, #16; adr 0065).
struct Parked {
    req: ClientReq,
    /// Parked at a gate only write-ordered ops wait for (client-ops 5.4 #16: the object, or a clone the write makes, is
    /// degraded / backfilling on a peer; scrub write block): nothing of it ran (no log entry, no repop, nothing applied).
    /// While it is the first parked op of its object, a pure read that arrives later passes it and returns the state before
    /// it (5.5 (6)); the read still waits for writes in flight and for its own gates (object missing here). `false`: the
    /// object is unreadable here (missing, being repaired: reads wait too), or the op only queued behind an earlier parked
    /// op of its object (never passed until a retry judged it).
    write_gate: bool,
}

/// `Parked::write_gate` of the first parked op of `head`; `None` = no op of the object is parked. `probes` counts the
/// lookups (tests: the per-object index keeps each one O(1) however many objects are parked).
fn parked_first(parked: &FastMap<Hobject, bool>, probes: &mut u64, head: &Hobject) -> Option<bool> {
    *probes += 1;
    parked.get(head).copied()
}

/// `b` (later) must stay behind `a` (earlier, gated): same object, unless both only read it.
fn ordered(a: &ClientReq, b: &ClientReq) -> bool {
    // the op-kind test first: the gate walk compares every gated op with the ones ahead of it, and listings of one
    // object would otherwise compare their names each time
    !(pure_read(&a.op) && pure_read(&b.op)) && same_obj(&a.op, &b.op)
}

/// The ops ahead of the scan position of [`Engine::retry_inner`], by object: answers "does an op ahead order before `r`"
/// ([`ordered`]) in O(1), so a scan of the gate is linear. Objects are keyed by a 64-bit hash of their identity (a
/// collision only holds an op back one more wake: its blocker leaves the gate).
#[derive(Default)]
struct Ahead {
    any: HashSet<u64>,
    writers: HashSet<u64>,
    /// Entries added and queries answered: the scan's work, bounded by the gate length (tests).
    steps: u64,
}

impl Ahead {
    fn key(m: &MOSDOp) -> u64 {
        use std::hash::{BuildHasher, Hash, Hasher};
        let mut h = foldhash::fast::FixedState::default().build_hasher();
        m.hash.hash(&mut h);
        m.oid.hash(&mut h);
        m.oloc.nspace.hash(&mut h);
        let key = if m.oloc.key == m.oid {
            &[][..]
        } else {
            m.oloc.key.as_slice()
        };
        key.hash(&mut h);
        h.finish()
    }
    fn add(&mut self, r: &ClientReq) {
        self.steps += 1;
        let k = Self::key(&r.op);
        self.any.insert(k);
        if !pure_read(&r.op) {
            self.writers.insert(k);
        }
    }
    /// Some op added before orders ahead of `r` (same object, unless both only read it).
    fn blocks(&mut self, r: &ClientReq) -> bool {
        self.steps += 1;
        let k = Self::key(&r.op);
        self.any.contains(&k) && (!pure_read(&r.op) || self.writers.contains(&k))
    }
    fn clear(&mut self) {
        self.any.clear();
        self.writers.clear();
    }
}

/// A listing request (omap_get_vals / omap_get_keys, PGLS / PGNLS): its passes share the core with the other work (adr
/// 0522, [`Env::list_turn`]).
pub fn is_listing(op: &MOSDOp) -> bool {
    op.ops.iter().any(|o| {
        matches!(
            o.op,
            code::OMAP_GET_VALS
                | code::OMAP_GET_KEYS
                | code::PGLS
                | code::PGLS_FILTER
                | code::PGNLS
                | code::PGNLS_FILTER
        )
    })
}

/// Same target object (head) of two ops of this PG. A locator key equal to the oid is the empty key (as `head_of`).
fn same_obj(a: &MOSDOp, b: &MOSDOp) -> bool {
    fn key(o: &MOSDOp) -> &[u8] {
        if o.oloc.key == o.oid {
            &[]
        } else {
            &o.oloc.key
        }
    }
    a.hash == b.hash && a.oid == b.oid && a.oloc.nspace == b.oloc.nspace && key(a) == key(b)
}

/// `head_of(op) == *head`, without building the head (per parked op on the hot path).
fn targets(op: &MOSDOp, head: &Hobject) -> bool {
    let key: &[u8] = if op.oloc.key == op.oid {
        &[]
    } else {
        &op.oloc.key
    };
    head.hash == op.hash
        && head.pool == op.pgid.pgid.pool as i64
        && head.snap == SnapId::NOSNAP
        && !head.max
        && head.oid == op.oid
        && head.nspace == op.oloc.nspace
        && head.key == key
}

pub fn head_of(op: &MOSDOp) -> Hobject {
    let mut h = Hobject::new(
        &op.oid,
        SnapId::NOSNAP,
        op.hash,
        op.pgid.pgid.pool as i64,
        &op.oloc.nspace,
    );
    h.set_key(&op.oloc.key);
    h
}

/// Classification with the cls registry and its load policy (unknown class = EPERM, unknown method = EOPNOTSUPP,
/// class off `osd_class_load_list` = EPERM, cls.md 2.1).
pub fn classify(op: &MOSDOp, classes: &clsx::ClassPolicy) -> Result<OpInfo, i32> {
    for o in &op.ops {
        if o.op == code::CALL {
            let c = o.cls_call().map_err(|_| errno::EINVAL)?;
            if let Err(e) = clsx::lookup(c.class, c.method, classes) {
                // per-class cls_unsupported counter (rgw-gap G26; the executor exports it)
                cls::unsupported::note(std::str::from_utf8(c.class).unwrap_or("?"));
                return Err(e);
            }
        }
    }
    OpInfo::classify(&op.ops, op.flags, &|c, m| clsx::lookup(c, m, classes).ok())
}

impl Engine {
    /// The OSD config changed: later messages run under `limits`.
    pub fn set_limits(&mut self, limits: Limits) {
        self.limits = limits;
    }
    /// `osd_class_load_list` / `osd_class_default_list` changed: later messages classify under `classes`.
    pub fn set_class_policy(&mut self, classes: clsx::ClassPolicy) {
        self.classes = classes;
    }
    pub fn new(spg: SpgT, limits: Limits, classes: clsx::ClassPolicy) -> Self {
        Engine {
            spg,
            limits,
            classes,
            objs: FastMap::default(),
            cache: Default::default(),
            inflight: BTreeMap::new(),
            by_reqid: FastMap::default(),
            dropped: Vec::new(),
            gate: VecDeque::new(),
            retry_from: None,
            retry_wrap: false,
            cold_only: false,
            list_deferred: false,
            parked_obj: Vec::new(),
            parked_head: FastMap::default(),
            out: Vec::new(),
            watch: Watches::default(),
            backoffs: Backoffs::default(),
            gate_cap: MAX_PARKED,
            stamps: FastMap::default(),
            arrival: 0,
            ahead: Ahead::default(),
            last_epoch: 0,
            internal_tid: 0,
            trims: BTreeMap::new(),
            trim: TrimRun::default(),
            scan: FastMap::default(),
            waits: Waits::default(),
            copies: BTreeMap::new(),
            copy_id: 0,
            copy_step: 0,
            copy_done: FastMap::default(),
            stage_tids: FastMap::default(),
            temp_garbage: Vec::new(),
            copy_queue: VecDeque::new(),
            in_copy_poll: false,
            copy_budget: copy::CopyBudget::global(),
            copy_wake: 0,
            c: Counters::default(),
        }
    }

    /// Use `b` instead of the process-wide copy memory budget (tests, several OSDs in one process).
    pub fn set_copy_budget(&mut self, b: std::sync::Arc<CopyBudget>) {
        self.copy_budget = b;
    }

    pub fn take_out(&mut self) -> Vec<Out> {
        std::mem::take(&mut self.out)
    }

    /// Move the pending outputs to the end of `dst`; the engine keeps its buffer capacity (no allocation per reply).
    pub fn out_into(&mut self, dst: &mut Vec<Out>) {
        dst.append(&mut self.out);
    }

    /// The PG is gone (merge source) or this OSD is not its primary any more: release every live backoff (UNBLOCK) so
    /// no client stays blocked on a PG that will not answer, and hand back what has to be sent.
    pub fn teardown(&mut self) -> Vec<Out> {
        // every op still held here is dropped: its client must learn the map that moved the PG
        let mut held: Vec<&ClientReq> = Vec::new();
        for i in self.inflight.values() {
            held.push(&i.req);
            held.extend(i.dups.iter());
        }
        for e in self.objs.values() {
            held.extend(e.waiters.iter());
        }
        held.extend(self.parked_obj.iter().map(|p| &p.req));
        held.extend(self.gate.iter());
        held.extend(self.copy_held());
        let d: Vec<Dropped> = held
            .into_iter()
            .filter(|r| r.session().is_some())
            .map(Dropped::of)
            .collect();
        self.dropped.extend(d);
        self.backoffs
            .release_all(self.spg, self.last_epoch, &mut self.out);
        self.backoffs.clear();
        self.take_out()
    }

    /// Client ops dropped without a reply since the last call.
    pub fn take_dropped(&mut self) -> Vec<Dropped> {
        std::mem::take(&mut self.dropped)
    }

    /// A client op dropped without reply: reported by `take_dropped`. Every drop of a session op goes through here (no
    /// op-tracker record may outlive the op). Internal ops have no session and no record.
    fn note_dropped(&mut self, req: &ClientReq) {
        if req.session().is_some() {
            self.dropped.push(Dropped::of(req));
        }
    }

    /// Nothing in flight, parked or watched: the engine may be dropped.
    pub fn is_idle(&self) -> bool {
        self.inflight.is_empty()
            && self.trims.is_empty()
            && self.trim.wake_at == 0
            && self.objs.is_empty()
            && self.gate.is_empty()
            && self.parked_obj.is_empty()
            && self.watch.is_empty()
    }

    /// Writes submitted to the PG and not yet completed: `((client conn, client tid), PG write tid)` (slow-op dumps ask
    /// the PG which peers still owe a commit).
    pub fn inflight_writes(&self) -> impl Iterator<Item = ((u64, u64), u64)> + '_ {
        self.inflight
            .iter()
            .map(|(wtid, i)| ((i.req.conn, i.req.tid), *wtid))
    }

    /// Decoded object states cached for this PG (`cache status` object_ctx).
    pub fn obj_cache_len(&self) -> usize {
        self.cache.len()
    }

    /// Operator `cache drop`: forget every cached object state of this PG (a read cache: the next op loads from the
    /// store). Returns the entries dropped.
    pub fn drop_obj_cache(&mut self) -> usize {
        let n = self.cache.len();
        self.cache.clear();
        n
    }

    /// Watchers of this PG (`dump_watchers`).
    pub fn watchers(
        &self,
    ) -> Vec<(
        Hobject,
        crate::types::WatchKey,
        u32,
        denc::types::EntityAddr,
    )> {
        self.watch.all()
    }

    /// The last retry left work for the next loop iteration: a listing continuation over the core share
    /// (`Env::list_turn`) or an unfinished probe sweep (`retry_from`). Run the PG again then, no store wake names it.
    pub fn runs_again(&self) -> bool {
        self.list_deferred || self.retry_from.is_some()
    }

    /// Ops waiting at the gate or on a degraded / scrubbed object (lab diagnostics).
    pub fn parked_len(&self) -> usize {
        self.gate.len() + self.parked_obj.len()
    }

    pub fn has_parked(&self) -> bool {
        !self.gate.is_empty()
            || !self.parked_obj.is_empty()
            || self.backoffs.has_live()
            || self.copies.values().any(copy::CopyState::ready_pending)
    }

    /// One-line state for diagnostics (tell dump_pgs).
    pub fn dump_state(&self) -> String {
        let waiters: usize = self.objs.values().map(|o| o.waiters.len()).sum();
        format!(
            "inflight={} obj_cache={} gate={} cold_only={} scan={:?} gate_head={} {}parked_obj={} obj_waiters={} backoffs_live={} {:?}",
            self.inflight.len(),
            self.cache.len(),
            self.gate.len(),
            self.cold_only,
            self.scan.values().collect::<Vec<_>>(),
            self.gate.front().map_or(String::new(), |r| format!(
                "{}:{} {} {:?}",
                r.conn,
                r.tid,
                String::from_utf8_lossy(&r.op.oid),
                r.op.ops.iter().map(|o| o.op).collect::<Vec<_>>()
            )),
            self.gate
                .front()
                .and_then(|r| self.waits.get(&(r.conn, r.tid)))
                .map_or(String::new(), |c| format!("cause={:x?} ", c.tokens())),
            self.parked_obj.len(),
            waiters,
            self.backoffs.has_live(),
            self.c
        )
    }

    pub fn in_flight(&self) -> usize {
        self.inflight.len()
    }

    /// New interval at the same primary: nothing is answered, every unanswered op (in flight, per-object waiters,
    /// parked) is re-queued at the gate in arrival order and re-runs once the PG is active again. The client does NOT
    /// resend when only replicas changed (its target primary is the same), so dropping would hang it; ops that did
    /// commit are caught by the dup check (client-ops 5.11).
    pub fn reset(&mut self) {
        self.requeue_all();
        self.scan.clear();
        self.waits.clear();
        self.trims.clear();
        self.trim = TrimRun::default();
        self.watch.clear();
        self.out.clear();
        // new interval: release backoffs (UNBLOCK); a DELETING record stays until the client's ACK (s6.2: classic keeps
        // it in the session, ops sent before the client saw the BLOCK stay dropped). A torn-down PG drops the engine.
        self.backoffs
            .release_all(self.spg, self.last_epoch, &mut self.out);
    }

    /// Every unanswered op (in flight in tid order with its dups, copies, per-object waiters, parked, gated) back to
    /// the gate in arrival order; object states are reloaded when they run again.
    fn requeue_all(&mut self) {
        let mut re: Vec<ClientReq> = Vec::new();
        for (_, mut i) in std::mem::take(&mut self.inflight) {
            re.push(i.req);
            re.append(&mut i.dups);
        }
        re.extend(self.copy_reqs());
        for (_, mut e) in std::mem::take(&mut self.objs) {
            re.extend(e.waiters.drain(..));
        }
        re.extend(self.parked_obj.drain(..).map(|p| p.req));
        self.parked_head.clear();
        re.extend(self.gate.drain(..));
        re.retain(|r| r.conn != COPY_CONN);
        self.gate = re.into();
        self.cold_only = false;
        self.gate_cap = MAX_PARKED.max(self.gate.len());
        self.retry_from = None;
        self.retry_wrap = false;
        self.by_reqid.clear();
    }

    // ------------------------------------------------------------------ ingress

    /// A client message for this PG (already routed, epoch-checked and permission-checked by the OSD).
    pub fn on_op<E: Env>(&mut self, env: &mut E, req: ClientReq) {
        let _s = wprof::span(wprof::S::Opexec);
        self.on_op_inner(env, req);
        self.copy_poll(env);
    }

    fn on_op_inner<E: Env>(&mut self, env: &mut E, mut req: ClientReq) {
        self.c.ops += 1;
        crate::exec::normalize_extents(&mut req.op.ops);
        self.last_epoch = env.epoch();
        // internal ops (watch timeout / blocklist UNWATCH) have no session: never backed off or dropped at intake, they
        // wait in the gate like any op (bounded by the watchers of the PG)
        let session = req.session();
        let head = head_of(&req.op);
        if let Some(conn) = session {
            if self.backoffs.covers(conn, &head) {
                // inside a live backoff of this session (PG-wide or this object): dropped, the client resends on
                // UNBLOCK (s6.5) or, for a linger op, re-registers under a new tid and never resends this one
                self.note_dropped(&req);
                return;
            }
            if !env.is_active() && env.pg_blocked() {
                self.c.backoffs += 1;
                let (spg, pg_num, epoch) = (self.spg, env.pg_num(), env.epoch());
                self.backoffs.block(spg, pg_num, epoch, conn, &mut self.out);
                self.note_dropped(&req);
                return;
            }
        }
        // also kicks the page loads of an op that queues behind others (overlap instead of one miss after the other)
        let why = if env.is_active() {
            Self::probe(env, &mut self.waits, &req, &head)
        } else {
            Cold::Ready
        };
        let cold = why != Cold::Ready;
        // Ordering is per object (an op that is not a pure read keeps its place among the object's ops), not per PG: a
        // warm op of another object runs even while cold ops wait (only when every gated op waits for the store,
        // `cold_only`).
        let behind = !self.gate.is_empty()
            && !(self.cold_only
                && self.gate.len() <= RETRY_PROBES
                && !cold
                && env.is_readable()
                && !req.op.oid.is_empty()
                && !self.gate.iter().any(|g| ordered(g, &req)));
        if cold || behind || !env.is_active() || !env.is_readable() {
            if self.gate.len() >= self.gate_cap
                && let Some(conn) = session
            {
                // Never lose an op silently (a client that is current gets nothing from a map share and would wait
                // for its own timeout): BLOCK its session, it resends on the UNBLOCK that `retry` sends when the PG is
                // active again (client-ops s6). The map share stays as the fallback for clients without backoff.
                self.c.backoffs += 1;
                let (spg, pg_num, epoch) = (self.spg, env.pg_num(), env.epoch());
                self.backoffs.block(spg, pg_num, epoch, conn, &mut self.out);
                self.waits.remove(&(conn, req.tid));
                self.note_dropped(&req);
                return;
            }
            self.c.parked_gate += 1;
            let why = match why {
                _ if !env.is_active() || !env.is_readable() => gate_why::INACTIVE,
                Cold::Ec(_) => gate_why::EC,
                Cold::Store | Cold::Log => match env.ov_refusal() {
                    gate_why::STORE if !env.admission_ready() => gate_why::ADMISSION,
                    r => r,
                },
                Cold::Ready => gate_why::BEHIND,
            };
            if req.session().is_some() {
                env.gate_in(&req.op.effective_reqid(req.who, req.tid), why);
            }
            self.stamp(&req);
            self.gate.push_back(req);
            // only ops without a named cause are probed (the new one among them); the others wait for their tokens
            self.retry_inner(env, &WakeSet::NONE);
            self.copy_poll(env);
            return;
        }
        // a listing's first pass takes its turn of the core share like its continuations (adr 0522): over the share it
        // waits in the gate, ready, for the next loop iteration
        let listing = is_listing(&req.op);
        if listing && !env.list_turn(false) {
            self.defer_listing(req);
            return;
        }
        // a fresh op: its submit (if any) is the last store access of `process` (only bookkeeping follows it)
        env.send_first(true);
        self.process(env, req, head);
        env.send_first(false);
        if listing {
            env.list_ran();
        }
    }

    /// `req` (a listing; gated ops from `gate[from..]` on arrived after it) holds a later op of its object: one that must
    /// stay behind it (`ordered`: an op that is not a pure read, a PG op behind a PG op), gated or waiting for the
    /// object. Such a listing is no background work (adr 0522 am. 1): every pass it waits for the core share or ends
    /// early for its CPU slice delays those ops as well (a write of a hot object waited for many loop iterations behind
    /// a 1024-entry listing), so it runs outside the share and lists whole (`ObjView::ov_list_whole`).
    fn holds_later(&self, req: &ClientReq, from: usize) -> bool {
        self.gate.iter().skip(from).any(|g| ordered(req, g))
            || self
                .objs
                .get(&head_of(&req.op))
                .is_some_and(|e| e.waiters.iter().any(|w| ordered(req, w)))
    }

    /// A fresh listing request over the core share (adr 0522): gated as a listing that may continue (no store wake names
    /// it, `list_deferred` makes the host run the PG in the next loop iteration). Point ops of other objects keep passing
    /// the gate (`cold_only`, as next to a sliced listing).
    fn defer_listing(&mut self, req: ClientReq) {
        self.scan.insert(
            (req.conn, req.tid),
            Refused {
                tries: 0,
                since: None,
                waiting: false,
                wakes: 0,
                progressed: true,
                local_wait: false,
                pgls: None,
            },
        );
        self.stamp(&req);
        self.gate.push_back(req);
        self.gate_cap = self.gate_cap.max(self.gate.len());
        self.list_deferred = true;
        self.c.list_deferred += 1;
        self.cold_only = self.parked_obj.is_empty() && !self.backoffs.has_live();
    }

    /// Something changed (readable, active, recovery progress): run parked ops again, oldest first.
    pub fn retry<E: Env>(&mut self, env: &mut E) {
        self.retry_inner(env, &WakeSet::ALL);
        self.copy_poll(env);
    }

    /// [`Self::cold`] for a gated op, remembering what it waits for (adr 0043 am. 9): the store's tree pages / prefetch
    /// runs, or (EC) the client read that covers it or the write of the object in flight (the token `Env::ec_wait`
    /// named; the PG's EC wake carries it when that ends). Anything else (admission, parked txn, nothing logged) leaves
    /// the op unnamed = probed on every wake.
    fn probe<E: Env>(env: &mut E, waits: &mut Waits, req: &ClientReq, head: &Hobject) -> Cold {
        env.ov_cause_begin();
        let why = Self::cold_why(env, req, head);
        let key = (req.conn, req.tid);
        let c = match why {
            Cold::Ready => Cause::default(),
            Cold::Store | Cold::Log => env.ov_cause_take(),
            // only that EC read / write makes `ec_wait` ready: the store loads it started on the way (own shard) end in
            // that read's completion
            Cold::Ec(tok) => Cause::one(tok),
        };
        if c.is_unknown() {
            waits.remove(&key);
        } else {
            waits.insert(key, c);
        }
        why
    }

    /// Debug check: only gated ops have a cause entry (the `waits.len() == gate.len()` fast path of `retry_woken` needs it).
    #[cfg(debug_assertions)]
    fn check_waits(&self) {
        let keys: std::collections::HashSet<(u64, u64)> =
            self.gate.iter().map(|r| (r.conn, r.tid)).collect();
        for k in self.waits.m.keys() {
            assert!(
                keys.contains(k),
                "cause entry of an op that is not gated: {k:?}"
            );
        }
    }

    /// `wake`: the gated ops whose named cause it does not hit stay (no probe); `WakeSet::ALL` probes every one.
    fn retry_inner<E: Env>(&mut self, env: &mut E, wake: &WakeSet) {
        self.list_deferred = false;
        if !env.admission_ready() {
            self.waits.clear();
            return;
        }
        self.last_epoch = env.epoch();
        if self.gate.is_empty() {
            self.scan.clear(); // nothing is waiting for a store load any more (drops stale entries)
            self.waits.clear();
        }
        if env.is_active() && self.backoffs.has_live() {
            // PG-wide backoffs end with activation; an object-level one ends only when its object is readable again or
            // left the degraded set (client-ops s6.4, 16.6)
            self.backoffs.release_ready(
                self.spg,
                env.epoch(),
                |head| !env.is_missing(head) && !env.write_degraded(head),
                &mut self.out,
            );
        }
        // Scan the gate in order: a cold op (store loads in flight) and every later op of the same object stay,
        // everything else runs (a slow op never holds ops of other objects). Bounded probe count per call.
        // `log_cold`: a write of this scan found the PG log head not ready (`Cold::Log`, adr 0082 am. 4). Every later
        // write appends to the same head and is refused the same way (pgmeta loads, this PG's parked txn and admission
        // change in the store poll; a FIFO drain inside the scan wakes the PG again), so they stay unprobed and unnamed
        // (probed on the next wake), outside the probe bound: one log probe per scan, not one per gated write.
        let start = self.retry_from.take().unwrap_or(0).min(self.gate.len());
        let wrap = std::mem::take(&mut self.retry_wrap) || (start > 0 && wake.any());
        let mut next = None;
        let (mut i, mut probed, mut log_cold) = (0, 0, false);
        self.ahead.clear();
        while i < self.gate.len() && env.is_active() && env.is_readable() {
            let r = &self.gate[i];
            let waiting = self.scan.get(&(r.conn, r.tid)).is_some_and(|s| s.waiting);
            let named = if wake.all {
                None
            } else {
                self.waits.get(&(r.conn, r.tid)).map(|c| wake.hits(c))
            };
            // named cause the wake does not hit: not probed, does not count against the probe bound
            if named == Some(false) {
                self.c.wake_skips += 1;
                self.ahead.add(r);
                i += 1;
                continue;
            }
            // a PG op waits for every op ahead of it, unless it already ran (a refused listing, adr 0021 S8): the ops
            // re-gated in front of it since arrived after it, and under a steady stream of refusals it would starve
            let pg_op_waits = r.op.oid.is_empty()
                && !self
                    .scan
                    .get(&(r.conn, r.tid))
                    .is_some_and(|s| s.pgls.is_some());
            let blocked = i > 0 && (pg_op_waits || self.ahead.blocks(r));
            if blocked || waiting {
                // its cause fired (or the wake is `all`) while it could not run: this wake is consumed, so it is probed
                // as soon as it can (an op unnamed again), not when some token it no longer waits for arrives
                self.waits.remove(&(r.conn, r.tid));
            }
            // a replicated read whose named cause this wake hits runs without probing again: the probe would resolve the
            // object and its extents a second time only to find the data in; the non-blocking execution resolves them
            // once and re-gates on whatever is still missing (tree page, prefetch run in flight, parked txn, durability).
            // Not for writes (the log head readiness is a probe-only check) nor EC (the decoded read cache is filled
            // by the probe's `ec_wait`, the execution does not re-check it).
            let write = r.op.ops.iter().any(|o| o.op & code::MODE_WR != 0);
            let direct = named == Some(true) && !env.ec_pool() && !write;
            if log_cold && write && !blocked && !waiting {
                self.waits.remove(&(r.conn, r.tid));
                self.c.wake_skips += 1;
                self.ahead.add(r);
                i += 1;
                continue;
            }
            // Probe budget (adr 0043 am. 23): ops before the cursor `start` were probed by an earlier slice, ops past
            // the budget wait for the next one; both still order the ops behind them. No cold prefix owns the budget.
            // Before the listing turn: a skipped continuation must not start the share's clock.
            if !blocked && !waiting && !direct && (i < start || probed >= RETRY_PROBES) {
                if i >= start && next.is_none() {
                    next = Some(i);
                }
                self.waits.remove(&(r.conn, r.tid));
                self.ahead.add(r);
                i += 1;
                continue;
            }
            // a listing that continues where its last run stopped takes its turn of the core share (adr 0522): over
            // the share it stays (ready, unnamed) for the next loop iteration
            let cont = !blocked
                && !waiting
                && self
                    .scan
                    .get(&(r.conn, r.tid))
                    .is_some_and(|s| s.progressed);
            if cont && !env.list_turn(self.holds_later(r, i + 1)) {
                self.waits.remove(&(r.conn, r.tid));
                self.list_deferred = true;
                self.c.list_deferred += 1;
                self.ahead.add(&self.gate[i]);
                i += 1;
                continue;
            }
            if blocked || waiting || {
                !direct && {
                    self.c.wake_probes += 1;
                    let why = Self::probe(env, &mut self.waits, r, &head_of(&r.op));
                    log_cold |= why == Cold::Log;
                    why != Cold::Ready
                }
            } {
                self.ahead.add(&self.gate[i]);
                i += 1;
                if !blocked && !waiting {
                    probed += 1;
                }
                continue;
            }
            let r = self.gate.remove(i).unwrap();
            let n = self.gate.len();
            let head = head_of(&r.op);
            self.waits.remove(&(r.conn, r.tid));
            self.c.wake_direct += u64::from(direct);
            self.process(env, r, head);
            if cont {
                env.list_ran();
            }
            let regated = self.gate.len().saturating_sub(n); // re-gated ops went to the front
            for g in self.gate.iter().take(regated) {
                self.ahead.add(g);
            }
            i += regated;
        }
        // A new wake consumed while skipping the prefix must be revisited after
        // the suffix. Continuations without a wake finish the sweep and sleep.
        self.retry_wrap = next.is_some() && wrap;
        self.retry_from = next.or_else(|| (start > 0 && wrap).then_some(0));
        self.c.gate_scan_steps += std::mem::take(&mut self.ahead.steps);
        self.ahead.clear();
        // ops the loop did not reach (probe bound, not active): their wake may be consumed now, probe them next time
        for r in self.gate.iter().skip(i) {
            self.waits.remove(&(r.conn, r.tid));
        }
        #[cfg(debug_assertions)]
        self.check_waits();
        let live = env.is_active() && env.is_readable();
        if live && !self.parked_obj.is_empty() {
            let mut v: VecDeque<ClientReq> = std::mem::take(&mut self.parked_obj)
                .into_iter()
                .map(|p| p.req)
                .collect();
            self.parked_head.clear(); // rebuilt below by every park of this loop
            while let Some(r) = v.pop_front() {
                let (key, head) = ((r.conn, r.tid), head_of(&r.op));
                let n0 = self.gate.len();
                // EC: the decoded read cache was not filled while the object was missing here (`Env::ec_wait` skips it):
                // warm it at the gate first, else the read runs cold (EIO). Not past older ops of the object that this
                // loop queued behind its in-flight writes: those keep their place (the op queues behind them).
                let queued = self.objs.get(&head).is_some_and(|e| !e.waiters.is_empty());
                if env.ec_pool() && !queued && Self::cold(env, &r, &head) {
                    self.regate(r);
                } else {
                    self.process(env, r, head.clone());
                }
                if self.gate.front().is_some_and(|g| (g.conn, g.tid) == key) {
                    // re-gated (cold page, not active): the object's later parked ops follow it (and the waiters the
                    // re-gate moved behind it) in order, AHEAD of the object's ops already in the gate: those arrived
                    // after every parked op (an ordered read left in the gate as cold, ack order)
                    let mut at = self.gate.len() - n0;
                    let mut i = 0;
                    while i < v.len() {
                        if targets(&v[i].op, &head) {
                            let r = v.remove(i).unwrap();
                            self.note_gate_insert(at, 1);
                            self.gate.insert(at, r);
                            at += 1;
                        } else {
                            i += 1;
                        }
                    }
                }
            }
        }
        self.cold_only = live
            && !self.gate.is_empty()
            && self.parked_obj.is_empty()
            && !self.backoffs.has_live();
    }

    /// [`Engine::retry`] for the PG post loop: nothing to do while only store misses gate the ops and no store load
    /// completed (`woke`), so an op arriving elsewhere does not cost a probe of every parked op.
    pub fn retry_woken<E: Env>(&mut self, env: &mut E, woke: &WakeSet) {
        if woke.all && !self.gate.is_empty() {
            self.c.wake_all += 1;
        }
        if woke.any() && !self.scan.is_empty() {
            // a page load finished: run the refused ops again once the whole batch of loads they queued is in (one
            // re-run per batch, not one per page); a busy store that never drains does not starve them. A run that
            // made progress (a listing that continues where it stopped, adr 0021 S8) runs again at once: its re-run
            // repeats nothing, it only goes on with what is resident now.
            let pending = env.ov_loads_pending();
            for (k, s) in self.scan.iter_mut() {
                if !woke.all && self.waits.get(k).is_some_and(|c| !woke.hits(c)) {
                    continue; // its refused run waits for other loads
                }
                if !pending || s.progressed || s.wakes >= MAX_SCAN_WAKES {
                    s.waiting = false;
                } else {
                    s.wakes += 1;
                }
            }
        }
        if self.skip_wake(woke, env.is_active() && env.is_readable(), || {
            env.admission_ready()
        }) {
            return;
        }
        self.retry_inner(env, woke);
        self.copy_poll(env);
    }

    /// Is [`Self::retry_woken`] with `woke` a no-op for this engine (then counted as skipped)? Answerable without an
    /// [`Env`], so the PG host can leave the engine alone (no per-PG run setup for every parked PG on every store
    /// wake). `live` = the PG is active and readable here, `admission` = the store admits its ops.
    pub fn skip_wake(
        &mut self,
        woke: &WakeSet,
        live: bool,
        admission: impl FnOnce() -> bool,
    ) -> bool {
        // an op that bypassed the gate since the last retry may have parked on a degraded object (`parked_obj`), or a
        // full gate blocked a session (backoff); those wait for recovery / release, not the store
        if !live || !self.waits_on_store_only() {
            return false;
        }
        if !woke.any() {
            // `cold_only` is from the last retry: only store loads gate the ops, and none completed
            return self.cold_only;
        }
        // every gated op names its cause and the wake names none of them: nothing to probe, no walk of the gate (a
        // named op's refused run, `scan`, waits for its own tokens too)
        if woke.all
            || self.gate.is_empty()
            || self.waits.len() != self.gate.len()
            || self.waits.named(woke)
            || !admission()
        {
            return false;
        }
        self.c.wake_skips += self.gate.len() as u64;
        true
    }

    /// No op waits on a degraded object, no session is blocked and no listing continuation is deferred: what is parked
    /// can only wait for the store or EC wake tokens ([`Self::skip_wake`]).
    fn waits_on_store_only(&self) -> bool {
        self.parked_obj.is_empty()
            && !self.backoffs.has_live()
            && !self.list_deferred
            && self.retry_from.is_none()
    }

    /// Is a live PG's engine a no-op for [`Self::retry_woken`] when nothing woke ([`Self::skip_wake`] with an empty wake)?
    /// Then only a store / EC wake or a PG state change (the PG is visited as touched) can unpark its ops; the PG host
    /// leaves it out of the pass that follows an op. Every engine state change goes through the host's `eng_note`, which
    /// keeps the index of the engines for which this is `false` (they are visited on every pass).
    pub fn quiet_without_wake(&self) -> bool {
        self.cold_only && self.waits_on_store_only()
    }

    /// Does the op read the omap of its object (EC: the stored omap lags the in-flight writes)?
    fn ec_omap_read(op: u16) -> bool {
        matches!(
            op,
            code::OMAP_GET_KEYS
                | code::OMAP_GET_VALS
                | code::OMAP_GET_HEADER
                | code::OMAP_GET_VALS_BY_KEYS
                | code::OMAP_CMP
                | code::COPY_GET
                | code::CALL
        )
    }

    /// The store pages `req` needs are not all resident (loads submitted). Only the first extent-style range is
    /// probed, capped at 4 MiB; anything missed later blocks as before.
    fn cold<E: Env>(env: &mut E, req: &ClientReq, head: &Hobject) -> bool {
        Self::cold_why(env, req, head) != Cold::Ready
    }

    /// [`Self::cold`] with what the op waits for.
    fn cold_why<E: Env>(env: &mut E, req: &ClientReq, head: &Hobject) -> Cold {
        if !env.admission_ready() {
            return Cold::Store;
        }
        if req.op.oid.is_empty() {
            return Cold::Ready;
        }
        let (mut lo, mut hi) = (u64::MAX, 0u64);
        let mut read_only = true;
        let mut reads = false;
        // EC (omap + cls): ops reading the object's omap / running cls code wait for its in-flight writes
        let mut omap_gate = false;
        for o in &req.op.ops {
            if o.op == code::SPARSE_READ && o.extent().length == 0 {
                continue;
            }
            if matches!(
                o.op,
                code::WRITE | code::APPEND | code::ZERO | code::TRUNCATE | code::CMPEXT
            ) {
                read_only = false;
            }
            if matches!(
                o.op,
                code::READ | code::SYNC_READ | code::SPARSE_READ | code::CMPEXT | code::CHECKSUM
            ) {
                reads = true;
            }
            if env.ec_pool() && Self::ec_omap_read(o.op) {
                omap_gate = true;
            }
            // cls methods may read the data (`cls_cxx_read`): warm what a method can reach, `EC_CLS_WARM` bytes
            if env.ec_pool() && o.op == code::CALL {
                reads = true;
                lo = 0;
                hi = hi.max(EC_CLS_WARM);
            }
            if matches!(
                o.op,
                code::READ
                    | code::SYNC_READ
                    | code::WRITE
                    | code::ZERO
                    | code::TRUNCATE
                    | code::SPARSE_READ
                    | code::CMPEXT
                    | code::CHECKSUM
            ) {
                let e = o.extent();
                lo = lo.min(e.offset);
                // Plain READ/CHECKSUM zero length reach EOF; sparse zero is an empty range.
                let to_end =
                    e.length == 0 && matches!(o.op, code::READ | code::SYNC_READ | code::CHECKSUM);
                hi = hi.max(if to_end {
                    u64::MAX
                } else {
                    e.offset.saturating_add(e.length)
                });
            }
        }
        if env.ec_pool() {
            // EC: copy-get (the source side of a copy-from) reads the chunk at its cursor through `ov_read`, i.e. the
            // decoded cache: warm it like a read
            for o in &req.op.ops {
                if o.op == code::COPY_GET
                    && let Ok(i) = o.copy_get_in()
                    && !i.cursor.data_complete
                    && i.max > 0
                {
                    lo = lo.min(i.cursor.data_offset);
                    hi = hi.max(i.cursor.data_offset.saturating_add(i.max));
                    reads = true;
                }
            }
        }
        let (off, len, full) = if lo == u64::MAX {
            (0, 0, 0)
        } else {
            (lo, (hi - lo).min(4 << 20), hi - lo)
        };
        if env.probe_meta() {
            // both probes always run: their page loads overlap
            let mut obj = env.warm(head, off, len);
            // a removal also walks every extent and key range of the object (adr 0021 am. 33): probe those too, in
            // the same pass (no short circuit: the loads overlap)
            if req.op.ops.iter().any(|o| o.op == code::DELETE) {
                obj &= env.warm_rm(head);
            }
            let log = !req.op.ops.iter().any(|o| o.op & code::MODE_WR != 0) || env.warm_log();
            if !log {
                return Cold::Log;
            }
            if !obj {
                return Cold::Store;
            }
        }
        // data probes: submit every missing device read at once (no short circuit: a write's head and tail block are
        // read in parallel), the op parks until all are in
        let mut cold = false;
        if env.ec_pool() {
            // EC: no data probe at logical offsets (the local shard holds chunks): `ec_wait` reads our shard and asks
            // the peers in one pass (a probe here first serialized local device read -> remote sub-reads, and its
            // prefetch runs never matched the shard read: pinned until expiry, adr 0116)
        } else if read_only {
            cold |= len > 0 && !env.warm_data(head, off, len);
        } else {
            // EC: the local shard holds chunks, not the logical bytes (probes at logical offsets would read blocks the
            // EC read-modify-write never consumes: device reads, table capacity and pins held for the TTL); `ec_wait`
            // covers the reads
            for o in &req.op.ops {
                let e = o.extent();
                match o.op {
                    code::READ
                    | code::SYNC_READ
                    | code::SPARSE_READ
                    | code::CMPEXT
                    | code::CHECKSUM => {
                        let n = if e.length == 0
                            && matches!(o.op, code::READ | code::SYNC_READ | code::CHECKSUM)
                        {
                            u64::MAX
                        } else {
                            e.length
                        };
                        let n = n.min(4 << 20);
                        cold |= n > 0 && !env.warm_data(head, e.offset, n);
                    }
                    code::APPEND => {
                        if let Ok(Some(size)) = env.ov_stat(env.spg(), head)
                            && e.length > 0
                            && size % DATA_BLK != 0
                        {
                            cold |= !env.warm_data(head, size, 1);
                        }
                    }
                    // read-modify-write: a partial head / tail block is read from the device first
                    code::WRITE | code::ZERO => {
                        let end = e.offset.saturating_add(e.length);
                        if e.length > 0 && e.offset % DATA_BLK != 0 {
                            cold |= !env.warm_data(head, e.offset, 1);
                        }
                        let head_probed = e.offset % DATA_BLK != 0;
                        if e.length > 0
                            && end % DATA_BLK != 0
                            && !(head_probed && (end - 1) / DATA_BLK == e.offset / DATA_BLK)
                        {
                            cold |= !env.warm_data(head, end - 1, 1);
                        }
                    }
                    code::TRUNCATE | code::TRIMTRUNC if e.offset % DATA_BLK != 0 => {
                        cold |= !env.warm_data(head, e.offset, 1);
                    }
                    _ => {}
                }
            }
        }
        if cold {
            return Cold::Store;
        }
        (reads && full > 0)
            .then(|| env.ec_wait(head, req.op.snapid, off, full))
            .flatten()
            .or_else(|| {
                omap_gate
                    .then(|| env.ec_wait(head, req.op.snapid, 0, 0))
                    .flatten()
            })
            .map_or(Cold::Ready, Cold::Ec)
    }

    /// Rule 12: a client write-ordered op that is not FULL_TRY and not a pure shrink is dropped while the local store is
    /// above its failsafe fill. Deliberate deviation (adr 0021 am. 6): a pure shrink passes, it is how space comes back;
    /// not on an EIO pool, which refuses every object request, so the classic outcome (drop) holds there.
    fn failsafe_refuses<E: Env>(env: &E, req: &ClientReq, info: &OpInfo) -> bool {
        info.rwordered
            && req.op.flags & mflag::FULL_TRY == 0
            && env.failsafe_full()
            && req.session().is_some()
            && (!pure_shrink(&req.op.ops) || env.pool_eio())
    }

    /// Fences of client-ops 5.4 in classic order: #11 write-ordered op sent before the pool was marked full (discard,
    /// client resends after the flag clears), #12 local failsafe full (drop), #13 pool EIO (drop for SUPPORTSPOOLEIO
    /// clients, else EIO). `true` = the op is answered or dropped here. Runs before an op queues behind an object
    /// (`process`) and again at every execution: a queued op never reaches `execute_req` unchecked.
    fn fence<E: Env>(
        &mut self,
        env: &mut E,
        req: &ClientReq,
        info: &OpInfo,
        reqid: &OsdReqId,
    ) -> bool {
        if info.rwordered
            && reqid.name.ty != denc::types::EntityName::MDS
            && req.op.flags & (mflag::FULL_TRY | mflag::FULL_FORCE) == 0
            && env.marked_full_epoch() > req.op.osdmap_epoch
        {
            self.c.full_drops += 1;
            self.note_dropped(req);
            return true;
        }
        if Self::failsafe_refuses(env, req, info) {
            self.c.full_drops += 1;
            self.note_dropped(req);
            return true;
        }
        if env.pool_eio() {
            if req.op.flags & mflag::SUPPORTSPOOLEIO != 0 {
                self.note_dropped(req);
            } else {
                self.reply_plain(env, req, -errno::EIO);
            }
            return true;
        }
        false
    }

    fn precheck<E: Env>(&mut self, env: &E, req: &ClientReq) -> Result<OpInfo, i32> {
        let op = &req.op;
        self.c.classify_calls += 1;
        let info = classify(op, &self.classes)?;
        if info.rwordered && op.flags & mflag::DIRECT_READ != 0 {
            // a write-ordered op (mutating message, or client RWORDERED) carrying BALANCE/LOCALIZE/EC_DIRECT_READ:
            // plain -EINVAL before execution (client-ops 16.8)
            return Err(errno::EINVAL);
        }
        if op.flags & mflag::PARALLELEXEC != 0 {
            return Err(errno::EINVAL);
        }
        if let Some(c) = &req.caps
            && !c.allows_op(op, &info.cls, &req.peer_addr, move || env.pool_caps_info())
        {
            return Err(errno::EPERM);
        }
        if info.pg_op {
            return Ok(info);
        }
        let lim = &self.limits;
        if op.oid.len() > lim.max_oid_len
            || op.oloc.key.len() > lim.max_oid_len
            || op.oloc.nspace.len() > lim.max_nspace_len
        {
            return Err(errno::ENAMETOOLONG);
        }
        if op.oid.is_empty() {
            return Err(errno::EINVAL);
        }
        // the store's own name-key limit (rule 9a): cheap sound bound first, the exact store check only above it
        if name_key_upper_bound(&op.oid, &op.oloc.key, &op.oloc.nspace)
            > env.ov_max_item_key().saturating_add(15)
            && !env.ov_name_fits(env.spg(), &head_of(op))
        {
            return Err(errno::ENAMETOOLONG);
        }
        // a name that needs the long-name index is accepted for writes only when every replica can store it
        if info.may_write
            && name_key_upper_bound(&op.oid, &op.oloc.key, &op.oloc.nspace)
                > env.ov_max_item_key().saturating_add(15)
            && !env.ov_name_repl_ok(env.spg(), &head_of(op))
        {
            return Err(errno::ENAMETOOLONG);
        }
        // fencing (client-ops 5.2 #10), classic position: after the name checks, pg ops (reads) not fenced
        if env.blocklisted(&req.addr) {
            return Err(errno::EBLOCKLISTED);
        }
        // Rules 12 and 13 precede snapshot, size and LIST_SNAPS validation. The execution
        // gate drops (12) or decides EIO versus drop (13) after the stale-full epoch.
        if Self::failsafe_refuses(env, req, &info) || env.pool_eio() {
            return Ok(info);
        }
        if info.may_write {
            if op.snapid != opwire::NOSNAP {
                return Err(errno::EINVAL);
            }
            if op.data_len() > lim.max_write_size {
                return Err(errno::EMSGSIZE);
            }
        }
        // a payload refused at intake (msgr2 data probe, client-ops 5.4.1) is gone: the op is answered as intake decided
        // and never executes without its data, also when the limit was raised or the class changed since intake
        if op.refused_data > 0 {
            return Err(errno::EMSGSIZE);
        }
        let has_ls = op.ops.iter().any(|o| o.op == code::LIST_SNAPS);
        if op.snapid == opwire::SNAPDIR {
            if op.ops.iter().any(|o| o.op != code::LIST_SNAPS) {
                return Err(errno::EINVAL);
            }
        } else if has_ls {
            return Err(errno::EINVAL);
        }
        Ok(info)
    }

    fn process<E: Env>(&mut self, env: &mut E, req: ClientReq, head: Hobject) {
        if !env.admission_ready() {
            self.regate(req);
            return;
        }
        if env.op_stale(req.op.osdmap_epoch) {
            self.scan.remove(&(req.conn, req.tid));
            self.copy_done_drop(&(req.conn, req.tid));
            self.c.stale += 1;
            self.note_dropped(&req);
            return;
        }
        let info = match self.precheck(env, &req) {
            Ok(i) => i,
            Err(e) => {
                self.c.errors += 1;
                self.scan.remove(&(req.conn, req.tid));
                // a fetched copy source of a re-run that ends here is not needed any more
                self.copy_done_drop(&(req.conn, req.tid));
                return self.reply_plain(env, &req, -e);
            }
        };
        if info.pg_op {
            return self.do_pg_op(env, req);
        }
        // precheck stopped before validation when a fence applies: decide it now, before any queuing or probing
        if (Self::failsafe_refuses(env, &req, &info) || env.pool_eio()) && {
            let reqid = req.op.effective_reqid(req.who, req.tid);
            self.fence(env, &req, &info, &reqid)
        } {
            self.scan.remove(&(req.conn, req.tid));
            self.copy_done_drop(&(req.conn, req.tid));
            return;
        }
        if let Some(write_gate) = parked_first(&self.parked_head, &mut self.c.parked_probes, &head)
            && !(write_gate && pure_read(&req.op))
        {
            self.c.parked_obj += 1;
            self.park(req, false);
            return;
        }
        if let Some(e) = self.objs.get_mut(&head) {
            // a dropped projected state (failed write, EC) is reloaded once nothing is in flight: everything waits
            let read_waits = (!info.may_write || e.state.is_none()) && e.inflight > 0;
            if e.copying && req.conn == COPY_CONN {
                // a copy's source read of an object a copy is writing into (its own clone, A<->B) never queues
                // behind the ops that copy blocks: they would wait for each other (copy.md 4.5)
                if read_waits {
                    e.waiters.push_front(req);
                    return;
                }
            } else if !e.waiters.is_empty() || e.copying || read_waits {
                e.waiters.push_back(req);
                return;
            }
        }
        self.execute_req(env, req, head, Some(info));
    }

    // ------------------------------------------------------------------ pg ops

    fn do_pg_op<E: Env>(&mut self, env: &mut E, mut req: ClientReq) {
        let key = (req.conn, req.tid);
        let (tries, since, mut run) = match self.scan.remove(&key) {
            Some(s) => (s.tries, s.since, s.pgls.map(|b| *b).unwrap_or_default()),
            None => {
                self.c.pg_ops += 1;
                (0, None, pgop::PgLsRun::default())
            }
        };
        self.waits.remove(&key);
        let spg = env.spg();
        let nspace = req.op.oloc.nspace.clone();
        let snapid = req.op.snapid;
        // adr 0021 S8: non-blocking and resumable like an object op's run; a refused run keeps its listing position
        let nb = tries < MAX_SCAN_TRIES;
        let examined = run.examined;
        env.ov_cause_begin();
        env.ov_read_session(Some(key), true);
        if self.holds_later(&req, 0) {
            env.ov_list_whole();
        }
        env.ov_nonblock(nb);
        let r = pgop::pg_ops(
            &*env,
            spg,
            env.pg_num(),
            &nspace,
            snapid,
            self.limits.max_pgls,
            &mut req.op.ops,
            &mut run,
        );
        env.ov_nonblock(false);
        let blocked = r.is_none();
        if !blocked && nb {
            let stray = env.ov_take_blocked();
            debug_assert!(!stray, "a PG op run swallowed a refused store read");
        }
        env.ov_read_session(None, blocked);
        let Some(r) = r else {
            let progressed = env.ov_take_progress() || run.examined > examined;
            let mut refused = Self::refusal(env, &req, tries, since, progressed);
            refused.pgls = Some(Box::new(run));
            self.park_scan(env, req, refused);
            return;
        };
        let lu = env.last_update();
        let luv = env.last_user_version();
        let mut rep = MOSDOpReply::for_request(&req.op, env.epoch());
        rep.result = r;
        if r >= 0 {
            let mut bad = lu;
            if luv != 0 {
                bad.version = luv;
            }
            rep.replay_version = lu;
            rep.user_version = luv;
            rep.bad_replay_version = bad;
        }
        fill_ops(&mut rep, &mut req.op.ops);
        self.push_reply(&req, Box::new(rep));
    }

    // ------------------------------------------------------------------ execution

    /// Run `req`; `info` = its classification (the caller's, when it already classified the message this run).
    fn execute_req<E: Env>(
        &mut self,
        env: &mut E,
        req: ClientReq,
        head: Hobject,
        info: Option<OpInfo>,
    ) {
        if self.copy_done.is_empty() {
            return self.execute_req_inner(env, req, head, info);
        }
        // a fetched copy source stays only while its message waits (parked / re-gated) for a later run
        let key = (req.conn, req.tid);
        self.execute_req_inner(env, req, head, info);
        let held = self
            .gate
            .iter()
            .chain(self.parked_obj.iter().map(|p| &p.req))
            .any(|r| (r.conn, r.tid) == key);
        if !held {
            self.copy_done_drop(&key);
        }
    }

    fn execute_req_inner<E: Env>(
        &mut self,
        env: &mut E,
        mut req: ClientReq,
        head: Hobject,
        info: Option<OpInfo>,
    ) {
        // refused non-blocking runs so far (taken here: every way out of this call but a new refusal ends the entry)
        let key = (req.conn, req.tid);
        let (tries, since, local_wait) = self
            .scan
            .remove(&key)
            .map_or((0, None, false), |s| (s.tries, s.since, s.local_wait));
        self.waits.remove(&key);
        if env.op_stale(req.op.osdmap_epoch) {
            self.c.stale += 1;
            self.note_dropped(&req);
            return;
        }
        // fencing again with the map of THIS run: per-object waiters (drain) and a finished copy-from source reach
        // here without the intake check, possibly after a map that blocklisted the client (classic requeues them
        // through do_op)
        if env.blocklisted(&req.addr) {
            return self.reply_err(env, &req, -errno::EBLOCKLISTED);
        }
        let spg = env.spg();
        let info = match info {
            Some(i) => i,
            None => {
                self.c.classify_calls += 1;
                match classify(&req.op, &self.classes) {
                    Ok(i) => i,
                    Err(e) => return self.reply_plain(env, &req, -e),
                }
            }
        };
        // internal ops are logged with the empty reqid (never indexed, never a dup: their tids restart with every
        // engine, a reused reqid would be answered from an old log entry instead of executed)
        let internal = req.session().is_none();
        let reqid = if internal {
            OsdReqId::default()
        } else {
            req.op.effective_reqid(req.who, req.tid)
        };
        env.run_start(&reqid);
        // ---- #11 - #13: full / failsafe / EIO fences (rechecked on every execution, waiters included)
        if self.fence(env, &req, &info, &reqid) {
            return;
        }
        // ---- missing / degraded object before dup detection (s5.4 rules 15-17): a resent write is answered only once
        // every copy of the object is back (a dup reply while degraded acknowledges data held by fewer copies)
        let missing = env.is_missing(&head);
        if missing || (info.rwordered && env.write_degraded(&head)) {
            // Object-level backoff (client-ops 16.6): an unfound head never recovers on its own, and with
            // osd_backoff_on_degraded a degraded one does not either -> BLOCK that object and drop the op (the client
            // holds it and resends after UNBLOCK) instead of retaining it here. Otherwise the op waits on the object.
            let backoff = if missing && env.is_unfound(&head) {
                self.limits.backoff_on_unfound || self.limits.backoff_on_degraded
            } else {
                self.limits.backoff_on_degraded
            };
            if backoff && let Some(conn) = req.session() {
                self.c.backoffs += 1;
                env.kick_recovery(&head);
                let (spg, epoch) = (self.spg, env.epoch());
                self.backoffs
                    .block_obj(spg, epoch, conn, &head, &mut self.out);
                self.note_dropped(&req);
                return;
            }
            self.c.parked_obj += 1;
            self.park(req, !missing);
            return;
        }
        // ---- dup detection (s5.6)
        if info.may_write && !internal {
            if let Some(tid) = self.by_reqid.get(&reqid).copied()
                && self.inflight.contains_key(&tid)
            {
                self.c.dups += 1;
                self.stamp(&req);
                if let Some(i) = self.inflight.get_mut(&tid) {
                    i.dups.push(req);
                }
                return;
            }
            if let Some((ver, uv, rc)) = env.find_reqid(&reqid) {
                self.c.dups += 1;
                return self.reply_dup(env, &req, &reqid, ver, uv, rc);
            }
        }
        // ---- object state: loaded non-blocking like the run below (adr 0021 am. 11): a cold onode / attribute page
        // refuses the load and re-gates the op on that page load instead of waiting for the device with the core
        env.eio_clear();
        let nb = local_wait || tries < MAX_SCAN_TRIES;
        env.ov_cause_begin();
        env.ov_nonblock(nb);
        let loaded = self.state_of(&*env, spg, &head, info.may_write);
        env.ov_nonblock(false);
        if env.ov_take_blocked() {
            return self.refused(env, req, tries, since, false);
        }
        let (mut st, st_gen) = match loaded {
            Ok(s) => s,
            Err(e) => {
                if e == errno::EIO && env.local_damage(&head, None) {
                    self.c.parked_repair += 1;
                    self.park(req, false);
                    return;
                }
                return self.reply_err(env, &req, -e);
            }
        };
        let now = env.mono();
        if let Some(oi) = &st.oi
            && !oi.watchers.is_empty()
        {
            let w: Vec<(WatchKey, u32, EntityAddr)> = oi
                .watchers
                .iter()
                .map(|(k, i)| (*k, i.timeout_seconds, i.addr))
                .collect();
            self.watch.populate(&head, &w, now);
        }
        let fast = crate::fast::overwrite(&*env, &mut req, &head, &reqid, &mut st, &self.limits);
        let (mut out, saved, dmg_hint) = if let Some(out) = fast {
            self.c.fast_writes += 1;
            (out, None, None)
        } else {
            // ---- snapshot context (writes)
            // (head reads need no removed-snaps set; the map's queue can hold ranges, keep that off the read path)
            let removed = if info.may_write
                || (req.op.snapid != opwire::NOSNAP && req.op.snapid != opwire::SNAPDIR)
            {
                env.removed_snaps()
            } else {
                Vec::new()
            };
            let mut snapc = SnapContext {
                seq: req.op.snap_seq,
                snaps: req.op.snaps.clone(),
            };
            if info.may_write {
                // pool-snap mode (rados mksnap): the POOL's snap context rules, the client's is ignored (client-ops 5.7.1)
                let pool_snapc = if req.op.flags & mflag::ENFORCE_SNAPC == 0 {
                    env.pool_snapc()
                } else {
                    None
                };
                if let Some(p) = pool_snapc {
                    snapc = p;
                } else {
                    if !snapc.is_valid() {
                        return self.reply_err(env, &req, -errno::EINVAL);
                    }
                    if !removed.is_empty() {
                        snapc
                            .snaps
                            .retain(|s| !crate::snap::is_removed(&removed, *s));
                    }
                }
                if req.op.flags & mflag::ORDERSNAP != 0 && snapc.seq < st.ss.seq {
                    return self.reply_err(env, &req, -errno::EOLDSNAPC);
                }
            }
            // ---- target (snap reads)
            let snapid = req.op.snapid;
            let clone_pre: ObjState;
            let (tgt, pre): (Hobject, &ObjState) =
                if info.may_write || snapid == opwire::NOSNAP || snapid == opwire::SNAPDIR {
                    (head.clone(), &st)
                } else {
                    match resolve_snap(&*env, spg, &head, &st, snapid, req.op.flags, &removed) {
                        Ok(Target::Head) => (head.clone(), &st),
                        Ok(Target::Clone(c, oi)) => {
                            clone_pre = ObjState {
                                oi: Some(oi),
                                ss: st.ss.clone(),
                                ss_stored: st.ss_stored,
                            };
                            (c, &clone_pre)
                        }
                        Ok(Target::None) => return self.reply_enoent_guard(env, &req),
                        Ok(Target::Damaged(c)) => {
                            // the clone's object_info is unreadable: repair it from a peer, the snap read waits (adr 0065)
                            if env.local_damage(&c, None) {
                                self.c.parked_repair += 1;
                                self.park(req, false);
                                return;
                            }
                            return self.reply_err(env, &req, -errno::EIO);
                        }
                        Err(e) => {
                            return self.reply_err(env, &req, -e);
                        }
                    }
                };
            // ---- ENOENT guard (#24)
            if !info.may_write {
                let gone = if snapid == opwire::SNAPDIR {
                    pre.oi.is_none()
                } else {
                    !pre.present()
                };
                if gone {
                    return self.reply_enoent_guard(env, &req);
                }
            }
            let (full, quota) = env.pool_full();
            let (write_bytes, write_entries) = admission_cost(&req.op.ops);
            let features = if req.op.features != 0 {
                req.op.features
            } else {
                req.features
            };
            let msg = Msg {
                spg,
                placement_read: req.placement_read.is_some() && req.op.placement_read_eligible(),
                source_pull_error: req.op.source_pull_error,
                head: head.clone(),
                flags: req.op.flags,
                snapid,
                snapc,
                reqid,
                mtime: req.op.mtime,
                now: env.wall(),
                caller: Caller {
                    name: req.who,
                    addr: req.addr,
                    features,
                },
                at_version: env.next_version(),
                last_user_version: env.last_user_version(),
                info: info.clone(),
                limits: self.limits,
                require_osd_release: env.require_osd_release(),
                connected: self.watch.connected_keys(&head),
                pool_full: full,
                pool_full_quota: quota,
                no_room: info.may_write
                    && !pure_shrink(&req.op.ops)
                    && !env.write_room(write_bytes, write_entries),
                removed_snaps: removed,
                copy: self.copy_done.get(&key).cloned(),
                ec_pool: env.ec_pool(),
                ec_caps: env.ec_caps(),
                // osdmap values only cls methods read: looked up for messages with a CALL op only
                cls_map: if info.cls.is_empty() {
                    crate::ClsMap::default()
                } else {
                    env.cls_map()
                },
            };
            // ---- run
            req.op.ops.iter_mut().for_each(OsdOp::reset_result);
            let saved = SavedOps::new(&req.op.ops);
            // ADR 0021 am. 11: run non-blocking: a cold store page (omap scan, cls read, RMW read) refuses the read instead of
            // spinning the core; the whole run is dropped (it only built an in-memory plan) and repeated after the load.
            let nb = local_wait || tries < MAX_SCAN_TRIES;
            env.ov_cause_begin();
            env.ov_read_session(Some((req.conn, req.tid)), true);
            if is_listing(&req.op) && self.holds_later(&req, 0) {
                env.ov_list_whole();
            }
            env.ov_nonblock(nb);
            let tgt_alt = (tgt != head).then(|| tgt.clone());
            let tgt_ver = pre.oi.as_ref().map(|o| o.version);
            let mut x = Exec::new(&*env, &msg, tgt, pre);
            x.copy_self = self.copy_self_op(&*env, &req, &head);
            let result = x.run(&mut req.op.ops);
            let mut out = x.finish(&mut req.op.ops, result);
            // a cls method's writes are not in the admission cost (its input only): check the real plan before any log
            // entry or repop; no room = the plain -ENOSPC of the admission check (adr 0021 S4, review F6)
            if out.disp == Disposition::Write
                && out.plan.room != (0, 0)
                && !env.write_room(out.plan.room.0 as usize, out.plan.room.1 as usize)
            {
                out.result = -errno::ENOSPC;
                out.disp = Disposition::Reply;
                out.plan = WritePlan::default();
                out.effects.clear();
            }
            env.ov_nonblock(false);
            // A blocking IO fallback can first encounter local ownership here.
            // Such a dependency MUST return to the executor, not become an EIO.
            let blocked = env.ov_take_blocked();
            env.ov_read_session(None, blocked);
            if blocked {
                // a refused run that advanced a resumable scan (listing slice, admitted data wait) made progress: not a try
                let progressed = env.ov_take_progress();
                saved.restore(&mut req.op.ops);
                return self.refused(env, req, tries, since, progressed);
            }
            if result == -errno::EINPROGRESS && self.needs_copy(&req) {
                // The prefix has passed its guards, but its planned mutations/effects remain uncommitted.
                // Fetch the source, then rerun the complete compound with that source installed.
                saved.restore(&mut req.op.ops);
                req.op.ops.iter_mut().for_each(OsdOp::reset_result);
                return self.copy_start(env, req);
            }
            (out, Some(saved), Some((tgt_alt, tgt_ver)))
        };
        // a read of a damaged local object: repair it from a peer and run the op again afterwards (classic: EIO on a
        // primary read marks the object missing, the op waits). Only a store / decode fault counts (checked by the PG).
        if out.result == -errno::EIO || req.op.ops.iter().any(|o| o.rval == -errno::EIO) {
            let (dmg_obj, dmg_ver) = match (out.damaged.take(), dmg_hint) {
                (Some(o), _) => (o, None),
                (None, Some((alt, ver))) => (alt.unwrap_or_else(|| head.clone()), ver),
                (None, None) => (head.clone(), None),
            };
            if env.local_damage(&dmg_obj, dmg_ver) {
                if let Some(s) = &saved {
                    s.restore(&mut req.op.ops);
                }
                req.op.ops.iter_mut().for_each(OsdOp::reset_result);
                self.c.parked_repair += 1;
                self.park(req, false);
                return;
            }
        }
        // Reply ops keep execution's echo; restore request opcodes and unions for a possible re-execution.
        let mut rops: Vec<OsdOp> = req
            .op
            .ops
            .iter_mut()
            .map(|o| {
                let mut e = o.echo();
                e.rval = o.rval;
                (
                    e.outdata,
                    e.outdata_crc,
                    e.outdata_more,
                    e.outdata_block_crcs,
                ) = o.take_outdata();
                e
            })
            .collect();
        if let Some(s) = &saved {
            s.restore(&mut req.op.ops);
        }
        let epoch = env.epoch();
        let mut rep = MOSDOpReply::for_request_ops(&req.op, epoch, Vec::new());
        rep.result = out.result;
        match out.disp {
            Disposition::Reply => {
                // a read (or a refused write) is answered now: its client io counts (spec pg-io-stats.md 1)
                if out.result >= 0 && !internal && !out.io.is_zero() {
                    env.note_io(&out.io);
                }
                self.c.reads += 1;
                if out.result >= 0 {
                    // a reply carries no log entry: report the current versions, no replay position
                    rep.set_versions(Eversion::default(), out.user_version);
                } else if !info.may_write {
                    rep.user_version = env.last_user_version();
                    rep.bad_replay_version = env.last_update();
                }
                // the oi only matters to watch effects (no copy on a plain read)
                let fin = if out.result >= 0 && !out.effects.is_empty() {
                    out.new_state.oi.take().or(st.oi.clone())
                } else {
                    None
                };
                let eff = std::mem::take(&mut out.effects);
                let ids = self.apply_effects(env, &req, &head, fin.as_ref(), eff, &mut rops);
                rep.ops = rops;
                self.push_reply(&req, Box::new(rep));
                for id in ids {
                    self.watch.check_complete(id, &mut self.out);
                }
            }
            Disposition::Drop => {
                // growing write to a full pool (step 5): no reply; the client resends after it learns the map
                self.scan.remove(&(req.conn, req.tid));
                self.copy_done_drop(&(req.conn, req.tid));
                self.c.full_drops += 1;
                self.note_dropped(&req);
            }
            Disposition::LogOnly | Disposition::Write => {
                self.c.writes += 1;
                let log_only = out.disp == Disposition::LogOnly;
                // a staged copy: this write renames its temp object into place (replicas forget it with it)
                let staged = if log_only {
                    None
                } else {
                    self.copy_done
                        .get(&(req.conn, req.tid))
                        .and_then(|c| c.staged.clone())
                };
                let wr = WriteReq {
                    reqid,
                    entries: std::mem::take(&mut out.plan.entries),
                    txn_middle: bytes::Bytes::new(),
                    txn_refs: if log_only {
                        Vec::new()
                    } else {
                        std::mem::take(&mut out.plan.txn_refs)
                    },
                    txn_ref_crcs: std::mem::take(&mut out.plan.txn_ref_crcs),
                    txn_data: if log_only {
                        replwire::Transaction::new()
                            .encode_v9()
                            .unwrap_or_default()
                            .into()
                    } else {
                        std::mem::take(&mut out.plan.txn)
                    },
                    discard_temp: staged.clone(),
                    ..Default::default()
                };
                let ver_first = env.next_version();
                let lu_before = env.last_update();
                match env.submit_write(wr) {
                    Ok(tid) => {
                        // a write's client io counts when it is submitted (spec pg-io-stats.md 1); a log-only entry
                        // (failed or no-op message) counts nothing
                        if !log_only && !internal && !out.io.is_zero() {
                            env.note_io(&out.io);
                        }
                        if staged.is_some() {
                            self.copy_done.remove(&(req.conn, req.tid));
                        }
                        // a log-only entry (failed or no-op message): its own version, the object unchanged
                        let (ver, uv, state) = if log_only {
                            let uv = if out.result < 0 {
                                env.last_user_version()
                            } else {
                                out.user_version
                            };
                            (ver_first, uv, st.clone())
                        } else {
                            if !out.keep_outdata {
                                for o in rops.iter_mut() {
                                    o.clear_outdata();
                                }
                            }
                            (
                                out.replay_version,
                                out.user_version,
                                std::mem::take(&mut out.new_state),
                            )
                        };
                        rep.set_versions(ver, uv);
                        if log_only && out.result < 0 {
                            self.c.errors += 1;
                            rep.bad_replay_version = lu_before;
                        }
                        rep.ops = rops;
                        // the post-write oi goes along only for watch effects at completion (failed messages carry
                        // none); the state moves into the object cache (no copy of oi + snapset per write)
                        let final_oi = if out.effects.is_empty() {
                            None
                        } else {
                            state.oi.clone()
                        };
                        let e = self.objs.entry(head.clone()).or_default();
                        e.inflight += 1;
                        if let Some(g) = st_gen {
                            e.gen_ = g;
                        }
                        e.state = Some(state);
                        if !internal {
                            self.by_reqid.insert(reqid, tid);
                        }
                        self.inflight.insert(
                            tid,
                            Inflight {
                                head,
                                reply: Box::new(rep),
                                effects: std::mem::take(&mut out.effects),
                                final_oi,
                                reqid,
                                version: ver,
                                user_version: uv,
                                rc: out.result,
                                dups: Vec::new(),
                                req,
                            },
                        );
                    }
                    Err(WriteErr::NotActive) => {
                        self.c.parked_gate += 1;
                        self.regate(req);
                        self.cold_only = false;
                    }
                    // scrub write block, an object of the write degraded / backfilling on a peer: a write-only gate,
                    // nothing of the write was logged, sent or applied (client-ops 5.4 #16)
                    Err(WriteErr::Degraded(_)) => {
                        self.c.parked_obj += 1;
                        self.park(req, true);
                    }
                    Err(WriteErr::TooBig(e)) => {
                        // the store can never apply this txn: plain error, no log entry, nothing cached
                        self.reply_err(env, &req, -e);
                    }
                    // the store's size check needs a metadata page that is loading or a parked txn of the PG (adr
                    // 0021 S8): nothing was logged, sent or applied; the op runs again after the wake, like a refused read
                    Err(WriteErr::Blocked) => {
                        self.c.writes -= 1;
                        let progressed = env.ov_take_progress();
                        self.refused(env, req, tries, since, progressed);
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------ completion

    /// `Action::WriteDone` from the PG.
    pub fn on_write_done<E: Env>(
        &mut self,
        env: &mut E,
        tid: u64,
        _version: Eversion,
        result: i32,
    ) {
        let _s = wprof::span(wprof::S::Opexec);
        if let Some(head) = self.trims.remove(&tid) {
            return self.trim_step_done(env, head, result);
        }
        if self.copy_stage_done(env, tid, result) {
            return self.copy_poll(env);
        }
        if result == -errno::EAGAIN && self.inflight.contains_key(&tid) {
            // aborted: only an interval change aborts writes, and it aborts all in flight. The PG resets the engine
            // before it delivers the aborts (they then find nothing here); one still in flight re-queues everything at
            // once in arrival order (per completion would put a later write ahead of an earlier one, and per-object
            // waiters would run on the aborted state)
            self.requeue_all();
            return self.copy_poll(env);
        }
        let Some(mut i) = self.inflight.remove(&tid) else {
            return;
        };
        self.by_reqid.remove(&i.reqid);
        let head = std::mem::take(&mut i.head);
        if result != 0 {
            // the backend failed the write for good (EC: a stripe it needed cannot be decoded): the client gets the
            // error, nothing was logged; its dups run again
            self.reply_plain(env, &i.req, result);
            self.cold_only = false;
            // the cached post-write state never happened: reload from the store once nothing is in flight (the backend
            // fails the later writes planned on top of it, EC ecprim)
            if let Some(e) = self.objs.get_mut(&head) {
                e.state = None;
            }
            // back among the gated ops where their arrival put them (not ahead of ops gated before them)
            for d in i.dups.drain(..) {
                let at = self
                    .stamps
                    .get(&(d.conn, d.tid))
                    .copied()
                    .unwrap_or(u64::MAX);
                let pos = self
                    .gate
                    .iter()
                    .position(|g| self.stamps.get(&(g.conn, g.tid)).is_some_and(|s| *s > at))
                    .unwrap_or(self.gate.len());
                self.note_gate_insert(pos, 1);
                self.gate.insert(pos, d);
            }
        } else {
            // effects at the completion point (s5.7 step 8), then the reply
            let mut rops = std::mem::take(&mut i.reply.ops);
            let eff = std::mem::take(&mut i.effects);
            let ids = self.apply_effects(env, &i.req, &head, i.final_oi.as_ref(), eff, &mut rops);
            i.reply.ops = rops;
            self.push_reply(&i.req, i.reply);
            for id in ids {
                self.watch.check_complete(id, &mut self.out);
            }
            // dups that arrived while this one was in flight: same answer
            for d in std::mem::take(&mut i.dups) {
                self.reply_dup(env, &d, &i.reqid, i.version, i.user_version, i.rc);
            }
        }
        // release the object
        self.drain_obj(env, &head, true);
        self.copy_poll(env);
    }

    /// A non-blocking state load or run of `req` was refused (cold store page): the op goes back to the gate, named by
    /// what the refused reads wait for (`ov_cause_begin` before the refused part), and runs again on that wake.
    fn refused<E: Env>(
        &mut self,
        env: &mut E,
        mut req: ClientReq,
        tries: u8,
        since: Option<Mono>,
        progressed: bool,
    ) {
        req.op.ops.iter_mut().for_each(OsdOp::reset_result);
        let refused = Self::refusal(env, &req, tries, since, progressed);
        self.park_scan(env, req, refused);
    }

    /// The scan entry of a refused run of `req` (`tries` / `since`: of its earlier refusals). The stuck detector counts
    /// from the op's first refusal: refused for `SCAN_STUCK_NS` since then, its next run is blocking (`WARNING TIMEOUT`).
    fn refusal<E: Env>(
        env: &E,
        req: &ClientReq,
        tries: u8,
        since: Option<Mono>,
        progressed: bool,
    ) -> Refused {
        let now = env.mono();
        let since = since.unwrap_or(now);
        let local_wait = env.ov_take_local_wait();
        let mut tries = tries
            .saturating_add(u8::from(!progressed && !local_wait))
            .min(MAX_SCAN_TRIES);
        if !local_wait && tries < MAX_SCAN_TRIES && now.saturating_sub(since) >= SCAN_STUCK_NS {
            eprintln!(
                "WARNING TIMEOUT refused op runs exceeded {}s (pg {:?}, client {}:{}, ops {:?}, {} runs without progress): next run blocking",
                SCAN_STUCK_NS / 1_000_000_000,
                env.spg(),
                req.conn,
                req.tid,
                req.op.ops.iter().map(|o| o.op).collect::<Vec<_>>(),
                tries
            );
            tries = MAX_SCAN_TRIES;
        }
        Refused {
            tries,
            since: Some(since),
            waiting: true,
            wakes: 0,
            progressed,
            local_wait,
            pgls: None,
        }
    }

    /// Park `req` (refused store read) under `refused`: remember what its reads wait for, back to the gate.
    fn park_scan<E: Env>(&mut self, env: &mut E, req: ClientReq, refused: Refused) {
        let key = (req.conn, req.tid);
        self.scan.insert(key, refused);
        let cause = env.ov_cause_take();
        if !cause.is_unknown() {
            self.waits.insert(key, cause);
        }
        self.c.parked_scan += 1;
        self.regate(req);
        self.cold_only = self.parked_obj.is_empty() && !self.backoffs.has_live();
    }

    /// State of `head` for an execution: the post-write state of its in-flight writes, else the object-state cache (a
    /// write takes the entry out: its post-write state comes back once the object is idle), else the store. Second
    /// value: the generation a state not taken from in-flight writes is valid for (0 = never cache it).
    fn state_of<E: Env>(
        &mut self,
        env: &E,
        spg: SpgT,
        head: &Hobject,
        write: bool,
    ) -> Result<(ObjState, Option<u64>), i32> {
        if let Some(e) = self.objs.get(head) {
            return match &e.state {
                Some(s) => Ok((s.clone(), None)),
                // unknown after a failed write, or a copy is filling the object: the store, uncached
                None => load_state(env, spg, head).map(|s| (s, Some(0))),
            };
        }
        let on = self.cache.sync(env.obj_cache());
        if let Some(g) = on {
            let hit = if write {
                self.cache.take(head)
            } else {
                self.cache.get_cloned(head)
            };
            if let Some(s) = hit {
                self.c.obj_hits += 1;
                #[cfg(debug_assertions)]
                verify_hit(env, spg, head, &s);
                return Ok((s, Some(g)));
            }
        }
        let s = load_state(env, spg, head)?;
        self.c.obj_misses += u64::from(on.is_some());
        if let Some(g) = on
            && !write
        {
            self.cache.put(head.clone(), s.clone());
            return Ok((s, Some(g)));
        }
        Ok((s, Some(on.unwrap_or(0))))
    }

    /// `head` became idle (nothing in flight, nobody waiting): its post-write state goes into the object-state cache
    /// while the PG is still at the generation the state started from.
    fn idle<E: Env>(&mut self, env: &E, head: Hobject, e: ObjEntry) {
        match e.state {
            Some(s) if e.gen_ != 0 && self.cache.sync(env.obj_cache()) == Some(e.gen_) => {
                self.cache.put(head, s)
            }
            _ => self.cache.remove(&head),
        }
    }

    /// Run the ops queued on `head` that may run now; an object left with nothing in flight and nobody waiting leaves
    /// the table. `released`: a write of the object finished (counted here: one lookup less than counting it apart).
    fn drain_obj<E: Env>(&mut self, env: &mut E, head: &Hobject, released: bool) {
        let mut released = released;
        // does the table entry qualify to leave, as the last pass of the loop saw it (`None`: not known, look again)
        let idle: Option<bool> = loop {
            let Some(e) = self.objs.get_mut(head) else {
                return;
            };
            if std::mem::take(&mut released) {
                e.inflight = e.inflight.saturating_sub(1);
            }
            let Some(front) = e.waiters.front() else {
                break Some(e.is_idle());
            };
            if e.copying && front.conn != COPY_CONN {
                break Some(false);
            }
            // an op of the object drained before was parked (degraded write, missing, repair): the rest queue behind
            // it there, never overtake it (a parked write and the ordered read after it). Pure reads pass a write-only
            // gate (`Parked::write_gate`): they stay here and wait only for the writes in flight.
            if let Some(write_gate) =
                parked_first(&self.parked_head, &mut self.c.parked_probes, head)
                && !(write_gate && pure_read(&front.op))
            {
                let (stay, park): (VecDeque<ClientReq>, VecDeque<ClientReq>) = e
                    .waiters
                    .drain(..)
                    .partition(|w| write_gate && pure_read(&w.op));
                self.c.parked_obj += park.len() as u64;
                // field-wise (the object entry `e` stays borrowed); every waiter here is an op of `head`
                if !park.is_empty() {
                    self.parked_head.entry(head.clone()).or_insert(false);
                }
                self.parked_obj.extend(park.into_iter().map(|req| Parked {
                    req,
                    write_gate: false,
                }));
                e.waiters = stay;
                if e.waiters.is_empty() {
                    break Some(e.is_idle());
                }
                continue; // a pure read is in front now
            }
            // one classification for the object's ordering decision and for the run itself (`None`: an error reply)
            self.c.classify_calls += 1;
            let info = classify(&front.op, &self.classes).ok();
            let writes = info.as_ref().is_some_and(|i| i.may_write);
            // reads wait for the writes in flight; everything waits while the state is unknown (a write failed)
            if (!writes || e.state.is_none()) && e.inflight > 0 {
                break Some(false);
            }
            let Some(r) = e.waiters.pop_front() else {
                break None;
            };
            // EC: a read that queued here was warmed before the writes ahead of it ran (they dropped the decoded
            // cache): warm it again at the gate, the object's later ops stay behind it
            if env.ec_pool()
                && (!writes || r.op.ops.iter().any(|o| Self::ec_omap_read(o.op)))
                && Self::cold(env, &r, head)
            {
                self.regate(r);
                break None;
            }
            self.execute_req(env, r, head.clone(), info);
        };
        if idle.unwrap_or_else(|| self.objs.get(head).is_some_and(ObjEntry::is_idle)) {
            let Some((k, e)) = self.objs.remove_entry(head) else {
                return;
            };
            self.idle(env, k, e);
        }
    }

    /// Note the arrival of an op that waits (gated, or a dup of an in-flight write); an op keeps its first stamp.
    fn stamp(&mut self, r: &ClientReq) {
        if self.stamps.len() > 2 * self.gate.len() + 256 {
            let live: std::collections::HashSet<(u64, u64)> = self
                .gate
                .iter()
                .chain(self.inflight.values().flat_map(|i| i.dups.iter()))
                .map(|g| (g.conn, g.tid))
                .collect();
            self.stamps.retain(|k, _| live.contains(k));
        }
        self.arrival += 1;
        self.stamps.entry((r.conn, r.tid)).or_insert(self.arrival);
    }

    /// Park `req` on its object until the PG retries (recovery, scrub, repair progress); see [`Parked::write_gate`].
    /// The parked set is bounded (`MAX_PARKED`): beyond it the head gets an object-level BLOCK and the op is dropped,
    /// so a client cannot make the OSD retain an unbounded number of messages with payload (client-ops 16.6).
    fn park(&mut self, req: ClientReq, write_gate: bool) {
        if self.parked_obj.len() >= MAX_PARKED
            && let Some(conn) = req.session()
        {
            let head = head_of(&req.op);
            self.c.backoffs += 1;
            self.backoffs
                .block_obj(self.spg, self.last_epoch, conn, &head, &mut self.out);
            self.note_dropped(&req);
            return;
        }
        self.park_push(Parked { req, write_gate });
    }

    /// Append a parked op; the first op of a head decides the `write_gate` later arrivals of the object see.
    fn park_push(&mut self, p: Parked) {
        self.parked_head
            .entry(head_of(&p.req.op))
            .or_insert(p.write_gate);
        self.parked_obj.push(p);
    }

    /// Put an op that already left the gate back at its front (a refused non-blocking run, a PG that stopped being
    /// active) and keep the object's later ops behind it: its per-object waiters would otherwise run next (drain loop)
    /// and overtake it (ADR 0043 am. 1, per-object order).
    fn regate(&mut self, req: ClientReq) {
        let head = head_of(&req.op);
        let inserted = 1 + self.objs.get(&head).map_or(0, |e| e.waiters.len());
        self.note_gate_insert(0, inserted);
        self.gate.push_front(req);
        if let Some(e) = self.objs.get_mut(&head) {
            for (j, w) in e.waiters.drain(..).enumerate() {
                self.gate.insert(1 + j, w);
            }
        }
        self.gate_cap = self.gate_cap.max(self.gate.len());
    }

    /// Preserve the next unvisited op when a callback inserts before a pending sweep.
    fn note_gate_insert(&mut self, pos: usize, count: usize) {
        if let Some(from) = &mut self.retry_from
            && pos <= *from
        {
            *from += count;
            self.retry_wrap = true;
        }
    }

    // ------------------------------------------------------------------ effects (watch / notify)

    fn apply_effects<E: Env>(
        &mut self,
        env: &E,
        req: &ClientReq,
        head: &Hobject,
        oi: Option<&ObjectInfo>,
        effects: Vec<Effect>,
        rops: &mut [OsdOp],
    ) -> Vec<u64> {
        let now = env.mono();
        let mut ids = Vec::new();
        for e in effects {
            match e {
                Effect::WatchConnect {
                    key,
                    timeout,
                    will_ping,
                    addr,
                } => self.watch.connect(
                    head,
                    key,
                    env.conn_open(req.conn).then_some(req.conn),
                    addr,
                    timeout,
                    will_ping,
                    now,
                    &mut self.out,
                ),
                Effect::WatchPing { key } => self.watch.ping(head, &key, now),
                Effect::WatchRemove { key } => self.watch.remove(head, &key, false, &mut self.out),
                Effect::WatchRemoveAll => self.watch.remove_all(head, &mut self.out),
                Effect::Notify {
                    op_index,
                    cookie,
                    timeout,
                    payload,
                } => {
                    let (watchers, ver): (Vec<WatchKey>, u64) = oi.map_or((Vec::new(), 0), |o| {
                        (o.watchers.keys().copied().collect(), o.user_version)
                    });
                    let id = self.watch.notify(
                        env.epoch(),
                        head,
                        &watchers,
                        req.conn,
                        req.who.num as u64,
                        cookie,
                        payload,
                        timeout,
                        ver,
                        now,
                        &mut self.out,
                    );
                    if let Some(o) = rops.get_mut(op_index) {
                        o.outdata = id.to_le_bytes().to_vec().into();
                    }
                    ids.push(id);
                }
                Effect::NotifyAck {
                    notify_id,
                    cookie,
                    reply,
                    legacy,
                } => self.watch.ack(
                    head,
                    req.who,
                    notify_id,
                    cookie,
                    legacy,
                    reply,
                    &mut self.out,
                ),
            }
        }
        ids
    }

    // ------------------------------------------------------------------ timers / events

    pub fn next_deadline(&self) -> Option<Mono> {
        let w = self.watch.next_deadline();
        let t = (self.trim.wake_at != 0).then_some(self.trim.wake_at);
        let c = self.copies.values().map(|c| c.deadline).min();
        let q = (self.copy_wake != 0).then_some(self.copy_wake);
        [w, t, c, q].into_iter().flatten().min()
    }

    /// Run watch/notify timers: expired watchers are removed through a PG write (oi update), expired notifies
    /// complete with ETIMEDOUT.
    pub fn tick<E: Env>(&mut self, env: &mut E, now: Mono) {
        let dead = self.watch.tick(now, &mut self.out);
        for (h, k) in dead {
            self.drop_watcher(env, h, k);
        }
        if self.trim.wake_at != 0 && now >= self.trim.wake_at {
            self.trim.wake_at = 0;
            self.trim_drive(env);
        }
        self.copy_expire(env, now);
        self.copy_retry_wait(env, now);
        self.copy_poll(env);
    }

    /// Osdmap changed: watchers whose address got blocklisted go away at once.
    pub fn check_blocklist<E: Env>(&mut self, env: &mut E) {
        // parked ops of blocklisted clients are refused now, not whenever they next get to run
        let mut dead: Vec<ClientReq> = Vec::new();
        let mut keep = VecDeque::new();
        // pg ops (listings) are not fenced (classic order, see precheck)
        let fenced = |r: &ClientReq| {
            env.blocklisted(&r.addr) && !classify(&r.op, &self.classes).is_ok_and(|i| i.pg_op)
        };
        let mut removed_before_cursor = 0;
        for (index, r) in std::mem::take(&mut self.gate).into_iter().enumerate() {
            if fenced(&r) {
                removed_before_cursor +=
                    usize::from(self.retry_from.is_some_and(|from| index < from));
                dead.push(r)
            } else {
                keep.push_back(r)
            }
        }
        self.gate = keep;
        if let Some(from) = &mut self.retry_from {
            *from -= removed_before_cursor;
        }
        let parked = std::mem::take(&mut self.parked_obj);
        self.parked_head.clear();
        for p in parked {
            if fenced(&p.req) {
                dead.push(p.req)
            } else {
                // field-wise (the `fenced` closure holds `self.classes`): same push as `park_push`
                self.parked_head
                    .entry(head_of(&p.req.op))
                    .or_insert(p.write_gate);
                self.parked_obj.push(p)
            }
        }
        for r in dead {
            self.scan.remove(&(r.conn, r.tid));
            self.waits.remove(&(r.conn, r.tid));
            self.copy_done_drop(&(r.conn, r.tid));
            self.reply_err(env, &r, -errno::EBLOCKLISTED);
        }
        let dead = self.watch.matching(|a| env.blocklisted(a));
        for (h, k) in dead {
            self.drop_watcher(env, h, k);
        }
    }

    fn drop_watcher<E: Env>(&mut self, env: &mut E, head: Hobject, key: WatchKey) {
        self.watch.remove(&head, &key, true, &mut self.out);
        self.internal_tid += 1;
        let mut op = MOSDOp {
            pgid: env.spg(),
            hash: head.hash,
            osdmap_epoch: env.epoch(),
            // an OSD-internal maintenance write: passes a full pool like classic's watch-timeout update
            flags: mflag::WRITE | mflag::ONDISK | mflag::FULL_FORCE,
            oid: head.oid.clone(),
            ops: vec![OsdOp::watch_op(key.0, opwire::consts::watch_op::UNWATCH, 0)],
            ..Default::default()
        };
        op.oloc.pool = head.pool;
        op.oloc.nspace = head.nspace.clone();
        op.oloc.key = head.key.clone();
        let req = ClientReq {
            placement_read: None,
            conn: INTERNAL_CONN,
            caps: None,
            tid: (1 << 63) | self.internal_tid,
            op: Box::new(op),
            who: key.1,
            addr: EntityAddr::default(),
            peer_addr: EntityAddr::default(),
            features: 0,
        };
        self.on_op(env, req);
    }

    /// A connection closed. Returns whether a timer or the parked state of this engine changed (the caller refreshes
    /// its deadline index and parked sets).
    pub fn conn_closed(&mut self, conn: u64, now: Mono) -> bool {
        let backoffs = self.backoffs.conn_closed(conn);
        self.watch.conn_closed(conn, now) | backoffs
    }

    /// MOSDBackoff ACK_BLOCK from a client (any PG state, s6.2).
    pub fn on_backoff_ack(&mut self, conn: u64, m: &MOSDBackoff) {
        if m.op == opwire::consts::backoff::ACK_BLOCK {
            self.backoffs.ack(conn, m.id, &m.begin);
        }
    }

    // ------------------------------------------------------------------ replies

    fn push_reply(&mut self, req: &ClientReq, reply: Box<MOSDOpReply>) {
        // the counter class comes from the request's op codes (spec ops-observability.md 2d), also when the reply is
        // an error: the accounting decides on the reply result
        let class = opwire::OpClass::of(&req.op.ops, &|c, m| clsx::flags(c, m).ok());
        self.out.push(Out::Reply {
            conn: req.conn,
            tid: req.tid,
            placement_read: req.placement_read,
            class,
            reply,
        });
    }

    fn reply_plain<E: Env>(&mut self, env: &E, req: &ClientReq, result: i32) {
        let mut rep = MOSDOpReply::for_request(&req.op, env.epoch());
        rep.result = result;
        self.push_reply(req, Box::new(rep));
    }

    /// Error reply that counts as a failed op.
    fn reply_err<E: Env>(&mut self, env: &E, req: &ClientReq, result: i32) {
        self.c.errors += 1;
        self.reply_plain(env, req, result);
    }

    /// ENOENT guard reply (client-ops 5.4 #24 + s15): flags echoed unchanged, all versions zero, rvals 0.
    fn reply_enoent_guard<E: Env>(&mut self, env: &E, req: &ClientReq) {
        let mut rep = MOSDOpReply::for_request(&req.op, env.epoch());
        rep.result = -errno::ENOENT;
        rep.flags = u64::from(req.op.flags);
        self.push_reply(req, Box::new(rep));
    }

    fn reply_dup<E: Env>(
        &mut self,
        env: &E,
        req: &ClientReq,
        reqid: &OsdReqId,
        ver: Eversion,
        uv: u64,
        rc: i32,
    ) {
        let mut rep = MOSDOpReply::for_request(&req.op, env.epoch());
        rep.result = rc;
        rep.set_versions(ver, uv);
        // replay (G24): the original per-op rvals and outdata come from the log whenever it has them (RETURNVEC
        // writes and every failed write), whatever the resend's flags say (classic `reply_op_error` + set_op_returns)
        {
            let opr = env.dup_op_returns(reqid);
            if !opr.is_empty() && opr.len() == rep.ops.len() {
                for (r, o) in rep.ops.iter_mut().zip(opr) {
                    r.rval = o.rval;
                    r.outdata = o.outdata.into();
                }
            }
        }
        self.push_reply(req, Box::new(rep));
    }
}

/// Copy rval/outdata of executed ops into the reply echo (pg ops).
fn fill_ops(rep: &mut MOSDOpReply, ops: &mut [OsdOp]) {
    for (r, o) in rep.ops.iter_mut().zip(ops.iter_mut()) {
        r.rval = o.rval;
        (
            r.outdata,
            r.outdata_crc,
            r.outdata_more,
            r.outdata_block_crcs,
        ) = o.take_outdata();
    }
}

// ---------------------------------------------------------------------------------------------------- snap trimmer

/// Why a step was not submitted.
enum StepFail {
    /// Inconsistent snap metadata: SNAPTRIM_ERROR.
    Fatal(String),
    /// Not active / object missing on a peer: try again later (the reason, reported once per wait).
    Later(String),
    /// The stale mapper entry was dropped: nothing to do for this clone.
    Skipped,
}

impl Engine {
    /// The PG says the trimmer may run (or continue). Idempotent.
    pub fn trim_kick<E: Env>(&mut self, env: &mut E) {
        self.last_epoch = env.epoch();
        self.trim_drive(env);
    }

    /// A step's repop finished (`result != 0`: aborted by an interval change, or failed by the backend).
    fn trim_step_done<E: Env>(&mut self, env: &mut E, head: Hobject, result: i32) {
        if result != 0 {
            // the head state the step projected never happened: reload once nothing is in flight (a failed client
            // write does the same)
            if let Some(e) = self.objs.get_mut(&head) {
                e.state = None;
            }
            self.trim.aborted = true;
        }
        self.drain_obj(env, &head, true);
        if !self.trims.is_empty() {
            return;
        }
        if self.trim.error {
            self.trim = TrimRun::default();
            env.trim_stop(true);
        } else if self.trim.aborted {
            self.trim = TrimRun::default();
            env.trim_stop(false);
        } else {
            let sleep = env.trim_cfg().sleep_ns;
            if sleep > 0 {
                self.trim.wake_at = env.mono() + sleep;
            } else {
                self.trim_drive(env);
            }
        }
    }

    /// One round: next snap, up to `max_concurrent` clones of it, one logged repop per clone.
    fn trim_drive<E: Env>(&mut self, env: &mut E) {
        if !self.trims.is_empty() {
            return; // the round in flight continues when its steps finish
        }
        if self.trim.wake_at != 0 {
            if env.mono() < self.trim.wake_at {
                return;
            }
            self.trim.wake_at = 0;
        }
        for _ in 0..64 {
            let snap = match env.trim_poll() {
                peering::TrimPoll::Go(s) => s,
                _ => return,
            };
            let cfg = env.trim_cfg();
            let clones = match env.snap_mapper_next(snap, cfg.max_concurrent.max(1)) {
                Ok(c) => c,
                Err(e) => {
                    self.c.trim_errors += 1;
                    env.trim_note(format!(
                        "snap trim of snap {snap:#x}: mapper unreadable ({e:?}), not marked purged"
                    ));
                    self.trim = TrimRun::default();
                    env.trim_stop(true);
                    return;
                }
            };
            if clones.is_empty() {
                env.trim_snap_done(snap);
                continue; // same run, next snap
            }
            let queue = peering::snaps::iv_from_pairs(&env.removed_snaps());
            let (mut submitted, mut skipped) = (0usize, 0usize);
            for c in &clones {
                match self.trim_one(env, snap, c, &queue) {
                    Ok(()) => submitted += 1,
                    Err(StepFail::Skipped) => skipped += 1,
                    Err(StepFail::Later(why)) => {
                        if !self.trim.blocked_noted {
                            self.trim.blocked_noted = true;
                            env.trim_note(why);
                        }
                        break;
                    }
                    Err(StepFail::Fatal(m)) => {
                        self.c.trim_errors += 1;
                        env.trim_note(m);
                        self.trim.error = true;
                        break;
                    }
                }
            }
            if self.trim.error {
                if self.trims.is_empty() {
                    self.trim = TrimRun::default();
                    env.trim_stop(true);
                }
                return;
            }
            if submitted > 0 {
                return;
            }
            if skipped == 0 {
                // nothing could start (not active, object degraded; reported above once per wait): retry each second
                env.trim_stop(false);
                self.trim.wake_at = env.mono() + peering::SEC;
                return;
            }
        }
        // a pathological run of stale entries: yield, continue at the next tick
        self.trim.wake_at = env.mono() + 1_000_000;
    }

    fn trim_one<E: Env>(
        &mut self,
        env: &mut E,
        snap: u64,
        clone: &Hobject,
        queue: &peering::snaps::Ivs,
    ) -> Result<(), StepFail> {
        let spg = env.spg();
        let mut head = clone.clone();
        head.snap = SnapId::NOSNAP;
        let what = |m: &str| {
            format!(
                "pg {spg}: snap trim of {}: {m}, repair needed",
                obj_name(clone)
            )
        };
        let st = match self.objs.get(&head) {
            Some(ObjEntry { state: Some(s), .. }) => s.clone(),
            // a failed write dropped the projected state while later writes of the head are in flight: the store does
            // not hold them yet, a step planned from it would revert their object info and SnapSet. Wait for the drain
            // (the read gate's rule); the next round loads the state again.
            Some(e) if e.inflight > 0 => {
                return Err(StepFail::Later(format!(
                    "pg {spg}: snap trim of {} waits: writes of the head in flight after a failed write",
                    obj_name(clone)
                )));
            }
            _ => load_state(env, spg, &head)
                .map_err(|e| StepFail::Fatal(what(&format!("head unreadable (errno {e})"))))?,
        };
        let coi = crate::exec::load_oi(env, spg, clone)
            .map_err(|e| StepFail::Fatal(what(&format!("clone unreadable (errno {e})"))))?;
        let Some(coi) = coi else {
            if !st.ss.clones.contains(&clone.snap) {
                // stale mapping: the object and its SnapSet entry are gone; drop it (spec 11)
                env.trim_unmap(clone);
                return Err(StepFail::Skipped);
            }
            return Err(StepFail::Fatal(what("clone object missing")));
        };
        let Some(hoi) = st.oi.as_ref() else {
            return Err(StepFail::Fatal(what("head object missing")));
        };
        let step = crate::trim::plan_step(&crate::trim::StepIn {
            head: &head,
            clone,
            snap,
            queue,
            head_oi: hoi,
            ss: &st.ss,
            clone_oi: &coi,
            now: env.wall(),
            v: env.next_version(),
        })
        .map_err(|e| StepFail::Fatal(what(e.text())))?;
        let (txn, txn_refs, _) = crate::exec::encode_txn(spg, &step.txn, &[], false)
            .map_err(|_| StepFail::Fatal(what("transaction encode failed")))?;
        let wr = WriteReq {
            reqid: OsdReqId::default(),
            entries: step.entries,
            txn_middle: bytes::Bytes::new(),
            txn_data: txn,
            txn_refs,
            ..Default::default()
        };
        match env.submit_write(wr) {
            Ok(tid) => {
                self.c.trim_steps += 1;
                self.trim.blocked_noted = false;
                let e = self.objs.entry(head.clone()).or_default();
                e.inflight += 1;
                e.gen_ = 0; // a trimmed head is not cached (adr 0160 D5: coarse)
                e.state = Some(ObjState {
                    oi: step.head_oi,
                    ss: if step.head_deleted {
                        replwire::SnapSet::default()
                    } else {
                        step.ss
                    },
                    ss_stored: !step.head_deleted,
                });
                self.trims.insert(tid, head);
                env.trim_counted(i64::from(step.clone_deleted) + i64::from(step.head_deleted));
                Ok(())
            }
            Err(WriteErr::TooBig(e)) => Err(StepFail::Fatal(what(&format!(
                "trim transaction refused by the store (errno {e})"
            )))),
            Err(WriteErr::NotActive) => Err(StepFail::Later(format!(
                "pg {spg}: snap trim of {} waits: PG not active",
                obj_name(clone)
            ))),
            Err(WriteErr::Degraded(o)) => Err(StepFail::Later(format!(
                "pg {spg}: snap trim of {} waits: object {} degraded",
                obj_name(clone),
                obj_name(&o)
            ))),
            Err(WriteErr::Blocked) => Err(StepFail::Later(format!(
                "pg {spg}: snap trim of {} waits: store pages loading",
                obj_name(clone)
            ))),
        }
    }
}

fn obj_name(h: &Hobject) -> String {
    format!("{}:{:x}", String::from_utf8_lossy(&h.oid), h.snap.0)
}

/// Sound upper bound of the store's name key of an object: 46 fixed bytes plus 2 per byte (NUL-escaping) of the
/// namespace, the effective key (the oid when there is no locator) and the oid.
pub fn name_key_upper_bound(oid: &[u8], key: &[u8], nspace: &[u8]) -> usize {
    let eff = if key.is_empty() { oid.len() } else { key.len() };
    46 + 2 * (oid.len() + eff + nspace.len())
}

/// Request opcodes and unions, kept to rerun a message after refusal, repair or an aborted write. Execution may
/// rewrite ZERO to TRUNCATE when it reaches the working EOF; a later run must reevaluate the original ZERO range.
/// Up to four ops inline, no heap.
struct SavedOps {
    inline: [(u16, [u8; opwire::UNION_LEN]); 4],
    more: Vec<(u16, [u8; opwire::UNION_LEN])>,
}

impl SavedOps {
    fn new(ops: &[OsdOp]) -> Self {
        let mut inline = [(0, [0u8; opwire::UNION_LEN]); 4];
        for (d, o) in inline.iter_mut().zip(ops) {
            *d = (o.op, o.u);
        }
        SavedOps {
            inline,
            more: ops.iter().skip(4).map(|o| (o.op, o.u)).collect(),
        }
    }

    fn restore(&self, ops: &mut [OsdOp]) {
        for (i, o) in ops.iter_mut().enumerate() {
            (o.op, o.u) = if i < 4 {
                self.inline[i]
            } else {
                self.more[i - 4]
            };
        }
    }
}

/// Admission cost of a write for [`Env::write_room`] (adr 0021 am. 45): (expanded payload bytes, omap / xattr entries it sets or
/// removes). Random keys each dirty a leaf of their own (a 1024-key `omap-set-vals` of 330 KiB payload dirtied ~1000
/// pages, the payload estimate admitted 83): an underestimate admits a txn the store then refuses with NoSpace, which
/// is fatal for the PG.
pub(crate) fn admission_cost(ops: &[OsdOp]) -> (usize, usize) {
    ops.iter()
        .map(|o| {
            let entries = match o.op {
                code::OMAP_SET_VALS | code::OMAP_RM_KEYS | code::SETXATTRS => o
                    .indata
                    .get(..4)
                    .map_or(1, |b| u32::from_le_bytes(b.try_into().unwrap()) as usize),
                code::SETXATTR | code::RMXATTR | code::OMAP_SET_HEADER | code::OMAP_CLEAR => 1,
                _ => 0,
            };
            let bytes = if o.op == code::WRITESAME {
                // The wire carries only the pattern; the store must allocate the whole repeated extent.
                usize::try_from(o.write_same().length)
                    .unwrap_or(usize::MAX)
                    .max(o.indata.len())
            } else {
                o.indata.len()
            };
            (bytes, entries.min(o.indata.len()))
        })
        .fold((0usize, 0usize), |a, (b, e)| {
            (a.0.saturating_add(b), a.1.saturating_add(e))
        })
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    #[test]
    fn admission_cost_counts_omap_and_xattr_entries() {
        let m: BTreeMap<Vec<u8>, Vec<u8>> = (0..1024u32)
            .map(|i| (i.to_be_bytes().repeat(16), vec![7u8; 256]))
            .collect();
        let set = OsdOp::omap_set_vals(&m);
        let (b, e) = admission_cost(&[
            set.clone(),
            OsdOp::setxattr(b"_", b"v"),
            OsdOp::write(0, vec![1; 8192]),
        ]);
        assert_eq!(e, 1024 + 1);
        assert_eq!(
            b,
            set.indata.len() + OsdOp::setxattr(b"_", b"v").indata.len() + 8192
        );
        // a hostile count never exceeds the payload bytes
        let mut bad = OsdOp::omap_set_vals(&BTreeMap::new());
        let mut d = bad.indata.to_vec();
        d[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        bad.indata = d.into();
        assert!(admission_cost(&[bad]).1 <= 4);
    }
}
