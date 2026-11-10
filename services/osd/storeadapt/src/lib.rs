// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! storeadapt: the NVMe object store (crate `store`, L2) behind the PG machinery's seam,
//! `peering::PgStoreOps` (adr 0008, spec replication.md 1/4/6, peering.md).
//!
//! * One PG = collection `Pg(spg)`; its pgmeta object carries the PG's durable state as omap keys (spec 4.1,
//!   local format, see [`meta`]). Objects of the PG, incl. recovery temp objects, live in the same collection
//!   (temp objects are told apart by their pool, as in hobject order they sort first).
//! * A `StoreTxn` (info + log + missing + object ops) is ONE `store::obj::OTxn` = one atomic WAL record.
//! * [`apply`] maps every `replwire::TxnOp`; unsupported ops fail loudly (`Err`), nothing is applied.
//! * `RemovePg` is the only multi-txn operation (chunked deletion behind a durable `_remove` marker).
//!
//! The adapter is single-threaded (`RefCell`): the owner core drives it. `submit` blocks until the txn is
//! durable (the OSD core will use `Store::queue` + completion later).

pub mod apply;
pub mod dedup;
pub mod meta;
pub mod migrate;
pub mod reformat;
pub mod scrub;
pub mod snapmap;
pub mod split;
pub mod view;

use denc::errno::{EIO, ENOENT};
use denc::types::{CollT, Eversion, Ghobject, Hobject, SpgT};
use opexec::view::gate_why;
use peering::WriteErr;
use peering::store::{
    MemObj, PersistedPg, PgStoreOps, Queued, ShardSpace, StoreOp, StoreReadError, StoreTxn,
};
use replwire::{ObjectInfo, ObjectRecoveryInfo, ObjectRecoveryProgress, PushOp, SnapSet};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;
use store::dev::{BlockDev, Clock};
use store::obj::{OTxn, ObjError, Store, TOp};

pub use store::obj::ObjError as Error;

pub fn pg_coll(spg: SpgT) -> CollT {
    CollT::Pg(spg)
}
pub fn temp_coll(spg: SpgT) -> CollT {
    CollT::PgTemp(spg)
}
/// pgmeta object of a PG.
pub fn pgmeta(spg: SpgT) -> Ghobject {
    Ghobject::pgmeta(spg.pgid.pool as i64, spg.pgid.seed, spg.shard)
}
pub fn gh(spg: SpgT, h: &Hobject) -> Ghobject {
    Ghobject::new(h.clone(), Ghobject::NO_GEN, spg.shard)
}
/// A user object of the PG: not a temp object, not pgmeta (nor the SnapMapper object), no stash generation.
pub(crate) fn is_user_object(g: &Ghobject) -> bool {
    !g.hobj.is_temp() && !g.is_pgmeta() && g.generation == Ghobject::NO_GEN
}

/// Objects removed per txn when deleting a PG (osd_target_transaction_size, spec peering 7.5).
pub const REMOVE_BATCH: usize = 24;

/// The smallest key strictly greater than `k`: where a listing that resumes after `k` starts, or
/// the exclusive end of a range that ends at `k` inclusive.
pub(crate) fn key_after(mut k: Vec<u8>) -> Vec<u8> {
    k.push(0);
    k
}

/// Store error -> negative errno of the EC shard reads: absent object = -ENOENT, anything else
/// (a missing collection included) = -EIO. (The replicated read view maps differently: view.rs.)
fn errno(e: ObjError) -> i32 {
    if e == ObjError::NoEnt { -ENOENT } else { -EIO }
}

fn peering_meta_growth_failure(
    f: store::shard::MetaGrowthFailure,
) -> peering::store::MetaGrowthFailure {
    peering::store::MetaGrowthFailure {
        sequence: f.sequence,
        reason: match f.reason {
            store::shard::MetaGrowthFailureReason::ImageLimit => "image_limit",
            store::shard::MetaGrowthFailureReason::InsufficientFreeBlocks => {
                "insufficient_free_blocks"
            }
            store::shard::MetaGrowthFailureReason::NoContiguousRun => "no_contiguous_run",
        },
        unix_time_ns: f.unix_time_ns,
        store_poll_time_ns: f.store_poll_time_ns,
        requested_free_pages: f.requested_free_pages,
        free_meta_pages: f.free_meta_pages,
        cell_blocks: f.cell_blocks,
        pages_per_cell: f.pages_per_cell,
        free_data_blocks: f.free_data_blocks,
        held_data_blocks: f.held_data_blocks,
        reserved_data_blocks: f.reserved_data_blocks,
        reserve_data_blocks: f.reserve_data_blocks,
        image_bytes: f.image_bytes,
        image_reserve_bytes: f.image_reserve_bytes,
        deferred_image_bytes: f.deferred_image_bytes,
        image_needed_bytes: f.image_needed_bytes,
        image_limit_bytes: f.image_limit_bytes,
        free_windows: f.free_windows,
    }
}
/// A deletion txn queued in the store and not yet durable: store token, PG, objects in it, closes the PG (`step_removals`).
#[derive(Clone, Copy, Debug)]
struct RmFlight {
    tok: u64,
    spg: SpgT,
    objs: u64,
    last: bool,
}
/// Back-off after a deletion txn of a single object hit NoSpace.
const REMOVE_RETRY_NS: u64 = 1_000_000_000;
/// Txns waiting for the deletion of their PG (`deferred`) above which the store fails (a wedge, not a slow deletion).
const DEFERRED_MAX: usize = 4096;
/// Wire bytes of a client txn below which `check_write` returns at once (cannot reach the store size limits).
const CHECK_MIN_WIRE: usize = 64 << 10;

pub struct StoreAdapter<D: BlockDev, C: Clock> {
    /// Shared with the OSD's meta store (same device; single owner thread, never borrowed re-entrantly).
    st: Rc<RefCell<Store<D, C>>>,
    /// Mutations addressed to a PG that does not exist: dropped (like `MemStore`) and failing the store (review
    /// 2026-11-03 #10).
    pub orphan_writes: Rc<Cell<u64>>,
    /// Operator-visible notes (slow or large structural operations), drained by the OSD.
    pub notes: RefCell<Vec<String>>,
    /// Scratch of `take_wake_set`, kept: a stack `Toks` is zero-filled (258 B memset) on every poll spin.
    wake_toks: store::toks::Toks<32>,
    /// Objects moved / copied and bytes copied by split and merge since mount.
    pub sm_moved: Cell<u64>,
    pub sm_copied: Cell<u64>,
    pub sm_copied_bytes: Cell<u64>,
    /// Objects deleted per txn by `remove_pg`.
    pub remove_batch: Cell<usize>,
    /// Current slice size: `remove_batch` halved on every NoSpace of a deletion txn (down to 1), doubled back on success.
    remove_cur: Cell<usize>,
    /// The deletion txn queued in the store and not yet durable (`step_removals`).
    rm_flight: Cell<Option<RmFlight>>,
    /// Learned CPU ns per object of a deletion step (0 = not measured yet).
    rm_ns_per_obj: Cell<u64>,
    /// PG deletion step ns since the last store poll: background work like the store's own (`PgStoreOps::bg_ns`).
    rm_step_ns: Cell<u64>,
    /// Earliest start of the next deletion txn after a NoSpace back-off.
    remove_next: Cell<Option<std::time::Instant>>,
    /// TEST ONLY (feature `test-knobs`): deletion txns of at least this many objects fail with NoSpace (0 = off).
    #[cfg(feature = "test-knobs")]
    pub remove_nospace_from: Cell<usize>,
    /// TEST ONLY (feature `test-knobs`): `admission_ready_for` is false for PGs of this physical shard (a congested shard).
    #[cfg(feature = "test-knobs")]
    pub deny_admission_shard: Cell<Option<u32>>,
    /// TEST ONLY (feature `test-knobs`): `apply_room` is false for PGs of this physical shard (a shard at its system floor).
    #[cfg(feature = "test-knobs")]
    pub deny_room_shard: Cell<Option<u32>>,
    /// TEST ONLY: key/value bytes materialized by EC omap source scans, before reply budgeting.
    #[cfg(feature = "test-knobs")]
    pub ec_omap_scan_bytes: Cell<u64>,
    /// TEST ONLY (feature `test-knobs`): one migration import refusal with NoSpace after this many more applied batches
    /// (one-shot; a destination that runs out of room in the middle of a copy).
    #[cfg(feature = "test-knobs")]
    pub import_nospace_after: Cell<Option<u32>>,
    /// PGs whose deletion is in progress (durable REMOVE marker set), worked off in slices by `step_removals`: deleting a PG
    /// of 100k+ objects in one go blocked the core for seconds (heartbeats missed, OSD marked down; found by the RGW e2e).
    removing: RefCell<std::collections::VecDeque<SpgT>>,
    /// Migration headroom held for PGs moving into this store (adr 0031 am. 4): `pgid -> (device shard, bytes left)`.
    mig_holds: RefCell<BTreeMap<denc::types::PgT, (u32, u64)>>,
    /// Txns of PGs whose queued deletion could not be finished for lack of space (NoSpace even with a 1-object slice):
    /// kept in order and applied by `apply_deferred` once the background deletion is done. `queue_txn` answers `Pending`;
    /// `poll_store` reports the token only once that apply is durable (adr 0008). Unlike a parked txn it is not visible
    /// before; nothing reads such a PG (OQ 127): every later txn of it or of its split children waits behind it
    /// (`behind_deferred`), its activation too, so the PG neither goes active nor acks its activation and its primary
    /// stays inactive. Peering reads (`read_oi`, listings, stats) see an empty PG, never the old one. More than
    /// `DEFERRED_MAX` txns fail the store.
    deferred: RefCell<std::collections::VecDeque<(SpgT, StoreTxn, u64)>>,
    /// Per-pool inline compression settings (adr 0059 am. 1), set from the osdmap pool options; absent = mode none.
    pool_comp: RefCell<BTreeMap<u64, store::compress::PoolComp>>,
    /// Per-pool deep-scrub reformat engines (adr 0593-dedup-deep-scrub-reformat); absent = none.
    pool_reformat: RefCell<BTreeMap<u64, reformat::Engines>>,
    /// PGs whose collection tracks data versions since this adapter switched it on or found it on (switched off again at
    /// the next deep scrub once their pool has no engine left).
    dv_tracked: RefCell<std::collections::BTreeSet<SpgT>>,
    rf_stats: reformat::ReformatCounters,
    /// Compression estimates of the recompress engine.
    rf_codec: RefCell<store::compress::SoftCodec>,
    /// Dedup info collection (adr 0593-dedup-deep-scrub-reformat): digest algorithm of new records, all-zero objects
    /// recorded too, PGs whose next scrub maps are the primary's own (`scrub_role`), counters.
    dd_alg: Cell<store::obj::dedup::DigestAlg>,
    dd_zero: Cell<bool>,
    /// Deep scrub data read size in bytes and omap keys per page (`PgStoreOps::set_deep_scrub_reads`).
    scrub_stride: Cell<u64>,
    scrub_keys: Cell<usize>,
    scrub_primary: RefCell<std::collections::BTreeSet<SpgT>>,
    dd_stats: dedup::DedupCounters,
    /// Deferred txns applied that were durable at once: reported by the next `poll_store`.
    deferred_done: RefCell<Vec<(SpgT, u64)>>,
    /// PG deletions finished since mount, and the count `apply_deferred` last ran at (it only has work after a deletion).
    removals_done: Cell<u64>,
    deferred_at: Cell<u64>,
    /// Objects deleted by PG deletions since mount; `est_total` = objects the queued PGs held when queued (since the queue was last
    /// empty, `est_base` = `removed_objs` then): `left = est_total - (removed_objs - est_base)`, an estimate (writes meanwhile).
    removed_objs: Cell<u64>,
    est_total: Cell<u64>,
    est_base: Cell<u64>,
    /// Sticky local failure (EIO / ENOSPC / dead device on commit or read): the OSD must stop and exit.
    failed: RefCell<Option<String>>,
    /// Store token -> (pg, caller token) of txns queued but not yet durable.
    inflight: RefCell<HashMap<u64, (SpgT, u64), foldhash::fast::RandomState>>,
    /// TEST ONLY: token-specific staging errors, never durability acknowledgements (production logs and classifies
    /// them; nothing drains this list).
    #[cfg(feature = "test-knobs")]
    pub queue_errors: RefCell<Vec<(SpgT, u64, ObjError)>>,
    next_tok: Cell<u64>,
    /// Adaptive cold-page probe per physical shard (`PgStoreOps::probe_cold_for`): page loads seen at the last call, and
    /// the number of further probes the last load pays for.
    cold_shards: Vec<(Cell<u64>, Cell<u32>)>,
    /// The store carries `FEAT_LAZY_PGINFO` (read once at construction = the mounted superblock): client writes may leave
    /// `_info` / `_loghead` behind the log (`PgStoreOps::lazy_info`).
    lazy_info: bool,
    /// Malformed transactions rejected through the infallible `submit` / `queue` paths.
    pub rejected: Cell<u64>,
    pub last_rejected: RefCell<Option<String>>,
    /// `check_write` calls that needed the full decode + staging (big txns only; ordinary writes must stay at 0).
    pub slow_checks: Cell<u64>,
    /// `check_write` calls refused with `WriteErr::Blocked` (a metadata page of the check was loading).
    pub check_blocks: Cell<u64>,
    /// Store probes (`warm*`) refused, per `opexec::view::gate_why` store code (`ADMISSION..=DATA`), and the code of the
    /// last refusal since `ov_cause_begin` (`ObjView::ov_refusal`). Diagnostics: perf `probe_refused_*`, op trace.
    probe_refused: [Cell<u64>; 6],
    refusal: Cell<u8>,
    /// Parked deep-scrub data/omap digest, one slot per PG (`scrub`): PGs of this core scrub
    /// concurrently (own chunks, replica chunks), a shared slot made each one restart the other's object forever.
    scrub_park: RefCell<BTreeMap<SpgT, scrub::OmapPark>>,
}

impl<D: BlockDev, C: Clock> std::fmt::Debug for StoreAdapter<D, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StoreAdapter")
    }
}

impl<D: BlockDev, C: Clock> StoreAdapter<D, C> {
    /// A store probe refused for `why` (an `opexec::view::gate_why` store code): count it and remember it for
    /// `ObjView::ov_refusal`. Always false (the probe's result).
    fn refused(&self, why: u8) -> bool {
        let c = &self.probe_refused[why as usize];
        c.set(c.get() + 1);
        self.refusal.set(why);
        false
    }

    /// The last refusal since `ov_cause_begin` reset it (`ObjView::ov_refusal`).
    pub(crate) fn refusal(&self) -> &Cell<u8> {
        &self.refusal
    }

    /// The next adapter-local id: a store-token stand-in for internal txns, and the scrub media-read session id.
    fn take_tok(&self) -> u64 {
        let t = self.next_tok.get();
        self.next_tok.set(t + 1);
        t
    }

    /// Admission gate plus one non-blocking store probe: `true` = the operation may proceed now. A refused probe is
    /// counted for `why` and remembered for `ObjView::ov_refusal`; a store error counts as ready (the operation itself
    /// then reports it).
    fn warm_probe(
        &self,
        spg: SpgT,
        why: u8,
        probe: impl FnOnce(&mut Store<D, C>) -> Result<bool, ObjError>,
    ) -> bool {
        if !self.admission_ready_for(spg) {
            return self.refused(gate_why::ADMISSION);
        }
        probe(&mut self.st.borrow_mut()).unwrap_or(true) || self.refused(why)
    }

    pub fn new(st: Store<D, C>) -> Self {
        Self::from_shared(Rc::new(RefCell::new(st)))
    }
    /// The txn's compression: the pool's mode resolved against the alloc hints its ops carried.
    fn set_comp(&self, spg: SpgT, hints: u32, t: &mut OTxn<'_>) {
        if let Some(p) = self.pool_comp.borrow().get(&spg.pgid.pool) {
            t.comp = p.resolve(hints);
        }
    }
    /// Set (or clear with `None`) the compression settings of `pool`; takes effect for the next txn.
    pub fn set_pool_comp(&self, pool: u64, c: Option<store::compress::PoolComp>) {
        // the idle recompaction compresses plain ranges as a write without client hints would (adr 0533)
        self.st
            .borrow_mut()
            .set_pool_comp(pool, c.as_ref().and_then(|p| p.resolve(0)));
        let mut m = self.pool_comp.borrow_mut();
        match c {
            Some(c) => m.insert(pool, c),
            None => m.remove(&pool),
        };
    }
    /// Adapter over a store that other users (the OSD meta store) share.
    pub fn from_shared(st: Rc<RefCell<Store<D, C>>>) -> Self {
        let lazy_info = st.borrow().features() & store::layout::FEAT_LAZY_PGINFO != 0;
        let cold_shards = (0..st.borrow().nshards())
            .map(|_| (Cell::new(0), Cell::new(0)))
            .collect();
        StoreAdapter {
            lazy_info,
            st,
            orphan_writes: Rc::new(Cell::new(0)),
            notes: RefCell::new(Vec::new()),
            wake_toks: store::toks::Toks::new(),
            sm_moved: Cell::new(0),
            sm_copied: Cell::new(0),
            sm_copied_bytes: Cell::new(0),
            remove_batch: Cell::new(REMOVE_BATCH),
            remove_cur: Cell::new(usize::MAX),
            rm_flight: Cell::new(None),
            rm_ns_per_obj: Cell::new(0),
            rm_step_ns: Cell::new(0),
            remove_next: Cell::new(None),
            #[cfg(feature = "test-knobs")]
            remove_nospace_from: Cell::new(0),
            #[cfg(feature = "test-knobs")]
            deny_admission_shard: Cell::new(None),
            #[cfg(feature = "test-knobs")]
            deny_room_shard: Cell::new(None),
            #[cfg(feature = "test-knobs")]
            ec_omap_scan_bytes: Cell::new(0),
            #[cfg(feature = "test-knobs")]
            import_nospace_after: Cell::new(None),
            removing: RefCell::new(Default::default()),
            mig_holds: RefCell::new(BTreeMap::new()),
            deferred: RefCell::new(Default::default()),
            pool_comp: RefCell::new(BTreeMap::new()),
            pool_reformat: RefCell::new(BTreeMap::new()),
            dv_tracked: RefCell::new(Default::default()),
            rf_stats: Default::default(),
            rf_codec: RefCell::new(Default::default()),
            dd_alg: Cell::new(store::obj::dedup::DigestAlg::Md5),
            dd_zero: Cell::new(false),
            scrub_stride: Cell::new(scrub::DEFAULT_STRIDE),
            scrub_keys: Cell::new(scrub::DEFAULT_KEYS),
            scrub_primary: RefCell::new(Default::default()),
            dd_stats: Default::default(),
            deferred_done: RefCell::new(Vec::new()),
            removals_done: Cell::new(0),
            removed_objs: Cell::new(0),
            est_total: Cell::new(0),
            est_base: Cell::new(0),
            deferred_at: Cell::new(0),
            failed: RefCell::new(None),
            inflight: RefCell::new(HashMap::default()),
            #[cfg(feature = "test-knobs")]
            queue_errors: RefCell::new(Vec::new()),
            next_tok: Cell::new(1),
            cold_shards,
            rejected: Cell::new(0),
            last_rejected: RefCell::new(None),
            slow_checks: Cell::new(0),
            check_blocks: Cell::new(0),
            probe_refused: Default::default(),
            refusal: Cell::new(gate_why::STORE),
            scrub_park: RefCell::new(Default::default()),
        }
    }
    /// The shared store handle.
    pub fn shared(&self) -> Rc<RefCell<Store<D, C>>> {
        self.st.clone()
    }
    /// Unwrap the store (fails if the handle is still shared).
    pub fn into_inner(self) -> Store<D, C> {
        match Rc::try_unwrap(self.st) {
            Ok(c) => c.into_inner(),
            Err(_) => panic!("store handle still shared"),
        }
    }
    /// Access to the underlying store (statfs, checkpoint, scrub, tests).
    pub fn with_store<R>(&self, f: impl FnOnce(&mut Store<D, C>) -> R) -> R {
        f(&mut self.st.borrow_mut())
    }

    fn commit(&self, t: &OTxn) -> Result<(), ObjError> {
        self.st.borrow_mut().commit(t)
    }

    /// Is `e` a property of the transaction (remote input) rather than of the local store?
    pub fn is_input_error(e: &ObjError) -> bool {
        !matches!(e, ObjError::Eio(_) | ObjError::NoSpace | ObjError::Store(_))
    }

    /// Record a local failure (sticky) and return it as `Queued::Failed`.
    fn fail(&self, what: &str, e: &ObjError) -> Queued {
        let m = format!("{what}: {e}");
        let mut f = self.failed.borrow_mut();
        if f.is_none() {
            *f = Some(m.clone());
        }
        Queued::Failed(m)
    }

    fn classify(&self, what: &str, e: ObjError) -> Queued {
        if Self::is_input_error(&e) {
            self.rejected.set(self.rejected.get() + 1);
            let m = format!("{what}: {e}");
            *self.last_rejected.borrow_mut() = Some(m.clone());
            Queued::Rejected(m)
        } else {
            self.fail(what, &e)
        }
    }

    /// Asynchronous apply: parked input fences reads until applied; durability arrives through `poll_store`.
    /// Immediate input errors are Rejected; a deferred error reports its token and fail-stops (ADR 0066).
    pub fn queue_txn(&self, spg: SpgT, txn: &StoreTxn, token: u64) -> Queued {
        let _s = wprof::span(wprof::S::Translate);
        if let Some(m) = self.failed.borrow().clone() {
            return Queued::Failed(m);
        }
        if !self.deferred.borrow().is_empty() {
            if self.behind_deferred(spg) {
                // behind an earlier txn of this PG (or of the PG it was split from) that waits for a deletion: order kept
                return self.defer(spg, txn, token);
            }
            if self.touches_deferred(spg, txn) {
                // an active PG splitting into / merging a PG whose re-create waits: cannot happen (that PG is not active,
                // so not clean); deferring would hold the active PG's client writes behind it. Fail closed, never reorder.
                return self.fail(&format!("pg {spg}"), &ObjError::NoSpace);
            }
        }
        if let Err(e) = self.finish_removals_touched(spg, txn) {
            if e == ObjError::NoSpace
                && !txn
                    .ops
                    .iter()
                    .any(|o| matches!(o, StoreOp::SplitOut { .. } | StoreOp::MergeIn { .. }))
            {
                // the old PG's deletion cannot finish on a full store yet: wait for the background deletion (it is queued,
                // with back-off) instead of failing the OSD
                return self.defer(spg, txn, token);
            }
            return self.classify(&format!("pg {spg}"), e);
        }
        if matches!(txn.ops.as_slice(), [StoreOp::RemovePg]) {
            return self.queue_remove_pg(spg, token);
        }
        if txn.ops.iter().any(|o| {
            matches!(
                o,
                StoreOp::CreatePg
                    | StoreOp::RemovePg
                    | StoreOp::SplitOut { .. }
                    | StoreOp::MergeIn { .. }
            )
        }) {
            // structural operations block until done (rare)
            return match self.try_submit(spg, txn) {
                Ok(()) => Queued::Durable,
                Err(e) => self.classify(&format!("pg {spg}"), e),
            };
        }
        let tok = self.take_tok();
        let make = || {
            Box::new(QueuedInput {
                spg,
                txn: txn.clone(),
                hidden: self.removal_queued(spg),
                comp: self.pool_comp.borrow().get(&spg.pgid.pool).cloned(),
                orphans: self.orphan_writes.clone(),
            }) as Box<dyn store::obj::QueueBuilder<D, C>>
        };
        let mut result = self.queue_store(spg, txn, tok, &make);
        if result == Err(ObjError::WouldBlock) {
            // Hard FIFO cap (admission throttles input before it, but one admitted event, e.g. an osdmap from the exempt
            // mon link, can persist many PGs of one shard). The PG already logged this txn and a refusal is fail-stop:
            // drain as a cold barrier instead.
            result = self
                .drain_fifo()
                .and_then(|()| self.queue_store(spg, txn, tok, &make));
        }
        match result {
            Ok(true) => {
                self.inflight.borrow_mut().insert(tok, (spg, token));
                Queued::Pending
            }
            Ok(false) => Queued::Durable,
            Err(e) => self.classify(&format!("pg {spg}"), e),
        }
    }

    /// Translate + queue (or park) one PG txn under store token `tok`. `Ok(false)` = nothing to write (durable as is);
    /// `Err(WouldBlock)` = the shard FIFO is at its hard cap (not accepted); a txn the store would drop is an error
    /// ([`orphan_write`]).
    fn queue_store(
        &self,
        spg: SpgT,
        txn: &StoreTxn,
        tok: u64,
        make: &dyn Fn() -> Box<dyn store::obj::QueueBuilder<D, C>>,
    ) -> Result<bool, ObjError> {
        let mut st = self.st.borrow_mut();
        if st.shard_queued(&pg_coll(spg)).unwrap_or(false) {
            return st
                .queue_builder(&[pg_coll(spg), temp_coll(spg)], tok, make(), false)
                .map(|_| true);
        }
        let scope = st.begin_queue_build(&pg_coll(spg), tok)?;
        let built = self.build_in(&mut st, spg, txn);
        st.end_queue_build(scope, matches!(built, Err(ObjError::WouldBlock)));
        match built {
            Ok(Some(t)) => st.queue_with_builder(&t, tok, make).map(|_| true),
            Ok(None) => Ok(false),
            Err(ObjError::WouldBlock) => st
                .queue_builder(&[pg_coll(spg), temp_coll(spg)], tok, make(), true)
                .map(|_| true),
            Err(e) => Err(e),
        }
    }

    /// Cold structural/migration barriers: finish the existing FIFO before translating their mutations.
    fn drain_fifo(&self) -> Result<(), ObjError> {
        self.st.borrow_mut().drain_queued()
    }

    /// Reap durable txns: appends `(spg, token)` in completion order. A store error makes the adapter failed.
    pub fn poll_store(&self, out: &mut Vec<(SpgT, u64)>) {
        if self.failed.borrow().is_some() {
            return;
        }
        out.append(&mut self.deferred_done.borrow_mut());
        self.rm_step_ns.set(0);
        let mut acked = Vec::new();
        let r = self.st.borrow_mut().poll(&mut acked);

        let mut errors = Vec::new();
        self.st.borrow_mut().take_queue_errors(&mut errors);
        let mut refused = None;
        for (tok, e) in errors {
            if let Some(f) = self.rm_flight.get().filter(|f| f.tok == tok) {
                // a deletion txn refused while staging: retried smaller (NoSpace; `poll` reports the same error), else the
                // store fails
                self.rm_flight.set(None);
                if e == ObjError::NoSpace {
                    self.removal_refused(f.spg, f.objs);
                    refused = Some(e);
                } else {
                    self.fail("pg deletion", &e);
                }
            } else if let Some((spg, token)) = self.inflight.borrow_mut().remove(&tok) {
                #[cfg(feature = "test-knobs")]
                self.queue_errors.borrow_mut().push((spg, token, e.clone()));
                self.classify(&format!("pg {spg}, token {token}"), e);
            }
        }
        if let Some(f) = self.rm_flight.get()
            && acked.contains(&f.tok)
        {
            self.removal_done(f);
        }
        {
            let mut inf = self.inflight.borrow_mut();
            out.extend(acked.iter().filter_map(|t| inf.remove(t)));
        }
        if let Err(e) = r
            && refused.as_ref() != Some(&e)
        {
            self.fail("poll", &e);
        }
    }

    /// Number of txns queued and not yet durable (tests).
    #[cfg(any(test, feature = "test-knobs"))]
    pub fn pending(&self) -> usize {
        self.inflight.borrow().len()
            + usize::from(self.rm_flight.get().is_some())
            + self.deferred.borrow().len()
            + self.deferred_done.borrow().len()
    }

    /// Sticky failure text.
    pub fn failure(&self) -> Option<String> {
        self.failed.borrow().clone()
    }

    /// Stage the txn; `None` = nothing to write.
    fn build<'a>(&self, spg: SpgT, txn: &'a StoreTxn) -> Result<Option<OTxn<'a>>, ObjError> {
        self.build_in(&mut self.st.borrow_mut(), spg, txn)
    }
    fn build_in<'a>(
        &self,
        st: &mut Store<D, C>,
        spg: SpgT,
        txn: &'a StoreTxn,
    ) -> Result<Option<OTxn<'a>>, ObjError> {
        build_input(
            st,
            spg,
            txn,
            self.removal_queued(spg),
            self.pool_comp.borrow().get(&spg.pgid.pool).cloned(),
            &self.orphan_writes,
        )
    }

    /// Size pre-flight shared by `check_write` / `check_write_split`: `mlen`/`dlen` = wire bytes (floor test), `mk` = the
    /// op to translate when the txn is big enough to need the real check.
    fn check_write_op(
        &self,
        spg: SpgT,
        mlen: usize,
        dlen: usize,
        expands: bool,
        mk: impl FnOnce() -> StoreOp,
    ) -> Result<(), WriteErr> {
        // Small txns cannot reach the SIZE limits: no decode, no staging (hot path). The floor is derived from the
        // store (page budget, WAL ring), never a fixed constant: a small cache must not let a few-KiB txn of tiny ops
        // through. Per-item limits (key lengths) are not size limits: the op executor enforces them (rule 9a).
        let (wire_floor, data_floor) = {
            let st = self.st.borrow();
            (
                CHECK_MIN_WIRE.min(st.check_wire_floor()),
                st.check_data_floor(),
            )
        };
        if mlen <= wire_floor && dlen <= data_floor && !expands {
            return Ok(());
        }
        self.slow_checks.set(self.slow_checks.get() + 1);
        let txn = StoreTxn { ops: vec![mk()] };
        // the PG core never waits for a store page here (adr 0021 S8): the translation and the record check run
        // non-blocking; a cold page submits its load and the write is submitted again after the wake
        let nb = self.st.borrow_mut().begin_nonblock();
        let r = match self.build(spg, &txn) {
            Ok(Some(t)) => {
                let mut st = self.st.borrow_mut();
                if st.txn_needs_check(&t) {
                    st.check_txn(&t)
                } else {
                    Ok(())
                }
            }
            Ok(None) => Ok(()),
            Err(e) => Err(e),
        };
        self.st.borrow_mut().end_nonblock(nb);
        let e = match r {
            Ok(()) => return Ok(()),
            Err(ObjError::WouldBlock) => {
                self.check_blocks.set(self.check_blocks.get() + 1);
                return Err(WriteErr::Blocked);
            }
            Err(ObjError::TooLarge) => denc::errno::EMSGSIZE,
            Err(ObjError::NameTooLong) => denc::errno::ENAMETOOLONG,
            Err(ObjError::NoSpace) => denc::errno::ENOSPC,
            Err(e) => {
                // a txn the translator or the store refuses as malformed input: never apply, never exit
                *self.last_rejected.borrow_mut() = Some(format!("check_write: {e}"));
                denc::errno::EINVAL
            }
        };
        Err(WriteErr::TooBig(e))
    }

    /// Apply a PG transaction atomically and durably. `Err` = nothing applied (except `RemovePg` progress).
    pub fn try_submit(&self, spg: SpgT, txn: &StoreTxn) -> Result<(), ObjError> {
        self.drain_fifo()?;
        if txn
            .ops
            .iter()
            .any(|o| matches!(o, StoreOp::SplitOut { .. } | StoreOp::MergeIn { .. }))
        {
            self.finish_removals_touched(spg, txn)?;
            return self.submit_structural(spg, txn);
        }
        self.finish_removals_touched(spg, txn)?;
        let mut ops = txn.ops.as_slice();
        let mut remove = false;
        if let Some(i) = ops.iter().position(|o| matches!(o, StoreOp::RemovePg)) {
            // the deletion drops the whole collection: an op after it would be acknowledged but never applied
            if i + 1 != ops.len() {
                return Err(ObjError::Invalid(format!(
                    "RemovePg with {} ops after it",
                    ops.len() - i - 1
                )));
            }
            ops = &ops[..i];
            remove = true;
        }
        if !ops.is_empty() {
            let exists = self.pg_live(spg)?;
            if !exists && !matches!(ops[0], StoreOp::CreatePg) {
                return Err(orphan_write(&self.orphan_writes));
            }
            let mut t = OTxn::new();
            t.sys = true;
            let mut store = self.st.borrow_mut();
            let mut tr = meta::Translator::new(&mut store, spg, exists).for_ops(ops);
            for op in ops {
                tr.op(op, &mut t)?;
            }
            self.set_comp(spg, tr.hints, &mut t);
            drop(tr);
            drop(store);
            if !t.is_empty() {
                self.commit(&t)?;
            }
        }
        if remove {
            self.remove_pg_async(spg)?;
        }
        Ok(())
    }

    /// Delete a PG completely (blocking): durable marker, objects in batches, then pgmeta + collections.
    pub fn remove_pg(&self, spg: SpgT) -> Result<(), ObjError> {
        // residency leases of ops of the PG (adr 0043 am. 18) end with it
        self.st.borrow_mut().lease_release_coll(&pg_coll(spg));
        if !self.st.borrow_mut().coll_exists(&pg_coll(spg))? {
            self.removals_done.set(self.removals_done.get() + 1);
            return Ok(());
        }
        self.mark_removing(spg)?;
        self.enqueue_removal(spg);
        self.finish_removal_blocking(spg)
    }

    /// The PGs `txn` of `spg` touches: `spg`, split children, merge sources.
    fn pgs_of(spg: SpgT, txn: &StoreTxn) -> Vec<SpgT> {
        let mut v = vec![spg];
        for op in &txn.ops {
            match op {
                StoreOp::SplitOut { children, .. } => v.extend(children.iter().map(|c| c.spg)),
                StoreOp::MergeIn { sources, .. } => v.extend(sources.iter().copied()),
                _ => {}
            }
        }
        v
    }

    /// Does `spg` have to queue behind a deferred txn (its own PG, or a split child / merge source of one)?
    fn behind_deferred(&self, spg: SpgT) -> bool {
        self.deferred
            .borrow()
            .iter()
            .any(|(s, t, _)| Self::pgs_of(*s, t).contains(&spg))
    }

    /// Does `txn` (of a PG that is not deferred) split into / merge from a PG with deferred txns?
    fn touches_deferred(&self, spg: SpgT, txn: &StoreTxn) -> bool {
        let mine = Self::pgs_of(spg, txn);
        mine.len() > 1 && mine.iter().any(|p| self.behind_deferred(*p))
    }

    /// Keep `txn` until the deletion its PG waits for is done (`apply_deferred`); bounded by `DEFERRED_MAX`.
    fn defer(&self, spg: SpgT, txn: &StoreTxn, token: u64) -> Queued {
        if self.deferred.borrow().len() >= DEFERRED_MAX {
            return self.fail(
                &format!(
                    "pg {spg}: {DEFERRED_MAX} txns wait for a PG deletion that cannot proceed"
                ),
                &ObjError::NoSpace,
            );
        }
        self.deferred
            .borrow_mut()
            .push_back((spg, txn.clone(), token));
        Queued::Pending
    }

    /// Apply the txns that waited for a PG deletion (see `deferred`) whose deletion is done now, in order. Runs only
    /// after a deletion finished (nothing else can unblock them).
    fn apply_deferred(&self) {
        if self.deferred.borrow().is_empty() || self.deferred_at.get() == self.removals_done.get() {
            return;
        }
        self.deferred_at.set(self.removals_done.get());
        let q = std::mem::take(&mut *self.deferred.borrow_mut());
        let mut keep = std::collections::VecDeque::new();
        let mut blocked: Vec<SpgT> = Vec::new();
        for (spg, txn, token) in q {
            let pgs = Self::pgs_of(spg, &txn);
            if pgs
                .iter()
                .any(|p| blocked.contains(p) || self.removal_queued(*p))
            {
                // still waiting (or behind one that waits): every later txn of these PGs stays behind it
                blocked.extend(pgs);
                keep.push_back((spg, txn, token));
                continue;
            }
            match self.queue_txn(spg, &txn, token) {
                // queued in the store (no PG of it has a deletion queued, so `queue_txn` cannot defer it again)
                Queued::Pending => debug_assert!(self.deferred.borrow().is_empty()),
                Queued::Durable => self.deferred_done.borrow_mut().push((spg, token)),
                // refused (counted in `rejected`): fail-stop like a refused txn that was not deferred (adr 0066): the PG
                // logged it in memory already, an unacked drop would hold its writes until the next interval
                Queued::Rejected(w) => {
                    let mut f = self.failed.borrow_mut();
                    if f.is_none() {
                        *f = Some(format!(
                            "pg {spg}: deferred transaction refused (not applied): {w}"
                        ));
                    }
                }
                Queued::Failed(_) => {}
            }
        }
        *self.deferred.borrow_mut() = keep;
    }

    fn removal_queued(&self, spg: SpgT) -> bool {
        let r = self.removing.borrow();
        !r.is_empty() && r.contains(&spg)
    }

    /// The PG exists and is not being deleted (a write to a PG whose deletion is queued is an orphan write).
    fn pg_live(&self, spg: SpgT) -> Result<bool, ObjError> {
        Ok(!self.removal_queued(spg) && self.st.borrow_mut().coll_exists(&pg_coll(spg))?)
    }

    /// Finish (blocking, rare) the queued deletion of every PG `txn` brings (back) into existence under the same
    /// collection: `CreatePg` of `spg`, split children, merge sources/target. Without it the new PG would land in the
    /// doomed collection (old pgmeta + REMOVE marker): `step_removals` or the next start would delete acked data, a
    /// merge would resurrect the deleted source's objects.
    fn finish_removals_touched(&self, spg: SpgT, txn: &StoreTxn) -> Result<(), ObjError> {
        if self.removing.borrow().is_empty() {
            return Ok(());
        }
        for op in &txn.ops {
            match op {
                StoreOp::CreatePg => self.finish_removal(spg)?,
                StoreOp::SplitOut { children, .. } => {
                    self.finish_removal(spg)?;
                    for c in children {
                        self.finish_removal(c.spg)?;
                    }
                }
                StoreOp::MergeIn { sources, .. } => {
                    self.finish_removal(spg)?;
                    for s in sources {
                        self.finish_removal(*s)?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Finish the queued deletion of `spg` now (no-op when none is queued).
    pub(crate) fn finish_removal(&self, spg: SpgT) -> Result<(), ObjError> {
        if self.removal_queued(spg) {
            self.finish_removal_blocking(spg)?;
        }
        Ok(())
    }

    /// Start deleting a PG without blocking: the durable marker is set now, the objects go in `step_removals` slices.
    pub fn remove_pg_async(&self, spg: SpgT) -> Result<(), ObjError> {
        // residency leases of ops of the PG (adr 0043 am. 18) end with it
        self.st.borrow_mut().lease_release_coll(&pg_coll(spg));
        if !self.st.borrow_mut().coll_exists(&pg_coll(spg))? {
            return Ok(());
        }
        self.mark_removing(spg)?;
        self.enqueue_removal(spg);
        Ok(())
    }

    /// Queue a PG whose durable marker is set for `step_removals` (once) and book its object count for the progress estimate.
    fn enqueue_removal(&self, spg: SpgT) {
        if self.removal_queued(spg) {
            return;
        }
        if self.removing.borrow().is_empty() {
            self.est_total.set(0);
            self.est_base.set(self.removed_objs.get());
        }
        let n = self
            .st
            .borrow_mut()
            .coll_stats(&pg_coll(spg))
            .ok()
            .flatten()
            .map_or(0, |s| s.nobj);
        self.est_total.set(self.est_total.get() + n);
        self.removing.borrow_mut().push_back(spg);
    }

    /// The txn that sets the durable REMOVE marker of `spg`.
    fn marker_txn(spg: SpgT) -> OTxn<'static> {
        let mut t = OTxn::new();
        t.sys = true;
        t.frees = true; // tiny, and the first step of freeing space: staged as a pure shrink (adr 0021 S4)
        t.push(TOp::OmapSetKeys {
            cid: pg_coll(spg),
            oid: pgmeta(spg),
            pairs: vec![(
                replwire::pgmeta::REMOVE_KEY.as_bytes().to_vec().into(),
                vec![1u8].into(),
            )],
        });
        t
    }

    fn mark_removing(&self, spg: SpgT) -> Result<(), ObjError> {
        self.commit(&Self::marker_txn(spg))
    }

    /// `RemovePg` without waiting: the marker txn goes through the store queue like any PG txn (durable = acked to the PG
    /// through `poll_store`) and the PG is booked for `step_removals` at once; the deletion txns queue behind the marker in
    /// the same shard FIFO, so the marker is durable before the first object goes. A pure-input PG layer sees the same
    /// contract as before (the PG's token completes when the marker is durable). A full store queue falls back to the
    /// blocking path.
    fn queue_remove_pg(&self, spg: SpgT, token: u64) -> Queued {
        if self.removal_queued(spg) {
            return Queued::Durable;
        }
        match self.st.borrow_mut().coll_exists(&pg_coll(spg)) {
            Ok(true) => {}
            Ok(false) => return Queued::Durable,
            Err(e) => return self.classify(&format!("pg {spg}"), e),
        }
        let tok = self.take_tok();
        let queued = self.st.borrow_mut().queue(&Self::marker_txn(spg), tok);
        match queued {
            Ok(_) => {
                self.inflight.borrow_mut().insert(tok, (spg, token));
                self.enqueue_removal(spg);
                Queued::Pending
            }
            Err(ObjError::WouldBlock) => {
                match self.mark_removing(spg).map(|()| self.enqueue_removal(spg)) {
                    Ok(()) => Queued::Durable,
                    Err(e) => self.classify(&format!("pg {spg}"), e),
                }
            }
            Err(e) => self.classify(&format!("pg {spg}"), e),
        }
    }

    /// The next deletion step must wait (NoSpace back-off).
    pub fn removal_paused(&self) -> bool {
        self.remove_next
            .get()
            .is_some_and(|t| std::time::Instant::now() < t)
    }

    /// Deletions are queued or a deletion txn is in flight.
    fn removal_pending(&self) -> bool {
        self.rm_flight.get().is_some() || !self.removing.borrow().is_empty()
    }

    /// One non-blocking step of the queued PG deletions: queue the next batch (<= `remove_batch` objects, or the closing
    /// txn of a PG) in the store like any PG txn and return. It never waits for a page load or for durability: a cold leaf
    /// is loaded in the background and the step retries, the ack of the txn arrives through `poll_store`. One deletion txn
    /// is in flight at a time, so the next step has nothing to do until the previous one is durable (`poll_store` reaps it).
    /// `bound_ns` caps the CPU time of the step (client work waits on this core): the batch is cut to what the measured
    /// cost per object fits in it; `u64::MAX` = synchronous drivers, full batches. True = deletions are still pending.
    pub fn step_removals(&self, bound_ns: u64) -> Result<bool, ObjError> {
        if self.rm_flight.get().is_some()
            || self.removal_paused()
            || self.st.borrow().queued_count() > 0
        {
            return Ok(self.removal_pending());
        }
        let Some(spg) = self.removing.borrow().front().copied() else {
            return Ok(false);
        };
        let t0 = std::time::Instant::now();
        let r = self.queue_removal(spg, bound_ns);
        let ns = t0.elapsed().as_nanos() as u64;
        self.rm_step_ns.set(self.rm_step_ns.get() + ns);
        if let Some(f) = self.rm_flight.get().filter(|f| f.objs > 0) {
            // learned cost per object of a step (EWMA 1/8; a step also lists and stages the batch)
            let sample = (ns / f.objs).max(1);
            let old = self.rm_ns_per_obj.get();
            self.rm_ns_per_obj.set(if old == 0 {
                sample
            } else {
                (old * 7 + sample) / 8
            });
        }
        match r {
            Ok(()) => {}
            // the store's queue is full: the next step tries again
            Err(ObjError::WouldBlock) => {}
            Err(e) => {
                // the durable marker finishes it at the next start
                self.removing.borrow_mut().retain(|s| *s != spg);
                return Err(e);
            }
        }
        Ok(self.removal_pending())
    }

    /// Queue the next deletion txn of `spg`: a batch of objects of its collections, then (nothing left) the closing txn.
    fn queue_removal(&self, spg: SpgT, bound_ns: u64) -> Result<(), ObjError> {
        let (pc, tc, pm) = (pg_coll(spg), temp_coll(spg), pgmeta(spg));
        let mapper = snapmap::mapper_obj(spg);
        let mut t = OTxn::new();
        let mut objs = 0u64;
        {
            let mut st = self.st.borrow_mut();
            if !st.coll_exists(&pc)? {
                drop(st);
                self.removals_done.set(self.removals_done.get() + 1);
                self.removing.borrow_mut().retain(|s| *s != spg);
                return Ok(());
            }
            let mut n = self.remove_cur.get().clamp(1, self.remove_batch.get());
            if bound_ns != u64::MAX {
                // until the first step measured the cost a bounded step removes one object
                let fit = bound_ns.checked_div(self.rm_ns_per_obj.get()).unwrap_or(1);
                n = n.min(fit.max(1) as usize);
            }
            for cid in [pc, tc] {
                if !st.coll_exists(&cid)? {
                    continue;
                }
                // a cold leaf must not stall the core: the read submits the page load and the next step finds it cached
                st.set_nonblock_reads(true);
                // Both pgmeta and SnapMapper stay until the closing txn. Account for both before filtering:
                // a one-object batch must not see only metadata and mistake the collection for empty.
                let retained = if cid == pc { 2 } else { 0 };
                let r = st.list(&cid, &Ghobject::MIN(), None, n.saturating_add(retained));
                st.set_nonblock_reads(false);
                let (list, _) = match r {
                    Ok(l) => l,
                    Err(ObjError::WouldBlock) => {
                        st.take_blocked(); // ours, not a refused client read
                        return Ok(());
                    }
                    Err(e) => return Err(e),
                };
                for o in list
                    .into_iter()
                    .filter(|o| !(o.is_pgmeta() && cid == pc))
                    .take(n)
                {
                    t.push(TOp::Remove { cid, oid: o });
                    objs += 1;
                }
                if objs > 0 {
                    break;
                }
            }
            if objs == 0 {
                t.push(TOp::Remove {
                    cid: pc,
                    oid: mapper,
                });
                t.push(TOp::Remove { cid: pc, oid: pm });
                t.push(TOp::RmColl { cid: pc });
                if st.coll_exists(&tc)? {
                    t.push(TOp::RmColl { cid: tc });
                }
            }
        }
        let tok = self.take_tok();
        #[cfg(feature = "test-knobs")]
        let queued = if (1..=objs as usize).contains(&self.remove_nospace_from.get()) {
            Err(ObjError::NoSpace)
        } else {
            self.st.borrow_mut().queue(&t, tok)
        };
        #[cfg(not(feature = "test-knobs"))]
        let queued = self.st.borrow_mut().queue(&t, tok);
        match queued {
            Ok(_) => self.rm_flight.set(Some(RmFlight {
                tok,
                spg,
                objs,
                last: objs == 0,
            })),
            Err(ObjError::NoSpace) => self.removal_refused(spg, objs),
            Err(e) => return Err(e),
        }
        Ok(())
    }

    /// The in-flight deletion txn is durable.
    fn removal_done(&self, f: RmFlight) {
        self.rm_flight.set(None);
        self.removed_objs.set(self.removed_objs.get() + f.objs);
        self.remove_cur
            .set((f.objs as usize * 2).min(self.remove_batch.get()));
        if f.last {
            self.removals_done.set(self.removals_done.get() + 1);
            self.removing.borrow_mut().retain(|s| *s != f.spg);
        }
    }

    /// A deletion txn of `objs` objects was refused for lack of space (by `queue` or as a staging error): half the batch
    /// next time, a single object (or the closing txn) backs off.
    fn removal_refused(&self, spg: SpgT, objs: u64) {
        if objs > 1 {
            self.remove_cur.set(objs as usize / 2);
        } else {
            self.removal_backoff(spg);
        }
    }

    /// Let the store make progress and reap the in-flight deletion txn (synchronous drivers only: the OSD loop polls the
    /// store itself). The acks of other txns wait in `deferred_done` for the next `poll_store`.
    fn reap_removal(&self) {
        let mut out = Vec::new();
        self.poll_store(&mut out);
        self.deferred_done.borrow_mut().extend(out);
        self.st.borrow_mut().idle();
    }

    /// `step_removals` for synchronous test drivers: when it queued a deletion txn, wait until the store has
    /// made it durable. True = deletions are still pending.
    #[cfg(any(test, feature = "test-knobs"))]
    pub fn step_removals_sync(&self) -> Result<bool, ObjError> {
        let more = self.step_removals(u64::MAX)?;
        if more && self.rm_flight.get().is_none() {
            self.reap_removal(); // nothing queued (cold page, back-off): let the page loads finish
        }
        while self.rm_flight.get().is_some() {
            self.reap_removal();
        }
        Ok(more && self.removal_pending())
    }

    /// Finish every queued PG deletion now and block (synchronous drivers: tests, tools).
    pub fn finish_removals(&self) -> Result<(), ObjError> {
        loop {
            let Some(spg) = self.removing.borrow().front().copied() else {
                return Ok(());
            };
            self.finish_removal_blocking(spg)?;
        }
    }

    /// Finish the deletion of `spg` now and block until it is done (a deletion in the way of a re-create, `remove_pg`). Its
    /// txns go through the same queue as the sliced ones. NoSpace on a single object leaves the PG queued, back-off set.
    fn finish_removal_blocking(&self, spg: SpgT) -> Result<(), ObjError> {
        {
            let mut r = self.removing.borrow_mut();
            r.retain(|s| *s != spg);
            r.push_front(spg);
        }
        self.remove_next.set(None);
        loop {
            if let Some(m) = self.failed.borrow().clone() {
                return Err(ObjError::Invalid(m));
            }
            if self.rm_flight.get().is_some() {
                self.reap_removal();
                continue;
            }
            if !self.removal_queued(spg) {
                return Ok(());
            }
            if self.removal_paused() {
                return Err(ObjError::NoSpace);
            }
            self.st.borrow_mut().drain_queued()?;
            self.step_removals(u64::MAX)?;
            if self.rm_flight.get().is_none() {
                self.reap_removal(); // nothing queued (cold page): let the page loads finish
            }
        }
    }

    /// A deletion txn of one object still hit NoSpace: retry the PG later (`step_removals` waits for `remove_next`).
    fn removal_backoff(&self, spg: SpgT) {
        self.remove_next.set(Some(
            std::time::Instant::now() + std::time::Duration::from_nanos(REMOVE_RETRY_NS),
        ));
        self.notes.borrow_mut().push(format!(
            "pg {spg}: deletion hit ENOSPC with a 1-object slice; retry in {} s",
            REMOVE_RETRY_NS / 1_000_000_000
        ));
    }

    /// PGs whose deletion was started but not finished (crash during `remove_pg`).
    pub fn pending_removals(&self) -> Result<Vec<SpgT>, ObjError> {
        let mut out = Vec::new();
        let colls = self.st.borrow_mut().list_colls()?;
        for c in colls {
            if let CollT::Pg(s) = c
                && self.is_removing(s)?
            {
                out.push(s);
            }
        }
        Ok(out)
    }

    /// Interrupted PG deletions (call after mount): queued, never run here. `step_removals` works them off in paced slices
    /// once the OSD serves (a synchronous resume of a 50M-object pool kept the OSD down for over an hour and ignored SIGTERM).
    /// The marker is durable, so a crash or stop at any time resumes again.
    pub fn resume_removals(&self) -> Result<usize, ObjError> {
        let p = self.pending_removals()?;
        for s in &p {
            self.enqueue_removal(*s);
        }
        Ok(p.len())
    }

    /// `(PGs queued, objects deleted since mount, estimated objects left)`.
    pub fn removal_progress(&self) -> (u32, u64, u64) {
        let done = self.removed_objs.get().saturating_sub(self.est_base.get());
        (
            self.removing.borrow().len() as u32,
            self.removed_objs.get(),
            self.est_total.get().saturating_sub(done),
        )
    }

    pub(crate) fn is_removing(&self, spg: SpgT) -> Result<bool, ObjError> {
        let mut st = self.st.borrow_mut();
        Ok(!st
            .omap_get(
                &pg_coll(spg),
                &pgmeta(spg),
                &[replwire::pgmeta::REMOVE_KEY.as_bytes()],
            )
            .or_else(|e| {
                if e == ObjError::NoEnt {
                    Ok(BTreeMap::new())
                } else {
                    Err(e)
                }
            })?
            .is_empty())
    }

    // ------------------------------------------------------------------ reads

    fn xattr(&self, spg: SpgT, h: &Hobject, name: &[u8]) -> Result<Option<Vec<u8>>, ObjError> {
        match self
            .st
            .borrow_mut()
            .getattr(&pg_coll(spg), &gh(spg, h), name)
        {
            Err(ObjError::NoEnt) => Ok(None),
            r => r,
        }
    }

    /// Full object (data, xattrs, omap, header) as `MemObj` (tests, tools).
    pub fn object(&self, spg: SpgT, h: &Hobject) -> Option<MemObj> {
        let (c, g) = (pg_coll(spg), gh(spg, h));
        let mut st = self.st.borrow_mut();
        let size = st.stat(&c, &g).ok()??.size;
        Some(MemObj {
            data: st.read(&c, &g, 0, size).ok()?,
            xattrs: st.getattrs(&c, &g).ok()?,
            omap: st.omap_all(&c, &g).ok()?,
            omap_header: st.omap_header(&c, &g).ok()?,
        })
    }

    /// All objects of the PG in hobject order (excluding pgmeta), temp objects included.
    pub fn all_object_names(&self, spg: SpgT) -> Vec<Hobject> {
        let c = pg_coll(spg);
        let mut st = self.st.borrow_mut();
        let mut out = Vec::new();
        let mut cur = Ghobject::MIN();
        loop {
            let Ok((v, n)) = st.list(&c, &cur, None, 256) else {
                return out;
            };
            out.extend(
                v.into_iter()
                    .filter(|o| !o.is_pgmeta() && o.generation == Ghobject::NO_GEN)
                    .map(|o| o.hobj),
            );
            match n {
                Some(x) => cur = x,
                None => return out,
            }
        }
    }

    /// Non-temp objects (like `MemStore::objects`).
    pub fn objects(&self, spg: SpgT) -> BTreeMap<Hobject, MemObj> {
        if self.removal_queued(spg) {
            return BTreeMap::new(); // being deleted: empty, never the old objects (`list_objects`)
        }
        self.all_object_names(spg)
            .into_iter()
            .filter(|h| !h.is_temp())
            .filter_map(|h| self.object(spg, &h).map(|o| (h, o)))
            .collect()
    }

    /// Number of temp objects of the PG (tests).
    #[cfg(any(test, feature = "test-knobs"))]
    pub fn temp_objects(&self, spg: SpgT) -> usize {
        self.all_object_names(spg)
            .iter()
            .filter(|h| h.is_temp())
            .count()
    }

    /// Operator-visible note about local damage (capped; drained by the OSD into the cluster log).
    pub(crate) fn note_damage(&self, msg: String) {
        let mut n = self.notes.borrow_mut();
        if n.len() < 64 {
            n.push(msg);
        }
    }

    /// object_info of an object, absent / damaged / unreadable kept apart (never fold them into "no object").
    fn read_oi(&self, spg: SpgT, h: &Hobject) -> Result<ObjectInfo, StoreReadError> {
        if self.removal_queued(spg) {
            return Err(StoreReadError::NoObject); // a PG being deleted (its re-create may wait: `deferred`) is empty
        }
        let r = self
            .st
            .borrow_mut()
            .getattr(&pg_coll(spg), &gh(spg, h), b"_");
        self.decode_oi(spg, h, r.as_ref().map(Option::as_deref))
    }

    /// [`Self::read_oi`] from an already read `_` attribute (`Ok(None)` = absent).
    fn decode_oi(
        &self,
        spg: SpgT,
        h: &Hobject,
        r: Result<Option<&[u8]>, &ObjError>,
    ) -> Result<ObjectInfo, StoreReadError> {
        match r {
            Ok(Some(b)) => denc::from_slice::<ObjectInfo>(b).map_err(|e| {
                self.note_damage(format!(
                    "pg {spg}: object_info of {} undecodable: {e}",
                    oname(h)
                ));
                StoreReadError::Corrupt
            }),
            Ok(None) => {
                self.note_damage(format!("pg {spg}: object {} has no object_info", oname(h)));
                Err(StoreReadError::Corrupt)
            }
            Err(ObjError::NoEnt | ObjError::NoColl) => Err(StoreReadError::NoObject),
            Err(e) => {
                self.note_damage(format!(
                    "pg {spg}: reading object_info of {}: {e}",
                    oname(h)
                ));
                Err(StoreReadError::Io)
            }
        }
    }
}

impl<D: BlockDev, C: Clock> PgStoreOps for StoreAdapter<D, C> {
    fn list_temps(&self, spg: SpgT) -> Vec<Hobject> {
        // temp objects (pool -2 - pool) sort before every object of the PG (same shard, smaller pool): list only up
        // to the first possible regular object, never the whole PG (runs for every PG at load)
        let c = pg_coll(spg);
        let end = Ghobject::new(
            Hobject {
                pool: spg.pgid.pool as i64,
                ..Hobject::MIN()
            },
            Ghobject::NO_GEN,
            spg.shard,
        );
        let mut st = self.st.borrow_mut();
        let mut out = Vec::new();
        let mut cur = Ghobject::MIN();
        loop {
            let Ok((v, n)) = st.list(&c, &cur, Some(&end), 256) else {
                return out;
            };
            out.extend(v.into_iter().filter(|o| o.hobj.is_temp()).map(|o| o.hobj));
            match n {
                Some(x) => cur = x,
                None => return out,
            }
        }
    }
    fn list_pgs(&self) -> Vec<SpgT> {
        let colls = match self.st.borrow_mut().list_colls() {
            Ok(c) => c,
            Err(e) => {
                self.fail("list collections", &e);
                return Vec::new();
            }
        };
        let mut v: Vec<SpgT> = colls
            .into_iter()
            .filter_map(|c| match c {
                CollT::Pg(s) => Some(s),
                _ => None,
            })
            .filter(|s| !self.is_removing(*s).unwrap_or(false))
            .collect();
        v.sort();
        v
    }

    fn load_pg(&self, spg: SpgT) -> Option<PersistedPg> {
        match meta::load(self, spg) {
            Ok(p) => p,
            Err(e) => {
                self.fail(&format!("load pg {spg}"), &e);
                None
            }
        }
    }

    fn submit(&mut self, spg: SpgT, txn: &StoreTxn) {
        // The replica never rejects (spec replication 3.2) and the trait cannot return an error: a local
        // failure is recorded (sticky, see `failure()`; the OSD stops serving), a malformed txn is counted.
        if let Err(e) = self.try_submit(spg, txn) {
            self.classify(&format!("pg {spg}"), e);
        } else if txn.ops.iter().any(|o| matches!(o, StoreOp::RemovePg)) {
            // `submit` is the synchronous form (tests, tools): finish the deletion; the OSD queues through `queue_txn` (sliced)
            if let Err(e) = self.finish_removals() {
                self.fail("pg deletion", &e);
            }
            self.apply_deferred();
        }
    }

    fn queue(&mut self, spg: SpgT, txn: &StoreTxn, token: u64) -> Queued {
        self.queue_txn(spg, txn, token)
    }

    fn poll_commits(&mut self, out: &mut Vec<(SpgT, u64)>) {
        self.poll_store(out);
    }

    fn end_pass(&mut self) {
        if self.failed.borrow().is_none() {
            self.st.borrow_mut().end_pass();
        }
    }

    fn failed(&self) -> Option<String> {
        self.failure()
    }

    fn comp_perf(&self) -> peering::store::CompPerf {
        let c = self.st.borrow().comp_counters();
        peering::store::CompPerf {
            ok: c.ok,
            rejected: c.rejected,
            sampled_out: c.sampled_out,
            gc_merged: c.gc_merged,
            decomp: c.decomp,
            comp_ns: c.comp_ns,
            decomp_ns: c.decomp_ns,
            staged_bytes: c.staged_bytes,
            zc_bytes: c.zc_bytes,
            crc_reused_bytes: c.crc_reused_bytes,
            placement_crc_reblocked_bytes: c.placement_crc_reblocked_bytes,
            placement_crc_hashed_bytes: c.placement_crc_hashed_bytes,
            probe_refused_admission: self.probe_refused[gate_why::ADMISSION as usize].get(),
            probe_refused_obj: self.probe_refused[gate_why::OBJ as usize].get(),
            probe_refused_log: self.probe_refused[gate_why::LOG as usize].get(),
            probe_refused_data: self.probe_refused[gate_why::DATA as usize].get(),
        }
    }

    fn removal_progress(&self) -> peering::store::RemovalProgress {
        let (pgs, objs_done, objs_left) = StoreAdapter::removal_progress(self);
        peering::store::RemovalProgress {
            pgs,
            objs_done,
            objs_left,
        }
    }

    fn step_removals(&self, bound_ns: u64) -> bool {
        let queued = || -> bool {
            if !self.removal_pending() {
                return false; // the common case: no clock read per driver loop pass
            }
            // failed, or paused by the NoSpace back-off: nothing happens, the driver may idle (it polls again within its idle sleep)
            if self.failed.borrow().is_some() || self.removal_paused() {
                return false;
            }
            let was_in_flight = self.rm_flight.get().is_some();
            match StoreAdapter::step_removals(self, bound_ns) {
                // progress = this call queued a deletion txn; waiting for its durability (or for a cold page) is store I/O in
                // flight, which keeps the driver polling without spinning
                Ok(_) => !was_in_flight && self.rm_flight.get().is_some(),
                Err(e) => {
                    // a local store failure like any commit error: sticky, the OSD stops (the durable marker finishes the
                    // deletion at the next start)
                    self.fail("pg deletion", &e);
                    false
                }
            }
        }();
        self.apply_deferred(); // txns that waited for a deletion that has finished now
        queued
    }

    fn write_room(&self, spg: SpgT, bytes: u64, entries: u64) -> bool {
        self.st.borrow().write_room(&pg_coll(spg), bytes, entries)
    }

    fn checkpoint_on_exit(&self) -> Result<(), String> {
        if let Some(f) = self.failure() {
            return Err(format!("store failed: {f}"));
        }
        self.st.borrow_mut().checkpoint().map_err(|e| e.to_string())
    }

    fn apply_room(&self, spg: SpgT, bytes: u64, entries: u64) -> bool {
        let st = self.st.borrow();
        #[cfg(feature = "test-knobs")]
        if self.deny_room_shard.get() == Some(st.pg_shard(spg.pgid.pool, spg.pgid.seed)) {
            return false;
        }
        st.apply_room(&pg_coll(spg), bytes, entries)
    }

    fn check_write(
        &self,
        spg: SpgT,
        middle: &bytes::Bytes,
        data: &bytes::Bytes,
    ) -> Result<(), WriteErr> {
        self.check_write_op(
            spg,
            middle.len(),
            data.len(),
            replwire::Transaction::expands_objects(middle, data).unwrap_or(false),
            || StoreOp::ApplyTxn {
                middle: middle.clone(),
                data: data.clone(),
            },
        )
    }

    fn check_write_split(
        &self,
        spg: SpgT,
        skel: &bytes::Bytes,
        refs: &[bytes::Bytes],
    ) -> Result<(), WriteErr> {
        let n = skel.len() + refs.iter().map(|r| r.len()).sum::<usize>();
        self.check_write_op(
            spg,
            0,
            n,
            replwire::Transaction::expands_objects(&[], skel).unwrap_or(false),
            || StoreOp::ApplyTxnSplit {
                skel: skel.clone(),
                refs: refs.to_vec(),
                hints: Vec::new(),
            },
        )
    }

    fn warm(&self, spg: SpgT, soid: &Hobject, off: u64, len: u64) -> bool {
        self.warm_probe(spg, gate_why::OBJ, |st| {
            st.warm(&pg_coll(spg), &gh(spg, soid), off, len)
        })
    }

    fn warm_rm(&self, spg: SpgT, soid: &Hobject) -> bool {
        self.warm_probe(spg, gate_why::OBJ, |st| {
            st.warm_rm(&pg_coll(spg), &gh(spg, soid))
        })
    }

    fn lease_open(&self, spg: SpgT) -> u64 {
        self.st.borrow_mut().lease_open(&pg_coll(spg)).unwrap_or(0)
    }

    fn lease_use(&self, lease: u64) {
        self.st.borrow_mut().lease_use(lease);
    }

    fn lease_release(&self, lease: u64) {
        self.st.borrow_mut().lease_release(lease);
    }

    fn lease_release_pg(&self, spg: SpgT) {
        self.st.borrow_mut().lease_release_coll(&pg_coll(spg));
    }

    fn warm_log(&self, spg: SpgT, head: Eversion) -> bool {
        // No shard write gate (adr 0082 am. 2): a write behind parked txns of other PGs queues behind them in the FIFO;
        // its own PG's parked txn fences the pgmeta key below; a big txn's size pre-flight refuses while the FIFO is
        // non-empty (`Store::check_txn`, non-blocking).
        let next = Eversion::new(head.epoch, head.version.saturating_add(1));
        let k = meta::log_key(next);
        self.warm_probe(spg, gate_why::LOG, |st| {
            st.warm_omap(&pg_coll(spg), &pgmeta(spg), &[k.as_slice()])
        })
    }

    fn lazy_info(&self) -> bool {
        self.lazy_info
    }

    fn set_dedup_digest(&self, alg: &str) -> bool {
        match store::obj::dedup::DigestAlg::parse(alg) {
            Some(a) => {
                self.dd_alg.set(a);
                true
            }
            None => false,
        }
    }

    fn set_dedup_zero_objects(&self, on: bool) {
        self.dd_zero.set(on);
    }

    /// Every read makes progress: at least one block of data, at least one omap key.
    fn set_deep_scrub_reads(&self, stride: u64, keys: u64) {
        self.scrub_stride.set(stride.max(store::BLK as u64));
        self.scrub_keys
            .set(usize::try_from(keys.max(1)).unwrap_or(usize::MAX));
    }

    fn dedup_list(
        &self,
        r: &peering::store::DedupListReq,
    ) -> Option<Result<peering::store::DedupListPart, String>> {
        Some(self.dedup_list_local(r))
    }

    fn dedup_stats(&self, pool: i64) -> Option<(u64, u64)> {
        self.dedup_stats_local(pool).ok()
    }

    fn dedup_clear(&self, pool: i64) -> Option<Result<(), String>> {
        Some(self.dedup_clear_local(pool))
    }

    fn dedup_wall_ns(&self) -> Option<u64> {
        Some(dedup::now_ns())
    }

    fn scrub_role(&self, spg: SpgT, primary: bool) {
        self.set_scrub_primary(spg, primary);
    }

    fn set_pool_reformat(&self, pool: u64, engines: &str) -> Vec<String> {
        let (e, unknown) = reformat::Engines::parse(engines);
        self.set_pool_engines(pool, e);
        unknown
    }

    fn set_pool_compression(&self, pool: u64, o: &peering::store::PoolCompOpts) {
        use store::compress::{Alg, Mode, PoolComp};
        let mode = Mode::parse(&o.mode);
        // classic default algorithm: snappy; an unknown name stores uncompressed
        let alg = if o.algorithm.is_empty() {
            Some(Alg::Snappy)
        } else {
            Alg::parse(&o.algorithm)
        };
        let pc = match alg {
            Some(alg) if mode != Mode::None => {
                let mut p = PoolComp::new(mode, alg);
                if o.required_ratio > 0.0 {
                    p.ratio_permille = (o.required_ratio.clamp(0.0, 1.0) * 1000.0) as u32;
                }
                if o.min_blob > 0 {
                    p.min_blob = o.min_blob.min(1 << 24) as u32;
                }
                if o.max_blob > 0 {
                    p.max_blob = o.max_blob.min(1 << 24) as u32;
                }
                Some(p)
            }
            _ => None,
        };
        self.set_pool_comp(pool, pc);
    }

    /// Probing every write costs ~2 us of a ~9 us write on a warm cache: probe only while the shard's tree cache is
    /// missing (a page load happened in the last 256 probes' worth of writes), its queue holds txns or lacks headroom.
    fn probe_cold_for(&self, spg: SpgT) -> bool {
        let store = self.st.borrow();
        if !store.admission_ready_for(&pg_coll(spg))
            || store.shard_queued(&pg_coll(spg)).unwrap_or(true)
        {
            return true;
        }
        let Ok(loads) = store.shard_page_loads(&pg_coll(spg)) else {
            return true;
        };
        let (seen, budget) = &self.cold_shards[store.shard_of(&pg_coll(spg))];
        if loads != seen.get() {
            seen.set(loads);
            budget.set(256);
        }
        let remaining = budget.get();
        if remaining == 0 {
            return false;
        }
        budget.set(remaining - 1);
        true
    }

    fn warm_data(&self, spg: SpgT, soid: &Hobject, off: u64, len: u64) -> bool {
        self.warm_probe(spg, gate_why::DATA, |st| {
            st.warm_data(&pg_coll(spg), &gh(spg, soid), off, len)
        })
    }

    fn warm_clone_src(&self, spg: SpgT, soid: &Hobject, off: u64, len: u64) -> bool {
        self.st
            .borrow_mut()
            .warm_clone_src(&pg_coll(spg), &gh(spg, soid), off, len)
            .unwrap_or(true)
    }

    fn take_wake(&mut self) -> bool {
        self.st.borrow_mut().take_wake()
    }

    #[cfg(feature = "elastic")]
    fn pool_take(&self, out: &mut Vec<peering::PoolMsg>) {
        use peering::PoolMsg as P;
        use store::lend::LendMsg as L;
        let mut st = self.st.borrow_mut();
        if !st.lend_active() {
            return;
        }
        let mut v = Vec::new();
        st.take_lend_out(&mut v);
        out.extend(v.into_iter().map(|m| match m {
            L::Request { shard, short } => P::Request { shard, short },
            L::Grant {
                shard,
                slot,
                phys,
                pool,
            } => P::Grant {
                shard,
                slot,
                phys,
                pool,
            },
            L::Deny { shard, pool } => P::Deny { shard, pool },
            L::Return { shard, slot, phys } => P::Return { shard, slot, phys },
            L::Grew { shard, pool } => P::Grew { shard, pool },
            L::Size {
                shard,
                pool,
                spare,
                target,
                prog,
            } => P::Size {
                shard,
                pool,
                spare,
                target,
                prog,
            },
            L::Spare {
                shard,
                chunks,
                prog,
            } => P::Spare {
                shard,
                chunks,
                prog,
            },
        }));
    }

    #[cfg(feature = "elastic")]
    fn pool_in(&self, m: peering::PoolMsg) {
        use peering::PoolMsg as P;
        use store::lend::LendMsg as L;
        self.st.borrow_mut().lend_in(match m {
            P::Request { shard, short } => L::Request { shard, short },
            P::Grant {
                shard,
                slot,
                phys,
                pool,
            } => L::Grant {
                shard,
                slot,
                phys,
                pool,
            },
            P::Deny { shard, pool } => L::Deny { shard, pool },
            P::Return { shard, slot, phys } => L::Return { shard, slot, phys },
            P::Grew { shard, pool } => L::Grew { shard, pool },
            P::Size {
                shard,
                pool,
                spare,
                target,
                prog,
            } => L::Size {
                shard,
                pool,
                spare,
                target,
                prog,
            },
            P::Spare {
                shard,
                chunks,
                prog,
            } => L::Spare {
                shard,
                chunks,
                prog,
            },
        });
    }

    fn take_wake_set(&mut self, ws: &mut peering::wake::WakeSet) -> bool {
        let toks = &mut self.wake_toks;
        toks.clear();
        let mut all = false;
        let any = self.st.borrow_mut().take_wake_set(toks, &mut all);
        ws.all |= all;
        for &t in toks.as_slice() {
            ws.push(t);
        }
        any
    }

    fn diag(&self) -> String {
        self.st.try_borrow().map(|s| s.diag()).unwrap_or_default()
    }

    fn io_quiet(&self) -> bool {
        self.failed.borrow().is_none()
            && self.deferred.borrow().is_empty()
            && self.deferred_done.borrow().is_empty()
            && self.removing.borrow().is_empty()
            && self.st.try_borrow().is_ok_and(|s| s.quiet())
    }

    fn set_owner_wake(&mut self, w: std::sync::Arc<dyn Fn() + Send + Sync>) {
        if let Ok(s) = self.st.try_borrow() {
            s.set_owner_wake(w);
        }
    }

    fn handed_completion(&self) -> bool {
        // An unexpected outstanding borrow means "cannot prove idle": do not sleep.
        self.st.try_borrow().map_or(true, |s| s.handed_completion())
    }

    fn io_wait_hint(&mut self) -> Option<std::time::Duration> {
        if self.failed.borrow().is_some()
            || !self.deferred.borrow().is_empty()
            || !self.deferred_done.borrow().is_empty()
            || !self.removing.borrow().is_empty()
        {
            return None;
        }
        self.st.try_borrow_mut().ok()?.wait_hint()
    }

    fn take_notes(&mut self) -> Vec<String> {
        std::mem::take(&mut self.notes.borrow_mut())
    }

    fn gc_orphans_after_load(&mut self) {
        if let Err(e) = self.gc_orphans() {
            self.fail("gc orphan collections", &e);
        }
    }

    fn place(&self, pgid: denc::types::PgT, shard: u32) {
        if let Err(e) = self.drain_fifo() {
            self.fail("placement barrier", &e);
            return;
        }
        self.st
            .borrow_mut()
            .set_placement(pgid.pool, pgid.seed, shard);
    }

    fn shards(&self) -> u32 {
        self.st.borrow().nshards() as u32
    }

    fn shard_of_pg(&self, pgid: denc::types::PgT) -> Option<u32> {
        Some(self.st.borrow().pg_shard(pgid.pool, pgid.seed))
    }

    fn mig_export(
        &self,
        spg: SpgT,
        cur: &mut peering::store::ExportCursor,
        budget: usize,
    ) -> Result<(Vec<peering::store::MigOp>, bool), String> {
        self.export_chunk(spg, cur, budget)
            .map_err(|e| e.to_string())
    }

    fn mig_import(
        &self,
        spg: SpgT,
        ops: Vec<peering::store::MigOp>,
    ) -> Result<(), peering::store::MigImportError> {
        use peering::store::MigImportError as E;
        self.import_ops(spg, ops).map_err(|e| match e {
            ObjError::NoSpace => E::NoSpace,
            e => E::Failed(e.to_string()),
        })
    }

    fn mig_gen(&self, spg: SpgT) -> u64 {
        StoreAdapter::mig_gen(self, spg)
    }

    fn mig_complete(&self, spg: SpgT) -> bool {
        self.pg_is_complete(spg)
    }

    fn mig_remove(&self, spg: SpgT) -> Result<(), String> {
        self.remove_pg(spg).map_err(|e| e.to_string())
    }

    fn admission_ready(&self) -> bool {
        self.st.borrow().admission_ready()
    }

    fn bg_ns(&self) -> u64 {
        self.st.borrow().bg_ns() + self.rm_step_ns.get()
    }

    fn pre_write(&self, spg: SpgT, piece: &bytes::Bytes) -> Option<peering::store::PreTicket> {
        if !self.pre_pool(spg.pgid.pool) {
            return None;
        }
        let (shard, id) = self
            .st
            .borrow_mut()
            .pre_write(&pg_coll(spg), piece)?
            .parts();
        Some(peering::store::PreTicket { shard, id })
    }

    fn pre_piece(&self) -> usize {
        self.st.borrow().pre_piece()
    }

    fn pre_pool(&self, pool: u64) -> bool {
        !self.pool_comp.borrow().contains_key(&pool)
    }

    fn pre_closed(&self) -> u64 {
        self.st.borrow().pre_closed()
    }

    fn pre_open(&self, t: peering::store::PreTicket) -> bool {
        self.st
            .borrow()
            .pre_open(store::obj::PreTicket::from_parts(t.shard, t.id))
    }

    fn pre_release(&self, t: peering::store::PreTicket) {
        self.st
            .borrow_mut()
            .pre_release(store::obj::PreTicket::from_parts(t.shard, t.id));
    }
    fn admission_ready_for(&self, spg: SpgT) -> bool {
        #[cfg(feature = "test-knobs")]
        if self.deny_admission_shard.get()
            == Some(self.st.borrow().pg_shard(spg.pgid.pool, spg.pgid.seed))
        {
            return false;
        }
        self.st.borrow().admission_ready_for(&pg_coll(spg))
    }

    fn mig_sync(&self) -> Result<(), String> {
        self.drain_fifo().map_err(|e| e.to_string())?;
        self.st.borrow_mut().sync().map_err(|e| e.to_string())
    }

    fn mig_bytes(&self, spg: SpgT) -> Result<u64, String> {
        StoreAdapter::mig_bytes(self, spg).map_err(|e| e.to_string())
    }

    fn mig_reserve(&self, pgid: denc::types::PgT, shard: u32, bytes: u64) -> bool {
        StoreAdapter::mig_reserve(self, pgid, shard, bytes)
    }

    fn mig_release_all(&self) {
        StoreAdapter::mig_release_all(self)
    }

    fn mig_rooms(&self) -> Vec<(u32, u64)> {
        self.st.borrow().mig_rooms()
    }

    #[cfg(feature = "elastic")]
    fn mig_want(&self, shard: u32, bytes: u64) {
        self.st.borrow_mut().mig_want(shard, bytes);
    }

    fn request_checkpoint(&mut self) {
        self.st.borrow_mut().request_checkpoint();
    }

    fn cache_status(&self) -> Vec<(&'static str, u64)> {
        self.st.borrow().cache_status()
    }

    fn drop_caches(&mut self) -> Vec<(&'static str, u64)> {
        let d = self.st.borrow_mut().drop_caches();
        vec![
            ("dropped_tree_pages", d.tree_pages),
            ("dropped_tree_bytes", d.tree_bytes),
            ("dropped_data_bytes", d.data_bytes),
            ("dropped_other_bytes", d.decomp_bytes + d.omap_run_bytes),
        ]
    }

    fn store_census(&mut self, request: bool) -> Vec<(&'static str, u64)> {
        let mut st = self.st.borrow_mut();
        if request {
            st.request_census();
        }
        let (c, seq) = st.census();
        let r = st.rc_stats();
        vec![
            ("census_seq", seq),
            ("objects", c.objects),
            ("records", c.records),
            ("plain_blocks", c.plain_blocks),
            ("chunks", c.chunks),
            ("chunk_blocks", c.chunk_blocks),
            ("comp_logical_blocks", c.comp_logical),
            ("windows", c.windows),
            ("cut_chunks", c.cut_chunks),
            ("cut_live_blocks", c.cut_live),
            ("cut_span_blocks", c.cut_span),
            ("unc_objects", c.unc_objects),
            ("unc_records", c.unc_records),
            ("unc_blocks", c.unc_blocks),
            ("recompact_sweeps", r.sweeps),
            ("recompact_chunks", r.chunks),
            ("recompact_freed_blocks", r.freed_blocks),
            ("recompact_new_blocks", r.new_blocks),
            ("recompact_no_gain", r.no_gain),
            ("recompact_skipped", r.skipped),
        ]
    }

    fn store_counters(&self) -> Vec<(&'static str, bool, u64)> {
        self.st.borrow().perf_counters()
    }

    fn mem_pools(&self) -> Vec<(&'static str, u64, u64)> {
        let m = self.st.borrow().mem();
        let t = &m.tree;
        vec![
            (
                "nvme_tree_pages",
                t.pages,
                t.page_bytes + t.touched_bytes + t.slab_bytes,
            ),
            ("nvme_tree_free_slots", t.free_slots, t.free_bytes),
            ("nvme_point_cache", m.point_entries, m.point_bytes),
            ("nvme_delta_chains", t.chains, t.chain_bytes),
            ("nvme_tree_dependencies", 0, t.dependency_bytes),
            ("nvme_alloc_bitmaps", m.alloc_chunks, m.alloc_bytes),
            // a counter, not memory: heap allocations of allocator chunks on the write path (should stay 0)
            ("nvme_alloc_pool_misses", m.alloc_pool_misses, 0),
            ("nvme_ckpt_arena", 0, m.ckpt_bytes),
            ("nvme_omap_runs", m.run_entries, m.run_bytes),
            (
                "nvme_free_lists",
                m.free_q_extents + m.limbo_extents + t.dead + t.retired,
                0,
            ),
            (
                "nvme_wal_units",
                m.ring_units + m.pipeline_units,
                m.pipeline_bytes,
            ),
        ]
    }

    fn free_report(&self) -> Option<(u64, Vec<(u64, u64)>)> {
        let st = self.st.borrow();
        Some((st.data_blocks() * store::BLK as u64, st.free_extents()))
    }

    fn space(&self) -> Option<peering::Space> {
        let s = self.st.borrow().statfs();
        Some(peering::Space {
            total: s.total_bytes,
            available: s.avail_bytes,
            // DATA matches the control core's NvmeMeta report. Metadata and the fullness charge are
            // accounted separately; charging them here inflates DATA on every worker core.
            allocated: s.real_used_bytes.saturating_sub(s.real_meta_bytes),
            internal_metadata: s.meta_used_bytes,
            pooled: s.pooled,
            fullest: f64::from(s.fullest_shard_pct) / 100.0,
        })
    }

    fn space_shards(&self) -> Vec<ShardSpace> {
        let st = self.st.borrow();
        let pooled = st.statfs().pooled;
        st.shards
            .iter()
            .map(|s| {
                let f = s.sh.statfs();
                let used = (f.fill_ratio() * f.data_blocks as f64) as u64 * store::BLK as u64;
                let allocated =
                    (f.used_blocks() * store::BLK as u64).saturating_sub(f.meta_in_data_bytes());
                let total = f.data_blocks * store::BLK as u64;
                ShardSpace {
                    shard: s.idx,
                    space: peering::Space {
                        total,
                        available: total - used,
                        allocated,
                        internal_metadata: f.meta_used * f.meta_bpp * store::BLK as u64,
                        pooled,
                        fullest: f.pooled_fill_ratio(),
                    },
                    data_used_bytes: f.data_used * store::BLK as u64,
                    data_held_bytes: f.data_held * store::BLK as u64,
                    data_reserved_bytes: f.data_reserved * store::BLK as u64,
                    data_reserve_bytes: f.data_reserve * store::BLK as u64,
                    meta_used_pages: f.meta_used,
                    meta_cell_used_pages: f.meta_cell_used,
                    meta_base_pages: f.meta_base_pages,
                    meta_cell_blocks: f.meta_cell_blocks,
                    meta_blocks_per_page: f.meta_bpp,
                    meta_dirty_pages: f.dirty_pages,
                    meta_run_pages: f.run_pages,
                    meta_usable_pages: f.meta_usable_pages(),
                    meta_grow_blocked: f.meta_grow_blocked,
                    elastic: f.elastic,
                    meta_growth_failure: s
                        .sh
                        .last_meta_growth_failure()
                        .map(peering_meta_growth_failure),
                }
            })
            .collect()
    }

    fn recovery_info_checked(
        &self,
        spg: SpgT,
        soid: &Hobject,
    ) -> Result<ObjectRecoveryInfo, StoreReadError> {
        let oi = self.read_oi(spg, soid)?;
        // a clone carries its head's SnapSet (spec replication 6.2): the receiver derives the mapper entry from it
        let ss_src = if peering::snaps::is_clone(soid) {
            let mut h = soid.clone();
            h.snap = denc::types::SnapId::NOSNAP;
            h
        } else {
            soid.clone()
        };
        let ss = match self.xattr(spg, &ss_src, b"snapset") {
            Ok(Some(b)) => denc::from_slice::<SnapSet>(&b).map_err(|e| {
                self.note_damage(format!(
                    "pg {spg}: snapset of {} undecodable: {e}",
                    oname(&ss_src)
                ));
                StoreReadError::Corrupt
            })?,
            Ok(None) => SnapSet::default(),
            Err(_) => return Err(StoreReadError::Io),
        };
        let (c, g) = (pg_coll(spg), gh(spg, soid));
        let mut st = self.st.borrow_mut();
        let size = match st.stat(&c, &g) {
            Ok(Some(s)) => s.size,
            Ok(None) => return Err(StoreReadError::NoObject),
            Err(_) => return Err(StoreReadError::Io),
        };
        Ok(ObjectRecoveryInfo {
            soid: soid.clone(),
            version: oi.version,
            size,
            copy_subset: BTreeMap::from([(0, size)]),
            clone_subset: BTreeMap::new(),
            object_exist: true,
            // omap keys are not counted (adr 0610); the push is chunked by key cursor
            num_omap_keys: 0,
            oi,
            ss,
        })
    }

    fn build_push(
        &self,
        spg: SpgT,
        ri: &ObjectRecoveryInfo,
        before: &ObjectRecoveryProgress,
        max_chunk: u64,
        max_omap_entries: usize,
    ) -> Result<PushOp, StoreReadError> {
        let io = |_e: ObjError| StoreReadError::Io;
        let (c, g) = (pg_coll(spg), gh(spg, &ri.soid));
        let size = self
            .st
            .borrow_mut()
            .stat(&c, &g)
            .map_err(io)?
            .ok_or(StoreReadError::NoObject)?
            .size;
        // the first chunk reads all xattrs anyway: object_info comes from them (same checks as read_oi)
        let (oi, attrs) = if before.first {
            if self.removal_queued(spg) {
                return Err(StoreReadError::NoObject);
            }
            let r = self.st.borrow_mut().getattrs(&c, &g);
            let oi = self.decode_oi(
                spg,
                &ri.soid,
                r.as_ref()
                    .map(|m| m.get(b"_".as_slice()).map(Vec::as_slice)),
            )?;
            (oi, r.unwrap_or_default())
        } else {
            (self.read_oi(spg, &ri.soid)?, BTreeMap::new())
        };
        if oi.version != ri.version {
            return Err(StoreReadError::VersionMismatch);
        }
        let mut after = before.clone();
        let mut budget = max_chunk;
        let mut op = PushOp {
            soid: ri.soid.clone(),
            version: ri.version,
            recovery_info: ri.clone(),
            before_progress: before.clone(),
            ..Default::default()
        };
        let mut st = self.st.borrow_mut();
        if before.first {
            op.omap_header = st.omap_header(&c, &g).map_err(io)?;
            op.attrset.extend(attrs);
            after.first = false;
        }
        if !before.omap_complete {
            let (kv, next) = st
                .omap_recovery_range(&c, &g, &before.omap_recovered_to, max_omap_entries, budget)
                .map_err(io)?;
            for (k, v) in kv {
                budget = budget.saturating_sub((k.len() + v.len()) as u64);
                op.omap_entries.insert(k, v);
            }
            if let Some(next) = next {
                after.omap_recovered_to = next;
            } else {
                after.omap_complete = true;
            }
        }
        let range_end = ri
            .copy_subset
            .iter()
            .map(|(s, l)| s.saturating_add(*l))
            .max()
            .unwrap_or(0);
        if budget > 0 && !ri.copy_subset.is_empty() {
            // one chunk per copy_subset range, concatenated in interval order (= `data`, spec 6.2)
            let mut parts: Vec<bytes::Bytes> = Vec::new();
            for (&off, &len) in &ri.copy_subset {
                let end = off.checked_add(len).ok_or(StoreReadError::Corrupt)?;
                if end <= after.data_recovered_to {
                    continue;
                }
                let start = off.max(after.data_recovered_to);
                let to = end.min(start.saturating_add(budget));
                if to > size {
                    return Err(StoreReadError::Corrupt);
                }
                if to > start {
                    let bytes = st.read(&c, &g, start, to - start).map_err(io)?;
                    if bytes.len() as u64 != to - start {
                        return Err(StoreReadError::Corrupt);
                    }
                    parts.push(bytes.into());
                    op.data_included.insert(start, to - start);
                    budget -= to - start;
                }
                after.data_recovered_to = to;
                if budget == 0 {
                    break;
                }
            }
            if parts.len() > 1 {
                let mut v = Vec::with_capacity(parts.iter().map(bytes::Bytes::len).sum());
                for p in &parts {
                    v.extend_from_slice(p);
                }
                op.data = v.into();
            } else if let Some(p) = parts.pop() {
                op.data = p;
            }
        } else if ri.copy_subset.is_empty() {
            after.data_recovered_to = 0;
        }
        if after.data_recovered_to >= range_end {
            after.data_complete = true;
        }
        // A multi-chunk receiver builds a fresh temp object: even clean omap must
        // be sent before that temp can replace the live copy (replication.md 6.3).
        if before.first && before.omap_complete && !after.data_complete {
            after.omap_complete = false;
        }
        op.after_progress = after;
        Ok(op)
    }

    fn list_objects(
        &self,
        spg: SpgT,
        begin: &Hobject,
        _min: usize,
        max: usize,
    ) -> Result<peering::ObjListing, StoreReadError> {
        let c = pg_coll(spg);
        let mut out = peering::ObjListing::empty();
        if self.removal_queued(spg) {
            return Ok(out); // being deleted: empty, never the old objects (`deferred`)
        }
        let mut cur = gh(spg, begin);
        match self.st.borrow_mut().coll_exists(&c) {
            Ok(true) => {}
            Ok(false) => return Ok(out),
            Err(e) => {
                self.note_damage(format!("pg {spg}: list objects: {e}"));
                return Err(StoreReadError::Io);
            }
        }
        loop {
            let r = self.st.borrow_mut().list(&c, &cur, None, 64);
            let (objs, next) = match r {
                Ok(r) => r,
                Err(e) => {
                    // no partial list: callers must not derive anything from a scan that did not finish
                    self.note_damage(format!("pg {spg}: list objects: {e}"));
                    return Err(StoreReadError::Io);
                }
            };
            for o in objs {
                if !is_user_object(&o) {
                    continue;
                }
                if out.objs.len() + out.corrupt.len() >= max {
                    out.next = o.hobj;
                    return Ok(out);
                }
                match self.read_oi(spg, &o.hobj) {
                    Ok(oi) => out.objs.push((o.hobj, oi.version)),
                    Err(StoreReadError::Corrupt) => out.corrupt.push(o.hobj),
                    // listed a moment ago and gone / unreadable: the scan cannot be trusted
                    Err(_) => return Err(StoreReadError::Io),
                }
            }
            match next {
                Some(n) => cur = n,
                None => return Ok(out),
            }
        }
    }

    fn object_version(&self, spg: SpgT, soid: &Hobject) -> Result<Eversion, StoreReadError> {
        self.read_oi(spg, soid).map(|oi| oi.version)
    }

    fn omap_keys_over(&self, spg: SpgT, soid: &Hobject, limit: u64) -> Option<bool> {
        // keys only (no values copied); at least one key is admitted, like the recovery scan
        let limit = usize::try_from(limit).unwrap_or(usize::MAX).max(1);
        self.st
            .borrow_mut()
            .omap_range(
                &pg_coll(spg),
                &gh(spg, soid),
                &[],
                &[],
                limit,
                usize::MAX,
                false,
            )
            .ok()
            .map(|(_, more)| more)
    }

    fn reset_scrub(&self, spg: SpgT) {
        self.reset_scrub_state(spg);
    }

    fn build_scrub_map(
        &self,
        spg: SpgT,
        start: &Hobject,
        end: &Hobject,
        deep: bool,
        max_objects: usize,
        max_bytes: u64,
    ) -> peering::ScrubPart {
        self.scrub_slice(spg, start, end, deep, max_objects, max_bytes)
    }

    fn build_scrub_map_ec(
        &self,
        spg: SpgT,
        start: &Hobject,
        end: &Hobject,
        deep: bool,
        max_objects: usize,
        max_bytes: u64,
        mode: replwire::ecscrub::EcScrubMode,
        chunk: u32,
    ) -> peering::ScrubPart {
        self.scrub_slice_ec(spg, start, end, deep, max_objects, max_bytes, mode, chunk)
    }

    fn ec_read(
        &self,
        spg: SpgT,
        soid: &Hobject,
        off: u64,
        len: u64,
    ) -> Result<(Vec<u8>, u64), i32> {
        let (c, g) = (pg_coll(spg), gh(spg, soid));
        let mut st = self.st.borrow_mut();
        let size = st.stat(&c, &g).map_err(errno)?.ok_or(-ENOENT)?.size;
        if off >= size || len == 0 {
            return Ok((Vec::new(), size));
        }
        let n = len.min(size - off);
        let data = st.read(&c, &g, off, n).map_err(errno)?;
        Ok((data, size))
    }

    fn ec_read_crc(
        &self,
        spg: SpgT,
        soid: &Hobject,
        off: u64,
        len: u64,
    ) -> Result<(Vec<u8>, u64, Option<u32>), i32> {
        let (c, g) = (pg_coll(spg), gh(spg, soid));
        let mut st = self.st.borrow_mut();
        let size = st.stat(&c, &g).map_err(errno)?.ok_or(-ENOENT)?.size;
        if off >= size || len == 0 {
            return Ok((Vec::new(), size, None));
        }
        let (data, crc) = st
            .read_crc(&c, &g, off, len.min(size - off))
            .map_err(errno)?;
        Ok((data, size, crc))
    }

    fn ec_read_shared(
        &self,
        spg: SpgT,
        soid: &Hobject,
        off: u64,
        len: u64,
    ) -> Result<(Vec<(bytes::Bytes, Option<u32>)>, u64), i32> {
        let (c, g) = (pg_coll(spg), gh(spg, soid));
        let mut st = self.st.borrow_mut();
        let size = st.stat(&c, &g).map_err(errno)?.ok_or(-ENOENT)?.size;
        if off >= size || len == 0 {
            return Ok((Vec::new(), size));
        }
        let parts = st
            .read_shared(&c, &g, off, len.min(size - off))
            .map_err(errno)?;
        Ok((parts, size))
    }

    fn ec_getattr(&self, spg: SpgT, soid: &Hobject, name: &[u8]) -> Result<Option<Vec<u8>>, i32> {
        let (c, g) = (pg_coll(spg), gh(spg, soid));
        self.st.borrow_mut().getattr(&c, &g, name).map_err(errno)
    }

    fn ec_getattrs(&self, spg: SpgT, soid: &Hobject) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, i32> {
        let (c, g) = (pg_coll(spg), gh(spg, soid));
        self.st
            .borrow_mut()
            .getattrs(&c, &g)
            .map(|m| m.into_iter().collect())
            .map_err(errno)
    }

    fn ec_omap_header(&self, spg: SpgT, soid: &Hobject) -> Result<Vec<u8>, i32> {
        let (c, g) = (pg_coll(spg), gh(spg, soid));
        self.st.borrow_mut().omap_header(&c, &g).map_err(errno)
    }

    fn ec_omap_read(
        &self,
        spg: SpgT,
        soid: &Hobject,
        after: Option<&[u8]>,
        max_bytes: u64,
        max_entries: usize,
    ) -> Result<(Vec<(Vec<u8>, Vec<u8>)>, bool), i32> {
        let (c, g) = (pg_coll(spg), gh(spg, soid));
        // The store scan starts at `from` inclusive: first key, or smallest key above `after`.
        let from = after.map_or_else(Vec::new, |a| key_after(a.to_vec()));
        let want = if max_entries == 0 {
            usize::MAX
        } else {
            max_entries
        };
        let mut st = self.st.borrow_mut();
        // Recovery's scan stops at >= budget; EC stops at > budget. The one-byte
        // adjustment admits an exact fit without loading the next value just to reject it.
        let (mut kv, mut next) = st
            .omap_recovery_range(&c, &g, &from, want, max_bytes.saturating_add(1))
            .map_err(errno)?;
        // The wire cursor cannot resume after an empty key. Match omap_batch:
        // a nonfinal batch containing it must also include the next key, even
        // if the empty-key value consumed the whole byte/entry budget.
        if kv.len() == 1
            && kv[0].0.is_empty()
            && let Some(from) = next.take()
        {
            let remaining = max_bytes.saturating_sub(kv[0].1.len() as u64);
            let (tail, tail_next) = st
                .omap_recovery_range(
                    &c,
                    &g,
                    &from,
                    want.saturating_sub(1).max(1),
                    remaining.saturating_add(1),
                )
                .map_err(errno)?;
            kv.extend(tail);
            next = tail_next;
        }
        #[cfg(feature = "test-knobs")]
        self.ec_omap_scan_bytes.set(
            self.ec_omap_scan_bytes.get()
                + kv.iter()
                    .map(|(k, v)| (k.len() + v.len()) as u64)
                    .sum::<u64>(),
        );
        Ok((kv, next.is_none()))
    }

    fn ec_list_stash(&self, spg: SpgT) -> Vec<(Hobject, u64)> {
        let c = pg_coll(spg);
        let mut out = Vec::new();
        let mut cur = Ghobject::MIN();
        let mut st = self.st.borrow_mut();
        loop {
            let Ok((v, n)) = st.list(&c, &cur, None, 256) else {
                return out;
            };
            out.extend(
                v.into_iter()
                    .filter(|g| !g.is_pgmeta() && g.generation != Ghobject::NO_GEN)
                    .map(|g| (g.hobj, g.generation)),
            );
            match n {
                Some(x) => cur = x,
                None => return out,
            }
        }
    }

    fn snapmap_next(
        &self,
        spg: SpgT,
        snap: u64,
        max: usize,
    ) -> Result<Vec<Hobject>, StoreReadError> {
        self.map_next(spg, snap, max)
    }

    fn snapmap_get(&self, spg: SpgT, clone: &Hobject) -> Option<Vec<u64>> {
        self.map_snaps(spg, clone)
    }

    fn snapmap_get_checked(
        &self,
        spg: SpgT,
        clone: &Hobject,
    ) -> Result<Option<Vec<u64>>, StoreReadError> {
        self.map_snaps_checked(spg, clone)
    }

    fn snapmap_scan(
        &self,
        spg: SpgT,
        from: &[u8],
        max: usize,
    ) -> Result<(Vec<u64>, Option<Vec<u8>>), StoreReadError> {
        self.map_scan(spg, from, max)
    }

    fn snapmap_check(
        &self,
        spg: SpgT,
        start: &Hobject,
        end: &Hobject,
    ) -> (Vec<peering::snaps::MapOp>, Vec<String>) {
        self.map_check(spg, start, end)
    }

    fn snapmap_key_scan(&self, spg: SpgT) -> Vec<String> {
        self.map_key_scan(spg)
    }

    fn object_stats(&self, spg: SpgT) -> (u64, u64) {
        if self.removal_queued(spg) {
            return (0, 0);
        }
        self.st
            .borrow_mut()
            .coll_stats(&pg_coll(spg))
            .ok()
            .flatten()
            .map_or((0, 0), |s| (s.nobj, s.nbytes))
    }

    fn compress_stats(&self, spg: SpgT) -> (u64, u64) {
        if self.removal_queued(spg) {
            return (0, 0);
        }
        self.st
            .borrow_mut()
            .coll_stats(&pg_coll(spg))
            .ok()
            .flatten()
            .map_or((0, 0), |s| (s.comp, s.comp_orig))
    }
}

impl<D: BlockDev, C: Clock> StoreAdapter<D, C> {
    /// Read exactly `len` bytes of a copy source. A short read means the object is smaller than the size the copy
    /// planned with (it shrank since that stat), which must fail the copy: advancing by the requested length would
    /// leave the rest of the chunk as a hole in the destination (`build_push` refuses the same mismatch).
    pub(crate) fn read_copy(
        &self,
        c: &CollT,
        g: &Ghobject,
        off: u64,
        len: u64,
    ) -> Result<Vec<u8>, ObjError> {
        let data = self.st.borrow_mut().read(c, g, off, len)?;
        if data.len() as u64 != len {
            return Err(ObjError::Eio(format!(
                "short read of {g:?} at {off}+{len}: {} bytes (object shrank under the copy)",
                data.len()
            )));
        }
        Ok(data)
    }

    /// Visit every object handle of collection `c` in store order, `page` handles per store call.
    /// A store error ends the walk with that error (no partial result). The store is not
    /// borrowed while `f` runs.
    pub(crate) fn list_pages(
        &self,
        c: &CollT,
        page: usize,
        mut f: impl FnMut(Vec<Ghobject>) -> Result<(), ObjError>,
    ) -> Result<(), ObjError> {
        let mut cur = Ghobject::MIN();
        loop {
            let (objs, next) = self.st.borrow_mut().list(c, &cur, None, page)?;
            f(objs)?;
            match next {
                Some(n) => cur = n,
                None => return Ok(()),
            }
        }
    }

    /// Visit the whole omap of `(c, o)` in key order, `batch` pairs per store call. A store error
    /// ends the walk with that error. The store is not borrowed while `f` runs.
    pub(crate) fn omap_pages(
        &self,
        c: &CollT,
        o: &Ghobject,
        batch: usize,
        mut f: impl FnMut(store::obj::KvList) -> Result<(), ObjError>,
    ) -> Result<(), ObjError> {
        let mut from = Vec::new();
        loop {
            let (kv, more) = self.st.borrow_mut().omap_iter(c, o, &from, batch)?;
            let next = match (more, kv.last()) {
                (true, Some((k, _))) => Some(key_after(k.clone())),
                _ => None,
            };
            f(kv)?;
            match next {
                Some(n) => from = n,
                None => return Ok(()),
            }
        }
    }
}

#[cfg(any(test, feature = "test-knobs"))]
impl<D: BlockDev, C: Clock> StoreAdapter<D, C> {
    /// Test helper: `CreatePg` for `spg`.
    pub fn submit_create(&self, spg: SpgT) {
        self.try_submit(
            spg,
            &StoreTxn {
                ops: vec![StoreOp::CreatePg],
            },
        )
        .expect("create pg");
    }
}

/// Short printable object name for operator notes.
fn oname(h: &Hobject) -> String {
    format!("{}:{:x}", String::from_utf8_lossy(&h.oid), h.snap.0)
}

/// Count the encoding without allocating or retaining a serialized copy. Version envelopes
/// only patch lengths, so patching is a bounds check in this sink.
fn encoded_input_len<T: denc::Encode + ?Sized>(v: &T) -> denc::Result<usize> {
    struct Count(usize);
    impl denc::BufMut for Count {
        fn len(&self) -> usize {
            self.0
        }
        fn put_slice(&mut self, s: &[u8]) -> denc::Result<()> {
            self.0 = self.0.checked_add(s.len()).ok_or(denc::Error::TooLong)?;
            Ok(())
        }
        fn patch(&mut self, pos: usize, s: &[u8]) {
            assert!(pos.checked_add(s.len()).is_some_and(|end| end <= self.0));
        }
    }
    let mut e = denc::Encoder::from_buf(Count(0));
    v.encode(&mut e)?;
    Ok(e.len())
}

fn queued_input_bytes(txn: &StoreTxn) -> usize {
    fn size<T: denc::Encode + ?Sized>(v: &T) -> usize {
        encoded_input_len(v).map_or(usize::MAX / 4, |len| {
            len.saturating_mul(4)
                .saturating_add(std::mem::size_of_val(v))
        })
    }
    txn.ops
        .iter()
        .map(|o| {
            std::mem::size_of::<StoreOp>()
                + match o {
                    StoreOp::ApplyTxn { middle, data } => middle.len() + data.len(),
                    StoreOp::ApplyTxnSplit { skel, refs, .. } => {
                        skel.len() + refs.iter().map(bytes::Bytes::len).sum::<usize>()
                    }
                    StoreOp::PutInfo(v) => encoded_input_len(&**v).unwrap_or(usize::MAX / 2),
                    StoreOp::PutPastIntervals(v) => {
                        encoded_input_len(&**v).unwrap_or(usize::MAX / 2)
                    }
                    StoreOp::TxnHint(_) | StoreOp::LogTrim { .. } => 0,
                    StoreOp::LogReplace(v) => encoded_input_len(&**v).unwrap_or(usize::MAX / 2),
                    StoreOp::LogAppendFast(v) => v.iter().map(|e| e.bl.len()).sum(),
                    StoreOp::LogAppend(v) | StoreOp::LogAppendKeep(v) => v
                        .iter()
                        .map(|e| encoded_input_len(e).unwrap_or(usize::MAX / 2))
                        .sum(),
                    StoreOp::LogDups(v) => v.iter().map(size).sum(),
                    StoreOp::Missing(v) => v
                        .iter()
                        .map(|(o, m)| size(o) + m.as_ref().map_or(0, size))
                        .sum(),
                    StoreOp::RemoveObject(o) => size(o),
                    StoreOp::SnapMap(v) => v
                        .iter()
                        .map(|o| match o {
                            peering::snaps::MapOp::Set { clone, snaps } => {
                                size(clone) + snaps.len() * 8
                            }
                            peering::snaps::MapOp::Remove { clone } => size(clone),
                        })
                        .sum(),
                    StoreOp::Shard(v) => v
                        .iter()
                        .map(|o| {
                            std::mem::size_of_val(o)
                                + match o {
                                    peering::store::ShardOp::Remove { soid, .. }
                                    | peering::store::ShardOp::Rename { soid, .. }
                                    | peering::store::ShardOp::Truncate { soid, .. }
                                    | peering::store::ShardOp::CloneRange { soid, .. } => {
                                        size(soid)
                                    }
                                    peering::store::ShardOp::SetAttrs { soid, attrs, .. } => {
                                        size(soid)
                                            + attrs
                                                .iter()
                                                .map(|(k, v)| {
                                                    k.len() + v.as_ref().map_or(0, Vec::len) + 64
                                                })
                                                .sum::<usize>()
                                    }
                                    peering::store::ShardOp::Omap { soid, omap, .. } => {
                                        size(soid)
                                            + omap.header.as_ref().map_or(0, Vec::len)
                                            + omap
                                                .ups
                                                .iter()
                                                .map(|u| match u {
                                                    ec::moddesc::OmapUp::Remove(v) => {
                                                        v.iter().map(|k| k.len() + 32).sum()
                                                    }
                                                    ec::moddesc::OmapUp::Insert(v) => v
                                                        .iter()
                                                        .map(|(k, v)| k.len() + v.len() + 64)
                                                        .sum(),
                                                    ec::moddesc::OmapUp::RemoveRange(a, b) => {
                                                        a.len() + b.len() + 64
                                                    }
                                                })
                                                .sum::<usize>()
                                    }
                                }
                        })
                        .sum(),
                    // Fixed-size operations retain no additional payload.
                    StoreOp::CreatePg
                    | StoreOp::RemovePg
                    | StoreOp::SplitOut { .. }
                    | StoreOp::MergeIn { .. }
                    | StoreOp::PutEpoch(_)
                    | StoreOp::LogRewind { .. }
                    | StoreOp::LogSetHead(_)
                    | StoreOp::MissingClear { .. }
                    | StoreOp::LogCursors { .. }
                    | StoreOp::LogHeadIs(..) => 0,
                }
        })
        .sum::<usize>()
}

struct QueuedInput {
    spg: SpgT,
    txn: StoreTxn,
    hidden: bool,
    comp: Option<store::compress::PoolComp>,
    orphans: Rc<Cell<u64>>,
}
impl<D: BlockDev, C: Clock> store::obj::QueueBuilder<D, C> for QueuedInput {
    fn build(&mut self, st: &mut Store<D, C>) -> Result<Option<OTxn<'_>>, ObjError> {
        build_input(
            st,
            self.spg,
            &self.txn,
            self.hidden,
            self.comp,
            &self.orphans,
        )
    }
    fn retained_bytes(&self) -> usize {
        queued_input_bytes(&self.txn)
    }
    fn payload_owners(&self) -> Vec<bytes::Bytes> {
        let mut owners = Vec::new();
        for op in &self.txn.ops {
            match op {
                StoreOp::ApplyTxn { middle, data } => {
                    owners.push(middle.clone());
                    owners.push(data.clone());
                }
                StoreOp::ApplyTxnSplit { skel, refs, .. } => {
                    owners.push(skel.clone());
                    owners.extend(refs.iter().cloned());
                }
                _ => {}
            }
        }
        owners
    }
}
/// A mutation of a PG this store does not hold (no collection, or its deletion is queued): the PG layer and the store
/// disagree, a caller bug. The txn is dropped and counted (`orphan_writes`) and the result is a local failure (the
/// adapter fail-stops), never "nothing to write": the PG already logged the txn in memory, a `Durable` would ack a write
/// that is not on disk (review 2026-11-03 #10).
fn orphan_write(orphans: &Cell<u64>) -> ObjError {
    orphans.set(orphans.get() + 1);
    ObjError::Store(store::StoreError::Invalid(
        "mutation of a PG the store does not hold (orphan write)",
    ))
}

/// Translate one PG txn: `None` = nothing to write (empty txn or no-op ops); a PG the store does not hold is an
/// [`orphan_write`] error.
fn build_input<'a, D: BlockDev, C: Clock>(
    st: &mut Store<D, C>,
    spg: SpgT,
    txn: &'a StoreTxn,
    hidden: bool,
    comp: Option<store::compress::PoolComp>,
    orphans: &Cell<u64>,
) -> Result<Option<OTxn<'a>>, ObjError> {
    let ops = txn.ops.as_slice();
    if ops.is_empty() {
        return Ok(None);
    }
    let exists = !hidden && st.coll_exists(&pg_coll(spg))?;
    if !exists && !matches!(ops[0], StoreOp::CreatePg) {
        return Err(orphan_write(orphans));
    }
    let mut t = OTxn::new();
    t.sys = true;
    let mut tr = meta::Translator::new(st, spg, exists).for_ops(ops);
    for op in ops {
        tr.op(op, &mut t)?;
    }
    if let Some(comp) = comp {
        t.comp = comp.resolve(tr.hints);
    }
    Ok(if t.is_empty() { None } else { Some(t) })
}

#[cfg(test)]
mod meta_growth_failure_snapshot_tests {
    use super::*;
    use store::shard::{MetaGrowthFailure, MetaGrowthFailureReason};

    #[test]
    fn conversion_preserves_failure_reason_and_all_captured_counters() {
        let source = MetaGrowthFailure {
            sequence: 3,
            reason: MetaGrowthFailureReason::NoContiguousRun,
            unix_time_ns: 10,
            store_poll_time_ns: 20,
            requested_free_pages: 30,
            free_meta_pages: 40,
            cell_blocks: 256,
            pages_per_cell: 128,
            free_data_blocks: 50,
            held_data_blocks: 60,
            reserved_data_blocks: 70,
            reserve_data_blocks: 80,
            image_bytes: 90,
            image_reserve_bytes: 100,
            deferred_image_bytes: 110,
            image_needed_bytes: 120,
            image_limit_bytes: 130,
            free_windows: 140,
        };
        let converted = peering_meta_growth_failure(source);
        assert_eq!(converted.reason, "no_contiguous_run");
        assert_eq!(converted.sequence, source.sequence);
        assert_eq!(converted.unix_time_ns, source.unix_time_ns);
        assert_eq!(converted.store_poll_time_ns, source.store_poll_time_ns);
        assert_eq!(converted.requested_free_pages, source.requested_free_pages);
        assert_eq!(converted.free_meta_pages, source.free_meta_pages);
        assert_eq!(converted.cell_blocks, source.cell_blocks);
        assert_eq!(converted.pages_per_cell, source.pages_per_cell);
        assert_eq!(converted.free_data_blocks, source.free_data_blocks);
        assert_eq!(converted.held_data_blocks, source.held_data_blocks);
        assert_eq!(converted.reserved_data_blocks, source.reserved_data_blocks);
        assert_eq!(converted.reserve_data_blocks, source.reserve_data_blocks);
        assert_eq!(converted.image_bytes, source.image_bytes);
        assert_eq!(converted.image_reserve_bytes, source.image_reserve_bytes);
        assert_eq!(converted.deferred_image_bytes, source.deferred_image_bytes);
        assert_eq!(converted.image_needed_bytes, source.image_needed_bytes);
        assert_eq!(converted.image_limit_bytes, source.image_limit_bytes);
        assert_eq!(converted.free_windows, source.free_windows);
    }
}

#[cfg(test)]
mod queue_size_tests {
    use super::*;

    #[test]
    fn counting_encoder_preserves_nested_envelope_and_map_sizes() {
        struct Nested;
        impl denc::Encode for Nested {
            fn encode<B: denc::BufMut>(&self, e: &mut denc::Encoder<B>) -> denc::Result<()> {
                e.versioned(3, 1, |e| {
                    e.bytes(b"some metadata")?;
                    e.versioned(2, 1, |e| {
                        for i in 0..1000 {
                            e.varint(i)?;
                        }
                        Ok(())
                    })
                })
            }
        }
        assert_eq!(
            encoded_input_len(&Nested).unwrap(),
            denc::to_vec(&Nested).unwrap().len()
        );
        let map = BTreeMap::from([(vec![0x42u8; 4000], vec![vec![1u32; 1000]; 8])]);
        assert_eq!(
            encoded_input_len(&map).unwrap(),
            denc::to_vec(&map).unwrap().len()
        );
    }
}

#[cfg(test)]
mod perf_audit;
