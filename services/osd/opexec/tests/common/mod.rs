// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Test PG: a `peering::MemStore` behind the engine's `Env`, with an in-memory pg log (versions, reqids, dups) and
//! synchronous "replication" (writes are applied at submit, completion is reported on request).
#![allow(clippy::allow_attributes, dead_code)]

#[macro_use]
mod env_noop;
use denc::types::{
    EntityAddr, EntityName, Eversion, Hobject, ObjectLocator, OsdReqId, PgT, ShardId, SnapId, SpgT,
    UTime,
};
use opexec::{ClientReq, Engine, Env, Limits, ObjView, Out};
use opwire::{ClientMsg, MOSDOp, MOSDOpReply, OsdOp};
use peering::{MemStore, PgStoreOps, StoreOp, StoreTxn, WriteErr, WriteReq};
use pgwire::LogEntry;
use std::collections::BTreeSet;

pub const POOL: u64 = 1;

/// Pending pages per `(object name, offset / 4096)`.
pub type SlotPages = std::collections::BTreeMap<(Vec<u8>, u64), Vec<u64>>;

pub struct TPg {
    pub spg: SpgT,
    pub store: MemStore,
    pub head: Eversion,
    pub entries: Vec<LogEntry>,
    pub luv: u64,
    pub epoch: u32,
    pub done: Vec<(u64, Eversion)>,
    pub tid: u64,
    pub missing: BTreeSet<Hobject>,
    /// Objects missing on a peer (`submit_write` answers `Degraded`, reads are served here).
    pub degraded: BTreeSet<Hobject>,
    /// `Env::is_unfound`: missing here with no location to recover from.
    pub unfound: BTreeSet<Hobject>,
    /// `Env::kick_recovery` calls (an object-level backoff kicks recovery).
    pub kicked: Vec<Hobject>,
    /// Missing objects whose recovery is a delete (still in the store, hidden from listings).
    pub missing_del: BTreeSet<Hobject>,
    /// Objects in the chunk a scrub holds (`Pg::scrub_blocks_write`): `submit_write` answers `Degraded`, reads pass.
    pub scrub: BTreeSet<Hobject>,
    pub active: bool,
    pub readable: bool,
    pub removed: Vec<(u64, u64)>,
    pub now: u64,
    pub notifies: Vec<Out>,
    pub blocked: bool,
    /// `last_epoch_split`: ops sent before this epoch are stale.
    pub split_epoch: u32,
    pub apps: opexec::caps::AppMeta,
    /// Local store has room (`Env::write_room`).
    pub room: bool,
    /// Maximum payload bytes admitted by the local store (None = unlimited).
    pub room_bytes: Option<usize>,
    /// Maximum omap / xattr entries admitted by the local store (None = unlimited).
    pub room_entries: Option<usize>,
    /// `Env::ec_pool` (an EC pool led here).
    pub ec: bool,
    /// `Env::ec_caps` (EC pool op-layer capabilities, client-ops 16.4).
    pub ec_caps: opexec::EcCaps,
    /// `require_osd_release` of the client's map (client-ops 16.5); default = the release this build tracks.
    pub release: u8,
    /// Osdmap values classes read (`Env::cls_map`).
    pub cls_map: opexec::ClsMap,
    /// `Env::ec_wait` names the object's token this many more times (EC decoded cache not filled yet); calls so far.
    pub ec_cold: std::cell::Cell<u32>,
    pub ec_waits: std::cell::Cell<u32>,
    /// EC: objects whose primary read / write is in flight (`ec_wait` names the object's token, on top of `ec_cold`);
    /// every `ec_wait` call records its object in `ec_wait_calls`.
    pub ec_busy_objs: std::cell::RefCell<std::collections::BTreeSet<Vec<u8>>>,
    pub ec_wait_calls: std::cell::RefCell<Vec<Vec<u8>>>,
    /// EC: client shard reads in flight, (object, logical offset) -> read token: a read at that offset waits for it.
    pub ec_rd_busy: std::cell::RefCell<std::collections::BTreeMap<(Vec<u8>, u64), u64>>,
    /// `Env::pool_full()` = (FULL, FULL_QUOTA) and `history.last_epoch_marked_full`.
    pub full: (bool, bool),
    pub pool_eio: bool,
    pub failsafe: bool,
    pub marked_full: u32,
    /// `Env::pool_snapc()`: the pool is in pool-snap mode with this snap context.
    pub pool_snaps: Option<replwire::SnapContext>,
    /// Pool of a second test PG `Env::locate` knows (copy-from across PGs).
    pub remote: Option<SpgT>,
    /// `Env::warm` answers false this many more times (cold store pages).
    pub cold: std::cell::Cell<u32>,
    /// `Env::warm` answers false for these object names until removed (per-object cold pages), recording the refusal
    /// `gate_why::OBJ` for `ObjView::ov_refusal`.
    pub cold_objs: std::cell::RefCell<Vec<Vec<u8>>>,
    pub refusal: std::cell::Cell<u8>,
    /// `Env::gate_in` reasons, in call order.
    pub gated: Vec<u8>,
    /// Pending store pages per object name (adr 0043 am. 9): `Env::warm` answers false while the list is non-empty and logs the
    /// pages as its cause (store wake tokens) unless the name is in `untracked_objs`. `warm_calls` records every `warm`.
    pub obj_pages: std::cell::RefCell<std::collections::BTreeMap<Vec<u8>, Vec<u64>>>,
    /// Same per `(object, offset / 4096)`: ops of one object that wait for different pages.
    pub slot_pages: std::cell::RefCell<SlotPages>,
    pub untracked_objs: std::cell::RefCell<BTreeSet<Vec<u8>>>,
    pub clog: std::cell::RefCell<Vec<u64>>,
    pub warm_calls: std::cell::RefCell<Vec<Vec<u8>>>,
    /// `Env::warm_data` answers false this many more times (cold object data); every probe is recorded in `probes`.
    /// `Env::probe_meta` answers false (warm tree cache: the metadata probe is skipped, `warm` is not asked).
    pub quiet_cache: bool,
    /// `Env::warm_log` answers false this many more times (cold PG log head leaf).
    pub cold_log: std::cell::Cell<u32>,
    pub admission_paused: bool,
    pub cold_data: std::cell::Cell<u32>,
    pub probes: std::cell::RefCell<Vec<(u64, u64)>>,
    /// Largest shipped txn (bytes) the store would take; bigger ones are refused like `PgStoreOps::check_write`.
    pub max_txn: Option<usize>,
    /// The next this many submitted writes are refused by the store's size check while its pages load
    /// (`WriteErr::Blocked`, adr 0021 S8): nothing logged.
    pub check_blocks: u32,
    /// The next this many copy temp-object discards (`WriteReq::discard_temp`) are refused with `WriteErr::Blocked`.
    pub discard_blocks: u32,
    /// Longest omap key / attr store key the store accepts (`ObjView::ov_max_item_key`).
    pub max_item_key: usize,
    /// Names over `max_item_key` use a long-name index: 0 = store refuses them, 1 = store takes them but a replica
    /// cannot, 2 = everybody takes them.
    pub long_names: u8,
    /// Non-blocking omap range reads are refused this many more times (cold tree pages, adr 0021 am. 11).
    pub cold_scan: std::cell::Cell<u32>,
    /// A complete immutable view reply, used only to witness executor ownership.
    pub immutable_listing: Option<bytes::Bytes>,
    /// Those refusals made progress (a listing that continues where it stopped, adr 0021 S8).
    pub scan_progress: std::cell::Cell<bool>,
    /// Non-blocking object listings (`ov_list`) are refused this many more times, each time after the first call of a
    /// run (a run lists one batch, then hits a cold leaf); `ov_list` calls so far.
    pub cold_list: std::cell::Cell<u32>,
    pub list_calls: std::cell::Cell<u32>,
    /// Missing object handles cloned into listing runs (bounded work proof).
    pub missing_listed: std::cell::Cell<usize>,
    run_lists: std::cell::Cell<u32>,
    /// Non-blocking `ov_getattr` calls are refused this many more times (cold onode / attribute page).
    pub cold_attr: std::cell::Cell<u32>,
    pub nb: std::cell::Cell<bool>,
    /// Non-blocking op runs are refused this many more times (cold store page somewhere in the run).
    pub refuse_runs: std::cell::Cell<u32>,
    /// Those refusals claim progress (a data wait, a listing slice): not counted against the engine's try bound.
    pub refuse_progress: std::cell::Cell<bool>,
    pub refused: std::cell::Cell<bool>,
    /// `ov_loads_pending`: page loads of the refused reads are still in flight.
    pub pending: std::cell::Cell<bool>,
    /// `ov_omap_range` calls so far.
    pub scan_runs: std::cell::Cell<u32>,
    /// `ov_take_progress`: set by a refusal that claims progress (`refuse_progress`, `scan_progress`), cleared when taken.
    pub rm_progress: std::cell::Cell<bool>,
    pub credit_owner: std::cell::Cell<Option<(u64, u64)>>,
    pub credit_session: std::cell::Cell<Option<(u64, u64)>>,
    pub credit_slices: std::cell::Cell<u32>,
    pub credit_blocking: std::cell::Cell<u32>,
    pub local_wait: std::cell::Cell<bool>,
    /// Writes are logged and applied by the backend later (EC pipeline): `submit_write` neither logs nor applies, the
    /// test completes them with `on_write_done`.
    pub deferred: bool,
    /// With `deferred`: log the entries at submit (the EC primary logs at generation), so dups are found after a reset.
    pub deferred_log: bool,
    /// Blocklisted client ips (`Env::blocklisted`, ip match only).
    pub blocklist: std::cell::RefCell<Vec<[u8; 4]>>,
    /// `Env::local_damage` accepts (replicated active primary): the object goes missing, `damaged` records it.
    pub repair: bool,
    pub damaged: Vec<Hobject>,
    /// Plain v9 blobs of the submitted writes (`txn_data`; split skeletons are not recorded).
    pub txns: Vec<bytes::Bytes>,
    /// `Env::obj_cache`: object-state generation (bump with [`TPg::foreign`] after changing the store behind the
    /// engine) and capacity (small: eviction runs in every test; 0 = off). EC / deferred PGs never cache.
    pub obj_gen: u64,
    pub obj_cap: usize,
    /// Client io the engine counted (`Env::note_io`), summed.
    pub io: pgwire::IoCount,
    /// Writes stay in flight until [`TPg::release`]: logged at submit, the store txn applied only on success (a
    /// backend that completes later, possibly with an error).
    pub hold: bool,
    /// Held writes: (tid, version, store txn).
    pub held: Vec<(u64, Eversion, StoreTxn)>,
    /// Snap trimmer: the snap `trim_poll` offers and the clones the mapper lists for it (`None` = nothing to trim).
    pub trim: Option<(u64, Vec<Hobject>)>,
    /// Operator notes of the trimmer (`Env::trim_note`).
    pub trim_notes: Vec<String>,
}

impl TPg {
    pub fn new() -> Self {
        Self::in_pool(POOL)
    }

    /// A PG of pool `pool` (cross-PG copy tests).
    pub fn in_pool(pool: u64) -> Self {
        let spg = SpgT {
            pgid: PgT::new(pool, 0),
            shard: ShardId::NO_SHARD,
        };
        let mut store = MemStore::new();
        store.submit(
            spg,
            &StoreTxn {
                ops: vec![StoreOp::CreatePg],
            },
        );
        TPg {
            spg,
            store,
            head: Eversion::new(10, 0),
            entries: Vec::new(),
            luv: 0,
            epoch: 10,
            done: Vec::new(),
            tid: 0,
            missing: BTreeSet::new(),
            degraded: BTreeSet::new(),
            unfound: BTreeSet::new(),
            kicked: Vec::new(),
            missing_del: BTreeSet::new(),
            scrub: BTreeSet::new(),
            active: true,
            readable: true,
            removed: Vec::new(),
            now: 1_000_000_000,
            notifies: Vec::new(),
            blocked: false,
            split_epoch: 0,
            apps: Default::default(),
            room: true,
            room_bytes: None,
            room_entries: None,
            ec: false,
            // an EC pool with optimizations and overwrites: existing EC tests are not restricted; the append-only form
            // is set per test
            ec_caps: opexec::EcCaps {
                allows_optimizations: true,
                requires_aligned_append: false,
                required_alignment: 0,
            },
            release: cls::release::UMBRELLA,
            cls_map: opexec::ClsMap::default(),
            ec_cold: Default::default(),
            ec_waits: Default::default(),
            ec_busy_objs: Default::default(),
            ec_wait_calls: Default::default(),
            ec_rd_busy: Default::default(),
            full: (false, false),
            pool_eio: false,
            failsafe: false,
            marked_full: 0,
            pool_snaps: None,
            remote: None,
            cold: std::cell::Cell::new(0),
            cold_objs: Default::default(),
            refusal: Default::default(),
            gated: Vec::new(),
            obj_pages: Default::default(),
            slot_pages: Default::default(),
            untracked_objs: Default::default(),
            clog: Default::default(),
            warm_calls: Default::default(),
            quiet_cache: false,
            cold_log: Default::default(),
            admission_paused: false,
            cold_data: Default::default(),
            probes: Default::default(),
            max_txn: None,
            check_blocks: 0,
            discard_blocks: 0,
            max_item_key: usize::MAX,
            long_names: 0,
            cold_scan: std::cell::Cell::new(0),
            immutable_listing: None,
            scan_progress: std::cell::Cell::new(false),
            cold_list: Default::default(),
            list_calls: Default::default(),
            missing_listed: Default::default(),
            run_lists: Default::default(),
            cold_attr: Default::default(),
            nb: std::cell::Cell::new(false),
            refuse_runs: Default::default(),
            refuse_progress: Default::default(),
            refused: std::cell::Cell::new(false),
            pending: std::cell::Cell::new(false),
            scan_runs: std::cell::Cell::new(0),
            rm_progress: std::cell::Cell::new(false),
            credit_owner: std::cell::Cell::new(None),
            credit_session: std::cell::Cell::new(None),
            credit_slices: std::cell::Cell::new(0),
            credit_blocking: std::cell::Cell::new(0),
            local_wait: std::cell::Cell::new(false),
            deferred: false,
            deferred_log: false,
            blocklist: Default::default(),
            repair: false,
            damaged: Vec::new(),
            txns: Vec::new(),
            obj_gen: 1,
            obj_cap: 8,
            io: Default::default(),
            hold: false,
            held: Vec::new(),
            trim: None,
            trim_notes: Vec::new(),
        }
    }
}

impl TPg {
    /// The store changed behind the engine (recovery, repair, a test fixture): what the PG does for such txns.
    pub fn foreign(&mut self) {
        self.obj_gen += 1;
    }

    /// Tids of the held writes, in submit order.
    pub fn held_tids(&self) -> Vec<u64> {
        self.held.iter().map(|(t, _, _)| *t).collect()
    }

    /// Complete held write `tid` with `result` (0 = its store txn is applied); returns the engine's outputs.
    pub fn release(&mut self, eng: &mut Engine, tid: u64, result: i32) -> Vec<Out> {
        let i = self
            .held
            .iter()
            .position(|(t, _, _)| *t == tid)
            .expect("held write");
        let (_, v, txn) = self.held.remove(i);
        if result == 0 {
            self.store.submit(self.spg, &txn);
        }
        eng.on_write_done(self, tid, v, result);
        settle(self, eng)
    }
}

impl Default for TPg {
    fn default() -> Self {
        Self::new()
    }
}

macro_rules! delegate_view {
    ($($f:ident($($a:ident: $t:ty),*) -> $r:ty;)*) => {
        $(fn $f(&self, spg: SpgT $(, $a: $t)*) -> $r { self.store.$f(spg $(, $a)*) })*
    };
}

impl ObjView for TPg {
    fn ov_read_shared_verified(
        &self,
        spg: SpgT,
        soid: &Hobject,
        off: u64,
        len: u64,
    ) -> Result<opexec::view::VerifiedRead, i32> {
        let data = self.store.ov_read(spg, soid, off, len)?;
        let block_crcs = data
            .chunks(4096)
            .map(|block| crc::crc32c(0, block))
            .collect();
        Ok(opexec::view::VerifiedRead {
            parts: vec![(data.into(), None)],
            block_crcs: Some(block_crcs),
        })
    }
    fn ov_max_item_key(&self) -> usize {
        self.max_item_key
    }
    fn ov_name_fits(&self, _spg: SpgT, soid: &Hobject) -> bool {
        soid.oid.len() <= self.max_item_key || self.long_names != 0
    }
    fn ov_name_repl_ok(&self, _spg: SpgT, soid: &Hobject) -> bool {
        self.long_names != 1 || soid.oid.len() <= self.max_item_key
    }
    fn ov_nonblock(&self, on: bool) {
        self.nb.set(on);
        self.run_lists.set(0);
        let n = self.refuse_runs.get();
        if on && n > 0 {
            self.refuse_runs.set(n - 1);
            self.refused.set(true);
            if self.refuse_progress.get() {
                self.rm_progress.set(true);
            }
        }
    }
    fn ov_take_blocked(&self) -> bool {
        self.refused.replace(false)
    }
    fn ov_read_session(&self, session: Option<(u64, u64)>, keep: bool) {
        if session.is_none() && !keep && self.credit_session.get() == self.credit_owner.get() {
            self.credit_owner.set(None);
        }
        self.credit_session.set(session);
    }
    fn ov_take_local_wait(&self) -> bool {
        self.local_wait.replace(false)
    }
    fn ov_loads_pending(&self) -> bool {
        self.pending.get()
    }
    fn ov_cause_begin(&self) {
        self.local_wait.set(false);
        self.clog.borrow_mut().clear();
        self.refusal.set(opexec::view::gate_why::STORE);
    }
    fn ov_refusal(&self) -> u8 {
        self.refusal.get()
    }
    fn ov_cause_take(&self) -> peering::wake::Cause {
        let l = self.clog.borrow();
        peering::wake::Cause::from_tokens(&l, false)
    }
    fn ov_take_progress(&self) -> bool {
        self.rm_progress.replace(false)
    }
    fn ov_omap_list_reply(
        &self,
        spg: SpgT,
        soid: &Hobject,
        after: Option<&[u8]>,
        prefix: &[u8],
        max: usize,
        max_bytes: usize,
        values: bool,
    ) -> Result<bytes::Bytes, i32> {
        if let Some(reply) = &self.immutable_listing {
            return Ok(reply.clone());
        }
        self.ov_omap_list(spg, soid, after, prefix, max, max_bytes, values)
            .map(|(enc, n, more)| opwire::omap_list_out(enc, n, more).into())
    }

    fn ov_omap_range(
        &self,
        spg: SpgT,
        soid: &Hobject,
        after: Option<&[u8]>,
        prefix: &[u8],
        max: usize,
        max_bytes: usize,
    ) -> Result<(Vec<opexec::view::Kv>, bool), i32> {
        self.scan_runs.set(self.scan_runs.get() + 1);
        if let Some(owner) = self.credit_owner.get() {
            if self.credit_session.get() != Some(owner) {
                self.credit_blocking
                    .set(self.credit_blocking.get() + u32::from(!self.nb.get()));
                self.refused.set(true);
                self.local_wait.set(true);
                return Err(5);
            }
            if self.credit_slices.get() != 0 {
                self.credit_slices.set(self.credit_slices.get() - 1);
                self.refused.set(true);
                self.rm_progress.set(true);
                return Err(5);
            }
        }
        if self.nb.get() && self.cold_scan.get() > 0 {
            self.cold_scan.set(self.cold_scan.get() - 1);
            self.refused.set(true);
            if self.scan_progress.get() {
                self.rm_progress.set(true);
            }
            return Err(5);
        }
        self.store
            .ov_omap_range(spg, soid, after, prefix, max, max_bytes)
    }
    delegate_view! {
        ov_stat(soid: &Hobject) -> Result<Option<u64>, i32>;
        ov_read(soid: &Hobject, off: u64, len: u64) -> Result<Vec<u8>, i32>;
        ov_getattrs(soid: &Hobject) -> Result<std::collections::BTreeMap<Vec<u8>, Vec<u8>>, i32>;
        ov_omap_header(soid: &Hobject) -> Result<Vec<u8>, i32>;
        ov_omap_get(soid: &Hobject, keys: &[&[u8]]) -> Result<std::collections::BTreeMap<Vec<u8>, Vec<u8>>, i32>;
    }
    fn ov_getattr(&self, spg: SpgT, soid: &Hobject, name: &[u8]) -> Result<Option<Vec<u8>>, i32> {
        if self.nb.get() && self.cold_attr.get() > 0 {
            self.cold_attr.set(self.cold_attr.get() - 1);
            self.refused.set(true);
            return Err(5);
        }
        self.store.ov_getattr(spg, soid, name)
    }
    fn ov_list(
        &self,
        spg: SpgT,
        begin: &Hobject,
        max: usize,
    ) -> Result<(Vec<Hobject>, Hobject), i32> {
        self.list_calls.set(self.list_calls.get() + 1);
        self.run_lists.set(self.run_lists.get() + 1);
        if self.nb.get() && self.cold_list.get() > 0 && self.run_lists.get() > 1 {
            self.cold_list.set(self.cold_list.get() - 1);
            self.refused.set(true);
            return Err(5);
        }
        self.store.ov_list(spg, begin, max)
    }
}

impl Env for TPg {
    env_noop!(
        eio_clear,
        list_ran,
        list_turn,
        run_start,
        scrub_ls,
        send_first,
        settle,
        trim_cfg,
        trim_counted,
        trim_stop,
        warm_rm,
        whoami,
    );
    fn gate_in(&mut self, _r: &OsdReqId, why: u8) {
        self.gated.push(why);
    }
    fn note_io(&mut self, io: &pgwire::IoCount) {
        self.io.rd += io.rd;
        self.io.rd_kb += io.rd_kb;
        self.io.wr += io.wr;
        self.io.wr_kb += io.wr_kb;
    }
    fn admission_ready(&self) -> bool {
        !self.admission_paused
    }
    fn spg(&self) -> SpgT {
        self.spg
    }
    fn epoch(&self) -> u32 {
        self.epoch
    }
    fn require_osd_release(&self) -> u8 {
        self.release
    }
    fn wall(&self) -> UTime {
        UTime::new(1_700_000_000, 0)
    }
    fn mono(&self) -> u64 {
        self.now
    }
    fn is_active(&self) -> bool {
        self.active
    }
    fn is_readable(&self) -> bool {
        self.readable
    }
    fn next_version(&self) -> Eversion {
        Eversion::new(self.epoch, self.head.version + 1)
    }
    fn last_update(&self) -> Eversion {
        self.head
    }
    fn last_user_version(&self) -> u64 {
        self.luv
    }
    fn find_reqid(&self, r: &OsdReqId) -> Option<(Eversion, u64, i32)> {
        self.entries
            .iter()
            .rev()
            .find(|e| e.reqid == *r)
            .map(|e| (e.version, e.user_version, e.return_code))
    }
    fn dup_op_returns(&self, r: &OsdReqId) -> Vec<pgwire::LogOpReturnItem> {
        self.entries
            .iter()
            .rev()
            .find(|e| e.reqid == *r)
            .map(|e| e.op_returns.clone())
            .unwrap_or_default()
    }
    fn is_missing(&self, soid: &Hobject) -> bool {
        // like the PG (`Pg::read_blocked`): the head or one of its clones
        self.missing.iter().any(|o| {
            let mut h = o.clone();
            h.snap = SnapId::NOSNAP;
            h == *soid
        })
    }
    fn missing_range(&self, from: &Hobject, to: &Hobject, max: usize) -> Vec<(Hobject, bool)> {
        let mut v: Vec<(Hobject, bool)> = self
            .missing
            .range(from.clone()..to.clone())
            .take(max)
            .map(|o| (o.clone(), false))
            .chain(
                self.missing_del
                    .range(from.clone()..to.clone())
                    .take(max)
                    .map(|o| (o.clone(), true)),
            )
            .collect();
        v.sort();
        v.truncate(max);
        self.missing_listed.set(self.missing_listed.get() + v.len());
        v
    }
    fn write_degraded(&self, head: &Hobject) -> bool {
        self.missing.contains(head) || self.degraded.contains(head)
    }
    fn is_unfound(&self, head: &Hobject) -> bool {
        self.unfound.contains(head)
    }
    fn kick_recovery(&mut self, head: &Hobject) {
        self.kicked.push(head.clone());
    }
    fn local_damage(&mut self, soid: &Hobject, _known: Option<Eversion>) -> bool {
        if !self.repair {
            return false;
        }
        self.missing.insert(soid.clone());
        self.damaged.push(soid.clone());
        true
    }
    fn probe_meta(&self) -> bool {
        !self.quiet_cache
    }
    fn warm_log(&self) -> bool {
        let n = self.cold_log.get();
        self.cold_log.set(n.saturating_sub(1));
        n == 0
    }
    fn warm(&self, head: &Hobject, off: u64, _len: u64) -> bool {
        self.warm_calls.borrow_mut().push(head.oid.to_vec());
        if let Some(p) = self
            .slot_pages
            .borrow()
            .get(&(head.oid[..].to_vec(), off / 4096))
            .filter(|p| !p.is_empty())
        {
            self.clog.borrow_mut().extend(p.iter().copied());
            return false;
        }
        if let Some(p) = self
            .obj_pages
            .borrow()
            .get(&head.oid[..].to_vec())
            .filter(|p| !p.is_empty())
        {
            if !self
                .untracked_objs
                .borrow()
                .contains(&head.oid[..].to_vec())
            {
                self.clog.borrow_mut().extend(p.iter().copied());
            }
            return false;
        }
        if self
            .cold_objs
            .borrow()
            .iter()
            .any(|n| n[..] == head.oid[..])
        {
            self.refusal.set(opexec::view::gate_why::OBJ);
            return false;
        }
        let n = self.cold.get();
        self.cold.set(n.saturating_sub(1));
        n == 0
    }
    fn warm_data(&self, _head: &Hobject, off: u64, len: u64) -> bool {
        self.probes.borrow_mut().push((off, len));
        let n = self.cold_data.get();
        self.cold_data.set(n.saturating_sub(1));
        n == 0
    }
    fn write_room(&self, bytes: usize, entries: usize) -> bool {
        self.room
            && self.room_bytes.is_none_or(|limit| bytes <= limit)
            && self.room_entries.is_none_or(|limit| entries <= limit)
    }
    fn obj_cache(&self) -> Option<(u64, usize)> {
        (!self.ec && !self.deferred).then_some((self.obj_gen, self.obj_cap))
    }
    fn ec_pool(&self) -> bool {
        self.ec
    }
    fn ec_caps(&self) -> opexec::EcCaps {
        self.ec_caps
    }
    fn copy_stripe_width(&self) -> u64 {
        if self.ec { 3 * 8192 } else { 1 }
    }
    fn ec_wait(&mut self, head: &Hobject, _snapid: u64, off: u64, _len: u64) -> Option<u64> {
        self.ec_waits.set(self.ec_waits.get() + 1);
        self.ec_wait_calls.borrow_mut().push(head.oid.to_vec());
        let n = self.ec_cold.get();
        self.ec_cold.set(n.saturating_sub(1));
        if n > 0 || self.ec_busy_objs.borrow().contains(&head.oid) {
            return Some(peering::wake::ec_tok(head));
        }
        self.ec_rd_busy
            .borrow()
            .get(&(head.oid.to_vec(), off))
            .copied()
    }
    fn pool_full(&self) -> (bool, bool) {
        self.full
    }
    fn pool_eio(&self) -> bool {
        self.pool_eio
    }
    fn failsafe_full(&self) -> bool {
        self.failsafe
    }
    fn cls_map(&self) -> opexec::ClsMap {
        self.cls_map
    }
    fn locate(&self, _name: &[u8], oloc: &denc::types::ObjectLocator) -> Option<(SpgT, u32)> {
        // Honor explicit locator hashes; otherwise use the placement hash `mkop` assigns.
        let h = if oloc.hash >= 0 {
            oloc.hash as u32
        } else {
            0x1234_5678
        };
        if oloc.pool == self.spg.pgid.pool as i64 {
            return Some((self.spg, h));
        }
        self.remote
            .filter(|r| oloc.pool == r.pgid.pool as i64)
            .map(|r| (r, h))
    }
    fn marked_full_epoch(&self) -> u32 {
        self.marked_full
    }
    fn pool_snapc(&self) -> Option<replwire::SnapContext> {
        self.pool_snaps.clone()
    }
    fn submit_write(&mut self, w: WriteReq) -> Result<u64, WriteErr> {
        if !self.active {
            return Err(WriteErr::NotActive);
        }
        for we in &w.entries {
            if self.missing.contains(&we.soid)
                || self.degraded.contains(&we.soid)
                || self.scrub.contains(&we.soid)
            {
                return Err(WriteErr::Degraded(we.soid.clone()));
            }
        }
        if let Some(m) = self.max_txn
            && w.txn_data.len()
                + w.txn_middle.len()
                + w.txn_refs.iter().map(|r| r.len()).sum::<usize>()
                > m
        {
            return Err(WriteErr::TooBig(opwire::errno::EMSGSIZE));
        }
        if w.discard_temp.is_some() && self.discard_blocks > 0 {
            self.discard_blocks -= 1;
            return Err(WriteErr::Blocked);
        }
        if self.check_blocks > 0 {
            self.check_blocks -= 1;
            return Err(WriteErr::Blocked);
        }
        if self.deferred && self.deferred_log {
            let mut last = self.head;
            for we in &w.entries {
                last = Eversion::new(self.epoch, last.version + 1);
                let mut e = LogEntry::new(we.op, we.soid.clone(), last, Eversion::default());
                e.reqid = w.reqid;
                e.user_version = we.user_version;
                e.return_code = we.return_code;
                self.luv = self.luv.max(e.user_version);
                self.entries.push(e);
            }
            self.head = last;
            self.tid += 1;
            self.done.push((self.tid, last));
            return Ok(self.tid);
        }
        if self.deferred {
            self.tid += 1;
            self.done
                .push((self.tid, Eversion::new(self.epoch, self.head.version + 1)));
            return Ok(self.tid);
        }
        if w.txn_refs.is_empty() {
            self.txns.push(w.txn_data.clone());
        }
        let mut last = self.head;
        for we in &w.entries {
            last = Eversion::new(self.epoch, last.version + 1);
            let mut e = LogEntry::new(we.op, we.soid.clone(), last, Eversion::default());
            e.reqid = w.reqid;
            e.user_version = we.user_version;
            e.mtime = we.mtime;
            e.snaps = we.snaps.clone();
            e.return_code = we.return_code;
            e.op_returns = we.op_returns.clone();
            self.luv = self.luv.max(e.user_version);
            self.entries.push(e);
        }
        self.head = last;
        let txn = StoreTxn {
            ops: vec![if w.txn_refs.is_empty() {
                StoreOp::ApplyTxn {
                    middle: w.txn_middle,
                    data: w.txn_data,
                }
            } else {
                StoreOp::ApplyTxnSplit {
                    skel: w.txn_data,
                    refs: w.txn_refs,
                    hints: w.txn_ref_crcs,
                }
            }],
        };
        self.tid += 1;
        if self.hold {
            self.held.push((self.tid, last, txn));
            return Ok(self.tid);
        }
        self.store.submit(self.spg, &txn);
        self.done.push((self.tid, last));
        Ok(self.tid)
    }
    fn pg_blocked(&self) -> bool {
        self.blocked
    }
    fn op_stale(&self, op_epoch: u32) -> bool {
        op_epoch < self.split_epoch
    }
    fn pool_caps_info(&self) -> (&[u8], Option<&opexec::caps::AppMeta>) {
        (b"testpool", Some(&self.apps))
    }
    fn pg_num(&self) -> u32 {
        1
    }
    fn blocklisted(&self, a: &denc::types::EntityAddr) -> bool {
        a.ipv4()
            .is_some_and(|i| self.blocklist.borrow().contains(&i))
    }
    fn removed_snaps(&self) -> Vec<(u64, u64)> {
        self.removed.clone()
    }
    fn trim_poll(&mut self) -> peering::TrimPoll {
        match &self.trim {
            Some((snap, _)) => peering::TrimPoll::Go(*snap),
            None => peering::TrimPoll::No,
        }
    }
    fn snap_mapper_next(
        &self,
        snap: u64,
        max: usize,
    ) -> Result<Vec<Hobject>, peering::StoreReadError> {
        Ok(match &self.trim {
            Some((s, clones)) if *s == snap => clones.iter().take(max).cloned().collect(),
            _ => Vec::new(),
        })
    }
    fn trim_snap_done(&mut self, _snap: u64) {
        self.trim = None;
    }
    fn trim_unmap(&mut self, clone: &Hobject) {
        if let Some((_, clones)) = &mut self.trim {
            clones.retain(|c| c != clone);
        }
    }
    fn trim_note(&mut self, msg: String) {
        self.trim_notes.push(msg);
    }
}

pub fn client(n: i64) -> EntityName {
    EntityName::client(n)
}

pub fn mkop(oid: &[u8], ops: Vec<OsdOp>) -> MOSDOp {
    mkop_in(POOL, oid, ops)
}

/// [`mkop`] in pool `pool`.
pub fn mkop_in(pool: u64, oid: &[u8], ops: Vec<OsdOp>) -> MOSDOp {
    let has_wr = ops.iter().any(|o| o.op & 0x2000 != 0);
    let mut flags = opwire::flag::ONDISK | opwire::flag::KNOWN_REDIR;
    flags |= if has_wr {
        opwire::flag::WRITE
    } else {
        opwire::flag::READ
    };
    MOSDOp {
        pgid: SpgT {
            pgid: PgT::new(pool, 0),
            shard: ShardId::NO_SHARD,
        },
        hash: 0x1234_5678,
        osdmap_epoch: 10,
        flags,
        oloc: ObjectLocator {
            pool: pool as i64,
            key: vec![],
            nspace: vec![],
            hash: -1,
        },
        oid: oid.to_vec(),
        ops,
        mtime: UTime::new(1_700_000_001, 5),
        ..Default::default()
    }
}

/// Feed the engine and complete writes; returns the reply to (conn, tid) if produced.
pub fn run(
    pg: &mut TPg,
    eng: &mut Engine,
    conn: u64,
    tid: u64,
    who: EntityName,
    op: MOSDOp,
) -> Vec<Out> {
    let req = ClientReq {
        placement_read: None,
        conn,
        caps: None,
        tid,
        op: Box::new(op),
        who,
        addr: EntityAddr::default(),
        peer_addr: EntityAddr::default(),
        features: 0x3f17_ffff_fffd_ffff,
    };
    eng.on_op(pg, req);
    settle(pg, eng)
}

/// Complete every submitted write, return all outputs.
pub fn settle(pg: &mut TPg, eng: &mut Engine) -> Vec<Out> {
    let mut outs = eng.take_out();
    loop {
        let done = std::mem::take(&mut pg.done);
        if done.is_empty() {
            break;
        }
        for (tid, v) in done {
            eng.on_write_done(pg, tid, v, 0);
        }
        outs.extend(eng.take_out());
    }
    outs
}

pub fn reply_of(outs: &mut Vec<Out>, conn: u64, tid: u64) -> Option<MOSDOpReply> {
    let i = outs
        .iter()
        .position(|o| matches!(o, Out::Reply { conn: c, tid: t, .. } if *c == conn && *t == tid))?;
    match outs.remove(i) {
        Out::Reply { reply, .. } => {
            // through the wire like a client would see it
            let (ty, v, _c, segs) = ClientMsg::OpReply(*reply).encode(u64::MAX).ok()?;
            match opwire::decode_client(ty, v, &segs).ok()? {
                ClientMsg::OpReply(r) => Some(r),
                _ => None,
            }
        }
        _ => None,
    }
}

pub fn engine(pg: &TPg) -> Engine {
    Engine::new(
        pg.spg,
        Limits::default(),
        opexec::clsx::ClassPolicy::default(),
    )
}
