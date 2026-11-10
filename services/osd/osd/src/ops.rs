// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Primary role glue (M3): drives the sans-IO `opexec::Engine` of every primary PG. The engine reaches the PG through
//! [`PgEnv`] (log versions, dup lookup, `PgSet::submit_write` with the local `Persist` applied immediately so
//! pipelined writes see each other), its outputs (op replies, MWatchNotify) go out over the client links, and
//! `Action::WriteDone` / state changes are fed back after every PG event (`pg_post`).
use crate::backend::Backend;
use crate::osd::{IoCmd, Osd};
use crate::xcore::link_core;
use denc::types::{EntityAddr, Eversion, Hobject, OsdReqId, SpgT, UTime};

use messages::Message;
use opexec::{ClientReq, Engine, Env, ObjView, Out};
use opwire::{ClientMsg, MOSDOp, MOSDOpReply, errno};
use osdmap::OsdMap;
use peering::wake::WakeSet;
use peering::{Action, PgSet, PgStoreOps, WriteErr, WriteReq};
use std::collections::VecDeque;
use std::time::Duration;

#[cfg(test)]
#[path = "ec_overlay_keys_tests.rs"]
pub(crate) mod ec_overlay_keys_tests;
#[cfg(test)]
#[path = "ops_full_tests.rs"]
mod ops_full_tests;
#[cfg(test)]
#[path = "shared_read_forwarding_tests.rs"]
mod shared_read_forwarding_tests;

/// The PG as the engine sees it. Borrows the PG set and store of the OSD for the duration of one engine call.
pub(crate) struct PgEnv<'a, P: PgStoreOps + ObjView> {
    pub set: &'a mut PgSet,
    pub store: &'a mut P,
    pub spg: SpgT,
    /// Monotonic ns (PG clock).
    pub now: u64,
    pub wall: UTime,
    pub map: Option<&'a OsdMap>,
    /// This OSD's id (identity of engine-internal source reads).
    pub whoami: i32,
    /// Is a client connection still open (local link, or a remote one that sent us ops)?
    pub conn_open: &'a dyn Fn(u64) -> bool,
    /// Actions of `submit_write` that are not local persistence (sends, WriteDone, ...): run by the caller.
    pub rest: Vec<Action>,
    pub failed: Option<String>,
    /// Operator-visible error lines raised by the engine (cluster log).
    pub notes: Vec<String>,
    /// Submit times of pending store txns (token -> ns), see `Perf::persist_t`.
    pub persist_t: &'a mut crate::perf::PersistTimes,
    /// Sampled-op tracing of this core.
    pub tr: &'a mut crate::trace::Tracer,
    /// First object whose local store read answered EIO since `Env::eio_clear` (a damaged object, not a client or
    /// cls error).
    pub eio: std::cell::RefCell<Option<Hobject>>,
    /// The local store is above its failsafe fill (`Osd::pg.failsafe`).
    pub failsafe: bool,
    /// Damaged local objects handed to the PG for repair (perf counter `read_repair`).
    pub repairs: u64,
    /// The driver sends before it applies (adr 0008 am. 2): `pg_run` inside a send-first window of the driver.
    pub late_ok: bool,
    /// The engine's send-first window ([`Env::send_first`]).
    pub send_first: bool,
    /// A client write's local txn held back until its repops left: `(spg, token, txn, its sends = the last n of
    /// rest)`.
    pub late: Option<(SpgT, u64, peering::StoreTxn, usize)>,
    /// Object-state cache capacity per PG in heads (`flashstore_obj_cache`, 0 = off; adr 0160 D5).
    pub obj_cache: usize,
    /// Core share of listing continuations (adr 0522); `None` = no share (tests).
    pub share: Option<&'a mut crate::pgs::ListShare>,
    /// Facts of the PG `spg` for this run ([`PgFacts`]); `None` = not read since the last change (fill with `Default`).
    pub facts: std::cell::Cell<Option<Option<PgFacts>>>,
    /// Test knob: the next own PG txn is answered `Rejected` with this reason (`PgHost::refuse_next`); tests set it, production leaves it `None`.
    pub refuse_own: &'a mut Option<&'static str>,
    /// Store-refused PG txns (`PgCounters::bad_txns`).
    pub bad_txns: &'a mut u64,
}

/// The scalar facts of the engine's PG that the Env / ObjView queries of one engine run ask again and again (a fast
/// write asks ~20 times): read in one `PgSet` lookup, kept until the PG may change. Every mutable access of the set
/// through [`PgEnv`] drops them ([`PgEnv::changed`]); the PG changes only through the env during a run.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PgFacts {
    /// Erasure-coded PG this OSD leads (`Pg::is_ec_pool`).
    ec: bool,
    primary_active: bool,
    /// `Pg::is_readable` at the env's clock.
    readable: bool,
    next_version: Eversion,
    last_update: Eversion,
    last_uv: u64,
    marked_full: u32,
    pool_eio: bool,
    /// `Pg::client_op_floor`.
    op_floor: u32,
    obj_gen: u64,
    stripe_width: Option<u64>,
    /// Primary of a down / incomplete / peered-not-active PG ([`Env::pg_blocked`]).
    blocked: bool,
}

impl<P: PgStoreOps + ObjView> PgEnv<'_, P> {
    /// The facts of PG `spg` (`None` = no such PG here), from the cache while the PG did not change.
    fn facts(&self) -> Option<PgFacts> {
        if let Some(f) = self.facts.get() {
            return f;
        }
        let f = self.set.pg(self.spg).map(|p| {
            use pgwire::state as s;
            let b = p.state_bits();
            let primary = p.is_primary();
            PgFacts {
                ec: p.is_ec_pool(),
                primary_active: primary && p.is_active(),
                readable: p.is_readable(self.now),
                next_version: p.next_version(),
                last_update: p.info().last_update,
                last_uv: p.info().last_user_version,
                marked_full: p.info().history.last_epoch_marked_full,
                pool_eio: self
                    .map
                    .and_then(|m| m.pool(self.spg.pgid.pool as i64))
                    .is_some_and(|p| p.has_flag(osdmap::pool::flags::EIO)),
                op_floor: p.client_op_floor(),
                obj_gen: p.obj_gen(),
                stripe_width: p.ec_stripe_width(),
                blocked: primary
                    && (b & (s::DOWN | s::INCOMPLETE) != 0
                        || (b & s::PEERED != 0 && b & s::ACTIVE == 0)),
            }
        });
        self.facts.set(Some(f));
        f
    }

    /// The PG set is about to change (a PG call, a write, a commit): the cached facts are stale.
    fn changed(&self) {
        self.facts.set(None);
    }

    /// Pass a store read result of `soid` through, remembering the first object that answered EIO (see
    /// `Env::local_damage`).
    fn seen<T>(&self, soid: &Hobject, r: Result<T, i32>) -> Result<T, i32> {
        if r.as_ref().is_err_and(|e| *e == errno::EIO) {
            self.eio.borrow_mut().get_or_insert_with(|| soid.clone());
        }
        r
    }

    /// Is `spg` an erasure-coded PG this OSD leads (logical view != shard file)? The engine's PG from its facts.
    fn is_ec(&self, spg: SpgT) -> bool {
        if spg == self.spg {
            return self.facts().is_some_and(|f| f.ec);
        }
        self.set.pg(spg).is_some_and(|p| p.is_ec_pool())
    }

    /// The PG `spg` when it is an erasure-coded PG this OSD leads (a replicated PG: no `PgSet` lookup).
    fn ec_pg(&self, spg: SpgT) -> Option<&peering::Pg> {
        if !self.is_ec(spg) {
            return None;
        }
        self.set.pg(spg)
    }

    /// EC: the in-flight EC_OMAP records laid over the local shard's stored omap (`Pg::ec_omap_overlay`).
    fn ec_overlay(&self, spg: SpgT, soid: &Hobject) -> Result<peering::ecomap::Overlay, i32> {
        self.set
            .pg(spg)
            .map_or(Err(opwire::errno::EIO), |p| p.ec_omap_overlay(soid))
    }

    /// EC: the state of `soid` after its queued / uncommitted writes (`Pg::ec_projected`); `None` = the local shard is
    /// current (or not an EC PG).
    fn ec_proj(&self, spg: SpgT, soid: &Hobject) -> Option<Option<(u64, &peering::Attrs)>> {
        self.ec_pg(spg).and_then(|p| p.ec_projected(soid))
    }

    /// Sampled write: remember its repop tid and local store token (trace.rs).
    #[cold]
    #[inline(never)]
    fn trace_bind(&mut self, reqid: &OsdReqId, wtid: u64, acts: &[Action]) {
        let token = acts.iter().find_map(|a| match a {
            Action::Persist { token, .. } => Some(*token),
            _ => None,
        });
        self.tr
            .bind_write(crate::trace::key_of(reqid), wtid, token.unwrap_or(0));
    }

    /// Sampled op: the engine starts a run of it (trace stage `pg_run`).
    #[cold]
    #[inline(never)]
    fn trace_run(&mut self, reqid: &OsdReqId) {
        self.tr.run_start(crate::trace::key_of(reqid));
    }

    /// Run `f` on the PG and serve what it emitted (reservations, persists, sends).
    fn pg_call<R>(&mut self, f: impl FnOnce(&mut peering::Pg) -> R) -> Option<R> {
        self.changed();
        let (r, acts) = self.set.with_pg(self.now, self.spg, &*self.store, f)?;
        self.run_actions(acts);
        Some(r)
    }

    /// `submit_write`'s actions. Inside the send-first window the batch of a replicated write (its repop sends + its
    /// one local `Persist`) holds the `Persist` back in `late`: `pg_run` sends first and leaves the apply to the
    /// driver (`Osd::settle_late`), or applies it before anything else runs (`settle_late`, [`Env::settle`]).
    fn run_submit(&mut self, mut acts: Vec<Action>) {
        let n = acts.len();
        let held = self.send_first
            && self.late_ok
            && self.late.is_none()
            && n >= 2
            && matches!(acts[n - 1], Action::Persist { .. })
            && acts[..n - 1].iter().all(|a| matches!(a, Action::Send(_)));
        if !held {
            return self.run_actions(acts);
        }
        let Some(Action::Persist { spg, token, txn }) = acts.pop() else {
            unreachable!()
        };
        self.late = Some((spg, token, txn, n - 1));
        self.rest.append(&mut acts);
    }

    /// Apply the held-back local txn now, exactly like an inline one: its sends (still the tail of `rest`, nothing
    /// was run after them) are staged again, so a Rejected txn withdraws them.
    fn settle_late(&mut self) {
        let Some((spg, token, txn, n)) = self.late.take() else {
            return;
        };
        let mut acts = self.rest.split_off(self.rest.len() - n);
        acts.push(Action::Persist { spg, token, txn });
        self.run_actions(acts);
    }

    fn run_actions(&mut self, acts: Vec<Action>) {
        if self.failed.is_some() {
            // the OSD stops after this call: nothing later may reach the store (a later entry durable over a refused
            // one would leave a hole under the persisted head)
            return;
        }
        self.settle_late(); // never overtaken by a later txn of the same call
        self.changed(); // commits change PGs
        // The batch runs in place; actions a commit adds go behind it (FIFO), as in one queue.
        let mut it = acts.into_iter();
        let mut more_q: VecDeque<Action> = VecDeque::new();
        // Sends are staged: the PG logs a write and queues its repops before the local txn is applied (the Persist
        // comes last), so a Rejected local txn must be able to withdraw them.
        let mut staged: Vec<Action> = Vec::new();
        while let Some(a) = it.next().or_else(|| more_q.pop_front()) {
            match a {
                Action::Persist { spg, token, txn } => {
                    if let Err(why) = crate::pgs::queue_persist(
                        self.store,
                        self.set,
                        self.tr,
                        self.persist_t,
                        self.refuse_own,
                        self.bad_txns,
                        self.now,
                        (spg, token, txn),
                        &mut more_q,
                    ) {
                        self.failed = Some(why);
                        // the entry is in no store and no replica saw it: its repops are withdrawn, never sent
                        return;
                    }
                }
                other => staged.push(other),
            }
        }
        self.rest.append(&mut staged);
    }
}

impl<P: PgStoreOps + ObjView> ObjView for PgEnv<'_, P> {
    fn ov_name_fits(&self, spg: SpgT, soid: &Hobject) -> bool {
        self.store.ov_name_fits(spg, soid)
    }
    fn ov_name_repl_ok(&self, spg: SpgT, soid: &Hobject) -> bool {
        !self.store.ov_name_long(spg, soid) || self.set.long_names_ok(spg)
    }
    fn ov_getattr(&self, spg: SpgT, soid: &Hobject, name: &[u8]) -> Result<Option<Vec<u8>>, i32> {
        if let Some(p) = self.ec_proj(spg, soid) {
            let (_, attrs) = p.ok_or(opwire::errno::ENOENT)?;
            return Ok(attrs.get(name).cloned());
        }
        self.seen(soid, self.store.ov_getattr(spg, soid, name))
    }
    fn ov_getattr_pair(
        &self,
        spg: SpgT,
        soid: &Hobject,
        a: &[u8],
        b: &[u8],
    ) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>), i32> {
        self.seen(soid, self.store.ov_getattr_pair(spg, soid, a, b))
    }
    fn ov_list(
        &self,
        spg: SpgT,
        begin: &Hobject,
        max: usize,
    ) -> Result<(Vec<Hobject>, Hobject), i32> {
        self.store.ov_list(spg, begin, max)
    }
    // Erasure-coded pools (primary role): the logical object is not the shard file: size from object_info, data from
    // the decoded read cache (`Env::ec_wait` filled it), omap = local shard + in-flight records, the backend-private hinfo is invisible.
    fn ov_stat(&self, spg: SpgT, soid: &Hobject) -> Result<Option<u64>, i32> {
        if let Some(pg) = self.ec_pg(spg) {
            if let Some(p) = pg.ec_projected(soid) {
                return Ok(p.map(|(size, _)| size));
            }
            return pg.ec_obj_size(soid, &*self.store);
        }
        self.seen(soid, self.store.ov_stat(spg, soid))
    }
    fn ov_read(&self, spg: SpgT, soid: &Hobject, off: u64, len: u64) -> Result<Vec<u8>, i32> {
        if let Some(pg) = self.ec_pg(spg) {
            let size = pg
                .ec_obj_size(soid, &*self.store)?
                .ok_or(opwire::errno::ENOENT)?;
            return pg.ec_cache_read(soid, off, len, size);
        }
        self.seen(soid, self.store.ov_read(spg, soid, off, len))
    }
    fn ov_read_bytes(
        &self,
        spg: SpgT,
        soid: &Hobject,
        off: u64,
        len: u64,
    ) -> Result<(bytes::Bytes, Option<u32>), i32> {
        if let Some(pg) = self.ec_pg(spg) {
            // a slice of the decoded cache entry (no copy), with its fused crc when the read is the whole entry
            let size = pg
                .ec_obj_size(soid, &*self.store)?
                .ok_or(opwire::errno::ENOENT)?;
            return pg.ec_cache_read_bytes(soid, off, len, size);
        }
        self.ov_read_crc(spg, soid, off, len)
            .map(|(d, c)| (bytes::Bytes::from(d), c))
    }
    fn ov_read_crc(
        &self,
        spg: SpgT,
        soid: &Hobject,
        off: u64,
        len: u64,
    ) -> Result<(Vec<u8>, Option<u32>), i32> {
        if self.is_ec(spg) {
            return self.ov_read(spg, soid, off, len).map(|d| (d, None));
        }
        self.seen(soid, self.store.ov_read_crc(spg, soid, off, len))
    }
    fn ov_read_shared(
        &self,
        spg: SpgT,
        soid: &Hobject,
        off: u64,
        len: u64,
    ) -> Result<Vec<(bytes::Bytes, Option<u32>)>, i32> {
        if self.is_ec(spg) {
            // the decoded EC cache: one piece (a slice of the cache entry)
            return self
                .ov_read_bytes(spg, soid, off, len)
                .map(|(d, c)| vec![(d, c)]);
        }
        self.seen(soid, self.store.ov_read_shared(spg, soid, off, len))
    }
    fn ov_read_shared_verified(
        &self,
        spg: SpgT,
        soid: &Hobject,
        off: u64,
        len: u64,
    ) -> Result<opexec::view::VerifiedRead, i32> {
        if self.is_ec(spg) {
            return self.ov_read_shared(spg, soid, off, len).map(|parts| {
                opexec::view::VerifiedRead {
                    parts,
                    block_crcs: None,
                }
            });
        }
        self.seen(
            soid,
            self.store.ov_read_shared_verified(spg, soid, off, len),
        )
    }
    fn ov_getattrs(
        &self,
        spg: SpgT,
        soid: &Hobject,
    ) -> Result<std::collections::BTreeMap<Vec<u8>, Vec<u8>>, i32> {
        let ec = self.ec_pg(spg);
        let mut a = match ec.and_then(|p| p.ec_projected(soid)) {
            Some(p) => p.ok_or(opwire::errno::ENOENT)?.1.clone(),
            None => self.seen(soid, self.store.ov_getattrs(spg, soid))?,
        };
        if ec.is_some() {
            a.remove(ec::HINFO_KEY.as_bytes());
        }
        Ok(a)
    }
    fn ov_omap_header(&self, spg: SpgT, soid: &Hobject) -> Result<Vec<u8>, i32> {
        if self.is_ec(spg) {
            let ov = self.ec_overlay(spg, soid)?;
            let base = if ov.cleared() {
                Vec::new()
            } else {
                self.seen(soid, self.store.ov_omap_header(spg, soid))?
            };
            return Ok(ov.header(base));
        }
        self.seen(soid, self.store.ov_omap_header(spg, soid))
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
        if self.is_ec(spg) {
            let ov = self.ec_overlay(spg, soid)?;
            if ov.is_empty() {
                return self.seen(
                    soid,
                    self.store
                        .ov_omap_range(spg, soid, after, prefix, max, max_bytes),
                );
            }
            return ov.range(
                |a, n| {
                    self.seen(
                        soid,
                        self.store.ov_omap_range(spg, soid, a, prefix, n, max_bytes),
                    )
                },
                after,
                prefix,
                max,
                max_bytes,
            );
        }
        self.seen(
            soid,
            self.store
                .ov_omap_range(spg, soid, after, prefix, max, max_bytes),
        )
    }
    fn ov_omap_keys_range(
        &self,
        spg: SpgT,
        soid: &Hobject,
        after: Option<&[u8]>,
        prefix: &[u8],
        max: usize,
        max_bytes: usize,
    ) -> Result<(Vec<Vec<u8>>, bool), i32> {
        if self.is_ec(spg) {
            let ov = self
                .set
                .pg(spg)
                .ok_or(opwire::errno::EIO)?
                .ec_omap_keys_overlay(soid)?;
            if !ov.is_empty() {
                return ov.range(
                    |a, n| {
                        self.seen(
                            soid,
                            self.store
                                .ov_omap_keys_range(spg, soid, a, prefix, n, usize::MAX),
                        )
                    },
                    after,
                    prefix,
                    max,
                    max_bytes,
                );
            }
        }
        self.seen(
            soid,
            self.store
                .ov_omap_keys_range(spg, soid, after, prefix, max, max_bytes),
        )
    }
    fn ov_omap_list(
        &self,
        spg: SpgT,
        soid: &Hobject,
        after: Option<&[u8]>,
        prefix: &[u8],
        max: usize,
        max_bytes: usize,
        values: bool,
    ) -> Result<opexec::view::OmapList, i32> {
        // EC with in-flight omap records: the merged pair listing (base + overlay), encoded
        if self.is_ec(spg) {
            let pg = self.set.pg(spg).ok_or(opwire::errno::EIO)?;
            let overlay = if values {
                !self.ec_overlay(spg, soid)?.is_empty()
            } else {
                !pg.ec_omap_keys_overlay(soid)?.is_empty()
            };
            if overlay {
                return opexec::view::omap_list_via(
                    self, spg, soid, after, prefix, max, max_bytes, values,
                );
            }
        }
        self.seen(
            soid,
            self.store
                .ov_omap_list(spg, soid, after, prefix, max, max_bytes, values),
        )
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
        // Preserve EC's overlay-aware route and visibility/error checks. Sharing
        // changes only the replicated fast path, not EC overlay publication.
        if self.is_ec(spg) {
            return self
                .ov_omap_list(spg, soid, after, prefix, max, max_bytes, values)
                .map(|(enc, n, more)| opwire::omap_list_out(enc, n, more).into());
        }
        self.seen(
            soid,
            self.store
                .ov_omap_list_reply(spg, soid, after, prefix, max, max_bytes, values),
        )
    }

    fn ov_omap_get(
        &self,
        spg: SpgT,
        soid: &Hobject,
        keys: &[&[u8]],
    ) -> Result<std::collections::BTreeMap<Vec<u8>, Vec<u8>>, i32> {
        if self.is_ec(spg) {
            let ov = self.ec_overlay(spg, soid)?;
            let base = if ov.cleared() {
                Default::default()
            } else {
                self.seen(soid, self.store.ov_omap_get(spg, soid, keys))?
            };
            return Ok(ov.get(keys, base));
        }
        self.seen(soid, self.store.ov_omap_get(spg, soid, keys))
    }
    fn ov_max_item_key(&self) -> usize {
        self.store.ov_max_item_key()
    }
    fn ov_nonblock(&self, on: bool) {
        self.store.ov_nonblock(on)
    }
    fn ov_read_session(&self, session: Option<(u64, u64)>, keep: bool) {
        self.store.ov_read_session(session, keep)
    }
    fn ov_list_whole(&self) {
        self.store.ov_list_whole()
    }
    fn ov_take_blocked(&self) -> bool {
        self.store.ov_take_blocked()
    }
    fn ov_take_local_wait(&self) -> bool {
        self.store.ov_take_local_wait()
    }
    fn ov_loads_pending(&self) -> bool {
        self.store.ov_loads_pending()
    }
    fn ov_cause_begin(&self) {
        self.store.ov_cause_begin()
    }
    fn ov_cause_take(&self) -> peering::wake::Cause {
        self.store.ov_cause_take()
    }
    fn ov_refusal(&self) -> u8 {
        self.store.ov_refusal()
    }
    fn ov_take_progress(&self) -> bool {
        self.store.ov_take_progress()
    }
}

/// Pool name and application metadata a client cap check of `pool` matches against (`""` / none for an
/// unknown pool or no map): the one source for the op engine, the EC direct read and the dedup list.
pub(crate) fn pool_caps_info(
    m: Option<&OsdMap>,
    pool: i64,
) -> (&[u8], Option<&opexec::caps::AppMeta>) {
    let name = m
        .and_then(|m| m.pool_name.get(&pool))
        .map_or(b"".as_slice(), |s| s.as_bytes());
    (
        name,
        m.and_then(|m| m.pool(pool))
            .map(|p| &p.application_metadata),
    )
}

impl<P: PgStoreOps + ObjView> Env for PgEnv<'_, P> {
    fn spg(&self) -> SpgT {
        self.spg
    }
    fn list_turn(&mut self, held: bool) -> bool {
        let spg = self.spg;
        self.share.as_deref_mut().is_none_or(|s| {
            let t = s.turn(held);
            if t {
                s.last = Some(spg);
            }
            t
        })
    }
    fn list_ran(&mut self) {
        if let Some(s) = self.share.as_deref_mut() {
            s.ran();
        }
    }
    fn epoch(&self) -> u32 {
        self.set.epoch()
    }
    fn require_osd_release(&self) -> u8 {
        self.map.map_or(0, |m| m.require_osd_release)
    }
    fn wall(&self) -> UTime {
        self.wall
    }
    fn mono(&self) -> u64 {
        self.now
    }
    fn is_active(&self) -> bool {
        self.facts().is_some_and(|f| f.primary_active)
    }
    fn is_readable(&self) -> bool {
        self.facts().is_some_and(|f| f.readable)
    }
    fn next_version(&self) -> Eversion {
        self.facts()
            .map_or_else(Eversion::default, |f| f.next_version)
    }
    fn last_update(&self) -> Eversion {
        self.facts()
            .map_or_else(Eversion::default, |f| f.last_update)
    }
    fn last_user_version(&self) -> u64 {
        self.facts().map_or(0, |f| f.last_uv)
    }
    fn find_reqid(&self, r: &OsdReqId) -> Option<(Eversion, u64, i32)> {
        self.set.pg(self.spg).and_then(|p| p.log().find_reqid(r))
    }
    fn marked_full_epoch(&self) -> u32 {
        self.facts().map_or(0, |f| f.marked_full)
    }
    fn dup_op_returns(&self, r: &OsdReqId) -> Vec<pgwire::LogOpReturnItem> {
        self.set
            .pg(self.spg)
            .map(|p| p.log().find_op_returns(r))
            .unwrap_or_default()
    }
    fn is_missing(&self, soid: &Hobject) -> bool {
        self.set.pg(self.spg).is_some_and(|p| p.read_blocked(soid))
    }
    fn is_unfound(&self, head: &Hobject) -> bool {
        self.set
            .pg(self.spg)
            .is_some_and(|p| p.obj_unfound_head(head))
    }
    fn kick_recovery(&mut self, head: &Hobject) {
        self.pg_call(|pg| pg.kick_recovery(head));
    }
    fn missing_range(&self, from: &Hobject, to: &Hobject, max: usize) -> Vec<(Hobject, bool)> {
        let Some(m) = self.set.pg(self.spg).map(|p| &p.missing().wire().missing) else {
            return Vec::new();
        };
        if m.is_empty() {
            return Vec::new();
        }
        m.range::<Hobject, _>(from..to)
            .take(max)
            .map(|(o, i)| (o.clone(), i.is_delete()))
            .collect()
    }
    fn write_degraded(&self, head: &Hobject) -> bool {
        self.set.pg(self.spg).is_some_and(|p| p.obj_degraded(head))
    }
    fn eio_clear(&self) {
        self.eio.take();
    }
    fn local_damage(&mut self, soid: &Hobject, known: Option<Eversion>) -> bool {
        // a store read fault OF THIS OBJECT, or an object_info / snapset that does not decode: never a cls or client
        // error, never a fault of another object read by the same op (that would repair the wrong object forever)
        let store_fault = self.eio.borrow().as_ref() == Some(soid)
            || matches!(
                self.store.recovery_info_checked(self.spg, soid),
                Err(peering::StoreReadError::Corrupt | peering::StoreReadError::Io)
            );
        if !store_fault {
            return false;
        }
        let soid = soid.clone();
        let ok = self
            .pg_call(|pg| pg.local_damage(&soid, known))
            .unwrap_or(false);
        if ok {
            self.repairs += 1;
        }
        ok
    }
    fn submit_write(&mut self, w: WriteReq) -> Result<u64, WriteErr> {
        self.settle_late();
        let reqid = w.reqid;
        self.changed();
        let (tid, acts) = self.set.submit_write(self.now, self.spg, w, &*self.store)?;
        if self.tr.live_n != 0 {
            self.trace_bind(&reqid, tid, &acts);
        }
        self.run_submit(acts);
        Ok(tid)
    }
    fn note_io(&mut self, io: &pgwire::IoCount) {
        self.changed();
        self.set.note_io(self.spg, io);
    }
    fn send_first(&mut self, on: bool) {
        self.send_first = on;
    }
    fn gate_in(&mut self, r: &OsdReqId, why: u8) {
        if self.tr.live_n != 0 {
            self.tr.gate_in(crate::trace::key_of(r), why);
        }
    }
    #[inline]
    fn run_start(&mut self, r: &OsdReqId) {
        if self.tr.live_n != 0 {
            self.trace_run(r);
        }
    }
    fn settle(&mut self) {
        self.settle_late();
    }
    fn warm(&self, head: &Hobject, off: u64, len: u64) -> bool {
        self.store.warm(self.spg, head, off, len)
    }
    fn warm_rm(&self, head: &Hobject) -> bool {
        self.store.warm_rm(self.spg, head)
    }
    fn warm_log(&self) -> bool {
        self.set
            .pg(self.spg)
            .is_none_or(|p| p.warm_log(&*self.store))
    }
    fn probe_meta(&self) -> bool {
        self.store.probe_cold_for(self.spg)
    }
    fn admission_ready(&self) -> bool {
        self.store.admission_ready_for(self.spg)
    }
    fn warm_data(&self, head: &Hobject, off: u64, len: u64) -> bool {
        self.store.warm_data(self.spg, head, off, len)
    }
    fn ec_pool(&self) -> bool {
        self.is_ec(self.spg)
    }
    fn ec_caps(&self) -> opexec::EcCaps {
        let Some(p) = self
            .map
            .and_then(|m| m.pool(self.spg.pgid.pool as i64))
            .filter(|p| p.is_erasure())
        else {
            return opexec::EcCaps::default();
        };
        opexec::EcCaps {
            allows_optimizations: p.has_flag(osdmap::pool::flags::EC_OPTIMIZATIONS),
            requires_aligned_append: !p.has_flag(osdmap::pool::flags::EC_OVERWRITES),
            required_alignment: p.stripe_width as u64,
        }
    }
    fn obj_cache(&self) -> Option<(u64, usize)> {
        // EC: reads see projected (in-flight) state, every EC txn changes the generation anyway: no cache
        self.facts()
            .filter(|f| self.obj_cache > 0 && !f.ec)
            .map(|f| (f.obj_gen, self.obj_cache))
    }
    fn copy_stripe_width(&self) -> u64 {
        self.facts().and_then(|f| f.stripe_width).unwrap_or(1)
    }
    fn ec_wait(&mut self, head: &Hobject, snapid: u64, off: u64, len: u64) -> Option<u64> {
        if !self.is_ec(self.spg) {
            return None;
        }
        self.changed();
        let store = &*self.store;
        let (tok, acts) = self.set.with_pg(self.now, self.spg, store, |pg| {
            pg.ec_wait_snap(head, snapid, off, len, store)
        })?;
        self.run_actions(acts);
        tok
    }
    fn write_room(&self, bytes: usize, entries: usize) -> bool {
        self.store
            .write_room(self.spg, bytes as u64, entries as u64)
    }
    fn pg_num(&self) -> u32 {
        self.map
            .and_then(|m| m.pool(self.spg.pgid.pool as i64))
            .map_or(1, |p| p.pg_num.max(1))
    }
    fn conn_open(&self, conn: u64) -> bool {
        (self.conn_open)(conn)
    }
    fn blocklisted(&self, addr: &EntityAddr) -> bool {
        self.map.is_some_and(|m| m.is_blocklisted(addr))
    }
    fn removed_snaps(&self) -> Vec<(u64, u64)> {
        // pre-octopus pool field + the map's queue of removed snaps not yet pruned (the only source on octopus+)
        let mut s = peering::snaps::Ivs::new();
        if let Some(m) = self.map {
            let pool = self.spg.pgid.pool as i64;
            if let Some(p) = m.pool(pool) {
                for (a, l) in &p.removed_snaps.0 {
                    peering::snaps::iv_insert(&mut s, *a, *l);
                }
            }
            if let Some(q) = m.removed_snaps_queue.get(&pool) {
                for (a, l) in &q.0 {
                    peering::snaps::iv_insert(&mut s, *a, *l);
                }
            }
        }
        s.into_iter().collect()
    }
    fn trim_poll(&mut self) -> peering::TrimPoll {
        self.pg_call(|pg| pg.trim_poll())
            .unwrap_or(peering::TrimPoll::No)
    }
    fn trim_cfg(&self) -> opexec::trim::TrimCfg {
        let c = self.set.cfg_ref();
        opexec::trim::TrimCfg {
            max_concurrent: c.snap_trim_concurrent,
            sleep_ns: c.snap_trim_sleep_ns,
        }
    }
    fn snap_mapper_next(
        &self,
        snap: u64,
        max: usize,
    ) -> Result<Vec<Hobject>, peering::StoreReadError> {
        self.store.snapmap_next(self.spg, snap, max)
    }
    fn trim_snap_done(&mut self, snap: u64) {
        self.pg_call(|pg| pg.trim_snap_done(snap));
    }
    fn trim_stop(&mut self, error: bool) {
        self.pg_call(|pg| pg.trim_stop(error));
    }
    fn trim_counted(&mut self, n: i64) {
        self.pg_call(|pg| pg.trim_counted(n));
    }
    fn trim_unmap(&mut self, clone: &Hobject) {
        let c = clone.clone();
        self.pg_call(|pg| pg.snap_unmap(c));
    }
    fn trim_note(&mut self, msg: String) {
        self.notes.push(msg);
    }
    fn op_stale(&self, op_epoch: u32) -> bool {
        self.facts().is_some_and(|f| op_epoch < f.op_floor)
    }
    fn scrub_ls(&self, arg: &peering::scrubls::LsArg) -> Result<(u32, Vec<Vec<u8>>), i32> {
        self.set
            .pg(self.spg)
            .map_or(Err(opwire::errno::ENOENT), |p| p.scrub_ls(arg))
    }
    fn pg_blocked(&self) -> bool {
        self.facts().is_some_and(|f| f.blocked)
    }
    fn pool_caps_info(&self) -> (&[u8], Option<&opexec::caps::AppMeta>) {
        pool_caps_info(self.map, self.spg.pgid.pool as i64)
    }
    fn locate(&self, name: &[u8], oloc: &denc::types::ObjectLocator) -> Option<(SpgT, u32)> {
        let m = self.map?;
        let raw = m
            .object_to_raw_pg(oloc.pool, name, &oloc.key, &oloc.nspace, oloc.hash)
            .ok()?;
        let pool = m.pool(oloc.pool)?;
        let pg = pool.raw_pg_to_pg(raw);
        // EC pool: the op goes to the acting primary's SHARD (a NO_SHARD pgid names no EC PG: the primary parks it forever)
        let mut shard = denc::types::ShardId::NO_SHARD;
        if pool.is_erasure() {
            let mp = crate::pgs::cur_mapping(self.set, m, pg);
            if let Some(i) = mp.acting.iter().position(|&o| o == mp.acting_primary) {
                shard = denc::types::ShardId(i as i8);
            }
        }
        Some((SpgT { pgid: pg, shard }, raw.seed))
    }
    fn whoami(&self) -> i64 {
        i64::from(self.whoami)
    }
    fn pool_snapc(&self) -> Option<replwire::SnapContext> {
        let p = self.map?.pool(self.spg.pgid.pool as i64)?;
        if !p.has_flag(osdmap::pool::flags::POOL_SNAPS) {
            return None;
        }
        Some(replwire::SnapContext {
            seq: p.snap_seq,
            snaps: p.snaps.keys().rev().copied().collect(),
        })
    }
    fn cls_map(&self) -> opexec::ClsMap {
        let Some(m) = self.map else {
            return opexec::ClsMap::default();
        };
        opexec::ClsMap {
            journal_pad: m.require_min_compat_client >= osdmap::consts::release::OCTOPUS,
            pool_stripe_width: m
                .pool(self.spg.pgid.pool as i64)
                .map_or(0, |p| p.stripe_width as u64),
        }
    }
    fn pool_full(&self) -> (bool, bool) {
        self.map
            .map(|m| {
                let pool = m.pool(self.spg.pgid.pool as i64);
                (
                    m.flags & osdmap::consts::map_flags::FULL != 0
                        || pool.is_some_and(|p| p.has_flag(osdmap::pool::flags::FULL)),
                    pool.is_some_and(|p| p.has_flag(osdmap::pool::flags::FULL_QUOTA)),
                )
            })
            .unwrap_or((false, false))
    }
    fn pool_eio(&self) -> bool {
        self.facts().is_some_and(|f| f.pool_eio)
    }
    fn failsafe_full(&self) -> bool {
        self.failsafe
    }
}

impl<B: Backend> Osd<B> {
    /// A client op at a primary PG (checks of client-ops 5.2 done here, the rest in the engine).
    pub(crate) fn pg_client_primary(&mut self, id: u64, tid: u64, mut op: MOSDOp) {
        let _s = wprof::span(wprof::S::Gate);
        // the pool entry is read once for the whole gate (the map cannot change inside this call)
        let pool = self
            .map
            .as_deref()
            .and_then(|m| m.pool(op.pgid.pgid.pool as i64));
        let (pool_ec, force_resend, pg_num) = pool.map_or((false, 0, None), |p| {
            (p.is_erasure(), p.last_force_op_resend, Some(p.pg_num))
        });
        // EC pool: an op whose header carries no shard (v7 MOSDOp decode, OSD-internal copy-get) targets our own shard
        if pool_ec {
            self.fill_own_shard(&mut op);
        }
        let spg = op.pgid;
        let Some(pg) = self.pg.set.pg(spg) else {
            // the map makes us its primary (checked by the caller) but the PG is not here yet (creation pending, store
            // load / move not done): wait for it like classic `waiting_for_pg`, the client sends nothing again; judged
            // again on every map (dropped there if it no longer maps to us). Passive pools never get the PG.
            if self.pg.set.is_passive(spg.pgid.pool) {
                return self.pg_drop_op("passive pg", id, tid, &op);
            }
            return self.pg_park_op(id, tid, op, true);
        };
        if pg.refusal().is_some() {
            // passive PG (EC / unsupported): never answer (counted, local log only)
            self.pg_drop_op("passive pg", id, tid, &op);
            return;
        }
        if pg.past_bounds_stopped() {
            // stopped PG (peering.md 3.8): nothing served or applied, the client retries
            self.pg_drop_op("past interval bounds stop", id, tid, &op);
            return;
        }
        if self.pg.dead {
            self.pg_drop_op("pg host dead", id, tid, &op);
            return;
        }
        if pg.client_op_stale(op.osdmap_epoch) || op.osdmap_epoch < force_resend {
            self.pg_drop_op("stale epoch", id, tid, &op);
            return; // dropped; the client resends after it sees the new map
        }
        // an op for an object this PG does not contain (stale client mapping around a split / merge): misdirected,
        // dropped; the client re-targets with the current map (split-merge.md 8)
        if let Some(n) = pg_num
            && pgwire::pgmath::object_pg(op.hash, n) != spg.pgid.seed
        {
            self.pg.c.misdirected_dropped += 1;
            self.pg_drop_op("object not in this pg", id, tid, &op);
            return;
        }
        let Some(info) = self.conn_info(id) else {
            self.pg_drop_op("no connection info", id, tid, &op);
            return;
        };
        let trace_key = if self.pg.tr.on() {
            self.trace_op_in(id, tid, &op, info.who)
        } else {
            0
        };
        if self.tracker.lim.enabled {
            let mut rec = crate::optrack::OpRec::new(
                id,
                tid,
                info.who,
                info.addr,
                &op,
                self.now.as_nanos() as u64,
            );
            rec.trace_key = trace_key;
            self.tracker.start(rec);
        }
        self.pg.share.note_message(opexec::engine::is_listing(&op));
        let req = ClientReq {
            placement_read: op.placement_read,
            conn: id,
            tid,
            caps: info.caps.clone(),
            op: Box::new(op),
            who: info.who,
            addr: info.addr,
            peer_addr: info.peer_addr,
            features: info.features,
        };
        let in_bytes = req.op.ops.iter().map(|o| o.indata.len() as u64).sum();
        self.note_pg_work(spg, 1, in_bytes);
        self.pg_run(spg, move |e, env| e.on_op(env, req));
        self.pg_post();
    }

    /// Run `f` against the engine of primary PG `spg` (created on first use) and ship its outputs.
    pub(crate) fn pg_run<F>(&mut self, spg: SpgT, f: F)
    where
        F: FnOnce(&mut Engine, &mut PgEnv<'_, B::Pg>),
    {
        if self.pg.dead {
            return;
        }
        self.settle_late(); // the engine reads the store: every held-back txn of an earlier call applies first
        let late_ok = self.pg.late_ok;
        let whoami = self.id.whoami;
        let now = self.pg_mono();
        let wall = self.wall();
        let mut dropped: Vec<opexec::Dropped> = Vec::new();
        let notes: Vec<String>;
        // reused buffer (taken so a nested call cannot see it): no allocation per reply
        let mut outs = std::mem::take(&mut self.pg.outs_buf);
        let (rest, failed, repairs, late) = {
            let map = self.map.as_deref();
            let host = &mut self.pg;
            let Some(reset) = host.set.pg(spg).map(|p| p.last_peering_reset()) else {
                return;
            };
            let limits = host.limits;
            let obj_cache = host.obj_cache;
            // the class lists are copied only into a new engine, never per call (hot path)
            let eng = match host.eng.entry(spg) {
                std::collections::hash_map::Entry::Occupied(o) => o.into_mut(),
                std::collections::hash_map::Entry::Vacant(v) => {
                    host.eng_reset.insert(spg, reset);
                    host.eng_new.push(spg);
                    v.insert(Engine::new(spg, limits, host.classes.clone()))
                }
            };
            let (links, remote, core) = (&self.links, &self.cl.remote, self.cl.spec.id);
            let conn_open = |id: u64| crate::xcore::conn_open(links, remote, core, id);
            let mut env = PgEnv {
                conn_open: &conn_open,
                set: &mut host.set,
                store: &mut host.store,
                spg,
                now,
                wall,
                map,
                whoami,
                rest: Vec::new(),
                failed: None,
                notes: Vec::new(),
                persist_t: &mut host.persist_t,
                tr: &mut host.tr,
                eio: Default::default(),
                failsafe: host.failsafe,
                repairs: 0,
                late_ok,
                send_first: false,
                late: None,
                obj_cache,
                share: Some(&mut host.share),
                facts: Default::default(),
                refuse_own: &mut host.refuse_next,
                bad_txns: &mut host.c.bad_txns,
            };
            let c = &eng.c;
            let c0 = [
                c.obj_hits,
                c.obj_misses,
                c.wake_probes,
                c.wake_skips,
                c.wake_direct,
                c.list_deferred,
            ];
            f(eng, &mut env);
            let (c, p) = (&eng.c, &mut self.perf.op);
            p.obj_cache_hit += c.obj_hits - c0[0];
            p.obj_cache_miss += c.obj_misses - c0[1];
            p.gate_probe += c.wake_probes - c0[2];
            p.gate_skip += c.wake_skips - c0[3];
            p.gate_direct += c.wake_direct - c0[4];
            p.list_deferred += c.list_deferred - c0[5];
            if eng.runs_again()
                && let Some(s) = env.share.as_deref_mut()
            {
                s.pending = true;
            }
            // only sends may go out before the held-back txn; anything else ran after it before (order kept)
            if !env.rest.iter().all(|a| matches!(a, Action::Send(_))) {
                env.settle_late();
            }
            dropped.extend(eng.take_dropped());
            notes = std::mem::take(&mut env.notes);
            let late = env.late.take().map(|(s, t, x, _)| (s, t, x));
            eng.out_into(&mut outs);
            (env.rest, env.failed, env.repairs, late)
        };
        let out_bytes = outs
            .iter()
            .map(|o| match o {
                Out::Reply { reply, .. } => reply.ops.iter().map(|o| o.outdata_len() as u64).sum(),
                _ => 0,
            })
            .sum();
        self.note_pg_work(spg, 0, out_bytes);
        self.perf.op.read_repair += repairs;
        self.pg.eng_note(spg);
        self.pg_dropped(dropped);
        for n in notes {
            self.log(format!("pg: {n}"));
            self.clog(messages::clog::ERROR, &n);
        }
        if let Some(why) = failed {
            return self.fail_stop(&why);
        }
        self.pg_exec(rest);
        if let Some(l) = late {
            // the repops are queued for their link cores: the local apply follows when the driver moved them
            // (`Osd::apply_late`), or before anything else touches this core's PGs (`settle_late`)
            self.perf.op.late_held += 1;
            self.pg.late.push(l);
        }
        self.pg_send_outs(&mut outs);
        self.pg.outs_buf = outs;
    }

    /// Ops an engine dropped without a reply: their tracker records end (the reply never comes, the client resends or
    /// supersedes the tid), their clients learn our map; a source read of a copy goes back to its origin (re-sent
    /// there).
    fn pg_dropped(&mut self, dropped: Vec<opexec::Dropped>) {
        for d in dropped {
            self.tracker.forget(d.conn, d.tid);
            if crate::copy::is_copy_conn(d.conn) {
                self.copy_answer(d.conn, Err(errno::EAGAIN));
            } else {
                self.pg_share_map(d.conn, d.epoch);
            }
        }
    }

    /// After every PG event: drop engines of PGs that are no longer ours / changed interval, feed completed writes
    /// back, re-run parked ops.
    ///
    /// The parked PGs visited per pass are driven by what can unpark an op, not by every op that ran: all of them
    /// when the store woke something (`woke`, tokens checked per PG by `skip_wake`) or the PG machinery touched too
    /// many PGs to list; else the sticky ones (`PgHost::eng_sticky`: waiting for more than store loads, these have no
    /// wake event) plus the PGs whose state changed (touched, write done, trim kick) or whose EC reads / writes woke.
    /// Every other parked PG would be skipped by `skip_wake` with an empty wake anyway
    /// ([`opexec::Engine::quiet_without_wake`]).
    pub(crate) fn pg_post(&mut self) {
        if self.pg.in_post || self.pg.dead {
            return;
        }
        self.pg.in_post = true;
        // every engine change goes through `eng_note`: the indexes match a scan (debug builds, i.e. every test)
        debug_assert!(
            self.pg.eng.iter().all(|(s, e)| {
                self.pg.eng_parked.contains(s) == e.has_parked()
                    && self.pg.eng_sticky.contains(s) == (e.has_parked() && !e.quiet_without_wake())
            }),
            "eng_parked / eng_sticky out of step with the engines"
        );
        let mut woke = std::mem::take(&mut self.pg.wake);
        let mut ec_woke = std::mem::take(&mut self.pg.ec_wake_buf);
        let mut extra = std::mem::take(&mut self.pg.post_extra);
        for _ in 0..100 {
            extra.clear();
            // EC reads / writes wake only their PG's ops parked on those objects (no core-wide probe of every gated op)
            self.pg.set.take_ec_wake(&mut ec_woke);
            let touched_all = self.pg_engine_sync(&mut extra);
            while let Some((spg, tid, ver, res)) = self.pg.done_q.pop_front() {
                extra.push(spg);
                self.pg_run(spg, move |e, env| e.on_write_done(env, tid, ver, res));
            }
            for spg in std::mem::take(&mut self.pg.trim_kicks) {
                extra.push(spg);
                if self.pg.set.pg(spg).is_some_and(|p| p.is_primary()) {
                    self.pg_run(spg, |e, env| e.trim_kick(env));
                }
            }
            let mut parked = std::mem::take(&mut self.pg.parked_buf);
            parked.clear();
            let host = &self.pg;
            if woke.any() || touched_all {
                crate::pgs::parked_walk(&host.eng_parked, host.share.last, &mut parked);
            } else {
                crate::pgs::parked_walk(&host.eng_sticky, host.share.last, &mut parked);
                if !host.eng_parked.is_empty() {
                    for &spg in extra.iter().chain(ec_woke.iter().map(|e| &e.0)) {
                        if host.eng_parked.contains(&spg) && !parked.contains(&spg) {
                            parked.push(spg);
                        }
                    }
                }
            }
            let now = self.pg_mono();
            for &spg in &parked {
                // the EC wake of this PG joins the store wake (a copy only for the rare PG that has one)
                let merged;
                let w: &WakeSet = match ec_woke.binary_search_by_key(&spg, |e| e.0) {
                    Ok(i) => {
                        let mut m = woke;
                        m.merge(&ec_woke[i].1);
                        merged = m;
                        &merged
                    }
                    Err(_) => &woke,
                };
                // a wake none of the PG's gated ops waits for: no engine run (its setup costs more than the check)
                let host = &mut self.pg;
                let live = host
                    .set
                    .pg(spg)
                    .is_some_and(|p| p.is_primary() && p.is_active() && p.is_readable(now));
                let store = &host.store;
                if host.eng.get_mut(&spg).is_some_and(|e| {
                    let s0 = e.c.wake_skips;
                    let skip = e.skip_wake(w, live, || store.admission_ready_for(spg));
                    self.perf.op.gate_skip += e.c.wake_skips - s0;
                    skip
                }) {
                    continue;
                }
                self.pg_run(spg, move |e, env| e.retry_woken(env, w));
            }
            self.pg.parked_buf = parked;
            self.pg.set.ec_read_errors_delivered();
            if self.pg.done_q.is_empty() && self.pg.trim_kicks.is_empty() {
                break;
            }
            woke.clear();
        }
        self.pg.ec_wake_buf = ec_woke;
        self.pg.post_extra = extra;
        self.pg.in_post = false;
    }

    /// Syncs the engines with their PGs; pushes the touched PGs that have parked ops onto `visit` and answers whether
    /// too many were touched to list them (every parked PG is a candidate then).
    fn pg_engine_sync(&mut self, visit: &mut Vec<SpgT>) -> bool {
        // What these engines emit while we reset / tear them down (UNBLOCKs) is sent NOW: an engine that parks
        // nothing is never visited again, and a client blocked by a backoff sends nothing that would wake it.
        // only PGs the PG machinery touched since the last sync can have changed role or interval
        // (plus engines created since: their PG may not be primary)
        let fresh = std::mem::take(&mut self.pg.eng_new);
        // reused buffer (swapped with the touched list): no allocation per call
        let mut spgs = std::mem::take(&mut self.pg.touched_buf);
        let all = match self.pg.set.take_touched(&mut spgs) {
            peering::Touched::All => {
                spgs.extend(self.pg.eng.keys().copied());
                true
            }
            peering::Touched::Listed => {
                if !fresh.is_empty() {
                    spgs.extend(fresh);
                    spgs.sort_unstable();
                    spgs.dedup();
                }
                spgs.retain(|s| self.pg.eng.contains_key(s));
                false
            }
        };
        let mut outs: Vec<Out> = Vec::new();
        let mut dropped: Vec<opexec::Dropped> = Vec::new();
        for &s in &spgs {
            let st = self
                .pg
                .set
                .pg(s)
                .map(|p| (p.is_primary(), p.last_peering_reset()));
            match st {
                Some((true, r)) => {
                    if self.pg.eng_reset.get(&s) != Some(&r) {
                        self.pg.eng_reset.insert(s, r);
                        if let Some(e) = self.pg.eng.get_mut(&s) {
                            e.reset();
                            outs.extend(e.take_out());
                        }
                    }
                }
                _ => {
                    self.tracker.forget_pg(s);
                    if let Some(mut e) = self.pg.eng.remove(&s) {
                        outs.extend(e.teardown());
                        dropped.extend(e.take_dropped());
                    }
                    self.pg.eng_reset.remove(&s);
                }
            }
            self.pg.eng_note(s);
        }
        // the engine states are final now (`eng_note` above): the touched PGs that still have parked ops
        if !self.pg.eng_parked.is_empty() {
            visit.extend(spgs.iter().filter(|s| self.pg.eng_parked.contains(s)));
        }
        spgs.clear();
        self.pg.touched_buf = spgs;
        self.pg_send_outs(&mut outs);
        self.pg_dropped(dropped);
        all
    }

    fn pg_send_outs(&mut self, outs: &mut Vec<Out>) {
        for o in outs.drain(..) {
            match o {
                Out::Reply {
                    conn,
                    tid,
                    placement_read,
                    class,
                    reply,
                } => {
                    if conn == opexec::engine::INTERNAL_CONN {
                        continue;
                    }
                    if crate::copy::is_copy_conn(conn) {
                        self.copy_answer(conn, Ok(*reply));
                        continue;
                    }
                    self.op_done(conn, tid, class, &reply);
                    let tkey = if self.pg.tr.live_n != 0 {
                        self.pg.tr.reply(conn, tid)
                    } else {
                        None
                    };
                    let _s = wprof::span(wprof::S::Reply);
                    let queued = match placement_read {
                        Some(retry) if !self.link_is_local(conn) => {
                            self.xsend(
                                link_core(conn),
                                crate::xcore::XMsg::ClientReply {
                                    link: conn,
                                    tid,
                                    retry,
                                    reply,
                                },
                            );
                            true
                        }
                        Some(retry) => self.deliver_placement_reply(conn, tid, retry, reply),
                        None => self.send_client_reply(conn, tid, *reply),
                    };
                    if let Some(k) = tkey.filter(|_| queued) {
                        self.trace_tx_queue(k, crate::trace::TX, link_core(conn));
                    }
                }
                Out::Backoff { conn, msg } => {
                    if crate::copy::is_copy_conn(conn) {
                        // the source PG cannot serve now: forget the backoff, the read is sent again later (the op
                        // that triggered the BLOCK is a reported drop: `pg_dropped` answers it EAGAIN)
                        if msg.op == opwire::consts::backoff::BLOCK {
                            self.engines_conn_closed(conn);
                        }
                        continue;
                    }
                    let feats = self.link_features(conn);
                    match ClientMsg::Backoff(msg).encode(feats) {
                        Ok((ty, v, c, segs)) => {
                            self.send_raw(conn, 0, 0, (ty, v, c), segs);
                        }
                        Err(e) => self.log(format!("encode MOSDBackoff: {e}")),
                    }
                }
                Out::CopyRead {
                    origin, step, op, ..
                } => self.copy_start(origin, step, *op),
                Out::Notify { conn, msg } => {
                    if crate::copy::is_copy_conn(conn) {
                        continue;
                    }
                    let feats = self.link_features(conn);
                    match ClientMsg::WatchNotify(msg).encode(feats) {
                        Ok((ty, v, c, segs)) => {
                            self.send_raw(conn, 0, 0, (ty, v, c), segs);
                        }
                        Err(e) => self.log(format!("encode MWatchNotify: {e}")),
                    }
                }
            }
        }
    }

    /// Delivers a placement-read reply on its link's core. A live attempt owns the
    /// reply: its original source pieces and checked grant go to the connection's
    /// RC QP; the transport posts the WRITEs and reports the terminal outcome,
    /// which sends the reply. An error reply has no WRITE source: its inline
    /// terminal reply is queued before later output on this session. A cancelled
    /// attempt is retired by its CANCEL (a late PG result must not start WRITEs);
    /// a retired attempt or a lost link drops the reply. Returns whether
    /// anything was queued.
    pub(crate) fn deliver_placement_reply(
        &mut self,
        conn: u64,
        tid: u64,
        retry: u32,
        reply: Box<MOSDOpReply>,
    ) -> bool {
        let Some(l) = self.links.get_mut(&conn) else {
            return false;
        };
        if l.placement.cancelled(tid, retry) {
            return false;
        }
        let Some(grant) = l.placement.grant(tid, retry) else {
            return false;
        };
        let source = reply.placed_read_source();
        l.placement.store_reply(tid, retry, *reply);
        match source {
            Some((pieces, block_crcs, len)) => self.io.push_back(IoCmd::PlaceReadReply {
                conn,
                tid,
                retry,
                grant,
                pieces,
                block_crcs,
                len,
            }),
            None => self.placement_preflight_refused(conn, tid, retry),
        }
        true
    }

    /// The connection core keeps an admitted reply's source pieces intact until
    /// it can choose the ordered transport path. Without a live attempt it uses
    /// the ordinary segmented SEND path, preserving `Bytes` ownership.
    pub(crate) fn send_client_reply(&mut self, conn: u64, tid: u64, reply: MOSDOpReply) -> bool {
        let feats = self.link_features(conn);
        match reply.encode_parts(feats) {
            Ok((segs, crc, more)) => {
                let hdr = (
                    MOSDOpReply::MSG_TYPE,
                    MOSDOpReply::HEAD_VERSION,
                    MOSDOpReply::COMPAT_VERSION,
                );
                self.send_raw_crc(
                    conn,
                    tid,
                    0,
                    hdr,
                    segs,
                    crate::xcore::DataX {
                        crc,
                        more,
                        ..Default::default()
                    },
                )
            }
            Err(e) => {
                self.log(format!("encode MOSDOpReply: {e}"));
                false
            }
        }
    }

    /// Earliest engine timer (watch/notify), absolute.
    pub(crate) fn engines_next_deadline(&self) -> Option<Duration> {
        let eng = self
            .pg
            .eng_due
            .first()
            .map(|(d, _)| Duration::from_nanos(d));
        // every engine change goes through `eng_note`: the index matches a scan
        debug_assert_eq!(
            self.pg.eng_due.first().map(|(d, _)| d),
            self.pg.eng.values().filter_map(|e| e.next_deadline()).min()
        );
        match (eng, self.pg.cp.next_due()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    pub(crate) fn engines_tick(&mut self) {
        let now = self.pg_mono();
        let due = self.pg.eng_due.due(now);
        for spg in due {
            self.pg_run(spg, move |e, env| e.tick(env, now));
        }
        self.copy_tick();
        self.pg_post();
    }

    pub(crate) fn engines_conn_closed(&mut self, conn: u64) {
        self.tracker.forget_conn(conn);
        let now = self.pg_mono();
        let changed: Vec<SpgT> = self
            .pg
            .eng
            .iter_mut()
            .filter_map(|(s, e)| e.conn_closed(conn, now).then_some(*s))
            .collect();
        for s in changed {
            self.pg.eng_note(s);
        }
    }

    /// New osdmap: blocklisted watchers go away.
    pub(crate) fn engines_after_map(&mut self) {
        let spgs: Vec<SpgT> = self.pg.eng.keys().copied().collect();
        for spg in spgs {
            self.pg_run(spg, |e, env| e.check_blocklist(env));
        }
        self.copy_after_map();
        self.pg_post();
    }
}
