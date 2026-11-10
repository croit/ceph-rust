// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! EC shard role on the PG (spec ec.md 6, 7; adr 0039, 0040): sub-write apply, sub-read service, log append with real
//! `can_rollback_to` / `rollback_info_trimmed_to` cursors, roll-forward and trim with stash cleanup. The primary role
//! is in `ecprim`/`ecrec`; a pool whose PG leads here peers normally only with the EC role switches on.

use crate::ecroll::{EcCtx, cleanup_entry};
use crate::held::{Probe, WaitOn};
use crate::pg::{Pending, Pg, St};
use crate::plog::recompute_last_complete;
use crate::store::{PgStoreOps, StoreOp, with_lease};
use crate::types::*;
use bytes::Bytes;
use denc::types::{Eversion, Hobject};
use ecwire::{
    ECSubReadReply, ECSubWriteReply, MOSDECSubOpRead, MOSDECSubOpReadReply, MOSDECSubOpWrite,
    MOSDECSubOpWriteReply,
};
use pgwire::LogEntry;

const EIO: i32 = -5;

/// What accompanies the entries of an EC shard log append.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum EcAppend {
    /// sub-write with its transaction applied
    Applied,
    /// sub-write to a backfill / async recovery target: transaction skipped, crt to the head without cleanup
    NotApplied,
    /// log-only update (MOSDPGUpdateLogMissing: write-error / lost entries): no transaction; cursors as for an applied
    /// write (roll forward to `pct`, classic `append_log_entries_update_missing`); every non-error entry updates missing
    LogOnly,
}
const EOPNOTSUPP: i32 = -95;
const EINVAL: i32 = -22;

/// Every store range `(soid, off, len)` a sub-read reads ([`sub_read_ranges`]; an extent or sub-chunk list the read
/// refuses warms nothing: `on_ec_read` reports it as an object error).
fn sub_read_each(
    ec: &pgwire::EcPoolInfo,
    op: &ecwire::ECSubRead,
    mut f: impl FnMut(&Hobject, u64, u64),
) {
    for (soid, extents) in &op.to_read {
        for (off, len, _) in extents {
            match sub_read_ranges(ec, op.subchunks.get(soid), *off, *len) {
                Ok(Some(rs)) => rs.into_iter().for_each(|(o, l)| f(soid, o, l)),
                Ok(None) => f(soid, *off, *len),
                Err(_) => {}
            }
        }
    }
}

/// Store ranges of one sub-read extent (ec-clay.md 7.1): `Ok(None)` = plain read of `(off, len)`; else for every chunk
/// stride `m_ < len` each `(first, count)` sub-chunk range in list order. Nothing is allocated or read before the
/// extent and the list are validated: they come from the peer, and every range is answered in one reply piece whose
/// length is a u32 (`ECSubReadReply`), so a longer extent can never be served (EINVAL).
fn sub_read_ranges(
    ec: &pgwire::EcPoolInfo,
    subs: Option<&Vec<(i32, i32)>>,
    off: u64,
    len: u64,
) -> Result<Option<Vec<(u64, u64)>>, i32> {
    if len == 0 {
        return Ok(None);
    }
    // every range is answered in one reply piece whose length is a u32 (`ECSubReadReply`): a longer extent can never
    // be served, and its end must not wrap
    if len > u64::from(u32::MAX) {
        return Err(EINVAL);
    }
    off.checked_add(len).ok_or(EINVAL)?;
    let Some(subs) = subs else {
        return Ok(None);
    };
    let s = i64::from(ec.sub_chunks.max(1));
    if s == 1 {
        // the pool has no sub-chunks: only the whole chunk is a valid list (classic sends nothing else)
        return if subs.as_slice() == [(0, 1)] {
            Ok(None)
        } else {
            Err(EOPNOTSUPP)
        };
    }
    let c = u64::from(ec.chunk_size);
    if c == 0 || !c.is_multiple_of(s as u64) {
        return Err(EINVAL);
    }
    // one range per sub-chunk at most, each a non-empty part of the chunk (a list that is not this is malformed)
    if subs.is_empty()
        || subs.len() > s as usize
        || subs
            .iter()
            .any(|(f, n)| *f < 0 || *n <= 0 || i64::from(*f) + i64::from(*n) > s)
    {
        return Err(EINVAL);
    }
    // exactly the whole chunk: a plain read of the extent
    if subs.len() == 1 && subs[0].0 == 0 && i64::from(subs[0].1) == s {
        return Ok(None);
    }
    let sc = c / s as u64;
    let strides = len.div_ceil(c);
    let ranges = usize::try_from(strides)
        .ok()
        .and_then(|n| n.checked_mul(subs.len()))
        .ok_or(EINVAL)?;
    let mut v = Vec::with_capacity(ranges);
    let mut m_ = 0;
    while m_ < len {
        for (f, n) in subs {
            let o = off
                .checked_add(m_)
                .and_then(|o| o.checked_add(*f as u64 * sc))
                .ok_or(EINVAL)?;
            v.push((o, *n as u64 * sc));
        }
        m_ += c;
    }
    Ok(Some(v))
}
/// Seed of the shard / data crc chains (raw register, `-1`).
const CRC_SEED: u32 = 0xFFFF_FFFF;

impl Pg {
    /// Supported EC pool (the gate said yes): we may serve our shard.
    pub(crate) fn ec_supported(&self) -> bool {
        self.pool.ec.as_ref().is_some_and(|e| e.supported)
    }

    /// Geometry for the rollback executor; `None` for replicated pools (and unsupported EC pools).
    pub(crate) fn ec_ctx(&self) -> Option<EcCtx> {
        let e = self.pool.ec.as_ref().filter(|e| e.supported)?;
        if self.spg.shard.0 < 0 {
            return None;
        }
        let mut c = EcCtx::of(e, self.spg.shard.0 as u32);
        c.epoch = self.map.epoch();
        Some(c)
    }

    /// Mode O (spec 8): apply the pwlc entry `src` carries for OUR shard to our info and log head (raises
    /// `last_update` over partial writes that skipped us). Persisted via info + explicit head.
    pub(crate) fn ec_apply_own_pwlc(&mut self, src: &pgwire::PgInfo) -> bool {
        if !self.ec_opt() {
            return false;
        }
        let Some(&p) = src.partial_writes_last_complete.get(&self.me.shard) else {
            return false;
        };
        let mut head = self.log.log.head;
        if !crate::ecopt::apply_pwlc(p, &mut self.info, Some(&mut head)) {
            return false;
        }
        if head != self.log.log.head {
            self.log.log.head = head;
            self.txn.push(StoreOp::LogSetHead(head));
        }
        self.info_dirty = true;
        true
    }

    /// Shard side of `update_peer_info` (spec 8) at activation by the primary's info `oinfo`: merge its pwlc (ignored
    /// from nonprimary shards), void coverage past its `last_update` (adr 0067 am. 5: a stale own entry or a primary
    /// entry past its head would raise us over the authoritative head), then apply our own entry.
    pub(crate) fn ec_update_peer_pwlc(
        &mut self,
        from_shard: denc::types::ShardId,
        oinfo: &pgwire::PgInfo,
    ) {
        let Some(e) = self.pool.ec.as_ref().filter(|e| e.supported && e.optimized) else {
            return;
        };
        let np = from_shard.0 >= 0 && e.is_nonprimary(from_shard.0 as u32);
        if crate::ecopt::merge_pwlc(&mut self.info, oinfo, np)
            | crate::ecopt::rollback_pwlc(&mut self.info, oinfo.last_update)
        {
            self.info_dirty = true;
        }
        let own = self.info.clone();
        self.ec_apply_own_pwlc(&own);
    }

    /// Mode O pool (adr 0067) served here.
    pub(crate) fn ec_opt(&self) -> bool {
        self.ec_ctx().is_some_and(|c| c.opt)
    }

    /// Operator visibility of the rollback executor: a note (logged by the OSD) and a counter whenever a log rewind /
    /// merge of an EC shard rolled entries back or removed objects.
    pub(crate) fn ec_note_rewind(&mut self, ops: &[StoreOp]) {
        if self.ec_ctx().is_none() {
            return;
        }
        let shard_ops: usize = ops
            .iter()
            .map(|o| match o {
                StoreOp::Shard(v) => v.len(),
                _ => 0,
            })
            .sum();
        let removed = ops
            .iter()
            .filter(|o| matches!(o, StoreOp::RemoveObject(_)))
            .count();
        if shard_ops + removed > 0 {
            self.ec_rewound_at = self.map.epoch();
            if self.cfg.ec_trace {
                let mut t = String::from("rewind");
                for o in ops {
                    match o {
                        StoreOp::Shard(v) => {
                            for s in v {
                                t.push_str(&format!(" {}", shard_op_brief(s)));
                            }
                        }
                        StoreOp::RemoveObject(h) => {
                            t.push_str(&format!(" rm {}", crate::ecprim::tname(h)))
                        }
                        _ => {}
                    }
                }
                t.push_str(&format!(
                    " -> lu {} head {}",
                    self.info.last_update, self.log.log.head
                ));
                self.ec_trace(|| t);
            }
            *self
                .counters
                .errors
                .entry("ec rewind executed")
                .or_default() += 1;
            self.notes.push(format!(
                "pg {}: EC divergent entries undone: {shard_ops} rollback/stash ops, {removed} objects removed (to be recovered)",
                self.spg
            ));
        }
    }

    /// Stash GC at activation (adr 0040): a stash object that no log entry newer than `rollback_info_trimmed_to`
    /// accounts for is a leak (missed roll-forward, crash between steps): delete it.
    pub(crate) fn ec_stash_gc(&mut self, store: &impl PgStoreOps) {
        let Some(ctx) = self.ec_ctx() else { return };
        let stash = store.ec_list_stash(self.spg);
        if stash.is_empty() {
            return;
        }
        let rit = self.log.log.rollback_info_trimmed_to;
        let mut keep: std::collections::BTreeSet<(Hobject, u64)> = Default::default();
        for e in self.log.entries().iter().filter(|e| e.version > rit) {
            if let Ok(c) = cleanup_entry(&ctx, e) {
                for op in c {
                    if let crate::store::ShardOp::Remove { soid, generation } = op {
                        keep.insert((soid, generation));
                    }
                }
            }
        }
        let rm: Vec<crate::store::ShardOp> = stash
            .into_iter()
            .filter(|k| !keep.contains(k))
            .map(|(soid, generation)| crate::store::ShardOp::Remove { soid, generation })
            .collect();
        if !rm.is_empty() {
            self.notes.push(format!(
                "pg {}: EC stash GC removed {} leaked stash objects",
                self.spg,
                rm.len()
            ));
            self.txn.push(StoreOp::Shard(rm));
        }
    }

    // ---- sub-write (ec.md 7.1) ------------------------------------------------------------------------------------

    /// `Some((m, on))` = the sub-write must wait for `on` (admission, space, the blocks its stash reads; nothing applied,
    /// nothing logged): the caller holds it (`held::Held`). Every check that drops it runs first.
    pub(crate) fn on_ec_write(
        &mut self,
        from: i32,
        tid: u64,
        m: MOSDECSubOpWrite,
        store: &impl PgStoreOps,
        probe: &mut Probe,
    ) -> Option<(MOSDECSubOpWrite, WaitOn)> {
        if self.st != St::ReplicaActive {
            // a classic primary waits for this reply forever: make it visible
            self.error("ec write in non-active state (dropped)");
            return None;
        }
        if from != self.acting_primary {
            self.error("ec write from non-primary (dropped)");
            return None;
        }
        if m.pgid.shard != self.me.shard || self.ec_ctx().is_none() {
            self.error("ec write for another shard or unsupported pool");
            return None;
        }
        // a duplicate (every entry already in our log) is never applied or acked twice (see `on_repop`); it is decided
        // before the wait verdict: a duplicate never waits for loads (no lease, no hold clock, no space note)
        if m.op
            .log_entries
            .last()
            .is_some_and(|e| e.version <= self.info.last_update)
        {
            self.discard("duplicate ec write");
            return None;
        }
        let mut prev = self.info.last_update;
        for e in &m.op.log_entries {
            if e.version <= prev {
                self.fatal("ec write: version not increasing");
                return None;
            }
            prev = e.version;
        }
        self.lat_note(1, m.op.tid);
        let applied = !m.op.backfill_or_async_recovery;
        let mut tr_txn: Option<String> = None;
        let (txn_nonempty, wait) = match m.txn(self.cfg.page) {
            // data for another shard is a bug of the sender: refuse before anything is logged
            Ok(t) if t.objs.iter().any(|g| g.shard != self.me.shard) => {
                self.fatal("ec write: transaction names an object of another shard");
                return None;
            }
            Ok(t) => {
                if self.cfg.ec_trace {
                    tr_txn = Some(txn_brief(&t));
                }
                let wait = if applied {
                    self.ec_write_must_wait(&t, store, probe)
                } else {
                    None
                };
                (!t.is_empty(), wait)
            }
            Err(_) => {
                self.fatal("ec write: bad transaction");
                return None;
            }
        };
        if let Some(on) = wait {
            return Some((m, on));
        }
        if let Some(tx) = tr_txn {
            let es: Vec<String> =
                m.op.log_entries
                    .iter()
                    .map(|e| {
                        format!(
                            "{} op{} {} ws{:#x}",
                            e.version,
                            e.op.0,
                            crate::ecprim::tname(&e.soid),
                            e.written_shards.0[0]
                        )
                    })
                    .collect();
            let t = format!(
                "subwrite from osd.{from} tid {} e{} applied {applied} entries [{}] txn{tx} (lu before {})",
                m.op.tid,
                m.map_epoch,
                es.join(", "),
                self.info.last_update
            );
            self.ec_trace(|| t);
        }
        let op = m.op;
        for t in &op.temp_added {
            self.temps.insert(t.clone());
        }
        for t in &op.temp_removed {
            self.temps.remove(t);
            if !applied {
                // the rename that would have consumed it never arrives
                self.txn.push(StoreOp::RemoveObject(t.clone()));
            }
        }
        self.info.stats = op.stats;
        // classic order: the sub-write transaction first, then log + roll-forward (an EC_OMAP roll-forward may target
        // the stash generation this very transaction creates)
        if applied && txn_nonempty {
            self.txn.push(StoreOp::ApplyTxn {
                middle: op.txn_middle,
                data: op.txn_data,
            });
        }
        let mode = if applied {
            EcAppend::Applied
        } else {
            EcAppend::NotApplied
        };
        self.ec_append_log(
            op.log_entries,
            op.trim_to,
            op.pg_committed_to,
            mode,
            store.lazy_info(),
        );
        let reply = MOSDECSubOpWriteReply {
            pgid: self.primary_spg(),
            map_epoch: self.map.epoch(),
            op: ECSubWriteReply {
                from: self.me,
                tid: op.tid,
                last_complete: self.info.last_complete, // post-append; durable with this txn
                committed: true,
                applied: true,
            },
            min_epoch: m.min_epoch,
            trace: [0; 3],
        };
        let interval = self.last_peering_reset;
        self.flush(Pending::EcWriteReply {
            interval,
            to: from,
            tid,
            reply,
        });
        None
    }

    /// Does the sub-write wait for the blocks its stash (`clone_range` sources) reads? Submits their device reads; bounded
    /// like a repop (held until the reads complete): a core never blocks on the device for the old data of an overwrite.
    fn ec_write_must_wait(
        &mut self,
        t: &replwire::Transaction<'_>,
        store: &impl PgStoreOps,
        probe: &mut Probe,
    ) -> Option<WaitOn> {
        if !store.admission_ready_for(self.spg) {
            return Some(WaitOn::Admission);
        }
        // space preflight (adr 0021 S4): a sub-write at a shard's system floor waits, never forced
        let (bytes, entries) = t.room_cost();
        if self.space_held(store.apply_room(self.spg, bytes, entries)) {
            return Some(WaitOn::Space);
        }
        let cold = with_lease(store, probe.lease, || {
            let mut cold = false;
            for op in &t.ops {
                if let replwire::TxnOp::CloneRange2 {
                    oid, src_off, len, ..
                } = &op.op
                {
                    let g = t.get_obj(*oid);
                    cold |= !self.ec_stash_warm(&g.hobj, *src_off, *len, store);
                }
            }
            cold
        });
        ec_wait_verdict(cold, probe)
    }

    /// Does the sub-read wait for its blocks (tree path + data) to be resident?
    fn ec_read_must_wait(
        &self,
        op: &ecwire::ECSubRead,
        store: &impl PgStoreOps,
        probe: &mut Probe,
    ) -> Option<WaitOn> {
        if !store.admission_ready_for(self.spg) {
            return Some(WaitOn::Admission);
        }
        let ec = self.pool.ec.clone().unwrap_or_default();
        let cold = with_lease(store, probe.lease, || {
            let mut cold = false;
            sub_read_each(&ec, op, |soid, o, l| {
                cold |= !self.ec_range_warm(soid, o, l, store)
            });
            cold
        });
        ec_wait_verdict(cold, probe)
    }

    /// Start the device reads of a sub-read queued behind a waiting head (`held::Step::kick`): the data blocks of every
    /// range whose tree path is resident, so they load while the messages before it wait (adr 0636 am. 1). No lease:
    /// the read takes its own when it is the head. `false` = a tree path is cold (its loads were submitted) or the
    /// admission is closed: kicked again when a replay leaves it queued.
    pub(crate) fn ec_read_kick(
        &self,
        from: i32,
        m: &MOSDECSubOpRead,
        store: &impl PgStoreOps,
    ) -> bool {
        let Some(ec) = self.pool.ec.as_ref() else {
            return true;
        };
        if self.st != St::ReplicaActive
            || from != self.acting_primary
            || m.pgid.shard != self.me.shard
            || !ec.supported
        {
            return true; // dropped when it runs (`on_ec_read`)
        }
        if !store.admission_ready_for(self.spg) {
            return false;
        }
        let mut started = true;
        sub_read_each(ec, &m.op, |soid, o, l| {
            if store.warm(self.spg, soid, o, l) {
                store.warm_data(self.spg, soid, o, l);
            } else {
                started = false;
            }
        });
        started
    }

    /// `append_log` of an EC shard: the cursors stay where they are, roll-forward and trim clean the stash.
    pub(crate) fn ec_append_log(
        &mut self,
        entries: Vec<LogEntry>,
        trim_to: Eversion,
        pct: Eversion,
        mode: EcAppend,
        lazy: bool,
    ) {
        let applied = mode == EcAppend::Applied;
        let not_applied = mode == EcAppend::NotApplied;
        let hist = self.info.last_epoch_started != self.info.history.last_epoch_started;
        if hist {
            self.info.history.last_epoch_started = self.info.last_epoch_started;
            self.info.history.last_interval_started = self.info.last_interval_started;
        }
        if !self.head_stale {
            // the stored `_loghead` = our in-memory log: the store needs no read-back for the ops below (adr 0160 am. 2)
            let l = &self.log.log;
            self.txn.push(StoreOp::LogHeadIs(
                l.head,
                l.can_rollback_to,
                l.rollback_info_trimmed_to,
            ));
        }
        let ctx = self.ec_ctx();
        let opt = ctx.is_some_and(|c| c.opt);
        // mode O (spec 5.3): `pg_committed_to` may name a version we never saw (partial writes): clamp to the head
        // BEFORE the new entries
        let pct = if opt { pct.min(self.log.head()) } else { pct };
        let in_acting = self.in_acting(self.me);
        let mut invalidate = false;
        if opt && not_applied {
            // backfill / async recovery target: crt to head without cleanup (skip_rollforward)
            self.ec_advance(self.log.head(), false);
            invalidate = true;
        }
        let had_entries = !entries.is_empty();
        let mut appended = Vec::with_capacity(entries.len());
        let mut map_ops = Vec::new();
        for e in entries {
            self.note_entry(&e, applied, ctx.as_ref(), &mut map_ops);
            self.log.append_keep(e.clone());
            appended.push(e);
        }
        if !appended.is_empty() {
            self.txn.push(StoreOp::LogAppendKeep(appended));
            if opt && not_applied {
                // each log-only entry moves crt to the head without cleanup (one advance = same per-entry order)
                self.ec_advance(self.log.head(), false);
            } else if opt && !in_acting {
                // backfill target: no rollback artifacts past last_backfill
                self.ec_advance(self.log.head(), true);
                invalidate = true;
            }
        }
        if !map_ops.is_empty() {
            self.txn.push(StoreOp::SnapMap(map_ops));
        }
        recompute_last_complete(&self.log, &mut self.info, &self.missing);
        if !not_applied {
            let to = pct.min(self.log.head());
            if to > self.log.log.can_rollback_to {
                self.ec_roll_forward_to(to);
            }
        }
        if invalidate {
            crate::ecopt::invalidate_pwlc(&mut self.info);
        }
        if trim_to != Eversion::default() {
            // mode O: a long run of partial writes then a full write can put trim_to past our crt
            let t = if opt {
                trim_to.min(self.log.log.can_rollback_to)
            } else {
                trim_to
            };
            self.ec_trim_log_to(t);
        }
        self.info.log_tail = self.log.tail();
        self.pg_committed_to = self.pg_committed_to.max(pct);
        // lazy PG info (adr 0021 am. 27 for legacy EC, adr 0160 am. 2): only the log progressed (applied, nothing missing,
        // history as persisted, no pwlc: mode O stays eager); `_loghead` is written by LogAppendKeep / LogCursors anyway,
        // `PersistedPg::normalize` rebuilds last_update / last_complete / last_user_version at load. A trim set
        // `info_dirty` itself. A roll-forward without entries changes nothing in `info`.
        if lazy && applied && !opt && !hist && self.missing.is_empty() {
            self.info_adv |= had_entries;
        } else {
            self.info_dirty = true;
        }
    }

    /// Stash removals for the entries in `(after, to]` (still in the log).
    fn ec_stash_removals(&mut self, after: Eversion, to: Eversion) -> Vec<crate::store::ShardOp> {
        let Some(ctx) = self.ec_ctx() else {
            return vec![];
        };
        let mut rm = Vec::new();
        let mut bad = 0u32;
        let es = self.log.entries();
        let i0 = es.partition_point(|e| e.version <= after);
        let i1 = es.partition_point(|e| e.version <= to);
        for i in i0..i1 {
            match crate::ecopt::rollforward_entry(&ctx, es, i) {
                Ok(c) => rm.extend(c),
                Err(_) => bad += 1,
            }
        }
        for _ in 0..bad {
            self.error("ec: unparsable mod_desc at roll-forward (stash may leak)");
        }
        rm
    }

    /// `roll_forward_to(to)` (ec.md 7.6): delete the stash of every entry in `(rollback_info_trimmed_to, to]`, then
    /// advance both cursors. Durable in the caller's transaction.
    pub(crate) fn ec_roll_forward_to(&mut self, to: Eversion) {
        self.ec_advance(to, true);
    }

    /// `advance_can_rollback_to(to)`: crt, rit := max(., to); every entry in `(old rit, new rit]` gives up its stash
    /// (`cleanup`) and, mode O on a primary-capable shard, updates pwlc (`partial_write`, spec 8). Durable in the
    /// caller's transaction.
    pub(crate) fn ec_advance(&mut self, to: Eversion, cleanup: bool) {
        let rit = self.log.log.rollback_info_trimmed_to;
        if cleanup {
            let rm = self.ec_stash_removals(rit, to);
            if !rm.is_empty() {
                self.txn.push(StoreOp::Shard(rm));
            }
        }
        let crt = self.log.log.can_rollback_to.max(to);
        let new_rit = rit.max(to);
        if let Some(ctx) = self.ec_ctx().filter(|c| c.opt && !c.np) {
            let es = self.log.entries();
            let i0 = es.partition_point(|e| e.version <= rit);
            let mut prev = if i0 == 0 {
                self.log.tail()
            } else {
                es[i0 - 1].version
            };
            for e in es.range(i0..).take_while(|e| e.version <= new_rit) {
                crate::ecopt::partial_write(&mut self.info, &ctx, prev, e);
                prev = e.version;
            }
        }
        if crt == self.log.log.can_rollback_to && new_rit == rit {
            return;
        }
        self.log.log.can_rollback_to = crt;
        self.log.log.rollback_info_trimmed_to = new_rit;
        self.txn.push(StoreOp::LogCursors {
            can_rollback_to: crt,
            rollback_info_trimmed_to: new_rit,
        });
    }

    /// Trim of an EC shard log: entries that leave the log first give up their stash.
    pub(crate) fn ec_trim_log_to(&mut self, trim_to: Eversion) {
        let limit = if self.missing.is_empty() {
            self.log.head()
        } else {
            self.info.last_complete
        };
        let to = trim_to.min(limit);
        if to <= self.log.tail() {
            return;
        }
        // entries leaving the log first give up their stash (and update pwlc in mode O)
        self.ec_advance(to, true);
        let cfg = self.cfg.clone();
        let t = self.log.trim_ex(to, &cfg);
        self.txn.push(StoreOp::LogTrim {
            to,
            dups_from: t.dups_from,
            tail_up: true,
        });
        if t.dups_rewrite {
            self.txn.push(StoreOp::LogDups(
                self.log.log.dups.iter().cloned().collect(),
            ));
        }
        // re-assert the cursors after the trim (store order: a trim may reset them to the tail)
        self.txn.push(StoreOp::LogCursors {
            can_rollback_to: self.log.log.can_rollback_to,
            rollback_info_trimmed_to: self.log.log.rollback_info_trimmed_to,
        });
        self.info.log_tail = self.log.tail();
        self.info_dirty = true;
    }

    // ---- sub-read (ec.md 7.2) -------------------------------------------------------------------------------------

    /// LAB: first arrival of a shard message (no-op unless wprof is on).
    fn lat_note(&mut self, kind: u8, tid: u64) {
        if wprof::ENABLED {
            if self.lat_in.len() > 4096 {
                self.lat_in.clear();
            }
            self.lat_in.entry((kind, tid)).or_insert_with(wprof::lat_t0);
        }
    }

    /// `Some(m)` = the blocks of the read are not resident yet (device reads submitted): held like a waiting sub-write.
    pub(crate) fn on_ec_read(
        &mut self,
        from: i32,
        m: MOSDECSubOpRead,
        store: &impl PgStoreOps,
        probe: &mut Probe,
    ) -> Option<(MOSDECSubOpRead, WaitOn)> {
        if self.st != St::ReplicaActive {
            self.error("ec read in non-active state (dropped)");
            return None;
        }
        if from != self.acting_primary {
            self.error("ec read from non-primary (dropped)");
            return None;
        }
        let same_shard = m.pgid.shard == self.me.shard;
        let Some(ec) = self.pool.ec.clone().filter(|_| same_shard) else {
            self.error("ec read for another shard or unsupported pool");
            return None;
        };
        if !ec.supported {
            self.error("ec read for unsupported pool");
            return None;
        }
        // mode O: never hinfo (spec 7.1)
        self.lat_note(0, m.op.tid);
        let hinfo_check = !ec.overwrites && !ec.optimized;
        if let Some(on) = self.ec_read_must_wait(&m.op, store, probe) {
            return Some((m, on));
        }
        let op = m.op;
        let mut rep = ECSubReadReply {
            from: self.me,
            tid: op.tid,
            // tentacle+ cluster: struct v3 (data in the DATA segment, what a tentacle classic shard sends too): the shard bytes
            // are not copied into the front and the primary slices them (adr 0116)
            data_segment: self.map.require_osd_release() >= osdmap::consts::release::TENTACLE,
            ..Default::default()
        };
        // store-known crc of a buffer read whole from verified blocks: the DATA segment crc when it is that buffer
        let mut last_crc: Option<(Bytes, u32)> = None;
        let mut tr = self.cfg.ec_trace.then(String::new);
        for (soid, extents) in &op.to_read {
            if let Some(t) = tr.as_mut() {
                t.push_str(&format!(
                    " {} missing {}",
                    crate::ecprim::tname(soid),
                    u8::from(self.missing.contains(soid))
                ));
            }
            let subs = op.subchunks.get(soid);
            let mut bufs = Vec::with_capacity(extents.len());
            let mut err = None;
            // the one buffer of a v3 reply (the usual sub-read: one object, one extent, plain range): the store's verified
            // buffers by reference, no copy; the first piece is the DATA segment, the others follow it by reference
            let one =
                rep.data_segment && !hinfo_check && op.to_read.len() == 1 && extents.len() == 1;
            for (off, len, _flags) in extents {
                if one && matches!(sub_read_ranges(&ec, subs, *off, *len), Ok(None)) {
                    match store.ec_read_shared(self.spg, soid, *off, *len) {
                        Ok((parts, size)) => {
                            if let Some(t) = tr.as_mut() {
                                let n: usize = parts.iter().map(|(b, _)| b.len()).sum();
                                t.push_str(&format!(
                                    " [{off},+{len})->{n} in {} sz {size}",
                                    parts.len()
                                ));
                            }
                            let mut it = parts.into_iter();
                            let (b, c) = it.next().unwrap_or_default();
                            if let Some(c) = c {
                                last_crc = Some((b.clone(), c));
                            }
                            rep.data_more = it
                                .map(|(p, c)| {
                                    let h = c.map_or_else(crc::CrcHint::default, |c| {
                                        crc::CrcHint::new(&p, c)
                                    });
                                    (p, h)
                                })
                                .collect();
                            bufs.push((*off, b));
                        }
                        Err(e) => {
                            if let Some(t) = tr.as_mut() {
                                t.push_str(&format!(" [{off},+{len})->err {e}"));
                            }
                            err = Some(e);
                        }
                    }
                    continue;
                }
                // clay sub-chunk reads (ec-clay.md 7.1): gather the ranges of every chunk stride
                let got = match sub_read_ranges(&ec, subs, *off, *len) {
                    Err(e) => Err(e),
                    Ok(None) => store.ec_read_crc(self.spg, soid, *off, *len),
                    Ok(Some(rs)) => rs
                        .iter()
                        .try_fold((Vec::new(), 0), |(mut acc, _), (o, l)| {
                            store.ec_read(self.spg, soid, *o, *l).map(|(d, size)| {
                                acc.extend_from_slice(&d);
                                (acc, size)
                            })
                        })
                        .map(|(d, s)| (d, s, None)),
                };
                if let Some(t) = tr.as_mut() {
                    match &got {
                        Ok((d, size, _)) => {
                            t.push_str(&format!(" [{off},+{len})->{} sz {size}", d.len()))
                        }
                        Err(e) => t.push_str(&format!(" [{off},+{len})->err {e}")),
                    }
                }
                match got {
                    Ok((data, size, crc)) => {
                        if hinfo_check
                            && let Err(e) = self.ec_hinfo_check(store, soid, *off, &data, size, crc)
                        {
                            err = Some(e);
                            break;
                        }
                        let b = Bytes::from(data);
                        if let Some(c) = crc {
                            last_crc = Some((b.clone(), c));
                        }
                        bufs.push((*off, b));
                    }
                    Err(e) => {
                        err = Some(e);
                        break;
                    }
                }
            }
            match err {
                Some(e) => {
                    rep.errors.insert(soid.clone(), e);
                }
                None => {
                    rep.buffers_read.insert(soid.clone(), bufs);
                }
            }
        }
        if let Some((b, c)) = last_crc {
            rep.data_crc = crc::CrcHint::new(&b, c);
        }
        for soid in &op.attrs_to_read {
            if rep.errors.contains_key(soid) {
                continue;
            }
            match store.ec_getattrs(self.spg, soid) {
                Ok(a) => {
                    rep.attrs_read.insert(soid.clone(), a);
                }
                Err(e) => {
                    rep.buffers_read.remove(soid);
                    rep.errors.insert(soid.clone(), e);
                }
            }
        }
        if ec.optimized && !ec.is_nonprimary(self.me.shard.0.max(0) as u32) {
            self.ec_read_omap(&op, &mut rep, store);
        }
        if let Some(t0) = self.lat_in.remove(&(0, rep.tid)) {
            wprof::lat(6, t0);
        }
        if let Some(t) = tr {
            let s = format!(
                "subread from osd.{from} tid {} e{}:{t} lu {} lc {} head {} crt {} rewound e{}",
                rep.tid,
                m.map_epoch,
                self.info.last_update,
                self.info.last_complete,
                self.log.log.head,
                self.log.log.can_rollback_to,
                self.ec_rewound_at
            );
            self.ec_trace(|| s);
        }
        if rep.buffers_read.is_empty() {
            // the object failed after its data was read (attrs, omap): its pieces go with it
            rep.data_more.clear();
        }
        let reply = MOSDECSubOpReadReply {
            pgid: self.primary_spg(),
            map_epoch: self.map.epoch(),
            op: rep,
            min_epoch: m.min_epoch,
            trace: [0; 3],
        };
        self.send(from, Body::Ec(reply.into()), 0);
        None
    }

    /// Mode O sub-read omap fields on a primary-capable shard (spec 12.3): header for `omap_headers_to_read`,
    /// entries after the start key for `omap_read_from` ([`crate::ecopt::omap_wire_after`]); an object whose `_` says
    /// "no omap" is complete at once.
    /// Keys are raw bytes on the wire (any byte string, as the store holds them).
    fn ec_read_omap(
        &mut self,
        op: &ecwire::ECSubRead,
        rep: &mut ECSubReadReply,
        store: &impl PgStoreOps,
    ) {
        let no_omap = |rep: &ECSubReadReply, soid: &Hobject| {
            rep.attrs_read
                .get(soid)
                .and_then(|a| a.get(b"_".as_slice()))
                .and_then(|b| denc::from_slice::<replwire::ObjectInfo>(b).ok())
                .is_some_and(|oi| oi.flags & replwire::oi::flag::OMAP == 0)
        };
        for soid in op
            .omap_headers_to_read
            .iter()
            .chain(op.omap_read_from.keys())
        {
            if no_omap(rep, soid) {
                rep.omaps_complete.insert(soid.clone(), true);
            }
        }
        let fail = |rep: &mut ECSubReadReply, soid: &Hobject, e: i32| {
            rep.attrs_read.remove(soid);
            rep.omap_headers_read.remove(soid);
            rep.omap_entries_read.remove(soid);
            rep.buffers_read.remove(soid);
            rep.errors.insert(soid.clone(), e);
        };
        for soid in &op.omap_headers_to_read {
            if rep.errors.contains_key(soid) || rep.omaps_complete.get(soid) == Some(&true) {
                continue;
            }
            match store.ec_omap_header(self.spg, soid) {
                Ok(h) => {
                    rep.omap_headers_read.insert(soid.clone(), h);
                }
                Err(e) => fail(rep, soid, e),
            }
        }
        let max_entries = self.cfg.recovery_max_omap_entries;
        for (soid, (start, max_bytes)) in &op.omap_read_from {
            if rep.errors.contains_key(soid) || rep.omaps_complete.get(soid) == Some(&true) {
                continue;
            }
            let after = crate::ecopt::omap_wire_after(start);
            match store.ec_omap_read(self.spg, soid, after, *max_bytes, max_entries) {
                Ok((kv, done)) => {
                    let m: std::collections::BTreeMap<Vec<u8>, Vec<u8>> = kv.into_iter().collect();
                    rep.omap_entries_read.insert(soid.clone(), m);
                    rep.omaps_complete.insert(soid.clone(), done);
                }
                Err(e) => fail(rep, soid, e),
            }
        }
    }

    /// L0 read check against `hinfo_key` (ec.md 7.2): missing / undecodable hinfo, a total that differs from the file
    /// size, or a whole-shard read whose crc differs from our recorded hash is -EIO. Applies to every L0 read source:
    /// a peer's sub-read and the primary's own shard. `crc` = `crc32c(CRC_SEED, data)` when the store already knows it
    /// (verified whole blocks); the bytes are hashed only when it is unknown and the read covers the whole shard.
    pub(crate) fn ec_hinfo_check(
        &mut self,
        store: &impl PgStoreOps,
        soid: &Hobject,
        off: u64,
        data: &[u8],
        size: u64,
        crc: Option<u32>,
    ) -> Result<(), i32> {
        let raw = store.ec_getattr(self.spg, soid, ec::HINFO_KEY.as_bytes())?;
        let raw = raw.as_deref().filter(|b| !b.is_empty());
        if raw.is_none() && size == 0 {
            // empty object without hinfo: valid (a fresh hinfo of size 0, the classic backend creates one)
            return Ok(());
        }
        let Some(raw) = raw else {
            self.error("ec read: missing hinfo");
            return Err(EIO);
        };
        let Ok(hi) = ec::HashInfo::decode(raw) else {
            self.error("ec read: undecodable hinfo");
            return Err(EIO);
        };
        if hi.total_chunk_size != size {
            self.error("ec read: hinfo size mismatch");
            return Err(EIO);
        }
        if off == 0 && data.len() as u64 == hi.total_chunk_size {
            let Some(want) = hi.hashes.get(self.spg.shard.0 as usize) else {
                self.error("ec read: missing shard hash");
                return Err(EIO);
            };
            if crc.unwrap_or_else(|| crc::crc32c(CRC_SEED, data)) != *want {
                self.error("ec read: bad shard hash");
                return Err(EIO);
            }
        }
        Ok(())
    }
}

// ---- trace helpers (Config::ec_trace, OQ 41) ----------------------------------------------------------------------

/// Verdict of a held sub-write's / sub-read's probe (`Pg::repop_must_wait` rules): wait while `cold` (its device reads
/// complete and wake it), unless a forced replay applies it.
fn ec_wait_verdict(cold: bool, probe: &mut Probe) -> Option<WaitOn> {
    if std::mem::take(&mut probe.force) || !cold {
        return None;
    }
    Some(WaitOn::Loads)
}

fn gen_tag(g: u64) -> String {
    if g == crate::ecroll::LIVE {
        String::new()
    } else {
        format!("#{g}")
    }
}

/// One shard op of a rollback / roll-forward, compact (no attribute values).
pub(crate) fn shard_op_brief(s: &crate::store::ShardOp) -> String {
    use crate::ecprim::tname;
    use crate::store::ShardOp as S;
    match s {
        S::Remove { soid, generation } => format!("rm {}{}", tname(soid), gen_tag(*generation)),
        S::Rename {
            soid,
            from_gen,
            to_gen,
        } => format!(
            "mv {}{}->{}",
            tname(soid),
            gen_tag(*from_gen),
            gen_tag(*to_gen)
        ),
        S::Truncate {
            soid,
            generation,
            size,
        } => format!("trunc {}{} {size}", tname(soid), gen_tag(*generation)),
        S::SetAttrs {
            soid, generation, ..
        } => format!("attrs {}{}", tname(soid), gen_tag(*generation)),
        S::CloneRange {
            soid,
            from_gen,
            to_gen,
            off,
            len,
        } => format!(
            "clone {}{}->{} [{off},+{len})",
            tname(soid),
            gen_tag(*from_gen),
            gen_tag(*to_gen)
        ),
        S::Omap {
            soid, generation, ..
        } => format!("omap {}{}", tname(soid), gen_tag(*generation)),
    }
}

/// Data ops of a sub-write / push transaction, compact (offsets and lengths only).
pub(crate) fn txn_brief(t: &replwire::Transaction<'_>) -> String {
    use replwire::TxnOp as T;
    let mut s = String::new();
    for op in &t.ops {
        let o = |x| {
            let g = t.get_obj(x);
            format!("{}{}", crate::ecprim::tname(&g.hobj), gen_tag(g.generation))
        };
        let e = match &op.op {
            T::Write { oid, off, data } => format!("w {} [{off},+{})", o(*oid), data.len()),
            T::Zero { oid, off, len } => format!("z {} [{off},+{len})", o(*oid)),
            T::Truncate { oid, size } => format!("t {} {size}", o(*oid)),
            T::Remove { oid } => format!("rm {}", o(*oid)),
            T::Touch { oid } | T::Create { oid } => format!("touch {}", o(*oid)),
            T::CloneRange2 {
                oid,
                dest_oid,
                src_off,
                len,
                dest_off,
            } => format!(
                "cr {} [{src_off},+{len})->{}@{dest_off}",
                o(*oid),
                o(*dest_oid)
            ),
            T::Clone { oid, dest_oid } => format!("clone {}->{}", o(*oid), o(*dest_oid)),
            T::SetAttr { oid, name, .. } => {
                format!("sa {} {}", o(*oid), String::from_utf8_lossy(name))
            }
            T::SetAttrs { oid, .. } => format!("sas {}", o(*oid)),
            T::RmAttr { oid, .. } | T::RmAttrs { oid } => format!("ra {}", o(*oid)),
            _ => continue,
        };
        s.push(' ');
        s.push_str(&e);
    }
    s
}

#[cfg(test)]
mod sub_read_tests {
    use super::sub_read_ranges;

    /// A clay pool, k = 4 m = 2, C = 4096, S = 16 sub-chunks of 256 bytes.
    fn clay() -> pgwire::EcPoolInfo {
        pgwire::EcPoolInfo {
            k: 4,
            m: 2,
            stripe_width: 4 * 4096,
            chunk_size: 4096,
            sub_chunks: 16,
            supported: true,
            ..Default::default()
        }
    }

    /// Two sub-chunk ranges per chunk over two strides, in list order.
    #[test]
    fn sub_chunk_ranges_follow_the_list_and_the_strides() {
        let subs = vec![(0, 1), (8, 1)];
        assert_eq!(
            sub_read_ranges(&clay(), Some(&subs), 0, 2 * 4096),
            Ok(Some(vec![
                (0, 256),
                (8 * 256, 256),
                (4096, 256),
                (4096 + 8 * 256, 256)
            ]))
        );
        // the last stride reads its full ranges even when `len` is not a multiple of the chunk
        assert_eq!(
            sub_read_ranges(&clay(), Some(&subs), 0, 4096 + 512),
            Ok(Some(vec![
                (0, 256),
                (8 * 256, 256),
                (4096, 256),
                (4096 + 8 * 256, 256)
            ]))
        );
    }

    /// Whole-chunk lists are plain reads (spec ec-clay.md 7.1); a pool without sub-chunks accepts only `[(0, 1)]`.
    #[test]
    fn whole_chunk_lists_are_a_plain_read() {
        let whole = vec![(0, 16)];
        assert_eq!(sub_read_ranges(&clay(), Some(&whole), 4096, 8192), Ok(None));
        let mut e = clay();
        e.sub_chunks = 1;
        assert_eq!(sub_read_ranges(&e, Some(&vec![(0, 1)]), 0, 4096), Ok(None));
        assert_eq!(sub_read_ranges(&e, Some(&vec![(0, 2)]), 0, 4096), Err(-95));
        // no list at all / nothing to read: plain read
        assert_eq!(sub_read_ranges(&clay(), None, 0, 4096), Ok(None));
        assert_eq!(sub_read_ranges(&clay(), Some(&vec![]), 0, 0), Ok(None));
    }

    /// The list is a wire value: a range outside the chunk, an empty count or more ranges than sub-chunks is refused
    /// instead of being half-read or read as the whole extent.
    #[test]
    fn malformed_sub_chunk_lists_are_refused() {
        let bad = [
            vec![(1, 16)], // f + n > S: was taken as the whole extent
            vec![(-1, 1)], // outside the chunk
            vec![(0, 0)],  // reads nothing
            vec![(0, 17)], // past the chunk
            vec![(0, 4), (12, 8)],
            vec![(0, 1); 17],
            vec![],
        ];
        for subs in bad {
            assert_eq!(
                sub_read_ranges(&clay(), Some(&subs), 0, 4096),
                Err(-22),
                "{subs:?}"
            );
        }
    }

    /// An extent no reply piece can carry, and one whose end wraps: never allocated, never read (EINVAL).
    #[test]
    fn unanswerable_extents_are_refused() {
        let subs = vec![(0, 1), (8, 1)];
        assert_eq!(sub_read_ranges(&clay(), Some(&subs), 0, 1 << 62), Err(-22));
        assert_eq!(
            sub_read_ranges(&clay(), Some(&subs), 0, u64::from(u32::MAX) + 1),
            Err(-22)
        );
        assert_eq!(
            sub_read_ranges(&clay(), Some(&subs), u64::MAX - 1, 4096),
            Err(-22)
        );
        // the largest one serveable: the stride count and the capacity are computed, not overflowed
        assert_eq!(
            sub_read_ranges(&clay(), Some(&subs), 0, 4096).map(|r| r.map(|v| v.len())),
            Ok(Some(2))
        );
    }
}
