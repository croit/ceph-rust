// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! EC primary role on the PG (spec ec.md 9-11, 13; doc/ec-phase-b.md, adr 0049).
//!
//! * Write pipeline: a client write is planned at submit (versions reserved, state projected so the op layer can
//!   pipeline on one object), its old stripes are read when no earlier write on the object is uncommitted, shard
//!   transactions are generated strictly in version order, appended to our own log and fanned out as
//!   `MOSDECSubOpWrite`. The write completes when every member of `acting_recovery_backfill` committed (adr 0008);
//!   an idle pipeline with `pg_committed_to > can_rollback_to` sends the dummy roll-forward sub-write.
//! * Read service: stripe spans of one object from the cheapest k (or the wanted data) shards, decoded when a data shard
//!   is missing, retried on shard errors with the remaining shards.

use crate::pg::{HeldComplaint, Pg, St};
use crate::primary::{Chosen, RepOp};
use crate::store::{PgStoreOps, StoreOp, with_lease};
use crate::types::*;
use bytes::Bytes;
use denc::types::{Eversion, Hobject, OsdReqId, PgShard};
use ecback::{OCtx, OWritePlan, OldObj, PdwMode, WritePlan};
use ecwire::{
    ECSubRead, ECSubReadReply, ECSubWrite, MOSDECSubOpRead, MOSDECSubOpReadReply, MOSDECSubOpWrite,
    MOSDECSubOpWriteReply,
};
use pgwire::{LogEntry, LogOp, ObjectModDesc, PgInfo};
use replwire::txn::Transaction;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ops::Bound;

const EIO: i32 = 5;

/// A planned write waiting for its reads / its turn.
#[derive(Debug)]
pub(crate) struct EcWrite {
    tid: u64,
    reqid: OsdReqId,
    entries: Vec<crate::WriteEntry>,
    versions: Vec<Eversion>,
    new_temp: Option<Hobject>,
    discard_temp: Option<Hobject>,
    plan: Option<Plan>,
    /// Mode O: old data-shard bytes per (object, raw shard) = (shard offset, bytes).
    old_o: BTreeMap<(Hobject, usize), (u64, Vec<u8>)>,
    /// Mode O: `(object, shard range lo, hi, raw shards)` still to read.
    o_reads: Vec<(Hobject, u64, u64, Vec<usize>)>,
    mds: BTreeMap<Hobject, ObjectModDesc>,
    objects: Vec<Hobject>,
    /// Earlier uncommitted writes on any of our objects: the old stripes are read after they committed.
    deps: Vec<u64>,
    /// `(object, first stripe, stripes)` still to read; started when `deps` are done.
    to_read: Vec<(Hobject, u64, u64)>,
    reads_started: bool,
    pending_reads: usize,
    old: BTreeMap<(Hobject, u64), Vec<u8>>,
    /// A read failed for good: complete with this errno (negative) when it reaches the front.
    failed: Option<i32>,
    /// Mode O: our own shard bytes the stash of the write reads (`OWritePlan::stash_srcs`): prefetched before the local apply.
    own: Vec<(Hobject, u64, u64)>,
    own_ready: bool,
    /// The stash waiting for its own-shard blocks.
    own_held: HeldComplaint,
    /// Residency lease of the own-shard wait (`PgStoreOps::lease_open`, 0 = none): released after the write generated.
    own_lease: u64,
    /// LAB: `wprof::lat_t0` at submit (0 in production builds).
    t0: u64,
    /// Legacy RMW (`write_cover`): logical ranges each object is written over when the txn holds only plain writes
    /// and attr ops (`None` otherwise): data chunks written whole are not read for the RMW (adr 0043 am. 6).
    cover: Option<BTreeMap<Hobject, Vec<(u64, u64)>>>,
}

/// Legacy (L0/L1) or optimized (O) write plan.
#[derive(Debug)]
pub(crate) enum Plan {
    L(WritePlan),
    O(OWritePlan),
}

/// What a finished read is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Purpose {
    /// Old stripes of write `tid`.
    Rmw(u64),
    /// Mode O old data-shard bytes of write `tid` (per raw shard, shard space).
    RmwO(u64),
    /// Client read cache fill (op layer, `Pg::ec_wait`).
    Client,
    /// One chunk of the recovery of the object (`ecrec`).
    Recov,
}

/// Short object name for trace notes (`name`, `name@snap`).
pub(crate) fn tname(h: &Hobject) -> String {
    let n = String::from_utf8_lossy(&h.oid);
    if h.snap == denc::types::SnapId::NOSNAP {
        n.into_owned()
    } else {
        format!("{n}@{:x}", h.snap.0)
    }
}

/// Xattrs of an object (name -> value).
pub type Attrs = BTreeMap<Vec<u8>, Vec<u8>>;

/// What an EC read asks: `span` = logical bytes `[lo, hi)`, `stripes` = stripes `[s0, s1)` covering it, `srange` =
/// shard bytes when the read is shard-addressed (mode O RMW), `want_raw` = raw shards wanted.
pub(crate) struct ReadSpec {
    purpose: Purpose,
    soid: Hobject,
    span: (u64, u64),
    stripes: (u64, u64),
    srange: Option<(u64, u64)>,
    want_raw: Vec<usize>,
}

/// One stripe-span read of one object.
#[derive(Debug)]
pub(crate) struct EcRd {
    /// `EcPrim::reads` key (the wake token of a client read, [`crate::wake::ec_rd_tok`]).
    id: u64,
    purpose: Purpose,
    soid: Hobject,
    s0: u64,
    s1: u64,
    /// Logical byte range wanted (inside the stripes `[s0, s1)`).
    lo: u64,
    hi: u64,
    want_raw: Vec<usize>,
    avail: Vec<u32>,
    /// Shards served by a stray (spec missing-loc.md 6): shard -> OSD; every other shard comes from its member.
    src: BTreeMap<u32, i32>,
    plan: ecback::ReadPlan,
    /// Shard bytes as received (a reply buffer is kept as is: no copy before the assembly).
    got: BTreeMap<u32, Bytes>,
    failed: BTreeSet<u32>,
    /// Shards asked and not answered yet.
    pending: BTreeMap<u32, Asked>,
    /// A write on the object finished or was submitted meanwhile: the data may be old, never cache it.
    stale: bool,
    /// Shard byte range asked (mode O RMW: 4 KiB pages, not whole chunks); `None` = the plan's stripe span.
    srange: Option<(u64, u64)>,
    /// Our own shard's part is not resident yet (device reads submitted): retried by `ec_pump` after the store woke.
    own_wait: bool,
    own_held: HeldComplaint,
    /// Residency lease of the own-shard wait (0 = none): released after the local read or when the read ends.
    own_lease: u64,
    /// LAB: `wprof::lat_t0` when registered.
    t0: u64,
}

impl EcRd {
    /// Shard range `(off, len)` every planned shard is asked for (chunk size `c`).
    fn asked(&self, c: u64) -> (u64, u64) {
        self.srange
            .map_or_else(|| self.plan.shard_range(c), |(a, b)| (a, b - a))
    }
}

/// Shape every shard reply of a read must have (spec ec.md 10): exactly one extent at the asked shard offset `off`,
/// `len` bytes. Legacy shards (L0/L1) hold whole chunks of every stripe below the object end and clay repair helpers
/// send exactly the asked sub-chunks (`exact`). Mode O shards are sparse: a reply may end early, but only where a
/// shard file can end, on a 4 KiB boundary (ec-optimized.md 2.3); the rest is zero padded. Anything else (no or
/// several extents, misplaced, long, torn) is a damaged shard or a protocol fault and counts as a failed shard
/// (replanned around it, else EIO), never zero padded: wrong client data, and an RMW would re-encode parity from
/// the zeros.
#[derive(Debug, Clone, Copy)]
struct ReplyShape {
    off: u64,
    len: u64,
    exact: bool,
}

impl ReplyShape {
    /// Are `n` bytes at the asked offset a valid reply?
    fn fits(self, n: u64) -> bool {
        n == self.len || !self.exact && n < self.len && (self.off + n).is_multiple_of(PAGE)
    }
}

/// Decoded stripes of one object for the op layer (`ObjView::ov_read`).
#[derive(Debug)]
pub(crate) struct CacheEnt {
    soid: Hobject,
    /// Logical bytes `[lo, hi)`.
    lo: u64,
    hi: u64,
    data: Bytes,
    /// `crc32c(!0, data)` when known (fused into the assembly).
    crc: Option<u32>,
    /// A client read took the whole entry (its reply shares the bytes): dropped at the next `ec_wait`.
    taken: std::cell::Cell<bool>,
}

/// A sub-read in flight. No timer: it is given up only when a map shows its OSD down or restarted (spec missing-loc.md
/// 5, a location whose OSD went down is dropped); a new interval clears every read (`EcPrim` is reset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Asked {
    pub tid: u64,
    pub osd: i32,
    /// Map epoch the sub-read was sent in.
    pub epoch: u32,
}

/// Cap of the client read cache (bytes).
const CACHE_CAP: usize = 64 << 20;

/// Pages of the mode O extent cache per PG (4 KiB each; the PG lives on one core: no locks).
const XC_PAGES: usize = 64;
const PAGE: u64 = ec::geom::OPT_ALIGN;

/// Mode O extent cache: shard pages `(object, raw shard, offset)` as they are after every write generated so far
/// (generation runs in version order), oldest first. An RMW write at the front of the queue whose reads are all here
/// is generated at once, without shard reads and without waiting for the commit of the write before it (pipelined
/// appends and partial-stripe overwrites of one object). Every generated write puts the pages of the stripes it covers
/// partly (`OGenerated::pages`); pages of an object whose old content is moved / cut away (delete, truncate, clone)
/// are dropped; the whole cache goes with `EcPrim` at every interval start (rollback of uncommitted writes happens only
/// there). Independent of `ec_pdw` (that only chooses parity-delta reads).
#[derive(Debug, Default)]
pub(crate) struct XCache {
    pages: VecDeque<(Hobject, usize, u64, Vec<u8>)>,
}

impl XCache {
    fn find(&self, soid: &Hobject, raw: usize, off: u64) -> Option<usize> {
        self.pages
            .iter()
            .rposition(|p| p.2 == off && p.1 == raw && p.0 == *soid)
    }
    fn pages_of(ext: &ecback::Ext) -> impl Iterator<Item = u64> + '_ {
        ext.iter()
            .flat_map(|(a, b)| (a / PAGE * PAGE..b).step_by(PAGE as usize))
    }
    fn covers(&self, soid: &Hobject, raw: usize, ext: &ecback::Ext) -> bool {
        Self::pages_of(ext).all(|p| self.find(soid, raw, p).is_some())
    }
    /// Bytes of `ext` (gaps zero) as `(first offset, buffer)`; the pages become most recent.
    fn take(&mut self, soid: &Hobject, raw: usize, ext: &ecback::Ext) -> (u64, Vec<u8>) {
        let (lo, hi) = (ext.first().unwrap_or(0), ext.last_end().unwrap_or(0));
        let mut buf = vec![0u8; (hi - lo) as usize];
        for p in Self::pages_of(ext) {
            if let Some(i) = self.find(soid, raw, p)
                && let Some(e) = self.pages.remove(i)
            {
                let (a, b) = (p.max(lo), (p + PAGE).min(hi));
                buf[(a - lo) as usize..(b - lo) as usize]
                    .copy_from_slice(&e.3[(a - p) as usize..(b - p) as usize]);
                self.pages.push_back(e);
            }
        }
        (lo, buf)
    }
    fn put(&mut self, soid: &Hobject, raw: usize, off: u64, data: Vec<u8>) {
        if let Some(i) = self.find(soid, raw, off) {
            self.pages.remove(i);
        }
        self.pages.push_back((soid.clone(), raw, off, data));
        while self.pages.len() > XC_PAGES {
            self.pages.pop_front();
        }
    }
    fn drop_obj(&mut self, soid: &Hobject) {
        self.pages.retain(|p| p.0 != *soid);
    }
}

/// EC primary state (cleared at every interval start).
#[derive(Debug, Default)]
pub(crate) struct EcPrim {
    /// Last version handed out to a write (`>= log.head`).
    pub reserved: Eversion,
    writes: VecDeque<EcWrite>,
    /// Submitted writes not yet completed (committed on all shards).
    uncommitted: BTreeSet<u64>,
    #[cfg(test)]
    pub(crate) completion_object_visits: usize,
    by_obj: BTreeMap<Hobject, BTreeSet<u64>>,
    /// State of objects with uncommitted writes (the plan of the next write starts from it).
    proj: BTreeMap<Hobject, OldObj>,
    reads: BTreeMap<u64, EcRd>,
    next_rd: u64,
    /// Sub-read tid -> read id.
    rd_tids: BTreeMap<u64, u64>,
    /// Dummy roll-forward sub-writes in flight (replies are not for a write).
    dummies: BTreeSet<u64>,
    /// Client read cache, oldest first.
    cache: VecDeque<CacheEnt>,
    cache_bytes: usize,
    /// Entries a read consumed whole (`CacheEnt::taken`): dropped at the next `ec_wait` (memory back at once, short scans).
    taken: std::cell::Cell<usize>,
    /// Objects whose client read failed for good, with the wake generation that announced the failure (`None` = not
    /// announced yet, [`Pg::ep_take_wake`]): the ops parked on that read get EIO when they run; once the op layer ran
    /// them the entry goes ([`Pg::ec_read_errors_delivered`]), so every later op asks the shards again (classic
    /// evaluates each op on its own; a transient failure never sticks).
    rd_err: BTreeMap<Hobject, Option<u64>>,
    /// Client reads ([`crate::wake::ec_rd_tok`]) and objects with a write ([`crate::wake::ec_tok`]) that finished since
    /// the last [`Pg::ep_take_wake`]: the ops parked on them may run.
    woke: crate::wake::WakeSet,
    /// Recovery as primary (`ecrec`).
    pub recov: crate::ecrec::EcRecov,
    /// Statistics.
    pub rmw_reads: u64,
    /// Legacy RMW reads that skipped data chunks the write overwrites whole (`write_cover`).
    pub rmw_partial: u64,
    pub degraded_reads: u64,
    /// Clay sub-chunk repair reads started (recovery).
    pub repair_reads: u64,
    /// Mode O: the first write of this interval was generated (`first_write_in_interval` consumed, wgen 8).
    opt_first_done: bool,
    /// Mode O: members that got a non-empty transaction since their last roll-forward (dummy op targets, spec 4.5).
    pending_rf: BTreeSet<PgShard>,
    /// Mode O: the next sub-write cycle goes to every member (log-only entries, wgen 8 `next_write_all_shards`).
    pub next_write_all: bool,
    /// Mode O extent cache.
    xc: XCache,
    /// Statistics: writes generated with PDW / RMW writes served by the extent cache.
    pub pdw_writes: u64,
    pub xc_hits: u64,
    /// Some write / read of ours waits for its own shard's blocks (device reads in flight): `retry_repops` pumps after a store wake.
    pub store_wait: bool,
    /// Warm sub-reads in flight (`ec_warm_unread`): tid -> target; their replies are dropped, a gone target forgets them.
    warm_tids: BTreeMap<u64, Asked>,
    /// Map epoch the sources of the sub-reads in flight were last checked against (`ec_tick`).
    src_epoch: u32,
    /// Statistics: warm sub-reads sent.
    pub warm_reads: u64,
    /// Adaptive idle roll-forward (adr 0160 am. 3): client write submit time of the last write, EWMA of the gaps (ns, 0 =
    /// none yet), deadline of a deferred dummy (0 = none). Statistics: dummy rounds sent / deferred rounds the next write
    /// carried.
    last_submit: Mono,
    gap_ewma: u64,
    rf_due: Mono,
    pub rf_dummies: u64,
    pub rf_piggy: u64,
}

impl EcPrim {
    /// Forget the cached stripes of `soid` (its content changed outside a write: `mark_unfound_lost`).
    pub(crate) fn xc_drop_obj(&mut self, soid: &Hobject) {
        self.xc.drop_obj(soid);
    }

    /// Tid of the oldest write not generated yet.
    pub(crate) fn front_tid(&self) -> Option<u64> {
        self.writes.front().map(|w| w.tid)
    }
}

/// A generated shard transaction: shared payloads (wire rope + local skeleton over the encoded shard buffers, no payload
/// copy).
type ShardTx = std::sync::Arc<ecback::SharedTxn>;

fn neg(e: i32) -> i32 {
    -e.abs()
}

impl Pg {
    /// Geometry + code of this pool when the primary role may run.
    pub(crate) fn ecb(&self) -> Option<&std::sync::Arc<ecback::Backend>> {
        self.ecb.as_ref().map(|(_, b)| b)
    }

    /// (Re)build the backend after the pool's EC facts changed.
    pub(crate) fn refresh_ecb(&mut self) {
        let Some(info) = self.pool.ec.as_ref().filter(|e| e.supported) else {
            self.ecb = None;
            return;
        };
        if self.ecb.as_ref().is_some_and(|(i, _)| i == info) {
            return;
        }
        let sizes = (info.stripe_width, info.chunk_size);
        let be = if info.profile.is_empty() {
            ecback::Backend::from_parts(
                &info.plugin,
                &info.technique,
                (info.k, info.m),
                sizes,
                info.chunk_mapping.clone(),
                info.overwrites,
            )
        } else {
            ecback::Backend::from_profile(
                &info.profile,
                sizes,
                info.chunk_mapping.clone(),
                info.overwrites,
            )
        };
        // legacy pools: classic literal index sequence of a non-identity mapping (spec ec-parity.md 3.4)
        let literal =
            ec::gate::literal_placement(&info.plugin, info.optimized, &info.chunk_mapping);
        let be = be.and_then(|b| b.literal_placement(literal));
        self.ecb = be.map(|mut b| {
            b.omap = info.omap;
            (info.clone(), std::sync::Arc::new(b))
        });
    }

    /// May this OSD lead the PG as an EC primary (pool served, role enabled, code available)?
    pub(crate) fn ec_may_lead(&self) -> bool {
        // A nonprimary shard never leads (spec 9.1). The role switches count as latched at the interval start.
        let np = self.ec_np_shard();
        // clay shard-only profiles (ec-clay.md 0.6) never lead
        let prim_ok = self.pool.ec.as_ref().is_none_or(|e| e.primary_ok);
        self.ec_lead_cfg && self.pool.is_erasure && self.ecb.is_some() && !np && prim_ok
    }

    /// Does this instance send primary-side EC messages (queries, leases, pushes, pulls, scans, sub-ops, scrub and
    /// reservation requests)? Only as the acting primary that may lead ([`Self::ec_may_lead`]: role switches latched at
    /// the interval start, no nonprimary shard, no shard-only profile, code available). The outbound role filter of
    /// `PgSet::collect` (adr 0039 point 5) keys on this, never on the global `ec_enable_primary`.
    pub(crate) fn ec_leads(&self) -> bool {
        self.is_primary() && self.ec_may_lead()
    }

    /// Is our shard a nonprimary shard of an optimized pool (spec 9.1)?
    pub(crate) fn ec_np_shard(&self) -> bool {
        self.pool
            .ec
            .as_ref()
            .is_some_and(|e| e.is_nonprimary(self.my_shard()))
    }

    /// The role switches as configured NOW: `ec_primary`, and for optimized pools (adr 0067) `ec_opt_primary` too (the
    /// legacy primary pipeline must never run on them).
    pub(crate) fn ec_lead_cfg_now(&self) -> bool {
        let opt_ok = self
            .pool
            .ec
            .as_ref()
            .is_none_or(|e| !e.optimized || self.cfg.ec_opt_primary);
        self.cfg.ec_primary && opt_ok
    }

    /// A role switch went off at runtime while we lead this EC PG (adr 0067 am. 4.4): the current interval keeps
    /// working (latched), and a new interval is requested the way `ceph pg repeer` makes one (pg_temp = only us, at our
    /// shard position): its primary_start refuses the role and clears that pg_temp again (`ec_refused_clear_temp`).
    pub(crate) fn ec_lead_switch_off(&mut self) {
        if !self.pool.is_erasure
            || !self.ec_lead_cfg
            || self.ec_lead_cfg_now()
            || !matches!(self.st, St::Primary(crate::pg::PSt::Active(_)))
            || self.prim.pending_temp.is_some()
        {
            return;
        }
        let me = self.my_shard() as usize;
        let mut want = vec![pgwire::NONE_OSD; self.pool.size as usize];
        let Some(w) = want.get_mut(me) else {
            return;
        };
        *w = self.me.osd;
        self.notes.push(format!(
            "pg {}: EC primary role switched off at runtime: requesting a new interval (pg_temp {want:?})",
            self.spg
        ));
        self.request_pg_temp(want);
    }

    /// A role switch went ON at runtime while a PG led here sits refused for it (frozen, INCOMPLETE): request a new
    /// interval like `ec_lead_switch_off` does (pg_temp = only us at our shard position); its primary_start lifts the
    /// refusal. Without it the PG stays frozen until the OSD restarts.
    pub(crate) fn ec_lead_switch_on(&mut self) {
        let role_refused = matches!(
            self.refuse,
            Some(r) if r == crate::primary::REFUSE_OPT_ROLE || r == crate::primary::REFUSE_EC_ROLE
        );
        if !role_refused
            || !self.pool.is_erasure
            || self.ec_lead_cfg
            || !self.ec_lead_cfg_now()
            || !matches!(self.st, St::Primary(_))
            || self.prim.pending_temp.is_some()
            || self.ecb.is_none()
            || self
                .pool
                .ec
                .as_ref()
                .is_some_and(|e| e.is_nonprimary(self.my_shard()) || !e.primary_ok)
        {
            return;
        }
        let me = self.my_shard() as usize;
        let mut want = vec![pgwire::NONE_OSD; self.pool.size as usize];
        let Some(w) = want.get_mut(me) else {
            return;
        };
        *w = self.me.osd;
        self.notes.push(format!(
            "pg {}: EC primary role switched on at runtime: requesting a new interval (pg_temp {want:?})",
            self.spg
        ));
        self.request_pg_temp(want);
    }

    /// primary_start refused the role because a switch is off: a pg_temp in force (our own repeer request, or an older
    /// one) is cleared, so the PG ends up as it would after a start with the switch off (acting = up).
    pub(crate) fn ec_refused_clear_temp(&mut self) {
        if self.pool.is_erasure
            && !self.ec_lead_cfg
            && self.acting != self.up
            && !self
                .pool
                .ec
                .as_ref()
                .is_some_and(|e| e.is_nonprimary(self.my_shard()))
        {
            self.request_pg_temp(vec![]);
        }
    }

    /// Our shard as `u32` (EC PGs only).
    pub(crate) fn my_shard(&self) -> u32 {
        self.me.shard.0.max(0) as u32
    }

    /// Rollback geometry of PEER `p` (its shard): what its replica role does with divergent entries.
    /// Mode O nonprimary shard (raw 1..k-1): sparse log, never authoritative, never leads.
    pub(crate) fn is_np_shard(&self, p: PgShard) -> bool {
        self.pool.ec.as_ref().is_some_and(|e| {
            e.supported && e.optimized && p.shard.0 >= 0 && e.is_nonprimary(p.shard.0 as u32)
        })
    }

    /// Mode O GET-LOG pass (prim spec C.1/C.2): the shard whose log GetLog fetches. The oldest of ALL shards
    /// (nonprimary included: its log decides which partial writes are divergent, C.3); `auth` when not optimized, when
    /// the pass finds nothing, or when the nonprimary log cannot be merged safely (its tail or head before our tail: a
    /// sparse log must never extend ours backwards). Our log behind `auth` with a nonprimary pick = repeat GetLog.
    pub(crate) fn ec_get_log_shard(
        &self,
        infos: &BTreeMap<PgShard, &PgInfo>,
        restrict: bool,
        auth: PgShard,
    ) -> (PgShard, bool) {
        if !self.ec_opt() {
            return (auth, false);
        }
        let Some(g) = self.find_best_info(infos, restrict, true, false) else {
            return (auth, false);
        };
        if g == auth || !self.is_np_shard(g) {
            return (g, false);
        }
        let gi = infos[&g];
        let tail = self.log.tail();
        // no overlap with our log: nothing to decide from it. A tail BEFORE ours is fine (partial writes skipped that shard,
        // its trim lags): `got_log` cuts it at our tail (OQ 45: falling back to our own log skipped the keep rule and kept
        // entries only this primary held)
        if gi.last_update < tail {
            return (auth, false);
        }
        if self.info.last_update < infos[&auth].last_update {
            return (auth, !self.prim.repeated_getlog);
        }
        (g, false)
    }

    /// Primary side of `update_peer_info` (prim spec B.3): merge the pwlc a primary-capable peer reports, then raise
    /// every nonprimary peer's info by our pwlc entry for its shard (partial writes that skipped it).
    pub(crate) fn ec_prim_update_peer_pwlc(&mut self, from: PgShard, oinfo: &PgInfo) {
        if !self.ec_opt() {
            return;
        }
        let np = self.is_np_shard(from);
        if crate::ecopt::merge_pwlc(&mut self.info, oinfo, np) {
            self.info_dirty = true;
        }
        let pwlc = self.info.partial_writes_last_complete.clone();
        let head = self.log.head();
        for (p, pi) in self.prim.peer_info.iter_mut() {
            if let Some(&w) = pwlc.get(&p.shard)
                && w.1 <= head
            {
                crate::ecopt::apply_pwlc(w, pi, None);
            }
        }
    }

    /// Mode O `proc_master_log` keep rule (prim spec C.3) before the merge with the log of `from` (head `ohead` after
    /// pwlc, newest entry `olast`), see [`crate::ecopt::keep_partial_writes`]: returns the last kept entry; the caller
    /// advances the head it merges to it.
    pub(crate) fn ec_keep_partial(
        &mut self,
        from: PgShard,
        ohead: Eversion,
        olast: Option<Eversion>,
    ) -> Option<LogEntry> {
        let ctx = self.ec_ctx().filter(|c| c.opt)?;
        if ohead >= self.log.head() || from.shard.0 < 0 {
            return None;
        }
        let infos: Vec<(i8, PgInfo)> = self
            .all_infos()
            .into_iter()
            .map(|(p, i)| (p.shard.0, i.clone()))
            .collect();
        let tail = self.log.tail();
        let j = crate::ecopt::keep_partial_writes(
            &self.log.log.log,
            tail,
            &mut self.info,
            &ctx,
            (from.shard.0 as u32, ohead, olast),
            &infos,
        )?;
        self.info_dirty = true;
        Some(self.log.log.log[j].clone())
    }

    pub(crate) fn ec_peer_ctx(&self, p: PgShard) -> Option<crate::ecroll::EcCtx> {
        let e = self.pool.ec.as_ref().filter(|e| e.supported)?;
        if p.shard.0 < 0 {
            return None;
        }
        Some(crate::ecroll::EcCtx::of(e, p.shard.0 as u32))
    }

    /// Next version for the op layer: pipelined writes already reserved theirs.
    pub(crate) fn ec_next_version(&self) -> Eversion {
        let head = self.log.head().max(self.ep.reserved);
        Eversion::new(self.map.epoch(), head.version + 1)
    }

    // ---- shard identity ---------------------------------------------------------------------------------------

    /// `PgShard` of `osd` in this PG: its position in `acting` (then `up`, then any peer we hold an info of) for EC
    /// pools, `NO_SHARD` for replicated pools (and for an EC OSD we cannot place: the choke point drops such a send).
    /// Our own OSD names the OTHER local instance (adr 0049 am. 1): a PG never addresses itself.
    pub(crate) fn pshard(&self, osd: i32) -> PgShard {
        if !self.pool.is_erasure {
            return ps(osd);
        }
        let me = self.me;
        let pos = |v: &[i32]| {
            (0..v.len()).position(|i| {
                v[i] == osd && osd >= 0 && !(osd == me.osd && i as i32 == i32::from(me.shard.0))
            })
        };
        let shard = pos(&self.acting)
            .or_else(|| pos(&self.up))
            .map(|i| denc::types::ShardId(i as i8))
            .or_else(|| {
                self.prim
                    .peer_info
                    .keys()
                    .chain(self.prim.prior.probe.iter())
                    .find(|p| p.osd == osd && **p != me)
                    .map(|p| p.shard)
            })
            .unwrap_or(denc::types::ShardId::NO_SHARD);
        PgShard { osd, shard }
    }

    // ---- peering: acting set of an EC PG (ec.md 9, calc_ec_acting) ---------------------------------------------------

    /// `choose_acting` for EC pools: positional `want` (shard i = acting position i, `NONE_OSD` holes), the OLDEST
    /// complete member is authoritative (the others roll back to it), up members that are incomplete or too far
    /// behind become backfill targets, recoverable = at least k shards.
    pub(crate) fn choose_acting_ec(&mut self, restrict: bool, only_temp: bool) -> Chosen {
        use pgwire::NONE_OSD;
        let infos = self.all_infos();
        let Some(auth) = self.find_best_info(&infos, restrict, true, true) else {
            return self.no_auth_acting();
        };
        let ai = infos[&auth];
        let size = self.pool.size as usize;
        let k = self.ecb().map_or(self.pool.ec_k as usize, |b| b.k);
        let mut want = vec![NONE_OSD; size];
        let mut acting_backfill: BTreeSet<PgShard> = BTreeSet::new();
        let mut backfill: BTreeSet<PgShard> = BTreeSet::new();
        let mut usable = 0usize;
        let ok = |i: &PgInfo| !i.is_incomplete() && i.last_update >= ai.log_tail;
        let valid = |o: Option<&i32>| o.copied().filter(|o| *o != NONE_OSD && *o >= 0);
        for (i, w) in want.iter_mut().enumerate() {
            let shard = denc::types::ShardId(i as i8);
            if let Some(o) = valid(self.up.get(i)) {
                let ss = PgShard { osd: o, shard };
                if infos.get(&ss).is_some_and(|x| ok(x)) {
                    *w = o;
                    acting_backfill.insert(ss);
                    usable += 1;
                    continue;
                }
                // an up member that cannot be caught up from the log is backfilled (in acting_recovery_backfill, not in want)
                backfill.insert(ss);
                acting_backfill.insert(ss);
            }
            if let Some(o) = valid(self.acting.get(i)) {
                let ss = PgShard { osd: o, shard };
                if !backfill.contains(&ss) && infos.get(&ss).is_some_and(|x| ok(x)) {
                    *w = o;
                    acting_backfill.insert(ss);
                    usable += 1;
                    continue;
                }
            }
            if !restrict {
                // any other member that holds this shard position with a usable log
                let mut best: Option<(Eversion, PgShard)> = None;
                for (p, x) in &infos {
                    if p.shard == shard
                        && *p != self.me
                        && self.map.is_up(p.osd)
                        && ok(x)
                        && !backfill.contains(p)
                        && best.is_none_or(|(lu, _)| x.last_update > lu)
                    {
                        best = Some((x.last_update, *p));
                    }
                }
                if let Some((_, p)) = best {
                    *w = p.osd;
                    acting_backfill.insert(p);
                    usable += 1;
                }
            }
        }
        if usable < k || !self.ec_want_recoverable(&want) {
            self.prim.want_acting.clear();
            return Chosen::Incomplete;
        }
        let async_set = self.ec_choose_async(&infos, ai, &mut want);
        if want != self.acting {
            return self.need_acting_change(want);
        }
        if only_temp {
            return Chosen::Ok;
        }
        let (log_shard, repeat) = self.ec_get_log_shard(&infos, restrict, auth);
        if self.cfg.ec_trace {
            let iv: Vec<String> = infos
                .iter()
                .map(|(p, i)| {
                    format!(
                        "{}/{}:{}/les{}",
                        p.osd, p.shard.0, i.last_update, i.last_epoch_started
                    )
                })
                .collect();
            let t = format!(
                "choose_acting auth {}/{} getlog {}/{} repeat {repeat} infos [{}] pwlc {:?}",
                auth.osd,
                auth.shard.0,
                log_shard.osd,
                log_shard.shard.0,
                iv.join(" "),
                self.info.partial_writes_last_complete
            );
            self.ec_trace(|| t);
        }
        self.prim.want_acting.clear();
        self.prim.auth_shard = Some(auth);
        self.prim.log_shard = Some(log_shard);
        self.prim.repeat_getlog = repeat;
        self.prim.acting_recovery_backfill = acting_backfill;
        self.prim.backfill_targets = backfill;
        self.prim.async_recovery_targets = async_set;
        Chosen::Ok
    }

    /// `recoverable(want)` of an EC PG (ec.md 9.4): at least min_size members unless `osd_allow_recovery_below_min_size`,
    /// and the code's own predicate over the member shards (non-MDS codes such as shec / lrc: k shards are necessary, not
    /// sufficient).
    fn ec_want_recoverable(&self, want: &[i32]) -> bool {
        let shards: Vec<u32> = want
            .iter()
            .enumerate()
            .filter(|(_, o)| **o != pgwire::NONE_OSD && **o >= 0)
            .map(|(i, _)| i as u32)
            .collect();
        (self.cfg.allow_recovery_below_min_size || shards.len() >= self.pool.min_size as usize)
            && self.ecb().is_none_or(|b| b.recoverable(&shards))
    }

    /// EC async recovery (ec.md 9.5): an up member whose shard is more than `osd_async_recovery_min_cost` behind the
    /// authoritative shard (its missing count plus the version distance; a shard past auth costs nothing, it rolls back
    /// locally) leaves `want` as a hole while the PG keeps min_size members and stays recoverable. It stays in
    /// acting_recovery_backfill (log-only sub-writes for objects it misses) and is recovered while the PG serves IO
    /// without it; the end of recovery takes it back (`Recovered`: pg_temp cleared). Highest cost first, ties by the
    /// larger (osd, shard); the member count drops for every candidate looked at, taken out or not. A classic primary of
    /// the same PG makes exactly this choice: any difference and the two primaries undo each other's pg_temp every epoch.
    fn ec_choose_async(
        &self,
        infos: &BTreeMap<PgShard, &PgInfo>,
        auth: &PgInfo,
        want: &mut Vec<i32>,
    ) -> BTreeSet<PgShard> {
        use pgwire::NONE_OSD;
        let mut members = want.iter().filter(|o| **o != NONE_OSD && **o >= 0).count();
        let mut cands: Vec<(u64, PgShard)> = Vec::new();
        for (i, &o) in want.iter().enumerate() {
            // only an up member at its own position: any other member taken out of acting would become a stray
            if o == NONE_OSD || o < 0 || self.up.get(i) != Some(&o) {
                continue;
            }
            let p = PgShard {
                osd: o,
                shard: denc::types::ShardId(i as i8),
            };
            let Some(pi) = infos.get(&p) else {
                continue;
            };
            let cost = pi.stats.stats.sum.num_objects_missing.max(0) as u64
                + auth
                    .last_update
                    .version
                    .saturating_sub(pi.last_update.version);
            if cost > self.cfg.async_recovery_min_cost {
                cands.push((cost, p));
            }
        }
        cands.sort_unstable();
        let mut out = BTreeSet::new();
        for (_, p) in cands.into_iter().rev() {
            members -= 1;
            let mut cand = want.clone();
            cand[p.shard.0 as usize] = NONE_OSD;
            if members >= self.pool.min_size as usize && self.ec_want_recoverable(&cand) {
                *want = cand;
                out.insert(p);
            }
        }
        out
    }

    // ---- recovery / backfill (B7: decode + push); until then the PG stays degraded and never pushes ------------------

    // ---- availability ------------------------------------------------------------------------------------------

    /// Shards that hold a current copy of `soid` (ec.md 10: acting, not missing it, backfill targets only below their
    /// cursor).
    pub(crate) fn ec_avail(&self, soid: &Hobject) -> Vec<u32> {
        let mut v: Vec<u32> = self
            .prim
            .acting_recovery_backfill
            .iter()
            .filter(|p| self.ec_member_has(p, soid))
            .map(|p| p.shard.0 as u32)
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// Member `p` holds a current copy of `soid` (see [`Self::ec_avail`]).
    pub(crate) fn ec_member_has(&self, p: &PgShard, soid: &Hobject) -> bool {
        if p.shard.0 < 0 || !self.map.is_up(p.osd) {
            return false;
        }
        if *p == self.me {
            return !self.missing.contains(soid);
        }
        !self
            .prim
            .peer_missing
            .get(p)
            .is_some_and(|m| m.contains(soid))
            && (!self.prim.backfill_targets.contains(p) || self.backfill_target_has_range(p, soid))
    }

    /// The OSD to read shard `sh` of `soid` from: the member at that position that holds a current copy. Two members can
    /// carry the same shard id (an acting member and a backfill target of its position): the target holds stale bytes
    /// beyond its cursor, a missing member an older version, and a shard serves whatever it has (no version check).
    pub(crate) fn ec_osd_holding(&self, soid: &Hobject, sh: u32) -> Option<i32> {
        self.prim
            .acting_recovery_backfill
            .iter()
            .find(|p| {
                p.shard.0 == sh as i8
                    && p.osd != pgwire::NONE_OSD
                    && p.osd >= 0
                    && self.ec_member_has(p, soid)
            })
            .map(|p| p.osd)
    }

    /// Read sources of `soid`: the member shards ([`Self::ec_avail`]) plus the shards strays serve ([`Self::ec_stray_src`]).
    pub(crate) fn ec_sources(&self, soid: &Hobject) -> (Vec<u32>, BTreeMap<u32, i32>) {
        let mut avail = self.ec_avail(soid);
        let src = self.ec_stray_src(soid, &avail);
        avail.extend(src.keys().copied());
        avail.sort_unstable();
        (avail, src)
    }

    // ---- write pipeline ----------------------------------------------------------------------------------------

    /// Old state of `soid` for a plan: the projection of an in-flight write, else the committed local shard.
    fn ec_old_obj(&self, soid: &Hobject, store: &impl PgStoreOps) -> Result<OldObj, i32> {
        if let Some(p) = self.ep.proj.get(soid) {
            return Ok(p.clone());
        }
        match store.ec_getattrs(self.spg, soid) {
            Err(e) if e.abs() == 2 => Ok(OldObj::default()),
            Err(e) => Err(e.abs()),
            Ok(attrs) => {
                let size = match attrs.get(b"_".as_slice()) {
                    Some(b) => {
                        denc::from_slice::<replwire::ObjectInfo>(b)
                            .map_err(|_| EIO)?
                            .size
                    }
                    None => return Err(EIO),
                };
                Ok(OldObj {
                    exists: true,
                    size,
                    attrs,
                })
            }
        }
    }

    /// `submit_write` of an EC pool (the checks of the replicated path ran already).
    pub(crate) fn ec_submit_write(
        &mut self,
        w: crate::WriteReq,
        store: &impl PgStoreOps,
    ) -> Result<u64, crate::WriteErr> {
        let _s = wprof::span(wprof::S::EcPlan);
        // write gap EWMA (1/8) for the adaptive idle roll-forward; gaps above 1 s count as 1 s
        let now = self.now;
        if self.ep.last_submit != 0 {
            let gap = now.saturating_sub(self.ep.last_submit).min(SEC);
            self.ep.gap_ewma = if self.ep.gap_ewma == 0 {
                gap
            } else {
                self.ep.gap_ewma - self.ep.gap_ewma / 8 + gap / 8
            };
        }
        self.ep.last_submit = now.max(1);
        let be = self.ecb().cloned().ok_or(crate::WriteErr::NotActive)?;
        let epoch = self.map.epoch();
        let mut v = self.log.head().max(self.ep.reserved);
        let mut versions = Vec::with_capacity(w.entries.len());
        let mut vmap: BTreeMap<Hobject, u64> = BTreeMap::new();
        for we in &w.entries {
            v = Eversion::new(epoch, v.version + 1);
            versions.push(v);
            if we.op != LogOp::ERROR {
                vmap.insert(we.soid.clone(), v.version);
            }
        }
        let t = if w.txn_refs.is_empty() {
            Transaction::decode(&w.txn_middle, &w.txn_data, self.cfg.page)
        } else {
            Transaction::decode_split(&w.txn_data, &w.txn_refs, self.cfg.page)
        }
        .map_err(|_| crate::WriteErr::TooBig(22))?;
        let cover = if self.ec_opt() { None } else { write_cover(&t) };
        let mut olds: BTreeMap<Hobject, OldObj> = BTreeMap::new();
        for g in &t.objs {
            if g.generation != denc::types::Ghobject::NO_GEN {
                return Err(crate::WriteErr::TooBig(22));
            }
            if !olds.contains_key(&g.hobj) {
                let o = self
                    .ec_old_obj(&g.hobj, store)
                    .map_err(crate::WriteErr::TooBig)?;
                olds.insert(g.hobj.clone(), o);
            }
        }
        if !w.txn_middle.is_empty() {
            return Err(crate::WriteErr::TooBig(22));
        }
        let txn = w.txn_data.clone();
        let plan = if self.ec_opt() {
            let members = self.ec_member_shards();
            let mut p = be
                .plan_write_o_txn(
                    self.spg.pgid,
                    &t,
                    if w.txn_refs.is_empty() {
                        core::slice::from_ref(&txn)
                    } else {
                        &w.txn_refs
                    },
                    &olds,
                    &vmap,
                    OCtx {
                        members: &members,
                        first_write: !self.ep.opt_first_done,
                    },
                )
                .map_err(crate::WriteErr::TooBig)?;
            if p.consumed_first_write {
                self.ep.opt_first_done = true;
            }
            let mode = self.cfg.ec_pdw;
            if mode != PdwMode::Never {
                // S5: parity-delta choice (reads only; shard output identical). The readable shards depend on the object
                // alone: one set per object of the plan, not one walk per (object, shard) the chooser looks at.
                let avail: BTreeMap<Hobject, Vec<u32>> = p
                    .objects()
                    .into_iter()
                    .map(|o| {
                        let v = self.ec_avail(&o);
                        (o, v)
                    })
                    .collect();
                let ep = &self.ep;
                let n = p.select_pdw(
                    mode,
                    |o, sh| avail.get(o).is_some_and(|v| v.contains(&sh)),
                    |o, r, e| ep.xc.covers(o, r, e),
                );
                self.ep.pdw_writes += n as u64;
            }
            Plan::O(p)
        } else {
            Plan::L(
                if w.txn_refs.is_empty() {
                    be.plan_write_shared(self.spg.pgid, &txn, &olds, &vmap)
                } else {
                    be.plan_write_split(self.spg.pgid, &txn, &w.txn_refs, &olds, &vmap)
                }
                .map_err(crate::WriteErr::TooBig)?,
            )
        };
        let own = match &plan {
            Plan::O(p) => be
                .mapping
                .iter()
                .position(|s| *s == self.my_shard())
                .map(|r| p.stash_srcs(r))
                .unwrap_or_default(),
            // legacy: the stripes read for the read-modify-write are the partly overwritten ones (their chunk is stashed)
            Plan::L(p) => p
                .reads()
                .into_iter()
                .map(|(o, st)| (o, st * be.c, be.c))
                .collect(),
        };
        self.write_tid += 1;
        let tid = self.write_tid;
        self.ep.reserved = v;
        let objects = plan.objects();
        for o in &objects {
            self.ec_invalidate(o);
        }
        let mut deps: BTreeSet<u64> = BTreeSet::new();
        for o in &objects {
            if let Some(s) = self.ep.by_obj.get(o) {
                deps.extend(s.iter().copied());
            }
        }
        for (o, p) in plan.post() {
            self.ep.proj.insert(o.clone(), p.into());
            self.ep.by_obj.entry(o).or_default().insert(tid);
        }
        self.ep.uncommitted.insert(tid);
        let mut to_read: Vec<(Hobject, u64, u64)> = Vec::new();
        let mut o_reads: Vec<(Hobject, u64, u64, Vec<usize>)> = Vec::new();
        match &plan {
            Plan::L(plan) => {
                // runs of consecutive stripes per object
                for (o, st) in plan.reads() {
                    match to_read.last_mut() {
                        Some((lo, s0, n)) if *lo == o && *s0 + *n == st => *n += 1,
                        _ => to_read.push((o, st, 1)),
                    }
                }
            }
            Plan::O(plan) => {
                // one read per object: the covering shard range of every raw shard it needs
                for (o, raw, ext) in plan.reads() {
                    let (a, b) = (ext.first().unwrap_or(0), ext.last_end().unwrap_or(0));
                    match o_reads.last_mut() {
                        Some((lo, x, y, raws)) if *lo == o => {
                            *x = (*x).min(a);
                            *y = (*y).max(b);
                            raws.push(raw);
                        }
                        _ => o_reads.push((o, a, b, vec![raw])),
                    }
                }
            }
        }
        let mds = plan.mod_descs();
        self.ep.writes.push_back(EcWrite {
            tid,
            reqid: w.reqid,
            entries: w.entries,
            versions,
            new_temp: w.new_temp,
            discard_temp: w.discard_temp,
            plan: Some(plan),
            mds,
            objects,
            deps: deps.into_iter().collect(),
            to_read,
            o_reads,
            old_o: BTreeMap::new(),
            reads_started: false,
            pending_reads: 0,
            old: BTreeMap::new(),
            failed: None,
            own,
            own_ready: false,
            own_held: HeldComplaint::default(),
            own_lease: 0,
            t0: wprof::lat_t0(),
            cover,
        });
        self.ec_pump(store);
        Ok(tid)
    }

    /// Is a write to an object in `[start, end)` not committed on every shard yet (queued, old stripes being read,
    /// sub-writes unacked)? `by_obj` holds each write from acceptance to `ec_forget`. A scrub chunk over it waits.
    pub(crate) fn ec_write_unacked_in(&self, start: &Hobject, end: &Hobject) -> bool {
        self.ep
            .by_obj
            .range::<Hobject, _>((Bound::Included(start), Bound::Unbounded))
            .next()
            .is_some_and(|(o, _)| end.max || o < end)
    }

    /// Start reads whose dependencies committed, generate ready writes in order.
    pub(crate) fn ec_pump(&mut self, store: &impl PgStoreOps) {
        if !self.ec_may_lead() {
            return;
        }
        self.ep.store_wait = false;
        self.ec_retry_own_reads(store);
        self.ec_xc_serve_front();
        // 1. reads
        let ready: Vec<u64> = self
            .ep
            .writes
            .iter()
            .filter(|w| {
                !w.reads_started
                    && w.has_reads()
                    && w.failed.is_none()
                    && w.deps.iter().all(|d| !self.ep.uncommitted.contains(d))
            })
            .map(|w| w.tid)
            .collect();
        for tid in ready {
            self.ec_start_reads(tid, store);
        }
        // 2. generate in version order
        while let Some(front) = self.ep.writes.front() {
            let front_tid = front.tid;
            // a marking submitted before this write goes first (mark_unfound_lost, version order)
            self.lost_generate_due(Some(front_tid));
            let Some(front) = self.ep.writes.front() else {
                break;
            };
            let done = front.failed.is_some()
                || (!front.has_reads() || (front.reads_started && front.pending_reads == 0));
            if !done {
                break;
            }
            // the stash of our own shard reads old blocks: have them resident, never wait for the device inside the apply
            if front.failed.is_none() && !self.ec_own_ready(store) {
                self.ep.store_wait = true;
                break;
            }
            let w = self.ep.writes.pop_front().unwrap();
            let lease = w.own_lease;
            self.ec_generate(w, store);
            self.lease_release(store, lease); // the stash read its blocks in the apply
            self.ec_xc_serve_front();
        }
        let front = self.ep.front_tid();
        self.lost_generate_due(front);
    }

    /// S5 counters of this interval: (writes generated with PDW, RMW writes served by the extent cache).
    /// Clay sub-chunk repair reads this PG instance started.
    pub fn ec_repair_reads(&self) -> u64 {
        self.ep.repair_reads
    }

    /// Idle roll-forward rounds: (dummy rounds sent, deferred rounds a write carried) (adr 0160 am. 3).
    pub fn ec_rf_stats(&self) -> (u64, u64) {
        (self.ep.rf_dummies, self.ep.rf_piggy)
    }

    /// Warm sub-reads (`ec_warm_unread`) this PG instance sent.
    pub fn ec_warm_reads(&self) -> u64 {
        self.ep.warm_reads
    }

    /// RMW shard reads started (legacy stripe spans and mode O objects): (all, partial = legacy spans that skipped
    /// whole-overwritten chunks).
    pub fn ec_rmw_stats(&self) -> (u64, u64) {
        (self.ep.rmw_reads, self.ep.rmw_partial)
    }

    pub fn ec_pdw_stats(&self) -> (u64, u64) {
        (self.ep.pdw_writes, self.ep.xc_hits)
    }

    /// Extent cache: the front write (every write before it is generated, so the cache holds the state it is
    /// planned on) takes its RMW reads from the cache when all are there.
    fn ec_xc_serve_front(&mut self) {
        let ep = &mut self.ep;
        let Some(w) = ep.writes.front_mut() else {
            return;
        };
        if w.reads_started || w.failed.is_some() || !w.to_read.is_empty() || w.o_reads.is_empty() {
            return;
        }
        let Some(Plan::O(p)) = &w.plan else {
            return;
        };
        let reads = p.reads();
        if reads.is_empty() || !reads.iter().all(|(o, r, e)| ep.xc.covers(o, *r, e)) {
            return;
        }
        for (o, r, e) in reads {
            let got = ep.xc.take(&o, r, &e);
            w.old_o.insert((o, r), got);
        }
        w.reads_started = true;
        w.pending_reads = 0;
        ep.xc_hits += 1;
    }

    /// Are `[off, off+len)` of our shard object resident (tree path, then data blocks)? false = reads were submitted.
    pub(crate) fn ec_range_warm(
        &self,
        soid: &Hobject,
        off: u64,
        len: u64,
        store: &impl PgStoreOps,
    ) -> bool {
        store.warm(self.spg, soid, off, len) && store.warm_data(self.spg, soid, off, len)
    }

    /// [`Self::ec_range_warm`] for a stash source (`clone_range` to the same offset): tree path, then only the data the
    /// store copies (a range it shares needs none, adr 0021 am. 38).
    pub(crate) fn ec_stash_warm(
        &self,
        soid: &Hobject,
        off: u64,
        len: u64,
        store: &impl PgStoreOps,
    ) -> bool {
        store.warm(self.spg, soid, off, len) && store.warm_clone_src(self.spg, soid, off, len)
    }

    /// Own-shard blocks of the front write's stash resident (prefetch started on the first call)? The write waits until
    /// the device reads complete (store wakes and the timer ask again); a wait past `REPOP_HELD_COMPLAINT_NS` is reported
    /// loudly once per period, it never proceeds to a blocking read because time passed.
    fn ec_own_ready(&mut self, store: &impl PgStoreOps) -> bool {
        let Some(w) = self.ep.writes.front_mut() else {
            return true;
        };
        if w.own_ready || w.own.is_empty() {
            return true;
        }
        let (own, lease) = (std::mem::take(&mut w.own), w.own_lease);
        let ok = with_lease(store, lease, || {
            own.iter().fold(true, |ok, (o, off, len)| {
                ok & self.ec_stash_warm(o, *off, *len, store)
            })
        });
        // what the next probes load stays resident until the write generated (released in `ec_pump`)
        let open = (!ok && lease == 0).then(|| self.lease_open(store));
        let (now, spg) = (self.now, self.spg);
        let w = self.ep.writes.front_mut().expect("front");
        w.own = own;
        w.own_ready = ok;
        if !ok {
            if let Some(l) = open {
                w.own_lease = l;
            }
            w.own_held.hold(now);
            let tid = w.tid;
            w.own_held.warn(now, "ec own-shard prefetch", |secs| {
                format!("pg {spg}, write tid {tid} held {secs} s; still waiting")
            });
        }
        ok
    }

    /// Ask again the own-shard part of the reads that waited for resident blocks.
    fn ec_retry_own_reads(&mut self, store: &impl PgStoreOps) {
        let ids: Vec<u64> = self
            .ep
            .reads
            .iter()
            .filter(|(_, r)| r.own_wait)
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            if let Some(rd) = self.ep.reads.get_mut(&id) {
                rd.own_wait = false;
            }
            self.ec_rd_ask(id, store);
            self.ec_rd_check(id, store);
        }
    }

    fn ec_start_reads(&mut self, tid: u64, store: &impl PgStoreOps) {
        let _s = wprof::span(wprof::S::EcRead);
        let Some(w) = self.ep.writes.iter_mut().find(|w| w.tid == tid) else {
            return;
        };
        w.reads_started = true;
        let spans = w.to_read.clone();
        let o_spans = w.o_reads.clone();
        w.pending_reads = spans.len() + o_spans.len();
        let Some(be) = self.ecb().cloned() else {
            return;
        };
        let raw: Vec<usize> = (0..be.k).collect();
        // own stash source (a parity shard of ours is not read by the RMW): tree pages (and any data the store copies) now,
        // not after the read
        let own = self
            .ep
            .writes
            .iter()
            .find(|w| w.tid == tid)
            .map(|w| w.own.clone())
            .unwrap_or_default();
        for (o, off, len) in &own {
            let _ = self.ec_stash_warm(o, *off, *len, store);
        }
        for (soid, s0, n) in spans {
            self.ep.rmw_reads += 1;
            let want = self.ec_rmw_want(tid, &soid, s0, n, &raw);
            if want.len() < raw.len() {
                self.ep.rmw_partial += 1;
            }
            self.ec_warm_unread(&soid, (s0 * be.c, n * be.c), &want);
            if self
                .ec_read_begin(
                    Purpose::Rmw(tid),
                    soid,
                    (s0 * be.s, (s0 + n) * be.s),
                    want,
                    store,
                )
                .is_err()
                && let Some(w) = self.ep.writes.iter_mut().find(|w| w.tid == tid)
            {
                w.failed = Some(-EIO);
                w.pending_reads = w.pending_reads.saturating_sub(1);
            }
        }
        for (soid, lo, hi, raws) in o_spans {
            self.ep.rmw_reads += 1;
            if self
                .ec_read_begin_shard(Purpose::RmwO(tid), soid, (lo, hi), raws, store)
                .is_err()
                && let Some(w) = self.ep.writes.iter_mut().find(|w| w.tid == tid)
            {
                w.failed = Some(-EIO);
                w.pending_reads = w.pending_reads.saturating_sub(1);
            }
        }
    }

    /// Raw data shards the legacy RMW read of stripes `[s0, s0+n)` of `soid` needs: all but the chunks the write `tid`
    /// overwrites whole in every stripe of the span (`EcWrite::cover`); all of them unless every shard is up at its member.
    fn ec_rmw_want(&self, tid: u64, soid: &Hobject, s0: u64, n: u64, raw: &[usize]) -> Vec<usize> {
        let Some(be) = self.ecb() else {
            return raw.to_vec();
        };
        let Some(ranges) = self
            .ep
            .writes
            .iter()
            .find(|w| w.tid == tid)
            .and_then(|w| w.cover.as_ref())
            .and_then(|c| c.get(soid))
        else {
            return raw.to_vec();
        };
        let (avail, src) = self.ec_sources(soid);
        if !src.is_empty() || !be.mapping.iter().all(|s| avail.contains(s)) {
            return raw.to_vec();
        }
        let want: Vec<usize> = raw
            .iter()
            .copied()
            .filter(|&r| {
                (s0..s0 + n).any(|st| {
                    let a = st * be.s + r as u64 * be.c;
                    !covered(ranges, a, a + be.c)
                })
            })
            .collect();
        if want.is_empty() { raw.to_vec() } else { want }
    }

    /// Send one `MOSDECSubOpRead` of shard `sh` (`[off, off+len)` of `soid`, sub-chunk ranges `sub`) to `osd`. A
    /// recovery read (`recov`) carries the recovery message priority: a classic mclock shard schedules a read at or
    /// below the forced class as background work, anything above as immediate (spec replication.md 6.1).
    #[expect(clippy::too_many_arguments)]
    fn ec_send_subread(
        &mut self,
        osd: i32,
        sh: u32,
        tid: u64,
        (soid, off, len): (&Hobject, u64, u64),
        sub: Vec<(i32, i32)>,
        epoch: u32,
        recov: bool,
    ) {
        let mut op = ECSubRead {
            from: self.me,
            tid,
            ..Default::default()
        };
        op.to_read.insert(soid.clone(), vec![(off, len, 0)]);
        op.subchunks.insert(soid.clone(), sub);
        let m = MOSDECSubOpRead {
            pgid: denc::types::SpgT {
                pgid: self.spg.pgid,
                shard: denc::types::ShardId(sh as i8),
            },
            map_epoch: epoch,
            op,
            min_epoch: self.last_peering_reset,
            trace: [0; 3],
            cost: len,
        };
        let body = Body::Ec(ecwire::EcMsg::from(m));
        if recov {
            let prio = self.recovery_message_priority();
            self.send_prio(osd, body, tid, prio);
        } else {
            self.send(osd, body, tid);
        }
    }

    /// adr 0043 am. 5: the shards a legacy RMW read of shard bytes `[off, off+len)` does not ask (parity)
    /// stash the same blocks when the sub-write arrives: a sub-read now (reply dropped) loads them on an croit-flashstore-osd shard
    /// (its store caches the served run, `pf_retain`) in parallel with the read instead of one device read after it.
    /// Classic shards are never asked (their stash is a metadata clone); degraded reads warm nothing.
    fn ec_warm_unread(&mut self, soid: &Hobject, (off, len): (u64, u64), want_raw: &[usize]) {
        let Some(be) = self.ecb().cloned() else {
            return;
        };
        let (avail, src) = self.ec_sources(soid);
        let read: Vec<u32> = want_raw
            .iter()
            .filter_map(|r| be.mapping.get(*r).copied())
            .collect();
        if read.len() != want_raw.len() || !read.iter().all(|s| avail.contains(s)) {
            return;
        }
        let me = self.my_shard();
        let epoch = self.map.epoch();
        for sh in be.mapping.clone() {
            if sh == me || read.contains(&sh) || !avail.contains(&sh) || src.contains_key(&sh) {
                continue;
            }
            let Some(osd) = self.ec_osd_holding(soid, sh) else {
                continue;
            };
            if !self.nv_peers.contains(&osd) {
                continue;
            }
            self.write_tid += 1;
            let tid = self.write_tid;
            self.ep.warm_tids.insert(tid, Asked { tid, osd, epoch });
            self.ep.warm_reads += 1;
            let sub = vec![(0, be.sub_chunks() as i32)];
            self.ec_send_subread(osd, sh, tid, (soid, off, len), sub, epoch, false);
        }
    }

    /// Generate the shard transactions of the front write, log it, apply our own shard and fan out.
    fn ec_generate(&mut self, mut w: EcWrite, store: &impl PgStoreOps) {
        let _s = wprof::span(wprof::S::EcGen);
        let tid = w.tid;
        wprof::lat(4, w.t0);
        let fail = |this: &mut Pg, w: &EcWrite, r: i32| {
            this.ec_forget(tid, &w.objects);
            // the extent cache may hold pages of this write (filled at generation)
            for o in &w.objects {
                this.ep.xc.drop_obj(o);
            }
            // later writes planned on top of this one would commit on a state that never happened
            for q in this.ep.writes.iter_mut() {
                if q.deps.contains(&tid) && q.failed.is_none() {
                    q.failed = Some(r);
                }
            }
            this.out.push(Action::WriteDone {
                spg: this.spg,
                tid,
                version: w.versions.last().copied().unwrap_or_default(),
                result: r,
            });
        };
        if let Some(r) = w.failed {
            return fail(self, &w, r);
        }
        let Some(plan) = w.plan.take() else {
            return fail(self, &w, -EIO);
        };
        let mut written: BTreeMap<Hobject, pgwire::log::ShardIdSet> = BTreeMap::new();
        let txns: Vec<Option<ShardTx>> = match plan {
            // legacy: shard payloads shared with the encoded shard buffers (wire rope, local skeleton): no copy
            Plan::L(plan) => match plan.generate_shared(&w.old) {
                Ok(g) => g
                    .into_iter()
                    .map(|t| Some(std::sync::Arc::new(t)))
                    .collect(),
                Err(e) => return fail(self, &w, -e),
            },
            Plan::O(plan) => {
                written = plan.written();
                // a clone of a head with omap: the not-yet-rolled-forward records of the source ride on the clone entry
                let replay = match self.ec_omap_replay(&plan.clone_srcs()) {
                    Ok(r) => r,
                    Err(e) => return fail(self, &w, -e),
                };
                // local-only form for my shard unless another member holds the same shard id (a backfill / async
                // recovery target of my position): that one needs the wire form too (adr 0113 am. 4)
                let mine = self.my_shard();
                let shared = self
                    .prim
                    .acting_recovery_backfill
                    .iter()
                    .any(|p| *p != self.me && p.shard == self.me.shard);
                let local = (!shared).then_some(mine);
                match plan.generate_shared(&w.old_o, &replay, local) {
                    Ok(g) => {
                        w.mds = g.mds;
                        for (o, pages) in g.pages {
                            match pages {
                                None => self.ep.xc.drop_obj(&o),
                                Some(v) => {
                                    for (r, off, d) in v {
                                        self.ep.xc.put(&o, r, off, d);
                                    }
                                }
                            }
                        }
                        g.txns
                            .into_iter()
                            .map(|t| t.map(std::sync::Arc::new))
                            .collect()
                    }
                    Err(e) => return fail(self, &w, -e),
                }
            }
        };
        let epoch = self.map.epoch();
        // log entries (versions were reserved at submit)
        let mut entries: Vec<LogEntry> = Vec::new();
        for (we, v) in w.entries.iter().zip(&w.versions) {
            // prior_version 0'0 tells a divergent shard "the write created the object": classic (PGLog case 2) and our shard
            // role then REMOVE it instead of rolling back. An object whose entries left the log keeps its stored version.
            let prior = match self.write_entry_prior(&entries, we, store) {
                Ok(p) => p,
                Err(_) => {
                    self.error("ec write: local object_info unreadable, refused");
                    return fail(self, &w, -EIO);
                }
            };
            let mut e = crate::primary::log_entry_from_write(w.reqid, we, *v, prior);
            if we.op != LogOp::ERROR
                && let Some(md) = w.mds.get(&we.soid)
            {
                e.mod_desc = md.clone();
                if crate::snaps::is_clone(&we.soid)
                    && matches!(we.op, LogOp::MODIFY | LogOp::DELETE)
                {
                    // Snapshot trim mutates the mapper independently of shard attrs/data: record the old mapping
                    // FIRST, before the attr/delete records (ec.md 8.1). Clone creation needs none: a divergent CLONE
                    // is removed (plog case 2), which clears the mapping. The indexed log includes preceding generated
                    // writes whose mapper txn is still queued.
                    let old = entries
                        .iter()
                        .rev()
                        .find(|e| e.soid == we.soid)
                        .or_else(|| self.log.entry_for(&we.soid))
                        .and_then(crate::snaps::entry_op);
                    let mut snaps = match old {
                        Some(crate::snaps::MapOp::Set { snaps, .. }) => snaps,
                        Some(crate::snaps::MapOp::Remove { .. }) => Vec::new(),
                        None => match store.snapmap_get_checked(self.spg, &we.soid) {
                            Ok(s) => s.unwrap_or_default(),
                            Err(_) => {
                                self.error("ec write: old snapshot mapping unreadable, refused");
                                return fail(self, &w, -EIO);
                            }
                        },
                    };
                    snaps.sort_unstable();
                    snaps.dedup();
                    // A classic shard's rollback re-adds the set and refuses an empty one (aborts): an unmapped clone
                    // gets no record, like a classic trim, whose old set is never empty.
                    if !snaps.is_empty() {
                        let mut prefix = ec::moddesc::ModDescBuilder::new();
                        prefix.update_snaps(&snaps);
                        let (mut bl, _, _) = prefix.finish();
                        bl.append(&mut e.mod_desc.bl);
                        e.mod_desc.bl = bl;
                    }
                }
            }
            if we.op != LogOp::ERROR
                && let Some(ws) = written.get(&we.soid)
            {
                e.written_shards = *ws;
            }
            entries.push(e);
        }
        let last = entries.last().map(|e| e.version).unwrap_or(self.log.head());
        let trim_to = self.calc_trim_to();
        let pct = self.pg_committed_to;
        if self.ep.rf_due != 0 {
            // the deferred roll-forward rides on this write's sub-writes
            self.ep.rf_due = 0;
            self.ep.rf_piggy += 1;
        }
        let mine = self.my_shard() as usize;
        let opt = self.ec_opt();
        let empty: Bytes = Transaction::new().encode_v9().expect("empty txn").into();
        // Apply the shard transaction before roll-forward: prior EC_OMAP records may target the stash this
        // write creates. The replica uses the same ordering; log and shard changes remain one durable txn.
        let own = txns.get(mine).cloned().flatten();
        if let Some(t) = own {
            self.txn.push(StoreOp::ApplyTxnSplit {
                skel: t.skel.clone(),
                refs: t.refs.clone(),
                hints: t.hints.clone(),
            });
        }
        self.ec_append_log(
            entries.clone(),
            Eversion::default(),
            pct,
            crate::ecpg::EcAppend::Applied,
            store.lazy_info(),
        );
        if let Some(temp) = &w.new_temp {
            self.temps.insert(temp.clone());
        }
        if let Some(temp) = &w.discard_temp {
            self.temps.remove(temp);
        }
        // mode O: entries without any shard transaction (log-only / error entries) go to every member (wgen 8)
        let all_members =
            !opt || std::mem::take(&mut self.ep.next_write_all) || txns.iter().all(|t| t.is_none());
        if trim_to != Eversion::default() {
            self.prim.pg_trim_to = trim_to;
            self.trim_log_to(trim_to);
        }
        let first_soid = w
            .entries
            .first()
            .map(|e| e.soid.clone())
            .or_else(|| w.new_temp.clone())
            .or_else(|| w.discard_temp.clone())
            .unwrap_or_default();
        // async-recovery targets that miss an object of this write: log-only sub-write, their missing set follows the
        // entries (ec-optimized-prim.md should_send, ec.md 9.5)
        let async_empty = self.async_targets_missing(&entries);
        let peers: Vec<PgShard> = self
            .prim
            .acting_recovery_backfill
            .iter()
            .copied()
            .filter(|p| *p != self.me && p.shard.0 >= 0)
            .collect();
        let mut waiting = BTreeSet::new();
        for p in peers {
            let beyond = async_empty.contains(&p)
                || (!w.entries.is_empty()
                    && self.prim.backfill_targets.contains(&p)
                    && w.entries
                        .iter()
                        .all(|e| !self.backfill_target_has_range(&p, &e.soid)));
            // pre_submit_op (prim A.1): every member's peer_info advances, skipped NP members included
            if let Some(pi) = self.prim.peer_info.get_mut(&p) {
                crate::primary::peer_info_written(pi, last);
            }
            let mine = txns.get(p.shard.0 as usize).cloned().flatten();
            let (txn, txn_zc, txn_hints, txn_payload_at) = if beyond {
                (empty.clone(), Vec::new(), crc::CrcHints::default(), None)
            } else if let Some(t) = mine {
                if opt {
                    self.ep.pending_rf.insert(p);
                }
                (
                    Bytes::copy_from_slice(&t.inline),
                    t.zc.clone(),
                    t.hints.clone().into(),
                    t.payload_at,
                )
            } else if all_members {
                (empty.clone(), Vec::new(), crc::CrcHints::default(), None)
            } else {
                // mode O partial write that skips this shard: no sub-write, its log stays sparse (spec 4.5)
                continue;
            };
            let m = MOSDECSubOpWrite {
                pgid: denc::types::SpgT {
                    pgid: self.spg.pgid,
                    shard: p.shard,
                },
                map_epoch: epoch,
                op: ECSubWrite {
                    from: self.me,
                    tid,
                    reqid: w.reqid,
                    soid: first_soid.clone(),
                    stats: self.info.stats.clone(),
                    txn_middle: Bytes::new(),
                    txn_data: txn,
                    txn_zc,
                    txn_hints,
                    txn_payload_at,
                    txn_data_more: Vec::new(),
                    at_version: if entries.is_empty() {
                        Eversion::default()
                    } else {
                        last
                    },
                    trim_to: self.prim.pg_trim_to,
                    log_entries: entries.clone(),
                    temp_added: w.new_temp.iter().cloned().collect(),
                    temp_removed: w.discard_temp.iter().cloned().collect(),
                    updated_hit_set_history: None,
                    pg_committed_to: pct,
                    backfill_or_async_recovery: beyond,
                },
                min_epoch: self.last_peering_reset,
                trace: [0; 3],
            };
            self.send(p.osd, Body::Ec(ecwire::EcMsg::from(m)), tid);
            waiting.insert(p);
        }
        self.prim.repops.insert(
            tid,
            RepOp {
                version: last,
                waiting,
                local_done: false,
                ec_objects: w.objects,
                t0: wprof::lat_t0(),
                t_local: 0,
            },
        );
        let interval = self.last_peering_reset;
        self.flush(crate::pg::Pending::LocalWrite { interval, tid });
    }

    /// A write finished (committed everywhere) or failed before generation: drop its bookkeeping.
    pub(crate) fn ec_forget(&mut self, tid: u64, objects: &[Hobject]) {
        self.ep.uncommitted.remove(&tid);
        // client reads parked on these objects (`ec_wait`) may run now
        for o in objects {
            self.ep.woke.push(crate::wake::ec_tok(o));
            self.ec_invalidate(o);
        }
        for o in objects {
            if let Some(s) = self.ep.by_obj.get_mut(o) {
                s.remove(&tid);
                if s.is_empty() {
                    self.ep.by_obj.remove(o);
                    self.ep.proj.remove(o);
                }
            }
        }
    }

    /// Reply of a shard to a sub-write.
    pub(crate) fn on_ec_write_reply(&mut self, from: i32, m: MOSDECSubOpWriteReply) {
        if !matches!(self.st, St::Primary(crate::pg::PSt::Active(_))) {
            self.discard("ec write reply outside Active");
            return;
        }
        // by pg_shard: one OSD may hold two positions (adr 0049 am. 3); the shard is the replier's, checked against the
        // connection's OSD and the members (am. 4)
        let p = m.op.from;
        if p.osd != from || p == self.me || !self.prim.acting_recovery_backfill.contains(&p) {
            self.discard("ec write reply from non-member");
            return;
        }
        let tid = m.op.tid;
        if self.ep.dummies.contains(&tid) {
            if m.op.committed {
                self.ep.dummies.remove(&tid);
            }
            return;
        }
        if !m.op.committed {
            return;
        }
        let Some(r) = self.prim.repops.get_mut(&tid) else {
            self.discard("ec write reply for unknown tid");
            return;
        };
        r.waiting.remove(&p);
        wprof::lat(1, r.t0);
        self.prim.peer_lcod.insert(p, m.op.last_complete);
        self.calc_min_lcod();
        self.complete_repops();
    }

    /// Idle pipeline with committed-but-not-rolled-forward entries: dummy sub-write to every shard (ec.md 11.1 step 5).
    pub(crate) fn ec_idle_rollforward(&mut self, lazy: bool) {
        if !self.ec_may_lead()
            || !matches!(self.st, St::Primary(crate::pg::PSt::Active(_)))
            || !self.prim.repops.is_empty()
            || !self.ep.writes.is_empty()
        {
            return;
        }
        let pct = self.pg_committed_to.min(self.log.head());
        if pct <= self.log.log.can_rollback_to {
            return;
        }
        // adaptive (adr 0160 am. 3): a PG whose writes come closer than half the bound waits up to 2 gaps for the next
        // write to carry `pct` (no dummy round); otherwise (QD1, sparse writes, bound 0) the dummy goes now, as classic
        let bound = self.cfg.ec_rf_defer_ns;
        let wait = self.ep.gap_ewma.saturating_mul(2);
        if bound > 0 && self.ep.gap_ewma > 0 && wait <= bound {
            if self.ep.rf_due == 0 {
                self.ep.rf_due = self.now.saturating_add(wait).max(1);
            }
            if self.now < self.ep.rf_due {
                return;
            }
        }
        self.ep.rf_due = 0;
        self.ep.rf_dummies += 1;
        self.ec_append_log(
            Vec::new(),
            Eversion::default(),
            pct,
            crate::ecpg::EcAppend::Applied,
            lazy,
        );
        let epoch = self.map.epoch();
        let opt = self.ec_opt();
        let all = std::mem::take(&mut self.ep.next_write_all);
        let pending = std::mem::take(&mut self.ep.pending_rf);
        let peers: Vec<PgShard> = self
            .prim
            .acting_recovery_backfill
            .iter()
            .copied()
            // mode O: only members that got a transaction since their last roll-forward (spec 4.5)
            .filter(|p| *p != self.me && p.shard.0 >= 0 && (!opt || all || pending.contains(p)))
            .collect();
        let empty: Bytes = Transaction::new().encode_v9().expect("empty txn").into();
        for p in peers {
            self.write_tid += 1;
            let tid = self.write_tid;
            self.ep.dummies.insert(tid);
            let m = MOSDECSubOpWrite {
                pgid: denc::types::SpgT {
                    pgid: self.spg.pgid,
                    shard: p.shard,
                },
                map_epoch: epoch,
                op: ECSubWrite {
                    from: self.me,
                    tid,
                    reqid: OsdReqId::default(),
                    soid: Hobject::MIN(),
                    stats: self.info.stats.clone(),
                    txn_middle: Bytes::new(),
                    txn_data: empty.clone(),
                    txn_zc: Vec::new(),
                    txn_hints: Default::default(),
                    txn_data_more: Vec::new(),
                    txn_payload_at: None,
                    at_version: Eversion::default(),
                    trim_to: self.prim.pg_trim_to,
                    log_entries: Vec::new(),
                    temp_added: Default::default(),
                    temp_removed: Default::default(),
                    updated_hit_set_history: None,
                    pg_committed_to: pct,
                    backfill_or_async_recovery: false,
                },
                min_epoch: self.last_peering_reset,
                trace: [0; 3],
            };
            self.send(p.osd, Body::Ec(ecwire::EcMsg::from(m)), tid);
        }
        self.flush(crate::pg::Pending::EcRollForward);
    }

    /// Interval ended: fail the pipeline (the op layer retries after peering).
    pub(crate) fn ec_abort_interval(&mut self) {
        let ep = std::mem::take(&mut self.ep);
        // read ids stay unique for the PG instance: a wake token of an aborted read never names a later one
        self.ep.next_rd = ep.next_rd;
        for w in ep.writes {
            self.out.push(Action::WriteDone {
                spg: self.spg,
                tid: w.tid,
                version: w.versions.last().copied().unwrap_or_default(),
                result: -11,
            });
        }
        // (writes already generated are failed through `prim.repops` by `abort_interval_work`)
        self.ep.reserved = Eversion::default();
    }

    // ---- read service ------------------------------------------------------------------------------------------

    /// Read stripes `[s0, s1)` of `soid` for `purpose`; the read's id.
    pub(crate) fn ec_read_begin(
        &mut self,
        purpose: Purpose,
        soid: Hobject,
        (lo, hi): (u64, u64),
        want_raw: Vec<usize>,
        store: &impl PgStoreOps,
    ) -> Result<u64, i32> {
        let be = self.ecb().cloned().ok_or(EIO)?;
        let (s0, s1) = (lo / be.s, hi.div_ceil(be.s));
        self.ec_read_start(
            ReadSpec {
                purpose,
                soid,
                span: (lo, hi),
                stripes: (s0, s1),
                srange: None,
                want_raw,
            },
            store,
        )
    }

    /// Mode O RMW read: shard bytes `[slo, shi)` of the raw data shards `want_raw` (decoded when one is missing).
    pub(crate) fn ec_read_begin_shard(
        &mut self,
        purpose: Purpose,
        soid: Hobject,
        (slo, shi): (u64, u64),
        want_raw: Vec<usize>,
        store: &impl PgStoreOps,
    ) -> Result<u64, i32> {
        let be = self.ecb().cloned().ok_or(EIO)?;
        let (s0, s1) = (slo / be.c, shi.div_ceil(be.c));
        let (lo, hi) = (s0 * be.s, s1 * be.s);
        self.ec_read_start(
            ReadSpec {
                purpose,
                soid,
                span: (lo, hi),
                stripes: (s0, s1),
                srange: Some((slo, shi)),
                want_raw,
            },
            store,
        )
    }

    fn ec_read_start(&mut self, spec: ReadSpec, store: &impl PgStoreOps) -> Result<u64, i32> {
        let (s0, s1) = spec.stripes;
        let soid = &spec.soid;
        let want_raw = &spec.want_raw;
        let be = self.ecb().cloned().ok_or(EIO)?;
        let (avail, src) = self.ec_sources(soid);
        let plan = be.plan_read(s0, s1, want_raw, &avail)?;
        if !plan.direct {
            self.ep.degraded_reads += 1;
        }
        Ok(self.ec_rd_register(spec, (avail, src), plan, store))
    }

    /// Clay recovery: rebuild the stripes `[s0, s1)` of shard `lost` from the repair sub-chunks of the helpers (fewer
    /// bytes than a whole-chunk decode). `false` when the code or the availability does not allow it.
    pub(crate) fn ec_repair_begin(
        &mut self,
        soid: &Hobject,
        (s0, s1): (u64, u64),
        lost: u32,
        store: &impl PgStoreOps,
    ) -> bool {
        let Some(be) = self.ecb().cloned() else {
            return false;
        };
        let (mut avail, src) = self.ec_sources(soid);
        avail.retain(|s| *s != lost);
        let Some(plan) = be.plan_repair(s0, s1, lost, &avail) else {
            return false;
        };
        if s0 == 0 {
            self.notes.push(format!(
                "pg {}: clay repair of shard {lost} of {:?} from {} helpers' sub-chunks",
                self.spg,
                soid.oid,
                plan.shards.len()
            ));
        }
        self.ep.repair_reads += 1;
        let (lo, hi) = (s0 * be.s, s1 * be.s);
        let spec = ReadSpec {
            purpose: Purpose::Recov,
            soid: soid.clone(),
            span: (lo, hi),
            stripes: (s0, s1),
            srange: None,
            want_raw: Vec::new(),
        };
        self.ec_rd_register(spec, (avail, src), plan, store);
        true
    }

    /// Start the read (it may finish before this returns); its id.
    fn ec_rd_register(
        &mut self,
        spec: ReadSpec,
        (avail, src): (Vec<u32>, BTreeMap<u32, i32>),
        plan: ecback::ReadPlan,
        store: &impl PgStoreOps,
    ) -> u64 {
        let ReadSpec {
            purpose,
            soid,
            span: (lo, hi),
            stripes: (s0, s1),
            srange,
            want_raw,
        } = spec;
        self.ep.next_rd += 1;
        let id = self.ep.next_rd;
        if matches!(purpose, Purpose::Recov) {
            // before the read starts: it may complete inside `ec_rd_check` below
            if let Some(op) = self.ep.recov.ops.get_mut(&soid) {
                op.read = Some(id);
            }
        }
        if self.cfg.ec_trace {
            let members: Vec<String> = self
                .prim
                .acting_recovery_backfill
                .iter()
                .map(|p| {
                    let has = u8::from(self.ec_member_has(p, &soid));
                    format!("{}/{}:{has}", p.osd, p.shard.0)
                })
                .collect();
            let t = format!(
                "rd#{id} {purpose:?} {} [{lo},{hi}) st [{s0},{s1}) sr {srange:?} want {want_raw:?} avail {avail:?} src {src:?} plan {:?} direct {} members [{}]",
                tname(&soid),
                plan.shards,
                plan.direct,
                members.join(" ")
            );
            self.ec_trace(|| t);
        }
        self.ep.reads.insert(
            id,
            EcRd {
                id,
                purpose,
                soid,
                s0,
                s1,
                lo,
                hi,
                want_raw,
                avail,
                src,
                plan,
                got: BTreeMap::new(),
                failed: BTreeSet::new(),
                pending: BTreeMap::new(),
                stale: false,
                srange,
                own_wait: false,
                own_held: HeldComplaint::default(),
                own_lease: 0,
                t0: wprof::lat_t0(),
            },
        );
        self.ec_rd_ask(id, store);
        self.ec_rd_check(id, store);
        id
    }

    /// Ask every planned shard that was not asked yet.
    fn ec_rd_ask(&mut self, id: u64, store: &impl PgStoreOps) {
        let Some(be) = self.ecb().cloned() else {
            return;
        };
        let Some(rd) = self.ep.reads.get(&id) else {
            return;
        };
        let (off, len) = rd.asked(be.c);
        let soid = rd.soid.clone();
        let src = rd.src.clone();
        let sub = rd.plan.repair.as_ref().map(|r| r.ranges.clone());
        let todo: Vec<u32> = rd
            .plan
            .shards
            .iter()
            .copied()
            .filter(|s| !rd.got.contains_key(s) && !rd.pending.contains_key(s))
            .collect();
        let epoch = self.map.epoch();
        for sh in todo {
            let stray = src.get(&sh).copied();
            // our own copy only when it is current (a backfill target of our shard id may hold the object instead)
            if stray.is_none() && sh == self.my_shard() && self.ec_member_has(&self.me, &soid) {
                // our own shard: read when the blocks are resident, else the device reads are submitted and `ec_pump` asks again
                // after the store woke (a blocking read stalls every PG of this core)
                let lease = self.ep.reads.get(&id).map_or(0, |r| r.own_lease);
                let warm = with_lease(store, lease, || self.ec_range_warm(&soid, off, len, store));
                if !warm {
                    let (now, spg) = (self.now, self.spg);
                    // what the next probes load stays resident until the local read (below) consumed it
                    let open = self
                        .ep
                        .reads
                        .get(&id)
                        .is_some_and(|rd| rd.own_lease == 0)
                        .then(|| self.lease_open(store));
                    if let Some(rd) = self.ep.reads.get_mut(&id) {
                        if let Some(l) = open {
                            rd.own_lease = l;
                        }
                        rd.own_held.hold(now);
                        rd.own_held.warn(now, "ec own-shard read prefetch", |secs| {
                            format!("pg {spg}, read {id} held {secs} s; still waiting")
                        });
                        rd.own_wait = true;
                        self.ep.store_wait = true;
                    }
                    continue;
                }
                // our shard is a read source like every peer's: L0 checks it against hinfo (ec.md 7.2) before its bytes
                // are returned or reconstructed from; the store-known crc spares the hash pass
                let l0 = self
                    .pool
                    .ec
                    .as_ref()
                    .is_some_and(|e| !e.overwrites && !e.optimized);
                let r = store
                    .ec_read_crc(self.spg, &soid, off, len)
                    .and_then(|(d, size, crc)| {
                        if l0 {
                            self.ec_hinfo_check(store, &soid, off, &d, size, crc)?;
                        }
                        Ok((d, size))
                    });
                if lease != 0 {
                    self.lease_release(store, lease);
                    if let Some(rd) = self.ep.reads.get_mut(&id) {
                        rd.own_lease = 0;
                    }
                }
                if self.cfg.ec_trace {
                    let t = match &r {
                        Ok((d, size)) => format!(
                            "rd#{id} sh{sh} local [{off},+{len}) -> {} (shard size {size}) lu {} head {}",
                            d.len(),
                            self.info.last_update,
                            self.log.log.head
                        ),
                        Err(e) => format!("rd#{id} sh{sh} local [{off},+{len}) -> err {e}"),
                    };
                    self.ec_trace(|| t);
                }
                let shape = self.ec_reply_shape(id);
                if let Some(rd) = self.ep.reads.get_mut(&id) {
                    let d = r.map(|(d, _)| match &rd.plan.repair {
                        Some(rp) => be.gather_sub(&d, &rp.ranges),
                        None => d,
                    });
                    match d {
                        Ok(d) if shape.is_some_and(|s| s.fits(d.len() as u64)) => {
                            rd.got.insert(sh, Bytes::from(d));
                        }
                        _ => {
                            rd.failed.insert(sh);
                        }
                    }
                }
                continue;
            }
            let Some(osd) = stray.or_else(|| self.ec_osd_holding(&soid, sh)) else {
                if let Some(rd) = self.ep.reads.get_mut(&id) {
                    rd.failed.insert(sh);
                }
                continue;
            };
            self.write_tid += 1;
            let tid = self.write_tid;
            self.ec_trace(|| format!("rd#{id} sh{sh} ask osd.{osd} tid {tid} [{off},+{len})"));
            self.ep.rd_tids.insert(tid, id);
            if let Some(rd) = self.ep.reads.get_mut(&id) {
                rd.pending.insert(sh, Asked { tid, osd, epoch });
            }
            let sub = sub
                .clone()
                .unwrap_or_else(|| vec![(0, be.sub_chunks() as i32)]);
            let recov = self
                .ep
                .reads
                .get(&id)
                .is_some_and(|rd| matches!(rd.purpose, Purpose::Recov));
            self.ec_send_subread(osd, sh, tid, (&soid, off, len), sub, epoch, recov);
        }
    }

    /// Complete, replan after failures, or keep waiting.
    fn ec_rd_check(&mut self, id: u64, store: &impl PgStoreOps) {
        loop {
            let Some(be) = self.ecb().cloned() else {
                return;
            };
            let Some(rd) = self.ep.reads.get_mut(&id) else {
                return;
            };
            if rd.plan.shards.iter().all(|s| rd.got.contains_key(s)) {
                let rd = self.ep.reads.remove(&id).unwrap();
                if self.cfg.ec_trace {
                    let span = rd.asked(be.c).1;
                    let lens: Vec<String> = rd
                        .got
                        .iter()
                        .map(|(s, b)| {
                            let short = if (b.len() as u64) < span { "<" } else { "" };
                            format!("sh{s}:{short}{}", b.len())
                        })
                        .collect();
                    let t = format!(
                        "rd#{id} done {:?} span {span} got [{}] direct {} stale {}",
                        rd.purpose,
                        lens.join(" "),
                        rd.plan.direct,
                        rd.stale
                    );
                    self.ec_trace(|| t);
                }
                if matches!(rd.purpose, Purpose::Rmw(_) | Purpose::RmwO(_)) {
                    wprof::lat(5, rd.t0);
                }
                if rd.plan.repair.is_some() {
                    let r = be.repair_shard(&rd.plan, &rd.got);
                    self.ec_rd_done(rd, r, None, store);
                    return;
                }
                if let (Purpose::RmwO(tid), Some((a, b))) = (rd.purpose, rd.srange) {
                    let r = be.shard_columns(&rd.plan, &rd.got, (b - a) as usize, &rd.want_raw);
                    self.ec_rmw_o_done(tid, &rd.soid, a, r);
                    return;
                }
                if matches!(rd.purpose, Purpose::Rmw(_))
                    && rd.want_raw.len() < be.k
                    && rd.plan.direct
                {
                    // chunks the write overwrites whole were not read: their old bytes are never used (zero)
                    let r = rmw_interleave(&be, &rd);
                    self.ec_rd_done(rd, r, None, store);
                    return;
                }
                // a client read keeps the crc of its bytes (fused into the interleave): the reply skips its crc pass
                let crc = rd.purpose == Purpose::Client;
                match be.assemble_crc(&rd.plan, &rd.got, rd.lo, rd.hi - rd.lo, crc) {
                    Ok((d, c)) => self.ec_rd_done(rd, Ok(d), c, store),
                    Err(e) => self.ec_rd_done(rd, Err(e), None, store),
                }
                return;
            }
            if !rd.pending.is_empty() || rd.own_wait {
                return;
            }
            // nothing in flight and still incomplete: a shard failed -> plan again without it
            if rd.plan.repair.is_some() {
                // a repair read is not replanned: recovery falls back to whole-chunk reads
                let rd = self.ep.reads.remove(&id).unwrap();
                self.ec_rd_done(rd, Err(EIO), None, store);
                return;
            }
            if matches!(rd.purpose, Purpose::Rmw(_)) && rd.want_raw.len() < be.k {
                // a shard of a partial RMW read failed: read whole stripes (decoded) like any other RMW
                rd.want_raw = (0..be.k).collect();
            }
            let failed = rd.failed.clone();
            let avail: Vec<u32> = rd
                .avail
                .iter()
                .copied()
                .filter(|s| !failed.contains(s))
                .collect();
            match be.plan_read(rd.s0, rd.s1, &rd.want_raw, &avail) {
                Ok(p) => {
                    if !p.direct && rd.plan.direct {
                        self.ep.degraded_reads += 1;
                    }
                    let rd = self.ep.reads.get_mut(&id).unwrap();
                    rd.avail = avail;
                    rd.plan = p;
                    self.ec_rd_ask(id, store);
                }
                Err(e) => {
                    let rd = self.ep.reads.remove(&id).unwrap();
                    self.ec_rd_done(rd, Err(e), None, store);
                    return;
                }
            }
        }
    }

    /// `crc` = `crc32c(!0, data)` of a client read (kept with the cache entry for the reply).
    fn ec_rd_done(
        &mut self,
        rd: EcRd,
        r: Result<Vec<u8>, i32>,
        crc: Option<u32>,
        store: &impl PgStoreOps,
    ) {
        self.lease_release(store, rd.own_lease); // ended while its own shard still waited
        match rd.purpose {
            Purpose::Recov => match rd.plan.repair {
                Some(rp) => self.ec_recov_repair_done(rd.soid, rp.lost, rd.id, r, store),
                None => self.ec_recov_read_done(rd.soid, rd.id, r, store),
            },
            Purpose::RmwO(tid) => {
                let e = r.err().unwrap_or(EIO);
                self.ec_rmw_o_done(tid, &rd.soid, 0, Err(e));
            }
            Purpose::Rmw(tid) => {
                let Some(be) = self.ecb().cloned() else {
                    return;
                };
                let Some(w) = self.ep.writes.iter_mut().find(|w| w.tid == tid) else {
                    return;
                };
                w.pending_reads = w.pending_reads.saturating_sub(1);
                match r {
                    Ok(bytes) => {
                        for (i, st) in (rd.s0..rd.s1).enumerate() {
                            let s = be.s as usize;
                            w.old
                                .insert((rd.soid.clone(), st), bytes[i * s..(i + 1) * s].to_vec());
                        }
                    }
                    Err(e) => w.failed = Some(neg(e)),
                }
            }
            Purpose::Client => {
                self.ep.woke.push(crate::wake::ec_rd_tok(rd.id));
                if rd.stale {
                    return;
                }
                match r {
                    Ok(data) => {
                        self.ep.cache_bytes += data.len();
                        self.ep.cache.push_back(CacheEnt {
                            soid: rd.soid,
                            lo: rd.lo,
                            hi: rd.hi,
                            data: Bytes::from(data),
                            crc,
                            taken: Default::default(),
                        });
                        while self.ep.cache_bytes > CACHE_CAP && self.ep.cache.len() > 1 {
                            if let Some(old) = self.ep.cache.pop_front() {
                                self.ep.cache_bytes -= old.data.len();
                            }
                        }
                    }
                    Err(_) => {
                        self.ep.rd_err.insert(rd.soid, None);
                    }
                }
            }
        }
    }

    // ---- op layer interface (client reads, ec.md 10) ------------------------------------------------------------------

    /// Client read cache fills in flight (diagnostics).
    pub fn ec_client_reads(&self) -> usize {
        self.ep
            .reads
            .values()
            .filter(|r| r.purpose == Purpose::Client)
            .count()
    }

    /// A client read cache fill finished since the last call; failures not announced yet are stamped with wake
    /// generation `gen`. Second value: such a failure exists.
    pub(crate) fn ep_take_wake(&mut self, wake_gen: u64) -> (crate::wake::WakeSet, bool) {
        let mut failed = false;
        for g in self.ep.rd_err.values_mut().filter(|g| g.is_none()) {
            *g = Some(wake_gen);
            failed = true;
        }
        (std::mem::take(&mut self.ep.woke), failed)
    }

    /// The ops parked on the client reads failed up to wake generation `wake_gen` have run (and got EIO): later ops
    /// read the shards again.
    pub(crate) fn ec_read_errors_delivered(&mut self, wake_gen: u64) {
        self.ep.rd_err.retain(|_, g| g.is_none_or(|g| g > wake_gen));
    }

    /// State of `soid` after its queued / uncommitted writes (the local shard lags behind them: generation waits for
    /// RMW reads and runs in version order): `Some(None)` = absent after them, `Some(Some((size, attrs)))` = exists;
    /// `None` = no write in flight, the local shard is current. The op layer reads attrs / sizes of objects other than
    /// the head it projects itself (e.g. the clone a pipelined rollback copies) through this.
    pub fn ec_projected(&self, soid: &Hobject) -> Option<Option<(u64, &Attrs)>> {
        self.ep
            .proj
            .get(soid)
            .map(|p| p.exists.then_some((p.size, &p.attrs)))
    }

    /// A write of `soid` is queued or uncommitted on this primary (the committed state is stale).
    pub(crate) fn ec_write_in_flight(&self, soid: &Hobject) -> bool {
        self.ep.by_obj.contains_key(soid)
    }

    /// Objects in `[lo, hi)` with a write queued or uncommitted on this primary.
    pub(crate) fn ec_writes_in_flight_in(&self, lo: &Hobject, hi: &Hobject) -> Vec<Hobject> {
        if lo >= hi {
            return Vec::new();
        }
        self.ep
            .by_obj
            .range(lo.clone()..hi.clone())
            .map(|(o, _)| o.clone())
            .collect()
    }

    /// Logical size of `soid` from the committed object_info of our shard (`None` = absent).
    pub fn ec_obj_size(&self, soid: &Hobject, store: &impl PgStoreOps) -> Result<Option<u64>, i32> {
        // one attribute, not the whole xattr map (every client read asks this 2-3 times)
        match store.ec_getattr(self.spg, soid, b"_") {
            Err(e) if e.abs() == 2 => Ok(None),
            Err(e) => Err(e.abs()),
            Ok(Some(b)) => denc::from_slice::<replwire::ObjectInfo>(&b)
                .map(|o| Some(o.size))
                .map_err(|_| EIO),
            Ok(None) => Err(EIO),
        }
    }

    /// [`Pg::ec_wait`] for a read at `snapid` of `head`: the data lives in the clone the head's SnapSet maps the snap to.
    pub fn ec_wait_snap(
        &mut self,
        head: &Hobject,
        snapid: u64,
        off: u64,
        len: u64,
        store: &impl PgStoreOps,
    ) -> Option<u64> {
        use denc::types::SnapId;
        if SnapId(snapid) == SnapId::NOSNAP || SnapId(snapid) == SnapId::SNAPDIR {
            return self.ec_wait(head, off, len, store);
        }
        // the head (or a clone of it) is missing on our shard: its SnapSet is stale, the op parks on it (see `ec_wait`)
        if self.read_blocked(head) {
            return None;
        }
        // the committed SnapSet is stale while a write on the head is in flight (it may make a new clone)
        if self.ep.by_obj.contains_key(head) {
            return Some(crate::wake::ec_tok(head));
        }
        let ss = store
            .ec_getattrs(self.spg, head)
            .ok()
            .and_then(|a| a.get(b"snapset".as_slice()).cloned())
            .and_then(|b| denc::from_slice::<replwire::SnapSet>(&b).ok());
        let Some(ss) = ss else {
            return None; // no snapset: the op layer answers (ENOENT / head)
        };
        if snapid > ss.seq {
            return self.ec_wait(head, off, len, store);
        }
        let c = ss.clones.iter().find(|c| c.0 >= snapid)?;
        let mut clone = head.clone();
        clone.snap = *c;
        self.ec_wait(&clone, off, len, store)
    }

    /// What `[off, off+len)` of `soid` waits for before `ec_cache_read` can serve it: `None` = ready, else the wake token
    /// that announces the change: the client read of the shards that covers the range ([`crate::wake::ec_rd_tok`],
    /// started here or already in flight), or the write on the object ([`crate::wake::ec_tok`]). Everything that cannot
    /// be served (absent object, no code, read failed) is ready: the op runs and `ec_cache_read` reports the error.
    pub fn ec_wait(
        &mut self,
        soid: &Hobject,
        off: u64,
        len: u64,
        store: &impl PgStoreOps,
    ) -> Option<u64> {
        let be = self.ecb().cloned()?;
        if !self.is_primary() || self.refuse.is_some() {
            return None;
        }
        // a write on the object is queued or not committed on every shard yet: the local object may not exist yet (a
        // creating write queued behind an RMW write of another object), shards would mix old and new stripes (and the
        // cache is dropped at its completion anyway); park, the completion wakes the op
        if self.ep.by_obj.contains_key(soid) {
            return Some(crate::wake::ec_tok(soid));
        }
        self.ec_drop_taken();
        // our own shard misses the object (we were down while it was written): the local object_info, and so the size
        // the read would be clipped to, is stale. Nothing is read: the op parks on the missing object and is warmed again
        // once it is recovered (a cache filled now would outlive the recovery: EIO or a short read after it)
        if self.read_blocked(soid) {
            return None;
        }
        let Ok(Some(size)) = self.ec_obj_size(soid, store) else {
            return None;
        };
        let end = off.saturating_add(len).min(size);
        if off >= end || self.ep.rd_err.contains_key(soid) {
            return None;
        }
        let covered = |ep: &EcPrim| {
            ep.cache
                .iter()
                .any(|c| c.soid == *soid && c.lo <= off && c.hi >= end)
        };
        if covered(&self.ep) {
            return None;
        }
        // the read in flight that covers the range: its completion wakes this op, not the ops on other reads of the object
        if let Some(id) = self.ep.reads.values().find_map(|r| {
            (r.purpose == Purpose::Client
                && r.soid == *soid
                && !r.stale
                && r.lo <= off
                && r.hi >= end)
                .then_some(r.id)
        }) {
            return Some(crate::wake::ec_rd_tok(id));
        }
        if self.cfg.ec_trace {
            let v = store
                .ec_getattr(self.spg, soid, b"_")
                .ok()
                .flatten()
                .and_then(|b| denc::from_slice::<replwire::ObjectInfo>(&b).ok())
                .map_or_else(|| "?".to_string(), |o| o.version.to_string());
            let t = format!("cread {} [{off},{end}) oi size {size} v {v}", tname(soid));
            self.ec_trace(|| t);
        }
        let want = be.raw_chunks_of(off, end - off).ok()?;
        // Err: the op runs now and `ec_cache_read` finds nothing cached: EIO for this op only
        let id = self
            .ec_read_begin(Purpose::Client, soid.clone(), (off, end), want, store)
            .ok()?;
        // a purely local completion (a single wanted chunk on our own shard) is already cached
        (!covered(&self.ep)).then(|| crate::wake::ec_rd_tok(id))
    }

    /// Logical bytes `[off, off+len)` (clamped to the object size by the caller's `ec_wait` clip) from the cache.
    pub fn ec_cache_read(
        &self,
        soid: &Hobject,
        off: u64,
        len: u64,
        size: u64,
    ) -> Result<Vec<u8>, i32> {
        self.ec_cache_read_bytes(soid, off, len, size)
            .map(|(d, _)| d.to_vec())
    }

    /// [`Self::ec_cache_read`] as a slice of the cache entry (no copy) and the crc32c (seed `!0`) of the slice when it is
    /// the whole entry (the reply then skips its crc pass).
    pub fn ec_cache_read_bytes(
        &self,
        soid: &Hobject,
        off: u64,
        len: u64,
        size: u64,
    ) -> Result<(Bytes, Option<u32>), i32> {
        if self.ecb().is_none() {
            return Err(EIO);
        }
        let end = off.saturating_add(len).min(size);
        if off >= end {
            return Ok((Bytes::new(), None));
        }
        if self.ep.rd_err.contains_key(soid) {
            return Err(EIO);
        }
        let Some(c) = self
            .ep
            .cache
            .iter()
            .find(|c| c.soid == *soid && c.lo <= off && c.hi >= end)
        else {
            // never warmed (a read shape `cold` did not foresee): the op layer sees an I/O error rather than wrong data
            return Err(EIO);
        };
        let whole = off == c.lo && end == c.hi;
        if whole && !c.taken.replace(true) {
            self.ep.taken.set(self.ep.taken.get() + 1);
        }
        let d = c.data.slice((off - c.lo) as usize..(end - c.lo) as usize);
        Ok((d, c.crc.filter(|_| whole)))
    }

    /// Drop the cache entries a read took whole (sequential readers never come back to them; a reader of the same range
    /// that comes later reads the shards again). Only between ops: an op reading the same range twice still finds it.
    fn ec_drop_taken(&mut self) {
        if self.ep.taken.replace(0) == 0 {
            return;
        }
        let mut freed = 0usize;
        self.ep.cache.retain(|c| {
            if c.taken.get() {
                freed += c.data.len();
                false
            } else {
                true
            }
        });
        self.ep.cache_bytes = self.ep.cache_bytes.saturating_sub(freed);
    }

    /// A write on `soid` was submitted or finished: cached / in-flight read data of it may be old.
    pub(crate) fn ec_invalidate(&mut self, soid: &Hobject) {
        self.ep.rd_err.remove(soid);
        let mut freed = 0usize;
        self.ep.cache.retain(|c| {
            if c.soid == *soid {
                freed += c.data.len();
                false
            } else {
                true
            }
        });
        self.ep.cache_bytes = self.ep.cache_bytes.saturating_sub(freed);
        for r in self.ep.reads.values_mut() {
            if r.purpose == Purpose::Client && r.soid == *soid {
                r.stale = true;
            }
        }
    }

    /// Did a map since `a` was sent show its OSD down (or down and up again: the instance asked is gone with the message)?
    pub(crate) fn ec_src_gone(&self, a: &Asked) -> bool {
        !self.map.is_up(a.osd) || self.map.up_from(a.osd) > a.epoch
    }

    /// Same-interval map change: sub-reads whose OSD went down are given up (classic drops such a location, spec
    /// missing-loc.md 5); those shards count as failed, the read is replanned without them (or fails). A slow or
    /// partitioned peer that is still up is waited for: a stall is never turned into an error.
    pub(crate) fn ec_tick(&mut self, store: &impl PgStoreOps) {
        let epoch = self.map.epoch();
        if self.ep.src_epoch == epoch {
            return;
        }
        self.ep.src_epoch = epoch;
        let gone: Vec<u64> = self
            .ep
            .reads
            .iter()
            .filter(|(_, r)| r.pending.values().any(|a| self.ec_src_gone(a)))
            .map(|(id, _)| *id)
            .collect();
        for id in gone {
            let Some(rd) = self.ep.reads.get(&id) else {
                continue;
            };
            let lost: Vec<(u32, Asked)> = rd
                .pending
                .iter()
                .filter(|(_, a)| self.ec_src_gone(a))
                .map(|(s, a)| (*s, *a))
                .collect();
            for (sh, a) in lost {
                self.ep.rd_tids.remove(&a.tid);
                if let Some(rd) = self.ep.reads.get_mut(&id) {
                    rd.pending.remove(&sh);
                    rd.failed.insert(sh);
                }
                self.ec_trace(|| {
                    format!(
                        "rd#{id} sh{sh} osd.{} went down, tid {} given up",
                        a.osd, a.tid
                    )
                });
            }
            self.ec_rd_check(id, store);
        }
        let warm: Vec<u64> = self
            .ep
            .warm_tids
            .values()
            .filter(|a| self.ec_src_gone(a))
            .map(|a| a.tid)
            .collect();
        for t in warm {
            self.ep.warm_tids.remove(&t);
        }
        self.ec_recov_src_check(store);
    }

    /// Earliest EC primary deadline.
    pub(crate) fn ec_next_deadline(&self) -> Option<Mono> {
        // a deferred roll-forward only matters while idle (a busy pipeline carries it or re-arms it)
        (self.ep.rf_due != 0 && self.prim.repops.is_empty() && self.ep.writes.is_empty())
            .then_some(self.ep.rf_due)
    }

    /// Shape every reply of read `id` (remote or our own shard) must have; `None` = the read or the backend is gone.
    fn ec_reply_shape(&self, id: u64) -> Option<ReplyShape> {
        let be = self.ecb()?;
        let rd = self.ep.reads.get(&id)?;
        let (off, asked) = rd.asked(be.c);
        let legacy = self.pool.ec.as_ref().is_some_and(|e| !e.optimized);
        let (len, exact) = be
            .repair_reply_len(&rd.plan)
            .map_or((asked, legacy), |gathered| (gathered, true));
        Some(ReplyShape { off, len, exact })
    }

    /// A shard answered a sub-read.
    pub(crate) fn on_ec_read_reply(
        &mut self,
        from: i32,
        m: MOSDECSubOpReadReply,
        store: &impl PgStoreOps,
    ) {
        let _s = wprof::span(wprof::S::EcRead);
        // a reply matches a sub-read by tid AND the OSD that was asked (a misrouted or duplicated reply from another
        // OSD must not fill or fail that shard)
        let tid = m.op.tid;
        if self.ep.warm_tids.get(&tid).is_some_and(|a| a.osd == from) {
            self.ep.warm_tids.remove(&tid);
            return; // only there to load the stash blocks of that shard
        }
        let Some(&id) = self.ep.rd_tids.get(&tid) else {
            if !self.ec_recov_attrs(from, tid, m, store) {
                self.discard("ec read reply for unknown tid");
            }
            return;
        };
        let shape = self.ec_reply_shape(id);
        let Some(rd) = self.ep.reads.get_mut(&id) else {
            self.ep.rd_tids.remove(&tid);
            return;
        };
        let Some(sh) = rd
            .pending
            .iter()
            .find(|(_, a)| a.tid == tid && a.osd == from)
            .map(|(s, _)| *s)
        else {
            self.discard("ec read reply from an osd not asked");
            return;
        };
        rd.pending.remove(&sh);
        let ECSubReadReply {
            mut buffers_read,
            errors,
            ..
        } = m.op;
        let got = if let Some(e) = errors.get(&rd.soid) {
            rd.failed.insert(sh);
            Err(*e)
        } else if let Some(bufs) = buffers_read.remove(&rd.soid) {
            match <[_; 1]>::try_from(bufs) {
                Ok([(at, data)])
                    if shape.is_some_and(|s| at == s.off && s.fits(data.len() as u64)) =>
                {
                    let n = data.len();
                    rd.got.insert(sh, data);
                    Ok(n)
                }
                _ => {
                    rd.failed.insert(sh);
                    Err(EIO)
                }
            }
        } else {
            rd.failed.insert(sh);
            Err(0)
        };
        self.ep.rd_tids.remove(&tid);
        self.ec_trace(|| format!("rd#{id} sh{sh} reply osd.{from} tid {tid}: {got:?}"));
        self.ec_rd_check(id, store);
    }
}

impl Plan {
    fn objects(&self) -> Vec<Hobject> {
        match self {
            Plan::L(p) => p.objects(),
            Plan::O(p) => p.objects(),
        }
    }
    fn post(&self) -> BTreeMap<Hobject, ecback::Post> {
        match self {
            Plan::L(p) => p.post(),
            Plan::O(p) => p.post(),
        }
    }
    fn mod_descs(&self) -> BTreeMap<Hobject, ObjectModDesc> {
        match self {
            Plan::L(p) => p.mod_descs(),
            Plan::O(p) => p.mod_descs(),
        }
    }
}

impl EcWrite {
    fn has_reads(&self) -> bool {
        !self.to_read.is_empty() || !self.o_reads.is_empty()
    }
}

impl Pg {
    /// Shard ids of `acting_recovery_backfill` (the members a mode O plan emits transactions for).
    fn ec_member_shards(&self) -> Vec<u32> {
        self.prim
            .acting_recovery_backfill
            .iter()
            .filter(|p| p.shard.0 >= 0 && p.osd != pgwire::NONE_OSD && p.osd >= 0)
            .map(|p| p.shard.0 as u32)
            .collect()
    }

    /// Mode O RMW read of write `tid` finished: per raw shard bytes starting at shard offset `off`.
    fn ec_rmw_o_done(
        &mut self,
        tid: u64,
        soid: &Hobject,
        off: u64,
        r: Result<Vec<(usize, Vec<u8>)>, i32>,
    ) {
        let Some(w) = self.ep.writes.iter_mut().find(|w| w.tid == tid) else {
            return;
        };
        w.pending_reads = w.pending_reads.saturating_sub(1);
        match r {
            Ok(cols) => {
                for (raw, bytes) in cols {
                    w.old_o.insert((soid.clone(), raw), (off, bytes));
                }
            }
            Err(e) => w.failed = Some(neg(e)),
        }
    }
}

/// Logical ranges each object of `t` is written over, when the txn holds only plain writes and attr ops (anything else,
/// e.g. zero / truncate / clone / remove, may need the old bytes in ways a write cover does not describe: `None`).
fn write_cover(t: &Transaction<'_>) -> Option<BTreeMap<Hobject, Vec<(u64, u64)>>> {
    use replwire::txn::TxnOp;
    let mut m: BTreeMap<Hobject, Vec<(u64, u64)>> = BTreeMap::new();
    for op in &t.ops {
        match &op.op {
            TxnOp::Write { oid, off, data } => {
                let len = data.len() as u64;
                if len > 0 {
                    m.entry(t.get_obj(*oid).hobj.clone())
                        .or_default()
                        .push((*off, *off + len));
                }
            }
            TxnOp::Nop
            | TxnOp::SetAllocHint { .. }
            | TxnOp::SetAttr { .. }
            | TxnOp::SetAttrs { .. }
            | TxnOp::RmAttr { .. }
            | TxnOp::RmAttrs { .. } => {}
            _ => return None,
        }
    }
    Some(m)
}

/// Is `[a, b)` inside the union of `ranges`?
fn covered(ranges: &[(u64, u64)], a: u64, b: u64) -> bool {
    let mut v: Vec<(u64, u64)> = ranges
        .iter()
        .copied()
        .filter(|r| r.1 > a && r.0 < b)
        .collect();
    v.sort_unstable();
    let mut at = a;
    for (x, y) in v {
        if x > at {
            return false;
        }
        at = at.max(y);
        if at >= b {
            return true;
        }
    }
    at >= b
}

/// Old stripes `[s0, s1)` of a legacy RMW read of the raw data shards `want_raw` only (direct, every shard read whole
/// over the span): chunk by chunk in raw order, the chunks not read are zero (the write overwrites them whole).
fn rmw_interleave(be: &ecback::Backend, rd: &EcRd) -> Result<Vec<u8>, i32> {
    let (c, n) = (be.c as usize, (rd.s1 - rd.s0) as usize);
    let mut out = vec![0u8; n * be.s as usize];
    for &r in &rd.want_raw {
        let sh = *be.mapping.get(r).ok_or(EIO)?;
        let d = rd.got.get(&sh).ok_or(EIO)?;
        if d.len() < n * c {
            return Err(EIO);
        }
        for i in 0..n {
            let at = i * be.s as usize + r * c;
            out[at..at + c].copy_from_slice(&d[i * c..(i + 1) * c]);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod lead_role_tests {
    use super::*;
    use crate::map::synth::SynthMap;
    use denc::types::{PgT, ShardId, SnapId, SpgT};
    use pgwire::PoolParams;
    use std::rc::Rc;
    use std::sync::Arc;

    /// Acting primary (osd.0 at shard 0) of a 2+1 legacy EC pool, before `primary_start` latched the role.
    fn pg(primary_ok: bool) -> Pg {
        let mut map = SynthMap::new(5)
            .with_osd(0, 1)
            .with_osd(1, 1)
            .with_osd(2, 1);
        let ec = pgwire::EcPoolInfo {
            k: 2,
            m: 1,
            stripe_width: 8192,
            chunk_size: 4096,
            overwrites: true,
            supported: true,
            reason: String::new(),
            plugin: "isa".into(),
            technique: "reed_sol_van".into(),
            profile: Default::default(),
            chunk_mapping: vec![0, 1, 2],
            optimized: false,
            nonprimary: vec![],
            omap: false,
            sub_chunks: 1,
            primary_ok,
        };
        map.pools.insert(
            1,
            PoolParams {
                size: 3,
                min_size: 2,
                pg_num: 1,
                pg_num_pending: 1,
                is_erasure: true,
                ec_k: 2,
                ec: Some(Arc::new(ec)),
                ..Default::default()
            },
        );
        let spg = SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId(0),
        };
        let mut cfg = Config::new(0);
        cfg.ec_enable = ec::EcEnable::All;
        cfg.ec_primary = true;
        let mut pg = Pg::blank(Arc::new(cfg), spg, Rc::new(map), PgInfo::new(spg));
        pg.acting = vec![0, 1, 2];
        pg.acting_primary = 0;
        pg.refresh_ecb();
        assert!(pg.ecb().is_some(), "code available");
        pg
    }

    /// Review M2: with `ec_enable_primary` on, an acting primary that may not lead (shard-only clay profile, role not
    /// latched, nonprimary shard) must not count as a sender of primary-side messages.
    #[test]
    fn acting_primary_that_may_not_lead_sends_no_primary_side_messages() {
        let mut p = pg(false);
        assert!(p.is_primary());
        p.ec_lead_cfg = true;
        assert!(!p.ec_leads(), "shard-only profile");
        let mut p = pg(true);
        assert!(!p.ec_leads(), "role not latched at the interval start");
        p.ec_lead_cfg = true;
        assert!(p.ec_leads(), "leads");
        p.acting_primary = 1;
        assert!(!p.ec_leads(), "not the acting primary");
    }

    #[test]
    fn ec_completion_visits_only_its_objects_and_preserves_later_dependencies() {
        let mut p = pg(true);
        let shared = Hobject::new(b"shared", SnapId::NOSNAP, 0, 1, b"");
        let n = 512u64;
        for tid in 1..=n {
            let o = Hobject::new(&tid.to_le_bytes(), SnapId::NOSNAP, tid as u32, 1, b"");
            let objects = vec![o.clone(), shared.clone()];
            p.ep.proj.insert(o.clone(), OldObj::default());
            p.ep.proj.insert(shared.clone(), OldObj::default());
            p.ep.by_obj.entry(o).or_default().insert(tid);
            p.ep.by_obj.entry(shared.clone()).or_default().insert(tid);
            p.ep.uncommitted.insert(tid);
            p.prim.repops.insert(
                tid,
                RepOp {
                    version: Eversion::new(5, tid),
                    waiting: BTreeSet::new(),
                    local_done: false,
                    ec_objects: objects,
                    t0: 0,
                    t_local: 0,
                },
            );
        }
        for tid in 1..=n {
            p.local_write_committed(tid);
            assert!(!p.ep.uncommitted.contains(&tid));
            if tid < n {
                assert_eq!(p.ep.by_obj.get(&shared).unwrap().len(), (n - tid) as usize);
                assert!(p.ep.uncommitted.contains(&(tid + 1)));
                assert!(p.ep.proj.contains_key(&shared));
            }
        }
        assert!(p.ep.by_obj.is_empty());
        assert!(p.ep.uncommitted.is_empty());
        assert!(p.ep.proj.is_empty());
        assert_eq!(p.ep.completion_object_visits, 2 * n as usize);

        // Interval abort drops retained object vectors with their owning repops.
        assert!(p.prim.repops.is_empty());
        p.ep.by_obj.entry(shared.clone()).or_default().insert(n + 1);
        p.ep.uncommitted.insert(n + 1);
        p.prim.repops.insert(
            n + 1,
            RepOp {
                version: Eversion::new(5, n + 1),
                waiting: BTreeSet::new(),
                local_done: false,
                ec_objects: vec![shared],
                t0: 0,
                t_local: 0,
            },
        );
        p.abort_interval_work();
        assert!(p.prim.repops.is_empty());
        assert!(p.ep.by_obj.is_empty());
        assert!(p.ep.uncommitted.is_empty());
    }
}
