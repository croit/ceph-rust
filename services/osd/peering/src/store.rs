// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Local persistence seam: typed store mutations emitted by the PG machinery, the abstract
//! [`PgStoreOps`] trait the NVMe store implements, and an in-memory implementation ([`MemStore`])
//! used by tests and dev tools (adr 0008: info + log + missing + data change commit atomically).

use denc::types::{CollT, Eversion, Hobject, PgT, SpgT};
use pgwire::{LogDup, LogEntry, MissingItem, PastIntervals, PgInfo, PgLog, PgMissing};
use replwire::{
    ObjectInfo, ObjectRecoveryInfo, ObjectRecoveryProgress, PushOp, SnapSet, Transaction, TxnOp,
};
use std::collections::BTreeMap;

/// One mutation of a PG's local durable state. A [`StoreTxn`] applies all-or-nothing.
#[derive(Debug, Clone, PartialEq)]
pub enum StoreOp {
    /// Create the PG collection + pgmeta (idempotent).
    CreatePg,
    /// Remove every object, the pgmeta and the collection of the PG.
    RemovePg,
    /// Last map epoch this PG processed (boot-time map selection).
    PutEpoch(u32),
    /// Full `pg_info_t` (incl. history, stats).
    PutInfo(Box<PgInfo>),
    PutPastIntervals(Box<PastIntervals>),
    /// Append entries to the log (ascending, newer than head). Head := last entry version.
    LogAppend(Vec<LogEntry>),
    /// [`StoreOp::LogAppend`] of a replicated client write: the entries only; the persisted `_loghead` is NOT touched (the
    /// PG writes it with a [`StoreOp::LogSetHead`] whenever it writes `info`, see `Pg::info_adv`; `PersistedPg::normalize`
    /// and `meta::load` derive a stale head from the newest entry).
    LogAppendFast(Vec<EncLogEntry>),
    /// Trim the log to `to`: tail := max(tail, to); the entries `<= to` become dup records (their own and one per extra
    /// request id, [`LogEntry::dups`]) and every dup record below `dups_from` is dropped (`None`: all). The persisted form
    /// is up to the store: the PG sends no dup records, a store keeps the trimmed entries as the dup source.
    LogTrim {
        to: Eversion,
        dups_from: Option<Eversion>,
        /// `to` is above the persisted tail (a PG trims forward only): the store sets the tail without reading it.
        tail_up: bool,
    },
    /// Remove entries with `version.version > to.version`; head := `to`; rollback bounds clamped.
    LogRewind {
        to: Eversion,
    },
    /// Set the log head (and the rollback bounds) without touching entries: the head may be newer than the last
    /// entry (after a PG split the head is the parent's, the entries only those of the child).
    LogSetHead(Eversion),
    /// Replace the whole log (claim / backfill reset).
    LogReplace(Box<PgLog>),
    /// Replace the dup list.
    LogDups(Vec<LogDup>),
    /// Missing-set delta: `Some(item)` = set, `None` = remove.
    Missing(Vec<(Hobject, Option<MissingItem>)>),
    /// Drop the whole missing set; `may_include_deletes` flag stored.
    MissingClear {
        may_include_deletes: bool,
    },
    /// Apply an object-store transaction (replwire wire form: v9 in `data` with empty `middle`,
    /// or v10 `middle`+`data`). Collection ids inside refer to this PG.
    ApplyTxn {
        middle: bytes::Bytes,
        data: bytes::Bytes,
    },
    /// Receive-pass block crcs of the `data` of the `ApplyTxn` right before (a replica's repop blob, grid at the
    /// payload, adr 0061 am. 7): the store reuses them instead of a crc pass. Purely a hint; ignored by every apply.
    TxnHint(crc::CrcHint),
    /// Same as `ApplyTxn` for the LOCAL skeleton form of a client write (`replwire::Transaction::encode_v9_split`):
    /// `skel` has the large write payloads out of line in `refs` (op order). Never goes on a wire.
    ApplyTxnSplit {
        skel: bytes::Bytes,
        refs: Vec<bytes::Bytes>,
        /// Known crcs of `refs` (receive-pass block crcs, adr 0061 am. 4): the store reuses them instead of a crc pass.
        /// May be empty or cover only some refs.
        hints: Vec<crc::CrcHint>,
    },
    /// Remove one object (head or clone or temp) if present. A clone also leaves the SnapMapper.
    RemoveObject(Hobject),
    /// SnapMapper mutations (spec snaptrim 4), applied in the same txn as the object change they belong to.
    SnapMap(Vec<crate::snaps::MapOp>),
    /// PG split, executed FIRST (whatever its position in the txn): carve every child out of this PG's
    /// collection (objects with `hash & (2^bits-1) == child seed`, temp objects stay), create the child PGs with
    /// their complete persisted state, and set this collection's bits. A child that already exists (redo after a
    /// crash) is left untouched; only the parent's copies of its objects are dropped. Idempotent.
    SplitOut {
        /// `split_bits(parent, new pg_num)` for the parent collection.
        parent_bits: u32,
        children: Vec<SplitChild>,
    },
    /// EC: append entries like `LogAppend` but leave `can_rollback_to` / `rollback_info_trimmed_to` untouched (head :=
    /// last entry). Replicated pools never use this (adr 0040).
    LogAppendKeep(Vec<LogEntry>),
    /// EC: set BOTH rollback cursors absolutely (`can_rollback_to`, `rollback_info_trimmed_to`); head unchanged. Later
    /// ops of the same txn win. The stash cleanup itself is a [`StoreOp::Shard`] in the same txn.
    LogCursors {
        can_rollback_to: Eversion,
        rollback_info_trimmed_to: Eversion,
    },
    /// EC hint, no write: the persisted `_loghead` (head, `can_rollback_to`, `rollback_info_trimmed_to`) at this point of
    /// the txn equals this triple (the PG's in-memory log). Lets the store skip the `_loghead` read-back of a later
    /// `LogAppendKeep` / `LogCursors` (adr 0160 am. 2). Ignored when the store already knows the value from an earlier
    /// op of the txn; debug builds check it against the stored value.
    LogHeadIs(Eversion, Eversion, Eversion),
    /// EC: shard-object mutations (stash/rollback), see [`ShardOp`]. Objects are `ghobject{soid, gen, shard of the PG}`.
    Shard(Vec<ShardOp>),
    /// PG merge (this PG is the target), executed FIRST: absorb every object of each source PG collection (absent
    /// source = skipped), then remove the sources completely (after this txn is durable), set the collection bits.
    /// Idempotent.
    MergeIn {
        sources: Vec<SpgT>,
        bits: u32,
    },
}

impl StoreOp {
    /// May change an object of the PG (data, attrs, omap, existence): everything but the PG's own metadata (info,
    /// log, missing set, SnapMapper). Unknown = yes (adr 0160 D5: an object-state cache is dropped on these).
    pub fn touches_objects(&self) -> bool {
        !matches!(
            self,
            StoreOp::CreatePg
                | StoreOp::PutEpoch(_)
                | StoreOp::PutInfo(_)
                | StoreOp::PutPastIntervals(_)
                | StoreOp::LogAppend(_)
                | StoreOp::LogAppendFast(_)
                | StoreOp::LogTrim { .. }
                | StoreOp::LogRewind { .. }
                | StoreOp::LogSetHead(_)
                | StoreOp::LogReplace(_)
                | StoreOp::LogDups(_)
                | StoreOp::Missing(_)
                | StoreOp::MissingClear { .. }
                | StoreOp::TxnHint(_)
                | StoreOp::SnapMap(_)
                | StoreOp::LogAppendKeep(_)
                | StoreOp::LogCursors { .. }
                | StoreOp::LogHeadIs(..)
        )
    }
}

/// Mutation of one shard object of an EC PG at a generation (`generation == u64::MAX` = the live object, otherwise a stash).
/// All ops are no-ops on a missing source (never an error: rollback must be re-runnable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShardOp {
    Remove {
        soid: Hobject,
        generation: u64,
    },
    /// Rename inside the PG collection (replaces an existing destination).
    Rename {
        soid: Hobject,
        from_gen: u64,
        to_gen: u64,
    },
    Truncate {
        soid: Hobject,
        generation: u64,
        size: u64,
    },
    /// `None` value = remove the attribute.
    SetAttrs {
        soid: Hobject,
        generation: u64,
        attrs: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    },
    /// Copy `[off, off+len)` (same offsets) from one generation of the object to another; the destination is created
    /// when absent.
    CloneRange {
        soid: Hobject,
        from_gen: u64,
        to_gen: u64,
        off: u64,
        len: u64,
    },
    /// Mode O EC_OMAP roll-forward (ec-optimized.md 12.2) on one generation: header, clear, then updates in order.
    /// No-op when that generation does not exist (crash re-run, object removed meanwhile).
    Omap {
        soid: Hobject,
        generation: u64,
        omap: ec::moddesc::EcOmap,
    },
}

/// One child of a [`StoreOp::SplitOut`].
#[derive(Debug, Clone, PartialEq)]
pub struct SplitChild {
    pub spg: SpgT,
    /// `split_bits(child, new pg_num)`: the child owns objects with `hash & (2^bits-1) == child seed`.
    pub bits: u32,
    /// Complete durable state of the child at the split epoch.
    pub state: Box<PersistedPg>,
}

/// Ordered mutations applied atomically.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StoreTxn {
    pub ops: Vec<StoreOp>,
}
impl StoreTxn {
    pub fn push(&mut self, op: StoreOp) {
        self.ops.push(op);
    }
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
    pub fn take(&mut self) -> StoreTxn {
        StoreTxn {
            ops: std::mem::take(&mut self.ops),
        }
    }
}

/// Everything a PG reloads at boot.
#[derive(Debug, Clone, PartialEq)]
pub struct PersistedPg {
    pub info: PgInfo,
    pub log: PgLog,
    pub missing: PgMissing,
    pub past_intervals: PastIntervals,
    /// Last map epoch the PG processed.
    pub epoch: u32,
}

/// A log entry as the store writes it: its version (the key) and its encoding (`denc` of the `LogEntry`, the value).
/// Built once by the PG (a replica keeps the bytes of the repop, the primary those it sends): the store copies no entry
/// and encodes none.
#[derive(Debug, Clone, PartialEq)]
pub struct EncLogEntry {
    pub version: Eversion,
    pub bl: bytes::Bytes,
}

impl EncLogEntry {
    pub fn of(e: &LogEntry) -> EncLogEntry {
        EncLogEntry {
            version: e.version,
            bl: denc::to_vec(e).expect("log entry encodes").into(),
        }
    }
    pub fn entry(&self) -> denc::Result<LogEntry> {
        denc::from_slice(&self.bl)
    }
}

impl PersistedPg {
    /// Bring the head and the log-progress fields of `info` up to the log. On a store with lazy PG info a client write
    /// persists its log entries in its own txn but neither `_loghead` nor `_info` (`Pg::info_adv`): after a crash both may
    /// lag the log by the writes since their last write (every other info change is written with its txn).
    /// `last_update` is the log head, `last_user_version` the newest of the entries, `log_tail` the log's, `last_complete`
    /// the last update when nothing is missing (a PG with missing objects always persists `info` with the write).
    pub fn normalize(&mut self) {
        // `_loghead` lags the entries of `LogAppendFast`: the head is the newest entry (replicated appends: rollback bounds =
        // head); a log trimmed empty ends at its tail
        let l = &mut self.log;
        let h = l.log.back().map_or(l.tail, |e| e.version);
        if h > l.head {
            (l.head, l.can_rollback_to, l.rollback_info_trimmed_to) = (h, h, h);
        }
        if self.log.head > self.info.last_update {
            self.info.last_update = self.log.head;
            // the stats of the writes since the last info write are not in `_info` (a replica takes them from the repops):
            // marked like a split child, the next scrub recounts them; a classic primary adopting this info as authoritative
            // then knows they are approximate
            self.info.stats.stats_invalid = true;
        }
        if self.log.tail > self.info.log_tail {
            self.info.log_tail = self.log.tail;
        }
        if let Some(uv) = self.log.log.iter().map(|e| e.user_version).max() {
            self.info.last_user_version = self.info.last_user_version.max(uv);
        }
        if self.missing.missing.is_empty() && self.info.last_complete < self.info.last_update {
            self.info.last_complete = self.info.last_update;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreReadError {
    /// Object absent.
    NoObject,
    /// Object present but its object_info / SnapSet / index entry is missing or undecodable (local damage).
    Corrupt,
    /// Version on disk differs from the requested one.
    VersionMismatch,
    /// The store failed to read (EIO, checksum, ...).
    Io,
}

/// Result of [`PgStoreOps::list_objects`]: absent, corrupt and unreadable are distinct (never conflate them: a
/// listing is the base of backfill removal decisions, adr 0042 / peering.md 7.2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ObjListing {
    /// Healthy objects with their version.
    pub objs: Vec<(Hobject, Eversion)>,
    /// Objects present in the store whose object_info is damaged: never pushed, never counted as absent.
    pub corrupt: Vec<Hobject>,
    /// Next unlisted object (`Hobject::MAX()` = exhausted).
    pub next: Hobject,
}

impl ObjListing {
    pub fn empty() -> Self {
        ObjListing {
            next: Hobject::MAX(),
            ..Default::default()
        }
    }
    /// Highest object of the listing, healthy or corrupt.
    pub fn last(&self) -> Option<&Hobject> {
        match (self.objs.last(), self.corrupt.last()) {
            (Some((a, _)), Some(b)) => Some(a.max(b)),
            (Some((a, _)), None) => Some(a),
            (None, b) => b,
        }
    }
    /// All names in order (healthy + corrupt).
    pub fn names(&self) -> Vec<Hobject> {
        let mut v: Vec<Hobject> = self
            .objs
            .iter()
            .map(|(h, _)| h.clone())
            .chain(self.corrupt.iter().cloned())
            .collect();
        v.sort();
        v
    }
}

/// The NVMe store as seen by the PG machinery. Reads are synchronous queries (the real store
/// serves them from its caches/index or the driver wraps its async reads); writes arrive as
/// `Action::Persist` and are applied by [`PgStoreOps::submit`].
/// Pool options `compression_*` (pool_opts keys 6..10); empty string / 0 = unset (the OSD default applies).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PoolCompOpts {
    pub mode: String,
    pub algorithm: String,
    pub required_ratio: f64,
    pub min_blob: u64,
    pub max_blob: u64,
}

/// A piece of a still arriving payload written ahead ([`PgStoreOps::pre_write`], adr 0477): opaque store handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreTicket {
    pub shard: u32,
    pub id: u64,
}

/// Run the `warm*` probes `f` under residency lease `lease` (0 = none, run as is).
pub(crate) fn with_lease<R>(store: &impl PgStoreOps, lease: u64, f: impl FnOnce() -> R) -> R {
    if lease == 0 {
        return f();
    }
    store.lease_use(lease);
    let r = f();
    store.lease_use(0);
    r
}

pub trait PgStoreOps {
    /// Receiver-side pre-write (adr 0477): write `piece` (whole 4 KiB blocks of a large write payload for `spg` that is
    /// still arriving, memory nobody writes again) to free blocks now. A later txn of `spg` whose data run starts at the
    /// piece's first byte takes those blocks instead of writing; an unclaimed piece is returned when that txn stages or
    /// by [`pre_release`](Self::pre_release). Nothing references the blocks before such a txn commits. `None` = not
    /// written ahead (default: stores without it).
    fn pre_write(&self, _spg: SpgT, _piece: &bytes::Bytes) -> Option<PreTicket> {
        None
    }
    /// Bytes of a pre-write piece (one store data run: a txn claims a piece cut on its grid whole); 0 = this store
    /// does not write ahead.
    fn pre_piece(&self) -> usize {
        0
    }
    /// A write of `pool` stores its payload raw, so a piece written ahead can be claimed (a compressing pool stores
    /// through the codec: nothing would claim it). Default false: stores without pre-write.
    fn pre_pool(&self, _pool: u64) -> bool {
        false
    }
    /// Count of pieces that stopped being open (taken by a txn or released) so far: while it does not move, every
    /// open ticket is still open.
    fn pre_closed(&self) -> u64 {
        0
    }
    /// The piece of `t` is still open: not taken by a txn, not released (its holder must release it when its frame is
    /// gone). False for stale tickets.
    fn pre_open(&self, _t: PreTicket) -> bool {
        false
    }
    /// The frame of a pre-written piece is gone (crc failure, connection loss, op dropped or done): return the piece's
    /// blocks unless a txn claimed them. Stale tickets are ignored.
    fn pre_release(&self, _t: PreTicket) {}
    fn list_pgs(&self) -> Vec<SpgT>;
    fn load_pg(&self, spg: SpgT) -> Option<PersistedPg>;
    /// Apply a PG transaction atomically. Called by the driver when it executes `Persist`.
    fn submit(&mut self, spg: SpgT, txn: &StoreTxn);
    /// Size + object_info + snapset of an object for building recovery pushes. Errors are typed: `NoObject` (absent),
    /// `Corrupt` (present, damaged oi/snapset), `Io` (read failed).
    fn recovery_info_checked(
        &self,
        spg: SpgT,
        soid: &Hobject,
    ) -> Result<ObjectRecoveryInfo, StoreReadError>;
    /// [`Self::recovery_info`] collapsed to "usable copy or not": ONLY for callers where every failure means "cannot
    /// push this object" (never derive a deletion or an absence from `None`).
    fn recovery_info(&self, spg: SpgT, soid: &Hobject) -> Option<ObjectRecoveryInfo> {
        self.recovery_info_checked(spg, soid).ok()
    }
    /// Does the object hold MORE than `limit` omap keys? (`None` = unknown / unreadable.) Omap keys are not counted
    /// (adr 0610): the store answers by a bounded cursor scan of at most `limit + 1` keys. Backfill uses it to give
    /// heavy objects (a push of more than one chunk) a batch of their own.
    fn omap_keys_over(&self, spg: SpgT, soid: &Hobject, limit: u64) -> Option<bool>;
    /// Next push chunk of `ri` after `before` (spec replication.md 6.3). `ri.size` is final.
    fn build_push(
        &self,
        spg: SpgT,
        ri: &ObjectRecoveryInfo,
        before: &ObjectRecoveryProgress,
        max_chunk: u64,
        max_omap_entries: usize,
    ) -> Result<PushOp, StoreReadError>;
    /// Objects of the PG in hobject order starting at `begin` (inclusive), skipping pgmeta and
    /// temp objects: at least `min` (if available) and at most `max`; returns the list and the
    /// next unlisted object (`Hobject::MAX()` when exhausted). Objects with a damaged object_info are reported in
    /// `corrupt`; a read error is `Err` (never a partial list).
    fn list_objects(
        &self,
        spg: SpgT,
        begin: &Hobject,
        min: usize,
        max: usize,
    ) -> Result<ObjListing, StoreReadError>;
    /// Temp objects of the PG (recovery / copy staging) the store still holds: leftovers of a crash. The PG removes
    /// them at its first interval, like the temps it made itself.
    fn list_temps(&self, _spg: SpgT) -> Vec<Hobject> {
        Vec::new()
    }
    /// Version (oi.version) of an object. Typed: `NoObject` = absent (a new object), `Corrupt` / `Io` = unknown
    /// (never treat as absent: a write must not log prior version 0'0 for an object that exists).
    fn object_version(&self, spg: SpgT, soid: &Hobject) -> Result<Eversion, StoreReadError>;
    /// `(num_objects, num_bytes)` for stats.
    fn object_stats(&self, _spg: SpgT) -> (u64, u64) {
        (0, 0)
    }
    /// `(physical bytes, logical bytes)` of the PG's compressed extents (adr 0059 am. 1; statfs `data_compressed*`).
    fn compress_stats(&self, _spg: SpgT) -> (u64, u64) {
        (0, 0)
    }
    /// Start a fresh scrub chunk, discarding any abandoned digest/media continuation.
    fn reset_scrub(&self, _spg: SpgT) {}

    /// One slice of the replica scrub map over `[start, end)` (spec scrub.md 3): at most `max_objects` objects, and
    /// (deep) stop after about `max_bytes` of object data (at least one object per slice). `next` continues.
    fn build_scrub_map(
        &self,
        spg: SpgT,
        start: &Hobject,
        end: &Hobject,
        deep: bool,
        max_objects: usize,
        max_bytes: u64,
    ) -> crate::scrub::ScrubPart;
    /// EC sub-read: bytes `[off, off+len)` of the LIVE shard object (short read at EOF, empty past EOF) and the stored
    /// object size. `Err` = negative errno (-2 absent, -5 I/O).
    fn ec_read(
        &self,
        _spg: SpgT,
        _soid: &Hobject,
        _off: u64,
        _len: u64,
    ) -> Result<(Vec<u8>, u64), i32> {
        Err(-95)
    }
    /// [`Self::ec_read`] plus `crc32c(!0, bytes)` when the store knows it without a pass (whole verified blocks).
    fn ec_read_crc(
        &self,
        spg: SpgT,
        soid: &Hobject,
        off: u64,
        len: u64,
    ) -> Result<(Vec<u8>, u64, Option<u32>), i32> {
        self.ec_read(spg, soid, off, len).map(|(d, s)| (d, s, None))
    }
    /// [`Self::ec_read_crc`] as pieces in order (their concatenation is the data), each with `crc32c(!0, piece)` when the
    /// store knows it without a pass. A store that holds verified device / prefetch buffers hands them by reference (no
    /// copy; the replicated read path does the same, adr 0043 am. 13). Default: the one copied buffer.
    #[expect(clippy::type_complexity)]
    fn ec_read_shared(
        &self,
        spg: SpgT,
        soid: &Hobject,
        off: u64,
        len: u64,
    ) -> Result<(Vec<(bytes::Bytes, Option<u32>)>, u64), i32> {
        self.ec_read_crc(spg, soid, off, len).map(|(d, s, c)| {
            let p = if d.is_empty() {
                Vec::new()
            } else {
                vec![(bytes::Bytes::from(d), c)]
            };
            (p, s)
        })
    }
    /// EC sub-read: every xattr of the live shard object (names as stored). `Err` = negative errno.
    fn ec_getattrs(&self, _spg: SpgT, _soid: &Hobject) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, i32> {
        Err(-95)
    }
    /// One xattr of the live shard object (`Ok(None)` = attr absent). Default: from [`Self::ec_getattrs`].
    fn ec_getattr(&self, spg: SpgT, soid: &Hobject, name: &[u8]) -> Result<Option<Vec<u8>>, i32> {
        self.ec_getattrs(spg, soid).map(|mut a| a.remove(name))
    }
    /// Mode O sub-read (ec-optimized.md 12.3): omap header of the live shard object.
    fn ec_omap_header(&self, _spg: SpgT, _soid: &Hobject) -> Result<Vec<u8>, i32> {
        Err(-95)
    }
    /// Mode O sub-read: omap entries after the cursor (ascending) until `max_entries` or about `max_bytes`
    /// ([`crate::ecopt::omap_batch`]); `true` = no more entries follow. `after`: `None` = from the first key (the empty
    /// key included), `Some(k)` = keys strictly greater than `k` (`Some(b"")` skips only the empty key).
    #[expect(clippy::type_complexity)]
    fn ec_omap_read(
        &self,
        _spg: SpgT,
        _soid: &Hobject,
        _after: Option<&[u8]>,
        _max_bytes: u64,
        _max_entries: usize,
    ) -> Result<(Vec<(Vec<u8>, Vec<u8>)>, bool), i32> {
        Err(-95)
    }
    /// EC: every stash object `(hobject, generation)` of the PG (generation != NO_GEN); input of the stash GC at
    /// activation (adr 0040).
    fn ec_list_stash(&self, _spg: SpgT) -> Vec<(Hobject, u64)> {
        Vec::new()
    }
    /// Scrub map slice of an EC shard (adr 0039): like `build_scrub_map` with the shard digest rules of ec.md 7.7.
    /// `mode` = L0 (hinfo hash check), L1 (digest 0) or O (whole-file crc), `chunk` = chunk size.
    #[expect(clippy::too_many_arguments)]
    fn build_scrub_map_ec(
        &self,
        spg: SpgT,
        start: &Hobject,
        end: &Hobject,
        deep: bool,
        max_objects: usize,
        max_bytes: u64,
        _mode: replwire::ecscrub::EcScrubMode,
        _chunk: u32,
    ) -> crate::scrub::ScrubPart {
        self.build_scrub_map(spg, start, end, deep, max_objects, max_bytes)
    }
    /// Asynchronous commit (adr 0008 / M2.4): apply or park `txn` (fence reads until applied) and report durability
    /// through [`PgStoreOps::poll_commits`] under `token`. Default: synchronous `submit`, durable at once.
    fn queue(&mut self, spg: SpgT, txn: &StoreTxn, _token: u64) -> Queued {
        self.submit(spg, txn);
        Queued::Durable
    }
    /// Append `(pg, token)` of every queued txn that became durable since the last call (in order per PG).
    fn poll_commits(&mut self, _out: &mut Vec<(SpgT, u64)>) {}
    /// End of the driver loop's pass (receive, cross-core pump, timers): the store may now group-commit what the pass
    /// queued (adr 0021 am. 67). Default: nothing to do.
    fn end_pass(&mut self) {}
    /// Transient staging backpressure; transport retains input before PG/log mutation.
    fn admission_ready(&self) -> bool {
        true
    }
    /// Destination-specific admission; stores without independent shards retain their global gate.
    fn admission_ready_for(&self, _spg: SpgT) -> bool {
        self.admission_ready()
    }
    /// Background work ns of the store's last poll (no message caused it; kept out of the core's message-cost learning).
    fn bg_ns(&self) -> u64 {
        0
    }
    /// Background PG deletion progress of this store (zeros when none ever ran).
    fn removal_progress(&self) -> RemovalProgress {
        RemovalProgress::default()
    }
    /// Cumulative inline-compression counters of this store (zeros when it never compresses).
    fn comp_perf(&self) -> CompPerf {
        CompPerf::default()
    }
    /// One non-blocking step of the queued PG deletions (queues the next deletion txn, never waits); true = this call
    /// queued a txn (progress). False: nothing to do now (none pending, one in flight, a cold page loading, paused): the
    /// driver goes on with the store's own I/O.
    /// `bound_ns` caps the CPU time of the step while client work waits on the core (`u64::MAX`: no client work).
    fn step_removals(&self, _bound_ns: u64) -> bool {
        false
    }
    /// Admission preflight for a client write of about `bytes` payload at PG `spg` (ADR 0021 amendment 6): false = the
    /// store has no room beyond its reserves, the op must not start (no log entry, no repop).
    fn write_room(&self, _spg: SpgT, _bytes: u64, _entries: u64) -> bool {
        true
    }
    /// Space preflight for a txn this OSD applies without a client admission of its own (replica write, EC sub-write,
    /// recovery push) of about `bytes` payload setting or removing `entries` tree entries (adr 0021 S4): false = the
    /// PG's store shard is at its system floor, applying it now would end in NoSpace (fail-stop). The caller holds the
    /// message (nothing applied, nothing logged) and asks again after store progress.
    fn apply_room(&self, _spg: SpgT, _bytes: u64, _entries: u64) -> bool {
        true
    }
    /// Clean shutdown (review M2): make everything durable in the store's checkpoint so the next mount replays nothing
    /// (a replay re-dirties every logged page and its first checkpoint freezes them all). Blocking; only after the OSD
    /// stopped serving. `Err` = the reason it could not (logged; the next mount replays as after a crash).
    fn checkpoint_on_exit(&self) -> Result<(), String> {
        Ok(())
    }
    /// Size pre-flight of the transaction a client write ships (`middle`/`data` = the wire form): `Err(TooBig(errno))` = the
    /// store could never apply it (record larger than the WAL ring allows, more tree pages than the txn budget, ...): the
    /// write must be refused with that errno BEFORE any log entry or repop exists (a txn the store refuses after
    /// the log append would fail the PG). `Err(Blocked)` = the check needs metadata pages that are loading (it never waits
    /// for them on the PG core): submit again after the wake. Called for every write, implementations return at once for
    /// small ones.
    fn check_write(
        &self,
        _spg: SpgT,
        _middle: &bytes::Bytes,
        _data: &bytes::Bytes,
    ) -> Result<(), crate::WriteErr> {
        Ok(())
    }
    /// [`PgStoreOps::check_write`] for the local skeleton form (`WriteReq::txn_refs` non-empty): `skel` + out-of-line payloads.
    fn check_write_split(
        &self,
        _spg: SpgT,
        _skel: &bytes::Bytes,
        _refs: &[bytes::Bytes],
    ) -> Result<(), crate::WriteErr> {
        Ok(())
    }
    /// Non-blocking readiness of the store pages a client op on `soid` over `[off, off+len)` walks (ADR 0021 am. 8):
    /// false = reads were submitted, park the op until [`PgStoreOps::take_wake`]. Default: always ready.
    fn warm(&self, _spg: SpgT, _soid: &Hobject, _off: u64, _len: u64) -> bool {
        true
    }
    /// Non-blocking data prefetch for a client READ of `soid` over `[off, off+len)` (after `warm` said ready,
    /// ADR 0043): false = device reads in flight, park until [`PgStoreOps::take_wake`]. Default: ready.
    fn warm_data(&self, _spg: SpgT, _soid: &Hobject, _off: u64, _len: u64) -> bool {
        true
    }
    /// [`PgStoreOps::warm_data`] for the source of an EC stash `clone_range` of `[off, off+len)` (same offset): a store
    /// that shares the range (adr 0021 am. 38) needs no data. Default: `warm_data`.
    fn warm_clone_src(&self, spg: SpgT, soid: &Hobject, off: u64, len: u64) -> bool {
        self.warm_data(spg, soid, off, len)
    }
    /// Like [`PgStoreOps::warm`] for the removal of `soid`: every page the remove visits (adr 0021 am. 33). Default: ready.
    fn warm_rm(&self, _spg: SpgT, _soid: &Hobject) -> bool {
        true
    }
    /// Open a residency lease for an op of `spg` that waits for its store loads (adr 0043 am. 18; 0 = the store needs
    /// none). The `warm*` probes run under it ([`PgStoreOps::lease_use`]) keep what they loaded resident (pages pinned,
    /// prefetch runs held: no eviction, no expiry) until [`PgStoreOps::lease_release`]; a refused prefetch admission
    /// keeps its queue place and is woken when capacity frees. The waiting op releases it once it consumed the data (or
    /// is dropped); [`PgStoreOps::lease_release_pg`] releases the rest at an interval change or PG teardown.
    fn lease_open(&self, _spg: SpgT) -> u64 {
        0
    }
    /// The lease of the `warm*` probes that follow (0 = none).
    fn lease_use(&self, _lease: u64) {}
    fn lease_release(&self, _lease: u64) {}
    fn lease_release_pg(&self, _spg: SpgT) {}
    /// No device IO in flight and nothing queued: a driver may sleep until the next timer / network event instead of
    /// polling for completions (the store needs no poll before its next periodic sweep). Default false (poll).
    fn io_quiet(&self) -> bool {
        false
    }
    /// The driver's core wake: the store calls it, from any thread, after publishing work completed off the owner thread
    /// (RocksDB OMAP workers), so an idle owner need not wait out its sleep cap. Default: ignored.
    fn set_owner_wake(&mut self, _w: std::sync::Arc<dyn Fn() + Send + Sync>) {}
    /// Work completed off the owner thread waits for the next poll: the driver's idle re-check after it announced its sleep
    /// (pairs with [`Self::set_owner_wake`]). Default false.
    fn handed_completion(&self) -> bool {
        false
    }
    /// Store not quiet ([`Self::io_quiet`] false) and the driver idle: time until a polled device may complete a command
    /// (`Some(0)` = due, poll), from the devices' learned service times (adr 0004 am. 1). `None` = no estimate: the
    /// driver keeps its own wait policy. Default `None`.
    fn io_wait_hint(&mut self) -> Option<std::time::Duration> {
        None
    }
    /// Diagnostic line (wake / prefetch state) for `tell dump_pgs`. Default empty.
    fn diag(&self) -> String {
        String::new()
    }
    /// Inline compression options of a pool as the osdmap carries them (adr 0059 am. 1); called on every map for every pool.
    /// Default: the store does not compress (the options are ignored).
    fn set_pool_compression(&self, _pool: u64, _o: &PoolCompOpts) {}
    /// Content digest algorithm of dedup info collection (`flashstore_dedup_digest`: `md5` or `sha256`). `false` = unknown name
    /// (the previous one stays). Default: ignored.
    fn set_dedup_digest(&self, _alg: &str) -> bool {
        true
    }
    /// Dedup info collection records all-zero objects too (`flashstore_dedup_zero_objects`). Default: ignored.
    fn set_dedup_zero_objects(&self, _on: bool) {}
    /// Deep scrub reads: object data in reads of `stride` bytes (`osd_deep_scrub_stride`), omap in pages of `keys` keys
    /// (`osd_deep_scrub_keys`). The digests do not depend on either. Default: ignored (the store reads as it likes).
    fn set_deep_scrub_reads(&self, _stride: u64, _keys: u64) {}
    /// This core's part of a dedup info listing (adr 0593-dedup-deep-scrub-reformat, dedup-collection.md 6); prunes on the
    /// way. `None`: the store keeps no dedup info; `Some(Err)`: the store failed to read its records.
    fn dedup_list(&self, _r: &DedupListReq) -> Option<Result<DedupListPart, String>> {
        None
    }
    /// This core's dedup records of `pool`: (approximate bytes, entries). `None`: no dedup info.
    fn dedup_stats(&self, _pool: i64) -> Option<(u64, u64)> {
        None
    }
    /// Remove this core's dedup records of `pool`. `None`: no dedup info.
    fn dedup_clear(&self, _pool: i64) -> Option<Result<(), String>> {
        None
    }
    /// Current unix nanoseconds from the clock that timestamps collected dedup records.
    /// Used once at deep-scrub session start so its cutoff shares the records' wall
    /// domain even after a backward clock correction. `None`: no dedup clock;
    /// simulations fall back to the PG's injected wall time.
    fn dedup_wall_ns(&self) -> Option<u64> {
        None
    }
    /// Whose scrub map of `spg` the next `build_scrub_map*` calls build: the PG primary's own (`true`) or a replica's map for
    /// the primary. Dedup info is collected only from the primary's own reads (adr 0593-dedup-deep-scrub-reformat). Default:
    /// ignored.
    fn scrub_role(&self, _spg: SpgT, _primary: bool) {}
    /// Deep-scrub reformat engine list of a pool (adr 0593-dedup-deep-scrub-reformat, grammar of dedup-reformat.md 2; empty =
    /// none); called on every map for every pool. Returns the unknown engine names for the caller to log. Default: no
    /// engines (the list is ignored).
    fn set_pool_reformat(&self, _pool: u64, _engines: &str) -> Vec<String> {
        Vec::new()
    }
    /// May client writes leave `_info` / `_loghead` behind the log (`StoreOp::LogAppendFast`, rebuilt by
    /// `PersistedPg::normalize` at load)? Only a store an older build refuses to mount (`FEAT_LAZY_PGINFO`). Default: no.
    fn lazy_info(&self) -> bool {
        false
    }
    /// Should a write to `spg` probe [`PgStoreOps::warm`] before it is applied (adaptive per physical shard: false while
    /// that shard's cache is warm)?
    fn probe_cold_for(&self, _spg: SpgT) -> bool {
        true
    }
    /// Non-blocking readiness of the pgmeta pages the next log entry of `spg` is appended to (the head of the sliding PG log,
    /// `head` = last entry version). `false` = their loads were submitted: park the write like a cold object (adr 0021
    /// am. 30). Default: ready.
    fn warm_log(&self, _spg: SpgT, _head: Eversion) -> bool {
        true
    }
    /// A store page load finished since the last call (parked ops may be ready).
    fn take_wake(&mut self) -> bool {
        false
    }
    /// Elastic pool (adr 0021 am. 53): messages this store wants delivered to other cores (requests to the pool owner core,
    /// answers to the cores of the borrowing shards). Appended in emission order. Default: none.
    fn pool_take(&self, _out: &mut Vec<PoolMsg>) {}
    /// Elastic pool: a message from another core, delivered exactly once. Default: ignored.
    fn pool_in(&self, _m: PoolMsg) {}
    /// [`PgStoreOps::take_wake`] with the specific part (adr 0043 am. 9): adds the tokens of the page loads and prefetch
    /// runs that completed to `ws`; `ws.all` when anything else woke. Default: every wake is `all`.
    fn take_wake_set(&mut self, ws: &mut crate::wake::WakeSet) -> bool {
        let w = self.take_wake();
        ws.all |= w;
        w
    }
    /// Sticky local failure (EIO/ENOSPC on commit, dead device): the OSD must stop serving and exit.
    fn failed(&self) -> Option<String> {
        None
    }
    /// Notes about slow / large structural operations for the operator log.
    fn take_notes(&mut self) -> Vec<String> {
        Vec::new()
    }
    /// After the PGs were loaded and advanced at start: drop collections that hold no PG (interrupted split).
    fn gc_orphans_after_load(&mut self) {}
    /// Operator `flush_journal`: ask for a checkpoint of every shard this handle owns (does not wait).
    fn request_checkpoint(&mut self) {}
    /// Operator `dump_mempools`: RAM consumers of the store as `(pool name, items, bytes)`; empty = not accounted.
    fn mem_pools(&self) -> Vec<(&'static str, u64, u64)> {
        Vec::new()
    }
    /// `perf dump` store section (adr 0021 am. 43): checkpoint / back-pressure counters `(name, gauge, value)` of the shards
    /// this handle owns. Default: none.
    fn store_counters(&self) -> Vec<(&'static str, bool, u64)> {
        Vec::new()
    }
    /// Operator `store census` (adr 0533): extent census of the last complete idle sweep of the shards
    /// this handle owns as `(name, value)`; `request` = walk every collection in the next sweep. Default: none.
    fn store_census(&mut self, _request: bool) -> Vec<(&'static str, u64)> {
        Vec::new()
    }
    /// Operator `cache status`: cache counters and gauges `(name, value)` of the shards this handle owns. Default: none.
    fn cache_status(&self) -> Vec<(&'static str, u64)> {
        Vec::new()
    }
    /// Operator `cache drop`: drop every clean cache of the shards this handle owns; `(name, bytes or entries)` of what
    /// went. Default: nothing cached.
    fn drop_caches(&mut self) -> Vec<(&'static str, u64)> {
        Vec::new()
    }
    /// Operator allocator reports: `(data capacity bytes, free runs as (first block, blocks))` of the shards this
    /// handle owns; None = not a device store. Scans the allocation bitmaps (operator command, not a hot path).
    fn free_report(&self) -> Option<(u64, Vec<(u64, u64)>)> {
        None
    }
    /// Capacity of the part of the device this store handle covers (a per-core store covers its own shards only;
    /// the OSD sums the cores). None = not a device store.
    fn space(&self) -> Option<Space> {
        None
    }
    /// Per-shard fullness inputs for periodic capacity reporting. Default: this store has no device shards.
    fn space_shards(&self) -> Vec<ShardSpace> {
        Vec::new()
    }
    /// Store shards of the mounted device (adr 0021): the OSD's input lanes and windows are indexed by them. 1 = this
    /// store has no shards.
    fn shards(&self) -> u32 {
        1
    }
    /// Multi-core: PG `pgid` lives on store shard `shard` (collections are created / found there). Called before
    /// the first transaction of a PG that does not sit on its hash shard (split children, migrated PGs).
    fn place(&self, _pgid: PgT, _shard: u32) {}
    /// The store shard `pgid` lives on (None = the store has no shards).
    fn shard_of_pg(&self, _pgid: PgT) -> Option<u32> {
        None
    }
    /// Migration (adr 0031): next ops of the export of `spg`, `true` = last batch.
    fn mig_export(
        &self,
        _spg: SpgT,
        _cur: &mut ExportCursor,
        _budget: usize,
    ) -> Result<(Vec<MigOp>, bool), String> {
        Err("migration unsupported by this store".into())
    }
    /// Apply exported ops (the PG was `place`d here).
    fn mig_import(&self, _spg: SpgT, _ops: Vec<MigOp>) -> Result<(), MigImportError> {
        Err(MigImportError::Failed(
            "migration unsupported by this store".into(),
        ))
    }
    /// How often `spg` was migrated into this store (the higher generation wins a duplicate).
    fn mig_gen(&self, _spg: SpgT) -> u64 {
        0
    }
    /// Is the PG complete in this store (has its state)?
    fn mig_complete(&self, _spg: SpgT) -> bool {
        false
    }
    /// Delete the PG's collections (after the destination acknowledged its copy).
    fn mig_remove(&self, _spg: SpgT) -> Result<(), String> {
        Err("migration unsupported by this store".into())
    }
    /// Wait until everything queued so far is durable.
    fn mig_sync(&self) -> Result<(), String> {
        Ok(())
    }
    /// Migration headroom (adr 0031 am. 4, 5): bytes a copy of `spg` needs at its destination, from the stored
    /// collection itself (data, objects, exact omap bytes). Default: no capacity accounting.
    fn mig_bytes(&self, _spg: SpgT) -> Result<u64, String> {
        Ok(0)
    }
    /// Reserve `bytes` on device shard `shard` for PG `pgid` moving in; false = no room now, nothing held.
    fn mig_reserve(&self, _pgid: PgT, _shard: u32, _bytes: u64) -> bool {
        true
    }
    /// The moves into this store ended: give back the headroom left.
    fn mig_release_all(&self) {}
    /// `(device shard, bytes a copy could still reserve)` of the shards this handle owns.
    fn mig_rooms(&self) -> Vec<(u32, u64)> {
        Vec::new()
    }
    /// Elastic pool: `bytes` the deferred moves into device shard `shard` need (0 = none); the shard borrows for them.
    fn mig_want(&self, _shard: u32, _bytes: u64) {}
    /// SnapMapper (spec snaptrim 4): up to `max` clones mapped to `snap`, ascending key order. Reads see queued txns.
    /// `Ok(empty)` = the index has no clone of `snap`; an unreadable / undecodable index is `Err` (never "empty").
    fn snapmap_next(
        &self,
        _spg: SpgT,
        _snap: u64,
        _max: usize,
    ) -> Result<Vec<Hobject>, StoreReadError> {
        Ok(Vec::new())
    }
    /// Snaps mapped to `clone` (ascending).
    fn snapmap_get(&self, _spg: SpgT, _clone: &Hobject) -> Option<Vec<u64>> {
        None
    }
    /// Snapshot mapping for rollback bookkeeping. Read/corruption errors must not become an absent old mapping.
    fn snapmap_get_checked(
        &self,
        spg: SpgT,
        clone: &Hobject,
    ) -> Result<Option<Vec<u64>>, StoreReadError> {
        Ok(self.snapmap_get(spg, clone))
    }
    /// Walk the forward index (`snap`, clone) from key `from` (inclusive; start with [`crate::snaps::fwd_prefix`]): up to
    /// `max` entries as their snaps (one per entry, ascending) and, when entries remain, the key to continue from.
    /// Cost = entries read, whatever the id range. An unreadable / undecodable index is `Err`.
    fn snapmap_scan(
        &self,
        _spg: SpgT,
        _from: &[u8],
        _max: usize,
    ) -> Result<(Vec<u64>, Option<Vec<u8>>), StoreReadError> {
        Ok((Vec::new(), None))
    }
    /// Scrub of the mapper over the clones in `[start, end)` against the SnapSets of their heads (spec snaptrim 8.2):
    /// the repairing mutations plus operator messages. Read-only; the caller submits the mutations.
    fn snapmap_check(
        &self,
        _spg: SpgT,
        _start: &Hobject,
        _end: &Hobject,
    ) -> (Vec<crate::snaps::MapOp>, Vec<String>) {
        (Vec::new(), Vec::new())
    }
    /// Deep scrub, first chunk: operator messages for mapper keys that name no clone (one walk of the whole mapper;
    /// such a key belongs to no chunk of [`PgStoreOps::snapmap_check`]).
    fn snapmap_key_scan(&self, _spg: SpgT) -> Vec<String> {
        Vec::new()
    }
}

/// Prefix of a [`PgStoreOps::snapmap_check`] message that reports an INCOMPLETE check (a read failed): the PG counts it
/// as an error and says so in the cluster log, it is never a repair finding.
pub const SNAPMAP_READ_ERR: &str = "snapmap check incomplete: ";

fn clone_name(c: &Hobject) -> String {
    format!("{}:{:x}", String::from_utf8_lossy(&c.oid), c.snap.0)
}

/// Shared mapper check: `clones` = `(clone, mapped snaps)` for every clone object of the chunk, `head_ss` = SnapSet of
/// the head of a clone (None = no head / unreadable: skip, scrub reports the SnapSet problem).
pub fn snapmap_check_with(
    clones: Vec<(Hobject, Option<Vec<u64>>)>,
    mut head_ss: impl FnMut(&Hobject) -> Option<SnapSet>,
) -> (Vec<crate::snaps::MapOp>, Vec<String>) {
    let (mut ops, mut msgs) = (Vec::new(), Vec::new());
    for (c, have) in clones {
        let mut head = c.clone();
        head.snap = denc::types::SnapId::NOSNAP;
        let Some(ss) = head_ss(&head) else { continue };
        let Some(want) = ss.clone_snaps.get(&c.snap) else {
            continue;
        };
        let mut want: Vec<u64> = want.iter().map(|s| s.0).collect();
        want.sort_unstable();
        want.dedup();
        if want.is_empty() || have.as_ref() == Some(&want) {
            continue;
        }
        msgs.push(match have {
            None => format!("snaps missing in mapper for {}, repaired", clone_name(&c)),
            Some(_) => format!("snap mapper error on {}, repaired", clone_name(&c)),
        });
        ops.push(crate::snaps::MapOp::Set {
            clone: c,
            snaps: want,
        });
    }
    (ops, msgs)
}

/// Capacity numbers of one store handle (see [`PgStoreOps::space`]), the fields of `StoreStatfs` that add up.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Space {
    pub total: u64,
    /// Capacity available after the store's fullness charge; metadata pressure may withhold additional space.
    pub available: u64,
    /// Physical object-data bytes, excluding metadata and withheld capacity (Ceph DATA).
    pub allocated: u64,
    pub internal_metadata: u64,
    /// The elastic pool is in use (adr 0021 am. 53): the pool's free chunks are counted by the owner's handle only.
    pub pooled: bool,
    /// Fill (0..=1) of the fullest shard of this handle against what it can still get (its capacity plus, pooled, the
    /// pool it may borrow; `StoreStatfs::fullest_shard_pct`): the OSD's fullness is never below it (adr 0021 S4).
    pub fullest: f64,
}

/// Periodic capacity and fullness inputs for one physical store shard.
#[derive(Debug, Clone, PartialEq)]
pub struct ShardSpace {
    pub shard: u32,
    pub space: Space,
    pub data_used_bytes: u64,
    pub data_held_bytes: u64,
    pub data_reserved_bytes: u64,
    pub data_reserve_bytes: u64,
    pub meta_used_pages: u64,
    pub meta_cell_used_pages: u64,
    pub meta_base_pages: u64,
    pub meta_cell_blocks: u64,
    pub meta_blocks_per_page: u64,
    pub meta_dirty_pages: u64,
    pub meta_run_pages: u64,
    pub meta_usable_pages: u64,
    pub meta_grow_blocked: bool,
    pub elastic: bool,
    pub meta_growth_failure: Option<MetaGrowthFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Store-adapter form of the last actual metadata-growth failure for one shard.
///
/// This diagnostic remains present after the shard recovers and changes only on a later failure that blocks growth.
pub struct MetaGrowthFailure {
    /// One-based failure count for the mounted shard, saturating at `u64::MAX`.
    pub sequence: u64,
    /// Stable reason string: `image_limit`, `insufficient_free_blocks`, or `no_contiguous_run`.
    pub reason: &'static str,
    /// UTC Unix wall-clock timestamp at capture, in nanoseconds.
    pub unix_time_ns: u64,
    /// Store driver's most recent poll timestamp, in nanoseconds; zero means no poll has run yet.
    pub store_poll_time_ns: u64,
    /// Free meta pages requested by the growth attempt.
    pub requested_free_pages: u64,
    /// Free meta pages observed at the failure.
    pub free_meta_pages: u64,
    /// Metadata cell size in store blocks.
    pub cell_blocks: u64,
    /// Tree pages in one metadata cell.
    pub pages_per_cell: u64,
    /// Allocator-free data blocks observed by the attempt.
    pub free_data_blocks: u64,
    /// Data blocks held until checkpoint/readers release them.
    pub held_data_blocks: u64,
    /// Allocator-reserved data blocks.
    pub reserved_data_blocks: u64,
    /// Reserve argument applied to this growth attempt.
    pub reserve_data_blocks: u64,
    /// Current elastic metadata image bytes.
    pub image_bytes: u64,
    /// Bytes reserved for image extension sections.
    pub image_reserve_bytes: u64,
    /// Bytes required by cells pending the active freeze.
    pub deferred_image_bytes: u64,
    /// Projected image size after adding one cell.
    pub image_needed_bytes: u64,
    /// Maximum image size indexable by the configured page size.
    pub image_limit_bytes: u64,
    /// Entirely free allocator windows (an O(1) counter).
    pub free_windows: u64,
}

/// Result of [`PgStoreOps::queue`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Queued {
    /// Applied and already durable.
    Durable,
    /// Applied (or, for a PG re-created while its old copy's deletion waits for space, applied in order once that
    /// deletion is done; the PG cannot activate before), durability reported later by `poll_commits`.
    Pending,
    /// The transaction itself is malformed (remote input): nothing applied, store healthy. Log + drop.
    Rejected(String),
    /// Local store failure: the store is now failed (`failed()`), nothing more will be accepted.
    Failed(String),
}

// ---- in-memory implementation ----------------------------------------------------------------

/// In-memory object.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemObj {
    pub data: Vec<u8>,
    pub xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
    pub omap: BTreeMap<Vec<u8>, Vec<u8>>,
    pub omap_header: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct MemPg {
    pub p: PersistedPg,
    pub objects: BTreeMap<Hobject, MemObj>,
    /// EC stash objects `(hobject, generation != NO_GEN)` (invisible to listing, scrub, recovery).
    pub stash: BTreeMap<(Hobject, u64), MemObj>,
    /// Debug: object removals `(name, how)`.
    pub removals: Vec<(Vec<u8>, &'static str)>,
    /// SnapMapper index of the PG.
    pub snapmap: crate::snaps::MemMap,
}

/// Plain in-memory store. `submit` applies immediately (the simulator decides when).
#[derive(Debug, Clone, Default)]
pub struct MemStore {
    #[cfg(feature = "test-knobs")]
    pub admission_paused: std::cell::Cell<bool>,
    pub pgs: BTreeMap<SpgT, MemPg>,
    /// Debug: mutations addressed to a PG that does not exist.
    pub orphan_writes: u64,
    pub orphan_ops: Vec<String>,
    /// Malformed transactions rejected (nothing applied).
    pub bad_txns: u64,
    pub last_bad_txn: Option<String>,
    /// Fault injection (tests): `list_objects` fails like an unreadable store.
    pub list_error: bool,
    /// Fault injection (tests): the `omap_keys_over` probe cannot answer (store read error).
    pub omap_probe_error: bool,
    /// Fault injection: the next recovery push build fails without failing the store.
    #[cfg(any(test, feature = "test-knobs"))]
    pub push_error: std::cell::RefCell<Option<StoreReadError>>,
    /// Fault injection (tests): the next `warm` probes answer "cold" this many times (cold tree pages).
    #[cfg(feature = "test-knobs")]
    pub warm_waits: std::cell::Cell<u32>,
    /// `warm` probes answered since creation (tests).
    #[cfg(feature = "test-knobs")]
    pub warm_calls: std::cell::Cell<u32>,
    /// Residency leases open (tests: id -> PG) and the last id given.
    #[cfg(feature = "test-knobs")]
    pub leases: std::cell::RefCell<BTreeMap<u64, SpgT>>,
    #[cfg(feature = "test-knobs")]
    pub lease_next: std::cell::Cell<u64>,
    /// Fault injection (tests): the next `warm_data` probes answer "device reads in flight" this many times.
    #[cfg(feature = "test-knobs")]
    pub data_waits: std::cell::Cell<u32>,
    /// `warm_data` probes answered since creation (tests).
    #[cfg(feature = "test-knobs")]
    pub data_calls: std::cell::Cell<u32>,
    /// Every range a `warm_data` probe asked for, i.e. whose device reads it started (tests: `(object, off, len)`).
    #[cfg(feature = "test-knobs")]
    pub data_probed: std::cell::RefCell<std::collections::BTreeSet<(Hobject, u64, u64)>>,
    /// Fault injection (tests): the next `warm_log` probes answer "cold" this many times (cold PG log head leaf).
    #[cfg(feature = "test-knobs")]
    pub log_waits: std::cell::Cell<u32>,
    /// `warm_log` probes answered since creation (tests).
    #[cfg(feature = "test-knobs")]
    pub log_calls: std::cell::Cell<u32>,
    /// The store does not take lazy PG info (an old-format store, `PgStoreOps::lazy_info` false): every client write
    /// persists `_info` and `_loghead`. Default false = lazy, like a store made by mkfs.
    pub eager_info: bool,
    /// Fault injection (tests): the SnapMapper index cannot be read (`snapmap_next`, `snapmap_check`).
    pub snapmap_error: bool,
}

impl MemStore {
    pub fn new() -> Self {
        Self::default()
    }
    /// Non-temp object map of a PG (for convergence checks).
    pub fn objects(&self, spg: SpgT) -> BTreeMap<Hobject, MemObj> {
        self.pgs
            .get(&spg)
            .map(|p| {
                p.objects
                    .iter()
                    .filter(|(h, _)| !h.is_temp())
                    .map(|(h, o)| (h.clone(), o.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
    /// One object (temp objects included) of a PG, for tests.
    pub fn object(&self, spg: SpgT, h: &Hobject) -> Option<MemObj> {
        self.pgs.get(&spg).and_then(|p| p.objects.get(h).cloned())
    }
    fn temp_list(&self, spg: SpgT) -> Vec<Hobject> {
        self.pgs
            .get(&spg)
            .map(|p| p.objects.keys().filter(|h| h.is_temp()).cloned().collect())
            .unwrap_or_default()
    }
    pub fn temp_objects(&self, spg: SpgT) -> usize {
        self.pgs
            .get(&spg)
            .map_or(0, |p| p.objects.keys().filter(|h| h.is_temp()).count())
    }
    /// EC stash objects of a PG (generation != NO_GEN), for tests.
    pub fn stash(&self, spg: SpgT) -> BTreeMap<(Hobject, u64), MemObj> {
        self.pgs
            .get(&spg)
            .map(|p| p.stash.clone())
            .unwrap_or_default()
    }
}

fn empty_persisted(spg: SpgT) -> PersistedPg {
    PersistedPg {
        info: PgInfo::new(spg),
        log: PgLog::default(),
        missing: PgMissing {
            may_include_deletes: true,
            ..Default::default()
        },
        past_intervals: PastIntervals::default(),
        epoch: 0,
    }
}

/// Largest object `MemStore` will materialize (remote input must not be able to ask for more memory).
pub const MEM_MAX_OBJECT: u64 = 128 << 20;

/// Object key inside a [`MemPg`]: live objects are `(hobject, u64::MAX)`, stash generations `(hobject, gen)`.
type GKey = (Hobject, u64);

fn gkey(g: &Ghobject) -> GKey {
    (g.hobj.clone(), g.generation)
}

impl MemPg {
    fn gget(&self, k: &GKey) -> Option<&MemObj> {
        if k.1 == Ghobject::NO_GEN {
            self.objects.get(&k.0)
        } else {
            self.stash.get(k)
        }
    }
    fn gget_mut(&mut self, k: &GKey) -> Option<&mut MemObj> {
        if k.1 == Ghobject::NO_GEN {
            self.objects.get_mut(&k.0)
        } else {
            self.stash.get_mut(k)
        }
    }
    fn gentry(&mut self, k: &GKey) -> &mut MemObj {
        if k.1 == Ghobject::NO_GEN {
            self.objects.entry(k.0.clone()).or_default()
        } else {
            self.stash.entry(k.clone()).or_default()
        }
    }
    fn gtake(&mut self, k: &GKey) -> Option<MemObj> {
        if k.1 == Ghobject::NO_GEN {
            self.objects.remove(&k.0)
        } else {
            self.stash.remove(k)
        }
    }
    fn gput(&mut self, k: &GKey, o: MemObj) {
        if k.1 == Ghobject::NO_GEN {
            self.objects.insert(k.0.clone(), o);
        } else {
            self.stash.insert(k.clone(), o);
        }
    }
}

/// Validate a decoded transaction against the current PG state before anything is applied: size
/// bounds and the spec'd source-existence rules (Clone/CloneRange2 of a missing source fails the
/// whole transaction; Truncate/rename/remove-style ops on missing objects are no-ops). Generations are
/// distinct objects; every object must carry the PG's own shard.
fn precheck_txn(pg: &MemPg, spg: SpgT, t: &Transaction<'_>) -> Result<(), String> {
    let mut ex: BTreeMap<GKey, bool> = BTreeMap::new();
    let exists = |ex: &BTreeMap<GKey, bool>, k: &GKey| {
        ex.get(k).copied().unwrap_or_else(|| pg.gget(k).is_some())
    };
    let lim = |a: u64, b: u64| -> Result<(), String> {
        match a.checked_add(b) {
            Some(e) if e <= MEM_MAX_OBJECT => Ok(()),
            _ => Err(format!("range {a}+{b} exceeds object limit")),
        }
    };
    for c in &t.colls {
        if !matches!(c, CollT::Pg(s) | CollT::PgTemp(s) if *s == spg) {
            return Err(format!("collection {c} outside pg {spg}"));
        }
    }
    for op in &t.ops {
        if matches!(op.op, TxnOp::Nop) {
            continue;
        }
        let o = |x: replwire::Ox| t.objs.get(x.0 as usize).map(gkey);
        let bad = || "object index out of range".to_string();
        match &op.op {
            TxnOp::Create { oid } | TxnOp::Touch { oid } | TxnOp::TouchTemp { oid, .. } => {
                ex.insert(o(*oid).ok_or_else(bad)?, true);
            }
            TxnOp::Write { oid, off, data } => {
                lim(*off, data.len() as u64)?;
                ex.insert(o(*oid).ok_or_else(bad)?, true);
            }
            TxnOp::Zero { oid, off, len } => {
                lim(*off, *len)?;
                ex.insert(o(*oid).ok_or_else(bad)?, true);
            }
            TxnOp::Truncate { size, .. } => lim(*size, 0)?,
            TxnOp::Remove { oid } => {
                ex.insert(o(*oid).ok_or_else(bad)?, false);
            }
            TxnOp::SetAttr { oid, .. }
            | TxnOp::SetAttrs { oid, .. }
            | TxnOp::OmapSetKeys { oid, .. }
            | TxnOp::OmapSetHeader { oid, .. } => {
                ex.insert(o(*oid).ok_or_else(bad)?, true);
            }
            TxnOp::Clone { oid, dest_oid } => {
                let (s, d) = (o(*oid).ok_or_else(bad)?, o(*dest_oid).ok_or_else(bad)?);
                if !exists(&ex, &s) {
                    return Err("clone of missing source".to_string());
                }
                ex.insert(d, true);
            }
            TxnOp::CloneRange2 {
                oid,
                dest_oid,
                src_off,
                len,
                dest_off,
            } => {
                let (s, d) = (o(*oid).ok_or_else(bad)?, o(*dest_oid).ok_or_else(bad)?);
                lim(*src_off, *len)?;
                lim(*dest_off, *len)?;
                if !exists(&ex, &s) {
                    return Err("clone_range of missing source".into());
                }
                ex.insert(d, true);
            }
            TxnOp::CollMoveRename { oid, dest_oid, .. } | TxnOp::TryRename { oid, dest_oid } => {
                let (s, d) = (o(*oid).ok_or_else(bad)?, o(*dest_oid).ok_or_else(bad)?);
                if exists(&ex, &s) {
                    ex.insert(s, false);
                    ex.insert(d, true);
                }
            }
            _ => {}
        }
    }
    for g in &t.objs {
        if g.shard != spg.shard && !g.is_pgmeta() {
            return Err(format!("object of shard {} in pg {spg}", g.shard.0));
        }
    }
    Ok(())
}

fn apply_txn(pg: &mut MemPg, spg: SpgT, middle: &[u8], data: &[u8]) -> Result<(), String> {
    let t = Transaction::decode(middle, data, replwire::DEFAULT_PAGE)
        .map_err(|e| format!("transaction decode: {e}"))?;
    precheck_txn(pg, spg, &t)?;
    for op in &t.ops {
        let o = |x: replwire::Ox| gkey(t.get_obj(x));
        match &op.op {
            TxnOp::Nop => {}
            TxnOp::Create { oid } | TxnOp::Touch { oid } | TxnOp::TouchTemp { oid, .. } => {
                pg.gentry(&o(*oid));
            }
            TxnOp::Write { oid, off, data } => {
                let ob = pg.gentry(&o(*oid));
                let end = *off as usize + data.len();
                if ob.data.len() < end {
                    ob.data.resize(end, 0);
                }
                // copy the payload parts into place (no staging copy per write)
                let mut at = *off as usize;
                for p in data.parts() {
                    ob.data[at..at + p.len()].copy_from_slice(p);
                    at += p.len();
                }
            }
            TxnOp::Zero { oid, off, len } => {
                let ob = pg.gentry(&o(*oid));
                let end = (*off + *len) as usize;
                if ob.data.len() < end {
                    ob.data.resize(end, 0);
                }
                ob.data[*off as usize..end].fill(0);
            }
            TxnOp::Truncate { oid, size } => {
                // no-op on a missing object (replication.md 1.6)
                if let Some(ob) = pg.gget_mut(&o(*oid)) {
                    ob.data.resize(*size as usize, 0);
                }
            }
            TxnOp::Remove { oid } => {
                let k = o(*oid);
                if pg.gtake(&k).is_some() && k.1 == Ghobject::NO_GEN {
                    pg.removals.push((k.0.oid, "TxnRemove"));
                }
            }
            TxnOp::SetAttr { oid, name, value } => {
                pg.gentry(&o(*oid))
                    .xattrs
                    .insert(name.to_vec(), value.to_vec());
            }
            TxnOp::SetAttrs { oid, attrs } => {
                let ob = pg.gentry(&o(*oid));
                for (k, v) in attrs {
                    ob.xattrs.insert(k.to_vec(), v.to_vec());
                }
            }
            TxnOp::RmAttr { oid, name } => {
                if let Some(ob) = pg.gget_mut(&o(*oid)) {
                    ob.xattrs.remove(*name);
                }
            }
            TxnOp::RmAttrs { oid } => {
                if let Some(ob) = pg.gget_mut(&o(*oid)) {
                    ob.xattrs.clear();
                }
            }
            TxnOp::Clone { oid, dest_oid } => {
                if let Some(src) = pg.gget(&o(*oid)).cloned() {
                    pg.gput(&o(*dest_oid), src);
                }
            }
            TxnOp::CloneRange2 {
                oid,
                dest_oid,
                src_off,
                len,
                dest_off,
            } => {
                // source existence was checked by precheck; bytes past the source size read as zeros
                // (same as the engine: the range is always fully written)
                let Some(src) = pg.gget(&o(*oid)) else {
                    continue;
                };
                let (s, l) = (*src_off as usize, *len as usize);
                let mut chunk = vec![0u8; l];
                let avail = src.data.len().saturating_sub(s).min(l);
                if avail > 0 {
                    chunk[..avail].copy_from_slice(&src.data[s..s + avail]);
                }
                let d = pg.gentry(&o(*dest_oid));
                let end = *dest_off as usize + l;
                if d.data.len() < end {
                    d.data.resize(end, 0);
                }
                d.data[*dest_off as usize..end].copy_from_slice(&chunk);
            }
            TxnOp::CollMoveRename { oid, dest_oid, .. } | TxnOp::TryRename { oid, dest_oid } => {
                // missing source: no-op; existing destination: replaced
                if let Some(src) = pg.gtake(&o(*oid)) {
                    pg.gput(&o(*dest_oid), src);
                }
            }
            TxnOp::OmapClear { oid } => {
                if let Some(ob) = pg.gget_mut(&o(*oid)) {
                    ob.omap.clear();
                    ob.omap_header.clear();
                }
            }
            TxnOp::OmapSetKeys { oid, pairs } => {
                let ob = pg.gentry(&o(*oid));
                for (k, v) in pairs {
                    ob.omap.insert(k.to_vec(), v.to_vec());
                }
            }
            TxnOp::OmapRmKeys { oid, keys } => {
                if let Some(ob) = pg.gget_mut(&o(*oid)) {
                    for k in keys {
                        ob.omap.remove(*k);
                    }
                }
            }
            TxnOp::OmapRmKeyRange { oid, first, last } => {
                if let Some(ob) = pg.gget_mut(&o(*oid)) {
                    ob.omap
                        .retain(|k, _| !(k.as_slice() >= *first && k.as_slice() < *last));
                }
            }
            TxnOp::OmapSetHeader { oid, header } => {
                pg.gentry(&o(*oid)).omap_header = header.to_vec();
            }
            // hints / collection management: nothing to do in memory
            _ => {}
        }
    }
    Ok(())
}

/// `ShardOp`s on the in-memory PG (rollback / stash cleanup): no-ops on a missing source.
fn apply_shard_ops(pg: &mut MemPg, ops: &[ShardOp]) {
    let k = |h: &Hobject, g: u64| -> GKey { (h.clone(), g) };
    for op in ops {
        match op {
            ShardOp::Remove { soid, generation } => {
                pg.gtake(&k(soid, *generation));
            }
            ShardOp::Rename {
                soid,
                from_gen,
                to_gen,
            } => {
                if from_gen != to_gen
                    && let Some(o) = pg.gtake(&k(soid, *from_gen))
                {
                    pg.gput(&k(soid, *to_gen), o);
                }
            }
            ShardOp::Truncate {
                soid,
                generation,
                size,
            } => {
                if let Some(o) = pg.gget_mut(&k(soid, *generation)) {
                    o.data.resize(*size as usize, 0);
                }
            }
            ShardOp::SetAttrs {
                soid,
                generation,
                attrs,
            } => {
                if let Some(o) = pg.gget_mut(&k(soid, *generation)) {
                    for (n, v) in attrs {
                        match v {
                            Some(v) => {
                                o.xattrs.insert(n.clone(), v.clone());
                            }
                            None => {
                                o.xattrs.remove(n);
                            }
                        }
                    }
                }
            }
            ShardOp::CloneRange {
                soid,
                from_gen,
                to_gen,
                off,
                len,
            } => {
                let Some(src) = pg.gget(&k(soid, *from_gen)) else {
                    continue;
                };
                let (s, l) = (*off as usize, *len as usize);
                let mut chunk = vec![0u8; l];
                let avail = src.data.len().saturating_sub(s).min(l);
                if avail > 0 {
                    chunk[..avail].copy_from_slice(&src.data[s..s + avail]);
                }
                let d = pg.gentry(&k(soid, *to_gen));
                if d.data.len() < s + l {
                    d.data.resize(s + l, 0);
                }
                d.data[s..s + l].copy_from_slice(&chunk);
            }
            ShardOp::Omap {
                soid,
                generation,
                omap,
            } => {
                use ec::moddesc::OmapUp;
                let Some(o) = pg.gget_mut(&k(soid, *generation)) else {
                    continue;
                };
                if let Some(h) = &omap.header {
                    o.omap_header = h.clone();
                }
                if omap.clear {
                    o.omap.clear();
                    o.omap_header.clear();
                }
                for u in &omap.ups {
                    match u {
                        OmapUp::Insert(kv) => {
                            for (a, b) in kv {
                                o.omap.insert(a.clone(), b.clone());
                            }
                        }
                        OmapUp::Remove(keys) => {
                            for a in keys {
                                o.omap.remove(a);
                            }
                        }
                        OmapUp::RemoveRange(a, z) => {
                            o.omap.retain(|key, _| !(key >= a && key < z));
                        }
                    }
                }
            }
        }
    }
}

impl MemStore {
    fn split_out(&mut self, parent: SpgT, children: &[SplitChild]) {
        let Some(par) = self.pgs.get_mut(&parent) else {
            self.orphan_writes += 1;
            return;
        };
        let mut made = Vec::new();
        for c in children {
            let mask = pgwire::pgmath::bits_mask(c.bits);
            let keys: Vec<Hobject> = par
                .objects
                .keys()
                .filter(|h| !h.is_temp() && h.hash & mask == c.spg.pgid.seed)
                .cloned()
                .collect();
            let objs: BTreeMap<Hobject, MemObj> = keys
                .into_iter()
                .filter_map(|k| par.objects.remove(&k).map(|o| (k, o)))
                .collect();
            let skeys: Vec<(Hobject, u64)> = par
                .stash
                .keys()
                .filter(|(h, _)| h.hash & mask == c.spg.pgid.seed)
                .cloned()
                .collect();
            let stash: BTreeMap<(Hobject, u64), MemObj> = skeys
                .into_iter()
                .filter_map(|k| par.stash.remove(&k).map(|o| (k, o)))
                .collect();
            let moved: Vec<(Hobject, Vec<u64>)> = par
                .snapmap
                .all()
                .into_iter()
                .filter(|(h, _)| h.hash & mask == c.spg.pgid.seed)
                .collect();
            for (h, _) in &moved {
                par.snapmap
                    .apply(&crate::snaps::MapOp::Remove { clone: h.clone() });
            }
            made.push((c, objs, stash, moved));
        }
        for (c, objs, stash, moved) in made {
            // a child that exists already (redo) keeps its own state and objects
            self.pgs.entry(c.spg).or_insert_with(|| MemPg {
                p: (*c.state).clone(),
                objects: objs,
                removals: vec![],
                stash,
                snapmap: {
                    let mut m = crate::snaps::MemMap::default();
                    for (clone, snaps) in moved {
                        m.apply(&crate::snaps::MapOp::Set { clone, snaps });
                    }
                    m
                },
            });
        }
    }

    fn merge_in(&mut self, target: SpgT, sources: &[SpgT]) {
        let mut objs = Vec::new();
        let mut maps = Vec::new();
        for s in sources {
            if let Some(mp) = self.pgs.remove(s) {
                maps.extend(mp.snapmap.all());
                objs.extend(mp.objects.into_iter().filter(|(h, _)| !h.is_temp()));
            }
        }
        let Some(t) = self.pgs.get_mut(&target) else {
            self.orphan_writes += 1;
            return;
        };
        t.objects.extend(objs);
        for (clone, snaps) in maps {
            t.snapmap.apply(&crate::snaps::MapOp::Set { clone, snaps });
        }
    }

    fn apply_op(&mut self, spg: SpgT, op: &StoreOp) {
        if matches!(op, StoreOp::CreatePg) {
            self.pgs.entry(spg).or_insert_with(|| MemPg {
                p: empty_persisted(spg),
                objects: BTreeMap::new(),
                removals: vec![],
                stash: BTreeMap::new(),
                snapmap: Default::default(),
            });
            return;
        }
        if matches!(op, StoreOp::RemovePg) {
            self.pgs.remove(&spg);
            return;
        }
        // Every PG starts with `CreatePg`; a write to a PG that does not exist is a bug of the
        // caller (e.g. a write after deletion): count it and ignore it.
        let Some(pg) = self.pgs.get_mut(&spg) else {
            self.orphan_writes += 1;
            self.orphan_ops
                .push(format!("{spg}: {:?}", op).chars().take(80).collect());
            return;
        };
        match op {
            StoreOp::SplitOut { .. } | StoreOp::MergeIn { .. } => unreachable!("handled by submit"),
            StoreOp::CreatePg | StoreOp::RemovePg => unreachable!(),
            StoreOp::PutEpoch(e) => pg.p.epoch = *e,
            StoreOp::PutInfo(i) => pg.p.info = (**i).clone(),
            StoreOp::PutPastIntervals(pi) => pg.p.past_intervals = (**pi).clone(),
            // like the real store: the fast form leaves the persisted head behind (`PersistedPg::normalize` at load)
            StoreOp::LogAppendFast(es) => {
                pg.p.log
                    .log
                    .extend(es.iter().map(|e| e.entry().expect("encoded log entry")))
            }
            StoreOp::LogAppend(es) => {
                for e in es {
                    pg.p.log.head = e.version;
                    pg.p.log.can_rollback_to = e.version;
                    pg.p.log.rollback_info_trimmed_to = e.version;
                    pg.p.log.log.push_back(e.clone());
                }
            }
            StoreOp::LogTrim { to, dups_from, .. } => {
                let l = &mut pg.p.log;
                let n = l.log.partition_point(|e| e.version <= *to);
                for e in l.log.drain(..n) {
                    if dups_from.is_some_and(|f| e.version >= f) {
                        l.dups.extend(e.dups());
                    }
                }
                if *to > l.tail {
                    l.tail = *to;
                }
                match dups_from {
                    Some(f) => l.dups.retain(|d| d.version >= *f),
                    None => l.dups.clear(),
                }
            }
            StoreOp::LogAppendKeep(es) => {
                for e in es {
                    pg.p.log.head = e.version;
                    pg.p.log.log.push_back(e.clone());
                }
            }
            StoreOp::LogCursors {
                can_rollback_to,
                rollback_info_trimmed_to,
            } => {
                pg.p.log.can_rollback_to = *can_rollback_to;
                pg.p.log.rollback_info_trimmed_to = *rollback_info_trimmed_to;
            }
            StoreOp::LogHeadIs(h, c, r) => {
                let l = &pg.p.log;
                debug_assert_eq!(
                    (l.head, l.can_rollback_to, l.rollback_info_trimmed_to),
                    (*h, *c, *r),
                    "LogHeadIs hint differs from the stored log head"
                );
            }
            StoreOp::Shard(ops) => apply_shard_ops(pg, ops),
            StoreOp::LogRewind { to } => {
                let l = &mut pg.p.log;
                l.log.retain(|e| e.version.version <= to.version);
                l.head = *to;
                l.can_rollback_to = l.can_rollback_to.min(*to);
                l.rollback_info_trimmed_to = l.rollback_info_trimmed_to.min(*to);
            }
            StoreOp::LogSetHead(h) => {
                let l = &mut pg.p.log;
                l.head = *h;
                l.can_rollback_to = *h;
                l.rollback_info_trimmed_to = *h;
            }
            StoreOp::LogReplace(l) => pg.p.log = (**l).clone(),
            StoreOp::LogDups(d) => pg.p.log.dups = d.iter().cloned().collect(),
            StoreOp::Missing(ch) => {
                for (k, v) in ch {
                    match v {
                        Some(it) => {
                            pg.p.missing.missing.insert(k.clone(), it.clone());
                        }
                        None => {
                            pg.p.missing.missing.remove(k);
                        }
                    }
                }
            }
            StoreOp::MissingClear {
                may_include_deletes,
            } => {
                pg.p.missing.missing.clear();
                pg.p.missing.may_include_deletes = *may_include_deletes;
            }
            StoreOp::ApplyTxn { middle, data } => {
                if let Err(e) = apply_txn(pg, spg, middle, data) {
                    self.bad_txns += 1;
                    self.last_bad_txn = Some(e);
                }
            }
            StoreOp::TxnHint(_) => {}
            StoreOp::ApplyTxnSplit { skel, refs, .. } => {
                let r = Transaction::decode_split(skel, refs, replwire::DEFAULT_PAGE)
                    .and_then(|t| t.encode_v9())
                    .map_err(|e| format!("transaction decode: {e}"))
                    .and_then(|blob| apply_txn(pg, spg, &[], &blob));
                if let Err(e) = r {
                    self.bad_txns += 1;
                    self.last_bad_txn = Some(e);
                }
            }
            StoreOp::RemoveObject(h) => {
                if pg.objects.remove(h).is_some() {
                    pg.removals.push((h.oid.clone(), "RemoveObject"));
                }
                if crate::snaps::is_clone(h) {
                    pg.snapmap
                        .apply(&crate::snaps::MapOp::Remove { clone: h.clone() });
                }
            }
            StoreOp::SnapMap(ops) => {
                for o in ops {
                    pg.snapmap.apply(o);
                }
            }
        }
    }
}

impl PgStoreOps for MemStore {
    fn admission_ready(&self) -> bool {
        #[cfg(feature = "test-knobs")]
        {
            !self.admission_paused.get()
        }
        #[cfg(not(feature = "test-knobs"))]
        {
            true
        }
    }
    fn lazy_info(&self) -> bool {
        !self.eager_info
    }
    fn list_temps(&self, spg: SpgT) -> Vec<Hobject> {
        self.temp_list(spg)
    }
    #[cfg(feature = "test-knobs")]
    fn lease_open(&self, spg: SpgT) -> u64 {
        let id = self.lease_next.get() + 1;
        self.lease_next.set(id);
        self.leases.borrow_mut().insert(id, spg);
        id
    }
    #[cfg(feature = "test-knobs")]
    fn lease_release(&self, lease: u64) {
        self.leases.borrow_mut().remove(&lease);
    }
    #[cfg(feature = "test-knobs")]
    fn lease_release_pg(&self, spg: SpgT) {
        self.leases.borrow_mut().retain(|_, s| *s != spg);
    }
    #[cfg(feature = "test-knobs")]
    fn warm(&self, _spg: SpgT, _soid: &Hobject, _off: u64, _len: u64) -> bool {
        self.warm_calls.set(self.warm_calls.get() + 1);
        let w = self.warm_waits.get();
        if w == 0 {
            return true;
        }
        self.warm_waits.set(w - 1);
        false
    }
    #[cfg(feature = "test-knobs")]
    fn warm_data(&self, _spg: SpgT, soid: &Hobject, off: u64, len: u64) -> bool {
        self.data_calls.set(self.data_calls.get() + 1);
        self.data_probed
            .borrow_mut()
            .insert((soid.clone(), off, len));
        let w = self.data_waits.get();
        if w == 0 {
            return true;
        }
        self.data_waits.set(w - 1);
        false
    }
    #[cfg(feature = "test-knobs")]
    fn warm_log(&self, _spg: SpgT, _head: Eversion) -> bool {
        self.log_calls.set(self.log_calls.get() + 1);
        let w = self.log_waits.get();
        if w == 0 {
            return true;
        }
        self.log_waits.set(w - 1);
        false
    }
    fn list_pgs(&self) -> Vec<SpgT> {
        self.pgs.keys().copied().collect()
    }
    fn load_pg(&self, spg: SpgT) -> Option<PersistedPg> {
        self.pgs.get(&spg).map(|p| {
            let mut p = p.p.clone();
            p.normalize();
            p
        })
    }
    fn submit(&mut self, spg: SpgT, txn: &StoreTxn) {
        // split / merge first, whatever their position
        for op in txn
            .ops
            .iter()
            .filter(|o| matches!(o, StoreOp::SplitOut { .. } | StoreOp::MergeIn { .. }))
        {
            match op {
                StoreOp::SplitOut { children, .. } => self.split_out(spg, children),
                StoreOp::MergeIn { sources, .. } => self.merge_in(spg, sources),
                _ => {}
            }
        }
        for op in txn
            .ops
            .iter()
            .filter(|o| !matches!(o, StoreOp::SplitOut { .. } | StoreOp::MergeIn { .. }))
        {
            self.apply_op(spg, op);
        }
    }
    fn queue(&mut self, spg: SpgT, txn: &StoreTxn, _token: u64) -> Queued {
        let before = self.bad_txns;
        self.submit(spg, txn);
        match (self.bad_txns > before, &self.last_bad_txn) {
            (true, Some(e)) => Queued::Rejected(e.clone()),
            _ => Queued::Durable,
        }
    }
    fn recovery_info_checked(
        &self,
        spg: SpgT,
        soid: &Hobject,
    ) -> Result<ObjectRecoveryInfo, StoreReadError> {
        let ob = self
            .pgs
            .get(&spg)
            .and_then(|p| p.objects.get(soid))
            .ok_or(StoreReadError::NoObject)?;
        let oi = denc::from_slice::<ObjectInfo>(
            ob.xattrs
                .get(b"_".as_slice())
                .ok_or(StoreReadError::Corrupt)?,
        )
        .map_err(|_| StoreReadError::Corrupt)?;
        // a clone carries its head's SnapSet (spec replication 6.2): the receiver derives the mapper entry from it
        let src = if crate::snaps::is_clone(soid) {
            let mut h = soid.clone();
            h.snap = denc::types::SnapId::NOSNAP;
            self.pgs.get(&spg).and_then(|p| p.objects.get(&h))
        } else {
            Some(ob)
        };
        let ss = match src.and_then(|o| o.xattrs.get(b"snapset".as_slice())) {
            Some(b) => denc::from_slice::<SnapSet>(b).map_err(|_| StoreReadError::Corrupt)?,
            None => SnapSet::default(),
        };
        Ok(ObjectRecoveryInfo {
            soid: soid.clone(),
            version: oi.version,
            size: ob.data.len() as u64,
            copy_subset: BTreeMap::from([(0, ob.data.len() as u64)]),
            clone_subset: BTreeMap::new(),
            object_exist: true,
            // omap keys are not counted (adr 0610); the field stays on the wire for classic peers
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
        #[cfg(any(test, feature = "test-knobs"))]
        if let Some(e) = self.push_error.take() {
            return Err(e);
        }
        let ob = self
            .pgs
            .get(&spg)
            .and_then(|p| p.objects.get(&ri.soid))
            .ok_or(StoreReadError::NoObject)?;
        let oi = denc::from_slice::<ObjectInfo>(
            ob.xattrs
                .get(b"_".as_slice())
                .ok_or(StoreReadError::NoObject)?,
        )
        .map_err(|_| StoreReadError::NoObject)?;
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
        if before.first {
            op.omap_header = ob.omap_header.clone();
            for (k, v) in &ob.xattrs {
                op.attrset.insert(k.clone(), v.clone());
            }
            after.first = false;
        }
        if !before.omap_complete {
            let mut stopped = false;
            for (n, (k, v)) in ob
                .omap
                .range(before.omap_recovered_to.clone()..)
                .enumerate()
            {
                let sz = (k.len() + v.len()) as u64;
                if n > 0 && (n >= max_omap_entries || sz >= budget) {
                    after.omap_recovered_to = k.clone();
                    stopped = true;
                    break;
                }
                op.omap_entries.insert(k.clone(), v.clone());
                budget = budget.saturating_sub(sz);
            }
            if !stopped {
                after.omap_complete = true;
            }
        }
        let range_end = ri.copy_subset.iter().map(|(s, l)| s + l).max().unwrap_or(0);
        if budget > 0 && !ri.copy_subset.is_empty() {
            // single contiguous span from data_recovered_to
            let start = before.data_recovered_to;
            let end = (start + budget).min(range_end).min(ob.data.len() as u64);
            if end > start {
                op.data = ob.data[start as usize..end as usize].to_vec().into();
                op.data_included = BTreeMap::from([(start, end - start)]);
            }
            after.data_recovered_to = if start + budget >= range_end {
                range_end
            } else {
                end
            };
        } else if ri.copy_subset.is_empty() {
            after.data_recovered_to = 0;
        }
        let done_data = after.data_recovered_to >= range_end;
        if done_data {
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
    ) -> Result<ObjListing, StoreReadError> {
        if self.list_error {
            return Err(StoreReadError::Io);
        }
        Ok(self.list_objects_impl(spg, begin, max))
    }
    fn omap_keys_over(&self, spg: SpgT, soid: &Hobject, limit: u64) -> Option<bool> {
        if self.omap_probe_error {
            return None;
        }
        self.pgs
            .get(&spg)
            .and_then(|p| p.objects.get(soid))
            .map(|o| o.omap.len() as u64 > limit)
    }
    fn object_version(&self, spg: SpgT, soid: &Hobject) -> Result<Eversion, StoreReadError> {
        let ob = self
            .pgs
            .get(&spg)
            .and_then(|p| p.objects.get(soid))
            .ok_or(StoreReadError::NoObject)?;
        let b = ob
            .xattrs
            .get(b"_".as_slice())
            .ok_or(StoreReadError::Corrupt)?;
        denc::from_slice::<ObjectInfo>(b)
            .map(|oi| oi.version)
            .map_err(|_| StoreReadError::Corrupt)
    }
    fn build_scrub_map(
        &self,
        spg: SpgT,
        start: &Hobject,
        end: &Hobject,
        deep: bool,
        max_objects: usize,
        max_bytes: u64,
    ) -> crate::scrub::ScrubPart {
        self.scrub_part(spg, start, end, deep, max_objects, max_bytes)
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
    ) -> crate::scrub::ScrubPart {
        self.scrub_part_ec(spg, start, end, deep, max_objects, max_bytes, mode, chunk)
    }
    fn ec_read(
        &self,
        spg: SpgT,
        soid: &Hobject,
        off: u64,
        len: u64,
    ) -> Result<(Vec<u8>, u64), i32> {
        let o = self
            .pgs
            .get(&spg)
            .and_then(|p| p.objects.get(soid))
            .ok_or(-2)?;
        let size = o.data.len() as u64;
        let s = (off.min(size)) as usize;
        let e = off.saturating_add(len).min(size) as usize;
        Ok((o.data[s..e].to_vec(), size))
    }
    fn ec_getattrs(&self, spg: SpgT, soid: &Hobject) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, i32> {
        self.pgs
            .get(&spg)
            .and_then(|p| p.objects.get(soid))
            .map(|o| o.xattrs.clone())
            .ok_or(-2)
    }
    fn ec_omap_header(&self, spg: SpgT, soid: &Hobject) -> Result<Vec<u8>, i32> {
        self.pgs
            .get(&spg)
            .and_then(|p| p.objects.get(soid))
            .map(|o| o.omap_header.clone())
            .ok_or(-2)
    }
    fn ec_omap_read(
        &self,
        spg: SpgT,
        soid: &Hobject,
        after: Option<&[u8]>,
        max_bytes: u64,
        max_entries: usize,
    ) -> Result<(Vec<(Vec<u8>, Vec<u8>)>, bool), i32> {
        let o = self
            .pgs
            .get(&spg)
            .and_then(|p| p.objects.get(soid))
            .ok_or(-2)?;
        Ok(crate::ecopt::omap_batch(
            o.omap
                .range::<[u8], _>((
                    after.map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded),
                    std::ops::Bound::Unbounded,
                ))
                .map(|(k, v)| (k.clone(), v.clone())),
            max_bytes,
            max_entries,
        ))
    }
    fn ec_list_stash(&self, spg: SpgT) -> Vec<(Hobject, u64)> {
        self.pgs
            .get(&spg)
            .map(|p| p.stash.keys().cloned().collect())
            .unwrap_or_default()
    }
    fn object_stats(&self, spg: SpgT) -> (u64, u64) {
        self.pgs.get(&spg).map_or((0, 0), |p| {
            let v = p.objects.iter().filter(|(h, _)| !h.is_temp());
            let (n, b) = v.fold((0u64, 0u64), |(n, b), (_, o)| {
                (n + 1, b + o.data.len() as u64)
            });
            (n, b)
        })
    }
    fn snapmap_next(
        &self,
        spg: SpgT,
        snap: u64,
        max: usize,
    ) -> Result<Vec<Hobject>, StoreReadError> {
        if self.snapmap_error {
            return Err(StoreReadError::Io);
        }
        match self.pgs.get(&spg) {
            Some(p) => p.snapmap.next(snap, max),
            None => Ok(Vec::new()),
        }
    }
    fn snapmap_get(&self, spg: SpgT, clone: &Hobject) -> Option<Vec<u64>> {
        self.pgs.get(&spg).and_then(|p| p.snapmap.get(clone))
    }
    fn snapmap_get_checked(
        &self,
        spg: SpgT,
        clone: &Hobject,
    ) -> Result<Option<Vec<u64>>, StoreReadError> {
        if self.snapmap_error {
            return Err(StoreReadError::Io);
        }
        Ok(self.snapmap_get(spg, clone))
    }
    fn snapmap_scan(
        &self,
        spg: SpgT,
        from: &[u8],
        max: usize,
    ) -> Result<(Vec<u64>, Option<Vec<u8>>), StoreReadError> {
        if self.snapmap_error {
            return Err(StoreReadError::Io);
        }
        match self.pgs.get(&spg) {
            Some(p) => p.snapmap.scan(from, max),
            None => Ok((Vec::new(), None)),
        }
    }
    fn snapmap_check(
        &self,
        spg: SpgT,
        start: &Hobject,
        end: &Hobject,
    ) -> (Vec<crate::snaps::MapOp>, Vec<String>) {
        if self.snapmap_error {
            return (
                Vec::new(),
                vec![format!("{SNAPMAP_READ_ERR}listing the clones failed")],
            );
        }
        let Some(p) = self.pgs.get(&spg) else {
            return Default::default();
        };
        let clones = p
            .objects
            .range(start.clone()..)
            .take_while(|(h, _)| *h < end)
            .filter(|(h, _)| crate::snaps::is_clone(h))
            .map(|(h, _)| (h.clone(), p.snapmap.get(h)))
            .collect();
        snapmap_check_with(clones, |h| {
            p.objects
                .get(h)
                .and_then(|o| o.xattrs.get(b"snapset".as_slice()))
                .and_then(|b| denc::from_slice::<SnapSet>(b).ok())
        })
    }
}

impl MemStore {
    /// [`PgStoreOps::list_objects`] body: one slice of at most `max`, exactly what is present; `min` is ignored (a real
    /// store only needs it for its read amortization).
    fn list_objects_impl(&self, spg: SpgT, begin: &Hobject, max: usize) -> ObjListing {
        let Some(p) = self.pgs.get(&spg) else {
            return ObjListing::empty();
        };
        let mut out = ObjListing::empty();
        for (h, o) in p.objects.range(begin.clone()..) {
            if h.is_temp() {
                continue;
            }
            if out.objs.len() + out.corrupt.len() >= max {
                out.next = h.clone();
                break;
            }
            match o
                .xattrs
                .get(b"_".as_slice())
                .and_then(|b| denc::from_slice::<ObjectInfo>(b).ok())
            {
                Some(oi) => out.objs.push((h.clone(), oi.version)),
                None => out.corrupt.push(h.clone()),
            }
        }
        out
    }
}

// ---------------------------------------------------------------- PG migration between cores (adr 0031)

use denc::types::Ghobject;
use std::collections::VecDeque;

/// Why a migration import batch was not applied (adr 0031 am. 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigImportError {
    /// The store has no room for the batch: nothing of it was applied, the store keeps serving (the move is undone
    /// and deferred, never a store failure).
    NoSpace,
    /// Any other failure (the store is broken).
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigOp {
    /// Create the collection.
    Coll { bits: u32 },
    /// (Re)create an object with its xattrs and omap header.
    Obj {
        oid: Ghobject,
        attrs: Vec<(Vec<u8>, Vec<u8>)>,
        hdr: Vec<u8>,
    },
    /// Omap keys of an object.
    Omap {
        oid: Ghobject,
        kv: Vec<(Vec<u8>, Vec<u8>)>,
    },
    /// A non-zero run of object data.
    Data {
        oid: Ghobject,
        off: u64,
        data: Vec<u8>,
    },
    /// Final size of an object (also creates trailing holes).
    Size { oid: Ghobject, size: u64 },
}

impl MigOp {
    /// Payload bytes (flow control).
    pub fn bytes(&self) -> usize {
        match self {
            MigOp::Data { data, .. } => data.len(),
            MigOp::Omap { kv, .. } => kv.iter().map(|(k, v)| k.len() + v.len()).sum(),
            MigOp::Obj { attrs, hdr, .. } => {
                hdr.len() + attrs.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>()
            }
            _ => 0,
        }
    }
}

#[derive(Debug)]
pub struct ObjPos {
    pub oid: Ghobject,
    pub size: u64,
    pub off: u64,
    pub omap_from: Option<Vec<u8>>,
    pub omap_done: bool,
    pub started: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Phase {
    Start,
    Objects,
    Meta,
    Done,
}

/// Where an export stopped.
#[derive(Debug)]
pub struct ExportCursor {
    pub list: Ghobject,
    pub listed_all: bool,
    pub queue: VecDeque<Ghobject>,
    pub cur: Option<ObjPos>,
    pub phase: Phase,
    pub generation: u64,
}

impl Default for ExportCursor {
    fn default() -> Self {
        ExportCursor {
            list: Ghobject::MIN(),
            listed_all: false,
            queue: VecDeque::new(),
            cur: None,
            phase: Phase::Start,
            generation: 0,
        }
    }
}

/// Inline-compression counters ([`PgStoreOps::comp_perf`]), cumulative; times in ns.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CompPerf {
    pub ok: u64,
    pub rejected: u64,
    pub sampled_out: u64,
    /// Compressed chunk windows rewritten by the chunk space rule (adr 0059 am. 4).
    pub gc_merged: u64,
    pub decomp: u64,
    pub comp_ns: u64,
    pub decomp_ns: u64,
    /// Data staging (adr 0061 am. 4): bytes copied into device buffers / written by reference (zero copy) / whose
    /// block crcs came from the receive pass.
    pub staged_bytes: u64,
    pub zc_bytes: u64,
    pub crc_reused_bytes: u64,
    /// Placement bytes covered by a shifted receipt CRC grid.
    pub placement_crc_reblocked_bytes: u64,
    /// Source bytes newly hashed to construct shifted receipt CRCs.
    pub placement_crc_hashed_bytes: u64,
    /// Store residency probes of the op gate (`warm*`) refused: shard admission headroom / object metadata page loading
    /// (or the object is written by a parked txn) / PG log page loading (or the PG has a parked txn) / data block read
    /// (`opexec::view::gate_why`).
    pub probe_refused_admission: u64,
    pub probe_refused_obj: u64,
    pub probe_refused_log: u64,
    pub probe_refused_data: u64,
}

/// Background PG deletion progress ([`PgStoreOps::removal_progress`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RemovalProgress {
    /// PGs queued for deletion.
    pub pgs: u32,
    /// Objects deleted since mount.
    pub objs_done: u64,
    /// Estimated objects left in the queued PGs (their object counts at queue time minus what was deleted since).
    pub objs_left: u64,
}

/// Cross-core message of the elastic shard pool (adr 0021 am. 52/53); mirrors the store's `LendMsg` so this crate stays
/// free of the store. The OSD moves it over its core lanes; shards are device-wide ids.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolMsg {
    /// Borrower -> pool owner core: `shard` wants a chunk (`short`: its allocation failed, it may wait for a return).
    Request { shard: u32, short: bool },
    /// Owner -> borrower core, after the table write is durable.
    Grant {
        shard: u32,
        slot: u32,
        phys: u64,
        pool: u64,
    },
    /// Owner -> borrower core: the pool is empty.
    Deny { shard: u32, pool: u64 },
    /// Borrower -> pool owner core (adr 0021 am. 57): slot `slot` of `shard` at engine block `phys` is a hole, write the free entry.
    Return { shard: u32, slot: u32, phys: u64 },
    /// Owner -> core of a shard denied earlier: the pool grew (`pool` free blocks).
    Grew { shard: u32, pool: u64 },
    /// Owner -> core of `shard`: free pool blocks now and the owner's view of `shard` (spare of the others, returns
    /// asked of it, progress for a waiter; after mount and every change).
    Size {
        shard: u32,
        pool: u64,
        spare: u64,
        target: u64,
        prog: u64,
    },
    /// Borrower -> pool owner core: chunks `shard` could give back on demand, its evacuation progress.
    Spare { shard: u32, chunks: u64, prog: u64 },
}

/// One core's dedup info listing request (adr 0593-dedup-deep-scrub-reformat, dedup-collection.md 6): digest shard `shard`
/// of `2^shard_bits` of `pool`, after the raw record key `after` (the fork's key bytes, empty = from the start), at most
/// `max` records with time `>= retrieve_after_ns`; records older than `remove_before_ns` are deleted on the way;
/// `max_duration_s` > 0 bounds the iteration (at least one record per call).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DedupListReq {
    pub pool: i64,
    pub shard: u32,
    pub shard_bits: u32,
    pub after: Vec<u8>,
    pub max: usize,
    pub retrieve_after_ns: u64,
    pub remove_before_ns: u64,
    pub max_duration_s: f64,
}

/// One record of a listing: its raw key (the fork's key bytes) and fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DedupEntry {
    pub key: Vec<u8>,
    pub digest: Vec<u8>,
    pub ts_ns: u64,
    /// Object hash in bitwise-key form.
    pub hash_key: u32,
}

/// One core's listing result: records in key order, the last key it examined (taken, skipped or pruned; empty = none) and
/// whether it reached the end of the shard range.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DedupListPart {
    pub entries: Vec<DedupEntry>,
    pub examined: Vec<u8>,
    pub completed: bool,
}

/// Merge the parts of all cores into one listing of at most `max` records: (records, cursor, completed). The cursor is the
/// last key every core has examined up to (records past it are dropped and come again with the next call), so no record
/// is skipped; `completed` = every core reached its range end and nothing was dropped.
pub fn merge_dedup_parts(
    parts: Vec<DedupListPart>,
    max: usize,
) -> (Vec<DedupEntry>, Vec<u8>, bool) {
    // the lowest key an incomplete core stopped at bounds what is known to be complete
    let bound = parts
        .iter()
        .filter(|p| !p.completed)
        .map(|p| p.examined.clone())
        .min();
    let mut all: Vec<DedupEntry> = parts.into_iter().flat_map(|p| p.entries).collect();
    all.sort_unstable_by(|a, b| a.key.cmp(&b.key));
    if let Some(b) = &bound {
        all.retain(|e| e.key <= *b);
    }
    let truncated = all.len() > max;
    all.truncate(max);
    let next = match (truncated, &bound) {
        (true, _) => all.last().map(|e| e.key.clone()).unwrap_or_default(),
        (false, Some(b)) => b.clone(),
        (false, None) => all.last().map(|e| e.key.clone()).unwrap_or_default(),
    };
    let completed = bound.is_none() && !truncated;
    (all, next, completed)
}

#[cfg(test)]
mod dedup_merge_tests {
    use super::*;

    fn e(k: u8) -> DedupEntry {
        DedupEntry {
            key: vec![k],
            digest: vec![k],
            ts_ns: 0,
            hash_key: 0,
        }
    }
    fn part(keys: &[u8], examined: u8, completed: bool) -> DedupListPart {
        DedupListPart {
            entries: keys.iter().map(|k| e(*k)).collect(),
            examined: vec![examined],
            completed,
        }
    }

    #[test]
    fn merge_never_skips_a_record() {
        // core A took 1,4,7 (max 3, stopped at 7), core B took 2,3 and finished: 4 is listed, 7 waits for the next call
        let (r, next, done) =
            merge_dedup_parts(vec![part(&[1, 4, 7], 7, false), part(&[2, 3], 9, true)], 4);
        assert_eq!(r.iter().map(|x| x.key[0]).collect::<Vec<_>>(), [1, 2, 3, 4]);
        assert_eq!((next, done), (vec![4], false));
        // both complete and everything fits: completed, cursor at the last record
        let (r, next, done) = merge_dedup_parts(vec![part(&[1], 1, true), part(&[2], 5, true)], 10);
        assert_eq!((r.len(), next, done), (2, vec![2], true));
        // an incomplete core that took nothing (time limit) bounds the cursor below the other core's records
        let (r, next, done) =
            merge_dedup_parts(vec![part(&[], 3, false), part(&[2, 5], 5, true)], 10);
        assert_eq!(r.iter().map(|x| x.key[0]).collect::<Vec<_>>(), [2]);
        assert_eq!((next, done), (vec![3], false));
        // nothing anywhere
        let (r, next, done) = merge_dedup_parts(
            vec![DedupListPart {
                completed: true,
                ..Default::default()
            }],
            10,
        );
        assert_eq!((r.len(), next.len(), done), (0, 0, true));
    }
}
