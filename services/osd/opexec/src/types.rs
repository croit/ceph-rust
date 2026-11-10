// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Plain data types shared by the executor and the engine.

use denc::types::{EntityAddr, EntityName, Hobject, OsdReqId, SpgT, UTime};
use opwire::OpInfo;
use peering::WriteEntry;
use replwire::{ObjectInfo, SnapContext, SnapSet};

/// Per-request limits (client-ops.md s3.8). Defaults = the classic option defaults; the OSD sets them from its config
/// (`osd_max_*`, see [`Limits`] field docs) at start and on every config change.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// `osd_max_write_size` (option in MiB).
    pub max_write_size: usize,
    /// `osd_max_object_size`.
    pub max_object_size: u64,
    /// `osd_max_object_name_len`.
    pub max_oid_len: usize,
    /// `osd_max_object_namespace_len`.
    pub max_nspace_len: usize,
    /// `osd_max_attr_name_len`.
    pub max_attr_name_len: usize,
    /// `osd_max_attr_size` (0 = unlimited).
    pub max_attr_size: u64,
    /// `osd_max_pgls`.
    pub max_pgls: u64,
    /// `osd_max_omap_entries_per_request` (also the cls `cls_get_config` value).
    pub max_omap_entries: usize,
    /// `osd_max_omap_bytes_per_request`.
    pub max_omap_bytes: usize,
    /// `osd_max_write_op_reply_len`.
    pub max_write_op_reply_len: usize,
    /// `osd_default_notify_timeout` (seconds).
    pub default_notify_timeout: u32,
    /// `osd_client_watch_timeout` (seconds).
    pub client_watch_timeout: u32,
    /// `osd_backoff_on_degraded` (default false): an object whose head is unreadable / write-degraded gets an
    /// object-level BLOCK backoff instead of parking the client op (client-ops 16.6).
    pub backoff_on_degraded: bool,
    /// `osd_backoff_on_unfound` (default true): an unfound head (missing here, no location can supply it) gets an
    /// object-level BLOCK backoff instead of parking the client op (client-ops 16.6).
    pub backoff_on_unfound: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_write_size: 90 << 20,
            max_object_size: 128 << 20,
            max_oid_len: 2048,
            max_nspace_len: 256,
            max_attr_name_len: 100,
            max_attr_size: 0,
            max_pgls: 1024,
            max_omap_entries: 1024,
            max_omap_bytes: 1 << 30,
            max_write_op_reply_len: 64,
            default_notify_timeout: 30,
            client_watch_timeout: 30,
            backoff_on_degraded: false,
            backoff_on_unfound: true,
        }
    }
}

/// Who sent the message.
#[derive(Debug, Clone)]
pub struct Caller {
    pub name: EntityName,
    pub addr: EntityAddr,
    /// msgr feature mask of the connection (MOSDOp.features if non-zero).
    pub features: u64,
}

/// Watch key: (cookie, client entity).
pub type WatchKey = (u64, EntityName);

/// Working view of a head object.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ObjState {
    pub oi: Option<ObjectInfo>,
    pub ss: SnapSet,
    /// The store holds a `snapset` attribute equal to `ss` (read by `load_state` or written by the last write): a write
    /// that leaves the snapset as it is does not set the attribute again.
    pub ss_stored: bool,
}

impl ObjState {
    pub fn present(&self) -> bool {
        self.oi.as_ref().is_some_and(|o| !o.is_whiteout())
    }
}

/// Everything the executor needs to know about one message.
#[derive(Debug, Clone)]
pub struct Msg {
    pub spg: SpgT,
    /// This authenticated single plain READ was admitted for placement; ask
    /// the store for verified block CRCs. The transport still owns its grant.
    pub placement_read: bool,
    /// The source-pull READ (adr 0665) of this write failed: report this negative errno
    /// instead of writing.
    pub source_pull_error: Option<i32>,
    /// Head object (snap = NOSNAP).
    pub head: Hobject,
    pub flags: u32,
    pub snapid: u64,
    pub snapc: SnapContext,
    pub reqid: OsdReqId,
    /// Client mtime (0 = unset).
    pub mtime: UTime,
    /// OSD wall clock.
    pub now: UTime,
    pub caller: Caller,
    /// Version the next log entry would get.
    pub at_version: denc::types::Eversion,
    /// PG `last_user_version` before this message.
    pub last_user_version: u64,
    pub info: OpInfo,
    pub limits: Limits,
    /// Watchers of this object that are currently connected (for PING).
    pub connected: Vec<WatchKey>,
    /// Pool is full (writes that grow need FULL_TRY/FULL_FORCE, s5.7 step 5).
    pub pool_full: bool,
    pub pool_full_quota: bool,
    /// The local store has no room for this write beyond its reserves: a mutating message that is not a pure shrink
    /// is answered -ENOSPC (plain reply, no log entry; ADR 0021 amendment 6).
    pub no_room: bool,
    /// Snaps the osdmap says are removed (client snapc is filtered, s5.7 step 1).
    pub removed_snaps: Vec<(u64, u64)>,
    /// Erasure-coded pool (primary role): WRITEFULL replaces the object (truncate to 0, then write), the form append-only
    /// EC pools accept.
    pub ec_pool: bool,
    /// EC pool capabilities (meaningful only with [`Msg::ec_pool`]): client-ops 16.4 gates.
    pub ec_caps: EcCaps,
    /// The cluster's `require_osd_release` (osdmap): gates log entry types/encodings an older peer cannot replay
    /// (client-ops 16.5).
    pub require_osd_release: u8,
    /// Source object fetched for a copy-from / copy-from2 op of this message (engine, before execution).
    pub copy: Option<std::sync::Arc<CopySrc>>,
    /// Osdmap values object classes read for this message's pool (default for a message without a CALL op).
    pub cls_map: ClsMap,
}

/// EC pool capabilities the op layer gates on (client-ops 16.4). Only meaningful together with [`Msg::ec_pool`]; the
/// default (optimizations allowed, overwrites allowed) does not restrict anything.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EcCaps {
    /// Pool flag EC_OPTIMIZATIONS: SYNC_READ (and EC direct reads) are served, else -EOPNOTSUPP.
    pub allows_optimizations: bool,
    /// EC pool without EC_OVERWRITES: only the legacy append-only write forms are accepted (WRITE offset rules,
    /// no ZERO, no TRUNCATE/TRIMTRUNC).
    pub requires_aligned_append: bool,
    /// `required_alignment` of an append-only EC pool: the pool's stripe width (0 = no offset alignment rule).
    pub required_alignment: u64,
}

/// Osdmap values object classes read (spec cls_journal.md, append): `journal.append` pads to the allocation unit only
/// when the map's `require_min_compat_client` >= octopus, rounded up to the pool `stripe_width` when that is non-zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClsMap {
    /// `require_min_compat_client` >= octopus.
    pub journal_pad: bool,
    /// Pool `stripe_width` (0 for replicated pools).
    pub pool_stripe_width: u64,
}

/// A fully fetched copy source (copy.md): what `copy-from` writes into the destination.
#[derive(Debug, Clone, Default)]
pub struct CopySrc {
    pub size: u64,
    pub mtime: UTime,
    /// User xattrs (names without the store `_` prefix).
    pub attrs: std::collections::BTreeMap<Vec<u8>, Vec<u8>>,
    pub data: Vec<u8>,
    pub omap_header: Vec<u8>,
    pub omap: Vec<(Vec<u8>, Vec<u8>)>,
    /// truncate_seq / truncate_size to store: the client's (copy-from2 TRUNCATE_SEQ) else the source's.
    pub truncate_seq: u64,
    pub truncate_size: u64,
    /// Source `user_version` (classic: the destination takes it unless other ops of the message bump it).
    pub user_version: u64,
    /// Multi-chunk source: data, xattrs, omap already sit in this temp object of the PG (written chunk by chunk, adr 0057
    /// am. 1); `data`/`attrs`/`omap` stay empty and the final transaction renames it into place.
    pub staged: Option<Hobject>,
    /// The source had an omap header or keys (staged copies: they are in the temp object).
    pub has_omap: bool,
}

/// Side effects run when the reply is sent (after commit for mutations): watch/notify (client-ops s10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// `watch` op registered/rebound; `will_ping` for WATCH(3)/RECONNECT.
    WatchConnect {
        key: WatchKey,
        timeout: u32,
        will_ping: bool,
        addr: EntityAddr,
    },
    WatchPing {
        key: WatchKey,
    },
    WatchRemove {
        key: WatchKey,
    },
    /// Object deleted: disconnect and drop all watchers.
    WatchRemoveAll,
    Notify {
        op_index: usize,
        cookie: u64,
        timeout: u32,
        payload: Vec<u8>,
    },
    NotifyAck {
        notify_id: u64,
        cookie: u64,
        reply: Vec<u8>,
        /// legacy short form: ack all watches of the caller
        legacy: bool,
    },
}

/// What happens to the message after execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Reply right away (reads, plain errors without a log entry).
    Reply,
    /// Mutating message that failed or changed nothing: ERROR log entry carrying its result (dup detection), reply
    /// after commit in order with the object's in-flight writes (s5.7 step 4).
    LogOnly,
    /// Mutation: transaction + log entries, reply after commit.
    Write,
    /// No reply at all (counted drop, the client learns the map and resends): a growing write of a plain client to a full pool.
    Drop,
}

/// A mutation to replicate.
#[derive(Debug, Clone, Default)]
pub struct WritePlan {
    pub entries: Vec<WriteEntry>,
    /// Encoded replwire transaction (v9), or the local skeleton when `txn_refs` is non-empty (see `WriteReq`).
    pub txn: bytes::Bytes,
    /// Out-of-line write payloads of the local skeleton `txn` (empty: `txn` is plain v9).
    pub txn_refs: Vec<bytes::Bytes>,
    /// Known crcs of payloads in `txn_refs` (the client message's verified receive crc; any order, owner-bound).
    pub txn_ref_crcs: Vec<crc::CrcHint>,
    /// Store room the transaction needs ([`replwire::Transaction::room_cost`]: payload bytes, tree entries set or
    /// removed); set only for growing writes whose cost the request does not show (cls calls), (0, 0) otherwise.
    pub room: (u64, u64),
}

/// Executor result.
#[derive(Debug)]
pub struct Outcome {
    pub result: i32,
    pub disp: Disposition,
    pub plan: WritePlan,
    pub effects: Vec<Effect>,
    /// Working state after the message (valid if Write).
    pub new_state: ObjState,
    /// user_version to report: for Write the new one, for reads the target's.
    pub user_version: u64,
    /// Head log entry version (replay_version of the reply) = last entry of the plan.
    pub replay_version: denc::types::Eversion,
    /// Set for mutations with RETURNVEC: the outcome keeps outdata.
    pub keep_outdata: bool,
    /// An object other than the target whose object_info does not decode was hit (rollback to a damaged clone): the
    /// repair (adr 0065) is for it, not for the target.
    pub damaged: Option<denc::types::Hobject>,
    /// Client io of the message (spec pg-io-stats.md 1); zero when it failed. Applied to the PG's stats by the engine
    /// when the write is submitted / the read is answered.
    pub io: pgwire::IoCount,
}

/// Every op of the vector only frees or shrinks (delete, truncate, zero, xattr/omap removal): such a message must
/// stay admissible on a full store, it is how space comes back.
pub fn pure_shrink(ops: &[opwire::OsdOp]) -> bool {
    use opwire::consts::op as c;
    !ops.is_empty()
        && ops.iter().all(|o| {
            matches!(
                o.op,
                c::DELETE
                    | c::TRUNCATE
                    | c::ZERO
                    | c::RMXATTR
                    | c::OMAP_RM_KEYS
                    | c::OMAP_RM_KEY_RANGE
                    | c::OMAP_CLEAR
            )
        })
}
