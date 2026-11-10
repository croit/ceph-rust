// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! The op executor (client-ops.md s5.7, s7, s8): runs one compound op vector against a WORKING view of the object
//! (existence, size, oi, SnapSet follow earlier ops) while object CONTENT (data, xattrs, omap) is read from the store
//! as of message start (the "two views" rule, client-ops.md s7). Writes accumulate in one mutation which `finish`
//! turns into a replwire transaction + pg log entries (make_writeable, whiteouts, user_version, dirty ranges).
//! cls primitives run through the same machinery (`cls.rs`).

use crate::types::*;
use crate::view::{ObjView, VerifiedRead};
use denc::types::{CollT, Eversion, Ghobject, Hobject, ShardId, SnapId, UTime};
use opwire::consts::{cmp, csum, op as code, opflag, watch_op};
use opwire::{
    ChecksumOut, CloneInfo, ObjListSnapResponse, ObjListWatchResponse, OmapKeysOut, OmapValsOut,
    OsdOp, SparseReadOut, StatOut, WatchItem, errno, flag as mflag,
};
use peering::WriteEntry;
use pgwire::{IoCount, LogOp, LogOpReturnItem};
use replwire::interval::{self, IntervalSet};
use replwire::oi::flag as oif;
use replwire::{ObjectInfo, SnapSet, Transaction, TxnOp, WatchInfo};
use std::borrow::Cow;
use std::collections::BTreeMap;

/// Owned transaction op on one object of the PG.
#[derive(Debug, Clone)]
pub(crate) enum MOp {
    Create,
    Write {
        off: u64,
        src: Src,
    },
    Zero {
        off: u64,
        len: u64,
    },
    Truncate {
        size: u64,
    },
    Remove,
    SetAttr {
        name: Vec<u8>,
        value: Vec<u8>,
    },
    RmAttr {
        name: Vec<u8>,
    },
    /// Clone this object (the item's object) to `dst`.
    CloneTo {
        dst: Hobject,
    },
    OmapClear,
    /// The batch as one buffer (opwire::KvRun): no per-key allocation from the wire to the transaction.
    OmapSetKeys(opwire::KvRun),
    OmapRmKeys(Vec<Vec<u8>>),
    OmapRmRange {
        first: Vec<u8>,
        last: Vec<u8>,
    },
    OmapSetHeader(Vec<u8>),
    SetAllocHint {
        oso: u64,
        wso: u64,
        flags: u32,
    },
    /// The temp object `src` becomes this object (data, xattrs, omap; an existing object must be removed first).
    RenameFrom {
        src: Hobject,
    },
}

/// Data source of a write: the whole indata of op `i`, its clipped prefix, or owned bytes.
#[derive(Debug, Clone)]
pub(crate) enum Src {
    Op(usize),
    Prefix(usize, usize),
    Own(Vec<u8>),
}

/// Result of executing one compound message (before `finish`).
pub struct Exec<'a, V: ObjView> {
    pub(crate) v: &'a V,
    pub(crate) m: &'a Msg,
    /// Store object content reads are served from (head, or the resolved clone for snap reads).
    pub(crate) tgt: Hobject,
    /// State the execution started from; the snapset is only read here, a write copies it in `finish`.
    pub(crate) pre: &'a ObjState,
    pub(crate) exists: bool,
    /// The object info as this message leaves it: `pre`'s until the first change (a read never copies it).
    pub(crate) oi: Cow<'a, ObjectInfo>,
    pub(crate) txn: Vec<(Hobject, MOp)>,
    pub(crate) modified: IntervalSet,
    pub(crate) modify: bool,
    pub(crate) user_modify: bool,
    pub(crate) effects: Vec<Effect>,
    pub(crate) n_read: u32,
    pub(crate) n_write: u32,
    pub(crate) cur: usize,
    /// Head was whiteouted by `delete` in this message (log REPLACE).
    pub(crate) whiteouted: bool,
    /// The message replaces a live head with a different object (copy-from over an existing destination): the commit
    /// picks REPLACE where the cluster release allows it (client-ops 16.5).
    pub(crate) use_replace: bool,
    pub(crate) grew: bool,
    /// `zero` was executed as `truncate` (the reply echoes the rewritten op).
    pub(crate) zero_trunc: bool,
    /// `undirty` ran on an object whose DIRTY flag is set: the message ends with the flag cleared, whatever else it does.
    pub(crate) undirty: bool,
    /// copy-from replaced the object: the source mtime is kept (the message mtime is ignored).
    pub(crate) copy_mtime: Option<UTime>,
    /// See [`Outcome::damaged`].
    pub(crate) damaged: Option<Hobject>,
    /// Client io counted so far (spec pg-io-stats.md 1): outer sub-ops and the cls primitives they run.
    pub(crate) io: IoCount,
    /// COPY_FROM subop whose source resolves to the destination, including its placement hash.
    pub(crate) copy_self: Option<usize>,
}

pub(crate) fn kn(name: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(name.len() + 1);
    k.push(b'_');
    k.extend_from_slice(name);
    k
}

fn enc_with<T: denc::Encode>(x: &T, features: u64) -> Vec<u8> {
    x.encode_to_vec_with_features(features).unwrap_or_default()
}

fn encb_with<T: denc::Encode>(x: &T, features: u64) -> bytes::Bytes {
    enc_with(x, features).into()
}

fn encb<T: denc::Encode>(x: &T) -> bytes::Bytes {
    enc(x).into()
}

/// A page of omap key/value pairs and whether more follow.
pub(crate) type OmapPage = (Vec<(Vec<u8>, Vec<u8>)>, bool);

pub(crate) fn enc<T: denc::Encode>(x: &T) -> Vec<u8> {
    denc::to_vec(x).unwrap_or_default()
}

/// Extent `[off, off + len)` reaches past the object size limit `mx` (EFBIG); shared by the executor and the fast path.
pub(crate) fn efbig(mx: u64, off: u64, len: u64) -> bool {
    off >= mx || len > mx || off.checked_add(len).is_none_or(|e| e > mx)
}

/// Validate the local COPY_FROM fields before suspending execution for a source fetch.
/// Local errors participate in ordinary FAILOK handling; asynchronous source errors do not.
pub(crate) fn copy_input(op: &OsdOp, max_oid: usize) -> Result<opwire::CopyFromIn, i32> {
    let cf = op.copy_from();
    if op.op == code::COPY_FROM2 && cf.flags & !opwire::copy_flag::ALL != 0 {
        return Err(errno::EINVAL);
    }
    let mut parse = op.clone();
    if op.op == code::COPY_FROM {
        let mut c = cf;
        c.flags &= !opwire::copy_flag::TRUNCATE_SEQ;
        parse.set_copy_from(c);
    }
    let inp = opwire::CopyFromIn::parse(&parse).map_err(|_| errno::EINVAL)?;
    if inp.src_oid.is_empty() || inp.src_oid.len() > max_oid {
        return Err(errno::EINVAL);
    }
    Ok(inp)
}

/// The CephFS "never truncated" hint (truncate_seq 1, truncate_size u64::MAX) means no hint: cleared to 0/0.
fn clear_never_truncated<S: PartialEq + From<u8>>(seq: &mut S, size: &mut u64) {
    if *seq == S::from(1) && *size == u64::MAX {
        *seq = S::from(0);
        *size = 0;
    }
}

/// Extent normalisation before execution (client-ops s7.2): the "never truncated" hint of every extent op means no hint
/// ([`clear_never_truncated`]), and trimtrunc truncates to its `truncate_size`. Idempotent (re-queued ops pass again).
pub(crate) fn normalize_extents(ops: &mut [OsdOp]) {
    for o in ops.iter_mut().filter(|o| opwire::is_extent_op(o.op)) {
        let mut e = o.extent();
        clear_never_truncated(&mut e.truncate_seq, &mut e.truncate_size);
        if o.op == code::TRIMTRUNC {
            e.offset = e.truncate_size;
        }
        o.set_extent(e);
    }
}

/// An object info recorded by an earlier croit-flashstore-osd that kept the "never truncated" hint (see [`normalize_extents`]) is
/// read as "no hint"; the next write of the object stores the repaired value.
fn normalize_oi(oi: &mut ObjectInfo) {
    clear_never_truncated(&mut oi.truncate_seq, &mut oi.truncate_size);
}

/// Load `(oi, snapset)` of a head from the store. `Err` = EIO.
pub fn load_state<V: ObjView>(
    v: &V,
    spg: denc::types::SpgT,
    head: &Hobject,
) -> Result<ObjState, i32> {
    let (raw, ssraw) = match v.ov_getattr_pair(spg, head, b"_", b"snapset") {
        Err(e) if e == errno::ENOENT => return Ok(ObjState::default()),
        Err(e) => return Err(e),
        Ok((None, _)) => return Ok(ObjState::default()),
        Ok((Some(a), b)) => (a, b),
    };
    let mut oi: ObjectInfo = denc::from_slice(&raw).map_err(|_| errno::EIO)?;
    normalize_oi(&mut oi);
    let (ss, ss_stored) = match ssraw {
        Some(b) => (
            denc::from_slice::<SnapSet>(&b).map_err(|_| errno::EIO)?,
            true,
        ),
        None => (SnapSet::default(), false),
    };
    // Snapshot overlap arithmetic assumes disjoint, nonoverflowing intervals.
    // Check stored metadata once on load, before it enters the state cache or
    // a mutation plan; malformed media contents are EIO, never wrapped ranges.
    if ss
        .clone_overlap
        .values()
        .any(|overlap| interval::checked_total(overlap).is_none())
    {
        return Err(errno::EIO);
    }
    Ok(ObjState {
        oi: Some(oi),
        ss,
        ss_stored,
    })
}

/// Load the object info of a clone (or any object) from the store.
pub fn load_oi<V: ObjView>(
    v: &V,
    spg: denc::types::SpgT,
    soid: &Hobject,
) -> Result<Option<ObjectInfo>, i32> {
    match v.ov_getattr(spg, soid, b"_") {
        Err(e) if e == errno::ENOENT => Ok(None),
        Err(e) => Err(e),
        Ok(None) => Ok(None),
        Ok(Some(b)) => {
            let mut oi: ObjectInfo = denc::from_slice(&b).map_err(|_| errno::EIO)?;
            normalize_oi(&mut oi);
            Ok(Some(oi))
        }
    }
}

impl<'a, V: ObjView> Exec<'a, V> {
    /// `tgt` = object whose store content content reads see; `pre` = state to start from (head state, or the clone's oi
    /// with the head's snapset for snap reads).
    pub fn new(v: &'a V, m: &'a Msg, tgt: Hobject, pre: &'a ObjState) -> Self {
        let exists = pre.oi.is_some();
        let oi = pre.oi.as_ref().map_or_else(
            || Cow::Owned(ObjectInfo::new(m.head.clone())),
            Cow::Borrowed,
        );
        Exec {
            v,
            m,
            tgt,
            pre,
            exists,
            oi,
            txn: Vec::new(),
            modified: IntervalSet::new(),
            modify: false,
            user_modify: false,
            effects: Vec::new(),
            n_read: 0,
            n_write: 0,
            cur: 0,
            whiteouted: false,
            use_replace: false,
            grew: false,
            zero_trunc: false,
            undirty: false,
            copy_mtime: None,
            damaged: None,
            io: IoCount::default(),
            copy_self: None,
        }
    }

    pub(crate) fn present(&self) -> bool {
        self.exists && !self.oi.is_whiteout()
    }

    /// Append-only EC pool (no EC_OVERWRITES, client-ops 16.4): no zero / truncate / trimtrunc, and writes must follow
    /// the append rules of [`Self::ec_append_ok`].
    fn ec_append_only(&self) -> bool {
        self.m.ec_pool && self.m.ec_caps.requires_aligned_append
    }

    /// The write forms an append-only EC pool accepts (`requires_aligned_append`, `required_alignment` = stripe width):
    /// offset on the alignment, a new object only at 0, an existing one only at its current size.
    fn ec_append_ok(&self, off: u64) -> bool {
        let a = self.m.ec_caps.required_alignment;
        if a != 0 && !off.is_multiple_of(a) {
            return false;
        }
        if self.present() {
            off == self.oi.size
        } else {
            off == 0
        }
    }

    fn push(&mut self, op: MOp) {
        self.txn.push((self.m.head.clone(), op));
    }

    /// `maybe_create_new_object`.
    pub(crate) fn touch(&mut self) {
        if !self.exists {
            self.exists = true;
            self.oi = Cow::Owned(ObjectInfo::new(self.m.head.clone()));
            self.push(MOp::Create);
            self.grew = true;
        } else if self.oi.is_whiteout() {
            let oi = self.oi.to_mut();
            oi.flags &= !oif::WHITEOUT;
            oi.flags &= !(oif::DATA_DIGEST | oif::OMAP_DIGEST);
            oi.data_digest = ObjectInfo::NO_DIGEST;
            oi.omap_digest = ObjectInfo::NO_DIGEST;
            self.grew = true;
        }
        self.modify = true;
    }

    fn dirty_data(&mut self) {
        let oi = self.oi.to_mut();
        oi.flags &= !oif::DATA_DIGEST;
        oi.data_digest = ObjectInfo::NO_DIGEST;
    }
    fn dirty_omap(&mut self) {
        let oi = self.oi.to_mut();
        oi.flags &= !oif::OMAP_DIGEST;
        oi.omap_digest = ObjectInfo::NO_DIGEST;
    }

    fn mark_modified(&mut self, off: u64, len: u64) {
        interval::insert(&mut self.modified, off, len);
    }

    // ------------------------------------------------------------------ dispatch

    /// Run the op vector. Returns the message result.
    pub fn run(&mut self, ops: &mut [OsdOp]) -> i32 {
        let mut result = 0i32;
        for (i, op) in ops.iter_mut().enumerate() {
            self.cur = i;
            let r = self.dispatch(i, op);
            op.rval = r;
            result = r;
            if r < 0 {
                if op.failok() && r != -errno::EAGAIN && r != -errno::EINPROGRESS {
                    result = 0;
                } else {
                    break;
                }
            }
        }
        result
    }

    fn dispatch(&mut self, i: usize, op: &mut OsdOp) -> i32 {
        let r = self.dispatch_op(i, op);
        self.count_io(op, r);
        r
    }

    /// Client io of one executed outer sub-op (spec pg-io-stats.md 1 table). Counts that need values only the op sees
    /// are taken inside it: CHECKSUM, CMPEXT, CMPXATTR, ZERO, TRUNCATE, DELETE, OMAP_CLEAR (shared with the cls
    /// primitives). A failed message drops the whole delta (`finish`); FAILOK keeps it.
    fn count_io(&mut self, op: &OsdOp, r: i32) {
        use code::*;
        let ok = r >= 0;
        let out = || op.outdata_len() as u64;
        match op.op {
            // extent length = bytes actually read (set by the op)
            READ | SYNC_READ | SPARSE_READ if ok => self.io.read(op.extent().length),
            MAPEXT if ok => self.io.read(out()),
            ISDIRTY if ok => self.io.read(0),
            STAT => self.io.read(0),
            GETXATTR | GETXATTRS => self.io.read(if ok { out() } else { 0 }),
            OMAP_GET_KEYS | OMAP_GET_VALS | OMAP_GET_VALS_BY_KEYS if ok => self.io.read(out()),
            OMAP_GET_HEADER if ok && self.oi.is_omap() => self.io.read(out()),
            // counted once the keys were looked up: a mismatch (ECANCELED) too
            OMAP_CMP if ok || r == -errno::ECANCELED => self.io.read(0),
            LIST_WATCHERS | LIST_SNAPS if ok => self.io.read(0),
            WRITE | APPEND | WRITEFULL if ok => self.io.write(op.extent().length),
            SETXATTR | RMXATTR | OMAP_SET_HEADER | OMAP_RM_KEYS | OMAP_RM_KEY_RANGE if ok => {
                self.io.write(0)
            }
            OMAP_SET_VALS if ok => self.io.write(op.indata.len() as u64),
            COPY_FROM | COPY_FROM2 if ok => self.io.write(self.oi.size),
            _ => {}
        }
    }

    fn dispatch_op(&mut self, i: usize, op: &mut OsdOp) -> i32 {
        use code::*;
        let c = op.op;
        match c {
            READ => {
                self.n_read += 1;
                self.op_read(op)
            }
            SYNC_READ => {
                // client-ops 16.4: an EC pool without EC_OPTIMIZATIONS cannot serve a direct sync read; elsewhere it
                // is a plain READ
                if self.m.ec_pool && !self.m.ec_caps.allows_optimizations {
                    return -errno::EOPNOTSUPP;
                }
                self.n_read += 1;
                self.op_read(op)
            }
            SPARSE_READ => {
                self.n_read += 1;
                self.op_sparse_read(op)
            }
            MAPEXT => {
                self.n_read += 1;
                self.op_mapext(op)
            }
            ISDIRTY => {
                self.n_read += 1;
                // the flag of the state at message start (it changes only when the message commits)
                let dirty = self
                    .pre
                    .oi
                    .as_ref()
                    .is_some_and(|o| o.flags & oif::DIRTY != 0);
                op.outdata = vec![u8::from(dirty)].into();
                0
            }
            UNDIRTY => {
                // not a user-visible modification: no user_version bump, no-op on a clean or missing object
                self.n_write += 1;
                if self
                    .pre
                    .oi
                    .as_ref()
                    .is_some_and(|o| o.flags & oif::DIRTY != 0)
                {
                    self.modify = true;
                    self.undirty = true;
                }
                0
            }
            STAT => self.op_stat(op),
            CHECKSUM => {
                self.n_read += 1;
                self.op_checksum(op)
            }
            CMPEXT => {
                self.n_read += 1;
                self.op_cmpext(op)
            }
            ASSERT_VER => {
                self.n_read += 1;
                self.op_assert_version(op)
            }
            LIST_SNAPS => {
                self.n_read += 1;
                self.op_list_snaps(op)
            }
            LIST_WATCHERS => {
                self.n_read += 1;
                self.op_list_watchers(op)
            }
            WRITE => {
                self.n_write += 1;
                self.op_write_op(i, op)
            }
            WRITEFULL => {
                self.n_write += 1;
                self.op_writefull_op(i, op)
            }
            APPEND => {
                self.n_write += 1;
                self.op_append_op(i, op)
            }
            WRITESAME => {
                self.n_write += 1;
                self.op_writesame(op)
            }
            ZERO => {
                // client-ops 16.4: no zero on an append-only EC pool
                if self.ec_append_only() {
                    return -errno::EOPNOTSUPP;
                }
                self.n_write += 1;
                let e = op.extent();
                self.zero_trunc = false;
                let r = self.op_zero(e.offset, e.length);
                if self.zero_trunc {
                    op.op = code::TRUNCATE;
                }
                r
            }
            TRUNCATE => {
                // client-ops 16.4: no truncate on an append-only EC pool
                if self.ec_append_only() {
                    return -errno::EOPNOTSUPP;
                }
                self.n_write += 1;
                let e = op.extent();
                self.op_truncate(e.offset, e.length, e.truncate_seq, e.truncate_size)
            }
            TRIMTRUNC => {
                // client-ops 16.4: no trimtrunc on an append-only EC pool
                if self.ec_append_only() {
                    return -errno::EOPNOTSUPP;
                }
                self.n_write += 1;
                let e = op.extent();
                // classic counts no client io for TRIMTRUNC (spec pg-io-stats.md 1)
                let io = self.io;
                let r = self.op_truncate(e.offset, e.length, e.truncate_seq, e.truncate_size);
                self.io = io;
                r
            }
            DELETE => {
                self.n_write += 1;
                self.op_delete()
            }
            CREATE => {
                self.n_write += 1;
                self.op_create(op.flags & opflag::EXCL != 0, &op.indata)
            }
            SET_ALLOC_HINT => {
                self.n_write += 1;
                let h = op.alloc_hint();
                self.op_alloc_hint(h.expected_object_size, h.expected_write_size, h.flags)
            }
            ROLLBACK => {
                self.n_write += 1;
                self.op_rollback(op.snap().snapid)
            }
            STARTSYNC => {
                self.n_write += 1;
                0
            }
            GETXATTR => {
                self.n_read += 1;
                self.op_getxattr(op)
            }
            GETXATTRS => {
                self.n_read += 1;
                self.op_getxattrs(op)
            }
            CMPXATTR => {
                self.n_read += 1;
                self.op_cmpxattr(op)
            }
            SETXATTR => {
                self.n_write += 1;
                self.op_setxattr(op)
            }
            RMXATTR => {
                self.n_write += 1;
                self.op_rmxattr(op)
            }
            OMAP_GET_KEYS => {
                self.n_read += 1;
                self.op_omap_get_keys(op)
            }
            OMAP_GET_VALS => {
                self.n_read += 1;
                self.op_omap_get_vals(op)
            }
            OMAP_GET_HEADER => {
                self.n_read += 1;
                self.op_omap_get_header(op)
            }
            OMAP_GET_VALS_BY_KEYS => {
                self.n_read += 1;
                self.op_omap_get_by_keys(op)
            }
            OMAP_CMP => {
                self.n_read += 1;
                self.op_omap_cmp(op)
            }
            OMAP_SET_VALS => {
                self.n_write += 1;
                self.op_omap_set(op)
            }
            OMAP_SET_HEADER => {
                self.n_write += 1;
                self.op_omap_set_header(op.indata.to_vec())
            }
            OMAP_CLEAR => {
                self.n_write += 1;
                self.op_omap_clear()
            }
            OMAP_RM_KEYS => {
                self.n_write += 1;
                self.op_omap_rm_keys(op)
            }
            OMAP_RM_KEY_RANGE => {
                self.n_write += 1;
                self.op_omap_rm_range(op)
            }
            WATCH => {
                self.n_write += 1;
                self.op_watch(op)
            }
            NOTIFY => {
                self.n_read += 1;
                self.op_notify(i, op)
            }
            NOTIFY_ACK => {
                self.n_read += 1;
                self.op_notify_ack(op)
            }
            COPY_GET => {
                self.n_read += 1;
                self.op_copy_get(op)
            }
            COPY_FROM | COPY_FROM2 => {
                self.n_write += 1;
                self.op_copy_from(op)
            }
            CALL => self.op_call(op),
            _ => -errno::EOPNOTSUPP,
        }
    }

    // ------------------------------------------------------------------ reads

    /// Effective size for a read (s7.1 read): truncate_seq/size client hint.
    fn read_size(&self, e: &opwire::Extent, off: u64, len: u64) -> u64 {
        let mut s = self.oi.size;
        if (self.oi.truncate_seq as u32) < e.truncate_seq
            && off.saturating_add(len) > e.truncate_size
            && s > e.truncate_size
        {
            s = e.truncate_size;
        }
        s
    }

    /// `(off, len)` a read extent covers within the working size (length 0 = to the end); `None` = nothing.
    fn read_range(&self, e: &opwire::Extent) -> Option<(u64, u64)> {
        let (off, mut len) = (e.offset, e.length);
        let s = self.read_size(e, off, len);
        if len == 0 {
            len = s.saturating_sub(off);
        }
        if off >= s {
            return None;
        }
        Some((off, len.min(s - off)))
    }

    /// Bytes a store read of `[off, off + len)` must return: the committed content covers the object's size at message
    /// start (s7 two views; a later op of the message may have grown the working size past it). Fewer is a local
    /// failure (EIO), never a silently shortened reply (the copy path's rule).
    fn committed_len(&self, off: u64, len: u64) -> u64 {
        let size = self.pre.oi.as_ref().map_or(0, |o| o.size);
        len.min(size.saturating_sub(off))
    }

    /// Shared by `read` and the cls primitive: content from the store, clipped to the working size.
    pub(crate) fn read_core(&mut self, e: &opwire::Extent) -> Result<Vec<u8>, i32> {
        let Some((off, len)) = self.read_range(e) else {
            return Ok(Vec::new());
        };
        let (mut d, _) = self.v.ov_read_bytes(self.m.spg, &self.tgt, off, len)?;
        if (d.len() as u64) < self.committed_len(off, len) {
            return Err(errno::EIO);
        }
        d.truncate(len as usize);
        Ok(Vec::from(d))
    }

    /// [`Self::read_core`] as pieces by reference ([`ObjView::ov_read_shared`]), each with its crc when known.
    fn read_core_parts(&mut self, e: &opwire::Extent) -> Result<VerifiedRead, i32> {
        let Some((off, len)) = self.read_range(e) else {
            return Ok(VerifiedRead {
                parts: Vec::new(),
                block_crcs: self.m.placement_read.then(Vec::new),
            });
        };
        let mut read = if self.m.placement_read {
            self.v
                .ov_read_shared_verified(self.m.spg, &self.tgt, off, len)?
        } else {
            VerifiedRead {
                parts: self.v.ov_read_shared(self.m.spg, &self.tgt, off, len)?,
                block_crcs: None,
            }
        };
        let before: usize = read.parts.iter().map(|(b, _)| b.len()).sum();
        if (before as u64) < self.committed_len(off, len) {
            return Err(errno::EIO);
        }
        clip_parts(&mut read.parts, len as usize);
        if before > len as usize {
            read.block_crcs = None; // a clipped result no longer has the source's exact grid
        }
        Ok(read)
    }

    fn op_read(&mut self, op: &mut OsdOp) -> i32 {
        let e = op.extent();
        // an op's reply payload carries a u32 length: a larger read cannot be represented on the wire
        if self
            .read_range(&e)
            .is_some_and(|(_, len)| len > u64::from(u32::MAX))
        {
            return -errno::EFBIG;
        }
        match self.read_core_parts(&e) {
            Ok(read) => {
                let VerifiedRead { parts, block_crcs } = read;
                let mut e2 = e;
                e2.length = parts.iter().map(|(b, _)| b.len() as u64).sum();
                op.set_extent(e2);
                op.set_outdata_vec(parts);
                op.outdata_block_crcs = block_crcs;
                0
            }
            Err(x) => -x,
        }
    }

    fn op_sparse_read(&mut self, op: &mut OsdOp) -> i32 {
        let e = op.extent();
        let (off, mut len) = (e.offset, e.length);
        let s = self.read_size(&e, off, len);
        if off > s {
            len = 0;
        } else if len > s - off {
            len = s - off;
        }
        // the sparse data blob carries a u32 length: a larger reply cannot be represented on the wire
        if len > u64::from(u32::MAX) {
            return -errno::EFBIG;
        }
        let mut e2 = e;
        // the reply header is a piece of its own in front of the data pieces (by reference: no pass over the payload)
        let mut parts = Vec::new();
        if len > 0 {
            parts = match self.v.ov_read_shared(self.m.spg, &self.tgt, off, len) {
                Ok(p) => p,
                Err(x) => return -x,
            };
            let got: usize = parts.iter().map(|(b, _)| b.len()).sum();
            if (got as u64) < self.committed_len(off, len) {
                return -errno::EIO;
            }
            clip_parts(&mut parts, len as usize);
        }
        let n: usize = parts.iter().map(|(b, _)| b.len()).sum();
        e2.length = n as u64;
        op.set_extent(e2);
        op.set_outdata_vec(sparse_parts(off, n, parts));
        0
    }

    /// MAPEXT (spec client-ops-misc 1): the stored extents of the committed object inside the request range, as a
    /// `map<u64,u64>`. The store keeps no hole map: one extent covers the clipped range (a valid answer there).
    fn op_mapext(&mut self, op: &mut OsdOp) -> i32 {
        if self.m.ec_pool {
            return -errno::EOPNOTSUPP;
        }
        let Some(pre) = self.pre.oi.as_ref() else {
            return -errno::ENOENT;
        };
        let e = op.extent();
        let end = e.offset.saturating_add(e.length).min(pre.size);
        let mut out = Vec::with_capacity(20);
        if e.length == 0 || e.offset >= end {
            out.extend_from_slice(&0u32.to_le_bytes());
        } else {
            out.extend_from_slice(&1u32.to_le_bytes());
            out.extend_from_slice(&e.offset.to_le_bytes());
            out.extend_from_slice(&(end - e.offset).to_le_bytes());
        }
        op.outdata = out.into();
        0
    }

    fn op_stat(&mut self, op: &mut OsdOp) -> i32 {
        if !self.present() {
            return -errno::ENOENT;
        }
        op.outdata = encb(&StatOut {
            size: self.oi.size,
            mtime: self.oi.mtime,
        });
        0
    }

    fn op_checksum(&mut self, op: &mut OsdOp) -> i32 {
        let c = op.checksum();
        let Some(w) = csum::width(c.ty) else {
            return -errno::EINVAL;
        };
        if op.indata.len() < w {
            return -errno::EINVAL;
        }
        let mut ib = [0u8; 8];
        ib[..w].copy_from_slice(&op.indata[..w]);
        let init = u64::from_le_bytes(ib);
        let s = self.oi.size;
        let (off, length, chunk) = (c.offset, c.length, c.chunk_size as u64);
        // the chunk rules come before the object-end shortcut (s7.1 black-box: `0 0 8` is EINVAL, also past the end)
        if chunk > 0 && (length == 0 || length % chunk != 0) {
            return -errno::EINVAL;
        }
        // `offset == 0 && length == 0` = the whole object: the length becomes the object size and execution continues
        // (only reachable with chunk_size 0, the chunk rule above rejects a zero length). Any other range past the
        // object end succeeds with NO outdata, unlike the zero-chunk count below (client-ops 16.1).
        let whole = off == 0 && length == 0;
        if !whole && off >= s {
            return 0;
        }
        let mut len = if whole { s } else { length };
        if len > s - off {
            len = s - off;
            if chunk > 0 && len % chunk != 0 {
                return -errno::EINVAL;
            }
        }
        // a zero-length window reads nothing: count 0, not a 0-byte reply (a client decodes u32 count first)
        if len == 0 {
            self.io.read(0);
            let empty = ChecksumOut {
                ty: c.ty,
                values: Vec::new(),
            };
            return match empty.encode_to_vec() {
                Ok(b) => {
                    op.outdata = b.into();
                    0
                }
                Err(_) => -errno::EINVAL,
            };
        }
        let chunk = if chunk == 0 { len } else { chunk };
        let data = match self.v.ov_read(self.m.spg, &self.tgt, off, len) {
            Ok(d) if d.len() as u64 >= self.committed_len(off, len) => d,
            Ok(_) => return -errno::EIO,
            Err(x) => return -x,
        };
        // the inner read counts (replicated); an EC pool reads raw and counts nothing
        if !self.m.ec_pool {
            self.io.read(data.len() as u64);
        }
        let mut values = Vec::new();
        for ch in data.chunks(chunk as usize) {
            values.push(match c.ty {
                csum::CRC32C => u64::from(crc::crc32c(init as u32, ch)),
                csum::XXHASH32 => u64::from(xxhash_rust::xxh32::xxh32(ch, init as u32)),
                _ => xxhash_rust::xxh64::xxh64(ch, init),
            });
        }
        match (ChecksumOut { ty: c.ty, values }).encode_to_vec() {
            Ok(b) => {
                op.outdata = b.into();
                0
            }
            Err(_) => -errno::EINVAL,
        }
    }

    fn op_cmpext(&mut self, op: &mut OsdOp) -> i32 {
        let e = op.extent();
        // no payload/extent length equality (client-ops 16.2): indata shorter than the extent compares its prefix,
        // longer indata needs the bytes past the read window to be zero
        let s = self.read_size(&e, e.offset, e.length);
        let mut want = e.length;
        if e.offset >= s {
            want = 0;
        } else if want > s - e.offset {
            want = s - e.offset;
        }
        let stored = if want == 0 {
            Vec::new()
        } else {
            match self.v.ov_read(self.m.spg, &self.tgt, e.offset, want) {
                Ok(d) => d,
                Err(x) if x == errno::ENOENT => Vec::new(),
                Err(x) => return -x,
            }
        };
        if (stored.len() as u64) < self.committed_len(e.offset, want) {
            return -errno::EIO; // a short read would compare the missing bytes as zeros
        }
        // the inner read counts (replicated); an EC pool counts nothing
        if !self.m.ec_pool {
            self.io.read(stored.len() as u64);
        }
        for (i, b) in op.indata.iter().enumerate() {
            let have = stored.get(i).copied().unwrap_or(0);
            if have != *b {
                return errno::cmpext_mismatch(i as u64);
            }
        }
        0
    }

    fn op_assert_version(&mut self, op: &mut OsdOp) -> i32 {
        let ver = op.assert_ver().ver;
        if ver == 0 {
            return -errno::EINVAL;
        }
        let uv = if self.exists { self.oi.user_version } else { 0 };
        if ver < uv {
            -errno::ERANGE
        } else if ver > uv {
            -errno::EOVERFLOW
        } else {
            0
        }
    }

    fn op_list_snaps(&mut self, op: &mut OsdOp) -> i32 {
        if self.m.snapid != opwire::SNAPDIR {
            return -errno::EINVAL;
        }
        let ss = &self.pre.ss;
        let mut resp = ObjListSnapResponse {
            clones: Vec::new(),
            seq: ss.seq,
        };
        for c in &ss.clones {
            // every clone id must have its snaps, overlap and size (client-ops 16.10): a missing one is inconsistent
            // state -> -EINVAL, never a silently empty list
            let (Some(snaps), Some(overlap), Some(size)) = (
                ss.clone_snaps.get(c),
                ss.clone_overlap.get(c),
                ss.clone_size.get(c),
            ) else {
                return -errno::EINVAL;
            };
            let mut snaps: Vec<u64> = snaps.iter().map(|s| s.0).collect();
            snaps.sort_unstable();
            let overlap: Vec<(u64, u64)> = overlap.iter().map(|(a, l)| (*a, *l)).collect();
            resp.clones.push(CloneInfo {
                cloneid: c.0,
                snaps,
                overlap,
                size: *size,
            });
        }
        if self.present() {
            resp.clones.push(CloneInfo {
                cloneid: SnapId::NOSNAP.0,
                snaps: Vec::new(),
                overlap: Vec::new(),
                size: self.oi.size,
            });
        }
        op.outdata = encb(&resp);
        0
    }

    fn op_list_watchers(&mut self, op: &mut OsdOp) -> i32 {
        if !self.present() {
            return -errno::ENOENT;
        }
        let entries: Vec<WatchItem> = self
            .oi
            .watchers
            .iter()
            .map(|((cookie, name), w)| WatchItem {
                name: *name,
                cookie: *cookie,
                timeout_s: w.timeout_seconds,
                addr: w.addr,
            })
            .collect();
        op.outdata = encb_with(&ObjListWatchResponse { entries }, self.m.caller.features);
        0
    }

    // ------------------------------------------------------------------ data writes

    fn efbig(&self, off: u64, len: u64) -> bool {
        efbig(self.m.limits.max_object_size, off, len)
    }

    /// Truncate hint of write (s7.2 write step 2). `tsize == u64::MAX` is the clients' "no size" sentinel
    /// (striper passes it through unchanged): record seq/size, never truncate. A size beyond the object limit is
    /// rejected with EFBIG before any state change (an invalid store op would fail the whole PG txn). On an absent or
    /// whiteout head the hint is only recorded; the following write decides the size (client-ops 16.7).
    fn truncate_hint(&mut self, tseq: u32, tsize: u64) -> i32 {
        if tseq == 0 {
            return 0;
        }
        if u64::from(tseq) > self.oi.truncate_seq {
            if self.present() && tsize != u64::MAX {
                if tsize > self.m.limits.max_object_size {
                    return -errno::EFBIG;
                }
                let old = self.oi.size;
                if tsize < old {
                    self.mark_modified(tsize, old - tsize);
                }
                self.push(MOp::Truncate { size: tsize });
                self.oi.to_mut().size = tsize;
                self.dirty_data();
                self.modify = true;
            }
            let oi = self.oi.to_mut();
            oi.truncate_seq = u64::from(tseq);
            oi.truncate_size = tsize;
        }
        0
    }

    pub(crate) fn do_write(&mut self, off: u64, len: u64, src: Src) -> i32 {
        if self.efbig(off, len) {
            return -errno::EFBIG;
        }
        let truncate = (self.oi.truncate_seq, self.oi.truncate_size);
        self.touch();
        // Creating an object initializes object_info; retain a truncate hint recorded before touch.
        let oi = self.oi.to_mut();
        (oi.truncate_seq, oi.truncate_size) = truncate;
        self.user_modify = true;
        if len == 0 {
            if off > self.oi.size {
                self.push(MOp::Truncate { size: off });
                self.oi.to_mut().size = off;
                self.dirty_data();
            }
            return 0;
        }
        self.push(MOp::Write { off, src });
        self.mark_modified(off, len);
        self.oi.to_mut().size = self.oi.size.max(off + len);
        self.dirty_data();
        0
    }

    fn op_write_op(&mut self, i: usize, op: &mut OsdOp) -> i32 {
        if let Some(error) = self.m.source_pull_error {
            return error;
        }
        let mut e = op.extent();
        if op.indata.len() as u64 != e.length {
            return -errno::EINVAL;
        }
        if self.ec_append_only() && !self.ec_append_ok(e.offset) {
            return -errno::EOPNOTSUPP;
        }
        let mut src = Src::Op(i);
        let stale = self.oi.truncate_seq > 0 && self.oi.truncate_seq > u64::from(e.truncate_seq);
        if stale && e.offset.saturating_add(e.length) > self.oi.size {
            e.length = self.oi.size.saturating_sub(e.offset);
            // Keep the request payload intact: nonblocking execution may retry with its original union.
            src = Src::Prefix(i, e.length as usize);
            op.set_extent(e);
            if e.length == 0 && e.offset > self.oi.size {
                if self.efbig(e.offset, 0) {
                    return -errno::EFBIG;
                }
                self.touch();
                self.user_modify = true;
                return 0;
            }
        }
        let r = self.truncate_hint(e.truncate_seq, e.truncate_size);
        if r < 0 {
            return r;
        }
        self.do_write(e.offset, e.length, src)
    }

    fn op_writefull_op(&mut self, i: usize, op: &mut OsdOp) -> i32 {
        // Source-pull PUT (adr 0665): the data segment is a descriptor naming a
        // client READ-only source. Refuse before any store reference exists; the
        // OSD-side RDMA READ that would fill the data is not implemented.
        if let Some(error) = self.m.source_pull_error {
            return error;
        }
        let e = op.extent();
        if op.indata.len() as u64 != e.length {
            return -errno::EINVAL;
        }
        self.do_writefull(e.length, Src::Op(i))
    }

    pub(crate) fn do_writefull(&mut self, len: u64, src: Src) -> i32 {
        if self.efbig(0, len) {
            return -errno::EFBIG;
        }
        self.touch();
        self.user_modify = true;
        let old = self.oi.size;
        if self.m.ec_pool && old > 0 {
            // EC: a replace is truncate-to-0 + write (append-only pools accept nothing else)
            self.push(MOp::Truncate { size: 0 });
        } else if len < old {
            self.push(MOp::Truncate { size: len });
        }
        if len > 0 {
            self.push(MOp::Write { off: 0, src });
        }
        self.mark_modified(0, old.max(len));
        self.oi.to_mut().size = len;
        self.dirty_data();
        0
    }

    fn op_append_op(&mut self, i: usize, op: &mut OsdOp) -> i32 {
        let e = op.extent();
        if op.indata.len() as u64 != e.length {
            return -errno::EINVAL;
        }
        // an append is a write at the current size: the append-only EC rules apply to it as to a write
        if self.ec_append_only() && !self.ec_append_ok(self.oi.size) {
            return -errno::EOPNOTSUPP;
        }
        self.do_write(self.oi.size, e.length, Src::Op(i))
    }

    fn op_writesame(&mut self, op: &mut OsdOp) -> i32 {
        let w = op.write_same();
        if w.length == 0 {
            return 0;
        }
        if w.data_length == 0
            || !w.length.is_multiple_of(w.data_length)
            || op.indata.len() as u64 != w.data_length
        {
            return -errno::EINVAL;
        }
        if self.efbig(w.offset, w.length) {
            return -errno::EFBIG;
        }
        // writesame expands to a write: the append-only EC rules apply at its offset
        if self.ec_append_only() && !self.ec_append_ok(w.offset) {
            return -errno::EOPNOTSUPP;
        }
        let data = op.indata.repeat((w.length / w.data_length) as usize);
        self.do_write(w.offset, w.length, Src::Own(data))
    }

    pub(crate) fn op_zero(&mut self, off: u64, len: u64) -> i32 {
        if self.efbig(off, len) {
            return -errno::EFBIG;
        }
        let mx = self.m.limits.max_object_size;
        let size = self.oi.size;
        if self.present() && len >= 1 && len <= mx && off < mx && off.saturating_add(len) >= size {
            if off >= size {
                return 0;
            }
            self.zero_trunc = true;
            self.io.write(0);
            return self.do_truncate(off);
        }
        if len > 0 && self.present() {
            self.io.write(0);
            self.push(MOp::Zero { off, len });
            self.mark_modified(off, len);
            self.dirty_data();
            self.modify = true;
            self.user_modify = true;
        }
        0
    }

    fn do_truncate(&mut self, off: u64) -> i32 {
        let old = self.oi.size;
        if off < old {
            self.mark_modified(off, old - off);
        }
        self.push(MOp::Truncate { size: off });
        self.oi.to_mut().size = off;
        self.dirty_data();
        self.modify = true;
        self.user_modify = true;
        0
    }

    pub(crate) fn op_truncate(&mut self, off: u64, len: u64, tseq: u32, tsize: u64) -> i32 {
        if !self.present() {
            return 0;
        }
        if self.efbig(off, len) {
            return -errno::EFBIG;
        }
        if tseq != 0 {
            if u64::from(tseq) <= self.oi.truncate_seq {
                return 0;
            }
            let oi = self.oi.to_mut();
            oi.truncate_seq = u64::from(tseq);
            oi.truncate_size = tsize;
        }
        self.io.write(0);
        self.do_truncate(off)
    }

    pub(crate) fn op_delete(&mut self) -> i32 {
        let whiteout = self.pre.ss.should_whiteout(&self.m.snapc);
        // a whiteout head is ENOENT only when the delete would leave a whiteout again; else it is removed (s7.2)
        if !self.exists || (self.oi.is_whiteout() && whiteout) {
            return -errno::ENOENT;
        }
        let size = self.oi.size;
        self.io.write(0);
        self.push(MOp::Remove);
        if size > 0 {
            self.mark_modified(0, size);
        }
        self.oi.to_mut().size = 0;
        self.dirty_data();
        self.dirty_omap();
        if !self.oi.watchers.is_empty() {
            self.oi.to_mut().watchers.clear();
            self.effects.push(Effect::WatchRemoveAll);
        }
        if whiteout {
            self.push(MOp::Create);
            self.oi.to_mut().flags |= oif::WHITEOUT;
            self.whiteouted = true;
        } else {
            // The omap flag survives: later reads of this message still see the committed omap (s7 two views); only
            // omap-clear hides it.
            let omap = self.oi.flags & oif::OMAP;
            self.exists = false;
            self.oi = Cow::Owned(ObjectInfo::new(self.m.head.clone()));
            self.oi.to_mut().flags |= omap;
        }
        self.modify = true;
        self.user_modify = true;
        0
    }

    pub(crate) fn op_create(&mut self, excl: bool, legacy: &[u8]) -> i32 {
        if !legacy.is_empty() && decode_prefix::<Vec<u8>>(legacy).is_none() {
            return -errno::EINVAL;
        }
        if self.present() && excl {
            return -errno::EEXIST;
        }
        self.touch();
        self.user_modify = true;
        0
    }

    pub(crate) fn op_alloc_hint(&mut self, oso: u64, wso: u64, flags: u32) -> i32 {
        self.touch();
        self.user_modify = true;
        let oi = self.oi.to_mut();
        oi.expected_object_size = oso;
        oi.expected_write_size = wso;
        oi.alloc_hint_flags = flags;
        self.push(MOp::SetAllocHint { oso, wso, flags });
        0
    }

    // ------------------------------------------------------------------ copy (copy.md)

    /// copy-get (source side): one chunk of the object, driven by the cursor the destination sends back.
    fn op_copy_get(&mut self, op: &mut OsdOp) -> i32 {
        let Ok(inp) = op.copy_get_in() else {
            return -errno::EINVAL;
        };
        if !self.present() {
            return -errno::ENOENT;
        }
        let mut cur = inp.cursor;
        let mut out = opwire::CopyData {
            size: self.oi.size,
            mtime: self.oi.mtime,
            truncate_seq: self.oi.truncate_seq,
            truncate_size: self.oi.truncate_size,
            ..Default::default()
        };
        if self.tgt.snap != SnapId::NOSNAP {
            out.snaps = self
                .pre
                .ss
                .clone_snaps
                .get(&self.tgt.snap)
                .map(|v| v.iter().map(|s| s.0).collect())
                .unwrap_or_default();
        } else {
            out.snap_seq = self.pre.ss.seq;
        }
        if self.oi.flags & oif::DATA_DIGEST != 0 {
            out.flags |= opwire::COPY_FLAG_DATA_DIGEST;
            out.data_digest = self.oi.data_digest;
        }
        if self.oi.flags & oif::OMAP_DIGEST != 0 {
            out.flags |= opwire::COPY_FLAG_OMAP_DIGEST;
            out.omap_digest = self.oi.omap_digest;
        }
        if !cur.attr_complete {
            match self.v.ov_getattrs(self.m.spg, &self.tgt) {
                Ok(m) => {
                    out.attrs = m
                        .into_iter()
                        .filter(|(k, _)| k.len() > 1 && k[0] == b'_')
                        .map(|(k, v)| (k[1..].to_vec(), v))
                        .collect();
                }
                Err(e) => return -e,
            }
            cur.attr_complete = true;
        }
        let mut left = inp.max as i64;
        if left > 0 && !cur.data_complete {
            if cur.data_offset < self.oi.size {
                let n = (self.oi.size - cur.data_offset).min(left as u64);
                match self.v.ov_read(self.m.spg, &self.tgt, cur.data_offset, n) {
                    Ok(d) if d.len() as u64 == n => out.data = d,
                    // a short read of a stored object is a local failure, never a silently truncated copy
                    Ok(_) => return -errno::EIO,
                    Err(e) => return -e,
                }
                left -= n as i64;
                cur.data_offset += n;
            }
            if cur.data_offset >= self.oi.size {
                cur.data_complete = true;
            }
        }
        if self.oi.flags & oif::OMAP == 0 {
            cur.omap_complete = true;
        } else if left > 0 && !cur.omap_complete {
            if cur.omap_offset.is_empty() {
                match self.v.ov_omap_header(self.m.spg, &self.tgt) {
                    Ok(h) => out.omap_header = h,
                    Err(e) if e == errno::ENOENT => {}
                    Err(e) => return -e,
                }
            }
            let after = (!cur.omap_offset.is_empty()).then_some(cur.omap_offset.as_slice());
            match self
                .v
                .ov_omap_range(self.m.spg, &self.tgt, after, &[], 1 << 20, left as usize)
            {
                Ok((kv, more)) => {
                    if more {
                        if let Some((k, _)) = kv.last() {
                            cur.omap_offset = k.clone();
                        }
                    } else {
                        cur.omap_complete = true;
                    }
                    out.omap_data = opwire::omap_section(&kv);
                }
                Err(e) if e == errno::ENOENT => cur.omap_complete = true,
                Err(e) => return -e,
            }
        }
        out.cursor = cur;
        op.outdata = encb_with(&out, self.m.caller.features);
        0
    }

    /// copy-from / copy-from2 (destination side, final step): the engine fetched the whole source into `m.copy`;
    /// the destination is REPLACED by it (data, xattrs, omap, mtime, truncate seq/size).
    fn op_copy_from(&mut self, op: &OsdOp) -> i32 {
        if let Err(e) = copy_input(op, self.m.limits.max_oid_len) {
            return -e;
        }
        if self.copy_self == Some(self.cur) {
            return -errno::EINVAL;
        }
        let Some(c) = self.m.copy.clone() else {
            // Suspend only when sequential execution reaches COPY_FROM. Earlier guards must win over
            // source-fetch errors (nt-writepath-review.md, copy failure ordering).
            return -errno::EINPROGRESS;
        };
        if self.efbig(0, c.size) {
            return -errno::EFBIG;
        }
        // staged: the finished object is renamed into place instead of being created and written
        let place = |s: &mut Self| match &c.staged {
            Some(t) => s.push(MOp::RenameFrom { src: t.clone() }),
            None => s.push(MOp::Create),
        };
        if self.exists {
            let old = self.oi.size;
            self.push(MOp::Remove);
            place(self);
            if old > 0 {
                self.mark_modified(0, old);
            }
            self.oi.to_mut().flags &= !(oif::WHITEOUT | oif::OMAP);
            if self.present_before_copy() {
                // the old object is removed and recreated: REPLACE where the release allows it (client-ops 16.5)
                self.use_replace = true;
            } else {
                self.grew = true;
            }
        } else {
            self.exists = true;
            self.oi = Cow::Owned(ObjectInfo::new(self.m.head.clone()));
            place(self);
            self.grew = true;
        }
        // classic: copy-from is not a "user modify" op; the destination takes the SOURCE user_version (finish_copyfrom),
        // only other modifying ops of the same message bump it (finish_ctx)
        self.modify = true;
        let oi = self.oi.to_mut();
        oi.user_version = c.user_version;
        oi.size = c.size;
        if !c.data.is_empty() {
            self.push(MOp::Write {
                off: 0,
                src: Src::Own(c.data.clone()),
            });
        }
        if c.size > 0 {
            self.mark_modified(0, c.size);
        }
        self.dirty_data();
        for (k, v) in &c.attrs {
            self.push(MOp::SetAttr {
                name: kn(k),
                value: v.clone(),
            });
        }
        if c.has_omap || !c.omap_header.is_empty() || !c.omap.is_empty() {
            self.oi.to_mut().flags |= oif::OMAP;
            if !c.omap_header.is_empty() {
                self.push(MOp::OmapSetHeader(c.omap_header.clone()));
            }
            if !c.omap.is_empty() {
                self.push(MOp::OmapSetKeys(opwire::KvRun::from_pairs(
                    c.omap.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
                )));
            }
        }
        self.dirty_omap();
        let oi = self.oi.to_mut();
        oi.truncate_seq = c.truncate_seq;
        oi.truncate_size = c.truncate_size;
        oi.mtime = c.mtime;
        self.copy_mtime = Some(c.mtime);
        0
    }

    /// The destination was a live object (not absent, not a whiteout) when the message started.
    fn present_before_copy(&self) -> bool {
        self.pre.oi.as_ref().is_some_and(|o| !o.is_whiteout())
    }

    // ------------------------------------------------------------------ xattrs

    fn op_getxattr(&mut self, op: &mut OsdOp) -> i32 {
        // name_len bytes, value_len ignored (client-ops 16.3)
        let name = match op.xattr_name() {
            Ok(x) => x,
            Err(_) => return -errno::EINVAL,
        };
        match self.v.ov_getattr(self.m.spg, &self.tgt, &kn(name)) {
            Ok(Some(val)) => {
                let mut x = op.xattr();
                x.value_len = val.len() as u32;
                op.set_xattr(x);
                op.outdata = val.into();
                0
            }
            Ok(None) => -errno::ENODATA,
            Err(e) => -e,
        }
    }

    fn op_getxattrs(&mut self, op: &mut OsdOp) -> i32 {
        match self.v.ov_getattrs(self.m.spg, &self.tgt) {
            Ok(m) => {
                let user: BTreeMap<Vec<u8>, Vec<u8>> = m
                    .into_iter()
                    .filter(|(k, _)| k.len() > 1 && k[0] == b'_')
                    .map(|(k, v)| (k[1..].to_vec(), v))
                    .collect();
                op.outdata = encb(&user);
                0
            }
            Err(e) => -e,
        }
    }

    fn op_cmpxattr(&mut self, op: &mut OsdOp) -> i32 {
        let x = op.xattr();
        if !(1..=6).contains(&x.cmp_op) || !(1..=2).contains(&x.cmp_mode) {
            return -errno::EINVAL;
        }
        // string mode: `value_len` bytes after the name; u64 mode: an 8-byte LE u64 right after the name
        // (`value_len` not consulted, like classic)
        let (name, given) = if x.cmp_mode == cmp::MODE_STRING {
            match op.xattr_name_value() {
                Ok(x) => x,
                Err(_) => return -errno::EINVAL,
            }
        } else {
            let n = x.name_len as usize;
            match (op.indata.get(..n), op.indata.get(n..n.saturating_add(8))) {
                (Some(name), Some(v)) => (name, v),
                _ => return -errno::EINVAL,
            }
        };
        let stored = match self.v.ov_getattr(self.m.spg, &self.tgt, &kn(name)) {
            Ok(Some(v)) => v,
            Ok(None) => Vec::new(),
            Err(e) => return -e,
        };
        self.io.read(stored.len() as u64);
        let ord = if x.cmp_mode == cmp::MODE_STRING {
            given.cmp(stored.as_slice())
        } else {
            let g = u64::from_le_bytes(given.try_into().unwrap_or([0; 8]));
            let s = if stored.is_empty() {
                0
            } else {
                match leading_u64(&stored) {
                    Some(n) => n,
                    None => return -errno::EINVAL,
                }
            };
            g.cmp(&s)
        };
        use std::cmp::Ordering::*;
        let ok = match x.cmp_op {
            cmp::EQ => ord == Equal,
            cmp::NE => ord != Equal,
            cmp::GT => ord == Greater,
            cmp::GTE => ord != Less,
            cmp::LT => ord == Less,
            _ => ord != Greater,
        };
        if ok { 1 } else { -errno::ECANCELED }
    }

    fn op_setxattr(&mut self, op: &mut OsdOp) -> i32 {
        let (name, val) = match op.xattr_name_value() {
            Ok(x) => x,
            Err(_) => return -errno::EINVAL,
        };
        self.do_setxattr(name, val)
    }

    pub(crate) fn do_setxattr(&mut self, name: &[u8], val: &[u8]) -> i32 {
        let lim = &self.m.limits;
        if lim.max_attr_size > 0 && val.len() as u64 > lim.max_attr_size {
            return -errno::EFBIG;
        }
        // the store key is "_" + name: the store's key limit applies on top of the classic 100 (rule 9a)
        if name.len() > lim.max_attr_name_len || name.len() + 1 > self.v.ov_max_item_key() {
            return -errno::ENAMETOOLONG;
        }
        self.touch();
        self.user_modify = true;
        self.push(MOp::SetAttr {
            name: kn(name),
            value: val.to_vec(),
        });
        0
    }

    fn op_rmxattr(&mut self, op: &mut OsdOp) -> i32 {
        // name_len bytes, value_len ignored (client-ops 16.3)
        let name = match op.xattr_name() {
            Ok(x) => x,
            Err(_) => return -errno::EINVAL,
        };
        if !self.present() {
            return -errno::ENOENT;
        }
        self.push(MOp::RmAttr { name: kn(name) });
        self.modify = true;
        self.user_modify = true;
        0
    }

    // ------------------------------------------------------------------ omap

    fn omap_limits(&self, max_return: u64) -> usize {
        (max_return.min(self.m.limits.max_omap_entries as u64)) as usize
    }

    fn op_omap_get_keys(&mut self, op: &mut OsdOp) -> i32 {
        let inp: opwire::OmapGetKeysIn = match op.indata_as() {
            Ok(x) => x,
            Err(_) => return -errno::EINVAL,
        };
        if !self.oi.is_omap() {
            op.outdata = encb(&OmapKeysOut::default());
            return 0;
        }
        match self.omap_list(Some(&inp.start_after), &[], inp.max_return, false) {
            Ok(reply) => {
                op.outdata = reply;
                0
            }
            // object absent in the store (created by this message): an empty listing
            Err(e) if e == errno::ENOENT => {
                op.outdata = encb(&OmapKeysOut::default());
                0
            }
            Err(e) => -e,
        }
    }

    /// The target's complete immutable listing reply (`ObjView::ov_omap_list_reply`).
    fn omap_list(
        &self,
        after: Option<&[u8]>,
        prefix: &[u8],
        max: u64,
        values: bool,
    ) -> Result<bytes::Bytes, i32> {
        self.v.ov_omap_list_reply(
            self.m.spg,
            &self.tgt,
            after,
            prefix,
            self.omap_limits(max),
            self.m.limits.max_omap_bytes,
            values,
        )
    }

    pub(crate) fn omap_keys_range(
        &self,
        after: Option<&[u8]>,
        max: u64,
    ) -> Result<(Vec<Vec<u8>>, bool), i32> {
        if !self.oi.is_omap() {
            return Ok((Vec::new(), false));
        }
        match self.v.ov_omap_keys_range(
            self.m.spg,
            &self.tgt,
            after,
            &[],
            self.omap_limits(max),
            self.m.limits.max_omap_bytes,
        ) {
            Err(e) if e == errno::ENOENT => Ok((Vec::new(), false)),
            result => result,
        }
    }

    /// `None` = the object is absent in the store.
    fn omap_range_raw(
        &self,
        after: Option<&[u8]>,
        prefix: &[u8],
        max: u64,
    ) -> Result<Option<OmapPage>, i32> {
        match self.v.ov_omap_range(
            self.m.spg,
            &self.tgt,
            after,
            prefix,
            self.omap_limits(max),
            self.m.limits.max_omap_bytes,
        ) {
            Err(e) if e == errno::ENOENT => Ok(None),
            Err(e) => Err(e),
            Ok(x) => Ok(Some(x)),
        }
    }

    /// Flag-aware range for cls primitives: empty if the working object has no omap.
    pub(crate) fn omap_range(
        &self,
        after: Option<&[u8]>,
        prefix: &[u8],
        max: u64,
    ) -> Result<OmapPage, i32> {
        if !self.oi.is_omap() {
            return Ok((Vec::new(), false));
        }
        Ok(self.omap_range_raw(after, prefix, max)?.unwrap_or_default())
    }

    fn op_omap_get_vals(&mut self, op: &mut OsdOp) -> i32 {
        let inp: opwire::OmapGetValsIn = match op.indata_as() {
            Ok(x) => x,
            Err(_) => return -errno::EINVAL,
        };
        if !self.oi.is_omap() {
            op.outdata = encb(&OmapValsOut::default());
            return 0;
        }
        match self.omap_list(
            Some(&inp.start_after),
            &inp.filter_prefix,
            inp.max_return,
            true,
        ) {
            Ok(reply) => {
                op.outdata = reply;
                0
            }
            // object absent in the store (created by this message): success, no data
            Err(e) if e == errno::ENOENT => 0,
            Err(e) => -e,
        }
    }

    fn op_omap_get_header(&mut self, op: &mut OsdOp) -> i32 {
        if !self.oi.is_omap() {
            return 0;
        }
        match self.v.ov_omap_header(self.m.spg, &self.tgt) {
            Ok(h) => {
                op.outdata = h.into();
                0
            }
            Err(e) if e == errno::ENOENT => 0,
            Err(e) => -e,
        }
    }

    fn op_omap_get_by_keys(&mut self, op: &mut OsdOp) -> i32 {
        let keys: opwire::KeySet = match op.indata_as() {
            Ok(x) => x,
            Err(_) => return -errno::EINVAL,
        };
        let ks: Vec<&[u8]> = keys.iter().map(|k| k.as_slice()).collect();
        if !self.oi.is_omap() {
            op.outdata = encb(&BTreeMap::<Vec<u8>, Vec<u8>>::new());
            return 0;
        }
        match self.v.ov_omap_get(self.m.spg, &self.tgt, &ks) {
            Ok(m) => {
                op.outdata = encb(&m);
                0
            }
            // not in the store yet (created earlier in this message): an empty map, like an object without omap
            Err(e) if e == errno::ENOENT => {
                op.outdata = encb(&BTreeMap::<Vec<u8>, Vec<u8>>::new());
                0
            }
            Err(e) => -e,
        }
    }

    fn op_omap_cmp(&mut self, op: &mut OsdOp) -> i32 {
        // classic answers a missing object before it looks at the payload
        if !self.present() {
            return -errno::ENOENT;
        }
        let m: opwire::OmapCmpIn = match op.indata_as() {
            Ok(x) => x,
            Err(_) => return -errno::EINVAL,
        };
        let ks: Vec<&[u8]> = m.keys().map(|k| k.as_slice()).collect();
        let have = if self.oi.is_omap() {
            match self.v.ov_omap_get(self.m.spg, &self.tgt, &ks) {
                Ok(h) => h,
                Err(e) if e == errno::ENOENT => BTreeMap::new(),
                Err(e) => return -e,
            }
        } else {
            BTreeMap::new()
        };
        for (k, (expected, cop)) in &m {
            let stored = have.get(k).map(|v| v.as_slice()).unwrap_or(&[]);
            // wire op codes follow the cmpxattr enum: EQ 1, GT 3, LT 5 are the valid ones; GT/LT in classic bufferlist
            // order (platform `char`, cls::cmpomap::bufferlist_cmp)
            let ord = || cls::cmpomap::bufferlist_cmp(stored, expected);
            let ok = match *cop {
                1 => stored == expected.as_slice(),
                3 => ord().is_gt(),
                5 => ord().is_lt(),
                _ => return -errno::EINVAL,
            };
            if !ok {
                return -errno::ECANCELED;
            }
        }
        0
    }

    fn op_omap_set(&mut self, op: &mut OsdOp) -> i32 {
        let Ok(run) = opwire::KvRun::parse(&op.indata) else {
            return -errno::EINVAL;
        };
        self.do_omap_set(run)
    }

    pub(crate) fn do_omap_set(&mut self, pairs: opwire::KvRun) -> i32 {
        // a key the store can never hold would fail the whole txn after it was logged (rule 9a): refuse it here
        let maxk = self.v.ov_max_item_key();
        if pairs.iter().any(|(k, _)| k.len() > maxk) {
            return -errno::ENAMETOOLONG;
        }
        self.touch();
        self.user_modify = true;
        self.oi.to_mut().flags |= oif::OMAP;
        self.dirty_omap();
        self.push(MOp::OmapSetKeys(pairs));
        0
    }

    pub(crate) fn op_omap_set_header(&mut self, h: Vec<u8>) -> i32 {
        self.touch();
        self.user_modify = true;
        self.oi.to_mut().flags |= oif::OMAP;
        self.dirty_omap();
        self.push(MOp::OmapSetHeader(h));
        0
    }

    pub(crate) fn op_omap_clear(&mut self) -> i32 {
        if !self.present() {
            return -errno::ENOENT;
        }
        // only an object that has omap changes anything (client-ops 16.9): without FLAG_OMAP the message is a no-op
        // write, answered with a log-only ERROR entry (return code 0) and an untouched object_info
        if self.oi.flags & oif::OMAP != 0 {
            self.io.write(0);
            self.push(MOp::OmapClear);
            self.oi.to_mut().flags &= !oif::OMAP;
            self.dirty_omap();
            self.modify = true;
            self.user_modify = true;
        }
        0
    }

    fn op_omap_rm_keys(&mut self, op: &mut OsdOp) -> i32 {
        let keys: opwire::KeySet = match op.indata_as() {
            Ok(x) => x,
            Err(_) => return -errno::EINVAL,
        };
        self.do_omap_rm_keys(keys.into_iter().collect())
    }

    pub(crate) fn do_omap_rm_keys(&mut self, keys: Vec<Vec<u8>>) -> i32 {
        if !self.present() {
            return -errno::ENOENT;
        }
        self.push(MOp::OmapRmKeys(keys));
        self.dirty_omap();
        self.modify = true;
        self.user_modify = true;
        0
    }

    fn op_omap_rm_range(&mut self, op: &mut OsdOp) -> i32 {
        let r: opwire::OmapRmKeyRangeIn = match op.indata_as() {
            Ok(x) => x,
            Err(_) => return -errno::EINVAL,
        };
        self.do_omap_rm_range(r.begin, r.end)
    }

    pub(crate) fn do_omap_rm_range(&mut self, first: Vec<u8>, last: Vec<u8>) -> i32 {
        if !self.present() {
            return -errno::ENOENT;
        }
        self.push(MOp::OmapRmRange { first, last });
        self.dirty_omap();
        self.modify = true;
        self.user_modify = true;
        0
    }

    // ------------------------------------------------------------------ watch / notify (s10)

    fn op_watch(&mut self, op: &mut OsdOp) -> i32 {
        let w = op.watch();
        let key: WatchKey = (w.cookie, self.m.caller.name);
        let timeout = if w.timeout > 0 {
            w.timeout
        } else {
            self.m.limits.client_watch_timeout
        };
        match w.op {
            watch_op::WATCH | watch_op::LEGACY_WATCH => {
                if !self.present() {
                    return -errno::ENOENT;
                }
                if !self.oi.watchers.contains_key(&key) {
                    self.oi.to_mut().watchers.insert(
                        key,
                        WatchInfo {
                            cookie: w.cookie,
                            timeout_seconds: timeout,
                            addr: self.m.caller.addr,
                        },
                    );
                    self.modify = true;
                }
                let t = self
                    .oi
                    .watchers
                    .get(&key)
                    .map_or(timeout, |i| i.timeout_seconds);
                self.effects.push(Effect::WatchConnect {
                    key,
                    timeout: t,
                    will_ping: w.op == watch_op::WATCH,
                    addr: self.m.caller.addr,
                });
                0
            }
            watch_op::RECONNECT => {
                if !self.present() {
                    return -errno::ENOENT;
                }
                let Some(info) = self.oi.watchers.get(&key) else {
                    return -errno::ENOTCONN;
                };
                self.effects.push(Effect::WatchConnect {
                    key,
                    timeout: info.timeout_seconds,
                    will_ping: true,
                    addr: self.m.caller.addr,
                });
                0
            }
            watch_op::PING => {
                if !self.present() {
                    return -errno::ENOENT;
                }
                if !self.oi.watchers.contains_key(&key) {
                    return -errno::ENOTCONN;
                }
                if !self.m.connected.contains(&key) {
                    return -errno::ETIMEDOUT;
                }
                self.effects.push(Effect::WatchPing { key });
                0
            }
            watch_op::UNWATCH => {
                if !self.present() {
                    return -errno::ENOENT;
                }
                if self.oi.to_mut().watchers.remove(&key).is_some() {
                    self.modify = true;
                }
                self.effects.push(Effect::WatchRemove { key });
                0
            }
            _ => -errno::EINVAL,
        }
    }

    fn op_notify(&mut self, i: usize, op: &mut OsdOp) -> i32 {
        // classic decodes version, timeout and payload as one unit and treats any failure (short body, bad length) as
        // "default timeout, empty payload", never as an error; bytes after the payload are ignored
        let inp = decode_prefix::<opwire::NotifyIn>(&op.indata).unwrap_or_default();
        if !self.present() {
            return -errno::ENOENT;
        }
        let timeout = if inp.timeout == 0 {
            self.m.limits.default_notify_timeout
        } else {
            inp.timeout
        };
        self.effects.push(Effect::Notify {
            op_index: i,
            cookie: op.notify().cookie,
            timeout,
            payload: inp.payload,
        });
        0
    }

    fn op_notify_ack(&mut self, op: &mut OsdOp) -> i32 {
        if op.indata.is_empty() {
            self.effects.push(Effect::NotifyAck {
                notify_id: op.notify().cookie,
                cookie: 0,
                reply: Vec::new(),
                legacy: true,
            });
            return 0;
        }
        // a body that does not decode is the legacy form again (classic: the notify id sits in the op's cookie field)
        let Some(a) = decode_prefix::<opwire::NotifyAckIn>(&op.indata) else {
            self.effects.push(Effect::NotifyAck {
                notify_id: op.notify().cookie,
                cookie: 0,
                reply: Vec::new(),
                legacy: true,
            });
            return 0;
        };
        self.effects.push(Effect::NotifyAck {
            notify_id: a.notify_id,
            cookie: a.cookie,
            reply: a.reply,
            legacy: false,
        });
        0
    }

    // ------------------------------------------------------------------ rollback (s8.3)

    pub(crate) fn op_rollback(&mut self, snapid: u64) -> i32 {
        // resolve the target like a snap read
        let target = match crate::snap::resolve_snap(
            self.v,
            self.m.spg,
            &self.m.head,
            self.pre,
            snapid,
            0,
            &self.m.removed_snaps,
        ) {
            Ok(t) => t,
            Err(e) => return -e,
        };
        let (clone, coi) = match target {
            crate::snap::Target::Head => {
                // head is the target: nothing to copy, counts as a modification
                if !self.present() {
                    return self.rollback_delete();
                }
                self.modify = true;
                self.user_modify = true;
                return 0;
            }
            crate::snap::Target::Clone(c, oi) => (c, oi),
            crate::snap::Target::None => return self.rollback_delete(),
            crate::snap::Target::Damaged(c) => {
                self.damaged = Some(c);
                return -errno::EIO;
            }
        };
        if coi.is_whiteout() {
            return self.rollback_delete();
        }
        // replace the head by a copy of the clone
        let old_size = if self.present() { self.oi.size } else { 0 };
        let cid = clone.snap.0;
        // ranges that differ from the target: [0,size) minus the overlap chain from the clone forward
        let mut keep: Option<IntervalSet> = None;
        let mut started = false;
        for c in &self.pre.ss.clones {
            if c.0 == cid {
                started = true;
            }
            if started {
                let ov = self
                    .pre
                    .ss
                    .clone_overlap
                    .get(c)
                    .cloned()
                    .unwrap_or_default();
                keep = Some(match keep {
                    None => ov,
                    Some(k) => {
                        let mut r = IntervalSet::new();
                        for (a, l) in &k {
                            for (x, y) in interval::intersect_range(&ov, *a, a + l) {
                                r.insert(x, y);
                            }
                        }
                        r
                    }
                });
            }
        }
        let csize = coi.size;
        let diff = interval::complement_in(&keep.unwrap_or_default(), 0, csize.max(old_size));
        for (a, l) in diff {
            self.mark_modified(a, l);
        }
        if self.exists {
            self.push(MOp::Remove);
        }
        self.txn.push((
            clone.clone(),
            MOp::CloneTo {
                dst: self.m.head.clone(),
            },
        ));
        let watchers = std::mem::take(&mut self.oi.to_mut().watchers);
        let mut noi = ObjectInfo::new(self.m.head.clone());
        noi.size = coi.size;
        noi.flags = coi.flags & (oif::OMAP | oif::DATA_DIGEST | oif::OMAP_DIGEST);
        noi.data_digest = coi.data_digest;
        noi.omap_digest = coi.omap_digest;
        // the truncate hint stays the head's (s8.3: only size, digests and the omap flag come from the clone): an
        // older sequence would let a delayed write with the newer hint truncate the rolled-back content again
        noi.truncate_seq = self.oi.truncate_seq;
        noi.truncate_size = self.oi.truncate_size;
        noi.mtime = coi.mtime;
        noi.watchers = watchers;
        noi.version = self.oi.version;
        noi.user_version = self.oi.user_version;
        noi.expected_object_size = self.oi.expected_object_size;
        noi.expected_write_size = self.oi.expected_write_size;
        noi.alloc_hint_flags = self.oi.alloc_hint_flags;
        if !self.exists {
            self.grew = true;
        }
        self.oi = Cow::Owned(noi);
        self.exists = true;
        self.modify = true;
        self.user_modify = true;
        0
    }

    fn rollback_delete(&mut self) -> i32 {
        if !self.present() {
            // nothing to roll back to and nothing here: success without change
            return 0;
        }
        if !self.oi.watchers.is_empty() {
            return -errno::EBUSY;
        }
        self.op_delete()
    }

    // ------------------------------------------------------------------ cls

    fn op_call(&mut self, op: &mut OsdOp) -> i32 {
        let call = match op.cls_call() {
            Ok(c) => c,
            Err(_) => return -errno::EINVAL,
        };
        let (r, out) = crate::clsx::call(self, call.class, call.method, call.input);
        // keep the cls union intact: only the extent length field of the echo (offset 8) is rewritten
        op.u[8..16].copy_from_slice(&(out.len() as u64).to_le_bytes());
        op.outdata = out.into();
        r
    }

    // ------------------------------------------------------------------ finish (s5.7 steps 5-7, s8.1)

    /// Turn the executed message into an [`Outcome`]. `result` = message result from `run`.
    pub fn finish(mut self, ops: &mut [OsdOp], mut result: i32) -> Outcome {
        let m = self.m;
        let returnvec = m.flags & mflag::RETURNVEC != 0;
        let may_write = m.info.may_write;
        if may_write {
            // a write's outdata may go into its log entry: one buffer per op (reads keep their pieces by reference)
            for o in ops.iter_mut() {
                o.flatten_outdata();
            }
        }
        let pre_uv = self.pre.oi.as_ref().map_or(0, |o| o.user_version);
        let mut out = Outcome {
            result,
            disp: Disposition::Reply,
            plan: WritePlan::default(),
            effects: Vec::new(),
            new_state: ObjState::default(),
            user_version: pre_uv,
            replay_version: Eversion::default(),
            keep_outdata: true,
            damaged: self.damaged.take(),
            // a failed message counts nothing (spec pg-io-stats.md 1)
            io: if result < 0 {
                IoCount::default()
            } else {
                self.io
            },
        };
        if result < 0 {
            if may_write {
                out.disp = Disposition::LogOnly;
                let mut e = error_entry(&m.head, pre_uv, result);
                // classic logs the per-op results of a failed write unconditionally (a resend gets the same rvals);
                // outdata is bounded so a failing message with a big read cannot bloat the log
                e.op_returns = logged_returns(ops);
                out.plan.entries.push(e);
            }
            return out;
        }
        if !may_write {
            out.effects = std::mem::take(&mut self.effects);
            return out;
        }
        if !(self.modify || !self.txn.is_empty()) {
            // a write that changed nothing: log-only entry with its result, reply after commit (never ahead of the
            // object's in-flight writes, and a resend is a dup); outdata stays, per-op results logged for RETURNVEC
            out.disp = Disposition::LogOnly;
            out.effects = std::mem::take(&mut self.effects);
            let mut e = error_entry(&m.head, pre_uv, result);
            if returnvec {
                e.op_returns = logged_returns(ops);
            }
            out.plan.entries.push(e);
            return out;
        }
        // ---- a real mutation
        // RETURNVEC: per-op outdata cap
        if returnvec {
            for o in ops.iter() {
                if o.outdata.len() > m.limits.max_write_op_reply_len {
                    let mut out2 = out;
                    out2.result = -errno::EOVERFLOW;
                    return self.fail_overflow(ops, out2);
                }
            }
        }
        // local store full (failsafe): plain -ENOSPC, even with FULL_TRY / FULL_FORCE (hard limit, never a crash)
        if m.no_room {
            out.result = -errno::ENOSPC;
            return out;
        }
        // full check (step 5)
        let grows = self.grew || self.oi.size > self.pre.oi.as_ref().map_or(0, |o| o.size);
        // MDS writes pass a full pool (classic: file removals / journal must not wedge)
        let mds = m.reqid.name.ty == denc::types::EntityName::MDS;
        if grows && m.pool_full && !mds && m.flags & (mflag::FULL_TRY | mflag::FULL_FORCE) == 0 {
            // dropped without a reply: -EAGAIN would make the stock client resend at once, with the same old map
            out.result = -errno::EAGAIN;
            out.disp = Disposition::Drop;
            return out;
        }
        if grows && m.pool_full && !mds && m.flags & mflag::FULL_FORCE == 0 {
            out.result = -(if m.pool_full_quota {
                errno::EDQUOT
            } else {
                errno::ENOSPC
            });
            return out;
        }
        let pre_present = self.pre.present();
        let snapc = &m.snapc;
        let need_clone = pre_present && snapc.snaps.first().is_some_and(|s| *s > self.pre.ss.seq);
        let mut v = m.at_version;
        // the head entry, plus the clone's
        let mut entries: Vec<WriteEntry> = Vec::with_capacity(1 + usize::from(need_clone));
        // the clone's ops go first, then the message's own ops (`self.txn`) and the head's attributes
        let mut txn: Vec<(Hobject, MOp)> = Vec::new();
        let mut ss = self.pre.ss.clone();
        // `ss` differs from the stored `pre.ss`: a new clone, a shrunk overlap or a newer seq
        let mut ss_changed = need_clone;
        // ---- make_writeable
        if need_clone {
            let pre_oi = self.pre.oi.clone().unwrap_or_default();
            let cid = snapc.seq;
            let mut coid = m.head.clone();
            coid.snap = SnapId(cid);
            let clone_snaps: Vec<u64> = snapc
                .snaps
                .iter()
                .copied()
                .take_while(|s| *s > self.pre.ss.seq)
                .collect();
            let mut coi = ObjectInfo::new(coid.clone());
            copy_user_bits(&mut coi, &pre_oi);
            coi.version = v;
            coi.prior_version = pre_oi.version;
            txn.push((m.head.clone(), MOp::CloneTo { dst: coid.clone() }));
            txn.push((
                coid.clone(),
                MOp::RmAttr {
                    name: b"snapset".to_vec(),
                },
            ));
            txn.push((
                coid.clone(),
                MOp::SetAttr {
                    name: b"_".to_vec(),
                    value: enc(&coi),
                },
            ));
            ss.clones.push(SnapId(cid));
            ss.clone_size.insert(SnapId(cid), pre_oi.size);
            ss.clone_snaps.insert(
                SnapId(cid),
                clone_snaps.iter().map(|s| SnapId(*s)).collect(),
            );
            let mut ov = IntervalSet::new();
            if pre_oi.size > 0 {
                ov.insert(0, pre_oi.size);
            }
            ss.clone_overlap.insert(SnapId(cid), ov);
            entries.push(WriteEntry {
                op: LogOp::CLONE,
                soid: coid,
                user_version: pre_oi.user_version,
                mtime: pre_oi.mtime,
                snaps: peering::snaps::encode_snaps(&clone_snaps),
                return_code: 0,
                op_returns: Vec::new(),
                prior: None,
            });
            v = Eversion::new(v.epoch, v.version + 1);
        }
        // newest clone's overlap shrinks by what this message modified
        if let Some(last) = ss.clones.last().copied()
            && let Some(ov) = ss.clone_overlap.get_mut(&last)
            && !self.modified.is_empty()
        {
            for (a, l) in &self.modified {
                ss_changed |= subtract(ov, *a, *l);
            }
        }
        if snapc.seq > ss.seq {
            ss.seq = snapc.seq;
            ss_changed = true;
        }
        // ---- head
        if txn.is_empty() {
            txn = std::mem::take(&mut self.txn);
        } else {
            txn.append(&mut self.txn);
        }
        txn.reserve(2); // object_info + snapset
        let head_exists = self.exists;
        let mut oi = std::mem::take(&mut self.oi).into_owned();
        let mut uv = pre_uv;
        let mut lop = LogOp::MODIFY;
        if head_exists {
            if oi.soid != m.head {
                oi.soid = m.head.clone();
            }
            oi.prior_version = self
                .pre
                .oi
                .as_ref()
                .map_or(Eversion::default(), |o| o.version);
            oi.version = v;
            oi.last_reqid = m.reqid;
            if let Some(t) = self.copy_mtime {
                oi.mtime = t;
            } else if m.mtime != UTime::default() {
                oi.mtime = m.mtime;
                oi.local_mtime = m.now;
            }
            if self.undirty {
                oi.flags &= !oif::DIRTY;
            } else {
                oi.flags |= oif::DIRTY;
            }
            if self.user_modify {
                // a stored / copied user_version may already sit at u64::MAX: it must never wrap to 0
                uv = m.last_user_version.max(oi.user_version).saturating_add(1);
                uv = uv.max(v.version);
                oi.user_version = uv;
            } else {
                uv = oi.user_version;
            }
            txn.push((
                m.head.clone(),
                MOp::SetAttr {
                    name: b"_".to_vec(),
                    value: enc(&oi),
                },
            ));
            // the snapset of an overwrite that clones nothing and moves no seq is what the store holds already: not
            // rewritten (one tree put less on the primary and on every replica, an RBD overwrite never changes it)
            if !(self.pre.oi.is_some()
                && self.pre.ss_stored
                && !ss_changed
                && snapset_attr_untouched(&txn, &m.head))
            {
                txn.push((
                    m.head.clone(),
                    MOp::SetAttr {
                        name: b"snapset".to_vec(),
                        value: enc(&ss),
                    },
                ));
            }
            if oi.is_whiteout() && self.whiteouted {
                // REPLACE only where every peer can replay it (umbrella+, client-ops 16.5); else MODIFY: the
                // whiteout head still exists after this entry, and a DELETE would make a recovering peer remove it
                // with its SnapSet, orphaning the clones
                lop = if m.require_osd_release >= cls::release::UMBRELLA {
                    LogOp::REPLACE
                } else {
                    LogOp::MODIFY
                };
            } else if self.use_replace {
                lop = if m.require_osd_release >= cls::release::UMBRELLA {
                    LogOp::REPLACE
                } else {
                    LogOp::MODIFY
                };
            }
        } else {
            lop = LogOp::DELETE;
            if self.user_modify {
                uv = m.last_user_version.max(pre_uv).saturating_add(1);
                uv = uv.max(v.version);
            }
            ss = SnapSet::default();
        }
        let (rc, opr) = if returnvec {
            (
                result,
                ops.iter()
                    .map(|o| LogOpReturnItem {
                        rval: o.rval,
                        outdata: o.outdata.to_vec(),
                    })
                    .collect(),
            )
        } else {
            (0, Vec::new())
        };
        entries.push(WriteEntry {
            op: lop,
            soid: m.head.clone(),
            user_version: uv,
            mtime: if let Some(t) = self.copy_mtime {
                t
            } else if m.mtime != UTime::default() {
                m.mtime
            } else {
                self.pre.oi.as_ref().map_or(UTime::default(), |o| o.mtime)
            },
            snaps: Vec::new(),
            return_code: rc,
            op_returns: opr,
            prior: Some(
                self.pre
                    .oi
                    .as_ref()
                    .map_or_else(Eversion::default, |o| o.version),
            ),
        });
        // a cls method's writes are not in the admission cost (its input only): the planned txn's store cost goes along
        // for the engine's room check (never for a txn that only removes or shrinks, like the admission's pure-shrink rule)
        let cost = ops.iter().any(|o| o.op == code::CALL) && txn_grows(&txn);
        out.plan.txn = match encode_txn(m.spg, &txn, ops, cost) {
            Ok((b, refs, room)) => {
                out.plan.room = room;
                out.plan.txn_ref_crcs = ops
                    .iter()
                    .filter(|o| refs.iter().any(|r| o.indata_crc.of(r).is_some()))
                    .map(|o| o.indata_crc.clone())
                    .collect();
                out.plan.txn_refs = refs;
                b
            }
            Err(_) => {
                out.result = -errno::EINVAL;
                return out;
            }
        };
        out.plan.entries = entries;
        out.disp = Disposition::Write;
        out.user_version = uv;
        out.replay_version = v;
        out.keep_outdata = returnvec;
        out.effects = std::mem::take(&mut self.effects);
        out.new_state = ObjState {
            oi: if head_exists { Some(oi) } else { None },
            ss,
            ss_stored: head_exists,
        };
        if !returnvec {
            result = 0;
        }
        out.result = result;
        out
    }

    fn fail_overflow(self, ops: &mut [OsdOp], mut out: Outcome) -> Outcome {
        for o in ops.iter_mut() {
            if o.outdata.len() > self.m.limits.max_write_op_reply_len {
                o.rval = -errno::EOVERFLOW;
                o.clear_outdata();
            }
        }
        out.disp = Disposition::Reply;
        out.result = -errno::EOVERFLOW;
        out
    }
}

/// Per-op outdata kept in the log entry of a failed write (classic keeps any size; ours is bounded, client-ops 5.6).
const ERR_OUTDATA_MAX: usize = 4096;

/// Per-op results of a log-only entry (failed or no-op write), outdata bounded by [`ERR_OUTDATA_MAX`].
fn logged_returns(ops: &[OsdOp]) -> Vec<LogOpReturnItem> {
    ops.iter()
        .map(|o| LogOpReturnItem {
            rval: o.rval,
            outdata: if o.outdata.len() <= ERR_OUTDATA_MAX {
                o.outdata.to_vec()
            } else {
                Vec::new()
            },
        })
        .collect()
}

fn error_entry(head: &Hobject, uv: u64, rc: i32) -> WriteEntry {
    WriteEntry {
        op: LogOp::ERROR,
        soid: head.clone(),
        user_version: uv,
        mtime: UTime::default(),
        snaps: Vec::new(),
        return_code: rc,
        op_returns: Vec::new(),
        prior: None,
    }
}

/// `copy_user_bits` (replication.md 5.1).
fn copy_user_bits(dst: &mut ObjectInfo, src: &ObjectInfo) {
    dst.size = src.size;
    dst.mtime = src.mtime;
    dst.local_mtime = src.local_mtime;
    dst.last_reqid = src.last_reqid;
    dst.truncate_seq = src.truncate_seq;
    dst.truncate_size = src.truncate_size;
    dst.flags = src.flags & !(oif::WHITEOUT | oif::LOST);
    dst.user_version = src.user_version;
    dst.data_digest = src.data_digest;
    dst.omap_digest = src.omap_digest;
    dst.expected_object_size = src.expected_object_size;
    dst.expected_write_size = src.expected_write_size;
    dst.alloc_hint_flags = src.alloc_hint_flags;
}

/// `s -= [off, off+len)`; true when that removed something.
fn subtract(s: &mut IntervalSet, off: u64, len: u64) -> bool {
    if len == 0 {
        return false;
    }
    let end = off + len;
    let hits: Vec<(u64, u64)> = s
        .iter()
        .filter(|(a, l)| **a < end && **a + **l > off)
        .map(|(a, l)| (*a, *l))
        .collect();
    let changed = !hits.is_empty();
    for (a, l) in hits {
        s.remove(&a);
        if a < off {
            s.insert(a, off - a);
        }
        if a + l > end {
            s.insert(end, a + l - end);
        }
    }
    changed
}

/// `txn` may need store room: it creates or sets something (a txn that only removes or shrinks is never refused for space).
fn txn_grows(txn: &[(Hobject, MOp)]) -> bool {
    txn.iter().any(|(_, op)| {
        matches!(
            op,
            MOp::Create
                | MOp::Write { .. }
                | MOp::SetAttr { .. }
                | MOp::OmapSetKeys(_)
                | MOp::OmapSetHeader(_)
                | MOp::CloneTo { .. }
                | MOp::RenameFrom { .. }
        )
    })
}

/// `(blob, refs, store room)` of [`encode_txn`].
type EncodedTxn = (bytes::Bytes, Vec<bytes::Bytes>, (u64, u64));

/// Encode the owned mutation into a replwire transaction: `(blob, refs)`. With empty `refs` the blob is the plain v9
/// transaction (valid for every peer). Otherwise it is the LOCAL skeleton (`Transaction::encode_v9_split`) and `refs`
/// are the large client write payloads, shared with the request (no copy); the primary turns it into the real blob
/// only when a peer needs it. `cost` = also return the store room the transaction needs
/// ([`replwire::Transaction::room_cost`], the counter of the replica-side space preflight); `(0, 0)` otherwise.
pub(crate) fn encode_txn(
    spg: denc::types::SpgT,
    txn: &[(Hobject, MOp)],
    ops: &[OsdOp],
    cost: bool,
) -> denc::Result<EncodedTxn> {
    let _s = wprof::span(wprof::S::TxnEnc);
    encode_txn_min(spg, txn, ops, replwire::SPLIT_MIN, cost)
}

/// [`encode_txn`] of the plain overwrite `[Write { off, indata }, SetAttr { "_", oi }]` on `head`, without the owned
/// mutation list (same bytes, `fast::overwrite`).
pub(crate) fn encode_overwrite(
    spg: denc::types::SpgT,
    head: &Hobject,
    off: u64,
    data: &bytes::Bytes,
    oi: &[u8],
) -> denc::Result<(bytes::Bytes, Vec<bytes::Bytes>)> {
    let _s = wprof::span(wprof::S::TxnEnc);
    let mut t = Transaction::new();
    let cx = t.coll(&CollT::Pg(spg));
    let ox = t.obj(&Ghobject::head(head.clone(), spg.shard));
    t.push(
        cx,
        TxnOp::Write {
            oid: ox,
            off,
            data: replwire::Data::new(data),
        },
    );
    t.push(
        cx,
        TxnOp::SetAttrs {
            oid: ox,
            attrs: vec![(b"_".as_slice(), oi)],
        },
    );
    if data.len() < replwire::SPLIT_MIN {
        return Ok((t.encode_v9_placed()?, Vec::new()));
    }
    Ok((t.encode_v9_split(&|i| i == 0)?.into(), vec![data.clone()]))
}

/// [`encode_txn`] with the out-of-line threshold as a parameter (`usize::MAX` = always the plain v9 blob).
fn encode_txn_min(
    spg: denc::types::SpgT,
    txn: &[(Hobject, MOp)],
    ops: &[OsdOp],
    split_min: usize,
    cost: bool,
) -> denc::Result<EncodedTxn> {
    let mut t = Transaction::new();
    let mut refs: Vec<bytes::Bytes> = Vec::new();
    let mut ool: Vec<bool> = Vec::with_capacity(txn.len());
    let cx = t.coll(&CollT::Pg(spg));
    let shard: ShardId = spg.shard;
    // consecutive ops on the same object (a write and its attrs): interned once, no Ghobject built per op
    let mut last: Option<(&Hobject, replwire::Ox)> = None;
    for (obj, op) in txn {
        let ox = match last {
            Some((o, x)) if o == obj => x,
            _ => {
                let x = t.obj(&Ghobject::head(obj.clone(), shard));
                last = Some((obj, x));
                x
            }
        };
        let mut out_of_line = false;
        let top = match op {
            MOp::Create => TxnOp::Create { oid: ox },
            MOp::Write { off, src } => {
                let d: &[u8] = match src {
                    Src::Op(i) | Src::Prefix(i, _) => {
                        let b = &ops[*i].indata;
                        let len = match src {
                            Src::Prefix(_, len) => *len,
                            _ => b.len(),
                        };
                        if len >= split_min {
                            out_of_line = true;
                            refs.push(b.slice(..len));
                        }
                        &b[..len]
                    }
                    Src::Own(v) => v,
                };
                TxnOp::Write {
                    oid: ox,
                    off: *off,
                    data: replwire::Data::new(d),
                }
            }
            MOp::Zero { off, len } => TxnOp::Zero {
                oid: ox,
                off: *off,
                len: *len,
            },
            MOp::Truncate { size } => TxnOp::Truncate {
                oid: ox,
                size: *size,
            },
            MOp::Remove => TxnOp::Remove { oid: ox },
            MOp::SetAttr { name, value } => TxnOp::SetAttrs {
                oid: ox,
                attrs: vec![(name.as_slice(), value.as_slice())],
            },
            MOp::RmAttr { name } => TxnOp::RmAttr { oid: ox, name },
            MOp::CloneTo { dst } => {
                let dx = t.obj(&Ghobject::head(dst.clone(), shard));
                TxnOp::Clone {
                    oid: ox,
                    dest_oid: dx,
                }
            }
            MOp::OmapClear => TxnOp::OmapClear { oid: ox },
            MOp::OmapSetKeys(p) => {
                let run = p.view();
                if run.entries().len() >= split_min {
                    // the client's run stays shared: no copy into the skeleton, none into the peers' message
                    out_of_line = true;
                    refs.push(p.encoded().slice(4..));
                }
                TxnOp::OmapSetKeys {
                    oid: ox,
                    pairs: replwire::OmapKv::Run(run),
                }
            }
            MOp::OmapRmKeys(k) => TxnOp::OmapRmKeys {
                oid: ox,
                keys: k.iter().map(|k| k.as_slice()).collect(),
            },
            MOp::OmapRmRange { first, last } => TxnOp::OmapRmKeyRange {
                oid: ox,
                first,
                last,
            },
            MOp::OmapSetHeader(h) => TxnOp::OmapSetHeader { oid: ox, header: h },
            MOp::SetAllocHint { oso, wso, flags } => TxnOp::SetAllocHint {
                oid: ox,
                expected_object_size: *oso,
                expected_write_size: *wso,
                flags: *flags,
            },
            MOp::RenameFrom { src } => {
                let sx = t.obj(&Ghobject::head(src.clone(), shard));
                TxnOp::TryRename {
                    oid: sx,
                    dest_oid: ox,
                }
            }
        };
        ool.push(out_of_line);
        t.push(cx, top);
    }
    let room = if cost { t.room_cost() } else { (0, 0) };
    if refs.is_empty() {
        return Ok((t.encode_v9_placed()?, refs, room));
    }
    Ok((t.encode_v9_split(&|i| ool[i])?.into(), refs, room))
}

impl<V: ObjView> std::fmt::Debug for Exec<'_, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Exec(head={:?}, exists={})",
            self.m.head.oid, self.exists
        )
    }
}

/// No op of `txn` can have replaced or dropped the `snapset` attribute of `head`: only data, omap and other attribute
/// mutations of it (a rollback clones another object over it, a remove / rename-from rebuilds it).
fn snapset_attr_untouched(txn: &[(Hobject, MOp)], head: &Hobject) -> bool {
    txn.iter().all(|(o, op)| match op {
        MOp::CloneTo { dst } => dst != head,
        MOp::RenameFrom { .. } => o != head,
        MOp::Remove => o != head,
        MOp::SetAttr { name, .. } | MOp::RmAttr { name } => o != head || name != b"snapset",
        _ => true,
    })
}

#[cfg(test)]
mod split_golden {
    //! The repop / EC sub-write blob of a client write must be byte-identical whether the primary keeps large payloads
    //! out of line (local skeleton + `WriteReq::wire`) or encodes the plain v9 blob directly (the pre-split behavior),
    //! for every mutation shape the executor emits.
    use super::*;
    use denc::types::{PgT, SpgT};

    fn pat(n: usize, seed: u8) -> Vec<u8> {
        (0..n)
            .map(|i| (i as u8).wrapping_mul(29).wrapping_add(seed))
            .collect()
    }

    fn ho(name: &[u8]) -> Hobject {
        Hobject {
            oid: name.to_vec(),
            ..Hobject::MIN()
        }
    }

    fn check(spg: SpgT, txn: &[(Hobject, MOp)], ops: &[OsdOp], want_refs: usize) {
        let (plain, none, _) = encode_txn_min(spg, txn, ops, usize::MAX, false).unwrap();
        assert!(none.is_empty());
        let (skel, refs, _) = encode_txn(spg, txn, ops, false).unwrap();
        assert_eq!(refs.len(), want_refs, "out-of-line payloads");
        if want_refs == 0 {
            assert_eq!(skel, plain, "no large write: the plain blob itself");
        }
        // payloads are shared with the request (write data) or the op's omap run (its entries), never copied
        for r in &refs {
            assert!(
                ops.iter().any(|o| o.indata.as_ptr() == r.as_ptr())
                    || txn.iter().any(|(_, m)| matches!(m,
                        MOp::OmapSetKeys(p) if p.encoded()[4..].as_ptr() == r.as_ptr())),
                "out-of-line payload not shared"
            );
        }
        let w = peering::WriteReq {
            reqid: Default::default(),
            entries: vec![],
            txn_middle: bytes::Bytes::new(),
            txn_data: skel,
            txn_refs: refs,
            ..Default::default()
        };
        let (m, d) = w.wire().unwrap();
        assert!(m.is_empty());
        assert!(
            d[..] == plain[..],
            "wire blob differs from the plain v9 blob"
        );
        // the local apply decodes the same transaction a replica decodes
        let local =
            Transaction::decode_split(&w.txn_data, &w.txn_refs, replwire::DEFAULT_PAGE).unwrap();
        let peer = Transaction::decode(&[], &plain, replwire::DEFAULT_PAGE).unwrap();
        assert_eq!(local.ops, peer.ops);
        assert_eq!((local.colls, local.objs), (peer.colls, peer.objs));
    }

    fn every_shape(big: &[OsdOp]) -> Vec<(Hobject, MOp)> {
        let (a, b, c) = (ho(b"a"), ho(b"b"), ho(b"c"));
        let mut v = vec![
            (a.clone(), MOp::Create),
            (
                a.clone(),
                MOp::SetAllocHint {
                    oso: 4 << 20,
                    wso: 4 << 20,
                    flags: 0,
                },
            ),
            (
                a.clone(),
                MOp::Write {
                    off: 0,
                    src: Src::Op(0),
                },
            ),
            (
                a.clone(),
                MOp::SetAttr {
                    name: b"_".to_vec(),
                    value: pat(250, 1),
                },
            ),
            (
                a.clone(),
                MOp::Write {
                    off: 7,
                    src: Src::Own(pat(100_000, 2)),
                },
            ),
            (
                a.clone(),
                MOp::Zero {
                    off: 4096,
                    len: 65_536,
                },
            ),
            (a.clone(), MOp::Truncate { size: 3 << 20 }),
            (
                a.clone(),
                MOp::OmapSetKeys(opwire::KvRun::from_pairs([
                    (&b"k1"[..], &pat(70_000, 3)[..]),
                    (&b"k2"[..], &[][..]),
                ])),
            ),
            (a.clone(), MOp::OmapRmKeys(vec![b"k0".to_vec()])),
            (
                a.clone(),
                MOp::OmapRmRange {
                    first: b"a".to_vec(),
                    last: b"b".to_vec(),
                },
            ),
            (a.clone(), MOp::OmapSetHeader(pat(9, 4))),
            (
                a.clone(),
                MOp::RmAttr {
                    name: b"x".to_vec(),
                },
            ),
            (a.clone(), MOp::CloneTo { dst: b.clone() }),
            (
                b.clone(),
                MOp::Write {
                    off: 12_345,
                    src: Src::Op(1),
                },
            ),
            (
                b.clone(),
                MOp::Write {
                    off: 0,
                    src: Src::Op(2),
                },
            ),
            (c.clone(), MOp::OmapClear),
            (
                c.clone(),
                MOp::Write {
                    off: 1,
                    src: Src::Op(0),
                },
            ),
            (c.clone(), MOp::Remove),
        ];
        if big.len() > 3 {
            v.push((
                c,
                MOp::Write {
                    off: 0,
                    src: Src::Op(3),
                },
            ));
        }
        v
    }

    #[test]
    fn clipped_payload_wire_matches_inline_encoding() {
        let m = replwire::SPLIT_MIN;
        let ops = [OsdOp::write(0, pat(m * 2, 7))];
        for shard in [ShardId::NO_SHARD, ShardId(2)] {
            let spg = SpgT {
                pgid: PgT { pool: 1, seed: 7 },
                shard,
            };
            for len in [0, m - 1, m, m + 1] {
                let txn = [(
                    ho(b"o"),
                    MOp::Write {
                        off: 17,
                        src: Src::Prefix(0, len),
                    },
                )];
                check(spg, &txn, &ops, usize::from(len >= m));
            }
        }
    }

    #[test]
    fn wire_blob_is_byte_identical_for_every_txn_shape() {
        let rep = SpgT {
            pgid: PgT { pool: 1, seed: 7 },
            shard: ShardId::NO_SHARD,
        };
        let ec = SpgT {
            pgid: PgT { pool: 2, seed: 3 },
            shard: ShardId(2),
        };
        let m = replwire::SPLIT_MIN;
        // op 0 big, op 1 exactly at the threshold, op 2 just below it (stays inline), op 3 empty
        let ops = vec![
            OsdOp::write(0, pat(4 << 20, 9)),
            OsdOp::write(0, pat(m, 10)),
            OsdOp::write(0, pat(m - 1, 11)),
            OsdOp::write(0, vec![]),
        ];
        for spg in [rep, ec] {
            // ops 0 (twice) and 1, and the 70 KB omap run, out of line, in op order
            check(spg, &every_shape(&ops), &ops, 4);
            // single big write (the 4M RBD case)
            check(
                spg,
                &[(
                    ho(b"r"),
                    MOp::Write {
                        off: 0,
                        src: Src::Op(0),
                    },
                )],
                &ops,
                1,
            );
            // small writes only: no skeleton at all
            check(
                spg,
                &[
                    (
                        ho(b"r"),
                        MOp::Write {
                            off: 0,
                            src: Src::Op(2),
                        },
                    ),
                    (ho(b"r"), MOp::Truncate { size: 1 }),
                ],
                &ops,
                0,
            );
        }
    }
}

/// Read output pieces in order, each with the crc32c (seed `!0`) of exactly its bytes when known.
type Parts = Vec<(bytes::Bytes, Option<u32>)>;

/// Cut `parts` to at most `len` bytes (a cut piece's crc is not known any more).
fn clip_parts(parts: &mut Parts, len: usize) {
    let mut left = len;
    parts.retain_mut(|(b, c)| {
        if left == 0 {
            return false;
        }
        if b.len() > left {
            b.truncate(left);
            *c = None;
        }
        left -= b.len();
        true
    });
}

/// Header of a sparse read reply of `n` data bytes at `off` (one extent, none when `n == 0`).
fn sparse_head(off: u64, n: usize) -> Vec<u8> {
    debug_assert!(
        n <= u32::MAX as usize,
        "sparse reply payload fits its u32 length"
    );
    let mut out = SparseReadOut::default();
    if n > 0 {
        out.extents.insert(off, n as u64);
    }
    let mut h = enc(&out.extents);
    h.extend_from_slice(&(n as u32).to_le_bytes());
    h
}

/// SparseReadOut encoding of one extent at `off` whose `n` data bytes are `data` (extent map, then the data as a
/// length-prefixed blob) as pieces: the header, then the data pieces untouched (no copy, no pass over the data).
fn sparse_parts(off: u64, n: usize, data: Parts) -> Parts {
    let h = sparse_head(off, n);
    let c = crc::crc32c(!0, &h);
    std::iter::once((bytes::Bytes::from(h), Some(c)))
        .chain(data)
        .collect()
}

/// Decode the leading value of a client payload; bytes after it are ignored (classic decodes from an iterator and
/// never requires the buffer to end).
fn decode_prefix<'a, T: denc::Decode<'a>>(b: &'a [u8]) -> Option<T> {
    T::decode(&mut denc::Decoder::new(b)).ok()
}

/// The stored text of a u64 CMPXATTR: the leading run of ASCII decimal digits as u64, trailing bytes ignored; no
/// sign and no leading whitespace (classic `std::from_chars`). `None` = no digit or overflow (EINVAL).
fn leading_u64(b: &[u8]) -> Option<u64> {
    let n = b.iter().take_while(|c| c.is_ascii_digit()).count();
    if n == 0 {
        return None;
    }
    b[..n].iter().try_fold(0u64, |a, c| {
        a.checked_mul(10)?.checked_add(u64::from(c - b'0'))
    })
}

#[cfg(test)]
mod sparse_tests {
    use super::*;

    fn flat(p: &Parts) -> Vec<u8> {
        p.iter().flat_map(|(b, _)| b.iter().copied()).collect()
    }

    #[test]
    fn sparse_read_output_decodes_and_its_crc_hints_are_the_crcs_of_the_pieces() {
        let d: Vec<u8> = (0..(1u32 << 20) + 4097)
            .map(|i| (i * 7 + 3) as u8)
            .collect();
        let pieces: Parts = d
            .chunks(300_000)
            .map(|c| (bytes::Bytes::copy_from_slice(c), Some(crc::crc32c(!0, c))))
            .collect();
        let p = sparse_parts(12_288, d.len(), pieces);
        for (b, c) in &p {
            assert_eq!(*c, Some(crc::crc32c(!0, b)));
        }
        let v = flat(&p);
        let o = <SparseReadOut as denc::Decode>::decode(&mut denc::Decoder::new(&v)).unwrap();
        assert_eq!(
            o.extents.into_iter().collect::<Vec<_>>(),
            vec![(12_288, d.len() as u64)]
        );
        assert!(o.data == d);
        let v = flat(&sparse_parts(0, 0, Vec::new()));
        let o = <SparseReadOut as denc::Decode>::decode(&mut denc::Decoder::new(&v)).unwrap();
        assert!(o.extents.is_empty() && o.data.is_empty());
    }

    #[test]
    fn clip_cuts_pieces_and_forgets_cut_crcs() {
        let b = |n: usize| (bytes::Bytes::from(vec![7u8; n]), Some(1u32));
        let mut p = vec![b(10), b(10), b(10)];
        clip_parts(&mut p, 15);
        assert_eq!(p.len(), 2);
        assert_eq!((p[0].0.len(), p[0].1), (10, Some(1)));
        assert_eq!((p[1].0.len(), p[1].1), (5, None));
        let mut p = vec![b(10)];
        clip_parts(&mut p, 10);
        assert_eq!(p[0].1, Some(1));
    }
}
