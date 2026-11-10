// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! copy-from / copy-from2, destination side (spec copy.md): the primary of the destination PG pulls the source
//! object chunk by chunk with `copy-get` reads (the source may live in this PG, another PG of this OSD or another
//! OSD). A source that fits ONE chunk is kept in memory and the original message runs with it (one transaction, one
//! log entry). A bigger one is written chunk by chunk into a temp object of the PG (replicated to the acting set like
//! a recovery temp, never logged, so no transaction ever grows with the object) and the original message then
//! renames it into place: the destination still changes in ONE transaction (atomic, one log entry). The destination
//! object is blocked for other ops while the copy runs.

use super::*;
use crate::exec::{MOp, Src};
use opwire::{CopyCursor, CopyData, copy_flag};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Pseudo connection id of the engine's own source reads (same-PG loopback); their replies never leave the engine.
pub const COPY_CONN: u64 = u64::MAX - 1;
/// Chunk size of one copy-get (`osd_copyfrom_max_chunk`; classic uses 8 MiB). 4 MiB = 1024 blocks: one staged chunk write can not exceed the
/// data extents of one store txn (device queue depth - 34) even on a fully fragmented replica, which a bigger chunk could (adr 0057 am. 1).
const COPY_CHUNK: u64 = 4 << 20;
/// Memory a running copy holds: at most one staged write plus one prefetched reply. Decode/encode
/// happen only after the preceding write is durable, with the old wire/decoded buffers dropped before fetching.
const COPY_RESERVE: u64 = 2 * COPY_CHUNK;
/// Concurrent copies per PG; more wait in a queue.
const MAX_COPIES: usize = 16;
/// A copy that makes no progress for this long fails with ETIMEDOUT (an unreachable source OSD).
const COPY_TIMEOUT: Mono = 120_000_000_000;
/// Chunks without any new byte, key or part before the copy fails (a misbehaving source must not loop us forever).
const MAX_EMPTY_STEPS: u8 = 8;
/// Bytes all running copies of one OSD process may hold (one [`COPY_RESERVE`] each, see [`CopyBudget`]).
pub const COPY_MEM_BUDGET: u64 = 1 << 30;
/// A copy waiting for budget tries again after this long (another PG or core may have released some).
const BUDGET_RETRY: Mono = 20_000_000;

/// Memory the copies of one OSD process hold (copy.md 4.6). Shared by every engine of every core (the copy path is
/// cold: one atomic per copy). A copy reserves [`COPY_RESERVE`] before its first read; a copy that cannot get it
/// waits in the PG's copy queue (back-pressure, the destination stays blocked) and never holds memory it cannot
/// complete with, so the copies that run always finish.
#[derive(Debug)]
pub struct CopyBudget {
    used: AtomicU64,
    limit: u64,
}

impl CopyBudget {
    pub fn new(limit: u64) -> Arc<Self> {
        Arc::new(CopyBudget {
            used: AtomicU64::new(0),
            limit,
        })
    }

    /// The budget of this process ([`COPY_MEM_BUDGET`]).
    pub fn global() -> Arc<Self> {
        static G: std::sync::LazyLock<Arc<CopyBudget>> =
            std::sync::LazyLock::new(|| CopyBudget::new(COPY_MEM_BUDGET));
        G.clone()
    }

    /// Bytes currently reserved.
    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }

    /// Reserve `n` bytes; when nothing else is reserved any size passes (one copy always runs).
    fn take(&self, n: u64) -> bool {
        let mut cur = self.used.load(Ordering::Relaxed);
        loop {
            if cur != 0 && cur.saturating_add(n) > self.limit {
                return false;
            }
            match self.used.compare_exchange_weak(
                cur,
                cur.saturating_add(n),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(x) => cur = x,
            }
        }
    }
}

/// Bytes one copy reserved; given back when the copy ends in any way (dropped).
struct Hold {
    b: Arc<CopyBudget>,
    n: u64,
}

impl Hold {
    fn new(b: &Arc<CopyBudget>) -> Option<Hold> {
        b.take(COPY_RESERVE).then(|| Hold {
            b: b.clone(),
            n: COPY_RESERVE,
        })
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        self.b.used.fetch_sub(self.n, Ordering::Relaxed);
    }
}

/// The temp object of a staged copy (source bigger than one chunk).
struct Stage {
    temp: Hobject,
    /// Outstanding write of the last chunk (0 = none).
    tid: u64,
    /// That chunk was the last: the copy ends when its write is durable on every shard.
    last: bool,
}

/// What one copy-get answer brought (staged copies write it into the temp object, the others keep it in memory).
struct Chunk {
    /// User xattrs, only in the answer that delivers them.
    attrs: Option<BTreeMap<Vec<u8>, Vec<u8>>>,
    data: Vec<u8>,
    data_off: u64,
    omap_header: Vec<u8>,
    omap: Vec<(Vec<u8>, Vec<u8>)>,
}

/// One copy in progress.
pub(super) struct CopyState {
    req: ClientReq,
    head: Hobject,
    src_spg: SpgT,
    src_hash: u32,
    src_oid: Vec<u8>,
    src_oloc: ObjectLocator,
    src_snap: u64,
    flags: u8,
    fadvise: u32,
    truncate: Option<(u32, u64)>,
    /// Cursor of the NEXT chunk to request.
    cursor: CopyCursor,
    /// Id of the outstanding source read (0 = none).
    step: u64,
    pub(super) deadline: Mono,
    /// Source `user_version`: asserted on every chunk after it was learned (the source must not change mid-copy).
    uv: u64,
    acc: CopySrc,
    /// Source digest flags / values of the last chunk.
    src_flags: u32,
    src_data_digest: u32,
    src_omap_digest: u32,
    data_crc: u32,
    omap_crc: u32,
    /// Data bytes delivered so far (must end at the source size).
    data_got: u64,
    /// The source has an omap header or keys.
    omap_seen: bool,
    /// Less than one EC stripe retained between source replies.
    partial: Vec<u8>,
    empty: u8,
    /// Set once the source did not fit one chunk: the temp object the chunks go to.
    stage: Option<Stage>,
    /// One source answer waiting for the preceding chunk's durability. Keep wire Bytes, not a decoded
    /// extra payload copy. Errors wait for the same barrier so cleanup never overtakes the chunk write.
    pending: Option<(u64, Result<MOSDOpReply, i32>)>,
    /// A chunk write the store's size check refused while its pages load (`WriteErr::Blocked`, nothing logged): the
    /// same write, its temp object and `last`, submitted again by [`Engine::copy_poll`] after the store wake (adr 0021 S8).
    blocked: Option<(WriteReq, Hobject, bool)>,
    /// Memory reserved in the OSD-wide [`CopyBudget`].
    hold: Hold,
}

impl CopyState {
    pub(super) fn ready_pending(&self) -> bool {
        self.pending.is_some() && self.stage.as_ref().is_none_or(|s| s.tid == 0)
    }
}

/// Index of the copy op of a message: at most one per message.
fn copy_op(op: &MOSDOp) -> Result<Option<usize>, i32> {
    let mut it = op
        .ops
        .iter()
        .enumerate()
        .filter(|(_, o)| o.op == code::COPY_FROM || o.op == code::COPY_FROM2)
        .map(|(i, _)| i);
    let first = it.next();
    if it.next().is_some() {
        return Err(errno::EINVAL);
    }
    Ok(first)
}

impl Engine {
    /// Resolve local self-copy validation with the map's actual source hash, never the destination's hash.
    pub(super) fn copy_self_op<E: Env>(
        &self,
        env: &E,
        req: &ClientReq,
        head: &Hobject,
    ) -> Option<usize> {
        req.op.ops.iter().enumerate().find_map(|(i, o)| {
            if o.op != code::COPY_FROM && o.op != code::COPY_FROM2 {
                return None;
            }
            let inp = crate::exec::copy_input(o, self.limits.max_oid_len).ok()?;
            let (_, hash) = env.locate(&inp.src_oid, &inp.src_oloc)?;
            let mut src = Hobject::new(
                &inp.src_oid,
                SnapId(o.copy_from().snapid),
                hash,
                inp.src_oloc.pool,
                &inp.src_oloc.nspace,
            );
            src.set_key(&inp.src_oloc.key);
            (src == *head).then_some(i)
        })
    }

    /// The message carries a copy op whose source is not fetched yet.
    pub(super) fn needs_copy(&self, req: &ClientReq) -> bool {
        req.op
            .ops
            .iter()
            .any(|o| o.op == code::COPY_FROM || o.op == code::COPY_FROM2)
            && !self.copy_done.contains_key(&(req.conn, req.tid))
    }

    /// Start (or queue) the fetch for `req`. The destination object stays blocked until it ends.
    pub(super) fn copy_start<E: Env>(&mut self, env: &mut E, req: ClientReq) {
        let hold = if self.copies.len() < MAX_COPIES && self.copy_queue.is_empty() {
            Hold::new(&self.copy_budget)
        } else {
            None
        };
        let Some(hold) = hold else {
            self.copy_wait(env, req, false);
            return;
        };
        self.copy_begin(env, req, hold);
    }

    /// Park a copy (over the per-PG cap or out of budget): the destination stays blocked; `front` = it ran already.
    fn copy_wait<E: Env>(&mut self, env: &E, req: ClientReq, front: bool) {
        self.objs.entry(head_of(&req.op)).or_default().copying = true;
        if front {
            self.copy_queue.push_front(req);
        } else {
            self.copy_queue.push_back(req);
        }
        if self.copies.len() < MAX_COPIES {
            // waiting for budget other PGs hold: no local copy end will wake it, the timer does
            self.c.copy_waits += 1;
            self.copy_wake = env.mono() + BUDGET_RETRY;
        }
    }

    /// A copy that cannot start: plain error; a queued one also releases its destination.
    fn copy_reject<E: Env>(&mut self, env: &mut E, req: &ClientReq, err: i32) {
        self.reply_plain(env, req, err);
        let head = head_of(&req.op);
        if self.objs.get(&head).is_some_and(|e| e.copying) {
            self.copy_unblock(&head);
            self.drain_obj(env, &head, false);
        }
    }

    fn copy_begin<E: Env>(&mut self, env: &mut E, req: ClientReq, hold: Hold) {
        let head = head_of(&req.op);
        let idx = match copy_op(&req.op) {
            Ok(Some(i)) => i,
            Ok(None) => return self.copy_reject(env, &req, -errno::EINVAL),
            Err(e) => return self.copy_reject(env, &req, -e),
        };
        let o = &req.op.ops[idx];
        let cf = o.copy_from();
        let inp = match crate::exec::copy_input(o, self.limits.max_oid_len) {
            Ok(inp) => inp,
            Err(e) => return self.copy_reject(env, &req, -e),
        };
        let Some((src_spg, src_hash)) = env.locate(&inp.src_oid, &inp.src_oloc) else {
            return self.copy_reject(env, &req, -errno::ENOENT);
        };
        let mut src = Hobject::new(
            &inp.src_oid,
            SnapId(cf.snapid),
            src_hash,
            inp.src_oloc.pool,
            &inp.src_oloc.nspace,
        );
        src.set_key(&inp.src_oloc.key);
        if src == head {
            return self.copy_reject(env, &req, -errno::EINVAL);
        }
        let id = {
            self.copy_id += 1;
            self.copy_id
        };
        let st = CopyState {
            head: head.clone(),
            src_spg,
            src_hash,
            src_oid: inp.src_oid,
            src_oloc: inp.src_oloc,
            src_snap: cf.snapid,
            flags: cf.flags,
            fadvise: cf.src_fadvise_flags,
            truncate: inp.truncate,
            cursor: CopyCursor::default(),
            step: 0,
            deadline: env.mono() + COPY_TIMEOUT,
            uv: cf.src_version,
            acc: CopySrc::default(),
            src_flags: 0,
            src_data_digest: u32::MAX,
            src_omap_digest: u32::MAX,
            data_crc: u32::MAX,
            omap_crc: u32::MAX,
            data_got: 0,
            partial: Vec::new(),
            omap_seen: false,
            empty: 0,
            stage: None,
            pending: None,
            blocked: None,
            hold,
            req,
        };
        self.objs.entry(head).or_default().copying = true;
        self.copies.insert(id, st);
        self.copy_fetch(env, id);
    }

    /// Ask the source for the next chunk.
    fn copy_fetch<E: Env>(&mut self, env: &mut E, id: u64) {
        self.copy_step += 1;
        let step = (1 << 62) | self.copy_step;
        let Some(c) = self.copies.get_mut(&id) else {
            return;
        };
        c.step = step;
        let mut ops = Vec::with_capacity(2);
        if c.uv != 0 {
            ops.push(OsdOp::assert_version(c.uv));
        }
        let stripe = env.copy_stripe_width().max(1);
        let limit = COPY_CHUNK.saturating_sub(stripe - 1).max(1);
        let mut g = OsdOp::copy_get_req(&c.cursor, limit);
        g.flags = c.fadvise;
        ops.push(g);
        let mut flags = mflag::READ | mflag::KNOWN_REDIR | mflag::SUPPORTSPOOLEIO | mflag::ONDISK;
        if c.flags & copy_flag::RWORDERED != 0 {
            flags |= mflag::RWORDERED;
        }
        if c.flags & copy_flag::MAP_SNAP_CLONE != 0 {
            flags |= mflag::MAP_SNAP_CLONE;
        }
        let mut op = MOSDOp {
            pgid: c.src_spg,
            hash: c.src_hash,
            osdmap_epoch: env.epoch(),
            flags,
            oloc: c.src_oloc.clone(),
            oid: c.src_oid.clone(),
            ops,
            snapid: c.src_snap,
            ..Default::default()
        };
        op.oloc.hash = -1;
        let local = c.src_spg == env.spg();
        if local {
            // same PG: the read goes through the normal path (gate, per-object ordering behind in-flight writes)
            let req = ClientReq {
                placement_read: None,
                conn: COPY_CONN,
                caps: None,
                tid: step,
                op: Box::new(op),
                who: EntityName {
                    ty: EntityName::OSD,
                    num: env.whoami(),
                },
                addr: EntityAddr::default(),
                peer_addr: EntityAddr::default(),
                features: 0,
            };
            self.on_op(env, req);
        } else {
            self.out.push(Out::CopyRead {
                origin: self.spg,
                step,
                spg: c.src_spg,
                op: Box::new(op),
            });
        }
    }

    /// Answer of a source read that went out as [`Out::CopyRead`]: the reply, or an errno (positive) when it could
    /// not be delivered at all.
    pub fn on_copy_reply<E: Env>(&mut self, env: &mut E, step: u64, rep: Result<MOSDOpReply, i32>) {
        self.copy_step_done(env, step, rep);
        self.copy_poll(env);
    }

    /// Divert the replies of same-PG source reads to their copy; every public entry point ends here.
    pub(super) fn copy_poll<E: Env>(&mut self, env: &mut E) {
        if !self.temp_garbage.is_empty() || !self.copies.is_empty() {
            env.settle(); // copies read the store: a held-back local txn applies first
        }
        for t in std::mem::take(&mut self.temp_garbage) {
            self.copy_discard(env, t);
        }
        if self.copies.is_empty() || self.in_copy_poll {
            return;
        }
        self.in_copy_poll = true;
        let blocked: Vec<u64> = self
            .copies
            .iter()
            .filter_map(|(id, c)| c.blocked.is_some().then_some(*id))
            .collect();
        for id in blocked {
            if let Some((w, temp, last)) = self.copies.get_mut(&id).and_then(|c| c.blocked.take()) {
                self.copy_submit(env, id, w, temp, last);
            }
        }
        // A received chunk can also wait for this shard's earlier FIFO writes, before preflight/logging.
        // Retain its encoded reply (the existing two-chunk ownership bound) and retry after the store wake.
        for _ in 0..8 {
            let Some(id) = self
                .copies
                .iter()
                .find_map(|(id, c)| c.ready_pending().then_some(*id))
            else {
                break;
            };
            if !env.warm_log() {
                break;
            }
            let c = self.copies.get_mut(&id).unwrap();
            let (step, reply) = c.pending.take().unwrap();
            c.step = step;
            self.copy_step_done(env, step, reply);
        }
        loop {
            let mut got: Vec<(u64, Box<MOSDOpReply>)> = Vec::new();
            let mut i = 0;
            while i < self.out.len() {
                if matches!(&self.out[i], Out::Reply { conn, .. } if *conn == COPY_CONN) {
                    if let Out::Reply { tid, reply, .. } = self.out.remove(i) {
                        got.push((tid, reply));
                    }
                } else {
                    i += 1;
                }
            }
            if got.is_empty() {
                break;
            }
            for (tid, rep) in got {
                self.copy_step_done(env, tid, Ok(*rep));
            }
        }
        self.in_copy_poll = false;
    }

    fn copy_step_done<E: Env>(&mut self, env: &mut E, step: u64, rep: Result<MOSDOpReply, i32>) {
        let Some(id) = self
            .copies
            .iter()
            .find(|(_, c)| c.step == step)
            .map(|(id, _)| *id)
        else {
            return; // cancelled (new interval) or already failed
        };
        let c = self.copies.get_mut(&id).unwrap();
        if c.stage.as_ref().is_some_and(|s| s.tid != 0) || !env.warm_log() {
            c.step = 0; // duplicate replies are ignored while this answer waits
            c.pending = Some((step, rep));
            return;
        }
        let rep = match rep {
            Ok(r) => r,
            Err(e) => return self.copy_fail(env, id, -e.abs()),
        };
        if rep.result < 0 {
            return self.copy_fail(env, id, rep.result);
        }
        let Some(last) = rep.ops.last() else {
            return self.copy_fail(env, id, -errno::EIO);
        };
        if last.rval < 0 {
            return self.copy_fail(env, id, last.rval);
        }
        let Ok(d) = denc::from_slice::<CopyData>(&last.outdata) else {
            return self.copy_fail(env, id, -errno::EIO);
        };
        let user_version = rep.user_version;
        drop(rep); // decoded CopyData owns its bytes; do not retain another chunk through staging
        let Some(c) = self.copies.get_mut(&id) else {
            return;
        };
        c.step = 0;
        if c.uv == 0 {
            c.uv = user_version;
        }
        let (chunk, complete) = match Self::copy_fold(c, d, self.limits.max_object_size) {
            Ok(x) => x,
            Err(e) => return self.copy_fail(env, id, -e),
        };
        if c.stage.is_none() && complete {
            // the whole source came in one chunk: keep it, the message runs with it
            c.acc.attrs = chunk.attrs.unwrap_or_default();
            c.acc.data = chunk.data;
            c.acc.omap_header = chunk.omap_header;
            c.acc.omap = chunk.omap;
            return self.copy_finish(env, id);
        }
        self.copy_stage(env, id, chunk, complete);
    }

    /// Check one answer and take its parts; `Ok((chunk, true))` = the source is complete. Errors are positive errno.
    fn copy_fold(c: &mut CopyState, d: CopyData, max_object: u64) -> Result<(Chunk, bool), i32> {
        let old = c.cursor.clone();
        let new = d.cursor.clone();
        // the cursor never goes back and a part never un-completes
        if new.data_offset < old.data_offset
            || (old.attr_complete && !new.attr_complete)
            || (old.data_complete && !new.data_complete)
            || (old.omap_complete && !new.omap_complete)
        {
            return Err(errno::EIO);
        }
        c.acc.size = d.size;
        c.acc.mtime = d.mtime;
        c.acc.truncate_seq = d.truncate_seq;
        c.acc.truncate_size = d.truncate_size;
        c.src_flags = d.flags;
        c.src_data_digest = d.data_digest;
        c.src_omap_digest = d.omap_digest;
        if c.acc.size == u64::MAX {
            return Err(errno::EIO);
        }
        // refuse what the destination could never hold before pulling more of it
        if c.acc.size > max_object {
            return Err(errno::EFBIG);
        }
        let mut ch = Chunk {
            attrs: None,
            data: Vec::new(),
            data_off: old.data_offset,
            omap_header: Vec::new(),
            omap: Vec::new(),
        };
        if !old.attr_complete {
            ch.attrs = Some(d.attrs);
        }
        if !old.data_complete {
            if d.data.len() as u64 != new.data_offset - old.data_offset {
                return Err(errno::EIO);
            }
            c.data_crc = crc::crc32c(c.data_crc, &d.data);
            c.data_got += d.data.len() as u64;
            ch.data = d.data;
        }
        if !old.omap_complete {
            if !d.omap_header.is_empty() {
                c.omap_crc = crc::crc32c(c.omap_crc, &d.omap_header);
                c.omap_seen = true;
                ch.omap_header = d.omap_header;
            }
            if !d.omap_data.is_empty() {
                // the digest covers the key/value pairs without the leading count
                c.omap_crc = crc::crc32c(c.omap_crc, &d.omap_data[4.min(d.omap_data.len())..]);
                ch.omap = opwire::parse_omap_section(&d.omap_data).map_err(|_| errno::EIO)?;
                c.omap_seen |= !ch.omap.is_empty();
            }
        }
        if c.data_got > c.acc.size {
            return Err(errno::EIO);
        }
        c.cursor = new;
        if c.cursor.is_complete() {
            if c.data_got != c.acc.size {
                return Err(errno::EIO);
            }
            if c.src_flags & opwire::COPY_FLAG_DATA_DIGEST != 0 && c.data_crc != c.src_data_digest {
                return Err(errno::EIO);
            }
            if c.src_flags & opwire::COPY_FLAG_OMAP_DIGEST != 0 && c.omap_crc != c.src_omap_digest {
                return Err(errno::EIO);
            }
            return Ok((ch, true));
        }
        if c.cursor == old {
            c.empty += 1;
            if c.empty >= MAX_EMPTY_STEPS {
                return Err(errno::EIO);
            }
        } else {
            c.empty = 0;
        }
        Ok((ch, false))
    }

    /// Write one chunk into the copy's temp object (created with the first one): an unlogged replicated or EC write that every
    /// acting shard applies. Fetch the next chunk now, but stage it only after this write is durable.
    fn copy_stage<E: Env>(&mut self, env: &mut E, id: u64, mut ch: Chunk, last: bool) {
        let Some(c) = self.copies.get_mut(&id) else {
            return;
        };
        let stripe = env.copy_stripe_width().max(1);
        if stripe > COPY_CHUNK {
            return self.copy_fail(env, id, -errno::EOPNOTSUPP);
        }
        ch.data_off -= c.partial.len() as u64;
        if !c.partial.is_empty() {
            c.partial.extend_from_slice(&ch.data);
            ch.data = std::mem::take(&mut c.partial);
        }
        if !c.cursor.data_complete {
            let keep = ch.data.len() % stripe as usize;
            c.partial = ch.data.split_off(ch.data.len() - keep);
        }
        let first = c.stage.is_none();
        let temp = match &c.stage {
            Some(s) => s.temp.clone(),
            // classic temp shape (head, empty key/nspace, temp pool, the destination's hash = same PG)
            None => Hobject {
                oid: format!("copy-tmp-{}-{}", env.epoch(), id).into_bytes(),
                pool: Hobject::temp_pool(c.head.pool),
                hash: c.head.hash,
                snap: SnapId::NOSNAP,
                ..Hobject::MIN()
            },
        };
        let bytes = ch.data.len()
            + ch.omap_header.len()
            + ch.omap
                .iter()
                .map(|(k, v)| k.len() + v.len())
                .sum::<usize>();
        // one tree entry per omap key (admission cost, adr 0021 am. 45)
        if !env.write_room(bytes, ch.omap.len() + 1) {
            return self.copy_fail(env, id, -errno::ENOSPC);
        }
        let mut txn: Vec<(Hobject, MOp)> = Vec::new();
        if first {
            txn.push((temp.clone(), MOp::Remove));
            txn.push((temp.clone(), MOp::Create));
        }
        for (k, v) in ch.attrs.into_iter().flatten() {
            txn.push((
                temp.clone(),
                MOp::SetAttr {
                    name: crate::exec::kn(&k),
                    value: v,
                },
            ));
        }
        if !ch.data.is_empty() {
            txn.push((
                temp.clone(),
                MOp::Write {
                    off: ch.data_off,
                    src: Src::Own(ch.data),
                },
            ));
        }
        if !ch.omap_header.is_empty() {
            txn.push((temp.clone(), MOp::OmapSetHeader(ch.omap_header)));
        }
        if !ch.omap.is_empty() {
            txn.push((
                temp.clone(),
                MOp::OmapSetKeys(opwire::KvRun::from_pairs(
                    ch.omap.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
                )),
            ));
        }
        if env.ec_pool() {
            // EC plans use the logical size of the committed temp for subsequent RMWs.
            let mut oi = ObjectInfo::new(temp.clone());
            oi.size = c.data_got - c.partial.len() as u64;
            if c.omap_seen {
                oi.flags |= replwire::oi::flag::OMAP;
            }
            let Ok(value) = denc::to_vec(&oi) else {
                return self.copy_fail(env, id, -errno::EIO);
            };
            txn.push((
                temp.clone(),
                MOp::SetAttr {
                    name: b"_".to_vec(),
                    value,
                },
            ));
        }
        let Ok((blob, refs, _)) = crate::exec::encode_txn(env.spg(), &txn, &[], false) else {
            return self.copy_fail(env, id, -errno::EIO);
        };
        let w = WriteReq {
            txn_data: blob,
            txn_refs: refs,
            new_temp: first.then(|| temp.clone()),
            ..Default::default()
        };
        drop(txn); // release decoded chunk before issuing a possibly synchronous source read
        self.copy_submit(env, id, w, temp, last);
    }

    /// Submit the chunk write `w` of copy `id` into `temp`; on success fetch the next chunk unless `last`.
    fn copy_submit<E: Env>(
        &mut self,
        env: &mut E,
        id: u64,
        w: WriteReq,
        temp: Hobject,
        last: bool,
    ) {
        let again = w.clone(); // Bytes handles: no payload copy
        match env.submit_write(w) {
            Ok(tid) => {
                self.stage_tids.insert(tid, id);
                if let Some(c) = self.copies.get_mut(&id) {
                    c.stage = Some(Stage { temp, tid, last });
                }
                if !last {
                    self.copy_fetch(env, id);
                }
            }
            Err(WriteErr::Blocked) => {
                if let Some(c) = self.copies.get_mut(&id) {
                    c.blocked = Some((again, temp, last));
                }
            }
            Err(WriteErr::TooBig(e)) => self.copy_fail(env, id, -e),
            Err(_) => self.copy_fail(env, id, -errno::EAGAIN),
        }
    }

    /// `Action::WriteDone`: stage the prefetched answer (if received), await its read, or finish.
    pub(super) fn copy_stage_done<E: Env>(&mut self, env: &mut E, tid: u64, result: i32) -> bool {
        let Some(id) = self.stage_tids.remove(&tid) else {
            return false;
        };
        let Some(c) = self.copies.get_mut(&id) else {
            return true;
        };
        let Some(s) = c.stage.as_mut() else {
            return true;
        };
        s.tid = 0;
        if result != 0 {
            self.copy_fail(env, id, result);
        } else if s.last {
            self.copy_finish(env, id);
        } else {
            c.deadline = env.mono() + COPY_TIMEOUT;
            if let Some((step, rep)) = c.pending.take() {
                c.step = step;
                self.copy_step_done(env, step, rep);
            }
        }
        true
    }

    /// Drop a temp object nobody will rename: an unlogged write that removes it everywhere (a PG that is not
    /// active any more clears it at its next interval change).
    pub(super) fn copy_discard<E: Env>(&mut self, env: &mut E, temp: Hobject) {
        let txn = [(temp.clone(), MOp::Remove)];
        let mut failed = None;
        match crate::exec::encode_txn(env.spg(), &txn, &[], false) {
            Ok((blob, refs, _)) => {
                let w = WriteReq {
                    txn_data: blob,
                    txn_refs: refs,
                    discard_temp: Some(temp.clone()),
                    ..Default::default()
                };
                if let Err(e) = env.submit_write(w) {
                    failed = Some(format!("{e:?}"));
                }
            }
            Err(e) => failed = Some(format!("{e:?}")),
        }
        if let Some(e) = failed {
            // best effort (the next interval change clears it), but never silent: the temp leaks until then
            self.c.copy_discard_errors += 1;
            eprintln!(
                "pg {:?}: copy temp object {temp:?} not removed: {e}",
                self.spg
            );
        }
    }

    /// The source is complete: run the original message with it.
    fn copy_finish<E: Env>(&mut self, env: &mut E, id: u64) {
        let Some(mut c) = self.copies.remove(&id) else {
            return;
        };
        if let Some((s, z)) = c.truncate {
            c.acc.truncate_seq = u64::from(s);
            c.acc.truncate_size = z;
        }
        c.acc.user_version = c.uv;
        c.acc.staged = c.stage.take().map(|s| s.temp);
        c.acc.has_omap = c.omap_seen;
        let head = c.head.clone();
        let req = c.req;
        self.copy_done.insert((req.conn, req.tid), Arc::new(c.acc));
        self.copy_unblock(&head);
        self.execute_req(env, req, head.clone(), None);
        drop(c.hold); // before the next copy asks for room
        self.drain_obj(env, &head, false);
        self.copy_next(env);
    }

    /// The copy failed: plain error reply (nothing was changed), the destination is released.
    pub(super) fn copy_fail<E: Env>(&mut self, env: &mut E, id: u64, result: i32) {
        let Some(mut c) = self.copies.remove(&id) else {
            return;
        };
        self.c.errors += 1;
        self.reply_plain(env, &c.req, result);
        if let Some(s) = c.stage.take() {
            self.stage_tids.remove(&s.tid);
            self.copy_discard(env, s.temp);
        }
        let head = c.head.clone();
        drop(c);
        self.copy_unblock(&head);
        self.drain_obj(env, &head, false);
        self.copy_next(env);
    }

    /// A fetched source that is not needed any more; the temp object of a staged one that no write consumed is
    /// garbage (removed at the next entry point).
    pub(super) fn copy_done_drop(&mut self, key: &(u64, u64)) {
        if let Some(c) = self.copy_done.remove(key)
            && let Some(t) = &c.staged
        {
            self.temp_garbage.push(t.clone());
        }
    }

    fn copy_unblock(&mut self, head: &Hobject) {
        let others = self.copies.values().any(|c| c.head == *head)
            || self.copy_queue.iter().any(|r| head_of(&r.op) == *head);
        if let Some(e) = self.objs.get_mut(head) {
            e.copying = others;
        }
    }

    /// A slot freed: start queued copies.
    fn copy_next<E: Env>(&mut self, env: &mut E) {
        while self.copies.len() < MAX_COPIES && !self.copy_queue.is_empty() {
            let Some(hold) = Hold::new(&self.copy_budget) else {
                self.copy_wake = env.mono() + BUDGET_RETRY;
                break;
            };
            let Some(r) = self.copy_queue.pop_front() else {
                break;
            };
            self.copy_begin(env, r, hold);
        }
    }

    /// `tick`: copies waiting for budget try again.
    pub(super) fn copy_retry_wait<E: Env>(&mut self, env: &mut E, now: Mono) {
        if self.copy_wake != 0 && now >= self.copy_wake {
            self.copy_wake = 0;
            self.copy_next(env);
        }
    }

    /// Fail copies that made no progress for `COPY_TIMEOUT` (`tick`).
    pub(super) fn copy_expire<E: Env>(&mut self, env: &mut E, now: Mono) {
        let dead: Vec<u64> = self
            .copies
            .iter()
            .filter(|(_, c)| now >= c.deadline)
            .map(|(id, _)| *id)
            .collect();
        for id in dead {
            eprintln!(
                "WARNING TIMEOUT copy no progress exceeded {}s (pg {:?}, copy {id})",
                COPY_TIMEOUT / 1_000_000_000,
                env.spg()
            );
            self.copy_fail(env, id, -errno::ETIMEDOUT);
        }
    }

    /// Requests held by copies (for reset / teardown), in no particular order.
    pub(super) fn copy_reqs(&mut self) -> Vec<ClientReq> {
        let mut v: Vec<ClientReq> = std::mem::take(&mut self.copies)
            .into_values()
            .map(|c| c.req)
            .collect();
        v.extend(self.copy_queue.drain(..));
        self.copy_done.clear();
        self.stage_tids.clear();
        self.copy_wake = 0;
        v
    }

    pub(super) fn copy_held(&self) -> Vec<&ClientReq> {
        self.copies
            .values()
            .map(|c| &c.req)
            .chain(self.copy_queue.iter())
            .collect()
    }
}
