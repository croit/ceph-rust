// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Straight-line executor of the plain overwrite: one `write` op onto an existing, whole object without snapshots (the
//! RBD / CephFS data-path write). It yields the [`Outcome`] the general executor ([`crate::exec::Exec`]) yields for the
//! same message, without building the general machinery for it (message context, working copies of object info and
//! snapset, op list, mutation list). Anything it does not know exactly falls through to the general executor, so the
//! two never diverge for other op kinds. `tests/fast_overwrite.rs` runs every shape through both and compares.

use crate::engine::{ClientReq, Env, admission_cost};
use crate::exec::{enc, encode_overwrite};
use crate::types::{Disposition, Limits, ObjState, Outcome, WritePlan};
use denc::types::{Hobject, OsdReqId, UTime};
use opwire::{consts::op as code, errno, flag as mflag};
use peering::WriteEntry;
use pgwire::LogOp;
use replwire::ObjectInfo;
use replwire::oi::flag as oif;

/// Message flags whose handling the plain overwrite does not do: RETURNVEC (per-op results in the log), ORDERSNAP
/// (snapc check against the object's snapset).
const GENERAL_FLAGS: u32 = mflag::RETURNVEC | mflag::ORDERSNAP;

/// The outcome of `req` when it is a plain overwrite of the whole-object state `st`, else `None` (nothing touched).
/// On `Some` the state moved into `Outcome::new_state` (`st` is left default) and the request ops are reset like the
/// general run does.
pub(crate) fn overwrite<E: Env>(
    env: &E,
    req: &mut ClientReq,
    head: &Hobject,
    reqid: &OsdReqId,
    st: &mut ObjState,
    limits: &Limits,
) -> Option<Outcome> {
    let op = &req.op;
    let [w] = op.ops.as_slice() else {
        return None;
    };
    if w.op != code::WRITE
        || op.flags & GENERAL_FLAGS != 0
        || !op.snaps.is_empty()
        || op.source_pull_error.is_some()
    {
        return None;
    }
    // An append-only EC pool accepts only the legacy write form (client-ops 16.4): the fast path does not know it, so
    // those messages go through the general executor's gate.
    if env.ec_pool() && env.ec_caps().requires_aligned_append {
        return None;
    }
    let e = w.extent();
    // payload present, whole, inside the object limit; no truncate bookkeeping on either side
    if e.length == 0
        || w.indata.len() as u64 != e.length
        || e.truncate_seq != 0
        || crate::exec::efbig(limits.max_object_size, e.offset, e.length)
    {
        return None;
    }
    // existing object that keeps its snapset: no clone, no seq bump, a stored snapset that stays as it is
    let oi = st.oi.as_ref()?;
    if oi.is_whiteout()
        || oi.truncate_seq != 0
        || !st.ss_stored
        || !st.ss.clones.is_empty()
        || op.snap_seq > st.ss.seq
    {
        return None;
    }
    // the message's own limits: pool state, pool-snap mode, store room (the general path answers these)
    if env.pool_full().0 || (op.flags & mflag::ENFORCE_SNAPC == 0 && env.pool_snapc().is_some()) {
        return None;
    }
    let (bytes, entries) = admission_cost(&op.ops);
    if !env.write_room(bytes, entries) {
        return None;
    }
    let (off, len, mtime) = (e.offset, e.length, op.mtime);

    let v = env.next_version();
    let pre_version = oi.version;
    let mut oi = st.oi.take()?;
    if oi.soid != *head {
        oi.soid = head.clone();
    }
    oi.prior_version = pre_version;
    oi.version = v;
    oi.last_reqid = *reqid;
    if mtime != UTime::default() {
        oi.mtime = mtime;
        oi.local_mtime = env.wall();
    }
    oi.flags |= oif::DIRTY;
    oi.flags &= !oif::DATA_DIGEST;
    oi.data_digest = ObjectInfo::NO_DIGEST;
    oi.size = oi.size.max(off + len);
    // a stored user_version may already sit at u64::MAX: it must never wrap to 0
    let uv = env
        .last_user_version()
        .max(oi.user_version)
        .saturating_add(1);
    let uv = uv.max(v.version);
    oi.user_version = uv;

    let oi_enc = enc(&oi);
    let w = &req.op.ops[0];
    let Ok((txn, refs)) = encode_overwrite(env.spg(), head, off, &w.indata, &oi_enc) else {
        // the general executor answers an unencodable plan the same way
        return Some(Outcome {
            result: -errno::EINVAL,
            disp: Disposition::Reply,
            plan: WritePlan::default(),
            effects: Vec::new(),
            new_state: ObjState::default(),
            user_version: 0,
            replay_version: Default::default(),
            keep_outdata: true,
            damaged: None,
            io: Default::default(),
        });
    };
    let crcs = if refs.iter().any(|r| w.indata_crc.of(r).is_some()) {
        vec![w.indata_crc.clone()]
    } else {
        Vec::new()
    };
    let entry = WriteEntry {
        op: LogOp::MODIFY,
        soid: head.clone(),
        user_version: uv,
        mtime: oi.mtime,
        snaps: Vec::new(),
        return_code: 0,
        op_returns: Vec::new(),
        prior: Some(pre_version),
    };
    let ss = std::mem::take(&mut st.ss);
    req.op.ops.iter_mut().for_each(opwire::OsdOp::reset_result);
    Some(Outcome {
        result: 0,
        disp: Disposition::Write,
        plan: WritePlan {
            entries: vec![entry],
            txn,
            txn_refs: refs,
            txn_ref_crcs: crcs,
            ..Default::default()
        },
        effects: Vec::new(),
        new_state: ObjState {
            oi: Some(oi),
            ss,
            ss_stored: true,
        },
        user_version: uv,
        replay_version: v,
        keep_outdata: false,
        damaged: None,
        // one WRITE sub-op (spec pg-io-stats.md 1), as the general executor counts it
        io: {
            let mut io = pgwire::IoCount::default();
            io.write(len);
            io
        },
    })
}
