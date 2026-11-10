// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
//! `omap_clear` on an object without FLAG_OMAP is a no-op write (client-ops 16.9): log-only ERROR entry with return
//! code 0, object_info untouched (no version, DIRTY or user_version bump); a resend is answered from that entry.
mod common;
use common::*;
use opwire::OsdOp;

fn go(pg: &mut TPg, eng: &mut opexec::Engine, tid: u64, ops: Vec<OsdOp>) -> opwire::MOSDOpReply {
    let mut outs = run(pg, eng, 1, tid, client(7), mkop(b"o", ops));
    reply_of(&mut outs, 1, tid).expect("reply")
}

fn oi(pg: &TPg) -> replwire::ObjectInfo {
    let objs = pg.store.objects(pg.spg);
    let o = objs.values().next().expect("object");
    denc::from_slice(o.xattrs.get(b"_".as_slice()).expect("oi")).unwrap()
}

#[test]
fn omap_clear_without_omap_is_a_noop_write() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let r = go(&mut pg, &mut eng, 1, vec![OsdOp::write(0, b"abc".to_vec())]);
    assert_eq!(r.result, 0);
    let before = oi(&pg);
    let uv = r.user_version;
    let entries = pg.entries.len();
    let r = go(&mut pg, &mut eng, 2, vec![OsdOp::omap_clear()]);
    assert_eq!(r.result, 0);
    assert_eq!(r.user_version, uv, "user_version unchanged");
    let after = oi(&pg);
    assert_eq!(after.version, before.version, "no new oi version");
    assert_eq!(after.prior_version, before.prior_version);
    assert_eq!(after.user_version, before.user_version);
    assert_eq!(after.last_reqid, before.last_reqid);
    assert_eq!(
        after.flags & replwire::oi::flag::DIRTY,
        before.flags & replwire::oi::flag::DIRTY
    );
    // the write was logged as an ERROR entry with return code 0 (dup detection), nothing else
    assert_eq!(pg.entries.len(), entries + 1);
    let e = pg.entries.last().unwrap();
    assert_eq!(e.op, pgwire::LogOp::ERROR);
    assert_eq!(e.return_code, 0);
    // a resend is answered from the entry: same result, no second entry
    let r = go(&mut pg, &mut eng, 2, vec![OsdOp::omap_clear()]);
    assert_eq!(r.result, 0);
    assert_eq!(pg.entries.len(), entries + 1);
}

#[test]
fn omap_clear_with_omap_clears_and_bumps() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let mut set = OsdOp::new(opwire::op::OMAP_SET_VALS);
    set.indata = denc::to_vec(&std::collections::BTreeMap::from([(
        b"k".to_vec(),
        b"v".to_vec(),
    )]))
    .unwrap()
    .into();
    assert_eq!(go(&mut pg, &mut eng, 1, vec![set]).result, 0);
    assert!(oi(&pg).is_omap());
    let r = go(&mut pg, &mut eng, 2, vec![OsdOp::omap_clear()]);
    assert_eq!(r.result, 0);
    let after = oi(&pg);
    assert!(!after.is_omap());
    let objs = pg.store.objects(pg.spg);
    let o = objs.values().next().unwrap();
    assert!(o.omap.is_empty() && o.omap_header.is_empty());
    assert_eq!(pg.entries.last().unwrap().op, pgwire::LogOp::MODIFY);
    assert!(r.user_version > 0);
}
