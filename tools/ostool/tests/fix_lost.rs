// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! A partial fix-lost scan must report objects whose metadata it cannot interpret.
mod common;
use common::*;
use denc::types::{CollT, SnapId};
use store::obj::{OTxn, TOp};

#[test]
fn fix_lost_reports_bad_or_absent_object_info_and_continues() {
    let mut r = rig(6);
    let s = spg(1, 0);
    make_pg(&r, s, 0);
    let cid = CollT::Pg(s);
    let bad = gh(s, &hobj(s, "big", SnapId::NOSNAP));
    let absent = gh(s, &hobj(s, "small", SnapId::NOSNAP));
    let lost = gh(s, &hobj(s, "omapobj", SnapId::NOSNAP));
    let raw =
        r.ad.with_store(|st| st.getattr(&cid, &lost, b"_"))
            .unwrap()
            .unwrap();
    let mut oi: replwire::ObjectInfo = denc::from_slice(&raw).unwrap();
    oi.flags |= replwire::oi::flag::LOST;
    let raw = denc::to_vec(&oi).unwrap();
    let mut t = OTxn::new();
    t.sys = true;
    t.setattr(cid, &bad, b"_", b"malformed");
    t.push(TOp::RmAttr {
        cid,
        oid: absent.clone(),
        name: b"_".to_vec().into(),
    });
    t.setattr(cid, &lost, b"_", &raw);
    r.ad.with_store(|st| st.commit(&t)).unwrap();
    for dry in [true, false] {
        let mut args = vec!["--op", "fix-lost", "--pgid", "1.0"];
        if dry {
            args.push("--dry-run");
        }
        let out = run(&mut r, &args, b"");
        assert_eq!(out.code, 0, "{}", out.err);
        assert!(
            out.err.contains("big") && out.err.contains("Error decoding attr"),
            "{}",
            out.err
        );
        assert!(
            out.err.contains("small") && out.err.contains("No data available"),
            "{}",
            out.err
        );
        let actual =
            r.ad.with_store(|st| st.getattr(&cid, &lost, b"_"))
                .unwrap()
                .unwrap();
        let actual: replwire::ObjectInfo = denc::from_slice(&actual).unwrap();
        assert_eq!(actual.flags & replwire::oi::flag::LOST != 0, dry);
        assert_eq!(
            r.ad.with_store(|st| st.getattr(&cid, &bad, b"_"))
                .unwrap()
                .unwrap(),
            b"malformed"
        );
        assert!(
            r.ad.with_store(|st| st.getattr(&cid, &absent, b"_"))
                .unwrap()
                .is_none()
        );
    }
}
