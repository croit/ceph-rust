// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Generation-specific removal must never remove the live snapshot clones.
mod common;
use common::*;
use denc::types::{CollT, Ghobject, SnapId};
use store::obj::OTxn;

#[test]
fn removeall_preserves_generation_and_live_snapmapper() {
    let mut r = rig(6);
    let s = spg(1, 0);
    make_pg(&r, s, 0);
    let cid = CollT::Pg(s);
    let live = [SnapId::NOSNAP, SnapId(4)].map(|snap| gh(s, &hobj(s, "snapped", snap)));
    let generated = live.clone().map(|mut g| {
        g.generation = 42;
        g
    });
    let attrs = live
        .iter()
        .map(|src| r.ad.with_store(|st| st.getattrs(&cid, src)).unwrap())
        .collect::<Vec<_>>();
    let mut t = OTxn::new();
    t.sys = true;
    for (attrs, dst) in attrs.iter().zip(&generated) {
        t.touch(cid, dst);
        t.write(cid, dst, 0, b"rollback");
        for (name, value) in attrs {
            t.setattr(cid, dst, name, value);
        }
    }
    r.ad.with_store(|st| st.commit(&t)).unwrap();
    let mapper = storeadapt::snapmap::mapper_obj(s);
    let before = r.ad.with_store(|st| st.omap_all(&cid, &mapper)).unwrap();
    let listing = run(&mut r, &["--op", "list", "--pgid", "1.0"], b"");
    assert_eq!(listing.code, 0, "{}", listing.err);
    let selected = listing
        .text()
        .lines()
        .find(|line| {
            let entry: serde_json::Value = serde_json::from_str(line).unwrap();
            entry[1]["generation"] == 42 && entry[1]["snapid"] == -2
        })
        .unwrap()
        .to_owned();
    for dry in [true, false] {
        let mut args = vec![selected.as_str(), "removeall"];
        if dry {
            args.push("--dry-run");
        }
        let out = run(&mut r, &args, b"");
        assert_eq!(out.code, 0, "{}", out.err);
        for g in &live {
            assert!(r.ad.with_store(|st| st.stat(&cid, g)).unwrap().is_some());
        }
        for g in &generated {
            assert_eq!(
                r.ad.with_store(|st| st.stat(&cid, g)).unwrap().is_some(),
                dry
            );
        }
        assert_eq!(
            r.ad.with_store(|st| st.omap_all(&cid, &mapper)).unwrap(),
            before
        );
    }
    let r = remount(r);
    for g in &live {
        assert!(r.ad.with_store(|st| st.stat(&cid, g)).unwrap().is_some());
    }
    for g in &generated {
        assert_eq!(g.generation, 42);
        assert_ne!(g.generation, Ghobject::NO_GEN);
        assert!(r.ad.with_store(|st| st.stat(&cid, g)).unwrap().is_none());
    }
    assert_eq!(
        r.ad.with_store(|st| st.omap_all(&cid, &mapper)).unwrap(),
        before
    );
}
