// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Local read problems are never folded into "absent" (backfill removals, recovery pushes derive decisions from
//! these answers): damaged object_info is `corrupt`, a missing object is `NoObject`.
mod common;
use common::*;
use denc::types::*;
use peering::store::{PgStoreOps, StoreReadError};
use store::obj::OTxn;

fn h(name: &str) -> Hobject {
    Hobject::new(name.as_bytes(), SnapId::NOSNAP, 5, 1, b"")
}

fn put(ad: &Ad, s: SpgT, name: &str, oi: &[u8]) {
    let o = Ghobject::new(h(name), Ghobject::NO_GEN, s.shard);
    let mut t = OTxn::new();
    t.touch(CollT::Pg(s), &o);
    t.setattr(CollT::Pg(s), &o, b"_", oi);
    ad.with_store(|st| st.commit(&t)).unwrap();
}

#[test]
fn damaged_object_info_is_reported_not_skipped() {
    let (_d, ad, _) = new_adapter(64, 1, 1);
    let s = spg(1, 0);
    ad.submit_create(s);
    for n in ["a", "b", "c"] {
        put(&ad, s, n, &oi_bytes(&h(n), Eversion::new(1, 5), 0));
    }
    put(&ad, s, "bad", &[1, 2, 3]);
    let l = ad.list_objects(s, &Hobject::MIN(), 0, 100).unwrap();
    assert_eq!(l.objs.len(), 3);
    assert_eq!(
        l.corrupt,
        vec![h("bad")],
        "damaged object listed as corrupt"
    );
    assert_eq!(l.names().len(), 4);
    assert_eq!(
        ad.recovery_info_checked(s, &h("bad")).unwrap_err(),
        StoreReadError::Corrupt
    );
    assert_eq!(
        ad.recovery_info_checked(s, &h("nope")).unwrap_err(),
        StoreReadError::NoObject
    );
    assert!(ad.recovery_info_checked(s, &h("a")).is_ok());
    assert_eq!(
        ad.object_version(s, &h("bad")),
        Err(StoreReadError::Corrupt)
    );
    assert_eq!(
        ad.object_version(s, &h("nope")),
        Err(StoreReadError::NoObject)
    );
    // max counts corrupt entries too, `next` continues after them
    let l = ad.list_objects(s, &Hobject::MIN(), 0, 2).unwrap();
    assert_eq!(l.objs.len() + l.corrupt.len(), 2);
    assert!(!l.next.max);
    assert!(
        ad.notes.borrow().iter().any(|n| n.contains("undecodable")),
        "operator note raised"
    );
}

#[test]
fn store_key_limits_match_what_the_executor_is_told() {
    let (_d, ad, _) = new_adapter(64, 1, 1);
    let s = spg(1, 0);
    ad.submit_create(s);
    let max = ad.with_store(|st| st.max_item_key());
    assert!(max > 100 && max < 10_000, "{max}");
    let o = Ghobject::new(h("k"), Ghobject::NO_GEN, s.shard);
    let ok = vec![b'x'; max];
    let mut t = OTxn::new();
    t.touch(CollT::Pg(s), &o);
    t.omap_set(CollT::Pg(s), &o, &ok, b"v");
    ad.with_store(|st| st.commit(&t))
        .expect("key of exactly the advertised limit");
    let bad = vec![b'x'; max + 1];
    let mut t = OTxn::new();
    t.omap_set(CollT::Pg(s), &o, &bad, b"v");
    assert_eq!(
        ad.with_store(|st| st.commit(&t)),
        Err(store::obj::ObjError::NameTooLong)
    );
    // object names: the advertised predicate agrees with the store
    let fits = |n: usize| {
        let g = Ghobject::new(h(&"n".repeat(n)), Ghobject::NO_GEN, s.shard);
        let f = ad.with_store(|st| st.name_fits(&g));
        let mut t = OTxn::new();
        t.touch(CollT::Pg(s), &g);
        let r = ad.with_store(|st| st.commit(&t));
        assert_eq!(f, r.is_ok(), "name len {n}: predicate {f}, commit {r:?}");
        f
    };
    assert!(fits(10));
    assert!(!fits(5000));
    let edge = (10..5000).rev().find(|n| fits(*n)).unwrap();
    assert!(!fits(edge + 1));
    // floor of the unchecked size gate is derived from the store, never zero for a normal rig
    assert!(ad.with_store(|st| st.check_wire_floor()) > 0);
}
