// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! cls_version / cls_refcount scenarios (spec/cls_version.md, spec/cls_refcount.md) on MemCtx.
mod common;
use cls::errno::*;
use cls::mem::MemStore;
use cls::refcount as rc;
use cls::version as ver;
use common::*;

const O: &str = "obj";

fn objv(v: u64, t: &str) -> ver::ObjVersion {
    ver::ObjVersion {
        ver: v,
        tag: t.into(),
    }
}
fn cond(v: u64, t: &str, c: u32) -> ver::VersionCond {
    ver::VersionCond {
        ver: objv(v, t),
        cond: c,
    }
}
fn read_ver(s: &mut MemStore) -> ver::ObjVersion {
    let r: ver::ReadRet = d(&ok(s, O, "version", "read", &[]));
    r.objv
}
fn inc(conds: Vec<ver::VersionCond>) -> Vec<u8> {
    e(&ver::IncOp {
        objv: Default::default(),
        conds,
    })
}

#[test]
fn version_registry() {
    use cls::registry::*;
    assert_eq!(methods("version").len(), 5);
    assert_eq!(lookup("version", "set").unwrap().flags, RW);
    assert_eq!(lookup("version", "inc").unwrap().flags, RW);
    assert_eq!(lookup("version", "inc_conds").unwrap().flags, RW);
    assert_eq!(lookup("version", "read").unwrap().flags, RD);
    assert_eq!(lookup("version", "check_conds").unwrap().flags, RD);
    assert_eq!(methods("refcount").len(), 4);
    assert_eq!(lookup("refcount", "read").unwrap().flags, RD);
    assert_eq!(lookup("refcount", "get").unwrap().flags, RW);
}

#[test]
fn version_fresh_inc_goes_to_two_with_random_tag() {
    let mut s = MemStore::new();
    s.objects.insert(O.into(), Default::default());
    ok(&mut s, O, "version", "inc", &inc(vec![]));
    let v = read_ver(&mut s);
    assert_eq!(v.ver, 2, "fresh object: init to 1, then incremented");
    assert_eq!(v.tag.len(), 24);
    assert!(
        v.tag
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
    );
    ok(&mut s, O, "version", "inc_conds", &inc(vec![]));
    let v2 = read_ver(&mut s);
    assert_eq!((v2.ver, &v2.tag), (3, &v.tag), "tag stays");
}

#[test]
fn version_set_read_exact_bytes() {
    let mut s = MemStore::new();
    ok(
        &mut s,
        O,
        "version",
        "set",
        &e(&ver::SetOp { objv: objv(7, "t") }),
    );
    // xattr = ENCODE_START(1,1){u64 ver; string tag}
    let want = cat(&[
        &[1, 1, 13, 0, 0, 0],
        &7u64.to_le_bytes(),
        &[1, 0, 0, 0, b't'],
    ]);
    assert_eq!(s.obj(O).unwrap().xattrs[ver::ATTR.as_bytes()], want);
    assert_eq!(read_ver(&mut s), objv(7, "t"));
    // read on object without attr: zero version, no create of the attribute
    let mut s2 = MemStore::new();
    s2.objects.insert(O.into(), Default::default());
    assert_eq!(read_ver(&mut s2), objv(0, ""));
    assert!(s2.obj(O).unwrap().xattrs.is_empty());
}

#[test]
fn version_conds() {
    let mut s = MemStore::new();
    ok(
        &mut s,
        O,
        "version",
        "set",
        &e(&ver::SetOp {
            objv: objv(5, "tg"),
        }),
    );
    let chk = |s: &mut MemStore, c: Vec<ver::VersionCond>, want: i32| {
        err(s, O, "version", "check_conds", &inc(c), want);
    };
    chk(&mut s, vec![], 0);
    chk(&mut s, vec![cond(5, "tg", ver::COND_EQ)], 0);
    chk(&mut s, vec![cond(5, "x", ver::COND_EQ)], ECANCELED);
    chk(&mut s, vec![cond(4, "x", ver::COND_GT)], 0);
    chk(&mut s, vec![cond(5, "x", ver::COND_GT)], ECANCELED);
    chk(&mut s, vec![cond(5, "x", ver::COND_GE)], 0);
    chk(&mut s, vec![cond(6, "x", ver::COND_LT)], 0);
    chk(&mut s, vec![cond(5, "x", ver::COND_LT)], ECANCELED);
    chk(&mut s, vec![cond(5, "x", ver::COND_LE)], 0);
    chk(&mut s, vec![cond(0, "tg", ver::COND_TAG_EQ)], 0);
    chk(&mut s, vec![cond(0, "tg", ver::COND_TAG_NE)], ECANCELED);
    chk(&mut s, vec![cond(0, "zz", ver::COND_TAG_NE)], 0);
    chk(&mut s, vec![cond(99, "zz", ver::COND_NONE)], 0);
    // all must hold
    chk(
        &mut s,
        vec![cond(5, "tg", ver::COND_EQ), cond(9, "", ver::COND_GT)],
        ECANCELED,
    );
    // failed inc leaves the version alone
    err(
        &mut s,
        O,
        "version",
        "inc_conds",
        &inc(vec![cond(1, "tg", ver::COND_EQ)]),
        ECANCELED,
    );
    assert_eq!(read_ver(&mut s), objv(5, "tg"));
    ok(
        &mut s,
        O,
        "version",
        "inc_conds",
        &inc(vec![cond(5, "tg", ver::COND_EQ)]),
    );
    assert_eq!(read_ver(&mut s), objv(6, "tg"));
}

#[test]
fn version_garbage_input() {
    let mut s = MemStore::new();
    for m in ["set", "inc", "inc_conds", "check_conds"] {
        err(&mut s, O, "version", m, &[1, 2, 3], EINVAL);
    }
    // corrupt stored value -> EIO
    s.objects.insert(O.into(), Default::default());
    s.objects
        .get_mut(O)
        .unwrap()
        .xattrs
        .insert(ver::ATTR.into(), vec![9]);
    err(&mut s, O, "version", "read", &[], EIO);
    err(&mut s, O, "version", "inc", &inc(vec![]), EIO);
}

fn rget(tag: &str, imp: bool) -> Vec<u8> {
    e(&rc::GetOp {
        tag: tag.into(),
        implicit_ref: imp,
    })
}
fn rput(tag: &str, imp: bool) -> Vec<u8> {
    e(&rc::PutOp {
        tag: tag.into(),
        implicit_ref: imp,
    })
}
fn rread(s: &mut MemStore, imp: bool) -> Vec<Vec<u8>> {
    let r: rc::ReadRet = d(&ok(
        s,
        O,
        "refcount",
        "read",
        &e(&rc::ReadOp { implicit_ref: imp }),
    ));
    r.refs
}

#[test]
fn refcount_implicit_get_put_lifecycle() {
    let mut s = MemStore::new();
    s.objects.insert(O.into(), Default::default());
    // untouched object counts as having the wildcard ref
    assert_eq!(rread(&mut s, true), vec![b"".to_vec()]);
    assert!(rread(&mut s, false).is_empty());
    ok(&mut s, O, "refcount", "get", &rget("t1", true));
    assert_eq!(rread(&mut s, true), vec![b"".to_vec(), b"t1".to_vec()]);
    ok(&mut s, O, "refcount", "put", &rput("t1", true));
    assert_eq!(rread(&mut s, true), vec![b"".to_vec()]);
    // t1 is retired: a second put is a silent no-op
    ok(&mut s, O, "refcount", "put", &rput("t1", true));
    assert_eq!(rread(&mut s, true), vec![b"".to_vec()]);
    // put with an unknown tag + implicit_ref consumes the wildcard -> object removed
    ok(&mut s, O, "refcount", "put", &rput("other", true));
    assert!(s.obj(O).is_none(), "last put removes the object");
}

#[test]
fn refcount_explicit_and_set() {
    let mut s = MemStore::new();
    s.objects.insert(O.into(), Default::default());
    // explicit put on object without attr: no refs at all -> EINVAL
    err(&mut s, O, "refcount", "put", &rput("a", false), EINVAL);
    ok(&mut s, O, "refcount", "get", &rget("a", false));
    ok(&mut s, O, "refcount", "get", &rget("b", false));
    assert_eq!(rread(&mut s, false), vec![b"a".to_vec(), b"b".to_vec()]);
    // unknown tag, explicit: no change
    ok(&mut s, O, "refcount", "put", &rput("zz", false));
    assert_eq!(rread(&mut s, false), vec![b"a".to_vec(), b"b".to_vec()]);
    ok(&mut s, O, "refcount", "put", &rput("a", false));
    assert_eq!(rread(&mut s, false), vec![b"b".to_vec()]);
    // exact stored bytes: v2 envelope {refs: {b: true}, retired: {a}}
    let want = cat(&[
        &[2, 1, 19, 0, 0, 0],
        &[1, 0, 0, 0, 1, 0, 0, 0, b'b', 1],
        &[1, 0, 0, 0, 1, 0, 0, 0, b'a'],
    ]);
    assert_eq!(s.obj(O).unwrap().xattrs[rc::ATTR.as_bytes()], want);
    // set replaces everything (retired dropped); empty set removes the object
    ok(
        &mut s,
        O,
        "refcount",
        "set",
        &e(&rc::SetOp {
            refs: vec!["x".into(), "y".into()],
        }),
    );
    assert_eq!(rread(&mut s, false), vec![b"x".to_vec(), b"y".to_vec()]);
    ok(&mut s, O, "refcount", "put", &rput("a", false)); // a no longer retired but absent
    ok(
        &mut s,
        O,
        "refcount",
        "set",
        &e(&rc::SetOp { refs: vec![] }),
    );
    assert!(s.obj(O).is_none());
}

#[test]
fn refcount_errors() {
    let mut s = MemStore::new();
    // absent object: ENOENT for get/put/read
    err(&mut s, O, "refcount", "get", &rget("a", true), ENOENT);
    err(&mut s, O, "refcount", "put", &rput("a", true), ENOENT);
    err(
        &mut s,
        O,
        "refcount",
        "read",
        &e(&rc::ReadOp { implicit_ref: true }),
        ENOENT,
    );
    for m in ["get", "put", "set", "read"] {
        err(&mut s, O, "refcount", m, &[0xff], EINVAL);
    }
}
