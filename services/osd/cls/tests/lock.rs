// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! cls_lock scenarios (spec/cls_lock.md s15) on MemCtx.
mod common;
use cls::errno::*;
use cls::lock::*;
use cls::mem::MemStore;
use common::*;
use denc::types::{EntityName, UTime};

const O: &str = "obj";

fn lock_op(name: &str, ty: u8, cookie: &str, tag: &str, dur: u32, flags: u8) -> Vec<u8> {
    e(&LockOp {
        name: name.into(),
        ty,
        cookie: cookie.into(),
        tag: tag.into(),
        description: "d".into(),
        duration: UTime::new(dur, 0),
        flags,
    })
}
fn unlock_op(name: &str, cookie: &str) -> Vec<u8> {
    e(&UnlockOp {
        name: name.into(),
        cookie: cookie.into(),
    })
}
fn assert_op(name: &str, ty: u8, cookie: &str, tag: &str) -> Vec<u8> {
    e(&AssertOp {
        name: name.into(),
        ty,
        cookie: cookie.into(),
        tag: tag.into(),
    })
}
fn info(s: &mut MemStore, name: &str) -> LockInfo {
    d(&ok(
        s,
        O,
        "lock",
        "get_info",
        &e(&GetInfoOp { name: name.into() }),
    ))
}

#[test]
fn registry_flags() {
    use cls::registry::*;
    let m = lookup("lock", "lock").unwrap();
    assert_eq!(m.flags, RD | WR | PROMOTE);
    assert_eq!(lookup("lock", "get_info").unwrap().flags, RD);
    assert_eq!(lookup("lock", "break_lock").unwrap().flags, RD | WR);
    assert_eq!(lookup("lock", "assert_locked").unwrap().flags, RD | PROMOTE);
    assert_eq!(methods("lock").len(), 7);
    assert!(lookup("lock", "nope").is_none());
    assert!(lookup("nope", "x").is_none());
}

#[test]
fn exclusive_vs_exclusive() {
    let mut s = MemStore::new();
    client(&mut s, 1);
    ok(&mut s, O, "lock", "lock", &lock_op("l", 1, "c1", "", 0, 0));
    client(&mut s, 2);
    err(
        &mut s,
        O,
        "lock",
        "lock",
        &lock_op("l", 1, "c1", "", 0, 0),
        EBUSY,
    );
    client(&mut s, 1);
    // same id again without renew
    err(
        &mut s,
        O,
        "lock",
        "lock",
        &lock_op("l", 1, "c1", "", 0, 0),
        EEXIST,
    );
    // different cookie, exclusive -> busy
    err(
        &mut s,
        O,
        "lock",
        "lock",
        &lock_op("l", 1, "c2", "", 0, 0),
        EBUSY,
    );
    let i = info(&mut s, "l");
    assert_eq!(i.lock_type, LOCK_EXCLUSIVE);
    assert_eq!(i.lockers.len(), 1);
    let (id, li) = i.lockers.iter().next().unwrap();
    assert_eq!(id.locker, EntityName::client(1));
    assert_eq!(li.addr.ty, 1, "stored address type is LEGACY");
    assert_eq!(li.description, b"d");
}

#[test]
fn shared_rules() {
    let mut s = MemStore::new();
    client(&mut s, 1);
    ok(&mut s, O, "lock", "lock", &lock_op("l", 2, "a", "t", 0, 0));
    client(&mut s, 2);
    ok(&mut s, O, "lock", "lock", &lock_op("l", 2, "a", "t", 0, 0));
    client(&mut s, 3);
    err(
        &mut s,
        O,
        "lock",
        "lock",
        &lock_op("l", 2, "a", "other", 0, 0),
        EBUSY,
    );
    err(
        &mut s,
        O,
        "lock",
        "lock",
        &lock_op("l", 1, "a", "t", 0, 0),
        EBUSY,
    );
    assert_eq!(info(&mut s, "l").lockers.len(), 2);
    // invalid args
    err(
        &mut s,
        O,
        "lock",
        "lock",
        &lock_op("l", 0, "a", "t", 0, 0),
        EINVAL,
    );
    err(
        &mut s,
        O,
        "lock",
        "lock",
        &lock_op("", 1, "a", "t", 0, 0),
        EINVAL,
    );
    err(
        &mut s,
        O,
        "lock",
        "lock",
        &lock_op("l", 1, "a", "t", 0, 3),
        EINVAL,
    );
    err(&mut s, O, "lock", "lock", &[1, 2], EINVAL);
}

#[test]
fn renew_table() {
    let mut s = MemStore::new();
    client(&mut s, 1);
    // MUST_RENEW without existing -> ENOENT
    err(
        &mut s,
        O,
        "lock",
        "lock",
        &lock_op("l", 1, "c", "", 0, 2),
        ENOENT,
    );
    ok(&mut s, O, "lock", "lock", &lock_op("l", 1, "c", "", 0, 0));
    ok(&mut s, O, "lock", "lock", &lock_op("l", 1, "c", "", 0, 1));
    ok(&mut s, O, "lock", "lock", &lock_op("l", 1, "c", "", 0, 2));
    // MAY_RENEW with absent id proceeds (-> busy because exclusive held)
    err(
        &mut s,
        O,
        "lock",
        "lock",
        &lock_op("l", 1, "other", "", 0, 1),
        EBUSY,
    );
    // tag mismatch is checked before renew handling
    err(
        &mut s,
        O,
        "lock",
        "lock",
        &lock_op("l", 1, "c", "x", 0, 1),
        EBUSY,
    );
}

#[test]
fn expiry_takeover_and_unlock_keeps_xattr() {
    let mut s = MemStore::new();
    client(&mut s, 1);
    ok(
        &mut s,
        O,
        "lock",
        "lock",
        &lock_op("l", 1, "c", "tagA", 30, 0),
    );
    client(&mut s, 2);
    err(
        &mut s,
        O,
        "lock",
        "lock",
        &lock_op("l", 1, "c", "tagB", 0, 0),
        EBUSY,
    );
    s.advance(31);
    assert!(
        info(&mut s, "l").lockers.is_empty(),
        "expired locker dropped from the view"
    );
    // takeover: tag check does not apply with no live lockers
    ok(
        &mut s,
        O,
        "lock",
        "lock",
        &lock_op("l", 1, "c", "tagB", 0, 0),
    );
    assert_eq!(info(&mut s, "l").tag, b"tagB");
    ok(&mut s, O, "lock", "unlock", &unlock_op("l", "c"));
    let i = info(&mut s, "l");
    assert!(i.lockers.is_empty());
    assert_eq!(i.lock_type, LOCK_EXCLUSIVE, "type kept after last unlock");
    assert_eq!(i.tag, b"tagB");
    let l: ListLocksReply = d(&ok(&mut s, O, "lock", "list_locks", &[]));
    assert_eq!(l.locks, vec![b"l".to_vec()]);
    err(&mut s, O, "lock", "unlock", &unlock_op("l", "c"), ENOENT);
}

/// Review F1: `expiration = now + duration` caps the seconds at u32::MAX like classic `utime_t` addition; a "forever"
/// duration must never wrap into the past (the lock would expire at once and a second exclusive locker succeed).
#[test]
fn long_duration_saturates_instead_of_wrapping() {
    for dur in [u32::MAX, u32::MAX - 10] {
        let mut s = MemStore::new();
        client(&mut s, 1);
        ok(
            &mut s,
            O,
            "lock",
            "lock",
            &lock_op("l", 1, "c1", "", dur, 0),
        );
        let i = info(&mut s, "l");
        let exp = i.lockers.values().next().expect("locker").expiration;
        assert_eq!(exp.sec, u32::MAX, "dur {dur}: capped");
        client(&mut s, 2);
        err(
            &mut s,
            O,
            "lock",
            "lock",
            &lock_op("l", 1, "c2", "", 0, 0),
            EBUSY,
        );
    }
}

#[test]
fn break_by_third_party_and_set_cookie() {
    let mut s = MemStore::new();
    client(&mut s, 1);
    ok(&mut s, O, "lock", "lock", &lock_op("l", 1, "c1", "", 0, 0));
    client(&mut s, 9);
    let brk = e(&BreakOp {
        name: "l".into(),
        locker: EntityName::client(1),
        cookie: "c1".into(),
    });
    ok(&mut s, O, "lock", "break_lock", &brk);
    err(&mut s, O, "lock", "break_lock", &brk, ENOENT);
    // set_cookie
    client(&mut s, 1);
    ok(
        &mut s,
        O,
        "lock",
        "lock",
        &lock_op("l", 1, "c1", "tg", 0, 0),
    );
    let sc = |n: &str| {
        e(&SetCookieOp {
            name: "l".into(),
            ty: 1,
            cookie: "c1".into(),
            tag: "tg".into(),
            new_cookie: n.into(),
        })
    };
    ok(&mut s, O, "lock", "set_cookie", &sc("c2"));
    err(&mut s, O, "lock", "set_cookie", &sc("c3"), EBUSY); // c1 no longer a locker
    ok(
        &mut s,
        O,
        "lock",
        "assert_locked",
        &assert_op("l", 1, "c2", "tg"),
    );
    err(
        &mut s,
        O,
        "lock",
        "assert_locked",
        &assert_op("l", 1, "c1", "tg"),
        EBUSY,
    );
    // collision: a second shared locker of the same entity cannot take an existing cookie
    let mut s2 = MemStore::new();
    client(&mut s2, 1);
    ok(&mut s2, O, "lock", "lock", &lock_op("l", 2, "a", "", 0, 0));
    ok(&mut s2, O, "lock", "lock", &lock_op("l", 2, "b", "", 0, 0));
    let sc2 = e(&SetCookieOp {
        name: "l".into(),
        ty: 2,
        cookie: "a".into(),
        tag: "".into(),
        new_cookie: "b".into(),
    });
    err(&mut s2, O, "lock", "set_cookie", &sc2, EBUSY);
}

#[test]
fn get_info_empty_and_absent() {
    let mut s = MemStore::new();
    // absent object: ENOENT (read_lock)
    err(
        &mut s,
        O,
        "lock",
        "get_info",
        &e(&GetInfoOp { name: "l".into() }),
        ENOENT,
    );
    // existing object without lock: success, empty, type 0
    s.msg(O, |c| (c.create(false).map_or(-1, |_| 0), ()));
    let i = info(&mut s, "l");
    assert_eq!(
        (i.lock_type, i.tag.as_slice(), i.lockers.len()),
        (0, b"".as_slice(), 0)
    );
    let r = call(&mut s, O, "lock", "get_info", &[0]);
    assert_eq!(r.ret, EINVAL);
}

use cls::ClsCtx;

#[test]
fn assert_locked_fence_rolls_back_siblings() {
    let mut s = MemStore::new();
    client(&mut s, 1);
    ok(
        &mut s,
        O,
        "lock",
        "lock",
        &lock_op("rbd_lock", 1, "auto 1", "internal", 0, 0),
    );
    // message: assert_locked (wrong cookie) + a write; whole message fails, nothing applied
    let (ret, _) = s.msg(O, |c| {
        c.setxattr("x", b"1").unwrap();
        let r = c.call(
            "lock",
            "assert_locked",
            &assert_op("rbd_lock", 1, "auto 2", "internal"),
        );
        (r.ret, ())
    });
    assert_eq!(ret, EBUSY);
    assert!(!s.obj(O).unwrap().xattrs.contains_key("x".as_bytes()));
    let (ret, _) = s.msg(O, |c| {
        let r = c.call(
            "lock",
            "assert_locked",
            &assert_op("rbd_lock", 1, "auto 1", "internal"),
        );
        c.setxattr("x", b"1").unwrap();
        (r.ret, ())
    });
    assert_eq!(ret, 0);
    assert!(s.obj(O).unwrap().xattrs.contains_key("x".as_bytes()));
}

#[test]
fn lock_then_get_info_in_one_message_sees_old_state() {
    let mut s = MemStore::new();
    client(&mut s, 1);
    s.msg(O, |c| (c.create(false).map_or(-1, |_| 0), ()));
    let (ret, out) = s.msg(O, |c| {
        let r = c.call("lock", "lock", &lock_op("l", 1, "c", "", 0, 0));
        assert_eq!(r.ret, 0);
        let g = c.call("lock", "get_info", &e(&GetInfoOp { name: "l".into() }));
        (g.ret, g.out)
    });
    assert_eq!(ret, 0);
    let i: LockInfo = d(&out);
    assert!(
        i.lockers.is_empty() && i.lock_type == 0,
        "message-start view"
    );
    assert_eq!(info(&mut s, "l").lockers.len(), 1);
}

#[test]
fn compound_lock_then_failure_leaves_no_xattr() {
    let mut s = MemStore::new();
    client(&mut s, 1);
    let (ret, _) = s.msg(O, |c| {
        c.call("lock", "lock", &lock_op("striper.lock", 1, "u", "", 30, 0));
        (ECANCELED, ())
    });
    assert_eq!(ret, ECANCELED);
    assert!(s.obj(O).is_none());
}

#[test]
fn ephemeral_lock() {
    let mut s = MemStore::new();
    client(&mut s, 1);
    ok(&mut s, O, "lock", "lock", &lock_op("l", 3, "c", "", 0, 0));
    ok(&mut s, O, "lock", "unlock", &unlock_op("l", "c"));
    assert!(s.obj(O).is_none(), "ephemeral unlock removes the object");
    // expired ephemeral in a read-only method: removal inside RD method -> EIO (flag enforcement)
    ok(&mut s, O, "lock", "lock", &lock_op("l", 3, "c", "", 5, 0));
    s.advance(6);
    err(
        &mut s,
        O,
        "lock",
        "get_info",
        &e(&GetInfoOp { name: "l".into() }),
        EIO,
    );
}

#[test]
fn legacy_client_addr_form() {
    let mut s = MemStore::new();
    client(&mut s, 1);
    s.env.client_features = !(1u64 << 59);
    ok(&mut s, O, "lock", "lock", &lock_op("l", 1, "c", "", 0, 0));
    let raw = &s.obj(O).unwrap().xattrs["lock.l".as_bytes()];
    let i: LockInfo = d(raw);
    assert_eq!(i.lockers.len(), 1);
    // legacy form is 136 bytes for the address (marker 0 form), stored value is larger
    let mut s2 = MemStore::new();
    client(&mut s2, 1);
    ok(&mut s2, O, "lock", "lock", &lock_op("l", 1, "c", "", 0, 0));
    assert!(raw.len() > s2.obj(O).unwrap().xattrs["lock.l".as_bytes()].len());
}

#[test]
fn raw_binary_fields_all_methods_and_name_nul_alias() {
    let mut s = MemStore::new();
    client(&mut s, 7);
    let name = vec![0xff, b'n', 0, b'x'];
    let canonical = vec![0xff, b'n'];
    let cookie = vec![0xfe, 0, b'c'];
    let tag = vec![0xfd, 0, b't'];
    let description = vec![0xfc, 0, b'd'];
    let acquire = LockOp {
        name: name.clone(),
        ty: LOCK_SHARED,
        cookie: cookie.clone(),
        tag: tag.clone(),
        description: description.clone(),
        duration: UTime::default(),
        flags: 0,
    };
    ok(&mut s, O, "lock", "lock", &e(&acquire));
    // Name suffix after NUL aliases; cookie/tag/description suffixes remain length-aware.
    let view: LockInfo = d(&ok(
        &mut s,
        O,
        "lock",
        "get_info",
        &e(&GetInfoOp {
            name: canonical.clone(),
        }),
    ));
    assert_eq!(view.tag, tag);
    assert_eq!(view.lock_type, LOCK_SHARED);
    let (id, holder) = view.lockers.iter().next().unwrap();
    assert_eq!(id.cookie, cookie);
    assert_eq!(holder.description, description);
    assert!(
        s.obj(O)
            .unwrap()
            .xattrs
            .contains_key(b"lock.\xffn".as_slice())
    );
    let names: ListLocksReply = d(&ok(&mut s, O, "lock", "list_locks", b"ignored"));
    assert_eq!(names.locks, vec![canonical.clone()]);
    let assertion = AssertOp {
        name: canonical.clone(),
        ty: LOCK_SHARED,
        cookie: cookie.clone(),
        tag: tag.clone(),
    };
    ok(&mut s, O, "lock", "assert_locked", &e(&assertion));
    let mut short = assertion.clone();
    short.cookie.truncate(1);
    err(&mut s, O, "lock", "assert_locked", &e(&short), EBUSY);
    short = assertion.clone();
    short.tag.truncate(1);
    err(&mut s, O, "lock", "assert_locked", &e(&short), EBUSY);
    let second = vec![0xfe, 0, b'z'];
    let mut another = acquire.clone();
    another.cookie = second.clone();
    another.name = canonical.clone();
    ok(&mut s, O, "lock", "lock", &e(&another));
    let view: LockInfo = d(&ok(
        &mut s,
        O,
        "lock",
        "get_info",
        &e(&GetInfoOp { name: name.clone() }),
    ));
    assert_eq!(
        view.lockers
            .keys()
            .map(|id| id.cookie.as_slice())
            .collect::<Vec<_>>(),
        vec![cookie.as_slice(), second.as_slice()]
    );
    let replacement = vec![0xfb, 0, b'c'];
    ok(
        &mut s,
        O,
        "lock",
        "set_cookie",
        &e(&SetCookieOp {
            name: name.clone(),
            ty: LOCK_SHARED,
            cookie: cookie.clone(),
            tag: tag.clone(),
            new_cookie: replacement.clone(),
        }),
    );
    err(&mut s, O, "lock", "assert_locked", &e(&assertion), EBUSY);
    ok(
        &mut s,
        O,
        "lock",
        "unlock",
        &e(&UnlockOp {
            name: canonical.clone(),
            cookie: replacement,
        }),
    );
    // A distinct authenticated client explicitly breaks the supplied owner's binary cookie.
    client(&mut s, 8);
    ok(
        &mut s,
        O,
        "lock",
        "break_lock",
        &e(&BreakOp {
            name: name.clone(),
            locker: EntityName::client(7),
            cookie: second,
        }),
    );
    let view: LockInfo = d(&ok(
        &mut s,
        O,
        "lock",
        "get_info",
        &e(&GetInfoOp { name: canonical }),
    ));
    assert_eq!(view.lockers.len(), 0);
    assert_eq!(view.tag, tag);
}

#[test]
fn original_empty_validation_precedes_nul_only_name_alias() {
    let mut s = MemStore::new();
    let mut input = LockOp {
        name: vec![0, b'x'],
        ty: LOCK_EXCLUSIVE,
        cookie: vec![0xff, 0],
        ..Default::default()
    };
    ok(&mut s, O, "lock", "lock", &e(&input));
    let names: ListLocksReply = d(&ok(&mut s, O, "lock", "list_locks", b""));
    assert_eq!(names.locks, vec![Vec::<u8>::new()]);
    assert!(s.obj(O).unwrap().xattrs.contains_key(b"lock.".as_slice()));
    input.name.clear();
    err(&mut s, O, "lock", "lock", &e(&input), EINVAL);
    let assertion = AssertOp {
        name: vec![],
        ty: LOCK_EXCLUSIVE,
        cookie: input.cookie.clone(),
        tag: vec![],
    };
    err(&mut s, O, "lock", "assert_locked", &e(&assertion), EINVAL);
    err(
        &mut s,
        O,
        "lock",
        "set_cookie",
        &e(&SetCookieOp {
            name: vec![],
            ty: LOCK_EXCLUSIVE,
            cookie: input.cookie,
            tag: vec![],
            new_cookie: vec![],
        }),
        EINVAL,
    );
}
