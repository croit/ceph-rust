// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Scenario tests of the small classes (spec/cls_hello.md, cls_sdk.md, ...) on MemStore.
mod common;
use cls::errno::*;
use cls::mem::MemStore;
use common::*;

const O: &str = "obj";

// ------------------------------------------------------------------ hello

#[test]
fn hello_registry_flags() {
    use cls::registry::*;
    assert_eq!(methods("hello").len(), 9);
    assert_eq!(lookup("hello", "say_hello").unwrap().flags, RD);
    assert_eq!(lookup("hello", "record_hello").unwrap().flags, WR | PROMOTE);
    assert_eq!(lookup("hello", "write_return_data").unwrap().flags, WR);
    assert_eq!(
        lookup("hello", "writes_dont_return_data").unwrap().flags,
        WR
    );
    assert_eq!(lookup("hello", "replay").unwrap().flags, RD);
    assert_eq!(
        lookup("hello", "turn_it_to_11").unwrap().flags,
        RW | PROMOTE
    );
    assert_eq!(lookup("hello", "bad_reader").unwrap().flags, WR);
    assert_eq!(lookup("hello", "bad_writer").unwrap().flags, RD);
}

#[test]
fn hello_say_and_record_replay() {
    let mut s = MemStore::new();
    assert_eq!(ok(&mut s, O, "hello", "say_hello", b""), b"Hello, world!");
    assert_eq!(
        ok(&mut s, O, "hello", "say_hello", b"Tester"),
        b"Hello, Tester!"
    );
    err(&mut s, O, "hello", "say_hello", &[b'x'; 101], EINVAL);
    assert_eq!(ok(&mut s, O, "hello", "say_hello", &[b'x'; 100]).len(), 108);

    assert!(ok(&mut s, O, "hello", "record_hello", b"").is_empty());
    err(&mut s, O, "hello", "record_hello", b"", EEXIST);
    err(&mut s, "o2", "hello", "record_hello", &[b'y'; 101], EINVAL);
    assert_eq!(ok(&mut s, O, "hello", "replay", b""), b"Hello, world!");
    let who = &s.obj(O).unwrap().xattrs["said_by".as_bytes()];
    assert_eq!(who, b"client.4123 v2:10.0.0.5:40000/1234");

    assert!(ok(&mut s, O, "hello", "turn_it_to_11", b"").is_empty());
    assert_eq!(ok(&mut s, O, "hello", "replay", b""), b"HELLO, WORLD!");
    assert!(
        s.obj(O)
            .unwrap()
            .xattrs
            .contains_key("amplified_by".as_bytes())
    );
    err(&mut s, O, "hello", "turn_it_to_11", b"x", EINVAL);
}

#[test]
fn hello_return_data_and_violators() {
    let mut s = MemStore::new();
    let r = call(&mut s, O, "hello", "write_return_data", b"");
    assert_eq!(
        (r.ret, r.out.as_slice()),
        (42, b"you might see this".as_slice())
    );
    assert_eq!(s.obj(O).unwrap().xattrs["foo".as_bytes()], b"bar");
    // failing call keeps its output, discards the xattr write
    let mut s2 = MemStore::new();
    let r = call(&mut s2, "n", "hello", "writes_dont_return_data", b"x");
    assert_eq!(
        (r.ret, r.out.as_slice()),
        (EINVAL, b"too much input data!".as_slice())
    );
    assert!(s2.obj("n").is_none());
    let r = call(&mut s, O, "hello", "write_too_much_return_data", b"");
    assert_eq!((r.ret, r.out.len()), (42, 520));

    // flag violations: executor semantics -> -EIO
    err(&mut s, O, "hello", "bad_writer", b"zz", EIO);
    err(&mut s, O, "hello", "bad_reader", b"", EIO);
}

// ------------------------------------------------------------------ sdk

#[test]
fn sdk_write_then_replay_removes() {
    let mut s = MemStore::new();
    assert!(ok(&mut s, O, "sdk", "test_coverage_write", b"").is_empty());
    let o = s.obj(O).unwrap();
    assert_eq!(o.data, b"test");
    assert_eq!(o.xattrs["foo".as_bytes()], b"test");
    assert_eq!(s.omap_get(O, "foo").unwrap(), b"test");
    ok(&mut s, O, "sdk", "test_coverage_replay", b"");
    assert!(s.obj(O).is_none());
}

#[test]
fn sdk_replay_errors() {
    let mut s = MemStore::new();
    ok(&mut s, O, "sdk", "test_coverage_write", b"");
    s.objects
        .get_mut(O)
        .unwrap()
        .xattrs
        .insert("foo".into(), b"toolong".to_vec());
    err(&mut s, O, "sdk", "test_coverage_replay", b"", EIO);
    s.objects
        .get_mut(O)
        .unwrap()
        .xattrs
        .remove("foo".as_bytes());
    err(&mut s, O, "sdk", "test_coverage_replay", b"", ENODATA);
}

/// Two-message scenario (recorded for the classic differential): a violating `writes_dont_return_data`
/// on an existing object keeps its output and the earlier write.
#[test]
fn hello_writes_dont_return_data_after_write() {
    let mut s = MemStore::new();
    let r = call(&mut s, O, "hello", "write_return_data", b"");
    assert_eq!(r.ret, 42);
    let r = call(&mut s, O, "hello", "writes_dont_return_data", b"x");
    assert_eq!(
        (r.ret, r.out.as_slice()),
        (EINVAL, b"too much input data!".as_slice())
    );
    assert_eq!(s.obj(O).unwrap().xattrs["foo".as_bytes()], b"bar");
}
