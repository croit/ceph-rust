// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! sem_set scenarios (spec/cls_sem_set.md) on MemStore.
mod common;
use cls::errno::*;
use cls::mem::MemStore;
use cls::sem_set::*;
use common::*;
use denc::types::Timespan;
use std::collections::{BTreeMap, BTreeSet};

const O: &str = "obj";

fn keys(k: &[&str]) -> BTreeSet<Vec<u8>> {
    k.iter().map(|s| s.as_bytes().to_vec()).collect()
}
fn inc(s: &mut MemStore, k: &[&str]) {
    ok(
        s,
        O,
        "sem_set",
        "increment",
        &e(&Increment { keys: keys(k) }),
    );
}
fn dec(s: &mut MemStore, k: &[&str], grace: i32) -> cls::Reply {
    let op = Decrement {
        keys: keys(k),
        grace: Timespan {
            sec: grace,
            nsec: 0,
        },
    };
    call(s, O, "sem_set", "decrement", &e(&op))
}
fn stored(s: &MemStore, k: &str) -> Option<SemVal> {
    s.omap_get(O, &format!("CLS_SEM_SET_{k}")).map(d)
}
fn list(s: &mut MemStore, count: u64, cursor: &str) -> ListRet {
    let op = ListOp {
        count,
        cursor: cursor.as_bytes().to_vec(),
    };
    d(&ok(s, O, "sem_set", "list", &e(&op)))
}

#[test]
fn registry_and_exact_bytes() {
    use cls::registry::*;
    assert_eq!(methods("sem_set").len(), 4);
    for m in ["increment", "decrement", "reset"] {
        assert_eq!(lookup("sem_set", m).unwrap().flags, RW);
    }
    assert_eq!(lookup("sem_set", "list").unwrap().flags, RD);
    let mut s = MemStore::new();
    inc(&mut s, &["a"]);
    let raw = s.omap_get(O, "CLS_SEM_SET_a").unwrap();
    // (1,1,len=16) u64 value=1, utime 0/0
    assert_eq!(
        raw,
        [
            1, 1, 16, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]
    );
    // increment input: (1,1,len) count=1, "a"
    assert_eq!(
        e(&Increment { keys: keys(&["a"]) }),
        [1, 1, 9, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, b'a']
    );
}

#[test]
fn increment_decrement_lifecycle() {
    let mut s = MemStore::new();
    inc(&mut s, &["a", "b"]);
    inc(&mut s, &["a"]);
    assert_eq!(stored(&s, "a").unwrap().value, 2);
    assert_eq!(stored(&s, "b").unwrap().value, 1);
    assert_eq!(dec(&mut s, &["a"], 0).ret, 0);
    let a = stored(&s, "a").unwrap();
    assert_eq!(a.value, 1);
    assert_eq!(a.last_decrement, s.env.now);
    // value 1 -> removed
    assert_eq!(dec(&mut s, &["a", "b"], 0).ret, 0);
    assert!(stored(&s, "a").is_none() && stored(&s, "b").is_none());
    // missing key fails the call and rolls back the rest
    inc(&mut s, &["c", "c"]);
    inc(&mut s, &["c"]);
    assert_eq!(dec(&mut s, &["c", "zz"], 0).ret, ENOENT);
    assert_eq!(stored(&s, "c").unwrap().value, 2);
}

#[test]
fn decrement_grace() {
    let mut s = MemStore::new();
    inc(&mut s, &["a"]);
    inc(&mut s, &["a"]);
    inc(&mut s, &["a"]);
    assert_eq!(dec(&mut s, &["a"], 10).ret, 0); // never decremented before: 3 -> 2
    assert_eq!(stored(&s, "a").unwrap().value, 2);
    s.advance(5);
    assert_eq!(dec(&mut s, &["a"], 10).ret, 0); // inside grace: skipped
    assert_eq!(stored(&s, "a").unwrap().value, 2);
    s.advance(10);
    assert_eq!(dec(&mut s, &["a"], 10).ret, 0);
    assert_eq!(stored(&s, "a").unwrap().value, 1);
    // negative grace = always skip
    s.advance(100);
    assert_eq!(dec(&mut s, &["a"], -1).ret, 0);
    assert_eq!(stored(&s, "a").unwrap().value, 1);
}

#[test]
fn reset_and_list() {
    let mut s = MemStore::new();
    let op = Reset {
        keys: BTreeMap::from([(b"x".to_vec(), 7), (b"y".to_vec(), 0)]),
    };
    ok(&mut s, O, "sem_set", "reset", &e(&op));
    assert_eq!(stored(&s, "x").unwrap().value, 7);
    // foreign omap keys are not listed
    s.objects
        .get_mut(O)
        .unwrap()
        .omap
        .insert(b"other".to_vec(), vec![1]);
    let l = list(&mut s, 100, "");
    assert_eq!(
        l.kvs,
        BTreeMap::from([(b"x".to_vec(), 7), (b"y".to_vec(), 0)])
    );
    assert!(l.cursor.is_empty());
    // paging: cursor continues after the last returned key
    let l = list(&mut s, 1, "");
    assert_eq!(l.kvs.len(), 1);
    assert_eq!(l.cursor, b"x");
    let l = list(&mut s, 1, "x");
    assert_eq!(l.kvs, BTreeMap::from([(b"y".to_vec(), 0)]));
    // count 0 echoes the cursor
    let l = list(&mut s, 0, "q");
    assert!(l.kvs.is_empty());
    assert_eq!(l.cursor, b"q");
}

#[test]
fn list_over_omap_cap_and_limits() {
    let mut s = MemStore::new();
    let m: BTreeMap<Vec<u8>, u64> = (0..2500)
        .map(|i| (format!("k{i:05}").into_bytes(), i as u64))
        .collect();
    // reset takes <= 1000 keys per call
    for chunk in m.iter().collect::<Vec<_>>().chunks(1000) {
        let op = Reset {
            keys: chunk.iter().map(|(k, v)| ((*k).clone(), **v)).collect(),
        };
        ok(&mut s, O, "sem_set", "reset", &e(&op));
    }
    let l = list(&mut s, 5000, "");
    assert_eq!(l.kvs.len(), 2500, "loops over the 1024 per-call cap");
    assert!(l.cursor.is_empty());
    let l = list(&mut s, 2000, "");
    assert_eq!(l.kvs.len(), 2000);
    assert_eq!(l.cursor, b"k01999");
    let l2 = list(&mut s, 2000, "k01999");
    assert_eq!(l2.kvs.len(), 500);
    assert!(l2.cursor.is_empty());

    let big: BTreeSet<Vec<u8>> = (0..1001).map(|i| format!("{i}").into_bytes()).collect();
    err(
        &mut s,
        O,
        "sem_set",
        "increment",
        &e(&Increment { keys: big.clone() }),
        E2BIG,
    );
    let op = Decrement {
        keys: big,
        grace: Timespan::default(),
    };
    err(&mut s, O, "sem_set", "decrement", &e(&op), E2BIG);
    let ok1000: BTreeSet<Vec<u8>> = (0..1000).map(|i| format!("{i}").into_bytes()).collect();
    ok(
        &mut s,
        O,
        "sem_set",
        "increment",
        &e(&Increment { keys: ok1000 }),
    );
}

#[test]
fn corrupt_and_garbage() {
    let mut s = MemStore::new();
    inc(&mut s, &["a"]);
    s.objects
        .get_mut(O)
        .unwrap()
        .omap
        .insert(b"CLS_SEM_SET_a".to_vec(), vec![1, 2]);
    err(
        &mut s,
        O,
        "sem_set",
        "increment",
        &e(&Increment { keys: keys(&["a"]) }),
        EIO,
    );
    assert_eq!(dec(&mut s, &["a"], 0).ret, EIO);
    err(
        &mut s,
        O,
        "sem_set",
        "list",
        &e(&ListOp {
            count: 5,
            cursor: vec![],
        }),
        EIO,
    );
    for m in ["increment", "decrement", "reset", "list"] {
        err(&mut s, O, "sem_set", m, &[1], EINVAL);
    }
}
