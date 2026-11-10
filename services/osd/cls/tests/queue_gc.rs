// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! cls_queue ring engine + rgw_gc scenarios (spec/cls_queue.md, spec/cls_rgw_gc.md) on MemCtx.
mod common;
use cls::errno::*;
use cls::mem::MemStore;
use cls::queue::{self, Entry, ListOp, ListRet};
use cls::rgw::types::ObjKey;
use cls::rgw_gc as gc;
use common::*;
use denc::types::UTime;

const Q: &str = "q";
const G: &str = "gc.0";

fn qinit(s: &mut MemStore, size: u64) -> i32 {
    let op = queue::InitOp {
        queue_size: size,
        max_urgent_data_size: 0,
        bl_urgent_data: vec![],
    };
    call(s, Q, "queue", "queue_init", &e(&op)).ret
}
fn enq(s: &mut MemStore, items: &[&[u8]]) -> i32 {
    let op = queue::EnqueueOp {
        bl_data_vec: items.iter().map(|x| x.to_vec()).collect(),
    };
    call(s, Q, "queue", "queue_enqueue", &e(&op)).ret
}
fn qlist(s: &mut MemStore, max: u64, start: &[u8], end: &[u8]) -> ListRet {
    let op = ListOp {
        max,
        start_marker: start.into(),
        end_marker: end.into(),
    };
    d(&ok(s, Q, "queue", "queue_list_entries", &e(&op)))
}
fn qrem(s: &mut MemStore, end: &[u8]) -> i32 {
    let op = queue::RemoveOp {
        end_marker: end.into(),
    };
    call(s, Q, "queue", "queue_remove_entries", &e(&op)).ret
}
fn head(s: &MemStore) -> queue::Head {
    head_at(s, Q)
}
fn head_at(s: &MemStore, oid: &str) -> queue::Head {
    let data = &s.obj(oid).unwrap().data;
    assert_eq!(&data[..2], &[0xAD, 0xDE], "head magic 0xDEAD little endian");
    let len = u64::from_le_bytes(data[2..10].try_into().unwrap()) as usize;
    d(&data[10..10 + len])
}
fn payloads(l: &ListRet) -> Vec<Vec<u8>> {
    l.entries.iter().map(|x: &Entry| x.data.clone()).collect()
}
fn mk(n: u8, len: usize) -> Vec<u8> {
    vec![n; len]
}

#[test]
fn registry() {
    use cls::registry::*;
    assert_eq!(methods("queue").len(), 5);
    assert_eq!(lookup("queue", "queue_list_entries").unwrap().flags, RD);
    assert_eq!(lookup("queue", "queue_get_capacity").unwrap().flags, RD);
    assert_eq!(lookup("queue", "queue_enqueue").unwrap().flags, RW);
    assert_eq!(methods("rgw_gc").len(), 5);
    assert_eq!(
        lookup("rgw_gc", "rgw_gc_queue_list_entries").unwrap().flags,
        RD
    );
    assert_eq!(lookup("rgw_gc", "rgw_gc_queue_enqueue").unwrap().flags, RW);
}

#[test]
fn marker_text_form_and_lenient_parse() {
    use queue::Marker;
    let m = Marker {
        gen_: 3,
        offset: 1050,
    };
    assert_eq!(m.to_bytes(), b"3/1050");
    assert_eq!(Marker::parse(b"3/1050"), m);
    assert_eq!(Marker::parse(b""), Marker::default());
    assert_eq!(Marker::parse(b"7"), Marker { gen_: 7, offset: 0 });
    assert_eq!(Marker::parse(b"garbage"), Marker::default());
    assert_eq!(Marker::parse(b"2/x"), Marker { gen_: 2, offset: 0 });
    // wire: ENCODE_START(1,1) with gen FIRST
    assert_eq!(
        e(&m),
        cat(&[
            &[1, 1, 16, 0, 0, 0],
            &3u64.to_le_bytes(),
            &1050u64.to_le_bytes()
        ])
    );
}

#[test]
fn count_matches_list_entry_count_without_payloads() {
    let mut s = MemStore::new();
    assert_eq!(qinit(&mut s, 4096), 0);
    assert_eq!(enq(&mut s, &[b"aaaa", b"bb", b"", b"cccc"]), 0);
    let h = head(&s);
    let l = qlist(&mut s, 1000, b"", b"");
    assert_eq!(l.entries.len(), 4);
    let (front, tail) = (h.front.to_bytes(), h.tail.to_bytes());
    let (mid, last) = (l.entries[1].marker.clone(), l.entries[3].marker.clone());
    let ends: Vec<&[u8]> = vec![b"", &front, &mid, &last, &tail, b"99/5"];
    let (ret, got) = s.msg(Q, |c| {
        let mut v = Vec::new();
        for e in &ends {
            let n = queue::count(c, &h, e).unwrap();
            v.push((
                n,
                queue::list(c, &h, u64::MAX, &[], e).unwrap().entries.len() as u64,
            ));
        }
        (0, v)
    });
    assert_eq!(ret, 0);
    assert_eq!(
        got,
        vec![(4, 4), (0, 0), (1, 1), (3, 3), (4, 4), (4, 4)],
        "(count, list) per end_marker"
    );

    // a corrupt entry frame is -EINVAL on both scans
    let front = head(&s).front.offset as usize;
    s.objects.get_mut(Q).unwrap().data[front] = 0;
    let h = head(&s);
    let (ret, both) = s.msg(Q, |c| {
        (
            0,
            (
                queue::count(c, &h, &[]).unwrap_err(),
                queue::list(c, &h, u64::MAX, &[], &[]).unwrap_err(),
            ),
        )
    });
    assert_eq!(ret, 0);
    assert_eq!(both, (EINVAL, EINVAL));
}

#[test]
fn count_spans_the_physical_ring_wrap() {
    let mut s = MemStore::new();
    assert_eq!(qinit(&mut s, 100), 0);
    for i in 0..20u8 {
        assert_eq!(enq(&mut s, &[&[i; 20], &[i + 1; 20]]), 0, "round {i}");
        let l = qlist(&mut s, 1000, b"", b"");
        assert_eq!(l.entries.len(), 2);
        let h = head(&s);
        let (ret, counts) = s.msg(Q, |c| {
            (
                0,
                (
                    queue::count(c, &h, &h.tail.to_bytes()).unwrap(),
                    queue::count(c, &h, &l.entries[1].marker).unwrap(),
                ),
            )
        });
        assert_eq!((ret, counts), (0, (2, 1)), "round {i}");
        assert_eq!(qrem(&mut s, &l.entries[1].marker), 0);
        assert_eq!(qrem(&mut s, &h.tail.to_bytes()), 0);
    }
    assert!(head(&s).front.gen_ >= 2, "the scan crossed the ring end");
}

#[test]
fn init_head_bytes_and_errors() {
    let mut s = MemStore::new();
    // recorded on classic 21.1.2: queue_init creates the object (the empty head read of an absent object takes the EINVAL path)
    assert_eq!(qinit(&mut s, 4096), 0);
    s.objects.remove(Q);
    s.objects.insert(Q.into(), Default::default());
    assert_eq!(qinit(&mut s, 4096), 0);
    let h = head(&s);
    assert_eq!(
        (h.max_head_size, h.queue_size, h.max_urgent_data_size),
        (1024, 4096 + 1024, 0)
    );
    assert_eq!(
        (h.front.gen_, h.front.offset, h.tail.offset),
        (0, 1024, 1024)
    );
    // exact head bytes
    let m = |g: u64, o: u64| cat(&[&[1, 1, 16, 0, 0, 0], &g.to_le_bytes(), &o.to_le_bytes()]);
    let body = cat(&[
        &1024u64.to_le_bytes(),
        &m(0, 1024),
        &m(0, 1024),
        &5120u64.to_le_bytes(),
        &0u64.to_le_bytes(),
        &[0, 0, 0, 0],
    ]);
    let want = cat(&[
        &[0xAD, 0xDE],
        &(body.len() as u64 + 6).to_le_bytes(),
        &[1, 1],
        &(body.len() as u32).to_le_bytes(),
        &body,
    ]);
    assert_eq!(&s.obj(Q).unwrap().data[..want.len()], &want[..]);
    // already initialised
    assert_eq!(qinit(&mut s, 4096), EEXIST);
    // capacity
    let cap: queue::GetCapacityRet = d(&ok(&mut s, Q, "queue", "queue_get_capacity", &[]));
    assert_eq!(cap.queue_capacity, 4096);
    // garbage head is overwritten silently; empty object counts as not initialised
    s.objects.get_mut(Q).unwrap().data = vec![0xAD, 0xDE, 1, 2, 3];
    assert_eq!(qinit(&mut s, 100), 0);
    // enqueue/list/capacity before init
    let mut s2 = MemStore::new();
    s2.objects.insert(Q.into(), Default::default());
    assert_eq!(enq(&mut s2, &[b"x"]), EINVAL);
    err(&mut s2, Q, "queue", "queue_get_capacity", &[], EINVAL);
}

#[test]
fn entry_framing_and_listing() {
    let mut s = MemStore::new();
    s.objects.insert(Q.into(), Default::default());
    qinit(&mut s, 4096);
    assert_eq!(enq(&mut s, &[b"hello", b"wor"]), 0);
    let data = &s.obj(Q).unwrap().data;
    // entry at 1024: BEEF (LE) + u64 len + bytes; second right after
    assert_eq!(
        &data[1024..1024 + 15],
        &cat(&[&[0xEF, 0xBE], &5u64.to_le_bytes(), b"hello"])[..]
    );
    assert_eq!(
        &data[1039..1039 + 13],
        &cat(&[&[0xEF, 0xBE], &3u64.to_le_bytes(), b"wor"])[..]
    );
    let h = head(&s);
    assert_eq!(
        (h.front.offset, h.tail.offset, h.tail.gen_),
        (1024, 1052, 0)
    );
    let l = qlist(&mut s, 100, b"", b"");
    assert_eq!(payloads(&l), [b"hello".to_vec(), b"wor".to_vec()]);
    assert_eq!(l.entries[0].marker, b"0/1024");
    assert_eq!(l.entries[1].marker, b"0/1039");
    assert!(!l.is_truncated);
    assert_eq!(l.next_marker, b"0/1052");
    // paging with max=1
    let l1 = qlist(&mut s, 1, b"", b"");
    assert_eq!(payloads(&l1), [b"hello".to_vec()]);
    assert!(l1.is_truncated);
    assert_eq!(l1.next_marker, b"0/1039");
    let l2 = qlist(&mut s, 1, &l1.next_marker, b"");
    assert_eq!(payloads(&l2), [b"wor".to_vec()]);
    assert!(!l2.is_truncated, "next == tail");
    // end_marker: stop before it, next_marker = end_marker
    let l3 = qlist(&mut s, 100, b"", b"0/1039");
    assert_eq!(payloads(&l3), [b"hello".to_vec()]);
    assert_eq!(l3.next_marker, b"0/1039");
    assert!(l3.is_truncated);
    // empty queue
    qrem(&mut s, b"0/1052");
    let l4 = qlist(&mut s, 10, b"", b"");
    assert!(l4.entries.is_empty() && !l4.is_truncated);
    assert_eq!(l4.next_marker, b"0/1052");
    // the zeroed range reaches the end of the object: classic munges ZERO to TRUNCATE (stat size 1024, recorded)
    assert_eq!(s.obj(Q).unwrap().data.len(), 1024);
}

#[test]
fn ring_wrap_split_entry_full_and_remove() {
    let mut s = MemStore::new();
    s.objects.insert(Q.into(), Default::default());
    qinit(&mut s, 100); // ring [1024, 1124)
    let (a, b, c3) = (mk(1, 30), mk(2, 30), mk(3, 30));
    assert_eq!(enq(&mut s, &[&a, &b]), 0); // 2 x 40 bytes
    // third (40 B) does not fit into the 20 free bytes
    assert_eq!(enq(&mut s, &[&c3]), ENOSPC);
    let before = s.obj(Q).unwrap().clone();
    assert_eq!(enq(&mut s, &[&a, &b]), ENOSPC);
    assert_eq!(s.obj(Q).unwrap(), &before, "failed enqueue changes nothing");
    // free the first entry, then the third wraps: 20 bytes at the end, 20 at the start
    assert_eq!(qrem(&mut s, b"0/1064"), 0);
    assert!(s.obj(Q).unwrap().data[1024..1064].iter().all(|x| *x == 0));
    assert_eq!(enq(&mut s, &[&c3]), 0);
    let h = head(&s);
    assert_eq!((h.front.gen_, h.front.offset), (0, 1064));
    assert_eq!(
        (h.tail.gen_, h.tail.offset),
        (1, 1044),
        "wrapped: generation + 1"
    );
    let data = s.obj(Q).unwrap().data.clone();
    let frame = cat(&[&[0xEF, 0xBE], &30u64.to_le_bytes(), &c3]);
    assert_eq!(&data[1104..1124], &frame[..20]);
    assert_eq!(&data[1024..1044], &frame[20..]);
    // list across the wrap: the straddling entry is reassembled; markers carry the generation
    let l = qlist(&mut s, 10, b"", b"");
    assert_eq!(payloads(&l), [b.clone(), c3.clone()]);
    assert_eq!(l.entries[0].marker, b"0/1064");
    assert_eq!(l.entries[1].marker, b"0/1104");
    assert_eq!(l.next_marker, b"1/1044");
    assert!(!l.is_truncated);
    // paging resumes inside generation 0 and crosses the wrap
    let p = qlist(&mut s, 1, b"0/1104", b"");
    assert_eq!(payloads(&p), std::slice::from_ref(&c3));
    // full ring now: used = 80 of 100; 21+ free bytes? free=20 -> a 10-byte payload needs 20
    assert_eq!(enq(&mut s, &[&mk(9, 10)]), 0, "exactly fills the ring");
    assert_eq!(enq(&mut s, &[b""]), ENOSPC, "ring full");
    let h = head(&s);
    assert_eq!((h.tail.gen_, h.tail.offset), (1, 1064));
    assert_eq!(h.tail.offset, h.front.offset, "full: same offset, gen + 1");
    // remove across the wrap: end marker in the next generation
    assert_eq!(qrem(&mut s, b"1/1044"), 0);
    let h = head(&s);
    assert_eq!((h.front.gen_, h.front.offset), (1, 1044));
    assert!(s.obj(Q).unwrap().data[1064..].iter().all(|x| *x == 0));
    // (past the last live byte the object is truncated, not zero filled)
    assert!(s.obj(Q).unwrap().data[1024..1044].iter().all(|x| *x == 0));
    // invalid end markers
    assert_eq!(qrem(&mut s, b"5/1100"), EINVAL);
    assert_eq!(qrem(&mut s, b"0/1000"), EINVAL);
    assert_eq!(qrem(&mut s, b""), EINVAL, "empty marker parses as 0/0");
}

#[test]
fn batch_filling_exactly_does_not_overwrite_front() {
    // upstream quirk NOT replicated: each entry is checked against the real free space
    let mut s = MemStore::new();
    s.objects.insert(Q.into(), Default::default());
    qinit(&mut s, 80);
    assert_eq!(enq(&mut s, &[&mk(1, 30), &mk(2, 30), &mk(3, 30)]), ENOSPC);
    assert_eq!(enq(&mut s, &[&mk(1, 30), &mk(2, 30)]), 0);
    assert_eq!(
        payloads(&qlist(&mut s, 10, b"", b"")),
        [mk(1, 30), mk(2, 30)]
    );
}

#[test]
fn large_head_read_spans_pages_and_bad_entry_magic() {
    let mut s = MemStore::new();
    s.objects.insert(Q.into(), Default::default());
    // head with a 6000 byte urgent blob (> one 4096 page): max_urgent_data_size makes room
    let op = queue::InitOp {
        queue_size: 1000,
        max_urgent_data_size: 7000,
        bl_urgent_data: vec![7; 6000],
    };
    ok(&mut s, Q, "queue", "queue_init", &e(&op));
    let h = head(&s);
    assert_eq!((h.max_head_size, h.bl_urgent_data.len()), (8024, 6000));
    assert_eq!(enq(&mut s, &[b"abc"]), 0);
    assert_eq!(head(&s).bl_urgent_data, vec![7; 6000]);
    assert_eq!(payloads(&qlist(&mut s, 5, b"", b"")), [b"abc".to_vec()]);
    // corrupt the entry magic
    s.objects.get_mut(Q).unwrap().data[8024] = 0;
    err(
        &mut s,
        Q,
        "queue",
        "queue_list_entries",
        &e(&ListOp {
            max: 5,
            ..Default::default()
        }),
        EINVAL,
    );
}

#[test]
fn queue_garbage_input() {
    let mut s = MemStore::new();
    s.objects.insert(Q.into(), Default::default());
    for m in [
        "queue_init",
        "queue_enqueue",
        "queue_list_entries",
        "queue_remove_entries",
    ] {
        err(&mut s, Q, "queue", m, &[1, 2], EINVAL);
    }
}

// ------------------------------------------------------------------ rgw_gc

fn info(tag: &str, n: usize) -> gc::GcObjInfo {
    gc::GcObjInfo {
        tag: tag.into(),
        chain: gc::GcChain {
            objs: (0..n)
                .map(|i| gc::GcObj {
                    pool: "p".into(),
                    key: ObjKey::new(&format!("{tag}_{i}"), ""),
                    loc: Vec::new(),
                })
                .collect(),
        },
        time: UTime::new(1, 1), // ignored: the OSD sets now + expiration
    }
}
fn ginit(s: &mut MemStore, size: u64) {
    s.objects.entry(G.into()).or_default();
    ok(
        s,
        G,
        "rgw_gc",
        "rgw_gc_queue_init",
        &e(&gc::QueueInitOp {
            size,
            num_deferred_entries: 0,
        }),
    );
}
fn genq(s: &mut MemStore, tag: &str, secs: u32) {
    let op = gc::SetEntryOp {
        expiration_secs: secs,
        info: info(tag, 2),
    };
    ok(s, G, "rgw_gc", "rgw_gc_queue_enqueue", &e(&op));
}
fn glist(s: &mut MemStore, marker: &[u8], max: u32, expired_only: bool) -> gc::ListRet {
    let op = gc::ListOp {
        marker: marker.into(),
        max,
        expired_only,
    };
    d(&ok(s, G, "rgw_gc", "rgw_gc_queue_list_entries", &e(&op)))
}
fn tags(l: &gc::ListRet) -> Vec<String> {
    l.entries
        .iter()
        .map(|x| String::from_utf8_lossy(&x.tag).into_owned())
        .collect()
}

#[test]
fn gc_init_head_has_1k_and_urgent_blob() {
    let mut s = MemStore::new();
    ginit(&mut s, 131071 * 1024);
    let h = head_at(&s, G);
    // 21.2.0: head = 1 KiB + rgw_gc_max_deferred_entries_size (3 KiB)
    assert_eq!(h.max_head_size, 1024 + 3072);
    assert_eq!(h.queue_size, 131071 * 1024 + 1024 + 3072);
    // urgent blob: ENCODE_START(1,1){map{} , 0, 0, 0}
    assert_eq!(h.bl_urgent_data, cat(&[&[1, 1, 16, 0, 0, 0], &[0; 16]]));
    // second init: EEXIST (RGW ignores via the version gate)
    err(
        &mut s,
        G,
        "rgw_gc",
        "rgw_gc_queue_init",
        &e(&gc::QueueInitOp {
            size: 10,
            num_deferred_entries: 0,
        }),
        EEXIST,
    );
}

#[test]
fn gc_enqueue_sets_time_and_lists_expired_only() {
    let mut s = MemStore::new();
    ginit(&mut s, 1 << 20);
    genq(&mut s, "t1", 3600);
    genq(&mut s, "t2", 0);
    genq(&mut s, "t3", 7200);
    let now = s.env.now;
    let all = glist(&mut s, b"", 0, false);
    assert_eq!(tags(&all), ["t1", "t2", "t3"]);
    assert_eq!(all.entries[0].time, UTime::new(now.sec + 3600, now.nsec));
    assert_eq!(
        all.entries[0].chain.objs.len(),
        2,
        "chain survives the round trip"
    );
    assert!(!all.truncated && all.next_marker.is_empty());
    // expired_only keeps only time <= now (but unexpired entries still count toward max)
    let ex = glist(&mut s, b"", 0, true);
    assert_eq!(tags(&ex), ["t2"]);
    s.advance(3601);
    assert_eq!(tags(&glist(&mut s, b"", 0, true)), ["t1", "t2"]);
    // paging
    let p1 = glist(&mut s, b"", 2, false);
    assert_eq!(tags(&p1), ["t1", "t2"]);
    assert!(p1.truncated);
    let p2 = glist(&mut s, &p1.next_marker, 2, false);
    assert_eq!(tags(&p2), ["t3"]);
    assert!(!p2.truncated);
}

#[test]
fn gc_remove_entries_removes_a_prefix() {
    let mut s = MemStore::new();
    ginit(&mut s, 1 << 20);
    for t in ["a", "b", "c", "d", "e"] {
        genq(&mut s, t, 0);
    }
    let rm = |s: &mut MemStore, n: u64| {
        ok(
            s,
            G,
            "rgw_gc",
            "rgw_gc_queue_remove_entries",
            &e(&gc::RemoveEntriesOp { num_entries: n }),
        );
    };
    rm(&mut s, 2);
    assert_eq!(tags(&glist(&mut s, b"", 0, false)), ["c", "d", "e"]);
    // asking for more than present drains everything
    rm(&mut s, 10);
    assert!(glist(&mut s, b"", 0, false).entries.is_empty());
    // removing from an empty queue is fine
    rm(&mut s, 1);
    // the queue keeps working after being drained
    genq(&mut s, "z", 0);
    assert_eq!(tags(&glist(&mut s, b"", 0, false)), ["z"]);
}

#[test]
fn gc_list_absent_or_uninitialized() {
    let mut s = MemStore::new();
    // absent object: ENOENT on an OSD (read-only message rule, before any op); MemStore::call has no pre-check, the empty head read is EINVAL
    let op = gc::ListOp::default();
    err(
        &mut s,
        G,
        "rgw_gc",
        "rgw_gc_queue_list_entries",
        &e(&op),
        EINVAL,
    );
    s.objects.insert(G.into(), Default::default());
    err(
        &mut s,
        G,
        "rgw_gc",
        "rgw_gc_queue_list_entries",
        &e(&op),
        EINVAL,
    );
}

#[test]
fn gc_update_entry_without_deferral_slots_is_enospc() {
    let mut s = MemStore::new();
    ginit(&mut s, 1 << 20);
    genq(&mut s, "t", 0);
    let op = gc::SetEntryOp {
        expiration_secs: 100,
        info: info("t", 1),
    };
    err(
        &mut s,
        G,
        "rgw_gc",
        "rgw_gc_queue_update_entry",
        &e(&op),
        ENOSPC,
    );
    // with deferral slots and head urgent size 0 (the dev tree) the tag goes to the xattr map
    let mut s = MemStore::new();
    s.env.config.rgw_gc_max_deferred_entries_size = 0;
    s.objects.insert(G.into(), Default::default());
    ok(
        &mut s,
        G,
        "rgw_gc",
        "rgw_gc_queue_init",
        &e(&gc::QueueInitOp {
            size: 1 << 20,
            num_deferred_entries: 2,
        }),
    );
    genq(&mut s, "t", 0);
    ok(&mut s, G, "rgw_gc", "rgw_gc_queue_update_entry", &e(&op));
    let x = &s.obj(G).unwrap().xattrs["cls_queue_urgent_data".as_bytes()];
    let m: std::collections::BTreeMap<String, UTime> = d(x);
    assert_eq!(m["t"].sec, s.env.now.sec + 100);
    // the old queue entry is now superseded: list hides it
    s.advance(1);
    assert!(glist(&mut s, b"", 0, false).entries.is_empty());
}

// ------------------------------------------------------------------ hostile stored / input state

/// Raw head bytes as classic writes them (`0xDEAD`, u64 len, encoded head).
fn raw_head(h: &queue::Head) -> Vec<u8> {
    let body = e(h);
    cat(&[&0xDEADu16.to_le_bytes(), &u64b(body.len() as u64), &body])
}

#[test]
fn hostile_sizes_and_corrupt_lengths_never_panic_or_overallocate() {
    // init with sizes that overflow u64: wraps (classic), no panic
    let mut s = MemStore::new();
    s.objects.insert(Q.into(), Default::default());
    let op = queue::InitOp {
        queue_size: u64::MAX,
        max_urgent_data_size: u64::MAX - 100,
        bl_urgent_data: vec![],
    };
    let _ = call(&mut s, Q, "queue", "queue_init", &e(&op));
    let _ = call(&mut s, Q, "queue", "queue_get_capacity", &[]);
    let _ = enq(&mut s, &[b"x"]);
    let _ = call(
        &mut s,
        Q,
        "queue",
        "queue_list_entries",
        &e(&ListOp {
            max: 10,
            ..Default::default()
        }),
    );
    let _ = qrem(&mut s, b"18446744073709551615/18446744073709551615");

    // client-written head: tail far ahead of front and an entry claiming 256 GiB. Must fail
    // EINVAL (short read) instead of preallocating the claimed length.
    let mut s = MemStore::new();
    let h = queue::Head {
        max_head_size: 1024,
        front: queue::Marker {
            gen_: 0,
            offset: 1024,
        },
        tail: queue::Marker {
            gen_: 1 << 40,
            offset: 1024,
        },
        queue_size: (1 << 20) + 1024,
        max_urgent_data_size: 0,
        bl_urgent_data: vec![],
    };
    let mut data = raw_head(&h);
    data.resize(1024, 0);
    data.extend_from_slice(&0xBEEFu16.to_le_bytes());
    data.extend_from_slice(&u64b(1 << 38));
    data.extend_from_slice(b"tiny");
    s.objects.entry(Q.into()).or_default().data = data;
    let r = call(
        &mut s,
        Q,
        "queue",
        "queue_list_entries",
        &e(&ListOp {
            max: 10,
            ..Default::default()
        }),
    );
    assert_eq!(r.ret, EINVAL);

    // front at u64::MAX gen and offset past queue_size: remove must not overflow
    let mut h2 = h.clone();
    h2.front = queue::Marker {
        gen_: u64::MAX,
        offset: u64::MAX,
    };
    s.objects.get_mut(Q).unwrap().data = raw_head(&h2);
    let _ = qrem(&mut s, b"0/1024");
    let _ = qrem(&mut s, b"0/18446744073709551615");
}

#[test]
fn gc_hostile_urgent_counters_wrap_like_classic() {
    // urgent data planted through class `queue` (arbitrary bl_urgent_data): counters at u32::MAX
    let mut s = MemStore::new();
    s.objects.insert(G.into(), Default::default());
    let urgent = gc::UrgentData {
        num_head_urgent_entries: u32::MAX,
        num_xattr_urgent_entries: 0,
        num_urgent_data_entries: 0,
        ..Default::default()
    };
    let op = queue::InitOp {
        queue_size: 1 << 16,
        max_urgent_data_size: 0,
        bl_urgent_data: e(&urgent),
    };
    ok(&mut s, G, "queue", "queue_init", &e(&op));
    let up = gc::SetEntryOp {
        expiration_secs: 1,
        info: info("t", 1),
    };
    // head +1 wraps to 0, spill: head -1 -> MAX, xattr +1 -> 1; MAX + 1 wraps to 0 <= 0 -> ok
    ok(&mut s, G, "rgw_gc", "rgw_gc_queue_update_entry", &e(&up));
    let h = head_at(&s, G);
    let u: gc::UrgentData = d(&h.bl_urgent_data);
    assert_eq!(
        (u.num_head_urgent_entries, u.num_xattr_urgent_entries),
        (u32::MAX, 1)
    );
    // remove with a count at the wrap edge
    let _ = call(
        &mut s,
        G,
        "rgw_gc",
        "rgw_gc_queue_remove_entries",
        &e(&gc::RemoveEntriesOp {
            num_entries: u64::MAX,
        }),
    );
}

#[test]
fn gc_update_entry_fits_in_the_head_with_the_21_1_2_urgent_size() {
    let mut s = MemStore::new();
    s.objects.insert(G.into(), Default::default());
    ok(
        &mut s,
        G,
        "rgw_gc",
        "rgw_gc_queue_init",
        &e(&gc::QueueInitOp {
            size: 1 << 20,
            num_deferred_entries: 2,
        }),
    );
    genq(&mut s, "t", 0);
    let op = gc::SetEntryOp {
        expiration_secs: 100,
        info: info("t", 1),
    };
    ok(&mut s, G, "rgw_gc", "rgw_gc_queue_update_entry", &e(&op));
    // the deferral lives in the head, no xattr map
    assert!(
        !s.obj(G)
            .unwrap()
            .xattrs
            .contains_key("cls_queue_urgent_data".as_bytes())
    );
}

/// `list` over many entries, across read-ahead refills, an entry larger than the first window and
/// the ring wrap; paging, end marker and a corrupt frame behind `max` give the per-entry results.
#[test]
fn list_many_entries_across_refills_and_wrap() {
    let mut s = MemStore::new();
    s.objects.insert(Q.into(), Default::default());
    qinit(&mut s, 1024 + (1 << 20)); // 1 MiB ring
    let sizes = |base: usize, n: usize| (0..n).map(move |i| base + (i * 997) % 9000);
    let mut model: Vec<Vec<u8>> = sizes(100, 60)
        .enumerate()
        .map(|(i, n)| mk(i as u8, n))
        .collect();
    model.insert(7, mk(0xAA, 200 << 10)); // larger than the first 64 KiB window
    for x in &model {
        assert_eq!(enq(&mut s, &[x]), 0);
    }
    let all = qlist(&mut s, 1000, b"", b"");
    assert_eq!(payloads(&all), model);
    assert!(!all.is_truncated);
    // drop the first 40 entries, then wrap with more
    assert_eq!(qrem(&mut s, &all.entries[40].marker), 0);
    model.drain(..40);
    for (i, n) in sizes(3000, 400).enumerate() {
        let x = mk(0x80 | i as u8, n);
        if enq(&mut s, &[&x]) != 0 {
            break;
        }
        model.push(x);
    }
    assert_eq!(head(&s).tail.gen_, 1, "ring wrapped");
    let all = qlist(&mut s, 1000, b"", b"");
    assert_eq!(payloads(&all), model);
    assert_eq!(all.next_marker, head(&s).tail.to_bytes());
    // pages of 3 give the same entries and markers
    let (mut got, mut start) = (Vec::new(), Vec::new());
    loop {
        let p = qlist(&mut s, 3, &start, b"");
        got.extend(p.entries.iter().map(|x| (x.marker.clone(), x.data.clone())));
        if !p.is_truncated {
            break;
        }
        start = p.next_marker;
    }
    let want: Vec<_> = all
        .entries
        .iter()
        .map(|x| (x.marker.clone(), x.data.clone()))
        .collect();
    assert_eq!(got, want);
    // end marker stops before that entry
    let l = qlist(&mut s, 1000, b"", &all.entries[25].marker);
    assert_eq!(payloads(&l), model[..25]);
    assert_eq!(l.next_marker, all.entries[25].marker);
    assert!(l.is_truncated);
    // corrupt frame 30: listing up to it works, listing over it is EINVAL
    let off = queue::Marker::parse(&all.entries[30].marker).offset as usize;
    s.objects.get_mut(Q).unwrap().data[off] ^= 0xFF;
    let l = qlist(&mut s, 30, b"", b"");
    assert_eq!(payloads(&l), model[..30]);
    let op = ListOp {
        max: 1000,
        start_marker: vec![],
        end_marker: vec![],
    };
    assert_eq!(
        call(&mut s, Q, "queue", "queue_list_entries", &e(&op)).ret,
        EINVAL
    );
}
