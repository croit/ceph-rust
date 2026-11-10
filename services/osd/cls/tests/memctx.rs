// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! MemCtx semantics = the objclass surface contract (cls.md s3, s4): message-start view, counters,
//! flag enforcement, omap caps.
use cls::ClsCtx;
use cls::errno::*;
use cls::mem::MemStore;

const O: &str = "o";

fn touch(s: &mut MemStore) {
    s.msg(O, |c| (c.create(false).map_or(-1, |_| 0), ()));
}

#[test]
fn content_reads_see_message_start_existence_and_size_follow_the_message() {
    let mut s = MemStore::new();
    s.msg(O, |c| {
        c.write_full(b"old").unwrap();
        c.setxattr("k", b"v1").unwrap();
        c.omap_set(&[(b"a", b"1")]).unwrap();
        (0, ())
    });
    let (ret, _) = s.msg(O, |c| {
        c.setxattr("k", b"v2").unwrap();
        assert_eq!(c.getxattr("k").unwrap(), b"v1", "xattr: old value");
        c.omap_set(&[(b"a", b"2"), (b"b", b"3")]).unwrap();
        assert_eq!(c.omap_get_val(b"a").unwrap(), b"1");
        assert_eq!(c.omap_get_val(b"b"), Err(ENOENT));
        c.write_full(b"newnewnew").unwrap();
        assert_eq!(c.stat().unwrap().size, 9, "stat follows the message");
        assert_eq!(
            c.read(0, 0).unwrap(),
            b"old",
            "read: store bytes, clipped to new size"
        );
        c.remove().unwrap();
        assert_eq!(c.stat(), Err(ENOENT));
        assert_eq!(
            c.getxattr("k").unwrap(),
            b"v1",
            "content still the committed one after delete"
        );
        assert_eq!(c.create(true), Ok(()), "exclusive create after delete");
        (0, ())
    });
    assert_eq!(ret, 0);
    // delete + re-create emptied the object
    let o = s.obj(O).unwrap();
    assert!(o.xattrs.is_empty() && o.omap.is_empty() && o.data.is_empty());
}

#[test]
fn read_after_delete_clips_to_working_size_and_serves_committed_bytes() {
    let mut s = MemStore::new();
    s.msg(O, |c| {
        c.write_full(b"committed").unwrap();
        (0, ())
    });
    // delete in one message: size 0, reads return no bytes, never the committed ones
    let (ret, _) = s.msg(O, |c| {
        c.remove().unwrap();
        assert!(!c.exists());
        for (off, len) in [(0, 0), (0, 4), (2, 10)] {
            assert_eq!(
                c.read(off, len).unwrap(),
                Vec::<u8>::new(),
                "read({off},{len})"
            );
        }
        (EINVAL, ()) // abort: nothing committed
    });
    assert_eq!(ret, EINVAL);
    // committed bytes are untouched: a later message reads them back
    s.msg(O, |c| {
        assert_eq!(c.read(0, 0).unwrap(), b"committed");
        (0, ())
    });
    // delete then re-create in one message: existence/size follow the message, bytes are the
    // committed ones clipped to the working size (cls.md s4 read visibility)
    s.msg(O, |c| {
        c.remove().unwrap();
        c.write_full(b"new").unwrap();
        assert_eq!(c.read(0, 0).unwrap(), b"com");
        assert_eq!(c.read(1, 0).unwrap(), b"om");
        (0, ())
    });
    assert_eq!(s.obj(O).unwrap().data, b"new");
}

#[test]
fn absent_object_errnos() {
    let mut s = MemStore::new();
    s.msg(O, |c| {
        assert_eq!(c.stat(), Err(ENOENT));
        // recorded on classic 21.1.1: a write-class method (queue_init) reads 0 bytes of a new object; read-only messages never reach
        // an op on an absent object (ENOENT before any op)
        assert_eq!(c.read(0, 0), Ok(vec![]));
        assert_eq!(c.getxattr("x"), Err(ENOENT));
        assert_eq!(c.getxattrs_raw(), Err(ENOENT));
        assert_eq!(c.omap_get_val(b"x"), Err(ENOENT));
        assert_eq!(
            c.omap_get_vals(b"", b"", 10),
            Ok((Default::default(), false))
        );
        assert_eq!(c.omap_get_header(), Ok(vec![]));
        assert_eq!(c.omap_remove_key(b"x"), Err(ENOENT));
        assert_eq!(c.omap_clear(), Err(ENOENT));
        assert_eq!(c.remove(), Err(ENOENT));
        assert_eq!(c.snapset_seq(), Err(ENOENT));
        // touch-on-write: setxattr creates it, but reads still see the (absent) store
        c.setxattr("x", b"y").unwrap();
        assert_eq!(c.stat().unwrap().size, 0);
        assert_eq!(c.getxattr("x"), Err(ENOENT));
        (-1, ()) // abort: nothing committed
    });
    assert!(s.obj(O).is_none());
}

#[test]
fn omap_listing_caps_and_more() {
    let mut s = MemStore::new();
    s.msg(O, |c| {
        let kv: Vec<(Vec<u8>, Vec<u8>)> = (0..2500u32)
            .map(|i| (format!("k{i:05}").into_bytes(), vec![1]))
            .collect();
        let e: Vec<(&[u8], &[u8])> = kv
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
            .collect();
        c.omap_set(&e).unwrap();
        (0, ())
    });
    s.msg(O, |c| {
        let (m, more) = c.omap_get_vals(b"", b"", u64::MAX).unwrap();
        assert_eq!(
            (m.len(), more),
            (1024, true),
            "capped at osd_max_omap_entries_per_request"
        );
        let (m, more) = c.omap_get_vals(b"k02400", b"", 1000).unwrap();
        assert_eq!((m.len(), more), (99, false));
        let (k, more) = c.omap_get_keys(b"k00010", 3).unwrap();
        assert_eq!(
            (k, more),
            (
                vec![b"k00011".to_vec(), b"k00012".to_vec(), b"k00013".to_vec()],
                true
            )
        );
        let (m, _) = c.omap_get_vals(b"", b"k0001", 100).unwrap();
        assert_eq!(m.len(), 10, "prefix filter");
        (0, ())
    });
}

#[test]
fn flag_enforcement_and_counters() {
    let mut s = MemStore::new();
    touch(&mut s);
    // a write inside an RD-only method (expired ephemeral lock in get_info) is EIO
    let mut c = s.begin(O);
    let r = c.call("lock", "get_info", &[]);
    assert_eq!(r.ret, EINVAL, "decode error");
    assert_eq!(
        (c.nread, c.nwrite),
        (0, 0),
        "decode failure touches nothing"
    );
    // stat does not count; list_locks reads; set_cookie on a missing lock reads (RW method)
    let mut c = s.begin(O);
    c.stat().unwrap();
    assert_eq!((c.nread, c.nwrite), (0, 0));
    c.getxattrs_raw().unwrap();
    c.setxattr("a", b"b").unwrap();
    assert_eq!((c.nread, c.nwrite), (1, 1));
    // unknown class / method
    let r = c.call("nope", "x", &[]);
    assert_eq!(r.ret, EOPNOTSUPP);
    let r = c.call("rbd", "no_such_method", &[]);
    assert_eq!(r.ret, EOPNOTSUPP);
}

#[test]
fn registry_listing() {
    assert_eq!(
        cls::CLASSES,
        [
            "lock",
            "rbd",
            "version",
            "refcount",
            "rgw",
            "queue",
            "rgw_gc",
            "user",
            "log",
            "timeindex",
            "fifo",
            "journal",
            "hello",
            "sdk",
            "numops",
            "cmpomap",
            "sem_set",
            "cas",
            "otp",
            "cephfs",
            "2pc_queue"
        ]
    );
    assert!(cls::methods("rbd").len() >= 65);
    // names unique per class, flags never zero
    for class in cls::CLASSES {
        let ms = cls::methods(class);
        let mut names: Vec<_> = ms.iter().map(|m| m.name).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), ms.len());
        assert!(ms.iter().all(|m| m.flags & (cls::RD | cls::WR) != 0));
    }
}

#[test]
fn raw_xattrs_keep_binary_identity_counters_message_start_and_rollback() {
    let mut s = MemStore::new();
    let key = b"lock.\xff\0x";
    s.msg(O, |c| {
        assert_eq!(c.getxattr_raw(key), Err(ENOENT));
        assert_eq!(c.getxattrs_raw(), Err(ENOENT));
        c.setxattr_raw(key, b"first").unwrap();
        assert_eq!(c.getxattr_raw(key), Err(ENOENT));
        assert_eq!((c.nread, c.nwrite), (3, 1));
        (0, ())
    });
    let (result, _) = s.msg(O, |c| {
        c.setxattr_raw(key, b"second").unwrap();
        assert_eq!(c.getxattr_raw(key).unwrap(), b"first");
        assert_eq!(c.getxattr_raw(b"lock.\xff"), Err(ENODATA));
        let all = c.getxattrs_raw().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[key.as_slice()], b"first");
        assert_eq!((c.nread, c.nwrite), (3, 1));
        (EINVAL, ())
    });
    assert_eq!(result, EINVAL);
    assert_eq!(s.obj(O).unwrap().xattrs[key.as_slice()], b"first");
}

#[test]
fn omap_scan_pages_prefix_max_and_break() {
    use cls::ctx::{SCAN_PAGE, omap_scan};
    use std::ops::ControlFlow::{Break, Continue};
    let n = SCAN_PAGE as usize * 2 + 7;
    let keys: Vec<Vec<u8>> = (0..n).map(|i| format!("p_{i:06}").into_bytes()).collect();
    s_scan(
        |c| {
            let kv: Vec<(&[u8], &[u8])> = keys.iter().map(|k| (k.as_slice(), &b"v"[..])).collect();
            c.omap_set(&kv).unwrap();
            c.omap_set(&[(b"a", b"x"), (b"q", b"y")]).unwrap();
        },
        |c| {
            // full scan across pages: exactly the prefixed keys, ascending, `more` = false
            let mut seen = Vec::new();
            let more = omap_scan(c, b"p_", b"p_", u64::MAX, |_, k, _| {
                seen.push(k);
                Ok(Continue(()))
            })
            .unwrap();
            assert_eq!((seen.as_slice(), more), (keys.as_slice(), false));
            // max across a page boundary: truncated, `more` = true
            let mut seen = Vec::new();
            let more = omap_scan(c, &keys[10], b"p_", SCAN_PAGE + 5, |_, k, _| {
                seen.push(k);
                Ok(Continue(()))
            })
            .unwrap();
            assert_eq!(
                (seen.as_slice(), more),
                (&keys[11..11 + SCAN_PAGE as usize + 5], true)
            );
            // max reached exactly at the end: `more` = false
            let more = omap_scan(c, &keys[n - 4], b"p_", 3, |_, _, _| Ok(Continue(()))).unwrap();
            assert!(!more);
            // break stops at once
            let mut cnt = 0;
            let more = omap_scan(c, b"", b"", u64::MAX, |_, _, _| {
                cnt += 1;
                Ok(if cnt == 3 { Break(()) } else { Continue(()) })
            })
            .unwrap();
            assert_eq!((cnt, more), (3, true));
            // max 0 reads nothing
            assert!(omap_scan(c, b"", b"", 0, |_, _, _| unreachable!()).unwrap());
        },
    );
}

#[test]
fn write_and_truncate_are_bounded_by_the_object_size_limit() {
    let mut s = MemStore::new();
    s.env.max_object_size = 4096;
    let (ret, _) = s.msg(O, |c| {
        // offset arithmetic: no overflow panic, the client range is rejected like the executor (EFBIG)
        assert_eq!(c.write(u64::MAX - 2, b"abc"), Err(EFBIG));
        assert_eq!(c.write(4094, b"abc"), Err(EFBIG), "end beyond the limit");
        assert_eq!(c.write(4093, b"abc"), Ok(()), "end at the limit is fine");
        assert_eq!(c.stat().unwrap().size, 4096);
        assert_eq!(c.truncate(u64::MAX), Err(EFBIG));
        assert_eq!(
            c.truncate(4096),
            Err(EFBIG),
            "a size at the limit is rejected"
        );
        assert_eq!(c.truncate(4095), Ok(()));
        (0, ())
    });
    assert_eq!(ret, 0);
    assert_eq!(s.obj(O).unwrap().data.len(), 4095);
}

fn s_scan(setup: impl FnOnce(&mut cls::mem::MemCtx), check: impl FnOnce(&mut cls::mem::MemCtx)) {
    let mut s = MemStore::new();
    s.msg(O, |c| {
        setup(c);
        (0, ())
    });
    s.msg(O, |c| {
        check(c);
        (0, ())
    });
}
