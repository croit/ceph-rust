// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Helper ownership conversion must preserve main's multipart/late-kill publication semantics.
use store::obj::keys::omap_key;
use store::runs::{Compaction, Hit, RunBuilder, RunSet};

fn add(s: &mut RunSet, lsn: u64, keys: &[u8]) {
    let mut b = RunBuilder::default();
    for k in keys {
        b.push(&omap_key(1, &[*k]), &[], &[0], &[*k]);
    }
    s.insert(lsn, b.finish(1).unwrap());
}

fn complete(c: &mut Compaction, helper: bool) {
    while !c.step(1) {}
    if helper {
        c.finish_output();
        assert!(c.built());
        // A duplicate completion/step cannot rebuild or overwrite sealed output.
        c.finish_output();
        assert!(c.step(1));
    }
}

fn keys(s: &RunSet) -> Vec<u8> {
    s.scan(&omap_key(1, b""), &omap_key(2, b""))
        .map(|(k, _)| *k.last().unwrap())
        .collect()
}

#[test]
fn sealed_multipart_result_tracks_current_records_and_remaps_removed_parts() {
    for helper in [false, true] {
        for remove_part in [false, true] {
            let mut s = RunSet::default();
            add(&mut s, 1, b"ab");
            add(&mut s, 2, b"cd");
            let mut first = s.compaction(1, 2, 16, 0, &[]).unwrap();
            complete(&mut first, helper);
            assert!(s.swap_in(first));
            add(&mut s, 3, b"ef");
            let mut c = s.compaction(1, 2, 2, 0, &[]).unwrap();
            complete(&mut c, helper);
            // A re-log of a multipart input updates the current part record, not the snapshot.
            let relog = s.relog_range(1, 1);
            assert_eq!(relog.len(), 1);
            s.insert(10, relog[0].clone());
            if remove_part {
                s.kill(&omap_key(1, b"c"));
                s.kill(&omap_key(1, b"d"));
            } else {
                s.kill(&omap_key(1, b"c"));
            }
            assert!(s.swap_in(c));
            assert_eq!(
                keys(&s),
                if remove_part {
                    b"abef".to_vec()
                } else {
                    b"abdef".to_vec()
                }
            );
            assert_eq!(s.floor(), Some(if remove_part { 3 } else { 2 }));
            s.kill(&omap_key(1, b"d")); // already dead in the remap case: no double unlink
            s.kill(&omap_key(1, b"e"));
            s.kill(&omap_key(1, b"f"));
            assert_eq!(
                s.floor(),
                Some(10),
                "must retain the current, re-logged record"
            );
            assert_eq!(keys(&s), b"ab");
            s.kill(&omap_key(1, b"a"));
            s.kill(&omap_key(1, b"b"));
            assert_eq!(s.floor(), None);
            assert_eq!((s.mem(), s.entries(), s.n_runs()), (0, 0, 0));
        }
    }
}

#[test]
fn partial_helper_decline_continues_inline_and_plain_relog_rejects_sealed_result() {
    let mut s = RunSet::default();
    add(&mut s, 1, b"abcd");
    add(&mut s, 2, b"cdef");
    let mut c = s.compaction(1, 2, 16, 0, &[]).unwrap();
    assert!(!c.step(1));
    c.keep_inline();
    assert!(!c.helper_allowed());
    s.kill(&omap_key(1, b"b"));
    complete(&mut c, false);
    assert!(!c.built());
    assert!(s.swap_in(c));
    assert_eq!(keys(&s), b"acdef");
    assert_eq!(s.get(&omap_key(1, b"c")), Hit::Live(b"\0c"));

    // Separate plain runs: a re-log replaces the buffer and invalidates the helper snapshot.
    let mut s = RunSet::default();
    add(&mut s, 1, b"ab");
    add(&mut s, 2, b"cd");
    let mut c = s.compaction(1, 2, 16, 0, &[]).unwrap();
    complete(&mut c, true);
    let relog = s.relog_range(1, 1);
    s.insert(10, relog[0].clone());
    assert!(!s.swap_in(c));
    assert_eq!(keys(&s), b"abcd");
    assert_eq!(s.floor(), Some(2));
}
