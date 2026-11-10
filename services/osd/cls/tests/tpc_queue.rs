// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! 2pc_queue scenarios (spec/cls_2pc_queue.md) on MemStore.
mod common;
use cls::errno::*;
use cls::mem::MemStore;
use cls::queue::{self, ListOp, ListRet};
use cls::tpc_queue::*;
use common::*;
use denc::types::UTime;

const Q: &str = "q";

fn init(s: &mut MemStore, size: u64) -> i32 {
    let op = queue::InitOp {
        queue_size: size,
        max_urgent_data_size: 1, // ignored by 2pc init
        bl_urgent_data: vec![9],
    };
    call(s, Q, "2pc_queue", "2pc_queue_init", &e(&op)).ret
}
fn reserve(s: &mut MemStore, size: u64, entries: u32) -> cls::Reply {
    call(
        s,
        Q,
        "2pc_queue",
        "2pc_queue_reserve",
        &e(&ReserveOp { size, entries }),
    )
}
fn rid(r: &cls::Reply) -> u32 {
    assert_eq!(r.ret, 0);
    d::<ReserveRet>(&r.out).id
}
fn commit(s: &mut MemStore, id: u32, items: &[&[u8]]) -> i32 {
    let op = CommitOp {
        id,
        bl_data_vec: items.iter().map(|x| x.to_vec()).collect(),
    };
    call(s, Q, "2pc_queue", "2pc_queue_commit", &e(&op)).ret
}
fn abort(s: &mut MemStore, id: u32) -> i32 {
    call(s, Q, "2pc_queue", "2pc_queue_abort", &e(&AbortOp { id })).ret
}
fn resv(s: &mut MemStore) -> Reservations {
    d::<ReservationsRet>(&ok(s, Q, "2pc_queue", "2pc_queue_list_reservations", &[])).reservations
}
fn stats(s: &mut MemStore) -> StatsRet {
    d(&ok(s, Q, "2pc_queue", "2pc_queue_get_topic_stats", &[]))
}
fn list(s: &mut MemStore) -> ListRet {
    let op = ListOp {
        max: 0,
        start_marker: vec![],
        end_marker: vec![],
    };
    d(&ok(s, Q, "2pc_queue", "2pc_queue_list_entries", &e(&op)))
}
fn remove(s: &mut MemStore, marker: &[u8], n: u32) -> i32 {
    let op = RemoveOp {
        end_marker: marker.to_vec(),
        entries_to_remove: n,
    };
    call(s, Q, "2pc_queue", "2pc_queue_remove_entries", &e(&op)).ret
}
fn expire(s: &mut MemStore, t: UTime) -> i32 {
    call(
        s,
        Q,
        "2pc_queue",
        "2pc_queue_expire_reservations",
        &e(&ExpireOp { stale_time: t }),
    )
    .ret
}
/// Head + urgent data as stored.
fn state(s: &mut MemStore) -> (queue::Head, Urgent) {
    let (r, h) = s.msg(Q, |c| match queue::read_head(c) {
        Ok(h) => (0, Some(h)),
        Err(e) => (e, None),
    });
    assert_eq!(r, 0);
    let h = h.unwrap();
    let u = d(&h.bl_urgent_data);
    (h, u)
}
fn put_state(s: &mut MemStore, mut h: queue::Head, u: &Urgent) {
    h.bl_urgent_data = e(u);
    let (r, _) = s.msg(Q, |c| (queue::write_head(c, &h).err().unwrap_or(0), ()));
    assert_eq!(r, 0);
}

#[test]
fn registry() {
    use cls::registry::*;
    assert_eq!(methods("2pc_queue").len(), 10);
    for (m, f) in [
        ("2pc_queue_init", RW),
        ("2pc_queue_get_capacity", RD),
        ("2pc_queue_get_topic_stats", RD),
        ("2pc_queue_reserve", RW),
        ("2pc_queue_commit", RW),
        ("2pc_queue_abort", RW),
        ("2pc_queue_list_reservations", RD),
        ("2pc_queue_list_entries", RD),
        ("2pc_queue_remove_entries", RW),
        ("2pc_queue_expire_reservations", RW),
    ] {
        assert_eq!(lookup("2pc_queue", m).unwrap().flags, f, "{m}");
    }
}

#[test]
fn init_head_and_exact_urgent_bytes() {
    let mut s = MemStore::new();
    assert_eq!(init(&mut s, 5000), 0);
    assert_eq!(init(&mut s, 5000), EEXIST);
    let (h, _) = state(&mut s);
    assert_eq!(h.max_head_size, 1024 + 23552);
    assert_eq!(h.max_urgent_data_size, 23552);
    assert_eq!(h.queue_size, 5000 + 1024 + 23552);
    // (3,1,len=21) reserved_size u64, last_id u32, map count u32, has_xattrs, committed u32
    let mut want = vec![3, 1, 21, 0, 0, 0];
    want.extend([0u8; 21]);
    assert_eq!(h.bl_urgent_data, want);
    let cap: queue::GetCapacityRet = d(&ok(&mut s, Q, "2pc_queue", "2pc_queue_get_capacity", &[]));
    assert_eq!(cap.queue_capacity, 5000);
}

#[test]
fn reservation_wire_bytes() {
    let r = Reservation {
        size: 7,
        timestamp: UTime::new(9, 8),
        entries: 3,
    };
    assert_eq!(
        e(&r),
        cat(&[
            &[2, 1, 20, 0, 0, 0],
            &u64b(7),
            &9u32.to_le_bytes(),
            &8u32.to_le_bytes(),
            &3u32.to_le_bytes()
        ])
    );
    // v1 reservation has no entries field
    let v1 = cat(&[
        &[1, 1, 16, 0, 0, 0],
        &u64b(7),
        &9u32.to_le_bytes(),
        &8u32.to_le_bytes(),
    ]);
    assert_eq!(d::<Reservation>(&v1), Reservation { entries: 0, ..r });
    // remove op v1 / v2
    assert_eq!(
        d::<RemoveOp>(&[1, 1, 5, 0, 0, 0, 1, 0, 0, 0, b'x']).entries_to_remove,
        0
    );
}

#[test]
fn reserve_commit_lifecycle() {
    let mut s = MemStore::new();
    init(&mut s, 100_000);
    let id = rid(&reserve(&mut s, 100, 2));
    assert_eq!(id, 1);
    let (_, u) = state(&mut s);
    assert_eq!(u.reserved_size, 100 + 2 * 10);
    assert_eq!(u.last_id, 1);
    let r = &resv(&mut s)[&1];
    assert_eq!((r.size, r.entries, r.timestamp), (100, 2, s.env.now));
    assert_eq!(rid(&reserve(&mut s, 10, 1)), 2);

    assert_eq!(commit(&mut s, 1, &[&[b'a'; 60], &[b'b'; 30]]), 0);
    let (_, u) = state(&mut s);
    assert_eq!(u.reserved_size, 10 + 10);
    assert_eq!(u.committed_entries, 2);
    assert!(!u.reservations.contains_key(&1));
    let l = list(&mut s);
    assert_eq!(l.entries.len(), 2);
    assert_eq!(l.entries[0].data, vec![b'a'; 60]);
    let st = stats(&mut s);
    assert_eq!((st.queue_size, st.queue_entries), (60 + 30 + 20, 2));
    // second commit of the same id
    assert_eq!(commit(&mut s, 1, &[]), ENOENT);
    // a commit may use fewer bytes/entries than reserved; committed counts RESERVED entries
    assert_eq!(commit(&mut s, 2, &[]), 0);
    assert_eq!(state(&mut s).1.committed_entries, 3);
    assert_eq!(state(&mut s).1.reserved_size, 0);
}

#[test]
fn commit_checks() {
    let mut s = MemStore::new();
    init(&mut s, 100_000);
    let id = rid(&reserve(&mut s, 10, 1));
    assert_eq!(
        commit(&mut s, id, &[&[0; 11]]),
        EINVAL,
        "payload larger than reserved"
    );
    assert_eq!(
        commit(&mut s, id, &[&[0; 6], &[0; 5]]),
        EINVAL,
        "sum counts"
    );
    assert_eq!(commit(&mut s, 99, &[]), ENOENT);
    assert_eq!(
        state(&mut s).1.reservations.len(),
        1,
        "failures change nothing"
    );
}

#[test]
fn abort_semantics() {
    let mut s = MemStore::new();
    init(&mut s, 100_000);
    assert_eq!(abort(&mut s, 5), 0, "unknown id is a no-op");
    let a = rid(&reserve(&mut s, 10, 1));
    let b = rid(&reserve(&mut s, 20, 2));
    assert_eq!(abort(&mut s, a), 0);
    let (_, u) = state(&mut s);
    assert_eq!(u.reserved_size, 20 + 20);
    assert_eq!(u.reservations.keys().copied().collect::<Vec<_>>(), vec![b]);
    assert_eq!(abort(&mut s, a), 0);
    assert_eq!(state(&mut s).1.reserved_size, 40);
}

#[test]
fn reserve_limits() {
    let mut s = MemStore::new();
    init(&mut s, 1000);
    assert_eq!(reserve(&mut s, 0, 1).ret, EINVAL);
    assert_eq!(reserve(&mut s, 5, 0).ret, EINVAL);
    assert_eq!(reserve(&mut s, 991, 1).ret, ENOSPC, "991 + 10 > 1000");
    assert_eq!(
        reserve(&mut s, u64::MAX, 1).ret,
        ENOSPC,
        "no overflow panic"
    );
    assert_eq!(rid(&reserve(&mut s, 990, 1)), 1);
    assert_eq!(reserve(&mut s, 1, 1).ret, ENOSPC);
    assert_eq!(abort(&mut s, 1), 0);
    assert_eq!(rid(&reserve(&mut s, 1, 1)), 2, "last_id keeps counting");
}

#[test]
fn reserve_id_clash_is_eagain() {
    let mut s = MemStore::new();
    init(&mut s, 100_000);
    let (h, mut u) = state(&mut s);
    u.last_id = 4;
    u.reservations.insert(
        5,
        Reservation {
            size: 1,
            timestamp: s.env.now,
            entries: 1,
        },
    );
    u.reserved_size = 11;
    put_state(&mut s, h, &u);
    let before = s.objects.clone();
    assert_eq!(reserve(&mut s, 5, 1).ret, EAGAIN);
    assert_eq!(s.objects, before);
}

#[test]
fn spill_to_xattr_and_back() {
    let mut s = MemStore::new();
    init(&mut s, 10_000_000);
    let n = 850u32;
    for i in 1..=n {
        assert_eq!(rid(&reserve(&mut s, 1, 1)), i);
    }
    let (h, u) = state(&mut s);
    assert!(
        u.has_xattrs,
        "urgent data exceeded {}",
        h.max_urgent_data_size
    );
    assert!(u.reservations.len() < n as usize);
    assert!(h.bl_urgent_data.len() as u64 <= h.max_urgent_data_size);
    assert_eq!(u.reserved_size, n as u64 * 11);
    let spilled = n - u.reservations.len() as u32;
    let spill_attr: Reservations = d(&s.obj(Q).unwrap().xattrs[URGENT_XATTR.as_bytes()]);
    assert_eq!(spill_attr.len() as u32, spilled);
    assert!(spill_attr.contains_key(&n), "newest id was spilled");
    assert_eq!(resv(&mut s).len() as u32, n);

    // commit a spilled id, abort another, commit a head id
    assert_eq!(commit(&mut s, n, &[b"x"]), 0);
    assert_eq!(abort(&mut s, n - 1), 0);
    assert_eq!(commit(&mut s, 1, &[b"y"]), 0);
    let (_, u) = state(&mut s);
    assert_eq!(u.reserved_size, (n as u64 - 3) * 11);
    assert_eq!(u.committed_entries, 2);
    let all = resv(&mut s);
    assert_eq!(all.len() as u32, n - 3);
    assert!(!all.contains_key(&n) && !all.contains_key(&(n - 1)) && !all.contains_key(&1));
    assert_eq!(commit(&mut s, n, &[]), ENOENT);
    assert_eq!(list(&mut s).entries.len(), 2);

    // expire everything (head and spilled)
    let future = UTime::new(s.env.now.sec + 10, 0);
    assert_eq!(expire(&mut s, future), 0);
    let (_, u) = state(&mut s);
    assert_eq!(u.reserved_size, 0);
    assert!(u.reservations.is_empty());
    assert!(resv(&mut s).is_empty());
    let spill_attr: Reservations = d(&s.obj(Q).unwrap().xattrs[URGENT_XATTR.as_bytes()]);
    assert!(spill_attr.is_empty());
}

#[test]
fn legacy_urgent_recomputes_reserved_size() {
    let mut s = MemStore::new();
    init(&mut s, 100_000);
    let (h, _) = state(&mut s);
    // hand-made struct_v 2 urgent data (no trailing fields beyond committed_entries): drifted counter
    let res = e(&Reservation {
        size: 40,
        timestamp: UTime::new(5, 0),
        entries: 2,
    });
    let body = cat(&[
        &u64b(999_999),
        &7u32.to_le_bytes(),
        &1u32.to_le_bytes(),
        &7u32.to_le_bytes(),
        &res,
        &[0],
        &3u32.to_le_bytes(),
    ]);
    let v2 = cat(&[&[2, 1], &(body.len() as u32).to_le_bytes(), &body]);
    let mut h2 = h.clone();
    h2.bl_urgent_data = v2;
    let (r, _) = s.msg(Q, |c| (queue::write_head(c, &h2).err().unwrap_or(0), ()));
    assert_eq!(r, 0);
    assert_eq!(rid(&reserve(&mut s, 5, 1)), 8);
    let (_, u) = state(&mut s);
    assert_eq!(u.decoded_v, 3, "rewritten as v3");
    assert_eq!(
        u.reserved_size,
        (40 + 20) + (5 + 10),
        "rebuilt from the reservations"
    );
    assert_eq!(u.committed_entries, 3);
}

#[test]
fn expire_only_stale() {
    let mut s = MemStore::new();
    init(&mut s, 100_000);
    let t0 = s.env.now;
    rid(&reserve(&mut s, 10, 1));
    s.advance(100);
    rid(&reserve(&mut s, 20, 1));
    let before = s.objects.clone();
    assert_eq!(expire(&mut s, t0), 0, "timestamp < stale_time is strict");
    assert_eq!(s.objects, before, "nothing stale: nothing written");
    assert_eq!(expire(&mut s, UTime::new(t0.sec + 50, 0)), 0);
    let all = resv(&mut s);
    assert_eq!(all.keys().copied().collect::<Vec<_>>(), vec![2]);
    assert_eq!(state(&mut s).1.reserved_size, 30);
}

#[test]
fn remove_entries_counts() {
    let mut s = MemStore::new();
    init(&mut s, 100_000);
    for i in 0..4u8 {
        let id = rid(&reserve(&mut s, 5, 1));
        assert_eq!(commit(&mut s, id, &[&[i; 5]]), 0);
    }
    let l = list(&mut s);
    assert_eq!(l.entries.len(), 4);
    assert_eq!(state(&mut s).1.committed_entries, 4);
    // explicit count
    assert_eq!(remove(&mut s, &l.entries[2].marker, 2), 0);
    assert_eq!(state(&mut s).1.committed_entries, 2);
    assert_eq!(list(&mut s).entries.len(), 2);
    // legacy sender: entries_to_remove 0 -> counted from the marker
    let l = list(&mut s);
    assert_eq!(remove(&mut s, &l.entries[1].marker, 0), 0);
    assert_eq!(state(&mut s).1.committed_entries, 1);
    assert_eq!(list(&mut s).entries.len(), 1);
    assert_eq!(remove(&mut s, b"7/99999999999", 1), EINVAL, "bad marker");
    assert_eq!(state(&mut s).1.committed_entries, 1);
}

#[test]
fn ring_wraparound_keeps_accounting() {
    let mut s = MemStore::new();
    init(&mut s, 300);
    for round in 0..30u8 {
        let id = rid(&reserve(&mut s, 50, 1));
        assert_eq!(commit(&mut s, id, &[&[round; 50]]), 0, "round {round}");
        let l = list(&mut s);
        assert_eq!(l.entries.len(), 1);
        assert_eq!(l.entries[0].data, vec![round; 50]);
        let tail = String::from_utf8(state(&mut s).0.tail.to_bytes()).unwrap();
        assert_eq!(remove(&mut s, tail.as_bytes(), 1), 0);
        let (_, u) = state(&mut s);
        assert_eq!((u.reserved_size, u.committed_entries), (0, 0));
    }
    assert!(state(&mut s).0.front.gen_ >= 3, "wrapped several times");
}

#[test]
fn garbage_and_unprepared() {
    let mut s = MemStore::new();
    for m in [
        "2pc_queue_init",
        "2pc_queue_reserve",
        "2pc_queue_commit",
        "2pc_queue_abort",
        "2pc_queue_list_entries",
        "2pc_queue_remove_entries",
        "2pc_queue_expire_reservations",
    ] {
        err(&mut s, Q, "2pc_queue", m, &[1], EINVAL);
    }
    // no head yet: every head-reading method answers -EINVAL
    for m in [
        "2pc_queue_get_capacity",
        "2pc_queue_get_topic_stats",
        "2pc_queue_list_reservations",
    ] {
        err(&mut s, Q, "2pc_queue", m, &[], EINVAL);
    }
    assert_eq!(reserve(&mut s, 1, 1).ret, EINVAL);
    // plain cls_queue head (urgent blob is not 2pc data) -> -EINVAL
    let op = queue::InitOp {
        queue_size: 1000,
        max_urgent_data_size: 100,
        bl_urgent_data: vec![1, 2, 3],
    };
    ok(&mut s, "plain", "queue", "queue_init", &e(&op));
    err(
        &mut s,
        "plain",
        "2pc_queue",
        "2pc_queue_list_reservations",
        &[],
        EINVAL,
    );
}

/// Entry framing is computed in 32 bits like classic (u32 count x unsigned constant): 429496730 entries = 4 bytes
/// of overhead, so the reservation fits and the persisted reserved_size is 1 + 4.
#[test]
fn reserve_entry_overhead_wraps_in_32_bits() {
    let mut s = MemStore::new();
    assert_eq!(init(&mut s, 64 * 1024), 0);
    let id = rid(&reserve(&mut s, 1, 429_496_730));
    assert_eq!(state(&mut s).1.reserved_size, 5);
    assert_eq!(abort(&mut s, id), 0);
    assert_eq!(state(&mut s).1.reserved_size, 0);
}
