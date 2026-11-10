// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! cls_journal scenarios (spec/cls_journal.md s6) on MemCtx.
mod common;
use cls::errno::*;
use cls::journal::*;
use cls::mem::MemStore;
use common::*;

const O: &str = "journal.id1";

fn s(v: &str) -> String {
    v.to_owned()
}
fn pos(v: &[(u64, u64, u64)]) -> ObjectSetPosition {
    ObjectSetPosition {
        object_positions: v
            .iter()
            .map(|&(object_number, tag_tid, entry_tid)| ObjectPosition {
                object_number,
                tag_tid,
                entry_tid,
            })
            .collect(),
    }
}
fn create(st: &mut MemStore, splay: u8) {
    ok(st, O, "journal", "create", &e(&(24u8, splay, 7i64)));
}
fn register(st: &mut MemStore, id: &str) {
    ok(
        st,
        O,
        "journal",
        "client_register",
        &e(&(s(id), vec![9u8, 9])),
    );
}
fn commit(st: &mut MemStore, id: &str, p: &ObjectSetPosition) {
    ok(st, O, "journal", "client_commit", &e(&(s(id), p.clone())));
}
fn get_client(st: &mut MemStore, id: &str) -> Client {
    d(&ok(st, O, "journal", "get_client", &e(&s(id))))
}
fn tag_create(st: &mut MemStore, tid: u64, class: u64) -> Reply {
    st.call(O, "journal", "tag_create", &e(&(tid, class, vec![1u8, 2])))
}
use cls::registry::Reply;
fn tag_list(st: &mut MemStore, after: u64, max: u64, client: &str, class: Option<u64>) -> Vec<u64> {
    let out = ok(
        st,
        O,
        "journal",
        "tag_list",
        &e(&(after, max, s(client), class)),
    );
    let mut dd = denc::Decoder::new(&out);
    let n = dd.count().unwrap();
    (0..n)
        .map(|_| denc::Decode::decode(&mut dd).map(|t: Tag| t.tid).unwrap())
        .collect()
}
fn u64_of(st: &mut MemStore, m: &str) -> u64 {
    d(&ok(st, O, "journal", m, &[]))
}

#[test]
fn registry_flags() {
    use cls::registry::*;
    assert_eq!(methods("journal").len(), 21);
    for m in methods("journal") {
        let rd_only = m.name.starts_with("get_") || m.name.ends_with("_list");
        assert_eq!(m.flags, if rd_only { RD } else { RD | WR }, "{}", m.name);
    }
    assert!(lookup("journal", "nope").is_none());
}

#[test]
fn create_and_getters() {
    let mut st = MemStore::new();
    err(&mut st, O, "journal", "get_order", &[], ENOENT);
    create(&mut st, 4);
    err(
        &mut st,
        O,
        "journal",
        "create",
        &e(&(1u8, 1u8, 1i64)),
        EEXIST,
    );
    assert_eq!(ok(&mut st, O, "journal", "get_order", &[]), vec![24]);
    assert_eq!(ok(&mut st, O, "journal", "get_splay_width", &[]), vec![4]);
    assert_eq!(
        ok(&mut st, O, "journal", "get_pool_id", &[]),
        7i64.to_le_bytes()
    );
    assert_eq!(u64_of(&mut st, "get_minimum_set"), 0);
    assert_eq!(u64_of(&mut st, "get_active_set"), 0);
    assert_eq!(u64_of(&mut st, "get_next_tag_tid"), 0);
    // stored layout: raw ints under fixed keys
    assert_eq!(st.omap_get(O, "order"), Some(&[24u8][..]));
    assert_eq!(st.omap_get(O, "pool_id"), Some(&7i64.to_le_bytes()[..]));
    assert_eq!(st.omap_get(O, "next_tag_class"), Some(&[0u8; 8][..]));
    // short input
    err(&mut st, O, "journal", "create", &[1, 2], EINVAL);
}

#[test]
fn set_rules() {
    let mut st = MemStore::new();
    err(&mut st, O, "journal", "set_active_set", &e(&1u64), ENOENT);
    create(&mut st, 2);
    // minimum may not pass active
    err(&mut st, O, "journal", "set_minimum_set", &e(&1u64), EINVAL);
    ok(&mut st, O, "journal", "set_active_set", &e(&5u64));
    ok(&mut st, O, "journal", "set_active_set", &e(&5u64)); // no-op
    err(&mut st, O, "journal", "set_active_set", &e(&4u64), ESTALE);
    ok(&mut st, O, "journal", "set_minimum_set", &e(&3u64));
    ok(&mut st, O, "journal", "set_minimum_set", &e(&3u64));
    err(&mut st, O, "journal", "set_minimum_set", &e(&2u64), ESTALE);
    // active may not go below minimum: 3 > 2 is ESTALE-order after EINVAL check (min > set -> EINVAL)
    err(&mut st, O, "journal", "set_active_set", &e(&2u64), EINVAL);
    assert_eq!(u64_of(&mut st, "get_minimum_set"), 3);
    assert_eq!(u64_of(&mut st, "get_active_set"), 5);
    err(&mut st, O, "journal", "set_active_set", &[1, 2], EINVAL);
}

#[test]
fn client_golden_bytes() {
    let mut st = MemStore::new();
    create(&mut st, 2);
    ok(
        &mut st,
        O,
        "journal",
        "client_register",
        &e(&(s("a"), Vec::<u8>::new())),
    );
    let want: Vec<u8> = vec![
        1, 1, 20, 0, 0, 0, // Client envelope
        1, 0, 0, 0, b'a', // id
        0, 0, 0, 0, // data
        1, 1, 4, 0, 0, 0, 0, 0, 0, 0, // ObjectSetPosition envelope, 0 positions
        0, // state
    ];
    assert_eq!(st.omap_get(O, "client_a"), Some(&want[..]));
    assert_eq!(ok(&mut st, O, "journal", "get_client", &e(&s("a"))), want);
}

#[test]
fn clients() {
    let mut st = MemStore::new();
    err(
        &mut st,
        O,
        "journal",
        "client_register",
        &e(&(s("a"), Vec::<u8>::new())),
        ENOENT,
    );
    create(&mut st, 2);
    register(&mut st, "b");
    register(&mut st, "a");
    register(&mut st, "c");
    err(
        &mut st,
        O,
        "journal",
        "client_register",
        &e(&(s("a"), Vec::<u8>::new())),
        EEXIST,
    );
    err(&mut st, O, "journal", "get_client", &e(&s("zz")), ENOENT);
    // list: ascending, paged
    let list = |st: &mut MemStore, after: &str, max: u64| -> Vec<Vec<u8>> {
        let out = ok(st, O, "journal", "client_list", &e(&(s(after), max)));
        let mut dd = denc::Decoder::new(&out);
        let n = dd.count().unwrap();
        (0..n)
            .map(|_| denc::Decode::decode(&mut dd).map(|c: Client| c.id).unwrap())
            .collect()
    };
    assert_eq!(
        list(&mut st, "", 10),
        vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]
    );
    assert_eq!(list(&mut st, "", 2), vec![b"a".to_vec(), b"b".to_vec()]);
    assert_eq!(list(&mut st, "b", 10), vec![b"c".to_vec()]);
    assert!(list(&mut st, "c", 10).is_empty());
    assert!(list(&mut st, "", 0).is_empty());
    // update data / state
    ok(
        &mut st,
        O,
        "journal",
        "client_update_data",
        &e(&(s("a"), vec![5u8])),
    );
    assert_eq!(get_client(&mut st, "a").data, vec![5]);
    ok(
        &mut st,
        O,
        "journal",
        "client_update_state",
        &e(&(s("a"), 1u8)),
    );
    assert_eq!(get_client(&mut st, "a").state, 1);
    ok(
        &mut st,
        O,
        "journal",
        "client_update_state",
        &e(&(s("a"), 77u8)),
    );
    assert_eq!(get_client(&mut st, "a").state, 77);
    err(
        &mut st,
        O,
        "journal",
        "client_update_state",
        &e(&(s("q"), 1u8)),
        ENOENT,
    );
    err(
        &mut st,
        O,
        "journal",
        "client_update_data",
        &e(&(s("q"), vec![1u8])),
        ENOENT,
    );
    // commit
    commit(&mut st, "b", &pos(&[(1, 2, 3), (0, 2, 2)]));
    assert_eq!(
        get_client(&mut st, "b").commit_position,
        pos(&[(1, 2, 3), (0, 2, 2)])
    );
    commit(&mut st, "b", &pos(&[(1, 2, 3), (0, 2, 2)])); // no-op
    err(
        &mut st,
        O,
        "journal",
        "client_commit",
        &e(&(s("b"), pos(&[(0, 0, 0), (1, 0, 0), (2, 0, 0)]))),
        EINVAL,
    );
    err(
        &mut st,
        O,
        "journal",
        "client_commit",
        &e(&(s("q"), pos(&[]))),
        ENOENT,
    );
    // unregister
    ok(&mut st, O, "journal", "client_unregister", &e(&s("b")));
    err(
        &mut st,
        O,
        "journal",
        "client_unregister",
        &e(&s("b")),
        ENOENT,
    );
    err(&mut st, O, "journal", "get_client", &e(&s("b")), ENOENT);
}

#[test]
fn register_inherits_min_commit() {
    let mut st = MemStore::new();
    create(&mut st, 4);
    register(&mut st, "a");
    register(&mut st, "b");
    register(&mut st, "d");
    commit(&mut st, "a", &pos(&[(3, 5, 10)]));
    commit(&mut st, "b", &pos(&[(1, 4, 99)]));
    // d stays empty -> a new client gets the empty position
    register(&mut st, "e");
    assert_eq!(get_client(&mut st, "e").commit_position, pos(&[]));
    // disconnected clients are ignored: d (empty) disconnected -> min of a,b,e(empty).. e is empty too
    ok(
        &mut st,
        O,
        "journal",
        "client_update_state",
        &e(&(s("d"), 1u8)),
    );
    ok(
        &mut st,
        O,
        "journal",
        "client_update_state",
        &e(&(s("e"), 1u8)),
    );
    register(&mut st, "f");
    assert_eq!(get_client(&mut st, "f").commit_position, pos(&[(1, 4, 99)]));
    // same tag_tid: lower entry_tid wins
    commit(&mut st, "a", &pos(&[(3, 4, 50)]));
    register(&mut st, "g");
    assert_eq!(get_client(&mut st, "g").commit_position, pos(&[(3, 4, 50)]));
}

#[test]
fn many_clients_paging() {
    let mut st = MemStore::new();
    create(&mut st, 2);
    for i in 0..300 {
        register(&mut st, &format!("c{i:04}"));
    }
    // all disconnected but the last (batch 2): its commit is the minimum
    for i in 0..299 {
        ok(
            &mut st,
            O,
            "journal",
            "client_update_state",
            &e(&(format!("c{i:04}"), 1u8)),
        );
    }
    commit(&mut st, "c0299", &pos(&[(0, 8, 8)]));
    register(&mut st, "new");
    assert_eq!(
        get_client(&mut st, "new").commit_position,
        pos(&[(0, 8, 8)])
    );
    // full listing is capped by the omap request cap, pageable via start_after
    let out = ok(
        &mut st,
        O,
        "journal",
        "client_list",
        &e(&(s("c0255"), 1000u64)),
    );
    let mut dd = denc::Decoder::new(&out);
    assert_eq!(dd.count().unwrap(), 45); // c0256..c0299 + new... "new" sorts after "c*"
}

#[test]
fn tags_create_and_class() {
    let mut st = MemStore::new();
    err(
        &mut st,
        O,
        "journal",
        "tag_create",
        &e(&(0u64, 0u64, Vec::<u8>::new())),
        ENOENT,
    );
    create(&mut st, 2);
    assert_eq!(tag_create(&mut st, 1, TAG_CLASS_NEW).ret, ESTALE); // out of order
    assert_eq!(tag_create(&mut st, 0, 5).ret, EINVAL); // class not yet allocated
    assert_eq!(tag_create(&mut st, 0, TAG_CLASS_NEW).ret, 0);
    assert_eq!(tag_create(&mut st, 0, TAG_CLASS_NEW).ret, EEXIST);
    assert_eq!(tag_create(&mut st, 1, 0).ret, 0); // existing class
    assert_eq!(tag_create(&mut st, 2, TAG_CLASS_NEW).ret, 0); // class 1
    assert_eq!(u64_of(&mut st, "get_next_tag_tid"), 3);
    assert_eq!(
        st.omap_get(O, "next_tag_class"),
        Some(&2u64.to_le_bytes()[..])
    );
    let t: Tag = d(&ok(&mut st, O, "journal", "get_tag", &e(&2u64)));
    assert_eq!((t.tid, t.tag_class, t.data), (2, 1, vec![1, 2]));
    assert!(st.omap_get(O, "tag_0000000000000002").is_some());
    err(&mut st, O, "journal", "get_tag", &e(&9u64), ENOENT);
}

#[test]
fn tag_list_hides_superseded() {
    let mut st = MemStore::new();
    create(&mut st, 2);
    register(&mut st, "e");
    register(&mut st, "f");
    commit(&mut st, "f", &pos(&[(0, 0, 1)])); // pins everything from tid 0
    commit(&mut st, "e", &pos(&[(0, 2, 1)]));
    for tid in 0..3 {
        assert_eq!(
            tag_create(&mut st, tid, if tid == 0 { TAG_CLASS_NEW } else { 0 }).ret,
            0
        );
    }
    assert_eq!(tag_create(&mut st, 3, TAG_CLASS_NEW).ret, 0); // class 1
    // f sees all, e sees tags >= 2 of class 0 plus class 1
    assert_eq!(tag_list(&mut st, 0, 100, "f", None), vec![0, 1, 2, 3]);
    assert_eq!(tag_list(&mut st, 0, 100, "e", None), vec![2, 3]);
    assert_eq!(tag_list(&mut st, 0, 100, "f", Some(1)), vec![3]);
    assert_eq!(tag_list(&mut st, 0, 100, "f", Some(0)), vec![0, 1, 2]);
    assert_eq!(tag_list(&mut st, 1, 100, "f", None), vec![2, 3]);
    assert_eq!(tag_list(&mut st, 0, 2, "f", None), vec![0, 1]);
    assert_eq!(tag_list(&mut st, 0, 1, "e", None), vec![2]);
    // client without positions: everything
    register(&mut st, "g");
    // (g registered with min commit = f's/e's min = (0,0,1))
    commit(&mut st, "g", &pos(&[]));
    assert_eq!(tag_list(&mut st, 0, 100, "g", None), vec![0, 1, 2, 3]);
    err(
        &mut st,
        O,
        "journal",
        "tag_list",
        &e(&(0u64, 1u64, s("nope"), None::<u64>)),
        ENOENT,
    );
    // nothing was removed
    assert!(st.omap_get(O, "tag_0000000000000000").is_some());
}

#[test]
fn expire_tags_on_create_and_unregister() {
    let mut st = MemStore::new();
    create(&mut st, 2);
    register(&mut st, "c");
    for tid in 0..4 {
        assert_eq!(
            tag_create(&mut st, tid, if tid == 0 { TAG_CLASS_NEW } else { 0 }).ret,
            0
        );
    }
    // c has no commit yet -> nothing expired
    for tid in 0..4 {
        assert!(st.omap_get(O, &format!("tag_{tid:016x}")).is_some());
    }
    commit(&mut st, "c", &pos(&[(0, 2, 5)]));
    assert_eq!(tag_create(&mut st, 4, 0).ret, 0);
    // tags below the newest tag <= commit (tid 2) of class 0 are gone: 0,1
    assert!(st.omap_get(O, "tag_0000000000000000").is_none());
    assert!(st.omap_get(O, "tag_0000000000000001").is_none());
    for tid in 2..5 {
        assert!(st.omap_get(O, &format!("tag_{tid:016x}")).is_some());
    }
    // second client with commit at tid 4; c unregisters -> min = 4 -> tags 2,3 expire
    register(&mut st, "x");
    commit(&mut st, "x", &pos(&[(0, 4, 0)]));
    ok(&mut st, O, "journal", "client_unregister", &e(&s("c")));
    assert!(st.omap_get(O, "tag_0000000000000002").is_none());
    assert!(st.omap_get(O, "tag_0000000000000003").is_none());
    assert!(st.omap_get(O, "tag_0000000000000004").is_some());
    // disconnected client does not hold tags back
    register(&mut st, "y");
    ok(
        &mut st,
        O,
        "journal",
        "client_update_state",
        &e(&(s("y"), 1u8)),
    );
    assert_eq!(tag_create(&mut st, 5, 0).ret, 0);
    assert_eq!(tag_list(&mut st, 0, 10, "x", None), vec![4, 5]);
}

fn append(st: &mut MemStore, oid: &str, max: u64, data: &[u8]) -> i32 {
    st.call(oid, "journal", "append", &e(&(max, data.to_vec())))
        .ret
}
fn guard(st: &mut MemStore, oid: &str, max: u64) -> i32 {
    st.call(oid, "journal", "guard_append", &e(&max)).ret
}

#[test]
fn append_and_guard() {
    let mut st = MemStore::new();
    st.env.config.journal_pad = true;
    let o = "journal_data.7.id1.0";
    assert_eq!(guard(&mut st, o, 10), 0); // absent object passes
    assert_eq!(guard(&mut st, o, 0), 0);
    assert_eq!(append(&mut st, o, 100_000, b"hello"), 0);
    // padded to the 4096 allocation unit
    assert_eq!(st.obj(o).unwrap().data.len(), 4096);
    assert_eq!(&st.obj(o).unwrap().data[..5], b"hello");
    assert!(st.obj(o).unwrap().data[5..].iter().all(|b| *b == 0));
    // next append lands after the padding
    assert_eq!(append(&mut st, o, 100_000, &[7u8; 4096]), 0);
    let dt = &st.obj(o).unwrap().data;
    assert_eq!(dt.len(), 8192);
    assert_eq!(dt[4096], 7);
    // exact multiple: no padding growth
    assert_eq!(append(&mut st, o, 100_000, &[1u8; 4096]), 0);
    assert_eq!(st.obj(o).unwrap().data.len(), 12288);
    // full
    assert_eq!(append(&mut st, o, 12288, b"x"), EOVERFLOW);
    assert_eq!(guard(&mut st, o, 12288), EOVERFLOW);
    assert_eq!(guard(&mut st, o, 12289), 0);
    assert_eq!(st.obj(o).unwrap().data.len(), 12288);
    // stripe width: align = round_up(4096, 6000) = 6000
    st.env.config.pool_stripe_width = 6000;
    let o2 = "journal_data.7.id1.1";
    assert_eq!(append(&mut st, o2, 1 << 20, b"abc"), 0);
    assert_eq!(st.obj(o2).unwrap().data.len(), 6000);
    // alloc 0 -> 8
    st.env.config.pool_stripe_width = 0;
    st.env.config.journal_min_alloc = 0;
    let o3 = "journal_data.7.id1.2";
    assert_eq!(append(&mut st, o3, 1 << 20, b"abc"), 0);
    assert_eq!(st.obj(o3).unwrap().data.len(), 8);
    // default (min_compat_client < octopus): no padding
    st.env.config.journal_pad = false;
    let o4 = "journal_data.7.id1.3";
    assert_eq!(append(&mut st, o4, 1 << 20, b"abc"), 0);
    assert_eq!(st.obj(o4).unwrap().data.len(), 3);
    // bad input
    assert_eq!(st.call(o3, "journal", "append", &[1]).ret, EINVAL);
    assert_eq!(st.call(o3, "journal", "guard_append", &[]).ret, EINVAL);
}

#[test]
fn corrupt_stored_values() {
    let mut st = MemStore::new();
    create(&mut st, 2);
    register(&mut st, "a");
    register(&mut st, "b");
    st.objects
        .get_mut(O)
        .unwrap()
        .omap
        .insert(b"order".to_vec(), vec![]);
    err(&mut st, O, "journal", "get_order", &[], EINVAL);
    st.objects
        .get_mut(O)
        .unwrap()
        .omap
        .insert(b"client_a".to_vec(), vec![1, 2, 3]);
    err(&mut st, O, "journal", "get_client", &e(&s("a")), EINVAL);
    err(
        &mut st,
        O,
        "journal",
        "client_list",
        &e(&(s(""), 5u64)),
        EIO,
    );
    err(&mut st, O, "journal", "client_unregister", &e(&s("b")), EIO);
    // a tag whose key disagrees with its tid trips expire (EINVAL) once a commit exists
    let mut st = MemStore::new();
    create(&mut st, 2);
    register(&mut st, "a");
    commit(&mut st, "a", &pos(&[(0, 1, 1)]));
    assert_eq!(tag_create(&mut st, 0, TAG_CLASS_NEW).ret, 0);
    let bad = e(&Tag {
        tid: 99,
        tag_class: 0,
        data: vec![],
    });
    st.objects
        .get_mut(O)
        .unwrap()
        .omap
        .insert(b"tag_0000000000000005".to_vec(), bad);
    assert_eq!(tag_create(&mut st, 1, 0).ret, EINVAL);
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

#[test]
fn random_inputs_never_panic() {
    let mut rng = Rng(0xfeed_beef_1234_5671);
    let mut base = MemStore::new();
    create(&mut base, 3);
    for c in ["a", "b"] {
        register(&mut base, c);
    }
    commit(&mut base, "a", &pos(&[(0, 1, 1)]));
    for tid in 0..4 {
        tag_create(&mut base, tid, TAG_CLASS_NEW);
    }
    append(&mut base, "journal_data.7.id1.0", 1 << 20, b"data");
    let mut objs = base.objects.clone();
    // corrupted variant: every omap value truncated
    for o in objs.values_mut() {
        for v in o.omap.values_mut() {
            v.truncate(v.len() / 2);
        }
    }
    let variants = [MemStore::new().objects, base.objects.clone(), objs];
    for m in cls::methods("journal") {
        for round in 0..80 {
            let n = (rng.next() % 64) as usize;
            let input = if round % 2 == 0 {
                // plausible: u64/string-ish prefix with small numbers
                let mut v = Vec::new();
                for _ in 0..(rng.next() % 4) {
                    v.extend((rng.next() % 5).to_le_bytes());
                }
                v.extend(rng.bytes(n % 16));
                v
            } else {
                rng.bytes(n)
            };
            for vars in &variants {
                let mut st = MemStore::new();
                st.objects = vars.clone();
                for oid in [O, "journal_data.7.id1.0"] {
                    let before = st.objects.clone();
                    let r = st.call(oid, "journal", m.name, &input);
                    if r.ret < 0 {
                        assert_eq!(
                            st.objects, before,
                            "journal.{}: failed call changed state",
                            m.name
                        );
                    }
                }
            }
        }
    }
}
