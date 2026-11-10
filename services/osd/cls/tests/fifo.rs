// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! cls fifo (spec/cls_fifo.md). No dencoder oracle exists for fifo types: wire vectors are
//! assembled by hand below from the documented layouts (independent of the crate's encoders).
mod common;
use cls::errno::*;
use cls::fifo::*;
use cls::mem::{MemStore, Obj};
use common::*;
use denc::types::UTime;

// ------------------------------------------------ hand-assembled wire pieces
fn env_(v: u8, c: u8, body: &[u8]) -> Vec<u8> {
    let mut o = vec![v, c];
    o.extend((body.len() as u32).to_le_bytes());
    o.extend(body);
    o
}
fn s(x: &str) -> Vec<u8> {
    let mut o = (x.len() as u32).to_le_bytes().to_vec();
    o.extend(x.as_bytes());
    o
}
fn bl(x: &[u8]) -> Vec<u8> {
    let mut o = (x.len() as u32).to_le_bytes().to_vec();
    o.extend(x);
    o
}
fn objv(inst: &str, ver: u64) -> Vec<u8> {
    env_(1, 1, &cat(&[&s(inst), &ver.to_le_bytes()]))
}
fn params(a: u64, b: u64, c: u64) -> Vec<u8> {
    env_(
        1,
        1,
        &cat(&[&a.to_le_bytes(), &b.to_le_bytes(), &c.to_le_bytes()]),
    )
}
fn opt(x: Option<Vec<u8>>) -> Vec<u8> {
    match x {
        None => vec![0],
        Some(v) => [vec![1], v].concat(),
    }
}
fn jentry(op: i32, num: i64) -> Vec<u8> {
    env_(1, 1, &cat(&[&op.to_le_bytes(), &num.to_le_bytes(), &s("")]))
}
fn jvec(v: &[(i32, i64)]) -> Vec<u8> {
    let mut o = (v.len() as u32).to_le_bytes().to_vec();
    for (a, b) in v {
        o.extend(jentry(*a, *b));
    }
    o
}
fn u64o(v: Option<u64>) -> Vec<u8> {
    opt(v.map(|x| x.to_le_bytes().to_vec()))
}
fn create_op(
    id: &str,
    ver: Option<(&str, u64)>,
    prefix: Option<&str>,
    mps: u64,
    mes: u64,
    excl: bool,
) -> Vec<u8> {
    env_(
        1,
        1,
        &cat(&[
            &s(id),
            &opt(ver.map(|(i, v)| objv(i, v))),
            &s("pool"),
            &s("ns"),
            &opt(prefix.map(s)),
            &mps.to_le_bytes(),
            &mes.to_le_bytes(),
            &[excl as u8],
        ]),
    )
}
fn get_meta_op(v: Option<(&str, u64)>) -> Vec<u8> {
    env_(1, 1, &opt(v.map(|(i, v)| objv(i, v))))
}
fn update_op(
    v: (&str, u64),
    tail: Option<u64>,
    head: Option<u64>,
    minp: Option<u64>,
    maxp: Option<u64>,
    add: &[(i32, i64)],
    rm: &[(i32, i64)],
) -> Vec<u8> {
    env_(
        1,
        1,
        &cat(&[
            &objv(v.0, v.1),
            &u64o(tail),
            &u64o(head),
            &u64o(minp),
            &u64o(maxp),
            &jvec(add),
            &jvec(rm),
        ]),
    )
}
fn init_op(p: Vec<u8>) -> Vec<u8> {
    env_(1, 1, &cat(&[&s(""), &p]))
}
fn push_op(bufs: &[&[u8]]) -> Vec<u8> {
    let total: u64 = bufs.iter().map(|b| b.len() as u64).sum();
    let mut b = s("");
    b.extend((bufs.len() as u32).to_le_bytes());
    for x in bufs {
        b.extend(bl(x));
    }
    b.extend(total.to_le_bytes());
    env_(1, 1, &b)
}
fn trim_op(ofs: u64, excl: bool) -> Vec<u8> {
    env_(1, 1, &cat(&[&[0], &ofs.to_le_bytes(), &[excl as u8]]))
}
fn list_op(ofs: u64, max: i32) -> Vec<u8> {
    env_(1, 1, &cat(&[&[0], &ofs.to_le_bytes(), &max.to_le_bytes()]))
}
fn info_bytes(
    id: &str,
    v: (&str, u64),
    prefix: &str,
    p: (u64, u64, u64),
    nums: [i64; 4],
    journal: &[(i32, i64)],
) -> Vec<u8> {
    let mut b = cat(&[&s(id), &objv(v.0, v.1), &s(prefix), &params(p.0, p.1, p.2)]);
    for n in nums {
        b.extend(n.to_le_bytes());
    }
    b.extend(0u32.to_le_bytes()); // tags
    b.extend(s("")); // head_tag
    b.extend((journal.len() as u32).to_le_bytes());
    for (o, n) in journal {
        b.extend(n.to_le_bytes());
        b.extend(jentry(*o, *n));
    }
    env_(1, 1, &b)
}

const M: &str = "fifo.meta";
const P: &str = "fifo.part";
const NOW: UTime = UTime::new(1_800_000_000, 5000);

fn mk() -> MemStore {
    let mut s = MemStore::new();
    s.env.now = NOW;
    s
}
fn create(s: &mut MemStore) {
    ok(
        s,
        M,
        "fifo",
        "create_meta",
        &create_op("fifo", Some(("inst", 1)), Some("pre"), 1000, 100, false),
    );
}
fn init(s: &mut MemStore) -> u64 {
    ok(s, P, "fifo", "init_part", &init_op(params(1000, 100, 842)));
    part_header(s).magic
}
fn part_header(s: &mut MemStore) -> PartHeader {
    let out = ok(s, P, "fifo", "get_part_info", &env_(1, 1, &[]));
    d::<GetPartInfoReply>(&out).header
}
fn push(s: &mut MemStore, bufs: &[&[u8]]) -> i32 {
    call(s, P, "fifo", "push_part", &push_op(bufs)).ret
}
fn list(s: &mut MemStore, ofs: u64, max: i32) -> ListPartReply {
    d(&ok(s, P, "fifo", "part_list", &list_op(ofs, max)))
}
/// Part with 5 ten-byte entries at ofs 512,580,648,716,784 (full: next_ofs 852 > 842).
fn full_part(s: &mut MemStore) {
    init(s);
    let bufs: Vec<Vec<u8>> = (0..8).map(|i| vec![b'a' + i; 10]).collect();
    let refs: Vec<&[u8]> = bufs.iter().map(Vec::as_slice).collect();
    assert_eq!(push(s, &refs), 5);
}

// ------------------------------------------------ tests

#[test]
fn flags_and_names() {
    use cls::{RD, RW};
    for (m, f) in [
        ("create_meta", RW),
        ("get_meta", RD),
        ("update_meta", RW),
        ("init_part", RW),
        ("push_part", RW),
        ("trim_part", RW),
        ("part_list", RD),
        ("get_part_info", RD),
    ] {
        assert_eq!(cls::lookup("fifo", m).unwrap().flags, f, "{m}");
    }
    assert_eq!(cls::methods("fifo").len(), 8);
    assert!(cls::lookup("fifo", "list_part").is_none());
}

#[test]
fn meta_wire_vector_and_threshold() {
    let mut s = mk();
    create(&mut s);
    // threshold = 1000 - 100 - 58 = 842; defaults tail 0, head -1, min_push 0, max_push -1
    let want = info_bytes(
        "fifo",
        ("inst", 1),
        "pre",
        (1000, 100, 842),
        [0, -1, 0, -1],
        &[],
    );
    assert_eq!(s.obj(M).unwrap().data, want);
    // fixed length: 6 env + (4+4) id + objv (6+8+4+4=22... checked via bytes) - just pin the total
    assert_eq!(want.len(), 6 + 8 + 22 + 7 + 30 + 32 + 4 + 4 + 4);
    // get_meta reply: info + 512 + 58
    let out = ok(
        &mut s,
        M,
        "fifo",
        "get_meta",
        &get_meta_op(Some(("inst", 1))),
    );
    let r: GetMetaReply = d(&out);
    assert_eq!(r.part_header_size, 512);
    assert_eq!(r.part_entry_overhead, 58);
    assert_eq!(
        out,
        env_(
            1,
            1,
            &cat(&[&want, &512u32.to_le_bytes(), &58u32.to_le_bytes()])
        )
    );
}

#[test]
fn create_meta_variants() {
    let mut s = mk();
    // random version/prefix when absent
    ok(
        &mut s,
        M,
        "fifo",
        "create_meta",
        &create_op("myid", None, None, 4096, 512, false),
    );
    let i: Info = d(&s.obj(M).unwrap().data);
    assert_eq!(i.version.ver, 1);
    assert_eq!(i.version.instance.len(), 16);
    assert!(i.oid_prefix.starts_with(b"myid."));
    assert_eq!(i.oid_prefix.len(), "myid.".len() + 11);
    // idempotent: same id, any (absent) optional
    ok(
        &mut s,
        M,
        "fifo",
        "create_meta",
        &create_op("myid", None, None, 1, 1, false),
    );
    ok(
        &mut s,
        M,
        "fifo",
        "create_meta",
        &create_op(
            "myid",
            Some((txt(&i.version.instance), 1)),
            Some(txt(&i.oid_prefix)),
            9,
            9,
            false,
        ),
    );
    // mismatches
    err(
        &mut s,
        M,
        "fifo",
        "create_meta",
        &create_op("other", None, None, 4, 4, false),
        EEXIST,
    );
    err(
        &mut s,
        M,
        "fifo",
        "create_meta",
        &create_op("myid", None, Some("x"), 4, 4, false),
        EEXIST,
    );
    err(
        &mut s,
        M,
        "fifo",
        "create_meta",
        &create_op("myid", Some(("zz", 1)), None, 4, 4, false),
        EEXIST,
    );
    err(
        &mut s,
        M,
        "fifo",
        "create_meta",
        &create_op(
            "myid",
            Some((txt(&i.version.instance), 2)),
            None,
            4,
            4,
            false,
        ),
        EEXIST,
    );
    // exclusive on existing
    err(
        &mut s,
        M,
        "fifo",
        "create_meta",
        &create_op("myid", None, None, 4, 4, true),
        EEXIST,
    );
    // invalid args
    for (id, a, b) in [("", 10, 1), ("x", 0, 0), ("x", 10, 0), ("x", 10, 11)] {
        err(
            &mut s,
            "n",
            "fifo",
            "create_meta",
            &create_op(id, None, None, a, b, false),
            EINVAL,
        );
    }
    err(&mut s, "n", "fifo", "create_meta", &[1, 2, 3], EINVAL);
    // empty version instance given: random instance is filled by write_header
    ok(
        &mut s,
        "e",
        "fifo",
        "create_meta",
        &create_op("e", Some(("", 7)), Some("p"), 10, 1, false),
    );
    let i: Info = d(&s.obj("e").unwrap().data);
    assert_eq!((i.version.instance.len(), i.version.ver), (15, 7));
    // threshold wraps when overhead exceeds (part - entry)
    ok(
        &mut s,
        "w",
        "fifo",
        "create_meta",
        &create_op("w", Some(("i", 1)), Some("p"), 10, 10, false),
    );
    let i: Info = d(&s.obj("w").unwrap().data);
    assert_eq!(i.params.full_size_threshold, 0u64.wrapping_sub(58));
}

#[test]
fn update_meta_semantics() {
    let mut s = mk();
    create(&mut s);
    // version mismatch (instance / ver)
    err(
        &mut s,
        M,
        "fifo",
        "update_meta",
        &update_op(("inst", 2), Some(1), None, None, None, &[], &[]),
        ECANCELED,
    );
    err(
        &mut s,
        M,
        "fifo",
        "update_meta",
        &update_op(("zzz", 1), Some(1), None, None, None, &[], &[]),
        ECANCELED,
    );
    // empty instance
    err(
        &mut s,
        M,
        "fifo",
        "update_meta",
        &update_op(("", 1), Some(1), None, None, None, &[], &[]),
        EINVAL,
    );
    // invalid journal entry in add
    err(
        &mut s,
        M,
        "fifo",
        "update_meta",
        &update_op(("inst", 1), None, None, None, None, &[(9, 1)], &[]),
        EINVAL,
    );
    err(
        &mut s,
        M,
        "fifo",
        "update_meta",
        &update_op(("inst", 1), None, None, None, None, &[(1, -1)], &[]),
        EINVAL,
    );
    // no change -> nothing written, version stays
    let before = s.obj(M).unwrap().data.clone();
    ok(
        &mut s,
        M,
        "fifo",
        "update_meta",
        &update_op(
            ("inst", 1),
            Some(0),
            None,
            Some(0),
            Some(0u64.wrapping_sub(1)),
            &[],
            &[(1, 5)],
        ),
    );
    assert_eq!(s.obj(M).unwrap().data, before);
    // change: ver bumps once, journal sorted by (op, part_num)
    ok(
        &mut s,
        M,
        "fifo",
        "update_meta",
        &update_op(
            ("inst", 1),
            Some(2),
            Some(7),
            Some(3),
            Some(4),
            &[(3, 1), (1, 9), (1, 2), (2, 5)],
            &[],
        ),
    );
    let want = info_bytes(
        "fifo",
        ("inst", 2),
        "pre",
        (1000, 100, 842),
        [2, 7, 3, 4],
        &[(1, 2), (1, 9), (2, 5), (3, 1)],
    );
    assert_eq!(s.obj(M).unwrap().data, want);
    // stale version now
    err(
        &mut s,
        M,
        "fifo",
        "update_meta",
        &update_op(("inst", 1), Some(9), None, None, None, &[], &[]),
        ECANCELED,
    );
    // rm of existing + duplicate add
    ok(
        &mut s,
        M,
        "fifo",
        "update_meta",
        &update_op(
            ("inst", 2),
            None,
            None,
            None,
            None,
            &[(1, 2)],
            &[(1, 9), (3, 1)],
        ),
    );
    let i: Info = d(&s.obj(M).unwrap().data);
    assert_eq!(i.version.ver, 3);
    assert_eq!(i.journal.len(), 2);
    // -1 as u64 applies as i64 -1
    ok(
        &mut s,
        M,
        "fifo",
        "update_meta",
        &update_op(("inst", 3), None, Some(u64::MAX), None, None, &[], &[]),
    );
    let i: Info = d(&s.obj(M).unwrap().data);
    assert_eq!(i.head_part_num, -1);
}

#[test]
fn meta_enodata_enoent_eio() {
    let mut s = mk();
    err(&mut s, M, "fifo", "get_meta", &get_meta_op(None), ENOENT);
    err(
        &mut s,
        M,
        "fifo",
        "update_meta",
        &update_op(("i", 1), Some(1), None, None, None, &[], &[]),
        ENOENT,
    );
    s.objects.insert(M.into(), Obj::default()); // empty "probe" object
    err(&mut s, M, "fifo", "get_meta", &get_meta_op(None), ENODATA);
    err(
        &mut s,
        M,
        "fifo",
        "update_meta",
        &update_op(("i", 1), Some(1), None, None, None, &[], &[]),
        ENODATA,
    );
    // create_meta on an existing empty object: decode of the stored info fails
    err(
        &mut s,
        M,
        "fifo",
        "create_meta",
        &create_op("x", None, None, 10, 1, false),
        EIO,
    );
    s.objects.get_mut(M).unwrap().data = vec![1, 2, 3, 4, 5, 6, 7];
    err(&mut s, M, "fifo", "get_meta", &get_meta_op(None), EIO);
    // invalid journal entry stored -> malformed -> EIO
    let mut bad = info_bytes("f", ("i", 1), "p", (1, 1, 1), [0, -1, 0, -1], &[(1, 1)]);
    // flip journal entry op (last env: op field is 4 bytes at tail-(8+4)... find by suffix)
    let n = bad.len();
    bad[n - 4 - 8 - 4 - 4..n - 4 - 8 - 4].copy_from_slice(&9i32.to_le_bytes());
    s.objects.get_mut(M).unwrap().data = bad;
    err(&mut s, M, "fifo", "get_meta", &get_meta_op(None), EIO);
}

#[test]
fn init_part_bytes_and_idempotence() {
    let mut s = mk();
    let magic = init(&mut s);
    let o = s.obj(P).unwrap();
    assert_eq!(o.data.len(), 96);
    // header: env(1,1,len 90){tag "", params, magic, min_ofs 512, last 0, next 512, min_idx 0,
    // max_idx 0, time}
    let want = env_(
        1,
        1,
        &cat(&[
            &s_(""),
            &params(1000, 100, 842),
            &magic.to_le_bytes(),
            &512u64.to_le_bytes(),
            &0u64.to_le_bytes(),
            &512u64.to_le_bytes(),
            &0u64.to_le_bytes(),
            &0u64.to_le_bytes(),
            &NOW.sec.to_le_bytes(),
            &NOW.nsec.to_le_bytes(),
        ]),
    );
    assert_eq!(o.data, want);
    // idempotent with same params, EEXIST with different
    ok(
        &mut s,
        P,
        "fifo",
        "init_part",
        &init_op(params(1000, 100, 842)),
    );
    assert_eq!(part_header(&mut s).magic, magic);
    err(
        &mut s,
        P,
        "fifo",
        "init_part",
        &init_op(params(1000, 100, 843)),
        EEXIST,
    );
    // existing but empty (created by the client in the same message): initializes
    s.objects.insert("q".into(), Obj::default());
    ok(&mut s, "q", "fifo", "init_part", &init_op(params(1, 1, 1)));
    // corrupt existing part
    s.objects.get_mut(P).unwrap().data = vec![9; 40];
    err(
        &mut s,
        P,
        "fifo",
        "init_part",
        &init_op(params(1000, 100, 842)),
        EIO,
    );
}
fn s_(x: &str) -> Vec<u8> {
    s(x)
}

#[test]
fn push_framing_and_counts() {
    let mut s = mk();
    let magic = init(&mut s);
    assert_eq!(push(&mut s, &[b"hello", b"wo"]), 2);
    let o = s.obj(P).unwrap();
    // hole [96,512) is zero; entries from 512
    assert_eq!(o.data.len(), 512 + (44 + 14 + 5) + (44 + 14 + 2));
    assert!(o.data[96..512].iter().all(|b| *b == 0));
    let eh = env_(
        1,
        1,
        &cat(&[&NOW.sec.to_le_bytes(), &NOW.nsec.to_le_bytes()]),
    );
    assert_eq!(eh.len(), 14);
    let mut want = Vec::new();
    for (i, data) in [&b"hello"[..], b"wo"].iter().enumerate() {
        for v in [magic, 44, 14, data.len() as u64, i as u64] {
            want.extend(v.to_le_bytes());
        }
        want.extend(0u32.to_le_bytes());
        want.extend(&eh);
        want.extend(*data);
    }
    assert_eq!(&o.data[512..], &want[..]);
    let h = part_header(&mut s);
    assert_eq!(
        (h.min_ofs, h.last_ofs, h.next_ofs, h.min_index, h.max_index),
        (512, 512 + 63, 512 + 63 + 60, 0, 2)
    );
    assert_eq!(h.max_time, NOW);
    // errors
    err(
        &mut s,
        P,
        "fifo",
        "push_part",
        &push_op(&[&[0u8; 2000]]),
        EINVAL,
    ); // effective len > max_part_size
    let mut bad = push_op(&[b"abc"]);
    let n = bad.len();
    bad[n - 8..].copy_from_slice(&4u64.to_le_bytes()); // total_len mismatch
    err(&mut s, P, "fifo", "push_part", &bad, EINVAL);
    err(&mut s, P, "fifo", "push_part", &push_op(&[]), EFAULT_);
    err(
        &mut s,
        "absent",
        "fifo",
        "push_part",
        &push_op(&[b"x"]),
        EIO,
    );
    s.objects.insert("empty".into(), Obj::default());
    err(&mut s, "empty", "fifo", "push_part", &push_op(&[b"x"]), EIO);
}
const EFAULT_: i32 = -14;

#[test]
fn push_until_full_partial_then_erange() {
    let mut s = mk();
    full_part(&mut s);
    let h = part_header(&mut s);
    assert_eq!((h.next_ofs, h.max_index, h.last_ofs), (852, 5, 784));
    assert!(h.next_ofs > h.params.full_size_threshold);
    err(&mut s, P, "fifo", "push_part", &push_op(&[b"zz"]), ERANGE);
    let l = list(&mut s, 0, 100);
    assert!(l.full_part && !l.more);
    assert_eq!(l.entries.len(), 5);
}

#[test]
fn list_pagination_skip_one() {
    let mut s = mk();
    full_part(&mut s);
    let l = list(&mut s, 0, 2);
    assert_eq!(
        l.entries.iter().map(|e| e.ofs).collect::<Vec<_>>(),
        [512, 580]
    );
    assert_eq!(l.entries[0].data, vec![b'a'; 10]);
    assert_eq!(l.entries[1].data, vec![b'b'; 10]);
    assert_eq!(l.entries[0].mtime, NOW);
    assert!(l.more && l.full_part && l.tag.is_empty());
    // resume after the last seen entry (op.ofs = last ofs): skip one
    let l = list(&mut s, 580, 2);
    assert_eq!(
        l.entries.iter().map(|e| e.ofs).collect::<Vec<_>>(),
        [648, 716]
    );
    assert!(l.more);
    let l = list(&mut s, 716, 100);
    assert_eq!(l.entries.iter().map(|e| e.ofs).collect::<Vec<_>>(), [784]);
    assert!(!l.more);
    let l = list(&mut s, 784, 100);
    assert!(l.entries.is_empty() && !l.more);
    // ofs below min_ofs: nothing skipped; max 0 / negative: none but more
    let l = list(&mut s, 100, 0);
    assert!(l.entries.is_empty() && l.more);
    let l = list(&mut s, 0, -5);
    assert!(l.entries.is_empty() && l.more);
    // non-boundary resume offset -> magic mismatch
    err(&mut s, P, "fifo", "part_list", &list_op(600, 5), ERANGE);
    // cap 512
    let mut s2 = mk();
    init(&mut s2);
    // big part so that > 512 tiny entries fit
    ok(
        &mut s2,
        "big",
        "fifo",
        "init_part",
        &init_op(params(1 << 22, 100, 1 << 21)),
    );
    for _ in 0..3 {
        let bufs: Vec<&[u8]> = vec![b"x"; 300];
        assert_eq!(
            call(&mut s2, "big", "fifo", "push_part", &push_op(&bufs)).ret,
            300
        );
    }
    let l: ListPartReply = d(&ok(
        &mut s2,
        "big",
        "fifo",
        "part_list",
        &list_op(0, 10_000),
    ));
    assert_eq!(l.entries.len(), 512);
    assert!(l.more && !l.full_part);
}

#[test]
fn trim_semantics() {
    // inclusive at an entry
    let mut s = mk();
    full_part(&mut s);
    ok(&mut s, P, "fifo", "trim_part", &trim_op(580, false));
    let h = part_header(&mut s);
    assert_eq!((h.min_ofs, h.min_index), (648, 2));
    // no-ops: below min_ofs, exclusive at min_ofs
    let before = s.obj(P).unwrap().data.clone();
    ok(&mut s, P, "fifo", "trim_part", &trim_op(100, false));
    ok(&mut s, P, "fifo", "trim_part", &trim_op(648, true));
    assert_eq!(s.obj(P).unwrap().data, before);
    // exclusive at an entry
    ok(&mut s, P, "fifo", "trim_part", &trim_op(716, true));
    let h = part_header(&mut s);
    assert_eq!((h.min_ofs, h.min_index), (716, 3));
    // listing honours min_ofs (entries before are hidden, data stays on disk)
    let l = list(&mut s, 0, 10);
    assert_eq!(
        l.entries.iter().map(|e| e.ofs).collect::<Vec<_>>(),
        [716, 784]
    );
    // non-boundary
    err(&mut s, P, "fifo", "trim_part", &trim_op(720, false), ERANGE);
    // last entry inclusive
    ok(&mut s, P, "fifo", "trim_part", &trim_op(784, false));
    let h = part_header(&mut s);
    assert_eq!((h.min_ofs, h.min_index), (852, 5));
    // full part, ofs >= next_ofs: object removed
    ok(&mut s, P, "fifo", "trim_part", &trim_op(852, false));
    assert!(s.obj(P).is_none());
    err(&mut s, P, "fifo", "trim_part", &trim_op(852, false), EIO);

    // head (non-full) part: trimming everything keeps the object
    let mut s = mk();
    init(&mut s);
    assert_eq!(push(&mut s, &[b"a", b"b"]), 2);
    ok(&mut s, P, "fifo", "trim_part", &trim_op(100_000, false));
    let h = part_header(&mut s);
    assert_eq!(
        (h.min_ofs, h.min_index, h.next_ofs, h.max_index),
        (h.next_ofs, 2, h.next_ofs, 2)
    );
    assert!(s.obj(P).is_some());
    // can still push and list afterwards
    assert_eq!(push(&mut s, &[b"c"]), 1);
    let l = list(&mut s, 0, 10);
    assert_eq!(l.entries.len(), 1);
    assert_eq!(l.entries[0].data, b"c");
    assert!(!l.full_part);
}

#[test]
fn part_header_errors() {
    let mut s = mk();
    for m in ["get_part_info", "part_list", "trim_part", "push_part"] {
        let inp = match m {
            "get_part_info" => env_(1, 1, &[]),
            "part_list" => list_op(0, 1),
            "trim_part" => trim_op(512, false),
            _ => push_op(&[b"x"]),
        };
        // classic: the header read of an absent object is empty -> undecodable -> EIO (recorded on 21.1.1); a read-only message
        // never gets here on an OSD (ENOENT before any op), MemStore::call has no such pre-check
        err(&mut s, P, "fifo", m, &inp, EIO);
    }
    s.objects.insert(P.into(), Obj::default());
    err(&mut s, P, "fifo", "get_part_info", &env_(1, 1, &[]), EIO);
    s.objects.get_mut(P).unwrap().data = vec![0xff; 100];
    err(&mut s, P, "fifo", "part_list", &list_op(0, 1), EIO);
    // garbage entry header (bad magic) -> ERANGE; truncated body -> ERANGE
    let mut s = mk();
    full_part(&mut s);
    s.objects.get_mut(P).unwrap().data.truncate(600);
    err(&mut s, P, "fifo", "part_list", &list_op(0, 10), ERANGE);
}

// ------------------------------------------------ fuzz

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn populated() -> MemStore {
    let mut s = mk();
    create(&mut s);
    full_part(&mut s);
    s
}

#[test]
fn fuzz_never_panics_and_failed_calls_change_nothing() {
    let methods = [
        "create_meta",
        "get_meta",
        "update_meta",
        "init_part",
        "push_part",
        "trim_part",
        "part_list",
        "get_part_info",
    ];
    let valid: Vec<Vec<u8>> = vec![
        create_op("fifo", Some(("inst", 1)), Some("pre"), 1000, 100, false),
        get_meta_op(Some(("inst", 1))),
        update_op(("inst", 1), Some(1), Some(2), None, None, &[(1, 3)], &[]),
        init_op(params(1000, 100, 842)),
        push_op(&[b"abc", b"de"]),
        trim_op(580, false),
        trim_op(0, true),
        list_op(512, 50),
        env_(1, 1, &[]),
    ];
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut calls = 0;
    for round in 0..400 {
        for m in methods {
            let mut input = match round % 3 {
                0 => (0..(rng.next() % 64))
                    .map(|_| rng.next() as u8)
                    .collect::<Vec<u8>>(),
                _ => valid[(rng.next() % valid.len() as u64) as usize].clone(),
            };
            if round % 3 == 2 && !input.is_empty() {
                for _ in 0..(1 + rng.next() % 3) {
                    let i = (rng.next() % input.len() as u64) as usize;
                    input[i] = rng.next() as u8;
                }
            }
            for variant in 0..4 {
                let mut s = populated();
                match variant {
                    1 => {
                        s.objects.get_mut(M).unwrap().data.truncate(20);
                        s.objects.get_mut(P).unwrap().data.truncate(300);
                    }
                    2 => {
                        for o in s.objects.values_mut() {
                            for b in o.data.iter_mut().step_by(7) {
                                *b ^= 0x5a;
                            }
                        }
                    }
                    3 => {
                        s.objects.clear();
                    }
                    _ => {}
                }
                for oid in [M, P] {
                    let before = s.objects.clone();
                    let r = s.call(oid, "fifo", m, &input);
                    calls += 1;
                    if r.ret < 0 {
                        assert_eq!(s.objects, before, "{m} on {oid}: failed call changed state");
                    }
                    if m == "part_list" && r.ret == 0 {
                        let l: ListPartReply = d(&r.out);
                        assert!(l.entries.len() <= 512);
                    }
                    if m == "push_part" {
                        assert!(r.ret <= 512 * 1024);
                    }
                }
            }
        }
    }
    assert!(calls > 10_000);
}

/// Entries across several 128 KiB reader refills: listing pages and trims see every entry at its
/// offset with its bytes; the one-refill rule makes a 200 KiB record readable and a 300 KiB one
/// `-ERANGE` (spec cls_fifo.md EntryReader).
#[test]
fn reader_refills_list_trim_and_record_size_limit() {
    let mut s = mk();
    ok(
        &mut s,
        P,
        "fifo",
        "init_part",
        &init_op(params(8 << 20, 512 << 10, 8 << 20)),
    );
    let bufs: Vec<Vec<u8>> = (0..90u32)
        .map(|i| vec![i as u8; 7000 + (i as usize * 37) % 3000])
        .collect();
    for chunk in bufs.chunks(30) {
        let refs: Vec<&[u8]> = chunk.iter().map(Vec::as_slice).collect();
        assert_eq!(push(&mut s, &refs), 30);
    }
    let first = part_header(&mut s).min_ofs;
    // pages of 7 entries, each page resumes after the last offset seen
    let (mut got, mut ofs) = (Vec::new(), 0u64);
    loop {
        let r = list(&mut s, ofs, 7);
        got.extend(r.entries.iter().map(|e| (e.ofs, e.data.clone())));
        if !r.more {
            break;
        }
        ofs = r.entries.last().unwrap().ofs;
    }
    assert_eq!(got.len(), 90);
    assert_eq!(got[0].0, first);
    for (i, ((o, d), b)) in got.iter().zip(&bufs).enumerate() {
        assert_eq!(d, b, "entry {i}");
        if i > 0 {
            assert_eq!(*o, got[i - 1].0 + 58 + bufs[i - 1].len() as u64, "ofs {i}");
        }
    }
    // exclusive trim keeps the entry at ofs, inclusive trim drops it
    ok(&mut s, P, "fifo", "trim_part", &trim_op(got[40].0, true));
    let h = part_header(&mut s);
    assert_eq!((h.min_ofs, h.min_index), (got[40].0, 40));
    ok(&mut s, P, "fifo", "trim_part", &trim_op(got[40].0, false));
    let h = part_header(&mut s);
    assert_eq!((h.min_ofs, h.min_index), (got[41].0, 41));
    assert_eq!(list(&mut s, 0, 1).entries[0].data, bufs[41]);

    for (len, want) in [(200 << 10, 0), (300 << 10, ERANGE)] {
        let mut s = mk();
        ok(
            &mut s,
            P,
            "fifo",
            "init_part",
            &init_op(params(8 << 20, 512 << 10, 8 << 20)),
        );
        assert_eq!(push(&mut s, &[&vec![7u8; len]]), 1);
        let r = call(&mut s, P, "fifo", "part_list", &list_op(0, 10));
        assert_eq!(r.ret, want, "record of {len} bytes");
    }
}
