// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Classes `log` and `timeindex`: dencoder fixtures, behaviour (MemStore), input fuzz, flags.
mod common;
use cls::errno::*;
use cls::log::{self as lg};
use cls::mem::MemStore;
use cls::timeindex as ti;
use common::*;
use denc::types::UTime;

const O: &str = "o";

fn t(sec: u32, nsec: u32) -> UTime {
    UTime::new(sec, nsec)
}

// ---------------------------------------------------------------- wire

#[test]
fn dencoder_fixtures() {
    assert_eq!(rt::<lg::Entry>("cls_log_entry"), 2);
    assert_eq!(rt::<lg::Header>("cls_log_header"), 2);
    assert_eq!(rt::<lg::AddOp>("cls_log_add_op"), 2);
    assert_eq!(rt::<lg::InfoOp>("cls_log_info_op"), 1);
    assert_eq!(rt::<lg::ListOp>("cls_log_list_op"), 2);
    assert_eq!(rt::<lg::ListRet>("cls_log_list_ret"), 2);
    assert_eq!(rt::<lg::TrimOp>("cls_log_trim_op"), 2);
    assert_eq!(rt::<ti::Entry>("cls_timeindex_entry"), 2);
    assert_eq!(rt::<ti::ListOp>("cls_timeindex_list_op"), 2);
    assert_eq!(rt::<ti::ListRet>("cls_timeindex_list_ret"), 2);
}

#[test]
fn hand_derived_bytes() {
    // timeindex add_op: env(1,1,len) + count 1 + entry env(1,1,len){ts, "x", value "v"}
    let op = ti::AddOp {
        entries: vec![ti::Entry {
            key_ts: t(1, 2),
            key_ext: "x".into(),
            value: b"v".to_vec(),
        }],
    };
    let entry_body: Vec<u8> = cat(&[
        &1u32.to_le_bytes(),
        &2u32.to_le_bytes(),
        &[1, 0, 0, 0, b'x'],
        &[1, 0, 0, 0, b'v'],
    ]);
    let entry = cat(&[
        &[1, 1],
        &(entry_body.len() as u32).to_le_bytes(),
        &entry_body,
    ]);
    let body = cat(&[&1u32.to_le_bytes(), &entry]);
    assert_eq!(
        e(&op),
        cat(&[&[1, 1], &(body.len() as u32).to_le_bytes(), &body])
    );
    // v1 log add_op decodes with monotonic_inc = true
    let v1 = cat(&[&[1, 1, 4, 0, 0, 0], &0u32.to_le_bytes()]);
    let a: lg::AddOp = d(&v1);
    assert!(a.monotonic_inc && a.entries.is_empty());
    assert_eq!(
        lg::time_prefix(t(1_700_000_000, 123_456_789)),
        b"1_1700000000.123456_"
    );
    assert_eq!(lg::time_prefix(t(5, 0)), b"1_0000000005.000000_");
}

// ---------------------------------------------------------------- log

fn entry(ts: UTime, name: &str) -> lg::Entry {
    lg::Entry {
        section: "s".into(),
        name: name.into(),
        timestamp: ts,
        data: name.as_bytes().to_vec(),
        ..Default::default()
    }
}
fn add(s: &mut MemStore, entries: Vec<lg::Entry>, monotonic_inc: bool) -> i32 {
    call(
        s,
        O,
        "log",
        "add",
        &e(&lg::AddOp {
            entries,
            monotonic_inc,
        }),
    )
    .ret
}
fn list(s: &mut MemStore, op: &lg::ListOp) -> lg::ListRet {
    d(&ok(s, O, "log", "list", &e(op)))
}
fn info(s: &mut MemStore) -> lg::Header {
    d::<lg::InfoRet>(&ok(s, O, "log", "info", &e(&lg::InfoOp {}))).header
}
fn lop(from: UTime, marker: impl AsRef<[u8]>, to: UTime, max: i32) -> lg::ListOp {
    lg::ListOp {
        from_time: from,
        marker: marker.as_ref().to_vec(),
        to_time: to,
        max_entries: max,
    }
}
fn omap_keys(s: &MemStore) -> Vec<String> {
    s.objects[O]
        .omap
        .keys()
        .map(|k| String::from_utf8_lossy(k).into_owned())
        .collect()
}

#[test]
fn log_add_key_format_header_and_ids() {
    let mut s = MemStore::new();
    s.env.version = 412;
    s.env.subop = 3;
    assert_eq!(add(&mut s, vec![entry(t(1000, 5_999), "a")], true), 0);
    assert_eq!(omap_keys(&s), ["1_0000001000.000005_412.4"]);
    // the stored entry carries its id
    let r = list(&mut s, &lop(t(0, 0), "", t(0, 0), 0));
    assert_eq!(r.entries.len(), 1);
    assert_eq!(r.entries[0].id, b"1_0000001000.000005_412.4");
    assert_eq!(r.entries[0].timestamp, t(1000, 5_999)); // stored ts is untouched
    let h = info(&mut s);
    assert_eq!(h.max_marker, b"1_0000001000.000005_412.4");
    assert_eq!(h.max_time, t(1000, 5_999));
}

#[test]
fn log_add_monotonic_clamp_and_non_monotonic() {
    let mut s = MemStore::new();
    s.env.version = 1;
    add(&mut s, vec![entry(t(100, 0), "a")], true);
    s.env.version = 2;
    // older entry is clamped UP to max_time for the key; stored timestamp field unchanged
    add(&mut s, vec![entry(t(50, 0), "b")], true);
    assert_eq!(
        omap_keys(&s),
        ["1_0000000100.000000_1.1", "1_0000000100.000000_2.1"]
    );
    let r = list(&mut s, &lop(t(0, 0), "", t(0, 0), 0));
    assert_eq!(r.entries[1].timestamp, t(50, 0));
    assert_eq!(info(&mut s).max_time, t(100, 0));
    // non-monotonic: key uses the real timestamp, max_time untouched
    s.env.version = 3;
    add(&mut s, vec![entry(t(50, 0), "c")], false);
    assert!(omap_keys(&s).contains(&"1_0000000050.000000_3.1".to_string()));
    assert_eq!(info(&mut s).max_time, t(100, 0));
    // max_marker is the bytewise max key, not the last written one
    assert_eq!(info(&mut s).max_marker, b"1_0000000100.000000_2.1");
}

#[test]
fn log_add_explicit_id_is_verbatim() {
    let mut s = MemStore::new();
    let mut en = entry(t(10, 0), "a");
    en.id = "1_custom".into();
    add(&mut s, vec![en], true);
    assert_eq!(omap_keys(&s), ["1_custom"]);
    // an id without the 1_ prefix is stored but invisible to list
    let mut en = entry(t(10, 0), "b");
    en.id = "zz".into();
    add(&mut s, vec![en], true);
    assert!(omap_keys(&s).contains(&"zz".to_string()));
    let r = list(&mut s, &lop(t(0, 0), "", t(0, 0), 0));
    assert_eq!(r.entries.len(), 1);
    // same-us entries of one call do NOT collide: the suffix carries the running subop number
    add(
        &mut s,
        vec![entry(t(20, 1), "x"), entry(t(20, 2), "y")],
        true,
    );
    let k: Vec<_> = omap_keys(&s)
        .into_iter()
        .filter(|k| k.starts_with("1_0000000020"))
        .collect();
    assert_eq!(k.len(), 2);
}

#[test]
fn log_list_paging_marker_boundary() {
    let mut s = MemStore::new();
    for i in 1..=10u32 {
        s.env.version = i as u64;
        add(&mut s, vec![entry(t(100 * i, 0), &format!("e{i}"))], true);
    }
    let r = list(&mut s, &lop(t(0, 0), "", t(0, 0), 4));
    assert_eq!(r.entries.len(), 4);
    assert!(r.truncated);
    assert_eq!(r.marker, b"1_0000000400.000000_4.1");
    let r2 = list(&mut s, &lop(t(0, 0), &r.marker, t(0, 0), 4));
    assert_eq!(r2.entries[0].name, b"e5");
    // last page: not truncated
    let r3 = list(
        &mut s,
        &lop(t(0, 0), "1_0000000600.000000_6.1", t(0, 0), 100),
    );
    assert_eq!(r3.entries.len(), 4);
    assert!(!r3.truncated);
    assert_eq!(r3.marker, b"1_0000001000.000000_10.1");
    // time window [from, to): from_time inclusive at us granularity, to_time exclusive
    let r = list(&mut s, &lop(t(300, 0), "", t(600, 0), 0));
    let names: Vec<_> = r
        .entries
        .iter()
        .map(|x| String::from_utf8_lossy(&x.name).into_owned())
        .collect();
    assert_eq!(names, ["e3", "e4", "e5"]);
    assert!(!r.truncated);
    // boundary hit -> marker is the boundary key (harmless since not truncated)
    assert_eq!(r.marker, b"1_0000000600.000000_6.1");
    // zero from_time disables the boundary
    let r = list(&mut s, &lop(t(0, 0), "", t(5, 0), 0));
    assert_eq!(r.entries.len(), 10);
    // to < from disables it too
    let r = list(&mut s, &lop(t(300, 0), "", t(100, 0), 0));
    assert_eq!(r.entries.len(), 8);
    // negative / huge max -> cap 1000 (all 10)
    assert_eq!(
        list(&mut s, &lop(t(0, 0), "", t(0, 0), -5)).entries.len(),
        10
    );
    assert_eq!(
        list(&mut s, &lop(t(0, 0), "", t(0, 0), 1 << 30))
            .entries
            .len(),
        10
    );
}

#[test]
fn log_list_cap_and_corrupt_entry_and_absent() {
    let mut s = MemStore::new();
    // absent object: empty, no error
    let r = list(&mut s, &lop(t(0, 0), "", t(0, 0), 0));
    assert!(r.entries.is_empty() && r.marker.is_empty() && !r.truncated);
    for i in 0..1100u32 {
        s.env.version = i as u64;
        add(&mut s, vec![entry(t(10 + i, 0), "x")], true);
    }
    let r = list(&mut s, &lop(t(0, 0), "", t(0, 0), 0));
    assert_eq!(r.entries.len(), 1000);
    assert!(r.truncated);
    // corrupt value: skipped, marker still advances
    let o = s.objects.get_mut(O).unwrap();
    let k = o.omap.keys().nth(1).unwrap().clone();
    o.omap.insert(k.clone(), vec![1, 2, 3]);
    let r = list(&mut s, &lop(t(0, 0), "", t(0, 0), 3));
    assert_eq!(r.entries.len(), 2);
    assert_eq!(r.marker.as_slice(), o_key(&s, 2));
}
fn o_key(s: &MemStore, n: usize) -> Vec<u8> {
    s.objects[O].omap.keys().nth(n).unwrap().clone()
}

#[test]
fn log_trim_semantics() {
    let mut s = MemStore::new();
    for i in 1..=5u32 {
        s.env.version = i as u64;
        add(&mut s, vec![entry(t(100 * i, 0), "e")], true);
    }
    let tr = |from: UTime, to: UTime, fm: &str, tm: &str| {
        e(&lg::TrimOp {
            from_time: from,
            to_time: to,
            from_marker: fm.into(),
            to_marker: tm.into(),
        })
    };
    // time trim: to_time + 1 ms bound
    err(
        &mut s,
        O,
        "log",
        "trim",
        &tr(t(0, 0), t(0, 0), "", ""),
        ENODATA,
    ); // nothing <= 0
    ok(&mut s, O, "log", "trim", &tr(t(0, 0), t(100, 0), "", ""));
    assert_eq!(omap_keys(&s).len(), 4);
    // key at 200.000000 is NOT removed by to_time 199.999: bound is 199.999+1ms = 200.000999 -> key < bound removed
    ok(
        &mut s,
        O,
        "log",
        "trim",
        &tr(t(0, 0), t(199, 999_500_000), "", ""),
    );
    assert_eq!(omap_keys(&s).len(), 3); // 200 removed (quirk: +1000 us)
    // marker trim: inclusive of to_marker; from_marker exclusive
    ok(
        &mut s,
        O,
        "log",
        "trim",
        &tr(
            t(0, 0),
            t(0, 0),
            "1_0000000300.000000_3.1",
            "1_0000000400.000000_4.1",
        ),
    );
    assert_eq!(
        omap_keys(&s),
        ["1_0000000300.000000_3.1", "1_0000000500.000000_5.1"]
    );
    // range empty after from -> ENODATA; first key beyond to -> ENODATA
    err(
        &mut s,
        O,
        "log",
        "trim",
        &tr(t(0, 0), t(0, 0), "zz", ""),
        ENODATA,
    );
    err(
        &mut s,
        O,
        "log",
        "trim",
        &tr(t(0, 0), t(0, 0), "", "1_0000000100"),
        ENODATA,
    );
    // loop until ENODATA (client behaviour)
    ok(&mut s, O, "log", "trim", &tr(t(0, 0), t(9999, 0), "", ""));
    assert!(omap_keys(&s).is_empty());
    err(
        &mut s,
        O,
        "log",
        "trim",
        &tr(t(0, 0), t(9999, 0), "", ""),
        ENODATA,
    );
}

#[test]
fn log_info_default_and_corrupt_header() {
    let mut s = MemStore::new();
    assert_eq!(info(&mut s), lg::Header::default());
    add(&mut s, vec![entry(t(7, 0), "a")], true);
    s.objects.get_mut(O).unwrap().omap_header = vec![9, 9];
    // undecodable header is ignored (default) for info and for add
    assert_eq!(info(&mut s), lg::Header::default());
    assert_eq!(add(&mut s, vec![entry(t(3, 0), "b")], true), 0);
    assert_eq!(info(&mut s).max_time, t(3, 0));
}

#[test]
fn log_bad_input_einval() {
    let mut s = MemStore::new();
    for m in ["add", "list", "trim", "info"] {
        err(&mut s, O, "log", m, &[1, 2, 3], EINVAL);
    }
}

// ---------------------------------------------------------------- timeindex

fn tadd(s: &mut MemStore, es: &[(UTime, &str, &str)]) {
    let op = ti::AddOp {
        entries: es
            .iter()
            .map(|(ts, ext, v)| ti::Entry {
                key_ts: *ts,
                key_ext: (*ext).into(),
                value: v.as_bytes().to_vec(),
            })
            .collect(),
    };
    ok(s, O, "timeindex", "add", &e(&op));
}
fn tlist(
    s: &mut MemStore,
    from: UTime,
    marker: impl AsRef<[u8]>,
    to: UTime,
    max: i32,
) -> ti::ListRet {
    let op = ti::ListOp {
        from_time: from,
        marker: marker.as_ref().to_vec(),
        to_time: to,
        max_entries: max,
    };
    d(&ok(s, O, "timeindex", "list", &e(&op)))
}

#[test]
fn timeindex_add_list_roundtrip_and_quirks() {
    let mut s = MemStore::new();
    tadd(
        &mut s,
        &[
            (t(100, 7_000), "ext_a", "va"),
            (t(100, 7_000), "ext_a", "va2"), // idempotent overwrite
            (t(200, 0), "", "empty-ext"),
            (t(300, 0), "has space", "sp"),
        ],
    );
    assert_eq!(
        omap_keys(&s),
        [
            "1_0000000100.000007_ext_a",
            "1_0000000200.000000_",
            "1_0000000300.000000_has space"
        ]
    );
    // value stored raw (not wrapped)
    assert_eq!(
        s.objects[O].omap[&b"1_0000000100.000007_ext_a".to_vec()],
        b"va2"
    );
    let r = tlist(&mut s, t(0, 0), "", t(0, 0), 10);
    // to == from == 0: boundary active with to_time(0) >= from_time(0) -> everything >= 1_000...0 stops
    assert!(r.entries.is_empty());
    let r = tlist(&mut s, t(0, 0), "", t(1000, 0), 10);
    assert_eq!(r.entries.len(), 3);
    // bug-compat: usec(7) is returned as 7 NANOseconds
    assert_eq!(r.entries[0].key_ts, t(100, 7));
    assert_eq!(r.entries[0].key_ext, b"ext_a");
    assert_eq!(r.entries[0].value, b"va2");
    // empty ext: sscanf leaves the stack buffer alone, so the PREVIOUS entry's ext shows (recorded on classic 21.1.1)
    assert_eq!(r.entries[1].key_ext, b"ext_a");
    // key_ext cut at whitespace
    assert_eq!(r.entries[2].key_ext, b"has");
    assert_eq!(r.marker, b"1_0000000300.000000_has space");
}

#[test]
fn timeindex_key_ext_255_limit_and_parse_failures() {
    let mut s = MemStore::new();
    let long = "x".repeat(300);
    tadd(&mut s, &[(t(5, 0), &long, "v")]);
    // a key that does not parse (but has the 1_ prefix): skipped, marker still advances
    s.objects
        .get_mut(O)
        .unwrap()
        .omap
        .insert(b"1_garbage".to_vec(), b"g".to_vec());
    // from > to disables the time boundary (garbage sorts after every numeric key)
    let r = tlist(&mut s, t(1, 0), "1_", t(0, 0), 10);
    assert_eq!(r.entries.len(), 1);
    assert_eq!(r.entries[0].key_ext.len(), 255);
    assert_eq!(r.marker, b"1_garbage");
}

#[test]
fn timeindex_list_paging_boundary_max() {
    let mut s = MemStore::new();
    for i in 1..=6u32 {
        tadd(&mut s, &[(t(100 * i, 0), "k", "v")]);
    }
    let r = tlist(&mut s, t(0, 0), "", t(10_000, 0), 2);
    assert_eq!(r.entries.len(), 2);
    assert!(r.truncated);
    let r2 = tlist(&mut s, t(0, 0), &r.marker, t(10_000, 0), 2);
    assert_eq!(r2.entries[0].key_ts, t(300, 0));
    // to_time exclusive; boundary stop clears truncated and does not advance the marker
    let r = tlist(&mut s, t(0, 0), "", t(300, 0), 10);
    assert_eq!(r.entries.len(), 2);
    assert!(!r.truncated);
    assert_eq!(r.marker, b"1_0000000200.000000_k");
    // to < from: no boundary
    let r = tlist(&mut s, t(500, 0), "", t(100, 0), 10);
    assert_eq!(r.entries.len(), 2);
    // max_entries 0 -> nothing returned; negative -> cap
    assert!(
        tlist(&mut s, t(0, 0), "", t(10_000, 0), 0)
            .entries
            .is_empty()
    );
    assert_eq!(
        tlist(&mut s, t(0, 0), "", t(10_000, 0), -1).entries.len(),
        6
    );
}

#[test]
fn timeindex_trim_prefix_semantics() {
    let mut s = MemStore::new();
    for i in 1..=5u32 {
        tadd(&mut s, &[(t(100 * i, 0), "k", "v")]);
    }
    let tr = |from: UTime, to: UTime, fm: &str, tm: &str| {
        e(&ti::TrimOp {
            from_time: from,
            to_time: to,
            from_marker: fm.into(),
            to_marker: tm.into(),
        })
    };
    // to_time inclusive at us granularity (prefix compare)
    ok(
        &mut s,
        O,
        "timeindex",
        "trim",
        &tr(t(0, 0), t(200, 0), "", ""),
    );
    assert_eq!(omap_keys(&s).len(), 3);
    err(
        &mut s,
        O,
        "timeindex",
        "trim",
        &tr(t(0, 0), t(200, 0), "", ""),
        ENODATA,
    );
    // to_marker is a prefix bound: "1_0000000300" matches keys starting with it
    ok(
        &mut s,
        O,
        "timeindex",
        "trim",
        &tr(t(0, 0), t(0, 0), "", "1_0000000300"),
    );
    assert_eq!(omap_keys(&s).len(), 2);
    // from_marker exclusive
    err(
        &mut s,
        O,
        "timeindex",
        "trim",
        &tr(t(0, 0), t(0, 0), "1_0000000500.000000_k", "1_9"),
        ENODATA,
    );
    ok(
        &mut s,
        O,
        "timeindex",
        "trim",
        &tr(t(0, 0), t(9999, 0), "", ""),
    );
    assert!(omap_keys(&s).is_empty());
}

#[test]
fn timeindex_trim_cap_1000() {
    let mut s = MemStore::new();
    for i in 0..1500u32 {
        tadd(&mut s, &[(t(1 + i, 0), "k", "v")]);
    }
    let op = e(&ti::TrimOp {
        to_time: t(100_000, 0),
        ..Default::default()
    });
    ok(&mut s, O, "timeindex", "trim", &op);
    assert_eq!(omap_keys(&s).len(), 500);
    ok(&mut s, O, "timeindex", "trim", &op);
    err(&mut s, O, "timeindex", "trim", &op, ENODATA);
}

// ---------------------------------------------------------------- flags + fuzz

#[test]
fn flags_match_classic() {
    use cls::{RD, RW, lookup};
    for (c, m, f) in [
        ("log", "add", RW),
        ("log", "list", RD),
        ("log", "trim", RW),
        ("log", "info", RD),
        ("timeindex", "add", RW),
        ("timeindex", "list", RD),
        ("timeindex", "trim", RW),
    ] {
        assert_eq!(lookup(c, m).unwrap().flags, f, "{c}.{m}");
    }
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

fn populated() -> MemStore {
    let mut s = MemStore::new();
    for i in 0..30u32 {
        s.env.version = i as u64;
        add(&mut s, vec![entry(t(10 + i, i * 1000), "x")], true);
        tadd(&mut s, &[(t(10 + i, i * 1000), "ext", "v")]);
    }
    s
}

#[test]
fn fuzz_inputs_never_panic_and_failure_is_atomic() {
    let mut rng = Rng(0xfeed_beef_1234_5678);
    for (class, m) in [
        ("log", "add"),
        ("log", "list"),
        ("log", "trim"),
        ("log", "info"),
        ("timeindex", "add"),
        ("timeindex", "list"),
        ("timeindex", "trim"),
    ] {
        for round in 0..120 {
            let n = (rng.next() % 120) as usize;
            let input = if round % 2 == 0 {
                let mut v = vec![(rng.next() % 4) as u8, 1];
                v.extend((n as u32).to_le_bytes());
                v.extend(rng.bytes(n));
                v
            } else {
                rng.bytes(n)
            };
            for mk in 0..3 {
                let mut s = match mk {
                    0 => MemStore::new(),
                    1 => populated(),
                    _ => {
                        let mut s = populated();
                        let o = s.objects.get_mut("o").unwrap();
                        for v in o.omap.values_mut() {
                            v.truncate(v.len() / 2);
                        }
                        o.omap_header.truncate(3);
                        s
                    }
                };
                let before = s.objects.clone();
                let r = call(&mut s, "o", class, m, &input);
                if r.ret < 0 {
                    assert_eq!(s.objects, before, "{class}.{m}: failed call changed state");
                }
                // bounded output: at most 1000 entries of bounded size
                assert!(r.out.len() < 4 << 20);
            }
        }
    }
}

#[test]
fn mutated_valid_inputs_never_panic() {
    let mut rng = Rng(42);
    let valid: Vec<(&str, &str, Vec<u8>)> = vec![
        (
            "log",
            "add",
            e(&lg::AddOp {
                entries: vec![entry(t(5, 5), "z")],
                monotonic_inc: true,
            }),
        ),
        ("log", "list", e(&lop(t(1, 0), "", t(99, 0), 5))),
        (
            "log",
            "trim",
            e(&lg::TrimOp {
                to_time: t(50, 0),
                ..Default::default()
            }),
        ),
        (
            "timeindex",
            "list",
            e(&ti::ListOp {
                to_time: t(99, 0),
                max_entries: 5,
                ..Default::default()
            }),
        ),
        (
            "timeindex",
            "trim",
            e(&ti::TrimOp {
                to_time: t(50, 0),
                ..Default::default()
            }),
        ),
    ];
    for (c, m, base) in &valid {
        for _ in 0..200 {
            let mut inp = base.clone();
            for _ in 0..(1 + rng.next() % 3) {
                let i = (rng.next() as usize) % inp.len();
                inp[i] = rng.next() as u8;
            }
            let mut s = populated();
            let _ = call(&mut s, "o", c, m, &inp);
        }
    }
}

/// real_time inputs carry nsec >= 1e9 into sec (classic decodes a nanosecond count): key, stored
/// timestamp, header and list/trim bounds all use the carried value; trim's +1 ms never wraps.
#[test]
fn log_unnormalized_real_time_inputs_carry() {
    let mut s = MemStore::new();
    s.env.version = 7;
    s.env.subop = 0;
    assert_eq!(
        add(&mut s, vec![entry(t(10, 1_500_000_000), "a")], false),
        0
    );
    assert_eq!(omap_keys(&s), ["1_0000000011.500000_7.1"]);
    assert_eq!(info(&mut s).max_time, t(11, 500_000_000));
    let r = list(&mut s, &lop(t(0, 0), "", t(0, 0), 0));
    assert_eq!(r.entries[0].timestamp, t(11, 500_000_000));
    // list bounds: from = 10s + 1.4e9 ns = 11.4 s -> the entry (11.5 s) is listed; to = 11.4 s stops it
    assert_eq!(
        list(&mut s, &lop(t(10, 1_400_000_000), "", t(20, 0), 0))
            .entries
            .len(),
        1
    );
    assert!(
        list(&mut s, &lop(t(1, 0), "", t(10, 1_400_000_000), 0))
            .entries
            .is_empty()
    );
    // trim with nsec near u32::MAX: 4.29 s carry, no wrap -> to = 14.29.. s removes the entry
    let op = lg::TrimOp {
        from_time: t(0, 0),
        to_time: t(10, u32::MAX),
        ..Default::default()
    };
    assert_eq!(call(&mut s, O, "log", "trim", &e(&op)).ret, 0);
    assert!(omap_keys(&s).is_empty());
}

/// Parsed key times follow `utime_t(sec, nsec)`: carry only when nsec > 1e9, sec saturates.
#[test]
fn timeindex_parse_utime_ctor_rules() {
    let mut s = MemStore::new();
    let o = s.objects.entry(O.into()).or_default();
    for k in [
        "1_5.1000000000_a",
        "1_5.1000000001_b",
        "1_-1.2000000000_c", // sec -1 -> u32::MAX, +2 saturates
    ] {
        o.omap.insert(k.as_bytes().to_vec(), b"v".to_vec());
    }
    let r = tlist(&mut s, t(1, 0), "1_", t(0, 0), 10);
    let ts: Vec<_> = r
        .entries
        .iter()
        .map(|e| (e.key_ext.clone(), e.key_ts))
        .collect();
    assert_eq!(
        ts,
        [
            (b"c".to_vec(), t(u32::MAX, 0)),
            (b"a".to_vec(), t(5, 1_000_000_000)),
            (b"b".to_vec(), t(6, 1)),
        ]
    );
}
