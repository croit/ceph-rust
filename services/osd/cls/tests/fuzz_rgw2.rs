// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Panic-freedom, RD/WR flag correctness and bounded outputs for the stage-2 rgw methods (olh,
//! bi_*, bilog, lc, legacy gc, usage, mp): valid inputs on a populated object must not trip the
//! flag enforcement (-EIO) and mutated / truncated / extended variants against clean, populated and
//! corrupted objects must never panic, never leave a failed call's writes behind and never produce
//! unbounded output.
mod common;
use cls::mem::MemStore;
use cls::rgw::gc::{DeferTagOp, RemoveTagsOp};
use cls::rgw::keys;
use cls::rgw::lc::*;
use cls::rgw::types::*;
use cls::rgw::usage::*;
use cls::rgw_gc::{GcChain, GcObjInfo, ListOp as GcListOp, SetEntryOp};
use common::*;
use denc::types::UTime;
use denc::{Encode, Encoder};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

const O: &str = "o";
/// Largest output any of these methods may produce for the test fixtures (list caps are 1000).
const MAX_OUT: usize = 4 << 20;

fn meta(size: u64) -> DirEntryMeta {
    DirEntryMeta {
        category: 1,
        size,
        accounted_size: size,
        mtime: UTime::new(100, 0),
        owner: "o".into(),
        ..Default::default()
    }
}

/// Index shard with plain + versioned entries and a bilog.
fn index_store() -> MemStore {
    let mut s = MemStore::new();
    ok(&mut s, O, "rgw", "bucket_init_index", &[]);
    for n in ["a", "b", "v"] {
        let p = ObjPrepareOp {
            op: op::ADD,
            tag: "t".into(),
            key: ObjKey::new(n, ""),
            ..Default::default()
        };
        s.call(O, "rgw", "bucket_prepare_op", &e(&p));
        let c = ObjCompleteOp {
            op_tag: "t".into(),
            key: ObjKey::new(n, ""),
            meta: meta(7),
            log_op: true,
            ..Default::default()
        };
        s.call(O, "rgw", "bucket_complete_op", &e(&c));
    }
    for (i, dm) in [("v1", false), ("v2", false), ("dm", true)] {
        s.env.now.sec += 1;
        if !dm {
            let en = DirEntry {
                key: ObjKey::new("v", i),
                exists: true,
                meta: meta(5),
                ..Default::default()
            };
            s.objects
                .get_mut(O)
                .unwrap()
                .omap
                .insert(keys::instance_key(&en.key, false), e(&en));
        }
        let l = LinkOlhOp {
            key: ObjKey::new("v", i),
            olh_tag: "tag".into(),
            delete_marker: dm,
            op_tag: "ot".into(),
            meta: meta(5),
            log_op: true,
            ..Default::default()
        };
        s.call(O, "rgw", "bucket_link_olh", &e(&l));
    }
    s
}

fn lc_store() -> MemStore {
    let mut s = MemStore::new();
    for b in ["b1", "b2"] {
        s.call(
            O,
            "rgw",
            "lc_set_entry",
            &e(&LcEntryEnv(LcEntry {
                bucket: b.into(),
                start_time: 1,
                status: 1,
            })),
        );
    }
    s.call(
        O,
        "rgw",
        "lc_put_head",
        &e(&LcPutHeadOp {
            head: LcHead::default(),
        }),
    );
    s
}

fn gc_store() -> MemStore {
    let mut s = MemStore::new();
    s.call(
        O,
        "rgw",
        "gc_set_entry",
        &e(&SetEntryOp {
            expiration_secs: 5,
            info: GcObjInfo {
                tag: "g".into(),
                chain: GcChain::default(),
                time: UTime::default(),
            },
        }),
    );
    s
}

fn usage_store() -> MemStore {
    let mut s = MemStore::new();
    for (ep, b) in [(3600u64, "b"), (7200, "c")] {
        let mut u = UsageEntry {
            owner: "u".into(),
            bucket: b.into(),
            epoch: ep,
            ..Default::default()
        };
        u.usage_map.insert("x".into(), UsageData::default());
        s.call(
            O,
            "rgw",
            "user_usage_log_add",
            &e(&UsageAddOp {
                info: UsageInfo { entries: vec![u] },
                user: Vec::new(),
            }),
        );
    }
    s
}

fn mp_store() -> MemStore {
    let mut s = MemStore::new();
    s.call(O, "rgw", "mp_upload_part_info_update", &mp_input());
    s
}

/// The object a method family runs on (their omap values would not decode as each other's).
fn populated(method: &str) -> MemStore {
    match method {
        m if m.starts_with("bucket_") || m.starts_with("bi_") => index_store(),
        m if m.starts_with("lc_") => lc_store(),
        m if m.starts_with("gc_") => gc_store(),
        m if m.contains("usage") => usage_store(),
        _ => mp_store(),
    }
}

fn manifest() -> Vec<u8> {
    let mut m = Encoder::new();
    m.versioned(8, 6, |e| {
        e.u64(1)?;
        e.u32(0)?;
        e.bool(false)?;
        e.versioned(6, 6, |e| e.raw(b"x"))?;
        e.u64(0)?;
        e.u64(0)?;
        "pfx".encode(e)?;
        e.u32(1)?;
        e.u64(0)?;
        e.versioned(2, 1, |e| e.raw(&[1; 4]))?;
        e.raw(&[0, 0])
    })
    .unwrap();
    m.into_vec()
}
fn mp_input() -> Vec<u8> {
    let mut o = Encoder::new();
    o.versioned(1, 1, |e| {
        "part.00000001".encode(e)?;
        e.versioned(7, 2, |e| {
            e.u32(1)?;
            e.u64(2)?;
            "etag".encode(e)?;
            UTime::new(1, 2).encode(e)?;
            e.raw(&manifest())?;
            e.versioned(2, 1, |e| {
                "none".encode(e)?;
                e.u64(0)?;
                e.u8(0)?;
                e.u32(0)
            })?;
            e.u64(2)?;
            std::collections::BTreeSet::<String>::new().encode(e)?;
            e.u8(0)?;
            "s".encode(e)
        })
    })
    .unwrap();
    o.into_vec()
}

/// (class, method, valid input) for every stage-2 method.
fn catalog() -> Vec<(&'static str, &'static str, Vec<u8>)> {
    let k = |n: &str, i: &str| ObjKey::new(n, i);
    let bi = |ty, idx: &[u8], en: &DirEntry| BiEntry {
        ty,
        idx: idx.to_vec(),
        data: e(en),
    };
    let plain = DirEntry {
        key: k("n", ""),
        exists: true,
        meta: meta(3),
        ..Default::default()
    };
    let trim_usage = UsageTrimOp {
        start_epoch: 0,
        end_epoch: u64::MAX,
        user: Vec::new(),
        bucket: Vec::new(),
    };
    let mut c = vec![
        (
            "rgw",
            "bucket_link_olh",
            e(&LinkOlhOp {
                key: k("v", "v3"),
                olh_tag: "tag".into(),
                op_tag: "o2".into(),
                meta: meta(1),
                log_op: true,
                ..Default::default()
            }),
        ),
        (
            "rgw",
            "bucket_unlink_instance",
            e(&UnlinkInstanceOp {
                key: k("v", "v2"),
                op_tag: "u".into(),
                olh_tag: "tag".into(),
                log_op: true,
                ..Default::default()
            }),
        ),
        (
            "rgw",
            "bucket_read_olh_log",
            e(&ReadOlhLogOp {
                olh: k("v", ""),
                olh_tag: "tag".into(),
                get_stales: true,
                ..Default::default()
            }),
        ),
        (
            "rgw",
            "bucket_trim_olh_log",
            e(&TrimOlhLogOp {
                olh: k("v", ""),
                ver: u64::MAX,
                olh_tag: "tag".into(),
            }),
        ),
        (
            "rgw",
            "bucket_clear_olh",
            e(&ClearOlhOp {
                key: k("v", ""),
                olh_tag: "tag".into(),
            }),
        ),
        (
            "rgw",
            "bi_get",
            e(&BiGetOp {
                key: k("a", ""),
                ty: bi::PLAIN,
            }),
        ),
        (
            "rgw",
            "bi_put",
            e(&BiPutOp {
                entry: bi(bi::PLAIN, b"n", &plain),
            }),
        ),
        (
            "rgw",
            "bi_put_entries",
            e(&BiPutEntriesOp {
                entries: vec![
                    bi(bi::PLAIN, b"n", &plain),
                    bi(bi::INSTANCE, b"\x801000_n\0ii", &plain),
                ],
                check_existing: true,
            }),
        ),
        (
            "rgw",
            "bi_list",
            e(&BiListOp {
                max: 50,
                ..Default::default()
            }),
        ),
        (
            "rgw",
            "bi_list",
            e(&BiListOp {
                max: 50,
                reshardlog: true,
                ..Default::default()
            }),
        ),
        (
            "rgw",
            "bi_log_list",
            e(&BiLogListOp {
                marker: Vec::new(),
                max: 50,
            }),
        ),
        (
            "rgw",
            "bi_log_trim",
            e(&BiLogTrimOp {
                start_marker: Vec::new(),
                end_marker: "99999999999".into(),
            }),
        ),
        ("rgw", "bi_log_resync", vec![]),
        ("rgw", "bi_log_stop", vec![]),
        (
            "rgw",
            "lc_get_entry",
            e(&LcMarkerOp {
                marker: "b1".into(),
            }),
        ),
        (
            "rgw",
            "lc_set_entry",
            e(&LcEntryEnv(LcEntry {
                bucket: "b3".into(),
                start_time: 2,
                status: 0,
            })),
        ),
        (
            "rgw",
            "lc_rm_entry",
            e(&LcEntryEnv(LcEntry {
                bucket: "b1".into(),
                ..Default::default()
            })),
        ),
        (
            "rgw",
            "lc_get_next_entry",
            e(&LcMarkerOp { marker: Vec::new() }),
        ),
        (
            "rgw",
            "lc_list_entries",
            e(&LcListOp {
                marker: Vec::new(),
                max_entries: 100,
                compat_v: 0,
            }),
        ),
        (
            "rgw",
            "lc_put_head",
            e(&LcPutHeadOp {
                head: LcHead {
                    start_date: 1,
                    marker: "m".into(),
                    shard_rollover_date: 2,
                },
            }),
        ),
        ("rgw", "lc_get_head", vec![]),
        (
            "rgw",
            "gc_set_entry",
            e(&SetEntryOp {
                expiration_secs: 9,
                info: GcObjInfo {
                    tag: "g2".into(),
                    ..Default::default()
                },
            }),
        ),
        (
            "rgw",
            "gc_defer_entry",
            e(&DeferTagOp {
                expiration_secs: 9,
                tag: "g".into(),
            }),
        ),
        (
            "rgw",
            "gc_list",
            e(&GcListOp {
                marker: Vec::new(),
                max: 10,
                expired_only: false,
            }),
        ),
        (
            "rgw",
            "gc_remove",
            e(&RemoveTagsOp {
                tags: vec!["g".into(), "zz".into()],
            }),
        ),
        (
            "rgw",
            "user_usage_log_add",
            e(&UsageAddOp {
                info: UsageInfo {
                    entries: vec![UsageEntry {
                        owner: "u".into(),
                        bucket: "b".into(),
                        epoch: 3600,
                        ..Default::default()
                    }],
                },
                user: Vec::new(),
            }),
        ),
        (
            "rgw",
            "user_usage_log_read",
            e(&UsageReadOp {
                end_epoch: u64::MAX,
                max_entries: 10,
                ..Default::default()
            }),
        ),
        ("rgw", "user_usage_log_trim", e(&trim_usage)),
        ("rgw", "usage_log_clear", vec![]),
        ("rgw", "mp_upload_part_info_update", mp_input()),
    ];
    c.push((
        "rgw",
        "bi_log_list",
        e(&BiLogListOp {
            marker: "x".into(),
            max: 0,
        }),
    ));
    c
}

#[test]
fn valid_inputs_respect_the_method_flags_and_bound_their_output() {
    for (class, method, input) in catalog() {
        let mut s = populated(method);
        let r = s.call(O, class, method, &input);
        assert_ne!(
            r.ret,
            cls::errno::EIO,
            "{method}: flag violation or decode fault"
        );
        assert!(r.out.len() <= MAX_OUT, "{method}: output {}", r.out.len());
        assert!(
            r.ret >= 0
                || r.ret == cls::errno::ENODATA
                || r.ret == cls::errno::ECANCELED
                || r.ret == cls::errno::ENOENT
                || r.ret == cls::errno::EEXIST,
            "{method}: unexpected {}",
            r.ret
        );
    }
}

#[test]
fn mutated_inputs_never_panic_and_failures_leave_no_trace() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for (class, method, valid) in catalog() {
        for round in 0..150 {
            let mut input = valid.clone();
            match round % 5 {
                0 => {
                    // flip a few bytes
                    for _ in 0..=rng.below(3) {
                        if !input.is_empty() {
                            let i = rng.below(input.len());
                            input[i] ^= 1 << rng.below(8);
                        }
                    }
                }
                1 => input.truncate(rng.below(input.len() + 1)),
                2 => input.extend((0..rng.below(40)).map(|_| rng.next() as u8)),
                3 => {
                    // overwrite a 4-byte window with a huge length / count
                    if input.len() >= 4 {
                        let i = rng.below(input.len() - 3);
                        input[i..i + 4].copy_from_slice(&[0xff, 0xff, 0xff, 0x7f]);
                    }
                }
                _ => {
                    input = (0..rng.below(64)).map(|_| rng.next() as u8).collect();
                }
            }
            for kind in 0..3 {
                let mut s = populated(method);
                if kind == 1 {
                    s.objects.get_mut(O).unwrap().omap.clear();
                }
                if kind == 2 {
                    let o = s.objects.get_mut(O).unwrap();
                    for v in o.omap.values_mut() {
                        v.truncate(v.len() / 2);
                    }
                    o.omap_header.truncate(7);
                }
                let before = s.objects.clone();
                let r = s.call(O, class, method, &input);
                assert!(r.out.len() <= MAX_OUT, "{method}: output {}", r.out.len());
                if r.ret < 0 {
                    assert_eq!(s.objects, before, "{method}: failed call left state behind");
                }
            }
        }
    }
}
