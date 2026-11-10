// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! RGW-family classes through the real executor: RGW-private negative return (-2300) passthrough,
//! `subop_num` (ops processed so far incl. nested primitives) reaching the bilog key, output delivery on -EFBIG,
//! per-class unsupported counters.
mod common;
use cls::rgw::types::*;
use common::*;
use denc::Encode;
use opexec::Engine;
use opwire::{MOSDOpReply, OmapValsOut, OsdOp};

fn go(pg: &mut TPg, eng: &mut Engine, tid: u64, ops: Vec<OsdOp>) -> MOSDOpReply {
    let mut outs = run(pg, eng, 1, tid, client(7), mkop(b".dir.b.0", ops));
    reply_of(&mut outs, 1, tid).expect("reply")
}
fn enc<T: Encode>(v: &T) -> Vec<u8> {
    v.encode_to_vec().unwrap()
}
fn call(m: &str, input: &[u8]) -> OsdOp {
    OsdOp::call(b"rgw", m.as_bytes(), input)
}

#[test]
fn guard_result_2300_and_subop_num_through_the_executor() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    // 1: create + init index
    let r = go(
        &mut pg,
        &mut eng,
        1,
        vec![OsdOp::create(false), call("bucket_init_index", &[])],
    );
    assert_eq!(r.result, 0);
    // 2: prepare "k"
    let prep = ObjPrepareOp {
        op: op::ADD,
        tag: "t".into(),
        key: ObjKey::new("k", ""),
        ..Default::default()
    };
    let r = go(
        &mut pg,
        &mut eng,
        2,
        vec![call("bucket_prepare_op", &enc(&prep))],
    );
    assert_eq!(r.result, 0);
    // 3: stat, stat, complete(log_op): 2 outer ops precede the call
    let comp = ObjCompleteOp {
        op: op::ADD,
        op_tag: "t".into(),
        key: ObjKey::new("k", ""),
        log_op: true,
        ..Default::default()
    };
    let r = go(
        &mut pg,
        &mut eng,
        3,
        vec![
            OsdOp::stat(),
            OsdOp::stat(),
            call("bucket_complete_op", &enc(&comp)),
        ],
    );
    assert_eq!(r.result, 0);
    // bilog key: 80 "0_" + index_ver(11 digits) . last_user_version(before this msg) . subop
    let r = go(
        &mut pg,
        &mut eng,
        4,
        vec![OsdOp::omap_get_vals(b"", 100, b"\x800_")],
    );
    let out: OmapValsOut = denc::from_slice(&r.ops[0].outdata).unwrap();
    let keys: Vec<Vec<u8>> = out.vals.keys().map(|k| k.to_vec()).collect();
    assert_eq!(keys.len(), 1, "{keys:?}");
    assert!(keys[0].starts_with(b"\x800_00000000001."), "{keys:?}");
    assert!(
        keys[0].ends_with(b".5"),
        "subop = 2 outer ops + 3 nested (header, entry read, entry write), as classic: {keys:?}"
    );

    // 4: RGW-private negative return passes through unchanged (not an errno)
    let h = DirHeader {
        new_instance: InstanceEntry {
            reshard_status: reshard::IN_PROGRESS,
        },
        ..Default::default()
    };
    let r = go(&mut pg, &mut eng, 5, vec![OsdOp::omap_set_header(enc(&h))]);
    assert_eq!(r.result, 0);
    let g = GuardOp { ret_err: -2300 };
    let r = go(
        &mut pg,
        &mut eng,
        6,
        vec![call("guard_bucket_resharding", &enc(&g))],
    );
    assert_eq!(r.result, -2300);
    assert_eq!(r.ops[0].rval, -2300);
    // the guard vetoes a compound message: nothing after it runs, nothing is written
    let r = go(
        &mut pg,
        &mut eng,
        7,
        vec![
            call("guard_bucket_resharding", &enc(&g)),
            call("bucket_prepare_op", &enc(&prep)),
        ],
    );
    assert_eq!(r.result, -2300);
}

#[test]
fn efbig_delivers_output() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    go(
        &mut pg,
        &mut eng,
        1,
        vec![OsdOp::create(false), call("bucket_init_index", &[])],
    );
    // 30 noncurrent version entries: a 1-entry page can never make progress
    let mut kv = std::collections::BTreeMap::new();
    for i in 0..30 {
        let e = DirEntry {
            key: ObjKey::new(&format!("n{i:02}"), "x"),
            flags: flag::VER,
            versioned_epoch: 1,
            ..Default::default()
        };
        kv.insert(cls::rgw::keys::list_key(&e), enc(&e));
    }
    go(&mut pg, &mut eng, 2, vec![OsdOp::omap_set_vals(&kv)]);
    let lop = ListOp {
        num_entries: 1,
        ..Default::default()
    };
    let r = go(&mut pg, &mut eng, 3, vec![call("bucket_list", &enc(&lop))]);
    assert_eq!(r.result, -27, "-EFBIG");
    let out: ListRet = denc::from_slice(&r.ops[0].outdata).unwrap();
    assert!(out.is_truncated && out.dir.m.is_empty());
    assert_eq!(out.marker.name, b"n07\x01");
}

#[test]
fn unsupported_class_counted() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let before = cls::unsupported::count("lua");
    let r = go(
        &mut pg,
        &mut eng,
        1,
        vec![OsdOp::create(false), OsdOp::call(b"lua", b"eval_json", &[])],
    );
    assert_eq!(r.result, -1, "unknown class -> EPERM (classic parity)");
    assert_eq!(cls::unsupported::count("lua"), before + 1);
    let r = go(
        &mut pg,
        &mut eng,
        2,
        vec![call("set_bucket_resharding2", &[])],
    );
    assert_eq!(
        r.result, -95,
        "unregistered method of a known class -> EOPNOTSUPP"
    );
    assert!(cls::unsupported::count("rgw") >= 1);
    // a registered class the default `osd_class_load_list` loads: an unregistered method is EOPNOTSUPP, never EPERM;
    // `sdk` is registered but not loaded (cls.md 2.1), so the whole message fails at the load policy first
    let policy = opexec::clsx::ClassPolicy::default();
    for class in cls::CLASSES {
        let r = go(
            &mut pg,
            &mut eng,
            3,
            vec![OsdOp::call(class.as_bytes(), b"no_such_method", &[])],
        );
        if policy.loadable(class) {
            assert_eq!(r.result, -95, "{class}: unknown method -> EOPNOTSUPP");
        } else {
            assert_eq!(r.result, -1, "{class}: not on osd_class_load_list -> EPERM");
        }
    }
}
