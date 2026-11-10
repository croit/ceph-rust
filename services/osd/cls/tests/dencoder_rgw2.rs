// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Byte-exact decode/re-encode of oracle fixtures (testdata/gen-dencoder-rgw2.sh) for the stage-2
//! rgw types (lifecycle, usage log), plus hand-derived bytes for what the oracle has no sample of.
mod common;
use cls::rgw::{lc, usage};
use common::*;
use denc::{Decode, Decoder, Encode};

#[test]
fn lc_types() {
    rt::<lc::LcEntry>("cls_rgw_lc_entry");
    rt::<lc::LcEntryEnv>("cls_rgw_lc_get_entry_ret");
    rt::<lc::LcEntryEnv>("cls_rgw_lc_set_entry_op");
}

#[test]
fn usage_types() {
    rt::<usage::UsageData>("rgw_usage_data");
    rt::<usage::S3SelectUsage>("rgw_s3select_usage_data");
    rt::<usage::UsageEntry>("rgw_usage_log_entry");
    rt::<usage::UsageInfo>("rgw_usage_log_info");
    rt::<usage::UsageAddOp>("rgw_cls_usage_log_add_op");
    rt::<usage::UsageReadOp>("rgw_cls_usage_log_read_op");
    rt::<usage::UsageReadRet>("rgw_cls_usage_log_read_ret");
    rt::<usage::UsageTrimOp>("rgw_cls_usage_log_trim_op");
}

/// `cls_rgw_lc_obj_head` (2,2) has no oracle sample: start_date u64, marker string,
/// shard_rollover_date u64.
#[test]
fn lc_head_bytes() {
    let h = lc::LcHead {
        start_date: 5,
        marker: "ab".into(),
        shard_rollover_date: 9,
    };
    let want = cat(&[
        &[2, 2],
        &(8u32 + 4 + 2 + 8).to_le_bytes(),
        &u64b(5),
        &2u32.to_le_bytes(),
        b"ab",
        &u64b(9),
    ]);
    assert_eq!(e(&h), want);
    assert_eq!(d::<lc::LcHead>(&want), h);
}

/// list_entries reply: envelope version echoes the request's struct_v; <= 2 = map form.
#[test]
fn lc_list_ret_forms() {
    let ent = |b: &str, st| lc::LcEntry {
        bucket: b.into(),
        start_time: 7,
        status: st,
    };
    let v3 = lc::LcListRet {
        entries: vec![ent("a", 1), ent("b", 2)],
        is_truncated: true,
        compat_v: 3,
    };
    let b3 = e(&v3);
    assert_eq!(&b3[..2], &[3, 1]);
    assert_eq!(d::<lc::LcListRet>(&b3), v3);
    let v2 = lc::LcListRet {
        compat_v: 2,
        ..v3.clone()
    };
    let b2 = e(&v2);
    assert_eq!(&b2[..2], &[2, 1]);
    // body: u32 n, (string, i32)*, bool
    let want_body = cat(&[
        &2u32.to_le_bytes(),
        &1u32.to_le_bytes(),
        b"a",
        &1i32.to_le_bytes(),
        &1u32.to_le_bytes(),
        b"b",
        &2i32.to_le_bytes(),
        &[1],
    ]);
    assert_eq!(&b2[6..], want_body.as_slice());
    let back: lc::LcListRet = d(&b2);
    assert_eq!(back.entries.len(), 2);
    assert_eq!(back.entries[1].status, 2);
    assert!(back.is_truncated);
    // never panics on garbage
    let _ = lc::LcListRet::decode(&mut Decoder::new(&[3, 1, 200, 0, 0, 0, 1]));
    let _ = v3.encode_to_vec().unwrap();
}
