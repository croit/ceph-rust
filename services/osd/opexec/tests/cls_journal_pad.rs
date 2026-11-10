// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! `journal.append` padding follows the osdmap the executor runs under (review F6, spec cls_journal.md append).
mod common;
use common::*;
use opwire::OsdOp;

fn append(max: u64, data: &[u8]) -> OsdOp {
    let mut e = denc::Encoder::new();
    e.u64(max).unwrap();
    e.bytes(data).unwrap();
    OsdOp::call(b"journal", b"append", &e.into_vec())
}

/// Object size after `journal.append(b"hello")` on a fresh object under `map`.
fn size_after_append(map: opexec::ClsMap) -> u64 {
    let mut pg = TPg::new();
    pg.cls_map = map;
    let mut eng = engine(&pg);
    let mut out = run(
        &mut pg,
        &mut eng,
        1,
        1,
        client(7),
        mkop(b"j", vec![append(1 << 20, b"hello")]),
    );
    out.extend(settle(&mut pg, &mut eng));
    assert_eq!(reply_of(&mut out, 1, 1).unwrap().result, 0);
    let mut out = run(
        &mut pg,
        &mut eng,
        1,
        2,
        client(7),
        mkop(b"j", vec![OsdOp::stat()]),
    );
    let r = reply_of(&mut out, 1, 2).unwrap();
    assert_eq!(r.result, 0);
    u64::from_le_bytes(r.ops[0].outdata[..8].try_into().unwrap())
}

#[test]
fn journal_append_pads_only_on_octopus_maps() {
    // require_min_compat_client < octopus: no padding
    assert_eq!(size_after_append(opexec::ClsMap::default()), 5);
    // >= octopus: padded to the 4096 allocation unit
    let pad = opexec::ClsMap {
        journal_pad: true,
        pool_stripe_width: 0,
    };
    assert_eq!(size_after_append(pad), 4096);
    // pool stripe width rounds the unit up
    let striped = opexec::ClsMap {
        journal_pad: true,
        pool_stripe_width: 6000,
    };
    assert_eq!(size_after_append(striped), 6000);
}
