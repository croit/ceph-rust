// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
//! Write-ordered ops must not carry a read-directing flag (client-ops 16.8): BALANCE_READS, LOCALIZE_READS or
//! EC_DIRECT_READ on a mutating message (even without the RWORDERED client flag) or on an RWORDERED read -> -EINVAL,
//! a plain error reply before execution. A plain read with BALANCE/LOCALIZE is fine.
mod common;
use common::*;
use opwire::{OsdOp, errno, flag as mflag};

fn go(pg: &mut TPg, eng: &mut opexec::Engine, tid: u64, ops: Vec<OsdOp>, flags: u32) -> i32 {
    let mut op = mkop(b"o", ops);
    op.flags |= flags;
    let mut outs = run(pg, eng, 1, tid, client(7), op);
    reply_of(&mut outs, 1, tid).expect("reply").result
}

#[test]
fn write_ordered_ops_reject_direct_read_flags() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    assert_eq!(
        go(
            &mut pg,
            &mut eng,
            1,
            vec![OsdOp::write(0, b"v".to_vec())],
            0
        ),
        0
    );
    let direct = [
        mflag::BALANCE_READS,
        mflag::LOCALIZE_READS,
        mflag::EC_DIRECT_READ,
    ];
    let mut tid = 10;
    for f in direct {
        // a mutating message is write-ordered without the RWORDERED flag
        let entries = pg.entries.len();
        tid += 1;
        assert_eq!(
            go(
                &mut pg,
                &mut eng,
                tid,
                vec![OsdOp::write(0, b"x".to_vec())],
                f
            ),
            -errno::EINVAL,
            "write + {f:#x}"
        );
        assert_eq!(pg.entries.len(), entries, "plain error, no log entry");
        // an RWORDERED read too
        tid += 1;
        assert_eq!(
            go(
                &mut pg,
                &mut eng,
                tid,
                vec![OsdOp::read(0, 1)],
                mflag::RWORDERED | f
            ),
            -errno::EINVAL,
            "RWORDERED read + {f:#x}"
        );
        // the same read bits without write ordering are served
        tid += 1;
        assert_eq!(
            go(&mut pg, &mut eng, tid, vec![OsdOp::read(0, 1)], f),
            0,
            "plain read + {f:#x}"
        );
    }
    // the rejected writes changed nothing
    assert_eq!(go(&mut pg, &mut eng, 100, vec![OsdOp::read(0, 8)], 0), 0);
}
