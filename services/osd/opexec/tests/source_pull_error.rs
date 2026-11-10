// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Failed source-pull transfers preserve negative errno through execution and duplicate replies.
mod common;
use common::*;
use opwire::{MOSDOp, MOSDOpReply, OsdOp, errno};

fn go(pg: &mut TPg, eng: &mut opexec::Engine, tid: u64, op: MOSDOp) -> MOSDOpReply {
    let mut outs = run(pg, eng, 1, tid, client(7), op);
    reply_of(&mut outs, 1, tid).expect("reply")
}

#[test]
fn source_pull_errors_are_failures_and_resends_keep_the_failure() {
    for full in [false, true] {
        for error in [errno::EIO, errno::EOPNOTSUPP] {
            for existing in [false, true] {
                let mut pg = TPg::new();
                let mut eng = engine(&pg);
                if existing {
                    let op = mkop(b"pull", vec![OsdOp::write(0, b"original".to_vec())]);
                    assert_eq!(go(&mut pg, &mut eng, 1, op).result, 0);
                }
                let write = if full {
                    OsdOp::writefull(Vec::new())
                } else {
                    OsdOp::write(0, Vec::new())
                };
                let mut op = mkop(b"pull", vec![write]);
                // The descriptor declared bytes, but the transfer failed and supplied no payload.
                let mut extent = op.ops[0].extent();
                extent.length = 4096;
                op.ops[0].set_extent(extent);
                op.source_pull_error = Some(-error);
                let first = go(&mut pg, &mut eng, 2, op.clone());
                assert_eq!(first.result, -error, "full={full}, existing={existing}");
                assert_eq!(first.ops[0].rval, -error);
                let entries = pg.entries.len();
                // A resend must replay the failed request, even if this transfer succeeded.
                op.source_pull_error = None;
                op.ops[0].indata = vec![b'X'; 4096].into();
                let duplicate = go(&mut pg, &mut eng, 2, op);
                assert_eq!(duplicate.result, -error);
                assert_eq!(duplicate.ops[0].rval, -error);
                assert_eq!(duplicate.replay_version, first.replay_version);
                assert_eq!(
                    pg.entries.len(),
                    entries,
                    "the failed request is not executed twice"
                );
                let read = mkop(b"pull", vec![OsdOp::read(0, 0)]);
                let reply = go(&mut pg, &mut eng, 3, read);
                if existing {
                    assert_eq!(reply.result, 0);
                    assert_eq!(reply.ops[0].outdata, &b"original"[..]);
                } else {
                    assert_eq!(reply.result, -errno::ENOENT);
                }
            }
        }
    }
}

#[test]
fn source_pull_failure_with_inline_payload_cannot_take_fast_overwrite() {
    for error in [errno::EIO, errno::EOPNOTSUPP] {
        let mut pg = TPg::new();
        let mut eng = engine(&pg);
        let seed = mkop(b"pull", vec![OsdOp::write(0, b"original".to_vec())]);
        assert_eq!(go(&mut pg, &mut eng, 1, seed).result, 0);
        // A source-pull record can retain inline bytes when its READ fails.
        // Matching the descriptor length must not turn those bytes into a write.
        let mut op = mkop(b"pull", vec![OsdOp::write(0, b"replaced".to_vec())]);
        op.source_pull_error = Some(-error);
        let first = go(&mut pg, &mut eng, 2, op.clone());
        assert_eq!(first.result, -error);
        assert_eq!(first.ops[0].rval, -error);
        op.source_pull_error = None;
        let duplicate = go(&mut pg, &mut eng, 2, op);
        assert_eq!(duplicate.result, -error);
        assert_eq!(duplicate.replay_version, first.replay_version);
        let read = mkop(b"pull", vec![OsdOp::read(0, 0)]);
        assert_eq!(
            go(&mut pg, &mut eng, 3, read).ops[0].outdata,
            &b"original"[..]
        );
    }
}
