// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use denc::types::{Eversion, PgT};
use opwire::{MOSDOpReply, OsdOp, flag, op, opflag};
use rustyrados::*;

fn route() -> ReadRoute {
    ReadRoute {
        direct_read: false,
        base_pool: 7,
        osd: 2,
        session: 3,
        pg: PgT { pool: 7, seed: 4 },
        hash: 55,
        epoch: 9,
        features: 0,
        generation: 1,
        pool: rustyrados::PoolRoute::Replicated,
    }
}
fn request(
    operations: Vec<OsdOp>,
    access: Access,
    legacy_reply: bool,
    legacy_write: bool,
) -> CompoundRequest {
    CompoundRequest {
        target: Target {
            pool: 7,
            object: b"legacy-write".to_vec(),
            namespace: vec![0, 255],
            locator: vec![],
        },
        access,
        context: RequestContext {
            legacy_reply,
            write_op: legacy_write.then_some(WriteOpReply::Legacy),
            ..Default::default()
        },
        operations,
        max_output_bytes: 64,
    }
}

#[test]
fn outgoing_returnvec_only_when_neither_legacy_policy_selected() {
    // (legacy_reply, legacy_write, vector, expected base flags)
    for (legacy_reply, legacy_write, operations, base) in [
        (
            false,
            false,
            vec![OsdOp::write(0, vec![42])],
            flag::WRITE | flag::RWORDERED | flag::ONDISK,
        ),
        (
            true,
            false,
            vec![OsdOp::call(b"hello", b"say_hello", b"")],
            flag::READ | flag::ONDISK,
        ),
        (
            false,
            true,
            vec![OsdOp::write(0, vec![42])],
            flag::WRITE | flag::RWORDERED | flag::ONDISK,
        ),
    ] {
        let mut q = ObjectQueue::new(1, 4096, 101).unwrap();
        let access = if legacy_reply {
            Access::Read
        } else {
            Access::Write
        };
        let t = q
            .submit_compound(request(operations, access, legacy_reply, legacy_write))
            .unwrap();
        let d = q.dispatch(t, route()).unwrap();
        assert_eq!(
            d.message.flags & (flag::WRITE | flag::RWORDERED | flag::READ | flag::ONDISK),
            base
        );
        assert_eq!(
            d.message.flags & flag::RETURNVEC,
            if legacy_reply || legacy_write {
                0
            } else {
                flag::RETURNVEC
            }
        );
        q.cancel(t).unwrap();
        q.poll_into(&mut [None]);
    }
}

#[test]
fn admission_rejects_read_nonwrite_access_and_both_flags_without_credit() {
    let mut q = ObjectQueue::new(4, 4096, 102).unwrap();
    for r in [
        // READ is outside the write allowlist.
        request(vec![OsdOp::read(0, 4)], Access::ReadWrite, false, true),
        // GETXATTR is supported normally but outside the write allowlist.
        request(vec![OsdOp::getxattr(b"a")], Access::ReadWrite, false, true),
        // Mixed vector with one out-of-allowlist op.
        request(
            vec![OsdOp::write(0, vec![42]), OsdOp::read(0, 4)],
            Access::ReadWrite,
            false,
            true,
        ),
        // Non-write-capable access.
        request(vec![OsdOp::write(0, vec![42])], Access::Read, false, true),
        // Both legacy flags are mutually exclusive.
        request(
            vec![OsdOp::call(b"hello", b"say_hello", b"")],
            Access::Read,
            true,
            true,
        ),
    ] {
        assert_eq!(
            q.submit_compound(r).unwrap_err().reason,
            AdmissionError::InvalidOperation
        );
    }
    assert_eq!(q.outstanding(), 0);
    assert_eq!(q.charged_bytes(), 0);
}

#[test]
fn allowlist_ops_are_admitted_with_write_capable_access() {
    let mut q = ObjectQueue::new(1, 8192, 103).unwrap();
    for operations in [
        vec![OsdOp::write(0, vec![1])],
        vec![OsdOp::writefull(vec![1])],
        vec![OsdOp::append(vec![1])],
        vec![OsdOp::zero(0, 4)],
        vec![OsdOp::truncate(4)],
        vec![OsdOp::delete()],
        vec![OsdOp::create(false)],
        vec![OsdOp::omap_set_header(vec![1])],
        vec![OsdOp::rollback(3)],
        vec![OsdOp::writesame(0, 4, vec![9])],
        vec![OsdOp::setxattr(b"a", &[1])],
        vec![OsdOp::rmxattr(b"a")],
        vec![OsdOp::cmpxattr(
            b"a",
            &[1],
            opwire::consts::cmp::EQ,
            opwire::consts::cmp::MODE_STRING,
        )],
        vec![OsdOp::assert_version(1)],
        vec![OsdOp::stat()],
        vec![OsdOp::cmpext(0, vec![1])],
        vec![OsdOp::alloc_hint_op(u64::MAX, 4096, u32::MAX)],
    ] {
        let t = q
            .submit_compound(request(operations, Access::ReadWrite, false, true))
            .unwrap();
        q.cancel(t).unwrap();
        q.poll_into(&mut [None]);
        assert_eq!(q.outstanding(), 0);
        assert_eq!(q.charged_bytes(), 0);
    }
}

#[test]
fn guarded_basic_write_and_readonly_vector_admitted_with_readwrite() {
    let mut q = ObjectQueue::new(1, 8192, 104).unwrap();
    // Guarded mutation vector: assert version, write, stat.
    let t = q
        .submit_compound(request(
            vec![
                OsdOp::assert_version(5),
                OsdOp::write(0, vec![42, 43]),
                OsdOp::stat(),
            ],
            Access::ReadWrite,
            false,
            true,
        ))
        .unwrap();
    let d = q.dispatch(t, route()).unwrap();
    assert_eq!(d.message.flags & flag::RETURNVEC, 0);
    assert_eq!(
        d.message.ops.iter().map(|o| o.op).collect::<Vec<_>>(),
        vec![op::ASSERT_VER, op::WRITE, op::STAT]
    );
    q.cancel(t).unwrap();
    q.poll_into(&mut [None]);
    // The policy names the C write-operation API, not a mutating
    // transaction: a read-only vector with write-capable access is
    // admitted and keeps the actual server status.
    let t = q
        .submit_compound(request(
            vec![OsdOp::stat(), OsdOp::cmpext(0, vec![1])],
            Access::ReadWrite,
            false,
            true,
        ))
        .unwrap();
    q.cancel(t).unwrap();
    q.poll_into(&mut [None]);
    assert_eq!(q.outstanding(), 0);
    assert_eq!(q.charged_bytes(), 0);
}

#[test]
fn successful_write_waits_for_ondisk_and_keeps_actual_vector_and_version() {
    let mut q = ObjectQueue::new(1, 4096, 105).unwrap();
    let t = q
        .submit_compound(request(
            vec![OsdOp::write(0, vec![42, 43])],
            Access::Write,
            false,
            true,
        ))
        .unwrap();
    let d = q.dispatch(t, route()).unwrap();
    assert_eq!(d.message.flags & flag::RETURNVEC, 0);
    // Early ACK: no write success before ONDISK.
    let mut early = MOSDOpReply::for_request(&d.message, 9);
    early.flags &= !u64::from(flag::ONDISK);
    assert!(!q.reply(t, 2, 3, early).unwrap());
    assert!(q.is_pending(t));
    assert_eq!(q.poll_into(&mut [None]), 0);
    // Durable reply: actual overall/per-op/version are retained raw.
    let durable = MOSDOpReply::for_request(&d.message, 9);
    let mut durable = durable;
    durable.set_versions(Eversion::new(9, 7), 31337);
    assert!(q.reply(t, 2, 3, durable).unwrap());
    let mut out = [None];
    assert_eq!(q.poll_into(&mut out), 1);
    assert!(matches!(
        &out[0].as_ref().unwrap().outcome,
        ReadOutcome::RemoteCompound {
            publication: rustyrados::ReadPublication::Reply,
            result: 0,
            user_version: 31337,
            replay_version,
            operations
        }
        if *replay_version == Eversion::new(9, 7)
            && operations.len() == 1
            && operations[0].op == op::WRITE
            && operations[0].rval == 0
            && operations[0].outdata.is_empty()
            && operations[0].extent().offset == 0
            && operations[0].extent().length == 2
    ));
    assert_eq!(q.charged_bytes(), 0);
}

#[test]
fn negative_overall_completes_without_fabricating_success() {
    let mut q = ObjectQueue::new(1, 4096, 106).unwrap();
    let t = q
        .submit_compound(request(
            vec![OsdOp::write(0, vec![42])],
            Access::Write,
            false,
            true,
        ))
        .unwrap();
    let f = q.fence();
    let d = q.dispatch(t, route()).unwrap();
    // Negative overall with the unexecuted request descriptor echoed.
    let mut r = MOSDOpReply::for_request(&d.message, 9);
    r.result = -5;
    assert!(q.reply(t, 2, 3, r).unwrap());
    let mut out = [None];
    assert_eq!(q.poll_into(&mut out), 1);
    assert!(matches!(
        &out[0].as_ref().unwrap().outcome,
        ReadOutcome::RemoteCompound {
            result,
            operations,
            ..
        }
        if *result == -5
            && operations.len() == 1
            && operations[0].op == op::WRITE
            && operations[0].rval == 0
            && operations[0].outdata.is_empty()
    ));
    assert!(matches!(
        q.fence_status(f),
        Ok(FenceStatus::Ready(Err((
            _,
            WriteFailure::Remote {
                result: -5,
                op_result: 0
            }
        ))))
    ));
    assert_eq!(q.charged_bytes(), 0);
}

#[test]
fn failok_negative_perop_preserved_with_positive_overall() {
    let mut q = ObjectQueue::new(1, 4096, 107).unwrap();
    let mut cmp = OsdOp::cmpxattr(
        b"a",
        &[1],
        opwire::consts::cmp::EQ,
        opwire::consts::cmp::MODE_STRING,
    );
    cmp.flags = opflag::FAILOK;
    let t = q
        .submit_compound(request(
            vec![cmp, OsdOp::write(0, vec![42])],
            Access::ReadWrite,
            false,
            true,
        ))
        .unwrap();
    let d = q.dispatch(t, route()).unwrap();
    assert_eq!(d.message.flags & flag::RETURNVEC, 0);
    // FAILOK comparison fails per-op while the overall transaction succeeds.
    let mut r = MOSDOpReply::for_request(&d.message, 9);
    r.ops[0].rval = -5;
    assert!(q.reply(t, 2, 3, r).unwrap());
    let mut out = [None];
    assert_eq!(q.poll_into(&mut out), 1);
    assert!(matches!(
        &out[0].as_ref().unwrap().outcome,
        ReadOutcome::RemoteCompound {
            result: 0,
            operations,
            ..
        }
        if operations.len() == 2
            && operations[0].op == op::CMPXATTR
            && operations[0].rval == -5
            && operations[1].op == op::WRITE
            && operations[1].rval == 0
    ));
    assert_eq!(q.charged_bytes(), 0);
}

#[test]
fn positive_comparator_status_is_preserved_for_both_server_transaction_paths() {
    for mode in [WriteOpReply::Legacy, WriteOpReply::ReturnVector] {
        let mut q = ObjectQueue::new(1, 4096, 108).unwrap();
        let cmp = OsdOp::cmpxattr(
            b"a",
            &[1],
            opwire::consts::cmp::EQ,
            opwire::consts::cmp::MODE_STRING,
        );
        // Legacy no-op/read-only vector can retain positive status; an actual
        // ReturnVector mutation does too. The client must not guess normalization.
        let operations = if mode == WriteOpReply::Legacy {
            vec![cmp]
        } else {
            vec![OsdOp::write(0, vec![42]), cmp]
        };
        let mut req = request(operations, Access::ReadWrite, false, false);
        req.context.write_op = Some(mode);
        let t = q.submit_compound(req).unwrap();
        let d = q.dispatch(t, route()).unwrap();
        let mut r = MOSDOpReply::for_request(&d.message, 9);
        r.result = 1;
        r.ops.last_mut().unwrap().rval = 1;
        assert!(q.reply(t, 2, 3, r).unwrap());
        let mut out = [None];
        assert_eq!(q.poll_into(&mut out), 1);
        assert!(matches!(&out[0].as_ref().unwrap().outcome,
            ReadOutcome::RemoteCompound {result:1,operations,..}
            if operations.last().unwrap().rval == 1));
        assert_eq!(q.charged_bytes(), 0);
    }
}

#[test]
fn write_api_modes_preserve_write_only_map_policy_even_with_read_guards() {
    for mode in [
        None,
        Some(WriteOpReply::Legacy),
        Some(WriteOpReply::ReturnVector),
    ] {
        let mut q = ObjectQueue::new(1, 4096, 109).unwrap();
        let mut req = request(
            vec![OsdOp::assert_version(2), OsdOp::write(0, vec![1])],
            Access::ReadWrite,
            false,
            false,
        );
        req.context.write_op = mode;
        let t = q.submit_compound(req).unwrap();
        let flags = q.request_flags(t).unwrap();
        assert_eq!(
            flags & (flag::WRITE | flag::RWORDERED),
            flag::WRITE | flag::RWORDERED
        );
        assert_eq!(
            flags & flag::READ,
            if mode.is_none() { flag::READ } else { 0 }
        );
        {
            let mut map = osdmap::OsdMap::default();
            map.pools.insert(7, osdmap::pool::PgPool::default());
            map.flags = osdmap::consts::map_flags::PAUSERD;
            assert_eq!(map_pauses_request(&map, 7, flags), mode.is_none());
            map.flags = osdmap::consts::map_flags::PAUSEWR;
            assert!(map_pauses_request(&map, 7, flags));
            map.flags = osdmap::consts::map_flags::FULL;
            assert!(map_pauses_request(&map, 7, flags));
        }
        let d = q.dispatch(t, route()).unwrap();
        assert_eq!(
            d.message.flags & (flag::READ | flag::WRITE),
            flags & (flag::READ | flag::WRITE)
        );
        assert_eq!(
            d.message.flags & flag::RETURNVEC,
            if mode == Some(WriteOpReply::Legacy) {
                0
            } else {
                flag::RETURNVEC
            }
        );
        q.cancel(t).unwrap();
        q.poll_into(&mut [None]);
    }
}

#[test]
fn omap_write_modes_preserve_policy_durable_reply_and_narrow_admission() {
    for mode in [
        None,
        Some(WriteOpReply::Legacy),
        Some(WriteOpReply::ReturnVector),
    ] {
        let mut q = ObjectQueue::new(1, 8192, 110).unwrap();
        let mut compare = OsdOp::new(op::OMAP_CMP);
        compare.indata = denc::to_vec(&opwire::OmapCmpIn::from([(
            b"a".to_vec(),
            (vec![0, 255], 1),
        )]))
        .unwrap()
        .into();
        let mut range = OsdOp::new(op::OMAP_RM_KEY_RANGE);
        range.indata = denc::to_vec(&opwire::OmapRmKeyRangeIn {
            begin: b"b".to_vec(),
            end: b"z".to_vec(),
        })
        .unwrap()
        .into();
        let operations = vec![
            compare,
            OsdOp::omap_set_vals(&Default::default()),
            OsdOp::omap_set_header(vec![1]),
            OsdOp::omap_rm_keys(&Default::default()),
            range,
            OsdOp::omap_clear(),
        ];
        let mut req = request(operations, Access::ReadWrite, false, false);
        req.context.write_op = mode;
        let t = q.submit_compound(req).unwrap();
        let d = q.dispatch(t, route()).unwrap();
        assert_eq!(
            d.message.flags & flag::RETURNVEC,
            if mode == Some(WriteOpReply::Legacy) {
                0
            } else {
                flag::RETURNVEC
            }
        );
        assert_eq!(
            d.message.flags & flag::READ,
            if mode.is_none() { flag::READ } else { 0 }
        );
        assert_ne!(d.message.flags & flag::WRITE, 0);
        let mut early = MOSDOpReply::for_request(&d.message, 9);
        early.flags &= !u64::from(flag::ONDISK);
        assert!(!q.reply(t, 2, 3, early).unwrap());
        assert!(q.is_pending(t));
        let durable = MOSDOpReply::for_request(&d.message, 9);
        assert!(q.reply(t, 2, 3, durable).unwrap());
        assert_eq!(q.poll_into(&mut [None]), 1);
        assert_eq!(q.charged_bytes(), 0);
        for operation in [OsdOp::omap_get_vals(b"", 1, b""), OsdOp::omap_get_header()] {
            if mode.is_some() {
                let mut req = request(vec![operation], Access::ReadWrite, false, false);
                req.context.write_op = mode;
                assert_eq!(
                    q.submit_compound(req).unwrap_err().reason,
                    AdmissionError::InvalidOperation
                );
                assert_eq!(q.outstanding(), 0);
                assert_eq!(q.charged_bytes(), 0);
            }
        }
    }
}
