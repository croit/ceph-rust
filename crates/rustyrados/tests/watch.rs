// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use bytes::Bytes;
use denc::types::PgT;
use opwire::consts::{notify, watch_op};
use opwire::{MOSDOpReply, MWatchNotify, NotifyAckIn, flag};
use rustyrados::*;
fn target() -> Target {
    Target {
        pool: 7,
        object: b"watch".to_vec(),
        namespace: vec![],
        locator: vec![],
    }
}
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
fn msg(cookie: u64, opcode: u8) -> MWatchNotify {
    MWatchNotify {
        msg_ver: 1,
        opcode,
        cookie,
        notify_id: 99,
        bl: vec![42],
        ..Default::default()
    }
}

#[test]
fn control_wire_fields_and_ping_do_not_enter_write_fence() {
    let mut q = ObjectQueue::new(1, 1024, 0).unwrap();
    for (operation, subop, generation) in [
        (
            ControlOperation::Register {
                cookie: 7,
                timeout_seconds: 30,
            },
            watch_op::WATCH,
            0,
        ),
        (
            ControlOperation::Reconnect {
                cookie: 7,
                generation: 2,
            },
            watch_op::RECONNECT,
            2,
        ),
        (
            ControlOperation::Ping {
                cookie: 7,
                generation: 2,
            },
            watch_op::PING,
            2,
        ),
        (
            ControlOperation::Unwatch { cookie: 7 },
            watch_op::UNWATCH,
            0,
        ),
    ] {
        let ping = subop == watch_op::PING;
        let t = q
            .submit_control(ControlRequest {
                target: target(),
                operation,
            })
            .unwrap();
        let f = q.fence();
        assert_eq!(
            q.fence_status(f).unwrap(),
            if ping {
                FenceStatus::Ready(Ok(()))
            } else {
                FenceStatus::Pending
            }
        );
        let d = q.dispatch(t, route()).unwrap();
        assert_eq!(d.message.ops[0].watch().cookie, 7);
        assert_eq!(d.message.ops[0].watch().op, subop);
        assert_eq!(d.message.ops[0].watch().gen_, generation);
        assert_ne!(d.message.flags & flag::WRITE, 0);
        assert_eq!(
            d.message.flags & flag::RWORDERED != 0,
            subop == watch_op::UNWATCH
        );
        q.reply(t, 2, 3, MOSDOpReply::for_request(&d.message, 9))
            .unwrap();
        q.poll_into(&mut [None]);
    }
}

#[test]
fn notify_initial_id_is_not_final_and_ack_encodes_both_ids() {
    let mut q = ObjectQueue::new(1, 1024, 0).unwrap();
    let t = q
        .submit_control(ControlRequest {
            target: target(),
            operation: ControlOperation::Notify {
                cookie: 7,
                timeout_seconds: 3,
                payload: Bytes::from_static(b"hello"),
            },
        })
        .unwrap();
    let d = q.dispatch(t, route()).unwrap();
    let mut r = MOSDOpReply::for_request(&d.message, 9);
    r.ops[0].outdata = Bytes::copy_from_slice(&99u64.to_le_bytes());
    q.reply(t, 2, 3, r).unwrap();
    q.poll_into(&mut [None]);
    let t = q
        .submit_control(ControlRequest {
            target: target(),
            operation: ControlOperation::NotifyAck {
                cookie: 7,
                notify_id: 99,
                response: Bytes::from_static(b"ack"),
            },
        })
        .unwrap();
    let d = q.dispatch(t, route()).unwrap();
    let decoded: NotifyAckIn = denc::from_slice(&d.message.ops[0].indata).unwrap();
    assert_eq!(decoded.notify_id, 99);
    assert_eq!(decoded.cookie, 7);
    assert_eq!(decoded.reply, b"ack");
}

#[test]
fn registry_enforces_cookie_session_generation_and_removal_lifetime() {
    let mut r = WatchRegistry::new(2, 2, 100).unwrap();
    let h = r.reserve(target(), route(), WatchKind::Watch).unwrap();
    r.activate(h, 0).unwrap();
    assert!(!r.on_event(2, 4, msg(h.cookie(), notify::NOTIFY)).unwrap());
    assert!(r.on_event(2, 3, msg(h.cookie(), notify::NOTIFY)).unwrap());
    let generation = r
        .rebind(
            h,
            ReadRoute {
                session: 4,
                ..route()
            },
        )
        .unwrap();
    assert_eq!(generation, 1);
    assert_eq!(r.activate(h, 0), Err(WatchError::Stale));
    r.activate(h, 1).unwrap();
    assert!(!r.on_event(2, 3, msg(h.cookie(), notify::NOTIFY)).unwrap());
    r.remove(h).unwrap();
    assert!(r.poll().is_none());
    assert_eq!(r.charged_bytes(), 0);
    let next = r.reserve(target(), route(), WatchKind::Watch).unwrap();
    assert_ne!(next.cookie(), h.cookie());
    assert!(!r.on_event(2, 3, msg(h.cookie(), notify::NOTIFY)).unwrap());
}

#[test]
fn event_cap_cannot_hide_disconnect_and_overflow_is_not_an_ack() {
    let mut r = WatchRegistry::new(1, 1, 100).unwrap();
    let h = r.reserve(target(), route(), WatchKind::Watch).unwrap();
    r.activate(h, 0).unwrap();
    r.on_event(2, 3, msg(h.cookie(), notify::NOTIFY)).unwrap();
    assert_eq!(
        r.on_event(2, 3, msg(h.cookie(), notify::NOTIFY)),
        Err(WatchError::NoCredit)
    );
    r.on_event(2, 3, msg(h.cookie(), notify::DISCONNECT))
        .unwrap();
    assert_eq!(r.poll_error(), Some((h, WatchError::Disconnected)));
    assert!(r.poll_error().is_none());
    assert!(
        !r.on_event(2, 3, msg(h.cookie(), notify::DISCONNECT))
            .unwrap()
    );
    assert!(matches!(r.poll(), Some(WatchEvent::Notification { .. })));
    let base = r.charged_bytes();
    r.remove(h).unwrap();
    assert_eq!(r.charged_bytes(), 0);
    assert!(base > 0);
}

#[test]
fn early_notify_completion_matches_initial_id_and_final_is_once_only() {
    let mut r = WatchRegistry::new(1, 1, 100).unwrap();
    let h = r.reserve(target(), route(), WatchKind::Notify).unwrap();
    let mut m = msg(h.cookie(), notify::NOTIFY_COMPLETE);
    m.bl.clear();
    m.data = vec![0; 8];
    assert!(r.on_event(2, 3, m.clone()).unwrap());
    assert_eq!(r.initial_notify_id(h, 100), Err(WatchError::InvalidEvent));
    r.initial_notify_id(h, 99).unwrap();
    assert!(!r.on_event(2, 3, m).unwrap());
    assert!(matches!(
        r.poll(),
        Some(WatchEvent::NotifyComplete { notify_id: 99, .. })
    ));
    assert!(r.poll().is_none());
}

#[test]
fn byte_cap_faults_peer_and_errors_have_reserved_storage() {
    let mut r = WatchRegistry::new(1, 2, 10).unwrap();
    let h = r.reserve(target(), route(), WatchKind::Watch).unwrap();
    let mut m = msg(h.cookie(), notify::NOTIFY);
    m.bl = vec![0; 11];
    assert_eq!(r.on_event(2, 3, m), Err(WatchError::NoCredit));
    r.fault_route(2, 3, WatchError::NoCredit);
    assert_eq!(r.poll_error(), Some((h, WatchError::NoCredit)));
    assert!(r.poll().is_none());
    r.remove(h).unwrap();
    assert_eq!(r.charged_bytes(), 0);
}

#[test]
fn watermark_captures_delivery_prefix_and_excludes_later_arrivals() {
    let mut r = WatchRegistry::new(2, 4, 1024).unwrap();
    let h = r.reserve(target(), route(), WatchKind::Watch).unwrap();
    let empty = r.event_watermark();
    r.on_event(2, 3, msg(h.cookie(), notify::NOTIFY)).unwrap();
    let first = r.event_watermark();
    r.on_event(2, 3, msg(h.cookie(), notify::NOTIFY)).unwrap();
    let both = r.event_watermark();
    assert_eq!(r.events_drained(empty), Ok(true));
    assert_eq!(r.events_drained(first), Ok(false));
    assert!(r.poll().is_some());
    assert_eq!(r.events_drained(first), Ok(true));
    assert_eq!(r.events_drained(both), Ok(false));
    assert!(r.poll().is_some());
    assert_eq!(r.events_drained(both), Ok(true));
    let other = WatchRegistry::new(1, 1, 10).unwrap();
    assert_eq!(other.events_drained(both), Err(WatchError::Stale));
}

#[test]
fn watermark_removal_holes_and_close_preserve_delivery_and_error_boundaries() {
    let mut r = WatchRegistry::new(2, 4, 1024).unwrap();
    let a = r.reserve(target(), route(), WatchKind::Watch).unwrap();
    let b = r.reserve(target(), route(), WatchKind::Watch).unwrap();
    r.on_event(2, 3, msg(a.cookie(), notify::NOTIFY)).unwrap();
    r.on_event(2, 3, msg(b.cookie(), notify::NOTIFY)).unwrap();
    let captured = r.event_watermark();
    r.remove(b).unwrap();
    assert_eq!(r.events_drained(captured), Ok(false));
    r.on_event(2, 3, msg(a.cookie(), notify::NOTIFY)).unwrap();
    assert!(r.poll().is_some());
    assert_eq!(r.events_drained(captured), Ok(true));
    let later = r.event_watermark();
    r.fault_all(WatchError::Disconnected);
    assert_eq!(r.events_drained(later), Ok(true));
    assert!(r.poll().is_none());
    assert_eq!(r.poll_error(), Some((a, WatchError::Disconnected)));
    r.remove(a).unwrap();
    assert_eq!(r.charged_bytes(), 0);
}

#[test]
fn managed_suspension_blocks_old_ingress_without_reviving_terminal_server_fault() {
    let mut r = WatchRegistry::new(2, 4, 1024).unwrap();
    let managed = r.reserve(target(), route(), WatchKind::Watch).unwrap();
    let raw = r.reserve(target(), route(), WatchKind::Watch).unwrap();
    r.on_event(2, 3, msg(managed.cookie(), notify::NOTIFY))
        .unwrap();
    r.suspend(managed).unwrap();
    r.fault_unsuspended_route(2, 3, WatchError::Disconnected);
    assert_eq!(r.poll_error(), Some((raw, WatchError::Disconnected)));
    assert!(
        !r.on_event(2, 3, msg(managed.cookie(), notify::NOTIFY))
            .unwrap()
    );
    assert!(r.poll().is_some());
    r.bind_managed(
        managed,
        ReadRoute {
            session: 4,
            ..route()
        },
        2,
    )
    .unwrap();
    assert!(r.bind_managed(managed, route(), 1).is_err());
    assert!(
        !r.on_event(2, 3, msg(managed.cookie(), notify::NOTIFY))
            .unwrap()
    );
    assert!(
        r.on_event(2, 4, msg(managed.cookie(), notify::NOTIFY))
            .unwrap()
    );
    r.on_event(2, 4, msg(managed.cookie(), notify::DISCONNECT))
        .unwrap();
    assert!(r.bind_managed(managed, route(), 3).is_err());
    assert!(r.suspend(managed).is_err());
}

#[test]
fn removing_watch_keeps_prefix_and_error_but_cannot_be_revived_on_cleanup_route() {
    let mut r = WatchRegistry::new(1, 2, 1024).unwrap();
    let h = r.reserve(target(), route(), WatchKind::Watch).unwrap();
    r.activate(h, 0).unwrap();
    r.on_event(2, 3, msg(h.cookie(), notify::NOTIFY)).unwrap();
    let mark = r.event_watermark();
    r.fault(h, WatchError::NoCredit).unwrap();
    r.mark_removing(h).unwrap();
    assert!(!r.live(h));
    assert_eq!(r.events_drained(mark), Ok(false));
    let new = ReadRoute {
        session: 4,
        ..route()
    };
    r.bind_cleanup(h, new).unwrap();
    assert!(r.activate(h, 0).is_err());
    assert!(r.suspend(h).is_err());
    assert!(r.rebind(h, new).is_err());
    assert!(r.bind_managed(h, new, 1).is_err());
    assert!(!r.on_event(2, 4, msg(h.cookie(), notify::NOTIFY)).unwrap());
    assert_eq!(r.poll_error(), Some((h, WatchError::NoCredit)));
    assert!(r.poll().is_some());
    assert_eq!(r.events_drained(mark), Ok(true));
    r.remove(h).unwrap();
    assert_eq!(r.charged_bytes(), 0);
}

#[test]
fn timed_delivery_tracks_cookie_fifo_and_rejects_invalid_clocks_without_mutation() {
    let mut r = WatchRegistry::new(2, 4, 1024).unwrap();
    let a = r.reserve(target(), route(), WatchKind::Watch).unwrap();
    let b = r.reserve(target(), route(), WatchKind::Watch).unwrap();
    r.on_event_at(2, 3, msg(a.cookie(), notify::NOTIFY), 10)
        .unwrap();
    let mark = r.event_watermark();
    let charged = r.charged_bytes();
    assert_eq!(
        r.on_event_at(2, 3, msg(a.cookie(), notify::NOTIFY), 9),
        Err(WatchError::Clock)
    );
    assert_eq!(
        r.on_event_at(2, 3, msg(a.cookie(), notify::NOTIFY), u64::MAX),
        Err(WatchError::Clock)
    );
    assert_eq!(r.event_watermark(), mark);
    assert_eq!(r.charged_bytes(), charged);
    assert_eq!(r.oldest_event_us(a), Ok(Some(10)));
    r.on_event_at(2, 3, msg(b.cookie(), notify::NOTIFY), 11)
        .unwrap();
    r.on_event_at(2, 3, msg(a.cookie(), notify::NOTIFY), 12)
        .unwrap();
    assert_eq!(r.oldest_event_us(a), Ok(Some(10)));
    assert!(r.poll().is_some());
    assert_eq!(r.oldest_event_us(a), Ok(Some(12)));
    assert_eq!(r.oldest_event_us(b), Ok(Some(11)));
    r.suspend(a).unwrap();
    r.bind_managed(
        a,
        ReadRoute {
            session: 4,
            ..route()
        },
        1,
    )
    .unwrap();
    r.mark_removing(a).unwrap();
    assert_eq!(r.oldest_event_us(a), Ok(Some(12)));
    r.remove(b).unwrap();
    assert_eq!(r.oldest_event_us(b), Err(WatchError::Stale));
    r.fault_all(WatchError::Disconnected);
    assert_eq!(r.oldest_event_us(a), Ok(None));
}
#[test]
fn legacy_untimed_work_cannot_fabricate_health_for_any_matching_event() {
    let mut r = WatchRegistry::new(2, 4, 1024).unwrap();
    let a = r.reserve(target(), route(), WatchKind::Watch).unwrap();
    let b = r.reserve(target(), route(), WatchKind::Watch).unwrap();
    r.on_event_at(2, 3, msg(a.cookie(), notify::NOTIFY), 10)
        .unwrap();
    r.on_event(2, 3, msg(b.cookie(), notify::NOTIFY)).unwrap();
    assert_eq!(r.oldest_event_us(a), Ok(Some(10)));
    assert_eq!(r.oldest_event_us(b), Err(WatchError::InvalidEvent));
    r.on_event(2, 3, msg(a.cookie(), notify::NOTIFY)).unwrap();
    assert_eq!(r.oldest_event_us(a), Err(WatchError::InvalidEvent));
    r.remove(a).unwrap();
    assert_eq!(r.oldest_event_us(a), Err(WatchError::Stale));
    assert!(r.poll().is_some());
    assert_eq!(r.oldest_event_us(b), Ok(None));
}

#[test]
fn broker_pending_hint_distinguishes_handles_deliveries_and_reserved_errors() {
    let mut r = WatchRegistry::new(1, 1, 1024).unwrap();
    assert_eq!(r.len(), 0);
    assert!(!r.has_pending_events());
    let h = r.reserve(target(), route(), WatchKind::Watch).unwrap();
    assert_eq!(r.len(), 1);
    assert!(!r.has_pending_events());
    r.on_event(2, 3, msg(h.cookie(), notify::NOTIFY)).unwrap();
    assert!(r.has_pending_events());
    assert!(r.poll().is_some());
    assert!(!r.has_pending_events());
    r.fault(h, WatchError::Disconnected).unwrap();
    assert!(r.has_pending_events());
    assert!(r.poll().is_none());
    assert_eq!(r.poll_error(), Some((h, WatchError::Disconnected)));
    assert!(!r.has_pending_events());
    assert_eq!(r.len(), 1);
    assert!(!r.is_empty());
    r.remove(h).unwrap();
    assert!(r.is_empty());
    assert_eq!(r.len(), 0);
}

#[test]
fn contextual_notify_preserves_snapshot_fullness_and_zero_server_default_without_fence() {
    let mut q = ObjectQueue::new(1, 4096, 0).unwrap();
    let t = q
        .submit_control_with_context(
            ControlRequest {
                target: target(),
                operation: ControlOperation::Notify {
                    cookie: 7,
                    timeout_seconds: 0,
                    payload: Bytes::from_static(&[0, 255, 65]),
                },
            },
            RequestContext {
                snapid: 123,
                full_policy: FullPolicy::Try,
                mtime: denc::types::UTime::new(8, 9),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(q.snapshot(t), Some(123));
    assert_eq!(q.fence_status(q.fence()), Ok(FenceStatus::Ready(Ok(()))));
    let d = q.dispatch(t, route()).unwrap();
    assert_eq!(
        (d.message.snapid, d.message.snap_seq, d.message.snaps.len()),
        (123, 0, 0)
    );
    assert_eq!(d.message.mtime, denc::types::UTime::new(8, 9));
    assert_ne!(d.message.flags & flag::READ, 0);
    assert_ne!(d.message.flags & flag::FULL_TRY, 0);
    assert_eq!(d.message.flags & (flag::WRITE | flag::RETURNVEC), 0);
    assert_eq!(
        d.message.ops[0].indata.as_ref(),
        &[1, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 255, 65]
    );
}
#[test]
fn contextual_write_charges_snapshot_capacity_and_rejection_preserves_all_input() {
    let request = || ControlRequest {
        target: target(),
        operation: ControlOperation::Register {
            cookie: 7,
            timeout_seconds: 30,
        },
    };
    let mut q = ObjectQueue::new(1, 4096, 0).unwrap();
    let mut snaps = Vec::with_capacity(16);
    snaps.extend_from_slice(&[8, 5]);
    let t = q
        .submit_control_with_context(
            request(),
            RequestContext {
                snap_sequence: 8,
                snapshots: snaps,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        q.charged_bytes(),
        target().object.capacity() as u64 + 16 * 8
    );
    let d = q.dispatch(t, route()).unwrap();
    assert_eq!(
        (d.message.snap_seq, d.message.snaps.as_slice()),
        (8, &[8, 5][..])
    );
    q.cancel(t).unwrap();
    q.poll_into(&mut [None]);
    for context in [
        RequestContext {
            snapid: 8,
            ..Default::default()
        },
        RequestContext {
            snap_sequence: 8,
            snapshots: vec![5, 8],
            ..Default::default()
        },
        RequestContext {
            legacy_reply: true,
            ..Default::default()
        },
    ] {
        let expected = context.clone();
        let r = q
            .submit_control_with_context(request(), context)
            .unwrap_err();
        assert_eq!(r.context, expected);
        assert_eq!(r.request.target, target());
        assert_eq!(q.charged_bytes(), 0);
    }
}

#[test]
fn unbound_managed_identity_rejects_all_ingress_until_a_real_route_is_bound() {
    let mut r = WatchRegistry::new(1, 4, 4096).unwrap();
    let h = r.reserve_unbound_watch(target()).unwrap();
    assert_eq!(r.route(h), None);
    assert!(
        !r.on_event(2, 3, msg(h.cookie(), opwire::consts::notify::NOTIFY))
            .unwrap()
    );
    r.fault_unsuspended_route(2, 3, WatchError::Disconnected);
    assert!(r.poll_error().is_none());
    r.bind_managed(h, route(), 0).unwrap();
    r.activate(h, 0).unwrap();
    assert!(
        r.on_event(2, 3, msg(h.cookie(), opwire::consts::notify::NOTIFY))
            .unwrap()
    );
    assert!(r.poll().is_some());
    r.remove(h).unwrap();
    assert_eq!(r.charged_bytes(), 0);
}

#[test]
fn compatible_registration_population_is_independent_of_event_capacity() {
    let mut registry = WatchRegistry::with_compatible_registrations(1, 1, 1, 4096).unwrap();
    let mut handles = Vec::new();
    for _ in 0..300 {
        let handle = registry
            .reserve(target(), route(), WatchKind::Watch)
            .unwrap();
        registry.activate(handle, 0).unwrap();
        handles.push(handle);
    }
    assert_eq!(registry.len(), 300);
    for handle in handles {
        registry.remove(handle).unwrap();
    }
    assert!(registry.is_empty());
    assert_eq!(registry.charged_bytes(), 0);
    let mut strict = WatchRegistry::new(1, 1, 4096).unwrap();
    strict.reserve(target(), route(), WatchKind::Watch).unwrap();
    assert!(strict.reserve(target(), route(), WatchKind::Watch).is_err());
}
