// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use rustyrados::*;
fn handle() -> WatchHandle {
    let mut r = WatchRegistry::new(1, 1, 1024).unwrap();
    r.reserve(
        Target {
            pool: 1,
            object: vec![1],
            namespace: vec![],
            locator: vec![],
        },
        ReadRoute {
            direct_read: false,
            base_pool: 1,
            osd: 1,
            session: 1,
            pg: Default::default(),
            hash: 0,
            epoch: 1,
            features: 0,
            generation: 1,
            pool: rustyrados::PoolRoute::Replicated,
        },
        WatchKind::Watch,
    )
    .unwrap()
}
fn timing() -> WatchTiming {
    WatchTiming {
        server_timeout_seconds: 1,
        ping_interval_us: 10,
        operation_timeout_us: 100,
    }
}
fn connected() -> WatchLifecycle {
    let mut l = WatchLifecycle::new(handle(), timing(), 0).unwrap();
    let a = l.poll_action(0, false).unwrap();
    assert_eq!(a.kind(), WatchActionKind::Register);
    assert!(l.sent(a, 2));
    assert!(l.complete(a, 0, 3));
    l
}
#[test]
fn timer_renewal_uses_first_actual_send_time_and_one_pending_control() {
    let mut l = connected();
    assert_eq!(l.state(), WatchLifecycleState::Connected);
    assert_eq!(l.valid_through(), Some(2));
    assert_eq!(l.next_timer(), Some(12));
    assert!(l.poll_action(11, false).is_none());
    let ping = l.poll_action(12, false).unwrap();
    assert_eq!(ping.kind(), WatchActionKind::Ping);
    assert_eq!(ping.generation(), 0);
    // PING arms no deadline: a missing reply only ages the watch (classic linger ping).
    assert_eq!(ping.deadline_us(), rustyrados::time::NO_DEADLINE);
    assert!(l.poll_action(13, false).is_none());
    assert!(l.sent(ping, 14));
    assert!(l.sent(ping, 15));
    assert!(l.complete(ping, 0, 20));
    assert_eq!(l.valid_through(), Some(14));
    assert_eq!(l.next_timer(), Some(24));
    assert!(!l.complete(ping, 0, 21));
    assert_eq!(l.valid_through(), Some(14));
}
#[test]
fn registered_loss_reconnects_with_fresh_identity_and_rejects_old_ping() {
    let mut l = connected();
    let ping = l.poll_action(12, false).unwrap();
    assert!(l.sent(ping, 13));
    l.transport_lost(14);
    assert_eq!(l.state(), WatchLifecycleState::Reconnecting);
    assert_eq!(l.next_timer(), Some(14));
    let reconnect = l.poll_action(15, false).unwrap();
    assert_eq!(reconnect.kind(), WatchActionKind::Reconnect);
    assert_ne!(ping.id(), reconnect.id());
    assert_eq!(reconnect.generation(), 1);
    assert!(!l.complete(ping, 0, 16));
    assert_eq!(l.valid_through(), Some(2));
    assert!(l.sent(reconnect, 17));
    assert!(l.complete(reconnect, 0, 18));
    assert_eq!(l.state(), WatchLifecycleState::Connected);
    let next = l.poll_action(27, false).unwrap();
    assert_eq!(next.generation(), 1);
    assert_eq!(next.handle(), reconnect.handle());
}
#[test]
fn initial_loss_preserves_setup_deadline_and_never_uses_reconnect() {
    let mut l = WatchLifecycle::new(handle(), timing(), 10).unwrap();
    assert_eq!(l.next_timer(), Some(10));
    let first = l.poll_action(11, false).unwrap();
    assert_eq!(first.deadline_us(), 110);
    l.sent(first, 12);
    l.transport_lost(50);
    let second = l.poll_action(80, false).unwrap();
    assert_eq!(second.kind(), WatchActionKind::Register);
    assert_eq!(second.generation(), 0);
    assert_eq!(second.deadline_us(), 110);
    assert!(!l.complete(first, 0, 81));
    l.sent(second, 90);
    assert!(!l.complete(second, 0, 110));
    assert_eq!(
        l.state(),
        WatchLifecycleState::Failed(WatchLifecycleError::Deadline)
    );
}
#[test]
fn outage_has_no_total_limit_and_each_reconnect_gets_its_own_budget() {
    let mut l = connected();
    l.transport_lost(20);
    let first = l.poll_action(21, false).unwrap();
    assert_eq!(first.deadline_us(), 121);
    l.transport_lost(100);
    let second = l.poll_action(101, false).unwrap();
    assert_eq!(second.generation(), 2);
    assert_eq!(second.deadline_us(), 201);
    // Homeless target: no RECONNECT, no deadline, the owner may sleep; far past any old local outage limit.
    l.transport_lost(190);
    l.set_routable(false);
    assert!(l.poll_action(191, false).is_none());
    assert!(l.can_wait(191, false));
    assert_eq!(l.next_timer(), None);
    assert!(l.poll_action(600_000_000, false).is_none());
    assert_eq!(l.state(), WatchLifecycleState::Reconnecting);
    l.set_routable(true);
    let third = l.poll_action(600_000_001, false).unwrap();
    assert_eq!(third.kind(), WatchActionKind::Reconnect);
    assert_eq!(third.deadline_us(), 600_000_101);
    assert!(l.sent(third, 600_000_002));
    assert!(l.complete(third, 0, 600_000_003));
    assert_eq!(l.state(), WatchLifecycleState::Connected);
    // An expired RECONNECT operation still ends the watch (rados_osd_op_timeout).
    l.transport_lost(600_000_004);
    let fourth = l.poll_action(600_000_005, false).unwrap();
    l.sent(fourth, 600_000_006);
    assert!(!l.complete(fourth, 0, 600_000_105));
    assert_eq!(
        l.state(),
        WatchLifecycleState::Failed(WatchLifecycleError::Deadline)
    );
    assert!(l.next_timer().is_none());
}
#[test]
fn pause_suppresses_new_ping_and_an_unanswered_ping_never_expires() {
    let mut l = connected();
    assert!(l.poll_action(12, true).is_none());
    assert!(l.next_timer().is_none());
    assert!(l.poll_action(1000, true).is_none());
    let ping = l.poll_action(1001, false).unwrap();
    assert!(l.poll_action(1002, true).is_none());
    assert_eq!(l.next_timer(), None);
    assert!(l.sent(ping, 1002));
    // One outstanding PING suppresses the next; its silence only ages the watch.
    assert!(l.poll_action(5000, false).is_none());
    assert_eq!(l.state(), WatchLifecycleState::Connected);
    assert_eq!(l.valid_through(), Some(2));
    assert!(l.complete(ping, 0, 5001));
    assert_eq!(l.valid_through(), Some(1002));
}
#[test]
fn remote_reconnect_failure_never_recreates_missing_watch() {
    for (result, expected) in [
        (-2, WatchLifecycleError::Disconnected),
        (-107, WatchLifecycleError::Disconnected),
        (-110, WatchLifecycleError::Remote(-110)),
        (-108, WatchLifecycleError::Remote(-108)),
        (-13, WatchLifecycleError::Remote(-13)),
    ] {
        let mut l = connected();
        l.transport_lost(4);
        let a = l.poll_action(5, false).unwrap();
        l.sent(a, 6);
        assert!(l.complete(a, result, 7));
        assert_eq!(l.state(), WatchLifecycleState::Failed(expected));
        l.transport_lost(8);
        assert!(l.poll_action(9, false).is_none());
    }
}
#[test]
fn invalid_clock_unsent_reply_server_disconnect_and_stop_are_terminal() {
    let mut l = connected();
    assert!(l.poll_action(2, false).is_none());
    assert_eq!(
        l.state(),
        WatchLifecycleState::Failed(WatchLifecycleError::Clock)
    );
    l.disconnected(9);
    assert_eq!(
        l.state(),
        WatchLifecycleState::Failed(WatchLifecycleError::Clock)
    );
    let mut l = WatchLifecycle::new(handle(), timing(), 0).unwrap();
    let a = l.poll_action(0, false).unwrap();
    assert!(l.complete(a, 0, 1));
    assert_eq!(
        l.state(),
        WatchLifecycleState::Failed(WatchLifecycleError::Protocol)
    );
    let mut l = connected();
    l.disconnected(4);
    assert_eq!(
        l.state(),
        WatchLifecycleState::Failed(WatchLifecycleError::Disconnected)
    );
    let mut l = connected();
    l.stop();
    l.transport_lost(9);
    assert_eq!(l.state(), WatchLifecycleState::Stopped);
    assert!(l.poll_action(1000, false).is_none());
    assert!(l.pending_action().is_none());
    assert!(l.next_timer().is_none());
}
#[test]
fn coordinator_domain_and_configuration_boundaries_are_explicit() {
    let h = handle();
    let mut a = WatchLifecycle::new(h, timing(), 0).unwrap();
    let mut b = WatchLifecycle::new(h, timing(), 0).unwrap();
    let old = a.poll_action(0, false).unwrap();
    let current = b.poll_action(0, false).unwrap();
    assert!(!b.sent(old, 1));
    assert!(!b.complete(old, 0, 2));
    assert_eq!(b.pending_action(), Some(current));
    assert!(
        WatchLifecycle::new(
            h,
            WatchTiming {
                ping_interval_us: 1_000_000,
                ..timing()
            },
            0
        )
        .is_err()
    );
    assert!(
        WatchLifecycle::new(
            h,
            WatchTiming {
                operation_timeout_us: 0,
                ..timing()
            },
            0
        )
        .is_err()
    );
    assert!(WatchLifecycle::new(h, timing(), u32::MAX as u64 * 1_000_000).is_ok());
    assert!(matches!(
        WatchLifecycle::new(h, timing(), rustyrados::time::MAX_TIME_US),
        Err(WatchLifecycleError::Overflow)
    ));
    let mut l = connected();
    assert!(l.poll_action(u64::MAX, false).is_none());
    assert_eq!(
        l.state(),
        WatchLifecycleState::Failed(WatchLifecycleError::Clock)
    );
}

#[test]
fn immutable_wait_hint_preserves_action_deadlines_and_uses_current_pause() {
    let mut l = WatchLifecycle::new(handle(), timing(), 0).unwrap();
    assert!(!l.can_wait(0, false));
    let action = l.poll_action(0, false).unwrap();
    assert!(l.can_wait(99, false)); // Owner still must admit the action.
    assert!(!l.can_wait(action.deadline_us(), false));
    assert_eq!(l.pending_action(), Some(action));
    let mut l = connected();
    assert!(!l.can_wait(2, false)); // Earlier than the observed completion clock.
    assert!(l.can_wait(11, false));
    assert!(!l.can_wait(12, false));
    assert!(l.can_wait(12, true));
    assert!(l.poll_action(11, true).is_none());
    assert_eq!(l.next_timer(), None);
    assert_eq!(l.next_timer_for(false), Some(12));
    assert!(!l.can_wait(12, false)); // Unpause before a lifecycle visit.
    let ping = l.poll_action(12, false).unwrap();
    assert_eq!(ping.deadline_us(), rustyrados::time::NO_DEADLINE);
    assert!(l.can_wait(13, false));
    assert!(l.can_wait(5000, false)); // An unanswered PING never expires locally.
    l.transport_lost(13);
    assert!(!l.can_wait(13, false));
    let reconnect = l.poll_action(13, false).unwrap();
    assert!(l.can_wait(14, false));
    assert!(!l.can_wait(reconnect.deadline_us(), false));
    assert!(!l.can_wait(u64::MAX, false));
    l.stop();
    assert!(!l.can_wait(14, false));
    assert_eq!(l.next_timer_for(false), None);
}

#[test]
fn server_default_lease_keeps_local_limits_without_claiming_a_remote_expiry() {
    let mut t = timing();
    t.server_timeout_seconds = 0;
    let mut l = WatchLifecycle::new(handle(), t, 0).unwrap();
    let a = l.poll_action(0, false).unwrap();
    assert!(matches!(
        a.operation(),
        ControlOperation::Register {
            timeout_seconds: 0,
            ..
        }
    ));
    assert!(l.sent(a, 1));
    assert!(l.complete(a, 0, 2));
    assert_eq!(l.next_timer(), Some(11));
    l.transport_lost(3);
    assert_eq!(l.state(), WatchLifecycleState::Reconnecting);
    for (bad, expected) in [
        (
            WatchTiming {
                ping_interval_us: 0,
                ..t
            },
            WatchLifecycleError::Limits,
        ),
        (
            WatchTiming {
                operation_timeout_us: 0,
                ..t
            },
            WatchLifecycleError::Limits,
        ),
        (
            WatchTiming {
                ping_interval_us: u64::MAX,
                ..t
            },
            WatchLifecycleError::Overflow,
        ),
        (
            WatchTiming {
                // Beyond the clock range but not the unlimited sentinel.
                operation_timeout_us: u64::MAX - 1,
                ..t
            },
            WatchLifecycleError::Overflow,
        ),
    ] {
        assert!(matches!(WatchLifecycle::new(handle(), bad, 0), Err(error) if error == expected));
    }
    // The unlimited sentinel is a valid operation budget (rados_osd_op_timeout = 0).
    assert!(
        WatchLifecycle::new(
            handle(),
            WatchTiming {
                operation_timeout_us: rustyrados::time::NO_DEADLINE,
                ..t
            },
            0
        )
        .is_ok()
    );
    assert!(matches!(
        WatchLifecycle::new(
            handle(),
            WatchTiming {
                server_timeout_seconds: 1,
                ping_interval_us: 1_000_000,
                ..t
            },
            0
        ),
        Err(WatchLifecycleError::Limits)
    ));
}
