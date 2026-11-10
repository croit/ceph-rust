// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use denc::types::PgT;
use rustyrados::*;
fn request() -> ReadRequest {
    ReadRequest {
        target: Target {
            pool: 7,
            object: b"ready".to_vec(),
            namespace: vec![],
            locator: vec![],
        },
        offset: 0,
        length: 16,
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
#[test]
fn recovery_fifo_deduplicates_and_never_evicts_on_overflow() {
    let mut q = ObjectQueue::new(3, 100, 0).unwrap();
    let mut ready = RecoveryQueue::new(2);
    let a = RecoveryItem {
        token: q.submit(request()).unwrap(),
        previous: route(),
        cause: RecoveryCause::BackoffReleased,
    };
    let b = RecoveryItem {
        token: q.submit(request()).unwrap(),
        ..a
    };
    let c = RecoveryItem {
        token: q.submit(request()).unwrap(),
        ..a
    };
    assert_eq!(ready.push(a), Ok(true));
    assert_eq!(ready.push(a), Ok(false));
    assert_eq!(ready.push(b), Ok(true));
    assert_eq!(ready.push(c), Err(c));
    assert_eq!(ready.len(), 2);
    assert_eq!(ready.pop(), Some(a));
    assert_eq!(ready.pop(), Some(b));
    assert!(ready.is_empty());
}
#[test]
fn cancel_expiry_and_slot_reuse_do_not_recover_new_request_by_old_token() {
    let mut q = ObjectQueue::new(1, 100, 0).unwrap();
    let mut ready = RecoveryQueue::new(1);
    let old = q.submit(request()).unwrap();
    q.set_deadline_us(old, 10, 10).unwrap();
    q.dispatch(old, route()).unwrap();
    ready
        .push(RecoveryItem {
            token: old,
            previous: route(),
            cause: RecoveryCause::BackoffReleased,
        })
        .unwrap();
    q.expire_us(10, 1);
    q.poll_into(&mut [None]);
    let new = q.submit(request()).unwrap();
    let item = ready.pop().unwrap();
    assert!(!q.is_pending(item.token));
    assert!(q.is_pending(new));
    ready
        .push(RecoveryItem {
            token: new,
            previous: route(),
            cause: RecoveryCause::Remap,
        })
        .unwrap();
    ready.remove(old);
    assert_eq!(ready.len(), 1);
    ready.remove(new);
    assert!(ready.is_empty());
}

#[test]
fn rejected_session_never_becomes_recoverable_after_io_or_reset() {
    for failure in [
        SessionFailure::Transport,
        SessionFailure::Reset,
        SessionFailure::Rejected,
    ] {
        assert_eq!(
            SessionFailure::Rejected.merge(failure),
            SessionFailure::Rejected
        );
        assert_eq!(
            failure.merge(SessionFailure::Rejected),
            SessionFailure::Rejected
        );
    }
    assert!(SessionFailure::Transport.recoverable());
    assert!(SessionFailure::Reset.recoverable());
    assert!(!SessionFailure::Rejected.recoverable());
}

#[test]
fn terminal_wakes_release_capacity_without_evicting_live_requests() {
    let mut q = ObjectQueue::new(2, 100, 0).unwrap();
    let mut ready = RecoveryQueue::new(1);
    let old = q.submit(request()).unwrap();
    let live = q.submit(request()).unwrap();
    let item = RecoveryItem {
        token: old,
        previous: route(),
        cause: RecoveryCause::ConnectionLost,
    };
    ready.push(item).unwrap();
    q.cancel(old).unwrap();
    ready.retain_live(|token| q.is_pending(token));
    assert!(ready.is_empty());
    let item = RecoveryItem {
        token: live,
        ..item
    };
    ready.push(item).unwrap();
    ready.retain_live(|token| q.is_pending(token));
    assert_eq!(ready.pop(), Some(item));
}

#[test]
fn delayed_recovery_does_not_starve_ready_work_or_shorten_on_duplicate_wake() {
    let mut q = ObjectQueue::new(2, 100, 0).unwrap();
    let mut ready = RecoveryQueue::new(2);
    let delayed = RecoveryItem {
        token: q.submit(request()).unwrap(),
        previous: route(),
        cause: RecoveryCause::TryAgain,
    };
    let immediate = RecoveryItem {
        token: q.submit(request()).unwrap(),
        ..delayed
    };
    ready.push_at(delayed, 100).unwrap();
    assert_eq!(ready.push(delayed), Ok(false));
    ready.push(immediate).unwrap();
    assert_eq!(ready.next_timer_us(), Some(0));
    assert_eq!(ready.pop_ready(0), Some(immediate));
    assert_eq!(ready.next_timer_us(), Some(100));
    assert_eq!(ready.pop_ready(99), None);
    assert_eq!(ready.len(), 1);
    assert_eq!(ready.pop_ready(100), Some(delayed));
    assert_eq!(ready.next_timer_us(), None);
}
