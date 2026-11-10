// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Requester correlation for modern administrative notifications.
//!
//! Register before sending; an acceptance ACK is separate from completion.
//! The caller supplies its configured timeout and monotonic clock observations,
//! drives expiry, and performs ownership/retry selection. Wire-version decoding
//! remains in `admin_notify`; legacy zero IDs do not enter this table.
//!
//! Handles are `Send + Sync` and contain no application callbacks. The invoking
//! thread consumes coalesced progress events, calls its own possibly non-Send
//! callback outside all core locks, and ignores its return value. Blocking waits
//! hold only the individual request mutex while entering a condition variable;
//! they never hold the pending-table mutex. This does not grant callbacks any
//! additional API reentrancy rights.

use crate::{AsyncRequestId, LockClientId};
use rustyrados::diag;
use std::{
    collections::HashMap,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

/// Linux RBD's restart result for closed, blocked or replaced requester watches.
pub const ADMIN_REQUEST_RESTART: i32 = -85;
/// Linux RBD's request deadline result; independent of notify aggregate timeout.
pub const ADMIN_REQUEST_TIMED_OUT: i32 = -110;

static NEXT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Registration cannot safely construct a new pending request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminRequestError {
    Closed,
    Duplicate,
    InvalidSequence,
    SequenceExhausted,
    ClockOverflow,
}

/// One event for the invoking thread. Progress callback results are ignored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminRequestEvent {
    Progress {
        offset: u64,
        total: u64,
    },
    Complete(i32),
    /// Only the supplied blocking interval elapsed; call `expire(now)` to apply
    /// the protocol deadline, which a concurrent progress event may have reset.
    WaitElapsed,
}

#[derive(Debug)]
struct RequestState {
    accepted: bool,
    result: Option<i32>,
    progress: Option<(u64, u64)>,
    deadline: Instant,
}

#[derive(Debug)]
struct RequestCell {
    state: Mutex<RequestState>,
    changed: Condvar,
    timeout: Duration,
}

impl RequestCell {
    fn finish(&self, status: i32) {
        let mut state = self.state.lock().expect("admin request state poisoned");
        debug_assert!(state.result.is_none());
        state.result = Some(status);
        state.progress = None;
        self.changed.notify_all();
    }
}

/// Owned wait/result state survives table removal, rewatch and image teardown.
/// No FFI callback pointers or borrowed application storage are retained here.
#[derive(Clone, Debug)]
pub struct AdminRequest {
    id: AsyncRequestId,
    cell: Arc<RequestCell>,
}

impl AdminRequest {
    pub fn id(&self) -> AsyncRequestId {
        self.id
    }
    pub fn result(&self) -> Option<i32> {
        self.cell
            .state
            .lock()
            .expect("admin request state poisoned")
            .result
    }
    pub fn accepted(&self) -> bool {
        self.cell
            .state
            .lock()
            .expect("admin request state poisoned")
            .accepted
    }
    pub fn deadline(&self) -> Instant {
        self.cell
            .state
            .lock()
            .expect("admin request state poisoned")
            .deadline
    }
    /// Consume the most recent undelivered progress sample, if any.
    pub fn take_progress(&self) -> Option<(u64, u64)> {
        self.cell
            .state
            .lock()
            .expect("admin request state poisoned")
            .progress
            .take()
    }
    /// Wait without polling. The supplied duration bounds this wait only;
    /// application callbacks and protocol expiry run after this method returns.
    /// A completed result remains available on every subsequent wait/result.
    pub fn wait_event(&self, maximum: Duration) -> AdminRequestEvent {
        let state = self
            .cell
            .state
            .lock()
            .expect("admin request state poisoned");
        let (mut state, _) = self
            .cell
            .changed
            .wait_timeout_while(state, maximum, |state| {
                state.result.is_none() && state.progress.is_none()
            })
            .expect("admin request state poisoned");
        if let Some(status) = state.result {
            AdminRequestEvent::Complete(status)
        } else if let Some((offset, total)) = state.progress.take() {
            AdminRequestEvent::Progress { offset, total }
        } else {
            AdminRequestEvent::WaitElapsed
        }
    }
}

#[derive(Debug)]
struct Pending {
    client: LockClientId,
    closed: bool,
    requests: HashMap<AsyncRequestId, Arc<RequestCell>>,
}

/// One image watch's pending modern requests. It performs no transport, callback
/// dispatch, hidden timer scheduling, owner selection or receiver deduplication.
#[derive(Debug)]
pub struct AdminRequests {
    pending: Mutex<Pending>,
}

impl AdminRequests {
    pub fn new(client: LockClientId) -> Self {
        Self {
            pending: Mutex::new(Pending {
                client,
                closed: false,
                requests: HashMap::new(),
            }),
        }
    }
    /// Reserve once per public invoke, then reuse the sequence on forwarding
    /// attempts with the then-current watch ClientId. Exhaustion never wraps.
    pub fn allocate_sequence() -> Result<u64, AdminRequestError> {
        NEXT_SEQUENCE
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map(|value| value + 1)
            .map_err(|_| AdminRequestError::SequenceExhausted)
    }
    /// Install pending state and deadline before the caller broadcasts. A zero
    /// sequence is reserved for legacy callers, and is not generated here.
    pub fn register(
        &self,
        sequence: u64,
        now: Instant,
        timeout: Duration,
    ) -> Result<AdminRequest, AdminRequestError> {
        if sequence == 0 {
            return Err(AdminRequestError::InvalidSequence);
        }
        let deadline = now
            .checked_add(timeout)
            .ok_or(AdminRequestError::ClockOverflow)?;
        let mut pending = self.pending.lock().expect("admin pending table poisoned");
        if pending.closed {
            return Err(AdminRequestError::Closed);
        }
        let id = AsyncRequestId {
            client: pending.client,
            sequence,
        };
        let std::collections::hash_map::Entry::Vacant(entry) = pending.requests.entry(id) else {
            return Err(AdminRequestError::Duplicate);
        };
        let cell = Arc::new(RequestCell {
            state: Mutex::new(RequestState {
                accepted: false,
                result: None,
                progress: None,
                deadline,
            }),
            changed: Condvar::new(),
            timeout,
        });
        entry.insert(cell.clone());
        Ok(AdminRequest { id, cell })
    }
    /// Negative submission/acceptance status settles only a still-pending ID.
    /// ACK0 marks acceptance, not completion. Late ACKs cannot replace a result.
    pub fn acceptance(&self, id: AsyncRequestId, status: i32) -> bool {
        if status < 0 {
            return self.complete(id, status);
        }
        let pending = self.pending.lock().expect("admin pending table poisoned");
        let Some(cell) = pending.requests.get(&id) else {
            return false;
        };
        let mut state = cell.state.lock().expect("admin request state poisoned");
        let first = !state.accepted;
        state.accepted = true;
        first
    }
    /// Remove before settlement, so duplicate completion and late acceptance
    /// cannot settle twice. Signed application results are preserved unchanged.
    pub fn complete(&self, id: AsyncRequestId, status: i32) -> bool {
        let cell = self
            .pending
            .lock()
            .expect("admin pending table poisoned")
            .requests
            .remove(&id);
        if let Some(cell) = cell {
            cell.finish(status);
            true
        } else {
            false
        }
    }
    /// Match the full identity, reset its configured deadline, and wake its
    /// consumer. Multiple undelivered progress samples coalesce to the latest.
    pub fn progress(
        &self,
        id: AsyncRequestId,
        offset: u64,
        total: u64,
        now: Instant,
    ) -> Result<bool, AdminRequestError> {
        let pending = self.pending.lock().expect("admin pending table poisoned");
        let Some(cell) = pending.requests.get(&id) else {
            return Ok(false);
        };
        let deadline = now
            .checked_add(cell.timeout)
            .ok_or(AdminRequestError::ClockOverflow)?;
        let mut state = cell.state.lock().expect("admin request state poisoned");
        state.deadline = deadline;
        state.progress = Some((offset, total));
        cell.changed.notify_all();
        Ok(true)
    }
    /// Number of requests still awaiting completion. Zero after a close or a
    /// rewatch proves no forwarded wait was left behind.
    pub fn pending_len(&self) -> usize {
        self.pending
            .lock()
            .expect("admin pending table poisoned")
            .requests
            .len()
    }
    /// The caller's next timer deadline; completion/removal cancels that timer.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.pending
            .lock()
            .expect("admin pending table poisoned")
            .requests
            .values()
            .map(|cell| {
                cell.state
                    .lock()
                    .expect("admin request state poisoned")
                    .deadline
            })
            .min()
    }
    /// Apply deadlines using the caller's clock. Progress and expiry are
    /// serialized by the table lock; an already-reset deadline cannot expire.
    pub fn expire(&self, now: Instant) -> usize {
        let expired = {
            let mut pending = self.pending.lock().expect("admin pending table poisoned");
            let ids: Vec<_> = pending
                .requests
                .iter()
                .filter_map(|(id, cell)| {
                    (cell
                        .state
                        .lock()
                        .expect("admin request state poisoned")
                        .deadline
                        <= now)
                        .then_some(*id)
                })
                .collect();
            ids.into_iter()
                .map(|id| {
                    pending
                        .requests
                        .remove(&id)
                        .expect("pending deadline identity")
                })
                .collect::<Vec<_>>()
        };
        let count = expired.len();
        for cell in expired {
            diag!(
                "WARNING TIMEOUT RBD admin request exceeded {}s (forwarded notify, ETIMEDOUT to caller)",
                cell.timeout.as_secs_f64()
            );
            cell.finish(ADMIN_REQUEST_TIMED_OUT);
        }
        count
    }
    /// Cancel current forwarded waits for block_notifies without closing future
    /// admission. The caller must separately fence new invokes while blocked.
    pub fn cancel_pending(&self) -> usize {
        let cells = {
            let mut pending = self.pending.lock().expect("admin pending table poisoned");
            std::mem::take(&mut pending.requests)
        };
        Self::restart(cells)
    }
    /// Replace the exact live ClientId, invalidating pending old-watch requests.
    /// A permanently closed image cannot be reopened through this operation.
    pub fn rewatch(&self, client: LockClientId) -> Result<usize, AdminRequestError> {
        let cells = {
            let mut pending = self.pending.lock().expect("admin pending table poisoned");
            if pending.closed {
                return Err(AdminRequestError::Closed);
            }
            pending.client = client;
            std::mem::take(&mut pending.requests)
        };
        Ok(Self::restart(cells))
    }
    /// Permanently fence registration and wake all retained wait handles.
    pub fn close(&self) -> usize {
        let cells = {
            let mut pending = self.pending.lock().expect("admin pending table poisoned");
            pending.closed = true;
            std::mem::take(&mut pending.requests)
        };
        Self::restart(cells)
    }
    fn restart(cells: HashMap<AsyncRequestId, Arc<RequestCell>>) -> usize {
        let count = cells.len();
        for cell in cells.into_values() {
            cell.finish(ADMIN_REQUEST_RESTART);
        }
        count
    }
}

impl Drop for AdminRequests {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeSet, sync::Barrier, thread};

    fn client(cookie: u64) -> LockClientId {
        LockClientId {
            instance: 42,
            watch_cookie: cookie,
        }
    }
    fn request(table: &AdminRequests, sequence: u64, now: Instant) -> AdminRequest {
        table
            .register(sequence, now, Duration::from_secs(30))
            .unwrap()
    }

    #[test]
    fn allocation_is_process_global_nonzero_and_unique_across_images_threads() {
        let workers: Vec<_> = (0..4)
            .map(|_| {
                thread::spawn(|| {
                    (0..64)
                        .map(|_| AdminRequests::allocate_sequence().unwrap())
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let ids: Vec<_> = workers
            .into_iter()
            .flat_map(|worker| worker.join().unwrap())
            .collect();
        assert!(ids.iter().all(|id| *id != 0));
        assert_eq!(ids.iter().copied().collect::<BTreeSet<_>>().len(), 256);
    }

    #[test]
    fn complete_before_acceptance_and_duplicate_late_events_settle_once() {
        let table = AdminRequests::new(client(7));
        let now = Instant::now();
        let handle = request(&table, 1, now);
        assert!(!handle.accepted());
        assert!(table.complete(handle.id(), -12345));
        assert!(!table.acceptance(handle.id(), 0));
        assert!(!table.acceptance(handle.id(), -22));
        assert!(!table.complete(handle.id(), 0));
        assert_eq!(table.progress(handle.id(), 1, 2, now), Ok(false));
        assert_eq!(handle.result(), Some(-12345));
        assert_eq!(
            handle.wait_event(Duration::ZERO),
            AdminRequestEvent::Complete(-12345)
        );
        assert_eq!(table.next_deadline(), None);
    }

    #[test]
    fn zero_timeout_expires_before_any_progress_arrives() {
        let table = AdminRequests::new(client(7));
        let now = Instant::now();
        // Zero is a zero-delay timeout, not a disabled timer.
        let handle = table
            .register(1, now, Duration::ZERO)
            .expect("zero-delay request");
        assert_eq!(handle.deadline(), now);
        assert_eq!(table.pending_len(), 1);
        assert_eq!(table.expire(now), 1);
        assert_eq!(handle.result(), Some(ADMIN_REQUEST_TIMED_OUT));
        assert_eq!(
            handle.wait_event(Duration::ZERO),
            AdminRequestEvent::Complete(ADMIN_REQUEST_TIMED_OUT)
        );
        assert_eq!(table.pending_len(), 0);
        assert_eq!(table.next_deadline(), None);
    }

    #[test]
    fn ack_is_only_acceptance_and_negative_acceptance_finishes() {
        let table = AdminRequests::new(client(7));
        let now = Instant::now();
        let first = request(&table, 1, now);
        assert!(table.acceptance(first.id(), 0));
        assert!(!table.acceptance(first.id(), 0));
        assert!(first.accepted());
        assert_eq!(first.result(), None);
        assert_eq!(
            first.wait_event(Duration::ZERO),
            AdminRequestEvent::WaitElapsed
        );
        assert!(table.complete(first.id(), 0));
        let second = request(&table, 2, now);
        assert!(table.acceptance(second.id(), -95));
        assert_eq!(second.result(), Some(-95));
    }

    #[test]
    fn progress_coalesces_and_resets_only_exact_identity_deadline() {
        let table = AdminRequests::new(client(7));
        let now = Instant::now();
        let handle = request(&table, 1, now);
        let mut wrong = handle.id();
        wrong.client.watch_cookie += 1;
        assert_eq!(
            table.progress(wrong, 10, 20, now + Duration::from_secs(29)),
            Ok(false)
        );
        assert_eq!(handle.deadline(), now + Duration::from_secs(30));
        assert_eq!(
            table.progress(handle.id(), 4, 20, now + Duration::from_secs(20)),
            Ok(true)
        );
        assert_eq!(
            table.progress(handle.id(), 9, 20, now + Duration::from_secs(25)),
            Ok(true)
        );
        assert_eq!(handle.deadline(), now + Duration::from_secs(55));
        assert_eq!(table.expire(now + Duration::from_secs(30)), 0);
        assert_eq!(
            handle.wait_event(Duration::ZERO),
            AdminRequestEvent::Progress {
                offset: 9,
                total: 20
            }
        );
        assert_eq!(handle.take_progress(), None);
        assert_eq!(table.next_deadline(), Some(now + Duration::from_secs(55)));
        assert_eq!(table.expire(now + Duration::from_secs(55)), 1);
        assert_eq!(handle.result(), Some(ADMIN_REQUEST_TIMED_OUT));
        assert!(!table.complete(handle.id(), 0));
    }

    #[test]
    fn registration_precedes_send_and_pending_duplicate_cannot_replace_waiter() {
        let table = AdminRequests::new(client(7));
        let now = Instant::now();
        let handle = request(&table, 1, now);
        assert!(matches!(
            table.register(1, now, Duration::ZERO),
            Err(AdminRequestError::Duplicate)
        ));
        assert!(matches!(
            table.register(0, now, Duration::ZERO),
            Err(AdminRequestError::InvalidSequence)
        ));
        assert!(table.complete(handle.id(), 17)); // transport can complete synchronously at send
        assert_eq!(handle.result(), Some(17));
    }

    #[test]
    fn rewatch_changes_full_identity_and_old_notifications_do_not_settle_new_attempt() {
        let table = AdminRequests::new(client(7));
        let now = Instant::now();
        let old = request(&table, 1, now);
        assert_eq!(table.rewatch(client(8)), Ok(1));
        assert_eq!(old.result(), Some(ADMIN_REQUEST_RESTART));
        let new = request(&table, 1, now);
        assert_ne!(old.id(), new.id());
        assert!(!table.complete(old.id(), 0));
        assert!(!table.acceptance(old.id(), -22));
        assert_eq!(table.progress(old.id(), 1, 2, now), Ok(false));
        assert_eq!(new.result(), None);
        assert!(table.complete(new.id(), 0));
    }

    #[test]
    fn owner_reselection_reuses_public_sequence_after_restart_and_timeout() {
        let table = AdminRequests::new(client(7));
        let now = Instant::now();
        let first = request(&table, 41, now);
        assert!(table.complete(first.id(), ADMIN_REQUEST_RESTART));

        let retry = request(&table, 41, now);
        assert_eq!(retry.id(), first.id());
        assert_eq!(table.expire(now + Duration::from_secs(30)), 1);
        assert_eq!(retry.result(), Some(ADMIN_REQUEST_TIMED_OUT));

        let final_attempt = request(&table, 41, now);
        assert_eq!(final_attempt.id(), first.id());
        assert!(table.complete(final_attempt.id(), 0));
        assert_eq!(final_attempt.result(), Some(0));
    }

    #[test]
    fn block_cancels_current_waits_close_fences_new_work_and_drop_wakes_handles() {
        let table = AdminRequests::new(client(7));
        let now = Instant::now();
        let first = request(&table, 1, now);
        assert_eq!(table.cancel_pending(), 1);
        assert_eq!(first.result(), Some(ADMIN_REQUEST_RESTART));
        let second = request(&table, 2, now);
        assert_eq!(table.close(), 1);
        assert_eq!(table.close(), 0);
        assert_eq!(second.result(), Some(ADMIN_REQUEST_RESTART));
        assert!(matches!(
            table.register(3, now, Duration::ZERO),
            Err(AdminRequestError::Closed)
        ));
        assert_eq!(table.rewatch(client(9)), Err(AdminRequestError::Closed));
        let dropped = {
            let table = AdminRequests::new(client(9));
            request(&table, 4, now)
        };
        assert_eq!(dropped.result(), Some(ADMIN_REQUEST_RESTART));
    }

    #[test]
    fn completion_wakes_condition_waiter_without_holding_table_lock() {
        let table = Arc::new(AdminRequests::new(client(7)));
        let handle = request(&table, 1, Instant::now());
        let barrier = Arc::new(Barrier::new(2));
        let waiter = {
            let handle = handle.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                handle.wait_event(Duration::from_secs(1))
            })
        };
        barrier.wait();
        assert!(table.complete(handle.id(), -5));
        assert_eq!(waiter.join().unwrap(), AdminRequestEvent::Complete(-5));
    }

    #[test]
    fn concurrent_acceptance_error_and_completion_remove_exactly_once() {
        let table = Arc::new(AdminRequests::new(client(7)));
        let handle = request(&table, 1, Instant::now());
        let barrier = Arc::new(Barrier::new(3));
        let acceptance = {
            let table = table.clone();
            let barrier = barrier.clone();
            let id = handle.id();
            thread::spawn(move || {
                barrier.wait();
                table.acceptance(id, -22)
            })
        };
        let completion = {
            let table = table.clone();
            let barrier = barrier.clone();
            let id = handle.id();
            thread::spawn(move || {
                barrier.wait();
                table.complete(id, -5)
            })
        };
        barrier.wait();
        let winners =
            usize::from(acceptance.join().unwrap()) + usize::from(completion.join().unwrap());
        assert_eq!(winners, 1);
        assert!(matches!(handle.result(), Some(-22) | Some(-5)));
    }
}
