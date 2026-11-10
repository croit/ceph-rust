// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Per-core output notifications. Registration allocates; repeated notify/pop does not.
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;

#[derive(Debug, Default)]
struct State {
    ready: VecDeque<(u64, Rc<Cell<bool>>)>,
    registered: usize,
}

/// Shared by connections on one core and their transport driver. Never sent across cores.
#[derive(Clone, Debug, Default)]
pub struct OutputQueue(Rc<RefCell<State>>);

impl OutputQueue {
    /// Register a connection (cold path), reserving room for its notification.
    pub fn register(&self, id: u64) -> OutputNotify {
        let mut s = self.0.borrow_mut();
        s.registered += 1;
        let n = s.registered;
        s.ready.reserve(n);
        OutputNotify {
            queue: self.clone(),
            id,
            pending: Rc::new(Cell::new(false)),
        }
    }

    /// Take a ready connection; clear its deduplication bit before returning.
    pub fn pop(&self) -> Option<u64> {
        let (id, pending) = self.0.borrow_mut().ready.pop_front()?;
        pending.set(false);
        Some(id)
    }

    /// No notification queued (the transport drained the queue).
    pub fn is_empty(&self) -> bool {
        self.0.borrow().ready.is_empty()
    }
}

/// A connection's notification registration; keep it with its owning core.
#[derive(Debug)]
pub struct OutputNotify {
    queue: OutputQueue,
    id: u64,
    pending: Rc<Cell<bool>>,
}

impl OutputNotify {
    /// Cancel a cold registration's queued token without affecting another registration of the same id.
    fn cancel(&self) {
        if self.pending.replace(false) {
            self.queue
                .0
                .borrow_mut()
                .ready
                .retain(|(_, p)| !Rc::ptr_eq(p, &self.pending));
        }
    }
    /// Queue at most one notification until it is consumed.
    pub fn notify(&self) {
        if !self.pending.replace(true) {
            self.queue
                .0
                .borrow_mut()
                .ready
                .push_back((self.id, self.pending.clone()));
        }
    }
}

/// Per-core connection events, reusing the output queue's deduplicated/preallocated readiness primitive.
#[derive(Clone, Debug, Default)]
pub struct EventQueue(OutputQueue);

impl EventQueue {
    pub fn register(&self, id: u64) -> EventNotify {
        EventNotify(self.0.register(id))
    }
    pub fn pop(&self) -> Option<u64> {
        self.0.pop()
    }
}

#[derive(Debug)]
pub struct EventNotify(OutputNotify);

impl EventNotify {
    pub fn notify(&self) {
        self.0.notify();
    }
}

impl Drop for OutputNotify {
    fn drop(&mut self) {
        // a closed or handed-off connection leaves no stale token (reserve covers live registrations only)
        self.cancel();
        self.queue.0.borrow_mut().registered -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn event_registrations_cancel_and_rearm_without_growing() {
        let q = EventQueue::default();
        let registrations: Vec<_> = (0..1000).map(|id| q.register(id)).collect();
        let capacity = q.0.0.borrow().ready.capacity();
        for _ in 0..100 {
            for r in &registrations {
                r.notify();
                r.notify();
            }
            for id in 0..1000 {
                assert_eq!(q.pop(), Some(id));
            }
            assert_eq!(q.pop(), None);
            assert_eq!(q.0.0.borrow().ready.capacity(), capacity);
        }
        drop(registrations);
        for _ in 0..1000 {
            let r = q.register(1);
            r.notify();
            drop(r);
            assert_eq!(
                q.pop(),
                None,
                "closed registration left a stale event token"
            );
        }
    }
    #[test]
    fn deduplicates_rearms_and_does_not_grow_after_registration() {
        let q = OutputQueue::default();
        let registrations: Vec<_> = (0..1000).map(|id| q.register(id)).collect();
        let capacity = q.0.borrow().ready.capacity();
        for _ in 0..100 {
            for r in &registrations {
                r.notify();
                r.notify();
            }
            for id in 0..1000 {
                assert_eq!(q.pop(), Some(id));
            }
            assert_eq!(q.pop(), None);
            assert_eq!(q.0.borrow().ready.capacity(), capacity);
        }
        drop(registrations);
        let r = q.register(1);
        r.notify();
        drop(r);
        assert_eq!(
            q.pop(),
            None,
            "closed registration left a stale output token"
        );
    }
}
