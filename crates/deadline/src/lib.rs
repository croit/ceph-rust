// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Indexed deadlines shared by PGs, engines, connections and client request queues: registration is cold, deadline
//! updates allocate nothing.
use std::collections::BTreeMap;

mod heap;
mod slot;
pub use slot::SlotIndex;

/// Project-wide loud timeout line: `WARNING TIMEOUT <operation> exceeded <limit>s (<context>)`. The limit is
/// printed in seconds with 3 decimals (`as_secs_f64`, so sub-second limits are exact, e.g. 50 ms -> `0.050s`);
/// an empty context prints `()`. Project rule: every timeout that fires emits this line to stderr or the log,
/// scripts append it to the run's warnings file, and gates count the lines; the caller chooses the sink. This
/// crate is the shared home of the line.
pub fn timeout_line(operation: &str, limit: std::time::Duration, context: &str) -> String {
    format!(
        "WARNING TIMEOUT {operation} exceeded {:.3}s ({context})",
        limit.as_secs_f64()
    )
}

/// Deadline index for owners with an ordered key (PGs, engines, connections).
#[derive(Debug)]
pub struct Index<K: Copy + Ord, T: Copy + Ord = u64> {
    heap: heap::Heap<K, T, BTreeMap<K, Option<usize>>>,
}

impl<K: Copy + Ord, T: Copy + Ord> Default for Index<K, T> {
    fn default() -> Self {
        Self {
            heap: Default::default(),
        }
    }
}

impl<K: Copy + Ord, T: Copy + Ord> Index<K, T> {
    /// Reserve one reusable heap slot for a live owner; call only on creation.
    pub fn register(&mut self, key: K) {
        self.heap.register(key);
    }

    /// Release an owner; a deadline it still holds is dropped.
    pub fn unregister(&mut self, key: K) {
        self.heap.unregister(key);
    }

    /// Update a registered owner. A removed owner may still have a dirty notification; ignore it.
    pub fn set(&mut self, key: K, deadline: Option<T>) {
        self.heap.set(key, deadline);
    }

    /// Earliest `(deadline, key)`; equal deadlines break on the key.
    pub fn first(&self) -> Option<(T, K)> {
        self.heap.first()
    }

    /// Keys due at `now`, earliest deadline first, then key; non-consuming. The `&mut` borrow lets the crate reuse its
    /// collect buffer, so a query allocates only the result vector.
    pub fn due(&mut self, now: T) -> Vec<K> {
        self.heap.due(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// C8: every loud timeout line names its limit in seconds, 3 decimals, with its context.
    #[test]
    fn timeout_line_names_the_limit() {
        assert_eq!(
            timeout_line("mon command", Duration::from_millis(2500), "tid 7"),
            "WARNING TIMEOUT mon command exceeded 2.500s (tid 7)"
        );
        assert_eq!(
            timeout_line("mon hunt round", Duration::from_secs(3), "x"),
            "WARNING TIMEOUT mon hunt round exceeded 3.000s (x)"
        );
        assert_eq!(
            timeout_line("ack", Duration::from_millis(50), "c"),
            "WARNING TIMEOUT ack exceeded 0.050s (c)"
        );
        assert_eq!(
            timeout_line("op", Duration::from_secs(1), ""),
            "WARNING TIMEOUT op exceeded 1.000s ()"
        );
    }

    /// Owners re-register on every change (`eng_note`): a repeated `register` keeps the deadline already queued.
    #[test]
    fn register_again_keeps_a_queued_deadline() {
        let mut q = Index::<u32>::default();
        q.register(1);
        q.set(1, Some(5));
        q.register(1);
        assert_eq!(q.first(), Some((5, 1)));
        q.register(2);
        q.set(2, Some(3));
        q.register(1);
        q.set(1, None);
        assert_eq!(q.first(), Some((3, 2)));
        q.set(2, None);
        assert_eq!(q.first(), None);
    }
    #[test]
    fn indexed_updates_match_ordered_reference() {
        let mut q = Index::default();
        let mut reference = BTreeMap::new();
        for key in 0..1000 {
            q.register(key);
        }
        let mut seed = 13u64;
        for _ in 0..10_000 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let key = (seed >> 32) % 1000;
            let d = (seed & 3 != 0).then_some(seed % 1000);
            q.set(key, d);
            if let Some(d) = d {
                reference.insert(key, d);
            } else {
                reference.remove(&key);
            }
            assert_eq!(q.first(), reference.iter().map(|(&k, &d)| (d, k)).min());
        }
        let mut due: Vec<_> = reference
            .iter()
            .filter(|(_, d)| **d <= 500)
            .map(|(&k, &d)| (d, k))
            .collect();
        due.sort_unstable();
        assert_eq!(q.due(500), due.iter().map(|&(_, k)| k).collect::<Vec<_>>());
        assert_eq!(q.due(500), q.due(500), "queries do not consume deadlines");
        for key in 0..1000 {
            q.unregister(key);
        }
        assert_eq!(q.first(), None);
        q.register(7);
        q.set(7, Some(1));
        q.unregister(7);
        q.set(7, Some(2));
        assert_eq!(q.first(), None, "removed owners cannot resurrect deadlines");
    }
}
