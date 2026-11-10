// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH

use std::collections::{BTreeSet, VecDeque};

/// Indexed membership with ticket-arrival traversal order. The ingress gate
/// orders admission across cores; preserving local arrival order lets one pass
/// admit consecutive ready tickets instead of repeatedly rejecting newer ones.
#[derive(Debug)]
pub(crate) struct FrameWait<T = u64> {
    order: VecDeque<T>,
    members: BTreeSet<T>,
}

impl<T: Ord + Clone> FrameWait<T> {
    pub(crate) fn new() -> Self {
        Self {
            order: VecDeque::new(),
            members: BTreeSet::new(),
        }
    }

    pub(crate) fn insert(&mut self, id: T) {
        if self.members.insert(id.clone()) {
            self.order.push_back(id);
        }
    }

    pub(crate) fn retain(&mut self, mut keep: impl FnMut(&T) -> bool) {
        self.order.retain(|id| {
            if keep(id) {
                true
            } else {
                self.members.remove(id);
                false
            }
        });
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

impl<'a, T> IntoIterator for &'a FrameWait<T> {
    type Item = &'a T;
    type IntoIter = std::collections::vec_deque::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.order.iter()
    }
}

#[cfg(test)]
mod frame_wait_tests {
    use super::FrameWait;
    use std::cell::Cell;
    use std::cmp::Ordering;
    use std::rc::Rc;

    #[derive(Clone)]
    struct Key(u64, Rc<Cell<usize>>);

    impl PartialEq for Key {
        fn eq(&self, other: &Self) -> bool {
            self.1.set(self.1.get() + 1);
            self.0 == other.0
        }
    }
    impl Eq for Key {}
    impl PartialOrd for Key {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }
    impl Ord for Key {
        fn cmp(&self, other: &Self) -> Ordering {
            self.1.set(self.1.get() + 1);
            self.0.cmp(&other.0)
        }
    }

    #[test]
    fn frame_wait_admission_scales_without_scanning_parked_sessions() {
        for n in [1_000usize, 10_000] {
            let probes = Rc::new(Cell::new(0));
            let mut indexed = FrameWait::new();
            for id in 0..n {
                indexed.insert(Key(id as u64, probes.clone()));
            }
            let first = probes.replace(0);
            for id in 0..n {
                indexed.insert(Key(id as u64, probes.clone()));
            }
            let duplicate = probes.get();
            assert_eq!(indexed.order.len(), n);
            // A tree node can compare several keys. Bound growth by N log N,
            // without relying on wall-clock timing or a particular node size.
            let bound = 8 * n * (n.ilog2() as usize + 1);
            assert!(first < bound, "{n} insertions: {first} comparisons");
            assert!(duplicate < bound, "{n} duplicates: {duplicate} comparisons");

            eprintln!("frame_wait n={n} indexed={first} duplicates={duplicate}");

            indexed.retain(|k| k.0 % 2 == 0);
            assert_eq!(indexed.order.len(), n / 2);
            for id in 0..n {
                indexed.insert(Key(id as u64, probes.clone()));
            }
            assert_eq!(indexed.order.len(), n, "retired waiters may park again");
        }
    }

    #[test]
    fn frame_wait_preserves_ticket_order_with_reverse_connection_ids() {
        let mut wait = FrameWait::new();
        for id in (0..10_000).rev() {
            wait.insert(id);
            wait.insert(id); // duplicate readiness does not move its ticket
        }
        let mut head = 9_999;
        let mut visits = 0;
        wait.retain(|id| {
            visits += 1;
            assert_eq!(*id, head, "newer ticket visited before the oldest");
            head -= 1;
            false
        });
        assert_eq!(visits, 10_000, "all ready tickets drain in one pass");
        assert!(wait.is_empty());
        assert!(wait.members.is_empty());
        wait.insert(3);
        assert_eq!(wait.into_iter().copied().collect::<Vec<_>>(), [3]);
    }
}
