// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Accept-time connection placement (open question 11): RSS / the kernel's `SO_REUSEPORT` hash spread client
//! connections over the cores by 4-tuple hash, balls into bins: 8 connections leave cores idle in most draws, and a
//! connection never moves later. Here the core that receives a public connection hands it to the least loaded core
//! instead, before anything was read from it, so every connection is owned by the core with the fewest connections at
//! that moment. What travels is the accepted socket (`knet::KPlace`).
//!
//! Shared state is one atomic counter per core (connections it owns plus hand-offs in transit to it: one moves from
//! "in transit" to "owned" without the counter changing, so a reader never sees a gap or a double count) read with
//! relaxed loads at accept time only; the hand-off travels in an `mpsc` channel (accept is rare, never on the data path).
//! A hand-off rings the target core's [`ingress::Doorbell`]: a sleeping target is woken, an awake one sees it in its
//! sleep re-check ([`Place::waiting`]).
//!
//! Load = connection count. Crude (a bulk stream weighs like an idle client) but it removes the dominant effect (two
//! busy connections on one core while another core idles) with no measurement loop; weighing by recent bytes is the
//! next step if needed. With `--steer cpu` flows are aligned with the NIC queue's core instead: do not combine.
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};

#[derive(Debug)]
struct Loads {
    /// Connections owned by core `i` plus sockets sent to it that it did not adopt yet (one word: no torn reads).
    conns: Vec<AtomicU32>,
    /// CPU of core `i` (empty = unknown: no softirq avoidance).
    cpus: Vec<usize>,
    /// Hand-offs to core `i` not taken yet, and its waker.
    bells: Vec<ingress::Doorbell>,
}

/// One core's end of the placement group; `T` = what a hand-off carries.
#[derive(Debug)]
pub struct Place<T> {
    me: usize,
    loads: Arc<Loads>,
    tx: Vec<Sender<T>>,
    rx: Receiver<T>,
}

impl<T> Place<T> {
    /// Placement ends for `n` cores (index = core); hand end `i` to core `i`.
    pub fn group(n: usize) -> Vec<Place<T>> {
        Self::group_on(n, Vec::new())
    }

    /// As [`group`](Self::group) with the CPU of every core (`cpus[i]` = CPU of core `i`), for [`pick`](Self::pick)'s
    /// softirq avoidance.
    pub fn group_on(n: usize, cpus: Vec<usize>) -> Vec<Place<T>> {
        let loads = Arc::new(Loads {
            cpus,
            conns: (0..n).map(|_| AtomicU32::new(0)).collect(),
            bells: (0..n).map(|_| ingress::Doorbell::default()).collect(),
        });
        let (tx, rx): (Vec<_>, Vec<_>) = (0..n).map(|_| channel()).unzip();
        rx.into_iter()
            .enumerate()
            .map(|(me, rx)| Place {
                me,
                loads: loads.clone(),
                tx: tx.clone(),
                rx,
            })
            .collect()
    }

    /// This core's index in the group.
    pub fn me(&self) -> usize {
        self.me
    }

    fn load(&self, i: usize) -> u32 {
        self.loads.conns[i].load(Ordering::Relaxed)
    }

    /// Core that should own a new connection accepted here: another core if it has strictly fewer connections (ties
    /// stay; the scan starts after this core so equal candidates rotate between the accepting cores). `rx_cpu` = the
    /// CPU of the connection's softirq (adr 0053 am. 4): the core pinned to it is skipped when there is another one.
    pub fn pick(&self, rx_cpu: Option<usize>) -> usize {
        let n = self.tx.len();
        let avoid = rx_cpu
            .and_then(|c| self.loads.cpus.iter().position(|x| *x == c))
            .filter(|_| n > 1);
        let mut best = self.me;
        let mut best_load = if avoid == Some(self.me) {
            u32::MAX
        } else {
            self.load(self.me)
        };
        for k in 1..n {
            let i = (self.me + k) % n;
            let l = self.load(i);
            if Some(i) != avoid && l < best_load {
                best = i;
                best_load = l;
            }
        }
        best
    }

    /// Hand `a` to core `to` (counted as in transit until it adopts) and wake it. Gives it back if the core is gone.
    pub fn send(&self, to: usize, a: T) -> Result<(), T> {
        self.loads.conns[to].fetch_add(1, Ordering::Relaxed);
        self.post(to, a).inspect_err(|_| {
            self.loads.conns[to].fetch_sub(1, Ordering::Relaxed);
        })
    }

    /// Send `a` to core `to` without counting it (a notice, not a connection) and wake it. Gives it back if the core is
    /// gone.
    pub fn post(&self, to: usize, a: T) -> Result<(), T> {
        let bell = &self.loads.bells[to];
        bell.queue();
        match self.tx[to].send(a) {
            Ok(()) => {
                bell.ring();
                Ok(())
            }
            Err(e) => {
                bell.take();
                Err(e.0)
            }
        }
    }

    /// Install this core's waker: hand-offs to it wake it.
    pub fn set_waker(&self, w: Arc<dyn ingress::Waker>) {
        self.loads.bells[self.me].set_waker(w);
    }

    /// A hand-off to this core waits or is being sent (the sleep re-check after the announcement).
    pub fn waiting(&self) -> bool {
        self.loads.bells[self.me].waiting()
    }

    /// A hand-off another core sent to this one. Already counted in this core's load by [`send`](Self::send): the
    /// connection made from it must not be counted again (`KNet::add_conn` with `counted`); one that ends before it was
    /// owned gives its count back with [`lose`](Self::lose).
    pub fn take(&self) -> Option<T> {
        let a = self.rx.try_recv().ok()?;
        self.loads.bells[self.me].take();
        Some(a)
    }

    /// This core gained an owned connection.
    pub fn gain(&self) {
        self.loads.conns[self.me].fetch_add(1, Ordering::Relaxed);
    }

    /// This core lost an owned connection (or a taken hand-off ended before it was owned).
    pub fn lose(&self) {
        self.loads.conns[self.me].fetch_sub(1, Ordering::Relaxed);
    }

    /// Connections this core owns or has in transit (diagnostics).
    pub fn owned_now(&self) -> u32 {
        self.loads.conns[self.me].load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_the_least_loaded_core_and_ties_stay() {
        let g = Place::<u32>::group(4);
        assert_eq!(g[0].pick(None), 0, "all equal: stay");
        g[0].gain();
        assert_eq!(g[0].pick(None), 1, "core 0 has one, the others none");
        g[1].gain();
        g[2].gain();
        assert_eq!(g[0].pick(None), 3);
        g[3].gain();
        assert_eq!(g[0].pick(None), 0, "all equal again");
        g[0].gain();
        assert_eq!(g[0].pick(None), 1, "scan starts after the accepting core");
        assert_eq!(g[3].pick(None), 3, "core 3 is not above the others");
    }

    #[test]
    fn in_transit_counts_as_load() {
        let g = Place::<u32>::group(2);
        let mk = || 7u32;
        g[0].gain();
        assert_eq!(g[0].pick(None), 1);
        assert!(g[0].send(1, mk()).is_ok());
        assert_eq!(g[0].pick(None), 0, "core 1 has one in transit: equal, stay");
        assert!(g[1].take().is_some());
        assert!(g[1].take().is_none());
        assert_eq!(
            g[0].pick(None),
            0,
            "taken, not registered yet: still counted"
        );
        assert_eq!(g[0].pick(None), 0, "adopted: counted once, not twice");
        g[1].lose();
        assert_eq!(g[0].pick(None), 1);
    }

    /// A hand-off wakes its target core (doc/perf/sleep-register-20261101.md row 5): before, an adopted socket waited for
    /// the target's idle cap. The target's re-check sees a hand-off until it took it; a refused send leaves no count.
    #[test]
    fn a_hand_off_wakes_the_target_core() {
        #[derive(Debug, Default)]
        struct Count(AtomicU32);
        impl ingress::Waker for Count {
            fn wake(&self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let mut g = Place::<u32>::group(3);
        let w = Arc::new(Count::default());
        g[1].set_waker(w.clone());
        assert!(!g[1].waiting());
        assert!(g[0].send(1, 7).is_ok());
        assert!(g[2].post(1, 8).is_ok());
        assert_eq!(w.0.load(Ordering::Relaxed), 2);
        assert!(g[1].waiting());
        assert_eq!(g[1].take(), Some(7));
        assert!(g[1].waiting());
        assert_eq!(g[1].take(), Some(8));
        assert!(!g[1].waiting());
        drop(g.remove(1));
        assert_eq!(g[0].send(1, 9), Err(9), "that core is gone");
        assert_eq!(w.0.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn pick_avoids_the_core_of_the_softirq_cpu() {
        let g = Place::<u32>::group_on(3, vec![2, 3, 4]);
        assert_eq!(
            g[0].pick(Some(2)),
            1,
            "all equal: next core, not the softirq core 0 (cpu 2)"
        );
        assert_eq!(g[0].pick(Some(3)), 0, "softirq on another core: stay");
        assert_eq!(g[0].pick(Some(9)), 0, "unknown cpu: as without");
        g[1].gain();
        g[2].gain();
        assert_eq!(
            g[0].pick(Some(2)),
            1,
            "the softirq core is skipped even when it is the least loaded"
        );
        assert_eq!(g[1].pick(Some(2)), 1, "ties stay on the accepting core");
        let one = Place::<u32>::group_on(1, vec![2]);
        assert_eq!(one[0].pick(Some(2)), 0, "a single core takes everything");
        let unknown = Place::<u32>::group(2);
        assert_eq!(unknown[0].pick(Some(0)), 0, "no cpu map: no avoidance");
    }
}
