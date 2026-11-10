// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Core-pair sequencing assigned before any local outbox or ring can stall.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Data(usize),
    Ordered,
    Progress,
}

/// Internal ownership envelope; none of these fields are encoded on the network.
#[derive(Debug)]
pub struct Stamped<T> {
    pub value: T,
    pub lane: usize,
    pub generation: u64,
    pub ordinal: u64,
    pub predecessors: Option<Box<[u64]>>,
    pub serial: u64,
}

impl<T> Stamped<T> {
    pub fn lane(&self) -> usize {
        self.lane
    }
}

#[derive(Debug)]
pub struct Sequencer {
    cores: usize,
    lanes: usize,
    sent: Vec<u64>,
    generation: Vec<u64>,
    serial: u64,
}

impl Sequencer {
    pub fn new(cores: usize, lanes: usize) -> Self {
        assert!(cores > 0 && (lanes == 1 || lanes >= 3));
        Self {
            cores,
            lanes,
            sent: vec![0; cores * lanes],
            generation: vec![0; cores],
            serial: 0,
        }
    }

    /// Data and progress use preallocated counters; only ordered cold controls allocate snapshots.
    pub fn stamp<T>(&mut self, dst: usize, route: Route, value: T) -> Stamped<T> {
        assert!(dst < self.cores);
        let lane = if self.lanes == 1 {
            0
        } else {
            match route {
                Route::Ordered => 0,
                Route::Progress => 1,
                Route::Data(lane) => {
                    assert!(lane < self.lanes - 2);
                    lane + 2
                }
            }
        };
        let predecessors = if self.lanes > 1 && route == Route::Ordered {
            let start = dst * self.lanes;
            let snapshot = self.sent[start..start + self.lanes].into();
            self.generation[dst] += 1;
            Some(snapshot)
        } else {
            None
        };
        self.sent[dst * self.lanes + lane] += 1;
        self.serial += 1;
        Stamped {
            value,
            lane,
            generation: self.generation[dst],
            ordinal: self.sent[dst * self.lanes + lane],
            predecessors,
            serial: self.serial,
        }
    }

    /// Legacy single-ring callers return ownership to their caller on a failed send.
    pub fn undo_single_send(&mut self, dst: usize) {
        assert_eq!(self.lanes, 1);
        self.sent[dst] -= 1;
    }
}

/// One FIFO per core-pair lane. Blocked lanes retain their heads while other lanes can be drained.
#[derive(Debug)]
pub struct Outbox<T> {
    lanes: usize,
    queues: Vec<std::collections::VecDeque<Stamped<T>>>,
    active: std::collections::VecDeque<usize>,
    count: usize,
}

impl<T> Outbox<T> {
    pub fn new(cores: usize, lanes: usize) -> Self {
        Self {
            lanes,
            queues: (0..cores * lanes)
                .map(|_| std::collections::VecDeque::with_capacity(32))
                .collect(),
            active: std::collections::VecDeque::with_capacity(cores * lanes),
            count: 0,
        }
    }

    /// OSDs have no self channel, and physical shard s can only route towards s % cores.
    pub fn sparse(cores: usize, lanes: usize, me: usize) -> Self {
        let shards = lanes - 4;
        Self {
            lanes,
            queues: (0..cores * lanes)
                .map(|index| {
                    let (dst, lane) = (index / lanes, index % lanes);
                    let capacity = if dst == me {
                        0
                    } else if lane == 0 {
                        128
                    } else if lane == 1 {
                        1
                    } else if lane == lanes - 1 {
                        64
                    } else if lane == lanes - 2 {
                        32
                    } else if (lane - 2) < shards && (lane - 2) % cores == dst {
                        128
                    } else {
                        0
                    };
                    std::collections::VecDeque::with_capacity(capacity)
                })
                .collect(),
            active: std::collections::VecDeque::with_capacity(cores * lanes),
            count: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Independent samples need only their newest value; retain the existing sequence position.
    pub fn replace_tail(&mut self, dst: usize, lane: usize, value: T) -> Result<(), T> {
        if let Some(tail) = self.queues[dst * self.lanes + lane].back_mut() {
            tail.value = value;
            Ok(())
        } else {
            Err(value)
        }
    }

    pub fn push(&mut self, dst: usize, message: Stamped<T>) {
        let index = dst * self.lanes + message.lane;
        if self.queues[index].is_empty() {
            self.active.push_back(index);
        }
        self.queues[index].push_back(message);
        self.count += 1;
    }

    /// Only each lane's head may pass the port's capacity test.
    pub fn pop_ready(
        &mut self,
        mut ready: impl FnMut(usize, usize, &T) -> bool,
    ) -> Option<(usize, Stamped<T>)> {
        let visits = self.active.len();
        for _ in 0..visits {
            let index = self.active.pop_front().unwrap();
            let queue = &mut self.queues[index];
            let message = queue.front().unwrap();
            if !ready(index / self.lanes, index % self.lanes, &message.value) {
                self.active.push_back(index);
                continue;
            }
            let message = queue.pop_front().unwrap();
            if !queue.is_empty() {
                self.active.push_back(index);
            }
            self.count -= 1;
            return Some((index / self.lanes, message));
        }
        None
    }

    /// Compatibility for simulations without a lane-aware port: retain the original global insertion order.
    pub fn pop_fifo(&mut self) -> Option<(usize, Stamped<T>)> {
        let index = self
            .active
            .iter()
            .copied()
            .min_by_key(|&i| self.queues[i].front().unwrap().serial)?;
        let lanes = self.lanes;
        self.pop_ready(|dst, lane, _| dst * lanes + lane == index)
    }
}
