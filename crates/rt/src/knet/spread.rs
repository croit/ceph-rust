// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Receive spread of the kernel tier (adr 0053 am. 3): the rest of a
//! large msgr2 data segment of one connection is received by ANOTHER core of the OSD. The kernel copies socket data in
//! the context of the thread that issues the `recv`, so the helper core pays the copy (sys time) and the block crcs
//! (adr 0061 am. 4) instead of the connection's core; TCP stays where it is.
//!
//! A [`RecvJob`] carries the lent segment buffer (`DirectRx`) and the socket fd to a helper, which receives it piecewise
//! on its own io_uring (`DIRECT_CHUNK` pieces, crc per piece while cache hot) and sends the job back. One job per
//! connection at a time (a byte stream is read in order); the connection's core keeps the fd open and issues no receive
//! on it while the job is out (`Conn::inflight`, `Rx::Away`). Rings: one SPSC job ring and one SPSC done ring per ordered
//! core pair; a submitter keeps at most `CAP` jobs out per helper, so a done ring never refuses. Wake-ups via the cores'
//! eventfds ([`crate::wake`]). No allocation per job: the job moves the connection's `DirectRx`.
//!
//! Send spread (adr 0053 am. 12), the mirror: a copied send batch larger than [`SEND_SPREAD_MIN`] leaves the
//! connection's core as a [`SendJob`] (fd + the connection's `SendState` box with its runs) to the core of the OSD with
//! the fewest send jobs running (ties: round robin, this core included), which issues the `SENDMSG` on its own ring (the
//! kernel copy runs there) and returns the job; the connection's core then pulls the next output. One send per
//! connection at a time as before (`Conn::sending` stays set while the job is out), so the byte stream keeps its order.
//! The load counts are shared atomics: a submitter counts its job on the chosen core at once, the executing core
//! uncounts it when done.
use super::{DirectRx, SendState};
use crate::spsc::{Consumer, Producer, channel};
use crate::wake::Wake;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

/// Jobs one submitter may have out per helper (= ring capacity).
const CAP: usize = 16;

/// The rest of one data segment, received by a helper core.
pub(super) struct RecvJob {
    /// Submitting core.
    pub from: usize,
    /// Connection slot and id on the submitter.
    pub slot: u32,
    pub id: u64,
    pub fd: RawFd,
    /// The lent segment buffer, its block crcs and the bytes still to come.
    pub dx: DirectRx,
    /// Bytes received by the helper.
    pub got: usize,
    /// Final failing receive result (0 = EOF, < 0 = -errno), `None` = the segment is complete.
    pub failed: Option<i32>,
}

/// Copied send batches larger than this go to the core with the fewest send jobs: the direct receive piece
/// (`DIRECT_CHUNK`). A copied send costs the kernel ~0.5 ns/B on the measured hosts (copy + page init), so this is
/// ~130 us of core time, about one loop slice; a smaller batch costs less than the hop and the lost cache locality.
pub(super) const SEND_SPREAD_MIN: usize = 256 << 10;

/// One send batch of a connection, sent by the core of the mesh with the fewest send jobs.
pub(super) struct SendJob {
    /// Submitting core.
    pub from: usize,
    /// Connection slot and id on the submitter.
    pub slot: u32,
    pub id: u64,
    pub fd: RawFd,
    /// The connection's send state: its runs are what is left to send (stable heap memory for the kernel).
    pub st: Box<SendState>,
    /// Bytes sent by the executing core.
    pub sent: usize,
    /// Final failing send result (-errno), `None` = everything went out.
    pub failed: Option<i32>,
}

// SAFETY: the raw pointers inside `SendState` (msghdr -> iovec array -> run bytes) point only into heap memory the job
// owns itself (`iov`, `runs`); they move with it and are dereferenced only by the kernel for the request of the one core
// that holds the job.
unsafe impl Send for SendJob {}

/// One core's end of the receive-spread mesh.
pub struct KSpread {
    id: usize,
    jobs_tx: Vec<Option<Producer<RecvJob>>>,
    jobs_rx: Vec<Option<Consumer<RecvJob>>>,
    done_tx: Vec<Option<Producer<RecvJob>>>,
    done_rx: Vec<Option<Consumer<RecvJob>>>,
    out: Vec<usize>,
    next: usize,
    wakes: Option<Arc<[Arc<Wake>]>>,
    /// Helper side: jobs with a receive in flight on this core's ring (index = user_data slot).
    pub(super) run: Vec<Option<RecvJob>>,
    run_free: Vec<u32>,
    sjobs_tx: Vec<Option<Producer<SendJob>>>,
    sjobs_rx: Vec<Option<Consumer<SendJob>>>,
    sdone_tx: Vec<Option<Producer<SendJob>>>,
    sdone_rx: Vec<Option<Consumer<SendJob>>>,
    sout: Vec<usize>,
    snext: usize,
    /// Send jobs running (or queued) per core of the mesh, shared by all cores.
    sload: Arc<[AtomicU32]>,
    /// Executing side: send jobs with a send in flight on this core's ring (index = user_data slot).
    pub(super) srun: Vec<Option<SendJob>>,
    srun_free: Vec<u32>,
    /// Own jobs this core executed itself, back for their connection.
    sdone_self: Vec<SendJob>,
}

impl std::fmt::Debug for KSpread {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KSpread")
            .field("id", &self.id)
            .field("out", &self.out)
            .finish()
    }
}

/// Build the mesh for the `n` network cores of one OSD (`wakes[i]` = core i's wake handle, if the cores sleep).
pub fn mesh(n: usize, wakes: Option<Arc<[Arc<Wake>]>>) -> Vec<KSpread> {
    let sload: Arc<[AtomicU32]> = (0..n).map(|_| AtomicU32::new(0)).collect();
    let mut v: Vec<KSpread> = (0..n)
        .map(|id| KSpread {
            id,
            jobs_tx: (0..n).map(|_| None).collect(),
            jobs_rx: (0..n).map(|_| None).collect(),
            done_tx: (0..n).map(|_| None).collect(),
            done_rx: (0..n).map(|_| None).collect(),
            out: vec![0; n],
            next: id,
            wakes: wakes.clone(),
            run: Vec::new(),
            run_free: Vec::new(),
            sjobs_tx: (0..n).map(|_| None).collect(),
            sjobs_rx: (0..n).map(|_| None).collect(),
            sdone_tx: (0..n).map(|_| None).collect(),
            sdone_rx: (0..n).map(|_| None).collect(),
            sout: vec![0; n],
            snext: id,
            sload: sload.clone(),
            srun: Vec::new(),
            srun_free: Vec::new(),
            sdone_self: Vec::new(),
        })
        .collect();
    for i in 0..n {
        for j in 0..n {
            if i != j {
                let (p, c) = channel(CAP);
                v[i].jobs_tx[j] = Some(p);
                v[j].jobs_rx[i] = Some(c);
                let (p, c) = channel(CAP);
                v[j].done_tx[i] = Some(p);
                v[i].done_rx[j] = Some(c);
                let (p, c) = channel(CAP);
                v[i].sjobs_tx[j] = Some(p);
                v[j].sjobs_rx[i] = Some(c);
                let (p, c) = channel(CAP);
                v[j].sdone_tx[i] = Some(p);
                v[i].sdone_rx[j] = Some(c);
            }
        }
    }
    v
}

impl KSpread {
    /// This core.
    pub fn id(&self) -> usize {
        self.id
    }

    fn poke(&self, core: usize) {
        if let Some(w) = &self.wakes {
            w[core].poke();
        }
    }

    /// Hand `j` to the next helper with room (round robin); gives it back when every helper is full.
    /// The refused job comes back by value: a move of the inline segment state, no allocation.
    #[expect(clippy::result_large_err)]
    pub(super) fn submit(&mut self, mut j: RecvJob) -> Result<(), RecvJob> {
        let n = self.jobs_tx.len();
        for _ in 0..n {
            self.next = (self.next + 1) % n;
            let h = self.next;
            if self.out[h] < CAP
                && let Some(p) = self.jobs_tx[h].as_mut()
            {
                match p.push(j) {
                    Ok(()) => {
                        self.out[h] += 1;
                        self.poke(h);
                        return Ok(());
                    }
                    Err(back) => j = back,
                }
            }
        }
        Err(j)
    }

    /// Next job another core sent here (helper side).
    pub(super) fn take_job(&mut self) -> Option<RecvJob> {
        self.jobs_rx.iter_mut().flatten().find_map(Consumer::pop)
    }

    /// Park a job whose receive goes into this core's ring; returns its run slot.
    pub(super) fn park(&mut self, j: RecvJob) -> u32 {
        match self.run_free.pop() {
            Some(i) => {
                self.run[i as usize] = Some(j);
                i
            }
            None => {
                self.run.push(Some(j));
                (self.run.len() - 1) as u32
            }
        }
    }

    /// The job of run slot `i` is finished: send it back to its submitter.
    pub(super) fn finish(&mut self, i: u32) {
        let Some(j) = self.run[i as usize].take() else {
            return;
        };
        self.run_free.push(i);
        let from = j.from;
        // never full: the submitter keeps at most CAP jobs out towards this core
        if self.done_tx[from]
            .as_mut()
            .expect("done ring")
            .push(j)
            .is_err()
        {
            unreachable!("knet spread done ring full");
        }
        self.poke(from);
    }

    /// Next own job that came back (submitter side).
    pub(super) fn take_done(&mut self) -> Option<RecvJob> {
        for h in 0..self.done_rx.len() {
            if self.out[h] == 0 {
                continue;
            }
            if let Some(j) = self.done_rx[h].as_mut().and_then(Consumer::pop) {
                self.out[h] -= 1;
                return Some(j);
            }
        }
        None
    }

    /// Nothing waits in a job or done ring of this core (idle re-check before sleeping).
    pub fn quiet(&self) -> bool {
        self.jobs_rx.iter().flatten().all(Consumer::is_empty)
            && self
                .done_rx
                .iter()
                .zip(&self.out)
                .all(|(c, &o)| o == 0 || c.as_ref().is_none_or(Consumer::is_empty))
            && self.sjobs_rx.iter().flatten().all(Consumer::is_empty)
            && self
                .sdone_rx
                .iter()
                .zip(&self.sout)
                .all(|(c, &o)| o == 0 || c.as_ref().is_none_or(Consumer::is_empty))
            && self.sdone_self.is_empty()
    }

    /// Own jobs out on helpers.
    pub fn outstanding(&self) -> usize {
        self.out.iter().sum::<usize>() + self.sout.iter().sum::<usize>()
    }

    /// Core for a send job: the fewest send jobs counted, ties round robin (this core included). Counts the job there.
    /// `None` = every other core with the fewest has `CAP` own jobs out already (the caller sends inline).
    fn pick_sender(&mut self) -> Option<usize> {
        let n = self.sload.len();
        let mut best: Option<(u32, usize)> = None;
        for k in 1..=n {
            let h = (self.snext + k) % n;
            if h != self.id && self.sout[h] >= CAP {
                continue;
            }
            let l = self.sload[h].load(Ordering::Relaxed);
            if best.is_none_or(|(b, _)| l < b) {
                best = Some((l, h));
            }
        }
        let (_, h) = best?;
        self.snext = h;
        self.sload[h].fetch_add(1, Ordering::Relaxed);
        Some(h)
    }

    /// Hand a send job to the core with the fewest send jobs. `Ok(Some)` = it runs on this core (`park_send` it),
    /// `Ok(None)` = out on another core, `Err` = no core with room (the caller sends it the classic way).
    pub(super) fn submit_send(&mut self, j: SendJob) -> Result<Option<SendJob>, SendJob> {
        let Some(h) = self.pick_sender() else {
            return Err(j);
        };
        if h == self.id {
            return Ok(Some(j));
        }
        match self.sjobs_tx[h].as_mut().expect("send job ring").push(j) {
            Ok(()) => {
                self.sout[h] += 1;
                self.poke(h);
                Ok(None)
            }
            Err(j) => {
                // never full: at most CAP own jobs out towards h
                self.sload[h].fetch_sub(1, Ordering::Relaxed);
                Err(j)
            }
        }
    }

    /// Next send job another core sent here.
    pub(super) fn take_send(&mut self) -> Option<SendJob> {
        self.sjobs_rx.iter_mut().flatten().find_map(Consumer::pop)
    }

    /// Park a send job whose send goes into this core's ring; returns its run slot.
    pub(super) fn park_send(&mut self, j: SendJob) -> u32 {
        match self.srun_free.pop() {
            Some(i) => {
                self.srun[i as usize] = Some(j);
                i
            }
            None => {
                self.srun.push(Some(j));
                (self.srun.len() - 1) as u32
            }
        }
    }

    /// The send job of run slot `i` is finished: uncount it, back to its submitter.
    pub(super) fn finish_send(&mut self, i: u32) {
        let Some(j) = self.srun[i as usize].take() else {
            return;
        };
        self.srun_free.push(i);
        self.sload[self.id].fetch_sub(1, Ordering::Relaxed);
        let from = j.from;
        if from == self.id {
            self.sdone_self.push(j);
            return;
        }
        if self.sdone_tx[from]
            .as_mut()
            .expect("send done ring")
            .push(j)
            .is_err()
        {
            unreachable!("knet send-spread done ring full");
        }
        self.poke(from);
    }

    /// Next own send job that came back (submitter side).
    pub(super) fn take_send_done(&mut self) -> Option<SendJob> {
        if let Some(j) = self.sdone_self.pop() {
            return Some(j);
        }
        for h in 0..self.sdone_rx.len() {
            if self.sout[h] == 0 {
                continue;
            }
            if let Some(j) = self.sdone_rx[h].as_mut().and_then(Consumer::pop) {
                self.sout[h] -= 1;
                return Some(j);
            }
        }
        None
    }

    /// Send jobs counted on each core (diagnostics, tests).
    pub fn send_load(&self) -> Vec<u32> {
        self.sload
            .iter()
            .map(|a| a.load(Ordering::Relaxed))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Send jobs go to the core with the fewest counted jobs (ties round robin, the submitter included) and are
    /// uncounted where they finish: two connections' sends end up on different cores, never stacked on one.
    #[test]
    fn send_jobs_pick_the_core_with_the_fewest() {
        let mut m = mesh(4, None);
        let a = m[0].pick_sender().unwrap();
        let b = m[1].pick_sender().unwrap();
        assert_ne!(a, b, "second job stacked on a sending core");
        let c = m[0].pick_sender().unwrap();
        let d = m[2].pick_sender().unwrap();
        let mut all = vec![a, b, c, d];
        all.sort_unstable();
        assert_eq!(all, [0, 1, 2, 3], "four jobs, four cores");
        assert_eq!(m[3].send_load(), [1, 1, 1, 1]);
        m[a].sload[a].fetch_sub(1, Ordering::Relaxed);
        assert_eq!(m[3].pick_sender(), Some(a), "the freed core is next");
        // a busy helper stays the choice of no one while idle cores exist
        let n: Vec<usize> = (0..8)
            .map(|k| {
                let h = m[k % 4].pick_sender().unwrap();
                m[h].sload[h].fetch_sub(1, Ordering::Relaxed);
                h
            })
            .collect();
        assert!(n.iter().all(|&h| h < 4));
    }
}
