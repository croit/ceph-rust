// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! The zcrx receive of a knet core (adr 0464, doc/spec/knet-zcrx.md): connections accepted from this core's zcrx queue
//! receive through `RECV_ZC` on the core's [`ZCore`] ring instead of the buffer ring. The OSD-facing rules are the copy
//! path's: bytes go to `Driver::on_bytes` or into a lent segment buffer (`Rx::Direct`, filled here from the area with
//! its crc instead of by socket receives), input the OSD does not take is held per connection and the socket is left
//! unread once a connection holds its receive queue's worth (`Conn::rmem`), so the peer blocks as on the copy path.
//!
//! Every area chunk goes back in the loop iteration that consumed it; held fragments stay leased within the core's lease
//! budget, beyond it they are copied out and their chunk goes back at once ([`zcrx::book`]).
use super::zcrx::book::Held;
use super::zcrx::{Plan, Reason, ZCore, ZStats};
use super::{Conn, DirectRx, Driver, K_ZWAKE, KNet, KStats, Rx};
use io_uring::opcode;
use io_uring::types::Fd;
use std::sync::Arc;
use std::time::Duration;

impl<const N: usize> KNet<N> {
    /// Receive the connections of this core's zcrx queue (`plan.queues[core]`, or every accepted connection in the
    /// device-less test mode) through `RECV_ZC`. Call on every core before polling: placement by NAPI id needs the
    /// plan on all cores. `Ok` = the core's description; `Err` = this core receives by copy (startup line).
    pub fn set_zcrx(&mut self, plan: Arc<Plan>, core: usize) -> Result<String, Reason> {
        if let Some(r) = &plan.off {
            return Err(r.clone());
        }
        let rxq = if plan.nodev {
            None
        } else {
            match plan.queues.get(core) {
                Some(&(q, napi)) => {
                    self.znapi = napi;
                    Some(q)
                }
                None => {
                    self.zplan = Some(plan);
                    return Err(Reason::NoQueueLeft);
                }
            }
        };
        let z = ZCore::new(&plan, rxq);
        self.zplan = Some(plan);
        let z = z.inspect_err(|_| self.znapi = 0)?;
        let text = z.describe();
        self.zrx = Some(z);
        Ok(text)
    }

    /// zcrx counters of this core (`None`: copy receive).
    pub fn zcrx_stats(&self) -> Option<ZStats> {
        self.zrx.as_ref().map(ZCore::stats)
    }

    /// Before an idle sleep: submit queued zcrx requests and let the zcrx ring's eventfd end the sleep.
    pub(super) fn zwake_arm(&mut self) {
        let Some(z) = self.zrx.as_mut() else {
            return;
        };
        z.submit();
        if self.zwake_armed {
            return;
        }
        self.zwake_armed = true;
        let e = opcode::Read::new(Fd(z.wake_fd()), (&raw mut *self.zwake).cast(), 8)
            .build()
            .user_data(K_ZWAKE);
        self.push(e);
    }

    /// Start the multishot `RECV_ZC` of `slot` (counted in the connection's in-flight requests).
    pub(super) fn zrx_arm(&mut self, slot: u32) {
        let (Some(z), Some(c)) = (self.zrx.as_mut(), self.slots[slot as usize].as_mut()) else {
            return;
        };
        c.inflight += 1;
        c.zarmed = true;
        z.arm(c.fd, slot);
    }

    /// The zcrx phase of `poll`: reap, deliver, return chunks (one refill publish), re-arm ended receives.
    pub(super) fn zrx_poll<D: Driver>(&mut self, d: &mut D, now: Duration) -> bool {
        let Some(z) = self.zrx.as_mut() else {
            return false;
        };
        z.reap();
        let batch = std::mem::take(&mut z.batch);
        for e in &batch {
            self.zrx_cqe(d, e.slot, e.res, e.more, e.off, now);
        }
        let work = !batch.is_empty();
        let z = self.zrx.as_mut().unwrap();
        z.batch = batch;
        // chunks back before re-arming: a receive that ended with ENOMEM finds them
        z.publish();
        if z.take_starved() {
            // a receive that stopped short waits for a socket wakeup that may never come: restart it (module docs)
            for (slot, c) in self.slots.iter().enumerate() {
                if let Some(c) = c
                    && c.zrx
                    && c.zarmed
                {
                    z.cancel(slot as u32);
                }
            }
        }
        for slot in std::mem::take(&mut self.zrearm) {
            if self.slots[slot as usize].as_ref().is_some_and(|c| {
                c.zrx
                    && !c.zarmed
                    && !c.dying
                    && !c.reported
                    && !c.rx_paused
                    && !matches!(c.rx, Rx::Eof)
            }) {
                self.zrx_arm(slot);
            }
        }
        work
    }

    fn zrx_cqe<D: Driver>(
        &mut self,
        d: &mut D,
        slot: u32,
        res: i32,
        more: bool,
        off: u64,
        now: Duration,
    ) {
        let z = self.zrx.as_mut().unwrap();
        let Some(c) = self.slots[slot as usize].as_mut() else {
            // unreachable while the receive counts in `inflight`; never keep a chunk
            if res > 0 {
                z.give(off, res as u32);
            }
            return;
        };
        if !more {
            c.inflight -= 1;
            c.zarmed = false;
        }
        let (silent, dying) = (c.reported, c.dying);
        let mut dead = false;
        if res > 0 {
            z.stats.bytes += res as u64;
            self.stats.rx_bytes += res as u64;
            self.stats.rx_cqes += 1;
            if silent || dying {
                z.give(off, res as u32);
            } else {
                self.zrx_frag(d, slot, off, res as u32, now);
            }
        } else if res == 0 {
            if !dying && !silent && d.keep_half_open() {
                c.rx = Rx::Eof;
                if c.zpend.is_empty() {
                    d.on_eof(c.id, now);
                }
                // A FIN terminates only the read half. Held bytes precede the
                // EOF callback, and this socket must never receive again.
                return;
            }
            dead = true;
        } else {
            match -res {
                // no free chunk / completion queue full: the data waits in the socket, re-armed after the refill
                libc::ENOMEM | libc::ENOSPC => z.stats.rearm_short += 1,
                libc::ECANCELED | libc::EINTR | libc::EAGAIN => {}
                // includes EFAULT: a fragment of another ifq is readable by no one (see the module docs)
                _ => dead = true,
            }
        }
        if dead {
            if !dying {
                self.conn_dead(d, slot, now);
            }
        } else if !more {
            self.zrearm.push(slot);
        }
        self.maybe_free(slot);
    }

    /// A fragment of `slot`'s stream: deliver what the OSD takes, hold the rest.
    fn zrx_frag<D: Driver>(&mut self, d: &mut D, slot: u32, off: u64, len: u32, now: Duration) {
        let c = self.slots[slot as usize].as_ref().unwrap();
        let id = c.id;
        let throttled = !c.zpend.is_empty() || !(d.input_ready(id) || d.rx_parked(id));
        let used = if throttled {
            0
        } else {
            let data = self.zrx.as_ref().unwrap().frag(off, len as usize);
            deliver(
                &mut self.slots,
                &mut self.stats,
                self.cfg.direct_min,
                d,
                slot,
                data,
                now,
            )
        };
        let z = self.zrx.as_mut().unwrap();
        z.stats.copied += used as u64;
        if used == len as usize {
            z.give(off, len);
            return;
        }
        let (off_rest, rest) = (off + used as u64, len - used as u32);
        let c = self.slots[slot as usize].as_mut().unwrap();
        let first = c.zpend.is_empty();
        if z.book.lease(rest as usize) {
            z.stats.leased += 1;
            c.zpend.push(Held::Area {
                off: off_rest,
                len: rest,
            });
        } else {
            c.zpend
                .push(Held::Owned(z.frag(off_rest, rest as usize).to_vec()));
            z.give(off, len);
        }
        if first && !c.rx_paused {
            self.zpaused.push(slot);
        }
        // a connection holds at most its receive queue's worth, then the socket stays unread (TCP backpressure)
        if (c.zpend.bytes() >= c.rmem || d.rx_parked(id)) && !c.rx_paused {
            c.pause(&mut self.stats, now);
            if c.zarmed {
                z.cancel(slot);
            }
        }
    }

    /// Feed held fragments to connections whose input is taken again; resume their receive once nothing is held.
    pub(super) fn zrx_resume<D: Driver>(&mut self, d: &mut D, now: Duration) -> bool {
        let mut work = false;
        let mut keep = Vec::new();
        for slot in std::mem::take(&mut self.zpaused) {
            let Some(c) = self.slots[slot as usize].as_ref() else {
                continue;
            };
            if c.dying || c.reported {
                continue; // held fragments go back when the slot is freed
            }
            let id = c.id;
            if !(d.input_ready(id) || d.rx_parked(id)) {
                keep.push(slot);
                continue;
            }
            while let Some(h) = self.slots[slot as usize].as_mut().unwrap().zpend.pop() {
                work = true;
                match h {
                    Held::Area { off, len } => {
                        let data = self.zrx.as_ref().unwrap().frag(off, len as usize);
                        let used = deliver(
                            &mut self.slots,
                            &mut self.stats,
                            self.cfg.direct_min,
                            d,
                            slot,
                            data,
                            now,
                        );
                        let z = self.zrx.as_mut().unwrap();
                        z.stats.copied += used as u64;
                        z.book.release(used);
                        if used == len as usize {
                            z.give(off, len);
                        } else {
                            let c = self.slots[slot as usize].as_mut().unwrap();
                            c.zpend.unpop(Held::Area {
                                off: off + used as u64,
                                len: len - used as u32,
                            });
                            break;
                        }
                    }
                    Held::Owned(v) => {
                        let used = deliver(
                            &mut self.slots,
                            &mut self.stats,
                            self.cfg.direct_min,
                            d,
                            slot,
                            &v,
                            now,
                        );
                        self.zrx.as_mut().unwrap().stats.copied += used as u64;
                        if used < v.len() {
                            let c = self.slots[slot as usize].as_mut().unwrap();
                            c.zpend.unpop(Held::Owned(v[used..].to_vec()));
                            break;
                        }
                    }
                }
            }
            let c = self.slots[slot as usize].as_mut().unwrap();
            if !c.zpend.is_empty() {
                keep.push(slot);
                continue;
            }
            let eof = matches!(c.rx, Rx::Eof);
            let id = c.id;
            if c.rx_paused {
                c.resume(&mut self.stats, now);
                if !c.zarmed && !eof {
                    self.zrx_arm(slot);
                }
            }
            if eof {
                d.on_eof(id, now);
            }
        }
        self.zpaused.extend(keep);
        work
    }
}

/// Hand `data` (a fragment of the core's area or held bytes) to the OSD under the copy path's rules; returns the bytes
/// taken (less when the input got throttled). Takes the fields it needs, so the area stays borrowed from the core.
fn deliver<D: Driver>(
    slots: &mut [Option<Conn>],
    stats: &mut KStats,
    direct_min: usize,
    d: &mut D,
    slot: u32,
    data: &[u8],
    now: Duration,
) -> usize {
    let mut at = 0;
    while at < data.len() {
        let Some(c) = slots[slot as usize].as_mut() else {
            break;
        };
        if c.dying || c.reported {
            at = data.len(); // nobody listens any more: consumed
            break;
        }
        let id = c.id;
        if let Rx::Direct(dx) = &mut c.rx {
            // a lent segment buffer never waits for the OSD
            let n = dx.remaining().min(data.len() - at);
            // SAFETY: the lent buffer has room for `remaining()` bytes at its receive pointer; `data` is the area.
            unsafe { std::ptr::copy_nonoverlapping(data[at..].as_ptr(), dx.receive_pointer(), n) };
            dx.commit(n);
            at += n;
            stats.direct_bytes += n as u64;
            if dx.remaining() > 0 {
                d.on_rx_progress(id, now);
                continue;
            }
            let Rx::Direct(dx) = std::mem::replace(&mut c.rx, Rx::Multi) else {
                unreachable!()
            };
            dx.put(d, id, now);
            continue;
        }
        if !(d.input_ready(id) || d.rx_parked(id)) {
            break;
        }
        if direct_min > 0
            && let Some(dx) = DirectRx::take(d, id, direct_min)
        {
            stats.direct_starts += 1;
            slots[slot as usize].as_mut().unwrap().rx = Rx::Direct(dx);
            continue;
        }
        d.on_bytes(id, &data[at..], now);
        at = data.len();
    }
    at
}
