// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! io_uring zero-copy receive for knet (adr 0464, doc/spec/knet-zcrx.md).
//!
//! Detection is by capability only (R1): a ring with the zcrx flags, the `RECV_ZC` opcode, the NIC's header/data split,
//! the host's steering of the public port to queues of their own, and finally the real registration of each core's
//! ifq. Every missing piece leaves the copy receive (adr 0053) unchanged and names itself once with its fix
//! ([`Reason`]); a core that registered keeps `RECV_ZC` for the connections that arrive on its queue.
//!
//! Each zcrx core owns a second ring (`SINGLE_ISSUER | DEFER_TASKRUN | TASKRUN_FLAG | CQE32`, the flags the kernel
//! requires for an ifq) next to its knet ring, whose setup stays exactly as without zcrx: the copy path is untouched.
//! The second ring signals an eventfd that the knet ring reads, so an idle core wakes for zcrx data like for any
//! other completion.
//!
//! Receive: one multishot `RECV_ZC` per accepted connection on the core's queue. A completion is a fragment of the
//! byte stream inside the area; knet copies it out (small frames into the decoder, data segments into the lent
//! segment buffer with their crc while cache hot) and returns the chunk in the same loop iteration. The kernel copy
//! (`recvmsg`, hardened usercopy) and the per-piece receive requests disappear; the payload copy into the segment
//! buffer remains until the segment chain type of spec section 3 (open point O4) lets the store read the area
//! directly. Throttled input keeps fragments as leases within the lease budget ([`book`]), beyond it copies them out.
//!
//! Runtime faults never cost a connection: the kernel copies data that did not land in the area (queue restarted, ifq
//! unbound) into area chunks itself, `ENOMEM` (no free chunk) and `ENOSPC` (completion queue full) re-arm the receive
//! after the next refill. A multishot receive that runs out of chunks or completion space AFTER taking part of the
//! socket's data posts no error: the kernel waits for the next socket wakeup, which never comes once the peer has sent
//! everything. The completion queue therefore holds two completions per area chunk (it cannot fill before the area
//! does), and a reap that leaves the kernel without free chunks restarts every armed receive (cancel, re-arm) after the
//! refill: a fresh receive reads the socket's queue at once. Only a fragment of another ifq (`EFAULT`: wrong host steering, which the plan rules out)
//! cannot be read by anyone and ends the connection, as any socket error does.
pub mod book;
pub mod nic;
pub mod steer;
mod sys;

use book::{Book, Refill, Sizing};
use io_uring::{IoUring, Probe, cqueue, opcode, squeue, types::Fd};
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// Why a core (or the whole OSD) receives by copy. The strings are fixed (startup line, `hwcheck zcrx`, spec section 5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reason {
    /// `--knet-zcrx off`.
    Disabled,
    /// No `--knet-zcrx`: off until a bare-metal A/B validates the path (adr 0464); `--knet-zcrx auto` opts in.
    DefaultOff,
    /// No ring with `SINGLE_ISSUER | DEFER_TASKRUN | CQE32`.
    NoRingFlags,
    /// The kernel lacks `IORING_OP_RECV_ZC`.
    NoOp,
    /// The public address is on no local interface with a device behind it (bond, VLAN, bridge, veth, tun).
    VirtualNetdev,
    /// Header/data split is off or has a threshold above 0.
    NoHds,
    /// The driver has no queue management API for memory providers (VFs, virtio, older drivers).
    NoQueueApi,
    /// The queue already has a memory provider (another process).
    QueueBusy,
    /// No flow rule sends the public port to queues outside the default RSS table.
    NoSteering,
    /// The queues of the public port also receive other traffic (RSS or another rule).
    SharedQueue,
    /// More zcrx cores than reserved queues.
    NoQueueLeft,
    /// Registration refused for lack of `CAP_NET_ADMIN`.
    NoCap,
    /// Pinned memory refused (`RLIMIT_MEMLOCK`, `ENOMEM` at registration).
    Memlock,
    /// The area could not be mapped.
    AreaAlloc,
    /// A NIC query failed (ethtool/netdev netlink, ethtool ioctl).
    NicQuery,
    /// Registration refused for another reason (errno).
    Refused(i32),
}

impl Reason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Reason::Disabled => "disabled",
            Reason::DefaultOff => "default-off",
            Reason::NoRingFlags => "no-ring-flags",
            Reason::NoOp => "no-op",
            Reason::VirtualNetdev => "virtual-netdev",
            Reason::NoHds => "no-hds",
            Reason::NoQueueApi => "no-queue-api",
            Reason::QueueBusy => "queue-busy",
            Reason::NoSteering => "no-steering",
            Reason::SharedQueue => "shared-queue",
            Reason::NoQueueLeft => "no-queue-left",
            Reason::NoCap => "no-cap",
            Reason::Memlock => "memlock",
            Reason::AreaAlloc => "area-alloc",
            Reason::NicQuery => "nic-query",
            Reason::Refused(_) => "refused",
        }
    }

    /// The exact fix (`iface`/`port` of the plan; `<if>`/`<port>` when unknown).
    pub fn fix(&self, iface: &str, port: u16) -> String {
        match self {
            Reason::Disabled => "none (operator choice: --knet-zcrx off)".into(),
            Reason::DefaultOff => {
                "disabled by default until validated (adr 0464); opt in with --knet-zcrx auto".into()
            }
            Reason::NoRingFlags | Reason::NoOp => {
                "run a kernel with io_uring zero-copy receive (IORING_OP_RECV_ZC, ifq registration); the copy receive is used meanwhile".into()
            }
            Reason::VirtualNetdev => format!(
                "{iface} has no NIC queue of its own (bond/VLAN/bridge/virtio/veth): zcrx needs the public address on a physical port; copy receive stays"
            ),
            Reason::NoHds => format!("ethtool -G {iface} tcp-data-split on hds-thresh 0"),
            Reason::NoQueueApi => format!(
                "driver of {iface} offers no queue memory providers (SR-IOV VF, virtio, driver without queue API): use a PF with a zcrx capable driver"
            ),
            Reason::QueueBusy => format!(
                "another process holds a provider on the queue (`ynl --family netdev --dump queue-get` on {iface}); give this OSD its own queues"
            ),
            Reason::NoSteering | Reason::SharedQueue => format!(
                "croit-flashstore-tool host-tune --iface {iface} --zcrx-queues <cores> --host-queues <host queues> --osd-port {port} --apply (dedicated queues for this OSD's public port only)"
            ),
            Reason::NoQueueLeft => format!(
                "reserve one queue per OSD core: croit-flashstore-tool host-tune --iface {iface} --zcrx-queues <cores> ... --osd-port {port}"
            ),
            Reason::NoCap => "run the OSD with CAP_NET_ADMIN (zcrx registers a NIC queue)".into(),
            Reason::Memlock => "raise RLIMIT_MEMLOCK of the OSD (LimitMEMLOCK=infinity) or lower its memory target".into(),
            Reason::AreaAlloc => "free memory for the receive area (see the memory envelope, adr 0175)".into(),
            Reason::NicQuery => format!("check `ethtool -g {iface}` / `ethtool -x {iface}` / netdev netlink access"),
            Reason::Refused(e) => format!(
                "registration refused: {} (see dmesg; tcp-data-split, rx ring and channel settings of {iface})",
                io::Error::from_raw_os_error(*e)
            ),
        }
    }

    fn of_register(e: &io::Error) -> Reason {
        match e.raw_os_error() {
            Some(libc::EPERM) => Reason::NoCap,
            Some(libc::EOPNOTSUPP) => Reason::NoQueueApi,
            Some(libc::EBUSY) => Reason::QueueBusy,
            Some(libc::ENOMEM) => Reason::Memlock,
            Some(n) => Reason::Refused(n),
            None => Reason::Refused(0),
        }
    }
}

type ZRing = IoUring<squeue::Entry, cqueue::Entry32>;

/// Largest completion queue the kernel accepts (`IORING_MAX_CQ_ENTRIES`).
const CQ_MAX: u32 = 65536;

fn zring(entries: u32, cq: u32) -> io::Result<ZRing> {
    IoUring::<squeue::Entry, cqueue::Entry32>::builder()
        .setup_single_issuer()
        .setup_defer_taskrun()
        .setup_taskrun_flag()
        .setup_cqsize(cq)
        .build(entries)
}

/// Kernel half of the probe: the ring flags and the opcode (no NIC touched).
pub fn probe_kernel() -> Result<(), Reason> {
    let ring = zring(8, 32).map_err(|_| Reason::NoRingFlags)?;
    let mut p = Probe::new();
    ring.submitter()
        .register_probe(&mut p)
        .map_err(|_| Reason::NoOp)?;
    if !p.is_supported(opcode::RecvZc::CODE) {
        return Err(Reason::NoOp);
    }
    Ok(())
}

/// Receive queue ceiling of a socket (`net.ipv4.tcp_rmem` max): the kernel-side share of an area.
pub fn rmem_max() -> io::Result<usize> {
    super::tcp_rmem_max()
}

/// The OSD's zcrx plan (computed once at start, before the cores).
#[derive(Clone, Debug)]
pub struct Plan {
    pub iface: String,
    pub ifindex: u32,
    pub port: u16,
    /// Reserved queues `(queue, napi id)`, ascending; core `i` takes entry `i`.
    pub queues: Vec<(u32, u32)>,
    /// Per queue.
    pub sizing: Sizing,
    /// Refill ring entries (every area chunk fits).
    pub entries: u32,
    /// Area chunks the NIC's page pool keeps out of the kernel's free list (its receive ring; 0 without a NIC).
    pub pool_chunks: u32,
    /// The whole OSD receives by copy.
    pub off: Option<Reason>,
    /// Detail of `off` (the probe's own words).
    pub detail: String,
    /// Device-less test mode (`--knet-zcrx nodev`): every core registers an ifq without a NIC queue and receives every
    /// accepted connection through `RECV_ZC`; the kernel copies all data into the area. Exercises the whole zcrx path
    /// (arming, leases, refill, pause, teardown) on any zcrx kernel; slower than the copy receive, never a production mode.
    pub nodev: bool,
}

const PAGE: usize = 4096;
/// Largest refill ring the kernel accepts (larger requests are refused without `IORING_SETUP_CLAMP`).
const REFILL_MAX: u32 = 32768;

impl Plan {
    fn refused(iface: &str, port: u16, r: Reason, detail: String) -> Plan {
        Plan {
            iface: iface.into(),
            ifindex: 0,
            port,
            queues: Vec::new(),
            sizing: Sizing { area: 0, budget: 0 },
            entries: 0,
            pool_chunks: 0,
            off: Some(r),
            detail,
            nodev: false,
        }
    }

    /// The plan without `--knet-zcrx`: copy receive, nothing probed ([`Reason::DefaultOff`]).
    pub fn default_off(port: u16) -> Plan {
        Plan::refused("<if>", port, Reason::DefaultOff, String::new())
    }

    /// The device-less test plan (see [`Plan::nodev`]); `rmem`: receive queue ceiling ([`rmem_max`] in production).
    pub fn nodev(port: u16, rmem: usize) -> Plan {
        if let Err(r) = probe_kernel() {
            return Plan::refused("-", port, r, String::new());
        }
        let sizing = book::sizing(0, rmem, PAGE, REFILL_MAX as usize);
        Plan {
            iface: "-".into(),
            ifindex: 0,
            port,
            queues: Vec::new(),
            entries: (sizing.area / PAGE) as u32,
            pool_chunks: 0,
            sizing,
            off: None,
            detail: "nodev (test mode: kernel copies into the area)".into(),
            nodev: true,
        }
    }

    /// Probe kernel and NIC for the public address `ip:port`. Never fails: a refusal is a plan with `off`.
    pub fn probe(ip: Ipv4Addr, port: u16, enabled: bool) -> Plan {
        if !enabled {
            return Plan::refused("<if>", port, Reason::Disabled, String::new());
        }
        if let Err(r) = probe_kernel() {
            return Plan::refused("<if>", port, r, String::new());
        }
        let Some(iface) = nic::iface_of(ip) else {
            return Plan::refused(
                "<if>",
                port,
                Reason::VirtualNetdev,
                format!("{ip} is on no local interface"),
            );
        };
        let Some(drv) = nic::driver(&iface) else {
            return Plan::refused(&iface, port, Reason::VirtualNetdev, String::new());
        };
        // a VF is named (it usually lacks the queue API), but only the registration decides
        let drv = if nic::is_vf(&iface) {
            format!("{drv} (SR-IOV VF)")
        } else {
            drv
        };
        let ifindex = nic::ifindex(&iface).unwrap_or(0);
        let rings = match nic::rings(ifindex) {
            Ok(r) => r,
            Err(e) => return Plan::refused(&iface, port, Reason::NicQuery, format!("rings: {e}")),
        };
        if rings.hds != Some(true) || rings.hds_thresh.is_some_and(|t| t > 0) {
            return Plan::refused(
                &iface,
                port,
                Reason::NoHds,
                format!(
                    "driver {drv}: tcp-data-split {:?} hds-thresh {:?}",
                    rings.hds, rings.hds_thresh
                ),
            );
        }
        let st = match nic::steering(&iface) {
            Ok(s) => s,
            Err(e) => {
                return Plan::refused(&iface, port, Reason::NicQuery, format!("steering: {e}"));
            }
        };
        let qs = match steer::queues(&st, port) {
            Ok(q) => q,
            Err(steer::Refused::NoSteering) => {
                return Plan::refused(&iface, port, Reason::NoSteering, format!("driver {drv}"));
            }
            Err(e) => {
                return Plan::refused(
                    &iface,
                    port,
                    Reason::SharedQueue,
                    format!("driver {drv}: {e:?}"),
                );
            }
        };
        let mut queues = Vec::with_capacity(qs.len());
        for q in qs {
            match nic::rx_queue(ifindex, q) {
                Ok(i) if i.zcrx_bound => {
                    return Plan::refused(
                        &iface,
                        port,
                        Reason::QueueBusy,
                        format!("driver {drv}: queue {q}"),
                    );
                }
                Ok(i) => queues.push((q, i.napi)),
                Err(e) => {
                    return Plan::refused(
                        &iface,
                        port,
                        Reason::NicQuery,
                        format!("queue {q}: {e}"),
                    );
                }
            }
        }
        let rmem = match rmem_max() {
            Ok(r) => r,
            Err(e) => {
                return Plan::refused(&iface, port, Reason::NicQuery, format!("tcp_rmem: {e}"));
            }
        };
        let sizing = book::sizing(rings.rx as usize * PAGE, rmem, PAGE, REFILL_MAX as usize);
        Plan {
            iface,
            ifindex,
            port,
            queues,
            entries: (sizing.area / PAGE) as u32,
            pool_chunks: rings.rx,
            sizing,
            off: None,
            detail: format!("driver {drv}"),
            nodev: false,
        }
    }

    /// Core of the queue whose NAPI instance is `napi` (accept-time placement).
    pub fn core_of_napi(&self, napi: u32) -> Option<usize> {
        if napi == 0 {
            return None;
        }
        self.queues.iter().position(|&(_, n)| n == napi)
    }

    /// Startup summary (one line; per-core registration failures are reported by the cores).
    pub fn line(&self) -> String {
        match &self.off {
            Some(r) => format!(
                "zcrx=off reason={}{}{} fix: {}",
                r.as_str(),
                if self.detail.is_empty() { "" } else { " " },
                self.detail,
                r.fix(&self.iface, self.port)
            ),
            None => format!(
                "zcrx=on iface={} queues={:?} area={}MiB/q lease_budget={}MiB/q {}",
                self.iface,
                self.queues.iter().map(|q| q.0).collect::<Vec<_>>(),
                self.sizing.area >> 20,
                self.sizing.budget >> 20,
                self.detail
            ),
        }
    }
}

/// zcrx counters of one core (perf dump / core exit line).
#[derive(Clone, Copy, Debug, Default)]
pub struct ZStats {
    pub cqes: u64,
    pub bytes: u64,
    /// Bytes copied into the decoder or a segment buffer straight from the area.
    pub copied: u64,
    /// Fragments held as leases (throttled input).
    pub leased: u64,
    pub conns: u64,
    /// Receives re-armed after `ENOMEM`/`ENOSPC` (no chunk free / completion queue full).
    pub rearm_short: u64,
    /// Fragments the kernel copied into the area itself (not area memory: queue restarted, ifq unbound, nodev).
    pub kernel_copy_frags: u64,
    /// Highest leased bytes / bytes copied out because the lease budget was used up.
    pub held_max: u64,
    pub converted: u64,
    /// Refill entries written and tail publishes.
    pub refill_entries: u64,
    pub refill_batches: u64,
    /// Reaps that left the kernel without free chunks or completion space (every armed receive restarted).
    pub starved: u64,
    /// Kernel enters of this core's ring to make room in a full submission queue.
    pub sq_enters: u64,
}

impl ZStats {
    /// `key=value` counters (core exit line).
    pub fn line(&self) -> String {
        format!(
            "zcrx_cqes={} zcrx_bytes={} zcrx_copied={} zcrx_leased={} zcrx_converted={} zcrx_held_max={} zcrx_conns={} zcrx_rearm_short={} zcrx_kernel_copy_frags={} zcrx_refill={}/{} zcrx_starved={} zcrx_sq_enters={}",
            self.cqes,
            self.bytes,
            self.copied,
            self.leased,
            self.converted,
            self.held_max,
            self.conns,
            self.rearm_short,
            self.kernel_copy_frags,
            self.refill_entries,
            self.refill_batches,
            self.starved,
            self.sq_enters
        )
    }
}

/// One zcrx completion: connection slot, result, more to come, area offset.
#[derive(Clone, Copy, Debug)]
pub(super) struct ZCqe {
    pub slot: u32,
    pub res: i32,
    pub more: bool,
    pub off: u64,
}

const Z_IGN: u64 = 0;

/// The zcrx state of one core: its second ring, ifq, accounting.
pub struct ZCore {
    ring: ZRing,
    ifq: sys::Ifq,
    efd: OwnedFd,
    nodev: bool,
    pub(super) book: Book,
    refill: Refill,
    /// Returned fragments waiting for room in the refill ring.
    backlog: Vec<(u64, u32)>,
    /// Fragments completed to this core and not yet back in the refill ring.
    out: u32,
    /// `out` at which the kernel's free list may be empty (area chunks less the page pool's share).
    starve_at: u32,
    cq_entries: u32,
    /// The last reap left the kernel without free chunks or completion space: restart the armed receives.
    starved: bool,
    pub(super) stats: ZStats,
    pub(super) batch: Vec<ZCqe>,
}

impl std::fmt::Debug for ZCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.describe())
    }
}

impl ZCore {
    /// Register the core's queue `rxq` of `plan` (or a device-less instance for tests).
    pub fn new(plan: &Plan, rxq: Option<u32>) -> Result<ZCore, Reason> {
        // two completions per chunk: the completion queue never fills before the area does (see the module docs)
        let cq_entries = (2 * plan.entries).next_power_of_two().min(CQ_MAX);
        let ring = zring(256, cq_entries).map_err(|_| Reason::NoRingFlags)?;
        let (target, area, entries) = match rxq {
            Some(q) => (
                sys::Target::Queue {
                    ifindex: plan.ifindex,
                    rxq: q,
                },
                plan.sizing.area,
                plan.entries,
            ),
            None => (sys::Target::NoDev, plan.sizing.area, plan.entries),
        };
        let ifq = sys::Ifq::register(ring.as_raw_fd(), target, area, entries).map_err(|e| {
            if e.kind() == io::ErrorKind::OutOfMemory {
                Reason::AreaAlloc
            } else {
                Reason::of_register(&e)
            }
        })?;
        // SAFETY: plain eventfd.
        let efd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if efd < 0 {
            return Err(Reason::Refused(
                io::Error::last_os_error().raw_os_error().unwrap_or(0),
            ));
        }
        // SAFETY: fresh fd we own.
        let efd = unsafe { OwnedFd::from_raw_fd(efd) };
        ring.submitter()
            .register_eventfd(efd.as_raw_fd())
            .map_err(|e| Reason::Refused(e.raw_os_error().unwrap_or(0)))?;
        Ok(ZCore {
            ring,
            ifq,
            efd,
            nodev: rxq.is_none(),
            book: Book::new(plan.sizing.budget),
            refill: Refill::default(),
            backlog: Vec::new(),
            out: 0,
            starve_at: plan.entries.saturating_sub(plan.pool_chunks),
            cq_entries,
            starved: false,
            stats: ZStats::default(),
            batch: Vec::with_capacity(256),
        })
    }

    /// Eventfd the knet ring reads to wake for zcrx completions.
    pub(super) fn wake_fd(&self) -> RawFd {
        self.efd.as_raw_fd()
    }

    fn push(&mut self, e: squeue::Entry) {
        // one bounded path with the knet ring (`WARNING TIMEOUT` + panic): a ring that refuses entries must never
        // spin a core silently
        super::push_sqe_bounded(
            &mut self.ring,
            &mut self.stats.sq_enters,
            e,
            super::SQ_STALL,
        );
    }

    /// Multishot zero-copy receive on the socket of `slot`.
    pub(super) fn arm(&mut self, fd: RawFd, slot: u32) {
        let e = opcode::RecvZc::new(Fd(fd), 0)
            .ifq(self.ifq.id)
            .build()
            .user_data(u64::from(slot) + 1);
        self.push(e);
    }

    /// Stop the receive of `slot` (its final completion follows with `ECANCELED`).
    pub(super) fn cancel(&mut self, slot: u32) {
        let e = opcode::AsyncCancel::new(u64::from(slot) + 1)
            .build()
            .user_data(Z_IGN);
        self.push(e);
    }

    /// Hand queued requests to the kernel (before an idle sleep: nothing else submits this ring then).
    pub(super) fn submit(&mut self) {
        if !self.ring.submission().is_empty() {
            let _ = self.ring.submit();
        }
    }

    /// Submit, run the deferred task work, collect completions into `batch`.
    pub(super) fn reap(&mut self) {
        self.batch.clear();
        let sq = self.ring.submission();
        let need = !sq.is_empty() || sq.taskrun() || sq.cq_overflow();
        drop(sq);
        if need {
            // DEFER_TASKRUN: task work (the receive itself) runs only inside an enter with GETEVENTS
            // SAFETY: plain enter without arguments.
            let n = self.ring.submission().len() as u32;
            let _ = unsafe {
                self.ring.submitter().enter::<libc::sigset_t>(
                    n, 0, 1, // IORING_ENTER_GETEVENTS
                    None,
                )
            };
            self.ring.submission().sync();
        }
        for c in self.ring.completion() {
            let ud = c.user_data();
            if ud == Z_IGN {
                continue;
            }
            self.out += u32::from(c.result() > 0);
            self.batch.push(ZCqe {
                slot: (ud - 1) as u32,
                res: c.result(),
                more: cqueue::more(c.flags()),
                off: c.big_cqe()[0],
            });
        }
        self.stats.cqes += self.batch.len() as u64;
        if self.out >= self.starve_at || self.batch.len() >= self.cq_entries as usize {
            self.starved = true;
            self.stats.starved += 1;
        }
    }

    /// Bytes of a delivered fragment.
    pub(super) fn frag(&self, off: u64, len: usize) -> &[u8] {
        // SAFETY: (off, len) came from a completion of this ifq and is not yet refilled (callers refill after use).
        unsafe { self.ifq.frag(off, len) }
    }

    /// Return a fragment (published at the next `publish`).
    pub(super) fn give(&mut self, off: u64, len: u32) {
        if !self.backlog.is_empty() || self.refill.room(self.ifq.head(), self.ifq.entries) == 0 {
            self.backlog.push((off, len));
            return;
        }
        let i = self.refill.take_slot();
        self.ifq.put_rqe(i, off, len);
        self.out -= 1;
    }

    /// Publish the refill entries of this iteration (one store).
    pub(super) fn publish(&mut self) {
        if !self.backlog.is_empty() {
            let room = self.refill.room(self.ifq.head(), self.ifq.entries) as usize;
            let n = room.min(self.backlog.len());
            for (off, len) in self.backlog.drain(..n) {
                let i = self.refill.take_slot();
                self.ifq.put_rqe(i, off, len);
            }
            self.out -= n as u32;
        }
        if let Some(t) = self.refill.publish() {
            self.ifq.publish_tail(t);
            if self.nodev {
                let _ = self.ifq.flush(self.ring.as_raw_fd());
            }
        }
        if let Some(s) = self.ifq.stats() {
            self.stats.kernel_copy_frags = s.copy_count;
        }
    }

    /// Whether the last reap starved the kernel (cleared): the caller restarts every armed receive after `publish`.
    pub(super) fn take_starved(&mut self) -> bool {
        std::mem::take(&mut self.starved)
    }

    /// Startup / describe text of this core.
    pub fn describe(&self) -> String {
        format!(
            "zcrx ifq={} chunk={}KiB area={}MiB refill={}{}",
            self.ifq.id,
            self.ifq.chunk >> 10,
            self.ifq.area.len() >> 20,
            self.ifq.entries,
            if self.nodev { " nodev" } else { "" }
        )
    }

    pub fn stats(&self) -> ZStats {
        ZStats {
            held_max: self.book.held_max as u64,
            converted: self.book.converted,
            refill_entries: self.refill.entries,
            refill_batches: self.refill.batches,
            ..self.stats
        }
    }
}
