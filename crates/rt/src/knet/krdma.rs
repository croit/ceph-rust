// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! RDMA data path of the kernel tier (0469-rdma-transport, msgr2 spec 18). A connection starts on TCP; the OSD's
//! `IoCmd::Rdma*` commands move it onto one RC queue pair of this core's verbs [`Core`]. The sans-IO rules (command
//! order, GID binding, switch point) are `rdma::upgrade`; this module does the I/O around them:
//! - per process: [`start`] opens the device of every local address, builds one verbs [`Core`] per core and device and runs
//!   the control thread (QP create/connect/destroy never run on a data-path core);
//! - per core: a CQ phase in `KNet::poll` (`Data` -> `Driver::on_bytes`, `Writable` -> resume output, `Fault` -> the
//!   connection's dead path), upgraded connections send through `Core::send`, the idle sleep waits on the CQ channel fd
//!   and on the core's own control wake (an eventfd the control thread pokes for every reply, independent of the mesh wake
//!   `--knet-wake`);
//! - a graceful close of an upgraded connection fences its posted output before the QP is destroyed (`rdma::fence`);
//! - the TCP socket of an upgraded connection stays open without data for the connection's life (liveness channel, spec
//!   18): an RC QP tells the passive side nothing when the peer closes, destroys its QP or dies. Its end (EOF / reset) =
//!   the peer closed or died: the CQ is drained first (what arrived is delivered), then the connection is dead. Every
//!   close of ours (fence done, fault, abort) shuts the socket down at once, so the peer learns it the same way.
use super::kpull::{Pull, PullArena};
use super::{Driver, K_RDMA, KNet, local_v4, peer_addr, ud};
use crate::FxMap;
use crate::wake::Wake;
use ::rdma::budget;
use ::rdma::control::{Control, ControlCfg, CoreLink, start_verbs};
use ::rdma::fence::Step;
use ::rdma::grant::SessionCap;
use ::rdma::hold::Flow;
use ::rdma::status::{Counters, DeviceStatus, Process, Setup, Unusable};
use ::rdma::upgrade::{Carrier, Done, Refused, SockRead, TcpRx, Upgrader};
use ::rdma::verbs::{
    Core, CoreCfg, Device, Event, PlacedReadWrite, Qp, ReadPostError, ReadState, ReadTarget,
    RemoteReadSource, WriteState, ZcMem,
};
use ::rdma::{Release, gid_of};
use io_uring::opcode;
use io_uring::types::Fd;
use osd::IoCmd;
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

/// Hand one received slot of connection `id` to the OSD, under the same input rule as a TCP chunk (memory envelope,
/// adr 0175 am. 1): input the OSD may not take (`Driver::input_ready` false, also a link parked at a message header for
/// ingress pool space) stays in its receive slot, held by the core with no credit returned, so the peer blocks; nothing
/// is copied aside. A slot the OSD took that filled it holds the slots after it. Message frames reserve their length at
/// the msgr2 frame header inside `on_bytes`, exactly as over TCP.
fn deliver<D: Driver>(d: &mut D, id: u64, b: &[u8], now: Duration) -> Flow {
    if !d.input_ready(id) {
        return Flow::Keep;
    }
    d.on_bytes(id, b, now);
    if d.input_ready(id) {
        Flow::Go
    } else {
        Flow::Pause
    }
}

/// Drive the in-flight placement WRITE-to-reply owners of a connection (spec
/// rdma-placement-runtime.md): post pending pieces on SQ progress and report the
/// terminal outcome of every owner whose accepted WRITEs are all retired. Terminal
/// owners are removed from the connection's placement list; the link's attempt owner
/// encodes and sends the reply. Called on SQ progress (`rdma_flush`) and in the CQ
/// phase (`rdma_poll`), so an idle connection's completed WRITEs still report.
/// Returns the older SEND-prefix bytes posted this pass for transport accounting.
#[cfg(feature = "rdma")]
fn drive_placement<D: Driver>(p: &mut Plane, d: &mut D, c: &mut super::Conn) -> usize {
    let conn = c.id;
    let mut sent = 0;
    let mut i = 0;
    while i < c.rdma.placement.len() {
        // Borrow pending attempts in place: remove/insert on every CQ pass
        // shifts the entire suffix twice for each still-pending owner.
        let inflight = &mut c.rdma.placement[i];
        let (tid, retry) = (inflight.tid, inflight.retry);
        // This frozen prefix predates the placement command. Keep it separate
        // from later output and resume it on the same CQ/credit progress as SEND.
        // No WRITE (including a later owner's) may overtake a blocked prefix.
        if !inflight.prefix.is_empty() {
            sent += p.core.send_chunks(inflight.qpn, &mut inflight.prefix);
            if !inflight.prefix.is_empty() {
                break;
            }
        }
        if !inflight.cancelled {
            while inflight.owner.has_pending() {
                // SAFETY: admission authenticated this grant on the live same-QP session.
                match unsafe { inflight.owner.post_next(&mut p.core) } {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => {
                        p.ctr.faulted += 1;
                        eprintln!(
                            "knet: rdma: conn {conn:#x}: placement WRITE post failed: {error}"
                        );
                        c.rdma.placement.remove(i);
                        d.placement_fault(conn, tid, retry);
                        return sent;
                    }
                }
            }
        }
        let state = inflight.owner.state();
        let ready = matches!(state, None | Some(WriteState::Complete));
        if state == Some(WriteState::Failed) {
            c.rdma.placement.remove(i);
            d.placement_fault(conn, tid, retry);
            return sent;
        }
        if !ready || (!inflight.cancelled && inflight.owner.has_pending()) {
            i += 1;
            continue;
        }
        // Only terminal owners leave the vector. Admission order is retained
        // for the remaining owners; no pending attempt or source is recopied.
        let mut inflight = c.rdma.placement.remove(i);
        let receipt = if inflight.cancelled {
            None
        } else {
            match inflight.owner.receipt_verified(&inflight.block_crcs) {
                Ok(receipt) => Some(receipt),
                Err(_) => {
                    // Immutable malformed metadata cannot become valid on another poll.
                    d.placement_fault(conn, tid, retry);
                    return sent;
                }
            }
        };
        if inflight.owner.recycle().is_err() {
            d.placement_fault(conn, tid, retry);
            return sent;
        }
        c.rdma
            .spare_placement
            .push((inflight.owner, inflight.prefix));
        if let Some(receipt) = receipt {
            d.placement_success(conn, tid, retry, receipt);
        } else {
            d.placement_cancelled(conn, tid, retry);
        }
    }
    sent
}

/// `ud` slot value of the control wake read (plane indices are small).
const CTL_WAKE: u32 = 0x0fff_ffff;

/// Longest wait for the control thread to drop a core's pooled QPs at shutdown.
const RETIRE_LIMIT: Duration = Duration::from_secs(10);

/// The in-flight placement WRITE-to-reply owners of one connection (spec
/// rdma-placement-runtime.md). Each entry holds the checked grant, the ordered
/// WRITEs and the prefetched pieces not yet posted (a queue-full admission
/// pauses there). Driven by [`KRdma`] on SQ progress and in the CQ phase; the
/// terminal outcome is reported to the link's attempt owner, which encodes and
/// sends the reply. Parallel attempts are kept in admission order.
#[derive(Debug)]
pub(super) struct PlacementInFlight {
    tid: u64,
    retry: u32,
    owner: PlacedReadWrite,
    /// Exact QP and frozen older SEND prefix; empty capacity is reused after retirement.
    qpn: u32,
    prefix: VecDeque<bytes::Bytes>,
    /// The store-verified seed-0 block CRCs (4096-byte grid).
    block_crcs: Vec<u32>,
    /// A matching CANCEL was accepted: no further WRITE may be posted.
    cancelled: bool,
}

impl PlacementInFlight {
    /// The attempt's identity (for the terminal-outcome report to the link).
    pub(super) fn identity(&self) -> (u64, u32) {
        (self.tid, self.retry)
    }
}

/// RDMA state of a connection.
#[derive(Debug)]
pub(super) struct ConnRdma {
    /// The plane (device) whose upgrade job or QP the connection holds.
    pub plane: Option<usize>,
    pub carrier: Carrier,
    /// Graceful close: the fence is posted behind the last output, no more output is taken.
    pub fencing: bool,
    /// The in-flight placement WRITE-to-reply owners (if any), in admission order.
    pub placement: Vec<PlacementInFlight>,
    /// Retired owners retain source-slot capacity/markers for the next READ.
    spare_placement: Vec<(PlacedReadWrite, VecDeque<bytes::Bytes>)>,
    /// In-flight source-pull READs of this connection (adr 0665), drained in the CQ phase.
    pub pulls: Vec<PullInFlight>,
}

/// One posted source-pull READ: the held op's tid and its completion handle.
pub(super) struct PullInFlight {
    pub tid: u64,
    pub handle: ::rdma::verbs::ReadHandle,
}

impl std::fmt::Debug for PullInFlight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PullInFlight")
            .field("tid", &self.tid)
            .finish_non_exhaustive()
    }
}

impl Default for ConnRdma {
    fn default() -> Self {
        ConnRdma {
            plane: None,
            carrier: Carrier::Tcp,
            fencing: false,
            placement: Vec::new(),
            spare_placement: Vec::new(),
            pulls: Vec::new(),
        }
    }
}

/// One core's resources on one RDMA device (one device per local address).
#[derive(Debug)]
pub struct Plane {
    ip: Ipv4Addr,
    /// Device name (`rdma status`).
    name: String,
    /// Outcomes of upgrades and faults of this core on this device (the core's own stalls are `Core::stats`).
    ctr: Counters,
    /// Dropped in `Plane::drop` only after the control thread confirmed the retire of this core (else leaked).
    core: std::mem::ManuallyDrop<Core>,
    up: Upgrader<Qp, CoreLink<Qp>>,
    /// QPN -> (connection slot, connection id) of the attached connections.
    by_qpn: FxMap<u32, (u32, u64)>,
    /// The one-shot poll of the CQ channel is in the ring.
    armed: bool,
    /// `Core::arm` failed (reported once): the sleep is bounded by its cap only.
    arm_failed: bool,
    /// Connections whose input the OSD does not take (`Driver::input_ready`): the core holds their receive slots, no credit
    /// goes back, the peer blocks (`Core::pause`). Resumed in a later phase once the OSD takes input again.
    paused: Vec<u32>,
    /// Connections the core paused during the current poll (`Flow`), added to `paused` after it.
    to_pause: Vec<u32>,
    /// Registered READ destinations for source-pull PUTs (adr 0665), registered once;
    /// `None` = no READ capability or the registration failed (pulls are declined).
    pulls: Option<PullArena>,
}

impl Plane {
    /// Count why an upgrade did not start: a full session limit / receive pool is `sessions_capped`, any other refusal is a
    /// decline (the connection stays TCP either way).
    fn count_refused(&mut self, e: Option<Refused>) {
        match e {
            Some(Refused::Capped) => self.ctr.sessions_capped += 1,
            Some(Refused::State) | None => {}
            Some(_) => self.ctr.declined += 1,
        }
    }
}

impl Drop for Plane {
    /// The control thread drops this core's pooled QPs first; only then may the CQ/SRQ go. Without its confirmation
    /// (hung > [`RETIRE_LIMIT`], loud) the thread may still use them: the core is leaked (counted), never destroyed under
    /// a QP.
    fn drop(&mut self) {
        let confirmed = self.up.retire(RETIRE_LIMIT, &self.ip.to_string());
        // SAFETY: the core is taken once, here, and never used afterwards (the plane is being dropped).
        let core = unsafe { std::mem::ManuallyDrop::take(&mut self.core) };
        if confirmed {
            drop(core);
        } else {
            core.leak(&format!(
                "plane {}: the control thread did not confirm the retire",
                self.ip
            ));
        }
    }
}

/// Work that needs the whole [`KNet`] again (the plane state is borrowed while it is found).
#[derive(Debug)]
enum Follow {
    /// Resume the output of a connection.
    Flush(u64),
    /// Continue the close of a connection the OSD closed (it is no longer found by id): drain, fence, destroy.
    Drain(u32),
    /// The connection is dead.
    Dead(u32),
}

/// The RDMA planes of one core.
#[derive(Debug)]
pub struct KRdma {
    planes: Vec<Plane>,
    follow: VecDeque<Follow>,
    /// (slot, connection id) of upgraded connections whose socket ended (the peer closed or died): dead once the CQ phase
    /// delivered what arrived before.
    ended: Vec<(u32, u64)>,
    /// The control threads poke this when they answered a request of this core (always present: the answer must end the
    /// idle sleep whether or not the mesh has wake handles).
    wake: Arc<Wake>,
    /// Landing place of the kernel's read of the wake eventfd (leaked: the kernel may write it until the ring is gone).
    wake_buf: &'static mut u64,
    /// `wake` announces a sleeping core.
    wake_sleeping: bool,
    /// Time of the last status report to the OSD.
    reported: Option<Duration>,
    /// Source-pull READs in flight on this core (upper bound: a connection that closed with a pull open leaves it high
    /// until the next walk recounts). Zero = the CQ phase skips the walk over all slots.
    pulls_open: usize,
}

/// The OSD gets the status of the planes once per this interval (`rdma status`, perf counters).
const REPORT_EVERY: Duration = Duration::from_secs(1);

impl KRdma {
    fn new(planes: Vec<Plane>, wake: Arc<Wake>) -> KRdma {
        KRdma {
            planes,
            follow: VecDeque::new(),
            ended: Vec::new(),
            wake,
            wake_buf: Box::leak(Box::new(0)),
            wake_sleeping: false,
            pulls_open: 0,
            reported: None,
        }
    }

    /// Status of every plane of this core, at most once per [`REPORT_EVERY`].
    fn report(&mut self, now: Duration) -> Option<Vec<DeviceStatus>> {
        if self
            .reported
            .is_some_and(|t| now.saturating_sub(t) < REPORT_EVERY)
        {
            return None;
        }
        self.reported = Some(now);
        Some(
            self.planes
                .iter()
                .map(|p| {
                    let s = p.core.snapshot();
                    let mut counters = p.ctr;
                    let t = p.core.transport();
                    counters.credit_stalls = t.stats.credit_stalls;
                    counters.queue_stalls = t.stats.queue_stalls;
                    counters.credit_stall_ns = t.stats.credit_stall_ns;
                    counters.slot_wakeups = t.stats.slot_wakeups;
                    counters.zc_bytes = t.stats.zc_bytes;
                    counters.zc_misses = t.stats.zc_misses;
                    counters.tx_bytes = t.stats.tx_bytes;
                    counters.tx_sends = t.stats.tx_sends;
                    counters.tx_chunks = t.stats.tx_chunks;
                    counters.tx_doorbells = t.stats.tx_doorbells;
                    counters.tx_write_wrs = t.stats.tx_write_wrs;
                    counters.tx_write_bytes = t.stats.tx_write_bytes;
                    counters.tx_write_doorbells = t.stats.tx_write_doorbells;
                    counters.tx_write_sq_stalls = t.stats.tx_write_sq_stalls;
                    counters.rx_doorbells = t.stats.rx_doorbells;
                    counters.wakes = t.stats.wakes;
                    counters.rx_post_failures = t.stats.rx_post_failures;
                    counters.cq_errors = t.stats.cq_errors;
                    counters.rx_withheld = t.stats.rx_withheld;
                    counters.rx_held = t.stats.rx_held;
                    counters.grants_demand = t.grants.grants_demand;
                    counters.grants_admission = t.grants.grants_admission;
                    counters.idle_decays = t.grants.idle_decays;
                    DeviceStatus {
                        addr: p.ip.to_string(),
                        device: p.name.clone(),
                        sessions: s.sessions,
                        capacity: s.capacity,
                        slots: s.slots,
                        granted: s.granted,
                        session_credits: s.session_credits,
                        held: s.held,
                        counters,
                    }
                })
                .collect(),
        )
    }

    fn plane_of(&self, ip: Ipv4Addr) -> Option<usize> {
        self.planes.iter().position(|p| p.ip == ip)
    }

    /// Without planes: only the control wake (tests of the wake path need no device).
    #[cfg(test)]
    pub(super) fn wake_only(wake: Arc<Wake>) -> KRdma {
        KRdma::new(Vec::new(), wake)
    }
}

/// Teardown outcomes of the verbs cores of this process (`rdma status`, perf counters; the same on every core).
pub fn process() -> Process {
    Process {
        leaked_cores: ::rdma::verbs::leaked_cores(),
        teardown_failures: ::rdma::verbs::teardown_failures(),
        qp_drain_timeouts: ::rdma::control::qp_drain_timeouts(),
        quarantined_windows: ::rdma::verbs::quarantined_windows(),
        quarantined_write_sources: ::rdma::verbs::quarantined_write_sources(),
    }
}

/// The control threads of the process; keep it alive until every core is gone.
#[derive(Debug)]
pub struct Hub {
    _controls: Vec<Control>,
    setup: Setup,
}

impl Hub {
    /// The session limit and the devices that could not be used (for the OSD's cluster-log warnings and `rdma status`).
    pub fn setup(&self) -> &Setup {
        &self.setup
    }
}

/// Open the RDMA device of every address in `addrs` (the OSD's own addresses), build one verbs core per core and device
/// and start the control threads. A device that cannot be used (no RoCE port with that GID, MTU below 1024, no memory) is
/// reported once and its connections stay TCP. `budget` is `flashstore_rdma_memory` (registered memory of all cores and
/// devices, separate from `osd_memory_target`): every (core, device) gets an equal part and sizes its
/// receive/send slots from it ([`budget::size`]); a part below [`budget::min_bytes`] is an error (the caller refuses to
/// start). `max_sessions` is `flashstore_rdma_max_sessions` (0 = unlimited): upgraded sessions of the whole process; a connection
/// beyond it stays TCP. Every core gets its own wake object, poked by the control threads when they answered a request of
/// the core. `zero_copy`: `Some(ranges)` registers these ranges of the payload heap once per
/// device (`ZcMem`), and every core sends output chunks of at least one send slot that lie in them zero copy
/// (`Core::send_bytes`); a registration failure makes the device unusable like any other device error.
/// `source_pull` opts every QP into RDMA READ capability (spec rdma-read-offer.md), which the object
/// source-pull PUT needs (adr 0665); the hub then reports [`Setup::reads`]. A device that cannot
/// answer or post READs keeps its SEND/WRITE QPs and turns the extension off process-wide.
/// Returns the hub and the per-core planes (`None` = no usable device).
///
/// # Safety
/// When `zero_copy` is Some, its ranges must be initialized host allocations mapped until process exit, including
/// after refused deregistration. Each SEND source must remain immutable until retirement/QP destruction.
pub unsafe fn start(
    addrs: &[Ipv4Addr],
    cores: usize,
    budget: u64,
    max_sessions: u32,
    zero_copy: Option<&[(u64, u64)]>,
    source_pull: bool,
) -> Result<(Hub, Vec<Option<KRdma>>), String> {
    let mut seen: Vec<Ipv4Addr> = Vec::new();
    for &ip in addrs {
        if !seen.contains(&ip) {
            seen.push(ip);
        }
    }
    let part = budget::per_core(budget, cores, seen.len());
    let cfg = CoreCfg::for_budget(part).map_err(|e| {
        format!(
            "rdma memory budget of {} MiB over {cores} core(s) x {} device(s): {e} (raise flashstore_rdma_memory, use fewer cores, \
             or set flashstore_rdma=false)",
            budget >> 20,
            seen.len()
        )
    })?;
    let ctl: Arc<[Arc<Wake>]> = (0..cores)
        .map(|_| Wake::new())
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|e| format!("rdma control wake (eventfd): {e}"))?
        .into();
    let mut per_core: Vec<Vec<Plane>> = (0..cores).map(|_| Vec::new()).collect();
    let mut controls = Vec::new();
    let cap = SessionCap::new(max_sessions);
    let mut unusable = Vec::new();
    let mut reads = !seen.is_empty();
    for &ip in &seen {
        // SAFETY: start's caller guarantees permanent backing; no owner is fabricated from numeric addresses.
        match unsafe { start_device(ip, cores, ctl.clone(), cfg, &cap, zero_copy, source_pull) } {
            Ok((ctl, planes, device_reads)) => {
                controls.push(ctl);
                reads = reads && device_reads;
                for (c, p) in planes.into_iter().enumerate() {
                    per_core[c].push(p);
                }
            }
            Err(e) => {
                eprintln!(
                    "croit-flashstore-osd: rdma: {ip}: {e} (connections of this address stay TCP, no retry)"
                );
                // A device without READ capability leaves the whole OSD without
                // source-pull: the extension is advertised once, process-wide.
                reads = false;
                unusable.push(Unusable {
                    addr: ip.to_string(),
                    reason: e.to_string(),
                });
            }
        }
    }
    let krdma = per_core
        .into_iter()
        .zip(ctl.iter())
        .map(|(planes, w)| (!planes.is_empty()).then(|| KRdma::new(planes, w.clone())))
        .collect();
    Ok((
        Hub {
            _controls: controls,
            setup: Setup {
                max_sessions,
                unusable,
                reads,
            },
        },
        krdma,
    ))
}

unsafe fn start_device(
    ip: Ipv4Addr,
    cores: usize,
    wakes: Arc<[Arc<Wake>]>,
    cfg: CoreCfg,
    cap: &Arc<SessionCap>,
    zero_copy: Option<&[(u64, u64)]>,
    source_pull: bool,
) -> std::io::Result<(Control, Vec<Plane>, bool)> {
    let dev = Device::open(gid_of(IpAddr::V4(ip)))?;
    // SAFETY: permanent mapped backing and SEND immutability are required by start's caller.
    let zc = zero_copy
        .map(|r| unsafe { ZcMem::register(&dev, r) })
        .transpose()?;
    let mut vc = Vec::with_capacity(cores);
    for c in 0..cores {
        // each core's CQ on its own completion vector (round robin over the device's interrupt lines)
        let mut core = Core::new(
            &dev,
            CoreCfg {
                comp_vector: c as u32,
                ..cfg
            },
        )?;
        if let Some(z) = &zc {
            core.set_zero_copy(z.clone(), cfg.slot as usize)?;
        }
        vc.push(core);
    }
    if let Some(z) = &zc {
        println!(
            "croit-flashstore-osd: rdma: {ip}: zero-copy sends from {} MiB of the payload heap ({} regions), chunks >= {} KiB",
            z.bytes() >> 20,
            z.regions(),
            cfg.slot >> 10
        );
    }
    let handles = vc.iter().map(Core::handles).collect::<Vec<_>>();
    // Source-pull PUT (adr 0665) needs QPs that post and answer RDMA READs
    // (spec rdma-read-offer.md). Without the opt-in every QP is SEND/WRITE only.
    // `memory-windows` (the READ/MW half of the verbs crate) is always on here:
    // this module only compiles with `rt`'s `rdma` feature, which enables it.
    let core_wakes = wakes.clone();
    let (ctl, links, reads) = if source_pull {
        ::rdma::control::start_verbs_prefer_reads(
            dev.clone(),
            handles,
            ControlCfg::default(),
            move |c| wakes[c].poke(),
        )?
    } else {
        let (ctl, links) = start_verbs(dev.clone(), handles, ControlCfg::default(), move |c| {
            wakes[c].poke()
        })?;
        (ctl, links, false)
    };
    println!(
        "croit-flashstore-osd: rdma: {ip} on {} ({} MiB registered per core: {} receive slots, {} send slots of {} KiB, up to {} sessions per core at the minimum window, {})",
        dev.name(),
        ((u64::from(cfg.srq_depth) + u64::from(cfg.tx_slots)) * u64::from(cfg.slot)) >> 20,
        cfg.srq_depth,
        cfg.tx_slots,
        cfg.slot >> 10,
        vc.first().map_or(0, Core::max_connections),
        match cap.limit() {
            0 => "no session limit".to_owned(),
            n => format!("at most {n} sessions in all"),
        },
    );
    let name = dev.name().to_owned();
    let planes = vc
        .into_iter()
        .zip(links)
        .zip(core_wakes.iter())
        .map(|((core, link), wake)| Plane {
            ip,
            name: name.clone(),
            ctr: Counters::default(),
            up: Upgrader::new(link, core.max_connections(), cap.clone()),
            core: std::mem::ManuallyDrop::new(core),
            by_qpn: FxMap::default(),
            armed: false,
            arm_failed: false,
            paused: Vec::new(),
            to_pause: Vec::new(),
            pulls: reads
                .then(|| register_pulls(&dev, ip, wake.clone()))
                .flatten(),
        })
        .collect();
    if reads {
        println!(
            "croit-flashstore-osd: rdma: {ip}: source-pull: {} MiB registered READ destination arena per core",
            super::kpull::ARENA >> 20
        );
    }
    Ok((ctl, planes, reads))
}

/// Source-pull READ destinations of one core on one device (adr 0665): one arena,
/// registered once. A device whose registration fails gets no source-pull (the OSD answers with an error).
fn register_pulls(dev: &Arc<Device>, ip: Ipv4Addr, wake: Arc<Wake>) -> Option<PullArena> {
    PullArena::register(dev, wake)
        .inspect_err(|error| {
            eprintln!(
                "croit-flashstore-osd: rdma: {ip}: source-pull destination registration failed: {error} (no source-pull on this core)"
            )
        })
        .ok()
}

/// The loud message of a close fence that did not complete within the linger limit.
pub(super) fn fence_timeout(limit: Duration, conn: u64) -> String {
    ::rdma::fence::timeout_message(limit, conn)
}

impl<const N: usize> KNet<N> {
    #[cfg(test)]
    pub(super) fn test_placement_core(&mut self, conn: u64) -> Option<(&mut Core, u32)> {
        let slot = *self.by_id.get(&conn)?;
        let c = self.slots[slot as usize].as_ref()?;
        let plane = c.rdma.plane?;
        let qpn = c.rdma.carrier.rdma_qpn()?;
        Some((&mut self.rdma.as_mut()?.planes[plane].core, qpn))
    }

    /// Install this core's RDMA planes (call before polling).
    pub fn set_rdma(&mut self, r: KRdma) {
        self.rdma = Some(r);
        self.rdma_arm_wake();
    }

    /// Read of the control wake eventfd (re-armed after every completion, like the mesh wake).
    fn rdma_arm_wake(&mut self) {
        let Some(r) = self.rdma.as_mut() else {
            return;
        };
        let e = opcode::Read::new(Fd(r.wake.raw_fd()), (&raw mut *r.wake_buf).cast(), 8)
            .build()
            .user_data(ud(K_RDMA, CTL_WAKE, 0));
        self.push(e);
    }

    /// Execute an `IoCmd::Rdma*`: without usable planes, or for a connection that no plane serves, the command is declined.
    pub(super) fn rdma_cmd<D: Driver>(&mut self, d: &mut D, cmd: IoCmd, now: Duration) {
        let Some(mut r) = self.rdma.take() else {
            return d.rdma_decline(cmd, now);
        };
        self.rdma_exec(&mut r, d, cmd, now);
        self.rdma = Some(r);
        self.rdma_follow(d, now);
    }

    /// The slot and connection of `conn` when it may be upgraded: plain TCP, established, not upgraded or being upgraded,
    /// and the peer is another host. A peer on this host stays TCP: its RDMA traffic would loop through the NIC (a QP pair
    /// on one device), where it takes receive buffers and PCIe bandwidth of the port from the real inbound traffic and
    /// makes the NIC drop that (doc/perf/rdma-size3-20261021.md), while the kernel's loopback TCP is a memory copy.
    pub(super) fn rdma_candidate(&self, conn: u64) -> Option<(u32, &super::Conn)> {
        let &slot = self.by_id.get(&conn)?;
        let c = self.slots[slot as usize].as_ref()?;
        let eligible = !(c.dying
            || c.dialing
            || !c.rdma.carrier.is_tcp()
            || c.rdma.plane.is_some()
            || c.local_peer
            // the zcrx receive delivers this stream (adr 0464): no carrier switch
            || c.zrx);
        eligible.then_some((slot, c))
    }

    /// The connection a command can start an upgrade on ([`KNet::rdma_candidate`]) with its plane and TCP peer address.
    fn rdma_target(&self, r: &KRdma, conn: u64) -> Option<(u32, usize, Ipv4Addr)> {
        let (slot, c) = self.rdma_candidate(conn)?;
        let pi = r.plane_of(local_v4(c.fd)?)?;
        // RDMA upgrades stay IPv4 (adr 0659-ip-address-families open question: GID by peer family)
        let ip = peer_v4(c.fd)?;
        Some((slot, pi, ip))
    }

    fn rdma_exec<D: Driver>(&mut self, r: &mut KRdma, d: &mut D, cmd: IoCmd, now: Duration) {
        match cmd {
            IoCmd::RdmaPrepare { conn } => {
                let started = self.rdma_target(r, conn).is_some_and(|(slot, pi, _)| {
                    let p = &mut r.planes[pi];
                    let res = p.up.prepare(conn, p.core.connections());
                    p.count_refused(res.err());
                    if res.is_ok()
                        && let Some(c) = self.slots[slot as usize].as_mut()
                    {
                        c.rdma.plane = Some(pi);
                    }
                    res.is_ok()
                });
                if !started {
                    d.rdma_decline(IoCmd::RdmaPrepare { conn }, now);
                }
            }
            IoCmd::RdmaAccept { conn, endpoint } => {
                let started = self.rdma_target(r, conn).is_some_and(|(slot, pi, ip)| {
                    let p = &mut r.planes[pi];
                    match p
                        .up
                        .accept(conn, &endpoint, IpAddr::V4(ip), p.core.connections())
                    {
                        Ok(()) => {
                            if let Some(c) = self.slots[slot as usize].as_mut() {
                                c.rdma.plane = Some(pi);
                            }
                            true
                        }
                        Err(e) => {
                            p.count_refused(Some(e));
                            if matches!(e, Refused::Gid | Refused::Endpoint) {
                                eprintln!(
                                    "knet: rdma: conn {conn:#x} from {ip}: declined: {}",
                                    e.as_str()
                                );
                            }
                            false
                        }
                    }
                });
                if !started {
                    d.rdma_decline(IoCmd::RdmaAccept { conn, endpoint }, now);
                }
            }
            IoCmd::RdmaConnect { conn, endpoint } => {
                let held = self.by_id.get(&conn).copied().and_then(|slot| {
                    let c = self.slots[slot as usize].as_ref()?;
                    let ip = peer_v4(c.fd)?;
                    Some((slot, c.rdma.plane?, ip))
                });
                let Some((slot, pi, ip)) = held else {
                    eprintln!(
                        "knet: rdma: conn {conn:#x}: accepted upgrade cannot be connected (no socket, peer address or prepared QP), connection dropped"
                    );
                    for p in &mut r.planes {
                        p.up.release(conn);
                    }
                    return d.rdma_decline(IoCmd::RdmaConnect { conn, endpoint }, now);
                };
                if let Err(e) = r.planes[pi].up.connect(conn, &endpoint, IpAddr::V4(ip)) {
                    r.planes[pi].count_refused(Some(e));
                    eprintln!("knet: rdma: conn {conn:#x} to {ip}: closed: {}", e.as_str());
                    self.conn_dead(d, slot, now);
                }
            }
            IoCmd::RdmaRelease { conn } => {
                for p in &mut r.planes {
                    // an upgrade that ends here without a QP: the server declined it (or the connection went away)
                    p.ctr.declined += u64::from(p.up.release(conn));
                }
                if let Some(&slot) = self.by_id.get(&conn)
                    && let Some(c) = self.slots[slot as usize].as_mut()
                {
                    c.rdma.plane = None;
                }
            }
            cmd @ IoCmd::PlaceReadReply { .. } => {
                self.rdma_place_read(r, d, cmd);
            }
            cmd @ IoCmd::SourcePullRead { .. } => self.rdma_source_pull_read(r, d, cmd),
            IoCmd::PlaceReadCancel { conn, tid, retry } => {
                // Close WRITE admission for the live attempt; it resumes on SQ progress
                // and in the CQ phase, where the accepted WRITE CQEs are drained and
                // RETIRED is sent on the same SQ.
                let found = self
                    .by_id
                    .get(&conn)
                    .and_then(|&slot| self.slots[slot as usize].as_mut())
                    .and_then(|c| {
                        c.rdma
                            .placement
                            .iter_mut()
                            .find(|inflight| inflight.tid == tid && inflight.retry == retry)
                    })
                    .map(|inflight| {
                        inflight.owner.cancel();
                        inflight.cancelled = true;
                    })
                    .is_some();
                if !found {
                    // No live owner on the transport (the WRITEs were never posted, or the
                    // attempt already settled): the link sends the RETIRED and vacates.
                    d.placement_cancelled(conn, tid, retry);
                }
            }
            IoCmd::Dial { .. } | IoCmd::Close { .. } => {}
        }
    }

    /// Start one source-pull READ (adr 0665) on the connection's RC QP into a destination
    /// of exactly its length from this core's arena. Without room or READ admission the pull waits (FIFO, retried in
    /// the CQ phase); a command the transport cannot serve answers the held op with an error (never a silent drop).
    fn rdma_source_pull_read<D: Driver>(&mut self, r: &mut KRdma, d: &mut D, cmd: IoCmd) {
        let IoCmd::SourcePullRead {
            conn,
            tid,
            source,
            rkey,
            length,
            ..
        } = cmd
        else {
            unreachable!("rdma_source_pull_read takes only SourcePullRead")
        };
        let pull = Pull {
            conn,
            tid,
            source,
            rkey,
            length,
        };
        let plane = self
            .by_id
            .get(&conn)
            .and_then(|&slot| self.slots[slot as usize].as_ref())
            .and_then(|c| c.rdma.plane.filter(|_| c.rdma.carrier.rdma_qpn().is_some()));
        let Some(pi) = plane.filter(|&pi| r.planes[pi].pulls.is_some()) else {
            // No READ direction on this connection (not upgraded / no depths / no arena).
            return d.source_pull_done(conn, tid, Err(-95));
        };
        if r.planes[pi]
            .pulls
            .as_ref()
            .is_some_and(|a| !a.waiting.is_empty())
        {
            // older pulls wait: this one queues behind them
            if let Some(arena) = r.planes[pi].pulls.as_mut() {
                arena.waiting.push_back(pull);
            }
            return;
        }
        let Some(pull) = self.post_pull(r, pi, d, pull) else {
            return;
        };
        if let Some(arena) = r.planes[pi].pulls.as_ref() {
            arena.starve();
        }
        if let Some(pull) = self.post_pull(r, pi, d, pull)
            && let Some(arena) = r.planes[pi].pulls.as_mut()
        {
            arena.waiting.push_back(pull);
        } else if let Some(arena) = r.planes[pi].pulls.as_ref() {
            arena.fed();
        }
    }

    /// Post the READ of `pull` on plane `pi`. `Some(pull)` = no arena room or READ admission now: the caller keeps it
    /// waiting. Anything else is answered to the OSD here (posted: in the CQ phase).
    fn post_pull<D: Driver>(
        &mut self,
        r: &mut KRdma,
        pi: usize,
        d: &mut D,
        pull: Pull,
    ) -> Option<Pull> {
        let Pull {
            conn,
            tid,
            source,
            rkey,
            length,
        } = pull;
        let Some(c) = self
            .by_id
            .get(&conn)
            .and_then(|&slot| self.slots[slot as usize].as_mut())
        else {
            d.source_pull_done(conn, tid, Err(-22));
            return None;
        };
        let Some(qpn) = c
            .rdma
            .carrier
            .rdma_qpn()
            .filter(|_| c.rdma.plane == Some(pi))
        else {
            d.source_pull_done(conn, tid, Err(-95));
            return None;
        };
        let Plane { core, pulls, .. } = &mut r.planes[pi];
        let Some(arena) = pulls.as_mut() else {
            d.source_pull_done(conn, tid, Err(-95));
            return None;
        };
        let destination = arena.claim(length)?;
        // SAFETY: the record was admitted on this authenticated session and the
        // client keeps the source live until the reply retires it.
        let Ok(remote) =
            (unsafe { RemoteReadSource::from_raw_parts(source, u64::from(length), rkey) })
        else {
            arena.give_back(destination);
            d.source_pull_done(conn, tid, Err(-22));
            return None;
        };
        match core.read(qpn, ReadTarget::prepare(destination), remote) {
            Ok(handle) => {
                c.rdma.pulls.push(PullInFlight { tid, handle });
                r.pulls_open += 1;
                None
            }
            Err(ReadPostError { error, target }) => {
                arena.give_back(target.into_destination());
                let errno = match error.kind() {
                    // READ admission (SQ / READ depth) is full: wait for SQ progress
                    std::io::ErrorKind::WouldBlock => return Some(pull),
                    std::io::ErrorKind::Unsupported => -95,
                    std::io::ErrorKind::NotConnected | std::io::ErrorKind::ConnectionAborted => {
                        -108
                    }
                    _ => -5,
                };
                d.source_pull_done(conn, tid, Err(errno));
                None
            }
        }
    }

    /// Post waiting pulls of every plane, oldest first, until one still finds no room. True if any left the queue.
    fn retry_pulls<D: Driver>(&mut self, r: &mut KRdma, d: &mut D) -> bool {
        let mut work = false;
        for pi in 0..r.planes.len() {
            while let Some(pull) = r.planes[pi]
                .pulls
                .as_mut()
                .and_then(|a| a.waiting.pop_front())
            {
                if let Some(pull) = self.post_pull(r, pi, d, pull) {
                    if let Some(arena) = r.planes[pi].pulls.as_mut() {
                        arena.waiting.push_front(pull);
                    }
                    break;
                }
                work = true;
            }
            if let Some(arena) = r.planes[pi].pulls.as_ref() {
                arena.fed();
            }
        }
        work
    }

    /// Placement WRITE-to-reply handoff (spec rdma-placement-runtime.md): drain the
    /// connection's older output onto the SQ, preflight the reply's original source pieces
    /// against this core's registered arena and the checked grant, post the WRITEs in
    /// destination order on the connection's RC QP, and keep the owner on the connection so
    /// [`KRdma`] drives it to a terminal outcome on SQ progress and in the CQ phase. A
    /// preflight refusal reports `placement_preflight_refused` (the link sends
    /// an ordered RETIRED error); a post fault reports `placement_fault`.
    fn rdma_place_read<D: Driver>(&mut self, r: &mut KRdma, d: &mut D, cmd: IoCmd) {
        let (conn, tid, retry, grant, pieces, block_crcs, len) = match cmd {
            IoCmd::PlaceReadReply {
                conn,
                tid,
                retry,
                grant,
                pieces,
                block_crcs,
                len,
            } => (conn, tid, retry, grant, pieces, block_crcs, len),
            _ => unreachable!("rdma_place_read takes only PlaceReadReply"),
        };
        let Some(&slot) = self.by_id.get(&conn) else {
            return d.placement_fault(conn, tid, retry);
        };
        let Some(c) = self.slots[slot as usize].as_ref() else {
            return d.placement_fault(conn, tid, retry);
        };
        let (Some(pi), Some(qpn)) = (c.rdma.plane, c.rdma.carrier.rdma_qpn()) else {
            return d.placement_fault(conn, tid, retry);
        };
        let p = &mut r.planes[pi];
        let Some(c) = self.slots[slot as usize].as_mut() else {
            return d.placement_fault(conn, tid, retry);
        };
        let (mut owner, mut prefix) = c.rdma.spare_placement.pop().unwrap_or_else(|| {
            let mut owner = PlacedReadWrite::new(grant, qpn);
            owner.recycle().expect("new owner has no posted WRITEs");
            (owner, VecDeque::new())
        });
        // Unbounded poll_output_chunks prepares and drains all currently eligible
        // older output. The messenger holds later ordinary messages for placement.
        // Freeze the prefix now; subsequent output must not extend this boundary.
        prefix.append(&mut c.out);
        prefix.extend(d.poll_output_chunks(conn));
        match owner.prepare(&p.core, grant, qpn, pieces, len) {
            Err(error) => {
                // The reply cannot be placed (source pieces outside the registered arena, a length that does not
                // match, or an owner that is not reusable): say why, then retire the grant with an error reply.
                eprintln!(
                    "knet: rdma: conn {conn:#x}: placement preflight refused: {}",
                    error.error
                );
                c.out.append(&mut prefix);
                c.rdma.spare_placement.push((owner, prefix));
                d.placement_preflight_refused(conn, tid, retry);
            }
            Ok(()) => {
                c.rdma.placement.push(PlacementInFlight {
                    tid,
                    retry,
                    owner,
                    qpn,
                    prefix,
                    block_crcs,
                    cancelled: false,
                });
                if !self.placement_slots.contains(&slot) {
                    self.placement_slots.push(slot);
                }
                self.stats.tx_bytes += drive_placement(p, d, c) as u64;
            }
        }
    }

    /// The RDMA phase of `poll`: release what closed connections held, answer finished control requests, drain the CQ.
    /// True if anything happened.
    pub(super) fn rdma_phase<D: Driver>(&mut self, d: &mut D, now: Duration) -> bool {
        self.rdma_awake();
        self.rdma_poll(d, now)
    }

    /// The core is running again: the control threads need not poke it.
    fn rdma_awake(&mut self) {
        if let Some(r) = self.rdma.as_mut()
            && std::mem::take(&mut r.wake_sleeping)
        {
            r.wake.set_sleeping(false);
            let _ = r.wake.take_poke();
        }
    }

    fn rdma_poll<D: Driver>(&mut self, d: &mut D, now: Duration) -> bool {
        let Some(mut r) = self.rdma.take() else {
            return false;
        };
        let mut work = !self.rdma_dead.is_empty();
        while let Some((pi, conn, qpn, pulls)) = self.rdma_dead.pop() {
            let p = &mut r.planes[pi];
            p.up.release(conn);
            if let Some(q) = qpn {
                p.by_qpn.remove(&q);
                // READs still in flight: their ranges go with the QP and return to the arena after it is destroyed
                if let Some(arena) = p.pulls.as_mut() {
                    for pull in pulls {
                        arena.abandon(&mut p.core, pull.handle);
                    }
                }
                if let Some(det) = p.core.detach(q) {
                    p.up.destroy(det.qp, det.held);
                }
            }
        }
        // Source-pull READ completions (adr 0665): a completed pull hands its
        // destination range to the OSD as the op's data (the OSD verifies the crc32c); the range returns to this
        // core's arena when the store dropped the last reference.
        if r.pulls_open != 0 {
            let mut open = 0;
            for slot in 0..self.slots.len() {
                let Some(c) = self.slots[slot].as_ref() else {
                    continue;
                };
                if c.rdma.pulls.is_empty() {
                    continue;
                }
                let id = c.id;
                let plane = c.rdma.plane;
                let mut pulls = std::mem::take(&mut self.slots[slot].as_mut().unwrap().rdma.pulls);
                let mut i = 0;
                while i < pulls.len() {
                    let state = pulls[i].handle.state();
                    match state {
                        ReadState::Complete | ReadState::Failed => {
                            let done = pulls.swap_remove(i);
                            work = true;
                            let tid = done.tid;
                            let outcome = match plane.map(|pi| &mut r.planes[pi]) {
                                Some(Plane {
                                    core,
                                    pulls: Some(arena),
                                    ..
                                }) => match done.handle.into_target() {
                                    // the destination's range becomes the op's data, no copy
                                    Ok(target) => {
                                        arena.publish(target.into_destination()).map_err(|_| -5)
                                    }
                                    // a fault is no proof the NIC stopped writing the range: it stays with the QP it
                                    // was posted on until that QP is destroyed (the fault tears the session down)
                                    Err(handle) => {
                                        arena.abandon(core, handle);
                                        Err(-5)
                                    }
                                },
                                _ => Err(-5),
                            };
                            d.source_pull_done(id, tid, outcome);
                        }
                        _ => i += 1,
                    }
                }
                open += pulls.len();
                if let Some(c) = self.slots[slot].as_mut() {
                    c.rdma.pulls = pulls;
                }
            }
            r.pulls_open = open;
        }
        // pulls that waited for room (released payloads ring this core) or READ admission (SQ progress)
        work |= self.retry_pulls(&mut r, d);
        for pi in 0..r.planes.len() {
            while let Some(done) = r.planes[pi].up.poll() {
                work = true;
                self.rdma_done(&mut r, pi, d, done, now);
            }
            // connections the OSD takes input from again get their held data, in order
            let p = &mut r.planes[pi];
            // lend credits to the busy sessions, take them from idle ones (one step per `grant::TICK`)
            p.core.tick(now.as_nanos() as u64);
            let mut i = 0;
            while i < p.paused.len() {
                let q = p.paused[i];
                let Some(&(slot, id)) = p.by_qpn.get(&q) else {
                    p.paused.swap_remove(i); // gone (its slots were re-posted by the detach)
                    continue;
                };
                if !d.input_ready(id) {
                    i += 1;
                    continue;
                }
                let silent = self.slots[slot as usize]
                    .as_ref()
                    .is_none_or(|c| c.reported);
                work |= p.core.resume(q, |_, ev| match ev {
                    Event::Data(b) if !silent => deliver(d, id, b, now),
                    _ => Flow::Go,
                }) > 0;
                if p.core.paused(q) {
                    i += 1; // the held data filled the OSD again: the rest stays held
                } else {
                    p.paused.swap_remove(i);
                }
            }
            loop {
                let slots = &self.slots;
                let follow = &mut r.follow;
                let p = &mut r.planes[pi];
                let n = p.core.poll_flow(|qpn, ev| {
                    let Some(&(slot, id)) = p.by_qpn.get(&qpn) else {
                        return Flow::Go;
                    };
                    match ev {
                        Event::Data(b) => {
                            if slots[slot as usize].as_ref().is_some_and(|c| !c.reported) {
                                let flow = deliver(d, id, b, now);
                                if flow != Flow::Go {
                                    p.to_pause.push(qpn);
                                }
                                return flow;
                            }
                        }
                        Event::Writable => {
                            // a connection the OSD closed is no longer found by id: its drain / fence goes by slot
                            let closing = slots[slot as usize]
                                .as_ref()
                                .is_some_and(|c| c.closing.is_some());
                            follow.push_back(if closing {
                                Follow::Drain(slot)
                            } else {
                                Follow::Flush(id)
                            });
                        }
                        Event::RemoteInvalidated(key) => {
                            eprintln!(
                                "knet: rdma: conn {id:#x}: unexpected remote invalidation {:#x}",
                                key.key()
                            );
                            p.ctr.faulted += 1;
                            follow.push_back(Follow::Dead(slot));
                        }
                        Event::Fault(why) => {
                            eprintln!("knet: rdma: conn {id:#x}: {why}");
                            p.ctr.faulted += 1;
                            follow.push_back(Follow::Dead(slot));
                        }
                    }
                    Flow::Go
                });
                work |= n > 0;
                // the core holds what the not-ready connections receive next (`Flow`); resumed by a later phase
                while let Some(q) = p.to_pause.pop() {
                    if !p.paused.contains(&q) {
                        p.paused.push(q);
                    }
                }
                if n < 32 {
                    break;
                }
            }
            // Drive the placement owners of every connection in this plane: a completed
            // WRITE CQE does not always produce a `Writable` event (the SQ was never full),
            // so an idle connection's placement reply would be lost without this pass.
            // Only slots with in-flight placement owners are visited (no allocation, no
            // full connection walk when placement is idle).
            let p = &mut r.planes[pi];
            let slots = &mut self.slots;
            // A connection that just retired its last placement owner owes a flush: `rdma_flush` returns early
            // while a placement is in flight and no `Writable` follows that pass, so its queued output (the
            // move's reply) would wait for an unrelated event. Collected here, flushed right after the pass.
            let mut flush_after_placement: Vec<u64> = Vec::new();
            self.placement_slots.retain(|&slot| {
                let Some(c) = slots[slot as usize].as_mut() else {
                    return false;
                };
                let before = c.rdma.placement.len();
                if c.rdma.plane == Some(pi) && !c.dying {
                    self.stats.tx_bytes += drive_placement(p, d, c) as u64;
                }
                let left = !c.rdma.placement.is_empty();
                if before != 0 && !left && !c.out.is_empty() {
                    flush_after_placement.push(c.id);
                }
                left
            });
            for id in flush_after_placement {
                r.follow.push_back(Follow::Flush(id));
            }
            // QPs whose completions this drain processed (quiesced before it): destroy now
            let p = &mut r.planes[pi];
            while let Some(det) = p.core.drained() {
                work = true;
                p.up.destroy_drained(det.qp, det.held);
            }
        }
        // sockets that ended (the peer closed or died): the CQ is drained above, what arrived before is delivered
        for (slot, id) in r.ended.drain(..) {
            work = true;
            if self.slots[slot as usize]
                .as_ref()
                .is_some_and(|c| c.id == id && !c.dying)
            {
                r.follow.push_back(Follow::Dead(slot));
            }
        }
        self.rdma = Some(r);
        self.rdma_follow(d, now);
        work
    }

    fn rdma_follow<D: Driver>(&mut self, d: &mut D, now: Duration) {
        while let Some(f) = self.rdma.as_mut().and_then(|r| r.follow.pop_front()) {
            match f {
                Follow::Flush(id) => self.flush_one(d, id),
                Follow::Drain(slot) => self.rdma_flush(d, slot),
                Follow::Dead(slot) => self.conn_dead(d, slot, now),
            }
        }
    }

    /// A control request of plane `pi` finished.
    fn rdma_done<D: Driver>(
        &mut self,
        r: &mut KRdma,
        pi: usize,
        d: &mut D,
        done: Done<Qp>,
        now: Duration,
    ) {
        let p = &mut r.planes[pi];
        match done {
            Done::Quiesced { qp, held } => p.core.quiesced(qp, held),
            Done::Reclaim { held } => p.core.reclaim(&held),
            Done::Prepared { conn, endpoint } => {
                let held = endpoint.is_some();
                p.ctr.declined += u64::from(!held);
                let answered = self.by_id.contains_key(&conn)
                    && d.rdma_prepared(conn, endpoint.map(|e| e.encode()), now);
                if !(held && answered) {
                    p.ctr.declined += u64::from(p.up.release(conn));
                    self.rdma_clear(conn);
                }
            }
            Done::Accepted { conn, accepted } => {
                let Some(slot) = self.by_id.get(&conn).copied() else {
                    if let Some(a) = accepted {
                        p.up.destroy(a.qp, Release::default()); // the connection is gone
                    }
                    return;
                };
                let Some(a) = accepted else {
                    p.ctr.declined += 1;
                    d.rdma_accepted(conn, None, now); // decline
                    self.rdma_clear(conn);
                    return;
                };
                let qpn = a.qp.qpn();
                match p.core.attach(a.qp, &a.peer, a.permit) {
                    Err(qp) => {
                        p.ctr.sessions_capped += 1;
                        p.up.destroy(qp, Release::default());
                        d.rdma_accepted(conn, None, now);
                        self.rdma_clear(conn);
                    }
                    Ok(()) => {
                        // attached before the ACCEPT leaves: the client's first frame may follow it closely. TCP stays the
                        // carrier until the ACCEPT frame is sent (`rdma_switch`).
                        p.by_qpn.insert(qpn, (slot, conn));
                        if let Some(c) = self.slots[slot as usize].as_mut() {
                            c.rdma.carrier.arm(qpn);
                        }
                        if !d.rdma_accepted(conn, Some(a.ours.encode()), now) {
                            // the connection moved on: no switch
                            p.by_qpn.remove(&qpn);
                            if let Some(c) = self.slots[slot as usize].as_mut() {
                                c.rdma.carrier = Carrier::Tcp;
                                c.rdma.plane = None;
                            }
                            if let Some(det) = p.core.detach(qpn) {
                                p.up.destroy(det.qp, det.held);
                            }
                        }
                    }
                }
            }
            Done::Connected {
                conn,
                qp,
                peer,
                permit,
            } => {
                let Some(slot) = self.by_id.get(&conn).copied() else {
                    p.up.destroy(qp, Release::default());
                    return;
                };
                let qpn = qp.qpn();
                match p.core.attach(qp, &peer, permit) {
                    Err(qp) => {
                        eprintln!(
                            "knet: rdma: conn {conn:#x}: connected QP {} not attached (core receive pool full or duplicate), connection dropped",
                            qp.qpn()
                        );
                        p.ctr.sessions_capped += 1;
                        p.up.destroy(qp, Release::default());
                        r.follow.push_back(Follow::Dead(slot));
                    }
                    Ok(()) => {
                        p.by_qpn.insert(qpn, (slot, conn));
                        if let Some(c) = self.slots[slot as usize].as_mut() {
                            // the OFFER was our last TCP byte: the QP carries everything from here, the socket stays
                            // open as the liveness channel
                            c.rdma.carrier.arm(qpn);
                            c.rdma.carrier.switch();
                        }
                        if d.rdma_connected(conn, now) {
                            p.ctr.upgraded += 1;
                        } else {
                            eprintln!(
                                "knet: rdma: conn {conn:#x}: session refused the switch (state moved on), connection dropped"
                            );
                            r.follow.push_back(Follow::Dead(slot));
                        }
                    }
                }
            }
            Done::ConnectFailed { conn } => {
                eprintln!("knet: rdma: conn {conn:#x}: QP connect failed, connection dropped");
                p.ctr.declined += 1;
                if let Some(&slot) = self.by_id.get(&conn) {
                    r.follow.push_back(Follow::Dead(slot));
                }
            }
        }
    }

    /// Server: the ACCEPT frame was the last TCP output. When it left completely, the QP carries our output; the socket stays
    /// open as the connection's liveness channel (spec 18).
    pub(super) fn rdma_switch_if_ready(&mut self, slot: u32) {
        let Some(c) = self.slots[slot as usize].as_mut() else {
            return;
        };
        let plane = c.rdma.plane;
        if !c.dying
            && c.rdma.carrier.switch_ready(c.out.is_empty(), c.sending)
            && c.rdma.carrier.switch()
            && let (Some(pi), Some(r)) = (plane, self.rdma.as_mut())
        {
            r.planes[pi].ctr.upgraded += 1;
        }
    }

    /// A receive completion on a socket past (or at) the switch point, where the socket is the connection's liveness
    /// channel: bytes behind the ACCEPT / OFFER frame are a fault (closed at once); its end (EOF / reset) = the peer closed
    /// or died: the connection is dead after the next CQ phase delivered what arrived over the QP before.
    pub(super) fn rdma_tcp_rx<D: Driver>(
        &mut self,
        d: &mut D,
        slot: u32,
        res: i32,
        more: bool,
        bid: Option<u16>,
        now: Duration,
    ) {
        if let Some(b) = bid {
            self.bufs.give(b);
        }
        let Some(c) = self.slots[slot as usize].as_ref() else {
            return;
        };
        let read = match res {
            1.. => SockRead::Bytes,
            0 => SockRead::End,
            // a multishot receive without a buffer: bytes are pending
            _ if -res == libc::ENOBUFS => SockRead::Bytes,
            _ if matches!(-res, libc::EINTR | libc::EAGAIN | libc::ECANCELED) => SockRead::Idle,
            _ => SockRead::End,
        };
        let (id, dying) = (c.id, c.dying);
        match c.rdma.carrier.tcp_rx(read) {
            TcpRx::Fault if !dying => {
                eprintln!(
                    "knet: rdma: conn {id:#x}: bytes on the TCP socket after the switch point, connection dropped"
                );
                self.conn_dead(d, slot, now);
            }
            TcpRx::Closed if !dying => {
                if let Some(r) = self.rdma.as_mut() {
                    r.ended.push((slot, id));
                }
            }
            // an own cancel (receive pause) is re-armed by `resume_rx`
            TcpRx::Idle if !more && !dying && -res != libc::ECANCELED => self.arm_recv(slot),
            _ => {}
        }
        self.maybe_free(slot);
    }

    /// Send the output of an upgraded connection through its QP; what the core cannot take yet stays queued and resumes on
    /// `Event::Writable`. Output is pulled again whenever the queue drained: a notification consumed while the queue was
    /// blocked (`flush_one` found `c.out` non-empty) is owed here, like `on_send` owes it on TCP; nothing re-notifies it.
    /// The in-flight placement WRITE-to-reply owner is driven first: pending pieces are posted on SQ progress and the
    /// terminal outcome is reported once every accepted WRITE is retired (spec rdma-placement-runtime.md).
    pub(super) fn rdma_flush<D: Driver>(&mut self, d: &mut D, slot: u32) {
        let (Some(r), Some(c)) = (self.rdma.as_mut(), self.slots[slot as usize].as_mut()) else {
            return;
        };
        let (Some(pi), Some(qpn)) = (c.rdma.plane, c.rdma.carrier.rdma_qpn()) else {
            return;
        };
        if c.dying {
            return;
        }
        let p = &mut r.planes[pi];
        // Drive the in-flight placement WRITE-to-reply owners (parallel READs, in admission order).
        self.stats.tx_bytes += drive_placement(p, d, c) as u64;
        // Clean up the placement slot tracking: if no owners remain, the slot is no longer
        // visited in the CQ phase.
        if c.rdma.placement.is_empty()
            && let Some(pos) = self.placement_slots.iter().position(|&s| s == slot)
        {
            self.placement_slots.remove(pos);
        }
        // While a placement owner is in flight, hold back later output: the placement reply
        // must not be overtaken by SENDs posted after the WRITEs (spec: SQ order). The output
        // stays queued until every placement owner is terminal.
        if !c.rdma.placement.is_empty() {
            return;
        }
        // behind the fence nothing more is sent: the fence must be the last WR
        if !c.rdma.fencing {
            loop {
                if c.out.is_empty() {
                    c.out.extend(d.poll_output_chunks(c.id));
                    if c.out.is_empty() {
                        break;
                    }
                }
                // the whole queue in one call: small chunks share SENDs, large ones in the registered payload heap go
                // zero copy (the core keeps a reference until the HCA has read them), the SENDs of the call leave
                // with one doorbell
                let n = p.core.send_chunks(qpn, &mut c.out);
                self.stats.tx_bytes += n as u64;
                if !c.out.is_empty() {
                    return;
                }
            }
        }
        if c.closing.is_some() {
            self.rdma_close_step(slot);
        }
    }

    /// Graceful close of an upgraded connection whose output is all posted: fence it, destroy the QP when the fence
    /// completed. `Blocked` (queue full / no credit) and `Pending` are continued by the next `Event::Writable` of the
    /// connection (`Follow::Drain`); the linger deadline (`tick`) bounds the wait. Nothing to do while output is queued.
    pub(super) fn rdma_close_step(&mut self, slot: u32) {
        let (Some(r), Some(c)) = (self.rdma.as_mut(), self.slots[slot as usize].as_mut()) else {
            return;
        };
        let (Some(pi), Some(qpn)) = (c.rdma.plane, c.rdma.carrier.rdma_qpn()) else {
            return;
        };
        if c.dying || !c.out.is_empty() {
            return;
        }
        match r.planes[pi].core.fence(qpn) {
            Step::Done => self.teardown(slot),
            Step::Pending | Step::Post { .. } => c.rdma.fencing = true,
            Step::Blocked => {}
        }
    }

    /// An upgraded connection's graceful close ran into the linger deadline (`tick`): tell loudly, the caller tears down.
    pub(super) fn rdma_close_timeout(&mut self, slot: u32) {
        if let Some(c) = self.slots[slot as usize].as_ref()
            && c.rdma.carrier.rdma_qpn().is_some()
        {
            eprintln!("{}", fence_timeout(self.cfg.close_linger, c.id));
            if let (Some(pi), Some(r)) = (c.rdma.plane, self.rdma.as_mut()) {
                r.planes[pi].ctr.close_fence_timeouts += 1;
            }
        }
    }

    /// This core's RDMA status for the OSD (`rdma status`, perf counters), at most once per second; `None` in between and
    /// without planes.
    pub fn rdma_status(&mut self, now: Duration) -> Option<Vec<DeviceStatus>> {
        self.rdma.as_mut()?.report(now)
    }

    /// Idle sleep: request a CQ event on every plane, add the channel's one-shot poll to the ring, and look at the CQ once
    /// more (a completion that arrived before the arming raises no event). The control wake announces the sleep first
    /// (see [`Wake`]: the re-check below sees a reply published before the control thread's poke looked at the flag). True:
    /// there was work, do not sleep.
    pub fn rdma_sleep_check<D: Driver>(&mut self, d: &mut D, now: Duration) -> bool {
        let Some(r) = self.rdma.as_mut() else {
            return false;
        };
        r.wake.set_sleeping(true);
        r.wake_sleeping = true;
        let n = r.planes.len();
        for i in 0..n {
            let Some(p) = self.rdma.as_mut().map(|r| &mut r.planes[i]) else {
                return false;
            };
            if let Err(e) = p.core.arm()
                && !std::mem::replace(&mut p.arm_failed, true)
            {
                eprintln!(
                    "knet: rdma: {}: CQ arm failed: {e} (the sleep is bounded by its cap)",
                    p.ip
                );
            }
            if !p.armed {
                p.armed = true;
                let fd = p.core.fd();
                let e = opcode::PollAdd::new(Fd(fd), libc::POLLIN as u32)
                    .build()
                    .user_data(ud(K_RDMA, i as u32, 0));
                self.push(e);
            }
        }
        let work = self.rdma_poll(d, now);
        if work {
            self.rdma_awake();
        }
        work
    }

    /// A completion of the RDMA ring ops: plane `i`'s CQ channel became readable (consume the event, the CQ polls in this
    /// iteration's phase), or the control wake was poked (read again, the replies are taken in this iteration's phase).
    pub(super) fn on_rdma_wake(&mut self, i: usize) {
        if i == CTL_WAKE as usize {
            self.rdma_arm_wake();
        } else if let Some(p) = self.rdma.as_mut().and_then(|r| r.planes.get_mut(i)) {
            p.core.ack();
            p.armed = false;
        }
    }

    fn rdma_clear(&mut self, conn: u64) {
        if let Some(&slot) = self.by_id.get(&conn)
            && let Some(c) = self.slots[slot as usize].as_mut()
        {
            c.rdma.plane = None;
        }
    }
}

/// IPv4 peer of a socket (RDMA planes are IPv4).
fn peer_v4(fd: std::os::fd::RawFd) -> Option<Ipv4Addr> {
    match peer_addr(fd)?.ip() {
        std::net::IpAddr::V4(ip) => Some(ip),
        std::net::IpAddr::V6(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Local address of a RoCEv2 device (`FLASHSTORE_TEST_RDMA_ADDR`); the hardware tests need one.
    fn device_addr() -> Ipv4Addr {
        std::env::var("FLASHSTORE_TEST_RDMA_ADDR")
            .expect("FLASHSTORE_TEST_RDMA_ADDR (local IPv4 of a RoCEv2 device)")
            .parse()
            .expect("FLASHSTORE_TEST_RDMA_ADDR is an IPv4 address")
    }

    /// The early fatal startup error of the multi-core launcher: the planes were started, no core ever polled them, and
    /// everything is dropped (planes first, then the hub).
    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn started_planes_drop_unused() {
        let before = ::rdma::verbs::teardown_failures();
        let leaked = ::rdma::verbs::leaked_cores();
        // SAFETY: no caller memory is registered.
        let (hub, planes) =
            unsafe { start(&[device_addr()], 4, 512 << 20, 0, None, false) }.unwrap();
        assert!(planes.iter().all(Option::is_some));
        drop(planes);
        drop(hub);
        assert_eq!(
            ::rdma::verbs::teardown_failures(),
            before,
            "a core CQ/SRQ was destroyed while a QP used it"
        );
        assert_eq!(
            ::rdma::verbs::leaked_cores(),
            leaked,
            "a retire was not confirmed"
        );
    }

    /// A core that ends before it ever polled (its mount failed): each plane is dropped on its own thread while the control
    /// thread is still filling the QP pools, the hub afterwards.
    #[test]
    #[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
    fn started_planes_drop_on_their_threads() {
        let before = ::rdma::verbs::teardown_failures();
        let leaked = ::rdma::verbs::leaked_cores();
        // SAFETY: no caller memory is registered.
        let (hub, planes) =
            unsafe { start(&[device_addr()], 4, 512 << 20, 0, None, false) }.unwrap();
        let threads: Vec<_> = planes
            .into_iter()
            .map(|p| std::thread::spawn(move || drop(p)))
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        drop(hub);
        assert_eq!(
            ::rdma::verbs::teardown_failures(),
            before,
            "a core CQ/SRQ was destroyed while a QP used it"
        );
        assert_eq!(
            ::rdma::verbs::leaked_cores(),
            leaked,
            "a retire was not confirmed"
        );
    }
}
