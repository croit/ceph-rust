// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `kernel:` devices (adr 0169): an NVMe namespace owned by the kernel `nvme` driver, IO through io_uring.
//!
//! Two modes, picked by the node: `/dev/nvmeXnY` (block device) = O_DIRECT reads/writes ("direct"); `/dev/ngXnY`
//! (generic char device) = NVMe passthrough commands (`IORING_OP_URING_CMD`, "cmd"). Both keep the store's device
//! contract of [`crate::spdk::SpdkDev`]: completion = durable (PLP; volatile cache: DSYNC/FUA per write), no ordering
//! between in-flight commands, 4096 B native LBAs without metadata. Native devices require whole namespaces;
//! validated partition-backed linear LVM uses direct LV-relative IO only (ADR 0646-restore-validated-linear-lvm).
//!
//! One io_uring per thread ("device ring", SQE128/CQE32, single issuer, no cooperative task running: the completion
//! task_work runs at the interrupt return on the submitting core, so a polling core sees CQEs without a syscall and a
//! sleeping core is woken). Every queue handle used on that thread shares it: SQEs are queued and submitted once per loop
//! iteration ([`flush`], or the next [`BlockDev::poll`]). The kernel tier sleeps on the ring fd ([`thread_ring_fd`]).
//! IO buffers come from one global arena registered as fixed buffer 0 in every device ring (no per-IO page pinning).
//! Reads whose bytes stay in the store's data cache (`BlockDev::alloc_buf_ram_uninit`) come from the thread's cache region
//! instead: 2 MiB chunks mapped on demand (never pre-faulted), each registered as one fixed buffer of the thread's ring
//! (sparse table slots 1.., IORING_REGISTER_BUFFERS_UPDATE) and handed back when all its buffers are free
//! ([`BlockDev::trim_ram`]), so the cache keeps the memory envelope's soft shrink (adr 0633).
//! Cmd mode runs only after [`probe_cmd`] proved the kernel maps fixed buffers for passthrough (adr 0169 am. 1), and a
//! passthrough command only ever names a registered buffer (arena or cache chunk, `IORING_URING_CMD_FIXED`): every other
//! buffer (payload views, a read the cache region cannot take, an arena miss) is an O_DIRECT read/write on the namespace block node. A passthrough command with a
//! plain user address is unsafe: when the kernel completes its submission in an io-wq worker (inline issue -EAGAIN), the
//! nvme driver converts the address with `in_compat_syscall()`, which can be true in that worker and truncates the
//! address to 32 bits (EFAULT, or IO on the wrong memory); adr 0169 am. 11.

use crate::{
    BlockDev, Completion, DSM_MAX_LBAS, DSM_RANGE_BYTES, DeallocLimits, Geometry, IoBuf, IoError,
    NVM_DSM, NVM_READ, NVM_WRITE, NVM_WRITE_ZEROES, Nanos, Op, Rejected, Submit, SubmitError,
    dsm_deallocate_all, dsm_ranges_into, errno_err, nvme_status_err,
};
use io_uring::{IoUring, cqueue, opcode, squeue, types};
use std::cell::{Cell, RefCell, UnsafeCell};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

pub use crate::LBA;
/// Memory alignment of a payload the device writes by reference ([`BlockDev::view_buf`]).
pub const VIEW_ALIGN: usize = 4096;

/// Cold read-only admission of a mounted filesystem's LVM block node. Applies
/// the same linear-map, backing NVMe durability and overlap checks as raw storage.
/// Does not create an I/O controller, reserve the LV exclusively, or write data.
/// Administrative map reload/resize/removal during use remains forbidden.
pub fn validate_lvm_filesystem(path: &Path, expected_device: u64) -> Result<(), String> {
    linear::validate_filesystem(path, expected_device)
}
/// Largest single command: passthrough maps user pages without splitting (128 segments x 4 KiB worst case).
const MAX_XFER_BYTES: u64 = 512 << 10;
/// Device ring: submission entries (flushed every loop iteration) and completion entries. The queues' depths may sum
/// to more than `RING_CQ` (one queue is clamped to a quarter of it): a full CQ spills into the kernel's overflow list,
/// which `KRing::reap` drains (`cq_overflow`), so completions are delayed, never lost.
/// `RING_SQ` is also the ring's in-flight command limit: every command owns its SQE until its CQE (`kdev_sq`).
const RING_SQ: u32 = 4096;
const RING_CQ: u32 = 8192;
/// Queue handles per device ring. Fixed-file slots: `q` = the queue's IO node, `MAX_QUEUES + q` = its namespace block
/// node (O_DIRECT IO of buffers outside the registered arena; the IO node itself in direct mode).
const MAX_QUEUES: u32 = 32;
/// `_IO('N', 0x40)`: namespace id of the opened node.
const NVME_IOCTL_ID: u64 = 0x4e40;
/// `_IOWR('N', 0x80, struct nvme_uring_cmd)`: IO passthrough through io_uring.
const NVME_URING_CMD_IO: u32 = (3 << 30) | (72 << 16) | (0x4e << 8) | 0x80;
/// Kernel `RWF_DSYNC` (preadv2 flags): the write is durable at completion (FUA or a post-flush).
const RWF_DSYNC: i32 = 2;
/// `BLOCK_URING_CMD_DISCARD` = `_IO(0x12, 0)`: `IORING_OP_URING_CMD` on a block device opened for write discards
/// `[sqe.addr, sqe.addr + sqe.addr3)` bytes (upstream 6.12+).
const BLOCK_URING_CMD_DISCARD: u32 = 0x1200;

/// IO path of a `kernel:` device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// O_DIRECT on the namespace block device.
    Direct,
    /// NVMe IO commands through `IORING_OP_URING_CMD` on the generic char device.
    Cmd,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Mode::Direct => "direct",
            Mode::Cmd => "cmd",
        }
    }
}

static ACTIVE: AtomicBool = AtomicBool::new(false);

/// A `kernel:` device was opened in this process (the kernel tier then sleeps on the device rings).
pub fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

// ------------------------------------------------------------------------------------------------ identify

/// What the store needs from Identify Controller (CNS 1) + Identify Namespace (CNS 0).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ident {
    pub nsze: u64,
    pub data_bytes: u32,
    pub meta_bytes: u32,
    pub pi: u8,
    pub lbaf: u8,
    pub awupf: u32,
    pub awun: u32,
    pub vwc: bool,
    pub dsm: bool,
    pub write_zeroes: bool,
    pub mdts: u8,
}

fn le16(b: &[u8], o: usize) -> u32 {
    u32::from(u16::from_le_bytes([b[o], b[o + 1]]))
}

/// Parse the two identify pages (4096 B each). AWUPF/AWUN are 0's based; the namespace values win when NSFEAT bit 1
/// says they are valid. Current format = FLBAS bits 3:0 (+ bits 6:5 as the high bits beyond 16 formats).
pub fn parse_ident(ctrl: &[u8], ns: &[u8]) -> Ident {
    let flbas = ns[26];
    let idx = (flbas & 0x0f) | ((flbas >> 5) & 0x3) << 4;
    let f = 128 + 4 * idx as usize;
    let lbaf = u32::from_le_bytes([ns[f], ns[f + 1], ns[f + 2], ns[f + 3]]);
    let lbads = (lbaf >> 16) & 0xff;
    let oncs = le16(ctrl, 520);
    let (mut awupf, mut awun) = (le16(ctrl, 528) + 1, le16(ctrl, 526) + 1);
    if ns[24] & 0x2 != 0 {
        (awupf, awun) = (le16(ns, 36) + 1, le16(ns, 34) + 1);
    }
    Ident {
        nsze: u64::from_le_bytes(ns[0..8].try_into().unwrap()),
        data_bytes: if (9..32).contains(&lbads) {
            1 << lbads
        } else {
            0
        },
        meta_bytes: lbaf & 0xffff,
        pi: ns[29] & 0x7,
        lbaf: idx,
        awupf,
        awun,
        vwc: ctrl[525] & 1 != 0,
        dsm: oncs & (1 << 2) != 0,
        write_zeroes: oncs & (1 << 3) != 0,
        mdts: ctrl[77],
    }
}

/// Geometry of a `kernel:` device (same rules as the SPDK shim). `hw_max_kb` = kernel `max_hw_sectors_kb`.
pub fn geometry_of(id: &Ident, mode: Mode, hw_max_kb: Option<u64>) -> Geometry {
    let mut max = MAX_XFER_BYTES;
    if id.mdts != 0 && id.mdts < 32 {
        max = max.min(4096u64 << id.mdts);
    }
    if let Some(k) = hw_max_kb.filter(|k| *k >= 4) {
        max = max.min(k << 10);
    }
    let ls = u64::from(id.data_bytes.max(1));
    Geometry {
        lba_size: id.data_bytes,
        lba_count: id.nsze,
        awupf_lbas: id.awupf,
        awun_lbas: id.awun.max(id.awupf),
        vwc: id.vwc,
        max_xfer_lbas: (max / ls).max(1) as u32,
        // direct: no discard path (production never trims on free); write zeroes = fallocate(ZERO_RANGE), which is not
        // FUA: refused on a volatile cache (the store then writes zero blocks with DSYNC)
        dealloc: mode == Mode::Cmd && id.dsm,
        write_zeroes: match mode {
            Mode::Direct => !id.vwc,
            Mode::Cmd => id.write_zeroes,
        },
    }
}

fn identify(fd: RawFd, cns: u32, nsid: u32) -> std::io::Result<Vec<u8>> {
    let mut b = vec![0u8; 4096];
    crate::kprobe::admin_fd(fd, 0x06, nsid, cns, &mut b)?;
    Ok(b)
}

/// Capability name of the startup line `missing=[..]` (adr 0169 am. 6): the kernel refuses NVMe passthrough (Identify,
/// IO commands) to a process without CAP_SYS_ADMIN (permission check older than upstream 6.2 "fine-granular
/// CAP_SYS_ADMIN for nvme io commands", e.g. RHEL 9 5.14). The OSD runs without it (adr 0056): geometry comes from sysfs
/// ([`sysfs_ident`]) and cmd mode falls back to direct mode on the block device.
pub const MISSING_UNPRIV_PASSTHRU: &str = "UNPRIV_PASSTHRU";
/// Cmd mode without fixed-buffer passthrough (am. 1): per-IO page pinning.
pub const MISSING_URING_CMD_FIXED: &str = "URING_CMD_FIXED";
/// Cmd mode where the device rejects passthrough DSM (am. 1): runtime deallocate only by the block node's discard command.
pub const MISSING_PASSTHRU_DSM: &str = "PASSTHRU_DSM";
/// The namespace block node does not take `BLOCK_URING_CMD_DISCARD` (upstream < 6.12): runtime deallocate only by
/// passthrough DSM (cmd mode with the accepted mkfs verdict), else off (adr 0642).
pub const MISSING_URING_DISCARD: &str = "URING_DISCARD";

/// Identify Controller + Namespace of `nsid`; `Ok(None)` = the kernel refuses admin passthrough to this process
/// (EACCES / EPERM, see [`MISSING_UNPRIV_PASSTHRU`]).
fn ident_of(fd: RawFd, nsid: u32) -> Result<Option<Ident>, String> {
    match identify(fd, 1, 0).and_then(|c| Ok((c, identify(fd, 0, nsid)?))) {
        Ok((c, n)) => Ok(Some(parse_ident(&c, &n))),
        Err(e) if matches!(e.raw_os_error(), Some(libc::EACCES | libc::EPERM)) => Ok(None),
        Err(e) => Err(format!("NVMe Identify: {e}")),
    }
}

/// Geometry of a namespace from its sysfs block directory (`/sys/class/block/nvmeXnY`) when Identify is refused: logical
/// block size, capacity, volatile write cache (`queue/write_cache`), discard / write zeroes support; metadata or PI the
/// kernel exposes show as an integrity profile (`integrity/tuple_size`) and are refused like an Identify format. The
/// atomic write unit is not in sysfs on every kernel: 1 LBA (the store's minimum contract; recorded in the superblock
/// only). A format the kernel hides (capacity 0: metadata it cannot handle) is refused with the format hint.
pub fn sysfs_ident(sys: &Path) -> Result<Ident, String> {
    let num = |rel: &str| -> Result<u64, String> {
        read_sys(sys.join(rel))
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| format!("{}: sysfs {rel} not readable", sys.display()))
    };
    let lbs = num("queue/logical_block_size")?;
    let bytes = num("size")? * 512;
    if lbs == 0 || bytes == 0 {
        return Err(format!(
            "{}: capacity 0 (the kernel hides this namespace format, e.g. metadata without PI support): format it 4096+0",
            sys.display()
        ));
    }
    let tuple = read_sys(sys.join("integrity/tuple_size"))
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    Ok(Ident {
        nsze: bytes / lbs,
        data_bytes: u32::try_from(lbs)
            .map_err(|_| format!("{}: logical block size {lbs}", sys.display()))?,
        meta_bytes: tuple,
        pi: u8::from(tuple != 0),
        lbaf: 0,
        awupf: 1,
        awun: 1,
        // unreadable = volatile: writes then carry DSYNC (fail closed, like a lab block device)
        vwc: read_sys(sys.join("queue/write_cache")).is_none_or(|v| v != "write through"),
        dsm: num("queue/discard_max_hw_bytes").is_ok_and(|v| v > 0),
        write_zeroes: num("queue/write_zeroes_max_bytes").is_ok_and(|v| v > 0),
        mdts: 0,
    })
}

/// Direct mode makes writes durable with `RWF_DSYNC`, which the kernel turns into FUA / flush only while the queue's
/// `write_cache` says "write back". A volatile cache (Identify VWC) the kernel was told is write-through would ack
/// writes before they are durable: refused with the fix.
pub(crate) fn direct_cache_ok(id: &Ident, sys: &Path) -> Result<(), String> {
    let attr = sys.join("queue/write_cache");
    if id.vwc && read_sys(&attr).as_deref() == Some("write through") {
        return Err(format!(
            "{}: volatile write cache (Identify VWC) but the kernel treats it as write-through, so it sends no flush or \
             FUA and writes would be acked before they are durable. Fix: echo 'write back' > {}",
            sys.display(),
            attr.display()
        ));
    }
    Ok(())
}

/// Can this process create io_uring instances at all? Checked at every namespace open, so a host policy that refuses
/// io_uring (`kernel.io_uring_disabled`, seccomp, LSM) fails the open with its cause and the exact fix instead of an IO
/// error at the first submit.
fn probe_uring(path: &Path) -> Result<(), String> {
    IoUring::<squeue::Entry128, cqueue::Entry32>::builder()
        .build(2)
        .map(drop)
        .map_err(|e| {
            format!(
                "{}: kernel store: {}",
                path.display(),
                uring_access::refused(e)
            )
        })
}

// ------------------------------------------------------------------------------------------------ sysfs

fn read_sys(p: impl AsRef<Path>) -> Option<String> {
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_owned())
}

/// Head name of a namespace path disk: `nvme0c1n2` (multipath hidden path) -> `nvme0n2`; `nvme0n2` unchanged.
pub(crate) fn head_name(disk: &str) -> String {
    let Some(rest) = disk.strip_prefix("nvme") else {
        return disk.to_owned();
    };
    match (rest.find('c'), rest.find('n')) {
        (Some(c), Some(n)) if c < n => format!("nvme{}{}", &rest[..c], &rest[n..]),
        _ => disk.to_owned(),
    }
}

/// Kernel nodes of namespace `nsid` on the controller at PCI address `bdf` (bound to the `nvme` driver):
/// (`/dev/nvmeXnY` block head, `/dev/ngCnY` generic char device of this controller).
pub fn nodes_of_pci(bdf: &str, nsid: u32) -> Result<(PathBuf, PathBuf), String> {
    let pdir = Path::new("/sys/bus/pci/devices").join(bdf);
    let drv = std::fs::read_link(pdir.join("driver")).ok();
    if drv
        .as_ref()
        .and_then(|d| d.file_name())
        .is_none_or(|d| d != "nvme")
    {
        return Err(format!(
            "{bdf} is not bound to the kernel nvme driver (driver: {})",
            drv.as_ref()
                .and_then(|d| d.file_name())
                .map_or("none".into(), |d| d.to_string_lossy().into_owned())
        ));
    }
    let ctrl = std::fs::read_dir(pdir.join("nvme"))
        .map_err(|e| format!("{bdf}: no nvme controller in sysfs: {e}"))?
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .find(|n| n.starts_with("nvme"))
        .ok_or_else(|| format!("{bdf}: no nvme controller in sysfs"))?;
    let cdir = pdir.join("nvme").join(&ctrl);
    let mut blk = None;
    for e in std::fs::read_dir(&cdir)
        .map_err(|e| e.to_string())?
        .flatten()
    {
        let n = e.file_name().to_string_lossy().into_owned();
        if n.starts_with("nvme")
            && n.contains('n')
            && read_sys(e.path().join("nsid")).and_then(|s| s.parse::<u32>().ok()) == Some(nsid)
        {
            blk = Some(n);
        }
    }
    let disk = blk.ok_or_else(|| format!("{bdf}: namespace {nsid} has no kernel block device"))?;
    let head = head_name(&disk);
    let inst = head.rsplit('n').next().unwrap_or("");
    let ng = format!("ng{}n{inst}", ctrl.trim_start_matches("nvme"));
    Ok((Path::new("/dev").join(head), Path::new("/dev").join(ng)))
}

/// Disk name (`nvmeXnY`) of a generic char node `ngCnY` from sysfs under `sys` (`/sys/class/nvme/nvmeC/*`): the
/// controller's namespace disk with head instance Y. Needs no `/dev/nvmeXnY` node (a container may pass only the ng node).
fn disk_of_ng(sys: &Path, ng: &str) -> Result<String, String> {
    let rest = ng.strip_prefix("ng").ok_or("not an ng node")?;
    let (c, inst) = rest.split_once('n').ok_or("not an ngCnY node")?;
    let cdir = sys.join("class/nvme").join(format!("nvme{c}"));
    for e in std::fs::read_dir(&cdir)
        .map_err(|e| format!("{ng}: cannot map to its namespace, {}: {e}", cdir.display()))?
        .flatten()
    {
        let n = e.file_name().to_string_lossy().into_owned();
        if n.starts_with("nvme") && n != format!("nvme{c}") {
            let h = head_name(&n);
            if h.rsplit('n').next() == Some(inst) {
                return Ok(h);
            }
        }
    }
    Err(format!(
        "{ng}: cannot map to its namespace, no nvme{c}/nvme{c}n{inst} in {}",
        cdir.display()
    ))
}

fn is_partition(sys: &Path, disk: &str) -> bool {
    sys.join("class/block")
        .join(disk)
        .join("partition")
        .exists()
}

/// Partitions of `disk` as listed by sysfs (`nvmeXnYpZ` children), independent of any `/dev` node.
fn has_partitions(sys: &Path, disk: &str) -> bool {
    !disk.is_empty()
        && std::fs::read_dir(sys.join("class/block").join(disk))
            .map(|d| {
                d.flatten().any(|e| {
                    let n = e.file_name().to_string_lossy().into_owned();
                    n.starts_with(disk) && e.path().join("partition").exists()
                })
            })
            .unwrap_or(false)
}

// ------------------------------------------------------------------------------------------------ controller

struct Ctrl {
    /// IO node (block device O_DIRECT, or the ng char device).
    io: OwnedFd,
    /// Cmd mode: the namespace block node, O_DIRECT | O_EXCL: exclusive claim, IO node of every buffer outside the
    /// registered arena (never a passthrough user address, module doc) and `BLKDISCARD` when passthrough DSM is
    /// unusable. Direct mode: `None` (`io` itself is the O_DIRECT | O_EXCL block node).
    claim: Option<OwnedFd>,
    mode: Mode,
    nsid: u32,
    geo: Geometry,
    id: Ident,
    path: PathBuf,
    /// Verified read-only backing identity/health path; data always stays on `io`.
    probe_path: PathBuf,
    mapped: bool,
    /// Memory alignment mask the kernel requires for DMA from user buffers (`queue/dma_alignment`; payload views must meet it).
    dma_mask: usize,
    /// Capabilities this kernel lacks for the device (`MISSING_*`; startup line `missing=[..]`).
    missing: Vec<&'static str>,
    /// Passthrough DSM verdict (`DSM_*`): set by the mkfs probe or from the superblock at mount, never by an open.
    dsm: AtomicU8,
    /// blk-mq tags per hardware queue (sysfs `queue/nr_requests`; 0 = unknown): bound of a queue's depth. A command
    /// beyond the tag count fails its inline issue with -EAGAIN and is punted to an io-wq worker (latency only).
    tags: u32,
    /// Discard limits of the namespace queue and the block-node discard command (runtime deallocate, adr 0642).
    discard: Discard,
}

/// Runtime deallocate inputs of a namespace (adr 0642): its queue's discard limits (sysfs) and whether its block node takes
/// `BLOCK_URING_CMD_DISCARD` ([`probe_discard`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Discard {
    /// `queue/max_discard_segments`: ranges per discard request (nvme: DMRL).
    pub segments: u32,
    /// `queue/discard_max_hw_bytes`: device limit (nvme: DMRSL; 0 = the queue does not discard).
    pub hw_bytes: u64,
    /// `queue/discard_max_bytes`: largest discard the block layer issues as one request.
    pub max_bytes: u64,
    /// `queue/discard_granularity`.
    pub gran_bytes: u64,
    /// The block node takes `BLOCK_URING_CMD_DISCARD`.
    pub uring: bool,
}

impl Discard {
    /// The queue's discard limits from sysfs (`sys` = `/sys/class/block/<disk>`); `uring` stays false.
    pub fn of_sysfs(sys: &Path) -> Discard {
        let num = |rel: &str| {
            read_sys(sys.join(rel))
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0)
        };
        Discard {
            segments: u32::try_from(num("queue/max_discard_segments")).unwrap_or(u32::MAX),
            hw_bytes: num("queue/discard_max_hw_bytes"),
            max_bytes: num("queue/discard_max_bytes"),
            gran_bytes: num("queue/discard_granularity"),
            uring: false,
        }
    }

    /// Runtime deallocate shape. Passthrough DSM (`dsm`: cmd mode with the accepted mkfs verdict) carries up to
    /// `max_discard_segments` ranges under the limit the kernel read from the controller (DMRSL, per command as the
    /// kernel's own discards). Else the block node's discard command, one range of at most `discard_max_bytes` (one block
    /// request). Else off.
    pub fn limits(&self, dsm: bool, lba_size: u32) -> DeallocLimits {
        let ls = u64::from(lba_size.max(1));
        let gran = self.gran_bytes / ls;
        if dsm {
            let lbas = self.hw_bytes / ls;
            return DeallocLimits::nvme(
                self.segments,
                u32::try_from(lbas).unwrap_or(u32::MAX),
                lbas,
                gran,
            );
        }
        let lbas = (self.max_bytes / ls).min(DSM_MAX_LBAS);
        if !self.uring {
            DeallocLimits::off(if self.hw_bytes == 0 {
                "off(queue without discard)"
            } else {
                "off(no passthrough DSM verdict, kernel without BLOCK_URING_CMD_DISCARD)"
            })
        } else if lbas == 0 {
            DeallocLimits::off("off(discard_max_bytes 0)")
        } else {
            DeallocLimits {
                max_ranges: 1,
                range_lbas: lbas as u32,
                max_lbas: lbas,
                gran_lbas: gran.max(1),
                via: "uring-discard",
            }
        }
    }
}

/// [`Ctrl::dsm`]: no verdict (runtime deallocate off).
const DSM_UNKNOWN: u8 = 0;
/// [`Ctrl::dsm`]: the device rejects passthrough DSM (runtime deallocate off, whole-device discard by BLKDISCARD).
const DSM_REJECTED: u8 = 1;
/// [`Ctrl::dsm`]: the device accepts passthrough DSM (runtime deallocate on).
const DSM_OK: u8 = 2;

impl Ctrl {
    /// The namespace block node: O_DIRECT IO of every buffer that passthrough must not name (module doc).
    fn block_fd(&self) -> RawFd {
        self.claim.as_ref().unwrap_or(&self.io).as_raw_fd()
    }

    /// Runtime deallocate (passthrough DSM) is usable: cmd mode and an accepted verdict.
    fn dealloc_ok(&self) -> bool {
        !self.mapped && self.mode == Mode::Cmd && self.dsm.load(Ordering::Acquire) == DSM_OK
    }

    /// Runtime deallocate shape now (the DSM verdict is applied at mount, after the open).
    fn dealloc_limits(&self) -> DeallocLimits {
        self.discard.limits(self.dealloc_ok(), self.geo.lba_size)
    }

    /// Geometry as the store sees it now: `dealloc` follows the verdict, which mount applies after the queues exist.
    fn geometry_now(&self) -> Geometry {
        Geometry {
            dealloc: self.dealloc_ok(),
            ..self.geo
        }
    }
}

/// An opened `kernel:` namespace; hands out per-core queue handles.
#[derive(Clone)]
pub struct KernelCtrl {
    c: Arc<Ctrl>,
}

impl std::fmt::Debug for KernelCtrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KernelCtrl")
            .field("path", &self.c.path)
            .field("mode", &self.c.mode)
            .field("nsid", &self.c.nsid)
            .finish()
    }
}

/// Open `path`; an exclusive open that finds the device busy is retried for up to 2 s (udev probes a namespace briefly after
/// a writer closed it), so only a lasting holder is reported as "in use".
fn open_flags(path: &Path, flags: i32, write: bool) -> std::io::Result<OwnedFd> {
    let mut tries = 0;
    loop {
        let r = std::fs::OpenOptions::new()
            .read(true)
            .write(write)
            .custom_flags(flags | libc::O_CLOEXEC)
            .open(path)
            .map(OwnedFd::from);
        match r {
            Err(e)
                if e.raw_os_error() == Some(libc::EBUSY)
                    && flags & libc::O_EXCL != 0
                    && tries < 40 =>
            {
                tries += 1;
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) if e.raw_os_error() == Some(libc::EBUSY) && flags & libc::O_EXCL != 0 => {
                eprintln!(
                    "WARNING TIMEOUT exclusive open exceeded 2s ({}: still busy after {tries} retries)",
                    path.display()
                );
                return Err(e);
            }
            r => return r,
        }
    }
}

fn busy(path: &Path, e: std::io::Error) -> String {
    if e.raw_os_error() == Some(libc::EBUSY) {
        format!(
            "{}: in use (mounted, partition/holder active, or opened by another OSD or tool)",
            path.display()
        )
    } else {
        format!("{}: {e}", path.display())
    }
}

impl KernelCtrl {
    /// Open exclusively: whole namespaces in direct/cmd mode, or validated linear LVM in direct mode.
    /// Unsupported mapped devices are refused even when the lab fallback is enabled.
    pub fn open(path: &Path) -> Result<KernelCtrl, String> {
        let md = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
        probe_uring(path)?;
        let name = path
            .canonicalize()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_default();
        #[cfg(feature = "lab")]
        if md.file_type().is_file() {
            return Self::lab_file(path);
        }
        let sysroot = Path::new("/sys");
        let (mut mode, blk, disk) = if md.file_type().is_block_device() {
            let disk = path
                .canonicalize()
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                .unwrap_or_default();
            (Mode::Direct, path.to_owned(), disk)
        } else if md.file_type().is_char_device() && name.starts_with("ng") {
            let disk = disk_of_ng(sysroot, &name)?;
            (Mode::Cmd, Path::new("/dev").join(&disk), disk)
        } else {
            return Err(format!(
                "croit-flashstore-osd needs a whole NVMe namespace: {} (/dev/nvmeXnY or /dev/ngXnY)",
                path.display()
            ));
        };
        // the opened node; the block device when cmd mode falls back to direct mode
        let mut path: &Path = path;
        if disk.is_empty() {
            return Err(format!(
                "{}: cannot determine the namespace disk name (canonicalize of the node failed)",
                blk.display()
            ));
        }
        if is_partition(sysroot, &disk) {
            return Err(format!(
                "croit-flashstore-osd needs a whole NVMe namespace: {} is a partition",
                blk.display()
            ));
        }
        if has_partitions(sysroot, &disk) {
            return Err(format!(
                "{}: namespace has partitions (wipe it first)",
                blk.display()
            ));
        }
        let (mut io, mut claim) = match mode {
            Mode::Direct => (
                open_flags(path, libc::O_DIRECT | libc::O_EXCL, true).map_err(|e| busy(path, e))?,
                None,
            ),
            Mode::Cmd => {
                // every buffer outside the registered arena is IO on the block node (module doc): cmd mode needs it
                if !blk.exists() {
                    return Err(format!(
                        "{}: kernel-cmd needs the namespace block node {} as well (claim and O_DIRECT IO of buffers outside \
                         the registered arena; adr 0169 am. 11): pass /dev/{} too (container: --device {} next to --device {})",
                        path.display(),
                        blk.display(),
                        disk,
                        blk.display(),
                        path.display()
                    ));
                }
                let claim = Some(
                    open_flags(&blk, libc::O_DIRECT | libc::O_EXCL, true)
                        .map_err(|e| busy(&blk, e))?,
                );
                (
                    open_flags(path, 0, true).map_err(|e| format!("{}: {e}", path.display()))?,
                    claim,
                )
            }
        };
        if mode == Mode::Direct && linear::is_mapped(&io)? {
            return linear::open(io, path);
        }
        let sys = sysroot.join("class/block").join(&disk);
        crate::kprobe::check_node(claim.as_ref().unwrap_or(&io), &sys, true)?;
        if mode == Mode::Cmd {
            crate::kprobe::check_node(&io, &sysroot.join("class/nvme-generic").join(&name), false)?;
        }
        // SAFETY: plain ioctl without argument on an open fd.
        let nsid = unsafe { libc::ioctl(io.as_raw_fd(), NVME_IOCTL_ID as _) };
        if nsid <= 0 {
            #[cfg(feature = "lab")]
            if mode == Mode::Direct {
                return Self::lab_block(io, path, &disk);
            }
            return Err(format!(
                "croit-flashstore-osd needs a whole NVMe namespace: {} (NVME_IOCTL_ID: {})",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        let nsid = nsid as u32;
        let mut missing = Vec::new();
        let id = match ident_of(io.as_raw_fd(), nsid)? {
            Some(id) => id,
            None => {
                missing.push(MISSING_UNPRIV_PASSTHRU);
                if mode == Mode::Cmd {
                    // passthrough IO is refused like Identify: same namespace through O_DIRECT on its block device
                    eprintln!(
                        "WARNING kernel-cmd {}: this kernel refuses NVMe passthrough to a process without CAP_SYS_ADMIN \
                         (Identify: EACCES): direct mode (O_DIRECT) on {} instead. Fix for cmd mode: a kernel with \
                         unprivileged NVMe passthrough (upstream 6.2+)",
                        path.display(),
                        blk.display()
                    );
                    io = claim.take().expect("cmd mode holds the block node");
                    mode = Mode::Direct;
                    path = &blk;
                }
                sysfs_ident(&sys)?
            }
        };
        if id.data_bytes != LBA || id.meta_bytes != 0 || id.pi != 0 {
            return Err(format!(
                "{}: LBA format {}+{} (lbaf {}, pi {}): the store needs 4096+0 without PI; format it (`nvme format {} --lbaf=<4096+0 index>`) or prepare through spdk:",
                path.display(),
                id.data_bytes,
                id.meta_bytes,
                id.lbaf,
                id.pi,
                blk.display()
            ));
        }
        // both modes write through the block layer (cmd mode: every buffer outside the arena)
        direct_cache_ok(&id, &sys)?;
        let hw = read_sys(sys.join("queue/max_hw_sectors_kb")).and_then(|s| s.parse().ok());
        let dma = read_sys(sys.join("queue/dma_alignment"))
            .and_then(|s| s.parse().ok())
            .unwrap_or(511);
        // opens never send a DSM: the verdict comes from the mkfs probe (see `probe_dsm_at_mkfs`) via the superblock
        if mode == Mode::Cmd {
            let vwc = geometry_of(&id, mode, hw).vwc;
            if !probe_cmd(&io, nsid, vwc, path)? {
                // passthrough without a registered buffer would name plain user addresses (module doc): direct mode
                eprintln!(
                    "WARNING kernel-cmd {}: this kernel lacks fixed-buffer NVMe passthrough (IORING_URING_CMD_FIXED of a \
                     registered-arena span: EINVAL): direct mode (O_DIRECT) on {} instead. Fix for cmd mode: a kernel with \
                     'block: fix sanity checks in blk_rq_map_user_bvec'",
                    path.display(),
                    blk.display()
                );
                missing.push(MISSING_URING_CMD_FIXED);
                io = claim.take().expect("cmd mode holds the block node");
                mode = Mode::Direct;
                path = &blk;
            }
        }
        let tags = blk_tags(&sys);
        let mut discard = Discard::of_sysfs(&sys);
        if discard.hw_bytes > 0 {
            match probe_discard(claim.as_ref().unwrap_or(&io)) {
                Ok(()) => discard.uring = true,
                Err(why) => missing_discard(&mut missing, path, &why),
            }
        }
        let mut ctrl = Self::from_parts(io, claim, mode, nsid, id, hw, dma, path);
        let c = Arc::get_mut(&mut ctrl.c).expect("fresh controller");
        c.missing = missing;
        c.tags = tags;
        c.discard = discard;
        Ok(ctrl)
    }

    #[expect(clippy::too_many_arguments)]
    fn from_parts(
        io: OwnedFd,
        claim: Option<OwnedFd>,
        mode: Mode,
        nsid: u32,
        id: Ident,
        hw: Option<u64>,
        dma_mask: usize,
        path: &Path,
    ) -> KernelCtrl {
        ACTIVE.store(true, Ordering::Relaxed);
        KernelCtrl {
            c: Arc::new(Ctrl {
                dma_mask,
                io,
                claim,
                mode,
                nsid,
                geo: geometry_of(&id, mode, hw),
                id,
                path: path.to_owned(),
                probe_path: path.to_owned(),
                mapped: false,
                missing: Vec::new(),
                dsm: AtomicU8::new(DSM_UNKNOWN),
                tags: 0,
                discard: Discard::default(),
            }),
        }
    }

    /// LAB ONLY: a regular file (O_DIRECT, `flock`ed) as a direct-mode namespace. Volatile cache assumed (DSYNC writes).
    #[cfg(feature = "lab")]
    fn lab_file(path: &Path) -> Result<KernelCtrl, String> {
        let err = |e: std::io::Error| format!("{}: {e}", path.display());
        let io = open_flags(path, libc::O_DIRECT, true).map_err(err)?;
        // SAFETY: plain syscall on an open fd.
        if unsafe { libc::flock(io.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(format!(
                "{}: in use by another process (running OSD or tool)",
                path.display()
            ));
        }
        let len = std::fs::metadata(path).map_err(err)?.len();
        let id = Ident {
            nsze: len / u64::from(LBA),
            data_bytes: LBA,
            awupf: 1,
            awun: 1,
            vwc: true,
            write_zeroes: true,
            ..Ident::default()
        };
        if id.nsze == 0 {
            return Err(format!("{}: smaller than one block", path.display()));
        }
        Ok(Self::from_parts(
            io,
            None,
            Mode::Direct,
            1,
            id,
            None,
            4095,
            path,
        ))
    }

    /// LAB ONLY: a non-NVMe block device (loop, null_blk) in direct mode: size and block size from the kernel, volatile
    /// cache per sysfs `write_cache`.
    #[cfg(feature = "lab")]
    fn lab_block(io: OwnedFd, path: &Path, disk: &str) -> Result<KernelCtrl, String> {
        const BLKSSZGET: u64 = 0x1268;
        const BLKGETSIZE64: u64 = 0x8008_1272;
        let (mut lbs, mut bytes) = (0i32, 0u64);
        // SAFETY: both ioctls write one integer of the given type.
        let ok = unsafe {
            libc::ioctl(io.as_raw_fd(), BLKSSZGET as _, &mut lbs) == 0
                && libc::ioctl(io.as_raw_fd(), BLKGETSIZE64 as _, &mut bytes) == 0
        };
        if !ok || lbs as u32 != LBA {
            return Err(format!(
                "{}: lab block device needs 4096-byte logical blocks (got {lbs})",
                path.display()
            ));
        }
        let vwc = read_sys(
            Path::new("/sys/class/block")
                .join(disk)
                .join("queue/write_cache"),
        )
        .is_none_or(|s| s != "write through");
        let id = Ident {
            nsze: bytes / u64::from(LBA),
            data_bytes: LBA,
            awupf: 1,
            awun: 1,
            vwc,
            write_zeroes: true,
            ..Ident::default()
        };
        let mut discard = Discard::of_sysfs(&Path::new("/sys/class/block").join(disk));
        discard.uring = discard.hw_bytes > 0 && probe_discard(&io).is_ok();
        let mut ctrl = Self::from_parts(io, None, Mode::Direct, 1, id, None, 4095, path);
        Arc::get_mut(&mut ctrl.c).expect("fresh controller").discard = discard;
        Ok(ctrl)
    }

    /// TEST ONLY: a regular file (O_DIRECT) as a direct-mode namespace of `bytes` (no identify, no claim).
    #[doc(hidden)]
    pub fn open_file_for_test(path: &Path, bytes: u64) -> std::io::Result<KernelCtrl> {
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .custom_flags(libc::O_DIRECT | libc::O_CLOEXEC)
            .open(path)?;
        f.set_len(bytes)?;
        let id = Ident {
            nsze: bytes / u64::from(LBA),
            data_bytes: LBA,
            awupf: 1,
            awun: 1,
            ..Ident::default()
        };
        Ok(Self::from_parts(
            f.into(),
            None,
            Mode::Direct,
            1,
            id,
            None,
            3,
            path,
        ))
    }

    pub fn geometry(&self) -> Geometry {
        self.c.geometry_now()
    }
    pub fn mode(&self) -> Mode {
        self.c.mode
    }
    pub fn nsid(&self) -> u32 {
        self.c.nsid
    }
    pub fn path(&self) -> &Path {
        &self.c.path
    }
    /// Read-only Identify/SMART path; mapped data I/O must never use this path.
    pub fn probe_path(&self) -> &Path {
        &self.c.probe_path
    }
    /// blk-mq tags per hardware queue (sysfs `queue/nr_requests`; 0 = unknown): bound of every queue's depth.
    pub fn tags(&self) -> u32 {
        self.c.tags
    }
    /// Capabilities this kernel lacks for the device, each with its tested fallback (`MISSING_*`). Passthrough DSM is
    /// listed once the mkfs probe rejected it.
    pub fn missing(&self) -> Vec<&'static str> {
        let mut m = self.c.missing.clone();
        if self.c.mode == Mode::Cmd
            && self.c.id.dsm
            && self.c.dsm.load(Ordering::Acquire) == DSM_REJECTED
        {
            m.push(MISSING_PASSTHRU_DSM);
        }
        m
    }

    /// Store mount: apply the superblock's DSM verdict (`FEAT_DSM_VERDICT`). `None` = the store carries no verdict
    /// (formatted before the mkfs probe): a cmd namespace then runs without runtime deallocate and
    /// logs one loud line. Other modes ignore the verdict.
    pub fn apply_dsm_verdict(&self, v: Option<bool>) {
        let c = &*self.c;
        if c.mapped || c.mode != Mode::Cmd || !c.id.dsm {
            return;
        }
        match v {
            Some(v) => c
                .dsm
                .store(if v { DSM_OK } else { DSM_REJECTED }, Ordering::Release),
            None => eprintln!(
                "WARNING kernel-cmd {}: DSM verdict unknown (store formatted before the mkfs DSM probe): \
                 no passthrough deallocate (trims use the block node if the kernel has it, `store: trim=` line); \
                 re-prepare the OSD for passthrough DSM",
                c.path.display()
            ),
        }
    }

    /// mkfs only, before its whole-namespace deallocate (`--no-discard` skips that, never this probe): probes passthrough DSM
    /// in the production shape (deallocate attribute set) over LBA 0..8, which mkfs deallocates anyway, so the probe cannot harm data. Sets the runtime
    /// verdict and returns it for the superblock; `None` = not a cmd namespace. Opens never call this (adr 0169 am. 8).
    pub fn probe_dsm_at_mkfs(&self) -> Result<Option<bool>, String> {
        let c = &*self.c;
        if c.mapped {
            return Err("namespace DSM probe is forbidden for mapped storage".into());
        }
        if c.mode != Mode::Cmd {
            return Ok(None);
        }
        let path = c.path.as_path();
        let err = |e: String| format!("{}: kernel-cmd DSM probe: {e}", path.display());
        let usable = if c.id.dsm {
            let (mut ring, registered) = probe_ring(path)?;
            let mut r = KBuf::new_uninit(4096);
            r.copy_from_slice(&dsm_range(0, 8));
            let cmd = UringCmd {
                opcode: NVM_DSM,
                nsid: c.nsid,
                addr: r.ptr as u64,
                data_len: 16,
                cdw11: DSM_AD,
                ..UringCmd::default()
            };
            // passthrough names only registered-arena buffers (module doc)
            if !(registered && r.fixed()) {
                return Err(err(
                    "the DSM range buffer is outside the registered arena (arena exhausted or not registered)".into(),
                ));
            }
            let res = match cmd_once(&mut ring, &c.io, cmd, true) {
                Ok(res) => res,
                Err(e) => {
                    // the command may still be in flight (wait bound passed): its arena span is never handed out again
                    std::mem::forget(r);
                    return Err(err(e));
                }
            };
            let ok = dsm_verdict(res).map_err(err)?;
            if !ok {
                eprintln!(
                    "WARNING kernel-cmd {}: the device rejects NVMe passthrough DSM ({:?}; the kernel's own discard is not \
                     affected): runtime deallocate off, whole-device discard through BLKDISCARD",
                    path.display(),
                    cmd_err(res)
                );
            }
            ok
        } else {
            // no DSM in the Identify controller data: nothing to probe, the discard stays BLKDISCARD
            false
        };
        c.dsm.store(
            if usable { DSM_OK } else { DSM_REJECTED },
            Ordering::Release,
        );
        Ok(Some(usable))
    }

    /// New queue handle of `depth` slots (bound to the device ring of the thread that first submits on it), at most the
    /// namespace's blk-mq tag count ([`Self::tags`]) so inline issue rarely runs out of tags.
    pub fn open_queue(&self, depth: u32) -> KernelDev {
        let depth = queue_depth(depth, self.c.tags);
        KernelDev {
            c: self.c.clone(),
            geo: self.c.geo,
            slots: (0..depth).map(|_| None).collect(),
            free: (0..depth).rev().collect(),
            ring: std::ptr::null_mut(),
            ring_id: 0,
            qid: 0,
            home: None,
            dead: crate::DeadLatch::default(),
            failure_logged: false,
            view_refusal_logged: false,
        }
    }
}

/// blk-mq tags per hardware queue of the disk at `sys` (`/sys/class/block/<disk>`, `queue/nr_requests`; 0 = unknown).
/// A native-multipath head is bio-based and has none: the smallest count of its hidden path disks (`nvmeXcCnY` siblings,
/// [`head_name`]).
fn blk_tags(sys: &Path) -> u32 {
    let tags = |d: &Path| read_sys(d.join("queue/nr_requests")).and_then(|s| s.parse::<u32>().ok());
    tags(sys)
        .or_else(|| {
            let disk = sys.file_name()?.to_str()?;
            std::fs::read_dir(sys.parent()?)
                .ok()?
                .filter_map(|e| {
                    let e = e.ok()?;
                    let name = e.file_name();
                    let name = name.to_str()?;
                    (name != disk && head_name(name) == disk).then(|| tags(&e.path()))?
                })
                .min()
        })
        .unwrap_or(0)
}

/// Slots of a queue asked for `want` on a namespace with `tags` blk-mq tags per hardware queue (0 = unknown).
fn queue_depth(want: u32, tags: u32) -> u32 {
    let cap = if tags == 0 {
        RING_CQ / 4
    } else {
        tags.min(RING_CQ / 4)
    };
    want.min(cap).max(2)
}

// ------------------------------------------------------------------------------------------------ buffers

/// Registered buffer arena (fixed buffer 0 of every device ring). `None` = disabled or mapping failed.
struct Arena {
    base: usize,
    len: usize,
    next: AtomicUsize,
    huge: bool,
}

static ARENA: OnceLock<Option<Arena>> = OnceLock::new();
/// Size of the registered buffer arena.
const ARENA_LEN: usize = 512 << 20;
/// Arena slice a thread carves its buffers from.
const CHUNK: usize = 2 << 20;

fn arena() -> Option<&'static Arena> {
    ARENA
        .get_or_init(|| {
            let len = ARENA_LEN;
            let prot = libc::PROT_READ | libc::PROT_WRITE;
            let fl = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE;
            for huge in [true, false] {
                let f = if huge { fl | libc::MAP_HUGETLB } else { fl };
                // SAFETY: anonymous mapping, never unmapped (process lifetime).
                let p = unsafe { libc::mmap(std::ptr::null_mut(), len, prot, f, -1, 0) };
                if p != libc::MAP_FAILED {
                    return Some(Arena {
                        base: p as usize,
                        len,
                        next: AtomicUsize::new(0),
                        huge,
                    });
                }
            }
            None
        })
        .as_ref()
}

/// `(addr, len)` of the buffer arena (mapped for the life of the process; created here if not yet used), for an RDMA device
/// to register once: read buffers sent as reply data by reference live there. `None` = not mappable.
pub fn arena_range() -> Option<(u64, u64)> {
    arena().map(|a| (a.base as u64, a.len as u64))
}

/// Arena state for logs: (MiB, hugepages, MiB carved so far).
pub fn arena_info() -> Option<(usize, bool, usize)> {
    arena().map(|a| {
        (
            a.len >> 20,
            a.huge,
            a.next.load(Ordering::Relaxed).min(a.len) >> 20,
        )
    })
}

/// Pooled sizes: 1..=MAX_POOL_BLK whole 4 KiB blocks (exact-size bins, per thread; 16 MiB covers 4 MiB objects + EC
/// chunks: a large buffer from the heap would page-fault on every IO).
const MAX_POOL_BLK: usize = 4096;
/// Heap (non-arena) bytes kept pooled per thread.
const HEAP_POOL_CAP: usize = 64 << 20;

struct Pool {
    /// Arena buffers: (address, initialized).
    bins: Vec<Vec<(usize, bool)>>,
    /// Heap buffers (arena exhausted, or [`KBuf::new_heap_uninit`]): (address, initialized), `heap_bytes` in total.
    hbins: Vec<Vec<(usize, bool)>>,
    heap_bytes: usize,
    cur: usize,
    end: usize,
    /// This thread's return inbox ([`RETURNS`]); `None` = none left (its buffers are pooled by their droppers).
    owner: Option<u16>,
}

impl Drop for Pool {
    fn drop(&mut self) {
        for (class, bin) in self.hbins.iter_mut().enumerate() {
            for (addr, _) in bin.drain(..) {
                // SAFETY: pooled heap buffers have no remaining user or IO owner;
                // bins retain the exact allocation length in 4 KiB blocks.
                unsafe { std::alloc::dealloc(addr as *mut u8, heap_layout(class * 4096)) };
            }
        }
        // the thread ends: refuse further returns (arena memory is never freed: what was parked is simply lost; parked heap
        // buffers are freed)
        if let Some(o) = self.owner {
            for (a, key) in RETURNS.retire(o) {
                if key & HEAP_KEY != 0 && key & CACHE_KEY == 0 {
                    // SAFETY: a heap buffer of its class size (`heap_alloc`), returned by its last user and referenced by no one.
                    unsafe {
                        std::alloc::dealloc(a as *mut u8, heap_layout((key & !HEAP_KEY) * 4096))
                    };
                }
            }
        }
    }
}

impl Pool {
    /// A pooled heap buffer of class `c` (`len` bytes).
    fn take_heap(&mut self, c: usize, len: usize) -> Option<(usize, bool)> {
        let got = self.hbins[c].pop()?;
        self.heap_bytes -= len;
        Some(got)
    }

    /// Take over a block parked in this thread's [`RETURNS`] inbox: an arena buffer goes to its bin, a heap buffer to its heap
    /// bin up to [`HEAP_POOL_CAP`] (else freed).
    fn adopt_plain(&mut self, a: usize, key: usize) {
        if key & HEAP_KEY == 0 {
            self.bins[key].push((a, true));
            return;
        }
        let c = key & !HEAP_KEY;
        let len = c * 4096;
        if self.heap_bytes + len <= HEAP_POOL_CAP {
            self.heap_bytes += len;
            self.hbins[c].push((a, true));
        } else {
            // SAFETY: a heap buffer of `len` bytes (`heap_alloc`), no longer referenced by anyone.
            unsafe { std::alloc::dealloc(a as *mut u8, heap_layout(len)) };
        }
    }
}

thread_local! {
    static POOL: RefCell<Pool> = RefCell::new(Pool {
        bins: vec![Vec::new(); MAX_POOL_BLK + 1],
        hbins: vec![Vec::new(); MAX_POOL_BLK + 1],
        heap_bytes: 0,
        cur: 0,
        end: 0,
        owner: crate::shelf::my_owner(),
    });
}

// ------------------------------------------------------------------------------------------------ cache region

/// Cache region chunk: mapped and registered as one unit.
const CACHE_CHUNK: usize = 2 << 20;
/// Registered chunks per ring (sparse table slots 1..=CACHE_SLOTS; slot 0 = the arena): 16 GiB of data cache per core
/// through fixed buffers, beyond that reads are plain block-node reads.
const CACHE_SLOTS: u32 = 8192;
/// Flag of a [`RETURNS`] key of a cache buffer (`CACHE_KEY | slot << 16 | class`); arena keys are the bare class.
const CACHE_KEY: usize = 1 << 40;
/// Flag of a [`RETURNS`] key of a heap buffer (`HEAP_KEY | class`): plain memory read buffers (reads above a quarter cache chunk,
/// e.g. 4 MiB objects) go home like arena ones, so the allocating core reuses its already faulted pages. A returned heap buffer is
/// adopted (and checked against [`HEAP_POOL_CAP`]) on its owner's next allocation, so a core that stops reading keeps at most its
/// peak in-flight reads parked until then; a thread that ends frees what is parked ([`Pool`] drop).
const HEAP_KEY: usize = 1 << 41;
/// Write stride of [`CacheRegion::populate_next`]: the smallest page size (one write per page on 4 KiB-page kernels, a few
/// redundant writes per page on larger ones).
const TOUCH: usize = 4096;
/// Live chunks (all threads) and reads that fell back to plain memory (`perf dump`, [`pool_counters`]).
static CACHE_CHUNKS: AtomicU64 = AtomicU64::new(0);
static CACHE_HEAP: AtomicU64 = AtomicU64::new(0);

/// Map one cache chunk (anonymous, private, read-write). Opted out of transparent huge pages: with THP `always` the first
/// write into the 2 MiB-aligned chunk would fault and zero all of it at once, which [`CacheRegion::populate_next`] spreads
/// page by page (the advice fails harmlessly on kernels without THP: their pages are 4 KiB anyway). `None` = mmap failed
/// (errno kept).
fn map_chunk() -> Option<usize> {
    // SAFETY: anonymous mapping; it becomes a chunk (unmapped by `release_idle` only after it was unregistered and has no
    // live buffer) or stays mapped until the process ends.
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            CACHE_CHUNK,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        return None;
    }
    // SAFETY: advice on the mapping above.
    unsafe { libc::madvise(p, CACHE_CHUNK, libc::MADV_NOHUGEPAGE) };
    Some(p as usize)
}

struct CacheChunk {
    base: usize,
    /// Bump offset of the next fresh buffer.
    used: usize,
    /// Buffers handed out and not yet back (a buffer parked in [`RETURNS`] is still live).
    live: u32,
}

/// This thread's registered memory for data-cache reads. Buffers are carved bump-style from the current chunk and reused by
/// exact size after they are freed; a chunk other than the current one with no live buffer is unregistered and unmapped by
/// [`CacheRegion::release_idle`] (called after the cache evicted). One thread, one ring: no locks. Memory of a buffer
/// that is dropped where nobody can free it (its thread is gone) stays mapped until the process ends.
///
/// Growth never faults a chunk in on the op path (doc/perf/r4k-tail-20261102.md): registering pins every page, and pinning
/// a fresh anonymous chunk faults and zeroes all 512 pages in one ~0.6 ms stall of the read that needed the room (1 of 512
/// 4 KiB cache reads while the cache grows). The chunk after the current one ([`CacheRegion::next`]) is mapped ahead in
/// 4 KiB pages ([`map_chunk`]) and written page by page while the current one is carved, so growth registers resident
/// pages; the faults are spread over the carving allocations like a heap's. Only a thread's first chunk is faulted in by
/// its registration.
struct CacheRegion {
    /// Ring the chunks are registered on (0 = none yet).
    ring: u64,
    /// Index = slot - 1.
    chunks: Vec<Option<CacheChunk>>,
    /// Free buffers by class: (address, slot, initialized).
    bins: Vec<Vec<(usize, u16, bool)>>,
    cur: Option<usize>,
    /// Chunks other than `cur` with no live buffer.
    idle: usize,
    /// A registration call failed: the region takes no more chunks (loud once).
    off: bool,
    /// The chunk the next growth registers: (base, bytes populated). Mapped when the current chunk is first carved and
    /// populated two pages per carved page ([`CacheRegion::populate_next`]): resident once the current chunk is half
    /// carved, before any allocation (at most a quarter chunk) can overflow it.
    next: Option<(usize, usize)>,
}

thread_local! {
    static CACHE: RefCell<CacheRegion> = const { RefCell::new(CacheRegion {
        ring: 0,
        chunks: Vec::new(),
        bins: Vec::new(),
        cur: None,
        idle: 0,
        off: false,
        next: None,
    }) };
}

impl CacheRegion {
    fn alloc(
        &mut self,
        len: usize,
        class: usize,
        owner: u16,
        ring: &KRing,
    ) -> Option<(usize, u16, bool)> {
        // read buffers of this core that went out as reply data and were dropped on another core
        for (a, key) in RETURNS.take_all(owner) {
            if key & CACHE_KEY != 0 {
                self.put(((key >> 16) & 0xffff) as u16, a, key & 0xffff, true);
            } else {
                let _ = POOL.try_with(|p| p.borrow_mut().adopt_plain(a, key));
            }
        }
        if self.ring == 0 {
            self.ring = ring.id;
            self.bins = vec![Vec::new(); MAX_POOL_BLK + 1];
        }
        debug_assert_eq!(self.ring, ring.id, "one cache region per thread ring");
        if let Some((a, slot, init)) = self.bins.get_mut(class).and_then(Vec::pop) {
            self.take(slot);
            return Some((a, slot, init));
        }
        if let Some(i) = self.cur
            && let Some(c) = self.chunks[i].as_mut()
            && c.used + len <= CACHE_CHUNK
        {
            let a = c.base + c.used;
            c.used += len;
            c.live += 1;
            let used = c.used;
            self.populate_next(used);
            return Some((a, i as u16 + 1, false));
        }
        let i = self.grow(ring)?;
        let c = self.chunks[i].as_mut().expect("new chunk");
        c.used = len;
        c.live = 1;
        let base = c.base;
        self.populate_next(len);
        Some((base, i as u16 + 1, false))
    }

    /// The current chunk is carved up to `used` bytes: map the next chunk if there is none and write its pages up to
    /// `2 * used` (one write per [`TOUCH`] stride faults a zeroed page in; the value written is the page's content
    /// already). A failed map leaves `next` empty: the growth then maps and faults its chunk itself.
    fn populate_next(&mut self, used: usize) {
        if self.off {
            return;
        }
        let (base, done) = match self.next {
            Some(n) => n,
            None => match map_chunk() {
                Some(p) => (p, 0),
                None => return,
            },
        };
        let want = (2 * used).min(CACHE_CHUNK);
        let mut at = done;
        while at < want {
            // SAFETY: inside the mapped, writable, not yet registered chunk; nothing else references its bytes.
            unsafe { std::ptr::write_volatile((base + at) as *mut u8, 0) };
            at += TOUCH;
        }
        self.next = Some((base, at));
    }

    /// Map and register a new chunk, make it current. `None` = the region cannot take one (reads go to plain memory).
    fn grow(&mut self, ring: &KRing) -> Option<usize> {
        if self.off {
            return None;
        }
        let i = match self.chunks.iter().position(Option::is_none) {
            Some(i) => i,
            None if (self.chunks.len() as u32) < ring.cache_slots => {
                self.chunks.push(None);
                self.chunks.len() - 1
            }
            None => return None,
        };
        // the populated next chunk, else (a thread's first chunk, a failed map) a fresh mapping its registration faults in
        let Some(p) = self.next.take().map(|(base, _)| base).or_else(map_chunk) else {
            self.off = true;
            eprintln!(
                "WARNING kernel store: data-cache chunk mmap failed ({}): cache reads use plain memory",
                std::io::Error::last_os_error()
            );
            return None;
        };
        let iov = libc::iovec {
            iov_base: p as *mut libc::c_void,
            iov_len: CACHE_CHUNK,
        };
        // SAFETY: the chunk stays mapped until it is unregistered again.
        if let Err(e) = unsafe {
            ring.ring
                .submitter()
                .register_buffers_update(i as u32 + 1, &[iov], None)
        } {
            self.off = true;
            eprintln!(
                "WARNING kernel store: registering a data-cache chunk failed ({e}): cache reads use plain memory"
            );
            // SAFETY: just mapped, never registered.
            unsafe { libc::munmap(p as *mut libc::c_void, CACHE_CHUNK) };
            return None;
        }
        if let Some(o) = self.cur
            && self.chunks[o].as_ref().is_some_and(|c| c.live == 0)
        {
            self.idle += 1;
        }
        self.chunks[i] = Some(CacheChunk {
            base: p,
            used: 0,
            live: 0,
        });
        self.cur = Some(i);
        CACHE_CHUNKS.fetch_add(1, Ordering::Relaxed);
        Some(i)
    }

    /// A buffer of `slot` leaves the free list.
    fn take(&mut self, slot: u16) {
        let i = slot as usize - 1;
        let c = self.chunks[i].as_mut().expect("live chunk");
        if c.live == 0 && self.cur != Some(i) {
            self.idle -= 1;
        }
        c.live += 1;
    }

    /// A buffer of `slot` is free again.
    fn put(&mut self, slot: u16, addr: usize, class: usize, init: bool) {
        let i = slot as usize - 1;
        self.bins[class].push((addr, slot, init));
        let c = self.chunks[i].as_mut().expect("live chunk");
        c.live -= 1;
        if c.live == 0 && self.cur != Some(i) {
            self.idle += 1;
        }
    }

    /// Unregister and unmap every chunk (not the current one) without a live buffer.
    fn release_idle(&mut self, ring: &KRing) {
        if self.idle == 0 {
            return;
        }
        let dead: Vec<usize> = (0..self.chunks.len())
            .filter(|&i| {
                self.cur != Some(i) && self.chunks[i].as_ref().is_some_and(|c| c.live == 0)
            })
            .collect();
        self.idle = 0;
        let empty = libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        };
        for &i in &dead {
            // SAFETY: clearing a slot of the ring this region registered on.
            if let Err(e) = unsafe {
                ring.ring
                    .submitter()
                    .register_buffers_update(i as u32 + 1, &[empty], None)
            } {
                self.off = true;
                eprintln!(
                    "WARNING kernel store: unregistering a data-cache chunk failed ({e}): the chunk stays mapped"
                );
                continue;
            }
            let c = self.chunks[i].take().expect("dead chunk");
            let (lo, hi) = (c.base, c.base + CACHE_CHUNK);
            for b in &mut self.bins {
                b.retain(|&(a, _, _)| a < lo || a >= hi);
            }
            // SAFETY: unregistered, no live buffer, no free-list entry points into it.
            unsafe { libc::munmap(c.base as *mut libc::c_void, CACHE_CHUNK) };
            CACHE_CHUNKS.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// A returned cache buffer reaches its owner (the allocating thread): back on the free list.
fn cache_adopt(addr: usize, key: usize) {
    let _ = CACHE.try_with(|c| {
        c.borrow_mut()
            .put(((key >> 16) & 0xffff) as u16, addr, key & 0xffff, true)
    });
}

/// Drop of a cache buffer: on its own thread back on the free list, anywhere else back to the owner's inbox.
fn cache_free(b: &KBuf, slot: u16, ring: u64) {
    let Some(class) = pool_class(b.len) else {
        return;
    };
    let (addr, init) = (b.ptr as usize, b.initialized.get());
    let local = CACHE
        .try_with(|c| {
            let mut c = c.borrow_mut();
            let mine = c.ring == ring;
            if mine {
                c.put(slot, addr, class, init);
            }
            mine
        })
        .unwrap_or(false);
    if !local && let Some(o) = b.owner {
        // refused (owner gone): the memory stays mapped in its chunk until the process ends
        RETURNS.put(o, addr, CACHE_KEY | (slot as usize) << 16 | class);
    }
}

fn pool_class(len: usize) -> Option<usize> {
    crate::block_class(len, MAX_POOL_BLK)
}

/// The `/proc/self/maps` lines (`start-end perms path`) overlapping `[addr, addr + len)`, `unmapped` where none covers a
/// byte of it (failure diagnostics only: reads the whole maps file).
fn mappings_of(addr: usize, len: usize) -> String {
    match std::fs::read_to_string("/proc/self/maps") {
        Ok(maps) => mappings_in(&maps, addr, len),
        Err(_) => "?".into(),
    }
}

/// [`mappings_of`] over the text of a maps file.
fn mappings_in(maps: &str, addr: usize, len: usize) -> String {
    let end = addr.saturating_add(len);
    let (mut out, mut covered) = (Vec::new(), addr);
    for line in maps.lines() {
        let mut f = line.split_ascii_whitespace();
        let (Some(range), Some(perms)) = (f.next(), f.next()) else {
            continue;
        };
        let Some((s, e)) = range.split_once('-') else {
            continue;
        };
        let (Ok(s), Ok(e)) = (usize::from_str_radix(s, 16), usize::from_str_radix(e, 16)) else {
            continue;
        };
        if e <= addr || s >= end {
            continue;
        }
        if s > covered {
            out.push(format!("unmapped {covered:#x}-{s:#x}"));
        }
        covered = covered.max(e);
        let path = f.nth(3).unwrap_or("[anon]");
        out.push(format!("{s:#x}-{e:#x} {perms} {path}"));
    }
    if covered < end {
        out.push(format!("unmapped {covered:#x}-{end:#x}"));
    }
    out.join("; ")
}

fn heap_layout(len: usize) -> std::alloc::Layout {
    std::alloc::Layout::from_size_align(len.max(1), 4096).expect("buffer layout")
}

#[derive(Debug)]
enum Kind {
    Arena,
    Heap,
    /// Data-cache read buffer inside a registered chunk of the allocating thread's [`CacheRegion`]: `slot` = its
    /// fixed-buffer index on the ring `ring`.
    Cache {
        slot: u16,
        ring: u64,
    },
    /// Zero-copy write view of an immutable payload (adr 0061 am. 4).
    View {
        _payload: bytes::Bytes,
        /// Payload crc and registry entry (debug and `viewguard` builds; a no-op otherwise): rechecked at the completion, a
        /// change = the bytes under a live view were reused while the device read them ([`KBuf::check_view`]).
        guard: crate::viewguard::ViewGuard,
    },
}

impl Kind {
    fn name(&self) -> &'static str {
        match self {
            Kind::Arena => "arena",
            Kind::Heap => "heap",
            Kind::Cache { .. } => "cache",
            Kind::View { .. } => "view",
        }
    }
}

/// IO buffer of a `kernel:` device: 4 KiB aligned, from the registered arena when possible.
pub struct KBuf {
    ptr: *mut u8,
    len: usize,
    initialized: Cell<bool>,
    kind: Kind,
    /// Return inbox of the thread that allocated the buffer ([`RETURNS`]).
    owner: Option<u16>,
}

/// Shape only: a `Kind::View` holds the whole payload as `bytes::Bytes`, whose `Debug` would print every byte (a
/// completion of a 128 MiB write view would dump it into the log).
impl std::fmt::Debug for KBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KBuf")
            .field("ptr", &self.ptr)
            .field("len", &self.len)
            .field("kind", &self.kind.name())
            .field("owner", &self.owner)
            .finish()
    }
}

// Moved between threads with its owner (a queue handle / store, or the `Bytes` of `into_shared`); never shared mutably.
unsafe impl Send for KBuf {}

/// Arena buffers that left their core as shared read data ([`IoBuf::into_shared`]) go back to the thread that allocated
/// them (its inbox, keyed by bin = blocks), on whatever core the last reference drops. Arena memory is never freed and
/// the arena itself is bounded, so nothing needs a cap: an inbox only moves memory between cores. A push to a retired
/// owner is refused (`kreturn_refused`) and the buffer's own drop pools it on the dropping thread: nothing is lost.
static RETURNS: crate::shelf::Returns = crate::shelf::Returns::new();

/// Return counters for `perf dump` (logger `flashstore_dma_pool`): `kreturn_hits` (shared read buffers taken back by the
/// core that allocated them), `kreturn_refused` (owner gone: the dropping thread pools the buffer, nothing is lost),
/// `kcache_chunks` (registered data-cache chunks of all cores, 2 MiB each), `kcache_heap` (cache reads that got plain
/// memory because the cache region could not take them: block-node reads).
pub fn pool_counters() -> Vec<(String, u64)> {
    let (hits, refused) = RETURNS.stats();
    vec![
        ("kreturn_hits".to_owned(), hits),
        ("kreturn_refused".to_owned(), refused),
        (
            "kcache_chunks".to_owned(),
            CACHE_CHUNKS.load(Ordering::Relaxed),
        ),
        ("kcache_heap".to_owned(), CACHE_HEAP.load(Ordering::Relaxed)),
    ]
}

/// A filled buffer owned by a `Bytes` ([`IoBuf::into_shared`]). An arena buffer goes back to its allocating thread
/// ([`RETURNS`]) when the last reference drops (the arena is bump-only: a buffer left in a foreign thread's pool is lost to
/// the thread that reads); anything else drops as usual.
struct SharedK(std::mem::ManuallyDrop<KBuf>);

impl AsRef<[u8]> for SharedK {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Drop for SharedK {
    fn drop(&mut self) {
        let b = &*self.0;
        crate::unpin(b.len);
        let key = match b.kind {
            Kind::Arena => pool_class(b.len),
            Kind::Heap => pool_class(b.len).map(|c| HEAP_KEY | c),
            _ => None,
        };
        if let Some(key) = key
            && let Some(owner) = b.owner
            && RETURNS.put(owner, b.ptr as usize, key)
        {
            return; // on its way home: the memory stays out of every pool until its owner adopts it
        }
        // SAFETY: dropped exactly once, here; not touched afterwards.
        unsafe { std::mem::ManuallyDrop::drop(&mut self.0) };
    }
}

impl KBuf {
    /// Zeroed buffer.
    pub fn new(len: usize) -> KBuf {
        let b = Self::new_uninit(len);
        // SAFETY: the buffer owns `len` bytes.
        unsafe { std::ptr::write_bytes(b.ptr, 0, len) };
        b.initialized.set(true);
        b
    }

    /// Buffer with unspecified contents: arena bin, else carved from the arena, else heap bin, else 4 KiB aligned heap.
    pub fn new_uninit(len: usize) -> KBuf {
        if let Some(c) = pool_class(len) {
            let mut owner = None;
            let got = POOL
                .try_with(|p| {
                    let mut p = p.borrow_mut();
                    owner = p.owner;
                    // read buffers of this core that went out as reply data and were dropped on another core
                    if let Some(o) = p.owner {
                        for (a, key) in RETURNS.take_all(o) {
                            if key & CACHE_KEY != 0 {
                                cache_adopt(a, key);
                            } else {
                                p.adopt_plain(a, key);
                            }
                        }
                    }
                    if let Some((a, init)) = p.bins[c].pop() {
                        return Some((a, init, true));
                    }
                    if let Some(a) = arena() {
                        if len > CHUNK / 4 {
                            // large: straight from the arena (a chunk would waste its tail)
                            let off = a.next.fetch_add(len, Ordering::Relaxed);
                            if off + len <= a.len {
                                return Some((a.base + off, false, true));
                            }
                        } else if p.cur + len <= p.end {
                            let addr = p.cur;
                            p.cur += len;
                            return Some((addr, false, true));
                        } else {
                            let off = a.next.fetch_add(CHUNK, Ordering::Relaxed);
                            if off + CHUNK <= a.len {
                                p.cur = a.base + off + len;
                                p.end = a.base + off + CHUNK;
                                return Some((a.base + off, false, true));
                            }
                        }
                    }
                    p.take_heap(c, len).map(|(a, init)| (a, init, false))
                })
                .ok()
                .flatten();
            if let Some((a, init, ar)) = got {
                return KBuf {
                    ptr: a as *mut u8,
                    len,
                    initialized: Cell::new(init),
                    kind: if ar { Kind::Arena } else { Kind::Heap },
                    owner,
                };
            }
        }
        Self::heap_alloc(len)
    }

    /// Buffer with unspecified contents in ordinary process memory (never the registered arena; heap bin, else 4 KiB
    /// aligned heap, faulted in by its first IO): the fallback of [`KBuf::new_cache_uninit`]. IO on it is plain (block
    /// node, per-IO page pinning instead of a fixed buffer).
    pub fn new_heap_uninit(len: usize) -> KBuf {
        if let Some(c) = pool_class(len)
            && let Some((a, init)) = POOL
                .try_with(|p| {
                    let mut p = p.borrow_mut();
                    // read buffers of this core that went out as reply data and were dropped on another core
                    if let Some(o) = p.owner {
                        for (a, key) in RETURNS.take_all(o) {
                            if key & CACHE_KEY != 0 {
                                cache_adopt(a, key);
                            } else {
                                p.adopt_plain(a, key);
                            }
                        }
                    }
                    p.take_heap(c, len)
                })
                .ok()
                .flatten()
        {
            return KBuf {
                ptr: a as *mut u8,
                len,
                initialized: Cell::new(init),
                kind: Kind::Heap,
                owner: crate::shelf::my_owner(),
            };
        }
        Self::heap_alloc(len)
    }

    /// Buffer with unspecified contents for a read whose bytes stay in the store's data cache (adr 0633): a registered
    /// chunk of this thread's [`CacheRegion`] (fixed-buffer passthrough, no per-IO pinning), memory mapped on demand. When
    /// the region cannot take it (no sparse table on this kernel, all slots used, a read above a quarter chunk, a
    /// registration error) it is [`KBuf::new_heap_uninit`] and its IO a block-node read, counted in `kcache_heap`.
    fn new_cache_uninit(len: usize, ring: &KRing) -> KBuf {
        if ring.cache_slots > 0
            && let Some(class) = pool_class(len)
            && len <= CACHE_CHUNK / 4
            && let Some(owner) = crate::shelf::my_owner()
        {
            let got = CACHE
                .try_with(|c| c.borrow_mut().alloc(len, class, owner, ring))
                .ok()
                .flatten();
            if let Some((addr, slot, init)) = got {
                return KBuf {
                    ptr: addr as *mut u8,
                    len,
                    initialized: Cell::new(init),
                    kind: Kind::Cache {
                        slot,
                        ring: ring.id,
                    },
                    owner: Some(owner),
                };
            }
        }
        CACHE_HEAP.fetch_add(1, Ordering::Relaxed);
        Self::new_heap_uninit(len)
    }

    fn heap_alloc(len: usize) -> KBuf {
        // SAFETY: non-zero size layout; checked for null below.
        let p = unsafe { std::alloc::alloc(heap_layout(len)) };
        assert!(!p.is_null(), "IO buffer allocation of {len} bytes failed");
        KBuf {
            ptr: p,
            len,
            initialized: Cell::new(false),
            kind: Kind::Heap,
            owner: crate::shelf::my_owner(),
        }
    }

    /// Write buffer viewing `data` in place (the queue checks the device's DMA alignment).
    pub fn view(data: &bytes::Bytes) -> Option<KBuf> {
        Some(KBuf {
            ptr: data.as_ptr() as *mut u8,
            len: data.len(),
            initialized: Cell::new(true),
            kind: Kind::View {
                _payload: data.clone(),
                guard: crate::viewguard::ViewGuard::new(data),
            },
            owner: None,
        })
    }

    /// `kind addr%4096 len`, the arena membership and the process mappings of the range for the first-failure log:
    /// where the payload came from, how it is aligned, and whether its memory is still mapped (an errno 14 = the kernel
    /// could not pin it).
    fn describe(&self) -> String {
        let kind = self.kind.name();
        let (a, l) = (self.ptr as usize, self.len);
        let in_arena = ARENA
            .get()
            .and_then(Option::as_ref)
            .is_some_and(|r| a >= r.base && a + l <= r.base + r.len);
        format!(
            "{kind} addr={a:#x} addr%4096={} len={l} in_arena={in_arena} maps={}",
            a % 4096,
            mappings_of(a, l)
        )
    }

    /// Debug and `viewguard` builds: fail-stop when the bytes under a write view changed between the view and its completion
    /// (the payload's memory was reused while the device DMA-read it; the written blocks may differ from the staged
    /// crcs). Production builds: nothing.
    fn check_view(&self, dev: &Path, lba: u64) {
        if let Kind::View { guard, .. } = &self.kind
            // SAFETY: the view's `Bytes` keeps `ptr..ptr + len` alive (that is the invariant checked here).
            && let Some((crc, now)) = unsafe { guard.changed(self.ptr, self.len) }
        {
            eprintln!(
                "ERROR kernel store {}: write view changed under the device: lba {lba} buffer [{}] crc at view {crc:#010x} \
                 at completion {now:#010x}; payload memory reused while in flight, stopping",
                dev.display(),
                self.describe(),
            );
            panic!("kernel store write view changed under the device");
        }
    }

    pub fn is_view(&self) -> bool {
        matches!(self.kind, Kind::View { .. })
    }

    /// Inside the registered arena (usable with fixed-buffer index 0).
    fn fixed(&self) -> bool {
        matches!(self.kind, Kind::Arena)
    }

    /// The fixed-buffer index a command on ring `fx` names for this buffer: the arena on a ring that registered it, a cache
    /// chunk on the ring of its thread; `None` = plain memory (block-node IO).
    fn fixed_index(&self, fx: Fx) -> Option<u16> {
        match self.kind {
            Kind::Arena if fx.arena => Some(0),
            Kind::Cache { slot, ring } if ring == fx.ring => Some(slot),
            _ => None,
        }
    }

    fn assert_owned(&self) {
        assert!(!self.is_view(), "CPU write into a zero-copy payload view");
    }

    fn initialize(&self) {
        if !self.initialized.get() {
            // SAFETY: owns len bytes; no slice was exposed while uninitialized, and no IO is in flight (the device
            // holds the buffer while it is).
            unsafe { std::ptr::write_bytes(self.ptr, 0, self.len) };
            self.initialized.set(true);
        }
    }
}

impl Drop for KBuf {
    fn drop(&mut self) {
        let arena = match &self.kind {
            Kind::Cache { slot, ring } => {
                cache_free(self, *slot, *ring);
                return;
            }
            Kind::View { guard, .. } => {
                // before the payload reference (a field) is released
                guard.release(self.ptr);
                return;
            }
            Kind::Arena => true,
            Kind::Heap => false,
        };
        if let Some(c) = pool_class(self.len) {
            let (len, ptr, init) = (self.len, self.ptr as usize, self.initialized.get());
            let kept = POOL
                .try_with(|p| {
                    let mut p = p.borrow_mut();
                    // arena memory always goes back to a bin (the arena is bump-only); heap up to the cap
                    if arena {
                        p.bins[c].push((ptr, init));
                        true
                    } else if p.heap_bytes + len <= HEAP_POOL_CAP {
                        p.heap_bytes += len;
                        p.hbins[c].push((ptr, init));
                        true
                    } else {
                        false
                    }
                })
                .unwrap_or(false);
            if kept || arena {
                return; // an arena buffer dropped during thread teardown is simply lost
            }
        }
        // SAFETY: allocated by `new_uninit` with this layout.
        unsafe { std::alloc::dealloc(self.ptr, heap_layout(self.len)) };
    }
}

impl IoBuf for KBuf {
    fn len(&self) -> usize {
        self.len
    }
    fn as_slice(&self) -> &[u8] {
        self.initialize();
        // SAFETY: owned or viewed allocation of len initialized bytes.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.assert_owned();
        self.initialize();
        // SAFETY: owned allocation; the &mut borrow excludes aliasing.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
    fn copy_from_slice(&mut self, src: &[u8]) {
        self.assert_owned();
        assert_eq!(self.len, src.len());
        // SAFETY: owned allocation of exactly src.len() bytes.
        unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), self.ptr, self.len) };
        self.initialized.set(true);
    }
    fn copy_from_slice_crc32c(&mut self, src: &[u8], block_bytes: usize, crcs: &mut [u32]) {
        self.assert_owned();
        crate::assert_crc_copy(self.len, src.len(), block_bytes, crcs.len());
        // SAFETY: owned allocation; MaybeUninit never exposes uninitialized bytes.
        let dst = unsafe { std::slice::from_raw_parts_mut(self.ptr.cast(), self.len) };
        for ((s, d), c) in src
            .chunks(block_bytes)
            .zip(dst.chunks_mut(block_bytes))
            .zip(crcs)
        {
            *c = crc::crc32c_copy_dma_uninit(*c, s, d);
        }
        self.initialized.set(true);
    }
    fn copy_from_slices_zero_tail(&mut self, parts: &[&[u8]]) {
        self.assert_owned();
        // SAFETY: the owned allocation of `len` bytes; the callee only writes.
        let dst = unsafe { std::slice::from_raw_parts_mut(self.ptr.cast(), self.len) };
        crate::copy_parts_zero_tail(dst, parts);
        self.initialized.set(true);
    }
    fn into_shared(self) -> bytes::Bytes {
        crate::pin(self.len);
        bytes::Bytes::from_owner(SharedK(std::mem::ManuallyDrop::new(self)))
    }
}

// ------------------------------------------------------------------------------------------------ device ring

static RING_IDS: AtomicU64 = AtomicU64::new(1);

/// Queue ids a handle gave up off its ring's thread (idle migration, idle drop elsewhere). Only the ring's own thread
/// may unregister them (single issuer, [`KRing::release_retired`]); a handle with commands in flight never gives its id
/// back (their completions still name it). Outlives an exited ring: late returns are then simply dropped.
#[derive(Default)]
struct Retired {
    any: AtomicBool,
    qids: Mutex<Vec<u32>>,
}

impl Retired {
    /// Hand queue `q` back to its ring (any thread; cold: migration and teardown only).
    fn give_back(&self, q: u32) {
        self.qids
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(q);
        self.any.store(true, Ordering::Release);
    }
}

/// `io_uring_enter` errors that only mean "reap completions / try again at the next flush".
fn enter_retry_later(e: &std::io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EBUSY | libc::EAGAIN | libc::EINTR)
    )
}

/// Per-thread device ring shared by the thread's queue handles.
struct KRing {
    /// Submission side: one SQE per in-flight command (never the crate's `submission()` on this ring).
    sq: sq::SqOwn,
    ring: IoUring<squeue::Entry128, cqueue::Entry32>,
    id: u64,
    /// The arena is registered as fixed buffer 0.
    fixed_buf: bool,
    /// The one loud line about a ring without fixed buffers refusing runtime deallocate was printed.
    dsm_warned: bool,
    /// Sparse table slots after the arena for data-cache chunks ([`CacheRegion`]); 0 = the kernel has no sparse table.
    cache_slots: u32,
    /// Completions per queue id: (slot, result).
    done: Vec<Vec<(u32, i32)>>,
    free_q: Vec<u32>,
    /// SQEs queued since the last submit.
    pending: u32,
    /// `io_uring_enter` failed with an error that is not "retry later": SQEs may never reach the kernel (latched).
    dead: crate::DeadLatch,
    /// Submit calls / SQEs submitted / reap passes that found CQEs (diagnostics).
    enters: u64,
    sqes: u64,
    /// Queue ids handed back by handles that left this ring.
    retired: Arc<Retired>,
}

thread_local! {
    static RING: UnsafeCell<Option<Box<KRing>>> = const { UnsafeCell::new(None) };
}

impl KRing {
    fn new() -> std::io::Result<KRing> {
        let mut ring = None;
        for single in [true, false] {
            let mut b = IoUring::<squeue::Entry128, cqueue::Entry32>::builder();
            b.setup_cqsize(RING_CQ).setup_clamp().setup_submit_all();
            if single {
                b.setup_single_issuer();
            }
            match b.build(RING_SQ) {
                Ok(r) => {
                    ring = Some(r);
                    break;
                }
                Err(e) if single && e.raw_os_error() == Some(libc::EINVAL) => {}
                Err(e) => return Err(e),
            }
        }
        let ring = ring.expect("ring built");
        ring.submitter().register_files_sparse(2 * MAX_QUEUES)?;
        let (mut fixed_buf, mut cache_slots) = (false, 0);
        if let Some(a) = arena() {
            let iov = libc::iovec {
                iov_base: a.base as *mut libc::c_void,
                iov_len: a.len,
            };
            // sparse table (kernel 5.19+): the arena in slot 0, data-cache chunks added later; else the arena alone
            let sub = ring.submitter();
            // SAFETY: the arena is mapped for the process lifetime.
            if sub.register_buffers_sparse(1 + CACHE_SLOTS).is_ok()
                && unsafe { sub.register_buffers_update(0, &[iov], None) }.is_ok()
            {
                (fixed_buf, cache_slots) = (true, CACHE_SLOTS);
            } else {
                let _ = sub.unregister_buffers();
                // SAFETY: as above.
                fixed_buf = unsafe { sub.register_buffers(&[iov]) }.is_ok();
            }
        }
        Ok(KRing {
            sq: sq::SqOwn::new(&ring)?,
            ring,
            id: RING_IDS.fetch_add(1, Ordering::Relaxed),
            fixed_buf,
            dsm_warned: false,
            cache_slots,
            done: Vec::new(),
            free_q: Vec::new(),
            pending: 0,
            dead: crate::DeadLatch::default(),
            enters: 0,
            sqes: 0,
            retired: Arc::default(),
        })
    }

    fn fx(&self) -> Fx {
        Fx {
            arena: self.fixed_buf,
            ring: self.id,
        }
    }

    fn add_queue(&mut self, fd: RawFd, blk: RawFd) -> std::io::Result<u32> {
        self.release_retired();
        let q = match self.free_q.pop() {
            Some(q) => q,
            None if (self.done.len() as u32) < MAX_QUEUES => {
                self.done.push(Vec::new());
                self.done.len() as u32 - 1
            }
            None => return Err(std::io::Error::other("too many queues on one device ring")),
        };
        let s = self.ring.submitter();
        if let Err(e) = s
            .register_files_update(q, &[fd])
            .and_then(|_| s.register_files_update(MAX_QUEUES + q, &[blk]))
        {
            let _ = s.register_files_update(q, &[-1]);
            self.free_q.push(q);
            return Err(e);
        }
        Ok(q)
    }

    fn drop_queue(&mut self, q: u32) {
        let _ = self.ring.submitter().register_files_update(q, &[-1]);
        let _ = self
            .ring
            .submitter()
            .register_files_update(MAX_QUEUES + q, &[-1]);
        self.done[q as usize].clear();
        self.free_q.push(q);
    }

    /// Unregister the queues handles handed back from other threads ([`Retired`]): their fixed-file slots (and the
    /// exclusive claim they hold) are freed for the next [`Self::add_queue`]. One relaxed load when there are none.
    fn release_retired(&mut self) {
        if !self.retired.any.load(Ordering::Relaxed)
            || !self.retired.any.swap(false, Ordering::Acquire)
        {
            return;
        }
        let qids = std::mem::take(
            &mut *self
                .retired
                .qids
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
        for q in qids {
            self.drop_queue(q);
        }
    }

    /// Queue one command in an SQE of its own (`kdev_sq`; reaping first when every SQE is in flight). `false` = all
    /// SQEs still in flight: the caller retries after a poll (`QueueFull`). Every buffer the SQE points at is owned by
    /// the queue's pending slot until its CQE is reaped.
    fn push(&mut self, e: &squeue::Entry128) -> bool {
        for _ in 0..2 {
            if self.sq.push(e.clone()).is_some() {
                self.pending += 1;
                return true;
            }
            self.flush();
            self.reap();
        }
        false
    }

    fn flush(&mut self) {
        if self.pending == 0 {
            return;
        }
        self.enters += 1;
        self.enter();
    }

    /// `io_uring_enter`. EBUSY/EAGAIN: completions must be reaped first, EINTR: interrupted; the SQEs stay queued for
    /// the next flush. Any other error means the ring cannot submit: latched dead (`is_dead`), loud once.
    fn enter(&mut self) {
        match self.ring.submit() {
            Ok(n) => {
                self.sqes += n as u64;
                self.pending = self.pending.saturating_sub(n as u32);
            }
            Err(e) if enter_retry_later(&e) => {}
            Err(e) => self
                .dead
                .trip("kernel store", format_args!("io_uring_enter failed: {e}")),
        }
    }

    fn reap(&mut self) {
        if self.sq.cq_overflow() {
            self.enter(); // GETEVENTS flushes the kernel's overflow list
        }
        let mut cq = self.ring.completion();
        cq.sync();
        for c in &mut cq {
            // user_data: queue id << 32 | SQE index << 16 | queue slot
            let u = c.user_data();
            self.sq.release(u);
            if let Some(v) = self.done.get_mut((u >> 32) as usize) {
                v.push(((u & 0xffff) as u32, c.result()));
            }
        }
    }
}

/// This thread's device ring (created on first use).
fn thread_ring() -> std::io::Result<*mut KRing> {
    RING.with(|r| {
        // SAFETY: thread-local, never re-entered (no callbacks run while the reference lives).
        let slot = unsafe { &mut *r.get() };
        if slot.is_none() {
            *slot = Some(Box::new(KRing::new()?));
        }
        Ok(&mut **slot.as_mut().expect("ring set") as *mut KRing)
    })
}

fn current_ring_id() -> u64 {
    RING.try_with(|r| {
        // SAFETY: as above.
        unsafe { &*r.get() }.as_ref().map_or(0, |k| k.id)
    })
    .unwrap_or(0)
}

/// Submit this thread's queued device SQEs (the kernel tier calls it at the end of every loop iteration).
#[inline]
pub fn flush() {
    let _ = RING.try_with(|r| {
        // SAFETY: as above.
        if let Some(k) = unsafe { &mut *r.get() }.as_mut() {
            if k.pending != 0 {
                k.flush();
            }
            k.release_retired();
        }
    });
}

/// File descriptor of this thread's device ring (created if needed): readable while it holds completions. The kernel
/// tier polls it in its own ring, so a store completion wakes a sleeping core.
pub fn thread_ring_fd() -> std::io::Result<RawFd> {
    // SAFETY: the ring lives in this thread's TLS until the thread exits.
    thread_ring().map(|p| unsafe { &*p }.ring.as_raw_fd())
}

/// Completions of this thread's device ring that no queue has taken yet (in the CQ or reaped for a queue that has not
/// polled since): a core must not sleep on the ring fd while one waits.
pub fn thread_ready() -> bool {
    RING.try_with(|r| {
        // SAFETY: as above.
        unsafe { &mut *r.get() }.as_mut().is_some_and(|k| {
            k.pending != 0
                || !k.ring.completion().is_empty()
                || k.done.iter().any(|d| !d.is_empty())
        })
    })
    .unwrap_or(false)
}

/// Device ring counters of this thread: (submit syscalls, SQEs submitted).
pub fn thread_stats() -> (u64, u64) {
    RING.try_with(|r| {
        // SAFETY: as above.
        unsafe { &*r.get() }
            .as_ref()
            .map_or((0, 0), |k| (k.enters, k.sqes))
    })
    .unwrap_or((0, 0))
}

// ------------------------------------------------------------------------------------------------ queue

/// One NVMe IO passthrough command (`struct nvme_uring_cmd`, 72 bytes, in the SQE128 command area).
#[derive(Clone, Copy, Default)]
struct UringCmd {
    opcode: u8,
    nsid: u32,
    addr: u64,
    data_len: u32,
    cdw10: u32,
    cdw11: u32,
    cdw12: u32,
}

impl UringCmd {
    fn bytes(&self) -> [u8; 80] {
        let mut b = [0u8; 80];
        b[0] = self.opcode;
        b[4..8].copy_from_slice(&self.nsid.to_le_bytes());
        b[24..32].copy_from_slice(&self.addr.to_le_bytes());
        b[36..40].copy_from_slice(&self.data_len.to_le_bytes());
        b[40..44].copy_from_slice(&self.cdw10.to_le_bytes());
        b[44..48].copy_from_slice(&self.cdw11.to_le_bytes());
        b[48..52].copy_from_slice(&self.cdw12.to_le_bytes());
        b
    }
}

// ------------------------------------------------------------------------------------------------ fixed-buffer probe

/// Probe transfer: several pages, so the kernel walks more than one segment of the registration.
const PROBE_BYTES: usize = 16 << 10;
/// Hugepage size the arena is mapped with (`MAP_HUGETLB` default); the probe span crosses one such boundary.
const HUGE: usize = 2 << 20;
/// Allocation the probe span is cut from: always contains a `HUGE` boundary with `PROBE_BYTES / 2` on both sides.
const PROBE_ALLOC: usize = HUGE + PROBE_BYTES;

/// Start of a `PROBE_BYTES` span inside `[ptr, ptr + len)` that is centred on a `HUGE` boundary relative to `base` (the
/// arena start: hugepages are aligned to it), so it covers two folios at a non-zero offset into each and ends before the
/// arena end. `None` = no such span inside the buffer.
fn probe_span(base: usize, ptr: usize, len: usize) -> Option<usize> {
    let half = PROBE_BYTES / 2;
    let rel = (ptr + half).checked_sub(base)?;
    let boundary = base + rel.next_multiple_of(HUGE);
    let start = boundary - half;
    (start >= ptr && start + PROBE_BYTES <= ptr + len).then_some(start)
}

/// Verdict of the probe from the completion result (0 = success, < 0 = -errno, > 0 = NVMe status) of the fixed-buffer
/// command. `Ok(true)` = cmd mode with fixed buffers, `Ok(false)` = the kernel cannot map fixed buffers for passthrough
/// (EINVAL: direct mode), `Err` = the device or kernel failed the probe for another reason.
fn probe_verdict(what: &str, fixed: i32) -> Result<bool, String> {
    match fixed {
        0 => Ok(true),
        r if r == -libc::EINVAL => Ok(false),
        r => Err(format!(
            "fixed-buffer probe {what}: {:?} (not a fixed-buffer capability error)",
            cmd_err(r)
        )),
    }
}

/// Passthrough DSM attribute AD (deallocate), CDW11 bit 2 of the NVMe Dataset Management command.
const DSM_AD: u32 = 1 << 2;

/// Probe ring of a cmd-mode namespace; the arena is registered on it when the kernel takes the registration.
fn probe_ring(path: &Path) -> Result<(IoUring<squeue::Entry128, cqueue::Entry32>, bool), String> {
    let ring = IoUring::<squeue::Entry128, cqueue::Entry32>::builder()
        .build(4)
        .map_err(|e| format!("{}: kernel-cmd probe ring: {e}", path.display()))?;
    let registered = arena().is_some_and(|a| {
        let iov = libc::iovec {
            iov_base: a.base as *mut libc::c_void,
            iov_len: a.len,
        };
        // SAFETY: the arena is mapped for the process lifetime.
        unsafe { ring.submitter().register_buffers(&[iov]) }.is_ok()
    });
    Ok((ring, registered))
}

/// One passthrough command on a probe ring, waited for; the completion result (see [`cmd_err`]).
fn cmd_once(
    ring: &mut IoUring<squeue::Entry128, cqueue::Entry32>,
    io: &OwnedFd,
    c: UringCmd,
    fixed: bool,
) -> Result<i32, String> {
    let mut e =
        opcode::UringCmd80::new(types::Fd(io.as_raw_fd()), NVME_URING_CMD_IO).cmd(c.bytes());
    if fixed {
        e = e.buf_index(Some(0));
    }
    // SAFETY: the caller's buffer outlives the wait below, and on an `Err` the caller leaks it (the command may still be
    // in flight once the wait bound passed).
    unsafe { ring.submission().push(&e.build()) }
        .map_err(|_| "probe: probe ring full".to_owned())?;
    probe_completion(ring, "kernel-cmd")
}

/// Bound of the wait for a capability probe's completion: a controller that stops completing must fail (or degrade) the
/// open with a loud line instead of blocking the OSD start. It equals the Linux NVMe driver's default command timeout, by
/// which a healthy controller has completed or aborted every command.
const PROBE_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// Wait for the one completion of a probe command: submit `ring` and sleep on its fd (the sleep the runtime uses for an
/// idle core, [`thread_ring_fd`]) until a completion arrives or [`PROBE_WAIT`] passes.
fn probe_completion(
    ring: &mut IoUring<squeue::Entry128, cqueue::Entry32>,
    what: &str,
) -> Result<i32, String> {
    ring.submit().map_err(|e| format!("probe submit: {e}"))?;
    let t0 = std::time::Instant::now();
    loop {
        if let Some(c) = ring.completion().next() {
            return Ok(c.result());
        }
        let left = PROBE_WAIT.saturating_sub(t0.elapsed());
        if left.is_zero() {
            eprintln!(
                "WARNING TIMEOUT {what} probe exceeded {:.3}s (the controller did not complete the command)",
                PROBE_WAIT.as_secs_f64()
            );
            return Err(format!(
                "probe: no completion within {}s",
                PROBE_WAIT.as_secs()
            ));
        }
        let mut p = libc::pollfd {
            fd: ring.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd; a signal only ends the wait early, the loop rechecks the deadline.
        unsafe { libc::poll(&mut p, 1, left.as_millis() as i32) };
    }
}

/// Capability probe at open of a cmd-mode namespace, before any IO; the probe commands have the production shape.
/// Sends no DSM: passthrough DSM is probed only at mkfs ([`KernelCtrl::probe_dsm_at_mkfs`]).
///
/// Fixed buffers: does this kernel run NVMe passthrough on a registered buffer (`IORING_URING_CMD_FIXED`)? Kernels without
/// upstream "block: fix sanity checks in blk_rq_map_user_bvec" reject every fixed buffer that is not the tail of its
/// registration with EINVAL (doc/perf/kcmd-fixed-probe-20261026.md). The probe reads 16 KiB at LBA 0 into an arena span
/// that crosses a hugepage boundary mid-arena, then writes the same bytes back (FUA per the write cache, as production
/// writes). The write-back is safe because it writes exactly the bytes the read just returned. A fixed command failing
/// with EINVAL = capability missing: the namespace runs in direct mode (one loud line at the open). The probe never
/// retries without the flag: a passthrough command with a plain user address is unsafe (module doc).
///
/// Returns whether passthrough may name the registered arena (`false` = direct mode).
fn probe_cmd(io: &OwnedFd, nsid: u32, vwc: bool, path: &Path) -> Result<bool, String> {
    let err = |e: String| format!("{}: kernel-cmd {e}", path.display());
    let (mut ring, registered) = probe_ring(path)?;
    // without a registration the device rings cannot register the arena either: no fixed buffers anywhere
    if !registered {
        return Ok(false);
    }
    let buf = KBuf::new_uninit(PROBE_ALLOC);
    let start = arena()
        .filter(|_| buf.fixed())
        .and_then(|a| probe_span(a.base, buf.ptr as usize, buf.len))
        .ok_or_else(|| err("fixed-buffer probe: no arena span free".into()))?;
    for (what, op) in [("read", NVM_READ), ("write-back", NVM_WRITE)] {
        let c = UringCmd {
            opcode: op,
            nsid,
            addr: start as u64,
            data_len: PROBE_BYTES as u32,
            cdw12: (PROBE_BYTES / LBA as usize - 1) as u32
                | if op == NVM_WRITE && vwc {
                    crate::IO_FLAG_FUA
                } else {
                    0
                },
            ..UringCmd::default()
        };
        let f = match cmd_once(&mut ring, io, c, true) {
            Ok(f) => f,
            Err(e) => {
                // the command may still be in flight (wait bound passed): its arena span is never handed out again
                std::mem::forget(buf);
                return Err(err(e));
            }
        };
        if !probe_verdict(what, f).map_err(err)? {
            return Ok(false);
        }
    }
    eprintln!(
        "kernel-cmd {}: fixed-buffer NVMe passthrough probe ok (IORING_URING_CMD_FIXED on)",
        path.display()
    );
    Ok(true)
}

/// Command area of a `BLOCK_URING_CMD_DISCARD` of `len` bytes: `sqe.addr3` (the first 8 bytes); the start goes to
/// `sqe.addr`. Every other field stays 0 (the kernel refuses `len`, `rw_flags`, `ioprio`, `file_index` otherwise).
fn discard_cmd(len: u64) -> [u8; 80] {
    let mut b = [0u8; 80];
    b[..8].copy_from_slice(&len.to_le_bytes());
    b
}

/// Does the namespace block node (opened for write) take `BLOCK_URING_CMD_DISCARD`? Sends nothing to the device: where
/// the command exists, a zero-length discard fails the kernel's byte-range check with EINVAL; a kernel without it answers
/// EOPNOTSUPP, one without `IORING_OP_URING_CMD` does not list the opcode. `Err` = why not.
fn probe_discard(fd: &OwnedFd) -> Result<(), String> {
    let mut ring = IoUring::<squeue::Entry128, cqueue::Entry32>::builder()
        .build(2)
        .map_err(|e| format!("probe ring: {e}"))?;
    let mut ops = io_uring::Probe::new();
    if ring.submitter().register_probe(&mut ops).is_err()
        || !ops.is_supported(opcode::UringCmd80::CODE)
    {
        return Err("no IORING_OP_URING_CMD".into());
    }
    let e = opcode::UringCmd80::new(types::Fd(fd.as_raw_fd()), BLOCK_URING_CMD_DISCARD)
        .addr(Some(0))
        .cmd(discard_cmd(0))
        .build();
    // SAFETY: the entry names no memory.
    unsafe { ring.submission().push(&e) }.map_err(|_| "probe ring full".to_owned())?;
    match probe_completion(&mut ring, "blkdiscard")? {
        r if r == -libc::EINVAL => Ok(()),
        r if r == -libc::EOPNOTSUPP => Err("no BLOCK_URING_CMD_DISCARD".into()),
        r => Err(format!("discard probe: errno {}", -r)),
    }
}

/// A failed [`probe_discard`] of a queue that discards: `missing=[URING_DISCARD]`; a failure other than the missing
/// command is one loud line.
fn missing_discard(missing: &mut Vec<&'static str>, path: &Path, why: &str) {
    missing.push(MISSING_URING_DISCARD);
    if why.starts_with("discard probe") || why.starts_with("probe") {
        eprintln!(
            "WARNING kernel store {}: {why}: block-node discard off (runtime deallocate only by passthrough DSM)",
            path.display()
        );
    }
}

/// One DSM range (16 bytes, padded to a 4 KiB block): context attributes 0, length, starting LBA.
fn dsm_range(lba: u64, nlba: u32) -> [u8; 4096] {
    let mut d = [0u8; 4096];
    d[4..8].copy_from_slice(&nlba.to_le_bytes());
    d[8..16].copy_from_slice(&lba.to_le_bytes());
    d
}

/// Passthrough DSM probe result: success = usable; an NVMe status = the device rejects passthrough DSM; an errno = the
/// probe itself failed (mkfs fails).
fn dsm_verdict(res: i32) -> Result<bool, String> {
    match res {
        0 => Ok(true),
        r if r > 0 => Ok(false),
        r => Err(format!("DSM probe: {:?}", cmd_err(r))),
    }
}

struct Pending {
    tag: u64,
    op: Op,
    buf: Option<KBuf>,
    /// DSM range list (kept alive until the completion, not returned).
    keep: Option<KBuf>,
    /// Path of the command (meaning of its completion result).
    via: Via,
    lba: u64,
}

/// Path of a submitted command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Via {
    /// O_DIRECT read/write or fallocate on the block node: result = bytes or -errno.
    Block,
    /// NVMe passthrough (`IORING_OP_URING_CMD`; a data buffer is always registered-arena, `IORING_URING_CMD_FIXED`):
    /// result = 0, -errno or the NVMe status.
    Cmd,
}

/// What a device ring registered: the arena (fixed buffer 0) and, by `id`, the cache chunks of its thread.
#[derive(Clone, Copy, Debug)]
struct Fx {
    arena: bool,
    ring: u64,
}

/// Path of a Cmd-mode command whose data buffer is `buf` (none: `WriteZeroes`, nothing to name). Passthrough only for a
/// registered buffer of this ring (arena, or a cache chunk of its thread): the kernel then imports the buffer by
/// registered range. A plain user address may be truncated to 32 bits when the kernel completes the submission in an
/// io-wq worker (module doc); such a read/write is O_DIRECT IO on the block node. A DSM range has no block-node path: on a
/// ring without registered fixed buffers `Unsupported` (permanent, the caller stops trimming that device); on a registered
/// ring with a range from outside the arena (arena exhausted, a transient state) `QueueFull`: retry later.
fn route(op: Op, buf: Option<&KBuf>, fx: Fx) -> Result<Via, SubmitError> {
    let Some(b) = buf else {
        return Ok(Via::Cmd);
    };
    if b.fixed_index(fx).is_some() {
        Ok(Via::Cmd)
    } else if op != Op::Deallocate {
        Ok(Via::Block)
    } else if fx.arena {
        Err(SubmitError::QueueFull)
    } else {
        Err(SubmitError::Unsupported)
    }
}

/// Per-core queue handle of a `kernel:` device.
pub struct KernelDev {
    c: Arc<Ctrl>,
    geo: Geometry,
    slots: Vec<Option<Pending>>,
    free: Vec<u32>,
    ring: *mut KRing,
    ring_id: u64,
    qid: u32,
    /// Hand-back inbox of the bound ring: where `qid` goes when the handle leaves that ring idle.
    home: Option<Arc<Retired>>,
    /// Latched: a completion named a slot that holds no command (the ring's own latch: [`KRing::dead`]).
    dead: crate::DeadLatch,
    /// The first failed completion of this device was logged (once per device).
    failure_logged: bool,
    /// The first refused view of this device was logged (once per device: where unplaced payloads come from).
    view_refusal_logged: bool,
}

impl std::fmt::Debug for KernelDev {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KernelDev")
            .field("mode", &self.c.mode)
            .field("inflight", &(self.slots.len() - self.free.len()))
            .finish()
    }
}

// Moved to its owning core while idle (no IO in flight), then used by that thread only; the ring pointer is
// re-bound on the new thread at the next submit.
unsafe impl Send for KernelDev {}

/// Decodes a failed completion for the loud first-failure line: `errno=<n>` (res < 0) or `nvme sct=.. sc=.. dnr=..` (res > 0).
fn describe_result(via: Via, res: i32) -> String {
    if res < 0 {
        format!("errno={}", -res)
    } else if via == Via::Cmd {
        crate::status_text(res, 14)
    } else {
        format!("short transfer: {res} bytes")
    }
}

/// Passthrough completion result: < 0 = -errno, > 0 = NVMe status field (sct << 8 | sc, plus CRD/M/DNR above).
fn cmd_err(res: i32) -> IoError {
    if res < 0 {
        return errno_err(-res);
    }
    nvme_status_err((res & 0x7ff) as u16)
}

impl KernelDev {
    fn inflight(&self) -> usize {
        self.slots.len() - self.free.len()
    }

    /// Attach to this thread's device ring (first use, or after the handle moved threads while idle).
    fn bind(&mut self) -> Result<&mut KRing, SubmitError> {
        let p = thread_ring().map_err(|e| {
            static ONCE: std::sync::Once = std::sync::Once::new();
            ONCE.call_once(|| {
                eprintln!(
                    "ERROR kernel store: device ring: {}",
                    uring_access::refused(e)
                );
            });
            SubmitError::Dead
        })?;
        // SAFETY: this thread's ring, alive until thread exit; no other reference is held across this call.
        let r = unsafe { &mut *p };
        if r.id != self.ring_id {
            assert_eq!(
                self.inflight(),
                0,
                "kernel nvme queue moved to another thread with IO in flight"
            );
            let q = r
                .add_queue(self.c.io.as_raw_fd(), self.c.block_fd())
                .map_err(|_| SubmitError::Dead)?;
            // idle: the former ring's thread unregisters the old binding (never touched from here, DS-iolayer-01)
            if let Some(old) = self.home.replace(r.retired.clone()) {
                old.give_back(self.qid);
            }
            self.ring = p;
            self.ring_id = r.id;
            self.qid = q;
        }
        Ok(r)
    }

    /// The SQE of one command and the path it takes. Cmd mode: [`route`] decides passthrough or the queue's block-node
    /// slot (module doc); an error is a DSM range that cannot be named.
    fn entry(
        &self,
        op: Op,
        lba: u64,
        nlba: u32,
        buf: Option<&KBuf>,
        keep: Option<&KBuf>,
        fx: Fx,
    ) -> Result<(squeue::Entry128, Via), SubmitError> {
        let ls = u64::from(self.geo.lba_size);
        let vwc = self.geo.vwc;
        let off = lba * ls;
        let block = |fd: types::Fixed, b: &KBuf| -> squeue::Entry128 {
            let fixed = b.fixed_index(fx);
            let e = match (op, fixed) {
                (Op::Read, Some(ix)) => opcode::ReadFixed::new(fd, b.ptr, b.len as u32, ix)
                    .offset(off)
                    .build(),
                (Op::Read, None) => opcode::Read::new(fd, b.ptr, b.len as u32)
                    .offset(off)
                    .build(),
                (Op::Write, Some(ix)) => opcode::WriteFixed::new(fd, b.ptr, b.len as u32, ix)
                    .offset(off)
                    .rw_flags(if vwc { RWF_DSYNC } else { 0 })
                    .build(),
                (Op::Write, None) => opcode::Write::new(fd, b.ptr, b.len as u32)
                    .offset(off)
                    .rw_flags(if vwc { RWF_DSYNC } else { 0 })
                    .build(),
                _ => unreachable!("block-node IO is a read or a write"),
            };
            e.into()
        };
        match self.c.mode {
            Mode::Direct => {
                let fd = types::Fixed(self.qid);
                let e = match (op, buf) {
                    (Op::Read | Op::Write, Some(b)) => block(fd, b),
                    (Op::WriteZeroes, _) => opcode::Fallocate::new(fd, u64::from(nlba) * ls)
                        .offset(off)
                        .mode(libc::FALLOC_FL_ZERO_RANGE | libc::FALLOC_FL_KEEP_SIZE)
                        .build()
                        .into(),
                    (Op::Deallocate, _) => opcode::UringCmd80::new(fd, BLOCK_URING_CMD_DISCARD)
                        .addr(Some(off))
                        .cmd(discard_cmd(u64::from(nlba) * ls))
                        .build(),
                    _ => unreachable!("validated by the submit path"),
                };
                Ok((e, Via::Block))
            }
            Mode::Cmd if op == Op::Deallocate && keep.is_none() => {
                // block-node discard (no passthrough DSM verdict): the queue's block-node slot
                let fd = types::Fixed(MAX_QUEUES + self.qid);
                let e = opcode::UringCmd80::new(fd, BLOCK_URING_CMD_DISCARD)
                    .addr(Some(off))
                    .cmd(discard_cmd(u64::from(nlba) * ls))
                    .build();
                Ok((e, Via::Block))
            }
            Mode::Cmd => {
                let data = if op == Op::Deallocate { keep } else { buf };
                if route(op, data, fx)? == Via::Block {
                    let b = buf.expect("data buffer");
                    return Ok((block(types::Fixed(MAX_QUEUES + self.qid), b), Via::Block));
                }
                let fua = if vwc { crate::IO_FLAG_FUA } else { 0 };
                let mut c = UringCmd {
                    nsid: self.c.nsid,
                    cdw10: lba as u32,
                    cdw11: (lba >> 32) as u32,
                    cdw12: nlba - 1,
                    ..UringCmd::default()
                };
                match op {
                    Op::Read | Op::Write => {
                        let b = buf.expect("data buffer");
                        c.opcode = if op == Op::Read { NVM_READ } else { NVM_WRITE };
                        c.addr = b.ptr as u64;
                        c.data_len = b.len as u32;
                        if op == Op::Write {
                            c.cdw12 |= fua;
                        }
                    }
                    Op::WriteZeroes => {
                        c.opcode = NVM_WRITE_ZEROES;
                        c.cdw12 |= fua;
                    }
                    Op::Deallocate => {
                        // `nlba` ranges (context attributes 0, length, starting LBA) with the AD (deallocate) attribute
                        let r = keep.expect("range buffer");
                        c.opcode = NVM_DSM;
                        c.addr = r.ptr as u64;
                        c.data_len = nlba * DSM_RANGE_BYTES as u32;
                        c.cdw10 = nlba - 1;
                        c.cdw11 = DSM_AD;
                        c.cdw12 = 0;
                    }
                }
                let mut e = opcode::UringCmd80::new(types::Fixed(self.qid), NVME_URING_CMD_IO)
                    .cmd(c.bytes());
                if let Some(b) = data {
                    // `route` sent every other buffer to the block node or refused it
                    let ix = b.fixed_index(fx).expect("routed to passthrough");
                    e = e.buf_index(Some(ix));
                }
                Ok((e.build(), Via::Cmd))
            }
        }
    }

    /// One command. `Op::Deallocate` with `keep` (DSM range list): passthrough DSM of `nlba` ranges; without: the block
    /// node's discard of `[lba, lba + nlba)`.
    fn submit_inner(
        &mut self,
        op: Op,
        lba: u64,
        nlba: u32,
        tag: u64,
        buf: Option<KBuf>,
        keep: Option<KBuf>,
    ) -> Submit<KBuf> {
        if self.dead.get() {
            return Err(Rejected::new(SubmitError::Dead, buf));
        }
        let Some(&slot) = self.free.last() else {
            return Err(Rejected::new(SubmitError::QueueFull, buf));
        };
        let ring = match self.bind() {
            Ok(r) => r as *mut KRing,
            Err(err) => return Err(Rejected::new(err, buf)),
        };
        // SAFETY: this thread's ring (bound above); not aliased while `self` is borrowed here.
        let r = unsafe { &mut *ring };
        if r.dead.get() {
            return Err(Rejected::new(SubmitError::Dead, buf));
        }
        let (e, via) = match self.entry(op, lba, nlba, buf.as_ref(), keep.as_ref(), r.fx()) {
            Ok(x) => x,
            Err(err) => {
                if err == SubmitError::Unsupported && !std::mem::replace(&mut r.dsm_warned, true) {
                    eprintln!(
                        "WARNING kernel-cmd {}: the io_uring ring has no registered fixed buffers, so passthrough \
                         deallocate (DSM) cannot name its range: runtime trim is off on this device (adr 0169)",
                        self.c.path.display()
                    );
                }
                return Err(Rejected::new(err, buf));
            }
        };
        let e = e.user_data(u64::from(self.qid) << 32 | u64::from(slot));
        if !r.push(&e) {
            return Err(Rejected::new(SubmitError::QueueFull, buf));
        }
        self.free.pop();
        self.slots[slot as usize] = Some(Pending {
            tag,
            op,
            buf,
            keep,
            via,
            lba,
        });
        Ok(())
    }

    fn rw(&mut self, op: Op, lba: u64, buf: KBuf, tag: u64) -> Submit<KBuf> {
        let ls = self.geo.lba_size as usize;
        let n = buf.len / ls.max(1);
        if buf.len == 0 || !buf.len.is_multiple_of(ls) {
            return Err(Rejected::new(SubmitError::Invalid, Some(buf)));
        }
        if let Err(err) = self.geo.check_io(lba, n as u64) {
            return Err(Rejected::new(err, Some(buf)));
        }
        self.submit_inner(op, lba, n as u32, tag, Some(buf), None)
    }

    fn reap(&mut self, out: &mut Vec<Completion<KBuf>>) -> usize {
        if self.ring_id != current_ring_id() {
            // Send permits moving even a busy handle. Its issuer may have exited;
            // never dereference its TLS ring or release buffers still owned by IO.
            self.dead.trip(
                "kernel store",
                format_args!("queue polled off its issuing thread with IO in flight"),
            );
            return 0;
        }
        // SAFETY: ring identity matches this thread's live TLS ring.
        let r = unsafe { &mut *self.ring };
        r.flush();
        r.reap();
        let q = self.qid as usize;
        if r.done[q].is_empty() {
            return 0;
        }
        let list = std::mem::take(&mut r.done[q]);
        let n0 = out.len();
        for &(slot, res) in &list {
            let Some(p) = self.slots.get_mut(slot as usize).and_then(Option::take) else {
                self.dead
                    .empty_slot(format_args!("kernel store {}", self.c.path.display()), slot);
                continue;
            };
            self.free.push(slot);
            let data_len = p.buf.as_ref().or(p.keep.as_ref()).map_or(0, |b| b.len);
            let result = match p.via {
                Via::Block => match (res, &p.buf) {
                    (r, Some(b)) if r >= 0 && r as usize == b.len => Ok(()),
                    (r, None) if r >= 0 => Ok(()),
                    (r, _) if r < 0 => Err(errno_err(-r)),
                    _ => Err(IoError::Status(0xffff)), // short transfer
                },
                Via::Cmd if res == 0 => Ok(()),
                Via::Cmd => {
                    // the probes passed both capabilities: a mapping rejection of a fixed buffer or a rejected DSM now is a
                    // hard error, never retried
                    let data = p.buf.is_some() || p.keep.is_some();
                    if (data && res == -libc::EINVAL) || (p.op == Op::Deallocate && res > 0) {
                        eprintln!(
                            "ERROR kernel-cmd {}: passthrough {:?} (fixed buffer) lba {} ({} bytes) failed {:?} although the \
                             probes passed (adr 0169 am. 1, am. 8)",
                            self.c.path.display(),
                            p.op,
                            p.lba,
                            data_len,
                            cmd_err(res),
                        );
                    }
                    Err(cmd_err(res))
                }
            };
            if let Some(b) = &p.buf {
                b.check_view(&self.c.path, p.lba);
            }
            if result.is_err() && !self.failure_logged {
                self.failure_logged = true;
                crate::log_first_failure(
                    format_args!("kernel store {}", self.c.path.display()),
                    p.op,
                    p.lba,
                    format_args!(
                        "bytes {} via {:?} buffer [{}] raw res {} ({})",
                        data_len,
                        p.via,
                        p.buf.as_ref().map_or_else(|| "none".into(), KBuf::describe),
                        res,
                        describe_result(p.via, res),
                    ),
                );
            }
            if result.is_ok()
                && p.op == Op::Read
                && let Some(b) = &p.buf
            {
                b.initialized.set(true); // the device filled every byte
            }
            out.push(Completion {
                tag: p.tag,
                op: p.op,
                result,
                buf: p.buf,
            });
        }
        let mut list = list;
        list.clear();
        // SAFETY: as above; the take/put keeps the vector's capacity.
        let r = unsafe { &mut *self.ring };
        if r.done[q].is_empty() {
            r.done[q] = list;
        }
        out.len() - n0
    }
}

impl Drop for KernelDev {
    fn drop(&mut self) {
        if self.ring.is_null() {
            return; // never bound: nothing in flight
        }
        if self.ring_id != current_ring_id() {
            // bound on another thread: its completions cannot be reaped here; the kernel may still write into the
            // buffers of commands in flight (they and the binding their completions name are leaked). Idle: the
            // ring's thread unregisters the binding.
            if self.inflight() > 0 {
                eprintln!(
                    "croit-flashstore-osd: nvme queue dropped off its thread with {} commands in flight: their buffers are leaked",
                    self.inflight()
                );
                self.forget_inflight();
            } else if let Some(home) = &self.home {
                home.give_back(self.qid);
            }
            return;
        }
        let mut sink = Vec::new();
        if crate::drain_or_leak(
            self,
            Self::inflight,
            |d| {
                sink.clear();
                d.reap(&mut sink);
            },
            Self::forget_inflight,
        ) {
            // SAFETY: this thread's ring.
            unsafe { &mut *self.ring }.drop_queue(self.qid);
        }
    }
}

impl KernelDev {
    /// The kernel may still write into the buffers of commands in flight: leak them rather than free memory under DMA.
    fn forget_inflight(&mut self) {
        for p in self.slots.iter_mut().flatten() {
            std::mem::forget(p.buf.take());
            std::mem::forget(p.keep.take());
        }
    }
}

/// `BLKDISCARD` = `_IO(0x12, 119)`, argument `[start, len]` in bytes.
const BLKDISCARD: u64 = 0x1277;

/// Discard `[0, capacity)` of the block device behind `io`. Returns the LBAs discarded.
fn blkdiscard(io: &OwnedFd, geo: &Geometry) -> Result<u64, String> {
    let range = [0u64, geo.lba_count * u64::from(geo.lba_size)];
    // SAFETY: BLKDISCARD reads two u64 from the pointer.
    if unsafe { libc::ioctl(io.as_raw_fd(), BLKDISCARD as _, range.as_ptr()) } != 0 {
        return Err(format!(
            "BLKDISCARD [0, {}): {}",
            range[1],
            std::io::Error::last_os_error()
        ));
    }
    Ok(geo.lba_count)
}

impl BlockDev for KernelDev {
    fn is_dead(&self) -> bool {
        if self.dead.get() || self.ring.is_null() {
            return self.dead.get();
        }
        if self.ring_id != current_ring_id() {
            // Idle migration rebinds on the next submit. A busy migrated queue
            // cannot be polled here; its buffers remain retained until teardown.
            return self.inflight() != 0;
        }
        // SAFETY: ring identity matches this thread's live TLS ring.
        unsafe { &*self.ring }.dead.get()
    }
    type Buf = KBuf;

    fn submits_at_flush(&self) -> bool {
        true
    }
    fn geometry(&self) -> Geometry {
        self.c.geometry_now()
    }
    fn alloc_buf(&mut self, len: usize) -> KBuf {
        KBuf::new(len)
    }
    fn alloc_buf_uninit(&mut self, len: usize) -> KBuf {
        KBuf::new_uninit(len)
    }
    fn ram_reads(&self) -> bool {
        true
    }
    fn alloc_buf_ram_uninit(&mut self, len: usize) -> KBuf {
        match self.bind() {
            Ok(r) => KBuf::new_cache_uninit(len, r),
            Err(_) => KBuf::new_heap_uninit(len),
        }
    }
    fn trim_ram(&mut self) {
        if CACHE.try_with(|c| c.borrow().idle == 0).unwrap_or(true) {
            return;
        }
        if let Ok(r) = self.bind() {
            let ring: &KRing = r;
            let _ = CACHE.try_with(|c| c.borrow_mut().release_idle(ring));
        }
    }
    /// Views only 4 KiB-aligned memory ([`VIEW_ALIGN`]); anything else is `None` and the caller copies into an
    /// aligned device buffer (counted by the store, `view_copy_bytes`). `queue/dma_alignment` (dword on NVMe) is
    /// what the PCIe path needs, but a namespace whose backend splits or re-issues the I/O with O_DIRECT (an nvmet
    /// file backend) fails a write from memory that is not block aligned with a device error (Status 6): views
    /// meet the strictest backend, receivers place payloads there (spec msgr2.md 3.1, adr 0061 am. 11).
    fn view_buf(&mut self, data: &bytes::Bytes) -> Option<KBuf> {
        if !data.len().is_multiple_of(self.geo.lba_size as usize)
            || data.as_ptr() as usize & (self.c.dma_mask | (VIEW_ALIGN - 1)) != 0
        {
            if !self.view_refusal_logged {
                self.view_refusal_logged = true;
                eprintln!(
                    "INFO kernel store {}: first unaligned write payload (addr%4096={} len {}): copied into a device buffer, counted in view_copy_bytes",
                    self.c.path.display(),
                    data.as_ptr() as usize % VIEW_ALIGN,
                    data.len()
                );
            }
            return None;
        }
        KBuf::view(data)
    }
    fn queue_space(&self) -> usize {
        self.free.len()
    }
    fn queue_depth(&self) -> usize {
        self.slots.len()
    }
    fn submit_write(&mut self, lba: u64, buf: KBuf, tag: u64) -> Submit<KBuf> {
        self.rw(Op::Write, lba, buf, tag)
    }
    fn submit_read(&mut self, lba: u64, buf: KBuf, tag: u64) -> Submit<KBuf> {
        if buf.is_view() {
            return Err(Rejected::new(SubmitError::Invalid, Some(buf)));
        }
        self.rw(Op::Read, lba, buf, tag)
    }
    fn dealloc_limits(&self) -> DeallocLimits {
        self.c.dealloc_limits()
    }
    /// Passthrough DSM with every range (cmd mode, accepted verdict; the range list in an arena buffer), else the block
    /// node's discard command (one range).
    fn submit_deallocate(&mut self, ranges: &[(u64, u32)], tag: u64) -> Submit<KBuf> {
        if let Err(err) = self.dealloc_limits().check(ranges) {
            return Err(Rejected::new(err, None));
        }
        for &(lba, n) in ranges {
            if let Err(err) = self.geo.check_range(lba, u64::from(n)) {
                return Err(Rejected::new(err, None));
            }
        }
        if self.c.dealloc_ok() {
            let mut list = [0u8; 4096];
            dsm_ranges_into(ranges, &mut list);
            let mut r = KBuf::new_uninit(4096);
            r.copy_from_slice(&list);
            return self.submit_inner(
                Op::Deallocate,
                ranges[0].0,
                ranges.len() as u32,
                tag,
                None,
                Some(r),
            );
        }
        let (lba, n) = ranges[0];
        self.submit_inner(Op::Deallocate, lba, n, tag, None, None)
    }
    /// Direct mode has no DSM passthrough (`Geometry::dealloc` false): the setup-time whole device discard is the
    /// BLKDISCARD ioctl, like BlueStore/blkdiscard; the kernel splits it by the device limits. Cmd mode does the same on
    /// its claimed block node when the mkfs probe found passthrough DSM unusable.
    fn deallocate_all(&mut self) -> Result<u64, String> {
        if self.c.mapped {
            return Err(
                "whole-device discard is forbidden for mapped storage; use --no-discard".into(),
            );
        }
        match (&self.c.claim, self.c.mode) {
            (_, Mode::Direct) => blkdiscard(&self.c.io, &self.geo),
            // passthrough DSM rejected at the open probe: the kernel's own discard on the claimed block node
            (Some(claim), Mode::Cmd) if !self.c.dealloc_ok() => blkdiscard(claim, &self.geo),
            _ => dsm_deallocate_all(self),
        }
    }
    fn submit_write_zeroes(&mut self, lba: u64, nlba: u32, tag: u64) -> Submit<KBuf> {
        if !self.geo.write_zeroes {
            return Err(Rejected::new(SubmitError::Unsupported, None));
        }
        // passthrough names the count in NVMe's 16-bit NLB field (direct mode: fallocate, no such field)
        if self.c.mode == Mode::Cmd && nlba > crate::NLB_MAX {
            return Err(Rejected::new(SubmitError::Invalid, None));
        }
        if let Err(err) = self.geo.check_range(lba, u64::from(nlba)) {
            return Err(Rejected::new(err, None));
        }
        self.submit_inner(Op::WriteZeroes, lba, nlba, tag, None, None)
    }
    fn poll(&mut self, _now: Nanos, out: &mut Vec<Completion<KBuf>>) -> usize {
        if self.inflight() == 0 {
            return 0;
        }
        self.reap(out)
    }
}

#[path = "kdev_sq.rs"]
mod sq;

#[path = "klinear.rs"]
mod linear;

#[cfg(test)]
#[path = "kdev_tests.rs"]
mod tests;
