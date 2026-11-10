// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! zcrx kernel interface (doc/spec/knet-zcrx.md section 1): the registration records as the kernel ABI lays them out,
//! the raw `io_uring_register` calls the `io-uring` crate lacks (its `register_ifq` record predates `rx_buf_len` and
//! the event descriptor and passes the record read-only although the kernel writes it back), and the memory the
//! kernel needs from us: the area and the refill ring region.
use std::io;
use std::os::fd::RawFd;
use std::ptr::NonNull;

/// `IORING_REGISTER_ZCRX_IFQ`.
const REGISTER_ZCRX_IFQ: u32 = 32;
/// `IORING_REGISTER_ZCRX_CTRL`.
const REGISTER_ZCRX_CTRL: u32 = 36;
/// `ZCRX_REG_NODEV`: an instance without a net device (every byte comes through the kernel copy path).
pub const REG_NODEV: u32 = 2;
/// `ZCRX_CTRL_FLUSH_RQ`: the kernel takes the refill entries now (device-less instances do not refill on their own).
const CTRL_FLUSH_RQ: u32 = 0;
/// `IORING_MEM_REGION_TYPE_USER`: the refill ring lives in memory we mapped.
const REGION_TYPE_USER: u32 = 1;
/// Bit from which the area id is encoded in fragment offsets (`IORING_ZCRX_AREA_SHIFT`).
pub const AREA_SHIFT: u32 = 48;
/// `ZCRX_EVENT_DESC_FLAG_STATS`: the kernel keeps copy-fallback counters in the refill region.
const EVENT_DESC_STATS: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Offsets {
    pub head: u32,
    pub tail: u32,
    pub rqes: u32,
    resv2: u32,
    resv: [u64; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct IfqReg {
    pub if_idx: u32,
    pub if_rxq: u32,
    pub rq_entries: u32,
    pub flags: u32,
    pub area_ptr: u64,
    pub region_ptr: u64,
    pub offsets: Offsets,
    pub zcrx_id: u32,
    pub rx_buf_len: u32,
    pub event_desc: u64,
    resv: [u64; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AreaReg {
    pub addr: u64,
    pub len: u64,
    pub rq_area_token: u64,
    pub flags: u32,
    pub dmabuf_fd: u32,
    resv2: [u64; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RegionDesc {
    pub user_addr: u64,
    pub size: u64,
    pub flags: u32,
    pub id: u32,
    pub mmap_offset: u64,
    resv: [u64; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EventDesc {
    pub user_data: u64,
    pub type_mask: u32,
    pub flags: u32,
    pub stats_offset: u64,
    resv2: [u64; 9],
}

/// Copy-fallback counters the kernel keeps at `EventDesc::stats_offset` of the refill region.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub copy_count: u64,
    pub copy_bytes: u64,
}

/// One refill entry: area offset (with the area token) and length of a returned fragment.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Rqe {
    pub off: u64,
    pub len: u32,
    pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct Ctrl {
    zcrx_id: u32,
    op: u32,
    resv: [u64; 2],
    body: [u64; 6],
}

const _: () = assert!(size_of::<IfqReg>() == 96);
const _: () = assert!(size_of::<AreaReg>() == 48);
const _: () = assert!(size_of::<RegionDesc>() == 64);
const _: () = assert!(size_of::<EventDesc>() == 96);
const _: () = assert!(size_of::<Rqe>() == 16);
const _: () = assert!(size_of::<Ctrl>() == 72);

fn register(ring: RawFd, op: u32, arg: *mut libc::c_void, nr: u32) -> io::Result<()> {
    // SAFETY: `arg` points to a live record of the layout `op` expects (callers), the kernel copies it in and out
    // within the call.
    let r = unsafe { libc::syscall(libc::SYS_io_uring_register, ring, op, arg, nr) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Anonymous private mapping, page aligned, zero filled; unmapped on drop.
#[derive(Debug)]
pub struct Map {
    ptr: NonNull<u8>,
    len: usize,
}

// SAFETY: plain memory owned by this value; access is coordinated by its users (single owner core).
unsafe impl Send for Map {}

impl Map {
    /// `len` bytes, 2 MiB pages when the host has them free (fewer IOTLB/TLB misses on a large area), else 4 KiB pages.
    pub fn new(len: usize, huge: bool) -> io::Result<Map> {
        let prot = libc::PROT_READ | libc::PROT_WRITE;
        let base = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE;
        let try_map = |flags| {
            // SAFETY: anonymous mapping, no fd, kernel chooses the address.
            let p = unsafe { libc::mmap(std::ptr::null_mut(), len, prot, flags, -1, 0) };
            (p != libc::MAP_FAILED).then_some(p)
        };
        let p = huge
            .then(|| try_map(base | libc::MAP_HUGETLB))
            .flatten()
            .or_else(|| try_map(base))
            .ok_or_else(io::Error::last_os_error)?;
        Ok(Map {
            ptr: NonNull::new(p.cast()).ok_or(io::ErrorKind::OutOfMemory)?,
            len,
        })
    }
    pub fn addr(&self) -> u64 {
        self.ptr.as_ptr() as u64
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }
}

impl Drop for Map {
    fn drop(&mut self) {
        // SAFETY: the mapping we created; nothing references it any more (the ring that registered it is closed first).
        unsafe { libc::munmap(self.ptr.as_ptr().cast(), self.len) };
    }
}

/// A registered interface queue: area, refill ring and the kernel's answers.
#[derive(Debug)]
pub struct Ifq {
    pub area: Map,
    pub region: Map,
    pub id: u32,
    pub token: u64,
    pub chunk: u32,
    pub entries: u32,
    pub offsets: Offsets,
    pub stats_offset: Option<u64>,
}

/// Where to register: a NIC rx queue, or no device at all (kernel copy path, functional tests).
#[derive(Clone, Copy, Debug)]
pub enum Target {
    Queue { ifindex: u32, rxq: u32 },
    NoDev,
}

const PAGE: usize = 4096;

impl Ifq {
    /// Register one ifq on the ring `ring` (`SINGLE_ISSUER | DEFER_TASKRUN | CQE32`), page sized chunks. Errors are the kernel's (`EPERM` no `CAP_NET_ADMIN`, `EINVAL` ring flags / HDS off / bad size,
    /// `EOPNOTSUPP` driver without queue API, `EBUSY` queue taken, `ENOMEM`).
    pub fn register(ring: RawFd, target: Target, area_len: usize, entries: u32) -> io::Result<Ifq> {
        let entries = entries.next_power_of_two();
        let area = Map::new(area_len, true)?;
        // header (head/tail) in the first cache lines, the entries after it, the kernel's stats at the very end
        let region_len = (PAGE + entries as usize * size_of::<Rqe>()).next_multiple_of(PAGE);
        let region = Map::new(region_len, false)?;
        let stats_at = (region_len - size_of::<Stats>()) as u64;
        let mut a = AreaReg {
            addr: area.addr(),
            len: area.len() as u64,
            ..AreaReg::default()
        };
        let mut rd = RegionDesc {
            user_addr: region.addr(),
            size: region.len() as u64,
            flags: REGION_TYPE_USER,
            ..RegionDesc::default()
        };
        let mut ev = EventDesc {
            flags: EVENT_DESC_STATS,
            stats_offset: stats_at,
            ..EventDesc::default()
        };
        let mut reg = IfqReg {
            rq_entries: entries,
            area_ptr: (&raw mut a) as u64,
            region_ptr: (&raw mut rd) as u64,
            event_desc: (&raw mut ev) as u64,
            ..IfqReg::default()
        };
        match target {
            Target::Queue { ifindex, rxq } => (reg.if_idx, reg.if_rxq) = (ifindex, rxq),
            Target::NoDev => reg.flags = REG_NODEV,
        }
        let r = register(ring, REGISTER_ZCRX_IFQ, (&raw mut reg).cast(), 1);
        // kernels without the stats descriptor refuse it with EINVAL: register once more without it
        let stats_offset = match r {
            Ok(()) => Some(stats_at),
            Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {
                reg.event_desc = 0;
                reg.offsets = Offsets::default();
                reg.zcrx_id = 0;
                a.rq_area_token = 0;
                register(ring, REGISTER_ZCRX_IFQ, (&raw mut reg).cast(), 1)?;
                None
            }
            Err(e) => return Err(e),
        };
        let chunk = if reg.rx_buf_len.is_power_of_two() {
            reg.rx_buf_len
        } else {
            PAGE as u32
        };
        Ok(Ifq {
            area,
            region,
            id: reg.zcrx_id,
            token: a.rq_area_token,
            chunk,
            entries: reg.rq_entries,
            offsets: reg.offsets,
            stats_offset,
        })
    }

    /// Bytes of a fragment the kernel reported at area offset `off` (area id bits stripped).
    ///
    /// # Safety
    /// `off..off + len` lies inside the area and is held by us (delivered by a completion, not yet refilled).
    pub unsafe fn frag(&self, off: u64, len: usize) -> &[u8] {
        let at = (off & ((1u64 << AREA_SHIFT) - 1)) as usize;
        // a completion that names bytes outside the area is a protocol fault: refused in release builds too (a slice
        // past the mapping is UB), as in knet's `DirectRx::receive_pointer`
        assert!(
            at.checked_add(len)
                .is_some_and(|end| end <= self.area.len()),
            "zcrx fragment {at}+{len} outside the {} byte area",
            self.area.len()
        );
        // SAFETY: caller contract, range checked above.
        unsafe { std::slice::from_raw_parts(self.area.ptr().add(at), len) }
    }

    fn word(&self, at: u32) -> &std::sync::atomic::AtomicU32 {
        // SAFETY: the kernel placed head/tail inside the first page of the region, 4-byte aligned.
        unsafe {
            &*self
                .region
                .ptr()
                .add(at as usize)
                .cast::<std::sync::atomic::AtomicU32>()
        }
    }

    /// Refill ring head (kernel consumer index).
    pub fn head(&self) -> u32 {
        self.word(self.offsets.head)
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Write refill entry `idx` (masked by the caller) for the fragment at `off`.
    pub fn put_rqe(&mut self, idx: u32, off: u64, len: u32) {
        let at =
            self.offsets.rqes as usize + (idx & (self.entries - 1)) as usize * size_of::<Rqe>();
        let e = Rqe {
            off: (off & ((1u64 << AREA_SHIFT) - 1)) | self.token,
            len,
            pad: 0,
        };
        // SAFETY: inside the region (entries were sized at registration), single producer = this core.
        unsafe { self.region.ptr().add(at).cast::<Rqe>().write(e) };
    }

    /// Publish the producer index (`Release`: the entries before it are visible to the kernel first).
    pub fn publish_tail(&self, tail: u32) {
        self.word(self.offsets.tail)
            .store(tail, std::sync::atomic::Ordering::Release);
    }

    /// Kernel copy-fallback counters, where the kernel keeps them.
    pub fn stats(&self) -> Option<Stats> {
        let at = self.stats_offset?;
        // SAFETY: inside the first page of the region; the kernel updates it concurrently (racy read of counters).
        Some(unsafe {
            self.region
                .ptr()
                .add(at as usize)
                .cast::<Stats>()
                .read_volatile()
        })
    }

    /// Ask the kernel to take the published refill entries now (device-less instances only).
    pub fn flush(&self, ring: RawFd) -> io::Result<()> {
        let mut c = Ctrl {
            zcrx_id: self.id,
            op: CTRL_FLUSH_RQ,
            ..Ctrl::default()
        };
        register(ring, REGISTER_ZCRX_CTRL, (&raw mut c).cast(), 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A completion that names bytes outside the area must be refused in release builds too: the slice would read
    /// past the mapping (the kernel-copy path takes the length from the kernel).
    #[test]
    #[should_panic(expected = "zcrx fragment 0+8192 outside the 4096 byte area")]
    fn a_fragment_past_the_area_is_refused() {
        let ifq = Ifq {
            area: Map::new(4096, false).unwrap(),
            region: Map::new(4096, false).unwrap(),
            id: 0,
            token: 0,
            chunk: 4096,
            entries: 1,
            offsets: Offsets::default(),
            stats_offset: None,
        };
        // SAFETY: the caller contract is deliberately broken: the length must be refused, never sliced.
        let _ = unsafe { ifq.frag(0, 8192) };
    }
}
