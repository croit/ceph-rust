// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `FileDev`: [`BlockDev`] over a regular file or a block device through `pread`/`pwrite`.
//!
//! **DEV / LAB ONLY.** Production storage is `SpdkDev` (userspace NVMe, no kernel in the data path, adr 0004) or
//! `KernelDev` (kernel nvme driver, the default tier, adr 0169).
//! This backend exists so the OSD can be run and crash-tested on machines without an NVMe controller (docker
//! lab, macOS). It is a completion-queue emulation: reads and writes are executed synchronously at submit
//! time (page cache), finished IOs sit in a queue until `poll`, and `poll` completes **writes only after one
//! `fdatasync` covering all of them** (group sync). Lab files and consumer disks have a volatile cache, so a
//! write completion without the sync would be a lie; with it, "completed == durable" holds like on a PLP
//! device and the geometry therefore reports `vwc = false`. Throughput is bounded by `fdatasync` latency.
//!
//! Handles from [`FileCtrl::open_queue`] share the file; each has its own completion queue (one per core).
//! Deallocate = `fallocate(PUNCH_HOLE|KEEP_SIZE)` (Linux; executed at submit, so it is ordered before any later write):
//! the store issues it for blocks it frees (`trims_freed`), so lab files shrink instead of only growing.
//! Not implemented (reported `Unsupported`): write zeroes (the engine falls back to writes).

use crate::{BlockDev, Completion, Geometry, IoError, Nanos, Op, Rejected, Submit, SubmitError};
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::Arc;

pub use crate::LBA;
/// Queue depth per handle.
pub const DEPTH: usize = 1024;
/// Largest IO in LBAs (1 MiB).
pub const MAX_XFER_LBAS: u32 = 256;

/// An opened file / block device; hands out queue handles.
#[derive(Clone, Debug)]
pub struct FileCtrl {
    file: Arc<File>,
    geo: Geometry,
    path: std::path::PathBuf,
}

impl FileCtrl {
    /// Remember the device path (kernel health probe).
    pub fn with_path(mut self, p: impl AsRef<Path>) -> Self {
        self.path = p.as_ref().to_owned();
        self
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Open an existing file or block device. `size` = None: whole file/device.
    pub fn open(path: impl AsRef<Path>, size: Option<u64>) -> std::io::Result<FileCtrl> {
        let f = OpenOptions::new().read(true).write(true).open(path)?;
        Self::from_file(f, size)
    }

    /// [`open`](Self::open) plus an exclusive advisory lock (`flock`) held as long as any handle lives: a second
    /// opener (OSD or offline tool) fails instead of corrupting the store. A block device is in addition opened with
    /// `O_EXCL`, the kernel's exclusive claim (Linux): a mounted device or one another exclusive opener holds fails
    /// with "in use"; mounts ignore `flock`. Anything but a regular file or a block device is refused, checked on the
    /// opened descriptor (a path replaced between the type probe and the open cannot slip past the claim).
    /// DEV/LAB only (`spdk:` devices: SPDK PCI claim, [`crate::pcilock`]).
    pub fn open_exclusive(path: impl AsRef<Path>, size: Option<u64>) -> std::io::Result<FileCtrl> {
        Self::open_exclusive_create(path, size, false)
    }

    /// [`open_exclusive`](Self::open_exclusive); `create` + `size`: a missing (or empty) file is created sparse with
    /// `size` bytes, after the lock is held.
    pub fn open_exclusive_create(
        path: impl AsRef<Path>,
        size: Option<u64>,
        create: bool,
    ) -> std::io::Result<FileCtrl> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
        let path = path.as_ref();
        let blk = std::fs::metadata(path).is_ok_and(|m| m.file_type().is_block_device());
        let mut o = OpenOptions::new();
        o.read(true).write(true).truncate(false);
        if blk {
            // without O_CREAT, O_EXCL on a block device = exclusive claim (EBUSY while mounted or claimed)
            o.custom_flags(libc::O_EXCL);
        } else {
            o.create(create && size.is_some());
        }
        let f = o.open(path).map_err(|e| {
            if blk && e.raw_os_error() == Some(libc::EBUSY) {
                std::io::Error::other(
                    "block device is in use (mounted or claimed by another process)",
                )
            } else {
                e
            }
        })?;
        let t = f.metadata()?.file_type();
        if !(t.is_file() || (blk && t.is_block_device())) {
            return Err(std::io::Error::other(
                "not a regular file or an exclusively claimed block device",
            ));
        }
        // SAFETY: plain syscall on a valid fd.
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let e = std::io::Error::last_os_error();
            return Err(if e.kind() == std::io::ErrorKind::WouldBlock {
                std::io::Error::other("device is in use by another process (running OSD or tool)")
            } else {
                e
            });
        }
        if create
            && let Some(s) = size
            && f.metadata()?.len() == 0
        {
            f.set_len(s)?;
            return Self::from_file(f, None);
        }
        Self::from_file(f, size)
    }

    /// Open `path`, creating it (sparse) with `size` bytes if it does not exist; an existing file keeps its size.
    pub fn open_or_create(path: impl AsRef<Path>, size: u64) -> std::io::Result<FileCtrl> {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        if f.metadata()?.len() == 0 {
            f.set_len(size)?;
        }
        Self::from_file(f, None)
    }

    fn from_file(mut f: File, size: Option<u64>) -> std::io::Result<FileCtrl> {
        let len = f.seek(SeekFrom::End(0))?;
        if let Some(s) = size
            && s > len
        {
            return Err(std::io::Error::other(format!(
                "requested size {s} bytes exceeds the device's {len} bytes"
            )));
        }
        // a smaller window on a larger file is the operator's choice (`size=` is the OSD's capacity, not the file's)
        let bytes = size.unwrap_or(len);
        let lbas = bytes / u64::from(LBA);
        if lbas == 0 {
            return Err(std::io::Error::other("device/file smaller than one block"));
        }
        Ok(FileCtrl {
            file: Arc::new(f),
            path: std::path::PathBuf::new(),
            geo: Geometry {
                lba_size: LBA,
                lba_count: lbas,
                awupf_lbas: 1,
                awun_lbas: 1,
                vwc: false, // writes complete after fdatasync
                max_xfer_lbas: MAX_XFER_LBAS,
                dealloc: cfg!(target_os = "linux"),
                write_zeroes: false,
            },
        })
    }

    pub fn geometry(&self) -> Geometry {
        self.geo
    }

    /// New queue handle.
    pub fn open_queue(&self) -> FileDev {
        FileDev {
            file: self.file.clone(),
            geo: self.geo,
            inflight: Vec::new(),
            dead: false,
        }
    }
}

/// Free the backing blocks of `[off, off+len)` (file keeps its size; reads of the range return zeroes).
#[cfg(target_os = "linux")]
fn punch(f: &File, off: u64, len: u64) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: plain syscall on a valid fd with in-range, non-negative offsets.
    let r = unsafe {
        libc::fallocate(
            f.as_raw_fd(),
            libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
            off as libc::off_t,
            len as libc::off_t,
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
fn punch(_: &File, _: u64, _: u64) -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}

struct Fin {
    tag: u64,
    op: Op,
    result: Result<(), IoError>,
    buf: Option<Vec<u8>>,
}

/// Queue handle (see module docs).
pub struct FileDev {
    file: Arc<File>,
    geo: Geometry,
    inflight: Vec<Fin>,
    dead: bool,
}

impl std::fmt::Debug for FileDev {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileDev")
            .field("inflight", &self.inflight.len())
            .finish()
    }
}

impl FileDev {
    fn check(&self, lba: u64, buf_len: usize) -> Result<u64, SubmitError> {
        let ls = self.geo.lba_size as usize;
        if buf_len == 0 || !buf_len.is_multiple_of(ls) {
            return Err(SubmitError::Invalid);
        }
        let n = (buf_len / ls) as u64;
        self.geo.check_io(lba, n)?;
        Ok(n)
    }

    fn rw(&mut self, op: Op, lba: u64, mut buf: Vec<u8>, tag: u64) -> Submit<Vec<u8>> {
        if self.dead {
            return Err(Rejected::new(SubmitError::Dead, Some(buf)));
        }
        if self.inflight.len() >= DEPTH {
            return Err(Rejected::new(SubmitError::QueueFull, Some(buf)));
        }
        if let Err(err) = self.check(lba, buf.len()) {
            return Err(Rejected::new(err, Some(buf)));
        }
        let off = lba * u64::from(self.geo.lba_size);
        let r = match op {
            Op::Write => self.file.write_all_at(&buf, off),
            _ => self.file.read_exact_at(&mut buf, off),
        };
        let result = r.map_err(io_err);
        self.inflight.push(Fin {
            tag,
            op,
            result,
            buf: Some(buf),
        });
        Ok(())
    }
}

/// `pread`/`pwrite`/`fallocate` failure -> store error: the errno is kept (a full filesystem is not a failing device).
/// An error without an errno has no io class to keep (media: it came from the device path).
fn io_err(e: std::io::Error) -> IoError {
    e.raw_os_error().map_or(IoError::Media, crate::errno_err)
}

impl BlockDev for FileDev {
    type Buf = Vec<u8>;

    fn geometry(&self) -> Geometry {
        self.geo
    }
    fn alloc_buf(&mut self, len: usize) -> Vec<u8> {
        vec![0; len]
    }
    fn ram_reads(&self) -> bool {
        true
    }
    fn queue_space(&self) -> usize {
        DEPTH - self.inflight.len()
    }
    fn queue_depth(&self) -> usize {
        DEPTH
    }
    fn submit_write(&mut self, lba: u64, buf: Vec<u8>, tag: u64) -> Submit<Vec<u8>> {
        self.rw(Op::Write, lba, buf, tag)
    }
    fn submit_read(&mut self, lba: u64, buf: Vec<u8>, tag: u64) -> Submit<Vec<u8>> {
        self.rw(Op::Read, lba, buf, tag)
    }
    fn dealloc_limits(&self) -> crate::DeallocLimits {
        if self.geo.dealloc {
            crate::DeallocLimits {
                via: "punch",
                ..crate::DeallocLimits::DSM
            }
        } else {
            crate::DeallocLimits::off("off(file without hole punching)")
        }
    }
    /// Punches every range at submit (lab): executed in submit order, completion at the next poll.
    fn submit_deallocate(&mut self, ranges: &[(u64, u32)], tag: u64) -> Submit<Vec<u8>> {
        let rej = |err| Err(Rejected::new(err, None));
        if let Err(e) = self.dealloc_limits().check(ranges) {
            return rej(e);
        }
        if self.dead {
            return rej(SubmitError::Dead);
        }
        if self.inflight.len() >= DEPTH {
            return rej(SubmitError::QueueFull);
        }
        if ranges.iter().any(|&(lba, n)| {
            lba.checked_add(u64::from(n))
                .is_none_or(|e| e > self.geo.lba_count)
        }) {
            return rej(SubmitError::OutOfRange);
        }
        let ls = u64::from(self.geo.lba_size);
        let result = ranges
            .iter()
            .try_for_each(|&(lba, n)| punch(&self.file, lba * ls, u64::from(n) * ls))
            .map_err(io_err);
        self.inflight.push(Fin {
            tag,
            op: Op::Deallocate,
            result,
            buf: None,
        });
        Ok(())
    }
    fn submit_write_zeroes(&mut self, _lba: u64, _nlba: u32, _tag: u64) -> Submit<Vec<u8>> {
        Err(Rejected::new(SubmitError::Unsupported, None))
    }

    fn poll(&mut self, _now: Nanos, out: &mut Vec<Completion<Vec<u8>>>) -> usize {
        self.poll_with_sync(out, File::sync_data)
    }

    fn is_dead(&self) -> bool {
        self.dead
    }
}

impl FileDev {
    /// Group-sync before publishing completions; injectable for filesystem error tests.
    fn poll_with_sync(
        &mut self,
        out: &mut Vec<Completion<Vec<u8>>>,
        sync: impl FnOnce(&File) -> std::io::Result<()>,
    ) -> usize {
        if self.inflight.is_empty() {
            return 0;
        }
        // one fdatasync covers every write executed so far; a failed sync fails all of them
        if self
            .inflight
            .iter()
            .any(|f| f.op == Op::Write && f.result.is_ok())
            && let Err(e) = sync(&self.file)
        {
            let err = io_err(e);
            for f in &mut self.inflight {
                if f.op == Op::Write && f.result.is_ok() {
                    f.result = Err(err);
                }
            }
        }
        let n = self.inflight.len();
        out.extend(self.inflight.drain(..).map(|f| Completion {
            tag: f.tag,
            op: f.op,
            result: f.result,
            buf: f.buf,
        }));
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_sync_preserves_errors_and_fails_only_successful_writes() {
        for errno in [libc::ENOSPC, libc::EDQUOT, libc::EIO, libc::ECANCELED] {
            let mut d = FileDev {
                file: Arc::new(File::open("/dev/null").unwrap()),
                geo: Geometry {
                    lba_size: LBA,
                    lba_count: 1,
                    awupf_lbas: 1,
                    awun_lbas: 1,
                    vwc: false,
                    max_xfer_lbas: 1,
                    dealloc: false,
                    write_zeroes: false,
                },
                inflight: [
                    (Op::Write, Ok(())),
                    (Op::Write, Ok(())),
                    (Op::Write, Err(IoError::Errno(libc::EACCES))),
                    (Op::Read, Ok(())),
                    (Op::Deallocate, Ok(())),
                ]
                .into_iter()
                .enumerate()
                .map(|(tag, (op, result))| Fin {
                    tag: tag as u64,
                    op,
                    result,
                    buf: (op != Op::Deallocate).then(|| vec![0x5a; 4096]),
                })
                .collect(),
                dead: false,
            };
            let mut calls = 0;
            let mut out = Vec::new();
            assert_eq!(
                d.poll_with_sync(&mut out, |_| {
                    calls += 1;
                    Err(std::io::Error::from_raw_os_error(errno))
                }),
                5
            );
            assert_eq!(calls, 1);
            assert_eq!(out[0].result, Err(crate::errno_err(errno)));
            assert_eq!(out[1].result, out[0].result);
            assert_eq!(out[2].result, Err(IoError::Errno(libc::EACCES)));
            assert_eq!(out[3].result, Ok(()));
            assert_eq!(out[4].result, Ok(()));
            assert!(
                out[..4]
                    .iter()
                    .all(|c| c.buf.as_ref().unwrap() == &vec![0x5a; 4096])
            );
            assert!(d.inflight.is_empty());
            assert_eq!(d.poll_with_sync(&mut out, |_| panic!("idle sync")), 0);
        }
    }

    #[test]
    fn exclusive_open_refuses_a_second_opener_until_released() {
        let _g = crate::testlock::guard(); // no forked sibling may hold a copy of the description
        let p = std::env::temp_dir().join(format!("filedev-lock-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        drop(FileCtrl::open_or_create(&p, 1 << 20).unwrap());
        let a = FileCtrl::open_exclusive(&p, None).unwrap();
        let q = a.open_queue(); // queue handles share the lock
        let e = FileCtrl::open_exclusive(&p, None).unwrap_err();
        assert!(e.to_string().contains("in use"), "{e}");
        // plain opens (read-only tools) are not blocked
        assert!(FileCtrl::open(&p, None).is_ok());
        drop(a);
        assert!(FileCtrl::open_exclusive(&p, None).is_err()); // `q` still holds the file
        drop(q);
        FileCtrl::open_exclusive(&p, None).unwrap();
        let _ = std::fs::remove_file(&p);
    }

    /// Character devices and symlinks to them are never a store device (`flock` is no claim there).
    #[test]
    fn exclusive_open_refuses_special_files() {
        let link = std::env::temp_dir().join(format!("filedev-null-{}", std::process::id()));
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink("/dev/null", &link).unwrap();
        for p in [Path::new("/dev/null"), link.as_path()] {
            let e = FileCtrl::open_exclusive(p, Some(1 << 20)).unwrap_err();
            assert!(e.to_string().contains("not a regular file"), "{e}");
        }
        let _ = std::fs::remove_file(&link);
    }

    /// A mounted block device (the one under `/`) is refused through the kernel's exclusive claim; `flock` alone let
    /// the open through. Opens read-write but never writes. Needs root (else: SKIP line).
    #[cfg(target_os = "linux")]
    #[test]
    fn exclusive_open_refuses_a_mounted_block_device() {
        let mi = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
        let majmin = mi
            .lines()
            .map(|l| l.split(' ').collect::<Vec<_>>())
            .find(|f| f.get(4) == Some(&"/"))
            .map(|f| f[2].to_owned())
            .unwrap();
        let uevent = std::fs::read_to_string(format!("/sys/dev/block/{majmin}/uevent"));
        let Some(name) = uevent.ok().and_then(|u| {
            u.lines()
                .find_map(|l| l.strip_prefix("DEVNAME=").map(str::to_owned))
        }) else {
            eprintln!("SKIP: / is not on a block device ({majmin})");
            return;
        };
        let dev = std::path::PathBuf::from("/dev").join(name);
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("SKIP: not root, cannot open {}", dev.display());
            return;
        }
        let e = FileCtrl::open_exclusive(&dev, None).unwrap_err();
        assert!(e.to_string().contains("in use"), "{}: {e}", dev.display());
    }

    #[test]
    fn roundtrip_and_errors() {
        let p = std::env::temp_dir().join(format!("filedev-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let ctrl = FileCtrl::open_or_create(&p, 1 << 20).unwrap();
        assert_eq!(ctrl.geometry().lba_count, 256);
        let mut d = ctrl.open_queue();
        let mut out = Vec::new();
        let mut b = d.alloc_buf(8192);
        b[0] = 7;
        b[8191] = 9;
        d.submit_write(3, b, 1).unwrap();
        assert_eq!(d.poll(0, &mut out), 1);
        assert!(out[0].result.is_ok() && out[0].op == Op::Write);
        out.clear();
        let mut d2 = ctrl.open_queue(); // second handle sees it
        let rb = d2.alloc_buf(8192);
        d2.submit_read(3, rb, 2).unwrap();
        d2.poll(0, &mut out);
        let b = out[0].buf.as_ref().unwrap();
        assert_eq!((b[0], b[8191]), (7, 9));
        assert_eq!(
            d.submit_read(255, vec![0; 8192], 3).unwrap_err().err,
            SubmitError::OutOfRange
        );
        assert_eq!(
            d.submit_read(0, vec![0; 100], 3).unwrap_err().err,
            SubmitError::Invalid
        );
        assert_eq!(
            d.submit_write_zeroes(0, 1, 4).unwrap_err().err,
            SubmitError::Unsupported
        );
        let _ = std::fs::remove_file(&p);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn deallocate_punches_hole_and_shrinks_allocation() {
        use std::os::unix::fs::MetadataExt;
        let p = std::env::temp_dir().join(format!("filedev-punch-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let ctrl = FileCtrl::open_or_create(&p, 8 << 20).unwrap();
        let mut d = ctrl.open_queue();
        assert!(d.dealloc_limits().is_on());
        let mut out = Vec::new();
        for i in 0..16 {
            // 16 x 256 KiB = 4 MiB of non-zero data
            d.submit_write(i * 64, vec![0xAB; 256 << 10], i).unwrap();
        }
        d.poll(0, &mut out);
        out.clear();
        let alloc = || std::fs::metadata(&p).unwrap().blocks() * 512;
        let before = alloc();
        assert!(before >= 4 << 20, "allocated {before}");
        d.submit_deallocate(&[(0, 512), (512, 512)], 99).unwrap(); // first 4 MiB, two ranges
        assert_eq!(d.poll(0, &mut out), 1);
        assert!(out[0].op == Op::Deallocate && out[0].result.is_ok());
        let after = alloc();
        assert!(after < before / 2, "allocated {before} -> {after}");
        assert_eq!(std::fs::metadata(&p).unwrap().len(), 8 << 20, "size kept");
        d.submit_read(0, vec![1; 4096], 100).unwrap();
        out.clear();
        d.poll(0, &mut out);
        assert!(out[0].buf.as_ref().unwrap().iter().all(|b| *b == 0));
        assert_eq!(
            d.submit_deallocate(&[(2047, 2)], 1).unwrap_err().err,
            SubmitError::OutOfRange
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn a_requested_size_beyond_the_file_is_refused() {
        let p = std::env::temp_dir().join(format!("filedev-size-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        drop(FileCtrl::open_or_create(&p, 1 << 20).unwrap());
        // 8 GiB on a 1 MiB file: the store would format (and later fill) a device that is not there
        let e = FileCtrl::open(&p, Some(8 << 30)).unwrap_err();
        assert!(e.to_string().contains("exceeds"), "{e}");
        // a smaller window on a larger file stays the operator's choice
        let d = FileCtrl::open(&p, Some(1 << 19)).unwrap();
        assert_eq!(d.geometry().lba_count, 128);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn deallocate_all_covers_the_namespace_or_errors() {
        let p = std::env::temp_dir().join(format!("filedev-dall-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let ctrl = FileCtrl::open_or_create(&p, 8 << 20).unwrap();
        let mut d = ctrl.open_queue();
        if cfg!(target_os = "linux") {
            for i in 0..16 {
                d.submit_write(i * 64, vec![0xAB; 256 << 10], i).unwrap();
            }
            let mut out = Vec::new();
            d.poll(0, &mut out);
            assert_eq!(d.deallocate_all(), Ok(2048));
            d.submit_read(0, vec![1; 4096], 1).unwrap();
            out.clear();
            d.poll(0, &mut out);
            assert!(out[0].buf.as_ref().unwrap().iter().all(|b| *b == 0));
        } else {
            assert!(d.deallocate_all().is_err());
        }
        let _ = std::fs::remove_file(&p);
    }
}
