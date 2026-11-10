// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Blocking helpers over a `BlockDev` for the cold paths (mkfs, mount, replay): submit many IOs, spin `poll`
//! until all complete. Addresses are engine blocks (4 KiB); 512 B devices are used 8 LBAs at a time.

use crate::BLK;
use crate::dev::{BlockDev, Clock, Completion, IoBuf, IoError, Submit, SubmitError};

use crate::error::{Result, StoreError};

#[derive(Debug)]
pub struct Sio<'a, D: BlockDev, C: Clock> {
    pub dev: &'a mut D,
    pub clk: &'a mut C,
}

/// Longest wall-clock stretch a synchronous device wait (mount, mkfs, replay) tolerates without progress.
const STALL_SECS: u64 = 30;

/// Wall-clock stall detector of a blocking store wait: no progress for [`STALL_SECS`] prints the `WARNING TIMEOUT` line
/// (`expired`). Shard waits and backpressure rounds of blocking callers end there only with device IO in flight and no
/// completion (a device stall); with nothing in flight they wait for memory or another core and keep waiting. [`Sio`]
/// device waits of mount, mkfs, replay and the mount checkpoint report and keep waiting either way, since abandoned IO
/// would complete into a later request. Progress = a completion, an event, a submit. Free until a wait finds no progress: the
/// clock is read only then.
pub(crate) struct Stall {
    op: &'static str,
    /// Start of the current stretch without progress (`None`: progress since the last check).
    since: Option<std::time::Instant>,
}

impl Stall {
    pub(crate) const fn new(op: &'static str) -> Self {
        Stall { op, since: None }
    }

    pub(crate) fn progress(&mut self) {
        self.since = None;
    }

    /// A stall whose stretch without progress already lasted [`STALL_SECS`] (tests of what a wait does past the bound).
    #[cfg(test)]
    pub(crate) fn aged(op: &'static str) -> Self {
        Stall {
            op,
            since: Some(std::time::Instant::now() - std::time::Duration::from_secs(STALL_SECS)),
        }
    }

    /// True (and loud) once the wait made no progress for [`STALL_SECS`]; the first check after progress starts the
    /// stretch.
    pub(crate) fn expired(&mut self, ctx: std::fmt::Arguments) -> bool {
        let since = *self.since.get_or_insert_with(std::time::Instant::now);
        let e = since.elapsed().as_secs() >= STALL_SECS;
        if e {
            eprintln!("WARNING TIMEOUT {} exceeded {STALL_SECS}s ({ctx})", self.op);
        }
        e
    }
}

/// Why a [`Sio::drive`] ended early; the first cause wins.
#[derive(Debug, PartialEq, Eq)]
enum Fail {
    Submit(SubmitError),
    Io(IoError),
    /// Jobs left, nothing in flight, and the device takes no more.
    Stuck,
}

impl From<Fail> for StoreError {
    fn from(f: Fail) -> StoreError {
        match f {
            Fail::Io(e) => StoreError::Io(e),
            Fail::Submit(SubmitError::OutOfRange) => {
                StoreError::Invalid("sio: LBA range beyond the device")
            }
            Fail::Submit(SubmitError::Invalid) => StoreError::Invalid("sio: invalid IO"),
            Fail::Submit(SubmitError::Unsupported) => {
                StoreError::Invalid("sio: IO not supported by the device")
            }
            Fail::Submit(SubmitError::QueueFull | SubmitError::Dead) | Fail::Stuck => {
                StoreError::Io(IoError::Aborted)
            }
        }
    }
}

struct Job {
    req: usize,
    off_blk: usize,
    lba: u64,
    nlba: u32,
}

impl<'a, D: BlockDev, C: Clock> Sio<'a, D, C> {
    pub fn new(dev: &'a mut D, clk: &'a mut C) -> Self {
        Sio { dev, clk }
    }

    /// LBAs per store block of the device; the first conversion of a call rejects a device whose LBA size the store's
    /// block arithmetic cannot use (`read_super` runs before any other geometry check).
    fn lpb(&self) -> Result<u64> {
        let g = self.dev.geometry();
        crate::dev::check_lba_size(&g)?;
        Ok(crate::dev::lbas_per_blk(&g))
    }

    /// Validate the whole range before converting addresses or allocating IO/output buffers.
    fn range(&self, blk: u64, n: u64, lpb: u64) -> Result<(u64, u64)> {
        let cap = self.dev.geometry().lba_count / lpb;
        if blk > cap || n > cap - blk {
            return Err(StoreError::Invalid("sio: LBA range beyond the device"));
        }
        Ok((blk * lpb, (blk + n) * lpb))
    }

    fn jobs(&self, reqs: impl Iterator<Item = (u64, usize)>) -> Result<Vec<Job>> {
        let lpb = self.lpb()?;
        let max_blk = crate::dev::max_xfer_blks(&self.dev.geometry()) as usize;
        let mut jobs = Vec::new();
        for (i, (blk, n)) in reqs.enumerate() {
            self.range(blk, n as u64, lpb)?;
            let mut off = 0;
            while off < n {
                let c = (n - off).min(max_blk);
                jobs.push(Job {
                    req: i,
                    off_blk: off,
                    lba: (blk + off as u64) * lpb,
                    nlba: (c as u64 * lpb) as u32,
                });
                off += c;
            }
        }
        Ok(jobs)
    }

    /// Read `(blk, nblk)` ranges concurrently.
    pub fn read(&mut self, reqs: &[(u64, u32)]) -> Result<Vec<Vec<u8>>> {
        let jobs = self.jobs(reqs.iter().map(|&(b, n)| (b, n as usize)))?;
        let mut out: Vec<Vec<u8>> = reqs
            .iter()
            .map(|&(_, n)| vec![0; n as usize * BLK])
            .collect();
        self.run(
            &jobs,
            true,
            |_, _| &[],
            |j, buf| {
                let o = j.off_blk * BLK;
                out[j.req][o..o + buf.len()].copy_from_slice(buf);
            },
        )?;
        Ok(out)
    }

    pub fn read_one(&mut self, blk: u64, nblk: u32) -> Result<Vec<u8>> {
        Ok(self.read(&[(blk, nblk)])?.pop().unwrap())
    }

    /// Write `(blk, data)` ranges concurrently (data length multiple of 4 KiB).
    pub fn write(&mut self, reqs: &[(u64, &[u8])]) -> Result<()> {
        if reqs.iter().any(|(_, d)| !d.len().is_multiple_of(BLK)) {
            return Err(StoreError::Invalid(
                "sio: write length is not block aligned",
            ));
        }
        let jobs = self.jobs(reqs.iter().map(|&(b, d)| (b, d.len() / BLK)))?;
        self.run(
            &jobs,
            false,
            |j, ls| {
                let o = j.off_blk * BLK;
                &reqs[j.req].1[o..o + j.nlba as usize * ls]
            },
            |_, _| {},
        )
    }

    pub fn write_one(&mut self, blk: u64, data: &[u8]) -> Result<()> {
        self.write(&[(blk, data)])
    }

    /// Zero `n` blocks from `blk`: Write Zeroes (no data transfer) in <= `ZERO_LBAS` pieces, plain zero writes
    /// when the device refuses the command (FileDev, controllers without it). Used by mkfs only.
    pub fn zero(&mut self, blk: u64, n: u64) -> Result<()> {
        const ZERO_LBAS: u64 = 2048;
        let ls = self.dev.geometry().lba_size as usize;
        let lpb = self.lpb()?;
        let (first, end) = self.range(blk, n, lpb)?;
        let pieces = (end - first).div_ceil(ZERO_LBAS) as usize;
        let piece = |i: usize| {
            let lba = first + i as u64 * ZERO_LBAS;
            (lba, ZERO_LBAS.min(end - lba))
        };
        match self.drive(
            Stall::new("sio zero"),
            pieces,
            |dev, i| {
                let (lba, c) = piece(i);
                Some(dev.submit_write_zeroes(lba, c as u32, i as u64))
            },
            |_| {},
        ) {
            Ok(()) => Ok(()),
            // the device refuses or fails Write Zeroes: plain writes over the whole range (idempotent over what
            // Write Zeroes already did)
            Err(Fail::Submit(SubmitError::Unsupported | SubmitError::Invalid) | Fail::Io(_)) => {
                let z = vec![0u8; ZERO_LBAS as usize * ls];
                let (mut b, e) = (blk, blk + n);
                while b < e {
                    let c = (z.len() as u64 / BLK as u64).min(e - b);
                    self.write_one(b, &z[..c as usize * BLK])?;
                    b += c;
                }
                Ok(())
            }
            Err(f) => Err(f.into()),
        }
    }

    fn run<'s>(
        &mut self,
        jobs: &[Job],
        read: bool,
        src: impl Fn(&Job, usize) -> &'s [u8],
        mut sink: impl FnMut(&Job, &[u8]),
    ) -> Result<()> {
        let ls = self.dev.geometry().lba_size as usize;
        self.drive(
            Stall::new(if read { "sio read" } else { "sio write" }),
            jobs.len(),
            |dev, i| {
                let j = &jobs[i];
                let mut b = dev.try_alloc_io_uninit(j.nlba as usize * ls)?;
                Some(if read {
                    dev.submit_read(j.lba, b, i as u64)
                } else {
                    b.copy_from_slice(src(j, ls));
                    dev.submit_write(j.lba, b, i as u64)
                })
            },
            |c| {
                if read && let Some(b) = &c.buf {
                    sink(&jobs[c.tag as usize], b.as_slice());
                }
            },
        )
        .map_err(Into::into)
    }

    /// Submit `njobs` IOs (`submit(dev, job)`, tag = job index; `None` = no buffer within the DMA budget now, in-flight
    /// IO memory, adr 0175 am. 4) keeping the queue full, spin `poll` until all completed, hand every successful
    /// completion to `done`. After the first failure nothing more is submitted and the in-flight IOs are drained. A dead
    /// device or jobs left with nothing in flight that the device takes no more fail the call: it never returns `Ok` with
    /// work undone. Refused memory is backpressure, never a failure: memory held without IO in flight stays within the
    /// budget's read gate, so IO in flight elsewhere returns it; the wait reports each `stall` stretch (`WARNING
    /// TIMEOUT`) and goes on. It never returns with IO in flight on a live device either: tags are per-call job indexes,
    /// so an abandoned IO would complete into a later call's request (or into the shard's completion stream of the same
    /// queue). Progress of this wait = a completion (a submit only fills the queue). A stretch of `stall` without one
    /// is reported (`WARNING TIMEOUT`) and the wait goes on: a slow device ends it with the completion, a failing one
    /// with an error completion or as dead (review 2026-11-03 #14).
    fn drive(
        &mut self,
        mut stall: Stall,
        njobs: usize,
        mut submit: impl FnMut(&mut D, usize) -> Option<Submit<D::Buf>>,
        mut done: impl FnMut(&Completion<D::Buf>),
    ) -> std::result::Result<(), Fail> {
        let mut next = 0;
        let mut inflight = 0usize;
        let mut comp = Vec::new();
        let mut fail: Option<Fail> = None;
        while next < njobs && fail.is_none() || inflight > 0 {
            let mut short = false;
            while next < njobs && fail.is_none() && self.dev.queue_space() > 0 {
                let Some(s) = submit(self.dev, next) else {
                    short = true;
                    break;
                };
                match s {
                    Ok(()) => {
                        next += 1;
                        inflight += 1;
                    }
                    Err(rej) => {
                        if rej.err != SubmitError::QueueFull {
                            fail = Some(Fail::Submit(rej.err));
                        }
                        break;
                    }
                }
            }
            let now = self.clk.now();
            comp.clear();
            if self.dev.poll(now, &mut comp) == 0 {
                if self.dev.is_dead() {
                    return Err(Fail::Submit(SubmitError::Dead));
                }
                if inflight == 0 && short && fail.is_none() {
                    // memory comes back from IO in flight on other cores (adr 0175 am. 4): report each stretch, wait on
                    if stall.expired(format_args!(
                        "no DMA buffer within the budget, nothing in flight, {} of {njobs} jobs left; still waiting",
                        njobs - next
                    )) {
                        stall.progress();
                    }
                    let h = self.dev.next_deadline();
                    self.clk.idle(h);
                    continue;
                }
                if inflight == 0 {
                    if fail.is_none() && next < njobs {
                        eprintln!(
                            "ERROR {}: device takes no IO with nothing in flight ({} of {njobs} jobs left)",
                            stall.op,
                            njobs - next
                        );
                        fail = Some(Fail::Stuck);
                    }
                    break;
                }
                // report, then the next stretch starts: never abandon IO of a live device
                if stall.expired(format_args!(
                    "{inflight} in flight, {} of {njobs} jobs left; still waiting",
                    njobs - next
                )) {
                    stall.progress();
                }
                let h = self.dev.next_deadline();
                self.clk.idle(h);
                continue;
            }
            stall.progress();
            for c in &comp {
                inflight -= 1;
                match c.result {
                    Ok(()) => done(c),
                    Err(e) => fail = fail.take().or(Some(Fail::Io(e))),
                }
            }
        }
        fail.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev::{Geometry, Nanos, SimClock, SimConfig, SimDev, SimDisk};

    #[test]
    fn unaligned_writes_fail_before_any_io() {
        for lba_size in [512, 4096] {
            let mut cfg = SimConfig::new(4 << 20);
            cfg.lba_size = lba_size;
            cfg.lba_count = (4 << 20) / u64::from(lba_size);
            let disk = SimDisk::new(cfg);
            let mut dev = disk.queue();
            let mut clk = SimClock::default();
            let mut io = Sio::new(&mut dev, &mut clk);
            let original = vec![0x33; 2 * BLK];
            io.write_one(1, &original).unwrap();
            for len in [1, BLK - 1, BLK + 1] {
                let bad = vec![0x77; len];
                let aligned = vec![0x55; BLK];
                assert!(matches!(
                    io.write(&[(1, &aligned), (2, &bad)]),
                    Err(StoreError::Invalid(_))
                ));
                assert_eq!(io.read_one(1, 2).unwrap(), original);
                assert!(matches!(io.write_one(1, &bad), Err(StoreError::Invalid(_))));
            }
            io.write_one(1, &[]).unwrap();
            assert_eq!(io.read_one(1, 2).unwrap(), original);
        }
    }

    /// SimDev with scripted submit refusals.
    struct Stub {
        inner: SimDev,
        /// Result of every read/write/write-zeroes submit when set (the IO is not queued).
        refuse: Option<SubmitError>,
    }

    impl BlockDev for Stub {
        type Buf = Vec<u8>;
        fn geometry(&self) -> Geometry {
            self.inner.geometry()
        }
        fn alloc_buf(&mut self, len: usize) -> Vec<u8> {
            self.inner.alloc_buf(len)
        }
        fn queue_space(&self) -> usize {
            self.inner.queue_space()
        }
        fn queue_depth(&self) -> usize {
            self.inner.queue_depth()
        }
        fn submit_write(&mut self, lba: u64, buf: Vec<u8>, tag: u64) -> Submit<Vec<u8>> {
            match self.refuse {
                Some(err) => Err(crate::dev::Rejected {
                    err,
                    buf: Some(buf),
                }),
                None => self.inner.submit_write(lba, buf, tag),
            }
        }
        fn submit_read(&mut self, lba: u64, buf: Vec<u8>, tag: u64) -> Submit<Vec<u8>> {
            match self.refuse {
                Some(err) => Err(crate::dev::Rejected {
                    err,
                    buf: Some(buf),
                }),
                None => self.inner.submit_read(lba, buf, tag),
            }
        }
        fn dealloc_limits(&self) -> nvme::DeallocLimits {
            self.inner.dealloc_limits()
        }
        fn submit_deallocate(&mut self, ranges: &[(u64, u32)], tag: u64) -> Submit<Vec<u8>> {
            self.inner.submit_deallocate(ranges, tag)
        }
        fn submit_write_zeroes(&mut self, lba: u64, nlba: u32, tag: u64) -> Submit<Vec<u8>> {
            match self.refuse {
                Some(err) => Err(crate::dev::Rejected { err, buf: None }),
                None => self.inner.submit_write_zeroes(lba, nlba, tag),
            }
        }
        fn poll(&mut self, now: Nanos, out: &mut Vec<Completion<Vec<u8>>>) -> usize {
            self.inner.poll(now, out)
        }
        fn next_deadline(&self) -> Option<Nanos> {
            self.inner.next_deadline()
        }
        fn is_dead(&self) -> bool {
            self.inner.is_dead()
        }
    }

    fn setup() -> (SimDisk, Stub, SimClock) {
        let disk = SimDisk::new(SimConfig::new(4 << 20));
        let stub = Stub {
            inner: disk.queue(),
            refuse: None,
        };
        (disk, stub, SimClock::default())
    }

    #[test]
    fn invalid_ranges_fail_before_io() {
        for lba_size in [512, 4096] {
            let mut cfg = SimConfig::new(4 << 20);
            cfg.lba_size = lba_size;
            cfg.lba_count = (4 << 20) / u64::from(lba_size);
            let disk = SimDisk::new(cfg);
            let mut dev = disk.queue();
            let mut clk = SimClock::default();
            let mut io = Sio::new(&mut dev, &mut clk);
            let bad = StoreError::Invalid("sio: LBA range beyond the device");
            for (blk, n) in [(u64::MAX, 2), (1023, 2), (1024, 1)] {
                assert_eq!(io.read_one(blk, n), Err(bad.clone()));
                assert_eq!(
                    io.write_one(blk, &vec![1; n as usize * BLK]),
                    Err(bad.clone())
                );
                assert_eq!(io.zero(blk, n as u64), Err(bad.clone()));
            }
            assert_eq!(io.zero(0, u64::MAX), Err(bad));
            io.write_one(1023, &[7; BLK]).unwrap();
            assert_eq!(io.read_one(1023, 1).unwrap(), vec![7; BLK]);
        }
    }

    #[test]
    fn roundtrip_and_zero() {
        let (_d, mut dev, mut clk) = setup();
        let mut io = Sio::new(&mut dev, &mut clk);
        let data = vec![7u8; 3 * BLK];
        io.write_one(4, &data).unwrap();
        assert_eq!(io.read_one(4, 3).unwrap(), data);
        io.zero(5, 1).unwrap();
        let got = io.read_one(4, 3).unwrap();
        assert_eq!(&got[..BLK], &data[..BLK]);
        assert!(got[BLK..2 * BLK].iter().all(|b| *b == 0));
        assert_eq!(&got[2 * BLK..], &data[2 * BLK..]);
    }

    /// Jobs left, nothing in flight, the device keeps answering QueueFull: an error, never `Ok` with zeros read.
    #[test]
    fn queue_full_at_inflight_zero_is_an_error() {
        let (_d, mut dev, mut clk) = setup();
        dev.refuse = Some(SubmitError::QueueFull);
        let mut io = Sio::new(&mut dev, &mut clk);
        assert_eq!(
            io.read_one(1, 1),
            Err(StoreError::Io(IoError::Aborted)),
            "read must not return the pre-zeroed output"
        );
        assert!(io.write_one(1, &[1u8; BLK]).is_err());
        assert!(io.zero(1, 1).is_err());
    }

    /// The submit error kind survives (no collapse into Aborted); Dead and the rest are not retried.
    #[test]
    fn submit_errors_keep_their_kind() {
        let (_d, mut dev, mut clk) = setup();
        for (e, want) in [
            (
                SubmitError::OutOfRange,
                StoreError::Invalid("sio: LBA range beyond the device"),
            ),
            (SubmitError::Invalid, StoreError::Invalid("sio: invalid IO")),
            (
                SubmitError::Unsupported,
                StoreError::Invalid("sio: IO not supported by the device"),
            ),
            (SubmitError::Dead, StoreError::Io(IoError::Aborted)),
        ] {
            dev.refuse = Some(e);
            let mut io = Sio::new(&mut dev, &mut clk);
            assert_eq!(io.read_one(1, 1), Err(want.clone()), "{e:?}");
            assert_eq!(io.write_one(1, &[1u8; BLK]), Err(want), "{e:?}");
        }
    }

    /// Write Zeroes refused (Unsupported/Invalid): plain zero writes finish the range.
    #[test]
    fn zero_falls_back_to_plain_writes() {
        let (_d, mut dev, mut clk) = setup();
        Sio::new(&mut dev, &mut clk)
            .write_one(2, &[9u8; 2 * BLK])
            .unwrap();
        // a device that refuses only Write Zeroes
        struct NoWz(Stub);
        impl BlockDev for NoWz {
            type Buf = Vec<u8>;
            fn geometry(&self) -> Geometry {
                self.0.geometry()
            }
            fn alloc_buf(&mut self, l: usize) -> Vec<u8> {
                self.0.alloc_buf(l)
            }
            fn queue_space(&self) -> usize {
                self.0.queue_space()
            }
            fn queue_depth(&self) -> usize {
                self.0.queue_depth()
            }
            fn submit_write(&mut self, a: u64, b: Vec<u8>, t: u64) -> Submit<Vec<u8>> {
                self.0.submit_write(a, b, t)
            }
            fn submit_read(&mut self, a: u64, b: Vec<u8>, t: u64) -> Submit<Vec<u8>> {
                self.0.submit_read(a, b, t)
            }
            fn submit_deallocate(&mut self, r: &[(u64, u32)], t: u64) -> Submit<Vec<u8>> {
                self.0.submit_deallocate(r, t)
            }
            fn submit_write_zeroes(&mut self, _: u64, _: u32, _: u64) -> Submit<Vec<u8>> {
                Err(crate::dev::Rejected {
                    err: SubmitError::Unsupported,
                    buf: None,
                })
            }
            fn poll(&mut self, n: Nanos, o: &mut Vec<Completion<Vec<u8>>>) -> usize {
                self.0.poll(n, o)
            }
            fn next_deadline(&self) -> Option<Nanos> {
                self.0.next_deadline()
            }
        }
        let mut dev = NoWz(dev);
        let mut io = Sio::new(&mut dev, &mut clk);
        io.zero(2, 2).unwrap();
        assert!(io.read_one(2, 2).unwrap().iter().all(|b| *b == 0));
    }

    #[test]
    fn dead_device_ends_the_wait() {
        let (disk, mut dev, mut clk) = setup();
        disk.crash_now();
        let mut io = Sio::new(&mut dev, &mut clk);
        assert_eq!(io.read_one(1, 1), Err(StoreError::Io(IoError::Aborted)));
        assert_eq!(io.zero(1, 1), Err(StoreError::Io(IoError::Aborted)));
    }

    #[test]
    fn io_errors_surface_through_sio() {
        let (disk, mut dev, mut clk) = setup();
        disk.fail_reads(8, 1);
        disk.fail_writes(9, 1);
        let mut io = Sio::new(&mut dev, &mut clk);
        assert_eq!(io.read_one(8, 1), Err(StoreError::Io(IoError::Media)));
        assert!(io.write_one(9, &[1u8; BLK]).is_err());
        io.write_one(10, &[1u8; BLK]).unwrap();
    }

    /// A device whose LBA size the store's block arithmetic cannot use (a non-conforming namespace above the store
    /// block, a size that is not a power of two, or zero) fails with `BadGeometry` at the first LBA conversion: the
    /// superblock read runs before every other geometry check and used to divide by zero here.
    #[test]
    fn unusable_lba_size_is_bad_geometry() {
        for lba in [0u32, 600, 8192] {
            let mut cfg = SimConfig::new(4 << 20);
            cfg.lba_count = (4 << 20) / u64::from(lba.max(1));
            cfg.lba_size = lba;
            let disk = SimDisk::new(cfg);
            let mut dev = disk.queue();
            let mut clk = SimClock::default();
            let mut io = Sio::new(&mut dev, &mut clk);
            assert!(
                matches!(io.read_one(0, 1), Err(StoreError::BadGeometry(_))),
                "lba {lba}: read"
            );
            assert!(
                matches!(
                    io.write_one(0, &[0u8; BLK]),
                    Err(StoreError::BadGeometry(_))
                ),
                "lba {lba}: write"
            );
            assert!(
                matches!(io.zero(0, 1), Err(StoreError::BadGeometry(_))),
                "lba {lba}: zero"
            );
        }
    }

    #[test]
    fn stall_is_wall_clock_and_loud() {
        let mut s = Stall::new("test op");
        assert!(!s.expired(format_args!("fresh")));
        s.since = s
            .since
            .map(|t| t - std::time::Duration::from_secs(STALL_SECS));
        assert!(s.expired(format_args!("aged")));
        s.progress();
        assert!(!s.expired(format_args!("after progress")));
    }

    /// A device whose completions arrive only after `hold` empty polls (a slow command); reaped ones wait in `held`.
    struct Slow {
        inner: SimDev,
        hold: usize,
        held: Vec<Completion<Vec<u8>>>,
    }

    impl BlockDev for Slow {
        type Buf = Vec<u8>;
        fn geometry(&self) -> Geometry {
            self.inner.geometry()
        }
        fn alloc_buf(&mut self, l: usize) -> Vec<u8> {
            self.inner.alloc_buf(l)
        }
        fn queue_space(&self) -> usize {
            self.inner.queue_space()
        }
        fn queue_depth(&self) -> usize {
            self.inner.queue_depth()
        }
        fn submit_write(&mut self, a: u64, b: Vec<u8>, t: u64) -> Submit<Vec<u8>> {
            self.inner.submit_write(a, b, t)
        }
        fn submit_read(&mut self, a: u64, b: Vec<u8>, t: u64) -> Submit<Vec<u8>> {
            self.inner.submit_read(a, b, t)
        }
        fn dealloc_limits(&self) -> nvme::DeallocLimits {
            self.inner.dealloc_limits()
        }
        fn submit_deallocate(&mut self, r: &[(u64, u32)], t: u64) -> Submit<Vec<u8>> {
            self.inner.submit_deallocate(r, t)
        }
        fn submit_write_zeroes(&mut self, a: u64, n: u32, t: u64) -> Submit<Vec<u8>> {
            self.inner.submit_write_zeroes(a, n, t)
        }
        fn poll(&mut self, now: Nanos, out: &mut Vec<Completion<Vec<u8>>>) -> usize {
            self.inner.poll(now, &mut self.held);
            if self.hold > 0 {
                self.hold -= 1;
                return 0;
            }
            let n = self.held.len();
            out.append(&mut self.held);
            n
        }
        fn next_deadline(&self) -> Option<Nanos> {
            self.inner.next_deadline()
        }
    }

    /// Review 2026-11-03 #14: a read that completes only after the stall bound (aged tracker: no 30 s wait) is reported
    /// and waited for, never abandoned: the call returns its own data, and the next call on the same queue reads its own
    /// block (an abandoned IO's completion, tag 0, would land in that call's request 0).
    #[test]
    fn stalled_drive_waits_for_its_io() {
        let disk = SimDisk::new(SimConfig::new(4 << 20));
        let mut dev = Slow {
            inner: disk.queue(),
            hold: 0,
            held: Vec::new(),
        };
        let mut clk = SimClock::default();
        let (a, b) = (vec![0xaau8; BLK], vec![0xbbu8; BLK]);
        let mut io = Sio::new(&mut dev, &mut clk);
        io.write(&[(1, &a), (2, &b)]).unwrap();
        io.dev.hold = 64;
        let aged = Stall {
            op: "sio read",
            since: Some(std::time::Instant::now() - std::time::Duration::from_secs(STALL_SECS)),
        };
        let lpb = io.lpb().unwrap();
        let mut got = Vec::new();
        let r = io.drive(
            aged,
            1,
            |dev, i| {
                let buf = dev.alloc_buf_uninit(BLK);
                Some(dev.submit_read(lpb, buf, i as u64))
            },
            |c| got.push((c.tag, c.buf.as_ref().map(|b| b.as_slice().to_vec()))),
        );
        assert_eq!(r, Ok(()), "stalled drive gave up with its read in flight");
        assert_eq!(got, vec![(0, Some(a))]);
        assert_eq!(io.dev.hold, 0);
        assert!(io.dev.held.is_empty());
        assert_eq!(io.read_one(2, 1).unwrap(), b);
    }

    /// Buffers the DMA budget refuses (in-flight IO memory, adr 0175 am. 4): the call waits for memory and completes;
    /// memory refused beyond a whole stall stretch with nothing in flight is reported (`WARNING TIMEOUT`) and the call
    /// still completes once memory returns: pressure never fails it (no `Stuck`, no `Aborted`).
    #[test]
    fn refused_buffers_wait_for_memory_and_never_fail() {
        let disk = SimDisk::new(SimConfig::new(4 << 20));
        let mut dev = disk.queue();
        let mut clk = SimClock::default();
        let data = vec![5u8; 3 * BLK];
        let mut io = Sio::new(&mut dev, &mut clk);
        disk.refuse_io_bufs(3);
        io.write_one(4, &data).unwrap();
        disk.refuse_io_bufs(2);
        assert_eq!(io.read_one(4, 3).unwrap(), data);
        assert_eq!(disk.stats().refused_io_bufs, 5);
        // a stretch already past the stall limit: reported, and the wait goes on until memory returns
        disk.refuse_io_bufs(50);
        let aged = Stall {
            op: "sio read",
            since: Some(std::time::Instant::now() - std::time::Duration::from_secs(STALL_SECS)),
        };
        let lpb = io.lpb().unwrap();
        let mut got = Vec::new();
        let r = io.drive(
            aged,
            1,
            |dev, i| {
                let buf = dev.try_alloc_io_uninit(BLK)?;
                Some(dev.submit_read(lpb * 4, buf, i as u64))
            },
            |c| got.extend_from_slice(c.buf.as_ref().unwrap().as_slice()),
        );
        assert_eq!(r, Ok(()));
        assert_eq!(disk.stats().refused_io_bufs, 55);
        assert_eq!(got, data[..BLK]);
    }
}
