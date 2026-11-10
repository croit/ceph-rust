// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! L0: device abstraction. The trait lives in crate `nvme` (so the SPDK driver can implement it without
//! depending on the store); re-exported here together with the simulator and clocks.

pub mod cow;
pub mod sim;

pub use cow::{CowDev, Overlay};
pub use nvme::{
    BlockDev, Completion, DeallocLimits, Geometry, IoBuf, IoError, Nanos, Op, Rejected, Submit,
    SubmitError,
};
pub use sim::{CrashPolicy, InflightInfo, Persist, SimConfig, SimDev, SimDisk, SimImage};

/// The LBA size the store's block arithmetic needs: one that divides [`crate::BLK`] (as `mkfs` requires), so
/// [`lbas_per_blk`] is >= 1. Device input: a namespace outside it fails the mount with
/// [`crate::error::StoreError::BadGeometry`], never divides by zero.
pub(crate) fn check_lba_size(g: &Geometry) -> crate::error::Result<()> {
    let l = g.lba_size;
    if l == 0 || !(crate::BLK as u32).is_multiple_of(l) {
        return Err(crate::error::StoreError::BadGeometry(format!(
            "device LBA size {l} does not divide the store block of {}",
            crate::BLK
        )));
    }
    Ok(())
}

/// LBAs per store block, for a validated device ([`check_lba_size`]): `mkfs` refuses an LBA size that does not divide
/// `BLK`, and every LBA conversion of the store checks the size first.
pub(crate) fn lbas_per_blk(g: &Geometry) -> u64 {
    crate::BLK as u64 / u64::from(g.lba_size)
}

/// Largest single device command in store blocks, at least 1. `Shard::open` refuses a device whose transfer limit is
/// below one block (`max_xfer_lbas < lbas_per_blk`), so on an opened shard the clamp never applies; before that
/// (mkfs, superblock reads) a sub-block limit issues one-block commands, which the device then rejects.
pub(crate) fn max_xfer_blks(g: &Geometry) -> u64 {
    (u64::from(g.max_xfer_lbas) / lbas_per_blk(g)).max(1)
}

/// Time source for sync helpers (mount, mkfs, replay). The engine proper takes `now` as a parameter.
pub trait Clock {
    fn now(&mut self) -> Nanos;
    /// Called when waiting for IO with nothing to do; `hint` = device's next completion time if known.
    fn idle(&mut self, hint: Option<Nanos>);
    /// `false` = virtual time: wall-clock CPU deadlines (preparation budget, adr 0093) are off and only step bounds
    /// apply, so simulated runs (crash matrices) issue the same IO sequence regardless of host load.
    fn wall_time(&self) -> bool {
        true
    }
}

/// Virtual clock: `idle` jumps to the device deadline (or +1 us), so simulated time is exact and fast.
#[derive(Clone, Debug, Default)]
pub struct SimClock {
    pub t: Nanos,
}

impl Clock for SimClock {
    fn wall_time(&self) -> bool {
        false
    }
    fn now(&mut self) -> Nanos {
        self.t
    }
    fn idle(&mut self, hint: Option<Nanos>) {
        self.t = hint.map_or(self.t + 1_000, |h| h.max(self.t + 1));
    }
}

/// Real monotonic clock (spins in `idle`).
#[derive(Debug)]
pub struct MonoClock {
    clk: crate::fastclock::Mono,
}

impl Default for MonoClock {
    fn default() -> Self {
        MonoClock {
            clk: crate::fastclock::Mono::at(std::time::Instant::now()),
        }
    }
}

impl Clock for MonoClock {
    fn now(&mut self) -> Nanos {
        self.clk.elapsed().as_nanos() as u64 // TSC on x86_64: no vDSO call per poll
    }
    fn idle(&mut self, _hint: Option<Nanos>) {
        std::hint::spin_loop();
    }
}
