// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Cheap monotonic clock for the poll loops: `Instant::elapsed` is a `clock_gettime` vDSO call (~25 ns, ~10 % of an idle
//! spinning core in perf); on x86_64 with an invariant TSC the time since an `Instant` is computed from `rdtsc` and a
//! scale calibrated once against `Instant` (process-wide, 50 ms at first use). Other targets / no invariant TSC fall
//! back to `Instant::elapsed`. Not for wall-clock use: the scale error (~1e-5) is irrelevant for protocol timers.
use std::sync::OnceLock;
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
struct Cal {
    base: Instant,
    tsc0: u64,
    /// ns per tick, Q32.
    mult: u64,
}

static CAL: OnceLock<Option<Cal>> = OnceLock::new();

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn tsc() -> u64 {
    // SAFETY: rdtsc has no memory effects.
    unsafe { core::arch::x86_64::_rdtsc() }
}

#[cfg(target_arch = "x86_64")]
fn invariant_tsc() -> bool {
    // CPUID 0x80000007 EDX bit 8
    // SAFETY: cpuid is always available on x86_64.
    let max = core::arch::x86_64::__cpuid(0x8000_0000).eax;
    max >= 0x8000_0007 && core::arch::x86_64::__cpuid(0x8000_0007).edx & (1 << 8) != 0
}

#[cfg(target_arch = "x86_64")]
fn calibrate() -> Option<Cal> {
    if !invariant_tsc() {
        return None;
    }
    let (b0, t0) = (Instant::now(), tsc());
    std::thread::sleep(Duration::from_millis(50));
    let (b1, t1) = (Instant::now(), tsc());
    let ns = b1.duration_since(b0).as_nanos() as u64;
    let ticks = t1.checked_sub(t0).filter(|t| *t > 0)?;
    Some(Cal {
        base: b0,
        tsc0: t0,
        mult: ((u128::from(ns) << 32) / u128::from(ticks)) as u64,
    })
}

#[cfg(not(target_arch = "x86_64"))]
fn calibrate() -> Option<Cal> {
    None
}

/// Calibrate now (call once at startup, before the cores run, so the 50 ms is not spent in a loop).
pub fn init() {
    CAL.get_or_init(calibrate);
}

/// Time elapsed since `t0` (same meaning as `t0.elapsed()`).
#[inline]
pub fn since(t0: Instant) -> Duration {
    #[cfg(target_arch = "x86_64")]
    if let Some(Some(c)) = CAL.get() {
        let d = tsc().wrapping_sub(c.tsc0);
        let ns = ((u128::from(d) * u128::from(c.mult)) >> 32) as u64;
        let now = Duration::from_nanos(ns);
        // position of `t0` on the calibrated timeline (t0 may predate the calibration)
        return match t0.checked_duration_since(c.base) {
            Some(off) => now.saturating_sub(off),
            None => now + c.base.duration_since(t0),
        };
    }
    t0.elapsed()
}

/// CPU time the calling thread has consumed, in ns. Unlike wall time it does not count the time the thread was
/// descheduled, so a cost measured with it is the work's cost, not the host's load.
pub fn thread_cpu_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid timespec for the call to fill in.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    debug_assert_eq!(rc, 0, "CLOCK_THREAD_CPUTIME_ID is supported");
    (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
}

/// A clock origin with the TSC value of that instant resolved once: `elapsed` is `rdtsc` + one multiply, no `Instant`
/// arithmetic (`since` re-derives the origin offset with `Timespec` subtractions on every call: ~4 % of a spinning
/// core in perf, Ice Lake host). Build it after [`init`]; without it (no invariant TSC / other targets) it is `Instant::elapsed`.
#[derive(Clone, Copy, Debug)]
pub struct Mono {
    t0: Instant,
    /// (TSC at `t0`, ns per tick Q32)
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    tsc: Option<(u64, u64)>,
}

impl Mono {
    pub fn at(t0: Instant) -> Mono {
        #[cfg(target_arch = "x86_64")]
        if let Some(Some(c)) = CAL.get() {
            // TSC reading at `t0` on the calibrated timeline (wrapping: `t0` may predate the calibration)
            let ticks = |ns: u128| ((ns << 32) / u128::from(c.mult)) as u64;
            let at = match t0.checked_duration_since(c.base) {
                Some(off) => c.tsc0.wrapping_add(ticks(off.as_nanos())),
                None => c
                    .tsc0
                    .wrapping_sub(ticks(c.base.duration_since(t0).as_nanos())),
            };
            return Mono {
                t0,
                tsc: Some((at, c.mult)),
            };
        }
        Mono { t0, tsc: None }
    }

    /// Time elapsed since the origin.
    #[inline]
    pub fn elapsed(&self) -> Duration {
        #[cfg(target_arch = "x86_64")]
        if let Some((at, mult)) = self.tsc {
            let d = tsc().wrapping_sub(at) as i64;
            let d = d.max(0) as u64;
            return Duration::from_nanos(((u128::from(d) * u128::from(mult)) >> 32) as u64);
        }
        self.t0.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_instant() {
        init();
        let t0 = Instant::now();
        std::thread::sleep(Duration::from_millis(30));
        let a = since(t0);
        let b = t0.elapsed();
        let diff = a.abs_diff(b);
        assert!(diff < Duration::from_millis(2), "{a:?} vs {b:?}");
        assert!(since(t0) >= a, "monotonic");
        let m = Mono::at(t0);
        let c = m.elapsed();
        assert!(c.abs_diff(t0.elapsed()) < Duration::from_millis(2), "{c:?}");
        assert!(m.elapsed() >= c, "monotonic");
        // an origin predating the calibration
        let early = Mono::at(t0 - Duration::from_millis(500));
        assert!(early.elapsed() >= Duration::from_millis(500));
    }
}
