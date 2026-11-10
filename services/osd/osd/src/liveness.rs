// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Internal liveness of every core (osd-lifecycle 5.4 "internal watchdog", adr 0034 am. 5).
//!
//! Each core beats from its 1 s tick ([`Liveness::beat`]): a core whose loop is wedged (a handler spinning, a blocking
//! call) stops beating. A component that knows its core cannot make progress although the loop still turns (e.g. a
//! device wait without completions) withholds the beat in the tick instead of adding a second mechanism. A checker
//! thread outside the cores ([`Checker::check`], once per second) compares the beats against the limits core 0
//! publishes from `osd_op_thread_timeout` / `osd_op_thread_suicide_timeout`:
//! - a core without a beat for longer than `osd_op_thread_timeout` makes the OSD unhealthy: core 0 drops incoming heartbeat
//!   pings (peers report it down after the heartbeat grace) and does not boot again while unhealthy, and the checker
//!   prints `WARNING TIMEOUT core <n> progress exceeded <limit>s (...)` once per episode;
//! - past `osd_op_thread_suicide_timeout` (0 = never): the checker aborts the process (fatal-signal crash report, the
//!   service manager restarts it), as the classic OSD does.
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

/// Cores a process can run (the cross-core link mask is a `u64`).
pub const MAX_CORES: usize = 64;

/// Shared between the cores (writers) and the checker thread (reader).
#[derive(Debug)]
pub struct Liveness {
    beats: [AtomicU64; MAX_CORES],
    timeout_ms: AtomicU64,
    suicide_ms: AtomicU64,
    unhealthy: AtomicBool,
}

/// The process-wide instance the daemon hands to its cores (`Osd::set_liveness`).
pub static LIVENESS: Liveness = Liveness::new();

impl Default for Liveness {
    fn default() -> Self {
        Self::new()
    }
}

impl Liveness {
    pub const fn new() -> Self {
        Self {
            beats: [const { AtomicU64::new(0) }; MAX_CORES],
            timeout_ms: AtomicU64::new(15_000),
            suicide_ms: AtomicU64::new(150_000),
            unhealthy: AtomicBool::new(false),
        }
    }

    /// Core `core` made progress (its tick ran).
    pub fn beat(&self, core: usize) {
        if let Some(b) = self.beats.get(core) {
            b.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Progress counter of `core` (a stalled core stops moving it); `None` outside `MAX_CORES`.
    pub fn beat_count(&self, core: usize) -> Option<u64> {
        self.beats.get(core).map(|b| b.load(Ordering::Relaxed))
    }

    /// Core 0: current limits (seconds, fractions allowed; suicide 0 = off).
    pub fn set_limits(&self, timeout: f64, suicide: f64) {
        let ms = |s: f64| (s.max(0.0) * 1000.0) as u64;
        self.timeout_ms.store(ms(timeout), Ordering::Relaxed);
        self.suicide_ms.store(ms(suicide), Ordering::Relaxed);
    }

    /// Some core missed its progress limit (set by the checker).
    pub fn unhealthy(&self) -> bool {
        self.unhealthy.load(Ordering::Relaxed)
    }

    /// Core 0 has ticked at least once (store open, loop running).
    pub fn started(&self) -> bool {
        self.beats[0].load(Ordering::Relaxed) != 0
    }
}

/// What the checker decided this round.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    Healthy,
    Unhealthy,
    /// Abort the process: `core` exceeded the suicide limit.
    Suicide {
        core: usize,
    },
}

/// One core as the checker last saw it.
#[derive(Debug, Clone, Copy)]
struct CoreSeen {
    /// Last beat counter value.
    beat: u64,
    /// Checker time when `beat` last changed.
    since: Duration,
    /// The stall warning of this episode was printed.
    warned: bool,
}

/// Per-core last beat and when it last changed (checker-thread state).
#[derive(Debug)]
pub struct Checker {
    seen: [CoreSeen; MAX_CORES],
}

impl Default for Checker {
    fn default() -> Self {
        Self {
            seen: [CoreSeen {
                beat: 0,
                since: Duration::ZERO,
                warned: false,
            }; MAX_CORES],
        }
    }
}

impl Checker {
    /// One round at checker time `now`; `warn` receives the loud timeout lines.
    pub fn check(&mut self, l: &Liveness, now: Duration, mut warn: impl FnMut(&str)) -> Verdict {
        let timeout = Duration::from_millis(l.timeout_ms.load(Ordering::Relaxed));
        let suicide = l.suicide_ms.load(Ordering::Relaxed);
        let mut verdict = Verdict::Healthy;
        for (core, seen) in self.seen.iter_mut().enumerate() {
            let b = l.beats[core].load(Ordering::Relaxed);
            if b != seen.beat {
                if seen.warned {
                    warn(&format!(
                        "core {core} progress resumed after {:.1}s",
                        now.saturating_sub(seen.since).as_secs_f64()
                    ));
                }
                seen.beat = b;
                seen.since = now;
                seen.warned = false;
                continue;
            }
            // a core that never beat is still starting (covered by the service start timeout)
            if b == 0 {
                continue;
            }
            let stalled = now.saturating_sub(seen.since);
            if suicide > 0 && stalled > Duration::from_millis(suicide) {
                let limit_s = suicide as f64 / 1000.0;
                warn(&format!(
                    "WARNING TIMEOUT core {core} progress exceeded {limit_s}s (osd_op_thread_suicide_timeout: aborting)"
                ));
                return Verdict::Suicide { core };
            }
            if stalled > timeout {
                if !seen.warned {
                    seen.warned = true;
                    warn(&format!(
                        "WARNING TIMEOUT core {core} progress exceeded {}s (osd_op_thread_timeout: heartbeat pings dropped)",
                        timeout.as_secs_f64()
                    ));
                }
                verdict = Verdict::Unhealthy;
            }
        }
        l.unhealthy
            .store(verdict != Verdict::Healthy, Ordering::Relaxed);
        verdict
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: u64) -> Duration {
        Duration::from_secs(x)
    }

    /// C4: a stalled worker core (not core 0) makes the OSD unhealthy after the op-thread timeout and aborts it after
    /// the suicide timeout; it recovers when the core beats again.
    #[test]
    fn stalled_worker_core_goes_unhealthy_then_suicide() {
        let l = Liveness::new();
        let mut c = Checker::default();
        let mut lines = Vec::new();
        l.beat(0);
        l.beat(3);
        assert_eq!(
            c.check(&l, s(0), |w| lines.push(w.to_owned())),
            Verdict::Healthy
        );
        for t in 1..=16 {
            l.beat(0); // core 0 keeps going, core 3 is wedged
            let v = c.check(&l, s(t), |w| lines.push(w.to_owned()));
            assert_eq!(v == Verdict::Unhealthy, t >= 16, "t={t}");
        }
        assert!(l.unhealthy());
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].starts_with("WARNING TIMEOUT core 3 progress exceeded 15s"),
            "{lines:?}"
        );
        // recovers
        l.beat(3);
        assert_eq!(
            c.check(&l, s(17), |w| lines.push(w.to_owned())),
            Verdict::Healthy
        );
        assert!(!l.unhealthy());
        // wedged for good: suicide after 150 s
        let mut v = Verdict::Healthy;
        for t in 18..=170 {
            l.beat(0);
            v = c.check(&l, s(t), |w| lines.push(w.to_owned()));
            if matches!(v, Verdict::Suicide { .. }) {
                assert_eq!(t, 168);
                break;
            }
        }
        assert_eq!(v, Verdict::Suicide { core: 3 });
        assert!(lines.last().unwrap().contains("exceeded 150s"));
    }

    #[test]
    fn limits_follow_config_and_zero_suicide_never_aborts() {
        let l = Liveness::new();
        l.set_limits(2.5, 0.0);
        let mut c = Checker::default();
        l.beat(1);
        c.check(&l, s(0), |_| {});
        assert_eq!(c.check(&l, s(2), |_| {}), Verdict::Healthy);
        assert_eq!(c.check(&l, s(3), |_| {}), Verdict::Unhealthy);
        assert_eq!(c.check(&l, s(100_000), |_| {}), Verdict::Unhealthy);
    }
}
