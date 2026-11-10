// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Lab diagnostics of long store polls (tail latency, doc/perf/tail-latency-20261015.md). Off unless [`enable`]d (the
//! OSD core loop does so under `NV_PHASE`): one relaxed load per `Store::poll` then. On: per thread (= core) the longest
//! single section of the current window, by kind, read and reset by [`take`].
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static ON: AtomicBool = AtomicBool::new(false);
/// Timeline window in ns (0 = off, [`tl_enable`]).
static TL_NS: AtomicU64 = AtomicU64::new(0);

/// Sections: shard pump (completions, WAL, checkpoint drive), checkpoint start (inside the pump), background
/// compaction, defrag step, prefetch expiry sweep, the whole `Store::poll`, one slice of a sliced freeze (inside the pump,
/// adr 0021 am. 40); then checkpoint parts (`ck_*`: delta fold, meta housekeeping, bitmap chunk flush, freeze begin, freeze
/// end + write job list; `ck_pages` = pages written, a count not us; `fz_*`: one settled page, one whole page, delta page
/// emit, meta image, longest write-barrier force), reported above 50 us (count: 50); last the omap run compaction and
/// tree-merge steps of a shard poll (adr 0476); then the checkpoint start's seal of the open WAL unit, the freeze's
/// pending-page order and arena, the freeze end's address fix-up of processed and live interior pages, and the size of
/// the unit the checkpoint start sealed (`ck_unit_kb`: payload bytes / 1000, a count not us); last the parts of a txn
/// submit (admission incl. elastic meta growth, WAL commit, reap of gone objects) and the elastic meta growth alone; the
/// client txn path (`Store::queue`: stage, prepare, apply).
pub const NAMES: [&str; 39] = [
    "pump",
    "ckpt_start",
    "bg_compact",
    "defrag",
    "pf_expire",
    "poll",
    "ckpt_slice",
    "ck_gc",
    "ck_hk",
    "ck_flush",
    "ck_begin",
    "ck_end",
    "ck_pages",
    "fz_settle",
    "fz_whole",
    "fz_emit",
    "fz_blob",
    "fz_force",
    "pm_comps",
    "pm_pre",
    "pm_ckpt",
    "pm_dead",
    "pm_wants",
    "c_devpoll",
    "c_page",
    "c_ckpt",
    "c_dead",
    "run_compact",
    "run_merge",
    "ck_seal",
    "fz_level",
    "fz_arena",
    "fz_remap",
    "ck_unit_kb",
    "sub_valid",
    "sub_commit",
    "sub_reap",
    "grow_meta",
    "queue",
];
/// First kind of the checkpoint start breakdown (lower report threshold).
const CK0: usize = 7;
const N: usize = NAMES.len();

thread_local! {
    static WIN: Cell<[u64; N]> = const { Cell::new([0; N]) };
    /// Sum and count per kind since the last [`take_all`] (bench averages).
    static SUM: Cell<[(u64, u64); N]> = const { Cell::new([(0, 0); N]) };
}

pub fn enable() {
    ON.store(true, Ordering::Relaxed);
}

/// Lab timeline (doc/perf/omap-p99-20261024.md): per core and window of `ms`, the core's busy time, the time in the
/// store sections [`TL_SECS`] and the store values [`TL_NAMES`] (deltas; gauges from [`TL_G0`] on as their last
/// value), one line per window with work ([`tl_take`]). Turns the section timing on.
pub fn tl_enable(ms: u64) {
    enable();
    TL_NS.store(ms.max(1) * 1_000_000, Ordering::Relaxed);
}

#[inline]
pub fn tl_on() -> bool {
    TL_NS.load(Ordering::Relaxed) != 0
}

/// Store values of the timeline, set by `Store::poll` ([`tl_set`]): client txns, omap batches staged as runs, queued
/// txns that waited for run room, parked txns, merge slices, entries merged into the tree, entries compacted, WAL units
/// acked and their commit latency split in us (`ShardStats::cm_*_ns`: open, queue, device, post), checkpoint KiB written,
/// then the gauges: run pool bytes and its soft size (KiB), this core's run memory (KiB), live run entries, a merge in progress
/// (1), dirty tree pages, runs held, entries of those runs killed by later tree ops (merged or superseded, still held:
/// a listing steps over them).
/// Values per timeline line ([`TL_NAMES`]).
pub const TL_N: usize = 21;
pub const TL_NAMES: [&str; TL_N] = [
    "txns",
    "run_puts",
    "run_waits",
    "parks",
    "merges",
    "merged",
    "compacted",
    "acks",
    "ack_open_us",
    "ack_q_us",
    "ack_dev_us",
    "ack_post_us",
    "ckpt_kib",
    "pool_kib",
    "soft_kib",
    "run_kib",
    "live",
    "merging",
    "dirty",
    "runs",
    "dead",
];
/// First gauge of [`TL_NAMES`].
pub const TL_G0: usize = 13;
/// Sections of the timeline (indices into [`NAMES`]): whole store poll, compaction, merge, client txn path.
const TL_SECS: [usize; 4] = [5, 27, 28, 38];

#[derive(Clone, Copy)]
struct Tl {
    start: Option<std::time::Instant>,
    busy: u64,
    secs: [u64; 4],
    vals: [u64; TL_N],
}

thread_local! {
    static TLV: Cell<[u64; TL_N]> = const { Cell::new([0; TL_N]) };
    static TLW: Cell<Tl> = const { Cell::new(Tl { start: None, busy: 0, secs: [0; 4], vals: [0; TL_N] }) };
}

/// The store's current timeline values of this core ([`TL_NAMES`]).
pub fn tl_set(v: [u64; TL_N]) {
    TLV.with(|c| c.set(v));
}

/// Core loop, after each iteration (`busy_ns`: the core's busy time so far): once the window passed, its line
/// `tl win_us=.. busy_us=.. poll_us=.. compact_us=.. merge_us=.. queue_us=.. <name>=<value>...` (None before, or for a
/// window without client txns or run maintenance), and the next window starts.
pub fn tl_take(busy_ns: u64) -> Option<String> {
    let win = TL_NS.load(Ordering::Relaxed);
    if win == 0 {
        return None;
    }
    let now = std::time::Instant::now();
    let mut w = TLW.with(|c| c.get());
    let sums = SUM.with(|c| c.get());
    let secs = TL_SECS.map(|k| sums[k].0);
    let vals = TLV.with(|c| c.get());
    let Some(st) = w.start else {
        TLW.with(|c| {
            c.set(Tl {
                start: Some(now),
                busy: busy_ns,
                secs,
                vals,
            })
        });
        return None;
    };
    let el = (now - st).as_nanos() as u64;
    if el < win {
        return None;
    }
    let d: Vec<u64> = (0..4)
        .map(|i| secs[i].saturating_sub(w.secs[i]) / 1000)
        .collect();
    let work = d[1] + d[2] + d[3] > 0 || (0..TL_G0).any(|i| vals[i] != w.vals[i]);
    let line = work.then(|| {
        let mut l = format!(
            "tl win_us={} busy_us={} poll_us={} compact_us={} merge_us={} queue_us={}",
            el / 1000,
            busy_ns.saturating_sub(w.busy) / 1000,
            d[0],
            d[1],
            d[2],
            d[3]
        );
        for (i, n) in TL_NAMES.iter().enumerate() {
            let v = if i < TL_G0 {
                vals[i].saturating_sub(w.vals[i])
            } else {
                vals[i]
            };
            l.push_str(&format!(" {n}={v}"));
        }
        l
    });
    w = Tl {
        start: Some(now),
        busy: busy_ns,
        secs,
        vals,
    };
    TLW.with(|c| c.set(w));
    line
}

#[inline]
pub fn on() -> bool {
    ON.load(Ordering::Relaxed)
}

/// Lab timer of a section (None = diag off: no clock read).
#[inline]
pub fn t0() -> Option<std::time::Instant> {
    on().then(std::time::Instant::now)
}

/// Note the time since `t` as `kind` and restart `t`.
#[inline]
pub fn lap(kind: usize, t: &mut Option<std::time::Instant>) {
    if let Some(s) = t {
        let n = std::time::Instant::now();
        note(kind, (n - *s).as_nanos() as u64);
        *s = n;
    }
}

/// Record a section of `ns` (kept if it is the window's longest of its kind).
#[inline]
pub fn note(kind: usize, ns: u64) {
    SUM.with(|w| {
        let mut a = w.get();
        a[kind].0 += ns;
        a[kind].1 += 1;
        w.set(a);
    });
    WIN.with(|w| {
        let mut a = w.get();
        if ns > a[kind] {
            a[kind] = ns;
            w.set(a);
        }
    });
}

/// The window's longest sections above 500 us as `name=us` pairs (None if none), and reset the window.
pub fn take() -> Option<String> {
    let a = WIN.with(|w| w.replace([0; N]));
    let parts: Vec<String> = (0..N)
        .filter(|&i| a[i] > if i >= CK0 { 50_000 } else { 500_000 })
        .map(|i| format!("{}={}", NAMES[i], a[i] / 1000))
        .collect();
    (!parts.is_empty()).then(|| parts.join(","))
}

/// Every section since the last call: `name max/avg` in us (`ck_pages`: pages), and reset (bench).
pub fn take_all() -> String {
    let a = WIN.with(|w| w.replace([0; N]));
    let s = SUM.with(|w| w.replace([(0, 0); N]));
    (0..N)
        .filter(|&i| a[i] > 0)
        .map(|i| {
            format!(
                "{} {}/{}",
                NAMES[i],
                a[i] / 1000,
                s[i].0 / s[i].1.max(1) / 1000
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    #[test]
    fn keeps_the_longest_per_kind_and_resets() {
        super::note(0, 700_000);
        super::note(0, 600_000);
        super::note(2, 100_000);
        assert_eq!(super::take().as_deref(), Some("pump=700"));
        assert_eq!(super::take(), None);
    }

    /// The timeline prints the section indices of `TL_SECS` under their own names ([`super::TL_NAMES`] order).
    #[test]
    fn timeline_sections_are_the_named_ones() {
        assert_eq!(
            super::TL_SECS.map(|k| super::NAMES[k]),
            ["poll", "run_compact", "run_merge", "queue"]
        );
    }
}
