// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Per-class `cls_unsupported` counters and the once-per-hour clog gate (rgw-gap G26, cls side).
//!
//! The executor calls [`note`] whenever classification fails (unknown class or method). Counters
//! are relaxed atomics (cold path only); the executor exports them (`cls list` tell, perf dump) and
//! uses [`ClogGate`] to emit at most one cluster-log line per (class, pool) per hour.

use crate::registry::CLASSES;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// Counter slots: every registry class, then the classes croit-flashstore-osd does not provide (`lua`),
/// then one shared slot for every other name.
const EXTRA: &[&str] = &["lua"];
const N: usize = CLASSES.len() + EXTRA.len() + 1;
static COUNTS: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];

fn name(slot: usize) -> &'static str {
    CLASSES
        .iter()
        .chain(EXTRA)
        .nth(slot)
        .copied()
        .unwrap_or("other")
}

fn slot(class: &str) -> usize {
    CLASSES
        .iter()
        .chain(EXTRA)
        .position(|c| *c == class)
        .unwrap_or(N - 1)
}

/// Count one refused call of `class`; returns its slot.
pub fn note(class: &str) -> usize {
    let s = slot(class);
    COUNTS[s].fetch_add(1, Ordering::Relaxed);
    s
}

pub fn counts() -> Vec<(&'static str, u64)> {
    (0..N)
        .filter_map(|i| {
            let n = COUNTS[i].load(Ordering::Relaxed);
            (n > 0).then(|| (name(i), n))
        })
        .collect()
}

/// Count for one class (tests, tell).
pub fn count(class: &str) -> u64 {
    COUNTS[slot(class)].load(Ordering::Relaxed)
}

/// At most one clog line per (class, pool) per [`ClogGate::PERIOD_SECS`] (one hour).
#[derive(Debug, Default)]
pub struct ClogGate {
    last: HashMap<(String, i64), u64>,
}
impl ClogGate {
    pub const PERIOD_SECS: u64 = 3600;
    pub fn new() -> Self {
        Self::default()
    }
    /// True if a line should be emitted now (and records it).
    pub fn should_log(&mut self, class: &str, pool: i64, now_secs: u64) -> bool {
        let k = (class.to_owned(), pool);
        match self.last.get(&k) {
            Some(t) if now_secs < t.saturating_add(Self::PERIOD_SECS) => false,
            _ => {
                self.last.insert(k, now_secs);
                true
            }
        }
    }
}
