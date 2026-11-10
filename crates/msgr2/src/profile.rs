// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Optional sampled thread-local stage CPU/wall aggregates. See client-stage-profile ADR.
use std::{marker::PhantomData, rc::Rc};

/// Thread-bound, nestable diagnostic scope. Empty in ordinary builds.
#[derive(Debug)]
pub struct Span {
    #[cfg(feature = "profile")]
    active: Option<enabled::Active>,
    thread_bound: PhantomData<Rc<()>>,
}
#[inline]
pub fn span(name: &'static str, bytes: usize) -> Span {
    #[cfg(feature = "profile")]
    let active = enabled::enter(name, bytes);
    #[cfg(not(feature = "profile"))]
    let _ = (name, bytes);
    Span {
        #[cfg(feature = "profile")]
        active,
        thread_bound: PhantomData,
    }
}
#[cfg(feature = "profile")]
impl Drop for Span {
    fn drop(&mut self) {
        if let Some(active) = self.active.take() {
            enabled::exit(active);
        }
    }
}
/// Flush this thread's completed aggregates, only outside all scopes.
/// No thread-local destructor is registered; application threads must flush explicitly.
pub fn flush() {
    #[cfg(feature = "profile")]
    enabled::flush();
}

#[cfg(all(test, not(feature = "profile")))]
mod disabled_tests {
    #[test]
    fn ordinary_scope_has_no_storage_or_destructor() {
        assert_eq!(std::mem::size_of::<super::Span>(), 0);
        assert!(!std::mem::needs_drop::<super::Span>());
        let _scope = super::span("disabled", usize::MAX);
    }
}

#[cfg(feature = "profile")]
mod enabled {
    use std::{
        cell::RefCell,
        io::Write,
        path::PathBuf,
        sync::{
            OnceLock,
            atomic::{AtomicU64, Ordering},
        },
        time::Instant,
    };
    const SLOTS: usize = 32;
    #[derive(Clone, Copy, Debug)]
    struct Metric {
        name: &'static str,
        calls: u64,
        bytes: u64,
        wall: u64,
        own_wall: u64,
        cpu: u64,
        own_cpu: u64,
        cpu_calls: u64,
        max_wall: u64,
        buckets: [u64; 64],
    }
    impl Metric {
        const fn new(name: &'static str) -> Self {
            Self {
                name,
                calls: 0,
                bytes: 0,
                wall: 0,
                own_wall: 0,
                cpu: 0,
                own_cpu: 0,
                cpu_calls: 0,
                max_wall: 0,
                buckets: [0; 64],
            }
        }
        fn add(&mut self, bytes: usize, wall: u64, own_wall: u64, cpu: Option<(u64, u64)>) {
            self.calls = self.calls.saturating_add(1);
            self.bytes = self.bytes.saturating_add(bytes as u64);
            self.wall = self.wall.saturating_add(wall);
            self.own_wall = self.own_wall.saturating_add(own_wall);
            self.max_wall = self.max_wall.max(wall);
            self.buckets[(63 - wall.max(1).leading_zeros()) as usize] += 1;
            if let Some((total, own)) = cpu {
                self.cpu_calls += 1;
                self.cpu = self.cpu.saturating_add(total);
                self.own_cpu = self.own_cpu.saturating_add(own);
            }
        }
    }
    struct State {
        depth: usize,
        selected: bool,
        roots: u64,
        sequence: u64,
        own_wall: u64,
        own_cpu: u64,
        slots: [Option<Metric>; SLOTS],
        overflow: u64,
        clock_errors: u64,
        thread: u64,
        batch: u64,
    }
    impl State {
        const fn new() -> Self {
            Self {
                depth: 0,
                selected: false,
                roots: 0,
                sequence: 0,
                own_wall: 0,
                own_cpu: 0,
                slots: [None; SLOTS],
                overflow: 0,
                clock_errors: 0,
                thread: 0,
                batch: 0,
            }
        }
        fn select(&mut self, period: u64) -> bool {
            if self.depth == 0 {
                self.roots = self.roots.wrapping_add(1);
                self.sequence = self.sequence.wrapping_add(1);
                // Hash root identity: periodic API phases must not alias a fixed sampling stride.
                let mut mixed = self.sequence.wrapping_add(0x9e37_79b9_7f4a_7c15);
                mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                self.selected = period == 1 || (mixed ^ (mixed >> 31)).is_multiple_of(period);
            }
            self.depth += 1;
            self.selected
        }
        fn record(&mut self, start: &Start, wall: u64, cpu: Option<u64>) {
            let own_wall = wall.saturating_sub(self.own_wall.saturating_sub(start.child_wall));
            let own_cpu = cpu.map(|total| {
                (
                    total,
                    total.saturating_sub(self.own_cpu.saturating_sub(start.child_cpu)),
                )
            });
            self.own_wall = self.own_wall.saturating_add(own_wall);
            if let Some((_, own)) = own_cpu {
                self.own_cpu = self.own_cpu.saturating_add(own);
            } else {
                self.clock_errors += 1;
            }
            if let Some(i) = start.slot {
                self.slots[i]
                    .as_mut()
                    .unwrap()
                    .add(start.bytes, wall, own_wall, own_cpu);
            }
        }
        fn slot(&mut self, name: &'static str) -> Option<usize> {
            if name.is_empty()
                || name.len() > 64
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            {
                self.overflow += 1;
                return None;
            }
            if let Some(i) = self
                .slots
                .iter()
                .position(|s| s.is_some_and(|m| m.name == name))
            {
                return Some(i);
            }
            if let Some(i) = self.slots.iter().position(Option::is_none) {
                self.slots[i] = Some(Metric::new(name));
                return Some(i);
            }
            self.overflow += 1;
            None
        }
    }
    thread_local! { static STATE: RefCell<State> = const { RefCell::new(State::new()) }; }
    struct Config {
        directory: PathBuf,
        period: u64,
    }
    static CONFIG: OnceLock<Option<Config>> = OnceLock::new();
    static THREAD: AtomicU64 = AtomicU64::new(1);
    fn config() -> Option<&'static Config> {
        CONFIG
            .get_or_init(|| {
                let directory = std::env::var_os("RUSTYRADOS_PROFILE_DIR")?;
                let period = match std::env::var("RUSTYRADOS_PROFILE_SAMPLE") {
                    Ok(n) => match n.parse::<u64>() {
                        Ok(n) if n > 0 => n,
                        _ => {
                            diag::diag!("WARNING client-profile invalid RUSTYRADOS_PROFILE_SAMPLE");
                            return None;
                        }
                    },
                    Err(std::env::VarError::NotPresent) => 100,
                    Err(_) => {
                        diag::diag!("WARNING client-profile invalid RUSTYRADOS_PROFILE_SAMPLE");
                        return None;
                    }
                };
                let directory = PathBuf::from(directory);
                if !directory.is_dir() {
                    diag::diag!("WARNING client-profile directory does not exist");
                    return None;
                }
                Some(Config { directory, period })
            })
            .as_ref()
    }
    fn cpu() -> Option<u64> {
        #[cfg(target_os = "linux")]
        {
            let mut ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            // SAFETY: valid out-pointer, thread CPU clock has no external object lifetime.
            if unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) } != 0 {
                return None;
            }
            u64::try_from(ts.tv_sec)
                .ok()?
                .checked_mul(1_000_000_000)?
                .checked_add(u64::try_from(ts.tv_nsec).ok()?)
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }
    #[derive(Debug)]
    struct Start {
        wall: Instant,
        cpu: Option<u64>,
        child_wall: u64,
        child_cpu: u64,
        slot: Option<usize>,
        bytes: usize,
    }
    #[derive(Debug)]
    pub(super) struct Active {
        start: Option<Start>,
    }
    pub(super) fn enter(name: &'static str, bytes: usize) -> Option<Active> {
        let config = config()?;
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            let start = if state.select(config.period) {
                Some(Start {
                    cpu: cpu(),
                    wall: Instant::now(),
                    child_wall: state.own_wall,
                    child_cpu: state.own_cpu,
                    slot: state.slot(name),
                    bytes,
                })
            } else {
                None
            };
            Some(Active { start })
        })
    }
    pub(super) fn exit(active: Active) {
        let measured = active.start.map(|start| {
            let wall = u64::try_from(start.wall.elapsed().as_nanos()).unwrap_or(u64::MAX);
            let cpu = cpu()
                .zip(start.cpu)
                .and_then(|(end, begin)| end.checked_sub(begin));
            (start, wall, cpu)
        });
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.depth -= 1;
            if let Some((start, wall, cpu)) = measured {
                state.record(&start, wall, cpu);
            }
        });
    }
    pub(super) fn flush() {
        let Some(config) = config() else {
            return;
        };
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            if state.depth != 0 || !state.slots.iter().any(Option::is_some) { return; }
            if state.thread == 0 { state.thread = THREAD.fetch_add(1, Ordering::Relaxed); }
            let path = config.directory.join(format!("client-profile-{}-{}.jsonl", std::process::id(), state.thread));
            let result = (|| -> std::io::Result<()> {
                let mut file = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
                for metric in state.slots.iter().flatten() {
                    // Labels were validated before registration; no payload names.
                    let hist = metric.buckets.iter().map(u64::to_string).collect::<Vec<_>>().join(",");
                    writeln!(file, "{{\"schema\":1,\"pid\":{},\"thread\":{},\"batch\":{},\"sample_period\":{},\"root_calls\":{},\"stage\":\"{}\",\"samples\":{},\"bytes\":{},\"wall_ns\":{},\"self_wall_ns\":{},\"cpu_samples\":{},\"cpu_ns\":{},\"self_cpu_ns\":{},\"max_wall_ns\":{},\"wall_log2_ns\":[{}],\"stage_overflow\":{},\"clock_errors\":{}}}",std::process::id(),state.thread,state.batch,config.period,state.roots,metric.name,metric.calls,metric.bytes,metric.wall,metric.own_wall,metric.cpu_calls,metric.cpu,metric.own_cpu,metric.max_wall,hist,state.overflow,state.clock_errors)?;
                }
                Ok(())
            })();
            if let Err(error) = result { diag::diag!("WARNING client-profile output failed: {error}"); }
            state.slots = [None; SLOTS];
            state.roots = 0;
            state.own_wall = 0;
            state.own_cpu = 0;
            state.overflow = 0;
            state.clock_errors = 0;
            state.batch += 1;
        });
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn root_sampling_keeps_nested_spans_together() {
            let mut state = State::new();
            let mut phases = [0usize; 2];
            for root in 0..2000 {
                let chosen = state.select(100);
                assert_eq!(
                    state.select(100),
                    chosen,
                    "nested scopes share the root decision"
                );
                if chosen {
                    phases[root % 2] += 1;
                }
                state.depth -= 2;
            }
            assert!(
                phases.iter().all(|n| *n > 0),
                "input and submit phases must both be sampled: {phases:?}"
            );
            assert!(state.select(1));
        }
        #[test]
        fn bounded_labels_and_histogram_do_not_grow() {
            let mut state = State::new();
            assert_eq!(state.slot("encode"), Some(0));
            assert_eq!(state.slot("encode"), Some(0));
            for i in 1..SLOTS {
                state.slots[i] = Some(Metric::new("occupied"));
            }
            assert_eq!(state.slot("overflow"), None);
            assert_eq!(state.overflow, 1);
            let mut m = Metric::new("test");
            m.add(12, 16, 10, Some((9, 3)));
            m.add(4, 0, 0, None);
            assert_eq!(
                (
                    m.calls,
                    m.bytes,
                    m.wall,
                    m.own_wall,
                    m.cpu_calls,
                    m.cpu,
                    m.own_cpu
                ),
                (2, 16, 16, 10, 1, 9, 3)
            );
            assert_eq!((m.buckets[4], m.buckets[0], m.max_wall), (1, 1, 16));
        }
        #[test]
        fn nested_cpu_and_wall_partition_without_double_counting() {
            let mut state = State::new();
            let root = state.slot("root");
            let child = state.slot("child");
            let leaf = state.slot("leaf");
            let start = |slot, child_wall, child_cpu| Start {
                wall: Instant::now(),
                cpu: Some(0),
                child_wall,
                child_cpu,
                slot,
                bytes: 4,
            };
            state.record(&start(leaf, 0, 0), 20, Some(10));
            state.record(&start(child, 0, 0), 60, Some(30));
            state.record(&start(root, 0, 0), 100, Some(50));
            assert_eq!(state.own_wall, 100);
            assert_eq!(state.own_cpu, 50);
            let m = state.slots[0].unwrap();
            assert_eq!((m.wall, m.own_wall, m.cpu, m.own_cpu), (100, 40, 50, 20));
            state.record(&start(root, 100, 50), 40, None);
            assert_eq!(state.own_wall, 140);
            assert_eq!(state.own_cpu, 50);
            assert_eq!(state.clock_errors, 1);
            assert_eq!(state.slots[0].unwrap().cpu_calls, 1);
        }
        #[test]
        fn tls_requires_no_destructor_even_in_dlopen_library() {
            assert!(!std::mem::needs_drop::<State>());
        }
    }
}
