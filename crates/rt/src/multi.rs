// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Spawning N pinned cores that share nothing but the [`mesh`](crate::mesh). Each core gets a [`CoreCtx`] (its index,
//! its mesh endpoint, the stop flag) and builds its own OSD state *inside* its thread, so
//! nothing non-`Send` ever crosses threads.
use crate::mesh::{Endpoint, mesh, mesh_store};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

/// What a core thread receives.
#[derive(Debug)]
pub struct CoreCtx<T> {
    /// Core index (also: PG-core index).
    pub id: usize,
    /// Number of cores.
    pub cores: usize,
    /// Cross-core message endpoint.
    pub ep: Endpoint<T>,
    /// Set on shutdown.
    pub stop: Arc<AtomicBool>,
}

impl<T> CoreCtx<T> {
    /// True once shutdown was requested.
    pub fn stopping(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }
}

/// Running cores.
#[derive(Debug)]
pub struct Cores<R> {
    stop: Arc<AtomicBool>,
    handles: Vec<JoinHandle<R>>,
}

/// Spawn `n` core threads; core `i` is pinned to cpu `cpus[i]` (Linux; no-op elsewhere) and runs `body`.
/// `ring_cap` = slots per cross-core ring.
pub fn spawn_cores<T, R>(
    n: usize,
    cpus: &[usize],
    ring_cap: usize,
    body: impl Fn(CoreCtx<T>) -> R + Send + Sync + 'static,
) -> Cores<R>
where
    T: Send + 'static,
    R: Send + 'static,
{
    spawn_endpoints(mesh::<T>(n, ring_cap), cpus, body)
}

/// OSD cores use physical-shard lanes and reserved control/progress lanes.
pub fn spawn_osd_cores<R: Send + 'static>(
    n: usize,
    cpus: &[usize],
    ring_cap: usize,
    shards: usize,
    body: impl Fn(CoreCtx<osd::XMsg>) -> R + Send + Sync + 'static,
) -> Cores<R> {
    spawn_endpoints(mesh_store(n, ring_cap, shards), cpus, body)
}

fn spawn_endpoints<T: Send + 'static, R: Send + 'static>(
    endpoints: Vec<Endpoint<T>>,
    cpus: &[usize],
    body: impl Fn(CoreCtx<T>) -> R + Send + Sync + 'static,
) -> Cores<R> {
    let n = endpoints.len();
    let pinned: Vec<usize> = (0..n)
        .map(|id| cpus.get(id).copied().unwrap_or(id))
        .collect();
    // helper threads (admin socket, log) keep off these CPUs
    crate::set_core_cpus(&pinned);
    let stop = Arc::new(AtomicBool::new(false));
    let body = Arc::new(body);
    let handles = endpoints
        .into_iter()
        .map(|ep| {
            let (stop, body) = (stop.clone(), body.clone());
            let id = ep.id();
            let cpu = cpus.get(id).copied().unwrap_or(id);
            std::thread::Builder::new()
                .name(format!("core{id}"))
                .spawn(move || {
                    if let Err(e) = crate::pin_current_thread(cpu) {
                        // thread-per-core placement is lost (cpu outside the allowed set): never silent
                        eprintln!("croit-flashstore-osd: WARNING: core {id}: pin to cpu {cpu}: {e} (continuing unpinned)");
                    }
                    body(CoreCtx {
                        id,
                        cores: n,
                        ep,
                        stop,
                    })
                })
                .expect("spawn core thread")
        })
        .collect();
    Cores { stop, handles }
}

impl<R> Cores<R> {
    /// Ask all cores to stop (they poll `CoreCtx::stopping`).
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Wait for every core; results in core order.
    pub fn join(self) -> Vec<R> {
        self.handles
            .into_iter()
            .map(|h| h.join().expect("core thread panicked"))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cores_exchange_and_stop() {
        let c = spawn_cores::<u64, u64>(3, &[0, 1, 2], 16, |mut cx| {
            let mut sum = 0;
            let mut sent = 0;
            while !cx.stopping() {
                let dst = (cx.id + 1) % cx.cores;
                if sent < 100 && cx.ep.send(dst, 1).is_ok() {
                    sent += 1;
                }
                cx.ep.drain(8, |_, v| sum += v);
                if sum == 100 && sent == 100 {
                    break;
                }
            }
            sum
        });
        assert_eq!(c.join(), vec![100, 100, 100]);
    }
}
