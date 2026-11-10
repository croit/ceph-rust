// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! What the multi-core launchers (kernel tier `kprod.rs`) share: building the OSD of one core
//! (core 0 = control plane reading identity / superblock, workers wait for them) on its slice of the store shards.
use nvme::any::AnyDev;
use osd::nvmestore::{mount_dev_core, open_nvme, open_nvme_pgs};
use osd::{CoreSpec, Identity, Osd, OsdConfig};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

/// The backend of a device-backed OSD.
pub(crate) type Be = osd::Nvme<AnyDev, store::dev::MonoClock>;

/// Process-wide facts of a multi-core OSD.
pub(crate) struct Boot {
    pub ocfg: OsdConfig,
    pub cores: usize,
    /// Actual selected service CPU IDs, shared by both transport launchers.
    pub cpus: Vec<usize>,
    /// Cores with a network endpoint (NIC queue / io_uring).
    pub nets: usize,
    pub shards: u32,
    pub ingress: osd::IngressCredits,
    /// Identity + superblock of core 0 (workers are built from them) or the reason core 0 failed.
    pub boot: BootFacts,
    pub t0: Instant,
}

pub(crate) fn say(core: usize, s: &str) {
    println!("[core {core}] {s}");
}

pub(crate) fn fail(m: impl std::fmt::Display) -> i32 {
    eprintln!("croit-flashstore-osd: {m}");
    1
}

/// Identity + superblock of core 0, or the reason it failed ([`Boot::boot`]).
type BootFacts = OnceLock<Result<(Identity, messages::OsdSuperblock), String>>;

/// Core `id` ended with `r` (its run, or the error that ended its startup); returns its exit code. No core runs without
/// the others (adr 0031), so any core that ends ends the OSD: `sig` makes core 0 shut down like on SIGTERM (mon
/// mark-down), `stop` ends the workers (also one still in [`wait_boot`]) and every core is woken. A failed startup of
/// core 0 also answers the workers waiting for its identity.
pub(crate) fn core_end(
    id: usize,
    r: Result<i32, String>,
    boot: &BootFacts,
    sig: &AtomicBool,
    stop: &AtomicBool,
    wakes: Option<&[Arc<rt::wake::Wake>]>,
) -> i32 {
    let code = match r {
        Ok(c) => c,
        Err(e) => {
            eprintln!("croit-flashstore-osd: core {id}: FATAL: {e}");
            if id == 0 {
                let _ = boot.set(Err(e));
            }
            1
        }
    };
    sig.store(true, Ordering::SeqCst);
    stop.store(true, Ordering::SeqCst);
    for w in wakes.into_iter().flatten() {
        w.ring();
    }
    code
}

/// Process exit code of the cores' codes (core order): the first failure, else 0. A failed worker fails the OSD even
/// when core 0 then shut down cleanly.
pub(crate) fn exit_code(codes: &[i32]) -> i32 {
    match codes.iter().find(|&&c| c != 0) {
        Some(&c) => c,
        None if codes.is_empty() => 1,
        None => 0,
    }
}

/// Mount core `id`'s shards and build its OSD. Core 0 also sets up logging / admin socket (the returned guard lives
/// until the core is done).
pub(crate) fn build_osd(
    b: &Boot,
    id: usize,
    queues: Vec<AnyDev>,
    stop: &AtomicBool,
) -> Result<(Osd<Be>, Option<crate::obs::Obs>), String> {
    let spec = CoreSpec::new(id, b.cores, b.nets, b.shards)?;
    let t_mount = Instant::now();
    let (store, rs) = mount_dev_core(queues, id, &b.cpus, b.shards)?;
    // one line per core: the replay cost a clean shutdown (final checkpoint) could save (adr 0034 am. 1)
    println!(
        "croit-flashstore-osd: core {id}: store mounted, replayed {} txns / {} units / {} wal blocks in {} ms",
        rs.iter().map(|s| s.txns).sum::<u64>(),
        rs.iter().map(|s| s.units).sum::<u64>(),
        rs.iter().map(|s| s.wal_blocks_read).sum::<u64>(),
        t_mount.elapsed().as_millis()
    );
    if id == 0 {
        let parts = open_nvme(store).map_err(|e| e.to_string())?;
        let mut o = Osd::<Be>::control(b.ocfg.clone(), parts.meta, parts.pgs, spec)?;
        o.set_ingress_credits(b.ingress.clone());
        o.set_liveness(&osd::liveness::LIVENESS);
        let obs = crate::obs::setup(&mut o);
        let _ = b
            .boot
            .set(Ok((o.identity().clone(), o.superblock().clone())));
        Ok((o, Some(obs)))
    } else {
        let (ident, sb) = wait_boot(b, stop)?;
        let pg = open_nvme_pgs(store).map_err(|e| e.to_string())?;
        let mut o = Osd::<Be>::worker(b.ocfg.clone(), ident, sb, pg, spec)?;
        o.set_ingress_credits(b.ingress.clone());
        o.set_liveness(&osd::liveness::LIVENESS);
        Ok((o, None))
    }
}

/// Workers wait for core 0's identity / superblock (it reads them from the meta store on shard 0).
fn wait_boot(b: &Boot, stop: &AtomicBool) -> Result<(Identity, messages::OsdSuperblock), String> {
    let end = Instant::now() + Duration::from_secs(120);
    loop {
        if let Some(r) = b.boot.get() {
            return r.clone();
        }
        if stop.load(Ordering::Relaxed) || Instant::now() > end {
            if !stop.load(Ordering::Relaxed) {
                eprintln!(
                    "WARNING TIMEOUT worker boot wait exceeded 120s (core 0 did not come up)"
                );
            }
            return Err("core 0 did not come up".into());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NT-rt-04: a worker whose startup fails before its event loop stops core 0 and the other workers (no stranded
    /// launcher) and the process exits nonzero although core 0 then shuts down cleanly.
    #[test]
    fn a_failed_worker_startup_ends_every_core_and_fails_the_process() {
        let boot = Arc::new(BootFacts::new());
        let sig = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let wakes: Arc<[Arc<rt::wake::Wake>]> =
            (0..3).map(|_| rt::wake::Wake::new().unwrap()).collect();
        let cores: Vec<_> = (0..3)
            .map(|id| {
                let (boot, sig, stop, wakes) = (boot.clone(), sig.clone(), stop.clone(), wakes.clone());
                std::thread::spawn(move || {
                    let r = if id == 1 {
                        Err("mount: injected failure".to_owned())
                    } else {
                        // core 0 runs until `sig`, the other worker until `stop` (the event loops' stop flags)
                        let flag = if id == 0 { &sig } else { &stop };
                        let end = Instant::now() + Duration::from_secs(5);
                        loop {
                            if flag.load(Ordering::SeqCst) {
                                break Ok(0);
                            }
                            if Instant::now() > end {
                                eprintln!("WARNING TIMEOUT core {id} stop wait exceeded 5s (worker failure not propagated)");
                                break Ok(0);
                            }
                            std::thread::sleep(Duration::from_millis(1));
                        }
                    };
                    let code = core_end(id, r, &boot, &sig, &stop, Some(&wakes));
                    (code, sig.load(Ordering::SeqCst) && stop.load(Ordering::SeqCst))
                })
            })
            .collect();
        let ends: Vec<_> = cores.into_iter().map(|h| h.join().unwrap()).collect();
        let codes: Vec<i32> = ends.iter().map(|e| e.0).collect();
        assert_eq!(codes, [0, 1, 0]);
        assert!(
            ends[0].1 && ends[2].1,
            "core 0 and worker 2 ended on the stop flags, not a timeout"
        );
        assert_eq!(exit_code(&codes), 1, "a failed worker fails the process");
        assert!(
            boot.get().is_none(),
            "a worker failure does not pose as core 0's boot result"
        );
    }

    #[test]
    fn exit_code_is_the_first_failure() {
        assert_eq!(exit_code(&[0, 0, 0]), 0);
        assert_eq!(exit_code(&[0, 3, 1]), 3);
        assert_eq!(exit_code(&[2, 1]), 2);
        assert_eq!(exit_code(&[]), 1);
    }
}
