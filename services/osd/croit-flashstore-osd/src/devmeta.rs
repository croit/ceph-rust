// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Device identity + SMART for `ceph device ls` / devicehealth: publish the identity before the OSD boots and
//! refresh the SMART snapshot from a slow background thread (admin commands only, never on a core).
//! SPDK devices use the controller admin queue; lab `file:/dev/nvmeXnY` uses the kernel passthrough ioctl.
//!
//! The thread is owned ([`Refresh`]): the caller keeps it until it returns from `main`, and dropping it stops and joins
//! the thread. It must not outlive `main`: when SPDK initialized the DPDK EAL itself (knet tier with an `spdk:` device),
//! SPDK's exit-time destructor runs `rte_eal_cleanup`, which unmaps the hugepage heap the log-page read allocates its DMA
//! buffer from (`exit()` with the read in flight = SIGSEGV in the DPDK heap, doc/perf/rdma-spike-20261019.md section 16).
use nvme::any::HealthProbe;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

const REFRESH: Duration = Duration::from_secs(300);

/// A thread that runs a job every period until dropped; drop wakes a waiting thread, lets a running job finish and joins.
#[derive(Debug)]
pub struct Refresh {
    stop: Arc<(Mutex<bool>, Condvar)>,
    thread: Option<JoinHandle<()>>,
}

impl Refresh {
    /// Run `job` now and then every `period` on a thread named `name`. `None` (reported) when the thread cannot start.
    fn spawn(
        name: &str,
        period: Duration,
        mut job: impl FnMut() + Send + 'static,
    ) -> Option<Refresh> {
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let s = stop.clone();
        let t = std::thread::Builder::new()
            .name(name.into())
            .spawn(move || {
                let (m, cv) = &*s;
                loop {
                    job();
                    let g = m.lock().unwrap_or_else(PoisonError::into_inner);
                    let (g, _) = cv
                        .wait_timeout_while(g, period, |stopped| !*stopped)
                        .unwrap_or_else(PoisonError::into_inner);
                    if *g {
                        return;
                    }
                }
            });
        match t {
            Ok(t) => Some(Refresh {
                stop,
                thread: Some(t),
            }),
            Err(e) => {
                eprintln!("croit-flashstore-osd: {name} thread: {e} (not refreshed)");
                None
            }
        }
    }
}

impl Drop for Refresh {
    fn drop(&mut self) {
        let (m, cv) = &*self.stop;
        *m.lock().unwrap_or_else(PoisonError::into_inner) = true;
        cv.notify_all();
        if let Some(t) = self.thread.take()
            && t.join().is_err()
        {
            eprintln!("croit-flashstore-osd: refresh thread panicked");
        }
    }
}

/// Device name as classic reports it: the kernel block name when the kernel owns the device (kernel tier), else the PCI
/// address (SPDK tier: no kernel name exists).
fn dev_meta(
    kname: String,
    pci: String,
    ident: nvme::health::Ident,
    size_bytes: u64,
) -> nvme::health::DevMeta {
    let kernel = !kname.is_empty();
    nvme::health::DevMeta {
        name: if kernel { kname } else { pci.clone() },
        pci,
        kernel,
        ident,
        size_bytes,
    }
}

/// Where the SMART data comes from (adr 0056 am. 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    /// NVMe admin command on our own handle (SPDK admin queue, or kernel passthrough when the kernel allows it).
    Direct,
    /// Classic: `sudo -n smartctl` / `sudo -n nvme <vendor> smart-log-add` (kernel tier, admin command denied).
    Sudo,
}

/// Route after a direct read failed: a permission error on a kernel device (it has a `/dev` name sudo can address)
/// switches to the classic route; everything else stays and is reported.
fn route_after_direct_error(e: &nvme::health::SmartError, kernel: bool) -> Route {
    match e {
        nvme::health::SmartError::Denied(_) if kernel => Route::Sudo,
        _ => Route::Direct,
    }
}

const SUDO_HINT: &str = "needs smartctl, the sudoers rule of the ceph packages (/etc/sudoers.d/ceph-smartctl: `ceph ALL=NOPASSWD: \
    /usr/sbin/smartctl -x --json=o /dev/*` and `/usr/sbin/nvme * smart-log-add --json /dev/*`) and a unit with \
    NoNewPrivileges=false";

/// Publish the device identity and start the SMART refresh thread (`None`: not an NVMe device, or no thread). Keep the
/// result until the daemon returns from `main` (module doc).
pub fn start(probe: HealthProbe, pci: String, size_bytes: u64) -> Option<Refresh> {
    let meta = dev_meta(probe.kernel_name(), pci, probe.ident(), size_bytes);
    // not an NVMe device (regular file, virtio): nothing to report
    if meta.ident.device_id().is_empty() && meta.kernel {
        return None;
    }
    nvme::health::set_device(meta.clone());
    let mut route = Route::Direct;
    let mut said: Option<String> = None;
    // each distinct message is printed once (a failing route retries every period without flooding the log)
    let mut say = move |m: String| {
        if said.as_deref() != Some(&m) {
            eprintln!("croit-flashstore-osd: smart: {m}");
            said = Some(m);
        }
    };
    Refresh::spawn("smart", REFRESH, move || {
        if route == Route::Direct {
            match probe.smart() {
                Ok(s) => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs());
                    nvme::health::set_smart_json(nvme::health::render_smartctl_json(
                        &meta, &s, now,
                    ));
                    say("route: direct NVMe admin command".into());
                    return;
                }
                Err(e) => {
                    route = route_after_direct_error(&e, meta.kernel);
                    if route == Route::Direct {
                        say(format!("smart log: {e}"));
                        return;
                    }
                    say(format!(
                        "direct admin command denied ({e}); using the classic route sudo -n smartctl"
                    ));
                }
            }
        }
        let v = crate::smartctl::metrics(
            &meta.name,
            &crate::smartctl::read_vendor(&meta.name),
            &crate::smartctl::run_sudo,
        );
        match crate::smartctl::failure(&v) {
            Some(e) => say(format!(
                "route sudo failed: {e} for /dev/{} ({SUDO_HINT})",
                meta.name
            )),
            None => say("route: classic sudo -n smartctl".into()),
        }
        nvme::health::set_smart_json(v.to_string());
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::time::Instant;

    /// Kernel tier: the kernel block name wins over the PCI address (classic `ceph device ls` shows `host:nvme2n1`);
    /// SPDK tier (no kernel name): the PCI address.
    #[test]
    fn device_name_kernel_vs_spdk() {
        let id = nvme::health::Ident::default();
        let k = dev_meta("nvme2n1".into(), "0000:01:00.0".into(), id.clone(), 1);
        assert_eq!((k.name.as_str(), k.kernel), ("nvme2n1", true));
        assert_eq!(k.path(), "pci-0000:01:00.0-nvme-1");
        let s = dev_meta(String::new(), "0000:01:00.0".into(), id.clone(), 1);
        assert_eq!((s.name.as_str(), s.kernel), ("0000:01:00.0", false));
        let n = dev_meta("nvme0n1".into(), String::new(), id, 1);
        assert_eq!((n.name.as_str(), n.path().as_str()), ("nvme0n1", ""));
    }

    /// Fallback decision: only a permission error on a kernel device selects the classic sudo route.
    #[test]
    fn sudo_route_only_on_denied_kernel_device() {
        use nvme::health::SmartError::{Denied, Failed};
        assert_eq!(
            route_after_direct_error(&Denied("x".into()), true),
            Route::Sudo
        );
        assert_eq!(
            route_after_direct_error(&Denied("x".into()), false),
            Route::Direct
        );
        assert_eq!(
            route_after_direct_error(&Failed("x".into()), true),
            Route::Direct
        );
    }

    /// LIVE (lab/tests/smart-sudo-vm.sh, ignored otherwise): a kernel NVMe node the test user may not open. `start` must
    /// fall back to the classic sudo route and publish its JSON; `SMART_LIVE_EXPECT=data` = smartctl data, `error` = the
    /// classic error object (sudo not usable in this unit).
    #[test]
    #[ignore = "live: needs a kernel NVMe device and lab/tests/smart-sudo-vm.sh"]
    fn live_denied_kernel_device_uses_the_sudo_route() {
        let dev = std::env::var("SMART_LIVE_DEV").expect("SMART_LIVE_DEV=/dev/nvmeXnY");
        let want = std::env::var("SMART_LIVE_EXPECT").expect("SMART_LIVE_EXPECT=data|error");
        let probe = HealthProbe::Kernel(nvme::kprobe::KernelProbe(dev.into()));
        let _t =
            start(probe, String::new(), 1 << 30).expect("device without identity or no thread");
        let end = Instant::now() + Duration::from_secs(30);
        let j = loop {
            if let Some(j) = nvme::health::smart_json() {
                break j;
            }
            assert!(
                Instant::now() < end,
                "WARNING TIMEOUT smart json exceeded 30s (devmeta live test)"
            );
            std::thread::sleep(Duration::from_millis(50));
        };
        let v: serde_json::Value = serde_json::from_str(&j).expect("valid json");
        println!("SMART_JSON {j}");
        match want.as_str() {
            "data" => assert!(
                v.get("nvme_smart_health_information_log").is_some() && v.get("error").is_none(),
                "{j}"
            ),
            _ => assert!(v.get("error").is_some(), "{j}"),
        }
    }

    /// Drop during a job: the job finishes before drop returns (nothing of the thread runs after its owner is gone, e.g.
    /// past `main` into the exit-time env teardown), and no further job starts.
    #[test]
    fn drop_waits_for_a_running_job_and_stops() {
        let busy = Arc::new(AtomicBool::new(false));
        let runs = Arc::new(AtomicU32::new(0));
        let (b, r) = (busy.clone(), runs.clone());
        let t = Refresh::spawn("refresh-test", Duration::from_secs(3600), move || {
            b.store(true, Ordering::SeqCst);
            r.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(200));
            b.store(false, Ordering::SeqCst);
        })
        .unwrap();
        let end = Instant::now() + Duration::from_secs(10);
        while !busy.load(Ordering::SeqCst) {
            assert!(
                Instant::now() < end,
                "WARNING TIMEOUT refresh job start exceeded 10s (devmeta test)"
            );
            std::thread::yield_now();
        }
        drop(t);
        assert!(!busy.load(Ordering::SeqCst), "job still running after drop");
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }

    /// Drop while the thread waits for its next period: it wakes and ends at once, not after the period.
    #[test]
    fn drop_wakes_a_waiting_thread() {
        let runs = Arc::new(AtomicU32::new(0));
        let r = runs.clone();
        let t = Refresh::spawn("refresh-test", Duration::from_secs(3600), move || {
            r.fetch_add(1, Ordering::SeqCst);
        })
        .unwrap();
        let end = Instant::now() + Duration::from_secs(10);
        while runs.load(Ordering::SeqCst) == 0 {
            assert!(
                Instant::now() < end,
                "WARNING TIMEOUT refresh job start exceeded 10s (devmeta test)"
            );
            std::thread::yield_now();
        }
        let t0 = Instant::now();
        drop(t);
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "drop waited for the period"
        );
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }

    /// A short period repeats the job until drop.
    #[test]
    fn repeats_every_period() {
        let runs = Arc::new(AtomicU32::new(0));
        let r = runs.clone();
        let t = Refresh::spawn("refresh-test", Duration::from_millis(1), move || {
            r.fetch_add(1, Ordering::SeqCst);
        })
        .unwrap();
        let end = Instant::now() + Duration::from_secs(10);
        while runs.load(Ordering::SeqCst) < 3 {
            assert!(
                Instant::now() < end,
                "WARNING TIMEOUT refresh repeats exceeded 10s (devmeta test)"
            );
            std::thread::yield_now();
        }
        drop(t);
        let n = runs.load(Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(runs.load(Ordering::SeqCst), n, "a job ran after drop");
    }
}
