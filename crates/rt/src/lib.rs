// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! rt: per-core run-to-completion runtime (ADR 0006): the kernel TCP tier over io_uring ([`knet`], ADR 0053) that runs the
//! sans-IO [`osd::Osd`] and its helpers.
//!
//! One pinned thread per core owns the connections accepted on its listeners. Nothing blocks, nothing is shared; cross-core
//! traffic goes only through [`spsc`] rings: [`mesh`] (N x N rings), [`place`] (PG / connection placement) and
//! [`multi`] (spawning N pinned cores) are the multi-core side (docs: doc/design/net-perf.md).

#[cfg(all(feature = "knet", target_os = "linux"))]
pub mod knet;
pub mod mesh;
pub mod multi;
pub mod netaddr;
pub mod place;
pub mod stream;
pub use ::spsc;
use store::fastclock;
pub mod topo;
#[cfg(target_os = "linux")]
pub mod wake;
mod xport;

pub use fastclock::{init as init_clock, since};
pub use xport::XPort;

/// What a core does when an iteration found no work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Idle {
    /// Pure busy poll (lowest latency).
    Spin,
    /// Sleep in the ring; the sleep policy is derived per core from the measured wake latency and the store state
    /// (see `knet::KCore`).
    Sleep,
}

/// Hash map with the fast non-cryptographic hasher of the per-core tables.
#[cfg(all(feature = "knet", target_os = "linux"))]
pub(crate) type FxMap<K, V> = std::collections::HashMap<K, V, foldhash::fast::FixedState>;

/// Move the calling thread onto `cpus`; CPUs outside `CPU_SETSIZE` are skipped (Linux only).
#[cfg(target_os = "linux")]
fn set_affinity(cpus: impl Iterator<Item = usize>) -> std::io::Result<()> {
    // SAFETY: zeroed cpu_set_t is a valid empty set; CPU_SET stays below CPU_SETSIZE (filtered).
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        for c in cpus.filter(|c| *c < libc::CPU_SETSIZE as usize) {
            libc::CPU_SET(c, &mut set);
        }
        if libc::sched_setaffinity(0, std::mem::size_of_val(&set), &set) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Pin the calling thread to `cpu` (Linux; no-op elsewhere).
pub fn pin_current_thread(cpu: usize) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        if cpu >= libc::CPU_SETSIZE as usize {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        set_affinity(std::iter::once(cpu))?;
    }
    let _ = cpu;
    Ok(())
}

/// CPUs of the helper threads ([`set_core_cpus`]); `shared` = the cores take the whole mask, the helpers share it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperCpus {
    pub cpus: Vec<usize>,
    pub shared: bool,
}

static HELPER_CPUS: std::sync::OnceLock<HelperCpus> = std::sync::OnceLock::new();

/// Record the CPUs of the OSD cores before they start (call it on an unpinned thread): helper threads
/// ([`place_helper_thread`]) run on the rest of the process affinity mask, or on the whole mask when the cores take all
/// of it. The first call wins.
pub fn set_core_cpus(cores: &[usize]) {
    let mask = affinity_cpus();
    let rest: Vec<usize> = mask
        .iter()
        .copied()
        .filter(|c| !cores.contains(c))
        .collect();
    let _ = HELPER_CPUS.set(if rest.is_empty() {
        HelperCpus {
            cpus: mask,
            shared: true,
        }
    } else {
        HelperCpus {
            cpus: rest,
            shared: false,
        }
    });
}

/// The helper CPUs (`None` before [`set_core_cpus`]).
pub fn helper_cpus() -> Option<&'static HelperCpus> {
    HELPER_CPUS.get()
}

/// Move the calling thread onto the helper CPUs. A thread inherits the affinity of the thread that starts it, so a helper
/// started from a pinned core would run on that core's CPU. Linux; no-op elsewhere or before [`set_core_cpus`].
pub fn place_helper_thread() -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    if let Some(h) = HELPER_CPUS.get() {
        set_affinity(h.cpus.iter().copied())?;
    }
    Ok(())
}

/// CPUs this process may run on (`sched_getaffinity`: respects cgroup cpusets, systemd `CPUAffinity`, `taskset`,
/// cephadm pinning), ascending. Elsewhere: `0..available_parallelism`.
pub fn affinity_cpus() -> Vec<usize> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: zeroed cpu_set_t is a valid empty set; CPU_ISSET stays below CPU_SETSIZE.
        unsafe {
            let mut set: libc::cpu_set_t = std::mem::zeroed();
            if libc::sched_getaffinity(0, std::mem::size_of_val(&set), &mut set) == 0 {
                let v: Vec<usize> = (0..libc::CPU_SETSIZE as usize)
                    .filter(|c| libc::CPU_ISSET(*c, &set))
                    .collect();
                if !v.is_empty() {
                    return v;
                }
            }
        }
    }
    (0..std::thread::available_parallelism().map_or(1, usize::from)).collect()
}

/// 32 bytes of OS randomness (ISN secret, seeds). Linux: `getrandom(2)` (no device node needed, blocks only until the
/// kernel pool is initialized at boot); elsewhere `/dev/urandom`. No OS randomness = panic at startup: a guessable
/// substitute would make ISNs and seeds predictable without anyone noticing.
pub fn os_random() -> [u8; 32] {
    let mut b = [0u8; 32];
    #[cfg(target_os = "linux")]
    {
        let mut got = 0;
        while got < b.len() {
            // SAFETY: writes at most `b.len() - got` bytes into `b[got..]`.
            let r = unsafe { libc::getrandom(b[got..].as_mut_ptr().cast(), b.len() - got, 0) };
            if r > 0 {
                got += r as usize;
                continue;
            }
            let e = std::io::Error::last_os_error();
            assert!(
                e.kind() == std::io::ErrorKind::Interrupted,
                "getrandom: {e}"
            );
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        use std::io::Read;
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut b))
            .unwrap_or_else(|e| panic!("/dev/urandom: {e}"));
    }
    b
}

#[cfg(test)]
mod tests {
    /// Two draws differ and are not the old clock fallback's shape (both 16-byte halves derived from one timestamp).
    #[test]
    fn os_random_draws_differ() {
        let (a, b) = (super::os_random(), super::os_random());
        assert_ne!(a, b);
        assert_ne!(a, [0; 32]);
    }
}
