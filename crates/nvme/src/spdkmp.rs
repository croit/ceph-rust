// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
//! SPDK multi-process mode: one NVMe controller shared by several processes, one namespace each (adr 0463).
//! DEBUG/TESTING ONLY (feature `spdk-mp`): production = one OSD per controller (adr 0103).
//!
//! Roles: ONE primary (`croit-flashstore-osd spdk-primary`) constructs the controller, holds the PCI claim ([`crate::pcilock`])
//! and polls admin completions (AERs, cleanup of the io queues of dead secondaries). OSDs and tools are secondaries,
//! started with `--proc-type=secondary`, never `auto`: an `auto` process becomes primary when the primary is gone and
//! re-creates the shared DPDK config under the running secondaries.
//!
//! Locks (`/run/croit-flashstore-osd` like the PCI claim; the daemon, `croit-flashstore-tool` and containers share it; held until process
//! exit, fds leaked):
//! - `flashstore_spdk_mp_<bdf>` (`flock`): secondaries hold it shared. The primary takes it exclusive while it starts: refused while
//!   any secondary lives (it would reset the controller under them); secondaries are refused until it is ready.
//! - `flashstore_spdk_ns_<bdf>_<nsid>`: exclusive per opened namespace (exclusive open at namespace granularity), taken
//!   with [`crate::pcilock::claim_at`] (per-process `fcntl` lock: the pre-env claim and the attach may both take it).
//! The directory is root-owned `1770 root:ceph` (tmpfiles.d, `croit-flashstore-prep@`); a missing or unwritable one is an error
//! naming the fix. SPDK's own internal lock stays in `/var/tmp`, private to the unit (`PrivateTmp=true`).
pub use crate::pciallow::canonical_bdf;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

/// SPDK shared-memory id of a controller: its PCI address as a number (`dddd:bb:dd.f` -> domain<<16 | bus<<8 |
/// dev<<3 | func), so every controller gets its own DPDK file prefix (`spdk<id>`).
pub fn shm_id(addr: &str) -> Result<i32, String> {
    let c = canonical_bdf(addr)?;
    let (rest, func) = c.rsplit_once('.').ok_or("bad bdf")?;
    let p: Vec<u32> = rest
        .split(':')
        .map(|s| u32::from_str_radix(s, 16).map_err(|e| e.to_string()))
        .chain(std::iter::once(
            u32::from_str_radix(func, 16).map_err(|e| e.to_string()),
        ))
        .collect::<Result<_, _>>()?;
    let id = (p[0] << 16) | (p[1] << 8) | (p[2] << 3) | p[3];
    i32::try_from(id).map_err(|_| format!("PCI domain of {addr} too large for an SPDK shm id"))
}

/// DPDK runtime config file of the primary for `shm_id` (DPDK: `/var/run` for root, else `$XDG_RUNTIME_DIR` or `/tmp`;
/// SPDK's file prefix `spdk<id>`).
pub fn runtime_config(shm_id: i32) -> PathBuf {
    // SAFETY: getuid has no preconditions.
    let dir = if unsafe { libc::getuid() } == 0 {
        "/var/run".to_owned()
    } else {
        std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".into())
    };
    PathBuf::from(format!("{dir}/dpdk/spdk{shm_id}/config"))
}

/// Is a DPDK primary alive on this config file (it holds a `lockf` lock on it for its lifetime, DPDK
/// `rte_eal_primary_proc_alive`)?
pub fn primary_alive(config: &Path) -> bool {
    let Ok(f) = File::open(config) else {
        return false;
    };
    // SAFETY: lockf on a valid fd.
    unsafe { libc::lockf(f.as_raw_fd(), libc::F_TEST, 0) != 0 }
}

pub fn mp_lock_path(addr: &str) -> Result<PathBuf, String> {
    Ok(crate::pcilock::lock_dir().join(format!("flashstore_spdk_mp_{}", canonical_bdf(addr)?)))
}

pub fn ns_lock_path(addr: &str, nsid: u32) -> Result<PathBuf, String> {
    Ok(crate::pcilock::lock_dir().join(format!(
        "flashstore_spdk_ns_{}_{nsid}",
        canonical_bdf(addr)?
    )))
}

/// Claim namespace `nsid` of the shared controller `addr` for this process (exclusive per namespace, kept until exit).
pub fn claim_ns(addr: &str, nsid: u32) -> Result<(), String> {
    crate::pcilock::claim_with(
        &ns_lock_path(addr, nsid)?,
        &format!(
            "namespace {nsid} of the shared controller {addr} is open in another process (adr 0463: one process per \
             namespace); stop the OSD / tool that owns it first"
        ),
    )
}

fn open_lock(path: &Path) -> Result<File, String> {
    // same rules as the PCI claim: no symlink, no hard link, a plain single-link file
    crate::pcilock::open_claim(path).map(|(f, _)| f)
}

/// `flock(op | LOCK_NB)`; false = held by someone else.
fn try_flock(f: &File, op: libc::c_int) -> bool {
    // SAFETY: flock on a valid fd.
    unsafe { libc::flock(f.as_raw_fd(), op | libc::LOCK_NB) == 0 }
}

/// Register this process as a secondary of `path`'s controller (shared lock, kept until exit).
pub fn hold_secondary_at(path: &Path) -> Result<(), String> {
    let f = open_lock(path)?;
    if !try_flock(&f, libc::LOCK_SH) {
        return Err(format!(
            "spdk-primary of this controller is starting ({} held exclusive): retry",
            path.display()
        ));
    }
    std::mem::forget(f);
    Ok(())
}

/// Exclusive start lock of the primary; released on drop (the primary is then ready for secondaries).
#[derive(Debug)]
pub struct PrimaryStart(File);

impl Drop for PrimaryStart {
    fn drop(&mut self) {
        // SAFETY: flock on our own fd.
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// Take the primary start lock: refused while any secondary of the controller is alive.
pub fn begin_primary_at(path: &Path) -> Result<PrimaryStart, String> {
    let f = open_lock(path)?;
    if !try_flock(&f, libc::LOCK_EX) {
        return Err(format!(
            "secondaries of this controller are still running ({} held): stop them first, a new primary would reset the controller under them",
            path.display()
        ));
    }
    Ok(PrimaryStart(f))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("spdkmp-{name}-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    /// Run `f` in a forked child that reports `ok` through a pipe and then sleeps until killed; returns (pid, ok).
    fn in_child(f: impl FnOnce() -> bool) -> (libc::pid_t, bool) {
        let mut fds = [0i32; 2];
        // SAFETY: pipe(2) into a 2-element array.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: the child runs `f` (open + flock only) and exits without unwinding.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let b = [u8::from(f())];
            unsafe {
                libc::write(fds[1], b.as_ptr().cast(), 1);
                libc::sleep(30);
                libc::_exit(0);
            }
        }
        let mut b = [0u8; 1];
        // SAFETY: read 1 byte from our pipe end.
        assert_eq!(unsafe { libc::read(fds[0], b.as_mut_ptr().cast(), 1) }, 1);
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        (pid, b[0] == 1)
    }

    fn reap(pid: libc::pid_t) {
        // SAFETY: stop our own child by its exact pid, reap it.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
    }

    #[test]
    fn shm_id_from_bdf() {
        assert_eq!(shm_id("0000:af:00.0").unwrap(), 0xaf00);
        assert_eq!(shm_id("af:00.1").unwrap(), 0xaf01);
        assert_eq!(shm_id("0001:c3:1f.7").unwrap(), 0x1_c3ff);
        assert!(shm_id("ffff:00:00.0").is_err());
        assert!(shm_id("nvme0").is_err());
    }

    #[test]
    fn lock_paths() {
        assert_eq!(
            mp_lock_path("af:0.0").unwrap(),
            PathBuf::from("/run/croit-flashstore-osd/flashstore_spdk_mp_0000:af:00.0")
        );
        assert_eq!(
            ns_lock_path("0000:af:00.0", 3).unwrap(),
            PathBuf::from("/run/croit-flashstore-osd/flashstore_spdk_ns_0000:af:00.0_3")
        );
    }

    #[test]
    fn shared_locks_refuse_a_symlink() {
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir().join(format!("spdkmp-links-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim");
        std::fs::write(&victim, "x").unwrap();
        let p = dir.join("lock");
        symlink(&victim, &p).unwrap();
        assert!(hold_secondary_at(&p).unwrap_err().contains("refused"));
        assert!(begin_primary_at(&p).unwrap_err().contains("refused"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn primary_refused_while_a_secondary_lives() {
        let _fork = crate::testlock::guard(); // forked children copy every open descriptor until reaped
        let p = tmp("mp");
        let (sec, ok) = in_child(|| hold_secondary_at(&p).is_ok());
        assert!(ok, "secondary could not register");
        assert!(begin_primary_at(&p).is_err());
        let e = begin_primary_at(&p).unwrap_err();
        assert!(e.contains("still running"), "{e}");
        // a second secondary may join
        let (sec2, ok2) = in_child(|| hold_secondary_at(&p).is_ok());
        assert!(ok2);
        reap(sec);
        assert!(begin_primary_at(&p).is_err(), "one secondary left");
        reap(sec2);
        let _g = begin_primary_at(&p).unwrap();
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn secondary_refused_while_the_primary_starts() {
        let _fork = crate::testlock::guard(); // forked children copy every open descriptor until reaped
        let p = tmp("start");
        let (pri, ok) = in_child(|| {
            let g = begin_primary_at(&p);
            let ok = g.is_ok();
            std::mem::forget(g);
            ok
        });
        assert!(ok);
        let e = hold_secondary_at(&p).unwrap_err();
        assert!(e.contains("starting"), "{e}");
        reap(pri);
        hold_secondary_at(&p).unwrap();
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn primary_start_lock_released_on_drop() {
        let _fork = crate::testlock::guard(); // forked children copy every open descriptor until reaped
        let p = tmp("drop");
        let g = begin_primary_at(&p).unwrap();
        let (c, ok) = in_child(|| begin_primary_at(&p).is_ok());
        assert!(!ok, "second primary start while the first holds the lock");
        reap(c);
        drop(g);
        let (c, ok) = in_child(|| hold_secondary_at(&p).is_ok());
        assert!(ok, "secondary after the primary is ready");
        reap(c);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn primary_alive_follows_the_lockf_lock() {
        let _fork = crate::testlock::guard(); // forked children copy every open descriptor until reaped
        let p = tmp("cfg");
        assert!(!primary_alive(&p), "missing file");
        std::fs::write(&p, b"x").unwrap();
        assert!(!primary_alive(&p), "unlocked file");
        let cp = p.clone();
        let (c, ok) = in_child(move || {
            let f = OpenOptions::new().read(true).write(true).open(&cp).unwrap();
            // SAFETY: lockf on a valid fd.
            let ok = unsafe { libc::lockf(f.as_raw_fd(), libc::F_TLOCK, 0) } == 0;
            std::mem::forget(f);
            ok
        });
        assert!(ok);
        assert!(primary_alive(&p));
        reap(c);
        assert!(!primary_alive(&p), "lock gone with the process");
        let _ = std::fs::remove_file(&p);
    }
}
