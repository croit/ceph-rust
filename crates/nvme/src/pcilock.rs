// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Claim an NVMe PCI function BEFORE any SPDK/DPDK code touches it.
//!
//! SPDK claims a controller only after DPDK has probed and mapped it (`nvme_pcie_ctrlr_construct`). A second process
//! that loses that claim still mapped the device; with `uio_pci_generic` (hosts without IOMMU) closing that mapping
//! makes the kernel clear PCI bus mastering of the device: the process that owns it loses DMA and its IO hangs
//! (verified on the lab VM with spdk_nvme_perf + spdk_nvme_identify). vfio refuses the second opener itself, uio
//! does not. So every opener takes a claim (POSIX `fcntl` write lock on
//! `/run/croit-flashstore-osd/spdk_pci_lock_<dddd:bb:dd.f>`, owner pid stored in the first 4 bytes) first and gives up while another
//! process holds it; our own later claim in the same process succeeds (POSIX locks belong to the process).
//! The file keeps SPDK's name and on-disk format, but it is OUR cross-process lock: SPDK's internal lock stays in
//! `/var/tmp` where the library puts it and is private to the unit (`PrivateTmp=true`), so it never excludes a second
//! croit-flashstore-osd. What must be shared is [`LOCK_DIR`]: the daemon (`ceph`), root `croit-flashstore-tool` and containers mount it.
//! The directory is root-owned `1770 root:ceph`, created by the package (tmpfiles.d) and `croit-flashstore-prep@`; a missing or
//! unwritable directory is an error naming the exact fix, never a fallback to a private `/var/tmp`.
//! The lock file is opened with `O_NOFOLLOW` and must be a regular file with exactly one link: a symlink or hard link
//! planted in the shared directory is refused (never followed, never written through). An existing file is opened
//! without `O_CREAT`, a new one is created `0666` (see [`open_claim`]): every opener of either uid gets it writable and
//! nothing is ever chowned. The claim (`fcntl` write lock) needs a writable descriptor: an unwritable file (an older
//! `0644` one of another uid) is refused with a "remove it" error (never reported as "in use"); the shared `flock` files
//! of [`crate::spdkmp`] open read-only too.
pub use crate::pciallow::canonical_bdf;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// Shared cross-process lock directory: root-owned, group `ceph` writes (`1770 root:ceph`, sticky so neither uid can
/// unlink the other's files), so the daemon, root `croit-flashstore-tool` and containers exclude each other while `/var/tmp`
/// stays private to the unit (`PrivateTmp=true`).
pub const LOCK_DIR: &str = "/run/croit-flashstore-osd";

/// [`LOCK_DIR`] as a path (one definition for the crate).
pub(crate) fn lock_dir() -> &'static Path {
    Path::new(LOCK_DIR)
}

/// Claim file of `addr` in `dir` (name only, no filesystem access; [`open_claim`] checks the directory).
fn lock_path_in(dir: &Path, addr: &str) -> Result<PathBuf, String> {
    Ok(dir.join(format!("spdk_pci_lock_{}", canonical_bdf(addr)?)))
}

/// Claim file of `addr` in the shared [`LOCK_DIR`].
pub fn lock_path(addr: &str) -> Result<PathBuf, String> {
    lock_path_in(lock_dir(), addr)
}

/// Refuse a lock directory this process cannot create files in, naming the exact fix: a missing or unwritable shared
/// directory would silently break the exclusion of daemon, tool and containers.
fn check_lock_dir(dir: &Path) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    let create = format!("install -d -o root -g ceph -m 1770 {}", dir.display());
    let m = std::fs::metadata(dir).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => format!(
            "cross-process lock directory {} is missing; create it with `{create}` (the croit-flashstore-osd package ships it as \
             /usr/lib/tmpfiles.d/croit-flashstore-osd.conf, croit-flashstore-prep@ creates it)",
            dir.display()
        ),
        _ => format!("cross-process lock directory {}: {e}", dir.display()),
    })?;
    if !m.is_dir() {
        return Err(format!(
            "cross-process lock directory {} is not a directory; remove it and run `{create}`",
            dir.display()
        ));
    }
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| format!("lock directory {} contains a NUL byte", dir.display()))?;
    // SAFETY: `c` is a valid NUL-terminated path; access(2) only reads it.
    if unsafe { libc::access(c.as_ptr(), libc::W_OK | libc::X_OK) } != 0 {
        let e = std::io::Error::last_os_error();
        // SAFETY: geteuid has no preconditions.
        let uid = unsafe { libc::geteuid() };
        return Err(format!(
            "cross-process lock directory {} is not writable for uid {uid} ({e}); fix owner and mode with `{create}` \
             and make uid {uid} a member of group ceph",
            dir.display()
        ));
    }
    Ok(())
}

/// Take the claim for this process (kept until the process exits: the descriptor is leaked on purpose, closing any
/// other descriptor of the same file would also drop the process's lock). `Err` names the owning pid when another
/// process holds it.
pub fn claim(addr: &str) -> Result<(), String> {
    claim_at(&lock_path(addr)?)
}

/// [`claim`] on an explicit lock file (namespace claim of a shared controller, tests).
pub fn claim_at(path: &Path) -> Result<(), String> {
    claim_with(
        path,
        "one process owns the whole NVMe controller with all its namespaces (adr 0103: one OSD per controller); stop \
         the OSD / tool that owns it first",
    )
}

/// Open the claim file without following a symlink and without accepting an inode somebody else could point another
/// name at: regular file with exactly one link. An existing file is opened without `O_CREAT` (with
/// `fs.protected_regular=2` an `O_CREAT` open of another uid's file in the sticky group-writable [`LOCK_DIR`] fails even
/// for root); a missing one is created exclusively and set `0666`: the daemon `ceph`, host root and a root container
/// without `CAP_DAC_OVERRIDE` all reopen it writable, and the `1770 root:ceph` directory keeps other users out. So no
/// file is ever chowned. Returns the descriptor and whether it is writable (`flock` users accept a read-only one; the
/// `fcntl` claim refuses it).
pub(crate) fn open_claim(path: &Path) -> Result<(std::fs::File, bool), String> {
    use std::os::unix::fs::MetadataExt;
    let dir = path
        .parent()
        .ok_or_else(|| format!("lock file {} has no directory", path.display()))?;
    check_lock_dir(dir)?;
    let flags = libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let open = |write: bool, create: bool| {
        OpenOptions::new()
            .read(true)
            .write(write)
            .create_new(create)
            .custom_flags(flags)
            .mode(0o666)
            .open(path)
    };
    let created = |f: std::fs::File| {
        // the creation mode is filtered by the umask: set the shared mode on the descriptor
        f.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o666))
            .map(|_| f)
    };
    // existing file first; a concurrent creator between the two opens makes `create_new` fail with EEXIST: reopen
    let rw = match open(true, false) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => match open(true, true) {
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => open(true, false),
            r => r.and_then(created),
        },
        r => r,
    };
    let (f, write) = match rw {
        Ok(f) => (f, true),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => (
            open(false, false).map_err(|e| format!("{}: {e}", path.display()))?,
            false,
        ),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(format!(
                "refused: claim file {} is a symlink; remove it",
                path.display()
            ));
        }
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let m = f
        .metadata()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if !m.is_file() || m.nlink() != 1 {
        return Err(format!(
            "refused: claim file {} is not a plain single-link file (symlink or hard link); remove it",
            path.display()
        ));
    }
    Ok((f, write))
}

/// [`claim_at`] with the explanation `why` behind the "in use" error (it names the claim and its holder first).
pub fn claim_with(path: &Path, why: &str) -> Result<(), String> {
    let (mut f, writable) = open_claim(path)?;
    // the claim is a `fcntl` WRITE lock: it needs a writable descriptor (a read-only one fails with EBADF, which must
    // not read as "in use"); SPDK's own claim of the same file needs write access too
    if !writable {
        return Err(format!(
            "claim file {} is not writable for uid {} (claim files are created 0666; an older one may be 0644): \
             remove it",
            path.display(),
            // SAFETY: geteuid has no preconditions.
            unsafe { libc::geteuid() }
        ));
    }
    // SAFETY: plain struct for fcntl; zeroed is a valid value.
    let mut fl: libc::flock = unsafe { std::mem::zeroed() };
    fl.l_type = libc::F_WRLCK as _;
    fl.l_whence = libc::SEEK_SET as _;
    // SAFETY: fcntl on a valid fd with a valid flock struct.
    if unsafe { libc::fcntl(f.as_raw_fd(), libc::F_SETLK, &fl) } != 0 {
        let mut pid = [0u8; 4];
        let owner = f
            .read_exact(&mut pid)
            .map(|_| holder(i32::from_le_bytes(pid)))
            .unwrap_or_else(|_| "?".into());
        return Err(format!(
            "device is in use by {owner} (SPDK claim {} held): {why}",
            path.display()
        ));
    }
    let me = std::process::id() as i32;
    let _ = f
        .seek(SeekFrom::Start(0))
        .and_then(|_| f.write_all(&me.to_le_bytes()));
    std::mem::forget(f);
    Ok(())
}

/// "osd.N (croit-flashstore-osd, pid P)" / "process P (comm)" for the claim holder, from `/proc/<pid>/cmdline`.
fn holder(pid: i32) -> String {
    let c = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    describe_holder(pid, &c)
}

/// [`holder`] on a raw NUL-separated command line: names the OSD (`--id N`, ceph-osd `-i N`) when it is one.
fn describe_holder(pid: i32, cmdline: &[u8]) -> String {
    let a: Vec<&str> = cmdline
        .split(|&b| b == 0)
        .filter_map(|s| std::str::from_utf8(s).ok())
        .collect();
    let exe = a
        .first()
        .and_then(|e| e.rsplit('/').next())
        .filter(|e| !e.is_empty());
    let Some(exe) = exe else {
        return format!("process {pid}");
    };
    let id = a
        .windows(2)
        .find(|w| matches!(w[0], "--id" | "-i"))
        .map(|w| w[1])
        .filter(|v| v.parse::<u32>().is_ok());
    match id {
        Some(n) => format!("osd.{n} ({exe}, pid {pid})"),
        None => format!("process {pid} ({exe})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_refuses_symlink_and_hard_link() {
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir().join(format!("pcilock-links-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim");
        std::fs::write(&victim, "0123456789abcdef").unwrap();
        let claim = dir.join("claim");
        symlink(&victim, &claim).unwrap();
        let e = claim_at(&claim).unwrap_err();
        assert!(e.contains("refused") && e.contains("symlink"), "{e}");
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "0123456789abcdef",
            "the PID was written through the symlink"
        );
        // a hard link to a foreign inode (the same file under another name) is refused too
        std::fs::remove_file(&claim).unwrap();
        std::fs::hard_link(&victim, &claim).unwrap();
        let e = claim_at(&claim).unwrap_err();
        assert!(e.contains("refused") && e.contains("hard link"), "{e}");
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "0123456789abcdef"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A claim file this uid cannot write (an older `0644` file of another uid; here a `0444` one of our own) is refused with
    /// the ownership reason, never as "in use" (a read-only `fcntl` write lock fails with EBADF). Root writes any file:
    /// the case does not exist there.
    #[test]
    fn claim_of_a_read_only_file_names_the_owner_problem() {
        use std::os::unix::fs::PermissionsExt;
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = std::env::temp_dir().join(format!("pcilock-ro-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("claim");
        std::fs::write(&p, [0u8; 4]).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o444)).unwrap();
        let e = claim_at(&p).unwrap_err();
        assert!(e.contains("not writable") && !e.contains("in use"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_creates_a_plain_file_and_records_the_pid() {
        let dir = std::env::temp_dir().join(format!("pcilock-new-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("claim");
        claim_at(&p).unwrap();
        let m = std::fs::metadata(&p).unwrap();
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        assert!(m.is_file() && m.nlink() == 1);
        assert_eq!(m.permissions().mode() & 0o777, 0o666);
        let pid = std::fs::read(&p).unwrap();
        assert_eq!(
            i32::from_le_bytes(pid[..4].try_into().unwrap()),
            std::process::id() as i32
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn holder_names_the_osd() {
        let osd = b"/usr/bin/croit-flashstore-osd\0run\0--id\x003\0--cluster\0ceph\0-f\0";
        assert_eq!(
            describe_holder(7, osd),
            "osd.3 (croit-flashstore-osd, pid 7)"
        );
        let tool = b"croit-flashstore-tool\0activate\0--id\x0012\0";
        assert_eq!(
            describe_holder(8, tool),
            "osd.12 (croit-flashstore-tool, pid 8)"
        );
        let other = b"spdk_nvme_perf\0-q\x0032\0";
        assert_eq!(describe_holder(9, other), "process 9 (spdk_nvme_perf)");
        assert_eq!(describe_holder(10, b""), "process 10");
    }

    #[test]
    fn lock_path_form() {
        assert_eq!(LOCK_DIR, "/run/croit-flashstore-osd");
        assert_eq!(
            lock_path("3:0.0").unwrap(),
            PathBuf::from("/run/croit-flashstore-osd/spdk_pci_lock_0000:03:00.0")
        );
        // a directory injected for tests yields the same name form
        assert_eq!(
            lock_path_in(Path::new("/tmp/claims"), "3:0.0").unwrap(),
            PathBuf::from("/tmp/claims/spdk_pci_lock_0000:03:00.0")
        );
    }

    /// Fork a child that creates `path` and takes the `fcntl` write lock on it, then sleeps until killed; returns its pid.
    fn holder_child(path: &Path) -> libc::pid_t {
        use std::os::unix::ffi::OsStrExt;
        let mut fds = [0i32; 2];
        // SAFETY: pipe(2) into a 2-element array.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let cp = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: the child only calls async-signal-safe functions (open, fcntl, write, sleep, _exit).
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            unsafe {
                let fd = libc::open(cp.as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o600);
                let mut fl: libc::flock = std::mem::zeroed();
                fl.l_type = libc::F_WRLCK as _;
                fl.l_whence = libc::SEEK_SET as _;
                let ok = fd >= 0 && libc::fcntl(fd, libc::F_SETLK, &fl) == 0;
                let b = [u8::from(ok)];
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
        assert_eq!(b[0], 1, "child could not take the lock");
        child
    }

    /// Stop our own child by its exact pid and reap it.
    fn reap(pid: libc::pid_t) {
        // SAFETY: kill/waitpid on our own child.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
    }

    #[test]
    fn claim_refuses_while_another_process_holds_it() {
        let dir = std::env::temp_dir().join(format!("pcilock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = lock_path_in(&dir, "3:0.0").unwrap();
        let _g = crate::testlock::guard(); // the child copies every open descriptor until it is reaped
        let child = holder_child(&p);
        let e = claim_at(&p).unwrap_err();
        assert!(e.contains("in use") && e.contains("adr 0103"), "{e}");
        // the explanation is the caller's (a namespace claim of a shared controller says so), "in use" stays (exit 3)
        let e = claim_with(&p, "namespace 2 is open elsewhere").unwrap_err();
        assert!(
            e.contains("in use") && e.ends_with("namespace 2 is open elsewhere"),
            "{e}"
        );
        reap(child);
        claim_at(&p).unwrap();
        // the same process may claim again (POSIX locks belong to the process)
        claim_at(&p).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_in_the_shared_lock_dir_refuses_a_second_holder() {
        let dir = std::env::temp_dir().join(format!("pcilock-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = lock_path_in(&dir, "af:0.1").unwrap();
        assert_eq!(
            p.file_name().unwrap(),
            std::ffi::OsStr::new("spdk_pci_lock_0000:af:00.1")
        );
        let _g = crate::testlock::guard(); // the child copies every open descriptor until it is reaped
        let child = holder_child(&p);
        let e = claim_at(&p).unwrap_err();
        assert!(
            e.contains("in use") && e.contains(&p.display().to_string()),
            "{e}"
        );
        reap(child);
        claim_at(&p).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_refuses_a_missing_lock_directory() {
        let dir = std::env::temp_dir().join(format!("pcilock-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let p = lock_path_in(&dir, "3:0.0").unwrap();
        let e = claim_at(&p).unwrap_err();
        assert!(
            e.contains("is missing") && e.contains("install -d -o root -g ceph -m 1770"),
            "{e}"
        );
    }

    /// A directory without write permission is refused with the fix, not opened read-only (a read-only file would make
    /// the `fcntl` write lock fail with EBADF and read as "in use"). Root writes any directory: the case does not exist.
    #[test]
    fn claim_refuses_an_unwritable_lock_directory() {
        use std::os::unix::fs::PermissionsExt;
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = std::env::temp_dir().join(format!("pcilock-nowrite-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        let p = lock_path_in(&dir, "3:0.0").unwrap();
        let e = claim_at(&p).unwrap_err();
        assert!(
            e.contains("not writable") && e.contains("1770") && !e.contains("in use"),
            "{e}"
        );
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
