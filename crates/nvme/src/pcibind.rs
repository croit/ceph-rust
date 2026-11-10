// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Exclusive admission and driver rebind of ONE NVMe PCI function to a userspace driver (`vfio-pci` /
//! `uio_pci_generic`) for the SPDK tier; caller: `croit-flashstore-tool nvme-rebind` from `croit-flashstore-prep@`.
//!
//! Unbinding the kernel `nvme` driver removes every namespace of the controller from the host. So the function is
//! only rebound when nothing on the host uses it, and the claim that proves this is held until the rebind is done:
//! - the PCI class must be an NVMe controller (`0x010802`) and the current driver `nvme`, none, or the other
//!   userspace driver; anything else (a mistyped address naming a NIC or a SATA controller) is refused.
//! - per namespace (multipath path nodes `nvmeXcYnZ` map to their head `nvmeXnZ`) and per partition: refused when it
//!   has sysfs holders (LVM, MD, dm-crypt, multipath), is mounted (mountinfo device number or mount source node, so
//!   aliases and btrfs count) or is active swap. These checks name the exact reason.
//! - then every namespace head is opened `O_EXCL` (the kernel's exclusive block-device claim: fails while any partition
//!   or the disk is mounted, a holder or swap claims it, or another process holds it exclusively, e.g. a kernel-tier
//!   croit-flashstore-osd), `flock(LOCK_EX)` is taken (the kernel-tier OSD's lock; udev's transient `LOCK_SH` during
//!   event processing is waited out, bounded) and an OFD record-lock probe must
//!   find no lock (a classic OSD's lock on a raw device). The descriptors stay open until the new driver is verified,
//!   so a mount, swapon or device-mapper table cannot claim the namespace between check and unbind.
//! - from `vfio-pci` / `uio_pci_generic` the SPDK claim of the function ([`crate::pcilock`]) is taken first: an SPDK
//!   OSD or tool that owns the controller is never unbound.
//!
//! Not detected: a process that opened a namespace without `O_EXCL` and without any lock (e.g. `dd`). Such users have
//! no claim the kernel or other tools could honour either.
use std::fs::File;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

/// PCI class code of an NVMe controller (mass storage, non-volatile memory, NVMe programming interface).
const NVME_CLASS: &str = "0x010802";

/// The userspace drivers the SPDK tier binds (adr 0034).
pub const DRIVERS: [&str; 2] = ["vfio-pci", "uio_pci_generic"];

/// Roots of the host views the admission reads (fixtures in tests).
#[derive(Clone, Debug)]
pub struct Roots {
    pub sysfs: PathBuf,
    pub procfs: PathBuf,
    pub dev: PathBuf,
}

impl Default for Roots {
    fn default() -> Self {
        Roots {
            sysfs: "/sys".into(),
            procfs: "/proc".into(),
            dev: "/dev".into(),
        }
    }
}

/// Why a rebind did not happen: `Refused` = the device is in use or not eligible (nothing changed, exit 3);
/// `Failed` = the rebind itself went wrong (exit 1).
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Refused(String),
    Failed(String),
}

/// What [`rebind`] did.
#[derive(Debug, PartialEq, Eq)]
pub struct Report {
    pub pci: String,
    pub driver: String,
    /// Driver before (`None` = unbound).
    pub from: Option<String>,
    /// `already` (no change), `rebound`, or `dry-run` (admission passed, nothing written).
    pub action: &'static str,
    /// Namespace heads held exclusively during the rebind (`/dev/nvmeXnY`).
    pub claimed: Vec<String>,
}

/// One block device of the controller: a namespace head or one of its partitions.
#[derive(Debug, PartialEq, Eq)]
struct Blk {
    name: String,
    /// `major:minor` as sysfs `dev` prints it.
    devnum: String,
    sysdir: PathBuf,
    part: bool,
}

fn refused(m: impl Into<String>) -> Error {
    Error::Refused(m.into())
}

fn read_trim(p: &Path) -> Result<String, Error> {
    std::fs::read_to_string(p)
        .map(|s| s.trim().to_owned())
        .map_err(|e| refused(format!("{}: {e}", p.display())))
}

/// `nvme<a>n<b>` or `nvme<a>c<c>n<b>` (namespace disk or multipath path node of a controller dir).
fn is_ns_name(n: &str) -> bool {
    let Some(r) = n.strip_prefix("nvme") else {
        return false;
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let Some((a, b)) = r.split_once('n') else {
        return false;
    };
    let a = match a.split_once('c') {
        Some((x, y)) => digits(x) && digits(y),
        None => digits(a),
    };
    a && digits(b)
}

/// Namespace heads of the controller(s) under PCI device dir `pdir`, each followed by its partitions.
fn block_devices(roots: &Roots, pdir: &Path) -> Result<Vec<Blk>, Error> {
    let mut heads = std::collections::BTreeSet::new();
    let nvme = pdir.join("nvme");
    let ctrls = match std::fs::read_dir(&nvme) {
        Ok(r) => r,
        // bound to nvme but the controller is gone or failed init: no namespace can be in use
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(refused(format!("{}: {e}", nvme.display()))),
    };
    for c in ctrls {
        let c = c.map_err(|e| refused(format!("{}: {e}", nvme.display())))?;
        let cdir = c.path();
        for e in
            std::fs::read_dir(&cdir).map_err(|e| refused(format!("{}: {e}", cdir.display())))?
        {
            let n = e
                .map_err(|e| refused(format!("{}: {e}", cdir.display())))?
                .file_name()
                .to_string_lossy()
                .into_owned();
            if is_ns_name(&n) {
                heads.insert(crate::kdev::head_name(&n));
            }
        }
    }
    let mut v = Vec::new();
    for h in heads {
        let sysdir = roots.sysfs.join("block").join(&h);
        let devnum = read_trim(&sysdir.join("dev")).map_err(|e| match e {
            Error::Refused(m) => refused(format!(
                "namespace {h}: no block device in sysfs ({m}); cannot prove it unused"
            )),
            f => f,
        })?;
        let mut parts = Vec::new();
        for e in
            std::fs::read_dir(&sysdir).map_err(|e| refused(format!("{}: {e}", sysdir.display())))?
        {
            let e = e.map_err(|e| refused(format!("{}: {e}", sysdir.display())))?;
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with(&h) && e.path().join("partition").exists() {
                parts.push(Blk {
                    devnum: read_trim(&e.path().join("dev"))?,
                    name: n,
                    sysdir: e.path(),
                    part: true,
                });
            }
        }
        parts.sort_by(|a, b| a.name.cmp(&b.name));
        v.push(Blk {
            name: h,
            devnum,
            sysdir,
            part: false,
        });
        v.extend(parts);
    }
    Ok(v)
}

/// `\040`-style octal escapes of /proc/self/mountinfo and /proc/swaps.
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && (b'0'..=b'3').contains(&b[i + 1])
            && b[i + 2..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            out.push((b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0'));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `major:minor` of a block device node (`None` = not a block device or not there).
fn node_devnum(p: &Path) -> Option<String> {
    let m = std::fs::metadata(p).ok()?;
    if !m.file_type().is_block_device() {
        return None;
    }
    let r = m.rdev();
    Some(format!("{}:{}", libc::major(r), libc::minor(r)))
}

/// Mount point of `devnum` (mountinfo: field 3 = device number; source after ` - fstype`), if mounted.
fn mounted_at(mountinfo: &str, devnum: &str) -> Option<String> {
    for l in mountinfo.lines() {
        let f: Vec<&str> = l.split(' ').collect();
        if f.len() < 5 {
            continue;
        }
        let src = f
            .iter()
            .position(|x| *x == "-")
            .and_then(|i| f.get(i + 2))
            .map(|s| unescape(s));
        if f[2] == devnum
            || src.as_deref().is_some_and(|s| {
                s.starts_with('/') && node_devnum(Path::new(s)).as_deref() == Some(devnum)
            })
        {
            return Some(unescape(f[4]));
        }
    }
    None
}

/// Swap entry of /proc/swaps backed by `devnum`.
fn swap_of(swaps: &str, devnum: &str) -> Option<String> {
    swaps
        .lines()
        .skip(1)
        .filter_map(|l| l.split_whitespace().next())
        .map(unescape)
        .find(|p| node_devnum(Path::new(p)).as_deref() == Some(devnum))
}

/// The named checks (holders, mounts, swap) of every namespace and partition: the exact reason for a refusal.
fn check_unused(roots: &Roots, blks: &[Blk]) -> Result<(), Error> {
    let mi_path = roots.procfs.join("self/mountinfo");
    let mountinfo = std::fs::read_to_string(&mi_path)
        .map_err(|e| refused(format!("{}: {e}", mi_path.display())))?;
    let sw_path = roots.procfs.join("swaps");
    let swaps = std::fs::read_to_string(&sw_path)
        .map_err(|e| refused(format!("{}: {e}", sw_path.display())))?;
    for b in blks {
        let hdir = b.sysdir.join("holders");
        let mut holders: Vec<String> = std::fs::read_dir(&hdir)
            .map_err(|e| {
                refused(format!(
                    "/dev/{}: cannot read {}: {e}",
                    b.name,
                    hdir.display()
                ))
            })?
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        if !holders.is_empty() {
            holders.sort();
            return Err(refused(format!(
                "/dev/{} has holders {} (LVM / MD / dm-crypt / multipath): deactivate them first",
                b.name,
                holders.join(",")
            )));
        }
        if let Some(m) = mounted_at(&mountinfo, &b.devnum) {
            return Err(refused(format!("/dev/{} is mounted on {m}", b.name)));
        }
        if let Some(s) = swap_of(&swaps, &b.devnum) {
            return Err(refused(format!("/dev/{} is active swap ({s})", b.name)));
        }
    }
    Ok(())
}

/// Exclusive claim of one namespace head, held by the returned descriptor.
fn claim(roots: &Roots, b: &Blk) -> Result<File, Error> {
    let node = roots.dev.join(&b.name);
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_EXCL | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&node)
        .map_err(|e| {
            refused(if e.raw_os_error() == Some(libc::EBUSY) {
                format!(
                    "{} is claimed exclusively by another user (a running OSD, a mount, swap or a device-mapper \
                     table): stop it first",
                    node.display()
                )
            } else {
                format!("{}: exclusive open: {e}", node.display())
            })
        })?;
    let md = f
        .metadata()
        .map_err(|e| refused(format!("{}: {e}", node.display())))?;
    let r = md.rdev();
    if !md.file_type().is_block_device()
        || format!("{}:{}", libc::major(r), libc::minor(r)) != b.devnum
    {
        return Err(refused(format!(
            "{} is not the block device {} of sysfs",
            node.display(),
            b.devnum
        )));
    }
    flock_exclusive(&f, &node)?;
    // SAFETY: flock is plain old data; all-zero is a valid value.
    let mut fl: libc::flock = unsafe { std::mem::zeroed() };
    fl.l_type = libc::F_WRLCK as libc::c_short;
    fl.l_whence = libc::SEEK_SET as libc::c_short;
    // SAFETY: f owns an open descriptor; fl is a valid flock record the kernel fills in.
    if unsafe { libc::fcntl(f.as_raw_fd(), libc::F_OFD_GETLK, &mut fl) } != 0 {
        return Err(refused(format!(
            "{}: record-lock probe: {}",
            node.display(),
            std::io::Error::last_os_error()
        )));
    }
    if fl.l_type != libc::F_UNLCK as libc::c_short {
        return Err(refused(format!(
            "{} holds a record lock of another process{} (a running OSD?): stop it first",
            node.display(),
            if fl.l_pid > 0 {
                format!(" (pid {})", fl.l_pid)
            } else {
                String::new()
            }
        )));
    }
    Ok(f)
}

/// How long [`flock_exclusive`] waits for a shared lock to go away. udev takes `LOCK_SH` on a whole disk while it
/// processes an event of it (systemd's block-device locking protocol: a writer takes `LOCK_EX`, blocking), so a
/// freshly written or attached disk is briefly locked; an owner's lock is held for its whole life.
const FLOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// `LOCK_EX` on the claimed node, waiting up to [`FLOCK_WAIT`] for transient holders (udev event processing).
fn flock_exclusive(f: &File, node: &Path) -> Result<(), Error> {
    let start = std::time::Instant::now();
    loop {
        // SAFETY: f owns an open descriptor.
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(refused(format!("{}: flock: {e}", node.display())));
        }
        if start.elapsed() >= FLOCK_WAIT {
            eprintln!(
                "WARNING TIMEOUT flock {} exceeded {:.3}s (another process keeps the block-device lock)",
                node.display(),
                FLOCK_WAIT.as_secs_f64()
            );
            return Err(refused(format!(
                "{} is locked (flock) by another process (a running OSD?): stop it first",
                node.display()
            )));
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

fn write_attr(p: &Path, v: &str) -> Result<(), Error> {
    use std::io::Write as _;
    std::fs::OpenOptions::new()
        .write(true)
        .open(p)
        .and_then(|mut f| f.write_all(v.as_bytes()))
        .map_err(|e| Error::Failed(format!("write {v} > {}: {e}", p.display())))
}

fn current_driver(pdir: &Path) -> Option<String> {
    std::fs::read_link(pdir.join("driver"))
        .ok()?
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
}

/// Admit and rebind the NVMe function `pci` to `driver` (one of [`DRIVERS`]); `dry` = admission only (claims are taken
/// and released, nothing is written). Already on `driver` = no change.
pub fn rebind(roots: &Roots, pci: &str, driver: &str, dry: bool) -> Result<Report, Error> {
    let pci = crate::pciallow::canonical_bdf(pci).map_err(refused)?;
    if !DRIVERS.contains(&driver) {
        return Err(refused(format!(
            "driver {driver:?}: must be one of {}",
            DRIVERS.join(", ")
        )));
    }
    let pdir = roots.sysfs.join("bus/pci/devices").join(&pci);
    if !pdir.is_dir() {
        return Err(refused(format!("{pci}: no such PCI device")));
    }
    let class = read_trim(&pdir.join("class"))?;
    if class != NVME_CLASS {
        return Err(refused(format!(
            "{pci}: PCI class {class} is not an NVMe controller ({NVME_CLASS}); check flashstore_dev"
        )));
    }
    let from = current_driver(&pdir);
    let mut report = Report {
        pci: pci.clone(),
        driver: driver.into(),
        from: from.clone(),
        action: "already",
        claimed: Vec::new(),
    };
    if from.as_deref() == Some(driver) {
        return Ok(report);
    }
    let mut held = Vec::new();
    match from.as_deref() {
        None => {}
        Some("nvme") => {
            let blks = block_devices(roots, &pdir)?;
            check_unused(roots, &blks)?;
            for b in blks.iter().filter(|b| !b.part) {
                held.push(claim(roots, b)?);
                report.claimed.push(format!("/dev/{}", b.name));
            }
        }
        // the other userspace driver: an SPDK process may own the function; its claim is taken first
        Some(d) if DRIVERS.contains(&d) => crate::pcilock::claim(&pci).map_err(refused)?,
        Some(d) => {
            return Err(refused(format!(
                "{pci}: bound to driver {d}, not nvme or a userspace NVMe driver; refusing to unbind it"
            )));
        }
    }
    if dry {
        report.action = "dry-run";
        return Ok(report);
    }
    write_attr(&pdir.join("driver_override"), driver)?;
    if from.is_some() {
        write_attr(&pdir.join("driver/unbind"), &pci)?;
    }
    write_attr(&roots.sysfs.join("bus/pci/drivers_probe"), &pci)?;
    let now = current_driver(&pdir);
    if now.as_deref() != Some(driver) {
        return Err(Error::Failed(format!(
            "{pci} did not bind to {driver} (driver now: {})",
            now.as_deref().unwrap_or("none")
        )));
    }
    drop(held);
    report.action = "rebound";
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixture host: PCI function 0000:03:00.0 on `nvme`, controller nvme0 with namespace `ns` (a path node on
    /// multipath hosts), head nvme0n1 (259:0) with partition nvme0n1p1 (259:1).
    struct Fx {
        t: PathBuf,
        roots: Roots,
    }

    impl Fx {
        fn new(tag: &str, ns: &str) -> Fx {
            let t = std::env::temp_dir().join(format!("pcibind-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&t);
            let roots = Roots {
                sysfs: t.join("sys"),
                procfs: t.join("proc"),
                dev: t.join("dev"),
            };
            let p = roots.sysfs.join("bus/pci/devices/0000:03:00.0");
            std::fs::create_dir_all(p.join("nvme/nvme0").join(ns)).unwrap();
            std::fs::create_dir_all(roots.sysfs.join("bus/pci/drivers/nvme")).unwrap();
            std::os::unix::fs::symlink(roots.sysfs.join("bus/pci/drivers/nvme"), p.join("driver"))
                .unwrap();
            std::fs::write(p.join("class"), "0x010802\n").unwrap();
            for f in ["driver_override", "driver/unbind"] {
                std::fs::write(p.join(f), "").unwrap();
            }
            std::fs::write(roots.sysfs.join("bus/pci/drivers_probe"), "").unwrap();
            let h = roots.sysfs.join("block/nvme0n1");
            std::fs::create_dir_all(h.join("holders")).unwrap();
            std::fs::create_dir_all(h.join("nvme0n1p1/holders")).unwrap();
            std::fs::write(h.join("dev"), "259:0\n").unwrap();
            std::fs::write(h.join("nvme0n1p1/dev"), "259:1\n").unwrap();
            std::fs::write(h.join("nvme0n1p1/partition"), "1\n").unwrap();
            std::fs::create_dir_all(roots.procfs.join("self")).unwrap();
            std::fs::write(roots.procfs.join("self/mountinfo"), "").unwrap();
            std::fs::write(
                roots.procfs.join("swaps"),
                "Filename Type Size Used Priority\n",
            )
            .unwrap();
            std::fs::create_dir_all(&roots.dev).unwrap();
            Fx { t, roots }
        }

        fn pdir(&self) -> PathBuf {
            self.roots.sysfs.join("bus/pci/devices/0000:03:00.0")
        }

        fn refusal(&self) -> String {
            match rebind(&self.roots, "0000:03:00.0", "vfio-pci", true) {
                Err(Error::Refused(m)) => m,
                o => panic!("expected a refusal, got {o:?}"),
            }
        }
    }

    impl Drop for Fx {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.t);
        }
    }

    #[test]
    fn namespace_names() {
        for n in ["nvme0n1", "nvme12n3", "nvme0c1n2"] {
            assert!(is_ns_name(n), "{n}");
        }
        for n in [
            "nvme0", "ng0n1", "nvme0n", "nvmexn1", "nvme0c1", "nvme0cn1", "hwmon0",
        ] {
            assert!(!is_ns_name(n), "{n}");
        }
    }

    /// Multipath hosts list the hidden path node under the controller: the head and its partitions are checked.
    #[test]
    fn multipath_path_node_maps_to_the_head_and_its_partitions() {
        let fx = Fx::new("mp", "nvme0c0n1");
        let b = block_devices(&fx.roots, &fx.pdir()).unwrap();
        let names: Vec<_> = b.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(names, ["nvme0n1", "nvme0n1p1"]);
        assert_eq!(b[1].devnum, "259:1");
    }

    #[test]
    fn partition_holder_is_refused() {
        let fx = Fx::new("holder", "nvme0n1");
        std::fs::create_dir_all(fx.roots.sysfs.join("block/nvme0n1/nvme0n1p1/holders/dm-0"))
            .unwrap();
        let m = fx.refusal();
        assert!(m.contains("/dev/nvme0n1p1 has holders dm-0"), "{m}");
    }

    /// The mount source is an alias (`/dev/disk/by-uuid/...`); the device number identifies it.
    #[test]
    fn aliased_partition_mount_is_refused() {
        let fx = Fx::new("mount", "nvme0c0n1");
        std::fs::write(
            fx.roots.procfs.join("self/mountinfo"),
            "40 20 259:1 / /srv/my\\040data rw - xfs /dev/disk/by-uuid/x rw\n",
        )
        .unwrap();
        let m = fx.refusal();
        assert_eq!(m, "/dev/nvme0n1p1 is mounted on /srv/my data");
    }

    #[test]
    fn missing_head_is_refused_not_skipped() {
        let fx = Fx::new("nohead", "nvme0c0n2");
        let m = fx.refusal();
        assert!(m.contains("namespace nvme0n2: no block device"), "{m}");
    }

    #[test]
    fn non_nvme_class_and_foreign_driver_are_refused() {
        let fx = Fx::new("class", "nvme0n1");
        std::fs::write(fx.pdir().join("class"), "0x020000\n").unwrap();
        assert!(fx.refusal().contains("not an NVMe controller"));
        std::fs::write(fx.pdir().join("class"), "0x010802\n").unwrap();
        std::fs::remove_file(fx.pdir().join("driver")).unwrap();
        std::fs::create_dir_all(fx.roots.sysfs.join("bus/pci/drivers/ahci")).unwrap();
        std::os::unix::fs::symlink(
            fx.roots.sysfs.join("bus/pci/drivers/ahci"),
            fx.pdir().join("driver"),
        )
        .unwrap();
        assert!(fx.refusal().contains("bound to driver ahci"));
        assert!(matches!(
            rebind(&fx.roots, "0000:03:00.0", "igb_uio", true),
            Err(Error::Refused(_))
        ));
        assert!(matches!(
            rebind(&fx.roots, "../../x", "vfio-pci", true),
            Err(Error::Refused(_))
        ));
    }

    /// No /dev node (fixture): the claim itself refuses; nothing is written to sysfs.
    #[test]
    fn unclaimable_namespace_writes_nothing() {
        let fx = Fx::new("noclaim", "nvme0n1");
        let r = rebind(&fx.roots, "0000:03:00.0", "vfio-pci", false);
        assert!(
            matches!(&r, Err(Error::Refused(m)) if m.contains("exclusive open")),
            "{r:?}"
        );
        assert_eq!(
            std::fs::read_to_string(fx.pdir().join("driver_override")).unwrap(),
            ""
        );
        assert_eq!(
            std::fs::read_to_string(fx.pdir().join("driver/unbind")).unwrap(),
            ""
        );
    }

    /// An unbound NVMe function (no namespaces) is bound: override, probe; a probe that does not attach fails loudly.
    #[test]
    fn unbound_function_is_bound_and_verified() {
        let fx = Fx::new("unbound", "nvme0n1");
        std::fs::remove_file(fx.pdir().join("driver")).unwrap();
        let r = rebind(&fx.roots, "0000:03:00.0", "vfio-pci", false);
        assert!(
            matches!(&r, Err(Error::Failed(m)) if m.contains("did not bind to vfio-pci")),
            "{r:?}"
        );
        assert_eq!(
            std::fs::read_to_string(fx.pdir().join("driver_override")).unwrap(),
            "vfio-pci"
        );
        assert_eq!(
            std::fs::read_to_string(fx.roots.sysfs.join("bus/pci/drivers_probe")).unwrap(),
            "0000:03:00.0"
        );
        let a = rebind(&fx.roots, "0000:03:00.0", "uio_pci_generic", true).unwrap();
        assert_eq!((a.action, a.from), ("dry-run", None));
    }

    #[test]
    fn already_bound_is_a_no_op() {
        let fx = Fx::new("already", "nvme0n1");
        let r = rebind(&fx.roots, "0000:03:00.0", "nvme", true);
        assert!(r.is_err(), "nvme is not a userspace driver");
        std::fs::remove_file(fx.pdir().join("driver")).unwrap();
        std::fs::create_dir_all(fx.roots.sysfs.join("bus/pci/drivers/vfio-pci")).unwrap();
        std::os::unix::fs::symlink(
            fx.roots.sysfs.join("bus/pci/drivers/vfio-pci"),
            fx.pdir().join("driver"),
        )
        .unwrap();
        let r = rebind(&fx.roots, "0000:03:00.0", "vfio-pci", false).unwrap();
        assert_eq!(r.action, "already");
    }

    /// Real kernel claims on a loop device this test creates (root, Linux; never a real disk). Run by
    /// lab/deploy/tests/croit-flashstore-nvme-admission.sh on a lab VM: `cargo test -p nvme --features kernel
    /// pcibind -- --ignored`.
    #[test]
    #[ignore = "root + loop devices: lab/deploy/tests/croit-flashstore-nvme-admission.sh"]
    fn loop_device_claims() {
        use std::process::Command;
        let sh = |c: &str| {
            let o = Command::new("sh").arg("-c").arg(c).output().unwrap();
            assert!(
                o.status.success(),
                "{c}: {}",
                String::from_utf8_lossy(&o.stderr)
            );
            String::from_utf8_lossy(&o.stdout).trim().to_owned()
        };
        let t = std::env::temp_dir().join(format!("pcibind-loop-{}", std::process::id()));
        std::fs::create_dir_all(t.join("mnt")).unwrap();
        let img = t.join("img");
        sh(&format!("truncate -s 64M {}", img.display()));
        let loopdev = sh(&format!("losetup -f --show {}", img.display()));
        struct Cleanup(String, PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                for c in [
                    format!("umount {}/mnt", self.1.display()),
                    format!("swapoff {}", self.0),
                    format!("dmsetup remove pcibind-test-{}", std::process::id()),
                    format!("losetup -d {}", self.0),
                ] {
                    let _ = Command::new("sh")
                        .arg("-c")
                        .arg(format!("{c} 2>/dev/null"))
                        .status();
                }
                let _ = std::fs::remove_dir_all(&self.1);
            }
        }
        let _c = Cleanup(loopdev.clone(), t.clone());
        let name = loopdev.trim_start_matches("/dev/").to_owned();
        let roots = Roots::default();
        let sysdir = roots.sysfs.join("block").join(&name);
        let b = Blk {
            devnum: read_trim(&sysdir.join("dev")).unwrap(),
            name,
            sysdir,
            part: false,
        };
        let blks = std::slice::from_ref(&b);
        let refusal = |r: Result<File, Error>| match r {
            Err(Error::Refused(m)) => m,
            o => panic!("expected a refusal, got {o:?}"),
        };
        // free: checks pass, claim held; a second exclusive claim is refused while it is held
        sh(&format!("mkswap {loopdev} >/dev/null"));
        check_unused(&roots, blks).unwrap();
        let held = claim(&roots, &b).unwrap();
        assert!(refusal(claim(&roots, &b)).contains("claimed exclusively"));
        // the held claim keeps swap (and likewise a mount or a dm table) out: no race between check and unbind
        assert!(
            Command::new("swapon")
                .arg(&loopdev)
                .status()
                .unwrap()
                .code()
                != Some(0)
        );
        drop(held);
        // swap
        sh(&format!("swapon {loopdev}"));
        let m = format!("{:?}", check_unused(&roots, blks));
        assert!(m.contains("is active swap"), "{m}");
        assert!(refusal(claim(&roots, &b)).contains("claimed exclusively"));
        sh(&format!("swapoff {loopdev}"));
        // mounted
        sh(&format!(
            "mkfs.ext4 -q -F {loopdev} && mount {loopdev} {}/mnt",
            t.display()
        ));
        let m = format!("{:?}", check_unused(&roots, blks));
        assert!(m.contains("is mounted on"), "{m}");
        assert!(refusal(claim(&roots, &b)).contains("claimed exclusively"));
        sh(&format!("umount {}/mnt", t.display()));
        // device-mapper holder
        let size = sh(&format!("blockdev --getsz {loopdev}"));
        sh(&format!(
            "echo '0 {size} linear {loopdev} 0' | dmsetup create pcibind-test-{}",
            std::process::id()
        ));
        let m = format!("{:?}", check_unused(&roots, blks));
        assert!(m.contains("has holders dm-"), "{m}");
        assert!(refusal(claim(&roots, &b)).contains("claimed exclusively"));
        sh(&format!(
            "dmsetup remove pcibind-test-{}",
            std::process::id()
        ));
        // a non-exclusive opener with flock (kernel-tier OSD lock) or an OFD record lock (classic OSD style)
        let other = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&loopdev)
            .unwrap();
        // SAFETY: other owns an open descriptor.
        assert_eq!(
            unsafe { libc::flock(other.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        assert!(refusal(claim(&roots, &b)).contains("locked (flock)"));
        drop(other);
        let other = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&loopdev)
            .unwrap();
        // SAFETY: flock is plain old data.
        let mut fl: libc::flock = unsafe { std::mem::zeroed() };
        fl.l_type = libc::F_WRLCK as libc::c_short;
        fl.l_whence = libc::SEEK_SET as libc::c_short;
        // SAFETY: other owns an open descriptor; fl is valid.
        assert_eq!(
            unsafe { libc::fcntl(other.as_raw_fd(), libc::F_OFD_SETLK, &fl) },
            0
        );
        assert!(refusal(claim(&roots, &b)).contains("record lock"));
        drop(other);
        claim(&roots, &b).unwrap();
    }
}
