// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! L3 / NUMA aware core placement (adr 0063). Reads the CPU topology from `/sys`, groups the allowed CPUs into L3
//! domains (a CCD on AMD, a socket on most Intel, a NUMA node when the kernel reports no L3) and picks the CPUs of
//! one domain for an OSD: one thread per physical core first, then SMT siblings of the same domain, then the next
//! domain. Several OSDs on a host take different domains: preferred rank = OSD id, refined by a `flock` on
//! `<lockdir>/croit-flashstore-l3-<node>-<l3>.lock` (held for the life of the process, released on crash). The lock file is
//! opened with `O_NOFOLLOW` (never a symlink or a hard link to a foreign inode) and chmod'ed through the descriptor,
//! not the path; a lock file that is not a plain single-link file is refused (plain rank, no lock).
//! Only CPUs of the given mask are ever returned; the number of CPUs equals the request (never fewer).
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::Path;

/// Key used for a CPU without L3 information: one pseudo domain per NUMA node.
const NO_L3: usize = 1 << 20;

/// One allowed CPU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuInfo {
    pub cpu: usize,
    pub node: usize,
    /// Lowest CPU id sharing this CPU's L3 (`NO_L3 + node` without L3 info).
    pub l3: usize,
    /// Lowest CPU id among the SMT siblings (identifies the physical core).
    pub core: usize,
}

/// Topology of the allowed CPUs.
#[derive(Debug, Clone, Default)]
pub struct Topology {
    pub cpus: Vec<CpuInfo>,
}

/// CPUs of one L3 domain: physical cores first (one thread each), then SMT siblings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Domain {
    pub node: usize,
    pub l3: usize,
    pub cpus: Vec<usize>,
}

/// Result of [`place`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placement {
    /// Ascending; core `i` of the OSD runs on `cpus[i]`.
    pub cpus: Vec<usize>,
    pub node: usize,
    pub l3: usize,
    /// L3 domains available in the mask.
    pub domains: usize,
    /// More CPUs than the chosen domain holds (other domains used too).
    pub spilled: bool,
}

impl Placement {
    /// One-line description for the log / OSD metadata.
    pub fn describe(&self) -> String {
        format!(
            "cpus={:?} l3={} node={} domains_in_mask={}{}",
            self.cpus,
            self.l3,
            self.node,
            self.domains,
            if self.spilled { " spilled" } else { "" }
        )
    }
}

/// Parse a kernel cpulist (`0-3,8,10-11`).
pub fn parse_cpulist(s: &str) -> Option<Vec<usize>> {
    let mut v = Vec::new();
    for p in s.trim().split(',').filter(|p| !p.is_empty()) {
        match p.split_once('-') {
            Some((a, b)) => {
                let (a, b): (usize, usize) = (a.trim().parse().ok()?, b.trim().parse().ok()?);
                if b < a || b - a > 1 << 16 {
                    return None;
                }
                v.extend(a..=b);
            }
            None => v.push(p.trim().parse().ok()?),
        }
    }
    Some(v)
}

fn read_list(p: &Path) -> Option<Vec<usize>> {
    parse_cpulist(&std::fs::read_to_string(p).ok()?)
}

impl Topology {
    /// Read `root` (= `/sys`) for the CPUs of `mask`. Missing files degrade: node 0, no L3, no SMT.
    pub fn read(root: &Path, mask: &[usize]) -> Topology {
        let base = root.join("devices/system/cpu");
        let cpus = mask
            .iter()
            .map(|&cpu| {
                let d = base.join(format!("cpu{cpu}"));
                let node = std::fs::read_dir(&d)
                    .ok()
                    .and_then(|rd| {
                        rd.filter_map(|e| {
                            let n = e.ok()?.file_name().into_string().ok()?;
                            n.strip_prefix("node")?.parse::<usize>().ok()
                        })
                        .min()
                    })
                    .unwrap_or(0);
                let l3 = std::fs::read_dir(d.join("cache"))
                    .ok()
                    .and_then(|rd| {
                        rd.filter_map(|e| {
                            let p = e.ok()?.path();
                            let lvl = std::fs::read_to_string(p.join("level")).ok()?;
                            if lvl.trim() != "3" {
                                return None;
                            }
                            read_list(&p.join("shared_cpu_list"))?.into_iter().min()
                        })
                        .min()
                    })
                    .unwrap_or(NO_L3 + node);
                let core = read_list(&d.join("topology/thread_siblings_list"))
                    .and_then(|v| v.into_iter().min())
                    .unwrap_or(cpu);
                CpuInfo {
                    cpu,
                    node,
                    l3,
                    core,
                }
            })
            .collect();
        Topology { cpus }
    }

    /// L3 domains of the mask. With `hint` (NUMA node of the NVMe / NIC) the domains of that node come first; the
    /// second value is how many leading domains are preferred (all of them without a usable hint).
    pub fn domains(&self, hint: Option<usize>) -> (Vec<Domain>, usize) {
        let mut m: BTreeMap<(usize, usize), Vec<&CpuInfo>> = BTreeMap::new();
        for c in &self.cpus {
            m.entry((c.node, c.l3)).or_default().push(c);
        }
        let mut doms: Vec<Domain> = m
            .into_iter()
            .map(|((node, l3), mut v)| {
                v.sort_by_key(|c| c.cpu);
                let mut seen = BTreeSet::new();
                let (prim, sec): (Vec<_>, Vec<_>) =
                    v.into_iter().partition(|c| seen.insert(c.core));
                Domain {
                    node,
                    l3,
                    cpus: prim.into_iter().chain(sec).map(|c| c.cpu).collect(),
                }
            })
            .collect();
        let pref = hint.map_or(0, |h| doms.iter().filter(|d| d.node == h).count());
        if pref == 0 {
            let n = doms.len();
            return (doms, n);
        }
        doms.sort_by_key(|d| d.node != hint.unwrap_or(usize::MAX)); // stable
        (doms, pref)
    }
}

/// Pick `n` CPUs: start in preferred domain `rank % pref`, fill physical cores then siblings, then continue with the
/// rest of the preferred domains (rotated from the start) and finally the other nodes. `n` is clamped to the mask.
pub fn place(doms: &[Domain], pref: usize, n: usize, rank: usize) -> Placement {
    assert!(!doms.is_empty() && pref >= 1 && pref <= doms.len());
    let start = rank % pref;
    let order: Vec<&Domain> = (0..pref)
        .map(|i| &doms[(start + i) % pref])
        .chain(&doms[pref..])
        .collect();
    let total: usize = doms.iter().map(|d| d.cpus.len()).sum();
    let n = n.min(total);
    let mut cpus: Vec<usize> = order
        .iter()
        .flat_map(|d| d.cpus.iter().copied())
        .take(n)
        .collect();
    cpus.sort_unstable();
    Placement {
        cpus,
        node: order[0].node,
        l3: order[0].l3,
        domains: doms.len(),
        spilled: n > order[0].cpus.len(),
    }
}

/// Open (create) one rank lock file without following a symlink and without trusting a foreign inode: a regular file
/// with a single link. `None` = unusable (symlink, hard link, device node, no permission): the caller falls back to
/// the plain rank instead of touching it. The mode is set through the descriptor (fchmod), never through the path:
/// `/run/ceph` is shared with the classic packages and the lock names are predictable.
#[cfg(unix)]
fn open_lock_file(p: &Path) -> Option<File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    // Validate the inode after opening without ever waiting for a FIFO writer.
    // In particular, the read-only fallback below must not block before fstat.
    let flags = libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
    let rw = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(flags)
        .mode(0o644)
        .open(p);
    let f = match rw {
        Ok(f) => f,
        // a lock file created by another uid (root lab vs ceph): flock works on a read-only descriptor
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(flags)
            .open(p)
            .ok()?,
        Err(_) => return None,
    };
    let m = f.metadata().ok()?;
    if !m.is_file() || m.nlink() != 1 {
        return None;
    }
    // let the other uid lock the same file (best effort: only the owner can); never chmod a path
    let _ = f.set_permissions(std::fs::Permissions::from_mode(0o644));
    Some(f)
}

#[cfg(not(unix))]
fn open_lock_file(_p: &Path) -> Option<File> {
    None
}

/// Take the first free domain at or after `pref_rank` (of the `pref` preferred ones) by locking its file; returns
/// the rank and the held lock (leak it: it lives as long as the process). Without a usable lock dir, or when every
/// domain is taken, the plain `pref_rank % pref` and no lock.
pub fn claim_rank(
    doms: &[Domain],
    pref: usize,
    pref_rank: usize,
    lockdir: &Path,
) -> (usize, Option<File>) {
    let plain = pref_rank % pref.max(1);
    if pref <= 1 || std::fs::create_dir_all(lockdir).is_err() {
        return (plain, None);
    }
    for i in 0..pref {
        let r = (plain + i) % pref;
        let d = &doms[r];
        let p = lockdir.join(format!("croit-flashstore-l3-{}-{}.lock", d.node, d.l3));
        let Some(f) = open_lock_file(&p) else {
            return (plain, None);
        };
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: valid open fd; flock has no memory effects.
            if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return (r, Some(f));
            }
        }
    }
    (plain, None)
}

/// NUMA node of a PCI device (`/sys/bus/pci/devices/<bdf>/numa_node`; `-1` / missing = unknown).
pub fn pci_numa_node(root: &Path, bdf: &str) -> Option<usize> {
    let s =
        std::fs::read_to_string(root.join("bus/pci/devices").join(bdf).join("numa_node")).ok()?;
    s.trim()
        .parse::<i64>()
        .ok()
        .and_then(|v| usize::try_from(v).ok())
}

/// Outcome of [`avoid_irq`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Irq {
    /// No NIC IRQ lands on a CPU of the mask.
    Clear,
    /// The mask was narrowed to IRQ-free CPUs; the CPUs left out.
    Avoided(Vec<usize>),
    /// Fewer IRQ-free CPUs than cores wanted (IRQs spread over the whole mask or most of it): the mask is unchanged and
    /// the OSD shares these CPUs with NIC IRQs, silently (adr 0063 am. 2).
    Shared(Vec<usize>),
}

/// Drop the CPUs that take NIC queue IRQs (`irq`) from `mask` when at least `n` CPUs remain (IRQs confined to a
/// subset); the OSD cores are then chosen among IRQ-free CPUs only. Otherwise the mask is kept and shared. Returns the mask to place on and what happened.
pub fn avoid_irq(mask: &[usize], irq: &[usize], n: usize) -> (Vec<usize>, Irq) {
    let (hit, free): (Vec<usize>, Vec<usize>) = mask.iter().partition(|c| irq.contains(c));
    if hit.is_empty() {
        (mask.to_vec(), Irq::Clear)
    } else if free.len() >= n {
        (free, Irq::Avoided(hit))
    } else {
        (mask.to_vec(), Irq::Shared(hit))
    }
}

/// Inputs of [`auto_place`].
#[derive(Debug)]
pub struct Request<'a> {
    /// CPUs the process may use (`affinity_cpus`).
    pub mask: &'a [usize],
    /// Number of cores wanted (`<= mask.len()`).
    pub n: usize,
    /// Preferred rank, e.g. the OSD id.
    pub rank: usize,
    /// NUMA node of the NVMe / NIC.
    pub hint_node: Option<usize>,
}

/// Production entry: `/sys` topology + `/run/ceph` locks. Falls back to `mask[..n]` when the mask has a single
/// domain worth of choice (n covers the whole mask) or placement yields fewer CPUs than asked.
pub fn auto_place(r: &Request) -> (Vec<usize>, Option<Placement>) {
    let plain = r.mask[..r.n.min(r.mask.len())].to_vec();
    if r.n >= r.mask.len() {
        return (plain, None);
    }
    let topo = Topology::read(Path::new("/sys"), r.mask);
    let (doms, pref) = topo.domains(r.hint_node);
    if doms.is_empty() {
        return (plain, None);
    }
    let (rank, lock) = claim_rank(&doms, pref, r.rank, Path::new("/run/ceph"));
    std::mem::forget(lock);
    let p = place(&doms, pref, r.n, rank);
    if p.cpus.len() != plain.len() || p.cpus.iter().any(|c| !r.mask.contains(c)) {
        return (plain, None);
    }
    (p.cpus.clone(), Some(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// `(cpu, node, l3 shared list or None, siblings list)`.
    type Fx = (usize, usize, Option<&'static str>, &'static str);

    fn fixture(tag: &str, cpus: &[Fx]) -> PathBuf {
        let root = std::env::temp_dir().join(format!("rt-topo-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for &(c, node, l3, sib) in cpus {
            let d = root.join(format!("devices/system/cpu/cpu{c}"));
            std::fs::create_dir_all(d.join("topology")).unwrap();
            std::fs::create_dir_all(d.join(format!("node{node}"))).unwrap();
            std::fs::write(d.join("topology/thread_siblings_list"), format!("{sib}\n")).unwrap();
            // index0..2 = private caches, index3 = L3
            let i2 = d.join("cache/index2");
            std::fs::create_dir_all(&i2).unwrap();
            std::fs::write(i2.join("level"), "2\n").unwrap();
            std::fs::write(i2.join("shared_cpu_list"), format!("{sib}\n")).unwrap();
            if let Some(l) = l3 {
                let i3 = d.join("cache/index3");
                std::fs::create_dir_all(&i3).unwrap();
                std::fs::write(i3.join("level"), "3\n").unwrap();
                std::fs::write(i3.join("shared_cpu_list"), format!("{l}\n")).unwrap();
            }
        }
        root
    }

    /// AMD-like, NPS1, SMT on: CCD0 = cores 0-3 (+ siblings 8-11), CCD1 = 4-7 (+12-15).
    fn amd_smt() -> Vec<Fx> {
        (0..16)
            .map(|c| {
                let ccd = (c % 8) / 4;
                let (l3, sib) = match (ccd, c < 8) {
                    (0, _) => ("0-3,8-11", ["0,8", "1,9", "2,10", "3,11"][c % 4]),
                    _ => ("4-7,12-15", ["4,12", "5,13", "6,14", "7,15"][c % 4]),
                };
                (c, 0, Some(l3), sib)
            })
            .collect()
    }

    fn topo(root: &Path, mask: &[usize]) -> (Vec<Domain>, usize) {
        Topology::read(root, mask).domains(None)
    }

    #[test]
    fn cpulist() {
        assert_eq!(
            parse_cpulist("0-3,8,10-11\n"),
            Some(vec![0, 1, 2, 3, 8, 10, 11])
        );
        assert_eq!(parse_cpulist("5"), Some(vec![5]));
        assert_eq!(parse_cpulist("3-1"), None);
        assert_eq!(parse_cpulist("x"), None);
    }

    #[test]
    fn amd_ccd_one_thread_per_core_then_siblings() {
        let root = fixture("amd", &amd_smt());
        let mask: Vec<usize> = (0..16).collect();
        let (d, pref) = topo(&root, &mask);
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].cpus, vec![0, 1, 2, 3, 8, 9, 10, 11]);
        let p0 = place(&d, pref, 4, 0);
        assert_eq!(
            (p0.cpus.as_slice(), p0.l3, p0.spilled),
            (&[0, 1, 2, 3][..], 0, false)
        );
        // second OSD lands on the other CCD
        assert_eq!(place(&d, pref, 4, 1).cpus, vec![4, 5, 6, 7]);
        assert_eq!(place(&d, pref, 4, 2).cpus, vec![0, 1, 2, 3]); // wraps
        // 6 cores: 4 physical + 2 siblings of the same CCD, no spill
        let p = place(&d, pref, 6, 0);
        assert_eq!(
            (p.cpus.as_slice(), p.spilled),
            (&[0, 1, 2, 3, 8, 9][..], false)
        );
        // 10 cores: whole CCD0 + physical cores of CCD1
        let p = place(&d, pref, 10, 0);
        assert_eq!(p.cpus, vec![0, 1, 2, 3, 4, 5, 8, 9, 10, 11]);
        assert!(p.spilled);
        // everything
        assert_eq!(place(&d, pref, 99, 0).cpus.len(), 16);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn never_outside_mask_and_same_count() {
        let root = fixture("mask", &amd_smt());
        let mask = [0, 1, 8, 9, 12];
        let (d, pref) = topo(&root, &mask);
        assert_eq!(d.len(), 2);
        for rank in 0..3 {
            for n in 1..=5 {
                let p = place(&d, pref, n, rank);
                assert_eq!(p.cpus.len(), n);
                assert!(p.cpus.iter().all(|c| mask.contains(c)), "{p:?}");
            }
        }
        // rank 1 -> CCD1, which only has cpu 12 in the mask
        assert_eq!(place(&d, pref, 1, 1).cpus, vec![12]);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn smt_off_amd() {
        let cpus: Vec<Fx> = (0..8)
            .map(|c| {
                (
                    c,
                    0,
                    Some(if c < 4 { "0-3" } else { "4-7" }),
                    ["0", "1", "2", "3", "4", "5", "6", "7"][c],
                )
            })
            .collect();
        let root = fixture("nosmt", &cpus);
        let (d, pref) = topo(&root, &(0..8).collect::<Vec<_>>());
        assert_eq!(place(&d, pref, 3, 1).cpus, vec![4, 5, 6]);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn intel_socket_l3_and_node_hint() {
        // 2 sockets, one L3 each; SMT siblings (c, c+8)
        let cpus: Vec<Fx> = (0..16)
            .map(|c| {
                let s = (c % 8) / 4;
                (
                    c,
                    s,
                    Some(if s == 0 { "0-3,8-11" } else { "4-7,12-15" }),
                    ["0,8", "1,9", "2,10", "3,11", "4,12", "5,13", "6,14", "7,15"][c % 8],
                )
            })
            .collect();
        let root = fixture("intel", &cpus);
        let t = Topology::read(&root, &(0..16).collect::<Vec<_>>());
        let (d, pref) = t.domains(None);
        assert_eq!(place(&d, pref, 4, 0).cpus, vec![0, 1, 2, 3]);
        // NVMe on node 1: even rank 0 goes there
        let (d, pref) = t.domains(Some(1));
        assert_eq!(pref, 1);
        let p = place(&d, pref, 4, 0);
        assert_eq!((p.cpus.as_slice(), p.node), (&[4, 5, 6, 7][..], 1));
        // more than the node has: spill to the other node
        assert!(place(&d, pref, 12, 0).spilled);
        // hint for a node outside the mask: ignored
        let (_, pref) = t.domains(Some(7));
        assert_eq!(pref, 2);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn arm_without_l3_uses_nodes() {
        let cpus: Vec<Fx> = (0..8)
            .map(|c| (c, c / 4, None, ["0", "1", "2", "3", "4", "5", "6", "7"][c]))
            .collect();
        let root = fixture("arm", &cpus);
        let (d, pref) = topo(&root, &(0..8).collect::<Vec<_>>());
        assert_eq!(d.len(), 2);
        assert_eq!(place(&d, pref, 2, 1).cpus, vec![4, 5]);
        // missing sysfs entirely: one domain, count preserved
        let (d, pref) = topo(Path::new("/nonexistent-sys"), &[2, 3, 5]);
        assert_eq!(d.len(), 1);
        assert_eq!(place(&d, pref, 2, 9).cpus.len(), 2);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn lock_claims_distinct_domains() {
        let root = fixture("lock", &amd_smt());
        let (d, pref) = topo(&root, &(0..16).collect::<Vec<_>>());
        let dir = root.join("run");
        let (r0, l0) = claim_rank(&d, pref, 0, &dir);
        let (r1, l1) = claim_rank(&d, pref, 0, &dir); // same preference, taken -> next
        assert_eq!((r0, r1), (0, 1));
        let (r2, l2) = claim_rank(&d, pref, 0, &dir); // all taken: plain preference, no lock
        assert_eq!(r2, 0);
        assert!(l0.is_some() && l1.is_some() && l2.is_none());
        drop(l0); // process exit analog: domain 0 is free again
        assert_eq!(claim_rank(&d, pref, 1, &dir).0, 0);
        // unusable lock dir: deterministic by rank
        let (r, l) = claim_rank(&d, pref, 3, Path::new("/proc/nope/x"));
        assert!(r == 1 && l.is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn lock_file_symlink_is_refused_not_followed() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = fixture("locksym", &amd_smt());
        let (d, pref) = topo(&root, &(0..16).collect::<Vec<_>>());
        let dir = root.join("run");
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim");
        std::fs::write(&victim, "secret").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();
        // predictable name of domain 0: a symlink to a root/ceph-owned file must not be chmod'ed (or locked)
        symlink(&victim, dir.join("croit-flashstore-l3-0-0.lock")).unwrap();
        let (r, lock) = claim_rank(&d, pref, 0, &dir);
        assert!(lock.is_none(), "symlinked lock file was followed");
        assert_eq!(r, 0);
        assert_eq!(
            std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o600,
            "target of the symlink changed mode"
        );
        // a hard link to a foreign inode is refused too (the lock would be that inode)
        let other = dir.join("other");
        std::fs::write(&other, "x").unwrap();
        std::fs::remove_file(dir.join("croit-flashstore-l3-0-0.lock")).unwrap();
        std::fs::hard_link(&other, dir.join("croit-flashstore-l3-0-0.lock")).unwrap();
        assert!(claim_rank(&d, pref, 0, &dir).1.is_none());
        // an ordinary lock file is created 0644 and locked
        std::fs::remove_file(dir.join("croit-flashstore-l3-0-0.lock")).unwrap();
        let (r, lock) = claim_rank(&d, pref, 0, &dir);
        assert_eq!(r, 0);
        assert!(lock.is_some());
        let m = std::fs::metadata(dir.join("croit-flashstore-l3-0-0.lock"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(m, 0o644, "lock file is created world-writable");
        drop(lock);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn read_only_fifo_lock_is_refused_without_waiting_for_a_writer() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        use std::time::Duration;

        let root = fixture("lockfifo", &[]);
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("lock");
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: valid NUL-terminated path in this test's private directory.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o444) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        let worker_path = path.clone();
        let worker = std::thread::spawn(move || {
            tx.send(open_lock_file(&worker_path).is_none()).unwrap();
        });
        let outcome = rx.recv_timeout(Duration::from_secs(2));
        let writer = if outcome.is_err() {
            eprintln!(
                "WARNING TIMEOUT lock FIFO validation exceeded 2s (waiting for a writer before inode validation)"
            );
            // Release the old implementation's blocking read-only open before
            // joining it, so the regression itself never strands a thread.
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            Some(
                std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(&path)
                    .unwrap(),
            )
        } else {
            None
        };
        worker.join().unwrap();
        drop(writer);
        std::fs::remove_dir_all(root).unwrap();
        assert_eq!(outcome, Ok(true), "must reject the FIFO before waiting");
    }

    #[test]
    fn irq_cpus_are_avoided_when_enough_remain() {
        let mask: Vec<usize> = (0..8).collect();
        assert_eq!(avoid_irq(&mask, &[20], 4), (mask.clone(), Irq::Clear));
        assert_eq!(
            avoid_irq(&mask, &[0, 1, 9], 4),
            (vec![2, 3, 4, 5, 6, 7], Irq::Avoided(vec![0, 1]))
        );
        // exactly n left: still avoided
        assert_eq!(avoid_irq(&mask, &[0, 1, 2, 3], 4).0, vec![4, 5, 6, 7]);
        // one short: unchanged, shared silently (partial coverage)
        assert_eq!(
            avoid_irq(&mask, &[0, 1, 2, 3, 4], 4),
            (mask.clone(), Irq::Shared(vec![0, 1, 2, 3, 4]))
        );
        // IRQs on the whole mask (spread layout): shared
        let all: Vec<usize> = (0..8).collect();
        assert_eq!(
            avoid_irq(&mask, &all, 4),
            (mask.clone(), Irq::Shared(all.clone()))
        );
        // placement on the narrowed mask never returns an IRQ cpu, on any rank
        let root = fixture("irq", &amd_smt());
        let (narrow, _) = avoid_irq(&(0..16).collect::<Vec<_>>(), &[0, 4, 8], 4);
        let (d, pref) = topo(&root, &narrow);
        for rank in 0..3 {
            let p = place(&d, pref, 4, rank);
            assert!(p.cpus.iter().all(|c| ![0, 4, 8].contains(c)), "{p:?}");
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pci_node() {
        let root = std::env::temp_dir().join(format!("rt-topo-{}-pci", std::process::id()));
        let d = root.join("bus/pci/devices/0000:41:00.0");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("numa_node"), "1\n").unwrap();
        assert_eq!(pci_numa_node(&root, "0000:41:00.0"), Some(1));
        std::fs::write(d.join("numa_node"), "-1\n").unwrap();
        assert_eq!(pci_numa_node(&root, "0000:41:00.0"), None);
        assert_eq!(pci_numa_node(&root, "0000:99:00.0"), None);
        let _ = std::fs::remove_dir_all(root);
    }
}
