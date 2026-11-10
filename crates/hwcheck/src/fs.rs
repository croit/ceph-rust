// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Read-only filesystem view below a root directory (fixture-testable).
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Fs {
    root: PathBuf,
}

impl Fs {
    pub fn new(root: &Path) -> Fs {
        Fs { root: root.into() }
    }
    /// True for the real host (live-only probes allowed).
    pub fn live(&self) -> bool {
        self.root == Path::new("/") && cfg!(target_os = "linux")
    }
    pub fn p(&self, rel: &str) -> PathBuf {
        self.root.join(rel.trim_start_matches('/'))
    }
    pub fn read(&self, rel: &str) -> Option<String> {
        std::fs::read_to_string(self.p(rel))
            .ok()
            .map(|s| s.trim().to_string())
    }
    pub fn num(&self, rel: &str) -> Option<u64> {
        self.read(rel)?.parse().ok()
    }
    /// Linux-style /sys and /proc trees present (false on macOS or an empty fixture).
    pub fn has_sys(&self) -> bool {
        self.exists("sys/devices")
    }
    pub fn has_proc(&self) -> bool {
        self.exists("proc/self") || self.exists("proc/meminfo") || self.exists("proc/cpuinfo")
    }
    pub fn exists(&self, rel: &str) -> bool {
        self.p(rel).exists()
    }
    /// Sorted entry names of a directory (empty when missing).
    pub fn list(&self, rel: &str) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(self.p(rel))
            .map(|d| {
                d.filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }
    /// Last path component of a symlink target (`driver` -> `.../nvme`).
    pub fn link_name(&self, rel: &str) -> Option<String> {
        let t = std::fs::read_link(self.p(rel)).ok()?;
        Some(t.file_name()?.to_string_lossy().into_owned())
    }
    /// `/proc/cmdline` words.
    pub fn cmdline(&self) -> Vec<String> {
        self.read("proc/cmdline")
            .map(|s| s.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default()
    }
    /// Value of `key=` (or bare `key` -> "") on the kernel command line.
    pub fn cmdline_arg(&self, key: &str) -> Option<String> {
        self.cmdline().iter().find_map(|w| {
            if w == key {
                Some(String::new())
            } else {
                w.strip_prefix(key)?.strip_prefix('=').map(str::to_string)
            }
        })
    }
}

/// Largest CPU id a Linux kernel can have (`CONFIG_NR_CPUS` maximum): a wider value in a cpulist is malformed input.
pub const MAX_CPUS: u32 = 8192;

/// `0-3,8,10-11` -> sorted CPU list. Err on a part that is not a list or names a cpu `>= MAX_CPUS` (a conf typo must
/// not allocate a huge list). Kernel-provided lists (sysfs/procfs) are bounded by the kernel; callers there treat Err
/// as "no cpu".
pub fn parse_cpulist(s: &str) -> Result<Vec<u32>, String> {
    let mut v = Vec::new();
    for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let bad = || format!("{part:?} is not a cpu list (0-{})", MAX_CPUS - 1);
        match part.split_once('-') {
            Some((a, b)) => {
                let a = a.parse::<u32>().map_err(|_| bad())?;
                let b = b.parse::<u32>().map_err(|_| bad())?;
                if a > b || b >= MAX_CPUS {
                    return Err(bad());
                }
                v.extend(a..=b);
            }
            None => {
                let a = part.parse::<u32>().map_err(|_| bad())?;
                if a >= MAX_CPUS {
                    return Err(bad());
                }
                v.push(a);
            }
        }
    }
    v.sort_unstable();
    v.dedup();
    Ok(v)
}

pub fn fmt_cpulist(v: &[u32]) -> String {
    let mut out = Vec::new();
    let mut i = 0;
    while i < v.len() {
        let mut j = i;
        while j + 1 < v.len() && v[j + 1] == v[j] + 1 {
            j += 1;
        }
        out.push(if j > i {
            format!("{}-{}", v[i], v[j])
        } else {
            v[i].to_string()
        });
        i = j + 1;
    }
    out.join(",")
}

pub fn mib(kb: u64) -> String {
    if kb >= 1 << 20 {
        format!("{:.1} GiB", kb as f64 / (1u64 << 20) as f64)
    } else {
        format!("{} MiB", kb >> 10)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cpulists() {
        assert_eq!(
            parse_cpulist("0-3,8,10-11"),
            Ok(vec![0, 1, 2, 3, 8, 10, 11])
        );
        assert_eq!(fmt_cpulist(&[0, 1, 2, 3, 8, 10, 11]), "0-3,8,10-11");
        assert!(parse_cpulist("").unwrap().is_empty());
        // a value no kernel can have is a malformed list, not a huge allocation (conf typo)
        assert!(parse_cpulist("0-9000").is_err(), "above MAX_CPUS");
        assert!(parse_cpulist("4000000000").is_err());
        assert!(parse_cpulist("4-x").is_err());
        assert!(parse_cpulist("7-4").is_err(), "reversed range");
        assert_eq!(
            parse_cpulist(&format!("0-{}", MAX_CPUS - 1)).unwrap().len(),
            MAX_CPUS as usize
        );
    }
}
