// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Memory: RAM, hugepages per NUMA node vs the conf's need, hugetlbfs, THP, memlock.
use crate::action::{Action, Step};
use crate::conf::{Conf, DEFAULT_HUGEPAGES_MB};
use crate::fs::{Fs, mib};
use crate::{Check, Facts, Section};

fn meminfo(fs: &Fs, key: &str) -> Option<u64> {
    fs.read("proc/meminfo")?.lines().find_map(|l| {
        l.strip_prefix(key)?
            .strip_prefix(':')?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    })
}

pub fn section(fs: &Fs, cfg: &Conf, facts: &mut Facts) -> Section {
    let mut v = Vec::new();
    match meminfo(fs, "MemTotal") {
        Some(t) => {
            let avail = meminfo(fs, "MemAvailable").unwrap_or(0);
            let c = Check::new("mem.total", "RAM")
                .val(format!("{} total, {} available", mib(t), mib(avail)))
                .why("per OSD: hugepage pool (default 2 GiB) + memory target + page cache of nothing (userspace NVMe): size for OSDs x ~4-8 GiB");
            v.push(if t < 4 << 20 {
                c.fail().fix("add RAM (>= 8 GiB per OSD recommended)")
            } else if t < 16 << 20 {
                c.warn().fix("add RAM (>= 8 GiB per OSD recommended)")
            } else {
                c.ok()
            });
        }
        None => v.push(
            Check::new("mem.total", "RAM")
                .val("not available")
                .why("sizing of hugepages and memory target")
                .na(),
        ),
    }
    // hugepages
    let mut per_node: Vec<String> = Vec::new();
    let mut free_mb = 0u64;
    let mut free_by_size = [0u64; 2];
    let mut total_mb = 0u64;
    // Keep the 2 MiB pool separate: remediation extends that pool only.
    let mut total_2m = 0u64;
    let mut found = false;
    for n in fs
        .list("sys/devices/system/node")
        .iter()
        .filter(|n| n.starts_with("node"))
    {
        for (index, sz) in ["hugepages-2048kB", "hugepages-1048576kB"]
            .iter()
            .enumerate()
        {
            let b = format!("sys/devices/system/node/{n}/hugepages/{sz}");
            if let (Some(tot), Some(free)) = (
                fs.num(&format!("{b}/nr_hugepages")),
                fs.num(&format!("{b}/free_hugepages")),
            ) {
                found = true;
                let kb = if sz.contains("1048576") {
                    1u64 << 20
                } else {
                    2048
                };
                total_mb += (tot * kb) >> 10;
                free_by_size[index] += free;
                if kb == 2048 {
                    total_2m += (tot * kb) >> 10;
                }
                if tot > 0 {
                    per_node.push(format!(
                        "{n} {}: {free}/{tot} free",
                        if kb == 2048 { "2M" } else { "1G" }
                    ));
                }
            }
        }
    }
    if found {
        // Reservations are global per page size, not per NUMA node. These pages
        // are still counted as free until faulted, but already promised to a
        // different mapping; subtract once after summing the nodes.
        for (index, kb) in [2048u64, 1 << 20].into_iter().enumerate() {
            let reserved = fs
                .num(&format!(
                    "sys/kernel/mm/hugepages/hugepages-{kb}kB/resv_hugepages"
                ))
                .or_else(|| {
                    (meminfo(fs, "Hugepagesize") == Some(kb))
                        .then(|| meminfo(fs, "HugePages_Rsvd"))
                        .flatten()
                })
                .unwrap_or(0);
            free_mb += (free_by_size[index].saturating_sub(reserved) * kb) >> 10;
        }
    }
    if !found && let Some(tot) = meminfo(fs, "HugePages_Total") {
        let kb = meminfo(fs, "Hugepagesize").unwrap_or(2048);
        let free = meminfo(fs, "HugePages_Free").unwrap_or(0);
        total_mb = (tot * kb) >> 10;
        free_mb = (free.saturating_sub(meminfo(fs, "HugePages_Rsvd").unwrap_or(0)) * kb) >> 10;
        if kb == 2048 {
            total_2m = total_mb;
        }
        found = true;
        per_node.push(format!("{free}/{tot} free of {} KiB", kb));
    }
    facts.hugepages_free_mb = free_mb;
    let osds = cfg.osds.len().max(1) as u64;
    let need: u64 = if cfg.osds.is_empty() {
        DEFAULT_HUGEPAGES_MB
    } else {
        cfg.osds.iter().map(|o| o.hugepages_mb).sum()
    };
    let hp = Check::new("mem.hugepages", "hugepages")
        .why(format!(
            "SPDK DMA memory (adr 0004); need {need} MiB for {osds} OSD(s) ({})",
            if cfg.osds.is_empty() {
                "default 2048 each, no conf"
            } else {
                "sum of flashstore_hugepages_mb"
            }
        ))
        .w(9);
    v.push(if !found {
        hp.val("not available").na()
    } else {
        let val = format!("{free_mb} MiB free (unreserved) of {total_mb} MiB [{}]", per_node.join("; "));
        // Address the 2 MiB pool explicitly; vm.nr_hugepages controls the
        // boot-selected default size, which can be 1 GiB.
        let pages = total_2m / 2 + need.saturating_sub(free_mb).div_ceil(2);
        let act = Action::new(vec![Step::Write { path: "sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages".into(), want: pages.to_string(), bracket: false }])
            .note(format!("reserves at least {need} MiB free as 2 MiB pages (N = current 2 MiB pool + missing free; a 1 GiB pool is not counted here); or kernel cmdline `hugepagesz=1G hugepages=<N>`; per NUMA node: echo N > /sys/devices/system/node/nodeX/hugepages/hugepages-2048kB/nr_hugepages"));
        if total_mb == 0 {
            hp.val(val).fail().act(act)
        } else if free_mb < need {
            hp.val(val).warn().act(act)
        } else {
            hp.val(val).ok()
        }
    });
    let has_proc = fs.has_proc();
    let hugefs = fs
        .read("proc/mounts")
        .unwrap_or_default()
        .lines()
        .any(|l| l.split_whitespace().nth(2) == Some("hugetlbfs"));
    v.push(
        Check::new("mem.hugetlbfs", "hugetlbfs mount")
            .val(if hugefs { "mounted" } else { "not mounted" })
            .why("SPDK maps hugepages through hugetlbfs (default /dev/hugepages; flashstore_huge_dir)")
            .st(if !has_proc { crate::Status::Na } else if hugefs { crate::Status::Ok } else { crate::Status::Warn })
            .act(Action::new(vec![Step::Mount { fstype: "hugetlbfs".into(), dev: "nodev".into(), target: "/dev/hugepages".into() }]).note("croit-flashstore-prep does this too"))
            .w(5),
    );
    match fs.read("sys/kernel/mm/transparent_hugepage/enabled") {
        Some(t) => {
            let sel = t
                .split('[')
                .nth(1)
                .and_then(|s| s.split(']').next())
                .unwrap_or("?")
                .to_string();
            v.push(
                Check::new("mem.thp", "transparent hugepages")
                    .val(sel.clone())
                    .why("`always` can stall allocation/compaction for ms on the hot path; madvise/never is neutral (DMA memory comes from reserved hugepages)")
                    .warn_if(sel == "always")
                    .act(Action::new(vec![Step::Write { path: "sys/kernel/mm/transparent_hugepage/enabled".into(), want: "madvise".into(), bracket: true }]).note("or cmdline transparent_hugepage=madvise"))
                    .w(3),
            );
        }
        None => v.push(
            Check::new("mem.thp", "transparent hugepages")
                .val("not available")
                .why("THP compaction stalls")
                .na(),
        ),
    }
    // memlock
    let lim = fs.read("proc/self/limits").and_then(|s| {
        s.lines()
            .find(|l| l.starts_with("Max locked memory"))
            .map(|l| l.split_whitespace().nth(3).unwrap_or("?").to_string())
    });
    v.push(match lim {
        Some(l) => Check::new("mem.memlock", "memlock limit (this process)")
            .val(l.clone())
            .why("DMA memory must be pinned; `croit-flashstore-tool activate` requires unlimited (the daemon unit sets LimitMEMLOCK=infinity)")
            .warn_if(l != "unlimited")
            .fix("systemd: LimitMEMLOCK=infinity; docker: --ulimit memlock=-1; shell: ulimit -l unlimited")
            .w(4),
        None => Check::new("mem.memlock", "memlock limit (this process)").val("not available").why("DMA memory must be pinned").na(),
    });
    Section {
        name: "Memory",
        checks: v,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn root(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("hwcheck-mem-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn write(root: &Path, rel: &str, s: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, s).unwrap();
    }

    fn hugepages_check(root: &Path) -> Check {
        let fs = Fs::new(root);
        let cfg = Conf {
            osds: crate::conf::parse("[osd.0]\nflashstore_hugepages_mb = 2048\n"),
            ..Default::default()
        };
        section(&fs, &cfg, &mut Facts::default())
            .checks
            .into_iter()
            .find(|c| c.id == "mem.hugepages")
            .unwrap()
    }

    #[test]
    fn reserved_hugepages_are_not_available_to_a_new_osd() {
        for numa in [false, true] {
            let r = root(if numa {
                "reserved-numa"
            } else {
                "reserved-proc"
            });
            write(
                &r,
                "proc/meminfo",
                "HugePages_Total: 1024\nHugePages_Free: 1024\nHugePages_Rsvd: 512\nHugepagesize: 2048 kB\n",
            );
            if numa {
                for node in [0, 1] {
                    let b =
                        format!("sys/devices/system/node/node{node}/hugepages/hugepages-2048kB");
                    write(&r, &format!("{b}/nr_hugepages"), "512");
                    write(&r, &format!("{b}/free_hugepages"), "512");
                }
                write(
                    &r,
                    "sys/kernel/mm/hugepages/hugepages-2048kB/resv_hugepages",
                    "512",
                );
            }
            let c = hugepages_check(&r);
            assert_eq!(c.status, crate::Status::Warn, "{c:?}");
            assert!(c.value.starts_with("1024 MiB free"), "{}", c.value);
            assert!(
                c.fix
                    .unwrap()
                    .contains("echo 1536 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages")
            );
            let _ = std::fs::remove_dir_all(r);
        }
    }

    #[test]
    fn reservations_stay_with_their_page_size() {
        let r = root("reserved-mixed");
        for (size, count) in [(2048, 512), (1048576, 2)] {
            let b = format!("sys/devices/system/node/node0/hugepages/hugepages-{size}kB");
            write(&r, &format!("{b}/nr_hugepages"), &count.to_string());
            write(&r, &format!("{b}/free_hugepages"), &count.to_string());
        }
        write(
            &r,
            "sys/kernel/mm/hugepages/hugepages-1048576kB/resv_hugepages",
            "2",
        );
        let c = hugepages_check(&r);
        assert_eq!(c.status, crate::Status::Warn);
        assert!(c.value.starts_with("1024 MiB free"), "{}", c.value);
        // A racing snapshot with more reservations than free pages must not
        // underflow or consume the other page-size pool.
        write(
            &r,
            "sys/kernel/mm/hugepages/hugepages-1048576kB/resv_hugepages",
            "3",
        );
        assert!(hugepages_check(&r).value.starts_with("1024 MiB free"));
        let _ = std::fs::remove_dir_all(r);
    }

    #[test]
    fn hugepage_fix_targets_2m_pages_with_a_1g_default() {
        let r = root("default-1g");
        write(
            &r,
            "proc/meminfo",
            "HugePages_Total: 0\nHugePages_Free: 0\nHugepagesize: 1048576 kB\n",
        );
        let c = hugepages_check(&r);
        assert_eq!(c.status, crate::Status::Fail);
        let fix = c.fix.unwrap();
        assert!(
            fix.contains("sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"),
            "{fix}"
        );
        assert!(!fix.contains("sysctl -w vm.nr_hugepages"), "{fix}");
        let _ = std::fs::remove_dir_all(r);
    }

    /// The remedy extends only the 2 MiB pool: the 1 GiB pool must not be counted again
    /// (that would reserve the same memory twice).
    #[test]
    fn hugepage_remedy_counts_the_2m_pool_only() {
        let r = root("1g");
        write(
            &r,
            "sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages",
            "2\n",
        );
        write(
            &r,
            "sys/devices/system/node/node0/hugepages/hugepages-1048576kB/free_hugepages",
            "0\n",
        );
        write(
            &r,
            "sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages",
            "0\n",
        );
        write(
            &r,
            "sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages",
            "0\n",
        );
        let c = hugepages_check(&r);
        let f = c.fix.unwrap();
        assert!(
            f.contains("echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"),
            "2048 MiB of 2 MiB pages on top of the 4 GiB reserved as 1 GiB pages: {f}"
        );
        // an existing 2 MiB pool is extended by the missing amount
        write(
            &r,
            "sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages",
            "1024\n",
        );
        let f = hugepages_check(&r).fix.unwrap();
        assert!(
            f.contains("echo 2048 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"),
            "{f}"
        );
        let _ = std::fs::remove_dir_all(&r);
    }
}
