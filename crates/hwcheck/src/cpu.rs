// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! CPU: model, topology, instruction flags, clock, power states, isolation, cgroup limits.
use crate::action::{Action, Step};
use crate::conf::{CORE_BUDGET, Conf};
use crate::fs::{Fs, fmt_cpulist, parse_cpulist};
use crate::{Check, Facts, Section};
use std::collections::{BTreeSet, HashMap};

/// First processor block of /proc/cpuinfo as key -> value.
fn cpuinfo(fs: &Fs) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for l in fs.read("proc/cpuinfo").unwrap_or_default().lines() {
        if l.trim().is_empty() && !m.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            m.entry(k.trim().to_string())
                .or_insert_with(|| v.trim().to_string());
        }
    }
    m
}

/// Marketing generation from family/model (best effort; empty when unknown).
pub fn generation(vendor: &str, family: u32, model: u32, stepping: u32) -> &'static str {
    match (vendor, family, model) {
        ("AuthenticAMD", 0x17, 0x31 | 0x30 | 0x70..=0x7f) => "AMD Zen 2 (Rome/Matisse)",
        ("AuthenticAMD", 0x17, _) => "AMD Zen/Zen+",
        ("AuthenticAMD", 0x19, 0x00..=0x0f | 0x30..=0x5f) => "AMD Zen 3 (Milan)",
        ("AuthenticAMD", 0x19, _) => "AMD Zen 4 (Genoa/Bergamo)",
        ("AuthenticAMD", 0x1a, _) => "AMD Zen 5 (Turin)",
        ("GenuineIntel", 6, 0x3f) => "Intel Haswell-EP",
        ("GenuineIntel", 6, 0x4f | 0x56) => "Intel Broadwell",
        ("GenuineIntel", 6, 0x55) if stepping >= 5 => "Intel Cascade/Cooper Lake",
        ("GenuineIntel", 6, 0x55) => "Intel Skylake-SP",
        ("GenuineIntel", 6, 0x6a | 0x6c) => "Intel Ice Lake-SP",
        ("GenuineIntel", 6, 0x8f) => "Intel Sapphire Rapids",
        ("GenuineIntel", 6, 0xcf) => "Intel Emerald Rapids",
        ("GenuineIntel", 6, 0xad | 0xae) => "Intel Granite Rapids",
        _ => "",
    }
}

pub fn section(fs: &Fs, cfg: &Conf, facts: &mut Facts) -> Section {
    let mut v = Vec::new();
    let ci = cpuinfo(fs);
    let flags: BTreeSet<String> = ci
        .get("flags")
        .or_else(|| ci.get("Features"))
        .map(|s| s.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();
    let has = |f: &str| flags.contains(f);
    let x86 = ci.contains_key("vendor_id");
    let arm = ci.contains_key("CPU implementer");

    // model
    if x86 {
        let vendor = ci.get("vendor_id").cloned().unwrap_or_default();
        let n = |k: &str| ci.get(k).and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
        let gen_ = generation(&vendor, n("cpu family"), n("model"), n("stepping"));
        v.push(
            Check::new("cpu.model", "CPU")
                .val(format!(
                    "{} {} (family {} model {} stepping {}){}",
                    vendor,
                    ci.get("model name").cloned().unwrap_or_default(),
                    n("cpu family"),
                    n("model"),
                    n("stepping"),
                    if gen_.is_empty() { String::new() } else { format!(" = {gen_}") }
                ))
                .why("x86-64 server class CPU (Zen 3+/Ice Lake+) is the measured baseline for the cycles/byte budgets")
                .ok(),
        );
    } else if arm {
        v.push(
            Check::new("cpu.model", "CPU")
                .val(format!(
                    "aarch64 implementer {} part {}",
                    ci.get("CPU implementer").cloned().unwrap_or_default(),
                    ci.get("CPU part").cloned().unwrap_or_default()
                ))
                .why("aarch64 is built and tested; flags below use the arm names")
                .ok(),
        );
    } else {
        v.push(
            Check::new("cpu.model", "CPU")
                .val("not available (no /proc/cpuinfo)")
                .why("CPU model, flags and clock checks need /proc/cpuinfo")
                .na(),
        );
    }

    // topology
    let mut cores: BTreeSet<(String, String)> = BTreeSet::new();
    let mut threads = 0usize;
    let mut pkgs: BTreeSet<String> = BTreeSet::new();
    for d in fs.list("sys/devices/system/cpu") {
        if let Some(n) = d.strip_prefix("cpu")
            && !n.is_empty()
            && n.chars().all(|c| c.is_ascii_digit())
        {
            threads += 1;
            let p = fs
                .read(&format!(
                    "sys/devices/system/cpu/{d}/topology/physical_package_id"
                ))
                .unwrap_or_default();
            let c = fs
                .read(&format!("sys/devices/system/cpu/{d}/topology/core_id"))
                .unwrap_or_default();
            pkgs.insert(p.clone());
            cores.insert((p, c));
        }
    }
    let mut nodes: Vec<(u32, Vec<u32>)> = Vec::new();
    for n in fs.list("sys/devices/system/node") {
        if let Some(i) = n.strip_prefix("node").and_then(|s| s.parse::<u32>().ok())
            && let Some(l) = fs.read(&format!("sys/devices/system/node/{n}/cpulist"))
        {
            nodes.push((i, parse_cpulist(&l).unwrap_or_default()));
        }
    }
    nodes.sort();
    if threads == 0 {
        v.push(
            Check::new("cpu.topology", "topology")
                .val("not available (no sysfs cpu tree)")
                .why("cores, NUMA nodes and SMT decide core placement (adr 0063)")
                .na(),
        );
    } else {
        v.push(
            Check::new("cpu.topology", "topology")
                .val(format!(
                    "{} socket(s), {} cores, {} threads, {} NUMA node(s){}",
                    pkgs.len(),
                    cores.len(),
                    threads,
                    nodes.len().max(1),
                    if nodes.is_empty() {
                        String::new()
                    } else {
                        format!(" [{}]", nodes.iter().map(|(i, c)| format!("node{i}: {}", fmt_cpulist(c))).collect::<Vec<_>>().join("; "))
                    }
                ))
                .why("PG-per-core ownership: keep an OSD's cores and its NVMe/NIC on one NUMA node and one L3 domain")
                .ok(),
        );
    }
    facts.cpu_numa = nodes;

    if x86 || arm {
        let (crc, crc_name) = if x86 {
            (has("sse4_2"), "sse4_2 (crc32c)")
        } else {
            (has("crc32"), "crc32")
        };
        v.push(
            Check::new("cpu.crc32c", "CRC32C instruction")
                .val(if crc { crc_name.to_string() } else { "missing".into() })
                .why("msgr2 crc mode and store checksums run at line rate only with hardware crc32c; software fallback costs several x cycles/byte")
                .warn_if(!crc)
                .fix("use a CPU with SSE4.2/ARMv8 CRC; in a VM expose host CPU flags (cpu=host)")
                .w(8),
        );
        if x86 {
            let p = has("pclmulqdq");
            let vp = has("vpclmulqdq");
            v.push(
                Check::new("cpu.pclmul", "PCLMULQDQ / VPCLMULQDQ")
                    .val(format!("pclmulqdq={} vpclmulqdq={}", yn(p), yn(vp)))
                    .why("carry-less multiply folds crc32c over multiple streams (3 crc lanes) for 4 GB/s per stream; VPCLMULQDQ doubles the width")
                    .warn_if(!p)
                    .fix("use a CPU with PCLMULQDQ; in a VM expose host CPU flags (cpu=host)")
                    .w(6),
            );
            v.push(
                Check::new("cpu.avx2", "AVX2")
                    .val(yn(has("avx2")))
                    .why("erasure-code / XOR / memcpy kernels use 256-bit vectors")
                    .warn_if(!has("avx2"))
                    .fix("use a CPU with AVX2 (Haswell/Zen 1 or newer); in a VM expose host CPU flags")
                    .w(5),
            );
            let a512: Vec<&str> = ["avx512f", "avx512bw", "avx512vl", "avx512_vnni"]
                .into_iter()
                .filter(|f| has(f))
                .collect();
            v.push(
                Check::new("cpu.avx512", "AVX-512")
                    .val(if a512.is_empty() {
                        "no (optional)".to_string()
                    } else {
                        a512.join(",")
                    })
                    .why("optional wider EC/crc kernels; never required")
                    .ok(),
            );
            v.push(
                Check::new("cpu.sha", "SHA extensions")
                    .val(format!("sha_ni={}", yn(has("sha_ni"))))
                    .why("optional: hardware SHA for cephx/secure-mode hashing")
                    .ok(),
            );
        }
        // TSC
        if x86 {
            let inv = has("constant_tsc") && has("nonstop_tsc");
            let clk = fs
                .read("sys/devices/system/clocksource/clocksource0/current_clocksource")
                .unwrap_or_default();
            let hv = has("hypervisor");
            let c = Check::new("cpu.tsc", "invariant TSC / clocksource")
                .val(format!("constant_tsc={} nonstop_tsc={} clocksource={}", yn(has("constant_tsc")), yn(has("nonstop_tsc")), if clk.is_empty() { "?" } else { &clk }))
                .why("the hot path reads time per op; with a usable TSC it is ~20 cycles, a hypervisor clock (kvm-clock/hpet/acpi_pm) falls back to a slower read or a syscall")
                .w(4);
            v.push(if !inv || (!clk.is_empty() && clk != "tsc") {
                c.warn().fix(if hv {
                    "VM: expose invariant TSC (KVM: cpu=host, tsc_scale/invtsc) and set clocksource=tsc"
                } else {
                    "BIOS: enable invariant TSC; kernel cmdline `clocksource=tsc tsc=reliable` if the kernel marked it unstable"
                })
            } else {
                c.ok()
            });
        }
    }

    // governor
    match fs.read("sys/devices/system/cpu/cpu0/cpufreq/scaling_governor") {
        Some(g) => v.push(
            Check::new("cpu.governor", "frequency governor")
                .val(g.clone())
                .why("a powersave/ondemand governor lowers the clock while cores spin-poll: latency and per-core throughput drop")
                .warn_if(g != "performance")
                .act(Action::new(vec![Step::Governor { want: "performance".into() }]).note("and BIOS: performance profile / max frequency"))
                .w(7),
        ),
        None => v.push(
            Check::new("cpu.governor", "frequency governor")
                .val("no cpufreq (VM or driver absent)")
                .why("clock policy matters for spin-polling cores; fixed in BIOS when the kernel has no cpufreq")
                .na(),
        ),
    }
    // C-states
    let states: Vec<String> = fs
        .list("sys/devices/system/cpu/cpu0/cpuidle")
        .into_iter()
        .filter(|s| s.starts_with("state"))
        .collect();
    if states.is_empty() {
        v.push(
            Check::new("cpu.cstates", "C-states")
                .val("no cpuidle (VM or disabled)")
                .why("deep C-states add 50-200 us wake latency to an idle core")
                .na(),
        );
    } else {
        let deep: Vec<String> = states
            .iter()
            .filter_map(|s| {
                let base = format!("sys/devices/system/cpu/cpu0/cpuidle/{s}");
                let lat = fs.num(&format!("{base}/latency"))?;
                let dis = fs.num(&format!("{base}/disable")).unwrap_or(0);
                (lat > 50 && dis == 0).then(|| {
                    fs.read(&format!("{base}/name"))
                        .unwrap_or_else(|| s.clone())
                })
            })
            .collect();
        v.push(
            Check::new("cpu.cstates", "C-states")
                .val(if deep.is_empty() { format!("{} state(s), none deeper than 50 us enabled", states.len()) } else { format!("deep states enabled: {}", deep.join(",")) })
                .why("a core that parks (adr 0162) wakes slower from deep C-states: p50 latency and wake jitter")
                .warn_if(!deep.is_empty())
                .fix("kernel cmdline `intel_idle.max_cstate=1 processor.max_cstate=1` (AMD: BIOS C-state control off) or cpupower idle-set -D 50")
                .w(5),
        );
    }
    // SMT
    match fs.read("sys/devices/system/cpu/smt/active") {
        Some(a) => v.push(
            Check::new("cpu.smt", "SMT")
                .val(if a == "1" { "on" } else { "off" })
                .why("thread-per-core: give each OSD core its own physical core; the sibling hyperthread shares its execution units and L1/L2")
                .ok(),
        ),
        None => v.push(Check::new("cpu.smt", "SMT").val("unknown").why("sibling threads share a physical core").na()),
    }
    // isolation
    let iso = fs
        .read("sys/devices/system/cpu/isolated")
        .unwrap_or_default();
    let nohz = fs
        .read("sys/devices/system/cpu/nohz_full")
        .unwrap_or_default();
    let cl = fs.cmdline();
    let rcu = fs.cmdline_arg("rcu_nocbs").unwrap_or_default();
    v.push(
        Check::new("cpu.isolation", "isolcpus / nohz_full")
            .val(format!("isolated=[{iso}] nohz_full=[{nohz}] rcu_nocbs=[{rcu}]{}", if cl.is_empty() { " (cmdline unreadable)" } else { "" }))
            .why("keeps scheduler ticks, RCU callbacks and kernel threads off the polling cores: lower tail latency (kernel tier steering, adr 0053 am. 4)")
            .st(if !fs.has_sys() { crate::Status::Na } else if iso.is_empty() && nohz.is_empty() { crate::Status::Warn } else { crate::Status::Ok })
            .fix("kernel cmdline `isolcpus=<osd cores> nohz_full=<osd cores> rcu_nocbs=<osd cores>` (optional, latency tuning)")
            .w(2),
    );
    // cgroup / cpuset
    let allowed = fs
        .read("proc/self/status")
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix("Cpus_allowed_list:")
                    .map(|v| v.trim().to_string())
            })
        })
        .and_then(|l| parse_cpulist(&l).ok())
        .unwrap_or_default();
    let quota = fs.read("sys/fs/cgroup/cpu.max").unwrap_or_default();
    let throttled = !quota.is_empty() && !quota.starts_with("max");
    let mut c = Check::new("cpu.cgroup", "cgroup CPU limits")
        .val(format!(
            "cpuset={} quota={}",
            if allowed.is_empty() { "?".to_string() } else { fmt_cpulist(&allowed) },
            if quota.is_empty() { "?" } else { &quota }
        ))
        .why("a CPU quota throttles spin-polling cores (deploy.md: no --cpus); the cpuset bounds where OSD cores can run")
        .w(7);
    if throttled {
        c = c.warn().fix("remove the CPU quota (docker --cpus / systemd CPUQuota=) and pin with --cpuset-cpus / CPUAffinity=");
    }
    if quota.is_empty() && allowed.is_empty() {
        c = c.na();
    }
    v.push(c);
    // core budget
    let max_cores = cfg.osds.iter().filter_map(|o| o.core_count()).max();
    v.push(match max_cores {
        Some(n) => Check::new("cpu.budget", "core budget")
            .val(format!("{} OSD(s) configured, max {n} cores/OSD, {threads} threads on host", cfg.osds.len()))
            .why("benchmarks and the supported budget are <= 8 cores per OSD (more cores/OSD does not scale, add OSDs)")
            .warn_if(n > CORE_BUDGET)
            .fix("set flashstore_lcores/flashstore_cores to at most 8 per OSD"),
        None => Check::new("cpu.budget", "core budget")
            .val("no per-OSD core plan in the conf")
            .why("budget is <= 8 cores per OSD; unset = auto (adr 0063)")
            .na(),
    });
    Section {
        name: "CPU",
        checks: v,
    }
}

fn yn(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gens() {
        assert_eq!(
            generation("AuthenticAMD", 25, 0x11, 1),
            "AMD Zen 4 (Genoa/Bergamo)"
        );
        assert_eq!(generation("GenuineIntel", 6, 106, 6), "Intel Ice Lake-SP");
        assert_eq!(generation("GenuineIntel", 6, 1, 1), "");
    }
}
