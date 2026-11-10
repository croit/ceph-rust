// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Host facts for the boot metadata (`collect_sys_info`, spec 3.3). Reads /proc and os-release;
//! missing files just yield missing keys.
use std::collections::BTreeMap;

fn read(p: &str) -> Option<String> {
    std::fs::read_to_string(p).ok()
}

fn os_release() -> BTreeMap<String, String> {
    let t = read("/etc/os-release").unwrap_or_default();
    t.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.trim_matches('"').to_owned()))
        .collect()
}

/// Messenger nonce of this process instance. pid alone repeats across restarts (pid 1 in containers) and the mon
/// ignores MOSDFull from a "down" osd whose address+nonce equal its last one, so a restarted daemon could never clear
/// stale full flags in preboot. Mixes the pid with the clock; never 0.
pub fn fresh_nonce() -> u32 {
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(1, |d| d.as_nanos() as u64);
    let x = (ns ^ (ns >> 29)).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ u64::from(std::process::id());
    ((x >> 32) as u32 ^ x as u32).max(1)
}

/// Short hostname (up to the first dot).
pub fn short_hostname() -> String {
    let h = std::env::var("NODE_NAME")
        .ok()
        .or_else(|| read("/proc/sys/kernel/hostname").map(|s| s.trim().to_owned()))
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "localhost".into());
    h.split('.').next().unwrap_or("localhost").to_owned()
}

/// uname/meminfo/cpu/distro keys.
pub fn collect() -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("os".into(), "Linux".into());
    m.insert("arch".into(), std::env::consts::ARCH.to_owned());
    if let Some(v) = read("/proc/sys/kernel/osrelease") {
        m.insert("kernel_version".into(), v.trim().to_owned());
    }
    if let Some(v) = read("/proc/sys/kernel/version") {
        m.insert("kernel_description".into(), v.trim().to_owned());
    }
    if let Some(t) = read("/proc/meminfo") {
        for l in t.lines() {
            let kv = l
                .split_once(':')
                .map(|(k, v)| (k, v.trim().trim_end_matches(" kB")));
            match kv {
                Some(("MemTotal", v)) => {
                    m.insert("mem_total_kb".into(), v.to_owned());
                }
                Some(("SwapTotal", v)) => {
                    m.insert("mem_swap_kb".into(), v.to_owned());
                }
                _ => {}
            }
        }
    }
    if let Some(t) = read("/proc/cpuinfo")
        && let Some(l) = t.lines().find(|l| l.starts_with("model name"))
        && let Some((_, v)) = l.split_once(':')
    {
        m.insert("cpu".into(), v.trim().to_owned());
    }
    let o = os_release();
    if let Some(v) = o.get("ID") {
        m.insert("distro".into(), v.clone());
    }
    if let Some(v) = o.get("VERSION_ID") {
        m.insert("distro_version".into(), v.clone());
    }
    if let Some(v) = o.get("PRETTY_NAME") {
        m.insert("distro_description".into(), v.clone());
    }
    m
}

#[cfg(test)]
mod nonce_tests {
    #[test]
    fn nonce_differs_between_calls_and_is_nonzero() {
        let a = super::fresh_nonce();
        std::thread::sleep(std::time::Duration::from_micros(50));
        let b = super::fresh_nonce();
        assert!(a != 0 && b != 0 && a != b);
    }
}
