// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Opt-in latency and read-only local resource observation. No daemon discovery.
use super::config::{Config, Op};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct Histogram {
    pub bins: Vec<u64>,
    pub n: u64,
    pub max: u64,
}
impl Histogram {
    pub fn new() -> Self {
        Self {
            bins: vec![0; 2304],
            n: 0,
            max: 0,
        }
    }
    pub fn record(&mut self, us: u64) {
        let i = if us < 64 {
            us as usize
        } else {
            let sh = (63 - us.leading_zeros() as usize) - 6;
            (sh * 64 + (us >> sh) as usize).min(2303)
        };
        self.bins[i] += 1;
        self.n += 1;
        self.max = self.max.max(us);
    }
    pub fn merge(&mut self, h: &Self) {
        for (a, b) in self.bins.iter_mut().zip(&h.bins) {
            *a += b;
        }
        self.n += h.n;
        self.max = self.max.max(h.max);
    }
    fn pct(&self, q: f64) -> Option<u64> {
        if self.n == 0 {
            return None;
        }
        let want = (self.n as f64 * q).ceil() as u64;
        let mut seen = 0;
        for (i, b) in self.bins.iter().enumerate() {
            seen += b;
            if seen >= want {
                let high = if i < 64 {
                    i as u64
                } else {
                    let sh = (i >> 6) - 1;
                    (((i - sh * 64 + 1) as u64) << sh) - 1
                };
                return Some(high.min(self.max));
            }
        }
        None
    }
    pub fn doc(&self) -> Value {
        json!({"unit":"us","count":self.n,"p50":self.pct(0.50),"p95":self.pct(0.95),"p99":self.pct(0.99),"max":if self.n==0{None}else{Some(self.max)},"bins":self.bins,"bucket_error_max_percent":1.6})
    }
}
pub struct Stats {
    pub requests: u64,
    pub keys: u64,
    pub key_bytes: u64,
    pub value_write_bytes: u64,
    pub value_read_bytes: u64,
    pub hist: Option<Histogram>,
}
impl Stats {
    pub fn new(latency: bool) -> Self {
        Self {
            requests: 0,
            keys: 0,
            key_bytes: 0,
            value_write_bytes: 0,
            value_read_bytes: 0,
            hist: latency.then(Histogram::new),
        }
    }
    pub fn record(&mut self, c: &Config, op: Op, us: u64) {
        self.requests += 1;
        self.keys += c.batch as u64;
        self.key_bytes += (c.batch * c.key_bytes) as u64;
        if matches!(op, Op::Insert | Op::Update) {
            self.value_write_bytes += (c.batch * c.value_bytes) as u64;
        }
        if op == Op::Read {
            self.value_read_bytes += (c.batch * c.value_bytes) as u64;
        }
        if let Some(h) = &mut self.hist {
            h.record(us);
        }
    }
    pub fn merge(&mut self, s: &Self) {
        self.requests += s.requests;
        self.keys += s.keys;
        self.key_bytes += s.key_bytes;
        self.value_write_bytes += s.value_write_bytes;
        self.value_read_bytes += s.value_read_bytes;
        if let (Some(a), Some(b)) = (&mut self.hist, &s.hist) {
            a.merge(b);
        }
    }
    pub fn doc(&self, seconds: f64, throughput: bool) -> Value {
        let mut v = json!({"requests":self.requests,"keys":self.keys,"logical_key_bytes":self.key_bytes,"logical_value_bytes_written":self.value_write_bytes,"logical_value_bytes_read":self.value_read_bytes});
        if throughput {
            v["requests_per_second"] = json!(self.requests as f64 / seconds);
            v["keys_per_second"] = json!(self.keys as f64 / seconds);
            v["logical_key_bytes_per_second"] = json!(self.key_bytes as f64 / seconds);
            v["logical_value_write_bytes_per_second"] =
                json!(self.value_write_bytes as f64 / seconds);
            v["logical_value_read_bytes_per_second"] =
                json!(self.value_read_bytes as f64 / seconds);
        }
        if let Some(h) = &self.hist {
            v["latency"] = h.doc();
        }
        v
    }
}

#[derive(Clone)]
struct Process {
    ticks: u64,
    stamp: u64,
    rss_kib: u64,
}
fn process(line: &str, status: Option<&str>) -> Result<Process, String> {
    let f: Vec<_> = line
        .rsplit_once(')')
        .ok_or("bad process stat")?
        .1
        .split_whitespace()
        .collect();
    let number = |i: usize| {
        f.get(i)
            .ok_or("short process stat")?
            .parse::<u64>()
            .map_err(|_| "invalid process stat")
    };
    let rss = if let Some(status) = status {
        status
            .lines()
            .find_map(|s| s.strip_prefix("VmRSS:"))
            .and_then(|s| s.split_whitespace().next())
            .ok_or("no process RSS")?
            .parse()
            .map_err(|_| "invalid RSS")?
    } else {
        0
    };
    Ok(Process {
        ticks: number(11)?
            .checked_add(number(12)?)
            .ok_or("CPU ticks overflow")?,
        stamp: number(19)?,
        rss_kib: rss,
    })
}
fn read_process(pid: u32, rss: bool) -> Result<Process, String> {
    let status = if rss {
        Some(std::fs::read_to_string(format!("/proc/{pid}/status")).map_err(|e| e.to_string())?)
    } else {
        None
    };
    process(
        &std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|e| e.to_string())?,
        status.as_deref(),
    )
}
fn clock_ticks() -> Result<u64, String> {
    use std::process::{Command, Stdio};
    let mut child = Command::new("getconf")
        .arg("CLK_TCK")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let end = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            if !status.success() {
                return Err("getconf failed".into());
            }
            let out = child.wait_with_output().map_err(|e| e.to_string())?;
            return String::from_utf8_lossy(&out.stdout)
                .trim()
                .parse::<u64>()
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| "invalid CLK_TCK".into());
        }
        if Instant::now() >= end {
            let _ = child.kill();
            let _ = child.wait();
            return Err("WARNING TIMEOUT clock-tick discovery exceeded 2s".into());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
#[derive(Clone)]
struct Snapshot {
    at: Instant,
    processes: BTreeMap<u32, Process>,
    writes: BTreeMap<String, u64>,
}
fn bounded_text(path: &Path, limit: u64) -> Result<String, String> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(limit + 1);
    let mut data = String::new();
    file.read_to_string(&mut data).map_err(|e| e.to_string())?;
    if data.len() as u64 > limit {
        return Err("resource stat exceeds bounded read size".into());
    }
    Ok(data)
}
/// Accept only the kernel stat attribute of a registered Linux block device.
/// In particular, never open arbitrary FIFOs/devices/large user files.
pub(super) fn block_target(path: &Path) -> Result<PathBuf, String> {
    let path = path.canonicalize().map_err(|e| e.to_string())?;
    if !path.starts_with("/sys/devices")
        || path.file_name().is_none_or(|n| n != "stat")
        || !std::fs::metadata(&path)
            .map_err(|e| e.to_string())?
            .is_file()
    {
        return Err(
            "--block-stat requires a genuine Linux /sys/.../block-device/stat attribute".into(),
        );
    }
    let parent = path.parent().ok_or("missing block device parent")?;
    let dev = bounded_text(&parent.join("dev"), 128)?;
    let dev = dev.trim();
    if dev.split_once(':').is_none_or(|(a, b)| {
        a.is_empty()
            || b.is_empty()
            || !a.bytes().all(|n| n.is_ascii_digit())
            || !b.bytes().all(|n| n.is_ascii_digit())
    }) || Path::new("/sys/dev/block")
        .join(dev)
        .canonicalize()
        .map_err(|e| e.to_string())?
        != parent
    {
        return Err("block stat parent is not the registered device identity".into());
    }
    Ok(path)
}
pub struct Sampler {
    before: Snapshot,
    last: Snapshot,
    hz: Option<u64>,
    pids: Vec<u32>,
    blocks: Vec<String>,
    pub samples: Vec<Value>,
    pub unavailable: Vec<String>,
    rss_peak: BTreeMap<u32, u64>,
    rss: bool,
}
impl Sampler {
    fn snapshot(pids: &[u32], blocks: &[String], rss: bool) -> Result<Snapshot, String> {
        let processes = pids
            .iter()
            .map(|&p| {
                Ok((
                    p,
                    read_process(p, rss)
                        .map_err(|e| format!("process {p} snapshot failed: {e}"))?,
                ))
            })
            .collect::<Result<_, String>>()?;
        let mut writes = BTreeMap::new();
        for path in blocks {
            let verified = block_target(Path::new(path))?;
            if verified != Path::new(path) {
                return Err("block stat identity changed".into());
            }
            let raw = bounded_text(&verified, 4096)?;
            let sectors = raw
                .split_whitespace()
                .nth(6)
                .ok_or("short block stat")?
                .parse::<u64>()
                .map_err(|_| "invalid block stat")?;
            writes.insert(path.clone(), sectors);
        }
        Ok(Snapshot {
            at: Instant::now(),
            processes,
            writes,
        })
    }
    pub fn new(c: &Config) -> Result<Option<Self>, String> {
        if !c.resources() {
            return Ok(None);
        }
        let mut unavailable = Vec::new();
        if c.metrics.contains("osd-cpu") && c.pids.is_empty() {
            unavailable.push("osd-cpu: no --osd-pid targets".into());
        }
        if c.metrics.contains("writes") && c.blocks.is_empty() {
            unavailable.push("writes: no --block-stat targets".into());
        }
        if c.metrics.contains("rss") && c.pids.is_empty() {
            unavailable.push("osd-rss: no --osd-pid targets (client RSS is available)".into());
        }
        let rss = c.metrics.contains("rss");
        if !cfg!(target_os = "linux") {
            unavailable.push("local CPU/RSS/block metrics require Linux".into());
            return Ok(Some(Self {
                before: Self::snapshot(&[], &[], false)?,
                last: Self::snapshot(&[], &[], false)?,
                hz: None,
                pids: Vec::new(),
                blocks: Vec::new(),
                samples: Vec::new(),
                unavailable,
                rss_peak: BTreeMap::new(),
                rss: false,
            }));
        }
        if c.pids.contains(&std::process::id()) {
            return Err("--osd-pid names the benchmark client itself".into());
        }
        let cpu = c.metrics.contains("client-cpu")
            || (c.metrics.contains("osd-cpu") && !c.pids.is_empty());
        let hz = if cpu { Some(clock_ticks()?) } else { None };
        let mut pids = if c.metrics.contains("osd-cpu") || c.metrics.contains("rss") {
            c.pids.clone()
        } else {
            Vec::new()
        };
        if c.metrics.contains("client-cpu") || c.metrics.contains("rss") {
            pids.push(std::process::id());
        }
        pids.sort_unstable();
        pids.dedup();
        let blocks: Vec<String> = if c.metrics.contains("writes") {
            c.blocks
                .iter()
                .map(|p| {
                    block_target(p)
                        .map(|p| p.to_string_lossy().into_owned())
                        .map_err(|e| e.to_string())
                })
                .collect::<Result<_, _>>()?
        } else {
            Vec::new()
        };
        if blocks
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != blocks.len()
        {
            return Err("duplicate canonical block-stat targets".into());
        }
        let before = Self::snapshot(&pids, &blocks, rss)?;
        let last = before.clone();
        let rss_peak = if rss {
            before
                .processes
                .iter()
                .map(|(p, v)| (*p, v.rss_kib))
                .collect()
        } else {
            BTreeMap::new()
        };
        Ok(Some(Self {
            before,
            last,
            hz,
            pids,
            blocks,
            samples: Vec::new(),
            unavailable,
            rss_peak,
            rss,
        }))
    }
    pub fn sample(&mut self) -> Result<(), String> {
        let s = Self::snapshot(&self.pids, &self.blocks, self.rss)?;
        for (p, v) in &s.processes {
            let old = &self.last.processes[p];
            if old.stamp != v.stamp || v.ticks < old.ticks {
                return Err(format!("process {p} identity changed or CPU regressed"));
            }
            if self.rss {
                self.rss_peak
                    .entry(*p)
                    .and_modify(|n| *n = (*n).max(v.rss_kib))
                    .or_insert(v.rss_kib);
            }
        }
        for (p, v) in &s.writes {
            if v < &self.last.writes[p] {
                return Err("block write counter regressed".into());
            }
            (v - self.before.writes[p])
                .checked_mul(512)
                .ok_or("block byte counter overflow")?;
        }
        self.samples.push(json!({"elapsed_since_resource_baseline_seconds":s.at.duration_since(self.before.at).as_secs_f64(),"processes":s.processes.iter().map(|(p,v)|json!({"pid":p,"start_ticks":v.stamp,"cpu_ticks":if self.hz.is_some(){Some(v.ticks)}else{None},"rss_kib":if self.rss{Some(v.rss_kib)}else{None}})).collect::<Vec<_>>(),"block_sectors_written":s.writes}));
        self.last = s;
        Ok(())
    }
    pub fn doc(&self, c: &Config, start: Instant, foreground_seconds: f64) -> Value {
        let seconds = self.last.at.duration_since(self.before.at).as_secs_f64();
        json!({"scope":if c.seconds.is_some(){"baseline immediately before start to foreground deadline; duration drain and final verification excluded"}else{"baseline immediately before start to final requested completion; setup and verification excluded"},
            "sample_seconds":seconds,"foreground_start_after_baseline_seconds":start.saturating_duration_since(self.before.at).as_secs_f64(),"foreground_seconds":foreground_seconds,"sample_end_after_foreground_seconds":seconds-start.saturating_duration_since(self.before.at).as_secs_f64()-foreground_seconds,
            "unavailable":self.unavailable,"clock_ticks":self.hz,"cpu_one_core_100":true,
            "processes":self.last.processes.iter().map(|(p,v)|{let a=&self.before.processes[p];let cpu_selected=if *p==std::process::id(){c.metrics.contains("client-cpu")}else{c.metrics.contains("osd-cpu")};json!({"pid":p,"role":if *p==std::process::id(){"client"}else{"osd"},"start_ticks":v.stamp,"cpu_ticks_start":if cpu_selected{Some(a.ticks)}else{None},"cpu_ticks_end":if cpu_selected{Some(v.ticks)}else{None},"cpu_percent":if cpu_selected{self.hz.map(|hz|100.0*(v.ticks-a.ticks) as f64/hz as f64/seconds)}else{None},"sampled_peak_rss_kib":if c.metrics.contains("rss"){self.rss_peak.get(p).copied()}else{None}})}).collect::<Vec<_>>(),
            "devices":self.last.writes.iter().map(|(p,v)|json!({"stat":p,"sectors_start":self.before.writes[p],"sectors_end":v,"bytes_written":(v-self.before.writes[p])*512,"MiB_per_second":(v-self.before.writes[p]) as f64/2048.0/seconds,"unit":"Linux512Bsectors,notNAND"})).collect::<Vec<_>>()})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn process_stat_fields_and_rss_are_optional() {
        let mut fields = vec!["0"; 22];
        fields[11] = "20";
        fields[12] = "30";
        fields[19] = "42";
        let line = format!("123 (name with ) parens) {}", fields.join(" "));
        let p = process(&line, Some("Name:\tunit\nVmRSS:\t1234 kB\n")).unwrap();
        assert_eq!((p.ticks, p.stamp, p.rss_kib), (50, 42, 1234));
        assert_eq!(process(&line, None).unwrap().rss_kib, 0);
        assert!(process("invalid", None).is_err());
    }
    #[test]
    fn latency_histogram_bounds_include_zero_and_large_tail() {
        for us in [0, 1, 63, 64, 65, 127, 128, 999, 100000, 1000000000] {
            let mut h = Histogram::new();
            h.record(us);
            let p = h.pct(0.99).unwrap();
            assert!(p >= us);
            assert!(p as f64 <= us as f64 * 1.016 + 1.0);
        }
    }
}
