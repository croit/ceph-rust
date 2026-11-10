// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Op {
    Insert,
    Update,
    Delete,
    Read,
}
impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Self::Insert => "insert",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Read => "read",
        }
    }
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "insert" => Ok(Self::Insert),
            "update" => Ok(Self::Update),
            "delete" => Ok(Self::Delete),
            "read" => Ok(Self::Read),
            _ => Err(format!("unknown operation {s}")),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub pool: String,
    pub namespace: String,
    pub locator: String,
    pub prefix: String,
    pub output: PathBuf,
    pub objects: usize,
    pub key_bytes: usize,
    pub value_bytes: usize,
    pub prefill: u64,
    pub batch: usize,
    pub clients: usize,
    pub qd: usize,
    pub operations: Vec<Op>,
    pub requests: Option<u64>,
    pub seconds: Option<u64>,
    pub max_seconds: u64,
    pub interval: u64,
    pub max_live: u64,
    pub metrics: BTreeSet<String>,
    pub pids: Vec<u32>,
    pub blocks: Vec<PathBuf>,
    pub format: String,
    pub plan: bool,
}
impl Config {
    pub fn parse(
        args: Vec<String>,
        pool: Option<String>,
        namespace: String,
        locator: String,
        out: Option<String>,
    ) -> Result<Self, String> {
        let mut m = BTreeMap::new();
        let mut flags = BTreeSet::new();
        let mut pids = Vec::new();
        let mut blocks = Vec::new();
        let mut it = args.into_iter();
        while let Some(k) = it.next() {
            if matches!(k.as_str(), "--all" | "--plan") {
                if !flags.insert(k.clone()) {
                    return Err(format!("duplicate {k}"));
                }
                continue;
            }
            if !k.starts_with("--") {
                return Err(format!("unexpected argument {k}"));
            }
            let v = it.next().ok_or_else(|| format!("missing value for {k}"))?;
            if v.starts_with("--") {
                return Err(format!("missing value for {k}"));
            }
            if k == "--osd-pid" {
                pids.push(v.parse::<u32>().map_err(|_| "invalid OSD PID")?);
            } else if k == "--block-stat" {
                blocks.push(PathBuf::from(v));
            } else if m.insert(k.clone(), v).is_some() {
                return Err(format!("duplicate {k}"));
            }
        }
        fn number(m: &mut BTreeMap<String, String>, k: &str, d: u64) -> Result<u64, String> {
            m.remove(k)
                .map_or(Ok(d), |v| v.parse().map_err(|_| format!("invalid {k}")))
        }
        fn size(m: &mut BTreeMap<String, String>, k: &str, d: u64) -> Result<usize, String> {
            usize::try_from(number(m, k, d)?).map_err(|_| format!("overflow {k}"))
        }
        let requests = m
            .remove("--ops-per-client")
            .map(|v| v.parse::<u64>().map_err(|_| "invalid --ops-per-client"))
            .transpose()?;
        let seconds = m
            .remove("--seconds")
            .map(|v| v.parse::<u64>().map_err(|_| "invalid --seconds"))
            .transpose()?;
        if requests.is_some() && seconds.is_some() {
            return Err("choose --ops-per-client OR --seconds".into());
        }
        let metrics = if flags.contains("--all") {
            if m.contains_key("--metrics") {
                return Err("choose --metrics OR --all".into());
            }
            "throughput,latency,client-cpu,osd-cpu,rss,writes".into()
        } else {
            m.remove("--metrics").unwrap_or_else(|| "throughput".into())
        };
        let metrics: BTreeSet<String> = metrics
            .split(',')
            .map(str::trim)
            .map(str::to_owned)
            .collect();
        if metrics.is_empty()
            || metrics.iter().any(|s| {
                !matches!(
                    s.as_str(),
                    "throughput" | "latency" | "client-cpu" | "osd-cpu" | "rss" | "writes"
                )
            })
        {
            return Err("invalid --metrics".into());
        }
        let operations = m
            .remove("--operations")
            .unwrap_or_else(|| "insert,delete".into())
            .split(',')
            .map(str::trim)
            .map(Op::parse)
            .collect::<Result<Vec<_>, _>>()?;
        if out.is_some() && m.contains_key("--output-dir") {
            return Err("choose --output-dir OR --out, not both".into());
        }
        let output = m
            .remove("--output-dir")
            .or(out)
            .map(PathBuf::from)
            .ok_or("--output-dir (fresh directory) required")?;
        let c = Self {
            pool: pool.ok_or("-p POOL required")?,
            namespace,
            locator,
            prefix: m.remove("--prefix").ok_or("--prefix required")?,
            output,
            objects: size(&mut m, "--objects", 1)?,
            key_bytes: size(&mut m, "--key-bytes", 48)?,
            value_bytes: size(&mut m, "--value-bytes", 300)?,
            prefill: number(&mut m, "--prefill", 250000)?,
            batch: size(&mut m, "--batch", 256)?,
            clients: size(&mut m, "--clients", 8)?,
            qd: size(&mut m, "--qd", 1)?,
            operations,
            requests,
            seconds: if requests.is_none() {
                Some(seconds.unwrap_or(60))
            } else {
                None
            },
            max_seconds: number(&mut m, "--max-seconds", 3600)?,
            interval: number(&mut m, "--interval", 60)?,
            max_live: number(&mut m, "--max-live-keys", 10000000)?,
            metrics,
            pids,
            blocks,
            format: m.remove("--format").unwrap_or_else(|| "json".into()),
            plan: flags.contains("--plan"),
        };
        if !m.is_empty() {
            return Err(format!("unknown options {:?}", m.keys()));
        }
        c.validate()?;
        Ok(c)
    }
    fn validate(&self) -> Result<(), String> {
        if self.prefix.is_empty()
            || self.prefix.len() > 160
            || self.pool.is_empty()
            || self.output.as_os_str().is_empty()
            || self.objects == 0
            || self.objects > 10000
            || self.clients == 0
            || self.clients > 1024
            || self.qd == 0
            || self.qd > 65536
            || self.batch == 0
            || self.batch > 65536
            || self.key_bytes == 0
            || self.key_bytes > 4096
            || self.value_bytes > 16 * 1024 * 1024
            || self.interval == 0
            || self.max_seconds == 0
            || self.requests == Some(0)
            || self.seconds == Some(0)
            || self.seconds.is_some_and(|s| s > self.max_seconds)
            || !matches!(self.format.as_str(), "plain" | "json" | "json-pretty")
            || self.pids.contains(&0)
        {
            return Err("invalid size, limit, prefix, format or duration bounds".into());
        }
        let initial = self
            .prefill
            .checked_mul(self.objects as u64)
            .ok_or("prefill overflow")?;
        if initial > self.max_live {
            return Err("prefill exceeds --max-live-keys".into());
        }
        if self.max_live > 32000000 {
            return Err("--max-live-keys must be <= 32000000 (bounded key oracle memory)".into());
        }
        if std::time::Instant::now()
            .checked_add(std::time::Duration::from_secs(self.max_seconds))
            .is_none()
            || std::time::Instant::now()
                .checked_add(std::time::Duration::from_secs(self.interval))
                .is_none()
        {
            return Err("--max-seconds exceeds monotonic clock range".into());
        }
        let windows = self
            .seconds
            .unwrap_or(self.max_seconds)
            .div_ceil(self.interval);
        let cohort_windows = windows
            .checked_mul(self.clients as u64)
            .ok_or("window count overflow")?;
        if cohort_windows > 1000000 {
            return Err("too many metric windows; increase --interval".into());
        }
        if self.latency()
            && cohort_windows
                .checked_add(2 * self.clients as u64)
                .and_then(|n| n.checked_mul(4 * 2304 * 8))
                .is_none_or(|n| n > 256 * 1024 * 1024)
        {
            return Err("latency histograms exceed 256 MiB budget; increase --interval or select throughput only".into());
        }
        let pending = self
            .clients
            .checked_mul(self.qd)
            .and_then(|n| n.checked_mul(self.batch))
            .and_then(|n| n.checked_mul(self.key_bytes + self.value_bytes + 64))
            .ok_or("pending buffer overflow")?;
        if pending > 1024 * 1024 * 1024 {
            return Err(
                "configured pending payload budget exceeds 1 GiB; reduce clients/QD/batch/sizes"
                    .into(),
            );
        }
        if self.requests.is_some_and(|n| {
            n.checked_mul(self.clients as u64)
                .and_then(|n| n.checked_mul(self.batch as u64))
                .and_then(|n| n.checked_mul((self.key_bytes + self.value_bytes) as u64))
                .is_none()
        }) {
            return Err("request/key/byte count overflow".into());
        }
        if self.pids.iter().collect::<BTreeSet<_>>().len() != self.pids.len()
            || self.blocks.iter().collect::<BTreeSet<_>>().len() != self.blocks.len()
        {
            return Err("duplicate resource target".into());
        }
        for client in 0..self.clients {
            let owned = self.owned(client);
            for (object_index, &object) in owned.iter().enumerate() {
                let (a, b, rank, owners) = self.partition(client, object);
                if self.operations.iter().any(|o| *o != Op::Insert)
                    && b - a < (self.qd * self.batch) as u64
                {
                    return Err(format!(
                        "object {object} client {client}: prefill partition must contain at least QD*batch keys for existing-key operations"
                    ));
                }
                let inserts = self.operations.iter().filter(|o| **o == Op::Insert).count() as u64;
                let future = if let Some(n) = self.requests {
                    let cycles = n / self.operations.len() as u64;
                    let tail = (n % self.operations.len() as u64) as usize;
                    let object_cycles = cycles / owned.len() as u64
                        + u64::from((object_index as u64) < cycles % owned.len() as u64);
                    let tail_inserts = if object_index as u64 == cycles % owned.len() as u64 {
                        self.operations[..tail]
                            .iter()
                            .filter(|o| **o == Op::Insert)
                            .count() as u64
                    } else {
                        0
                    };
                    object_cycles
                        .checked_mul(inserts)
                        .and_then(|n| n.checked_add(tail_inserts))
                        .and_then(|n| n.checked_mul(self.batch as u64))
                        .ok_or("key namespace overflow")?
                } else {
                    0
                };
                let highest = if future == 0 {
                    self.prefill.saturating_sub(1)
                } else {
                    self.prefill
                        .checked_add(rank)
                        .and_then(|n| n.checked_add((future - 1).checked_mul(owners)?))
                        .ok_or("key namespace overflow")?
                };
                if !self.key_fits(self.prefill.saturating_sub(1)) || !self.key_fits(highest) {
                    return Err("key byte length cannot encode prefill/request namespace; increase --key-bytes".into());
                }
            }
        }
        Ok(())
    }
    pub fn key_fits(&self, id: u64) -> bool {
        self.key_bytes >= 8 || id < (1u64 << (self.key_bytes * 8))
    }
    pub fn owned(&self, client: usize) -> Vec<usize> {
        if self.clients <= self.objects {
            (0..self.objects)
                .filter(|o| o % self.clients == client)
                .collect()
        } else {
            vec![client % self.objects]
        }
    }
    /// Initial half-open interval and rank/width of the owner's new-key stride.
    pub fn partition(&self, client: usize, object: usize) -> (u64, u64, u64, u64) {
        let (r, n) = if self.clients <= self.objects {
            (0, 1)
        } else {
            (
                (client / self.objects) as u64,
                ((self.clients - 1 - object) / self.objects + 1) as u64,
            )
        };
        (
            ((self.prefill as u128 * r as u128) / n as u128) as u64,
            ((self.prefill as u128 * (r + 1) as u128) / n as u128) as u64,
            r,
            n,
        )
    }
    pub fn live_limit(&self, client: usize) -> u64 {
        let initial = self.prefill * self.objects as u64;
        let spare = self.max_live - initial;
        self.owned(client)
            .iter()
            .map(|&o| {
                let (a, b, _, _) = self.partition(client, o);
                b - a
            })
            .sum::<u64>()
            + spare / self.clients as u64
            + u64::from((client as u64) < spare % self.clients as u64)
    }
    pub fn latency(&self) -> bool {
        self.metrics.contains("latency")
    }
    pub fn resources(&self) -> bool {
        self.metrics
            .iter()
            .any(|s| !matches!(s.as_str(), "throughput" | "latency"))
    }
    pub fn document(&self) -> Value {
        json!({"schema":1,"pool":self.pool,"namespace":self.namespace,"locator":self.locator,"prefix":self.prefix,"output_dir":self.output,
        "objects":self.objects,"key_bytes":self.key_bytes,"value_bytes":self.value_bytes,"prefill_keys_per_object":self.prefill,"batch":self.batch,"clients":self.clients,"qd_per_client":self.qd,
        "operations":self.operations.iter().map(|o|o.name()).collect::<Vec<_>>(),"ops_per_client":self.requests,"seconds":self.seconds,"max_seconds":self.max_seconds,"interval":self.interval,"max_live_keys":self.max_live,
        "metrics":self.metrics,"osd_pids":self.pids,"block_stats":self.blocks,"ownership":(0..self.clients).map(|c|json!({"client":c,"live_key_limit":self.live_limit(c),"objects":self.owned(c).iter().map(|&o|{let(a,b,r,n)=self.partition(c,o);json!({"object":o,"prefill_begin":a,"prefill_end":b,"rank":r,"owners":n})}).collect::<Vec<_>>()})).collect::<Vec<_>>()})
    }
}
