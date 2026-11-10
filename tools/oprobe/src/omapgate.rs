// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! OMAP gate cells: insert / prefill / delete / update / mixed mutation / full scan / object
//! deletion with multi-client, multi-object ownership, against any RADOS cluster (classic
//! BlueStore or croit-flashstore-osd).
//!
//! Model
//! * One *client* = one thread = one RADOS session ([`Probe`]); `--qd` ops outstanding per client.
//! * Keys are 64-byte lowercase hex of a `u64` id `(rank << 40) | local`: every key *owner* (rank)
//!   of an object owns one contiguous key block, so ownership is disjoint by construction and a
//!   contiguous run of an owner's sorted live keys is a contiguous key range containing only its
//!   own keys. Values are `omapbench::value(key, generation, value_bytes)`: deterministic, and
//!   reads check the exact generation the client last wrote.
//! * Layouts: `shared` = every client works on every object (rank = global client index);
//!   `owned` = object `g*K + j` belongs to global client `g` alone (rank 0).
//! * `--object-inflight M` bounds the outstanding ops per (object, op type); the scheduler walks
//!   (object, type) slots round-robin. M=1 with QD = objects x types gives the "one outstanding op
//!   of each type per object" cells.
//! * Update / delete / read / range delete only touch keys of the client's own live set
//!   (kept in memory, sorted). Keys of in-flight ops are reserved: no op ever races its own keys.
//! * Key placement: `local = i * ID_STRIDE` (2^16) for the i-th key of a fresh `insert` /
//!   `prefill` (at most 2^24 keys per owner, so the grid fits the owner's 2^40 block). Later
//!   inserts (`insert --manifest`, inserts inside `mix-*`) draw uniformly random *unused* local
//!   ids in `[0, highest id ever used + 1)`, i.e. between existing keys. An id is unused when it
//!   is not live, not in flight, not inside an in-flight range delete and never existed in this
//!   object (deleted ids are remembered as `dead`), so a deleted key is never simply re-inserted.
//! * `delete --delete-fraction F`: each owner deletes `round(live * F)` of its live keys, chosen
//!   uniformly at random, `--keys-per-op` scattered keys per op, each key once. `update`:
//!   every live key is overwritten exactly once, random order, with the owner's next generation
//!   (max live generation + 1). `insert --manifest M --insert-keys N`: N new keys per object,
//!   split over the owners (shared) or all by the owner (owned).
//! * Latency = submission to completion of one RPC (build and validation excluded). Connections
//!   are warmed before the timed phase.
//! * Manifest (`--manifest-out`, read back with `--manifest`; schema 2, older ones are refused):
//!   per object the live count and per owner rank `live_n`, `live` and `dead`: sorted local ids
//!   delta-coded as LEB128 varints in hex (`live`: delta then generation per key; `dead`: delta
//!   only), plus `id_stride`. `insert` (with manifest), `delete`, `update` and `mix-*` need it;
//!   `scan` (live counts only), `delete-objects` pass it on. A manifest covers the ranks of the
//!   clients of one process; multi-process runs of one shared object use `--expect-keys`.
//! * Exact time per op kind: every `op` record has `lat_sum_ns` (integer sum of submission ->
//!   completion latencies in ns, the same measurement as the histogram), `ops`, `lat_mean_ns`
//!   (`lat_sum_ns / ops`). `client_op` records (one per client and kind) carry the same fields
//!   plus `client`, `keys`, `errors`, `wall_s`. The summary has `wall_ns` (timed wall of the
//!   slowest client = cell wall time) and `kinds` ({kind: {ops, keys, lat_sum_ns, lat_mean_ns}}).

use crate::client::{Done, Opts, Probe};
use crate::omapbench::{Hist, splitmix, target, value, value_ok};
use crate::omapload::entries;
use crate::script::ScriptMsg;
use denc::Encode;
use opwire::{KvMap, OsdOp};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Barrier, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const HELP: &str = "omapgate TEST -p POOL [options]   OMAP gate cells (docs: oprobe::omapgate)\n\
TEST: insert | prefill | delete | update | mix-delete | mix-range | scan | delete-objects\n\
  insert        N keys per object into fresh objects (shared layout: split over the clients);\n\
                with --manifest: --insert-keys N new keys per object at random free ids between existing keys\n\
  delete        delete --delete-fraction F of every owner's live keys (random, --keys-per-op scattered keys per op)\n\
  update        overwrite every live key once, random order, new generation\n\
  prefill       like insert, but one process fills the blocks of all --total-clients key owners\n\
  mix-delete    insert/update/delete/point_read on a prefilled manifest (--ops-per-client N | --ops-per-object N | --duration S)\n\
  mix-range     insert/update/delete_range/point_read, delete_range removes keys-per-op live keys\n\
  scan          timed paged full scan of the manifest objects; checks counts and values\n\
  delete-objects  delete (--per-client N of) the manifest objects, then verify stat = ENOENT\n\
options (global --conf --keyring --entity --mode crc|secure|auto --timeout S as for every oprobe command):\n\
  --prefix NAME             fresh object-name prefix (insert/prefill; names NAME-oNNNNN)\n\
  --layout shared|owned     default shared\n\
  --objects N               shared layout: objects (default 1)\n\
  --objects-per-client K    owned layout: objects per client (default 1)\n\
  --clients C               sessions in this process (default 1)\n\
  --client-base B           global index of this process's first client (default 0)\n\
  --total-clients T         key owners per shared object = clients over all processes (default B+C)\n\
  --qd Q                    outstanding ops per client (default 1)\n\
  --object-inflight M       max outstanding ops per (object, op type) (default: unlimited)\n\
  --keys N                  insert/prefill: keys per object (default 1048576)\n\
  --keys-per-op N           keys per op (default 256)\n\
  --insert-keys N           insert with --manifest: new keys per object (split over the owners)\n\
  --delete-fraction F       delete: fraction (0,1] of each owner's live keys\n\
  --passes N                scan: full passes over the objects (default 1)\n\
  --value-bytes N           value size >= 8 (default 256)\n\
  --ops-per-client N        mix: ops per client, split over the op types and the client's objects\n\
  --ops-per-object N        mix: ops per object and client, split over the op types\n\
  --duration S              mix: wall seconds instead of an op count (exactly one of the three)\n\
  --manifest FILE           input manifest (insert-keys, delete, update, mix, scan, delete-objects)\n\
  --manifest-out FILE       output manifest (default PREFIX.TEST.manifest.json in the cwd)\n\
  --expect-keys N           scan without manifest: keys per object (needs --prefix, --objects)\n\
  --scan-page N             scan page size (default 1024)\n\
  --per-client N            delete-objects: objects deleted per client (default all)\n\
  --seed N  --idle-us N  --start-at UNIX_SECONDS  --max-seconds N\n\
  --format plain|json|json-pretty|jsonl   records: one per op type + one summary\n\
Record fields (op): record,test,kind,ops,keys,bytes,errors,wall_s,ops_per_s,keys_per_s,\n\
  lat_sum_ns,lat_mean_ns,lat_us{p50,p90,p99,p99.9,max,avg},hist_us[[upper_edge_us,count]...]. client_op\n\
  records (per client and kind): client,kind,ops,keys,errors,wall_s,lat_sum_ns,lat_mean_ns. kinds: insert update delete\n\
  delete_range point_read scan delete_object verify_absent. Phase records: phase (prefill|insert|\n\
  ops|scan|delete|verify),start_unix_ns,end_unix_ns,duration_s (UTC). Summary: record,test,ok,\n\
  tool,version,command,params,pool,layout,clients,qd,objects,wall_s,wall_ns,kinds{kind:{ops,keys,lat_sum_ns,lat_mean_ns}},start_unix_ns,end_unix_ns,\n\
  ops,keys,errors,live_keys,manifest,messages (first 20 error details). Every record has schema.\n\
  Exit 0 ok, 1 failed run, 2 usage. `oprobe --version` prints version and git commit.\n";

const BLOCK_BITS: u32 = 40;
/// Gap between the local ids of a fresh fill: key `i` of an owner gets local id `i * ID_STRIDE`.
const ID_STRIDE: u64 = 1 << 16;
/// Most keys one owner may fill fresh: the grid must stay inside its 2^40 block.
const MAX_GRID_KEYS: u64 = (1 << BLOCK_BITS) / ID_STRIDE;
/// Draws before a random new id is given up (the id space is nearly exhausted).
const PICK_TRIES: usize = 64;
/// Manifest layout version; other versions are refused.
const MANIFEST_SCHEMA: u64 = 2;
/// Version of the record layout (`schema` field of every output record).
const SCHEMA: u32 = 1;
/// Error details kept in the summary `messages`.
const MAX_ERROR_DETAILS: usize = 20;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Test {
    Insert,
    Prefill,
    Delete,
    Update,
    MixDelete,
    MixRange,
    Scan,
    DeleteObjects,
}

impl Test {
    fn parse(s: &str) -> Result<Self, String> {
        Ok(match s {
            "insert" => Self::Insert,
            "prefill" => Self::Prefill,
            "delete" => Self::Delete,
            "update" => Self::Update,
            "mix-delete" => Self::MixDelete,
            "mix-range" => Self::MixRange,
            "scan" => Self::Scan,
            "delete-objects" => Self::DeleteObjects,
            _ => return Err(format!("unknown test '{s}' (see omapgate --help)")),
        })
    }
    fn name(self) -> &'static str {
        match self {
            Self::Insert => "insert",
            Self::Prefill => "prefill",
            Self::Delete => "delete",
            Self::Update => "update",
            Self::MixDelete => "mix-delete",
            Self::MixRange => "mix-range",
            Self::Scan => "scan",
            Self::DeleteObjects => "delete-objects",
        }
    }
    fn is_mix(self) -> bool {
        matches!(self, Self::MixDelete | Self::MixRange)
    }
    fn is_fill(self) -> bool {
        matches!(self, Self::Insert | Self::Prefill)
    }
    /// Tests that work off a precomputed random key list of every owner.
    fn is_listed(self) -> bool {
        matches!(self, Self::Delete | Self::Update)
    }
    fn kinds(self) -> &'static [Kind] {
        match self {
            Self::Delete => &[Kind::Delete],
            Self::Update => &[Kind::Update],
            Self::MixDelete => &[Kind::Insert, Kind::Update, Kind::Delete, Kind::PointRead],
            Self::MixRange => &[
                Kind::Insert,
                Kind::Update,
                Kind::DeleteRange,
                Kind::PointRead,
            ],
            _ => &[Kind::Insert],
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Kind {
    Insert,
    Update,
    Delete,
    DeleteRange,
    PointRead,
    Scan,
    DeleteObject,
    VerifyAbsent,
}

const KINDS: [Kind; 8] = [
    Kind::Insert,
    Kind::Update,
    Kind::Delete,
    Kind::DeleteRange,
    Kind::PointRead,
    Kind::Scan,
    Kind::DeleteObject,
    Kind::VerifyAbsent,
];

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Insert => "insert",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::DeleteRange => "delete_range",
            Self::PointRead => "point_read",
            Self::Scan => "scan",
            Self::DeleteObject => "delete_object",
            Self::VerifyAbsent => "verify_absent",
        }
    }
}

#[derive(Clone, Debug)]
struct Cfg {
    test: Test,
    pool: String,
    prefix: Option<String>,
    owned: bool,
    objects: u64,
    per_client: u64,
    clients: u64,
    base: u64,
    total: u64,
    qd: usize,
    object_inflight: Option<usize>,
    keys: u64,
    keys_per_op: u64,
    insert_keys: Option<u64>,
    delete_fraction: Option<f64>,
    passes: u64,
    value_bytes: usize,
    ops: Option<OpScope>,
    duration: Option<Duration>,
    manifest_in: Option<PathBuf>,
    manifest_out: Option<PathBuf>,
    expect_keys: Option<u64>,
    scan_page: u64,
    delete_per_client: Option<u64>,
    seed: u64,
    idle_us: u64,
    start_at: Option<u64>,
    max_seconds: Option<u64>,
}

impl Cfg {
    fn parse(test: Test, a: Vec<String>) -> Result<Self, String> {
        let mut m = BTreeMap::new();
        let mut it = a.into_iter();
        while let Some(k) = it.next() {
            if !k.starts_with("--") || m.contains_key(&k) {
                return Err(format!("unexpected or duplicate argument {k}"));
            }
            let v = it.next().ok_or_else(|| format!("missing value for {k}"))?;
            m.insert(k, v);
        }
        fn num(m: &mut BTreeMap<String, String>, k: &str) -> Result<Option<u64>, String> {
            m.remove(k)
                .map(|v| v.parse().map_err(|_| format!("invalid {k}")))
                .transpose()
        }
        let owned = match m.remove("--layout").as_deref().unwrap_or("shared") {
            "shared" => false,
            "owned" => true,
            _ => return Err("--layout must be shared|owned".into()),
        };
        let clients = num(&mut m, "--clients")?.unwrap_or(1);
        let base = num(&mut m, "--client-base")?.unwrap_or(0);
        let client_end = base.checked_add(clients).ok_or("client range overflows")?;
        let c = Self {
            test,
            pool: String::new(),
            prefix: m.remove("--prefix"),
            owned,
            objects: num(&mut m, "--objects")?.unwrap_or(1),
            per_client: num(&mut m, "--objects-per-client")?.unwrap_or(1),
            clients,
            base,
            total: num(&mut m, "--total-clients")?.unwrap_or(client_end),
            qd: num(&mut m, "--qd")?.unwrap_or(1) as usize,
            object_inflight: num(&mut m, "--object-inflight")?.map(|v| v as usize),
            keys: num(&mut m, "--keys")?.unwrap_or(1 << 20),
            keys_per_op: num(&mut m, "--keys-per-op")?.unwrap_or(256),
            insert_keys: num(&mut m, "--insert-keys")?,
            delete_fraction: m
                .remove("--delete-fraction")
                .map(|v| {
                    v.parse()
                        .map_err(|_| "invalid --delete-fraction".to_string())
                })
                .transpose()?,
            passes: num(&mut m, "--passes")?.unwrap_or(1),
            value_bytes: num(&mut m, "--value-bytes")?.unwrap_or(256) as usize,
            ops: match (
                num(&mut m, "--ops-per-client")?,
                num(&mut m, "--ops-per-object")?,
            ) {
                (Some(_), Some(_)) => {
                    return Err("--ops-per-client and --ops-per-object are exclusive".into());
                }
                (Some(n), None) => Some(OpScope::Client(n)),
                (None, Some(n)) => Some(OpScope::Object(n)),
                (None, None) => None,
            },
            duration: num(&mut m, "--duration")?.map(Duration::from_secs),
            manifest_in: m.remove("--manifest").map(PathBuf::from),
            manifest_out: m.remove("--manifest-out").map(PathBuf::from),
            expect_keys: num(&mut m, "--expect-keys")?,
            scan_page: num(&mut m, "--scan-page")?.unwrap_or(1024),
            delete_per_client: num(&mut m, "--per-client")?,
            seed: num(&mut m, "--seed")?.unwrap_or(1),
            idle_us: num(&mut m, "--idle-us")?.unwrap_or(100),
            start_at: num(&mut m, "--start-at")?,
            max_seconds: num(&mut m, "--max-seconds")?,
        };
        if !m.is_empty() {
            return Err(format!("unknown options: {:?}", m.keys()));
        }
        c.validate()?;
        Ok(c)
    }

    fn validate(&self) -> Result<(), String> {
        let t = self.test;
        if self.clients == 0
            || self.clients > 1024
            || self
                .base
                .checked_add(self.clients)
                .is_none_or(|end| end > self.total)
            || self.qd == 0
            || self.qd > 4096
            || self.object_inflight == Some(0)
            || self.objects == 0
            || self.per_client == 0
            || self.keys == 0
            || !(1..=1024).contains(&self.keys_per_op)
            || !(8..=1 << 20).contains(&self.value_bytes)
            || !(1..=4096).contains(&self.scan_page)
        {
            return Err("invalid bounds (see omapgate --help)".into());
        }
        if t == Test::Prefill && self.manifest_in.is_some() {
            return Err("prefill: --manifest not accepted (fresh objects)".into());
        }
        if t == Test::Insert && self.manifest_in.is_some() != self.insert_keys.is_some() {
            return Err("insert: --manifest and --insert-keys go together (populated objects); fresh objects use --keys".into());
        }
        if self.insert_keys == Some(0) {
            return Err("--insert-keys must be > 0".into());
        }
        if t.is_fill() && self.prefix.is_none() && self.manifest_in.is_none() {
            return Err(format!("{}: --prefix required", t.name()));
        }
        if t == Test::Delete && !self.delete_fraction.is_some_and(|f| f > 0.0 && f <= 1.0) {
            return Err("delete: --delete-fraction F with 0 < F <= 1 required".into());
        }
        if t != Test::Delete && self.delete_fraction.is_some() {
            return Err("--delete-fraction is a delete option".into());
        }
        if self.passes == 0 || (t != Test::Scan && self.passes != 1) {
            return Err("--passes N >= 1 is a scan option".into());
        }
        if t == Test::Prefill && self.base != 0 {
            return Err("prefill: --client-base must be 0 (one process fills all ranks)".into());
        }
        if (t.is_mix() || t.is_listed() || t == Test::DeleteObjects) && self.manifest_in.is_none() {
            return Err(format!("{}: --manifest required", t.name()));
        }
        if t == Test::Scan
            && self.manifest_in.is_none()
            && (self.prefix.is_none() || self.expect_keys.is_none())
        {
            return Err("scan: --manifest, or --prefix + --objects + --expect-keys".into());
        }
        if t.is_mix() && self.ops.is_some() == self.duration.is_some() {
            return Err(format!(
                "{}: exactly one of --ops-per-client | --ops-per-object | --duration",
                t.name()
            ));
        }
        if !t.is_mix() && (self.ops.is_some() || self.duration.is_some()) {
            return Err(format!(
                "{}: --ops-per-*/--duration are mix options",
                t.name()
            ));
        }
        Ok(())
    }

    fn name(&self, index: u64) -> String {
        object_name(self.prefix.as_deref().unwrap_or(""), index)
    }
}

fn object_name(prefix: &str, index: u64) -> String {
    format!("{prefix}-o{index:05}")
}

fn key_id(rank: u64, local: u64) -> u64 {
    (rank << BLOCK_BITS) | local
}

fn key_bytes(id: u64) -> Vec<u8> {
    format!("{id:064x}").into_bytes()
}

/// Size of part `i` when `n` is split evenly into `parts`.
fn interval(n: u64, i: u64, parts: u64) -> u64 {
    let at = |j: u64| (u128::from(n) * u128::from(j) / u128::from(parts)) as u64;
    at(i + 1) - at(i)
}

/// Keys of owner `i` of `parts` when the `n` keys of a shared object are written in whole
/// `keys_per_op` batches: owner boundaries fall on batch boundaries, so every owner writes
/// `ceil(quota / keys_per_op)` whole ops (their sum is `ceil(n / keys_per_op)`) and the quotas
/// still sum to exactly `n` (the last owner carries the partial batch).
fn share_batches(n: u64, i: u64, parts: u64, keys_per_op: u64) -> u64 {
    let batches = n.div_ceil(keys_per_op);
    let at = |j: u64| {
        (u128::from(batches) * u128::from(j) / u128::from(parts)) * u128::from(keys_per_op)
    };
    (at(i + 1).min(u128::from(n)) - at(i).min(u128::from(n))) as u64
}

// ---------------------------------------------------------------- manifest

/// Key sets of one owner rank in one object (see the module doc for the encoding).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OwnerBlob {
    pub live_n: u64,
    pub live: String,
    pub dead: String,
}

/// One object of a manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManObj {
    pub index: u64,
    pub name: String,
    pub live_keys: u64,
    /// Key sets per owner rank (`None`: not known by this manifest); empty: no key sets at all.
    pub owners: Vec<Option<OwnerBlob>>,
}

/// Objects and final live key counts of a mutating run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub pool: String,
    pub prefix: String,
    pub owned: bool,
    pub per_client: u64,
    pub client_base: u64,
    pub total_clients: u64,
    pub value_bytes: usize,
    pub objects: Vec<ManObj>,
}

/// Decoded owner key sets: live `(id, generation)` and dead ids, ascending.
type KeySets = (Vec<(u64, u32)>, Vec<u64>);

const HEX: &[u8; 16] = b"0123456789abcdef";

fn put_varint(out: &mut String, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        let b = if v == 0 { b } else { b | 0x80 };
        out.push(HEX[usize::from(b >> 4)] as char);
        out.push(HEX[usize::from(b & 15)] as char);
        if v == 0 {
            return;
        }
    }
}

/// Local ids (and generations) of sorted `ids`, delta-coded; `rank` fixes the block base.
fn encode_ids(rank: u64, ids: impl Iterator<Item = (u64, Option<u32>)>) -> String {
    let (base, mut prev, mut out) = (key_id(rank, 0), 0, String::new());
    for (id, g) in ids {
        let local = id - base;
        put_varint(&mut out, local - prev);
        prev = local;
        if let Some(g) = g {
            put_varint(&mut out, u64::from(g));
        }
    }
    out
}

fn decode_varints(s: &str) -> Result<Vec<u64>, String> {
    let bad = || "manifest: malformed key set".to_string();
    let nib = |c: u8| match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(bad()),
    };
    if !s.len().is_multiple_of(2) {
        return Err(bad());
    }
    let (mut out, mut v, mut shift) = (Vec::new(), 0u64, 0u32);
    for p in s.as_bytes().chunks(2) {
        let b = nib(p[0])? << 4 | nib(p[1])?;
        if shift > 63 {
            return Err(bad());
        }
        v |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            out.push(v);
            (v, shift) = (0, 0);
        } else {
            shift += 7;
        }
    }
    if shift != 0 {
        return Err(bad());
    }
    Ok(out)
}

impl OwnerBlob {
    fn encode(rank: u64, live: &BTreeMap<u64, u32>, dead: &BTreeSet<u64>) -> Self {
        Self {
            live_n: live.len() as u64,
            live: encode_ids(rank, live.iter().map(|(k, g)| (*k, Some(*g)))),
            dead: encode_ids(rank, dead.iter().map(|k| (*k, None))),
        }
    }

    /// Live `(id, generation)` pairs and dead ids, ascending.
    fn decode(&self, rank: u64) -> Result<KeySets, String> {
        let base = key_id(rank, 0);
        let flat = decode_varints(&self.live)?;
        if flat.len() as u64 != self.live_n * 2 {
            return Err("manifest: live key count mismatch".into());
        }
        let mut local = 0u64;
        let live = flat
            .chunks(2)
            .map(|p| {
                local += p[0];
                (base + local, p[1] as u32)
            })
            .collect();
        local = 0;
        let dead = decode_varints(&self.dead)?
            .into_iter()
            .map(|d| {
                local += d;
                base + local
            })
            .collect();
        Ok((live, dead))
    }
}

impl Manifest {
    pub fn to_json(&self) -> Value {
        json!({"schema":MANIFEST_SCHEMA,"pool":self.pool,"prefix":self.prefix,
            "layout":if self.owned {"owned"} else {"shared"},
            "objects_per_client":self.per_client,"client_base":self.client_base,
            "total_clients":self.total_clients,"key_bytes":64,"value_bytes":self.value_bytes,
            "id_stride":ID_STRIDE,
            "objects":self.objects.iter().map(|o| {
                let mut j = json!({"index":o.index,"name":o.name,"live_keys":o.live_keys});
                if !o.owners.is_empty() {
                    j["owners"] = json!(o.owners.iter().map(|b| b.as_ref().map(|b|
                        json!({"live_n":b.live_n,"live":b.live,"dead":b.dead}))).collect::<Vec<_>>());
                }
                j}).collect::<Vec<_>>()})
    }

    pub fn from_json(v: &Value) -> Result<Self, String> {
        let s = |k: &str| {
            v[k].as_str()
                .map(String::from)
                .ok_or(format!("manifest: {k}"))
        };
        let n = |v: &Value, k: &str| v[k].as_u64().ok_or(format!("manifest: {k}"));
        let schema = n(v, "schema")?;
        if schema != MANIFEST_SCHEMA {
            return Err(format!(
                "manifest: schema {schema} not supported (need {MANIFEST_SCHEMA}); recreate it with prefill/insert"
            ));
        }
        if n(v, "id_stride")? != ID_STRIDE {
            return Err("manifest: id_stride differs from this build".into());
        }
        let objects = v["objects"]
            .as_array()
            .ok_or("manifest: objects")?
            .iter()
            .map(|o| {
                let owners = match o.get("owners") {
                    None => Vec::new(),
                    Some(b) => b
                        .as_array()
                        .ok_or("manifest: owners")?
                        .iter()
                        .map(|x| {
                            if x.is_null() {
                                return Ok(None);
                            }
                            Ok(Some(OwnerBlob {
                                live_n: n(x, "live_n")?,
                                live: x["live"].as_str().ok_or("manifest: live")?.into(),
                                dead: x["dead"].as_str().ok_or("manifest: dead")?.into(),
                            }))
                        })
                        .collect::<Result<_, String>>()?,
                };
                Ok(ManObj {
                    index: n(o, "index")?,
                    name: o["name"].as_str().ok_or("manifest: name")?.into(),
                    live_keys: n(o, "live_keys")?,
                    owners,
                })
            })
            .collect::<Result<_, String>>()?;
        Ok(Self {
            pool: s("pool")?,
            prefix: s("prefix")?,
            owned: match s("layout")?.as_str() {
                "owned" => true,
                "shared" => false,
                _ => return Err("manifest: layout".into()),
            },
            per_client: n(v, "objects_per_client")?,
            client_base: n(v, "client_base")?,
            total_clients: n(v, "total_clients")?,
            value_bytes: n(v, "value_bytes")? as usize,
            objects,
        })
    }

    fn load(p: &Path) -> Result<Self, String> {
        let t = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
        let v: Value = serde_json::from_str(&t).map_err(|e| format!("{}: {e}", p.display()))?;
        Self::from_json(&v)
    }
}

// ---------------------------------------------------------------- plan

/// One (object, key owner) pair handled by one client.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Unit {
    index: u64,
    name: String,
    rank: u64,
    /// Insert: new keys to add.
    quota: u64,
    /// Fresh fill: keys go on the `ID_STRIDE` grid; otherwise random free ids.
    grid: bool,
    /// Keys live at the start, ascending, with their generation.
    live: Vec<(u64, u32)>,
    /// Ids that existed before and are gone, ascending.
    dead: Vec<u64>,
}

/// Units per local client for insert / prefill / delete / update / mix.
fn plan(c: &Cfg, man: Option<&Manifest>) -> Result<Vec<Vec<Unit>>, String> {
    let mut out = vec![Vec::new(); c.clients as usize];
    let share = |rank: u64| match (c.test, c.insert_keys) {
        (Test::Insert, Some(n)) if c.owned => n,
        (Test::Insert, Some(n)) => share_batches(n, rank, c.total, c.keys_per_op),
        _ => 0,
    };
    if let Some(m) = man {
        for o in &m.objects {
            if o.owners.is_empty() {
                return Err(format!(
                    "{}: manifest has no key sets (scan manifest?); prefill first",
                    o.name
                ));
            }
            let unit = |rank: u64, slot: usize| {
                let b = o.owners.get(slot).and_then(Option::as_ref).ok_or_else(|| {
                    format!("{}: manifest has no key set for owner {rank}", o.name)
                })?;
                let (live, dead) = b.decode(rank)?;
                Ok::<_, String>(Unit {
                    index: o.index,
                    name: o.name.clone(),
                    rank,
                    quota: share(rank),
                    grid: false,
                    live,
                    dead,
                })
            };
            if m.owned {
                let g = o.index / m.per_client;
                if g < c.base || g >= c.base + c.clients {
                    return Err(format!("{}: owner client {g} not in this process", o.name));
                }
                out[(g - c.base) as usize].push(unit(0, 0)?);
            } else {
                if o.owners.len() as u64 != c.total {
                    return Err("manifest owners != --total-clients".into());
                }
                for (i, cl) in out.iter_mut().enumerate() {
                    let rank = c.base + i as u64;
                    cl.push(unit(rank, rank as usize)?);
                }
            }
        }
        return Ok(out);
    }
    let fresh = |index: u64, rank: u64, quota: u64| {
        if quota > MAX_GRID_KEYS {
            return Err(format!(
                "object {index}: {quota} keys for one owner exceed the {MAX_GRID_KEYS} that fit its block"
            ));
        }
        Ok(Unit {
            index,
            name: c.name(index),
            rank,
            quota,
            grid: true,
            live: Vec::new(),
            dead: Vec::new(),
        })
    };
    for (i, cl) in out.iter_mut().enumerate() {
        let g = c.base + i as u64;
        if c.owned {
            for j in 0..c.per_client {
                cl.push(fresh(g * c.per_client + j, 0, c.keys)?);
            }
        } else {
            // prefill: one process fills every rank, round-robin over its sessions
            let ranks: Vec<u64> = if c.test == Test::Prefill {
                (0..c.total).filter(|r| r % c.clients == i as u64).collect()
            } else {
                vec![g]
            };
            for index in 0..c.objects {
                for &rank in &ranks {
                    cl.push(fresh(
                        index,
                        rank,
                        share_batches(c.keys, rank, c.total, c.keys_per_op),
                    )?);
                }
            }
        }
    }
    Ok(out)
}

/// Objects per local client for scan / delete-objects.
fn objects_for(c: &Cfg, man: &Manifest) -> Vec<Vec<ManObj>> {
    let mut out = vec![Vec::new(); c.clients as usize];
    for (pos, o) in man.objects.iter().enumerate() {
        let i = if man.owned {
            (o.index / man.per_client).saturating_sub(c.base) % c.clients
        } else {
            pos as u64 % c.clients
        };
        out[i as usize].push(o.clone());
    }
    out
}

// ---------------------------------------------------------------- scheduler

/// Round-robin over (object, op type) slots with a global QD and a per-slot limit.
struct Sched {
    qd: usize,
    limit: usize,
    inflight: Vec<usize>,
    remaining: Vec<u64>,
    total: usize,
    cursor: usize,
}

impl Sched {
    fn new(qd: usize, limit: usize, remaining: Vec<u64>) -> Self {
        Self {
            qd,
            limit,
            inflight: vec![0; remaining.len()],
            remaining,
            total: 0,
            cursor: 0,
        }
    }
    /// Slots that may start an op now, in round-robin order from the cursor.
    fn candidates(&self) -> Vec<usize> {
        if self.total >= self.qd {
            return Vec::new();
        }
        let n = self.remaining.len();
        (0..n)
            .map(|i| (self.cursor + i) % n)
            .filter(|&s| self.inflight[s] < self.limit && self.remaining[s] > 0)
            .collect()
    }
    fn can_take(&self, s: usize) -> bool {
        self.total < self.qd && self.inflight[s] < self.limit && self.remaining[s] > 0
    }
    fn take(&mut self, s: usize) {
        self.inflight[s] += 1;
        self.total += 1;
        if self.remaining[s] != u64::MAX {
            self.remaining[s] -= 1;
        }
        self.cursor = (s + 1) % self.remaining.len();
    }
    fn release(&mut self, s: usize) {
        self.inflight[s] -= 1;
        self.total -= 1;
    }
    fn exhausted(&self) -> bool {
        self.remaining.iter().all(|&r| r == 0)
    }
}

// ---------------------------------------------------------------- per-object client state

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        splitmix(&mut self.0)
    }
}

struct UnitState {
    unit: Unit,
    live: BTreeMap<u64, u32>,
    /// Ids that existed and are gone: never drawn again.
    dead: BTreeSet<u64>,
    reserved: BTreeSet<u64>,
    /// `[begin, end)` id spans of in-flight range deletes: no insert may land inside.
    spans: Vec<(u64, u64)>,
    /// Exclusive upper bound of the local ids ever used.
    hi: u64,
    /// Grid fill: next grid index.
    next_grid: u64,
    insert_left: u64,
    generation: u32,
    /// Delete / update tests: ids still to process, in random order (popped from the end).
    todo: Option<Vec<u64>>,
    rng: Rng,
}

/// One op with its reserved keys (id, generation).
struct Built {
    kind: Kind,
    ids: Vec<(u64, u32)>,
    msg: ScriptMsg,
    bytes: u64,
}

fn msg(op: OsdOp) -> ScriptMsg {
    ScriptMsg {
        ops: vec![op],
        ..Default::default()
    }
}

impl UnitState {
    fn new(c: &Cfg, mut unit: Unit, client: u64) -> Self {
        let base = key_id(unit.rank, 0);
        let live_v = std::mem::take(&mut unit.live);
        let dead: BTreeSet<u64> = std::mem::take(&mut unit.dead).into_iter().collect();
        let hi = live_v
            .last()
            .map(|(k, _)| *k)
            .max(dead.last().copied())
            .map_or(0, |k| k - base + 1);
        let top = live_v.iter().map(|(_, g)| *g).max().unwrap_or(0);
        let mut rng = Rng(c.seed
            ^ (client << 32)
            ^ unit.index.wrapping_mul(0x9E37_79B9)
            ^ (c.test as u64).wrapping_mul(0xD6E8_FEB8_6659_FD93));
        let todo = c.test.is_listed().then(|| {
            let mut ids: Vec<u64> = live_v.iter().map(|(k, _)| *k).collect();
            for i in (1..ids.len()).rev() {
                ids.swap(i, (rng.next() % (i as u64 + 1)) as usize);
            }
            if let Some(f) = c.delete_fraction {
                ids.truncate((live_v.len() as f64 * f).round() as usize);
            }
            ids
        });
        Self {
            insert_left: if c.test.is_mix() {
                u64::MAX
            } else {
                unit.quota
            },
            // an update test writes one generation above everything live
            generation: top + u32::from(c.test == Test::Update),
            next_grid: 0,
            hi,
            todo,
            rng,
            reserved: BTreeSet::new(),
            spans: Vec::new(),
            live: live_v.into_iter().collect(),
            dead,
            unit,
        }
    }

    /// Nothing left to build for the fill / list tests.
    fn drained(&self) -> bool {
        self.todo
            .as_ref()
            .map_or(self.insert_left == 0, Vec::is_empty)
    }

    /// An id in `[0, hi)` that is not live, dead, in flight, in `batch` or inside a range delete.
    fn pick_free(&mut self, batch: &BTreeSet<u64>) -> Option<u64> {
        let lo = key_id(self.unit.rank, 0);
        if self.hi == 0 {
            return None;
        }
        for _ in 0..PICK_TRIES {
            let id = lo + self.rng.next() % self.hi;
            let used = self.live.contains_key(&id)
                || self.dead.contains(&id)
                || self.reserved.contains(&id)
                || batch.contains(&id)
                || self.spans.iter().any(|(a, b)| (*a..*b).contains(&id));
            if !used {
                return Some(id);
            }
        }
        None
    }

    /// Up to `n` keys for the next op: the next ones of the random list, or scattered live keys.
    /// Removed from the live set (reserved by the caller).
    fn take_keys(&mut self, n: u64) -> Vec<(u64, u32)> {
        let Some(todo) = &mut self.todo else {
            return self.take_scattered(n);
        };
        let at = todo.len().saturating_sub(n as usize);
        let mut ids = todo.split_off(at);
        ids.sort_unstable();
        ids.into_iter()
            .map(|k| (k, self.live.remove(&k).expect("listed key is live")))
            .collect()
    }

    /// Up to `n` scattered live keys, removed from the live set (reserved by the caller).
    fn take_scattered(&mut self, n: u64) -> Vec<(u64, u32)> {
        let lo = key_id(self.unit.rank, 0);
        let span = self.hi.max(1);
        let mut out = Vec::new();
        while (out.len() as u64) < n && !self.live.is_empty() {
            let r = lo + self.rng.next() % span;
            let id = self
                .live
                .range(r..)
                .next()
                .or_else(|| self.live.iter().next())
                .map(|(k, g)| (*k, *g))
                .expect("non-empty");
            self.live.remove(&id.0);
            out.push(id);
        }
        out.sort_unstable();
        out
    }

    /// A contiguous run of up to `n` live keys with no reserved key inside its span.
    fn take_run(&mut self, n: u64) -> Option<Vec<(u64, u32)>> {
        let lo = key_id(self.unit.rank, 0);
        let span = self.hi.max(1);
        for _ in 0..8 {
            let r = lo + self.rng.next() % span;
            let mut run: Vec<(u64, u32)> = self
                .live
                .range(r..)
                .take(n as usize)
                .map(|(k, g)| (*k, *g))
                .collect();
            if (run.len() as u64) < n {
                // not enough keys above the probe: take the highest live keys instead
                run = self
                    .live
                    .iter()
                    .rev()
                    .take(n as usize)
                    .map(|(k, g)| (*k, *g))
                    .collect();
                run.reverse();
            }
            let (Some(f), Some(l)) = (run.first(), run.last()) else {
                return None;
            };
            if self.reserved.range(f.0..=l.0).next().is_none() {
                for (k, _) in &run {
                    self.live.remove(k);
                }
                return Some(run);
            }
        }
        None
    }

    fn build(&mut self, c: &Cfg, kind: Kind) -> Option<Built> {
        let n = c.keys_per_op;
        let vb = c.value_bytes;
        let set = |ids: &[(u64, u32)]| {
            let vals: KvMap = ids
                .iter()
                .map(|(id, g)| {
                    let k = key_bytes(*id);
                    let v = value(&k, u64::from(*g), vb);
                    (k, v)
                })
                .collect();
            msg(OsdOp::omap_set_vals(&vals))
        };
        let key_set = |ids: &[(u64, u32)]| -> BTreeSet<Vec<u8>> {
            ids.iter().map(|(k, _)| key_bytes(*k)).collect()
        };
        let kv_bytes = |ids: &[(u64, u32)]| ids.len() as u64 * (64 + vb as u64);
        let b = match kind {
            Kind::Insert => {
                let n = n.min(self.insert_left);
                if n == 0 {
                    return None;
                }
                let rank = self.unit.rank;
                let ids: Vec<(u64, u32)> = if self.unit.grid {
                    let from = self.next_grid;
                    self.next_grid += n;
                    (from..self.next_grid)
                        .map(|i| (key_id(rank, i * ID_STRIDE), 0))
                        .collect()
                } else {
                    let mut got = BTreeSet::new();
                    while (got.len() as u64) < n {
                        let Some(id) = self.pick_free(&got) else {
                            break;
                        };
                        got.insert(id);
                    }
                    got.into_iter().map(|k| (k, 0)).collect()
                };
                let last = ids.last()?.0;
                self.hi = self.hi.max(last - key_id(rank, 0) + 1);
                if self.insert_left != u64::MAX {
                    self.insert_left -= ids.len() as u64;
                }
                Built {
                    kind,
                    msg: set(&ids),
                    bytes: kv_bytes(&ids),
                    ids,
                }
            }
            Kind::Update => {
                let ids = self.take_keys(n);
                if ids.is_empty() {
                    return None;
                }
                if self.todo.is_none() {
                    self.generation += 1;
                }
                let g = self.generation;
                let ids: Vec<_> = ids.into_iter().map(|(k, _)| (k, g)).collect();
                Built {
                    kind,
                    msg: set(&ids),
                    bytes: kv_bytes(&ids),
                    ids,
                }
            }
            Kind::PointRead => {
                let ids = self.take_scattered(n);
                if ids.is_empty() {
                    return None;
                }
                let mut op = OsdOp::new(opwire::op::OMAP_GET_VALS_BY_KEYS);
                op.indata = key_set(&ids)
                    .encode_to_vec()
                    .expect("bounded key set")
                    .into();
                Built {
                    kind,
                    msg: msg(op),
                    bytes: kv_bytes(&ids),
                    ids,
                }
            }
            Kind::Delete => {
                let ids = self.take_keys(n);
                if ids.is_empty() {
                    return None;
                }
                Built {
                    kind,
                    msg: msg(OsdOp::omap_rm_keys(&key_set(&ids))),
                    bytes: ids.len() as u64 * 64,
                    ids,
                }
            }
            Kind::DeleteRange => {
                let ids = self.take_run(n)?;
                let (f, l) = (ids[0].0, ids[ids.len() - 1].0);
                self.spans.push((f, l + 1));
                let mut op = OsdOp::new(opwire::op::OMAP_RM_KEY_RANGE);
                op.indata = opwire::OmapRmKeyRangeIn {
                    begin: key_bytes(f),
                    end: key_bytes(l + 1),
                }
                .encode_to_vec()
                .expect("range")
                .into();
                Built {
                    kind,
                    msg: msg(op),
                    bytes: ids.len() as u64 * 64,
                    ids,
                }
            }
            _ => return None,
        };
        self.reserved.extend(b.ids.iter().map(|(k, _)| *k));
        Some(b)
    }

    /// Apply a successful completion.
    fn complete(&mut self, b: &Built) {
        for (k, g) in &b.ids {
            self.reserved.remove(k);
            match b.kind {
                Kind::Insert | Kind::Update | Kind::PointRead => {
                    self.live.insert(*k, *g);
                }
                Kind::Delete | Kind::DeleteRange => {
                    self.dead.insert(*k);
                }
                _ => {}
            }
        }
        if let (Kind::DeleteRange, Some(f), Some(l)) = (b.kind, b.ids.first(), b.ids.last()) {
            self.spans.retain(|s| *s != (f.0, l.0 + 1));
        }
    }

    fn live_keys(&self) -> u64 {
        self.live.len() as u64
    }
}

// ---------------------------------------------------------------- stats

#[derive(Default)]
struct Stats {
    ops: u64,
    keys: u64,
    bytes: u64,
    errors: u64,
    sum_ns: u64,
    wall: f64,
    hist: Hist,
}

impl Stats {
    fn rec(&mut self, d: &Done, keys: u64, bytes: u64) {
        let ns = d.finished.duration_since(d.submitted).as_nanos() as u64;
        self.ops += 1;
        self.keys += keys;
        self.bytes += bytes;
        self.sum_ns += ns;
        self.hist.rec(ns / 1000);
    }
    fn merge(&mut self, o: &Stats) {
        self.ops += o.ops;
        self.keys += o.keys;
        self.bytes += o.bytes;
        self.errors += o.errors;
        self.sum_ns += o.sum_ns;
        self.wall = self.wall.max(o.wall);
        self.hist.merge(&o.hist);
    }
}

fn new_stats() -> Vec<Stats> {
    KINDS.iter().map(|_| Stats::default()).collect()
}

struct ClientOut {
    stats: Vec<Stats>,
    objects: Vec<ManObj>,
    /// Timed wall of this client in ns.
    wall_ns: u64,
    messages: Vec<String>,
    /// (phase, start, end) in UTC unix nanoseconds.
    phases: Vec<(&'static str, u64, u64)>,
}

struct Ctl {
    abort: AtomicBool,
    rpc_timeout: Duration,
}

fn warn(op: &str, limit: f64, ctx: &str) -> String {
    let m = format!("WARNING TIMEOUT {op} exceeded {limit}s ({ctx})");
    eprintln!("{m}");
    m
}

/// Reply payload of a single-op message; timeouts are loud.
fn payload<'a>(d: &'a Done, ctl: &Ctl, what: &str) -> Result<&'a [u8], String> {
    let r = d.reply.as_ref().ok_or_else(|| {
        if d.err.to_ascii_lowercase().contains("timeout") {
            warn(
                "omapgate rpc",
                ctl.rpc_timeout.as_secs_f64(),
                &format!("{what}, tag {}", d.tag),
            )
        } else {
            format!("{what}: {}", d.err)
        }
    })?;
    if r.result < 0 || r.ops.len() != 1 || r.ops[0].rval < 0 {
        return Err(format!(
            "{what}: failed reply result={} ops={:?}",
            r.result,
            r.ops.iter().map(|o| o.rval).collect::<Vec<_>>()
        ));
    }
    Ok(&r.ops[0].outdata)
}

fn unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("epoch")
        .as_nanos() as u64
}

/// Warm the OSD connection of every object (stat; ENOENT is fine).
fn warm(p: &mut Probe, pool: i64, names: &[String], ctl: &Ctl) -> Result<(), String> {
    for (i, n) in names.iter().enumerate() {
        p.submit(target(pool, n), msg(OsdOp::stat()), i as u64)?;
    }
    while p.in_flight() != 0 {
        for d in p.poll() {
            if d.reply.as_ref().is_none_or(|r| r.result != -2) {
                payload(&d, ctl, "warm-up stat")?;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- write engine (insert/prefill/mix)

fn run_write(
    p: &mut Probe,
    pool: i64,
    c: &Cfg,
    units: Vec<Unit>,
    client: u64,
    ctl: &Ctl,
    t0: Instant,
) -> Result<ClientOut, String> {
    let kinds = c.test.kinds();
    let nk = kinds.len();
    let mut states: Vec<UnitState> = units
        .into_iter()
        .map(|u| UnitState::new(c, u, client))
        .collect();
    let units_n = states.len() as u64;
    let remaining = (0..states.len() * nk)
        .map(|s| op_quota(c.ops, nk as u64, (s % nk) as u64, (s / nk) as u64, units_n))
        .collect();
    let mut sched = Sched::new(c.qd, c.object_inflight.unwrap_or(c.qd), remaining);
    let mut stats = new_stats();
    let start_ns = unix_ns();
    let mut pending: HashMap<u64, (usize, Built)> = HashMap::new();
    let mut tag = 0u64;
    let end = c.duration.map(|d| t0 + d);
    let hard = c
        .max_seconds
        .unwrap_or_else(|| c.duration.map_or(86_400, |d| d.as_secs() + 600));
    let hard_end = t0 + Duration::from_secs(hard);
    loop {
        if ctl.abort.load(Ordering::Relaxed) {
            return Err("aborted: another client failed".into());
        }
        let stopping = end.is_some_and(|e| Instant::now() >= e);
        if !stopping {
            for s in sched.candidates() {
                if !sched.can_take(s) {
                    continue;
                }
                let (ui, ki) = (s / nk, s % nk);
                if let Some(b) = states[ui].build(c, kinds[ki]) {
                    p.submit(target(pool, &states[ui].unit.name), b.msg.clone(), tag)?;
                    sched.take(s);
                    pending.insert(tag, (s, b));
                    tag += 1;
                }
            }
        }
        if pending.is_empty() {
            let done = stopping
                || if c.test.is_mix() {
                    sched.exhausted()
                } else {
                    states.iter().all(UnitState::drained)
                };
            if done {
                break;
            }
            return Err(
                "stuck: no op can be built (no live keys left, or id space nearly exhausted?)"
                    .into(),
            );
        }
        if Instant::now() >= hard_end {
            return Err(warn(
                "omapgate",
                hard as f64,
                &format!(
                    "{}, client {client}, {} pending",
                    c.test.name(),
                    pending.len()
                ),
            ));
        }
        for d in p.poll() {
            let (s, b) = pending.remove(&d.tag).ok_or("unknown completion tag")?;
            let ui = s / nk;
            let what = format!("{} {}", b.kind.name(), states[ui].unit.name);
            let out = payload(&d, ctl, &what)?;
            if b.kind == Kind::PointRead {
                check_read(out, &b, c.value_bytes).map_err(|e| format!("{what}: {e}"))?;
            }
            stats[b.kind as usize].rec(&d, b.ids.len() as u64, b.bytes);
            states[ui].complete(&b);
            sched.release(s);
        }
    }
    let wall = t0.elapsed();
    for st in &mut stats {
        st.wall = wall.as_secs_f64();
    }
    let phase = match c.test {
        Test::Prefill => "prefill",
        Test::Insert => "insert",
        Test::Delete => "delete_keys",
        Test::Update => "update",
        _ => "ops",
    };
    Ok(ClientOut {
        stats,
        objects: object_summary(c, &states),
        wall_ns: wall.as_nanos() as u64,
        messages: Vec::new(),
        phases: vec![(phase, start_ns, unix_ns())],
    })
}

/// Per object: live keys of this client and the key sets of its owner ranks.
fn object_summary(c: &Cfg, states: &[UnitState]) -> Vec<ManObj> {
    let mut objects: BTreeMap<u64, ManObj> = BTreeMap::new();
    for s in states {
        let o = objects.entry(s.unit.index).or_insert_with(|| ManObj {
            index: s.unit.index,
            name: s.unit.name.clone(),
            live_keys: 0,
            owners: vec![None; if c.owned { 1 } else { c.total as usize }],
        });
        o.live_keys += s.live_keys();
        o.owners[s.unit.rank as usize] = Some(OwnerBlob::encode(s.unit.rank, &s.live, &s.dead));
    }
    objects.into_values().collect()
}

/// Add one client's view of an object to the process-wide totals (counts are summed once).
fn merge_object(into: &mut BTreeMap<u64, ManObj>, ob: &ManObj) {
    let e = into.entry(ob.index).or_insert_with(|| ManObj {
        index: ob.index,
        name: ob.name.clone(),
        live_keys: 0,
        owners: vec![None; ob.owners.len()],
    });
    e.live_keys += ob.live_keys;
    for (x, y) in e.owners.iter_mut().zip(&ob.owners) {
        if y.is_some() {
            x.clone_from(y);
        }
    }
}

fn check_read(b: &[u8], built: &Built, vb: usize) -> Result<(), String> {
    let (got, _) = entries(b, false)?;
    if got.len() != built.ids.len() {
        return Err(format!(
            "{} keys returned, {} expected",
            got.len(),
            built.ids.len()
        ));
    }
    for ((k, v), (id, g)) in got.iter().zip(&built.ids) {
        if *k != key_bytes(*id) {
            return Err("unexpected key".into());
        }
        if *v != value(k, u64::from(*g), vb) {
            return Err(format!(
                "wrong value/generation for key {id:x} (want gen {g})"
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- scan engine

fn run_scan(
    p: &mut Probe,
    pool: i64,
    c: &Cfg,
    objs: Vec<ManObj>,
    ctl: &Ctl,
    t0: Instant,
) -> Result<ClientOut, String> {
    struct S {
        after: Vec<u8>,
        seen: u64,
    }
    let mut st: Vec<S> = objs
        .iter()
        .map(|_| S {
            after: Vec::new(),
            seen: 0,
        })
        .collect();
    let mut stats = new_stats();
    let start_ns = unix_ns();
    let mut messages = Vec::new();
    let mut pending: HashMap<u64, usize> = HashMap::new();
    let mut tag = 0;
    let hard = c.max_seconds.unwrap_or(86_400);
    let mut failed = 0u64;
    for _ in 0..c.passes {
        for x in &mut st {
            x.after.clear();
            x.seen = 0;
        }
        let mut queue: Vec<usize> = (0..objs.len()).rev().collect();
        loop {
            while pending.len() < c.qd {
                let Some(i) = queue.pop() else { break };
                let m = msg(OsdOp::omap_get_vals(&st[i].after, c.scan_page, b""));
                p.submit(target(pool, &objs[i].name), m, tag)?;
                pending.insert(tag, i);
                tag += 1;
            }
            if pending.is_empty() {
                break;
            }
            if t0.elapsed().as_secs() >= hard {
                return Err(warn(
                    "omapgate scan",
                    hard as f64,
                    &format!("{} pending", pending.len()),
                ));
            }
            for d in p.poll() {
                let i = pending.remove(&d.tag).ok_or("unknown completion tag")?;
                let o = &objs[i];
                let b = payload(&d, ctl, &format!("scan {}", o.name))?;
                let (page, more) = entries(b, true).map_err(|e| format!("{}: {e}", o.name))?;
                let mut bytes = 0;
                for (k, v) in &page {
                    let after_ok = st[i].seen == 0 || *k > st[i].after.as_slice();
                    let hex = k.len() == 64
                        && k.iter()
                            .all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(x));
                    if !(after_ok && hex && value_ok(k, v, c.value_bytes)) {
                        failed += 1;
                        if messages.len() < 20 {
                            messages.push(format!(
                                "{}: invalid entry after {} keys",
                                o.name, st[i].seen
                            ));
                        }
                    }
                    bytes += (k.len() + v.len()) as u64;
                }
                stats[Kind::Scan as usize].rec(&d, page.len() as u64, bytes);
                st[i].seen += page.len() as u64;
                if let Some((k, _)) = page.last() {
                    st[i].after = k.to_vec();
                }
                if more && page.is_empty() {
                    return Err(format!("{}: truncated page without progress", o.name));
                }
                if more {
                    queue.push(i);
                } else if st[i].seen != o.live_keys {
                    failed += 1;
                    messages.push(format!(
                        "{}: scanned {} keys, expected {}",
                        o.name, st[i].seen, o.live_keys
                    ));
                }
            }
        }
    }
    let wall = t0.elapsed();
    stats[Kind::Scan as usize].wall = wall.as_secs_f64();
    stats[Kind::Scan as usize].errors = failed;
    let objects = objs
        .into_iter()
        .zip(&st)
        .map(|(o, s)| ManObj {
            live_keys: s.seen,
            ..o
        })
        .collect();
    Ok(ClientOut {
        stats,
        objects,
        wall_ns: wall.as_nanos() as u64,
        messages,
        phases: vec![("scan", start_ns, unix_ns())],
    })
}

// ---------------------------------------------------------------- delete-objects engine

fn run_delete(
    p: &mut Probe,
    pool: i64,
    c: &Cfg,
    objs: Vec<ManObj>,
    ctl: &Ctl,
    t0: Instant,
) -> Result<ClientOut, String> {
    let n = c
        .delete_per_client
        .map_or(objs.len(), |k| (k as usize).min(objs.len()));
    let (gone, kept) = objs.split_at(n);
    let mut stats = new_stats();
    let mut messages = Vec::new();
    let hard = c.max_seconds.unwrap_or(86_400);
    let phases: [(Kind, fn() -> OsdOp); 2] = [
        (Kind::DeleteObject, OsdOp::delete),
        (Kind::VerifyAbsent, OsdOp::stat),
    ];
    let mut spans = Vec::new();
    for (kind, op) in phases {
        let phase = Instant::now();
        let start_ns = unix_ns();
        let mut next = 0;
        let mut pending: HashMap<u64, usize> = HashMap::new();
        while next < gone.len() || !pending.is_empty() {
            while pending.len() < c.qd && next < gone.len() {
                p.submit(target(pool, &gone[next].name), msg(op()), next as u64)?;
                pending.insert(next as u64, next);
                next += 1;
            }
            if phase.elapsed().as_secs() >= hard {
                return Err(warn("omapgate delete-objects", hard as f64, kind.name()));
            }
            for d in p.poll() {
                let i = pending.remove(&d.tag).ok_or("unknown completion tag")?;
                let name = &gone[i].name;
                if kind == Kind::DeleteObject {
                    payload(&d, ctl, &format!("delete {name}"))?;
                } else if d.reply.as_ref().is_none_or(|r| r.result != -2) {
                    stats[kind as usize].errors += 1;
                    messages.push(format!("{name}: object still present or stat failed"));
                }
                stats[kind as usize].rec(&d, 0, 0);
            }
        }
        stats[kind as usize].wall = phase.elapsed().as_secs_f64();
        let name = if kind == Kind::DeleteObject {
            "delete"
        } else {
            "verify"
        };
        spans.push((name, start_ns, unix_ns()));
    }
    Ok(ClientOut {
        stats,
        objects: kept.to_vec(),
        wall_ns: t0.elapsed().as_nanos() as u64,
        messages,
        phases: spans,
    })
}

// ---------------------------------------------------------------- CLI

enum WorkItem {
    Units(Vec<Unit>),
    Scan(Vec<ManObj>),
    Delete(Vec<ManObj>),
}

impl WorkItem {
    fn names(&self) -> Vec<String> {
        match self {
            Self::Units(u) => u
                .iter()
                .map(|u| u.name.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            Self::Scan(o) | Self::Delete(o) => o.iter().map(|o| o.name.clone()).collect(),
        }
    }
}

/// One thread + session per client; returns the finished clients and the failures.
fn gather(o: &Opts, c: &Cfg, work: Vec<WorkItem>) -> (Vec<(u64, ClientOut)>, Vec<String>) {
    let barrier = Barrier::new(c.clients as usize);
    let setup_err = Mutex::new(None::<String>);
    let ctl = Ctl {
        abort: AtomicBool::new(false),
        rpc_timeout: o.timeout,
    };
    let results: Vec<Result<ClientOut, String>> = std::thread::scope(|s| {
        let hs: Vec<_> = work
            .into_iter()
            .enumerate()
            .map(|(i, item)| {
                let (barrier, setup_err, ctl) = (&barrier, &setup_err, &ctl);
                let o = o.clone();
                s.spawn(move || -> Result<ClientOut, String> {
                    let ready = (|| {
                        let mut p = Probe::connect(o)?;
                        p.idle_sleep = Duration::from_micros(c.idle_us);
                        let pool = p
                            .osdmap()
                            .pool_id_by_name(&c.pool)
                            .ok_or("pool not found")?;
                        warm(&mut p, pool, &item.names(), ctl)?;
                        Ok::<_, String>((p, pool))
                    })();
                    if let Err(e) = &ready {
                        *setup_err.lock().expect("lock") = Some(e.clone());
                    }
                    barrier.wait();
                    if let Some(e) = setup_err.lock().expect("lock").clone() {
                        return Err(e);
                    }
                    let (mut p, pool) = ready?;
                    if let Some(at) = c.start_at {
                        let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("epoch");
                        std::thread::sleep(Duration::from_secs(at).saturating_sub(now));
                    }
                    let t0 = Instant::now();
                    let r = match item {
                        WorkItem::Units(u) => {
                            run_write(&mut p, pool, c, u, c.base + i as u64, ctl, t0)
                        }
                        WorkItem::Scan(l) => run_scan(&mut p, pool, c, l, ctl, t0),
                        WorkItem::Delete(l) => run_delete(&mut p, pool, c, l, ctl, t0),
                    };
                    if r.is_err() {
                        ctl.abort.store(true, Ordering::Relaxed);
                    }
                    r
                })
            })
            .collect();
        hs.into_iter()
            .map(|h| h.join().unwrap_or_else(|_| Err("client panic".into())))
            .collect()
    });
    let (mut ok, mut errs) = (Vec::new(), Vec::new());
    for (i, r) in results.into_iter().enumerate() {
        match r {
            Ok(r) => ok.push((c.base + i as u64, r)),
            Err(e) => errs.push(e),
        }
    }
    (ok, errs)
}

/// Parse and run one gate test; prints the records; exit code per `HELP`.
pub fn cli(a: Vec<String>, o: Opts, pool: Option<String>) -> Result<ExitCode, String> {
    let (fmt, a) = outfmt::extract(&a, true)?;
    let test = Test::parse(
        a.first()
            .ok_or("omapgate: TEST required (see omapgate --help)")?,
    )?;
    let mut c = Cfg::parse(test, a[1..].to_vec())?;
    c.pool = pool.ok_or("omapgate: -p POOL required")?;
    let man = match (&c.manifest_in, test) {
        (Some(p), _) => Some(Manifest::load(p)?),
        (None, Test::Scan) => {
            let prefix = c.prefix.clone().expect("validated");
            Some(Manifest {
                pool: c.pool.clone(),
                prefix: prefix.clone(),
                owned: false,
                per_client: 1,
                client_base: 0,
                total_clients: c.total,
                value_bytes: c.value_bytes,
                objects: (0..c.objects)
                    .map(|index| ManObj {
                        index,
                        name: object_name(&prefix, index),
                        live_keys: c.expect_keys.expect("validated"),
                        owners: Vec::new(),
                    })
                    .collect(),
            })
        }
        (None, _) => None,
    };
    if let Some(m) = &man {
        if m.pool != c.pool {
            return Err(format!("manifest pool '{}' != -p {}", m.pool, c.pool));
        }
        c.prefix = Some(m.prefix.clone());
        c.value_bytes = m.value_bytes;
        c.owned = m.owned;
        c.per_client = m.per_client;
    }
    let work: Vec<WorkItem> = match (test, &man) {
        (Test::Scan, Some(m)) => objects_for(&c, m).into_iter().map(WorkItem::Scan).collect(),
        (Test::DeleteObjects, Some(m)) => objects_for(&c, m)
            .into_iter()
            .map(WorkItem::Delete)
            .collect(),
        _ => plan(&c, man.as_ref())?
            .into_iter()
            .map(WorkItem::Units)
            .collect(),
    };
    let start = unix_ns();
    let (outs, errs) = gather(&o, &c, work);
    let mut all = new_stats();
    let mut objects: BTreeMap<u64, ManObj> = BTreeMap::new();
    let mut messages: Vec<String> = errs.clone();
    let mut wall_ns = 0u64;
    let mut phases: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
    for (_, r) in &outs {
        for (n, a, b) in &r.phases {
            let e = phases.entry(n).or_insert((*a, *b));
            *e = (e.0.min(*a), e.1.max(*b));
        }
        for (a, b) in all.iter_mut().zip(&r.stats) {
            a.merge(b);
        }
        wall_ns = wall_ns.max(r.wall_ns);
        messages.extend(r.messages.iter().cloned());
        for ob in &r.objects {
            merge_object(&mut objects, ob);
        }
    }
    let check_errors: u64 = all.iter().map(|s| s.errors).sum();
    let ok = errs.is_empty() && check_errors == 0;
    // scan keeps the manifest it read; the other tests record the state they leave behind
    let writes_manifest = test != Test::Scan && errs.is_empty();
    let manifest_path = c.manifest_out.clone().unwrap_or_else(|| {
        PathBuf::from(format!(
            "{}.{}.manifest.json",
            c.prefix.as_deref().unwrap_or("oprobe"),
            test.name()
        ))
    });
    if writes_manifest {
        let m = Manifest {
            pool: c.pool.clone(),
            prefix: c.prefix.clone().unwrap_or_default(),
            owned: c.owned,
            per_client: c.per_client,
            client_base: c.base,
            total_clients: c.total,
            value_bytes: c.value_bytes,
            objects: objects.values().cloned().collect(),
        };
        let text = serde_json::to_string_pretty(&m.to_json()).expect("json") + "\n";
        std::fs::write(&manifest_path, text)
            .map_err(|e| format!("{}: {e}", manifest_path.display()))?;
    }
    messages.truncate(MAX_ERROR_DETAILS);
    let used = |s: &Stats| s.ops != 0 || s.errors != 0;
    let mut rows: Vec<Value> = KINDS
        .iter()
        .zip(&all)
        .filter(|(_, s)| used(s))
        .map(|(k, s)| op_record(test, *k, s))
        .collect();
    for (client, r) in &outs {
        rows.extend(
            KINDS
                .iter()
                .zip(&r.stats)
                .filter(|(_, s)| used(s))
                .map(|(k, s)| {
                    let mut j = op_record(test, *k, s);
                    j["record"] = json!("client_op");
                    j["client"] = json!(client);
                    j
                }),
        );
    }
    let mut phase_rows: Vec<_> = phases.iter().collect();
    phase_rows.sort_by_key(|(_, (a, _))| *a);
    for (n, (a, b)) in phase_rows {
        rows.push(
            json!({"schema":SCHEMA,"record":"phase","test":test.name(),"phase":n,
            "start_unix_ns":a,"end_unix_ns":b,"duration_s":(b - a) as f64 / 1e9}),
        );
    }
    rows.push(
        json!({"schema":SCHEMA,"record":"summary","test":test.name(),"ok":ok,"pool":c.pool,
        "tool":"oprobe","version":crate::VERSION,"command":std::env::args().collect::<Vec<_>>(),
        "params":params(&c),
        "layout":if c.owned {"owned"} else {"shared"},"clients":c.clients,"client_base":c.base,
        "qd":c.qd,"object_inflight":c.object_inflight,"objects":objects.len(),
        "keys_per_op":c.keys_per_op,"value_bytes":c.value_bytes,"wall_s":wall_ns as f64 / 1e9,
        "wall_ns":wall_ns,
        "kinds":KINDS.iter().zip(&all).filter(|(_, s)| used(s)).map(|(k, s)|
            (k.name().to_string(), json!({"ops":s.ops,"keys":s.keys,"lat_sum_ns":s.sum_ns,
                "lat_mean_ns":mean_ns(s)}))).collect::<serde_json::Map<_, _>>(),
        "start_unix_ns":start,
        "end_unix_ns":unix_ns(),
        "ops":all.iter().map(|s| s.ops).sum::<u64>(),"keys":all.iter().map(|s| s.keys).sum::<u64>(),
        "errors":check_errors + errs.len() as u64,"error_details_max":MAX_ERROR_DETAILS,
        "live_keys":objects.values().map(|o| o.live_keys).sum::<u64>(),
        "manifest":writes_manifest.then(|| manifest_path.display().to_string()),
        "messages":messages}),
    );
    if fmt == outfmt::Format::Plain {
        for r in &rows {
            println!("{}", plain(r));
        }
    } else {
        // a zero-row stream is zero bytes: an empty line is not a JSON record
        let out = fmt.records(&rows);
        if !out.is_empty() {
            println!("{out}");
        }
    }
    Ok(if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// Scope of a mix op count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OpScope {
    /// Total ops of one client, split over its objects.
    Client(u64),
    /// Ops on each object of each client.
    Object(u64),
}

/// Ops of op type `ki` (of `nk`) on object `ui` (of `units`) of one client; unbounded without a count.
fn op_quota(ops: Option<OpScope>, nk: u64, ki: u64, ui: u64, units: u64) -> u64 {
    let per_type = |n: u64| n / nk + u64::from(ki < n % nk);
    match ops {
        None => u64::MAX,
        Some(OpScope::Client(n)) => interval(per_type(n), ui, units),
        Some(OpScope::Object(n)) => per_type(n),
    }
}

/// Every effective parameter of the run (after manifest overrides).
fn params(c: &Cfg) -> Value {
    json!({"test":c.test.name(),"pool":c.pool,"prefix":c.prefix,
        "layout":if c.owned {"owned"} else {"shared"},"objects":c.objects,
        "objects_per_client":c.per_client,"clients":c.clients,"client_base":c.base,
        "total_clients":c.total,"qd":c.qd,"object_inflight":c.object_inflight,
        "keys_per_object":c.keys,"keys_per_op":c.keys_per_op,"insert_keys":c.insert_keys,
        "delete_fraction":c.delete_fraction,"passes":c.passes,"value_bytes":c.value_bytes,
        "ops_per_client":match c.ops { Some(OpScope::Client(n)) => Some(n), _ => None },
        "ops_per_object":match c.ops { Some(OpScope::Object(n)) => Some(n), _ => None },
        "ops_scope":match c.ops { Some(OpScope::Client(_)) => "client", Some(OpScope::Object(_)) => "object", None => "duration" },"duration_s":c.duration.map(|d| d.as_secs()),
        "manifest_in":c.manifest_in.as_ref().map(|p| p.display().to_string()),
        "expect_keys":c.expect_keys,"scan_page":c.scan_page,"delete_per_client":c.delete_per_client,
        "seed":c.seed,"start_at":c.start_at,"max_seconds":c.max_seconds})
}

fn op_record(test: Test, k: Kind, s: &Stats) -> Value {
    let w = s.wall.max(1e-9);
    let h = &s.hist;
    json!({"schema":SCHEMA,"record":"op","test":test.name(),"kind":k.name(),"ops":s.ops,"keys":s.keys,
        "bytes":s.bytes,"errors":s.errors,"wall_s":s.wall,
        "lat_sum_ns":s.sum_ns,"lat_mean_ns":mean_ns(s),
        "ops_per_s":s.ops as f64 / w,"keys_per_s":s.keys as f64 / w,
        "hist_us":h.buckets().iter().map(|(u, n)| json!([u, n])).collect::<Vec<_>>(),
        "lat_us":{"p50":h.pct(0.5),"p90":h.pct(0.9),"p99":h.pct(0.99),"p99.9":h.pct(0.999),
            "max":h.max,"avg":mean_ns(s) / 1000.0}})
}

/// Mean op latency in ns (0 without ops).
fn mean_ns(s: &Stats) -> f64 {
    if s.ops == 0 {
        0.0
    } else {
        s.sum_ns as f64 / s.ops as f64
    }
}

fn plain(r: &Value) -> String {
    if r["record"] == "summary" {
        format!(
            "summary {} ok={} wall={:.2}s ops={} keys={} errors={} live_keys={} manifest={} {}",
            r["test"].as_str().unwrap_or(""),
            r["ok"],
            r["wall_s"].as_f64().unwrap_or(0.0),
            r["ops"],
            r["keys"],
            r["errors"],
            r["live_keys"],
            r["manifest"],
            r["messages"]
        )
    } else {
        let l = &r["lat_us"];
        let who = if r["record"] == "client_op" {
            format!("client {} ", r["client"])
        } else {
            String::new()
        };
        format!(
            "{who}{:<13} ops={} keys={} errors={} {:.0} ops/s {:.0} keys/s lat_us p50={} p90={} p99={} p99.9={} max={} avg={:.0} lat_sum_ns={}",
            r["kind"].as_str().unwrap_or(""),
            r["ops"],
            r["keys"],
            r["errors"],
            r["ops_per_s"].as_f64().unwrap_or(0.0),
            r["keys_per_s"].as_f64().unwrap_or(0.0),
            l["p50"],
            l["p90"],
            l["p99"],
            l["p99.9"],
            l["max"],
            l["avg"].as_f64().unwrap_or(0.0),
            r["lat_sum_ns"]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(test: &str, extra: &[&str]) -> Cfg {
        let mut a: Vec<String> = vec!["--prefix".into(), "t".into()];
        a.extend(extra.iter().map(|s| s.to_string()));
        Cfg::parse(Test::parse(test).unwrap(), a).unwrap()
    }

    #[test]
    fn overflowing_client_range_is_a_usage_error() {
        for explicit_total in [false, true] {
            let mut args = vec![
                "--prefix",
                "t",
                "--client-base",
                "18446744073709551615",
                "--clients",
                "1",
            ];
            if explicit_total {
                args.extend(["--total-clients", "1"]);
            }
            let error =
                Cfg::parse(Test::Insert, args.into_iter().map(String::from).collect()).unwrap_err();
            assert!(error.contains("overflows"), "{error}");
        }
    }

    #[test]
    fn keys_are_64_lowercase_hex_and_sorted_by_id() {
        let k = key_bytes(key_id(3, 0xabc));
        assert_eq!(k.len(), 64);
        assert!(
            k.iter()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
        );
        assert!(key_bytes(key_id(1, 5)) < key_bytes(key_id(1, 6)));
        assert!(key_bytes(key_id(1, (1 << 40) - 1)) < key_bytes(key_id(2, 0)));
    }

    #[test]
    fn interval_splits_exactly() {
        assert_eq!(
            (0..8).map(|i| interval(4_194_304, i, 8)).sum::<u64>(),
            4_194_304
        );
        assert_eq!(
            (0..3).map(|i| interval(10, i, 3)).collect::<Vec<_>>(),
            vec![3, 3, 4]
        );
    }

    #[test]
    fn shared_prefill_ops_are_whole_batches() {
        let c = cfg(
            "prefill",
            &[
                "--clients",
                "3",
                "--total-clients",
                "3",
                "--keys",
                "1048576",
                "--keys-per-op",
                "64",
            ],
        );
        let units = plan(&c, None).unwrap();
        let quota: Vec<u64> = units.iter().flatten().map(|u| u.quota).collect();
        assert_eq!(quota.iter().sum::<u64>(), 1_048_576);
        assert_eq!(quota.iter().map(|q| q.div_ceil(64)).sum::<u64>(), 16_384);
    }

    #[test]
    fn shared_insert_with_non_divisible_total_writes_whole_batches() {
        let c = cfg(
            "insert",
            &[
                "--clients",
                "7",
                "--total-clients",
                "7",
                "--keys",
                "1000003",
                "--keys-per-op",
                "64",
            ],
        );
        let units = plan(&c, None).unwrap();
        let mut ids = BTreeSet::new();
        let mut ops = 0;
        let mut total = 0;
        for cl in &units {
            assert_eq!(cl.len(), 1);
            let u = &cl[0];
            ops += u.quota.div_ceil(64);
            total += u.quota;
            for l in 0..u.quota {
                assert!(ids.insert(key_id(u.rank, l)), "duplicate key id");
            }
        }
        assert_eq!(ops, 1_000_003u64.div_ceil(64));
        assert_eq!(total, 1_000_003);
    }

    #[test]
    fn shared_insert_key_ownership_is_disjoint_and_complete() {
        let c = cfg("insert", &["--clients", "8", "--keys", "1000"]);
        let units = plan(&c, None).unwrap();
        let mut ids = BTreeSet::new();
        let mut total = 0;
        for (i, cl) in units.iter().enumerate() {
            assert_eq!(cl.len(), 1);
            let u = &cl[0];
            assert_eq!(u.rank, i as u64);
            total += u.quota;
            for l in 0..u.quota {
                assert!(ids.insert(key_id(u.rank, l)), "duplicate key id");
            }
        }
        assert_eq!(total, 1000);
    }

    #[test]
    fn owned_layout_assigns_objects_by_client() {
        let c = cfg(
            "insert",
            &[
                "--layout",
                "owned",
                "--clients",
                "4",
                "--objects-per-client",
                "8",
                "--client-base",
                "4",
                "--total-clients",
                "8",
            ],
        );
        let units = plan(&c, None).unwrap();
        let all: Vec<u64> = units.iter().flatten().map(|u| u.index).collect();
        assert_eq!(all, (32..64).collect::<Vec<_>>());
        assert_eq!(
            units[1].iter().map(|u| u.index).collect::<Vec<_>>(),
            (40..48).collect::<Vec<_>>()
        );
        assert!(
            units
                .iter()
                .flatten()
                .all(|u| u.rank == 0 && u.quota == 1 << 20)
        );
        assert_eq!(units[0][0].name, "t-o00032");
    }

    /// Run the fill accounting of every client (no I/O) and merge like `cli` does.
    fn simulate_fill(c: &Cfg) -> Vec<ManObj> {
        let mut merged = BTreeMap::new();
        for (client, units) in plan(c, None).unwrap().into_iter().enumerate() {
            let mut states: Vec<UnitState> = units
                .into_iter()
                .map(|u| UnitState::new(c, u, client as u64))
                .collect();
            for s in &mut states {
                while let Some(b) = s.build(c, Kind::Insert) {
                    s.complete(&b);
                }
            }
            for ob in object_summary(c, &states) {
                merge_object(&mut merged, &ob);
            }
        }
        merged.into_values().collect()
    }

    #[test]
    fn fill_blocks_sum_to_keys_per_object() {
        let owned = [
            "--layout",
            "owned",
            "--clients",
            "2",
            "--objects-per-client",
            "3",
            "--keys",
            "4096",
            "--total-clients",
            "2",
        ];
        for (test, extra, ranks) in [
            (
                "prefill",
                vec!["--total-clients", "2", "--keys", "16384", "--objects", "3"],
                2,
            ),
            (
                "prefill",
                vec!["--total-clients", "8", "--keys", "1000", "--clients", "3"],
                8,
            ),
            ("insert", vec!["--clients", "8", "--keys", "1000"], 8),
            ("insert", owned.to_vec(), 1),
            ("prefill", owned.to_vec(), 1),
        ] {
            let c = cfg(test, &extra);
            let objs = simulate_fill(&c);
            assert!(!objs.is_empty());
            for o in &objs {
                let blocks: Vec<u64> = o
                    .owners
                    .iter()
                    .map(|b| b.as_ref().unwrap().live_n)
                    .collect();
                assert_eq!(blocks.len(), ranks, "{test} {extra:?}");
                assert_eq!(
                    blocks.iter().sum::<u64>(),
                    c.keys,
                    "{test} {extra:?} {}",
                    o.name
                );
                assert_eq!(o.live_keys, c.keys);
                for (r, n) in blocks.iter().enumerate() {
                    assert_eq!(
                        *n,
                        if c.owned {
                            c.keys
                        } else {
                            // shared: whole `keys_per_op` batches per owner, not a per-key split
                            share_batches(c.keys, r as u64, c.total, c.keys_per_op)
                        }
                    );
                }
                if !c.owned {
                    assert_eq!(
                        blocks
                            .iter()
                            .map(|n| n.div_ceil(c.keys_per_op))
                            .sum::<u64>(),
                        c.keys.div_ceil(c.keys_per_op),
                        "{test} {extra:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn mix_plan_from_fill_manifest_matches_written_keys() {
        let c = cfg("prefill", &["--total-clients", "2", "--keys", "16384"]);
        let objs = simulate_fill(&c);
        let m = Manifest {
            pool: "p".into(),
            prefix: "t".into(),
            owned: false,
            per_client: 1,
            client_base: 0,
            total_clients: 2,
            value_bytes: 256,
            objects: objs,
        };
        let mc = cfg(
            "mix-delete",
            &[
                "--clients",
                "2",
                "--ops-per-client",
                "256",
                "--manifest",
                "x",
            ],
        );
        let units = plan(&mc, Some(&m)).unwrap();
        assert_eq!(units[0][0].live.len() + units[1][0].live.len(), 16384);
        assert_eq!(units[0][0].live.len(), 8192);
        // gaps: grid ids, key 1 of owner 1 sits one stride above its block base
        assert_eq!(units[1][0].live[1].0, key_id(1, ID_STRIDE));
    }

    #[test]
    fn prefill_single_session_fills_all_ranks_like_insert() {
        let p = cfg("prefill", &["--total-clients", "8", "--keys", "1048576"]);
        let units = plan(&p, None).unwrap();
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].len(), 8);
        let i = cfg("insert", &["--clients", "8", "--keys", "1048576"]);
        let want: Vec<u64> = plan(&i, None).unwrap().iter().map(|c| c[0].quota).collect();
        assert_eq!(units[0].iter().map(|u| u.quota).collect::<Vec<_>>(), want);
    }

    fn grid(n: u64, rank: u64) -> Vec<u64> {
        (0..n).map(|i| key_id(rank, i * ID_STRIDE)).collect()
    }

    /// Mix state with `initial` consecutive local ids `0..initial` live (no gaps).
    fn state(initial: u64, rank: u64) -> UnitState {
        let c = cfg("mix-range", &["--ops-per-client", "4", "--manifest", "x"]);
        state_with(&c, (0..initial).map(|l| key_id(rank, l)).collect(), rank)
    }

    fn state_with(c: &Cfg, ids: Vec<u64>, rank: u64) -> UnitState {
        let u = Unit {
            index: 0,
            name: "o".into(),
            rank,
            quota: 0,
            grid: false,
            live: ids.into_iter().map(|k| (k, 0)).collect(),
            dead: Vec::new(),
        };
        UnitState::new(c, u, 0)
    }

    #[test]
    fn range_run_is_contiguous_in_live_set_and_own_block() {
        let mut s = state(2000, 3);
        // punch holes so runs are contiguous in the live set but not in the id space
        for l in (100..200).step_by(2) {
            s.live.remove(&key_id(3, l));
        }
        for _ in 0..4 {
            let run = s.take_run(256).unwrap();
            assert_eq!(run.len(), 256);
            let (f, l) = (run[0].0, run[255].0);
            assert!(f >= key_id(3, 0) && l < key_id(4, 0));
            assert!(run.windows(2).all(|w| w[0].0 < w[1].0));
            // no live key may remain inside the removed span
            assert!(s.live.range(f..=l).next().is_none());
        }
        assert_eq!(s.live.len(), 2000 - 50 - 4 * 256);
    }

    #[test]
    fn range_run_wraps_to_highest_keys_and_skips_reserved_spans() {
        let mut s = state(300, 0);
        let run = s.take_run(256).unwrap();
        assert_eq!(run.len(), 256);
        s.live = (0..300).map(|l| (key_id(0, l), 0)).collect();
        s.reserved.insert(key_id(0, 150));
        s.live.remove(&key_id(0, 150));
        // every 256-run of 299 live keys spans id 150 unless it is entirely above/below it
        assert!(s.take_run(256).is_none());
        s.reserved.clear();
        assert!(s.take_run(256).is_some());
        s.live.clear();
        assert!(s.take_run(256).is_none());
    }

    #[test]
    fn scattered_keys_are_live_distinct_and_reserved_ops_do_not_overlap() {
        let mut s = state(1000, 1);
        let a = s.take_scattered(256);
        let b = s.take_scattered(256);
        assert_eq!((a.len(), b.len()), (256, 256));
        let all: BTreeSet<u64> = a.iter().chain(&b).map(|x| x.0).collect();
        assert_eq!(all.len(), 512);
        assert!(all.iter().all(|k| (key_id(1, 0)..key_id(2, 0)).contains(k)));
        assert_eq!(s.live.len(), 488);
        assert_eq!(s.take_scattered(1000).len(), 488);
    }

    #[test]
    fn mix_ops_complete_into_live_set() {
        let c = cfg("mix-range", &["--ops-per-client", "4", "--manifest", "x"]);
        let mut s = state_with(&c, grid(600, 0), 0);
        let up = s.build(&c, Kind::Update).unwrap();
        assert_eq!(s.live.len(), 600 - 256);
        assert_eq!(s.reserved.len(), 256);
        s.complete(&up);
        assert_eq!(s.live.len(), 600);
        assert!(s.reserved.is_empty());
        assert!(s.live.values().filter(|g| **g == 1).count() == 256);
        let ins = s.build(&c, Kind::Insert).unwrap();
        assert_eq!(ins.ids.len(), 256);
        s.complete(&ins);
        assert_eq!(s.live_keys(), 856);
        let del = s.build(&c, Kind::DeleteRange).unwrap();
        s.complete(&del);
        assert_eq!(s.live_keys(), 600);
    }

    #[test]
    fn insert_quota_bounds_last_op() {
        let c = cfg("insert", &["--keys", "300"]);
        let mut s = UnitState::new(&c, plan(&c, None).unwrap()[0][0].clone(), 0);
        let (a, b) = (
            s.build(&c, Kind::Insert).unwrap(),
            s.build(&c, Kind::Insert).unwrap(),
        );
        assert_eq!((a.ids.len(), b.ids.len()), (256, 44));
        assert!(s.build(&c, Kind::Insert).is_none());
        assert_eq!(b.ids.last().unwrap().0, key_id(0, 299 * ID_STRIDE));
        assert_eq!(a.ids[1].0 - a.ids[0].0, ID_STRIDE);
    }

    #[test]
    fn scheduler_round_robin_qd_and_per_slot_limit() {
        // 8 objects x 1 type, QD 8, one outstanding per object
        let mut s = Sched::new(8, 1, vec![u64::MAX; 8]);
        let mut order = Vec::new();
        while let Some(&x) = s.candidates().first() {
            s.take(x);
            order.push(x);
        }
        assert_eq!(order, (0..8).collect::<Vec<_>>());
        assert!(s.candidates().is_empty());
        s.release(3);
        assert_eq!(s.candidates(), vec![3]);
        s.take(3);
        // 8 objects x 4 types, QD 32, limit 1: everything runs, nothing twice
        let mut s = Sched::new(32, 1, vec![u64::MAX; 32]);
        for x in s.candidates() {
            s.take(x);
        }
        assert_eq!(s.total, 32);
        assert!(s.inflight.iter().all(|&n| n == 1));
        // QD below slots: QD wins; limit above 1 on a single object
        let mut s = Sched::new(8, 8, vec![u64::MAX; 1]);
        for _ in 0..8 {
            let x = s.candidates()[0];
            s.take(x);
        }
        assert!(s.candidates().is_empty());
    }

    #[test]
    fn op_counts_scope_client_or_object() {
        let per = |o, ui| (0..4).map(|ki| op_quota(o, 4, ki, ui, 8)).sum::<u64>();
        // 131072 ops per client over 8 objects = 16384 per object; both scopes agree
        for ui in 0..8 {
            assert_eq!(per(Some(OpScope::Client(131_072)), ui), 16_384);
            assert_eq!(per(Some(OpScope::Object(16_384)), ui), 16_384);
        }
        assert_eq!(
            (0..8)
                .map(|ui| per(Some(OpScope::Client(10)), ui))
                .sum::<u64>(),
            10
        );
        assert_eq!(per(Some(OpScope::Object(6)), 3), 6);
        assert_eq!(op_quota(None, 4, 0, 0, 8), u64::MAX);
    }

    #[test]
    fn scheduler_counts_down_quotas() {
        let mut s = Sched::new(4, 4, vec![2, 1]);
        while let Some(&x) = s.candidates().first() {
            s.take(x);
        }
        assert_eq!(s.inflight, vec![2, 1]);
        assert!(s.exhausted());
    }

    #[test]
    fn manifest_round_trip_and_plan_from_it() {
        let live = |r: u64, n: u64| -> BTreeMap<u64, u32> {
            grid(n, r).into_iter().map(|k| (k, 3)).collect()
        };
        let dead: BTreeSet<u64> = [key_id(0, 5), key_id(0, 70_000)].into();
        let m = Manifest {
            pool: "p".into(),
            prefix: "pre".into(),
            owned: false,
            per_client: 1,
            client_base: 0,
            total_clients: 2,
            value_bytes: 256,
            objects: vec![
                ManObj {
                    index: 0,
                    name: "pre-o00000".into(),
                    live_keys: 10,
                    owners: vec![
                        Some(OwnerBlob::encode(0, &live(0, 6), &dead)),
                        Some(OwnerBlob::encode(1, &live(1, 4), &BTreeSet::new())),
                    ],
                },
                ManObj {
                    index: 1,
                    name: "pre-o00001".into(),
                    live_keys: 7,
                    owners: Vec::new(),
                },
            ],
        };
        let back =
            Manifest::from_json(&serde_json::from_str(&m.to_json().to_string()).unwrap()).unwrap();
        assert_eq!(back, m);
        let c = cfg(
            "mix-delete",
            &["--clients", "2", "--ops-per-client", "8", "--manifest", "x"],
        );
        // the second object has no key sets: mixing it is refused
        assert!(plan(&c, Some(&m)).is_err());
        let mut m2 = m.clone();
        m2.objects.pop();
        let units = plan(&c, Some(&m2)).unwrap();
        assert_eq!((units[0][0].rank, units[0][0].live.len()), (0, 6));
        assert_eq!((units[1][0].rank, units[1][0].live.len()), (1, 4));
        assert_eq!(units[0][0].dead, dead.iter().copied().collect::<Vec<_>>());
        assert!(units[0][0].live.iter().all(|(_, g)| *g == 3));
        assert_eq!(units[1][0].live[3].0, key_id(1, 3 * ID_STRIDE));
    }

    #[test]
    fn manifest_of_other_schema_is_refused_loudly() {
        let mut j = Manifest {
            pool: "p".into(),
            prefix: "p".into(),
            owned: true,
            per_client: 1,
            client_base: 0,
            total_clients: 1,
            value_bytes: 256,
            objects: Vec::new(),
        }
        .to_json();
        assert!(Manifest::from_json(&j).is_ok());
        j["schema"] = json!(1);
        let e = Manifest::from_json(&j).unwrap_err();
        assert!(e.contains("schema 1 not supported"), "{e}");
    }

    #[test]
    fn key_set_encoding_round_trips_edge_values() {
        let live: BTreeMap<u64, u32> = [
            (key_id(7, 0), 0),
            (key_id(7, 1), u32::MAX),
            (key_id(7, (1 << 40) - 1), 128),
        ]
        .into();
        let dead: BTreeSet<u64> = [key_id(7, 2), key_id(7, 1 << 39)].into();
        let b = OwnerBlob::encode(7, &live, &dead);
        let (l, d) = b.decode(7).unwrap();
        assert_eq!(l, live.into_iter().collect::<Vec<_>>());
        assert_eq!(d, dead.into_iter().collect::<Vec<_>>());
        assert!(decode_varints("8").is_err() && decode_varints("zz").is_err());
        assert!(decode_varints("80").is_err()); // truncated varint
        let mut bad = b.clone();
        bad.live_n += 1;
        assert!(bad.decode(7).is_err());
    }

    #[test]
    fn cli_validation() {
        let bad = |t: &str, extra: &[&str]| {
            let mut a: Vec<String> = Vec::new();
            a.extend(extra.iter().map(|s| s.to_string()));
            Cfg::parse(Test::parse(t).unwrap(), a).is_err()
        };
        assert!(bad("insert", &[])); // no prefix
        assert!(bad(
            "mix-delete",
            &["--prefix", "x", "--ops-per-client", "1"]
        )); // no manifest
        assert!(bad("mix-delete", &["--manifest", "m"])); // neither ops nor duration
        assert!(bad(
            "mix-delete",
            &[
                "--manifest",
                "m",
                "--ops-per-client",
                "1",
                "--duration",
                "2"
            ]
        ));
        assert!(bad("insert", &["--prefix", "x", "--ops-per-client", "1"]));
        assert!(bad("insert", &["--prefix", "x", "--qd", "0"]));
        assert!(bad("scan", &[]));
        assert!(bad("insert", &["--manifest", "m"])); // populated insert needs --insert-keys
        assert!(bad("insert", &["--prefix", "x", "--insert-keys", "5"])); // fresh uses --keys
        assert!(!bad("insert", &["--manifest", "m", "--insert-keys", "5"]));
        assert!(bad("prefill", &["--prefix", "x", "--manifest", "m"]));
        assert!(bad("delete", &["--manifest", "m"])); // no fraction
        for f in ["0", "1.5", "x"] {
            assert!(bad("delete", &["--manifest", "m", "--delete-fraction", f]));
        }
        assert!(!bad(
            "delete",
            &["--manifest", "m", "--delete-fraction", "0.5"]
        ));
        assert!(bad("update", &[])); // no manifest
        assert!(!bad("update", &["--manifest", "m"]));
        assert!(bad(
            "update",
            &["--manifest", "m", "--delete-fraction", "0.5"]
        ));
        assert!(bad("insert", &["--prefix", "x", "--passes", "2"]));
        assert!(bad("scan", &["--manifest", "m", "--passes", "0"]));
        assert!(!bad("scan", &["--manifest", "m", "--passes", "3"]));
        assert!(
            Cfg::parse(
                Test::Scan,
                ["--prefix", "x", "--expect-keys", "5"]
                    .map(String::from)
                    .to_vec()
            )
            .is_ok()
        );
    }

    #[test]
    fn scan_objects_follow_owner_clients() {
        let m = Manifest {
            pool: "p".into(),
            prefix: "p".into(),
            owned: true,
            per_client: 2,
            client_base: 4,
            total_clients: 8,
            value_bytes: 256,
            objects: (8..16)
                .map(|i| ManObj {
                    index: i,
                    name: format!("p-o{i:05}"),
                    live_keys: 1,
                    owners: Vec::new(),
                })
                .collect(),
        };
        let c = cfg(
            "scan",
            &[
                "--manifest",
                "x",
                "--layout",
                "owned",
                "--clients",
                "4",
                "--client-base",
                "4",
                "--total-clients",
                "8",
            ],
        );
        let per = objects_for(&c, &m);
        assert_eq!(
            per[0].iter().map(|o| o.index).collect::<Vec<_>>(),
            vec![8, 9]
        );
        assert_eq!(
            per[3].iter().map(|o| o.index).collect::<Vec<_>>(),
            vec![14, 15]
        );
    }

    fn lcg_cfg(test: &str, extra: &[&str]) -> Cfg {
        let mut a = vec!["--manifest", "x"];
        a.extend_from_slice(extra);
        let a: Vec<String> = a.into_iter().map(String::from).collect();
        Cfg::parse(Test::parse(test).unwrap(), a).unwrap()
    }

    #[test]
    fn fresh_fill_uses_stride_and_refuses_what_does_not_fit_the_block() {
        assert_eq!(MAX_GRID_KEYS * ID_STRIDE, 1 << BLOCK_BITS);
        // 8M keys of the benchmark (one owner) fit with room to spare
        const { assert!(8_388_608 <= MAX_GRID_KEYS) };
        let c = cfg("prefill", &["--total-clients", "1", "--keys", "100"]);
        let mut s = UnitState::new(&c, plan(&c, None).unwrap()[0][0].clone(), 0);
        let ids: Vec<u64> = std::iter::from_fn(|| s.build(&c, Kind::Insert))
            .flat_map(|b| b.ids.into_iter().map(|x| x.0))
            .collect();
        assert_eq!(ids.len(), 100);
        assert!(ids.windows(2).all(|w| w[1] - w[0] == ID_STRIDE));
        let max = cfg(
            "insert",
            &["--keys", &MAX_GRID_KEYS.to_string(), "--total-clients", "1"],
        );
        assert!(plan(&max, None).is_ok());
        let over = cfg(
            "insert",
            &[
                "--keys",
                &(MAX_GRID_KEYS + 1).to_string(),
                "--total-clients",
                "1",
            ],
        );
        assert!(plan(&over, None).unwrap_err().contains("exceed"));
    }

    #[test]
    fn new_keys_land_between_existing_ones_never_reuse_and_never_collide() {
        let c = lcg_cfg("insert", &["--insert-keys", "1000", "--keys-per-op", "64"]);
        let existing = grid(1000, 2);
        let mut s = state_with(&c, existing.clone(), 2);
        s.insert_left = 1000;
        // delete some, remember them as dead
        let gone: Vec<u64> = existing.iter().copied().step_by(3).collect();
        for k in &gone {
            s.live.remove(k);
            s.dead.insert(*k);
        }
        let before: BTreeSet<u64> = s.live.keys().copied().chain(gone.iter().copied()).collect();
        let (lo, hi) = (*before.first().unwrap(), *before.last().unwrap());
        let mut inflight = Vec::new();
        let mut all = BTreeSet::new();
        // several ops in flight at once, then complete: ids must never repeat
        for _ in 0..8 {
            let b = s.build(&c, Kind::Insert).unwrap();
            assert_eq!(b.ids.len(), 64);
            assert!(b.ids.windows(2).all(|w| w[0].0 < w[1].0));
            for (k, _) in &b.ids {
                assert!(all.insert(*k), "id drawn twice");
                assert!(!before.contains(k), "live or dead id re-used");
                assert!((lo..hi).contains(k), "outside the occupied range");
                assert_eq!(*k >> BLOCK_BITS, 2, "left the owner block");
            }
            inflight.push(b);
        }
        for b in &inflight {
            s.complete(b);
        }
        assert_eq!(all.len(), 512);
        assert_eq!(s.live.len(), 1000 - gone.len() + 512);
        // new ids sit between existing ones, not appended after the last
        let ex: Vec<u64> = existing.clone();
        let between = all
            .iter()
            .filter(|k| ex.windows(2).any(|w| w[0] < **k && **k < w[1]))
            .count();
        assert_eq!(between, 512);
        // the insert quota ends the stream
        let mut left = s.insert_left;
        while let Some(b) = s.build(&c, Kind::Insert) {
            left -= b.ids.len() as u64;
            s.complete(&b);
        }
        assert_eq!(left, 0);
        assert_eq!(s.live.len() as u64, 1000 - gone.len() as u64 + 1000);
    }

    #[test]
    fn inserts_avoid_in_flight_range_deletes_and_deleted_ids() {
        let c = lcg_cfg(
            "mix-range",
            &["--ops-per-client", "4", "--keys-per-op", "2"],
        );
        let mut s = state_with(&c, vec![key_id(0, 0), key_id(0, 10)], 0);
        let del = s.build(&c, Kind::DeleteRange).unwrap();
        assert_eq!(del.ids.len(), 2);
        // every id of [0, 11) is inside the range delete span: nothing may be placed
        assert!(s.build(&c, Kind::Insert).is_none());
        s.complete(&del);
        assert!(s.spans.is_empty());
        // now both ends are dead and the span is gone: the 9 ids between are free, no more
        let mut got = BTreeSet::new();
        while let Some(b) = s.build(&c, Kind::Insert) {
            for (k, _) in &b.ids {
                assert!((1..10).contains(&(*k & 0xff)), "dead end id re-used");
                got.insert(*k);
            }
            s.complete(&b);
            if got.len() >= 9 {
                break;
            }
        }
        assert!(got.len() <= 9);
    }

    #[test]
    fn delete_removes_exact_fraction_scattered_each_key_once() {
        for (n, f, want) in [
            (1000u64, "0.5", 500usize),
            (1001, "0.5", 501),
            (1000, "1", 1000),
        ] {
            let c = lcg_cfg("delete", &["--delete-fraction", f, "--keys-per-op", "64"]);
            let ids = grid(n, 1);
            let mut s = state_with(&c, ids.clone(), 1);
            let mut seen = Vec::new();
            let mut ops = 0;
            while let Some(b) = s.build(&c, Kind::Delete) {
                assert!(b.ids.len() <= 64);
                assert!(b.ids.windows(2).all(|w| w[0].0 < w[1].0));
                seen.extend(b.ids.iter().map(|x| x.0));
                s.complete(&b);
                ops += 1;
            }
            assert!(s.drained());
            assert_eq!(seen.len(), want, "n={n} f={f}");
            assert_eq!(ops, want.div_ceil(64));
            let set: BTreeSet<u64> = seen.iter().copied().collect();
            assert_eq!(set.len(), want, "a key was deleted twice");
            assert!(set.iter().all(|k| ids.contains(k)));
            assert_eq!(s.live_keys(), n - want as u64);
            assert_eq!(s.dead.len(), want);
            if want < 1000 {
                // scattered: the first op is not the first 64 keys of the owner
                let first: Vec<u64> = ids.iter().copied().take(64).collect();
                let mut s2 = state_with(&c, ids.clone(), 1);
                let b = s2.build(&c, Kind::Delete).unwrap();
                assert_ne!(b.ids.iter().map(|x| x.0).collect::<Vec<_>>(), first);
            }
        }
    }

    #[test]
    fn update_covers_every_live_key_once_with_a_new_generation() {
        let c = lcg_cfg("update", &["--keys-per-op", "64"]);
        let ids = grid(1000, 0);
        let mut s = state_with(&c, ids.clone(), 0);
        for v in s.live.values_mut() {
            *v = 4;
        }
        // restart so the generation base comes from the live set
        let u = Unit {
            index: 0,
            name: "o".into(),
            rank: 0,
            quota: 0,
            grid: false,
            live: s.live.iter().map(|(k, g)| (*k, *g)).collect(),
            dead: Vec::new(),
        };
        let mut s = UnitState::new(&c, u, 0);
        let mut seen = Vec::new();
        while let Some(b) = s.build(&c, Kind::Update) {
            assert!(b.ids.iter().all(|(_, g)| *g == 5));
            seen.extend(b.ids.iter().map(|x| x.0));
            s.complete(&b);
        }
        let mut sorted = seen.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, ids, "every key exactly once");
        assert_ne!(seen, ids, "random order");
        assert!(s.live.values().all(|g| *g == 5));
        assert_eq!(s.live_keys(), 1000);
    }

    #[test]
    fn mix_generations_continue_above_the_manifest() {
        let c = lcg_cfg("mix-delete", &["--ops-per-client", "4"]);
        let u = Unit {
            index: 0,
            name: "o".into(),
            rank: 0,
            quota: 0,
            grid: false,
            live: grid(10, 0).into_iter().map(|k| (k, 7)).collect(),
            dead: Vec::new(),
        };
        let mut s = UnitState::new(&c, u, 0);
        let b = s.build(&c, Kind::Update).unwrap();
        assert!(b.ids.iter().all(|(_, g)| *g == 8));
    }

    #[test]
    fn stats_keep_exact_per_kind_nanosecond_sums() {
        let t = Instant::now();
        let done = |ns: u64| Done {
            tag: 0,
            tid: 0,
            reply: None,
            err: String::new(),
            submitted: t,
            finished: t + Duration::from_nanos(ns),
        };
        let mut st = new_stats();
        for ns in [1_500, 2_345_678, 999] {
            st[Kind::Insert as usize].rec(&done(ns), 64, 0);
        }
        st[Kind::Update as usize].rec(&done(10), 64, 0);
        let mut all = new_stats();
        for _ in 0..2 {
            for (a, b) in all.iter_mut().zip(&st) {
                a.merge(b);
            }
        }
        let i = &all[Kind::Insert as usize];
        assert_eq!((i.ops, i.sum_ns), (6, 2 * 2_348_177));
        assert_eq!(all[Kind::Update as usize].sum_ns, 20);
        let r = op_record(Test::MixDelete, Kind::Insert, i);
        assert_eq!(r["lat_sum_ns"], 4_696_354u64);
        assert_eq!(r["ops"], 6);
        assert_eq!(r["lat_mean_ns"].as_f64().unwrap(), 4_696_354.0 / 6.0);
        assert_eq!(all[Kind::Delete as usize].ops, 0);
    }

    #[test]
    fn mix_slots_8_objects_x_4_types_qd32_run_in_parallel_and_replace_in_place() {
        let c = lcg_cfg(
            "mix-delete",
            &[
                "--ops-per-object",
                "16384",
                "--qd",
                "32",
                "--object-inflight",
                "1",
            ],
        );
        let mut states: Vec<UnitState> = (0..8)
            .map(|i| {
                let mut s = state_with(&c, grid(2000, 0), 0);
                s.unit.index = i;
                s
            })
            .collect();
        let kinds = c.test.kinds();
        let nk = kinds.len();
        let rem = (0..8 * nk)
            .map(|s| op_quota(c.ops, nk as u64, (s % nk) as u64, (s / nk) as u64, 8))
            .collect();
        let mut sched = Sched::new(32, 1, rem);
        let mut pending: Vec<(usize, Built)> = Vec::new();
        for s in sched.candidates() {
            if sched.can_take(s) {
                let b = states[s / nk].build(&c, kinds[s % nk]).unwrap();
                sched.take(s);
                pending.push((s, b));
            }
        }
        // one op of every type on every object, all at once
        assert_eq!(pending.len(), 32);
        let slots: BTreeSet<usize> = pending.iter().map(|(s, _)| *s).collect();
        assert_eq!(slots.len(), 32);
        for (s, b) in pending.drain(..) {
            states[s / nk].complete(&b);
            sched.release(s);
            // the completed slot, and only it, may start the next op of its type on its object
            assert!(sched.can_take(s));
            assert_eq!(sched.candidates().first(), Some(&s));
            sched.take(s);
            sched.release(s);
        }
        assert_eq!(sched.total, 0);
    }
}
