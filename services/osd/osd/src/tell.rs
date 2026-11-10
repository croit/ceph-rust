// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `ceph tell osd.N ...` (MCommand) and legacy MMonCommand handling (spec 9).
use crate::asok::{AsokRx, CmdResult};
use crate::backend::Backend;
use crate::config::Level;
use crate::ctrsnap::Doc;
use crate::osd::{Osd, State};
use crate::version;
use crate::xcore::XMsg;
use messages::{MCommand, MCommandReply, MMonCommand, MMonCommandAck};
use peering::PgStoreOps as _;
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;

pub(crate) const ENOENT: i32 = -2;
const EACCES: i32 = -13;
const EPERM: i32 = -1;
pub(crate) const EINVAL: i32 = -22;
pub(crate) const EIO: i32 = -5;
const ETIMEDOUT: i32 = -110;

/// `(prefix words, [(arg name, type, required, n)], help)`.
type Arg = (&'static str, &'static str, bool, bool);
struct Cmd {
    words: &'static [&'static str],
    args: &'static [Arg],
    help: &'static str,
}

const VAR: Arg = ("var", "CephString", true, false);
const OVAR: Arg = ("var", "CephString", false, false);

const CMDS: &[Cmd] = &[
    Cmd {
        words: &["config", "diff"],
        args: &[],
        help: "dump diff of current config and default config",
    },
    Cmd {
        words: &["config", "get"],
        args: &[VAR],
        help: "config get <field>: get the config value",
    },
    Cmd {
        words: &["config", "help"],
        args: &[OVAR],
        help: "get config setting schema and descriptions",
    },
    Cmd {
        words: &["config", "set"],
        args: &[VAR, ("val", "CephString", true, true)],
        help: "config set <field> <val> [<val> ...]: set a config variable",
    },
    Cmd {
        words: &["config", "show"],
        args: &[],
        help: "dump current config settings",
    },
    Cmd {
        words: &["config", "unset"],
        args: &[VAR],
        help: "config unset <field>: unset a config variable",
    },
    Cmd {
        words: &["counter", "dump"],
        args: &[],
        help: "dump all labeled and non-labeled counters and their values",
    },
    Cmd {
        words: &["counter", "schema"],
        args: &[],
        help: "dump all labeled and non-labeled counters schemas",
    },
    Cmd {
        words: &["debug_up_thru"],
        args: &[("epoch", "CephInt", true, false)],
        help: "dev hook: request up_thru >= <epoch> (MOSDAlive)",
    },
    Cmd {
        words: &["dump_blocked_ops"],
        args: &[],
        help: "show the blocked ops currently in flight",
    },
    Cmd {
        words: &["dump_blocklist"],
        args: &[],
        help: "dump blocklisted clients and times",
    },
    Cmd {
        words: &["dump_historic_ops"],
        args: &[],
        help: "show recent ops",
    },
    Cmd {
        words: &["dump_historic_ops_by_duration"],
        args: &[],
        help: "show slowest recent ops, sorted by duration (longest first)",
    },
    Cmd {
        words: &["dump_historic_slow_ops"],
        args: &[],
        help: "show slowest recent ops",
    },
    Cmd {
        words: &["dump_ops_in_flight"],
        args: &[],
        help: "show the ops currently in flight",
    },
    Cmd {
        words: &["dump_osd_network"],
        args: &[("value", "CephInt", false, false)],
        help: "Dump osd heartbeat network ping times",
    },
    Cmd {
        words: &["dump_pgs"],
        args: &[],
        help: "dev: dump PG machine state of every hosted PG",
    },
    Cmd {
        words: &["dump_scrubs"],
        args: &[],
        help: "print scheduled scrubs",
    },
    Cmd {
        words: &["dump_watchers"],
        args: &[],
        help: "show clients which have active watches, and on which objects",
    },
    Cmd {
        words: &["flush_pg_stats"],
        args: &[],
        help: "flush pg stats",
    },
    Cmd {
        words: &["get_command_descriptions"],
        args: &[],
        help: "list available commands",
    },
    Cmd {
        words: &["get_latest_osdmap"],
        args: &[],
        help: "force osd to update the latest map from the mon",
    },
    Cmd {
        words: &["git_version"],
        args: &[],
        help: "show git commit sha1",
    },
    Cmd {
        words: &["help"],
        args: &[],
        help: "list available commands",
    },
    Cmd {
        words: &["injectargs"],
        args: &[("injected_args", "CephString", true, true)],
        help: "inject configuration arguments into running daemon",
    },
    Cmd {
        words: &["list_devices"],
        args: &[],
        help: "list OSD devices.",
    },
    Cmd {
        words: &["scrub"],
        args: &[("pgid", "CephPgid", false, false)],
        help: "Trigger a scrub (of one PG, or of every PG this OSD is primary for)",
    },
    Cmd {
        words: &["deep-scrub"],
        args: &[("pgid", "CephPgid", false, false)],
        help: "Trigger a deep scrub (of one PG, or of every PG this OSD is primary for)",
    },
    Cmd {
        words: &["repair"],
        args: &[("pgid", "CephPgid", false, false)],
        help: "Trigger a deep scrub that repairs (of one PG, or of every PG this OSD is primary for)",
    },
    Cmd {
        words: &["ops"],
        args: &[],
        help: "show the ops currently in flight",
    },
    Cmd {
        words: &["objecter_requests"],
        args: &[],
        help: "show in-progress Objecter requests",
    },
    Cmd {
        words: &["pg"],
        args: &[
            ("pgid", "CephPgid", true, false),
            ("cmd", "CephChoices:query", true, false),
        ],
        help: "show details of a specific pg",
    },
    Cmd {
        words: &["pg"],
        args: &[
            ("pgid", "CephPgid", true, false),
            ("cmd", "CephChoices:log", true, false),
        ],
        help: "dump pg_log of a specific pg",
    },
    Cmd {
        words: &["log"],
        args: &[],
        help: "dump pg_log of a specific pg",
    },
    Cmd {
        words: &["pg"],
        args: &[
            ("pgid", "CephPgid", true, false),
            ("cmd", "CephChoices:list_unfound", true, false),
            ("offset", "CephString", false, false),
        ],
        help: "list unfound objects on this pg, perhaps starting at an offset given in JSON",
    },
    Cmd {
        words: &["log", "flush"],
        args: &[],
        help: "flush log entries to log file",
    },
    Cmd {
        words: &["log", "reopen"],
        args: &[],
        help: "reopen log file",
    },
    Cmd {
        words: &["perf", "histogram", "dump"],
        args: &[
            ("logger", "CephString", false, false),
            ("counter", "CephString", false, false),
        ],
        help: "dump perf histogram values",
    },
    Cmd {
        words: &["perf", "histogram", "schema"],
        args: &[],
        help: "dump perf histogram schema",
    },
    Cmd {
        words: &["perf", "dump"],
        args: &[
            ("logger", "CephString", false, false),
            ("counter", "CephString", false, false),
        ],
        help: "dump perfcounters value",
    },
    Cmd {
        words: &["perf", "reset"],
        args: &[("var", "CephString", true, false)],
        help: "perf reset <name>: perf reset all or one perfcounter name",
    },
    Cmd {
        words: &["perf", "schema"],
        args: &[],
        help: "dump perfcounters schema",
    },
    #[cfg(feature = "lab")]
    Cmd {
        words: &["lab_panic"],
        args: &[],
        help: "LAB: panic this core (crash dump test)",
    },
    #[cfg(feature = "lab")]
    Cmd {
        words: &["lab_ec_corrupt"],
        args: &[
            ("pgid", "CephString", true, false),
            ("oid", "CephString", true, false),
            ("off", "CephInt", false, false),
        ],
        help: "LAB: flip one byte of an object of an EC shard PG in the store (pgid like 86.5s0)",
    },
    #[cfg(feature = "lab")]
    Cmd {
        words: &["lab_stall"],
        args: &[("ms", "CephInt", true, false)],
        help: "LAB: hold back store completions for <ms> (slow op test)",
    },
    Cmd {
        words: &["send_beacon"],
        args: &[],
        help: "send OSD beacon to mon immediately",
    },
    Cmd {
        words: &["smart"],
        args: &[("devid", "CephString", false, false)],
        help: "probe OSD devices for SMART data.",
    },
    Cmd {
        words: &["pg"],
        args: &[
            ("pgid", "CephPgid", true, false),
            ("cmd", "CephChoices:mark_unfound_lost", true, false),
            ("mulcmd", "CephChoices:revert|delete", true, false),
        ],
        help: "mark all unfound objects in this pg as lost, either removing or reverting to a prior version if one is available",
    },
    Cmd {
        words: &["scrub-abort"],
        args: &[("pgid", "CephPgid", true, false)],
        help: "Abort a running scrub of a pg and drop the pending request",
    },
    Cmd {
        words: &["scrubdebug"],
        args: &[
            ("pgid", "CephPgid", true, false),
            (
                "opcode",
                "CephChoices:set|unset|status|block|unblock",
                true,
                false,
            ),
            ("value", "CephString", false, false),
        ],
        help: "debug the scrubber (only 'status' is supported)",
    },
    Cmd {
        words: &["schedule-scrub"],
        args: &[("pgid", "CephPgid", true, false)],
        help: "Schedule a scrub of a pg now (dev/tests)",
    },
    Cmd {
        words: &["schedule-deep-scrub"],
        args: &[("pgid", "CephPgid", true, false)],
        help: "Schedule a deep scrub of a pg now (dev/tests)",
    },
    Cmd {
        words: &["bench"],
        args: &[
            ("count", "CephInt", false, false),
            ("size", "CephInt", false, false),
            ("object_size", "CephInt", false, false),
            ("object_num", "CephInt", false, false),
        ],
        help: "OSD benchmark: write <count> bytes in <size>-byte durable writes (default count=1GB size=4MB)",
    },
    Cmd {
        words: &["cache", "drop"],
        args: &[],
        help: "Drop all OSD caches (nothing to drop in croit-flashstore-osd: no-op)",
    },
    Cmd {
        words: &["cache", "status"],
        args: &[],
        help: "Get OSD caches statistics",
    },
    Cmd {
        words: &["rdma", "status"],
        args: &[],
        help: "RDMA transport status per device and core: sessions, granted credits, held slots, counters (--format plain|json|json-pretty)",
    },
    #[cfg(feature = "rdma-fault")]
    Cmd {
        words: &["rdma", "fault", "qp-err"],
        args: &[("count", "CephInt", false, false)],
        help: "TEST ONLY (feature rdma-fault): force the QP of one connection per count into ERR (RDMA fault campaign)",
    },
    #[cfg(feature = "rdma-fault")]
    Cmd {
        words: &["rdma", "fault", "write-qp-err"],
        args: &[("count", "CephInt", false, false)],
        help: "TEST ONLY: set the next accepted WRITE's QP to ERR; count=0 queries pending, triggered and failed transitions",
    },
    Cmd {
        words: &["cluster_log"],
        args: &[
            ("level", "CephChoices:error|warning|info|debug", true, false),
            ("message", "CephString", true, true),
        ],
        help: "log a message to the cluster log",
    },
    Cmd {
        words: &["compact"],
        args: &[],
        help: "compact object store's omap (no LSM in croit-flashstore-osd: no-op)",
    },
    Cmd {
        words: &["flush_journal"],
        args: &[],
        help: "flush the journal to permanent store (forces a checkpoint)",
    },
    Cmd {
        words: &["flush_store_cache"],
        args: &[],
        help: "Flush the store caches (alias of cache drop)",
    },
    Cmd {
        words: &["dump_blocked_ops_count"],
        args: &[],
        help: "show the count of blocked ops currently in flight",
    },
    Cmd {
        words: &["dump_op_pq_state"],
        args: &[],
        help: "dump op queue state",
    },
    Cmd {
        words: &["dump_pgstate_history"],
        args: &[],
        help: "show recent state history of the pgs",
    },
    Cmd {
        words: &["dump_recovery_reservations"],
        args: &[],
        help: "show recovery reservations",
    },
    Cmd {
        words: &["dump_scrub_reservations"],
        args: &[],
        help: "print scrub reservations",
    },
    Cmd {
        words: &["get_mapped_pools"],
        args: &[],
        help: "dump pools whose PG(s) are mapped to this OSD.",
    },
    Cmd {
        words: &["dump_pool_statfs"],
        args: &[("poolid", "CephInt", true, false)],
        help: "Dump store's statistics for the given pool",
    },
    Cmd {
        words: &["dump_osd_pg_stats"],
        args: &[],
        help: "Dump OSD PGs' statistics",
    },
    Cmd {
        words: &["dump_mempools"],
        args: &[],
        help: "get mempool stats (only the pools croit-flashstore-osd has, measured bytes; classic JSON shape)",
    },
    Cmd {
        words: &["heap"],
        args: &[
            (
                "heapcmd",
                "CephChoices:dump|start_profiler|stop_profiler|release|get_release_rate|set_release_rate|stats",
                true,
                false,
            ),
            ("value", "CephString", false, false),
        ],
        help: "show heap usage info (available only if compiled with tcmalloc: refused)",
    },
    Cmd {
        words: &["cpu_profiler"],
        args: &[("arg", "CephChoices:status|flush", true, false)],
        help: "run cpu profiling on daemon",
    },
    Cmd {
        words: &["dump_pg_recovery_stats"],
        args: &[],
        help: "dump pg recovery statistics",
    },
    Cmd {
        words: &["reset_pg_recovery_stats"],
        args: &[],
        help: "reset pg recovery statistics",
    },
    Cmd {
        words: &["scrub_purged_snaps"],
        args: &[],
        help: "Scrub purged_snaps vs snapmapper index",
    },
    Cmd {
        words: &["dump_objectstore_kv_stats"],
        args: &[],
        help: "print statistics of kvdb which used by bluestore",
    },
    Cmd {
        words: &["calc_objectstore_db_histogram"],
        args: &[],
        help: "Generate key value histogram of kvdb(rocksdb) which used by bluestore",
    },
    Cmd {
        words: &["get_heap_property"],
        args: &[("property", "CephString", true, false)],
        help: "get malloc extension heap property",
    },
    Cmd {
        words: &["set_heap_property"],
        args: &[
            ("property", "CephString", true, false),
            ("value", "CephInt", true, false),
        ],
        help: "update malloc extension heap property",
    },
    Cmd {
        words: &["log", "dump"],
        args: &[],
        help: "dump recent log entries to log file (lines are written live: no-op)",
    },
    Cmd {
        words: &["trim", "stale", "osdmaps"],
        args: &[],
        help: "cleanup any existing osdmap from the store in the range of 0 up to the superblock's oldest_map",
    },
    Cmd {
        words: &["store", "census"],
        args: &[("request", "CephBool", false, false)],
        help: "extent census of the last complete idle sweep (objects, records, plain blocks, compressed chunks, windows, cut chunks) and idle recompaction counters; request=true walks every collection in the next idle sweep (census_seq grows by one per store shard)",
    },
    Cmd {
        words: &["store", "free"],
        args: &[("extents", "CephBool", false, false)],
        help: "free space of the data allocator: bytes, runs, largest run, fragmentation; extents=true adds the run list (alias: bluestore allocator ...)",
    },
    Cmd {
        words: &["bluestore", "allocator", "dump"],
        args: &[("name", "CephString", true, false)],
        help: "dump allocator free regions",
    },
    Cmd {
        words: &["bluestore", "allocator", "score"],
        args: &[("name", "CephString", true, false)],
        help: "give score on allocator fragmentation (0-no fragmentation, 1-absolute fragmentation)",
    },
    Cmd {
        words: &["bluestore", "allocator", "fragmentation"],
        args: &[("name", "CephString", true, false)],
        help: "give allocator fragmentation (0-no fragmentation, 1-absolute fragmentation)",
    },
    Cmd {
        words: &["bluestore", "dedup", "stats"],
        args: &[("pool", "CephInt", true, false)],
        help: "dedup info records of a pool: estimated bytes and entries",
    },
    Cmd {
        words: &["bluestore", "dedup", "clear"],
        args: &[("pool", "CephInt", true, false)],
        help: "remove the dedup info records of a pool",
    },
    Cmd {
        words: &["bluestore", "dedup", "list"],
        args: &[
            ("pool", "CephInt", true, false),
            ("shard", "CephInt", false, false),
            ("shard_bits", "CephInt", false, false),
            ("after", "CephString", false, false),
            ("max", "CephInt", false, false),
            ("newer_than", "CephInt", false, false),
            ("prune_older_than", "CephInt", false, false),
            ("max_duration", "CephFloat", false, false),
        ],
        help: "list dedup info records of a digest shard of a pool (debugging view of the OSD listing request)",
    },
    Cmd {
        words: &["bluestore", "bluefs-bdev-expand"],
        args: &[],
        help: "grown device: refused online, use `croit-flashstore-tool expand` offline",
    },
    Cmd {
        words: &["debug", "dump_missing"],
        args: &[("filename", "CephFilepath", false, false)],
        help: "dump missing objects of every PG (croit-flashstore-osd answers inline; the filename is ignored like classic)",
    },
    Cmd {
        words: &["debug", "kick_recovery_wq"],
        args: &[("delay", "CephInt", true, false)],
        help: "set osd_recovery_delay_start to <val> (croit-flashstore-osd never delays recovery: only 0 is accepted)",
    },
    Cmd {
        words: &["set_recovery_delay"],
        args: &[("utime", "CephInt", false, false)],
        help: "Delay osd recovery by specified seconds (croit-flashstore-osd never delays recovery: only 0 is accepted)",
    },
    Cmd {
        words: &["reset_purged_snaps_last"],
        args: &[],
        help: "Reset the superblock's purged_snaps_last",
    },
    Cmd {
        words: &["clear_shards_repaired"],
        args: &[("count", "CephInt", false, false)],
        help: "clear num_shards_repaired to clear health warning",
    },
    Cmd {
        words: &["rotate-stored-key"],
        args: &[],
        help: "replace the stored cephx key (key in the input blob, `ceph tell -i FILE`)",
    },
    Cmd {
        words: &["rotate-key"],
        args: &[],
        help: "rotate live authentication key (key in the input blob, `ceph tell -i FILE`)",
    },
    Cmd {
        words: &["wipe-rotating-secrets"],
        args: &[],
        help: "wipe rotating secrets",
    },
    Cmd {
        words: &["perfcounters_dump"],
        args: &[],
        help: "dump perfcounters value (legacy name of perf dump)",
    },
    Cmd {
        words: &["perfcounters_schema"],
        args: &[],
        help: "dump perfcounters schema (legacy name of perf schema)",
    },
    Cmd {
        words: &["status"],
        args: &[],
        help: "high-level status of OSD",
    },
    Cmd {
        words: &["dump_op_traces"],
        args: &[("last", "CephInt", false, false)],
        help: "dump sampled per-op stage traces (flashstore_trace_sample); --format plain|json|json-pretty|jsonl, last N ops",
    },
    Cmd {
        words: &["trace_summary"],
        args: &[],
        help: "p50/p99/p999/max per stage segment of the sampled op traces",
    },
    Cmd {
        words: &["trace_reset"],
        args: &[],
        help: "clear the sampled op trace rings",
    },
    Cmd {
        words: &["version"],
        args: &[],
        help: "get ceph version",
    },
];

fn descriptions(store: crate::storeid::StoreIdentity) -> Value {
    let mut m = serde_json::Map::new();
    for (i, c) in CMDS.iter().enumerate() {
        let mut sig: Vec<Value> = store
            .external_words(c.words)
            .iter()
            .map(|w| json!(w))
            .collect();
        for (name, ty, req, n) in c.args {
            let mut o = serde_json::Map::new();
            o.insert("name".into(), json!(name));
            if let Some(ch) = ty.strip_prefix("CephChoices:") {
                o.insert("strings".into(), json!(ch));
                o.insert("type".into(), json!("CephChoices"));
            } else {
                o.insert("type".into(), json!(ty));
            }
            if !req {
                o.insert("req".into(), json!(false));
            }
            if *n {
                o.insert("n".into(), json!("N"));
            }
            sig.push(Value::Object(o));
        }
        m.insert(
            format!("cmd{i:03}"),
            json!({"sig": sig, "help": store.help(c.help)}),
        );
    }
    Value::Object(m)
}

fn interval_str(s: &std::collections::BTreeMap<u32, u32>) -> String {
    let v: Vec<String> = s.iter().map(|(a, l)| format!("{a}~{l}")).collect();
    format!("[{}]", v.join(","))
}

pub(crate) fn str_list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a
            .iter()
            .map(|x| x.as_str().map_or_else(|| x.to_string(), ToOwned::to_owned))
            .collect(),
        Some(Value::String(s)) => vec![s.clone()],
        Some(x) if !x.is_null() => vec![x.to_string()],
        _ => Vec::new(),
    }
}

/// Where the answer of a command goes.
#[derive(Clone, Debug)]
pub(crate) enum ReplyTo {
    /// `ceph tell` (MCommand) on `link`.
    Tell { link: u64, tid: u64, compact: bool },
    /// Legacy MMonCommand on `link` (the request echoes in the ack).
    Legacy {
        link: u64,
        tid: u64,
        cmd: Vec<String>,
        compact: bool,
    },
    /// Admin socket request (token of [`CmdState::pending`]).
    Asok(u64),
    /// Dedup listing request (MOSDDedupList) on `link`: the merged `bluestore dedup list` answer becomes the reply;
    /// `now_ns` = the OSD wall clock at the request.
    DedupList { link: u64, tid: u64, now_ns: u64 },
    /// Started by the OSD itself (periodic purged-snaps scrub): the result is dropped.
    Internal,
}

/// A command whose parts run on every core; the control core merges the answers.
pub(crate) struct Scatter {
    to: ReplyTo,
    cmd: Value,
    /// Cores whose answer is still expected: one that has not replied, one whose part answered [`PENDING`] (the core
    /// delivers the part later) and one whose part answered [`DEFERRED`] (its PG answers with [`XMsg::CmdDone`]). All of
    /// them are under the loud timeout below: an owner that never follows up must not silence the command.
    wait: BTreeSet<usize>,
    parts: Vec<(i32, Value)>,
    /// Liveness beat counters of every core at the previous check (the start before the first one).
    beats: Vec<u64>,
    /// Per core, the time its beat counter last advanced (the start until it does).
    progress: Vec<Duration>,
    deadline: Duration,
    /// The loud TIMEOUT line was logged (once per scatter).
    warned: bool,
    /// The deferred part's final `(r, rs)`.
    done: Option<(i32, String)>,
}

/// Result of a scattered part that answers later ([`XMsg::CmdDone`] with the scatter id of
/// [`CmdState::cur_query`]).
pub(crate) const DEFERRED: i32 = 1;

/// Result of a scattered part whose core delivers the part itself later, as an ordinary [`XMsg::QueryReply`] of the
/// same scatter id (`scrub_purged_snaps`: the walk goes on in steps between other work).
pub(crate) const PENDING: i32 = 2;

#[cfg(test)]
impl Scatter {
    /// Test hook: a scatter with the given cores still owing an answer (a part that answered [`PENDING`] or
    /// [`DEFERRED`] keeps its core in `wait`), so tests can drive the deferred-answer paths without the real commands.
    pub(crate) fn pending(
        to: ReplyTo,
        cmd: Value,
        wait: BTreeSet<usize>,
        start: Duration,
        beats: Vec<u64>,
    ) -> Scatter {
        Scatter {
            to,
            cmd,
            wait,
            parts: Vec::new(),
            progress: vec![start; beats.len()],
            beats,
            deadline: start + SCATTER_WAIT,
            warned: false,
            done: None,
        }
    }
}

/// A `ceph tell` reply whose body the admin socket's render thread builds ([`CmdState::rendering`]).
struct Rendering {
    body: Receiver<Vec<u8>>,
    to: ReplyTo,
    r: i32,
    rs: String,
}

/// Command plumbing of the control core.
#[derive(Default)]
pub(crate) struct CmdState {
    asok: Option<AsokRx>,
    /// This core's wake handle (`Osd::set_core_waker`), for the admin socket workers.
    waker: Option<Arc<dyn ingress::Waker>>,
    /// `ceph tell` replies waiting for their body from the admin socket's render thread (polled with the admin socket).
    rendering: Vec<Rendering>,
    pub(crate) pending: HashMap<u64, Sender<CmdResult>>,
    pub(crate) seq: u64,
    pub(crate) scatter: HashMap<u64, Scatter>,
    /// `(control core, scatter id)` of the scattered part running on this core (`query_local`), for a part that
    /// answers [`DEFERRED`].
    pub(crate) cur_query: Option<(usize, u64)>,
    /// Scatter parts `(core, id)` of `scrub_purged_snaps` waiting for this core's running walk.
    pub(crate) purged_waiters: Vec<(usize, u64)>,
    /// `mark_unfound_lost` waiting for its PG ([`peering::Action::LostMarked`]): `(spg, tid)` -> [`Self::cur_query`].
    pub(crate) lost_wait: HashMap<(denc::types::SpgT, u64), (usize, u64)>,
    /// `bench` in progress: one write per driver iteration.
    pub(crate) bench: Option<crate::tellx::Bench>,
    /// Input blob of the tell being executed (`ceph tell ... -i FILE`).
    pub(crate) inbl: Vec<u8>,
    /// LAB: store completions are held back until this time.
    #[cfg(feature = "lab")]
    pub stall_until: Duration,
}

impl CmdState {
    #[inline]
    pub(crate) fn has_asok(&self) -> bool {
        self.asok.is_some()
    }
}

/// Outcome of one runtime value change ([`Osd::runtime_set`]): classic's `ConfigValues::SET_NO_CHANGE`,
/// `SET_NO_EFFECT` and `SET_HAVE_EFFECT`, plus the two refusals.
enum RuntimeSet {
    /// Stored, and the effective value moved: broadcast and re-read it.
    Effect,
    /// The override moved, the effective value stays: broadcast only.
    NoEffect,
    /// The override already held that value: nothing to do.
    NoChange,
    /// The value does not parse (spec osd-lifecycle.md 2.9), with the reason.
    Invalid(String),
    /// Refused by the runtime guard (spec osd-lifecycle.md 9.2).
    Refused,
}

/// One runtime config observer: the options its pass re-reads from the effective config, and the pass itself. Classic's
/// `ConfigObserverMgr::is_tracking`: a runtime `config set`/`injectargs` may change an option whose schema flags alone
/// forbid it only when an observer of this daemon tracks it (spec osd-lifecycle.md 9.2). A pass that starts reading
/// another option adds it to its keys.
struct Observer<B: Backend> {
    keys: &'static [&'static str],
    apply: fn(&mut Osd<B>),
}

fn malformed_command() -> Res {
    (EINVAL, "invalid json".into(), Out::default())
}

/// Validate before dispatch, including scattered commands. The advertised descriptors are also the server's
/// contract (spec/osd-admin-review-2026-11-08.md); CLI-side checking cannot protect raw messenger/asok requests.
fn validate_command(v: &mut Value) -> Result<(), &'static str> {
    let Some(obj) = v.as_object_mut() else {
        return Err("invalid json");
    };
    for value in obj.values() {
        let valid = match value {
            Value::String(_) | Value::Bool(_) | Value::Number(_) => true,
            Value::Array(a) => {
                a.is_empty()
                    || a.iter().all(Value::is_string)
                    || a.iter().all(Value::is_i64)
                    || a.iter().all(Value::is_f64)
            }
            _ => false,
        };
        if !valid {
            return Err("invalid json");
        }
    }
    if ["prefix", "format"]
        .iter()
        .any(|k| obj.get(*k).is_some_and(|x| !x.is_string()))
    {
        return Err("invalid json, missing format and/or prefix");
    }
    let prefix = obj.get("prefix").and_then(Value::as_str).unwrap_or("");
    let mut registered = false;
    for c in CMDS.iter().filter(|c| {
        c.words.join(" ") == prefix
            || (prefix == "pg"
                && c.words.len() == 1
                && obj.get("cmd").and_then(Value::as_str) == Some(c.words[0]))
    }) {
        registered = true;
        if c.args.iter().all(|(name, ty, required, many)| {
            let Some(value) = obj.get(*name) else {
                return !required || *many;
            };
            let scalar = |value: &Value| match *ty {
                "CephInt" => value.is_i64(),
                "CephFloat" => value.is_f64(),
                "CephBool" => {
                    value.is_boolean()
                        || value
                            .as_str()
                            .is_some_and(|s| s == format!("--{}", name.replace('_', "-")))
                }
                ty => value.as_str().is_some_and(|s| {
                    ty.strip_prefix("CephChoices:")
                        .is_none_or(|choices| choices.split('|').any(|c| c == s))
                }),
            };
            // classic refuses a bare scalar for a vector argument; one value of the element type is accepted as the
            // one-element vector (in-repo lab tooling and existing asok callers send `"val": "x"`; never ambiguous)
            match (value.as_array(), *many) {
                (Some(a), true) => a.iter().all(scalar),
                _ => scalar(value),
            }
        }) {
            for (name, ty, _, _) in c.args {
                if *ty == "CephBool" && obj.get(*name).is_some_and(Value::is_string) {
                    obj.insert((*name).into(), Value::Bool(true));
                }
            }
            return Ok(());
        }
    }
    if registered {
        Err("invalid command json")
    } else {
        Ok(())
    }
}

/// How long a scattered command waits for the other cores before it logs the loud timeout; it keeps waiting while the
/// missing cores make progress (spec ops-observability 6.7).
const SCATTER_WAIT: Duration = Duration::from_secs(5);

/// This store policy has an acknowledged all-core update path, unlike startup-only store tunables.
fn range_threshold_option(var: &str) -> bool {
    var.trim().replace([' ', '-'], "_") == "flashstore_omap_delete_range_threshold"
}

/// Command result: `(retval, status text, output)`.
pub(crate) type Res = (i32, String, Out);

/// Command output. Commands answer with a [`Value`]; it is serialized exactly once, at the reply: compact for the
/// `json`/`jsonl` formats, pretty otherwise. `Raw` carries bytes that are not a command JSON document. `Counters` is a
/// counter document still to be built from its snapshot: by the admin socket thread that answers, or by the render
/// thread for a `ceph tell` (never on a core when an admin socket runs, [`crate::ctrsnap`]).
#[derive(Debug, Clone)]
pub(crate) enum Out {
    Json(Value),
    Raw(Vec<u8>),
    Counters(Box<crate::ctrsnap::CounterReq>),
}

impl Default for Out {
    fn default() -> Self {
        Out::Raw(Vec::new())
    }
}

impl From<Vec<u8>> for Out {
    fn from(bytes: Vec<u8>) -> Self {
        Out::Raw(bytes)
    }
}

impl Out {
    /// Compact bytes (the unformatted command output).
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        match self {
            Out::Json(v) => v.to_string().into_bytes(),
            Out::Raw(b) => b,
            Out::Counters(c) => c.render(true),
        }
    }

    /// Reply body for the requested format (see [`crate::asok::render`]).
    pub(crate) fn render(self, compact: bool) -> Vec<u8> {
        match self {
            Out::Json(v) if compact => v.to_string().into_bytes(),
            Out::Json(v) => crate::asok::pretty(&v),
            Out::Raw(b) => crate::asok::format_bytes(compact, b),
            Out::Counters(c) => c.render(compact),
        }
    }
}

impl<B: Backend> Osd<B> {
    /// Admin commands need admin caps (osdcaps.md s1): the session's osd cap text, parsed with the op grammar,
    /// must hold an unrestricted `allow *` grant. Unparsable or missing caps deny. Parsed per command: tell is
    /// rare and forwarded links carry only the text.
    fn tell_allowed(&self, link: u64) -> bool {
        self.link_auth(link).is_some_and(|(caps, _)| {
            caps.as_deref()
                .is_some_and(|c| opexec::caps::Caps::parse(c).is_ok_and(|c| c.allows_admin()))
        })
    }

    pub(crate) fn on_tell(&mut self, link: u64, tid: u64, c: MCommand) {
        let to = ReplyTo::Tell {
            link,
            tid,
            compact: false,
        };
        if !self.tell_allowed(link) {
            let who = self.link_auth(link).map(|a| a.1).unwrap_or_default();
            self.log(format!("tell from {who} denied (caps)"));
            self.finish_cmd(to, (EACCES, "access denied".to_owned(), Out::default()));
        } else if c.fsid != self.id.cluster_fsid && c.fsid != Default::default() {
            self.finish_cmd(to, (EINVAL, "wrong fsid".to_owned(), Out::default()));
        } else {
            self.cmds.inbl = c.data;
            self.exec_command(c.cmd.first().map_or("{}", String::as_str), to);
            self.cmds.inbl = Vec::new();
        }
    }

    pub(crate) fn on_legacy_mon_command(&mut self, link: u64, tid: u64, c: MMonCommand) {
        let to = ReplyTo::Legacy {
            link,
            tid,
            cmd: c.cmd.clone(),
            compact: false,
        };
        if self.tell_allowed(link) {
            self.cmds.inbl = c.data;
            self.exec_command(c.cmd.first().map_or("{}", String::as_str), to);
            self.cmds.inbl = Vec::new();
        } else {
            self.finish_cmd(to, (EACCES, "access denied".to_owned(), Out::default()));
        }
    }

    pub(crate) fn ok(v: Value) -> Res {
        (0, String::new(), Out::Json(v))
    }

    /// Meta expansion context of this daemon (`config show|get|diff`).
    pub(crate) fn config_meta(&self) -> crate::schema::Meta {
        let cluster = self.conf.get("cluster").unwrap_or("ceph");
        crate::schema::Meta::new(cluster, self.id.whoami, &self.cfg.hostname)
    }

    /// Run a command; the answer goes to `to` now or, for scattered commands, when every core answered.
    pub(crate) fn exec_command(&mut self, json_cmd: &str, mut to: ReplyTo) {
        let res = match serde_json::from_str::<Value>(json_cmd) {
            Ok(v) => {
                // The command is parsed once: the reply format comes from the same document.
                let compact = crate::asok::wants_compact(&v);
                match &mut to {
                    ReplyTo::Tell { compact: c, .. } | ReplyTo::Legacy { compact: c, .. } => {
                        *c = compact;
                    }
                    ReplyTo::Asok(_) | ReplyTo::DedupList { .. } | ReplyTo::Internal => {}
                }
                self.run_parsed(v, &to)
            }
            Err(_) => Some(malformed_command()),
        };
        if let Some(res) = res {
            self.finish_cmd(to, res);
        }
    }

    pub(crate) fn finish_cmd(&mut self, to: ReplyTo, (r, rs, out): Res) {
        match to {
            ReplyTo::Tell { compact, .. } | ReplyTo::Legacy { compact, .. } => {
                let out = match (out, &self.cmds.asok) {
                    (Out::Counters(req), Some(asok)) => {
                        match asok.render(Out::Counters(req), compact) {
                            Ok(body) => {
                                self.cmds.rendering.push(Rendering { body, to, r, rs });
                                return;
                            }
                            // the render thread is gone (shutdown): build the body here
                            Err(out) => out,
                        }
                    }
                    (out, _) => out,
                };
                self.send_cmd_reply(to, r, rs, out.render(compact));
            }
            ReplyTo::Asok(tok) => {
                if let Some(s) = self.cmds.pending.remove(&tok) {
                    // serialized by the admin socket thread
                    let _ = s.send((r, rs, out));
                }
            }
            ReplyTo::DedupList { link, tid, now_ns } => {
                let reply = crate::dedupwire::reply_of(r, &out.into_bytes(), now_ns);
                self.send_link_tid(link, tid, reply);
            }
            ReplyTo::Internal => {
                // periodic work started by the OSD itself: nobody receives the result, so a failure would be silent
                if r != 0 {
                    self.logl(0, format!("WARNING internal command failed ({r}): {rs}"));
                }
            }
        }
    }

    /// Send the reply of a `ceph tell` / legacy command with its finished body.
    fn send_cmd_reply(&mut self, to: ReplyTo, r: i32, rs: String, data: Vec<u8>) {
        match to {
            ReplyTo::Tell { link, tid, .. } => {
                self.send_link_tid(link, tid, MCommandReply { r, rs, data });
            }
            ReplyTo::Legacy { link, tid, cmd, .. } => {
                let m = MMonCommandAck {
                    version: 0,
                    r,
                    rs,
                    cmd,
                    data,
                };
                self.send_link_tid(link, tid, m);
            }
            ReplyTo::Asok(_) | ReplyTo::DedupList { .. } | ReplyTo::Internal => {}
        }
    }

    // ------------------------------------------------------------------ admin socket (control core)

    /// Serve the admin socket requests arriving on `rx` (see [`crate::asok`]). Control core only.
    pub fn attach_asok(&mut self, rx: AsokRx) {
        if let Some(w) = &self.cmds.waker {
            rx.set_waker(w.clone());
        }
        self.cmds.asok = Some(rx);
    }

    /// Send the `ceph tell` replies whose body the render thread finished.
    fn poll_rendered(&mut self) -> bool {
        let mut any = false;
        let mut i = 0;
        while i < self.cmds.rendering.len() {
            let Some(asok) = &self.cmds.asok else { break };
            match asok.rendered(&self.cmds.rendering[i].body) {
                Ok(data) => {
                    let p = self.cmds.rendering.swap_remove(i);
                    self.send_cmd_reply(p.to, p.r, p.rs, data);
                    any = true;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => i += 1,
                // the render thread stopped (shutdown): no reply
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.cmds.rendering.swap_remove(i);
                }
            }
        }
        any
    }

    /// The admin socket workers poke `w` after queueing a request, its render thread after a finished body (installed by
    /// `set_core_waker`, before or after [`attach_asok`](Self::attach_asok)).
    pub(crate) fn set_cmd_waker(&mut self, w: Arc<dyn ingress::Waker>) {
        if let Some(rx) = &self.cmds.asok {
            rx.set_waker(w.clone());
        }
        self.cmds.waker = Some(w);
    }

    /// Work another thread queued for this core and pokes it for (admin socket requests, rendered `ceph tell` bodies,
    /// store completions published by off-owner workers): the sleeper's re-check after it announced its sleep
    /// (`rt::wake`).
    pub fn handed_work(&self) -> bool {
        self.cmds.asok.as_ref().is_some_and(AsokRx::waiting) || self.pg.store.handed_completion()
    }

    /// Run the admin socket requests that arrived (cheap: one channel poll per driver loop iteration).
    pub(crate) fn poll_asok(&mut self, now: Duration) -> bool {
        let mut any = !self.cmds.rendering.is_empty() && self.poll_rendered();
        for _ in 0..16 {
            let Some(rx) = &self.cmds.asok else { break };
            let Some(req) = rx.try_recv() else { break };
            any = true;
            self.set_now(now);
            self.cmds.seq += 1;
            let tok = self.cmds.seq;
            self.cmds.pending.insert(tok, req.reply);
            self.exec_command(&req.cmd, ReplyTo::Asok(tok));
        }
        if any {
            self.pump();
        }
        any
    }

    // ------------------------------------------------------------------ scattered commands

    /// Run the per-core part on this core, ask every other core, answer when all replied (or after a timeout).
    /// `Some` = answered at once (single core, nothing deferred).
    pub(crate) fn scatter(&mut self, v: &Value, to: &ReplyTo) -> Option<Res> {
        self.cmds.seq += 1;
        let id = self.cmds.seq;
        let wait: BTreeSet<usize> = (0..self.cores()).collect();
        let me = self.core_id();
        self.cmds.scatter.insert(
            id,
            Scatter {
                to: to.clone(),
                cmd: v.clone(),
                wait: wait.clone(),
                parts: Vec::new(),
                progress: vec![self.now; self.cores()],
                beats: (0..self.cores())
                    .map(|c| self.live.and_then(|l| l.beat_count(c)).unwrap_or(0))
                    .collect(),
                deadline: self.now + SCATTER_WAIT,
                warned: false,
                done: None,
            },
        );
        let cmd = v.to_string();
        for c in wait.into_iter().filter(|c| *c != me) {
            self.xsend(
                c,
                XMsg::Query {
                    id,
                    cmd: cmd.clone(),
                },
            );
        }
        self.cmds.cur_query = Some((me, id));
        let (r, out) = self.query_local(v);
        self.cmds.cur_query = None;
        self.scatter_part(me, id, r, out);
        self.scatter_take_done(id).map(|(_, res)| res)
    }

    /// Any core: the part of a scattered command that runs against this core's state.
    pub(crate) fn on_query(&mut self, from: usize, id: u64, cmd: &str) {
        let v: Value = serde_json::from_str(cmd).unwrap_or(Value::Null);
        self.cmds.cur_query = Some((from, id));
        let (r, out) = self.query_local(&v);
        self.cmds.cur_query = None;
        self.xsend(
            from,
            XMsg::QueryReply {
                id,
                r,
                out: Box::new(out),
            },
        );
    }

    pub(crate) fn on_query_reply(&mut self, from: usize, id: u64, r: i32, out: Value) {
        self.scatter_part(from, id, r, out);
        self.scatter_try_finish(id);
    }

    fn scatter_part(&mut self, from: usize, id: u64, r: i32, out: Value) {
        let Some(s) = self.cmds.scatter.get_mut(&id) else {
            return;
        };
        // A part that answers PENDING (its core delivers it later) or DEFERRED (its PG answers with CmdDone) keeps its
        // core in `wait`: the answer is still expected and stays under the loud timeout.
        if r == PENDING || r == DEFERRED {
            return;
        }
        if s.wait.remove(&from) {
            s.parts.push((r, out));
        }
    }

    /// Control core: the deferred part of scatter `id` finished on `core` (`mark_unfound_lost`).
    pub(crate) fn on_cmd_done(&mut self, core: usize, id: u64, r: i32, rs: String) {
        let Some(s) = self.cmds.scatter.get_mut(&id) else {
            return;
        };
        s.wait.remove(&core);
        s.done = Some((r, rs));
        self.scatter_try_finish(id);
    }

    /// The part of scatter `(core, id)` that answered [`DEFERRED`] on this core finished.
    pub(crate) fn cmd_done(&mut self, (core, id): (usize, u64), r: i32, rs: String) {
        if core == self.core_id() {
            self.on_cmd_done(core, id, r, rs);
        } else {
            self.xsend(core, XMsg::CmdDone { id, r, rs });
        }
    }

    /// Answer scatter `id` once every part (and a deferred part's final answer) is in.
    fn scatter_try_finish(&mut self, id: u64) {
        if let Some((to, res)) = self.scatter_take_done(id) {
            self.finish_cmd(to, res);
        }
    }

    /// Scatter `id` with every part (and a deferred part's final answer) in: removed, with its merged answer.
    fn scatter_take_done(&mut self, id: u64) -> Option<(ReplyTo, Res)> {
        let s = self.cmds.scatter.get(&id)?;
        if !s.wait.is_empty() {
            return None;
        }
        let s = self.cmds.scatter.remove(&id)?;
        let res = match s.done {
            Some((r, rs)) => (r, rs, Out::default()),
            None => self.merge_parts(&s.cmd, s.parts),
        };
        Some((s.to, res))
    }

    /// Scattered commands never answer a subset (spec ops-observability 6.7): the loud timeout line is logged, but the
    /// answer waits while the missing cores make progress. A core whose liveness beat has not advanced for
    /// `osd_op_thread_timeout` is gone: the command answers an error instead of a well-formed subset. This covers a core that never replied, one whose part answers [`PENDING`] later and one whose
    /// part answers [`DEFERRED`] to its PG: all of them keep their place in [`Scatter::wait`], so no owner can hang a
    /// command without a loud line.
    pub(crate) fn scatter_expire(&mut self) {
        if self.cmds.scatter.is_empty() {
            return;
        }
        let now = self.now;
        let limit = Duration::from_secs(self.conf.u64("osd_op_thread_timeout", 15));
        let due: Vec<u64> = self
            .cmds
            .scatter
            .iter()
            .filter(|(_, s)| s.deadline <= now)
            .map(|(i, _)| *i)
            .collect();
        for id in due {
            let Some((cmd, wait, warned)) = self
                .cmds
                .scatter
                .get(&id)
                .map(|s| (s.cmd["prefix"].clone(), s.wait.clone(), s.warned))
            else {
                continue;
            };
            if !warned {
                if let Some(s) = self.cmds.scatter.get_mut(&id) {
                    s.warned = true;
                }
                self.logl(
                    0,
                    format!(
                        "WARNING TIMEOUT scattered command exceeded {:.3}s (command {cmd}: cores {wait:?} did not answer yet, waiting)",
                        SCATTER_WAIT.as_secs_f64()
                    ),
                );
            }
            if let (Some(l), Some(s)) = (self.live, self.cmds.scatter.get_mut(&id)) {
                for c in 0..s.beats.len() {
                    if let Some(b) = l.beat_count(c).filter(|b| *b > s.beats[c]) {
                        s.beats[c] = b;
                        s.progress[c] = now;
                    }
                }
            }
            let gone: Vec<usize> = {
                let s = self.cmds.scatter.get(&id).expect("checked above");
                s.wait
                    .iter()
                    .copied()
                    .filter(|c| self.live.is_some() && now.saturating_sub(s.progress[*c]) >= limit)
                    .collect()
            };
            let wait_more = gone.is_empty();
            if wait_more {
                if let Some(s) = self.cmds.scatter.get_mut(&id) {
                    s.deadline = now + SCATTER_WAIT;
                }
                continue;
            }
            let s = self.cmds.scatter.remove(&id).expect("checked above");
            self.logl(
                0,
                format!(
                    "WARNING TIMEOUT scattered command exceeded {:.3}s (command {}: cores {:?} made no progress, answering an error)",
                    SCATTER_WAIT.as_secs_f64(),
                    s.cmd["prefix"],
                    gone
                ),
            );
            self.finish_cmd(
                s.to,
                (
                    ETIMEDOUT,
                    format!(
                        "scatter: core(s) {gone:?} did not answer {}",
                        s.cmd["prefix"]
                    ),
                    Out::default(),
                ),
            );
        }
    }

    pub(crate) fn scatter_deadline(&self) -> Option<Duration> {
        self.cmds.scatter.values().map(|s| s.deadline).min()
    }

    /// Writes of this core's PGs that still await peer commits: `(client conn, client tid)` -> `"N,M"` (replicated: the
    /// replica OSDs; EC: `N(sS)` per shard).
    fn write_waiting_map(&self) -> std::collections::HashMap<(u64, u64), String> {
        let mut m = std::collections::HashMap::new();
        for (spg, e) in &self.pg.eng {
            let Some(pg) = self.pg.set.pg(*spg) else {
                continue;
            };
            for (key, wtid) in e.inflight_writes() {
                if let Some(w) = pg.write_waiting(wtid) {
                    m.insert(key, waiting_text(&w));
                }
            }
        }
        m
    }

    /// The part of a scattered command that runs on this core: `(result, data)`.
    fn query_local(&mut self, v: &Value) -> (i32, Value) {
        let prefix = v.get("prefix").and_then(Value::as_str).unwrap_or("");
        let now = self.now.as_nanos() as u64;
        let origin = self.wall_origin_ns;
        let wall = move |ns| crate::optrack::wall_str(origin, ns);
        let pairs = |v: Vec<(u64, Value)>| {
            Value::Array(v.into_iter().map(|(k, o)| json!([k, o])).collect())
        };
        match prefix {
            "config set" | "config unset"
                if v.get("var")
                    .and_then(Value::as_str)
                    .is_some_and(range_threshold_option) =>
            {
                let var = v["var"].as_str().expect("matched threshold option");
                if prefix == "config set" {
                    let val = str_list(v.get("val")).join(" ");
                    if let Err(error) = self.conf.set(Level::Override, var, &val) {
                        return (EINVAL, Value::String(error));
                    }
                } else {
                    self.conf.unset(Level::Override, var);
                }
                // No publish here: the command itself is delivered once to every core, and the
                // control core does not acknowledge it until every store has applied its part.
                self.conf_changed();
                let body = if prefix == "config set" {
                    json!({"success": ""})
                } else {
                    json!({})
                };
                (0, body)
            }
            "dump_ops_in_flight" | "ops" | "dump_blocked_ops" => {
                let blocked = prefix == "dump_blocked_ops";
                let waiting = self.write_waiting_map();
                let mut v = self
                    .tracker
                    .dump_live_with(now, &wall, blocked, &|k| waiting.get(&k).cloned());
                // ops waiting for a map / the OSD / their PG count as in flight too (classic tracks them)
                v.extend(self.pg_parked_dump(now, &wall, blocked));
                (0, pairs(v))
            }
            "dump_historic_ops" | "dump_historic_ops_by_duration" | "dump_historic_slow_ops" => {
                let slow = prefix == "dump_historic_slow_ops";
                let h = self
                    .tracker
                    .dump_hist(now, &wall, slow, &|k| self.trace_hist_events(k));
                (
                    0,
                    Value::Array(h.into_iter().map(|(e, d, o)| json!([e, d, o])).collect()),
                )
            }
            "dump_op_traces" | "trace_summary" | "trace_reset" => self.trace_query_local(prefix),
            "dump_pgs" => (0, self.pg_dump()),
            "dump_scrubs" => (0, self.scrubs_local()),
            "pg" if v
                .get("cmd")
                .and_then(Value::as_str)
                .is_some_and(|c| c != "query") =>
            {
                self.query_local_ext(prefix, v)
                    .unwrap_or((ENOENT, Value::Null))
            }
            "pg" => {
                let pgid = v.get("pgid").and_then(Value::as_str).unwrap_or("");
                let (r, rs, out) = self.pg_query(pgid);
                if r == 0 {
                    (
                        0,
                        if let Out::Json(v) = out {
                            v
                        } else {
                            Value::Null
                        },
                    )
                } else {
                    (r, Value::String(rs))
                }
            }
            // a worker ships its numbers now (the control core refreshes its own after the answers arrived)
            "flush_pg_stats" => {
                self.push_stats();
                (0, Value::Null)
            }
            _ => self
                .query_local_ext(prefix, v)
                .unwrap_or((ENOENT, Value::Null)),
        }
    }

    /// Control core: the answer of a scattered command from every core's part (own part first).
    fn merge_parts(&mut self, v: &Value, parts: Vec<(i32, Value)>) -> Res {
        let prefix = v.get("prefix").and_then(Value::as_str).unwrap_or("");
        let arrays = |parts: &[(i32, Value)]| -> Vec<Value> {
            parts
                .iter()
                .filter_map(|(_, p)| p.as_array())
                .flatten()
                .cloned()
                .collect()
        };
        let key = |x: &Value, i: usize| x.get(i).and_then(Value::as_u64).unwrap_or(0);
        match prefix {
            "config set" | "config unset"
                if v.get("var")
                    .and_then(Value::as_str)
                    .is_some_and(range_threshold_option) =>
            {
                if let Some((r, error)) = parts.iter().find(|(r, _)| *r != 0) {
                    (
                        *r,
                        error
                            .as_str()
                            .unwrap_or("threshold update failed")
                            .to_owned(),
                        Out::default(),
                    )
                } else if prefix == "config set" {
                    Self::ok(json!({"success": ""}))
                } else {
                    Self::ok(json!({}))
                }
            }
            "dump_ops_in_flight" | "ops" | "dump_blocked_ops" => {
                let ops = arrays(&parts)
                    .iter()
                    .map(|x| (key(x, 0), x[1].clone()))
                    .collect();
                let mut r = crate::optrack::live_reply(ops);
                if prefix == "dump_blocked_ops" {
                    // classic: blocked form carries the threshold and the count under another name
                    let n = r["num_ops"].take();
                    if let Some(o) = r.as_object_mut() {
                        o.remove("num_ops");
                        o.insert(
                            "complaint_time".into(),
                            json!(self.conf.f64("osd_op_complaint_time", 30.0)),
                        );
                        o.insert("num_blocked_ops".into(), n);
                    }
                }
                Self::ok(r)
            }
            "dump_historic_ops" | "dump_historic_ops_by_duration" | "dump_historic_slow_ops" => {
                let slow = prefix == "dump_historic_slow_ops";
                let ops = arrays(&parts)
                    .iter()
                    .map(|x| (key(x, 0), key(x, 1), x[2].clone()))
                    .collect();
                let (size_key, dur) = if slow {
                    ("osd_op_history_slow_op_size", 0)
                } else {
                    (
                        "osd_op_history_size",
                        self.conf.u64("osd_op_history_duration", 600),
                    )
                };
                let size = self.conf.u64(size_key, 20) as usize;
                let dur = if slow {
                    self.conf.u64("osd_op_history_slow_op_threshold", 10)
                } else {
                    dur
                };
                Self::ok(crate::optrack::hist_reply(
                    ops,
                    size,
                    dur,
                    prefix != "dump_historic_ops",
                ))
            }
            "dump_op_traces" | "trace_summary" | "trace_reset" => {
                self.trace_merge(prefix, v, parts)
            }
            "dump_pgs" => {
                let mut pgs: Vec<Value> = Vec::new();
                let mut peers = BTreeSet::new();
                let mut dropped = 0u64;
                // each part names the core of every PG (`pg_dump`): reply order says nothing about ownership
                for (_, p) in parts.iter() {
                    pgs.extend(p["pgs"].as_array().into_iter().flatten().cloned());
                    peers.extend(
                        p["peers"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .filter_map(Value::as_i64),
                    );
                    // per reason counters of the core
                    dropped += p["dropped"]
                        .as_object()
                        .into_iter()
                        .flatten()
                        .filter_map(|(_, n)| n.as_u64())
                        .sum::<u64>();
                }
                pgs.sort_by_key(|p| p["pgid"].as_str().unwrap_or("").to_owned());
                let counters = parts
                    .first()
                    .map_or(Value::Null, |(_, p)| p["counters"].clone());
                let by_core: Vec<Value> = parts
                    .iter()
                    .map(|(_, p)| json!({"counters": p["counters"], "dropped": p["dropped"], "parked": p["parked"], "store_diag": p["store_diag"]}))
                    .collect();
                Self::ok(json!({"pgs": pgs, "peers": peers, "dropped": dropped,
                    "counters": counters, "counters_by_core": by_core, "cores": self.cores()}))
            }
            "dump_scrubs" => Self::ok(Value::Array(arrays(&parts))),
            "pg" if v
                .get("cmd")
                .and_then(Value::as_str)
                .is_some_and(|c| c != "query") =>
            {
                self.merge_ext(prefix, v, parts)
                    .unwrap_or_else(|| (ENOENT, "no such pg command".into(), Out::default()))
            }
            "pg" => match parts.iter().find(|(r, _)| *r == 0) {
                Some((_, q)) => Self::ok(q.clone()),
                None => {
                    let rs = parts
                        .first()
                        .and_then(|(_, m)| m.as_str())
                        .unwrap_or("no such pg");
                    (
                        parts.first().map_or(ENOENT, |p| p.0),
                        rs.to_owned(),
                        Out::default(),
                    )
                }
            },
            "flush_pg_stats" => {
                let seq = self.flush_pg_stats();
                Self::ok(json!({ "stat_seq": seq }))
            }
            p => match self.merge_ext(p, v, parts) {
                Some(r) => r,
                None => (
                    EINVAL,
                    format!("unknown command prefix {p}"),
                    Out::default(),
                ),
            },
        }
    }

    fn scrubs_local(&self) -> Value {
        let v: Vec<Value> = self
            .pg
            .set
            .pgs()
            .filter(|(_, p)| p.is_primary())
            .map(|(s, p)| {
                let (done, aborted) = p.scrub_counts();
                let req = p.scrub_requested();
                json!({"pgid": s.to_string(), "state": p.state_string(),
                    "scrubbing": p.scrub_running(), "scrubs_done": done, "scrubs_aborted": aborted,
                    "requested": req.map(|r| json!({"deep": r.deep, "repair": r.repair})),
                    "scrub_errors": p.info().stats.stats.sum.num_scrub_errors,
                    "inconsistent_objects": p.scrub_inconsistent().len()})
            })
            .collect();
        Value::Array(v)
    }

    /// The config observers of this daemon that every core runs on a config change, in pass order.
    fn setup_observers() -> [Observer<B>; 10] {
        [
            Observer {
                keys: &[
                    "ms_cluster_mode",
                    "ms_service_mode",
                    "ms_mon_cluster_mode",
                    "auth_cluster_required",
                    "auth_service_required",
                    "auth_client_required",
                    "auth_service_ticket_ttl",
                ],
                apply: Osd::obs_auth,
            },
            Observer {
                keys: &["debug_osd"],
                apply: Osd::obs_log,
            },
            Observer {
                keys: &[
                    "osd_enable_op_tracker",
                    "osd_op_history_size",
                    "osd_op_history_duration",
                    "osd_op_history_slow_op_size",
                    "osd_op_history_slow_op_threshold",
                    "osd_op_complaint_time",
                ],
                apply: Osd::obs_tracker,
            },
            Observer {
                keys: &[
                    "osd_max_write_size",
                    "osd_max_object_size",
                    "osd_max_object_name_len",
                    "osd_max_object_namespace_len",
                    "osd_max_attr_name_len",
                    "osd_max_attr_size",
                    "osd_max_pgls",
                    "osd_max_omap_entries_per_request",
                    "osd_max_omap_bytes_per_request",
                    "osd_max_write_op_reply_len",
                    "osd_default_notify_timeout",
                    "osd_client_watch_timeout",
                    "osd_backoff_on_degraded",
                    "osd_backoff_on_unfound",
                ],
                apply: Osd::obs_limits,
            },
            Observer {
                keys: &["osd_class_load_list", "osd_class_default_list"],
                apply: Osd::obs_classes,
            },
            Observer {
                keys: &["flashstore_obj_cache"],
                apply: Osd::obs_memory,
            },
            Observer {
                keys: &[
                    "flashstore_omap_delete_range_threshold",
                    "flashstore_prewrite",
                ],
                apply: Osd::obs_store,
            },
            Observer {
                keys: &["osd_client_message_size_cap", "ms_crc_data"],
                apply: Osd::obs_msgr,
            },
            Observer {
                keys: &["flashstore_trace_sample", "flashstore_trace_ring"],
                apply: Osd::obs_trace,
            },
            Observer {
                keys: crate::monboot::MON_CLIENT_TIMER_KEYS,
                apply: Osd::obs_monc,
            },
        ]
    }

    /// The config observers of this daemon that only the control core runs on a config change, in pass order. The
    /// other cores re-apply their part on `XMsg::Conf` (`refresh_obs_conf`).
    fn change_observers() -> [Observer<B>; 6] {
        [
            Observer {
                keys: &["osd_client_message_size_cap", "osd_client_message_cap"],
                apply: Osd::client_throttle_note,
            },
            Observer {
                keys: &["osd_memory_target"],
                apply: Osd::obs_memory_note,
            },
            Observer {
                keys: crate::pgs::COMPRESSION_KEYS,
                apply: Osd::pg_reapply_compression,
            },
            Observer {
                keys: &crate::config::RECOVERY_QOS_OBS_KEYS,
                apply: Osd::recovery_qos_guard,
            },
            Observer {
                keys: crate::pgs::SCRUB_CFG_KEYS,
                apply: Osd::pg_apply_scrub_cfg,
            },
            // tracks no option: it only reports, so the classic runtime guard of a startup option (e.g.
            // osd_op_num_shards) must keep refusing a runtime change
            Observer {
                keys: &[],
                apply: Osd::no_effect_guard,
            },
        ]
    }

    /// Every option an observer of this daemon tracks, observers in pass order.
    pub(crate) fn observed_keys() -> impl Iterator<Item = &'static str> {
        Self::setup_observers()
            .into_iter()
            .chain(Self::change_observers())
            .flat_map(|o| o.keys.iter().copied())
    }

    /// Does a runtime change of `key` reach an observer of this daemon (spec osd-lifecycle.md 9.2)? Classic's
    /// `ConfigObserverMgr::is_tracking`: the observers declare the options they re-read, so the pass and this answer
    /// cannot disagree.
    pub(crate) fn observed(key: &str) -> bool {
        let k = crate::config::norm(key);
        Self::observed_keys().any(|o| o == k)
    }

    /// Classic's runtime guard (spec osd-lifecycle.md 9.2) for a change to the parsed value `val`: the pinned schema
    /// allows it (`Schema::runtime_changeable`), an observer tracks the option, or the option already has that value
    /// (no-op). A name the pinned schema does not know is croit-flashstore-osd's own (`flashstore_*`, the `debug_*` levels) and changes.
    fn runtime_refused(&self, key: &str, val: &str) -> bool {
        let Some(schema) = crate::optval::schema(&crate::config::norm(key)) else {
            return false;
        };
        !schema.runtime_changeable()
            && !Self::observed(key)
            && crate::schema::current(&self.conf, key).as_deref() != Some(val)
    }

    /// One runtime value change at the override level (`config set`, one `injectargs` token): parse (§2.9), then
    /// classic's runtime guard (§9.2), then store. The outcome says whether the effective value moved, which is what
    /// decides the observer pass (classic `SET_NO_CHANGE` / `SET_NO_EFFECT` / `SET_HAVE_EFFECT`).
    fn runtime_set(&mut self, key: &str, val: &str) -> RuntimeSet {
        let parsed = match crate::config::normalized(key, val) {
            Ok(parsed) => parsed,
            Err(reason) => return RuntimeSet::Invalid(reason),
        };
        if self.runtime_refused(key, &parsed) {
            return RuntimeSet::Refused;
        }
        let before = crate::schema::current(&self.conf, key);
        let version = self.conf.version();
        if let Err(reason) = self.conf.set_reason(Level::Override, key, val) {
            return RuntimeSet::Invalid(reason);
        }
        if self.conf.version() == version {
            RuntimeSet::NoChange
        } else if crate::schema::current(&self.conf, key) == before {
            RuntimeSet::NoEffect
        } else {
            RuntimeSet::Effect
        }
    }

    /// Re-read the settings this core interprets (on every config change: `conf_changed` here, `XMsg::Conf` on the
    /// worker cores).
    pub(crate) fn refresh_obs_conf(&mut self) {
        for o in Self::setup_observers() {
            (o.apply)(self);
        }
    }

    /// Auth method lists and modes of new sessions, rotating refresh cutoff (classic `AuthRegistry`).
    fn obs_auth(&mut self) {
        // mode warnings are only new when the policy changed
        if let Some(log) = self.keys.set_modes(&self.conf)
            && self.is_control()
        {
            for l in log {
                self.log(l);
            }
        }
        // `ms_mon_cluster_mode`: the next mon handshake offers the current list (existing sessions keep theirs)
        self.mc.set_modes(&self.keys.modes().mon);
        // auth_*_required are runtime options (classic re-reads them): new sessions use the current lists
        if let Some(log) = self.keys.refresh_lists(&self.conf, self.id.whoami)
            && self.is_control()
        {
            self.mc.set_methods(&self.keys.lists().cluster);
            for l in log {
                self.log(l);
            }
        }
        if self.is_control() {
            // auth_service_ticket_ttl: runtime option of the mon client (rotating refresh cutoff, clock-skew bound)
            let ttl = self.conf.f64("auth_service_ticket_ttl", 3600.0);
            self.mc
                .set_service_ticket_ttl(ttl.clamp(0.0, f64::from(u32::MAX)) as u32);
        }
    }

    /// `mon_client_*` timers of the mon session (classic reads them on every use): the next hunt, keepalive and log
    /// flush use the current values.
    fn obs_monc(&mut self) {
        if self.is_control() {
            let t = crate::monboot::mon_client_timers(|k| self.conf.get(k));
            self.mc.set_timers(t);
        }
    }

    /// Debug level of this core (`N` of `N/M`), and the per-op EC trace it gates.
    fn obs_log(&mut self) {
        let lvl = self
            .conf
            .get("debug_osd")
            .and_then(|s| s.split('/').next())
            .and_then(|s| s.trim().parse::<u8>().ok())
            .unwrap_or(1);
        self.log_level = lvl;
        // per-op EC trace (OQ 41 lab diagnostic): debug_osd >= 15
        if self.pg.set.set_ec_trace(lvl >= 15) {
            self.pg.set.push_cfg_to_pgs();
        }
    }

    /// Op tracker limits of this core.
    fn obs_tracker(&mut self) {
        let c = &self.conf;
        self.tracker.lim = crate::optrack::Limits {
            hist_size: c.u64("osd_op_history_size", 20) as usize,
            hist_dur_ns: c
                .u64("osd_op_history_duration", 600)
                .saturating_mul(1_000_000_000),
            slow_size: c.u64("osd_op_history_slow_op_size", 20) as usize,
            slow_ns: (c.f64("osd_op_history_slow_op_threshold", 10.0) * 1e9) as u64,
            complaint_ns: (c.f64("osd_op_complaint_time", 30.0) * 1e9) as u64,
            enabled: c.bool("osd_enable_op_tracker", true),
        };
    }

    /// Per-request limits of this core and of its PG engines.
    fn obs_limits(&mut self) {
        let limits = op_limits(&self.conf);
        self.pg.limits = limits;
        for e in self.pg.eng.values_mut() {
            e.set_limits(limits);
        }
        // `osd_max_write_size` reaches the public links at once (client-ops 5.4.1: a write above it is refused before
        // its data segment is admitted)
        let probe = self.data_probe(crate::osd::MsgrId::Public);
        for l in self
            .links
            .values_mut()
            .filter(|l| l.msgr == crate::osd::MsgrId::Public)
        {
            l.conn.set_data_probe(probe);
        }
    }

    /// Object class policies: classes served at all, and those a plain class-read/-write cap may reach.
    fn obs_classes(&mut self) {
        let c = &self.conf;
        let classes = opexec::clsx::ClassPolicy::parse(
            c.get("osd_class_load_list")
                .unwrap_or(opexec::clsx::ClassPolicy::CEPH_DEFAULT_LIST),
            c.get("osd_class_default_list")
                .unwrap_or(opexec::clsx::ClassPolicy::CEPH_DEFAULT_LIST),
        );
        self.pg.classes = classes.clone();
        for e in self.pg.eng.values_mut() {
            e.set_class_policy(classes.clone());
        }
    }

    /// Object-state cache capacity per PG of this core: the share over the PGs the OSD hosts (adr 0160 D5); re-applied
    /// when `flashstore_obj_cache` or the OSD-wide PG count ([`Self::pg_set_num_pgs`]) changes.
    pub(crate) fn obs_memory(&mut self) {
        let c = &self.conf;
        self.pg.obj_cache = if c.bool("flashstore_obj_cache", true) {
            crate::nvmestore::obj_cache_per_pg(self.pg.set.config().num_pgs_hint)
        } else {
            0
        };
    }

    /// Store settings of this core: omap range-delete threshold, pre-write.
    fn obs_store(&mut self) {
        let c = &self.conf;
        B::set_omap_delete_range_threshold(
            &self.pg.store,
            c.u64("flashstore_omap_delete_range_threshold", 0),
        );
        let prewrite = c.bool("flashstore_prewrite", true);
        self.pre_configure(prewrite);
    }

    /// Messenger settings of this core: public link message cap and msgr2 segment CRCs.
    fn obs_msgr(&mut self) {
        let c = &self.conf;
        // received client messages: `osd_client_message_size_cap` (classic: the OSD-wide byte throttle of the public
        // messenger's client policy) is the size above which a MESSAGE of a public link is admitted alone (spec
        // msgr2.md 8.2); `osd_client_message_cap` (classic: OSD-wide count of client messages in flight) is not
        // enforced: the client pool's frame slots and bytes are the aggregate bound (adr 0175).
        let cap = client_message_size_cap(c);
        self.msgr[crate::osd::MsgrId::Public as usize]
            .cfg
            .max_message = cap;
        // `ms_crc_data` (spec msgr2.md 4.3): connections read it at creation, so existing ones keep their value
        let crc_data = c.bool("ms_crc_data", true);
        for m in &mut self.msgr {
            m.cfg.crc_data = crc_data;
        }
        self.mc.set_crc_data(crc_data);
        self.crc_data_note(crc_data);
        for l in self
            .links
            .values_mut()
            .filter(|l| l.msgr == crate::osd::MsgrId::Public)
        {
            l.conn.set_frame_cap(cap);
        }
    }

    /// Per-op stage trace sampling of this core.
    fn obs_trace(&mut self) {
        let c = &self.conf;
        self.pg.tr.configure(
            c.u64("flashstore_trace_sample", 0).min(u64::from(u32::MAX)) as u32,
            c.u64("flashstore_trace_ring", crate::trace::DEFAULT_RING as u64) as usize,
            self.cl.spec.id,
        );
    }

    /// Once per value: the memory envelope is sized before the stores mount (adr 0175 am. 2).
    fn obs_memory_note(&mut self) {
        let active = crate::memory::active().target;
        if let Some(note) = crate::memory::restart_note(
            self.conf.get("osd_memory_target"),
            active,
            &mut self.mem_noted,
        ) {
            self.log(note);
        }
    }

    /// Once per value: what croit-flashstore-osd enforces of the classic client throttles (the operator knobs otherwise look
    /// effective while their mechanism does not exist here). Control core only.
    pub(crate) fn client_throttle_note(&mut self) {
        if !self.is_control() {
            return;
        }
        // the operator's value as set (0 = no cap)
        let size_cap = self.conf.u64("osd_client_message_size_cap", 0);
        let write_cap = op_limits(&self.conf).max_write_size >> 20;
        if self.msg_cap_noted == Some((size_cap, write_cap)) {
            return;
        }
        self.msg_cap_noted = Some((size_cap, write_cap));
        self.log(format!(
            "client message throttles: osd_client_message_size_cap {} is the size above which a client message is \
             admitted alone (never a fault) and osd_max_write_size {} MiB the limit above which a write is refused \
             -EMSGSIZE before its payload is admitted; osd_client_message_cap {} and ms_dispatch_throttle_bytes are \
             not enforced: the per-core client ingress pools bound messages in flight (adr 0175)",
            size_cap,
            write_cap,
            self.conf.u64("osd_client_message_cap", 256)
        ));
    }

    /// Once per value: a [`crate::config::NO_EFFECT`] option at a non-default value (local file, mon config db or
    /// runtime) gets a loud line in the log and the cluster log; the option keeps being reported. Control core only.
    pub(crate) fn no_effect_guard(&mut self) {
        if !self.is_control() {
            return;
        }
        let mut seen = std::mem::take(&mut self.no_effect_seen);
        for w in self.conf.no_effect_warnings(&mut seen) {
            self.clog(messages::clog::WARN, &w);
            self.logl(0, w);
        }
        self.no_effect_seen = seen;
    }

    /// Once per value: `ms_crc_data=false` drops the msgr2 segment CRCs, so frame integrity rests on TCP checksums and
    /// NIC offloads only; a mixed cluster breaks one-way (a 0-crc sender against a verifying receiver faults at the
    /// first frame). Loud, because nothing on the wire announces it. Control core only.
    pub(crate) fn crc_data_note(&mut self, crc_data: bool) {
        if !self.is_control() || self.crc_data_noted == Some(crc_data) {
            return;
        }
        self.crc_data_noted = Some(crc_data);
        if !crc_data {
            self.logl(
                0,
                "WARNING ms_crc_data is false: msgr2 does not compute or verify segment CRCs, so frame integrity \
                 rests on TCP/NIC checksums only; set it true unless every daemon of the cluster also runs with it \
                 off (applies to connections created from now on)",
            );
        }
    }

    /// The config changed at runtime (`config set`, `injectargs`, mon config): re-read what we interpret.
    pub(crate) fn conf_changed(&mut self) {
        self.refresh_obs_conf();
        for o in Self::change_observers() {
            (o.apply)(self);
        }
    }

    /// Execute one JSON command. `Some((r, rs, output))` = answered; `None` = a scattered command that answers later.
    #[cfg(test)]
    pub(crate) fn run_command(&mut self, json_cmd: &str, to: &ReplyTo) -> Option<Res> {
        match serde_json::from_str::<Value>(json_cmd) {
            Ok(v) => self.run_parsed(v, to),
            Err(_) => Some(malformed_command()),
        }
    }

    fn run_parsed(&mut self, v: Value, to: &ReplyTo) -> Option<Res> {
        let mut v = match self.store_id.internal_command(v) {
            Ok(v) => crate::tellx::normalize(v),
            Err(p) => {
                return Some((
                    EINVAL,
                    format!("unknown command prefix {p}"),
                    Out::default(),
                ));
            }
        };
        if let Err(reason) = validate_command(&mut v) {
            return Some((EINVAL, reason.into(), Out::default()));
        }
        let prefix = v
            .get("prefix")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let arg = |k: &str| v.get(k).and_then(Value::as_str).map(ToOwned::to_owned);
        let scattered = matches!(
            prefix.as_str(),
            "dump_ops_in_flight"
                | "ops"
                | "dump_blocked_ops"
                | "dump_historic_ops"
                | "dump_historic_ops_by_duration"
                | "dump_historic_slow_ops"
                | "dump_pgs"
                | "dump_scrubs"
                | "dump_op_traces"
                | "trace_summary"
                | "trace_reset"
                | "flush_pg_stats"
        ) || (prefix == "pg" && arg("cmd").as_deref() == Some("query"))
            || crate::tellx::is_scattered(&prefix, &v);
        if scattered {
            return self.scatter(&v, to);
        }
        Some(match prefix.as_str() {
            "get_command_descriptions" => Self::ok(descriptions(self.store_id)),
            "help" => {
                // two signatures may share their words (`pg`): the map keeps one help text, so a later empty one must
                // not erase the first
                let mut m: serde_json::Map<String, Value> = serde_json::Map::new();
                for c in CMDS {
                    m.entry(self.store_id.external_words(c.words).join(" "))
                        .or_insert_with(|| json!(self.store_id.help(c.help)));
                }
                Self::ok(Value::Object(m))
            }
            "version" => Self::ok(json!({
                "version": version::CEPH_VERSION_SHORT,
                "release": version::CEPH_RELEASE,
                "release_type": "dev",
                "flashstore_version": version::FLASHSTORE_VERSION,
            })),
            "git_version" => Self::ok(json!({"git_version": version::CEPH_SHA})),
            // This OSD has no internal Objecter; inbound ops/recovery are separate diagnostics.
            "objecter_requests" => Self::ok(json!({"ops": [], "linger_ops": [], "pool_ops": [],
                "pool_stat_ops": [], "statfs_ops": [], "command_ops": []})),
            "status" => {
                // valid Ceph options given with `--set` that croit-flashstore-osd does not use (adr 0021 am. 60)
                let ignored_options: BTreeSet<String> = self
                    .cfg
                    .local_config
                    .iter()
                    .filter(|(k, _)| crate::config::classify(k) == crate::config::KeyClass::Ignored)
                    .map(|(k, _)| k.trim().replace([' ', '-'], "_"))
                    .collect();
                let (oldest, newest) = (
                    self.sb.mapc.keys().next().copied().unwrap_or(0),
                    self.sb.current_epoch,
                );
                Self::ok(json!({
                    "cluster_fsid": self.id.cluster_fsid.to_string(),
                    "osd_fsid": self.id.osd_fsid.to_string(),
                    "whoami": self.id.whoami,
                    "state": self.state.name(),
                    "maps": interval_str(&self.sb.mapc),
                    "oldest_map": oldest.to_string(),
                    "newest_map": newest.to_string(),
                    "cluster_osdmap_trim_lower_bound": self.sb.cluster_osdmap_trim_lower_bound,
                    "num_pgs": self.pg_num_pgs(),
                    "passive_pools": self.pg_passive_pools(),
                    "ec_pools": self.pg_ec_pools(),
                    "ec_declined": self.pg_ec_declined(),
                    "client_ops_parked": self.pg_parked_len(),
                    "client_ops_parked_total": self.pg.c.parked_ops,
                    "client_ops_dropped": self.pg.c.dropped_ops,
                    "placement": self.cfg.sys_metadata.get("flashstore_placement"),
                    "ignored_options": ignored_options,
                    "ignored_options_count": ignored_options.len(),
                    "store": crate::nvmestore::store_feature_report(),
                }))
            }
            "config get" => {
                let Some(var) = arg("var") else {
                    return Some((EINVAL, "missing var".into(), Out::default()));
                };
                match crate::schema::get(&self.conf, &self.config_meta(), &var) {
                    Some(val) => Self::ok(json!({ var: val })),
                    None => (
                        ENOENT,
                        format!("error getting '{var}': (2) No such file or directory"),
                        Out::default(),
                    ),
                }
            }
            "config set" => {
                let Some(var) = arg("var") else {
                    return Some((EINVAL, "missing var".into(), Out::default()));
                };
                let val = str_list(v.get("val")).join(" ");
                // spec osd-lifecycle.md 9.1: unknown name -ENOENT, invalid value -EINVAL, nothing changes
                if crate::config::classify(&var) == crate::config::KeyClass::Unknown {
                    return Some((
                        ENOENT,
                        format!("error setting '{var}' to '{val}': (2) No such file or directory"),
                        Out::default(),
                    ));
                }
                if range_threshold_option(&var) {
                    if self.conf.clone().set(Level::Override, &var, &val).is_err() {
                        return Some((
                            EINVAL,
                            format!("error setting '{var}' to '{val}': (22) Invalid argument"),
                            Out::default(),
                        ));
                    }
                    return self.scatter(&v, to);
                }
                // the value is parsed before the runtime guard, and the guard reads the parsed value (spec 9.2)
                match self.runtime_set(&var, &val) {
                    RuntimeSet::Effect => {
                        self.conf_changed();
                        self.publish_conf();
                    }
                    RuntimeSet::NoEffect => self.publish_conf(),
                    RuntimeSet::NoChange => {}
                    RuntimeSet::Invalid(_) => {
                        return Some((
                            EINVAL,
                            format!("error setting '{var}' to '{val}': (22) Invalid argument"),
                            Out::default(),
                        ));
                    }
                    RuntimeSet::Refused => {
                        return Some((
                            EPERM,
                            format!(
                                "error setting '{var}' to '{val}': (1) Operation not permitted"
                            ),
                            Out::default(),
                        ));
                    }
                }
                Self::ok(json!({"success": ""}))
            }
            "config unset" => {
                let Some(var) = arg("var") else {
                    return Some((EINVAL, "missing var".into(), Out::default()));
                };
                // spec 9.3: the name must match the schema exactly (-EINVAL, empty body, nothing changes)
                if !crate::config::known_name_exact(&var) {
                    return Some((
                        EINVAL,
                        format!("error unsetting '{var}': (22) Invalid argument"),
                        Out::default(),
                    ));
                }
                if range_threshold_option(&var) {
                    return self.scatter(&v, to);
                }
                // only a real override drop broadcasts; the observers run when that moves the effective value (classic
                // `SET_NO_EFFECT` when a lower layer already holds the same value)
                let before = crate::schema::current(&self.conf, &var);
                let version = self.conf.version();
                self.conf.unset(Level::Override, &var);
                if self.conf.version() != version {
                    if crate::schema::current(&self.conf, &var) != before {
                        self.conf_changed();
                    }
                    self.publish_conf();
                }
                Self::ok(json!({}))
            }
            "config show" => {
                // every schema option with its effective value, meta-expanded, plus the daemon's name and cluster
                // (spec ops-observability 6.6)
                Self::ok(json!(crate::schema::show(&self.conf, &self.config_meta())))
            }
            "config diff" => {
                Self::ok(json!({ "diff": crate::schema::diff(&self.conf, &self.config_meta()) }))
            }
            "config help" => Self::ok(json!({})),
            "injectargs" => {
                let toks = str_list(v.get("injected_args"));
                let toks: Vec<String> = toks
                    .iter()
                    .flat_map(|t| {
                        t.split_whitespace()
                            .map(ToOwned::to_owned)
                            .collect::<Vec<_>>()
                    })
                    .collect();
                // spec osd-lifecycle.md 9.1/9.2: valid tokens apply, also when a later one fails; an option whose flags
                // forbid a runtime change and that no observer tracks is refused; no value is echoed into a log line or
                // the reply
                let (pairs, bad) = crate::config::injectargs(&toks);
                let mut rs = String::new();
                let mut rc = 0;
                let mut broadcast = false;
                let mut effect = false;
                for (k, val) in pairs {
                    match self.runtime_set(&k, &val) {
                        RuntimeSet::Effect => {
                            broadcast = true;
                            effect = true;
                        }
                        RuntimeSet::NoEffect => broadcast = true,
                        RuntimeSet::NoChange => {}
                        RuntimeSet::Invalid(reason) => {
                            rs.push_str(&format!(
                                "Parse error setting {k} to '{val}' using injectargs ({reason}).\n"
                            ));
                            rc = EINVAL;
                        }
                        RuntimeSet::Refused => {
                            rs.push_str(&format!(
                                "Parse error setting {k} to '{val}' using injectargs (Configuration option '{k}' \
                                 may not be modified at runtime).\n"
                            ));
                            rc = EPERM;
                        }
                    }
                }
                if !bad.is_empty() {
                    rs.push_str(&format!(" failed to parse arguments: {}\n", bad.join(",")));
                    rc = EINVAL;
                }
                if effect {
                    self.conf_changed();
                }
                if broadcast {
                    self.publish_conf();
                }
                if rs.is_empty() {
                    Self::ok(json!({}))
                } else {
                    (rc, rs, Out::default())
                }
            }
            "send_beacon" => {
                if self.state == State::Active {
                    self.send_beacon();
                    (0, String::new(), Out::default())
                } else {
                    (-11, "not active".into(), Out::default())
                }
            }
            "debug_up_thru" => {
                // dev hook: exercises MOSDAlive end to end (peering will call queue_want_up_thru)
                let e = v.get("epoch").and_then(Value::as_u64).unwrap_or(0) as u32;
                self.want_up_thru_inner(e);
                (0, String::new(), Out::default())
            }
            "get_latest_osdmap" => {
                let e = u64::from(self.epoch()) + 1;
                self.mon_sub("osdmap", e, messages::SubItem::ONETIME);
                (0, String::new(), Out::default())
            }
            // counter documents: a snapshot here, the body is built off the cores (ctrsnap.rs)
            "perf dump" => self.counter_cmd(Doc::PerfDump, arg("logger"), arg("counter")),
            "counter dump" => self.counter_cmd(Doc::CounterDump, arg("logger"), arg("counter")),
            "perf schema" => self.counter_cmd(Doc::PerfSchema, None, None),
            "counter schema" => self.counter_cmd(Doc::CounterSchema, None, None),
            "perf histogram dump" => self.counter_cmd(Doc::HistDump, arg("logger"), arg("counter")),
            "perf histogram schema" => self.counter_cmd(Doc::HistSchema, None, None),
            "perf reset" => {
                let var = arg("var").unwrap_or_default();
                if self.perf_reset(&var) {
                    Self::ok(json!({"success": format!("perf reset {var}")}))
                } else {
                    Self::ok(json!({"error": format!("Not find: {var}")}))
                }
            }
            "log flush" => {
                crate::log_flush();
                (0, String::new(), Out::default())
            }
            "log reopen" => {
                crate::log_reopen();
                (0, String::new(), Out::default())
            }
            #[cfg(feature = "lab")]
            "lab_panic" => panic!("lab_panic: induced by tell"),
            #[cfg(feature = "lab")]
            "lab_ec_corrupt" => {
                let (Some(pg), Some(oid)) = (arg("pgid"), arg("oid")) else {
                    return Some((EINVAL, "pgid and oid needed".into(), Out::default()));
                };
                let off = v.get("off").and_then(Value::as_u64).unwrap_or(0);
                match self.pg_lab_corrupt(&pg, &oid, off) {
                    Ok(m) => (0, m, Out::default()),
                    Err(e) => (EINVAL, e, Out::default()),
                }
            }
            #[cfg(feature = "lab")]
            "lab_stall" => {
                let ms = v.get("ms").and_then(Value::as_u64).unwrap_or(0);
                self.cmds.stall_until = self.now + Duration::from_millis(ms);
                self.log(format!("lab: store completions held back for {ms} ms"));
                // the stalled completions run once the time passes
                self.xbcast(|| XMsg::LabStall(ms));
                (0, String::new(), Out::default())
            }
            "dump_osd_network" => {
                // threshold in µs: given ms, else mon_warn_on_slow_ping_time, else grace x ratio (spec 6.5)
                let given = v.get("value").and_then(Value::as_i64);
                let thr = match given {
                    // a huge (client-supplied) millisecond value saturates instead of wrapping the µs threshold
                    Some(ms) => (ms.max(0) as u64).saturating_mul(1000),
                    None => {
                        let t = self.conf.f64("mon_warn_on_slow_ping_time", 0.0);
                        if t > 0.0 {
                            (t * 1000.0) as u64
                        } else {
                            let grace = self.conf.u64("osd_heartbeat_grace", 20) as f64;
                            let ratio = self.conf.f64("mon_warn_on_slow_ping_ratio", 0.05);
                            (grace * 1e6 * ratio) as u64
                        }
                    }
                };
                let now_s = self.wall().sec;
                let stale = self.conf.u64("osd_heartbeat_stale", 600) as u32;
                let mut rows: Vec<crate::hb::PingRow> = self
                    .ping_dump_rows()
                    .into_iter()
                    .filter(|r| u64::from(r.ping) >= thr)
                    .collect();
                rows.sort_by(|a, b| {
                    b.ping
                        .cmp(&a.ping)
                        .then(b.osd.cmp(&a.osd))
                        .then(b.back.cmp(&a.back))
                });
                let secs = |us: u32| json!(f64::from(us) / 1000.0);
                let tri = |a: [u32; 3]| json!({"1min": secs(a[0]), "5min": secs(a[1]), "15min": secs(a[2])});
                let e: Vec<Value> = rows
                    .into_iter()
                    .map(|r| {
                        let (osd, back, avg, mn, mx, last) =
                            (r.osd, r.back, r.avg, r.min, r.max, r.last);
                        let last_update = r.last_update;
                        json!({
                            "last update": crate::tellx::ctime_str(last_update),
                            "stale": now_s.saturating_sub(last_update) > stale,
                            "from osd": self.id.whoami,
                            "to osd": osd,
                            "interface": if back { "back" } else { "front" },
                            "average": tri(avg),
                            // classic writes the max arrays under "min" (reference bug); we report the real minima
                            "min": tri(mn),
                            "max": tri(mx),
                            "last": secs(last),
                        })
                    })
                    .collect();
                Self::ok(json!({"threshold": thr / 1000, "entries": e}))
            }
            "pg" => (
                EINVAL,
                format!("unsupported pg command {:?}", arg("cmd")),
                Out::default(),
            ),
            "scrub" | "deep-scrub" | "repair" => {
                let (r, rs) = self.pg_scrub_tell(
                    prefix != "scrub",
                    prefix == "repair",
                    arg("pgid").as_deref().filter(|p| !p.is_empty()),
                );
                (r, rs, Out::default())
            }
            "list_devices" => Self::ok(match nvme::health::device() {
                Some(d) if !d.ident.device_id().is_empty() => {
                    json!([{"device": d.node(), "device_id": d.ident.device_id()}])
                }
                _ => json!([]),
            }),
            "dump_blocklist" => Self::ok(self.map.as_deref().map_or_else(
                || json!({"blocklist": [], "range_blocklist": []}),
                blocklist_json,
            )),
            "smart" => {
                // devicehealth: {devid: smartctl-json}; optional `devid` filter
                let want = arg("devid").unwrap_or_default();
                let mut m = serde_json::Map::new();
                if let (Some(d), Some(j)) = (nvme::health::device(), nvme::health::smart_json()) {
                    let id = d.ident.device_id();
                    if !id.is_empty()
                        && (want.is_empty() || want == id)
                        && let Ok(v) = serde_json::from_str::<Value>(&j)
                    {
                        m.insert(id, v);
                    }
                }
                Self::ok(Value::Object(m))
            }
            "bench" => return self.start_bench(&v, to),
            p => match self.run_ext(p, &v) {
                Some(r) => r,
                None => (
                    EINVAL,
                    format!("unknown command prefix {p}"),
                    Out::default(),
                ),
            },
        })
    }
}

/// `dump_blocklist` (classic OSD asok form): entries and ranges of the current map with their expiry.
fn blocklist_json(m: &osdmap::OsdMap) -> Value {
    let ent = |l: &std::collections::BTreeMap<denc::types::EntityAddr, denc::types::UTime>| -> Vec<Value> {
        l.iter()
            .map(|(a, t)| json!({"entity_addr_t": addr_json(a), "expire_time": crate::pgs::utime_str(*t)}))
            .collect()
    };
    json!({"blocklist": ent(&m.blocklist), "range_blocklist": ent(m.range_blocklist())})
}

/// classic `entity_addr_t::dump`: type name, `ip:port` (`[ip6]:port`), nonce.
pub(crate) fn addr_json(a: &denc::types::EntityAddr) -> Value {
    use denc::types::EntityAddr as A;
    let ty = match a.ty {
        A::TYPE_NONE => "none",
        A::TYPE_LEGACY => "v1",
        A::TYPE_MSGR2 => "v2",
        A::TYPE_ANY => "any",
        A::TYPE_CIDR => "cidr",
        _ => "???",
    };
    let sa = match (a.ipv4(), a.ipv6()) {
        (Some(ip), _) => format!("{}:{}", std::net::Ipv4Addr::from(ip), a.port()),
        (_, Some(ip)) => format!("[{}]:{}", std::net::Ipv6Addr::from(ip), a.port()),
        _ => format!("(unrecognized address family {})", a.family),
    };
    json!({"type": ty, "addr": sa, "nonce": a.nonce})
}

/// Per-request op limits from the classic `osd_max_*` options (defaults = [`opexec::Limits::default`]).
/// `osd_client_message_size_cap` as the public links' alone threshold (spec msgr2.md 8.2). 0 = no cap, as classic reads
/// it (the throttle is off). The built-in default lives in [`crate::config::DEFAULTS`] only.
fn client_message_size_cap(c: &crate::config::ConfigDb) -> u64 {
    match c.u64("osd_client_message_size_cap", 0) {
        0 => u64::MAX,
        n => n,
    }
}

fn op_limits(c: &crate::config::ConfigDb) -> opexec::Limits {
    let d = opexec::Limits::default();
    let us = |k: &str, v: usize| c.u64(k, v as u64) as usize;
    let secs = |k: &str, v: u32| c.u64(k, u64::from(v)).min(u64::from(u32::MAX)) as u32;
    opexec::Limits {
        max_write_size: (c.u64("osd_max_write_size", (d.max_write_size >> 20) as u64) as usize)
            .saturating_mul(1 << 20),
        max_object_size: c.u64("osd_max_object_size", d.max_object_size),
        max_oid_len: us("osd_max_object_name_len", d.max_oid_len),
        max_nspace_len: us("osd_max_object_namespace_len", d.max_nspace_len),
        max_attr_name_len: us("osd_max_attr_name_len", d.max_attr_name_len),
        max_attr_size: c.u64("osd_max_attr_size", d.max_attr_size),
        max_pgls: c.u64("osd_max_pgls", d.max_pgls),
        max_omap_entries: us("osd_max_omap_entries_per_request", d.max_omap_entries),
        max_omap_bytes: us("osd_max_omap_bytes_per_request", d.max_omap_bytes),
        max_write_op_reply_len: us("osd_max_write_op_reply_len", d.max_write_op_reply_len),
        default_notify_timeout: secs("osd_default_notify_timeout", d.default_notify_timeout),
        client_watch_timeout: secs("osd_client_watch_timeout", d.client_watch_timeout),
        backoff_on_degraded: c.bool("osd_backoff_on_degraded", d.backoff_on_degraded),
        backoff_on_unfound: c.bool("osd_backoff_on_unfound", d.backoff_on_unfound),
    }
}

/// `1,2` for replicas, `1(s0),3(s2)` for EC shards.
pub(crate) fn waiting_text(w: &[denc::types::PgShard]) -> String {
    w.iter()
        .map(|p| {
            if p.shard == denc::types::ShardId::NO_SHARD {
                p.osd.to_string()
            } else {
                format!("{}(s{})", p.osd, p.shard.0)
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use denc::types::{EntityAddr, UTime};

    #[test]
    fn command_validation_preserves_classic_valid_forms() {
        for mut cmd in [
            json!({"prefix": "injectargs"}),
            json!({"prefix": "injectargs", "injected_args": []}),
            json!({"prefix": "config set", "var": "debug_osd", "val": ["1/5"]}),
            json!({"prefix": "config set", "var": "debug_osd", "val": "1/5"}),
            json!({"prefix": "injectargs", "injected_args": "--debug_osd=1"}),
            json!({"prefix": "bench", "count": i64::MAX}),
            json!({"prefix": "heap", "heapcmd": "stats"}),
            json!({"prefix": "pg", "cmd": "log", "pgid": "1.0"}),
            json!({"prefix": "pg", "cmd": "scrub-abort", "pgid": "1.0"}),
            json!({"prefix": "version", "extra": [1, 2]}),
        ] {
            assert_eq!(validate_command(&mut cmd), Ok(()), "{cmd}");
        }
        let mut cmd = json!({"prefix": "store free", "extents": "--extents"});
        assert_eq!(validate_command(&mut cmd), Ok(()));
        assert_eq!(cmd["extents"], true);
    }

    #[test]
    fn command_validation_rejects_bad_headers_and_value_shapes() {
        for mut cmd in [
            json!(null),
            json!([]),
            json!({"prefix": "version", "extra": null}),
            json!({"prefix": "version", "extra": {"nested": 1}}),
            json!({"prefix": "injectargs", "injected_args": [true]}),
            json!({"prefix": "injectargs", "injected_args": ["--debug_osd=1", 3]}),
        ] {
            assert_eq!(validate_command(&mut cmd), Err("invalid json"), "{cmd}");
        }
        for mut cmd in [
            json!({"prefix": 1}),
            json!({"prefix": "version", "format": false}),
        ] {
            assert_eq!(
                validate_command(&mut cmd),
                Err("invalid json, missing format and/or prefix")
            );
        }
        let mut cmd = json!({"prefix": "heap", "heapcmd": "wrong"});
        assert_eq!(validate_command(&mut cmd), Err("invalid command json"));
        let mut cmd = json!({"prefix": "config set", "var": "debug_osd", "val": 5});
        assert_eq!(validate_command(&mut cmd), Err("invalid command json"));
        let mut cmd = json!({"prefix": "bench", "count": [4096]});
        assert_eq!(validate_command(&mut cmd), Err("invalid command json"));
    }

    #[test]
    fn dump_blocklist_classic_form() {
        let mut m = osdmap::OsdMap::default();
        m.blocklist.insert(
            EntityAddr::v4(EntityAddr::TYPE_ANY, 77, [10, 1, 2, 3], 0),
            UTime {
                sec: 86_400,
                nsec: 0,
            },
        );
        let mut ip6 = [0u8; 16];
        ip6[0] = 0xfd;
        m.insert_range_blocklist(
            EntityAddr::v6(EntityAddr::TYPE_CIDR, 8, ip6, 0, 0),
            UTime::default(),
        );
        let v = blocklist_json(&m);
        assert_eq!(
            v["blocklist"][0],
            json!({"entity_addr_t": {"type": "any", "addr": "10.1.2.3:0", "nonce": 77},
                "expire_time": "1970-01-02T00:00:00.000000+0000"})
        );
        assert_eq!(
            v["range_blocklist"][0]["entity_addr_t"],
            json!({"type": "cidr", "addr": "[fd00::]:0", "nonce": 8})
        );
    }

    /// `osd_client_message_size_cap` 0 = no cap, as classic reads it; the built-in default comes from the table.
    #[test]
    fn client_message_size_cap_zero_is_no_cap() {
        let mut c = crate::config::ConfigDb::default();
        assert_eq!(client_message_size_cap(&c), 524_288_000);
        c.set(
            crate::config::Level::Mon,
            "osd_client_message_size_cap",
            "0",
        )
        .unwrap();
        assert_eq!(client_message_size_cap(&c), u64::MAX);
        c.set(
            crate::config::Level::Mon,
            "osd_client_message_size_cap",
            "8M",
        )
        .unwrap();
        assert_eq!(client_message_size_cap(&c), 8 << 20);
    }
}
