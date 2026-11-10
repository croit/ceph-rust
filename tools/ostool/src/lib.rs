// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! ostool: offline operator tool on an croit-flashstore-osd store, parity subset of `ceph-objectstore-tool`
//! (doc/spec/objectstore-tool.md, doc/ops/objectstore-tool.md). Generic over the device so tests run on `SimDisk`.
//!
//! The binary (`croit-flashstore-tool objectstore`) opens the device (exclusive), mounts the store (WAL replay) and calls
//! [`run`]. Mutations go through normal store txns (WAL, crash safe); a PG import stays invisible (`_remove`
//! marker) until its last atomic txn.

mod cmds;
pub mod fmt;
mod import;
pub mod json;
mod objs;
mod pg;
mod repair;

use denc::types::{CollT, Ghobject, SpgT};
use osd::meta::MetaStore;
use osd::nvmestore::NvmeMeta;
use std::io::{Read, Write};
use store::dev::{BlockDev, Clock};
use store::obj::ObjError;
use storeadapt::StoreAdapter;

/// Failure with the process exit status (classic: 1; 10 pool gone, 11 incompatible features, 12 split/merge clash).
#[derive(Debug)]
pub struct Fail {
    pub msg: String,
    pub code: i32,
}
impl From<String> for Fail {
    fn from(msg: String) -> Self {
        Fail { msg, code: 1 }
    }
}
impl From<&str> for Fail {
    fn from(msg: &str) -> Self {
        Fail {
            msg: msg.into(),
            code: 1,
        }
    }
}
impl From<ObjError> for Fail {
    fn from(e: ObjError) -> Self {
        Fail {
            msg: format!("store: {e}"),
            code: 1,
        }
    }
}
impl From<std::io::Error> for Fail {
    fn from(e: std::io::Error) -> Self {
        Fail {
            msg: format!("io: {e}"),
            code: 1,
        }
    }
}
pub type R<T = ()> = Result<T, Fail>;
pub(crate) fn fail<T>(m: impl Into<String>) -> R<T> {
    Err(Fail {
        msg: m.into(),
        code: 1,
    })
}
pub(crate) fn fail_code<T>(code: i32, m: impl Into<String>) -> R<T> {
    Err(Fail {
        msg: m.into(),
        code,
    })
}

/// Largest input read into memory at once (superblock, OSDMap, `set-bytes` payload, one metadata section): Ceph's
/// default `osd_max_object_size`. Bigger inputs are refused instead of being buffered; streamed object data (import
/// DATA sections) is bounded by the store format only ([`store::MAX_OBJECT_BYTES`]).
pub const MAX_INPUT: u64 = 128 << 20;

/// Read a whole input stream, refusing more than `limit` bytes (only one byte above the limit is read).
pub(crate) fn read_capped(r: &mut dyn Read, limit: u64, what: &str) -> R<Vec<u8>> {
    let mut v = Vec::new();
    let n = r
        .take(limit + 1)
        .read_to_end(&mut v)
        .map_err(|e| format!("{what}: {e}"))?;
    if n as u64 > limit {
        return fail(format!("{what}: more than {limit} bytes (refused)"));
    }
    Ok(v)
}

/// Open a named output (`--file`, `get-bytes FILE`) without replacing anything: a new path is created exclusively;
/// an existing path is accepted only when `stream` allows it and it is a FIFO (a stream consumer such as `ssh`). An
/// existing regular file (a previous backup), a symlink to one, a device or anything else is refused before a byte is
/// written. The type check runs on the opened descriptor, so a path swapped after the lookup cannot slip through.
pub(crate) fn create_output(path: &str, stream: bool) -> R<std::fs::File> {
    use std::os::unix::fs::FileTypeExt;
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(f) => return Ok(f),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return fail(format!("file: {path}: {e}")),
    }
    let refused = || {
        fail(format!(
            "file: {path}: File exists (named output must be a new path or a FIFO)"
        ))
    };
    // checked before open: opening a FIFO blocks until its reader appears, opening a device has side effects
    if !stream || !std::fs::metadata(path).is_ok_and(|m| m.file_type().is_fifo()) {
        return refused();
    }
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| format!("file: {path}: {e}"))?;
    if !f.metadata()?.file_type().is_fifo() {
        return refused();
    }
    Ok(f)
}

/// Read a whole `--file`, refusing a file above `limit` from its metadata (before it is read).
pub(crate) fn read_capped_file(p: &str, limit: u64) -> R<Vec<u8>> {
    let f = std::fs::File::open(p).map_err(|e| format!("file: {p}: {e}"))?;
    let len = f.metadata().map_err(|e| format!("file: {p}: {e}"))?.len();
    if len > limit {
        return fail(format!(
            "file: {p}: {len} bytes exceeds the {limit} byte limit"
        ));
    }
    read_capped(&mut &f, limit, p)
}

/// Command line (classic option names).
#[derive(Debug, Default, Clone)]
pub struct Opts {
    pub op: Option<String>,
    pub pgid: Option<String>,
    pub file: Option<String>,
    pub force: bool,
    pub dry_run: bool,
    pub debug: bool,
    /// Output mode: `json-pretty` (default; legacy listing records), `json`, or `plain`.
    pub format: String,
    pub epoch: Option<u32>,
    pub head: bool,
    pub namespace: Option<String>,
    pub object: Option<String>,
    pub objcmd: Option<String>,
    pub arg1: Option<String>,
    pub arg2: Option<String>,
    /// stdout is a terminal: no binary data, binary values are escaped.
    pub tty: bool,
    /// stdin is a terminal: refuse to read values from it.
    pub stdin_tty: bool,
    /// Entries to keep for `trim-pg-log` (classic: `osd_max_pg_log_entries`).
    pub max_entries: Option<u64>,
    /// Dups to keep for `trim-pg-log-dups` (classic: `osd_pg_log_dups_tracked`).
    pub max_dups: Option<u64>,
    /// Seconds above which an omap listing counts as slow for `list-slow-omap` (classic default 16).
    pub slow_omap_threshold: Option<u64>,
    /// `update-mon-db` target (accepted only to give the explanatory refusal).
    pub mon_store_path: Option<String>,
    /// Shards to skip for a degraded read-only mount (`--skip-shard N`, repeatable).
    pub skip_shards: Vec<u32>,
    /// Explicit shard selection for a degraded read-only mount (`--shards LIST`, comma list).
    pub shards: Vec<u32>,
}

/// Exit status of a degraded read-only mount (`--skip-shard` / `--shards`) that refuses an operation: a mutating op,
/// or a read of a PG whose shard is skipped.
pub const EXIT_DEGRADED: i32 = 4;

/// Does the invocation write to the store (a normal store txn, a PG removal or the superblock/maps)?
pub fn mutating(o: &Opts) -> bool {
    matches!(
        o.op.as_deref(),
        Some(
            "import"
                | "remove"
                | "export-remove"
                | "mark-complete"
                | "reset-last-complete"
                | "trim-pg-log"
                | "trim-pg-log-dups"
                | "fix-lost"
                | "set-osdmap"
                | "set-inc-osdmap"
                | "set-superblock"
        )
    ) || matches!(
        o.objcmd.as_deref(),
        Some(
            "set-bytes"
                | "set-size"
                | "corrupt-size"
                | "clear-data-digest"
                | "clear-snapset"
                | "remove-clone-metadata"
                | "set-attr"
                | "rm-attr"
                | "set-omap"
                | "rm-omap"
                | "set-omaphdr"
                | "remove"
                | "removeall"
        )
    )
}

impl Opts {
    /// Parse the arguments after `objectstore` (device options are handled by the caller and skipped here).
    pub fn parse(a: &[String]) -> Result<Opts, String> {
        let a = outfmt::normalize_args(a);
        let a = a.as_slice();
        let mut o = Opts {
            format: "json-pretty".into(),
            ..Default::default()
        };
        let mut pos: Vec<String> = Vec::new();
        let mut i = 0;
        let val = |i: &mut usize, k: &str| -> Result<String, String> {
            *i += 1;
            a.get(*i).cloned().ok_or(format!("{k} needs a value"))
        };
        while i < a.len() {
            let k = a[i].as_str();
            match k {
                "--op" => o.op = Some(val(&mut i, k)?),
                "--pgid" => o.pgid = Some(val(&mut i, k)?),
                "--file" => o.file = Some(val(&mut i, k)?),
                "--format" => o.format = val(&mut i, k)?,
                "--epoch" => {
                    o.epoch = Some(
                        val(&mut i, k)?
                            .parse()
                            .map_err(|_| "bad --epoch".to_string())?,
                    )
                }
                "--namespace" => o.namespace = Some(val(&mut i, k)?),
                "--max-entries" => {
                    o.max_entries = Some(val(&mut i, k)?.parse().map_err(|_| "bad --max-entries")?)
                }
                "--max-dups" => {
                    o.max_dups = Some(val(&mut i, k)?.parse().map_err(|_| "bad --max-dups")?)
                }
                "--slow-omap-threshold" => {
                    o.slow_omap_threshold = Some(
                        val(&mut i, k)?
                            .parse()
                            .map_err(|_| "bad --slow-omap-threshold")?,
                    )
                }
                "--mon-store-path" => o.mon_store_path = Some(val(&mut i, k)?),
                "--skip-shard" => o.skip_shards.push(
                    val(&mut i, k)?
                        .parse()
                        .map_err(|_| "bad --skip-shard (expected a shard id)".to_string())?,
                ),
                "--shards" => {
                    o.shards = val(&mut i, k)?
                        .split(',')
                        .map(|s| {
                            s.trim()
                                .parse::<u32>()
                                .map_err(|_| format!("bad --shards list entry {s:?}"))
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                }
                "--force" => o.force = true,
                "--dry-run" => o.dry_run = true,
                "--debug" => o.debug = true,
                "--head" => o.head = true,
                "--tty" => o.tty = true,
                // device selection is the caller's; classic no-ops
                "--dev" | "--id" | "--cluster" | "--conf" | "--data-path" | "--type" => {
                    val(&mut i, k)?;
                }
                "--no-mon-config"
                | "--no-superblock"
                | "--skip-journal-replay"
                | "--skip-mount-omap" => {}
                s if s.starts_with("--") => return Err(format!("unknown option {s}")),
                _ => pos.push(a[i].clone()),
            }
            i += 1;
        }
        let mut it = pos.into_iter();
        o.object = it.next();
        o.objcmd = it.next();
        o.arg1 = it.next();
        o.arg2 = it.next();
        if it.next().is_some() {
            return Err("too many positional arguments".into());
        }
        // one writer decides the shape: the tool emits JSON documents only (no record stream)
        match outfmt::Format::parse(&o.format) {
            Some(outfmt::Format::Plain | outfmt::Format::Json | outfmt::Format::JsonPretty) => {}
            _ => return Err(format!("unrecognized format: {}", o.format)),
        }
        Ok(o)
    }

    /// A degraded read-only mount was requested (`--skip-shard` or `--shards`).
    pub fn degraded(&self) -> bool {
        !self.skip_shards.is_empty() || !self.shards.is_empty()
    }

    /// Is shard `s` excluded by the operator's selection (never opened in a degraded session)?
    pub fn excludes_shard(&self, s: u32) -> bool {
        (!self.shards.is_empty() && !self.shards.contains(&s)) || self.skip_shards.contains(&s)
    }
}

/// Everything a command needs.
#[expect(missing_debug_implementations)]
pub struct Ctx<'a, D: BlockDev, C: Clock> {
    pub ad: &'a StoreAdapter<D, C>,
    pub meta: &'a mut NvmeMeta<D, C>,
    pub o: &'a Opts,
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
    pub input: Option<Box<dyn Read + 'a>>,
}

pub const USAGE: &str = "usage: croit-flashstore-tool objectstore (--dev SPEC | --id N | --data-path DIR) [--op OP] [--pgid PGID] [--file F] \
[--force] [--dry-run] [--format plain|json|json-pretty] [--epoch E] [--head] [--namespace NS] [--debug] \
[--skip-shard N]... [--shards LIST]\n\
  OP: list list-pgs info log meta-list dump-super statfs fsck fsck-deep export export-remove import remove mark-complete\n\
      reset-last-complete trim-pg-log trim-pg-log-dups fix-lost get-osdmap set-osdmap get-inc-osdmap set-inc-osdmap\n\
      get-superblock set-superblock dump-export list-slow-omap [--slow-omap-threshold S] update-mon-db (refused)\n\
  object commands: <object> (get|set)-bytes [file] | (get|set|rm)-(attr|omap) <key> [file] | get-omaphdr | set-omaphdr [file] |\n\
      list-attrs | list-omap | remove | removeall | dump | set-size <n> | clear-data-digest |\n\
      clear-snapset [corrupt|seq|snaps|clones|clone_size|clone_overlap|size] | remove-clone-metadata <cloneid>\n\
  <object>: name, JSON from --op list, or '' (pgmeta, needs --pgid). See doc/ops/objectstore-tool.md";

/// Run one invocation; returns the process exit status. `dry-run` and all safety checks live below.
pub fn run<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>) -> i32 {
    match dispatch(c) {
        Ok(()) => {
            if c.o.dry_run {
                let _ = if c.o.op.as_deref() == Some("export") {
                    writeln!(c.err, "dry-run: Nothing changed")
                } else {
                    writeln!(c.out, "dry-run: Nothing changed")
                };
            }
            0
        }
        Err(f) => {
            let _ = writeln!(c.err, "{}", f.msg);
            f.code
        }
    }
}

fn dispatch<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>) -> R {
    // Degraded read-only mount: every write op is refused up front with the same exit code, before any store access
    // beyond the mount. Repair/upgrade are separate tool subcommands and never combine with `--skip-shard`/`--shards`.
    if c.o.degraded() && mutating(c.o) {
        let what =
            c.o.op
                .clone()
                .or_else(|| c.o.objcmd.clone())
                .unwrap_or_default();
        return fail_code(
            EXIT_DEGRADED,
            format!(
                "--op {what} writes to the store and is refused on a degraded read-only mount (--skip-shard/--shards); \
                 only read-only ops (list-pgs, list, export, info, log, fsck, statfs, ...) are allowed"
            ),
        );
    }
    if c.o.degraded() {
        // every op of a degraded session (listings, fsck, statfs, ...) covers the mounted shards only: name the
        // excluded ones so no result is silently partial
        let nshards = c.ad.with_store(|s| s.nshards());
        for shard in (0..nshards as u32).filter(|s| c.o.excludes_shard(*s)) {
            writeln!(
                c.err,
                "shard {shard} skipped (degraded read-only mount): its PGs and objects are not included"
            )?;
        }
    }
    let op = c.o.op.clone();
    if let Some(op) = op.as_deref() {
        match op {
            "list" => return objs::op_list(c),
            "list-pgs" => return pg::op_list_pgs(c),
            "info" => return pg::op_info(c),
            "log" => return pg::op_log(c),
            "meta-list" => return objs::op_meta_list(c),
            "export" | "export-remove" => return pg::op_export(c, op == "export-remove"),
            "import" => return import::op_import(c),
            "remove" => return pg::op_remove(c),
            "mark-complete" => return pg::op_mark_complete(c),
            "reset-last-complete" => return pg::op_reset_last_complete(c),
            "trim-pg-log" => return pg::op_trim_log(c),
            "trim-pg-log-dups" => return pg::op_trim_dups(c),
            "fix-lost" => return objs::op_fix_lost(c),
            "list-slow-omap" => return repair::op_list_slow_omap(c),
            "update-mon-db" => return repair::op_update_mon_db(c),
            "dump-export" => return import::op_dump_export(c),
            "fsck" | "fsck-deep" => return cmds::op_fsck(c, op == "fsck-deep"),
            "statfs" => return cmds::op_statfs(c),
            "dump-super" => return cmds::op_dump_super(c),
            "get-superblock" => return cmds::op_get_super(c),
            "set-superblock" => return cmds::op_set_super(c),
            "get-osdmap" => return cmds::op_get_map(c, false),
            "set-osdmap" => return cmds::op_set_map(c, false),
            "get-inc-osdmap" => return cmds::op_get_map(c, true),
            "set-inc-osdmap" => return cmds::op_set_map(c, true),
            "mkfs"
            | "repair"
            | "repair-deep"
            | "fuse"
            | "dup"
            | "extend-log-with-fake-entries"
            | "pg-log-inject-dups"
            | "dump-journal-mount" => {
                return fail(format!(
                    "--op {op} is not supported on croit-flashstore-osd (see doc/spec/objectstore-tool.md 8)"
                ));
            }
            _ => return fail(format!("unknown --op {op}\n{USAGE}")),
        }
    }
    if c.o.objcmd.is_some() {
        return objs::object_cmd(c);
    }
    fail(format!("Must provide --op or an object command\n{USAGE}"))
}

/// The OSD superblock (required by most ops).
pub(crate) fn superblock<D: BlockDev, C: Clock>(c: &Ctx<'_, D, C>) -> R<messages::OsdSuperblock> {
    match c.meta.load_superblock() {
        Ok(Some(sb)) => Ok(sb),
        Ok(None) => fail("Failure to read OSD superblock: not found (OSD never booted?)"),
        Err(e) => fail(format!("Failure to read OSD superblock: {e}")),
    }
}

/// All PG collections.
pub(crate) fn pg_colls<D: BlockDev, C: Clock>(c: &Ctx<'_, D, C>) -> R<Vec<SpgT>> {
    let mut v: Vec<SpgT> =
        c.ad.with_store(|s| s.list_colls())?
            .into_iter()
            .filter_map(|x| match x {
                CollT::Pg(s) => Some(s),
                _ => None,
            })
            .collect();
    v.sort_by_key(|s| (s.pgid.pool, s.pgid.seed, s.shard.0));
    Ok(v)
}

/// Objects of `cid` in order, batch by batch (`f` returns false to stop).
pub(crate) fn walk<D: BlockDev, C: Clock>(
    ad: &StoreAdapter<D, C>,
    cid: CollT,
    mut f: impl FnMut(Ghobject) -> R<bool>,
) -> R {
    let mut cur = Ghobject::MIN();
    loop {
        let (objs, next) = ad.with_store(|s| s.list(&cid, &cur, None, 128))?;
        for o in objs {
            if !f(o)? {
                return Ok(());
            }
        }
        match next {
            Some(n) => cur = n,
            None => return Ok(()),
        }
    }
}

/// `--op dump-export` without a store; returns the exit status.
pub fn dump_export_cmd(
    o: &Opts,
    input: Box<dyn Read + '_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    match import::dump_export(o, Some(input), out) {
        Ok(()) => 0,
        Err(f) => {
            let _ = writeln!(err, "dump-export: {}", f.msg);
            1
        }
    }
}

/// After a mutation (not dry-run): checkpoint so the next mount needs no WAL replay.
pub(crate) fn checkpoint<D: BlockDev, C: Clock>(c: &Ctx<'_, D, C>) -> R {
    if c.o.dry_run {
        return Ok(());
    }
    c.ad.with_store(|s| s.checkpoint())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::read_capped;

    /// A stream input stops one byte above the limit instead of reading (or allocating) the rest.
    #[test]
    fn read_capped_bounds_a_stream() {
        let mut fits = std::io::Cursor::new(vec![7u8; 8]);
        assert_eq!(read_capped(&mut fits, 8, "stdin").unwrap(), vec![7; 8]);
        let mut over = std::io::Cursor::new(vec![0u8; 1000]);
        let e = read_capped(&mut over, 8, "stdin").unwrap_err();
        assert!(e.msg.contains("more than 8 bytes"), "{}", e.msg);
        assert_eq!(over.position(), 9);
    }
}
