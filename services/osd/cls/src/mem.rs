// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! In-memory [`ClsCtx`] with the message-start view semantics (cls.md s4), for unit/scenario tests
//! and the differential harness. Lab backend (adr 0024): behind feature `mem`, never in prod.
//!
//! Model: one [`MemCtx`] per message and target object. `start` = committed object at message
//! start (all CONTENT reads), `cur` = the object after the writes of this message so far (existence,
//! size, mtime, snapset seq, and where writes land). [`MemStore::commit`] publishes `cur`.

use crate::config::ClsConfig;
use crate::ctx::{ClsCtx, OmapMap, Origin, SCAN_PAGE, Stat, Watcher, release};
use crate::errno::*;
use crate::registry::{self, Reply};
use denc::types::{EntityAddr, EntityName, UTime};
use std::collections::BTreeMap;
use std::ops::Bound;

/// One stored object.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Obj {
    pub data: Vec<u8>,
    pub xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
    pub omap: OmapMap,
    pub omap_header: Vec<u8>,
    pub mtime: UTime,
    pub snap_seq: u64,
    pub watchers: Vec<Watcher>,
}

/// Environment shared by the messages of a [`MemStore`].
#[derive(Debug, Clone)]
pub struct Env {
    pub origin: Origin,
    pub now: UTime,
    pub client_features: u64,
    pub osd_features: u64,
    pub release: u8,
    pub version: u64,
    pub rng: u64,
    /// Index of the call op inside the message (`subop_num`).
    pub subop: u32,
    pub config: ClsConfig,
    /// `osd_max_object_size`: writes/truncates that would end beyond it are `-EFBIG` (the executor's rule).
    pub max_object_size: u64,
}

impl Default for Env {
    fn default() -> Self {
        Env {
            origin: Origin {
                name: EntityName::client(4123),
                addr: EntityAddr::v4(EntityAddr::TYPE_MSGR2, 1234, [10, 0, 0, 5], 40000),
            },
            now: UTime::new(1_800_000_000, 5000),
            client_features: u64::MAX,
            osd_features: u64::MAX,
            release: release::SQUID,
            version: 0,
            rng: 0x9E37_79B9_7F4A_7C15,
            subop: 0,
            config: ClsConfig::DEFAULT,
            max_object_size: 128 << 20,
        }
    }
}

/// Object store + environment.
#[derive(Debug, Default)]
pub struct MemStore {
    pub objects: BTreeMap<String, Obj>,
    pub env: Env,
}

impl MemStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a message on `oid`.
    pub fn begin(&self, oid: &str) -> MemCtx {
        let start = self.objects.get(oid).cloned();
        MemCtx {
            cur: start.clone(),
            start,
            env: self.env.clone(),
            nread: 0,
            nwrite: 0,
        }
    }

    /// Publish the message's writes (call only when the message succeeded).
    pub fn commit(&mut self, oid: &str, ctx: MemCtx) {
        self.env.rng = ctx.env.rng;
        match ctx.cur {
            Some(o) => {
                self.objects.insert(oid.to_owned(), o);
            }
            None => {
                self.objects.remove(oid);
            }
        }
    }

    /// One cls call as its own message; commits iff `ret >= 0`.
    pub fn call(&mut self, oid: &str, class: &str, method: &str, input: &[u8]) -> Reply {
        record(oid, class, method, input);
        let mut ctx = self.begin(oid);
        let r = ctx.call(class, method, input);
        if r.ret >= 0 {
            self.commit(oid, ctx);
        }
        r
    }

    /// Multi-op message: `f` returns the message result; commit iff `>= 0`.
    pub fn msg<R>(&mut self, oid: &str, f: impl FnOnce(&mut MemCtx) -> (i32, R)) -> (i32, R) {
        let mut ctx = self.begin(oid);
        let (ret, r) = f(&mut ctx);
        if ret >= 0 {
            self.commit(oid, ctx);
        }
        (ret, r)
    }

    pub fn obj(&self, oid: &str) -> Option<&Obj> {
        self.objects.get(oid)
    }
    pub fn omap_get(&self, oid: &str, key: &str) -> Option<&[u8]> {
        self.objects
            .get(oid)?
            .omap
            .get(key.as_bytes())
            .map(Vec::as_slice)
    }
    pub fn omap_u64(&self, oid: &str, key: &str) -> Option<u64> {
        let v = self.omap_get(oid, key)?;
        Some(u64::from_le_bytes(v.try_into().ok()?))
    }
    /// Advance the OSD clock.
    pub fn advance(&mut self, secs: u32) {
        self.env.now.sec += secs;
    }
}

/// Per-message context (see module docs).
#[derive(Debug)]
pub struct MemCtx {
    start: Option<Obj>,
    cur: Option<Obj>,
    pub env: Env,
    /// Read/write counters (cls.md s3.1); `stat` counts as neither.
    pub nread: u32,
    pub nwrite: u32,
}

impl MemCtx {
    /// Run one registered method with the executor's flag enforcement (cls.md s3 step 5):
    /// read without RD or write without WR -> `-EIO` (wins over any ret). Unknown -> EOPNOTSUPP.
    pub fn call(&mut self, class: &str, method: &str, input: &[u8]) -> Reply {
        let Some(m) = registry::lookup(class, method) else {
            return Reply {
                ret: EOPNOTSUPP,
                out: Vec::new(),
            };
        };
        let (r0, w0) = (self.nread, self.nwrite);
        let mut r = registry::call(self, m, input);
        if (self.nread > r0 && !m.rd()) || (self.nwrite > w0 && !m.wr()) {
            r.ret = EIO;
        }
        r
    }

    /// True if the message so far changed the object (non-empty transaction).
    pub fn changed(&self) -> bool {
        self.start != self.cur
    }
    /// True if the object exists after the writes of this message so far.
    pub fn exists(&self) -> bool {
        self.cur.is_some()
    }
    fn touch(&mut self) -> &mut Obj {
        let now = self.env.now;
        self.cur.get_or_insert_with(|| Obj {
            mtime: now,
            ..Default::default()
        })
    }

    /// The executor's write/truncate range check ([`Env::max_object_size`]): `-EFBIG` before any state change.
    fn efbig(&self, off: u64, len: u64) -> bool {
        let mx = self.env.max_object_size;
        off >= mx || len > mx || off.checked_add(len).is_none_or(|e| e > mx)
    }
}

impl ClsCtx for MemCtx {
    fn origin(&self) -> Origin {
        self.env.origin.clone()
    }
    fn now(&self) -> UTime {
        self.env.now
    }
    fn client_features(&self) -> u64 {
        self.env.client_features
    }
    fn osd_features(&self) -> u64 {
        self.env.osd_features
    }
    fn require_osd_release(&self) -> u8 {
        self.env.release
    }
    fn current_version(&self) -> u64 {
        self.env.version
    }
    fn subop_num(&self) -> u32 {
        // env.subop = outer ops before this call; + nested primitives so far (ctx.rs)
        self.env
            .subop
            .wrapping_add(self.nread)
            .wrapping_add(self.nwrite)
    }
    fn config(&self) -> ClsConfig {
        self.env.config
    }
    fn random_bytes(&mut self, out: &mut [u8]) {
        for b in out {
            let mut x = self.env.rng;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.env.rng = x;
            *b = (x >> 24) as u8;
        }
    }
    fn snapset_seq(&mut self) -> Result<u64, Errno> {
        self.cur.as_ref().map(|o| o.snap_seq).ok_or(ENOENT)
    }
    fn list_watchers(&mut self) -> Result<Vec<Watcher>, Errno> {
        self.nread += 1;
        self.start
            .as_ref()
            .map(|o| o.watchers.clone())
            .ok_or(ENOENT)
    }

    fn stat(&mut self) -> Result<Stat, Errno> {
        self.cur
            .as_ref()
            .map(|o| Stat {
                size: o.data.len() as u64,
                mtime: o.mtime,
            })
            .ok_or(ENOENT)
    }
    fn read(&mut self, off: u64, len: u64) -> Result<Vec<u8>, Errno> {
        self.nread += 1;
        // absent object: empty (classic: a message with a write op on a new object reads 0 bytes; recorded queue_init/rgw_gc init).
        // Read-only messages on absent objects never get here (ENOENT before any op, differential.rs rule #24).
        let Some(s) = self.start.as_ref() else {
            return Ok(Vec::new());
        };
        // Working size follows the message (cls.md s4 B4: after a remove in the message it is 0);
        // bytes always come from the committed store.
        let size = self.cur.as_ref().map_or(0, |o| o.data.len()) as u64;
        let end = if len == 0 {
            size
        } else {
            size.min(off.saturating_add(len))
        };
        if off >= end {
            return Ok(Vec::new());
        }
        let hi = (end as usize).min(s.data.len());
        let lo = (off as usize).min(hi);
        Ok(s.data[lo..hi].to_vec())
    }
    fn create(&mut self, excl: bool) -> Result<(), Errno> {
        self.nwrite += 1;
        if excl && self.cur.is_some() {
            return Err(EEXIST);
        }
        self.touch();
        Ok(())
    }
    fn remove(&mut self) -> Result<(), Errno> {
        self.nwrite += 1;
        if self.cur.is_none() {
            return Err(ENOENT);
        }
        self.cur = None;
        Ok(())
    }
    fn write(&mut self, off: u64, data: &[u8]) -> Result<(), Errno> {
        self.nwrite += 1;
        if self.efbig(off, data.len() as u64) {
            return Err(EFBIG);
        }
        let now = self.env.now;
        let o = self.touch();
        o.mtime = now;
        if data.is_empty() {
            return Ok(());
        }
        let end = off as usize + data.len();
        if o.data.len() < end {
            o.data.resize(end, 0);
        }
        o.data[off as usize..end].copy_from_slice(data);
        Ok(())
    }
    fn write_full(&mut self, data: &[u8]) -> Result<(), Errno> {
        self.nwrite += 1;
        let now = self.env.now;
        let o = self.touch();
        o.mtime = now;
        o.data = data.to_vec();
        Ok(())
    }
    fn truncate(&mut self, size: u64) -> Result<(), Errno> {
        self.nwrite += 1;
        if self.efbig(size, 0) {
            return Err(EFBIG);
        }
        let now = self.env.now;
        let o = self.touch();
        o.mtime = now;
        o.data.resize(size as usize, 0);
        Ok(())
    }
    fn zero(&mut self, off: u64, len: u64) -> Result<(), Errno> {
        self.nwrite += 1;
        if let Some(o) = self.cur.as_mut() {
            // classic munges ZERO -> TRUNCATE when the range reaches the end of the object (size shrinks to `off`)
            if off < o.data.len() as u64 && off.saturating_add(len) >= o.data.len() as u64 {
                o.data.truncate(off as usize);
                return Ok(());
            }
            let end = (off.saturating_add(len) as usize).min(o.data.len());
            if (off as usize) < end {
                o.data[off as usize..end].fill(0);
            }
        }
        Ok(())
    }

    fn getxattr(&mut self, name: &str) -> Result<Vec<u8>, Errno> {
        self.getxattr_raw(name.as_bytes())
    }
    fn setxattr(&mut self, name: &str, value: &[u8]) -> Result<(), Errno> {
        self.setxattr_raw(name.as_bytes(), value)
    }
    fn getxattr_raw(&mut self, name: &[u8]) -> Result<Vec<u8>, Errno> {
        self.nread += 1;
        let s = self.start.as_ref().ok_or(ENOENT)?;
        s.xattrs.get(name).cloned().ok_or(ENODATA)
    }
    fn getxattrs_raw(&mut self) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, Errno> {
        self.nread += 1;
        Ok(self.start.as_ref().ok_or(ENOENT)?.xattrs.clone())
    }
    fn setxattr_raw(&mut self, name: &[u8], value: &[u8]) -> Result<(), Errno> {
        self.nwrite += 1;
        self.touch().xattrs.insert(name.to_owned(), value.to_vec());
        Ok(())
    }

    fn omap_get_val(&mut self, key: &[u8]) -> Result<Vec<u8>, Errno> {
        self.nread += 1;
        let s = self.start.as_ref().ok_or(ENOENT)?;
        s.omap.get(key).cloned().ok_or(ENOENT)
    }
    fn omap_get_vals_by_keys(&mut self, keys: &[&[u8]]) -> Result<OmapMap, Errno> {
        self.nread += 1;
        let Some(s) = self.start.as_ref() else {
            return Ok(OmapMap::new()); // absent object: empty, like classic
        };
        Ok(keys
            .iter()
            .filter_map(|k| s.omap.get(*k).map(|v| (k.to_vec(), v.clone())))
            .collect())
    }
    fn omap_get_vals(
        &mut self,
        start_after: &[u8],
        filter_prefix: &[u8],
        max: u64,
    ) -> Result<(OmapMap, bool), Errno> {
        self.nread += 1;
        let Some(s) = self.start.as_ref() else {
            return Ok((OmapMap::new(), false));
        };
        let max = max.min(SCAN_PAGE) as usize;
        let mut out = OmapMap::new();
        let mut more = false;
        for (k, v) in s
            .omap
            .range::<[u8], _>((Bound::Excluded(start_after), Bound::Unbounded))
            .filter(|(k, _)| k.starts_with(filter_prefix))
        {
            if out.len() >= max {
                more = true;
                break;
            }
            out.insert(k.clone(), v.clone());
        }
        Ok((out, more))
    }
    fn omap_get_keys(
        &mut self,
        start_after: &[u8],
        max: u64,
    ) -> Result<(Vec<Vec<u8>>, bool), Errno> {
        self.nread += 1;
        let Some(s) = self.start.as_ref() else {
            return Ok((Vec::new(), false));
        };
        let max = max.min(SCAN_PAGE) as usize;
        let mut it = s
            .omap
            .range::<[u8], _>((Bound::Excluded(start_after), Bound::Unbounded))
            .map(|(k, _)| k.clone());
        let keys: Vec<_> = it.by_ref().take(max).collect();
        let more = it.next().is_some();
        Ok((keys, more))
    }
    fn omap_get_header(&mut self) -> Result<Vec<u8>, Errno> {
        self.nread += 1;
        Ok(self
            .start
            .as_ref()
            .map(|o| o.omap_header.clone())
            .unwrap_or_default())
    }
    fn omap_set(&mut self, entries: &[(&[u8], &[u8])]) -> Result<(), Errno> {
        self.nwrite += 1;
        let o = self.touch();
        for (k, v) in entries {
            o.omap.insert(k.to_vec(), v.to_vec());
        }
        Ok(())
    }
    fn omap_set_header(&mut self, header: &[u8]) -> Result<(), Errno> {
        self.nwrite += 1;
        self.touch().omap_header = header.to_vec();
        Ok(())
    }
    fn omap_remove_key(&mut self, key: &[u8]) -> Result<(), Errno> {
        self.nwrite += 1;
        let o = self.cur.as_mut().ok_or(ENOENT)?;
        o.omap.remove(key);
        Ok(())
    }
    fn omap_remove_range(&mut self, begin: &[u8], end: &[u8]) -> Result<(), Errno> {
        self.nwrite += 1;
        let o = self.cur.as_mut().ok_or(ENOENT)?;
        let ks: Vec<Vec<u8>> = o
            .omap
            .range::<[u8], _>((Bound::Included(begin), Bound::Excluded(end)))
            .map(|(k, _)| k.clone())
            .collect();
        for k in ks {
            o.omap.remove(&k);
        }
        Ok(())
    }
    fn omap_clear(&mut self) -> Result<(), Errno> {
        self.nwrite += 1;
        let o = self.cur.as_mut().ok_or(ENOENT)?;
        o.omap.clear();
        o.omap_header.clear();
        Ok(())
    }
}

// ------------------------------------------------------------------------------ call recorder
// Differential-corpus helper (lab/test only): with `CLS_RECORD_DIR=<dir>` every single-call message of
// `MemStore::call` is appended as an oprobe script statement to `<dir>/<test thread>__<oid>.ops`
// (messages separated by `---`). The scripts replay the same call sequence on a classic OSD
// (examples/capture.rs); `tests/differential.rs` then compares both. RGW-family classes only; a script
// stops at `MAX_MSGS` messages or at a call whose input exceeds `MAX_INPUT` bytes.

const MAX_MSGS: usize = 300;
const MAX_INPUT: usize = 16 * 1024;

fn record(oid: &str, class: &str, method: &str, input: &[u8]) {
    use std::io::Write;
    let Ok(dir) = std::env::var("CLS_RECORD_DIR") else {
        return;
    };
    // default: RGW family only; CLS_RECORD_CLASSES="rbd lock" selects classes explicitly (gen-rbd-ops.sh)
    match std::env::var("CLS_RECORD_CLASSES") {
        Ok(l) => {
            if !l.split_whitespace().any(|c| c == class) {
                return;
            }
        }
        Err(_) => {
            if matches!(class, "lock" | "rbd") {
                return;
            }
        }
    }
    let t = std::thread::current();
    let tname = t.name().unwrap_or("main").replace("::", "_");
    let clean: String = oid
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '-'
            }
        })
        .take(24)
        .collect();
    let path = std::path::Path::new(&dir).join(format!("{tname}__{clean}.ops"));
    let stop = path.with_extension("stop");
    if stop.exists() {
        return;
    }
    let n = std::fs::read_to_string(&path).map_or(0, |s| s.matches("\n---\n").count() + 1);
    if n >= MAX_MSGS || input.len() > MAX_INPUT {
        let _ = std::fs::write(stop, b"");
        return;
    }
    let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    else {
        return;
    };
    let sep = if n == 0 { "" } else { "---\n" };
    let arg = if input.is_empty() {
        String::new()
    } else {
        let hex: String = input.iter().map(|b| format!("{b:02x}")).collect();
        format!(" hex:{hex}")
    };
    let _ = writeln!(f, "{sep}call {class} {method}{arg}");
}
