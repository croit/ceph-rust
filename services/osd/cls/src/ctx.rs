// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! The objclass surface (spec/cls.md s4) as a trait. The OP EXECUTOR (crates/opexec) implements it;
//! `mem::MemCtx` is the in-memory reference implementation.
//!
//! Static dispatch (adr 0024): all class code is generic over `C: ClsCtx`; the registry
//! ([`crate::call`]) is a monomorphized jump table, no `dyn` anywhere on the call path.
//!
//! # View semantics (cls.md s4, CONFIRMED against classic OSD) - the implementor provides them
//! Per message there is one ctx per target object. Reads of object CONTENT (data bytes, xattr
//! values and names, omap keys/values/header) see the **committed state at message start**: they do
//! NOT observe writes made earlier in the same message (by earlier ops or earlier cls calls).
//! What earlier ops DO change for later calls: **existence** (create/remove/touch-on-write), **size**
//! and mtime (`stat`), and the SnapSet (`snapset_seq`). Writes always land in the message's single
//! transaction; a negative return from the outer method discards it (executor's job).
//!
//! # Read/write counters (cls.md s3.1)
//! Each primitive counts as READ or WRITE (marked R/W/-). The executor compares the deltas with the
//! method flags (RD/WR) and replaces the result by -EIO on a violation. `stat` counts as neither.
//!
//! # Errors
//! Negative errno values (`crate::errno`). Absent object: reads of content fail `ENOENT`
//! (omap `get_vals`/`get_keys`/`get_header` succeed empty, plain-op asymmetry), writes touch-create.

use crate::config::ClsConfig;
use crate::errno::Errno;
use denc::types::{EntityAddr, EntityName, UTime, Uuid};
use std::collections::BTreeMap;
use std::ops::ControlFlow;

/// `cls_get_request_origin`: who sent the message (authenticated entity + connection peer address).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    /// Entity name of the message source, e.g. `client.4123` (num = cephx global_id for clients).
    pub name: EntityName,
    /// Peer socket address (ip:port + nonce) of the connection that carried the MOSDOp. The type
    /// field is whatever the messenger reports (msgr2); lock forces LEGACY itself.
    pub addr: EntityAddr,
}

/// Result of `stat` (= `cls_cxx_stat2`, nanosecond mtime): size and mtime of the object **as of
/// this message so far** (not message start). mtime is the client-supplied message mtime of the
/// last write (RGW conditional ops depend on it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stat {
    pub size: u64,
    pub mtime: UTime,
}

/// One entry of `list_watchers` (`obj_list_watch_response_t` item).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Watcher {
    pub name: EntityName,
    pub cookie: u64,
    pub timeout_seconds: u32,
    pub addr: EntityAddr,
}

/// Omap listing: ordered key -> value (keys are arbitrary bytes, e.g. rbd_children).
pub type OmapMap = BTreeMap<Vec<u8>, Vec<u8>>;

/// ceph_release_t numeric values (only for `require_osd_release`).
pub mod release {
    pub const NAUTILUS: u8 = 14;
    pub const OCTOPUS: u8 = 15;
    pub const PACIFIC: u8 = 16;
    pub const QUINCY: u8 = 17;
    pub const REEF: u8 = 18;
    pub const SQUID: u8 = 19;
    pub const TENTACLE: u8 = 20;
    pub const UMBRELLA: u8 = 21;
}

pub trait ClsCtx {
    // ---------------------------------------------------------------- environment (no counters)

    /// `cls_get_request_origin`. Direct client ops only.
    fn origin(&self) -> Origin;
    /// OSD wall clock (utime). Must be constant within one message (all `now` of a message equal).
    fn now(&self) -> UTime;
    /// `cls_get_client_features`: msgr feature mask of the client connection (ADDR2 form decision).
    fn client_features(&self) -> u64;
    /// `cls_get_features`: AND of the feature bits of all up OSDs (mirror encodings only).
    fn osd_features(&self) -> u64;
    /// `cls_get_required_osd_release`: osdmap require_osd_release ([`release`]). croit-flashstore-osd: >= NAUTILUS.
    fn require_osd_release(&self) -> u8;
    /// `cls_current_version`: pg last_user_version BEFORE this message's bump.
    fn current_version(&self) -> u64;
    /// `cls_gen_random_bytes`.
    fn random_bytes(&mut self, out: &mut [u8]);
    /// `cls_get_snapset_seq`: SnapSet.seq of the object after the ops so far; `ENOENT` if the object
    /// is absent (after the current ops) or a whiteout without clones. Counter: none.
    fn snapset_seq(&mut self) -> Result<u64, Errno>;
    /// `cls_cxx_list_watchers` (R).
    fn list_watchers(&mut self) -> Result<Vec<Watcher>, Errno>;
    /// `cls_current_subop_num` = classic `processed_subop_count`: ops processed so far in the
    /// message, counting the outer ops before this one AND every nested primitive (omap/xattr/data
    /// call) made so far by class methods of this message. Grows with each primitive, so two bilog
    /// writes of one method never share an id (bilog key suffix). Default 0 (single-op contexts).
    fn subop_num(&self) -> u32 {
        0
    }
    /// `cls_get_config`: the OSD options classes read (static constants unless overridden).
    fn config(&self) -> ClsConfig {
        ClsConfig::DEFAULT
    }
    /// `cls_get_manifest_ref_count(fp_oid)`: number of manifest (dedup) references from this object
    /// to chunk `fp_oid`. croit-flashstore-osd has no manifest objects: default 0 (cas `references_chunk` -> `-ENOLINK`).
    fn manifest_ref_count(&mut self, _fp_oid: &[u8]) -> i32 {
        0
    }
    /// `CLS_LOG`. Default: discard.
    fn log(&mut self, _level: i32, _msg: &str) {}

    // ---------------------------------------------------------------- object data

    /// `cls_cxx_stat`: size/mtime as of the message so far. `ENOENT` if absent or whiteout. (-)
    fn stat(&mut self) -> Result<Stat, Errno>;
    /// `cls_cxx_read`: `len == 0` = to end. Clipped to the CURRENT size (message-so-far) but bytes
    /// come from message-start content. `ENOENT` if the object is not in the committed store. (R)
    fn read(&mut self, off: u64, len: u64) -> Result<Vec<u8>, Errno>;
    /// `cls_cxx_create`; `excl` -> `EEXIST` if the object exists (as of the message so far). (W)
    fn create(&mut self, excl: bool) -> Result<(), Errno>;
    /// `cls_cxx_remove`. `ENOENT` if absent. (W)
    fn remove(&mut self) -> Result<(), Errno>;
    /// `cls_cxx_write` (touch-creates). (W)
    fn write(&mut self, off: u64, data: &[u8]) -> Result<(), Errno>;
    /// `cls_cxx_write_full` (touch-creates). (W)
    fn write_full(&mut self, data: &[u8]) -> Result<(), Errno>;
    /// `cls_cxx_truncate`. (W)
    fn truncate(&mut self, size: u64) -> Result<(), Errno>;
    /// `cls_cxx_write_zero`. (W)
    fn zero(&mut self, off: u64, len: u64) -> Result<(), Errno>;
    /// `cls_cxx_replace`: truncate(0) then write(off, data) (two ops). (W)
    fn replace(&mut self, off: u64, data: &[u8]) -> Result<(), Errno> {
        self.truncate(0)?;
        self.write(off, data)
    }

    // ---------------------------------------------------------------- xattrs (user namespace)

    /// `cls_cxx_getxattr`: `ENODATA` attr absent, `ENOENT` object absent (in the committed store). (R)
    fn getxattr(&mut self, name: &str) -> Result<Vec<u8>, Errno>;
    /// `cls_cxx_setxattr` (touch-creates). (W)
    fn setxattr(&mut self, name: &str, value: &[u8]) -> Result<(), Errno>;

    /// Raw user xattr keys, without UTF8 conversion. Same view/errno/counters as str helpers. (R)
    fn getxattr_raw(&mut self, name: &[u8]) -> Result<Vec<u8>, Errno>;
    /// `cls_cxx_getxattrs`: all user xattrs, raw names, ordered by name. `ENOENT` if object absent. (R)
    fn getxattrs_raw(&mut self) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, Errno>;
    /// Raw user xattr key; touch-creates in this transaction. (W)
    fn setxattr_raw(&mut self, name: &[u8], value: &[u8]) -> Result<(), Errno>;

    // ---------------------------------------------------------------- omap

    /// `cls_cxx_map_get_val`: `ENOENT` if key missing OR object has no omap/absent. (R)
    fn omap_get_val(&mut self, key: &[u8]) -> Result<Vec<u8>, Errno>;
    /// `cls_cxx_map_get_vals_by_keys`: existing keys only. (R)
    fn omap_get_vals_by_keys(&mut self, keys: &[&[u8]]) -> Result<OmapMap, Errno>;
    /// `cls_cxx_map_get_vals`: entries with key > `start_after` and starting with `filter_prefix`,
    /// ascending, at most `min(max, 1024)` (osd_max_omap_entries_per_request); `more` = truncated.
    /// Absent object: empty, no error. (R)
    fn omap_get_vals(
        &mut self,
        start_after: &[u8],
        filter_prefix: &[u8],
        max: u64,
    ) -> Result<(OmapMap, bool), Errno>;
    /// `cls_cxx_map_get_keys`: like `omap_get_vals` without prefix filter, keys only. (R)
    fn omap_get_keys(
        &mut self,
        start_after: &[u8],
        max: u64,
    ) -> Result<(Vec<Vec<u8>>, bool), Errno>;
    /// `cls_cxx_map_read_header`. Absent object: empty. (R)
    fn omap_get_header(&mut self) -> Result<Vec<u8>, Errno>;
    /// `cls_cxx_map_set_val` / `map_set_vals` (upsert, touch-creates). (W)
    fn omap_set(&mut self, entries: &[(&[u8], &[u8])]) -> Result<(), Errno>;
    /// `cls_cxx_map_write_header`. (W)
    fn omap_set_header(&mut self, header: &[u8]) -> Result<(), Errno>;
    /// `cls_cxx_map_remove_key`: missing key ignored; `ENOENT` if the object is absent. (W)
    fn omap_remove_key(&mut self, key: &[u8]) -> Result<(), Errno>;
    /// `cls_cxx_map_remove_range` [begin, end). (W)
    fn omap_remove_range(&mut self, begin: &[u8], end: &[u8]) -> Result<(), Errno>;
    /// `cls_cxx_map_clear`: `ENOENT` if the object is absent. (W)
    fn omap_clear(&mut self) -> Result<(), Errno>;
}

/// Base64 armor alphabet (`cls_gen_rand_base64`).
pub const ARMOR: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// `n` random armor characters (the context's randomness, like `cls_gen_rand_base64`).
pub fn rand_armor<C: ClsCtx>(c: &mut C, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    c.random_bytes(&mut b);
    b.iter().map(|x| ARMOR[(*x & 63) as usize]).collect()
}

/// Version-4 uuid text (8-4-4-4-12) from the context's randomness.
pub fn rand_uuid_text<C: ClsCtx>(c: &mut C) -> Vec<u8> {
    let mut b = [0u8; 16];
    c.random_bytes(&mut b);
    Uuid::v4_from(b).to_string().into_bytes()
}

/// Page size of [`omap_scan`]: the per-call cap of `omap_get_vals` (osd_max_omap_entries_per_request).
pub const SCAN_PAGE: u64 = 1024;

/// Visit the omap entries with key > `start_after` that start with `prefix`, ascending, at most
/// `max` of them, until `f` breaks. Pages through `omap_get_vals` ([`SCAN_PAGE`] each); a page
/// without entries ends the scan (no-progress rule). Returns the `more` flag of the last page
/// read: `true` = entries may remain after the last one visited (`max` reached or no progress).
pub fn omap_scan<C: ClsCtx>(
    c: &mut C,
    start_after: &[u8],
    prefix: &[u8],
    max: u64,
    mut f: impl FnMut(&mut C, Vec<u8>, Vec<u8>) -> Result<ControlFlow<()>, Errno>,
) -> Result<bool, Errno> {
    let mut last = start_after.to_vec();
    let mut left = max;
    loop {
        if left == 0 {
            return Ok(true);
        }
        let (page, more) = c.omap_get_vals(&last, prefix, left.min(SCAN_PAGE))?;
        let Some(next) = page.keys().next_back().cloned() else {
            return Ok(more);
        };
        left = left.saturating_sub(page.len() as u64);
        for (k, v) in page {
            if f(c, k, v)?.is_break() {
                return Ok(true);
            }
        }
        if !more {
            return Ok(false);
        }
        last = next;
    }
}
