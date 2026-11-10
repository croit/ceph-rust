// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Object class calls (cls.md): the executor implements `cls::ClsCtx` over its op context (every primitive is the
//! same machinery as the plain ops, so the two-view visibility rule holds), classifies `call` ops with the
//! registry, enforces the RD/WR flags (-EIO) and counts primitives. A tiny `hello` class (lab/test only classes of
//! the upstream test suite) lives here too.

use crate::exec::{Exec, Src, kn};
use crate::view::ObjView;
use cls::errno as ce;
use cls::{ClsCtx, Errno, Origin, Stat, Watcher};
use denc::types::UTime;
use opwire::{ClsEntry, ClsFlags, errno};
use std::collections::{BTreeMap, BTreeSet};

/// `hello` methods (test class): (name, rd, wr).
const HELLO: &[(&str, bool, bool)] = &[("say_hello", true, false), ("replay", true, false)];

/// Class load policy of the OSD (cls.md 2.1): `osd_class_load_list` (classes this OSD serves at all; the static
/// registry is the available set, exactly like the `.so` directory) and `osd_class_default_list` (classes an
/// `allow rwx` grant reaches without an explicit `allow class NAME`). Both are whitespace-separated class names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassPolicy {
    load: BTreeSet<String>,
    default: BTreeSet<String>,
}

impl ClassPolicy {
    /// The pinned version's default of both options (20 classes; `sdk`/`lua` are not on either).
    pub const CEPH_DEFAULT_LIST: &'static str = "cephfs hello journal lock log numops otp rbd refcount rgw \
         rgw_gc timeindex user version cas cmpomap queue 2pc_queue fifo sem_set";

    pub fn parse(load: &str, default: &str) -> ClassPolicy {
        let set = |s: &str| s.split_whitespace().map(str::to_owned).collect();
        ClassPolicy {
            load: set(load),
            default: set(default),
        }
    }

    /// On `osd_class_load_list` (or the list holds `*`): the class is served at all (else the message fails -EPERM).
    pub fn loadable(&self, class: &str) -> bool {
        self.load.contains("*") || self.load.contains(class)
    }

    /// On `osd_class_default_list` (or the list holds `*`): class-read/-write cap bits reach it (else only
    /// `allow class NAME` does).
    fn default_allowed(&self, class: &str) -> bool {
        self.default.contains("*") || self.default.contains(class)
    }
}

impl Default for ClassPolicy {
    fn default() -> ClassPolicy {
        ClassPolicy::parse(Self::CEPH_DEFAULT_LIST, Self::CEPH_DEFAULT_LIST)
    }
}

/// `class` is in the registry (the classes this binary could serve).
fn known(class: &str) -> bool {
    class == "hello" || cls::CLASSES.contains(&class)
}

/// Registered flags of `class.method`, without the load policy (execution: the message already passed
/// classification). `Err(positive errno)` = classification failure of the whole message (unknown class -> EPERM,
/// unknown method -> EOPNOTSUPP; black-box confirmed, client-ops s15).
pub fn flags(class: &[u8], method: &[u8]) -> Result<ClsFlags, i32> {
    let Ok(c) = std::str::from_utf8(class) else {
        return Err(errno::EPERM);
    };
    // Wire names are byte strings: invalid UTF-8 cannot name a registered method,
    // but does not turn a known class into a class-load failure.
    let m = std::str::from_utf8(method).map_err(|_| {
        if known(c) {
            errno::EOPNOTSUPP
        } else {
            errno::EPERM
        }
    })?;
    if let Some(mm) = cls::lookup(c, m) {
        return Ok(ClsFlags {
            rd: mm.rd(),
            wr: mm.wr(),
        });
    }
    if c == "hello" {
        return HELLO
            .iter()
            .find(|(n, _, _)| *n == m)
            .map(|(_, rd, wr)| ClsFlags { rd: *rd, wr: *wr })
            .ok_or(errno::EOPNOTSUPP);
    }
    if cls::CLASSES.contains(&c) {
        Err(errno::EOPNOTSUPP)
    } else {
        Err(errno::EPERM)
    }
}

/// Classification lookup of one `call` op under the load policy (cls.md 2.1): a registered class the policy does
/// not load answers -EPERM before caps; the entry carries whether the class is on the default-allowed list.
pub fn lookup(class: &[u8], method: &[u8], policy: &ClassPolicy) -> Result<ClsEntry, i32> {
    let Ok(c) = std::str::from_utf8(class) else {
        return Err(errno::EPERM);
    };
    if known(c) && !policy.loadable(c) {
        return Err(errno::EPERM);
    }
    Ok(ClsEntry {
        flags: flags(class, method)?,
        allowed: policy.default_allowed(c),
    })
}

/// Execute a method. Returns `(ret, out)`; `ret < 0` aborts the message.
pub(crate) fn call<V: ObjView>(
    x: &mut Exec<'_, V>,
    class: &[u8],
    method: &[u8],
    input: &[u8],
) -> (i32, Vec<u8>) {
    let flags = match flags(class, method) {
        Ok(f) => f,
        Err(e) => return (-e, Vec::new()),
    };
    let (c, m) = (
        std::str::from_utf8(class).unwrap_or(""),
        std::str::from_utf8(method).unwrap_or(""),
    );
    let (r0, w0) = (x.n_read, x.n_write);
    if flags.wr {
        x.user_modify = true;
    }
    let (mut ret, out) = if let Some(mm) = cls::lookup(c, m) {
        let r = cls::call(x, mm, input);
        (r.ret, r.out)
    } else {
        hello(x, m, input)
    };
    // enforcement (cls.md s3 step 5): the delta of this method must stay within its flags
    if (x.n_read > r0 && !flags.rd) || (x.n_write > w0 && !flags.wr) {
        ret = -errno::EIO;
    }
    (ret, out)
}

fn hello<V: ObjView>(x: &mut Exec<'_, V>, method: &str, input: &[u8]) -> (i32, Vec<u8>) {
    match method {
        "say_hello" => {
            let who: &[u8] = if input.is_empty() { b"world" } else { input };
            let mut o = b"Hello, ".to_vec();
            o.extend_from_slice(who);
            o.push(b'!');
            (0, o)
        }
        "replay" => match ClsCtx::read(x, 0, 0) {
            Ok(d) => (0, d),
            Err(e) => (e, Vec::new()),
        },
        _ => (-errno::EOPNOTSUPP, Vec::new()),
    }
}

fn neg(r: i32) -> Result<(), Errno> {
    if r < 0 { Err(r) } else { Ok(()) }
}

impl<V: ObjView> Exec<'_, V> {
    /// A point omap read (one counted read): `false` = the working view has no omap. Point reads see the working view's
    /// omap flag like the listing reads (an omap_clear / delete earlier in the message hides the committed keys and
    /// header), then the committed content (s7 two views).
    fn omap_point_read(&mut self) -> bool {
        self.n_read += 1;
        self.oi.is_omap()
    }
}

/// Encoded length of a `map<string, bufferlist>` (u32 count + u32-prefixed keys and values): the outdata / indata size
/// classic counts in KiB for a cls primitive's inner omap op (spec pg-io-stats.md 1).
fn kv_len<'a>(kv: impl Iterator<Item = (&'a [u8], &'a [u8])>) -> u64 {
    kv.fold(4, |n, (k, v)| n + 8 + k.len() as u64 + v.len() as u64)
}

impl<V: ObjView> ClsCtx for Exec<'_, V> {
    fn origin(&self) -> Origin {
        Origin {
            name: self.m.caller.name,
            addr: self.m.caller.addr,
        }
    }
    fn now(&self) -> UTime {
        self.m.now
    }
    fn client_features(&self) -> u64 {
        self.m.caller.features
    }
    fn osd_features(&self) -> u64 {
        denc::features::ALL
    }
    fn require_osd_release(&self) -> u8 {
        self.m.require_osd_release
    }
    fn current_version(&self) -> u64 {
        self.m.last_user_version
    }
    fn config(&self) -> cls::ClsConfig {
        cls::ClsConfig {
            journal_pad: self.m.cls_map.journal_pad,
            pool_stripe_width: self.m.cls_map.pool_stripe_width,
            osd_max_omap_entries_per_request: self.m.limits.max_omap_entries as u64,
            ..cls::ClsConfig::DEFAULT
        }
    }
    fn subop_num(&self) -> u32 {
        // outer ops before this one + nested primitives so far (classic processed_subop_count)
        (self.cur as u32)
            .wrapping_add(self.n_read)
            .wrapping_add(self.n_write)
    }
    fn random_bytes(&mut self, out: &mut [u8]) {
        let mut s = self.m.now.as_nanos() ^ 0x9E37_79B9_7F4A_7C15 ^ (self.cur as u64) << 32;
        for b in out.iter_mut() {
            s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = s;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            *b = (z ^ (z >> 31)) as u8;
        }
    }
    fn snapset_seq(&mut self) -> Result<u64, Errno> {
        if !self.exists || (self.oi.is_whiteout() && self.pre.ss.clones.is_empty()) {
            return Err(ce::ENOENT);
        }
        Ok(self.pre.ss.seq)
    }
    fn list_watchers(&mut self) -> Result<Vec<Watcher>, Errno> {
        self.n_read += 1;
        if !self.present() {
            return Err(ce::ENOENT);
        }
        self.io.read(0);
        Ok(self
            .oi
            .watchers
            .iter()
            .map(|((cookie, name), w)| Watcher {
                name: *name,
                cookie: *cookie,
                timeout_seconds: w.timeout_seconds,
                addr: w.addr,
            })
            .collect())
    }

    fn stat(&mut self) -> Result<Stat, Errno> {
        self.io.read(0);
        if !self.present() {
            return Err(ce::ENOENT);
        }
        Ok(Stat {
            size: self.oi.size,
            mtime: self.oi.mtime,
        })
    }
    fn read(&mut self, off: u64, len: u64) -> Result<Vec<u8>, Errno> {
        self.n_read += 1;
        let e = opwire::Extent {
            offset: off,
            length: len,
            ..Default::default()
        };
        let d = self.read_core(&e).map_err(|x| -x)?;
        self.io.read(d.len() as u64);
        Ok(d)
    }
    fn create(&mut self, excl: bool) -> Result<(), Errno> {
        self.n_write += 1;
        neg(self.op_create(excl, &[]))
    }
    fn remove(&mut self) -> Result<(), Errno> {
        self.n_write += 1;
        neg(self.op_delete())
    }
    fn write(&mut self, off: u64, data: &[u8]) -> Result<(), Errno> {
        self.n_write += 1;
        neg(self.do_write(off, data.len() as u64, Src::Own(data.to_vec())))?;
        self.io.write(data.len() as u64);
        Ok(())
    }
    fn write_full(&mut self, data: &[u8]) -> Result<(), Errno> {
        self.n_write += 1;
        neg(self.do_writefull(data.len() as u64, Src::Own(data.to_vec())))?;
        self.io.write(data.len() as u64);
        Ok(())
    }
    fn truncate(&mut self, size: u64) -> Result<(), Errno> {
        self.n_write += 1;
        neg(self.op_truncate(size, 0, 0, 0))
    }
    fn zero(&mut self, off: u64, len: u64) -> Result<(), Errno> {
        self.n_write += 1;
        neg(self.op_zero(off, len))
    }

    fn getxattr(&mut self, name: &str) -> Result<Vec<u8>, Errno> {
        self.getxattr_raw(name.as_bytes())
    }
    fn setxattr(&mut self, name: &str, value: &[u8]) -> Result<(), Errno> {
        self.setxattr_raw(name.as_bytes(), value)
    }

    fn getxattr_raw(&mut self, name: &[u8]) -> Result<Vec<u8>, Errno> {
        self.n_read += 1;
        match self.v.ov_getattr(self.m.spg, &self.tgt, &kn(name)) {
            Ok(Some(v)) => {
                self.io.read(v.len() as u64);
                Ok(v)
            }
            Ok(None) => {
                self.io.read(0);
                Err(ce::ENODATA)
            }
            Err(e) => {
                self.io.read(0);
                Err(-e)
            }
        }
    }
    fn getxattrs_raw(&mut self) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, Errno> {
        self.n_read += 1;
        match self.v.ov_getattrs(self.m.spg, &self.tgt) {
            Ok(m) => {
                let user: BTreeMap<Vec<u8>, Vec<u8>> = m
                    .into_iter()
                    .filter(|(k, _)| k.len() > 1 && k[0] == b'_')
                    .map(|(k, v)| (k[1..].to_vec(), v))
                    .collect();
                self.io.read(kv_len(
                    user.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
                ));
                Ok(user)
            }
            Err(e) => {
                self.io.read(0);
                Err(-e)
            }
        }
    }
    fn setxattr_raw(&mut self, name: &[u8], value: &[u8]) -> Result<(), Errno> {
        self.n_write += 1;
        neg(self.do_setxattr(name, value))?;
        self.io.write(0);
        Ok(())
    }

    fn omap_get_val(&mut self, key: &[u8]) -> Result<Vec<u8>, Errno> {
        if !self.omap_point_read() {
            self.io.read(4);
            return Err(ce::ENOENT);
        }
        match self.v.ov_omap_get(self.m.spg, &self.tgt, &[key]) {
            Ok(mut m) => {
                let v = m.remove(key);
                let n = v.as_ref().map_or(0, |v| 8 + key.len() + v.len()) as u64;
                self.io.read(4 + n);
                v.ok_or(ce::ENOENT)
            }
            Err(e) => Err(-e),
        }
    }
    fn omap_get_vals_by_keys(&mut self, keys: &[&[u8]]) -> Result<cls::OmapMap, Errno> {
        if !self.omap_point_read() {
            self.io.read(4);
            return Ok(BTreeMap::new());
        }
        match self.v.ov_omap_get(self.m.spg, &self.tgt, keys) {
            Ok(m) => {
                self.io
                    .read(kv_len(m.iter().map(|(k, v)| (k.as_slice(), v.as_slice()))));
                Ok(m)
            }
            Err(e) if e == errno::ENOENT => {
                self.io.read(4);
                Ok(BTreeMap::new())
            }
            Err(e) => Err(-e),
        }
    }
    fn omap_get_vals(
        &mut self,
        start_after: &[u8],
        filter_prefix: &[u8],
        max: u64,
    ) -> Result<(cls::OmapMap, bool), Errno> {
        self.n_read += 1;
        let (kv, more) = self
            .omap_range(Some(start_after), filter_prefix, max)
            .map_err(|e| -e)?;
        // the inner op's outdata: the map plus its "more" flag
        self.io
            .read(kv_len(kv.iter().map(|(k, v)| (k.as_slice(), v.as_slice()))) + 1);
        Ok((kv.into_iter().collect(), more))
    }
    fn omap_get_keys(
        &mut self,
        start_after: &[u8],
        max: u64,
    ) -> Result<(Vec<Vec<u8>>, bool), Errno> {
        self.n_read += 1;
        let (keys, more) = self
            .omap_keys_range(Some(start_after), max)
            .map_err(|e| -e)?;
        self.io
            .read(keys.iter().fold(5, |n, k| n + 4 + k.len() as u64));
        Ok((keys, more))
    }
    fn omap_get_header(&mut self) -> Result<Vec<u8>, Errno> {
        if !self.omap_point_read() {
            return Ok(Vec::new());
        }
        match self.v.ov_omap_header(self.m.spg, &self.tgt) {
            Ok(h) => {
                self.io.read(h.len() as u64);
                Ok(h)
            }
            Err(e) if e == errno::ENOENT => {
                self.io.read(0);
                Ok(Vec::new())
            }
            Err(e) => Err(-e),
        }
    }
    fn omap_set(&mut self, entries: &[(&[u8], &[u8])]) -> Result<(), Errno> {
        self.n_write += 1;
        neg(self.do_omap_set(opwire::KvRun::from_pairs(entries.iter().copied())))?;
        self.io.write(kv_len(entries.iter().copied()));
        Ok(())
    }
    fn omap_set_header(&mut self, header: &[u8]) -> Result<(), Errno> {
        self.n_write += 1;
        neg(self.op_omap_set_header(header.to_vec()))?;
        self.io.write(0);
        Ok(())
    }
    fn omap_remove_key(&mut self, key: &[u8]) -> Result<(), Errno> {
        self.n_write += 1;
        neg(self.do_omap_rm_keys(vec![key.to_vec()]))?;
        self.io.write(0);
        Ok(())
    }
    fn omap_remove_range(&mut self, begin: &[u8], end: &[u8]) -> Result<(), Errno> {
        self.n_write += 1;
        neg(self.do_omap_rm_range(begin.to_vec(), end.to_vec()))?;
        self.io.write(0);
        Ok(())
    }
    fn omap_clear(&mut self) -> Result<(), Errno> {
        self.n_write += 1;
        neg(self.op_omap_clear())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_policy_defaults_and_lists() {
        let d = ClassPolicy::default();
        // every registry class except the upstream test probe `sdk` is on both Ceph default lists
        for c in cls::CLASSES.iter().chain(&["hello"]) {
            let want = *c != "sdk";
            assert_eq!(d.loadable(c), want, "{c} loadable");
            assert_eq!(d.default_allowed(c), want, "{c} default-allowed");
        }
        assert!(!d.loadable("sdk") && !d.default_allowed("sdk"));
        // empty option = no class at all; the two lists are independent
        let p = ClassPolicy::parse("", "lock");
        assert!(!p.loadable("lock"));
        assert!(p.default_allowed("lock"));
        // `*` = every class, on either list (classic "allow all")
        let all = ClassPolicy::parse("rbd *", "*");
        for c in cls::CLASSES.iter().chain(&["hello"]) {
            assert!(all.loadable(c) && all.default_allowed(c), "{c}");
        }
    }

    #[test]
    fn load_list_refuses_before_the_method_is_even_looked_up() {
        let p = ClassPolicy::parse("lock", "lock");
        assert_eq!(
            lookup(b"lock", b"get_info", &p).map(|e| e.allowed),
            Ok(true)
        );
        assert_eq!(
            lookup(b"lock", b"no_such_method", &p),
            Err(errno::EOPNOTSUPP)
        );
        // not loaded: the whole message fails, whatever the method
        assert_eq!(
            lookup(b"sdk", b"test_coverage_write", &p),
            Err(errno::EPERM)
        );
        assert_eq!(lookup(b"sdk", b"no_such_method", &p), Err(errno::EPERM));
        // a registered class off the default list: callable with the entry says so
        let q = ClassPolicy::parse("lock", "rbd");
        assert_eq!(
            lookup(b"lock", b"get_info", &q).map(|e| e.allowed),
            Ok(false)
        );
        // unknown classes stay EPERM
        assert_eq!(lookup(b"nope", b"x", &p), Err(errno::EPERM));
    }
}
