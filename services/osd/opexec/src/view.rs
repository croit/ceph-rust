// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! The read side of the store as the op executor sees it (client-ops.md s7 "committed view").
//! Implemented by `storeadapt::StoreAdapter` (NVMe store), by `peering::MemStore` (tests, below) and by the
//! OSD's dev store. All methods are synchronous point queries; errors are POSITIVE errno (`ENOENT` = object absent
//! in the store, `EIO` = local read/checksum failure).

use denc::types::{Hobject, SpgT};
use opwire::errno;
use std::collections::BTreeMap;

pub type Kv = (Vec<u8>, Vec<u8>);
/// An omap listing encoded for its reply ([`ObjView::ov_omap_list`]): buffer, entries, more.
pub type OmapList = (Vec<u8>, u32, bool);

/// READ pieces plus optional source-verified seed-0 CRCs on the returned
/// 4 KiB grid. The optional vector belongs only to placement candidates;
/// the ordinary shared read has no sidecar allocation.
#[derive(Debug)]
pub struct VerifiedRead {
    pub parts: Vec<(bytes::Bytes, Option<u32>)>,
    pub block_crcs: Option<Vec<u32>>,
}

/// Why an op waits in the PG gate (op trace stage `pg_gate`, doc/ops/op-trace.md) and why a store probe refused
/// ([`ObjView::ov_refusal`]; perf `probe_refused_*`). `1..=5` are store refusals, recorded by the store at the probe
/// that refused; [`STORE`] = cold without a recorded refusal. Code 2 is unused (was the shard write gate, adr 0082 am. 2).
pub mod gate_why {
    pub const STORE: u8 = 0;
    /// The PG's store shard has no admission headroom (parked transactions at their limit).
    pub const ADMISSION: u8 = 1;
    /// An object metadata page (onode / extent tree) is being loaded.
    pub const OBJ: u8 = 3;
    /// The PG log's next key page is being loaded.
    pub const LOG: u8 = 4;
    /// A data block a partial write / read needs is being read.
    pub const DATA: u8 = 5;
    /// Warm, but earlier ops wait in the gate and it may not pass them.
    pub const BEHIND: u8 = 8;
    /// The PG is not active or not readable.
    pub const INACTIVE: u8 = 9;
    /// EC: waiting for the object's in-flight read or write.
    pub const EC: u8 = 10;

    pub fn name(why: u8) -> &'static str {
        match why {
            STORE => "store",
            ADMISSION => "admission",
            OBJ => "obj_page",
            LOG => "log_page",
            DATA => "data",
            BEHIND => "behind",
            INACTIVE => "inactive",
            EC => "ec",
            _ => "unknown",
        }
    }
}

pub trait ObjView {
    /// Stored size; `Ok(None)` = the object is absent in the store.
    fn ov_stat(&self, spg: SpgT, soid: &Hobject) -> Result<Option<u64>, i32>;
    /// `[off, off+len)` clamped to the stored size. `ENOENT` if absent.
    fn ov_read(&self, spg: SpgT, soid: &Hobject, off: u64, len: u64) -> Result<Vec<u8>, i32>;
    /// [`ObjView::ov_read`] plus the crc32c (seed `!0`) of the bytes when the store knows it without a pass (whole
    /// verified blocks). Default: unknown.
    fn ov_read_crc(
        &self,
        spg: SpgT,
        soid: &Hobject,
        off: u64,
        len: u64,
    ) -> Result<(Vec<u8>, Option<u32>), i32> {
        self.ov_read(spg, soid, off, len).map(|d| (d, None))
    }
    /// [`ObjView::ov_read_crc`] as a shared buffer: a view that keeps the bytes in a `Bytes` (EC decoded read cache) hands out a
    /// slice without a copy. Default: the owned read, moved.
    fn ov_read_bytes(
        &self,
        spg: SpgT,
        soid: &Hobject,
        off: u64,
        len: u64,
    ) -> Result<(bytes::Bytes, Option<u32>), i32> {
        self.ov_read_crc(spg, soid, off, len)
            .map(|(d, c)| (bytes::Bytes::from(d), c))
    }
    /// [`ObjView::ov_read_bytes`] as pieces in order (the bytes are their concatenation), each with the crc32c (seed `!0`)
    /// of exactly its bytes when known: a view that holds the data in shared buffers (store device / prefetch buffers)
    /// hands them out without a copy. Default: the shared read as one piece.
    fn ov_read_shared(
        &self,
        spg: SpgT,
        soid: &Hobject,
        off: u64,
        len: u64,
    ) -> Result<Vec<(bytes::Bytes, Option<u32>)>, i32> {
        self.ov_read_bytes(spg, soid, off, len)
            .map(|(d, c)| vec![(d, c)])
    }
    /// Placement-only read. Implementations with verified device block CRCs
    /// return them without a payload scan; other views preserve their bytes
    /// and return `None` for the CRC sidecar.
    fn ov_read_shared_verified(
        &self,
        spg: SpgT,
        soid: &Hobject,
        off: u64,
        len: u64,
    ) -> Result<VerifiedRead, i32> {
        self.ov_read_shared(spg, soid, off, len)
            .map(|parts| VerifiedRead {
                parts,
                block_crcs: None,
            })
    }
    /// Raw attribute (store key, e.g. `_` or `_user`). `Err(ENOENT)` = object absent, `Ok(None)` = attr absent.
    fn ov_getattr(&self, spg: SpgT, soid: &Hobject, name: &[u8]) -> Result<Option<Vec<u8>>, i32>;
    /// Two raw attributes of one object (`Err(ENOENT)` = object absent). One store lookup where the view can.
    #[expect(clippy::type_complexity)]
    fn ov_getattr_pair(
        &self,
        spg: SpgT,
        soid: &Hobject,
        a: &[u8],
        b: &[u8],
    ) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>), i32> {
        Ok((
            self.ov_getattr(spg, soid, a)?,
            self.ov_getattr(spg, soid, b)?,
        ))
    }
    /// All raw attributes (store keys). `Err(ENOENT)` = object absent.
    fn ov_getattrs(&self, spg: SpgT, soid: &Hobject) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, i32>;
    /// Omap header (empty if none). `Err(ENOENT)` = object absent.
    fn ov_omap_header(&self, spg: SpgT, soid: &Hobject) -> Result<Vec<u8>, i32>;
    /// Omap entries with key `> after` (all if `after` is `None`) that start with `prefix`, ascending, at most `max`
    /// entries and about `max_bytes` bytes (at least one entry); `more` = further matching entries exist.
    fn ov_omap_range(
        &self,
        spg: SpgT,
        soid: &Hobject,
        after: Option<&[u8]>,
        prefix: &[u8],
        max: usize,
        max_bytes: usize,
    ) -> Result<(Vec<Kv>, bool), i32>;
    /// Keys-only projection. Budget counts encoded keys (four-byte length plus key bytes),
    /// as in Ceph OMAPGETKEYS; values do not consume the reply budget.
    fn ov_omap_keys_range(
        &self,
        spg: SpgT,
        soid: &Hobject,
        after: Option<&[u8]>,
        prefix: &[u8],
        max: usize,
        max_bytes: usize,
    ) -> Result<(Vec<Vec<u8>>, bool), i32> {
        let (kv, more) = self.ov_omap_range(spg, soid, after, prefix, max, usize::MAX)?;
        Ok(omap_project_keys(kv, more, max_bytes))
    }
    /// [`ObjView::ov_omap_range`] (`values`) or [`ObjView::ov_omap_keys_range`] (keys only) encoded for the reply:
    /// `opwire::OMAP_LIST_HEAD` reserved bytes, then per entry `le32 len, key` (+ `le32 len, value`) in strictly
    /// ascending key order; same selection, budget and `more` (finished by `opwire::omap_list_out`). The store view writes
    /// it in one pass from its tree leaves (no allocation per entry); default: the pair listing, encoded
    /// ([`omap_list_via`]).
    #[expect(clippy::too_many_arguments)]
    fn ov_omap_list(
        &self,
        spg: SpgT,
        soid: &Hobject,
        after: Option<&[u8]>,
        prefix: &[u8],
        max: usize,
        max_bytes: usize,
        values: bool,
    ) -> Result<OmapList, i32> {
        omap_list_via(self, spg, soid, after, prefix, max, max_bytes, values)
    }
    /// Complete immutable listing output, including count and `more`. Unlike
    /// [`ObjView::ov_omap_list`], no caller mutation/finalization is required.
    /// A backing shared with retries must survive the read session and must not
    /// export unaccounted spare capacity. Default views keep their existing
    /// writable encoding/finalization path.
    #[expect(clippy::too_many_arguments)]
    fn ov_omap_list_reply(
        &self,
        spg: SpgT,
        soid: &Hobject,
        after: Option<&[u8]>,
        prefix: &[u8],
        max: usize,
        max_bytes: usize,
        values: bool,
    ) -> Result<bytes::Bytes, i32> {
        self.ov_omap_list(spg, soid, after, prefix, max, max_bytes, values)
            .map(|(enc, n, more)| opwire::omap_list_out(enc, n, more).into())
    }

    /// Omap values of the given keys (missing keys omitted).
    fn ov_omap_get(
        &self,
        spg: SpgT,
        soid: &Hobject,
        keys: &[&[u8]],
    ) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, i32>;
    /// Objects of the PG (heads and clones, no temp/pgmeta) in hobject order from `begin` (inclusive): up to `max`
    /// plus the next unlisted one (`Hobject::MAX()` = exhausted).
    fn ov_list(
        &self,
        spg: SpgT,
        begin: &Hobject,
        max: usize,
    ) -> Result<(Vec<Hobject>, Hobject), i32>;
    /// Longest omap key / attribute store key the store accepts (client-ops.md rule 9a: longer = ENAMETOOLONG,
    /// decided before any log entry). `usize::MAX` = no store limit (test views).
    fn ov_max_item_key(&self) -> usize {
        usize::MAX
    }
    /// Run the reads of one op non-blocking (adr 0021 am. 11): a store page miss submits the load and fails the read
    /// (reported as an error) instead of spinning the PG core. The caller drops the op result when
    /// [`ObjView::ov_take_blocked`] says a read was refused and re-runs the op after the load. Default: reads never
    /// refuse (in-memory views).
    fn ov_nonblock(&self, _on: bool) {}
    /// Start/end a request's resumable data reads. End with `keep` only when the request parked.
    fn ov_read_session(&self, _session: Option<(u64, u64)>, _keep: bool) {}
    /// The run of the request [`ObjView::ov_read_session`] started lists without CPU slice (adr 0021 S8, adr 0522): it
    /// holds later ops of its object. Ends with the session. Default: listings never slice.
    fn ov_list_whole(&self) {}
    /// A read was refused since the last call (see [`ObjView::ov_nonblock`]).
    fn ov_take_blocked(&self) -> bool {
        false
    }
    /// A refused read needs another request on this executor to release local
    /// ownership, not independently progressing IO. It MUST yield even when
    /// blocking fallback was selected. Clear at cause_begin and when taken.
    /// This is not scan progress; default views never report a local wait.
    fn ov_take_local_wait(&self) -> bool {
        false
    }
    /// A refused run still made progress since the last call, e.g. a listing slice or an admitted data wait: the engine
    /// does not count that run against its try bound.
    fn ov_take_progress(&self) -> bool {
        false
    }
    /// Page loads submitted by refused reads are still in flight.
    fn ov_loads_pending(&self) -> bool {
        false
    }
    /// Start collecting what the next store probe (`warm*`, a refused run) waits for (adr 0043 am. 9).
    fn ov_cause_begin(&self) {}
    /// What the probes since [`ObjView::ov_cause_begin`] waited for; the default (unknown) is probed on every wake.
    fn ov_cause_take(&self) -> peering::wake::Cause {
        peering::wake::Cause::default()
    }
    /// The [`gate_why`] store refusal of the last refused probe since [`ObjView::ov_cause_begin`] ([`gate_why::STORE`]:
    /// none recorded). Diagnostics only (op trace).
    fn ov_refusal(&self) -> u8 {
        gate_why::STORE
    }
    /// Can the store name this object (its tree key within the store limit)? `false` = ENAMETOOLONG.
    fn ov_name_fits(&self, _spg: SpgT, _soid: &Hobject) -> bool {
        true
    }
    /// Does the name need the store's long-name index (beyond the plain name key limit)?
    fn ov_name_long(&self, _spg: SpgT, _soid: &Hobject) -> bool {
        false
    }
    /// May a WRITE create / keep this name: every replica and recovery target of the PG must store it too (a long name
    /// is only accepted when all of them have `FEAT_LONG_NAME`; adr 0021 am. 30). `false` = ENAMETOOLONG.
    fn ov_name_repl_ok(&self, _spg: SpgT, _soid: &Hobject) -> bool {
        true
    }
}

/// [`ObjView::ov_omap_list`] from the pair listing of `v` (views without an encoding store; EC pools with in-flight
/// omap records). Values: a list out of key order takes the map rule of the reply (sorted, the last of a repeated key
/// wins).
#[expect(clippy::too_many_arguments)]
pub fn omap_list_via<V: ObjView + ?Sized>(
    v: &V,
    spg: SpgT,
    soid: &Hobject,
    after: Option<&[u8]>,
    prefix: &[u8],
    max: usize,
    max_bytes: usize,
    values: bool,
) -> Result<OmapList, i32> {
    let mut buf = vec![0u8; opwire::OMAP_LIST_HEAD];
    let put = |b: &mut Vec<u8>, x: &[u8]| {
        b.extend_from_slice(&(x.len() as u32).to_le_bytes());
        b.extend_from_slice(x);
    };
    if !values {
        let (keys, more) = v.ov_omap_keys_range(spg, soid, after, prefix, max, max_bytes)?;
        keys.iter().for_each(|k| put(&mut buf, k));
        return Ok((buf, keys.len() as u32, more));
    }
    let (mut kv, more) = v.ov_omap_range(spg, soid, after, prefix, max, max_bytes)?;
    if !kv.windows(2).all(|w| w[0].0 < w[1].0) {
        kv = kv
            .into_iter()
            .collect::<BTreeMap<_, _>>()
            .into_iter()
            .collect();
    }
    for (k, x) in &kv {
        put(&mut buf, k);
        put(&mut buf, x);
    }
    Ok((buf, kv.len() as u32, more))
}

/// Keys-only projection of a value scan under the encoded-key byte budget (4 + key bytes per key).
fn omap_project_keys(kv: Vec<Kv>, more: bool, max_bytes: usize) -> (Vec<Vec<u8>>, bool) {
    let mut bytes = 0usize;
    let mut keys = Vec::with_capacity(kv.len());
    for (key, _) in kv {
        if bytes >= max_bytes {
            return (keys, true);
        }
        bytes = bytes.saturating_add(4).saturating_add(key.len());
        keys.push(key);
    }
    (keys, more)
}

/// Seek bound of an omap listing: the larger of (after, exclusive) and (prefix, inclusive), so the scan never walks
/// below the prefix.
fn omap_seek<'a>(after: Option<&'a [u8]>, prefix: &'a [u8]) -> std::ops::Bound<&'a [u8]> {
    use std::ops::Bound;
    match after {
        Some(a) if a >= prefix => Bound::Excluded(a),
        _ if prefix.is_empty() => Bound::Unbounded,
        _ => Bound::Included(prefix),
    }
}

/// Ordered keys-only scan of an in-memory omap without cloning values, using Ceph's encoded-key byte budget.
fn omap_keys_range_from_map(
    m: &BTreeMap<Vec<u8>, Vec<u8>>,
    after: Option<&[u8]>,
    prefix: &[u8],
    max: usize,
    max_bytes: usize,
) -> (Vec<Vec<u8>>, bool) {
    let mut keys = Vec::new();
    let mut bytes = 0usize;
    let lo = omap_seek(after, prefix);
    for (key, _) in m.range::<[u8], _>((lo, std::ops::Bound::Unbounded)) {
        if !key.starts_with(prefix) {
            break;
        }
        if keys.len() >= max || bytes >= max_bytes {
            return (keys, true);
        }
        bytes = bytes.saturating_add(4).saturating_add(key.len());
        keys.push(key.clone());
    }
    (keys, false)
}

/// Ordered key/value scan of an in-memory omap (classic OMAPGETVALS budget: key + value bytes, at least one entry).
fn omap_range_from_map(
    m: &BTreeMap<Vec<u8>, Vec<u8>>,
    after: Option<&[u8]>,
    prefix: &[u8],
    max: usize,
    max_bytes: usize,
) -> (Vec<Kv>, bool) {
    let mut out: Vec<Kv> = Vec::new();
    let mut bytes = 0usize;
    let lo = omap_seek(after, prefix);
    for (k, v) in m.range::<[u8], _>((lo, std::ops::Bound::Unbounded)) {
        if !k.starts_with(prefix) {
            break;
        }
        if out.len() >= max || (!out.is_empty() && bytes >= max_bytes) {
            return (out, true);
        }
        bytes += k.len() + v.len();
        out.push((k.clone(), v.clone()));
    }
    (out, false)
}

// ---- peering::MemStore (tests / dev) ----------------------------------------------------------------

impl ObjView for peering::MemStore {
    fn ov_stat(&self, spg: SpgT, soid: &Hobject) -> Result<Option<u64>, i32> {
        Ok(self
            .pgs
            .get(&spg)
            .and_then(|p| p.objects.get(soid))
            .map(|o| o.data.len() as u64))
    }
    fn ov_read(&self, spg: SpgT, soid: &Hobject, off: u64, len: u64) -> Result<Vec<u8>, i32> {
        let o = self
            .pgs
            .get(&spg)
            .and_then(|p| p.objects.get(soid))
            .ok_or(errno::ENOENT)?;
        let sz = o.data.len() as u64;
        if off >= sz || len == 0 {
            return Ok(vec![]);
        }
        let end = off.saturating_add(len).min(sz);
        Ok(o.data[off as usize..end as usize].to_vec())
    }
    fn ov_getattr(&self, spg: SpgT, soid: &Hobject, name: &[u8]) -> Result<Option<Vec<u8>>, i32> {
        let o = self
            .pgs
            .get(&spg)
            .and_then(|p| p.objects.get(soid))
            .ok_or(errno::ENOENT)?;
        Ok(o.xattrs.get(name).cloned())
    }
    fn ov_getattrs(&self, spg: SpgT, soid: &Hobject) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, i32> {
        let o = self
            .pgs
            .get(&spg)
            .and_then(|p| p.objects.get(soid))
            .ok_or(errno::ENOENT)?;
        Ok(o.xattrs.clone())
    }
    fn ov_omap_header(&self, spg: SpgT, soid: &Hobject) -> Result<Vec<u8>, i32> {
        let o = self
            .pgs
            .get(&spg)
            .and_then(|p| p.objects.get(soid))
            .ok_or(errno::ENOENT)?;
        Ok(o.omap_header.clone())
    }
    fn ov_omap_range(
        &self,
        spg: SpgT,
        soid: &Hobject,
        after: Option<&[u8]>,
        prefix: &[u8],
        max: usize,
        max_bytes: usize,
    ) -> Result<(Vec<Kv>, bool), i32> {
        let o = self
            .pgs
            .get(&spg)
            .and_then(|p| p.objects.get(soid))
            .ok_or(errno::ENOENT)?;
        Ok(omap_range_from_map(&o.omap, after, prefix, max, max_bytes))
    }
    fn ov_omap_keys_range(
        &self,
        spg: SpgT,
        soid: &Hobject,
        after: Option<&[u8]>,
        prefix: &[u8],
        max: usize,
        max_bytes: usize,
    ) -> Result<(Vec<Vec<u8>>, bool), i32> {
        let o = self
            .pgs
            .get(&spg)
            .and_then(|p| p.objects.get(soid))
            .ok_or(errno::ENOENT)?;
        Ok(omap_keys_range_from_map(
            &o.omap, after, prefix, max, max_bytes,
        ))
    }
    fn ov_omap_get(
        &self,
        spg: SpgT,
        soid: &Hobject,
        keys: &[&[u8]],
    ) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, i32> {
        let o = self
            .pgs
            .get(&spg)
            .and_then(|p| p.objects.get(soid))
            .ok_or(errno::ENOENT)?;
        Ok(keys
            .iter()
            .filter_map(|k| o.omap.get(*k).map(|v| (k.to_vec(), v.clone())))
            .collect())
    }
    fn ov_list(
        &self,
        spg: SpgT,
        begin: &Hobject,
        max: usize,
    ) -> Result<(Vec<Hobject>, Hobject), i32> {
        use peering::PgStoreOps;
        let l = self
            .list_objects(spg, begin, max, max)
            .map_err(|_| errno::EIO)?;
        let next = l.next.clone();
        Ok((l.names(), next))
    }
}

#[cfg(test)]
mod range_tests {
    use super::*;

    fn map(keys: &[&[u8]]) -> BTreeMap<Vec<u8>, Vec<u8>> {
        keys.iter().map(|k| (k.to_vec(), b"v".to_vec())).collect()
    }
    fn ks(
        m: &BTreeMap<Vec<u8>, Vec<u8>>,
        after: Option<&[u8]>,
        prefix: &[u8],
        max: usize,
    ) -> (Vec<Vec<u8>>, bool) {
        let r = omap_range_from_map(m, after, prefix, max, 1 << 20);
        (r.0.into_iter().map(|(k, _)| k).collect(), r.1)
    }

    #[test]
    fn keys_budget_uses_encoded_keys_and_ignores_values() {
        let m = BTreeMap::from([
            (b"a".to_vec(), vec![1; 1 << 20]),
            (b"bb".to_vec(), vec![2; 1 << 20]),
            (b"c".to_vec(), vec![3; 1 << 20]),
        ]);
        // Five encoded bytes for a, six for bb; stop before c.
        let expected = (vec![b"a".to_vec(), b"bb".to_vec()], true);
        assert_eq!(omap_keys_range_from_map(&m, None, b"", 10, 6), expected);
        assert_eq!(
            omap_keys_range_from_map(&m, None, b"", 10, 0),
            (vec![], true)
        );
        assert_eq!(
            omap_keys_range_from_map(&m, None, b"", 0, 100),
            (vec![], true)
        );
        assert_eq!(
            omap_keys_range_from_map(&m, Some(b"bb"), b"", 10, 1),
            (vec![b"c".to_vec()], false)
        );
        assert_eq!(
            omap_keys_range_from_map(&m, None, b"bb", 1, 100),
            (vec![b"bb".to_vec()], false)
        );
    }

    #[test]
    fn prefix_seek_and_after_combinations() {
        let m = map(&[b"a1", b"b1", b"b2", b"b3", b"c1", b"\xff"]);
        let b = |x: &[&[u8]]| x.iter().map(|k| k.to_vec()).collect::<Vec<_>>();
        // prefix only: jumps over a*, stops after b*
        assert_eq!(ks(&m, None, b"b", 10), (b(&[b"b1", b"b2", b"b3"]), false));
        // after below the prefix: the prefix wins
        assert_eq!(ks(&m, Some(b"a"), b"b", 2), (b(&[b"b1", b"b2"]), true));
        assert_eq!(ks(&m, Some(b"a9"), b"b", 10).0.len(), 3);
        // after inside the prefix: exclusive
        assert_eq!(ks(&m, Some(b"b1"), b"b", 10).0, b(&[b"b2", b"b3"]));
        // after past the prefix: nothing
        assert_eq!(ks(&m, Some(b"c"), b"b", 10), (vec![], false));
        // after == prefix is exclusive
        let m2 = map(&[b"b", b"b1"]);
        assert_eq!(ks(&m2, Some(b"b"), b"b", 10).0, b(&[b"b1"]));
        // empty prefix: everything, 0xff included
        assert_eq!(ks(&m, None, b"", 10).0.len(), 6);
        assert_eq!(ks(&m, None, b"\xff", 10).0, b(&[b"\xff"]));
    }
}
