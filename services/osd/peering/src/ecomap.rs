// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Optimized-EC omap on the primary (spec ec-optimized.md 12, adr 0067 am. 2): no in-memory journal. The stored omap of
//! our primary-capable shard holds every EC_OMAP record up to the roll-forward cursor; the records of the log entries
//! after it ([`pending`]) are laid over it ([`Overlay`]) for reads and replayed onto a clone of the head.

use crate::pg::Pg;
use denc::types::Hobject;
use ec::moddesc::{EcOmap, EcOmapKeys, ModOp, OmapKeysUp, OmapUp, parse, project_omap_keys};
use pgwire::{LogEntry, LogOp};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;

const EIO: i32 = 5;
const EAGAIN: i32 = 11;
const EOPNOTSUPP: i32 = 95;

pub type Kv = (Vec<u8>, Vec<u8>);

/// Generation the object of `e` moved to when `e` made it a different object (stash rename), else `None`: later
/// EC_OMAP records then belong to a new live object and the earlier ones to that stash generation.
pub fn moved_to(e: &LogEntry) -> Option<u64> {
    if matches!(e.op, LogOp::DELETE | LogOp::LOST_DELETE | LogOp::REPLACE)
        || (e.op == LogOp::CLONE && e.soid.snap == denc::types::SnapId::NOSNAP)
    {
        return Some(e.version.version);
    }
    if !e.mod_desc.can_local_rollback || e.mod_desc.bl.is_empty() {
        return None;
    }
    parse(&e.mod_desc.bl)
        .ok()?
        .into_iter()
        .find_map(|o| match o {
            ModOp::Delete { version } | ModOp::TryDelete { version } => Some(version),
            _ => None,
        })
}

/// EC_OMAP records of `soid` among `es` (ascending, all newer than the roll-forward cursor) that apply to its LIVE
/// object: those after the last entry that moved the object away. `None` = a mod_desc we cannot read.
pub fn pending<'a>(
    es: impl IntoIterator<Item = &'a LogEntry>,
    soid: &Hobject,
) -> Option<Vec<EcOmap>> {
    let mut out = Vec::new();
    for e in es.into_iter().filter(|e| e.soid == *soid) {
        if moved_to(e).is_some() {
            out.clear();
        }
        if e.mod_desc.bl.is_empty() {
            continue;
        }
        if !e.mod_desc.can_local_rollback {
            return None;
        }
        for op in parse(&e.mod_desc.bl).ok()? {
            if let ModOp::EcOmap(r) = op {
                out.push(r);
            }
        }
    }
    Some(out)
}

/// Same generation/order rules as [`pending`], without materializing payloads.
pub fn pending_keys<'a>(
    es: impl IntoIterator<Item = &'a LogEntry>,
    soid: &Hobject,
) -> Option<Vec<EcOmapKeys>> {
    let mut out = Vec::new();
    for e in es.into_iter().filter(|e| e.soid == *soid) {
        let log_moves = matches!(e.op, LogOp::DELETE | LogOp::LOST_DELETE | LogOp::REPLACE)
            || (e.op == LogOp::CLONE && e.soid.snap == denc::types::SnapId::NOSNAP);
        if log_moves {
            out.clear();
        }
        if e.mod_desc.bl.is_empty() {
            continue;
        }
        if !e.mod_desc.can_local_rollback {
            return None;
        }
        let p = project_omap_keys(&e.mod_desc.bl).ok()?;
        if p.moved_to.is_some() {
            out.clear();
        }
        out.extend(p.records);
    }
    Some(out)
}

/// Pending EC updates projected to keys. No stored or pending value is owned here.
#[derive(Debug, Default)]
pub struct KeysOverlay {
    cleared: bool,
    header_changed: bool,
    ins: BTreeSet<Vec<u8>>,
    del_keys: BTreeSet<Vec<u8>>,
    del_ranges: Vec<(Vec<u8>, Vec<u8>)>,
}

impl KeysOverlay {
    pub fn of(recs: Vec<EcOmapKeys>) -> Self {
        let mut o = Self::default();
        for r in recs {
            o.header_changed |= r.header_changed;
            if r.clear {
                o = Self {
                    cleared: true,
                    header_changed: true,
                    ..Default::default()
                };
            }
            for u in r.ups {
                match u {
                    OmapKeysUp::Insert(keys) => o.ins.extend(keys),
                    OmapKeysUp::Remove(keys) => {
                        for k in keys {
                            o.ins.remove(&k);
                            o.del_keys.insert(k);
                        }
                    }
                    OmapKeysUp::RemoveRange(a, z) if a < z => {
                        let hit: Vec<_> = o
                            .ins
                            .range::<[u8], _>((
                                Bound::Included(a.as_slice()),
                                Bound::Excluded(z.as_slice()),
                            ))
                            .cloned()
                            .collect();
                        for k in hit {
                            o.ins.remove(&k);
                        }
                        o.del_ranges.push((a, z));
                    }
                    OmapKeysUp::RemoveRange(_, _) => {}
                }
            }
        }
        o
    }

    pub fn is_empty(&self) -> bool {
        !self.cleared
            && !self.header_changed
            && self.ins.is_empty()
            && self.del_keys.is_empty()
            && self.del_ranges.is_empty()
    }

    fn deleted(&self, k: &[u8]) -> bool {
        self.del_keys.contains(k)
            || self
                .del_ranges
                .iter()
                .any(|(a, z)| a.as_slice() <= k && k < z.as_slice())
    }

    /// Merge projected base keys with pending keys. Limits are checked before
    /// admitting the next surviving key, with encoded-key cost `4 + key.len()`.
    pub fn range(
        &self,
        mut base: impl FnMut(Option<&[u8]>, usize) -> Result<(Vec<Vec<u8>>, bool), i32>,
        after: Option<&[u8]>,
        prefix: &[u8],
        max: usize,
        max_bytes: usize,
    ) -> Result<(Vec<Vec<u8>>, bool), i32> {
        let lo = match after {
            Some(a) if a >= prefix => Bound::Excluded(a),
            _ if prefix.is_empty() => Bound::Unbounded,
            _ => Bound::Included(prefix),
        };
        let mut ins = self
            .ins
            .range::<[u8], _>((lo, Bound::Unbounded))
            .take_while(|k| k.starts_with(prefix))
            .peekable();
        let mut cursor = after.map(<[u8]>::to_vec);
        let mut page: std::collections::VecDeque<Vec<u8>> = Default::default();
        let mut base_more = !self.cleared;
        let mut out = Vec::new();
        let mut bytes = 0usize;
        loop {
            while page.is_empty() && base_more {
                let (v, more) = base(cursor.as_deref(), max.clamp(16, 1024))?;
                if let Some(last) = v.last() {
                    // `base` returns keys strictly after the cursor: the walk advances even when a whole page is removed
                    debug_assert!(
                        cursor.as_ref().is_none_or(|c| last > c),
                        "omap page without progress"
                    );
                    cursor = Some(last.clone());
                }
                base_more = more && !v.is_empty();
                page.extend(
                    v.into_iter()
                        .filter(|k| k.starts_with(prefix) && !self.deleted(k)),
                );
            }
            let take_base = match (page.front(), ins.peek()) {
                (None, None) => return Ok((out, false)),
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (Some(b), Some(i)) => {
                    if b.as_slice() == i.as_slice() {
                        page.pop_front();
                        false
                    } else {
                        b.as_slice() < i.as_slice()
                    }
                }
            };
            if out.len() >= max || bytes >= max_bytes {
                return Ok((out, true));
            }
            let k = if take_base {
                page.pop_front().unwrap()
            } else {
                ins.next().unwrap().clone()
            };
            bytes = bytes.saturating_add(4).saturating_add(k.len());
            out.push(k);
        }
    }
}

/// The net effect of sequential EC_OMAP records on a stored omap.
#[derive(Debug, Default, Clone)]
pub struct Overlay {
    /// The stored omap is wiped.
    cleared: bool,
    header: Option<Vec<u8>>,
    ins: BTreeMap<Vec<u8>, Vec<u8>>,
    del_keys: BTreeSet<Vec<u8>>,
    del_ranges: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Overlay {
    pub fn of(recs: &[EcOmap]) -> Overlay {
        let mut o = Overlay::default();
        for r in recs {
            o.apply(r);
        }
        o
    }

    /// One record as a shard applies it: header, clear, updates in order.
    fn apply(&mut self, r: &EcOmap) {
        if let Some(h) = &r.header {
            self.header = Some(h.clone());
        }
        if r.clear {
            *self = Overlay {
                cleared: true,
                header: Some(Vec::new()),
                ..Default::default()
            };
        }
        for u in &r.ups {
            match u {
                OmapUp::Insert(kv) => {
                    for (k, v) in kv {
                        self.ins.insert(k.clone(), v.clone());
                    }
                }
                OmapUp::Remove(keys) => {
                    for k in keys {
                        self.ins.remove(k);
                        self.del_keys.insert(k.clone());
                    }
                }
                OmapUp::RemoveRange(a, z) => {
                    // literal half-open: an empty end removes nothing (as the store does)
                    if a < z {
                        let hit: Vec<Vec<u8>> = self
                            .ins
                            .range::<[u8], _>((
                                Bound::Included(a.as_slice()),
                                Bound::Excluded(z.as_slice()),
                            ))
                            .map(|(k, _)| k.clone())
                            .collect();
                        for k in hit {
                            self.ins.remove(&k);
                        }
                        self.del_ranges.push((a.clone(), z.clone()));
                    }
                }
            }
        }
    }

    /// No effect on the stored omap (reads pass straight through).
    pub fn is_empty(&self) -> bool {
        !self.cleared
            && self.header.is_none()
            && self.ins.is_empty()
            && self.del_keys.is_empty()
            && self.del_ranges.is_empty()
    }

    /// The stored omap is wiped: the base need not be read.
    pub fn cleared(&self) -> bool {
        self.cleared
    }

    fn deleted(&self, k: &[u8]) -> bool {
        self.del_keys.contains(k)
            || self
                .del_ranges
                .iter()
                .any(|(a, z)| a.as_slice() <= k && k < z.as_slice())
    }

    pub fn header(&self, base: Vec<u8>) -> Vec<u8> {
        self.header.clone().unwrap_or(base)
    }

    /// Values of `keys` (missing omitted); `base` = stored values of the keys (only needed unless cleared).
    pub fn get(
        &self,
        keys: &[&[u8]],
        base: BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> BTreeMap<Vec<u8>, Vec<u8>> {
        let mut out = BTreeMap::new();
        for k in keys {
            if let Some(v) = self.ins.get(*k) {
                out.insert(k.to_vec(), v.clone());
            } else if !self.cleared
                && !self.deleted(k)
                && let Some(v) = base.get(*k)
            {
                out.insert(k.to_vec(), v.clone());
            }
        }
        out
    }

    /// `ObjView::ov_omap_range` over base + overlay: entries `> after` starting with `prefix`, ascending, at most `max`
    /// entries and about `max_bytes` bytes (at least one); `more` = further entries exist. `base(after, n)` = stored
    /// entries after the key (up to `n`, `more` as the store reports).
    pub fn range(
        &self,
        mut base: impl FnMut(Option<&[u8]>, usize) -> Result<(Vec<Kv>, bool), i32>,
        after: Option<&[u8]>,
        prefix: &[u8],
        max: usize,
        max_bytes: usize,
    ) -> Result<(Vec<Kv>, bool), i32> {
        let lo: Bound<&[u8]> = match after {
            Some(a) if a >= prefix => Bound::Excluded(a),
            _ if prefix.is_empty() => Bound::Unbounded,
            _ => Bound::Included(prefix),
        };
        let mut ins = self
            .ins
            .range::<[u8], _>((lo, Bound::Unbounded))
            .take_while(|(k, _)| k.starts_with(prefix))
            .peekable();
        let mut cursor: Option<Vec<u8>> = after.map(|a| a.to_vec());
        let mut page: std::collections::VecDeque<Kv> = Default::default();
        let mut base_more = !self.cleared;
        let mut out: Vec<Kv> = Vec::new();
        let mut bytes = 0usize;
        let page_n = max.clamp(16, 1024);
        loop {
            while page.is_empty() && base_more {
                let (v, more) = base(cursor.as_deref(), page_n)?;
                if let Some(l) = v.last() {
                    // `base` returns keys strictly after the cursor: the walk advances even when a whole page is removed
                    debug_assert!(
                        cursor.as_ref().is_none_or(|c| l.0 > *c),
                        "omap page without progress"
                    );
                    cursor = Some(l.0.clone());
                }
                base_more = more && !v.is_empty();
                page.extend(
                    v.into_iter()
                        .filter(|(k, _)| k.starts_with(prefix) && !self.deleted(k)),
                );
            }
            let take_base = match (page.front(), ins.peek()) {
                (None, None) => return Ok((out, false)),
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (Some(b), Some(i)) => {
                    if b.0.as_slice() == i.0.as_slice() {
                        page.pop_front(); // the overlay value wins
                        false
                    } else {
                        b.0.as_slice() < i.0.as_slice()
                    }
                }
            };
            if out.len() >= max || (!out.is_empty() && bytes >= max_bytes) {
                return Ok((out, true));
            }
            let kv = if take_base {
                page.pop_front().unwrap()
            } else {
                let (k, v) = ins.next().unwrap();
                (k.clone(), v.clone())
            };
            bytes += kv.0.len() + kv.1.len();
            out.push(kv);
        }
    }
}

impl Pg {
    /// Omap + cls on this EC pool (optimized pool with FLAG_OMAP, primary role available).
    pub fn ec_omap_ok(&self) -> bool {
        self.ecb().is_some_and(|b| b.omap)
            && self.pool.ec.as_ref().is_some_and(|e| e.optimized && e.omap)
    }

    /// EC_OMAP records of `soid` not rolled forward yet (see [`pending`]); the stored omap lacks them.
    pub(crate) fn ec_omap_pending(&self, soid: &Hobject) -> Result<Vec<EcOmap>, i32> {
        let es = self.log.entries();
        let rit = self.log.log.rollback_info_trimmed_to;
        let i0 = es.partition_point(|e| e.version <= rit);
        pending(es.range(i0..), soid).ok_or(EIO)
    }

    /// Overlay for reads of `soid`'s omap on top of the local shard's stored omap. `EAGAIN` while a write on the object
    /// is queued or uncommitted (the stored object may not reflect it yet: the op layer waits for it before it reads).
    pub fn ec_omap_overlay(&self, soid: &Hobject) -> Result<Overlay, i32> {
        if !self.ec_omap_ok() {
            return Err(EOPNOTSUPP);
        }
        if self.ec_write_in_flight(soid) {
            return Err(EAGAIN);
        }
        Ok(Overlay::of(&self.ec_omap_pending(soid)?))
    }

    /// Key-only read of the same pending log window and visibility gate.
    pub fn ec_omap_keys_overlay(&self, soid: &Hobject) -> Result<KeysOverlay, i32> {
        if !self.ec_omap_ok() {
            return Err(EOPNOTSUPP);
        }
        if self.ec_write_in_flight(soid) {
            return Err(EAGAIN);
        }
        let es = self.log.entries();
        let rit = self.log.log.rollback_info_trimmed_to;
        let i0 = es.partition_point(|e| e.version <= rit);
        Ok(KeysOverlay::of(
            pending_keys(es.range(i0..), soid).ok_or(EIO)?,
        ))
    }

    /// Replay records of the clone sources of a write being generated (spec 12.2): `src` -> pending records.
    pub(crate) fn ec_omap_replay(
        &self,
        srcs: &[Hobject],
    ) -> Result<BTreeMap<Hobject, Vec<EcOmap>>, i32> {
        srcs.iter()
            .map(|s| Ok((s.clone(), self.ec_omap_pending(s)?)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn projected(recs: &[EcOmap]) -> KeysOverlay {
        let mut b = ec::moddesc::ModDescBuilder::new();
        for r in recs {
            b.ec_omap(r);
        }
        KeysOverlay::of(project_omap_keys(&b.finish().0).unwrap().records)
    }

    #[test]
    fn projected_keys_match_value_merge_through_updates_and_limits() {
        let base = vec![
            kv("a", "base"),
            kv("p0", "base"),
            kv("p1", "base"),
            kv("p2", "base"),
            kv("z", "base"),
        ];
        let mut recs = Vec::new();
        for r in [
            ins(&[("b", "new"), ("p1", "replace"), ("p3", "new")]),
            EcOmap {
                ups: vec![OmapUp::Remove(vec![b"a".to_vec(), b"p3".to_vec()])],
                ..Default::default()
            },
            EcOmap {
                ups: vec![OmapUp::RemoveRange(b"p0".to_vec(), b"p2".to_vec())],
                ..Default::default()
            },
            ins(&[("p1", "after range"), ("p3", "after remove")]),
            EcOmap {
                ups: vec![OmapUp::RemoveRange(b"p1".to_vec(), Vec::new())],
                ..Default::default()
            },
            EcOmap {
                header: Some(b"unused header".to_vec()),
                ..Default::default()
            },
            EcOmap {
                clear: true,
                ..Default::default()
            },
            ins(&[("p0", "after clear"), ("z", "after clear")]),
        ] {
            recs.push(r);
            let values = Overlay::of(&recs);
            let keys = projected(&recs);
            assert_eq!(keys.is_empty(), values.is_empty());
            for after in [None, Some(b"p0".as_slice()), Some(b"z".as_slice())] {
                for prefix in [b"".as_slice(), b"p", b"x"] {
                    for max in [0, 1, 2, 10] {
                        for budget in [0, 1, 5, 6, 100] {
                            let (kv, more) = values
                                .range(base_of(base.clone()), after, prefix, max, usize::MAX)
                                .unwrap();
                            let mut expected = Vec::new();
                            let mut bytes = 0;
                            let mut expected_more = more;
                            for (k, _) in kv {
                                if bytes >= budget {
                                    expected_more = true;
                                    break;
                                }
                                bytes += 4 + k.len();
                                expected.push(k);
                            }
                            // Single-key base pages force merges across deletions/page boundaries.
                            let actual = keys
                                .range(
                                    |a, _| {
                                        let v: Vec<_> = base
                                            .iter()
                                            .filter(|(k, _)| {
                                                a.is_none_or(|a| k.as_slice() > a)
                                                    && k.starts_with(prefix)
                                            })
                                            .map(|(k, _)| k.clone())
                                            .collect();
                                        Ok((v.iter().take(1).cloned().collect(), v.len() > 1))
                                    },
                                    after,
                                    prefix,
                                    max,
                                    budget,
                                )
                                .unwrap();
                            assert_eq!(
                                actual,
                                (expected, expected_more),
                                "after={after:?} prefix={prefix:?} max={max} budget={budget}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn projected_pending_preserves_generation_resets_and_errors() {
        let soid = Hobject {
            snap: denc::types::SnapId::NOSNAP,
            ..Default::default()
        };
        let entry = |op, bl| LogEntry {
            op,
            soid: soid.clone(),
            mod_desc: pgwire::ObjectModDesc {
                bl,
                ..Default::default()
            },
            ..Default::default()
        };
        let omap = |k: &str| {
            let mut b = ec::moddesc::ModDescBuilder::new();
            b.ec_omap(&ins(&[(k, "value")]));
            b.finish().0
        };
        for op in [
            LogOp::DELETE,
            LogOp::LOST_DELETE,
            LogOp::REPLACE,
            LogOp::CLONE,
        ] {
            let es = [entry(LogOp::MODIFY, omap("old")), entry(op, omap("new"))];
            assert_eq!(
                pending_keys(&es, &soid),
                Some(project_omap_keys(&omap("new")).unwrap().records)
            );
        }
        for try_delete in [false, true] {
            let mut b = ec::moddesc::ModDescBuilder::new();
            if try_delete {
                b.try_delete(7);
            } else {
                b.delete(7);
            }
            b.ec_omap(&ins(&[("new", "value")]));
            let es = [
                entry(LogOp::MODIFY, omap("old")),
                entry(LogOp::MODIFY, b.finish().0),
            ];
            let old = pending(&es, &soid).unwrap();
            assert_eq!(
                pending_keys(&es, &soid),
                Some(project_omap_keys(&omap("new")).unwrap().records)
            );
            assert_eq!(old.len(), 1);
        }
        let mut bad = entry(LogOp::MODIFY, omap("bad"));
        bad.mod_desc.can_local_rollback = false;
        assert_eq!(pending_keys([&bad], &soid), None);
        bad.mod_desc.can_local_rollback = true;
        bad.mod_desc.bl = vec![99];
        assert_eq!(pending_keys([&bad], &soid), None);
    }

    #[test]
    fn projected_many_disjoint_ranges_leave_insertions_intact() {
        let keys: Vec<Vec<u8>> = (0..4096)
            .map(|i| format!("p/{i:06}").into_bytes())
            .collect();
        let mut ups = vec![OmapKeysUp::Insert(keys.clone())];
        ups.extend((0..512).map(|i| {
            OmapKeysUp::RemoveRange(
                format!("z/{i:06}").into_bytes(),
                format!("z/{:06}", i + 1).into_bytes(),
            )
        }));
        let o = KeysOverlay::of(vec![EcOmapKeys {
            ups,
            ..Default::default()
        }]);
        assert_eq!(o.ins.into_iter().collect::<Vec<_>>(), keys);
        // Each range's bounded tree iterator has zero hits; the implementation
        // neither walks nor copies the unrelated p/ keys for those deletions.
    }

    fn kv(k: &str, v: &str) -> Kv {
        (k.as_bytes().to_vec(), v.as_bytes().to_vec())
    }
    fn ins(p: &[(&str, &str)]) -> EcOmap {
        EcOmap {
            ups: vec![OmapUp::Insert(p.iter().map(|(k, v)| kv(k, v)).collect())],
            ..Default::default()
        }
    }
    #[expect(clippy::type_complexity)]
    fn base_of(m: Vec<Kv>) -> impl FnMut(Option<&[u8]>, usize) -> Result<(Vec<Kv>, bool), i32> {
        move |after, n| {
            let rest: Vec<Kv> = m
                .iter()
                .filter(|(k, _)| after.is_none_or(|a| k.as_slice() > a))
                .cloned()
                .collect();
            let more = rest.len() > n;
            Ok((rest.into_iter().take(n).collect(), more))
        }
    }
    fn keys(r: Result<(Vec<Kv>, bool), i32>) -> (Vec<String>, bool) {
        let (v, m) = r.unwrap();
        (
            v.into_iter()
                .map(|(k, _)| String::from_utf8(k).unwrap())
                .collect(),
            m,
        )
    }

    #[test]
    fn merge_order_and_overrides() {
        let base = vec![kv("a", "1"), kv("c", "1"), kv("e", "1")];
        let recs = vec![
            ins(&[("b", "2"), ("c", "2")]),
            EcOmap {
                ups: vec![OmapUp::Remove(vec![b"a".to_vec()])],
                ..Default::default()
            },
        ];
        let o = Overlay::of(&recs);
        let (v, more) = o
            .range(base_of(base.clone()), None, b"", 10, 1 << 20)
            .unwrap();
        assert!(!more);
        assert_eq!(v, vec![kv("b", "2"), kv("c", "2"), kv("e", "1")]);
        // limit and cursor
        assert_eq!(
            keys(o.range(base_of(base.clone()), None, b"", 2, 1 << 20)),
            (vec!["b".into(), "c".into()], true)
        );
        assert_eq!(
            keys(o.range(base_of(base), Some(b"b"), b"", 5, 1 << 20)),
            (vec!["c".into(), "e".into()], false)
        );
    }

    #[test]
    fn clear_range_header_order() {
        let base = vec![kv("a", "1"), kv("b", "1"), kv("c", "1")];
        // range [a, c) removes a, b; clear then insert keeps only the insert
        let r = EcOmap {
            ups: vec![OmapUp::RemoveRange(b"a".to_vec(), b"c".to_vec())],
            ..Default::default()
        };
        let o = Overlay::of(&[r]);
        assert_eq!(
            keys(o.range(base_of(base.clone()), None, b"", 9, 1 << 20)).0,
            vec!["c"]
        );
        let o = Overlay::of(&[
            ins(&[("z", "9")]),
            EcOmap {
                clear: true,
                ..Default::default()
            },
            ins(&[("y", "8")]),
        ]);
        assert!(o.cleared());
        assert_eq!(
            keys(o.range(base_of(base.clone()), None, b"", 9, 1 << 20)).0,
            vec!["y"]
        );
        // empty end removes nothing
        let o = Overlay::of(&[EcOmap {
            ups: vec![OmapUp::RemoveRange(b"a".to_vec(), Vec::new())],
            ..Default::default()
        }]);
        assert_eq!(
            keys(o.range(base_of(base.clone()), None, b"", 9, 1 << 20))
                .0
                .len(),
            3
        );
        // one record with clear + header: the shard applies the header first, the clear wipes it (UI-3)
        let o = Overlay::of(&[EcOmap {
            clear: true,
            header: Some(b"h".to_vec()),
            ..Default::default()
        }]);
        assert_eq!(o.header(b"old".to_vec()), Vec::<u8>::new());
        let o = Overlay::of(&[EcOmap {
            header: Some(b"h".to_vec()),
            ..Default::default()
        }]);
        assert_eq!(o.header(b"old".to_vec()), b"h");
        assert!(Overlay::default().is_empty());
    }

    #[test]
    fn prefix_and_bytes_budget() {
        let base = vec![kv("p1", "x"), kv("q1", "x")];
        let o = Overlay::of(&[ins(&[("p0", "y"), ("p2", "y"), ("q0", "y")])]);
        assert_eq!(
            keys(o.range(base_of(base.clone()), None, b"p", 9, 1 << 20)).0,
            vec!["p0", "p1", "p2"]
        );
        // byte budget stops after the first entry that reaches it, at least one entry always
        assert_eq!(
            keys(o.range(base_of(base), None, b"", 9, 1)),
            (vec!["p0".into()], true)
        );
    }

    /// Recovery byte cap (ecrec `ec_recov_omap_payload`): a capped read stops pulling base pages once past the budget,
    /// so an over-cap omap is never loaded whole.
    #[test]
    fn capped_read_stops_pulling_base_pages() {
        let big: Vec<Kv> = (0..10_000u32)
            .map(|i| (format!("k{i:06}").into_bytes(), vec![0u8; 1024]))
            .collect();
        let mut pulls = 0usize;
        let mut inner = base_of(big);
        let base = |after: Option<&[u8]>, n: usize| {
            pulls += 1;
            inner(after, n)
        };
        let o = Overlay::of(&[]);
        let (v, more) = o.range(base, None, b"", usize::MAX, 64 << 10).unwrap();
        assert!(more, "budget reached: more entries follow");
        assert!(v.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>() < 65 << 10);
        assert!(
            pulls <= 2,
            "base read bounded by the budget, pulled {pulls} pages"
        );
    }

    #[test]
    fn get_by_keys() {
        let o = Overlay::of(&[
            ins(&[("b", "2")]),
            EcOmap {
                ups: vec![OmapUp::Remove(vec![b"a".to_vec()])],
                ..Default::default()
            },
        ]);
        let base = BTreeMap::from([
            (b"a".to_vec(), b"1".to_vec()),
            (b"c".to_vec(), b"1".to_vec()),
        ]);
        let r = o.get(&[b"a", b"b", b"c", b"d"], base);
        assert_eq!(
            r.keys().map(|k| k.as_slice()).collect::<Vec<_>>(),
            vec![b"b".as_slice(), b"c"]
        );
    }
}
