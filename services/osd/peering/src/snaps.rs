// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Snapshot bookkeeping shared by the PG machinery, the stores and the trimmer (spec snaptrim.md 2, 4).
//!
//! * Interval-set helpers on `BTreeMap<start, len>` (the `pg_info_t.purged_snaps` shape).
//! * The SnapMapper index of one PG: `clone -> snaps` (reverse) and `(snap, clone)` (forward) as ordered key/value
//!   pairs. Layout is ours (adr 0037): one object-local key space per PG, so the index moves, splits and dies with the
//!   PG. [`apply`] maintains both directions over any [`MapKv`] (the in-memory model and the NVMe store share it).
//! * Mapper maintenance hooks: which log entry / recovery event changes which mapping ([`entry_op`], [`push_ops`]).

use denc::types::{Hobject, SnapId};
use pgwire::{LogEntry, LogOp};
use replwire::SnapSet;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------------------------------------- intervals

/// `interval_set<u64>` as `start -> len` (disjoint, non-adjacent).
pub type Ivs = BTreeMap<u64, u64>;

pub fn iv_contains(s: &Ivs, v: u64) -> bool {
    s.range(..=v)
        .next_back()
        .is_some_and(|(a, l)| v < a.saturating_add(*l))
}

/// Number of ids (sum of lengths), saturating.
pub fn iv_len(s: &Ivs) -> u64 {
    s.values().fold(0u64, |a, l| a.saturating_add(*l))
}

pub fn iv_insert(s: &mut Ivs, start: u64, len: u64) {
    if len == 0 {
        return;
    }
    let (mut a, mut e) = (start, start.saturating_add(len));
    if let Some((&ps, &pl)) = s.range(..=a).next_back() {
        let pe = ps.saturating_add(pl);
        if pe >= a {
            a = ps;
            e = e.max(pe);
        }
    }
    let hit: Vec<u64> = s.range(a..=e).map(|(k, _)| *k).collect();
    for k in hit {
        let l = s.remove(&k).unwrap_or(0);
        e = e.max(k.saturating_add(l));
    }
    s.insert(a, e - a);
}

pub fn iv_erase(s: &mut Ivs, start: u64, len: u64) {
    if len == 0 {
        return;
    }
    let e = start.saturating_add(len);
    let hit: Vec<(u64, u64)> = s
        .range(..e)
        .filter(|(a, l)| a.saturating_add(**l) > start)
        .map(|(a, l)| (*a, *l))
        .collect();
    for (a, l) in hit {
        s.remove(&a);
        let ae = a.saturating_add(l);
        if a < start {
            s.insert(a, start - a);
        }
        if ae > e {
            s.insert(e, ae - e);
        }
    }
}

/// `a - b`.
pub fn iv_subtract(a: &Ivs, b: &Ivs) -> Ivs {
    let mut r = a.clone();
    for (s, l) in b {
        iv_erase(&mut r, *s, *l);
    }
    r
}

/// `a & b` (disjoint sets; per range only the relevant fragments of `b` are visited).
pub fn iv_intersect(a: &Ivs, b: &Ivs) -> Ivs {
    let mut r = Ivs::new();
    for (s, l) in a {
        for (lo, len) in replwire::interval::intersect_range(b, *s, s.saturating_add(*l)) {
            iv_insert(&mut r, lo, len);
        }
    }
    r
}

pub fn iv_from_pairs(p: &[(u64, u64)]) -> Ivs {
    let mut r = Ivs::new();
    for (s, l) in p {
        iv_insert(&mut r, *s, *l);
    }
    r
}

/// First `max` intervals (`pg_stat_t.purged_snaps` cap).
pub fn iv_head(s: &Ivs, max: usize) -> Ivs {
    s.iter().take(max).map(|(a, l)| (*a, *l)).collect()
}

/// `[3~1,a~2]` (hex, `pg query` / `ceph osd pool ls detail` shape).
pub fn iv_text(s: &Ivs) -> String {
    let v: Vec<String> = s.iter().map(|(a, l)| format!("{a:x}~{l:x}")).collect();
    format!("[{}]", v.join(","))
}

// --------------------------------------------------------------------------------------------------------- snaps blob

/// `entry.snaps` / `ObjectInfo` snap vector: `u32 n + n * u64`, any order, as a sorted unique set. Malformed = empty.
pub fn decode_snaps(b: &[u8]) -> Vec<u64> {
    let Some(n) = b
        .get(..4)
        .map(|x| u32::from_le_bytes(x.try_into().unwrap()))
    else {
        return Vec::new();
    };
    let n = n as usize;
    if b.len() != 4 + 8 * n {
        return Vec::new();
    }
    let mut v: Vec<u64> = b[4..]
        .as_chunks::<8>()
        .0
        .iter()
        .map(|c| u64::from_le_bytes(*c))
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

pub fn encode_snaps(v: &[u64]) -> Vec<u8> {
    let mut b = Vec::with_capacity(4 + 8 * v.len());
    b.extend_from_slice(&(v.len() as u32).to_le_bytes());
    for x in v {
        b.extend_from_slice(&x.to_le_bytes());
    }
    b
}

/// A clone object: head snaps are NOSNAP / SNAPDIR.
pub fn is_clone(h: &Hobject) -> bool {
    h.snap.0 <= SnapId::MAXSNAP.0 && !h.is_temp()
}

// ------------------------------------------------------------------------------------------------------------ mapper

/// One mapper mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MapOp {
    /// `clone -> snaps` (replaces any previous mapping of the clone; `add` and `update` are the same op). `snaps`
    /// is a non-empty set.
    Set { clone: Hobject, snaps: Vec<u64> },
    /// Drop the clone's mapping (absent = fine).
    Remove { clone: Hobject },
}

const K_REV: u8 = b'c';
pub const K_FWD: u8 = b's';
/// Encoded hobjects up to this size are used verbatim in keys; longer ones are replaced by a 128-bit digest (the
/// store limits key sizes; the full hobject always travels in the value).
const INLINE_MAX: usize = 200;

fn fnv(seed: u64, b: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64 ^ seed;
    for x in b {
        h ^= u64::from(*x);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn mkey(h: &Hobject) -> Vec<u8> {
    let enc = denc::to_vec(h).unwrap_or_default();
    if enc.len() <= INLINE_MAX {
        let mut k = Vec::with_capacity(1 + enc.len());
        k.push(0);
        k.extend_from_slice(&enc);
        k
    } else {
        let mut k = Vec::with_capacity(21);
        k.push(1);
        k.extend_from_slice(&h.hash.to_be_bytes());
        k.extend_from_slice(&fnv(0, &enc).to_be_bytes());
        k.extend_from_slice(&fnv(0x9e37_79b9_7f4a_7c15, &enc).to_be_bytes());
        k
    }
}

/// Reverse key of `clone`.
pub fn rev_key(clone: &Hobject) -> Vec<u8> {
    let mut k = vec![K_REV];
    k.extend_from_slice(&mkey(clone));
    k
}

/// Forward key `(snap, clone)`.
pub fn fwd_key(snap: u64, clone: &Hobject) -> Vec<u8> {
    let mut k = vec![K_FWD];
    k.extend_from_slice(&snap.to_be_bytes());
    k.extend_from_slice(&mkey(clone));
    k
}

/// Snap of a forward key.
pub fn fwd_snap(key: &[u8]) -> u64 {
    key.get(1..9)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u64::from_be_bytes)
}

/// First forward key of `snap` (scan start); a key belongs to `snap` iff it starts with [`fwd_prefix`].
pub fn fwd_prefix(snap: u64) -> Vec<u8> {
    let mut k = vec![K_FWD];
    k.extend_from_slice(&snap.to_be_bytes());
    k
}

/// Hash of the clone a reverse or forward key names, read from the key alone. Split and merge place mapper entries
/// by this hash and never decode values (classic filters its OSD-wide mapper by hash bits, split-merge.md 4/7): a
/// damaged value travels unchanged with its clone and is reported by its reader. `None`: not a mapper key.
pub fn key_hash(key: &[u8]) -> Option<u32> {
    let m = match *key.first()? {
        K_REV => &key[1..],
        K_FWD => key.get(9..)?,
        _ => return None,
    };
    match m.split_first()? {
        (0, enc) => denc::from_slice::<Hobject>(enc).ok().map(|h| h.hash),
        (1, d) if d.len() == 20 => d[..4].try_into().ok().map(u32::from_be_bytes),
        _ => None,
    }
}

/// Reverse range `[REV_FIRST, REV_END)`.
pub const REV_FIRST: &[u8] = &[K_REV];
pub const REV_END: &[u8] = &[K_REV + 1];
/// Forward range.
pub const FWD_FIRST: &[u8] = &[K_FWD];
pub const FWD_END: &[u8] = &[K_FWD + 1];

pub fn enc_rev_val(clone: &Hobject, snaps: &[u64]) -> Vec<u8> {
    denc::to_vec(&(clone.clone(), snaps.to_vec())).unwrap_or_default()
}

pub fn dec_rev_val(b: &[u8]) -> Option<(Hobject, Vec<u64>)> {
    denc::from_slice::<(Hobject, Vec<u64>)>(b).ok()
}

pub fn enc_fwd_val(clone: &Hobject) -> Vec<u8> {
    denc::to_vec(clone).unwrap_or_default()
}

pub fn dec_fwd_val(b: &[u8]) -> Option<Hobject> {
    denc::from_slice::<Hobject>(b).ok()
}

/// Key/value access of one PG's mapper space.
pub trait MapKv {
    type Err;
    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Err>;
    fn put(&mut self, key: Vec<u8>, val: Vec<u8>);
    fn del(&mut self, key: Vec<u8>);
}

/// Snaps currently mapped to `clone`.
pub fn get_snaps<K: MapKv>(kv: &mut K, clone: &Hobject) -> Result<Option<Vec<u64>>, K::Err> {
    Ok(kv
        .get(&rev_key(clone))?
        .and_then(|v| dec_rev_val(&v))
        .map(|(_, s)| s))
}

/// Apply one mutation (reverse + forward keys together).
pub fn apply<K: MapKv>(kv: &mut K, op: &MapOp) -> Result<(), K::Err> {
    let (clone, new) = match op {
        MapOp::Set { clone, snaps } => (clone, Some(snaps)),
        MapOp::Remove { clone } => (clone, None),
    };
    if let Some(old) = get_snaps(kv, clone)? {
        for s in old {
            if new.is_none_or(|n| !n.contains(&s)) {
                kv.del(fwd_key(s, clone));
            }
        }
    }
    match new {
        Some(n) => {
            let fv = enc_fwd_val(clone);
            for s in n {
                kv.put(fwd_key(*s, clone), fv.clone());
            }
            kv.put(rev_key(clone), enc_rev_val(clone, n));
        }
        None => kv.del(rev_key(clone)),
    }
    Ok(())
}

/// Mutation implied by a log entry (spec 4 maintenance points); `None` = nothing to do. Heads are skipped; an empty
/// snap set on an update entry keeps the old mapping (a classic primary never sends one, tolerate it).
pub fn entry_op(e: &LogEntry) -> Option<MapOp> {
    if !is_clone(&e.soid) {
        return None;
    }
    match e.op {
        LogOp::CLONE | LogOp::PROMOTE | LogOp::MODIFY | LogOp::REPLACE => {
            let snaps = decode_snaps(&e.snaps);
            (!snaps.is_empty()).then(|| MapOp::Set {
                clone: e.soid.clone(),
                snaps,
            })
        }
        LogOp::DELETE | LogOp::LOST_DELETE => Some(MapOp::Remove {
            clone: e.soid.clone(),
        }),
        _ => None,
    }
}

/// Mutations after a recovery push of `clone` completed: drop the old mapping, add the head SnapSet's `clone_snaps`
/// entry (missing = no mapping, scrub notices).
pub fn push_ops(clone: &Hobject, ss: &SnapSet) -> Vec<MapOp> {
    let mut v = vec![MapOp::Remove {
        clone: clone.clone(),
    }];
    if let Some(s) = ss.clone_snaps.get(&clone.snap) {
        let mut snaps: Vec<u64> = s.iter().map(|x| x.0).collect();
        snaps.sort_unstable();
        snaps.dedup();
        if !snaps.is_empty() {
            v.push(MapOp::Set {
                clone: clone.clone(),
                snaps,
            });
        }
    }
    v
}

/// In-memory mapper (MemStore, tests, oracle).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemMap(pub BTreeMap<Vec<u8>, Vec<u8>>);

impl MapKv for MemMap {
    type Err = std::convert::Infallible;
    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Err> {
        Ok(self.0.get(key).cloned())
    }
    fn put(&mut self, key: Vec<u8>, val: Vec<u8>) {
        self.0.insert(key, val);
    }
    fn del(&mut self, key: Vec<u8>) {
        self.0.remove(&key);
    }
}

impl MemMap {
    pub fn apply(&mut self, op: &MapOp) {
        let _ = apply(self, op);
    }
    /// Up to `max` clones mapped to `snap`; `Err` = an entry of the index does not decode (never skipped: the caller
    /// would take the snap for trimmed).
    pub fn next(
        &self,
        snap: u64,
        max: usize,
    ) -> Result<Vec<Hobject>, crate::store::StoreReadError> {
        let p = fwd_prefix(snap);
        self.0
            .range(p.clone()..)
            .take_while(|(k, _)| k.starts_with(&p))
            .take(max)
            .map(|(_, v)| dec_fwd_val(v).ok_or(crate::store::StoreReadError::Corrupt))
            .collect()
    }
    /// Forward entries from key `from` (inclusive): up to `max` snaps, one per entry, ascending, and the key to go on
    /// from when more follow ([`crate::store::PgStoreOps::snapmap_scan`]).
    pub fn scan(
        &self,
        from: &[u8],
        max: usize,
    ) -> Result<(Vec<u64>, Option<Vec<u8>>), crate::store::StoreReadError> {
        let mut snaps = Vec::new();
        let mut it = self
            .0
            .range(from.to_vec()..)
            .take_while(|(k, _)| k.first() == Some(&K_FWD));
        for (k, _) in it.by_ref().take(max) {
            snaps.push(fwd_snap(k));
        }
        let more = it.next().map(|(k, _)| k.clone());
        Ok((snaps, more))
    }
    pub fn get(&self, clone: &Hobject) -> Option<Vec<u64>> {
        self.0
            .get(&rev_key(clone))
            .and_then(|v| dec_rev_val(v))
            .map(|(_, s)| s)
    }
    /// Every `(clone, snaps)`.
    pub fn all(&self) -> Vec<(Hobject, Vec<u64>)> {
        self.0
            .range(REV_FIRST.to_vec()..REV_END.to_vec())
            .filter_map(|(_, v)| dec_rev_val(v))
            .collect()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Reverse + forward key/value pairs of one mapping (bulk copy between PGs).
pub fn entry_pairs(clone: &Hobject, snaps: &[u64]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let fv = enc_fwd_val(clone);
    let mut v: Vec<(Vec<u8>, Vec<u8>)> = snaps
        .iter()
        .map(|s| (fwd_key(*s, clone), fv.clone()))
        .collect();
    v.push((rev_key(clone), enc_rev_val(clone, snaps)));
    v
}

/// Keys of one mapping.
pub fn entry_keys(clone: &Hobject, snaps: &[u64]) -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = snaps.iter().map(|s| fwd_key(*s, clone)).collect();
    v.push(rev_key(clone));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clone(name: &str, snap: u64) -> Hobject {
        Hobject::new(name.as_bytes(), SnapId(snap), 7, 1, b"")
    }

    #[test]
    fn intervals() {
        let mut s = Ivs::new();
        iv_insert(&mut s, 3, 1);
        iv_insert(&mut s, 10, 2);
        iv_insert(&mut s, 4, 2);
        assert_eq!(iv_text(&s), "[3~3,a~2]");
        assert!(iv_contains(&s, 5) && !iv_contains(&s, 6));
        assert_eq!(iv_len(&s), 5);
        let b = iv_from_pairs(&[(4, 7)]);
        assert_eq!(iv_text(&iv_intersect(&s, &b)), "[4~2,a~1]");
        assert_eq!(iv_text(&iv_subtract(&s, &b)), "[3~1,b~1]");
        assert_eq!(iv_head(&s, 1).len(), 1);
    }

    #[test]
    fn mapper_ops() {
        let mut m = MemMap::default();
        let (a, b) = (clone("a", 8), clone("b", 8));
        m.apply(&MapOp::Set {
            clone: a.clone(),
            snaps: vec![5, 7],
        });
        m.apply(&MapOp::Set {
            clone: b.clone(),
            snaps: vec![7],
        });
        assert_eq!(m.next(7, 10).unwrap().len(), 2);
        assert_eq!(m.next(5, 10).unwrap(), vec![a.clone()]);
        // update: drops forward key of 7 for a
        m.apply(&MapOp::Set {
            clone: a.clone(),
            snaps: vec![5],
        });
        assert_eq!(m.next(7, 10).unwrap(), vec![b.clone()]);
        assert_eq!(m.get(&a), Some(vec![5]));
        m.apply(&MapOp::Remove { clone: a.clone() });
        m.apply(&MapOp::Remove { clone: a.clone() }); // ENOENT tolerated
        assert!(m.next(5, 10).unwrap().is_empty());
        m.apply(&MapOp::Remove { clone: b });
        assert!(m.is_empty());
    }

    #[test]
    fn long_names_use_digest() {
        let name = "x".repeat(1500);
        let c = clone(&name, 4);
        assert!(rev_key(&c).len() < 40);
        let mut m = MemMap::default();
        m.apply(&MapOp::Set {
            clone: c.clone(),
            snaps: vec![2],
        });
        assert_eq!(m.next(2, 5).unwrap(), vec![c.clone()]);
        assert_eq!(m.all().len(), 1);
    }

    /// Split/merge place entries by the clone hash in the key (inline and digest keys, reverse and forward).
    #[test]
    fn key_hash_reads_the_clone_hash_from_every_key() {
        for name in ["o".to_string(), "x".repeat(1500)] {
            let mut c = clone(&name, 4);
            c.hash = 0xdead_beef;
            for (k, _) in entry_pairs(&c, &[2, 3]) {
                assert_eq!(key_hash(&k), Some(0xdead_beef));
            }
        }
        assert_eq!(key_hash(b""), None);
        assert_eq!(key_hash(&[K_REV, 0, 0xff]), None);
        assert_eq!(key_hash(&[b'x', 1, 0, 0, 0, 1]), None);
    }

    /// An index entry that does not decode is an error, never a skipped clone (the trimmer would take the snap for done).
    #[test]
    fn undecodable_index_value_is_an_error() {
        let c = clone("o", 4);
        let mut m = MemMap::default();
        m.apply(&MapOp::Set {
            clone: c,
            snaps: vec![2],
        });
        let k =
            m.0.keys()
                .find(|k| k.starts_with(&fwd_prefix(2)))
                .unwrap()
                .clone();
        m.0.insert(k, vec![0xff]);
        assert_eq!(m.next(2, 5), Err(crate::store::StoreReadError::Corrupt));
    }

    #[test]
    fn hooks() {
        let mut e = LogEntry {
            soid: clone("o", 8),
            op: LogOp::CLONE,
            snaps: encode_snaps(&[7, 5]),
            ..Default::default()
        };
        assert_eq!(
            entry_op(&e),
            Some(MapOp::Set {
                clone: e.soid.clone(),
                snaps: vec![5, 7]
            })
        );
        e.snaps = encode_snaps(&[]);
        assert_eq!(entry_op(&e), None);
        e.op = LogOp::DELETE;
        assert!(matches!(entry_op(&e), Some(MapOp::Remove { .. })));
        e.soid.snap = SnapId::NOSNAP;
        assert_eq!(entry_op(&e), None);
    }
}
