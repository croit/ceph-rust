// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Leaf deltas (adr 0021 am. 19): a checkpoint writes the few changed keys of a lightly dirty leaf into a shared
//! delta page instead of rewriting the whole leaf (and, through the new address, its parents).
//!
//! * Touch log (in memory, per dirty leaf): the keys put/deleted and the key spans range-deleted since the leaf was
//!   last frozen. At a checkpoint it is turned into the NET diff against the page's previous durable state: the
//!   spans, then the touched keys with their current value (or "absent"). Order does not matter: untouched keys
//!   are unchanged, touched keys are set to their final state, spans only remove keys that no touched key re-sets.
//! * Delta entry (on disk, in `page::DELTA` pages): `[base addr u64][base crc u32][len u32][ops]`. A leaf keeps
//!   its on-disk address and its parent reference; the entries of a leaf (its chain) are applied in order to the
//!   base image whenever the page is read (`ChainSet::apply`). An entry only applies to the image it was taken
//!   against (address AND crc), so a stale entry of a page that was rewritten later is inert.
//! * Relog (segment cleaning, `FEAT_DELTA_RELOG`): a checkpoint may copy whole chains that pin the oldest segment into
//!   its own segment so that segment is freed. Bit 31 of `len` ([`RESTART`]) marks the first entry of such a copy: the
//!   loader drops what it has of that chain and starts it again (no entry is ever applied twice: an intermediate
//!   state of a replayed prefix may not fit the page).
//! * Ops: `[nspans u16] (alen u16, a, blen u16, b)* [nkeys u16] (klen u16, key, tag u8 {0 absent, 1 value}, [vlen u16,
//!   val])*`.
//! * Delta page: `[page header, kind DELTA][n u32][entries...]`.

use crate::fx::FxMap;
use crate::page::{self, HDR};
use std::collections::BTreeSet;

/// Bytes of an entry header (`addr`, `crc`, `len`).
pub const ENT_HDR: usize = 16;
/// Bytes before the first entry in a delta page body (entry count).
pub const BODY_HDR: usize = 4;
/// Entry `len` flag: first entry of a relogged chain (the chain restarts here).
pub const RESTART: u32 = 1 << 31;

/// Record `key` as touched (put or delete).
#[inline]
pub fn touch_key(t: &mut Vec<u8>, key: &[u8]) {
    t.push(0);
    t.extend_from_slice(&(key.len() as u16).to_le_bytes());
    t.extend_from_slice(key);
}

/// Record the key span `[a, b)` as range-deleted.
#[inline]
pub fn touch_span(t: &mut Vec<u8>, a: &[u8], b: &[u8]) {
    t.push(1);
    t.extend_from_slice(&(a.len() as u16).to_le_bytes());
    t.extend_from_slice(a);
    t.extend_from_slice(&(b.len() as u16).to_le_bytes());
    t.extend_from_slice(b);
}

fn rd16(b: &[u8], o: usize) -> Option<usize> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?) as usize)
}

/// Parse a touch log into point keys and spans.
type Spans<'a> = Vec<(&'a [u8], &'a [u8])>;

fn parse_touch(t: &[u8]) -> (Vec<&[u8]>, Spans<'_>) {
    let (mut keys, mut spans) = (Vec::new(), Vec::new());
    let mut o = 0;
    while o < t.len() {
        let tag = t[o];
        let kl = rd16(t, o + 1).expect("touch log");
        let a = &t[o + 3..o + 3 + kl];
        o += 3 + kl;
        if tag == 0 {
            keys.push(a);
        } else {
            let bl = rd16(t, o).expect("touch log");
            spans.push((a, &t[o + 2..o + 2 + bl]));
            o += 2 + bl;
        }
    }
    (keys, spans)
}

/// Result of [`build_ops`].
#[derive(Debug, PartialEq, Eq)]
pub enum Built {
    /// The ops exceed the limit: write the page whole.
    TooBig,
    /// The net diff is empty (nothing to write).
    Empty,
    /// The ops are in `out`; a key inside the leaf's range (to route to the page again later).
    Route(Vec<u8>),
}

/// Net diff of `leaf` (its current content) against its previous durable state, from the touch log `touched`.
pub fn build_ops(leaf: &[u8], touched: &[u8], limit: usize, out: &mut Vec<u8>) -> Built {
    let (mut keys, spans) = parse_touch(touched);
    keys.sort_unstable();
    keys.dedup();
    out.clear();
    out.extend_from_slice(&(spans.len() as u16).to_le_bytes());
    for (a, b) in &spans {
        out.extend_from_slice(&(a.len() as u16).to_le_bytes());
        out.extend_from_slice(a);
        out.extend_from_slice(&(b.len() as u16).to_le_bytes());
        out.extend_from_slice(b);
    }
    let np = out.len();
    out.extend_from_slice(&0u16.to_le_bytes());
    let mut nk = 0u16;
    for k in &keys {
        match page::leaf_search(leaf, k) {
            Ok(i) => {
                let v = page::leaf_ent(leaf, i).1;
                out.extend_from_slice(&(k.len() as u16).to_le_bytes());
                out.extend_from_slice(k);
                out.push(1);
                out.extend_from_slice(&(v.len() as u16).to_le_bytes());
                out.extend_from_slice(v);
                nk += 1;
            }
            Err(_) => {
                // absent: a span that covers it removes it anyway
                if spans.iter().any(|(a, b)| *a <= *k && *k < *b) {
                    continue;
                }
                out.extend_from_slice(&(k.len() as u16).to_le_bytes());
                out.extend_from_slice(k);
                out.push(0);
                nk += 1;
            }
        }
        if out.len() > limit {
            return Built::TooBig;
        }
    }
    out[np..np + 2].copy_from_slice(&nk.to_le_bytes());
    if out.len() > limit {
        return Built::TooBig;
    }
    route_of(out).map_or(Built::Empty, Built::Route)
}

/// A key inside the leaf the ops blob belongs to: the first touched key, else the start of the first span (every span
/// was clipped to keys that existed in the leaf). `None` for an empty or malformed blob.
pub fn route_of(ops: &[u8]) -> Option<Vec<u8>> {
    let ns = rd16(ops, 0)?;
    let mut o = 2;
    let mut first_span: Option<&[u8]> = None;
    for _ in 0..ns {
        let al = rd16(ops, o)?;
        let a = ops.get(o + 2..o + 2 + al)?;
        o += 2 + al;
        let bl = rd16(ops, o)?;
        o += 2 + bl;
        first_span.get_or_insert(a);
    }
    let nk = rd16(ops, o)?;
    if nk > 0 {
        let kl = rd16(ops, o + 2)?;
        return Some(ops.get(o + 4..o + 4 + kl)?.to_vec());
    }
    first_span.map(<[u8]>::to_vec)
}

/// Apply one ops blob to the leaf image `b`. `Err` = malformed ops or the result does not fit (corruption).
pub fn apply_ops(
    b: &mut [u8],
    tmp: &mut [u8],
    ents: &mut page::Ents,
    ops: &[u8],
) -> Result<(), &'static str> {
    let bad = "malformed leaf delta";
    let mut o = 0;
    let ns = rd16(ops, o).ok_or(bad)?;
    o += 2;
    for _ in 0..ns {
        let al = rd16(ops, o).ok_or(bad)?;
        let a = ops.get(o + 2..o + 2 + al).ok_or(bad)?;
        o += 2 + al;
        let bl = rd16(ops, o).ok_or(bad)?;
        let e = ops.get(o + 2..o + 2 + bl).ok_or(bad)?;
        o += 2 + bl;
        let (lo, hi) = (page::leaf_lower_bound(b, a), page::leaf_lower_bound(b, e));
        page::remove_range(b, ents, lo, hi);
    }
    let nk = rd16(ops, o).ok_or(bad)?;
    o += 2;
    let kv = o;
    // removals first, then the values: the page only grows towards its final state (which fits), never past it. Both
    // passes walk the same keys: the second needs no collected list (no allocation on the read path).
    let mut p = kv;
    for _ in 0..nk {
        let kl = rd16(ops, p).ok_or(bad)?;
        let k = ops.get(p + 2..p + 2 + kl).ok_or(bad)?;
        p += 2 + kl;
        match *ops.get(p).ok_or(bad)? {
            0 => {
                p += 1;
                if let Ok(i) = page::leaf_search(b, k) {
                    page::remove_range(b, ents, i, i + 1);
                }
            }
            1 => {
                let vl = rd16(ops, p + 1).ok_or(bad)?;
                ops.get(p + 3..p + 3 + vl).ok_or(bad)?;
                p += 3 + vl;
                // the old value goes with the removals (a replacement must not hold both versions at once)
                if let Ok(i) = page::leaf_search(b, k) {
                    page::remove_range(b, ents, i, i + 1);
                }
            }
            _ => return Err(bad),
        }
    }
    if p != ops.len() {
        return Err(bad);
    }
    let mut p = kv;
    for _ in 0..nk {
        let kl = rd16(ops, p).ok_or(bad)?;
        let k = ops.get(p + 2..p + 2 + kl).ok_or(bad)?;
        p += 2 + kl;
        if *ops.get(p).ok_or(bad)? == 1 {
            let vl = rd16(ops, p + 1).ok_or(bad)?;
            let v = ops.get(p + 3..p + 3 + vl).ok_or(bad)?;
            p += 3 + vl;
            if !page::leaf_put_nosplit(b, tmp, ents, k, v) {
                return Err("leaf delta does not fit its page");
            }
        } else {
            p += 1;
        }
    }
    Ok(())
}

/// The delta chain of one leaf: its entries in application order (each `[len u32][ops]`).
#[derive(Debug, Clone)]
pub struct Chain {
    /// crc of the base image the entries were taken against.
    pub crc: u32,
    pub ops: Vec<u8>,
    /// Sequence number of the oldest segment holding one of its entries.
    pub oldest: u64,
    /// A key inside the leaf (routes to it again).
    pub route: Vec<u8>,
}

/// The entries' ops of a chain's `ops` (`[len u32][ops]*`), in application order.
pub fn blobs(ops: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut o = 0;
    std::iter::from_fn(move || {
        if o >= ops.len() {
            return None;
        }
        let l = u32::from_le_bytes(ops[o..o + 4].try_into().unwrap()) as usize;
        let r = &ops[o + 4..o + 4 + l];
        o += 4 + l;
        Some(r)
    })
}

/// Fresh delta pages entries of ops lengths `lens` take after the page being filled (`used` bytes, `None` = no page).
pub fn new_pages(psz: usize, used: Option<usize>, lens: impl IntoIterator<Item = usize>) -> usize {
    let (mut n, mut off) = (0, used.unwrap_or(psz));
    for l in lens {
        if off + ENT_HDR + l > psz {
            n += 1;
            off = HDR + BODY_HDR;
        }
        off += ENT_HDR + l;
    }
    n
}

/// All chains of a shard, by base page address.
#[derive(Debug, Default)]
pub struct ChainSet {
    map: FxMap<u64, Chain>,
    /// `(oldest, addr)` of every chain: the holders of a segment and the fold order without a scan.
    age: BTreeSet<(u64, u64)>,
    bytes: usize,
}

impl ChainSet {
    pub fn new() -> ChainSet {
        ChainSet::default()
    }
    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    /// Bytes of ops held (the RAM the chains cost).
    pub fn bytes(&self) -> usize {
        self.bytes
    }
    pub fn get(&self, addr: u64) -> Option<&Chain> {
        self.map.get(&addr)
    }
    pub fn clear(&mut self) {
        self.map.clear();
        self.age.clear();
        self.bytes = 0;
    }
    pub fn remove(&mut self, addr: u64) -> bool {
        match self.map.remove(&addr) {
            Some(c) => {
                self.bytes -= c.ops.len();
                self.age.remove(&(c.oldest, addr));
                true
            }
            None => false,
        }
    }
    /// Append an entry taken against the base image `(addr, crc)` in segment `seq`. An entry against another image
    /// of the same address replaces the chain (that page was rewritten; the old entries are stale).
    pub fn add(&mut self, addr: u64, crc: u32, seq: u64, route: &[u8], ops: &[u8]) {
        if self.map.get(&addr).is_some_and(|c| c.crc != crc) {
            self.remove(addr);
        }
        let c = self.map.entry(addr).or_insert_with(|| {
            self.age.insert((seq, addr));
            Chain {
                crc,
                ops: Vec::new(),
                oldest: seq,
                route: route.to_vec(),
            }
        });
        c.ops.extend_from_slice(&(ops.len() as u32).to_le_bytes());
        c.ops.extend_from_slice(ops);
        self.bytes += 4 + ops.len();
    }
    /// Mount / fsck: one entry of a persisted segment `seq` (`len` with its [`RESTART`] flag).
    pub fn load(
        &mut self,
        addr: u64,
        crc: u32,
        seq: u64,
        len: u32,
        ops: &[u8],
    ) -> Result<(), &'static str> {
        let route = route_of(ops).ok_or("empty entry")?;
        if len & RESTART != 0 {
            self.remove(addr);
        }
        self.add(addr, crc, seq, &route, ops);
        Ok(())
    }
    /// Relog: lend the ops of the chain at `addr` out (`(crc, ops)`; the chain keeps its place and byte count) until
    /// [`ChainSet::relogged`] gives them back.
    pub fn lend(&mut self, addr: u64) -> (u32, Vec<u8>) {
        let c = self.map.get_mut(&addr).expect("relogged chain");
        (c.crc, std::mem::take(&mut c.ops))
    }
    /// The whole chain at `addr` (its ops back from [`ChainSet::lend`]) was copied into segment `seq`: its older
    /// segments no longer hold it.
    pub fn relogged(&mut self, addr: u64, ops: Vec<u8>, seq: u64) {
        let c = self.map.get_mut(&addr).expect("relogged chain");
        debug_assert!(c.ops.is_empty());
        c.ops = ops;
        self.age.remove(&(c.oldest, addr));
        c.oldest = seq;
        self.age.insert((seq, addr));
    }
    /// Give lent ops back unchanged (not relogged).
    pub fn give_back(&mut self, addr: u64, ops: Vec<u8>) {
        let c = self.map.get_mut(&addr).expect("lent chain");
        debug_assert!(c.ops.is_empty());
        c.ops = ops;
    }
    /// Addresses of the chains holding segment `seq` or an older one (`holds`), oldest first, at most `max`.
    pub fn holders(&self, seq: u64, max: usize) -> Vec<u64> {
        self.age
            .range(..=(seq, u64::MAX))
            .take(max)
            .map(|&(_, a)| a)
            .collect()
    }
    /// Bytes the chain of the base image `(addr, crc)` has now (0 if none; a chain of another image is stale).
    pub fn chain_bytes(&self, addr: u64, crc: u32) -> usize {
        self.map
            .get(&addr)
            .filter(|c| c.crc == crc)
            .map_or(0, |c| c.ops.len())
    }
    /// Apply the chain of the base image `(addr, crc)` to `b` (no-op without a matching chain).
    pub fn apply(
        &self,
        addr: u64,
        crc: u32,
        b: &mut [u8],
        tmp: &mut [u8],
        ents: &mut page::Ents,
    ) -> Result<(), &'static str> {
        let Some(c) = self.map.get(&addr).filter(|c| c.crc == crc) else {
            return Ok(());
        };
        for ops in blobs(&c.ops) {
            apply_ops(b, tmp, ents, ops)?;
        }
        Ok(())
    }
    /// The chains to fold back first: oldest first (by the segment of their oldest entry, then address) until their
    /// bytes add up to `want`, at most `max`: `(addr, crc, route)`. The order is deterministic (a retry picks the same).
    pub fn victims(&self, want: usize, max: usize) -> Vec<(u64, u32, Vec<u8>)> {
        let (mut got, mut out) = (0usize, Vec::new());
        for &(_, a) in &self.age {
            if got >= want || out.len() >= max {
                break;
            }
            let c = &self.map[&a];
            out.push((a, c.crc, c.route.clone()));
            got += c.ops.len();
        }
        out
    }
    /// Does any chain still hold an entry of segment `seq`? (`oldest` only tells the first; a chain's entries come
    /// from consecutive segments, so `oldest <= seq` and `newest >= seq` would be exact: entries of a chain are
    /// added in segment order, the check below is conservative: a chain keeps a segment alive while it is the
    /// oldest one holding it.)
    pub fn holds(&self, seq: u64) -> bool {
        self.age.first().is_some_and(|&(o, _)| o <= seq)
    }
}

/// Builds delta pages: entries are appended until the page body is full.
#[derive(Debug)]
pub struct PageFill {
    pub buf: Vec<u8>,
    n: u32,
    off: usize,
}

impl PageFill {
    /// `buf` is a page-sized buffer whose header the caller initialises (`page::init(.., page::DELTA, ..)`).
    pub fn new(buf: Vec<u8>) -> PageFill {
        PageFill {
            buf,
            n: 0,
            off: HDR + BODY_HDR,
        }
    }
    pub fn fits(&self, ops_len: usize) -> bool {
        self.off + ENT_HDR + ops_len <= self.buf.len()
    }
    pub fn is_empty(&self) -> bool {
        self.n == 0
    }
    /// Bytes of the page in use (header and entries).
    pub fn used(&self) -> usize {
        self.off
    }
    /// Append an entry; `restart` = first entry of a relogged chain ([`RESTART`]).
    pub fn push(&mut self, addr: u64, crc: u32, restart: bool, ops: &[u8]) {
        debug_assert!(self.fits(ops.len()));
        let o = self.off;
        let len = ops.len() as u32 | if restart { RESTART } else { 0 };
        self.buf[o..o + 8].copy_from_slice(&addr.to_le_bytes());
        self.buf[o + 8..o + 12].copy_from_slice(&crc.to_le_bytes());
        self.buf[o + 12..o + 16].copy_from_slice(&len.to_le_bytes());
        self.buf[o + 16..o + 16 + ops.len()].copy_from_slice(ops);
        self.off += ENT_HDR + ops.len();
        self.n += 1;
    }
    /// Write the entry count and zero the unused tail (a reused buffer); the caller seals the page.
    pub fn finish(mut self) -> Vec<u8> {
        let n = self.n;
        self.buf[HDR..HDR + 4].copy_from_slice(&n.to_le_bytes());
        self.buf[self.off..].fill(0);
        self.buf
    }
}

/// One entry of a delta page: base address, base crc, `len` word (ops length and [`RESTART`] flag), ops.
pub type PageEntry<'a> = (u64, u32, u32, &'a [u8]);

/// Entries of a delta page (already validated with `page::validate_delta`).
pub fn parse_page(b: &[u8]) -> Result<Vec<PageEntry<'_>>, &'static str> {
    let bad = "malformed delta page";
    let n = u32::from_le_bytes(b.get(HDR..HDR + 4).ok_or(bad)?.try_into().unwrap()) as usize;
    let mut o = HDR + BODY_HDR;
    let mut v = Vec::new();
    for _ in 0..n {
        let h = b.get(o..o + ENT_HDR).ok_or(bad)?;
        let w = u32::from_le_bytes(h[12..16].try_into().unwrap());
        let l = (w & !RESTART) as usize;
        let ops = b.get(o + ENT_HDR..o + ENT_HDR + l).ok_or(bad)?;
        v.push((
            u64::from_le_bytes(h[0..8].try_into().unwrap()),
            u32::from_le_bytes(h[8..12].try_into().unwrap()),
            w,
            ops,
        ));
        o += ENT_HDR + l;
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::page::{Ents, FMT_SLOTTED};
    use std::collections::BTreeMap;

    fn leaf_from(m: &BTreeMap<Vec<u8>, Vec<u8>>, psz: usize) -> Vec<u8> {
        let mut e = Ents::default();
        for (k, v) in m {
            e.push(k, v);
        }
        let mut b = vec![0u8; psz];
        page::init(&mut b, page::LEAF, 0, 8, 0);
        assert!(page::build(&mut b, &e, 0, e.len(), FMT_SLOTTED));
        b
    }

    fn content(b: &[u8]) -> BTreeMap<Vec<u8>, Vec<u8>> {
        let mut m = BTreeMap::new();
        let mut k = Vec::new();
        for i in 0..page::nslots(b) {
            k.clear();
            page::key_into(b, i, &mut k);
            m.insert(k.clone(), page::leaf_ent(b, i).1.to_vec());
        }
        m
    }

    /// Random edits through touch logs: base + delta == edited page, over several rounds (a chain).
    #[test]
    fn delta_of_random_edits_reproduces_the_page() {
        let mut rng = crate::rng::Rng::new(5);
        let psz = 4096;
        let key = |i: u64| format!("k/{i:05}/{}", "x".repeat((i % 7) as usize)).into_bytes();
        let mut model: BTreeMap<Vec<u8>, Vec<u8>> = (0..30)
            .map(|i| (key(i * 3), vec![i as u8; 20 + (i % 5) as usize]))
            .collect();
        let base = leaf_from(&model, psz);
        let mut cur = base.clone();
        let mut chain: Vec<Vec<u8>> = Vec::new();
        let (mut tmp, mut ents) = (vec![0u8; psz], Ents::default());
        for _round in 0..40 {
            let mut touched = Vec::new();
            for _ in 0..rng.range(1, 6) {
                match rng.below(4) {
                    0 | 1 => {
                        let k = key(rng.below(100));
                        let v = vec![rng.below(250) as u8; rng.range(0, 60) as usize];
                        touch_key(&mut touched, &k);
                        if !page::leaf_put_nosplit(&mut cur, &mut tmp, &mut ents, &k, &v) {
                            touched.clear();
                            break;
                        }
                        model.insert(k, v);
                    }
                    2 => {
                        let k = key(rng.below(100));
                        touch_key(&mut touched, &k);
                        if let Ok(i) = page::leaf_search(&cur, &k) {
                            page::remove_range(&mut cur, &mut ents, i, i + 1);
                        }
                        model.remove(&k);
                    }
                    _ => {
                        let (a, b) = (key(rng.below(100)), key(rng.below(100)));
                        if a < b {
                            let (lo, hi) = (
                                page::leaf_lower_bound(&cur, &a),
                                page::leaf_lower_bound(&cur, &b),
                            );
                            page::remove_range(&mut cur, &mut ents, lo, hi);
                            touch_span(&mut touched, &a, &b);
                            model.retain(|k, _| !(*k >= a && *k < b));
                        }
                    }
                }
            }
            assert_eq!(content(&cur), model);
            if touched.is_empty() {
                continue;
            }
            let mut ops = Vec::new();
            match build_ops(&cur, &touched, 4096, &mut ops) {
                Built::TooBig => break,
                Built::Empty => continue,
                Built::Route(_) => {}
            }
            chain.push(ops);
            // base + the whole chain == the current page
            let mut re = base.clone();
            for o in &chain {
                apply_ops(&mut re, &mut tmp, &mut ents, o).unwrap();
            }
            assert_eq!(content(&re), model);
        }
        assert!(chain.len() > 5);
    }

    /// `apply_ops` runs on every leaf read that has a chain: it must not allocate (the removals pass and the value
    /// pass walk the ops blob; the old code collected the puts into a fresh `Vec`).
    #[test]
    fn apply_ops_does_not_allocate() {
        let psz = 4096;
        let m: BTreeMap<Vec<u8>, Vec<u8>> = (0..10u8)
            .map(|i| (format!("k/{i:02}").into_bytes(), vec![i; 8]))
            .collect();
        let base = leaf_from(&m, psz);
        let mut t = Vec::new();
        touch_span(&mut t, b"k/02", b"k/04");
        touch_key(&mut t, b"k/07");
        touch_key(&mut t, b"k/08");
        let mut ops = Vec::new();
        assert!(matches!(
            build_ops(&base, &t, psz, &mut ops),
            Built::Route(_)
        ));
        let (mut tmp, mut ents) = (vec![0u8; psz], Ents::default());
        let mut warm = base.clone();
        apply_ops(&mut warm, &mut tmp, &mut ents, &ops).unwrap();
        let mut b = base.clone();
        let n = crate::test_alloc::allocations(|| {
            apply_ops(&mut b, &mut tmp, &mut ents, &ops).unwrap()
        });
        assert_eq!(n, 0, "the value pass collects its puts");
    }

    #[test]
    fn malformed_ops_are_rejected_never_panic() {
        let psz = 4096;
        let m: BTreeMap<Vec<u8>, Vec<u8>> =
            (0..10u8).map(|i| (vec![b'k', i], vec![i; 8])).collect();
        let base = leaf_from(&m, psz);
        let mut touched = Vec::new();
        touch_key(&mut touched, b"k\x03");
        touch_span(&mut touched, b"k\x05", b"k\x08");
        let mut ops = Vec::new();
        assert!(matches!(
            build_ops(&base, &touched, 4096, &mut ops),
            Built::Route(_)
        ));
        let (mut tmp, mut ents) = (vec![0u8; psz], Ents::default());
        let mut rng = crate::rng::Rng::new(1);
        for _ in 0..2000 {
            let mut o = ops.clone();
            match rng.below(3) {
                0 => o.truncate(rng.below(o.len() as u64) as usize),
                1 => {
                    let i = rng.below(o.len() as u64) as usize;
                    o[i] ^= 1 << rng.below(8);
                }
                _ => o.push(rng.below(256) as u8),
            }
            let mut b = base.clone();
            let _ = apply_ops(&mut b, &mut tmp, &mut ents, &o);
        }
    }

    #[test]
    fn pages_roundtrip() {
        let psz = 4096;
        let mut b = vec![0u8; psz];
        page::init(&mut b, page::DELTA, 0, 77, 3);
        let mut f = PageFill::new(b);
        f.push(5, 6, false, b"abc");
        f.push(7, 8, true, b"");
        assert!(!f.fits(psz));
        let mut b = f.finish();
        page::seal(&mut b, 77, 9);
        page::validate_delta(&b, psz, 77).unwrap();
        assert!(page::validate_delta(&b, psz, 78).is_err());
        let e = parse_page(&b).unwrap();
        assert_eq!(e, vec![(5, 6, 3, &b"abc"[..]), (7, 8, RESTART, &b""[..])]);
    }

    /// `victims` walks the age index: same result as a full sort of all chains, for every
    /// `want` / `max`, with duplicate segment numbers (ties broken by address).
    #[test]
    fn victims_equal_the_sorted_prefix() {
        let mut r = crate::rng::Rng::new(7);
        for n in [0usize, 1, 5, 64, 65, 300] {
            let mut cs = ChainSet::new();
            for _ in 0..n {
                let addr = r.below(1 << 20) * 8;
                let seq = r.below(9);
                let len = r.range(1, 40) as usize;
                cs.add(addr, addr as u32, seq, &addr.to_le_bytes(), &vec![1u8; len]);
            }
            for max in [0usize, 1, 3, 64, 1000] {
                for want in [0usize, 1, 100, usize::MAX] {
                    let mut all: Vec<(u64, u64, usize)> = cs
                        .map
                        .iter()
                        .map(|(a, c)| (c.oldest, *a, c.ops.len()))
                        .collect();
                    all.sort_unstable();
                    let (mut got, mut exp) = (0usize, Vec::new());
                    for (_, a, l) in all {
                        if got >= want || exp.len() >= max {
                            break;
                        }
                        let c = cs.get(a).unwrap();
                        exp.push((a, c.crc, c.route.clone()));
                        got += l;
                    }
                    assert_eq!(cs.victims(want, max), exp, "n {n} max {max} want {want}");
                }
            }
        }
    }

    /// The age index follows add / replace / remove / relog: `holds` and `holders` match a scan of all chains, and a
    /// loaded [`RESTART`] entry starts its chain again (the earlier copy is not applied twice).
    #[test]
    fn age_index_and_restart() {
        let mut r = crate::rng::Rng::new(11);
        let mut cs = ChainSet::new();
        for step in 0..2000u64 {
            let addr = r.below(64) * 8;
            match r.below(4) {
                0 => cs.add(addr, r.below(2) as u32, step / 50, b"k", b"x"),
                1 => {
                    cs.remove(addr);
                }
                2 if cs.get(addr).is_some() => {
                    let (_, ops) = cs.lend(addr);
                    cs.relogged(addr, ops, step / 50 + 1);
                }
                _ => {}
            }
            let seq = r.below(step / 50 + 2);
            let scan: Vec<u64> = {
                let mut v: Vec<(u64, u64)> = cs
                    .map
                    .iter()
                    .filter(|(_, c)| c.oldest <= seq)
                    .map(|(a, c)| (c.oldest, *a))
                    .collect();
                v.sort_unstable();
                v.into_iter().map(|x| x.1).collect()
            };
            assert_eq!(cs.holds(seq), !scan.is_empty());
            assert_eq!(cs.holders(seq, usize::MAX), scan);
            assert_eq!(cs.holders(seq, 2), scan[..scan.len().min(2)]);
            assert_eq!(cs.age.len(), cs.map.len());
        }
        // restart on load
        let mut m = BTreeMap::new();
        m.insert(b"a".to_vec(), b"1".to_vec());
        let leaf = leaf_from(&m, 4096);
        let (mut t, mut e1) = (Vec::new(), Vec::new());
        touch_key(&mut t, b"a");
        assert!(matches!(
            build_ops(&leaf, &t, 1024, &mut e1),
            Built::Route(_)
        ));
        let mut cs = ChainSet::new();
        cs.load(8, 1, 1, e1.len() as u32, &e1).unwrap();
        cs.load(8, 1, 2, e1.len() as u32 | RESTART, &e1).unwrap();
        assert_eq!(cs.chain_bytes(8, 1), 4 + e1.len());
        assert_eq!(cs.get(8).unwrap().oldest, 2);
        cs.load(8, 1, 2, e1.len() as u32, &e1).unwrap();
        assert_eq!(cs.chain_bytes(8, 1), 2 * (4 + e1.len()));
        assert_eq!(cs.get(8).unwrap().oldest, 2);
    }

    /// `new_pages` (the relog room check) counts exactly the pages `PageFill` takes for the same entries.
    #[test]
    fn new_pages_matches_the_fill() {
        let mut r = crate::rng::Rng::new(3);
        let psz = 4096;
        for _ in 0..300 {
            let lens: Vec<usize> = (0..r.below(40))
                .map(|_| r.below(psz as u64 / 4) as usize)
                .collect();
            let start = r.below(2) == 1;
            let mut fill: Option<PageFill> = start.then(|| PageFill::new(vec![0u8; psz]));
            if let Some(f) = fill.as_mut() {
                f.push(1, 1, false, &vec![0u8; r.below(1500) as usize]);
            }
            let want = new_pages(psz, fill.as_ref().map(PageFill::used), lens.iter().copied());
            let mut got = 0;
            for &l in &lens {
                if fill.as_ref().is_none_or(|f| !f.fits(l)) {
                    fill = Some(PageFill::new(vec![0u8; psz]));
                    got += 1;
                }
                fill.as_mut().unwrap().push(2, 2, false, &vec![0u8; l]);
            }
            assert_eq!(want, got);
        }
    }
}
