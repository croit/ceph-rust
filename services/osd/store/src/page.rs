// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Slotted B+tree page (design 2.6, 3): fixed-size image, per-page common key prefix stored once, sorted `u16`
//! slot array growing up, entry heap growing down, binary search. The in-memory image IS the on-disk image
//! (mutated in place; `crc` is set when the page is frozen for a checkpoint).
//!
//! ```text
//! 0  crc u32 (of bytes 4..)   4 magic u16   6 kind u8   7 level u8   8 nslots u16   10 plen u16
//! 12 heap_lo u16   14 frag u16   16 gen_lsn u64   24 self_addr u64   32 shard u32   36 fmt u8   37..40 reserved
//! 40 prefix[plen] | slots[nslots] u16 ...gap... heap (entries, grows down from the page end)
//! leaf entry:     klen u16 | vlen u16 | key suffix | value
//! interior entry: klen u16 | key suffix | child addr u64 | child crc u32     (slot 0: klen = 0, key = -inf)
//! ```
//! Interior slot `i` covers keys in `[key_i, key_{i+1})` (key_0 = the page's lower fence, kept in the parent).
//!
//! Interior pages come in two formats (`fmt`, byte 36; leaves are always fmt 0, old stores have only fmt 0 pages):
//! * fmt 0 (above): slotted, editable in place.
//! * fmt 1 (compact interior, adr 0021 am. 13; rebuilt wholesale on every structural change, only child
//!   references are patched in place): the slot array is a RESTART array (`nrestart = ceil(n / RESTART)` u16
//!   offsets of every 16th entry), `heap_lo` = start of the entry area (right after it), `frag` = its length:
//!   ```text
//!   40 prefix[plen] | restart offsets u16 x nrestart | entries in key order
//!   entry: lcp varint | slen varint | key suffix[slen] | child addr u40 | child crc u32
//!   ```
//!   The key of an entry is the page prefix + (the previous entry's suffix up to `lcp` bytes) + `suffix`; restart
//!   entries have `lcp` 0. Entry 0 is slot 0 (key = -inf, empty suffix). varint: 1 byte below 128, else 2 bytes
//!   `0x80 | v >> 8`, `v & 0xff`. The child address is 5 bytes: real addresses (< 2^39 blocks) as is, virtual
//!   (unfrozen) pages as bit 39 + counter. Per child ~13 B instead of ~21 B for dense keys, ~17 instead of ~29 B for
//!   hierarchical keys.

use crate::codec::crc;
use std::cmp::Ordering;

pub const HDR: usize = 40;
pub const MAGIC: u16 = 0xB7EE;
pub const LEAF: u8 = 1;
pub const INT: u8 = 2;
pub const REF_LEN: usize = 12;
/// Interior page formats (header byte 36).
pub const FMT_SLOTTED: u8 = 0;
pub const FMT_COMPACT: u8 = 1;
/// Entries per restart group of a compact interior page.
pub const RESTART: usize = 16;
/// Marker of virtual (not yet written) pages in the in-memory tree (see `tree::VIRT`).
pub const VIRT: u64 = 1 << 63;
/// Real child addresses of compact pages must stay below this (2 PiB of 4 KiB blocks).
pub const ADDR_LIMIT: u64 = 1 << 39;

#[inline]
fn r16(b: &[u8], o: usize) -> usize {
    u16::from_le_bytes([b[o], b[o + 1]]) as usize
}
#[inline]
fn w16(b: &mut [u8], o: usize, v: usize) {
    debug_assert!(v <= u16::MAX as usize);
    b[o..o + 2].copy_from_slice(&(v as u16).to_le_bytes());
}
#[inline]
fn r64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
#[inline]
fn r32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

pub fn kind(b: &[u8]) -> u8 {
    b[6]
}
pub fn level(b: &[u8]) -> u8 {
    b[7]
}
pub fn nslots(b: &[u8]) -> usize {
    r16(b, 8)
}
fn plen(b: &[u8]) -> usize {
    r16(b, 10)
}
fn heap_lo(b: &[u8]) -> usize {
    r16(b, 12)
}
fn frag(b: &[u8]) -> usize {
    r16(b, 14)
}
pub fn self_addr(b: &[u8]) -> u64 {
    r64(b, 24)
}
pub fn stored_crc(b: &[u8]) -> u32 {
    r32(b, 0)
}
pub fn prefix(b: &[u8]) -> &[u8] {
    &b[HDR..HDR + plen(b)]
}
fn sl_base(b: &[u8]) -> usize {
    HDR + plen(b)
}
fn slot(b: &[u8], i: usize) -> usize {
    r16(b, sl_base(b) + 2 * i)
}
/// Bytes used by the heap entry at `o`.
fn ent_size(b: &[u8], o: usize, kind: u8) -> usize {
    if kind == LEAF {
        4 + r16(b, o) + r16(b, o + 2)
    } else {
        2 + r16(b, o) + REF_LEN
    }
}
/// Free bytes between the slot array and the heap (without reclaimable fragmentation). Compact interior pages:
/// all bytes after the entry area.
pub fn gap(b: &[u8]) -> usize {
    if is_compact(b) {
        return b.len() - heap_lo(b) - frag(b);
    }
    heap_lo(b) - (HDR + plen(b) + 2 * nslots(b))
}
/// Gap plus reclaimable fragmentation.
pub fn free_total(b: &[u8]) -> usize {
    if is_compact(b) {
        return gap(b);
    }
    gap(b) + frag(b)
}

/// Interior page format (see the module doc); leaves are always `FMT_SLOTTED`.
pub fn fmt(b: &[u8]) -> u8 {
    b[36]
}

/// Compact interior page (fmt 1).
#[inline]
pub fn is_compact(b: &[u8]) -> bool {
    b[6] == INT && b[36] == FMT_COMPACT
}

/// Format an empty page (slotted format).
pub fn init(b: &mut [u8], kind: u8, level: u8, addr: u64, shard: u32) {
    init_fmt(b, kind, level, addr, shard, FMT_SLOTTED);
}

/// Format an empty page; interior pages get `fmt`, leaves are always slotted. An empty compact page has no entries
/// (callers fill it with `build`).
pub fn init_fmt(b: &mut [u8], kind: u8, level: u8, addr: u64, shard: u32, fmt: u8) {
    let n = b.len();
    b[..HDR].fill(0);
    b[4..6].copy_from_slice(&MAGIC.to_le_bytes());
    b[6] = kind;
    b[7] = level;
    w16(b, 12, n);
    b[24..32].copy_from_slice(&addr.to_le_bytes());
    b[32..36].copy_from_slice(&shard.to_le_bytes());
    b[36] = if kind == INT { fmt } else { FMT_SLOTTED };
    if is_compact(b) {
        w16(b, 12, HDR);
    }
}

/// Reset an emptied page (keeps kind/level/addr).
fn reset(b: &mut [u8]) {
    let n = b.len();
    w16(b, 8, 0);
    w16(b, 10, 0);
    w16(b, 12, if is_compact(b) { HDR } else { n });
    w16(b, 14, 0);
    w16(b, 37, 0);
}

/// Stamp address, generation and crc (page is about to be written).
pub fn seal(b: &mut [u8], addr: u64, lsn: u64) -> u32 {
    b[24..32].copy_from_slice(&addr.to_le_bytes());
    b[16..24].copy_from_slice(&lsn.to_le_bytes());
    let c = crc(&b[4..]);
    b[0..4].copy_from_slice(&c.to_le_bytes());
    c
}

/// Kind of a page holding a piece of the elastic meta image (see `alloc::blob_pack`); never a tree page.
pub const BLOB: u8 = 3;

/// Validation of an elastic meta image page: crc, magic, kind, self address.
pub fn validate_blob(b: &[u8], psz: usize, addr: u64) -> Result<(), &'static str> {
    if b.len() != psz {
        return Err("page size");
    }
    if stored_crc(b) != crc(&b[4..]) {
        return Err("meta image page crc");
    }
    if u16::from_le_bytes([b[4], b[5]]) != MAGIC || kind(b) != BLOB {
        return Err("meta image page magic");
    }
    if self_addr(b) != addr {
        return Err("misdirected meta image page");
    }
    Ok(())
}

/// Kind of a page holding leaf deltas (adr 0021 am. 19, `delta`); never a tree page.
pub const DELTA: u8 = 4;

/// Validation of a delta page: crc, magic, kind, self address.
pub fn validate_delta(b: &[u8], psz: usize, addr: u64) -> Result<(), &'static str> {
    if b.len() != psz {
        return Err("page size");
    }
    if stored_crc(b) != crc(&b[4..]) {
        return Err("delta page crc");
    }
    if u16::from_le_bytes([b[4], b[5]]) != MAGIC || kind(b) != DELTA {
        return Err("delta page magic");
    }
    if self_addr(b) != addr {
        return Err("misdirected delta page");
    }
    Ok(())
}

/// Structural validation of an image read from disk: crc, magic, bounds, no virtual child references. Does not
/// check key order (fsck does).
pub fn validate(b: &[u8], psz: usize, addr: u64) -> Result<(), &'static str> {
    check_image(b, psz, addr, true)
}

/// `validate`; `stored` false = an in-memory image (virtual children allowed; tests).
fn check_image(b: &[u8], psz: usize, addr: u64, stored: bool) -> Result<(), &'static str> {
    if b.len() != psz {
        return Err("page size");
    }
    if stored_crc(b) != crc(&b[4..]) {
        return Err("page crc");
    }
    if u16::from_le_bytes([b[4], b[5]]) != MAGIC {
        return Err("page magic");
    }
    if self_addr(b) != addr {
        return Err("misdirected page (self addr)");
    }
    let k = kind(b);
    if k != LEAF && k != INT {
        return Err("page kind");
    }
    if (k == LEAF) != (level(b) == 0) {
        return Err("page kind/level");
    }
    if b[36] > FMT_COMPACT || k == LEAF && b[36] != FMT_SLOTTED {
        return Err("page format");
    }
    if is_compact(b) {
        return validate_compact(b, psz, stored);
    }
    let (n, pl, hl) = (nslots(b), plen(b), heap_lo(b));
    if HDR + pl + 2 * n > hl || hl > psz || frag(b) > psz {
        return Err("page header bounds");
    }
    let mut used = 0;
    for i in 0..n {
        let o = slot(b, i);
        if o < hl || o + 2 > psz {
            return Err("slot offset");
        }
        let min = if k == LEAF { 4 } else { 2 + REF_LEN };
        if o + min > psz {
            return Err("entry bounds");
        }
        let s = ent_size(b, o, k);
        if o + s > psz {
            return Err("entry bounds");
        }
        if stored && k == INT && int_ent(b, i).1 & VIRT != 0 {
            return Err("virtual child address in a stored page");
        }
        used += s;
    }
    if used + frag(b) != psz - hl {
        return Err("heap accounting");
    }
    Ok(())
}

// ------------------------------------------------------------------ entry access

pub fn leaf_ent(b: &[u8], i: usize) -> (&[u8], &[u8]) {
    let o = slot(b, i);
    let (kl, vl) = (r16(b, o), r16(b, o + 2));
    (&b[o + 4..o + 4 + kl], &b[o + 4 + kl..o + 4 + kl + vl])
}

/// (key suffix, child addr, child crc). Slot 0 has an empty suffix. Slotted interior pages only (compact pages
/// store front-coded suffixes: use `key_into` / `int_child`).
pub fn int_ent(b: &[u8], i: usize) -> (&[u8], u64, u32) {
    debug_assert!(!is_compact(b));
    let o = slot(b, i);
    let kl = r16(b, o);
    (
        &b[o + 2..o + 2 + kl],
        r64(b, o + 2 + kl),
        r32(b, o + 10 + kl),
    )
}

pub fn int_child(b: &[u8], i: usize) -> (u64, u32) {
    if is_compact(b) {
        let (_, sp, sl, _) = c_parse(b, c_off(b, i));
        return (dec_addr(r40(b, sp + sl)), r32(b, sp + sl + 5));
    }
    let (_, a, c) = int_ent(b, i);
    (a, c)
}

pub fn int_set_ref(b: &mut [u8], i: usize, addr: u64, c: u32) {
    if is_compact(b) {
        let (_, sp, sl, _) = c_parse(b, c_off(b, i));
        w40(b, sp + sl, enc_addr(addr));
        b[sp + sl + 5..sp + sl + 9].copy_from_slice(&c.to_le_bytes());
        return;
    }
    let o = slot(b, i);
    let kl = r16(b, o);
    b[o + 2 + kl..o + 10 + kl].copy_from_slice(&addr.to_le_bytes());
    b[o + 10 + kl..o + 14 + kl].copy_from_slice(&c.to_le_bytes());
}

/// Full key of entry `i` (prefix + suffix) appended to `out`.
pub fn key_into(b: &[u8], i: usize, out: &mut Vec<u8>) {
    out.extend_from_slice(prefix(b));
    if is_compact(b) {
        // decode the restart group up to entry i (suffix = previous suffix up to lcp + stored bytes)
        let base = out.len();
        let g = rs_of(b, i);
        let mut o = rs_off(b, g);
        for _ in 0..=i - rs_idx(b, g) {
            let (lcp, sp, sl, next) = c_parse(b, o);
            out.truncate(base + lcp);
            out.extend_from_slice(&b[sp..sp + sl]);
            o = next;
        }
        return;
    }
    out.extend_from_slice(if kind(b) == LEAF {
        leaf_ent(b, i).0
    } else {
        int_ent(b, i).0
    });
}

/// Does interior entry `i` have exactly the full key `key`? (Slot 0: the page prefix.) `scratch` decodes the key
/// (reused: a range scan calls this once per interior page, no allocation on a warm buffer).
pub fn int_key_eq(b: &[u8], i: usize, key: &[u8], scratch: &mut Vec<u8>) -> bool {
    if !is_compact(b) {
        let (sfx, _, _) = int_ent(b, i);
        let p = prefix(b);
        return key.len() == p.len() + sfx.len() && key.starts_with(p) && &key[p.len()..] == sfx;
    }
    scratch.clear();
    key_into(b, i, scratch);
    scratch.as_slice() == key
}

// ------------------------------------------------------------------ compact interior pages (fmt 1)

fn rvar(b: &[u8], o: &mut usize) -> usize {
    let x = b[*o];
    if x < 0x80 {
        *o += 1;
        x as usize
    } else {
        let v = ((x & 0x7f) as usize) << 8 | b[*o + 1] as usize;
        *o += 2;
        v
    }
}

fn var_len(v: usize) -> usize {
    if v < 0x80 { 1 } else { 2 }
}

fn wvar(b: &mut [u8], o: &mut usize, v: usize) {
    debug_assert!(v < 0x8000);
    if v < 0x80 {
        b[*o] = v as u8;
        *o += 1;
    } else {
        b[*o] = 0x80 | (v >> 8) as u8;
        b[*o + 1] = v as u8;
        *o += 2;
    }
}

fn r40(b: &[u8], o: usize) -> u64 {
    let mut x = [0u8; 8];
    x[..5].copy_from_slice(&b[o..o + 5]);
    u64::from_le_bytes(x)
}

fn w40(b: &mut [u8], o: usize, v: u64) {
    debug_assert!(v < 1 << 40);
    b[o..o + 5].copy_from_slice(&v.to_le_bytes()[..5]);
}

/// In-page form of a child address: virtual pages (`VIRT | n`) become `ADDR_LIMIT | n`.
fn enc_addr(a: u64) -> u64 {
    if a & VIRT != 0 {
        ADDR_LIMIT | (a & !VIRT)
    } else {
        assert!(
            a < ADDR_LIMIT,
            "page address beyond the compact reference range"
        );
        a
    }
}

fn dec_addr(v: u64) -> u64 {
    if v & ADDR_LIMIT != 0 {
        VIRT | (v & (ADDR_LIMIT - 1))
    } else {
        v
    }
}

/// Restarts of a compact page (header bytes 37..39).
fn n_restarts(b: &[u8]) -> usize {
    r16(b, 37)
}

/// Entry index / byte offset of restart `g`.
fn rs_idx(b: &[u8], g: usize) -> usize {
    r16(b, HDR + plen(b) + 4 * g)
}
fn rs_off(b: &[u8], g: usize) -> usize {
    r16(b, HDR + plen(b) + 4 * g + 2)
}

/// Last restart whose entry index is `<= i`.
fn rs_of(b: &[u8], i: usize) -> usize {
    let (mut lo, mut hi) = (1, n_restarts(b));
    while lo < hi {
        let mid = (lo + hi) / 2;
        if rs_idx(b, mid) <= i {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo - 1
}

/// Entry at `o`: `(lcp, suffix start, suffix len, next entry offset)`.
#[inline(always)]
fn c_parse(b: &[u8], o: usize) -> (usize, usize, usize, usize) {
    // fast path: both varints one byte (lcp and stored length < 128)
    let (x, y) = (b[o], b[o + 1]);
    if (x | y) < 0x80 {
        return (x as usize, o + 2, y as usize, o + 11 + y as usize);
    }
    let mut p = o;
    let lcp = rvar(b, &mut p);
    let sl = rvar(b, &mut p);
    (lcp, p, sl, p + sl + 9)
}

/// Offset of entry `i`.
fn c_off(b: &[u8], i: usize) -> usize {
    let g = rs_of(b, i);
    let mut o = rs_off(b, g);
    for _ in 0..i - rs_idx(b, g) {
        o = c_parse(b, o).3;
    }
    o
}

fn validate_compact(b: &[u8], psz: usize, stored: bool) -> Result<(), &'static str> {
    let (n, pl, hl, dl, nr) = (nslots(b), plen(b), heap_lo(b), frag(b), n_restarts(b));
    if hl != HDR + pl + 4 * nr || hl + dl > psz || (n == 0) != (nr == 0) || nr > n {
        return Err("page header bounds");
    }
    let end = hl + dl;
    let (mut o, mut prev_len, mut g) = (hl, 0usize, 0usize);
    for i in 0..n {
        let listed = g < nr && r16(b, HDR + pl + 4 * g) == i;
        // two varints (<= 2 bytes each) must fit before the end of the entry area
        if o + 2 > end {
            return Err("entry bounds");
        }
        let mut p = o;
        let lcp = rvar(b, &mut p);
        // the length varint may take 2 bytes (every valid entry has >= 10 more after the lcp)
        if p + 2 > end {
            return Err("entry bounds");
        }
        let sl = rvar(b, &mut p);
        if listed {
            if lcp != 0 || r16(b, HDR + pl + 4 * g + 2) != o {
                return Err("restart entry");
            }
            g += 1;
        } else if lcp == 0 || i == 0 {
            return Err("restart list");
        }
        if lcp > prev_len || (i == 0 && sl != 0) {
            return Err("entry prefix length");
        }
        o = p + sl + 9;
        if o > end {
            return Err("entry bounds");
        }
        if stored && r40(b, p + sl) & ADDR_LIMIT != 0 {
            return Err("virtual child address in a stored page");
        }
        prev_len = lcp + sl;
    }
    if o != end || g != nr {
        return Err("heap accounting");
    }
    Ok(())
}

/// Result of [`c_route`].
struct CRoute {
    /// The last entry whose key is `<= k`.
    idx: usize,
    /// Offset of its child reference.
    refo: usize,
    /// Entry `idx + 1` (none: `idx` is the last entry) as `(lcp, suffix start, suffix len)`: its key is the page
    /// prefix + `k[..lcp]` + the suffix.
    next: Option<(usize, usize, usize)>,
}

/// Child covering `k` (the search key without the page prefix) in a compact interior page with `n >= 2` entries:
/// the last entry whose key is `<= k`. Restart keys are searched first, then the winning run is decoded
/// incrementally; the relation of each entry to `k` follows from the entry before it and its `lcp`, no key is
/// ever materialised.
///
/// The entry after the child shares its first `lcp` bytes with `k`: either it is the first entry found above `k`, which
/// is only decided by a comparison, made when `lcp <= lp` (`lp` = common prefix of the previous key and `k`), or it
/// starts the next restart run (`lcp` 0).
fn c_route(b: &[u8], k: &[u8]) -> CRoute {
    let (n, nr) = (nslots(b), n_restarts(b));
    // first restart (>= 1) whose key is > k
    let (mut lo, mut hi) = (1, nr);
    while lo < hi {
        let mid = (lo + hi) / 2;
        let (_, sp, sl, _) = c_parse(b, rs_off(b, mid));
        if &b[sp..sp + sl] <= k {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let g = lo - 1;
    let (first, end) = (rs_idx(b, g), if g + 1 < nr { rs_idx(b, g + 1) } else { n });
    let mut o = rs_off(b, g);
    let (mut last, mut refo) = (first, 0);
    // lp = common prefix of the previous entry's key and k, greater = previous key > k
    let (mut lp, mut greater) = (0usize, false);
    for idx in first..end {
        let (lcp, sp, sl, next) = c_parse(b, o);
        o = next;
        // slot 0 = -inf; lcp > lp: the entry differs from k at the same byte as the previous one
        if idx != 0 && lcp <= lp {
            let kk = &k[lcp..];
            let s = &b[sp..sp + sl];
            let c = s.iter().zip(kk).take_while(|(x, y)| x == y).count();
            lp = lcp + c;
            greater = if c < sl && c < kk.len() {
                s[c] > kk[c]
            } else {
                // equal, or one is a prefix of the other: the longer one is greater
                sl > kk.len()
            };
        }
        if greater {
            return CRoute {
                idx: last,
                refo,
                next: Some((lcp, sp, sl)),
            };
        }
        last = idx;
        refo = sp + sl;
    }
    let next = (end < n).then(|| {
        let (_, sp, sl, _) = c_parse(b, o);
        (0, sp, sl)
    });
    CRoute {
        idx: last,
        refo,
        next,
    }
}

/// Per-entry encoding of `e[lo..hi]` as a compact page body: calls `f(j, lcp, restart, suffix)` in order (`j` = entry
/// number in the page; entry 0 is slot 0 with an empty suffix). An entry is a restart when it is the first, shares
/// nothing with its predecessor, was one in the source page (`e.flags`, removal keeps the encoding stable so a
/// page can never grow) or - fresh encodes only - when the run since the last restart reaches `RESTART`.
fn c_plan(e: &Ents, lo: usize, hi: usize, pl: usize, mut f: impl FnMut(usize, usize, bool, &[u8])) {
    let mut prev: &[u8] = &[];
    let mut run = 0usize;
    for (j, i) in (lo..hi).enumerate() {
        let sfx: &[u8] = if j == 0 { &[] } else { &e.key(i)[pl..] };
        let mut lcp = if j == 0 { 0 } else { lcp(prev, sfx) };
        let restart = j == 0
            || lcp == 0
            || if e.flags.is_empty() {
                run >= RESTART
            } else {
                e.flags[i]
            };
        if restart {
            lcp = 0;
            run = 1;
        } else {
            run += 1;
        }
        f(j, lcp, restart, sfx);
        prev = sfx;
    }
}

/// In-place edit of a compact interior page: replace the entries `[lo, hi)` (`1 <= lo <= hi <= n`) by `ins` (None:
/// pure removal, `lo == hi`: pure insert at `lo`), streaming the page through `s.tmp`. Everything outside the edit is
/// copied verbatim; only the entry after the edit (`D`) is re-encoded against its new predecessor (it keeps a
/// restart if it was one, so a removal never grows the page) and the restart list is patched. False, page
/// untouched: the result would not fit, or the new key does not start with the page prefix (rebuild instead).
fn c_splice(
    b: &mut [u8],
    s: &mut Ents,
    lo: usize,
    hi: usize,
    ins: Option<(&[u8], u64, u32)>,
) -> bool {
    let psz = b.len();
    let (n, pl, nr, hl, dl) = (nslots(b), plen(b), n_restarts(b), heap_lo(b), frag(b));
    debug_assert!(1 <= lo && lo <= hi && hi <= n);
    let bkey: &[u8] = match ins {
        Some((k, ..)) if !k.starts_with(prefix(b)) => return false,
        Some((k, ..)) => &k[pl..],
        None => &[],
    };
    let ins_n = ins.is_some() as usize;
    // A = entry lo-1: its full suffix, and the run it sits in
    let ga = rs_of(b, lo - 1);
    let mut o = rs_off(b, ga);
    s.ka.clear();
    for _ in rs_idx(b, ga)..lo {
        let (lcp, sp, sl, next) = c_parse(b, o);
        s.ka.truncate(lcp);
        s.ka.extend_from_slice(&b[sp..sp + sl]);
        o = next;
    }
    let off_lo = o;
    // the removed entries, to find D's full suffix
    s.kd.clear();
    s.kd.extend_from_slice(&s.ka);
    for _ in lo..hi {
        let (lcp, sp, sl, next) = c_parse(b, o);
        s.kd.truncate(lcp);
        s.kd.extend_from_slice(&b[sp..sp + sl]);
        o = next;
    }
    let off_d = o;
    // B
    let (mut b_restart, mut b_len) = (false, 0usize);
    let mut b_lcp = 0;
    if ins.is_some() {
        b_lcp = lcp(&s.ka, bkey);
        // runs stay bounded exactly like a fresh encode does: B restarts when the run it would join gets longer than RESTART
        let next_restart = (0..nr)
            .map(|g| rs_idx(b, g))
            .find(|&i| i >= hi)
            .unwrap_or(n);
        let run = (lo - rs_idx(b, ga)) + 1 + (next_restart - hi);
        b_restart = b_lcp == 0 || run > RESTART;
        if b_restart {
            b_lcp = 0;
        }
        let stored = bkey.len() - b_lcp;
        b_len = var_len(b_lcp) + var_len(stored) + stored + 9;
    }
    // D: unchanged when it is a restart, else re-encoded against B (or A)
    let (mut tail_start, mut d_new_len, mut d_new_restart, mut d_lcp) =
        (off_d, 0usize, false, 0usize);
    if hi < n {
        let (lcp_d, sp, sl, next) = c_parse(b, off_d);
        if lcp_d != 0 {
            s.kd.truncate(lcp_d);
            s.kd.extend_from_slice(&b[sp..sp + sl]);
            let prev: &[u8] = if ins.is_some() { bkey } else { &s.ka };
            d_lcp = lcp(prev, &s.kd);
            let stored = s.kd.len() - d_lcp;
            d_new_len = var_len(d_lcp) + var_len(stored) + stored + 9;
            d_new_restart = d_lcp == 0;
            tail_start = next;
        }
    }
    let rewrites_d = tail_start != off_d;
    // sizes and restart count
    let removed_restarts = (0..nr)
        .filter(|&g| (lo..hi).contains(&rs_idx(b, g)))
        .count();
    let nr2 = nr - removed_restarts + b_restart as usize + d_new_restart as usize;
    let seg_new = b_len + d_new_len;
    let new_dl = dl - (tail_start - off_lo) + seg_new;
    let new_hl = HDR + pl + 4 * nr2;
    if new_hl + new_dl > psz {
        return false;
    }
    // stream into tmp
    if s.tmp.len() != psz {
        s.tmp.resize(psz, 0);
    }
    let t = &mut s.tmp;
    t[..HDR + pl].copy_from_slice(&b[..HDR + pl]);
    // entries: [hl, off_lo) | B | D' | [tail_start, end)
    let mut w = new_hl;
    t[w..w + off_lo - hl].copy_from_slice(&b[hl..off_lo]);
    w += off_lo - hl;
    let b_off = w;
    if let Some((_, addr, c)) = ins {
        let stored = bkey.len() - b_lcp;
        let mut p = w;
        wvar(t, &mut p, b_lcp);
        wvar(t, &mut p, stored);
        t[p..p + stored].copy_from_slice(&bkey[b_lcp..]);
        p += stored;
        w40(t, p, enc_addr(addr));
        t[p + 5..p + 9].copy_from_slice(&c.to_le_bytes());
        w += b_len;
    }
    let d_off = w;
    if rewrites_d {
        let (_, sp, sl, _) = c_parse(b, off_d);
        let stored = s.kd.len() - d_lcp;
        let mut p = w;
        wvar(t, &mut p, d_lcp);
        wvar(t, &mut p, stored);
        t[p..p + stored].copy_from_slice(&s.kd[d_lcp..]);
        p += stored;
        t[p..p + 9].copy_from_slice(&b[sp + sl..sp + sl + 9]);
        w += d_new_len;
    }
    let end = hl + dl;
    t[w..w + end - tail_start].copy_from_slice(&b[tail_start..end]);
    // restart list: kept ones before the edit, B, D', the ones after the edit shifted
    let shift = seg_new as isize - (tail_start - off_lo) as isize;
    let rs_base = HDR + pl;
    let mut j = 0;
    let mut put = |t: &mut [u8], idx: usize, off: usize| {
        w16(t, rs_base + 4 * j, idx);
        w16(t, rs_base + 4 * j + 2, off);
        j += 1;
    };
    for g in 0..nr {
        let (idx, off) = (rs_idx(b, g), rs_off(b, g));
        if idx < lo {
            put(t, idx, off - hl + new_hl);
        }
    }
    if b_restart {
        put(t, lo, b_off);
    }
    if d_new_restart {
        put(t, lo + ins_n, d_off);
    }
    for g in 0..nr {
        let (idx, off) = (rs_idx(b, g), rs_off(b, g));
        if idx >= hi && off >= tail_start {
            put(
                t,
                idx - (hi - lo) + ins_n,
                (off as isize - hl as isize + new_hl as isize + shift) as usize,
            );
        }
    }
    debug_assert_eq!(j, nr2);
    w16(t, 8, n - (hi - lo) + ins_n);
    w16(t, 12, new_hl);
    w16(t, 14, new_dl);
    w16(t, 37, nr2);
    b.copy_from_slice(t);
    true
}
fn build_size_compact(e: &Ents, lo: usize, hi: usize, pl: usize) -> usize {
    let (mut data, mut restarts) = (0usize, 0usize);
    c_plan(e, lo, hi, pl, |_, lcp, restart, sfx| {
        data += var_len(lcp) + var_len(sfx.len() - lcp) + sfx.len() - lcp + 9;
        restarts += restart as usize;
    });
    HDR + pl + 4 * restarts + data
}

/// Write `e[lo..hi]` as a compact interior page body (prefix `pl` bytes already chosen by the caller).
fn build_compact(b: &mut [u8], e: &Ents, lo: usize, hi: usize, pl: usize) {
    b[36] = FMT_COMPACT;
    reset(b);
    if pl > 0 {
        b[HDR..HDR + pl].copy_from_slice(&e.key(lo + 1)[..pl]);
    }
    w16(b, 10, pl);
    let mut restarts = 0usize;
    c_plan(e, lo, hi, pl, |_, _, restart, _| {
        restarts += restart as usize
    });
    let (rs_base, heap_lo) = (HDR + pl, HDR + pl + 4 * restarts);
    let (mut o, mut g) = (heap_lo, 0usize);
    c_plan(e, lo, hi, pl, |j, lcp, restart, sfx| {
        if restart {
            w16(b, rs_base + 4 * g, j);
            w16(b, rs_base + 4 * g + 2, o);
            g += 1;
        }
        wvar(b, &mut o, lcp);
        wvar(b, &mut o, sfx.len() - lcp);
        b[o..o + sfx.len() - lcp].copy_from_slice(&sfx[lcp..]);
        o += sfx.len() - lcp;
        let (addr, c) = e.ref_at(lo + j);
        w40(b, o, enc_addr(addr));
        b[o + 5..o + 9].copy_from_slice(&c.to_le_bytes());
        o += 9;
    });
    w16(b, 8, hi - lo);
    w16(b, 12, heap_lo);
    w16(b, 14, o - heap_lo);
    w16(b, 37, restarts);
}

// ------------------------------------------------------------------ search

/// Leaf: `Ok(i)` = key found at slot i, `Err(i)` = insertion point.
pub fn leaf_search(b: &[u8], key: &[u8]) -> Result<usize, usize> {
    let n = nslots(b);
    let p = prefix(b);
    if !key.starts_with(p) {
        return Err(if key < p { 0 } else { n });
    }
    let k = &key[p.len()..];
    let (mut lo, mut hi) = (0, n);
    while lo < hi {
        let mid = (lo + hi) / 2;
        match leaf_ent(b, mid).0.cmp(k) {
            Ordering::Less => lo = mid + 1,
            Ordering::Greater => hi = mid,
            Ordering::Equal => return Ok(mid),
        }
    }
    Err(lo)
}

/// Interior: index of the child covering `key` (largest i with key_i <= key; 0 if none).
pub fn int_route(b: &[u8], key: &[u8]) -> usize {
    let n = nslots(b);
    if n <= 1 {
        return 0;
    }
    let p = prefix(b);
    if !key.starts_with(p) {
        return if key < p { 0 } else { n - 1 };
    }
    let k = &key[p.len()..];
    if is_compact(b) {
        return c_route(b, k).idx;
    }
    // first i in 1..n with suffix_i > k
    let (mut lo, mut hi) = (1, n);
    while lo < hi {
        let mid = (lo + hi) / 2;
        if int_ent(b, mid).0 <= k {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo - 1
}

/// [`int_route`] with what a descent takes next from the same walk.
#[derive(Clone, Copy, Debug)]
pub struct Route {
    /// The child covering the key.
    pub idx: usize,
    /// Its reference.
    pub addr: u64,
    pub crc: u32,
    /// `idx` is not the page's last entry: the fence buffer holds the full key of entry `idx + 1`, the child's upper
    /// fence. Else the buffer is unchanged (the fence comes from a page above).
    pub fenced: bool,
}

/// [`int_route`] + [`int_child`] + the child's upper fence ([`key_into`] of entry `idx + 1`) into `fence` (see
/// [`Route::fenced`]). A compact page takes them from its one routing walk: the next entry's key is the search key's
/// first `lcp` bytes + its stored suffix, the restart run is not decoded again.
pub fn int_route_fence(b: &[u8], key: &[u8], fence: &mut Vec<u8>) -> Route {
    let (n, p) = (nslots(b), prefix(b));
    if n >= 2 && is_compact(b) && key.starts_with(p) {
        let k = &key[p.len()..];
        let r = c_route(b, k);
        if let Some((lcp, sp, sl)) = r.next {
            fence.clear();
            fence.extend_from_slice(p);
            fence.extend_from_slice(&k[..lcp]);
            fence.extend_from_slice(&b[sp..sp + sl]);
        }
        return Route {
            idx: r.idx,
            addr: dec_addr(r40(b, r.refo)),
            crc: r32(b, r.refo + 5),
            fenced: r.next.is_some(),
        };
    }
    // slotted page (entries are direct), one child, or a key outside the prefix (first or last child)
    let idx = int_route(b, key);
    let (addr, crc) = int_child(b, idx);
    let fenced = idx + 1 < n;
    if fenced {
        fence.clear();
        key_into(b, idx + 1, fence);
    }
    Route {
        idx,
        addr,
        crc,
        fenced,
    }
}

/// Number of leading entries whose key is `< key` (leaf: lower bound).
pub fn leaf_lower_bound(b: &[u8], key: &[u8]) -> usize {
    match leaf_search(b, key) {
        Ok(i) | Err(i) => i,
    }
}

// ------------------------------------------------------------------ in-place edits

/// Compact the heap (drop fragmentation). `tmp` must be a page-sized scratch buffer.
pub fn compact(b: &mut [u8], tmp: &mut [u8]) {
    let psz = b.len();
    let k = kind(b);
    let (n, sb) = (nslots(b), sl_base(b));
    let mut top = psz;
    for i in 0..n {
        let o = slot(b, i);
        let sz = ent_size(b, o, k);
        top -= sz;
        tmp[top..top + sz].copy_from_slice(&b[o..o + sz]);
        w16(b, sb + 2 * i, top);
    }
    b[top..psz].copy_from_slice(&tmp[top..psz]);
    w16(b, 12, top);
    w16(b, 14, 0);
}

fn place(b: &mut [u8], tmp: &mut [u8], pos: usize, need_entry: usize) -> Option<usize> {
    let need = need_entry + 2;
    if gap(b) < need {
        if free_total(b) < need {
            return None;
        }
        compact(b, tmp);
    }
    let n = nslots(b);
    let sb = sl_base(b);
    let off = heap_lo(b) - need_entry;
    b.copy_within(sb + 2 * pos..sb + 2 * n, sb + 2 * pos + 2);
    w16(b, sb + 2 * pos, off);
    w16(b, 8, n + 1);
    w16(b, 12, off);
    Some(off)
}

/// Insert a leaf entry at slot `pos` (key must be absent). False = does not fit / key outside the page prefix.
pub fn leaf_insert(b: &mut [u8], tmp: &mut [u8], pos: usize, key: &[u8], val: &[u8]) -> bool {
    let pl = plen(b);
    if !key.starts_with(&b[HDR..HDR + pl]) {
        return false;
    }
    let sfx = &key[pl..];
    let Some(off) = place(b, tmp, pos, 4 + sfx.len() + val.len()) else {
        return false;
    };
    w16(b, off, sfx.len());
    w16(b, off + 2, val.len());
    b[off + 4..off + 4 + sfx.len()].copy_from_slice(sfx);
    b[off + 4 + sfx.len()..off + 4 + sfx.len() + val.len()].copy_from_slice(val);
    true
}

/// Insert interior entry `(key, child)` at slot `pos >= 1`. False (page untouched): does not fit / key outside the
/// page prefix, the caller rebuilds or splits the page through `Ents`.
pub fn int_insert(
    b: &mut [u8],
    tmp: &mut [u8],
    scratch: &mut Ents,
    pos: usize,
    key: &[u8],
    addr: u64,
    c: u32,
) -> bool {
    debug_assert!(pos >= 1);
    if is_compact(b) {
        return c_splice(b, scratch, pos, pos, Some((key, addr, c)));
    }
    let pl = plen(b);
    if !key.starts_with(&b[HDR..HDR + pl]) {
        return false;
    }
    let sfx = &key[pl..];
    let Some(off) = place(b, tmp, pos, 2 + sfx.len() + REF_LEN) else {
        return false;
    };
    w16(b, off, sfx.len());
    b[off + 2..off + 2 + sfx.len()].copy_from_slice(sfx);
    let o = off + 2 + sfx.len();
    b[o..o + 8].copy_from_slice(&addr.to_le_bytes());
    b[o + 8..o + 12].copy_from_slice(&c.to_le_bytes());
    true
}

/// Set `key` in a leaf without ever splitting (replaying a delta onto the page it was taken from): false = the page
/// cannot hold the result. A rebuild through `ents` handles keys outside the page prefix and fragmentation.
pub fn leaf_put_nosplit(
    b: &mut [u8],
    tmp: &mut [u8],
    ents: &mut Ents,
    key: &[u8],
    val: &[u8],
) -> bool {
    let pos = match leaf_search(b, key) {
        Ok(i) => {
            if leaf_val_len(b, i) == val.len() {
                leaf_set_same_len(b, i, val);
                return true;
            }
            remove_range(b, ents, i, i + 1);
            i
        }
        Err(i) => i,
    };
    if leaf_insert(b, tmp, pos, key, val) {
        return true;
    }
    ents.load(b);
    ents.insert(pos, key, val);
    let n = ents.len();
    if !fits(ents, 0, n, true, b.len(), FMT_SLOTTED) {
        return false;
    }
    build(b, ents, 0, n, FMT_SLOTTED)
}

/// Overwrite the value of leaf slot `i` with one of identical length.
pub fn leaf_set_same_len(b: &mut [u8], i: usize, val: &[u8]) {
    let o = slot(b, i);
    let (kl, vl) = (r16(b, o), r16(b, o + 2));
    debug_assert_eq!(vl, val.len());
    b[o + 4 + kl..o + 4 + kl + vl].copy_from_slice(val);
}

pub fn leaf_val_len(b: &[u8], i: usize) -> usize {
    r16(b, slot(b, i) + 2)
}

/// Remove slots `[lo, hi)` (either kind; for interior pages slot 0 must be handled by the caller). Compact
/// interior pages are rebuilt through `scratch`.
pub fn remove_range(b: &mut [u8], scratch: &mut Ents, lo: usize, hi: usize) {
    if lo >= hi {
        return;
    }
    if is_compact(b) {
        if lo == 0 && hi >= nslots(b) {
            reset(b); // every child gone
            return;
        }
        if lo >= 1 && c_splice(b, scratch, lo, hi, None) {
            return;
        }
        // (when slot 0 goes, the entry that moves up becomes the -inf slot: `build` ignores its key)
        scratch.load_keep(b);
        scratch.remove(lo, hi);
        let n = scratch.len();
        assert!(
            build(b, scratch, 0, n, FMT_COMPACT),
            "a page minus entries must fit"
        );
        return;
    }
    let k = kind(b);
    let (n, sb) = (nslots(b), sl_base(b));
    let mut dead = 0;
    for i in lo..hi {
        dead += ent_size(b, slot(b, i), k);
    }
    b.copy_within(sb + 2 * hi..sb + 2 * n, sb + 2 * lo);
    w16(b, 8, n - (hi - lo));
    if n == hi - lo {
        reset(b);
    } else {
        let f = frag(b) + dead;
        w16(b, 14, f);
    }
}

// ------------------------------------------------------------------ bulk build / split support

/// Contiguous scratch list of (key, value) pairs used for rebuilds and splits.
#[derive(Debug, Default)]
pub struct Ents {
    data: Vec<u8>,
    idx: Vec<(u32, u16, u32, u32)>, // key off, klen, val off, vlen
    /// `load_keep`: per entry, was it a restart in the compact source page (empty = fresh encode).
    flags: Vec<bool>,
    /// `load_keep`: prefix length of the compact source page. A keep-mode build never takes a longer prefix: every entry
    /// whose front coding shared exactly the extra bytes would turn into a restart (+4 B each) and the "page minus
    /// entries never grows" bound would break (first-child removal of a full page, adr 0021 am. 28).
    keep_pl: usize,
    /// Scratch of `c_splice` (page image under construction, two decoded key suffixes).
    tmp: Vec<u8>,
    ka: Vec<u8>,
    kd: Vec<u8>,
}

impl Ents {
    pub fn clear(&mut self) {
        self.data.clear();
        self.idx.clear();
        self.flags.clear();
    }
    /// Drop entries `[lo, hi)`.
    pub fn remove(&mut self, lo: usize, hi: usize) {
        self.idx.drain(lo..hi);
        if !self.flags.is_empty() {
            self.flags.drain(lo..hi);
        }
    }
    pub fn len(&self) -> usize {
        self.idx.len()
    }
    pub fn is_empty(&self) -> bool {
        self.idx.is_empty()
    }
    pub fn push(&mut self, key: &[u8], val: &[u8]) {
        let ko = self.data.len() as u32;
        self.data.extend_from_slice(key);
        let vo = self.data.len() as u32;
        self.data.extend_from_slice(val);
        self.idx.push((ko, key.len() as u16, vo, val.len() as u32));
        if !self.flags.is_empty() {
            self.flags.push(false);
        }
    }
    pub fn key(&self, i: usize) -> &[u8] {
        let (ko, kl, _, _) = self.idx[i];
        &self.data[ko as usize..ko as usize + kl as usize]
    }
    pub fn val(&self, i: usize) -> &[u8] {
        let (_, _, vo, vl) = self.idx[i];
        &self.data[vo as usize..vo as usize + vl as usize]
    }
    /// Insert at `pos` by appending and rotating the index (data stays append-only).
    pub fn insert(&mut self, pos: usize, key: &[u8], val: &[u8]) {
        self.push(key, val);
        let e = self.idx.pop().unwrap();
        self.idx.insert(pos, e);
        if !self.flags.is_empty() {
            self.flags.pop();
            self.flags.insert(pos, false);
        }
    }
    /// Entry footprint in a page without prefix truncation (worst case, slot included).
    fn full_size(&self, i: usize, leaf: bool) -> usize {
        let (_, kl, _, vl) = self.idx[i];
        2 + if leaf {
            4 + kl as usize + vl as usize
        } else {
            2 + kl as usize + REF_LEN
        }
    }
    /// Load all entries of a page (full keys; interior slot 0 key = empty).
    pub fn load(&mut self, b: &[u8]) {
        self.load_ex(b, false);
    }

    /// `load` for a compact interior page that is about to lose entries: remembers which entries were restarts so
    /// that `build` re-encodes the remainder without growing it (a fresh encode may place its forced restarts
    /// differently and need more bytes).
    pub fn load_keep(&mut self, b: &[u8]) {
        self.load_ex(b, true);
    }

    fn load_ex(&mut self, b: &[u8], keep: bool) {
        self.clear();
        let k = kind(b);
        let p = prefix(b);
        let mut key = Vec::new();
        self.keep_pl = plen(b);
        if is_compact(b) {
            let mut sfx: Vec<u8> = Vec::new();
            let (mut o, mut g) = (rs_off(b, 0), 0usize);
            for i in 0..nslots(b) {
                let (lcp, sp, sl, next) = c_parse(b, o);
                sfx.truncate(lcp);
                sfx.extend_from_slice(&b[sp..sp + sl]);
                key.clear();
                if i > 0 {
                    key.extend_from_slice(p);
                    key.extend_from_slice(&sfx);
                }
                let mut v = [0u8; REF_LEN];
                v[..8].copy_from_slice(&dec_addr(r40(b, sp + sl)).to_le_bytes());
                v[8..].copy_from_slice(&r32(b, sp + sl + 5).to_le_bytes());
                self.push(&key, &v);
                if keep {
                    let restart = g < n_restarts(b) && rs_idx(b, g) == i;
                    g += restart as usize;
                    self.flags.resize(i, false);
                    self.flags.push(restart);
                }
                o = next;
            }
            return;
        }
        for i in 0..nslots(b) {
            key.clear();
            if k == LEAF {
                let (s, v) = leaf_ent(b, i);
                key.extend_from_slice(p);
                key.extend_from_slice(s);
                self.push(&key, v);
            } else {
                let (s, a, c) = int_ent(b, i);
                if i > 0 {
                    key.extend_from_slice(p);
                    key.extend_from_slice(s);
                }
                let mut v = [0u8; REF_LEN];
                v[..8].copy_from_slice(&a.to_le_bytes());
                v[8..].copy_from_slice(&c.to_le_bytes());
                self.push(&key, &v);
            }
        }
    }
    pub fn ref_at(&self, i: usize) -> (u64, u32) {
        let v = self.val(i);
        (
            u64::from_le_bytes(v[..8].try_into().unwrap()),
            u32::from_le_bytes(v[8..12].try_into().unwrap()),
        )
    }
    /// Bytes each entry takes in a compact interior page built from the whole list (entry + restart slot).
    fn compact_sizes(&self) -> Vec<usize> {
        let n = self.len();
        let mut pl = 0;
        if n >= 3 {
            pl = range_pl(self, 1, n);
        }
        let mut sizes = Vec::with_capacity(n);
        c_plan(self, 0, n, pl, |_, lcp, restart, sfx| {
            sizes.push(
                var_len(lcp) + var_len(sfx.len() - lcp) + sfx.len() - lcp
                    + 9
                    + 4 * restart as usize,
            );
        });
        sizes
    }
    /// Split point so that the left side holds about half the bytes; both sides >= 1 entry and both fit a page of
    /// `psz`. The half-bytes point is taken when it fits (always, for small entries); with entries up to
    /// `psz / 2 - 256` it may not, then the fitting point nearest to it wins. One always exists when the list is
    /// one page plus one entry.
    pub fn split_point(&self, leaf: bool, psz: usize, fmt: u8) -> usize {
        self.try_split_point(leaf, psz, fmt).unwrap_or_else(|| {
            let sizes: Vec<usize> = (0..self.len()).map(|i| self.full_size(i, leaf)).collect();
            panic!("no fitting split (leaf {leaf}, psz {psz}): entry sizes {sizes:?}")
        })
    }

    /// `split_point`, None when no 2-way split fits: a FRESH compact encode (forced restarts) can need more bytes
    /// than the page held in place; `load_keep` entries always split.
    pub fn try_split_point(&self, leaf: bool, psz: usize, fmt: u8) -> Option<usize> {
        let n = self.len();
        let sizes: Vec<usize> = if !leaf && fmt == FMT_COMPACT {
            self.compact_sizes()
        } else {
            (0..n).map(|i| self.full_size(i, leaf)).collect()
        };
        let total: usize = sizes.iter().sum();
        let mut acc = 0;
        let mut m = n - 1;
        for (i, s) in sizes.iter().enumerate() {
            acc += s;
            if acc * 2 >= total {
                // keep at least one entry on each side
                m = (i + 1).clamp(1, n - 1);
                break;
            }
        }
        if fits(self, 0, m, leaf, psz, fmt) && fits(self, m, n, leaf, psz, fmt) {
            return Some(m);
        }
        (1..n)
            .filter(|&k| fits(self, 0, k, leaf, psz, fmt) && fits(self, k, n, leaf, psz, fmt))
            .min_by_key(|&k| k.abs_diff(m))
    }
}

/// Leaf `b`'s entries and the strictly ascending entries `new` merged into `out` in key order (a key in both: the new
/// entry); a new entry with an empty value is a removal: its key is left out. `put(j, old)` sees every new entry `j` in
/// order with the value it replaces or removes (`None`: a key the leaf does not hold).
pub fn leaf_merge(b: &[u8], new: &Ents, out: &mut Ents, mut put: impl FnMut(usize, Option<&[u8]>)) {
    debug_assert_eq!(kind(b), LEAF);
    out.clear();
    let p = prefix(b);
    let n = nslots(b);
    let mut key = Vec::with_capacity(p.len() + 64);
    let (mut i, mut j) = (0usize, 0usize);
    while i < n || j < new.len() {
        let (s, v) = if i < n {
            leaf_ent(b, i)
        } else {
            (&[][..], &[][..])
        };
        if i < n {
            key.clear();
            key.extend_from_slice(p);
            key.extend_from_slice(s);
        }
        let c = match (i < n, j < new.len()) {
            (true, true) => key.as_slice().cmp(new.key(j)),
            (true, false) => std::cmp::Ordering::Less,
            _ => std::cmp::Ordering::Greater,
        };
        match c {
            std::cmp::Ordering::Less => {
                out.push(&key, v);
                i += 1;
            }
            std::cmp::Ordering::Equal => {
                put(j, Some(v));
                if !new.val(j).is_empty() {
                    out.push(new.key(j), new.val(j));
                }
                i += 1;
                j += 1;
            }
            std::cmp::Ordering::Greater => {
                put(j, None);
                if !new.val(j).is_empty() {
                    out.push(new.key(j), new.val(j));
                }
                j += 1;
            }
        }
    }
}

/// Bytes of leaf entry `i` without prefix truncation (slot, header, key, value).
fn leaf_esz(e: &Ents, i: usize) -> usize {
    let (_, kl, _, vl) = e.idx[i];
    6 + kl as usize + vl as usize
}

/// Cut `e` (sorted leaf entries) into the fewest leaf pages of `psz`: `cuts` = start of every page after the first.
/// `full_left`: each page as full as it gets, left to right (an append at the right end of the tree: the next appends
/// land right of them); else the same number of pages with about equal bytes (a generalized balanced split; the greedy
/// cut when a balanced one does not fit). Every entry fits a page alone (`max_entry_for`).
pub fn leaf_cuts(e: &Ents, psz: usize, full_left: bool, cuts: &mut Vec<usize>) {
    cuts.clear();
    let n = e.len();
    // greedy: the longest prefix that fits, from each start (the leaf size grows with every entry added)
    let (mut lo, mut sum) = (0usize, 0usize);
    let mut total = 0usize;
    for hi in 0..n {
        let es = leaf_esz(e, hi);
        total += es;
        let cnt = hi + 1 - lo;
        let pl = if cnt >= 2 {
            lcp(e.key(lo), e.key(hi))
        } else {
            0
        };
        if HDR + pl + sum + es - cnt * pl > psz {
            debug_assert!(hi > lo, "an entry fits a page alone");
            cuts.push(hi);
            lo = hi;
            sum = 0;
        }
        sum += es;
    }
    if full_left || cuts.is_empty() {
        return;
    }
    let pages = cuts.len() + 1;
    let mut bal = Vec::with_capacity(pages - 1);
    let (mut acc, mut k) = (0usize, 1usize);
    for i in 0..n {
        if k < pages && acc * pages >= k * total && i > bal.last().copied().unwrap_or(0) {
            bal.push(i);
            k += 1;
        }
        acc += leaf_esz(e, i);
    }
    if bal.len() + 1 != pages {
        return;
    }
    let mut lo = 0;
    for &c in bal.iter().chain(std::iter::once(&n)) {
        if !fits(e, lo, c, true, psz, FMT_SLOTTED) {
            return;
        }
        lo = c;
    }
    *cuts = bal;
}

/// Length of the common prefix of `a` and `b`, 8 bytes per step.
pub(crate) fn lcp(a: &[u8], b: &[u8]) -> usize {
    let n = a.len().min(b.len());
    let mut i = 0;
    while i + 8 <= n {
        let x = u64::from_le_bytes(a[i..i + 8].try_into().unwrap())
            ^ u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        if x != 0 {
            return i + (x.trailing_zeros() / 8) as usize;
        }
        i += 8;
    }
    i + a[i..n]
        .iter()
        .zip(&b[i..n])
        .take_while(|(x, y)| x == y)
        .count()
}

/// Common prefix length of the keys `[lo, hi)` (at least one). `Ents` keys are byte-wise sorted, so it is the common
/// prefix of the first and the last: sizing a page costs O(entries), not O(key bytes).
fn range_pl(e: &Ents, lo: usize, hi: usize) -> usize {
    debug_assert!(
        (lo + 1..hi).all(|i| e.key(i - 1) <= e.key(i)),
        "Ents keys not sorted in {lo}..{hi}"
    );
    lcp(e.key(lo), e.key(hi - 1))
}

/// Shortest separator `s` with `left < s <= right` (requires `left < right`).
pub fn short_sep(left: &[u8], right: &[u8], out: &mut Vec<u8>) {
    let l = lcp(left, right);
    out.clear();
    out.extend_from_slice(&right[..(l + 1).min(right.len())]);
}

/// Size a page built from `ents[lo..hi]` would take, and its prefix length. Interior: key of `lo` ignored.
fn build_size(e: &Ents, lo: usize, hi: usize, leaf: bool, fmt: u8) -> (usize, usize) {
    let n = hi - lo;
    let kstart = if leaf { lo } else { lo + 1 };
    let mut pl = 0;
    if hi - kstart >= 2 {
        pl = range_pl(e, kstart, hi);
    }
    if !leaf && fmt == FMT_COMPACT && !e.flags.is_empty() {
        pl = pl.min(e.keep_pl);
    }
    if !leaf && fmt == FMT_COMPACT {
        return (build_size_compact(e, lo, hi, pl), pl);
    }
    let mut sz = HDR + pl + 2 * n;
    for i in lo..hi {
        let (_, kl, _, vl) = e.idx[i];
        let kl = if !leaf && i == lo {
            0
        } else {
            kl as usize - pl
        };
        sz += if leaf {
            4 + kl + vl as usize
        } else {
            2 + kl + REF_LEN
        };
    }
    (sz, pl)
}

/// Build page `b` (already `init`ed or reused) from `ents[lo..hi]`; an interior page takes format `fmt`
/// (leaves ignore it). False (page untouched) if it does not fit.
pub fn build(b: &mut [u8], e: &Ents, lo: usize, hi: usize, fmt: u8) -> bool {
    let psz = b.len();
    let leaf = kind(b) == LEAF;
    let (sz, pl) = build_size(e, lo, hi, leaf, fmt);
    if sz > psz {
        return false;
    }
    if !leaf && fmt == FMT_COMPACT {
        build_compact(b, e, lo, hi, pl);
        return true;
    }
    b[36] = FMT_SLOTTED;
    reset(b);
    let kstart = if leaf { lo } else { lo + 1 };
    if pl > 0 {
        b[HDR..HDR + pl].copy_from_slice(&e.key(kstart)[..pl]);
    }
    w16(b, 10, pl);
    let sb = HDR + pl;
    let mut top = psz;
    for (s, i) in (lo..hi).enumerate() {
        let (key, val) = (e.key(i), e.val(i));
        let sfx: &[u8] = if !leaf && i == lo { &[] } else { &key[pl..] };
        let esz = if leaf {
            4 + sfx.len() + val.len()
        } else {
            2 + sfx.len() + REF_LEN
        };
        top -= esz;
        w16(b, top, sfx.len());
        if leaf {
            w16(b, top + 2, val.len());
            b[top + 4..top + 4 + sfx.len()].copy_from_slice(sfx);
            b[top + 4 + sfx.len()..top + esz].copy_from_slice(val);
        } else {
            b[top + 2..top + 2 + sfx.len()].copy_from_slice(sfx);
            b[top + 2 + sfx.len()..top + esz].copy_from_slice(val);
        }
        w16(b, sb + 2 * s, top);
    }
    w16(b, 8, hi - lo);
    w16(b, 12, top);
    w16(b, 14, 0);
    true
}

/// Would `ents[lo..hi]` fit in one page of `psz` bytes?
pub fn fits(e: &Ents, lo: usize, hi: usize, leaf: bool, psz: usize, fmt: u8) -> bool {
    build_size(e, lo, hi, leaf, fmt).0 <= psz
}

#[cfg(test)]
mod tests {
    use super::*;

    fn newp(kind: u8, psz: usize) -> Vec<u8> {
        let mut b = vec![0; psz];
        init(&mut b, kind, if kind == LEAF { 0 } else { 1 }, 77, 0);
        b
    }

    /// `leaf_cuts`: the fewest pages (no page of a cut fits one more entry when packed left), every page fits, the
    /// balanced cut has as many pages; `leaf_merge` puts every new entry once, in order, with the value it replaces, and
    /// leaves out the keys of removals (an empty new value) whether the leaf held them or not.
    #[test]
    fn leaf_cuts_and_merge() {
        let mut rng = crate::rng::Rng::new(11);
        for psz in [4096usize, 8192] {
            for round in 0..200 {
                let mut e = Ents::default();
                let n = rng.range(1, 400) as usize;
                let big = round % 4 == 0;
                for i in 0..n {
                    let k = format!("pfx/{:06}/{}", i * 3, "x".repeat(rng.below(40) as usize));
                    let vl = if big {
                        rng.range(100, (psz / 2 - 400) as u64)
                    } else {
                        rng.below(200)
                    };
                    e.push(k.as_bytes(), &vec![b'v'; vl as usize]);
                }
                let mut greedy = Vec::new();
                leaf_cuts(&e, psz, true, &mut greedy);
                let mut bal = Vec::new();
                leaf_cuts(&e, psz, false, &mut bal);
                assert_eq!(greedy.len(), bal.len(), "same page count");
                for cuts in [&greedy, &bal] {
                    let mut lo = 0;
                    for &c in cuts.iter().chain(std::iter::once(&n)) {
                        assert!(
                            c > lo && fits(&e, lo, c, true, psz, FMT_SLOTTED),
                            "page fits"
                        );
                        lo = c;
                    }
                }
                let mut lo = 0;
                for &c in &greedy {
                    assert!(
                        !fits(&e, lo, c + 1, true, psz, FMT_SLOTTED),
                        "greedy page is full"
                    );
                    lo = c;
                }
                // merge every other entry (as a leaf) with new entries: half overwrites, half new keys, every fifth key a
                // removal (of a held or an absent key)
                let mut leaf = Ents::default();
                let mut new = Ents::default();
                for i in 0..n.min(20) {
                    if i % 2 == 0 {
                        leaf.push(e.key(i), b"old");
                    }
                    if i % 3 != 1 {
                        new.push(e.key(i), if i % 5 == 0 { &b""[..] } else { b"new" });
                    }
                }
                let mut b = newp(LEAF, psz);
                assert!(build(&mut b, &leaf, 0, leaf.len(), FMT_SLOTTED));
                let mut out = Ents::default();
                let mut seen = Vec::new();
                leaf_merge(&b, &new, &mut out, |j, o| {
                    seen.push((j, o.map(<[u8]>::to_vec)))
                });
                assert_eq!(seen.len(), new.len());
                for (x, (j, o)) in seen.iter().enumerate() {
                    assert_eq!(x, *j);
                    let had = (0..leaf.len()).any(|i| leaf.key(i) == new.key(*j));
                    assert_eq!(o.as_deref(), had.then_some(&b"old"[..]));
                }
                let keys: Vec<&[u8]> = (0..out.len()).map(|i| out.key(i)).collect();
                assert!(keys.windows(2).all(|w| w[0] < w[1]), "merged keys ascend");
                assert!((0..out.len()).all(|i| {
                    let isnew = (0..new.len()).any(|j| new.key(j) == out.key(i));
                    out.val(i) == if isnew { &b"new"[..] } else { &b"old"[..] }
                }));
                let want = (0..leaf.len())
                    .map(|i| leaf.key(i))
                    .chain((0..new.len()).map(|j| new.key(j)))
                    .filter(|k| !(0..new.len()).any(|j| new.key(j) == *k && new.val(j).is_empty()))
                    .collect::<std::collections::BTreeSet<_>>();
                assert_eq!(keys.len(), want.len(), "removed keys left out");
            }
        }
    }

    #[test]
    fn leaf_insert_search_remove_compact() {
        let mut b = newp(LEAF, 4096);
        let mut tmp = vec![0; 4096];
        let mut model = std::collections::BTreeMap::new();
        let mut rng = crate::rng::Rng::new(5);
        for _ in 0..5000 {
            let k = format!("key/{:03}", rng.below(60)).into_bytes();
            let v = vec![b'v'; rng.below(40) as usize];
            match leaf_search(&b, &k) {
                Ok(i) => {
                    if rng.pct(50) {
                        remove_range(&mut b, &mut Ents::default(), i, i + 1);
                        model.remove(&k);
                    }
                }
                Err(i) => {
                    if leaf_insert(&mut b, &mut tmp, i, &k, &v) {
                        model.insert(k, v);
                    } else {
                        // full or prefix mismatch: rebuild path
                        let mut e = Ents::default();
                        e.load(&b);
                        e.insert(i, &k, &v);
                        if build(&mut b, &e, 0, e.len(), FMT_SLOTTED) {
                            model.insert(k, v);
                        }
                    }
                }
            }
            validate_shape(&b);
        }
        assert_eq!(nslots(&b), model.len());
        for (i, (k, v)) in model.iter().enumerate() {
            let (s, val) = leaf_ent(&b, i);
            let mut full = prefix(&b).to_vec();
            full.extend_from_slice(s);
            assert_eq!((&full, val), (k, &v[..]));
            assert_eq!(leaf_search(&b, k), Ok(i));
        }
    }

    fn validate_shape(b: &[u8]) {
        let mut c = b.to_vec();
        seal(&mut c, 77, 1);
        check_image(&c, b.len(), 77, false).unwrap();
    }

    #[test]
    fn prefix_truncation_and_interior_routing() {
        let mut e = Ents::default();
        let mut v = [0u8; REF_LEN];
        e.push(b"", &v);
        for i in 1..20u64 {
            v[..8].copy_from_slice(&(100 + i).to_le_bytes());
            e.push(format!("pg/00/obj{i:03}").as_bytes(), &v);
        }
        for fmt in [FMT_SLOTTED, FMT_COMPACT] {
            let mut b = newp(INT, 4096);
            assert!(build(&mut b, &e, 0, e.len(), fmt));
            assert!(prefix(&b).starts_with(b"pg/00/obj"), "{:?}", prefix(&b));
            assert_eq!(int_route(&b, b"a"), 0);
            assert_eq!(int_route(&b, b"zzz"), 19);
            assert_eq!(int_route(&b, b"pg/00/obj005"), 5);
            assert_eq!(int_route(&b, b"pg/00/obj005\0"), 5);
            assert_eq!(int_route(&b, b"pg/00/obj0044"), 4);
            let mut k = Vec::new();
            key_into(&b, 7, &mut k);
            assert_eq!(k, b"pg/00/obj007");
            assert_eq!(int_child(&b, 3).0, 103);
            validate_shape(&b);
        }
    }

    // ---------------------------------------------------------------- compact interior pages

    /// Random sorted interior key list with shared prefixes of several depths (`bigkeys`: some keys near the
    /// limit), the refs and a model for the page contents.
    fn gen_int(
        rng: &mut crate::rng::Rng,
        n: usize,
        bigkeys: bool,
    ) -> (Ents, Vec<Vec<u8>>, Vec<(u64, u32)>) {
        let mut keys: Vec<Vec<u8>> = (0..n)
            .map(|_| match rng.below(10) {
                0 if bigkeys => {
                    let mut k = b"tag/".to_vec();
                    k.extend((0..rng.range(300, 1500)).map(|_| b'a' + rng.below(3) as u8));
                    k
                }
                1..=5 => format!(
                    "dir{:03}/sub{:03}/file{:06}",
                    rng.below(40),
                    rng.below(30),
                    rng.below(1000)
                )
                .into_bytes(),
                6..=8 => format!("dir{:03}/x{}", rng.below(40), rng.below(100000)).into_bytes(),
                _ => (0..rng.range(1, 12))
                    .map(|_| rng.below(256) as u8)
                    .collect(),
            })
            .collect();
        keys.sort();
        keys.dedup();
        keys.insert(0, Vec::new()); // slot 0
        let refs: Vec<(u64, u32)> = (0..keys.len())
            .map(|i| {
                let a = if rng.pct(10) {
                    VIRT | (1 + i as u64)
                } else {
                    1000 + rng.below(1 << 38)
                };
                (a, rng.next_u64() as u32)
            })
            .collect();
        let mut e = Ents::default();
        for (k, (a, c)) in keys.iter().zip(&refs) {
            let mut v = [0u8; REF_LEN];
            v[..8].copy_from_slice(&a.to_le_bytes());
            v[8..].copy_from_slice(&c.to_le_bytes());
            e.push(k, &v);
        }
        (e, keys, refs)
    }

    /// Reference routing: last entry with key <= probe (slot 0 = -inf).
    fn model_route(keys: &[Vec<u8>], probe: &[u8]) -> usize {
        keys.iter()
            .skip(1)
            .take_while(|k| k.as_slice() <= probe)
            .count()
    }

    fn check_page(b: &[u8], keys: &[Vec<u8>], refs: &[(u64, u32)], rng: &mut crate::rng::Rng) {
        validate_shape(b);
        assert_eq!(nslots(b), keys.len());
        let mut k = Vec::new();
        let mut cmp = Vec::new();
        for i in 0..keys.len() {
            assert_eq!(int_child(b, i), refs[i], "child {i}");
            if i > 0 {
                k.clear();
                key_into(b, i, &mut k);
                assert_eq!(k, keys[i], "key {i}");
            }
            assert!(i == 0 || int_key_eq(b, i, &keys[i], &mut cmp));
        }
        // routing: every key, its neighbours (append 0 / drop the last byte / bump the last byte), random probes
        let mut probes: Vec<Vec<u8>> = vec![Vec::new(), vec![0xff; 8]];
        for key in keys.iter().skip(1) {
            probes.push(key.clone());
            let mut p = key.clone();
            p.push(0);
            probes.push(p);
            if let Some((_, rest)) = key.split_last() {
                probes.push(rest.to_vec());
            }
            let mut p = key.clone();
            if let Some(l) = p.last_mut() {
                *l = l.wrapping_add(1);
            }
            probes.push(p);
        }
        for _ in 0..200 {
            probes.push(
                (0..rng.range(0, 20))
                    .map(|_| rng.below(256) as u8)
                    .collect(),
            );
        }
        // the routing walk's child reference and fence equal the entry accessors'; no fence: the buffer is untouched
        let mut f = Vec::new();
        for p in probes {
            let want = model_route(keys, &p);
            assert_eq!(int_route(b, &p), want, "probe {p:?}");
            f.clear();
            f.extend_from_slice(b"untouched");
            let r = int_route_fence(b, &p, &mut f);
            let fenced = want + 1 < keys.len();
            assert_eq!(
                (r.idx, (r.addr, r.crc), r.fenced),
                (want, refs[want], fenced),
                "probe {p:?}"
            );
            let fence: &[u8] = if fenced {
                &keys[want + 1]
            } else {
                b"untouched"
            };
            assert_eq!(f, fence, "fence of probe {p:?}");
        }
    }

    #[test]
    fn compact_interior_pages_match_the_model() {
        let mut rng = crate::rng::Rng::new(33);
        let mut smaller = 0;
        for case in 0..400 {
            let n = rng.range(1, 60) as usize * if case % 7 == 0 { 8 } else { 1 };
            let (e, keys, refs) = gen_int(&mut rng, n, case % 3 == 0);
            for psz in [8192usize, 16384, 32768] {
                if !fits(&e, 0, e.len(), false, psz, FMT_COMPACT) {
                    continue;
                }
                let mut b = newp(INT, psz);
                assert!(build(&mut b, &e, 0, e.len(), FMT_COMPACT));
                assert!(is_compact(&b) && fmt(&b) == FMT_COMPACT);
                check_page(&b, &keys, &refs, &mut rng);
                // reload -> identical entries, rebuild -> identical page
                let mut e2 = Ents::default();
                e2.load(&b);
                assert_eq!(e2.len(), e.len());
                for i in 0..e.len() {
                    assert_eq!((e2.key(i), e2.ref_at(i)), (e.key(i), e.ref_at(i)));
                }
                let mut b2 = newp(INT, psz);
                assert!(build(&mut b2, &e2, 0, e2.len(), FMT_COMPACT));
                assert_eq!(&b2[HDR..], &b[HDR..], "rebuild is deterministic");
                // the slotted page of the same content is never smaller
                if fits(&e, 0, e.len(), false, psz, FMT_SLOTTED) {
                    let mut s = newp(INT, psz);
                    assert!(build(&mut s, &e, 0, e.len(), FMT_SLOTTED));
                    assert!(
                        free_total(&b) + 8 >= free_total(&s),
                        "compact {} slotted {}",
                        free_total(&b),
                        free_total(&s)
                    );
                    smaller += (free_total(&b) > free_total(&s)) as u32;
                    check_page(&s, &keys, &refs, &mut rng);
                }
                // in-place reference patches (real and virtual addresses)
                let mut c = b.clone();
                let mut refs2 = refs.clone();
                for _ in 0..30 {
                    let i = rng.below(keys.len() as u64) as usize;
                    let r = (
                        if rng.pct(30) {
                            VIRT | rng.below(1 << 30)
                        } else {
                            rng.below(1 << 38)
                        },
                        rng.next_u64() as u32,
                    );
                    int_set_ref(&mut c, i, r.0, r.1);
                    refs2[i] = r;
                }
                check_page(&c, &keys, &refs2, &mut rng);
            }
        }
        assert!(smaller > 100, "compact pages were not smaller: {smaller}");
    }

    /// `int_key_eq` runs per interior page on every range scan (`Tree::child_range`): comparing a compact entry's key
    /// must not allocate it (front coding allows the compare in place, as `c_route` does).
    #[test]
    fn int_key_eq_does_not_allocate() {
        let mut rng = crate::rng::Rng::new(51);
        let (e, keys, _) = gen_int(&mut rng, 40, true);
        let mut b = newp(INT, 16384);
        assert!(build(&mut b, &e, 0, e.len(), FMT_COMPACT));
        assert!(is_compact(&b));
        let mut scratch = Vec::new();
        for (i, k) in keys.iter().enumerate().skip(1) {
            assert!(int_key_eq(&b, i, k, &mut scratch));
        }
        // the compare buffer is warm: a scan descent allocates nothing
        for (i, k) in keys.iter().enumerate().skip(1) {
            let n = crate::test_alloc::allocations(|| assert!(int_key_eq(&b, i, k, &mut scratch)));
            assert_eq!(n, 0, "entry {i} materialises its key");
        }
    }

    /// Removing children never grows a compact page (the prune path cannot fail), also the first child, and the
    /// remaining content matches the model; pages stay valid for any sequence of removals.
    #[test]
    fn compact_interior_removal_never_grows_the_page() {
        let mut rng = crate::rng::Rng::new(44);
        let mut scratch = Ents::default();
        for case in 0..300 {
            let n = rng.range(3, 80) as usize;
            let (e, mut keys, mut refs) = gen_int(&mut rng, n, case % 4 == 0);
            let psz = 16384;
            if !fits(&e, 0, e.len(), false, psz, FMT_COMPACT) {
                continue;
            }
            let mut b = newp(INT, psz);
            assert!(build(&mut b, &e, 0, e.len(), FMT_COMPACT));
            while keys.len() > 2 && rng.pct(95) {
                let before = free_total(&b);
                if rng.pct(15) {
                    // first child goes: the next separator becomes the implicit lower fence
                    let n = nslots(&b);
                    scratch.load_keep(&b);
                    assert!(
                        build(&mut b, &scratch, 1, n, FMT_COMPACT),
                        "first-child removal must fit"
                    );
                    keys.remove(0);
                    refs.remove(0);
                    keys[0] = Vec::new();
                } else {
                    let lo = rng.range(1, keys.len() as u64 - 1) as usize;
                    let hi = (lo + rng.range(1, 4) as usize).min(keys.len());
                    remove_range(&mut b, &mut scratch, lo, hi);
                    keys.drain(lo..hi);
                    refs.drain(lo..hi);
                }
                assert!(
                    free_total(&b) >= before,
                    "page grew by a removal: {before} -> {}",
                    free_total(&b)
                );
                check_page(&b, &keys, &refs, &mut rng);
            }
        }
    }

    /// Regression (adr 0021 am. 28): removing the first child of a full compact page whose slot-1 key limits the page
    /// prefix. Keys after it share exactly one byte beyond the prefix, so a rebuild with the longer prefix of the rest
    /// made every one of them a restart (+4 B each) and overflowed (`Tree::int_remove_child` asserted). Both the in-place
    /// path the tree takes (child 1 into slot 0, slot 1 removed by `c_splice`) and a keep-mode rebuild must fit.
    #[test]
    fn first_child_removal_of_a_full_page_never_grows() {
        let mut rng = crate::rng::Rng::new(28);
        let mut scratch = Ents::default();
        for psz in [4096usize, 8192, 16384] {
            // slot 0, "p0" (limits the prefix to "p"), then "p1" + a distinct rising byte + filler: consecutive keys share
            // exactly the "1" beyond the prefix
            let mut keys: Vec<Vec<u8>> = vec![Vec::new(), b"p0".to_vec()];
            let mut e = Ents::default();
            let mut b = newp(INT, psz);
            let mut i = 0u64;
            loop {
                assert!(i < 200, "psz {psz}: filler too short to fill the page");
                let mut k = b"p1".to_vec();
                k.push(32 + i as u8);
                k.extend(std::iter::repeat_n(b'z', psz / 100));
                let mut ks = keys.clone();
                ks.push(k);
                e.clear();
                for k in &ks {
                    e.push(k, &[0u8; REF_LEN]);
                }
                if !fits(&e, 0, ks.len(), false, psz, FMT_COMPACT) {
                    break;
                }
                keys = ks;
                i += 1;
            }
            e.clear();
            let refs: Vec<(u64, u32)> = (0..keys.len())
                .map(|_| (1000 + rng.below(1 << 30), rng.next_u64() as u32))
                .collect();
            for (k, (a, c)) in keys.iter().zip(&refs) {
                let mut v = [0u8; REF_LEN];
                v[..8].copy_from_slice(&a.to_le_bytes());
                v[8..].copy_from_slice(&c.to_le_bytes());
                e.push(k, &v);
            }
            assert!(build(&mut b, &e, 0, keys.len(), FMT_COMPACT));
            assert!(
                free_total(&b) < 20 + psz / 100,
                "page not full: {}",
                free_total(&b)
            );
            // keep-mode rebuild without slot 0 (the old tree path): never a longer prefix, so it fits
            let n = nslots(&b);
            let mut r = b.clone();
            scratch.load_keep(&r);
            assert!(
                build(&mut r, &scratch, 1, n, FMT_COMPACT),
                "psz {psz}: keep-mode rebuild without slot 0 must fit"
            );
            // in place: child 1 takes the -inf slot, slot 1 goes
            let before = free_total(&b);
            let (a1, c1) = int_child(&b, 1);
            int_set_ref(&mut b, 0, a1, c1);
            remove_range(&mut b, &mut scratch, 1, 2);
            assert!(
                free_total(&b) >= before,
                "psz {psz}: in-place removal grew the page"
            );
            let mut mk = keys.clone();
            let mut mr = refs.clone();
            mk.remove(1);
            mr.remove(0);
            check_page(&b, &mk, &mr, &mut rng);
        }
    }

    /// In-place inserts and removals (`c_splice`) keep a compact page equal to the model through a long random
    /// history, also when pages are nearly full, when inserted keys leave the page prefix (rebuild) and when
    /// restart runs get long.
    #[test]
    fn compact_interior_in_place_edits_match_the_model() {
        let mut rng = crate::rng::Rng::new(66);
        let mut scratch = Ents::default();
        let mut tmp = vec![0u8; 4096];
        let (mut inplace, mut rebuilt, mut removed, mut full) = (0, 0, 0, 0);
        for case in 0..30 {
            let psz = 4096;
            let mut b = newp(INT, psz);
            let shape = case % 3;
            let mkkey = |rng: &mut crate::rng::Rng| -> Vec<u8> {
                if rng.pct(2) {
                    return format!("0outlier{}", rng.below(1000)).into_bytes();
                }
                match shape {
                    0 => format!(
                        "dir{:03}/sub{:03}/f{:05}",
                        rng.below(8),
                        rng.below(40),
                        rng.below(100_000)
                    )
                    .into_bytes(),
                    1 => format!("pfx/{:010}", rng.below(1 << 30)).into_bytes(),
                    _ => (0..rng.range(1, 30))
                        .map(|_| b'a' + rng.below(4) as u8)
                        .collect(),
                }
            };
            let mut keys: Vec<Vec<u8>> = vec![Vec::new()];
            let mut refs: Vec<(u64, u32)> = vec![(500, 1)];
            let mut e = Ents::default();
            e.push(b"", &{
                let mut v = [0u8; REF_LEN];
                v[..8].copy_from_slice(&500u64.to_le_bytes());
                v[8..].copy_from_slice(&1u32.to_le_bytes());
                v
            });
            // start from a few entries so the page has a prefix (later outliers force the rebuild path)
            let mut init: Vec<Vec<u8>> = (0..6).map(|_| mkkey(&mut rng)).collect();
            init.sort();
            init.dedup();
            for k in &init {
                keys.push(k.clone());
                refs.push((600 + keys.len() as u64, 2));
                let mut v = [0u8; REF_LEN];
                v[..8].copy_from_slice(&refs.last().unwrap().0.to_le_bytes());
                v[8..].copy_from_slice(&2u32.to_le_bytes());
                e.push(k, &v);
            }
            assert!(build(&mut b, &e, 0, e.len(), FMT_COMPACT));
            for step in 0..1500u64 {
                if rng.pct(88) || keys.len() < 3 {
                    let k = mkkey(&mut rng);
                    let pos = match keys[1..].binary_search(&k) {
                        Ok(_) => continue,
                        Err(p) => p + 1,
                    };
                    let r = (
                        if rng.pct(10) {
                            VIRT | step
                        } else {
                            1000 + step
                        },
                        step as u32,
                    );
                    if int_insert(&mut b, &mut tmp, &mut scratch, pos, &k, r.0, r.1) {
                        inplace += 1;
                    } else {
                        // rebuild path of the tree: reload, insert, rebuild if it fits (else the tree would split)
                        let mut e = Ents::default();
                        e.load(&b);
                        let mut v = [0u8; REF_LEN];
                        v[..8].copy_from_slice(&r.0.to_le_bytes());
                        v[8..].copy_from_slice(&r.1.to_le_bytes());
                        e.insert(pos, &k, &v);
                        if !fits(&e, 0, e.len(), false, psz, FMT_COMPACT) {
                            full += 1;
                            continue;
                        }
                        assert!(build(&mut b, &e, 0, e.len(), FMT_COMPACT));
                        rebuilt += 1;
                    }
                    keys.insert(pos, k);
                    refs.insert(pos, r);
                } else {
                    let lo = rng.range(1, keys.len() as u64 - 1) as usize;
                    let hi = (lo + rng.range(1, 6) as usize).min(keys.len());
                    let before = free_total(&b);
                    remove_range(&mut b, &mut scratch, lo, hi);
                    assert!(free_total(&b) >= before, "removal grew the page");
                    keys.drain(lo..hi);
                    refs.drain(lo..hi);
                    removed += 1;
                }
                if step % 7 == 0 || keys.len() < 40 {
                    check_page(&b, &keys, &refs, &mut rng);
                }
            }
            check_page(&b, &keys, &refs, &mut rng);
        }
        eprintln!(
            "compact edits: {inplace} in place, {rebuilt} rebuilt, {full} full, {removed} removals"
        );
        assert!(inplace > 1000 && rebuilt > 10 && full > 10 && removed > 100);
    }

    /// Hostile compact pages: a valid crc is no proof of a sane page.
    #[test]
    fn mutated_compact_pages_never_panic() {
        let mut rng = crate::rng::Rng::new(55);
        for case in 0..30 {
            let (e, keys, _) = gen_int(&mut rng, 20 + case * 3, case % 2 == 0);
            let mut b = newp(INT, 8192);
            if !build(&mut b, &e, 0, e.len(), FMT_COMPACT) {
                continue;
            }
            for _ in 0..4000 {
                let mut c = b.clone();
                for _ in 0..rng.range(1, 4) {
                    let i = if rng.pct(40) {
                        rng.below(HDR as u64 + 80) as usize
                    } else {
                        rng.below(c.len() as u64) as usize
                    };
                    c[i] = rng.next_u64() as u8;
                }
                seal(&mut c, 77, 1);
                if validate(&c, 8192, 77).is_ok() {
                    let mut k = Vec::new();
                    for i in 0..nslots(&c) {
                        k.clear();
                        key_into(&c, i, &mut k);
                        int_child(&c, i);
                    }
                    let _ = int_route(&c, keys.get(3).map_or(b"x".as_slice(), |k| k.as_slice()));
                    let mut e2 = Ents::default();
                    e2.load(&c);
                }
            }
        }
    }

    /// Bit-rot with a valid crc (or a bad writer): validate must reject or the page must be fully walkable.
    #[test]
    fn mutated_pages_never_panic() {
        let mut rng = crate::rng::Rng::new(9);
        for kind in [LEAF, INT] {
            let mut b = newp(kind, 4096);
            let mut e = Ents::default();
            let v = [7u8; REF_LEN];
            for i in 0..40u32 {
                let k = format!("key/{i:04}");
                if kind == LEAF {
                    e.push(k.as_bytes(), &[i as u8; 9]);
                } else {
                    e.push(if i == 0 { b"" } else { k.as_bytes() }, &v);
                }
            }
            assert!(build(&mut b, &e, 0, e.len(), FMT_SLOTTED));
            for _ in 0..20000 {
                let mut c = b.clone();
                for _ in 0..rng.range(1, 5) {
                    let i = rng.below(c.len() as u64) as usize;
                    c[i] = rng.next_u64() as u8;
                }
                seal(&mut c, 77, 1);
                if validate(&c, 4096, 77).is_ok() {
                    let mut k = Vec::new();
                    for i in 0..nslots(&c) {
                        key_into(&c, i, &mut k);
                        if kind == INT {
                            int_child(&c, i);
                        }
                    }
                    if kind == LEAF {
                        let _ = leaf_search(&c, b"key/0007");
                    } else {
                        let _ = int_route(&c, b"key/0007");
                    }
                }
            }
        }
    }

    #[test]
    fn short_separator() {
        let mut o = Vec::new();
        short_sep(b"abcdef", b"abcxyz", &mut o);
        assert_eq!(o, b"abcx");
        short_sep(b"ab", b"abc", &mut o);
        assert_eq!(o, b"abc");
        short_sep(b"a", b"b", &mut o);
        assert_eq!(o, b"b");
    }

    /// Word-at-a-time `lcp` equals the byte-wise definition at every length and mismatch position.
    #[test]
    fn lcp_word_steps_match_bytewise() {
        let a: Vec<u8> = (0..40u8).collect();
        for la in 0..=a.len() {
            for lb in 0..=a.len() {
                for d in 0..=lb {
                    let mut b = a[..lb].to_vec();
                    if d < lb {
                        b[d] ^= 0x80;
                    }
                    let want = a[..la].iter().zip(&b).take_while(|(x, y)| x == y).count();
                    assert_eq!(lcp(&a[..la], &b), want, "la {la} lb {lb} d {d}");
                }
            }
        }
    }

    /// Entries up to the page's entry limit: a list of one page plus one entry always splits into two pages that
    /// fit (leaf and interior), also when the half-bytes point does not.
    #[test]
    fn split_point_with_entries_up_to_the_limit() {
        for psz in [4096usize, 8192, 16384] {
            let max_entry = psz / 2 - 256;
            let mut rng = crate::rng::Rng::new(psz as u64);
            let (mut fallback, mut total_cases) = (0, 0);
            for case in 0..4000 {
                let leaf = case % 2 == 0;
                let fmt = if case % 4 == 1 {
                    FMT_COMPACT
                } else {
                    FMT_SLOTTED
                };
                let mut e = Ents::default();
                // grow a list of random keys/values until it is one page plus one more entry
                let mut keys: Vec<Vec<u8>> = Vec::new();
                let mut valid = false;
                loop {
                    let big = rng.pct(60);
                    let klen = if big {
                        rng.range(max_entry as u64 / 4, max_entry as u64 - 24) as usize
                    } else {
                        rng.range(1, 40) as usize
                    };
                    // interior entries are key + 12 byte ref: the key limit holds there too
                    let mut k = vec![0u8; klen];
                    rng.fill(&mut k);
                    keys.push(k);
                    keys.sort();
                    keys.dedup();
                    e.clear();
                    for (i, k) in keys.iter().enumerate() {
                        if leaf {
                            {
                                let room = max_entry.saturating_sub(4 + k.len());
                                let cap = if k.len() > max_entry / 4 {
                                    room.min(300)
                                } else {
                                    room
                                };
                                e.push(k, &vec![7u8; (k[0] as usize * 37 + k.len()) % (cap + 1)]);
                            }
                        } else {
                            e.push(if i == 0 { &[] } else { k }, &[0u8; REF_LEN]);
                        }
                    }
                    let n = e.len();
                    if n >= 3 && !fits(&e, 0, n, leaf, psz, fmt) {
                        // drop the newest key's effect: the list before the last push fitted by construction only
                        // when removing one entry makes it fit (one page + one entry)
                        let mut ok = false;
                        for skip in 0..n {
                            let mut e2 = Ents::default();
                            for i in (0..n).filter(|&i| i != skip) {
                                e2.push(e.key(i), e.val(i));
                            }
                            if fits(&e2, 0, n - 1, leaf, psz, fmt) {
                                ok = true;
                                break;
                            }
                        }
                        valid = ok;
                        break;
                    }
                    if keys.len() > 40 {
                        break;
                    }
                }
                let n = e.len();
                if !valid || n < 2 || fits(&e, 0, n, leaf, psz, fmt) {
                    continue;
                }
                total_cases += 1;
                let m = e.split_point(leaf, psz, fmt);
                assert!((1..n).contains(&m));
                assert!(
                    fits(&e, 0, m, leaf, psz, fmt),
                    "left half {m}/{n} psz {psz}"
                );
                assert!(
                    fits(&e, m, n, leaf, psz, fmt),
                    "right half {m}/{n} psz {psz}"
                );
                // the plain half-bytes point (what every page used before am. 10)
                let total: usize = (0..n).map(|i| e.full_size(i, leaf)).sum();
                let mut acc = 0;
                let mut h = n - 1;
                for i in 0..n {
                    acc += e.full_size(i, leaf);
                    if acc * 2 >= total {
                        h = (i + 1).clamp(1, n - 1);
                        break;
                    }
                }
                if !(fits(&e, 0, h, leaf, psz, fmt) && fits(&e, h, n, leaf, psz, fmt)) {
                    fallback += 1;
                }
            }
            assert!(total_cases > 100, "psz {psz}: only {total_cases} cases");
            assert!(
                fallback > 0,
                "psz {psz}: the fallback split was never needed"
            );
        }
    }

    /// In-place inserts keep runs <= 16 entries, but removing a restart merges its run into the previous one, so
    /// runs grow under insert/remove churn. With long suffixes shared by neighbours only, a FRESH encode of such a
    /// page (+1 entry) then needs more than two pages: the split must keep the page's restarts (`load_keep`).
    #[test]
    fn compact_split_after_churn_keeps_restarts() {
        let psz = 8192;
        let key = |g: u8, i: u16| {
            let mut k = vec![g];
            k.extend(std::iter::repeat_n(b'x', 1200));
            k.extend_from_slice(&i.to_be_bytes());
            k
        };
        let mut b = newp(INT, psz);
        let mut tmp = vec![0u8; psz];
        let mut e = Ents::default();
        let v = [0u8; REF_LEN];
        let groups = *b"abc";
        let heads: Vec<Vec<u8>> = groups.iter().map(|&g| key(g, 0)).collect();
        e.push(b"", &v);
        for h in &heads {
            e.push(h, &v);
        }
        assert!(build(&mut b, &e, 0, e.len(), FMT_COMPACT));
        let mut next: u16 = 60000;
        let mut cycles = 0;
        'outer: loop {
            let g = groups[cycles % groups.len()];
            for _ in 0..16 {
                next -= 1;
                let k = key(g, next);
                let pos = int_route(&b, &k) + 1;
                if !int_insert(&mut b, &mut tmp, &mut e, pos, &k, 5, 0) {
                    break 'outer;
                }
            }
            // drop entries one by one as the tree prunes children (restarts among them)
            loop {
                let mut done = false;
                for i in 1..nslots(&b) {
                    let mut kk = Vec::new();
                    key_into(&b, i, &mut kk);
                    if heads.contains(&kk) {
                        continue;
                    }
                    let mut c = b.clone();
                    remove_range(&mut c, &mut e, i, i + 1);
                    if free_total(&c) >= free_total(&b) + 1000 {
                        b = c;
                        done = true;
                        break;
                    }
                }
                if !done {
                    break;
                }
            }
            cycles += 1;
            assert!(cycles < 10_000);
        }
        next -= 1;
        let k = key(b'c', next);
        let pos = int_route(&b, &k) + 1;
        e.load(&b);
        e.insert(pos, &k, &v);
        let fresh = e.try_split_point(false, psz, FMT_COMPACT);
        e.load_keep(&b);
        e.insert(pos, &k, &v);
        let m = e
            .try_split_point(false, psz, FMT_COMPACT)
            .expect("a split keeping the restarts always exists");
        let n = e.len();
        let (mut l, mut r) = (newp(INT, psz), newp(INT, psz));
        assert!(build(&mut l, &e, 0, m, FMT_COMPACT));
        assert!(build(&mut r, &e, m, n, FMT_COMPACT));
        assert_eq!(nslots(&l) + nslots(&r), n);
        validate_compact(&l, psz, false).unwrap();
        validate_compact(&r, psz, false).unwrap();
        eprintln!("entries {n}, fresh split {fresh:?}, kept split {m}");
    }

    /// A full compact page whose last entry's lcp is a 2-byte varint ending one byte before the page end and whose
    /// length byte is >= 0x80: validate read past the page (panic) instead of rejecting it.
    #[test]
    fn compact_validate_rejects_a_varint_at_the_page_end() {
        let psz = 58;
        let mut b = vec![0u8; psz];
        b[4..6].copy_from_slice(&MAGIC.to_le_bytes());
        b[6] = INT;
        b[7] = 1;
        b[36] = FMT_COMPACT;
        b[8] = 2; // entries
        b[12] = 44; // heap lo
        b[14] = 14; // entry bytes
        b[37] = 1; // restarts
        b[42] = 44; // restart 0 at offset 44
        b[55] = 0x80;
        b[56] = 1;
        b[57] = 0x80;
        seal(&mut b, 9, 1);
        assert!(validate(&b, psz, 9).is_err());
    }

    /// A stored interior page never references a virtual (not yet written) page: such a child address would route
    /// into an unrelated in-memory page, so validate rejects it (both formats).
    #[test]
    fn stored_pages_with_virtual_children_are_rejected() {
        for fmt in [FMT_SLOTTED, FMT_COMPACT] {
            for virt in [false, true] {
                let mut e = Ents::default();
                for i in 0..20u64 {
                    let k = if i == 0 {
                        Vec::new()
                    } else {
                        format!("k{i:03}").into_bytes()
                    };
                    let a = if virt && i == 7 { VIRT | 5 } else { 1000 + i };
                    let mut v = [0u8; REF_LEN];
                    v[..8].copy_from_slice(&a.to_le_bytes());
                    e.push(&k, &v);
                }
                let mut b = vec![0u8; 4096];
                init_fmt(&mut b, INT, 1, 77, 0, fmt);
                assert!(build(&mut b, &e, 0, e.len(), fmt));
                seal(&mut b, 77, 1);
                assert_eq!(
                    validate(&b, 4096, 77).is_err(),
                    virt,
                    "fmt {fmt} virt {virt}"
                );
            }
        }
    }
}
