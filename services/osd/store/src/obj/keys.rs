// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! L2 key space (design 2.3). One ordered KV per shard; first byte = tag. `id` = u64 BE.
//!
//! | Tag | Key | Value |
//! |---|---|---|
//! | `C` | coll key | coll id, bits, object/byte counters |
//! | `N` | coll id, ghobject sort key | onode id |
//! | `L` | coll id, long-name key (names whose `N` key exceeds the tree key limit, adr 0021 am. 30) | onode id |
//! | `n` | id, 0x00 | onode |
//! | `a` | id, 0x01, name | xattr value (inline or fragment marker) |
//! | `h` | id, 0x02 | omap header |
//! | `e` | id, 0x03, lblk u32 BE | extent run |
//! | `o` | id, 0x04, key | omap value (inline or fragment marker) |
//! | `p` | id, 0x05, ty, key, frag u32 BE | fragments of values that do not fit a tree entry |
//! | `d` | id | inline data of a small object (onode flag `F_INLINE`, adr 0021 am. 14) |
//! | `r` | first data block u64 BE | refcount of shared blocks: run length, owners >= 2 (adr 0021 am. 32) |
//! | `Z` | class u8 | value-compression template of the class (adr 0021 am. 58) |
//! | `c` | id | omap counter delta resolved from omap runs: keys i64 LE, bytes i64 LE (adr 0476) |
//! | `m` | ... | reserved (shard misc) |
//! | `f` | chunk | engine (data bitmap), never touched here |

use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SpgT};

pub const T_COLL: u8 = b'C';
pub const T_NAME: u8 = b'N';
pub const T_ONODE: u8 = b'n';
pub const T_ATTR: u8 = b'a';
pub const T_HDR: u8 = b'h';
pub const T_EXT: u8 = b'e';
pub const T_OMAP: u8 = b'o';
pub const T_FRAG: u8 = b'p';
pub const T_INL: u8 = b'd';
/// Name index of names whose `N` key exceeds the tree key limit (adr 0021 am. 30).
pub const T_LNAME: u8 = b'L';
/// Refcount records of shared data blocks (adr 0021 am. 32).
pub const T_REF: u8 = b'r';
/// Value-compression templates (adr 0021 am. 58): `Z` + class -> template bytes. Immutable once written, never deleted.
pub const T_DICT: u8 = b'Z';

/// Omap counter deltas of earlier builds (adr 0476 before adr 0647-omap-blind-removals): `c` + id. No longer written or
/// read; the mount removes what an earlier build left (`Store::drop_counter_records`).
pub const T_OPEND: u8 = b'c';

/// `r` key of the refcount run starting at data block `pba`.
pub fn ref_key(pba: u64) -> [u8; 9] {
    let mut k = [0u8; 9];
    k[0] = T_REF;
    k[1..].copy_from_slice(&pba.to_be_bytes());
    k
}

pub const S_ONODE: u8 = 0;
pub const S_ATTR: u8 = 1;
pub const S_HDR: u8 = 2;
pub const S_EXT: u8 = 3;
pub const S_OMAP: u8 = 4;
pub const S_FRAG: u8 = 5;

/// Fragment owner type.
pub const FT_ATTR: u8 = 1;
pub const FT_OMAP: u8 = 2;

fn flip64(v: i64) -> [u8; 8] {
    ((v as u64) ^ (1 << 63)).to_be_bytes()
}

fn unflip64(b: &[u8]) -> i64 {
    (u64::from_be_bytes(b.try_into().unwrap()) ^ (1 << 63)) as i64
}

/// Memcomparable string: 0x00 -> 0x00 0xFF, terminator 0x00 0x01.
fn esc(out: &mut Vec<u8>, s: &[u8]) {
    if !s.contains(&0) {
        out.extend_from_slice(s);
        out.extend_from_slice(&[0, 1]);
        return;
    }
    for &c in s {
        out.push(c);
        if c == 0 {
            out.push(0xFF);
        }
    }
    out.push(0);
    out.push(1);
}

/// Inverse of [`esc`]: the string at `pos` (moved past its terminator). Copies runs between zero bytes in one piece (a
/// name without a zero byte: one allocation of its exact size, one copy).
fn unesc(b: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    let mut out: Option<Vec<u8>> = None;
    loop {
        let rest = b.get(*pos..)?;
        let z = rest.iter().position(|&c| c == 0)?;
        let run = &rest[..z];
        match *rest.get(z + 1)? {
            1 => {
                *pos += z + 2;
                return Some(match out {
                    None => run.to_vec(),
                    Some(mut o) => {
                        o.extend_from_slice(run);
                        o
                    }
                });
            }
            0xFF => {
                *pos += z + 2;
                let o = out.get_or_insert_with(Vec::new);
                o.extend_from_slice(run);
                o.push(0);
            }
            _ => return None,
        }
    }
}

/// The head of a decoded name: the vectors move in (no second copy); the locator key is stored empty when it equals
/// the oid (as [`Hobject::set_key`]).
fn hobj_of(
    oid: Vec<u8>,
    eff: Vec<u8>,
    nspace: Vec<u8>,
    snap: u64,
    hash: u32,
    pool: i64,
    max: bool,
) -> Hobject {
    let key = if eff == oid { Vec::new() } else { eff };
    Hobject {
        key,
        oid,
        snap: denc::types::SnapId(snap),
        hash,
        max,
        nspace,
        pool,
    }
}

/// Collection key (`C` + type + pool + seed + shard); not order-critical but stable and decodable.
pub fn coll_key(c: &CollT) -> Vec<u8> {
    let mut b = [0u8; COLL_KEY_MAX];
    let n = coll_key_buf(c, &mut b);
    b[..n].to_vec()
}

pub fn decode_coll_key(k: &[u8]) -> Option<CollT> {
    if k.first() != Some(&T_COLL) {
        return None;
    }
    match *k.get(1)? {
        0 if k.len() == 2 => Some(CollT::Meta),
        t @ (1 | 2) if k.len() == 15 => {
            let spg = SpgT {
                pgid: PgT::new(
                    u64::from_be_bytes(k[2..10].try_into().unwrap()),
                    u32::from_be_bytes(k[10..14].try_into().unwrap()),
                ),
                shard: ShardId((k[14] ^ 0x80) as i8),
            };
            Some(if t == 1 {
                CollT::Pg(spg)
            } else {
                CollT::PgTemp(spg)
            })
        }
        _ => None,
    }
}

/// Bytes of a collection prefix ([`name_prefix`], [`long_prefix`]).
const NAME_PREFIX_LEN: usize = 9;

/// Prefix of all `N` keys of a collection.
pub fn name_prefix(coll: u64) -> [u8; NAME_PREFIX_LEN] {
    let mut k = [0u8; NAME_PREFIX_LEN];
    k[0] = T_NAME;
    k[1..].copy_from_slice(&coll.to_be_bytes());
    k
}

/// End (exclusive) of a collection's `N` range.
pub fn name_end(coll: u64) -> [u8; NAME_PREFIX_LEN] {
    name_prefix(coll + 1)
}

/// `N` key of `g` in collection `coll`, built in one allocation.
pub fn name_key_of(coll: u64, g: &Ghobject) -> Vec<u8> {
    let h = &g.hobj;
    let mut k = crate::vpool::take(64 + 2 * h.oid.len() + h.nspace.len() + h.key.len());
    k.extend_from_slice(&name_prefix(coll));
    sort_key_into(&mut k, g);
    k
}

pub fn name_key(coll: u64, sk: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(NAME_PREFIX_LEN + sk.len());
    k.extend_from_slice(&name_prefix(coll));
    k.extend_from_slice(sk);
    k
}

/// Bytes [`esc`] appends for `s`.
fn esc_len(s: &[u8]) -> usize {
    s.len() + s.iter().filter(|&&c| c == 0).count() + 2
}

/// Bytes of [`sort_key`] without building it (parked-txn cost accounting, the name-limit checks of `check`).
pub fn sort_key_len(g: &Ghobject) -> usize {
    let h = &g.hobj;
    let eff: &[u8] = if h.key.is_empty() { &h.oid } else { &h.key };
    // fixed head: max, shard, hobject max, pool, hash
    15 + esc_len(&h.nspace)
        + esc_len(eff)
        + esc_len(&h.oid)
        // snap and generation
        + 16
}

/// Bytes of [`name_key_of`] for any collection.
pub fn name_key_len(g: &Ghobject) -> usize {
    NAME_PREFIX_LEN + sort_key_len(g)
}

/// Memcomparable ghobject key following Ceph's order (encoding.md 8.5/8.6): ghobject max, shard (signed),
/// hobject max, pool (signed), bit-reversed hash, nspace, effective key, oid, snap, generation.
/// The effective key (locator, or oid when none) is always encoded: for two objects without locator this
/// reduces to comparing oids, so the rule "compare keys only if one side has one" holds.
pub fn sort_key(g: &Ghobject) -> Vec<u8> {
    let h = &g.hobj;
    let mut k = Vec::with_capacity(48 + 2 * h.oid.len() + h.nspace.len() + h.key.len());
    sort_key_into(&mut k, g);
    k
}

/// Fixed leading fields of every name key (15 bytes after the collection prefix).
fn fixed_into(k: &mut Vec<u8>, g: &Ghobject) {
    let h = &g.hobj;
    k.push(g.max as u8);
    k.push(g.shard.0 as u8 ^ 0x80);
    k.push(h.max as u8);
    k.extend_from_slice(&flip64(h.pool));
    k.extend_from_slice(&h.hash.reverse_bits().to_be_bytes());
}

/// Append the sort key of `g` to `k`.
pub fn sort_key_into(k: &mut Vec<u8>, g: &Ghobject) {
    let h = &g.hobj;
    fixed_into(k, g);
    esc(k, &h.nspace);
    esc(k, if h.key.is_empty() { &h.oid } else { &h.key });
    esc(k, &h.oid);
    k.extend_from_slice(&h.snap.0.to_be_bytes());
    k.extend_from_slice(&g.generation.to_be_bytes());
}

pub fn decode_sort_key(b: &[u8]) -> Option<Ghobject> {
    if b.len() < 3 + 8 + 4 {
        return None;
    }
    let (gmax, shard, hmax) = (b[0] != 0, ShardId((b[1] ^ 0x80) as i8), b[2] != 0);
    let pool = unflip64(&b[3..11]);
    let hash = u32::from_be_bytes(b[11..15].try_into().unwrap()).reverse_bits();
    let mut pos = 15;
    let nspace = unesc(b, &mut pos)?;
    let eff = unesc(b, &mut pos)?;
    let oid = unesc(b, &mut pos)?;
    if b.len() != pos + 16 {
        return None;
    }
    let snap = u64::from_be_bytes(b[pos..pos + 8].try_into().unwrap());
    let generation = u64::from_be_bytes(b[pos + 8..].try_into().unwrap());
    Some(Ghobject {
        hobj: hobj_of(oid, eff, nspace, snap, hash, pool, hmax),
        generation,
        shard,
        max: gmax,
    })
}

/// Prefix of all `L` keys of a collection.
pub fn long_prefix(coll: u64) -> [u8; NAME_PREFIX_LEN] {
    let mut k = name_prefix(coll);
    k[0] = T_LNAME;
    k
}

/// End (exclusive) of a collection's `L` range.
pub fn long_end(coll: u64) -> [u8; NAME_PREFIX_LEN] {
    long_prefix(coll + 1)
}

/// Class of the oid against the effective key: 0 below, 1 equal (every locator-less name), 2 above.
fn cls_of(eff: &[u8], oid: &[u8]) -> u8 {
    match oid.cmp(eff) {
        std::cmp::Ordering::Less => 0,
        std::cmp::Ordering::Equal => 1,
        std::cmp::Ordering::Greater => 2,
    }
}

/// `L` key of `g` in collection `coll` (adr 0021 am. 30): the sort key with the oid replaced by its class against the
/// effective key (stored once for a locator-less name). Orders like [`sort_key`] among `L` keys; valid for any ghobject
/// (also as a scan bound).
pub fn long_key_of(coll: u64, g: &Ghobject) -> Vec<u8> {
    let h = &g.hobj;
    let eff: &[u8] = if h.key.is_empty() { &h.oid } else { &h.key };
    let cls = cls_of(eff, &h.oid);
    let mut k = Vec::with_capacity(
        48 + eff.len() + h.nspace.len() + if cls == 1 { 0 } else { h.oid.len() },
    );
    k.extend_from_slice(&long_prefix(coll));
    fixed_into(&mut k, g);
    esc(&mut k, &h.nspace);
    esc(&mut k, eff);
    k.push(cls);
    if cls != 1 {
        esc(&mut k, &h.oid);
    }
    k.extend_from_slice(&h.snap.0.to_be_bytes());
    k.extend_from_slice(&g.generation.to_be_bytes());
    k
}

/// Decode the part of an `L` key after the 9-byte prefix.
pub fn decode_long_key(b: &[u8]) -> Option<Ghobject> {
    if b.len() < 3 + 8 + 4 {
        return None;
    }
    let (gmax, shard, hmax) = (b[0] != 0, ShardId((b[1] ^ 0x80) as i8), b[2] != 0);
    let pool = unflip64(&b[3..11]);
    let hash = u32::from_be_bytes(b[11..15].try_into().unwrap()).reverse_bits();
    let mut pos = 15;
    let nspace = unesc(b, &mut pos)?;
    let eff = unesc(b, &mut pos)?;
    let cls = *b.get(pos)?;
    pos += 1;
    let oid = match cls {
        1 => eff.clone(),
        0 | 2 => unesc(b, &mut pos)?,
        _ => return None,
    };
    if cls_of(&eff, &oid) != cls || b.len() != pos + 16 {
        return None;
    }
    let snap = u64::from_be_bytes(b[pos..pos + 8].try_into().unwrap());
    let generation = u64::from_be_bytes(b[pos + 8..].try_into().unwrap());
    Some(Ghobject {
        hobj: hobj_of(oid, eff, nspace, snap, hash, pool, hmax),
        generation,
        shard,
        max: gmax,
    })
}

fn idkey(tag: u8, id: u64, sub: u8, extra: usize) -> Vec<u8> {
    let mut k = crate::vpool::take(10 + extra);
    k.push(tag);
    k.extend_from_slice(&id.to_be_bytes());
    k.push(sub);
    k
}

/// Object id of an id-keyed record (`idkey` layout: tag, id big endian, sub tag, ...).
#[inline]
pub fn onode_id_of(k: &[u8]) -> Option<u64> {
    k.get(1..9)
        .map(|b| u64::from_be_bytes(b.try_into().unwrap()))
}

pub fn onode_key(id: u64) -> Vec<u8> {
    idkey(T_ONODE, id, S_ONODE, 0)
}
pub fn attr_key(id: u64, name: &[u8]) -> Vec<u8> {
    let mut k = idkey(T_ATTR, id, S_ATTR, name.len());
    k.extend_from_slice(name);
    k
}
pub fn hdr_key(id: u64) -> Vec<u8> {
    idkey(T_HDR, id, S_HDR, 0)
}
pub fn ext_key(id: u64, lblk: u32) -> Vec<u8> {
    let mut k = idkey(T_EXT, id, S_EXT, 4);
    k.extend_from_slice(&lblk.to_be_bytes());
    k
}
pub fn omap_key(id: u64, key: &[u8]) -> Vec<u8> {
    let mut k = idkey(T_OMAP, id, S_OMAP, key.len());
    k.extend_from_slice(key);
    k
}
pub fn frag_key(id: u64, ty: u8, key: &[u8], idx: u32) -> Vec<u8> {
    let mut k = idkey(T_FRAG, id, S_FRAG, key.len() + 5);
    k.push(ty);
    k.extend_from_slice(key);
    k.extend_from_slice(&idx.to_be_bytes());
    k
}

/// Prefix of every key of tag `tag` belonging to `id`, and its exclusive end.
pub fn id_range(tag: u8, id: u64) -> (Vec<u8>, Vec<u8>) {
    let mut a = vec![tag];
    a.extend_from_slice(&id.to_be_bytes());
    let mut b = vec![tag];
    b.extend_from_slice(&(id + 1).to_be_bytes());
    (a, b)
}

/// Range of fragments of one owner type.
pub fn frag_range(id: u64, ty: u8) -> (Vec<u8>, Vec<u8>) {
    let a = idkey(T_FRAG, id, S_FRAG, 1);
    let mut a2 = a.clone();
    a2.push(ty);
    let mut b = a;
    b.push(ty + 1);
    (a2, b)
}

/// Range of all user keys of `ty` (`o` or `a`) of `id`.
pub fn sub_range(tag: u8, sub: u8, id: u64) -> (Vec<u8>, Vec<u8>) {
    (idkey(tag, id, sub, 0), idkey(tag, id, sub + 1, 0))
}

/// First byte after a key prefix (exclusive upper bound of "all keys starting with `p`"); `None` when every byte of
/// `p` is `0xFF` (no key sorts above it, so there is no finite bound).
pub fn prefix_end(p: &[u8]) -> Option<Vec<u8>> {
    let mut e = p.to_vec();
    while let Some(l) = e.last_mut() {
        if *l == 0xFF {
            e.pop();
        } else {
            *l += 1;
            return Some(e);
        }
    }
    None
}

/// Exclusive end of the omap keys of `id` that start with `prefix` (every omap key of `id` for an empty prefix).
pub fn omap_prefix_end(id: u64, prefix: &[u8]) -> Vec<u8> {
    let all = sub_range(T_OMAP, S_OMAP, id).1;
    if prefix.is_empty() {
        return all;
    }
    // the key starts with the `o` tag (never `0xFF`), so a bound exists; the id's whole range also bounds it
    match prefix_end(&omap_key(id, prefix)) {
        Some(e) => e.min(all),
        None => all,
    }
}

/// Longest collection key ([`coll_key_buf`]).
pub const COLL_KEY_MAX: usize = 15;

/// Stack form of [`coll_key`]: writes into `b`, returns the key length.
pub fn coll_key_buf(c: &CollT, b: &mut [u8; COLL_KEY_MAX]) -> usize {
    b[0] = T_COLL;
    match c {
        CollT::Meta => {
            b[1] = 0;
            2
        }
        CollT::Pg(s) | CollT::PgTemp(s) => {
            b[1] = if matches!(c, CollT::Pg(_)) { 1 } else { 2 };
            b[2..10].copy_from_slice(&s.pgid.pool.to_be_bytes());
            b[10..14].copy_from_slice(&s.pgid.seed.to_be_bytes());
            b[14] = s.shard.0 as u8 ^ 0x80;
            15
        }
    }
}

/// Stack form of [`onode_key`].
pub fn onode_key_arr(id: u64) -> [u8; 10] {
    let mut k = [0u8; 10];
    k[0] = T_ONODE;
    k[1..9].copy_from_slice(&id.to_be_bytes());
    k[9] = S_ONODE;
    k
}

/// Key of the inline data of object `id` (tag + id, nothing else).
pub fn inl_key_arr(id: u64) -> [u8; 9] {
    let mut k = [0u8; 9];
    k[0] = T_INL;
    k[1..].copy_from_slice(&id.to_be_bytes());
    k
}

/// Stack form of [`ext_key`].
pub fn ext_key_arr(id: u64, lblk: u32) -> [u8; 14] {
    let mut k = [0u8; 14];
    k[0] = T_EXT;
    k[1..9].copy_from_slice(&id.to_be_bytes());
    k[9] = S_EXT;
    k[10..].copy_from_slice(&lblk.to_be_bytes());
    k
}

#[cfg(test)]
mod tests {
    use super::*;
    use denc::types::SnapId;

    fn g(oid: &[u8], key: &[u8], ns: &[u8], hash: u32, snap: u64, pool: i64) -> Ghobject {
        let mut h = Hobject::new(oid, SnapId(snap), hash, pool, ns);
        h.set_key(key);
        Ghobject::new(h, Ghobject::NO_GEN, ShardId::NO_SHARD)
    }

    #[test]
    fn roundtrip_and_order() {
        let mut v = vec![];
        let names: [&[u8]; 9] = [
            b"",
            b"a",
            b"a\0",
            b"a\0b",
            b"ab",
            b"\xff",
            b"\0",
            b"\0\0",
            b"a\0\0b\0c",
        ];
        for (i, n) in names.iter().enumerate() {
            for ns in [&b""[..], b"ns", b"n\0s"] {
                for key in [&b""[..], b"k", b"a\0"] {
                    for hash in [0u32, 1, 0x8000_0000, 0xdead_beef] {
                        v.push(g(
                            n,
                            key,
                            ns,
                            hash,
                            i as u64 * 7 % 3,
                            if i % 2 == 0 { 1 } else { -3 },
                        ));
                    }
                }
            }
        }
        let mut gm = g(b"x", b"", b"", 5, 1, 2);
        gm.generation = 7;
        gm.shard = ShardId(3);
        v.push(gm);
        for a in &v {
            assert_eq!(decode_sort_key(&sort_key(a)).as_ref(), Some(a));
            assert_eq!(sort_key_len(a), sort_key(a).len(), "{a:?}");
            assert_eq!(name_key_len(a), name_key_of(7, a).len(), "{a:?}");
        }
        for a in &v {
            for b in &v {
                assert_eq!(a.cmp(b), sort_key(a).cmp(&sort_key(b)), "{a:?} {b:?}");
            }
        }
    }

    /// The prefix bound is the exact successor while a byte below `0xFF` exists, and absent for an all-`0xFF` prefix:
    /// no key sorts above it, so there is no finite bound (never a made-up one).
    #[test]
    fn prefix_end_is_the_exact_successor_or_absent() {
        assert_eq!(prefix_end(b""), None);
        assert_eq!(prefix_end(b"\xff"), None);
        assert_eq!(prefix_end(b"\xff\xff"), None);
        assert_eq!(prefix_end(b"o"), Some(b"p".to_vec()));
        assert_eq!(
            prefix_end(b"o\xff\xff\x01"),
            Some(b"o\xff\xff\x02".to_vec())
        );
        assert_eq!(prefix_end(b"o\xff\xff"), Some(b"p".to_vec()));
        assert_eq!(prefix_end(b"a\x00"), Some(b"a\x01".to_vec()));
        // the omap bound stays an exclusive upper bound (and inside the id's omap range) for every prefix
        let all = sub_range(T_OMAP, S_OMAP, 9).1;
        for p in [&b""[..], b"k", b"\xff", b"\xff\xff", b"a\0"] {
            let end = omap_prefix_end(9, p);
            assert!(omap_key(9, p) < end && end <= all, "{p:?}");
        }
    }

    /// `unesc` takes runs between zero bytes in one piece: escapes in a row, an escape at the end, a bad escape byte and a
    /// missing terminator.
    #[test]
    fn unesc_runs_and_bad_input() {
        for s in [
            &b""[..],
            b"abc",
            b"\0",
            b"\0\0\0",
            b"a\0",
            b"\0a",
            b"a\0\0b\0c",
        ] {
            let mut e = Vec::new();
            esc(&mut e, s);
            e.push(9);
            let mut pos = 0;
            assert_eq!(unesc(&e, &mut pos).as_deref(), Some(s));
            assert_eq!(pos, e.len() - 1, "{s:?}");
        }
        let mut pos = 0;
        assert_eq!(unesc(b"ab\0\x02", &mut pos), None, "bad escape");
        let mut pos = 0;
        assert_eq!(unesc(b"ab\0", &mut pos), None, "cut after the zero");
        let mut pos = 0;
        assert_eq!(unesc(b"ab", &mut pos), None, "no terminator");
    }

    #[test]
    fn long_key_roundtrip_and_order_equal_the_hobject_order() {
        // names around the class pivots: same (nspace, effective key), oids below / equal / above, NULs, long ones
        let k1700 = vec![b'k'; 1700];
        let mut below = k1700.clone();
        below.pop();
        let mut above = k1700.clone();
        above.push(0);
        let mut nul = k1700.clone();
        nul[10] = 0;
        let oids: Vec<Vec<u8>> = vec![
            vec![],
            b"a".to_vec(),
            below,
            k1700.clone(),
            above,
            nul,
            vec![b'l'; 1700],
            b"\xff".to_vec(),
        ];
        let mut v = vec![];
        for oid in &oids {
            for key in [&b""[..], &k1700, b"a"] {
                for ns in [&b""[..], b"ns", b"n\0s"] {
                    for (hash, snap) in [(1u32, 0u64), (1, 5), (0x8000_0000, 2)] {
                        v.push(g(oid, key, ns, hash, snap, 1));
                    }
                }
            }
        }
        let mut gm = g(b"x", b"", b"", 5, 1, 2);
        gm.generation = 7;
        gm.shard = ShardId(3);
        v.push(gm);
        for a in &v {
            let lk = long_key_of(9, a);
            assert_eq!(&lk[..9], &long_prefix(9));
            assert_eq!(decode_long_key(&lk[9..]).as_ref(), Some(a), "{a:?}");
        }
        for a in &v {
            for b in &v {
                assert_eq!(
                    a.cmp(b),
                    long_key_of(9, a).cmp(&long_key_of(9, b)),
                    "{a:?} {b:?}"
                );
            }
        }
        // a locator-less name is stored once
        let lk = long_key_of(1, &g(&vec![b'a'; 2048], b"", b"", 3, 0, 1));
        assert!(lk.len() < 2200, "{}", lk.len());
        // damaged class / trailing bytes never decode
        let mut bad = long_key_of(1, &g(b"o", b"k", b"", 3, 0, 1));
        let n = bad.len();
        bad[n - 17 - 2 - 1] = 1; // flip the class byte of the stored oid
        assert!(decode_long_key(&bad[9..]).is_none());
    }

    #[test]
    fn coll_roundtrip() {
        for c in [
            CollT::Meta,
            CollT::Pg(SpgT {
                pgid: PgT::new(3, 0x1f),
                shard: ShardId::NO_SHARD,
            }),
            CollT::PgTemp(SpgT {
                pgid: PgT::new(u64::MAX, 7),
                shard: ShardId(2),
            }),
        ] {
            assert_eq!(decode_coll_key(&coll_key(&c)), Some(c));
        }
    }
}
