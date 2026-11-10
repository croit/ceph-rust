// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! ObjectStore::Transaction wire format v9 / v10 (spec replication.md 1).
//!
//! Decoding yields a typed [`Transaction`]: collection and object tables plus a list of [`Op`]s that
//! reference the tables by [`Cx`] / [`Ox`] index. Payload bytes borrow from the input segments
//! (zero copy); only the small attr/key lists allocate. Unsupported op codes are a decode error
//! (spec 1.6: fail the PG loudly instead of mis-parsing).

use core::fmt;
use denc::types::{CollT, Ghobject};
use denc::{Decoder, Encoder, Error, Result, le};

/// Page size assumed for the v10 aligned/misaligned write split (spec U1).
pub const DEFAULT_PAGE: usize = 4096;

/// SERVER_TENTACLE feature bit (bit 50). A v10 txn whose `data_features` lacks it carries write
/// payloads as plain length-prefixed `bl` in the misaligned stream (observed on a classic primary:
/// struct_v 10, data_features 0, len_aligned 0); only with the bit set are writes split (spec 1.4).
pub use denc::features::{SERVER_TENTACLE, TENTACLE_BIT};

/// Write payloads and omap set-keys runs (their entry bytes) of at least this many bytes are kept out of line in the local
/// txn skeleton (`encode_v9_split`).
pub const SPLIT_MIN: usize = 64 * 1024;

/// Offset of the first write payload in a v9 blob made by [`Transaction::encode_v9`] / `encode_v9_rope`: the 6-byte
/// versioned envelope, the u32 length of the inline stream, the u32 length of the payload. A replica receives a client
/// write's blob with this offset on a 4 KiB grid (sender `data_off` = [`crate::REPOP_DATA_OFF`], `msgr2::Decoder::set_rx_place`, adr 0061 am. 7); a blob that differs
/// (other ops first, a classic primary) just does not match the grid and is staged as before.
pub const PAYLOAD_AT: usize = 14;

/// Offset of the misaligned stream in a v9 blob: the 6-byte versioned envelope and the u32 stream length.
pub const V9_STREAM_AT: usize = 10;

/// Memory alignment [`Transaction::encode_v9_placed`] gives the first write payload: the device block and the kernel
/// view alignment (`nvme::kdev::VIEW_ALIGN`).
pub const PLACE_ALIGN: usize = crc::blocks::BLK;

/// Inline-stream length marker of an out-of-line write payload (impossible as a real length).
const REF_MARK: u32 = u32::MAX;

/// Op record size in `op_bl`.
pub const OP_SIZE: usize = 72;

/// `Transaction::OP_*` codes.
pub mod opc {
    pub const NOP: u32 = 0;
    pub const CREATE: u32 = 7;
    pub const TOUCH: u32 = 9;
    pub const WRITE: u32 = 10;
    pub const ZERO: u32 = 11;
    pub const TRUNCATE: u32 = 12;
    pub const REMOVE: u32 = 13;
    pub const SETATTR: u32 = 14;
    pub const SETATTRS: u32 = 15;
    pub const RMATTR: u32 = 16;
    pub const CLONE: u32 = 17;
    pub const CLONERANGE: u32 = 18;
    pub const MKCOLL: u32 = 20;
    pub const RMCOLL: u32 = 21;
    pub const RMATTRS: u32 = 28;
    pub const CLONERANGE2: u32 = 30;
    pub const OMAP_CLEAR: u32 = 31;
    pub const OMAP_SETKEYS: u32 = 32;
    pub const OMAP_RMKEYS: u32 = 33;
    pub const OMAP_SETHEADER: u32 = 34;
    pub const SPLIT_COLLECTION2: u32 = 36;
    pub const OMAP_RMKEYRANGE: u32 = 37;
    pub const COLL_MOVE_RENAME: u32 = 38;
    pub const SETALLOCHINT: u32 = 39;
    pub const COLL_HINT: u32 = 40;
    pub const TRY_RENAME: u32 = 41;
    pub const COLL_SET_BITS: u32 = 42;
    pub const MERGE_COLLECTION: u32 = 43;
    pub const TOUCH_TEMP: u32 = 44;
}

/// Index into [`Transaction::colls`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Cx(pub u32);
/// Index into [`Transaction::objs`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Ox(pub u32);

/// Write payload: up to three slices (v10 splits into misaligned prefix, aligned middle, misaligned
/// suffix; v9 and small writes use `head` only). Logical bytes = head || mid || tail.
#[derive(Clone, Copy, Default)]
pub struct Data<'a> {
    pub head: &'a [u8],
    pub mid: &'a [u8],
    pub tail: &'a [u8],
}

impl<'a> Data<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Data {
            head: b,
            mid: &[],
            tail: &[],
        }
    }
    pub fn len(&self) -> usize {
        self.head.len() + self.mid.len() + self.tail.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn parts(&self) -> [&'a [u8]; 3] {
        [self.head, self.mid, self.tail]
    }
    pub fn to_vec(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.len());
        self.copy_range(0, self.len(), &mut v);
        v
    }
    /// Append logical bytes `[lo, hi)` to `out`.
    pub fn copy_range(&self, lo: usize, hi: usize, out: &mut Vec<u8>) {
        let mut base = 0;
        for p in self.parts() {
            let (a, b) = (lo.max(base), hi.min(base + p.len()));
            if a < b {
                out.extend_from_slice(&p[a - base..b - base]);
            }
            base += p.len();
        }
    }
}
impl<'a> From<&'a [u8]> for Data<'a> {
    fn from(b: &'a [u8]) -> Self {
        Data::new(b)
    }
}
impl PartialEq for Data<'_> {
    fn eq(&self, o: &Self) -> bool {
        self.len() == o.len()
            && self
                .parts()
                .into_iter()
                .flatten()
                .eq(o.parts().into_iter().flatten())
    }
}
impl Eq for Data<'_> {}
impl fmt::Debug for Data<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Data({}B)", self.len())
    }
}

/// One transaction operation (spec 1.6). Object operands are table indices. `KV` / `KS` = representation of the
/// key-value / key lists: `Vec`s in [`TxnOp`], lazy wire slices ([`Kv`], [`Ks`]) in [`LazyOp`] ([`OpStream`]); `OKV` =
/// the omap set-keys list ([`OmapKv`] in [`TxnOp`]: pairs or a sorted run kept as its encoding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxnOpG<'a, KV, KS, OKV> {
    Nop,
    Create {
        oid: Ox,
    },
    Touch {
        oid: Ox,
    },
    /// crimson only; = touch(oid), `dest_oid` ignored.
    TouchTemp {
        oid: Ox,
        dest_oid: Ox,
    },
    Write {
        oid: Ox,
        off: u64,
        data: Data<'a>,
    },
    Zero {
        oid: Ox,
        off: u64,
        len: u64,
    },
    Truncate {
        oid: Ox,
        size: u64,
    },
    Remove {
        oid: Ox,
    },
    SetAttr {
        oid: Ox,
        name: &'a [u8],
        value: &'a [u8],
    },
    SetAttrs {
        oid: Ox,
        attrs: KV,
    },
    RmAttr {
        oid: Ox,
        name: &'a [u8],
    },
    RmAttrs {
        oid: Ox,
    },
    Clone {
        oid: Ox,
        dest_oid: Ox,
    },
    CloneRange2 {
        oid: Ox,
        dest_oid: Ox,
        src_off: u64,
        len: u64,
        dest_off: u64,
    },
    MkColl {
        bits: u32,
    },
    RmColl,
    CollHint {
        ty: u32,
        data: &'a [u8],
    },
    CollMoveRename {
        oid: Ox,
        dest_cid: Cx,
        dest_oid: Ox,
    },
    TryRename {
        oid: Ox,
        dest_oid: Ox,
    },
    OmapClear {
        oid: Ox,
    },
    OmapSetKeys {
        oid: Ox,
        pairs: OKV,
    },
    OmapRmKeys {
        oid: Ox,
        keys: KS,
    },
    /// Delete keys in `[first, last)`.
    OmapRmKeyRange {
        oid: Ox,
        first: &'a [u8],
        last: &'a [u8],
    },
    OmapSetHeader {
        oid: Ox,
        header: &'a [u8],
    },
    SetAllocHint {
        oid: Ox,
        expected_object_size: u64,
        expected_write_size: u64,
        flags: u32,
    },
    SplitCollection2 {
        dest_cid: Cx,
        bits: u32,
        rem: u32,
    },
    MergeCollection {
        dest_cid: Cx,
        bits: u32,
    },
    CollSetBits {
        bits: u32,
    },
}

impl<KV, KS, OKV> TxnOpG<'_, KV, KS, OKV> {
    /// Wire op code.
    pub fn code(&self) -> u32 {
        use TxnOpG::*;
        match self {
            Nop => opc::NOP,
            Create { .. } => opc::CREATE,
            Touch { .. } => opc::TOUCH,
            TouchTemp { .. } => opc::TOUCH_TEMP,
            Write { .. } => opc::WRITE,
            Zero { .. } => opc::ZERO,
            Truncate { .. } => opc::TRUNCATE,
            Remove { .. } => opc::REMOVE,
            SetAttr { .. } => opc::SETATTR,
            SetAttrs { .. } => opc::SETATTRS,
            RmAttr { .. } => opc::RMATTR,
            RmAttrs { .. } => opc::RMATTRS,
            Clone { .. } => opc::CLONE,
            CloneRange2 { .. } => opc::CLONERANGE2,
            MkColl { .. } => opc::MKCOLL,
            RmColl => opc::RMCOLL,
            CollHint { .. } => opc::COLL_HINT,
            CollMoveRename { .. } => opc::COLL_MOVE_RENAME,
            TryRename { .. } => opc::TRY_RENAME,
            OmapClear { .. } => opc::OMAP_CLEAR,
            OmapSetKeys { .. } => opc::OMAP_SETKEYS,
            OmapRmKeys { .. } => opc::OMAP_RMKEYS,
            OmapRmKeyRange { .. } => opc::OMAP_RMKEYRANGE,
            OmapSetHeader { .. } => opc::OMAP_SETHEADER,
            SetAllocHint { .. } => opc::SETALLOCHINT,
            SplitCollection2 { .. } => opc::SPLIT_COLLECTION2,
            MergeCollection { .. } => opc::MERGE_COLLECTION,
            CollSetBits { .. } => opc::COLL_SET_BITS,
        }
    }
}

/// [`TxnOpG`] with owned lists (the decoded / encodable form).
pub type TxnOp<'a> = TxnOpG<'a, Vec<(&'a [u8], &'a [u8])>, Vec<&'a [u8]>, OmapKv<'a>>;

/// Omap set-keys list of a [`TxnOp`]: pairs, or a run of strictly ascending keys kept as its map encoding (a client
/// batch; encoded and decoded as one block, no per-key work: doc/perf/omap-perkey-20261021.md).
#[derive(Debug, Clone)]
pub enum OmapKv<'a> {
    Pairs(Vec<(&'a [u8], &'a [u8])>),
    Run(denc::SortedKv<'a>),
}

impl<'a> OmapKv<'a> {
    pub fn len(&self) -> usize {
        match self {
            OmapKv::Pairs(p) => p.len(),
            OmapKv::Run(r) => r.len(),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// The entries (a run in ascending key order, pairs as given).
    pub fn iter(&self) -> OmapKvIter<'a, '_> {
        match self {
            OmapKv::Pairs(p) => OmapKvIter::Pairs(p.iter()),
            OmapKv::Run(r) => OmapKvIter::Run(r.iter()),
        }
    }
    /// The sorted run, if this list is one.
    pub fn run(&self) -> Option<denc::SortedKv<'a>> {
        match self {
            OmapKv::Run(r) => Some(*r),
            OmapKv::Pairs(_) => None,
        }
    }
}

impl<'a> From<Vec<(&'a [u8], &'a [u8])>> for OmapKv<'a> {
    fn from(p: Vec<(&'a [u8], &'a [u8])>) -> Self {
        OmapKv::Pairs(p)
    }
}

/// Equal when the entries are equal (pairs and run are two encodings of one list).
impl PartialEq for OmapKv<'_> {
    fn eq(&self, o: &Self) -> bool {
        self.len() == o.len() && self.iter().eq(o.iter())
    }
}
impl Eq for OmapKv<'_> {}

impl<'a> FromIterator<(&'a [u8], &'a [u8])> for OmapKv<'a> {
    fn from_iter<I: IntoIterator<Item = (&'a [u8], &'a [u8])>>(it: I) -> Self {
        OmapKv::Pairs(it.into_iter().collect())
    }
}

impl<'a, 'b> IntoIterator for &'b OmapKv<'a> {
    type Item = (&'a [u8], &'a [u8]);
    type IntoIter = OmapKvIter<'a, 'b>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator of [`OmapKv::iter`].
#[derive(Debug, Clone)]
pub enum OmapKvIter<'a, 'b> {
    Pairs(core::slice::Iter<'b, (&'a [u8], &'a [u8])>),
    Run(denc::SortedKvIter<'a>),
}

impl<'a> Iterator for OmapKvIter<'a, '_> {
    type Item = (&'a [u8], &'a [u8]);
    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            OmapKvIter::Pairs(i) => i.next().copied(),
            OmapKvIter::Run(i) => i.next(),
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            OmapKvIter::Pairs(i) => i.size_hint(),
            OmapKvIter::Run(i) => i.size_hint(),
        }
    }
}

impl ExactSizeIterator for OmapKvIter<'_, '_> {}

/// An op plus the collection it applies to (`cid` is 0 and unused for [`TxnOp::Nop`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Op<'a> {
    pub cid: Cx,
    pub op: TxnOp<'a>,
}

/// A decoded (or under construction) transaction.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Transaction<'a> {
    /// Index order (index i = `colls[i]`).
    pub colls: Vec<CollT>,
    pub objs: Vec<Ghobject>,
    pub ops: Vec<Op<'a>>,
    /// TransactionData.fadvise_flags (txn-global cache hints; ignorable).
    pub fadvise_flags: u32,
    /// TransactionData bytes 8..20 (hint fields), kept for byte-exact re-encode.
    pub td_hints: [u8; 12],
    /// v10 `data_features` (0 for v9).
    pub data_features: u64,
    /// Wire struct_v this was decoded from (9 or 10); informational.
    pub struct_v: u8,
    /// Side-stream bytes left unconsumed by the ops (non-zero = sender oddity, lenient).
    pub trailing: usize,
}

fn bad(s: &'static str) -> Error {
    Error::BadValue(s)
}

/// Bytes of the write that go into the aligned stream: `(head_len, mid_len, tail_len)` for v10. A page size of 0 is
/// refused (no page grid).
pub fn split_write(off: u64, len: u64, page: usize) -> Result<(u64, u64, u64)> {
    if page == 0 {
        return Err(bad("page size"));
    }
    let p = page as u64;
    let a = (p - off % p) % p;
    if len >= p + a {
        let m = (len - a) / p * p;
        Ok((a, m, len - a - m))
    } else {
        Ok((len, 0, 0))
    }
}

struct Rec<'r>(&'r [u8]);
impl Rec<'_> {
    fn u32(&self, o: usize) -> u32 {
        le::rd_u32(self.0, o)
    }
    fn u64(&self, o: usize) -> u64 {
        le::rd_u64(self.0, o)
    }
    fn code(&self) -> u32 {
        self.u32(0)
    }
    fn cid(&self) -> u32 {
        self.u32(4)
    }
    fn oid(&self) -> u32 {
        self.u32(8)
    }
    fn off(&self) -> u64 {
        self.u64(12)
    }
    fn len(&self) -> u64 {
        self.u64(20)
    }
    fn dest_cid(&self) -> u32 {
        self.u32(28)
    }
    fn dest_oid(&self) -> u32 {
        self.u32(32)
    }
    fn dest_off(&self) -> u64 {
        self.u64(36)
    }
    fn hint(&self) -> u32 {
        self.u32(44)
    }
    fn eos(&self) -> u64 {
        self.u64(48)
    }
    fn ews(&self) -> u64 {
        self.u64(56)
    }
    fn bits(&self) -> u32 {
        self.u32(64)
    }
    fn rem(&self) -> u32 {
        self.u32(68)
    }
}

fn index_table<'a, K: denc::Decode<'a>>(d: &mut Decoder<'a>) -> Result<Vec<K>> {
    let n = d.count()?;
    // every entry is at least its u32 index plus one byte: a larger count is malformed (no allocation from it)
    if n > d.remaining() / 5 {
        return Err(bad("txn index table count exceeds its bytes"));
    }
    // in index order (one entry: always): straight into the table, no slot vector
    let mut v: Vec<K> = Vec::with_capacity(n.min(1024));
    while v.len() < n {
        let k = K::decode(d)?;
        let i = d.u32()? as usize;
        if i != v.len() {
            return index_table_unordered(d, n, v, k, i);
        }
        v.push(k);
    }
    Ok(v)
}

/// [`index_table`] once an entry came out of index order: `(k, i)` is that entry, `head` holds the earlier ones (indices
/// `0..head.len()`). The pairs grow only with decoded entries (never sized from the wire count), then sort by index.
fn index_table_unordered<'a, K: denc::Decode<'a>>(
    d: &mut Decoder<'a>,
    n: usize,
    head: Vec<K>,
    k: K,
    i: usize,
) -> Result<Vec<K>> {
    let mut pairs: Vec<(usize, K)> = head.into_iter().enumerate().collect();
    pairs.push((i, k));
    while pairs.len() < n {
        let k = K::decode(d)?;
        pairs.push((d.u32()? as usize, k));
    }
    pairs.sort_unstable_by_key(|(i, _)| *i);
    for (want, (i, _)) in pairs.iter().enumerate() {
        if *i >= n {
            return Err(bad("txn index out of range"));
        }
        if *i != want {
            return Err(bad("txn duplicate index"));
        }
    }
    Ok(pairs.into_iter().map(|(_, k)| k).collect())
}

/// Index of `k` in `v`, appending a clone on first use.
fn intern<K: Clone + PartialEq>(v: &mut Vec<K>, k: &K) -> u32 {
    let i = v.iter().position(|x| x == k).unwrap_or_else(|| {
        v.push(k.clone());
        v.len() - 1
    });
    i as u32
}

/// `count` + `(key, index)` pairs sorted by key (the index table wire form).
fn put_table<K: denc::Encode + Ord, B: denc::BufMut>(e: &mut Encoder<B>, keys: &[K]) -> Result<()> {
    let mut t: Vec<(&K, u32)> = keys.iter().zip(0u32..).collect();
    t.sort();
    e.count(t.len())?;
    for (k, i) in t {
        k.encode(e)?;
        e.u32(i)?;
    }
    Ok(())
}

impl<'a> Transaction<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Intern a collection (index = order of first use).
    pub fn coll(&mut self, c: &CollT) -> Cx {
        Cx(intern(&mut self.colls, c))
    }
    /// Intern an object (index = order of first use).
    pub fn obj(&mut self, o: &Ghobject) -> Ox {
        Ox(intern(&mut self.objs, o))
    }
    pub fn push(&mut self, cid: Cx, op: TxnOp<'a>) {
        self.ops.push(Op { cid, op });
    }
    pub fn get_coll(&self, c: Cx) -> &CollT {
        &self.colls[c.0 as usize]
    }
    pub fn get_obj(&self, o: Ox) -> &Ghobject {
        &self.objs[o.0 as usize]
    }
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Space a store needs to apply this txn, for a space preflight: `(payload bytes, tree entries set or removed)`.
    /// Bytes = written data plus copied ranges plus attr / omap values; entries = omap keys, xattrs, omap headers and
    /// clears (each may dirty a tree leaf of its own).
    pub fn room_cost(&self) -> (u64, u64) {
        use TxnOpG::*;
        self.ops.iter().fold((0u64, 0u64), |(b, e), o| {
            let (ob, oe) = match &o.op {
                Write { data, .. } => (data.len() as u64, 0),
                CloneRange2 { len, .. } => (*len, 0),
                SetAttr { value, .. } => (value.len() as u64, 1),
                SetAttrs { attrs, .. } => (
                    attrs.iter().map(|(_, v)| v.len() as u64).sum(),
                    attrs.len() as u64,
                ),
                OmapSetKeys { pairs, .. } => (
                    pairs.iter().map(|(_, v)| v.len() as u64).sum(),
                    pairs.len() as u64,
                ),
                OmapRmKeys { keys, .. } => (0, keys.len() as u64),
                OmapSetHeader { header, .. } => (header.len() as u64, 1),
                RmAttr { .. } | OmapClear { .. } | OmapRmKeyRange { .. } => (0, 1),
                _ => (0, 0),
            };
            (b.saturating_add(ob), e.saturating_add(oe))
        })
    }

    /// Upper bound of [`Self::room_cost`] from the wire segments and the op count alone (no decode), for a txn without
    /// clone ops ([`Self::expands_objects`] false: a clone range may copy more than the wire carries): every byte may be
    /// payload, every 8 bytes of the op stream an entry (a key or attr costs at least its two length words), plus one
    /// entry per op.
    pub fn room_bound(middle: &[u8], data: &[u8], nops: usize) -> (u64, u64) {
        let stream = if middle.is_empty() { data } else { middle };
        (
            (middle.len() + data.len()) as u64,
            (nops + stream.len() / 8) as u64,
        )
    }

    /// Op records only (no object table, no allocation): the op count. An op code `decode` does not know is refused here
    /// too; everything else is checked by the full decode of the store apply.
    pub fn peek(middle: &[u8], data: &[u8]) -> Result<usize> {
        use opc::*;
        let p = if middle.is_empty() { data } else { middle };
        Decoder::new(p).versioned_min(9, 10, |d, v| {
            if v == 9 {
                d.bytes()?;
            }
            let ops = d.bytes()?;
            if ops.len() % OP_SIZE != 0 {
                return Err(bad("txn op_bl size"));
            }
            for b in ops.as_chunks::<OP_SIZE>().0 {
                match Rec(b).code() {
                    NOP | CREATE | TOUCH | TOUCH_TEMP | WRITE | ZERO | TRUNCATE | REMOVE
                    | SETATTR | SETATTRS | RMATTR | RMATTRS | CLONE | CLONERANGE2 | MKCOLL
                    | RMCOLL | COLL_HINT | COLL_MOVE_RENAME | TRY_RENAME | OMAP_CLEAR
                    | OMAP_SETKEYS | OMAP_RMKEYS | OMAP_RMKEYRANGE | OMAP_SETHEADER
                    | SETALLOCHINT | SPLIT_COLLECTION2 | MERGE_COLLECTION | COLL_SET_BITS => {}
                    _ => return Err(bad("unsupported txn op code")),
                }
            }
            Ok(ops.len() / OP_SIZE)
        })
    }

    /// Inspect fixed operation records without decoding objects or copying write payloads.
    /// Clones can expand tiny wire transactions into arbitrary source-dependent store work.
    pub fn expands_objects(middle: &[u8], data: &[u8]) -> Result<bool> {
        let p = if middle.is_empty() { data } else { middle };
        Decoder::new(p).versioned_min(9, 10, |d, v| {
            if v == 9 {
                d.bytes()?;
            }
            let ops = d.bytes()?;
            if ops.len() % OP_SIZE != 0 {
                return Err(bad("txn op_bl size"));
            }
            Ok(ops
                .as_chunks::<OP_SIZE>()
                .0
                .iter()
                .any(|b| matches!(Rec(b).code(), opc::CLONE | opc::CLONERANGE2)))
        })
    }

    /// Decode from the MOSDRepOp segments: p part = `middle` if non-empty else `data`; the d part
    /// (v10 aligned/misaligned streams) is `data`, or the bytes behind the p envelope when `middle` is empty (spec
    /// 1.1). `page` = sender page size (4096).
    pub fn decode(middle: &'a [u8], data: &'a [u8], page: usize) -> Result<Self> {
        let p_in_d = middle.is_empty();
        let p = if p_in_d { data } else { middle };
        Self::decode_inner(p, data, p_in_d, page, None)
    }

    /// Decode with explicit p / d buffers (two separate parts).
    pub fn decode_pd(p: &'a [u8], d: &'a [u8], page: usize) -> Result<Self> {
        Self::decode_inner(p, d, false, page, None)
    }

    /// Decode a LOCAL skeleton made by [`Transaction::encode_v9_split`]; `refs` are the out-of-line write payloads and
    /// omap run entries in op order (borrowed, no copy). Every ref must be used exactly once. An omap run ref is the
    /// entries of a strictly ascending map encoding (without its count) and is trusted, not walked (see `Kv::from_entries`).
    pub fn decode_split(skel: &'a [u8], refs: &'a [bytes::Bytes], page: usize) -> Result<Self> {
        Self::decode_inner(skel, &[], false, page, Some(refs))
    }

    fn decode_inner(
        p: &'a [u8],
        d: &'a [u8],
        p_in_d: bool,
        page: usize,
        refs: Option<&'a [bytes::Bytes]>,
    ) -> Result<Self> {
        let mut s = OpStream::open(p, d, p_in_d, page, refs)?;
        let mut ops = Vec::with_capacity(s.ops_left());
        while let Some((cid, op)) = s.next_op()? {
            ops.push(Op {
                cid,
                op: op.into_vecs(),
            });
        }
        let trailing = s.finish()?;
        Ok(Transaction {
            colls: s.colls,
            objs: s.objs,
            ops,
            fadvise_flags: s.fadvise_flags,
            td_hints: s.td_hints,
            data_features: s.data_features,
            struct_v: s.struct_v,
            trailing,
        })
    }

    // ---- encode ----

    fn put_rec(&self, op: &Op<'_>) -> [u8; OP_SIZE] {
        use TxnOpG::*;
        let mut r = [0u8; OP_SIZE];
        let p32 = |r: &mut [u8; OP_SIZE], o: usize, v: u32| le::wr_u32(r, o, v);
        let p64 = |r: &mut [u8; OP_SIZE], o: usize, v: u64| le::wr_u64(r, o, v);
        p32(&mut r, 0, op.op.code());
        if !matches!(op.op, Nop) {
            p32(&mut r, 4, op.cid.0);
        }
        match &op.op {
            Nop | RmColl => {}
            Create { oid }
            | Touch { oid }
            | Remove { oid }
            | RmAttrs { oid }
            | OmapClear { oid } => p32(&mut r, 8, oid.0),
            SetAttr { oid, .. }
            | SetAttrs { oid, .. }
            | RmAttr { oid, .. }
            | OmapSetKeys { oid, .. }
            | OmapRmKeys { oid, .. }
            | OmapRmKeyRange { oid, .. }
            | OmapSetHeader { oid, .. } => p32(&mut r, 8, oid.0),
            TouchTemp { oid, dest_oid } | Clone { oid, dest_oid } | TryRename { oid, dest_oid } => {
                p32(&mut r, 8, oid.0);
                p32(&mut r, 32, dest_oid.0);
            }
            Write { oid, off, data } => {
                p32(&mut r, 8, oid.0);
                p64(&mut r, 12, *off);
                p64(&mut r, 20, data.len() as u64);
            }
            Zero { oid, off, len } => {
                p32(&mut r, 8, oid.0);
                p64(&mut r, 12, *off);
                p64(&mut r, 20, *len);
            }
            Truncate { oid, size } => {
                p32(&mut r, 8, oid.0);
                p64(&mut r, 12, *size);
            }
            CloneRange2 {
                oid,
                dest_oid,
                src_off,
                len,
                dest_off,
            } => {
                p32(&mut r, 8, oid.0);
                p64(&mut r, 12, *src_off);
                p64(&mut r, 20, *len);
                p32(&mut r, 32, dest_oid.0);
                p64(&mut r, 36, *dest_off);
            }
            MkColl { bits } | CollSetBits { bits } => p32(&mut r, 64, *bits),
            CollHint { ty, .. } => p32(&mut r, 44, *ty),
            CollMoveRename {
                oid,
                dest_cid,
                dest_oid,
            } => {
                p32(&mut r, 8, oid.0);
                p32(&mut r, 28, dest_cid.0);
                p32(&mut r, 32, dest_oid.0);
            }
            SetAllocHint {
                oid,
                expected_object_size,
                expected_write_size,
                flags,
            } => {
                p32(&mut r, 8, oid.0);
                p32(&mut r, 44, *flags);
                p64(&mut r, 48, *expected_object_size);
                p64(&mut r, 56, *expected_write_size);
            }
            SplitCollection2 {
                dest_cid,
                bits,
                rem,
            } => {
                p32(&mut r, 28, dest_cid.0);
                p32(&mut r, 64, *bits);
                p32(&mut r, 68, *rem);
            }
            MergeCollection { dest_cid, bits } => {
                p32(&mut r, 28, dest_cid.0);
                p32(&mut r, 64, *bits);
            }
        }
        r
    }

    /// Build `(op_bl, misaligned_stream, aligned_stream)`. v9 puts everything in the misaligned
    /// (inline) stream with u32-prefixed write payloads.
    fn build_streams(&self, split: bool, page: usize) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let (mut mis, mut ali) = (Vec::new(), Vec::new());
        let opbl = self.build_streams_into(split, page, &mut mis, &mut ali, None, None, None)?;
        Ok((opbl, mis, ali))
    }

    /// Like [`build_streams`](Self::build_streams) but appends the misaligned / aligned streams to the given buffers
    /// (the v9 encoder writes the misaligned stream straight into the output, one copy of the payload).
    #[expect(clippy::too_many_arguments)]
    fn build_streams_into(
        &self,
        split: bool,
        page: usize,
        mis: &mut Vec<u8>,
        ali: &mut Vec<u8>,
        out_of_line: Option<&dyn Fn(usize) -> bool>,
        mut marks: Option<&mut Vec<(usize, usize, u32)>>,
        mut rope: Option<&mut Vec<(usize, usize)>>,
    ) -> Result<Vec<u8>> {
        use TxnOpG::*;
        let mut opbl = Vec::with_capacity(self.ops.len() * OP_SIZE);
        fn count(o: &mut Vec<u8>, n: usize) -> Result<()> {
            Encoder::from_buf(o).count(n)
        }
        fn bytes(o: &mut Vec<u8>, b: &[u8]) -> Result<()> {
            Encoder::from_buf(&mut *o).bytes(b)
        }
        for (oi, op) in self.ops.iter().enumerate() {
            opbl.extend_from_slice(&self.put_rec(op));
            match &op.op {
                Write { off, data, .. } => {
                    if out_of_line.is_some_and(|f| f(oi)) {
                        // local skeleton (`encode_v9_split`): the payload travels out of line
                        if split || !data.mid.is_empty() || !data.tail.is_empty() {
                            return Err(bad("out-of-line write must be a plain v9 payload"));
                        }
                        if let Some(r) = rope.as_deref_mut() {
                            // wire rope (`encode_v9_rope`): real length, the caller splices the payload here
                            count(mis, data.len())?;
                            r.push((mis.len(), oi));
                        } else {
                            mis.extend_from_slice(&REF_MARK.to_le_bytes());
                        }
                    } else if !split {
                        count(mis, data.len())?;
                        if let Some(m) = marks.as_deref_mut() {
                            // copy fused with the crc of the payload (seed 0, joined by `crc32c_combine`)
                            for p in data.parts() {
                                let at = mis.len();
                                m.push((at, p.len(), crc::crc32c_extend(0, p, mis)));
                            }
                        } else {
                            data.copy_range(0, data.len(), mis);
                        }
                    } else {
                        let (h, m, t) = split_write(*off, data.len() as u64, page)?;
                        let (h, m, t) = (h as usize, m as usize, t as usize);
                        data.copy_range(0, h, mis);
                        data.copy_range(h, h + m, ali);
                        data.copy_range(h + m, h + m + t, mis);
                    }
                }
                SetAttr { name, value, .. } => {
                    bytes(mis, name)?;
                    bytes(mis, value)?;
                }
                SetAttrs { attrs: kv, .. }
                | OmapSetKeys {
                    pairs: OmapKv::Pairs(kv),
                    ..
                } => {
                    count(mis, kv.len())?;
                    for (k, v) in kv {
                        bytes(mis, k)?;
                        bytes(mis, v)?;
                    }
                }
                OmapSetKeys {
                    pairs: OmapKv::Run(r),
                    ..
                } => {
                    if out_of_line.is_some_and(|f| f(oi)) {
                        if split {
                            return Err(bad("out-of-line omap run must be a v9 payload"));
                        }
                        if let Some(sp) = rope.as_deref_mut() {
                            // wire rope: the real count, the caller splices the entries here
                            count(mis, r.len())?;
                            sp.push((mis.len(), oi));
                        } else {
                            // local skeleton: marker + count, the entries travel out of line
                            mis.extend_from_slice(&REF_MARK.to_le_bytes());
                            count(mis, r.len())?;
                        }
                    } else {
                        count(mis, r.len())?;
                        mis.extend_from_slice(r.entries());
                    }
                }
                RmAttr { name, .. } => bytes(mis, name)?,
                CollHint { data, .. } => bytes(mis, data)?,
                OmapRmKeys { keys, .. } => {
                    count(mis, keys.len())?;
                    for k in keys {
                        bytes(mis, k)?;
                    }
                }
                OmapRmKeyRange { first, last, .. } => {
                    bytes(mis, first)?;
                    bytes(mis, last)?;
                }
                OmapSetHeader { header, .. } => bytes(mis, header)?,
                _ => {}
            }
        }
        Ok(opbl)
    }

    /// Offset of the first write payload byte in the misaligned stream as [`encode_v9`](Self::encode_v9) and an
    /// unsplit [`encode_v10`](Self::encode_v10) (`data_features` without TENTACLE) lay it out: the v9 blob holds it at
    /// `10 + at` (envelope + stream length), the v10 data part at `at`. `None`: no write with payload. A sender states
    /// it in the msgr2 header `data_off` so a placing receiver gets the payload 4 KiB aligned (spec msgr2.md 3.1).
    /// Walks only the ops before that write, no bytes.
    pub fn payload_at(&self) -> Option<usize> {
        self.first_payload().map(|(at, _)| at)
    }

    /// Bytes `op` takes in the misaligned stream; `None` for the ops whose size depends on their payload placement
    /// (a write: [`first_payload`](Self::first_payload), [`payload_hint`](Self::payload_hint)).
    fn stream_len(op: &TxnOp<'_>) -> Option<usize> {
        use TxnOpG::*;
        Some(match op {
            SetAttr { name, value, .. } => 8 + name.len() + value.len(),
            SetAttrs { attrs: kv, .. }
            | OmapSetKeys {
                pairs: OmapKv::Pairs(kv),
                ..
            } => 4 + kv.iter().map(|(k, v)| 8 + k.len() + v.len()).sum::<usize>(),
            OmapSetKeys {
                pairs: OmapKv::Run(r),
                ..
            } => 4 + r.entries().len(),
            OmapRmKeys { keys, .. } => 4 + keys.iter().map(|k| 4 + k.len()).sum::<usize>(),
            OmapRmKeyRange { first, last, .. } => 8 + first.len() + last.len(),
            OmapSetHeader { header, .. } => 4 + header.len(),
            _ => return None,
        })
    }

    /// `(offset in the misaligned stream, length)` of the first write payload ([`payload_at`](Self::payload_at)).
    fn first_payload(&self) -> Option<(usize, usize)> {
        use TxnOpG::*;
        let mut at = 0usize;
        for op in &self.ops {
            at += match &op.op {
                Write { data, .. } if !data.is_empty() => return Some((at + 4, data.len())),
                Write { .. } => 4,
                RmAttr { name, .. } => 4 + name.len(),
                CollHint { data, .. } => 4 + data.len(),
                op => Self::stream_len(op).unwrap_or(0),
            };
        }
        None
    }

    /// Variable payload bytes of the ops (capacity hint: an op without a size rule counts 64).
    fn payload_hint(&self, ool: Option<&dyn Fn(usize) -> bool>) -> usize {
        use TxnOpG::*;
        self.ops
            .iter()
            .enumerate()
            .map(|(i, op)| match &op.op {
                Write { .. } if ool.is_some_and(|f| f(i)) => 4,
                Write { data, .. } => data.len() + 4,
                OmapSetKeys {
                    pairs: OmapKv::Run(_),
                    ..
                } if ool.is_some_and(|f| f(i)) => 8,
                op => Self::stream_len(op).unwrap_or(64),
            })
            .sum()
    }

    fn put_tables(&self, e: &mut Encoder<Vec<u8>>) -> Result<()> {
        put_table(e, &self.colls)?;
        put_table(e, &self.objs)?;
        e.u64(self.ops.len() as u64)?;
        e.raw(&self.td_hints)?;
        e.u32(self.fadvise_flags)
    }

    /// Encode as v9 (one contiguous buffer; valid for every peer). Goes into the DATA segment.
    pub fn encode_v9(&self) -> Result<Vec<u8>> {
        self.encode_v9_marks(None, None)
    }

    /// LOCAL skeleton form (never sent to a peer): like v9, but every write op `i` for which `out_of_line(i)` is true
    /// (a plain head-only write) has its payload left out of the inline stream (marker length `u32::MAX`, no bytes);
    /// the caller keeps those payloads, in op order, and hands both to [`Transaction::decode_split`]. Saves the
    /// multi-MiB payload copy of the contiguous form while no peer needs the blob; `decode_split` + `encode_v9` makes
    /// the real v9 blob when one does.
    pub fn encode_v9_split(&self, out_of_line: &dyn Fn(usize) -> bool) -> Result<Vec<u8>> {
        self.encode_v9_marks(Some(out_of_line), None)
    }

    /// [`encode_v9`](Self::encode_v9) plus `crc32c(!0, blob)` (the msgr2 data-segment crc), computed while the payloads are
    /// copied into the blob (fused copy+crc, joined with the crc of the small remainder by `crc32c_combine`): no second
    /// pass over the multi-MiB blob.
    pub fn encode_v9_crc(&self) -> Result<(Vec<u8>, u32)> {
        let mut marks = Vec::new();
        let blob = self.encode_v9_marks(None, Some(&mut marks))?;
        let (mut r, mut pos) = (!0u32, 0usize);
        for (at, len, c0) in marks {
            r = crc::crc32c(r, &blob[pos..at]);
            r = crc::crc32c_combine(r, c0, len as u64);
            pos = at + len;
        }
        let r = crc::crc32c(r, &blob[pos..]);
        Ok((blob, r))
    }

    /// Wire v9 as a rope (msgr2 zero-copy): `(inline, runs)` = the [`encode_v9`](Self::encode_v9) blob with every plain
    /// write payload of at least [`SPLIT_MIN`] bytes that lies inside one of `owners` left out of `inline` and listed as
    /// `(offset in inline, shared slice of its owner)` (ascending), see `denc::Encoder::into_rope`. Flattened it is
    /// byte-identical to `encode_v9`.
    #[expect(clippy::type_complexity)]
    pub fn encode_v9_rope(
        &self,
        owners: &[bytes::Bytes],
    ) -> Result<(Vec<u8>, Vec<(usize, bytes::Bytes)>)> {
        let ool = |oi: usize| self.owned_run(oi, owners).is_some();
        let run = |oi: usize| self.owned_run(oi, owners).unwrap_or_default();
        Ok(self
            .encode_v9_enc(Some(&ool), None, Some(&run))?
            .into_rope())
    }

    /// LOCAL skeleton ([`encode_v9_split`](Self::encode_v9_split)) of the same payloads [`encode_v9_rope`](Self::encode_v9_rope)
    /// shares: `(skeleton, out-of-line payloads in op order)` for [`Transaction::decode_split`] / a local apply.
    /// Without out-of-line payloads the skeleton is the plain blob in [`encode_v9_placed`](Self::encode_v9_placed) form.
    pub fn encode_v9_local(
        &self,
        owners: &[bytes::Bytes],
    ) -> Result<(bytes::Bytes, Vec<bytes::Bytes>)> {
        let refs: Vec<bytes::Bytes> = (0..self.ops.len())
            .filter_map(|oi| self.owned_run(oi, owners))
            .collect();
        if refs.is_empty() {
            return Ok((self.encode_v9_placed()?, refs));
        }
        let ool = |oi: usize| self.owned_run(oi, owners).is_some();
        Ok((self.encode_v9_split(&ool)?.into(), refs))
    }

    /// Op `oi` as a shared slice of one of `owners`: a plain write payload or an omap set-keys run (its entries) of at
    /// least [`SPLIT_MIN`] bytes inside one.
    fn owned_run(&self, oi: usize, owners: &[bytes::Bytes]) -> Option<bytes::Bytes> {
        match &self.ops.get(oi)?.op {
            TxnOp::OmapSetKeys {
                pairs: OmapKv::Run(r),
                ..
            } if r.entries().len() >= SPLIT_MIN => {
                let o = owners.iter().find(|o| contains(o, r.entries()))?;
                Some(o.slice_ref(r.entries()))
            }
            TxnOp::Write { data, .. }
                if data.mid.is_empty() && data.tail.is_empty() && data.len() >= SPLIT_MIN =>
            {
                let o = owners.iter().find(|o| contains(o, data.head))?;
                Some(o.slice_ref(data.head))
            }
            _ => None,
        }
    }

    fn encode_v9_marks(
        &self,
        ool: Option<&dyn Fn(usize) -> bool>,
        marks: Option<&mut Vec<(usize, usize, u32)>>,
    ) -> Result<Vec<u8>> {
        self.encode_v9_enc(ool, marks, None).map(Encoder::into_vec)
    }

    /// Encoder holding the whole v9 blob. `rope`: the out-of-line writes (`ool`) keep their real length prefix and
    /// their payload `rope(op index)` is spliced (`denc::Encoder::splice_at`) instead of copied or marked.
    fn encode_v9_enc(
        &self,
        ool: Option<&dyn Fn(usize) -> bool>,
        marks: Option<&mut Vec<(usize, usize, u32)>>,
        rope: Option<&dyn Fn(usize) -> bytes::Bytes>,
    ) -> Result<Encoder<Vec<u8>>> {
        self.encode_v9_into(
            Encoder::with_capacity(self.v9_capacity(ool)),
            ool,
            marks,
            rope,
        )
    }

    /// Exact-ish capacity of a v9 blob: a growth realloc would memcpy the whole (multi-MiB) data stream again.
    fn v9_capacity(&self, ool: Option<&dyn Fn(usize) -> bool>) -> usize {
        self.payload_hint(ool)
            + 64 * (self.colls.len() + self.objs.len() + 2 * self.ops.len())
            + 256
    }

    /// [`encode_v9`](Self::encode_v9) as shared bytes whose first write payload, when it holds at least one whole
    /// [`PLACE_ALIGN`] block, starts on a [`PLACE_ALIGN`] boundary in memory: the local apply then writes it to the
    /// device by reference (kernel views need aligned memory, spec msgr2.md 3.1) instead of copying it. The blob lies
    /// `pad` (< [`PLACE_ALIGN`]) bytes into its allocation (zeroed, never part of the bytes); same bytes as `encode_v9`,
    /// no extra pass over the payload (unless the capacity estimate missed and the buffer had to be re-placed).
    pub fn encode_v9_placed(&self) -> Result<bytes::Bytes> {
        let Some((at, len)) = self.first_payload() else {
            return self.encode_v9().map(Into::into);
        };
        if len < PLACE_ALIGN {
            return self.encode_v9().map(Into::into);
        }
        let mut v = Vec::with_capacity(self.v9_capacity(None) + PLACE_ALIGN);
        let off = V9_STREAM_AT + at;
        let mut pad = (PLACE_ALIGN - (v.as_ptr() as usize + off) % PLACE_ALIGN) % PLACE_ALIGN;
        v.resize(pad, 0);
        let mut blob = self
            .encode_v9_into(Encoder::from_buf(v), None, None, None)?
            .into_vec();
        // `v9_capacity` is an estimate (index-table keys vary in size): a growth realloc during the encode moves the
        // buffer and voids the alignment computed above. Re-place the bytes then (one pointer test, no payload pass).
        if !(blob.as_ptr() as usize + pad + off).is_multiple_of(PLACE_ALIGN) {
            let body = &blob[pad..];
            let mut w = Vec::with_capacity(body.len() + PLACE_ALIGN);
            pad = (PLACE_ALIGN - (w.as_ptr() as usize + off) % PLACE_ALIGN) % PLACE_ALIGN;
            w.resize(pad, 0);
            w.extend_from_slice(body);
            blob = w;
        }
        Ok(bytes::Bytes::from(blob).slice(pad..))
    }

    fn encode_v9_into(
        &self,
        mut e: Encoder<Vec<u8>>,
        ool: Option<&dyn Fn(usize) -> bool>,
        marks: Option<&mut Vec<(usize, usize, u32)>>,
        rope: Option<&dyn Fn(usize) -> bytes::Bytes>,
    ) -> Result<Encoder<Vec<u8>>> {
        e.versioned(9, 9, |e| {
            // the misaligned stream (write payloads inline) is built in place behind its length prefix
            let at = e.len();
            e.u32(0)?;
            let mut spl = Vec::new();
            let opbl = self.build_streams_into(
                false,
                DEFAULT_PAGE,
                e.buf_mut(),
                &mut Vec::new(),
                ool,
                marks,
                rope.is_some().then_some(&mut spl),
            )?;
            let mut spliced = 0;
            if let Some(f) = rope {
                // registered while the envelope is open: its length counts the runs
                for (pos, oi) in spl {
                    let r = f(oi);
                    spliced += r.len();
                    e.splice_at(pos, r);
                }
            }
            let n = u32::try_from(e.len() - at - 4 + spliced).map_err(|_| bad("txn too long"))?;
            denc::BufMut::patch(e.buf_mut(), at, &n.to_le_bytes());
            e.bytes(&opbl)?;
            self.put_tables(e)
        })?;
        Ok(e)
    }

    /// Encode as v10: returns `(p, d)`. Send `p` in MIDDLE and `d` in DATA, or `p` in DATA if `d` is empty.
    pub fn encode_v10(&self, page: usize) -> Result<(Vec<u8>, Vec<u8>)> {
        if page == 0 {
            return Err(bad("page size"));
        }
        let (opbl, mis, mut ali) =
            self.build_streams(denc::features::have(self.data_features, TENTACLE_BIT), page)?;
        let mut e = Encoder::new();
        e.versioned(10, 10, |e| {
            e.bytes(&opbl)?;
            self.put_tables(e)?;
            e.u64(self.data_features)?;
            e.count(ali.len())?;
            e.count(mis.len())
        })?;
        ali.extend_from_slice(&mis);
        Ok((e.into_vec(), ali))
    }
}

/// `s` lies inside `o` (then `o.slice_ref(s)` is valid).
fn contains(o: &bytes::Bytes, s: &[u8]) -> bool {
    let (a, b) = (o.as_ptr() as usize, s.as_ptr() as usize);
    b >= a && b + s.len() <= a + o.len()
}

// ---- streaming decode (adr 0160 D3) ----

/// [`TxnOp`] with the key-value / key lists left as validated wire slices (no `Vec` per op).
pub type LazyOp<'a> = TxnOpG<'a, Kv<'a>, Ks<'a>, Kv<'a>>;

/// `count` + `(key, value)` byte strings, validated at decode; iterate with [`Kv::iter`].
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Kv<'a> {
    n: usize,
    raw: &'a [u8],
    /// Set when decoding already found the keys strictly ascending (an out-of-line run): [`Kv::omap`] needs no second pass.
    run: Option<denc::SortedKv<'a>>,
}
/// `count` + key byte strings, validated at decode; iterate with [`Ks::iter`].
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Ks<'a> {
    n: usize,
    raw: &'a [u8],
}

/// Consume `count` + `n * per` byte strings from `d`; `(n, the strings' bytes)`.
fn take_strs<'a>(d: &mut Decoder<'a>, per: usize) -> Result<(usize, &'a [u8])> {
    let n = d.count()?;
    let rest = d.peek_rest();
    for _ in 0..n * per {
        d.bytes()?;
    }
    Ok((n, &rest[..rest.len() - d.remaining()]))
}

/// Next length-prefixed string of a validated slice.
fn next_str<'a>(raw: &mut &'a [u8]) -> &'a [u8] {
    let n = le::rd_u32(raw, 0) as usize;
    let s = &raw[4..4 + n];
    *raw = &raw[4 + n..];
    s
}

impl<'a> Kv<'a> {
    fn take(d: &mut Decoder<'a>) -> Result<Self> {
        let (n, raw) = take_strs(d, 2)?;
        Ok(Kv { n, raw, run: None })
    }
    /// `n` entries held out of line as exactly their encoded bytes (without the count). Trusted, not walked: only
    /// the local skeleton form carries these, built from a `denc::SortedKv` the executor validated once when it
    /// parsed the client op (a second pass over the payload would cost what the copy it replaces cost). Wrong bytes
    /// make iteration panic, never read out of bounds.
    fn from_entries(n: usize, ents: &'a [u8]) -> Self {
        Kv {
            n,
            raw: ents,
            run: Some(denc::SortedKv::trusted(n, ents)),
        }
    }
    pub fn len(&self) -> usize {
        self.n
    }
    pub fn is_empty(&self) -> bool {
        self.n == 0
    }
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&'a [u8], &'a [u8])> + use<'a> {
        let mut raw = self.raw;
        (0..self.n).map(move |_| {
            let k = next_str(&mut raw);
            (k, next_str(&mut raw))
        })
    }
    /// The [`OmapKv`] form: a strictly ascending list (every map a Ceph peer encodes) stays one block, any other
    /// becomes pairs.
    pub fn omap(&self) -> OmapKv<'a> {
        if let Some(r) = self.run {
            return OmapKv::Run(r);
        }
        match denc::SortedKv::check(self.n, self.raw) {
            Ok(denc::KvShape::Sorted(r)) => OmapKv::Run(r),
            _ => OmapKv::Pairs(self.iter().collect()),
        }
    }
}
impl<'a> Ks<'a> {
    fn take(d: &mut Decoder<'a>) -> Result<Self> {
        let (n, raw) = take_strs(d, 1)?;
        Ok(Ks { n, raw })
    }
    pub fn len(&self) -> usize {
        self.n
    }
    pub fn is_empty(&self) -> bool {
        self.n == 0
    }
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &'a [u8]> + use<'a> {
        let mut raw = self.raw;
        (0..self.n).map(move |_| next_str(&mut raw))
    }
}
impl fmt::Debug for Kv<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}
impl fmt::Debug for Ks<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<'a> LazyOp<'a> {
    /// The [`TxnOp`] form (lists collected).
    pub fn into_vecs(self) -> TxnOp<'a> {
        use TxnOpG::*;
        match self {
            Nop => Nop,
            Create { oid } => Create { oid },
            Touch { oid } => Touch { oid },
            TouchTemp { oid, dest_oid } => TouchTemp { oid, dest_oid },
            Write { oid, off, data } => Write { oid, off, data },
            Zero { oid, off, len } => Zero { oid, off, len },
            Truncate { oid, size } => Truncate { oid, size },
            Remove { oid } => Remove { oid },
            SetAttr { oid, name, value } => SetAttr { oid, name, value },
            SetAttrs { oid, attrs } => SetAttrs {
                oid,
                attrs: attrs.iter().collect(),
            },
            RmAttr { oid, name } => RmAttr { oid, name },
            RmAttrs { oid } => RmAttrs { oid },
            Clone { oid, dest_oid } => Clone { oid, dest_oid },
            CloneRange2 {
                oid,
                dest_oid,
                src_off,
                len,
                dest_off,
            } => CloneRange2 {
                oid,
                dest_oid,
                src_off,
                len,
                dest_off,
            },
            MkColl { bits } => MkColl { bits },
            RmColl => RmColl,
            CollHint { ty, data } => CollHint { ty, data },
            CollMoveRename {
                oid,
                dest_cid,
                dest_oid,
            } => CollMoveRename {
                oid,
                dest_cid,
                dest_oid,
            },
            TryRename { oid, dest_oid } => TryRename { oid, dest_oid },
            OmapClear { oid } => OmapClear { oid },
            OmapSetKeys { oid, pairs } => OmapSetKeys {
                oid,
                pairs: pairs.omap(),
            },
            OmapRmKeys { oid, keys } => OmapRmKeys {
                oid,
                keys: keys.iter().collect(),
            },
            OmapRmKeyRange { oid, first, last } => OmapRmKeyRange { oid, first, last },
            OmapSetHeader { oid, header } => OmapSetHeader { oid, header },
            SetAllocHint {
                oid,
                expected_object_size,
                expected_write_size,
                flags,
            } => SetAllocHint {
                oid,
                expected_object_size,
                expected_write_size,
                flags,
            },
            SplitCollection2 {
                dest_cid,
                bits,
                rem,
            } => SplitCollection2 {
                dest_cid,
                bits,
                rem,
            },
            MergeCollection { dest_cid, bits } => MergeCollection { dest_cid, bits },
            CollSetBits { bits } => CollSetBits { bits },
        }
    }
}

fn idx_ok(n: usize, i: u32, what: &'static str) -> Result<u32> {
    if (i as usize) < n {
        Ok(i)
    } else {
        Err(bad(what))
    }
}

/// One pass over a wire (or local skeleton) transaction: header and tables at [`OpStream::open`], then the ops one by
/// one ([`OpStream::next_op`]) with the same checks as [`Transaction::decode`] (which is built on it), without an op
/// vector or per-op list allocations. The object table is public so a consumer may move objects out of it.
pub struct OpStream<'a> {
    pub colls: Vec<CollT>,
    pub objs: Vec<Ghobject>,
    pub fadvise_flags: u32,
    pub td_hints: [u8; 12],
    pub data_features: u64,
    pub struct_v: u8,
    recs: &'a [[u8; OP_SIZE]],
    mis: Decoder<'a>,
    ali: Decoder<'a>,
    /// v10 `d` bytes past `len_aligned + len_misaligned` (a sender oddity, reported by [`OpStream::finish`]).
    extra: usize,
    split: bool,
    page: usize,
    refs: Option<core::slice::Iter<'a, bytes::Bytes>>,
}

impl fmt::Debug for OpStream<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpStream")
            .field("colls", &self.colls)
            .field("objs", &self.objs)
            .field("ops_left", &self.recs.len())
            .finish_non_exhaustive()
    }
}

impl<'a> OpStream<'a> {
    /// Wire form: p part = `middle` if non-empty else `data`, d part = `data` (like [`Transaction::decode`]).
    pub fn new(middle: &'a [u8], data: &'a [u8], page: usize) -> Result<Self> {
        let p = if middle.is_empty() { data } else { middle };
        Self::open(p, data, middle.is_empty(), page, None)
    }

    /// Local skeleton form (like [`Transaction::decode_split`]).
    pub fn new_split(skel: &'a [u8], refs: &'a [bytes::Bytes], page: usize) -> Result<Self> {
        Self::open(skel, &[], false, page, Some(refs))
    }

    /// `p_in_d` = the p part is the head of `d` (a v10 transaction whose d part is empty travels as p in DATA): its d
    /// part, if a sender appended one, starts behind the p envelope (spec 1.1).
    fn open(
        p: &'a [u8],
        d: &'a [u8],
        p_in_d: bool,
        page: usize,
        refs: Option<&'a [bytes::Bytes]>,
    ) -> Result<Self> {
        if page == 0 {
            return Err(bad("page size"));
        }
        let d_off = if p_in_d {
            let mut h = Decoder::new(p);
            h.envelope_raw()?;
            h.position()
        } else {
            0
        };
        let mut dec = Decoder::new(p);
        dec.versioned_min(9, 10, |dec, v| {
            let mis_inline = if v == 9 { Some(dec.bytes()?) } else { None };
            let op_bl = dec.bytes()?;
            let colls: Vec<CollT> = index_table(dec)?;
            let objs: Vec<Ghobject> = index_table(dec)?;
            let nops = dec.u64()?;
            let td_hints: [u8; 12] = dec.array()?;
            let fadvise_flags = dec.u32()?;
            let (data_features, ali, mis, split, extra);
            if v == 9 {
                data_features = 0;
                split = false;
                ali = Decoder::new(&[]);
                mis = Decoder::new(mis_inline.unwrap_or(&[]));
                // the v9 stream is inline; bytes behind the p envelope (p in DATA) are trailing
                extra = if p_in_d { d.len() - d_off } else { 0 };
            } else {
                data_features = dec.u64()?;
                let la = dec.u32()? as usize;
                split = denc::features::have(data_features, TENTACLE_BIT) || la > 0;
                let lm = dec.u32()? as usize;
                let tot = d_off
                    .checked_add(la)
                    .and_then(|t| t.checked_add(lm))
                    .ok_or(bad("txn d lens"))?;
                if tot > d.len() {
                    return Err(Error::BadLength {
                        len: tot as u64,
                        remaining: d.len(),
                    });
                }
                ali = Decoder::new(&d[d_off..d_off + la]);
                mis = Decoder::new(&d[d_off + la..tot]);
                extra = d.len() - tot;
            }
            if op_bl.len() % OP_SIZE != 0 || (op_bl.len() / OP_SIZE) as u64 != nops {
                return Err(bad("txn op_bl size"));
            }
            Ok(OpStream {
                colls,
                objs,
                fadvise_flags,
                td_hints,
                data_features,
                struct_v: v,
                recs: op_bl.as_chunks::<OP_SIZE>().0,
                mis,
                ali,
                extra,
                split,
                page,
                refs: refs.map(<[_]>::iter),
            })
        })
    }

    /// Ops not yet returned.
    pub fn ops_left(&self) -> usize {
        self.recs.len()
    }

    /// `(op code, oid field, dest_oid field)` of every op not yet returned, unchecked (raw record fields).
    pub fn raw_refs(&self) -> impl Iterator<Item = (u32, u32, u32)> + '_ {
        self.recs.iter().map(|b| {
            let r = Rec(b);
            (r.code(), r.oid(), r.dest_oid())
        })
    }

    /// Next op; `None` after the last one (then call [`OpStream::finish`]).
    pub fn next_op(&mut self) -> Result<Option<(Cx, LazyOp<'a>)>> {
        let Some((rec, rest)) = self.recs.split_first() else {
            return Ok(None);
        };
        self.recs = rest;
        self.decode_op(&Rec(rec)).map(Some)
    }

    /// After the last op: every out-of-line payload must have been used. Returns the unconsumed side-stream bytes
    /// (including v10 `d` bytes past the declared stream lengths).
    pub fn finish(&mut self) -> Result<usize> {
        if self.refs.as_mut().is_some_and(|r| r.next().is_some()) {
            return Err(bad("txn out-of-line payload not used"));
        }
        Ok(self.mis.remaining() + self.ali.remaining() + self.extra)
    }

    fn decode_op(&mut self, r: &Rec<'_>) -> Result<(Cx, LazyOp<'a>)> {
        use TxnOpG::*;
        let code = r.code();
        if code == opc::NOP {
            return Ok((Cx(0), Nop));
        }
        let (nc, no) = (self.colls.len(), self.objs.len());
        let (split, page) = (self.split, self.page);
        let (mis, ali, refs) = (&mut self.mis, &mut self.ali, &mut self.refs);
        let cx = |i: u32| idx_ok(nc, i, "txn collection index").map(Cx);
        let ox = |i: u32| idx_ok(no, i, "txn object index").map(Ox);
        let cid = cx(r.cid())?;
        let oid = || ox(r.oid());
        let dest_oid = || ox(r.dest_oid());
        let dest_cid = || cx(r.dest_cid());
        let op = match code {
            opc::CREATE => Create { oid: oid()? },
            opc::TOUCH => Touch { oid: oid()? },
            opc::TOUCH_TEMP => TouchTemp {
                oid: oid()?,
                dest_oid: dest_oid()?,
            },
            opc::WRITE => {
                let (off, len) = (r.off(), r.len());
                let data = if !split {
                    let out_of_line =
                        refs.is_some() && mis.peek_rest().starts_with(&REF_MARK.to_le_bytes());
                    let b = if out_of_line {
                        mis.skip(4)?;
                        let it = refs.as_mut().expect("checked above");
                        it.next()
                            .map(|b| b.as_ref())
                            .ok_or(bad("txn out-of-line payload missing"))?
                    } else {
                        mis.bytes()?
                    };
                    if b.len() as u64 != len {
                        return Err(bad("txn write len"));
                    }
                    Data::new(b)
                } else {
                    let (h, m, t) = split_write(off, len, page)?;
                    if m == 0 {
                        Data::new(mis.take(h as usize)?)
                    } else {
                        let head = mis.take(h as usize)?;
                        let mid = ali.take(m as usize)?;
                        let tail = mis.take(t as usize)?;
                        Data { head, mid, tail }
                    }
                };
                Write {
                    oid: oid()?,
                    off,
                    data,
                }
            }
            opc::ZERO => Zero {
                oid: oid()?,
                off: r.off(),
                len: r.len(),
            },
            opc::TRUNCATE => Truncate {
                oid: oid()?,
                size: r.off(),
            },
            opc::REMOVE => Remove { oid: oid()? },
            opc::SETATTR => {
                let name = mis.bytes()?;
                SetAttr {
                    oid: oid()?,
                    name,
                    value: mis.bytes()?,
                }
            }
            opc::SETATTRS => SetAttrs {
                oid: oid()?,
                attrs: Kv::take(mis)?,
            },
            opc::RMATTR => RmAttr {
                oid: oid()?,
                name: mis.bytes()?,
            },
            opc::RMATTRS => RmAttrs { oid: oid()? },
            opc::CLONE => Clone {
                oid: oid()?,
                dest_oid: dest_oid()?,
            },
            opc::CLONERANGE2 => CloneRange2 {
                oid: oid()?,
                dest_oid: dest_oid()?,
                src_off: r.off(),
                len: r.len(),
                dest_off: r.dest_off(),
            },
            opc::MKCOLL => MkColl { bits: r.bits() },
            opc::RMCOLL => RmColl,
            opc::COLL_HINT => CollHint {
                ty: r.hint(),
                data: mis.bytes()?,
            },
            opc::COLL_MOVE_RENAME => CollMoveRename {
                oid: oid()?,
                dest_cid: dest_cid()?,
                dest_oid: dest_oid()?,
            },
            opc::TRY_RENAME => TryRename {
                oid: oid()?,
                dest_oid: dest_oid()?,
            },
            opc::OMAP_CLEAR => OmapClear { oid: oid()? },
            opc::OMAP_SETKEYS => {
                let out_of_line =
                    refs.is_some() && mis.peek_rest().starts_with(&REF_MARK.to_le_bytes());
                let pairs = if out_of_line {
                    mis.skip(4)?;
                    let n = mis.u32()? as usize;
                    let it = refs.as_mut().expect("checked above");
                    let b = it.next().ok_or(bad("txn out-of-line payload missing"))?;
                    Kv::from_entries(n, b)
                } else {
                    Kv::take(mis)?
                };
                OmapSetKeys { oid: oid()?, pairs }
            }
            opc::OMAP_RMKEYS => {
                let keys = Ks::take(mis)?;
                OmapRmKeys { oid: oid()?, keys }
            }
            opc::OMAP_RMKEYRANGE => {
                let first = mis.bytes()?;
                OmapRmKeyRange {
                    oid: oid()?,
                    first,
                    last: mis.bytes()?,
                }
            }
            opc::OMAP_SETHEADER => OmapSetHeader {
                oid: oid()?,
                header: mis.bytes()?,
            },
            opc::SETALLOCHINT => SetAllocHint {
                oid: oid()?,
                expected_object_size: r.eos(),
                expected_write_size: r.ews(),
                flags: r.hint(),
            },
            opc::SPLIT_COLLECTION2 => SplitCollection2 {
                dest_cid: dest_cid()?,
                bits: r.bits(),
                rem: r.rem(),
            },
            opc::MERGE_COLLECTION => MergeCollection {
                dest_cid: dest_cid()?,
                bits: r.bits(),
            },
            opc::COLL_SET_BITS => CollSetBits { bits: r.bits() },
            _ => return Err(bad("unsupported txn op code")),
        };
        Ok((cid, op))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_table_any_order() {
        let enc = |e: &[(u32, u32)]| {
            let mut v = (e.len() as u32).to_le_bytes().to_vec();
            for (k, i) in e {
                v.extend_from_slice(&k.to_le_bytes());
                v.extend_from_slice(&i.to_le_bytes());
            }
            v
        };
        let t = |e: &[(u32, u32)]| index_table::<u32>(&mut Decoder::new(&enc(e)));
        assert_eq!(t(&[(7, 0), (8, 1), (9, 2)]).unwrap(), [7, 8, 9]);
        assert_eq!(t(&[(7, 0), (9, 2), (8, 1)]).unwrap(), [7, 8, 9]);
        assert_eq!(t(&[(9, 2), (7, 0), (8, 1)]).unwrap(), [7, 8, 9]);
        assert!(t(&[(7, 0), (8, 0)]).is_err(), "duplicate");
        assert!(t(&[(7, 1), (8, 1)]).is_err(), "duplicate");
        assert!(t(&[(7, 0), (8, 2)]).is_err(), "out of range");
        assert!(t(&[(7, 1)]).is_err(), "out of range");
        assert!(t(&[]).unwrap().is_empty());
    }

    /// E2 regression: a count far above the entries present is refused before any allocation from it, and an
    /// out-of-order table never allocates per wire count.
    #[test]
    fn index_table_count_bomb() {
        let mut v = 0x0100_0000u32.to_le_bytes().to_vec();
        v.extend_from_slice(&7u32.to_le_bytes());
        v.extend_from_slice(&5u32.to_le_bytes());
        assert!(index_table::<u32>(&mut Decoder::new(&v)).is_err());
        // count fits the bytes, first index out of order, then truncated
        let mut v = 4u32.to_le_bytes().to_vec();
        for (k, i) in [(1u32, 3u32), (2, 0)] {
            v.extend_from_slice(&k.to_le_bytes());
            v.extend_from_slice(&i.to_le_bytes());
        }
        v.extend_from_slice(&[0; 16]);
        assert!(index_table::<u32>(&mut Decoder::new(&v)).is_err());
    }

    #[test]
    fn first_write_payload_sits_at_the_published_offset() {
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i * 7) as u8).collect();
        let mut t = Transaction::default();
        t.colls.push(CollT::Meta);
        t.objs.push(Ghobject::default());
        t.ops.push(Op {
            cid: Cx(0),
            op: TxnOp::Write {
                oid: Ox(0),
                off: 0,
                data: Data::new(&payload),
            },
        });
        t.ops.push(Op {
            cid: Cx(0),
            op: TxnOp::SetAttr {
                oid: Ox(0),
                name: b"_",
                value: b"oi",
            },
        });
        let blob = t.encode_v9().unwrap();
        assert_eq!(&blob[PAYLOAD_AT..PAYLOAD_AT + payload.len()], &payload[..]);
        assert_eq!(
            u32::from_le_bytes(blob[PAYLOAD_AT - 4..PAYLOAD_AT].try_into().unwrap()) as usize,
            payload.len()
        );
        // the rope form (payload spliced in by reference) flattens to the same bytes, payload at the same offset
        let owner = bytes::Bytes::from(payload.clone());
        let (head, runs) = t.encode_v9_rope(std::slice::from_ref(&owner)).unwrap();
        assert!(runs.is_empty() || runs[0].0 == PAYLOAD_AT);
        let _ = head;
    }

    /// `payload_at` names where the first write payload lies in the v9 blob (`10 + at`) and in the unsplit v10 data
    /// part (`at`), whatever ops come first (their stream bytes counted, no payload of an empty write);
    /// `encode_v9_placed` puts it on a 4 KiB boundary in memory.
    #[test]
    fn payload_at_matches_both_encodings() {
        let payload: Vec<u8> = (0..9000u32).map(|i| (i * 13 + 5) as u8).collect();
        let run_enc = {
            let kv: Vec<(&[u8], &[u8])> = vec![(b"k1", b"v"), (b"k2", &[3u8; 70])];
            let mut enc = Vec::new();
            denc::SortedKv::encode_into(&mut enc, kv.len(), kv.iter().copied());
            enc
        };
        let denc::KvShape::Sorted(run) = denc::SortedKv::parse(&run_enc).unwrap() else {
            panic!("sorted")
        };
        let o = Ox(0);
        let firsts: Vec<Vec<TxnOp<'_>>> = vec![
            vec![],
            vec![
                TxnOp::Touch { oid: o },
                TxnOp::SetAllocHint {
                    oid: o,
                    expected_object_size: 1,
                    expected_write_size: 1,
                    flags: 0,
                },
            ],
            vec![TxnOp::Write {
                oid: o,
                off: 0,
                data: Data::new(&[]),
            }],
            vec![
                TxnOp::SetAttr {
                    oid: o,
                    name: b"_",
                    value: b"object-info",
                },
                TxnOp::SetAttrs {
                    oid: o,
                    attrs: vec![(b"a", b"12"), (b"hinfo_key", b"xyz")],
                },
                TxnOp::RmAttr {
                    oid: o,
                    name: b"gone",
                },
                TxnOp::CollHint {
                    ty: 1,
                    data: b"hint",
                },
                TxnOp::OmapSetKeys {
                    oid: o,
                    pairs: OmapKv::Pairs(vec![(b"key", b"value")]),
                },
                TxnOp::OmapSetKeys {
                    oid: o,
                    pairs: OmapKv::Run(run),
                },
                TxnOp::OmapRmKeys {
                    oid: o,
                    keys: vec![b"x", b"yy"],
                },
                TxnOp::OmapRmKeyRange {
                    oid: o,
                    first: b"a",
                    last: b"b",
                },
                TxnOp::OmapSetHeader {
                    oid: o,
                    header: b"hdr",
                },
            ],
        ];
        for first in firsts {
            let mut t = Transaction::default();
            t.colls.push(CollT::Meta);
            t.objs.push(Ghobject::default());
            for op in first {
                t.ops.push(Op { cid: Cx(0), op });
            }
            assert_eq!(t.payload_at(), None);
            t.ops.push(Op {
                cid: Cx(0),
                op: TxnOp::Write {
                    oid: o,
                    off: 4096,
                    data: Data::new(&payload),
                },
            });
            let at = t.payload_at().expect("a write");
            let blob = t.encode_v9().unwrap();
            assert_eq!(&blob[10 + at..10 + at + payload.len()], &payload[..]);
            let (_, d) = t.encode_v10(DEFAULT_PAGE).unwrap();
            assert_eq!(&d[at..at + payload.len()], &payload[..]);
            // the placed form: same bytes, the payload on a PLACE_ALIGN boundary in memory
            let placed = t.encode_v9_placed().unwrap();
            assert_eq!(placed[..], blob[..]);
            assert_eq!(placed[10 + at..].as_ptr() as usize % PLACE_ALIGN, 0);
        }
        // a payload below one block stays a plain blob (nothing to view)
        let mut t = Transaction::default();
        t.colls.push(CollT::Meta);
        t.objs.push(Ghobject::default());
        t.ops.push(Op {
            cid: Cx(0),
            op: TxnOp::Write {
                oid: o,
                off: 0,
                data: Data::new(&payload[..PLACE_ALIGN - 1]),
            },
        });
        assert_eq!(
            t.encode_v9_placed().unwrap()[..],
            t.encode_v9().unwrap()[..]
        );
    }

    #[test]
    fn omap_run_block() {
        let kv: Vec<(&[u8], &[u8])> = vec![(b"a", b"1"), (b"b", b""), (b"c", &[7u8; 300])];
        let mut enc = Vec::new();
        denc::SortedKv::encode_into(&mut enc, kv.len(), kv.iter().copied());
        let denc::KvShape::Sorted(run) = denc::SortedKv::parse(&enc).unwrap() else {
            panic!("sorted")
        };
        let txn = |pairs: OmapKv<'_>| {
            let mut t = Transaction::default();
            t.colls.push(CollT::Meta);
            t.objs.push(Ghobject::default());
            t.ops.push(Op {
                cid: Cx(0),
                op: TxnOp::OmapSetKeys { oid: Ox(0), pairs },
            });
            t.encode_v9().unwrap()
        };
        // a run encodes as one block, byte-identical to the same entries as pairs
        let blob = txn(OmapKv::Run(run));
        assert_eq!(blob, txn(OmapKv::Pairs(kv.clone())));
        // and decodes back into a run (borrowing the message), unsorted lists into pairs
        let t = Transaction::decode(&[], &blob, 4096).unwrap();
        assert!(
            matches!(&t.ops[0].op, TxnOp::OmapSetKeys { pairs: OmapKv::Run(r), .. } if r.iter().eq(kv.iter().copied()))
        );
        let rev: Vec<_> = kv.iter().rev().copied().collect();
        let blob = txn(OmapKv::Pairs(rev.clone()));
        let t = Transaction::decode(&[], &blob, 4096).unwrap();
        assert_eq!(
            t.ops[0].op,
            TxnOp::OmapSetKeys {
                oid: Ox(0),
                pairs: OmapKv::Pairs(rev)
            }
        );
    }

    #[test]
    fn split() {
        // spec 1.4 example, P=4096
        assert_eq!(
            split_write(0x1200, 0x3000, 4096).unwrap(),
            (0xe00, 0x2000, 0x200)
        );
        assert_eq!(split_write(0, 4096, 4096).unwrap(), (0, 4096, 0));
        assert_eq!(split_write(1, 4096, 4096).unwrap(), (4096, 0, 0));
        assert_eq!(split_write(0, 10, 4096).unwrap(), (10, 0, 0));
        assert!(split_write(0, 4096, 0).is_err());
    }
}
