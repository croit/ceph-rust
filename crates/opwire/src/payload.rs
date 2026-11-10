// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Per-op indata parsers and outdata encodings (spec client-ops.md s1.4, s7, s9, s10).
//! Strings/keys are byte vectors (they are not necessarily UTF-8).

use crate::consts::csum;
use crate::osdop::OsdOp;
use bytes::Bytes;
use denc::types::{EntityAddr, EntityName, Hobject, ObjectLocator, UTime};
use denc::{BufMut, Decode, Decoder, Encode, Encoder, Error, Result};
use std::collections::{BTreeMap, BTreeSet};

// ---------- indata ----------

/// Split of a `call` op's indata: class || method || input (lengths from the union).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClsCall<'a> {
    pub class: &'a [u8],
    pub method: &'a [u8],
    pub input: &'a [u8],
}
impl OsdOp {
    pub fn cls_call(&self) -> Result<ClsCall<'_>> {
        let c = self.cls();
        let (cl, ml, il) = (
            c.class_len as usize,
            c.method_len as usize,
            c.indata_len as usize,
        );
        if cl + ml + il != self.indata.len() {
            return Err(Error::BadValue("call indata length"));
        }
        let d = &self.indata;
        Ok(ClsCall {
            class: &d[..cl],
            method: &d[cl..cl + ml],
            input: &d[cl + ml..],
        })
    }
    /// getxattr/rmxattr: name; setxattr/cmpxattr: (name, value).
    pub fn xattr_name_value(&self) -> Result<(&[u8], &[u8])> {
        let x = self.xattr();
        let (n, v) = (x.name_len as usize, x.value_len as usize);
        if self.indata.len() < n || self.indata.len() - n < v {
            return Err(Error::BadValue("xattr indata length"));
        }
        Ok((&self.indata[..n], &self.indata[n..n + v]))
    }
    /// getxattr/rmxattr: the name only. These two ops take `name_len` bytes and ignore `value_len` (client-ops 16.3);
    /// setxattr/cmpxattr still need the declared value bytes.
    pub fn xattr_name(&self) -> Result<&[u8]> {
        let n = self.xattr().name_len as usize;
        if self.indata.len() < n {
            return Err(Error::BadValue("xattr indata length"));
        }
        Ok(&self.indata[..n])
    }
    pub fn indata_as<'a, T: Decode<'a>>(&'a self) -> Result<T> {
        denc::from_slice(&self.indata)
    }
}

/// omap-get-keys indata.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OmapGetKeysIn {
    pub start_after: Vec<u8>,
    pub max_return: u64,
}
impl Encode for OmapGetKeysIn {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.bytes(&self.start_after)?;
        e.u64(self.max_return)
    }
}
impl<'a> Decode<'a> for OmapGetKeysIn {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        Ok(Self {
            start_after: d.bytes()?.to_vec(),
            max_return: d.u64()?,
        })
    }
}

/// omap-get-vals indata.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OmapGetValsIn {
    pub start_after: Vec<u8>,
    pub max_return: u64,
    pub filter_prefix: Vec<u8>,
}
impl Encode for OmapGetValsIn {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.bytes(&self.start_after)?;
        e.u64(self.max_return)?;
        e.bytes(&self.filter_prefix)
    }
}
impl<'a> Decode<'a> for OmapGetValsIn {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        Ok(Self {
            start_after: d.bytes()?.to_vec(),
            max_return: d.u64()?,
            filter_prefix: d.bytes()?.to_vec(),
        })
    }
}

/// omap-rm-key-range indata.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OmapRmKeyRangeIn {
    pub begin: Vec<u8>,
    pub end: Vec<u8>,
}
impl Encode for OmapRmKeyRangeIn {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.bytes(&self.begin)?;
        e.bytes(&self.end)
    }
}
impl<'a> Decode<'a> for OmapRmKeyRangeIn {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        Ok(Self {
            begin: d.bytes()?.to_vec(),
            end: d.bytes()?.to_vec(),
        })
    }
}

/// omap-get-vals-by-keys / omap-rm-keys indata: `set<string>`.
pub type KeySet = BTreeSet<Vec<u8>>;
/// omap-set-vals indata: `map<string,bufferlist>`.
pub type KvMap = BTreeMap<Vec<u8>, Vec<u8>>;

/// omap-set-vals indata kept as one buffer: the encoding of a `map<string,bufferlist>` with strictly ascending keys
/// ([`denc::SortedKv`]). A client batch stays one unit from the wire to the transaction (no per-key allocation,
/// doc/perf/omap-perkey-20261021.md); [`KvRun::parse`] keeps a canonical indata as is and normalizes any other once
/// with the map-decode rule (map order, last value of a repeated key wins).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvRun {
    buf: Bytes,
    n: u32,
}

impl Default for KvRun {
    fn default() -> Self {
        Self {
            buf: Bytes::from_static(&[0; 4]),
            n: 0,
        }
    }
}

impl KvRun {
    /// Validate `indata` (same errors as decoding a [`KvMap`], trailing bytes included); zero-copy when canonical.
    pub fn parse(indata: &Bytes) -> Result<KvRun> {
        match denc::SortedKv::parse(indata)? {
            denc::KvShape::Sorted(r) => Ok(KvRun {
                buf: indata.clone(),
                n: r.len() as u32,
            }),
            denc::KvShape::Unsorted => {
                let m: BTreeMap<&[u8], &[u8]> = denc::from_slice(indata)?;
                Ok(Self::encode_sorted(m.len(), m.into_iter()))
            }
        }
    }

    /// From pairs in any order (map rule: the last value of a repeated key wins).
    pub fn from_pairs<'a>(pairs: impl IntoIterator<Item = (&'a [u8], &'a [u8])>) -> KvRun {
        let m: BTreeMap<&[u8], &[u8]> = pairs.into_iter().collect();
        Self::encode_sorted(m.len(), m.into_iter())
    }

    fn encode_sorted<'a>(n: usize, it: impl Iterator<Item = (&'a [u8], &'a [u8])>) -> KvRun {
        let mut v = Vec::new();
        denc::SortedKv::encode_into(&mut v, n, it);
        KvRun {
            buf: Bytes::from(v),
            n: n as u32,
        }
    }

    pub fn len(&self) -> usize {
        self.n as usize
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// The map encoding (count included).
    pub fn encoded(&self) -> &Bytes {
        &self.buf
    }

    /// Borrowed view.
    pub fn view(&self) -> denc::SortedKv<'_> {
        denc::SortedKv::trusted(self.n as usize, &self.buf[4..])
    }

    /// Entries in ascending key order.
    pub fn iter(&self) -> denc::SortedKvIter<'_> {
        self.view().iter()
    }
}

/// omap-cmp indata: key -> (expected value, cmp op as i32; cmpxattr EQ 1, GT 3, LT 5 only).
pub type OmapCmpIn = BTreeMap<Vec<u8>, (Vec<u8>, i32)>;

/// notify indata.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NotifyIn {
    pub prot_ver: u32,
    pub timeout: u32,
    pub payload: Vec<u8>,
}
impl Encode for NotifyIn {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.u32(self.prot_ver)?;
        e.u32(self.timeout)?;
        e.bytes(&self.payload)
    }
}
impl<'a> Decode<'a> for NotifyIn {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        Ok(Self {
            prot_ver: d.u32()?,
            timeout: d.u32()?,
            payload: d.bytes()?.to_vec(),
        })
    }
}

/// notify-ack indata (empty indata = legacy short form; see `OsdOp::notify()`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NotifyAckIn {
    pub notify_id: u64,
    pub cookie: u64,
    pub reply: Vec<u8>,
}
impl Encode for NotifyAckIn {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.u64(self.notify_id)?;
        e.u64(self.cookie)?;
        e.bytes(&self.reply)
    }
}
impl<'a> Decode<'a> for NotifyAckIn {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        Ok(Self {
            notify_id: d.u64()?,
            cookie: d.u64()?,
            // the reply is optional
            reply: if d.is_empty() {
                Vec::new()
            } else {
                d.bytes()?.to_vec()
            },
        })
    }
}

/// pgls/pgnls indata: the cursor.
pub fn pgls_cursor(indata: &[u8]) -> Result<Hobject> {
    let mut d = Decoder::new(indata);
    Hobject::decode(&mut d)
}

/// One pgls filter (the `type` string and its arguments of a pgnls-filter / pgls-filter op).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PgFilter {
    /// `plain` and `hello.hello`: keep objects whose raw store attribute `xattr` equals `val` exactly (empty `xattr`
    /// = compare against an empty value, i.e. keep everything when `val` is empty).
    Xattr { xattr: Vec<u8>, val: Vec<u8> },
    /// `cephfs.inode_tag`: names ending `.00000000` whose `scrub_tag` attribute differs from `scrub_tag` (empty tag
    /// = every such name).
    CephfsInodeTag { scrub_tag: Vec<u8> },
}

/// pgnls-filter / pgls-filter indata: `string class, string method, string type, <type arguments>, hobject cursor`.
/// An unknown `type` yields `filter = None` and no cursor (the op answers EINVAL).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgFilterIn {
    pub class: Vec<u8>,
    pub method: Vec<u8>,
    pub filter_type: Vec<u8>,
    pub filter: Option<PgFilter>,
    pub cursor: Option<Hobject>,
}
impl<'a> Decode<'a> for PgFilterIn {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        let class = d.bytes()?.to_vec();
        let method = d.bytes()?.to_vec();
        let filter_type = d.bytes()?.to_vec();
        let filter = match &filter_type[..] {
            b"plain" | b"hello.hello" => Some(PgFilter::Xattr {
                xattr: d.bytes()?.to_vec(),
                val: d.bytes()?.to_vec(),
            }),
            b"cephfs.inode_tag" => Some(PgFilter::CephfsInodeTag {
                scrub_tag: d.versioned(1, |d, _| Ok(d.bytes()?.to_vec()))?,
            }),
            _ => None,
        };
        let cursor = match filter {
            Some(_) => Some(Hobject::decode(d)?),
            None => None,
        };
        Ok(PgFilterIn {
            class,
            method,
            filter_type,
            filter,
            cursor,
        })
    }
}

// ---------- outdata ----------

/// stat outdata: u64 size, utime_t mtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StatOut {
    pub size: u64,
    pub mtime: UTime,
}
impl Encode for StatOut {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.u64(self.size)?;
        self.mtime.encode(e)
    }
}
impl<'a> Decode<'a> for StatOut {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        Ok(Self {
            size: d.u64()?,
            mtime: UTime::decode(d)?,
        })
    }
}

/// omap-get-keys outdata.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OmapKeysOut {
    pub keys: Vec<Vec<u8>>,
    pub truncated: bool,
}
impl Encode for OmapKeysOut {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        self.keys.encode(e)?;
        e.bool(self.truncated)
    }
}
impl<'a> Decode<'a> for OmapKeysOut {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        Ok(Self {
            keys: Vec::<Vec<u8>>::decode(d)?,
            truncated: d.bool()?,
        })
    }
}

/// omap-get-vals outdata.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OmapValsOut {
    pub vals: KvMap,
    pub truncated: bool,
}
impl Encode for OmapValsOut {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        self.vals.encode(e)?;
        e.bool(self.truncated)
    }
}
impl<'a> Decode<'a> for OmapValsOut {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        Ok(Self {
            vals: KvMap::decode(d)?,
            truncated: d.bool()?,
        })
    }
}

/// omap-get-vals outdata straight from a listing: the bytes [`OmapValsOut`] encodes for the same entries, written in
/// one pass into an exactly sized buffer (no map of the entries; a listing reply of 1024 keys built ~1024 map nodes on
/// the PG core). Entries in strictly ascending key order (the store's order) are written as they are; any other list
/// takes the map rule (sorted, last of a repeated key wins).
pub fn omap_vals_out(entries: &[(Vec<u8>, Vec<u8>)], truncated: bool) -> Vec<u8> {
    if !entries.windows(2).all(|w| w[0].0 < w[1].0) {
        let vals: KvMap = entries.iter().cloned().collect();
        return denc::to_vec(&OmapValsOut { vals, truncated }).unwrap_or_default();
    }
    let len = 4
        + 1
        + entries
            .iter()
            .map(|(k, v)| 8 + k.len() + v.len())
            .sum::<usize>();
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (k, v) in entries {
        out.extend_from_slice(&(k.len() as u32).to_le_bytes());
        out.extend_from_slice(k);
        out.extend_from_slice(&(v.len() as u32).to_le_bytes());
        out.extend_from_slice(v);
    }
    out.push(u8::from(truncated));
    debug_assert_eq!(out.len(), len);
    out
}

/// Bytes reserved in front of an encoded listing for [`omap_list_out`] (the entry count).
pub const OMAP_LIST_HEAD: usize = 4;

/// omap-get-vals / omap-get-keys outdata finished in place from a listing encoded by the store: `buf` = [`OMAP_LIST_HEAD`]
/// reserved bytes, then `n` entries (`le32 len, key, le32 len, value` resp. `le32 len, key`) in strictly ascending key
/// order. The count goes into the head, the truncated flag after the entries: the bytes [`OmapValsOut`] /
/// [`OmapKeysOut`] encode for the same entries, without a copy of them.
pub fn omap_list_out(mut buf: Vec<u8>, n: u32, truncated: bool) -> Vec<u8> {
    buf[..OMAP_LIST_HEAD].copy_from_slice(&n.to_le_bytes());
    buf.push(u8::from(truncated));
    buf
}

/// sparse-read outdata: `map<u64,u64>` extents then a bufferlist with the concatenated data.
/// Validated borrowed view; records and data retain the caller's storage.
#[derive(Debug, Clone, Copy)]
pub struct SparseReadView<'a> {
    records: &'a [u8],
    data: &'a [u8],
}
impl SparseReadView<'_> {
    pub fn data(&self) -> &[u8] {
        self.data
    }
    pub fn extents(&self) -> impl ExactSizeIterator<Item = (u64, u64)> + '_ {
        self.records
            .as_chunks::<16>()
            .0
            .iter()
            .map(|r| (denc::le::rd_u64(r, 0), denc::le::rd_u64(r, 8)))
    }

    /// Check absolute extents against the submitted range, without inferring EOF.
    pub fn validate_range(&self, offset: u64, length: u64) -> Result<()> {
        let end = offset.checked_add(length).ok_or(Error::TooLong)?;
        if self
            .extents()
            .any(|(at, len)| at < offset || at > end || len > end - at)
        {
            return Err(Error::BadValue("sparse extent range"));
        }
        Ok(())
    }
}
impl<'a> Decode<'a> for SparseReadView<'a> {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        let n = d.count()?;
        let records = d.take(n.checked_mul(16).ok_or(Error::TooLong)?)?;
        let data = d.bytes()?;
        let view = Self { records, data };
        let mut previous = None;
        let mut total = 0u64;
        for (at, len) in view.extents() {
            let end = at.checked_add(len).ok_or(Error::TooLong)?;
            if previous.is_some_and(|(start, end)| at <= start || at < end) {
                return Err(Error::BadValue("sparse extent order"));
            }
            previous = Some((at, end));
            total = total.checked_add(len).ok_or(Error::TooLong)?;
        }
        if total != data.len() as u64 {
            return Err(Error::BadValue("sparse data length"));
        }
        Ok(view)
    }
}

/// Owned sparse result; decoding validates before allocating the map/data.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SparseReadOut {
    pub extents: BTreeMap<u64, u64>,
    pub data: Vec<u8>,
}
impl Encode for SparseReadOut {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        self.extents.encode(e)?;
        e.bytes(&self.data)
    }
}
impl<'a> Decode<'a> for SparseReadOut {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        let view = SparseReadView::decode(d)?;
        Ok(Self {
            extents: view.extents().collect(),
            data: view.data.to_vec(),
        })
    }
}

/// checksum outdata: u32 count, count x value (width per type).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChecksumOut {
    pub ty: u8,
    pub values: Vec<u64>,
}
impl ChecksumOut {
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let w = csum::width(self.ty).ok_or(Error::BadValue("checksum type"))?;
        let mut e = Encoder::new();
        e.count(self.values.len())?;
        for v in &self.values {
            e.raw(&v.to_le_bytes()[..w])?;
        }
        Ok(e.into_vec())
    }
    pub fn decode(ty: u8, b: &[u8]) -> Result<Self> {
        let w = csum::width(ty).ok_or(Error::BadValue("checksum type"))?;
        // A successful range beyond EOF has no checksum payload at all.
        if b.is_empty() {
            return Ok(Self {
                ty,
                values: Vec::new(),
            });
        }
        let mut d = Decoder::new(b);
        let n = d.u32()? as usize;
        if n.checked_mul(w).is_none_or(|t| t > d.remaining()) {
            return Err(Error::BadLength {
                len: n as u64,
                remaining: d.remaining(),
            });
        }
        let trailing = d.remaining() - n * w;
        if trailing != 0 {
            return Err(Error::TrailingBytes(trailing));
        }
        let mut values = Vec::with_capacity(n);
        for _ in 0..n {
            let mut a = [0u8; 8];
            a[..w].copy_from_slice(d.take(w)?);
            values.push(u64::from_le_bytes(a));
        }
        Ok(ChecksumOut { ty, values })
    }
}

/// clone_info ENV(1,1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CloneInfo {
    pub cloneid: u64,
    pub snaps: Vec<u64>,
    pub overlap: Vec<(u64, u64)>,
    pub size: u64,
}
impl Encode for CloneInfo {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(1, 1, |e| {
            e.u64(self.cloneid)?;
            self.snaps.encode(e)?;
            self.overlap.encode(e)?;
            e.u64(self.size)
        })
    }
}
impl<'a> Decode<'a> for CloneInfo {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned(1, |d, _| {
            Ok(Self {
                cloneid: d.u64()?,
                snaps: Vec::<u64>::decode(d)?,
                overlap: Vec::<(u64, u64)>::decode(d)?,
                size: d.u64()?,
            })
        })
    }
}

/// list-snaps outdata `obj_list_snap_response_t` ENV(2,1): clones, seq.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ObjListSnapResponse {
    pub clones: Vec<CloneInfo>,
    pub seq: u64,
}
impl Encode for ObjListSnapResponse {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(2, 1, |e| {
            self.clones.encode(e)?;
            e.u64(self.seq)
        })
    }
}
impl<'a> Decode<'a> for ObjListSnapResponse {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned(2, |d, v| {
            Ok(Self {
                clones: Vec::<CloneInfo>::decode(d)?,
                seq: if v >= 2 { d.u64()? } else { 0 },
            })
        })
    }
}

/// watch_item_t ENV(2,1): entity_name, cookie, timeout, addr (featured).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchItem {
    pub name: EntityName,
    pub cookie: u64,
    pub timeout_s: u32,
    pub addr: EntityAddr,
}
impl Encode for WatchItem {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(2, 1, |e| {
            self.name.encode(e)?;
            e.u64(self.cookie)?;
            e.u32(self.timeout_s)?;
            self.addr.encode(e)
        })
    }
}
impl<'a> Decode<'a> for WatchItem {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned(2, |d, _| {
            Ok(Self {
                name: EntityName::decode(d)?,
                cookie: d.u64()?,
                timeout_s: d.u32()?,
                addr: EntityAddr::decode(d)?,
            })
        })
    }
}

/// list-watchers outdata `obj_list_watch_response_t` ENV(1,1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ObjListWatchResponse {
    pub entries: Vec<WatchItem>,
}
impl Encode for ObjListWatchResponse {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(1, 1, |e| self.entries.encode(e))
    }
}
impl<'a> Decode<'a> for ObjListWatchResponse {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned(1, |d, _| {
            Ok(Self {
                entries: Vec::<WatchItem>::decode(d)?,
            })
        })
    }
}

/// One `pgnls` entry: namespace, object name, locator key (empty if == oid).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListObjEntry {
    pub nspace: Vec<u8>,
    pub oid: Vec<u8>,
    pub locator: Vec<u8>,
}
impl Encode for ListObjEntry {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.bytes(&self.nspace)?;
        e.bytes(&self.oid)?;
        e.bytes(&self.locator)
    }
}
impl<'a> Decode<'a> for ListObjEntry {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        Ok(Self {
            nspace: d.bytes()?.to_vec(),
            oid: d.bytes()?.to_vec(),
            locator: d.bytes()?.to_vec(),
        })
    }
}

/// pgnls outdata `pg_nls_response_t` ENV(1,1): handle, entries.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PgNlsResponse {
    pub handle: Hobject,
    pub entries: Vec<ListObjEntry>,
}
impl Encode for PgNlsResponse {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(1, 1, |e| {
            self.handle.encode(e)?;
            self.entries.encode(e)
        })
    }
}
impl<'a> Decode<'a> for PgNlsResponse {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned(1, |d, _| {
            Ok(Self {
                handle: Hobject::decode(d)?,
                entries: Vec::<ListObjEntry>::decode(d)?,
            })
        })
    }
}

/// pgls (legacy) outdata `pg_ls_response_t`: u8 version(1), handle, list<(oid, key)>.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PgLsResponse {
    pub handle: Hobject,
    pub entries: Vec<(Vec<u8>, Vec<u8>)>,
}
impl Encode for PgLsResponse {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.u8(1)?;
        self.handle.encode(e)?;
        self.entries.encode(e)
    }
}
impl<'a> Decode<'a> for PgLsResponse {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        if d.u8()? != 1 {
            return Err(Error::BadValue("pg_ls_response_t version"));
        }
        Ok(Self {
            handle: Hobject::decode(d)?,
            entries: Vec::<(Vec<u8>, Vec<u8>)>::decode(d)?,
        })
    }
}

/// request_redirect_t ENV(1,1): locator, redirect object, legacy trailer (skipped, written empty).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RequestRedirect {
    pub oloc: ObjectLocator,
    pub redirect_object: Vec<u8>,
}
impl Encode for RequestRedirect {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(1, 1, |e| {
            self.oloc.encode(e)?;
            e.bytes(&self.redirect_object)?;
            e.u32(0)
        })
    }
}
impl<'a> Decode<'a> for RequestRedirect {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned(1, |d, _| {
            let oloc = ObjectLocator::decode(d)?;
            let redirect_object = d.bytes()?.to_vec();
            let n = d.u32()? as usize;
            d.skip(n)?;
            Ok(Self {
                oloc,
                redirect_object,
            })
        })
    }
}

/// NOTIFY_COMPLETE data segment: replies `map<(gid,cookie), bufferlist>` then missed watchers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NotifyCompleteData {
    pub replies: BTreeMap<(u64, u64), Vec<u8>>,
    pub missed: Vec<(u64, u64)>,
}
impl Encode for NotifyCompleteData {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        self.replies.encode(e)?;
        self.missed.encode(e)
    }
}
impl<'a> Decode<'a> for NotifyCompleteData {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        Ok(Self {
            replies: BTreeMap::<(u64, u64), Vec<u8>>::decode(d)?,
            missed: Vec::<(u64, u64)>::decode(d)?,
        })
    }
}

/// copy-from / copy-from2 indata: source oid, source locator, and (copy-from2 with flag
/// TRUNCATE_SEQ 0x20 in `copy_from().flags`) truncate_seq/truncate_size.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CopyFromIn {
    pub src_oid: Vec<u8>,
    pub src_oloc: ObjectLocator,
    pub truncate: Option<(u32, u64)>,
}
impl CopyFromIn {
    pub fn parse(op: &OsdOp) -> Result<Self> {
        let mut d = Decoder::new(&op.indata);
        let src_oid = d.bytes()?.to_vec();
        let src_oloc = ObjectLocator::decode(&mut d)?;
        let truncate = if op.copy_from().flags & crate::copy::copy_flag::TRUNCATE_SEQ != 0 {
            Some((d.u32()?, d.u64()?))
        } else {
            None
        };
        Ok(CopyFromIn {
            src_oid,
            src_oloc,
            truncate,
        })
    }
}
