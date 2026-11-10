// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! copy-get wire (spec copy.md): the cursor + chunk size a destination sends, the `object_copy_data_t` the source
//! answers with, the omap section layout, and the destination's copy-from / copy-from2 indata.

use crate::consts::op as code;
use crate::osdop::OsdOp;
use denc::types::{OsdReqId, UTime};
use denc::{BufMut, Decode, Decoder, Encode, Encoder, Error, Result};
use std::collections::BTreeMap;

/// copy-from2 flag bits (`CopyFrom::flags`).
pub mod copy_flag {
    pub const FLUSH: u8 = 1;
    pub const IGNORE_OVERLAY: u8 = 2;
    pub const IGNORE_CACHE: u8 = 4;
    pub const MAP_SNAP_CLONE: u8 = 8;
    pub const RWORDERED: u8 = 16;
    pub const TRUNCATE_SEQ: u8 = 32;
    /// Every bit copy-from2 accepts.
    pub const ALL: u8 = 63;
}

/// `object_copy_data_t::flags`.
pub const COPY_FLAG_DATA_DIGEST: u32 = 1;
pub const COPY_FLAG_OMAP_DIGEST: u32 = 2;

/// Progress marker of a chunked copy ENV(1,1): which parts the destination already has.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CopyCursor {
    pub attr_complete: bool,
    pub data_offset: u64,
    pub data_complete: bool,
    /// Last omap key already delivered (empty = none yet).
    pub omap_offset: Vec<u8>,
    pub omap_complete: bool,
}

impl CopyCursor {
    /// Nothing copied yet: every part flag unset and no offset advanced (spec copy.md 3).
    pub fn is_initial(&self) -> bool {
        !self.attr_complete
            && self.data_offset == 0
            && !self.data_complete
            && self.omap_offset.is_empty()
            && !self.omap_complete
    }
    pub fn is_complete(&self) -> bool {
        self.attr_complete && self.data_complete && self.omap_complete
    }
}

impl Encode for CopyCursor {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(1, 1, |e| {
            e.bool(self.attr_complete)?;
            e.u64(self.data_offset)?;
            e.bool(self.data_complete)?;
            e.bytes(&self.omap_offset)?;
            e.bool(self.omap_complete)
        })
    }
}
impl<'a> Decode<'a> for CopyCursor {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned(1, |d, _| {
            Ok(Self {
                attr_complete: d.bool()?,
                data_offset: d.u64()?,
                data_complete: d.bool()?,
                omap_offset: d.bytes()?.to_vec(),
                omap_complete: d.bool()?,
            })
        })
    }
}

/// copy-get indata: cursor, then the byte budget of this chunk.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CopyGetIn {
    pub cursor: CopyCursor,
    pub max: u64,
}
impl Encode for CopyGetIn {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        self.cursor.encode(e)?;
        e.u64(self.max)
    }
}
impl<'a> Decode<'a> for CopyGetIn {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        Ok(Self {
            cursor: CopyCursor::decode(d)?,
            max: d.u64()?,
        })
    }
}

/// `object_copy_data_t` ENV(8,5): one chunk. Which of attrs / data / omap are filled follows the cursor the sender
/// returns; `size` and `mtime` are always set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyData {
    pub size: u64,
    pub mtime: UTime,
    /// User xattrs (names without the store's `_` prefix).
    pub attrs: BTreeMap<Vec<u8>, Vec<u8>>,
    pub data: Vec<u8>,
    /// `u32 n` then `n` x (key bytes, value bytes), each length-prefixed. Empty = no keys in this chunk.
    pub omap_data: Vec<u8>,
    pub cursor: CopyCursor,
    pub omap_header: Vec<u8>,
    /// Snaps the (clone) object belongs to.
    pub snaps: Vec<u64>,
    /// SnapSet.seq (head).
    pub snap_seq: u64,
    pub flags: u32,
    pub data_digest: u32,
    pub omap_digest: u32,
    pub reqids: Vec<(OsdReqId, u64)>,
    pub truncate_seq: u64,
    pub truncate_size: u64,
    pub reqid_return_codes: BTreeMap<u32, i32>,
}

impl Default for CopyData {
    fn default() -> Self {
        CopyData {
            size: u64::MAX,
            mtime: UTime::default(),
            attrs: BTreeMap::new(),
            data: Vec::new(),
            omap_data: Vec::new(),
            cursor: CopyCursor::default(),
            omap_header: Vec::new(),
            snaps: Vec::new(),
            snap_seq: 0,
            flags: 0,
            data_digest: u32::MAX,
            omap_digest: u32::MAX,
            reqids: Vec::new(),
            truncate_seq: 0,
            truncate_size: 0,
            reqid_return_codes: BTreeMap::new(),
        }
    }
}

impl Encode for CopyData {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(8, 5, |e| {
            e.u64(self.size)?;
            self.mtime.encode(e)?;
            self.attrs.encode(e)?;
            e.bytes(&self.data)?;
            e.bytes(&self.omap_data)?;
            self.cursor.encode(e)?;
            e.bytes(&self.omap_header)?;
            self.snaps.encode(e)?;
            e.u64(self.snap_seq)?;
            e.u32(self.flags)?;
            e.u32(self.data_digest)?;
            e.u32(self.omap_digest)?;
            self.reqids.encode(e)?;
            e.u64(self.truncate_seq)?;
            e.u64(self.truncate_size)?;
            self.reqid_return_codes.encode(e)
        })
    }
}
impl<'a> Decode<'a> for CopyData {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        // v < 5 (pre-luminous layout) is not produced by any supported peer; struct_compat is accepted up to the
        // version this decoder reads (8), as every Ceph decoder does
        d.versioned_min(5, 8, |d, v| {
            let mut x = CopyData {
                size: d.u64()?,
                mtime: UTime::decode(d)?,
                attrs: BTreeMap::decode(d)?,
                data: d.bytes()?.to_vec(),
                omap_data: d.bytes()?.to_vec(),
                cursor: CopyCursor::decode(d)?,
                omap_header: d.bytes()?.to_vec(),
                snaps: Vec::<u64>::decode(d)?,
                snap_seq: d.u64()?,
                ..Default::default()
            };
            x.flags = d.u32()?;
            x.data_digest = d.u32()?;
            x.omap_digest = d.u32()?;
            if v >= 6 {
                x.reqids = Vec::<(OsdReqId, u64)>::decode(d)?;
            }
            if v >= 7 {
                x.truncate_seq = d.u64()?;
                x.truncate_size = d.u64()?;
            }
            if v >= 8 {
                x.reqid_return_codes = BTreeMap::<u32, i32>::decode(d)?;
            }
            Ok(x)
        })
    }
}

/// Encode an `omap_data` section: `u32 n` then `n` x (key, value), each length-prefixed. Empty = no count, no entries.
pub fn omap_section(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    if entries.is_empty() {
        return Vec::new();
    }
    let mut e = Encoder::new();
    let _ = e.u32(entries.len() as u32);
    for (k, v) in entries {
        let _ = e.bytes(k);
        let _ = e.bytes(v);
    }
    e.into_vec()
}

/// Parse an `omap_data` section into its entries (empty section = none).
pub fn parse_omap_section(b: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    if b.is_empty() {
        return Ok(Vec::new());
    }
    let mut d = Decoder::new(b);
    let n = d.u32()? as usize;
    // every entry is at least its two u32 lengths: a larger count is malformed, never an allocation size
    if n > d.remaining() / 8 {
        return Err(Error::BadLength {
            len: n as u64,
            remaining: d.remaining(),
        });
    }
    let mut out = Vec::with_capacity(n.min(1024));
    for _ in 0..n {
        let k = d.bytes()?.to_vec();
        let v = d.bytes()?.to_vec();
        out.push((k, v));
    }
    if !d.is_empty() {
        return Err(Error::BadValue("omap section trailing bytes"));
    }
    Ok(out)
}

impl OsdOp {
    /// copy-get request: indata = cursor + max; the union mirrors `max`.
    pub fn copy_get_req(cursor: &CopyCursor, max: u64) -> Self {
        let mut o = OsdOp::new(code::COPY_GET);
        o.set_copy_get(crate::osdop::CopyGet { max });
        o.indata = denc::to_vec(&CopyGetIn {
            cursor: cursor.clone(),
            max,
        })
        .expect("vec")
        .into();
        o
    }
    pub fn copy_get_in(&self) -> Result<CopyGetIn> {
        denc::from_slice(&self.indata)
    }
    /// copy-from (`op` = COPY_FROM) / copy-from2 (`op` = COPY_FROM2) request. `truncate` = (seq, size) is sent only by
    /// copy-from2 (sets flag TRUNCATE_SEQ).
    pub fn copy_from_req(
        op: u16,
        src_oid: &[u8],
        src_oloc: &denc::types::ObjectLocator,
        snapid: u64,
        src_version: u64,
        flags: u8,
        truncate: Option<(u32, u64)>,
    ) -> Self {
        let mut o = OsdOp::new(op);
        let mut flags = flags;
        if truncate.is_some() {
            flags |= copy_flag::TRUNCATE_SEQ;
        }
        o.set_copy_from(crate::osdop::CopyFrom {
            snapid,
            src_version,
            flags,
            src_fadvise_flags: 0,
        });
        let mut e = Encoder::new();
        e.bytes(src_oid).expect("vec");
        src_oloc.encode(&mut e).expect("vec");
        if let Some((s, z)) = truncate {
            e.u32(s).expect("vec");
            e.u64(z).expect("vec");
        }
        o.indata = e.into_vec().into();
        o
    }
}
