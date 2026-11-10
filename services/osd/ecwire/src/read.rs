// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! MOSDECSubOpRead / MOSDECSubOpReadReply and their payload structs (spec ec.md 6.2).

use crate::{BytesLen, get_trace, put_trace};
use bytes::Bytes;
use denc::types::{Hobject, PgShard, SpgT};
use denc::{Decode, Decoder, Encode, Error, Result};
use messages::{Message, Segments, front_with, meta};
use std::collections::{BTreeMap, BTreeSet};

/// ECSubRead (we emit struct v4, compat 2; decode v1..4).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ECSubRead {
    pub from: PgShard,
    pub tid: u64,
    /// `(offset, length, fadvise flags)` per range.
    pub to_read: BTreeMap<Hobject, Vec<(u64, u64, u32)>>,
    pub attrs_to_read: BTreeSet<Hobject>,
    /// `(first sub-chunk, count)`; non-clay = `[(0, 1)]`.
    pub subchunks: BTreeMap<Hobject, Vec<(i32, i32)>>,
    pub omap_read_from: BTreeMap<Hobject, (Vec<u8>, u64)>,
    pub omap_headers_to_read: BTreeSet<Hobject>,
}

impl ECSubRead {
    fn encode_into<B: denc::BufMut>(&self, e: &mut denc::Encoder<B>) -> Result<()> {
        e.versioned(4, 2, |e| {
            self.from.encode(e)?;
            e.u64(self.tid)?;
            self.to_read.encode(e)?;
            self.attrs_to_read.encode(e)?;
            self.subchunks.encode(e)?;
            self.omap_read_from.encode(e)?;
            self.omap_headers_to_read.encode(e)
        })
    }

    fn decode_from(d: &mut Decoder<'_>) -> Result<Self> {
        // struct v1, and v2 with compat 1 (peer without FADVISE_FLAGS), carry (off, len) pairs
        let compat = d.peek_rest().get(1).copied().unwrap_or(0);
        // struct_v 1..; refused only when the sender's struct_compat exceeds the version this decoder reads (4), the
        // rule of every Ceph decoder: a later struct_v whose compat is <= 4 keeps our fields in place and appends
        d.versioned_min(1, 4, |d, v| {
            let from = PgShard::decode(d)?;
            let tid = d.u64()?;
            let pairs = v == 1 || (v == 2 && compat == 1);
            let to_read: BTreeMap<Hobject, Vec<(u64, u64, u32)>> = if pairs {
                let m = BTreeMap::<Hobject, Vec<(u64, u64)>>::decode(d)?;
                m.into_iter()
                    .map(|(k, l)| (k, l.into_iter().map(|(o, n)| (o, n, 0)).collect()))
                    .collect()
            } else {
                BTreeMap::decode(d)?
            };
            let attrs_to_read = BTreeSet::<Hobject>::decode(d)?;
            let subchunks = if v >= 3 {
                BTreeMap::decode(d)?
            } else {
                to_read.keys().map(|k| (k.clone(), vec![(0, 1)])).collect()
            };
            let (omap_read_from, omap_headers_to_read) = if v >= 4 {
                (BTreeMap::decode(d)?, BTreeSet::decode(d)?)
            } else {
                Default::default()
            };
            Ok(ECSubRead {
                from,
                tid,
                to_read,
                attrs_to_read,
                subchunks,
                omap_read_from,
                omap_headers_to_read,
            })
        })
    }
}

/// MOSDECSubOpRead (110, head 4, compat 1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDECSubOpRead {
    pub pgid: SpgT,
    pub map_epoch: u32,
    pub op: ECSubRead,
    pub min_epoch: u32,
    pub trace: [i64; 3],
    pub cost: u64,
}

impl Message for MOSDECSubOpRead {
    meta!(110, 4, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            self.pgid.encode(e)?;
            e.u32(self.map_epoch)?;
            self.op.encode_into(e)?;
            e.u32(self.min_epoch)?;
            put_trace(e, &self.trace)?;
            e.u64(self.cost)
        })?))
    }
    fn decode(version: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        let pgid = SpgT::decode(&mut d)?;
        let map_epoch = d.u32()?;
        let op = ECSubRead::decode_from(&mut d)?;
        let (mut min_epoch, mut trace, mut cost) = (map_epoch, [0; 3], 0);
        if version >= 3 {
            min_epoch = d.u32()?;
            trace = get_trace(&mut d)?;
        }
        if version >= 4 {
            cost = d.u64()?;
        }
        Ok(MOSDECSubOpRead {
            pgid,
            map_epoch,
            op,
            min_epoch,
            trace,
            cost,
        })
    }
}

/// ECSubReadReply. Encoded as struct v1 (data inline) unless [`Self::data_segment`] is set or an omap field is non-empty
/// (then v3, data in the DATA segment).
#[derive(Clone, PartialEq, Eq, Default)]
pub struct ECSubReadReply {
    pub from: PgShard,
    pub tid: u64,
    pub buffers_read: BTreeMap<Hobject, Vec<(u64, Bytes)>>,
    pub attrs_read: BTreeMap<Hobject, BTreeMap<Vec<u8>, Vec<u8>>>,
    /// Negative errno.
    pub errors: BTreeMap<Hobject, i32>,
    pub omap_headers_read: BTreeMap<Hobject, Vec<u8>>,
    pub omap_entries_read: BTreeMap<Hobject, BTreeMap<Vec<u8>, Vec<u8>>>,
    pub omaps_complete: BTreeMap<Hobject, bool>,
    /// Emit struct v3 (data in the DATA segment: no copy into the front, a shared slice for the receiver) even without
    /// omap fields; only for a tentacle+ receiver (spec ec.md 6.2.2). Decode: the struct was v >= 2.
    pub data_segment: bool,
    /// Known `crc32c(!0, ..)` of the one shard buffer (store block crcs): msgr2 skips its pass when the DATA segment is exactly
    /// that buffer (v3, single buffer). Never encoded; not part of equality.
    pub data_crc: crc::CrcHint,
    /// Send side only (never decoded): further pieces of the ONE shard buffer, in order after it (store buffers by
    /// reference, each with its known crc). The encoded extent length covers them; [`Message::encode`] appends them to the
    /// DATA segment (copy), the cluster send path moves them out with [`Self::take_data_more`] and sends them by reference
    /// after the DATA segment (adr 0116 am. 4).
    pub data_more: Vec<(Bytes, crc::CrcHint)>,
    /// Bytes of `data_more` already moved out by [`Self::take_data_more`] (still counted in the extent length).
    pub data_more_sent: usize,
}

/// `Debug` without the buffers (`buffers_read` holds the shard chunk, up to a stripe width, `data_more` its pieces;
/// the attrs/omap fields are small and print in full). The exhaustive destructuring makes a new field a compile error
/// here until it is shown or summarized on purpose.
impl std::fmt::Debug for ECSubReadReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ECSubReadReply {
            from,
            tid,
            buffers_read,
            attrs_read,
            errors,
            omap_headers_read,
            omap_entries_read,
            omaps_complete,
            data_segment,
            data_crc,
            data_more,
            data_more_sent,
        } = self;
        let buffers: Vec<(&Hobject, Vec<(u64, BytesLen)>)> = buffers_read
            .iter()
            .map(|(h, items)| {
                (
                    h,
                    items
                        .iter()
                        .map(|(off, b)| (*off, BytesLen(b.len())))
                        .collect(),
                )
            })
            .collect();
        let more: Vec<BytesLen> = data_more.iter().map(|(b, _)| BytesLen(b.len())).collect();
        f.debug_struct("ECSubReadReply")
            .field("from", from)
            .field("tid", tid)
            .field("buffers_read", &buffers)
            .field("attrs_read", attrs_read)
            .field("errors", errors)
            .field("omap_headers_read", omap_headers_read)
            .field("omap_entries_read", omap_entries_read)
            .field("omaps_complete", omaps_complete)
            .field("data_segment", data_segment)
            .field("data_crc", data_crc)
            .field("data_more", &more)
            .field("data_more_sent", data_more_sent)
            .finish()
    }
}

impl ECSubReadReply {
    /// Move the further pieces of the one shard buffer out for a by-reference send after the DATA segment: the encoding
    /// keeps their length, the DATA segment then holds only the first piece.
    pub fn take_data_more(&mut self) -> Vec<(Bytes, crc::CrcHint)> {
        let m = std::mem::take(&mut self.data_more);
        self.data_more_sent += m.iter().map(|(b, _)| b.len()).sum::<usize>();
        m
    }

    fn v3(&self) -> bool {
        self.data_segment
            || !(self.omap_headers_read.is_empty()
                && self.omap_entries_read.is_empty()
                && self.omaps_complete.is_empty())
    }

    /// Encode the struct; returns the DATA segment bytes (empty for v1).
    fn encode_into<B: denc::BufMut>(&self, e: &mut denc::Encoder<B>) -> Result<Bytes> {
        let v3 = self.v3();
        let mut data = Vec::new();
        // one buffer (the usual sub-read reply): the DATA segment is that buffer itself, shared
        let mut single: Option<Bytes> = None;
        if v3 {
            let mut it = self.buffers_read.values().flatten();
            if let (Some((_, b)), None) = (it.next(), it.next()) {
                single = Some(if self.data_more.is_empty() {
                    b.clone()
                } else {
                    let mut v = Vec::with_capacity(
                        b.len() + self.data_more.iter().map(|(x, _)| x.len()).sum::<usize>(),
                    );
                    v.extend_from_slice(b);
                    for (x, _) in &self.data_more {
                        v.extend_from_slice(x);
                    }
                    v.into()
                });
            }
        }
        // the pieces after the one buffer (sent or still here) are part of its extent
        let more = self.data_more_sent + self.data_more.iter().map(|(x, _)| x.len()).sum::<usize>();
        if more != 0 && single.is_none() {
            return Err(Error::BadValue(
                "ECSubReadReply: buffer pieces need the one-buffer v3 shape",
            ));
        }
        e.versioned(if v3 { 3 } else { 1 }, if v3 { 2 } else { 1 }, |e| {
            self.from.encode(e)?;
            e.u64(self.tid)?;
            e.count(self.buffers_read.len())?;
            for (h, items) in &self.buffers_read {
                h.encode(e)?;
                e.count(items.len())?;
                for (off, b) in items {
                    e.u64(*off)?;
                    if v3 {
                        e.u32(u32::try_from(b.len() + more).map_err(|_| Error::TooLong)?)?;
                        if single.is_none() {
                            data.extend_from_slice(b);
                        }
                    } else {
                        e.bytes(b)?;
                    }
                }
            }
            self.attrs_read.encode(e)?;
            self.errors.encode(e)?;
            if v3 {
                self.omap_headers_read.encode(e)?;
                self.omap_entries_read.encode(e)?;
                self.omaps_complete.encode(e)?;
            }
            Ok(())
        })?;
        Ok(single.unwrap_or_else(|| data.into()))
    }

    fn decode_from(d: &mut Decoder<'_>, data: &Bytes) -> Result<Self> {
        // struct_v 1..; refused only when struct_compat exceeds the version this decoder reads (3), as for ECSubRead
        d.versioned_min(1, 3, |d, v| {
            let from = PgShard::decode(d)?;
            let tid = d.u64()?;
            let mut buffers_read: BTreeMap<Hobject, Vec<(u64, Bytes)>> = BTreeMap::new();
            if v >= 2 {
                let n = d.count()?;
                let mut pos = 0usize;
                for _ in 0..n {
                    let h = Hobject::decode(d)?;
                    let m = d.count()?;
                    let mut items = Vec::with_capacity(m.min(1024));
                    for _ in 0..m {
                        let off = d.u64()?;
                        let len = d.u32()? as usize;
                        let end = pos.checked_add(len).ok_or(Error::TooLong)?;
                        if end > data.len() {
                            return Err(Error::BadLength {
                                len: len as u64,
                                remaining: data.len() - pos,
                            });
                        }
                        items.push((off, data.slice(pos..end)));
                        pos = end;
                    }
                    buffers_read.insert(h, items);
                }
            } else {
                let n = d.count()?;
                for _ in 0..n {
                    let h = Hobject::decode(d)?;
                    let m = d.count()?;
                    let mut items = Vec::with_capacity(m.min(1024));
                    for _ in 0..m {
                        let off = d.u64()?;
                        items.push((off, Bytes::copy_from_slice(d.bytes()?)));
                    }
                    buffers_read.insert(h, items);
                }
            }
            let attrs_read = BTreeMap::decode(d)?;
            let errors = BTreeMap::decode(d)?;
            let (omap_headers_read, omap_entries_read, omaps_complete) = if v >= 3 {
                (
                    BTreeMap::decode(d)?,
                    BTreeMap::decode(d)?,
                    BTreeMap::decode(d)?,
                )
            } else {
                Default::default()
            };
            // only what the omap fields do not already imply (re-encodes as v3)
            let data_segment = v >= 2
                && omap_headers_read.is_empty()
                && omap_entries_read.is_empty()
                && omaps_complete.is_empty();
            Ok(ECSubReadReply {
                from,
                tid,
                buffers_read,
                attrs_read,
                errors,
                omap_headers_read,
                omap_entries_read,
                omaps_complete,
                data_segment,
                data_crc: Default::default(),
                data_more: Vec::new(),
                data_more_sent: 0,
            })
        })
    }
}

/// MOSDECSubOpReadReply (111, head 2, compat 1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MOSDECSubOpReadReply {
    pub pgid: SpgT,
    pub map_epoch: u32,
    pub op: ECSubReadReply,
    pub min_epoch: u32,
    pub trace: [i64; 3],
}

impl MOSDECSubOpReadReply {
    /// Decode keeping the DATA segment as a shared slice (no copy of the chunk bytes for struct v>=2).
    pub fn decode_shared(version: u16, front: &[u8], data: &Bytes) -> Result<Self> {
        let mut d = Decoder::new(front);
        let pgid = SpgT::decode(&mut d)?;
        let map_epoch = d.u32()?;
        let op = ECSubReadReply::decode_from(&mut d, data)?;
        let min_epoch = if version >= 2 { d.u32()? } else { map_epoch };
        let trace = get_trace(&mut d)?;
        Ok(MOSDECSubOpReadReply {
            pgid,
            map_epoch,
            op,
            min_epoch,
            trace,
        })
    }
}

impl Message for MOSDECSubOpReadReply {
    meta!(111, 2, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        let mut data = Bytes::new();
        let front = front_with(f, |e| {
            self.pgid.encode(e)?;
            e.u32(self.map_epoch)?;
            data = self.op.encode_into(e)?;
            e.u32(self.min_epoch)?;
            put_trace(e, &self.trace)
        })?;
        Ok(Segments {
            front_zc: Vec::new(),
            front_hints: Default::default(),
            front,
            middle: Vec::new(),
            data,
        })
    }
    fn decode(version: u16, front: &[u8], _m: &[u8], data: &[u8]) -> Result<Self> {
        Self::decode_shared(version, front, &Bytes::copy_from_slice(data))
    }
}

impl ECSubRead {
    /// The struct alone (envelope included).
    pub fn to_struct_bytes(&self) -> Result<Vec<u8>> {
        front_with(0, |e| self.encode_into(e))
    }
    pub fn from_struct_bytes(buf: &[u8]) -> Result<Self> {
        Self::decode_from(&mut Decoder::new(buf))
    }
}

impl ECSubReadReply {
    /// The struct alone plus the DATA segment bytes (non-empty only for struct v3).
    pub fn to_struct_bytes(&self) -> Result<(Vec<u8>, Bytes)> {
        let mut data = Bytes::new();
        let b = front_with(0, |e| {
            data = self.encode_into(e)?;
            Ok(())
        })?;
        Ok((b, data))
    }
    pub fn from_struct_bytes(buf: &[u8], data: &Bytes) -> Result<Self> {
        Self::decode_from(&mut Decoder::new(buf), data)
    }
}
