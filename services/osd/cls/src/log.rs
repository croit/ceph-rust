// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Class `log` (spec/cls_log.md): timestamp-ordered omap log (RGW mdlog / datalog omap backend).
//! Keys `1_<sec:010>.<usec:06>_<suffix>`, values = enveloped entries, header = max marker/time.

use crate::ctx::ClsCtx;
use crate::env_struct;
use crate::errno::*;
use denc::types::UTime;
use denc::{BufMut, Decode, Decoder, Encode, Encoder};

pub const PREFIX: &[u8] = b"1_";
/// Entries returned per `list` call at most.
pub const MAX_LIST: usize = 1000;

/// `cls::log::entry` (2,1): id is the omap key it is stored under. Timestamps are `real_time`
/// (decoded as a nanosecond count): nsec >= 1e9 carries into sec, as classic re-encodes them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Entry {
    pub id: Vec<u8>,
    pub section: Vec<u8>,
    pub name: Vec<u8>,
    pub timestamp: UTime,
    pub data: Vec<u8>,
}
impl Encode for Entry {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(2, 1, |e| {
            self.section.encode(e)?;
            self.name.encode(e)?;
            self.timestamp.encode(e)?;
            self.data.encode(e)?;
            self.id.encode(e)
        })
    }
}
impl<'a> Decode<'a> for Entry {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(2, |d, v| {
            let mut x = Entry {
                section: Vec::<u8>::decode(d)?,
                name: Vec::<u8>::decode(d)?,
                timestamp: UTime::decode(d)?.normalized(),
                data: Vec::<u8>::decode(d)?,
                ..Default::default()
            };
            if v >= 2 {
                x.id = Vec::<u8>::decode(d)?;
            }
            Ok(x)
        })
    }
}

env_struct!(
    /// `cls::log::header` (1,1): omap header.
    Header (1, 1) { max_marker: Vec<u8>, max_time: UTime });

/// `cls::log::ops::add_op` (2,1): `monotonic_inc` defaults to TRUE (also for v1 encodings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddOp {
    pub entries: Vec<Entry>,
    pub monotonic_inc: bool,
}
impl Default for AddOp {
    fn default() -> Self {
        AddOp {
            entries: Vec::new(),
            monotonic_inc: true,
        }
    }
}
impl Encode for AddOp {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(2, 1, |e| {
            self.entries.encode(e)?;
            e.bool(self.monotonic_inc)
        })
    }
}
impl<'a> Decode<'a> for AddOp {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(2, |d, v| {
            let mut x = AddOp {
                entries: Vec::decode(d)?,
                ..Default::default()
            };
            if v >= 2 {
                x.monotonic_inc = d.bool()?;
            }
            Ok(x)
        })
    }
}

env_struct!(
    /// `list_op` (1,1)
    ListOp (1, 1) { from_time: UTime, marker: Vec<u8>, to_time: UTime, max_entries: i32 });
env_struct!(
    /// `list_ret` (1,1)
    ListRet (1, 1) { entries: Vec<Entry>, marker: Vec<u8>, truncated: bool });
env_struct!(
    /// `info_op` (1,1): empty body.
    InfoOp (1, 1) {});
env_struct!(
    /// `info_ret` (1,1)
    InfoRet (1, 1) { header: Header });

/// `trim_op` (2,1): the marker fields exist from v2.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrimOp {
    pub from_time: UTime,
    pub to_time: UTime,
    pub from_marker: Vec<u8>,
    pub to_marker: Vec<u8>,
}
impl Encode for TrimOp {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(2, 1, |e| {
            self.from_time.encode(e)?;
            self.to_time.encode(e)?;
            self.from_marker.encode(e)?;
            self.to_marker.encode(e)
        })
    }
}
impl<'a> Decode<'a> for TrimOp {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(2, |d, v| {
            let mut x = TrimOp {
                from_time: UTime::decode(d)?.normalized(),
                to_time: UTime::decode(d)?.normalized(),
                ..Default::default()
            };
            if v >= 2 {
                x.from_marker = Vec::<u8>::decode(d)?;
                x.to_marker = Vec::<u8>::decode(d)?;
            }
            Ok(x)
        })
    }
}

/// `1_%010ld.%06ld_` of the timestamp (nanoseconds truncated to microseconds).
pub fn time_prefix(t: UTime) -> Vec<u8> {
    format!("1_{:010}.{:06}_", t.sec, t.nsec / 1000).into_bytes()
}

/// Header read: empty/absent -> default; an undecodable header is ignored (default, no error).
fn read_header<C: ClsCtx>(c: &mut C) -> Result<Header, Errno> {
    let b = c.omap_get_header()?;
    if b.is_empty() {
        return Ok(Header::default());
    }
    Ok(Header::decode(&mut Decoder::new(&b)).unwrap_or_default())
}

pub fn add<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let mut op: AddOp = dec_op(input)?;
    let mut h = read_header(c)?;
    for e in &mut op.entries {
        let mut ts = e.timestamp;
        if op.monotonic_inc && ts < h.max_time {
            ts = h.max_time;
        } else if ts > h.max_time {
            h.max_time = ts;
        }
        let key: Vec<u8> = if e.id.is_empty() {
            // unique suffix `<pg last_user_version>.<subop>`
            let mut k = time_prefix(ts);
            k.extend_from_slice(format!("{}.{}", c.current_version(), c.subop_num()).as_bytes());
            e.id = k.clone();
            k
        } else {
            e.id.clone()
        };
        if key.as_slice() > h.max_marker.as_slice() {
            h.max_marker = key.clone();
        }
        c.omap_set(&[(&key, &enc(e)?)])?;
    }
    c.omap_set_header(&enc(&h)?)?;
    Ok(())
}

/// First `to.len()` bytes of `key` compared with `to` (`key.compare(0, n, to)`).
pub(crate) fn prefix_cmp(key: &[u8], to: &[u8]) -> std::cmp::Ordering {
    key[..key.len().min(to.len())].cmp(to)
}

pub fn list<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let mut op: ListOp = dec_op(input)?;
    op.from_time = op.from_time.normalized();
    op.to_time = op.to_time.normalized();
    let from = if op.marker.is_empty() {
        time_prefix(op.from_time)
    } else {
        op.marker.clone()
    };
    let boundary = op.from_time != UTime::default() && op.to_time >= op.from_time;
    let to = if boundary {
        time_prefix(op.to_time)
    } else {
        Vec::new()
    };
    let max = if op.max_entries <= 0 || op.max_entries as usize > MAX_LIST {
        MAX_LIST
    } else {
        op.max_entries as usize
    };
    let (vals, more) = c.omap_get_vals(&from, PREFIX, max as u64)?;
    let mut ret = ListRet {
        truncated: more,
        ..Default::default()
    };
    for (k, v) in &vals {
        ret.marker = k.clone();
        if boundary && prefix_cmp(k, &to).is_ge() {
            ret.truncated = false;
            break;
        }
        // an undecodable entry is skipped, the marker still advances
        if let Ok(e) = Entry::decode(&mut Decoder::new(v)) {
            ret.entries.push(e);
        }
    }
    enc(&ret)
}

pub fn trim<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: TrimOp = dec_op(input)?;
    let from = if op.from_marker.is_empty() {
        time_prefix(op.from_time)
    } else {
        op.from_marker.clone()
    };
    // exclusive end: to_time + 1000 us (upstream comment says 1 us; reproduced), or marker + NUL
    let to = if op.to_marker.is_empty() {
        let t = UTime::new(op.to_time.sec, op.to_time.nsec + 1_000_000).normalized();
        time_prefix(t)
    } else {
        let mut k = op.to_marker.clone();
        k.push(0);
        k
    };
    let (ks, _) = c.omap_get_keys(&from, 1)?;
    let Some(first) = ks.into_iter().next() else {
        return Err(ENODATA);
    };
    if to < first {
        return Err(ENODATA);
    }
    c.omap_remove_range(&first, &to)?;
    Ok(())
}

pub fn info<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let _: InfoOp = dec_op(input)?;
    let header = read_header(c)?;
    enc(&InfoRet { header })
}
