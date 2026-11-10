// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Class `fifo` (spec/cls_fifo.md): append-only log striped over part objects with a head meta
//! object. Persisted bytes are classic's (info in the meta object data, part header at offset 0 of
//! a part, entries from offset 512).

use crate::ctx::{ClsCtx, rand_armor};
use crate::env_struct;
use crate::errno::*;
use crate::registry::Reply;
use denc::types::UTime;
use denc::{BufMut, Decode, Decoder, Encode, Encoder};
use std::collections::BTreeSet;

pub const PART_HEADER_SIZE: u64 = 512;
/// 44-byte pre-header + 14-byte entry header.
pub const ENTRY_OVERHEAD: u64 = PRE_SIZE as u64 + 14;
pub const MAX_LIST_ENTRIES: i32 = 512;
const PRE_SIZE: usize = 44;
const EFAULT: Errno = -14;
const PREFETCH: u64 = 128 * 1024;
/// Sanity cap for a stored `next_ofs` (corrupt header guard, deviation from classic).
const MAX_NEXT_OFS: u64 = 1 << 32;

pub const OP_CREATE: i32 = 1;
pub const OP_SET_HEAD: i32 = 2;
pub const OP_REMOVE: i32 = 3;

// ---------------------------------------------------------------- types

env_struct!(
    /// `objv`
    Objv (1, 1) { instance: Vec<u8>, ver: u64 });
env_struct!(
    /// `data_params`
    DataParams (1, 1) { max_part_size: u64, max_entry_size: u64, full_size_threshold: u64 });

/// `journal_entry` (1,1); the part tag is always empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct JournalEntry {
    pub op: i32,
    pub part_num: i64,
}
impl JournalEntry {
    pub fn valid(&self) -> bool {
        (OP_CREATE..=OP_REMOVE).contains(&self.op) && self.part_num >= 0
    }
}
impl Encode for JournalEntry {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(1, 1, |e| {
            e.i32(self.op)?;
            e.i64(self.part_num)?;
            e.bytes(b"")
        })
    }
}
impl<'a> Decode<'a> for JournalEntry {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(1, |d, _| {
            let x = JournalEntry {
                op: d.i32()?,
                part_num: d.i64()?,
            };
            d.bytes()?;
            Ok(x)
        })
    }
}

/// `info` (1,1): value of the meta object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    pub id: Vec<u8>,
    pub version: Objv,
    pub oid_prefix: Vec<u8>,
    pub params: DataParams,
    pub tail_part_num: i64,
    pub head_part_num: i64,
    pub min_push_part_num: i64,
    pub max_push_part_num: i64,
    pub journal: BTreeSet<JournalEntry>,
}
impl Default for Info {
    fn default() -> Self {
        Info {
            id: Vec::new(),
            version: Objv::default(),
            oid_prefix: Vec::new(),
            params: DataParams::default(),
            tail_part_num: 0,
            head_part_num: -1,
            min_push_part_num: 0,
            max_push_part_num: -1,
            journal: BTreeSet::new(),
        }
    }
}
impl Encode for Info {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(1, 1, |e| {
            self.id.encode(e)?;
            self.version.encode(e)?;
            self.oid_prefix.encode(e)?;
            self.params.encode(e)?;
            e.i64(self.tail_part_num)?;
            e.i64(self.head_part_num)?;
            e.i64(self.min_push_part_num)?;
            e.i64(self.max_push_part_num)?;
            e.count(0)?; // tags: always empty
            e.bytes(b"")?; // head_tag
            e.count(self.journal.len())?;
            for j in &self.journal {
                e.i64(j.part_num)?;
                j.encode(e)?;
            }
            Ok(())
        })
    }
}
impl<'a> Decode<'a> for Info {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(1, |d, _| {
            let mut i = Info {
                id: Vec::<u8>::decode(d)?,
                version: Objv::decode(d)?,
                oid_prefix: Vec::<u8>::decode(d)?,
                params: DataParams::decode(d)?,
                tail_part_num: d.i64()?,
                head_part_num: d.i64()?,
                min_push_part_num: d.i64()?,
                max_push_part_num: d.i64()?,
                journal: BTreeSet::new(),
            };
            let n = d.count()?;
            for _ in 0..n {
                d.i64()?;
                Vec::<u8>::decode(d)?;
            }
            d.bytes()?; // head_tag
            let n = d.count()?;
            for _ in 0..n {
                d.i64()?;
                let j = JournalEntry::decode(d)?;
                if !j.valid() {
                    return Err(denc::Error::BadValue("fifo journal entry"));
                }
                i.journal.insert(j);
            }
            Ok(i)
        })
    }
}

/// `part_header` (1,1): at offset 0 of a part object.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PartHeader {
    pub params: DataParams,
    pub magic: u64,
    pub min_ofs: u64,
    pub last_ofs: u64,
    pub next_ofs: u64,
    pub min_index: u64,
    pub max_index: u64,
    pub max_time: UTime,
}
impl PartHeader {
    pub fn full(&self) -> bool {
        self.next_ofs > self.params.full_size_threshold
    }
}
impl Encode for PartHeader {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(1, 1, |e| {
            e.bytes(b"")?; // tag
            self.params.encode(e)?;
            e.u64(self.magic)?;
            e.u64(self.min_ofs)?;
            e.u64(self.last_ofs)?;
            e.u64(self.next_ofs)?;
            e.u64(self.min_index)?;
            e.u64(self.max_index)?;
            self.max_time.encode(e)
        })
    }
}
impl<'a> Decode<'a> for PartHeader {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(1, |d, _| {
            d.bytes()?;
            Ok(PartHeader {
                params: DataParams::decode(d)?,
                magic: d.u64()?,
                min_ofs: d.u64()?,
                last_ofs: d.u64()?,
                next_ofs: d.u64()?,
                min_index: d.u64()?,
                max_index: d.u64()?,
                max_time: UTime::decode(d)?,
            })
        })
    }
}

env_struct!(
/// `op::create_meta`; the pool name/namespace are ignored by the server.
CreateMetaOp (1, 1) {
    id: Vec<u8>,
    version: Option<Objv>,
    pool_name: Vec<u8>,
    pool_ns: Vec<u8>,
    oid_prefix: Option<Vec<u8>>,
    max_part_size: u64,
    max_entry_size: u64,
    exclusive: bool,
});
env_struct!(GetMetaOp (1, 1) { version: Option<Objv> });
env_struct!(GetMetaReply (1, 1) { info: Info, part_header_size: u32, part_entry_overhead: u32 });
env_struct!(
UpdateMetaOp (1, 1) {
    version: Objv,
    tail_part_num: Option<u64>,
    head_part_num: Option<u64>,
    min_push_part_num: Option<u64>,
    max_push_part_num: Option<u64>,
    journal_entries_add: Vec<JournalEntry>,
    journal_entries_rm: Vec<JournalEntry>,
});
env_struct!(InitPartOp (1, 1) { tag: Vec<u8>, params: DataParams });
env_struct!(PushPartOp (1, 1) { tag: Vec<u8>, data_bufs: Vec<Vec<u8>>, total_len: u64 });
env_struct!(TrimPartOp (1, 1) { tag: Option<Vec<u8>>, ofs: u64, exclusive: bool });
env_struct!(ListPartOp (1, 1) { tag: Option<Vec<u8>>, ofs: u64, max_entries: i32 });
env_struct!(PartListEntry (1, 1) { data: Vec<u8>, ofs: u64, mtime: UTime });
env_struct!(ListPartReply (1, 1) {
    tag: Vec<u8>, entries: Vec<PartListEntry>, more: bool, full_part: bool });
env_struct!(GetPartInfoOp (1, 1) {});
env_struct!(GetPartInfoReply (1, 1) { header: PartHeader });

// ---------------------------------------------------------------- helpers

fn write_header<C: ClsCtx>(c: &mut C, i: &mut Info) -> Result<(), Errno> {
    if i.version.instance.is_empty() {
        i.version.instance = rand_armor(c, 15);
    }
    c.write_full(&enc(i)?)
}

/// `read_header` of the meta object; empty object -> `ENODATA`; version mismatch -> `ECANCELED`.
fn read_header<C: ClsCtx>(c: &mut C, want: Option<&Objv>) -> Result<Info, Errno> {
    let size = c.stat()?.size;
    if size == 0 {
        return Err(ENODATA);
    }
    let b = c.read(0, size)?;
    if b.is_empty() {
        return Err(ENODATA);
    }
    let i: Info = dec_stored(&b)?;
    if let Some(w) = want
        && i.version != *w
    {
        return Err(ECANCELED);
    }
    Ok(i)
}

fn read_part_header<C: ClsCtx>(c: &mut C) -> Result<PartHeader, Errno> {
    dec_stored(&c.read(0, PART_HEADER_SIZE)?)
}

fn write_part_header<C: ClsCtx>(c: &mut C, h: &PartHeader) -> Result<(), Errno> {
    let b = enc(h)?;
    if b.len() as u64 > PART_HEADER_SIZE {
        return Err(EIO);
    }
    c.write(0, &b)
}

fn entry_header_bytes(now: UTime) -> Result<Vec<u8>, Errno> {
    let mut e = Encoder::new();
    e.versioned(1, 1, |e| now.encode(e)).eio()?;
    Ok(e.into_vec())
}

struct Pre {
    pre_size: u64,
    header_size: u64,
    data_size: u64,
    index: u64,
}

impl Pre {
    /// Pre-header at the start of `b` (>= PRE_SIZE bytes); a foreign magic is `-ERANGE`.
    fn parse(b: &[u8], magic: u64) -> Result<Pre, Errno> {
        let rd = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap_or([0; 8]));
        if rd(0) != magic {
            return Err(ERANGE);
        }
        Ok(Pre {
            pre_size: rd(8),
            header_size: rd(16),
            data_size: rd(24),
            index: rd(32),
        })
    }
}

/// Entry reader over a part: `buf[pos..]` are the bytes at `ofs`. Refill rule (spec cls_fifo.md):
/// a short buffer gets ONE read of PREFETCH bytes, still short = `-ERANGE`. Consumed bytes are
/// dropped only on a refill (one move per refill, none per entry).
struct Reader<'h> {
    h: &'h PartHeader,
    ofs: u64,
    buf: Vec<u8>,
    pos: usize,
}
impl<'h> Reader<'h> {
    fn new(h: &'h PartHeader, ofs: u64) -> Self {
        Reader {
            h,
            ofs: ofs.max(h.min_ofs),
            buf: Vec::new(),
            pos: 0,
        }
    }
    fn end(&self) -> bool {
        self.ofs >= self.h.next_ofs
    }
    fn buffered(&self) -> u64 {
        (self.buf.len() - self.pos) as u64
    }
    fn fetch<C: ClsCtx>(&mut self, c: &mut C, n: u64) -> Result<(), Errno> {
        if self.buffered() < n {
            let at = self.ofs.saturating_add(self.buffered());
            let more = c.read(at, PREFETCH)?;
            self.buf.drain(..self.pos);
            self.pos = 0;
            self.buf.extend_from_slice(&more);
        }
        if n > self.buffered() {
            return Err(ERANGE);
        }
        Ok(())
    }
    /// Consume `n` bytes; returns their range in `buf` (valid until the next fetch).
    fn take<C: ClsCtx>(&mut self, c: &mut C, n: u64) -> Result<std::ops::Range<usize>, Errno> {
        self.fetch(c, n)?;
        let r = self.pos..self.pos + n as usize;
        self.pos = r.end;
        self.ofs = self.ofs.saturating_add(n);
        Ok(r)
    }
    fn peek_pre<C: ClsCtx>(&mut self, c: &mut C) -> Result<Pre, Errno> {
        if self.end() {
            return Err(ENOENT);
        }
        self.fetch(c, PRE_SIZE as u64)?;
        Pre::parse(&self.buf[self.pos..], self.h.magic)
    }
    /// Returns (entry start offset, mtime, data if `want_data`).
    fn next_entry<C: ClsCtx>(
        &mut self,
        c: &mut C,
        want_data: bool,
    ) -> Result<(u64, UTime, Vec<u8>), Errno> {
        let p = self.peek_pre(c)?;
        let start = self.ofs;
        self.take(c, p.pre_size)?;
        let hr = self.take(c, p.header_size)?;
        let mtime: UTime = {
            let mut d = Decoder::new(&self.buf[hr]);
            d.versioned(1, |d, _| UTime::decode(d)).eio()?
        };
        let dr = self.take(c, p.data_size)?;
        let data = if want_data {
            self.buf[dr].to_vec()
        } else {
            Vec::new()
        };
        Ok((start, mtime, data))
    }
}

// ---------------------------------------------------------------- methods

pub fn create_meta<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: CreateMetaOp = dec_op(input)?;
    if op.id.is_empty()
        || op.max_part_size == 0
        || op.max_entry_size == 0
        || op.max_entry_size > op.max_part_size
    {
        return Err(EINVAL);
    }
    let size = match c.stat() {
        Ok(s) => Some(s.size),
        Err(ENOENT) => None,
        Err(e) => return Err(e),
    };
    if let Some(size) = size {
        if op.exclusive {
            return Err(EEXIST);
        }
        let i: Info = dec_stored(&c.read(0, size)?)?;
        let same = i.id == op.id
            && op.oid_prefix.as_ref().is_none_or(|p| *p == i.oid_prefix)
            && op.version.as_ref().is_none_or(|v| *v == i.version);
        return if same { Ok(Vec::new()) } else { Err(EEXIST) };
    }
    let mut i = Info {
        id: op.id.clone(),
        ..Default::default()
    };
    i.version = match op.version {
        Some(v) => v,
        None => Objv {
            instance: rand_armor(c, 16),
            ver: 1,
        },
    };
    i.oid_prefix = match op.oid_prefix {
        Some(p) => p,
        None => [op.id.as_slice(), b".", &rand_armor(c, 11)].concat(),
    };
    i.params = DataParams {
        max_part_size: op.max_part_size,
        max_entry_size: op.max_entry_size,
        full_size_threshold: op
            .max_part_size
            .wrapping_sub(op.max_entry_size)
            .wrapping_sub(ENTRY_OVERHEAD),
    };
    write_header(c, &mut i)?;
    Ok(Vec::new())
}

pub fn get_meta<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: GetMetaOp = dec_op(input)?;
    let info = read_header(c, op.version.as_ref())?;
    enc(&GetMetaReply {
        info,
        part_header_size: PART_HEADER_SIZE as u32,
        part_entry_overhead: ENTRY_OVERHEAD as u32,
    })
}

pub fn update_meta<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: UpdateMetaOp = dec_op(input)?;
    if op.version.instance.is_empty() || op.journal_entries_add.iter().any(|j| !j.valid()) {
        return Err(EINVAL);
    }
    let mut h = read_header(c, Some(&op.version))?;
    let mut changed = false;
    if let Some(t) = op.tail_part_num
        && h.tail_part_num != t as i64
    {
        h.tail_part_num = t as i64;
        changed = true;
    }
    if let Some(t) = op.min_push_part_num
        && h.min_push_part_num != t as i64
    {
        h.min_push_part_num = t as i64;
        changed = true;
    }
    if let Some(t) = op.max_push_part_num
        && h.max_push_part_num != t as i64
    {
        h.max_push_part_num = t as i64;
        changed = true;
    }
    for j in &op.journal_entries_add {
        changed |= h.journal.insert(*j);
    }
    for j in &op.journal_entries_rm {
        changed |= h.journal.remove(j);
    }
    if let Some(t) = op.head_part_num
        && h.head_part_num != t as i64
    {
        h.head_part_num = t as i64;
        changed = true;
    }
    if changed {
        h.version.ver = h.version.ver.wrapping_add(1);
        write_header(c, &mut h)?;
    }
    Ok(())
}

pub fn init_part<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: InitPartOp = dec_op(input)?;
    match c.stat() {
        Ok(s) if s.size > 0 => {
            let h = read_part_header(c)?;
            return if h.params == op.params {
                Ok(Vec::new())
            } else {
                Err(EEXIST)
            };
        }
        Ok(_) | Err(ENOENT) => {}
        Err(e) => return Err(e),
    }
    let mut m = [0u8; 8];
    c.random_bytes(&mut m);
    let h = PartHeader {
        params: op.params,
        magic: u64::from_le_bytes(m),
        min_ofs: PART_HEADER_SIZE,
        last_ofs: 0,
        next_ofs: PART_HEADER_SIZE,
        max_time: c.now(),
        ..Default::default()
    };
    write_part_header(c, &h)?;
    Ok(Vec::new())
}

/// Returns the number of entries pushed as the (positive) method return value.
pub fn push_part<C: ClsCtx>(c: &mut C, input: &[u8]) -> Reply {
    match push_part_inner(c, input) {
        Ok(n) => Reply {
            ret: n,
            out: Vec::new(),
        },
        Err(e) => Reply {
            ret: e,
            out: Vec::new(),
        },
    }
}

fn push_part_inner<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<i32, Errno> {
    let op: PushPartOp = dec_op(input)?;
    let mut h = read_part_header(c)?;
    let eff = op
        .total_len
        .wrapping_add((op.data_bufs.len() as u64).wrapping_mul(ENTRY_OVERHEAD));
    if eff > h.params.max_part_size {
        return Err(EINVAL);
    }
    if h.full() {
        return Err(ERANGE);
    }
    let total: u64 = op.data_bufs.iter().map(|b| b.len() as u64).sum();
    if total != op.total_len {
        return Err(EINVAL);
    }
    if h.next_ofs > MAX_NEXT_OFS {
        return Err(EIO);
    }
    let now = c.now();
    let eh = entry_header_bytes(now)?;
    let write_ofs = h.next_ofs;
    let mut all = Vec::new();
    let mut pushed = 0i32;
    for data in &op.data_bufs {
        if h.full() {
            break;
        }
        all.extend_from_slice(&h.magic.to_le_bytes());
        all.extend_from_slice(&(PRE_SIZE as u64).to_le_bytes());
        all.extend_from_slice(&(eh.len() as u64).to_le_bytes());
        all.extend_from_slice(&(data.len() as u64).to_le_bytes());
        all.extend_from_slice(&h.max_index.to_le_bytes());
        all.extend_from_slice(&0u32.to_le_bytes());
        all.extend_from_slice(&eh);
        all.extend_from_slice(data);
        h.last_ofs = h.next_ofs;
        h.next_ofs += (PRE_SIZE + eh.len() + data.len()) as u64;
        h.max_index += 1;
        pushed += 1;
    }
    h.max_time = now;
    if pushed == 0 {
        return Err(EFAULT);
    }
    c.write(write_ofs, &all)?;
    write_part_header(c, &h)?;
    Ok(pushed)
}

pub fn trim_part<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: TrimPartOp = dec_op(input)?;
    let mut h = read_part_header(c)?;
    if op.ofs < h.min_ofs || (op.exclusive && op.ofs == h.min_ofs) {
        return Ok(());
    }
    if op.ofs >= h.next_ofs {
        if h.full() {
            c.remove()?;
            return Ok(());
        }
        h.min_ofs = h.next_ofs;
        h.min_index = h.max_index;
    } else {
        if op.exclusive {
            // only the pre-header at `ofs` (op.ofs >= min_ofs here, so the reader would not move it)
            let b = c.read(op.ofs, PRE_SIZE as u64)?;
            if b.len() < PRE_SIZE {
                return Err(ERANGE);
            }
            h.min_index = Pre::parse(&b, h.magic)?.index;
            h.min_ofs = op.ofs;
        } else {
            let hc = h.clone();
            let mut r = Reader::new(&hc, op.ofs);
            let pre = r.peek_pre(c)?;
            r.next_entry(c, false)?;
            h.min_index = pre.index.wrapping_add(1);
            h.min_ofs = r.ofs;
        }
    }
    write_part_header(c, &h)?;
    Ok(())
}

pub fn part_list<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: ListPartOp = dec_op(input)?;
    let h = read_part_header(c)?;
    let mut r = Reader::new(&h, op.ofs);
    if op.ofs >= h.min_ofs && !r.end() {
        r.next_entry(c, false)?;
    }
    let mut reply = ListPartReply::default();
    let max = op.max_entries.min(MAX_LIST_ENTRIES);
    let mut i = 0;
    while i < max && !r.end() {
        let (ofs, mtime, data) = r.next_entry(c, true)?;
        reply.entries.push(PartListEntry { data, ofs, mtime });
        i += 1;
    }
    reply.more = !r.end();
    reply.full_part = h.full();
    enc(&reply)
}

pub fn get_part_info<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let _: GetPartInfoOp = dec_op(input)?;
    let header = read_part_header(c)?;
    enc(&GetPartInfoReply { header })
}
