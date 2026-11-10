// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Class `queue` and the ring-buffer engine behind it (spec/cls_queue.md). Also used by `rgw_gc`
//! (and later `2pc_queue`).
//!
//! The queue lives in the object DATA: a head block `[0, max_head_size)` (`0xDEAD`, u64 length,
//! encoded [`Head`]) followed by a circular byte ring `[max_head_size, queue_size)` of entries
//! (`0xBEEF`, u64 length, payload). An entry may straddle the physical end of the ring. Markers
//! are `"<gen>/<offset>"`; the generation counts wraps. Bytes on disk are identical to classic
//! (classic OSDs and tools read/write the same object after failover).
//!
//! Engine rules (own formulation): positions are linear `gen * ring + (offset - max_head)`;
//! `front <= tail <= front + ring`; free space = ring - (tail - front). Upstream quirks NOT
//! copied: a multi-entry batch is checked per entry against the real free space (upstream could
//! overwrite the front after an exactly-filling entry).

use crate::ctx::ClsCtx;
use crate::env_struct;
use crate::errno::*;
use denc::{BufMut, Decode, Decoder, Encode, Encoder};
use std::borrow::Cow;

pub const HEAD_MAGIC: u16 = 0xDEAD;
pub const ENTRY_MAGIC: u16 = 0xBEEF;
/// u16 magic + u64 length
pub const ENTRY_OVERHEAD: u64 = 10;
pub const HEAD_SIZE_1K: u64 = 1024;
const PAGE: u64 = 4096;

/// `cls_queue_marker` (1,1): generation FIRST, then offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Marker {
    pub gen_: u64,
    pub offset: u64,
}
/// Longest decimal `"<gen>/<offset>"` text: two 20-digit u64 plus `/`.
pub const MARKER_MAX: usize = 41;

/// `v` in decimal, right-aligned to `end` in `out`; returns the first written index.
fn write_num(v: u64, out: &mut [u8; MARKER_MAX], end: usize) -> usize {
    let (mut i, mut v) = (end, v);
    loop {
        i -= 1;
        out[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            return i;
        }
    }
}
fn num(d: &[u8]) -> u64 {
    std::str::from_utf8(d)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}
impl Marker {
    /// Decimal `gen/offset` text in `out` (`out[MARKER_MAX - len..]`).
    fn text<'a>(&self, out: &'a mut [u8; MARKER_MAX]) -> &'a [u8] {
        let i = write_num(self.offset, out, MARKER_MAX) - 1;
        out[i] = b'/';
        let start = write_num(self.gen_, out, i);
        &out[start..]
    }
    /// Marker text bytes (classic form), one heap allocation for the returned value.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = [0u8; MARKER_MAX];
        self.text(&mut b).to_vec()
    }
    /// True if the marker text equals `raw`; no allocation (the `end_marker` compare of a scan).
    pub fn matches(&self, raw: &[u8]) -> bool {
        let mut b = [0u8; MARKER_MAX];
        self.text(&mut b) == raw
    }
    /// Lenient parse like strtoull: digits `/` digits; whatever parses is kept, the rest stays 0.
    pub fn parse(b: &[u8]) -> Marker {
        let mut m = Marker::default();
        let dig = |from: usize| b[from..].iter().take_while(|c| c.is_ascii_digit()).count();
        let n = dig(0);
        m.gen_ = num(&b[..n]);
        if b.get(n) == Some(&b'/') {
            let o = dig(n + 1);
            m.offset = num(&b[n + 1..n + 1 + o]);
        }
        m
    }
}
impl Encode for Marker {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(1, 1, |e| {
            e.u64(self.gen_)?;
            e.u64(self.offset)
        })
    }
}
impl<'a> Decode<'a> for Marker {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(1, |d, _| {
            Ok(Marker {
                gen_: d.u64()?,
                offset: d.u64()?,
            })
        })
    }
}

env_struct!(
/// `cls_queue_head` (1,1)
Head (1, 1) {
    max_head_size: u64,
    front: Marker,
    tail: Marker,
    queue_size: u64,
    max_urgent_data_size: u64,
    bl_urgent_data: Vec<u8>,
});

env_struct!(InitOp (1, 1) { queue_size: u64, max_urgent_data_size: u64, bl_urgent_data: Vec<u8> });
env_struct!(EnqueueOp (1, 1) { bl_data_vec: Vec<Vec<u8>> });
env_struct!(RemoveOp (1, 1) { end_marker: Vec<u8> });
env_struct!(GetCapacityRet (1, 1) { queue_capacity: u64 });
env_struct!(Entry (1, 1) { data: Vec<u8>, marker: Vec<u8> });
env_struct!(ListRet (1, 1) { is_truncated: bool, next_marker: Vec<u8>, entries: Vec<Entry> });

/// `cls_queue_list_op` (2,1): `end_marker` only in v2.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListOp {
    pub max: u64,
    pub start_marker: Vec<u8>,
    pub end_marker: Vec<u8>,
}
impl Encode for ListOp {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(2, 1, |e| {
            e.u64(self.max)?;
            self.start_marker.encode(e)?;
            self.end_marker.encode(e)
        })
    }
}
impl<'a> Decode<'a> for ListOp {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(2, |d, v| {
            Ok(ListOp {
                max: d.u64()?,
                start_marker: Vec::<u8>::decode(d)?,
                end_marker: if v >= 2 {
                    Vec::<u8>::decode(d)?
                } else {
                    Vec::new()
                },
            })
        })
    }
}

impl Head {
    fn ring(&self) -> u64 {
        self.queue_size.saturating_sub(self.max_head_size)
    }
    fn pos(&self, m: &Marker) -> u64 {
        m.gen_
            .wrapping_mul(self.ring())
            .wrapping_add(m.offset.wrapping_sub(self.max_head_size))
    }
    fn marker_at(&self, pos: u64) -> Marker {
        let r = self.ring().max(1);
        Marker {
            gen_: pos / r,
            offset: self.max_head_size.wrapping_add(pos % r),
        }
    }
    fn is_empty(&self) -> bool {
        self.front == self.tail
    }
}

/// Read `len` ring bytes starting at absolute object offset `off` (wrapping at `queue_size`).
/// Every byte of `[front, tail)` was written by an enqueue, so a short read (range beyond the
/// object end) means a corrupt head/entry -> `-EINVAL`. Nothing is preallocated from `len`
/// (stored, i.e. client-writable): memory is bounded by what the object really holds.
fn read_ring<C: ClsCtx>(c: &mut C, h: &Head, off: u64, len: u64) -> Result<Vec<u8>, Errno> {
    let first = len.min(h.queue_size.saturating_sub(off));
    let mut out = Vec::new();
    if first > 0 {
        out = c.read(off, first)?;
    }
    if len > first {
        out.extend(c.read(h.max_head_size, len - first)?);
    }
    if out.len() as u64 != len {
        return Err(EINVAL);
    }
    Ok(out)
}
fn write_ring<C: ClsCtx>(c: &mut C, h: &Head, off: u64, data: &[u8]) -> Result<(), Errno> {
    let first = (data.len() as u64).min(h.queue_size.saturating_sub(off)) as usize;
    c.write(off, &data[..first])?;
    if first < data.len() {
        c.write(h.max_head_size, &data[first..])?;
    }
    Ok(())
}

/// `queue_write_head`: `-EINVAL` if head + framing exceed `max_head_size`.
pub fn write_head<C: ClsCtx>(c: &mut C, h: &Head) -> Result<(), Errno> {
    let body = enc(h)?;
    let mut b = Vec::with_capacity(body.len() + 10);
    b.extend_from_slice(&HEAD_MAGIC.to_le_bytes());
    b.extend_from_slice(&(body.len() as u64).to_le_bytes());
    b.extend_from_slice(&body);
    if b.len() as u64 > h.max_head_size {
        return Err(EINVAL);
    }
    c.write(0, &b)
}

/// `queue_read_head`: empty object / bad magic / undecodable -> `-EINVAL`; read errors pass.
pub fn read_head<C: ClsCtx>(c: &mut C) -> Result<Head, Errno> {
    let mut b = c.read(0, PAGE)?;
    if b.is_empty() {
        return Err(EINVAL);
    }
    let mut d = Decoder::new(&b);
    let magic = d.u16().inval()?;
    if magic != HEAD_MAGIC {
        return Err(EINVAL);
    }
    let len = d.u64().inval()?;
    if len > PAGE - ENTRY_OVERHEAD {
        let more = c.read(PAGE, len - (PAGE - ENTRY_OVERHEAD))?;
        b.extend(more);
    }
    let body = b.get(10..).ok_or(EINVAL)?;
    Head::decode(&mut Decoder::new(body)).inval()
}

/// `queue_init`: `-EEXIST` if a valid head exists; garbage heads are overwritten.
pub fn init<C: ClsCtx>(c: &mut C, op: &InitOp) -> Result<(), Errno> {
    match read_head(c) {
        Ok(_) => return Err(EEXIST),
        Err(EINVAL) => {}
        Err(e) => return Err(e),
    }
    // client-supplied sizes: u64 arithmetic wraps like classic (no panic on overflow)
    let max_head = HEAD_SIZE_1K.wrapping_add(op.max_urgent_data_size);
    let h = Head {
        max_head_size: max_head,
        front: Marker {
            gen_: 0,
            offset: max_head,
        },
        tail: Marker {
            gen_: 0,
            offset: max_head,
        },
        queue_size: op.queue_size.wrapping_add(max_head),
        max_urgent_data_size: op.max_urgent_data_size,
        bl_urgent_data: op.bl_urgent_data.clone(),
    };
    write_head(c, &h)
}

/// Append entries (head is updated in memory; the caller writes it back). `-ENOSPC` if full.
pub fn enqueue<C: ClsCtx>(c: &mut C, h: &mut Head, entries: &[Vec<u8>]) -> Result<(), Errno> {
    let ring = h.ring();
    let used = |h: &Head| h.pos(&h.tail).saturating_sub(h.pos(&h.front));
    if used(h) >= ring {
        return Err(ENOSPC);
    }
    for data in entries {
        let frame = data.len() as u64 + ENTRY_OVERHEAD;
        if used(h).saturating_add(frame) > ring {
            return Err(ENOSPC);
        }
        let mut buf = Vec::with_capacity(frame as usize);
        buf.extend_from_slice(&ENTRY_MAGIC.to_le_bytes());
        buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
        buf.extend_from_slice(data);
        write_ring(c, h, h.tail.offset, &buf)?;
        h.tail = h.marker_at(h.pos(&h.tail).wrapping_add(frame));
    }
    Ok(())
}

/// Read-ahead over the ring for [`list`]: one store read per window instead of two per entry.
/// The window starts at 64 KiB and doubles up to [`LARGE_CHUNK`], never past `tail`. A range not
/// fully inside a freshly filled window (entry larger than the window, short store read) is read
/// exactly with [`read_ring`], so results and errors equal a per-entry exact read.
#[derive(Default)]
struct Window {
    start: u64,
    buf: Vec<u8>,
    next_len: u64,
}

impl Window {
    fn get<C: ClsCtx>(
        &mut self,
        c: &mut C,
        h: &Head,
        pos: u64,
        len: u64,
        tail_pos: u64,
    ) -> Result<Cow<'_, [u8]>, Errno> {
        let inside = |w: &Self| {
            pos >= w.start
                && pos
                    .checked_add(len)
                    .is_some_and(|e| e <= w.start + w.buf.len() as u64)
        };
        if !inside(self) {
            self.next_len = (self.next_len * 2).clamp(1 << 16, LARGE_CHUNK);
            let want = self.next_len.min(tail_pos.saturating_sub(pos));
            let off = h.marker_at(pos).offset;
            let first = want.min(h.queue_size.saturating_sub(off));
            self.start = pos;
            self.buf = if first > 0 {
                c.read(off, first)?
            } else {
                Vec::new()
            };
            if self.buf.len() as u64 == first && want > first {
                let rest = c.read(h.max_head_size, want - first)?;
                self.buf.extend(rest);
            }
            if !inside(self) {
                return Ok(Cow::Owned(read_ring(c, h, h.marker_at(pos).offset, len)?));
            }
        }
        let s = (pos - self.start) as usize;
        Ok(Cow::Borrowed(&self.buf[s..s + len as usize]))
    }
}

/// Result of [`list`].
#[derive(Debug)]
pub struct Listing {
    pub entries: Vec<Entry>,
    pub is_truncated: bool,
    pub next_marker: Vec<u8>,
}

/// `queue_list_entries`: up to `max` (0 = one chunk, see `list_max_zero`) entries from `start_marker` (empty/offset 0 =
/// front), stopping before an entry whose marker equals `end_marker`.
pub fn list<C: ClsCtx>(
    c: &mut C,
    h: &Head,
    max: u64,
    start_marker: &[u8],
    end_marker: &[u8],
) -> Result<Listing, Errno> {
    let done = |next: Marker| Listing {
        entries: Vec::new(),
        is_truncated: false,
        next_marker: next.to_bytes(),
    };
    if h.is_empty() {
        return Ok(done(h.front));
    }
    let start = Marker::parse(start_marker);
    let start = if start.offset == 0 { h.front } else { start };
    if start.offset < h.max_head_size || start.offset >= h.queue_size {
        return Err(EINVAL);
    }
    if max == 0 {
        return list_max_zero(c, h, start, end_marker);
    }
    let (front_pos, tail_pos) = (h.pos(&h.front), h.pos(&h.tail));
    let mut cur = h.pos(&start);
    if cur < front_pos || cur > tail_pos {
        return Ok(done(h.tail)); // start inside the free space
    }
    let mut out = Vec::new();
    let mut next = h.tail;
    let mut truncated = false;
    let mut win = Window::default();
    while cur < tail_pos {
        let m = h.marker_at(cur);
        if !end_marker.is_empty() && m.matches(end_marker) {
            next = m;
            truncated = true;
            break;
        }
        if max != 0 && out.len() as u64 >= max {
            next = m;
            truncated = true;
            break;
        }
        let hdr = win.get(c, h, cur, ENTRY_OVERHEAD, tail_pos)?;
        let magic = u16::from_le_bytes([hdr[0], hdr[1]]);
        let len = u64::from_le_bytes(hdr[2..10].try_into().unwrap_or([0; 8]));
        let avail = tail_pos - cur;
        if magic != ENTRY_MAGIC || avail < ENTRY_OVERHEAD || len > avail - ENTRY_OVERHEAD {
            return Err(EINVAL);
        }
        let data = win
            .get(c, h, cur.wrapping_add(ENTRY_OVERHEAD), len, tail_pos)?
            .into_owned();
        out.push(Entry {
            data,
            marker: m.to_bytes(),
        });
        cur += ENTRY_OVERHEAD + len;
    }
    if cur >= tail_pos {
        next = h.tail;
        truncated = false;
    } else if next == h.tail {
        truncated = false;
    }
    Ok(Listing {
        entries: out,
        is_truncated: truncated,
        next_marker: next.to_bytes(),
    })
}

const LARGE_CHUNK: u64 = 1 << 22;

/// `max == 0` (classic quirk, matched): classic's outer loop runs `while num_ops < max`, i.e. exactly
/// ONE chunk (`min(contiguous bytes, 4 MiB)` from the start offset, never across the ring end) is
/// scanned; entries not completely inside it are dropped. Afterwards `next_marker` stays `0/0` and
/// `truncated` stays true, unless the queue end was reached (next = tail, not truncated) or an
/// `end_marker` entry stopped the scan (next = end_marker).
fn list_max_zero<C: ClsCtx>(
    c: &mut C,
    h: &Head,
    start: Marker,
    end_marker: &[u8],
) -> Result<Listing, Errno> {
    let (so, tail_off, front_off) = (start.offset, h.tail.offset, h.front.offset);
    let mut wrap = false;
    let contiguous = if tail_off > front_off {
        tail_off.saturating_sub(so)
    } else if so >= front_off {
        wrap = true;
        h.queue_size.saturating_sub(so)
    } else {
        tail_off.saturating_sub(so)
    };
    let size = contiguous.min(LARGE_CHUNK);
    let mk = |next: Marker, truncated: bool| Listing {
        entries: Vec::new(),
        is_truncated: truncated && next != h.tail,
        next_marker: next.to_bytes(),
    };
    if size == 0 {
        return Ok(mk(h.tail, false));
    }
    let chunk = c.read(so, size)?;
    let (mut idx, mut out) = (0usize, Vec::new());
    let mut next = Marker { gen_: 0, offset: 0 };
    let mut stopped = false;
    while idx < chunk.len() {
        let rest = &chunk[idx..];
        if (rest.len() as u64) < ENTRY_OVERHEAD {
            break;
        }
        if u16::from_le_bytes([rest[0], rest[1]]) != ENTRY_MAGIC {
            return Err(EINVAL);
        }
        let len = u64::from_le_bytes(rest[2..10].try_into().unwrap_or([0; 8]));
        if len > rest.len() as u64 - ENTRY_OVERHEAD {
            break;
        }
        let marker = Marker {
            gen_: start.gen_,
            offset: so + idx as u64,
        };
        if !end_marker.is_empty() && marker.matches(end_marker) {
            next = marker;
            stopped = true;
            break;
        }
        let d = ENTRY_OVERHEAD as usize;
        out.push(Entry {
            data: rest[d..d + len as usize].to_vec(),
            marker: marker.to_bytes(),
        });
        idx += d + len as usize;
    }
    let mut truncated = true;
    if !stopped && size == contiguous && !wrap {
        next = h.tail;
        truncated = false;
    }
    let mut l = mk(next, truncated);
    l.entries = out;
    Ok(l)
}

/// Number of entries from the front up to (excluding) `end_marker`, without materializing payloads:
/// only each entry's pre-header is taken from the read-ahead [`Window`] (`2pc_queue_remove_entries`
/// counts a client-chosen range of a ring that can hold the whole client-set `queue_size`; memory
/// stays bounded by one window, store reads stay one per window). Same order and `-EINVAL` cases
/// as [`list`] with `max = u64::MAX`.
pub fn count<C: ClsCtx>(c: &mut C, h: &Head, end_marker: &[u8]) -> Result<u64, Errno> {
    let tail_pos = h.pos(&h.tail);
    let mut cur = h.pos(&h.front);
    let mut n = 0u64;
    let mut win = Window::default();
    while cur < tail_pos {
        let m = h.marker_at(cur);
        if !end_marker.is_empty() && m.matches(end_marker) {
            break;
        }
        let avail = tail_pos - cur;
        if avail < ENTRY_OVERHEAD {
            return Err(EINVAL);
        }
        let hdr = win.get(c, h, cur, ENTRY_OVERHEAD, tail_pos)?;
        let magic = u16::from_le_bytes([hdr[0], hdr[1]]);
        let len = u64::from_le_bytes(hdr[2..10].try_into().unwrap_or([0; 8]));
        if magic != ENTRY_MAGIC || len > avail - ENTRY_OVERHEAD {
            return Err(EINVAL);
        }
        n += 1;
        cur += ENTRY_OVERHEAD + len;
    }
    Ok(n)
}

/// `queue_remove_entries`: advance the front to `end_marker`, zeroing the freed ranges.
pub fn remove<C: ClsCtx>(c: &mut C, h: &mut Head, end_marker: &[u8]) -> Result<(), Errno> {
    if h.is_empty() {
        return Ok(());
    }
    let end = Marker::parse(end_marker);
    if end.offset > h.front.offset && end.gen_ == h.front.gen_ {
        c.zero(h.front.offset, end.offset - h.front.offset)?;
    } else if h.front.offset >= end.offset && end.gen_ == h.front.gen_.wrapping_add(1) {
        let len = h.queue_size.saturating_sub(h.front.offset);
        if len > 0 {
            c.zero(h.front.offset, len)?;
        }
        let len = end.offset.saturating_sub(h.max_head_size);
        if len > 0 {
            c.zero(h.max_head_size, len)?;
        }
    } else if end == h.front {
        // nothing to free
    } else {
        return Err(EINVAL);
    }
    h.front = end;
    if h.front.offset == h.queue_size {
        h.front.offset = h.max_head_size;
        h.front.gen_ = h.front.gen_.wrapping_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------- class `queue`

pub fn m_init<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: InitOp = dec_op(input)?;
    init(c, &op)?;
    Ok(())
}
pub fn m_get_capacity<C: ClsCtx>(c: &mut C, _input: &[u8]) -> R {
    let h = read_head(c)?;
    enc(&GetCapacityRet {
        queue_capacity: h.queue_size.wrapping_sub(h.max_head_size),
    })
}
pub fn m_enqueue<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: EnqueueOp = dec_op(input)?;
    let mut h = read_head(c)?;
    enqueue(c, &mut h, &op.bl_data_vec)?;
    write_head(c, &h)?;
    Ok(())
}
pub fn m_list_entries<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: ListOp = dec_op(input)?;
    let h = read_head(c)?;
    let l = list(c, &h, op.max, &op.start_marker, &op.end_marker)?;
    enc(&ListRet {
        is_truncated: l.is_truncated,
        next_marker: l.next_marker,
        entries: l.entries,
    })
}
pub fn m_remove_entries<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: RemoveOp = dec_op(input)?;
    let mut h = read_head(c)?;
    remove(c, &mut h, &op.end_marker)?;
    write_head(c, &h)?;
    Ok(())
}
