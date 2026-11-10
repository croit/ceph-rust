// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Class `2pc_queue` (spec/cls_2pc_queue.md): reserve/commit/abort on top of the cls_queue ring.

use crate::ctx::ClsCtx;
use crate::env_struct;
use crate::errno::*;
use crate::queue::{self, ENTRY_OVERHEAD, Head, InitOp};
use denc::types::UTime;
use denc::{BufMut, Decode, Decoder, Encode, Encoder};
use std::collections::BTreeMap;

pub const URGENT_XATTR: &str = "cls_queue_urgent_data";
/// Head = 1 KiB + this (room for ~1K pending reservations).
pub const MAX_URGENT_DATA_SIZE: u64 = 23552;

/// `cls_2pc_reservation` (2,1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Reservation {
    pub size: u64,
    pub timestamp: UTime,
    pub entries: u32,
}
impl Reservation {
    /// Bytes the reservation holds back: payload + per-entry framing.
    fn weight(&self) -> u64 {
        self.size.wrapping_add(entry_overhead(self.entries))
    }
}

/// Framing bytes of `n` entries. Classic multiplies in 32 bits (u32 count x unsigned constant): wraps there too,
/// which the persisted `reserved_size` reflects.
fn entry_overhead(n: u32) -> u64 {
    u64::from(n.wrapping_mul(ENTRY_OVERHEAD as u32))
}

/// Sum of reservation weights, wrapping like classic (stored sizes are client-controlled: no debug overflow panic).
fn wsum<'a>(rs: impl Iterator<Item = &'a Reservation>) -> u64 {
    rs.fold(0, |a, r| a.wrapping_add(r.weight()))
}
impl Encode for Reservation {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(2, 1, |e| {
            e.u64(self.size)?;
            self.timestamp.encode(e)?;
            e.u32(self.entries)
        })
    }
}
impl<'a> Decode<'a> for Reservation {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(1, |d, v| {
            Ok(Reservation {
                size: d.u64()?,
                timestamp: UTime::decode(d)?,
                entries: if v >= 2 { d.u32()? } else { 0 },
            })
        })
    }
}
pub type Reservations = BTreeMap<u32, Reservation>;

/// `cls_2pc_urgent_data` (3,1)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Urgent {
    pub reserved_size: u64,
    pub last_id: u32,
    pub reservations: Reservations,
    pub has_xattrs: bool,
    pub committed_entries: u32,
    /// struct_v seen at decode (transient; 3 for fresh values).
    pub decoded_v: u8,
}
impl Default for Urgent {
    fn default() -> Self {
        Urgent {
            reserved_size: 0,
            last_id: 0,
            reservations: BTreeMap::new(),
            has_xattrs: false,
            committed_entries: 0,
            decoded_v: 3,
        }
    }
}
impl Encode for Urgent {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(3, 1, |e| {
            e.u64(self.reserved_size)?;
            e.u32(self.last_id)?;
            self.reservations.encode(e)?;
            e.bool(self.has_xattrs)?;
            e.u32(self.committed_entries)
        })
    }
}
impl<'a> Decode<'a> for Urgent {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(3, |d, v| {
            Ok(Urgent {
                reserved_size: d.u64()?,
                last_id: d.u32()?,
                reservations: Reservations::decode(d)?,
                has_xattrs: d.bool()?,
                committed_entries: if v >= 2 { d.u32()? } else { 0 },
                decoded_v: v,
            })
        })
    }
}

env_struct!(ReserveOp (1, 1) { size: u64, entries: u32 });
env_struct!(ReserveRet (1, 1) { id: u32 });
env_struct!(CommitOp (1, 1) { id: u32, bl_data_vec: Vec<Vec<u8>> });
env_struct!(AbortOp (1, 1) { id: u32 });
env_struct!(ExpireOp (1, 1) { stale_time: UTime });
env_struct!(ReservationsRet (1, 1) { reservations: Reservations });
env_struct!(StatsRet (1, 1) { queue_size: u64, queue_entries: u32 });

/// `cls_2pc_queue_remove_op` (2,1): `entries_to_remove` only from struct_v 2.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RemoveOp {
    pub end_marker: Vec<u8>,
    pub entries_to_remove: u32,
}
impl Encode for RemoveOp {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(2, 1, |e| {
            self.end_marker.encode(e)?;
            e.u32(self.entries_to_remove)
        })
    }
}
impl<'a> Decode<'a> for RemoveOp {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(2, |d, v| {
            Ok(RemoveOp {
                end_marker: Vec::<u8>::decode(d)?,
                entries_to_remove: if v >= 2 { d.u32()? } else { 0 },
            })
        })
    }
}

/// Head + decoded urgent data (`-EINVAL` if the urgent blob does not decode).
fn load<C: ClsCtx>(c: &mut C) -> Result<(Head, Urgent), Errno> {
    let head = queue::read_head(c)?;
    let urgent: Urgent = dec_op(&head.bl_urgent_data)?;
    Ok((head, urgent))
}
fn store<C: ClsCtx>(c: &mut C, mut head: Head, urgent: &Urgent) -> Result<(), Errno> {
    head.bl_urgent_data = enc(urgent)?;
    queue::write_head(c, &head)
}

/// Spill map: absent attribute = empty (`Ok(None)`), undecodable -> -EINVAL.
fn read_spill<C: ClsCtx>(c: &mut C) -> Result<Option<Reservations>, Errno> {
    match c.getxattr(URGENT_XATTR) {
        Err(ENOENT) | Err(ENODATA) => Ok(None),
        Err(e) => Err(e),
        Ok(b) => dec_op(&b).map(Some),
    }
}
fn write_spill<C: ClsCtx>(c: &mut C, m: &Reservations) -> Result<(), Errno> {
    c.setxattr(URGENT_XATTR, &enc(m)?)
}

fn remaining(h: &Head) -> u64 {
    if h.tail.offset >= h.front.offset {
        h.queue_size
            .wrapping_sub(h.tail.offset)
            .wrapping_add(h.front.offset.wrapping_sub(h.max_head_size))
    } else {
        h.front.offset.wrapping_sub(h.tail.offset)
    }
}

pub fn init<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: InitOp = dec_op(input)?;
    let op = InitOp {
        queue_size: op.queue_size,
        max_urgent_data_size: MAX_URGENT_DATA_SIZE,
        bl_urgent_data: enc(&Urgent::default())?,
    };
    queue::init(c, &op)?;
    Ok(())
}

pub fn get_topic_stats<C: ClsCtx>(c: &mut C, _input: &[u8]) -> R {
    let (head, urgent) = load(c)?;
    enc(&StatsRet {
        queue_size: head
            .queue_size
            .wrapping_sub(head.max_head_size)
            .wrapping_sub(remaining(&head)),
        queue_entries: urgent.committed_entries,
    })
}

pub fn reserve<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: ReserveOp = dec_op(input)?;
    if op.size == 0 || op.entries == 0 {
        return Err(EINVAL);
    }
    let (head, mut urgent) = load(c)?;
    if urgent.decoded_v < 3 {
        // legacy queues: counter may have drifted, rebuild it from the reservations
        urgent.reserved_size = wsum(urgent.reservations.values());
        if urgent.has_xattrs
            && let Some(m) = read_spill(c)?
        {
            urgent.reserved_size = urgent.reserved_size.wrapping_add(wsum(m.values()));
        }
    }
    let r = Reservation {
        size: op.size,
        timestamp: c.now(),
        entries: op.entries,
    };
    let overhead = entry_overhead(op.entries);
    if op
        .size
        .saturating_add(urgent.reserved_size)
        .saturating_add(overhead)
        > remaining(&head)
    {
        return Err(ENOSPC);
    }
    urgent.reserved_size = urgent.reserved_size.wrapping_add(r.weight());
    urgent.last_id = urgent.last_id.wrapping_add(1);
    let id = urgent.last_id;
    if urgent.reservations.contains_key(&id) {
        return Err(EAGAIN);
    }
    urgent.reservations.insert(id, r);
    if (enc(&urgent)?.len() as u64) > head.max_urgent_data_size {
        let mut spill = read_spill(c)?.unwrap_or_default();
        if spill.contains_key(&id) {
            return Err(EAGAIN);
        }
        spill.insert(id, r);
        write_spill(c, &spill)?;
        urgent.has_xattrs = true;
        urgent.reservations.remove(&id);
    }
    store(c, head, &urgent)?;
    enc(&ReserveRet { id })
}

pub fn commit<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: CommitOp = dec_op(input)?;
    let (mut head, mut urgent) = load(c)?;
    let mut spill: Option<Reservations> = None;
    let res = match urgent.reservations.get(&op.id) {
        Some(r) => *r,
        None => {
            if !urgent.has_xattrs {
                return Err(ENOENT);
            }
            let m = read_spill(c)?.ok_or(ENOENT)?;
            let r = *m.get(&op.id).ok_or(ENOENT)?;
            spill = Some(m);
            r
        }
    };
    let actual: u64 = op.bl_data_vec.iter().map(|b| b.len() as u64).sum();
    if res.size < actual {
        return Err(EINVAL);
    }
    queue::enqueue(c, &mut head, &op.bl_data_vec)?;
    urgent.reserved_size = urgent.reserved_size.wrapping_sub(res.weight());
    urgent.committed_entries = urgent.committed_entries.wrapping_add(res.entries);
    match spill {
        Some(mut m) => {
            m.remove(&op.id);
            write_spill(c, &m)?;
        }
        None => {
            urgent.reservations.remove(&op.id);
        }
    }
    store(c, head, &urgent)?;
    Ok(())
}

pub fn abort<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: AbortOp = dec_op(input)?;
    let (head, mut urgent) = load(c)?;
    let res = if let Some(r) = urgent.reservations.remove(&op.id) {
        r
    } else {
        if !urgent.has_xattrs {
            return Ok(());
        }
        let Some(mut m) = read_spill(c)? else {
            return Ok(());
        };
        let Some(r) = m.remove(&op.id) else {
            return Ok(());
        };
        write_spill(c, &m)?;
        r
    };
    urgent.reserved_size = urgent.reserved_size.wrapping_sub(res.weight());
    store(c, head, &urgent)?;
    Ok(())
}

pub fn list_reservations<C: ClsCtx>(c: &mut C, _input: &[u8]) -> R {
    let (_head, urgent) = load(c)?;
    let mut all = urgent.reservations;
    if urgent.has_xattrs
        && let Some(m) = read_spill(c)?
    {
        for (k, v) in m {
            all.entry(k).or_insert(v);
        }
    }
    enc(&ReservationsRet { reservations: all })
}

pub fn expire_reservations<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: ExpireOp = dec_op(input)?;
    let (head, mut urgent) = load(c)?;
    let mut freed = 0u64;
    let mut found = false;
    urgent.reservations.retain(|_, r| {
        let stale = r.timestamp < op.stale_time;
        if stale {
            freed = freed.wrapping_add(r.weight());
            found = true;
        }
        !stale
    });
    if urgent.has_xattrs
        && let Some(mut m) = read_spill(c)?
    {
        let mut spill_changed = false;
        m.retain(|_, r| {
            let stale = r.timestamp < op.stale_time;
            if stale {
                freed = freed.wrapping_add(r.weight());
                spill_changed = true;
            }
            !stale
        });
        if spill_changed {
            write_spill(c, &m)?;
            found = true;
        }
    }
    if found {
        urgent.reserved_size = urgent.reserved_size.wrapping_sub(freed);
        store(c, head, &urgent)?;
    }
    Ok(())
}

pub fn remove_entries<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let mut op: RemoveOp = dec_op(input)?;
    let mut head = queue::read_head(c)?;
    if op.entries_to_remove == 0 {
        // sender is a plain cls_queue client: count what the marker will drop (headers only, the
        // ring can be as large as the client-set queue_size); the counter is u32 like classic
        let n = queue::count(c, &head, &op.end_marker)?;
        op.entries_to_remove = u32::try_from(n).map_err(|_| EINVAL)?;
    }
    queue::remove(c, &mut head, &op.end_marker)?;
    let mut urgent: Urgent = dec_op(&head.bl_urgent_data)?;
    urgent.committed_entries = urgent.committed_entries.wrapping_sub(op.entries_to_remove);
    store(c, head, &urgent)?;
    Ok(())
}
