// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Receiver-side pre-write (adr 0477 D1/D2): device writes of the whole-block pieces of a large payload while the
//! payload is still arriving, into blocks of a volatile reservation that nothing references.
//!
//! A piece is a `Bytes` view of receive memory that is filled and immutable (the transport only appends behind it). It
//! goes to the device by reference into blocks reserved from free space (the allocator's volatile `reserved` overlay,
//! never `held`: the checkpoint rule of adr 0021 am. 2 is untouched). Until a txn of the same shard claims it, no WAL
//! record, extent entry, read path or ack refers to those blocks: a crash leaves them free space (replay rebuilds the
//! allocator from the tree, reservations are not persisted), a failed frame (crc, tag, connection loss) only releases
//! them.
//!
//! Claim = identity of memory: a staged data run whose source bytes start at a piece's first byte takes the piece's
//! blocks instead of a fresh allocation and a data write. The slot keeps its piece alive until it is claimed or released,
//! so no other bytes can sit at that address meanwhile; a run that is a slice of the very same memory holds the very
//! same bytes (the claimed record is built after the frame was verified, its block crcs come from the verified payload).
//!
//! Release never returns blocks under an in-flight write: a released slot whose write is still in flight frees its blocks
//! at the completion. A committed claim makes its txn's unit wait for the write like any data write of the txn (the ack
//! needs it, adr 0008).

use bytes::Bytes;

/// Handle of one pre-written piece: slot index (low 32 bits) and the slot's generation (high 32 bits), so a stale
/// handle never touches a reused slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PreId(u64);

impl PreId {
    fn new(idx: u32, generation: u32) -> PreId {
        PreId(u64::from(idx) | (u64::from(generation) << 32))
    }
    pub(crate) fn raw(self) -> u64 {
        self.0
    }
    pub(crate) fn from_raw(v: u64) -> PreId {
        PreId(v)
    }
    fn idx(self) -> usize {
        (self.0 & 0xffff_ffff) as usize
    }
    fn generation(self) -> u32 {
        (self.0 >> 32) as u32
    }
}

/// A claimed piece in a staged txn (`Txn::pre`): its blocks `[blk, blk + nblk)` (a prefix of the piece) become the
/// extent with `crcs`; the rest of the piece is returned once its write landed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreClaim {
    pub id: PreId,
    pub blk: u64,
    pub nblk: u32,
    pub crcs: Vec<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum St {
    /// Write in flight, not claimed.
    Inflight,
    /// Write landed, not claimed.
    Done,
    /// Released while its write was in flight: its blocks are returned at the completion.
    Released,
    /// Claimed by a txn that is staged but not committed yet (`written`: the write landed).
    Taken { written: bool },
    /// The claiming txn is committed into unit `seq` with the first `n` blocks; the unit waits for the write.
    Committed { seq: u64, n: u32 },
}

#[derive(Debug)]
struct Slot {
    blk: u64,
    nblk: u32,
    /// Address and length of the piece (claim identity).
    ptr: usize,
    len: usize,
    /// Keeps the piece's memory alive (and its address unique) while the slot can be claimed.
    piece: Option<Bytes>,
    generation: u32,
    st: St,
}

/// Counters (perf dump `flashstore_store_pre_*`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PreStats {
    /// Pieces written ahead / their bytes.
    pub writes: u64,
    pub bytes: u64,
    /// Pieces a txn claimed (blocks a record references) / claimed bytes.
    pub claimed: u64,
    pub claimed_bytes: u64,
    /// Of `claimed`: the write had landed when the txn claimed the piece (the device time was fully hidden).
    pub claimed_landed: u64,
    /// Pieces released unclaimed (wasted device writes, adr 0477 open question "claimed/released").
    pub released: u64,
    pub released_bytes: u64,
    /// Pieces not written ahead: no reservation (space floor, no contiguous run), no queue room.
    pub skipped: u64,
    /// Pieces written from a copy (the device cannot DMA from the payload memory: the copy the txn would make, made earlier).
    pub copied: u64,
}

/// What the completion of a pre-write means to the shard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Landed {
    /// Nothing to do (unclaimed, or claimed by a txn not committed yet).
    Keep,
    /// Return `[blk, blk + n)` to the allocator (released slot or the unclaimed rest of a committed one).
    Unreserve(u64, u32),
    /// The write of committed unit `seq` landed (one of its pending data writes); return the rest `[blk, blk + n)` too.
    Unit { seq: u64, rest: (u64, u32) },
}

/// Pre-written pieces of one shard. Single-threaded (the shard's core); slots are reused, the table does not shrink.
#[derive(Debug, Default)]
pub(crate) struct PreTab {
    slots: Vec<Option<Slot>>,
    /// Generation of each slot index (the last one handed out; a vacant slot keeps it).
    gens: Vec<u32>,
    free: Vec<u32>,
    /// Slots that may be claimed (`Inflight` or `Done`).
    open: usize,
    /// Slots that stopped being claimable so far (taken, released): a holder of tickets only has to look again when
    /// it moved.
    closed: u64,
    pub stats: PreStats,
}

impl PreTab {
    /// Record a piece whose write `[blk, blk + nblk)` is being submitted; returns the handle and the slot index for
    /// the completion tag.
    pub(crate) fn insert(&mut self, piece: &Bytes, blk: u64, nblk: u32) -> (PreId, u32) {
        let idx = match self.free.pop() {
            Some(i) => i,
            None => {
                self.slots.push(None);
                self.gens.push(0);
                (self.slots.len() - 1) as u32
            }
        };
        let generation = self.gens[idx as usize].wrapping_add(1);
        self.gens[idx as usize] = generation;
        self.slots[idx as usize] = Some(Slot {
            blk,
            nblk,
            ptr: piece.as_ptr() as usize,
            len: piece.len(),
            piece: Some(piece.clone()),
            generation,
            st: St::Inflight,
        });
        self.open += 1;
        self.stats.writes += 1;
        self.stats.bytes += piece.len() as u64;
        (PreId::new(idx, generation), idx)
    }

    /// The submit failed after `insert`: forget the slot (nothing is in flight); the caller returns the blocks.
    pub(crate) fn abort_insert(&mut self, id: PreId) {
        if let Some(s) = self.get(id) {
            debug_assert_eq!(s.st, St::Inflight);
            let len = s.len as u64;
            self.stats.writes -= 1;
            self.stats.bytes -= len;
            self.close();
            self.drop_slot(id.idx());
        }
    }

    fn get(&self, id: PreId) -> Option<&Slot> {
        self.slots
            .get(id.idx())?
            .as_ref()
            .filter(|s| s.generation == id.generation())
    }

    fn get_mut(slots: &mut [Option<Slot>], id: PreId) -> Option<&mut Slot> {
        slots
            .get_mut(id.idx())?
            .as_mut()
            .filter(|s| s.generation == id.generation())
    }

    fn drop_slot(&mut self, idx: usize) {
        self.slots[idx] = None;
        self.free.push(idx as u32);
    }

    /// Piece `id` may still be claimed or released (written ahead, not taken by a txn, not released yet).
    pub(crate) fn is_open(&self, id: PreId) -> bool {
        self.get(id)
            .is_some_and(|s| matches!(s.st, St::Inflight | St::Done))
    }

    fn close(&mut self) {
        self.open -= 1;
        self.closed += 1;
    }

    /// Count of slots that stopped being claimable ([`Self::is_open`] turned false) since the table exists.
    pub(crate) fn closed(&self) -> u64 {
        self.closed
    }

    /// Any piece that may still be claimed.
    pub(crate) fn has_open(&self) -> bool {
        self.open > 0
    }

    /// Slots in use (written ahead and not finished: tests, diagnostics).
    pub(crate) fn live(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    /// Release an unclaimed piece (frame gone, staged without it). Claimed ones belong to their txn: untouched.
    /// Returns blocks to unreserve now (`None`: nothing now; an in-flight write returns them at its completion).
    pub(crate) fn release(&mut self, id: PreId) -> Option<(u64, u32)> {
        let s = Self::get_mut(&mut self.slots, id)?;
        match s.st {
            St::Inflight => {
                s.st = St::Released;
                s.piece = None;
                let len = s.len as u64;
                self.close();
                self.stats.released += 1;
                self.stats.released_bytes += len;
                None
            }
            St::Done => {
                let r = (s.blk, s.nblk);
                let len = s.len as u64;
                self.close();
                self.stats.released += 1;
                self.stats.released_bytes += len;
                self.drop_slot(id.idx());
                Some(r)
            }
            St::Released | St::Taken { .. } | St::Committed { .. } => None,
        }
    }

    /// Release every unclaimed piece whose memory lies in `[lo, hi)`; `out` collects blocks to unreserve now.
    pub(crate) fn release_within(&mut self, lo: usize, hi: usize, out: &mut Vec<(u64, u32)>) {
        if self.open == 0 {
            return;
        }
        for i in 0..self.slots.len() {
            let Some(s) = &self.slots[i] else { continue };
            if matches!(s.st, St::Inflight | St::Done) && s.ptr >= lo && s.ptr + s.len <= hi {
                let id = PreId::new(i as u32, s.generation);
                if let Some(r) = self.release(id) {
                    out.push(r);
                }
            }
        }
    }

    /// A staged run whose source starts at `ptr` and spans `max` blocks: the piece written from exactly there, its
    /// first `min(max, piece)` blocks. The slot is `Taken` until the txn commits ([`Self::commit`]) or its staging is
    /// discarded ([`Self::unclaim`]).
    pub(crate) fn claim(&mut self, ptr: usize, max: u32) -> Option<(PreId, u64, u32)> {
        if self.open == 0 || max == 0 {
            return None;
        }
        let i = self.slots.iter().position(|s| {
            s.as_ref()
                .is_some_and(|s| s.ptr == ptr && matches!(s.st, St::Inflight | St::Done))
        })?;
        let s = self.slots[i].as_mut().unwrap();
        s.st = St::Taken {
            written: s.st == St::Done,
        };
        let r = (PreId::new(i as u32, s.generation), s.blk, s.nblk.min(max));
        self.close();
        Some(r)
    }

    /// The piece is claimed by a txn that `validate` may accept: its blocks.
    pub(crate) fn taken(&self, id: PreId) -> Option<(u64, u32)> {
        let s = self.get(id)?;
        matches!(s.st, St::Taken { .. }).then_some((s.blk, s.nblk))
    }

    /// The claiming txn was discarded before commit: the piece is released like an unclaimed one (a retry of the txn
    /// writes the data itself).
    pub(crate) fn unclaim(&mut self, id: PreId) -> Option<(u64, u32)> {
        let s = Self::get_mut(&mut self.slots, id)?;
        let St::Taken { written } = s.st else {
            return None;
        };
        let len = s.len as u64;
        self.stats.released += 1;
        self.stats.released_bytes += len;
        if written {
            let r = (s.blk, s.nblk);
            self.drop_slot(id.idx());
            Some(r)
        } else {
            s.st = St::Released;
            s.piece = None;
            None
        }
    }

    /// The claiming txn is committed into unit `seq` with the piece's first `n` blocks. `Ok(rest)`: the write already
    /// landed, the slot is done and the rest `[blk, blk + n)` is returned now; `Err(())`: the unit must wait for the
    /// write (one more pending data write), the rest is returned at its completion.
    pub(crate) fn commit(&mut self, id: PreId, n: u32, seq: u64) -> Result<(u64, u32), ()> {
        let s = Self::get_mut(&mut self.slots, id).expect("validated claim");
        let St::Taken { written } = s.st else {
            unreachable!("validated claim is taken")
        };
        self.stats.claimed += 1;
        self.stats.claimed_bytes += u64::from(n) * crate::BLK as u64;
        self.stats.claimed_landed += u64::from(written);
        if written {
            let rest = (s.blk + u64::from(n), s.nblk - n);
            self.drop_slot(id.idx());
            Ok(rest)
        } else {
            s.st = St::Committed { seq, n };
            // the claimed bytes are referenced by the payload of the txn until it is durable; the slot's own reference
            // is not needed for identity any more
            s.piece = None;
            Err(())
        }
    }

    /// The write of slot `idx` landed.
    pub(crate) fn landed(&mut self, idx: usize) -> Landed {
        let Some(s) = self.slots.get_mut(idx).and_then(Option::as_mut) else {
            return Landed::Keep;
        };
        match s.st {
            St::Inflight => {
                s.st = St::Done;
                Landed::Keep
            }
            St::Taken { .. } => {
                s.st = St::Taken { written: true };
                Landed::Keep
            }
            St::Released => {
                let r = (s.blk, s.nblk);
                self.drop_slot(idx);
                Landed::Unreserve(r.0, r.1)
            }
            St::Committed { seq, n } => {
                let rest = (s.blk + u64::from(n), s.nblk - n);
                self.drop_slot(idx);
                Landed::Unit { seq, rest }
            }
            St::Done => Landed::Keep,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn piece(n: usize) -> Bytes {
        Bytes::from(vec![7u8; n * crate::BLK])
    }

    #[test]
    fn stale_handle_never_touches_a_reused_slot() {
        let mut t = PreTab::default();
        let (a, ia) = t.insert(&piece(2), 100, 2);
        assert_eq!(t.landed(ia as usize), Landed::Keep);
        assert_eq!(t.release(a), Some((100, 2)), "landed: returned at once");
        let p = piece(4);
        let (b, ib) = t.insert(&p, 200, 4);
        assert_eq!(ia, ib, "slot reused");
        assert_eq!(t.release(a), None, "old generation");
        assert_eq!(t.unclaim(a), None);
        assert!(t.has_open(), "the new piece is untouched");
        assert_eq!(t.claim(p.as_ptr() as usize, 3), Some((b, 200, 3)));
    }

    #[test]
    fn lifecycle_in_flight() {
        let mut t = PreTab::default();
        let p = piece(4);
        // released in flight: blocks only at the completion
        let (a, ia) = t.insert(&p, 10, 4);
        assert_eq!(t.release(a), None);
        assert_eq!(t.landed(ia as usize), Landed::Unreserve(10, 4));
        assert_eq!(t.live(), 0);
        // claimed and committed in flight: the unit gets the completion, the rest is returned with it
        let (b, ib) = t.insert(&p, 20, 4);
        assert_eq!(t.claim(p.as_ptr() as usize, 3), Some((b, 20, 3)));
        assert_eq!(t.taken(b), Some((20, 4)));
        assert_eq!(t.release(b), None, "a claim belongs to its txn");
        assert_eq!(t.commit(b, 3, 77), Err(()));
        assert_eq!(
            t.landed(ib as usize),
            Landed::Unit {
                seq: 77,
                rest: (23, 1)
            }
        );
        // claimed, discarded before commit, write landed later
        let (c, ic) = t.insert(&p, 30, 4);
        assert!(t.claim(p.as_ptr() as usize, 4).is_some());
        assert_eq!(t.unclaim(c), None);
        assert_eq!(t.landed(ic as usize), Landed::Unreserve(30, 4));
        // claimed after the write landed, committed: nothing pending, the rest at once
        let (d, id) = t.insert(&p, 40, 4);
        assert_eq!(t.landed(id as usize), Landed::Keep);
        assert!(t.claim(p.as_ptr() as usize, 2).is_some());
        assert_eq!(t.commit(d, 2, 78), Ok((42, 2)));
        assert_eq!(t.live(), 0);
        assert!(!t.has_open());
        let s = t.stats;
        assert_eq!((s.writes, s.claimed, s.released), (4, 2, 2));
    }

    #[test]
    fn release_within_takes_only_unclaimed_pieces_of_the_range() {
        let mut t = PreTab::default();
        let p = piece(8);
        let (_, i0) = t.insert(&p.slice(0..4 * crate::BLK), 0, 4);
        let (_, _i1) = t.insert(&p.slice(4 * crate::BLK..), 4, 4);
        let other = piece(4);
        let (_, _) = t.insert(&other, 50, 4);
        assert_eq!(t.landed(i0 as usize), Landed::Keep);
        // the second piece is claimed: stays with its txn
        assert!(t.claim(p.as_ptr() as usize + 4 * crate::BLK, 4).is_some());
        let mut out = Vec::new();
        let lo = p.as_ptr() as usize;
        t.release_within(lo, lo + p.len(), &mut out);
        assert_eq!(
            out,
            vec![(0, 4)],
            "landed unclaimed piece of the range only"
        );
        assert!(t.has_open(), "the other payload's piece stays claimable");
    }
}
