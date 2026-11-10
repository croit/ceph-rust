// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Entry-to-splay assignment and object rollover for the local librbd
//! journal writer (spec `doc/spec/rustyrbd/ffi-journal-io.md`, "DATA
//! ordering" step 4 and "Rollover").
//!
//! Entry `tid` belongs to splay `tid % splay_width`, object
//! `active_set * splay_width + splay`. One active set is shared by every
//! splay: after a rollover all later appends of every splay use the new set,
//! so records of one splay are never written to an older set after a newer
//! one. The cursor counts the bytes this writer appended to each splay's
//! current object to cut a splay batch so that no record byte passes the
//! soft maximum `1 << order` (spec J9: the client pre-empts at the soft
//! maximum); a record that does not fit closes the object and the writer
//! rolls over. The count is exact without class padding and a lower bound
//! with it (the class zero-pads every append to the OSD allocation unit);
//! an append the class finds full returns `-EOVERFLOW` and rolls over too.
//! Every record fits an empty object (a compare-and-write is split into
//! sub-range records), so no record ever needs an oversized-record path.

use denc::Error;

/// The class's minimum append padding alignment (`osd_min_alloc_size` 0
/// pads to 8 bytes, `doc/spec/cls_journal.md`).
const MIN_APPEND_ALIGN: u64 = 8;

/// Splay/object assignment state of one journal writer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalAppendCursor {
    splay_width: u8,
    soft_max: u64,
    active_set: u64,
    next_tid: u64,
    /// Bytes appended by this cursor to each splay's object in the active
    /// set.
    object_bytes: Vec<u64>,
}

impl JournalAppendCursor {
    /// Start at the first unallocated entry `next_tid` in `active_set`.
    /// Zero width, an order of 64 or more, or an active set whose last
    /// object number does not fit `u64` is rejected.
    pub fn new(splay_width: u8, order: u8, active_set: u64, next_tid: u64) -> denc::Result<Self> {
        if splay_width == 0 || order >= 64 {
            return Err(Error::BadValue("journal append geometry"));
        }
        checked_set_end(active_set, splay_width)?;
        let mut object_bytes = Vec::new();
        object_bytes
            .try_reserve_exact(usize::from(splay_width))
            .map_err(|_| Error::NoSpace)?;
        object_bytes.resize(usize::from(splay_width), 0);
        Ok(Self {
            splay_width,
            soft_max: 1u64 << order,
            active_set,
            next_tid,
            object_bytes,
        })
    }

    /// The next unallocated entry TID.
    pub fn next_tid(&self) -> u64 {
        self.next_tid
    }

    /// The current, inclusive append set.
    pub fn active_set(&self) -> u64 {
        self.active_set
    }

    /// The per-object soft maximum `1 << order` passed to the class append.
    pub fn soft_max(&self) -> u64 {
        self.soft_max
    }

    /// Allocate `count >= 1` consecutive entry TIDs; returns the first.
    pub fn allocate(&mut self, count: u64) -> denc::Result<u64> {
        if count == 0 {
            return Err(Error::BadValue("journal append entry count"));
        }
        let first = self.next_tid;
        self.next_tid = first.checked_add(count).ok_or(Error::TooLong)?;
        Ok(first)
    }

    /// The splay stream of `entry_tid`.
    pub fn splay(&self, entry_tid: u64) -> usize {
        (entry_tid % u64::from(self.splay_width)) as usize
    }

    /// The object of `splay` in the active set (`splay < splay_width`).
    pub fn object_number(&self, splay: usize) -> u64 {
        // Representable: checked by `new` and `rollover_to`.
        self.active_set * u64::from(self.splay_width) + splay as u64
    }

    /// How many of the next records (encoded lengths in append order) of
    /// `splay` fit one append to its current object without any record
    /// byte passing the soft maximum. Every record is at most the soft
    /// maximum, so the first one always fits an empty object. `0` means
    /// the object is closed: the caller rolls over to the next set.
    pub fn batch_len(&self, splay: usize, record_lens: impl Iterator<Item = usize>) -> usize {
        let mut size = self.object_bytes[splay];
        let mut count = 0;
        for len in record_lens {
            match size.checked_add(len as u64) {
                Some(end) if end <= self.soft_max => size = end,
                _ => break,
            }
            count += 1;
        }
        count
    }

    /// Account `bytes` durably appended to the splay's current object. The
    /// count is rounded up to the class's minimum padding alignment (8).
    pub fn appended(&mut self, splay: usize, bytes: u64) {
        self.object_bytes[splay] = self.object_bytes[splay]
            .saturating_add(bytes)
            .saturating_add(MIN_APPEND_ALIGN - 1)
            / MIN_APPEND_ALIGN
            * MIN_APPEND_ALIGN;
    }

    /// Move every splay to the newer active set `set`; objects of the new
    /// set start empty. A set not above the current one, or whose last
    /// object number does not fit `u64`, is rejected.
    pub fn rollover_to(&mut self, set: u64) -> denc::Result<()> {
        if set <= self.active_set {
            return Err(Error::BadValue("journal rollover set"));
        }
        checked_set_end(set, self.splay_width)?;
        self.active_set = set;
        self.object_bytes.fill(0);
        Ok(())
    }
}

fn checked_set_end(active_set: u64, splay_width: u8) -> denc::Result<()> {
    active_set
        .checked_mul(u64::from(splay_width))
        .and_then(|base| base.checked_add(u64::from(splay_width) - 1))
        .ok_or(Error::TooLong)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assigns_consecutive_entries_round_robin_in_the_active_set() {
        let mut cursor = JournalAppendCursor::new(2, 12, 0, 0).unwrap();
        assert_eq!(cursor.allocate(3).unwrap(), 0);
        assert_eq!(cursor.next_tid(), 3);
        assert_eq!(
            (0..3)
                .map(|tid| cursor.object_number(cursor.splay(tid)))
                .collect::<Vec<_>>(),
            [0, 1, 0]
        );
        cursor.rollover_to(1).unwrap();
        assert_eq!(cursor.object_number(0), 2);
        assert_eq!(cursor.object_number(1), 3);
        assert!(cursor.rollover_to(1).is_err(), "never back or in place");
    }

    #[test]
    fn batches_cut_at_the_soft_maximum() {
        let mut cursor = JournalAppendCursor::new(1, 12, 0, 0).unwrap();
        assert_eq!(cursor.batch_len(0, [1000, 1000, 1000].into_iter()), 3);
        // 4000 + 1000 would pass 4096: the batch stops before that record.
        assert_eq!(cursor.batch_len(0, [2000, 2000, 1000, 1].into_iter()), 2);
        assert_eq!(cursor.batch_len(0, [2048, 2048, 1].into_iter()), 2);
        cursor.appended(0, 4089);
        // Rounded to 4096: closed.
        assert_eq!(cursor.batch_len(0, [1].into_iter()), 0);
        cursor.rollover_to(3).unwrap();
        assert_eq!(cursor.batch_len(0, [4096].into_iter()), 1);
    }

    #[test]
    fn a_record_equal_to_the_soft_maximum_fits_an_empty_object() {
        let mut cursor = JournalAppendCursor::new(1, 12, 0, 0).unwrap();
        assert_eq!(cursor.batch_len(0, [4096].into_iter()), 1);
        cursor.appended(0, 4096);
        assert_eq!(cursor.batch_len(0, [1].into_iter()), 0);
        cursor.rollover_to(1).unwrap();
        assert_eq!(cursor.batch_len(0, [4096, 1].into_iter()), 1);
    }

    #[test]
    fn rejects_bad_geometry_and_tid_overflow() {
        assert!(JournalAppendCursor::new(0, 12, 0, 0).is_err());
        assert!(JournalAppendCursor::new(2, 64, 0, 0).is_err());
        assert!(JournalAppendCursor::new(2, 12, u64::MAX, 0).is_err());
        let mut cursor = JournalAppendCursor::new(2, 12, 0, u64::MAX - 1).unwrap();
        assert!(cursor.allocate(0).is_err());
        assert!(cursor.allocate(2).is_err());
        assert_eq!(cursor.allocate(1).unwrap(), u64::MAX - 1);
        assert!(cursor.allocate(1).is_err());
        let mut cursor = JournalAppendCursor::new(2, 12, u64::MAX / 2, 0).unwrap();
        assert!(cursor.rollover_to(u64::MAX / 2 + 1).is_err());
    }
}
