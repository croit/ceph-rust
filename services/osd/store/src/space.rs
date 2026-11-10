// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Space admission of a shard (adr 0637-store-admission-ledger): what a txn asks for ([`Ask`]), what the store charges
//! for it ([`Cost`]), and the one rule that decides whether it fits next to what is already held ([`fits`]).
//!
//! Held = the cost of every txn the shard accepted but has not applied yet (parked txns). The rule charges each of them
//! once, so the admission of the next txn sees the space they will take, not a guess of it.

use crate::BLK;
use crate::shard::RoomView;

/// What a txn will write, as its caller counts it before the txn exists in the store: payload bytes (data and values)
/// and tree entries it sets or removes (omap keys, xattrs).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ask {
    pub bytes: u64,
    pub entries: u64,
}

/// Space a txn may take from its shard: data blocks, tree entries that may each dirty a clean page, and tree pages it
/// may add. Costs add up (the held cost of a shard is the sum of its parked txns').
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cost {
    pub blocks: u64,
    pub entries: u64,
    pub pages: u64,
}

impl Cost {
    /// Charge of a txn the caller describes by `ask` (adr 0021 am. 45): its payload in whole blocks plus one, one clean
    /// page per entry (random keys each dirty a leaf of their own), a page per block of payload (worst case) plus 16 for
    /// the object records.
    pub fn of(ask: Ask) -> Cost {
        let blk = BLK as u64;
        Cost {
            blocks: ask.bytes.div_ceil(blk) + 1,
            entries: ask.entries,
            pages: 16 + ask.bytes / blk,
        }
    }

    /// Charge of a parked txn that retains `bytes` of input and sets or removes `entries` tree entries: its retained
    /// bytes in whole blocks (0 once prepared: its data blocks are reserved then) and its entries.
    pub(crate) fn parked(bytes: usize, entries: u64) -> Cost {
        Cost {
            blocks: (bytes as u64).div_ceil(BLK as u64),
            entries,
            pages: 0,
        }
    }

    pub(crate) fn add(&mut self, c: Cost) {
        self.blocks += c.blocks;
        self.entries += c.entries;
        self.pages += c.pages;
    }

    /// Remove a cost that was added before (exact: a held cost never goes negative).
    pub(crate) fn sub(&mut self, c: Cost) {
        debug_assert!(
            self.blocks >= c.blocks && self.entries >= c.entries && self.pages >= c.pages,
            "held cost below zero: {self:?} - {c:?}"
        );
        self.blocks -= c.blocks;
        self.entries -= c.entries;
        self.pages -= c.pages;
    }
}

/// Does `c` fit the shard `v` describes (for the txn's class) next to the `held` cost? Data: the blocks above the class
/// floor. Tree pages (adr 0021 am. 45): dirty pages are charged already; every entry held or asked may dirty one clean
/// page (at most every clean page once); new pages for payload and object records; elastic meta may still grow into
/// the free data beyond the blocks this check charges (those cells' free pages are counted once: as data).
pub(crate) fn fits(v: &RoomView, held: Cost, c: Cost) -> bool {
    let want = c.blocks + held.blocks + v.data_floor;
    let cow = (c.entries + held.entries).min(v.meta_used.saturating_sub(v.dirty_pages));
    let need = v.dirty_pages + v.meta_floor + cow + c.pages + held.pages;
    let growable = if v.meta_growable {
        v.data_free.saturating_sub(want) / v.meta_bpp.max(1)
    } else {
        0
    };
    let meta_free = v
        .meta_free
        .saturating_sub(v.data_reclaim / v.meta_bpp.max(1));
    v.data_free >= want && meta_free + growable >= need
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view() -> RoomView {
        RoomView {
            data_floor: 100,
            meta_floor: 10,
            data_free: 1_000,
            data_reclaim: 0,
            meta_used: 50,
            meta_free: 100,
            dirty_pages: 20,
            meta_bpp: 4,
            meta_growable: false,
        }
    }

    #[test]
    fn held_cost_is_charged_once_and_released_exactly() {
        // meta is ample: data decides (each txn: 451 blocks, 466 pages)
        let v = RoomView {
            meta_free: 10_000,
            ..view()
        };
        let one = Cost::of(Ask {
            bytes: 450 * BLK as u64,
            entries: 0,
        });
        assert!(fits(&v, Cost::default(), one));
        let mut held = Cost::default();
        held.add(one);
        // 451 + 451 + floor 100 > 1000 free blocks: the second does not fit while the first is held
        assert!(!fits(&v, held, one));
        held.sub(one);
        assert_eq!(held, Cost::default());
        assert!(fits(&v, held, one));
    }

    #[test]
    fn entries_dirty_at_most_every_clean_page_once() {
        let v = view();
        // 30 clean pages: 10 000 entries cost 30 pages, not 10 000
        let many = Cost {
            blocks: 0,
            entries: 10_000,
            pages: 0,
        };
        assert!(fits(&v, Cost::default(), many));
        // dirty 20 + floor 10 + 30 clean + 41 new = 101 > 100 free
        let more = Cost { pages: 41, ..many };
        assert!(!fits(&v, Cost::default(), more));
    }

    #[test]
    fn elastic_meta_grows_into_free_data_beyond_the_charged_blocks() {
        let mut v = view();
        let c = Cost {
            blocks: 0,
            entries: 0,
            pages: 200,
        };
        assert!(!fits(&v, Cost::default(), c));
        v.meta_growable = true;
        // (1000 - 100 floor) / 4 = 225 growable pages
        assert!(fits(&v, Cost::default(), c));
        let held = Cost {
            blocks: 600,
            entries: 0,
            pages: 0,
        };
        // the held blocks are data, not growable meta: (1000 - 700) / 4 = 75
        assert!(!fits(&v, held, c));
    }
}
