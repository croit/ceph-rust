// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Per-4 KiB block crcs of a payload, computed in the receive pass (DAOS lessons L1, adr 0061 am. 4).
//!
//! A large msgr2 data segment is checksummed once, on a 4 KiB grid that starts at the segment's first byte: one raw
//! crc32c (seed 0) per whole block. The segment crc of the wire (seed `!0` over all bytes) follows from the block crcs
//! without touching the data again ([`crate::crc32c_blocks`] + [`crate::crc32c_combine`] for a partial tail). The
//! block crcs travel with the payload ([`crate::CrcHint`]); the store turns them into its own seeded block crcs with
//! [`reseed_4k`] (no pass) instead of checksumming the bytes again.

/// Block size of the grid.
pub const BLK: usize = 4096;

/// `crc32c(seed, B)` for a 4096-byte block `B` from `crc32c(0, B)`: `U(s, B) = Z(s) ^ U(0, B)` (raw update linear in
/// the seed), `Z` = feeding 4096 zero bytes, four table lookups. No pass over the data.
#[inline]
pub fn reseed_4k(seed: u32, crc0: u32) -> u32 {
    crate::crc32c_blocks(seed, [(crc0, 0)])
}

/// Accumulator of the block crcs of one payload that arrives in order (any piece sizes). The 4 KiB grid starts at byte
/// `head` of the payload (0 = its first byte): the first `head` bytes only feed `pre` (a replicated write's v9 blob
/// carries the client payload at offset 14, so its blocks lie on the payload's grid, not the blob's).
#[derive(Debug, Default, Clone)]
pub struct BlockCrcs {
    /// `crc32c(0, block)` of every whole block so far.
    blocks: Vec<u32>,
    /// `crc32c(0, ..)` of the bytes of the current partial block.
    part: u32,
    /// `crc32c(0, ..)` of the first `min(pos, head)` bytes.
    pre: u32,
    /// Start of the grid.
    head: usize,
    /// Bytes accounted so far (head + whole blocks + the partial one).
    pos: usize,
}

impl BlockCrcs {
    /// Room for a payload of `len` bytes (no reallocation while it arrives).
    pub fn with_len(len: usize) -> BlockCrcs {
        Self::with_head(len, 0)
    }

    /// [`with_len`](Self::with_len) with the grid starting at byte `head` of the payload.
    pub fn with_head(len: usize, head: usize) -> BlockCrcs {
        BlockCrcs {
            blocks: Vec::with_capacity(len.saturating_sub(head) / BLK),
            part: 0,
            pre: 0,
            head,
            pos: 0,
        }
    }

    /// Bytes accounted so far.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Start of the grid in the payload.
    pub fn head(&self) -> usize {
        self.head
    }

    /// Bytes from the current position to the next grid boundary (the head, then every block end).
    fn room(&self) -> usize {
        if self.pos < self.head {
            self.head - self.pos
        } else {
            BLK - (self.pos - self.head) % BLK
        }
    }

    /// `piece` more bytes (seed-0 crc `c`) accounted: into the prefix, or the current block (closed at its end).
    fn add(&mut self, c: u32, len: usize, combine: bool) {
        let acc = if self.pos < self.head {
            &mut self.pre
        } else {
            &mut self.part
        };
        *acc = if combine {
            crate::crc32c_combine(*acc, c, len as u64)
        } else {
            c
        };
        self.pos += len;
        if self.pos > self.head && (self.pos - self.head).is_multiple_of(BLK) {
            self.blocks.push(core::mem::take(&mut self.part));
        }
    }

    /// Checksum the next bytes of the payload (one pass, split at grid boundaries).
    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let take = self.room().min(data.len());
            let seed = if self.pos < self.head {
                self.pre
            } else {
                self.part
            };
            self.add(crate::crc32c(seed, &data[..take]), take, false);
            data = &data[take..];
        }
    }

    /// [`update`](Self::update) fused with the copy of `src` into `dst` (same length, possibly uninitialized; every byte
    /// written): one pass reads the bytes once (the receive copy out of a registered RDMA slot).
    pub fn update_copy(&mut self, mut src: &[u8], dst: &mut [core::mem::MaybeUninit<u8>]) {
        assert_eq!(src.len(), dst.len());
        let mut dst = dst;
        while !src.is_empty() {
            let take = self.room().min(src.len());
            let seed = if self.pos < self.head {
                self.pre
            } else {
                self.part
            };
            let (d, rest) = dst.split_at_mut(take);
            self.add(
                crate::crc32c_copy_uninit(seed, &src[..take], d),
                take,
                false,
            );
            src = &src[take..];
            dst = rest;
        }
    }

    /// [`update`](Self::update) fused with appending `src` to `dst` (one read pass, like [`crate::crc32c_extend`]).
    pub fn update_extend(&mut self, mut src: &[u8], dst: &mut Vec<u8>) {
        dst.reserve(src.len());
        while !src.is_empty() {
            let take = self.room().min(src.len());
            let seed = if self.pos < self.head {
                self.pre
            } else {
                self.part
            };
            self.add(crate::crc32c_extend(seed, &src[..take], dst), take, false);
            src = &src[take..];
        }
    }

    /// Catch up with a buffer that holds the payload from its first byte: checksum the whole blocks of
    /// `buf[pos..]` (and, with `end`, the partial tail). Bytes of an unfinished block stay for a later call, so a
    /// payload appended in small pieces is checksummed in whole-block runs while the bytes are still cache-hot.
    pub fn advance(&mut self, buf: &[u8], end: bool) {
        debug_assert!(buf.len() >= self.pos);
        let upto = if end {
            buf.len()
        } else if buf.len() < self.head {
            0
        } else {
            self.head + (buf.len() - self.head) / BLK * BLK
        };
        if upto > self.pos {
            self.update(&buf[self.pos..upto]);
        }
    }

    /// Account a piece whose seed-0 crc is known (computed elsewhere, e.g. a helper core); it must not cross a
    /// grid boundary after the bytes accounted so far.
    pub fn push_piece(&mut self, crc0: u32, len: usize) {
        if len == 0 {
            return;
        }
        assert!(len <= self.room(), "piece crosses a block boundary");
        self.add(crc0, len, true);
    }

    /// `crc32c(seed, all bytes so far)` from the block crcs (no pass over the data).
    pub fn crc(&self, seed: u32) -> u32 {
        let pre = self.pos.min(self.head);
        let r = crate::crc32c_combine(seed, self.pre, pre as u64);
        let r = crate::crc32c_blocks(r, self.blocks.iter().map(|&c| (c, 0)));
        crate::crc32c_combine(r, self.part, (self.pos - pre) as u64 % BLK as u64)
    }

    /// The whole-block crcs (a partial tail block is not included).
    pub fn blocks(&self) -> &[u32] {
        &self.blocks
    }

    /// Take the whole-block crcs.
    pub fn into_blocks(self) -> Vec<u32> {
        self.blocks
    }
}

/// Grid pieces of `[at, at + len)` (`at` counted from the payload start, grid starting at `head`): a head up to the
/// next grid boundary, whole blocks, a tail (each may be empty). The caller checksums each piece and feeds the results
/// to [`BlockCrcs::push_piece`] in order.
pub fn grid_split(at: usize, len: usize, head: usize) -> (usize, usize, usize) {
    let first = if at < head {
        head - at
    } else {
        (BLK - (at - head) % BLK) % BLK
    };
    let first = first.min(len);
    let whole = (len - first) / BLK;
    (first, whole, len - first - whole * BLK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crc32c;

    fn data(n: usize) -> Vec<u8> {
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 32) as u8
            })
            .collect()
    }

    #[test]
    fn reseed_matches_a_direct_crc() {
        let d = data(BLK);
        for s in [0u32, 1, !0, 0xDEAD_BEEF, 0x8000_0000] {
            assert_eq!(reseed_4k(s, crc32c(0, &d)), crc32c(s, &d), "seed {s:x}");
        }
    }

    #[test]
    fn every_piece_pattern_gives_the_same_blocks_and_crc() {
        let d = data(5 * BLK + 1234);
        for head in [0usize, 1, 14, 4095, 4096, 5000] {
            let want: Vec<u32> = d[head..]
                .as_chunks::<BLK>()
                .0
                .iter()
                .map(|b| crc32c(0, b))
                .collect();
            for step in [1usize, 7, 1448, 4095, 4096, 4097, 9000, d.len()] {
                let mut u = BlockCrcs::with_head(d.len(), head);
                let mut a = BlockCrcs::with_head(d.len(), head);
                let mut p = BlockCrcs::with_head(d.len(), head);
                let mut buf = Vec::new();
                for c in d.chunks(step) {
                    u.update(c);
                    buf.extend_from_slice(c);
                    a.advance(&buf, buf.len() == d.len());
                    let (h, w, t) = grid_split(p.pos(), c.len(), head);
                    p.push_piece(crc32c(0, &c[..h]), h);
                    for b in c[h..h + w * BLK].chunks(BLK) {
                        p.push_piece(crc32c(0, b), BLK);
                    }
                    p.push_piece(crc32c(0, &c[h + w * BLK..]), t);
                }
                let mut f = BlockCrcs::with_head(d.len(), head);
                let mut copy = vec![core::mem::MaybeUninit::<u8>::uninit(); d.len()];
                let mut at = 0;
                for c in d.chunks(step) {
                    f.update_copy(c, &mut copy[at..at + c.len()]);
                    at += c.len();
                }
                // SAFETY: update_copy wrote every byte of `copy`.
                let copy: Vec<u8> = copy
                    .into_iter()
                    .map(|b| unsafe { b.assume_init() })
                    .collect();
                assert_eq!(copy, d, "head {head} step {step}");
                for x in [&u, &a, &p, &f] {
                    assert_eq!(x.blocks(), &want[..], "head {head} step {step}");
                    assert_eq!(x.pos(), d.len());
                    assert_eq!(x.head(), head);
                    for s in [0u32, !0, 0x1234_5678] {
                        assert_eq!(
                            x.crc(s),
                            crc32c(s, &d),
                            "head {head} step {step} seed {s:x}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn crc_of_a_partial_payload_covers_what_was_accounted() {
        let d = data(3 * BLK);
        for head in [0usize, 14] {
            for n in [0usize, 5, 14, 15, BLK, BLK + 14, BLK + 15, 3 * BLK] {
                let mut a = BlockCrcs::with_head(d.len(), head);
                a.update(&d[..n]);
                assert_eq!(a.crc(!0), crc32c(!0, &d[..n]), "head {head} n {n}");
            }
        }
    }

    #[test]
    fn advance_waits_for_whole_blocks() {
        let d = data(3 * BLK);
        let mut a = BlockCrcs::with_len(d.len());
        a.advance(&d[..BLK - 1], false);
        assert_eq!((a.pos(), a.blocks().len()), (0, 0));
        a.advance(&d[..2 * BLK + 5], false);
        assert_eq!((a.pos(), a.blocks().len()), (2 * BLK, 2));
        a.advance(&d[..2 * BLK + 5], true);
        assert_eq!(a.pos(), 2 * BLK + 5);
        assert_eq!(a.crc(!0), crc32c(!0, &d[..2 * BLK + 5]));
        // grid at 14: the first block closes at 14 + 4096
        let mut a = BlockCrcs::with_head(d.len(), 14);
        a.advance(&d[..BLK + 13], false);
        assert_eq!((a.pos(), a.blocks().len()), (14, 0));
        a.advance(&d[..BLK + 14], false);
        assert_eq!((a.pos(), a.blocks().len()), (BLK + 14, 1));
    }

    #[test]
    fn grid_split_covers_the_range() {
        for head in [0usize, 14, 4096] {
            for at in [0usize, 1, 13, 14, 15, 4095, 4096, 4110, 5000] {
                for len in [0usize, 1, 100, 4096, 9000] {
                    let (h, w, t) = grid_split(at, len, head);
                    assert_eq!(h + w * BLK + t, len);
                    assert!(t < BLK);
                    if w + t > 0 {
                        assert!(
                            at + h >= head && (at + h - head) % BLK == 0,
                            "{head} {at} {len}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn update_extend_matches_update() {
        let d = data(3 * BLK + 77);
        for step in [1usize, 100, 4095, 4096, 5000, d.len()] {
            let mut a = BlockCrcs::with_len(d.len());
            let mut b = BlockCrcs::with_len(d.len());
            let mut out = vec![9u8];
            for c in d.chunks(step) {
                a.update(c);
                b.update_extend(c, &mut out);
            }
            assert_eq!(&out[1..], &d[..]);
            assert_eq!(out[0], 9);
            assert_eq!(a.blocks(), b.blocks(), "step {step}");
            assert_eq!(b.crc(!0), crc32c(!0, &d));
        }
    }
}
