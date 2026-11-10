// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Known crc of a shared payload, bound to the payload's owner.

use bytes::Bytes;
use std::sync::Arc;

use crate::blocks::BLK;

/// `crc32c(!0, data)` (the msgr2 data-segment crc) of a payload the producer already knows (store block checksums,
/// fused copy+crc). Holds a reference to the exact bytes it was made for: while the hint lives that allocation can be
/// neither freed nor reused nor mutated (`Bytes` is immutable and shared), so (address, length) identifies the very
/// same bytes. [`of`](Self::of) yields the crc only for a `Bytes` viewing that same range; anything else (replaced,
/// cut, copied, rebuilt payload) gets `None` and the consumer recomputes. Not part of equality (a hint, not content).
/// Optionally also the per-4 KiB block crcs of the receive pass ([`crate::blocks`], adr 0061 am. 4).
#[derive(Clone, Default)]
pub struct CrcHint(Option<Hinted>);

/// The hinted bytes, their crc, their block crcs if known (with the grid start in the bytes).
type Hinted = (Bytes, u32, Option<(Arc<[u32]>, usize)>);

impl CrcHint {
    /// Hint for `data`; `crc` must be `crc32c(!0, data)` (debug builds check).
    pub fn new(data: &Bytes, crc: u32) -> Self {
        debug_assert_eq!(
            crc,
            crate::crc32c(!0, data),
            "crc hint made for other bytes"
        );
        if data.is_empty() {
            return CrcHint(None);
        }
        CrcHint(Some((data.clone(), crc, None)))
    }

    /// [`new`](Self::new) plus `blocks[i] = crc32c(0, data[i*4096..(i+1)*4096])` for every whole block of `data`
    /// (debug builds check).
    pub fn with_blocks(data: &Bytes, crc: u32, blocks: Arc<[u32]>) -> Self {
        Self::with_blocks_at(data, crc, blocks, 0)
    }

    /// [`with_blocks`](Self::with_blocks) for a grid that starts at byte `grid` of `data`: `blocks[i]` covers
    /// `data[grid + i*4096..][..4096]` (a replicated write's blob, the payload sits at offset 14).
    pub fn with_blocks_at(data: &Bytes, crc: u32, blocks: Arc<[u32]>, grid: usize) -> Self {
        debug_assert_eq!(
            blocks.len(),
            data.len().saturating_sub(grid) / BLK,
            "block crc count"
        );
        debug_assert!(
            data[grid.min(data.len())..]
                .as_chunks::<BLK>()
                .0
                .iter()
                .zip(blocks.iter())
                .all(|(b, &c)| crate::crc32c(0, b) == c),
            "block crcs made for other bytes"
        );
        let mut h = Self::new(data, crc);
        if let Some(x) = h.0.as_mut() {
            x.2 = Some((blocks, grid));
        }
        h
    }

    /// The crc if `data` views exactly the bytes this hint was made for.
    pub fn of(&self, data: &[u8]) -> Option<u32> {
        let (b, c, _) = self.0.as_ref()?;
        (b.as_ptr() == data.as_ptr() && b.len() == data.len()).then_some(*c)
    }

    /// The payload (owner + block crcs if known) for the store, when the hint has block crcs.
    pub fn payload(&self) -> Option<Payload> {
        let (b, _, blocks) = self.0.as_ref()?;
        Some(Payload {
            owner: b.clone(),
            blocks: blocks.as_ref().map(|x| x.0.clone()),
            grid: blocks.as_ref().map_or(0, |x| x.1),
        })
    }
}

/// The hints of several payloads (e.g. the shared runs of one message); `of` looks a payload up by its exact bytes. Like
/// Send-side metadata, not content: deliberately no `PartialEq`, so a struct that carries hints must decide (and say) how it compares.
#[derive(Clone, Default, Debug)]
pub struct CrcHints(Vec<CrcHint>);

impl CrcHints {
    /// The crc (seed `!0`) of `data` if one of the hints was made for exactly these bytes.
    pub fn of(&self, data: &[u8]) -> Option<u32> {
        self.0.iter().find_map(|h| h.of(data))
    }

    /// The hint made for exactly `data`, if any.
    pub fn get(&self, data: &[u8]) -> Option<&CrcHint> {
        self.0.iter().find(|h| h.of(data).is_some())
    }

    /// Drop every hint (releases their references to the hinted bytes).
    pub fn clear(&mut self) {
        self.0.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<CrcHint>> for CrcHints {
    fn from(v: Vec<CrcHint>) -> Self {
        CrcHints(v)
    }
}

/// A payload buffer the store may write from by reference, with its receive-pass block crcs when known
/// (adr 0061 am. 4). `blocks[i]` = `crc32c(0, owner[grid + i*4096..][..4096])` for every whole block of `owner` after
/// `grid` (0 for a client payload that is a whole data segment; 14 for a replica's v9 txn blob).
#[derive(Clone)]
pub struct Payload {
    pub owner: Bytes,
    pub blocks: Option<Arc<[u32]>>,
    pub grid: usize,
}

impl Payload {
    /// Payload without block crcs (owner only).
    pub fn owner(owner: Bytes) -> Payload {
        Payload {
            owner,
            blocks: None,
            grid: 0,
        }
    }

    /// The payload of `list` whose bytes contain `src`, and the offset of `src` in it.
    pub fn find<'p>(list: &'p [Payload], src: &[u8]) -> Option<(&'p Payload, usize)> {
        let s = src.as_ptr() as usize;
        list.iter().find_map(|p| {
            let b = p.owner.as_ptr() as usize;
            (s >= b && s + src.len() <= b + p.owner.len()).then(|| (p, s - b))
        })
    }

    /// Block crcs of `owner[off..off + nblk*4096]` when that range starts on the grid and every block is whole.
    pub fn blocks_at(&self, off: usize, nblk: usize) -> Option<&[u32]> {
        let b = self.blocks.as_deref()?;
        let rel = off.checked_sub(self.grid)?;
        if !rel.is_multiple_of(BLK) {
            return None;
        }
        b.get(rel / BLK..(rel / BLK).checked_add(nblk)?)
    }
}

impl core::fmt::Debug for Payload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Payload({} B, {} block crcs)",
            self.owner.len(),
            self.blocks.as_ref().map_or(0, |b| b.len())
        )
    }
}

impl core::fmt::Debug for CrcHint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.0 {
            None => f.write_str("CrcHint(None)"),
            Some((b, c, k)) => write!(
                f,
                "CrcHint({c:#010x}, {} B{})",
                b.len(),
                if k.is_some() { ", blocks" } else { "" }
            ),
        }
    }
}

impl PartialEq for CrcHint {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
impl Eq for CrcHint {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bound_to_the_exact_bytes() {
        let d = Bytes::from((0..10_000u32).map(|i| i as u8).collect::<Vec<u8>>());
        let c = crate::crc32c(!0, &d);
        let h = CrcHint::new(&d, c);
        assert_eq!(h.of(&d), Some(c));
        assert_eq!(h.of(&d.clone()), Some(c));
        assert_eq!(h.of(&d.slice(..)), Some(c));
        assert_eq!(h.of(&d.slice(1..)), None);
        assert_eq!(h.of(&d.slice(..9_999)), None);
        let copy = Bytes::copy_from_slice(&d);
        assert_eq!(h.of(&copy), None, "equal content elsewhere is not trusted");
        assert_eq!(CrcHint::default().of(&d), None);
        assert_eq!(CrcHint::new(&Bytes::new(), 0xFFFF_FFFF).of(&[]), None);
        assert!(h.payload().is_some_and(|p| p.blocks.is_none()));
    }

    #[test]
    fn no_address_reuse_while_the_hint_lives() {
        // the old ptr+len hint matched a new allocation landing on the freed address (ABA): the hint now owns a
        // reference, so the original allocation stays alive and a fresh one can never share its address
        let mut d = Bytes::from(vec![7u8; 4096]);
        let h = CrcHint::new(&d, crate::crc32c(!0, &d));
        let addr = d.as_ptr();
        for i in 0..64u8 {
            d = Bytes::from(vec![i; 4096]);
            assert_ne!(d.as_ptr(), addr);
            assert_eq!(h.of(&d), None);
        }
    }

    #[test]
    fn payload_blocks_only_on_the_grid_and_inside() {
        let d = Bytes::from(
            (0..3 * BLK + 100)
                .map(|i| (i * 7) as u8)
                .collect::<Vec<u8>>(),
        );
        let blocks: Arc<[u32]> = d
            .as_chunks::<BLK>()
            .0
            .iter()
            .map(|b| crate::crc32c(0, b))
            .collect();
        let h = CrcHint::with_blocks(&d, crate::crc32c(!0, &d), blocks.clone());
        let p = h.payload().unwrap();
        let list = [Payload::owner(Bytes::from(vec![0u8; 10])), p];
        let (q, off) = Payload::find(&list, &d[BLK..3 * BLK]).unwrap();
        assert_eq!(off, BLK);
        assert_eq!(q.blocks_at(off, 2), Some(&blocks[1..3]));
        assert_eq!(
            q.blocks_at(off, 3),
            None,
            "the partial tail has no block crc"
        );
        assert_eq!(q.blocks_at(1, 1), None, "off the grid");
        assert_eq!(
            q.blocks_at(BLK, usize::MAX),
            None,
            "a block count past the table is not a panic"
        );
        assert!(Payload::find(&list, &Bytes::copy_from_slice(&d[..BLK])).is_none());
    }

    #[test]
    fn payload_grid_starts_at_the_blob_offset() {
        // a replica's txn blob: the client payload (whole blocks) starts at byte 14
        let d = Bytes::from(
            (0..14 + 3 * BLK + 50)
                .map(|i| (i * 11) as u8)
                .collect::<Vec<u8>>(),
        );
        let blocks: Arc<[u32]> = d[14..]
            .as_chunks::<BLK>()
            .0
            .iter()
            .map(|b| crate::crc32c(0, b))
            .collect();
        let h = CrcHint::with_blocks_at(&d, crate::crc32c(!0, &d), blocks.clone(), 14);
        let p = h.payload().unwrap();
        assert_eq!(p.grid, 14);
        assert_eq!(p.blocks_at(14, 3), Some(&blocks[..]));
        assert_eq!(p.blocks_at(14 + BLK, 2), Some(&blocks[1..3]));
        assert_eq!(p.blocks_at(0, 1), None, "before the grid");
        assert_eq!(
            p.blocks_at(BLK, 1),
            None,
            "the blob grid is not the payload grid"
        );
        assert_eq!(p.blocks_at(14, 4), None);
    }
}
