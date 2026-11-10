// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Source-pull PUT descriptor (adr 0665): the client names a READ-only source
//! region instead of sending the object bytes inline.
//!
//! A PUT extends the existing plain write MOSDOp: when both peers negotiated
//! source-pull (msgr2 banner bit 60), the connection is RDMA READY and READ
//! depths are offered, the request's data segment may carry exactly one
//! [`Descriptor`] (48 bytes, little-endian) instead of inline bytes. The OSD
//! RDMA-READs the named range into its registered write buffers, verifies the
//! transferred extents against `crc32c` when the record carries one, then
//! follows the unchanged durable write and replication contract.
//!
//! The crc is optional: a host source carries it (the client hashes its CPU
//! bytes), a device source (GPU memory without a CPU mapping) does not; its
//! transfer integrity is the RoCE ICRC the receiving NIC checks per packet.
//!
//! The record is a fixed-size value with strict validation: any unknown version,
//! reserved bit, wrong magic, zero length, trailing byte or a crc field without
//! its flag is rejected before a byte is read. A peer that did not negotiate the
//! capability never receives a descriptor (the client sends inline data).
//!
//! Identity: `transaction` is chosen by the client per attempt and must not be
//! reused while an attempt may still be live; `attempt` counts retries of the
//! same logical write. The OSD binds the grant to the connection generation,
//! the transaction and the attempt (spec rdma-source-pull-contract.md).
use crate::le;

/// `b"SPUT"` in little-endian byte order.
pub const MAGIC: u32 = u32::from_le_bytes(*b"SPUT");
/// The only record version this implementation encodes or accepts.
pub const VERSION: u16 = 1;
/// Encoded length of one descriptor.
pub const LEN: usize = 48;
/// Largest range one descriptor may name (the MOSDOp data segment is bounded by
/// the messenger, this is the protocol's own hard limit).
pub const MAX_TRANSFER: u32 = 64 << 20;

/// `flags` bit 0: the range's crc32c is present in [`Descriptor::crc32c`]; clear = no crc
/// (the crc field is then zero).
pub const FLAG_CRC32C: u16 = 1 << 0;

/// Whether `middle` starts with this protocol's magic: the discriminator that
/// separates a source-pull PUT record from a placement READ record on the same
/// MOSDOp middle segment.
pub fn is_record(middle: &[u8]) -> bool {
    middle.len() >= 4 && middle[..4] == MAGIC.to_le_bytes()
}

/// Why a record was rejected. Every variant is a protocol violation of the
/// sender; the OSD answers without reading the source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The buffer is not exactly [`LEN`] bytes.
    Length,
    /// The first four bytes are not [`MAGIC`].
    Magic,
    /// An unsupported record version.
    Version,
    /// A reserved flag bit is set.
    Flags,
    /// A reserved field is non-zero (or the crc field without its flag).
    Reserved,
    /// A zero-length or over-large transfer.
    Range,
    /// A zero remote key or address.
    Source,
}

impl DecodeError {
    /// Negative errno the OSD reports for this rejection (`EINVAL`/`EPROTO`).
    pub fn errno(self) -> i32 {
        match self {
            Self::Length | Self::Range | Self::Source => -22,
            Self::Magic | Self::Version | Self::Flags | Self::Reserved => -71,
        }
    }
}

/// One source-pull PUT grant: where the client's READ-only bytes are and how the
/// OSD verifies them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Descriptor {
    /// Client virtual address (or DMA-BUF iova) the OSD reads from.
    pub address: u64,
    /// READ-only remote key: a type-2 MW bound to this attempt, or the parent MR
    /// of a provider that cannot bind (DMA-BUF).
    pub rkey: u32,
    /// Bytes to read; equals the object write length of this request.
    pub length: u32,
    /// crc32c over exactly `address..address + length`; `None` for a device source
    /// whose bytes the client cannot hash.
    pub crc32c: Option<u32>,
    /// Client transaction identity of this attempt (never reused while live).
    pub transaction: u64,
    /// Retry counter of the same logical write.
    pub attempt: u32,
}

impl Descriptor {
    /// Encode the fixed-size record.
    pub fn encode(&self) -> [u8; LEN] {
        let mut out = [0u8; LEN];
        out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&VERSION.to_le_bytes());
        let flags = if self.crc32c.is_some() {
            FLAG_CRC32C
        } else {
            0
        };
        out[6..8].copy_from_slice(&flags.to_le_bytes());
        out[8..12].copy_from_slice(&self.length.to_le_bytes());
        out[12..16].copy_from_slice(&self.crc32c.unwrap_or(0).to_le_bytes());
        out[16..24].copy_from_slice(&self.address.to_le_bytes());
        out[24..28].copy_from_slice(&self.rkey.to_le_bytes());
        out[28..32].copy_from_slice(&self.attempt.to_le_bytes());
        out[32..40].copy_from_slice(&self.transaction.to_le_bytes());
        // 40..48 reserved, zero.
        out
    }

    /// Decode and validate one record. Rejects anything this implementation does
    /// not encode exactly.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != LEN {
            return Err(DecodeError::Length);
        }
        if le::u32_at(bytes, 0) != MAGIC {
            return Err(DecodeError::Magic);
        }
        if le::u16_at(bytes, 4) != VERSION {
            return Err(DecodeError::Version);
        }
        let flags = le::u16_at(bytes, 6);
        if flags & !FLAG_CRC32C != 0 {
            return Err(DecodeError::Flags);
        }
        let crc32c = le::u32_at(bytes, 12);
        let crc32c = if flags & FLAG_CRC32C != 0 {
            Some(crc32c)
        } else if crc32c == 0 {
            None
        } else {
            return Err(DecodeError::Reserved);
        };
        let length = le::u32_at(bytes, 8);
        let address = le::u64_at(bytes, 16);
        let rkey = le::u32_at(bytes, 24);
        let attempt = le::u32_at(bytes, 28);
        let transaction = le::u64_at(bytes, 32);
        if le::u64_at(bytes, 40) != 0 {
            return Err(DecodeError::Reserved);
        }
        if length == 0 || length > MAX_TRANSFER {
            return Err(DecodeError::Range);
        }
        if address == 0 || rkey == 0 {
            return Err(DecodeError::Source);
        }
        Ok(Self {
            address,
            rkey,
            length,
            crc32c,
            transaction,
            attempt,
        })
    }
}

/// Alignment of every pull destination start in the OSD's arena: a pulled payload is a valid direct-IO
/// write buffer (kernel NVMe write view) without a copy.
pub const DEST_ALIGN: u64 = 4096;

/// Placement of pull destinations in one registered OSD arena: each pull gets a range of exactly its
/// length, 4 KiB aligned, first fit. The ring head (behind the last placed range) is tried first:
/// payloads are released roughly in arrival order (store completion), so the head walks over freed
/// space. Else every free gap is tried: a gap starts at the arena start or behind a range in use
/// (`ends`), so a range held long (a READ whose QP is not destroyed yet, a payload the store keeps)
/// shrinks the room instead of blocking it. `claim` tries one offset (it fails while that range
/// overlaps one in use); `None` = no gap fits now, the pull waits.
#[derive(Debug, Default)]
pub struct Ring {
    head: u64,
}

impl Ring {
    /// Claim `length` bytes in an arena of `arena` bytes; `ends` = end offsets of the ranges in use
    /// (bounded by the arena's lease capacity: at most `ends.len() + 2` claims are tried).
    pub fn place<T, E>(
        &mut self,
        arena: u64,
        length: u64,
        ends: &[u64],
        mut claim: impl FnMut(u64) -> Result<T, E>,
    ) -> Option<T> {
        let gaps = ends.iter().map(|e| e.next_multiple_of(DEST_ALIGN));
        for offset in std::iter::once(self.head)
            .chain(gaps)
            .chain(std::iter::once(0))
        {
            if offset.checked_add(length).is_none_or(|end| end > arena) {
                continue;
            }
            if let Ok(claimed) = claim(offset) {
                let next = (offset + length).next_multiple_of(DEST_ALIGN);
                self.head = if next >= arena { 0 } else { next };
                return Some(claimed);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Descriptor {
        Descriptor {
            address: 0x7f00_0000_1000,
            rkey: 0xdead_beef,
            length: 1 << 20,
            crc32c: Some(0x1234_5678),
            transaction: 0x0102_0304_0506_0708,
            attempt: 3,
        }
    }

    #[test]
    fn magic_discriminates_the_record() {
        assert!(is_record(&sample().encode()));
        assert!(!is_record(&[]));
        assert!(!is_record(b"SP"));
        // A placement READ record never starts with this magic.
        assert!(!is_record(&[0u8; LEN]));
    }

    #[test]
    fn round_trip_is_exact() {
        let d = sample();
        let bytes = d.encode();
        assert_eq!(bytes.len(), LEN);
        assert_eq!(Descriptor::decode(&bytes), Ok(d));
    }

    #[test]
    fn record_layout_is_stable() {
        let bytes = sample().encode();
        assert_eq!(&bytes[0..4], b"SPUT");
        assert_eq!(u16::from_le_bytes([bytes[4], bytes[5]]), 1);
        assert_eq!(u16::from_le_bytes([bytes[6], bytes[7]]), 1);
        assert_eq!(
            u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            1 << 20
        );
        assert_eq!(bytes[40..48], [0u8; 8]);
    }

    #[test]
    fn rejects_wrong_length() {
        let bytes = sample().encode();
        assert_eq!(
            Descriptor::decode(&bytes[..LEN - 1]),
            Err(DecodeError::Length)
        );
        let mut longer = bytes.to_vec();
        longer.push(0);
        assert_eq!(Descriptor::decode(&longer), Err(DecodeError::Length));
        assert_eq!(Descriptor::decode(&[]), Err(DecodeError::Length));
    }

    #[test]
    fn rejects_foreign_magic_and_version() {
        let mut bytes = sample().encode();
        bytes[0] ^= 0xff;
        assert_eq!(Descriptor::decode(&bytes), Err(DecodeError::Magic));
        let mut bytes = sample().encode();
        bytes[4] = 2;
        assert_eq!(Descriptor::decode(&bytes), Err(DecodeError::Version));
    }

    #[test]
    fn rejects_an_unknown_flag_or_a_crc_without_its_flag() {
        let mut bytes = sample().encode();
        bytes[6] |= 0x02;
        assert_eq!(Descriptor::decode(&bytes), Err(DecodeError::Flags));
        let mut bytes = sample().encode();
        bytes[6] = 0;
        assert_eq!(Descriptor::decode(&bytes), Err(DecodeError::Reserved));
    }

    /// A device source carries no crc: flag clear, field zero.
    #[test]
    fn a_crc_less_record_round_trips() {
        let d = Descriptor {
            crc32c: None,
            ..sample()
        };
        let bytes = d.encode();
        assert_eq!(u16::from_le_bytes([bytes[6], bytes[7]]), 0);
        assert_eq!(bytes[12..16], [0u8; 4]);
        assert_eq!(Descriptor::decode(&bytes), Ok(d));
    }

    #[test]
    fn rejects_reserved_bytes() {
        let mut bytes = sample().encode();
        bytes[47] = 1;
        assert_eq!(Descriptor::decode(&bytes), Err(DecodeError::Reserved));
    }

    #[test]
    fn rejects_zero_or_oversized_range() {
        let mut d = sample();
        d.length = 0;
        assert_eq!(Descriptor::decode(&d.encode()), Err(DecodeError::Range));
        let mut d = sample();
        d.length = MAX_TRANSFER + 1;
        assert_eq!(Descriptor::decode(&d.encode()), Err(DecodeError::Range));
    }

    #[test]
    fn rejects_null_source_or_key() {
        let mut d = sample();
        d.address = 0;
        assert_eq!(Descriptor::decode(&d.encode()), Err(DecodeError::Source));
        let mut d = sample();
        d.rkey = 0;
        assert_eq!(Descriptor::decode(&d.encode()), Err(DecodeError::Source));
    }

    #[test]
    fn errno_separates_bad_shape_from_bad_source() {
        assert_eq!(DecodeError::Magic.errno(), -71);
        assert_eq!(DecodeError::Reserved.errno(), -71);
        assert_eq!(DecodeError::Range.errno(), -22);
        assert_eq!(DecodeError::Source.errno(), -22);
    }

    /// Fake arena: claimed ranges, overlap refused.
    fn claim_in(used: &mut Vec<(u64, u64)>, offset: u64, length: u64) -> Result<(u64, u64), ()> {
        if used
            .iter()
            .any(|&(o, l)| o < offset + length && offset < o + l)
        {
            return Err(());
        }
        used.push((offset, length));
        Ok((offset, length))
    }

    /// Place `length` in the fake arena `used`.
    fn put(
        ring: &mut Ring,
        arena: u64,
        used: &mut Vec<(u64, u64)>,
        length: u64,
    ) -> Option<(u64, u64)> {
        let ends: Vec<u64> = used.iter().map(|&(o, l)| o + l).collect();
        ring.place(arena, length, &ends, |o| claim_in(used, o, length))
    }

    #[test]
    fn ring_places_exact_lengths_at_aligned_starts_and_waits_without_room() {
        let arena = u64::from(MAX_TRANSFER);
        let mut ring = Ring::default();
        let mut used = Vec::new();
        for (length, at) in [
            (4096, 0),
            (1 << 20, 4096),
            ((1 << 20) + 1, 4096 + (1 << 20)),
            (4096, 4096 + (2 << 20) + 4096),
        ] {
            let got = put(&mut ring, arena, &mut used, length);
            assert_eq!(got, Some((at, length)), "length {length}");
            assert_eq!(at % DEST_ALIGN, 0);
        }
        // a full-size pull waits while any payload is in use, then fits at the start
        let full = arena;
        assert_eq!(put(&mut ring, arena, &mut used, full), None);
        used.clear();
        assert_eq!(put(&mut ring, arena, &mut used, full), Some((0, full)));
        assert_eq!(put(&mut ring, arena, &mut used, 4096), None);
        used.clear();
        // the head wrapped after the full arena: the next pull starts at 0 again
        assert_eq!(put(&mut ring, arena, &mut used, 4096), Some((0, 4096)));
    }

    /// A range held for long (an abandoned READ's range until its QP is destroyed) at the start, in the
    /// middle, at the end or under the head shrinks the room; pulls keep being placed around it.
    #[test]
    fn ring_places_around_a_long_held_range() {
        let arena = 8 << 20;
        for stuck in [0, 4 << 20, arena - 4096, 12 << 10] {
            let mut ring = Ring::default();
            // the head sits at 12 KiB when the range at 12 KiB gets stuck
            let mut used = vec![(stuck, 4096)];
            for (i, length) in [4096u64, 1 << 20, (1 << 20) + 1, 3 << 20, 5000]
                .into_iter()
                .cycle()
                .take(200)
                .enumerate()
            {
                let got = put(&mut ring, arena, &mut used, length);
                let (at, _) =
                    got.unwrap_or_else(|| panic!("stuck {stuck}: pull {i} of {length} waits"));
                assert_eq!(at % DEST_ALIGN, 0);
                assert!(at + length <= arena);
                // the payload is released before the next pull; the stuck range stays
                used.retain(|&(o, _)| o == stuck);
            }
        }
    }

    /// The head and the start are both in use: the free gap behind another range takes the pull.
    #[test]
    fn ring_uses_a_gap_away_from_the_head_and_the_start() {
        let arena = 8 << 20;
        let mut ring = Ring::default();
        let mut used = Vec::new();
        let one = 1 << 20;
        assert_eq!(put(&mut ring, arena, &mut used, one), Some((0, one)));
        assert_eq!(put(&mut ring, arena, &mut used, one), Some((one, one)));
        // a range under the head stays (abandoned READ), the range at 1 MiB is released
        used.push((2 << 20, 4096));
        used.retain(|&(o, _)| o != one);
        assert_eq!(ring.head, 2 << 20);
        assert_eq!(put(&mut ring, arena, &mut used, one), Some((one, one)));
        // and the gap behind the held range for the next one
        assert_eq!(
            put(&mut ring, arena, &mut used, one),
            Some(((2 << 20) + 4096, one))
        );
        // no gap of 6 MiB: waits
        assert_eq!(put(&mut ring, arena, &mut used, 6 << 20), None);
    }

    #[test]
    fn ring_wraps_to_the_start_when_the_tail_is_too_short() {
        let arena = 8 << 20;
        let mut ring = Ring::default();
        let mut used = Vec::new();
        let six = 6 << 20;
        assert_eq!(put(&mut ring, arena, &mut used, six), Some((0, six)));
        // 3 MiB does not fit behind the head (2 MiB left) nor at 0 (in use): wait
        let three = 3 << 20;
        assert_eq!(put(&mut ring, arena, &mut used, three), None);
        used.clear();
        assert_eq!(put(&mut ring, arena, &mut used, three), Some((0, three)));
        // a pull longer than the arena never fits
        assert_eq!(put(&mut ring, arena, &mut used, arena + 1), None);
    }
}
