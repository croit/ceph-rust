// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Borrowed successful READ receipt. Shape validation and CRC verification do not authorize
//! remote memory access or establish peer retirement; the authenticated attempt owner does that.
use super::WindowDescriptor;
use std::io;

const HEADER: usize = 40;
const BLOCK: usize = 4096;

/// Direction of a one-attempt retirement control record. A decoded record is never
/// itself proof that the server has stopped posting writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetirementKind {
    /// Client asks the server to stop issuing writes for the exact offered grant.
    Cancel,
    /// Server confirms it stopped and retired all earlier writes on this RC SQ.
    Retired,
}

/// Exact-identity in-band control record for cancellation and ordered retirement.
/// The enclosing msgr2 control frame supplies CRC or authentication and QP ordering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetirementRecord {
    pub kind: RetirementKind,
    pub descriptor: WindowDescriptor,
}

impl RetirementRecord {
    pub const ENCODED_LEN: usize = 28;

    pub fn encode(self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        out[0] = 1;
        out[1] = match self.kind {
            RetirementKind::Cancel => 3,
            RetirementKind::Retired => 4,
        };
        out[4..12].copy_from_slice(&self.descriptor.attempt.connection.to_le_bytes());
        out[12..20].copy_from_slice(&self.descriptor.attempt.tid.to_le_bytes());
        out[20..24].copy_from_slice(&self.descriptor.attempt.retry.to_le_bytes());
        out[24..28].copy_from_slice(&self.descriptor.rkey.to_le_bytes());
        out
    }

    /// Match the wire identity to a live local grant before any state transition.
    /// The caller also checks the authenticated connection and control-frame direction.
    pub fn decode(bytes: &[u8], descriptor: WindowDescriptor) -> io::Result<Self> {
        if bytes.len() != Self::ENCODED_LEN || bytes[0] != 1 || bytes[2..4] != [0, 0] {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let kind = match bytes[1] {
            3 => RetirementKind::Cancel,
            4 => RetirementKind::Retired,
            _ => return Err(io::ErrorKind::InvalidData.into()),
        };
        let u32_at = |o| u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
        let u64_at = |o| u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap());
        if u64_at(4) != descriptor.attempt.connection
            || u64_at(12) != descriptor.attempt.tid
            || u32_at(20) != descriptor.attempt.retry
            || u32_at(24) != descriptor.rkey
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(Self { kind, descriptor })
    }
}

/// Validated metadata for one successful placed READ. Borrows the enclosing msgr2 middle segment.
#[derive(Clone, Copy, Debug)]
pub struct ReadReceipt<'a> {
    descriptor: WindowDescriptor,
    written_len: usize,
    crcs: &'a [u8],
}

impl<'a> ReadReceipt<'a> {
    /// Encode a receipt directly from retained immutable source pieces. One allocation holds
    /// the final wire record; a split 4096-byte block is checksummed across piece boundaries.
    /// The caller must already have observed every WRITE CQE for these exact pieces.
    pub(crate) fn encode_parts<'p>(
        descriptor: WindowDescriptor,
        written_len: usize,
        parts: impl IntoIterator<Item = &'p [u8]>,
    ) -> io::Result<Vec<u8>> {
        let count = written_len.div_ceil(BLOCK);
        let written = u64::try_from(written_len).map_err(|_| io::ErrorKind::InvalidInput)?;
        if written > descriptor.range.length() || u32::try_from(count).is_err() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let total = HEADER
            .checked_add(count.checked_mul(4).ok_or(io::ErrorKind::InvalidInput)?)
            .ok_or(io::ErrorKind::InvalidInput)?;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&[1, 2, 0, 0]);
        out.extend_from_slice(&descriptor.attempt.connection.to_le_bytes());
        out.extend_from_slice(&descriptor.attempt.tid.to_le_bytes());
        out.extend_from_slice(&descriptor.attempt.retry.to_le_bytes());
        out.extend_from_slice(&descriptor.rkey.to_le_bytes());
        out.extend_from_slice(&written.to_le_bytes());
        out.extend_from_slice(&(count as u32).to_le_bytes());
        let (mut seen, mut filled, mut crc) = (0usize, 0usize, 0u32);
        for mut part in parts {
            seen = seen
                .checked_add(part.len())
                .filter(|&n| n <= written_len)
                .ok_or(io::ErrorKind::InvalidInput)?;
            while !part.is_empty() {
                let n = part.len().min(BLOCK - filled);
                crc = crc::crc32c(crc, &part[..n]);
                filled += n;
                part = &part[n..];
                if filled == BLOCK {
                    out.extend_from_slice(&crc.to_le_bytes());
                    (crc, filled) = (0, 0);
                }
            }
        }
        if seen != written_len {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if filled != 0 {
            out.extend_from_slice(&crc.to_le_bytes());
        }
        debug_assert_eq!(out.len(), total);
        Ok(out)
    }

    /// Encode metadata for the exact descriptor. The caller must first finish its RMA WRITEs
    /// and calculate `crcs` from the bytes actually written in 4096-byte blocks (tail included).
    pub fn encode(
        descriptor: WindowDescriptor,
        written_len: usize,
        crcs: &[u32],
    ) -> io::Result<Vec<u8>> {
        let count = written_len.div_ceil(BLOCK);
        let written = u64::try_from(written_len).map_err(|_| io::ErrorKind::InvalidInput)?;
        if written > descriptor.range.length()
            || count != crcs.len()
            || u32::try_from(count).is_err()
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let total = HEADER
            .checked_add(count.checked_mul(4).ok_or(io::ErrorKind::InvalidInput)?)
            .ok_or(io::ErrorKind::InvalidInput)?;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&[1, 2, 0, 0]);
        out.extend_from_slice(&descriptor.attempt.connection.to_le_bytes());
        out.extend_from_slice(&descriptor.attempt.tid.to_le_bytes());
        out.extend_from_slice(&descriptor.attempt.retry.to_le_bytes());
        out.extend_from_slice(&descriptor.rkey.to_le_bytes());
        out.extend_from_slice(&written.to_le_bytes());
        out.extend_from_slice(&(count as u32).to_le_bytes());
        for crc in crcs {
            out.extend_from_slice(&crc.to_le_bytes());
        }
        Ok(out)
    }

    /// Reject malformed or mismatched metadata before reading any placed bytes. This is numeric
    /// validation; the caller separately authenticates the msgr2 frame and matches its session.
    pub fn decode(bytes: &'a [u8], descriptor: WindowDescriptor) -> io::Result<Self> {
        if bytes.len() < HEADER || bytes[..4] != [1, 2, 0, 0] {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let u32_at = |o| u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
        let u64_at = |o| u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap());
        if u64_at(4) != descriptor.attempt.connection
            || u64_at(12) != descriptor.attempt.tid
            || u32_at(20) != descriptor.attempt.retry
            || u32_at(24) != descriptor.rkey
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let written = u64_at(28);
        let written_len = usize::try_from(written).map_err(|_| io::ErrorKind::InvalidData)?;
        let count = written_len.div_ceil(BLOCK);
        if written > descriptor.range.length()
            || u32::try_from(count).ok() != Some(u32_at(36))
            || HEADER.checked_add(count.checked_mul(4).ok_or(io::ErrorKind::InvalidData)?)
                != Some(bytes.len())
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(Self {
            descriptor,
            written_len,
            crcs: &bytes[HEADER..],
        })
    }

    pub fn written_len(&self) -> usize {
        self.written_len
    }

    pub fn descriptor(&self) -> WindowDescriptor {
        self.descriptor
    }

    /// Verify all placed bytes after peer retirement and before exposing them to the application.
    /// A failed block rejects the entire placed result; no partial data is accepted.
    pub fn verify(&self, data: &[u8]) -> io::Result<()> {
        if data.len() != self.written_len {
            return Err(io::ErrorKind::InvalidData.into());
        }
        for (i, block) in data.chunks(BLOCK).enumerate() {
            let at = 4 * i;
            let expected = u32::from_le_bytes(self.crcs[at..at + 4].try_into().unwrap());
            if crc::crc32c(0, block) != expected {
                return Err(io::ErrorKind::InvalidData.into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryRange;
    use crate::verbs::WindowAttempt;

    fn descriptor() -> WindowDescriptor {
        WindowDescriptor {
            attempt: WindowAttempt {
                connection: 7,
                tid: 11,
                retry: 2,
            },
            range: MemoryRange::new(0x1000, 8192).unwrap(),
            rkey: 0x1234_5678,
        }
    }

    #[test]
    fn exact_receipt_and_tail_crc_reject_mutated_data() {
        let data = vec![0x5au8; 5000];
        let crcs: Vec<_> = data.chunks(BLOCK).map(|b| crc::crc32c(0, b)).collect();
        let wire = ReadReceipt::encode(descriptor(), data.len(), &crcs).unwrap();
        assert_eq!(wire.len(), HEADER + 8);
        assert_eq!(&wire[..4], &[1, 2, 0, 0]);
        let receipt = ReadReceipt::decode(&wire, descriptor()).unwrap();
        assert_eq!(receipt.written_len(), data.len());
        assert_eq!(receipt.descriptor(), descriptor());
        receipt.verify(&data).unwrap();
        let mut changed = data.clone();
        changed[4096] ^= 1;
        assert!(receipt.verify(&changed).is_err(), "tail mutation");
        changed = data;
        changed[0] ^= 1;
        assert!(receipt.verify(&changed).is_err(), "first block mutation");
        assert!(
            receipt.verify(&changed[..4999]).is_err(),
            "wrong payload length"
        );
    }

    #[test]
    fn source_pieces_encode_into_one_receipt_across_block_boundaries() {
        let data: Vec<u8> = (0..7001).map(|i| (i * 37) as u8).collect();
        let chunks = [
            &data[..31],
            &data[31..4089],
            &data[4089..4099],
            &data[4099..],
        ];
        let wire = ReadReceipt::encode_parts(descriptor(), data.len(), chunks).unwrap();
        let expected: Vec<_> = data.chunks(BLOCK).map(|b| crc::crc32c(0, b)).collect();
        assert_eq!(
            wire,
            ReadReceipt::encode(descriptor(), data.len(), &expected).unwrap()
        );
        ReadReceipt::decode(&wire, descriptor())
            .unwrap()
            .verify(&data)
            .unwrap();
        assert_eq!(
            ReadReceipt::encode_parts(descriptor(), 0, std::iter::empty()).unwrap(),
            ReadReceipt::encode(descriptor(), 0, &[]).unwrap()
        );
        assert!(ReadReceipt::encode_parts(descriptor(), data.len() - 1, chunks).is_err());
        assert!(ReadReceipt::encode_parts(descriptor(), data.len() + 1, chunks).is_err());
    }

    #[test]
    fn malformed_receipt_never_allocates_or_accepts_other_attempt() {
        let d = descriptor();
        let mut wire = ReadReceipt::encode(d, 0, &[]).unwrap();
        assert_eq!(wire.len(), HEADER);
        ReadReceipt::decode(&wire, d).unwrap().verify(&[]).unwrap();
        let mut other = d;
        other.attempt.retry += 1;
        assert!(ReadReceipt::decode(&wire, other).is_err());
        wire[2] = 1;
        assert!(ReadReceipt::decode(&wire, d).is_err());
        wire[2] = 0;
        wire[36] = 1;
        assert!(ReadReceipt::decode(&wire, d).is_err());
        wire[36] = 0;
        wire.extend_from_slice(&0u32.to_le_bytes());
        assert!(ReadReceipt::decode(&wire, d).is_err());
        assert!(ReadReceipt::decode(&wire[..39], d).is_err());
    }

    #[test]
    fn retirement_record_matches_full_identity_and_rejects_malformed_control() {
        let descriptor = descriptor();
        for kind in [RetirementKind::Cancel, RetirementKind::Retired] {
            let record = RetirementRecord { kind, descriptor };
            let wire = record.encode();
            assert_eq!(RetirementRecord::decode(&wire, descriptor).unwrap(), record);
            assert_eq!(wire.len(), RetirementRecord::ENCODED_LEN);
            assert_eq!(&wire[..1], &[1]);
            for changed in [
                WindowDescriptor {
                    rkey: descriptor.rkey + 1,
                    ..descriptor
                },
                WindowDescriptor {
                    attempt: crate::verbs::WindowAttempt {
                        retry: descriptor.attempt.retry + 1,
                        ..descriptor.attempt
                    },
                    ..descriptor
                },
            ] {
                assert!(RetirementRecord::decode(&wire, changed).is_err());
            }
            for offset in [0, 1, 2, 4, 12, 20, 24] {
                let mut corrupt = wire;
                corrupt[offset] ^= 0x80;
                assert!(RetirementRecord::decode(&corrupt, descriptor).is_err());
            }
            assert!(RetirementRecord::decode(&wire[..27], descriptor).is_err());
            let mut extra = wire.to_vec();
            extra.push(0);
            assert!(RetirementRecord::decode(&extra, descriptor).is_err());
        }
    }
}
