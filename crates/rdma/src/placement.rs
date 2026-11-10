// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Portable numeric descriptor for one placed READ. Decoding checks shape only;
//! the authenticated same-QP grant and retirement belong to the runtime owner.

use crate::le;
use crate::memory::MemoryRange;
use std::io;

/// One logical transfer on one authenticated connection. Retry numbers must
/// not be reused while an older descriptor can still exist at the peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowAttempt {
    pub connection: u64,
    pub tid: u64,
    pub retry: u32,
}

/// Client-owned destination for one peer attempt. Numeric fields alone never
/// prove that the peer has granted access to a live registered window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowDescriptor {
    pub attempt: WindowAttempt,
    pub range: MemoryRange,
    pub rkey: u32,
}

impl WindowDescriptor {
    /// Fixed v1 transport record; the enclosing msgr2 frame supplies integrity.
    pub const ENCODED_LEN: usize = 44;

    pub fn encode(self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        out[0] = 1;
        out[1] = 1; // read destination
        out[4..12].copy_from_slice(&self.attempt.connection.to_le_bytes());
        out[12..20].copy_from_slice(&self.attempt.tid.to_le_bytes());
        out[20..24].copy_from_slice(&self.attempt.retry.to_le_bytes());
        out[24..28].copy_from_slice(&self.rkey.to_le_bytes());
        out[28..36].copy_from_slice(&self.range.address().to_le_bytes());
        out[36..44].copy_from_slice(&self.range.length().to_le_bytes());
        out
    }

    /// Parse numeric shape only. A decoded record is untrusted until the caller
    /// validates the negotiated connection and live attempt.
    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != Self::ENCODED_LEN
            || bytes[0] != 1
            || bytes[1] != 1
            || bytes[2..4] != [0, 0]
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let u32_at = |o| le::u32_at(bytes, o);
        let u64_at = |o| le::u64_at(bytes, o);
        let range =
            MemoryRange::new(u64_at(28), u64_at(36)).map_err(|_| io::ErrorKind::InvalidData)?;
        Ok(Self {
            attempt: WindowAttempt {
                connection: u64_at(4),
                tid: u64_at(12),
                retry: u32_at(20),
            },
            rkey: u32_at(24),
            range,
        })
    }
}

/// In-band control record on the upgraded RC stream (msgr2 tag `0xF2`,
/// direction-checked by the connection layer). Kind 3 is the client's CANCEL,
/// kind 4 the server's RETIRED. The record carries no address or length: the
/// sender matches it to a retained attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlRecord {
    pub attempt: WindowAttempt,
    pub rkey: u32,
}

impl ControlRecord {
    /// Client CANCEL (server-role receivers).
    pub const CANCEL: u8 = 3;
    /// Server RETIRED (client-role receivers).
    pub const RETIRED: u8 = 4;
    pub const ENCODED_LEN: usize = 28;

    pub fn encode(self, kind: u8) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        out[0] = 1;
        out[1] = kind;
        out[4..12].copy_from_slice(&self.attempt.connection.to_le_bytes());
        out[12..20].copy_from_slice(&self.attempt.tid.to_le_bytes());
        out[20..24].copy_from_slice(&self.attempt.retry.to_le_bytes());
        out[24..28].copy_from_slice(&self.rkey.to_le_bytes());
        out
    }

    /// Parse numeric shape only (`kind` in {CANCEL, RETIRED}). The caller
    /// validates the direction, the negotiated connection and the live attempt.
    pub fn decode(bytes: &[u8]) -> io::Result<(u8, Self)> {
        if bytes.len() != Self::ENCODED_LEN
            || bytes[0] != 1
            || !matches!(bytes[1], Self::CANCEL | Self::RETIRED)
            || bytes[2..4] != [0, 0]
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let u32_at = |o| le::u32_at(bytes, o);
        let u64_at = |o| le::u64_at(bytes, o);
        Ok((
            bytes[1],
            Self {
                attempt: WindowAttempt {
                    connection: u64_at(4),
                    tid: u64_at(12),
                    retry: u32_at(20),
                },
                rkey: u32_at(24),
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_roundtrip_and_exact_shape_without_verbs() {
        let descriptor = WindowDescriptor {
            attempt: WindowAttempt {
                connection: 3,
                tid: 7,
                retry: 2,
            },
            range: MemoryRange::new(0x1000, 8192).unwrap(),
            rkey: 55,
        };
        let bytes = descriptor.encode();
        assert_eq!(WindowDescriptor::decode(&bytes).unwrap(), descriptor);
        assert!(WindowDescriptor::decode(&bytes[..43]).is_err());
        let mut bad = bytes;
        bad[2] = 1;
        assert!(WindowDescriptor::decode(&bad).is_err());
    }

    #[test]
    fn control_record_roundtrip_and_exact_shape_without_verbs() {
        let record = ControlRecord {
            attempt: WindowAttempt {
                connection: 9,
                tid: 4,
                retry: 1,
            },
            rkey: 77,
        };
        for kind in [ControlRecord::CANCEL, ControlRecord::RETIRED] {
            let bytes = record.encode(kind);
            let (decoded_kind, decoded) = ControlRecord::decode(&bytes).unwrap();
            assert_eq!(decoded_kind, kind);
            assert_eq!(decoded, record);
        }
        assert!(ControlRecord::decode(&[0; ControlRecord::ENCODED_LEN - 1]).is_err());
        let mut bad = record.encode(ControlRecord::CANCEL);
        bad[1] = 2; // a kind neither CANCEL nor RETIRED
        assert!(ControlRecord::decode(&bad).is_err());
        bad = record.encode(ControlRecord::CANCEL);
        bad[3] = 1; // reserved
        assert!(ControlRecord::decode(&bad).is_err());
    }
}
