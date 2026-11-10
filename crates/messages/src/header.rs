// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `ceph_msg_header2` (msgr2.md 8.1), 41 bytes packed, little endian.

use denc::{Error, Result, le};

/// MESSAGE frame header (segment 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Header2 {
    pub seq: u64,
    pub tid: u64,
    pub ty: u16,
    pub priority: u16,
    pub version: u16,
    pub data_pre_padding_len: u32,
    pub data_off: u16,
    pub ack_seq: u64,
    pub flags: u8,
    pub compat_version: u16,
    pub reserved: u16,
}

impl Header2 {
    pub const LEN: usize = 41;
    /// Flags Ceph sends: COMPLETE | NOCRC.
    pub const FLAGS_DEFAULT: u8 = 0x03;

    /// New header (flags COMPLETE | NOCRC); a sender-left compat of 0 means `version`
    /// (seq/ack_seq/priority are filled by the messenger).
    pub fn new(tid: u64, ty: u16, version: u16, compat_version: u16) -> Self {
        Header2 {
            tid,
            ty,
            version,
            compat_version: if compat_version == 0 {
                version
            } else {
                compat_version
            },
            flags: Self::FLAGS_DEFAULT,
            ..Default::default()
        }
    }

    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() < Self::LEN {
            return Err(Error::Eof {
                needed: Self::LEN,
                remaining: b.len(),
            });
        }
        let u16_at = |o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
        let u64_at = |o: usize| le::rd_u64(b, o);
        Ok(Header2 {
            seq: u64_at(0),
            tid: u64_at(8),
            ty: u16_at(16),
            priority: u16_at(18),
            version: u16_at(20),
            data_pre_padding_len: le::rd_u32(b, 22),
            data_off: u16_at(26),
            ack_seq: u64_at(28),
            flags: b[36],
            compat_version: u16_at(37),
            reserved: u16_at(39),
        })
    }

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        le::wr_u64(&mut b, 0, self.seq);
        le::wr_u64(&mut b, 8, self.tid);
        b[16..18].copy_from_slice(&self.ty.to_le_bytes());
        b[18..20].copy_from_slice(&self.priority.to_le_bytes());
        b[20..22].copy_from_slice(&self.version.to_le_bytes());
        le::wr_u32(&mut b, 22, self.data_pre_padding_len);
        b[26..28].copy_from_slice(&self.data_off.to_le_bytes());
        le::wr_u64(&mut b, 28, self.ack_seq);
        b[36] = self.flags;
        b[37..39].copy_from_slice(&self.compat_version.to_le_bytes());
        b[39..41].copy_from_slice(&self.reserved.to_le_bytes());
        b
    }

    /// Effective compat: a sender that left 0 meant `version`.
    pub fn effective_compat(&self) -> u16 {
        if self.compat_version == 0 {
            self.version
        } else {
            self.compat_version
        }
    }
}
