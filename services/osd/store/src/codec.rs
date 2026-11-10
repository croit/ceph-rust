// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Little-endian encode/decode helpers and the crc conventions used on disk.

/// crc32c for on-disk structures (headers, root slots, WAL units): seed all-ones so that an all-zero
/// block never validates.
pub fn crc(data: &[u8]) -> u32 {
    crc::crc32c(!0, data)
}

/// Seed for per-data-block crcs: salted with the block address (design R7: misdirected/stale blocks fail).
pub fn blk_seed(blk: u64) -> u32 {
    !((blk as u32) ^ ((blk >> 32) as u32).wrapping_mul(0x9E37_79B1))
}

/// crc32c of one 4 KiB data block stored at engine block address `blk`.
pub fn blk_crc(blk: u64, data: &[u8]) -> u32 {
    crc::crc32c(blk_seed(blk), data)
}

#[derive(Default, Debug)]
pub struct Enc {
    pub b: Vec<u8>,
}

impl Enc {
    pub fn new() -> Enc {
        Enc { b: Vec::new() }
    }
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.b.push(v);
        self
    }
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.b.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.b.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.b.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.b.extend_from_slice(v);
        self
    }
    pub fn pad_to(&mut self, n: usize) -> &mut Self {
        assert!(self.b.len() <= n);
        self.b.resize(n, 0);
        self
    }
}

#[derive(Debug)]
pub struct Dec<'a> {
    b: &'a [u8],
    pub pos: usize,
}

impl<'a> Dec<'a> {
    pub fn new(b: &'a [u8]) -> Dec<'a> {
        Dec { b, pos: 0 }
    }
    pub fn left(&self) -> usize {
        self.b.len() - self.pos
    }
    pub fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.left() < n {
            return None;
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
    pub fn u8(&mut self) -> Option<u8> {
        self.bytes(1).map(|b| b[0])
    }
    pub fn u16(&mut self) -> Option<u16> {
        self.bytes(2)
            .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
    }
    pub fn u32(&mut self) -> Option<u32> {
        self.bytes(4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Option<u64> {
        self.bytes(8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
    }
    pub fn arr16(&mut self) -> Option<[u8; 16]> {
        self.bytes(16).map(|b| b.try_into().unwrap())
    }
}
