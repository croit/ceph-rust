// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `ceph::BitVector<2>` blob (object map), spec cls_rbd.md C.1.2 / C.1.3.
//!
//! Layout: `u32 14 | u8 v=1 | u8 compat=1 | u32 8 | u64 n` (18 bytes), `ceil(n/4)` data bytes
//! (element 0 = MSB pair of byte 0), `u32 footer_len`, then if footer_len > 0:
//! `u32 header_crc | u32 k | k x u32 data_crc` (one crc per 4096 data bytes; crc32c seed 0).

use denc::Decoder;

pub const HEADER_LEN: usize = 18;
pub const BLOCK: usize = 4096;
pub const ELEMS_PER_BLOCK: u64 = (BLOCK * 4) as u64;

pub const OBJECT_NONEXISTENT: u8 = 0;
pub const OBJECT_EXISTS: u8 = 1;
pub const OBJECT_PENDING: u8 = 2;
pub const OBJECT_EXISTS_CLEAN: u8 = 3;

/// Decoded/in-memory object map.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ObjMap {
    pub n: u64,
    /// Exactly `ceil(n/4)` bytes (padding bits preserved).
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadBlob;

pub fn data_len(n: u64) -> usize {
    n.div_ceil(4) as usize
}

pub fn crc(b: &[u8]) -> u32 {
    crc::crc32c(0, b)
}

/// Header bytes (18) for `n` elements.
pub fn header(n: u64) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0..4].copy_from_slice(&14u32.to_le_bytes());
    h[4] = 1;
    h[5] = 1;
    h[6..10].copy_from_slice(&8u32.to_le_bytes());
    h[10..18].copy_from_slice(&n.to_le_bytes());
    h
}

/// Parse the 18-byte header; returns `n`.
pub fn parse_header(h: &[u8]) -> Result<u64, BadBlob> {
    if h.len() < HEADER_LEN {
        return Err(BadBlob);
    }
    let mut d = Decoder::new(h);
    let len = d.u32().map_err(|_| BadBlob)?;
    if len != 14 {
        // the outer length covers the struct header (6) + 8; anything else is not ours
        return Err(BadBlob);
    }
    d.versioned(1, |d, _| d.u64()).map_err(|_| BadBlob)
}

pub fn get(data: &[u8], i: u64) -> u8 {
    let b = data[(i / 4) as usize];
    (b >> ((3 - (i % 4) as u32) * 2)) & 3
}

pub fn set(data: &mut [u8], i: u64, v: u8) {
    let sh = (3 - (i % 4) as u32) * 2;
    let b = &mut data[(i / 4) as usize];
    *b = (*b & !(3 << sh)) | ((v & 3) << sh);
}

/// Byte with all four elements set to `v`.
fn fill_byte(v: u8) -> u8 {
    let v = v & 3;
    v | (v << 2) | (v << 4) | (v << 6)
}

impl ObjMap {
    pub fn new(n: u64, fill: u8) -> Self {
        let mut m = ObjMap::default();
        m.resize(n, fill);
        m
    }
    pub fn get(&self, i: u64) -> u8 {
        get(&self.data, i)
    }
    pub fn set(&mut self, i: u64, v: u8) {
        set(&mut self.data, i, v)
    }

    /// Decode a full blob. CRCs (header + every data block) are verified when the footer carries
    /// them; footer_len 0 = CRCs disabled.
    pub fn decode(b: &[u8]) -> Result<Self, BadBlob> {
        Self::decode_crc(b).map(|(m, _)| m)
    }

    /// `decode` plus whether the blob carried CRCs (a re-encode keeps that choice, classic parity).
    pub fn decode_crc(b: &[u8]) -> Result<(Self, bool), BadBlob> {
        let n = parse_header(b)?;
        let dl = data_len(n);
        // n comes from the blob: bound it by the bytes we actually have
        let rest = b.get(HEADER_LEN..).ok_or(BadBlob)?;
        let data = rest.get(..dl).ok_or(BadBlob)?;
        let foot = &rest[dl..];
        let mut d = Decoder::new(foot);
        let flen = d.u32().map_err(|_| BadBlob)? as usize;
        if flen > 0 {
            let hcrc = d.u32().map_err(|_| BadBlob)?;
            let k = d.u32().map_err(|_| BadBlob)? as usize;
            if flen != 8 + 4 * k || k != dl.div_ceil(BLOCK) {
                return Err(BadBlob);
            }
            if hcrc != crc(&b[4..HEADER_LEN]) {
                return Err(BadBlob);
            }
            for j in 0..k {
                let want = d.u32().map_err(|_| BadBlob)?;
                let blk = &data[j * BLOCK..((j + 1) * BLOCK).min(dl)];
                if crc(blk) != want {
                    return Err(BadBlob);
                }
            }
        }
        let m = ObjMap {
            n,
            data: data.to_vec(),
        };
        Ok((m, flen > 0))
    }

    /// Encode with CRC footer.
    pub fn encode(&self) -> Vec<u8> {
        self.encode_opt(true)
    }
    /// Encode without CRCs (`footer_len = 0`), as `object_map_load` returns it.
    pub fn encode_nocrc(&self) -> Vec<u8> {
        self.encode_opt(false)
    }
    pub fn encode_opt(&self, with_crc: bool) -> Vec<u8> {
        let h = header(self.n);
        let k = self.data.len().div_ceil(BLOCK);
        // footer body (header crc, count, block crcs); its u32 length prefix comes on top.
        let footer = 8 + 4 * k;
        let tail = if with_crc { 4 + footer } else { 4 };
        // exact size: growing would reallocate and copy the whole map for the last CRC slot
        let mut out = Vec::with_capacity(HEADER_LEN + self.data.len() + tail);
        out.extend_from_slice(&h);
        out.extend_from_slice(&self.data);
        if with_crc {
            out.extend_from_slice(&(footer as u32).to_le_bytes());
            out.extend_from_slice(&crc(&h[4..]).to_le_bytes());
            out.extend_from_slice(&(k as u32).to_le_bytes());
            for blk in self.data.chunks(BLOCK) {
                out.extend_from_slice(&crc(blk).to_le_bytes());
            }
        } else {
            out.extend_from_slice(&0u32.to_le_bytes());
        }
        out
    }

    /// Resize: grow fills new elements with `fill`, shrink truncates. Padding bits (elements >= n in
    /// the last byte) are zero in newly added bytes and untouched in an existing byte (spec: "left
    /// untouched on shrink"; a later grow inside that byte overwrites only the new elements). The
    /// interior is filled in bulk, so a grow to `MAX_OBJECT_MAP_OBJECT_COUNT` (256M elements, `rbd
    /// create`/resize of a 1 PiB image) is one patterned `Vec::resize` instead of 256M masked
    /// read-modify-writes.
    pub fn resize(&mut self, n: u64, fill: u8) {
        let old = self.n;
        self.n = n;
        if n <= old {
            self.data.truncate(data_len(n));
            return;
        }
        let v = fill & 3;
        // the byte that already holds old elements is finished element-wise (at most 3 elements)
        if !old.is_multiple_of(4) {
            let end = ((old / 4 + 1) * 4).min(n);
            for i in old..end {
                set(&mut self.data, i, v);
            }
        }
        let (old_len, new_len) = (self.data.len(), data_len(n));
        if new_len > old_len {
            self.data.resize(new_len, fill_byte(v));
            // padding of the fresh last byte is zero (old code: zero-extended, then set per element)
            for i in n..new_len as u64 * 4 {
                set(&mut self.data, i, 0);
            }
        }
    }
}
