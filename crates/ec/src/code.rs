// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! One erasure code of a pool, whatever the plugin (static dispatch, no allocation in the region loops).
//!
//! Indices are RAW chunk indices (0..k data in order, k..n parity/other), the shard mapping stays with the caller.
//! `read_set` is the minimum_to_decode of the OSD: which raw chunks must be read to rebuild `want` from `avail`.

use crate::bitmat::{BitCodec, BitTech};
use crate::clay::ClayCodec;
use crate::gf::{Codec, DecodeError, Kind};
use crate::lrc::LrcCodec;
use crate::placed::Placed;
use crate::profile::{EcProfile, Plugin};
use crate::shec::ShecCodec;
use crate::wide::{WideCodec, WideKind};
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub enum Code {
    /// Byte-wise GF(2^8) matrix codes (isa, jerasure reed_sol_*), any k of n.
    Rs(Codec),
    /// jerasure reed_sol_van / r6_op over GF(2^16) or GF(2^32) (little-endian word regions).
    Wide(WideCodec),
    /// Jerasure bit-matrix codes (packet XOR), any k of n.
    Bit(BitCodec),
    /// shec: shingled non-MDS GF(2^8) code (spec ec-shec.md).
    Shec(ShecCodec),
    /// Layered locally repairable code (lrc plugin): non-MDS, own read planner. Chunk indices are still RAW.
    Lrc(Box<LrcCodec>),
    /// Coupled-layer MSR code (clay plugin, GF(2^8) MDS scalars only); per-stripe codewords, see [`ClayCodec::set_chunk`].
    Clay(Box<ClayCodec>),
    /// Classic legacy index placement of a non-identity mapping around isa / jerasure / clay (spec ec-parity.md 3.4).
    Placed(Box<Placed>),
}

impl Code {
    /// Code of a profile map; `Err(reason)` for a plugin/technique/parameter set we cannot encode.
    pub fn from_profile(map: &BTreeMap<String, String>) -> Result<Code, String> {
        let p = EcProfile::parse(map).map_err(|e| e.to_string())?;
        Code::from_parsed(&p)
    }

    /// The classic legacy index sequence for the completed `mapping` (raw r on shard `mapping[r]`, spec ec-parity.md
    /// 3.4): identity keeps the code, anything else wraps it in [`Placed`]. `None` when `mapping` is no permutation.
    pub fn placed(self, mapping: &[u32]) -> Option<Code> {
        if mapping.iter().enumerate().all(|(r, s)| r as u32 == *s) && mapping.len() == self.n() {
            return Some(self);
        }
        Placed::new(self, mapping).map(|p| Code::Placed(Box::new(p)))
    }

    pub fn from_parsed(p: &EcProfile) -> Result<Code, String> {
        if let Some(s) = &p.lrc {
            // layers without an explicit plugin: Ceph main default (isa); see spec ec-lrc.md 1.5
            return Ok(Code::Lrc(Box::new(LrcCodec::new(s, "isa")?)));
        }
        if let Some(c) = &p.clay {
            return ClayCodec::new(c)
                .map(|c| Code::Clay(Box::new(c)))
                .ok_or_else(|| {
                    format!(
                        "clay scalar {} {}: no codec (shard role only)",
                        c.scalar, c.technique
                    )
                });
        }
        let (k, m) = (p.k as usize, p.m as usize);
        let bad = |what: &str| Err(format!("{} {}: {what}", p.plugin.name(), p.technique));
        // jerasure bit-matrix techniques (pure GF(2) packet XOR, spec ec.md 4.3.3)
        if p.plugin == Plugin::Jerasure
            && let Some(tech) = BitTech::parse(&p.technique)
        {
            return match BitCodec::try_new(tech, k, m, p.w as usize, p.packetsize as usize) {
                Some(c) => Ok(Code::Bit(c)),
                None => bad("parameters rejected"),
            };
        }
        match (&p.plugin, p.technique.as_str()) {
            (Plugin::Shec, t) => match (t, p.w) {
                ("single" | "multiple", 8) => {
                    ShecCodec::try_new(k, m, p.c as usize, t == "single", 8)
                        .map(Code::Shec)
                        .ok_or_else(|| {
                            "shec: parameters rejected (need k>=m>=c>=1, k<=12, k+m<=20)"
                                .to_string()
                        })
                }
                ("single" | "multiple", w) => bad(&format!("w={w} not supported (only 8)")),
                _ => bad("not supported"),
            },
            (Plugin::Isa, "reed_sol_van") => Ok(Code::Rs(
                Codec::try_new(Kind::IsaVan, k, m).ok_or("codec geometry")?,
            )),
            (Plugin::Isa, "cauchy") => Ok(Code::Rs(
                Codec::try_new(Kind::IsaCauchy, k, m).ok_or("codec geometry")?,
            )),
            (Plugin::Jerasure, "reed_sol_van") if p.w == 8 => Ok(Code::Rs(
                Codec::try_new(Kind::JerVan, k, m).ok_or("codec geometry")?,
            )),
            // r6_op = isa reed_sol_van for m == 2 (ec.md 4.3.2)
            (Plugin::Jerasure, "reed_sol_r6_op") if p.w == 8 && m == 2 => Ok(Code::Rs(
                Codec::try_new(Kind::IsaVan, k, m).ok_or("codec geometry")?,
            )),
            (Plugin::Jerasure, "reed_sol_r6_op") if m != 2 => bad("requires m=2"),
            (Plugin::Jerasure, t @ ("reed_sol_van" | "reed_sol_r6_op")) => {
                let kind = if t == "reed_sol_van" {
                    WideKind::Van
                } else {
                    WideKind::R6
                };
                WideCodec::try_new(kind, k, m, p.w)
                    .map(Code::Wide)
                    .ok_or_else(|| format!("jerasure {t}: w={} not supported (8, 16, 32)", p.w))
            }
            _ => bad("not supported"),
        }
    }

    pub fn k(&self) -> usize {
        match self {
            Code::Rs(c) => c.k(),
            Code::Wide(c) => c.k(),
            Code::Bit(c) => c.k(),
            Code::Shec(c) => c.k(),
            Code::Lrc(c) => c.k(),
            Code::Clay(c) => c.k(),
            Code::Placed(p) => p.inner().k(),
        }
    }

    pub fn m(&self) -> usize {
        match self {
            Code::Rs(c) => c.m(),
            Code::Wide(c) => c.m(),
            Code::Bit(c) => c.m(),
            Code::Shec(c) => c.m(),
            Code::Lrc(c) => c.m(),
            Code::Clay(c) => c.m(),
            Code::Placed(p) => p.inner().m(),
        }
    }

    pub fn n(&self) -> usize {
        self.k() + self.m()
    }

    /// The m x k GF(2^8) coding matrix (byte-wise codes only; optimized-EC parity deltas need it).
    pub fn matrix(&self) -> Option<&[u8]> {
        match self {
            Code::Rs(c) => Some(c.matrix()),
            _ => None,
        }
    }

    /// Chunk lengths handed to encode/decode must be a multiple of this.
    pub fn unit(&self) -> usize {
        match self {
            Code::Rs(_) => 1,
            Code::Wide(c) => c.unit(),
            Code::Bit(c) => c.unit(),
            Code::Shec(_) => 1,
            Code::Lrc(c) => c.unit(),
            Code::Clay(c) => c.unit(),
            Code::Placed(p) => p.inner().unit(),
        }
    }

    /// Sub-chunks per chunk (clay: q^t; 1 otherwise): "the whole chunk" on the wire is `[(0, sub_chunks)]`.
    pub fn sub_chunks(&self) -> usize {
        match self {
            Code::Clay(c) => c.sub_chunk_count(),
            Code::Placed(p) => p.inner().sub_chunks(),
            _ => 1,
        }
    }

    /// Pool chunk size: codes with per-stripe codewords (clay) then split multi-stripe regions at it. No-op otherwise.
    pub fn set_chunk(&mut self, chunk: usize) {
        match self {
            Code::Clay(c) => c.set_chunk(chunk),
            Code::Placed(p) => p.inner_mut().set_chunk(chunk),
            _ => {}
        }
    }

    /// The encode also changes data chunks (classic literal sequences: a mapping that places client data on a parity
    /// index, an lrc layer coding into a data position; spec ec-parity.md 3.4, 14.2): use [`encode_all`](Self::encode_all).
    pub fn rewrites_data(&self) -> bool {
        match self {
            Code::Placed(p) => p.rewrites_data(),
            Code::Lrc(c) => c.rewrites_data(),
            _ => false,
        }
    }

    /// Every raw chunk (`out.len() == n`, data then parity) of the client chunks `data`. Same as copying `data` and
    /// [`encode`](Self::encode) unless [`rewrites_data`](Self::rewrites_data).
    pub fn encode_all(&self, data: &[&[u8]], out: &mut [&mut [u8]]) {
        match self {
            Code::Placed(p) => p.encode_all(data, out),
            Code::Lrc(c) => c.encode_all(data, out),
            _ => {
                let (d, p) = out.split_at_mut(self.k());
                for (o, i) in d.iter_mut().zip(data) {
                    o.copy_from_slice(i);
                }
                self.encode(data, p);
            }
        }
    }

    /// parity[r] from the k data chunks; all regions the same length (a multiple of [`unit`](Self::unit)). Data chunks
    /// are unchanged only when ![`rewrites_data`](Self::rewrites_data).
    pub fn encode(&self, data: &[&[u8]], parity: &mut [&mut [u8]]) {
        match self {
            Code::Rs(c) => c.encode(data, parity),
            Code::Wide(c) => c.encode(data, parity),
            Code::Bit(c) => c.encode(data, parity),
            Code::Shec(c) => c.encode(data, parity),
            Code::Lrc(c) => c.encode(data, parity),
            Code::Clay(c) => c.encode(data, parity),
            Code::Placed(p) => p.encode(data, parity),
        }
    }

    /// Rebuild the raw chunks `want[i]` into `out[i]` from the surviving chunks `have = (raw, bytes)`, which must be
    /// a set returned by [`read_set`](Self::read_set).
    pub fn decode_into(
        &self,
        have: &[(usize, &[u8])],
        want: &[usize],
        out: &mut [&mut [u8]],
    ) -> Result<(), DecodeError> {
        match self {
            Code::Rs(c) => c.decode_into(have, want, out),
            Code::Wide(c) => c.decode_into(have, want, out),
            Code::Bit(c) => c.decode_into(have, want, out),
            Code::Shec(c) => c.decode_into(have, want, out),
            Code::Lrc(c) => c.decode_into(have, want, out),
            Code::Clay(c) => c.decode_into(have, want, out),
            Code::Placed(p) => p.decode_into(have, want, out),
        }
    }

    /// Clay single-chunk repair (spec ec-clay.md 6): helper raw chunks and the sub-chunk ranges each one reads to
    /// rebuild `lost` from `avail`; `None` for other codes or when the repair preconditions do not hold.
    #[expect(clippy::type_complexity)]
    pub fn repair_plan(
        &self,
        lost: usize,
        avail: &[usize],
    ) -> Option<(Vec<usize>, Vec<(usize, usize)>)> {
        match self {
            Code::Clay(c) => {
                let h = c.minimum_to_repair(lost, avail)?;
                Some((h, c.repair_subchunks(lost)))
            }
            Code::Placed(p) => p.repair_plan(lost, avail),
            _ => None,
        }
    }

    /// Rebuild raw chunk `lost` (whole chunks, `out.len()` = stripes x chunk) from the helpers' repair-plane bytes.
    pub fn repair(
        &self,
        lost: usize,
        helpers: &[(usize, &[u8])],
        out: &mut [u8],
    ) -> Result<(), DecodeError> {
        match self {
            Code::Clay(c) => c.repair(lost, helpers, out),
            Code::Placed(p) => p.repair(lost, helpers, out),
            _ => Err(DecodeError::Unrecoverable),
        }
    }

    /// Raw chunks to read (in preference order) to obtain `want` from the readable chunks `avail`: the wanted chunks
    /// that are readable first, then, if a wanted chunk is missing, enough others to decode (MDS: data then parity up
    /// to k). `None` when `want` cannot be rebuilt.
    pub fn read_set(&self, want: &[usize], avail: &[usize]) -> Option<Vec<usize>> {
        // a wanted chunk that does not exist or is wanted twice cannot be rebuilt by a read set (each entry is one
        // chunk to read)
        let n = self.n();
        if want.iter().any(|&r| r >= n)
            || want
                .iter()
                .enumerate()
                .any(|(i, &r)| want[..i].contains(&r))
        {
            return None;
        }
        if let Code::Lrc(c) = self {
            return c.read_set(want, avail);
        }
        if let Code::Clay(c) = self {
            return c.read_set(want, avail);
        }
        if let Code::Placed(p) = self {
            return p.read_set(want, avail);
        }
        let have = |r: usize| avail.contains(&r);
        if want.iter().all(|r| have(*r)) {
            return Some(want.to_vec());
        }
        if let Code::Shec(s) = self {
            return s.min_set(want, avail);
        }
        let k = self.k();
        if let Code::Bit(b) = self
            && !b.is_mds()
        {
            return first_decodable(b, want, avail);
        }
        let mut order: Vec<usize> = Vec::new();
        order.extend(want.iter().copied().filter(|r| have(*r)));
        for r in 0..self.n() {
            if have(r) && !order.contains(&r) {
                order.push(r);
            }
        }
        if order.len() < k {
            return None;
        }
        order.truncate(k);
        Some(order)
    }
}

/// Non-MDS code: first k-subset of `avail` (wanted chunks first, then ascending) that decodes.
fn first_decodable(b: &BitCodec, want: &[usize], avail: &[usize]) -> Option<Vec<usize>> {
    let k = b.k();
    let mut pool: Vec<usize> = want.iter().copied().filter(|r| avail.contains(r)).collect();
    let rest: Vec<usize> = avail
        .iter()
        .copied()
        .filter(|r| !pool.contains(r))
        .collect();
    pool.extend(rest);
    if pool.len() < k {
        return None;
    }
    // k-combinations in lexicographic order of pool positions
    let mut idx: Vec<usize> = (0..k).collect();
    loop {
        let set: Vec<usize> = idx.iter().map(|&i| pool[i]).collect();
        if b.decodable(&set) {
            return Some(set);
        }
        let mut i = k;
        loop {
            if i == 0 {
                return None;
            }
            i -= 1;
            if idx[i] != i + pool.len() - k {
                break;
            }
        }
        idx[i] += 1;
        for j in i + 1..k {
            idx[j] = idx[j - 1] + 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `want` with an out-of-range index or a duplicate cannot be rebuilt: `None`, never a set that would make the
    /// caller read a chunk twice or decode a nonexistent one (every code, MDS path included).
    #[test]
    fn read_set_rejects_bad_want() {
        let rs = Code::Rs(Codec::new(Kind::IsaVan, 2, 2));
        assert_eq!(rs.read_set(&[7], &[0, 1]), None);
        assert_eq!(rs.read_set(&[0, 0], &[0, 1]), None);
        assert_eq!(rs.read_set(&[0, 1], &[0, 1]), Some(vec![0, 1]));
        // the wanted chunk that is not readable pulls the next one in, as before
        assert_eq!(rs.read_set(&[0, 2], &[0, 1, 3]), Some(vec![0, 1]));
        let wide = Code::Wide(WideCodec::try_new(WideKind::Van, 2, 2, 16).unwrap());
        assert_eq!(wide.read_set(&[4], &[0, 1]), None);
        assert_eq!(wide.read_set(&[1, 1], &[0, 1]), None);
        let bit = Code::Bit(BitCodec::try_new(BitTech::CauchyOrig, 2, 2, 8, 8).unwrap());
        assert_eq!(bit.read_set(&[4], &[0, 1]), None);
        assert_eq!(bit.read_set(&[0, 0], &[0, 1]), None);
        let shec = Code::Shec(ShecCodec::try_new(4, 3, 2, false, 8).unwrap());
        assert_eq!(shec.read_set(&[0, 0], &[0, 1, 2, 3]), None);
        let lrc = Code::Lrc(Box::new(
            LrcCodec::new(&crate::lrc::LrcSpec::generate(4, 2, 3).unwrap(), "isa").unwrap(),
        ));
        assert_eq!(lrc.read_set(&[0, 0], &[0, 1, 2, 3]), None);
        assert_eq!(lrc.read_set(&[99], &[0, 1, 2, 3]), None);
    }
}
