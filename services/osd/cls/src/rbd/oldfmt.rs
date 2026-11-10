// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Old-format (v1) snapshot methods `snap_list/snap_add/snap_remove/snap_rename` (cls_rbd.md B.9b).
//! The header object's DATA is a packed `rbd_obj_header_ondisk` + snap array + NUL-terminated names.

use super::*;
use crate::ctx::ClsCtx;
use crate::errno::*;

const HDR: usize = 112;
const OFF_IMAGE_SIZE: usize = 80;
const OFF_SNAP_SEQ: usize = 88;
const OFF_COUNT: usize = 96;
const OFF_NAMES_LEN: usize = 104;

struct V1 {
    hdr: [u8; HDR],
    snaps: Vec<(u64, u64)>,
    /// Raw names region (`snap_names_len` bytes).
    names: Vec<u8>,
    /// Start offset of each snapshot's name inside `names`.
    starts: Vec<usize>,
}

fn le64(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 8)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}
fn le32(b: &[u8], o: usize) -> u32 {
    b.get(o..o + 4)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

/// Snapshot count of a v1 header (`None`: data shorter than the v1 header = not old format).
pub(super) fn v1_snap_count(data: &[u8]) -> Option<u64> {
    (data.len() >= HDR).then(|| le32(data, OFF_COUNT) as u64)
}

impl V1 {
    fn load<C: ClsCtx>(c: &mut C) -> Result<V1, Errno> {
        let data = c.read(0, 0)?;
        if data.len() < HDR {
            return Err(EINVAL);
        }
        let count = le32(&data, OFF_COUNT) as usize;
        let nlen = le64(&data, OFF_NAMES_LEN) as usize;
        let snaps_end = count
            .checked_mul(16)
            .and_then(|n| n.checked_add(HDR))
            .ok_or(EIO)?;
        let end = snaps_end.checked_add(nlen).ok_or(EIO)?;
        if end > data.len() {
            return Err(EIO);
        }
        let mut hdr = [0u8; HDR];
        hdr.copy_from_slice(&data[..HDR]);
        let snaps = (0..count)
            .map(|i| (le64(&data, HDR + i * 16), le64(&data, HDR + i * 16 + 8)))
            .collect();
        let names = data[snaps_end..end].to_vec();
        let mut starts = Vec::with_capacity(count);
        let mut pos = 0;
        for _ in 0..count {
            starts.push(pos);
            let nul = names[pos..].iter().position(|&b| b == 0).ok_or(EIO)?;
            pos += nul + 1;
        }
        Ok(V1 {
            hdr,
            snaps,
            names,
            starts,
        })
    }

    fn name(&self, i: usize) -> &[u8] {
        let s = &self.names[self.starts[i]..];
        &s[..s.iter().position(|&b| b == 0).unwrap_or(s.len())]
    }

    fn pos_of(&self, name: &[u8]) -> Option<usize> {
        (0..self.snaps.len()).find(|&i| self.name(i) == name)
    }

    /// Serialize: header (count/names_len from the vectors, seq as given) + snaps + names.
    /// `count == 0` writes the header only (classic).
    fn store<C: ClsCtx>(mut self, c: &mut C, seq: u64) -> Result<(), Errno> {
        self.hdr[OFF_SNAP_SEQ..OFF_SNAP_SEQ + 8].copy_from_slice(&seq.to_le_bytes());
        self.hdr[OFF_COUNT..OFF_COUNT + 4]
            .copy_from_slice(&(self.snaps.len() as u32).to_le_bytes());
        self.hdr[OFF_NAMES_LEN..OFF_NAMES_LEN + 8]
            .copy_from_slice(&(self.names.len() as u64).to_le_bytes());
        let mut out = self.hdr.to_vec();
        if !self.snaps.is_empty() {
            for (id, sz) in &self.snaps {
                out.extend(id.to_le_bytes());
                out.extend(sz.to_le_bytes());
            }
            out.extend(&self.names);
        }
        c.write_full(&out)
    }

    fn seq(&self) -> u64 {
        le64(&self.hdr, OFF_SNAP_SEQ)
    }
}

/// Name as a C string: cut at the first NUL.
fn cstr(s: &[u8]) -> &[u8] {
    &s[..s.iter().position(|&x| x == 0).unwrap_or(s.len())]
}

pub fn snap_list<C: ClsCtx>(c: &mut C, _i: &[u8]) -> R {
    let v = V1::load(c)?;
    let mut o = v.seq().to_le_bytes().to_vec();
    o.extend((v.snaps.len() as u32).to_le_bytes());
    for (i, (id, sz)) in v.snaps.iter().enumerate() {
        o.extend(id.to_le_bytes());
        o.extend(sz.to_le_bytes());
        o.extend(enc(v.name(i))?);
    }
    Ok(o)
}

pub fn snap_add<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut v = V1::load(c)?;
    let mut d = input(inp);
    let name = Vec::<u8>::decode(&mut d).inval()?;
    let id = d.u64().inval()?;
    if v.seq() > id {
        return Err(ESTALE);
    }
    let limit = rd_opt_u64(c, "snap_limit")?.unwrap_or(u64::MAX);
    if v.snaps.len() as u64 >= limit {
        return Err(EDQUOT);
    }
    let name = cstr(&name);
    if v.pos_of(name).is_some() {
        return Err(EEXIST);
    }
    let mut names = name.to_vec();
    names.push(0);
    names.extend(&v.names);
    v.names = names;
    v.snaps.insert(0, (id, le64(&v.hdr, OFF_IMAGE_SIZE)));
    v.store(c, id)?;
    Ok(())
}

pub fn snap_remove<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut v = V1::load(c)?;
    let name = Vec::<u8>::decode(&mut input(inp)).inval()?;
    let i = v.pos_of(cstr(&name)).ok_or(ENOENT)?;
    let s = v.starts[i];
    let e = s + v.name(i).len() + 1;
    v.names.drain(s..e.min(v.names.len()));
    v.snaps.remove(i);
    let seq = v.seq();
    v.store(c, seq)?;
    Ok(())
}

pub fn snap_rename<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut v = V1::load(c)?;
    let mut d = input(inp);
    let id = d.u64().inval()?;
    let dst = Vec::<u8>::decode(&mut d).inval()?;
    let dst = cstr(&dst);
    if v.pos_of(dst).is_some() {
        return Err(EEXIST);
    }
    let i = v.snaps.iter().position(|s| s.0 == id).ok_or(ENOENT)?;
    let s = v.starts[i];
    let e = (s + v.name(i).len() + 1).min(v.names.len());
    let mut repl = dst.to_vec();
    repl.push(0);
    v.names.splice(s..e, repl);
    let seq = v.seq();
    v.store(c, seq)?;
    Ok(())
}
