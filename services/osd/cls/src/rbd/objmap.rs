// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Object map methods (cls_rbd.md C.1.5) on `rbd_object_map.<id>[.<snap>]`.

use super::bitvec::{self, ObjMap};
use super::*;
use crate::ctx::ClsCtx;
use crate::errno::*;

pub const MAX_OBJECT_MAP_OBJECT_COUNT: u64 = 256_000_000;

/// "read map": stat, empty/absent -> ENOENT, whole read, CRC-verified decode (-> EINVAL). Also returns whether the
/// stored blob carries CRCs: a whole-map rewrite keeps that (classic re-encodes with the decoded setting).
fn read_map<C: ClsCtx>(c: &mut C) -> Result<(ObjMap, bool), Errno> {
    let st = c.stat()?;
    if st.size == 0 {
        return Err(ENOENT);
    }
    let raw = c.read(0, 0)?;
    ObjMap::decode_crc(&raw).map_err(|_| EINVAL)
}

pub fn object_map_load<C: ClsCtx>(c: &mut C, _i: &[u8]) -> R {
    Ok(read_map(c)?.0.encode_nocrc())
}

pub fn object_map_save<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let m = ObjMap::decode(inp).map_err(|_| EINVAL)?;
    c.write_full(&m.encode())?;
    Ok(())
}

pub fn object_map_resize<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut d = input(inp);
    let count = d.u64().inval()?;
    let state = d.u8().inval()?;
    if count > MAX_OBJECT_MAP_OBJECT_COUNT {
        return Err(EINVAL);
    }
    let (mut m, crc_on) = rd_opt(read_map(c))?.unwrap_or((ObjMap::default(), true));
    if count < m.n {
        for i in count..m.n {
            // unmasked compare (classic): a default_state > 3 never matches a stored element
            if m.get(i) != state {
                return Err(ESTALE);
            }
        }
    }
    m.resize(count, state & 3);
    c.write_full(&m.encode_opt(crc_on))?;
    Ok(())
}

pub fn object_map_update<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    use bitvec::*;
    let mut d = input(inp);
    let start = d.u64().inval()?;
    let end = d.u64().inval()?;
    let new_state = d.u8().inval()? & 3;
    let cur: Option<u8> = Option::<u8>::decode(&mut d).inval()?;
    c.stat()?;
    let hdr = c.read(0, HEADER_LEN as u64)?;
    let n = parse_header(&hdr).map_err(|_| EINVAL)?;
    if start >= end || end > n {
        return Err(ERANGE);
    }
    let dl = data_len(n) as u64;
    let foot_off = HEADER_LEN as u64 + dl;
    let first_blk = (start / 4) / BLOCK as u64;
    let last_blk = ((end - 1) / 4) / BLOCK as u64;
    let byte_lo = first_blk * BLOCK as u64;
    let byte_hi = ((last_blk + 1) * BLOCK as u64).min(dl);
    let mut data = c.read(HEADER_LEN as u64 + byte_lo, byte_hi - byte_lo)?;
    if data.len() as u64 != byte_hi - byte_lo {
        return Err(EINVAL);
    }
    let nblk = (last_blk - first_blk + 1) as usize;
    let slot_off = foot_off + 12 + 4 * first_blk;
    // Classic model: the footer length is never consulted here, the CRC slots are always read and verified. A slot
    // beyond the object (short read: truncated footer, CRC-less map) is compared uninitialised by classic, i.e. a
    // mismatch: EINVAL (not "0": an all-zero block has crc32c(0) == 0 and would pass).
    let mut slots = c.read(slot_off, 4 * nblk as u64)?;
    if slots.len() != 4 * nblk {
        return Err(EINVAL);
    }
    for (j, s) in slots.as_chunks::<4>().0.iter().enumerate() {
        let want = u32::from_le_bytes([s[0], s[1], s[2], s[3]]);
        let blk = &data[j * BLOCK..((j + 1) * BLOCK).min(data.len())];
        if crc(blk) != want {
            return Err(EINVAL);
        }
    }
    let mut changed = false;
    for i in start..end {
        let bi = (i / 4 - byte_lo) as usize;
        let sh = (3 - (i % 4) as u32) * 2;
        let s = (data[bi] >> sh) & 3;
        let matches = match cur {
            None => true,
            Some(cs) => s == cs || (cs == OBJECT_EXISTS && s == OBJECT_EXISTS_CLEAN),
        };
        if matches && s != new_state {
            data[bi] = (data[bi] & !(3 << sh)) | (new_state << sh);
            changed = true;
        }
    }
    if !changed {
        return Ok(());
    }
    c.write(HEADER_LEN as u64 + byte_lo, &data)?;
    slots.clear();
    for blk in data.chunks(BLOCK) {
        slots.extend_from_slice(&crc(blk).to_le_bytes());
    }
    c.write(slot_off, &slots)?;
    Ok(())
}

pub fn object_map_snap_add<C: ClsCtx>(c: &mut C, _i: &[u8]) -> Result<(), Errno> {
    use bitvec::*;
    let (mut m, crc_on) = read_map(c)?;
    // 01 -> 11 per 2-bit element: whole bytes in one pass (a 1 PiB map has 256M elements), the
    // trailing byte element-wise so its padding bits stay untouched
    let full = (m.n / 4) as usize;
    let mut changed = false;
    for b in &mut m.data[..full] {
        let v = *b | ((*b & 0x55) << 1); // low bit set (01 or 11) -> 11
        changed |= v != *b;
        *b = v;
    }
    for i in full as u64 * 4..m.n {
        if m.get(i) == OBJECT_EXISTS {
            m.set(i, OBJECT_EXISTS_CLEAN);
            changed = true;
        }
    }
    if changed {
        c.write_full(&m.encode_opt(crc_on))?;
    }
    Ok(())
}

pub fn object_map_snap_remove<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    use bitvec::*;
    let snap = ObjMap::decode(inp).map_err(|_| EINVAL)?;
    let (mut m, crc_on) = read_map(c)?;
    let mut changed = false;
    for i in 0..m.n {
        if m.get(i) == OBJECT_EXISTS_CLEAN && (i >= snap.n || snap.get(i) == OBJECT_EXISTS) {
            m.set(i, OBJECT_EXISTS);
            changed = true;
        }
    }
    if changed {
        c.write_full(&m.encode_opt(crc_on))?;
    }
    Ok(())
}
