// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Data-object methods (cls_rbd.md C.2).

use super::*;
use crate::ctx::ClsCtx;
use crate::errno::*;

/// Legacy thick copyup: the whole input is the data.
pub fn copyup<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    if rd_opt(c.stat())?.is_none() {
        c.write(0, inp)?;
    }
    Ok(())
}

pub fn sparse_copyup<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut d = input(inp);
    let n = d.count().inval()?;
    // a map on the wire (classic): applied in offset order, a repeated offset keeps the last length
    let mut extents = std::collections::BTreeMap::new();
    for _ in 0..n {
        extents.insert(d.u64().inval()?, d.u64().inval()?);
    }
    let data = d.bytes().inval()?;
    if rd_opt(c.stat())?.is_some() {
        return Ok(());
    }
    if extents.is_empty() {
        c.create(true)?;
        return Ok(());
    }
    let mut pos = 0usize;
    for (off, len) in extents {
        let end = usize::try_from(len)
            .ok()
            .and_then(|l| pos.checked_add(l))
            .ok_or(EINVAL)?;
        let chunk = data.get(pos..end).ok_or(EINVAL)?;
        c.write(off, chunk)?;
        pos = end;
    }
    Ok(())
}

pub const GT_SNAPSET_SEQ: u8 = 0;
pub const LE_SNAPSET_SEQ: u8 = 1;

pub fn assert_snapc_seq<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut d = input(inp);
    let snapc_seq = d.u64().inval()?;
    let state = d.u8().inval()?;
    let seq = rd_opt(c.snapset_seq())?;
    match state {
        GT_SNAPSET_SEQ => {
            if seq.is_some_and(|s| snapc_seq <= s) {
                return Err(ERANGE);
            }
        }
        LE_SNAPSET_SEQ => {
            if seq.is_none_or(|s| snapc_seq > s) {
                return Err(ERANGE);
            }
        }
        _ => return Err(EOPNOTSUPP),
    }
    Ok(())
}

pub fn sparsify<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut d = input(inp);
    let sparse = d.u64().inval()?;
    let remove_empty = d.bool().inval()?;
    if sparse == 0 {
        return Err(EINVAL);
    }
    let st = c.stat()?;
    let data = c.read(0, 0)?;
    let sp = usize::try_from(sparse).unwrap_or(usize::MAX);
    if data.iter().all(|&b| b == 0) {
        if remove_empty {
            c.remove()?;
        } else if st.size > 0 {
            c.truncate(0)?;
        }
        return Ok(());
    }
    // runs of non-zero chunks
    let nchunks = data.len().div_ceil(sp);
    let zero = |i: usize| {
        data[i * sp..((i + 1) * sp).min(data.len())]
            .iter()
            .all(|&b| b == 0)
    };
    let mut runs: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i < nchunks {
        if zero(i) {
            i += 1;
            continue;
        }
        let s = i;
        while i < nchunks && !zero(i) {
            i += 1;
        }
        runs.push((s * sp, (i * sp).min(data.len())));
    }
    if runs.len() == 1 && runs[0] == (0, data.len()) {
        return Ok(());
    }
    for (n, (s, e)) in runs.into_iter().enumerate() {
        if n == 0 {
            c.replace(s as u64, &data[s..e])?;
        } else {
            c.write(s as u64, &data[s..e])?;
        }
    }
    Ok(())
}
