// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Trash and namespace methods (cls_rbd.md B.7, B.8).

use super::types::*;
use super::*;
use crate::ctx::ClsCtx;
use crate::errno::*;
use std::collections::BTreeMap;

pub fn trash_add<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    c.create(false)?;
    let mut d = input(inp);
    let id = Vec::<u8>::decode(&mut d).inval()?;
    let spec = TrashImageSpec::decode(&mut d).inval()?;
    if !is_valid_id(&id) {
        return Err(EINVAL);
    }
    let k = key("id_", &id);
    if rd_opt_raw(c, &k)?.is_some() {
        return Err(EEXIST);
    }
    wr(c, &k, &enc(&spec)?)?;
    Ok(())
}

pub fn trash_remove<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let id = Vec::<u8>::decode(&mut input(inp)).inval()?;
    let k = key("id_", &id);
    rd(c, &k)?;
    rm(c, &k)?;
    Ok(())
}

pub fn trash_list<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let mut d = input(inp);
    let start = Vec::<u8>::decode(&mut d).inval()?;
    let max = d.u64().inval()?;
    let from = key("id_", &start);
    let mut out: BTreeMap<Vec<u8>, TrashImageSpec> = BTreeMap::new();
    if max > 0 {
        for (k, v) in scan(c, "id_", &from, max)? {
            let spec: TrashImageSpec = dec_stored(&v)?;
            out.insert(suffix(&k, "id_".len()), spec);
        }
    }
    enc(&out)
}

pub fn trash_get<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let id = Vec::<u8>::decode(&mut input(inp)).inval()?;
    rd(c, &key("id_", &id))
}

pub fn trash_state_set<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut d = input(inp);
    let id = Vec::<u8>::decode(&mut d).inval()?;
    let new = d.u8().inval()?;
    let expected = d.u8().inval()?;
    let k = key("id_", &id);
    let mut spec: TrashImageSpec = dec_stored(&rd(c, &k)?)?;
    if spec.state == expected {
        spec.state = new;
        wr(c, &k, &enc(&spec)?)?;
    } else if spec.state != new {
        return Err(ESTALE);
    }
    Ok(())
}

// ---- namespaces ---------------------------------------------------------------------------------

pub fn namespace_add<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let name = Vec::<u8>::decode(&mut input(inp)).inval()?;
    let k = key("name_", &name);
    if rd_opt_raw(c, &k)?.is_some() {
        return Err(EEXIST);
    }
    wr(c, &k, &[])?;
    Ok(())
}

pub fn namespace_remove<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let name = Vec::<u8>::decode(&mut input(inp)).inval()?;
    let k = key("name_", &name);
    rd(c, &k)?;
    rm(c, &k)?;
    Ok(())
}

pub fn namespace_list<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let mut d = input(inp);
    let start = Vec::<u8>::decode(&mut d).inval()?;
    let max = d.u64().inval()?;
    let from = key("name_", &start);
    let names: Vec<Vec<u8>> = scan(c, "name_", &from, max)?
        .into_iter()
        .map(|(k, _)| suffix(&k, "name_".len()))
        .collect();
    enc(&names)
}
