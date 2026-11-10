// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Header / id / directory / metadata / group methods (cls_rbd.md A.5).

use super::types::*;
use super::*;
use crate::ctx::{ClsCtx, omap_scan};
use crate::errno::*;
use denc::types::UTime;
use std::collections::BTreeMap;
use std::ops::ControlFlow::Continue;

const FEATURES_ALL: u64 = feature::ALL;

pub fn create<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut d = input(inp);
    let size = d.u64().inval()?;
    let order = d.u8().inval()?;
    let features = d.u64().inval()?;
    let prefix = Vec::<u8>::decode(&mut d).inval()?;
    let pool = if d.is_empty() { -1 } else { d.i64().inval()? };
    if features & !FEATURES_ALL != 0 {
        return Err(ENOSYS);
    }
    if prefix.is_empty() {
        return Err(EINVAL);
    }
    // spec A.9 B3: only a clean ENOENT proceeds; any other outcome of the read (incl. EIO) -> EEXIST
    if !matches!(rd(c, "object_prefix"), Err(ENOENT)) {
        return Err(EEXIST);
    }
    if features & feature::OPERATIONS != 0 {
        return Err(EINVAL);
    }
    if features & feature::DATA_POOL != 0 {
        if pool == -1 {
            return Err(EINVAL);
        }
    } else if pool != -1 {
        return Err(EINVAL);
    }
    let now = enc(&c.now())?;
    let order_b = [order];
    let enc_prefix = enc(&prefix)?;
    let size_b = enc_u64(size);
    let feat_b = enc_u64(features);
    let zero = enc_u64(0);
    let pool_b = pool.to_le_bytes();
    let mut e: Vec<(&[u8], &[u8])> = vec![
        (b"size", &size_b),
        (b"order", &order_b),
        (b"features", &feat_b),
        (b"object_prefix", &enc_prefix),
        (b"snap_seq", &zero),
        (b"create_timestamp", &now),
        (b"access_timestamp", &now),
        (b"modify_timestamp", &now),
    ];
    if features & feature::DATA_POOL != 0 {
        e.push((b"data_pool_id", &pool_b));
    }
    c.omap_set(&e)?;
    Ok(())
}

pub fn get_features<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let mut d = input(inp);
    let _snap = d.u64().inval()?;
    let ro = if d.is_empty() {
        false
    } else {
        d.bool().inval()?
    };
    let f = rd_u64(c, "features")?;
    let incompat = f & if ro {
        feature::INCOMPATIBLE
    } else {
        FEATURES_ALL
    };
    let mut o = enc_u64(f);
    o.extend(enc_u64(incompat));
    Ok(o)
}

pub fn set_features<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut d = input(inp);
    let features = d.u64().inval()?;
    let mut mask = d.u64().inval()?;
    let orig = rd_opt_u64(c, "features")?.unwrap_or(0);
    if mask & feature::INTERNAL != 0 {
        return Err(EINVAL);
    }
    mask &= FEATURES_ALL;
    let enable = features & mask;
    let disable = !features & mask;
    if enable & !feature::MUTABLE != 0 {
        return Err(EINVAL);
    }
    if disable & !(feature::MUTABLE | feature::DISABLE_ONLY) != 0 {
        return Err(EINVAL);
    }
    let new = (orig & !mask) | (features & mask);
    wr_u64(c, "features", new)?;
    Ok(())
}

pub fn get_size<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let snap = input(inp).u64().inval()?;
    let order = {
        let v = rd(c, "order")?;
        *v.first().ok_or(EIO)?
    };
    let size = if snap == NOSNAP {
        rd_u64(c, "size")?
    } else {
        read_snap(c, snap)?.image_size
    };
    let mut o = vec![order];
    o.extend(enc_u64(size));
    Ok(o)
}

pub fn set_size<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let size = input(inp).u64().inval()?;
    let old = rd_u64(c, "size")?;
    wr_u64(c, "size", size)?;
    if size < old
        && let Some(mut p) = read_parent(c)?
        && p.exists()
        && p.head_overlap.is_some_and(|o| o > size)
    {
        p.head_overlap = Some(size);
        write_parent(c, &p)?;
    }
    Ok(())
}

pub fn get_object_prefix<C: ClsCtx>(c: &mut C, _inp: &[u8]) -> R {
    rd(c, "object_prefix")
}

pub fn get_data_pool<C: ClsCtx>(c: &mut C, _inp: &[u8]) -> R {
    let p = match rd_opt(rd(c, "data_pool_id"))? {
        Some(v) => denc::Decoder::new(&v).i64().eio()?,
        None => -1,
    };
    Ok(p.to_le_bytes().to_vec())
}

pub fn get_all_features<C: ClsCtx>(_c: &mut C, _inp: &[u8]) -> R {
    Ok(enc_u64(FEATURES_ALL))
}

fn get_ts<C: ClsCtx>(c: &mut C, key: &str) -> R {
    let t: UTime = match rd_opt(rd(c, key))? {
        Some(v) => dec_stored(&v)?,
        None => UTime::default(),
    };
    enc(&t)
}
pub fn get_create_timestamp<C: ClsCtx>(c: &mut C, _i: &[u8]) -> R {
    get_ts(c, "create_timestamp")
}
pub fn get_access_timestamp<C: ClsCtx>(c: &mut C, _i: &[u8]) -> R {
    get_ts(c, "access_timestamp")
}
pub fn get_modify_timestamp<C: ClsCtx>(c: &mut C, _i: &[u8]) -> R {
    get_ts(c, "modify_timestamp")
}
fn set_ts<C: ClsCtx>(c: &mut C, key: &str) -> Result<(), Errno> {
    check_exists(c)?;
    let now = enc(&c.now())?;
    wr(c, key, &now)?;
    Ok(())
}
pub fn set_access_timestamp<C: ClsCtx>(c: &mut C, _i: &[u8]) -> Result<(), Errno> {
    set_ts(c, "access_timestamp")
}
pub fn set_modify_timestamp<C: ClsCtx>(c: &mut C, _i: &[u8]) -> Result<(), Errno> {
    set_ts(c, "modify_timestamp")
}

pub fn get_flags<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let snap = input(inp).u64().inval()?;
    let f = if snap == NOSNAP {
        rd_opt_u64(c, "flags")?.unwrap_or(0)
    } else {
        read_snap(c, snap)?.flags
    };
    Ok(enc_u64(f))
}

pub fn set_flags<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut d = input(inp);
    let flags = d.u64().inval()?;
    let mask = d.u64().inval()?;
    let snap = if d.is_empty() {
        NOSNAP
    } else {
        d.u64().inval()?
    };
    if snap == NOSNAP {
        let orig = rd_opt_u64(c, "flags")?.unwrap_or(0);
        wr_u64(c, "flags", (orig & !mask) | (flags & mask))?;
    } else {
        let mut s = read_snap(c, snap)?;
        s.flags = (s.flags & !mask) | (flags & mask);
        write_snap(c, s)?;
    }
    Ok(())
}

pub fn op_features_get<C: ClsCtx>(c: &mut C, _i: &[u8]) -> R {
    Ok(enc_u64(rd_opt_u64(c, "op_features")?.unwrap_or(0)))
}

pub fn op_features_set<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut d = input(inp);
    let op = d.u64().inval()?;
    let mask = d.u64().inval()?;
    if mask & !op_feature::ALL != 0 {
        return Err(EINVAL);
    }
    set_op_features(c, op, mask)?;
    Ok(())
}

pub fn get_stripe_unit_count<C: ClsCtx>(c: &mut C, _i: &[u8]) -> R {
    check_exists(c)?;
    require_feature(c, feature::STRIPINGV2)?;
    let unit = match rd_opt_u64(c, "stripe_unit")? {
        Some(u) => u,
        None => {
            // spec A.5: a missing `order` key is -EIO (not the getters' ENOENT); the value is one byte
            let o = rd_opt_raw(c, "order")?.ok_or(EIO)?;
            1u64 << (*o.first().ok_or(EIO)? & 63)
        }
    };
    let count = rd_opt_u64(c, "stripe_count")?.unwrap_or(1);
    let mut o = enc_u64(unit);
    o.extend(enc_u64(count));
    Ok(o)
}

pub fn set_stripe_unit_count<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut d = input(inp);
    let unit = d.u64().inval()?;
    let count = d.u64().inval()?;
    if unit == 0 || count == 0 {
        return Err(EINVAL);
    }
    check_exists(c)?;
    require_feature(c, feature::STRIPINGV2)?;
    let order = *rd(c, "order")?.first().ok_or(EIO)?;
    let osz = 1u64.checked_shl(order as u32).ok_or(EINVAL)?;
    if osz % unit != 0 || unit > osz {
        return Err(EINVAL);
    }
    c.omap_set(&[
        (b"stripe_unit", &enc_u64(unit)),
        (b"stripe_count", &enc_u64(count)),
    ])?;
    Ok(())
}

pub fn get_snapcontext<C: ClsCtx>(c: &mut C, _i: &[u8]) -> R {
    let mut ids: Vec<u64> = Vec::new();
    omap_scan(c, b"snapshot_", b"snapshot_", u64::MAX, |_, k, _| {
        let h = std::str::from_utf8(&k[b"snapshot_".len()..]).map_err(|_| EIO)?;
        ids.push(u64::from_str_radix(h, 16).map_err(|_| EIO)?);
        Ok(Continue(()))
    })?;
    ids.reverse();
    let seq = rd_u64(c, "snap_seq")?;
    let mut o = enc_u64(seq);
    o.extend(enc(&ids)?);
    Ok(o)
}

// ---- metadata -----------------------------------------------------------------------------------

pub fn metadata_list<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let mut d = input(inp);
    let start = Vec::<u8>::decode(&mut d).inval()?;
    let mut max = d.u64().inval()?;
    if max == 0 {
        max = MAX_KEYS_READ;
    }
    let mut out: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    for (k, v) in scan(c, "metadata_", &key("metadata_", &start), max)? {
        out.insert(suffix(&k, "metadata_".len()), v);
    }
    enc(&out)
}

pub fn metadata_set<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let m: BTreeMap<Vec<u8>, Vec<u8>> = dec_op(inp)?;
    let keys: Vec<Vec<u8>> = m.keys().map(|k| key("metadata_", k)).collect();
    let e: Vec<(&[u8], &[u8])> = keys
        .iter()
        .zip(m.values())
        .map(|(k, v)| (k.as_slice(), v.as_slice()))
        .collect();
    c.omap_set(&e)?;
    Ok(())
}

pub fn metadata_get<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let k = Vec::<u8>::decode(&mut input(inp)).inval()?;
    let v = rd(c, &key("metadata_", &k))?;
    enc(&v)
}

pub fn metadata_remove<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let k = Vec::<u8>::decode(&mut input(inp)).inval()?;
    rm(c, &key("metadata_", &k))?;
    Ok(())
}

// ---- rbd_id.<name> ------------------------------------------------------------------------------

pub fn get_id<C: ClsCtx>(c: &mut C, _i: &[u8]) -> R {
    let st = c.stat()?;
    if st.size == 0 {
        return Err(ENOENT);
    }
    let data = c.read(0, 0)?;
    let id = Vec::<u8>::decode(&mut Decoder::new(&data)).eio()?;
    enc(&id)
}

pub fn set_id<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    check_exists(c)?;
    let id = Vec::<u8>::decode(&mut input(inp)).inval()?;
    if !is_valid_id(&id) {
        return Err(EINVAL);
    }
    if c.stat()?.size != 0 {
        return Err(EEXIST);
    }
    c.write(0, &enc(&id)?)?;
    Ok(())
}

// ---- rbd_directory ------------------------------------------------------------------------------

pub(crate) fn dir_remove_helper<C: ClsCtx>(c: &mut C, name: &[u8], id: &[u8]) -> Result<(), Errno> {
    let nk = key("name_", name);
    let ik = key("id_", id);
    let sid: Vec<u8> = dec_stored(&rd(c, &nk)?)?;
    let sname: Vec<u8> = dec_stored(&rd(c, &ik)?)?;
    if sid != id || sname != name {
        return Err(ESTALE);
    }
    rm(c, &nk)?;
    rm(c, &ik)
}

pub(crate) fn dir_add_helper<C: ClsCtx>(
    c: &mut C,
    name: &[u8],
    id: &[u8],
    check_id_unique: bool,
) -> Result<(), Errno> {
    if name.is_empty() || !is_valid_id(id) {
        return Err(EINVAL);
    }
    let nk = key("name_", name);
    let ik = key("id_", id);
    if rd_opt_raw(c, &nk)?.is_some() {
        return Err(EEXIST);
    }
    if check_id_unique && rd_opt_raw(c, &ik)?.is_some() {
        return Err(EBADF);
    }
    c.omap_set(&[(&nk, &enc(&id)?), (&ik, &enc(&name)?)])
}

pub fn dir_add_image<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut d = input(inp);
    let name = Vec::<u8>::decode(&mut d).inval()?;
    let id = Vec::<u8>::decode(&mut d).inval()?;
    c.create(false)?;
    dir_add_helper(c, &name, &id, true)?;
    Ok(())
}

pub fn dir_remove_image<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut d = input(inp);
    let name = Vec::<u8>::decode(&mut d).inval()?;
    let id = Vec::<u8>::decode(&mut d).inval()?;
    dir_remove_helper(c, &name, &id)?;
    Ok(())
}

pub fn dir_rename_image<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut d = input(inp);
    let src = Vec::<u8>::decode(&mut d).inval()?;
    let dest = Vec::<u8>::decode(&mut d).inval()?;
    let id = Vec::<u8>::decode(&mut d).inval()?;
    dir_remove_helper(c, &src, &id)?;
    dir_add_helper(c, &dest, &id, false)?;
    Ok(())
}

pub fn dir_get_id<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let name = Vec::<u8>::decode(&mut input(inp)).inval()?;
    rd(c, &key("name_", &name))
}

pub fn dir_get_name<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let id = Vec::<u8>::decode(&mut input(inp)).inval()?;
    rd(c, &key("id_", &id))
}

pub fn dir_list<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let mut d = input(inp);
    let start = Vec::<u8>::decode(&mut d).inval()?;
    let max = d.u64().inval()?;
    let mut out: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    for (k, v) in scan(c, "name_", &key("name_", &start), max)? {
        let id: Vec<u8> = dec_stored(&v)?;
        out.insert(suffix(&k, "name_".len()), id);
    }
    enc(&out)
}

pub const DIR_READY: u8 = 0;
pub const DIR_ADD_DISABLED: u8 = 1;

pub fn dir_state_assert<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let want = input(inp).u8().inval()?;
    let v = rd(c, "state")?;
    let stored = *v.first().ok_or(EIO)?;
    if stored != want {
        return Err(ENOENT);
    }
    Ok(())
}

pub fn dir_state_set<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let st = input(inp).u8().inval()?;
    match st {
        DIR_READY => {}
        DIR_ADD_DISABLED => {
            check_exists(c)?;
            if !scan(c, "name_", b"name_", 1)?.is_empty() {
                return Err(EBUSY);
            }
        }
        _ => return Err(EINVAL),
    }
    wr(c, "state", &[st])?;
    Ok(())
}

// ---- groups -------------------------------------------------------------------------------------

pub fn image_group_get<C: ClsCtx>(c: &mut C, _i: &[u8]) -> R {
    let spec = match rd_opt_raw(c, "rbd_group_ref")? {
        Some(v) => GroupSpec::decode(&mut Decoder::new(&v)).inval()?,
        None => GroupSpec::default(),
    };
    enc(&spec)
}

pub fn image_group_add<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let spec: GroupSpec = dec_op(inp)?;
    if let Some(v) = rd_opt_raw(c, "rbd_group_ref")? {
        let cur: GroupSpec = dec_op(&v)?;
        return if cur == spec { Ok(()) } else { Err(EEXIST) };
    }
    set_op_features(c, op_feature::GROUP, op_feature::GROUP)?;
    wr(c, "rbd_group_ref", &enc(&spec)?)?;
    Ok(())
}

pub fn image_group_remove<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let spec: GroupSpec = dec_op(inp)?;
    let cur: GroupSpec = dec_op(&rd(c, "rbd_group_ref")?)?;
    if cur != spec {
        return Err(EBADF);
    }
    rm(c, "rbd_group_ref")?;
    set_op_features(c, 0, op_feature::GROUP)?;
    Ok(())
}
