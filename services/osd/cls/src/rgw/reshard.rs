// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Class `rgw`, reshard queue (spec/cls_rgw.md s3.6): object `reshard.<n>` in the log pool, omap
//! only. Key = `<tenant>:<bucket_name>`, value = `cls_rgw_reshard_entry`.

use super::index::read_omap;
use super::types::*;
use crate::ctx::ClsCtx;
use crate::errno::*;
use denc::{Decode, Decoder};

const MAX_LIST: u32 = 1000;

fn key(tenant: &[u8], bucket: &[u8]) -> Vec<u8> {
    [tenant, b":", bucket].concat()
}

/// `reshard_add`: `create_only` fails `-EEXIST` if the bucket is already queued.
pub fn reshard_add<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: ReshardAddOp = dec_op(input)?;
    let k = key(&op.entry.tenant, &op.entry.bucket_name);
    if op.create_only {
        match c.omap_get_val(&k) {
            Ok(_) => return Err(EEXIST),
            Err(ENOENT) => {}
            Err(e) => return Err(e),
        }
    }
    c.omap_set(&[(&k, &enc(&op.entry)?)])?;
    Ok(Vec::new())
}

/// `reshard_list`: `max` 0 or > 1000 fetches 1000 but decodes only `max` entries (so max 0 yields
/// an empty list, possibly flagged truncated: upstream behaviour).
pub fn reshard_list<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: ReshardListOp = dec_op(input)?;
    let fetch = if op.max != 0 && op.max < MAX_LIST {
        op.max
    } else {
        MAX_LIST
    };
    let (vals, more) = c.omap_get_vals(&op.marker, b"", fetch as u64)?;
    let mut ret = ReshardListRet {
        is_truncated: more,
        ..Default::default()
    };
    for v in vals.values().take(op.max as usize) {
        ret.entries
            .push(Decode::decode(&mut Decoder::new(v)).eio()?);
    }
    enc(&ret)
}

pub fn reshard_get<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: ReshardGetOp = dec_op(input)?;
    let entry: ReshardEntry = read_omap(c, &key(&op.entry.tenant, &op.entry.bucket_name))?;
    enc(&ReshardGetRet { entry })
}

/// `reshard_remove`: a non-empty `bucket_id` that differs from the queued one leaves the (newer)
/// entry alone; a failing removal is swallowed (returns 0).
pub fn reshard_remove<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: ReshardRemoveOp = dec_op(input)?;
    let k = key(&op.tenant, &op.bucket_name);
    let entry: ReshardEntry = read_omap(c, &k)?;
    if !op.bucket_id.is_empty() && entry.bucket_id != op.bucket_id {
        return Ok(());
    }
    let _ = c.omap_remove_key(&k);
    Ok(())
}
