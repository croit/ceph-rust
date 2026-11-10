// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Class `cmpomap` (spec/cls_cmpomap.md): conditional omap read/set/remove.

use crate::ctx::ClsCtx;
use crate::errno::*;
use denc::{Decode, Decoder, Encode};
use std::collections::BTreeMap;

pub const MODE_STRING: u8 = 1;
pub const MODE_U64: u8 = 2;
pub const OP_EQ: u8 = 1;
pub const OP_NE: u8 = 2;
pub const OP_GT: u8 = 3;
pub const OP_GTE: u8 = 4;
pub const OP_LT: u8 = 5;
pub const OP_LTE: u8 = 6;

/// `cmp_vals_op` / `cmp_set_vals_op` (`default_value` present) and `cmp_rm_keys_op` (always None).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CmpOp {
    pub mode: u8,
    pub comparison: u8,
    pub values: BTreeMap<Vec<u8>, Vec<u8>>,
    pub default_value: Option<Vec<u8>>,
}
impl CmpOp {
    /// Encode as `cmp_vals_op`/`cmp_set_vals_op` (with default) or `cmp_rm_keys_op` (`with_default` false).
    pub fn to_bytes(&self, with_default: bool) -> Vec<u8> {
        let mut e = denc::Encoder::new();
        let _ = e.versioned(1, 1, |e| {
            e.u8(self.mode)?;
            e.u8(self.comparison)?;
            self.values.encode(e)?;
            if with_default {
                self.default_value.encode(e)?;
            }
            Ok(())
        });
        e.into_vec()
    }
    fn parse(input: &[u8], with_default: bool) -> Result<CmpOp, Errno> {
        Decoder::new(input)
            .versioned(1, |d, _| {
                Ok(CmpOp {
                    mode: d.u8()?,
                    comparison: d.u8()?,
                    values: BTreeMap::decode(d)?,
                    default_value: if with_default {
                        Option::<Vec<u8>>::decode(d)?
                    } else {
                        None
                    },
                })
            })
            .inval()
    }
}

/// Order of two values the way a classic OSD orders `bufferlist`s: lexicographic, a proper prefix sorts first, and the
/// bytes compare as the platform C `char` (signed on x86_64, unsigned on aarch64 Linux). An croit-flashstore-osd therefore agrees
/// with the classic OSDs of its own architecture in a mixed acting set (doc/spec/cls_cmpomap.md, client-ops.md). EQ/NE
/// are plain byte equality either way.
pub fn bufferlist_cmp(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    let ch = |x: &u8| *x as std::ffi::c_char;
    a.iter().map(ch).cmp(b.iter().map(ch))
}

/// A value in classic `bufferlist` order ([`bufferlist_cmp`]).
#[derive(PartialEq, Eq)]
struct Bl<'a>(&'a [u8]);
impl PartialOrd for Bl<'_> {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Bl<'_> {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        bufferlist_cmp(self.0, o.0)
    }
}

fn apply<T: Ord>(op: u8, l: T, r: T) -> Result<bool, Errno> {
    Ok(match op {
        OP_EQ => l == r,
        OP_NE => l != r,
        OP_GT => l > r,
        OP_GTE => l >= r,
        OP_LT => l < r,
        OP_LTE => l <= r,
        _ => return Err(EINVAL),
    })
}

fn rd_u64(b: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(..8)?.try_into().ok()?))
}

/// `Ok(true/false)` or the errno (EINVAL bad input/mode/op, EIO undecodable stored value).
fn compare(mode: u8, op: u8, input: &[u8], stored: &[u8]) -> Result<bool, Errno> {
    match mode {
        MODE_STRING => apply(op, Bl(input), Bl(stored)),
        MODE_U64 => {
            let l = rd_u64(input).ok_or(EINVAL)?;
            let r = if stored.is_empty() {
                0
            } else {
                rd_u64(stored).ok_or(EIO)?
            };
            apply(op, l, r)
        }
        _ => Err(EINVAL),
    }
}

/// `compare` with -EIO folded into "false" (set/rm).
fn compare_lenient(mode: u8, op: u8, input: &[u8], stored: &[u8]) -> Result<bool, Errno> {
    match compare(mode, op, input, stored) {
        Err(EIO) => Ok(false),
        r => r,
    }
}

fn fetch<C: ClsCtx>(c: &mut C, op: &CmpOp) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, Errno> {
    let keys: Vec<&[u8]> = op.values.keys().map(|k| k.as_slice()).collect();
    c.omap_get_vals_by_keys(&keys)
}

pub fn cmp_vals<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op = CmpOp::parse(input, true)?;
    let stored = fetch(c, &op)?;
    for (key, want) in &op.values {
        let cur = match stored.get(key).or(op.default_value.as_ref()) {
            Some(v) => v,
            None => return Err(ECANCELED),
        };
        if !compare(op.mode, op.comparison, want, cur)? {
            return Err(ECANCELED);
        }
    }
    Ok(())
}

pub fn cmp_set_vals<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op = CmpOp::parse(input, true)?;
    let stored = fetch(c, &op)?;
    let mut write: Vec<(&[u8], &[u8])> = Vec::new();
    for (key, want) in &op.values {
        let Some(cur) = stored.get(key).or(op.default_value.as_ref()) else {
            continue;
        };
        if compare_lenient(op.mode, op.comparison, want, cur)? {
            write.push((key, want));
        }
    }
    if !write.is_empty() {
        c.omap_set(&write)?;
    }
    Ok(())
}

pub fn cmp_rm_keys<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op = CmpOp::parse(input, false)?;
    let stored = fetch(c, &op)?;
    for (key, want) in &op.values {
        let Some(cur) = stored.get(key) else {
            continue;
        };
        if compare_lenient(op.mode, op.comparison, want, cur)? {
            c.omap_remove_key(key)?;
        }
    }
    Ok(())
}
