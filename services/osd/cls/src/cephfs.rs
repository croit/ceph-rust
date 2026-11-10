// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Class `cephfs` (spec/cls_cephfs.md): `accumulate_inode_metadata` for cephfs-data-scan.

use crate::ctx::ClsCtx;
use crate::env_struct;
use crate::errno::*;
use denc::{Decode, Decoder, Encode};

env_struct!(
    /// `ObjCeiling`: highest object index seen and its size.
    ObjCeiling (1, 1) { id: u64, size: u64 });
env_struct!(
/// `AccumulateArgs`
AccumulateArgs (1, 1) {
    obj_xattr_name: Vec<u8>,
    mtime_xattr_name: Vec<u8>,
    obj_size_xattr_name: Vec<u8>,
    obj_index: u64,
    obj_size: u64,
    mtime: i64,
});

/// Write `new` to xattr `name` unless the stored value decodes cleanly (no trailing bytes) and is
/// not smaller than `new` under `greater(new, old)`.
fn set_if_greater<C: ClsCtx, T>(
    c: &mut C,
    name: &[u8],
    new: &T,
    greater: impl Fn(&T, &T) -> bool,
) -> Result<(), Errno>
where
    T: Encode + for<'a> Decode<'a>,
{
    let write = match c.getxattr_raw(name) {
        Err(_) => true,
        Ok(b) if b.is_empty() => true,
        Ok(b) => {
            let mut d = Decoder::new(&b);
            match T::decode(&mut d) {
                Ok(old) if d.remaining() == 0 => greater(new, &old),
                _ => true,
            }
        }
    };
    if write {
        c.setxattr_raw(name, &new.encode_to_vec().eio()?)?;
    }
    Ok(())
}

pub fn accumulate_inode_metadata<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let a = AccumulateArgs::decode(&mut Decoder::new(input)).inval()?;
    let ceiling = ObjCeiling {
        id: a.obj_index,
        size: a.obj_size,
    };
    set_if_greater(c, &a.obj_xattr_name, &ceiling, |n, o| n.id > o.id)?;
    set_if_greater(c, &a.mtime_xattr_name, &a.mtime, |n, o| n > o)?;
    set_if_greater(c, &a.obj_size_xattr_name, &a.obj_size, |n, o| n > o)?;
    Ok(())
}
