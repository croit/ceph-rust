// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Class `refcount` (spec/cls_refcount.md): tag set in xattr `refcount`; last put removes the object.

use crate::ctx::ClsCtx;
use crate::env_struct;
use crate::errno::*;
use denc::{BufMut, Decode, Decoder, Encode, Encoder};
use std::collections::{BTreeMap, BTreeSet};

pub const ATTR: &str = "refcount";

env_struct!(GetOp (1, 1) { tag: Vec<u8>, implicit_ref: bool });
env_struct!(PutOp (1, 1) { tag: Vec<u8>, implicit_ref: bool });
env_struct!(SetOp (1, 1) { refs: Vec<Vec<u8>> });
env_struct!(ReadOp (1, 1) { implicit_ref: bool });
env_struct!(ReadRet (1, 1) { refs: Vec<Vec<u8>> });

/// Stored value `obj_refcount` (v2, compat 1): refs map + retired set (v>=2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ObjRefcount {
    pub refs: BTreeMap<Vec<u8>, bool>,
    pub retired: BTreeSet<Vec<u8>>,
}
impl Encode for ObjRefcount {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(2, 1, |e| {
            self.refs.encode(e)?;
            self.retired.encode(e)
        })
    }
}
impl<'a> Decode<'a> for ObjRefcount {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(2, |d, v| {
            let refs = BTreeMap::decode(d)?;
            let retired = if v >= 2 {
                BTreeSet::decode(d)?
            } else {
                BTreeSet::new()
            };
            Ok(ObjRefcount { refs, retired })
        })
    }
}

/// `ENODATA` (object exists, no attr) -> empty (+ wildcard "" if implicit); `ENOENT` is an error.
fn read_refcount<C: ClsCtx>(c: &mut C, implicit: bool) -> Result<ObjRefcount, Errno> {
    match c.getxattr(ATTR) {
        Err(ENODATA) => {
            let mut o = ObjRefcount::default();
            if implicit {
                o.refs.insert(Vec::new(), true);
            }
            Ok(o)
        }
        Err(e) => Err(e),
        Ok(b) => ObjRefcount::decode(&mut Decoder::new(&b)).eio(),
    }
}
fn set_refcount<C: ClsCtx>(c: &mut C, o: &ObjRefcount) -> Result<(), Errno> {
    c.setxattr(ATTR, &o.encode_to_vec().eio()?)
}

pub fn get<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: GetOp = dec_op(input)?;
    let mut o = read_refcount(c, op.implicit_ref)?;
    o.refs.insert(op.tag, true);
    set_refcount(c, &o)?;
    Ok(())
}

pub fn put<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: PutOp = dec_op(input)?;
    let mut o = read_refcount(c, op.implicit_ref)?;
    if o.refs.is_empty() {
        return Err(EINVAL);
    }
    let found = if o.refs.contains_key(&op.tag) {
        Some(op.tag.clone())
    } else if op.implicit_ref && o.refs.contains_key(&[][..]) {
        Some(Vec::new())
    } else {
        None
    };
    let Some(found) = found else {
        return Ok(());
    };
    // bug-compat: an already retired tag is a silent no-op even if a ref was found
    if o.retired.contains(&op.tag) {
        return Ok(());
    }
    o.retired.insert(op.tag);
    o.refs.remove(&found);
    if o.refs.is_empty() {
        c.remove()?;
        return Ok(());
    }
    set_refcount(c, &o)?;
    Ok(())
}

pub fn set<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: SetOp = dec_op(input)?;
    if op.refs.is_empty() {
        c.remove()?;
        return Ok(());
    }
    let o = ObjRefcount {
        refs: op.refs.into_iter().map(|t| (t, true)).collect(),
        retired: BTreeSet::new(),
    };
    set_refcount(c, &o)?;
    Ok(())
}

pub fn read<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<Vec<u8>, Errno> {
    let op: ReadOp = dec_op(input)?;
    let o = read_refcount(c, op.implicit_ref)?;
    let r = ReadRet {
        refs: o.refs.into_keys().collect(),
    };
    r.encode_to_vec().eio()
}
