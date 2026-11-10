// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Map a wire `replwire` transaction (spec replication.md 1.6) onto `store::obj::TOp`s in one streaming pass
//! (`replwire::OpStream`, adr 0160 D3): no decoded `Transaction`, no op vector, objects moved out of the object table
//! on their last use. `apply_tests` keeps the former decode-then-translate path as the differential oracle.
//!
//! Every op code the replica can receive is handled or rejected explicitly:
//! NOP/COLL_HINT/SETALLOCHINT are hints (dropped); the wire ops SPLIT_COLLECTION2/MERGE_COLLECTION fail with
//! `Unsupported` (PG split and merge run locally, `StoreOp::SplitOut` / `MergeIn`); legacy codes never get here (the
//! decoder rejects them).
//! Error precedence is the oracle's: any decode error of the whole transaction wins over a semantic refusal (foreign
//! collection / shard, range, unsupported op), which wins in op order.

use denc::types::{CollT, Ghobject, SpgT};
use replwire::txn::opc;
use replwire::{OpStream, TxnOpG};
use store::obj::txn::Bytes as TxnBytes;
use store::obj::{ObjError, TOp};

fn b(x: &[u8]) -> TxnBytes<'_> {
    TxnBytes::Borrowed(x)
}

fn write_bytes(data: replwire::Data<'_>) -> TxnBytes<'_> {
    let mut parts = data.parts().into_iter().filter(|p| !p.is_empty());
    let first = parts.next().unwrap_or(data.head);
    if parts.next().is_none() {
        // Fully aligned v10 writes use only `mid`; v9 writes use only `head`.
        // Keep either wire slice borrowed so the store can retain its payload owner.
        TxnBytes::Borrowed(first)
    } else {
        TxnBytes::Owned(data.to_vec())
    }
}

// The primary enforces osd_max_object_size; a replica may receive valid objects
// larger than that setting's default. Sparse growth needs no offset-sized buffer;
// the store enforces its format bounds when staging the transaction.
fn range_ok(off: u64, len: u64) -> Result<(), ObjError> {
    match off.checked_add(len) {
        Some(_) => Ok(()),
        _ => Err(ObjError::Invalid(format!(
            "range {off}+{len} overflows the object address space"
        ))),
    }
}

fn dec_err(e: denc::Error) -> ObjError {
    ObjError::Invalid(format!("transaction decode: {e}"))
}

/// Translate; `out` receives ops in order (collection creation for the temp collection first). On `Err` `out` may hold
/// a prefix (the caller drops the whole txn).
pub fn translate<'a>(
    spg: SpgT,
    middle: &'a [u8],
    data: &'a [u8],
    out: &mut Vec<TOp<'a>>,
    hints: &mut u32,
) -> Result<(), ObjError> {
    let s = OpStream::new(middle, data, replwire::DEFAULT_PAGE).map_err(dec_err)?;
    translate_stream(spg, s, out, hints)
}

/// [`translate`] for the local skeleton form of a client write (`Transaction::encode_v9_split`): the out-of-line write
/// payloads in `refs` are borrowed as they are, no copy until the store stages them.
pub fn translate_split<'a>(
    spg: SpgT,
    skel: &'a [u8],
    refs: &'a [bytes::Bytes],
    out: &mut Vec<TOp<'a>>,
    hints: &mut u32,
) -> Result<(), ObjError> {
    let s = OpStream::new_split(skel, refs, replwire::DEFAULT_PAGE).map_err(dec_err)?;
    translate_stream(spg, s, out, hints)
}

/// Failure of [`emit`]: a decode error of the stream, or a semantic refusal (decided before the rest is decoded).
enum Fail {
    Decode(denc::Error),
    Refuse(ObjError),
}
impl From<ObjError> for Fail {
    fn from(e: ObjError) -> Self {
        Fail::Refuse(e)
    }
}
impl From<denc::Error> for Fail {
    fn from(e: denc::Error) -> Self {
        Fail::Decode(e)
    }
}

fn translate_stream<'a>(
    spg: SpgT,
    mut s: OpStream<'a>,
    out: &mut Vec<TOp<'a>>,
    hints: &mut u32,
) -> Result<(), ObjError> {
    match emit(spg, &mut s, out, hints) {
        Ok(()) => s.finish().map(|_| ()).map_err(dec_err),
        Err(Fail::Decode(e)) => Err(dec_err(e)),
        Err(Fail::Refuse(e)) => {
            // a decode error anywhere in the transaction takes precedence (the oracle decodes everything first)
            while s.next_op().map_err(dec_err)?.is_some() {}
            s.finish().map_err(dec_err)?;
            Err(e)
        }
    }
}

/// Object operands an op consumes (as [`emit`] takes them), from the raw record fields.
fn consumed(code: u32, oid: u32, dest: u32) -> [Option<u32>; 2] {
    use opc::*;
    match code {
        CREATE | TOUCH | TOUCH_TEMP | WRITE | ZERO | TRUNCATE | REMOVE | SETATTR | SETATTRS
        | RMATTR | RMATTRS | OMAP_CLEAR | OMAP_SETKEYS | OMAP_RMKEYS | OMAP_RMKEYRANGE
        | OMAP_SETHEADER => [Some(oid), None],
        CLONE | CLONERANGE2 | COLL_MOVE_RENAME | TRY_RENAME => [Some(oid), Some(dest)],
        _ => [None, None],
    }
}

/// The object for one operand: moved out of the table on its last counted use, cloned before. A use the count did not
/// foresee is refused (never an emptied object).
fn take(objs: &mut [Ghobject], uses: &mut [u32], x: replwire::Ox) -> Result<Ghobject, ObjError> {
    let i = x.0 as usize;
    match uses.get_mut(i) {
        Some(1) => {
            uses[i] = 0;
            Ok(std::mem::replace(&mut objs[i], Ghobject::MIN()))
        }
        Some(u) if *u > 1 => {
            *u -= 1;
            Ok(objs[i].clone())
        }
        _ => Err(ObjError::Invalid(format!(
            "transaction object {i}: operand not counted"
        ))),
    }
}

fn emit<'a>(
    spg: SpgT,
    s: &mut OpStream<'a>,
    out: &mut Vec<TOp<'a>>,
    hints: &mut u32,
) -> Result<(), Fail> {
    for c in &s.colls {
        match c {
            CollT::Pg(x) if *x == spg => {}
            CollT::PgTemp(x) if *x == spg => out.push(TOp::MkColl {
                cid: *c,
                bits: 0,
                exist_ok: true,
            }),
            _ => {
                return Err(ObjError::Invalid(format!(
                    "transaction names collection {c} outside pg {spg}"
                ))
                .into());
            }
        }
    }
    // a PG instance only ever touches objects of its own shard (replicated: NO_SHARD): data for a foreign shard is a
    // bug of the sender and must never land in our collection
    if let Some(g) = s.objs.iter().find(|g| g.shard != spg.shard) {
        return Err(ObjError::Invalid(format!(
            "transaction names object of shard {} in pg {spg}",
            g.shard.0
        ))
        .into());
    }
    let mut small = [0u32; 8];
    let mut big = Vec::new();
    let n = s.objs.len();
    let uses: &mut [u32] = if n <= small.len() {
        &mut small[..n]
    } else {
        big.resize(n, 0);
        &mut big
    };
    for (code, o, d) in s.raw_refs() {
        for x in consumed(code, o, d).into_iter().flatten() {
            if let Some(u) = uses.get_mut(x as usize) {
                *u += 1;
            }
        }
    }
    out.reserve(s.ops_left());
    while let Some((cx, op)) = s.next_op()? {
        use TxnOpG::*;
        match &op {
            Write { off, data, .. } => range_ok(*off, data.len() as u64)?,
            Zero { off, len, .. } => range_ok(*off, *len)?,
            Truncate { size, .. } => range_ok(*size, 0)?,
            CloneRange2 {
                src_off,
                len,
                dest_off,
                ..
            } => {
                range_ok(*src_off, *len)?;
                range_ok(*dest_off, *len)?;
            }
            _ => {}
        }
        let objs = &mut s.objs;
        let mut o = |x: replwire::Ox| take(objs, uses, x);
        let cid = match op {
            Nop | CollHint { .. } => continue,
            _ => s.colls[cx.0 as usize],
        };
        let top = match op {
            Nop | CollHint { .. } => continue,
            // input of the pool's compression mode decision (adr 0059 am. 1)
            SetAllocHint { flags, .. } => {
                *hints |= flags;
                continue;
            }
            Create { oid } | Touch { oid } | TouchTemp { oid, .. } => {
                TOp::Touch { cid, oid: o(oid)? }
            }
            Write { oid, off, data } => TOp::Write {
                cid,
                oid: o(oid)?,
                off,
                data: write_bytes(data),
            },
            Zero { oid, off, len } => TOp::Zero {
                cid,
                oid: o(oid)?,
                off,
                len,
            },
            Truncate { oid, size } => TOp::Truncate {
                cid,
                oid: o(oid)?,
                size,
            },
            Remove { oid } => TOp::Remove { cid, oid: o(oid)? },
            SetAttr { oid, name, value } => TOp::SetAttrs {
                cid,
                oid: o(oid)?,
                attrs: vec![(b(name), b(value))],
            },
            SetAttrs { oid, attrs } => TOp::SetAttrs {
                cid,
                oid: o(oid)?,
                attrs: attrs.iter().map(|(k, v)| (b(k), b(v))).collect(),
            },
            RmAttr { oid, name } => TOp::RmAttr {
                cid,
                oid: o(oid)?,
                name: b(name),
            },
            RmAttrs { oid } => TOp::RmAttrs { cid, oid: o(oid)? },
            Clone { oid, dest_oid } => TOp::Clone {
                cid,
                src: o(oid)?,
                dst: o(dest_oid)?,
            },
            CloneRange2 {
                oid,
                dest_oid,
                src_off,
                len,
                dest_off,
            } => TOp::CloneRange {
                cid,
                src: o(oid)?,
                dst: o(dest_oid)?,
                src_off,
                len,
                dst_off: dest_off,
            },
            MkColl { bits } => TOp::MkColl {
                cid,
                bits,
                exist_ok: true,
            },
            RmColl => TOp::RmColl { cid },
            CollMoveRename {
                oid,
                dest_cid,
                dest_oid,
            } => TOp::MoveRename {
                cid,
                oid: o(oid)?,
                dcid: s.colls[dest_cid.0 as usize],
                doid: o(dest_oid)?,
            },
            TryRename { oid, dest_oid } => TOp::MoveRename {
                cid,
                oid: o(oid)?,
                dcid: cid,
                doid: o(dest_oid)?,
            },
            OmapClear { oid } => TOp::OmapClear { cid, oid: o(oid)? },
            OmapSetKeys { oid, pairs } => match pairs.omap() {
                replwire::OmapKv::Run(r) => TOp::OmapSetRun {
                    cid,
                    oid: o(oid)?,
                    run: store::obj::KvRunData::new(r),
                },
                replwire::OmapKv::Pairs(p) => TOp::OmapSetKeys {
                    cid,
                    oid: o(oid)?,
                    pairs: p.into_iter().map(|(k, v)| (b(k), b(v))).collect(),
                },
            },
            OmapRmKeys { oid, keys } => TOp::OmapRmKeys {
                cid,
                oid: o(oid)?,
                keys: keys.iter().map(b).collect(),
            },
            OmapRmKeyRange { oid, first, last } => TOp::OmapRmKeyRange {
                cid,
                oid: o(oid)?,
                first: b(first),
                last: b(last),
            },
            OmapSetHeader { oid, header } => TOp::OmapSetHeader {
                cid,
                oid: o(oid)?,
                header: b(header),
            },
            CollSetBits { bits } => TOp::SetCollBits { cid, bits },
            SplitCollection2 { .. } => {
                return Err(ObjError::Unsupported(
                    "SPLIT_COLLECTION2 (wire op; PG split runs locally)",
                )
                .into());
            }
            MergeCollection { .. } => {
                return Err(ObjError::Unsupported(
                    "MERGE_COLLECTION (wire op; PG merge runs locally)",
                )
                .into());
            }
        };
        out.push(top);
    }
    Ok(())
}

#[cfg(test)]
#[path = "apply_tests.rs"]
mod tests;
