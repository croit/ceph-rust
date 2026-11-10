// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Class `rgw`, `mp_upload_part_info_update` (spec/cls_rgw.md s11): one multipart part record on the
//! upload's meta object. Server side it only guards against a part retry reusing a tail-object
//! prefix that an earlier attempt of the same part already used, and records the old prefixes in
//! `past_prefixes` for later cleanup.
//!
//! The `RGWUploadPartInfo` value is treated as bytes with a few parsed fields: everything is kept
//! verbatim (manifest, compression info, checksum are opaque enveloped blobs) except
//! `past_prefixes`, which is rewritten; the manifest is parsed just far enough to read its
//! `prefix` and `empty()`.

use crate::ctx::ClsCtx;
use crate::errno::*;
use crate::wire::legacy;
use denc::types::UTime;
use denc::{BufMut, Decode, Decoder, Encode, Encoder, Error};
use std::collections::BTreeSet;

type D<T> = denc::Result<T>;

/// `RGWUploadPartInfo` v7 layout with opaque blobs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PartInfo {
    pub num: u32,
    pub size: u64,
    pub etag: Vec<u8>,
    pub modified: UTime,
    /// Whole enveloped `RGWObjManifest` (header included).
    pub manifest: Vec<u8>,
    /// Whole enveloped `RGWCompressionInfo`.
    pub cs_info: Vec<u8>,
    pub accounted_size: u64,
    pub past_prefixes: BTreeSet<Vec<u8>>,
    /// `optional<Cksum>`: presence byte + enveloped blob.
    pub cksum: Vec<u8>,
    pub crypt_salt: Vec<u8>,
    // parsed out of `manifest`
    pub prefix: Vec<u8>,
    pub manifest_empty: bool,
}

/// `RGWCompressionInfo` default: compression_type "none", orig_size 0, no message, no blocks.
fn default_cs_info() -> Vec<u8> {
    let mut e = Encoder::new();
    let _ = e.versioned(2, 1, |e| {
        e.bytes(b"none")?;
        e.u64(0)?;
        e.u8(0)?; // optional<int32> absent
        e.u32(0) // blocks
    });
    e.into_vec()
}

/// Read `prefix` and `empty()` of an enveloped `RGWObjManifest` (struct_v >= 3 layout; older
/// manifests are explicit-object only with an empty prefix).
fn manifest_info(raw: &[u8]) -> D<(Vec<u8>, bool)> {
    Decoder::new(raw).versioned_min(2, 6, |d, v| {
        let skip_map = |d: &mut Decoder<'_>| -> D<usize> {
            // map<u64, enveloped value>
            let n = d.count()?;
            for _ in 0..n {
                d.u64()?;
                d.envelope_raw()?;
            }
            Ok(n)
        };
        d.u64()?; // obj_size
        let objs = skip_map(d)?;
        if v < 3 {
            return Ok((Vec::new(), objs == 0));
        }
        let explicit = d.bool()?;
        d.envelope_raw()?; // rgw_obj
        d.u64()?; // head_size
        d.u64()?; // max_head_size
        let prefix = Vec::<u8>::decode(d)?;
        let rules = skip_map(d)?;
        Ok((prefix, if explicit { objs == 0 } else { rules == 0 }))
    })
}

impl<'a> Decode<'a> for PartInfo {
    fn decode(d: &mut Decoder<'a>) -> D<Self> {
        legacy(d, 7, 2, 2, |d, v| {
            let mut p = PartInfo {
                num: d.u32()?,
                size: d.u64()?,
                etag: Vec::<u8>::decode(d)?,
                modified: UTime::decode(d)?,
                ..Default::default()
            };
            if v < 3 {
                return Err(Error::BadValue("upload part info without manifest"));
            }
            p.manifest = d.envelope_raw()?.to_vec();
            (p.prefix, p.manifest_empty) = manifest_info(&p.manifest)?;
            if v >= 4 {
                p.cs_info = d.envelope_raw()?.to_vec();
                p.accounted_size = d.u64()?;
            } else {
                p.cs_info = default_cs_info();
                p.accounted_size = p.size;
            }
            if v >= 5 {
                p.past_prefixes = BTreeSet::decode(d)?;
            }
            if v >= 6 {
                if d.u8()? == 0 {
                    p.cksum = vec![0];
                } else {
                    p.cksum = vec![1];
                    p.cksum.extend_from_slice(d.envelope_raw()?);
                }
            } else {
                p.cksum = vec![0];
            }
            if v >= 7 {
                p.crypt_salt = Vec::<u8>::decode(d)?;
            }
            Ok(p)
        })
    }
}
impl Encode for PartInfo {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> D<()> {
        e.versioned(7, 2, |e| {
            e.u32(self.num)?;
            e.u64(self.size)?;
            self.etag.encode(e)?;
            self.modified.encode(e)?;
            e.raw(&self.manifest)?;
            e.raw(&self.cs_info)?;
            e.u64(self.accounted_size)?;
            self.past_prefixes.encode(e)?;
            e.raw(&self.cksum)?;
            self.crypt_salt.encode(e)
        })
    }
}

/// `cls_rgw_mp_upload_part_info_update_op` (1,1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MpUpdateOp {
    pub part_key: Vec<u8>,
    pub info: PartInfo,
}
impl Encode for MpUpdateOp {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> D<()> {
        e.versioned(1, 1, |e| {
            self.part_key.encode(e)?;
            self.info.encode(e)
        })
    }
}
impl<'a> Decode<'a> for MpUpdateOp {
    fn decode(d: &mut Decoder<'a>) -> D<Self> {
        d.versioned(1, |d, _| {
            Ok(MpUpdateOp {
                part_key: Vec::<u8>::decode(d)?,
                info: PartInfo::decode(d)?,
            })
        })
    }
}

/// `mp_upload_part_info_update` (RW): `EEXIST` when the new manifest prefix was used before for
/// this part (own `past_prefixes`, the stored record's, or the stored manifest's current prefix);
/// else store the record with the merged `past_prefixes`.
pub fn mp_upload_part_info_update<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let mut op: MpUpdateOp = dec_op(input)?;
    let stored = match c.omap_get_val(&op.part_key) {
        Ok(b) => Some(PartInfo::decode(&mut Decoder::new(&b)).eio()?),
        Err(ENOENT) => None,
        Err(e) => return Err(e),
    };
    if let Some(s) = stored {
        if !s.manifest_empty {
            op.info.past_prefixes.insert(s.prefix);
        }
        op.info.past_prefixes.extend(s.past_prefixes);
    }
    if op.info.past_prefixes.contains(&op.info.prefix) {
        return Err(EEXIST);
    }
    let v = op.info.encode_to_vec().inval()?;
    c.omap_set(&[(&op.part_key, &v)])?;
    Ok(Vec::new())
}
