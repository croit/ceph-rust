// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Class `user` (spec/cls_user.md): per-user bucket list objects (omap key = bucket name, header =
//! `cls_user_header`) and per-account resource indexes (omap key = lowercased resource name).

use crate::ctx::{ClsCtx, omap_scan};
use crate::env_struct;
use crate::errno::*;
use crate::wire::legacy;
use denc::types::UTime;
use denc::{BufMut, Decode, Decoder, Encode, Encoder};
use std::ops::ControlFlow::Continue;

/// `-EUSERS` (Linux 87): account resource limit reached.
pub const EUSERS: Errno = -87;
const MAX_ENTRIES: u64 = 1000;

/// `cls_user_bucket`: written as v9/c8 only when `placement_id` is set, else v7/c3 (older RGW
/// must keep decoding what a newer OSD wrote).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UserBucket {
    pub name: Vec<u8>,
    pub marker: Vec<u8>,
    pub bucket_id: Vec<u8>,
    pub placement_id: Vec<u8>,
    pub data_pool: Vec<u8>,
    pub index_pool: Vec<u8>,
    pub data_extra_pool: Vec<u8>,
}
impl Encode for UserBucket {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        if !self.placement_id.is_empty() {
            e.versioned(9, 8, |e| {
                self.name.encode(e)?;
                self.marker.encode(e)?;
                self.bucket_id.encode(e)?;
                self.placement_id.encode(e)
            })
        } else {
            e.versioned(7, 3, |e| {
                self.name.encode(e)?;
                self.data_pool.encode(e)?;
                self.marker.encode(e)?;
                self.bucket_id.encode(e)?;
                self.index_pool.encode(e)?;
                self.data_extra_pool.encode(e)
            })
        }
    }
}
impl<'a> Decode<'a> for UserBucket {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        legacy(d, 8, 3, 3, |d, v| {
            let mut b = UserBucket {
                name: Vec::<u8>::decode(d)?,
                ..Default::default()
            };
            if v < 8 {
                b.data_pool = Vec::<u8>::decode(d)?;
            }
            if v >= 2 {
                b.marker = Vec::<u8>::decode(d)?;
                if v <= 3 {
                    b.bucket_id = d.u64()?.to_string().into_bytes();
                } else {
                    b.bucket_id = Vec::<u8>::decode(d)?;
                }
            }
            if v < 8 {
                if v >= 5 {
                    b.index_pool = Vec::<u8>::decode(d)?;
                } else {
                    b.index_pool = b.data_pool.clone();
                }
                if v >= 7 {
                    b.data_extra_pool = Vec::<u8>::decode(d)?;
                }
            } else {
                b.placement_id = Vec::<u8>::decode(d)?;
                if v == 8 && b.placement_id.is_empty() {
                    b.data_pool = Vec::<u8>::decode(d)?;
                    b.index_pool = Vec::<u8>::decode(d)?;
                    b.data_extra_pool = Vec::<u8>::decode(d)?;
                }
            }
            Ok(b)
        })
    }
}

/// `cls_user_bucket_entry`: encoded v9/c5; decode accepts the legacy forms up to v9.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BucketEntry {
    pub bucket: UserBucket,
    pub size: u64,
    pub size_rounded: u64,
    pub creation_time: UTime,
    pub count: u64,
    pub user_stats_sync: bool,
}
impl Encode for BucketEntry {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(9, 5, |e| {
            Vec::<u8>::new().encode(e)?; // formerly the bucket name
            e.u64(self.size)?;
            e.u32(self.creation_time.sec)?; // time_t, truncated like upstream
            e.u64(self.count)?;
            self.bucket.encode(e)?;
            e.u64(self.size_rounded)?;
            e.bool(self.user_stats_sync)?;
            self.creation_time.encode(e)
        })
    }
}
impl<'a> Decode<'a> for BucketEntry {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        legacy(d, 9, 5, 5, |d, v| {
            let mut x = BucketEntry::default();
            Vec::<u8>::decode(d)?;
            x.size = d.u64()?;
            let mt = d.u32()?;
            if v < 7 {
                x.creation_time = UTime::new(mt, 0);
            }
            if v >= 2 {
                x.count = d.u64()?;
            }
            if v >= 3 {
                x.bucket = UserBucket::decode(d)?;
            }
            if v >= 4 {
                x.size_rounded = d.u64()?;
            }
            if v >= 6 {
                x.user_stats_sync = d.bool()?;
            }
            if v >= 7 {
                x.creation_time = UTime::decode(d)?;
            }
            if v == 8 {
                Vec::<u8>::decode(d)?; // placement_rule, removed in v9
            }
            Ok(x)
        })
    }
}

env_struct!(Stats (1, 1) { total_entries: u64, total_bytes: u64, total_bytes_rounded: u64 });
env_struct!(
    /// `cls_user_header` = omap header of a user bucket-list object.
    Header (1, 1) { stats: Stats, last_stats_sync: UTime, last_stats_update: UTime });
env_struct!(AccountHeader (1, 1) { count: u32 });
env_struct!(AccountResource (1, 1) { name: Vec<u8>, path: Vec<u8>, metadata: Vec<u8> });

env_struct!(SetBucketsOp (1, 1) { entries: Vec<BucketEntry>, add: bool, time: UTime });
env_struct!(RemoveBucketOp (1, 1) { bucket: UserBucket });
env_struct!(ListBucketsRet (1, 1) { entries: Vec<BucketEntry>, marker: Vec<u8>, truncated: bool });
env_struct!(GetHeaderOp (1, 1) {});
env_struct!(GetHeaderRet (1, 1) { header: Header });
env_struct!(CompleteStatsSyncOp (1, 1) { time: UTime });
env_struct!(ResetStatsOp (1, 1) { time: UTime });
env_struct!(ResetStats2Op (1, 1) { time: UTime, marker: Vec<u8>, acc_stats: Stats });
env_struct!(ResetStats2Ret (1, 1) { marker: Vec<u8>, acc_stats: Stats, truncated: bool });
env_struct!(AccountResourceAddOp (1, 1) { entry: AccountResource, exclusive: bool, limit: u32 });
env_struct!(AccountResourceGetOp (1, 1) { name: Vec<u8> });
env_struct!(AccountResourceGetRet (1, 1) { entry: AccountResource });
env_struct!(AccountResourceRmOp (1, 1) { name: Vec<u8> });
env_struct!(AccountResourceListOp (1, 1) { marker: Vec<u8>, path_prefix: Vec<u8>, max_entries: u32 });
env_struct!(AccountResourceListRet (1, 1) { entries: Vec<AccountResource>, truncated: bool, marker: Vec<u8> });

/// `cls_user_list_buckets_op` (2,1): `end_marker` only in v2.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListBucketsOp {
    pub marker: Vec<u8>,
    pub max_entries: i32,
    pub end_marker: Vec<u8>,
}
impl Encode for ListBucketsOp {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(2, 1, |e| {
            self.marker.encode(e)?;
            e.i32(self.max_entries)?;
            self.end_marker.encode(e)
        })
    }
}
impl<'a> Decode<'a> for ListBucketsOp {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(2, |d, v| {
            Ok(ListBucketsOp {
                marker: Vec::<u8>::decode(d)?,
                max_entries: d.i32()?,
                end_marker: if v >= 2 {
                    Vec::<u8>::decode(d)?
                } else {
                    Vec::new()
                },
            })
        })
    }
}

/// Header read: empty/absent = default; undecodable = `EIO`.
fn read_header<C: ClsCtx, T: for<'a> Decode<'a> + Default>(c: &mut C) -> Result<T, Errno> {
    let b = c.omap_get_header()?;
    if b.is_empty() {
        Ok(T::default())
    } else {
        dec_stored(&b)
    }
}
fn get_entry<C: ClsCtx>(c: &mut C, name: &[u8]) -> Result<BucketEntry, Errno> {
    if name.is_empty() {
        return Err(EINVAL);
    }
    dec_stored(&c.omap_get_val(name)?)
}
fn add_stats(s: &mut Stats, e: &BucketEntry) {
    s.total_entries = s.total_entries.wrapping_add(e.count);
    s.total_bytes = s.total_bytes.wrapping_add(e.size);
    s.total_bytes_rounded = s.total_bytes_rounded.wrapping_add(e.size_rounded);
}
fn dec_stats(s: &mut Stats, e: &BucketEntry) {
    s.total_bytes = s.total_bytes.wrapping_sub(e.size);
    s.total_bytes_rounded = s.total_bytes_rounded.wrapping_sub(e.size_rounded);
    s.total_entries = s.total_entries.wrapping_sub(e.count);
}

pub fn set_buckets_info<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: SetBucketsOp = dec_op(input)?;
    let mut h: Header = read_header(c)?;
    for upd in &op.entries {
        let mut entry = match get_entry(c, &upd.bucket.name) {
            Err(ENOENT) => {
                if !op.add {
                    continue; // bucket already removed: nothing to update
                }
                upd.clone()
            }
            Err(e) => return Err(e),
            Ok(mut ex) => {
                if op.add {
                    // bucket id may change (reshard), creation time too (recreate)
                    ex.bucket.bucket_id = upd.bucket.bucket_id.clone();
                    ex.creation_time = upd.creation_time;
                }
                ex
            }
        };
        if entry.user_stats_sync {
            dec_stats(&mut h.stats, &entry);
        }
        if !op.add {
            entry.size = upd.size;
            entry.size_rounded = upd.size_rounded;
            entry.count = upd.count;
        }
        entry.user_stats_sync = true;
        c.omap_set(&[(&upd.bucket.name, &enc(&entry)?)])?;
        add_stats(&mut h.stats, &entry);
    }
    if h.last_stats_update < op.time {
        h.last_stats_update = op.time;
    }
    c.omap_set_header(&enc(&h)?)?;
    Ok(Vec::new())
}

pub fn complete_stats_sync<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: CompleteStatsSyncOp = dec_op(input)?;
    let mut h: Header = read_header(c)?;
    if h.last_stats_sync < op.time {
        h.last_stats_sync = op.time;
    }
    c.omap_set_header(&enc(&h)?)?;
    Ok(())
}

pub fn remove_bucket<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: RemoveBucketOp = dec_op(input)?;
    let mut h: Header = read_header(c)?;
    let entry = match get_entry(c, &op.bucket.name) {
        Err(ENOENT) => return Ok(Vec::new()), // idempotent
        Err(e) => return Err(e),
        Ok(e) => e,
    };
    c.omap_remove_key(&op.bucket.name)?;
    if entry.user_stats_sync {
        dec_stats(&mut h.stats, &entry);
        c.omap_set_header(&enc(&h)?)?;
    }
    Ok(Vec::new())
}

pub fn list_buckets<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: ListBucketsOp = dec_op(input)?;
    // i32 -> size_t like upstream (negative = huge), capped at 1000
    let max = (op.max_entries as u32 as u64).min(MAX_ENTRIES);
    let (keys, more) = c.omap_get_vals(&op.marker, b"", max)?;
    let mut ret = ListBucketsRet {
        truncated: more,
        ..Default::default()
    };
    let mut marker = Vec::new();
    for (k, v) in &keys {
        marker = k.clone();
        if !op.end_marker.is_empty() && op.end_marker.as_slice() <= k.as_slice() {
            ret.truncated = false;
            break;
        }
        if let Ok(e) = BucketEntry::decode(&mut Decoder::new(v)) {
            ret.entries.push(e); // undecodable entries are skipped
        }
    }
    if ret.truncated {
        ret.marker = marker;
    }
    enc(&ret)
}

pub fn get_header<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let _: GetHeaderOp = dec_op(input)?;
    let header: Header = read_header(c)?;
    enc(&GetHeaderRet { header })
}

/// Legacy full-scan stats reset (sums every entry into a fresh header).
pub fn reset_user_stats<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: ResetStatsOp = dec_op(input)?;
    let mut h = Header::default();
    omap_scan(c, b"", b"", u64::MAX, |_, _, v| {
        let e: BucketEntry = dec_stored(&v)?;
        add_stats(&mut h.stats, &e);
        Ok(Continue(()))
    })?;
    h.last_stats_update = op.time;
    c.omap_set_header(&enc(&h)?)?;
    Ok(())
}

/// One page of the stats reset; the accumulator starts at ZERO each call (op.acc_stats ignored).
pub fn reset_user_stats2<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: ResetStats2Op = dec_op(input)?;
    let (keys, more) = c.omap_get_vals(&op.marker, b"", MAX_ENTRIES)?;
    let mut ret = ResetStats2Ret {
        truncated: more,
        ..Default::default()
    };
    for v in keys.values() {
        let e: BucketEntry = dec_stored(v)?;
        add_stats(&mut ret.acc_stats, &e);
    }
    if !ret.truncated {
        // last page: a FRESH header (last_stats_sync = 0), the stored one is not read (classic)
        let h = Header {
            stats: ret.acc_stats.clone(),
            last_stats_update: op.time,
            ..Default::default()
        };
        c.omap_set_header(&enc(&h)?)?;
        return enc(&ret);
    }
    if let Some(k) = keys.keys().next_back() {
        ret.marker = k.clone();
    }
    enc(&ret)
}

// ---------------------------------------------------------------- account resources

fn resource_key(name: &[u8]) -> Vec<u8> {
    name.to_ascii_lowercase()
}

pub fn account_resource_add<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: AccountResourceAddOp = dec_op(input)?;
    let key = resource_key(&op.entry.name);
    let exists = match c.omap_get_val(&key) {
        Ok(_) => true,
        Err(ENOENT) => false,
        Err(e) => return Err(e),
    };
    let mut header = None;
    if !exists {
        let mut h: AccountHeader = read_header(c)?;
        if h.count >= op.limit {
            return Err(EUSERS);
        }
        h.count += 1;
        header = Some(h);
    } else if op.exclusive {
        return Err(EEXIST);
    }
    c.omap_set(&[(&key, &enc(&op.entry)?)])?;
    if let Some(h) = header {
        c.omap_set_header(&enc(&h)?)?;
    }
    Ok(Vec::new())
}

pub fn account_resource_get<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: AccountResourceGetOp = dec_op(input)?;
    let v = c.omap_get_val(&resource_key(&op.name))?;
    let entry: AccountResource = dec_stored(&v)?;
    enc(&AccountResourceGetRet { entry })
}

pub fn account_resource_rm<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: AccountResourceRmOp = dec_op(input)?;
    let key = resource_key(&op.name);
    c.omap_get_val(&key)?; // ENOENT if absent (remove_key alone would succeed either way)
    c.omap_remove_key(&key)?;
    let mut h: AccountHeader = read_header(c)?;
    if h.count > 0 {
        h.count -= 1;
    }
    c.omap_set_header(&enc(&h)?)?;
    Ok(())
}

pub fn account_resource_list<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: AccountResourceListOp = dec_op(input)?;
    let max = (op.max_entries.min(1000)) as u64;
    let (keys, more) = c.omap_get_vals(&op.marker, b"", max)?;
    let mut ret = AccountResourceListRet {
        truncated: more,
        ..Default::default()
    };
    for v in keys.values() {
        let e: AccountResource = dec_stored(v)?;
        if e.path.starts_with(&op.path_prefix) {
            ret.entries.push(e);
        }
    }
    if let Some(k) = keys.keys().next_back() {
        ret.marker = k.clone(); // last FETCHED key
    }
    enc(&ret)
}
