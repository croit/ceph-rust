// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Class `rgw`, usage log (spec/cls_rgw.md s10): objects `usage.<n>` in the log pool, off by
//! default in RGW. Methods `user_usage_log_add`, `user_usage_log_read`, `user_usage_log_trim`,
//! `usage_log_clear`.
//!
//! Every record is stored twice with the same value: by time (`<epoch:011>_<user>_<bucket>`) and
//! by user (`<user>_<epoch:011>_<bucket>`; users starting with `0` get a `~` prefix so the key
//! cannot land among the by-time keys). While `rgw_usage_log_key_transition` is on, such users'
//! legacy un-prefixed by-user keys are also cleaned (add/trim) and read (two passes).

use crate::ctx::ClsCtx;
use crate::env_struct;
use crate::errno::*;
use denc::{BufMut, Decode, Decoder, Encode, Encoder};
use std::collections::BTreeMap;

type D<T> = denc::Result<T>;

/// Read page size when the request gives none.
const READ_MAX: u32 = 1000;
/// Records one `user_usage_log_trim` call removes at most (per page).
const TRIM_PAGE: u32 = 1000;

env_struct!(
    /// `rgw_usage_data` (1,1)
    UsageData (1, 1) { bytes_sent: u64, bytes_received: u64, ops: u64, successful_ops: u64 });
env_struct!(
    /// `rgw_s3select_usage_data` (1,1)
    S3SelectUsage (1, 1) { bytes_processed: u64, bytes_returned: u64 });

impl UsageData {
    fn aggregate(&mut self, o: &UsageData) {
        self.bytes_sent = self.bytes_sent.wrapping_add(o.bytes_sent);
        self.bytes_received = self.bytes_received.wrapping_add(o.bytes_received);
        self.ops = self.ops.wrapping_add(o.ops);
        self.successful_ops = self.successful_ops.wrapping_add(o.successful_ops);
    }
}

/// `rgw_user` text form round trip (`from_str` then `to_str`): `tenant$id`, `tenant$ns$id`,
/// `$ns$id` or `id`. Owner/payer are stored in this normalized form; an empty id = "empty".
fn norm_user(s: &[u8]) -> Vec<u8> {
    let (tenant, ns, id) = split_user(s);
    join_user(tenant, ns, id)
}
fn split_once(s: &[u8]) -> Option<(&[u8], &[u8])> {
    s.iter()
        .position(|&b| b == b'$')
        .map(|i| (&s[..i], &s[i + 1..]))
}
fn split_user(s: &[u8]) -> (&[u8], &[u8], &[u8]) {
    match split_once(s) {
        None => (&[], &[], s),
        Some((tenant, rest)) => match split_once(rest) {
            Some((ns, id)) => (tenant, ns, id),
            None => (tenant, &[], rest),
        },
    }
}
fn join_user(tenant: &[u8], ns: &[u8], id: &[u8]) -> Vec<u8> {
    let mut o = Vec::new();
    if !tenant.is_empty() {
        o.extend_from_slice(tenant);
        o.push(b'$');
    }
    if !ns.is_empty() {
        if tenant.is_empty() {
            o.push(b'$');
        }
        o.extend_from_slice(ns);
        o.push(b'$');
    }
    o.extend_from_slice(id);
    o
}
fn user_empty(s: &[u8]) -> bool {
    split_user(s).2.is_empty()
}

/// `rgw_usage_log_entry` (4,1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UsageEntry {
    pub owner: Vec<u8>,
    pub payer: Vec<u8>,
    pub bucket: Vec<u8>,
    pub epoch: u64,
    /// Legacy total, kept by `aggregate`/`add_usage`.
    pub total: UsageData,
    pub usage_map: BTreeMap<Vec<u8>, UsageData>,
    pub s3select: S3SelectUsage,
}
impl UsageEntry {
    /// User the record is filed under: payer if set, else owner.
    fn puser(&self) -> &[u8] {
        if user_empty(&self.payer) {
            &self.owner
        } else {
            &self.payer
        }
    }
    fn add_usage(&mut self, cat: &[u8], d: &UsageData) {
        self.usage_map.entry(cat.to_vec()).or_default().aggregate(d);
        self.total.aggregate(d);
    }
    /// `aggregate`: an entry without owner adopts the other's identity; categories are summed.
    fn aggregate(&mut self, e: &UsageEntry) {
        if user_empty(&self.owner) {
            self.owner = e.owner.clone();
            self.bucket = e.bucket.clone();
            self.epoch = e.epoch;
            self.payer = e.payer.clone();
        }
        for (k, v) in &e.usage_map {
            self.add_usage(k, v);
        }
        self.s3select.bytes_processed = self
            .s3select
            .bytes_processed
            .wrapping_add(e.s3select.bytes_processed);
        self.s3select.bytes_returned = self
            .s3select
            .bytes_returned
            .wrapping_add(e.s3select.bytes_returned);
    }
}
impl Encode for UsageEntry {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> D<()> {
        e.versioned(4, 1, |e| {
            self.owner.encode(e)?;
            self.bucket.encode(e)?;
            e.u64(self.epoch)?;
            e.u64(self.total.bytes_sent)?;
            e.u64(self.total.bytes_received)?;
            e.u64(self.total.ops)?;
            e.u64(self.total.successful_ops)?;
            self.usage_map.encode(e)?;
            self.payer.encode(e)?;
            self.s3select.encode(e)
        })
    }
}
impl<'a> Decode<'a> for UsageEntry {
    fn decode(d: &mut Decoder<'a>) -> D<Self> {
        d.versioned(4, |d, v| {
            let mut x = UsageEntry {
                owner: norm_user(&Vec::<u8>::decode(d)?),
                bucket: Vec::<u8>::decode(d)?,
                epoch: d.u64()?,
                ..Default::default()
            };
            x.total = UsageData {
                bytes_sent: d.u64()?,
                bytes_received: d.u64()?,
                ops: d.u64()?,
                successful_ops: d.u64()?,
            };
            if v < 2 {
                x.usage_map.insert(Vec::new(), x.total.clone());
            } else {
                x.usage_map = BTreeMap::decode(d)?;
            }
            if v >= 3 {
                x.payer = norm_user(&Vec::<u8>::decode(d)?);
            }
            if v >= 4 {
                x.s3select = S3SelectUsage::decode(d)?;
            }
            Ok(x)
        })
    }
}

env_struct!(
    /// `rgw_usage_log_info` (1,1)
    UsageInfo (1, 1) { entries: Vec<UsageEntry> });

/// `rgw_cls_usage_log_add_op` (2,1): the trailing user (v2) is unused by the server.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UsageAddOp {
    pub info: UsageInfo,
    pub user: Vec<u8>,
}
impl Encode for UsageAddOp {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> D<()> {
        e.versioned(2, 1, |e| {
            self.info.encode(e)?;
            self.user.encode(e)
        })
    }
}
impl<'a> Decode<'a> for UsageAddOp {
    fn decode(d: &mut Decoder<'a>) -> D<Self> {
        d.versioned(2, |d, v| {
            Ok(UsageAddOp {
                info: UsageInfo::decode(d)?,
                user: if v >= 2 {
                    norm_user(&Vec::<u8>::decode(d)?)
                } else {
                    Vec::new()
                },
            })
        })
    }
}

/// `rgw_cls_usage_log_read_op` (2,1); wire order start, end, owner, iter, max, bucket (v2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UsageReadOp {
    pub start_epoch: u64,
    pub end_epoch: u64,
    pub owner: Vec<u8>,
    pub bucket: Vec<u8>,
    pub iter: Vec<u8>,
    pub max_entries: u32,
}
impl Encode for UsageReadOp {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> D<()> {
        e.versioned(2, 1, |e| {
            e.u64(self.start_epoch)?;
            e.u64(self.end_epoch)?;
            self.owner.encode(e)?;
            self.iter.encode(e)?;
            e.u32(self.max_entries)?;
            self.bucket.encode(e)
        })
    }
}
impl<'a> Decode<'a> for UsageReadOp {
    fn decode(d: &mut Decoder<'a>) -> D<Self> {
        d.versioned(2, |d, v| {
            let mut x = UsageReadOp {
                start_epoch: d.u64()?,
                end_epoch: d.u64()?,
                owner: Vec::<u8>::decode(d)?,
                iter: Vec::<u8>::decode(d)?,
                max_entries: d.u32()?,
                ..Default::default()
            };
            if v >= 2 {
                x.bucket = Vec::<u8>::decode(d)?;
            }
            Ok(x)
        })
    }
}

env_struct!(
    /// `rgw_user_bucket` (1,1); ordered (user, bucket).
    #[derive(PartialOrd, Ord)]
    UserBucket (1, 1) { user: Vec<u8>, bucket: Vec<u8> });
env_struct!(
    /// `rgw_cls_usage_log_read_ret` (1,1)
    UsageReadRet (1, 1) { usage: BTreeMap<UserBucket, UsageEntry>, truncated: bool, next_iter: Vec<u8> });

/// `rgw_cls_usage_log_trim_op` (3,2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UsageTrimOp {
    pub start_epoch: u64,
    pub end_epoch: u64,
    pub user: Vec<u8>,
    pub bucket: Vec<u8>,
}
impl Encode for UsageTrimOp {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> D<()> {
        e.versioned(3, 2, |e| {
            e.u64(self.start_epoch)?;
            e.u64(self.end_epoch)?;
            self.user.encode(e)?;
            self.bucket.encode(e)
        })
    }
}
impl<'a> Decode<'a> for UsageTrimOp {
    fn decode(d: &mut Decoder<'a>) -> D<Self> {
        d.versioned(3, |d, v| {
            let mut x = UsageTrimOp {
                start_epoch: d.u64()?,
                end_epoch: d.u64()?,
                user: Vec::<u8>::decode(d)?,
                ..Default::default()
            };
            if v >= 3 {
                x.bucket = Vec::<u8>::decode(d)?;
            }
            Ok(x)
        })
    }
}

// ---------------------------------------------------------------- keys

fn by_time_prefix(epoch: u64) -> Vec<u8> {
    format!("{epoch:011}").into_bytes()
}
fn by_user_prefix_old(user: &[u8], epoch: u64) -> Vec<u8> {
    cat(&[user, format!("_{epoch:011}_").as_bytes()])
}
fn tilde(user: &[u8], mut k: Vec<u8>) -> Vec<u8> {
    if user.starts_with(b"0") {
        k.insert(0, b'~');
    }
    k
}
fn by_user_prefix(user: &[u8], epoch: u64) -> Vec<u8> {
    tilde(user, by_user_prefix_old(user, epoch))
}
fn name_by_time(epoch: u64, user: &[u8], bucket: &[u8]) -> Vec<u8> {
    cat(&[format!("{epoch:011}_").as_bytes(), user, b"_", bucket])
}
fn name_by_user_old(user: &[u8], epoch: u64, bucket: &[u8]) -> Vec<u8> {
    cat(&[user, format!("_{epoch:011}_").as_bytes(), bucket])
}
fn name_by_user(user: &[u8], epoch: u64, bucket: &[u8]) -> Vec<u8> {
    tilde(user, name_by_user_old(user, epoch, bucket))
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn decode_record(b: &[u8]) -> Result<UsageEntry, Errno> {
    UsageEntry::decode(&mut Decoder::new(b)).inval()
}

// ---------------------------------------------------------------- add

/// `user_usage_log_add` (RW): per entry aggregate with the committed record (a second entry of
/// the same key in one call does not see the first) and write both key copies.
pub fn user_usage_log_add<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: UsageAddOp = dec_op(input)?;
    let transition = c.config().rgw_usage_log_key_transition;
    for mut entry in op.info.entries {
        let puser = entry.puser().to_vec();
        let k_time = name_by_time(entry.epoch, &puser, &entry.bucket);
        match c.omap_get_val(&k_time) {
            Ok(b) => entry.aggregate(&decode_record(&b)?),
            Err(ENOENT) => {}
            Err(_) => return Err(EINVAL),
        }
        let v = enc(&entry)?;
        c.omap_set(&[(&k_time, &v)])?;
        c.omap_set(&[(&name_by_user(&puser, entry.epoch, &entry.bucket), &v)])?;
        if transition && puser.starts_with(b"0") {
            let _ = c.omap_remove_key(&name_by_user_old(&puser, entry.epoch, &entry.bucket));
        }
    }
    Ok(Vec::new())
}

// ---------------------------------------------------------------- range iteration

struct Range<'a> {
    start_epoch: u64,
    end_epoch: u64,
    bucket: &'a [u8],
}

/// `usage_handle_range`: one omap page from `start_key`; applies the by-time end key or the
/// by-user key prefix, the bucket/epoch filters and calls `cb` for each match. `key_iter` follows
/// the last visited key; `truncated` = more keys remain (cleared when a stop condition hits).
#[expect(clippy::too_many_arguments)]
fn handle_range<C: ClsCtx>(
    c: &mut C,
    r: &Range<'_>,
    start_key: &[u8],
    end_key: &[u8],
    user_key: &[u8],
    key_iter: &mut Vec<u8>,
    max: u32,
    truncated: &mut bool,
    cb: &mut impl FnMut(&mut C, &[u8], &UsageEntry) -> Result<(), Errno>,
) -> Result<u32, Errno> {
    let (logs, more) = c.omap_get_vals(start_key, b"", max as u64)?;
    *truncated = more;
    let by_user = !user_key.is_empty();
    let mut cnt = 0;
    for (key, v) in logs {
        *key_iter = key.clone();
        if !by_user && key.as_slice() >= end_key {
            *truncated = false;
            break;
        }
        if by_user && !key.starts_with(user_key) {
            *truncated = false;
            break;
        }
        let e = decode_record(&v)?;
        if !r.bucket.is_empty() && r.bucket != e.bucket.as_slice() {
            continue;
        }
        if e.epoch < r.start_epoch {
            continue;
        }
        if e.epoch >= r.end_epoch {
            *truncated = false; // keys are time ordered: past the window
            break;
        }
        cb(c, &key, &e)?;
        cnt += 1;
    }
    Ok(cnt)
}

/// `usage_iterate_range_by_user` incl. the key-transition double pass for users starting with '0'.
fn iterate_by_user<C: ClsCtx>(
    c: &mut C,
    r: &Range<'_>,
    user: &[u8],
    key_iter: &mut Vec<u8>,
    mut max: u32,
    truncated: &mut bool,
    cb: &mut impl FnMut(&mut C, &[u8], &UsageEntry) -> Result<(), Errno>,
) -> Result<u32, Errno> {
    let transition = c.config().rgw_usage_log_key_transition;
    if transition && user.starts_with(b"0") && (key_iter.is_empty() || key_iter.starts_with(b"0")) {
        // old (un-prefixed) keys first, then the new ones
        let user_key = cat(&[user, b"_"]);
        let start = if key_iter.is_empty() {
            by_user_prefix_old(user, r.start_epoch)
        } else {
            key_iter.clone()
        };
        let mut old_iter = key_iter.clone();
        let n = handle_range(
            c,
            r,
            &start,
            b"",
            &user_key,
            &mut old_iter,
            max,
            truncated,
            cb,
        )?;
        if *truncated {
            *key_iter = old_iter;
            return Ok(0);
        }
        key_iter.clear(); // old keys done: start fresh on the new ones
        max -= n;
    }
    if max > 0 {
        let user_key = if user.starts_with(b"0") {
            cat(&[b"~", user, b"_"])
        } else {
            cat(&[user, b"_"])
        };
        let start = if key_iter.is_empty() {
            by_user_prefix(user, r.start_epoch)
        } else {
            key_iter.clone()
        };
        return handle_range(c, r, &start, b"", &user_key, key_iter, max, truncated, cb);
    }
    Ok(0)
}

fn iterate_range<C: ClsCtx>(
    c: &mut C,
    r: &Range<'_>,
    user: &[u8],
    key_iter: &mut Vec<u8>,
    max: u32,
    truncated: &mut bool,
    cb: &mut impl FnMut(&mut C, &[u8], &UsageEntry) -> Result<(), Errno>,
) -> Result<u32, Errno> {
    if user.is_empty() {
        let end = by_time_prefix(r.end_epoch);
        let start = if key_iter.is_empty() {
            by_time_prefix(r.start_epoch)
        } else {
            key_iter.clone()
        };
        handle_range(c, r, &start, &end, b"", key_iter, max, truncated, cb)
    } else {
        iterate_by_user(c, r, user, key_iter, max, truncated, cb)
    }
}

// ---------------------------------------------------------------- read / trim / clear

/// `user_usage_log_read` (RD): aggregate matching records per (user, bucket). `max_entries` 0 =
/// 1000. When truncated `next_iter` is the last visited key.
pub fn user_usage_log_read<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: UsageReadOp = dec_op(input)?;
    let mut iter = op.iter.clone();
    let max = if op.max_entries != 0 {
        op.max_entries
    } else {
        READ_MAX
    };
    let r = Range {
        start_epoch: op.start_epoch,
        end_epoch: op.end_epoch,
        bucket: op.bucket.as_slice(),
    };
    let mut ret = UsageReadRet::default();
    let mut truncated = false;
    iterate_range(
        c,
        &r,
        &op.owner,
        &mut iter,
        max,
        &mut truncated,
        &mut |_, _, e| {
            let ub = UserBucket {
                user: e.puser().to_vec(),
                bucket: e.bucket.clone(),
            };
            ret.usage.entry(ub).or_default().aggregate(e);
            Ok(())
        },
    )?;
    ret.truncated = truncated;
    if truncated {
        ret.next_iter = iter;
    }
    enc(&ret)
}

/// `user_usage_log_trim` (RW): remove matching records (both/all key copies), up to one page per
/// call. `ENODATA` when nothing matched and nothing more remains (client loop end). `ENOENT` for
/// an absent object. Filtered pages advance the scan until a match or the range end;
/// only an exhausted range may report `ENODATA`.
pub fn user_usage_log_trim<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    c.stat()?; // only continue if the object exists
    let op: UsageTrimOp = dec_op(input)?;
    let transition = c.config().rgw_usage_log_key_transition;
    let r = Range {
        start_epoch: op.start_epoch,
        end_epoch: op.end_epoch,
        bucket: op.bucket.as_slice(),
    };
    let mut found = false;
    let mut iter = Vec::new();
    loop {
        let mut more = false;
        iterate_range(
            c,
            &r,
            &op.user,
            &mut iter,
            TRIM_PAGE,
            &mut more,
            &mut |c, _, e| {
                found = true;
                let o = e.puser();
                c.omap_remove_key(&name_by_time(e.epoch, o, &e.bucket))?;
                if transition && o.starts_with(b"0") {
                    let _ = c.omap_remove_key(&name_by_user_old(o, e.epoch, &e.bucket));
                }
                c.omap_remove_key(&name_by_user(o, e.epoch, &e.bucket))
            },
        )?;
        if found {
            return Ok(());
        }
        if !more {
            return Err(ENODATA);
        }
    }
}

/// `usage_log_clear` (WR): drop every record; an absent object counts as cleared.
pub fn usage_log_clear<C: ClsCtx>(c: &mut C, _input: &[u8]) -> R {
    match c.omap_clear() {
        Ok(()) | Err(ENOENT) => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}
