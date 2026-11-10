// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Class `lock` (spec/cls_lock.md): advisory object locks stored in xattr `lock.<name>`.

use crate::ctx::ClsCtx;
use crate::env_struct;
use crate::errno::*;
use denc::types::{EntityAddr, EntityName, UTime};
use denc::{BufMut, Decode, Decoder, Encode, Encoder};
use std::collections::BTreeMap;

pub const LOCK_NONE: u8 = 0;
pub const LOCK_EXCLUSIVE: u8 = 1;
pub const LOCK_SHARED: u8 = 2;
pub const LOCK_EXCLUSIVE_EPHEMERAL: u8 = 3;
pub const FLAG_MAY_RENEW: u8 = 1;
pub const FLAG_MUST_RENEW: u8 = 2;

const PREFIX: &[u8] = b"lock.";

/// `rados::cls::lock::locker_id_t`: (locker entity, cookie). Ordered (type, num, cookie).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct LockerId {
    pub locker: EntityName,
    pub cookie: Vec<u8>,
}
impl Encode for LockerId {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(1, 1, |e| {
            self.locker.encode(e)?;
            self.cookie.encode(e)
        })
    }
}
impl<'a> Decode<'a> for LockerId {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(1, |d, _| {
            Ok(LockerId {
                locker: EntityName::decode(d)?,
                cookie: <Vec<u8>>::decode(d)?,
            })
        })
    }
}

env_struct! {
    /// `locker_info_t` (featured: addr form follows MSG_ADDR2).
    LockerInfo (1, 1) {
        /// Absolute expiration; zero = never.
        expiration: UTime,
        addr: EntityAddr,
        description: Vec<u8>,
    }
}

env_struct! {
    /// `lock_info_t` (the stored xattr value) == `cls_lock_get_info_reply` body layout.
    LockInfo (1, 1) {
        lockers: BTreeMap<LockerId, LockerInfo>,
        lock_type: u8,
        tag: Vec<u8>,
    }
}

/// `cls_lock_get_info_reply`: same layout as [`LockInfo`].
pub type GetInfoReply = LockInfo;

macro_rules! op_struct {
    ($(#[$m:meta])* $name:ident { $($f:ident : $t:ty),* }) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Eq, Default)]
        pub struct $name { $(pub $f: $t),* }
        impl Encode for $name {
            fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
                e.versioned(1, 1, |e| { $(self.$f.encode(e)?;)* Ok(()) })
            }
        }
        impl<'a> Decode<'a> for $name {
            fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
                d.versioned(1, |d, _| Ok($name { $($f: <$t>::decode(d)?),* }))
            }
        }
    };
}
op_struct!(
    /// `cls_lock_lock_op`
    LockOp { name: Vec<u8>, ty: u8, cookie: Vec<u8>, tag: Vec<u8>, description: Vec<u8>, duration: UTime, flags: u8 });
op_struct!(UnlockOp {
    name: Vec<u8>,
    cookie: Vec<u8>
});
op_struct!(BreakOp {
    name: Vec<u8>,
    locker: EntityName,
    cookie: Vec<u8>
});
op_struct!(GetInfoOp { name: Vec<u8> });
op_struct!(ListLocksReply { locks: Vec<Vec<u8>> });
op_struct!(AssertOp {
    name: Vec<u8>,
    ty: u8,
    cookie: Vec<u8>,
    tag: Vec<u8>
});
op_struct!(SetCookieOp {
    name: Vec<u8>,
    ty: u8,
    cookie: Vec<u8>,
    tag: Vec<u8>,
    new_cookie: Vec<u8>
});

fn valid_type(t: u8) -> bool {
    (1..=3).contains(&t)
}
fn exclusive(t: u8) -> bool {
    t == LOCK_EXCLUSIVE || t == LOCK_EXCLUSIVE_EPHEMERAL
}

/// Xattr key of lock `name`; built once per method call.
fn lock_key(name: &[u8]) -> Vec<u8> {
    // Pinned class xattr API receives a C string; original-name validation is earlier.
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    let mut k = Vec::with_capacity(PREFIX.len() + end);
    k.extend_from_slice(PREFIX);
    k.extend_from_slice(&name[..end]);
    k
}

/// Shared helper (spec s4): load `lock.<name>`, dropping expired lockers from the view.
fn read_lock<C: ClsCtx>(c: &mut C, key: &[u8]) -> Result<LockInfo, Errno> {
    let mut info = match c.getxattr_raw(key) {
        Ok(v) => denc::from_slice::<LockInfo>(&v)
            .or_else(|_| {
                // trailing bytes tolerated like a bufferlist decode
                let mut d = Decoder::new(&v);
                LockInfo::decode(&mut d)
            })
            .eio()?,
        Err(ENODATA) => LockInfo::default(),
        Err(e) => return Err(e),
    };
    let now = c.now();
    info.lockers
        .retain(|_, l| l.expiration == UTime::default() || l.expiration >= now);
    if info.lockers.is_empty() && info.lock_type == LOCK_EXCLUSIVE_EPHEMERAL {
        // quirk kept bit-identical: the object goes away (EIO in an RD-only method via counters)
        c.remove()?;
    }
    Ok(info)
}

fn write_lock<C: ClsCtx>(c: &mut C, key: &[u8], info: &LockInfo) -> Result<(), Errno> {
    let v = info
        .encode_to_vec_with_features(c.client_features())
        .eio()?;
    c.setxattr_raw(key, &v)
}

fn caller_id<C: ClsCtx>(c: &C, cookie: &[u8]) -> LockerId {
    LockerId {
        locker: c.origin().name,
        cookie: cookie.to_owned(),
    }
}

/// `lock.lock`
pub fn lock<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: LockOp = dec_op(input)?;
    if !valid_type(op.ty) || op.name.is_empty() {
        return Err(EINVAL);
    }
    let may_renew = op.flags & FLAG_MAY_RENEW != 0;
    let must_renew = op.flags & FLAG_MUST_RENEW != 0;
    if may_renew && must_renew {
        return Err(EINVAL);
    }
    let key = lock_key(&op.name);
    let mut info = rd_opt(read_lock(c, &key))?.unwrap_or_default();
    let id = caller_id(c, &op.cookie);
    if !info.lockers.is_empty() && op.tag != info.tag {
        return Err(EBUSY);
    }
    if info.lockers.contains_key(&id) {
        if !may_renew && !must_renew {
            return Err(EEXIST);
        }
        info.lockers.remove(&id);
    } else if must_renew {
        return Err(ENOENT);
    }
    if !info.lockers.is_empty() && (exclusive(op.ty) || info.lock_type != op.ty) {
        return Err(EBUSY);
    }
    info.lock_type = op.ty;
    info.tag = op.tag;
    let expiration = if op.duration == UTime::default() {
        UTime::default()
    } else {
        UTime::saturating_add(c.now(), op.duration)
    };
    let mut addr = c.origin().addr;
    addr.ty = EntityAddr::TYPE_LEGACY;
    info.lockers.insert(
        id,
        LockerInfo {
            expiration,
            addr,
            description: op.description,
        },
    );
    write_lock(c, &key, &info)?;
    Ok(())
}

fn remove_locker<C: ClsCtx>(c: &mut C, name: &[u8], id: LockerId) -> Result<(), Errno> {
    let key = lock_key(name);
    let mut info = read_lock(c, &key)?;
    if info.lockers.remove(&id).is_none() {
        return Err(ENOENT);
    }
    if info.lock_type == LOCK_EXCLUSIVE_EPHEMERAL {
        c.remove()?;
    } else {
        write_lock(c, &key, &info)?;
    }
    Ok(())
}

/// `lock.unlock`
pub fn unlock<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: UnlockOp = dec_op(input)?;
    let id = caller_id(c, &op.cookie);
    remove_locker(c, &op.name, id)
}

/// `lock.break_lock`
pub fn break_lock<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: BreakOp = dec_op(input)?;
    let id = LockerId {
        locker: op.locker,
        cookie: op.cookie,
    };
    remove_locker(c, &op.name, id)
}

/// `lock.get_info`
pub fn get_info<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<Vec<u8>, Errno> {
    let op: GetInfoOp = dec_op(input)?;
    let info = read_lock(c, &lock_key(&op.name))?;
    enc_f(&info, c.client_features())
}

/// `lock.list_locks` (input ignored)
pub fn list_locks<C: ClsCtx>(c: &mut C, _input: &[u8]) -> Result<Vec<u8>, Errno> {
    let attrs = c.getxattrs_raw()?;
    let locks = attrs
        .keys()
        .filter_map(|k| k.strip_prefix(PREFIX).map(<[u8]>::to_vec))
        .collect();
    enc_f(&ListLocksReply { locks }, c.client_features())
}

/// `lock.assert_locked`
pub fn assert_locked<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: AssertOp = dec_op(input)?;
    if !valid_type(op.ty) || op.name.is_empty() {
        return Err(EINVAL);
    }
    let info = read_lock(c, &lock_key(&op.name))?;
    let id = caller_id(c, &op.cookie);
    if info.lockers.is_empty()
        || info.lock_type != op.ty
        || info.tag != op.tag
        || !info.lockers.contains_key(&id)
    {
        return Err(EBUSY);
    }
    Ok(())
}

/// `lock.set_cookie`
pub fn set_cookie<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: SetCookieOp = dec_op(input)?;
    if !valid_type(op.ty) || op.name.is_empty() {
        return Err(EINVAL);
    }
    let key = lock_key(&op.name);
    let mut info = read_lock(c, &key)?;
    let id = caller_id(c, &op.cookie);
    let new_id = caller_id(c, &op.new_cookie);
    if info.lockers.is_empty()
        || info.lock_type != op.ty
        || info.tag != op.tag
        || !info.lockers.contains_key(&id)
        || info.lockers.contains_key(&new_id)
    {
        return Err(EBUSY);
    }
    let Some(l) = info.lockers.remove(&id) else {
        return Err(EBUSY);
    };
    info.lockers.insert(new_id, l);
    write_lock(c, &key, &info)?;
    Ok(())
}
