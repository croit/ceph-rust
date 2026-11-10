// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Class `sem_set` (spec/cls_sem_set.md): counting semaphores stored as omap keys.

use crate::ctx::ClsCtx;
use crate::env_struct;
use crate::errno::*;
use denc::types::{Timespan, UTime};
use denc::{BufMut, Decode, Decoder, Encode, Encoder};
use std::collections::{BTreeMap, BTreeSet};

pub const PREFIX: &[u8] = b"CLS_SEM_SET_";
pub const MAX_KEYS: usize = 1000;

env_struct!(Increment (1, 1) { keys: BTreeSet<Vec<u8>> });
env_struct!(Decrement (1, 1) { keys: BTreeSet<Vec<u8>>, grace: Timespan });
env_struct!(Reset (1, 1) { keys: BTreeMap<Vec<u8>, u64> });
env_struct!(ListOp (1, 1) { count: u64, cursor: Vec<u8> });
env_struct!(ListRet (1, 1) { kvs: BTreeMap<Vec<u8>, u64>, cursor: Vec<u8> });

/// Stored value (1,1): counter + time of the last decrement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SemVal {
    pub value: u64,
    pub last_decrement: UTime,
}
impl Encode for SemVal {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> denc::Result<()> {
        e.versioned(1, 1, |e| {
            e.u64(self.value)?;
            self.last_decrement.encode(e)
        })
    }
}
impl<'a> Decode<'a> for SemVal {
    fn decode(d: &mut Decoder<'a>) -> denc::Result<Self> {
        d.versioned(1, |d, _| {
            Ok(SemVal {
                value: d.u64()?,
                last_decrement: UTime::decode(d)?,
            })
        })
    }
}

fn full_key(k: &[u8]) -> Vec<u8> {
    [PREFIX, k].concat()
}
fn read_val<C: ClsCtx>(c: &mut C, key: &[u8]) -> Result<SemVal, Errno> {
    let b = c.omap_get_val(key)?;
    SemVal::decode(&mut Decoder::new(&b)).eio()
}
fn write_val<C: ClsCtx>(c: &mut C, key: &[u8], v: &SemVal) -> Result<(), Errno> {
    c.omap_set(&[(key, &v.encode_to_vec().eio()?)])
}
fn check_count(n: usize) -> Result<(), Errno> {
    if n > MAX_KEYS { Err(E2BIG) } else { Ok(()) }
}

pub fn increment<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<Vec<u8>, Errno> {
    let op: Increment = dec_op(input)?;
    check_count(op.keys.len())?;
    for k in &op.keys {
        let key = full_key(k);
        let mut v = match read_val(c, &key) {
            Ok(v) => v,
            Err(ENOENT) => SemVal::default(),
            Err(e) => return Err(e),
        };
        v.value = v.value.wrapping_add(1);
        write_val(c, &key, &v)?;
    }
    Ok(Vec::new())
}

pub fn reset<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: Reset = dec_op(input)?;
    check_count(op.keys.len())?;
    for (k, value) in &op.keys {
        let v = SemVal {
            value: *value,
            last_decrement: UTime::default(),
        };
        write_val(c, &full_key(k), &v)?;
    }
    Ok(())
}

pub fn decrement<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: Decrement = dec_op(input)?;
    check_count(op.keys.len())?;
    let now = c.now();
    let now_ns = now.as_nanos();
    // chrono: seconds + nanoseconds computed signed, stored into an unsigned span (wraps)
    let grace = (op.grace.sec as i64 * 1_000_000_000 + op.grace.nsec as i64) as u64;
    for k in &op.keys {
        let key = full_key(k);
        let mut v = read_val(c, &key)?;
        let last = v.last_decrement.as_nanos();
        if now_ns < last || now_ns - last < grace {
            continue;
        }
        if v.value > 1 {
            v.value -= 1;
            v.last_decrement = now;
            write_val(c, &key, &v)?;
        } else {
            c.omap_remove_key(&key)?;
        }
    }
    Ok(())
}

pub fn list<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<Vec<u8>, Errno> {
    let op: ListOp = dec_op(input)?;
    let mut count = op.count;
    let mut ret = ListRet {
        kvs: BTreeMap::new(),
        cursor: op.cursor,
    };
    while count > 0 {
        let start = [PREFIX, ret.cursor.as_slice(), &[1u8]].concat();
        let (vals, more) = c.omap_get_vals(&start, PREFIX, count)?;
        count = count.saturating_sub(vals.len() as u64);
        if let Some((last, _)) = vals.iter().next_back() {
            ret.cursor = last.strip_prefix(PREFIX).unwrap_or_default().to_vec();
        }
        for (k, b) in &vals {
            let v = SemVal::decode(&mut Decoder::new(b)).eio()?;
            ret.kvs
                .entry(k.strip_prefix(PREFIX).unwrap_or_default().to_vec())
                .or_insert(v.value);
        }
        if !more {
            ret.cursor.clear();
            break;
        }
        if vals.is_empty() {
            break; // defensive: `more` without progress
        }
    }
    ret.encode_to_vec().eio()
}
