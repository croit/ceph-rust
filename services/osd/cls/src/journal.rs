// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Class `journal` (spec/cls_journal.md): RBD journal header omap + data-object append guards.

use crate::ctx::ClsCtx;
use crate::env_struct;
use crate::errno::*;
use denc::{Decode, Decoder, Encode, Encoder};
use std::collections::BTreeMap;

const CLIENT_PREFIX: &[u8] = b"client_";
const TAG_PREFIX: &[u8] = b"tag_";
const K_ORDER: &[u8] = b"order";
const K_SPLAY: &[u8] = b"splay_width";
const K_POOL: &[u8] = b"pool_id";
const K_MIN_SET: &[u8] = b"minimum_set";
const K_ACTIVE_SET: &[u8] = b"active_set";
const K_NEXT_TID: &[u8] = b"next_tag_tid";
const K_NEXT_CLASS: &[u8] = b"next_tag_class";
/// Page size for scans inside the class.
const PAGE: u64 = 64;
/// `JOURNAL_MAX_RETURN`.
const MAX_RETURN: u64 = 256;
pub const TAG_CLASS_NEW: u64 = u64::MAX;
const STATE_DISCONNECTED: u8 = 1;

env_struct!(ObjectPosition (1, 1) { object_number: u64, tag_tid: u64, entry_tid: u64 });
env_struct!(ObjectSetPosition (1, 1) { object_positions: Vec<ObjectPosition> });
env_struct!(Client (1, 1) { id: Vec<u8>, data: Vec<u8>, commit_position: ObjectSetPosition, state: u8 });
env_struct!(Tag (1, 1) { tid: u64, tag_class: u64, data: Vec<u8> });

type Page = BTreeMap<Vec<u8>, Vec<u8>>;

fn client_key(id: &[u8]) -> Vec<u8> {
    [CLIENT_PREFIX, id].concat()
}
fn tag_key(tid: u64) -> Vec<u8> {
    format!("tag_{tid:016x}").into_bytes()
}
/// `None` if the hex part is malformed.
fn tid_from_key(key: &[u8]) -> Option<u64> {
    let h = key.get(TAG_PREFIX.len()..)?;
    if h.is_empty() || !h.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    u64::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok()
}

/// Stored value read: absent -> -ENOENT, undecodable -> -EINVAL.
fn read_key<C: ClsCtx, T: for<'a> Decode<'a>>(c: &mut C, key: &[u8]) -> Result<T, Errno> {
    let b = c.omap_get_val(key)?;
    T::decode(&mut Decoder::new(&b)).inval()
}
fn write_key<C: ClsCtx, T: Encode>(c: &mut C, key: &[u8], v: &T) -> Result<(), Errno> {
    c.omap_set(&[(key, &enc(v)?)])
}
fn exists<C: ClsCtx>(c: &mut C, key: &[u8]) -> Result<bool, Errno> {
    match c.omap_get_val(key) {
        Ok(_) => Ok(true),
        Err(ENOENT) => Ok(false),
        Err(e) => Err(e),
    }
}
fn vals<C: ClsCtx>(
    c: &mut C,
    after: &[u8],
    prefix: &[u8],
    max: u64,
) -> Result<(Page, bool), Errno> {
    match c.omap_get_vals(after, prefix, max) {
        Err(ENOENT) => Ok((Page::new(), false)),
        r => r,
    }
}
/// `u32 n` + elements.
fn enc_set<'a, T: Encode + 'a>(
    n: usize,
    items: impl Iterator<Item = &'a T>,
) -> Result<Vec<u8>, Errno> {
    let mut e = Encoder::new();
    e.count(n).eio()?;
    for t in items {
        t.encode(&mut e).eio()?;
    }
    Ok(e.into_vec())
}

/// Scan tags ascending in pages; `f` returns `Ok(false)` to stop. Undecodable tag -> -EIO.
fn scan_tags<C: ClsCtx>(
    c: &mut C,
    mut f: impl FnMut(&mut C, &[u8], Tag) -> Result<bool, Errno>,
) -> Result<(), Errno> {
    let mut last = TAG_PREFIX.to_vec();
    loop {
        let (page, more) = vals(c, &last, TAG_PREFIX, PAGE)?;
        for (k, v) in &page {
            let tag = Tag::decode(&mut Decoder::new(v)).eio()?;
            if !f(c, k, tag)? {
                return Ok(());
            }
        }
        match page.keys().next_back() {
            Some(k) if more => last = k.clone(),
            _ => return Ok(()),
        }
    }
}

fn check_tid(key: &[u8], tag: &Tag) -> Result<(), Errno> {
    if tid_from_key(key) == Some(tag.tid) {
        Ok(())
    } else {
        Err(EINVAL)
    }
}

/// Prune tags superseded in every connected client's commit history (spec s4 expire_tags).
fn expire_tags<C: ClsCtx>(c: &mut C, skip: Option<&[u8]>) -> Result<(), Errno> {
    let skip_key = skip.map(client_key);
    let mut min_tid = u64::MAX;
    let mut last = Vec::new();
    loop {
        let (page, more) = vals(c, &last, CLIENT_PREFIX, PAGE)?;
        for (k, v) in &page {
            if Some(k) == skip_key.as_ref() {
                continue;
            }
            let cl = dec_stored::<Client>(v)?;
            if cl.state == STATE_DISCONNECTED {
                continue;
            }
            if cl.commit_position.object_positions.is_empty() {
                return Ok(());
            }
            for p in &cl.commit_position.object_positions {
                min_tid = min_tid.min(p.tag_tid);
            }
        }
        match page.keys().next_back() {
            Some(k) if more => last = k.clone(),
            _ => break,
        }
    }
    if min_tid == u64::MAX {
        return Ok(());
    }
    let mut class_min: BTreeMap<u64, u64> = BTreeMap::new();
    scan_tags(c, |_, k, t| {
        check_tid(k, &t)?;
        class_min.insert(t.tag_class, t.tid);
        Ok(t.tid < min_tid)
    })?;
    scan_tags(c, |c, k, t| {
        check_tid(k, &t)?;
        if t.tid < class_min.get(&t.tag_class).copied().unwrap_or(0) {
            match c.omap_remove_key(k) {
                Ok(()) | Err(ENOENT) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(t.tid < min_tid)
    })
}

fn client_range<C: ClsCtx>(
    c: &mut C,
    last_read: &[u8],
    max: u64,
) -> Result<Vec<(Vec<u8>, Client)>, Errno> {
    let (page, _) = vals(c, last_read, CLIENT_PREFIX, max)?;
    page.into_iter()
        .map(|(k, v)| Ok((k, dec_stored::<Client>(&v)?)))
        .collect()
}

/// Minimum commit position over connected clients (bug-compatible, spec s4 client_register).
fn find_min_commit_position<C: ClsCtx>(c: &mut C) -> Result<ObjectSetPosition, Errno> {
    let mut best = ObjectSetPosition::default();
    let mut valid = false;
    let (mut tag_tid, mut entry_tid) = (0u64, 0u64);
    let mut last = Vec::new();
    loop {
        let batch = client_range(c, &last, MAX_RETURN)?;
        let Some((lk, _)) = batch.last() else { break };
        last = lk.clone();
        let n = batch.len() as u64;
        for (_, cl) in &batch {
            if cl.state == STATE_DISCONNECTED {
                continue;
            }
            let Some(first) = cl.commit_position.object_positions.first() else {
                best = ObjectSetPosition::default();
                break;
            };
            if !valid || (tag_tid, entry_tid) > (first.tag_tid, first.entry_tid) {
                tag_tid = first.tag_tid;
                entry_tid = first.entry_tid;
                best = cl.commit_position.clone();
                valid = true;
            }
        }
        if n < MAX_RETURN {
            break;
        }
    }
    Ok(best)
}

pub fn create<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let d = &mut Decoder::new(input);
    let order: u8 = Decode::decode(d).inval()?;
    let splay: u8 = Decode::decode(d).inval()?;
    let pool: i64 = Decode::decode(d).inval()?;
    if exists(c, K_ORDER)? {
        return Err(EEXIST);
    }
    write_key(c, K_ORDER, &order)?;
    write_key(c, K_SPLAY, &splay)?;
    write_key(c, K_POOL, &pool)?;
    for k in [K_ACTIVE_SET, K_MIN_SET, K_NEXT_TID, K_NEXT_CLASS] {
        write_key(c, k, &0u64)?;
    }
    Ok(())
}

fn getter<C: ClsCtx, T: Encode + for<'a> Decode<'a>>(
    c: &mut C,
    k: &[u8],
) -> Result<Vec<u8>, Errno> {
    let v: T = read_key(c, k)?;
    enc(&v)
}
pub fn get_order<C: ClsCtx>(c: &mut C, _: &[u8]) -> Result<Vec<u8>, Errno> {
    getter::<C, u8>(c, K_ORDER)
}
pub fn get_splay_width<C: ClsCtx>(c: &mut C, _: &[u8]) -> Result<Vec<u8>, Errno> {
    getter::<C, u8>(c, K_SPLAY)
}
pub fn get_pool_id<C: ClsCtx>(c: &mut C, _: &[u8]) -> Result<Vec<u8>, Errno> {
    getter::<C, i64>(c, K_POOL)
}
pub fn get_minimum_set<C: ClsCtx>(c: &mut C, _: &[u8]) -> Result<Vec<u8>, Errno> {
    getter::<C, u64>(c, K_MIN_SET)
}
pub fn get_active_set<C: ClsCtx>(c: &mut C, _: &[u8]) -> Result<Vec<u8>, Errno> {
    getter::<C, u64>(c, K_ACTIVE_SET)
}
pub fn get_next_tag_tid<C: ClsCtx>(c: &mut C, _: &[u8]) -> Result<Vec<u8>, Errno> {
    getter::<C, u64>(c, K_NEXT_TID)
}

pub fn set_minimum_set<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let set: u64 = Decode::decode(&mut Decoder::new(input)).inval()?;
    let active: u64 = read_key(c, K_ACTIVE_SET)?;
    if active < set {
        return Err(EINVAL);
    }
    let min: u64 = read_key(c, K_MIN_SET)?;
    if set == min {
        return Ok(());
    }
    if set < min {
        return Err(ESTALE);
    }
    write_key(c, K_MIN_SET, &set)?;
    Ok(())
}

pub fn set_active_set<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let set: u64 = Decode::decode(&mut Decoder::new(input)).inval()?;
    let min: u64 = read_key(c, K_MIN_SET)?;
    if min > set {
        return Err(EINVAL);
    }
    let active: u64 = read_key(c, K_ACTIVE_SET)?;
    if set == active {
        return Ok(());
    }
    if set < active {
        return Err(ESTALE);
    }
    write_key(c, K_ACTIVE_SET, &set)?;
    Ok(())
}

pub fn get_client<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<Vec<u8>, Errno> {
    let id: Vec<u8> = Decode::decode(&mut Decoder::new(input)).inval()?;
    let cl: Client = read_key(c, &client_key(&id))?;
    enc(&cl)
}

pub fn client_register<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let d = &mut Decoder::new(input);
    let id: Vec<u8> = Decode::decode(d).inval()?;
    let data: Vec<u8> = Decode::decode(d).inval()?;
    let _: u8 = read_key(c, K_ORDER)?;
    let key = client_key(&id);
    if exists(c, &key)? {
        return Err(EEXIST);
    }
    let commit_position = find_min_commit_position(c)?;
    let cl = Client {
        id,
        data,
        commit_position,
        state: 0,
    };
    write_key(c, &key, &cl)?;
    Ok(())
}

pub fn client_update_data<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let d = &mut Decoder::new(input);
    let id: Vec<u8> = Decode::decode(d).inval()?;
    let data: Vec<u8> = Decode::decode(d).inval()?;
    let key = client_key(&id);
    let mut cl: Client = read_key(c, &key)?;
    cl.data = data;
    write_key(c, &key, &cl)?;
    Ok(())
}

pub fn client_update_state<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let d = &mut Decoder::new(input);
    let id: Vec<u8> = Decode::decode(d).inval()?;
    let state: u8 = Decode::decode(d).inval()?;
    let key = client_key(&id);
    let mut cl: Client = read_key(c, &key)?;
    cl.state = state;
    write_key(c, &key, &cl)?;
    Ok(())
}

pub fn client_unregister<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let id: Vec<u8> = Decode::decode(&mut Decoder::new(input)).inval()?;
    let key = client_key(&id);
    c.omap_get_val(&key)?;
    c.omap_remove_key(&key)?;
    expire_tags(c, Some(&id))?;
    Ok(())
}

pub fn client_commit<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let d = &mut Decoder::new(input);
    let id: Vec<u8> = Decode::decode(d).inval()?;
    let pos: ObjectSetPosition = Decode::decode(d).inval()?;
    let splay: u8 = read_key(c, K_SPLAY)?;
    if pos.object_positions.len() > splay as usize {
        return Err(EINVAL);
    }
    let key = client_key(&id);
    let mut cl: Client = read_key(c, &key)?;
    if cl.commit_position == pos {
        return Ok(());
    }
    cl.commit_position = pos;
    write_key(c, &key, &cl)?;
    Ok(())
}

pub fn client_list<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<Vec<u8>, Errno> {
    let d = &mut Decoder::new(input);
    let start: Vec<u8> = Decode::decode(d).inval()?;
    let max: u64 = Decode::decode(d).inval()?;
    let last = if start.is_empty() {
        Vec::new()
    } else {
        client_key(&start)
    };
    let clients = client_range(c, &last, max)?;
    enc_set(clients.len(), clients.iter().map(|(_, cl)| cl))
}

pub fn get_tag<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<Vec<u8>, Errno> {
    let tid: u64 = Decode::decode(&mut Decoder::new(input)).inval()?;
    let t: Tag = read_key(c, &tag_key(tid))?;
    enc(&t)
}

pub fn tag_create<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let d = &mut Decoder::new(input);
    let tid: u64 = Decode::decode(d).inval()?;
    let mut class: u64 = Decode::decode(d).inval()?;
    let data: Vec<u8> = Decode::decode(d).inval()?;
    let key = tag_key(tid);
    if exists(c, &key)? {
        return Err(EEXIST);
    }
    let next: u64 = read_key(c, K_NEXT_TID)?;
    if tid != next {
        return Err(ESTALE);
    }
    let next_class: u64 = read_key(c, K_NEXT_CLASS)?;
    if class == TAG_CLASS_NEW {
        class = next_class;
        write_key(c, K_NEXT_CLASS, &class.wrapping_add(1))?;
    } else if class >= next_class {
        return Err(EINVAL);
    }
    expire_tags(c, None)?;
    write_key(c, K_NEXT_TID, &tid.wrapping_add(1))?;
    let tag = Tag {
        tid,
        tag_class: class,
        data,
    };
    write_key(c, &key, &tag)?;
    Ok(())
}

pub fn tag_list<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<Vec<u8>, Errno> {
    let d = &mut Decoder::new(input);
    let start_after: u64 = Decode::decode(d).inval()?;
    let max: u64 = Decode::decode(d).inval()?;
    let client_id: Vec<u8> = Decode::decode(d).inval()?;
    let filter: Option<u64> = Decode::decode(d).inval()?;
    let cl: Client = read_key(c, &client_key(&client_id))?;
    let min_tid = cl
        .commit_position
        .object_positions
        .iter()
        .map(|p| p.tag_tid)
        .min()
        .unwrap_or(u64::MAX);
    let mut class_min: BTreeMap<u64, u64> = BTreeMap::new();
    if min_tid != u64::MAX {
        scan_tags(c, |_, _, t| {
            class_min.insert(t.tag_class, t.tid);
            Ok(t.tid < min_tid)
        })?;
    }
    let mut out: BTreeMap<u64, Tag> = BTreeMap::new();
    scan_tags(c, |_, _, t| {
        if start_after != 0 && t.tid <= start_after {
            return Ok(true);
        }
        if t.tid >= class_min.get(&t.tag_class).copied().unwrap_or(0)
            && filter.is_none_or(|f| f == t.tag_class)
        {
            out.insert(t.tid, t);
        }
        Ok((out.len() as u64) < max)
    })?;
    enc_set(out.len(), out.values())
}

fn stat_size<C: ClsCtx>(c: &mut C) -> Result<u64, Errno> {
    match c.stat() {
        Ok(s) => Ok(s.size),
        Err(ENOENT) => Ok(0),
        Err(e) => Err(e),
    }
}

pub fn guard_append<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<Vec<u8>, Errno> {
    let max: u64 = Decode::decode(&mut Decoder::new(input)).inval()?;
    match c.stat() {
        Ok(s) if s.size >= max => Err(EOVERFLOW),
        Ok(_) | Err(ENOENT) => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

fn round_up(n: u64, a: u64) -> Result<u64, Errno> {
    match n % a {
        0 => Ok(n),
        r => n.checked_add(a - r).ok_or(EOVERFLOW),
    }
}

pub fn append<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let d = &mut Decoder::new(input);
    let max: u64 = Decode::decode(d).inval()?;
    let data: Vec<u8> = Decode::decode(d).inval()?;
    let size = stat_size(c)?;
    if size >= max {
        return Err(EOVERFLOW);
    }
    c.write(size, &data)?;
    let cfg = c.config();
    if !cfg.journal_pad {
        return Ok(());
    }
    let mut align = if cfg.journal_min_alloc == 0 {
        8
    } else {
        cfg.journal_min_alloc
    };
    if cfg.pool_stripe_width > 0 {
        align = round_up(align, cfg.pool_stripe_width)?;
    }
    let end = size.checked_add(data.len() as u64).ok_or(EOVERFLOW)?;
    let new_end = round_up(end, align)?;
    if new_end != end {
        c.truncate(new_end)?;
    }
    Ok(())
}
