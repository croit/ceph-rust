// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! SnapMapper on the NVMe store (spec snaptrim.md 4, adr 0037): one object of the PG collection holds the index as
//! omap keys (layout in `peering::snaps`). The object is pgmeta-like (empty name, snapid SNAPDIR): never listed,
//! counted, scrubbed, backfilled or split with the user objects; it is deleted with the PG, copied by core migration
//! and carved up by split / merge ([`split`](crate::split)).

use crate::{StoreAdapter, gh, key_after, pg_coll};
use denc::types::{Ghobject, Hobject, SnapId, SpgT};
use peering::snaps::{self, MapKv, MapOp};
use peering::store::StoreReadError;
use std::collections::HashMap;
use store::dev::{BlockDev, Clock};
use store::obj::txn::Bytes as TxnBytes;
use store::obj::{OTxn, ObjError, TOp};

/// The mapper object of a PG.
pub fn mapper_obj(spg: SpgT) -> Ghobject {
    Ghobject::new(
        Hobject::new(
            b"",
            SnapId::SNAPDIR,
            spg.pgid.seed,
            spg.pgid.pool as i64,
            b"",
        ),
        Ghobject::NO_GEN,
        spg.shard,
    )
}

/// Keys written / deleted by the ops of one `StoreTxn`, so later ops of the same txn see earlier ones.
#[derive(Default)]
pub(crate) struct Overlay(HashMap<Vec<u8>, Option<Vec<u8>>>);

/// [`MapKv`] over the store + the txn's overlay; collects the changes of one op.
struct TxnKv<'a, D: BlockDev, C: Clock> {
    st: &'a mut store::obj::Store<D, C>,
    spg: SpgT,
    ov: &'a mut Overlay,
    puts: Vec<(Vec<u8>, Vec<u8>)>,
    dels: Vec<Vec<u8>>,
}

impl<D: BlockDev, C: Clock> MapKv for TxnKv<'_, D, C> {
    type Err = ObjError;
    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, ObjError> {
        if let Some(v) = self.ov.0.get(key) {
            return Ok(v.clone());
        }
        match self
            .st
            .omap_get(&pg_coll(self.spg), &mapper_obj(self.spg), &[key])
        {
            Ok(mut m) => Ok(m.remove(key)),
            Err(ObjError::NoEnt | ObjError::NoColl) => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn put(&mut self, key: Vec<u8>, val: Vec<u8>) {
        self.ov.0.insert(key.clone(), Some(val.clone()));
        self.puts.push((key, val));
    }
    fn del(&mut self, key: Vec<u8>) {
        self.ov.0.insert(key.clone(), None);
        self.dels.push(key);
    }
}

/// Append the store ops of one mapper mutation to `out`.
pub(crate) fn apply_op<'a, D: BlockDev, C: Clock>(
    st: &mut store::obj::Store<D, C>,
    spg: SpgT,
    ov: &mut Overlay,
    op: &MapOp,
    out: &mut OTxn<'a>,
) -> Result<(), ObjError> {
    let mut kv = TxnKv {
        st,
        spg,
        ov,
        puts: Vec::new(),
        dels: Vec::new(),
    };
    snaps::apply(&mut kv, op)?;
    let (puts, dels) = (kv.puts, kv.dels);
    let (cid, oid) = (pg_coll(spg), mapper_obj(spg));
    if !dels.is_empty() {
        out.push(TOp::OmapRmKeys {
            cid,
            oid: oid.clone(),
            keys: dels.into_iter().map(TxnBytes::Owned).collect(),
        });
    }
    if !puts.is_empty() {
        out.push(TOp::OmapSetKeys {
            cid,
            oid,
            pairs: puts
                .into_iter()
                .map(|(k, v)| (TxnBytes::Owned(k), TxnBytes::Owned(v)))
                .collect(),
        });
    }
    Ok(())
}

impl<D: BlockDev, C: Clock> StoreAdapter<D, C> {
    fn map_get(&self, spg: SpgT, key: &[u8]) -> Result<Option<Vec<u8>>, ObjError> {
        match self
            .st
            .borrow_mut()
            .omap_get(&pg_coll(spg), &mapper_obj(spg), &[key])
        {
            Ok(mut m) => Ok(m.remove(key)),
            Err(ObjError::NoEnt | ObjError::NoColl) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// [`peering::PgStoreOps::snapmap_scan`]: one omap read of up to `max` forward entries from `from`.
    pub fn map_scan(
        &self,
        spg: SpgT,
        from: &[u8],
        max: usize,
    ) -> Result<(Vec<u64>, Option<Vec<u8>>), StoreReadError> {
        let r = self.st.borrow_mut().omap_iter(
            &pg_coll(spg),
            &mapper_obj(spg),
            from,
            max.max(1).saturating_add(1),
        );
        let (kv, _) = match r {
            Ok(x) => x,
            Err(ObjError::NoEnt | ObjError::NoColl) => return Ok((Vec::new(), None)),
            Err(e) => {
                self.note_damage(format!("pg {spg}: snap mapper scan: {e}"));
                return Err(StoreReadError::Io);
            }
        };
        let fwd = |k: &Vec<u8>| k.first() == Some(&snaps::K_FWD);
        let mut snaps_out = Vec::new();
        for (k, _) in kv.iter().take(max.max(1)).take_while(|(k, _)| fwd(k)) {
            snaps_out.push(snaps::fwd_snap(k));
        }
        let next = kv
            .get(snaps_out.len())
            .filter(|(k, _)| fwd(k))
            .map(|(k, _)| k.clone());
        Ok((snaps_out, next))
    }

    /// Up to `max` clones mapped to `snap`. `Ok(empty)` = the index has no clone of `snap` (an absent mapper object
    /// counts as empty); an unreadable store or an undecodable entry is `Err` (never "empty": the caller would
    /// record the snap as purged while clones still exist).
    pub fn map_next(
        &self,
        spg: SpgT,
        snap: u64,
        max: usize,
    ) -> Result<Vec<Hobject>, StoreReadError> {
        let p = snaps::fwd_prefix(snap);
        let mut out = Vec::new();
        let mut from = p.clone();
        loop {
            let r = self.st.borrow_mut().omap_iter(
                &pg_coll(spg),
                &mapper_obj(spg),
                &from,
                max.max(1) + 1,
            );
            let (kv, more) = match r {
                Ok(x) => x,
                Err(ObjError::NoEnt | ObjError::NoColl) => return Ok(out),
                Err(e) => {
                    self.note_damage(format!("pg {spg}: snap mapper read (snap {snap}): {e}"));
                    return Err(StoreReadError::Io);
                }
            };
            for (k, v) in &kv {
                if !k.starts_with(&p) {
                    return Ok(out);
                }
                let Some(h) = snaps::dec_fwd_val(v) else {
                    self.note_damage(format!(
                        "pg {spg}: snap mapper entry for snap {snap} undecodable"
                    ));
                    return Err(StoreReadError::Corrupt);
                };
                out.push(h);
                if out.len() >= max {
                    return Ok(out);
                }
            }
            match (more, kv.last()) {
                (true, Some((k, _))) => from = key_after(k.clone()),
                _ => return Ok(out),
            }
        }
    }

    /// Snaps mapped to `clone`.
    pub fn map_snaps(&self, spg: SpgT, clone: &Hobject) -> Option<Vec<u64>> {
        self.map_get(spg, &snaps::rev_key(clone))
            .ok()
            .flatten()
            .and_then(|v| snaps::dec_rev_val(&v))
            .map(|(_, s)| s)
    }

    /// Read the reverse entry without treating a failed or malformed read as an absent mapping.
    pub fn map_snaps_checked(
        &self,
        spg: SpgT,
        clone: &Hobject,
    ) -> Result<Option<Vec<u64>>, StoreReadError> {
        let value = self.map_get(spg, &snaps::rev_key(clone)).map_err(|e| {
            self.note_damage(format!("pg {spg}: snap mapper reverse read: {e}"));
            StoreReadError::Io
        })?;
        value
            .map(|v| {
                snaps::dec_rev_val(&v)
                    .filter(|(h, _)| h == clone)
                    .map(|(_, snaps)| snaps)
                    .ok_or_else(|| {
                        self.note_damage(format!(
                            "pg {spg}: snap mapper reverse entry undecodable or mismatched"
                        ));
                        StoreReadError::Corrupt
                    })
            })
            .transpose()
    }

    /// All `(clone, snaps)` of the PG (tests, tools, split).
    pub fn map_all(&self, spg: SpgT) -> Vec<(Hobject, Vec<u64>)> {
        let mut out = Vec::new();
        let mut from = snaps::REV_FIRST.to_vec();
        loop {
            let r = self
                .st
                .borrow_mut()
                .omap_iter(&pg_coll(spg), &mapper_obj(spg), &from, 512);
            let Ok((kv, more)) = r else { return out };
            for (k, v) in &kv {
                if k.as_slice() >= snaps::REV_END {
                    return out;
                }
                if let Some(x) = snaps::dec_rev_val(v) {
                    out.push(x);
                }
            }
            match (more, kv.last()) {
                (true, Some((k, _))) => from = key_after(k.clone()),
                _ => return out,
            }
        }
    }

    /// Mapper check of the clones in `[start, end)` (read-only).
    pub fn map_check(
        &self,
        spg: SpgT,
        start: &Hobject,
        end: &Hobject,
    ) -> (Vec<MapOp>, Vec<String>) {
        let c = pg_coll(spg);
        let end_g = (!end.max).then(|| gh(spg, end));
        let mut clones = Vec::new();
        let mut cur = gh(spg, start);
        let (mut unreadable, mut failed) = (0u64, None);
        loop {
            let r = self.st.borrow_mut().list(&c, &cur, end_g.as_ref(), 64);
            let (objs, next) = match r {
                Ok(x) => x,
                Err(e) => {
                    failed = Some(e.to_string());
                    break;
                }
            };
            for o in objs {
                if !o.is_pgmeta() && o.generation == Ghobject::NO_GEN && snaps::is_clone(&o.hobj) {
                    // an unreadable mapper entry is not "missing": skip it (no repair write from a read error)
                    let Ok(v) = self.map_get(spg, &snaps::rev_key(&o.hobj)) else {
                        unreadable += 1;
                        continue;
                    };
                    let have = v.and_then(|v| snaps::dec_rev_val(&v)).map(|(_, s)| s);
                    clones.push((o.hobj, have));
                }
            }
            match next {
                Some(n) => cur = n,
                None => break,
            }
        }
        let (ops, mut msgs) = peering::store::snapmap_check_with(clones, |h| {
            self.xattr(spg, h, b"snapset")
                .ok()
                .flatten()
                .and_then(|b| denc::from_slice::<replwire::SnapSet>(&b).ok())
        });
        // a read that failed is reported, never folded into "nothing to repair" (adr 0042)
        let rd = peering::store::SNAPMAP_READ_ERR;
        if let Some(e) = failed {
            msgs.push(format!("{rd}listing the clones failed: {e}"));
        }
        if unreadable > 0 {
            msgs.push(format!("{rd}{unreadable} mapper entries unreadable"));
        }
        (ops, msgs)
    }

    /// Whole-mapper walk of a deep scrub's first chunk: reports the keys that name no clone hash
    /// ([`snaps::key_hash`] `None`; split leaves them in place). A key naming no clone belongs to no chunk, so only
    /// this walk finds it; shallow scrubs never read the whole mapper.
    pub fn map_key_scan(&self, spg: SpgT) -> Vec<String> {
        match self.map_bad_keys(spg) {
            Ok(Some((n, k))) => vec![format!(
                "snap mapper: {n} unparseable keys, left in place (first {k:02x?})"
            )],
            Ok(None) => Vec::new(),
            Err(e) => vec![format!(
                "{}scanning the mapper keys failed: {e}",
                peering::store::SNAPMAP_READ_ERR
            )],
        }
    }

    /// Count and first of the mapper keys that name no clone hash ([`snaps::key_hash`] `None`).
    fn map_bad_keys(&self, spg: SpgT) -> Result<Option<(u64, Vec<u8>)>, ObjError> {
        let (c, o) = (pg_coll(spg), mapper_obj(spg));
        let mut bad: Option<(u64, Vec<u8>)> = None;
        for (first, end) in [
            (snaps::REV_FIRST, snaps::REV_END),
            (snaps::FWD_FIRST, snaps::FWD_END),
        ] {
            let mut pos = first.to_vec();
            loop {
                let (kv, more) = match self.st.borrow_mut().omap_iter(&c, &o, &pos, MOVE_BATCH) {
                    Ok(r) => r,
                    Err(ObjError::NoEnt | ObjError::NoColl) => return Ok(bad),
                    Err(e) => return Err(e),
                };
                for (k, _) in &kv {
                    if k.as_slice() >= end {
                        break;
                    }
                    if snaps::key_hash(k).is_none() {
                        bad.get_or_insert_with(|| (0, k.clone())).0 += 1;
                    }
                }
                match (more, kv.last()) {
                    (true, Some((k, _))) if k.as_slice() < end => pos = key_after(k.clone()),
                    _ => break,
                }
            }
        }
        Ok(bad)
    }
}

const MOVE_BATCH: usize = 256;

impl<D: BlockDev, C: Clock> StoreAdapter<D, C> {
    /// Carry the mapper entries of `from` whose clone hash satisfies `pick` over to `to` (idempotent puts), and/or
    /// drop them from `from` (`delete`). Used by split, merge and the deferred cleanup after a cross-shard split; every
    /// step is safe to repeat after a crash. Entries are placed by the hash in their key and copied byte for byte,
    /// values are never decoded: a damaged entry stays with its clone, where reads and `map_check` report it.
    /// `pick` gets the clone hash of a key, `None` for a key that names none (damaged): split and its cleanup leave
    /// such a key in `from` (the count and first such key are returned for the caller to note once; a deep scrub's
    /// `map_key_scan` reports it), merge carries it like any other.
    /// A damaged key never fails the move: the redo after a restart would meet it again and never finish.
    pub(crate) fn map_move(
        &self,
        from: SpgT,
        to: Option<SpgT>,
        pick: &dyn Fn(Option<u32>) -> bool,
        delete: bool,
    ) -> Result<Option<(u64, Vec<u8>)>, ObjError> {
        let (fc, fo) = (pg_coll(from), mapper_obj(from));
        let mut kept: Option<(u64, Vec<u8>)> = None;
        for (first, end) in [
            (snaps::REV_FIRST, snaps::REV_END),
            (snaps::FWD_FIRST, snaps::FWD_END),
        ] {
            let mut pos = first.to_vec();
            loop {
                let (kv, more) = match self.st.borrow_mut().omap_iter(&fc, &fo, &pos, MOVE_BATCH) {
                    Ok(r) => r,
                    Err(ObjError::NoEnt | ObjError::NoColl) => return Ok(kept),
                    Err(e) => return Err(e),
                };
                let next = match (more, kv.last()) {
                    (true, Some((k, _))) if k.as_slice() < end => Some(key_after(k.clone())),
                    _ => None,
                };
                let mut picked: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
                for (k, v) in kv {
                    if k.as_slice() >= end {
                        break;
                    }
                    let h = snaps::key_hash(&k);
                    if pick(h) {
                        picked.push((k, v));
                    } else if h.is_none() {
                        kept.get_or_insert_with(|| (0, k.clone())).0 += 1;
                    }
                }
                if !picked.is_empty() {
                    if let Some(to) = to {
                        let mut t = OTxn::new();
                        t.sys = true;
                        t.push(TOp::OmapSetKeys {
                            cid: pg_coll(to),
                            oid: mapper_obj(to),
                            pairs: picked
                                .iter()
                                .map(|(k, v)| (TxnBytes::Borrowed(k), TxnBytes::Borrowed(v)))
                                .collect(),
                        });
                        self.commit(&t)?;
                    }
                    if delete {
                        let mut t = OTxn::new();
                        t.sys = true;
                        t.push(TOp::OmapRmKeys {
                            cid: fc,
                            oid: fo.clone(),
                            keys: picked.iter().map(|(k, _)| TxnBytes::Borrowed(k)).collect(),
                        });
                        self.commit(&t)?;
                    }
                }
                match next {
                    Some(n) => pos = n,
                    None => break,
                }
            }
        }
        Ok(kept)
    }
}
