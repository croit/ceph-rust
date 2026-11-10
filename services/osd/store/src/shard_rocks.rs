// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Owner publication and immutable read handoffs for the external OMAP base.
use super::*;
use crate::olsm::{Olsm, mem::Probe};
use crate::rocks_omap::mem::{Buffers, Memtable};
use crate::rocks_omap::{Answer, Client, PageEnd, Query};
use bytes::Bytes;
use std::sync::Arc;

#[derive(Debug)]
pub(super) struct RocksDrv {
    pub client: Client,
}

fn sources<'a>(o: &'a Buffers, over: Option<&'a Memtable>) -> [Option<&'a Memtable>; 3] {
    [over, Some(&o.active), o.frozen.as_deref()]
}
fn probe(mems: &[Option<&Memtable>], id: u64, key: &[u8]) -> Probe {
    for m in mems.iter().flatten() {
        match m.probe(id, key) {
            Probe::Pass => {}
            p => return p,
        }
    }
    Probe::Pass
}

pub(super) fn mount(
    cfg: &crate::rocks_omap::Config,
    sb: &Superblock,
    shard: u32,
    mut o: Olsm,
    replay: &[(u64, crate::olsm::wire::OOp)],
    frontier: u64,
    mem: usize,
) -> Result<(RocksDrv, Olsm, Buffers)> {
    if !o.man.top().is_empty() || !o.man.tiers.is_empty() {
        return Err(StoreError::Corrupt(
            "RocksDB store contains native LSM runs".into(),
        ));
    }
    let mut client = Client::open(cfg, sb, shard, mem, o.man.flushed_lsn, frontier)?;
    o.active = crate::olsm::Memtable::new();
    let mut buffers = Buffers::default();
    for (lsn, op) in replay.iter().filter(|(l, _)| *l > client.watermark) {
        op.apply_rocks(&mut buffers.active, *lsn);
    }
    if client.watermark > o.man.flushed_lsn && !client.read_only {
        client.flushed = Some(client.watermark);
    }
    Ok((RocksDrv { client }, o, buffers))
}

impl<D: BlockDev> Shard<D> {
    pub(super) fn rocks_step(&mut self) {
        let Some(mut r) = self.rocks.take() else {
            return;
        };
        if r.client.poll() {
            self.wake = true;
        }
        if let Some(e) = r.client.failure.clone() {
            self.fail(e);
        }
        if self.failed.is_none() && !r.client.read_only {
            if let Some(lsn) = r.client.flushed {
                let mut t = Txn::new(MERGE_TOKEN);
                t.sys = true;
                t.olsm = Some(Vec::new());
                t.ops.push(Op::Put(
                    super::olsm_drv::FLUSHED_KEY.to_vec(),
                    lsn.to_le_bytes().to_vec(),
                ));
                match self.submit(t) {
                    Ok(_) => {
                        let mem = self.state.rocks_mem.as_mut().expect("RocksDB buffers");
                        if mem.frozen.as_ref().is_some_and(|f| f.lsn_hi() == lsn) {
                            mem.frozen = None;
                        }
                        self.state
                            .olsm
                            .as_mut()
                            .expect("RocksDB manifest")
                            .man
                            .flushed_lsn = lsn;
                        r.client.flushed = None;
                        r.client.note_published();
                    }
                    Err((StoreError::Busy | StoreError::Miss | StoreError::WalFull, _)) => {}
                    Err((e, _)) => self.fail(e),
                }
            }
            if r.client.flushed.is_none() && !r.client.busy() {
                let o = self.state.rocks_mem.as_mut().expect("RocksDB buffers");
                if o.frozen.is_none() && !o.active.is_empty() {
                    o.freeze();
                    let f = o.frozen.as_ref().expect("just frozen");
                    r.client
                        .note_frozen(f.lsn_hi(), f.bytes() as u64, self.durable_lsn);
                }
                if let Some(f) = &o.frozen
                    && f.lsn_hi() <= self.durable_lsn
                {
                    match r.client.flush(Arc::clone(f)) {
                        Ok(()) | Err(StoreError::Busy) => {}
                        Err(e) => self.fail(e),
                    }
                }
            }
        }
        let blocked = self.state.rocks_mem.as_ref().is_some_and(|m| {
            m.frozen.is_some()
                && self
                    .ol
                    .as_ref()
                    .is_some_and(|d| m.active.bytes() >= d.mt_soft)
        });
        if !blocked {
            r.client.note_unblocked();
        }
        self.rocks = Some(r);
    }

    pub(super) fn rocks_note_blocked(&mut self) {
        if let Some(r) = &mut self.rocks {
            r.client.note_blocked();
        }
    }

    pub(crate) fn rocks_profile_gauges(&self) -> Option<[u64; 72]> {
        Some(self.rocks.as_ref()?.client.profile_metrics())
    }

    pub fn rocks_selected(&self) -> bool {
        self.rocks.is_some()
    }

    /// Cold/admin snapshot only. DB-owned diagnostics are sampled on the worker;
    /// invalid or old samples remain explicit, never evidence of zero debt.
    pub(crate) fn rocks_gauges(&self) -> Option<[u64; 37]> {
        let r = self.rocks.as_ref()?;
        let o = self.state.rocks_mem.as_ref().expect("RocksDB buffers");
        let sample = r.client.metrics();
        let mut out = [0; 37];
        out[..10].copy_from_slice(&[
            1,
            u64::from(sample.valid),
            sample.age_ns,
            o.active.bytes() as u64,
            o.frozen.as_ref().map_or(0, |f| f.bytes() as u64),
            r.client.pending_reads(),
            u64::from(r.client.materializing()),
            u64::from(r.client.flushed.is_some()),
            u64::from(self.rocks_busy()),
            sample.errors,
        ]);
        out[10..19].copy_from_slice(&sample.values);
        out[19] = r.client.allocated_bytes();
        out[20] = r.client.watermark;
        out[21] = self
            .state
            .olsm
            .as_ref()
            .expect("RocksDB manifest")
            .man
            .flushed_lsn;
        out[22] = u64::from(r.client.read_only);
        out[23..].copy_from_slice(&sample.work);
        Some(out)
    }

    pub(crate) fn rocks_session(&mut self, session: Option<(u64, u64)>, keep: bool) {
        if let Some(r) = &mut self.rocks {
            let before = r.client.retained_session();
            r.client.read_session(session, keep);
            self.wake |= before.is_some() && r.client.retained_session().is_none();
        }
    }

    pub(crate) fn rocks_scan_admit(&mut self, session: (u64, u64), bytes: usize) -> Result<()> {
        self.rocks
            .as_mut()
            .expect("selected")
            .client
            .admit_scan(session, bytes)
    }

    pub(crate) fn rocks_scan_admission(
        &mut self,
        session: (u64, u64),
    ) -> Result<crate::rocks_omap::ScanAdmission<'_>> {
        self.rocks
            .as_mut()
            .expect("selected")
            .client
            .scan_admission(session)
    }

    pub(crate) fn rocks_session_admitted(&self, session: (u64, u64)) -> bool {
        self.rocks
            .as_ref()
            .is_some_and(|r| r.client.session_admitted(session))
    }
    pub(crate) fn rocks_scan_charge(&mut self, bytes: usize) {
        if let Some(r) = &mut self.rocks {
            r.client.set_scan_charge(bytes);
        }
    }

    /// Hand the owner's wake to this shard's RocksDB worker (see `OwnerWake`).
    pub(crate) fn rocks_set_owner_wake(&self, w: crate::rocks_omap::OwnerWake) {
        if let Some(r) = &self.rocks {
            r.client.set_owner_wake(w);
        }
    }

    /// A RocksDB worker completion waits for the owner's next poll.
    pub(crate) fn rocks_has_completion(&self) -> bool {
        self.rocks
            .as_ref()
            .is_some_and(|r| r.client.has_completion())
    }

    pub(super) fn rocks_busy(&self) -> bool {
        self.rocks.as_ref().is_some_and(|r| {
            r.client.needs_poll()
                || (!r.client.read_only
                    && self
                        .state
                        .rocks_mem
                        .as_ref()
                        .is_some_and(|o| !o.active.is_empty() || o.frozen.is_some()))
        })
    }

    pub(crate) fn rocks_get(
        &mut self,
        over: Option<&Memtable>,
        id: u64,
        key: &[u8],
    ) -> Result<Option<Bytes>> {
        let o = self.state.rocks_mem.as_ref().expect("RocksDB buffers");
        match probe(&sources(o, over), id, key) {
            Probe::Hit(v) => return Ok(v),
            Probe::Covered => return Ok(None),
            Probe::Pass => {}
        }
        let a = self
            .rocks
            .as_mut()
            .expect("selected")
            .client
            .query(Query::Keys {
                id,
                keys: vec![Bytes::copy_from_slice(key)],
            });
        // Pending worker/admission work keeps the shard pollable. Only a real
        // completion, failure or credit release is readiness progress.
        match &*a? {
            Answer::Entries(v, false) => Ok(v.first().map(|(_, v)| v.clone())),
            _ => Err(StoreError::Invalid("wrong RocksDB get response")),
        }
    }

    pub(crate) fn rocks_by_keys(
        &mut self,
        over: Option<&Memtable>,
        id: u64,
        keys: &[Bytes],
    ) -> Result<Vec<(Bytes, Bytes)>> {
        let o = self.state.rocks_mem.as_ref().expect("RocksDB buffers");
        let mems = sources(o, over);
        let ask: Vec<_> = keys
            .iter()
            .filter(|k| matches!(probe(&mems, id, k), Probe::Pass))
            .cloned()
            .collect();
        let answer = if ask.is_empty() {
            None
        } else {
            let a = self
                .rocks
                .as_mut()
                .expect("selected")
                .client
                .query(Query::Keys { id, keys: ask });
            Some(a?)
        };
        let base: std::collections::HashMap<Bytes, Bytes> = match answer.as_deref() {
            Some(Answer::Entries(v, false)) => v.iter().cloned().collect(),
            None => Default::default(),
            _ => return Err(StoreError::Invalid("wrong RocksDB multiget response")),
        };
        Ok(keys
            .iter()
            .filter_map(|k| {
                match probe(&mems, id, k) {
                    Probe::Hit(v) => v,
                    Probe::Covered => None,
                    Probe::Pass => base.get(k).cloned(),
                }
                .map(|v| (k.clone(), v))
            })
            .collect())
    }

    pub(crate) fn rocks_list(
        &mut self,
        over: Option<&Memtable>,
        id: u64,
        from: &[u8],
        excl: bool,
        prefix: &[u8],
        _max: usize,
    ) -> Result<(Vec<(Bytes, Bytes)>, bool)> {
        self.rocks_list_page(over, id, from, excl, prefix, _max)
            .map(|(page, end)| (page, end.has_more()))
    }

    pub(crate) fn rocks_list_page(
        &mut self,
        over: Option<&Memtable>,
        id: u64,
        from: &[u8],
        excl: bool,
        prefix: &[u8],
        max: usize,
    ) -> Result<(Vec<(Bytes, Bytes)>, PageEnd)> {
        let (q, view) =
            self.rocks_page_query(over, id, from, excl, prefix, crate::rocks_omap::PAGE);
        let a = self
            .rocks
            .as_mut()
            .expect("selected")
            .client
            .query_view(q, view);
        match &*a? {
            Answer::Page(v, end) => {
                let n = v.len().min(max);
                let next = if n < v.len() {
                    PageEnd::Next(Bytes::copy_from_slice(
                        v.get(n).expect("unreturned entry").0,
                    ))
                } else {
                    end.clone()
                };
                // This legacy unscoped API exports independent entries, not the
                // charged batch envelope. A tiny prefix must not pin a full slab.
                let entries = v
                    .iter()
                    .take(n)
                    .map(|(k, v)| (Bytes::copy_from_slice(k), Bytes::copy_from_slice(v)))
                    .collect();
                Ok((entries, next))
            }
            _ => Err(StoreError::Invalid("wrong RocksDB page response")),
        }
    }

    pub(crate) fn rocks_scan_batch(
        &mut self,
        over: Option<&Memtable>,
        id: u64,
        from: &[u8],
        excl: bool,
        prefix: &[u8],
        entries: usize,
    ) -> Result<(crate::rocks_omap::PageEntries, PageEnd)> {
        let (q, view) = self.rocks_page_query(over, id, from, excl, prefix, entries);
        self.rocks
            .as_mut()
            .expect("selected")
            .client
            .take_page(q, view)
    }

    fn rocks_page_query(
        &self,
        over: Option<&Memtable>,
        id: u64,
        from: &[u8],
        excl: bool,
        prefix: &[u8],
        entries: usize,
    ) -> (
        Query,
        [Option<std::sync::Arc<crate::rocks_omap::mem::ObjMem>>; 3],
    ) {
        let o = self.state.rocks_mem.as_ref().expect("RocksDB buffers");
        let mems = sources(o, over);
        // O(1) object snapshots: never clone an object's map for each cold page.
        let view = mems.map(|m| m.and_then(|m| m.snapshot(id)));
        let mut versions = view
            .each_ref()
            .map(|v| v.as_ref().map_or((0, 0), |v| v.revision));
        let session = self.rocks.as_ref().expect("selected").client.session();
        if session.is_none()
            && let Some(m) = over
        {
            versions[0].0 = m.scan_stamp().0;
        }
        let q = Query::Page {
            id,
            from: Bytes::copy_from_slice(from),
            excl,
            prefix: Bytes::copy_from_slice(prefix),
            entries: entries.clamp(1, crate::rocks_omap::SCAN_BATCH),
            versions,
            session,
        };
        (q, view)
    }

    pub fn rocks_ids(&mut self, after: Option<u64>) -> Result<Option<(Vec<u64>, bool)>> {
        let Some(r) = &mut self.rocks else {
            return Ok(None);
        };
        let a = r.client.query(Query::Ids { after });
        match &*a? {
            Answer::Ids(ids, more) => Ok(Some((ids.clone(), *more))),
            _ => Err(StoreError::Invalid("wrong RocksDB ID response")),
        }
    }
}

#[cfg(test)]
#[path = "shard_rocks_tests.rs"]
mod tests;
