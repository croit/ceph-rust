// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
//! Owner-only publication of the independent foreign OMAP base.
use super::*;
use crate::foreign_mem::{Buffers, Memtable};
use crate::olsm::{Olsm, mem::Probe};
use crate::splinter_omap::{Answer, Client, Query};
use bytes::Bytes;
use std::sync::Arc;

#[derive(Debug)]
pub(super) struct SplinterDrv {
    pub client: Client,
    buffered_since: Option<u64>,
    #[cfg(test)]
    hold: bool,
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
    cfg: &crate::splinter_omap::Config,
    sb: &Superblock,
    shard: u32,
    mut o: Olsm,
    replay: &[(u64, crate::olsm::wire::OOp)],
    frontier: u64,
    mem: usize,
) -> Result<(SplinterDrv, Olsm, Buffers)> {
    if !o.man.top().is_empty() || !o.man.tiers.is_empty() {
        return Err(StoreError::Corrupt(
            "SplinterDB store contains native LSM runs".into(),
        ));
    }
    let mut client = Client::open(cfg, sb, shard, mem, o.man.flushed_lsn, frontier)?;
    // Unpublished partial foreign mutations can survive with an OLD watermark.
    // All native-durable operations above it remain in this authoritative overlay
    // before service starts, including range tombstones; never expose raw partials.
    o.active = crate::olsm::Memtable::new();
    let mut buffers = Buffers::default();
    for (lsn, op) in replay.iter().filter(|(l, _)| *l > client.watermark) {
        op.apply_splinter(&mut buffers.active, *lsn);
    }
    if client.watermark > o.man.flushed_lsn {
        client.flushed = Some(client.watermark);
    }
    Ok((
        SplinterDrv {
            client,
            buffered_since: None,
            #[cfg(test)]
            hold: false,
        },
        o,
        buffers,
    ))
}
impl<D: BlockDev> Shard<D> {
    #[cfg(test)]
    pub(crate) fn set_splinter_age_for_test(&mut self, age: u64) {
        self.cfg.ckpt_interval_ns = age;
    }
    #[cfg(test)]
    pub(crate) fn splinter_hold_completions(&mut self, hold: bool) {
        self.splinter.as_mut().unwrap().client.hold_completions = hold;
    }

    pub(super) fn splinter_step(&mut self) {
        let Some(mut r) = self.splinter.take() else {
            return;
        };
        if r.client.poll() {
            self.wake = true;
        }
        // Pipelined: an applied flush is visible in the engine; its frozen buffer goes.
        // Its native publication still waits for the durable `flushed` below.
        if let Some(lsn) = r.client.take_applied() {
            let o = self
                .state
                .splinter_mem
                .as_mut()
                .expect("SplinterDB buffers");
            if o.frozen.as_ref().is_some_and(|f| f.lsn_hi() == lsn) {
                o.frozen = None;
            }
        }
        let o = self
            .state
            .splinter_mem
            .as_ref()
            .expect("SplinterDB buffers");
        if o.active.is_empty() {
            r.buffered_since = None;
            if o.frozen.is_none() {
                self.ol.as_mut().expect("logical driver").want_freeze = false;
            }
        } else {
            r.buffered_since.get_or_insert(self.poll_now);
        }
        let aged = r
            .buffered_since
            .is_some_and(|t| self.poll_now.saturating_sub(t) >= self.cfg.ckpt_interval_ns);
        let pending = self
            .state
            .splinter_mem
            .as_ref()
            .is_some_and(|o| !o.active.is_empty() || o.frozen.is_some());
        r.client
            .set_pressure(pending || self.read_admission_waiting);
        if let Some(e) = r.client.failure.clone() {
            self.fail(e);
        }
        if self.failed.is_none() {
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
                        let o = self
                            .state
                            .splinter_mem
                            .as_mut()
                            .expect("SplinterDB buffers");
                        if o.frozen.as_ref().is_some_and(|f| f.lsn_hi() == lsn) {
                            o.frozen = None;
                        }
                        self.state
                            .olsm
                            .as_mut()
                            .expect("logical engine")
                            .man
                            .flushed_lsn = lsn;
                        r.client.flushed = None;
                    }
                    Err((StoreError::Busy | StoreError::Miss | StoreError::WalFull, _)) => {}
                    Err((e, _)) => self.fail(e),
                }
            }
            if r.client.can_flush() {
                #[cfg(test)]
                if r.hold {
                    self.splinter = Some(r);
                    return;
                }
                let due = aged || self.splinter_freeze_due();
                let o = self
                    .state
                    .splinter_mem
                    .as_mut()
                    .expect("SplinterDB buffers");
                if o.frozen.is_none() && !o.active.is_empty() && due {
                    o.freeze();
                    r.buffered_since = None;
                    self.ol.as_mut().expect("logical driver").want_freeze = false;
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
        self.splinter = Some(r);
    }
    pub fn splinter_selected(&self) -> bool {
        self.splinter.is_some()
    }
    fn splinter_freeze_due(&self) -> bool {
        let o = self
            .state
            .splinter_mem
            .as_ref()
            .expect("SplinterDB buffers");
        let d = self.ol.as_ref().expect("logical driver");
        o.frozen.is_none()
            && !o.active.is_empty()
            && (o.active.bytes() >= d.mt_soft
                || d.want_freeze
                || o.floor().is_some_and(|floor| {
                    self.state.runs.floor().is_none_or(|r| r >= floor)
                        && self.floor_blocks_at(floor) * 100
                            >= self.dir.wal_blocks * self.cfg.ckpt_wal_pct as u64
                }))
    }
    /// No foreign request or replay-discovered publication remains before a checkpoint target is captured.
    pub(crate) fn splinter_drained(&self) -> bool {
        self.olsm_flushed() && self.splinter.as_ref().is_none_or(|r| !r.client.busy())
    }
    pub(crate) fn splinter_gauges(&self) -> Option<[u64; 10]> {
        let r = self.splinter.as_ref()?;
        let o = self
            .state
            .splinter_mem
            .as_ref()
            .expect("SplinterDB buffers");
        let c = r.client.counters();
        Some([
            1,
            c[0],
            c[1],
            c[2],
            c[3],
            c[4],
            r.client.watermark,
            self.state
                .olsm
                .as_ref()
                .expect("logical engine")
                .man
                .flushed_lsn,
            o.active.bytes() as u64,
            o.frozen.as_ref().map_or(0, |f| f.bytes() as u64),
        ])
    }
    pub(crate) fn splinter_read_gauges(&self) -> Option<[u64; 29]> {
        self.splinter.as_ref().map(|r| r.client.read_gauges())
    }
    pub(crate) fn splinter_timing_counters(
        &self,
    ) -> Option<[u64; crate::splinter_omap::timing::FIELDS]> {
        self.splinter.as_ref().map(|r| r.client.timing_counters())
    }
    pub(crate) fn splinter_session(&mut self, s: Option<(u64, u64)>, keep: bool) {
        if let Some(r) = &mut self.splinter {
            let old = r.client.retained_session();
            r.client.read_session(s, keep);
            self.wake |= old.is_some() && r.client.retained_session().is_none();
        }
    }
    pub(crate) fn splinter_scan_admit(&mut self, s: (u64, u64), bytes: usize) -> Result<()> {
        self.splinter
            .as_mut()
            .expect("selected")
            .client
            .admit_scan(s, bytes)
    }
    /// Hand the owner's wake to this shard's SplinterDB worker (see `OwnerWake`).
    pub(crate) fn splinter_set_owner_wake(&self, w: crate::splinter_omap::OwnerWake) {
        if let Some(r) = &self.splinter {
            r.client.set_owner_wake(w);
        }
    }
    /// A SplinterDB worker completion waits for the owner's next poll.
    pub(crate) fn splinter_has_completion(&self) -> bool {
        self.splinter
            .as_ref()
            .is_some_and(|r| r.client.has_completion())
    }
    pub(crate) fn splinter_session_admitted(&self, s: (u64, u64)) -> bool {
        self.splinter
            .as_ref()
            .is_some_and(|r| r.client.session_admitted(s))
    }
    pub(crate) fn splinter_credit_blocked(&self) -> bool {
        self.splinter
            .as_ref()
            .is_some_and(|r| r.client.credit_blocked())
    }
    pub(crate) fn splinter_begin_blocking_read(&mut self) {
        if let Some(r) = &mut self.splinter {
            self.wake |= r.client.begin_blocking_read();
        }
    }
    pub(crate) fn splinter_end_blocking_read(&mut self) {
        if let Some(r) = &mut self.splinter {
            r.client.end_blocking_read();
        }
    }
    pub(crate) fn splinter_independent_reads(&self) -> bool {
        self.splinter
            .as_ref()
            .is_some_and(|r| r.client.independent_reads())
    }
    pub(crate) fn splinter_begin_barrier_read(&mut self) {
        if let Some(r) = &mut self.splinter {
            self.wake |= r.client.begin_barrier_read();
        }
    }
    pub(crate) fn splinter_end_barrier_read(&mut self) {
        if let Some(r) = &mut self.splinter {
            r.client.end_barrier_read();
        }
    }
    pub(crate) fn splinter_scan_charge(&mut self, bytes: usize) {
        if let Some(r) = &mut self.splinter {
            r.client.set_scan_charge(bytes);
        }
    }
    pub(super) fn splinter_busy(&self) -> bool {
        self.splinter.as_ref().is_some_and(|r| {
            r.client.needs_poll()
                || self
                    .state
                    .splinter_mem
                    .as_ref()
                    .is_some_and(|o| !o.active.is_empty() || o.frozen.is_some())
        })
    }
    pub(super) fn splinter_needs_poll(&self) -> bool {
        self.splinter.as_ref().is_some_and(|r| {
            r.client.needs_poll()
                || self
                    .state
                    .splinter_mem
                    .as_ref()
                    .is_some_and(|o| o.frozen.is_some())
        })
    }
    pub(crate) fn splinter_get(
        &mut self,
        over: Option<&Memtable>,
        id: u64,
        key: &[u8],
    ) -> Result<Option<Bytes>> {
        match probe(
            &sources(
                self.state
                    .splinter_mem
                    .as_ref()
                    .expect("SplinterDB buffers"),
                over,
            ),
            id,
            key,
        ) {
            Probe::Hit(v) => return Ok(v),
            Probe::Covered => return Ok(None),
            Probe::Pass => {}
        }
        let a = self
            .splinter
            .as_mut()
            .expect("selected")
            .client
            .query(Query::Keys {
                id,
                keys: vec![Bytes::copy_from_slice(key)],
            })?;
        match &*a {
            Answer::Entries(v, _) => Ok(v.first().map(|(_, v)| v.clone())),
            _ => Err(StoreError::Invalid("wrong SplinterDB get response")),
        }
    }
    pub(crate) fn splinter_by_keys(
        &mut self,
        over: Option<&Memtable>,
        id: u64,
        keys: &[Bytes],
    ) -> Result<Vec<(Bytes, Bytes)>> {
        let mems = sources(
            self.state
                .splinter_mem
                .as_ref()
                .expect("SplinterDB buffers"),
            over,
        );
        let ask: Vec<_> = keys
            .iter()
            .filter(|k| matches!(probe(&mems, id, k), Probe::Pass))
            .cloned()
            .collect();
        let a = if ask.is_empty() {
            None
        } else {
            Some(
                self.splinter
                    .as_mut()
                    .expect("selected")
                    .client
                    .query(Query::Keys { id, keys: ask })?,
            )
        };
        let base: std::collections::HashMap<Bytes, Bytes> = match a.as_deref() {
            Some(Answer::Entries(v, _)) => v.iter().cloned().collect(),
            None => Default::default(),
            _ => return Err(StoreError::Invalid("wrong SplinterDB multiget response")),
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
    pub(crate) fn splinter_list(
        &mut self,
        over: Option<&Memtable>,
        id: u64,
        from: &[u8],
        excl: bool,
        prefix: &[u8],
        max: usize,
    ) -> Result<(Vec<(Bytes, Bytes)>, bool)> {
        self.splinter_list_mode(over, id, from, excl, prefix, (max, false, usize::MAX))
    }
    pub(crate) fn splinter_list_mode(
        &mut self,
        over: Option<&Memtable>,
        id: u64,
        from: &[u8],
        excl: bool,
        prefix: &[u8],
        projection: (usize, bool, usize),
    ) -> Result<(Vec<(Bytes, Bytes)>, bool)> {
        // `take`: rows this owner pass can consume; fewer are copied, `more` stays true.
        let (max, keys_only, take) = projection;
        let mems = sources(
            self.state
                .splinter_mem
                .as_ref()
                .expect("SplinterDB buffers"),
            over,
        );
        let view = mems.map(|m| m.and_then(|m| m.snapshot(id)));
        let mut versions = view
            .each_ref()
            .map(|v| v.as_ref().map_or((0, 0), |v| v.revision));
        let session = self
            .splinter
            .as_ref()
            .expect("selected")
            .client
            .query_session();
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
            versions,
            session,
            keys_only,
            demand: max.clamp(1, crate::splinter_omap::MAX_SCAN_ROWS),
        };
        let a = self
            .splinter
            .as_mut()
            .expect("selected")
            .client
            .query_view_take(q, view, take)?;
        match &*a {
            Answer::Entries(v, more) => {
                let n = v.len().min(max).min(take);
                Ok((v[..n].to_vec(), *more || n < v.len()))
            }
            _ => Err(StoreError::Invalid("wrong SplinterDB page response")),
        }
    }
    pub fn splinter_ids(&mut self, after: Option<u64>) -> Result<Option<(Vec<u64>, bool)>> {
        let Some(r) = &mut self.splinter else {
            return Ok(None);
        };
        match &*r.client.query(Query::Ids { after })? {
            Answer::Ids(ids, more) => Ok(Some((ids.clone(), *more))),
            _ => Err(StoreError::Invalid("wrong SplinterDB inventory response")),
        }
    }
}

#[cfg(test)]
#[path = "shard_splinter_tests.rs"]
mod tests;
