// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Replica side of scrub (spec scrub.md 4): reservation requests (the slots: [`crate::slots`]), chunk requests (wait
//! for earlier transactions, build the [`ScrubMap`] in slices, reply), abort on interval change. The primary role is
//! [`crate::scrubp`].

use crate::pg::{Pg, St};
use crate::store::{MemStore, PgStoreOps};
use crate::types::*;
use denc::types::{Hobject, SpgT};
use replwire::scrubmsgs::{
    DIGEST_SEED, MOSDRepScrub, MOSDRepScrubMap, MOSDScrubReserve, OmapDigest, ScrubMap,
    ScrubObject, attr_visible, data_digest_update,
};
use std::collections::BTreeMap;

/// Objects per slice of a shallow build.
pub const SLICE_OBJECTS: usize = 64;
/// Bytes of object data per slice of a deep build (at least one object is always processed). 1 MiB (was 8): Ice Lake VMs, deep
/// scrub under rep3 4K writes: longest core iteration 64-112 -> 14 ms, write max 3.0-4.5 -> 1.0-2.4 s (tail-latency-20261015.md).
pub const SLICE_BYTES: u64 = 1 << 20;
/// Read stride of the data digest (osd_deep_scrub_stride).
pub const STRIDE: u64 = 4 << 20;
/// Omap keys per read (osd_deep_scrub_keys).
pub const OMAP_BATCH: usize = 1024;

/// One slice of a chunk build.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScrubPart {
    pub objects: BTreeMap<Hobject, ScrubObject>,
    /// First unprocessed object of the range; `None` = the range is done.
    pub next: Option<Hobject>,
    /// Enumeration failed: this slice must never be used as a complete scrub map.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Resv {
    #[default]
    None,
    Pending {
        nonce: u32,
        epoch: u32,
    },
    Granted,
}

#[derive(Debug)]
struct Chunk {
    req: MOSDRepScrub,
    /// Highest pending store token at the first step; `None` until then.
    barrier: Option<u64>,
    building: bool,
    cursor: Hobject,
    map: ScrubMap,
}

/// Per-PG replica scrub state.
#[derive(Debug, Default)]
pub(crate) struct ScrubReplica {
    resv: Resv,
    chunk: Option<Chunk>,
    pub served: u64,
}

impl Pg {
    /// Chunk served so far on this PG instance (tests/diagnostics).
    pub fn scrub_chunks_served(&self) -> u64 {
        self.scrub.served
    }
    /// Is a replica scrub reservation held or pending? (diagnostics)
    pub fn scrub_reserved(&self) -> bool {
        self.scrub.resv != Resv::None
    }
    pub(crate) fn scrub_replica_debug(&self) -> String {
        format!("{:?}", self.scrub.resv)
    }
    pub fn scrub_chunk_active(&self) -> bool {
        self.scrub.chunk.is_some()
    }
    /// A slice is ready to run: `tick` should be called without delay.
    pub(crate) fn scrub_busy(&self) -> bool {
        self.scrub.chunk.as_ref().is_some_and(|c| c.building) || self.sp_busy()
    }

    /// New interval / leaving the replica role: drop reservation and chunk, send nothing.
    pub(crate) fn scrub_reset(&mut self) {
        self.sp_reset();
        if self.scrub.resv != Resv::None {
            self.slot_release(SlotPool::ScrubReplica);
        }
        self.scrub = ScrubReplica {
            served: self.scrub.served,
            ..Default::default()
        };
    }

    fn scrub_reply_reserve(&mut self, ty: i32, epoch: u32, nonce: u32) {
        let to = self.acting_primary;
        if to < 0 {
            return;
        }
        let m = MOSDScrubReserve {
            pgid: self.primary_spg(),
            map_epoch: epoch,
            ty,
            from: self.me,
            nonce,
            wait_for_resources: false,
        };
        self.send_repl(to, m, 0);
    }

    pub(crate) fn on_scrub_reserve(&mut self, from: i32, m: MOSDScrubReserve) {
        if matches!(self.st, St::Primary(_)) {
            return self.sp_on_reserve_reply(from, m);
        }
        if self.st != St::ReplicaActive || from != self.acting_primary {
            self.discard("scrub reserve in wrong role");
            return;
        }
        match m.ty {
            MOSDScrubReserve::REQUEST => {
                if self.scrub.resv != Resv::None {
                    self.error("scrub: unexpected reservation request");
                    self.slot_release(SlotPool::ScrubReplica);
                }
                self.scrub.resv = Resv::Pending {
                    nonce: m.nonce,
                    epoch: m.map_epoch,
                };
                self.slot_ask(
                    SlotPool::ScrubReplica,
                    SlotOp::Request {
                        immediate: !m.wait_for_resources,
                        prio: 0,
                    },
                );
            }
            MOSDScrubReserve::RELEASE => {
                if self.scrub.resv == Resv::None {
                    self.error("scrub: release without reservation");
                } else {
                    self.slot_release(SlotPool::ScrubReplica);
                    self.scrub.resv = Resv::None;
                }
            }
            _ => self.discard("scrub reserve grant/reject on replica"),
        }
    }

    /// The OSD-wide limiter granted our slot.
    pub(crate) fn scrub_granted(&mut self) {
        if let Resv::Pending { nonce, epoch } = self.scrub.resv {
            self.scrub.resv = Resv::Granted;
            self.scrub_reply_reserve(MOSDScrubReserve::GRANT, epoch, nonce);
        } else {
            // canceled meanwhile: pass the slot on
            self.slot_release(SlotPool::ScrubReplica);
        }
    }

    /// Immediate-mode request found no slot.
    pub(crate) fn scrub_rejected(&mut self) {
        if let Resv::Pending { nonce, epoch } = self.scrub.resv {
            self.scrub.resv = Resv::None;
            self.scrub_reply_reserve(MOSDScrubReserve::REJECT, epoch, nonce);
        }
    }

    pub(crate) fn on_rep_scrub(&mut self, from: i32, m: MOSDRepScrub) {
        if self.st != St::ReplicaActive || from != self.acting_primary {
            self.discard("rep scrub in wrong role");
            return;
        }
        if m.map_epoch < self.info.history.same_interval_since {
            self.discard("rep scrub from old interval");
            return;
        }
        if self.scrub.chunk.is_some() {
            self.error("scrub: new chunk request while handling previous one");
        }
        if matches!(self.scrub.resv, Resv::Pending { .. }) {
            self.error("scrub: chunk request while waiting for reservation");
            self.slot_release(SlotPool::ScrubReplica);
            self.scrub.resv = Resv::None;
        }
        let cursor = m.start.clone();
        self.scrub.chunk = Some(Chunk {
            req: m,
            barrier: None,
            building: false,
            cursor,
            map: ScrubMap::default(),
        });
    }

    /// Advance the chunk machine by at most one slice. Runs at the end of every public entry point
    /// (after the PG's own transactions were flushed).
    pub(crate) fn scrub_step(&mut self, store: &impl PgStoreOps) {
        self.sp_step(store);
        let Some(c) = self.scrub.chunk.as_mut() else {
            return;
        };
        if !c.building {
            // all transactions queued so far (repops, pushes, deletes) must be applied
            let barrier = *c
                .barrier
                .get_or_insert_with(|| self.pending.keys().next_back().copied().unwrap_or(0));
            if self.pending.range(..=barrier).next().is_some() {
                return;
            }
            store.reset_scrub(self.spg);
            c.building = true;
            c.map.valid_through = self.info.last_update;
            return self.scrub_step(store);
        }
        let (max_obj, max_bytes) = if c.req.deep {
            (SLICE_OBJECTS, self.cfg.scrub.slice_bytes)
        } else {
            (SLICE_OBJECTS, u64::MAX)
        };
        store.scrub_role(self.spg, false);
        let part = match self.pool.ec.as_ref().filter(|e| e.supported) {
            Some(e) => store.build_scrub_map_ec(
                self.spg,
                &c.cursor,
                &c.req.end,
                c.req.deep,
                max_obj,
                max_bytes,
                crate::ecopt::scrub_mode(e),
                e.chunk_size,
            ),
            None => store.build_scrub_map(
                self.spg, &c.cursor, &c.req.end, c.req.deep, max_obj, max_bytes,
            ),
        };
        if let Some(error) = part.error {
            self.notes.push(format!("pg {}: {error}", self.spg));
            let c = self.scrub.chunk.take().expect("chunk");
            let reply = MOSDRepScrubMap {
                pgid: self.primary_spg(),
                map_epoch: c.req.min_epoch,
                from: self.me,
                preempted: true,
                map: Default::default(),
            };
            self.send_repl(self.acting_primary, reply, 0);
            return;
        }
        let (kt, bt) = (
            self.cfg.scrub.large_omap_keys,
            self.cfg.scrub.large_omap_bytes,
        );
        c.map
            .objects
            .extend(part.objects.into_iter().map(|(h, mut o)| {
                o.apply_large_omap(kt, bt);
                (h, o)
            }));
        if let Some(n) = part.next {
            c.cursor = n;
            return;
        }
        if let Some(c) = self.scrub.chunk.as_ref() {
            let (s, e, deep) = (c.req.start.clone(), c.req.end.clone(), c.req.deep);
            self.snapmap_scrub(store, &s, &e, deep);
        }
        let c = self.scrub.chunk.take().expect("chunk");
        self.scrub.served += 1;
        let to = self.acting_primary;
        if to < 0 {
            return;
        }
        let reply = MOSDRepScrubMap {
            pgid: self.primary_spg(),
            map_epoch: c.req.min_epoch,
            from: self.me,
            preempted: false,
            map: c.map,
        };
        self.send_repl(to, reply, 0);
    }
}

// ---- in-memory builder --------------------------------------------------------------------------

impl MemStore {
    /// EC shard variant of [`MemStore::scrub_part`] (ec.md 7.7): shard file size, all xattrs, shard digest rules.
    #[expect(clippy::too_many_arguments)]
    pub fn scrub_part_ec(
        &self,
        spg: SpgT,
        start: &Hobject,
        end: &Hobject,
        deep: bool,
        max_objects: usize,
        max_bytes: u64,
        mode: replwire::ecscrub::EcScrubMode,
        chunk: u32,
    ) -> ScrubPart {
        let mut part = ScrubPart::default();
        let Some(pg) = self.pgs.get(&spg) else {
            return part;
        };
        let mut spent = 0u64;
        for (h, o) in pg.objects.range(start.clone()..) {
            if h.is_temp() {
                continue;
            }
            if !end.max && h >= end {
                break;
            }
            if part.objects.len() >= max_objects || (spent >= max_bytes && !part.objects.is_empty())
            {
                part.next = Some(h.clone());
                return part;
            }
            let mut so = ScrubObject {
                size: o.data.len() as u64,
                attrs: o.xattrs.clone(),
                ..Default::default()
            };
            if deep {
                spent += so.size;
                let crc = data_digest_update(DIGEST_SEED, &o.data);
                replwire::ecscrub::ec_deep_finish(
                    &mut so,
                    spg.shard.0.max(0) as usize,
                    mode,
                    chunk,
                    crc,
                    o.data.len() as u64,
                );
                if mode == replwire::ecscrub::EcScrubMode::Optimized
                    && !so.read_error
                    && !so.ec_hash_mismatch
                    && !so.ec_size_mismatch
                {
                    let mut d = OmapDigest::default();
                    d.header(&o.omap_header);
                    for (k, v) in &o.omap {
                        d.entry(k, v);
                    }
                    spent += d.key_bytes + d.bytes;
                    so.set_omap_stats(&d);
                }
            }
            part.objects.insert(h.clone(), so);
        }
        part
    }

    /// Slice of a scrub map over the in-memory PG (reference for the NVMe adapter).
    pub fn scrub_part(
        &self,
        spg: SpgT,
        start: &Hobject,
        end: &Hobject,
        deep: bool,
        max_objects: usize,
        max_bytes: u64,
    ) -> ScrubPart {
        let mut part = ScrubPart::default();
        let Some(pg) = self.pgs.get(&spg) else {
            return part;
        };
        let mut spent = 0u64;
        for (h, o) in pg.objects.range(start.clone()..) {
            if h.is_temp() {
                continue;
            }
            if !end.max && h >= end {
                break;
            }
            if part.objects.len() >= max_objects || (spent >= max_bytes && !part.objects.is_empty())
            {
                part.next = Some(h.clone());
                return part;
            }
            let mut so = ScrubObject {
                size: o.data.len() as u64,
                ..Default::default()
            };
            for (k, v) in &o.xattrs {
                if attr_visible(k) {
                    so.attrs.insert(k.clone(), v.clone());
                }
            }
            if deep {
                spent += so.size;
                so.digest = data_digest_update(DIGEST_SEED, &o.data);
                so.digest_present = true;
                let mut d = OmapDigest::default();
                d.header(&o.omap_header);
                for (k, v) in &o.omap {
                    d.entry(k, v);
                }
                so.set_omap(&d);
            }
            part.objects.insert(h.clone(), so);
        }
        part
    }
}
