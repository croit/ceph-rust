// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Offline repair: ownership census, false-free data allocation, shared-refcount rebuild, exclusive-owner
//! relocation, leak reclaim and counter recount. Repair mounts publish false-free metadata cells by checkpoint.
//! Structural/checksum damage refuses.
use super::keys::{T_EXT, ref_key};
use super::onode::{Ext, ref_encode, vext, vext_encode};
use super::{ObjError, Result, Store};
use crate::BLK;
use crate::StoreError;
use crate::dev::{BlockDev, Clock, IoBuf};
use crate::fsck::RepairPlan;
use crate::shard::Txn;
use std::collections::HashSet;

/// Leaked runs freed per txn: bounds the WAL record, each txn is durable before the next.
const FREES_PER_TXN: usize = 64;
/// False-free extents (each at most one device transfer) claimed per txn.
const CLAIMS_PER_TXN: usize = 16;
/// Refcount record changes per txn (a group of overlapping records is never split).
const REF_OPS_PER_TXN: usize = 256;

/// What [`Store::repair`] found and did.
#[derive(Clone, Debug, Default)]
pub struct RepairReport {
    /// Findings of the checks before any correction (correctable ones included).
    pub before: Vec<String>,
    /// Corrections, each appended once its txn (or checkpoint) is durable.
    pub actions: Vec<String>,
    /// What remains after the repair; empty = the store checks clean. On a refusal: the unrepairable findings.
    pub after: Vec<String>,
    /// Unrepairable findings: nothing was corrected.
    pub refused: bool,
}

const UNREPAIRABLE: &str = "not repairable, export PGs / recover from replicas";

/// `Ok` value of `$op`, or the report so far plus a line naming the interruption (an IO error mid-repair: what is done
/// stays done, a rerun continues).
macro_rules! attempt {
    ($report:ident, $op:expr) => {
        match $op {
            Ok(v) => v,
            Err(e) => {
                $report.after.push(format!(
                    "repair interrupted: {e}; run repair again; if it persists: {UNREPAIRABLE}"
                ));
                return Ok($report);
            }
        }
    };
}

/// Repair never touches an external omap engine (RocksDB): a store whose superblock selects one is refused before
/// anything is read or written beyond the superblock. `None` = repairable engine (native B+tree / LSM omap).
pub fn refuse_engine(features: u64) -> Option<&'static str> {
    (features & crate::layout::FEAT_OMAP_ROCKSDB != 0).then_some(
        "store uses the RocksDB omap engine: offline repair does not support it (nothing written); \
         export PGs / recover from replicas",
    )
}

impl RepairPlan {
    fn findings(&self) -> impl Iterator<Item = String> + '_ {
        let s = self.shard;
        self.leaks
            .iter()
            .map(move |(b, n)| {
                format!("shard {s}: blocks {b}+{n} allocated but unreferenced (leak)")
            })
            .chain(
                self.used_counter.map(|(old, new)| {
                    format!("shard {s}: root usage counter {old} != bitmap {new}")
                }),
            )
            .chain(self.meta_counter.map(|(old, new)| {
                format!("shard {s}: root meta page counter {old} != meta bitmap {new}")
            }))
            .chain(
                self.missing.iter().map(move |(b, n)| {
                    format!("shard {s}: blocks {b}+{n} referenced but unallocated")
                }),
            )
            .chain(self.missing_meta.iter().map(move |(b, n)| {
                format!("shard {s}: metadata blocks {b}+{n} in use but unallocated")
            }))
            .chain(
                self.relocate
                    .iter()
                    .map(move |k| format!("shard {s}: double-referenced owner {k:02x?}")),
            )
            .chain(
                self.refs
                    .iter()
                    .map(move |_| format!("shard {s}: shared refcounts differ from census")),
            )
    }
}

impl<D: BlockDev, C: Clock> Store<D, C> {
    /// Offline repair of a store mounted with every shard (exclusive device owner; a mount with
    /// `ShardCfg::repair_counters` also admits root counter drift). False-free metadata cells require a fresh
    /// `ShardCfg::repair_fence` mount: it publishes their allocation by checkpoint before returning this store.
    ///
    /// 1. Ownership census of the durable state (`fsck::repair_plan`: tree, meta bitmap, every data reference against
    ///    the data bitmap) and the object-layer check of every shard. Structural/checksum damage refuses before
    ///    writes. Relocation always verifies data checksums, including without `deep`.
    /// 2. Reserve every false free, claim immutable bytes through ordinary allocation records, relocate later
    ///    exclusive owner keys (metadata/shared/engine owners keep originals), rebuild shared refcounts.
    ///    Checkpoint and census again on the now durable state; only its leaks are freed.
    /// 3. Leaks freed by normal txns (WAL, then checkpoint publishes bitmap and tree together), counter records
    ///    rewritten from the recount, root counters recomputed by a checkpoint from the allocator and meta bitmap.
    /// 4. Census and object check again: `after`.
    ///
    /// Crash safety: every correction is an ordinary durable txn; a crash leaves a store that mounts (replay) and a
    /// second repair finds what is left. An IO error ends the repair with the completed actions and an `after` line.
    pub fn repair(&mut self, deep: bool) -> Result<RepairReport> {
        if self.shards.len() != self.nshards() {
            return Err(ObjError::Invalid("repair requires every shard".into()));
        }
        let mut report = RepairReport::default();
        // Raw-device census IO owns this queue's completions. Mount/placement walks may leave asynchronous page
        // prefetches in flight; consume those through their shard owner before handing the queue to Sio.
        attempt!(report, self.repair_drain());
        let (sb, _) = crate::layout::read_super(self.shards[0].sh.dev(), &mut self.clk)?;
        if let Some(m) = refuse_engine(sb.features) {
            report.refused = true;
            report.after.push(m.into());
            return Ok(report);
        }
        // False-free metadata cells: allocated by the repair mount itself (fence before replay, durable by its
        // checkpoint before the mount returned), `ShardCfg::repair_fence`.
        for s in &mut self.shards {
            for (b, n) in s.sh.take_repaired_meta() {
                report.before.push(format!(
                    "shard {}: metadata blocks {b}+{n} in use but unallocated",
                    s.idx
                ));
                report.actions.push(format!(
                    "shard {}: mount checkpoint allocated metadata blocks {b}+{n}",
                    s.idx
                ));
            }
        }
        let refs = super::onode::fsck_refs;
        // Before the first checkpoint: it may allocate metadata cells from blocks the durable state calls free.
        let mut bad = Vec::new();
        let plans = match crate::fsck::repair_plan(self.shards[0].sh.dev(), &mut self.clk, &refs) {
            Ok(plans) => {
                report
                    .before
                    .extend(plans.iter().flat_map(RepairPlan::findings));
                if plans.iter().any(|p| !p.missing_meta.is_empty()) {
                    bad.push("false-free metadata requires a fresh repair_fence mount".into());
                }
                plans
            }
            Err(e) => {
                bad.push(e);
                Vec::new()
            }
        };
        let verify_data = deep || plans.iter().any(|p| !p.relocate.is_empty());
        let mut fixes = Vec::with_capacity(self.shards.len());
        for s in &mut self.shards {
            let mut records = Vec::new();
            let r = attempt!(
                report,
                super::check::check_shard_plan(s, &mut self.clk, verify_data, Some(&mut records))
            );
            bad.extend(r.errors.iter().map(|e| format!("shard {}: {e}", s.idx)));
            report.before.extend(
                records
                    .iter()
                    .map(|(m, ..)| format!("shard {}: {m}", s.idx)),
            );
            fixes.push(records);
        }
        if bad.is_empty() {
            // Fence EVERY false free before any txn / checkpoint may allocate metadata (a repair mount fenced the
            // pre-replay census already, `ShardCfg::repair_fence`).
            for s in &mut self.shards {
                let Some(plan) = plans.iter().find(|p| p.shard == s.idx) else {
                    bad.push(format!(
                        "shard {}: missing from the ownership census",
                        s.idx
                    ));
                    continue;
                };
                let a = &mut s.sh.state_mut().alloc;
                for blk in plan.missing.iter().flat_map(|&(b, n)| b..b + u64::from(n)) {
                    if !a.is_reserved(blk, 1) && !a.reserve_named(blk, 1) {
                        bad.push(format!(
                            "shard {}: false-free block {blk} not reservable",
                            s.idx
                        ));
                    }
                }
            }
        }
        if bad.is_empty() {
            for s in &mut self.shards {
                let plan = plans
                    .iter()
                    .find(|p| p.shard == s.idx)
                    .expect("checked by the fence");
                attempt!(
                    report,
                    repair_owners(s, &mut self.clk, plan, &mut report.actions)
                );
            }
            attempt!(report, self.checkpoint());
            attempt!(report, self.repair_drain());
            match crate::fsck::repair_plan(self.shards[0].sh.dev(), &mut self.clk, &refs) {
                Ok(plans) => return self.apply(report, plans, fixes, deep),
                Err(e) => bad.push(e),
            }
        }
        report.before.extend(bad.iter().cloned());
        report.after = bad
            .into_iter()
            .map(|e| format!("{e}: {UNREPAIRABLE}"))
            .collect();
        report.refused = true;
        Ok(report)
    }

    /// Transfer completion ownership from the asynchronous shard readers to the synchronous offline census.
    fn repair_drain(&mut self) -> Result<()> {
        for s in &mut self.shards {
            s.wait(&mut self.clk, |s| {
                let d = s.sh.dev();
                d.queue_space() == d.queue_depth()
            })?;
        }
        Ok(())
    }

    fn apply(
        &mut self,
        mut report: RepairReport,
        plans: Vec<RepairPlan>,
        fixes: Vec<Vec<super::check::Correction>>,
        deep: bool,
    ) -> Result<RepairReport> {
        // the census lists the shards in superblock order: match by index, never by position
        let mut ordered = Vec::with_capacity(self.shards.len());
        for s in &self.shards {
            match plans.iter().find(|p| p.shard == s.idx) {
                Some(p) => ordered.push(p),
                None => {
                    report.refused = true;
                    report.after.push(format!(
                        "shard {}: missing from the ownership census: {UNREPAIRABLE}",
                        s.idx
                    ));
                    return Ok(report);
                }
            }
        }
        for ((s, records), plan) in self.shards.iter_mut().zip(fixes).zip(ordered) {
            for batch in plan.leaks.chunks(FREES_PER_TXN) {
                let mut t = Txn::new(0);
                t.frees.extend_from_slice(batch);
                attempt!(report, repair_txn(s, &mut self.clk, t, true));
                report.actions.extend(
                    batch
                        .iter()
                        .map(|(b, n)| format!("shard {}: freed leaked blocks {b}+{n}", s.idx)),
                );
            }
            for (m, key, value) in records {
                let mut t = Txn::new(0);
                t.put(&key, &value);
                attempt!(report, repair_txn(s, &mut self.clk, t, false));
                report
                    .actions
                    .push(format!("shard {}: rewrote from recount: {m}", s.idx));
            }
            if plan.used_counter.is_some() || plan.meta_counter.is_some() {
                // a checkpoint writes the root counters from the allocator and meta bitmap; an idle shard skips it
                // unless something was logged since the last one
                attempt!(report, repair_txn(s, &mut self.clk, Txn::new(0), true));
                attempt!(report, s.checkpoint(&mut self.clk));
                if let Some((old, _)) = plan.used_counter {
                    report.actions.push(format!(
                        "shard {}: root usage counter {old} -> {}",
                        s.idx,
                        s.sh.state().alloc.n_alloc()
                    ));
                }
                if let Some((old, _)) = plan.meta_counter {
                    report.actions.push(format!(
                        "shard {}: root meta page counter {old} recounted",
                        s.idx
                    ));
                }
            }
        }
        attempt!(report, self.checkpoint());
        attempt!(report, self.repair_drain());
        let refs = super::onode::fsck_refs;
        if let Err(e) = crate::fsck::fsck(self.shards[0].sh.dev(), &mut self.clk, Some(&refs)) {
            report.after.push(e);
        }
        let checked = attempt!(report, self.check(deep));
        report.after.extend(checked.errors);
        Ok(report)
    }
}

/// Correct ownership before reclaiming anything; every correction is an ordinary durable txn, an interrupted one is
/// found again by the next census. Old physical blocks are never freed here: the second census reclaims what is no
/// longer referenced.
fn repair_owners<D: BlockDev, C: Clock>(
    s: &mut super::ShardStore<D>,
    clk: &mut C,
    plan: &RepairPlan,
    actions: &mut Vec<String>,
) -> Result<()> {
    let piece = (s.sh.pre_piece() / BLK) as u64;
    // False frees: the fenced blocks become allocated through the already-durable extent path of a txn (no payload
    // write; replay checks the recorded crcs against the unchanged bytes).
    for &(b, n) in &plan.missing {
        let end = b + u64::from(n);
        let mut at = b;
        while at < end {
            let first = at;
            let mut claim = Vec::new();
            while at < end && claim.len() < CLAIMS_PER_TXN {
                let k = (end - at).min(piece) as u32;
                let data = s.read_runs(clk, &[(at, k)])?;
                let crcs = block_crcs(at, &data[0]);
                claim.push(crate::state::Extent {
                    blk: at,
                    nblk: k,
                    crcs,
                });
                at += u64::from(k);
            }
            let mut t = Txn::new(0);
            t.olsm = Some(claim);
            repair_txn(s, clk, t, false)?;
            actions.push(format!(
                "shard {}: allocated false-free blocks {first}+{}",
                s.idx,
                at - first
            ));
        }
    }
    // Aliases: the owner gets a private copy of the bytes it reads today; allocation, copy and repoint are one txn.
    for key in &plan.relocate {
        let mut value = Vec::new();
        s.tget(clk, key, &mut value)?;
        let bad = || ObjError::Invalid(format!("owner {key:02x?}: no decodable extent"));
        let (mut ext, value_len) = if key.first() == Some(&T_EXT) {
            (Ext::decode(&value).ok_or_else(bad)?, None)
        } else {
            let (len, _) = vext(&value).ok_or_else(bad)?;
            (Ext::decode(&value[5..]).ok_or_else(bad)?, Some(len))
        };
        let old = ext.pba;
        let data = s.read_runs(clk, &[(old, ext.len())])?;
        if block_crcs(old, &data[0]) != ext.crcs {
            // the pre-check (object check with data checksums) refuses this before any write
            return Err(ObjError::Invalid(format!(
                "owner {key:02x?}: checksum mismatch; left unchanged"
            )));
        }
        let dest = s.sh.alloc_sys(ext.len())?;
        ext.pba = dest;
        ext.crcs = block_crcs(dest, &data[0]);
        let mut t = Txn::new(0);
        let encoded =
            value_len.map_or_else(|| ext.encode(), |len| vext_encode(len, dest, &ext.crcs));
        t.put(key, &encoded);
        for (i, bytes) in data[0].chunks(piece as usize * BLK).enumerate() {
            let mut buf = s.sh.alloc_buf(bytes.len() / BLK);
            buf.copy_from_slice(bytes);
            t.data.push((dest + i as u64 * piece, buf));
        }
        repair_txn(s, clk, t, false)?;
        actions.push(format!(
            "shard {}: relocated owner {key:02x?} blocks {old}+{} -> {dest}",
            s.idx,
            ext.len()
        ));
    }
    // Refcounts: changed records only. Records that overlap go into one txn (a crash never leaves a range with its old
    // record deleted and the new one missing); unrelated ranges are batched.
    if let Some((old, new)) = &plan.refs {
        let (os, ns): (HashSet<_>, HashSet<_>) = (old.iter().collect(), new.iter().collect());
        let puts: HashSet<u64> = new
            .iter()
            .filter(|r| !os.contains(r))
            .map(|r| r.0)
            .collect();
        let mut changes: Vec<(u64, u32, Option<u32>)> = old
            .iter()
            .filter(|r| !ns.contains(r) && !puts.contains(&r.0))
            .map(|&(b, n, _)| (b, n, None))
            .chain(
                new.iter()
                    .filter(|r| !os.contains(r))
                    .map(|&(b, n, c)| (b, n, Some(c))),
            )
            .collect();
        changes.sort_unstable();
        let mut t = Txn::new(0);
        let (mut done, mut reach) = (Vec::new(), 0u64);
        for (b, n, put) in changes {
            if done.len() >= REF_OPS_PER_TXN && b >= reach {
                repair_txn(s, clk, std::mem::replace(&mut t, Txn::new(0)), false)?;
                actions.append(&mut done);
            }
            match put {
                Some(c) => {
                    t.put(&ref_key(b), &ref_encode(n, c));
                    done.push(format!("shard {}: refcount {b}+{n} set to {c}", s.idx));
                }
                None => {
                    t.del(&ref_key(b));
                    done.push(format!("shard {}: refcount {b}+{n} removed", s.idx));
                }
            }
            reach = reach.max(b + u64::from(n));
        }
        if !done.is_empty() {
            repair_txn(s, clk, t, false)?;
            actions.append(&mut done);
        }
    }
    Ok(())
}

/// Per-block crcs (seeded with the physical block address) of `data` stored at `pba`.
fn block_crcs(pba: u64, data: &[u8]) -> Vec<u32> {
    data.chunks(BLK)
        .enumerate()
        .map(|(i, b)| crate::codec::blk_crc(pba + i as u64, b))
        .collect()
}

/// Submit one system txn (it may use the system reserves: a repair must work on a full device; `shrink`: frees only,
/// every reserve) and wait until it is durable.
fn repair_txn<D: BlockDev, C: Clock>(
    s: &mut super::ShardStore<D>,
    clk: &mut C,
    mut t: Txn<D::Buf>,
    shrink: bool,
) -> Result<()> {
    t.sys = true;
    t.shrink = shrink;
    let lsn = loop {
        match s.sh.submit(t) {
            Ok(lsn) => break lsn,
            Err((StoreError::Miss | StoreError::Busy | StoreError::WalFull, back)) => {
                t = back;
                s.miss_wait(clk)?;
            }
            Err((e, _)) => return Err(e.into()),
        }
    };
    s.wait(clk, |s| s.sh.durable_lsn() >= lsn)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The RocksDB omap engine is refused from the superblock bit alone; native engines are repairable.
    #[test]
    fn rocksdb_omap_engine_is_refused() {
        assert!(refuse_engine(crate::layout::FEAT_OMAP_ROCKSDB).is_some());
        assert!(refuse_engine(crate::layout::FEAT_OMAP_ROCKSDB | 1).is_some());
        assert!(refuse_engine(0).is_none());
        assert!(refuse_engine(!crate::layout::FEAT_OMAP_ROCKSDB).is_none());
    }
}
