// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Format upgrade step S7 (adr 0611): one shard's tree omap into the omap LSM engine (adr 0610), offline, resumable
//! without a cursor. Per batch: the first tree omap entries left (adr 0476 runs included) go into the engine's
//! memtable, the normal flush installs them as a run (manifest sys txn), then one txn removes exactly those entries
//! from the tree. The tree is the cursor: a crash before the removal is durable converts the batch again (a second run
//! with the same values, newest wins, merged away later); the removal's WAL record follows the manifest's, so it is
//! never durable without the run.

use super::shardio::ShardStore;
use super::stage::Stage;
use super::store::run_with;
use super::{ObjError, Result};
use crate::BLK;
use crate::dev::{BlockDev, Clock};

/// Data blocks a shard can still give the engine: free, held (free after a checkpoint) and reclaimable meta cells,
/// minus the floor sys txns keep (a third of the user floor).
pub(crate) fn avail_blocks<D: BlockDev>(s: &ShardStore<D>) -> u64 {
    let f = s.sh.statfs();
    (f.data_free + f.data_held + f.data_reclaim).saturating_sub(f.data_reserve / 3)
}

impl<D: BlockDev> ShardStore<D> {
    /// Tree omap entries left in this shard and their run entry bytes (adr 0611 S7 survey).
    pub(crate) fn upgrade_omap_survey<C: Clock>(&mut self, clk: &mut C) -> Result<(u64, u64)> {
        Stage::new(self, clk).upgrade_omap_survey()
    }

    /// Convert the shard's tree omap into engine runs (adr 0611 S7). The store is mounted for the upgrade (engine on,
    /// omap reads from the tree). `prog(entries, bytes)` after each batch. Ends with no tree omap and no adr 0476 run,
    /// checkpointed.
    pub(crate) fn upgrade_omap_convert<C: Clock>(
        &mut self,
        clk: &mut C,
        mut prog: impl FnMut(u64, u64),
    ) -> Result<()> {
        let budget = self.sh.olsm_batch_bytes().ok_or(ObjError::Invalid(
            "omap upgrade: the engine is not on".into(),
        ))?;
        loop {
            let mut t = Stage::new(self, clk).upgrade_omap_take(budget)?;
            if t.entries.is_empty() {
                break;
            }
            let (n, b) = (t.entries.len() as u64, t.bytes as u64);
            self.sh.olsm_upgrade_batch(std::mem::take(&mut t.entries))?;
            self.upgrade_wait_flushed(clk)?;
            staged(run_with(self, clk, 0, |st| st.upgrade_omap_drop(&t))?)?;
            prog(n, b);
        }
        Stage::new(self, clk).upgrade_omap_finish()?;
        self.checkpoint(clk)?;
        if !self.sh.state().runs.is_empty() {
            return Err(ObjError::Eio(
                "omap upgrade: adr 0476 runs left after the conversion".into(),
            ));
        }
        Ok(())
    }

    /// Wait until the engine installed the batch (run written, manifest txn submitted). Allocation waits of the
    /// engine are answered with a checkpoint (held blocks become free); waits again without more free blocks than at
    /// the previous checkpoint = the shard is full.
    fn upgrade_wait_flushed<C: Clock>(&mut self, clk: &mut C) -> Result<()> {
        let waits = |s: &Self| s.sh.olsm_stats().map_or(0, |x| x.alloc_waits);
        let mut seen = waits(self);
        let mut last_free: Option<u64> = None;
        loop {
            self.wait(clk, |s| s.sh.olsm_flushed() || waits(s) > seen)?;
            if self.sh.olsm_flushed() {
                return Ok(());
            }
            let before = avail_blocks(self);
            if last_free.is_some_and(|f| before <= f) {
                return Err(ObjError::NoSpace);
            }
            self.checkpoint(clk)?;
            last_free = Some(avail_blocks(self));
            seen = waits(self);
        }
    }
}

/// Run entry bytes in data blocks.
pub(crate) fn blocks_of(bytes: u64) -> u64 {
    bytes.div_ceil(BLK as u64)
}

/// `run_with` staged and submitted (`None` = compression bit needed: never for removals).
fn staged(r: Option<u64>) -> Result<()> {
    r.map(|_| ()).ok_or(ObjError::Invalid(
        "omap upgrade: removal txn wants compression".into(),
    ))
}
