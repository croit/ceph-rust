// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Lab / test backends of [`BlockSink`] + [`ChunkRead`] (feature `lab`, tests): [`MemBlocks`] (RAM, for
//! microbenchmarks and write-amplification sims) and [`SimBlocks`] (the store's [`SimDev`] with its crash and
//! corruption injection, driven synchronously by a [`SimClock`]).

use super::{BlockSink, ChunkRead};
use crate::dev::{BlockDev, Clock, SimClock, SimDev};
use crate::{BLK, StoreError};
use bytes::Bytes;
use std::collections::BTreeMap;

/// RAM block store: extents as written, bump allocation, byte counters.
#[derive(Debug, Default)]
pub struct MemBlocks {
    ext: BTreeMap<u64, Bytes>,
    next: u64,
    /// Bytes written / read through the traits.
    pub written: u64,
    pub read: u64,
    /// Read calls.
    pub reads: u64,
    /// Blocks currently allocated.
    pub live_blocks: u64,
}

impl MemBlocks {
    pub fn new() -> MemBlocks {
        MemBlocks::default()
    }
    /// Release an extent (after a merge was installed).
    pub fn free(&mut self, blk: u64, nblk: u32) {
        self.ext.remove(&blk).expect("free of an unknown extent");
        self.live_blocks -= nblk as u64;
    }
}

impl BlockSink for MemBlocks {
    fn alloc(&mut self, nblk: u32) -> Result<u64, StoreError> {
        let b = self.next;
        self.next += nblk as u64;
        self.live_blocks += nblk as u64;
        Ok(b)
    }
    fn write(&mut self, blk: u64, data: Vec<u8>, _crcs: &[u32]) -> Result<(), StoreError> {
        debug_assert_eq!(data.len() % BLK, 0);
        self.written += data.len() as u64;
        self.ext.insert(blk, Bytes::from(data));
        Ok(())
    }
    fn sync(&mut self) -> Result<(), StoreError> {
        Ok(())
    }
}

impl ChunkRead for MemBlocks {
    fn read(&mut self, blk: u64, nblk: u32) -> Result<Bytes, StoreError> {
        let (start, b) = self
            .ext
            .range(..=blk)
            .next_back()
            .ok_or(StoreError::Invalid("read of an unwritten extent"))?;
        let off = (blk - start) as usize * BLK;
        let len = nblk as usize * BLK;
        if off + len > b.len() {
            return Err(StoreError::Invalid("read beyond the written extent"));
        }
        self.read += len as u64;
        self.reads += 1;
        Ok(b.slice(off..off + len))
    }
}

/// [`SimDev`] block store: blocks `[base, end)` leased by bump allocation; IO split at the device transfer limit;
/// `sync` and `read` drive the device to completion on a virtual clock.
#[derive(Debug)]
pub struct SimBlocks {
    pub dev: SimDev,
    pub clk: SimClock,
    next: u64,
    end: u64,
    lbas_per_blk: u64,
    max_blks: usize,
    inflight: usize,
    tag: u64,
}

impl SimBlocks {
    pub fn new(dev: SimDev, base: u64, end: u64) -> SimBlocks {
        let g = dev.geometry();
        let lbas_per_blk = crate::dev::lbas_per_blk(&g);
        SimBlocks {
            max_blks: crate::dev::max_xfer_blks(&g) as usize,
            dev,
            clk: SimClock::default(),
            next: base,
            end,
            lbas_per_blk,
            inflight: 0,
            tag: 0,
        }
    }

    fn step(&mut self, out: &mut Vec<crate::dev::Completion<Vec<u8>>>) -> Result<(), StoreError> {
        if self.dev.is_dead() {
            return Err(StoreError::Failed);
        }
        let h = self.dev.next_deadline();
        self.clk.idle(h);
        self.dev.poll(self.clk.now(), out);
        for c in out.iter() {
            c.result.map_err(StoreError::Io)?;
        }
        Ok(())
    }

    fn submit(&mut self, write: bool, blk: u64, buf: Vec<u8>) -> Result<(), StoreError> {
        let lba = blk * self.lbas_per_blk;
        self.tag += 1;
        let mut buf = buf;
        loop {
            let r = if write {
                self.dev.submit_write(lba, buf, self.tag)
            } else {
                self.dev.submit_read(lba, buf, self.tag)
            };
            match r {
                Ok(()) => {
                    self.inflight += 1;
                    return Ok(());
                }
                Err(rej) if rej.err == crate::dev::SubmitError::QueueFull => {
                    buf = rej.buf.expect("rejected buffer");
                    let mut out = Vec::new();
                    self.step(&mut out)?;
                    self.inflight -= out.len();
                }
                Err(_) => return Err(StoreError::Failed),
            }
        }
    }
}

impl BlockSink for SimBlocks {
    fn alloc(&mut self, nblk: u32) -> Result<u64, StoreError> {
        if self.next + nblk as u64 > self.end {
            return Err(StoreError::NoSpace);
        }
        self.next += nblk as u64;
        Ok(self.next - nblk as u64)
    }
    fn write(&mut self, blk: u64, data: Vec<u8>, _crcs: &[u32]) -> Result<(), StoreError> {
        for (i, part) in data.chunks(self.max_blks * BLK).enumerate() {
            self.submit(true, blk + (i * self.max_blks) as u64, part.to_vec())?;
        }
        Ok(())
    }
    fn sync(&mut self) -> Result<(), StoreError> {
        while self.inflight > 0 {
            let mut out = Vec::new();
            self.step(&mut out)?;
            self.inflight -= out.len();
        }
        Ok(())
    }
}

impl ChunkRead for SimBlocks {
    fn read(&mut self, blk: u64, nblk: u32) -> Result<Bytes, StoreError> {
        self.sync()?;
        let mut v = Vec::with_capacity(nblk as usize * BLK);
        let mut b = blk;
        let end = blk + nblk as u64;
        while b < end {
            let n = (end - b).min(self.max_blks as u64);
            let buf = self.dev.alloc_buf(n as usize * BLK);
            self.submit(false, b, buf)?;
            let mut got = None;
            while got.is_none() {
                let mut out = Vec::new();
                self.step(&mut out)?;
                self.inflight -= out.len();
                got = out
                    .into_iter()
                    .find(|c| c.tag == self.tag)
                    .and_then(|c| c.buf);
            }
            v.extend_from_slice(&got.expect("read buffer"));
            b += n;
        }
        Ok(Bytes::from(v))
    }
}
