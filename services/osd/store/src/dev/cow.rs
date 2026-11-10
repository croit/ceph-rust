// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Read-only view of a device for checks that must not change it (`croit-flashstore-tool fsck`). A mount through the view
//! replays and checkpoints as usual, but writes, write-zeroes and deallocates land in a memory overlay shared by all
//! queues of the view and complete at once; reads see the overlay over the media. Nothing reaches the media, so a
//! check never commits a WAL cut (`--accept-wal-loss`) or a new epoch. Memory grows with the blocks the mount writes
//! (the post-replay checkpoint): a tool, never the OSD.

use super::{BlockDev, Completion, Geometry, IoBuf, Nanos, Op, Rejected, Submit, SubmitError};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

/// LBA -> content written through the view (`None`: zeroes, from write-zeroes or deallocate).
pub type Overlay = Rc<RefCell<HashMap<u64, Option<Box<[u8]>>>>>;

/// One queue of a read-only view; all queues of one view share its [`Overlay`].
#[derive(Debug)]
pub struct CowDev<D: BlockDev> {
    inner: D,
    over: Overlay,
    lba: usize,
    lba_count: u64,
    /// Completions of overlay-only commands, handed out by the next `poll`.
    done: Vec<Completion<D::Buf>>,
    /// Reads in flight on the media `(tag, lba)`: the overlay is laid over them at completion.
    reads: Vec<(u64, u64)>,
}

impl<D: BlockDev> CowDev<D> {
    pub fn new(inner: D, over: Overlay) -> CowDev<D> {
        let g = inner.geometry();
        CowDev {
            inner,
            over,
            lba: g.lba_size as usize,
            lba_count: g.lba_count,
            done: Vec::new(),
            reads: Vec::new(),
        }
    }

    fn range_ok(&self, lba: u64, nlba: u64) -> bool {
        nlba > 0 && lba.checked_add(nlba).is_some_and(|e| e <= self.lba_count)
    }

    fn put(&mut self, lba: u64, nlba: u64, data: Option<&[u8]>) {
        let mut o = self.over.borrow_mut();
        for i in 0..nlba {
            let v = data.map(|d| {
                d[i as usize * self.lba..(i as usize + 1) * self.lba]
                    .to_vec()
                    .into_boxed_slice()
            });
            o.insert(lba + i, v);
        }
    }
}

impl<D: BlockDev> BlockDev for CowDev<D> {
    type Buf = D::Buf;

    fn geometry(&self) -> Geometry {
        self.inner.geometry()
    }
    fn alloc_buf(&mut self, len: usize) -> Self::Buf {
        self.inner.alloc_buf(len)
    }
    fn alloc_buf_uninit(&mut self, len: usize) -> Self::Buf {
        self.inner.alloc_buf_uninit(len)
    }
    fn try_alloc_buf_uninit(&mut self, len: usize) -> Option<Self::Buf> {
        self.inner.try_alloc_buf_uninit(len)
    }
    fn try_alloc_io_uninit(&mut self, len: usize) -> Option<Self::Buf> {
        self.inner.try_alloc_io_uninit(len)
    }
    fn release_pooled(&mut self) {
        self.inner.release_pooled()
    }
    fn ram_reads(&self) -> bool {
        self.inner.ram_reads()
    }
    fn alloc_buf_ram_uninit(&mut self, len: usize) -> Self::Buf {
        self.inner.alloc_buf_ram_uninit(len)
    }
    fn trim_ram(&mut self) {
        self.inner.trim_ram()
    }
    fn view_buf(&mut self, data: &bytes::Bytes) -> Option<Self::Buf> {
        self.inner.view_buf(data)
    }
    fn queue_space(&self) -> usize {
        self.inner.queue_space()
    }
    fn queue_depth(&self) -> usize {
        self.inner.queue_depth()
    }
    fn submit_write(&mut self, lba: u64, buf: Self::Buf, tag: u64) -> Submit<Self::Buf> {
        let n = (buf.len() / self.lba) as u64;
        if buf.len() % self.lba != 0 || !self.range_ok(lba, n) {
            return Err(Rejected {
                err: SubmitError::Invalid,
                buf: Some(buf),
            });
        }
        self.put(lba, n, Some(buf.as_slice()));
        self.done.push(Completion {
            tag,
            op: Op::Write,
            result: Ok(()),
            buf: Some(buf),
        });
        Ok(())
    }
    fn submit_read(&mut self, lba: u64, buf: Self::Buf, tag: u64) -> Submit<Self::Buf> {
        self.inner.submit_read(lba, buf, tag)?;
        self.reads.push((tag, lba));
        Ok(())
    }
    fn submits_at_flush(&self) -> bool {
        self.inner.submits_at_flush()
    }
    fn issue(&mut self) {
        self.inner.issue()
    }
    fn wait_hint(&mut self) -> Option<std::time::Duration> {
        if self.done.is_empty() {
            self.inner.wait_hint()
        } else {
            Some(std::time::Duration::ZERO)
        }
    }
    /// Read-only view: no runtime deallocate (`dealloc_limits` is off, the store never trims through it).
    fn submit_deallocate(&mut self, _ranges: &[(u64, u32)], _tag: u64) -> Submit<Self::Buf> {
        Err(Rejected {
            err: SubmitError::Unsupported,
            buf: None,
        })
    }
    fn deallocate_all(&mut self) -> Result<u64, String> {
        Err("read-only device view: no whole-device deallocate".into())
    }
    fn submit_write_zeroes(&mut self, lba: u64, nlba: u32, tag: u64) -> Submit<Self::Buf> {
        self.zero(lba, nlba, tag, Op::WriteZeroes)
    }
    fn poll(&mut self, now: Nanos, out: &mut Vec<Completion<Self::Buf>>) -> usize {
        let s = out.len();
        self.inner.poll(now, out);
        for c in &mut out[s..] {
            if c.op != Op::Read {
                continue;
            }
            let Some(i) = self.reads.iter().position(|r| r.0 == c.tag) else {
                continue;
            };
            let (_, lba) = self.reads.swap_remove(i);
            if let (Ok(()), Some(b)) = (c.result, c.buf.as_mut()) {
                let o = self.over.borrow();
                for (j, blk) in b.as_mut_slice().chunks_mut(self.lba).enumerate() {
                    match o.get(&(lba + j as u64)) {
                        Some(Some(d)) => blk.copy_from_slice(d),
                        Some(None) => blk.fill(0),
                        None => {}
                    }
                }
            }
        }
        out.append(&mut self.done);
        out.len() - s
    }
    fn next_deadline(&self) -> Option<Nanos> {
        if self.done.is_empty() {
            self.inner.next_deadline()
        } else {
            Some(0)
        }
    }
    fn is_dead(&self) -> bool {
        self.inner.is_dead()
    }
}

impl<D: BlockDev> CowDev<D> {
    fn zero(&mut self, lba: u64, nlba: u32, tag: u64, op: Op) -> Submit<D::Buf> {
        if !self.range_ok(lba, u64::from(nlba)) {
            return Err(Rejected {
                err: SubmitError::OutOfRange,
                buf: None,
            });
        }
        self.put(lba, u64::from(nlba), None);
        self.done.push(Completion {
            tag,
            op,
            result: Ok(()),
            buf: None,
        });
        Ok(())
    }
}
