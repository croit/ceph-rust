// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `kernel:` devices outside Linux: the types exist (so callers need no extra cfg), opening always fails.

use crate::{BlockDev, Completion, Geometry, IoBuf, Nanos, Submit};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Direct,
    Cmd,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Mode::Direct => "direct",
            Mode::Cmd => "cmd",
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Never {}

pub fn active() -> bool {
    false
}
pub fn flush() {}
pub fn thread_ring_fd() -> std::io::Result<i32> {
    Err(std::io::ErrorKind::Unsupported.into())
}
pub fn thread_ready() -> bool {
    false
}
pub fn thread_stats() -> (u64, u64) {
    (0, 0)
}
pub fn pool_counters() -> Vec<(String, u64)> {
    Vec::new()
}
pub fn arena_info() -> Option<(usize, bool, usize)> {
    None
}
pub fn arena_range() -> Option<(u64, u64)> {
    None
}
pub fn nodes_of_pci(_bdf: &str, _nsid: u32) -> Result<(PathBuf, PathBuf), String> {
    Err("kernel: devices need Linux".into())
}

#[derive(Clone, Debug)]
pub struct KernelCtrl(Never);

impl KernelCtrl {
    pub fn open(_path: &Path) -> Result<KernelCtrl, String> {
        Err("kernel: devices need Linux".into())
    }
    pub fn geometry(&self) -> Geometry {
        match self.0 {}
    }
    pub fn mode(&self) -> Mode {
        match self.0 {}
    }
    pub fn nsid(&self) -> u32 {
        match self.0 {}
    }
    pub fn path(&self) -> &Path {
        match self.0 {}
    }
    pub fn probe_path(&self) -> &Path {
        match self.0 {}
    }
    /// blk-mq tags per hardware queue: no device on this host, no queues.
    pub fn tags(&self) -> u32 {
        match self.0 {}
    }
    pub fn missing(&self) -> Vec<&'static str> {
        match self.0 {}
    }
    /// Passthrough DSM probe of a cmd namespace (Linux only: it needs io_uring command passthrough).
    pub fn probe_dsm_at_mkfs(&self) -> Result<Option<bool>, String> {
        match self.0 {}
    }
    /// Superblock DSM verdict at store mount (Linux only).
    pub fn apply_dsm_verdict(&self, _v: Option<bool>) {
        match self.0 {}
    }
    pub fn open_queue(&self, _depth: u32) -> KernelDev {
        match self.0 {}
    }
}

#[derive(Debug)]
pub struct KBuf(Never);

impl IoBuf for KBuf {
    fn len(&self) -> usize {
        match self.0 {}
    }
    fn as_slice(&self) -> &[u8] {
        match self.0 {}
    }
    fn as_mut_slice(&mut self) -> &mut [u8] {
        match self.0 {}
    }
}

#[derive(Debug)]
pub struct KernelDev(Never);

impl BlockDev for KernelDev {
    type Buf = KBuf;
    fn geometry(&self) -> Geometry {
        match self.0 {}
    }
    fn alloc_buf(&mut self, _len: usize) -> KBuf {
        match self.0 {}
    }
    fn queue_space(&self) -> usize {
        match self.0 {}
    }
    fn queue_depth(&self) -> usize {
        match self.0 {}
    }
    fn submit_write(&mut self, _lba: u64, _buf: KBuf, _tag: u64) -> Submit<KBuf> {
        match self.0 {}
    }
    fn submit_read(&mut self, _lba: u64, _buf: KBuf, _tag: u64) -> Submit<KBuf> {
        match self.0 {}
    }
    fn submit_deallocate(&mut self, _ranges: &[(u64, u32)], _tag: u64) -> Submit<KBuf> {
        match self.0 {}
    }
    fn submit_write_zeroes(&mut self, _lba: u64, _nlba: u32, _tag: u64) -> Submit<KBuf> {
        match self.0 {}
    }
    fn poll(&mut self, _now: Nanos, _out: &mut Vec<Completion<KBuf>>) -> usize {
        match self.0 {}
    }
}
