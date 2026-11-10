// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! DEV ONLY: [`DevMemStore`], the PG object store used until the NVMe store (crates/store) is wired
//! in. Everything lives in RAM and is LOST on restart: a restarted OSD comes up with no PGs and
//! claims nothing (peers see it as an empty OSD and recover/backfill it). Acks given while running
//! are therefore NOT durable; never use against data you care about.
use denc::types::{Eversion, Hobject, SpgT};
use peering::{MemStore, PersistedPg, PgStoreOps, StoreReadError, StoreTxn};
use replwire::{ObjectRecoveryInfo, ObjectRecoveryProgress, PushOp};

/// Non-persistent [`PgStoreOps`] (wraps `peering::MemStore`).
#[derive(Debug, Default)]
pub struct DevMemStore(MemStore);

impl DevMemStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }
    /// Number of PGs held.
    pub fn num_pgs(&self) -> usize {
        self.0.pgs.len()
    }
}

impl PgStoreOps for DevMemStore {
    fn list_temps(&self, spg: SpgT) -> Vec<Hobject> {
        self.0.list_temps(spg)
    }
    fn list_pgs(&self) -> Vec<SpgT> {
        self.0.list_pgs()
    }
    fn load_pg(&self, spg: SpgT) -> Option<PersistedPg> {
        self.0.load_pg(spg)
    }
    fn submit(&mut self, spg: SpgT, txn: &StoreTxn) {
        self.0.submit(spg, txn);
    }
    fn recovery_info_checked(
        &self,
        spg: SpgT,
        soid: &Hobject,
    ) -> Result<ObjectRecoveryInfo, StoreReadError> {
        self.0.recovery_info_checked(spg, soid)
    }
    fn build_push(
        &self,
        spg: SpgT,
        ri: &ObjectRecoveryInfo,
        before: &ObjectRecoveryProgress,
        max_chunk: u64,
        max_omap_entries: usize,
    ) -> Result<PushOp, StoreReadError> {
        self.0
            .build_push(spg, ri, before, max_chunk, max_omap_entries)
    }
    fn list_objects(
        &self,
        spg: SpgT,
        begin: &Hobject,
        min: usize,
        max: usize,
    ) -> Result<peering::ObjListing, StoreReadError> {
        self.0.list_objects(spg, begin, min, max)
    }
    fn object_version(&self, spg: SpgT, soid: &Hobject) -> Result<Eversion, StoreReadError> {
        self.0.object_version(spg, soid)
    }
    fn omap_keys_over(&self, spg: SpgT, soid: &Hobject, limit: u64) -> Option<bool> {
        self.0.omap_keys_over(spg, soid, limit)
    }
    fn object_stats(&self, spg: SpgT) -> (u64, u64) {
        self.0.object_stats(spg)
    }
    fn snapmap_next(
        &self,
        spg: SpgT,
        snap: u64,
        max: usize,
    ) -> Result<Vec<Hobject>, StoreReadError> {
        self.0.snapmap_next(spg, snap, max)
    }
    fn snapmap_get(&self, spg: SpgT, clone: &Hobject) -> Option<Vec<u64>> {
        self.0.snapmap_get(spg, clone)
    }
    fn snapmap_get_checked(
        &self,
        spg: SpgT,
        clone: &Hobject,
    ) -> Result<Option<Vec<u64>>, StoreReadError> {
        self.0.snapmap_get_checked(spg, clone)
    }
    fn snapmap_scan(
        &self,
        spg: SpgT,
        from: &[u8],
        max: usize,
    ) -> Result<(Vec<u64>, Option<Vec<u8>>), StoreReadError> {
        self.0.snapmap_scan(spg, from, max)
    }
    fn snapmap_check(
        &self,
        spg: SpgT,
        start: &Hobject,
        end: &Hobject,
    ) -> (Vec<peering::snaps::MapOp>, Vec<String>) {
        self.0.snapmap_check(spg, start, end)
    }
    fn snapmap_key_scan(&self, spg: SpgT) -> Vec<String> {
        self.0.snapmap_key_scan(spg)
    }
    fn build_scrub_map(
        &self,
        spg: SpgT,
        start: &Hobject,
        end: &Hobject,
        deep: bool,
        max_objects: usize,
        max_bytes: u64,
    ) -> peering::ScrubPart {
        self.0
            .build_scrub_map(spg, start, end, deep, max_objects, max_bytes)
    }
}

impl opexec::ObjView for DevMemStore {
    fn ov_stat(&self, spg: SpgT, soid: &Hobject) -> Result<Option<u64>, i32> {
        self.0.ov_stat(spg, soid)
    }
    fn ov_read(&self, spg: SpgT, soid: &Hobject, off: u64, len: u64) -> Result<Vec<u8>, i32> {
        self.0.ov_read(spg, soid, off, len)
    }
    fn ov_read_crc(
        &self,
        spg: SpgT,
        soid: &Hobject,
        off: u64,
        len: u64,
    ) -> Result<(Vec<u8>, Option<u32>), i32> {
        self.0.ov_read_crc(spg, soid, off, len)
    }
    fn ov_read_shared(
        &self,
        spg: SpgT,
        soid: &Hobject,
        off: u64,
        len: u64,
    ) -> Result<Vec<(bytes::Bytes, Option<u32>)>, i32> {
        self.0.ov_read_shared(spg, soid, off, len)
    }

    fn ov_read_shared_verified(
        &self,
        spg: SpgT,
        soid: &Hobject,
        off: u64,
        len: u64,
    ) -> Result<opexec::view::VerifiedRead, i32> {
        self.0.ov_read_shared_verified(spg, soid, off, len)
    }
    fn ov_getattr(&self, spg: SpgT, soid: &Hobject, name: &[u8]) -> Result<Option<Vec<u8>>, i32> {
        self.0.ov_getattr(spg, soid, name)
    }
    fn ov_getattr_pair(
        &self,
        spg: SpgT,
        soid: &Hobject,
        a: &[u8],
        b: &[u8],
    ) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>), i32> {
        self.0.ov_getattr_pair(spg, soid, a, b)
    }
    fn ov_getattrs(
        &self,
        spg: SpgT,
        soid: &Hobject,
    ) -> Result<std::collections::BTreeMap<Vec<u8>, Vec<u8>>, i32> {
        self.0.ov_getattrs(spg, soid)
    }
    fn ov_omap_header(&self, spg: SpgT, soid: &Hobject) -> Result<Vec<u8>, i32> {
        self.0.ov_omap_header(spg, soid)
    }
    fn ov_omap_range(
        &self,
        spg: SpgT,
        soid: &Hobject,
        after: Option<&[u8]>,
        prefix: &[u8],
        max: usize,
        max_bytes: usize,
    ) -> Result<(Vec<opexec::view::Kv>, bool), i32> {
        self.0
            .ov_omap_range(spg, soid, after, prefix, max, max_bytes)
    }
    fn ov_omap_keys_range(
        &self,
        spg: SpgT,
        soid: &Hobject,
        after: Option<&[u8]>,
        prefix: &[u8],
        max: usize,
        max_bytes: usize,
    ) -> Result<(Vec<Vec<u8>>, bool), i32> {
        self.0
            .ov_omap_keys_range(spg, soid, after, prefix, max, max_bytes)
    }
    fn ov_omap_get(
        &self,
        spg: SpgT,
        soid: &Hobject,
        keys: &[&[u8]],
    ) -> Result<std::collections::BTreeMap<Vec<u8>, Vec<u8>>, i32> {
        self.0.ov_omap_get(spg, soid, keys)
    }
    fn ov_list(
        &self,
        spg: SpgT,
        begin: &Hobject,
        max: usize,
    ) -> Result<(Vec<Hobject>, Hobject), i32> {
        self.0.ov_list(spg, begin, max)
    }
}
