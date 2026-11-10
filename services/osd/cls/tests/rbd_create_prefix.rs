// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `rbd create`: any non-ENOENT outcome of the object_prefix read maps to EEXIST (cls_rbd.md A.9 B3).
use cls::ClsConfig;
use cls::ctx::{ClsCtx, OmapMap, Origin, Stat, Watcher};
use cls::errno::*;
use cls::mem::{MemCtx, MemStore};
use cls::rbd::header;
use denc::types::UTime;
use std::collections::BTreeMap;

const HDR: &str = "rbd_header.prefix-test";

fn create_input() -> Vec<u8> {
    let pfx = b"rbd_data.prefix-test";
    let mut v = vec![0u8; 8]; // size 0
    v.push(22); // order
    v.extend(0u64.to_le_bytes()); // features
    v.extend((pfx.len() as u32).to_le_bytes());
    v.extend(pfx);
    v
}

/// Test-side fault injection: delegates to `MemCtx`, fails the `object_prefix` omap read with EIO.
struct EioPrefix(MemCtx);

impl ClsCtx for EioPrefix {
    fn origin(&self) -> Origin {
        self.0.origin()
    }
    fn now(&self) -> UTime {
        self.0.now()
    }
    fn client_features(&self) -> u64 {
        self.0.client_features()
    }
    fn osd_features(&self) -> u64 {
        self.0.osd_features()
    }
    fn require_osd_release(&self) -> u8 {
        self.0.require_osd_release()
    }
    fn current_version(&self) -> u64 {
        self.0.current_version()
    }
    fn random_bytes(&mut self, out: &mut [u8]) {
        self.0.random_bytes(out)
    }
    fn snapset_seq(&mut self) -> Result<u64, Errno> {
        self.0.snapset_seq()
    }
    fn list_watchers(&mut self) -> Result<Vec<Watcher>, Errno> {
        self.0.list_watchers()
    }
    fn subop_num(&self) -> u32 {
        self.0.subop_num()
    }
    fn config(&self) -> ClsConfig {
        self.0.config()
    }
    fn stat(&mut self) -> Result<Stat, Errno> {
        self.0.stat()
    }
    fn read(&mut self, off: u64, len: u64) -> Result<Vec<u8>, Errno> {
        self.0.read(off, len)
    }
    fn create(&mut self, excl: bool) -> Result<(), Errno> {
        self.0.create(excl)
    }
    fn remove(&mut self) -> Result<(), Errno> {
        self.0.remove()
    }
    fn write(&mut self, off: u64, data: &[u8]) -> Result<(), Errno> {
        self.0.write(off, data)
    }
    fn write_full(&mut self, data: &[u8]) -> Result<(), Errno> {
        self.0.write_full(data)
    }
    fn truncate(&mut self, size: u64) -> Result<(), Errno> {
        self.0.truncate(size)
    }
    fn zero(&mut self, off: u64, len: u64) -> Result<(), Errno> {
        self.0.zero(off, len)
    }
    fn getxattr(&mut self, name: &str) -> Result<Vec<u8>, Errno> {
        self.0.getxattr(name)
    }
    fn setxattr(&mut self, name: &str, value: &[u8]) -> Result<(), Errno> {
        self.0.setxattr(name, value)
    }
    fn getxattr_raw(&mut self, name: &[u8]) -> Result<Vec<u8>, Errno> {
        self.0.getxattr_raw(name)
    }
    fn getxattrs_raw(&mut self) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, Errno> {
        self.0.getxattrs_raw()
    }
    fn setxattr_raw(&mut self, name: &[u8], value: &[u8]) -> Result<(), Errno> {
        self.0.setxattr_raw(name, value)
    }
    fn omap_get_val(&mut self, key: &[u8]) -> Result<Vec<u8>, Errno> {
        if key == b"object_prefix" {
            return Err(EIO);
        }
        self.0.omap_get_val(key)
    }
    fn omap_get_vals_by_keys(&mut self, keys: &[&[u8]]) -> Result<OmapMap, Errno> {
        self.0.omap_get_vals_by_keys(keys)
    }
    fn omap_get_vals(
        &mut self,
        start_after: &[u8],
        filter_prefix: &[u8],
        max: u64,
    ) -> Result<(OmapMap, bool), Errno> {
        self.0.omap_get_vals(start_after, filter_prefix, max)
    }
    fn omap_get_keys(
        &mut self,
        start_after: &[u8],
        max: u64,
    ) -> Result<(Vec<Vec<u8>>, bool), Errno> {
        self.0.omap_get_keys(start_after, max)
    }
    fn omap_get_header(&mut self) -> Result<Vec<u8>, Errno> {
        self.0.omap_get_header()
    }
    fn omap_set(&mut self, entries: &[(&[u8], &[u8])]) -> Result<(), Errno> {
        self.0.omap_set(entries)
    }
    fn omap_set_header(&mut self, header: &[u8]) -> Result<(), Errno> {
        self.0.omap_set_header(header)
    }
    fn omap_remove_key(&mut self, key: &[u8]) -> Result<(), Errno> {
        self.0.omap_remove_key(key)
    }
    fn omap_remove_range(&mut self, begin: &[u8], end: &[u8]) -> Result<(), Errno> {
        self.0.omap_remove_range(begin, end)
    }
    fn omap_clear(&mut self) -> Result<(), Errno> {
        self.0.omap_clear()
    }
}

#[test]
fn create_maps_object_prefix_read_errors_to_eexist() {
    let store = MemStore::new();
    let mut c = EioPrefix(store.begin(HDR));
    assert_eq!(
        header::create(&mut c, &create_input()),
        Err(EEXIST),
        "EIO -> EEXIST"
    );
    assert!(store.obj(HDR).is_none(), "no object created");
}

#[test]
fn create_on_absent_object_succeeds() {
    let mut store = MemStore::new();
    assert_eq!(store.call(HDR, "rbd", "create", &create_input()).ret, 0);
    assert!(store.obj(HDR).is_some());
    assert!(store.omap_get(HDR, "object_prefix").is_some());
    assert_eq!(store.omap_u64(HDR, "size"), Some(0));
}
