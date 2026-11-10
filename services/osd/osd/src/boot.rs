// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! MOSDBoot metadata (spec 3.3, 13; ADR 0019).
use crate::backend::Backend;
use crate::osd::{Osd, addrs_str};
use crate::version;
use std::collections::BTreeMap;
use std::path::Path;

impl<B: Backend> Osd<B> {
    /// Metadata map sent in MOSDBoot and stored verbatim by the mon (`osd metadata`).
    pub(crate) fn boot_metadata(&self) -> BTreeMap<String, String> {
        let mut m: BTreeMap<String, String> = self.cfg.sys_metadata.clone();
        let mut set = |k: &str, v: String| {
            m.insert(k.to_owned(), v);
        };
        set("hostname", self.cfg.hostname.clone());
        set("ceph_version", version::ceph_version_pretty());
        set("ceph_version_short", version::CEPH_VERSION_SHORT.to_owned());
        set("ceph_release", version::CEPH_RELEASE.to_owned());
        set(
            "ceph_version_when_created",
            if self.id.ceph_version_when_created.is_empty() {
                version::ceph_version_pretty()
            } else {
                self.id.ceph_version_when_created.clone()
            },
        );
        set("created_at", self.id.created_at.clone());
        set("osd_objectstore", self.store_id.as_str().into());
        set("osd_data", self.cfg.data_path.clone());
        set("osdspec_affinity", String::new());
        set("flashstore_version", version::FLASHSTORE_VERSION.to_owned());
        set("flashstore_build", "dev".into());
        // peers gate long object names on this (adr 0021 am. 30, OQ 29); absent = an older build = no
        set(
            "flashstore_long_names",
            if crate::nvmestore::long_names_supported() {
                "1"
            } else {
                "0"
            }
            .into(),
        );
        let sf = crate::nvmestore::store_features();
        if sf != 0 {
            set(
                "flashstore_store_features",
                store::layout::feature_names(sf).join(","),
            );
        }
        set("front_addr", addrs_str(&self.public_addrs));
        set("back_addr", addrs_str(&self.cluster_addrs));
        set("hb_front_addr", addrs_str(&self.hb_front_addrs));
        set("hb_back_addr", addrs_str(&self.hb_back_addrs));
        // interface names come from the driver (sys_metadata): kernel iface (knet)
        for k in ["front_iface", "back_iface"] {
            if !self.cfg.sys_metadata.contains_key(k) {
                set(k, String::new());
            }
        }
        set("rotational", "0".into());
        set("journal_rotational", "0".into());
        set("default_device_class", "nvme".into());
        // device identity (classic: `devices` = names, `device_ids` = name=ID pairs, `device_paths` = name=path pairs;
        // mgr builds `ceph device ls` from them). Name = kernel block name on the kernel tier, PCI address on the SPDK tier (no kernel name).
        let dm = nvme::health::device();
        let (name, id, path) = dm.as_ref().map_or_else(Default::default, |d| {
            (d.name.clone(), d.ident.device_id(), d.path())
        });
        set("devices", name.clone());
        set(
            "device_ids",
            if id.is_empty() {
                String::new()
            } else {
                format!("{name}={id}")
            },
        );
        set(
            "device_paths",
            if path.is_empty() {
                String::new()
            } else {
                format!("{name}={path}")
            },
        );
        // device identity, geometry and the NUMA keys operator tooling reads (spec osd-lifecycle.md 3.3.1):
        // `ceph osd numa-status` and device inventories; unknown facts are omitted, never invented
        let cpus: Vec<usize> = crate::devmeta::placement_cpus(
            self.cfg
                .sys_metadata
                .get("flashstore_placement")
                .map(String::as_str),
        );
        let iface = |k: &str| {
            self.cfg
                .sys_metadata
                .get(k)
                .map(String::as_str)
                .unwrap_or("")
        };
        m.extend(crate::devmeta::keys(
            Path::new("/sys"),
            dm.as_ref(),
            &cpus,
            iface("front_iface"),
            iface("back_iface"),
            self.store_id,
        ));
        m
    }
}
