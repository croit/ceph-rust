// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Device and NUMA identity keys of the boot metadata (spec osd-lifecycle.md 3.3.1, delta J-12): what operator
//! tooling reads from `ceph osd metadata` (device inventories) and `ceph osd numa-status`. Every key comes from a fact
//! this daemon owns (the NVMe identity it identified, sysfs of the kernel device, the CPU/iface placement); a fact that
//! is genuinely unknown is omitted, never invented.
use nvme::health::DevMeta;
use std::collections::BTreeMap;
use std::path::Path;

fn read(root: &Path, rel: &str) -> Option<String> {
    std::fs::read_to_string(root.join(rel))
        .ok()
        .map(|s| s.trim().to_owned())
}

fn read_num(root: &Path, rel: &str) -> Option<i64> {
    read(root, rel)?.parse().ok()
}

/// `numa_node` of a sysfs node: `-1`/absent means the kernel has no NUMA information.
fn numa_of(root: &Path, rel: &str) -> Option<i32> {
    match read_num(root, rel)? {
        n if n >= 0 && n <= i32::MAX as i64 => Some(n as i32),
        _ => None,
    }
}

/// NUMA node of a network interface: a kernel name through `/sys/class/net`.
fn iface_node(root: &Path, iface: &str) -> Option<i32> {
    if iface.is_empty() {
        return None;
    }
    numa_of(root, &format!("class/net/{iface}/device/numa_node"))
}

/// NUMA node of a kernel block device: NVMe exposes it on the controller, other devices on the parent.
fn dev_node(root: &Path, name: &str) -> Option<i32> {
    numa_of(root, &format!("class/block/{name}/device/numa_node"))
        .or_else(|| numa_of(root, &format!("class/block/{name}/device/device/numa_node")))
}

/// CPUs of `node` as a range list (`0-15,32-47`): every `cpuN/nodeN` under sysfs.
fn node_cpus(root: &Path, node: i32) -> Vec<usize> {
    let mut v: Vec<usize> = std::fs::read_dir(root.join("devices/system/cpu"))
        .map(|d| {
            d.flatten()
                .filter_map(|e| {
                    let name = e.file_name();
                    let n = name.to_str()?.strip_prefix("cpu")?.parse::<usize>().ok()?;
                    e.path().join(format!("node{node}")).exists().then_some(n)
                })
                .collect()
        })
        .unwrap_or_default();
    v.sort_unstable();
    v
}

/// Sorted CPU numbers as classic range text (`0-15,32`).
pub fn cpu_ranges(cpus: &[usize]) -> String {
    let mut v = cpus.to_vec();
    v.sort_unstable();
    v.dedup();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < v.len() {
        let start = v[i];
        let mut end = start;
        while i + 1 < v.len() && v[i + 1] == end + 1 {
            i += 1;
            end = v[i];
        }
        if start == end {
            out.push(start.to_string());
        } else {
            out.push(format!("{start}-{end}"));
        }
        i += 1;
    }
    out.join(",")
}

/// Classic set text of a sorted list (`{front_iface,back_iface}`); empty text for none.
fn set_text<S: AsRef<str>>(items: impl IntoIterator<Item = S>) -> String {
    let mut v: Vec<String> = items.into_iter().map(|s| s.as_ref().to_owned()).collect();
    v.sort();
    v.dedup();
    format!("{{{}}}", v.join(","))
}

/// `<prefix>_numa_nodes`, `<prefix>_numa_node` (only when every source reported one node and none is unknown) and
/// `unknown_key` (the sources without NUMA information).
fn numa_keys(
    put: &mut impl FnMut(&str, String),
    prefix: &str,
    nodes: &[i32],
    unknown: &[&str],
    unknown_key: &str,
) {
    if !nodes.is_empty() {
        put(
            &format!("{prefix}_numa_nodes"),
            nodes
                .iter()
                .map(i32::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    if nodes.len() == 1 && unknown.is_empty() {
        put(&format!("{prefix}_numa_node"), nodes[0].to_string());
    }
    if !unknown.is_empty() {
        put(unknown_key, set_text(unknown));
    }
}

/// The CPU list of `flashstore_placement` (`cpus=[0, 1, 3] ...`).
pub fn placement_cpus(placement: Option<&str>) -> Vec<usize> {
    let Some(p) = placement else {
        return Vec::new();
    };
    let Some(rest) = p.split("cpus=[").nth(1) else {
        return Vec::new();
    };
    let end = rest.find(']').unwrap_or(rest.len());
    rest[..end]
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect()
}

/// Build the 3.3.1 device and NUMA keys from sysfs `root`, the identified device, the OSD's CPUs and interfaces.
pub fn keys(
    root: &Path,
    dev: Option<&DevMeta>,
    cpus: &[usize],
    front: &str,
    back: &str,
    store: crate::storeid::StoreIdentity,
) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    let mut put = |k: &str, v: String| {
        m.insert(k.to_owned(), v);
    };

    // ---- network NUMA
    let mut unknown: Vec<&str> = Vec::new();
    let mut seen: Vec<i32> = Vec::new();
    for (key, iface) in [("front_iface", front), ("back_iface", back)] {
        match iface_node(root, iface) {
            Some(n) => {
                if !seen.contains(&n) {
                    seen.push(n);
                }
            }
            None => unknown.push(key),
        }
    }
    numa_keys(
        &mut put,
        "network",
        &seen,
        &unknown,
        "network_numa_unknown_ifaces",
    );

    // ---- thread placement
    let dev_num = dev.and_then(|d| {
        if d.kernel {
            dev_node(root, &d.name)
        } else if d.pci.is_empty() {
            None
        } else {
            numa_of(root, &format!("bus/pci/devices/{}/numa_node", d.pci))
        }
    });
    // the node every pinned CPU sits on (absent when the placement is unknown or spans nodes): what the threads are
    // actually pinned to, not a configured or device-derived guess
    let cpu_node_of = |c: usize| {
        std::fs::read_dir(root.join(format!("devices/system/cpu/cpu{c}")))
            .ok()?
            .flatten()
            .find_map(|e| {
                let n = e.file_name();
                n.to_str()?.strip_prefix("node")?.parse::<i32>().ok()
            })
    };
    let mut pinned = cpus.iter().map(|c| cpu_node_of(*c));
    let node = match pinned.next().flatten() {
        Some(n) if pinned.all(|x| x == Some(n)) => Some(n),
        _ => None,
    };
    if let Some(n) = node {
        put("numa_node", n.to_string());
        let nc = node_cpus(root, n);
        if !nc.is_empty() {
            put("numa_node_cpus", cpu_ranges(&nc));
        }
    }

    // ---- object store NUMA
    let mut dev_unknown: Vec<&str> = Vec::new();
    let mut dev_nodes: Vec<i32> = Vec::new();
    if let Some(d) = dev {
        match dev_num {
            Some(n) => dev_nodes.push(n),
            None => dev_unknown.push(&d.name),
        }
    }
    numa_keys(
        &mut put,
        "objectstore",
        &dev_nodes,
        &dev_unknown,
        "objectstore_numa_unknown_devices",
    );

    // ---- device identity, geometry and tier of this OSD. croit-flashstore-osd has no BlueFS/BlueStore, so their facts
    // (`bluefs*`, allocator, allocation-from-file, elastic blobs, min_alloc_size) are omitted, not invented.
    let rotational = dev.and_then(|d| {
        d.kernel
            .then(|| read_num(root, &format!("class/block/{}/queue/rotational", d.name)))
            .flatten()
    });
    let ssd = rotational != Some(1);
    let bdev = |suffix: &str| store.bdev_key(suffix);

    if let Some(d) = dev {
        put(&bdev("type"), if ssd { "ssd" } else { "hdd" }.into());
        if !d.ident.model.is_empty() {
            put(&bdev("model"), d.ident.model.clone());
        }
        if !d.ident.serial.is_empty() {
            put(&bdev("serial"), d.ident.serial.clone());
        }
        put(&bdev("size"), d.size_bytes.to_string());
        put(
            &bdev("driver"),
            if d.kernel { "KernelDevice" } else { "SPDK" }.into(),
        );
        if d.kernel {
            put(&bdev("devices"), d.name.clone());
            let q = |f: &str| read_num(root, &format!("class/block/{}/queue/{f}", d.name));
            if let Some(devno) = read(root, &format!("class/block/{}/dev", d.name)) {
                put(&bdev("dev"), devno);
            }
            let node = d.node();
            put(&bdev("dev_node"), node.clone());
            put(&bdev("partition_path"), node);
            if let Some(b) = q("logical_block_size") {
                put(&bdev("block_size"), b.to_string());
            }
            if let Some(b) = q("optimal_io_size") {
                put(&bdev("optimal_io_size"), b.to_string());
            }
            if let Some(r) = rotational {
                put(&bdev("rotational"), u8::from(r != 0).to_string());
            }
            if let Some(x) = q("discard_max_bytes") {
                put(&bdev("support_discard"), u8::from(x > 0).to_string());
            }
            put(&bdev("access_mode"), "blk".into());
            if let Some(n) = dev_node(root, &d.name) {
                put(&bdev("numa_node"), n.to_string());
            }
        } else if let Some(n) = dev_num {
            put(&bdev("numa_node"), n.to_string());
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storeid::StoreIdentity;

    fn write(root: &Path, rel: &str, v: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, v).unwrap();
    }

    fn tree() -> std::path::PathBuf {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("devmeta-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write(&dir, "class/net/eth0/device/numa_node", "0\n");
        write(&dir, "class/net/eth1/device/numa_node", "1\n");
        write(&dir, "class/net/eth2/device/numa_node", "-1\n");
        for c in 0..4 {
            std::fs::create_dir_all(dir.join(format!("devices/system/cpu/cpu{c}/node0"))).unwrap();
        }
        std::fs::create_dir_all(dir.join("devices/system/cpu/cpu4/node1")).unwrap();
        write(&dir, "class/block/nvme0n1/device/numa_node", "0\n");
        write(&dir, "class/block/nvme0n1/dev", "259:0\n");
        write(
            &dir,
            "class/block/nvme0n1/queue/logical_block_size",
            "4096\n",
        );
        write(
            &dir,
            "class/block/nvme0n1/queue/optimal_io_size",
            "131072\n",
        );
        write(&dir, "class/block/nvme0n1/queue/rotational", "0\n");
        write(&dir, "class/block/nvme0n1/queue/discard_max_bytes", "0\n");
        dir
    }

    fn device() -> DevMeta {
        DevMeta {
            name: "nvme0n1".into(),
            pci: "0000:03:00.0".into(),
            kernel: true,
            ident: nvme::health::Ident::from_raw(b"MODEL1", b"SER1", b"FW1"),
            size_bytes: 1_000_000,
        }
    }

    #[test]
    fn cpu_ranges_are_classic_text() {
        assert_eq!(cpu_ranges(&[0, 1, 2, 3, 32, 33]), "0-3,32-33");
        assert_eq!(cpu_ranges(&[5]), "5");
        assert_eq!(cpu_ranges(&[]), "");
        assert_eq!(
            placement_cpus(Some("cpus=[0, 1, 3] l3 placement: node 0")),
            vec![0, 1, 3]
        );
        assert!(placement_cpus(None).is_empty());
    }

    #[test]
    fn device_and_numa_keys_come_from_sysfs_and_omit_unknowns() {
        let root = tree();
        let m = keys(
            &root,
            Some(&device()),
            &[0, 1],
            "eth0",
            "eth1",
            StoreIdentity::default(),
        );
        assert_eq!(m["network_numa_nodes"], "0,1");
        assert!(!m.contains_key("network_numa_node"), "two nodes");
        assert!(!m.contains_key("network_numa_unknown_ifaces"));
        assert_eq!(m["numa_node"], "0", "the node of the pinned CPUs");
        assert_eq!(m["numa_node_cpus"], "0-3");
        assert_eq!(m["objectstore_numa_nodes"], "0");
        assert_eq!(m["objectstore_numa_node"], "0");
        assert_eq!(m["bluestore_bdev_dev"], "259:0");
        assert_eq!(m["bluestore_bdev_dev_node"], "/dev/nvme0n1");
        assert_eq!(m["bluestore_bdev_partition_path"], "/dev/nvme0n1");
        assert_eq!(m["bluestore_bdev_devices"], "nvme0n1");
        assert_eq!(m["bluestore_bdev_model"], "MODEL1");
        assert_eq!(m["bluestore_bdev_serial"], "SER1");
        assert_eq!(m["bluestore_bdev_size"], "1000000");
        assert_eq!(m["bluestore_bdev_block_size"], "4096");
        assert_eq!(m["bluestore_bdev_optimal_io_size"], "131072");
        assert_eq!(m["bluestore_bdev_rotational"], "0");
        assert_eq!(m["bluestore_bdev_support_discard"], "0");
        assert_eq!(m["bluestore_bdev_driver"], "KernelDevice");
        assert_eq!(m["bluestore_bdev_type"], "ssd");
        assert_eq!(m["bluestore_bdev_access_mode"], "blk");
        assert_eq!(m["bluestore_bdev_numa_node"], "0");
        assert!(
            !m.contains_key("bluefs"),
            "croit-flashstore-osd has no BlueFS"
        );
        assert!(!m.contains_key("bluestore_min_alloc_size"));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The SPDK tier reports its real driver and omits the kernel-node keys it cannot state (spec 3.3.1: unknown
    /// facts are omitted, never invented).
    #[test]
    fn spdk_reports_its_tier_and_omits_kernel_node_keys() {
        let root = tree();
        let mut d = device();
        d.kernel = false;
        d.name = "0000:03:00.0".into();
        let m = keys(
            &root,
            Some(&d),
            &[0],
            "eth0",
            "eth1",
            StoreIdentity::default(),
        );
        assert_eq!(m["bluestore_bdev_driver"], "SPDK");
        assert_eq!(m["bluestore_bdev_type"], "ssd");
        assert_eq!(m["bluestore_bdev_size"], "1000000");
        assert_eq!(m["bluestore_bdev_model"], "MODEL1");
        assert!(!m.contains_key("bluestore_bdev_devices"));
        assert!(!m.contains_key("bluestore_bdev_dev"), "no kernel device");
        assert!(!m.contains_key("bluestore_bdev_dev_node"));
        assert!(!m.contains_key("bluestore_bdev_partition_path"));
        assert!(!m.contains_key("bluestore_bdev_access_mode"));
        assert!(!m.contains_key("bluefs"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unknown_facts_are_omitted_not_invented() {
        let root = tree();
        // an iface without NUMA info and no store node: the keys stay absent, the iface is named in the unknown set
        let m = keys(&root, None, &[], "eth2", "", StoreIdentity::default());
        assert!(!m.contains_key("network_numa_nodes"));
        assert_eq!(m["network_numa_unknown_ifaces"], "{back_iface,front_iface}");
        assert!(!m.contains_key("numa_node"));
        assert!(!m.contains_key("numa_node_cpus"));
        assert!(!m.contains_key("objectstore_numa_nodes"));
        assert!(!m.contains_key("bluestore_bdev_dev"));
        // numa_node is the node of the pinned CPUs; osd_numa_node is not honoured by the placement, so not reported
        let m = keys(&root, None, &[4], "eth2", "eth2", StoreIdentity::default());
        assert_eq!(m["numa_node"], "1");
        assert_eq!(m["numa_node_cpus"], "4");
        // CPUs on two nodes: no single pinned node
        let m = keys(
            &root,
            None,
            &[0, 4],
            "eth2",
            "eth2",
            StoreIdentity::default(),
        );
        assert!(!m.contains_key("numa_node"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn flashstore_mode_renames_the_bdev_keys() {
        let root = tree();
        let b = keys(
            &root,
            Some(&device()),
            &[0, 1],
            "eth0",
            "eth1",
            StoreIdentity::BlueStore,
        );
        let f = keys(
            &root,
            Some(&device()),
            &[0, 1],
            "eth0",
            "eth1",
            StoreIdentity::FlashStore,
        );
        let bdev = |m: &BTreeMap<String, String>, p: &str| {
            m.keys()
                .filter(|k| k.contains("_bdev_"))
                .all(|k| k.starts_with(p))
        };
        assert!(b.keys().any(|k| k == "bluestore_bdev_size") && bdev(&b, "bluestore_bdev_"));
        assert!(f.keys().any(|k| k == "flashstore_bdev_size") && bdev(&f, "flashstore_bdev_"));
        assert!(!f.keys().any(|k| k.starts_with("bluestore_")));
        assert_eq!(b.len(), f.len());
    }
}
