// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Independent vectors; no device-mapper, block nodes, backing namespace access or data-destructive tests.
use super::*;
use std::io::Write;

fn table() -> Vec<u8> {
    let mut b = vec![0u8; 416];
    for (o, n) in [
        (0, 4u32),
        (12, 416),
        (16, 312),
        (20, 1),
        (28, ACTIVE),
        (32, 7),
    ] {
        b[o..o + 4].copy_from_slice(&n.to_ne_bytes());
    }
    b[40..48].copy_from_slice(&libc::makedev(253, 7).to_ne_bytes());
    let uuid = format!("LVM-{}", "a".repeat(64));
    b[176..244].copy_from_slice(uuid.as_bytes());
    b[320..328].copy_from_slice(&8192u64.to_ne_bytes());
    b[336..342].copy_from_slice(b"linear");
    b[352..362].copy_from_slice(b"259:2 2048");
    b
}
fn mapping() -> Mapping {
    parse_table(&table(), libc::makedev(253, 7)).unwrap()
}
fn backing(logical: u32) -> Ident {
    Ident {
        data_bytes: logical,
        nsze: 1 << 24,
        awupf: 32,
        awun: 64,
        dsm: true,
        write_zeroes: true,
        ..Ident::default()
    }
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "linear-fixture-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn put(&self, p: &str, s: &str) {
        let p = self.0.join(p);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, s).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn mounted_filesystem_admission_refuses_regular_files_and_symlinks_without_writes() {
    let f = Fixture::new();
    f.put("ordinary", "preserved bytes");
    let path = f.0.join("ordinary");
    let io: OwnedFd = std::fs::File::open(&path).unwrap().into();
    assert!(check_filesystem_device(&io, 0).is_err());
    assert!(validate_filesystem(&path, 0).is_err());
    std::os::unix::fs::symlink(&path, f.0.join("alias")).unwrap();
    assert!(validate_filesystem(&f.0.join("alias"), 0).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"preserved bytes");
}

#[test]
fn parses_live_lvm_identity_and_offsets() {
    let m = mapping();
    assert_eq!(m.offset, 2048);
    assert_eq!(m.sectors, 8192);
    assert_eq!(m.backing, libc::makedev(259, 2));
    assert_eq!(m.event, 7);
    let mut b = table();
    b[332..336].copy_from_slice(&104u32.to_ne_bytes());
    assert_eq!(parse_table(&b, m.device).unwrap(), m);
}
#[test]
fn malformed_and_truncated_abi_never_accepted_or_panics() {
    let b = table();
    let dev = mapping().device;
    for n in 0..363 {
        assert!(parse_table(&b[..n], dev).is_err(), "length {n}");
    }
    for (o, v) in [
        (0, 3u32),
        (12, 4097),
        (16, 1),
        (16, 417),
        (20, 0),
        (20, 2),
        (28, 0),
        (332, 39),
        (332, 41),
        (332, 112),
    ] {
        let mut b = table();
        b[o..o + 4].copy_from_slice(&v.to_ne_bytes());
        assert!(parse_table(&b, dev).is_err(), "offset {o} value {v}");
    }
    assert!(parse_table(&b, libc::makedev(253, 8)).is_err());
}
#[test]
fn refuses_readonly_suspended_pending_bufferfull_and_removal() {
    for flag in [1u32, 1 << 1, 1 << 6, 1 << 8, 1 << 17, 1 << 18] {
        let mut b = table();
        b[28..32].copy_from_slice(&(ACTIVE | flag).to_ne_bytes());
        assert!(parse_table(&b, mapping().device).is_err());
    }
}
#[test]
fn rejects_non_lvm_and_unsupported_targets_and_parameters() {
    for (o, bytes) in [
        (176, &b"bad-"[..]),
        (180, &b"!"[..]),
        (336, &b"striped\0"[..]),
        (336, &b"thin\0"[..]),
        (352, &b"259:2 2048 extra\0"[..]),
        (352, &b"4096:2 0\0"[..]),
        (352, &b"259:1048576 0\0"[..]),
        (352, &b"259:2 -1\0"[..]),
    ] {
        let mut b = table();
        b[o..o + bytes.len()].copy_from_slice(bytes);
        assert!(parse_table(&b, mapping().device).is_err(), "offset {o}");
    }
    for (o, v) in [(312, 1u64), (320, 0), (320, u64::MAX)] {
        let mut b = table();
        b[o..o + 8].copy_from_slice(&v.to_ne_bytes());
        assert!(parse_table(&b, mapping().device).is_err());
    }
    let mut b = table();
    b[352..].fill(b'x');
    assert!(parse_table(&b, mapping().device).is_err());
}
#[test]
fn bounds_are_lv_relative_and_overflow_checked() {
    let m = mapping();
    check_range(&m, 10240, 4 << 20).unwrap();
    assert!(check_range(&m, 10239, 4 << 20).is_err());
    assert!(check_range(&m, 10240, (4 << 20) + 512).is_err());
    assert_eq!(byte_range(2048, 8192).unwrap(), (1 << 20, 5 << 20));
    assert!(byte_range(u64::MAX, 1).is_err());
    assert!(byte_range(u64::MAX / 512, 1).is_err());
    let b = backing(512);
    assert_eq!(
        check_backing_range(&m, 4096, 16384, &b).unwrap(),
        (3 << 20, 7 << 20)
    );
    assert!(check_backing_range(&m, u64::MAX, 16384, &b).is_err());
    assert!(check_backing_range(&m, 0, 1 << 25, &b).is_err());
    let mut b = backing(4096);
    b.nsze = u64::MAX;
    assert!(check_backing_range(&m, 4096, 16384, &b).is_err());
    assert!(check_backing_range(&m, 4097, 16384, &backing(4096)).is_err());
}
#[test]
fn mapped_admission_requires_actual_identify_not_configured_sysfs_cache_policy() {
    assert!(
        identified_backing(None)
            .unwrap_err()
            .contains("sysfs fallback is insufficient")
    );
    let mut id = backing(512);
    id.vwc = true;
    assert!(mapped_ident(identified_backing(Some(id)).unwrap(), 512, 4096).is_err());
    assert!(mapped_ident(identified_backing(Some(backing(512))).unwrap(), 512, 4096).is_ok());
}

#[test]
fn mapped_geometry_is_truthful_conservative_and_non_destructive() {
    for logical in [512, 4096] {
        let id = mapped_ident(backing(logical), logical, 4 << 20).unwrap();
        let g = geometry_of(&id, Mode::Direct, Some(128));
        assert_eq!(g.capacity_bytes(), 4 << 20);
        assert_eq!(g.lba_size, logical);
        assert_eq!((g.awun_lbas, g.awupf_lbas), (1, 1));
        assert_eq!(g.max_xfer_lbas, 131072 / logical);
        assert!(!id.dsm && !id.write_zeroes && !id.vwc);
    }
    for field in 0..4 {
        let mut id = backing(512);
        match field {
            0 => id.vwc = true,
            1 => id.meta_bytes = 8,
            2 => id.pi = 1,
            _ => id.data_bytes = 4096,
        };
        assert!(mapped_ident(id, 512, 4 << 20).is_err());
    }
    for bytes in [0, 512, 4095, 4097] {
        assert!(mapped_ident(backing(512), 512, bytes).is_err());
    }
    assert!(mapped_ident(backing(512), 1024, 4 << 20).is_err());
}
#[test]
fn mapped_queue_limits_refuse_unknown_zero_overflow_and_bad_alignment() {
    assert_eq!(queue_limits(128, 3, 512).unwrap(), (128, 511));
    assert_eq!(queue_limits(256, 511, 4096).unwrap(), (256, 4095));
    for (hw, dma, logical) in [
        (0, 511, 512),
        (1, 511, 512),
        (u64::MAX, 511, 512),
        (128, 8192, 512),
        (128, u64::MAX, 512),
        (128, 511, 0),
    ] {
        assert!(queue_limits(hw, dma, logical).is_err());
    }
}
#[test]
fn peer_holders_allow_only_identified_disjoint_stable_lvs() {
    let f = Fixture::new();
    f.put("holders/selected/dev", "253:7");
    f.put("holders/peer/dev", "253:8");
    let m = mapping();
    let mut peer = m.clone();
    peer.device = libc::makedev(253, 8);
    peer.offset = m.offset + m.sectors;
    check_holders(&f.0, &m, 1 << 20, |dev| {
        Ok(if dev == m.device {
            m.clone()
        } else {
            peer.clone()
        })
    })
    .unwrap();
    for variant in 0..4 {
        let mut bad = peer.clone();
        match variant {
            0 => bad.offset -= 1,
            1 => bad.backing += 1,
            2 => bad.device += 1,
            _ => bad.sectors = u64::MAX,
        };
        assert!(
            check_holders(&f.0, &m, 1 << 20, |dev| Ok(if dev == m.device {
                m.clone()
            } else {
                bad.clone()
            }))
            .is_err()
        );
    }
    assert!(check_holders(&f.0, &m, 1 << 20, |_| Err("unsupported peer target".into())).is_err());
    let mut changed = m.clone();
    changed.event += 1;
    assert!(
        check_holders(&f.0, &m, 1 << 20, |dev| Ok(if dev == m.device {
            changed.clone()
        } else {
            peer.clone()
        }))
        .is_err()
    );
    std::fs::remove_file(f.0.join("holders/selected/dev")).unwrap();
    std::fs::remove_dir(f.0.join("holders/selected")).unwrap();
    assert!(check_holders(&f.0, &m, 1 << 20, |_| Ok(peer.clone())).is_err());
}
#[test]
fn topology_refuses_namespace_holders_and_physical_partition_overlap() {
    let f = Fixture::new();
    std::fs::create_dir(f.0.join("holders")).unwrap();
    check_namespace_holders(&f.0).unwrap();
    f.put("holders/conflict/dev", "253:42");
    assert!(check_namespace_holders(&f.0).is_err());
    f.put("nvme0n1p1/partition", "1");
    f.put("nvme0n1p1/start", "0");
    f.put("nvme0n1p1/size", "2048");
    let part = f.0.join("nvme0n1p2");
    check_partitions(&f.0, &part, 1 << 20, 5 << 20).unwrap();
    assert!(check_partitions(&f.0, &part, 0, 4096).is_err());
    f.put("nvme0n1p1/size", "18446744073709551615");
    assert!(check_partitions(&f.0, &part, 1 << 20, 5 << 20).is_err());
}
#[test]
fn backing_requires_kernel_nvme_partition_not_nested_mapping() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let part = f.0.join("nvme0/nvme0n1/nvme0n1p2");
    f.put("nvme0/nvme0n1/nvme0n1p2/partition", "2");
    std::fs::create_dir(f.0.join("nvme0/device")).unwrap();
    symlink("/drivers/nvme", f.0.join("nvme0/device/driver")).unwrap();
    assert_eq!(backing_namespace(&part).unwrap(), f.0.join("nvme0/nvme0n1"));
    std::fs::remove_file(f.0.join("nvme0/device/driver")).unwrap();
    symlink("/drivers/loop", f.0.join("nvme0/device/driver")).unwrap();
    assert!(backing_namespace(&part).is_err());
    f.put("nvme0/nvme0n1/nvme0n1p2/partition", "0");
    assert!(backing_namespace(&part).is_err());
}
#[test]
fn mapped_controller_keeps_data_fd_and_refuses_destructive_calls_without_io() {
    let f = Fixture::new();
    let path = f.0.join("lv-data");
    let health = f.0.join("backing-must-never-open");
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    file.write_all(&[0x5a; 4096]).unwrap();
    let inode = file.metadata().unwrap().ino();
    let ctrl = KernelCtrl::from_parts(
        file.into(),
        None,
        Mode::Direct,
        19,
        mapped_ident(backing(512), 512, 4096).unwrap(),
        Some(128),
        511,
        &path,
    );
    let ctrl = finish_mapped(ctrl, health.clone());
    assert_eq!(ctrl.path(), path);
    assert_eq!(ctrl.probe_path(), health);
    match crate::any::AnyCtrl::Kernel(ctrl.clone())
        .health_probe()
        .unwrap()
    {
        crate::any::HealthProbe::Kernel(probe) => assert_eq!(probe.0, health),
        #[cfg(feature = "spdk")]
        crate::any::HealthProbe::Spdk(_) => {
            panic!("mapped health must use the verified kernel backing path")
        }
    }
    assert_eq!(ctrl.c.nsid, 19);
    assert_eq!(ctrl.c.mode, Mode::Direct);
    assert!(ctrl.c.claim.is_none());
    assert_eq!(
        std::fs::File::from(ctrl.c.io.try_clone().unwrap())
            .metadata()
            .unwrap()
            .ino(),
        inode
    );
    assert!(!ctrl.geometry().dealloc && !ctrl.geometry().write_zeroes);
    assert!(ctrl.probe_dsm_at_mkfs().unwrap_err().contains("mapped"));
    ctrl.apply_dsm_verdict(Some(true));
    let mut q = ctrl.open_queue(4);
    assert!(q.deallocate_all().unwrap_err().contains("mapped"));
    assert!(q.submit_deallocate(&[(0, 1)], 0).is_err());
    assert!(q.submit_write_zeroes(0, 1, 0).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), vec![0x5a; 4096]);
    assert!(!health.exists());
}
#[test]
fn positive_persisted_verdict_cannot_enable_mapped_passthrough_even_in_cmd_mode() {
    let f = Fixture::new();
    let path = f.0.join("data");
    let file = std::fs::File::create(&path).unwrap();
    let ctrl = KernelCtrl::from_parts(
        file.into(),
        None,
        Mode::Cmd,
        1,
        backing(4096),
        Some(128),
        4095,
        &path,
    );
    let ctrl = finish_mapped(ctrl, f.0.join("backing"));
    ctrl.apply_dsm_verdict(Some(true));
    assert_eq!(ctrl.c.dsm.load(Ordering::Acquire), DSM_UNKNOWN);
    assert!(!ctrl.geometry().dealloc);
    assert!(ctrl.probe_dsm_at_mkfs().is_err());
    assert!(ctrl.open_queue(1).deallocate_all().is_err());
}
