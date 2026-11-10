// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `kernel:` backend tests: identify parsing, geometry rules, command layout, and IO through the device ring on an
//! O_DIRECT file (direct mode). Passthrough IO needs a real namespace: lab/baremetal/kvnme-func.sh.
use super::*;

fn pages() -> (Vec<u8>, Vec<u8>) {
    let (mut c, mut n) = (vec![0u8; 4096], vec![0u8; 4096]);
    c[77] = 5; // MDTS 2^5 pages = 128 KiB
    c[520] = 0b1100; // ONCS: DSM + write zeroes
    c[525] = 0; // no volatile write cache
    c[526..528].copy_from_slice(&7u16.to_le_bytes()); // AWUN 8 LBAs
    c[528..530].copy_from_slice(&0u16.to_le_bytes()); // AWUPF 1 LBA
    n[0..8].copy_from_slice(&1_000_000u64.to_le_bytes());
    n[25] = 1; // two formats
    n[26] = 1; // current = format 1
    n[128..132].copy_from_slice(&(9u32 << 16).to_le_bytes()); // format 0: 512+0
    n[132..136].copy_from_slice(&(12u32 << 16).to_le_bytes()); // format 1: 4096+0
    (c, n)
}

#[test]
fn identify_pages_parse() {
    let (c, mut n) = pages();
    let id = parse_ident(&c, &n);
    assert_eq!(
        (id.nsze, id.data_bytes, id.meta_bytes, id.pi, id.lbaf),
        (1_000_000, 4096, 0, 0, 1)
    );
    assert_eq!(
        (id.awupf, id.awun, id.vwc, id.dsm, id.write_zeroes, id.mdts),
        (1, 8, false, true, true, 5)
    );
    // namespace atomic values win when NSFEAT bit 1 is set
    n[24] = 0x2;
    n[34..36].copy_from_slice(&15u16.to_le_bytes());
    n[36..38].copy_from_slice(&3u16.to_le_bytes());
    let id = parse_ident(&c, &n);
    assert_eq!((id.awupf, id.awun), (4, 16));
    // metadata format, PI, high index bits (FLBAS 6:5)
    n[26] = 0x20 | 0x1; // index 0x11 = 17
    n[128 + 4 * 17..128 + 4 * 18].copy_from_slice(&((12u32 << 16) | 64).to_le_bytes());
    n[29] = 1;
    let id = parse_ident(&c, &n);
    assert_eq!(
        (id.lbaf, id.data_bytes, id.meta_bytes, id.pi),
        (17, 4096, 64, 1)
    );
}

/// Fake sysfs block directory of one namespace.
fn sysfs(tag: &str, files: &[(&str, &str)]) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("kdev-sysfs-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    for (f, c) in files {
        let p = d.join(f);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, c).unwrap();
    }
    d
}

/// Kernel without unprivileged passthrough (RHEL 9 5.14 as user ceph): the geometry from sysfs equals what Identify gives
/// for the store's purposes (4096+0, capacity, VWC, DSM / write zeroes), atomic unit 1 LBA.
#[test]
fn sysfs_ident_without_passthrough() {
    let base = [
        ("queue/logical_block_size", "4096\n"),
        ("size", "16777216\n"), // 8 GiB in 512-byte sectors
        ("queue/write_cache", "write back\n"),
        ("queue/discard_max_hw_bytes", "2199023255040\n"),
        ("queue/write_zeroes_max_bytes", "0\n"),
    ];
    let d = sysfs("plain", &base);
    let id = sysfs_ident(&d).unwrap();
    assert_eq!(
        (id.nsze, id.data_bytes, id.meta_bytes, id.pi),
        (2 << 20, 4096, 0, 0)
    );
    assert_eq!((id.awupf, id.awun, id.mdts), (1, 1, 0));
    assert!(id.vwc && id.dsm && !id.write_zeroes);
    let g = geometry_of(&id, Mode::Direct, Some(512));
    assert_eq!((g.lba_size, g.lba_count, g.awupf_lbas), (4096, 2 << 20, 1));
    assert!(g.vwc && !g.dealloc);
    let _ = std::fs::remove_dir_all(&d);
    // PI / metadata the kernel exposes = integrity profile: refused by the format check like an Identify format
    let mut pi = base.to_vec();
    pi.push(("integrity/tuple_size", "8\n"));
    pi[2] = ("queue/write_cache", "write through\n");
    let d = sysfs("pi", &pi);
    let id = sysfs_ident(&d).unwrap();
    assert_eq!((id.meta_bytes, id.pi, id.vwc), (8, 1, false));
    let _ = std::fs::remove_dir_all(&d);
    // a format the kernel hides (capacity 0) and a missing sysfs file are clear errors
    let mut hidden = base.to_vec();
    hidden[1] = ("size", "0\n");
    let d = sysfs("hidden", &hidden);
    assert!(sysfs_ident(&d).unwrap_err().contains("capacity 0"));
    let _ = std::fs::remove_dir_all(&d);
    // an unreadable write_cache counts as volatile (writes carry DSYNC)
    let d = sysfs("nocache", &[base[0], base[1]]);
    assert!(sysfs_ident(&d).unwrap().vwc);
    let _ = std::fs::remove_dir_all(&d);
    let d = sysfs("nosize", &base[..1]);
    assert!(
        sysfs_ident(&d)
            .unwrap_err()
            .contains("sysfs size not readable")
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn geometry_rules() {
    let (c, n) = pages();
    let id = parse_ident(&c, &n);
    let g = geometry_of(&id, Mode::Direct, None);
    assert_eq!(
        (g.lba_size, g.lba_count, g.max_xfer_lbas),
        (4096, 1_000_000, 32),
        "MDTS 128 KiB"
    );
    assert!(!g.dealloc && g.write_zeroes && !g.vwc);
    let g = geometry_of(&id, Mode::Cmd, Some(64));
    assert_eq!(g.max_xfer_lbas, 16, "kernel max_hw_sectors_kb caps");
    assert!(g.dealloc && g.write_zeroes);
    let big = Ident { mdts: 0, ..id };
    assert_eq!(
        geometry_of(&big, Mode::Cmd, None).max_xfer_lbas,
        128,
        "512 KiB cap"
    );
    let vwc = Ident { vwc: true, ..id };
    assert!(
        !geometry_of(&vwc, Mode::Direct, None).write_zeroes,
        "fallocate zeroing is not FUA"
    );
    assert!(
        geometry_of(&vwc, Mode::Cmd, None).write_zeroes,
        "cmd write zeroes carries FUA"
    );
}

#[test]
fn passthrough_command_layout() {
    assert_eq!(NVME_URING_CMD_IO, 0xC048_4E80);
    let c = UringCmd {
        opcode: NVM_WRITE,
        nsid: 3,
        addr: 0x1122_3344_5566_7788,
        data_len: 8192,
        cdw10: 0xaabb_ccdd,
        cdw11: 0x11,
        cdw12: 1 | crate::IO_FLAG_FUA,
    };
    let b = c.bytes();
    assert_eq!(b[0], 1);
    assert_eq!(u32::from_le_bytes(b[4..8].try_into().unwrap()), 3);
    assert_eq!(
        u64::from_le_bytes(b[24..32].try_into().unwrap()),
        0x1122_3344_5566_7788
    );
    assert_eq!(u32::from_le_bytes(b[36..40].try_into().unwrap()), 8192);
    assert_eq!(
        u32::from_le_bytes(b[40..44].try_into().unwrap()),
        0xaabb_ccdd
    );
    assert_eq!(u32::from_le_bytes(b[44..48].try_into().unwrap()), 0x11);
    assert_eq!(
        u32::from_le_bytes(b[48..52].try_into().unwrap()),
        1 | 1 << 30
    );
    assert!(b[52..].iter().all(|x| *x == 0));
}

#[test]
fn status_mapping() {
    assert_eq!(cmd_err(0x281), IoError::Media, "sct 2");
    assert_eq!(cmd_err(0x4007), IoError::Aborted, "DNR + abort requested");
    assert_eq!(cmd_err(0x0002), IoError::Status(2));
    assert_eq!(cmd_err(-libc::ENODATA), IoError::Media);
    assert_eq!(errno_err(libc::ECANCELED), IoError::Aborted);
    assert_eq!(errno_err(libc::EIO), IoError::Errno(libc::EIO));
    assert_eq!(errno_err(libc::ENXIO), IoError::Errno(6));
    assert_eq!(cmd_err(0x0006), IoError::Status(6)); // NVMe internal error: distinct from errno 6 above
}

/// The probe span straddles a hugepage boundary of the arena at a non-zero offset into both folios, wherever the 4 KiB
/// aligned probe allocation lands.
#[test]
fn probe_span_crosses_a_hugepage_boundary() {
    let base = 64 * HUGE;
    for off in (0..2 * HUGE).step_by(4096) {
        let ptr = base + off;
        let s = probe_span(base, ptr, PROBE_ALLOC).expect("span inside the allocation");
        assert!(
            s >= ptr && s + PROBE_BYTES <= ptr + PROBE_ALLOC,
            "inside at {off}"
        );
        assert_eq!(
            (s + PROBE_BYTES / 2 - base) % HUGE,
            0,
            "centred on a boundary at {off}"
        );
        assert_ne!((s - base) % HUGE, 0, "starts inside a folio at {off}");
    }
    assert_eq!(
        probe_span(base, base + 4096, PROBE_BYTES),
        None,
        "too small"
    );
}

/// Only EINVAL of the fixed command means "capability missing" (direct mode); every other failure stops the open instead
/// of being papered over. No plain (non-fixed) retry exists: it would name a plain user address (module doc).
#[test]
fn blk_tags_of_a_disk_and_of_a_multipath_head() {
    let d = std::env::temp_dir().join(format!("kdev-tags-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    let w = |p: &str, v: &str| {
        let p = d.join(p);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, v).unwrap();
    };
    w("nvme1n1/queue/nr_requests", "1023\n");
    w("nvme0n1/queue/rotational", "0\n");
    w("nvme0c0n1/queue/nr_requests", "256\n");
    w("nvme0c3n1/queue/nr_requests", "128\n");
    w("nvme0c0n2/queue/nr_requests", "7\n");
    w("nvme2n1/queue/rotational", "0\n");
    assert_eq!(blk_tags(&d.join("nvme1n1")), 1023);
    assert_eq!(blk_tags(&d.join("nvme0n1")), 128);
    assert_eq!(blk_tags(&d.join("nvme2n1")), 0);
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
fn queue_depth_stays_within_the_blk_mq_tags() {
    assert_eq!(queue_depth(1024, 256), 256);
    assert_eq!(queue_depth(64, 256), 64);
    assert_eq!(queue_depth(1024, 0), (RING_CQ / 4).min(1024));
    assert_eq!(queue_depth(1, 0), 2);
    assert_eq!(queue_depth(1024, 1), 2);
}

#[test]
fn probe_verdicts() {
    assert_eq!(probe_verdict("read", 0), Ok(true));
    assert_eq!(probe_verdict("read", -libc::EINVAL), Ok(false));
    assert!(probe_verdict("write-back", -libc::EIO).is_err());
    assert!(probe_verdict("read", 0x281).is_err(), "NVMe media status");
}

/// Only an NVMe status marks passthrough DSM unusable (BLKDISCARD fallback); an errno fails the open.
#[test]
fn dsm_probe_verdicts_and_range_layout() {
    assert_eq!(dsm_verdict(0), Ok(true));
    assert_eq!(dsm_verdict(0x4002), Ok(false), "DNR + invalid field");
    assert!(dsm_verdict(-libc::EINVAL).is_err());
    let r = dsm_range(0x1_0000_0002, 8);
    assert_eq!(&r[..4], &[0; 4], "context attributes");
    assert_eq!(&r[4..8], &8u32.to_le_bytes());
    assert_eq!(&r[8..16], &0x1_0000_0002u64.to_le_bytes());
    assert!(r[16..].iter().all(|b| *b == 0));
}

#[test]
fn head_names() {
    assert_eq!(head_name("nvme0c1n2"), "nvme0n2");
    assert_eq!(head_name("nvme3n1"), "nvme3n1");
    assert_eq!(head_name("nvme12c12n10"), "nvme12n10");
}

#[test]
fn direct_io_offsets_follow_512_byte_geometry() {
    use std::os::unix::fs::FileExt;
    let Some((mut c, p)) = file_ctrl("sector512", 16 << 20) else {
        return;
    };
    let inner = Arc::get_mut(&mut c.c).unwrap();
    inner.id.data_bytes = 512;
    inner.id.nsze = (16 << 20) / 512;
    inner.geo = geometry_of(&inner.id, Mode::Direct, None);
    let mut d = c.open_queue(4);
    let mut b = d.alloc_buf(4096);
    b.as_mut_slice().fill(0xa7);
    d.submit_write(8, b, 1).unwrap();
    assert!(wait_all(&mut d, 1)[0].result.is_ok());
    let f = std::fs::File::open(&p).unwrap();
    let mut bytes = vec![0; 4096];
    f.read_exact_at(&mut bytes, 4096).unwrap();
    assert!(bytes.iter().all(|v| *v == 0xa7));
    f.read_exact_at(&mut bytes, 8 * 4096).unwrap();
    assert!(
        bytes.iter().all(|v| *v == 0),
        "must not use hardcoded 4K sectors"
    );
    let b = d.alloc_buf(4096);
    d.submit_read(8, b, 2).unwrap();
    let b = wait_all(&mut d, 1).remove(0).buf.unwrap();
    assert!(b.as_slice().iter().all(|v| *v == 0xa7));
    drop(d);
    drop(c);
    std::fs::remove_file(p).unwrap();
}

/// A directory that supports O_DIRECT (tmpfs does not).
fn file_ctrl(name: &str, bytes: u64) -> Option<(KernelCtrl, std::path::PathBuf)> {
    let mut dirs: Vec<std::path::PathBuf> = ["KDEV_TEST_DIR", "CARGO_TARGET_DIR"]
        .iter()
        .filter_map(|v| std::env::var_os(v).map(Into::into))
        .collect();
    dirs.push(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"));
    dirs.push(std::env::temp_dir());
    for d in dirs {
        let p = d.join(format!("kdev-{name}-{}.img", std::process::id()));
        match KernelCtrl::open_file_for_test(&p, bytes) {
            Ok(c) => return Some((c, p)),
            Err(_) => {
                let _ = std::fs::remove_file(&p);
            }
        }
    }
    eprintln!("no O_DIRECT capable directory: skipped");
    None
}

fn wait_all(d: &mut KernelDev, n: usize) -> Vec<Completion<KBuf>> {
    let mut out = Vec::new();
    let t = std::time::Instant::now();
    while out.len() < n {
        d.poll(0, &mut out);
        assert!(
            t.elapsed().as_secs() < 10,
            "WARNING TIMEOUT kernel device IO exceeded 10s (completion wait)"
        );
    }
    out
}

/// A payload view needs 4 KiB-aligned memory ([`VIEW_ALIGN`]); dword-aligned memory (all `queue/dma_alignment` asks)
/// is refused, so the caller copies instead of risking a device error on a block-aligned backend (the receive offset
/// 360 of an EC sub-write seen in the lab is the case).
#[test]
fn views_only_page_aligned_memory() {
    let Some((c, p)) = file_ctrl("va", 1 << 20) else {
        return;
    };
    let mut d = c.open_queue(4);
    let raw = bytes::Bytes::from(vec![7u8; 3 * 4096]);
    let at = raw.as_ptr().align_offset(VIEW_ALIGN);
    assert!(d.view_buf(&raw.slice(at..at + 4096)).is_some());
    for off in [4usize, 8, 360, 512, 2048] {
        assert!(
            d.view_buf(&raw.slice(at + off..at + off + 4096)).is_none(),
            "offset {off}"
        );
    }
    // a length that is not whole blocks never views either
    assert!(d.view_buf(&raw.slice(at..at + 512)).is_none());
    drop(d);
    let _ = std::fs::remove_file(p);
}

#[test]
fn direct_roundtrip_fixed_plain_and_view() {
    let Some((c, p)) = file_ctrl("rt", 16 << 20) else {
        return;
    };
    let mut d = c.open_queue(8);
    let g = d.geometry();
    assert_eq!(g.lba_size, 4096);
    // arena (fixed) buffer
    let mut w = d.alloc_buf_uninit(8192);
    let pat: Vec<u8> = (0..8192u32).map(|i| (i * 7 + 3) as u8).collect();
    w.copy_from_slice(&pat);
    d.submit_write(10, w, 1).unwrap();
    // zero-copy view (plain write)
    let raw = bytes::Bytes::from(vec![0x5au8; 2 * 4096]);
    let at = raw.as_ptr().align_offset(VIEW_ALIGN);
    let v = raw.slice(at..at + 4096);
    let vb = d.view_buf(&v).expect("aligned payload view");
    assert!(vb.is_view());
    d.submit_write(20, vb, 2).unwrap();
    let done = wait_all(&mut d, 2);
    assert!(done.iter().all(|c| c.result.is_ok() && c.op == Op::Write));
    // read back both ranges; one into an oversized (heap) buffer
    {
        let b = d.alloc_buf_uninit(8192);
        d.submit_read(10, b, 3)
    }
    .unwrap();
    let big = KBuf::new_uninit(4096);
    d.submit_read(20, big, 4).unwrap();
    for c in wait_all(&mut d, 2) {
        let b = c.buf.unwrap();
        match c.tag {
            3 => assert_eq!(b.as_slice(), &pat[..]),
            4 => assert!(b.as_slice().iter().all(|x| *x == 0x5a)),
            t => panic!("tag {t}"),
        }
    }
    // write zeroes (fallocate ZERO_RANGE)
    d.submit_write_zeroes(10, 1, 5).unwrap();
    let r = wait_all(&mut d, 1)[0].result;
    if r == Err(IoError::Errno(libc::EOPNOTSUPP)) {
        eprintln!("ZERO_RANGE unsupported on this filesystem: zeroing not checked");
        return;
    }
    assert!(r.is_ok(), "{r:?}");
    {
        let b = d.alloc_buf_uninit(8192);
        d.submit_read(10, b, 6)
    }
    .unwrap();
    let b = wait_all(&mut d, 1).remove(0).buf.unwrap();
    assert!(b.as_slice()[..4096].iter().all(|x| *x == 0));
    assert_eq!(&b.as_slice()[4096..], &pat[4096..]);
    drop(d);
    let _ = std::fs::remove_file(p);
}

#[test]
fn submit_validation_and_queue_full() {
    let Some((c, p)) = file_ctrl("val", 1 << 20) else {
        return;
    };
    let mut d = c.open_queue(2);
    let e = {
        let b = d.alloc_buf_uninit(8192);
        d.submit_read(255, b, 1)
    }
    .unwrap_err();
    assert_eq!(e.err, SubmitError::OutOfRange);
    let e = d.submit_write(0, KBuf::new_uninit(100), 1).unwrap_err();
    assert_eq!(e.err, SubmitError::Invalid);
    let e = d.submit_deallocate(&[(0, 1)], 1).unwrap_err();
    assert_eq!(e.err, SubmitError::Unsupported, "regular file: no discard");
    assert!(!d.dealloc_limits().is_on());
    {
        let b = d.alloc_buf(4096);
        d.submit_read(0, b, 1)
    }
    .unwrap();
    {
        let b = d.alloc_buf(4096);
        d.submit_read(1, b, 2)
    }
    .unwrap();
    let e = {
        let b = d.alloc_buf(4096);
        d.submit_read(2, b, 3)
    }
    .unwrap_err();
    assert_eq!(e.err, SubmitError::QueueFull);
    assert!(e.buf.is_some(), "the buffer comes back");
    assert_eq!(wait_all(&mut d, 2).len(), 2);
    assert_eq!(d.queue_space(), 2);
    drop(d);
    let _ = std::fs::remove_file(p);
}

#[test]
fn queues_share_the_thread_ring_and_completions_route_by_queue() {
    let Some((c, p)) = file_ctrl("mq", 4 << 20) else {
        return;
    };
    let (mut a, mut b) = (c.open_queue(16), c.open_queue(16));
    for i in 0..8u64 {
        let mut w = a.alloc_buf_uninit(4096);
        w.copy_from_slice(&[i as u8; 4096]);
        a.submit_write(i, w, 100 + i).unwrap();
        let mut w = b.alloc_buf_uninit(4096);
        w.copy_from_slice(&[0x80 | i as u8; 4096]);
        b.submit_write(64 + i, w, 200 + i).unwrap();
    }
    // reaping b first must not lose a's completions
    let db = wait_all(&mut b, 8);
    assert!(db.iter().all(|c| (200..208).contains(&c.tag)));
    let da = wait_all(&mut a, 8);
    assert!(da.iter().all(|c| (100..108).contains(&c.tag)));
    // one submit syscall per flush, not per IO
    let (enters, sqes) = thread_stats();
    assert!(sqes >= 16 && enters < sqes, "enters {enters} sqes {sqes}");
    // the ring fd signals completions (the kernel tier polls it)
    let fd = thread_ring_fd().unwrap();
    {
        let b = a.alloc_buf_uninit(4096);
        a.submit_read(3, b, 9)
    }
    .unwrap();
    flush();
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd.
    let r = unsafe { libc::poll(&mut pfd, 1, 5000) };
    assert_eq!(r, 1, "ring fd readable after the completion");
    let c9 = wait_all(&mut a, 1).remove(0);
    assert!(c9.buf.unwrap().as_slice().iter().all(|x| *x == 3));
    drop((a, b));
    let _ = std::fs::remove_file(p);
}

#[test]
fn idle_queue_moves_to_another_thread() {
    let Some((c, p)) = file_ctrl("mv", 1 << 20) else {
        return;
    };
    let mut d = c.open_queue(4);
    let mut w = d.alloc_buf_uninit(4096);
    w.copy_from_slice(&[9u8; 4096]);
    d.submit_write(5, w, 1).unwrap();
    wait_all(&mut d, 1);
    let d = std::thread::spawn(move || {
        let mut d = d;
        {
            let b = d.alloc_buf_uninit(4096);
            d.submit_read(5, b, 2)
        }
        .unwrap();
        let c = wait_all(&mut d, 1).remove(0);
        assert!(c.buf.unwrap().as_slice().iter().all(|x| *x == 9));
        d
    })
    .join()
    .unwrap();
    // The issuer has exited: its TLS ring is gone. Health checks must be safe
    // before the first submission rebinds this idle queue.
    assert!(!d.is_dead());
    drop(d);
    let _ = std::fs::remove_file(p);
}

/// Queue bindings registered on this thread's device ring.
fn bound_queues() -> usize {
    // SAFETY: this thread's ring; no other reference is live.
    let r = unsafe { &*thread_ring().unwrap() };
    r.done.len() - r.free_q.len()
}

/// A worker thread that stays alive and runs the jobs sent to it on its own device ring.
type Job = Box<dyn FnOnce() + Send>;
fn worker() -> (std::sync::mpsc::Sender<Job>, std::thread::JoinHandle<()>) {
    let (tx, rx) = std::sync::mpsc::channel::<Job>();
    (
        tx,
        std::thread::spawn(move || rx.into_iter().for_each(|j| j())),
    )
}

fn run_on<T: Send + 'static>(
    tx: &std::sync::mpsc::Sender<Job>,
    f: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (rtx, rrx) = std::sync::mpsc::channel();
    tx.send(Box::new(move || rtx.send(f()).unwrap())).unwrap();
    match rrx.recv_timeout(std::time::Duration::from_secs(20)) {
        Ok(v) => v,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            panic!("WARNING TIMEOUT kernel device worker job exceeded 20s")
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            panic!("kernel device worker job panicked")
        }
    }
}

/// NT-kernelnvme-03: an idle queue that moves back and forth between two live threads far more often than a ring has
/// queue slots keeps working; each move hands the former binding back to its ring, which unregisters it on its own
/// thread (next flush or registration), and an idle drop off the ring's thread does the same.
#[test]
fn idle_migration_between_live_threads_reuses_bindings() {
    let Some((c, p)) = file_ctrl("pingpong", 1 << 20) else {
        return;
    };
    let (a, ja) = worker();
    let (b, jb) = worker();
    let mut d = c.open_queue(4);
    // 96 moves: 48 bindings per thread, more than its MAX_QUEUES slots
    for i in 0..(3 * MAX_QUEUES as u64) {
        d = run_on(if i % 2 == 0 { &a } else { &b }, move || {
            let mut d = d;
            let mut w = d.alloc_buf_uninit(4096);
            w.copy_from_slice(&[i as u8; 4096]);
            d.submit_write(i % 64, w, i).unwrap();
            assert!(wait_all(&mut d, 1)[0].result.is_ok());
            assert_eq!(
                bound_queues(),
                1,
                "the former binding of this thread is released"
            );
            d
        });
    }
    // the last move went to b; a's binding was handed back
    let count = |tx| {
        run_on(tx, || {
            flush();
            bound_queues()
        })
    };
    assert_eq!((count(&a), count(&b)), (0, 1));
    // idle drop off the issuer: b unregisters the binding at its next flush
    drop(d);
    assert_eq!((count(&a), count(&b)), (0, 0));
    drop((a, b));
    ja.join().unwrap();
    jb.join().unwrap();
    drop(c);
    let _ = std::fs::remove_file(p);
}

/// Exercise off-thread guards without requiring io_uring or a real NVMe device.
/// The non-dereferenceable pointer represents an issuer's destroyed TLS ring.
#[test]
fn migrated_queue_never_dereferences_the_issuers_ring() {
    let c = KernelCtrl::from_parts(
        std::fs::File::open("/dev/null").unwrap().into(),
        None,
        Mode::Direct,
        1,
        Ident {
            nsze: 256,
            data_bytes: LBA,
            awupf: 1,
            awun: 1,
            ..Ident::default()
        },
        None,
        4095,
        Path::new("/dev/null"),
    );
    let mut d = c.open_queue(2);
    d.ring = std::ptr::NonNull::<KRing>::dangling().as_ptr();
    d.ring_id = u64::MAX; // cannot be this thread's ring
    assert!(!d.is_dead(), "idle queues can rebind on submission");
    assert_eq!(d.poll(0, &mut Vec::new()), 0);
    // A busy handle can also be moved by safe Rust (KernelDev: Send).
    let slot = d.free.pop().unwrap();
    d.slots[slot as usize] = Some(Pending {
        tag: 7,
        op: Op::Read,
        buf: Some(KBuf::new(4096)),
        keep: None,
        via: Via::Block,
        lba: 0,
    });
    assert!(d.is_dead());
    let mut out = Vec::new();
    assert_eq!(d.poll(0, &mut out), 0);
    assert!(
        out.is_empty(),
        "no fabricated completion or early buffer release"
    );
    assert!(d.slots[slot as usize].as_ref().unwrap().buf.is_some());
    let b = KBuf::new(4096);
    assert_eq!(d.submit_read(0, b, 8).unwrap_err().err, SubmitError::Dead);
    // No IO was actually issued; reclaim the test buffer rather than leak it.
    d.slots[slot as usize] = None;
    d.free.push(slot);
}

#[test]
fn spec_resolution_errors_are_clear() {
    // a PCI address without a controller is reported, not a panic
    let e = nodes_of_pci("ffff:ff:1f.7", 1).unwrap_err();
    assert!(e.contains("ffff:ff:1f.7"), "{e}");
    let e = KernelCtrl::open(Path::new("/dev/null")).unwrap_err();
    assert!(
        e.contains("croit-flashstore-osd needs a whole NVMe namespace: /dev/null"),
        "{e}"
    );
}

#[test]
fn direct_deallocate_all_takes_the_blkdiscard_path() {
    let Some((c, p)) = file_ctrl("dall", 4 << 20) else {
        return;
    };
    let mut d = c.open_queue(8);
    // runtime trims stay off in direct mode ...
    assert!(!d.geometry().dealloc);
    // ... and the setup-time discard is the ioctl, not the DSM path (a regular file rejects it)
    let e = d.deallocate_all().unwrap_err();
    assert!(e.starts_with("BLKDISCARD [0, 4194304): "), "{e}");
    let _ = std::fs::remove_file(&p);
}

/// The DSM verdict (adr 0169 am. 8): a rejected or unknown verdict keeps runtime deallocate off, an accepted one turns it on
/// for every queue (also one opened before the mount applied it). Cmd mode over a plain file: no IO is submitted.
#[test]
fn dsm_verdict_gates_runtime_deallocate() {
    let p = std::env::temp_dir().join(format!("kdev-dsmv-{}.img", std::process::id()));
    let f = std::fs::File::create(&p).unwrap();
    let id = Ident {
        nsze: 1024,
        data_bytes: LBA,
        awupf: 1,
        awun: 1,
        dsm: true,
        ..Ident::default()
    };
    let c = KernelCtrl::from_parts(f.into(), None, Mode::Cmd, 1, id, None, 3, &p);
    let d = c.open_queue(8);
    assert!(
        !d.geometry().dealloc,
        "no verdict after open: runtime deallocate off"
    );
    c.apply_dsm_verdict(None);
    assert!(!c.geometry().dealloc);
    c.apply_dsm_verdict(Some(true));
    assert!(d.geometry().dealloc && c.geometry().dealloc);
    assert!(c.missing().is_empty());
    c.apply_dsm_verdict(Some(false));
    assert!(!d.geometry().dealloc);
    assert_eq!(c.missing(), vec![MISSING_PASSTHRU_DSM]);
    drop(d);
    drop(c);
    let _ = std::fs::remove_file(&p);
}

#[test]
fn dsm_verdict_is_ignored_in_direct_mode() {
    let Some((c, p)) = file_ctrl("dsmv", 4 << 20) else {
        return;
    };
    c.apply_dsm_verdict(Some(true));
    assert!(!c.geometry().dealloc, "direct mode has no passthrough DSM");
    let _ = std::fs::remove_file(&p);
}

#[test]
fn dsm_probe_status_maps_to_verdict() {
    assert_eq!(dsm_verdict(0), Ok(true));
    assert_eq!(dsm_verdict(0x4002), Ok(false));
    assert!(dsm_verdict(-libc::EINVAL).is_err());
}

/// Write zeroes names its length in NVMe's 16-bit NLB field: a zero or oversized count is a caller shape error (rejected
/// here, so the driver never sees it and the device is never latched dead), not a missing capability.
#[test]
fn write_zeroes_shape_is_refused_before_the_command() {
    let p = std::env::temp_dir().join(format!("kdev-wz-{}.img", std::process::id()));
    let f = std::fs::File::create(&p).unwrap();
    let id = Ident {
        nsze: 1 << 20,
        data_bytes: LBA,
        awupf: 1,
        awun: 1,
        write_zeroes: true,
        ..Ident::default()
    };
    let c = KernelCtrl::from_parts(f.into(), None, Mode::Cmd, 1, id, None, 3, &p);
    let mut d = c.open_queue(8);
    assert_eq!(
        d.submit_write_zeroes(0, 0, 1).unwrap_err().err,
        SubmitError::Invalid
    );
    assert_eq!(
        d.submit_write_zeroes(0, crate::NLB_MAX + 1, 2)
            .unwrap_err()
            .err,
        SubmitError::Invalid
    );
    assert_eq!(
        d.submit_write_zeroes(1 << 20, 1, 3).unwrap_err().err,
        SubmitError::OutOfRange,
        "in-shape but beyond the namespace"
    );
    let _ = std::fs::remove_file(&p);
}

/// A `Debug` of an IO buffer stays a shape: the write-view variant holds the whole payload, whose `Bytes` `Debug` would print
/// every byte (a 128 MiB write view in a log line).
#[test]
fn kbuf_debug_prints_the_shape_not_the_payload() {
    let payload = bytes::Bytes::from(vec![7u8; 4096]);
    let b = KBuf::view(&payload).unwrap();
    let s = format!("{b:?}");
    assert!(s.contains("kind: \"view\""), "{s}");
    assert!(s.contains("len: 4096"), "{s}");
    assert!(
        !s.contains("7, 7"),
        "payload bytes in the Debug output: {s}"
    );
    assert!(s.len() < 200, "{s}");
}

/// Per-piece cost of serving a read piece by reference against copying it (doc/perf/read-path-memory-20261020.md):
/// a device buffer of the piece size is either verified in place and handed out as shared data (`into_shared`: owner box,
/// shelf put / take on the way back) or copied fused with its block crcs into a reused destination (the copy path). Prints
/// ns per piece, the crc pass alone, and the owner + shelf part. Run: `cargo test --release -p nvme --features kernel
/// --lib -- --ignored --nocapture shared_piece_cost`.
#[test]
#[ignore = "microbenchmark"]
fn shared_piece_cost() {
    const BLK: usize = 4096;
    let reps = |len: usize| (400_000_000 / len).clamp(2000, 400_000);
    let ns = |t: std::time::Instant, n: usize| t.elapsed().as_nanos() as f64 / n as f64;
    for kib in [4usize, 8, 16, 32, 64, 256, 1024] {
        let len = kib << 10;
        let n = reps(len);
        let mut dst = vec![std::mem::MaybeUninit::<u8>::uninit(); len];
        let mut crcs = vec![0u32; len / BLK];
        let ring = vec![1u8; 256 << 20]; // the source rotates over more than the LLC: a device buffer is cold
        let at = |i: usize| &ring[(i * len) % ring.len()..][..len];
        let in_place = |b: &[u8], crcs: &mut [u32]| {
            for (c, blk) in crcs.iter_mut().zip(b.as_chunks::<BLK>().0) {
                *c = crc::crc32c(7, blk);
            }
        };
        let t = std::time::Instant::now();
        for i in 0..n {
            in_place(std::hint::black_box(at(i)), &mut crcs);
        }
        let crc_only = ns(t, n);
        let t = std::time::Instant::now();
        for i in 0..n {
            let b = std::hint::black_box(KBuf::new_uninit(len));
            for ((c, s), d) in crcs
                .iter_mut()
                .zip(at(i).as_chunks::<BLK>().0)
                .zip(dst.as_chunks_mut::<BLK>().0)
            {
                *c = crc::crc32c_copy_uninit(7, s, d);
            }
            drop(b);
        }
        let copy = ns(t, n);
        let t = std::time::Instant::now();
        for i in 0..n {
            let b = std::hint::black_box(KBuf::new_uninit(len));
            in_place(at(i), &mut crcs);
            drop(b.into_shared());
        }
        let shared = ns(t, n);
        eprintln!(
            "{kib:5} KiB: crc only {crc_only:8.0} ns | copy path (alloc + crc_copy) {copy:8.0} | shared (alloc + crc + owner + shelf) {shared:8.0} | share - copy {:+.0}",
            shared - copy
        );
    }
}

/// A shared arena buffer dropped on another thread comes back to its allocating thread (`kreturn_hits`); the next buffer of its
/// size on the allocating thread is that very memory, not a fresh carve.
#[test]
fn shared_arena_buffer_returns_to_its_allocating_thread() {
    let len = 37 * 4096; // a bin no other test uses
    let b = KBuf::new_uninit(len);
    if !b.fixed() {
        return; // no arena on this host
    }
    let p = b.ptr as usize;
    let hits = || {
        pool_counters()
            .into_iter()
            .find(|(n, _)| n == "kreturn_hits")
            .unwrap()
            .1
    };
    let before = hits();
    let shared = b.into_shared();
    std::thread::spawn(move || drop(shared)).join().unwrap();
    let again = KBuf::new_uninit(len);
    assert_eq!(again.ptr as usize, p);
    // the counter is process-wide: tests on other threads (the 1500-buffer return test below) add to it concurrently
    assert!(hits() > before);
}

/// A shared heap buffer (a 4 MiB read: above a quarter cache chunk, so plain memory) dropped on another thread comes back to
/// its allocating thread: the next buffer of its size there is that very memory (already faulted), not a fresh allocation.
#[test]
fn shared_heap_buffer_returns_to_its_allocating_thread() {
    let len = 1024 * 4096;
    let b = KBuf::new_heap_uninit(len);
    assert!(!b.fixed() && b.owner.is_some());
    let p = b.ptr as usize;
    let shared = b.into_shared();
    std::thread::spawn(move || drop(shared)).join().unwrap();
    let again = KBuf::new_heap_uninit(len);
    assert_eq!(again.ptr as usize, p);
    assert!(again.initialized.get());
}

/// A whole large read (here 1500 buffers of one bin, far above any fixed slot count) dropped on another thread comes
/// back to the thread that allocated it: the next 1500 allocations are that very memory.
#[test]
fn a_whole_large_read_of_shared_arena_buffers_comes_home() {
    let len = 41 * 4096; // a bin no other test uses
    let first = KBuf::new_uninit(len);
    if !first.fixed() {
        return; // no arena on this host
    }
    let mut bufs = vec![first];
    bufs.extend((1..1500).map(|_| KBuf::new_uninit(len)));
    if !bufs.iter().all(KBuf::fixed) {
        return; // the arena is smaller than the test
    }
    let mut ptrs: Vec<usize> = bufs.iter().map(|b| b.ptr as usize).collect();
    let shared: Vec<_> = bufs.into_iter().map(IoBuf::into_shared).collect();
    std::thread::spawn(move || drop(shared)).join().unwrap();
    let again: Vec<KBuf> = (0..1500).map(|_| KBuf::new_uninit(len)).collect();
    let mut got: Vec<usize> = again.iter().map(|b| b.ptr as usize).collect();
    ptrs.sort_unstable();
    got.sort_unstable();
    assert_eq!(got, ptrs);
}

/// Direct mode: a volatile cache (Identify VWC) the kernel treats as write-through is refused (DSYNC would send no
/// flush / FUA); write back, or no volatile cache, is fine.
#[test]
fn direct_mode_refuses_a_volatile_cache_marked_write_through() {
    let vwc = Ident {
        vwc: true,
        ..Ident::default()
    };
    let d = sysfs("wt", &[("queue/write_cache", "write through\n")]);
    assert!(
        direct_cache_ok(&vwc, &d)
            .unwrap_err()
            .contains("write back")
    );
    assert!(direct_cache_ok(&Ident::default(), &d).is_ok());
    let _ = std::fs::remove_dir_all(&d);
    let d = sysfs("wb", &[("queue/write_cache", "write back\n")]);
    assert!(direct_cache_ok(&vwc, &d).is_ok());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn enter_errors_other_than_retry_later_are_fatal() {
    for e in [libc::EBUSY, libc::EAGAIN, libc::EINTR] {
        assert!(enter_retry_later(&std::io::Error::from_raw_os_error(e)));
    }
    for e in [libc::EBADF, libc::EIO, libc::ENODEV, libc::EFAULT] {
        assert!(!enter_retry_later(&std::io::Error::from_raw_os_error(e)));
    }
}

/// A latched ring failure surfaces through `is_dead` at the next poll and refuses further submits.
#[test]
fn dead_ring_latches_the_device() {
    let Some((c, p)) = file_ctrl("dead", 16 << 20) else {
        return;
    };
    let mut d = c.open_queue(4);
    let mut w = d.alloc_buf_uninit(4096);
    w.copy_from_slice(&[1u8; 4096]);
    d.submit_write(1, w, 1).unwrap();
    assert!(!d.is_dead());
    // SAFETY: this thread's ring, no other reference alive.
    unsafe { &mut *thread_ring().unwrap() }
        .dead
        .trip("test", format_args!("ring failed"));
    let mut out = Vec::new();
    d.poll(0, &mut out);
    assert!(d.is_dead());
    let w = d.alloc_buf_uninit(4096);
    assert_eq!(d.submit_write(2, w, 2).unwrap_err().err, SubmitError::Dead);
    let _ = std::fs::remove_file(p);
}

/// Fake sysfs: controller nvme3 with namespace nvme3n1 (optionally partitioned); no /dev nodes involved.
fn fake_sys(tag: &str, parts: bool) -> PathBuf {
    let root = std::env::temp_dir().join(format!("kdev-sys-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("class/nvme/nvme3/nvme3n1")).unwrap();
    std::fs::create_dir_all(root.join("class/block/nvme3n1")).unwrap();
    if parts {
        std::fs::create_dir_all(root.join("class/block/nvme3n1/nvme3n1p1")).unwrap();
        std::fs::write(root.join("class/block/nvme3n1/nvme3n1p1/partition"), "1").unwrap();
    }
    root
}

#[test]
fn ng_only_identity_and_partitions_from_sysfs() {
    let sys = fake_sys("clean", false);
    assert_eq!(disk_of_ng(&sys, "ng3n1").unwrap(), "nvme3n1");
    assert!(!is_partition(&sys, "nvme3n1"));
    assert!(!has_partitions(&sys, "nvme3n1"));
    // unknown instance / controller: loud, named cause
    assert!(
        disk_of_ng(&sys, "ng3n2")
            .unwrap_err()
            .contains("no nvme3/nvme3n2")
    );
    assert!(
        disk_of_ng(&sys, "ng9n1")
            .unwrap_err()
            .contains("cannot map")
    );
    // an empty disk name never reports partitions (the old false positive)
    assert!(!has_partitions(&sys, ""));
    let sys = fake_sys("parts", true);
    assert!(has_partitions(&sys, "nvme3n1"));
    let _ = std::fs::remove_dir_all(sys);
}

/// The first-failure log names the mappings under a buffer: a range whose tail was unmapped (the errno 14 case: the
/// kernel cannot pin a payload that is gone) says so.
#[test]
fn failure_log_names_unmapped_payload_memory() {
    let len = 4 * 4096;
    // SAFETY: fresh anonymous mapping, unmapped below.
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(p, libc::MAP_FAILED);
    let a = p as usize;
    let whole = mappings_of(a, len);
    assert!(whole.contains("rw"), "{whole}");
    assert!(!whole.contains("unmapped"), "{whole}");
    // SAFETY: the mapping made above.
    assert_eq!(unsafe { libc::munmap(p, len) }, 0);
    // holes from a fixed maps text: other test threads may map into a freed range at any time
    let maps = "10000-12000 rw-p 00000000 00:00 0\n14000-15000 r--p 00000000 08:01 42 /lib/x.so\n";
    assert_eq!(
        mappings_in(maps, 0x10000, 0x6000),
        "0x10000-0x12000 rw-p [anon]; unmapped 0x12000-0x14000; 0x14000-0x15000 r--p /lib/x.so; unmapped 0x15000-0x16000"
    );
    assert_eq!(
        mappings_in(maps, 0x20000, 0x1000),
        "unmapped 0x20000-0x21000"
    );
}

/// The write-view guard (debug and `viewguard` builds only).
#[cfg(any(debug_assertions, feature = "viewguard"))]
mod view_guard {
    use super::*;

    /// Payload memory a test can change behind a `Bytes` (the bug the view guard catches: the bytes under a live write view
    /// reused while the device reads them).
    struct Mutable(Box<[std::cell::UnsafeCell<u8>]>);

    // SAFETY: test-only; written from the test thread while no reader runs.
    unsafe impl Send for Mutable {}
    // SAFETY: see above.
    unsafe impl Sync for Mutable {}

    impl AsRef<[u8]> for Mutable {
        fn as_ref(&self) -> &[u8] {
            // SAFETY: UnsafeCell<u8> has the layout of u8.
            unsafe { std::slice::from_raw_parts(self.0.as_ptr().cast(), self.0.len()) }
        }
    }

    #[test]
    fn view_guard_passes_unchanged_payload() {
        let b = bytes::Bytes::from(vec![7u8; 8192]);
        let v = KBuf::view(&b).expect("views on");
        v.check_view(Path::new("/dev/test"), 0);
    }

    #[test]
    #[should_panic(expected = "write view changed under the device")]
    fn view_guard_stops_on_payload_changed_in_flight() {
        let cells: Box<[std::cell::UnsafeCell<u8>]> =
            (0..8192).map(|_| std::cell::UnsafeCell::new(1)).collect();
        let raw = cells[0].get();
        let b = bytes::Bytes::from_owner(Mutable(cells));
        let v = KBuf::view(&b).expect("views on");
        // SAFETY: inside the cells owned by `b` (UnsafeCell: mutation through a shared owner is allowed).
        unsafe { *raw.add(100) = 2 };
        v.check_view(Path::new("/dev/test"), 0);
    }
}

/// SQE bytes of an entry (opcode at 0, flags at 1, fd at 4, uring_cmd_flags at 28).
fn sqe_bytes(e: squeue::Entry128) -> [u8; 128] {
    // SAFETY: `Entry128` is the 128-byte `io_uring_sqe` plus its 64-byte command area, plain old data.
    unsafe { std::mem::transmute::<squeue::Entry128, [u8; 128]>(e) }
}

/// Data safety (adr 0169 am. 11): in cmd mode a read or write names a buffer in a passthrough command only when the buffer
/// is in the registered arena and the ring registered it (`IORING_URING_CMD_FIXED`); payload views, heap buffers and every
/// buffer on a ring without the registration go as O_DIRECT IO on the queue's block-node slot. A plain user address in a
/// passthrough command can be truncated to 32 bits when the kernel issues it from an io-wq worker (EFAULT, or IO on the
/// wrong memory). Builds the SQEs of every combination and checks the bytes the kernel would read.
#[test]
fn cmd_mode_passthrough_names_only_registered_arena_buffers() {
    const OP_READ: u8 = 22;
    const OP_WRITE: u8 = 23;
    const OP_READ_FIXED: u8 = 4;
    const OP_WRITE_FIXED: u8 = 5;
    const OP_URING_CMD: u8 = 46;
    let p = std::env::temp_dir().join(format!("kdev-route-{}.img", std::process::id()));
    let f = std::fs::File::create(&p).unwrap();
    let blk = f.try_clone().unwrap();
    let id = Ident {
        nsze: 1024,
        data_bytes: LBA,
        awupf: 1,
        awun: 1,
        vwc: true,
        ..Ident::default()
    };
    let c = KernelCtrl::from_parts(f.into(), Some(blk.into()), Mode::Cmd, 1, id, None, 3, &p);
    let mut d = c.open_queue(8);
    d.qid = 3;
    // a view needs 4 KiB-aligned memory (view_buf refuses anything else): slice an aligned window out of a larger buffer
    let raw = bytes::Bytes::from(vec![7u8; 8192 + 4096]);
    let off = (4096 - raw.as_ptr() as usize % 4096) % 4096;
    let payload = raw.slice(off..off + 8192);
    let arena_buf = KBuf::new_uninit(8192);
    // a cache chunk of this thread's ring (none where the kernel has no sparse buffer table)
    let ring = thread_ring().expect("ring");
    // SAFETY: this thread's ring, alive until the thread ends.
    let ring = unsafe { &*ring };
    let cache_buf = KBuf::new_cache_uninit(8192, ring);
    let cached = matches!(cache_buf.kind, Kind::Cache { .. });
    let bufs = [
        ("view", d.view_buf(&payload).expect("aligned view")),
        ("heap", KBuf::new_heap_uninit(8192)),
        ("arena", arena_buf),
        ("cache", cache_buf),
    ];
    let mut cmds = 0;
    for (name, b) in &bufs {
        for op in [Op::Read, Op::Write] {
            for ring_fixed in [false, true] {
                let fx = Fx {
                    arena: ring_fixed,
                    ring: if ring_fixed { ring.id } else { 0 },
                };
                let (e, via) = d.entry(op, 16, 2, Some(b), None, fx).unwrap();
                let s = sqe_bytes(e);
                let fd = i32::from_le_bytes(s[4..8].try_into().unwrap());
                assert_eq!(s[1] & 1, 1, "{name} {op:?}: fixed-file slot");
                if s[0] == OP_URING_CMD {
                    cmds += 1;
                    assert_eq!(via, Via::Cmd);
                    assert!(
                        b.fixed_index(fx).is_some(),
                        "{name} {op:?} ring_fixed={ring_fixed}: passthrough of a plain user address"
                    );
                    assert_eq!(s[28] & 1, 1, "{name} {op:?}: IORING_URING_CMD_FIXED");
                    assert_eq!(fd, 3, "passthrough on the queue's ng slot");
                } else {
                    assert_eq!(via, Via::Block);
                    assert!(
                        b.fixed_index(fx).is_none(),
                        "{name}: registered buffer left passthrough"
                    );
                    let want = match (op, b.fixed_index(fx).is_some()) {
                        (Op::Read, false) => OP_READ,
                        (Op::Write, false) => OP_WRITE,
                        (Op::Read, true) => OP_READ_FIXED,
                        _ => OP_WRITE_FIXED,
                    };
                    assert_eq!(s[0], want, "{name} {op:?} ring_fixed={ring_fixed}");
                    assert_eq!(
                        fd,
                        (MAX_QUEUES + 3) as i32,
                        "{name}: O_DIRECT IO on the block-node slot"
                    );
                    if op == Op::Write {
                        assert_eq!(
                            i32::from_le_bytes(s[28..32].try_into().unwrap()),
                            RWF_DSYNC,
                            "durable write"
                        );
                    }
                }
            }
        }
    }
    if bufs[2].1.fixed() {
        assert_eq!(
            cmds,
            if cached { 4 } else { 2 },
            "arena and cache buffers on a registered ring: passthrough read and write each"
        );
        if cached {
            // the index is the chunk's slot, not the arena's 0
            let (e, _) = d
                .entry(
                    Op::Read,
                    16,
                    2,
                    Some(&bufs[3].1),
                    None,
                    Fx {
                        arena: true,
                        ring: ring.id,
                    },
                )
                .unwrap();
            let Kind::Cache { slot, .. } = bufs[3].1.kind else {
                unreachable!()
            };
            assert_eq!(
                u16::from_le_bytes(sqe_bytes(e)[40..42].try_into().unwrap()),
                slot,
                "buf_index of the cache buffer"
            );
        }
    } else {
        eprintln!("no arena on this host: only the block-node routing checked");
    }
    // write zeroes names no buffer: passthrough
    let none = Fx {
        arena: false,
        ring: 0,
    };
    let (e, via) = d.entry(Op::WriteZeroes, 16, 2, None, None, none).unwrap();
    assert_eq!((sqe_bytes(e)[0], via), (OP_URING_CMD, Via::Cmd));
    // a DSM range is a passthrough data buffer: only from a registered buffer
    let heap_range = KBuf::new_heap_uninit(4096);
    let fx = |arena| Fx {
        arena,
        ring: ring.id,
    };
    let rt = |arena, r: &KBuf| route(Op::Deallocate, Some(r), fx(arena));
    assert_eq!(
        route(Op::Write, Some(&heap_range), fx(true)),
        Ok(Via::Block),
        "a plain read/write is block-node IO"
    );
    // ring without fixed buffers: permanent Unsupported (never the transient QueueFull); registered ring, range outside
    // the arena: QueueFull; arena range on a registered ring: fine
    assert_eq!(rt(false, &heap_range), Err(SubmitError::Unsupported));
    assert_eq!(
        rt(false, &KBuf::new_uninit(4096)),
        Err(SubmitError::Unsupported)
    );
    assert_eq!(rt(true, &heap_range), Err(SubmitError::QueueFull));
    if KBuf::new_uninit(4096).fixed() {
        assert_eq!(rt(true, &KBuf::new_uninit(4096)), Ok(Via::Cmd));
    }
    drop(bufs);
    d.qid = 0;
    drop(d);
    drop(c);
    let _ = std::fs::remove_file(&p);
}

/// Data safety (adr 0169 am. 11): a command keeps its SQE until its CQE is reaped. The kernel may read a passthrough
/// command's SQE after the submit returned (6.12.y issues a punted `URING_CMD` from io-wq with the ring's SQE); a reused
/// slot would hand it another command. A read of an empty pipe stays in flight while three rings' worth of NOPs pass
/// through the same ring: its SQE bytes never change and its index is never handed out; after the pipe write completes it,
/// the index is free again.
#[test]
fn a_pending_command_keeps_its_sqe_until_its_completion() {
    let mut fds = [0i32; 2];
    // SAFETY: plain syscall into a two-int array.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let (rd, wr) = (fds[0], fds[1]);
    let mut r = KRing::new().expect("device ring");
    let q = r.add_queue(rd, rd).expect("queue");
    let mut buf = [0u8; 8];
    let read: squeue::Entry128 = opcode::Read::new(types::Fd(rd), buf.as_mut_ptr(), 8)
        .build()
        .user_data(u64::from(q) << 32 | 7)
        .into();
    let i = r.sq.push(read).expect("free SQE");
    r.pending += 1;
    r.flush();
    let snapshot = r.sq.sqe_bytes(i);
    let entries = r.ring.params().sq_entries() as usize;
    for n in 0..3 * entries {
        let nop: squeue::Entry128 = opcode::Nop::new()
            .build()
            .user_data(u64::from(q) << 32 | 1)
            .into();
        assert!(r.push(&nop), "push {n}");
        r.flush();
        r.reap();
        assert_eq!(
            r.sq.sqe_bytes(i),
            snapshot,
            "SQE of the pending read rewritten at push {n}"
        );
        assert!(
            r.done[q as usize].iter().all(|&(s, _)| s == 1),
            "the read completed early"
        );
        r.done[q as usize].clear();
    }
    assert_eq!(r.sq.out(), 1, "only the pending read holds an SQE");
    // SAFETY: write of 8 bytes from a local array to our own pipe.
    assert_eq!(unsafe { libc::write(wr, [1u8; 8].as_ptr().cast(), 8) }, 8);
    let t = std::time::Instant::now();
    while !r.done[q as usize].iter().any(|&(s, _)| s == 7) {
        r.enter();
        r.reap();
        assert!(
            t.elapsed().as_secs() < 10,
            "WARNING TIMEOUT pipe read exceeded 10s (completion wait)"
        );
    }
    assert_eq!(r.sq.out(), 0, "the read's SQE is free after its CQE");
    assert_eq!(buf, [1u8; 8]);
    r.drop_queue(q);
    // SAFETY: our own fds.
    unsafe {
        libc::close(rd);
        libc::close(wr);
    }
}

/// Data-cache reads come from registered chunks of the thread's ring and read the right bytes; a freed chunk goes back to
/// the kernel after `trim_ram` (the region's own state, not the process-wide counter other tests move), buffers dropped
/// on another thread come home, and the current chunk stays.
#[test]
fn cache_reads_use_registered_chunks_and_chunks_are_returned() {
    let Some((c, p)) = file_ctrl("cr", 64 << 20) else {
        return;
    };
    let mut d = c.open_queue(8);
    let pat: Vec<u8> = (0..65536u32).map(|i| (i * 13 + 5) as u8).collect();
    let mut w = d.alloc_buf_uninit(65536);
    w.copy_from_slice(&pat);
    d.submit_write(0, w, 1).unwrap();
    wait_all(&mut d, 1);
    let chunks = || CACHE.with(|c| (c.borrow().chunks.iter().flatten().count(), c.borrow().idle));
    let probe = d.alloc_buf_ram_uninit(4096);
    if !matches!(probe.kind, Kind::Cache { .. }) {
        eprintln!("no sparse buffer table on this kernel: cache reads are plain memory");
        return;
    }
    drop(probe);
    // fill more than two chunks with 64 KiB reads: all fixed, all correct
    let per_chunk = CACHE_CHUNK / 65536;
    let mut held = Vec::new();
    for i in 0..2 * per_chunk + 5 {
        let b = d.alloc_buf_ram_uninit(65536);
        assert!(matches!(b.kind, Kind::Cache { .. }), "read {i}");
        d.submit_read(0, b, 100 + i as u64).unwrap();
        for c in wait_all(&mut d, 1) {
            let b = c.buf.unwrap();
            assert_eq!(b.as_slice(), &pat[..], "read {i}");
            held.push(b);
        }
    }
    assert_eq!(chunks().0, 3);
    // freeing everything: the two older chunks go back after the trim, the current one stays
    let moved: Vec<KBuf> = held.drain(..per_chunk).collect();
    std::thread::spawn(move || drop(moved)).join().unwrap(); // foreign drop: comes home with the next allocation
    drop(held);
    drop(d.alloc_buf_ram_uninit(65536)); // adopts the returned buffers
    assert_eq!(chunks(), (3, 2));
    d.trim_ram();
    assert_eq!(chunks(), (1, 0));
    // a buffer of a released chunk's size class is carved fresh again, still correct
    let b = d.alloc_buf_ram_uninit(65536);
    d.submit_read(0, b, 9).unwrap();
    assert_eq!(
        wait_all(&mut d, 1)[0].buf.as_ref().unwrap().as_slice(),
        &pat[..]
    );
    drop(d);
    let _ = std::fs::remove_file(p);
}

/// Minor page faults of this thread so far (`getrusage(RUSAGE_THREAD)`; faults the kernel takes while pinning pages for a
/// buffer registration count here too).
fn thread_minflt() -> i64 {
    // SAFETY: getrusage fills the zeroed struct.
    let mut u: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: valid out pointer.
    assert_eq!(unsafe { libc::getrusage(libc::RUSAGE_THREAD, &mut u) }, 0);
    u.ru_minflt
}

/// `AnonHugePages` of the mapping that holds `addr` (`/proc/self/smaps`), in KiB.
fn anon_huge_kb(addr: usize) -> u64 {
    let smaps = std::fs::read_to_string("/proc/self/smaps").expect("smaps");
    let mut inside = false;
    for l in smaps.lines() {
        let first = l.split_whitespace().next().unwrap_or("");
        if let Some((a, b)) = first.split_once('-')
            && let (Ok(a), Ok(b)) = (usize::from_str_radix(a, 16), usize::from_str_radix(b, 16))
        {
            inside = (a..b).contains(&addr);
        } else if inside && let Some(v) = l.strip_prefix("AnonHugePages:") {
            return v
                .trim()
                .trim_end_matches("kB")
                .trim()
                .parse()
                .expect("AnonHugePages kB");
        }
    }
    panic!("no mapping holds {addr:#x}");
}

/// Pages of `[addr, addr + len)` not resident (`mincore`).
fn not_resident(addr: usize, len: usize) -> usize {
    let mut v = vec![0u8; len / 4096];
    // SAFETY: page-aligned range of a live mapping, one vector byte per 4 KiB page.
    let rc = unsafe { libc::mincore(addr as *mut libc::c_void, len, v.as_mut_ptr()) };
    assert_eq!(rc, 0, "mincore: {}", std::io::Error::last_os_error());
    v.iter().filter(|&&b| b & 1 == 0).count()
}

/// Cache growth registers a chunk whose pages are already resident (doc/perf/r4k-tail-20261102.md): when an allocation is
/// about to open a chunk after a thread's first one, the next chunk is fully resident (before: the registration faulted all
/// 512 pages of a fresh chunk in, ~0.6 ms), and no chunk is a transparent huge page (one write would fault and zero all of
/// it). The faults and time of the opening allocations are printed, not asserted: compaction or reclaim on a loaded runner
/// may move populated pages before they are pinned.
#[test]
fn cache_growth_registers_resident_pages() {
    let Some((c, p)) = file_ctrl("cg", 64 << 20) else {
        return;
    };
    let mut d = c.open_queue(8);
    let probe = d.alloc_buf_ram_uninit(4096);
    if !matches!(probe.kind, Kind::Cache { .. }) {
        eprintln!("no sparse buffer table on this kernel: cache reads are plain memory");
        return;
    }
    let chunks = || CACHE.with(|c| c.borrow().chunks.iter().flatten().count());
    let per_chunk = CACHE_CHUNK / 4096;
    let mut held = Vec::with_capacity(3 * per_chunk);
    held.push(probe);
    let (mut checked, mut opened) = (0, 0);
    for i in 0..2 * per_chunk + 8 {
        let full = CACHE.with(|c| {
            let c = c.borrow();
            let cur = c.chunks[c.cur.expect("current chunk")]
                .as_ref()
                .expect("live");
            (cur.used + 4096 > CACHE_CHUNK).then(|| c.next.expect("next chunk mapped").0)
        });
        if let Some(next) = full {
            checked += 1;
            assert_eq!(
                not_resident(next, CACHE_CHUNK),
                0,
                "allocation {i} opens a chunk that is not resident"
            );
        }
        let before = (chunks(), thread_minflt(), std::time::Instant::now());
        let b = d.alloc_buf_ram_uninit(4096);
        let (faults, took) = (thread_minflt() - before.1, before.2.elapsed());
        assert!(matches!(b.kind, Kind::Cache { .. }), "allocation {i}");
        if chunks() > before.0 {
            opened += 1;
            eprintln!("allocation {i} opened a chunk: {faults} faults, {took:?}");
        }
        held.push(b);
    }
    assert_eq!(
        (opened, checked),
        (2, 2),
        "two chunk boundaries crossed, each checked"
    );
    // one fault = one 4 KiB page: a huge page would fault and zero a whole chunk in one write (THP `always`)
    let bases: Vec<usize> = CACHE.with(|c| {
        let c = c.borrow();
        c.chunks
            .iter()
            .flatten()
            .map(|k| k.base)
            .chain(c.next.map(|n| n.0))
            .collect()
    });
    for b in bases {
        assert_eq!(
            anon_huge_kb(b),
            0,
            "chunk {b:#x} is backed by transparent huge pages"
        );
    }
    drop(held);
    drop(d);
    let _ = std::fs::remove_file(p);
}

/// Measurement, not a check: the cost of registering one cache chunk on this kernel (doc/perf/r4k-tail-20261102.md),
/// fresh anonymous memory (the registration faults and zeroes every page) vs populated pages, each with and without
/// transparent huge pages. Run: `cargo test -p nvme --features kernel,lab --lib -- --ignored --nocapture registration_cost`.
#[test]
#[ignore = "measurement: prints registration times"]
fn cache_chunk_registration_cost() {
    let Some((c, p)) = file_ctrl("cr", 64 << 20) else {
        return;
    };
    let mut d = c.open_queue(8);
    let Ok(r) = d.bind() else {
        return;
    };
    if r.cache_slots == 0 {
        eprintln!("no sparse buffer table on this kernel");
        return;
    }
    let slot = r.cache_slots; // the region fills slots from 1
    let empty = libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    };
    for round in 0..3 {
        for (populated, huge) in [(false, true), (true, true), (false, false), (true, false)] {
            // SAFETY: anonymous mapping, unmapped below after it was unregistered.
            let m = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    CACHE_CHUNK,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(m, libc::MAP_FAILED);
            if !huge {
                // SAFETY: advice on the mapping above.
                unsafe { libc::madvise(m, CACHE_CHUNK, libc::MADV_NOHUGEPAGE) };
            }
            if populated {
                for at in (0..CACHE_CHUNK).step_by(TOUCH) {
                    // SAFETY: inside the mapping above.
                    unsafe { std::ptr::write_volatile((m as usize + at) as *mut u8, 0) };
                }
            }
            let iov = libc::iovec {
                iov_base: m,
                iov_len: CACHE_CHUNK,
            };
            let (f0, t0) = (thread_minflt(), std::time::Instant::now());
            // SAFETY: the mapping stays until it is unregistered below.
            unsafe {
                r.ring
                    .submitter()
                    .register_buffers_update(slot, &[iov], None)
            }
            .expect("register");
            let (faults, reg) = (thread_minflt() - f0, t0.elapsed());
            let t1 = std::time::Instant::now();
            // SAFETY: clearing the slot registered above.
            unsafe {
                r.ring
                    .submitter()
                    .register_buffers_update(slot, &[empty], None)
            }
            .expect("unregister");
            let unreg = t1.elapsed();
            // SAFETY: unregistered above.
            unsafe { libc::munmap(m, CACHE_CHUNK) };
            eprintln!(
                "round {round} populated {populated} thp {huge}: register {reg:?} ({faults} faults), unregister {unreg:?}"
            );
        }
    }
    // populating a 4 KiB-page chunk: one write fault per page vs MADV_POPULATE_WRITE batches (no trap per page)
    for round in 0..3 {
        for batch in [0usize, 16 * TOUCH, CACHE_CHUNK] {
            let m = map_chunk().expect("map");
            let t0 = std::time::Instant::now();
            let mut at = 0;
            while at < CACHE_CHUNK {
                if batch == 0 {
                    // SAFETY: inside the mapping above.
                    unsafe { std::ptr::write_volatile((m + at) as *mut u8, 0) };
                    at += TOUCH;
                } else {
                    // SAFETY: range inside the mapping above.
                    let rc = unsafe {
                        libc::madvise(
                            (m + at) as *mut libc::c_void,
                            batch,
                            libc::MADV_POPULATE_WRITE,
                        )
                    };
                    assert_eq!(
                        rc,
                        0,
                        "MADV_POPULATE_WRITE: {}",
                        std::io::Error::last_os_error()
                    );
                    at += batch;
                }
            }
            let took = t0.elapsed();
            // SAFETY: never registered.
            unsafe { libc::munmap(m as *mut libc::c_void, CACHE_CHUNK) };
            eprintln!(
                "round {round} populate batch {batch} B: {took:?} per chunk, {:?} per page",
                took / (CACHE_CHUNK / TOUCH) as u32
            );
        }
    }
    drop(d);
    let _ = std::fs::remove_file(p);
}
