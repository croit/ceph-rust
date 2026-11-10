// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Hostile or corrupted import file (spec 3): section bounds, data offsets, undecodable attributes, unknown
//! section types, io error classification, and the size bound of a `--file` / stdin input.
mod common;
use common::*;
use denc::types::{CollT, Eversion, SnapId};
use std::io::Read;
use store::obj::OTxn;

/// 16 byte export super header (magic, format version 2, header 18, footer 10).
fn super_hdr() -> Vec<u8> {
    let mut v = Vec::new();
    for x in [0xffce_ffceu32, 2, 18, 10] {
        v.extend_from_slice(&x.to_le_bytes());
    }
    v
}

/// 18 byte section header: `ENV(1,1){ u32 type_magic, i64 size }`.
fn section_hdr(t: u8, size: i64) -> Vec<u8> {
    let mut v = vec![1, 1];
    v.extend_from_slice(&12u32.to_le_bytes());
    v.extend_from_slice(&((u32::from(t) << 24) | (u32::from(t) << 16) | 0xffce).to_le_bytes());
    v.extend_from_slice(&size.to_le_bytes());
    v
}

/// Byte offset of the `n`-th section of type `t` in an export file.
fn find_section(bytes: &[u8], t: u8, n: usize) -> usize {
    let mut off = 16;
    let mut seen = 0;
    while off + 18 <= bytes.len() {
        let ty = bytes[off + 8];
        let size = i64::from_le_bytes(bytes[off + 10..off + 18].try_into().unwrap());
        assert!(size >= 0, "corrupt size in a real export");
        if ty == t {
            if seen == n {
                return off;
            }
            seen += 1;
        }
        off += 18 + size as usize + if size > 0 { 10 } else { 0 };
    }
    panic!("no section type {t} #{n}");
}

fn export_to(r: &mut Rig, pgid: &str, f: &std::path::Path) -> Vec<u8> {
    let o = run(
        r,
        &[
            "--op",
            "export",
            "--pgid",
            pgid,
            "--file",
            f.to_str().unwrap(),
        ],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    std::fs::read(f).unwrap()
}

fn tmp(tag: &str, name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("ostool-ct-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d.join(name)
}

/// A reader that fails with an io error that is not EOF.
#[derive(Debug)]
struct Eio;

impl Read for Eio {
    fn read(&mut self, _b: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("media error"))
    }
}

#[test]
fn export_reader_refuses_oversized_bodies() {
    // A few-bytes file that claims a 2 GiB DATA body must be refused before it is allocated.
    let mut b = super_hdr();
    b.extend_from_slice(&section_hdr(5, 0x7fff_ffff));
    b.push(0);
    let mut body = Vec::new();
    match ostool::fmt::SectionReader::open(&b[..]).and_then(|mut r| r.read_next(&mut body)) {
        Ok(t) => panic!("accepted a 2 GiB section, type {t}"),
        Err(e) => assert!(e.contains("size"), "{e}"),
    }
    // The same body size is legal for a non-DATA section only up to the in-memory input bound.
    let mut b = super_hdr();
    b.extend_from_slice(&section_hdr(6, 1 << 30));
    b.push(0);
    let mut body = Vec::new();
    match ostool::fmt::SectionReader::open(&b[..]).and_then(|mut r| r.read_next(&mut body)) {
        Ok(_) => panic!("accepted a 1 GiB attributes section"),
        Err(e) => assert!(e.contains("size"), "{e}"),
    }
    // A DATA body above one 8 MiB chunk is out of spec.
    let mut b = super_hdr();
    b.extend_from_slice(&section_hdr(5, (8 << 20) + 64));
    let mut body = Vec::new();
    assert!(
        ostool::fmt::SectionReader::open(&b[..])
            .and_then(|mut r| r.read_next(&mut body))
            .is_err()
    );
    // A truncated body is a clean EOF error, not a huge allocation.
    let mut b = super_hdr();
    b.extend_from_slice(&section_hdr(5, 1000));
    b.extend_from_slice(&[0; 10]);
    let mut body = Vec::new();
    let e = ostool::fmt::SectionReader::open(&b[..])
        .and_then(|mut r| r.read_next(&mut body))
        .unwrap_err();
    assert!(e.contains("Unexpected EOF"), "{e}");
}

#[test]
fn export_reader_reports_io_errors() {
    let e = ostool::fmt::SectionReader::open(Eio).unwrap_err();
    assert!(e.contains("media error"), "{e}");
    assert!(!e.contains("Unexpected EOF"), "{e}");
    // the stream ends after the first section: the next header read is a short read, not an io error
    let mut b = super_hdr();
    b.extend_from_slice(&section_hdr(1, 0));
    let mut rd = ostool::fmt::SectionReader::open(&b[..]).unwrap();
    let mut body = Vec::new();
    assert_eq!(rd.read_next(&mut body).unwrap(), 1);
    let e = rd.read_next(&mut body).unwrap_err();
    assert!(e.contains("Unexpected EOF"), "{e}");
}

#[test]
fn import_refuses_out_of_range_data_offset() {
    let dir = std::env::temp_dir().join(format!("ostool-ct-off-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("pg.export");
    let mut a = rig(6);
    make_pg(&a, spg(1, 2), 1);
    let mut bytes = export_to(&mut a, "1.2", &f);
    // the first DATA body: ENV(1,1){ u64 off, u64 len, buffer } with off at body + 6
    let h = find_section(&bytes, 5, 0);
    bytes[h + 18 + 6..h + 18 + 14].copy_from_slice(&u64::MAX.to_le_bytes());
    let bad = dir.join("bad.export");
    std::fs::write(&bad, &bytes).unwrap();
    let mut b = rig(6);
    let o = run(
        &mut b,
        &["--op", "import", "--file", bad.to_str().unwrap()],
        b"",
    );
    assert_ne!(o.code, 0);
    assert!(o.err.contains("size limit"), "{}", o.err);
    assert!(list_pgs(&mut b).is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn import_refuses_undecodable_snapset() {
    let dir = std::env::temp_dir().join(format!("ostool-ct-ss-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("pg.export");
    let mut a = rig(6);
    let s = spg(1, 2);
    make_pg(&a, s, 1);
    // the head's snapset does not decode: the import must fail instead of dropping the clone metadata
    let g = gh(s, &hobj(s, "snapped", SnapId::NOSNAP));
    let mut t = OTxn::new();
    t.sys = true;
    t.setattr(CollT::Pg(s), &g, b"snapset", &[0xff; 3]);
    a.ad.with_store(|st| st.commit(&t)).unwrap();
    export_to(&mut a, "1.2", &f);
    let mut b = rig(6);
    let o = run(
        &mut b,
        &["--op", "import", "--file", f.to_str().unwrap()],
        b"",
    );
    assert_ne!(o.code, 0);
    assert!(o.err.contains("snapset"), "{}", o.err);
    assert!(list_pgs(&mut b).is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn import_skips_unknown_section_inside_object() {
    let dir = std::env::temp_dir().join(format!("ostool-ct-unk-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("pg.export");
    let mut a = rig(6);
    make_pg(&a, spg(1, 2), 1);
    let mut bytes = export_to(&mut a, "1.2", &f);
    // a future section type (12, header-only) inside an object group, before its first DATA section
    let h = find_section(&bytes, 3, 0);
    let after =
        h + 18 + i64::from_le_bytes(bytes[h + 10..h + 18].try_into().unwrap()) as usize + 10;
    bytes.splice(after..after, section_hdr(12, 0));
    let unk = dir.join("unk.export");
    std::fs::write(&unk, &bytes).unwrap();
    let mut b = rig(6);
    let o = run(
        &mut b,
        &["--op", "import", "--file", unk.to_str().unwrap()],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    assert_eq!(snapshot(&a, spg(1, 2)), snapshot(&b, spg(1, 2)));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn input_size_is_bounded() {
    // a sparse file above the in-memory input bound is refused from its metadata, before it is read
    let p = tmp("big", "huge.bin");
    let f = std::fs::File::create(&p).unwrap();
    f.set_len(256 << 20).unwrap();
    drop(f);
    let mut r = rig(6);
    make_pg(&r, spg(1, 0), 0);
    let o = run(
        &mut r,
        &["--op", "set-superblock", "--file", p.to_str().unwrap()],
        b"",
    );
    assert_ne!(o.code, 0);
    assert!(o.err.contains("limit"), "{}", o.err);
    let o = run(
        &mut r,
        &["--pgid", "1.0", "small", "set-bytes", p.to_str().unwrap()],
        b"",
    );
    assert_ne!(o.code, 0);
    assert!(o.err.contains("limit"), "{}", o.err);
    let _ = std::fs::remove_dir_all(p.parent().unwrap());
}

#[test]
fn streamed_data_section_is_byte_identical_to_the_encoded_one() {
    // the export writes the DATA payload straight into the writer: the container bytes must not change
    let data = pattern(3000, 7);
    for (off, d) in [(0u64, &data[..]), (1 << 40, &data[..0])] {
        let mut streamed = Vec::new();
        let mut w = ostool::fmt::SectionWriter::new(&mut streamed);
        w.data(off, d).unwrap();
        w.finish().unwrap();
        let mut encoded = Vec::new();
        let mut w = ostool::fmt::SectionWriter::new(&mut encoded);
        w.section(ostool::fmt::T_DATA, &ostool::fmt::enc_data(off, d).unwrap())
            .unwrap();
        w.finish().unwrap();
        assert_eq!(streamed, encoded);
    }
}

#[test]
fn import_overlapping_zero_data_clears_previous_bytes_after_replay() {
    use ostool::fmt::{self, SectionReader, SectionWriter};
    let f = tmp("overlap-zero", "pg.export");
    let mut source = rig(6);
    let spg = spg(1, 2);
    make_pg(&source, spg, 1);
    let cid = CollT::Pg(spg);
    let g = gh(spg, &hobj(spg, "big", SnapId::NOSNAP));
    // Bigger than the import batch: the original data becomes durable before
    // the overlapping zero section is applied. Unaligned ends cover partial blocks.
    let original = pattern((5 << 20) + 17, 31);
    let mut t = OTxn::new();
    t.sys = true;
    t.write(cid, &g, 0, &original);
    let oi = oi_bytes(&g.hobj, Eversion::new(3, 2), original.len() as u64);
    t.setattr(cid, &g, b"_", &oi);
    source.ad.with_store(|s| s.commit(&t)).unwrap();
    let bytes = export_to(&mut source, "1.2", &f);
    let mut rd = SectionReader::open(&bytes[..]).unwrap();
    let mut wr = SectionWriter::new(Vec::new());
    wr.write_super().unwrap();
    let mut body = Vec::new();
    let mut target = false;
    let mut injected = false;
    loop {
        let ty = rd.read_next(&mut body).unwrap();
        if ty == fmt::T_OBJECT_BEGIN {
            target = fmt::dec_object_begin(&body).unwrap().hoid == g;
        }
        if body.is_empty() {
            wr.simple(ty).unwrap();
        } else {
            wr.section(ty, &body).unwrap();
        }
        if target && ty == fmt::T_DATA {
            assert!(!injected);
            wr.data(3, &vec![0; original.len() - 6]).unwrap();
            injected = true;
        }
        if ty == fmt::T_PG_END {
            break;
        }
    }
    assert!(injected);
    let archive = wr.finish().unwrap();
    let mut dest = rig(6);
    let out = run(&mut dest, &["--op", "import"], &archive);
    assert_eq!(out.code, 0, "{}", out.err);
    // Capture power-loss media before dropping any live store state.
    let recovered_disk = store::dev::SimDisk::from_image(
        &dest.disk.crash_image(store::dev::CrashPolicy::DROP_ALL),
        dest.disk.config(),
    );
    let mut dest = mount(&recovered_disk);
    let out = run(&mut dest, &["--pgid", "1.2", "big", "get-bytes"], b"");
    assert_eq!(out.code, 0, "{}", out.err);
    let mut expected = original;
    let end = expected.len() - 3;
    expected[3..end].fill(0);
    assert!(
        out.out == expected,
        "overlapping zero DATA retained old bytes"
    );
    std::fs::remove_dir_all(f.parent().unwrap()).unwrap();
}

#[test]
fn import_preserves_ec_log_head_above_last_entry() {
    use denc::types::ShardId;
    use osd::meta::{MapKind, MetaStore};
    use peering::{StoreOp, StoreTxn};

    // A log head may advance without an entry (mark-complete), or remain above
    // the last retained entry after the placement filter discards entries.
    for shard in [ShardId::NO_SHARD, ShardId(0)] {
        let mut source = rig(6);
        let mut s = spg(1, 2);
        s.shard = shard;
        let mut map = osdmap_at(6, &[1]);
        if shard.0 >= 0 {
            map.pools.get_mut(&1).unwrap().ptype = 3;
        }
        let raw_map = map.encode_full().unwrap();
        let sb = source.meta.load_superblock().unwrap().unwrap();
        source
            .meta
            .commit_maps(&[(6, MapKind::Full, raw_map.clone())], &sb)
            .unwrap();
        source
            .ad
            .try_submit(
                s,
                &StoreTxn {
                    ops: vec![StoreOp::CreatePg],
                },
            )
            .unwrap();
        let head = Eversion::new(6, 9);
        let rollback = Eversion::new(4, 3);
        let mut info = pgwire::PgInfo::new(s);
        info.last_update = head;
        info.last_complete = head;
        let log = pgwire::PgLog {
            head,
            can_rollback_to: rollback,
            rollback_info_trimmed_to: rollback,
            ..Default::default()
        };
        source
            .ad
            .try_submit(
                s,
                &StoreTxn {
                    ops: vec![
                        StoreOp::LogReplace(Box::new(log.clone())),
                        StoreOp::PutInfo(Box::new(info.clone())),
                        StoreOp::PutEpoch(6),
                    ],
                },
            )
            .unwrap();
        let path = tmp(&format!("ec-head-{}", shard.0), "pg.export");
        let archive = export_to(&mut source, &s.to_string(), &path);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
        let mut dest = rig(6);
        dest.meta
            .commit_maps(&[(6, MapKind::Full, raw_map)], &sb)
            .unwrap();
        let o = run(&mut dest, &["--op", "import"], &archive);
        assert_eq!(o.code, 0, "{}", o.err);
        let disk = store::dev::SimDisk::from_image(
            &dest.disk.crash_image(store::dev::CrashPolicy::DROP_ALL),
            dest.disk.config(),
        );
        let recovered = mount(&disk);
        let actual = storeadapt::meta::load(&recovered.ad, s).unwrap().unwrap();
        assert_eq!(
            actual.log.head, head,
            "shard {} lost exported log head",
            shard.0
        );
        if shard.0 >= 0 {
            assert_eq!(actual.log.can_rollback_to, rollback);
            assert_eq!(actual.log.rollback_info_trimmed_to, rollback);
        }
    }
}
