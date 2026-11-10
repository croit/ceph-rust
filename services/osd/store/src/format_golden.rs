// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Downgrade guard (adr 0021 "Format changes" rule): golden encodings of the persisted store structures, keyed by the format
//! key `(FORMAT_VERSION, shared-format incompat feature bits)`. An older build refuses a store only through that key (an
//! unknown bit or version, `layout::read_super`); an encoding that changes under an unchanged key would be misread by it.
//!
//! The test encodes one fixed sample of every structure and compares it with `format-golden.txt` (crate root):
//! - an entry of the current key differs: the format changed without a new bit or version -> add a `FEAT_` bit (set it
//!   before the first record that needs it) or bump `FORMAT_VERSION`, then append the entries of the new key;
//! - the current key or a sample is missing: append the printed lines.
//!
//! The file is append-only (`scripts/check-store-format.sh`, pre-commit): an entry of an existing key is never edited.
//! New persisted structures add a sample here.

use crate::alloc::{MetaAlloc, MetaExtent};
use crate::codec::Enc;
use crate::layout::{
    Expansion, FEAT_CHUNKED, FEAT_OMAP_SPLINTERDB, FEATURES_KNOWN, FORMAT_VERSION, RootSlot,
    ShardDir, Superblock,
};
use crate::obj::keys::omap_key;
use crate::obj::onode::{CollInfo, CompMeta, Ext, F_COMP, F_DVER, F_OMAP, Onode};
use crate::olsm::wire::OOp;
use crate::runs::RunBuilder;
use crate::state::{Extent, Op, Record};
use crate::wal::{FLAG_END, UnitHeader, encode_record};

/// SplinterDB adds an engine identity, not another encoding of these shared
/// structures. Keep native/Rocks golden samples identical even in combined builds.
/// Its independent feature-bit encoding is checked below and in layout tests.
fn shared_format_features() -> u64 {
    (FEATURES_KNOWN & !FEAT_OMAP_SPLINTERDB) | FEAT_CHUNKED
}

fn format_key() -> String {
    format!("v{FORMAT_VERSION} f{:#x}", shared_format_features())
}

/// `<length>:<crc32c>` of a sample: any change of the encoding changes it. The length is appended before the crc: a
/// self-checksummed encoding (its own crc32c at the end) would otherwise always yield the crc residue.
fn digest(b: &[u8]) -> String {
    let mut m = b.to_vec();
    m.extend_from_slice(&(b.len() as u64).to_le_bytes());
    format!("{}:{:08x}", b.len(), crate::codec::crc(&m))
}

/// Encoded bytes up to the last non-zero byte (block padding is not part of the format statement).
fn trimmed(b: &[u8]) -> &[u8] {
    &b[..b.iter().rposition(|&x| x != 0).map_or(0, |i| i + 1)]
}

fn samples() -> Vec<(&'static str, Vec<u8>)> {
    let mut v: Vec<(&'static str, Vec<u8>)> = Vec::new();
    let sb = Superblock {
        version: FORMAT_VERSION,
        features: shared_format_features(),
        osd_fsid: [1; 16],
        osd_id: 7,
        cluster_fsid: [2; 16],
        lba_size: 4096,
        size_bytes: 1 << 40,
        nsid: 1,
        awupf_lbas: 1,
        awun_lbas: 2,
        plp: true,
        shards: 2,
        node_size: 4096,
        wal_blocks: 1024,
        meta_pct: 8,
        dir_blk: 2,
        dir_blocks: 1,
        dir_crc: 0x1234_5678,
        mkfs_time: 1_700_000_000,
        cell_pages: 256,
        expand: vec![Expansion {
            start: 1 << 20,
            per_shard: 4096,
        }],
        base_pct: 25,
        chunk_blocks: 1 << 14,
        upgrading: 7,
        dsm_verdict: Some(true),
    };
    v.push(("superblock", trimmed(&sb.encode()).to_vec()));
    let dir = ShardDir {
        shard: 1,
        region_start: 16,
        region_blocks: 1 << 20,
        root_a: 16,
        root_b: 17,
        wal_start: 18,
        wal_blocks: 1024,
        meta_start: 1042,
        meta_blocks: 4096,
        data_start: 5138,
        data_blocks: 1 << 19,
        ext: Vec::new(),
        chunk_blocks: 0,
        #[cfg(feature = "elastic")]
        lent: Vec::new(),
    };
    let mut e = Enc::new();
    dir.encode(&mut e);
    v.push(("shard_dir", e.b));
    let mut root = RootSlot {
        shard: 1,
        seq: 9,
        epoch: 3,
        ckpt_lsn: 100,
        wal_tail_pos: 5,
        wal_tail_prev_crc: 0xdead_beef,
        tree_root: 77,
        tree_crc: 0x0bad_f00d,
        tree_height: 3,
        meta_bitmap_addr: 1042,
        meta_bitmap_len: 2,
        meta_bitmap_crc: 0x55aa_55aa,
        next_onode_id: 1000,
        used_blocks: 12345,
        meta_pages_used: 99,
        ..Default::default()
    };
    v.push(("root_slot", trimmed(&root.encode()).to_vec()));
    root.wal_tail_lsn = 90;
    root.run_floor = 80;
    v.push(("root_slot_runs", trimmed(&root.encode()).to_vec()));
    let h = UnitHeader {
        epoch: 3,
        first_lsn: 101,
        ntxn: 1,
        nblocks: 2,
        flags: FLAG_END,
        shard: 1,
        payload_len: 300,
        prev_crc: 0x1111_2222,
        payload_crc: 0x3333_4444,
        acked_lsn: 99,
        store_id: 5,
    };
    let mut b = vec![0u8; crate::wal::HDR_LEN];
    h.write(&mut b);
    v.push(("wal_unit_header", b));
    let mut run = RunBuilder::with_capacity(3, 64);
    run.push(&omap_key(5, b"a"), b"", b"", b"1");
    run.push(&omap_key(5, b"b"), b"", b"", b"22");
    // a removal (FEAT_OMAP_TOMBS): empty value
    run.push(&omap_key(5, b"c"), b"", b"", b"");
    let run = run.finish(5).expect("valid run");
    let (n, blob) = {
        let mut e = Enc::new();
        e.u16(1).bytes(b"k").u32(1).bytes(b"v");
        (1, bytes::Bytes::from(e.b))
    };
    let rec = Record {
        lsn: 101,
        ops: vec![
            Op::Put(b"key".to_vec(), b"val".to_vec()),
            Op::Del(b"gone".to_vec()),
            Op::DelRange(b"a".to_vec(), b"b".to_vec()),
            Op::RunPut(run),
            Op::RunMerge {
                id: 5,
                upto: 90,
                a: b"a".to_vec(),
                b: b"z".to_vec(),
                fin: true,
            },
            Op::Omap(OOp::Put { id: 6, n, blob }),
            Op::Omap(OOp::Range {
                id: 6,
                first: bytes::Bytes::from_static(b"c"),
                end: Some(bytes::Bytes::from_static(b"d")),
            }),
        ],
        data: vec![Extent {
            blk: 5200,
            nblk: 2,
            crcs: vec![0xaaaa_bbbb, 0xcccc_dddd],
        }],
        frees: vec![(6000, 4)],
    };
    let mut e = Enc::new();
    encode_record(&rec, &mut e);
    v.push(("wal_record", e.b));
    // format 2 (exact omap counters) is read, never written (`FEAT_OMAP_UNCOUNTED`)
    for (name, flags) in [
        ("onode_v1", 0),
        ("onode_v3", F_OMAP | F_COMP),
        ("onode_v4", F_OMAP | F_COMP | F_DVER),
    ] {
        let o = Onode {
            size: 4 << 20,
            flags,
            comp: 1000,
            comp_orig: 4000,
            dv: 3,
        };
        v.push((name, o.encode()));
    }
    let mut c = CollInfo {
        id: 42,
        bits: 5,
        nobj: 10,
        nbytes: 1 << 20,
        ..Default::default()
    };
    v.push(("coll_v1", c.encode()));
    c.comp = 100;
    c.comp_orig = 400;
    v.push(("coll_v2", c.encode()));
    c.dv_on = true;
    c.dv_gen = 2;
    v.push(("coll_v3", c.encode()));
    let mut x = Ext {
        pba: 5200,
        crcs: vec![1, 2, 3],
        comp: None,
        shared: false,
    };
    v.push(("ext", x.encode()));
    x.shared = true;
    v.push(("ext_shared", x.encode()));
    x.comp = Some(CompMeta {
        alg: 1,
        raw_blks: 16,
        lcrc: 0x7777_8888,
        skip: 2,
        win: 4,
    });
    v.push(("ext_comp_view", x.encode()));
    let mut m = MetaAlloc::new_elastic(128, 64);
    m.set(3);
    m.add_cell_extents(vec![
        MetaExtent {
            start: 9000,
            pages: 32,
        },
        MetaExtent {
            start: 9100,
            pages: 32,
        },
    ]);
    v.push(("meta_image", m.blob_encode(&[])));
    for (name, kind, fmt) in [
        ("tree_leaf", crate::page::LEAF, 0),
        ("tree_int_compact", crate::page::INT, 1),
    ] {
        let mut b = vec![0u8; 4096];
        crate::page::init_fmt(
            &mut b,
            kind,
            u8::from(kind == crate::page::INT),
            300,
            1,
            fmt,
        );
        crate::page::seal(&mut b, 300, 101);
        v.push((name, b));
    }
    let d = crate::olsm::manifest::RunDesc {
        id: 11,
        lsn_lo: 50,
        lsn_hi: 60,
        meta_blk: 7000,
        meta_nblk: 2,
        meta_crc: 0x9999_aaaa,
        chunks: 3,
        entries: 1000,
        tombs: 10,
        data_bytes: 1 << 20,
        place: crate::olsm::Place {
            tier: 1,
            lo: crate::olsm::Gk {
                id: 5,
                key: bytes::Bytes::from_static(b"m"),
            },
            hi: Some(crate::olsm::Gk {
                id: 9,
                key: bytes::Bytes::new(),
            }),
        },
    };
    v.push(("olsm_run_desc", d.encode()));
    #[cfg(feature = "elastic")]
    v.push((
        "lend_block",
        trimmed(&crate::lend::encode(
            0,
            4,
            &[crate::lend::Entry { owner: 1, slot: 2 }],
        ))
        .to_vec(),
    ));
    v
}

#[test]
fn splinter_identity_does_not_replace_shared_golden_keys() {
    let expected = if cfg!(feature = "rocksdb") {
        "v2 f0x3ffdfff"
    } else {
        "v2 f0x1ffdfff"
    };
    assert_eq!(format_key(), expected);
    assert_eq!(shared_format_features() & FEAT_OMAP_SPLINTERDB, 0);
    assert_eq!(
        shared_format_features() | (FEATURES_KNOWN & FEAT_OMAP_SPLINTERDB),
        FEATURES_KNOWN | FEAT_CHUNKED,
    );
    // Independent little-endian vector for the newly reserved engine identity.
    // Shared structures keep their existing goldens; selected-SDB provisioning,
    // read_super and replay tests cover actually setting/reading this header bit.
    assert_eq!(FEAT_OMAP_SPLINTERDB.to_le_bytes(), [0, 0, 0, 4, 0, 0, 0, 0]);
}

#[test]
fn encoded_splinter_header_has_an_independent_feature_vector() {
    let (mut sb, _) = crate::layout::plan(
        (64 << 20) / crate::BLK as u64,
        &crate::layout::MkfsParams {
            shards: 1,
            wal_blocks: 512,
            align_blocks: 1,
            ..Default::default()
        },
    )
    .unwrap();
    // Isolate the engine header from optional shared-format fields. This tests
    // production serialization, not a vector computed from the feature constant.
    sb.features = crate::layout::FEAT_OMAP_LSM | FEAT_OMAP_SPLINTERDB;
    sb.osd_fsid = [0x5a; 16];
    let encoded = sb.encode();
    assert_eq!(&encoded[8..12], &[2, 0, 0, 0]);
    assert_eq!(&encoded[12..20], &[0, 0, 8, 4, 0, 0, 0, 0]);
    assert_eq!(&encoded[20..36], &[0x5a; 16]);
}

#[test]
fn persisted_encodings_match_their_format_key() {
    let golden = include_str!("../format-golden.txt");
    let key = format_key();
    let have: std::collections::BTreeMap<&str, &str> = golden
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let mut it = l.splitn(4, ' ');
            let (v, f, name, hx) = (it.next()?, it.next()?, it.next()?, it.next()?);
            (format!("{v} {f}") == key).then_some((name, hx))
        })
        .collect();
    let mut changed = Vec::new();
    let mut missing = Vec::new();
    for (name, bytes) in samples() {
        let hx = digest(&bytes);
        match have.get(name) {
            Some(g) if *g == hx => {}
            Some(_) => changed.push(name),
            None => missing.push(format!("{key} {name} {hx}")),
        }
    }
    assert!(
        changed.is_empty(),
        "on-disk encoding of {changed:?} changed under the unchanged format key `{key}`: an older build would misread \
         it. Add a FEAT_ bit (FEATURES_KNOWN) or bump FORMAT_VERSION, then append the entries of the new key to \
         format-golden.txt (append-only; adr 0021 format-change rule)"
    );
    assert!(
        missing.is_empty(),
        "format-golden.txt has no entry for these samples; append (never edit existing lines):\n{}",
        missing.join("\n")
    );
}

/// Every defined incompat bit has a name (status output, the `Newer` / "missing features" refusals) and the sticky and
/// required sets are defined bits.
#[test]
fn every_feature_bit_is_named() {
    use crate::layout::{FEATURES_REQUIRED, FEATURES_STICKY, feature_names};
    let all = FEATURES_KNOWN | FEAT_CHUNKED;
    let names = feature_names(all);
    assert_eq!(names.len() as u32, all.count_ones(), "{names:?}");
    assert!(names.iter().all(|n| !n.starts_with("0x")), "{names:?}");
    assert_eq!(feature_names(1 << 50), vec![format!("{:#x}", 1u64 << 50)]);
    assert_eq!(FEATURES_STICKY & !all, 0);
    assert_eq!(FEATURES_REQUIRED & !all, 0);
}
