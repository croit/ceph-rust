// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Wire-fuzz robustness tests for every on-disk record decoder of the OSD store (AGENTS.md wire-fuzz goal,
//! target 6). The decoders parse bytes that come from a device read: superblock and shard directory
//! (`layout::read_super`), root slots (`layout::read_root`), the WAL ring (`wal::replay`: unit headers,
//! record stream, data-block crcs), the meta page bitmap and elastic meta image (`layout::read_meta_image`,
//! `alloc::MetaAlloc::decode` / `blob_decode_ext`, `alloc::blob_head` / `blob_unpack`,
//! `tree::Tree::decode_ext`), tree / blob / delta pages (`page::validate*`), delta page entries
//! (`delta::parse_page`, `delta::apply_ops`, `delta::route_of`), omap runs (`runs::RunBlob::decode`) and the
//! object records stored as tree entries (`obj::onode::Onode` / `CollInfo` / `Ext` / `ref_decode` / `vext`,
//! `obj::keys::decode_coll_key` / `decode_sort_key` / `decode_long_key`, `obj::dedup::parse_key` /
//! `RecordValue::decode`).
//!
//! Property, for ANY input bytes: a decoder returns Ok or Err — it never panics, never overflows/aborts,
//! never allocates more than a bound proportional to the input (no length-field-driven huge
//! `Vec::with_capacity`), never loops forever. Plus, where an encoder exists:
//!  * roundtrip: `decode(encode(x)) == x` for generated valid `x`;
//!  * truncated: a valid encoding cut at every point is Err — or, if the prefix happens to be a complete
//!    encoding of its own, Ok of a value whose canonical encoding is exactly the consumed prefix (never a
//!    value that consumed past the end);
//!  * mutated: a valid encoding with one byte flipped / a byte swapped / a length field set to an extreme
//!    (0, max, i::MIN, len-1, len+1) decodes to Ok or Err.
//!
//! Random bytes alone rarely get past the first length check, so the mutation strategies start from valid
//! encodings (the crate's own encoders). Device-level entry points are driven through `SimDisk` with
//! arbitrary block contents.
//!
//! Out of scope (excluded by the task): the RocksDB omap backend — no decoder of `rocks_omap` is read,
//! tested or run here.
//!
//! Default case count is small (each crate's wirefuzz tests finish in < 20 s in debug); `WIREFUZZ_CASES`
//! raises it for long runs (lab/wirefuzz-long.sh).

use bytes::Bytes;
use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SnapId, SpgT};
use proptest::prelude::*;
use store::BLK;
use store::alloc::{Alloc, MetaAlloc, MetaExtent, blob_head, blob_pack, blob_pages, blob_unpack};
use store::codec::crc;
use store::delta::{PageFill, apply_ops, parse_page, route_of};
use store::dev::{SimClock, SimConfig, SimDisk};
use store::layout::{
    MetaGeom, MkfsParams, RootSlot, ShardDir, mkfs, plan, read_meta_image, read_root, read_super,
};
use store::obj::dedup::{self, DigestAlg, RecordValue};
use store::obj::keys::{
    coll_key, decode_coll_key, decode_long_key, decode_sort_key, long_key_of, omap_key, sort_key,
};
use store::obj::onode::{
    CollInfo, CompMeta, Ext, F_COMP, F_DVER, MAX_RUN, Onode, ref_decode, ref_encode, vext,
    vext_encode,
};
use store::page::{
    BLOB, DELTA, Ents, FMT_COMPACT, FMT_SLOTTED, INT, LEAF, build, init, init_fmt, int_child,
    key_into, leaf_ent, nslots, seal, validate, validate_blob, validate_delta,
};
use store::runs::RunBlob;
use store::sio::Sio;
use store::state::{Op, Record, State};
use store::tree::{Dead, SegDir, Tree, TreeCfg};
use store::wal::{HDR_LEN, ReplayCfg, UnitHeader, decode_record, encode_record, replay};

/// Case count: 256 by default, `WIREFUZZ_CASES` raises it for long runs.
fn cases() -> u32 {
    std::env::var("WIREFUZZ_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(256)
}

/// The proptest! blocks below all share this case-count config.
fn cfg() -> ProptestConfig {
    ProptestConfig::with_cases(cases())
}

/// Arbitrary bytes of length in `r` (decoders must fail fast, not grind).
fn bytes(r: std::ops::Range<usize>) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), r)
}

/// One local mutation of a valid encoding.
#[derive(Clone, Copy, Debug)]
enum Mutation {
    /// Flip one byte.
    Flip(usize, u8),
    /// Replace one byte and insert one (net: a byte shift inside the encoding, length kept).
    Swap(usize, u8),
    /// Write an extreme value into a u16 field (0, max, i16::MIN, cur-1, cur+1).
    Ext16(usize, u8),
    /// Write an extreme value into a u32 field (0, max, i32::MIN, cur-1, cur+1).
    Ext32(usize, u8),
}

// W18: positions are full `usize`s, scaled to the buffer length in `apply` (modulo), so a
// mutation can land anywhere in an 8 KiB page or a 128 KiB WAL ring, not just the first 256 B.
fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        (any::<usize>(), any::<u8>()).prop_map(|(p, b)| Mutation::Flip(p, b)),
        (any::<usize>(), any::<u8>()).prop_map(|(p, b)| Mutation::Swap(p, b)),
        (any::<usize>(), 0..5usize).prop_map(|(p, i)| Mutation::Ext16(p, i as u8)),
        (any::<usize>(), 0..5usize).prop_map(|(p, i)| Mutation::Ext32(p, i as u8)),
    ]
}

fn extremes16(cur: u16) -> [u16; 5] {
    [
        0,
        u16::MAX,
        i16::MIN as u16,
        cur.wrapping_sub(1),
        cur.wrapping_add(1),
    ]
}

fn extremes32(cur: u32) -> [u32; 5] {
    [
        0,
        u32::MAX,
        i32::MIN as u32,
        cur.wrapping_sub(1),
        cur.wrapping_add(1),
    ]
}

fn apply(enc: &[u8], m: &Mutation) -> Vec<u8> {
    let mut v = enc.to_vec();
    match m {
        Mutation::Flip(p, b) if !v.is_empty() => {
            let i = *p % v.len();
            v[i] = *b;
        }
        Mutation::Swap(p, b) if v.len() > 1 => {
            let i = *p % v.len();
            v.remove(i);
            v.insert((*p + 1).min(v.len()), *b);
        }
        Mutation::Ext16(p, i) if v.len() >= 2 => {
            let o = *p % (v.len() - 1);
            let cur = u16::from_le_bytes([v[o], v[o + 1]]);
            v[o..o + 2].copy_from_slice(&extremes16(cur)[*i as usize].to_le_bytes());
        }
        Mutation::Ext32(p, i) if v.len() >= 4 => {
            let o = *p % (v.len() - 3);
            let cur = u32::from_le_bytes(v[o..o + 4].try_into().unwrap());
            v[o..o + 4].copy_from_slice(&extremes32(cur)[*i as usize].to_le_bytes());
        }
        _ => {}
    }
    v
}

/// A valid encoding cut at every point before its end.
fn every_cut(b: &[u8]) -> impl Iterator<Item = &[u8]> {
    (0..b.len()).map(|i| &b[..i])
}

// ------------------------------------------------------------- layout (superblock, directory, roots)

/// The shard directory in its on-disk form (same layout as `layout::encode_dir`: 128 B entries back to
/// back, zero-padded to whole blocks).
fn encode_dir_image(dirs: &[ShardDir], block_bytes: usize) -> Vec<u8> {
    let mut e = store::codec::Enc::new();
    for d in dirs {
        e.u32(d.shard)
            .u64(d.region_start)
            .u64(d.region_blocks)
            .u64(d.root_a)
            .u64(d.root_b)
            .u64(d.wal_start)
            .u64(d.wal_blocks)
            .u64(d.meta_start)
            .u64(d.meta_blocks)
            .u64(d.data_start)
            .u64(d.data_blocks);
        e.b.resize(e.b.len() + 44, 0); // 84 bytes of fields + 44 pad = 128 B entry
    }
    e.b.resize(block_bytes, 0);
    e.b
}

/// A consistent superblock + shard directory for a device of `total_blocks` 4 KiB blocks (no device
/// involved: `plan` is pure).
fn test_sb(total_blocks: u64) -> (store::layout::Superblock, Vec<ShardDir>) {
    let (mut sb, dirs) = plan(
        total_blocks,
        &MkfsParams {
            shards: 2,
            wal_blocks: 64,
            align_blocks: 16,
            meta_pct: 3,
            node_size: 8192,
            elastic_meta: false,
            ..Default::default()
        },
    )
    .unwrap();
    sb.lba_size = 4096;
    sb.size_bytes = total_blocks * BLK as u64;
    (sb, dirs)
}

/// The on-disk superblock encoding (same layout as `layout::Superblock::encode`), for plan-based test
/// stores without the variable-length feature fields (no elastic / expand / chunked / upgrading / dsm
/// bits): fixed fields, the trailing crc32c, zero padding to a block.
fn encode_sb(sb: &store::layout::Superblock) -> Vec<u8> {
    let mut e = store::codec::Enc::new();
    e.bytes(store::layout::SB_MAGIC)
        .u32(sb.version)
        .u64(sb.features)
        .bytes(&sb.osd_fsid)
        .u32(sb.osd_id as u32)
        .bytes(&sb.cluster_fsid)
        .u32(sb.lba_size)
        .u64(sb.size_bytes)
        .u32(sb.nsid)
        .u32(sb.awupf_lbas)
        .u32(sb.awun_lbas)
        .u8(sb.plp as u8)
        .u32(sb.shards)
        .u32(sb.node_size)
        .u64(sb.wal_blocks)
        .u32(sb.meta_pct)
        .u64(sb.dir_blk)
        .u32(sb.dir_blocks)
        .u32(sb.dir_crc)
        .u64(sb.mkfs_time);
    let c = crc(&e.b);
    e.u32(c).pad_to(BLK);
    e.b
}

fn sim(capacity_bytes: u64) -> (SimDisk, SimClock) {
    (
        SimDisk::new(SimConfig::new(capacity_bytes)),
        SimClock::default(),
    )
}

fn root_slot() -> impl Strategy<Value = RootSlot> {
    (
        any::<u32>(),
        any::<u64>(),
        any::<u32>(),
        any::<u64>(),
        any::<u64>(),
        any::<u8>(),
        any::<bool>(),
        any::<u64>(),
    )
        .prop_map(
            |(shard, seq, epoch, ckpt, tail_pos, tree_height, nonplain, _a)| {
                // no slot exists past the last representable lsn (its `+ 1` would wrap)
                let ckpt = ckpt.min(u64::MAX - 1);
                // the canonical form: a plain slot materializes `ckpt_lsn + 1` in both run-window fields
                let run_floor = if nonplain && ckpt > 0 {
                    ckpt.min(10)
                } else {
                    ckpt + 1
                };
                RootSlot {
                    shard,
                    seq,
                    epoch,
                    ckpt_lsn: ckpt,
                    wal_tail_pos: tail_pos,
                    wal_tail_prev_crc: 0x1234_5678,
                    tree_root: 0,
                    tree_crc: 0,
                    tree_height,
                    meta_bitmap_addr: 0,
                    meta_bitmap_len: 0,
                    meta_bitmap_crc: 0,
                    next_onode_id: 1,
                    used_blocks: 0,
                    meta_pages_used: 0,
                    wal_tail_lsn: run_floor,
                    run_floor,
                }
            },
        )
}

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn root_slot_decode_any_bytes(b in bytes(0..BLK)) {
        let _ = RootSlot::decode(&b); // Ok or None, never a panic
    }

    #[test]
    fn root_slot_roundtrip(r in root_slot()) {
        let b = r.encode();
        assert_eq!(b.len(), BLK);
        assert_eq!(RootSlot::decode(&b), Some(r), "decode(encode(x)) == x");
    }

    #[test]
    fn root_slot_mutated(r in root_slot(), m in mutation()) {
        let _ = RootSlot::decode(&apply(&r.encode(), &m)); // Ok or None, never a panic
    }
}

#[test]
fn root_slot_truncated() {
    // plain form (ROOT_MAGIC) and run-window form (ROOT_MAGIC2); plain slots in their canonical
    // form (`wal_tail_lsn` / `run_floor` materialized to `ckpt_lsn + 1`)
    for r in [
        RootSlot {
            wal_tail_lsn: 1,
            run_floor: 1,
            ..Default::default()
        },
        root_slot_plain(),
        root_slot_nonplain(),
    ] {
        let enc = r.encode();
        for p in every_cut(&enc) {
            match RootSlot::decode(p) {
                None => {}
                Some(x) => {
                    // the prefix must be a complete encoding of its own: x re-encodes to a buffer
                    // starting with exactly the prefix (never consumed past it)
                    let e2 = x.encode();
                    assert_eq!(
                        &e2[..p.len()],
                        p,
                        "a truncated decode consumed past the end"
                    );
                    assert_eq!(x, r, "the only complete prefix is the whole encoding");
                }
            }
        }
    }
}

fn root_slot_plain() -> RootSlot {
    RootSlot {
        shard: 3,
        seq: 7,
        epoch: 2,
        ckpt_lsn: 5,
        wal_tail_pos: 9,
        wal_tail_prev_crc: 0xA5A5,
        tree_root: 100,
        tree_crc: 0x1111,
        tree_height: 1,
        meta_bitmap_addr: 200,
        meta_bitmap_len: 1,
        meta_bitmap_crc: 0x2222,
        next_onode_id: 11,
        used_blocks: 12,
        meta_pages_used: 13,
        wal_tail_lsn: 6,
        run_floor: 6,
    }
}

fn root_slot_nonplain() -> RootSlot {
    RootSlot {
        ckpt_lsn: 10,
        wal_tail_lsn: 8,
        run_floor: 9,
        ..root_slot_plain()
    }
}

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn superblock_read_any_bytes(b0 in prop::collection::vec(any::<u8>(), BLK), b1 in prop::collection::vec(any::<u8>(), BLK)) {
        let (disk, mut clk) = sim(2 * BLK as u64);
        let mut dev = disk.queue();
        let mut io = Sio::new(&mut dev, &mut clk);
        io.write_one(0, &b0).unwrap();
        io.write_one(1, &b1).unwrap();
        let _ = read_super(&mut dev, &mut clk); // Ok or Err, never a panic
    }

    #[test]
    fn superblock_mutated(m in mutation()) {
        let (sb, dirs) = test_sb(2048);
        let b = encode_sb(&sb);
        let mut dev = superblock_device(&b, &apply(&b, &m), &dirs, 2048);
        let mut clk = SimClock::default();
        let _ = read_super(&mut dev, &mut clk); // Ok or Err, never a panic
    }

    #[test]
    fn shard_dir_read_any_bytes(dir in prop::collection::vec(any::<u8>(), 4096)) {
        let (sb, dirs) = test_sb(2048);
        let crc = crc(&dir);
        let mut sb = sb;
        sb.dir_crc = crc;
        let b = encode_sb(&sb);
        let mut dev = superblock_device(&b, &b, &dirs, 2048);
        let mut clk = SimClock::default();
        let mut io = Sio::new(&mut dev, &mut clk);
        io.write_one(sb.dir_blk, &dir).unwrap();
        let _ = read_super(&mut dev, &mut clk); // Ok or Err, never a panic
    }

    #[test]
    fn shard_dir_mutated(m in mutation()) {
        let (sb, dirs) = test_sb(2048);
        let dirimg = encode_dir_image(&dirs, sb.dir_blocks as usize * BLK);
        let mut sb = sb;
        sb.dir_crc = crc(&dirimg);
        let b = encode_sb(&sb);
        let mut dev = superblock_device(&b, &b, &dirs, 2048);
        let mut clk = SimClock::default();
        let mut io = Sio::new(&mut dev, &mut clk);
        let mut d = apply(&dirimg, &m);
        d.resize(sb.dir_blocks as usize * BLK, 0);
        io.write_one(sb.dir_blk, &d).unwrap();
        let _ = read_super(&mut dev, &mut clk); // Ok or Err, never a panic
    }

    #[test]
    fn read_root_any_bytes(a in prop::collection::vec(any::<u8>(), BLK), b in prop::collection::vec(any::<u8>(), BLK)) {
        let dir = test_dir();
        let (disk, mut clk) = sim(dir.region_blocks * BLK as u64);
        let mut dev = disk.queue();
        let mut io = Sio::new(&mut dev, &mut clk);
        io.write_one(dir.root_a, &a).unwrap();
        io.write_one(dir.root_b, &b).unwrap();
        let _ = read_root(&mut dev, &mut clk, &dir); // Ok or Err, never a panic
    }
}

/// Device with the superblock copies (`blk 0` = `b0`, `blk 1` = `b1`) and the shard directory written.
fn superblock_device(
    b0: &[u8],
    b1: &[u8],
    dirs: &[ShardDir],
    total_blocks: u64,
) -> store::dev::SimDev {
    let (sb, _) = test_sb(total_blocks);
    let (disk, mut clk) = sim(total_blocks * BLK as u64);
    let mut dev = disk.queue();
    let mut io = Sio::new(&mut dev, &mut clk);
    io.write_one(0, b0).unwrap();
    io.write_one(1, b1).unwrap();
    io.write_one(
        sb.dir_blk,
        &encode_dir_image(dirs, sb.dir_blocks as usize * BLK),
    )
    .unwrap();
    dev
}

#[test]
fn superblock_roundtrip() {
    // plan-based store (the read path of a freshly formatted device)
    let (sb, dirs) = test_sb(2048);
    let b = encode_sb(&sb);
    let mut dev = superblock_device(&b, &b, &dirs, 2048);
    let mut clk = SimClock::default();
    let (sb2, dirs2) = read_super(&mut dev, &mut clk).expect("an intact store mounts");
    assert_eq!((sb2, dirs2), (sb, dirs), "decode(encode(x)) == x");
    // and one formatted through the full mkfs
    let (disk, mut clk) = sim(16 << 20);
    let mut dev = disk.queue();
    let p = MkfsParams {
        shards: 2,
        wal_blocks: 64,
        align_blocks: 16,
        meta_pct: 3,
        ..Default::default()
    };
    let (sb, dirs) = mkfs(&mut dev, &mut clk, &p).expect("mkfs");
    let (sb2, dirs2) = read_super(&mut dev, &mut clk).expect("an mkfs'd store mounts");
    assert_eq!((sb2, dirs2), (sb, dirs), "decode(encode(x)) == x");
}

#[test]
fn read_root_roundtrip() {
    let dir = test_dir();
    let (disk, mut clk) = sim(dir.region_blocks * BLK as u64);
    let mut dev = disk.queue();
    let mut io = Sio::new(&mut dev, &mut clk);
    let lo = RootSlot {
        shard: 0,
        seq: 1,
        epoch: 1,
        wal_tail_lsn: 1,
        run_floor: 1,
        ..Default::default()
    };
    let hi = RootSlot {
        shard: 0,
        seq: 3,
        epoch: 1,
        wal_tail_lsn: 1,
        run_floor: 1,
        ..Default::default()
    };
    io.write_one(dir.root_a, &lo.encode()).unwrap();
    io.write_one(dir.root_b, &hi.encode()).unwrap();
    let r = read_root(&mut dev, &mut clk, &dir).expect("two intact root slots");
    assert_eq!(r, hi, "the highest seq wins");
}

// ------------------------------------------------------------- WAL (unit header, record, replay)

fn wal_header() -> impl Strategy<Value = UnitHeader> {
    (
        any::<u32>(),
        any::<u64>(),
        any::<u32>(),
        any::<u16>(),
        any::<u16>(),
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
        any::<u64>(),
        any::<u32>(),
    )
        .prop_map(
            |(
                epoch,
                first_lsn,
                ntxn,
                nblocks,
                flags,
                shard,
                payload_len,
                prev_crc,
                acked_lsn,
                store_id,
            )| {
                UnitHeader {
                    epoch,
                    first_lsn,
                    ntxn,
                    nblocks,
                    flags,
                    shard,
                    payload_len,
                    prev_crc,
                    payload_crc: 0,
                    acked_lsn,
                    store_id,
                }
            },
        )
}

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn wal_header_read_any_bytes(b in bytes(0..256)) {
        let mut b = b;
        b.resize(HDR_LEN, 0);
        let _ = UnitHeader::read(&b); // Ok or None, never a panic
    }

    #[test]
    fn wal_header_roundtrip(h in wal_header()) {
        let mut buf = vec![0u8; HDR_LEN];
        let c = h.write(&mut buf);
        assert_eq!(UnitHeader::read(&buf), Some((h, c)), "read(write(h)) == (h, crc)");
    }

    #[test]
    fn wal_header_mutated(h in wal_header(), m in mutation()) {
        let mut buf = vec![0u8; HDR_LEN];
        h.write(&mut buf);
        let _ = UnitHeader::read(&apply(&buf, &m)); // Ok or None, never a panic
    }

    // W5: random bytes match the header crc with p = 2^-32, so the plain any-byte case only ever
    // hits the crc reject path. Recompute the trailing crc over the fuzzed header so the hostile
    // *fields* (magic, nblocks, payload_len, ...) reach the parser.
    #[test]
    fn wal_header_read_any_bytes_recomputed(b in bytes(0..256)) {
        let mut b = b;
        b.resize(HDR_LEN, 0);
        let c = crc(&b[..HDR_LEN - 4]);
        b[HDR_LEN - 4..].copy_from_slice(&c.to_le_bytes());
        let _ = UnitHeader::read(&b); // Ok or None, never a panic
    }

    // W5: one mutation of a valid header, then the trailing crc recomputed so the mutated
    // fields reach the parser (the crc reject path is covered by `wal_header_mutated`).
    #[test]
    fn wal_header_mutated_recomputed(h in wal_header(), m in mutation()) {
        let mut buf = vec![0u8; HDR_LEN];
        h.write(&mut buf);
        let mut buf = apply(&buf, &m);
        let c = crc(&buf[..HDR_LEN - 4]);
        buf[HDR_LEN - 4..].copy_from_slice(&c.to_le_bytes());
        let _ = UnitHeader::read(&buf); // Ok or None, never a panic
    }
}

#[test]
fn wal_header_truncated() {
    let mut buf = vec![0u8; HDR_LEN];
    UnitHeader {
        epoch: 1,
        first_lsn: 1,
        ntxn: 1,
        nblocks: 1,
        flags: 0,
        shard: 0,
        payload_len: 0,
        prev_crc: 0,
        payload_crc: 0,
        acked_lsn: 0,
        store_id: 0,
    }
    .write(&mut buf);
    for p in every_cut(&buf) {
        assert!(
            UnitHeader::read(p).is_none(),
            "a header cut at {} bytes must not read",
            p.len()
        );
    }
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (bytes(0..64), bytes(0..512)).prop_map(|(k, v)| Op::Put(k, v)),
        bytes(0..64).prop_map(Op::Del),
        (bytes(1..32), bytes(1..32)).prop_map(|(a, b)| {
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            Op::DelRange(lo, hi)
        }),
        run_put(),
        (any::<u64>(), bytes(1..24), bytes(1..24)).prop_map(|(id, a, b)| {
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            Op::RunMerge {
                id,
                upto: 1,
                a: lo,
                b: hi,
                fin: true,
            }
        }),
        omap_op(),
    ]
}

fn run_put() -> impl Strategy<Value = Op> {
    (
        any::<u64>(),
        prop::collection::vec((bytes(1..24), bytes(0..128)), 1..8),
    )
        .prop_map(|(id, mut entries)| {
            entries.sort();
            entries.dedup_by(|a, b| a.0 == b.0); // strict key order of the run
            let mut buf = Vec::new();
            for (k, v) in &entries {
                let key = omap_key(id, k);
                buf.extend_from_slice(&(key.len() as u16).to_le_bytes());
                buf.extend_from_slice(&(v.len() as u32).to_le_bytes());
                buf.extend_from_slice(&key);
                buf.extend_from_slice(v);
            }
            let r = RunBlob::decode(id, entries.len(), Bytes::from(buf)).expect("a valid run");
            Op::RunPut(r)
        })
}

fn omap_op() -> impl Strategy<Value = Op> {
    use store::olsm::wire::OOp;
    prop_oneof![
        (
            any::<u64>(),
            prop::collection::vec((bytes(1..16), bytes(0..64)), 0..8)
        )
            .prop_map(|(id, mut entries)| {
                entries.sort();
                entries.dedup_by(|a, b| a.0 == b.0); // strict key order of the batch
                let mut blob = Vec::new();
                for (k, v) in &entries {
                    blob.extend_from_slice(&(k.len() as u32).to_le_bytes());
                    blob.extend_from_slice(k);
                    blob.extend_from_slice(&(v.len() as u32).to_le_bytes());
                    blob.extend_from_slice(v);
                }
                Op::Omap(OOp::Put {
                    id,
                    n: entries.len() as u32,
                    blob: Bytes::from(blob),
                })
            }),
        (any::<u64>(), prop::collection::vec(bytes(1..16), 0..8)).prop_map(|(id, keys)| {
            let mut blob = Vec::new();
            for k in &keys {
                blob.extend_from_slice(&(k.len() as u32).to_le_bytes());
                blob.extend_from_slice(k);
            }
            Op::Omap(OOp::Del {
                id,
                blob: Bytes::from(blob),
            })
        }),
        (any::<u64>(), bytes(0..16), any::<bool>()).prop_map(|(id, first, has_end)| {
            // a present end must be above the first key: the first key plus one byte is
            let end = has_end.then(|| {
                let mut e = first.clone();
                e.push(0xFF);
                Bytes::from(e)
            });
            Op::Omap(OOp::Range {
                id,
                first: Bytes::from(first),
                end,
            })
        }),
    ]
}

fn record() -> impl Strategy<Value = Record> {
    // lsn >= 1: a fresh run (`ord == 0`) is refused against `lsn == 0` in `decode_record`
    (
        1u64..u64::MAX,
        prop::collection::vec(op(), 0..4),
        prop::collection::vec(any::<(u64, u32)>(), 0..3),
    )
        .prop_map(|(lsn, ops, frees)| Record {
            lsn,
            ops,
            data: Vec::new(),
            frees,
        })
}

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn wal_record_decode_any_bytes(b in bytes(0..2048)) {
        let _ = decode_record(&mut store::codec::Dec::new(&b)); // Ok or None, never a panic
    }

    #[test]
    fn wal_record_roundtrip(r in record()) {
        let mut e = store::codec::Enc::new();
        encode_record(&r, &mut e);
        let d = decode_record(&mut store::codec::Dec::new(&e.b));
        assert_eq!(d, Some(r), "decode(encode(x)) == x");
    }

    #[test]
    fn wal_record_mutated(r in record(), m in mutation()) {
        let mut e = store::codec::Enc::new();
        encode_record(&r, &mut e);
        let _ = decode_record(&mut store::codec::Dec::new(&apply(&e.b, &m))); // Ok or None
    }
}

#[test]
fn wal_record_truncated() {
    for r in [
        Record::default(),
        Record {
            lsn: 3,
            ops: vec![
                Op::Put(b"key".to_vec(), vec![7u8; 100]),
                Op::Del(b"k2".to_vec()),
                Op::DelRange(b"a".to_vec(), b"b".to_vec()),
            ],
            data: vec![store::state::Extent {
                blk: 10,
                nblk: 2,
                crcs: vec![1, 2],
            }],
            frees: vec![(5, 3)],
        },
    ] {
        let mut e = store::codec::Enc::new();
        encode_record(&r, &mut e);
        for p in every_cut(&e.b) {
            assert!(
                decode_record(&mut store::codec::Dec::new(p)).is_none(),
                "a record cut at {} bytes must not decode",
                p.len()
            );
        }
    }
}

/// A WAL ring of `wal_blocks` blocks at `wal_start` of a shard region, with a root slot that expects
/// the chain to start at ring block 0 with lsn 1.
fn test_dir() -> ShardDir {
    ShardDir {
        shard: 0,
        region_start: 0,
        region_blocks: 4096,
        root_a: 2,
        root_b: 3,
        wal_start: 8,
        wal_blocks: 32,
        meta_start: 40,
        meta_blocks: 128,
        data_start: 168,
        data_blocks: 3000,
        ext: Vec::new(),
        chunk_blocks: 0,
        #[cfg(feature = "elastic")]
        lent: Vec::new(),
    }
}

fn test_root() -> RootSlot {
    RootSlot {
        shard: 0,
        seq: 1,
        epoch: 1,
        ckpt_lsn: 0,
        wal_tail_pos: 0,
        wal_tail_prev_crc: 0x1234,
        ..Default::default()
    }
}

fn test_state(dir: &ShardDir) -> State {
    let geom = MetaGeom::new(dir, 8192).expect("meta geometry");
    let tree = Tree::new(
        TreeCfg {
            psz: 8192,
            shard: 0,
            cache_pages: 64,
            max_walk: 64,
            compact_int: true,
            bg_compact: false,
        },
        geom.clone(),
        MetaAlloc::new(geom.npages),
        None,
    );
    State::new(
        tree,
        Alloc::with_extents(dir.data_start, dir.data_blocks, &dir.ext),
    )
}

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn wal_replay_any_bytes(ring in prop::collection::vec(any::<u8>(), 32 * BLK)) {
        let dir = test_dir();
        let root = test_root();
        let (disk, mut clk) = sim(dir.region_blocks * BLK as u64);
        let mut dev = disk.queue();
        let mut io = Sio::new(&mut dev, &mut clk);
        io.write_one(dir.wal_start, &ring).unwrap();
        let mut state = test_state(&dir);
        let _ = replay(&mut io, &dir, &root, 0, &mut state, &ReplayCfg::default()); // Ok or Err
    }

    #[test]
    fn wal_replay_mutated(m in mutation()) {
        let dir = test_dir();
        let (disk, mut clk) = sim(dir.region_blocks * BLK as u64);
        let mut dev = disk.queue();
        // a valid unit (header + payload crcs intact), then one byte disturbed in its block
        let rec = Record { lsn: 1, ops: vec![Op::Put(b"k".to_vec(), vec![9u8; 100])], ..Default::default() };
        let mut e = store::codec::Enc::new();
        encode_record(&rec, &mut e);
        let mut buf = vec![0u8; BLK];
        buf[HDR_LEN..HDR_LEN + e.b.len()].copy_from_slice(&e.b);
        let h = UnitHeader {
            epoch: 1,
            first_lsn: 1,
            ntxn: 1,
            nblocks: 1,
            flags: 0,
            shard: 0,
            payload_len: e.b.len() as u32,
            prev_crc: 0x1234,
            payload_crc: 0,
            acked_lsn: 0,
            store_id: 0,
        };
        h.write(&mut buf);
        let mut buf = apply(&buf, &m);
        buf.resize(BLK, 0);
        let mut io = Sio::new(&mut dev, &mut clk);
        io.write_one(dir.wal_start, &buf).unwrap();
        let root = test_root();
        let mut state = test_state(&dir);
        let _ = replay(&mut io, &dir, &root, 0, &mut state, &ReplayCfg::default()); // Ok or Err
    }

    // W6: 128 KiB of random bytes essentially never form a valid unit, so `wal_replay_any_bytes`
    // only proves "garbage tail is not applied". Here a *valid* unit (header crc, payload crc
    // recomputed after the mutation) carries the fuzzed record, so the record stream, data-crc
    // and run-merge code actually run.
    #[test]
    fn wal_replay_records_mutated(r in replay_record(), m in mutation()) {
        let dir = test_dir();
        let (disk, mut clk) = sim(dir.region_blocks * BLK as u64);
        let mut dev = disk.queue();
        let mut e = store::codec::Enc::new();
        encode_record(&r, &mut e);
        let payload = apply(&e.b, &m);
        assert!(payload.len() <= BLK - HDR_LEN, "the record fits one block");
        let mut buf = vec![0u8; BLK];
        buf[HDR_LEN..HDR_LEN + payload.len()].copy_from_slice(&payload);
        let h = UnitHeader {
            epoch: 1,
            first_lsn: 1,
            ntxn: 1,
            nblocks: 1,
            flags: 0,
            shard: 0,
            payload_len: payload.len() as u32,
            prev_crc: 0x1234,
            payload_crc: crc(&payload),
            acked_lsn: 0,
            store_id: 0,
        };
        h.write(&mut buf);
        let mut io = Sio::new(&mut dev, &mut clk);
        io.write_one(dir.wal_start, &buf).unwrap();
        let root = test_root();
        let mut state = test_state(&dir);
        let _ = replay(&mut io, &dir, &root, 0, &mut state, &ReplayCfg::default()); // Ok or Err
    }
}

/// A replayable record: `lsn` pinned to 1 (`test_root()` starts the chain at lsn 1) and ops
/// bounded so the payload fits a single 4 KiB WAL block.
fn replay_record() -> impl Strategy<Value = Record> {
    (
        prop::collection::vec(
            prop_oneof![
                (bytes(0..24), bytes(0..256)).prop_map(|(k, v)| Op::Put(k, v)),
                bytes(0..24).prop_map(Op::Del),
            ],
            0..4,
        ),
        prop::collection::vec(any::<(u64, u32)>(), 0..3),
    )
        .prop_map(|(ops, frees)| Record {
            lsn: 1,
            ops,
            data: Vec::new(),
            frees,
        })
}

#[test]
fn wal_replay_roundtrip() {
    let dir = test_dir();
    let (disk, mut clk) = sim(dir.region_blocks * BLK as u64);
    let mut dev = disk.queue();
    let rec = Record {
        lsn: 1,
        ops: vec![
            Op::Put(b"k1".to_vec(), vec![9u8; 100]),
            Op::Del(b"k0".to_vec()),
        ],
        data: vec![],
        frees: vec![],
    };
    let mut e = store::codec::Enc::new();
    encode_record(&rec, &mut e);
    let h = UnitHeader {
        epoch: 1,
        first_lsn: 1,
        ntxn: 1,
        nblocks: 1,
        flags: 0,
        shard: 0,
        payload_len: e.b.len() as u32,
        prev_crc: 0x1234,
        payload_crc: 0,
        acked_lsn: 0,
        store_id: 0,
    };
    let mut io = Sio::new(&mut dev, &mut clk);
    let mut buf = vec![0u8; BLK];
    buf[HDR_LEN..HDR_LEN + e.b.len()].copy_from_slice(&e.b);
    let c = {
        let mut h2 = h;
        h2.payload_crc = crc(&e.b);
        h2.write(&mut buf)
    };
    io.write_one(dir.wal_start, &buf).unwrap();
    // the unit's `prev_crc` (0x1234) must equal the root's chain seed; the header crc `c` is
    // the chain value the *next* unit carries
    let root = test_root();
    let mut state = test_state(&dir);
    let out = replay(&mut io, &dir, &root, 0, &mut state, &ReplayCfg::default())
        .expect("a valid unit replays");
    assert_eq!(out.last_lsn, 1, "the replayed lsn");
    assert_eq!(out.head_crc, c, "the chain value for the next unit");
    assert_eq!(out.stats.txns, 1);
    let mut v = Vec::new();
    assert!(
        state.tree.get(b"k1", &mut v).expect("tree read"),
        "the put applied"
    );
    assert_eq!(v, vec![9u8; 100]);
}

#[test]
fn wal_replay_extreme_headers() {
    use store::error::StoreError;
    /// One extreme-header case: name, the header tweak, the outcome check.
    type Case = (
        &'static str,
        fn(&mut UnitHeader),
        fn(&store::error::Result<store::wal::ReplayOut>),
    );
    let dir = test_dir();
    let root = test_root();
    // (description, header fields beyond the chain-valid ones, expected outcome)
    let payload = vec![0xFFu8; REC_LEN_GARBAGE];
    let cases: [Case; 8] = [
        (
            "nblocks past the ring",
            |h| h.nblocks = u16::MAX,
            |r| assert!(r.is_ok()),
        ),
        (
            "payload_len past the unit",
            |h| h.payload_len = u32::MAX,
            |r| assert!(r.is_ok()),
        ),
        (
            "record count beyond the payload",
            |h| h.ntxn = u32::MAX,
            |r| assert!(matches!(r, Err(StoreError::Corrupt(_)))),
        ),
        (
            "unknown header flag",
            |h| h.flags = 0x8,
            |r| assert!(matches!(r, Err(StoreError::Corrupt(_)))),
        ),
        (
            "epoch above the root",
            |h| h.epoch = 2, // test_root() has epoch 1
            |r| assert!(matches!(r, Err(StoreError::Corrupt(_)))),
        ),
        ("foreign shard", |h| h.shard = 1, |r| assert!(r.is_ok())),
        ("lsn gap", |h| h.first_lsn = 2, |r| assert!(r.is_ok())),
        (
            "prev crc mismatch",
            |h| h.prev_crc = 0xDEAD,
            |r| assert!(r.is_ok()),
        ),
    ];
    for (name, tweak, expect) in cases {
        let (disk, mut clk) = sim(dir.region_blocks * BLK as u64);
        let mut dev = disk.queue();
        let mut h = UnitHeader {
            epoch: 1,
            first_lsn: 1,
            ntxn: 1,
            nblocks: 1,
            flags: 0,
            shard: 0,
            payload_len: payload.len() as u32,
            prev_crc: 0x1234,
            payload_crc: 0,
            acked_lsn: 0,
            store_id: 0,
        };
        tweak(&mut h);
        let mut buf = vec![0u8; BLK];
        buf[HDR_LEN..HDR_LEN + payload.len()].copy_from_slice(&payload);
        h.payload_crc = crc(&payload);
        h.write(&mut buf);
        let mut io = Sio::new(&mut dev, &mut clk);
        io.write_one(dir.wal_start, &buf).unwrap();
        let mut state = test_state(&dir);
        let r = replay(&mut io, &dir, &root, 0, &mut state, &ReplayCfg::default());
        expect(&r);
        let _ = name;
    }
}

const REC_LEN_GARBAGE: usize = 24;

// ------------------------------------------------------------- meta bitmap and elastic meta image

fn meta_alloc() -> impl Strategy<Value = (u32, MetaAlloc)> {
    (64u32..1024, prop::collection::vec(any::<u32>(), 0..32)).prop_map(|(n, pages)| {
        let mut m = MetaAlloc::new(n);
        for &p in &pages {
            if p < n {
                m.set(p);
            }
        }
        (n, m)
    })
}

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn meta_bitmap_decode_any_bytes(b in bytes(0..4096), n in 1u32..4096) {
        let _ = MetaAlloc::decode(&b, n); // Ok or Err, never a panic
    }

    #[test]
    fn meta_bitmap_roundtrip((n, m) in meta_alloc()) {
        let b = m.encode(MetaAlloc::bytes_needed(n), None);
        let d = MetaAlloc::decode(&b, n).expect("decode(encode(x))");
        assert_eq!(d.used(), m.used());
        for i in 0..n {
            assert_eq!(d.get(i), m.get(i), "page {i} of {n}");
        }
    }

    #[test]
    fn meta_bitmap_mutated((n, m) in meta_alloc(), mut_ in mutation()) {
        let b = m.encode(MetaAlloc::bytes_needed(n), None);
        let _ = MetaAlloc::decode(&apply(&b, &mut_), n); // Ok or Err, never a panic
    }

    #[test]
    fn meta_blob_decode_ext_any_bytes(b in bytes(0..4096), n in 64u32..1024) {
        let _ = MetaAlloc::blob_decode_ext(&b, n); // Ok or Err, never a panic
    }

    #[test]
    fn meta_blob_roundtrip((n, mut m) in meta_alloc()) {
        m = elasticize(&m);
        // W4: the generated page pattern is carried into the elastic alloc, and set bits land in
        // the cells too, so the elastic bitmap roundtrip verifies real bits in both areas.
        let s0 = m.add_cell_extents(vec![MetaExtent { start: 7, pages: m.ppc() }]);
        let s1 = m.add_cell_extents(vec![MetaExtent { start: 9000, pages: m.ppc() }]);
        m.set(n + s0 * m.ppc()); // first page of cell 0
        m.set(n + s1 * m.ppc() + 5); // an inner page of cell 1
        let b = m.blob_encode(&[]);
        let (d, used) = MetaAlloc::blob_decode_ext(&b, n).expect("decode(encode(x))");
        assert_eq!(used, b.len(), "no trailing bytes");
        assert_eq!(d.len(), m.len(), "total page count (base + cells)");
        assert_eq!(d.used(), m.used());
        for i in 0..m.len() {
            assert_eq!(d.get(i), m.get(i), "page {i} of {}", m.len());
        }
    }

    #[test]
    fn meta_blob_mutated((n, mut m) in meta_alloc(), mut_ in mutation()) {
        m = elasticize(&m);
        let s0 = m.add_cell_extents(vec![MetaExtent { start: 7, pages: m.ppc() }]);
        m.set(n + s0 * m.ppc());
        let b = m.blob_encode(&[]);
        let _ = MetaAlloc::blob_decode_ext(&apply(&b, &mut_), n); // Ok or Err, never a panic
    }

    #[test]
    fn blob_pack_roundtrip(payload in bytes(0..24001)) {
        let psz = 8192;
        let k = blob_pages(payload.len(), psz);
        let addrs: Vec<u64> = (0..k as u64).map(|i| 100 + i * 2).collect();
        let (pages, c0) = blob_pack(&payload, psz, &addrs, 0, 1);
        let p0 = &pages[..psz];
        let (k2, len, refs) = blob_head(p0, psz, addrs[0]).expect("the header page");
        assert_eq!((k2, len), (k, payload.len()));
        assert_eq!(
            refs.iter().map(|(a, _)| *a).collect::<Vec<_>>(),
            &addrs[1..]
        );
        let rest: Vec<Vec<u8>> = pages[psz..].chunks(psz).map(|c| c.to_vec()).collect();
        assert_eq!(
            blob_unpack(p0, &rest, &refs, len, psz).expect("the payload"),
            payload
        );
        assert_eq!(store::page::stored_crc(p0), c0);
    }

    #[test]
    fn blob_head_mutated(payload in bytes(1..8000), mut_ in mutation()) {
        let psz = 8192;
        let k = blob_pages(payload.len(), psz);
        let addrs: Vec<u64> = (0..k as u64).map(|i| 100 + i * 2).collect();
        let (pages, _) = blob_pack(&payload, psz, &addrs, 0, 1);
        let mut p0 = pages[..psz].to_vec();
        p0 = apply(&p0, &mut_);
        let _ = blob_head(&p0, psz, addrs[0]); // Ok or Err, never a panic
    }
}

// W4: carry the generated page pattern into the elastic alloc (a fresh `new_elastic` would be
// all-zero, making the elastic bitmap roundtrip compare `false == false` for every page).
fn elasticize(m: &MetaAlloc) -> MetaAlloc {
    let mut e = MetaAlloc::new_elastic(m.base_pages(), 64);
    for i in 0..m.base_pages() {
        if m.get(i) {
            e.set(i);
        }
    }
    e
}

#[test]
fn meta_bitmap_truncated() {
    let mut m = MetaAlloc::new(200);
    for i in 0..50 {
        m.set(i * 4);
    }
    let b = m.encode(MetaAlloc::bytes_needed(200), None);
    for p in every_cut(&b) {
        assert!(
            MetaAlloc::decode(p, 200).is_err(),
            "a bitmap cut at {} bytes must not decode",
            p.len()
        );
    }
}

#[test]
fn meta_blob_truncated() {
    let mut m = MetaAlloc::new_elastic(200, 64);
    m.add_cell_extents(vec![MetaExtent {
        start: 7,
        pages: 64,
    }]);
    m.set(3);
    let b = m.blob_encode(&[]);
    let content = m.blob_len();
    for p in every_cut(&b) {
        match MetaAlloc::blob_decode_ext(p, 200) {
            Err(_) => {}
            // a cut at the end of the payload (before the zero padding) is a complete encoding
            Ok((_, used)) => {
                assert!(
                    p.len() >= content && used == content,
                    "an image cut at {} bytes decoded past its content",
                    p.len()
                );
            }
        }
    }
}

// ------------------------------------------------------------- device-level meta image reads

fn meta_sb(elastic: bool) -> store::layout::Superblock {
    store::layout::Superblock {
        version: store::layout::FORMAT_VERSION,
        features: if elastic {
            store::layout::FEAT_ELASTIC_META
        } else {
            0
        },
        osd_fsid: [1; 16],
        osd_id: 0,
        cluster_fsid: [2; 16],
        lba_size: 4096,
        size_bytes: 4096 * BLK as u64,
        nsid: 1,
        awupf_lbas: 1,
        awun_lbas: 1,
        plp: true,
        shards: 1,
        node_size: 8192,
        wal_blocks: 32,
        meta_pct: 3,
        dir_blk: 2,
        dir_blocks: 1,
        dir_crc: 0,
        mkfs_time: 1,
        cell_pages: 64,
        expand: Vec::new(),
        base_pct: 0,
        chunk_blocks: 0,
        upgrading: 0,
        dsm_verdict: None,
    }
}

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn read_meta_image_legacy_any_bytes(bm in bytes(0..4096)) {
        let dir = test_dir();
        let sb = meta_sb(false);
        let geom = MetaGeom::new(&dir, 8192).expect("meta geometry");
        let (disk, mut clk) = sim(dir.region_blocks * BLK as u64);
        let mut dev = disk.queue();
        let mut io = Sio::new(&mut dev, &mut clk);
        let mut bm = bm;
        bm.resize(geom.bm_blocks as usize * BLK, 0);
        io.write_one(geom.bm_a, &bm).unwrap();
        let root = RootSlot {
            shard: 0,
            meta_bitmap_addr: geom.bm_a,
            meta_bitmap_len: geom.bm_blocks,
            meta_bitmap_crc: crc(&bm),
            ..Default::default()
        };
        let _ = read_meta_image(&mut dev, &mut clk, &sb, &geom, &root); // Ok or Err
    }

    #[test]
    fn read_meta_image_elastic_mutated(mut_ in mutation()) {
        let dir = test_dir();
        let sb = meta_sb(true);
        let geom = MetaGeom::new(&dir, 8192).expect("meta geometry");
        // a valid elastic image (two pages), one byte disturbed
        let mut m = MetaAlloc::new_elastic(geom.npages, sb.cell_pages);
        let k = blob_pages(m.blob_len(), 8192) as u32;
        let addrs: Vec<u64> = (0..k).map(|i| geom.page_addr(i)).collect();
        for i in 0..k {
            m.set(i);
        }
        let payload = m.blob_encode(&[]);
        let (pages, c0) = blob_pack(&payload, 8192, &addrs, 0, 1);
        let mut pages = pages;
        pages = apply(&pages, &mut_);
        pages.resize(k as usize * 8192, 0);
        let (disk, mut clk) = sim(dir.region_blocks * BLK as u64);
        let mut dev = disk.queue();
        let mut io = Sio::new(&mut dev, &mut clk);
        for (a, p) in addrs.iter().zip(pages.chunks(8192)) {
            io.write_one(*a, p).unwrap();
        }
        let root = RootSlot {
            shard: 0,
            meta_bitmap_addr: addrs[0],
            meta_bitmap_len: k,
            meta_bitmap_crc: c0,
            meta_pages_used: u64::from(m.used()),
            ..Default::default()
        };
        let _ = read_meta_image(&mut dev, &mut clk, &sb, &geom, &root); // Ok or Err
    }
}

#[test]
fn read_meta_image_elastic_roundtrip() {
    let dir = test_dir();
    let sb = meta_sb(true);
    let geom = MetaGeom::new(&dir, 8192).expect("meta geometry");
    let mut m = MetaAlloc::new_elastic(geom.npages, sb.cell_pages);
    let k = blob_pages(m.blob_len(), 8192) as u32;
    let addrs: Vec<u64> = (0..k).map(|i| geom.page_addr(i)).collect();
    for i in 0..k {
        m.set(i);
    }
    let payload = m.blob_encode(&[]);
    let (pages, c0) = blob_pack(&payload, 8192, &addrs, 0, 1);
    let (disk, mut clk) = sim(dir.region_blocks * BLK as u64);
    let mut dev = disk.queue();
    let mut io = Sio::new(&mut dev, &mut clk);
    for (a, p) in addrs.iter().zip(pages.chunks(8192)) {
        io.write_one(*a, p).unwrap();
    }
    let root = RootSlot {
        shard: 0,
        meta_bitmap_addr: addrs[0],
        meta_bitmap_len: k,
        meta_bitmap_crc: c0,
        meta_pages_used: u64::from(m.used()),
        ..Default::default()
    };
    let img = read_meta_image(&mut dev, &mut clk, &sb, &geom, &root).expect("an intact image");
    assert_eq!(img.meta.used(), m.used());
    for i in 0..k {
        assert!(img.meta.get(i), "the image's own pages are used");
    }
}

// ------------------------------------------------------------- pages (tree, blob, delta)

/// One tree entry (key, value).
type LeafEntry = (Vec<u8>, Vec<u8>);

fn leaf_page(n: usize, key_seed: u64) -> (Vec<u8>, Vec<LeafEntry>) {
    let mut ents = Ents::default();
    let mut entries = Vec::new();
    for i in 0..n {
        let k = format!("k{key_seed:04}{i:04}").into_bytes();
        let v = vec![(i as u8) ^ (key_seed as u8); 8 + i % 40];
        ents.push(&k, &v);
        entries.push((k, v));
    }
    let mut b = vec![0u8; BLK];
    init(&mut b, LEAF, 0, 100, 0);
    assert!(
        build(&mut b, &ents, 0, ents.len(), FMT_SLOTTED),
        "the leaf fits"
    );
    seal(&mut b, 100, 1);
    (b, entries)
}

fn interior_page(fmt: u8, n: usize) -> (Vec<u8>, Vec<(u64, u32)>) {
    let mut ents = Ents::default();
    let mut refs = Vec::new();
    ents.push(b"", &[0u8; 12]); // slot 0: -inf, key ignored, a child ref of its own
    for i in 0..n {
        let k = format!("p{i:04}").into_bytes();
        let (a, c) = (4096 + i as u64, 0x9999 + i as u32);
        let mut v = [0u8; 12];
        v[..8].copy_from_slice(&a.to_le_bytes());
        v[8..].copy_from_slice(&c.to_le_bytes());
        ents.push(&k, &v);
        refs.push((a, c));
    }
    let mut b = vec![0u8; BLK];
    init_fmt(&mut b, INT, 1, 200, 0, fmt);
    assert!(
        build(&mut b, &ents, 0, ents.len(), fmt),
        "the interior page fits"
    );
    seal(&mut b, 200, 1);
    (b, refs)
}

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn page_validate_any_bytes(b in prop::collection::vec(any::<u8>(), BLK)) {
        let _ = validate(&b, BLK, 100); // Ok or Err, never a panic
    }

    #[test]
    fn page_leaf_roundtrip(n in 1usize..12, seed in any::<u64>()) {
        let (b, entries) = leaf_page(n, seed);
        assert!(validate(&b, BLK, 100).is_ok(), "an intact leaf validates");
        assert_eq!(nslots(&b), n);
        for (i, (k, v)) in entries.iter().enumerate() {
            let mut key = Vec::new();
            key_into(&b, i, &mut key);
            assert_eq!(&key, k, "entry {i} key");
            assert_eq!(leaf_ent(&b, i).1, v.as_slice(), "entry {i} value");
        }
    }

    #[test]
    fn page_compact_roundtrip(n in 2usize..24) {
        let (b, refs) = interior_page(FMT_COMPACT, n);
        assert!(validate(&b, BLK, 200).is_ok(), "an intact compact interior page validates");
        for (i, (a, c)) in refs.iter().enumerate() {
            assert_eq!(int_child(&b, i + 1), (*a, *c), "entry {i} child");
        }
    }

    #[test]
    fn page_slotted_int_roundtrip(n in 2usize..12) {
        let (b, refs) = interior_page(FMT_SLOTTED, n);
        assert!(validate(&b, BLK, 200).is_ok(), "an intact slotted interior page validates");
        for (i, (a, c)) in refs.iter().enumerate() {
            assert_eq!(int_child(&b, i + 1), (*a, *c), "entry {i} child");
        }
    }

    #[test]
    fn page_mutated(n in 2usize..8, seed in any::<u64>(), m in mutation()) {
        let (b, _) = leaf_page(n, seed);
        let _ = validate(&apply(&b, &m), BLK, 100); // Ok or Err, never a panic
    }

    #[test]
    fn page_validate_blob_any_bytes(b in prop::collection::vec(any::<u8>(), BLK)) {
        let _ = validate_blob(&b, BLK, 100); // Ok or Err, never a panic
    }

    #[test]
    fn page_validate_delta_any_bytes(b in prop::collection::vec(any::<u8>(), BLK)) {
        let _ = validate_delta(&b, BLK, 100); // Ok or Err, never a panic
    }
}

#[test]
fn page_truncated() {
    let (b, _) = leaf_page(3, 1);
    for p in every_cut(&b) {
        assert!(
            validate(p, BLK, 100).is_err(),
            "a page cut to {} bytes must not validate",
            p.len()
        );
    }
}

#[test]
fn page_blob_roundtrip() {
    let mut b = vec![0u8; BLK];
    init(&mut b, BLOB, 0, 300, 0);
    seal(&mut b, 300, 1);
    assert!(
        validate_blob(&b, BLK, 300).is_ok(),
        "an intact blob page validates"
    );
    init(&mut b, DELTA, 0, 300, 0);
    seal(&mut b, 300, 1);
    assert!(
        validate_delta(&b, BLK, 300).is_ok(),
        "an intact delta page validates"
    );
}

// ------------------------------------------------------------- delta pages

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn delta_parse_page_any_bytes(b in prop::collection::vec(any::<u8>(), BLK)) {
        let _ = parse_page(&b); // Ok or Err, never a panic
    }

    #[test]
    fn delta_parse_page_roundtrip(entries in prop::collection::vec(
        (any::<u64>(), any::<u32>(), any::<bool>(), bytes(0..300)), 0..6)) {
        let mut b = vec![0u8; BLK];
        init(&mut b, DELTA, 0, 400, 0);
        let mut pf = PageFill::new(b);
        for (a, c, r, ops) in &entries {
            pf.push(*a, *c, *r, ops);
        }
        let page = pf.finish();
        let mut page = page;
        seal(&mut page, 400, 1);
        assert!(validate_delta(&page, BLK, 400).is_ok(), "an intact delta page validates");
        let got = parse_page(&page).expect("decode(encode(x))");
        assert_eq!(got.len(), entries.len());
        for (g, (a, c, r, ops)) in got.iter().zip(&entries) {
            assert_eq!(g.0, *a);
            assert_eq!(g.1, *c);
            assert_eq!(g.2 & !store::delta::RESTART, ops.len() as u32);
            assert_eq!(g.2 & store::delta::RESTART, (*r) as u32 * store::delta::RESTART);
            assert_eq!(g.3, ops.as_slice());
        }
    }

    #[test]
    fn delta_parse_page_mutated(entries in prop::collection::vec(
        (any::<u64>(), any::<u32>(), any::<bool>(), bytes(0..300)), 0..6), m in mutation()) {
        let mut b = vec![0u8; BLK];
        init(&mut b, DELTA, 0, 400, 0);
        let mut pf = PageFill::new(b);
        for (a, c, r, ops) in &entries {
            pf.push(*a, *c, *r, ops);
        }
        let page = pf.finish();
        let _ = parse_page(&apply(&page, &m)); // Ok or Err, never a panic
    }

    #[test]
    fn delta_apply_ops_any_bytes(ops in bytes(0..BLK)) {
        let (b, _) = leaf_page(4, 2);
        let mut b = b;
        let mut tmp = vec![0u8; BLK];
        let mut ents = Ents::default();
        let _ = apply_ops(&mut b, &mut tmp, &mut ents, &ops); // Ok or Err, never a panic
    }

    #[test]
    fn delta_route_of_any_bytes(ops in bytes(0..1024)) {
        let _ = route_of(&ops); // Ok or None, never a panic
    }
}

#[test]
fn delta_parse_page_truncated() {
    let mut b = vec![0u8; BLK];
    init(&mut b, DELTA, 0, 400, 0);
    let mut pf = PageFill::new(b);
    pf.push(1, 2, false, b"ops-one");
    pf.push(3, 4, true, b"ops-two");
    let page = pf.finish();
    let full = parse_page(&page).expect("the full page");
    for p in every_cut(&page) {
        match parse_page(p) {
            Err(_) => {}
            // a cut at the end of the last entry is a complete encoding of its own (the zero
            // tail is padding): it may decode, but only to the full entry list
            Ok(v) => assert_eq!(
                v.len(),
                full.len(),
                "a delta page cut to {} bytes decoded partially",
                p.len()
            ),
        }
    }
}

// ------------------------------------------------------------- meta image extension sections

/// Extension section `[magic u32][len u32][payload]` (tree.rs `encode_ext` / `decode_ext`).
fn ext_section(magic: u32, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + payload.len());
    v.extend_from_slice(&magic.to_le_bytes());
    v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    v.extend_from_slice(payload);
    v
}

const DEAD_MAGIC: u32 = 0x3141_4544; // tree.rs "DEA1"
const DELTA_MAGIC: u32 = 0x314c_4544; // tree.rs "DEL1"

fn ext_bytes() -> impl Strategy<Value = (Vec<Dead>, Vec<SegDir>)> {
    (
        prop::collection::vec((any::<u64>(), any::<u32>(), any::<u8>()), 0..4),
        prop::collection::vec(
            (
                any::<u64>(),
                prop::collection::vec((any::<u64>(), any::<u32>()), 0..4),
            ),
            0..4,
        ),
    )
        .prop_map(|(dead, segs)| {
            let dead: Vec<Dead> = dead
                .into_iter()
                .map(|(addr, crc, level)| Dead { addr, crc, level })
                .collect();
            let segs: Vec<SegDir> = segs
                .into_iter()
                .map(|(seq, pages)| SegDir { seq, pages })
                .collect();
            (dead, segs)
        })
}

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn tree_decode_ext_any_bytes(b in bytes(0..2048)) {
        let _ = Tree::decode_ext(&b); // Ok or Err, never a panic
    }

    #[test]
    fn tree_decode_ext_roundtrip((dead, segs) in ext_bytes()) {
        let mut b = Vec::new();
        if !dead.is_empty() {
            let mut flat = Vec::new();
            flat.extend_from_slice(&(dead.len() as u32).to_le_bytes());
            for d in &dead {
                flat.extend_from_slice(&d.addr.to_le_bytes());
                flat.extend_from_slice(&d.crc.to_le_bytes());
                flat.push(d.level);
            }
            b.extend_from_slice(&ext_section(DEAD_MAGIC, &flat));
        }
        if !segs.is_empty() {
            let mut flat = Vec::new();
            flat.extend_from_slice(&(segs.len() as u32).to_le_bytes());
            for s in &segs {
                flat.extend_from_slice(&s.seq.to_le_bytes());
                flat.extend_from_slice(&(s.pages.len() as u32).to_le_bytes());
                for (a, c) in &s.pages {
                    flat.extend_from_slice(&a.to_le_bytes());
                    flat.extend_from_slice(&c.to_le_bytes());
                }
            }
            b.extend_from_slice(&ext_section(DELTA_MAGIC, &flat));
        }
        assert_eq!(Tree::decode_ext(&b).expect("decode(encode(x))"), (dead, segs));
    }

    #[test]
    fn tree_decode_ext_mutated((dead, segs) in ext_bytes(), m in mutation()) {
        let mut b = Vec::new();
        if !dead.is_empty() {
            let mut flat = Vec::new();
            flat.extend_from_slice(&(dead.len() as u32).to_le_bytes());
            for d in &dead {
                flat.extend_from_slice(&d.addr.to_le_bytes());
                flat.extend_from_slice(&d.crc.to_le_bytes());
                flat.push(d.level);
            }
            b.extend_from_slice(&ext_section(DEAD_MAGIC, &flat));
        }
        if !segs.is_empty() {
            let mut flat = Vec::new();
            flat.extend_from_slice(&(segs.len() as u32).to_le_bytes());
            for s in &segs {
                flat.extend_from_slice(&s.seq.to_le_bytes());
                flat.extend_from_slice(&(s.pages.len() as u32).to_le_bytes());
                for (a, c) in &s.pages {
                    flat.extend_from_slice(&a.to_le_bytes());
                    flat.extend_from_slice(&c.to_le_bytes());
                }
            }
            b.extend_from_slice(&ext_section(DELTA_MAGIC, &flat));
        }
        if b.is_empty() {
            b = ext_section(DEAD_MAGIC, &[]);
        }
        let _ = Tree::decode_ext(&apply(&b, &m)); // Ok or Err, never a panic
    }
}

#[test]
fn tree_decode_ext_truncated() {
    let (dead, segs) = (
        vec![Dead {
            addr: 5,
            crc: 6,
            level: 2,
        }],
        vec![SegDir {
            seq: 9,
            pages: vec![(1, 2), (3, 4)],
        }],
    );
    let mut b = Vec::new();
    let mut flat = Vec::new();
    flat.extend_from_slice(&1u32.to_le_bytes());
    flat.extend_from_slice(&dead[0].addr.to_le_bytes());
    flat.extend_from_slice(&dead[0].crc.to_le_bytes());
    flat.push(dead[0].level);
    b.extend_from_slice(&ext_section(DEAD_MAGIC, &flat));
    let mut flat = Vec::new();
    flat.extend_from_slice(&1u32.to_le_bytes());
    flat.extend_from_slice(&segs[0].seq.to_le_bytes());
    flat.extend_from_slice(&2u32.to_le_bytes());
    for (a, c) in &segs[0].pages {
        flat.extend_from_slice(&a.to_le_bytes());
        flat.extend_from_slice(&c.to_le_bytes());
    }
    b.extend_from_slice(&ext_section(DELTA_MAGIC, &flat));
    for p in every_cut(&b) {
        match Tree::decode_ext(p) {
            Err(_) => {}
            // a cut at a section boundary is a complete encoding of a section prefix
            Ok((d, s)) => {
                assert!(
                    (d.is_empty() && s.is_empty())
                        || (d == dead && s.is_empty())
                        || (d == dead && s == segs),
                    "ext sections cut to {} bytes decoded partially",
                    p.len()
                );
            }
        }
    }
}

// ------------------------------------------------------------- omap runs

fn run_entries() -> impl Strategy<Value = (u64, Vec<LeafEntry>)> {
    (
        any::<u64>(),
        prop::collection::vec((bytes(1..24), bytes(0..128)), 1..8),
    )
        .prop_map(|(id, mut entries)| {
            entries.sort();
            entries.dedup_by(|a, b| a.0 == b.0);
            (id, entries)
        })
}

fn run_buf(id: u64, entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut buf = Vec::new();
    for (k, v) in entries {
        let key = omap_key(id, k);
        buf.extend_from_slice(&(key.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(v.len() as u32).to_le_bytes());
        buf.extend_from_slice(&key);
        buf.extend_from_slice(v);
    }
    buf
}

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn run_blob_decode_any_bytes(id in any::<u64>(), n in 0usize..64, buf in bytes(0..1024)) {
        let _ = RunBlob::decode(id, n, Bytes::from(buf)); // Ok or None, never a panic
    }

    #[test]
    fn run_blob_roundtrip((id, entries) in run_entries()) {
        let buf = run_buf(id, &entries);
        let r = RunBlob::decode(id, entries.len(), Bytes::from(buf)).expect("decode(encode(x))");
        assert_eq!(r.id(), id);
        assert_eq!(r.len(), entries.len());
        for (i, (k, v)) in entries.iter().enumerate() {
            let (ek, ev) = r.entry(i);
            assert_eq!(ek, omap_key(id, k).as_slice(), "entry {i} key");
            assert_eq!(ev, v.as_slice(), "entry {i} value");
        }
        assert_eq!(r.raw().len(), run_buf(id, &entries).len());
    }

    #[test]
    fn run_blob_mutated((id, entries) in run_entries(), m in mutation()) {
        let buf = run_buf(id, &entries);
        let _ = RunBlob::decode(id, entries.len(), Bytes::from(apply(&buf, &m))); // Ok or None
    }
}

#[test]
fn run_blob_truncated() {
    let entries: Vec<(Vec<u8>, Vec<u8>)> = (0..5)
        .map(|i| (format!("n{i}").into_bytes(), vec![i as u8; 20]))
        .collect();
    let buf = run_buf(42, &entries);
    for p in every_cut(&buf) {
        assert!(
            RunBlob::decode(42, entries.len(), Bytes::from(p.to_vec())).is_none(),
            "a run cut to {} bytes must not decode",
            p.len()
        );
    }
}

// ------------------------------------------------------------- object records (tree entry values)

fn onode() -> impl Strategy<Value = Onode> {
    (
        any::<u64>(),
        any::<bool>(),
        any::<bool>(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
    )
        .prop_map(|(size, comp, dver, c, co, dv)| Onode {
            size,
            flags: ((comp as u32) * F_COMP) | ((dver as u32) * F_DVER),
            // the record carries exactly the fields its flags announce
            comp: if comp { c } else { 0 },
            comp_orig: if comp { co } else { 0 },
            dv: if dver { dv } else { 0 },
        })
}

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn onode_decode_any_bytes(b in bytes(0..128)) {
        let _ = Onode::decode(&b); // Ok or None, never a panic
    }

    #[test]
    fn onode_roundtrip(o in onode()) {
        assert_eq!(Onode::decode(&o.encode()), Some(o), "decode(encode(x)) == x");
    }

    #[test]
    fn onode_mutated(o in onode(), m in mutation()) {
        let _ = Onode::decode(&apply(&o.encode(), &m)); // Ok or None, never a panic
    }

    #[test]
    fn collinfo_decode_any_bytes(b in bytes(0..128)) {
        let _ = CollInfo::decode(&b); // Ok or None, never a panic
    }

    #[test]
    fn collinfo_roundtrip(
        (id, bits, nobj, nbytes, comp, comp_orig, dv_on, dv_gen) in (
            any::<u64>(), any::<u32>(), any::<i64>(), any::<i64>(), any::<i64>(),
            any::<i64>(), any::<bool>(), any::<u64>(),
        )
    ) {
        let c = CollInfo { id, bits, nobj, nbytes, comp, comp_orig, dv_on, dv_gen };
        assert_eq!(CollInfo::decode(&c.encode()), Some(c), "decode(encode(x)) == x");
    }

    #[test]
    fn collinfo_mutated(
        (id, bits, nobj, nbytes, comp, comp_orig, dv_on, dv_gen) in (
            any::<u64>(), any::<u32>(), any::<i64>(), any::<i64>(), any::<i64>(),
            any::<i64>(), any::<bool>(), any::<u64>(),
        ),
        m in mutation(),
    ) {
        let c = CollInfo { id, bits, nobj, nbytes, comp, comp_orig, dv_on, dv_gen };
        let _ = CollInfo::decode(&apply(&c.encode(), &m)); // Ok or None, never a panic
    }

    #[test]
    fn ext_decode_any_bytes(b in bytes(0..512)) {
        let _ = Ext::decode(&b); // Ok or None, never a panic
    }

    #[test]
    fn ext_roundtrip(e in ext()) {
        assert_eq!(Ext::decode(&e.encode()), Some(e), "decode(encode(x)) == x");
    }

    #[test]
    fn ext_mutated(e in ext(), m in mutation()) {
        let _ = Ext::decode(&apply(&e.encode(), &m)); // Ok or None, never a panic
    }

    #[test]
    fn ref_decode_roundtrip(n in 1u32..=MAX_RUN, owners in 2u32..1000) {
        assert_eq!(ref_decode(&ref_encode(n, owners)), Some((n, owners)));
    }

    #[test]
    fn ref_decode_any_bytes(b in bytes(0..32)) {
        let _ = ref_decode(&b); // Ok or None, never a panic
    }

    #[test]
    fn vext_roundtrip(n in 1usize..16, pba in any::<u64>()) {
        let crcs: Vec<u32> = (0..n).map(|i| 0x1000 + i as u32).collect();
        let len = (n - 1) * BLK + 7;
        let b = vext_encode(len, pba, &crcs);
        let (l, e) = vext(&b).expect("decode(encode(x))");
        assert_eq!(l, len);
        assert_eq!(e.len() as usize, n);
        assert_eq!(e.pba(), pba);
        for (i, c) in crcs.iter().enumerate() {
            assert_eq!(e.crc(i as u32), *c);
        }
        assert!(e.comp().is_none() && !e.shared());
    }

    #[test]
    fn vext_any_bytes(b in bytes(0..512)) {
        let _ = vext(&b); // Ok or None, never a panic
    }
}

fn ext() -> impl Strategy<Value = Ext> {
    prop_oneof![
        // plain run
        (
            any::<u64>(),
            prop::collection::vec(any::<u32>(), 1..64),
            any::<bool>()
        )
            .prop_map(|(pba, crcs, shared)| Ext {
                pba,
                crcs,
                comp: None,
                shared
            },),
        // compressed whole chunk
        (
            any::<u64>(),
            prop::collection::vec(any::<u32>(), 1..48),
            any::<u8>(),
            any::<u32>(),
            any::<bool>()
        )
            .prop_map(|(pba, crcs, alg, lcrc, shared)| {
                let n = crcs.len() as u8;
                let raw = n + 1 + ((lcrc % ((MAX_RUN as u8) - n - 1) as u32) as u8);
                Ext {
                    pba,
                    crcs,
                    comp: Some(CompMeta::whole(alg, raw, lcrc)),
                    shared,
                }
            }),
        // compressed window
        (
            any::<u64>(),
            prop::collection::vec(any::<u32>(), 1..32),
            any::<u8>(),
            any::<u32>(),
            any::<bool>()
        )
            .prop_map(|(pba, crcs, alg, lcrc, shared)| {
                let n = crcs.len() as u8;
                let raw = n + 2 + ((lcrc % ((MAX_RUN as u8) - n - 2) as u32) as u8);
                let win = 1 + ((lcrc % (raw as u32 - 1)) as u8);
                let skip = ((lcrc >> 8) as u8) % (raw - win);
                Ext {
                    pba,
                    crcs,
                    comp: Some(CompMeta {
                        alg,
                        raw_blks: raw,
                        lcrc,
                        skip,
                        win,
                    }),
                    shared,
                }
            }),
    ]
}

#[test]
fn onode_truncated() {
    for o in [
        Onode {
            size: 1234,
            flags: 0,
            ..Default::default()
        },
        Onode {
            size: 1,
            flags: F_COMP,
            comp: 2,
            comp_orig: 3,
            ..Default::default()
        },
        Onode {
            size: 1,
            flags: F_DVER,
            dv: 9,
            ..Default::default()
        },
        Onode {
            size: 1,
            flags: F_COMP | F_DVER,
            comp: 2,
            comp_orig: 3,
            dv: 9,
        },
    ] {
        let b = o.encode();
        for p in every_cut(&b) {
            assert!(
                Onode::decode(p).is_none(),
                "an onode cut to {} bytes must not decode",
                p.len()
            );
        }
    }
}

#[test]
fn collinfo_truncated() {
    for c in [
        CollInfo {
            id: 1,
            bits: 2,
            nobj: 3,
            nbytes: 4,
            ..Default::default()
        },
        CollInfo {
            id: 1,
            comp: 5,
            comp_orig: 6,
            ..Default::default()
        },
        CollInfo {
            id: 1,
            dv_on: true,
            dv_gen: 7,
            ..Default::default()
        },
    ] {
        let b = c.encode();
        for p in every_cut(&b) {
            assert!(
                CollInfo::decode(p).is_none(),
                "a collinfo cut to {} bytes must not decode",
                p.len()
            );
        }
    }
}

#[test]
fn ext_truncated() {
    let e = Ext {
        pba: 40,
        crcs: vec![1, 2, 3],
        comp: None,
        shared: false,
    };
    let b = e.encode();
    for p in every_cut(&b) {
        assert!(
            Ext::decode(p).is_none(),
            "an extent cut to {} bytes must not decode",
            p.len()
        );
    }
}

// ------------------------------------------------------------- tree keys

fn ghobject() -> impl Strategy<Value = Ghobject> {
    (
        prop::collection::vec(any::<u8>(), 0..32),
        prop::collection::vec(any::<u8>(), 0..16),
        prop::collection::vec(any::<u8>(), 0..32),
        any::<u64>(),
        any::<u32>(),
        any::<i64>(),
        any::<u64>(),
        any::<i8>(),
    )
        .prop_map(|(oid, nspace, key, snap, hash, pool, generation, shard)| {
            let hobj = Hobject {
                key,
                oid,
                snap: SnapId(snap),
                hash,
                max: false,
                nspace,
                pool,
            };
            Ghobject {
                hobj,
                generation,
                shard: ShardId(shard),
                max: false,
            }
        })
}

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn coll_key_roundtrip(
        (kind, pool, seed, shard) in (0u8..3, any::<u64>(), any::<u32>(), any::<i8>())
    ) {
        let c = match kind {
            0 => CollT::Meta,
            1 => CollT::Pg(SpgT { pgid: PgT::new(pool, seed), shard: ShardId(shard) }),
            _ => CollT::PgTemp(SpgT { pgid: PgT::new(pool, seed), shard: ShardId(shard) }),
        };
        let k = coll_key(&c);
        assert_eq!(decode_coll_key(&k), Some(c), "decode(encode(x)) == x");
    }

    #[test]
    fn decode_coll_key_any_bytes(b in bytes(0..64)) {
        let _ = decode_coll_key(&b); // Ok or None, never a panic
    }

    #[test]
    fn sort_key_roundtrip(g in ghobject()) {
        let k = sort_key(&g);
        assert_eq!(decode_sort_key(&k), Some(g), "decode(encode(x)) == x");
    }

    #[test]
    fn decode_sort_key_any_bytes(b in bytes(0..256)) {
        let _ = decode_sort_key(&b); // Ok or None, never a panic
    }

    #[test]
    fn long_key_roundtrip(coll in any::<u64>(), g in ghobject()) {
        let k = long_key_of(coll, &g);
        assert_eq!(decode_long_key(&k[9..]), Some(g), "decode(encode(x)) == x");
    }

    #[test]
    fn decode_long_key_any_bytes(b in bytes(0..256)) {
        let _ = decode_long_key(&b); // Ok or None, never a panic
    }
}

#[test]
fn key_decoders_truncated() {
    let g = Ghobject {
        hobj: Hobject {
            key: Vec::new(),
            oid: b"obj-1".to_vec(),
            snap: SnapId(7),
            hash: 99,
            max: false,
            nspace: b"ns".to_vec(),
            pool: 3,
        },
        generation: 5,
        shard: ShardId(2),
        max: false,
    };
    let sk = sort_key(&g);
    for p in every_cut(&sk) {
        assert!(
            decode_sort_key(p).is_none(),
            "a sort key cut to {} bytes must not decode",
            p.len()
        );
    }
    let lk = long_key_of(4, &g);
    for p in every_cut(&lk) {
        assert!(
            decode_long_key(p.get(9..).unwrap_or(&[])).is_none(),
            "a long key cut to {} bytes must not decode",
            p.len()
        );
    }
    let c = CollT::Pg(SpgT {
        pgid: PgT::new(8, 9),
        shard: ShardId(1),
    });
    let ck = coll_key(&c);
    for p in every_cut(&ck) {
        assert!(
            decode_coll_key(p).is_none(),
            "a coll key cut to {} bytes must not decode",
            p.len()
        );
    }
}

// ------------------------------------------------------------- dedup records

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn dedup_record_roundtrip(
        (alg, id, dv_gen, dv, g) in (any::<bool>(), any::<u64>(), any::<u64>(), any::<u64>(), ghobject())
    ) {
        let r = RecordValue {
            alg: if alg { DigestAlg::Sha256 } else { DigestAlg::Md5 },
            id,
            dv_gen,
            dv,
            oid: g,
        };
        assert_eq!(dedup::RecordValue::decode(&r.encode()), Some(r), "decode(encode(x)) == x");
    }

    #[test]
    fn dedup_record_decode_any_bytes(b in bytes(0..256)) {
        let _ = RecordValue::decode(&b); // Ok or None, never a panic
    }

    #[test]
    fn dedup_record_mutated(
        (alg, id, dv_gen, dv, g) in (any::<bool>(), any::<u64>(), any::<u64>(), any::<u64>(), ghobject()),
        m in mutation(),
    ) {
        let r = RecordValue {
            alg: if alg { DigestAlg::Sha256 } else { DigestAlg::Md5 },
            id,
            dv_gen,
            dv,
            oid: g,
        };
        let _ = RecordValue::decode(&apply(&r.encode(), &m)); // Ok or None, never a panic
    }

    #[test]
    fn dedup_key_roundtrip(pool in any::<i64>(), digest in bytes(1..33), ts in any::<u64>(), hash in any::<u32>()) {
        let k = dedup::key(pool, &digest, ts, hash);
        let p = dedup::parse_key(&k).expect("decode(encode(x))");
        assert_eq!(p.pool, pool);
        assert_eq!(p.digest, digest.as_slice());
        assert_eq!(p.ts_ns, ts);
        assert_eq!(p.hash_key, hash);
    }

    #[test]
    fn dedup_key_parse_any_bytes(b in bytes(0..128)) {
        let _ = dedup::parse_key(&b); // Ok or None, never a panic
    }
}

#[test]
fn dedup_record_truncated() {
    let r = RecordValue {
        alg: DigestAlg::Md5,
        id: 1,
        dv_gen: 2,
        dv: 3,
        oid: Ghobject {
            hobj: Hobject {
                key: Vec::new(),
                oid: b"o".to_vec(),
                snap: SnapId(1),
                hash: 2,
                max: false,
                nspace: Vec::new(),
                pool: 3,
            },
            generation: 4,
            shard: ShardId(0),
            max: false,
        },
    };
    let b = r.encode();
    for p in every_cut(&b) {
        assert!(
            RecordValue::decode(p).is_none(),
            "a dedup record cut to {} bytes must not decode",
            p.len()
        );
    }
}
