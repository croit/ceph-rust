// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Wire-fuzz robustness tests for every messages decoder (AGENTS.md wire-fuzz goal, target 3).
//!
//! Property, for ANY input bytes: a decoder returns Ok or Err — it never panics, never
//! overflows/aborts, never allocates more than a bound proportional to the input (no
//! length-field-driven huge `Vec::with_capacity`; enforced by the counting global allocator
//! on the any-byte and length-mutation cases), never loops forever. The messages decoders
//! that parse bytes from outside the process are:
//!  * the type-id dispatchers `decode_any` / `decode_with_header` (incl. the shared and owned
//!    front paths) with arbitrary header fields and segments;
//!  * every message type in the crate's `AnyMessage` enum (45 types) via `Message::decode`;
//!  * the MESSAGE header (`Header2::parse`);
//!  * the borrowed daemon-command result (`CommandReplyView::decode`);
//!  * the mgr config blobs (`ConfigBl::decode`, `decode_config_defaults_bl`) and the
//!    perf-counter `packed` blob (`decode_packed`);
//!  * every payload struct with a denc codec (`OsdStat`, `OsdSuperblock`, `StoreStatfs`,
//!    `RawPoolStatistics`, `LogEntry`, ...).
//!
//! Plus, where an encoder exists:
//!  * roundtrip: `decode(encode(x)) == x` for generated valid `x`;
//!  * truncated: a valid front cut at every point decodes to Err — or to a value whose
//!    re-encoding is a prefix of the consumed bytes (trailing bytes of newer versions are
//!    ignored, per the `Message` contract; a re-encoding longer than the cut would mean a
//!    field was defaulted on Eof);
//!  * mutated: a valid encoding with one byte flipped / inserted / deleted, or a length field
//!    set to an extreme (0, u32::MAX, i32::MIN, len-1, len+1), in any of the three segments,
//!    decodes to Ok or Err (never a panic, never a huge allocation).
//!
//! Random bytes alone rarely get past the first length check, so the mutation strategies start
//! from valid encodings (the crate's own `Message::encode`) and disturb them.
//!
//! Default case count is small (this crate's wirefuzz tests finish in < 20 s in debug);
//! `WIREFUZZ_CASES` raises it for long runs (lab/wirefuzz-long.sh).

use bytes::Bytes;
use denc::types::entity::{AF_INET, AF_INET6};
use denc::types::{EntityAddr, EntityAddrVec, EntityName, Eversion, PgT, Timespan, UTime, Uuid};
use denc::{Encode, from_slice, to_vec};
use messages::*;
use proptest::prelude::*;
use std::collections::BTreeMap;

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

/// Counting global allocator (W3): a decoder must not allocate more than a bound proportional
/// to the input (no length-field-driven huge `Vec::with_capacity`). Tracks peak live bytes for
/// the whole test binary; [`baseline`] re-arms it right before the decode under test so only the
/// decode's own growth is measured (the 1 MiB slack covers concurrent tests' transient
/// allocations in this process).
mod allocs {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    // Per-thread counters: the decoders run on the calling thread, so the measurement sees only the decode under
    // test, never the allocations of tests running in parallel threads (no noise, no re-runs). `const` thread
    // locals with `Cell` need no allocation, so the allocator can use them.
    thread_local! {
        static LIVE: Cell<i64> = const { Cell::new(0) };
        static PEAK: Cell<i64> = const { Cell::new(0) };
    }

    struct Counting;

    #[global_allocator]
    static GLOBAL: Counting = Counting;

    fn bump(delta: i64) {
        // `try_with`: allocations during thread-local teardown are simply not counted
        let _ = LIVE.try_with(|live| {
            let now = live.get() + delta;
            live.set(now);
            let _ = PEAK.try_with(|peak| peak.set(peak.get().max(now)));
        });
    }

    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let p = unsafe { System.alloc(layout) };
            if !p.is_null() {
                bump(layout.size() as i64);
            }
            p
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) };
            bump(-(layout.size() as i64));
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            let p = unsafe { System.realloc(ptr, layout, new_size) };
            if !p.is_null() {
                bump(new_size as i64 - layout.size() as i64);
            }
            p
        }
    }

    /// W3 bound, measured once around one decode on this thread: the growth of live heap memory during the decode
    /// (peak live bytes minus the live total right before it) must stay `<= 64 * input_len + 1 MiB`. A decoder that
    /// sizes an allocation from an untrusted length field instead of the remaining input fails deterministically.
    pub fn measure<F: FnMut()>(input_len: usize, what: &str, mut decode: F) {
        let bound = 64 * input_len + 1024 * 1024;
        let base = LIVE.with(Cell::get);
        PEAK.with(|peak| peak.set(base));
        decode();
        let growth = usize::try_from(PEAK.with(Cell::get) - base).unwrap_or(0);
        assert!(
            growth <= bound,
            "{what}: live heap growth {growth} B during one decode exceeds 64 * {input_len} B + 1 MiB"
        );
    }
}

/// Arbitrary bytes, biased short (decoders must fail fast, not grind).
fn bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..2048)
}

fn u8s(n: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..n)
}

/// Feature mask for encodings: all features, so `ObjectstorePerfStat` takes its exact v2 form.
const FEATURES: u64 = u64::MAX;

/// Short ASCII strings (names, hostnames, command JSON).
const STR_ASCII_0_8: &str = r"[a-z]{0,8}";

/// Extreme values written into a u32 length field.
#[derive(Clone, Copy, Debug)]
enum LenExtreme {
    Zero,
    Max,
    IMin,
    MinusOne,
    PlusOne,
}

/// One local mutation of a valid encoding.
#[derive(Clone, Copy, Debug)]
enum Mutation {
    Flip(usize, u8),
    Delete(usize),
    Insert(usize, u8),
    Len(usize, LenExtreme),
}

fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof!(
        (0usize..512, any::<u8>()).prop_map(|(p, b)| Mutation::Flip(p, b)),
        (0usize..512).prop_map(Mutation::Delete),
        (0usize..=512, any::<u8>()).prop_map(|(p, b)| Mutation::Insert(p, b)),
        (0usize..512, 0..5usize).prop_map(|(p, i)| {
            Mutation::Len(
                p,
                match i {
                    0 => LenExtreme::Zero,
                    1 => LenExtreme::Max,
                    2 => LenExtreme::IMin,
                    3 => LenExtreme::MinusOne,
                    _ => LenExtreme::PlusOne,
                },
            )
        })
    )
}

fn apply(enc: &[u8], m: &Mutation) -> Vec<u8> {
    let mut v = enc.to_vec();
    match m {
        Mutation::Flip(p, b) => {
            if !v.is_empty() {
                let i = *p % v.len();
                v[i] = *b;
            }
        }
        Mutation::Delete(p) => {
            if *p < v.len() {
                v.remove(*p);
            }
        }
        Mutation::Insert(p, b) => v.insert((*p).min(v.len()), *b),
        Mutation::Len(p, x) if v.len() >= 4 => {
            let p = (*p).min(v.len() - 4);
            let cur = u32::from_le_bytes(v[p..p + 4].try_into().unwrap());
            let val = match x {
                LenExtreme::Zero => 0,
                LenExtreme::Max => u32::MAX,
                LenExtreme::IMin => i32::MIN as u32,
                LenExtreme::MinusOne => cur.wrapping_sub(1),
                LenExtreme::PlusOne => cur.wrapping_add(1),
            };
            v[p..p + 4].copy_from_slice(&val.to_le_bytes());
        }
        _ => {}
    }
    v
}

// ---------------------------------------------------------------------------
// building-block strategies
// ---------------------------------------------------------------------------

fn uuid() -> impl Strategy<Value = Uuid> {
    prop::array::uniform::<_, 16>(any::<u8>()).prop_map(Uuid)
}

fn entity_name() -> impl Strategy<Value = EntityName> {
    (any::<u8>(), any::<i64>()).prop_map(|(ty, num)| EntityName::new(ty, num))
}

fn entity_addr() -> impl Strategy<Value = EntityAddr> {
    (
        any::<u32>(),
        any::<u32>(),
        prop_oneof![Just(0u16), Just(AF_INET), Just(AF_INET6)],
        prop::array::uniform::<_, 26>(any::<u8>()),
    )
        .prop_map(|(ty, nonce, family, mut data)| {
            // the v4 form carries only 14 data bytes on the wire; the rest must be zero
            if family == AF_INET {
                data[14..].fill(0);
            }
            EntityAddr {
                ty,
                nonce,
                family,
                data,
            }
        })
}

fn entity_addr_vec() -> impl Strategy<Value = EntityAddrVec> {
    prop::collection::vec(entity_addr(), 0..4).prop_map(EntityAddrVec)
}

fn utime() -> impl Strategy<Value = UTime> {
    (any::<u32>(), any::<u32>()).prop_map(|(sec, nsec)| UTime::new(sec, nsec))
}

fn timespan() -> impl Strategy<Value = Timespan> {
    (any::<i32>(), any::<i32>()).prop_map(|(sec, nsec)| Timespan { sec, nsec })
}

fn pg() -> impl Strategy<Value = PgT> {
    (any::<u64>(), any::<u32>()).prop_map(|(pool, seed)| PgT::new(pool, seed))
}

fn eversion() -> impl Strategy<Value = Eversion> {
    (any::<u32>(), any::<u64>()).prop_map(|(epoch, version)| Eversion::new(epoch, version))
}

fn ceph_entity_name() -> impl Strategy<Value = CephEntityName> {
    (any::<u32>(), STR_ASCII_0_8).prop_map(|(ty, id)| CephEntityName { ty, id })
}

fn f64_finite() -> impl Strategy<Value = f64> {
    any::<u64>()
        .prop_map(f64::from_bits)
        .prop_filter("no NaN (not PartialEq)", |v| !v.is_nan())
}

fn feature_set() -> impl Strategy<Value = FeatureSet> {
    (
        any::<u64>(),
        prop::collection::btree_map(any::<u64>(), STR_ASCII_0_8, 0..4),
    )
        .prop_map(|(mask, names)| FeatureSet { mask, names })
}

fn compat_set() -> impl Strategy<Value = CompatSet> {
    (feature_set(), feature_set(), feature_set()).prop_map(|(compat, ro_compat, incompat)| {
        CompatSet {
            compat,
            ro_compat,
            incompat,
        }
    })
}

fn store_statfs() -> impl Strategy<Value = StoreStatfs> {
    (
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
        any::<i64>(),
        any::<i64>(),
        any::<i64>(),
        any::<i64>(),
        any::<i64>(),
        any::<i64>(),
        any::<i64>(),
    )
        .prop_map(
            |(
                total,
                available,
                internally_reserved,
                allocated,
                data_stored,
                data_compressed,
                data_compressed_allocated,
                data_compressed_original,
                omap_allocated,
                internal_metadata,
            )| StoreStatfs {
                total,
                available,
                internally_reserved,
                allocated,
                data_stored,
                data_compressed,
                data_compressed_allocated,
                data_compressed_original,
                omap_allocated,
                internal_metadata,
            },
        )
}

fn pow2_hist() -> impl Strategy<Value = Pow2Hist> {
    prop::collection::vec(any::<i32>(), 0..8).prop_map(Pow2Hist)
}

fn obj_perf_stat() -> impl Strategy<Value = ObjectstorePerfStat> {
    (any::<u64>(), any::<u64>()).prop_map(|(os_commit_latency_ns, os_apply_latency_ns)| {
        ObjectstorePerfStat {
            os_commit_latency_ns,
            os_apply_latency_ns,
        }
    })
}

fn hb_pingtime() -> impl Strategy<Value = HbPingtime> {
    (
        any::<i32>(),
        any::<u32>(),
        prop::array::uniform::<_, 3>(any::<u32>()),
        prop::array::uniform::<_, 3>(any::<u32>()),
        prop::array::uniform::<_, 3>(any::<u32>()),
        any::<u32>(),
        prop::array::uniform::<_, 3>(any::<u32>()),
        prop::array::uniform::<_, 3>(any::<u32>()),
        prop::array::uniform::<_, 3>(any::<u32>()),
        any::<u32>(),
    )
        .prop_map(
            |(
                osd,
                last_update,
                back_pingtime,
                back_min,
                back_max,
                back_last,
                front_pingtime,
                front_min,
                front_max,
                front_last,
            )| HbPingtime {
                osd,
                last_update,
                back_pingtime,
                back_min,
                back_max,
                back_last,
                front_pingtime,
                front_min,
                front_max,
                front_last,
            },
        )
}

fn osd_stat() -> impl Strategy<Value = OsdStat> {
    (
        (
            any::<i64>(),
            any::<i64>(),
            any::<i64>(),
            any::<i32>(),
            any::<i32>(),
        ),
        (
            prop::collection::vec(any::<i32>(), 0..4),
            pow2_hist(),
            obj_perf_stat(),
        ),
        (
            any::<u32>(),
            any::<u64>(),
            any::<u32>(),
            any::<i64>(),
            any::<i64>(),
            any::<i64>(),
        ),
        (
            store_statfs(),
            prop::collection::btree_map(
                any::<i32>(),
                prop::collection::btree_map(STR_ASCII_0_8, STR_ASCII_0_8, 0..2),
                0..2,
            ),
            any::<u64>(),
        ),
        (
            any::<u32>(),
            any::<u32>(),
            any::<u32>(),
            prop::collection::vec(hb_pingtime(), 0..2),
        ),
    )
        .prop_map(
            |(
                (kb, kb_used, kb_avail, snap_trim_queue_len, num_snap_trimming),
                (hb_peers, op_queue_age_hist, os_perf_stat),
                (up_from, seq, num_pgs, kb_used_data, kb_used_omap, kb_used_meta),
                (statfs, os_alerts, num_shards_repaired),
                (num_osds, num_per_pool_osds, num_per_pool_omap_osds, hb_pingtime),
            )| OsdStat {
                kb,
                kb_used,
                kb_avail,
                snap_trim_queue_len,
                num_snap_trimming,
                hb_peers,
                op_queue_age_hist,
                os_perf_stat,
                up_from,
                seq,
                num_pgs,
                kb_used_data,
                kb_used_omap,
                kb_used_meta,
                statfs,
                os_alerts,
                num_shards_repaired,
                num_osds,
                num_per_pool_osds,
                num_per_pool_omap_osds,
                hb_pingtime,
            },
        )
}

fn osd_superblock() -> impl Strategy<Value = OsdSuperblock> {
    (
        uuid(),
        any::<i32>(),
        any::<u32>(),
        f64_finite(),
        compat_set(),
        any::<u32>(),
        any::<u32>(),
        uuid(),
        any::<u32>(),
        utime(),
        any::<u32>(),
        prop::collection::btree_map(any::<u32>(), any::<u32>(), 0..4),
    )
        .prop_map(
            |(
                cluster_fsid,
                whoami,
                current_epoch,
                weight,
                compat_features,
                clean_thru,
                mounted,
                osd_fsid,
                purged_snaps_last,
                last_purged_snaps_scrub,
                cluster_osdmap_trim_lower_bound,
                mapc,
            )| OsdSuperblock {
                cluster_fsid,
                whoami,
                current_epoch,
                weight,
                compat_features,
                clean_thru,
                mounted,
                osd_fsid,
                purged_snaps_last,
                last_purged_snaps_scrub,
                cluster_osdmap_trim_lower_bound,
                mapc,
            },
        )
}

fn raw_stat() -> impl Strategy<Value = RawPoolStatistics> {
    (
        prop::array::uniform::<_, 40>(any::<i64>()),
        any::<i64>(),
        any::<i64>(),
        any::<i32>(),
        any::<i32>(),
        store_statfs(),
        any::<i32>(),
    )
        .prop_map(
            |(counters, log_size, ondisk_log_size, up, acting, store, num_store_stats)| {
                let mut counters = counters;
                // counters 28..32 are i32 on the wire: keep them in range
                for c in &mut counters[28..32] {
                    *c = *c as i32 as i64;
                }
                RawPoolStatistics {
                    counters,
                    log_size,
                    ondisk_log_size,
                    up,
                    acting,
                    store,
                    num_store_stats,
                }
            },
        )
}

fn log_entry() -> impl Strategy<Value = LogEntry> {
    (
        ceph_entity_name(),
        entity_name(),
        entity_addr_vec(),
        utime(),
        any::<u64>(),
        any::<u16>(),
        STR_ASCII_0_8,
        STR_ASCII_0_8,
    )
        .prop_map(
            |(name, rank, addrs, stamp, seq, prio, msg, channel)| LogEntry {
                name,
                rank,
                addrs,
                stamp,
                seq,
                prio,
                msg,
                channel,
            },
        )
}

fn perf_counter_type() -> impl Strategy<Value = PerfCounterType> {
    (
        STR_ASCII_0_8,
        STR_ASCII_0_8,
        STR_ASCII_0_8,
        any::<u8>(),
        any::<u8>(),
        any::<u8>(),
    )
        .prop_map(
            |(path, description, nick, ty, priority, unit)| PerfCounterType {
                path,
                description,
                nick,
                ty,
                priority,
                unit,
            },
        )
}

fn daemon_health() -> impl Strategy<Value = DaemonHealthMetric> {
    (any::<u8>(), any::<u64>()).prop_map(|(ty, value)| DaemonHealthMetric { ty, value })
}

fn config_bl() -> impl Strategy<Value = ConfigBl> {
    (
        prop::collection::vec(
            (
                STR_ASCII_0_8,
                prop::collection::vec((any::<i32>(), STR_ASCII_0_8), 0..3),
            ),
            0..4,
        ),
        prop::collection::btree_map(STR_ASCII_0_8, STR_ASCII_0_8, 0..4),
    )
        .prop_map(|(options, ignored_mon_values)| ConfigBl {
            options,
            ignored_mon_values,
        })
}

fn config_defaults() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec((STR_ASCII_0_8, STR_ASCII_0_8), 0..8)
        .prop_map(|v| encode_config_defaults_bl(&v).unwrap())
}

fn dedup_result() -> impl Strategy<Value = DedupListResult> {
    (
        any::<bool>(),
        u8s(16),
        any::<u64>(),
        prop::collection::vec((u8s(16), any::<u64>(), any::<u32>()), 0..4),
    )
        .prop_map(|(completed, next, now, entries)| DedupListResult {
            completed,
            next,
            now,
            entries: entries
                .into_iter()
                .map(|(digest, timestamp, oid_hash)| DedupListEntry {
                    digest,
                    timestamp,
                    oid_hash,
                })
                .collect(),
        })
}

fn pool_op() -> impl Strategy<Value = PoolOperation> {
    prop_oneof![
        Just(PoolOperation::CreatePool),
        Just(PoolOperation::DeletePool),
        Just(PoolOperation::CreateNamedSnap),
        Just(PoolOperation::RemoveNamedSnap),
        Just(PoolOperation::AllocateSelfManagedSnap),
        Just(PoolOperation::RemoveSelfManagedSnap),
    ]
}

/// `FeatureSet` encodes `mask & !1` (bit 0 is never set on the wire): compare canonical.
fn norm_feature(fs: FeatureSet) -> FeatureSet {
    FeatureSet {
        mask: fs.mask & !1,
        ..fs
    }
}

fn norm_compat_set(cs: CompatSet) -> CompatSet {
    CompatSet {
        compat: norm_feature(cs.compat),
        ro_compat: norm_feature(cs.ro_compat),
        incompat: norm_feature(cs.incompat),
    }
}

fn norm_superblock(sb: OsdSuperblock) -> OsdSuperblock {
    OsdSuperblock {
        compat_features: norm_compat_set(sb.compat_features),
        ..sb
    }
}

/// `MMgrOpen` encodes `daemon_metadata` / `daemon_status` only when `service_daemon`:
/// a non-service open carries empty maps on the wire.
fn norm_mmgropen(m: MMgrOpen) -> MMgrOpen {
    if m.service_daemon {
        m
    } else {
        MMgrOpen {
            daemon_metadata: BTreeMap::new(),
            daemon_status: BTreeMap::new(),
            ..m
        }
    }
}

/// Canonical form after one wire roundtrip, over the whole enum.
fn norm_message(m: AnyMessage) -> AnyMessage {
    match m {
        AnyMessage::MMgrOpen(o) => AnyMessage::MMgrOpen(norm_mmgropen(o)),
        AnyMessage::MOSDBoot(b) => AnyMessage::MOSDBoot(MOSDBoot {
            sb: norm_superblock(b.sb),
            ..b
        }),
        other => other,
    }
}

/// A valid MMgrMap: the v14/compat-6 envelope with the five prefix fields.
fn mmgr_map() -> impl Strategy<Value = MMgrMap> {
    (
        any::<u32>(),
        entity_addr_vec(),
        any::<u64>(),
        any::<bool>(),
        STR_ASCII_0_8,
    )
        .prop_map(
            |(epoch, active_addrs, active_gid, available, active_name)| {
                let prefix = MgrMapPrefix {
                    epoch,
                    active_addrs,
                    active_gid,
                    available,
                    active_name,
                };
                let raw = denc::encode_exact(FEATURES, |e| {
                    e.versioned(14, MgrMapPrefix::MAX_COMPAT, |e| {
                        e.u32(prefix.epoch)?;
                        prefix.active_addrs.encode(e)?;
                        e.u64(prefix.active_gid)?;
                        e.bool(prefix.available)?;
                        prefix.active_name.encode(e)
                    })
                })
                .unwrap();
                MMgrMap { raw, prefix }
            },
        )
}

// ---------------------------------------------------------------------------
// per-message-type tests
// ---------------------------------------------------------------------------

/// Four wirefuzz tests per message type: any-byte decode (no panic, no huge allocation), roundtrip, truncation at
/// every cut point of the front, and a single mutation of any of the three segments.
macro_rules! wirefuzz_msg {
    ($name:ident, $ty:ty, $strategy:expr, $normalize:expr) => {
        mod $name {
            use super::*;

            proptest! {
                #![proptest_config(cfg())]

                // W1: 7 decoders pin/limit the version before touching a body byte, so a uniform
                // `any::<u16>()` enters the body with probability 1/65536. Bias to the reachable
                // range (plus the head version) and keep one fully random arm.
                #[test]
                fn any_byte(
                    version in prop_oneof![
                        Just(<$ty>::HEAD_VERSION),
                        0..=<$ty>::HEAD_VERSION,
                        any::<u16>()
                    ],
                    f in bytes(),
                    m in bytes(),
                    d in bytes(),
                ) {
                    allocs::measure(
                        f.len() + m.len() + d.len(),
                        concat!(stringify!($name), " any_byte"),
                        || {
                            let _ = <$ty as Message>::decode(version, &f, &m, &d);
                        },
                    );
                }

                #[test]
                fn roundtrip(v in $strategy) {
                    let segs = v.encode(FEATURES).unwrap();
                    let dec = <$ty as Message>::decode(
                        <$ty>::HEAD_VERSION,
                        &segs.front,
                        &segs.middle,
                        &segs.data,
                    )
                    .unwrap();
                    assert_eq!($normalize(dec), $normalize(v));
                }

                #[test]
                fn truncated(v in $strategy) {
                    let segs = v.encode(FEATURES).unwrap();
                    let f = &segs.front;
                    for c in 0..f.len() {
                        if let Ok(dec) = <$ty as Message>::decode(
                            <$ty>::HEAD_VERSION,
                            &f[..c],
                            &segs.middle,
                            &segs.data,
                        ) {
                            let re = dec.encode(FEATURES).unwrap();
                            // W7: the re-encoding must be exactly the consumed prefix, or — for
                            // the types with a documented version-optional trailing field
                            // (MLogAck `channel`, MOSDMap `gap_removed_snaps`) — the consumed
                            // prefix must be a prefix of it. A re-encoding that is longer than
                            // the cut *and* diverges from it would mean a field was defaulted
                            // on Eof.
                            assert!(
                                re.front == f[..c] || re.front.starts_with(&f[..c]),
                                "cut {c}: re-encoding diverges from the consumed prefix (defaulted a field on Eof?)"
                            );
                            assert_eq!(re.middle, segs.middle, "cut {c}: middle changed");
                            assert_eq!(re.data, segs.data, "cut {c}: data changed");
                        }
                    }
                }

                #[test]
                fn mutated(v in $strategy, m in mutation()) {
                    let segs = v.encode(FEATURES).unwrap();
                    let len = matches!(m, Mutation::Len(..));
                    if len {
                        let n = segs.front.len() + segs.middle.len() + segs.data.len();
                        allocs::measure(n, concat!(stringify!($name), " mutated"), || {
                            for (f, mm, dd) in [
                                (apply(&segs.front, &m), segs.middle.clone(), segs.data.to_vec()),
                                (segs.front.clone(), apply(&segs.middle, &m), segs.data.to_vec()),
                                (segs.front.clone(), segs.middle.clone(), apply(&segs.data, &m)),
                            ] {
                                let _ = <$ty as Message>::decode(<$ty>::HEAD_VERSION, &f, &mm, &dd);
                            }
                        });
                    } else {
                        for (f, mm, dd) in [
                            (apply(&segs.front, &m), segs.middle.clone(), segs.data.to_vec()),
                            (segs.front.clone(), apply(&segs.middle, &m), segs.data.to_vec()),
                            (segs.front.clone(), segs.middle.clone(), apply(&segs.data, &m)),
                        ] {
                            let _ = <$ty as Message>::decode(<$ty>::HEAD_VERSION, &f, &mm, &dd);
                        }
                    }
                }
            }
        }
    };
}

fn mping() -> impl Strategy<Value = MPing> {
    prop_oneof![
        Just(MPing::default()),
        u8s(64).prop_map(|reply| MPing { reply: Some(reply) })
    ]
}
fn mauth() -> impl Strategy<Value = MAuth> {
    (any::<u64>(), any::<u32>(), u8s(64), any::<u32>()).prop_map(
        |(version, protocol, auth_payload, monmap_epoch)| MAuth {
            version,
            protocol,
            auth_payload,
            monmap_epoch,
        },
    )
}
fn mauth_reply() -> impl Strategy<Value = MAuthReply> {
    (
        any::<u32>(),
        any::<i32>(),
        any::<u64>(),
        u8s(64),
        STR_ASCII_0_8,
    )
        .prop_map(
            |(protocol, result, global_id, result_bl, result_msg)| MAuthReply {
                protocol,
                result,
                global_id,
                result_bl,
                result_msg,
            },
        )
}
fn mmonsubscribe() -> impl Strategy<Value = MMonSubscribe> {
    (
        prop::collection::btree_map(
            STR_ASCII_0_8,
            (any::<u64>(), any::<u8>()).prop_map(|(start, flags)| SubItem { start, flags }),
            0..4,
        ),
        STR_ASCII_0_8,
    )
        .prop_map(|(what, hostname)| MMonSubscribe { what, hostname })
}
fn mmonsubscribeack() -> impl Strategy<Value = MMonSubscribeAck> {
    (any::<u32>(), uuid()).prop_map(|(interval, fsid)| MMonSubscribeAck { interval, fsid })
}
fn mmongetversion() -> impl Strategy<Value = MMonGetVersion> {
    (any::<u64>(), STR_ASCII_0_8).prop_map(|(handle, what)| MMonGetVersion { handle, what })
}
fn mmongetversionreply() -> impl Strategy<Value = MMonGetVersionReply> {
    (any::<u64>(), any::<u64>(), any::<u64>()).prop_map(|(handle, version, oldest_version)| {
        MMonGetVersionReply {
            handle,
            version,
            oldest_version,
        }
    })
}
fn mgetpoolstats() -> impl Strategy<Value = MGetPoolStats> {
    (any::<u64>(), uuid(), prop::collection::vec(u8s(32), 0..8)).prop_map(
        |(version, fsid, pools)| MGetPoolStats {
            version,
            fsid,
            pools,
        },
    )
}
fn mgetpoolstatsreply() -> impl Strategy<Value = MGetPoolStatsReply> {
    (
        any::<u64>(),
        uuid(),
        prop::collection::btree_map(u8s(16), raw_stat(), 0..4),
        any::<bool>(),
    )
        .prop_map(|(version, fsid, pools, per_pool)| MGetPoolStatsReply {
            version,
            fsid,
            pools,
            per_pool,
        })
}
fn mstatfs() -> impl Strategy<Value = MStatfs> {
    (any::<u64>(), uuid(), any::<Option<i64>>()).prop_map(|(version, fsid, data_pool)| MStatfs {
        version,
        fsid,
        data_pool,
    })
}
fn mstatfsreply() -> impl Strategy<Value = MStatfsReply> {
    (
        uuid(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
    )
        .prop_map(
            |(fsid, version, kb, kb_used, kb_avail, num_objects)| MStatfsReply {
                fsid,
                version,
                statistics: ClusterStatistics {
                    kb,
                    kb_used,
                    kb_avail,
                    num_objects,
                },
            },
        )
}
fn mpoolop() -> impl Strategy<Value = MPoolOp> {
    (
        any::<u64>(),
        uuid(),
        any::<u32>(),
        pool_op(),
        any::<u64>(),
        u8s(32),
        any::<i16>(),
    )
        .prop_map(
            |(version, fsid, pool, operation, snapid, name, crush_rule)| MPoolOp {
                version,
                fsid,
                pool,
                operation,
                snapid,
                name,
                crush_rule,
            },
        )
}
fn mpoolopreply() -> impl Strategy<Value = MPoolOpReply> {
    (any::<u64>(), uuid(), any::<i32>(), any::<u32>(), u8s(64)).prop_map(
        |(version, fsid, result, epoch, response_data)| MPoolOpReply {
            version,
            fsid,
            result,
            epoch,
            response_data,
        },
    )
}
fn mmoncommand() -> impl Strategy<Value = MMonCommand> {
    (
        any::<u64>(),
        uuid(),
        prop::collection::vec(STR_ASCII_0_8, 0..4),
        u8s(64),
    )
        .prop_map(|(version, fsid, cmd, data)| MMonCommand {
            version,
            fsid,
            cmd,
            data,
        })
}
fn mmoncommandack() -> impl Strategy<Value = MMonCommandAck> {
    (
        any::<u64>(),
        any::<i32>(),
        STR_ASCII_0_8,
        prop::collection::vec(STR_ASCII_0_8, 0..4),
        u8s(64),
    )
        .prop_map(|(version, r, rs, cmd, data)| MMonCommandAck {
            version,
            r,
            rs,
            cmd,
            data,
        })
}
fn mconfig() -> impl Strategy<Value = MConfig> {
    prop::collection::btree_map(STR_ASCII_0_8, STR_ASCII_0_8, 0..8)
        .prop_map(|config| MConfig { config })
}
fn mgetconfig() -> impl Strategy<Value = MGetConfig> {
    (ceph_entity_name(), STR_ASCII_0_8, STR_ASCII_0_8).prop_map(|(name, host, device_class)| {
        MGetConfig {
            name,
            host,
            device_class,
        }
    })
}
fn mlog() -> impl Strategy<Value = MLog> {
    (
        any::<u64>(),
        uuid(),
        prop::collection::vec(log_entry(), 0..4),
    )
        .prop_map(|(version, fsid, entries)| MLog {
            version,
            fsid,
            entries,
        })
}
fn mlogack() -> impl Strategy<Value = MLogAck> {
    (uuid(), any::<u64>(), STR_ASCII_0_8).prop_map(|(fsid, last, channel)| MLogAck {
        fsid,
        last,
        channel,
    })
}
fn mcommand() -> impl Strategy<Value = MCommand> {
    (uuid(), prop::collection::vec(STR_ASCII_0_8, 0..4), u8s(64))
        .prop_map(|(fsid, cmd, data)| MCommand { fsid, cmd, data })
}
fn mcommandreply() -> impl Strategy<Value = MCommandReply> {
    (any::<i32>(), STR_ASCII_0_8, u8s(64)).prop_map(|(r, rs, data)| MCommandReply { r, rs, data })
}
fn mosddeduplist() -> impl Strategy<Value = MOSDDedupList> {
    (
        uuid(),
        any::<u32>(),
        any::<i64>(),
        any::<u64>(),
        any::<u8>(),
        u8s(16),
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
    )
        .prop_map(
            |(fsid, epoch, pool, shard, shard_bits, after, max, newer_than, prune_older_than)| {
                MOSDDedupList {
                    fsid,
                    epoch,
                    pool,
                    shard,
                    shard_bits,
                    after,
                    max,
                    newer_than,
                    prune_older_than,
                }
            },
        )
}
fn mosddeduplistreply() -> impl Strategy<Value = MOSDDedupListReply> {
    (any::<i32>(), dedup_result()).prop_map(|(r, result)| MOSDDedupListReply { r, result })
}
fn mosdmap() -> impl Strategy<Value = MOSDMap> {
    (
        uuid(),
        prop::collection::btree_map(any::<u32>(), u8s(64), 0..2),
        prop::collection::btree_map(any::<u32>(), u8s(64), 0..2),
        any::<u32>(),
        any::<u32>(),
    )
        .prop_map(
            |(fsid, incremental_maps, maps, cluster_osdmap_trim_lower_bound, newest_map)| MOSDMap {
                fsid,
                incremental_maps,
                maps,
                cluster_osdmap_trim_lower_bound,
                newest_map,
            },
        )
}
fn mmongetosdmap() -> impl Strategy<Value = MMonGetOSDMap> {
    (
        any::<u64>(),
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
    )
        .prop_map(
            |(version, full_first, full_last, inc_first, inc_last)| MMonGetOSDMap {
                version,
                full_first,
                full_last,
                inc_first,
                inc_last,
            },
        )
}
fn mosdboot() -> impl Strategy<Value = MOSDBoot> {
    (
        any::<u64>(),
        osd_superblock(),
        entity_addr_vec(),
        entity_addr_vec(),
        any::<u32>(),
        entity_addr_vec(),
        prop::collection::btree_map(STR_ASCII_0_8, STR_ASCII_0_8, 0..4),
        any::<u64>(),
    )
        .prop_map(
            |(
                version,
                sb,
                hb_back_addrs,
                cluster_addrs,
                boot_epoch,
                hb_front_addrs,
                metadata,
                osd_features,
            )| MOSDBoot {
                version,
                sb,
                hb_back_addrs,
                cluster_addrs,
                boot_epoch,
                hb_front_addrs,
                metadata,
                osd_features,
            },
        )
}
fn mosdalive() -> impl Strategy<Value = MOSDAlive> {
    (any::<u64>(), any::<u32>()).prop_map(|(version, want)| MOSDAlive { version, want })
}
fn mosdbeacon() -> impl Strategy<Value = MOSDBeacon> {
    (
        any::<u64>(),
        prop::collection::vec(pg(), 0..4),
        any::<u32>(),
        utime(),
        any::<i32>(),
    )
        .prop_map(
            |(
                version,
                pgs,
                min_last_epoch_clean,
                last_purged_snaps_scrub,
                osd_beacon_report_interval,
            )| MOSDBeacon {
                version,
                pgs,
                min_last_epoch_clean,
                last_purged_snaps_scrub,
                osd_beacon_report_interval,
            },
        )
}
fn mosdmarkmedown() -> impl Strategy<Value = MOSDMarkMeDown> {
    (
        any::<u64>(),
        uuid(),
        any::<i32>(),
        entity_addr_vec(),
        any::<u32>(),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(
            |(version, fsid, target_osd, target_addrs, epoch, request_ack, down_and_dead)| {
                MOSDMarkMeDown {
                    version,
                    fsid,
                    target_osd,
                    target_addrs,
                    epoch,
                    request_ack,
                    down_and_dead,
                }
            },
        )
}
fn mosdmarkmedead() -> impl Strategy<Value = MOSDMarkMeDead> {
    (any::<u64>(), uuid(), any::<i32>(), any::<u32>()).prop_map(
        |(version, fsid, target_osd, epoch)| MOSDMarkMeDead {
            version,
            fsid,
            target_osd,
            epoch,
        },
    )
}
fn mosdfailure() -> impl Strategy<Value = MOSDFailure> {
    (
        any::<u64>(),
        uuid(),
        any::<i32>(),
        entity_addr_vec(),
        any::<u32>(),
        any::<u8>(),
        any::<i32>(),
    )
        .prop_map(
            |(version, fsid, target_osd, target_addrs, epoch, flags, failed_for)| MOSDFailure {
                version,
                fsid,
                target_osd,
                target_addrs,
                epoch,
                flags,
                failed_for,
            },
        )
}
fn mosdfull() -> impl Strategy<Value = MOSDFull> {
    (any::<u64>(), any::<u32>(), any::<u32>()).prop_map(|(version, map_epoch, state)| MOSDFull {
        version,
        map_epoch,
        state,
    })
}
fn mosdping() -> impl Strategy<Value = MOSDPing> {
    (
        uuid(),
        any::<u32>(),
        any::<u8>(),
        utime(),
        0..=32u32,
        any::<u32>(),
        timespan(),
        timespan(),
        prop::option::of(timespan()),
    )
        .prop_map(
            |(
                fsid,
                map_epoch,
                op,
                ping_stamp,
                pad_len,
                up_from,
                mono_ping_stamp,
                mono_send_stamp,
                delta_ub,
            )| MOSDPing {
                fsid,
                map_epoch,
                op,
                ping_stamp,
                pad_len,
                up_from,
                mono_ping_stamp,
                mono_send_stamp,
                delta_ub,
            },
        )
}
fn mosdpg_temp() -> impl Strategy<Value = MOSDPGTemp> {
    (
        any::<u64>(),
        any::<u32>(),
        prop::collection::btree_map(pg(), prop::collection::vec(any::<i32>(), 0..3), 0..4),
        any::<bool>(),
    )
        .prop_map(|(version, map_epoch, pg_temp, forced)| MOSDPGTemp {
            version,
            map_epoch,
            pg_temp,
            forced,
        })
}
fn mosdpgcreated() -> impl Strategy<Value = MOSDPGCreated> {
    (any::<u64>(), pg()).prop_map(|(version, pgid)| MOSDPGCreated { version, pgid })
}
fn mosdpgreadytomerde() -> impl Strategy<Value = MOSDPGReadyToMerge> {
    (
        any::<u64>(),
        pg(),
        eversion(),
        eversion(),
        any::<u32>(),
        any::<u32>(),
        any::<bool>(),
    )
        .prop_map(
            |(
                version,
                pgid,
                source_version,
                target_version,
                last_epoch_started,
                last_epoch_clean,
                ready,
            )| MOSDPGReadyToMerge {
                version,
                pgid,
                source_version,
                target_version,
                last_epoch_started,
                last_epoch_clean,
                ready,
            },
        )
}
fn mmongetpurgedsnaps() -> impl Strategy<Value = MMonGetPurgedSnaps> {
    (any::<u64>(), any::<u32>(), any::<u32>()).prop_map(|(version, start, last)| {
        MMonGetPurgedSnaps {
            version,
            start,
            last,
        }
    })
}
fn mmongetpurgedsnapsreply() -> impl Strategy<Value = MMonGetPurgedSnapsReply> {
    (
        any::<u64>(),
        any::<u32>(),
        any::<u32>(),
        prop::collection::btree_map(
            any::<u32>(),
            prop::collection::btree_map(
                any::<i64>(),
                prop::collection::btree_map(any::<u64>(), any::<u64>(), 0..2),
                0..2,
            ),
            0..2,
        ),
    )
        .prop_map(
            |(version, start, last, purged_snaps)| MMonGetPurgedSnapsReply {
                version,
                start,
                last,
                purged_snaps,
            },
        )
}
fn mmgropen() -> impl Strategy<Value = MMgrOpen> {
    (
        STR_ASCII_0_8,
        STR_ASCII_0_8,
        any::<bool>(),
        prop::collection::btree_map(STR_ASCII_0_8, STR_ASCII_0_8, 0..2),
        prop::collection::btree_map(STR_ASCII_0_8, STR_ASCII_0_8, 0..2),
        config_bl().prop_map(|c| c.encode().unwrap()),
        config_defaults(),
    )
        .prop_map(
            |(
                daemon_name,
                service_name,
                service_daemon,
                daemon_metadata,
                daemon_status,
                config_bl,
                config_defaults_bl,
            )| MMgrOpen {
                daemon_name,
                service_name,
                service_daemon,
                daemon_metadata,
                daemon_status,
                config_bl,
                config_defaults_bl,
            },
        )
}
fn mmgrconfigure() -> impl Strategy<Value = MMgrConfigure> {
    (any::<u32>(), any::<u32>(), u8s(32)).prop_map(|(stats_period, stats_threshold, tail)| {
        MMgrConfigure {
            stats_period,
            stats_threshold,
            tail,
        }
    })
}
fn mmgrreport() -> impl Strategy<Value = MMgrReport> {
    (
        STR_ASCII_0_8,
        prop::collection::vec(perf_counter_type(), 0..3),
        u8s(64),
        prop::collection::vec(STR_ASCII_0_8, 0..3),
        STR_ASCII_0_8,
        any::<Option<BTreeMap<String, String>>>(),
        prop::collection::vec(daemon_health(), 0..3),
        u8s(64),
        u8s(16),
    )
        .prop_map(
            |(
                daemon_name,
                declare_types,
                packed,
                undeclare_types,
                service_name,
                daemon_status,
                daemon_health_metrics,
                config_bl,
                tail,
            )| MMgrReport {
                daemon_name,
                declare_types,
                packed,
                undeclare_types,
                service_name,
                daemon_status,
                daemon_health_metrics,
                config_bl,
                tail,
            },
        )
}
/// One `pg_stat_t` value of MPGStats' `map<pg_t, pg_stat_t>`: a versioned envelope (version, compat, u32 length,
/// payload). The message keeps it opaque; the wire form has no extra length prefix (the envelope delimits it).
fn pg_stat_envelope() -> impl Strategy<Value = Vec<u8>> {
    (any::<u8>(), any::<u8>(), u8s(64)).prop_map(|(v, c, body)| {
        let mut raw = vec![v, c];
        raw.extend_from_slice(&(body.len() as u32).to_le_bytes());
        raw.extend_from_slice(&body);
        raw
    })
}
fn mpgstats() -> impl Strategy<Value = MPGStats> {
    (
        any::<u64>(),
        uuid(),
        osd_stat(),
        prop::collection::vec((pg(), pg_stat_envelope()), 0..3),
        any::<u32>(),
        utime(),
        prop::collection::btree_map(any::<i64>(), store_statfs(), 0..3),
    )
        .prop_map(
            |(version, fsid, osd_stat, pg_stat, epoch, dummy, pool_stat)| MPGStats {
                version,
                fsid,
                osd_stat,
                pg_stat,
                epoch,
                dummy,
                pool_stat,
            },
        )
}

wirefuzz_msg!(mping, MPing, mping(), |v| v);
wirefuzz_msg!(mauth, MAuth, mauth(), |v| v);
wirefuzz_msg!(mauth_reply, MAuthReply, mauth_reply(), |v| v);
wirefuzz_msg!(mmongetmap, MMonGetMap, Just(MMonGetMap), |v| v);
wirefuzz_msg!(mmonsubscribe, MMonSubscribe, mmonsubscribe(), |v| v);
wirefuzz_msg!(
    mmonsubscribeack,
    MMonSubscribeAck,
    mmonsubscribeack(),
    |v| v
);
wirefuzz_msg!(mmongetversion, MMonGetVersion, mmongetversion(), |v| v);
wirefuzz_msg!(
    mmongetversionreply,
    MMonGetVersionReply,
    mmongetversionreply(),
    |v| v
);
wirefuzz_msg!(mgetpoolstats, MGetPoolStats, mgetpoolstats(), |v| v);
wirefuzz_msg!(
    mgetpoolstatsreply,
    MGetPoolStatsReply,
    mgetpoolstatsreply(),
    |v| v
);
wirefuzz_msg!(mstatfs, MStatfs, mstatfs(), |v| v);
wirefuzz_msg!(mstatfsreply, MStatfsReply, mstatfsreply(), |v| v);
wirefuzz_msg!(mpoolop, MPoolOp, mpoolop(), |v| v);
wirefuzz_msg!(mpoolopreply, MPoolOpReply, mpoolopreply(), |v| v);
wirefuzz_msg!(mmoncommand, MMonCommand, mmoncommand(), |v| v);
wirefuzz_msg!(mmoncommandack, MMonCommandAck, mmoncommandack(), |v| v);
wirefuzz_msg!(
    mmonmap,
    MMonMap,
    u8s(128).prop_map(|monmap| MMonMap { monmap }),
    |v| v
);
wirefuzz_msg!(mconfig, MConfig, mconfig(), |v| v);
wirefuzz_msg!(mgetconfig, MGetConfig, mgetconfig(), |v| v);
wirefuzz_msg!(mlog, MLog, mlog(), |v| v);
wirefuzz_msg!(mlogack, MLogAck, mlogack(), |v| v);
wirefuzz_msg!(mcommand, MCommand, mcommand(), |v| v);
wirefuzz_msg!(mcommandreply, MCommandReply, mcommandreply(), |v| v);
wirefuzz_msg!(mosddeduplist, MOSDDedupList, mosddeduplist(), |v| v);
wirefuzz_msg!(
    mosddeduplistreply,
    MOSDDedupListReply,
    mosddeduplistreply(),
    |v| v
);
wirefuzz_msg!(mosdmap, MOSDMap, mosdmap(), |v| v);
wirefuzz_msg!(mmongetosdmap, MMonGetOSDMap, mmongetosdmap(), |v| v);
wirefuzz_msg!(mosdboot, MOSDBoot, mosdboot(), |v: MOSDBoot| MOSDBoot {
    sb: norm_superblock(v.sb),
    ..v
});
wirefuzz_msg!(mosdalive, MOSDAlive, mosdalive(), |v| v);
wirefuzz_msg!(mosdbeacon, MOSDBeacon, mosdbeacon(), |v| v);
wirefuzz_msg!(mosdmarkmedown, MOSDMarkMeDown, mosdmarkmedown(), |v| v);
wirefuzz_msg!(mosdmarkmedead, MOSDMarkMeDead, mosdmarkmedead(), |v| v);
wirefuzz_msg!(mosdfailure, MOSDFailure, mosdfailure(), |v| v);
wirefuzz_msg!(mosdfull, MOSDFull, mosdfull(), |v| v);
wirefuzz_msg!(mosdping, MOSDPing, mosdping(), |v| v);
wirefuzz_msg!(mosdpg_temp, MOSDPGTemp, mosdpg_temp(), |v| v);
wirefuzz_msg!(mosdpgcreated, MOSDPGCreated, mosdpgcreated(), |v| v);
wirefuzz_msg!(
    mosdpgreadytomerde,
    MOSDPGReadyToMerge,
    mosdpgreadytomerde(),
    |v| v
);
wirefuzz_msg!(
    mmongetpurgedsnaps,
    MMonGetPurgedSnaps,
    mmongetpurgedsnaps(),
    |v| v
);
wirefuzz_msg!(
    mmongetpurgedsnapsreply,
    MMonGetPurgedSnapsReply,
    mmongetpurgedsnapsreply(),
    |v| v
);
wirefuzz_msg!(mmgrmap, MMgrMap, mmgr_map(), |v| v);
wirefuzz_msg!(mmgropen, MMgrOpen, mmgropen(), norm_mmgropen);
wirefuzz_msg!(mmgrconfigure, MMgrConfigure, mmgrconfigure(), |v| v);
wirefuzz_msg!(mmgrreport, MMgrReport, mmgrreport(), |v| v);
wirefuzz_msg!(
    mmgrclose,
    MMgrClose,
    u8s(64).prop_map(|raw| MMgrClose { raw }),
    |v| v
);
wirefuzz_msg!(mpgstats, MPGStats, mpgstats(), |v| v);

// ---------------------------------------------------------------------------
// dispatch: decode_any / decode_with_header (incl. shared and owned front)
// ---------------------------------------------------------------------------

/// A type id drawn from the known `HEAD_BY_TYPE` set (W2: bias dispatch tests to real decoders).
fn known_type_id() -> impl Strategy<Value = u16> {
    let ids: Vec<u16> = AnyMessage::HEAD_BY_TYPE.iter().map(|(t, _)| *t).collect();
    prop::sample::select(ids)
}

fn header2() -> impl Strategy<Value = Header2> {
    (
        any::<u64>(),
        any::<u64>(),
        // W2: only ~45 of 65536 type ids are known, so a uniform `any::<u16>()` reaches a real
        // message decoder in ~0.07% of cases. Bias to the known ids, keep one random arm.
        prop_oneof![known_type_id(), any::<u16>()],
        any::<u16>(),
        any::<u16>(),
        any::<u32>(),
        any::<u16>(),
        any::<u64>(),
        any::<u8>(),
        any::<u16>(),
        any::<u16>(),
    )
        .prop_map(
            |(
                seq,
                tid,
                ty,
                priority,
                version,
                data_pre_padding_len,
                data_off,
                ack_seq,
                flags,
                compat_version,
                reserved,
            )| Header2 {
                seq,
                tid,
                ty,
                priority,
                version,
                data_pre_padding_len,
                data_off,
                ack_seq,
                flags,
                compat_version,
                reserved,
            },
        )
}

/// Every message type the crate decodes, one arm each.
fn message() -> impl Strategy<Value = AnyMessage> {
    prop_oneof![
        mping().prop_map(AnyMessage::MPing),
        mauth().prop_map(AnyMessage::MAuth),
        mauth_reply().prop_map(AnyMessage::MAuthReply),
        Just(AnyMessage::MMonGetMap(MMonGetMap)),
        mmonsubscribe().prop_map(AnyMessage::MMonSubscribe),
        mmonsubscribeack().prop_map(AnyMessage::MMonSubscribeAck),
        mmongetversion().prop_map(AnyMessage::MMonGetVersion),
        mmongetversionreply().prop_map(AnyMessage::MMonGetVersionReply),
        mgetpoolstats().prop_map(AnyMessage::MGetPoolStats),
        mgetpoolstatsreply().prop_map(AnyMessage::MGetPoolStatsReply),
        mstatfs().prop_map(AnyMessage::MStatfs),
        mstatfsreply().prop_map(AnyMessage::MStatfsReply),
        mpoolop().prop_map(AnyMessage::MPoolOp),
        mpoolopreply().prop_map(AnyMessage::MPoolOpReply),
        mmoncommand().prop_map(AnyMessage::MMonCommand),
        mmoncommandack().prop_map(AnyMessage::MMonCommandAck),
        u8s(128).prop_map(|monmap| AnyMessage::MMonMap(MMonMap { monmap })),
        mconfig().prop_map(AnyMessage::MConfig),
        mgetconfig().prop_map(AnyMessage::MGetConfig),
        mlog().prop_map(AnyMessage::MLog),
        mlogack().prop_map(AnyMessage::MLogAck),
        mcommand().prop_map(AnyMessage::MCommand),
        mcommandreply().prop_map(AnyMessage::MCommandReply),
        mosddeduplist().prop_map(AnyMessage::MOSDDedupList),
        mosddeduplistreply().prop_map(AnyMessage::MOSDDedupListReply),
        mosdmap().prop_map(AnyMessage::MOSDMap),
        mmongetosdmap().prop_map(AnyMessage::MMonGetOSDMap),
        mosdboot().prop_map(AnyMessage::MOSDBoot),
        mosdalive().prop_map(AnyMessage::MOSDAlive),
        mosdbeacon().prop_map(AnyMessage::MOSDBeacon),
        mosdmarkmedown().prop_map(AnyMessage::MOSDMarkMeDown),
        mosdmarkmedead().prop_map(AnyMessage::MOSDMarkMeDead),
        mosdfailure().prop_map(AnyMessage::MOSDFailure),
        mosdfull().prop_map(AnyMessage::MOSDFull),
        mosdping().prop_map(AnyMessage::MOSDPing),
        mosdpg_temp().prop_map(AnyMessage::MOSDPGTemp),
        mosdpgcreated().prop_map(AnyMessage::MOSDPGCreated),
        mosdpgreadytomerde().prop_map(AnyMessage::MOSDPGReadyToMerge),
        mmongetpurgedsnaps().prop_map(AnyMessage::MMonGetPurgedSnaps),
        mmongetpurgedsnapsreply().prop_map(AnyMessage::MMonGetPurgedSnapsReply),
        mmgr_map().prop_map(AnyMessage::MMgrMap),
        mmgropen().prop_map(AnyMessage::MMgrOpen),
        mmgrconfigure().prop_map(AnyMessage::MMgrConfigure),
        mmgrreport().prop_map(AnyMessage::MMgrReport),
        u8s(64).prop_map(|raw| AnyMessage::MMgrClose(MMgrClose { raw })),
        mpgstats().prop_map(AnyMessage::MPGStats),
    ]
}

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn decode_any_arbitrary(
        ty in prop_oneof![known_type_id(), any::<u16>()],
        version in any::<u16>(),
        f in bytes(),
        m in bytes(),
        d in bytes(),
    ) {
        allocs::measure(f.len() + m.len() + d.len(), "decode_any arbitrary", || {
            let _ = decode_any(ty, version, &f, &m, &d);
        });
    }

    #[test]
    fn decode_with_header_arbitrary(h in header2(), f in bytes(), m in bytes(), d in bytes()) {
        allocs::measure(f.len() + m.len() + d.len(), "decode_with_header arbitrary", || {
            let _ = decode_with_header(&h, &f, &m, &d);
        });
    }

    #[test]
    fn decode_with_header_shared_arbitrary(
        h in header2(),
        f in bytes(),
        m in bytes(),
        d in bytes(),
    ) {
        let n = f.len() + m.len() + d.len();
        let d = Bytes::from(d);
        allocs::measure(n, "decode_with_header_shared arbitrary", || {
            let _ = decode_with_header_shared(&h, &f, &m, &d);
        });
    }

    #[test]
    fn decode_with_header_owned_arbitrary(
        h in header2(),
        f in bytes(),
        m in bytes(),
        d in bytes(),
    ) {
        let n = f.len() + m.len() + d.len();
        let (f, d) = (Bytes::from(f), Bytes::from(d));
        allocs::measure(n, "decode_with_header_owned arbitrary", || {
            let _ = decode_with_header_owned(&h, &f, &m, &d);
        });
    }

    #[test]
    fn dispatch_roundtrip(m in message()) {
        let (ty, version, compat, segs) = m.encode(FEATURES).unwrap();
        let h = Header2::new(7, ty, version, compat);
        let dec =
            decode_with_header(&h, &segs.front, &segs.middle, &segs.data).unwrap();
        assert_eq!(norm_message(dec), norm_message(m.clone()));
        let dec2 =
            decode_any(ty, version, &segs.front, &segs.middle, &segs.data).unwrap();
        assert_eq!(norm_message(dec2), norm_message(m));
    }

    #[test]
    fn newer_compat_is_rejected(m in message()) {
        let (ty, version, _compat, segs) = m.encode(FEATURES).unwrap();
        let h = Header2 {
            ty,
            version,
            compat_version: version + 1,
            ..Default::default()
        };
        assert!(
            decode_with_header(&h, &segs.front, &segs.middle, &segs.data).is_err(),
            "type {ty} compat {version}+1 must be rejected"
        );
    }
}

#[test]
fn head_by_type_type_ids_are_unique() {
    let mut ids: Vec<u16> = AnyMessage::HEAD_BY_TYPE.iter().map(|(t, _)| *t).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(
        ids.len(),
        AnyMessage::HEAD_BY_TYPE.len(),
        "duplicate type id"
    );
}

/// W15 regression (deterministic): the MPGStats `pg_stat` map is the classic
/// `map<pg_t, pg_stat_t>` wire form — `count + (pg_t + self-delimiting versioned envelope)`,
/// with no length prefix around the envelope. The envelope bytes sit verbatim in the front,
/// and `decode(encode(x)) == x` (a real envelope, not the generator's shape).
#[test]
fn mpgstats_pg_stat_is_a_classic_map() {
    let env = |body: usize| {
        let mut raw = vec![1u8, 0]; // struct_v = 1, struct_compat = 0
        raw.extend_from_slice(&(body as u32).to_le_bytes());
        raw.extend(std::iter::repeat_n(0xAA, body));
        raw
    };
    let m = MPGStats {
        version: 2,
        fsid: Uuid([7u8; 16]),
        osd_stat: OsdStat::default(),
        pg_stat: vec![(PgT::new(3, 4), env(11)), (PgT::new(5, 6), env(23))],
        epoch: 9,
        dummy: UTime::new(1, 2),
        pool_stat: BTreeMap::new(),
    };
    let segs = m.encode(FEATURES).unwrap();
    for (_, raw) in &m.pg_stat {
        assert!(
            segs.front.windows(raw.len()).any(|w| w == raw.as_slice()),
            "the pg_stat envelope must sit verbatim in the front (no extra length prefix)"
        );
    }
    let dec = MPGStats::decode(2, &segs.front, &[], &[]).unwrap();
    assert_eq!(dec, m, "decode(encode(x)) == x over the classic map form");
}

#[test]
fn unknown_type_passes_through_unchanged() {
    let (f, m, d) = (vec![1, 2, 3], vec![4], vec![5, 6]);
    match decode_any(0x999, 3, &f, &m, &d).unwrap() {
        AnyMessage::Unknown {
            ty,
            version,
            compat,
            segments,
        } => {
            assert_eq!(ty, 0x999);
            assert_eq!(version, 3);
            assert_eq!(compat, 3);
            assert_eq!(segments.front, f);
            assert_eq!(segments.middle, m);
            assert_eq!(segments.data, d);
        }
        other => panic!("expected Unknown, got {other:?}"),
    }
}

#[test]
fn unknown_type_large_front_stays_shared() {
    let h = Header2::new(1, 0x999, 1, 0);
    let front = Bytes::from(vec![0u8; 70 * 1024]);
    let data = Bytes::new();
    match decode_with_header_owned(&h, &front, &[], &data).unwrap() {
        AnyMessage::Unknown { segments, .. } => {
            assert!(
                segments.front_shared().is_some(),
                "a large front must stay a reference, not a copy"
            );
            assert!(segments.front.is_empty());
        }
        other => panic!("expected Unknown, got {other:?}"),
    }
}

#[test]
fn compat_zero_falls_back_to_version() {
    let h = Header2 {
        ty: ty::PING,
        version: 1,
        compat_version: 0,
        ..Default::default()
    };
    assert_eq!(h.effective_compat(), 1);
    assert!(
        matches!(
            decode_with_header(&h, &[], &[], &[]),
            Ok(AnyMessage::MPing(_))
        ),
        "MPing with an empty front and zero compat must decode"
    );
}

// ---------------------------------------------------------------------------
// Header2 (the 41-byte ceph_msg_header2)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn header2_any_byte(b in bytes()) {
        allocs::measure(b.len(), "header2 any_byte", || {
            let _ = Header2::parse(&b);
        });
    }

    #[test]
    fn header2_roundtrip(h in header2()) {
        let enc = h.encode();
        assert_eq!(Header2::parse(&enc).unwrap(), h);
    }

    #[test]
    fn header2_truncated(h in header2()) {
        let enc = h.encode();
        for c in 0..enc.len() {
            assert!(
                Header2::parse(&enc[..c]).is_err(),
                "cut {c}: parsed a header from a prefix"
            );
        }
    }

    #[test]
    fn header2_mutated(h in header2(), m in mutation()) {
        let enc = h.encode();
        let buf = apply(&enc, &m);
        let len = matches!(m, Mutation::Len(..));
        if len {
            allocs::measure(buf.len(), "header2 mutated", || {
                let _ = Header2::parse(&buf);
            });
        }
    }
}

// ---------------------------------------------------------------------------
// CommandReplyView (borrowed daemon-command result)
// ---------------------------------------------------------------------------

fn command_reply_front(result: i32, status: &[u8]) -> Vec<u8> {
    let mut front = Vec::new();
    front.extend_from_slice(&result.to_le_bytes());
    front.extend_from_slice(&(status.len() as u32).to_le_bytes());
    front.extend_from_slice(status);
    front
}

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn command_reply_any_byte(
        // W1: the decoder pins `version == 1` before touching a byte; vary `compat` instead so
        // the hostile bytes reach the body.
        compat in any::<u16>(),
        f in bytes(),
        m in bytes(),
        d in bytes(),
    ) {
        allocs::measure(f.len() + m.len() + d.len(), "command_reply any_byte", || {
            let _ = CommandReplyView::decode(1, compat, &f, &m, &d);
        });
    }

    #[test]
    fn command_reply_roundtrip(result in any::<i32>(), status in u8s(64), data in u8s(64)) {
        let front = command_reply_front(result, &status);
        let view = CommandReplyView::decode(1, 1, &front, &[], &data).unwrap();
        assert_eq!(view.result, result);
        assert_eq!(view.status, status.as_slice());
        assert_eq!(view.data, data.as_slice());
    }

    #[test]
    fn command_reply_truncated(result in any::<i32>(), status in u8s(64), data in u8s(64)) {
        let front = command_reply_front(result, &status);
        for c in 0..front.len() {
            assert!(
                CommandReplyView::decode(1, 1, &front[..c], &[], &data).is_err(),
                "cut {c}: decoded a command reply from a prefix"
            );
        }
    }

    #[test]
    fn command_reply_mutated(
        result in any::<i32>(),
        status in u8s(64),
        data in u8s(64),
        m in mutation(),
    ) {
        let front = command_reply_front(result, &status);
        let len = matches!(m, Mutation::Len(..));
        if len {
            allocs::measure(front.len() + data.len() + 1, "command_reply mutated", || {
                for (f, mm, dd) in [
                    (apply(&front, &m), vec![1u8], data.clone()),
                    (front.clone(), vec![1u8], data.clone()),
                    (front.clone(), vec![], apply(&data, &m)),
                ] {
                    let _ = CommandReplyView::decode(1, 1, &f, &mm, &dd);
                }
            });
        } else {
            for (f, mm, dd) in [
                (apply(&front, &m), vec![1u8], data.clone()),
                (front.clone(), vec![1u8], data.clone()),
                (front.clone(), vec![], apply(&data, &m)),
            ] {
                let _ = CommandReplyView::decode(1, 1, &f, &mm, &dd);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// mgr config blobs and the perf-counter packed blob
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn config_bl_any_byte(b in bytes()) {
        allocs::measure(b.len(), "config_bl any_byte", || {
            let _ = ConfigBl::decode(&b);
        });
    }

    #[test]
    fn config_bl_roundtrip(v in config_bl()) {
        let enc = v.encode().unwrap();
        assert_eq!(ConfigBl::decode(&enc).unwrap(), v);
    }

    #[test]
    fn config_bl_truncated(v in config_bl()) {
        let enc = v.encode().unwrap();
        for c in 0..enc.len() {
            if let Ok(dec) = ConfigBl::decode(&enc[..c]) {
                // no version-optional trailing field: the consumed prefix is the whole encoding
                assert_eq!(
                    dec.encode().unwrap(),
                    &enc[..c],
                    "cut {c}: re-encoding is not exactly the consumed prefix"
                );
            }
        }
    }

    #[test]
    fn config_bl_mutated(v in config_bl(), m in mutation()) {
        let enc = v.encode().unwrap();
        let buf = apply(&enc, &m);
        let len = matches!(m, Mutation::Len(..));
        if len {
            allocs::measure(buf.len(), "config_bl mutated", || {
                let _ = ConfigBl::decode(&buf);
            });
        }
    }

    #[test]
    fn config_defaults_any_byte(b in bytes()) {
        allocs::measure(b.len(), "config_defaults any_byte", || {
            let _ = decode_config_defaults_bl(&b);
        });
    }

    #[test]
    fn config_defaults_roundtrip(
        v in prop::collection::vec((STR_ASCII_0_8, STR_ASCII_0_8), 0..8),
    ) {
        let enc = encode_config_defaults_bl(&v).unwrap();
        assert_eq!(decode_config_defaults_bl(&enc).unwrap(), v);
    }

    #[test]
    fn config_defaults_truncated(
        v in prop::collection::vec((STR_ASCII_0_8, STR_ASCII_0_8), 0..8),
    ) {
        let enc = encode_config_defaults_bl(&v).unwrap();
        for c in 0..enc.len() {
            if let Ok(dec) = decode_config_defaults_bl(&enc[..c]) {
                assert_eq!(
                    encode_config_defaults_bl(&dec).unwrap(),
                    &enc[..c],
                    "cut {c}: re-encoding is not exactly the consumed prefix"
                );
            }
        }
    }

    #[test]
    fn config_defaults_mutated(
        v in prop::collection::vec((STR_ASCII_0_8, STR_ASCII_0_8), 0..8),
        m in mutation(),
    ) {
        let enc = encode_config_defaults_bl(&v).unwrap();
        let buf = apply(&enc, &m);
        let len = matches!(m, Mutation::Len(..));
        if len {
            allocs::measure(buf.len(), "config_defaults mutated", || {
                let _ = decode_config_defaults_bl(&buf);
            });
        }
    }

    #[test]
    fn packed_any_byte(decl in prop::collection::vec(perf_counter_type(), 0..4), b in bytes()) {
        let declared: Vec<&PerfCounterType> = decl.iter().collect();
        allocs::measure(b.len(), "packed any_byte", || {
            let _ = decode_packed(&declared, &b);
        });
    }

    #[test]
    fn packed_roundtrip(decl in prop::collection::vec(perf_counter_type(), 0..4)) {
        let entries: Vec<(&PerfCounterType, CounterValue)> = decl
            .iter()
            .map(|t| (t, CounterValue { value: 1, avgcount: 2, avgcount2: 3 }))
            .collect();
        let declared: Vec<&PerfCounterType> = entries.iter().map(|(t, _)| *t).collect();
        let enc = encode_packed(&entries).unwrap();
        let dec = decode_packed(&declared, &enc).unwrap();
        assert_eq!(dec.len(), decl.len());
        // only LONGRUNAVG types carry avgcount / avgcount2 on the wire
        for (d, (t, v)) in dec.iter().zip(entries.iter()) {
            let want = CounterValue {
                value: v.value,
                avgcount: if t.is_longrunavg() { v.avgcount } else { 0 },
                avgcount2: if t.is_longrunavg() { v.avgcount2 } else { 0 },
            };
            assert_eq!(*d, want);
        }
    }

    #[test]
    fn packed_truncated(decl in prop::collection::vec(perf_counter_type(), 0..4)) {
        let entries: Vec<(&PerfCounterType, CounterValue)> = decl
            .iter()
            .map(|t| (t, CounterValue { value: 1, avgcount: 2, avgcount2: 3 }))
            .collect();
        let declared: Vec<&PerfCounterType> = entries.iter().map(|(t, _)| *t).collect();
        let enc = encode_packed(&entries).unwrap();
        for c in 0..enc.len() {
            assert!(
                decode_packed(&declared, &enc[..c]).is_err(),
                "cut {c}: decoded a truncated packed blob"
            );
        }
    }

    #[test]
    fn packed_mutated(
        decl in prop::collection::vec(perf_counter_type(), 0..4),
        m in mutation(),
    ) {
        let entries: Vec<(&PerfCounterType, CounterValue)> = decl
            .iter()
            .map(|t| (t, CounterValue { value: 1, avgcount: 2, avgcount2: 3 }))
            .collect();
        let declared: Vec<&PerfCounterType> = entries.iter().map(|(t, _)| *t).collect();
        let enc = encode_packed(&entries).unwrap();
        let buf = apply(&enc, &m);
        let len = matches!(m, Mutation::Len(..));
        if len {
            allocs::measure(buf.len(), "packed mutated", || {
                let _ = decode_packed(&declared, &buf);
            });
        }
    }
}

// ---------------------------------------------------------------------------
// payload structs with a denc codec (from_slice: trailing bytes are an error)
// ---------------------------------------------------------------------------

macro_rules! wirefuzz_denc {
    ($name:ident, $ty:ty, $strategy:expr, $normalize:expr) => {
        mod $name {
            use super::*;

            proptest! {
                #![proptest_config(cfg())]

                #[test]
                fn any_byte(b in bytes()) {
                    allocs::measure(b.len(), concat!(stringify!($name), " any_byte"), || {
                        let _ = from_slice::<$ty>(&b);
                    });
                }

                #[test]
                fn roundtrip(v in $strategy) {
                    let enc = to_vec(&v).unwrap();
                    let dec = from_slice::<$ty>(&enc).unwrap();
                    assert_eq!($normalize(dec), $normalize(v));
                }

                #[test]
                fn truncated(v in $strategy) {
                    let enc = to_vec(&v).unwrap();
                    for c in 0..enc.len() {
                        if let Ok(dec) = from_slice::<$ty>(&enc[..c]) {
                            // from_slice rejects trailing bytes: Ok means the prefix was
                            // consumed exactly, so the re-encoding must equal it (W7).
                            assert_eq!(
                                to_vec(&dec).unwrap(),
                                &enc[..c],
                                "cut {c}: re-encoding is not exactly the consumed prefix"
                            );
                        }
                    }
                }

                #[test]
                fn mutated(v in $strategy, m in mutation()) {
                    let enc = to_vec(&v).unwrap();
                    let buf = apply(&enc, &m);
                    let len = matches!(m, Mutation::Len(..));
                    if len {
                        allocs::measure(buf.len(), concat!(stringify!($name), " mutated"), || {
                            let _ = from_slice::<$ty>(&buf);
                        });
                    }
                }
            }
        }
    };
}

wirefuzz_denc!(osd_stat, OsdStat, osd_stat(), |v| v);
wirefuzz_denc!(
    osd_superblock,
    OsdSuperblock,
    osd_superblock(),
    norm_superblock
);
wirefuzz_denc!(store_statfs, StoreStatfs, store_statfs(), |v| v);
wirefuzz_denc!(pow2_hist, Pow2Hist, pow2_hist(), |v| v);
wirefuzz_denc!(obj_perf_stat, ObjectstorePerfStat, obj_perf_stat(), |v| v);
wirefuzz_denc!(compat_set, CompatSet, compat_set(), norm_compat_set);
wirefuzz_denc!(feature_set, FeatureSet, feature_set(), norm_feature);
wirefuzz_denc!(ceph_entity_name, CephEntityName, ceph_entity_name(), |v| v);
wirefuzz_denc!(log_entry, LogEntry, log_entry(), |v| v);
wirefuzz_denc!(raw_stat, RawPoolStatistics, raw_stat(), |v| v);
wirefuzz_denc!(
    perf_counter_type,
    PerfCounterType,
    perf_counter_type(),
    |v| v
);
wirefuzz_denc!(daemon_health, DaemonHealthMetric, daemon_health(), |v| v);
