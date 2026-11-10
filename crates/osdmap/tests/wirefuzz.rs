// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Wire-fuzz robustness tests for every osdmap decoder (AGENTS.md wire-fuzz goal, target 4).
//!
//! Property, for ANY input bytes: a decoder returns Ok or Err — it never panics, never
//! overflows/aborts, never allocates more than a bound proportional to the input (no
//! length-field-driven huge `Vec::with_capacity`), never loops forever. The osdmap decoders
//! that parse bytes from outside the process (mon full maps / incrementals, monmaps, pools)
//! are:
//!  * `OsdMap::decode_from` / `decode_opts` (full map, incl. the outer crc and the
//!    `max_osd` admission bound);
//!  * `Incremental::decode_from` / `decode_opts` (incremental map, incl. `inc_crc`);
//!  * `MonMap::decode_from`;
//!  * every denc-decodable sub-struct: `PgPool`, `PoolSnapInfo`, `PoolOpts`,
//!    `PgMergeMeta`, `OsdInfo`, `OsdXInfo`, `IntervalSet`, `PoolName`, `MonInfo`.
//!
//! Plus, where an encoder exists:
//!  * roundtrip: `decode(encode(x)) == x` for generated valid `x` (decode-time side effects —
//!    the pool snapshot-flag fix-up — are applied to the expectation);
//!  * truncated: a valid encoding cut at every point is Err — or, if the prefix happens to be
//!    a complete encoding of its own, Ok of a value whose canonical encoding is exactly the
//!    consumed prefix (never a value that consumed past the end);
//!  * mutated: a valid encoding with one byte flipped / inserted / deleted, or a length
//!    field set to an extreme (0, u32::MAX, i32::MIN, len-1, len+1), decodes to Ok or Err.
//!
//! Random bytes alone rarely get past the first length check, so the mutation strategies
//! start from valid encodings (the crate's own encoders) and disturb them.
//!
//! Default case count is small (this crate's wirefuzz tests finish in < 20 s in debug);
//! `WIREFUZZ_CASES` raises it for long runs (lab/wirefuzz-long.sh).

use denc::types::entity::{AF_INET, AF_INET6};
use denc::types::{EntityAddr, EntityAddrVec, Fsid, PgT, UTime, Uuid};
use denc::{Encode, from_slice};
use osdmap::pool::{
    OptVal, PeeringCrush, PgMergeMeta, PgPool, PoolOpts, PoolSnapInfo, ShardIdSet, TYPE_ERASURE,
    TYPE_REPLICATED, flags as pool_flags,
};
use osdmap::{Incremental, IntervalSet, MonInfo, MonMap, OsdInfo, OsdMap, OsdXInfo, PoolName};
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

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

/// Arbitrary bytes, biased short (decoders must fail fast, not grind).
fn bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..2048)
}

fn u8s(n: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..n)
}

/// proptest 1.12: a `&'static str` regex is itself a string strategy.
const STR_UNI_8: &str = r"[\p{L}\p{N}\p{P}\p{S}\p{Z}]{1,8}";
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

// ---- value strategies ------------------------------------------------------

fn fsid() -> impl Strategy<Value = Fsid> {
    prop::array::uniform::<_, 16>(any::<u8>()).prop_map(Uuid)
}

fn utime() -> impl Strategy<Value = UTime> {
    (any::<u32>(), any::<u32>()).prop_map(|(sec, nsec)| UTime::new(sec, nsec))
}

fn pgt() -> impl Strategy<Value = PgT> {
    (any::<u64>(), any::<u32>()).prop_map(|(pool, seed)| PgT::new(pool, seed))
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

fn addrvec() -> impl Strategy<Value = EntityAddrVec> {
    prop::collection::vec(entity_addr(), 0..3).prop_map(EntityAddrVec)
}

fn pool_name() -> impl Strategy<Value = PoolName> {
    u8s(16).prop_map(PoolName::from)
}

fn interval_set() -> impl Strategy<Value = IntervalSet> {
    prop::collection::btree_map(any::<u64>(), any::<u64>(), 0..8).prop_map(IntervalSet)
}

fn non_nan_f32() -> impl Strategy<Value = f32> {
    any::<u32>()
        .prop_map(f32::from_bits)
        .prop_filter("no NaN (not PartialEq)", |v| !v.is_nan())
}

fn pool_snap_info() -> impl Strategy<Value = PoolSnapInfo> {
    (any::<u64>(), utime(), u8s(16)).prop_map(|(snapid, stamp, name)| PoolSnapInfo {
        snapid,
        stamp,
        name,
    })
}

fn opt_val() -> impl Strategy<Value = OptVal> {
    prop_oneof![
        STR_UNI_8.prop_map(OptVal::Str),
        any::<i64>().prop_map(OptVal::Int),
        any::<u64>()
            .prop_map(f64::from_bits)
            .prop_filter("no NaN (not PartialEq)", |v| !v.is_nan())
            .prop_map(OptVal::Double),
    ]
}

fn pool_opts() -> impl Strategy<Value = PoolOpts> {
    prop::collection::btree_map(any::<i32>(), opt_val(), 0..8).prop_map(PoolOpts)
}

fn pg_merge_meta() -> impl Strategy<Value = PgMergeMeta> {
    (
        pgt(),
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
        (any::<u64>(), any::<u32>()),
        (any::<u64>(), any::<u32>()),
    )
        .prop_map(
            |(source_pgid, ready_epoch, last_epoch_started, last_epoch_clean, sv, tv)| {
                PgMergeMeta {
                    source_pgid,
                    ready_epoch,
                    last_epoch_started,
                    last_epoch_clean,
                    source_version: sv,
                    target_version: tv,
                }
            },
        )
}

/// `peering_crush` roundtrips only when `bucket_count == 0` implies the default
/// (the encoder omits the fields for non-stretch pools, and decode keeps the defaults).
fn peering_crush() -> impl Strategy<Value = PeeringCrush> {
    (0u32..=3, any::<u32>(), any::<u32>(), any::<i32>()).prop_map(
        |(bucket_count, bucket_target, bucket_barrier, mandatory_member)| {
            if bucket_count == 0 {
                PeeringCrush::default()
            } else {
                PeeringCrush {
                    bucket_count,
                    bucket_target,
                    bucket_barrier,
                    mandatory_member,
                }
            }
        },
    )
}

type PoolG1 = (
    u8,
    u8,
    u8,
    u8,
    u32,
    u32,
    u32,
    u64,
    u32,
    BTreeMap<u64, PoolSnapInfo>,
);

fn pool_g1() -> impl Strategy<Value = PoolG1> {
    (
        prop_oneof![Just(TYPE_REPLICATED), Just(TYPE_ERASURE)],
        1u8..=8,
        0u8..=2,
        0u8..=2,
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
        any::<u64>(),
        any::<u32>(),
        prop::collection::btree_map(any::<u64>(), pool_snap_info(), 0..3),
    )
}

fn pool_g2() -> impl Strategy<
    Value = (
        IntervalSet,
        u64,
        u64,
        u32,
        u8,
        u64,
        u64,
        BTreeSet<u64>,
        i64,
        u8,
    ),
> {
    (
        interval_set(),
        any::<u64>(),
        any::<u64>(),
        any::<u32>(),
        0u8..=8,
        any::<u64>(),
        any::<u64>(),
        prop::collection::btree_set(any::<u64>(), 0..3),
        any::<i64>(),
        0u8..=4,
    )
}

type PoolG3 = (
    i64,
    i64,
    BTreeMap<String, String>,
    Vec<u8>,
    u32,
    u32,
    u32,
    u64,
    u64,
    u32,
);

fn pool_g3() -> impl Strategy<Value = PoolG3> {
    (
        any::<i64>(),
        any::<i64>(),
        prop::collection::btree_map(STR_UNI_8, STR_UNI_8, 0..3),
        hit_set_params(),
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
        any::<u64>(),
        any::<u64>(),
        any::<u32>(),
    )
}

/// `hit_set_params` is stored as raw bytes but *decoded* as a versioned envelope
/// (v, compat, len, body), so a roundtrippable value must be a well-formed envelope.
fn hit_set_params() -> impl Strategy<Value = Vec<u8>> {
    (0u8..=1, 0u8..=1, u8s(32)).prop_map(|(v, compat, body)| {
        let mut e = vec![v, compat];
        e.extend_from_slice(&(body.len() as u32).to_le_bytes());
        e.extend_from_slice(&body);
        e
    })
}

fn pool_g4() -> impl Strategy<Value = (u32, u32, u32, String, u32, u32, u64, u32, u32)> {
    (
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
        STR_UNI_8,
        any::<u32>(),
        any::<u32>(),
        any::<u64>(),
        any::<u32>(),
        any::<u32>(),
    )
}

type PoolG5 = (
    bool,
    bool,
    u32,
    u32,
    PoolOpts,
    u32,
    BTreeMap<String, BTreeMap<String, String>>,
    UTime,
    u32,
    u32,
);

fn pool_g5() -> impl Strategy<Value = PoolG5> {
    (
        any::<bool>(),
        any::<bool>(),
        any::<u32>(),
        any::<u32>(),
        pool_opts(),
        any::<u32>(),
        prop::collection::btree_map(
            STR_UNI_8,
            prop::collection::btree_map(STR_UNI_8, STR_UNI_8, 0..2),
            0..2,
        ),
        utime(),
        any::<u32>(),
        any::<u32>(),
    )
}

type PoolG6 = (
    u32,
    u32,
    u8,
    PgMergeMeta,
    PeeringCrush,
    ShardIdSet,
    Vec<i8>,
    Option<u8>,
    Option<u8>,
);

fn pool_g6() -> impl Strategy<Value = PoolG6> {
    (
        any::<u32>(),
        any::<u32>(),
        0u8..=3,
        pg_merge_meta(),
        peering_crush(),
        (any::<u64>(), any::<u64>()).prop_map(|(a, b)| ShardIdSet([a, b])),
        prop::collection::vec(any::<i8>(), 0..4),
        any::<Option<u8>>(),
        any::<Option<u8>>(),
    )
}

fn pg_pool() -> impl Strategy<Value = PgPool> {
    (
        pool_g1(),
        pool_g2(),
        pool_g3(),
        pool_g4(),
        pool_g5(),
        pool_g6(),
    )
        .prop_map(|(g1, g2, g3, g4, g5, g6)| PgPool {
            ptype: g1.0,
            size: g1.1,
            crush_rule: g1.2,
            object_hash: g1.3,
            pg_num: g1.4,
            pgp_num: g1.5,
            last_change: g1.6,
            snap_seq: g1.7,
            snap_epoch: g1.8,
            snaps: g1.9,
            removed_snaps: g2.0,
            auid: g2.1,
            flags: g2.2,
            crash_replay_interval: g2.3,
            min_size: g2.4,
            quota_max_bytes: g2.5,
            quota_max_objects: g2.6,
            tiers: g2.7,
            tier_of: g2.8,
            cache_mode: g2.9,
            read_tier: g3.0,
            write_tier: g3.1,
            properties: g3.2,
            hit_set_params: g3.3,
            hit_set_period: g3.4,
            hit_set_count: g3.5,
            stripe_width: g3.6,
            target_max_bytes: g3.7,
            target_max_objects: g3.8,
            cache_target_dirty_ratio_micro: g3.9,
            cache_target_full_ratio_micro: g4.0,
            cache_min_flush_age: g4.1,
            cache_min_evict_age: g4.2,
            erasure_code_profile: g4.3,
            last_force_op_resend_preluminous: g4.4,
            min_read_recency_for_promote: g4.5,
            expected_num_objects: g4.6,
            cache_target_dirty_high_ratio_micro: g4.7,
            min_write_recency_for_promote: g4.8,
            use_gmt_hitset: g5.0,
            fast_read: g5.1,
            hit_set_grade_decay_rate: g5.2,
            hit_set_search_last_n: g5.3,
            opts: g5.4,
            last_force_op_resend_prenautilus: g5.5,
            application_metadata: g5.6,
            create_time: g5.7,
            pg_num_target: g5.8,
            pgp_num_target: g5.9,
            pg_num_pending: g6.0,
            last_force_op_resend: g6.1,
            pg_autoscale_mode: g6.2,
            last_pg_merge_meta: g6.3,
            peering_crush: g6.4,
            nonprimary_shards: g6.5,
            shard_mapping: g6.6,
            ec_data_shard_count: g6.7,
            ec_coding_shard_count: g6.8,
        })
}

/// The decode-time pool flag side effect (spec 2): `snap_seq > 0` without a snapshot
/// flag implies one. Applied to the expectation so roundtrips compare canonical values.
fn norm_pool_flags(p: &mut PgPool) {
    if p.snap_seq > 0 && p.flags & (pool_flags::SELFMANAGED_SNAPS | pool_flags::POOL_SNAPS) == 0 {
        p.flags |= if p.removed_snaps.is_empty() {
            pool_flags::POOL_SNAPS
        } else {
            pool_flags::SELFMANAGED_SNAPS
        };
    }
}

fn norm_pool(p: PgPool) -> PgPool {
    let mut p = p;
    norm_pool_flags(&mut p);
    p
}

/// The decode-time flag fix-up is unconditional in `PgPool::decode` (no `require_osd_release`
/// gate), so `norm_pool_flags` is applied unconditionally to the roundtrip expectation.
type OsdMapG1 = (
    Fsid,
    u32,
    UTime,
    UTime,
    BTreeMap<i64, PgPool>,
    BTreeMap<i64, PoolName>,
    i32,
    u32,
);

fn osd_map_g1() -> impl Strategy<Value = OsdMapG1> {
    (
        fsid(),
        any::<u32>(),
        utime(),
        utime(),
        prop::collection::btree_map(any::<i64>(), pg_pool(), 0..2),
        prop::collection::btree_map(any::<i64>(), pool_name(), 0..3),
        any::<i32>(),
        any::<u32>(),
    )
}

type OsdMapG2 = (
    Vec<u32>,
    Vec<u32>,
    Vec<EntityAddrVec>,
    BTreeMap<PgT, Vec<i32>>,
    BTreeMap<PgT, i32>,
    Vec<u32>,
    Vec<u8>,
    BTreeMap<String, BTreeMap<String, String>>,
);

fn osd_map_g2(max_osd: i32) -> impl Strategy<Value = OsdMapG2> {
    let n = max_osd as usize;
    (
        prop::collection::vec(any::<u32>(), n),
        prop::collection::vec(any::<u32>(), n),
        prop::collection::vec(addrvec(), n),
        prop::collection::btree_map(pgt(), prop::collection::vec(any::<i32>(), 0..3), 0..3),
        prop::collection::btree_map(pgt(), any::<i32>(), 0..3),
        (any::<bool>(), prop::collection::vec(any::<u32>(), n))
            .prop_map(move |(full, v)| if full { v } else { vec![] }),
        u8s(128),
        prop::collection::btree_map(
            STR_UNI_8,
            prop::collection::btree_map(STR_UNI_8, STR_UNI_8, 0..2),
            0..2,
        ),
    )
}

type OsdMapG3 = (
    BTreeMap<PgT, Vec<i32>>,
    BTreeMap<PgT, Vec<(i32, i32)>>,
    u32,
    BTreeMap<i64, IntervalSet>,
    BTreeMap<i64, IntervalSet>,
    UTime,
    UTime,
    BTreeMap<PgT, i32>,
);

fn osd_map_g3() -> impl Strategy<Value = OsdMapG3> {
    (
        prop::collection::btree_map(pgt(), prop::collection::vec(any::<i32>(), 0..3), 0..3),
        prop::collection::btree_map(
            pgt(),
            prop::collection::vec((any::<i32>(), any::<i32>()), 0..3),
            0..3,
        ),
        any::<u32>(),
        prop::collection::btree_map(any::<i64>(), interval_set(), 0..2),
        prop::collection::btree_map(any::<i64>(), interval_set(), 0..2),
        utime(),
        utime(),
        prop::collection::btree_map(pgt(), any::<i32>(), 0..3),
    )
}

type OsdMapG4 = (
    Vec<EntityAddrVec>,
    Vec<OsdInfo>,
    BTreeMap<EntityAddr, UTime>,
    Vec<EntityAddrVec>,
    u32,
    String,
    Vec<Fsid>,
    Vec<OsdXInfo>,
    Vec<EntityAddrVec>,
    (f32, f32, f32),
);

fn osd_map_g4(max_osd: i32) -> impl Strategy<Value = OsdMapG4> {
    let n = max_osd as usize;
    (
        prop::collection::vec(addrvec(), n),
        prop::collection::vec(osd_info(), n),
        prop::collection::btree_map(entity_addr(), utime(), 0..3),
        prop::collection::vec(addrvec(), n),
        any::<u32>(),
        STR_ASCII_0_8,
        prop::collection::vec(fsid(), n),
        prop::collection::vec(osd_xinfo(), n),
        prop::collection::vec(addrvec(), n),
        (non_nan_f32(), non_nan_f32(), non_nan_f32()),
    )
}

/// The stretch fields are only encoded when `stretch_mode_enabled` (osd_part v >= 10), so a
/// roundtrippable map keeps them at their defaults when the flag is off.
fn stretch_group() -> impl Strategy<Value = (bool, u32, u32, u32, i32)> {
    prop_oneof![
        (any::<u32>(), any::<u32>(), any::<u32>(), any::<i32>())
            .prop_map(|(a, b, c, d)| (true, a, b, c, d)),
        (Just(0u32), Just(0u32), Just(0u32), Just(0i32))
            .prop_map(|(a, b, c, d)| (false, a, b, c, d)),
    ]
}

type OsdMapG5 = (
    u8,
    u8,
    BTreeMap<i64, IntervalSet>,
    BTreeMap<i32, u32>,
    BTreeMap<i32, u32>,
    (bool, u32, u32, u32, i32),
    bool,
);

fn osd_map_g5() -> impl Strategy<Value = OsdMapG5> {
    (
        any::<u8>(),
        0u8..=11,
        prop::collection::btree_map(any::<i64>(), interval_set(), 0..2),
        prop::collection::btree_map(any::<i32>(), any::<u32>(), 0..3),
        prop::collection::btree_map(any::<i32>(), any::<u32>(), 0..3),
        stretch_group(),
        any::<bool>(),
    )
}

fn osd_map() -> impl Strategy<Value = OsdMap> {
    (osd_map_g1(), 0i32..=8)
        .prop_flat_map(|(g1, max_osd)| {
            (
                Just(g1),
                Just(max_osd),
                osd_map_g2(max_osd),
                osd_map_g3(),
                osd_map_g4(max_osd),
                osd_map_g5(),
            )
        })
        .prop_map(|(g1, max_osd, g2, g3, g4, g5)| {
            // The private fields (`crush`, `crush_cache`, `range_blocklist`, `range_index`)
            // stay at their defaults; the CRUSH blob goes through `set_crush`.
            let mut m = OsdMap::default();
            m.fsid = g1.0;
            m.epoch = g1.1;
            m.created = g1.2;
            m.modified = g1.3;
            m.pools = g1.4;
            m.pool_name = g1.5;
            m.pool_max = g1.6;
            m.flags = g1.7;
            m.max_osd = max_osd;
            m.osd_state = g2.0;
            m.osd_weight = g2.1;
            m.client_addrs = g2.2;
            m.pg_temp = g2.3;
            m.primary_temp = g2.4;
            m.osd_primary_affinity = g2.5;
            m.erasure_code_profiles = g2.7;
            m.pg_upmap = g3.0;
            m.pg_upmap_items = g3.1;
            m.crush_version = g3.2;
            m.new_removed_snaps = g3.3;
            m.new_purged_snaps = g3.4;
            m.last_up_change = g3.5;
            m.last_in_change = g3.6;
            m.pg_upmap_primaries = g3.7;
            m.hb_back_addrs = g4.0;
            m.osd_info = g4.1;
            m.blocklist = g4.2;
            m.cluster_addrs = g4.3;
            m.cluster_snapshot_epoch = g4.4;
            m.cluster_snapshot = g4.5;
            m.osd_uuid = g4.6;
            m.osd_xinfo = g4.7;
            m.hb_front_addrs = g4.8;
            m.nearfull_ratio = g4.9.0;
            m.full_ratio = g4.9.1;
            m.backfillfull_ratio = g4.9.2;
            m.require_min_compat_client = g5.0;
            m.require_osd_release = g5.1;
            m.removed_snaps_queue = g5.2;
            m.crush_node_flags = g5.3;
            m.device_class_flags = g5.4;
            m.stretch_mode_enabled = g5.5.0;
            m.stretch_bucket_count = g5.5.1;
            m.degraded_stretch_mode = g5.5.2;
            m.recovering_stretch_mode = g5.5.3;
            m.stretch_mode_bucket = g5.5.4;
            m.allow_crimson = g5.6;
            m.set_crush(g2.6);
            m
        })
}

fn osd_info() -> impl Strategy<Value = OsdInfo> {
    (
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
    )
        .prop_map(
            |(last_clean_begin, last_clean_end, up_from, up_thru, down_at, lost_at)| OsdInfo {
                last_clean_begin,
                last_clean_end,
                up_from,
                up_thru,
                down_at,
                lost_at,
            },
        )
}

fn osd_xinfo() -> impl Strategy<Value = OsdXInfo> {
    (
        utime(),
        any::<u32>(),
        any::<u32>(),
        any::<u64>(),
        any::<u32>(),
        utime(),
        any::<u32>(),
    )
        .prop_map(
            |(
                down_stamp,
                laggy_probability,
                laggy_interval,
                features,
                old_weight,
                last_purged_snaps_scrub,
                dead_epoch,
            )| {
                OsdXInfo {
                    down_stamp,
                    laggy_probability,
                    laggy_interval,
                    features,
                    old_weight,
                    last_purged_snaps_scrub,
                    dead_epoch,
                }
            },
        )
}

fn mon_info() -> impl Strategy<Value = MonInfo> {
    (
        STR_UNI_8,
        addrvec(),
        any::<u16>(),
        any::<u16>(),
        prop::collection::btree_map(STR_UNI_8, STR_UNI_8, 0..3),
        utime(),
    )
        .prop_map(
            |(name, public_addrs, priority, weight, crush_loc, time_added)| MonInfo {
                name,
                public_addrs,
                priority,
                weight,
                crush_loc,
                time_added,
            },
        )
}

/// The encoder sorts `auth_allowed_ciphers`; generate them sorted so the roundtrip is
/// identity.
type MonmapG1 = (
    Fsid,
    u32,
    UTime,
    UTime,
    u64,
    u64,
    BTreeMap<String, MonInfo>,
    Vec<String>,
    u8,
    BTreeSet<u32>,
);

fn monmap_g1() -> impl Strategy<Value = MonmapG1> {
    (
        fsid(),
        any::<u32>(),
        utime(),
        utime(),
        any::<u64>(),
        any::<u64>(),
        prop::collection::btree_map(STR_UNI_8, mon_info(), 0..3),
        prop::collection::vec(STR_UNI_8, 0..4),
        any::<u8>(),
        prop::collection::btree_set(any::<u32>(), 0..3),
    )
}

type MonmapG2 = (
    u8,
    BTreeSet<String>,
    bool,
    String,
    BTreeSet<String>,
    u32,
    i32,
    Vec<i32>,
    i32,
);

fn monmap_g2() -> impl Strategy<Value = MonmapG2> {
    (
        prop_oneof![Just(1u8), Just(2u8), Just(3u8)],
        prop::collection::btree_set(STR_UNI_8, 0..3),
        any::<bool>(),
        STR_ASCII_0_8,
        prop::collection::btree_set(STR_UNI_8, 0..3),
        any::<u32>(),
        any::<i32>(),
        prop::collection::vec(any::<i32>(), 0..4),
        any::<i32>(),
    )
}

fn monmap() -> impl Strategy<Value = MonMap> {
    (monmap_g1(), monmap_g2()).prop_map(|(a, b)| MonMap {
        fsid: a.0,
        epoch: a.1,
        last_changed: a.2,
        created: a.3,
        persistent_features: a.4,
        optional_features: a.5,
        mon_info: a.6,
        ranks: a.7,
        min_mon_release: a.8,
        removed_ranks: a.9,
        election_strategy: b.0,
        disallowed_leaders: b.1,
        stretch_mode_enabled: b.2,
        tiebreaker_mon: b.3,
        stretch_marked_down_mons: b.4,
        auth_epoch: b.5,
        auth_service_cipher: b.6,
        auth_allowed_ciphers: {
            let mut c = b.7;
            c.sort_unstable();
            c.dedup();
            c
        },
        auth_preferred_cipher: b.8,
    })
}

type IncG1 = (
    Fsid,
    u32,
    UTime,
    i64,
    i32,
    Vec<u8>,
    Vec<u8>,
    i32,
    BTreeMap<i64, PgPool>,
    BTreeMap<i64, PoolName>,
);

fn incremental_g1() -> impl Strategy<Value = IncG1> {
    (
        fsid(),
        any::<u32>(),
        utime(),
        any::<i64>(),
        any::<i32>(),
        u8s(64),
        u8s(64),
        -1i32..=8,
        prop::collection::btree_map(any::<i64>(), pg_pool(), 0..2),
        prop::collection::btree_map(any::<i64>(), pool_name(), 0..3),
    )
}

type IncG2 = (
    BTreeSet<i64>,
    BTreeMap<i32, EntityAddrVec>,
    BTreeMap<i32, u32>,
    BTreeMap<i32, u32>,
    BTreeMap<PgT, Vec<i32>>,
    BTreeMap<PgT, i32>,
    BTreeMap<i32, u32>,
    BTreeMap<String, BTreeMap<String, String>>,
    Vec<String>,
    BTreeMap<PgT, Vec<i32>>,
);

fn incremental_g2() -> impl Strategy<Value = IncG2> {
    (
        prop::collection::btree_set(any::<i64>(), 0..3),
        prop::collection::btree_map(any::<i32>(), addrvec(), 0..3),
        prop::collection::btree_map(any::<i32>(), any::<u32>(), 0..3),
        prop::collection::btree_map(any::<i32>(), any::<u32>(), 0..3),
        prop::collection::btree_map(pgt(), prop::collection::vec(any::<i32>(), 0..3), 0..3),
        prop::collection::btree_map(pgt(), any::<i32>(), 0..3),
        prop::collection::btree_map(any::<i32>(), any::<u32>(), 0..3),
        prop::collection::btree_map(
            STR_UNI_8,
            prop::collection::btree_map(STR_UNI_8, STR_UNI_8, 0..2),
            0..2,
        ),
        prop::collection::vec(STR_UNI_8, 0..3),
        prop::collection::btree_map(pgt(), prop::collection::vec(any::<i32>(), 0..3), 0..3),
    )
}

type IncG3 = (
    BTreeSet<PgT>,
    BTreeMap<PgT, Vec<(i32, i32)>>,
    BTreeSet<PgT>,
    BTreeMap<i64, IntervalSet>,
    BTreeMap<i64, IntervalSet>,
    UTime,
    UTime,
    BTreeMap<PgT, i32>,
    BTreeSet<PgT>,
    BTreeMap<i32, EntityAddrVec>,
);

fn incremental_g3() -> impl Strategy<Value = IncG3> {
    (
        prop::collection::btree_set(pgt(), 0..3),
        prop::collection::btree_map(
            pgt(),
            prop::collection::vec((any::<i32>(), any::<i32>()), 0..3),
            0..3,
        ),
        prop::collection::btree_set(pgt(), 0..3),
        prop::collection::btree_map(any::<i64>(), interval_set(), 0..2),
        prop::collection::btree_map(any::<i64>(), interval_set(), 0..2),
        utime(),
        utime(),
        prop::collection::btree_map(pgt(), any::<i32>(), 0..3),
        prop::collection::btree_set(pgt(), 0..3),
        prop::collection::btree_map(any::<i32>(), addrvec(), 0..3),
    )
}

type IncG4 = (
    BTreeMap<i32, u32>,
    BTreeMap<i32, (u32, u32)>,
    BTreeMap<i32, u32>,
    BTreeMap<EntityAddr, UTime>,
    Vec<EntityAddr>,
    BTreeMap<i32, EntityAddrVec>,
    String,
    BTreeMap<i32, Fsid>,
    BTreeMap<i32, OsdXInfo>,
    BTreeMap<i32, EntityAddrVec>,
);

fn incremental_g4() -> impl Strategy<Value = IncG4> {
    (
        prop::collection::btree_map(any::<i32>(), any::<u32>(), 0..3),
        prop::collection::btree_map(any::<i32>(), (any::<u32>(), any::<u32>()), 0..3),
        prop::collection::btree_map(any::<i32>(), any::<u32>(), 0..3),
        prop::collection::btree_map(entity_addr(), utime(), 0..3),
        prop::collection::vec(entity_addr(), 0..3),
        prop::collection::btree_map(any::<i32>(), addrvec(), 0..3),
        STR_ASCII_0_8,
        prop::collection::btree_map(any::<i32>(), fsid(), 0..3),
        prop::collection::btree_map(any::<i32>(), osd_xinfo(), 0..3),
        prop::collection::btree_map(any::<i32>(), addrvec(), 0..3),
    )
}

/// The incremental stretch fields are only encoded when `change_stretch_mode` (osd_part
/// v >= 10), so a roundtrippable incremental keeps them at their defaults when it is off.
fn inc_stretch_group() -> impl Strategy<Value = (bool, u32, u32, u32, i32, bool)> {
    prop_oneof![
        (
            any::<u32>(),
            any::<u32>(),
            any::<u32>(),
            any::<i32>(),
            any::<bool>()
        )
            .prop_map(|(a, b, c, d, e)| (true, a, b, c, d, e)),
        (Just(0u32), Just(0u32), Just(0u32), Just(0i32), Just(false))
            .prop_map(|(a, b, c, d, e)| (false, a, b, c, d, e)),
    ]
}

type IncG5a = (
    u64,
    (f32, f32, f32),
    u8,
    u8,
    BTreeMap<i32, u32>,
    BTreeMap<i32, u32>,
    (bool, u32, u32, u32, i32, bool),
);

fn incremental_g5a() -> impl Strategy<Value = IncG5a> {
    (
        any::<u64>(),
        (non_nan_f32(), non_nan_f32(), non_nan_f32()),
        any::<u8>(),
        any::<u8>(),
        prop::collection::btree_map(any::<i32>(), any::<u32>(), 0..3),
        prop::collection::btree_map(any::<i32>(), any::<u32>(), 0..3),
        inc_stretch_group(),
    )
}

fn incremental_g5b() -> impl Strategy<Value = (BTreeMap<EntityAddr, UTime>, Vec<EntityAddr>, u8)> {
    (
        prop::collection::btree_map(entity_addr(), utime(), 0..2),
        prop::collection::vec(entity_addr(), 0..2),
        0u8..=2,
    )
}

fn incremental() -> impl Strategy<Value = Incremental> {
    (
        incremental_g1(),
        incremental_g2(),
        incremental_g3(),
        incremental_g4(),
        incremental_g5a(),
        incremental_g5b(),
    )
        .prop_map(|(g1, g2, g3, g4, g5a, g5b)| Incremental {
            fsid: g1.0,
            epoch: g1.1,
            modified: g1.2,
            new_pool_max: g1.3,
            new_flags: g1.4,
            fullmap: g1.5,
            crush: g1.6,
            new_max_osd: g1.7,
            new_pools: g1.8,
            new_pool_names: g1.9,
            old_pools: g2.0,
            new_up_client: g2.1,
            new_state: g2.2,
            new_weight: g2.3,
            new_pg_temp: g2.4,
            new_primary_temp: g2.5,
            new_primary_affinity: g2.6,
            new_erasure_code_profiles: g2.7,
            old_erasure_code_profiles: g2.8,
            new_pg_upmap: g2.9,
            old_pg_upmap: g3.0,
            new_pg_upmap_items: g3.1,
            old_pg_upmap_items: g3.2,
            new_removed_snaps: g3.3,
            new_purged_snaps: g3.4,
            new_last_up_change: g3.5,
            new_last_in_change: g3.6,
            new_pg_upmap_primary: g3.7,
            old_pg_upmap_primary: g3.8,
            new_hb_back_up: g3.9,
            new_up_thru: g4.0,
            new_last_clean_interval: g4.1,
            new_lost: g4.2,
            new_blocklist: g4.3,
            old_blocklist: g4.4,
            new_up_cluster: g4.5,
            cluster_snapshot: g4.6,
            new_uuid: g4.7,
            new_xinfo: g4.8,
            new_hb_front_up: g4.9,
            encode_features: g5a.0,
            new_nearfull_ratio: g5a.1.0,
            new_full_ratio: g5a.1.1,
            new_backfillfull_ratio: g5a.1.2,
            new_require_min_compat_client: g5a.2,
            new_require_osd_release: g5a.3,
            new_crush_node_flags: g5a.4,
            new_device_class_flags: g5a.5,
            change_stretch_mode: g5a.6.0,
            new_stretch_bucket_count: g5a.6.1,
            new_degraded_stretch_mode: g5a.6.2,
            new_recovering_stretch_mode: g5a.6.3,
            new_stretch_mode_bucket: g5a.6.4,
            stretch_mode_enabled: g5a.6.5,
            new_range_blocklist: g5b.0,
            old_range_blocklist: g5b.1,
            mutate_allow_crimson: g5b.2,
            has_crc: true,
            inc_crc: 0,
            full_crc: 0,
        })
}

/// Roundtrip expectation for a full map: the pool snapshot-flag fix-up on every pool.
fn norm_osdmap(m: OsdMap) -> OsdMap {
    let mut m = m;
    for p in m.pools.values_mut() {
        norm_pool_flags(p);
    }
    m
}

/// Roundtrip expectation for an incremental: the same pool fix-up on `new_pools`.
fn norm_incremental(inc: Incremental) -> Incremental {
    let mut inc = inc;
    for p in inc.new_pools.values_mut() {
        norm_pool_flags(p);
    }
    inc
}

// ---- denc-decodable sub-structs: four wirefuzz tests each ------------------

macro_rules! wirefuzz_type {
    ($name:ident, $ty:ty, $strategy:expr, $normalize:expr) => {
        mod $name {
            use super::*;

            proptest! {
                #![proptest_config(cfg())]

                #[test]
                fn any_byte(b in bytes()) {
                    let _ = from_slice::<$ty>(&b);
                }

                #[test]
                fn roundtrip(v in $strategy) {
                    let enc = v.encode_to_vec().unwrap();
                    let dec = from_slice::<$ty>(&enc).unwrap();
                    let exp = $normalize(v);
                    assert_eq!(dec, exp);
                }

                #[test]
                fn truncated(v in $strategy) {
                    let enc = v.encode_to_vec().unwrap();
                    for c in 0..enc.len() {
                        if let Ok(dec) = from_slice::<$ty>(&enc[..c]) {
                            let re = $normalize(dec);
                            assert_eq!(
                                re.encode_to_vec().unwrap(),
                                &enc[..c],
                                "cut {c}: Ok value re-encodes differently (consumed past the end?)"
                            );
                        }
                    }
                }

                #[test]
                fn mutated(v in $strategy, m in mutation()) {
                    let enc = v.encode_to_vec().unwrap();
                    let buf = apply(&enc, &m);
                    let _ = from_slice::<$ty>(&buf);
                }
            }
        }
    };
}

wirefuzz_type!(osd_info, OsdInfo, osd_info(), |v| v);
wirefuzz_type!(osd_xinfo, OsdXInfo, osd_xinfo(), |v| v);
wirefuzz_type!(pool_snap_info, PoolSnapInfo, pool_snap_info(), |v| v);
wirefuzz_type!(pool_opts, PoolOpts, pool_opts(), |v| v);
wirefuzz_type!(pg_merge_meta, PgMergeMeta, pg_merge_meta(), |v| v);
wirefuzz_type!(pool_name, PoolName, pool_name(), |v| v);
wirefuzz_type!(mon_info, MonInfo, mon_info(), |v| v);
wirefuzz_type!(interval_set, IntervalSet, interval_set(), |v| v);
wirefuzz_type!(pg_pool, PgPool, pg_pool(), norm_pool);
wirefuzz_type!(monmap, MonMap, monmap(), |v| v);

/// W15 regression (deterministic): `hit_set_params` with an empty body roundtrips. The field is
/// stored as raw bytes and decoded as a versioned envelope (v, compat, len, body), so the
/// roundtrippable "empty" case is the 6-byte zero envelope, not an empty `Vec` (that is not a
/// pool encoding at all). The proptest seed that recorded this case predates the current
/// generator and no longer reproduces it, so the case is pinned here by name.
#[test]
fn pg_pool_hit_set_params_empty_roundtrip() {
    let p = PgPool {
        size: 1,
        hit_set_params: vec![0u8, 0, 0, 0, 0, 0], // (v, compat, len = 0): empty body
        ..PgPool::default()
    };
    let enc = p.encode_to_vec().unwrap();
    let dec = from_slice::<PgPool>(&enc).unwrap();
    assert_eq!(
        dec,
        norm_pool(p),
        "an empty-body hit_set_params must roundtrip"
    );
}

// ---- full map / incremental: decode_from entry points -----------------------

mod osdmap_full {
    use super::*;

    proptest! {
        #![proptest_config(cfg())]

        #[test]
        fn any_byte(b in bytes()) {
            let _ = OsdMap::decode_from(&b);
            let _ = OsdMap::decode_opts(&b, false);
        }

        #[test]
        fn roundtrip(v in osd_map()) {
            let enc = v.encode_full().unwrap();
            let dec = OsdMap::decode_from(&enc).unwrap();
            let exp = norm_osdmap(v);
            assert_eq!(dec, exp);
        }

        #[test]
        fn truncated(v in osd_map()) {
            let enc = v.encode_full().unwrap();
            for c in 0..enc.len() {
                if let Ok(dec) = OsdMap::decode_from(&enc[..c]) {
                    let re = norm_osdmap(dec);
                    assert_eq!(
                        re.encode_full().unwrap(),
                        &enc[..c],
                        "cut {c}: Ok value re-encodes differently (consumed past the end?)"
                    );
                }
            }
        }

        #[test]
        fn mutated(v in osd_map(), m in mutation()) {
            let enc = v.encode_full().unwrap();
            let buf = apply(&enc, &m);
            let _ = OsdMap::decode_from(&buf);
            let _ = OsdMap::decode_opts(&buf, false);
        }
    }
}

mod incremental_full {
    use super::*;

    proptest! {
        #![proptest_config(cfg())]

        #[test]
        fn any_byte(b in bytes()) {
            let _ = Incremental::decode_from(&b);
            let _ = Incremental::decode_opts(&b, false);
        }

        #[test]
        fn roundtrip(v in incremental()) {
            let enc = v.encode_inc().unwrap();
            let dec = Incremental::decode_from(&enc).unwrap();
            let mut exp = norm_incremental(v);
            // `encode_inc` recomputes `inc_crc`; the expectation takes the stored value.
            exp.inc_crc =
                u32::from_le_bytes(enc[enc.len() - 8..enc.len() - 4].try_into().unwrap());
            assert_eq!(dec, exp);
        }

        #[test]
        fn truncated(v in incremental()) {
            let enc = v.encode_inc().unwrap();
            for c in 0..enc.len() {
                if let Ok(dec) = Incremental::decode_from(&enc[..c]) {
                    let re = norm_incremental(dec);
                    assert_eq!(
                        re.encode_inc().unwrap(),
                        &enc[..c],
                        "cut {c}: Ok value re-encodes differently (consumed past the end?)"
                    );
                }
            }
        }

        #[test]
        fn mutated(v in incremental(), m in mutation()) {
            let enc = v.encode_inc().unwrap();
            let buf = apply(&enc, &m);
            let _ = Incremental::decode_from(&buf);
            let _ = Incremental::decode_opts(&buf, false);
        }
    }
}
