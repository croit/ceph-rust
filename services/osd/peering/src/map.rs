// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Map access for the PG machinery: [`PgMapView`] = pgwire's [`OsdMapView`] + PG mapping;
//! adapter for the real `osdmap::OsdMap` and a synthetic map (`synth`) for tests/dev.

use denc::types::PgT;
use osdmap::OsdMap;
use pgwire::{MapFlags, Mapping, NONE_OSD, OsdMapView, PoolParams};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;
use std::sync::Arc;

/// An osdmap epoch as the PG sees it.
pub trait PgMapView: OsdMapView {
    /// `pg_to_up_acting` (up, up_primary, acting, acting_primary); empty mapping if the pool or
    /// PG does not exist.
    fn pg_mapping(&self, pg: PgT) -> Mapping;
    /// `(position of osd in acting, acting_primary)` of `pg`: the per-op placement checks without a copy of the
    /// mapping (an implementation that memoizes mappings borrows its memo).
    fn acting_pos(&self, pg: PgT, osd: i32) -> (Option<usize>, i32) {
        let m = self.pg_mapping(pg);
        (m.acting.iter().position(|&o| o == osd), m.acting_primary)
    }
    /// `removed_snaps_queue[pool]` (ids removed at the mon, not yet pruned): input of the snap trimmer.
    fn removed_snaps_queue(&self, _pool: u64) -> crate::snaps::Ivs {
        Default::default()
    }
    /// `osd_state & FULL` (classic `OSDMap::isfull`): the mon flagged the OSD full.
    fn is_full(&self, osd: i32) -> bool;
    /// Cluster `map_flags::FULL` (client-ops 5.4 #11 / 5.7 step 5): the OSD refuses growing writes as if the pool
    /// were FLAG_FULL. Synthetic maps default to false.
    fn map_full(&self) -> bool {
        false
    }
    /// Cluster flag NOSNAPTRIM.
    fn nosnaptrim(&self) -> bool {
        false
    }
    /// One past the highest OSD id the map can hold (`max_osd`).
    fn max_osd(&self) -> i32;
    /// `(pool id, pg_num)` of every pool: the splits a newer map brings (`PgSet::handle_map`).
    fn pg_nums(&self) -> Vec<(u64, u32)>;
    /// Cluster flags that hold back recovery / backfill.
    fn rb_flags(&self) -> RbFlags {
        RbFlags::default()
    }
    /// Pool name (kill switch `ec_enable_pools` accepts names).
    fn pool_name(&self, _pool: u64) -> Option<osdmap::PoolName> {
        None
    }
    /// `require_osd_release` (osdmap::consts::release); 0 = unknown (no encoding newer than the oldest peer's).
    fn require_osd_release(&self) -> u8 {
        0
    }
}

/// Osdmap flags that gate recovery and backfill (spec peering.md 9.4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RbFlags {
    pub norecover: bool,
    pub nobackfill: bool,
    pub norebalance: bool,
    pub pauserec: bool,
}

/// Shared map handle of one core (thread-per-core: never crosses threads; [`RealMap`] memoizes mappings in a `RefCell`).
pub type MapHandle = Rc<dyn PgMapView>;

/// Shard ids of a pool: `shard_id_t` is an `i8`, so the ids are `0..SHARD_ID_SPACE`.
const SHARD_ID_SPACE: u32 = 128;

/// Support gate verdict of an erasure pool (adr 0039): everything not provably supported stays passive. `None` for
/// replicated pools.
pub fn ec_pool_info(map: &OsdMap, p: &osdmap::pool::PgPool) -> Option<pgwire::EcPoolInfo> {
    if p.ptype != osdmap::pool::TYPE_ERASURE {
        return None;
    }
    let v = ec::evaluate(&ec::PoolEcInput {
        size: p.size as u32,
        min_size: p.min_size as u32,
        stripe_width: p.stripe_width,
        flag_overwrites: p.has_flag(osdmap::pool::flags::EC_OVERWRITES),
        flag_optimizations: p.has_flag(osdmap::pool::flags::EC_OPTIMIZATIONS),
        flag_omap: p.has_flag(osdmap::pool::flags::OMAP),
        profile: map.erasure_code_profiles.get(&p.erasure_code_profile),
        nonprimary_shards: (0..SHARD_ID_SPACE)
            .filter(|s| p.nonprimary_shards.contains(*s as usize))
            .collect(),
    });
    Some(match v {
        ec::Verdict::Supported(f) => pgwire::EcPoolInfo {
            k: f.k,
            m: f.m,
            stripe_width: f.stripe_width,
            chunk_size: f.chunk_size,
            // pool flag (mode L1, or append-only client rule in mode O)
            overwrites: p.has_flag(osdmap::pool::flags::EC_OVERWRITES),
            supported: true,
            reason: String::new(),
            plugin: f.plugin.name().to_string(),
            technique: f.technique.clone(),
            profile: f.profile.clone(),
            chunk_mapping: f.chunk_mapping.clone(),
            optimized: f.mode == ec::EcMode::Optimized,
            nonprimary: f.nonprimary.clone(),
            omap: p.has_flag(osdmap::pool::flags::OMAP),
            sub_chunks: f.sub_chunks,
            primary_ok: f.primary_ok,
        },
        ec::Verdict::Unsupported(reason) => pgwire::EcPoolInfo {
            supported: false,
            reason,
            ..Default::default()
        },
    })
}

/// Erasure pools on the ISA plugin as `(pool, k, m)`, but only when the map holds at least two distinct `(k, m)` among
/// them (empty otherwise). Ceph tracker 74943: classic ISA builds before the fix cached decode tables per plugin
/// without k/m in the key, so a second profile shape can decode with a wrong table (adr 0039 am. 4).
pub fn isa_distinct_km_pools(map: &OsdMap) -> Vec<(u64, u32, u32)> {
    let v: Vec<(u64, u32, u32)> = map
        .pools
        .iter()
        .filter(|(id, _)| **id >= 0)
        .filter_map(|(id, p)| {
            let i = ec_pool_info(map, p)?;
            (i.supported && i.plugin == "isa").then_some((*id as u64, i.k, i.m))
        })
        .collect();
    let shapes: BTreeSet<(u32, u32)> = v.iter().map(|(_, k, m)| (*k, *m)).collect();
    if shapes.len() >= 2 { v } else { Vec::new() }
}

/// Why this OSD does not serve an erasure pool (`None` = served): gate verdict, `ec_enable_pools`, and for optimized
/// pools also `ec_enable_optimized` (adr 0039 point 3, adr 0067 point 2). One rule for PGs, notices and `tell status`.
pub fn ec_not_served(
    info: &pgwire::EcPoolInfo,
    en: &ec::EcEnable,
    en_opt: &ec::EcEnable,
    pool: u64,
    name: impl AsRef<[u8]>,
) -> Option<String> {
    if !info.supported {
        return Some(info.reason.clone());
    }
    if !en.allows(pool, name.as_ref()) {
        return Some("EC shard role disabled (config ec_enable_pools)".to_string());
    }
    if info.optimized && !en_opt.allows(pool, name.as_ref()) {
        return Some("optimized EC pool disabled (config ec_enable_optimized)".to_string());
    }
    None
}

/// Decline mode applies (adr 0039 am. 1, adr 0067 am. 1): the gate rejects the pool, or it is an optimized pool that
/// `ec_enable_optimized` does not enable. A supported pool disabled only by `ec_enable_pools` is never declined.
pub fn ec_declinable(
    info: &pgwire::EcPoolInfo,
    en_opt: &ec::EcEnable,
    pool: u64,
    name: impl AsRef<[u8]>,
) -> bool {
    !info.supported || (info.optimized && !en_opt.allows(pool, name.as_ref()))
}

/// Adapter over a decoded real [`OsdMap`], with the [`PoolParams`] of every pool derived once (the EC support gate
/// evaluates the profile: `pool` runs per outbound PG message) and a per-epoch memo of the PG mappings.
#[derive(Debug, Clone)]
pub struct RealMap(pub Arc<OsdMap>, BTreeMap<u64, PoolParams>, MappingMemo);

/// `pg_to_up_acting` results of one epoch, filled on first use. The map is immutable and every epoch is a new
/// [`RealMap`], so a new epoch, a pool change, a pg_num change (split / merge), pg_temp / primary_temp or an OSD state
/// change never meets an entry computed for another map. Bounded by the PGs of the map (classic `OSDMapMapping` keeps
/// all of them per epoch); a PG the map does not have (a peer's seed beyond `pg_num`, an unknown pool) is not kept. A
/// full CRUSH run per outbound PG message (the validator) and per client op was ~10 % of an EC OSD's instructions
/// (doc/perf/w4k-cpu.md).
type MappingMemo = RefCell<HashMap<PgT, Mapping, foldhash::fast::RandomState>>;

impl RealMap {
    pub fn new(m: Arc<OsdMap>) -> Self {
        let pools = m
            .pools
            .iter()
            .map(|(&id, p)| (id as u64, pool_params(&m, p)))
            .collect();
        RealMap(m, pools, MappingMemo::default())
    }
}

/// `pg_to_up_acting` of `pg` in `m` (a CRUSH run; [`RealMap`] memoizes it per epoch).
pub fn crush_mapping(m: &OsdMap, pg: PgT) -> Mapping {
    let m = m.pg_to_up_acting(pg);
    Mapping {
        up: m.up,
        up_primary: m.up_primary,
        acting: m.acting,
        acting_primary: m.acting_primary,
    }
}

/// pool_opts_t key of `read_lease_interval` (double, seconds; osdmap.md 2.4).
const POOL_OPT_READ_LEASE_INTERVAL: i32 = 19;
/// pool_opts_t keys of the scrub options (osdmap.md 2.4): 0 `scrub_min_interval` (d), 2 `deep_scrub_interval` (d),
/// 5 `scrub_priority` (i).
const POOL_OPT_SCRUB_MIN_INTERVAL: i32 = 0;
const POOL_OPT_DEEP_SCRUB_INTERVAL: i32 = 2;
const POOL_OPT_SCRUB_PRIORITY: i32 = 5;
/// pool_opts_t key 3 `recovery_priority` (i, documented range -10..10; spec replication.md 11.1).
const POOL_OPT_RECOVERY_PRIORITY: i32 = 3;
/// WPQ recovery message header priority (spec replication.md 6).
const POOL_OPT_RECOVERY_OP_PRIORITY: i32 = 4;

/// Positive seconds of a pool interval option in ns (`0`/unset = the OSD option applies, spec scrub.md 12.1.6).
fn pool_interval(p: &osdmap::pool::PgPool, key: i32) -> Option<u64> {
    match p.opts.0.get(&key) {
        Some(osdmap::pool::OptVal::Double(v)) if *v > 0.0 => Some((*v * 1e9) as u64),
        Some(osdmap::pool::OptVal::Int(v)) if *v > 0 => (*v as u64).checked_mul(1_000_000_000),
        _ => None,
    }
}

pub(crate) fn pool_params(m: &OsdMap, p: &osdmap::pool::PgPool) -> PoolParams {
    let is_ec = p.ptype == osdmap::pool::TYPE_ERASURE;
    let ec_info = ec_pool_info(m, p).map(Arc::new);
    let ec_k = match (&ec_info, p.ec_data_shard_count) {
        (_, Some(k)) => k as u32,
        (Some(i), None) if i.supported => i.k,
        _ => 0,
    };
    PoolParams {
        ec: ec_info,
        size: p.size as u32,
        min_size: p.min_size as u32,
        pg_num: p.pg_num,
        pg_num_pending: p.pg_num_pending,
        is_erasure: is_ec,
        ec_k,
        crush_rule: i32::from(p.crush_rule),
        peering_crush_bucket_count: p.peering_crush.bucket_count,
        peering_crush_bucket_target: p.peering_crush.bucket_target,
        peering_crush_bucket_barrier: p.peering_crush.bucket_barrier,
        peering_crush_mandatory_member: p.peering_crush.mandatory_member,
        ec_optimizations: p.has_flag(osdmap::pool::flags::EC_OPTIMIZATIONS),
        full: p.has_flag(osdmap::pool::flags::FULL),
        tiered: p.tier_of >= 0
            || p.read_tier >= 0
            || p.write_tier >= 0
            || p.cache_mode != 0
            || !p.tiers.is_empty(),
        read_lease_ns: match p.opts.0.get(&POOL_OPT_READ_LEASE_INTERVAL) {
            Some(osdmap::pool::OptVal::Double(v)) if *v > 0.0 => Some(crate::types::lease_ns(*v)),
            _ => None,
        },
        scrub_min_interval_ns: pool_interval(p, POOL_OPT_SCRUB_MIN_INTERVAL),
        deep_scrub_interval_ns: pool_interval(p, POOL_OPT_DEEP_SCRUB_INTERVAL),
        scrub_priority: match p.opts.0.get(&POOL_OPT_SCRUB_PRIORITY) {
            Some(osdmap::pool::OptVal::Int(v)) if *v > 0 && *v <= i32::MAX as i64 => {
                Some(*v as i32)
            }
            Some(osdmap::pool::OptVal::Double(v)) if *v > 0.0 && *v <= i32::MAX as f64 => {
                Some(*v as i32)
            }
            _ => None,
        },
        recovery_priority: match p.opts.0.get(&POOL_OPT_RECOVERY_PRIORITY) {
            Some(osdmap::pool::OptVal::Int(v)) => (*v).clamp(-10, 10) as i32,
            Some(osdmap::pool::OptVal::Double(v)) => (*v as i32).clamp(-10, 10),
            _ => 0,
        },
        recovery_op_priority: match p.opts.0.get(&POOL_OPT_RECOVERY_OP_PRIORITY) {
            Some(osdmap::pool::OptVal::Int(v)) if *v > 0 => {
                Some((*v).min(i64::from(u16::MAX)) as u16)
            }
            _ => None,
        },
        merge_meta: pgwire::MergeMeta {
            source_seed: p.last_pg_merge_meta.source_pgid.seed,
            ready_epoch: p.last_pg_merge_meta.ready_epoch,
            last_epoch_started: p.last_pg_merge_meta.last_epoch_started,
            last_epoch_clean: p.last_pg_merge_meta.last_epoch_clean,
            source_version: denc::types::Eversion::new(
                p.last_pg_merge_meta.source_version.1,
                p.last_pg_merge_meta.source_version.0,
            ),
            target_version: denc::types::Eversion::new(
                p.last_pg_merge_meta.target_version.1,
                p.last_pg_merge_meta.target_version.0,
            ),
        },
    }
}

impl OsdMapView for RealMap {
    fn epoch(&self) -> u32 {
        self.0.epoch
    }
    fn pool(&self, pool: u64) -> Option<PoolParams> {
        self.1.get(&pool).cloned()
    }
    fn flags(&self) -> MapFlags {
        MapFlags {
            sortbitwise: self.0.flags & osdmap::consts::map_flags::SORTBITWISE != 0,
            recovery_deletes: self.0.flags & osdmap::consts::map_flags::RECOVERY_DELETES != 0,
        }
    }
    fn exists(&self, osd: i32) -> bool {
        self.0.exists(osd)
    }
    fn is_up(&self, osd: i32) -> bool {
        self.0.is_up(osd)
    }
    fn up_from(&self, osd: i32) -> u32 {
        self.info(osd).map_or(0, |i| i.up_from)
    }
    fn up_thru(&self, osd: i32) -> u32 {
        self.info(osd).map_or(0, |i| i.up_thru)
    }
    fn lost_at(&self, osd: i32) -> u32 {
        self.info(osd).map_or(0, |i| i.lost_at)
    }
    fn is_dead(&self, osd: i32) -> bool {
        self.0.exists(osd)
            && self
                .0
                .osd_xinfo
                .get(osd as usize)
                .is_some_and(|x| x.dead_epoch > self.up_from(osd))
    }
    fn barrier_bucket(&self, osd: i32, barrier: u32, rule: i32) -> i32 {
        self.0
            .crush_state()
            .map_or(0, |c| c.map.parent_of_type(osd, barrier, rule))
    }
}

impl RealMap {
    fn info(&self, osd: i32) -> Option<&osdmap::OsdInfo> {
        if osd < 0 {
            return None;
        }
        self.0.osd_info.get(osd as usize)
    }
}

impl PgMapView for RealMap {
    fn is_full(&self, osd: i32) -> bool {
        self.0.is_full(osd)
    }
    fn map_full(&self) -> bool {
        self.0.flags & osdmap::consts::map_flags::FULL != 0
    }
    fn removed_snaps_queue(&self, pool: u64) -> crate::snaps::Ivs {
        self.0
            .removed_snaps_queue
            .get(&(pool as i64))
            .map(|s| s.0.clone())
            .unwrap_or_default()
    }
    fn nosnaptrim(&self) -> bool {
        self.0.flags & osdmap::consts::map_flags::NOSNAPTRIM != 0
    }
    fn max_osd(&self) -> i32 {
        self.0.max_osd
    }
    fn pg_nums(&self) -> Vec<(u64, u32)> {
        self.1.iter().map(|(id, p)| (*id, p.pg_num)).collect()
    }
    fn rb_flags(&self) -> RbFlags {
        use osdmap::consts::map_flags as f;
        let g = self.0.flags;
        RbFlags {
            norecover: g & f::NORECOVER != 0,
            nobackfill: g & f::NOBACKFILL != 0,
            norebalance: g & f::NOREBALANCE != 0,
            pauserec: g & f::PAUSEREC != 0,
        }
    }
    fn pool_name(&self, pool: u64) -> Option<osdmap::PoolName> {
        self.0.pool_name.get(&(pool as i64)).cloned()
    }
    fn require_osd_release(&self) -> u8 {
        self.0.require_osd_release
    }
    fn pg_mapping(&self, pg: PgT) -> Mapping {
        self.with_mapping(pg, Mapping::clone)
    }
    fn acting_pos(&self, pg: PgT, osd: i32) -> (Option<usize>, i32) {
        self.with_mapping(pg, |m| {
            (m.acting.iter().position(|&o| o == osd), m.acting_primary)
        })
    }
}

impl RealMap {
    /// `f` over the memoized mapping of `pg` (computed by CRUSH and kept on first use).
    fn with_mapping<R>(&self, pg: PgT, f: impl FnOnce(&Mapping) -> R) -> R {
        if let Some(m) = self.2.borrow().get(&pg) {
            debug_assert_eq!(
                *m,
                crush_mapping(&self.0, pg),
                "memoized mapping of {pg} differs from CRUSH at epoch {}",
                self.0.epoch
            );
            return f(m);
        }
        let m = crush_mapping(&self.0, pg);
        let r = f(&m);
        // Only PGs of the map are kept: `pg_mapping` is also asked for whatever a peer names (`PgSet::route` ->
        // `should_exist`), and a seed beyond `pg_num` or an unknown pool has no mapping to remember.
        if self.1.get(&pg.pool).is_some_and(|p| pg.seed < p.pg_num) {
            self.2.borrow_mut().insert(pg, m);
        }
        r
    }
}

/// Synthetic maps with scripted mappings (tests, dev tools).
pub mod synth {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct SOsd {
        pub exists: bool,
        pub up: bool,
        pub in_: bool,
        pub up_from: u32,
        pub up_thru: u32,
        pub lost_at: u32,
        /// `osd_xinfo.dead_epoch` (MOSDMarkMeDead).
        pub dead_epoch: u32,
        /// `osd_state & FULL`.
        pub full: bool,
    }

    /// Deterministic map: `up` = first `size` up+in OSDs ranked by a per-PG hash (rendezvous),
    /// unless overridden. `pg_temp` becomes `acting`.
    #[derive(Debug, Clone, Default)]
    pub struct SynthMap {
        pub epoch: u32,
        pub pools: BTreeMap<u64, PoolParams>,
        pub osds: BTreeMap<i32, SOsd>,
        pub flags: MapFlags,
        /// Cluster `map_flags::FULL` (client-ops 5.4 #11 / 5.7 step 5).
        pub full: bool,
        pub pg_temp: BTreeMap<PgT, Vec<i32>>,
        pub up_override: BTreeMap<PgT, Vec<i32>>,
        /// `pgp_num` per pool (placement input); absent = pg_num. Split children keep the parent's placement while
        /// pg_num > pgp_num.
        pub pgp: BTreeMap<u64, u32>,
        /// `removed_snaps_queue` per pool.
        pub removed_queue: BTreeMap<u64, crate::snaps::Ivs>,
        pub nosnaptrim: bool,
        pub rb: RbFlags,
        /// Stretch barrier bucket per OSD, whatever the barrier type and rule; absent = 0 (not found).
        pub barrier: BTreeMap<i32, i32>,
    }

    fn rank(pg: PgT, osd: i32) -> u64 {
        let mut x =
            (pg.pool << 32 | pg.seed as u64) ^ ((osd as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
        x ^= x >> 33;
        x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
        x ^= x >> 33;
        x = x.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
        x ^ (x >> 33)
    }

    impl SynthMap {
        pub fn new(epoch: u32) -> Self {
            SynthMap {
                epoch,
                flags: MapFlags {
                    sortbitwise: true,
                    recovery_deletes: true,
                },
                ..Default::default()
            }
        }
        pub fn with_pool(mut self, pool: u64, size: u32, min_size: u32, pg_num: u32) -> Self {
            self.pools.insert(
                pool,
                PoolParams {
                    size,
                    min_size,
                    pg_num,
                    pg_num_pending: pg_num,
                    ..Default::default()
                },
            );
            self
        }
        /// Add an OSD that is up+in since `up_from`.
        pub fn with_osd(mut self, osd: i32, up_from: u32) -> Self {
            self.osds.insert(
                osd,
                SOsd {
                    exists: true,
                    up: true,
                    in_: true,
                    up_from,
                    up_thru: 0,
                    lost_at: 0,
                    dead_epoch: 0,
                    full: false,
                },
            );
            self
        }
        pub fn into_handle(self) -> MapHandle {
            Rc::new(self)
        }
        fn usable(&self, o: i32) -> bool {
            self.osds.get(&o).is_some_and(|x| x.exists && x.up && x.in_)
        }
    }

    impl OsdMapView for SynthMap {
        fn epoch(&self) -> u32 {
            self.epoch
        }
        fn pool(&self, pool: u64) -> Option<PoolParams> {
            self.pools.get(&pool).cloned()
        }
        fn flags(&self) -> MapFlags {
            self.flags
        }
        fn exists(&self, osd: i32) -> bool {
            self.osds.get(&osd).is_some_and(|x| x.exists)
        }
        fn is_up(&self, osd: i32) -> bool {
            self.osds.get(&osd).is_some_and(|x| x.exists && x.up)
        }
        fn up_from(&self, osd: i32) -> u32 {
            self.osds.get(&osd).map_or(0, |x| x.up_from)
        }
        fn up_thru(&self, osd: i32) -> u32 {
            self.osds.get(&osd).map_or(0, |x| x.up_thru)
        }
        fn lost_at(&self, osd: i32) -> u32 {
            self.osds.get(&osd).map_or(0, |x| x.lost_at)
        }
        fn is_dead(&self, osd: i32) -> bool {
            self.osds
                .get(&osd)
                .is_some_and(|x| x.exists && x.dead_epoch > x.up_from)
        }
        fn barrier_bucket(&self, osd: i32, _barrier: u32, _rule: i32) -> i32 {
            self.barrier.get(&osd).copied().unwrap_or(0)
        }
    }

    impl PgMapView for SynthMap {
        fn is_full(&self, osd: i32) -> bool {
            self.osds.get(&osd).is_some_and(|x| x.exists && x.full)
        }
        fn map_full(&self) -> bool {
            self.full
        }
        fn removed_snaps_queue(&self, pool: u64) -> crate::snaps::Ivs {
            self.removed_queue.get(&pool).cloned().unwrap_or_default()
        }
        fn nosnaptrim(&self) -> bool {
            self.nosnaptrim
        }
        fn rb_flags(&self) -> RbFlags {
            self.rb
        }
        fn max_osd(&self) -> i32 {
            self.osds.keys().next_back().map_or(0, |o| o + 1)
        }
        fn pg_nums(&self) -> Vec<(u64, u32)> {
            self.pools.iter().map(|(id, p)| (*id, p.pg_num)).collect()
        }
        fn pg_mapping(&self, pg: PgT) -> Mapping {
            let Some(pool) = self.pools.get(&pg.pool) else {
                return Mapping {
                    up: vec![],
                    up_primary: -1,
                    acting: vec![],
                    acting_primary: -1,
                };
            };
            if pg.seed >= pool.pg_num {
                return Mapping {
                    up: vec![],
                    up_primary: -1,
                    acting: vec![],
                    acting_primary: -1,
                };
            }
            if pool.is_erasure {
                // positional (indep) mapping: shard i = index i, a missing member is a NONE hole
                let size = pool.size as usize;
                let first = |v: &[i32]| v.iter().copied().find(|o| *o != NONE_OSD).unwrap_or(-1);
                let up: Vec<i32> = if let Some(o) = self.up_override.get(&pg) {
                    o.iter()
                        .map(|x| if self.usable(*x) { *x } else { NONE_OSD })
                        .collect()
                } else {
                    let pgp = self
                        .pgp
                        .get(&pg.pool)
                        .copied()
                        .unwrap_or(pool.pg_num)
                        .max(1);
                    let pps = PgT::new(
                        pg.pool,
                        pgwire::stable_mod(pg.seed, pgp, pgwire::pg_num_mask(pgp)),
                    );
                    let mut c: Vec<i32> = self
                        .osds
                        .iter()
                        .filter(|(_, x)| x.exists && x.in_)
                        .map(|(o, _)| *o)
                        .collect();
                    c.sort_by_key(|o| std::cmp::Reverse(rank(pps, *o)));
                    c.truncate(size);
                    c.resize(size, NONE_OSD);
                    c.into_iter()
                        .map(|o| {
                            if o != NONE_OSD && self.usable(o) {
                                o
                            } else {
                                NONE_OSD
                            }
                        })
                        .collect()
                };
                let up_primary = first(&up);
                let (acting, acting_primary) = match self.pg_temp.get(&pg) {
                    Some(t) if !t.is_empty() => {
                        let a: Vec<i32> = t
                            .iter()
                            .map(|o| {
                                if *o != NONE_OSD && self.is_up(*o) {
                                    *o
                                } else {
                                    NONE_OSD
                                }
                            })
                            .collect();
                        // optimized EC: the mon stores pg_temp primary-capable shards first, so the temp primary is
                        // the first present primary-capable member (mapping.rs `undo_ec_opt_order`)
                        let p = match pool.ec.as_ref().filter(|e| e.optimized) {
                            Some(e) => {
                                let np = |i: usize| e.nonprimary.contains(&(i as u32));
                                let pc = (0..a.len()).filter(|i| !np(*i));
                                pc.chain((0..a.len()).filter(|i| np(*i)))
                                    .map(|i| a[i])
                                    .find(|o| *o != NONE_OSD)
                                    .unwrap_or(-1)
                            }
                            None => first(&a),
                        };
                        (a, p)
                    }
                    _ => (up.clone(), up_primary),
                };
                return Mapping {
                    up,
                    up_primary,
                    acting,
                    acting_primary,
                };
            }
            let up: Vec<i32> = if let Some(o) = self.up_override.get(&pg) {
                o.iter().copied().filter(|x| self.usable(*x)).collect()
            } else {
                let pgp = self
                    .pgp
                    .get(&pg.pool)
                    .copied()
                    .unwrap_or(pool.pg_num)
                    .max(1);
                let pps = PgT::new(
                    pg.pool,
                    pgwire::stable_mod(pg.seed, pgp, pgwire::pg_num_mask(pgp)),
                );
                let mut c: Vec<i32> = self
                    .osds
                    .keys()
                    .copied()
                    .filter(|o| self.usable(*o))
                    .collect();
                c.sort_by_key(|o| std::cmp::Reverse(rank(pps, *o)));
                c.truncate(pool.size as usize);
                c
            };
            let up_primary = up.first().copied().unwrap_or(-1);
            let (acting, acting_primary) = match self.pg_temp.get(&pg) {
                Some(t) if !t.is_empty() => {
                    let a: Vec<i32> = t.iter().copied().filter(|o| self.is_up(*o)).collect();
                    let p = a.first().copied().unwrap_or(-1);
                    (a, p)
                }
                _ => (up.clone(), up_primary),
            };
            debug_assert!(!acting.contains(&NONE_OSD));
            Mapping {
                up,
                up_primary,
                acting,
                acting_primary,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osdmap::pool::{OptVal, PgPool, PoolOpts};

    /// PG-L2: pool option `recovery_priority` comes from pool_opts key 3 and is clamped to its documented range.
    #[test]
    fn pool_recovery_priority_is_read_and_clamped_from_pool_opts_key_3() {
        let mut p = PgPool::default();
        for (v, want) in [(15, 10), (-12, -10), (4, 4)] {
            p.opts = PoolOpts(BTreeMap::from([(3, OptVal::Int(v))]));
            assert_eq!(
                pool_params(&OsdMap::default(), &p).recovery_priority,
                want,
                "value {v}"
            );
        }
        p.opts = PoolOpts::default();
        assert_eq!(
            pool_params(&OsdMap::default(), &p).recovery_priority,
            0,
            "unset"
        );
    }

    #[test]
    fn pool_recovery_message_priority_uses_positive_option_4() {
        let mut p = osdmap::pool::PgPool::default();
        for (input, expected) in [(-1, None), (0, None), (7, Some(7)), (65535, Some(65535))] {
            p.opts.0.insert(
                POOL_OPT_RECOVERY_OP_PRIORITY,
                osdmap::pool::OptVal::Int(input),
            );
            assert_eq!(
                pool_params(&OsdMap::default(), &p).recovery_op_priority,
                expected
            );
        }
    }

    /// NT-clocks-03: an unrepresentable pool `read_lease_interval` is bounded at admission, never cast to u64::MAX.
    #[test]
    fn pool_read_lease_interval_is_bounded() {
        let mut p = PgPool::default();
        for (v, want) in [
            (2.5, Some(2_500_000_000)),
            (2e10, Some(crate::types::MAX_READABLE_INTERVAL)),
            (f64::INFINITY, Some(crate::types::MAX_READABLE_INTERVAL)),
            (-1.0, None),
            (f64::NAN, None),
        ] {
            p.opts = PoolOpts(BTreeMap::from([(
                POOL_OPT_READ_LEASE_INTERVAL,
                OptVal::Double(v),
            )]));
            assert_eq!(
                pool_params(&OsdMap::default(), &p).read_lease_ns,
                want,
                "{v}"
            );
        }
    }

    /// PG-P2: the per-epoch memo holds only PGs of the map. A peer may address any seed of a valid pool (`MOSDPGNotify2`
    /// -> `PgSet::route` -> `should_exist`), and an unknown pool; those lookups run CRUSH but must not grow the memo.
    #[test]
    fn memo_holds_only_pgs_of_the_map() {
        let mut m = OsdMap::default();
        m.pools.insert(
            1,
            PgPool {
                pg_num: 4,
                pgp_num: 4,
                size: 3,
                min_size: 2,
                ..Default::default()
            },
        );
        let rm = RealMap::new(Arc::new(m));
        for seed in 0..4 {
            let _ = rm.pg_mapping(PgT::new(1, seed));
        }
        assert_eq!(rm.2.borrow().len(), 4, "the PGs of the map are memoized");
        for seed in 4..1_000 {
            let _ = rm.pg_mapping(PgT::new(1, seed));
        }
        let _ = rm.pg_mapping(PgT::new(2, 0));
        assert_eq!(
            rm.2.borrow().len(),
            4,
            "a seed beyond pg_num or an unknown pool must not add a memo entry"
        );
    }
}
