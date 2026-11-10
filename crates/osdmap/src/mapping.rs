// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! PG mapping pipeline (spec osdmap.md 4): object -> pg -> up/acting.

use crate::consts::{ITEM_NONE, WEIGHT_IN};
use crate::error::{Error, Result};
use crate::hash::{crush_hash32_2, hash_key};
use crate::map::OsdMap;
use crate::pool::{PgPool, flags};
use denc::types::{PgT, ShardId};

/// Acting-primary destination for an ordinary client transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrimaryDestination {
    pub osd: i32,
    pub shard: ShardId,
}

/// CRUSH placement, implemented by [`crate::CrushState`] (the decoded map inside [`OsdMap`]) and the test doubles
/// in [`testing`]. The map itself keeps the CRUSH blob opaque; the mapper owns the parsed form.
pub trait CrushMapper {
    /// Run `rule` for input `x`, producing at most `result_max` items into `out`
    /// (cleared first). `weights` = osd_weight vector (16.16, len max_osd).
    /// `choose_args` = weight-set index (pool id; mapper falls back to its
    /// default set when absent). Unknown rule -> empty result. Non-shifting
    /// (EC) rules emit `ITEM_NONE` for holes.
    fn do_rule(
        &self,
        rule: i32,
        x: u32,
        result_max: usize,
        weights: &[u32],
        choose_args: i64,
        out: &mut Vec<i32>,
    );
}

/// Result of mapping one PG.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PgMapping {
    pub up: Vec<i32>,
    pub up_primary: i32,
    pub acting: Vec<i32>,
    pub acting_primary: i32,
}

impl PgMapping {
    pub fn empty() -> Self {
        PgMapping {
            up: vec![],
            up_primary: -1,
            acting: vec![],
            acting_primary: -1,
        }
    }
}

impl OsdMap {
    /// Resolve the canonical shard of the acting primary. `mapping` must be the
    /// result of this map's pipeline for this actual PG (including temp undo).
    pub fn primary_destination(&self, pg: PgT, mapping: &PgMapping) -> Option<PrimaryDestination> {
        let pool = self.pool(pg.pool as i64)?;
        let osd = mapping.acting_primary;
        if pg.seed >= pool.pg_num || osd < 0 || !self.is_up(osd) {
            return None;
        }
        let optimized_temp = pool.is_erasure()
            && pool.has_flag(flags::EC_OPTIMIZATIONS)
            && self.pg_temp.get(&pg).is_some_and(|t| !t.is_empty());
        if optimized_temp
            && (self.pg_temp[&pg].len() != usize::from(pool.size)
                || (usize::from(pool.size)..128).any(|s| pool.nonprimary_shards.contains(s)))
        {
            return None;
        }
        let selection_order = optimized_temp;
        let position = if selection_order {
            (0..mapping.acting.len())
                .filter(|&i| !pool.nonprimary_shards.contains(i))
                .chain((0..mapping.acting.len()).filter(|&i| pool.nonprimary_shards.contains(i)))
                .find(|&i| mapping.acting[i] == osd)
        } else {
            mapping.acting.iter().position(|&o| o == osd)
        }?;
        let shard = if pool.is_replicated() {
            ShardId::NO_SHARD
        } else if pool.is_erasure() {
            if position >= usize::from(pool.size) {
                return None;
            }
            ShardId(i8::try_from(position).ok()?)
        } else {
            return None;
        };
        Some(PrimaryDestination { osd, shard })
    }

    /// Object -> raw pg (spec 4.1). `hash >= 0` is a locator hash override.
    /// Err if the pool does not exist.
    pub fn object_to_raw_pg(
        &self,
        pool_id: i64,
        name: &[u8],
        key: &[u8],
        nspace: &[u8],
        hash: i64,
    ) -> Result<PgT> {
        let pool = self
            .pools
            .get(&pool_id)
            .ok_or(Error::Invalid("no such pool"))?;
        let ps = if hash >= 0 {
            hash as u32
        } else {
            let k = if key.is_empty() { name } else { key };
            hash_key(pool.object_hash, nspace, k)
        };
        Ok(PgT::new(pool_id as u64, ps))
    }

    /// Object -> actual pg (raw pg reduced with stable_mod).
    pub fn object_to_pg(
        &self,
        pool_id: i64,
        name: &[u8],
        key: &[u8],
        nspace: &[u8],
        hash: i64,
    ) -> Result<PgT> {
        let raw = self.object_to_raw_pg(pool_id, name, key, nspace, hash)?;
        Ok(self.pools[&pool_id].raw_pg_to_pg(raw))
    }

    fn remove_nonexistent(&self, pool: &PgPool, raw: &mut Vec<i32>) {
        if pool.can_shift_osds() {
            raw.retain(|&o| self.exists(o));
        } else {
            for o in raw.iter_mut() {
                if !self.exists(*o) {
                    *o = ITEM_NONE;
                }
            }
        }
    }

    fn bad_target(&self, t: i32) -> bool {
        t != ITEM_NONE && t >= 0 && t < self.max_osd && self.osd_weight[t as usize] == 0
    }

    /// pg_upmap / pg_upmap_items / pg_upmap_primaries (spec 4.4); `pg` = actual pg.
    fn apply_upmap(&self, pg: PgT, raw: &mut Vec<i32>) {
        if !self.pg_upmap.is_empty()
            && let Some(v) = self.pg_upmap.get(&pg)
        {
            if v.iter().any(|&t| self.bad_target(t)) {
                return;
            }
            raw.clear();
            raw.extend_from_slice(v);
        }
        if !self.pg_upmap_items.is_empty()
            && let Some(items) = self.pg_upmap_items.get(&pg)
        {
            for &(from, to) in items {
                if raw.contains(&to) {
                    continue;
                }
                if self.bad_target(to) {
                    continue;
                }
                if let Some(pos) = raw.iter().position(|&o| o == from) {
                    raw[pos] = to;
                }
            }
        }
        if !self.pg_upmap_primaries.is_empty()
            && let Some(&p) = self.pg_upmap_primaries.get(&pg)
            && p != ITEM_NONE
            && p >= 0
            && p < self.max_osd
            && self.osd_weight[p as usize] != 0
            && let Some(i) = raw.iter().skip(1).position(|&o| o == p)
        {
            raw.swap(0, i + 1);
        }
    }

    fn raw_to_up(&self, pool: &PgPool, raw: &[i32]) -> (Vec<i32>, i32) {
        let mut up: Vec<i32> = Vec::with_capacity(raw.len());
        if pool.can_shift_osds() {
            up.extend(raw.iter().copied().filter(|&o| self.is_up(o)));
        } else {
            up.extend(
                raw.iter()
                    .map(|&o| if self.is_up(o) { o } else { ITEM_NONE }),
            );
        }
        let primary = up.iter().copied().find(|&o| o != ITEM_NONE).unwrap_or(-1);
        (up, primary)
    }

    fn apply_primary_affinity(&self, pps: u32, pool: &PgPool, up: &mut [i32], primary: &mut i32) {
        if self.osd_primary_affinity.is_empty() {
            return;
        }
        if !up
            .iter()
            .any(|&o| o != ITEM_NONE && self.primary_affinity(o) != WEIGHT_IN)
        {
            return;
        }
        let mut pos: Option<usize> = None;
        let mut fallback: Option<usize> = None;
        for (i, &o) in up.iter().enumerate() {
            if o == ITEM_NONE {
                continue;
            }
            let a = self.primary_affinity(o);
            if a < WEIGHT_IN && (crush_hash32_2(pps, o as u32) >> 16) >= a {
                fallback.get_or_insert(i);
            } else {
                pos = Some(i);
                break;
            }
        }
        let Some(pos) = pos.or(fallback) else { return };
        *primary = up[pos];
        if pos > 0 && pool.can_shift_osds() {
            up[..=pos].rotate_right(1);
        }
    }

    /// Raw CRUSH result (after dropping non-existent osds) for an actual pg.
    pub fn pg_to_raw_osds<M: CrushMapper + ?Sized>(&self, mapper: &M, pg: PgT) -> Vec<i32> {
        let Some(pool) = self.pools.get(&(pg.pool as i64)) else {
            return Vec::new();
        };
        let mut raw = Vec::with_capacity(pool.size as usize);
        let pps = pool.raw_pg_to_pps(pg);
        mapper.do_rule(
            pool.crush_rule as i32,
            pps,
            pool.size as usize,
            &self.osd_weight,
            pg.pool as i64,
            &mut raw,
        );
        self.remove_nonexistent(pool, &mut raw);
        raw
    }

    /// Full pipeline using the map's own decoded CRUSH map (empty mapping if it has none).
    pub fn pg_to_up_acting(&self, pg: PgT) -> PgMapping {
        match self.crush_state() {
            Some(c) => self.pg_to_up_acting_with(&**c, pg),
            None => PgMapping::empty(),
        }
    }

    /// Full pipeline (spec 4.3-4.6) for an *actual* pg (ps < pg_num), custom mapper.
    pub fn pg_to_up_acting_with<M: CrushMapper + ?Sized>(&self, mapper: &M, pg: PgT) -> PgMapping {
        let Some(pool) = self.pools.get(&(pg.pool as i64)) else {
            return PgMapping::empty();
        };
        if pg.seed >= pool.pg_num {
            return PgMapping::empty();
        }
        // temp (acting override)
        let mut temp: Vec<i32> = Vec::new();
        if !self.pg_temp.is_empty()
            && let Some(t) = self.pg_temp.get(&pg)
        {
            temp.reserve(t.len());
            for &o in t {
                if !self.exists(o) || !self.is_up(o) {
                    if !pool.can_shift_osds() {
                        temp.push(ITEM_NONE);
                    }
                } else {
                    temp.push(o);
                }
            }
        }
        let from_temp = || temp.iter().copied().find(|&o| o != ITEM_NONE).unwrap_or(-1);
        let temp_primary = if self.primary_temp.is_empty() {
            from_temp()
        } else {
            self.primary_temp
                .get(&pg)
                .copied()
                .unwrap_or_else(from_temp)
        };
        let had_temp = !temp.is_empty();

        let pps = pool.raw_pg_to_pps(pg);
        let mut raw = self.pg_to_raw_osds(mapper, pg);
        self.apply_upmap(pg, &mut raw);
        let (mut up, mut up_primary) = self.raw_to_up(pool, &raw);
        self.apply_primary_affinity(pps, pool, &mut up, &mut up_primary);

        if had_temp {
            let acting = self.undo_ec_opt_order(pool, temp);
            return PgMapping {
                up,
                up_primary,
                acting,
                acting_primary: temp_primary,
            };
        }
        let acting_primary = if temp_primary != -1 {
            temp_primary
        } else {
            up_primary
        };
        PgMapping {
            acting: up.clone(),
            up,
            up_primary,
            acting_primary,
        }
    }

    fn undo_ec_opt_order(&self, pool: &PgPool, temp: Vec<i32>) -> Vec<i32> {
        let size = pool.size as usize;
        if !pool.has_flag(flags::EC_OPTIMIZATIONS) || temp.len() != size {
            return temp;
        }
        let np = pool.nonprimary_shards.count();
        if np > size {
            return temp;
        }
        let (mut head, mut tail) = (0, size - np);
        let mut out = Vec::with_capacity(size);
        for s in 0..size {
            if pool.nonprimary_shards.contains(s) {
                out.push(temp[tail]);
                tail += 1;
            } else {
                out.push(temp[head]);
                head += 1;
            }
        }
        out
    }
}

/// Test doubles for [`CrushMapper`].
pub mod testing {
    use super::*;

    /// Always returns a fixed list (truncated to `result_max`).
    #[derive(Debug, Clone)]
    pub struct FixedMapper(pub Vec<i32>);
    impl CrushMapper for FixedMapper {
        fn do_rule(&self, _r: i32, _x: u32, max: usize, _w: &[u32], _c: i64, out: &mut Vec<i32>) {
            out.clear();
            out.extend(self.0.iter().copied().take(max));
        }
    }

    /// Deterministic pseudo-placement: ranks osds 0..n with weight != 0 by
    /// `crush_hash32_2(x, osd)` and takes the best `result_max`.
    #[derive(Debug, Clone)]
    pub struct HashMapper {
        pub rule_exists: bool,
    }
    impl CrushMapper for HashMapper {
        fn do_rule(&self, _r: i32, x: u32, max: usize, w: &[u32], _c: i64, out: &mut Vec<i32>) {
            out.clear();
            if !self.rule_exists {
                return;
            }
            let mut c: Vec<(u32, i32)> = (0..w.len() as i32)
                .filter(|&o| w[o as usize] != 0)
                .map(|o| (crush_hash32_2(x, o as u32), o))
                .collect();
            c.sort();
            out.extend(c.into_iter().take(max).map(|(_, o)| o));
        }
    }
}
