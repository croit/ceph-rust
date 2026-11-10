// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Balanced PG placement over the cores of a multi-core OSD (adr 0639, on adr 0031).
//!
//! The control core decides, per map update and before the map is applied, where the PGs go that map to this OSD for
//! the first time: [`Mine`] is the set of PGs of the served pools that map to the OSD (kept from map to map, only what
//! a map changed is mapped again), [`arrivals`] places the PGs that are in the new set but not in the old one on the
//! least loaded core (instances of the PG's pool first, then all instances), on top of every PG that stays where it
//! is. A PG never moves for balance once it is here: only arriving PGs are placed (no data moves, no interval
//! without a map change).

use denc::types::PgT;
use osdmap::OsdMap;
use osdmap::consts::osd_state;
use osdmap::pool::{PgPool, flags};
use std::collections::{BTreeMap, BTreeSet};

/// PGs of the served pools that map to one OSD in one map (up or acting), each with the number of positions the OSD
/// holds in it (instances: 1 for a replicated pool, the shards it holds for an erasure pool).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mine {
    pub epoch: u32,
    /// The served pools the PGs were collected from.
    pub pools: BTreeSet<u64>,
    pub pgs: BTreeMap<PgT, u8>,
}

impl Mine {
    /// Every PG of every pool in `pools` through CRUSH.
    pub fn scan(map: &OsdMap, me: i32, pools: BTreeSet<u64>) -> Mine {
        let mut pgs = BTreeMap::new();
        for &pool in &pools {
            scan_pool(map, me, pool, &mut pgs);
        }
        Mine {
            epoch: map.epoch,
            pools,
            pgs,
        }
    }

    /// The set of `new` from this one (of `old`; any other epoch = full scan). Only what the map changed is mapped
    /// again: everything when CRUSH, the OSD weights, which OSDs exist or this OSD's up state changed; a pool whose
    /// placement inputs or served state changed; the PGs whose pg_temp / pg_upmap / pg_upmap_items entry changed.
    /// Primary choice (affinity, primary_temp, pg_upmap_primaries) and other OSDs' up states do not change
    /// membership.
    pub fn next(&self, old: &OsdMap, new: &OsdMap, me: i32, pools: BTreeSet<u64>) -> Mine {
        if self.epoch != old.epoch || !same_osds(old, new, me) {
            return Mine::scan(new, me, pools);
        }
        let mut pgs = self.pgs.clone();
        let mut redone = BTreeSet::new();
        for &pool in self.pools.union(&pools) {
            let id = pool as i64;
            if self.pools.contains(&pool)
                && pools.contains(&pool)
                && same_shape(old.pools.get(&id), new.pools.get(&id))
            {
                continue;
            }
            pgs.retain(|pg, _| pg.pool != pool);
            if pools.contains(&pool) {
                scan_pool(new, me, pool, &mut pgs);
            }
            redone.insert(pool);
        }
        let mut touched = BTreeSet::new();
        changed(&old.pg_temp, &new.pg_temp, &mut touched);
        changed(&old.pg_upmap, &new.pg_upmap, &mut touched);
        changed(&old.pg_upmap_items, &new.pg_upmap_items, &mut touched);
        for pg in touched {
            if pools.contains(&pg.pool) && !redone.contains(&pg.pool) {
                pgs.remove(&pg);
                map_one(new, me, pg, &mut pgs);
            }
        }
        Mine {
            epoch: new.epoch,
            pools,
            pgs,
        }
    }
}

/// A down OSD is in no up or acting set (pg_temp drops down OSDs too): no CRUSH work for it.
fn scan_pool(map: &OsdMap, me: i32, pool: u64, out: &mut BTreeMap<PgT, u8>) {
    let Some(p) = map.pools.get(&(pool as i64)).filter(|_| map.is_up(me)) else {
        return;
    };
    for seed in 0..p.pg_num {
        map_one(map, me, PgT::new(pool, seed), out);
    }
}

fn map_one(map: &OsdMap, me: i32, pg: PgT, out: &mut BTreeMap<PgT, u8>) {
    let m = map.pg_to_up_acting(pg);
    let n = |v: &[i32]| v.iter().filter(|o| **o == me).count();
    let w = n(&m.up).max(n(&m.acting));
    if w > 0 {
        out.insert(pg, u8::try_from(w).unwrap_or(u8::MAX));
    }
}

/// CRUSH and the OSD inputs of this OSD's memberships are the same in both maps. Another OSD going down or up does
/// not change them: CRUSH does not look at up states, a down OSD only leaves the up / acting sets (and a pg_temp
/// with this OSD in it keeps it while it is up); this OSD's own up state does.
fn same_osds(a: &OsdMap, b: &OsdMap, me: i32) -> bool {
    let same = osd_state::EXISTS;
    a.max_osd == b.max_osd
        && a.is_up(me) == b.is_up(me)
        && a.osd_weight == b.osd_weight
        && a.crush_blob() == b.crush_blob()
        && a.osd_state.len() == b.osd_state.len()
        && a.osd_state
            .iter()
            .zip(&b.osd_state)
            .all(|(x, y)| x & same == y & same)
}

/// The pool fields its PG mappings depend on are the same.
fn same_shape(a: Option<&PgPool>, b: Option<&PgPool>) -> bool {
    let shape = |p: &PgPool| {
        (
            p.pg_num,
            p.pgp_num,
            p.size,
            p.crush_rule,
            p.ptype,
            p.has_flag(flags::HASHPSPOOL),
        )
    };
    matches!((a, b), (Some(a), Some(b)) if shape(a) == shape(b))
}

/// Keys whose entry differs between `a` and `b` (added, removed or changed).
fn changed<V: PartialEq>(a: &BTreeMap<PgT, V>, b: &BTreeMap<PgT, V>, out: &mut BTreeSet<PgT>) {
    if a == b {
        return;
    }
    out.extend(
        a.iter()
            .filter(|(k, v)| b.get(k) != Some(v))
            .map(|(k, _)| *k),
    );
    out.extend(b.keys().filter(|k| !a.contains_key(k)));
}

/// `pg_num` the pool is heading to (`pg_num_pending` when a merge is announced).
pub fn pool_lo(p: &PgPool) -> u32 {
    if p.pg_num_pending == 0 {
        p.pg_num
    } else {
        p.pg_num.min(p.pg_num_pending)
    }
}

/// PG instances per store shard of one OSD, per pool and in total. Core `c` owns the shards `s % cores == c` (adr
/// 0031), so a core's load is the sum over its shards.
#[derive(Debug, Clone)]
pub struct Balance {
    cores: usize,
    shards: u32,
    pool: BTreeMap<u64, Vec<u32>>,
    total: Vec<u32>,
}

impl Balance {
    pub fn new(cores: usize, shards: u32) -> Balance {
        Balance {
            cores: cores.max(1),
            shards: shards.max(1),
            pool: BTreeMap::new(),
            total: vec![0; shards.max(1) as usize],
        }
    }

    /// `w` instances of a PG of `pool` on store shard `shard`.
    pub fn add(&mut self, pool: u64, shard: u32, w: u32) {
        let s = (shard % self.shards) as usize;
        let n = self.shards as usize;
        self.pool.entry(pool).or_insert_with(|| vec![0; n])[s] += w;
        self.total[s] += w;
    }

    /// `(instances of pool, all instances)` on core `core`.
    fn load(&self, pool: u64, core: usize) -> (u32, u32) {
        let p = self.pool.get(&pool);
        (0..self.shards as usize)
            .filter(|s| s % self.cores == core)
            .fold((0, 0), |(a, b), s| {
                (a + p.map_or(0, |v| v[s]), b + self.total[s])
            })
    }

    /// The core for one more PG of `pool`: fewest instances of the pool, then fewest in total, then the lowest index
    /// (deterministic).
    pub fn core(&self, pool: u64) -> usize {
        (0..self.cores.min(self.shards as usize))
            .min_by_key(|&c| (self.load(pool, c), c))
            .unwrap_or(0)
    }

    /// The store shard of core `core` for one more PG of `pool` (same order as [`Self::core`]).
    pub fn shard(&self, pool: u64, core: usize) -> u32 {
        let p = self.pool.get(&pool);
        (0..self.shards as usize)
            .filter(|s| s % self.cores == core)
            .min_by_key(|&s| (p.map_or(0, |v| v[s]), self.total[s], s))
            .unwrap_or(core) as u32
    }

    /// Instances per core: of `pool`, or of all pools (`None`).
    pub fn per_core(&self, pool: Option<u64>) -> Vec<u32> {
        let per_shard = match pool {
            Some(p) => self.pool.get(&p).map_or(&[][..], Vec::as_slice),
            None => &self.total,
        };
        let mut v = vec![0; self.cores];
        for (s, n) in per_shard.iter().enumerate() {
            v[s % self.cores] += n;
        }
        v
    }
}

/// An arriving PG goes to store shard `shard` (core `shard % cores`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Place {
    pub pgid: PgT,
    pub shard: u32,
}

/// Placement of the PGs that map to this OSD in `next` (map `new`) but not in `prev` (map `old`), balanced over the
/// cores on top of every PG that stays (counted where `shard_of` routes it now). Only PGs whose core changes are
/// returned. Not placed here: a split child of this update (it lives on its parent's shard, zero-copy split, and
/// `shard_of` already routes it there) and the PGs of a pool that merges (merge sources follow their targets, adr
/// 0031 am. 5). Returns the decisions and the load after them.
pub fn arrivals(
    prev: &Mine,
    next: &Mine,
    old: &OsdMap,
    new: &OsdMap,
    cores: usize,
    shards: u32,
    shard_of: impl Fn(PgT) -> u32,
) -> (Vec<Place>, Balance) {
    let mut bal = Balance::new(cores, shards);
    let keep = |pg: &PgT| {
        let id = pg.pool as i64;
        let Some(np) = new.pools.get(&id) else {
            return true;
        };
        let was = old.pools.get(&id).map_or(np.pg_num, |op| op.pg_num);
        prev.pgs.contains_key(pg) || pg.seed >= was || pool_lo(np) < was.max(np.pg_num)
    };
    let mut arriving = Vec::new();
    for (pg, w) in &next.pgs {
        if keep(pg) {
            bal.add(pg.pool, shard_of(*pg), u32::from(*w));
        } else {
            arriving.push((*pg, u32::from(*w)));
        }
    }
    let mut out = Vec::new();
    for (pg, w) in arriving {
        let cur = shard_of(pg);
        let core = bal.core(pg.pool);
        let shard = if core == cur as usize % bal.cores {
            cur
        } else {
            let s = bal.shard(pg.pool, core);
            out.push(Place { pgid: pg, shard: s });
            s
        };
        bal.add(pg.pool, shard, w);
    }
    (out, bal)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic pseudo-CRUSH: `size` distinct OSDs of `osds` for each PG.
    fn members(pool: u64, seed: u32, osds: u32, size: u32) -> Vec<u32> {
        let mut v = Vec::new();
        let mut x = (pool << 32 | u64::from(seed)).wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        while v.len() < size as usize {
            x ^= x >> 33;
            x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
            x ^= x >> 29;
            let o = (x % u64::from(osds)) as u32;
            if !v.contains(&o) {
                v.push(o);
            }
        }
        v
    }

    fn mine_of(osd: u32, osds: u32, pools: &[(u64, u32, u32)]) -> Mine {
        let mut pgs = BTreeMap::new();
        for &(pool, pg_num, size) in pools {
            for seed in 0..pg_num {
                if members(pool, seed, osds, size).contains(&osd) {
                    pgs.insert(PgT::new(pool, seed), 1);
                }
            }
        }
        Mine {
            epoch: 2,
            pools: pools.iter().map(|p| p.0).collect(),
            pgs,
        }
    }

    fn map_with(pools: &[(u64, u32, u32)], epoch: u32) -> OsdMap {
        let mut m = OsdMap::default();
        m.epoch = epoch;
        for &(id, pg_num, size) in pools {
            let p = PgPool {
                pg_num,
                pgp_num: pg_num,
                size: size as u8,
                ..PgPool::default()
            };
            m.pools.insert(id as i64, p);
        }
        m
    }

    fn spread(v: &[u32]) -> (u32, u32, f64) {
        let (lo, hi) = (*v.iter().min().unwrap(), *v.iter().max().unwrap());
        let mean = f64::from(v.iter().sum::<u32>()) / v.len() as f64;
        (lo, hi, f64::from(hi) / mean)
    }

    /// The brief's bound: 30 OSDs, 3 pools of 1024..4096 PGs, 6..8 cores, every PG arriving with the pool's creation:
    /// per pool and in total no core holds more than one PG above the least loaded one (hash: up to 1.6x the mean).
    #[test]
    fn arrivals_of_new_pools_are_balanced_per_pool_and_in_total() {
        for pg_num in [1024, 2048, 4096] {
            let pools = [(64, pg_num, 3), (65, pg_num / 2, 3), (66, pg_num / 4, 3)];
            for cores in [6usize, 7, 8] {
                for osd in 0..30 {
                    let next = mine_of(osd, 30, &pools);
                    let prev = Mine {
                        epoch: 1,
                        ..Mine::default()
                    };
                    let (old, new) = (map_with(&[], 1), map_with(&pools, 2));
                    let hash = |pg: PgT| ((pg.pool + u64::from(pg.seed)) % cores as u64) as u32;
                    let (_, bal) = arrivals(&prev, &next, &old, &new, cores, cores as u32, hash);
                    for pool in [Some(64), Some(65), Some(66), None] {
                        let (lo, hi, _) = spread(&bal.per_core(pool));
                        assert!(
                            hi - lo <= 1,
                            "osd {osd} cores {cores} pg_num {pg_num} pool {pool:?}: {lo}..{hi}"
                        );
                    }
                }
            }
        }
    }

    /// The hash placement the balance replaces is far off on the same input (the motivation, adr 0639).
    #[test]
    fn hash_placement_of_the_same_pgs_is_unbalanced() {
        let pools = [(64, 1024, 3), (65, 512, 3), (66, 256, 3)];
        let mut worst: f64 = 0.0;
        for osd in 0..30 {
            let next = mine_of(osd, 30, &pools);
            let mut per = vec![0u32; 6];
            for pg in next.pgs.keys().filter(|p| p.pool == 64) {
                per[((pg.pool + u64::from(pg.seed)) % 6) as usize] += 1;
            }
            worst = worst.max(spread(&per).2);
        }
        assert!(worst > 1.3, "hash worst {worst}");
    }

    /// PGs that stay are counted where they are; arrivals fill the least loaded cores first.
    #[test]
    fn arrivals_fill_the_cores_that_lost_pgs() {
        let pools = [(1, 64, 3)];
        let (old, new) = (map_with(&pools, 1), map_with(&pools, 2));
        // 4 cores: PGs 0..12 stay, all on core 0; 12..20 arrive
        let prev = Mine {
            epoch: 1,
            pools: [1].into(),
            pgs: (0..12).map(|s| (PgT::new(1, s), 1)).collect(),
        };
        let mut next = prev.clone();
        next.epoch = 2;
        next.pgs.extend((12..20).map(|s| (PgT::new(1, s), 1)));
        let at = |pg: PgT| if pg.seed < 12 { 0 } else { pg.seed % 4 };
        let (places, bal) = arrivals(&prev, &next, &old, &new, 4, 4, at);
        assert_eq!(bal.per_core(Some(1)), vec![12, 3, 3, 2]);
        assert_eq!(places.len(), 8);
        assert!(places.iter().all(|p| p.shard != 0 && p.shard != at(p.pgid)));
        // an arrival already routed to the least loaded core stays there (nothing to do)
        let mut one = prev.clone();
        one.pgs.insert(PgT::new(1, 13), 1);
        let (places, bal) = arrivals(&prev, &one, &old, &new, 4, 4, at);
        assert!(places.is_empty());
        assert_eq!(bal.per_core(None), vec![12, 1, 0, 0]);
    }

    /// Split children of this update and the PGs of a merging pool are not placed (they follow their parents /
    /// targets), but they count.
    #[test]
    fn split_children_and_merging_pools_are_left_alone() {
        let old = map_with(&[(1, 8, 3), (2, 16, 3)], 1);
        let mut new = map_with(&[(1, 16, 3), (2, 16, 3)], 2);
        new.pools.get_mut(&2).unwrap().pg_num_pending = 8;
        let prev = Mine {
            epoch: 1,
            pools: [1, 2].into(),
            pgs: [(PgT::new(1, 0), 1)].into(),
        };
        let mut next = prev.clone();
        next.epoch = 2;
        next.pgs.extend([
            (PgT::new(1, 8), 1),
            (PgT::new(1, 5), 1),
            (PgT::new(2, 3), 1),
            (PgT::new(2, 12), 1),
        ]);
        let (places, bal) = arrivals(&prev, &next, &old, &new, 4, 4, |_| 0);
        assert_eq!(
            places,
            vec![Place {
                pgid: PgT::new(1, 5),
                shard: 1
            }]
        );
        assert_eq!(bal.per_core(None), vec![4, 1, 0, 0]);
    }

    /// More shards than cores: the core is chosen first, then its least loaded shard; fewer shards owned by a core
    /// count the same.
    #[test]
    fn shards_of_the_chosen_core_are_filled_evenly() {
        let mut b = Balance::new(4, 6);
        // core 0 owns shards 0 and 4, core 1 owns 1 and 5
        b.add(7, 0, 1);
        assert_eq!(b.core(7), 1);
        b.add(7, 1, 1);
        b.add(7, 2, 1);
        b.add(7, 3, 1);
        assert_eq!(b.core(7), 0);
        assert_eq!(b.shard(7, 0), 4);
        b.add(7, 4, 1);
        assert_eq!(b.core(7), 1);
        assert_eq!(b.shard(7, 1), 5);
        assert_eq!(b.per_core(Some(7)), vec![2, 1, 1, 1]);
    }

    fn real() -> OsdMap {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../testdata/osdmap/full/0091.bin");
        OsdMap::decode_from(&std::fs::read(p).unwrap()).unwrap()
    }

    fn pools_of(m: &OsdMap) -> BTreeSet<u64> {
        m.pools.keys().map(|id| *id as u64).collect()
    }

    /// The incremental set equals a full scan of the new map for every kind of change, and maps only what changed.
    #[test]
    fn next_matches_a_full_scan() {
        let old = real();
        let me = 2;
        let prev = Mine::scan(&old, me, pools_of(&old));
        assert!(!prev.pgs.is_empty());
        let first = *prev.pgs.keys().next().unwrap();
        let pool = first.pool as i64;
        let others: Vec<i32> = (0..old.max_osd).filter(|o| *o != me).collect();
        let check = |what: &str, f: &dyn Fn(&mut OsdMap), pools: Option<BTreeSet<u64>>| {
            let mut new = old.clone();
            new.epoch += 1;
            f(&mut new);
            let pools = pools.unwrap_or_else(|| pools_of(&new));
            let got = prev.next(&old, &new, me, pools.clone());
            assert_eq!(got, Mine::scan(&new, me, pools), "{what}");
            got
        };
        // pg_temp alone keeps the PG (up still holds this OSD); with an upmap without this OSD it leaves
        let got = check(
            "pg_temp",
            &|m| {
                m.pg_temp.insert(first, others.clone());
            },
            None,
        );
        assert!(got.pgs.contains_key(&first));
        let got = check(
            "upmap and pg_temp",
            &|m| {
                m.pg_temp.insert(first, others.clone());
                m.pg_upmap.insert(first, others.clone());
            },
            None,
        );
        assert!(!got.pgs.contains_key(&first));
        check(
            "upmap items",
            &|m| {
                m.pg_upmap_items.insert(first, vec![(me, others[0])]);
            },
            None,
        );
        check(
            "primary only",
            &|m| {
                m.primary_temp.insert(first, others[0]);
            },
            None,
        );
        check(
            "split",
            &|m| {
                let p = m.pools.get_mut(&pool).unwrap();
                p.pg_num *= 2;
                p.pgp_num *= 2;
            },
            None,
        );
        check(
            "pool gone",
            &|m| {
                m.pools.remove(&pool);
            },
            None,
        );
        check(
            "not served",
            &|_| {},
            Some(
                pools_of(&old)
                    .into_iter()
                    .filter(|p| *p != first.pool)
                    .collect(),
            ),
        );
        check(
            "other osd down",
            &|m| m.osd_state[others[0] as usize] &= !osd_state::UP,
            None,
        );
        check(
            "this osd down",
            &|m| m.osd_state[me as usize] &= !osd_state::UP,
            None,
        );
        check(
            "other osd down, pg_temp",
            &|m| {
                m.pg_temp.insert(first, vec![others[0]]);
                m.osd_state[others[0] as usize] &= !osd_state::UP;
            },
            None,
        );
        check("osd gone", &|m| m.osd_state[others[1] as usize] = 0, None);
        check("weight", &|m| m.osd_weight[me as usize] = 0, None);
        // another epoch than the one the set is of: full scan
        let mut stale = prev.clone();
        stale.epoch -= 1;
        let mut new = old.clone();
        new.epoch += 1;
        new.pg_temp.insert(first, others.clone());
        assert_eq!(
            stale.next(&old, &new, me, pools_of(&new)),
            Mine::scan(&new, me, pools_of(&new))
        );
    }

    /// EC instances weigh by the positions the OSD holds.
    #[test]
    fn instances_weigh_by_positions() {
        let mut b = Balance::new(2, 2);
        b.add(3, 0, 2);
        assert_eq!(b.core(3), 1);
        b.add(3, 1, 1);
        assert_eq!(b.core(3), 1);
        assert_eq!(b.per_core(None), vec![2, 1]);
    }
}
