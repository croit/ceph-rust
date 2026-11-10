// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
//! Dedup info listing, client side without I/O (croit fork `wip-ifed-dedup` `IoCtx::dedup_candidate_list*`,
//! doc/spec/dedup-client.md 1-3; adr 0593-dedup-deep-scrub-reformat). A [`DedupCursor`] walks one digest shard of a pool
//! over every up OSD serving the listing; each call asks some of those OSDs for their next records ([`DedupListArgs`],
//! sent as MOSDDedupList by the runtime) and [`DedupCursor::apply`] turns a reply into a [`DedupItemBatch`] and advances
//! that OSD's position. Batches of one OSD are sorted by digest and continue each other.

pub use messages::DedupListResult;
use messages::FEATUREMASK_OSD_DEDUP_LIST;
use osdmap::OsdMap;

/// Listing failures; [`DedupError::errno`] gives librados' negative errno.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DedupError {
    /// Invalid argument (osd, max, shard, shard count, target not in the cursor).
    Invalid,
    /// The pool is not in the client's map.
    NoPool,
    /// The OSD does not advertise the listing.
    NotSupported,
    /// The OSD does not exist in the latest map.
    NoOsd,
    /// The OSD is down in the latest map.
    OsdDown,
    /// `rados_osd_op_timeout` expired.
    Deadline,
    /// The OSD answered with this negative errno.
    Osd(i32),
    /// The reply did not decode.
    Protocol,
    /// The client is not ready, closed or out of request slots.
    Client,
    Cancelled,
}

impl DedupError {
    pub fn errno(self) -> i32 {
        match self {
            DedupError::Invalid => -22,
            DedupError::NoPool | DedupError::NoOsd => -2,
            DedupError::NotSupported => -95,
            DedupError::OsdDown => -6,
            DedupError::Deadline => -110,
            DedupError::Osd(r) => r,
            DedupError::Protocol => -74,
            DedupError::Client => -107,
            DedupError::Cancelled => -125,
        }
    }
}

/// One record: raw digest, raw object hash, creation time (recording OSD's wall clock, ns since the epoch), age in seconds
/// at the OSD's reply time, source OSD.
#[derive(Clone, Debug, PartialEq)]
pub struct DedupItem {
    pub digest: Vec<u8>,
    pub hash: u32,
    pub timestamp: u64,
    pub age: f64,
    pub osd: i32,
}

/// One OSD's records of one call; `completed` = that OSD has no more records of the shard.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DedupItemBatch {
    pub osd: i32,
    pub completed: bool,
    pub items: Vec<DedupItem>,
}

/// One MOSDDedupList request to one OSD.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DedupListArgs {
    pub osd: i32,
    pub pool: i64,
    pub shard: u64,
    pub shard_bits: u8,
    pub after: Vec<u8>,
    pub max: u32,
    pub newer_than: u32,
    pub prune_older_than: u32,
}

/// The OSD advertises the listing in its map features.
pub fn osd_serves_dedup_list(map: &OsdMap, osd: i32) -> bool {
    map.osd_xinfo
        .get(osd as usize)
        .is_some_and(|x| x.features & FEATUREMASK_OSD_DEDUP_LIST == FEATUREMASK_OSD_DEDUP_LIST)
}

impl DedupListArgs {
    /// Checks before anything is sent (spec 1.1, in this order). A missing OSD is not an error here: the runtime confirms
    /// it with the latest map.
    pub fn check(&self, map: &OsdMap) -> Result<(), DedupError> {
        if self.osd < 0 || self.max < 1 {
            return Err(DedupError::Invalid);
        }
        if self.shard_bits > 32 || self.shard >= 1u64 << self.shard_bits {
            return Err(DedupError::Invalid);
        }
        if map.pool(self.pool).is_none() {
            return Err(DedupError::NoPool);
        }
        if map.exists(self.osd) && !osd_serves_dedup_list(map, self.osd) {
            return Err(DedupError::NotSupported);
        }
        Ok(())
    }

    /// The request message at map `epoch` of cluster `fsid`.
    pub fn message(&self, fsid: denc::types::Uuid, epoch: u32) -> messages::MOSDDedupList {
        messages::MOSDDedupList {
            fsid,
            epoch,
            pool: self.pool,
            shard: self.shard,
            shard_bits: self.shard_bits,
            after: self.after.clone(),
            max: self.max,
            newer_than: self.newer_than,
            prune_older_than: self.prune_older_than,
        }
    }
}

/// The records of a reply of `osd`: hash back from the wire's bitwise-key form, age from the OSD's reply time.
pub fn items_of(osd: i32, r: &DedupListResult) -> Vec<DedupItem> {
    r.entries
        .iter()
        .map(|e| DedupItem {
            digest: e.digest.clone(),
            hash: e.oid_hash.reverse_bits(),
            timestamp: e.timestamp,
            age: if r.now > e.timestamp {
                (r.now - e.timestamp) as f64 / 1e9
            } else {
                0.0
            },
            osd,
        })
        .collect()
}

/// Position of a listing of digest shard `shard` of `2^shard_bits` over a fixed, ascending OSD set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DedupCursor {
    pool: i64,
    shard: u64,
    shard_bits: u8,
    osds: Vec<i32>,
    positions: Vec<Vec<u8>>,
    completed: Vec<bool>,
    num_completed: usize,
    next_target: usize,
}

impl DedupCursor {
    /// `dedup_candidate_list_slice(n, m)`: shard `n` of `m` (a power of two up to 2^32) of `pool`, over every up OSD of
    /// `map` serving the listing.
    pub fn slice(map: &OsdMap, pool: i64, n: u64, m: u64) -> Result<DedupCursor, DedupError> {
        if !m.is_power_of_two() || m > 1u64 << 32 || n >= m {
            return Err(DedupError::Invalid);
        }
        if map.pool(pool).is_none() {
            return Err(DedupError::NoPool);
        }
        let osds: Vec<i32> = (0..map.max_osd)
            .filter(|&o| map.exists(o) && map.is_up(o) && osd_serves_dedup_list(map, o))
            .collect();
        Ok(DedupCursor {
            pool,
            shard: n,
            shard_bits: m.trailing_zeros() as u8,
            positions: vec![Vec::new(); osds.len()],
            completed: vec![false; osds.len()],
            num_completed: 0,
            next_target: 0,
            osds,
        })
    }

    pub fn is_end(&self) -> bool {
        self.num_completed == self.osds.len()
    }
    pub fn shard(&self) -> u64 {
        self.shard
    }
    pub fn shard_count(&self) -> u64 {
        1 << self.shard_bits
    }
    pub fn osds(&self) -> &[i32] {
        &self.osds
    }

    /// Up to `max_targets` incomplete OSDs, round robin from where the last call stopped (spec 3.3).
    pub fn round_robin(&mut self, max_targets: usize) -> Result<Vec<i32>, DedupError> {
        if max_targets == 0 {
            return Err(DedupError::Invalid);
        }
        let n = self.osds.len();
        let mut out = Vec::new();
        if self.is_end() {
            return Ok(out);
        }
        let start = self.next_target % n;
        let mut scanned = 0;
        while scanned < n && out.len() < max_targets {
            let i = (start + scanned) % n;
            scanned += 1;
            if !self.completed[i] {
                out.push(self.osds[i]);
            }
        }
        self.next_target = (start + scanned) % n;
        Ok(out)
    }

    /// The requests of one explicit-target call (spec 3.2 steps 1-2): every target must be in the cursor; completed ones
    /// and duplicates are dropped.
    pub fn requests(
        &self,
        targets: &[i32],
        per_target_max: u64,
        newer_than: u32,
        prune_older_than: u32,
    ) -> Result<Vec<DedupListArgs>, DedupError> {
        if per_target_max == 0 || per_target_max > u64::from(u32::MAX) {
            return Err(DedupError::Invalid);
        }
        let mut idx = Vec::with_capacity(targets.len());
        for &o in targets {
            idx.push(
                self.osds
                    .binary_search(&o)
                    .map_err(|_| DedupError::Invalid)?,
            );
        }
        let mut seen = Vec::with_capacity(idx.len());
        Ok(idx
            .into_iter()
            .filter(|&i| {
                !self.completed[i] && !seen.contains(&i) && {
                    seen.push(i);
                    true
                }
            })
            .map(|i| DedupListArgs {
                osd: self.osds[i],
                pool: self.pool,
                shard: self.shard,
                shard_bits: self.shard_bits,
                after: self.positions[i].clone(),
                max: per_target_max as u32,
                newer_than,
                prune_older_than,
            })
            .collect())
    }

    /// A successful reply of `osd`: its batch; the OSD's position moves to the reply's cursor. A reply of an OSD that
    /// is not a target of this cursor is rejected, never applied.
    pub fn apply(&mut self, osd: i32, r: &DedupListResult) -> Result<DedupItemBatch, DedupError> {
        let i = self
            .osds
            .binary_search(&osd)
            .map_err(|_| DedupError::Invalid)?;
        self.positions[i] = r.next.clone();
        if r.completed && !self.completed[i] {
            self.completed[i] = true;
            self.num_completed += 1;
        }
        Ok(DedupItemBatch {
            osd,
            completed: r.completed,
            items: items_of(osd, r),
        })
    }
}

impl std::fmt::Display for DedupCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "dedup_cursor(shard {}/{}, osds {}/{} done)",
            self.shard,
            self.shard_count(),
            self.num_completed,
            self.osds.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use messages::DedupListEntry;
    use osdmap::consts::osd_state::{EXISTS, UP};

    fn map() -> OsdMap {
        let mut m = OsdMap::default();
        m.max_osd = 5;
        m.osd_state = vec![EXISTS | UP; 5];
        m.osd_state[3] = EXISTS; // down
        m.osd_xinfo = vec![Default::default(); 5];
        for o in [0, 1, 3, 4] {
            m.osd_xinfo[o].features = FEATUREMASK_OSD_DEDUP_LIST;
        }
        m.osd_xinfo[2].features = 1 << 51; // bit 51 alone: an older incarnation of the bit
        m.pools.insert(7, Default::default());
        m
    }

    #[test]
    fn slice_picks_up_serving_osds() {
        let m = map();
        let c = DedupCursor::slice(&m, 7, 3, 16).unwrap();
        assert_eq!(c.osds(), [0, 1, 4]);
        assert_eq!((c.shard(), c.shard_count(), c.is_end()), (3, 16, false));
        assert_eq!(c.to_string(), "dedup_cursor(shard 3/16, osds 0/3 done)");
        for (n, mm) in [(0, 3), (4, 4), (0, 0), (0, 1 << 33)] {
            assert_eq!(DedupCursor::slice(&m, 7, n, mm), Err(DedupError::Invalid));
        }
        assert!(DedupCursor::slice(&m, 7, 0, 1 << 32).is_ok());
        assert_eq!(DedupCursor::slice(&m, 8, 0, 1), Err(DedupError::NoPool));
        let mut empty = m.clone();
        empty.osd_xinfo.iter_mut().for_each(|x| x.features = 0);
        assert!(DedupCursor::slice(&empty, 7, 0, 1).unwrap().is_end());
    }

    #[test]
    fn argument_checks() {
        let m = map();
        let ok = DedupListArgs {
            osd: 1,
            pool: 7,
            shard: 15,
            shard_bits: 4,
            max: 1,
            ..Default::default()
        };
        assert_eq!(ok.check(&m), Ok(()));
        let bad = |f: fn(&mut DedupListArgs)| {
            let mut a = ok.clone();
            f(&mut a);
            a.check(&m)
        };
        assert_eq!(bad(|a| a.osd = -1), Err(DedupError::Invalid));
        assert_eq!(bad(|a| a.max = 0), Err(DedupError::Invalid));
        assert_eq!(bad(|a| a.shard = 16), Err(DedupError::Invalid));
        assert_eq!(bad(|a| a.shard_bits = 33), Err(DedupError::Invalid));
        assert_eq!(bad(|a| a.pool = 8), Err(DedupError::NoPool));
        assert_eq!(bad(|a| a.osd = 2), Err(DedupError::NotSupported));
        assert_eq!(
            bad(|a| a.osd = 9),
            Ok(()),
            "a missing osd: the runtime decides"
        );
        assert_eq!(bad(|a| a.osd = 3), Ok(()), "down: the runtime decides");
        assert_eq!(DedupError::OsdDown.errno(), -6);
    }

    fn reply(completed: bool, next: &[u8], entries: &[(u8, u32, u64)]) -> DedupListResult {
        DedupListResult {
            completed,
            next: next.to_vec(),
            now: 10_000_000_000,
            entries: entries
                .iter()
                .map(|&(d, h, t)| DedupListEntry {
                    digest: vec![d; 16],
                    timestamp: t,
                    oid_hash: h,
                })
                .collect(),
        }
    }

    #[test]
    fn round_robin_requests_and_apply() {
        let mut c = DedupCursor::slice(&map(), 7, 1, 2).unwrap();
        assert_eq!(c.round_robin(0), Err(DedupError::Invalid));
        assert_eq!(c.round_robin(2).unwrap(), [0, 1]);
        assert_eq!(c.round_robin(2).unwrap(), [4, 0]);
        let r = c.requests(&[4, 0, 4], 100, 5, 6).unwrap();
        assert_eq!(r.len(), 2, "duplicates dropped");
        assert_eq!(
            (r[0].osd, r[0].shard, r[0].shard_bits, r[0].max),
            (4, 1, 1, 100)
        );
        assert_eq!((r[1].newer_than, r[1].prune_older_than), (5, 6));
        assert_eq!(
            c.requests(&[2], 1, 0, 0),
            Err(DedupError::Invalid),
            "not in the cursor"
        );
        assert_eq!(c.requests(&[0], 0, 0, 0), Err(DedupError::Invalid));
        assert_eq!(c.requests(&[0], 1 << 32, 0, 0), Err(DedupError::Invalid));
        let b = c
            .apply(
                0,
                &reply(
                    false,
                    b"k1",
                    &[(1, 0x1234_5678, 4_000_000_000), (2, 1, 20_000_000_000)],
                ),
            )
            .unwrap();
        assert_eq!(
            b.items[0].hash, 0x1E6A_2C48,
            "the wire hash is bit-reversed"
        );
        assert_eq!(c.apply(2, &reply(true, b"", &[])), Err(DedupError::Invalid));
        assert_eq!(c.apply(9, &reply(true, b"", &[])), Err(DedupError::Invalid));
        assert_eq!(
            c.requests(&[0], 9, 0, 0).unwrap()[0].after,
            b"k1",
            "a foreign reply moves no position"
        );
        assert_eq!((b.items[0].age, b.items[1].age), (6.0, 0.0));
        c.apply(0, &reply(true, b"k2", &[])).unwrap();
        c.apply(0, &reply(true, b"k2", &[])).unwrap();
        assert_eq!(c.to_string(), "dedup_cursor(shard 1/2, osds 1/3 done)");
        assert!(
            c.requests(&[0], 9, 0, 0).unwrap().is_empty(),
            "completed: dropped"
        );
        assert_eq!(c.round_robin(5).unwrap(), [1, 4]);
        c.apply(1, &reply(true, b"", &[])).unwrap();
        c.apply(4, &reply(true, b"", &[])).unwrap();
        assert!(c.is_end());
        assert!(c.round_robin(5).unwrap().is_empty());
    }
}
