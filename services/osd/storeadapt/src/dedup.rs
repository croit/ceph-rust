// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
//! Dedup info collection (adr 0593-dedup-deep-scrub-reformat, doc/spec/dedup-collection.md): the `collect_csum` engine
//! digests every object the PG primary deep-scrubs, while the scrub reads it, and records the digest in the store
//! (`store::obj::dedup`). The digest runs in the object's scrub session (its reads come in order, from offset 0, one
//! object at a time), so it is never built from two data states; it is recorded only if the object's data state at the
//! end equals the one taken before its first byte was read. Records are hints written without waiting: a busy shard
//! drops one, the next deep scrub makes it again. Listing, stats and clear serve the admin commands and the OSD listing
//! request per core; the OSD merges the cores ([`peering::store::merge_dedup_parts`]).

use crate::{StoreAdapter, key_after};
use denc::types::{CollT, Ghobject, Hobject, ShardId};
use md5::Digest;
use peering::store::{DedupEntry, DedupListPart, DedupListReq};
use std::cell::Cell;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use store::dev::{BlockDev, Clock};
use store::obj::dedup::{self, DigestAlg, RecordValue};
use store::obj::{DataVersion, OTxn, ObjError, Store, TOp};

#[derive(Clone)]
enum Digester {
    Md5(md5::Md5),
    Sha256(sha2::Sha256),
}

/// Incremental content digest of one object, and whether every byte so far was zero (tracked only while all-zero
/// objects are kept out of collection, `flashstore_dedup_zero_objects` false).
#[derive(Clone)]
pub(crate) struct Hasher {
    d: Digester,
    zero: bool,
}

impl std::fmt::Debug for Hasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.d {
            Digester::Md5(_) => "Md5",
            Digester::Sha256(_) => "Sha256",
        })
    }
}

/// `b` has no non-zero byte. Ends at the first non-zero 64-byte block, so ordinary data costs one block.
fn all_zero(b: &[u8]) -> bool {
    let (blocks, rest) = b.as_chunks::<64>();
    blocks
        .iter()
        .all(|w| w.iter().fold(0u8, |a, &x| a | x) == 0)
        && rest.iter().all(|&x| x == 0)
}

impl Hasher {
    /// `track_zero`: find out whether the object is all zero.
    pub(crate) fn new(alg: DigestAlg, track_zero: bool) -> Hasher {
        let d = match alg {
            DigestAlg::Md5 => Digester::Md5(md5::Md5::new()),
            DigestAlg::Sha256 => Digester::Sha256(sha2::Sha256::new()),
        };
        Hasher {
            d,
            zero: track_zero,
        }
    }
    pub(crate) fn update(&mut self, b: &[u8]) {
        if self.zero && !all_zero(b) {
            self.zero = false;
        }
        match &mut self.d {
            Digester::Md5(h) => h.update(b),
            Digester::Sha256(h) => h.update(b),
        }
    }
    fn finish(self) -> (DigestAlg, Vec<u8>) {
        match self.d {
            Digester::Md5(h) => (DigestAlg::Md5, h.finalize().to_vec()),
            Digester::Sha256(h) => (DigestAlg::Sha256, h.finalize().to_vec()),
        }
    }
}

/// Collection counters.
#[derive(Debug, Default)]
pub struct DedupCounters {
    /// Records written.
    pub recorded: Cell<u64>,
    /// Digests not recorded: the object changed during its read, or the shard was busy.
    pub dropped: Cell<u64>,
    /// Records deleted by listings (older than the prune age, or of another digest algorithm).
    pub pruned: Cell<u64>,
    /// All-zero objects not recorded (`flashstore_dedup_zero_objects` false).
    pub zero_skipped: Cell<u64>,
}

fn inc(c: &Cell<u64>, n: u64) {
    c.set(c.get() + n);
}

pub(crate) fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

impl<D: BlockDev, C: Clock> StoreAdapter<D, C> {
    pub fn dedup_counters(&self) -> &DedupCounters {
        &self.dd_stats
    }

    /// Digest algorithm of new records.
    pub fn dedup_digest(&self) -> DigestAlg {
        self.dd_alg.get()
    }

    /// All-zero objects are recorded too (`flashstore_dedup_zero_objects`).
    pub fn dedup_zero_objects(&self) -> bool {
        self.dd_zero.get()
    }

    pub(crate) fn set_scrub_primary(&self, spg: denc::types::SpgT, primary: bool) {
        let mut s = self.scrub_primary.borrow_mut();
        if primary {
            s.insert(spg);
        } else {
            s.remove(&spg);
        }
    }

    /// A digest for the deep read of `h` that is starting, or `None` when this read does not collect: the pool has no
    /// `collect_csum`, this is not the primary's own map, an EC shard, an empty object, or no data state (`before`).
    pub(crate) fn collect_begin(
        &self,
        c: &CollT,
        size: u64,
        ec: bool,
        before: Option<&DataVersion>,
    ) -> Option<Hasher> {
        let CollT::Pg(spg) = c else { return None };
        (self.reformat_engines(spg.pgid.pool).collect_csum
            && self.scrub_primary.borrow().contains(spg)
            && !ec
            && spg.shard == ShardId::NO_SHARD
            && size > 0
            && before.is_some())
        .then(|| Hasher::new(self.dd_alg.get(), !self.dd_zero.get()))
    }

    /// The deep read of `h` is complete: record its digest if the object is still in the state `before`.
    pub(crate) fn collect_finish(
        &self,
        st: &mut Store<D, C>,
        c: &CollT,
        g: &Ghobject,
        h: &Hobject,
        hasher: Hasher,
        before: DataVersion,
    ) {
        let CollT::Pg(spg) = c else { return };
        if st.data_version(c, g).ok().flatten() != Some(before) {
            inc(&self.dd_stats.dropped, 1);
            return;
        }
        if hasher.zero {
            inc(&self.dd_stats.zero_skipped, 1);
            return;
        }
        let (alg, digest) = hasher.finish();
        let key = dedup::key(
            spg.pgid.pool as i64,
            &digest,
            now_ns(),
            h.hash.reverse_bits(),
        );
        let val = RecordValue {
            alg,
            id: before.id,
            dv_gen: before.dv_gen,
            dv: before.dv,
            oid: g.clone(),
        };
        let mut t = OTxn::new();
        t.push(TOp::DedupKv {
            shard: st.shard_of(c) as u32,
            puts: vec![(key, val.encode())],
            dels: Vec::new(),
            del_range: None,
        });
        let tok = self.take_tok();
        match st.try_local(&t, tok) {
            Ok(true) => inc(&self.dd_stats.recorded, 1),
            _ => inc(&self.dd_stats.dropped, 1),
        }
    }

    /// This core's part of a listing (dedup-collection.md 6, merged by the OSD): records of the digest shard after `r.after`
    /// in key order; old records and records of another digest length are pruned on the way.
    pub fn dedup_list_local(&self, r: &DedupListReq) -> Result<DedupListPart, String> {
        let mut st = self.st.borrow_mut();
        let dlen = self.dd_alg.get().digest_len();
        let (lo, hi) = dedup::shard_range(r.pool, r.shard, r.shard_bits, dlen);
        let mut start = lo;
        if !r.after.is_empty() {
            // strictly after the cursor
            start = start.max(key_after([&[dedup::T_DEDUP][..], &r.after].concat()));
        }
        let t0 = Instant::now();
        // nothing examined: the cursor stays where the request started (never back to the range start)
        let mut out = DedupListPart {
            examined: r.after.clone(),
            ..Default::default()
        };
        let mut prune: std::collections::BTreeMap<u32, Vec<Vec<u8>>> = Default::default();
        'scan: loop {
            // never waits on the core for a tree page: a miss ends this part early (the load is submitted)
            let batch = match st.dedup_scan(&start, &hi, 256, true) {
                Ok(b) => b,
                Err(ObjError::WouldBlock) => break,
                Err(e) => return Err(e.to_string()),
            };
            if batch.is_empty() {
                out.completed = true;
                break;
            }
            for (k, _, shard) in &batch {
                let Some(p) = dedup::parse_key(k) else {
                    continue;
                };
                if p.digest.len() != dlen
                    || p.ts_ns < r.retrieve_after_ns && p.ts_ns < r.remove_before_ns
                {
                    prune.entry(*shard).or_default().push(k.clone());
                } else if p.ts_ns >= r.retrieve_after_ns {
                    out.entries.push(DedupEntry {
                        key: k[1..].to_vec(),
                        digest: p.digest.to_vec(),
                        ts_ns: p.ts_ns,
                        hash_key: p.hash_key,
                    });
                }
                out.examined = k[1..].to_vec();
                if out.entries.len() >= r.max
                    || r.max_duration_s > 0.0 && t0.elapsed().as_secs_f64() > r.max_duration_s
                {
                    break 'scan;
                }
            }
            start = key_after(batch.last().unwrap().0.clone());
        }
        // the range may have ended exactly at the record that filled the reply
        if !out.completed {
            let a = key_after([&[dedup::T_DEDUP][..], &out.examined].concat());
            out.completed = match st.dedup_scan(&a, &hi, 1, true) {
                Ok(rest) => rest.is_empty(),
                Err(ObjError::WouldBlock) => false,
                Err(e) => return Err(e.to_string()),
            };
        }
        for (shard, dels) in prune {
            let n = dels.len() as u64;
            let mut t = OTxn::new();
            t.push(TOp::DedupKv {
                shard,
                puts: Vec::new(),
                dels,
                del_range: None,
            });
            let tok = self.take_tok();
            if st.try_local(&t, tok).unwrap_or(false) {
                inc(&self.dd_stats.pruned, n);
            }
        }
        Ok(out)
    }

    /// (approximate bytes, entries) of this core's records of `pool`.
    pub fn dedup_stats_local(&self, pool: i64) -> Result<(u64, u64), String> {
        let mut st = self.st.borrow_mut();
        let (lo, hi) = dedup::shard_range(pool, 0, 0, 0);
        let (mut bytes, mut n) = (0u64, 0u64);
        let mut start = lo;
        loop {
            let b = st
                .dedup_scan(&start, &hi, 1024, false)
                .map_err(|e| e.to_string())?;
            let Some(last) = b.last() else { break };
            bytes += b
                .iter()
                .map(|(k, v, _)| (k.len() + v.len()) as u64)
                .sum::<u64>();
            n += b.len() as u64;
            start = key_after(last.0.clone());
        }
        Ok((bytes, n))
    }

    /// Remove this core's records of `pool` (every shard; waits until durable: an admin command).
    pub fn dedup_clear_local(&self, pool: i64) -> Result<(), String> {
        let mut st = self.st.borrow_mut();
        let (lo, hi) = dedup::shard_range(pool, 0, 0, 0);
        for shard in st.dedup_shards() {
            let mut t = OTxn::new();
            t.push(TOp::DedupKv {
                shard,
                puts: Vec::new(),
                dels: Vec::new(),
                del_range: Some((lo.clone(), hi.clone())),
            });
            st.commit(&t).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}
