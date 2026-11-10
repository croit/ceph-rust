// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Per-session backoffs (client-ops.md s6): PG-wide BLOCK when ops hit a PG that is down / incomplete / peered
//! but not active, object-level BLOCK when the head object is unreadable and cannot recover on its own (unfound) or
//! the option allows backing off degraded objects (16.6). UNBLOCK on activation / new interval (all records) or when
//! the object becomes readable / leaves the degraded set (object-level); ACK_BLOCK bookkeeping.

use crate::engine::Out;
use denc::types::{Hobject, SnapId, SpgT};
use opwire::{MOSDBackoff, consts::backoff as bo};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

// IDs belong to the client session, which can span PGs on different cores.
// Allocate only when creating a BLOCK; no ordering of other memory is needed.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum St {
    /// BLOCK sent, not yet acked.
    New,
    /// ACK_BLOCK received.
    Acked,
    /// UNBLOCK sent while still New: keep until the late ACK arrives.
    Deleting,
}

#[derive(Debug)]
struct Rec {
    id: u64,
    begin: Hobject,
    end: Hobject,
    st: St,
}

impl Rec {
    /// `[begin, end)` covers `head`; `begin == end` blocks exactly that object (all its snaps, client-ops s6.1).
    fn covers(&self, head: &Hobject) -> bool {
        if self.begin == self.end {
            self.begin == *head
        } else {
            self.begin <= *head && *head < self.end
        }
    }

    /// Object-level (one exact object) rather than PG-wide.
    fn is_object(&self) -> bool {
        self.begin == self.end
    }
}

#[derive(Debug, Default)]
struct ConnBo {
    recs: Vec<Rec>,
}

#[derive(Debug, Default)]
pub struct Backoffs {
    conns: HashMap<u64, ConnBo, foldhash::fast::RandomState>,
}

/// `[begin, end)` covering the whole PG (s6.1).
fn pg_range(spg: SpgT, pg_num: u32) -> (Hobject, Hobject) {
    let pool = spg.pgid.pool as i64;
    let begin = Hobject::new(b"", SnapId(0), spg.pgid.seed, pool, b"");
    (begin, crate::pgop::pg_end(pool, spg.pgid.seed, pg_num))
}

impl Backoffs {
    /// Ops of `conn` on `head` are dropped: a record covering it (PG-wide, object-level, also one DELETING or not yet
    /// ACKed) exists. Ops arriving before the ACK were sent before the client saw the BLOCK; it resends all of them on
    /// the UNBLOCK, in order (client-ops s6.5).
    pub fn covers(&self, conn: u64, head: &Hobject) -> bool {
        self.conns
            .get(&conn)
            .is_some_and(|c| c.recs.iter().any(|r| r.covers(head)))
    }

    /// Anything to release on activation.
    pub fn has_live(&self) -> bool {
        self.conns
            .values()
            .any(|c| c.recs.iter().any(|r| r.st != St::Deleting))
    }

    /// No record left (test-only view of the state machine).
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.conns.values().all(|c| c.recs.is_empty())
    }

    pub fn clear(&mut self) {
        self.conns.clear();
    }

    /// Drop the backoffs of a closed connection. Returns whether any were live.
    pub fn conn_closed(&mut self, conn: u64) -> bool {
        self.conns.remove(&conn).is_some()
    }

    /// Push a BLOCK for `[begin, end)` to `conn`, unless one for the same begin is already live (s6.3: never BLOCK
    /// twice for the same range). `false` = nothing sent.
    fn add(
        &mut self,
        spg: SpgT,
        epoch: u32,
        conn: u64,
        begin: Hobject,
        end: Hobject,
        out: &mut Vec<Out>,
    ) -> bool {
        let c = self.conns.entry(conn).or_default();
        if c.recs.iter().any(|r| r.begin == begin) {
            return false;
        }
        // Full-width allocation avoids lossy pool/seed packing and reuse after
        // a short per-PG counter wraps. A process restart replaces sessions.
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        out.push(Out::Backoff {
            conn,
            msg: MOSDBackoff {
                pgid: spg,
                map_epoch: epoch,
                op: bo::BLOCK,
                id,
                begin: begin.clone(),
                end: end.clone(),
            },
        });
        c.recs.push(Rec {
            id,
            begin,
            end,
            st: St::New,
        });
        true
    }

    /// Send BLOCK for the whole PG to `conn` (once; not while a record of the session, even a DELETING one, exists).
    pub fn block(&mut self, spg: SpgT, pg_num: u32, epoch: u32, conn: u64, out: &mut Vec<Out>) {
        if self.covers(conn, &Hobject::MIN()) {
            return;
        }
        let (begin, end) = pg_range(spg, pg_num);
        self.add(spg, epoch, conn, begin, end, out);
    }

    /// Send BLOCK for exactly one object (`begin == end == head`, client-ops s6.1/16.6). `false` = such a record
    /// already exists (nothing sent).
    pub fn block_obj(
        &mut self,
        spg: SpgT,
        epoch: u32,
        conn: u64,
        head: &Hobject,
        out: &mut Vec<Out>,
    ) -> bool {
        self.add(spg, epoch, conn, head.clone(), head.clone(), out)
    }

    /// ACK_BLOCK from the client (any PG state).
    pub fn ack(&mut self, conn: u64, id: u64, begin: &Hobject) {
        let Some(c) = self.conns.get_mut(&conn) else {
            return;
        };
        let Some(i) = c.recs.iter().position(|r| r.id == id && r.begin == *begin) else {
            return;
        };
        match c.recs[i].st {
            St::New => c.recs[i].st = St::Acked,
            St::Deleting => {
                c.recs.remove(i);
            }
            St::Acked => {}
        }
    }

    /// UNBLOCK every live record of a connection whose `keep` decides, then drop the records the client acked.
    fn release(
        &mut self,
        spg: SpgT,
        epoch: u32,
        mut keep: impl FnMut(&Rec) -> bool,
        out: &mut Vec<Out>,
    ) {
        for (&conn, c) in self.conns.iter_mut() {
            let mut left = Vec::new();
            for mut r in std::mem::take(&mut c.recs) {
                if r.st == St::Deleting || !keep(&r) {
                    left.push(r);
                    continue;
                }
                out.push(Out::Backoff {
                    conn,
                    msg: MOSDBackoff {
                        pgid: spg,
                        map_epoch: epoch,
                        op: bo::UNBLOCK,
                        id: r.id,
                        begin: r.begin.clone(),
                        end: r.end.clone(),
                    },
                });
                if r.st == St::New {
                    r.st = St::Deleting;
                    left.push(r);
                }
            }
            c.recs = left;
        }
    }

    /// UNBLOCK every live record (activation, new interval, teardown).
    pub fn release_all(&mut self, spg: SpgT, epoch: u32, out: &mut Vec<Out>) {
        self.release(spg, epoch, |_| true, out);
    }

    /// Release PG-wide records and object records whose heads are ready, in one
    /// pass. Deleting records still wait for their late ACK.
    pub fn release_ready(
        &mut self,
        spg: SpgT,
        epoch: u32,
        mut ready: impl FnMut(&Hobject) -> bool,
        out: &mut Vec<Out>,
    ) {
        self.release(spg, epoch, |r| !r.is_object() || ready(&r.begin), out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use denc::types::{PgT, ShardId};

    fn spg(seed: u32) -> SpgT {
        SpgT {
            pgid: PgT::new(3, seed),
            shard: ShardId::NO_SHARD,
        }
    }

    #[test]
    fn range_bounds() {
        let (b, e) = pg_range(spg(0), 1);
        assert_eq!(b.hash, 0);
        assert!(e.max);
        // pg_num 4: seed 1 -> rev(1)=0x80000000 | 0x3fffffff, +1 = 0xC0000000, rev = 3
        let (b, e) = pg_range(spg(1), 4);
        assert_eq!(b.hash, 1);
        assert!(!e.max);
        assert_eq!(e.hash, 3);
        assert_eq!(e.snap, SnapId::NOSNAP);
        // last pg (seed 3 of 4): sum reaches 2^32 -> MAX
        let (_, e) = pg_range(spg(3), 4);
        assert!(e.max);
    }

    #[test]
    fn release_ready_scans_each_live_record_once() {
        let mut b = Backoffs::default();
        let mut out = Vec::new();
        let n = 2048;
        // Direct setup avoids measuring BLOCK admission rather than release.
        let c = b.conns.entry(7).or_default();
        for i in 0..n {
            let o = Hobject::new(format!("{i:08}").as_bytes(), SnapId::NOSNAP, 0, 3, b"");
            c.recs.push(Rec {
                id: i,
                begin: o.clone(),
                end: o,
                st: St::Acked,
            });
        }
        let mut probes = 0;
        b.release_ready(
            spg(0),
            6,
            |_| {
                probes += 1;
                true
            },
            &mut out,
        );
        assert_eq!(probes, n);
        assert_eq!(out.len() as u64, n);
        assert!(b.is_empty());
        // The old per-object release pass examined every remaining record.
        // With acked records removed each pass, its exact count was triangular.
        eprintln!(
            "backoff release: records={n}, readiness probes={probes}, old release record visits={}",
            n * (n + 1) / 2
        );
    }

    #[test]
    fn state_machine() {
        let mut b = Backoffs::default();
        let mut out = Vec::new();
        b.block(spg(0), 8, 5, 7, &mut out);
        b.block(spg(0), 8, 5, 7, &mut out); // only one live
        assert_eq!(out.len(), 1);
        let (begin, _) = pg_range(spg(0), 8);
        assert!(b.covers(7, &begin) && !b.covers(7, &Hobject::MIN()));
        assert!(!b.covers(8, &begin));
        let id1 = match &out[0] {
            Out::Backoff { msg, .. } => msg.id,
            _ => unreachable!(),
        };
        b.ack(7, id1, &begin);
        out.clear();
        b.release_all(spg(0), 6, &mut out);
        assert_eq!(out.len(), 1);
        assert!(!b.covers(7, &begin) && b.is_empty());
        // UNBLOCK while still NEW: record kept until the late ACK
        b.block(spg(0), 8, 5, 7, &mut out);
        b.release_all(spg(0), 6, &mut out);
        assert!(!b.is_empty() && b.covers(7, &begin)); // DELETING still drops until the ACK
        let id2 = match out.last() {
            Some(Out::Backoff { msg, .. }) => msg.id,
            _ => unreachable!(),
        };
        assert_ne!(id1, id2);
        b.ack(7, id2, &begin);
        assert!(b.is_empty() && !b.covers(7, &begin));
        // unknown id ignored
        b.ack(7, 99, &begin);
    }
}

#[cfg(test)]
mod id_tests {
    use super::*;
    use denc::types::{PgT, ShardId};

    fn spg(seed: u32) -> SpgT {
        SpgT {
            pgid: PgT::new(3, seed),
            shard: ShardId::NO_SHARD,
        }
    }

    /// Regression (mixed-cluster suite, PG merge/split under rbd bench): two PGs blocking the same client session must not reuse
    /// an id, the client's per-session id map mixes them up otherwise.
    #[test]
    fn ids_are_unique_across_pgs_of_one_session() {
        let (mut a, mut b) = (Backoffs::default(), Backoffs::default());
        let mut out = Vec::new();
        a.block(spg(1), 8, 5, 7, &mut out);
        b.block(spg(2), 8, 5, 7, &mut out);
        let ids: Vec<u64> = out
            .iter()
            .map(|o| match o {
                Out::Backoff { msg, .. } => msg.id,
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1]);
        assert_ne!(ids[0], 0);
    }

    #[test]
    fn ids_preserve_full_pool_and_pg_identity() {
        let mut out = Vec::new();
        // Pool IDs and PG seeds are not restricted to the old packed ID's
        // 20-bit pool / 24-bit seed fields.
        for (pool, seed) in [(3, 1), (3 + (1 << 20), 1), (3, 1 + (1 << 24))] {
            let mut b = Backoffs::default();
            let mut pg = spg(seed);
            pg.pgid.pool = pool;
            let head = Hobject::new(b"o", SnapId::NOSNAP, seed, pool as i64, b"");
            b.block_obj(pg, 5, 7, &head, &mut out);
        }
        let ids: std::collections::HashSet<_> = out
            .iter()
            .map(|o| match o {
                Out::Backoff { msg, .. } => msg.id,
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(
            ids.len(),
            out.len(),
            "each session backoff needs its own ID"
        );
    }
}
