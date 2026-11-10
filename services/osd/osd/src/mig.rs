// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! PG placement and migration between the cores of one OSD (adr 0031 am. 1, 2, 4, 5).
//!
//! * Placement: a PG lives on the store shard its collection was created in (where it was placed when it arrived, else
//!   the hash; split children inherit the parent's shard; migrated PGs sit where they were moved). The core of a PG is
//!   `shard % cores`. Every core keeps the table of off-hash placements (`PgSet::place`); it is rebuilt at boot from
//!   where the collections are.
//! * Balanced arrival (adr 0639): with each map the control core places the PGs that map to this OSD for the first
//!   time on the least loaded core (`peering::place`), as *placement moves* of the same round: no data travels (an
//!   arriving PG has no copy here; one that has stays where it is), what waits for the PG on its hash core moves with
//!   it. A PG that is here never moves for balance.
//! * Merge across cores: a merge source must sit on the core of its target. When a map lowers `pg_num` /
//!   `pg_num_pending`, every core first runs a *round*. The control core alone decides it (single source of truth: the
//!   moves, computed from its placement table when the map reaches the head of its queue, go to the workers in
//!   [`XMsg::Gate`], one per map, empty = no round). The cores holding sources that are not co-located export the PG
//!   (objects, attrs, omap, pgmeta last) to the target's core over the mesh with a credit window, the target core
//!   imports every instance of the PG, adopts them all once the last one is complete and acknowledges them; the source
//!   deletes its copies after the acknowledgements and reports [`XMsg::MigDone`] to the control core. When all
//!   reported, the control core sends [`XMsg::Release`]; every core then switches the placements of the round's moves
//!   and applies the held map (in order). No placement travels between workers.
//! * Messages of a moving PG (adr 0031 am. 8): the rings keep order per lane and pair only, so the order of what one
//!   core routes for a PG (client ops, backoff acks, copy reads, pre-write pieces, peer PG messages) is kept by the
//!   protocol. From the start of a round until its Release every core holds what it routes itself for the round's PGs
//!   and sends each source core [`XMsg::MigHold`], an ordered barrier behind everything it routed before. A source
//!   starts its moves once every other core's barrier is in. What waits for a detached PG (its PG set queues, parked
//!   client ops, whatever still reaches it) is handed to the destination together with the placement switch and
//!   closed by [`XMsg::MigHandoff`]; the destination runs the hand-off first, then what the other cores send it after
//!   their Release, and only once it switched itself. Nothing is answered by a core that no longer hosts the PG, nothing
//!   is dropped, no message of one sender overtakes an earlier one.
//! * Headroom (adr 0031 am. 4, 5): before a source detaches, the destination core reserves the copy's exact size
//!   (from the stored collection, [`PgStoreOps::mig_bytes`]) on its store shard ([`XMsg::MigReserve`]). No room = the
//!   move is *deferred*: the PG keeps serving on its old core (the merge waits: source and target on different cores
//!   are never reported ready to merge), the control core raises `FLASHSTORE_PG_MOVE_DEFERRED` and retries
//!   ([`XMsg::MigRetry`]) once the destination reports room. An import that still finds no room is undone
//!   ([`XMsg::MigAbort`]: the destination deletes what it imported, the source serves its untouched copy again) and
//!   deferred the same way: capacity never stops the store or the OSD.
//! * Strand (adr 0031 am. 5): the mon completes a merge on the reports of the primaries; on a non-primary member the
//!   source may still sit on another core then. The merged PG is created without it: incomplete (`last_backfill` MIN,
//!   classic semantics), so it never serves or peers as authoritative, its peers backfill it. The stranded copy is
//!   NEVER moved or absorbed later (that would overwrite newer data); it stays unloaded and is deleted once the PG
//!   covering it is complete on this OSD again or gone ([`XMsg::MigObsolete`]).
//! * Boot: core 0 collects every core's PG list ([`BootPg`]), resolves copies of one PG on two cores (an interrupted
//!   move: the core holding more instances wins, then the newer epoch, then the higher migration generation; see
//!   `storeadapt::migrate`) and the placement table. A merge source not on its target's core is a deferral (moved by a
//!   runtime retry), or stranded when the maps completed its merge. Boot never moves data.

use crate::backend::Backend;
use crate::osd::Osd;
use crate::xcore::XMsg;
use denc::types::{Hobject, PgT, ShardId, SpgT};
use opwire::MOSDOp;
use osdmap::OsdMap;
use peering::PgStoreOps;
use peering::place;
use peering::store::{ExportCursor, MigImportError, MigOp};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

/// Batches in flight per exported PG.
const WINDOW: u32 = 3;
/// Payload bytes per batch.
const BUDGET: usize = 1 << 20;

/// Every PG instance (`pgid` + shard: an EC OSD may hold several shards of one PG) of `pgid` in `held`.
fn instances(held: &BTreeSet<SpgT>, pgid: PgT) -> impl Iterator<Item = SpgT> + '_ {
    let lo = SpgT {
        pgid,
        shard: ShardId(i8::MIN),
    };
    let hi = SpgT {
        pgid,
        shard: ShardId(i8::MAX),
    };
    held.range(lo..=hi).copied()
}

/// The one PG a message routed to its PG's core addresses (`None`: not such a message, or a peer message for several
/// PGs, which every owning core gets).
fn item_pgid(m: &XMsg) -> Option<PgT> {
    match m {
        XMsg::Op { op, .. } | XMsg::CopyRead { op, .. } => Some(op.pgid.pgid),
        XMsg::BackoffAck { b, .. } => Some(b.pgid.pgid),
        XMsg::PrePiece { spg, .. } => Some(spg.pgid),
        XMsg::Pg { body, .. } => match *peering::body_spgs(body) {
            [s] => Some(s.pgid),
            _ => None,
        },
        _ => None,
    }
}

/// A complete PG instance found in a core's store at boot.
#[derive(Debug, Clone)]
pub struct BootPg {
    pub spg: SpgT,
    /// Store shard of its collection.
    pub shard: u32,
    pub generation: u64,
    /// Epoch the instance was persisted at.
    pub epoch: u32,
}

/// A move that did not run: no headroom for the PG at its destination (adr 0031 am. 4), or a stranded merge source
/// (am. 5: the merge completed without it; never moved, deleted once obsolete).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deferred {
    pub pgid: PgT,
    pub to: usize,
    pub shard: u32,
    pub bytes: u64,
    pub stranded: bool,
}

/// Core 0's answer to the boot reports.
#[derive(Debug, Default)]
pub struct BootInfo {
    pub maps: Vec<Arc<OsdMap>>,
    /// Off-hash placements of every PG of the OSD.
    pub placement: Vec<(PgT, u32)>,
    /// Copies this core must delete (the PG's copy on another core wins).
    pub drop: Vec<SpgT>,
    /// Stranded merge sources this core holds: kept in the store, never loaded.
    pub strand: Vec<SpgT>,
    /// Every deferred move of the OSD.
    pub deferred: Vec<Deferred>,
    /// Pools of the PGs stored on ANY core: never declined (adr 0039 am. 1 point 7).
    pub held_pools: Vec<u64>,
}

#[derive(Debug)]
struct Job {
    spg: SpgT,
    dst: usize,
    shard: u32,
    /// Move attempt (the destination drops batches of an attempt it undid).
    seq: u64,
    /// Headroom reserved for the whole PG.
    bytes: u64,
    cur: ExportCursor,
    in_flight: u32,
    exported: bool,
}

/// Destination: a PG moving in.
#[derive(Debug)]
struct Incoming {
    from: usize,
    seq: u64,
    /// Instances the source moves.
    n: usize,
    /// Instances complete and durable here (adopted together when all are).
    done: Vec<SpgT>,
    /// The placement before the move (restored when the import is undone).
    old_shard: u32,
    /// Payload bytes imported so far.
    imported: u64,
    aborted: bool,
}

/// Destination: messages for a PG moving in, run once the source handed it over ([`XMsg::MigHandoff`]) and this core
/// switched its placement (its Release). The source's hand-off (`first`) runs before what other cores send directly.
#[derive(Debug)]
struct Arrival {
    from: usize,
    handed: bool,
    switched: bool,
    first: Vec<XMsg>,
    later: Vec<XMsg>,
}

#[derive(Debug)]
struct Held {
    prev_map: Option<Arc<OsdMap>>,
    new: Arc<OsdMap>,
    /// Every epoch the update brought (decoded once by the control core, shared), oldest first.
    chain: Vec<Arc<OsdMap>>,
    checked: bool,
}

#[derive(Debug)]
pub(crate) struct Round {
    /// Rounds started on this core so far (every core runs the same rounds in the same order).
    id: u64,
    epoch: u32,
    moves: Vec<Move>,
    /// This core's own moves started (every other core's [`XMsg::MigHold`] is in).
    started: bool,
    done_sent: bool,
    /// Control: cores done (bit per core, own included).
    mask: u64,
    /// Moves that did not run for lack of headroom (own; control: every core's).
    deferred: Vec<Deferred>,
    /// Placements of arriving PGs that found an instance on their source core: they stay (own; control: every
    /// core's).
    stay: Vec<PgT>,
    /// The map applied after the round.
    next: Arc<OsdMap>,
}

/// A PG changes core: a merge source that does not sit on its target's core, or (`place`) a PG that arrives on this
/// OSD and goes to the least loaded core (adr 0639). The unit is the PG (placement is per PG): the source core moves
/// EVERY instance of `pgid` its store holds (replicated: `NO_SHARD`; EC: each shard it holds), never a guessed one. A
/// placement never carries data: a source that holds an instance of an arriving PG keeps it (the round's `stay`).
#[derive(Debug, Clone, Copy)]
pub struct Move {
    pub pgid: PgT,
    pub from: usize,
    pub to: usize,
    /// Store shard of the destination.
    pub shard: u32,
    /// Placement of an arriving PG (no data; a source with an instance keeps the PG).
    pub place: bool,
}

/// A core's boot report: oldest PG epoch, complete PG instances.
type BootReport = (u32, Vec<BootPg>);

/// Per-core migration state.
#[derive(Debug)]
pub(crate) struct MigState {
    jobs: Vec<Job>,
    held: VecDeque<Held>,
    pub(crate) round: Option<Round>,
    /// Worker: the control core's decision per map epoch (moves, empty = no round), until the map is at the head.
    gates: BTreeMap<u32, Vec<Move>>,
    /// Rounds started on this core (the id of the running one).
    rounds: u64,
    /// PGs of the running round: what this core routes for them waits in `hold_q` (in order) until its Release. Held
    /// client ops and peer messages keep their input reservation (`IngressCredits`): the input windows bound them, a
    /// full window makes the links wait.
    hold: BTreeSet<PgT>,
    pub(crate) hold_q: Vec<XMsg>,
    /// Source: [`XMsg::MigHold`] barriers received, by round id.
    holds_in: BTreeMap<u64, usize>,
    /// Source: messages for a PG leaving this core (what waited for it at the detach, what reached it since), handed to
    /// the destination with the placement switch.
    handoff: BTreeMap<PgT, Vec<XMsg>>,
    /// Destination: messages for a PG moving in.
    arriving: BTreeMap<PgT, Arrival>,
    /// Boot: migration messages that arrived before this worker's boot answer (cross-ring order is not guaranteed).
    pub(crate) boot_early: Vec<(usize, XMsg)>,
    /// The map the PG set has been advanced to (None until the boot answer was applied).
    applied: Option<Arc<OsdMap>>,
    /// Source: moves waiting for the destination's headroom answer, with the bytes asked for and the attempt.
    reserving: BTreeMap<PgT, (Move, u64, u64)>,
    /// Source: last move attempt number.
    seq: u64,
    /// Destination: PGs moving in.
    incoming: BTreeMap<PgT, Incoming>,
    /// Worker: a retry round `(held maps to apply first, epoch, moves)`.
    retry: Option<(usize, u32, Vec<Move>)>,
    /// Destination: deferred moves into this core `(store shard, bytes)` by PG: the store borrows room for them
    /// (elastic pool) until they move or the control core drops them.
    wants: BTreeMap<PgT, (u32, u64)>,
    /// Store shards whose want is set (to clear them).
    want_shards: BTreeSet<u32>,
    /// Deferred moves of the OSD by source PG (control: the truth; workers: its last broadcast).
    pub(crate) deferred: BTreeMap<PgT, Deferred>,
    /// Control: moves deferred so far (counter).
    pub(crate) deferrals: u64,
    /// Stranded merge source instances this core holds (unloaded, deleted once obsolete).
    pub(crate) strands: BTreeSet<SpgT>,
    /// Stranded sources this core reported obsolete (until the control core's answer).
    obsolete_sent: BTreeSet<PgT>,
    /// Control: boot reports by core.
    boot_in: Vec<Option<BootReport>>,
    /// Control: the PGs that map to this OSD in the newest map a gate was decided for (adr 0639).
    mine: Option<peering::place::Mine>,
    /// PG instances whose destination placement was set by a running import.
    placed: BTreeSet<SpgT>,
    /// Finished moves (diagnostics).
    pub moved: u64,
}

impl MigState {
    pub(crate) fn new(n: usize) -> MigState {
        MigState {
            jobs: Vec::new(),
            held: VecDeque::new(),
            round: None,
            gates: BTreeMap::new(),
            rounds: 0,
            hold: BTreeSet::new(),
            hold_q: Vec::new(),
            holds_in: BTreeMap::new(),
            handoff: BTreeMap::new(),
            arriving: BTreeMap::new(),
            boot_early: Vec::new(),
            applied: None,
            reserving: BTreeMap::new(),
            seq: 0,
            incoming: BTreeMap::new(),
            retry: None,
            wants: BTreeMap::new(),
            want_shards: BTreeSet::new(),
            deferred: BTreeMap::new(),
            deferrals: 0,
            strands: BTreeSet::new(),
            obsolete_sent: BTreeSet::new(),
            boot_in: (0..n).map(|_| None).collect(),
            mine: None,
            placed: BTreeSet::new(),
            moved: 0,
        }
    }
}

/// Seed of the PG that holds the objects of seed `s` when the pool has `n` PGs.
fn covering(s: u32, n: u32) -> u32 {
    if s < n {
        s
    } else {
        pgwire::pgmath::merge_target(s, n)
    }
}

impl<B: Backend> Osd<B> {
    // ------------------------------------------------------------ map gate

    /// New osdmap epochs for the PG set. Single core: straight through. Several cores: queued behind PG moves a merge
    /// needs, applied in order.
    pub(crate) fn pg_maps(&mut self, prev_map: Option<Arc<OsdMap>>, chain: Vec<Arc<OsdMap>>) {
        self.pg_peer_sweep();
        if !self.multi() {
            self.pg_on_maps(chain);
            return;
        }
        let Some(new) = self.map.clone() else { return };
        self.cl.mig.held.push_back(Held {
            prev_map,
            new,
            chain,
            checked: false,
        });
        self.drain_held();
    }

    fn drain_held(&mut self) {
        loop {
            if self.cl.mig.round.is_some() {
                return;
            }
            // (not before the boot answer: the PG set has no map yet)
            if self.cl.mig.retry.as_ref().is_some_and(|r| r.0 == 0)
                && let Some(cur) = self.cl.mig.applied.clone()
                && let Some((_, epoch, moves)) = self.cl.mig.retry.take()
            {
                self.start_round(epoch, moves, cur);
                continue;
            }
            let Some(h) = self.cl.mig.held.front() else {
                return;
            };
            let (epoch, next) = (h.new.epoch, h.new.clone());
            if !h.checked {
                let applied = self.cl.mig.applied.clone();
                // a map the PG set is already at (boot loaded newer ones) needs no decision
                let moves = if applied.as_ref().is_some_and(|a| a.epoch >= epoch) {
                    Vec::new()
                } else if self.is_control() {
                    let new = h.new.clone();
                    let old = applied.or_else(|| h.prev_map.clone());
                    let moves = old.map_or_else(Vec::new, |o| {
                        let mut v = self.place_moves(&o, &new);
                        v.extend(self.cross_moves(&o, &new));
                        v
                    });
                    self.xbcast(|| XMsg::Gate {
                        epoch,
                        moves: moves.clone(),
                    });
                    moves
                } else {
                    match self.cl.mig.gates.remove(&epoch) {
                        Some(m) => m,
                        None => return, // the control core has not decided yet
                    }
                };
                if let Some(h) = self.cl.mig.held.front_mut() {
                    h.checked = true;
                }
                if !moves.is_empty() {
                    self.start_round(epoch, moves, next);
                    continue;
                }
            }
            let Some(h) = self.cl.mig.held.pop_front() else {
                return;
            };
            if let Some(r) = self.cl.mig.retry.as_mut() {
                r.0 = r.0.saturating_sub(1);
            }
            self.cl.mig.gates = self.cl.mig.gates.split_off(&(epoch + 1));
            self.cl.mig.applied = Some(h.new.clone());
            self.pg_on_maps(h.chain);
        }
    }

    /// Worker: the control core's decision for map `epoch`.
    pub(crate) fn on_mig_gate(&mut self, epoch: u32, moves: Vec<Move>) {
        self.cl.mig.gates.insert(epoch, moves);
        self.drain_held();
    }

    /// Worker: the control core retries deferred moves; the round runs once the maps received before it are applied
    /// (the control core had applied them when it decided).
    pub(crate) fn on_mig_retry(&mut self, epoch: u32, moves: Vec<Move>) {
        self.cl.mig.retry = Some((self.cl.mig.held.len(), epoch, moves));
        self.drain_held();
    }

    /// Control: retry the deferred moves whose destination reports room now. Deferrals of merges that were cancelled
    /// or are settled otherwise are dropped. Stranded sources are never retried (their merge completed without them).
    pub(crate) fn mig_retry_check(&mut self) {
        if !self.is_control() || !self.multi() {
            return;
        }
        let m = &self.cl.mig;
        if m.deferred.is_empty() || m.round.is_some() || !m.held.is_empty() {
            return;
        }
        let Some(cur) = m.applied.clone() else {
            return;
        };
        let mut keep = BTreeMap::new();
        let mut moves = Vec::new();
        let mut room: BTreeMap<u32, u64> = BTreeMap::new();
        let before = self.cl.mig.deferred.len();
        for (pg, d) in std::mem::take(&mut self.cl.mig.deferred) {
            let Some(pool) = cur.pools.get(&(pg.pool as i64)) else {
                continue; // pool deleted (a stranded copy goes with it)
            };
            if d.stranded {
                keep.insert(pg, d);
                continue;
            }
            let lo = place::pool_lo(pool);
            if pg.seed < lo {
                continue; // merge cancelled
            }
            let t = PgT::new(pg.pool, pgwire::pgmath::merge_target(pg.seed, lo));
            // (the copy is where it is stored: a merge that completed meanwhile routes the seed to its target)
            let (from, to) = (self.pg.set.stored_core(pg), self.pg.set.core_of(t));
            if from == to {
                continue;
            }
            keep.insert(pg, d);
            let shard = self.pg.set.pg_shard(t);
            let r = room
                .entry(shard)
                .or_insert_with(|| self.mig_room_of(to, shard));
            if *r >= d.bytes {
                *r -= d.bytes;
                moves.push(Move {
                    pgid: pg,
                    from,
                    to,
                    shard,
                    place: false,
                });
            }
        }
        let pruned = keep.len() != before;
        self.cl.mig.deferred = keep;
        if pruned {
            self.mig_bcast_deferred();
        }
        if moves.is_empty() {
            return;
        }
        let epoch = cur.epoch;
        self.log(format!(
            "retrying {} deferred PG move(s): room at their destinations",
            moves.len()
        ));
        self.xbcast(|| XMsg::MigRetry {
            epoch,
            moves: moves.clone(),
        });
        self.start_round(epoch, moves, cur);
    }

    /// Control: the deferred moves changed outside a round: every core learns the list.
    fn mig_bcast_deferred(&mut self) {
        let list: Vec<Deferred> = self.cl.mig.deferred.values().copied().collect();
        self.xbcast(|| XMsg::MigDeferred { list: list.clone() });
        self.on_mig_deferred(list);
    }

    /// Headroom core `core` last reported for store shard `shard` (own: live).
    fn mig_room_of(&self, core: usize, shard: u32) -> u64 {
        let rooms = if core == self.core_id() {
            self.pg.store.mig_rooms()
        } else {
            self.cl
                .stats
                .get(core)
                .and_then(Option::as_ref)
                .map_or_else(Vec::new, |s| s.mig_rooms.clone())
        };
        rooms.iter().find(|r| r.0 == shard).map_or(0, |r| r.1)
    }

    /// The PGs that map to this OSD with `new` and did not with `old` go to the least loaded cores (control core, adr
    /// 0639): a placement move per PG whose core changes. They are not here yet (or a stray copy is: the source keeps
    /// it, the round's `stay`), so what waits for them moves with the round and nothing is copied.
    fn place_moves(&mut self, old: &Arc<OsdMap>, new: &Arc<OsdMap>) -> Vec<Move> {
        let me = self.id.whoami;
        let (n, shards) = (self.cl.spec.n, self.cl.spec.shards);
        let prev = match self.cl.mig.mine.take() {
            Some(m) if m.epoch == old.epoch => m,
            _ => place::Mine::scan(old, me, self.pg.set.served_pools(old)),
        };
        let next = prev.next(old, new, me, self.pg.set.served_pools(new));
        let set = &self.pg.set;
        let (places, bal) =
            place::arrivals(&prev, &next, old, new, n, shards, |pg| set.pg_shard(pg));
        let moves: Vec<Move> = places
            .into_iter()
            .map(|p| Move {
                pgid: p.pgid,
                from: set.core_of(p.pgid),
                to: p.shard as usize % n,
                shard: p.shard,
                place: true,
            })
            .collect();
        self.cl.mig.mine = Some(next);
        if !moves.is_empty() {
            self.log(format!(
                "map {}: {} arriving PG(s) placed on the least loaded cores; PG instances per core {:?}",
                new.epoch,
                moves.len(),
                bal.per_core(None)
            ));
        }
        moves
    }

    /// Merge sources of `old -> new` that sit on another core than their targets (control core).
    fn cross_moves(&self, old: &OsdMap, new: &OsdMap) -> Vec<Move> {
        let mut v = Vec::new();
        for (id, np) in &new.pools {
            let Some(op) = old.pools.get(id) else {
                continue;
            };
            let (lo, hi) = (place::pool_lo(np), op.pg_num.max(np.pg_num));
            for s in lo..hi {
                let t = pgwire::pgmath::merge_target(s, lo);
                let (sp, tp) = (PgT::new(*id as u64, s), PgT::new(*id as u64, t));
                let (from, to) = (self.pg.set.core_of(sp), self.pg.set.core_of(tp));
                if from != to {
                    v.push(Move {
                        pgid: sp,
                        from,
                        to,
                        shard: self.pg.set.pg_shard(tp),
                        place: false,
                    });
                }
            }
        }
        v
    }

    /// Start a round: from now on this core holds what it routes for the round's PGs and tells every source core so
    /// ([`XMsg::MigHold`]). A source starts its moves once every other core did ([`Self::mig_hold_check`]).
    fn start_round(&mut self, epoch: u32, moves: Vec<Move>, next: Arc<OsdMap>) {
        let me = self.cl.spec.id;
        let m = &mut self.cl.mig;
        m.rounds += 1;
        let id = m.rounds;
        m.hold = moves.iter().map(|mv| mv.pgid).collect();
        for mv in moves.iter().filter(|mv| mv.to == me) {
            m.arriving.insert(
                mv.pgid,
                Arrival {
                    from: mv.from,
                    handed: false,
                    switched: false,
                    first: Vec::new(),
                    later: Vec::new(),
                },
            );
        }
        let sources: BTreeSet<usize> = moves
            .iter()
            .map(|mv| mv.from)
            .filter(|&f| f != me)
            .collect();
        m.round = Some(Round {
            id,
            epoch,
            moves,
            started: false,
            done_sent: false,
            mask: 0,
            deferred: Vec::new(),
            stay: Vec::new(),
            next,
        });
        for s in sources {
            self.xsend(s, XMsg::MigHold { round: id });
        }
        self.mig_hold_check();
    }

    /// Source: another core holds what it routes for the PGs of round `round`; everything it routed before is here.
    pub(crate) fn on_mig_hold(&mut self, round: u64) {
        *self.cl.mig.holds_in.entry(round).or_default() += 1;
        self.mig_hold_check();
    }

    /// Start this core's moves of the running round once every other core's [`XMsg::MigHold`] is in: nothing routed
    /// by an old placement table is on its way to the PGs any more.
    fn mig_hold_check(&mut self) {
        let (me, others) = (self.cl.spec.id, self.cl.spec.n - 1);
        let m = &mut self.cl.mig;
        let Some(r) = m.round.as_mut() else {
            return;
        };
        let mine: Vec<Move> = r.moves.iter().filter(|mv| mv.from == me).copied().collect();
        if r.started || (!mine.is_empty() && m.holds_in.get(&r.id).copied().unwrap_or(0) < others) {
            return;
        }
        r.started = true;
        m.holds_in.remove(&r.id);
        self.start_moves(mine);
        self.round_check();
    }

    /// Source: each move first asks its destination for the copy's headroom ([`XMsg::MigReserve`]); the PG detaches
    /// only once that is held. A PG with no instance here has nothing to copy: only what waits for it moves.
    fn start_moves(&mut self, mine: Vec<Move>) {
        if mine.is_empty() {
            return;
        }
        let mut ask = Vec::new();
        let held = self.held_instances();
        for m in mine {
            let spgs: Vec<SpgT> = instances(&held, m.pgid).collect();
            if spgs.is_empty() {
                let items = self.mig_take_items(m.pgid);
                self.cl.mig.handoff.insert(m.pgid, items);
                self.mig_hand_over(m.pgid, m.to, m.shard);
                continue;
            }
            if m.place {
                // an arriving PG with a (stray) copy here stays: a placement never carries data
                if let Some(r) = self.cl.mig.round.as_mut() {
                    r.stay.push(m.pgid);
                }
                continue;
            }
            let mut bytes = 0;
            for spg in &spgs {
                match self.pg.store.mig_bytes(*spg) {
                    Ok(b) => bytes += b,
                    Err(e) => return self.store_failed(&format!("size of pg {spg}: {e}")),
                }
            }
            ask.push((m, bytes, spgs.len()));
        }
        for (m, bytes, n) in ask {
            self.cl.mig.seq += 1;
            let seq = self.cl.mig.seq;
            self.cl.mig.reserving.insert(m.pgid, (m, bytes, seq));
            self.xsend(
                m.to,
                XMsg::MigReserve {
                    pgid: m.pgid,
                    shard: m.shard,
                    bytes,
                    seq,
                    n,
                },
            );
        }
    }

    /// Destination: hold the headroom for a PG moving in, or refuse (the source defers the move).
    pub(crate) fn on_mig_reserve(
        &mut self,
        from: usize,
        pgid: PgT,
        shard: u32,
        bytes: u64,
        seq: u64,
        n: usize,
    ) {
        if self.cl.boot_wait {
            let m = XMsg::MigReserve {
                pgid,
                shard,
                bytes,
                seq,
                n,
            };
            self.cl.mig.boot_early.push((from, m));
            return;
        }
        let ok = self.pg.store.mig_reserve(pgid, shard, bytes);
        if ok {
            self.cl.mig.wants.remove(&pgid);
            let old_shard = self.pg.set.stored_shard(pgid);
            self.cl.mig.incoming.insert(
                pgid,
                Incoming {
                    from,
                    seq,
                    n,
                    done: Vec::new(),
                    old_shard,
                    imported: 0,
                    aborted: false,
                },
            );
        } else {
            self.log(format!(
                "pg {pgid}: no room for a {bytes} B copy on store shard {shard}: move deferred"
            ));
            self.cl.mig.wants.insert(pgid, (shard, bytes));
        }
        self.mig_apply_wants();
        self.xsend(from, XMsg::MigGrant { pgid, ok });
    }

    /// Tick: deferred moves into this core keep their store shards asking the pool (a denied shard asks again after
    /// its retry delay); stranded sources whose covering PG is complete here are reported obsolete.
    pub(crate) fn mig_tick(&mut self) {
        if !self.cl.mig.wants.is_empty() {
            self.mig_apply_wants();
        }
        self.mig_strand_watch();
    }

    /// A stranded copy is obsolete once every instance of the PG covering it on this core is complete (backfilled by
    /// its peers) or none is left here; the core owning that PG reports it to the control core.
    fn mig_strand_watch(&mut self) {
        let m = &self.cl.mig;
        if m.round.is_some() || !m.deferred.values().any(|d| d.stranded) {
            return;
        }
        let Some(cur) = m.applied.clone() else {
            return; // not booted yet
        };
        let me = self.core_id();
        let mut obsolete = Vec::new();
        for d in m.deferred.values() {
            if !d.stranded || m.obsolete_sent.contains(&d.pgid) {
                continue;
            }
            let s = d.pgid.seed;
            let Some(pool) = cur.pools.get(&(d.pgid.pool as i64)) else {
                continue; // the control core drops it
            };
            let c = PgT::new(d.pgid.pool, covering(s, pool.pg_num));
            if self.pg.set.core_of(c) != me {
                continue;
            }
            let done = self
                .pg
                .set
                .pgs()
                .filter(|(k, _)| k.pgid == c)
                .all(|(_, p)| {
                    covering(s, p.pool_pg_num()) == c.seed
                        && p.info().last_backfill == Hobject::MAX()
                });
            if done {
                obsolete.push(d.pgid);
            }
        }
        for pgid in obsolete {
            self.cl.mig.obsolete_sent.insert(pgid);
            if self.is_control() {
                self.on_mig_obsolete(pgid);
            } else {
                self.xsend(0, XMsg::MigObsolete { pgid });
            }
        }
    }

    /// Control: stranded source `pgid` is obsolete: drop it from the deferrals (its holder deletes the copy).
    pub(crate) fn on_mig_obsolete(&mut self, pgid: PgT) {
        if !self.cl.mig.deferred.get(&pgid).is_some_and(|d| d.stranded) {
            return;
        }
        self.log(format!(
            "pg {pgid}: stranded merge source obsolete (the merged PG is complete here): deleting the copy"
        ));
        self.cl.mig.deferred.remove(&pgid);
        self.mig_bcast_deferred();
    }

    /// Hand the deferred moves' needs to the store, per shard (cleared where none is left).
    fn mig_apply_wants(&mut self) {
        let mut per: BTreeMap<u32, u64> = BTreeMap::new();
        for &(shard, bytes) in self.cl.mig.wants.values() {
            *per.entry(shard).or_default() += bytes;
        }
        for shard in std::mem::take(&mut self.cl.mig.want_shards) {
            per.entry(shard).or_insert(0);
        }
        for (&shard, &bytes) in &per {
            self.pg.store.mig_want(shard, bytes);
        }
        self.cl.mig.want_shards = per.into_iter().filter(|p| p.1 > 0).map(|p| p.0).collect();
    }

    /// The deferred moves of the OSD now: destinations borrow room for exactly theirs (stranded ones never move),
    /// holders delete the stranded copies that left the list (obsolete or pool deleted).
    pub(crate) fn on_mig_deferred(&mut self, list: Vec<Deferred>) {
        let me = self.core_id();
        let m = &mut self.cl.mig;
        m.deferred = list.iter().map(|d| (d.pgid, *d)).collect();
        m.obsolete_sent
            .retain(|pg| list.iter().any(|d| d.pgid == *pg));
        // refusals of the running round reach the list only at its end
        let in_round: BTreeSet<PgT> = m
            .round
            .as_ref()
            .map(|r| r.moves.iter().map(|mv| mv.pgid).collect())
            .unwrap_or_default();
        m.wants.retain(|pg, _| in_round.contains(pg));
        for d in list.iter().filter(|d| d.to == me && !d.stranded) {
            m.wants.insert(d.pgid, (d.shard, d.bytes));
        }
        self.mig_apply_wants();
        if self.cl.mig.round.is_some() {
            return;
        }
        let gone: Vec<SpgT> = self
            .cl
            .mig
            .strands
            .iter()
            .filter(|s| !list.iter().any(|d| d.pgid == s.pgid && d.stranded))
            .copied()
            .collect();
        for spg in gone {
            self.cl.mig.strands.remove(&spg);
            if let Err(e) = self.pg.store.mig_remove(spg) {
                return self.store_failed(&format!("remove stranded pg {spg}: {e}"));
            }
            self.pg.set.removed_unloaded(spg);
            self.log(format!("pg {spg}: stranded merge source deleted"));
        }
    }

    /// Source: the destination answered: move every instance of `pgid`, or keep serving it here (deferred).
    pub(crate) fn on_mig_grant(&mut self, pgid: PgT, ok: bool) {
        let Some((m, bytes, seq)) = self.cl.mig.reserving.remove(&pgid) else {
            return;
        };
        if ok {
            let held = self.held_instances();
            let spgs: Vec<SpgT> = instances(&held, pgid).collect();
            for spg in spgs {
                self.start_export(spg, m.to, m.shard, seq, bytes);
            }
            // what waits here for the PG goes with it (and what reaches this core until the placement switch)
            let items = self.mig_take_items(pgid);
            self.cl.mig.handoff.insert(pgid, items);
        } else {
            self.mig_defer(m.pgid, m.to, m.shard, bytes);
        }
        self.round_check();
    }

    /// Source: the move of `pgid` did not run (no headroom). The PG keeps living here; when the round's map completes
    /// its merge, it is stranded instead.
    fn mig_defer(&mut self, pgid: PgT, to: usize, shard: u32, bytes: u64) {
        let Some(r) = self.cl.mig.round.as_mut() else {
            return;
        };
        let stranded = Self::merged_away(&r.next, pgid);
        r.deferred.push(Deferred {
            pgid,
            to,
            shard,
            bytes,
            stranded,
        });
        if stranded {
            self.strand(pgid);
        }
    }

    /// Does map `m` complete the merge of source `pgid` (the PG no longer exists in it)?
    fn merged_away(m: &OsdMap, pgid: PgT) -> bool {
        m.pools
            .get(&(pgid.pool as i64))
            .is_some_and(|p| pgid.seed >= p.pg_num)
    }

    /// A merge source the map completes while it cannot reach its target's core: stop hosting it here, keep its data
    /// unloaded. The target merges without it (incomplete, backfilled by its peers); this copy is never absorbed
    /// (it would overwrite newer data) and is deleted once obsolete. Hosting it here would make this core create a
    /// second instance of the target.
    fn strand(&mut self, pgid: PgT) {
        let held = self.held_instances();
        for spg in instances(&held, pgid) {
            self.log(format!(
                "pg {spg}: merge completes before it can move: stranded (unloaded, the merged PG is backfilled by its peers)"
            ));
            if self.pg.set.pg(spg).is_some() {
                let now = self.pg_mono();
                let acts = self.pg.set.detach(now, spg, &self.pg.store);
                self.pg_exec(acts);
            } else {
                self.pg.set.keep_unloaded(spg);
            }
            self.cl.mig.strands.insert(spg);
        }
    }

    /// PG instances this core holds: the loaded ones and every complete collection of its store (the store is the
    /// truth for data: an instance that is not loaded still has to travel with its PG).
    fn held_instances(&self) -> BTreeSet<SpgT> {
        let mut held: BTreeSet<SpgT> = self.pg.set.pgs().map(|(s, _)| *s).collect();
        held.extend(
            self.pg
                .store
                .list_pgs()
                .into_iter()
                .filter(|s| self.pg.store.mig_complete(*s)),
        );
        held
    }

    fn round_check(&mut self) {
        let mine_done = self.cl.mig.reserving.is_empty() && self.cl.mig.jobs.is_empty();
        let ctl = self.is_control();
        let n = self.cl.spec.n;
        let Some(r) = self.cl.mig.round.as_mut() else {
            return;
        };
        if !r.done_sent && r.started && mine_done {
            r.done_sent = true;
            if ctl {
                r.mask |= 1;
            } else {
                let (epoch, deferred, stay) = (r.epoch, r.deferred.clone(), r.stay.clone());
                self.xsend(
                    0,
                    XMsg::MigDone {
                        epoch,
                        deferred,
                        stay,
                    },
                );
            }
        }
        let Some(r) = self.cl.mig.round.as_ref() else {
            return;
        };
        let all = if n >= 64 { u64::MAX } else { (1u64 << n) - 1 };
        if ctl && r.done_sent && r.mask == all {
            let e = r.epoch;
            let deferred = r.deferred.clone();
            let stay = r.stay.clone();
            let moved: Vec<PgT> = r.moves.iter().map(|m| m.pgid).collect();
            if !stay.is_empty() {
                self.log(format!(
                    "map {e}: {} arriving PG(s) kept on their cores (a copy is there already)",
                    stay.len()
                ));
            }
            let m = &mut self.cl.mig;
            for pg in moved {
                m.deferred.remove(&pg);
            }
            for d in &deferred {
                m.deferred.insert(d.pgid, *d);
                m.deferrals += 1;
            }
            // every deferred move, not only this round's: the destinations keep borrowing for exactly these
            let list: Vec<Deferred> = m.deferred.values().copied().collect();
            self.xbcast(|| XMsg::Release {
                epoch: e,
                deferred: list.clone(),
                stay: stay.clone(),
            });
            self.finish_round(list, stay);
        }
    }

    /// Control: a core finished its part of the round (`deferred` = its moves that found no headroom, `stay` = its
    /// placements that found an instance).
    pub(crate) fn on_mig_done(
        &mut self,
        from: usize,
        epoch: u32,
        deferred: Vec<Deferred>,
        stay: Vec<PgT>,
    ) {
        match self.cl.mig.round.as_mut() {
            Some(r) if r.epoch == epoch => {
                r.mask |= 1 << from;
                r.deferred.extend(deferred);
                r.stay.extend(stay);
            }
            _ => {
                self.log(format!(
                    "core {from}: stray migration report for epoch {epoch}"
                ));
                return;
            }
        }
        self.round_check();
    }

    /// Worker: every core finished the round.
    pub(crate) fn on_mig_release(&mut self, epoch: u32, deferred: Vec<Deferred>, stay: Vec<PgT>) {
        if self.cl.mig.round.as_ref().is_some_and(|r| r.epoch == epoch) {
            self.finish_round(deferred, stay);
        }
    }

    /// The round is over everywhere: the moved PGs live on their new cores for everybody (the `deferred` ones, every
    /// deferred move of the OSD, and the `stay` ones stay), headroom left over is given back. A PG that moved in runs
    /// the source's hand-off first, then what this core held during the round goes on (in order), then the held map.
    fn finish_round(&mut self, deferred: Vec<Deferred>, stay: Vec<PgT>) {
        let Some(r) = self.cl.mig.round.take() else {
            return;
        };
        let stay: BTreeSet<PgT> = stay.into_iter().collect();
        let me = self.cl.spec.id;
        let mut stray = Vec::new();
        let mut arrived = Vec::new();
        for m in &r.moves {
            if deferred.iter().any(|d| d.pgid == m.pgid) || stay.contains(&m.pgid) {
                // stays where it is: whatever reached this core for it goes there
                if let Some(a) = self.cl.mig.arriving.remove(&m.pgid) {
                    stray.extend(a.first.into_iter().chain(a.later));
                }
                continue;
            }
            self.set_input_placement(m.pgid, m.shard);
            if m.from == me {
                self.pg.set.moved_unloaded(m.pgid);
            }
            if m.to == me {
                arrived.push(m.pgid);
            }
            // a link of this core whose messages reached the source may have state on the destination now (handed
            // over): its close is told there too
            for l in self.links.values_mut() {
                if l.fwd & (1 << m.from) != 0 {
                    l.fwd |= 1 << m.to;
                }
            }
        }
        self.pg.store.mig_release_all();
        self.on_mig_deferred(deferred);
        for pgid in arrived {
            if let Some(a) = self.cl.mig.arriving.get_mut(&pgid) {
                a.switched = true;
            }
            self.mig_arrived(pgid);
        }
        self.cl.mig.hold.clear();
        let held = std::mem::take(&mut self.cl.mig.hold_q);
        for m in stray.into_iter().chain(held) {
            // (a client link of this core that closed meanwhile has nobody to answer)
            if let XMsg::Op { conn, .. } | XMsg::BackoffAck { conn, .. } = &m
                && self.link_is_local(*conn)
                && !self.links.contains_key(conn)
            {
                continue;
            }
            self.pg_item(None, m);
        }
        self.drain_held();
    }

    // ------------------------------------------------------------ PG messages during a move

    /// Route PG message `m` (client op, backoff ack, copy read, pre-write pieces, peer PG message): `origin` = the core
    /// it came from, `None` = this core routes it by its own placement table. Held while its PG is in a round, queued
    /// while its PG leaves (source) or arrives (destination), else to the owner core.
    pub(crate) fn pg_item(&mut self, origin: Option<usize>, m: XMsg) {
        let Some(pgid) = item_pgid(&m).filter(|_| self.multi()) else {
            return self.pg_item_here(m);
        };
        let mig = &mut self.cl.mig;
        if origin.is_none() && mig.hold.contains(&pgid) {
            mig.hold_q.push(m);
            return;
        }
        if let Some(q) = mig.handoff.get_mut(&pgid) {
            q.push(m);
            return;
        }
        if let Some(a) = mig.arriving.get_mut(&pgid) {
            if origin == Some(a.from) && !a.handed {
                a.first.push(m);
            } else {
                a.later.push(m);
            }
            return;
        }
        let owner = self.pg.set.core_of(pgid);
        if owner == self.cl.spec.id {
            self.pg_item_here(m);
        } else {
            self.pg_item_send(owner, m);
        }
    }

    /// Is PG `pgid` part of a move (held, handed over by this core or arriving): its messages take [`Self::pg_item`].
    pub(crate) fn mig_busy(&self, pgid: PgT) -> bool {
        let m = &self.cl.mig;
        (!m.hold.is_empty() && m.hold.contains(&pgid))
            || (!m.handoff.is_empty() && m.handoff.contains_key(&pgid))
            || (!m.arriving.is_empty() && m.arriving.contains_key(&pgid))
    }

    /// Send PG message `m` to core `dst`; a client link of this core learns that `dst` may hold state of it (the
    /// link's close is told there).
    fn pg_item_send(&mut self, dst: usize, m: XMsg) {
        match &m {
            XMsg::Op { conn, .. } | XMsg::BackoffAck { conn, .. } => {
                if let Some(l) = self.links.get_mut(conn) {
                    l.fwd |= 1 << dst;
                }
                if matches!(m, XMsg::Op { .. }) {
                    self.cl.fwd_ops += 1;
                }
            }
            XMsg::Pg { .. } => self.cl.fwd_pg += 1,
            _ => {}
        }
        self.xsend(dst, m);
    }

    /// PG message `m` for a PG of this core.
    fn pg_item_here(&mut self, m: XMsg) {
        match m {
            XMsg::Op {
                conn,
                tid,
                info,
                op,
            } => {
                if !self.link_is_local(conn) {
                    self.cl.remote.entry(conn).or_insert(info);
                }
                self.pg_client_op(conn, tid, *op);
            }
            XMsg::CopyRead { conn, op } => self.copy_exec(conn, *op),
            XMsg::BackoffAck { conn, b } => self.pg_backoff_ack(conn, *b),
            XMsg::PrePiece {
                spg,
                watch,
                pieces,
                at,
                ..
            } => {
                self.pre_lag(at);
                self.pre_pieces(spg, watch, pieces);
            }
            XMsg::Pg {
                ingress,
                link,
                from,
                tid,
                prio,
                body,
            } => self.pg_deliver_body_with_ingress(link, from, tid, prio, body, ingress),
            // (only the PG messages above are routed here)
            other => debug_assert!(false, "{other:?} is no PG message"),
        }
    }

    /// Source: what waits on this core for PG `pgid` (its PG set queues, its parked client ops), oldest first.
    fn mig_take_items(&mut self, pgid: PgT) -> Vec<XMsg> {
        let mut items: Vec<XMsg> = self
            .pg
            .set
            .take_waiting(pgid)
            .into_iter()
            .map(|m| XMsg::Pg {
                ingress: m.ingress,
                link: 0,
                from: m.from,
                tid: m.tid,
                prio: m.prio,
                body: m.body,
            })
            .collect();
        for (conn, tid, op) in self.pg_take_parked(pgid) {
            let info = if self.link_is_local(conn) {
                self.links.get(&conn).and_then(|l| l.info.clone())
            } else {
                self.cl.remote.get(&conn).cloned()
            };
            match info {
                Some(info) => items.push(XMsg::Op {
                    conn,
                    tid,
                    info,
                    op: Box::new(op),
                }),
                None => self.pg_drop_op("connection gone", conn, tid, &op),
            }
        }
        items
    }

    /// Source: PG `pgid` lives on core `to` (store shard `shard`) from now on for this core: switch the placement (the
    /// lane its messages take, too), send what waited here for it, close the hand-off.
    fn mig_hand_over(&mut self, pgid: PgT, to: usize, shard: u32) {
        let items = self.cl.mig.handoff.remove(&pgid).unwrap_or_default();
        self.set_input_placement(pgid, shard);
        for m in items {
            self.pg_item_send(to, m);
        }
        self.xsend(to, XMsg::MigHandoff { pgid });
    }

    /// Destination: the source handed PG `pgid` over.
    pub(crate) fn on_mig_handoff(&mut self, pgid: PgT) {
        if let Some(a) = self.cl.mig.arriving.get_mut(&pgid) {
            a.handed = true;
        }
        self.mig_arrived(pgid);
    }

    /// Destination: run what waited for PG `pgid` once the source handed it over and this core switched.
    fn mig_arrived(&mut self, pgid: PgT) {
        if !self
            .cl
            .mig
            .arriving
            .get(&pgid)
            .is_some_and(|a| a.handed && a.switched)
        {
            return;
        }
        let Some(a) = self.cl.mig.arriving.remove(&pgid) else {
            return;
        };
        for m in a.first.into_iter().chain(a.later) {
            self.pg_item_here(m);
        }
    }

    /// A waiting client op goes on: here when this core hosts its PG (a source keeps running what waited for the PG
    /// until it hands it over), else routed again (a move between cores took the PG away while the op waited).
    pub(crate) fn reroute_op(&mut self, conn: u64, tid: u64, op: MOSDOp) {
        if self.pg.set.core_of(op.pgid.pgid) == self.cl.spec.id {
            self.pg_client_op(conn, tid, op);
        } else if self.link_is_local(conn) {
            self.route_client_op(conn, tid, op);
        } else if let Some(info) = self.cl.remote.get(&conn).cloned() {
            self.pg_item(
                None,
                XMsg::Op {
                    conn,
                    tid,
                    info,
                    op: Box::new(op),
                },
            );
        }
    }

    // ------------------------------------------------------------ export (source core)

    fn start_export(&mut self, spg: SpgT, dst: usize, shard: u32, seq: u64, bytes: u64) {
        if self.pg.set.pg(spg).is_some() {
            let now = self.pg_mono();
            let acts = self.pg.set.detach(now, spg, &self.pg.store);
            self.pg_exec(acts);
        }
        if let Err(e) = self.pg.store.mig_sync() {
            return self.store_failed(&e);
        }
        self.log(format!("pg {spg}: moving to core {dst} (shard {shard})"));
        self.cl.mig.jobs.push(Job {
            spg,
            dst,
            shard,
            seq,
            bytes,
            cur: ExportCursor::default(),
            in_flight: 0,
            exported: false,
        });
        self.export_pump(spg);
    }

    fn export_pump(&mut self, spg: SpgT) {
        loop {
            let Some(i) = self.cl.mig.jobs.iter().position(|j| j.spg == spg) else {
                return;
            };
            let j = &mut self.cl.mig.jobs[i];
            if j.exported || j.in_flight >= WINDOW {
                return;
            }
            match self.pg.store.mig_export(spg, &mut j.cur, BUDGET) {
                Ok((ops, last)) => {
                    j.in_flight += 1;
                    j.exported = last;
                    let (dst, shard, seq) = (j.dst, j.shard, j.seq);
                    self.xsend(
                        dst,
                        XMsg::MigData {
                            spg,
                            shard,
                            ops,
                            last,
                            seq,
                        },
                    );
                }
                Err(e) => return self.store_failed(&format!("export of pg {spg}: {e}")),
            }
        }
    }

    pub(crate) fn on_mig_credit(&mut self, spg: SpgT) {
        if let Some(j) = self.cl.mig.jobs.iter_mut().find(|j| j.spg == spg) {
            j.in_flight = j.in_flight.saturating_sub(1);
        }
        self.export_pump(spg);
    }

    /// The destination holds the PG durably (every instance: it acknowledges them together): delete ours; after the
    /// last instance the PG is handed over.
    pub(crate) fn on_mig_ack(&mut self, spg: SpgT) {
        let Some(i) = self.cl.mig.jobs.iter().position(|j| j.spg == spg) else {
            return;
        };
        let j = self.cl.mig.jobs.remove(i);
        if let Err(e) = self.pg.store.mig_remove(spg) {
            return self.store_failed(&format!("remove of moved pg {spg}: {e}"));
        }
        self.cl.mig.moved += 1;
        self.log(format!("pg {spg}: moved to core {}", j.dst));
        if !self.cl.mig.jobs.iter().any(|k| k.spg.pgid == spg.pgid) {
            self.mig_hand_over(spg.pgid, j.dst, j.shard);
        }
        self.round_check();
    }

    /// Source: the destination undid the import of `pgid` (no room after all; it imported `imported` payload bytes):
    /// serve the untouched copy here again (or strand it when the round's map completes its merge) and defer the move,
    /// asking for more room next time.
    pub(crate) fn on_mig_abort(&mut self, pgid: PgT, imported: u64) {
        let Some(j) = self.cl.mig.jobs.iter().find(|j| j.spg.pgid == pgid) else {
            return;
        };
        let (to, shard, bytes) = (j.dst, j.shard, j.bytes);
        let spgs: Vec<SpgT> = self
            .cl
            .mig
            .jobs
            .iter()
            .filter(|j| j.spg.pgid == pgid)
            .map(|j| j.spg)
            .collect();
        self.cl.mig.jobs.retain(|j| j.spg.pgid != pgid);
        self.log(format!(
            "pg {pgid}: no room at core {to} after {imported} B imported: move undone, deferred"
        ));
        self.mig_defer(pgid, to, shard, bytes + imported);
        if !self.cl.mig.strands.iter().any(|s| s.pgid == pgid) {
            let now = self.pg_mono();
            for spg in spgs {
                let acts = self.pg.set.adopt(now, spg, &self.pg.store);
                self.pg_exec(acts);
            }
        }
        // what waited for the PG during the copy runs here again, in order
        for m in self.cl.mig.handoff.remove(&pgid).unwrap_or_default() {
            self.pg_item_here(m);
        }
        self.round_check();
    }

    // ------------------------------------------------------------ import (destination core)

    pub(crate) fn on_mig_data(
        &mut self,
        from: usize,
        spg: SpgT,
        shard: u32,
        ops: Vec<MigOp>,
        last: bool,
        seq: u64,
    ) {
        if self.cl.boot_wait {
            // our boot answer (drops, placements) is still on its way from the control core
            let m = XMsg::MigData {
                spg,
                shard,
                ops,
                last,
                seq,
            };
            self.cl.mig.boot_early.push((from, m));
            return;
        }
        let pgid = spg.pgid;
        if !self
            .cl
            .mig
            .incoming
            .get(&pgid)
            .is_some_and(|i| i.seq == seq && !i.aborted)
        {
            return; // a batch of an undone attempt that was in flight
        }
        if self.cl.mig.placed.insert(spg) {
            self.set_input_placement(pgid, shard);
        }
        let size: u64 = ops.iter().map(|o| o.bytes() as u64).sum();
        match self.pg.store.mig_import(spg, ops) {
            Ok(()) => {}
            Err(MigImportError::NoSpace) => return self.mig_undo_import(pgid),
            Err(MigImportError::Failed(e)) => {
                return self.store_failed(&format!("import of pg {spg}: {e}"));
            }
        }
        self.xsend(from, XMsg::MigCredit { spg });
        let Some(inc) = self.cl.mig.incoming.get_mut(&pgid) else {
            return;
        };
        inc.imported += size;
        if !last {
            return;
        }
        if let Err(e) = self.pg.store.mig_sync() {
            return self.store_failed(&e);
        }
        let Some(inc) = self.cl.mig.incoming.get_mut(&pgid) else {
            return;
        };
        inc.done.push(spg);
        if inc.done.len() < inc.n {
            return; // the PG is adopted as a whole
        }
        let Some(inc) = self.cl.mig.incoming.remove(&pgid) else {
            return;
        };
        let now = self.pg_mono();
        for &s in &inc.done {
            self.cl.mig.placed.remove(&s);
            let acts = self.pg.set.adopt(now, s, &self.pg.store);
            self.pg_exec(acts);
        }
        for s in inc.done {
            self.xsend(from, XMsg::MigAck { spg: s });
        }
    }

    /// Destination: the store has no room for the copy of `pgid` after all: delete what was imported (nothing of it
    /// was adopted), restore the placement, tell the source.
    fn mig_undo_import(&mut self, pgid: PgT) {
        let Some(inc) = self.cl.mig.incoming.get_mut(&pgid) else {
            return;
        };
        inc.aborted = true;
        let (from, old_shard, imported) = (inc.from, inc.old_shard, inc.imported);
        let mut spgs: BTreeSet<SpgT> = inc.done.drain(..).collect();
        spgs.extend(instances(&self.cl.mig.placed, pgid));
        self.log(format!(
            "pg {pgid}: no room for the copy after {imported} B: import undone"
        ));
        for spg in spgs {
            self.cl.mig.placed.remove(&spg);
            if let Err(e) = self.pg.store.mig_remove(spg) {
                return self.store_failed(&format!("remove of undone import {spg}: {e}"));
            }
        }
        self.set_input_placement(pgid, old_shard);
        self.xsend(from, XMsg::MigAbort { pgid, imported });
    }

    // ------------------------------------------------------------ boot

    /// A core reported its stored PGs (control core; also its own).
    pub(crate) fn boot_note(&mut self, from: usize, lo: u32, pgs: Vec<BootPg>) {
        self.cl.mig.boot_in[from] = Some((lo, pgs));
        if self.cl.mig.boot_in.iter().all(Option::is_some) {
            self.boot_resolve();
        }
    }

    /// Control: copies on two cores, placement table, deferred and stranded merge sources; then every core gets its
    /// [`BootInfo`].
    fn boot_resolve(&mut self) {
        let n = self.cl.spec.n;
        let reports: Vec<BootReport> = self
            .cl
            .mig
            .boot_in
            .iter_mut()
            .map(|r| r.take().unwrap_or((u32::MAX, Vec::new())))
            .collect();
        let cur = self.epoch();
        let lo = reports.iter().map(|r| r.0).min().unwrap_or(cur).min(cur);
        let maps: Vec<Arc<OsdMap>> = if cur == 0 {
            Vec::new()
        } else {
            self.pg_load_maps(lo, cur)
                .into_iter()
                .map(Arc::new)
                .collect()
        };
        // the instances of each PG by core: an interrupted move leaves the PG on two cores
        let mut of_pg: BTreeMap<PgT, BTreeMap<usize, Vec<&BootPg>>> = BTreeMap::new();
        for (core, (_, pgs)) in reports.iter().enumerate() {
            for p in pgs {
                of_pg
                    .entry(p.spg.pgid)
                    .or_default()
                    .entry(core)
                    .or_default()
                    .push(p);
            }
        }
        let mut infos: Vec<BootInfo> = (0..n).map(|_| BootInfo::default()).collect();
        // winner: the core with every instance (the destination acknowledges only all of them, the source deletes
        // only after that), then the newer epoch (a stranded copy against a later split child), then the higher
        // migration generation (a complete copy whose source was not deleted yet), then the lower core
        let mut winner: BTreeMap<PgT, (usize, u32)> = BTreeMap::new();
        for (pg, cores) in &of_pg {
            let key = |c: &usize, v: &Vec<&BootPg>| {
                (
                    v.len(),
                    v.iter().map(|p| p.epoch).max(),
                    v.iter().map(|p| p.generation).max(),
                    std::cmp::Reverse(*c),
                )
            };
            let Some((core, inst)) = cores.iter().max_by_key(|(c, v)| key(c, v)) else {
                continue;
            };
            winner.insert(*pg, (*core, inst[0].shard));
            for (c, v) in cores.iter().filter(|(c, _)| *c != core) {
                infos[*c].drop.extend(v.iter().map(|p| p.spg));
            }
        }
        let owner = self.cl.spec.owner();
        let dflt = |p: PgT| owner.map_or(0, |o| o.default_shard(p.pool, p.seed));
        let placement: Vec<(PgT, u32)> = winner
            .iter()
            .filter(|(pg, w)| w.1 != dflt(**pg))
            .map(|(pg, w)| (*pg, w.1))
            .collect();
        // merge sources not on their target's core: moved by a runtime retry (headroom reserved like any move), or
        // stranded when the maps completed the merge (the target merges without them)
        let mut deferred = Vec::new();
        if let Some(last) = maps.last() {
            for (pg, &(core, _)) in &winner {
                let Some(pool) = last.pools.get(&(pg.pool as i64)) else {
                    continue;
                };
                let lo_n = place::pool_lo(pool);
                if pg.seed < lo_n {
                    continue;
                }
                let t = PgT::new(pg.pool, pgwire::pgmath::merge_target(pg.seed, lo_n));
                let tshard = winner.get(&t).map_or_else(|| dflt(t), |w| w.1);
                let to = tshard as usize % n;
                if to == core {
                    continue;
                }
                let stranded = pg.seed >= pool.pg_num;
                if stranded {
                    infos[core]
                        .strand
                        .extend(of_pg[pg][&core].iter().map(|p| p.spg));
                }
                self.log(format!(
                    "pg {pg}: merge source on core {core}, target on core {to}: {}",
                    if stranded {
                        "merge completed, stranded"
                    } else {
                        "move deferred to a runtime retry"
                    }
                ));
                deferred.push(Deferred {
                    pgid: *pg,
                    to,
                    shard: tshard,
                    bytes: 0,
                    stranded,
                });
            }
        }
        self.cl.mig.deferrals += deferred.len() as u64;
        let held: BTreeSet<u64> = of_pg.keys().map(|pg| pg.pool).collect();
        for info in infos.iter_mut() {
            info.held_pools = held.iter().copied().collect();
            info.maps = maps.clone();
            info.placement = placement.clone();
            info.deferred = deferred.clone();
        }
        let own = infos.remove(0);
        for (i, info) in infos.into_iter().enumerate() {
            self.xsend(i + 1, XMsg::Boot(Box::new(info)));
        }
        self.worker_boot(own);
    }

    /// The boot answer arrived (worker) / was computed (control): drop the losing copies, learn placements and
    /// deferrals, keep stranded sources unloaded, load the PGs.
    pub(crate) fn worker_boot(&mut self, info: BootInfo) {
        self.cl.boot_wait = false;
        if let Some(last) = info.maps.last()
            && self.epoch() < last.epoch
        {
            self.map = Some(last.clone());
        }
        self.pg.set.note_held_pools(info.held_pools.iter().copied());
        for &spg in &info.drop {
            self.log(format!(
                "pg {spg}: copy of a PG that lives on another core, deleting"
            ));
            if let Err(e) = self.pg.store.mig_remove(spg) {
                return self.store_failed(&format!("remove duplicate pg {spg}: {e}"));
            }
        }
        for (pg, sh) in &info.placement {
            self.set_input_placement(*pg, *sh);
        }
        for &spg in &info.strand {
            self.log(format!(
                "pg {spg}: stranded merge source: not loaded, deleted once the merged PG is complete here"
            ));
            self.pg.set.keep_unloaded(spg);
            self.cl.mig.strands.insert(spg);
        }
        self.on_mig_deferred(info.deferred);
        self.cl.mig.applied = info.maps.last().cloned();
        self.pg_boot_with(info.maps);
        for (from, m) in std::mem::take(&mut self.cl.mig.boot_early) {
            match m {
                XMsg::MigReserve {
                    pgid,
                    shard,
                    bytes,
                    seq,
                    n,
                } => self.on_mig_reserve(from, pgid, shard, bytes, seq, n),
                XMsg::MigData {
                    spg,
                    shard,
                    ops,
                    last,
                    seq,
                } => self.on_mig_data(from, spg, shard, ops, last, seq),
                _ => {}
            }
        }
        self.drain_held();
    }
}
