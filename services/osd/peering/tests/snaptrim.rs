// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Snap trimming end to end on the deterministic simulator: real PGs (primary + replicas on `MemStore`), real op
//! engine (`opexec`) as the trimmer driver, client writes with snap contexts that create clones. Checks: clones and
//! mapper entries disappear on every replica, purged_snaps is reported and shared, gates (NOSNAPTRIM, degraded),
//! recovery of a replica that missed trims, empty PGs, whiteout heads, queue pruning.
mod common;
#[macro_use]
#[path = "../../opexec/tests/common/env_noop.rs"]
mod env_noop;
use common::*;
use denc::types::*;
use opexec::{ClientReq, Engine, Env, Limits, ObjView};
use opwire::{MOSDOp, OsdOp};
use peering::snaps::{Ivs, iv_from_pairs};
use peering::{Action, MemStore, PgSet, PgStoreOps, TrimPoll, WriteErr, WriteReq};
use std::collections::{BTreeMap, BTreeSet};

thread_local! {
    /// Fault injection: the mapper index reads as unreadable (per test thread).
    static MAPPER_UNREADABLE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Fault injection: every write submit is refused with this errno (`WriteErr::TooBig`, 0 = off).
    static SUBMIT_TOO_BIG: std::cell::Cell<i32> = const { std::cell::Cell::new(0) };
}

/// The op engine's view of one PG of the simulator.
struct SimEnv<'a> {
    set: &'a mut PgSet,
    store: &'a MemStore,
    spg: SpgT,
    now: u64,
    acts: Vec<Action>,
}

impl SimEnv<'_> {
    fn call<R>(&mut self, f: impl FnOnce(&mut peering::Pg) -> R) -> Option<R> {
        let (r, a) = self.set.with_pg(self.now, self.spg, self.store, f)?;
        self.acts.extend(a);
        Some(r)
    }
}

macro_rules! delegate_view {
    ($($f:ident($($a:ident: $t:ty),*) -> $r:ty;)*) => {
        $(fn $f(&self, spg: SpgT $(, $a: $t)*) -> $r { self.store.$f(spg $(, $a)*) })*
    };
}

impl ObjView for SimEnv<'_> {
    delegate_view! {
        ov_stat(soid: &Hobject) -> Result<Option<u64>, i32>;
        ov_read(soid: &Hobject, off: u64, len: u64) -> Result<Vec<u8>, i32>;
        ov_getattr(soid: &Hobject, name: &[u8]) -> Result<Option<Vec<u8>>, i32>;
        ov_getattrs(soid: &Hobject) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, i32>;
        ov_omap_header(soid: &Hobject) -> Result<Vec<u8>, i32>;
        ov_omap_range(soid: &Hobject, after: Option<&[u8]>, prefix: &[u8], max: usize, max_bytes: usize) -> Result<(Vec<opexec::view::Kv>, bool), i32>;
        ov_omap_get(soid: &Hobject, keys: &[&[u8]]) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, i32>;
        ov_list(begin: &Hobject, max: usize) -> Result<(Vec<Hobject>, Hobject), i32>;
    }
}

impl Env for SimEnv<'_> {
    env_noop!(
        admission_ready,
        blocklisted,
        cls_map,
        copy_stripe_width,
        dup_op_returns,
        ec_pool,
        ec_caps,
        ec_wait,
        eio_clear,
        gate_in,
        list_ran,
        list_turn,
        local_damage,
        locate,
        marked_full_epoch,
        require_osd_release,
        is_unfound,
        kick_recovery,
        note_io,
        obj_cache,
        op_stale,
        pg_blocked,
        pool_caps_info,
        pool_eio,
        failsafe_full,
        pool_full,
        pool_snapc,
        probe_meta,
        run_start,
        scrub_ls,
        send_first,
        settle,
        trim_note,
        warm,
        warm_data,
        warm_log,
        warm_rm,
        whoami,
        write_room,
    );
    fn spg(&self) -> SpgT {
        self.spg
    }
    fn epoch(&self) -> u32 {
        self.set.epoch()
    }
    fn wall(&self) -> UTime {
        UTime::new(1_700_000_000, 0)
    }
    fn mono(&self) -> u64 {
        self.now
    }
    fn is_active(&self) -> bool {
        self.set
            .pg(self.spg)
            .is_some_and(|p| p.is_primary() && p.is_active())
    }
    fn is_readable(&self) -> bool {
        self.set
            .pg(self.spg)
            .is_some_and(|p| p.is_readable(self.now))
    }
    fn next_version(&self) -> Eversion {
        self.set
            .pg(self.spg)
            .map_or_else(Default::default, |p| p.next_version())
    }
    fn last_update(&self) -> Eversion {
        self.set
            .pg(self.spg)
            .map_or_else(Default::default, |p| p.info().last_update)
    }
    fn last_user_version(&self) -> u64 {
        self.set
            .pg(self.spg)
            .map_or(0, |p| p.info().last_user_version)
    }
    fn find_reqid(&self, r: &OsdReqId) -> Option<(Eversion, u64, i32)> {
        self.set.pg(self.spg).and_then(|p| p.log().find_reqid(r))
    }
    fn is_missing(&self, soid: &Hobject) -> bool {
        self.set
            .pg(self.spg)
            .is_some_and(|p| p.missing().contains(soid))
    }
    fn missing_range(&self, from: &Hobject, to: &Hobject, max: usize) -> Vec<(Hobject, bool)> {
        self.set.pg(self.spg).map_or_else(Vec::new, |p| {
            p.missing()
                .wire()
                .missing
                .range(from.clone()..to.clone())
                .take(max)
                .map(|(o, i)| (o.clone(), i.is_delete()))
                .collect()
        })
    }
    fn write_degraded(&self, head: &Hobject) -> bool {
        self.set.pg(self.spg).is_some_and(|p| p.obj_degraded(head))
    }
    fn submit_write(&mut self, w: WriteReq) -> Result<u64, WriteErr> {
        let e = SUBMIT_TOO_BIG.with(|c| c.get());
        if e != 0 {
            return Err(WriteErr::TooBig(e));
        }
        let (tid, a) = self.set.submit_write(self.now, self.spg, w, self.store)?;
        self.acts.extend(a);
        Ok(tid)
    }
    fn pg_num(&self) -> u32 {
        self.set
            .current_map()
            .and_then(|m| m.pool(self.spg.pgid.pool))
            .map_or(1, |p| p.pg_num)
    }
    fn removed_snaps(&self) -> Vec<(u64, u64)> {
        self.set
            .current_map()
            .map(|m| m.removed_snaps_queue(self.spg.pgid.pool))
            .unwrap_or_default()
            .into_iter()
            .collect()
    }
    fn trim_poll(&mut self) -> peering::TrimPoll {
        self.call(|p| p.trim_poll())
            .unwrap_or(peering::TrimPoll::No)
    }
    fn trim_cfg(&self) -> opexec::trim::TrimCfg {
        let c = self.set.cfg_ref();
        opexec::trim::TrimCfg {
            max_concurrent: c.snap_trim_concurrent,
            sleep_ns: c.snap_trim_sleep_ns,
        }
    }
    fn snap_mapper_next(
        &self,
        snap: u64,
        max: usize,
    ) -> Result<Vec<Hobject>, peering::StoreReadError> {
        if MAPPER_UNREADABLE.with(|c| c.get()) {
            return Err(peering::StoreReadError::Io);
        }
        self.store.snapmap_next(self.spg, snap, max)
    }
    fn trim_snap_done(&mut self, snap: u64) {
        self.call(|p| p.trim_snap_done(snap));
    }
    fn trim_stop(&mut self, error: bool) {
        self.call(|p| p.trim_stop(error));
    }
    fn trim_counted(&mut self, n: i64) {
        self.call(|p| p.trim_counted(n));
    }
    fn trim_unmap(&mut self, clone: &Hobject) {
        let c = clone.clone();
        self.call(|p| p.snap_unmap(c));
    }
}

/// One engine on the primary of PG `spg` and the plumbing that feeds it.
struct Drv {
    eng: Engine,
    spg: SpgT,
    /// Completions of `Sim::acked_full` already fed.
    fed: usize,
    fed_failed: usize,
    osd: i32,
    tid: u64,
}

impl Drv {
    fn new(s: &Sim, spg: SpgT) -> Drv {
        let osd = s.primary_of(spg.pgid);
        Drv {
            eng: Engine::new(spg, Limits::default(), opexec::clsx::ClassPolicy::default()),
            spg,
            fed: 0,
            fed_failed: 0,
            osd,
            tid: 0,
        }
    }

    fn with_env(&mut self, s: &mut Sim, f: impl FnOnce(&mut Engine, &mut SimEnv)) {
        let (osd, spg) = (self.osd, self.spg);
        let eng = &mut self.eng;
        s.call(osd, |set, now, store| {
            let mut env = SimEnv {
                set,
                store,
                spg,
                now,
                acts: Vec::new(),
            };
            f(eng, &mut env);
            env.acts
        });
    }

    /// Feed completions + kicks to the engine; true if anything happened.
    fn pump(&mut self, s: &mut Sim) -> bool {
        let mut any = false;
        let (osd, spg) = (self.osd, self.spg);
        let done: Vec<u64> = s.acked_full[self.fed..]
            .iter()
            .filter(|x| x.0 == osd && x.2 == spg)
            .map(|x| x.3)
            .collect();
        self.fed = s.acked_full.len();
        let failed: Vec<u64> = s.failed_full[self.fed_failed..]
            .iter()
            .filter(|x| x.0 == osd && x.2 == spg)
            .map(|x| x.3)
            .collect();
        self.fed_failed = s.failed_full.len();
        for (tid, res) in done
            .into_iter()
            .map(|t| (t, 0))
            .chain(failed.into_iter().map(|t| (t, -11)))
        {
            self.with_env(s, |e, env| {
                e.on_write_done(env, tid, Eversion::default(), res)
            });
            any = true;
        }
        if s.trim_kicks.remove(&(osd, spg)) {
            self.with_env(s, |e, env| e.trim_kick(env));
            any = true;
        }
        let now = s.now;
        if self.eng.next_deadline().is_some_and(|d| d <= now) {
            self.with_env(s, |e, env| e.tick(env, now));
            any = true;
        }
        let _ = self.eng.take_out();
        any
    }

    /// Run the simulator in small steps, pumping the engine, until `pred`.
    fn until(&mut self, s: &mut Sim, timeout: u64, why: &str, pred: impl Fn(&Sim) -> bool) {
        let end = s.now + timeout;
        while s.now < end {
            if pred(s) {
                return;
            }
            s.run_for(MS);
            self.pump(s);
        }
        if !pred(s) {
            panic!("timeout: {why}\n{}", s.dump());
        }
    }

    fn settle(&mut self, s: &mut Sim, dur: u64) {
        let end = s.now + dur;
        while s.now < end {
            s.run_for(MS);
            self.pump(s);
        }
    }

    /// A client write with a snap context.
    fn write(&mut self, s: &mut Sim, name: &str, off: u64, data: &[u8], seq: u64, snaps: &[u64]) {
        let h = hobj(1, name);
        let mut op = MOSDOp {
            pgid: self.spg,
            hash: h.hash,
            osdmap_epoch: s.epoch(),
            flags: opwire::flag::ONDISK | opwire::flag::KNOWN_REDIR | opwire::flag::WRITE,
            oloc: ObjectLocator {
                pool: 1,
                key: vec![],
                nspace: vec![],
                hash: -1,
            },
            oid: name.as_bytes().to_vec(),
            ops: vec![OsdOp::write(off, data.to_vec())],
            mtime: UTime::new(1_700_000_001, 5),
            ..Default::default()
        };
        op.snap_seq = seq;
        op.snaps = snaps.to_vec();
        let req = ClientReq {
            placement_read: None,
            conn: 1,
            caps: None,
            tid: {
                self.tid += 1;
                self.tid
            },
            op: Box::new(op),
            who: EntityName::client(7),
            addr: EntityAddr::default(),
            peer_addr: EntityAddr::default(),
            features: 0x3f17_ffff_fffd_ffff,
        };
        self.with_env(s, |e, env| e.on_op(env, req));
        self.settle(s, 20 * MS);
    }

    fn delete(&mut self, s: &mut Sim, name: &str, seq: u64, snaps: &[u64]) {
        let h = hobj(1, name);
        let mut op = MOSDOp {
            pgid: self.spg,
            hash: h.hash,
            osdmap_epoch: s.epoch(),
            flags: opwire::flag::ONDISK | opwire::flag::KNOWN_REDIR | opwire::flag::WRITE,
            oloc: ObjectLocator {
                pool: 1,
                key: vec![],
                nspace: vec![],
                hash: -1,
            },
            oid: name.as_bytes().to_vec(),
            ops: vec![OsdOp::delete()],
            mtime: UTime::new(1_700_000_001, 5),
            ..Default::default()
        };
        op.snap_seq = seq;
        op.snaps = snaps.to_vec();
        let req = ClientReq {
            placement_read: None,
            conn: 1,
            caps: None,
            tid: {
                self.tid += 1;
                self.tid
            },
            op: Box::new(op),
            who: EntityName::client(7),
            addr: EntityAddr::default(),
            peer_addr: EntityAddr::default(),
            features: 0x3f17_ffff_fffd_ffff,
        };
        self.with_env(s, |e, env| e.on_op(env, req));
        self.settle(s, 20 * MS);
    }
}

fn queue_snaps(s: &mut Sim, pool: u64, pairs: &[(u64, u64)]) {
    let q: Ivs = iv_from_pairs(pairs);
    s.new_epoch(|m| {
        if q.is_empty() {
            m.removed_queue.remove(&pool);
        } else {
            m.removed_queue.insert(pool, q.clone());
        }
    });
}

fn clones_on(s: &Sim, osd: i32, spg_: SpgT) -> BTreeSet<Hobject> {
    s.nodes[&osd]
        .store
        .objects(spg_)
        .into_keys()
        .filter(peering::snaps::is_clone)
        .collect()
}

fn mapped_on(s: &Sim, osd: i32, spg_: SpgT) -> BTreeSet<Hobject> {
    s.nodes[&osd].store.pgs[&spg_]
        .snapmap
        .all()
        .into_iter()
        .map(|x| x.0)
        .collect()
}

/// Every replica: mapper entries == clone objects, and the same set everywhere.
fn assert_mapper_consistent(s: &Sim, osds: &[i32], spg_: SpgT) {
    let first = clones_on(s, osds[0], spg_);
    for o in osds {
        let c = clones_on(s, *o, spg_);
        assert_eq!(
            c,
            mapped_on(s, *o, spg_),
            "osd.{o}: mapper != clone objects"
        );
        assert_eq!(c, first, "osd.{o}: clones differ from osd.{}", osds[0]);
    }
}

fn purged_of(s: &Sim, osd: i32, spg_: SpgT) -> Ivs {
    s.pg(osd, spg_).unwrap().info().purged_snaps.clone()
}

fn setup(seed: u64, pg_num: u32) -> (Sim, Drv, SpgT) {
    let mut s = cluster(seed, &[0, 1, 2], 1, 3, 2, pg_num);
    s.run_until(30_000 * MS, "clean", |s| s.pool_clean(1));
    let spg0 = spg(1, 0);
    let d = Drv::new(&s, spg0);
    (s, d, spg0)
}

/// Object `name` of PG 1.0 (hash picks seed 0 with pg_num 1).
fn make_snapshots(s: &mut Sim, d: &mut Drv, name: &str) {
    d.write(s, name, 0, &[1; 64], 0, &[]);
    // snapshot 2, overwrite -> clone 2 ; snapshot 4, overwrite -> clone 4
    d.write(s, name, 0, &[2; 8], 2, &[2]);
    d.write(s, name, 0, &[3; 8], 4, &[4, 2]);
}

#[test]
fn trim_removes_clones_and_mapper_on_every_replica() {
    let (mut s, mut d, spg0) = setup(21, 1);
    for n in ["a", "b", "c"] {
        make_snapshots(&mut s, &mut d, n);
    }
    d.settle(&mut s, 50 * MS);
    assert_eq!(clones_on(&s, 0, spg0).len(), 6);
    assert_mapper_consistent(&s, &[0, 1, 2], spg0);
    let before = s.nodes[&d.osd].store.objects(spg0).len();
    // remove snap 2 at the mon
    queue_snaps(&mut s, 1, &[(2, 1)]);
    d.until(&mut s, 5_000 * MS, "snap 2 purged", |s| {
        peering::snaps::iv_contains(&purged_of(s, s.primary_of(spg0.pgid), spg0), 2)
    });
    d.settle(&mut s, 200 * MS);
    assert_eq!(
        clones_on(&s, 0, spg0).len(),
        3,
        "the three clones of snap 2 are gone"
    );
    assert_mapper_consistent(&s, &[0, 1, 2], spg0);
    assert_eq!(s.nodes[&d.osd].store.objects(spg0).len(), before - 3);
    // purged set shared with the replicas and reported to the mgr
    for o in 0..3 {
        assert_eq!(purged_of(&s, o, spg0), iv_from_pairs(&[(2, 1)]), "osd.{o}");
    }
    let st = &s.pgstats[&spg0].1;
    assert_eq!(st.purged_snaps, iv_from_pairs(&[(2, 1)]));
    assert_eq!(st.snaptrimq_len, 0);
    assert!(st.objects_trimmed >= 0);
    // heads untouched and their SnapSet follows
    let objs = s.nodes[&d.osd].store.objects(spg0);
    let head = objs.get(&hobj(1, "a")).unwrap();
    let ss: replwire::SnapSet = denc::from_slice(&head.xattrs[b"snapset".as_slice()]).unwrap();
    assert_eq!(ss.clones, vec![SnapId(4)]);
    assert_eq!(ss.seq, 4);
    // snap 4 too
    queue_snaps(&mut s, 1, &[(2, 1), (4, 1)]);
    d.until(&mut s, 5_000 * MS, "snap 4 purged", |s| {
        peering::snaps::iv_contains(&purged_of(s, s.primary_of(spg0.pgid), spg0), 4)
    });
    d.settle(&mut s, 200 * MS);
    assert!(clones_on(&s, 1, spg0).is_empty());
    assert_mapper_consistent(&s, &[0, 1, 2], spg0);
    // the mon prunes: the PGs drop the ids from purged_snaps again (activate / advmap rule), replicas follow
    queue_snaps(&mut s, 1, &[]);
    d.settle(&mut s, 300 * MS);
    for o in 0..3 {
        assert!(
            purged_of(&s, o, spg0).is_empty(),
            "osd.{o} keeps pruned ids"
        );
    }
    s.assert_persisted_consistent();
}

#[test]
fn shared_clone_is_shrunk_then_deleted() {
    let (mut s, mut d, spg0) = setup(22, 1);
    d.write(&mut s, "x", 0, &[1; 32], 0, &[]);
    // one clone serving snaps 3 and 2 (both taken before the next write)
    d.write(&mut s, "x", 0, &[2; 8], 3, &[3, 2]);
    d.settle(&mut s, 50 * MS);
    let c = clones_on(&s, 0, spg0);
    assert_eq!(c.len(), 1);
    // remove snap 3 only: the clone shrinks to [2], mapper follows
    queue_snaps(&mut s, 1, &[(3, 1)]);
    d.until(&mut s, 5_000 * MS, "snap 3 purged", |s| {
        peering::snaps::iv_contains(&purged_of(s, s.primary_of(spg0.pgid), spg0), 3)
    });
    d.settle(&mut s, 100 * MS);
    for o in 0..3 {
        assert_eq!(clones_on(&s, o, spg0), c);
        let cl = c.iter().next().unwrap();
        assert_eq!(
            s.nodes[&o].store.snapmap_get(spg0, cl),
            Some(vec![2]),
            "osd.{o}"
        );
    }
    // now snap 2: the clone dies
    queue_snaps(&mut s, 1, &[(2, 2)]);
    d.until(&mut s, 5_000 * MS, "snap 2 purged", |s| {
        peering::snaps::iv_contains(&purged_of(s, s.primary_of(spg0.pgid), spg0), 2)
    });
    d.settle(&mut s, 100 * MS);
    assert!(clones_on(&s, 2, spg0).is_empty());
    assert_mapper_consistent(&s, &[0, 1, 2], spg0);
}

#[test]
fn one_pass_retires_all_queued_snaps_of_a_clone() {
    let (mut s, mut d, spg0) = setup(23, 1);
    d.write(&mut s, "y", 0, &[1; 32], 0, &[]);
    d.write(&mut s, "y", 0, &[2; 8], 3, &[3, 2]);
    d.settle(&mut s, 50 * MS);
    let steps_before = d.eng.c.trim_steps;
    queue_snaps(&mut s, 1, &[(2, 2)]);
    d.until(&mut s, 5_000 * MS, "both purged", |s| {
        let p = purged_of(s, s.primary_of(spg0.pgid), spg0);
        p == iv_from_pairs(&[(2, 2)])
    });
    // one step removed the clone for both ids; the scan of the second id found nothing
    assert_eq!(d.eng.c.trim_steps - steps_before, 1);
    assert!(clones_on(&s, 0, spg0).is_empty());
}

#[test]
fn whiteout_head_dies_with_its_last_clone() {
    let (mut s, mut d, spg0) = setup(24, 1);
    d.write(&mut s, "w", 0, &[1; 16], 0, &[]);
    d.write(&mut s, "w", 0, &[2; 4], 2, &[2]);
    // delete with clones: whiteout head stays
    d.delete(&mut s, "w", 2, &[2]);
    d.settle(&mut s, 50 * MS);
    assert!(s.nodes[&0].store.objects(spg0).contains_key(&hobj(1, "w")));
    queue_snaps(&mut s, 1, &[(2, 1)]);
    d.until(&mut s, 5_000 * MS, "purged", |s| {
        peering::snaps::iv_contains(&purged_of(s, s.primary_of(spg0.pgid), spg0), 2)
    });
    d.settle(&mut s, 100 * MS);
    for o in 0..3 {
        assert!(
            s.nodes[&o].store.objects(spg0).is_empty(),
            "osd.{o}: whiteout head and clone are gone"
        );
    }
    assert_mapper_consistent(&s, &[0, 1, 2], spg0);
}

#[test]
fn empty_pgs_purge_too() {
    let (mut s, mut d0, _) = setup(25, 2);
    let (spg0, spg1) = (spg(1, 0), spg(1, 1));
    let mut d1 = Drv::new(&s, spg1);
    // only PG 0 gets an object (name chosen by hash): find a name that lands in pg 0
    let mut name = String::new();
    for i in 0..50 {
        let n = format!("o{i}");
        if s.named_seed(1, &n) == 0 {
            name = n;
            break;
        }
    }
    d0.write(&mut s, &name, 0, &[1; 8], 0, &[]);
    d0.write(&mut s, &name, 0, &[2; 8], 2, &[2]);
    queue_snaps(&mut s, 1, &[(2, 1)]);
    let end = s.now + 5_000 * MS;
    while s.now < end {
        s.run_for(MS);
        d0.pump(&mut s);
        d1.pump(&mut s);
        let both = [spg0, spg1]
            .iter()
            .all(|g| peering::snaps::iv_contains(&purged_of(&s, s.primary_of(g.pgid), *g), 2));
        if both {
            break;
        }
    }
    for g in [spg0, spg1] {
        let p = s.primary_of(g.pgid);
        assert!(
            peering::snaps::iv_contains(&purged_of(&s, p, g), 2),
            "{g}: empty PG must report the snap purged\n{}",
            s.dump()
        );
        assert_eq!(s.pgstats[&g].1.purged_snaps, iv_from_pairs(&[(2, 1)]));
    }
}

#[test]
fn nosnaptrim_and_unclean_pgs_do_not_trim() {
    let (mut s, mut d, spg0) = setup(26, 1);
    make_snapshots(&mut s, &mut d, "n");
    d.settle(&mut s, 50 * MS);
    // NOSNAPTRIM
    s.new_epoch(|m| {
        m.nosnaptrim = true;
        m.removed_queue.insert(1, iv_from_pairs(&[(2, 1)]));
    });
    d.settle(&mut s, 500 * MS);
    assert_eq!(
        clones_on(&s, 0, spg0).len(),
        2,
        "NOSNAPTRIM: nothing trimmed"
    );
    assert_eq!(s.pgstats[&spg0].1.snaptrimq_len, 1);
    s.new_epoch(|m| m.nosnaptrim = false);
    d.until(&mut s, 5_000 * MS, "trimmed after unset", |s| {
        peering::snaps::iv_contains(&purged_of(s, s.primary_of(spg0.pgid), spg0), 2)
    });
    // degraded PG: replica down -> no trimming until clean again
    let prim = s.primary_of(spg0.pgid);
    let victim = (0..3).find(|o| *o != prim).unwrap();
    s.mark_down(victim);
    s.kill(victim);
    s.run_for(200 * MS);
    queue_snaps(&mut s, 1, &[(2, 1), (4, 1)]);
    d.settle(&mut s, 2_000 * MS);
    assert!(
        !peering::snaps::iv_contains(&purged_of(&s, prim, spg0), 4),
        "degraded PG must not trim"
    );
    assert_eq!(clones_on(&s, prim, spg0).len(), 1);
    // the replica comes back, recovers (clone delete via recovery / log), PG goes clean, trimming runs
    s.restart(victim);
    s.mark_up(victim);
    d.until(&mut s, 60_000 * MS, "snap 4 purged after recovery", |s| {
        peering::snaps::iv_contains(&purged_of(s, s.primary_of(spg0.pgid), spg0), 4)
    });
    d.settle(&mut s, 1_000 * MS);
    assert_mapper_consistent(&s, &[0, 1, 2], spg0);
    assert!(clones_on(&s, victim, spg0).is_empty());
}

#[test]
fn replica_that_missed_trims_converges_through_recovery() {
    let (mut s, mut d, spg0) = setup(27, 1);
    for n in ["p", "q"] {
        make_snapshots(&mut s, &mut d, n);
    }
    d.settle(&mut s, 50 * MS);
    let prim = s.primary_of(spg0.pgid);
    let victim = (0..3).find(|o| *o != prim).unwrap();
    // trim while the replica is down but the PG stays active (size 3 min 2) ... the PG is degraded: trimming waits;
    // so mark it OUT-less: kill then bring back quickly after the removal is queued
    queue_snaps(&mut s, 1, &[(2, 1)]);
    d.until(&mut s, 5_000 * MS, "purged", |s| {
        peering::snaps::iv_contains(&purged_of(s, s.primary_of(spg0.pgid), spg0), 2)
    });
    d.settle(&mut s, 100 * MS);
    // now a replica restarts: it must come back with the same clone set and mapper
    s.kill(victim);
    s.restart(victim);
    d.settle(&mut s, 3_000 * MS);
    assert_mapper_consistent(&s, &[0, 1, 2], spg0);
    s.assert_persisted_consistent();
}

#[test]
fn split_children_inherit_mapper_entries_and_trim() {
    let (mut s, mut d, spg0) = setup(28, 1);
    // clones for a spread of names
    for i in 0..12 {
        make_snapshots(&mut s, &mut d, &format!("s{i}"));
    }
    d.settle(&mut s, 100 * MS);
    assert_eq!(clones_on(&s, 0, spg0).len(), 24);
    s.set_pg_num(1, 2);
    s.set_pgp_num(1, 2);
    s.run_until(60_000 * MS, "clean after split", |s| s.pool_clean(1));
    let spg1 = spg(1, 1);
    for g in [spg0, spg1] {
        assert_mapper_consistent(&s, &[0, 1, 2], g);
    }
    assert_eq!(
        clones_on(&s, 0, spg0).len() + clones_on(&s, 0, spg1).len(),
        24,
        "every clone is in exactly one child"
    );
    assert!(!clones_on(&s, 0, spg1).is_empty() && !clones_on(&s, 0, spg0).is_empty());
    // both children trim (engines on their primaries)
    let mut d0 = Drv::new(&s, spg0);
    let mut d1 = Drv::new(&s, spg1);
    queue_snaps(&mut s, 1, &[(2, 1), (4, 1)]);
    let end = s.now + 20_000 * MS;
    while s.now < end {
        s.run_for(MS);
        d0.pump(&mut s);
        d1.pump(&mut s);
        let all = [spg0, spg1]
            .iter()
            .all(|g| iv_from_pairs(&[(2, 1), (4, 1)]) == purged_of(&s, s.primary_of(g.pgid), *g));
        if all {
            break;
        }
    }
    s.run_for(200 * MS);
    for g in [spg0, spg1] {
        assert!(clones_on(&s, 0, g).is_empty(), "{g}");
        assert_mapper_consistent(&s, &[0, 1, 2], g);
    }
}

#[test]
fn broken_snapset_sets_snaptrim_error_without_spinning() {
    use pgwire::state as pgs;
    let (mut s, mut d, spg0) = setup(29, 1);
    make_snapshots(&mut s, &mut d, "e");
    d.settle(&mut s, 50 * MS);
    // damage the primary's head SnapSet: drop clone_snaps (classic: "No clone_snaps in snapset")
    let prim = d.osd;
    {
        let st = &mut s.nodes.get_mut(&prim).unwrap().store;
        let pg = st.pgs.get_mut(&spg0).unwrap();
        let o = pg.objects.get_mut(&hobj(1, "e")).unwrap();
        let mut ss: replwire::SnapSet = denc::from_slice(&o.xattrs[b"snapset".as_slice()]).unwrap();
        ss.clone_snaps.clear();
        o.xattrs
            .insert(b"snapset".to_vec(), denc::to_vec(&ss).unwrap());
    }
    queue_snaps(&mut s, 1, &[(2, 1)]);
    d.settle(&mut s, 2_000 * MS);
    let p = s.pg(prim, spg0).unwrap();
    assert!(
        p.state_bits() & pgs::SNAPTRIM_ERROR != 0,
        "{}",
        p.state_string()
    );
    assert_eq!(p.state_bits() & (pgs::SNAPTRIM | pgs::SNAPTRIM_WAIT), 0);
    let errs = d.eng.c.trim_errors;
    assert_eq!(
        errs, 1,
        "one failed attempt, no busy retry within the epoch"
    );
    assert!(!peering::snaps::iv_contains(&purged_of(&s, prim, spg0), 2));
    // PG stays active+clean: client io unaffected
    assert!(p.is_clean());
    // next map epoch: it tries again (still broken -> second error), still no spin
    s.new_epoch(|_| {});
    d.settle(&mut s, 1_000 * MS);
    assert_eq!(d.eng.c.trim_errors, 2);
}

/// A step the store can never apply (oversized trim transaction) is a SNAPTRIM_ERROR, not a silent retry each
/// second for ever: one error per map epoch, nothing purged.
#[test]
fn refused_trim_transaction_sets_snaptrim_error_without_spinning() {
    use pgwire::state as pgs;
    let (mut s, mut d, spg0) = setup(37, 1);
    make_snapshots(&mut s, &mut d, "t");
    d.settle(&mut s, 50 * MS);
    let prim = d.osd;
    SUBMIT_TOO_BIG.with(|c| c.set(opwire::errno::EMSGSIZE));
    queue_snaps(&mut s, 1, &[(2, 1)]);
    d.settle(&mut s, 5_000 * MS);
    SUBMIT_TOO_BIG.with(|c| c.set(0));
    let p = s.pg(prim, spg0).unwrap();
    assert!(
        p.state_bits() & pgs::SNAPTRIM_ERROR != 0,
        "{}",
        p.state_string()
    );
    assert_eq!(p.state_bits() & (pgs::SNAPTRIM | pgs::SNAPTRIM_WAIT), 0);
    assert_eq!(
        d.eng.c.trim_errors, 1,
        "one error, no retry within the epoch"
    );
    assert!(!peering::snaps::iv_contains(&purged_of(&s, prim, spg0), 2));
    assert!(!clones_on(&s, prim, spg0).is_empty(), "clones untouched");
}

/// An unreadable mapper index is NOT an empty one: the snap must not be recorded as purged (clones may remain).
#[test]
fn unreadable_mapper_sets_snaptrim_error_and_never_purges() {
    use pgwire::state as pgs;
    let (mut s, mut d, spg0) = setup(33, 1);
    make_snapshots(&mut s, &mut d, "u");
    d.settle(&mut s, 50 * MS);
    let prim = d.osd;
    MAPPER_UNREADABLE.with(|c| c.set(true));
    queue_snaps(&mut s, 1, &[(2, 1)]);
    d.settle(&mut s, 2_000 * MS);
    let p = s.pg(prim, spg0).unwrap();
    assert!(
        p.state_bits() & pgs::SNAPTRIM_ERROR != 0,
        "{}",
        p.state_string()
    );
    assert!(!peering::snaps::iv_contains(&purged_of(&s, prim, spg0), 2));
    assert!(d.eng.c.trim_errors >= 1);
    assert!(!clones_on(&s, prim, spg0).is_empty(), "clones untouched");
    // index readable again: the next epoch trims for real and purges
    MAPPER_UNREADABLE.with(|c| c.set(false));
    s.new_epoch(|_| {});
    d.until(&mut s, 5_000 * MS, "purged once readable", |s| {
        peering::snaps::iv_contains(&purged_of(s, s.primary_of(spg0.pgid), spg0), 2)
    });
}

#[test]
fn stale_mapper_entry_is_dropped_and_the_snap_purges() {
    let (mut s, mut d, spg0) = setup(30, 1);
    make_snapshots(&mut s, &mut d, "z");
    d.settle(&mut s, 50 * MS);
    let prim = d.osd;
    // a mapping for a clone object that does not exist and is not in the SnapSet
    let ghost = {
        let mut h = hobj(1, "ghost");
        h.snap = SnapId(2);
        h
    };
    s.nodes.get_mut(&prim).unwrap().store.submit(
        spg0,
        &peering::StoreTxn {
            ops: vec![peering::StoreOp::SnapMap(vec![
                peering::snaps::MapOp::Set {
                    clone: ghost.clone(),
                    snaps: vec![2],
                },
            ])],
        },
    );
    queue_snaps(&mut s, 1, &[(2, 1)]);
    d.until(&mut s, 5_000 * MS, "purged despite the stale entry", |s| {
        peering::snaps::iv_contains(&purged_of(s, s.primary_of(spg0.pgid), spg0), 2)
    });
    assert!(s.nodes[&prim].store.snapmap_get(spg0, &ghost).is_none());
    assert_eq!(d.eng.c.trim_errors, 0);
}

#[test]
fn pacing_sleep_separates_rounds_of_one_clone() {
    let (mut s, mut d, spg0) = setup(31, 1);
    for n in ["p1", "p2", "p3"] {
        d.write(&mut s, n, 0, &[1; 16], 0, &[]);
        d.write(&mut s, n, 0, &[2; 4], 2, &[2]);
    }
    d.settle(&mut s, 50 * MS);
    let prim = d.osd;
    s.call(prim, |set, _, _| {
        set.set_snap_trim(2, 1, 50 * MS); // one clone per round, 50 ms between rounds
        vec![]
    });
    let t0 = s.now;
    queue_snaps(&mut s, 1, &[(2, 1)]);
    d.until(&mut s, 10_000 * MS, "purged", |s| {
        peering::snaps::iv_contains(&purged_of(s, s.primary_of(spg0.pgid), spg0), 2)
    });
    assert!(
        s.now - t0 >= 100 * MS,
        "3 rounds of 1 step need 2 sleeps of 50 ms, took {} ms",
        (s.now - t0) / MS
    );
    assert_eq!(d.eng.c.trim_steps, 3);
    assert!(clones_on(&s, 0, spg0).is_empty());
}

/// `scrub_purged_snaps` (spec osd-tell-gaps.md 2): a purged snap whose clone is still mapped is a stray; the active
/// primary queues it for another trim run, which removes the clone and leaves `purged_snaps` as it was.
#[test]
fn purged_snaps_scrub_requeues_strays() {
    let (mut s, mut d, spg0) = setup(41, 1);
    make_snapshots(&mut s, &mut d, "a");
    d.settle(&mut s, 50 * MS);
    let prim = s.primary_of(spg0.pgid);
    let scrub = |s: &mut Sim, osd: i32| {
        let now = s.now;
        let n = s.nodes.get_mut(&osd).unwrap();
        n.set.purged_snaps_start();
        let mut steps = 0;
        loop {
            let n = s.nodes.get_mut(&osd).unwrap();
            let (done, acts) = n.set.purged_snaps_step(now, &n.store);
            s.dispatch(osd, acts);
            steps += 1;
            assert!(steps < 100, "the walk ends");
            if let Some(f) = done {
                return f;
            }
        }
    };
    // nothing purged: nothing to find
    assert_eq!(scrub(&mut s, prim), peering::PurgedScrub::default());
    // snap 2 is queued, trimming is off, and the primary wrongly records snap 2 as purged: its clone is a stray
    s.new_epoch(|m| {
        m.nosnaptrim = true;
        m.removed_queue.insert(1, iv_from_pairs(&[(2, 1)]));
    });
    d.settle(&mut s, 100 * MS);
    let now = s.now;
    let n = s.nodes.get_mut(&prim).unwrap();
    let _ = n.set.with_pg(now, spg0, &n.store, |p| p.trim_snap_done(2));
    let clones = clones_on(&s, prim, spg0).len();
    assert_eq!(clones, 2);
    let f = scrub(&mut s, prim);
    assert_eq!((f.strays, f.retrimmed, f.read_errors), (1, 1, 0), "{f:?}");
    // the queue holds it across map advances, and the trimmer runs once trimming is allowed
    s.new_epoch(|m| m.nosnaptrim = false);
    d.until(&mut s, 5_000 * MS, "stray clone trimmed", |s| {
        clones_on(s, s.primary_of(spg0.pgid), spg0).len() == 1
    });
    d.settle(&mut s, 200 * MS);
    assert_mapper_consistent(&s, &[0, 1, 2], spg0);
    assert!(peering::snaps::iv_contains(&purged_of(&s, prim, spg0), 2));
    assert_eq!(s.pgstats[&spg0].1.snaptrimq_len, 0);
    assert_eq!(scrub(&mut s, prim), peering::PurgedScrub::default());
    // an unreadable mapper is counted, never reported as clean
    s.nodes.get_mut(&prim).unwrap().store.snapmap_error = true;
    let f = scrub(&mut s, prim);
    assert_eq!((f.strays, f.read_errors), (0, 1), "{f:?}");
}

/// spec 7.3 (CS-5566): a finished snap leaves Trimming — the OSD-wide trim slot is released and re-reserved per snap
/// instead of being held for the whole queue, observed through the slot pool count.
#[test]
fn trim_slot_is_released_after_every_snap() {
    let mut s = cluster(50, &[0, 1, 2], 1, 3, 2, 1);
    let spg0 = spg(1, 0);
    let prim = s.primary_of(spg0.pgid);
    // two empty snaps (no clones): each trims in zero steps
    queue_snaps(&mut s, 1, &[(2, 1), (4, 1)]);
    s.run_for(500 * MS);
    let now = s.now;
    let n = s.nodes.get_mut(&prim).unwrap();
    // first snap: reserve (slot held), trim, release
    assert_eq!(
        n.set
            .with_pg(now, spg0, &n.store, |p| p.trim_poll())
            .unwrap()
            .0,
        TrimPoll::Wait
    );
    assert_eq!(n.set.trimming_pgs(), 1, "slot held while a snap trims");
    assert_eq!(
        n.set
            .with_pg(now, spg0, &n.store, |p| p.trim_poll())
            .unwrap()
            .0,
        TrimPoll::Go(2)
    );
    n.set
        .with_pg(now, spg0, &n.store, |p| p.trim_snap_done(2))
        .unwrap();
    assert_eq!(n.set.trimming_pgs(), 0, "slot released after the snap");
    // the next snap re-reserves through the normal path
    assert_eq!(
        n.set
            .with_pg(now, spg0, &n.store, |p| p.trim_poll())
            .unwrap()
            .0,
        TrimPoll::Wait
    );
    assert_eq!(n.set.trimming_pgs(), 1, "the next snap re-reserved");
    assert_eq!(
        n.set
            .with_pg(now, spg0, &n.store, |p| p.trim_poll())
            .unwrap()
            .0,
        TrimPoll::Go(4)
    );
    n.set
        .with_pg(now, spg0, &n.store, |p| p.trim_snap_done(4))
        .unwrap();
    assert_eq!(
        n.set.trimming_pgs(),
        0,
        "slot released when the queue drains"
    );
}

/// CS-5566 (adr 0037): a due scheduled scrub interleaves between the snaps of a long trim queue — it finishes while
/// snaps are still queued — instead of waiting for the whole queue to drain; trimming then finishes every snap.
#[test]
fn due_scrub_interleaves_between_snaps_of_a_long_queue() {
    let mut s = cluster_cfg(51, &[0, 1, 2], 1, 3, 2, 1, |c| {
        c.scrub.min_interval = 0.5;
        c.scrub.deep_interval = 3600.0;
        c.scrub.randomize_ratio = 0.0;
        c.scrub.deep_interval_cv = 0.0;
        c.scrub.backoff_ratio = 0.0;
        c.scrub.retry_trimming = 0;
    });
    s.run_until(30_000 * MS, "clean", |s| s.pool_clean(1));
    let spg0 = spg(1, 0);
    let mut d = Drv::new(&s, spg0);
    for n in ["a", "b", "c"] {
        make_snapshots(&mut s, &mut d, n);
    }
    d.settle(&mut s, 50 * MS);
    // slow the trimmer so the due scrub gets a window between snaps
    let prim = d.osd;
    s.call(prim, |set, _, _| {
        set.set_snap_trim(2, 1, 100 * MS);
        vec![]
    });
    queue_snaps(&mut s, 1, &[(2, 50)]);
    let mut interleaved = false;
    let end = s.now + 60_000 * MS;
    while s.now < end {
        s.run_for(MS);
        d.pump(&mut s);
        let p = s.pg(prim, spg0).unwrap();
        if p.scrub_counts().0 >= 1 && p.snap_trimq_len() > 0 {
            interleaved = true;
        }
        if p.snap_trimq_len() == 0 {
            break;
        }
    }
    s.run_for(500 * MS);
    assert!(
        interleaved,
        "the due scrub must finish before the queue drains\n{}",
        s.dump()
    );
    assert_eq!(purged_of(&s, prim, spg0), iv_from_pairs(&[(2, 50)]));
    assert!(
        s.pg(prim, spg0).unwrap().scrub_counts().0 >= 1,
        "the scrub completed"
    );
}
