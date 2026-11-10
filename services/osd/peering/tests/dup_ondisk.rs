// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! A resent write is answered ONDISK only once every acting member committed it (client-ops.md 5.6), end to end on the
//! deterministic simulator: real PGs (primary + replica on `MemStore`), the real op engine (`opexec`) on the primary,
//! the replica's link held so its commit stays outstanding. Review 2026-11-03 #2.
mod common;
#[macro_use]
#[path = "../../opexec/tests/common/env_noop.rs"]
mod env_noop;
use common::*;
use denc::types::*;
use opexec::{ClientReq, Engine, Env, Limits, ObjView, Out};
use opwire::{MOSDOp, MOSDOpReply, OsdOp};
use peering::{Action, MemStore, PgSet, WriteErr, WriteReq};
use std::collections::BTreeMap;

/// The op engine's view of one PG of the simulator.
struct SimEnv<'a> {
    set: &'a mut PgSet,
    store: &'a MemStore,
    spg: SpgT,
    now: u64,
    acts: Vec<Action>,
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
        removed_snaps,
        run_start,
        scrub_ls,
        send_first,
        settle,
        snap_mapper_next,
        trim_cfg,
        trim_counted,
        trim_note,
        trim_poll,
        trim_snap_done,
        trim_stop,
        trim_unmap,
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
    fn missing_range(&self, _from: &Hobject, _to: &Hobject, _max: usize) -> Vec<(Hobject, bool)> {
        Vec::new()
    }
    fn write_degraded(&self, head: &Hobject) -> bool {
        self.set.pg(self.spg).is_some_and(|p| p.obj_degraded(head))
    }
    fn submit_write(&mut self, w: WriteReq) -> Result<u64, WriteErr> {
        let (tid, a) = self.set.submit_write(self.now, self.spg, w, self.store)?;
        self.acts.extend(a);
        Ok(tid)
    }
    fn pg_num(&self) -> u32 {
        1
    }
}

/// A client reply and the PG state when the engine produced it.
struct Answer {
    conn: u64,
    reply: Box<MOSDOpReply>,
    /// `pg_committed_to` of the primary at that moment.
    committed_to: Eversion,
    /// `last_peering_reset` of the primary at that moment.
    reset: u32,
}

/// The primary's op engine and the plumbing an OSD core gives it (`ops.rs`): engine reset on a new interval before the
/// old interval's completions, completions, gate retries.
struct Drv {
    eng: Engine,
    spg: SpgT,
    osd: i32,
    fed: usize,
    fed_failed: usize,
    reset: u32,
    answers: Vec<Answer>,
}

impl Drv {
    fn new(s: &Sim, spg: SpgT) -> Drv {
        let osd = s.primary_of(spg.pgid);
        Drv {
            eng: Engine::new(spg, Limits::default(), opexec::clsx::ClassPolicy::default()),
            spg,
            osd,
            fed: s.acked_full.len(),
            fed_failed: s.failed_full.len(),
            reset: s.pg(osd, spg).unwrap().last_peering_reset(),
            answers: Vec::new(),
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
        let p = s.pg(osd, spg).unwrap();
        let (committed_to, reset) = (p.pg_committed_to(), p.last_peering_reset());
        for o in self.eng.take_out() {
            if let Out::Reply { conn, reply, .. } = o {
                self.answers.push(Answer {
                    conn,
                    reply,
                    committed_to,
                    reset,
                });
            }
        }
    }

    fn pump(&mut self, s: &mut Sim) {
        let (osd, spg) = (self.osd, self.spg);
        let reset = s.pg(osd, spg).unwrap().last_peering_reset();
        if reset != self.reset {
            self.reset = reset;
            self.eng.reset();
        }
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
        }
        self.with_env(s, |e, env| e.retry(env));
    }

    fn settle(&mut self, s: &mut Sim, dur: u64) {
        let end = s.now + dur;
        while s.now < end {
            s.run_for(MS);
            self.pump(s);
        }
    }

    fn until(&mut self, s: &mut Sim, timeout: u64, why: &str, pred: impl Fn(&Drv) -> bool) {
        let end = s.now + timeout;
        while s.now < end && !pred(self) {
            s.run_for(MS);
            self.pump(s);
        }
        assert!(pred(self), "timeout: {why}\n{}", s.dump());
    }

    /// Client 7 sends `op` with client tid `tid` on connection `conn`.
    fn send(&mut self, s: &mut Sim, conn: u64, tid: u64, op: &MOSDOp) {
        let req = ClientReq {
            placement_read: None,
            conn,
            caps: None,
            tid,
            op: Box::new(op.clone()),
            who: CLIENT,
            addr: EntityAddr::default(),
            peer_addr: EntityAddr::default(),
            features: 0x3f17_ffff_fffd_ffff,
        };
        self.with_env(s, |e, env| e.on_op(env, req));
    }
}

const CLIENT: EntityName = EntityName::client(7);

/// A write of `data` to `name`.
fn write(s: &Sim, spg: SpgT, name: &str, data: &[u8]) -> MOSDOp {
    let h = hobj(1, name);
    MOSDOp {
        pgid: spg,
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
        ops: vec![OsdOp::write(0, data.to_vec())],
        mtime: UTime::new(1_700_000_001, 5),
        ..Default::default()
    }
}

/// Log entries of the primary carrying `reqid`.
fn logged(s: &Sim, osd: i32, spg: SpgT, reqid: &OsdReqId) -> Vec<Eversion> {
    s.pg(osd, spg)
        .unwrap()
        .log()
        .entries()
        .iter()
        .filter(|e| e.reqid == *reqid)
        .map(|e| e.version)
        .collect()
}

/// Every answer is a success at the logged version, sent only once the version was committed by every acting member.
fn assert_committed_answers(d: &Drv, conns: &[u64], ver: Eversion) {
    let mut got: Vec<u64> = d.answers.iter().map(|a| a.conn).collect();
    got.sort_unstable();
    assert_eq!(got, conns, "one answer per send");
    for a in &d.answers {
        assert_eq!(a.reply.result, 0, "conn {}", a.conn);
        assert_eq!(a.reply.replay_version, ver, "conn {}", a.conn);
        assert!(
            a.committed_to >= ver,
            "conn {}: ONDISK answer for {ver:?} while pg_committed_to = {:?}",
            a.conn,
            a.committed_to
        );
    }
}

/// The write lands in the primary's log and store, its repop to the replica is held: neither the write nor a resend of
/// it (new connection, same reqid) is answered. Once the replica's commit arrives (`complete_repops`), both are, with
/// the one logged version.
#[test]
fn resend_of_a_write_the_replica_has_not_committed_waits_for_the_commit() {
    let mut s = cluster(71, &[0, 1], 1, 2, 1, 1);
    let pg = spg(1, 0);
    let mut d = Drv::new(&s, pg);
    let prim = d.osd;
    let rep = *s.acting_of(pg.pgid).iter().find(|o| **o != prim).unwrap();
    s.partition(prim, rep);
    let op = write(&s, pg, "o", b"payload");
    let reqid = op.effective_reqid(CLIENT, 5);
    d.send(&mut s, 1, 5, &op);
    d.settle(&mut s, 50 * MS);
    let ver = logged(&s, prim, pg, &reqid);
    assert_eq!(ver.len(), 1, "logged once");
    let ver = ver[0];
    let p = s.pg(prim, pg).unwrap();
    assert!(
        p.log().find_reqid(&reqid).is_some(),
        "a resend finds the entry"
    );
    assert!(
        p.pg_committed_to() < ver,
        "the replica has not committed it"
    );
    assert!(d.answers.is_empty(), "no ack before the replica commits");
    // the client resends (reconnect): the entry is in the log, the commit is still outstanding
    d.send(&mut s, 2, 5, &op);
    d.settle(&mut s, 50 * MS);
    assert!(
        d.answers.is_empty(),
        "the resend of an uncommitted write must wait for the commit"
    );
    assert_eq!(
        logged(&s, prim, pg, &reqid),
        vec![ver],
        "not executed again"
    );
    s.heal_link(prim, rep);
    d.until(&mut s, 5_000 * MS, "both sends answered", |d| {
        d.answers.len() == 2
    });
    assert_committed_answers(&d, &[1, 2], ver);
    assert_eq!(logged(&s, prim, pg, &reqid), vec![ver]);
}

/// Same, and the interval ends before the replica commits (it is marked down): the write and its waiting resend go back
/// to the gate, nothing is answered in the old interval; after the new interval activated (the log is now held by every
/// acting member) both are answered from the log, once each, with the original version.
#[test]
fn interval_abort_requeues_the_waiting_resend() {
    let mut s = cluster(72, &[0, 1], 1, 2, 1, 1);
    let pg = spg(1, 0);
    let mut d = Drv::new(&s, pg);
    let prim = d.osd;
    let rep = *s.acting_of(pg.pgid).iter().find(|o| **o != prim).unwrap();
    let old = d.reset;
    s.partition(prim, rep);
    let op = write(&s, pg, "o", b"payload");
    let reqid = op.effective_reqid(CLIENT, 9);
    d.send(&mut s, 1, 9, &op);
    d.settle(&mut s, 50 * MS);
    d.send(&mut s, 2, 9, &op);
    d.settle(&mut s, 50 * MS);
    assert!(d.answers.is_empty());
    let ver = logged(&s, prim, pg, &reqid);
    assert_eq!(ver.len(), 1);
    let ver = ver[0];
    s.mark_down(rep);
    d.until(&mut s, 60_000 * MS, "both sends answered", |d| {
        d.answers.len() == 2
    });
    assert_eq!(s.primary_of(pg.pgid), prim);
    assert!(
        d.answers.iter().all(|a| a.reset > old),
        "nothing answered in the aborted interval"
    );
    assert_committed_answers(&d, &[1, 2], ver);
    assert_eq!(
        logged(&s, prim, pg, &reqid),
        vec![ver],
        "answered from the log, not executed again"
    );
}
