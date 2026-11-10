// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Unlogged temp writes (copy staging, adr 0057 am. 1): a write without log entries and with `new_temp` reaches every
//! shard and leaves the log alone; the final write renames the temp object into place and forgets it everywhere;
//! a temp object nobody renames disappears at the next interval change.
mod common;
use common::*;
use denc::types::{CollT, Ghobject, Hobject};
use peering::WriteReq;
use replwire::{ObjectInfo, Transaction, TxnOp};

const POOL: u64 = 1;

fn temp_of(name: &str) -> Hobject {
    Hobject {
        pool: Hobject::temp_pool(POOL as i64),
        ..hobj(POOL, name)
    }
}

/// Temp-object txn of one chunk: create (first) + write at `off`.
fn stage(s: &Sim, temp: &Hobject, first: bool, off: u64, data: &[u8]) -> WriteReq {
    let spg = s.lead_spg(POOL, 0);
    let mut t = Transaction::new();
    let cx = t.coll(&CollT::Pg(spg));
    let ox = t.obj(&Ghobject::head(temp.clone(), spg.shard));
    if first {
        t.push(cx, TxnOp::Remove { oid: ox });
        t.push(cx, TxnOp::Touch { oid: ox });
        t.push(
            cx,
            TxnOp::SetAttrs {
                oid: ox,
                attrs: vec![(b"_user".as_slice(), b"v".as_slice())],
            },
        );
    }
    t.push(
        cx,
        TxnOp::Write {
            oid: ox,
            off,
            data: replwire::Data::new(data),
        },
    );
    WriteReq {
        txn_data: t.encode_v9().unwrap().into(),
        new_temp: first.then(|| temp.clone()),
        ..Default::default()
    }
}

/// The client write that replaces `dest` by `temp`.
fn rename(s: &Sim, temp: &Hobject, dest: &str, size: u64) -> WriteReq {
    let spg = s.lead_spg(POOL, 0);
    let version = s.pg(s.primary_of(spg.pgid), spg).unwrap().next_version();
    let soid = hobj(POOL, dest);
    let oi = ObjectInfo {
        soid: soid.clone(),
        version,
        size,
        user_version: version.version,
        ..Default::default()
    };
    let oi_bytes = denc::to_vec(&oi).unwrap();
    let mut t = Transaction::new();
    let cx = t.coll(&CollT::Pg(spg));
    let tx = t.obj(&Ghobject::head(temp.clone(), spg.shard));
    let dx = t.obj(&Ghobject::head(soid.clone(), spg.shard));
    t.push(cx, TxnOp::Remove { oid: dx });
    t.push(
        cx,
        TxnOp::TryRename {
            oid: tx,
            dest_oid: dx,
        },
    );
    t.push(
        cx,
        TxnOp::SetAttr {
            oid: dx,
            name: b"_",
            value: &oi_bytes,
        },
    );
    WriteReq {
        entries: vec![peering::WriteEntry {
            op: pgwire::LogOp::MODIFY,
            soid,
            user_version: version.version,
            mtime: Default::default(),
            snaps: vec![],
            return_code: 0,
            op_returns: vec![],
            prior: None,
        }],
        txn_data: t.encode_v9().unwrap().into(),
        discard_temp: Some(temp.clone()),
        ..Default::default()
    }
}

fn temps(s: &Sim) -> Vec<usize> {
    let spg = s.lead_spg(POOL, 0);
    s.nodes
        .values()
        .filter(|n| n.alive)
        .map(|n| n.store.temp_objects(spg))
        .collect()
}

#[test]
fn staged_object_is_unlogged_everywhere_and_renamed_by_the_final_write() {
    let mut s = cluster(41, &[0, 1, 2], POOL, 3, 2, 1);
    let spg = s.lead_spg(POOL, 0);
    let prim = s.primary_of(spg.pgid);
    let head0 = s.pg(prim, spg).unwrap().log().head();
    let temp = temp_of("copy-tmp-1");
    let a = vec![7u8; 100_000];
    let b = vec![9u8; 50_000];
    let t1 = s
        .submit_raw(POOL, 0, stage(&s, &temp, true, 0, &a))
        .unwrap();
    s.wait_writes(&[t1], spg);
    let t2 = s
        .submit_raw(POOL, 0, stage(&s, &temp, false, 100_000, &b))
        .unwrap();
    s.wait_writes(&[t2], spg);
    assert_eq!(
        temps(&s),
        vec![1, 1, 1],
        "every shard holds the temp object"
    );
    assert_eq!(
        s.pg(prim, spg).unwrap().log().head(),
        head0,
        "staging writes no log entry"
    );
    for n in s.nodes.values() {
        let o = n.store.object(spg, &temp).expect("temp object");
        assert_eq!(o.data.len(), 150_000);
        assert_eq!(o.xattrs.get(b"_user".as_slice()), Some(&b"v".to_vec()));
    }
    // the final write: dest := temp
    let t3 = s
        .submit_raw(POOL, 0, rename(&s, &temp, "dest", 150_000))
        .unwrap();
    s.wait_writes(&[t3], spg);
    assert_eq!(
        temps(&s),
        vec![0, 0, 0],
        "the rename consumed the temp object"
    );
    let want: Vec<u8> = a.iter().chain(b.iter()).copied().collect();
    for n in s.nodes.values() {
        let o = n.store.object(spg, &hobj(POOL, "dest")).expect("dest");
        assert!(o.data == want, "dest content");
        assert_eq!(o.xattrs.get(b"_user".as_slice()), Some(&b"v".to_vec()));
    }
    s.assert_persisted_consistent();
    // forgotten: a later interval change has nothing left to remove (and nothing breaks)
    s.mark_down(2);
    s.run_for(5_000 * MS);
    s.mark_up(2);
    s.run_until(60_000 * MS, "clean", |s| s.pool_clean(POOL));
    assert_eq!(temps(&s), vec![0, 0, 0]);
}

/// PG-P1: a staging write assigns no log version (`last` = log head), so a second one submitted while the first is still
/// in flight (or one behind an unacked logged write) must not trip the repop version check of `send_repops`.
#[test]
fn pipelined_staging_writes_do_not_reuse_a_repop_version() {
    let mut s = cluster(44, &[0, 1, 2], POOL, 3, 2, 1);
    let spg = s.lead_spg(POOL, 0);
    let temp = temp_of("copy-tmp-4");
    let t1 = s
        .submit_raw(POOL, 0, stage(&s, &temp, true, 0, &[7u8; 4096]))
        .unwrap();
    // second chunk while the first repop is unacked
    let t2 = s
        .submit_raw(POOL, 0, stage(&s, &temp, false, 4096, &[9u8; 4096]))
        .unwrap();
    s.wait_writes(&[t1, t2], spg);
    // a staging write behind an unacked logged write (whose version is the log head)
    let t3 = s.write_obj(POOL, 0, "k", b"v").unwrap();
    let temp2 = temp_of("copy-tmp-4b");
    let t4 = s
        .submit_raw(POOL, 0, stage(&s, &temp2, true, 0, &[5u8; 4096]))
        .unwrap();
    s.wait_writes(&[t3, t4], spg);
    assert_eq!(temps(&s), vec![2, 2, 2], "both temp objects on every shard");
    s.assert_persisted_consistent();
}

#[test]
fn an_unconsumed_temp_object_is_removed_at_the_next_interval() {
    let mut s = cluster(42, &[0, 1, 2], POOL, 3, 2, 1);
    let spg = s.lead_spg(POOL, 0);
    let temp = temp_of("copy-tmp-2");
    let t1 = s
        .submit_raw(POOL, 0, stage(&s, &temp, true, 0, &[1u8; 4096]))
        .unwrap();
    s.wait_writes(&[t1], spg);
    assert_eq!(temps(&s), vec![1, 1, 1]);
    // a replica leaves and comes back: new interval on everyone
    s.mark_down(2);
    s.run_for(5_000 * MS);
    s.mark_up(2);
    s.run_until(60_000 * MS, "clean", |s| s.pool_clean(POOL));
    assert_eq!(temps(&s), vec![0, 0, 0], "leftover staging is cleaned");
    s.assert_persisted_consistent();
}

#[test]
fn temp_objects_left_by_a_crash_are_removed_after_the_restart() {
    let mut s = cluster(43, &[0, 1, 2], POOL, 3, 2, 1);
    let spg = s.lead_spg(POOL, 0);
    let temp = temp_of("copy-tmp-3");
    let t1 = s
        .submit_raw(POOL, 0, stage(&s, &temp, true, 0, &[1u8; 4096]))
        .unwrap();
    s.wait_writes(&[t1], spg);
    assert_eq!(temps(&s), vec![1, 1, 1]);
    // every OSD crashes and restarts: the new process knows nothing of the temp object it finds in its store
    for o in [0, 1, 2] {
        s.kill(o);
    }
    for o in [0, 1, 2] {
        s.restart(o);
    }
    s.run_until(120_000 * MS, "clean", |s| s.pool_clean(POOL));
    assert_eq!(temps(&s), vec![0, 0, 0], "leftover staging is cleaned");
    s.assert_persisted_consistent();
}

/// A write whose executor already knows the version of the object it replaces (`WriteEntry::prior`) logs that version
/// as prior_version without asking the store (the object is absent from the store and the log window here, so a store
/// read would log 0'0).
#[test]
fn a_prior_version_given_by_the_executor_is_logged_as_is() {
    let mut s = cluster(43, &[0, 1, 2], POOL, 3, 2, 1);
    let spg = s.lead_spg(POOL, 0);
    let prim = s.primary_of(spg.pgid);
    let temp = temp_of("copy-tmp-3");
    let t1 = s
        .submit_raw(POOL, 0, stage(&s, &temp, true, 0, &[1u8; 4096]))
        .unwrap();
    s.wait_writes(&[t1], spg);
    let mut w = rename(&s, &temp, "dest", 4096);
    let known = denc::types::Eversion::new(3, 77);
    w.entries[0].prior = Some(known);
    let t2 = s.submit_raw(POOL, 0, w).unwrap();
    s.wait_writes(&[t2], spg);
    let pg = s.pg(prim, spg).unwrap();
    let e = pg
        .log()
        .log
        .log
        .iter()
        .rev()
        .find(|e| e.soid == hobj(POOL, "dest"))
        .unwrap();
    assert_eq!(e.prior_version, known);
}
