// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! PG log trim keeps the trimmed entries' log keys as the dup records of the window (feature `log_dups`, adr/0634-pg-log-dups-from-retained-entries): the adapter must stay equal to `peering::MemStore` for steady-state trims, trims below / above the stored
//! dups, several trims in one StoreTxn, a trim followed by a dup rewrite or a log replace in the same txn, and a store
//! that holds old-format `dup_` keys next to retained entries (mixed state). The feature bit is durable from the first
//! mount on.
mod common;
use common::*;
use denc::types::*;
use peering::store::{MemStore, PgStoreOps, StoreOp, StoreTxn};
use pgwire::{LogOp, PgLog};
use store::layout::{FEAT_LOG_DUPS, read_super};

fn both(mem: &mut MemStore, ad: &mut Ad, s: SpgT, t: StoreTxn) {
    mem.submit(s, &t);
    ad.submit(s, &t);
}

fn trim(g: &PgGen, back: u64, from_back: Option<u64>) -> StoreOp {
    StoreOp::LogTrim {
        to: Eversion::new(g.epoch, g.ver.saturating_sub(back)),
        dups_from: from_back.map(|b| Eversion::new(g.epoch, g.ver.saturating_sub(b))),
        tail_up: false,
    }
}

fn create(mem: &mut MemStore, ad: &mut Ad, s: SpgT) {
    both(
        mem,
        ad,
        s,
        StoreTxn {
            ops: vec![StoreOp::CreatePg],
        },
    );
}

fn append(g: &mut PgGen) -> StoreTxn {
    let mut t = StoreTxn::default();
    t.push(StoreOp::LogAppend(vec![g.entry(LogOp::MODIFY)]));
    t
}

#[test]
fn trim_matches_memstore_with_a_large_dup_window() {
    let (_disk, mut ad, _sim) = new_adapter(64, 1, 7);
    let mut mem = MemStore::new();
    let s = spg(1, 0);
    let mut g = PgGen::new(s, 7);
    create(&mut mem, &mut ad, s);
    // fill: every write trims one entry, the dup window keeps 60
    for _ in 0..80 {
        let mut t = append(&mut g);
        t.push(trim(&g, 3, Some(60)));
        both(&mut mem, &mut ad, s, t);
    }
    assert_same(&mem, &ad, s, "filled");
    let p = ad.load_pg(s).unwrap();
    assert_eq!(p.log.dups.len(), 58, "window of dups, log of 3");
    // batch trim like a PG at osd_pg_log_trim_min: 20 entries at once
    for i in 0..20 {
        let mut t = append(&mut g);
        if i % 5 == 4 {
            t.push(trim(&g, 3, Some(60)));
        }
        both(&mut mem, &mut ad, s, t);
        assert_same(&mem, &ad, s, &format!("batch {i}"));
    }
    // two trims in one StoreTxn
    let mut t = append(&mut g);
    t.push(trim(&g, 3, Some(60)));
    t.push(append(&mut g).ops.remove(0));
    t.push(trim(&g, 3, Some(55)));
    both(&mut mem, &mut ad, s, t);
    assert_same(&mem, &ad, s, "two trims in one txn");
    // no dup kept: every record goes
    let mut t = append(&mut g);
    t.push(trim(&g, 3, None));
    both(&mut mem, &mut ad, s, t);
    assert_same(&mem, &ad, s, "no dups kept");
    assert!(ad.load_pg(s).unwrap().log.dups.is_empty());
}

#[test]
fn old_dup_keys_and_retained_entries_mix() {
    let (_disk, mut ad, _sim) = new_adapter(64, 1, 8);
    let mut mem = MemStore::new();
    let s = spg(1, 0);
    let mut g = PgGen::new(s, 8);
    create(&mut mem, &mut ad, s);
    for _ in 0..10 {
        let t = append(&mut g);
        both(&mut mem, &mut ad, s, t);
    }
    // an explicit dup list (old-format `dup_` keys: what a build before the feature wrote, and what a log merge writes)
    let old: Vec<_> = (0..6)
        .map(|_| {
            let e = g.entry(LogOp::MODIFY);
            g.dup_of(&e)
        })
        .collect();
    let mut t = StoreTxn::default();
    t.push(StoreOp::LogDups(old));
    both(&mut mem, &mut ad, s, t);
    assert_same(&mem, &ad, s, "explicit dups");
    for i in 0..30 {
        let mut t = append(&mut g);
        // the window slides over the old keys and the retained entries alike
        t.push(trim(&g, 4, Some(8 + (i % 4))));
        both(&mut mem, &mut ad, s, t);
        assert_same(&mem, &ad, s, &format!("slide {i}"));
    }
    // a dup rewrite replaces both kinds
    let mut t = append(&mut g);
    t.push(trim(&g, 4, Some(20)));
    let e = g.entry(LogOp::MODIFY);
    t.push(StoreOp::LogDups(vec![g.dup_of(&e)]));
    both(&mut mem, &mut ad, s, t);
    assert_same(&mem, &ad, s, "trim then dup rewrite");
    assert_eq!(ad.load_pg(s).unwrap().log.dups.len(), 1);
    // a log replace drops the retained entries as well
    let mut t = append(&mut g);
    t.push(trim(&g, 4, Some(20)));
    let e = g.entry(LogOp::MODIFY);
    let l = one_entry_log(&e, g.epoch, g.ver - 1, [g.dup_of(&e)].into());
    t.push(StoreOp::LogReplace(Box::new(l)));
    both(&mut mem, &mut ad, s, t);
    assert_same(&mem, &ad, s, "trim then replace");
}

/// A divergent rewind removes exactly the entries above `to` and above the tail; the retained dup-source entries
/// `<= tail` stay (and are never visited: the scan starts behind the higher of `to` and the tail).
#[test]
fn rewind_removes_only_entries_above_to_and_tail() {
    let (_disk, mut ad, _sim) = new_adapter(64, 1, 9);
    let mut mem = MemStore::new();
    let s = spg(1, 0);
    let mut g = PgGen::new(s, 9);
    create(&mut mem, &mut ad, s);
    for _ in 0..40 {
        let mut t = append(&mut g);
        t.push(trim(&g, 4, Some(30)));
        both(&mut mem, &mut ad, s, t);
    }
    let dups = ad.load_pg(s).unwrap().log.dups.len();
    assert!(dups > 20);
    // rewind by two (inside the log): entries ver-1 and ver go, the dups stay
    let mut t = StoreTxn::default();
    t.push(StoreOp::LogRewind {
        to: Eversion::new(g.epoch, g.ver - 2),
    });
    both(&mut mem, &mut ad, s, t);
    assert_same(&mem, &ad, s, "rewind inside the log");
    let p = ad.load_pg(s).unwrap();
    assert_eq!(p.log.head, Eversion::new(g.epoch, g.ver - 2));
    assert_eq!(p.log.dups.len(), dups, "retained entries untouched");
    assert_eq!(p.log.log.back().unwrap().version, p.log.head);
    // rewind below the tail: only what is above the tail is removed, the retained entries stay
    let mut t = StoreTxn::default();
    t.push(StoreOp::LogRewind {
        to: Eversion::new(g.epoch, g.ver - 20),
    });
    both(&mut mem, &mut ad, s, t);
    assert_same(&mem, &ad, s, "rewind below the tail");
    assert_eq!(ad.load_pg(s).unwrap().log.dups.len(), dups);
}

/// The extra request ids of a trimmed entry are dup records of their own (return code 0), also after a reload.
#[test]
fn extra_reqids_of_a_retained_entry_are_dups() {
    let (_disk, mut ad, _sim) = new_adapter(64, 1, 9);
    let mut mem = MemStore::new();
    let s = spg(1, 0);
    let mut g = PgGen::new(s, 9);
    create(&mut mem, &mut ad, s);
    let mut e = g.entry(LogOp::MODIFY);
    let r = denc::types::OsdReqId {
        tid: 77,
        ..Default::default()
    };
    e.extra_reqids = vec![(r, 5)];
    let mut t = StoreTxn::default();
    t.push(StoreOp::LogAppend(vec![e.clone()]));
    for _ in 0..3 {
        t.push(StoreOp::LogAppend(vec![g.entry(LogOp::MODIFY)]));
    }
    t.push(StoreOp::LogTrim {
        to: e.version,
        dups_from: Some(e.version),
        tail_up: false,
    });
    both(&mut mem, &mut ad, s, t);
    assert_same(&mem, &ad, s, "extra reqids");
    let d = ad.load_pg(s).unwrap().log.dups;
    assert_eq!(d.len(), 2);
    assert_eq!(
        (d[1].reqid.tid, d[1].user_version, d[1].return_code),
        (77, 5, 0)
    );
}

#[test]
fn dup_rewrite_preserves_same_version_requests_across_restart() {
    explicit_dups_preserve_same_version_requests(false);
}

#[test]
fn log_replace_preserves_same_version_requests_across_restart() {
    explicit_dups_preserve_same_version_requests(true);
}

fn explicit_dups_preserve_same_version_requests(replace: bool) {
    let (disk, mut ad, sim) = new_adapter(64, 1, 9);
    let mut mem = MemStore::new();
    let s = spg(1, 0);
    let mut g = PgGen::new(s, 9);
    create(&mut mem, &mut ad, s);
    let mut e = g.entry(LogOp::MODIFY);
    e.reqid.tid = 50;
    e.extra_reqids = (77..80)
        .map(|tid| {
            (
                OsdReqId {
                    tid,
                    ..Default::default()
                },
                tid,
            )
        })
        .collect();
    e.extra_reqid_return_codes.insert(1, -5);
    let dups: Vec<_> = e.dups().collect();
    let newest = g.entry(LogOp::MODIFY);
    let mut t = StoreTxn::default();
    t.push(StoreOp::LogAppend(vec![e.clone(), newest.clone()]));
    t.push(StoreOp::LogTrim {
        to: e.version,
        dups_from: Some(e.version),
        tail_up: false,
    });
    if replace {
        t.push(StoreOp::LogReplace(Box::new(one_entry_log(
            &newest,
            g.epoch,
            e.version.version,
            dups.clone().into(),
        ))));
    } else {
        t.push(StoreOp::LogDups(dups.clone()));
    }
    both(&mut mem, &mut ad, s, t);
    assert_eq!(ad.load_pg(s).unwrap().log.dups, dups, "replace={replace}");
    drop(ad);
    let (_disk, mut ad) = open(&disk.image(), &sim, &store::obj::StoreCfg::default());
    assert_eq!(
        ad.load_pg(s).unwrap().log.dups,
        dups,
        "restart replace={replace}"
    );
    let reloaded = peering::IndexedLog::new(ad.load_pg(s).unwrap().log);
    for d in &dups {
        assert_eq!(
            reloaded.find_reqid(&d.reqid),
            Some((d.version, d.user_version, d.return_code)),
            "resend must be recognized after restart"
        );
    }
    // A later trim at this version must retain every request; moving past it removes all.
    for (to, from) in [(e.version, e.version), (newest.version, newest.version)] {
        let t = StoreTxn {
            ops: vec![StoreOp::LogTrim {
                to,
                dups_from: Some(from),
                tail_up: false,
            }],
        };
        both(&mut mem, &mut ad, s, t);
        assert_same(&mem, &ad, s, "same-version dup trim after restart");
    }
}

/// `log_dups` is durable from the first mount on (adr 0634): a store without the bit (mkfs leaves it to the mount,
/// an older build never set it) gets it before it takes any txn, so a PG's first trim never waits for a superblock write
/// on its core.
#[test]
fn feature_bit_is_durable_from_mount() {
    let sim = sim_cfg(64, 5);
    let img = fresh_image(&sim, 1, 1024);
    let feat = |d: &store::dev::SimDisk| {
        let mut q = d.queue();
        read_super(&mut q, &mut store::dev::SimClock::default())
            .unwrap()
            .0
            .features
            & FEAT_LOG_DUPS
    };
    let unmounted = store::dev::SimDisk::from_image(&img, sim.clone());
    assert_eq!(feat(&unmounted), 0, "mkfs leaves it to the mount");
    let (disk, mut ad) = open(&img, &sim, &store::obj::StoreCfg::default());
    assert_ne!(feat(&disk), 0, "durable before the first txn");
    let s = spg(1, 0);
    let mut g = PgGen::new(s, 5);
    let mut t = StoreTxn::default();
    t.push(StoreOp::CreatePg);
    for _ in 0..5 {
        t.push(StoreOp::LogAppend(vec![g.entry(LogOp::MODIFY)]));
    }
    ad.submit(s, &t);
    let mut t = StoreTxn::default();
    t.push(trim(&g, 2, Some(3)));
    ad.submit(s, &t);
    assert_ne!(feat(&disk), 0);
    drop(ad);
    let img2 = disk.image();
    let (_d, ad2) = open(&img2, &sim, &store::obj::StoreCfg::default());
    assert_eq!(ad2.load_pg(s).unwrap().log.tail.version, g.ver - 2);
}

/// Random mixes in ONE StoreTxn of trims, dup rewrites and log replaces: the adapter (state read back from the store)
/// must keep exactly the dup set `MemStore` keeps.
#[test]
fn random_dup_mixes_in_one_txn_match_memstore() {
    use store::rng::Rng;
    for seed in 1..=12u64 {
        let (_disk, mut ad, _sim) = new_adapter(64, 1, seed);
        let mut mem = MemStore::new();
        let s = spg(1, 0);
        let mut g = PgGen::new(s, seed);
        let mut r = Rng::new(seed ^ 0xd0b);
        create(&mut mem, &mut ad, s);
        for i in 0..60 {
            let mut t = StoreTxn::default();
            let mut tail = mem.load_pg(s).unwrap().log.tail.version;
            for _ in 0..r.range(1, 5) {
                let e = g.entry(LogOp::MODIFY);
                t.push(StoreOp::LogAppend(vec![e.clone()]));
                match r.below(10) {
                    0 => t.push(StoreOp::LogDups(
                        (0..r.below(6)).map(|_| new_dup(&mut g)).collect(),
                    )),
                    1 => {
                        tail = g.ver - 1;
                        let dups = (0..r.below(6)).map(|_| new_dup(&mut g)).collect();
                        let l = one_entry_log(&e, g.epoch, tail, dups);
                        t.push(StoreOp::LogReplace(Box::new(l)));
                    }
                    _ => {
                        let from = if r.pct(10) {
                            None
                        } else {
                            Some(r.range(0, 12))
                        };
                        // a PG trims forward only and keeps dups from at most `to`
                        let back = r.range(1, 6);
                        if g.ver.saturating_sub(back) > tail {
                            tail = g.ver.saturating_sub(back);
                            t.push(trim(&g, back, from.map(|f| f + back)));
                        }
                    }
                }
            }
            both(&mut mem, &mut ad, s, t);
            assert_same(&mem, &ad, s, &format!("seed {seed} txn {i}"));
        }
    }
}

fn one_entry_log(
    e: &pgwire::LogEntry,
    epoch: u32,
    tail: u64,
    dups: std::collections::VecDeque<pgwire::LogDup>,
) -> PgLog {
    PgLog {
        head: e.version,
        tail: Eversion::new(epoch, tail),
        can_rollback_to: e.version,
        rollback_info_trimmed_to: e.version,
        log: [e.clone()].into(),
        dups,
    }
}

fn new_dup(g: &mut PgGen) -> pgwire::LogDup {
    let e = g.entry(LogOp::MODIFY);
    g.dup_of(&e)
}

#[test]
fn warm_log_is_ready_for_a_warm_or_missing_pg_log() {
    // `PgStoreOps::warm_log` probes the pgmeta page of the next log key (adr 0021 am. 30): no PG, or a warm cache, is ready
    let (_disk, mut ad, _sim) = new_adapter(64, 1, 9);
    let s = spg(1, 0);
    assert!(ad.warm_log(s, Eversion::new(5, 1)), "no such PG");
    let mut g = PgGen::new(s, 9);
    let mut t = StoreTxn::default();
    t.push(StoreOp::CreatePg);
    for _ in 0..20 {
        t.push(StoreOp::LogAppend(vec![g.entry(LogOp::MODIFY)]));
    }
    ad.submit(s, &t);
    assert!(ad.warm_log(s, Eversion::new(g.epoch, g.ver)));
    assert!(ad.warm_log(s, Eversion::new(g.epoch, g.ver + 1000)));
}
