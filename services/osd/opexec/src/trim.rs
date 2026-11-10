// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Snap trimming, primary op side (spec snaptrim.md 5, 7.3): the planner of one trim step and the trimmer driver of
//! the [`Engine`](crate::Engine).
//!
//! A step takes one clone `C` of the snap being trimmed and rewrites it and its head `H` as ONE logged, replicated
//! write (two log entries, clone first): the clone is deleted when no snap needs it any more, else shrunk to the
//! snaps that are still alive; the head's SnapSet follows. [`plan_step`] is pure (object states in, entries +
//! transaction out); everything else lives in the engine.

use crate::exec::{MOp, enc};
use denc::types::{Eversion, Hobject, SnapId, UTime};
use peering::WriteEntry;
use peering::snaps::{Ivs, encode_snaps, iv_contains, iv_intersect};
use pgwire::LogOp;
use replwire::{ObjectInfo, SnapSet};

/// Trimmer tunables (osd_pg_max_concurrent_snap_trims, osd_snap_trim_sleep*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrimCfg {
    /// Steps (clones) per round, at least 1.
    pub max_concurrent: usize,
    /// Pause between rounds, ns (0 = none).
    pub sleep_ns: u64,
}

impl Default for TrimCfg {
    fn default() -> Self {
        TrimCfg {
            max_concurrent: 2,
            sleep_ns: 0,
        }
    }
}

/// Why a step cannot run (PG gets SNAPTRIM_ERROR; classic stalls too, scrub repairs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepErr {
    /// Head SnapSet has no `clone_snaps` entry for the clone.
    NoCloneSnaps,
    /// `clone_snaps` entry empty.
    EmptyCloneSnaps,
    /// `snapset.seq == 0`.
    SeqZero,
    /// The clone is not in `snapset.clones`.
    NotInClones,
}

impl StepErr {
    pub fn text(&self) -> &'static str {
        match self {
            StepErr::NoCloneSnaps => "No clone_snaps in snapset",
            StepErr::EmptyCloneSnaps => "Empty clone_snaps in snapset",
            StepErr::SeqZero => "Snapset seq is zero",
            StepErr::NotInClones => "Snap not in clones",
        }
    }
}

/// Inputs of one step.
#[derive(Debug)]
pub struct StepIn<'a> {
    pub head: &'a Hobject,
    pub clone: &'a Hobject,
    /// Snap being trimmed.
    pub snap: u64,
    /// Snaps the osdmap says are removed (`removed_snaps_queue[pool]`).
    pub queue: &'a Ivs,
    pub head_oi: &'a ObjectInfo,
    pub ss: &'a SnapSet,
    pub clone_oi: &'a ObjectInfo,
    pub now: UTime,
    /// Version of the clone's log entry; the head's is the next one.
    pub v: Eversion,
}

/// What the step does.
#[derive(Debug)]
pub struct Step {
    /// `[clone entry, head entry]`.
    pub entries: Vec<WriteEntry>,
    pub(crate) txn: Vec<(Hobject, MOp)>,
    /// Head after the step (`None` = the whiteout head was deleted).
    pub head_oi: Option<ObjectInfo>,
    pub ss: SnapSet,
    pub clone_deleted: bool,
    pub head_deleted: bool,
}

fn entry(op: LogOp, soid: &Hobject, uv: u64, mtime: UTime, snaps: Vec<u8>) -> WriteEntry {
    WriteEntry {
        op,
        soid: soid.clone(),
        user_version: uv,
        mtime,
        snaps,
        return_code: 0,
        op_returns: Vec::new(),
        prior: None,
    }
}

/// Plan one trim step (spec 5).
pub fn plan_step(i: &StepIn<'_>) -> Result<Step, StepErr> {
    let c = i.clone.snap;
    let mut ss = i.ss.clone();
    if ss.seq == 0 {
        return Err(StepErr::SeqZero);
    }
    let old: Vec<u64> = match ss.clone_snaps.get(&c) {
        None => return Err(StepErr::NoCloneSnaps),
        Some(v) if v.is_empty() => return Err(StepErr::EmptyCloneSnaps),
        Some(v) => v.iter().map(|s| s.0).collect(),
    };
    // all queued snaps go in one pass, not only the one being trimmed
    let new: Vec<u64> = old
        .iter()
        .copied()
        .filter(|x| *x != i.snap && !iv_contains(i.queue, *x))
        .collect();
    let clone_deleted = new.is_empty();
    let mut txn: Vec<(Hobject, MOp)> = Vec::new();
    let mut entries = Vec::with_capacity(2);
    let v1 = Eversion::new(i.v.epoch, i.v.version + 1);
    if clone_deleted {
        let Some(idx) = ss.clones.iter().position(|x| *x == c) else {
            return Err(StepErr::NotInClones);
        };
        if idx > 0 {
            let older = ss.clones[idx - 1];
            if let (Some(oo), Some(co)) = (ss.clone_overlap.get(&older), ss.clone_overlap.get(&c)) {
                let n = iv_intersect(oo, co);
                ss.clone_overlap.insert(older, n);
            }
        }
        ss.clones.remove(idx);
        ss.clone_overlap.remove(&c);
        ss.clone_size.remove(&c);
        ss.clone_snaps.remove(&c);
        txn.push((i.clone.clone(), MOp::Remove));
        entries.push(entry(LogOp::DELETE, i.clone, 0, i.now, encode_snaps(&[])));
    } else {
        // wire: clone_snaps descending; the log entry carries the set ascending
        let mut desc: Vec<SnapId> = new.iter().map(|s| SnapId(*s)).collect();
        desc.sort_unstable_by(|a, b| b.cmp(a));
        ss.clone_snaps.insert(c, desc);
        let mut coi = i.clone_oi.clone();
        coi.prior_version = coi.version;
        coi.version = i.v;
        txn.push((
            i.clone.clone(),
            MOp::SetAttr {
                name: b"_".to_vec(),
                value: enc(&coi),
            },
        ));
        let mut asc = new;
        asc.sort_unstable();
        entries.push(entry(LogOp::MODIFY, i.clone, 0, i.now, encode_snaps(&asc)));
    }
    // head: always touched (its SnapSet changed)
    let (head_oi, head_deleted) = if ss.clones.is_empty() && i.head_oi.is_whiteout() {
        txn.push((i.head.clone(), MOp::Remove));
        entries.push(entry(
            LogOp::DELETE,
            i.head,
            i.head_oi.user_version,
            i.now,
            Vec::new(),
        ));
        (None, true)
    } else {
        let mut hoi = i.head_oi.clone();
        hoi.prior_version = hoi.version;
        hoi.version = v1;
        txn.push((
            i.head.clone(),
            MOp::SetAttr {
                name: b"_".to_vec(),
                value: enc(&hoi),
            },
        ));
        txn.push((
            i.head.clone(),
            MOp::SetAttr {
                name: b"snapset".to_vec(),
                value: enc(&ss),
            },
        ));
        entries.push(entry(
            LogOp::MODIFY,
            i.head,
            i.head_oi.user_version,
            i.now,
            Vec::new(),
        ));
        (Some(hoi), false)
    };
    Ok(Step {
        entries,
        txn,
        head_oi,
        ss,
        clone_deleted,
        head_deleted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use peering::snaps::iv_from_pairs;
    use std::collections::BTreeMap;

    fn h(snap: u64) -> Hobject {
        Hobject::new(b"obj", SnapId(snap), 5, 1, b"")
    }

    /// Spec 13.1: clones [4,8,12], overlaps {4:[0,10),8:[0,10),12:[0,6)}, clone_snaps {4:[3,2],8:[7,5],12:[10,9]}.
    fn ss0() -> SnapSet {
        let ov = |a: u64, b: u64| -> BTreeMap<u64, u64> { BTreeMap::from([(a, b - a)]) };
        SnapSet {
            seq: 12,
            clones: vec![SnapId(4), SnapId(8), SnapId(12)],
            clone_overlap: BTreeMap::from([
                (SnapId(4), ov(0, 10)),
                (SnapId(8), ov(0, 10)),
                (SnapId(12), ov(0, 6)),
            ]),
            clone_size: BTreeMap::from([(SnapId(4), 10), (SnapId(8), 10), (SnapId(12), 10)]),
            clone_snaps: BTreeMap::from([
                (SnapId(4), vec![SnapId(3), SnapId(2)]),
                (SnapId(8), vec![SnapId(7), SnapId(5)]),
                (SnapId(12), vec![SnapId(10), SnapId(9)]),
            ]),
        }
    }

    fn oi(soid: &Hobject, ver: u64, whiteout: bool) -> ObjectInfo {
        let mut o = ObjectInfo::new(soid.clone());
        o.version = Eversion::new(3, ver);
        o.user_version = ver;
        if whiteout {
            o.flags |= replwire::oi::flag::WHITEOUT;
        }
        o
    }

    fn run(
        ss: &SnapSet,
        clone: u64,
        snap: u64,
        queue: &Ivs,
        whiteout: bool,
    ) -> Result<Step, StepErr> {
        let (head, c) = (h(SnapId::NOSNAP.0), h(clone));
        let (hoi, coi) = (oi(&head, 20, whiteout), oi(&c, 10, false));
        plan_step(&StepIn {
            head: &head,
            clone: &c,
            snap,
            queue,
            head_oi: &hoi,
            ss,
            clone_oi: &coi,
            now: UTime::new(9, 9),
            v: Eversion::new(4, 100),
        })
    }

    fn snaps_of(e: &WriteEntry) -> Vec<u64> {
        peering::snaps::decode_snaps(&e.snaps)
    }

    #[test]
    fn vector1_shrink_then_vector2_delete() {
        let q = iv_from_pairs(&[(7, 1)]);
        let s = run(&ss0(), 8, 7, &q, false).unwrap();
        assert!(!s.clone_deleted && !s.head_deleted);
        assert_eq!(s.entries.len(), 2);
        assert_eq!(s.entries[0].op, LogOp::MODIFY);
        assert_eq!(s.entries[0].soid, h(8));
        assert_eq!(snaps_of(&s.entries[0]), vec![5]);
        assert_eq!(s.entries[1].op, LogOp::MODIFY);
        assert_eq!(s.entries[1].soid, h(SnapId::NOSNAP.0));
        assert!(s.entries[1].snaps.is_empty());
        assert_eq!(s.ss.clone_snaps[&SnapId(8)], vec![SnapId(5)]);
        assert_eq!(s.ss.seq, 12);
        assert_eq!(s.head_oi.as_ref().unwrap().version, Eversion::new(4, 101));
        assert_eq!(
            s.head_oi.as_ref().unwrap().prior_version,
            Eversion::new(3, 20)
        );
        // vector 2: trim 5 afterwards: clone 8 deleted, older overlap = [0,10) & [0,10)
        let q2 = iv_from_pairs(&[(5, 1), (7, 1)]);
        let s2 = run(&s.ss, 8, 5, &q2, false).unwrap();
        assert!(s2.clone_deleted);
        assert_eq!(s2.entries[0].op, LogOp::DELETE);
        assert_eq!(s2.entries[0].snaps, vec![0, 0, 0, 0]);
        assert_eq!(s2.ss.clones, vec![SnapId(4), SnapId(12)]);
        assert_eq!(s2.ss.clone_overlap[&SnapId(4)], BTreeMap::from([(0, 10)]));
        assert!(!s2.ss.clone_size.contains_key(&SnapId(8)));
        assert!(!s2.ss.clone_snaps.contains_key(&SnapId(8)));
    }

    #[test]
    fn vector3_middle_overlap_intersect() {
        let mut ss = ss0();
        ss.clone_overlap.insert(SnapId(8), BTreeMap::from([(2, 4)])); // [2,6)
        let q = iv_from_pairs(&[(5, 1), (7, 1)]);
        let s = run(&ss, 8, 7, &q, false).unwrap();
        // both queued snaps of the clone go in one pass
        assert!(s.clone_deleted);
        assert_eq!(s.ss.clone_overlap[&SnapId(4)], BTreeMap::from([(2, 4)]));
    }

    #[test]
    fn vector4_oldest_and_newest() {
        let q = iv_from_pairs(&[(2, 2)]);
        let s = run(&ss0(), 4, 2, &q, false).unwrap();
        assert!(s.clone_deleted);
        assert_eq!(s.ss.clones, vec![SnapId(8), SnapId(12)]);
        assert_eq!(s.ss.clone_overlap[&SnapId(8)], BTreeMap::from([(0, 10)]));
        // newest: older becomes newest; its overlap = older & removed
        let q = iv_from_pairs(&[(9, 2)]);
        let s = run(&ss0(), 12, 9, &q, false).unwrap();
        assert!(s.clone_deleted);
        assert_eq!(s.ss.clones, vec![SnapId(4), SnapId(8)]);
        assert_eq!(s.ss.clone_overlap[&SnapId(8)], BTreeMap::from([(0, 6)]));
    }

    #[test]
    fn vector6_whiteout_head() {
        let mut ss = ss0();
        ss.clones = vec![SnapId(8)];
        ss.clone_overlap.retain(|k, _| *k == SnapId(8));
        ss.clone_size.retain(|k, _| *k == SnapId(8));
        ss.clone_snaps.retain(|k, _| *k == SnapId(8));
        let q = iv_from_pairs(&[(5, 1), (7, 1)]);
        // whiteout head + last clone dies: head deleted too
        let s = run(&ss, 8, 7, &q, true).unwrap();
        assert!(s.clone_deleted && s.head_deleted && s.head_oi.is_none());
        assert_eq!(s.entries[1].op, LogOp::DELETE);
        assert_eq!(s.entries[1].soid, h(SnapId::NOSNAP.0));
        // plain head: MODIFY with empty clones, head kept
        let s = run(&ss, 8, 7, &q, false).unwrap();
        assert!(s.clone_deleted && !s.head_deleted);
        assert_eq!(s.entries[1].op, LogOp::MODIFY);
        assert!(s.ss.clones.is_empty());
        // whiteout head with clones left: untouched except the SnapSet
        let q = iv_from_pairs(&[(7, 1)]);
        let s = run(&ss0(), 8, 7, &q, true).unwrap();
        assert!(!s.head_deleted);
    }

    #[test]
    fn errors() {
        let q = iv_from_pairs(&[(7, 1)]);
        let mut ss = ss0();
        ss.seq = 0;
        assert_eq!(run(&ss, 8, 7, &q, false).unwrap_err(), StepErr::SeqZero);
        let mut ss = ss0();
        ss.clone_snaps.remove(&SnapId(8));
        assert_eq!(
            run(&ss, 8, 7, &q, false).unwrap_err(),
            StepErr::NoCloneSnaps
        );
        let mut ss = ss0();
        ss.clone_snaps.insert(SnapId(8), vec![]);
        assert_eq!(
            run(&ss, 8, 7, &q, false).unwrap_err(),
            StepErr::EmptyCloneSnaps
        );
        let mut ss = ss0();
        ss.clones.retain(|c| c.0 != 8);
        let q = iv_from_pairs(&[(5, 1), (7, 1)]);
        assert_eq!(run(&ss, 8, 7, &q, false).unwrap_err(), StepErr::NotInClones);
    }
}
