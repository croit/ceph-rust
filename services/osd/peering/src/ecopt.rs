// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Optimized EC (mode O, adr 0067) shard-role bookkeeping: `partial_writes_last_complete` (pwlc) rules as pure
//! functions on [`PgInfo`] (spec ec-optimized.md 8), the nonprimary missing-skip rule (5.2) and the divergent-entry
//! filter (6.2). Callers own the store transaction; nothing here does I/O.

use crate::ecroll::EcCtx;
use crate::plog::MissingSet;
use denc::types::{Eversion, ShardId};
use pgwire::{LogEntry, PgInfo};
use std::collections::VecDeque;

/// pwlc "invalid" sentinel (backfill / async recovery target until the next interval): epoch 0, version max.
pub const PWLC_INVALID: Eversion = Eversion {
    version: u64::MAX,
    epoch: 0,
};

fn is_invalid(v: Eversion) -> bool {
    v.version == u64::MAX
}

/// Did `e` write shard `s`? (`written_shards` empty = all shards.)
pub fn writes_shard(e: &LogEntry, s: u32) -> bool {
    e.written_shards.is_empty()
        || (s < 128 && e.written_shards.0[s as usize / 64] >> (s % 64) & 1 == 1)
}

/// `partial_write` (spec 8): entry `e` passed the rollback cursor (roll-forward, trim or skip) on a PRIMARY-CAPABLE
/// shard; `prev` = version of the log entry before it (or the log tail). Nonprimary shards never maintain pwlc.
pub fn partial_write(info: &mut PgInfo, ctx: &EcCtx, prev: Eversion, e: &LogEntry) {
    if !ctx.opt || ctx.np {
        return;
    }
    if e.written_shards.is_empty() && info.partial_writes_last_complete.is_empty() {
        return;
    }
    for s in 0..128u32 {
        if ctx.np_set >> s & 1 == 0 {
            continue;
        }
        let key = ShardId(s as i8);
        let cur = info.partial_writes_last_complete.get(&key).copied();
        if !writes_shard(e, s) {
            match cur {
                None => {
                    // first partial write since every log was updated
                    info.partial_writes_last_complete
                        .insert(key, (prev, e.version));
                    info.partial_writes_last_complete_epoch = ctx.epoch;
                }
                Some((a, b)) if a == b => {
                    if is_invalid(a) || a >= e.version {
                        // invalid (backfill/async target) or ahead of the entry (peering adjusted it): keep
                    } else {
                        info.partial_writes_last_complete
                            .insert(key, (prev, e.version));
                        info.partial_writes_last_complete_epoch = ctx.epoch;
                    }
                }
                Some((a, b)) if b == prev => {
                    // contiguous run of partial writes
                    info.partial_writes_last_complete
                        .insert(key, (a, e.version));
                    info.partial_writes_last_complete_epoch = ctx.epoch;
                }
                Some(_) => {} // gap: cannot update
            }
        } else if let Some((a, _)) = cur {
            // the shard's log got this entry: the partial-write run ends here
            if !is_invalid(a) && a < e.version {
                info.partial_writes_last_complete
                    .insert(key, (e.version, e.version));
                info.partial_writes_last_complete_epoch = ctx.epoch;
            }
        }
    }
}

/// `proc_master_log` keep rule (prim spec C.3) on the primary's log `es` (tail `tail`) against the log of shard `from`
/// with head `ohead` (pwlc applied) and newest entry `olast`; `infos` = (shard, info) of every peer and us. Our entries
/// after the common point that did not write `from` and that every currently present written shard has are not
/// divergent: `partial_write` records each in `info`'s pwlc (after `consider_adjusting_pwlc` restarted it at the
/// common point). Returns the index of the last kept entry.
pub fn keep_partial_writes(
    es: &VecDeque<LogEntry>,
    tail: Eversion,
    info: &mut PgInfo,
    ctx: &EcCtx,
    (from, ohead, olast): (u32, Eversion, Option<Eversion>),
    infos: &[(i8, PgInfo)],
) -> Option<usize> {
    let first = es.front()?.version; // empty log (split): nothing to keep
    let n = es.partition_point(|e| e.version <= ohead);
    // common point: both logs hold it, or `from` has nothing between it and its head
    let (lc, start) = if n > 0 {
        let pv = es[n - 1].version;
        if olast.is_some_and(|o| o > pv) {
            return None; // the other log is ahead of ours there: plain divergence
        }
        (pv, n)
    } else if olast.is_none_or(|o| o < first) {
        (tail, 0)
    } else {
        return None;
    };
    // consider_adjusting_pwlc
    for w in info.partial_writes_last_complete.values_mut() {
        if w.1 != lc {
            *w = (lc, lc);
        }
    }
    let les = |i: &PgInfo| {
        let a = i.history.last_epoch_started;
        if i.is_incomplete() {
            a
        } else {
            a.max(i.last_epoch_started)
        }
    };
    let max_les = infos.iter().map(|(_, i)| les(i)).max().unwrap_or(0);
    let min_lu = infos
        .iter()
        .filter(|(_, i)| i.last_epoch_started >= max_les)
        .map(|(_, i)| i.last_update)
        .min()
        .unwrap_or_default();
    let present: Vec<i8> = infos
        .iter()
        .filter(|(_, i)| i.last_update >= min_lu && i.last_epoch_started >= max_les)
        .map(|(s, _)| *s)
        .collect();
    let mut kept = None;
    for (j, e) in es.iter().enumerate().skip(start) {
        if writes_shard(e, from) {
            break; // meant for `from`, which lacks it: the divergent tail starts here
        }
        // a present shard the entry was written to lacks it (unless another copy of that shard has it)
        let lacking = infos.iter().any(|(s, i)| {
            *s >= 0
                && writes_shard(e, *s as u32)
                && i.last_update < e.version
                && present.contains(s)
                && !infos
                    .iter()
                    .any(|(s2, i2)| s2 == s && i2.last_update >= e.version)
        });
        if lacking {
            break;
        }
        let prev = if j == 0 { tail } else { es[j - 1].version };
        partial_write(info, ctx, prev, e);
        kept = Some(j);
    }
    kept
}

/// `apply_pwlc` (spec 8): raise `info.last_update` (and `last_complete` if it was complete, and the log `head`) to
/// `to` when `from <= last_update < to`. Returns true if applied.
pub fn apply_pwlc(
    pwlc: (Eversion, Eversion),
    info: &mut PgInfo,
    head: Option<&mut Eversion>,
) -> bool {
    let (from, to) = pwlc;
    if to <= info.last_update || from > info.last_update {
        return false;
    }
    if info.last_complete == info.last_update {
        info.last_complete = to;
    }
    info.last_update = to;
    if let Some(h) = head
        && to > *h
    {
        *h = to;
    }
    true
}

/// pwlc merge of `update_peer_info` (spec 8): adopt `oinfo`'s pwlc entries that are newer (epoch, then `to`, then
/// lower `from`); pwlc reported by a nonprimary shard is ignored. Returns true if anything changed.
pub fn merge_pwlc(info: &mut PgInfo, oinfo: &PgInfo, from_is_np: bool) -> bool {
    if oinfo.partial_writes_last_complete.is_empty() || from_is_np {
        return false;
    }
    let (oe, e) = (
        oinfo.partial_writes_last_complete_epoch,
        info.partial_writes_last_complete_epoch,
    );
    let mut updated = false;
    for (shard, &(ofrom, oto)) in &oinfo.partial_writes_last_complete {
        let take = match info.partial_writes_last_complete.get(shard) {
            None => true,
            Some(&(from, to)) => oe > e || (oe == e && (oto > to || (oto == to && ofrom < from))),
        };
        if take {
            info.partial_writes_last_complete
                .insert(*shard, (ofrom, oto));
            updated = true;
        }
    }
    if updated {
        info.partial_writes_last_complete_epoch = e.max(oe);
    }
    updated
}

/// `consider_rollback_pwlc(head)` (prim spec B.3): partial-write coverage past `head` is void (those entries are
/// divergent). Invalid sentinels stay. Returns true if anything changed.
pub fn rollback_pwlc(info: &mut PgInfo, head: Eversion) -> bool {
    let mut changed = false;
    for w in info.partial_writes_last_complete.values_mut() {
        if is_invalid(w.0) {
            continue;
        }
        if head.version < w.0.version {
            *w = (head, head);
            changed = true;
        } else if head < w.1 {
            w.1 = head;
            changed = true;
        }
    }
    changed
}

/// Backfill / async-recovery shard: pwlc invalid until the next interval (spec 5.3).
pub fn invalidate_pwlc(info: &mut PgInfo) {
    for v in info.partial_writes_last_complete.values_mut() {
        *v = (PWLC_INVALID, PWLC_INVALID);
    }
    info.partial_writes_last_complete_epoch = 0;
}

/// Clamp every pwlc entry to a (lowered) head `to`: to-version = min(to-version, `to`), then from-version = min(from,
/// to-version). Invalid sentinels (epoch 0) of a backfill / async-recovery shard order below every real version and
/// stay: clamped, they would claim that shard has every entry up to `to`. Shared by `split_pwlc` and the primary
/// rolling a peer's `last_update` back (21.2.0 B5, `proc_replica_log`).
pub fn clamp_pwlc(info: &mut PgInfo, to: Eversion) {
    for (a, b) in info.partial_writes_last_complete.values_mut() {
        if *b > to {
            *b = to;
        }
        if *a > *b {
            *a = *b;
        }
    }
}

/// `split_pwlc`: after a log split no pwlc entry may point past `prev` (version of the newest entry at or below the
/// rollback-info cursor, or the tail).
pub fn split_pwlc(info: &mut PgInfo, prev: Eversion) {
    clamp_pwlc(info, prev)
}

/// Version `split_pwlc` clamps to: the newest entry at or below `rollback_info_trimmed_to`, else the tail.
pub fn rit_prev(log: &pgwire::PgLog) -> Eversion {
    let i = log
        .log
        .partition_point(|e| e.version <= log.rollback_info_trimmed_to);
    if i == 0 {
        log.tail
    } else {
        log.log[i - 1].version
    }
}

/// PG merge (target side): every pwlc entry collapses to the merged `last_update`, stamped with `epoch`.
pub fn merge_reset_pwlc(info: &mut PgInfo, epoch: u32) {
    if info.partial_writes_last_complete.is_empty() {
        return;
    }
    let lu = info.last_update;
    for v in info.partial_writes_last_complete.values_mut() {
        *v = (lu, lu);
    }
    info.partial_writes_last_complete_epoch = epoch;
}

/// Generation the EC_OMAP records of `es[i]` apply to at roll-forward (spec 12.2, OQ O2): the live object, unless a
/// LATER entry of the same object in the log moved it away (DELETE, LOST_DELETE, REPLACE, CLONE of a head): then the
/// stash generation of the first such entry. Derived from the log, so it survives restarts (classic keeps it in an
/// in-memory journal).
pub fn omap_generation(es: &VecDeque<LogEntry>, i: usize) -> u64 {
    let e = &es[i];
    es.range(i + 1..)
        .filter(|x| x.soid == e.soid)
        .find_map(crate::ecomap::moved_to)
        .unwrap_or(crate::ecroll::LIVE)
}

/// Roll-forward / trim of `es[i]` on our shard: stash cleanup, and on a primary-capable shard of mode O the EC_OMAP
/// records applied to [`omap_generation`] (after the entry's own stash removal, as the classic visitor order).
pub fn rollforward_entry(
    ctx: &EcCtx,
    es: &VecDeque<LogEntry>,
    i: usize,
) -> Result<Vec<crate::store::ShardOp>, crate::ecroll::RollErr> {
    let mut v = crate::ecroll::cleanup_entry(ctx, &es[i])?;
    if ctx.opt && !ctx.np && es[i].mod_desc.can_local_rollback {
        let ops = crate::ecroll::entry_ops(&es[i])?;
        let mut generation = None;
        for op in ops {
            if let ec::moddesc::ModOp::EcOmap(omap) = op {
                let g = *generation.get_or_insert_with(|| omap_generation(es, i));
                v.push(crate::store::ShardOp::Omap {
                    soid: es[i].soid.clone(),
                    generation: g,
                    omap,
                });
            }
        }
    }
    Ok(v)
}

/// One sub-read omap batch (classic rule): entries until `max_entries` or the byte budget, always at least one;
/// `true` = the iterator was exhausted. A batch that is not the last one never ends at the empty key: the next batch
/// starts after the last key of this one ([`omap_wire_after`]), and the wire start key cannot say "after the empty key"
/// (the empty start key means "from the first key").
pub type OmapBatch = Vec<(Vec<u8>, Vec<u8>)>;

pub fn omap_batch(
    mut it: impl Iterator<Item = (Vec<u8>, Vec<u8>)>,
    max_bytes: u64,
    max_entries: usize,
) -> (OmapBatch, bool) {
    let mut out: OmapBatch = Vec::new();
    let mut avail = max_bytes;
    loop {
        let Some((k, v)) = it.next() else {
            return (out, true);
        };
        let n = (k.len() + v.len()) as u64;
        let cut = out.last().is_some_and(|(l, _)| !l.is_empty());
        if cut && ((max_entries > 0 && out.len() >= max_entries) || n > avail) {
            return (out, false);
        }
        avail = avail.saturating_sub(n);
        out.push((k, v));
    }
}

/// Cursor of an `ECSubRead::omap_read_from` start key: the empty key = from the first key (the empty key included),
/// any other key = strictly after it. (The classic shard seeks strictly after the start key even when it is empty,
/// which never serves an empty omap key; we serve it.)
pub fn omap_wire_after(start: &[u8]) -> Option<&[u8]> {
    (!start.is_empty()).then_some(start)
}

/// Deep-scrub digest rule of a pool (L0 hinfo check, L1 digest 0, O whole-file crc).
pub fn scrub_mode(e: &pgwire::EcPoolInfo) -> replwire::ecscrub::EcScrubMode {
    use replwire::ecscrub::EcScrubMode as M;
    if e.optimized {
        M::Optimized
    } else {
        e.overwrites.into()
    }
}

/// `add_next_event` with the nonprimary skip rule (spec 5.2): an entry that did not write our nonprimary shard does
/// not make a not-yet-missing object missing.
pub fn add_next_event(missing: &mut MissingSet, ctx: Option<&EcCtx>, e: &LogEntry) {
    if let Some(c) = ctx
        && c.opt
        && c.np
        && !writes_shard(e, c.shard)
        && !missing.contains(&e.soid)
    {
        return;
    }
    missing.add_next_event(e);
}

#[cfg(test)]
mod tests {
    use super::*;
    use denc::types::{Hobject, SpgT};
    use pgwire::LogOp;

    fn ctx(np: bool) -> EcCtx {
        // k=3 m=2: raw 1, 2 = shards 1, 2 nonprimary
        EcCtx {
            stripe_width: 3 * 4096,
            chunk: 4096,
            shard: if np { 1 } else { 0 },
            opt: true,
            k: 3,
            raw: if np { 1 } else { 0 },
            np,
            np_set: 0b110,
            epoch: 9,
        }
    }

    fn ent(v: u64, written: &[u32]) -> LogEntry {
        let mut e = LogEntry::new(
            LogOp::MODIFY,
            Hobject::default(),
            Eversion::new(5, v),
            Eversion::new(5, v.saturating_sub(1)),
        );
        for s in written {
            e.written_shards.0[*s as usize / 64] |= 1 << (s % 64);
        }
        e
    }

    fn ev(v: u64) -> Eversion {
        Eversion::new(5, v)
    }

    /// Prim spec C.3 example: k=4 m=2, shard 3 (nonprimary) fetched at v5; v6 and v7 skipped it and every present
    /// written shard has them: both kept, pwlc follows; shard 2 stopped at v6: v7 is divergent.
    #[test]
    fn keep_partial_writes_spec_example() {
        let c = EcCtx {
            stripe_width: 4 * 4096,
            chunk: 4096,
            shard: 0,
            opt: true,
            k: 4,
            raw: 0,
            np: false,
            np_set: 0b1110,
            epoch: 9,
        };
        let es: std::collections::VecDeque<_> =
            vec![ent(5, &[]), ent(6, &[0, 1, 4, 5]), ent(7, &[0, 2, 4, 5])].into();
        let peers = |lu2: u64| -> Vec<(i8, PgInfo)> {
            [(0, 7), (1, 6), (2, lu2), (3, 5), (4, 7), (5, 7)]
                .into_iter()
                .map(|(s, v)| {
                    let i = PgInfo {
                        last_update: ev(v),
                        ..Default::default()
                    };
                    (s, i)
                })
                .collect()
        };
        let mut info = PgInfo::default();
        info.partial_writes_last_complete
            .insert(ShardId(3), (ev(5), ev(5)));
        let k = keep_partial_writes(
            &es,
            ev(4),
            &mut info,
            &c,
            (3, ev(5), Some(ev(5))),
            &peers(7),
        );
        assert_eq!(k, Some(2));
        assert_eq!(pw(&info, 3), Some((5, 7)));
        assert_eq!(pw(&info, 2), Some((7, 7)));
        assert_eq!(pw(&info, 1), Some((6, 7)));
        let mut info = PgInfo::default();
        let k = keep_partial_writes(
            &es,
            ev(4),
            &mut info,
            &c,
            (3, ev(5), Some(ev(5))),
            &peers(6),
        );
        assert_eq!(k, Some(1), "v7 is missing on present shard 2");
        // an entry meant for the fetched shard is divergent at once; the other log ahead of ours: nothing kept
        let mut info = PgInfo::default();
        assert_eq!(
            keep_partial_writes(
                &es,
                ev(4),
                &mut info,
                &c,
                (1, ev(5), Some(ev(5))),
                &peers(7)
            ),
            None
        );
        assert_eq!(
            keep_partial_writes(
                &es,
                ev(4),
                &mut info,
                &c,
                (3, ev(5), Some(ev(6))),
                &peers(7)
            ),
            None
        );
        // a lagging shard that is not present (older les) does not block
        let mut p = peers(6);
        p[2].1.last_epoch_started = 0;
        for x in p.iter_mut().filter(|x| x.0 != 2) {
            x.1.last_epoch_started = 3;
        }
        let mut info = PgInfo::default();
        assert_eq!(
            keep_partial_writes(&es, ev(4), &mut info, &c, (3, ev(5), Some(ev(5))), &p),
            Some(2)
        );
    }

    fn pw(info: &PgInfo, s: i8) -> Option<(u64, u64)> {
        info.partial_writes_last_complete
            .get(&ShardId(s))
            .map(|(a, b)| (a.version, b.version))
    }

    /// Own vectors: a run of partial writes skipping shard 2, then a write to 2, then a gap.
    #[test]
    fn partial_write_sequence() {
        let c = ctx(false);
        let mut i = PgInfo::new(SpgT::default());
        // full write (all shards): no pwlc yet -> nothing
        partial_write(&mut i, &c, ev(0), &ent(1, &[]));
        assert!(i.partial_writes_last_complete.is_empty());
        // writes 0,1,3,4 (skips 2): first partial write
        partial_write(&mut i, &c, ev(1), &ent(2, &[0, 1, 3, 4]));
        assert_eq!((pw(&i, 1), pw(&i, 2)), (None, Some((1, 2))));
        assert_eq!(i.partial_writes_last_complete_epoch, 9);
        // contiguous skip of 2 again; shard 1 written
        partial_write(&mut i, &c, ev(2), &ent(3, &[0, 1, 3, 4]));
        assert_eq!((pw(&i, 1), pw(&i, 2)), (None, Some((1, 3))));
        // shard 2 written: collapses
        partial_write(&mut i, &c, ev(3), &ent(4, &[0, 2, 3, 4]));
        assert_eq!((pw(&i, 1), pw(&i, 2)), (Some((3, 4)), Some((4, 4))));
        // shard 1 skipped with a gap in its run (pwlc 1 = (3,4), prev 6): unchanged
        partial_write(&mut i, &c, ev(6), &ent(7, &[0, 2, 3, 4]));
        assert_eq!((pw(&i, 1), pw(&i, 2)), (Some((3, 4)), Some((7, 7))));
        // nonprimary shards never maintain pwlc
        let mut j = PgInfo::new(SpgT::default());
        partial_write(&mut j, &ctx(true), ev(1), &ent(2, &[0]));
        assert!(j.partial_writes_last_complete.is_empty());
        // invalid sentinel stays
        invalidate_pwlc(&mut i);
        assert_eq!(i.partial_writes_last_complete_epoch, 0);
        partial_write(&mut i, &c, ev(7), &ent(8, &[0]));
        partial_write(&mut i, &c, ev(8), &ent(9, &[0, 1, 2]));
        assert!(
            i.partial_writes_last_complete
                .values()
                .all(|(a, b)| *a == PWLC_INVALID && *b == PWLC_INVALID)
        );
    }

    #[test]
    fn apply_and_merge() {
        let mut i = PgInfo::new(SpgT::default());
        i.last_update = ev(3);
        i.last_complete = ev(3);
        let mut head = ev(3);
        assert!(!apply_pwlc((ev(4), ev(6)), &mut i, Some(&mut head)));
        assert!(!apply_pwlc((ev(1), ev(3)), &mut i, Some(&mut head)));
        assert!(apply_pwlc((ev(2), ev(6)), &mut i, Some(&mut head)));
        assert_eq!(
            (i.last_update, i.last_complete, head),
            (ev(6), ev(6), ev(6))
        );
        i.last_complete = ev(4);
        assert!(apply_pwlc((ev(6), ev(8)), &mut i, None));
        assert_eq!((i.last_update, i.last_complete), (ev(8), ev(4)));

        let mut a = PgInfo::new(SpgT::default());
        let mut o = PgInfo::new(SpgT::default());
        o.partial_writes_last_complete
            .insert(ShardId(1), (ev(2), ev(5)));
        o.partial_writes_last_complete_epoch = 7;
        assert!(!merge_pwlc(&mut a, &o, true));
        assert!(merge_pwlc(&mut a, &o, false));
        assert_eq!(
            (pw(&a, 1), a.partial_writes_last_complete_epoch),
            (Some((2, 5)), 7)
        );
        // same epoch: higher `to` wins, then lower `from`
        o.partial_writes_last_complete
            .insert(ShardId(1), (ev(3), ev(5)));
        assert!(!merge_pwlc(&mut a, &o, false));
        o.partial_writes_last_complete
            .insert(ShardId(1), (ev(1), ev(5)));
        assert!(merge_pwlc(&mut a, &o, false));
        assert_eq!(pw(&a, 1), Some((1, 5)));
        // older epoch loses even with higher `to`
        o.partial_writes_last_complete_epoch = 6;
        o.partial_writes_last_complete
            .insert(ShardId(1), (ev(1), ev(9)));
        assert!(!merge_pwlc(&mut a, &o, false));
    }

    #[test]
    fn split_and_merge_reset() {
        let mut i = PgInfo::new(SpgT::default());
        i.partial_writes_last_complete
            .insert(ShardId(1), (ev(4), ev(9)));
        i.partial_writes_last_complete
            .insert(ShardId(2), (ev(9), ev(9)));
        i.partial_writes_last_complete
            .insert(ShardId(3), (ev(1), ev(2)));
        split_pwlc(&mut i, ev(6));
        assert_eq!(
            (pw(&i, 1), pw(&i, 2), pw(&i, 3)),
            (Some((4, 6)), Some((6, 6)), Some((1, 2)))
        );
        i.last_update = ev(12);
        merge_reset_pwlc(&mut i, 33);
        assert!(
            i.partial_writes_last_complete
                .values()
                .all(|v| *v == (ev(12), ev(12)))
        );
        assert_eq!(i.partial_writes_last_complete_epoch, 33);
    }

    /// A clamp (split, rolled-back peer head) leaves the invalid sentinel of a backfill / async-recovery shard alone:
    /// `Eversion` orders by (epoch, version) and the sentinel's epoch is 0, so it compares below every real head.
    /// Rewriting it into `(to, to)` would tell a primary that shard has every entry up to `to`.
    #[test]
    fn clamp_leaves_the_invalid_sentinel() {
        let mut i = PgInfo::new(SpgT::default());
        i.partial_writes_last_complete
            .insert(ShardId(1), (PWLC_INVALID, PWLC_INVALID));
        i.partial_writes_last_complete
            .insert(ShardId(2), (ev(4), ev(9)));
        split_pwlc(&mut i, ev(6));
        assert_eq!(pw(&i, 1), Some((u64::MAX, u64::MAX)));
        assert_eq!(pw(&i, 2), Some((4, 6)));
        clamp_pwlc(&mut i, ev(2));
        assert_eq!(pw(&i, 1), Some((u64::MAX, u64::MAX)));
        assert_eq!(pw(&i, 2), Some((2, 2)));
        // the sentinel never raises a lagging shard through `apply_pwlc`
        i.last_update = ev(1);
        let e = i.partial_writes_last_complete[&ShardId(1)];
        assert!(!apply_pwlc(e, &mut i, None));
        assert_eq!(i.last_update, ev(1));
    }

    #[test]
    fn np_missing_skip() {
        let mut m = MissingSet::new(true);
        let mut e = ent(5, &[0]);
        e.soid = Hobject::new(b"o", denc::types::SnapId::NOSNAP, 1, 1, b"");
        add_next_event(&mut m, Some(&ctx(true)), &e);
        assert!(m.is_empty());
        add_next_event(&mut m, Some(&ctx(false)), &e);
        assert!(m.contains(&e.soid));
        // already missing on the NP shard: the usual need update
        let mut e2 = ent(6, &[0]);
        e2.soid = e.soid.clone();
        add_next_event(&mut m, Some(&ctx(true)), &e2);
        assert_eq!(m.get(&e.soid).unwrap().need, ev(6));
    }
}
