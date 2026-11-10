// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! EC shard rollback / roll-forward executor (spec ec.md 7.5, 7.6; adr 0040): pure functions from a log entry's
//! `mod_desc` to shard-object operations. No I/O: the PG turns the result into [`StoreOp`]s inside the same store
//! transaction as the log change that caused it.

use crate::snaps::MapOp;
use crate::store::ShardOp;
use denc::types::Hobject;
use ec::moddesc::{ModOp, extent_set_has, parse};
use pgwire::LogEntry;

/// Generation of the live object (`ghobject_t::NO_GEN`).
pub const LIVE: u64 = u64::MAX;

/// Geometry of the pool and our shard (legacy modes L0/L1, or mode O when `opt`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EcCtx {
    pub stripe_width: u64,
    pub chunk: u64,
    pub shard: u32,
    /// Mode O (adr 0067): sparse per-shard sizes, written_shards rules, pwlc.
    pub opt: bool,
    /// Mode O: k (data shards) and our raw chunk index (shard size formula, ec-optimized.md 2.2).
    pub k: u32,
    pub raw: u32,
    /// Mode O: our shard is a nonprimary data shard (raw 1..k-1).
    pub np: bool,
    /// Mode O: bit set of every nonprimary shard id (pwlc maintenance on PC shards, spec 8).
    pub np_set: u128,
    /// Map epoch the PG is at (pwlc epoch stamps); 0 when built for a pure geometry query.
    pub epoch: u32,
}

impl EcCtx {
    /// Context of `shard` in pool `e` (supported pools only).
    pub fn of(e: &pgwire::EcPoolInfo, shard: u32) -> EcCtx {
        let raw = e
            .chunk_mapping
            .iter()
            .position(|s| *s == shard)
            .map_or(shard, |r| r as u32);
        EcCtx {
            stripe_width: u64::from(e.stripe_width),
            chunk: u64::from(e.chunk_size),
            shard,
            opt: e.optimized,
            k: e.k,
            raw,
            np: e.is_nonprimary(shard),
            np_set: if e.optimized {
                e.nonprimary
                    .iter()
                    .filter(|s| **s < 128)
                    .fold(0u128, |a, s| a | 1 << s)
            } else {
                0
            },
            epoch: 0,
        }
    }

    /// Shard file size for a logical object size: legacy `ceil(n / S) * C` (ec.md 3); mode O per shard (2.2).
    pub fn shard_size(&self, logical: u64) -> u64 {
        if self.stripe_width == 0 {
            return 0;
        }
        if self.opt {
            return ec::geom::opt_shard_size(
                logical,
                self.stripe_width,
                self.chunk,
                self.k,
                self.raw,
            );
        }
        logical.div_ceil(self.stripe_width) * self.chunk
    }

    /// Did entry `e` write our shard? Legacy: always. Mode O: `written_shards` empty (= all) or contains us.
    pub fn written(&self, e: &LogEntry) -> bool {
        !self.opt || crate::ecopt::writes_shard(e, self.shard)
    }
}

/// Undo of one divergent entry.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Rollback {
    pub shard_ops: Vec<ShardOp>,
    pub snap_ops: Vec<MapOp>,
}

/// Why an entry cannot be interpreted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollErr {
    /// `can_local_rollback` is false (the primary marked it unrollbackable).
    Unrollbackable,
    /// Unknown record id / undecodable body / record type we do not implement (EC omap).
    Unparsable(String),
}

/// The entry's rollback records in order of appearance.
pub fn entry_ops(e: &LogEntry) -> Result<Vec<ModOp>, RollErr> {
    if !e.mod_desc.can_local_rollback {
        return Err(RollErr::Unrollbackable);
    }
    parse(&e.mod_desc.bl).map_err(|x| RollErr::Unparsable(x.to_string()))
}

fn live_rm(soid: &Hobject) -> ShardOp {
    ShardOp::Remove {
        soid: soid.clone(),
        generation: LIVE,
    }
}

/// Undo `e` on our shard: the records in REVERSE order of appearance (ec.md 7.6).
pub fn rollback_entry(ctx: &EcCtx, e: &LogEntry) -> Result<Rollback, RollErr> {
    let ops = entry_ops(e)?;
    // A pool can become optimized while legacy entries are still divergent. Legacy writes always record the old
    // hinfo_key; optimized writes never modify it (ec.md 8.1, ec-optimized.md 3, 13). Those entries restore padded
    // shard sizes and all attributes even when our current role is a nonprimary optimized shard.
    let legacy = ops.iter().any(|op| {
        matches!(op, ModOp::SetAttrs(attrs) if attrs.iter().any(|(k, _)| k.as_slice() == ec::HINFO_KEY.as_bytes()))
    });
    let ctx = &EcCtx {
        opt: ctx.opt && !legacy,
        ..*ctx
    };
    let soid = &e.soid;
    let mut r = Rollback::default();
    for op in ops.iter().rev() {
        match op {
            ModOp::Append { old_size } => r.shard_ops.push(ShardOp::Truncate {
                soid: soid.clone(),
                generation: LIVE,
                size: ctx.shard_size(*old_size),
            }),
            ModOp::SetAttrs(attrs) if ctx.opt && ctx.np => {
                // nonprimary shard (spec 6.2): only `_`, only if the entry wrote us; the restored OI names our own
                // older version when `shard_versions` says we lag
                if !ctx.written(e) {
                    continue;
                }
                let Some(old) = attrs
                    .iter()
                    .find(|(k, _)| k.as_slice() == b"_")
                    .and_then(|(_, v)| v.clone())
                else {
                    continue;
                };
                let oi = np_object_info(&old, ctx.shard).map_err(RollErr::Unparsable)?;
                r.shard_ops.push(ShardOp::SetAttrs {
                    soid: soid.clone(),
                    generation: LIVE,
                    attrs: vec![(b"_".to_vec(), Some(oi))],
                });
            }
            ModOp::SetAttrs(attrs) => r.shard_ops.push(ShardOp::SetAttrs {
                soid: soid.clone(),
                generation: LIVE,
                attrs: attrs.clone(),
            }),
            ModOp::Delete { version } | ModOp::TryDelete { version } => {
                r.shard_ops.push(live_rm(soid));
                r.shard_ops.push(ShardOp::Rename {
                    soid: soid.clone(),
                    from_gen: *version,
                    to_gen: LIVE,
                });
            }
            ModOp::Create => r.shard_ops.push(live_rm(soid)),
            ModOp::UpdateSnaps(old) => {
                if crate::snaps::is_clone(soid) {
                    r.snap_ops.push(if old.is_empty() {
                        MapOp::Remove {
                            clone: soid.clone(),
                        }
                    } else {
                        MapOp::Set {
                            clone: soid.clone(),
                            snaps: old.clone(),
                        }
                    });
                }
            }
            ModOp::RollbackExtents {
                generation,
                extents,
                object_size,
                shards,
            } => {
                let lim = object_size.map(|s| ctx.shard_size(s));
                let mut any = false;
                for (i, (off, len)) in extents.iter().enumerate() {
                    // v3: per-extent shard set (empty vector or set = all shards); `parse` refused any vector that is
                    // neither empty nor parallel to the extents (case 5, never a partial rollback)
                    if !shards.is_empty()
                        && !shards.get(i).is_some_and(|s| extent_set_has(s, ctx.shard))
                    {
                        continue;
                    }
                    // the extent is ours: the stash generation goes even if the extent lies past the shard size
                    any = true;
                    let len = match lim {
                        Some(l) if *off >= l => continue,
                        Some(l) => (*len).min(l - *off),
                        None => *len,
                    };
                    r.shard_ops.push(ShardOp::CloneRange {
                        soid: soid.clone(),
                        from_gen: *generation,
                        to_gen: LIVE,
                        off: *off,
                        len,
                    });
                }
                if any || shards.is_empty() {
                    r.shard_ops.push(ShardOp::Remove {
                        soid: soid.clone(),
                        generation: *generation,
                    });
                }
            }
            // never applied before roll-forward: nothing to undo (spec 6.2)
            ModOp::EcOmap(_) => {}
        }
    }
    Ok(r)
}

/// Nonprimary shard OI rollback (spec 6.2): an old `_` whose `shard_versions[us]` differs from its `version` is
/// rewritten as version := our shard version, `shard_versions` cleared (what this shard really held).
pub fn np_object_info(old: &[u8], shard: u32) -> Result<Vec<u8>, String> {
    let mut oi: replwire::ObjectInfo =
        denc::from_slice(old).map_err(|e| format!("object_info: {e}"))?;
    match oi
        .shard_versions
        .get(&denc::types::ShardId(shard as i8))
        .copied()
    {
        Some(v) if v != oi.version => {
            oi.version = v;
            oi.shard_versions.clear();
            denc::to_vec(&oi).map_err(|e| format!("object_info encode: {e}"))
        }
        _ => Ok(old.to_vec()),
    }
}

/// Stash objects that roll-forward / trim of `e` deletes (ec.md 7.6 ROLLFORWARD). An unrollbackable entry owns no
/// stash; an unparsable one is reported to the caller (the stash, if any, leaks until the activation GC).
pub fn cleanup_entry(ctx: &EcCtx, e: &LogEntry) -> Result<Vec<ShardOp>, RollErr> {
    let ops = match entry_ops(e) {
        Ok(o) => o,
        Err(RollErr::Unrollbackable) => return Ok(vec![]),
        Err(x) => return Err(x),
    };
    Ok(ec::moddesc::stash_generations_for(&ops, ctx.shard)
        .into_iter()
        .map(|g| ShardOp::Remove {
            soid: e.soid.clone(),
            generation: g,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use denc::types::Eversion;
    use ec::moddesc::ModDescBuilder;
    use pgwire::{LogOp, ObjectModDesc};

    fn entry(v: u64, bl: Vec<u8>, ver: u8) -> LogEntry {
        let mut e = LogEntry::new(
            LogOp::MODIFY,
            Hobject::default(),
            Eversion::new(5, v),
            Eversion::default(),
        );
        e.mod_desc = ObjectModDesc {
            version: ver,
            can_local_rollback: true,
            rollback_info_completed: false,
            bl,
        };
        e
    }

    const CTX: EcCtx = EcCtx {
        stripe_width: 8192,
        chunk: 4096,
        shard: 1,
        opt: false,
        k: 2,
        raw: 1,
        np: false,
        np_set: 0,
        epoch: 0,
    };

    #[test]
    fn append_and_attrs_roll_back_in_reverse() {
        let mut b = ModDescBuilder::new();
        b.set_attrs(&[
            (b"hinfo_key".to_vec(), Some(b"old".to_vec())),
            (b"x".to_vec(), None),
        ]);
        b.append(10_000);
        let (bl, v, _) = b.finish();
        let r = rollback_entry(&CTX, &entry(7, bl, v)).unwrap();
        // shard size of 10000 logical bytes = ceil(10000/8192) * 4096 = 8192
        assert!(matches!(
            r.shard_ops[0],
            ShardOp::Truncate { size: 8192, .. }
        ));
        assert!(matches!(r.shard_ops[1], ShardOp::SetAttrs { .. }));
        assert_eq!(r.shard_ops.len(), 2);
    }

    #[test]
    fn delete_stash_and_extents() {
        let mut b = ModDescBuilder::new();
        b.rollback_extents(9, &[(0, 4096), (8192, 4096)]);
        b.append(16384);
        let (bl, v, _) = b.finish();
        let e = entry(9, bl, v);
        let r = rollback_entry(&CTX, &e).unwrap();
        assert!(matches!(
            r.shard_ops[0],
            ShardOp::Truncate { size: 8192, .. }
        ));
        assert!(matches!(
            r.shard_ops[1],
            ShardOp::CloneRange {
                from_gen: 9,
                to_gen: LIVE,
                off: 0,
                len: 4096,
                ..
            }
        ));
        assert!(matches!(
            r.shard_ops[3],
            ShardOp::Remove { generation: 9, .. }
        ));
        // cleanup (roll-forward) only removes the stash
        let c = cleanup_entry(&CTX, &e).unwrap();
        assert_eq!(c.len(), 1);
        assert!(matches!(c[0], ShardOp::Remove { generation: 9, .. }));

        let mut b = ModDescBuilder::new();
        b.delete(11);
        let (bl, v, _) = b.finish();
        let r = rollback_entry(&CTX, &entry(11, bl, v)).unwrap();
        assert!(matches!(
            r.shard_ops[0],
            ShardOp::Remove {
                generation: LIVE,
                ..
            }
        ));
        assert!(matches!(
            r.shard_ops[1],
            ShardOp::Rename {
                from_gen: 11,
                to_gen: LIVE,
                ..
            }
        ));
    }

    #[test]
    fn unrollbackable_and_garbage() {
        let mut e = entry(3, vec![], 1);
        e.mod_desc.can_local_rollback = false;
        assert_eq!(rollback_entry(&CTX, &e), Err(RollErr::Unrollbackable));
        assert_eq!(cleanup_entry(&CTX, &e), Ok(vec![]));
        let e = entry(4, vec![1, 2, 3, 99, 77], 1);
        assert!(matches!(
            rollback_entry(&CTX, &e),
            Err(RollErr::Unparsable(_))
        ));
    }

    /// k=2 m=2 C=4K mode O: shard 0 = raw 0 (PC), shard 1 = raw 1 (NP), shards 2,3 parity (PC).
    fn octx(shard: u32) -> EcCtx {
        EcCtx {
            stripe_width: 8192,
            chunk: 4096,
            shard,
            opt: true,
            k: 2,
            raw: shard,
            np: shard == 1,
            np_set: 0b10,
            epoch: 3,
        }
    }

    fn written(mut e: LogEntry, shards: &[u32]) -> LogEntry {
        for s in shards {
            e.written_shards.0[0] |= 1 << s;
        }
        e
    }

    #[test]
    fn legacy_append_rollback_after_optimized_switch_preserves_padded_shard() {
        let mut hinfo = ec::HashInfo::new(4);
        hinfo.clear_hashes(4096);
        let old_hinfo = hinfo.encode();
        let attrs = vec![(ec::HINFO_KEY.as_bytes().to_vec(), Some(old_hinfo))];
        let mut b = ModDescBuilder::new();
        b.set_attrs(&attrs);
        b.append(100);
        let (bl, v, _) = b.finish();
        let e = entry(7, bl, v);
        for shard in 0..4 {
            let r = rollback_entry(&octx(shard), &e).unwrap();
            let legacy_ctx = EcCtx { shard, ..CTX };
            assert_eq!(r, rollback_entry(&legacy_ctx, &e).unwrap());
            assert_eq!(
                r.shard_ops,
                vec![
                    ShardOp::Truncate {
                        soid: e.soid.clone(),
                        generation: LIVE,
                        size: 4096,
                    },
                    ShardOp::SetAttrs {
                        soid: e.soid.clone(),
                        generation: LIVE,
                        attrs: attrs.clone(),
                    },
                ],
                "legacy rollback on shard {shard} after enabling optimized EC"
            );
        }
    }

    #[test]
    fn optimized_append_on_legacy_object_uses_optimized_rollback() {
        // An optimized write of a legacy object leaves hinfo_key on disk, but records only its updated attributes.
        // The old OI may describe a legacy object; its size and absence of shard_versions do not select legacy mode.
        let oi = replwire::ObjectInfo {
            size: 100,
            ..Default::default()
        };
        let mut b = ModDescBuilder::new();
        b.set_attrs(&[(b"_".to_vec(), Some(denc::to_vec(&oi).unwrap()))]);
        b.append(4096);
        let (bl, v, _) = b.finish();
        let e = entry(7, bl, v);
        let r = rollback_entry(&octx(1), &e).unwrap();
        assert!(matches!(r.shard_ops[0], ShardOp::Truncate { size: 0, .. }));
        assert!(matches!(
            &r.shard_ops[1],
            ShardOp::SetAttrs { attrs, .. } if attrs.len() == 1 && attrs[0].0 == b"_"
        ));
    }

    /// APPEND rolls back to the per-shard O size (100 logical bytes: raw 1 holds nothing).
    #[test]
    fn opt_append_sizes_per_shard() {
        let mut b = ModDescBuilder::new();
        b.append(100);
        let (bl, v, _) = b.finish();
        let e = entry(7, bl, v);
        let size = |s| match rollback_entry(&octx(s), &e).unwrap().shard_ops[0] {
            ShardOp::Truncate { size, .. } => size,
            ref o => panic!("{o:?}"),
        };
        assert_eq!([0, 1, 2, 3].map(size), [4096, 0, 4096, 4096]);
        // one stripe + 100 bytes: raw 0 holds 4096 + 100, raw 1 only its full-stripe chunk
        let mut b = ModDescBuilder::new();
        b.append(8192 + 100);
        let (bl, v, _) = b.finish();
        let e = entry(8, bl, v);
        let size = |s| match rollback_entry(&octx(s), &e).unwrap().shard_ops[0] {
            ShardOp::Truncate { size, .. } => size,
            ref o => panic!("{o:?}"),
        };
        assert_eq!([0, 1, 2, 3].map(size), [8192, 4096, 8192, 8192]);
    }

    /// v3 extents: an extent applies to the shards of its set (empty = all), clipped to the O shard size of
    /// `object_size`; the stash goes on every shard with at least one extent, kept elsewhere.
    #[test]
    fn opt_rollback_extents_sets() {
        let mut b = ModDescBuilder::new();
        // extent A on shards {0,2,3}, extent B on all shards, beyond shard 1's size (object 4096 -> shard 1 size 0)
        b.rollback_extents_v3(9, &[(0, 4096), (4096, 4096)], 4096, &[[0b1101, 0], [0, 0]]);
        let (bl, v, _) = b.finish();
        let e = entry(9, bl, v);
        // shard 1: B is ours but past its size (0): no copy, stash removed
        let r = rollback_entry(&octx(1), &e).unwrap();
        assert_eq!(r.shard_ops.len(), 1, "{:?}", r.shard_ops);
        assert!(matches!(
            r.shard_ops[0],
            ShardOp::Remove { generation: 9, .. }
        ));
        // shard 0: A copied, B past size 4096: stash removed
        let r = rollback_entry(&octx(0), &e).unwrap();
        assert!(matches!(
            r.shard_ops[0],
            ShardOp::CloneRange {
                off: 0,
                len: 4096,
                from_gen: 9,
                ..
            }
        ));
        assert!(matches!(
            r.shard_ops[1],
            ShardOp::Remove { generation: 9, .. }
        ));
        assert_eq!(r.shard_ops.len(), 2);
        // a set naming only shard 2: shard 3 untouched, stash stays (it was never created there)
        let mut b = ModDescBuilder::new();
        b.rollback_extents_v3(10, &[(0, 4096)], 8192, &[[0b100, 0]]);
        let (bl, v, _) = b.finish();
        let e = entry(10, bl, v);
        assert!(rollback_entry(&octx(3), &e).unwrap().shard_ops.is_empty());
        assert_eq!(cleanup_entry(&octx(3), &e), Ok(vec![]));
        assert_eq!(cleanup_entry(&octx(2), &e).unwrap().len(), 1);
    }

    /// A v3 record with fewer shard sets than extents (count truncated, review 2026-11-03 #5) is unparsable: no
    /// partial rollback that restores the first extent, skips the rest and drops the stash; the caller removes the
    /// object and recovers it (pglog case 5), the stash stays.
    #[test]
    fn opt_short_shard_set_vector_is_unparsable() {
        let mut b = ModDescBuilder::new();
        b.rollback_extents_v3(
            9,
            &[(0, 4096), (4096, 4096)],
            8192,
            &[[0b1111, 0], [0b1111, 0]],
        );
        let (mut bl, v, _) = b.finish();
        // the shard-set count is the u32 before the two sets (2 one-byte varints each)
        let at = bl.len() - 8;
        assert_eq!(bl[at..at + 4], 2u32.to_le_bytes());
        bl[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
        let e = entry(9, bl, v);
        for s in 0..4 {
            assert!(
                matches!(rollback_entry(&octx(s), &e), Err(RollErr::Unparsable(_))),
                "shard {s}: {:?}",
                rollback_entry(&octx(s), &e)
            );
            assert!(matches!(
                cleanup_entry(&octx(s), &e),
                Err(RollErr::Unparsable(_))
            ));
        }
    }

    /// SETATTRS on a nonprimary shard: unwritten -> nothing; written -> only `_`, rewritten to our shard version.
    #[test]
    fn opt_np_setattrs() {
        use denc::types::ShardId;
        let mut oi = replwire::ObjectInfo::new(Hobject::default());
        oi.version = Eversion::new(5, 20);
        oi.shard_versions.insert(ShardId(1), Eversion::new(5, 12));
        let old = denc::to_vec(&oi).unwrap();
        let mut b = ModDescBuilder::new();
        b.set_attrs(&[
            (b"_".to_vec(), Some(old.clone())),
            (b"snapset".to_vec(), Some(b"s".to_vec())),
            (b"user.x".to_vec(), None),
        ]);
        let (bl, v, _) = b.finish();
        let e = entry(21, bl, v);
        // unwritten NP shard
        let e_un = written(e.clone(), &[0, 2, 3]);
        assert!(
            rollback_entry(&octx(1), &e_un)
                .unwrap()
                .shard_ops
                .is_empty()
        );
        // written NP shard: only `_`, version 12, no shard_versions
        let e_w = written(e.clone(), &[0, 1, 2, 3]);
        let r = rollback_entry(&octx(1), &e_w).unwrap();
        let ShardOp::SetAttrs { attrs, .. } = &r.shard_ops[0] else {
            panic!("{r:?}")
        };
        assert_eq!(attrs.len(), 1);
        let got: replwire::ObjectInfo = denc::from_slice(attrs[0].1.as_ref().unwrap()).unwrap();
        assert_eq!(got.version, Eversion::new(5, 12));
        assert!(got.shard_versions.is_empty());
        // PC shard: every attr incl. the removal
        let r = rollback_entry(&octx(2), &e_w).unwrap();
        let ShardOp::SetAttrs { attrs, .. } = &r.shard_ops[0] else {
            panic!("{r:?}")
        };
        assert_eq!(attrs.len(), 3);
        assert_eq!(attrs[0].1.as_deref(), Some(old.as_slice()));
        // NP shard whose shard_versions entry equals the version: bytes unchanged
        assert_eq!(np_object_info(&old, 0).unwrap(), old);
    }
}
