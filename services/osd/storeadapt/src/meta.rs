// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! PG metadata persistence on the pgmeta object (spec replication.md 4.1, local format).
//!
//! | omap key | value |
//! |---|---|
//! | `_infover` | u8 10 |
//! | `_epoch` | u32 LE |
//! | `_info` | `pg_info_t` (full, incl. purged_snaps) |
//! | `_biginfo` | `PastIntervals` |
//! | `_loghead` | (head, can_rollback_to, rollback_info_trimmed_to) eversions |
//! | `_logtail` | eversion |
//! | `<epoch:010>.<version:020>` | `pg_log_entry_t` |
//! | `dup_<31 chars>[/<ordinal:016x>]` | `pg_log_dup_t` (ordinal preserves equal-version request order) |
//! | `missing/<hobject str>` | (hobject, missing item) |
//! | `may_include_deletes_in_missing` | u8 |
//! | `_remove` | present = PG deletion in progress |

use crate::{StoreAdapter, apply, key_after, pg_coll, pgmeta};
use denc::types::{CollT, Eversion, Ghobject, Hobject, SpgT};
use peering::store::{PersistedPg, StoreOp};
use pgwire::{LogDup, LogEntry, MissingItem, PastIntervals, PgInfo, PgLog, PgMissing};
use replwire::pgmeta as keys;
use store::dev::{BlockDev, Clock};
use store::obj::txn::Bytes as TxnBytes;
use store::obj::{OTxn, ObjError, TOp};

const K_LOGHEAD: &[u8] = b"_loghead";
const K_LOGTAIL: &[u8] = b"_logtail";
/// Exclusive end of the digit-leading key range (all log entry keys).
const LOG_FIRST: &[u8] = b"0";
const LOG_END: &[u8] = b":";
/// Exclusive end of the dup key space.
const DUP_END: &[u8] = b"dup`";

fn enc<T: denc::Encode + ?Sized>(v: &T) -> Result<Vec<u8>, ObjError> {
    denc::to_vec(v).map_err(|e| ObjError::Invalid(format!("encode: {e}")))
}

fn dec<'a, T: denc::Decode<'a>>(b: &'a [u8], what: &str) -> Result<T, ObjError> {
    denc::from_slice::<T>(b).map_err(|e| ObjError::Eio(format!("pgmeta {what}: {e}")))
}

pub(crate) fn log_key(v: Eversion) -> Vec<u8> {
    v.key_bytes().to_vec()
}
fn dup_key(v: Eversion) -> Vec<u8> {
    let mut k = Vec::with_capacity(keys::DUP_PREFIX.len() + 31);
    k.extend_from_slice(keys::DUP_PREFIX.as_bytes());
    k.extend_from_slice(&v.key_bytes());
    k
}

fn dup_record_key(v: Eversion, ordinal: usize) -> Vec<u8> {
    let mut k = dup_key(v);
    // Several requests (the main id and extra_reqids) can share a version. Both explicit writers replace the
    // whole dup range, so the list ordinal uniquely identifies each record and preserves equal-version order.
    // Keep the version-only prefix as the trim lower bound and accept existing unsuffixed records at load.
    if ordinal != 0 {
        k.extend_from_slice(format!("/{ordinal:016x}").as_bytes());
    }
    k
}

/// Parse a 31-char log key back to its eversion.
fn parse_log_key(k: &[u8]) -> Option<Eversion> {
    let s = std::str::from_utf8(k).ok()?;
    let (e, v) = s.split_once('.')?;
    Some(Eversion::new(e.parse().ok()?, v.parse().ok()?))
}

/// Builds the ops of one `StoreTxn` with exact sequential semantics for the log/dup bookkeeping.
#[expect(missing_debug_implementations)]
pub struct Translator<'s, D: BlockDev, C: Clock> {
    st: &'s mut store::obj::Store<D, C>,
    spg: SpgT,
    exists: bool,
    log_touched: bool,
    head: Option<(Eversion, Eversion, Eversion)>,
    tail: Option<Eversion>,
    /// Mapper keys touched by earlier ops of this txn.
    snap_ov: crate::snapmap::Overlay,
    /// Existence of objects touched by earlier ops of this txn (shard ops decide on it).
    ovl: std::collections::HashMap<CollT, std::collections::HashMap<Ghobject, bool>>,
    /// Record `ovl` (only EC shard ops read it; a replicated client write skips the per-op Ghobject clone + hash insert).
    track_ovl: bool,
    /// OR of the alloc-hint flags of the txn's object ops.
    pub hints: u32,
}

impl<'s, D: BlockDev, C: Clock> Translator<'s, D, C> {
    pub fn new(st: &'s mut store::obj::Store<D, C>, spg: SpgT, exists: bool) -> Self {
        Translator {
            st,
            spg,
            exists,
            log_touched: false,
            head: None,
            tail: None,
            snap_ov: Default::default(),
            ovl: Default::default(),
            track_ovl: true,
            hints: 0,
        }
    }

    /// Track the txn-local object overlay only if `ops` has shard ops (the only readers of it).
    pub fn for_ops(mut self, ops: &[StoreOp]) -> Self {
        self.track_ovl = ops.iter().any(|o| matches!(o, StoreOp::Shard(_)));
        self
    }

    fn set<'a>(&self, out: &mut OTxn<'a>, pairs: Vec<(Vec<u8>, Vec<u8>)>) {
        if pairs.is_empty() {
            return;
        }
        out.push(TOp::OmapSetKeys {
            cid: pg_coll(self.spg),
            oid: pgmeta(self.spg),
            pairs: pairs
                .into_iter()
                .map(|(k, v)| (TxnBytes::Owned(k), TxnBytes::Owned(v)))
                .collect(),
        });
    }

    fn rm<'a>(&self, out: &mut OTxn<'a>, keys: Vec<Vec<u8>>) {
        if keys.is_empty() {
            return;
        }
        out.push(TOp::OmapRmKeys {
            cid: pg_coll(self.spg),
            oid: pgmeta(self.spg),
            keys: keys.into_iter().map(TxnBytes::Owned).collect(),
        });
    }

    fn rm_range<'a>(&self, out: &mut OTxn<'a>, first: &[u8], last: &[u8]) {
        out.push(TOp::OmapRmKeyRange {
            cid: pg_coll(self.spg),
            oid: pgmeta(self.spg),
            first: TxnBytes::Owned(first.to_vec()),
            last: TxnBytes::Owned(last.to_vec()),
        });
    }

    fn get_meta(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, ObjError> {
        let (c, g) = (pg_coll(self.spg), pgmeta(self.spg));
        let st = &mut *self.st;
        match st.omap_get(&c, &g, &[key]) {
            Ok(mut m) => Ok(m.remove(key)),
            // the PG is created by an earlier op of the same StoreTxn
            Err(ObjError::NoEnt | ObjError::NoColl) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn head(&mut self) -> Result<(Eversion, Eversion, Eversion), ObjError> {
        if self.head.is_none() {
            self.head = Some(match self.get_meta(K_LOGHEAD)? {
                Some(b) => dec::<(Eversion, Eversion, Eversion)>(&b, "_loghead")?,
                None => Default::default(),
            });
        }
        Ok(self.head.unwrap())
    }

    fn tail(&mut self) -> Result<Eversion, ObjError> {
        if self.tail.is_none() {
            self.tail = Some(match self.get_meta(K_LOGTAIL)? {
                Some(b) => dec::<Eversion>(&b, "_logtail")?,
                None => Default::default(),
            });
        }
        Ok(self.tail.unwrap())
    }

    fn put_head<'a>(
        &mut self,
        out: &mut OTxn<'a>,
        h: (Eversion, Eversion, Eversion),
    ) -> Result<(), ObjError> {
        self.head = Some(h);
        self.set(out, vec![(K_LOGHEAD.to_vec(), enc(&h)?)]);
        Ok(())
    }

    fn put_tail<'a>(&mut self, out: &mut OTxn<'a>, t: Eversion) -> Result<(), ObjError> {
        self.tail = Some(t);
        self.set(out, vec![(K_LOGTAIL.to_vec(), enc(&t)?)]);
        Ok(())
    }

    /// Every persisted dup record goes (one key range, nothing read).
    fn rm_all_dups<'a>(&mut self, out: &mut OTxn<'a>) {
        self.rm_range(out, keys::DUP_PREFIX.as_bytes(), DUP_END);
    }

    /// Append the ops of one `StoreOp`.
    pub fn op<'a>(&mut self, op: &'a StoreOp, out: &mut OTxn<'a>) -> Result<(), ObjError> {
        let n0 = out.ops.len();
        self.op_inner(op, out)?;
        if self.track_ovl && !matches!(op, StoreOp::Shard(_)) {
            for t in &out.ops[n0..] {
                self.note(t)?;
            }
        }
        Ok(())
    }

    /// Track which objects earlier ops of this txn created / removed.
    fn note(&mut self, t: &TOp<'_>) -> Result<(), ObjError> {
        match t {
            TOp::Touch { cid, oid }
            | TOp::Write { cid, oid, .. }
            | TOp::Zero { cid, oid, .. }
            | TOp::SetAttrs { cid, oid, .. }
            | TOp::OmapSetKeys { cid, oid, .. }
            | TOp::OmapSetRun { cid, oid, .. }
            | TOp::OmapSetHeader { cid, oid, .. }
            | TOp::Clone { cid, dst: oid, .. }
            | TOp::CloneRange { cid, dst: oid, .. } => {
                self.ovl.entry(*cid).or_default().insert(oid.clone(), true);
            }
            TOp::Remove { cid, oid } => {
                self.ovl.entry(*cid).or_default().insert(oid.clone(), false);
            }
            TOp::MoveRename {
                cid,
                oid,
                dcid,
                doid,
            } if self.obj_exists_in(cid, oid)? => {
                self.ovl.entry(*cid).or_default().insert(oid.clone(), false);
                self.ovl
                    .entry(*dcid)
                    .or_default()
                    .insert(doid.clone(), true);
            }
            _ => {}
        }
        Ok(())
    }

    fn obj_exists(&mut self, g: &Ghobject) -> Result<bool, ObjError> {
        self.obj_exists_in(&pg_coll(self.spg), g)
    }

    fn obj_exists_in(&mut self, cid: &CollT, g: &Ghobject) -> Result<bool, ObjError> {
        if let Some(b) = self.ovl.get(cid).and_then(|objects| objects.get(g)) {
            return Ok(*b);
        }
        match self.st.stat(cid, g) {
            Ok(s) => Ok(s.is_some()),
            Err(ObjError::NoEnt | ObjError::NoColl) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// EC shard ops (rollback / stash cleanup): no-ops on a missing source, decided on the txn-local overlay.
    fn shard_ops<'a>(
        &mut self,
        ops: &'a [peering::store::ShardOp],
        out: &mut OTxn<'a>,
    ) -> Result<(), ObjError> {
        use peering::store::ShardOp as S;
        let cid = pg_coll(self.spg);
        let shard = self.spg.shard;
        let g = |h: &Hobject, generation: u64| Ghobject::new(h.clone(), generation, shard);
        for o in ops {
            let n0 = out.ops.len();
            match o {
                S::Remove { soid, generation } => {
                    out.push(TOp::Remove {
                        cid,
                        oid: g(soid, *generation),
                    });
                }
                S::Rename {
                    soid,
                    from_gen,
                    to_gen,
                } => {
                    let (a, b) = (g(soid, *from_gen), g(soid, *to_gen));
                    if a != b && self.obj_exists(&a)? {
                        out.push(TOp::MoveRename {
                            cid,
                            oid: a,
                            dcid: cid,
                            doid: b,
                        });
                    }
                }
                S::Truncate {
                    soid,
                    generation,
                    size,
                } => {
                    out.push(TOp::Truncate {
                        cid,
                        oid: g(soid, *generation),
                        size: *size,
                    });
                }
                S::SetAttrs {
                    soid,
                    generation,
                    attrs,
                } => {
                    let oid = g(soid, *generation);
                    if !self.obj_exists(&oid)? {
                        continue;
                    }
                    let set: Vec<_> = attrs
                        .iter()
                        .filter_map(|(k, v)| {
                            v.as_ref().map(|v| {
                                (
                                    TxnBytes::Borrowed(k.as_slice()),
                                    TxnBytes::Borrowed(v.as_slice()),
                                )
                            })
                        })
                        .collect();
                    if !set.is_empty() {
                        out.push(TOp::SetAttrs {
                            cid,
                            oid: oid.clone(),
                            attrs: set,
                        });
                    }
                    for (k, v) in attrs {
                        if v.is_none() {
                            out.push(TOp::RmAttr {
                                cid,
                                oid: oid.clone(),
                                name: TxnBytes::Borrowed(k.as_slice()),
                            });
                        }
                    }
                }
                S::CloneRange {
                    soid,
                    from_gen,
                    to_gen,
                    off,
                    len,
                } => {
                    let (a, b) = (g(soid, *from_gen), g(soid, *to_gen));
                    if self.obj_exists(&a)? {
                        out.push(TOp::CloneRange {
                            cid,
                            src: a,
                            dst: b,
                            src_off: *off,
                            len: *len,
                            dst_off: *off,
                        });
                    }
                }
                S::Omap {
                    soid,
                    generation,
                    omap,
                } => {
                    use ec::moddesc::OmapUp;
                    let oid = g(soid, *generation);
                    if !self.obj_exists(&oid)? {
                        continue;
                    }
                    // classic Trimmer order: header, clear, updates
                    if let Some(h) = &omap.header {
                        out.push(TOp::OmapSetHeader {
                            cid,
                            oid: oid.clone(),
                            header: TxnBytes::Borrowed(h.as_slice()),
                        });
                    }
                    if omap.clear {
                        out.push(TOp::OmapClear {
                            cid,
                            oid: oid.clone(),
                        });
                    }
                    for u in &omap.ups {
                        match u {
                            OmapUp::Insert(kv) => out.push(TOp::OmapSetKeys {
                                cid,
                                oid: oid.clone(),
                                pairs: kv
                                    .iter()
                                    .map(|(k, v)| {
                                        (
                                            TxnBytes::Borrowed(k.as_slice()),
                                            TxnBytes::Borrowed(v.as_slice()),
                                        )
                                    })
                                    .collect(),
                            }),
                            OmapUp::Remove(keys) => out.push(TOp::OmapRmKeys {
                                cid,
                                oid: oid.clone(),
                                keys: keys
                                    .iter()
                                    .map(|k| TxnBytes::Borrowed(k.as_slice()))
                                    .collect(),
                            }),
                            OmapUp::RemoveRange(a, z) => out.push(TOp::OmapRmKeyRange {
                                cid,
                                oid: oid.clone(),
                                first: TxnBytes::Borrowed(a.as_slice()),
                                last: TxnBytes::Borrowed(z.as_slice()),
                            }),
                        };
                    }
                }
            }
            // keep the overlay current between ops of one batch
            for t in &out.ops[n0..] {
                self.note(t)?;
            }
        }
        Ok(())
    }

    fn op_inner<'a>(&mut self, op: &'a StoreOp, out: &mut OTxn<'a>) -> Result<(), ObjError> {
        let (pc, pm) = (pg_coll(self.spg), pgmeta(self.spg));
        match op {
            StoreOp::CreatePg => {
                if self.exists {
                    return Ok(());
                }
                self.exists = true;
                out.push(TOp::MkColl {
                    cid: pc,
                    bits: 0,
                    exist_ok: true,
                });
                out.push(TOp::Touch { cid: pc, oid: pm });
                self.set(
                    out,
                    vec![
                        (keys::INFOVER_KEY.into(), vec![keys::INFOVER]),
                        (keys::INFO_KEY.into(), enc(&PgInfo::new(self.spg))?),
                        (keys::MAY_INCLUDE_DELETES_KEY.into(), vec![1]),
                    ],
                );
            }
            StoreOp::RemovePg => unreachable!("handled by try_submit"),
            StoreOp::SplitOut { .. } | StoreOp::MergeIn { .. } => {
                unreachable!("handled by try_submit")
            }
            StoreOp::PutEpoch(e) => self.set(
                out,
                vec![(keys::EPOCH_KEY.into(), e.to_le_bytes().to_vec())],
            ),
            StoreOp::PutInfo(i) => self.set(out, vec![(keys::INFO_KEY.into(), enc(&**i)?)]),
            StoreOp::PutPastIntervals(p) => {
                self.set(out, vec![(keys::BIGINFO_KEY.into(), enc(&**p)?)])
            }
            StoreOp::LogAppend(es) => {
                let Some(last) = es.last() else { return Ok(()) };
                self.log_touched = true;
                let mut pairs = Vec::with_capacity(es.len());
                for e in es {
                    pairs.push((log_key(e.version), enc(e)?));
                }
                self.set(out, pairs);
                let v = last.version;
                self.put_head(out, (v, v, v))?;
            }
            StoreOp::LogAppendFast(es) => {
                let Some(last) = es.last() else { return Ok(()) };
                self.log_touched = true;
                // the PG's encodings as they are (no copy, no second encode)
                out.push(TOp::OmapSetKeys {
                    cid: pg_coll(self.spg),
                    oid: pgmeta(self.spg),
                    pairs: es
                        .iter()
                        .map(|e| {
                            (
                                TxnBytes::Owned(log_key(e.version)),
                                TxnBytes::Borrowed(&e.bl[..]),
                            )
                        })
                        .collect(),
                });
                let v = last.version;
                // no `_loghead` write: the PG persists it with its next `info` (`LogSetHead`), `PersistedPg::normalize` derives it
                self.head = Some((v, v, v));
            }
            StoreOp::LogAppendKeep(es) => {
                let Some(last) = es.last() else { return Ok(()) };
                self.log_touched = true;
                let mut pairs = Vec::with_capacity(es.len());
                for e in es {
                    pairs.push((log_key(e.version), enc(e)?));
                }
                self.set(out, pairs);
                let (_, crt, rit) = self.head()?;
                self.put_head(out, (last.version, crt, rit))?;
            }
            StoreOp::LogCursors {
                can_rollback_to,
                rollback_info_trimmed_to,
            } => {
                let (h, _, _) = self.head()?;
                self.put_head(out, (h, *can_rollback_to, *rollback_info_trimmed_to))?;
            }
            StoreOp::LogHeadIs(h, c, r) => {
                // the PG's in-memory copy: no `_loghead` read-back for a later LogAppendKeep / LogCursors
                if self.head.is_none() {
                    if cfg!(debug_assertions) {
                        let stored = self.head()?;
                        debug_assert_eq!(stored, (*h, *c, *r), "LogHeadIs hint vs stored _loghead");
                    }
                    self.head = Some((*h, *c, *r));
                }
            }
            StoreOp::Shard(ops) => self.shard_ops(ops, out)?,
            StoreOp::LogTrim {
                to,
                dups_from,
                tail_up,
            } => {
                self.log_touched = true;
                // The entries `<= to` stay as the dup records of the window (the loader derives them): only the ones
                // below the oldest kept dup go, with the old-format dup keys below it. The trim is one tail write
                // and two key ranges whatever the batch size.
                let end = key_after(log_key(*to));
                match dups_from {
                    Some(f) => {
                        let below = log_key(*f);
                        self.rm_range(out, LOG_FIRST, below.min(end).as_slice());
                        self.rm_range(out, keys::DUP_PREFIX.as_bytes(), &dup_key(*f));
                    }
                    None => {
                        self.rm_range(out, LOG_FIRST, &end);
                        self.rm_all_dups(out);
                    }
                }
                // a PG trims forward only (`tail_up`): no read of `_logtail` per trim
                let up = match self.tail {
                    Some(t) => *to > t,
                    None => *tail_up || *to > self.tail()?,
                };
                if up {
                    self.put_tail(out, *to)?;
                }
            }
            StoreOp::LogSetHead(h) => {
                self.log_touched = true;
                self.put_head(out, (*h, *h, *h))?;
            }
            StoreOp::LogRewind { to } => {
                if self.log_touched {
                    return Err(ObjError::Invalid(
                        "LogRewind after other log ops in the same StoreTxn".into(),
                    ));
                }
                let (_, crt, rit) = self.head()?;
                // the retained entries `<= tail` are dup records, not log: a rewind never removes them
                let tail = self.tail()?;
                let tail_v = tail.version;
                let mut kill = Vec::new();
                {
                    let st = &mut *self.st;
                    // only entries above both `to` and the tail can go: start behind the higher of the two, never over
                    // the retained dup-source entries `<= tail` (thousands of key reads on the PG core)
                    let lo = if to.version >= tail_v { *to } else { tail };
                    let mut from = key_after(log_key(lo));
                    loop {
                        let (kv, more) = match st.omap_iter(&pc, &pm, &from, 512) {
                            Ok(r) => r,
                            Err(ObjError::NoEnt) => break,
                            Err(e) => return Err(e),
                        };
                        let mut done = !more;
                        for (k, _) in &kv {
                            if k.as_slice() >= LOG_END {
                                done = true;
                                break;
                            }
                            if let Some(v) = parse_log_key(k)
                                && v.version > to.version
                                && v.version > tail_v
                            {
                                kill.push(k.clone());
                            }
                        }
                        if done {
                            break;
                        }
                        from = key_after(kv.last().unwrap().0.clone());
                    }
                }
                self.rm(out, kill);
                self.put_head(out, (*to, crt.min(*to), rit.min(*to)))?;
            }
            StoreOp::LogReplace(l) => {
                self.log_touched = true;
                self.rm_range(out, LOG_FIRST, LOG_END);
                self.rm_all_dups(out);
                let mut pairs = Vec::with_capacity(l.log.len() + l.dups.len());
                for e in &l.log {
                    pairs.push((log_key(e.version), enc(e)?));
                }
                for (i, d) in l.dups.iter().enumerate() {
                    pairs.push((dup_record_key(d.version, i), enc(d)?));
                }
                self.set(out, pairs);
                self.put_head(out, (l.head, l.can_rollback_to, l.rollback_info_trimmed_to))?;
                self.put_tail(out, l.tail)?;
            }
            StoreOp::LogDups(d) => {
                // the list replaces every dup record, the ones the retained trimmed entries stand for included
                self.log_touched = true;
                let end = key_after(log_key(self.tail()?));
                self.rm_range(out, LOG_FIRST, &end);
                self.rm_all_dups(out);
                let mut pairs = Vec::with_capacity(d.len());
                for (i, x) in d.iter().enumerate() {
                    pairs.push((dup_record_key(x.version, i), enc(x)?));
                }
                self.set(out, pairs);
            }
            StoreOp::Missing(ch) => {
                // last change per object wins (sequential semantics of the delta)
                let mut last: std::collections::BTreeMap<Vec<u8>, Option<Vec<u8>>> =
                    Default::default();
                for (h, v) in ch {
                    let k = keys::missing_key(h).into_bytes();
                    let v = match v {
                        Some(it) => Some(enc(&(h.clone(), it.clone()))?),
                        None => None,
                    };
                    last.insert(k, v);
                }
                let (mut pairs, mut rms) = (Vec::new(), Vec::new());
                for (k, v) in last {
                    match v {
                        Some(v) => pairs.push((k, v)),
                        None => rms.push(k),
                    }
                }
                self.set(out, pairs);
                self.rm(out, rms);
            }
            StoreOp::MissingClear {
                may_include_deletes,
            } => {
                self.rm_range(out, b"missing/", b"missing0");
                self.set(
                    out,
                    vec![(
                        keys::MAY_INCLUDE_DELETES_KEY.into(),
                        vec![*may_include_deletes as u8],
                    )],
                );
            }
            StoreOp::ApplyTxn { middle, data } => {
                apply::translate(self.spg, middle, data, &mut out.ops, &mut self.hints)?;
                // writes borrow from the blob: the store may write them by reference (adr 0061 am. 4)
                out.payloads.0.push(crc::Payload::owner(data.clone()));
            }
            StoreOp::TxnHint(h) => {
                // block crcs (on the payload's grid) of the blob the ApplyTxn right before borrows from
                if let Some(p) = h.payload()
                    && let Some(last) = out.payloads.0.last_mut()
                    && p.owner.as_ptr() == last.owner.as_ptr()
                    && p.owner.len() == last.owner.len()
                {
                    *last = p;
                }
            }
            StoreOp::ApplyTxnSplit { skel, refs, hints } => {
                apply::translate_split(self.spg, skel, refs, &mut out.ops, &mut self.hints)?;
                for r in refs {
                    let p = hints
                        .iter()
                        .find(|h| h.of(r).is_some())
                        .and_then(crc::CrcHint::payload)
                        .unwrap_or_else(|| crc::Payload::owner(r.clone()));
                    out.payloads.0.push(p);
                }
            }
            StoreOp::RemoveObject(h) => {
                out.push(TOp::Remove {
                    cid: pc,
                    oid: crate::gh(self.spg, h),
                });
                if peering::snaps::is_clone(h) {
                    let op = peering::snaps::MapOp::Remove { clone: h.clone() };
                    crate::snapmap::apply_op(self.st, self.spg, &mut self.snap_ov, &op, out)?;
                }
            }
            StoreOp::SnapMap(ops) => {
                for op in ops {
                    crate::snapmap::apply_op(self.st, self.spg, &mut self.snap_ov, op, out)?;
                }
            }
        }
        Ok(())
    }
}

/// Load the persisted PG state.
pub fn load<D: BlockDev, C: Clock>(
    ad: &StoreAdapter<D, C>,
    spg: SpgT,
) -> Result<Option<PersistedPg>, ObjError> {
    if ad.removal_queued(spg) {
        // deletion queued (`_remove` durable): the same empty answer as `list_pgs` / `read_oi` / `object_stats`, never
        // the state of a collection that is about to disappear
        return Ok(None);
    }
    let (c, g) = (pg_coll(spg), pgmeta(spg));
    let all = {
        let mut st = ad.st.borrow_mut();
        if !st.coll_exists(&c)? {
            return Ok(None);
        }
        match st.omap_all(&c, &g) {
            Ok(m) => m,
            Err(ObjError::NoEnt) => return Ok(None),
            Err(e) => return Err(e),
        }
    };
    let Some(info) = all.get(keys::INFO_KEY.as_bytes()) else {
        return Ok(None);
    };
    // a migrated copy is complete only with its marker (`_info` sorts early, keys behind it may be missing)
    if all.contains_key(crate::migrate::MIG_KEY) && !all.contains_key(crate::migrate::MIG_DONE_KEY)
    {
        return Ok(None);
    }
    let info: PgInfo = dec(info, "_info")?;
    let epoch = match all.get(keys::EPOCH_KEY.as_bytes()) {
        Some(b) if b.len() == 4 => denc::le::rd_u32(b, 0),
        _ => 0,
    };
    let past_intervals: PastIntervals = match all.get(keys::BIGINFO_KEY.as_bytes()) {
        Some(b) => dec(b, "_biginfo")?,
        None => PastIntervals::default(),
    };
    let mut log = PgLog::default();
    if let Some(b) = all.get(K_LOGHEAD) {
        let (h, crt, rit) = dec::<(Eversion, Eversion, Eversion)>(b, "_loghead")?;
        (log.head, log.can_rollback_to, log.rollback_info_trimmed_to) = (h, crt, rit);
    }
    if let Some(b) = all.get(K_LOGTAIL) {
        log.tail = dec(b, "_logtail")?;
    }
    let mut missing = PgMissing {
        may_include_deletes: true,
        ..Default::default()
    };
    // dup records: the stored dup keys (older), then the ones the retained trimmed entries (<= tail) stand for
    let mut from_entries = Vec::new();
    for (k, v) in &all {
        if k.as_slice() >= LOG_FIRST && k.as_slice() < LOG_END {
            let e = dec::<LogEntry>(v, "log entry")?;
            if e.version <= log.tail {
                from_entries.extend(e.dups());
            } else {
                log.log.push_back(e);
            }
        } else if k.starts_with(b"dup_") {
            log.dups.push_back(dec::<LogDup>(v, "dup")?);
        } else if k.starts_with(b"missing/") {
            let (h, it) = dec::<(Hobject, MissingItem)>(v, "missing")?;
            missing.missing.insert(h, it);
        }
    }
    log.dups.extend(from_entries);
    if let Some(b) = all.get(keys::MAY_INCLUDE_DELETES_KEY.as_bytes()) {
        missing.may_include_deletes = b.first().copied().unwrap_or(1) != 0;
    }
    // `_info` / `_loghead` may lag the entries of client writes (`StoreOp::LogAppendFast`): rebuilt from the log
    let mut p = PersistedPg {
        info,
        log,
        missing,
        past_intervals,
        epoch,
    };
    p.normalize();
    Ok(Some(p))
}
