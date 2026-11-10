// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
//! Deep-scrub reformat engines (adr 0593-dedup-deep-scrub-reformat, doc/spec/dedup-reformat.md): per pool a set of engines
//! runs on the data the deep scrub reads anyway. `recompress` and `defragment` rewrite the bytes just read in place
//! (store-local, [`store::obj::Store::try_local`]) when that makes the object smaller or less fragmented; at most one
//! rewrite per read. The data state of the object is taken before its first byte is read, so a rewrite only ever puts
//! back bytes nobody changed since (the store checks it again when it stages the rewrite).

use crate::StoreAdapter;
use denc::types::{CollT, Ghobject};
use std::cell::Cell;
use store::BLK;
use store::dev::{BlockDev, Clock};
use store::obj::{DataVersion, OTxn, Store, TOp};

/// Engines enabled for a pool (pool option `deep_scrub_reformat` or `flashstore_deep_scrub_reformat`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Engines {
    pub collect_csum: bool,
    pub recompress: bool,
    pub defragment: bool,
}

impl Engines {
    /// The engine list grammar of dedup-reformat.md 2: tokens separated by `;` or `,`, leading whitespace dropped, matched
    /// by prefix (`collect_csum`, `recompress`, `defragment`; the rest of a token is ignored). Returns the engines and the
    /// unknown tokens (non-blank ones only) for the caller to log.
    pub fn parse(s: &str) -> (Engines, Vec<String>) {
        let mut e = Engines::default();
        let mut unknown = Vec::new();
        for tok in s.split([';', ',']) {
            let t = tok.trim_start();
            if t.starts_with("collect_csum") {
                e.collect_csum = true;
            } else if t.starts_with("recompress") {
                e.recompress = true;
            } else if t.starts_with("defragment") {
                e.defragment = true;
            } else if !t.is_empty() {
                unknown.push(t.to_owned());
            }
        }
        (e, unknown)
    }
    pub fn any(&self) -> bool {
        self.collect_csum || self.modifying()
    }
    /// Engines that rewrite object data.
    pub fn modifying(&self) -> bool {
        self.recompress || self.defragment
    }
}

/// Engine counters (the fork's `reformat_*` perf counters, dedup-reformat.md 10, plus `skipped`).
#[derive(Debug, Default)]
pub struct ReformatCounters {
    pub compress_attempted: Cell<u64>,
    pub compress_omitted: Cell<u64>,
    pub defragment_attempted: Cell<u64>,
    pub defragment_omitted: Cell<u64>,
    /// Rewrites submitted.
    pub issued: Cell<u64>,
    /// Reads the engines were offered (the fork's `reformat_lat` sample count).
    pub offered: Cell<u64>,
    /// Decided rewrites not applied: the shard was busy, the object changed meanwhile, or a store error.
    pub skipped: Cell<u64>,
}

fn inc(c: &Cell<u64>) {
    c.set(c.get() + 1);
}

impl<D: BlockDev, C: Clock> StoreAdapter<D, C> {
    /// Engines of `pool` (none when unset).
    pub fn reformat_engines(&self, pool: u64) -> Engines {
        self.pool_reformat
            .borrow()
            .get(&pool)
            .copied()
            .unwrap_or_default()
    }

    /// Set the engines of `pool` (empty = off); used from the next deep-scrub read on.
    pub fn set_pool_engines(&self, pool: u64, e: Engines) {
        let mut m = self.pool_reformat.borrow_mut();
        if e.any() {
            m.insert(pool, e);
        } else {
            m.remove(&pool);
        }
    }

    pub fn reformat_counters(&self) -> &ReformatCounters {
        &self.rf_stats
    }

    /// Data state of `oid` before its deep-scrub read starts, or `None` when no engine of its pool needs one. Keeps the
    /// collection's data version tracking in step with the pool's engines (any engine = on); a collection whose tracking
    /// had to be switched first yields `None` for this object (its state from before the switch proves nothing).
    pub(crate) fn reformat_begin(
        &self,
        st: &mut Store<D, C>,
        c: &CollT,
        oid: &Ghobject,
    ) -> Option<DataVersion> {
        let CollT::Pg(spg) = c else { return None };
        let e = self.reformat_engines(spg.pgid.pool);
        if !e.any() {
            if self.dv_tracked.borrow_mut().remove(spg) {
                self.set_tracking(st, c, false);
            }
            return None;
        }
        let v = st.data_version(c, oid).ok().flatten()?;
        self.dv_tracked.borrow_mut().insert(*spg);
        if !v.tracking {
            self.set_tracking(st, c, true);
            return None;
        }
        Some(v)
    }

    fn set_tracking(&self, st: &mut Store<D, C>, c: &CollT, on: bool) {
        let mut t = OTxn::new();
        t.push(TOp::SetCollDvTrack { cid: *c, on });
        let tok = self.take_tok();
        // a cold collection op (barrier like MkColl); its completion token is not ours to report
        if st.queue(&t, tok).is_err() {
            inc(&self.rf_stats.skipped);
        }
    }

    /// Modifying engines on one completed deep-scrub read of `oid`: `data` are the bytes at `off` (block aligned), `before`
    /// the object's data state taken before its first byte was read (`reformat_begin`). In engine order, the first that
    /// decides to rewrite submits it; nothing changes the scrub result.
    pub(crate) fn reformat_read(
        &self,
        st: &mut Store<D, C>,
        c: &CollT,
        oid: &Ghobject,
        off: u64,
        data: &[u8],
        before: DataVersion,
    ) {
        let CollT::Pg(spg) = c else { return };
        let e = self.reformat_engines(spg.pgid.pool);
        if !e.modifying() || data.is_empty() || !off.is_multiple_of(BLK as u64) {
            return;
        }
        inc(&self.rf_stats.offered);
        if st.data_version(c, oid).ok().flatten() != Some(before) {
            return; // changed since the read started
        }
        let Ok(Some(span)) = st.span_stats(c, oid, off, data.len() as u64) else {
            return;
        };
        if span.allocated_shared != 0 {
            return; // rewriting blocks shared with a clone would only add space
        }
        let comp = self
            .pool_comp
            .borrow()
            .get(&spg.pgid.pool)
            .and_then(|p| p.resolve_reformat(0));
        if e.recompress
            && let Some(cs) = comp
            && span.allocated > 0
        {
            inc(&self.rf_stats.compress_attempted);
            let old = (span.allocated + span.allocated_compressed) / BLK as u64;
            let need = store::compress::estimate_blocks(
                &mut *self.rf_codec.borrow_mut(),
                cs,
                off / BLK as u64,
                data,
            );
            if need < old {
                self.rewrite(st, c, oid, off, data, before, comp, 0);
                return;
            }
            inc(&self.rf_stats.compress_omitted);
        }
        if e.defragment && span.frags > 1 {
            inc(&self.rf_stats.defragment_attempted);
            if !self.rewrite(st, c, oid, off, data, before, comp, span.frags as u32) {
                inc(&self.rf_stats.defragment_omitted);
            }
        }
    }

    #[expect(clippy::too_many_arguments)]
    fn rewrite(
        &self,
        st: &mut Store<D, C>,
        c: &CollT,
        oid: &Ghobject,
        off: u64,
        data: &[u8],
        expect: DataVersion,
        comp: Option<store::compress::CompSpec>,
        max_frags: u32,
    ) -> bool {
        let mut t = OTxn::new();
        t.comp = comp;
        t.push(TOp::Reformat {
            cid: *c,
            oid: oid.clone(),
            off,
            data: store::obj::txn::Bytes::Borrowed(data),
            expect,
            max_frags,
        });
        let tok = self.take_tok();
        match st.try_local(&t, tok) {
            Ok(true) => {
                inc(&self.rf_stats.issued);
                true
            }
            Ok(false) if max_frags > 0 => false,
            _ => {
                inc(&self.rf_stats.skipped);
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Engines;

    #[test]
    fn engine_list_grammar() {
        let all = Engines {
            collect_csum: true,
            recompress: true,
            defragment: true,
        };
        assert_eq!(
            Engines::parse("collect_csum, recompress;defragment"),
            (all, vec![])
        );
        // prefix match, trailing text ignored, leading whitespace only stripped
        let (e, u) = Engines::parse("  recompressXYZ ;\tdefragment args");
        assert_eq!(
            (e.recompress, e.defragment, e.collect_csum),
            (true, true, false)
        );
        assert!(u.is_empty());
        // unknown names are reported, blank tokens and empty separators are not
        assert_eq!(
            Engines::parse("collect_cksum; foo ,,; "),
            (
                Engines::default(),
                vec!["collect_cksum".to_owned(), "foo ".to_owned()]
            )
        );
        let (e, u) = Engines::parse("bar;collect_csum, baz");
        assert_eq!(
            (e, u),
            (
                Engines {
                    collect_csum: true,
                    ..Default::default()
                },
                vec!["bar".to_owned(), "baz".to_owned()]
            )
        );
        assert!(!Engines::parse("").0.any());
        assert!(Engines::parse("defragment").0.modifying());
        assert!(!Engines::parse("collect_csum").0.modifying());
    }
}
