// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! The op executor's read view (`opexec::ObjView`) over the NVMe store: synchronous point queries on the PG
//! collection (client-ops.md s7 "committed view"). Reads see every queued transaction (`StoreAdapter::queue_txn`
//! applies at once, durability is reported later), so pipelined writes build on each other. Exception: a txn deferred
//! behind its PG's old-copy deletion (`StoreAdapter::deferred`) is visible only once applied; that PG is not active.

use crate::{StoreAdapter, gh, key_after, pg_coll};
use denc::errno::{EIO, ENOENT};
use denc::types::{Hobject, SpgT};
use opexec::{
    ObjView,
    view::{Kv, VerifiedRead},
};
use std::collections::BTreeMap;
use store::dev::{BlockDev, Clock};
use store::obj::ObjError;

/// First store key of an omap listing: just after `after`, at least `prefix`.
fn omap_from(after: Option<&[u8]>, prefix: &[u8]) -> Vec<u8> {
    let from = after.map_or_else(Vec::new, |a| key_after(a.to_vec()));
    if from.as_slice() < prefix {
        prefix.to_vec()
    } else {
        from
    }
}

fn errno(e: ObjError) -> i32 {
    match e {
        ObjError::NoEnt | ObjError::NoColl => ENOENT,
        _ => EIO,
    }
}

impl<D: BlockDev, C: Clock> ObjView for StoreAdapter<D, C> {
    fn ov_stat(&self, spg: SpgT, soid: &Hobject) -> Result<Option<u64>, i32> {
        match self.with_store(|st| st.stat(&pg_coll(spg), &gh(spg, soid))) {
            Ok(s) => Ok(s.map(|s| s.size)),
            Err(ObjError::NoColl) => Ok(None),
            Err(e) => Err(errno(e)),
        }
    }

    fn ov_read(&self, spg: SpgT, soid: &Hobject, off: u64, len: u64) -> Result<Vec<u8>, i32> {
        self.with_store(|st| st.read(&pg_coll(spg), &gh(spg, soid), off, len))
            .map_err(errno)
    }

    fn ov_read_crc(
        &self,
        spg: SpgT,
        soid: &Hobject,
        off: u64,
        len: u64,
    ) -> Result<(Vec<u8>, Option<u32>), i32> {
        self.with_store(|st| st.read_crc(&pg_coll(spg), &gh(spg, soid), off, len))
            .map_err(errno)
    }

    fn ov_read_shared(
        &self,
        spg: SpgT,
        soid: &Hobject,
        off: u64,
        len: u64,
    ) -> Result<Vec<(bytes::Bytes, Option<u32>)>, i32> {
        self.with_store(|st| st.read_shared(&pg_coll(spg), &gh(spg, soid), off, len))
            .map_err(errno)
    }

    fn ov_read_shared_verified(
        &self,
        spg: SpgT,
        soid: &Hobject,
        off: u64,
        len: u64,
    ) -> Result<VerifiedRead, i32> {
        self.with_store(|st| st.read_shared_verified(&pg_coll(spg), &gh(spg, soid), off, len))
            .map(|read| VerifiedRead {
                parts: read.parts,
                block_crcs: read.block_crcs,
            })
            .map_err(errno)
    }

    fn ov_getattr(&self, spg: SpgT, soid: &Hobject, name: &[u8]) -> Result<Option<Vec<u8>>, i32> {
        self.with_store(|st| st.getattr(&pg_coll(spg), &gh(spg, soid), name))
            .map_err(errno)
    }

    fn ov_getattr_pair(
        &self,
        spg: SpgT,
        soid: &Hobject,
        a: &[u8],
        b: &[u8],
    ) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>), i32> {
        self.with_store(|st| st.getattr_pair(&pg_coll(spg), &gh(spg, soid), a, b))
            .map_err(errno)
    }

    fn ov_getattrs(&self, spg: SpgT, soid: &Hobject) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, i32> {
        self.with_store(|st| st.getattrs(&pg_coll(spg), &gh(spg, soid)))
            .map_err(errno)
    }

    fn ov_omap_header(&self, spg: SpgT, soid: &Hobject) -> Result<Vec<u8>, i32> {
        self.with_store(|st| st.omap_header(&pg_coll(spg), &gh(spg, soid)))
            .map_err(errno)
    }

    fn ov_omap_range(
        &self,
        spg: SpgT,
        soid: &Hobject,
        after: Option<&[u8]>,
        prefix: &[u8],
        max: usize,
        max_bytes: usize,
    ) -> Result<(Vec<Kv>, bool), i32> {
        let from = omap_from(after, prefix);
        self.with_store(|st| {
            st.omap_range(
                &pg_coll(spg),
                &gh(spg, soid),
                &from,
                prefix,
                max,
                max_bytes,
                true,
            )
        })
        .map_err(errno)
    }

    fn ov_omap_keys_range(
        &self,
        spg: SpgT,
        soid: &Hobject,
        after: Option<&[u8]>,
        prefix: &[u8],
        max: usize,
        max_bytes: usize,
    ) -> Result<(Vec<Vec<u8>>, bool), i32> {
        let from = omap_from(after, prefix);
        self.with_store(|st| {
            st.omap_range(
                &pg_coll(spg),
                &gh(spg, soid),
                &from,
                prefix,
                max,
                max_bytes,
                false,
            )
        })
        .map(|(kv, more)| (kv.into_iter().map(|(k, _)| k).collect(), more))
        .map_err(errno)
    }

    fn ov_omap_list(
        &self,
        spg: SpgT,
        soid: &Hobject,
        after: Option<&[u8]>,
        prefix: &[u8],
        max: usize,
        max_bytes: usize,
        values: bool,
    ) -> Result<opexec::view::OmapList, i32> {
        let from = omap_from(after, prefix);
        self.with_store(|st| {
            st.omap_list_enc(
                &pg_coll(spg),
                &gh(spg, soid),
                &from,
                prefix,
                max,
                max_bytes,
                values,
                opwire::OMAP_LIST_HEAD,
            )
        })
        .map(|(buf, n, more)| (buf, n as u32, more))
        .map_err(errno)
    }

    fn ov_omap_list_reply(
        &self,
        spg: SpgT,
        soid: &Hobject,
        after: Option<&[u8]>,
        prefix: &[u8],
        max: usize,
        max_bytes: usize,
        values: bool,
    ) -> Result<bytes::Bytes, i32> {
        let from = omap_from(after, prefix);
        self.with_store(|st| {
            st.omap_list_reply(
                &pg_coll(spg),
                &gh(spg, soid),
                &from,
                prefix,
                max,
                max_bytes,
                values,
            )
        })
        .map_err(errno)
    }

    fn ov_omap_get(
        &self,
        spg: SpgT,
        soid: &Hobject,
        keys: &[&[u8]],
    ) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, i32> {
        self.with_store(|st| st.omap_get(&pg_coll(spg), &gh(spg, soid), keys))
            .map_err(errno)
    }

    fn ov_list(
        &self,
        spg: SpgT,
        begin: &Hobject,
        max: usize,
    ) -> Result<(Vec<Hobject>, Hobject), i32> {
        let c = pg_coll(spg);
        let mut out = Vec::new();
        let mut cur = gh(spg, begin);
        if !self.with_store(|st| st.coll_exists(&c)).map_err(errno)? {
            return Ok((out, Hobject::MAX()));
        }
        loop {
            // one store call for the rest (+1: the handle after the last), unless temp / pgmeta objects were skipped
            let want = (max - out.len()).saturating_add(1);
            let (objs, next) = match self.with_store(|st| st.list(&c, &cur, None, want)) {
                Ok(x) => x,
                // a refused later call (cold leaf, listing slice, adr 0021 S8) keeps what this call listed: the caller
                // continues at `cur` and its next call is refused again (a run that lists nothing is the refusal)
                Err(ObjError::WouldBlock) if !out.is_empty() => {
                    self.with_store(|st| st.take_blocked());
                    return Ok((out, cur.hobj));
                }
                Err(e) => return Err(errno(e)),
            };
            for o in objs {
                if !crate::is_user_object(&o) {
                    continue;
                }
                if out.len() >= max {
                    return Ok((out, o.hobj));
                }
                out.push(o.hobj);
            }
            match next {
                Some(n) => cur = n,
                None => return Ok((out, Hobject::MAX())),
            }
        }
    }

    fn ov_max_item_key(&self) -> usize {
        self.with_store(|st| st.max_item_key())
    }

    fn ov_name_fits(&self, spg: SpgT, soid: &Hobject) -> bool {
        self.with_store(|st| st.name_fits(&gh(spg, soid)))
    }

    fn ov_name_long(&self, spg: SpgT, soid: &Hobject) -> bool {
        self.with_store(|st| st.name_is_long(&gh(spg, soid)))
    }

    fn ov_nonblock(&self, on: bool) {
        self.with_store(|st| st.set_nonblock_reads(on))
    }
    fn ov_read_session(&self, session: Option<(u64, u64)>, keep: bool) {
        self.with_store(|st| st.read_session(session, keep))
    }
    fn ov_list_whole(&self) {
        self.with_store(|st| st.list_whole())
    }

    fn ov_take_blocked(&self) -> bool {
        self.with_store(|st| st.take_blocked())
    }
    fn ov_take_local_wait(&self) -> bool {
        self.with_store(|st| st.take_local_wait())
    }

    fn ov_loads_pending(&self) -> bool {
        self.with_store(|st| st.loads_pending())
    }

    fn ov_cause_begin(&self) {
        self.refusal().set(opexec::view::gate_why::STORE);
        self.with_store(|st| st.cause_begin())
    }

    fn ov_refusal(&self) -> u8 {
        self.refusal().get()
    }

    fn ov_cause_take(&self) -> peering::wake::Cause {
        self.with_store(|st| {
            let mut t = store::toks::Toks::<8>::new();
            st.cause_take(&mut t);
            peering::wake::Cause::from_tokens(t.as_slice(), t.overflowed())
        })
    }

    fn ov_take_progress(&self) -> bool {
        self.with_store(|st| st.take_rm_progress())
    }
}
