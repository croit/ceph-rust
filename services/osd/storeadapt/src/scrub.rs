// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Replica scrub map builder over the NVMe object store (spec scrub.md 3). One call builds one slice of
//! the chunk; the PG machinery re-enters until the range is done. Store errors never abort: they become
//! object flags (`stat_error`, `read_error`), never the adapter's sticky failure state.

use crate::{StoreAdapter, gh, key_after, pg_coll};
use denc::types::{Hobject, SpgT};
use peering::ScrubPart;
use replwire::scrubmsgs::{DIGEST_SEED, OmapDigest, ScrubObject, attr_visible, data_digest_update};
use store::dev::{BlockDev, Clock};
use store::obj::ObjError;

/// Data read stride of the digest until `osd_deep_scrub_stride` is applied (classic default).
pub(crate) const DEFAULT_STRIDE: u64 = 4 << 20;
/// Omap keys per read until `osd_deep_scrub_keys` is applied (classic default).
pub(crate) const DEFAULT_KEYS: usize = 1024;

impl<D: BlockDev, C: Clock> StoreAdapter<D, C> {
    pub(crate) fn reset_scrub_state(&self, spg: SpgT) {
        if let Some(p) = self.scrub_park.borrow_mut().remove(&spg) {
            let _ = self
                .st
                .borrow_mut()
                .cancel_media_read(&pg_coll(spg), p.session);
        }
    }

    /// Slice of the scrub map for `[start, end)`: at most `max_objects` objects, and (deep) stop once about
    /// `max_bytes` of data were digested (at least one object per slice). `next` = first unprocessed object.
    pub fn scrub_slice(
        &self,
        spg: SpgT,
        start: &Hobject,
        end: &Hobject,
        deep: bool,
        max_objects: usize,
        max_bytes: u64,
    ) -> ScrubPart {
        self.scrub_slice_inner(spg, start, end, deep, max_objects, max_bytes, None)
    }

    /// EC shard slice (ec.md 7.7): `ec = (mode, chunk_size)`.
    #[expect(clippy::too_many_arguments)]
    pub fn scrub_slice_ec(
        &self,
        spg: SpgT,
        start: &Hobject,
        end: &Hobject,
        deep: bool,
        max_objects: usize,
        max_bytes: u64,
        mode: replwire::ecscrub::EcScrubMode,
        chunk: u32,
    ) -> ScrubPart {
        let ec = Some((mode, chunk));
        self.scrub_slice_inner(spg, start, end, deep, max_objects, max_bytes, ec)
    }

    #[expect(clippy::too_many_arguments)]
    fn scrub_slice_inner(
        &self,
        spg: SpgT,
        start: &Hobject,
        end: &Hobject,
        deep: bool,
        max_objects: usize,
        max_bytes: u64,
        ec: Option<(replwire::ecscrub::EcScrubMode, u32)>,
    ) -> ScrubPart {
        let c = pg_coll(spg);
        let mut part = ScrubPart::default();
        let end_g = (!end.max).then(|| gh(spg, end));
        // candidate names: up to max_objects + 1 (the extra one is the continuation point)
        let mut names: Vec<Hobject> = Vec::new();
        let mut cur = gh(spg, start);
        {
            let mut st = self.st.borrow_mut();
            match st.coll_exists(&c) {
                Ok(true) => {}
                Ok(false) => {
                    part.error = Some("scrub collection missing".into());
                    return part;
                }
                Err(e) => {
                    part.error = Some(format!("scrub collection: {e}"));
                    return part;
                }
            }
            'list: loop {
                let (objs, next) = match st.list(&c, &cur, end_g.as_ref(), 64) {
                    Ok(v) => v,
                    Err(e) => {
                        part.error = Some(format!("scrub list: {e}"));
                        return part;
                    }
                };
                for o in objs {
                    if !crate::is_user_object(&o) {
                        continue;
                    }
                    names.push(o.hobj);
                    if names.len() > max_objects {
                        break 'list;
                    }
                }
                match next {
                    Some(n) => cur = n,
                    None => break,
                }
            }
        }
        let mut spent = 0u64;
        for (i, h) in names.iter().enumerate() {
            if i >= max_objects || (i > 0 && spent >= max_bytes) {
                part.next = Some(h.clone());
                return part;
            }
            match self.scrub_object(spg, h, deep, &mut spent, max_bytes, ec) {
                Step::Obj(o) => {
                    part.objects.insert(h.clone(), o);
                }
                Step::Gone => {}
                // omap digest parked mid-object (budget spent): this object continues the next slice
                Step::Parked => {
                    part.next = Some(h.clone());
                    return part;
                }
            }
        }
        part
    }

    fn scrub_object(
        &self,
        spg: SpgT,
        h: &Hobject,
        deep: bool,
        spent: &mut u64,
        max_bytes: u64,
        ec: Option<(replwire::ecscrub::EcScrubMode, u32)>,
    ) -> Step {
        let (c, g) = (pg_coll(spg), gh(spg, h));
        let (stride, keys) = (self.scrub_stride.get(), self.scrub_keys.get());
        let mut st = self.st.borrow_mut();
        let mut o = ScrubObject::default();
        match st.stat(&c, &g) {
            Ok(Some(s)) => o.size = s.size,
            Ok(None) | Err(ObjError::NoEnt) => return Step::Gone,
            Err(_) => {
                o.stat_error = true;
                return Step::Obj(o);
            }
        }
        match st.getattrs(&c, &g) {
            Ok(a) => {
                // EC shards report every xattr (incl. the backend's `hinfo_key`)
                o.attrs = a
                    .into_iter()
                    .filter(|(k, _)| ec.is_some() || attr_visible(k))
                    .collect();
            }
            Err(ObjError::NoEnt) => return Step::Gone,
            Err(_) => {
                o.stat_error = true;
                o.size = u64::MAX;
                return Step::Obj(o);
            }
        }
        if !deep {
            return Step::Obj(o);
        }
        // One continuation per PG, including EC shard data. A changed identity/version
        // invalidates both the running digest and its pinned physical read snapshot.
        let parked = self.scrub_park.borrow_mut().remove(&spg);
        let parked = parked.and_then(|p| {
            if p.oid == *h && p.o.attrs == o.attrs && p.o.size == o.size && p.ec == ec {
                Some(p)
            } else {
                let _ = st.cancel_media_read(&c, p.session);
                None
            }
        });
        let mut p = match parked {
            Some(p) => p,
            None => {
                let session = self.take_tok();
                // the data state before the first byte is read: the reformat engines rewrite only unchanged objects
                let rf = if deep {
                    self.reformat_begin(&mut st, &c, &g)
                } else {
                    None
                };
                let dg = self.collect_begin(&c, o.size, ec.is_some(), rf.as_ref());
                OmapPark {
                    oid: h.clone(),
                    o,
                    d: OmapDigest::default(),
                    from: Vec::new(),
                    pos: 0,
                    crc: DIGEST_SEED,
                    session,
                    ec,
                    rf,
                    dg,
                }
            }
        };
        if !p.o.digest_present {
            while p.pos < p.o.size {
                // The budget is soft at one block, like the existing omap batch budget.
                let want = stride
                    .min(p.o.size - p.pos)
                    .min(max_bytes.max(store::BLK as u64));
                match st.read_media_async_crc(&c, &g, p.pos, want, p.session) {
                    Ok((b, rc)) => {
                        let prev = p.crc;
                        p.crc = match rc {
                            // joined from the verified block crcs (adr 0061 am. 4): crc32c(prev, b) without a pass
                            Some(r) => {
                                let n = b.len() as u64;
                                crc::crc32c_combine(prev, r ^ crc::crc32c_shift(!0, n), n)
                            }
                            None => data_digest_update(prev, &b),
                        };
                        debug_assert_eq!(p.crc, data_digest_update(prev, &b));
                        if let Some(d) = &mut p.dg {
                            d.update(&b);
                        }
                        if let Some(v) = p.rf {
                            self.reformat_read(&mut st, &c, &g, p.pos, &b, v);
                        }
                        p.pos += b.len() as u64;
                        *spent += b.len() as u64;
                        if (b.len() as u64) < want {
                            break;
                        }
                    }
                    Err(ObjError::WouldBlock) => {
                        self.scrub_park.borrow_mut().insert(spg, p);
                        return Step::Parked;
                    }
                    Err(ObjError::NoEnt) => return Step::Gone,
                    Err(_) => {
                        p.o.set_read_error();
                        return Step::Obj(p.o);
                    }
                }
                if *spent >= max_bytes && p.pos < p.o.size {
                    self.scrub_park.borrow_mut().insert(spg, p);
                    return Step::Parked;
                }
            }
            if let (Some(d), Some(v)) = (p.dg.take(), p.rf)
                && p.pos == p.o.size
            {
                self.collect_finish(&mut st, &c, &g, h, d, v);
            }
            if let Some((mode, chunk)) = ec {
                replwire::ecscrub::ec_deep_finish(
                    &mut p.o,
                    spg.shard.0.max(0) as usize,
                    mode,
                    chunk,
                    p.crc,
                    p.pos,
                );
                if mode != replwire::ecscrub::EcScrubMode::Optimized
                    || p.o.read_error
                    || p.o.ec_hash_mismatch
                    || p.o.ec_size_mismatch
                {
                    return Step::Obj(p.o);
                }
            } else {
                p.o.digest = p.crc;
                p.o.digest_present = true;
            }
            match st.omap_header(&c, &g) {
                Ok(hd) => p.d.header(&hd),
                Err(ObjError::NoEnt) => return Step::Gone,
                Err(_) => {
                    p.o.set_read_error();
                    return Step::Obj(p.o);
                }
            }
        }
        let mut o = p.o;
        let mut d = p.d;
        let mut from = p.from;
        // Streamed in pages of `osd_deep_scrub_keys`, never all keys in memory. Each page comes from the listing encoder in the digest
        // encoding itself (len-prefixed key and value), so it is hashed in one crc pass without per-entry copies. A huge
        // omap does not hold the core: once the slice budget is spent (after at least one page, so every call
        // progresses) the digest state parks and the next slice continues at `from`.
        let mut park = false;
        loop {
            match st.omap_list_enc(&c, &g, &from, b"", keys, usize::MAX, true, 0) {
                Ok((buf, n, more)) => {
                    let Some(last) = d.entries_enc(&buf, n) else {
                        o.set_read_error();
                        return Step::Obj(o);
                    };
                    // key and value bytes (the encoding adds two le32 lengths per entry)
                    *spent += (buf.len() - 8 * n) as u64;
                    match (more, last) {
                        (true, Some(k)) => from = key_after(k.to_vec()),
                        _ => break,
                    }
                    if *spent >= max_bytes {
                        park = true;
                        break;
                    }
                }
                Err(ObjError::WouldBlock) => {
                    park = true;
                    break;
                }
                Err(ObjError::NoEnt) => return Step::Gone,
                Err(_) => {
                    o.set_read_error();
                    return Step::Obj(o);
                }
            }
        }
        if park {
            self.scrub_park.borrow_mut().insert(
                spg,
                OmapPark {
                    oid: h.clone(),
                    o,
                    d,
                    from,
                    pos: p.pos,
                    crc: p.crc,
                    session: p.session,
                    ec,
                    rf: p.rf,
                    dg: None,
                },
            );
            return Step::Parked;
        }
        if ec.is_some() {
            // Optimized EC keeps the classic shard OMAP digest (-1), but its logical payload
            // counters come from the same complete, bounded scan as replicated objects.
            o.set_omap_stats(&d);
        } else {
            o.set_omap(&d);
        }
        Step::Obj(o)
    }
}

/// Outcome of one object in a slice.
enum Step {
    Obj(ScrubObject),
    /// The object vanished.
    Gone,
    /// Data IO/digest or omap digest parked; continue in the next slice.
    Parked,
}

/// Parked deep-scrub data and omap state (one slot per PG).
#[derive(Debug)]
pub(crate) struct OmapPark {
    oid: Hobject,
    o: ScrubObject,
    d: OmapDigest,
    from: Vec<u8>,
    pos: u64,
    crc: u32,
    session: u64,
    ec: Option<(replwire::ecscrub::EcScrubMode, u32)>,
    /// Data state of the object before its deep read started (reformat engines of its pool), `None` = no engine runs.
    rf: Option<store::obj::DataVersion>,
    /// Content digest of the data read so far (`collect_csum`, primary only).
    dg: Option<crate::dedup::Hasher>,
}
