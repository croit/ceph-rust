// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! PG-level ops: pgls / pgnls (+ plain filter) with a hobject-order cursor (client-ops.md s9). Run non-blocking and
//! resumable (adr 0021 S8): a refused store read (cold page, listing slice) ends the run, the next run continues at the
//! first object not yet examined.

use denc::types::{Hobject, SnapId, SpgT};
use opwire::{
    ListObjEntry, OsdOp, PgFilter, PgFilterIn, PgLsResponse, PgNlsResponse, errno, op as code,
};

/// Namespace filter value meaning "all namespaces".
pub const ALL_NSPACES: &[u8] = b"\x01";
const HITSET_NSPACE: &[u8] = b".ceph-internal";
/// Candidates whose filter attribute is asked for ahead when one of them is cold (their loads overlap: one round of
/// reads instead of one refused run per object).
const FILTER_WARM: usize = 64;
/// Most objects one store listing call of a PGLS run asks for (the store's listing slice, adr 0021 S8).
const LIST_BATCH: usize = 256;

/// `hobj_end` of PG `(pool, seed)` at `pg_num` (s6.1); `Hobject::MAX()` for the last PG.
pub fn pg_end(pool: i64, seed: u32, pg_num: u32) -> Hobject {
    let bits = pgwire::pgmath::split_bits(seed, pg_num);
    let rb = u64::from(seed.reverse_bits());
    let mask = if bits >= 32 {
        0
    } else {
        0xFFFF_FFFFu64 >> bits
    };
    let sum = (rb | mask) + 1;
    if sum >= 1 << 32 {
        return Hobject::MAX();
    }
    Hobject::new(b"", SnapId::NOSNAP, (sum as u32).reverse_bits(), pool, b"")
}

/// Progress of one PG-op message across non-blocking runs refused by a cold store page or a listing slice (adr 0021
/// S8): the ops before `op` are done (rval and outdata set in the request), op `op` has listed `out` and goes on at
/// `cur` (the first object it has not examined). A re-run continues there, nothing is examined twice, and the reply is
/// the one an uninterrupted run gives: the listing reads the PG's committed object set, and the reply cursor (handle =
/// first object not returned) is the same.
#[derive(Clone, Debug, Default)]
pub struct PgLsRun {
    op: usize,
    result: i32,
    out: Vec<Hobject>,
    cur: Option<Hobject>,
    /// Objects examined so far (a refused run that raised it made progress).
    pub examined: u64,
}

/// A store read of the run was refused (non-blocking run: cold page or listing slice).
struct Refused;

/// Execute the PG ops of one message from where `run` stands. `Some` = the message result (positive errno negated,
/// or 0/1); `None` = a store read was refused: run again after the store wake, with the same `run`.
#[expect(clippy::too_many_arguments)]
pub fn pg_ops<V: crate::engine::Env>(
    v: &V,
    spg: SpgT,
    pg_num: u32,
    nspace: &[u8],
    snapid: u64,
    max_pgls: u64,
    ops: &mut [OsdOp],
    run: &mut PgLsRun,
) -> Option<i32> {
    while run.op < ops.len() {
        let op = &mut ops[run.op];
        let r = pg_op(v, spg, pg_num, nspace, snapid, max_pgls, op, run).ok()?;
        // PG results belong to the message result; classic leaves per-op rvals zero
        // (spec nt-errors-reference.md). Unlike object ops, FAILOK does not continue.
        run.result = r;
        run.op += 1;
        run.out.clear();
        run.cur = None;
        if r < 0 {
            break;
        }
    }
    Some(run.result)
}

#[expect(clippy::too_many_arguments)]
fn pg_op<V: crate::engine::Env>(
    v: &V,
    spg: SpgT,
    pg_num: u32,
    nspace: &[u8],
    snapid: u64,
    max_pgls: u64,
    op: &mut OsdOp,
    run: &mut PgLsRun,
) -> Result<i32, Refused> {
    if snapid != opwire::NOSNAP {
        return Ok(-errno::EINVAL);
    }
    if op.op == code::SCRUBLS {
        let r = scrub_ls(v, op);
        return if v.ov_take_blocked() {
            Err(Refused)
        } else {
            Ok(r)
        };
    }
    let (cursor, filter, legacy) = match op.op {
        code::PGNLS | code::PGLS => match opwire::pgls_cursor(&op.indata) {
            Ok(c) => (c, None, op.op == code::PGLS),
            Err(_) => return Ok(-errno::EINVAL),
        },
        code::PGNLS_FILTER | code::PGLS_FILTER => match op.indata_as::<PgFilterIn>() {
            Ok(f) => match (f.filter, f.cursor) {
                (Some(p), Some(c)) => (c, Some(p), op.op == code::PGLS_FILTER),
                _ => return Ok(-errno::EINVAL),
            },
            Err(_) => return Ok(-errno::EINVAL),
        },
        // no pool of ours has hit sets (client-ops-misc 3): an empty list, and no archived set for any stamp
        code::PG_HITSET_LS => {
            op.outdata = bytes::Bytes::from_static(&[0; 4]);
            return Ok(0);
        }
        code::PG_HITSET_GET => return Ok(-errno::ENOENT),
        _ => return Ok(-errno::EINVAL),
    };
    let count = op.pgls().count.min(max_pgls) as usize;
    let start = Hobject::new(b"", SnapId(0), spg.pgid.seed, spg.pgid.pool as i64, b"");
    let end = if legacy {
        Hobject::MAX()
    } else {
        pg_end(spg.pgid.pool as i64, spg.pgid.seed, pg_num)
    };
    if !legacy
        && cursor != Hobject::MIN()
        && cursor != Hobject::MAX()
        && (cursor < start || (cursor >= end && end != Hobject::MAX()))
    {
        return Ok(-errno::EINVAL);
    }
    let mut out = std::mem::take(&mut run.out);
    let mut cur = run.cur.take().unwrap_or(cursor);
    let mut handle = end.clone();
    let mut done = true;
    'outer: loop {
        // the rest of the page, at least a batch (objects of other namespaces / filtered ones do not count), at most
        // a listing slice (a refused run continues after the last call that returned)
        let want = count.saturating_sub(out.len()).clamp(64, LIST_BATCH);
        let (mut objs, mut next) = match v.ov_list(spg, &cur, want) {
            Ok(x) => x,
            Err(_) if v.ov_take_blocked() => {
                (run.out, run.cur) = (out, Some(cur));
                return Err(Refused);
            }
            Err(e) => return Ok(-e),
        };
        // the PG's object set, not only what this store holds yet: objects missing here are listed, objects whose
        // recovery is a delete are not (s9)
        // At most one batch of missing objects per store batch (+1: the bound): a page over a PG whose store holds
        // few of its objects copies only what it examines, not the whole remaining missing set. Neither input crosses
        // the first missing object not taken (it may be the delete of a store object): the next round starts there.
        let mut missing = v.missing_range(&cur, &next, want + 1);
        if missing.len() > want
            && let Some((bound, _)) = missing.pop()
        {
            objs.truncate(objs.partition_point(|o| o < &bound));
            next = bound;
        }
        let listed = objs.len() + missing.len();
        let objs = with_missing(objs, missing);
        // the listed names move into the reply (no copy per name)
        let mut it = objs.into_iter().enumerate();
        while let Some((i, o)) = it.next() {
            if out.len() >= count {
                handle = o;
                done = false;
                break 'outer;
            }
            if o.snap != SnapId::NOSNAP || (!legacy && o.nspace == HITSET_NSPACE) {
                continue;
            }
            if (legacy || nspace != ALL_NSPACES) && o.nspace != nspace {
                continue;
            }
            if let Some(f) = &filter {
                match filter_keeps(v, spg, f, &o) {
                    Some(true) => {}
                    Some(false) => continue,
                    None => {
                        for (_, w) in it.take(FILTER_WARM) {
                            let _ = filter_keeps(v, spg, f, &w);
                        }
                        run.examined += i as u64;
                        (run.out, run.cur) = (out, Some(o));
                        return Err(Refused);
                    }
                }
            }
            out.push(o);
        }
        run.examined += listed as u64;
        if next == Hobject::MAX() || next == cur {
            break;
        }
        cur = next;
    }
    if count == 0 && done {
        // nothing requested: still report where we are
        handle = end;
    }
    op.outdata = if legacy {
        bytes::Bytes::from(crate::exec::enc(&PgLsResponse {
            handle,
            entries: out.into_iter().map(|o| (o.oid, o.key)).collect(),
        }))
    } else {
        bytes::Bytes::from(crate::exec::enc(&PgNlsResponse {
            handle,
            entries: out
                .into_iter()
                .map(|o| ListObjEntry {
                    nspace: o.nspace,
                    oid: o.oid,
                    locator: o.key,
                })
                .collect(),
        }))
    };
    Ok(i32::from(done))
}

/// Store listing `objs` merged with the missing objects of the same range (ascending, "pending delete" flag): missing
/// objects added, pending deletes removed.
fn with_missing(objs: Vec<Hobject>, miss: Vec<(Hobject, bool)>) -> Vec<Hobject> {
    if miss.is_empty() {
        return objs;
    }
    // Both inputs are ascending. Consume each once: inserting missing objects
    // into a vector shifts the remaining store page for every missing name.
    let mut out = Vec::with_capacity(objs.len() + miss.len());
    let mut objs = objs.into_iter().peekable();
    for (m, del) in miss {
        while objs.peek().is_some_and(|o| o < &m) {
            out.extend(objs.next());
        }
        if objs.peek() == Some(&m) {
            objs.next();
        }
        if !del {
            out.push(m);
        }
    }
    out.extend(objs);
    out
}

/// SCRUBLS: the scrub findings of the PG (`rados list-inconsistent-obj|snapset`).
fn scrub_ls<V: crate::engine::Env>(v: &V, op: &mut OsdOp) -> i32 {
    let Some(arg) = peering::scrubls::decode_arg(&op.indata) else {
        return -errno::EINVAL;
    };
    match v.scrub_ls(&arg) {
        Ok((interval, vals)) => {
            op.outdata = bytes::Bytes::from(peering::scrubls::encode_result(interval, &vals));
            0
        }
        Err(e) => -e,
    }
}

/// Does `f` keep head object `o`? Attribute names of filters are raw store keys (user xattr `x` = `_x`). `None` = the
/// attribute read was refused (non-blocking run, cold page); any other error rejects the object.
fn filter_keeps<V: crate::engine::Env>(
    v: &V,
    spg: SpgT,
    f: &PgFilter,
    o: &Hobject,
) -> Option<bool> {
    let mut cold = false;
    // (value of the attribute or empty, was it absent)
    let mut attr = |name: &[u8]| -> Option<(Vec<u8>, bool)> {
        if name.is_empty() {
            return Some((Vec::new(), false));
        }
        // The pinned PGBackend passes a C string after checking the original name emptiness.
        let name = name.split(|&b| b == 0).next().unwrap_or_default();
        match v.ov_getattr(spg, o, name) {
            Ok(Some(val)) => Some((val, false)),
            Ok(None) => Some((Vec::new(), true)),
            Err(_) => {
                cold = v.ov_take_blocked();
                None
            }
        }
    };
    let keep = match f {
        PgFilter::Xattr { xattr, val } => {
            matches!(attr(xattr), Some((got, false)) if got == *val)
        }
        PgFilter::CephfsInodeTag { scrub_tag } => 'tag: {
            if !o.oid.ends_with(b".00000000") {
                break 'tag false;
            }
            if scrub_tag.is_empty() {
                break 'tag true;
            }
            let Some((got, _)) = attr(b"_scrub_tag") else {
                break 'tag false;
            };
            // on-disk value = encoded string (u32 len + bytes); equal tag = already scrubbed = rejected
            let tag_ondisk = got.get(..4).and_then(|l| {
                let n = u32::from_le_bytes(l.try_into().ok()?) as usize;
                got.get(4..4 + n)
            });
            tag_ondisk != Some(&scrub_tag[..])
        }
    };
    (!cold).then_some(keep)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(i: usize) -> Hobject {
        Hobject::new(format!("{i:08}").as_bytes(), SnapId::NOSNAP, 0, 1, b"")
    }

    #[test]
    fn missing_merge_matches_pg_object_set() {
        // Exhaust all store/missing/delete memberships, including duplicates,
        // deletes absent from the store, and either empty input.
        for mask in 0usize..4096 {
            let store: Vec<_> = (0..4).filter(|i| mask & (1 << i) != 0).map(obj).collect();
            let missing: Vec<_> = (0..4)
                .filter(|i| mask & (1 << (i + 4)) != 0)
                .map(|i| (obj(i), mask & (1 << (i + 8)) != 0))
                .collect();
            let mut expected: std::collections::BTreeSet<_> = store.iter().cloned().collect();
            for (o, del) in &missing {
                if *del {
                    expected.remove(o);
                } else {
                    expected.insert(o.clone());
                }
            }
            assert_eq!(
                with_missing(store, missing),
                expected.into_iter().collect::<Vec<_>>()
            );
        }
    }

    #[test]
    #[ignore = "targeted recovery listing microbenchmark"]
    fn missing_merge_benchmark() {
        let n = 65536;
        let store: Vec<_> = (n..n + LIST_BATCH).map(obj).collect();
        let missing: Vec<_> = (0..n).map(|i| (obj(i), false)).collect();
        // Historical insertion strategy, retained only as the benchmark oracle.
        let mut old = store.clone();
        let input = missing.clone();
        let begin = std::time::Instant::now();
        let mut shifted = 0;
        for (o, _) in input {
            let i = old.binary_search(&o).unwrap_err();
            shifted += old.len() - i;
            old.insert(i, o);
        }
        let old_time = begin.elapsed();
        let begin = std::time::Instant::now();
        let merged = with_missing(store, missing);
        let new_time = begin.elapsed();
        assert_eq!(merged, old);
        assert_eq!(shifted, n * LIST_BATCH);
        eprintln!(
            "recovery merge: insertion={old_time:?}, linear={new_time:?}, historical shifted Hobjects={shifted}, linear shifted Hobjects=0"
        );
        std::hint::black_box(merged);
    }
}
