// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Optimized EC direct reads (adr 0067 am. 3) on the deterministic simulator, all croit-flashstore-osd: primary and every data shard
//! serve their own chunks of an object under the real lease / pct traffic; whatever is served equals the model (never
//! stale, never partial); refusals are EAGAIN. Expected bytes come from a brute-force model, not from the code under test.
mod common;
use common::*;
use peering::ecdirect::DirectExtent;

const POOL: u64 = 1;
const K: u64 = 4;
const C: u64 = 4096;

fn payload(i: usize, len: usize) -> Vec<u8> {
    (0..len)
        .map(|j| ((i * 131 + j * 7) % 251) as u8 | 1)
        .collect()
}

fn cluster(seed: u64) -> Sim {
    let mut s = Sim::new(seed);
    for o in 0..6 {
        s.add_osd_cfg(o, |c| {
            c.ec_enable = ec::EcEnable::All;
            c.ec_enable_optimized = ec::EcEnable::All;
            c.ec_primary = true;
            c.ec_opt_primary = true;
        });
    }
    // The sans-IO simulator uses one clock for all OSDs; model the heartbeat bounds explicitly.
    let clocks: Vec<_> = s.map().osds.iter().map(|(&o, i)| (o, i.up_from)).collect();
    for node in s.nodes.values_mut() {
        for &(o, up_from) in &clocks {
            let clock = peering::PeerClockBounds {
                up_from,
                lower: Some(0),
                upper: Some(0),
            };
            let slot = std::sync::Arc::new(peering::PeerClockSlot::default());
            slot.store(Some(clock));
            node.set.attach_peer_clock(o, slot);
        }
    }
    s.run_for(50 * MS);
    s.create_pool_ec_opt(POOL, K as u32, 2, C as u32, true, 1);
    s.run_for(2000 * MS);
    s.run_until(60_000 * MS, "ec pool clean", |s| s.pool_clean(POOL));
    s
}

/// Brute force: the bytes of `model[off..off+len]` (clipped) that data chunk `raw` holds.
fn expect(model: &[u8], off: u64, len: u64, raw: u64) -> Vec<u8> {
    let end = (off + len).min(model.len() as u64);
    (off..end)
        .filter(|x| (x / C) % K == raw)
        .map(|x| model[x as usize])
        .collect()
}

fn ext(offset: u64, length: u64) -> DirectExtent {
    DirectExtent {
        offset,
        length,
        truncate_seq: 0,
        truncate_size: 0,
        sparse: false,
    }
}

/// Direct read on every data shard of PG 0: `(shard, result)`.
fn all(s: &Sim, name: &str, off: u64, len: u64) -> Vec<(u64, Result<Vec<u8>, i32>)> {
    let acting = s.acting_of(denc::types::PgT::new(POOL, 0));
    let h = hobj(POOL, name);
    (0..K)
        .map(|sh| {
            let osd = acting[sh as usize];
            let spg = s.spg_on(osd, POOL, 0);
            let r = s
                .pg(osd, spg)
                .unwrap()
                .ec_direct_read(s.now, &h, &[ext(off, len)], false, &s.nodes[&osd].store)
                .map(|mut d| d.data.remove(0));
            (sh, r)
        })
        .collect()
}

#[test]
fn every_data_shard_and_the_primary_serve_what_the_model_says() {
    let mut s = cluster(77);
    let lead = s.lead_spg(POOL, 0);
    let st = (K * C) as usize;
    let data = payload(1, 3 * st + 1234);
    let tid = s
        .write_ops(
            POOL,
            0,
            "a",
            &[EcOp::Touch, EcOp::Write(0, data.clone())],
            Some(data.len() as u64),
        )
        .expect("accepted");
    s.wait_writes(&[tid], lead);
    s.run_for(3000 * MS); // leases renewed, pct idle
    let mut served = 0;
    for (off, len) in [
        (0, 100),
        (C + 7, 50),
        (3 * C, C),
        (100, st as u64 - 100),
        (5000, 3 * st as u64),
        (3 * st as u64, 5000),
        (data.len() as u64 - 10, 100),
        (data.len() as u64 + 5, 100),
    ] {
        for (sh, r) in all(&s, "a", off, len) {
            let want = expect(&data, off, len, sh);
            let got = r.unwrap_or_else(|e| panic!("shard {sh} {off}~{len}: refused {e}"));
            assert_eq!(got, want, "shard {sh} {off}~{len}");
            served += 1;
        }
    }
    assert_eq!(served, 8 * 4);
    // an overwrite that touches one data shard only: right after it commits a shard answers the OLD or NEW bytes
    // never garbage, and once idle every shard answers the new ones
    let mut m2 = data.clone();
    let w = payload(2, 100);
    m2[(2 * C + 10) as usize..(2 * C + 110) as usize].copy_from_slice(&w);
    let tid = s
        .write_ops(
            POOL,
            0,
            "a",
            &[EcOp::Write(2 * C + 10, w)],
            Some(m2.len() as u64),
        )
        .expect("accepted");
    // in flight: a refusal or the old bytes (nothing acked yet), never the new bytes of an uncommitted write... and
    // never a mix
    for (sh, r) in all(&s, "a", 0, 4 * C) {
        if let Ok(g) = r {
            let (old, new) = (expect(&data, 0, 4 * C, sh), expect(&m2, 0, 4 * C, sh));
            assert!(g == old || g == new, "shard {sh}: torn answer in flight");
        }
    }
    s.wait_writes(&[tid], lead);
    s.run_for(3000 * MS);
    for (sh, r) in all(&s, "a", 0, 4 * C) {
        assert_eq!(r.unwrap(), expect(&m2, 0, 4 * C, sh), "shard {sh} after");
    }
    // absent object: refused
    for (_, r) in all(&s, "nope", 0, 100) {
        assert_eq!(r.unwrap_err(), 11);
    }
}

/// SPARSE_READ as a direct read (adr 0067 am. 4.5, prim spec F.5): every data shard answers logical extents (one per
/// chunk piece, inside the request, on its own chunks) whose bytes equal the model; positions not covered are holes
/// (zeros in the model). A sparse read is not refused for a short shard file.
#[test]
fn sparse_direct_reads_answer_logical_extents_of_our_chunks() {
    let mut s = cluster(78);
    let lead = s.lead_spg(POOL, 0);
    let st = K * C;
    let mut model = payload(3, (2 * st + 3 * C + 100) as usize);
    // a zeroed range and a hole beyond the old end (truncate up)
    model[(C + 100) as usize..(2 * C) as usize].fill(0);
    let n = model.len() as u64;
    let tid = s
        .write_ops(
            POOL,
            0,
            "sp",
            &[
                EcOp::Touch,
                EcOp::Write(0, model.clone()),
                EcOp::Zero(C + 100, C - 100),
                EcOp::Trunc(n + 2 * st),
            ],
            Some(n + 2 * st),
        )
        .expect("accepted");
    s.wait_writes(&[tid], lead);
    model.resize((n + 2 * st) as usize, 0);
    s.run_for(3000 * MS);
    let acting = s.acting_of(denc::types::PgT::new(POOL, 0));
    let h = hobj(POOL, "sp");
    for (off, len) in [
        (0, 100),
        (C + 7, 50),
        (100, st - 100),
        (5000, 3 * st),
        (n - 10, 3 * st),
        (n + st, 100),
    ] {
        for raw in 0..K {
            let osd = acting[raw as usize];
            let spg = s.spg_on(osd, POOL, 0);
            let mut e = ext(off, len);
            e.sparse = true;
            let r = s
                .pg(osd, spg)
                .unwrap()
                .ec_direct_read(s.now, &h, &[e], false, &s.nodes[&osd].store)
                .unwrap_or_else(|e| panic!("shard {raw} {off}~{len}: refused {e}"));
            let (data, exts) = (&r.data[0], r.extents[0].as_ref().expect("sparse extents"));
            assert_eq!(exts.iter().map(|x| x.1).sum::<u64>(), data.len() as u64);
            let end = (off + len).min(model.len() as u64);
            let mut got = std::collections::BTreeMap::new();
            let mut i = 0usize;
            for &(lo, l) in exts {
                assert!(
                    lo >= off && lo + l <= end,
                    "shard {raw}: extent {lo}~{l} outside {off}~{len}"
                );
                assert!(
                    (lo / C) % K == raw && lo / C == (lo + l - 1) / C,
                    "shard {raw}: extent {lo}~{l} not one own chunk"
                );
                for x in lo..lo + l {
                    got.insert(x, data[i]);
                    i += 1;
                }
            }
            for x in (off..end).filter(|x| (x / C) % K == raw) {
                assert_eq!(
                    got.get(&x).copied().unwrap_or(0),
                    model[x as usize],
                    "shard {raw} {off}~{len} at {x}"
                );
            }
        }
    }
}

#[test]
fn acked_write_is_visible_to_every_shard_at_once() {
    // read-your-writes: once the client has its ack, a direct read on any shard that answers returns the new bytes
    let mut s = cluster(78);
    let lead = s.lead_spg(POOL, 0);
    let mut model = payload(3, (2 * K * C) as usize);
    let mut served = 0;
    let tid = s
        .write_ops(
            POOL,
            0,
            "a",
            &[EcOp::Touch, EcOp::Write(0, model.clone())],
            Some(model.len() as u64),
        )
        .unwrap();
    s.wait_writes(&[tid], lead);
    s.run_for(3000 * MS);
    for i in 0..6 {
        let off = i as u64 * 5000 + 5;
        let w = payload(10 + i, 700);
        model[off as usize..off as usize + 700].copy_from_slice(&w);
        let tid = s
            .write_ops(
                POOL,
                0,
                "a",
                &[EcOp::Write(off, w)],
                Some(model.len() as u64),
            )
            .unwrap();
        s.wait_writes(&[tid], lead);
        for (sh, r) in all(&s, "a", 0, model.len() as u64) {
            if let Ok(g) = r {
                served += 1;
                assert_eq!(
                    g,
                    expect(&model, 0, model.len() as u64, sh),
                    "i={i} shard {sh}"
                );
            }
        }
        s.run_for(2000 * MS);
    }
    assert!(served > 0, "no shard ever answered");
}
