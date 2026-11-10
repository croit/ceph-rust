// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Sub-reads that queue on an EC shard behind a sub-read waiting for its blocks start their own device reads while they
//! queue (adr 0636 am. 1): a sequential client read pattern (consecutive 4K reads of one object, every second one on
//! the same remote data shard) loads its blocks in parallel instead of one device latency per sub-read in a row. Order
//! and bytes stay as before: the queued sub-reads are answered in arrival order once their blocks are resident.
mod common;
use common::*;

const POOL: u64 = 1;
const CHUNK: u64 = 4096;
const READS: u64 = 8;

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|j| ((j * 7 + 3) % 251) as u8 | 1).collect()
}

fn cluster_k2m1(seed: u64) -> Sim {
    let mut s = Sim::new(seed);
    for o in [0, 1, 2] {
        s.add_osd_cfg(o, |c| {
            c.ec_enable = ec::EcEnable::All;
            c.ec_enable_optimized = ec::EcEnable::All;
            c.ec_primary = true;
            c.ec_opt_primary = true;
        });
    }
    s.run_for(50 * MS);
    s.create_pool_ec_opt(POOL, 2, 1, CHUNK as u32, true, 1);
    s.run_for(2000 * MS);
    s.run_until(60_000 * MS, "ec pool clean", |s| s.pool_clean(POOL));
    s
}

/// Start the client reads of `[off, off+len)` on the primary in one call; true = all served from the cache.
fn start_reads(s: &mut Sim, h: &denc::types::Hobject, reads: &[(u64, u64)]) -> bool {
    let lead = s.lead_spg(POOL, 0);
    let prim = s.primary_of(lead.pgid);
    let mut ready = true;
    s.call(prim, |set, now, store| {
        let (r, acts) = set
            .with_pg(now, lead, store, |pg| {
                reads
                    .iter()
                    .fold(true, |a, &(o, l)| pg.ec_wait(h, o, l, store).is_none() && a)
            })
            .expect("pg");
        ready = r;
        acts
    });
    ready
}

#[test]
fn queued_sub_reads_load_their_blocks_while_they_wait() {
    overlap(41, 0, 20 * MS);
}

/// The tree path is cold for the head and for every sub-read when it queues (the kicks could not start the data reads):
/// once a replay finds the path resident, the queued ones start their data reads too, not one by one as heads.
#[test]
fn queued_sub_reads_with_a_cold_tree_path_load_once_it_is_resident() {
    // one replay at the next timer pass of the shard PG
    overlap(42, READS as u32, 250 * MS);
}

/// 8 consecutive 4K reads of data chunk 1 of one object (the remote shard's blocks never load while asserting);
/// `tree_cold`: the first tree probes on the non-primary shards answer cold; `wait`: time before the probe check.
fn overlap(seed: u64, tree_cold: u32, wait: u64) {
    let mut s = cluster_k2m1(seed);
    let lead = s.lead_spg(POOL, 0);
    let prim = s.primary_of(lead.pgid);
    let h = hobj(POOL, "o");
    // 16 stripes of 2 x 4K
    let data = payload(16 * 2 * CHUNK as usize);
    let tid = s
        .write_ops(
            POOL,
            0,
            "o",
            &[EcOp::Write(0, data.clone())],
            Some(data.len() as u64),
        )
        .expect("accepted");
    s.wait_writes(&[tid], lead);
    s.run_for(100 * MS);
    // the blocks of every non-primary shard are cold and their device reads never complete
    let others: Vec<i32> = s
        .acting_of(lead.pgid)
        .into_iter()
        .filter(|o| *o != prim)
        .collect();
    for o in &others {
        let st = &s.nodes[o].store;
        st.data_waits.set(u32::MAX);
        st.warm_waits.set(tree_cold);
        st.data_probed.borrow_mut().clear();
    }
    s.captured.clear();
    s.capture = true;
    // the sequential pattern: data chunk 1 of 8 consecutive stripes, all on the same remote shard
    let reads: Vec<(u64, u64)> = (0..READS).map(|i| (CHUNK + 2 * CHUNK * i, CHUNK)).collect();
    assert!(
        !start_reads(&mut s, &h, &reads),
        "the reads go to the shard"
    );
    s.run_for(wait);
    let asked: Vec<i32> = s
        .captured
        .iter()
        .filter_map(|(f, t, b)| match b {
            peering::Body::Ec(ecwire::EcMsg::Read(_)) if *f == prim => Some(*t),
            _ => None,
        })
        .collect();
    assert_eq!(asked.len(), READS as usize, "one sub-read per client read");
    let shard = asked[0];
    assert!(
        asked.iter().all(|t| *t == shard),
        "all on one shard: {asked:?}"
    );
    let probed = s.nodes[&shard].store.data_probed.borrow().len();
    assert_eq!(
        probed, READS as usize,
        "every queued sub-read started its device reads (not only the head)"
    );
    // the device reads complete: every read is answered, bytes exact
    for o in &others {
        s.nodes[o].store.data_waits.set(0);
    }
    for _ in 0..1000 {
        if start_reads(&mut s, &h, &reads) {
            break;
        }
        s.run_for(2 * MS);
    }
    assert!(start_reads(&mut s, &h, &reads), "all reads served");
    let pg = s.pg(prim, lead).unwrap();
    for &(o, l) in &reads {
        let got = pg.ec_cache_read(&h, o, l, data.len() as u64).expect("read");
        assert_eq!(got, data[o as usize..(o + l) as usize], "bytes at {o}");
    }
    s.ec_ops_ran(prim);
}
