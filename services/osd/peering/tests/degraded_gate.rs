// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Write-only gates at the PG (client-ops 5.4 #16): an object degraded on a replica refuses writes (`WriteErr::Degraded`,
//! parked by the op layer) but stays readable here, so pure reads pass the parked write (5.5 (6)). EC sibling:
//! `ec_primary::ec_primary_object_degraded_on_a_peer_shard_blocks_writes_not_reads`.
mod common;
use common::*;

const POOL: u64 = 1;

#[test]
fn object_degraded_on_a_replica_blocks_writes_not_reads() {
    let mut s = cluster(63, &[0, 1, 2], POOL, 3, 2, 1);
    let lead = s.lead_spg(POOL, 0);
    let t = s.write_obj(POOL, 0, "g", b"old").unwrap();
    s.wait_writes(&[t], lead);
    let prim = s.primary_of(lead.pgid);
    let victim = *s.acting_of(lead.pgid).iter().find(|o| **o != prim).unwrap();
    s.kill(victim);
    s.run_until(30_000 * MS, "degraded active", |s| {
        s.pg(prim, lead).is_some_and(|pg| {
            !pg.acting().contains(&victim)
                && pg.map_epoch() == s.epoch()
                && pg.state_bits() & pgwire::state::ACTIVE != 0
        })
    });
    s.new_epoch(|m| m.rb.norecover = true);
    // g changes while the replica is away
    let t = s.write_obj(POOL, 0, "g", b"cur").unwrap();
    s.wait_writes(&[t], lead);
    s.restart(victim);
    let h = hobj(POOL, "g");
    s.run_until(30_000 * MS, "replica back, g degraded on it", |s| {
        s.pg(prim, lead).is_some_and(|pg| {
            pg.acting().contains(&victim)
                && pg.map_epoch() == s.epoch()
                && pg.state_bits() & pgwire::state::ACTIVE != 0
                && pg.obj_degraded(&h)
        })
    });
    assert!(
        !s.pg(prim, lead).unwrap().read_blocked(&h),
        "g is readable here: reads are not held"
    );
    match s.write_obj(POOL, 0, "g", b"new") {
        Err(peering::WriteErr::Degraded(o)) => assert_eq!(o, h),
        r => panic!("write to a degraded object: {r:?}"),
    }
    assert_eq!(
        s.contents(prim, POOL, 0)
            .get(b"g".as_slice())
            .map(Vec::as_slice),
        Some(b"cur".as_slice()),
        "nothing of the refused write applied: reads see the current data"
    );
    s.new_epoch(|m| m.rb.norecover = false);
    s.run_until(60_000 * MS, "recovered and clean", |s| s.pool_clean(POOL));
    let t = s
        .write_obj(POOL, 0, "g", b"new")
        .expect("accepted after the recovery");
    s.wait_writes(&[t], lead);
    s.assert_replicas_equal(
        POOL,
        0,
        &std::collections::BTreeMap::from([("g".to_string(), b"new".to_vec())]),
    );
}
