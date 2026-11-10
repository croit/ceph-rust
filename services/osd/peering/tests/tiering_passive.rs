// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Cache tiering is out of scope (adr 0168): both the base pool (`tiers`, `read_tier`, `write_tier`) and the cache pool
//! (`tier_of`, `cache_mode`) are fully passive: no PG, no store write, no outbound PG message, one notice per pool.
//! A plain replicated pool next to them is unchanged.
use denc::types::{PgT, ShardId, SpgT};
use peering::synth::SynthMap;
use peering::{Action, Body, Config, Inbound, MemStore, PgSet, PgStoreOps};
use pgwire::{MOSDPGCreate2, MOSDPGQuery2, PeeringMsg, PgHistory, PgQuery, QueryType};

const ME: i32 = 3;
const PLAIN: u64 = 1;
const BASE: u64 = 7;
const CACHE: u64 = 8;

fn map(epoch: u32, tiered: bool) -> peering::MapHandle {
    let mut m = SynthMap::new(epoch);
    for o in 0..4 {
        m = m.with_osd(o, 1);
    }
    for p in [PLAIN, BASE, CACHE] {
        m = m.with_pool(p, 3, 2, 8);
        for seed in 0..8 {
            m.up_override.insert(PgT::new(p, seed), vec![ME, 1, 2]);
        }
    }
    m.pools.get_mut(&BASE).unwrap().tiered = tiered;
    m.pools.get_mut(&CACHE).unwrap().tiered = tiered;
    m.into_handle()
}

fn spg(pool: u64) -> SpgT {
    SpgT {
        pgid: PgT::new(pool, 3),
        shard: ShardId::NO_SHARD,
    }
}

fn create(set: &mut PgSet, store: &MemStore, pool: u64) -> Vec<Action> {
    let s = spg(pool);
    let mut c = MOSDPGCreate2 {
        epoch: 5,
        ..Default::default()
    };
    c.pgs.insert(s, (5, Default::default()));
    let h = PgHistory {
        epoch_created: 5,
        same_interval_since: 5,
        same_up_since: 5,
        same_primary_since: 5,
        epoch_pool_created: 5,
        ..Default::default()
    };
    c.pg_extra.insert(s, (h, Default::default()));
    set.handle_create(1_000_001, c, store)
}

fn query(set: &mut PgSet, store: &MemStore, pool: u64) -> Vec<Action> {
    let q = MOSDPGQuery2 {
        spgid: spg(pool),
        query: PgQuery {
            ty: QueryType::INFO,
            since: Default::default(),
            history: PgHistory::default(),
            epoch_sent: 5,
            to: ShardId::NO_SHARD,
            from: ShardId::NO_SHARD,
        },
    };
    set.handle_msg(
        1_000_002,
        Inbound {
            ingress: Default::default(),
            from: 1,
            tid: 0,
            prio: pgwire::msgs::PRIO_DEFAULT,
            body: Box::new(Body::Peering(PeeringMsg::from(q))),
        },
        store,
    )
}

#[test]
fn tiered_pools_are_silent_and_stateless() {
    let store = MemStore::new();
    let mut set = PgSet::new(Config::new(ME));
    let mut out = set.handle_map(0, map(5, true), &store);
    for p in [BASE, CACHE] {
        out.extend(create(&mut set, &store, p));
        out.extend(query(&mut set, &store, p));
    }
    out.extend(set.tick(10_000_000_000, &store));
    assert!(
        !out.iter()
            .any(|a| matches!(a, Action::Send(_) | Action::Persist { .. })),
        "tiered pool produced output: {out:?}"
    );
    assert!(
        set.pgs()
            .all(|(s, _)| s.pgid.pool != BASE && s.pgid.pool != CACHE)
    );
    assert!(store.list_pgs().is_empty());
    assert!(set.is_passive(BASE) && set.is_passive(CACHE) && !set.is_passive(PLAIN));
    let n = set.take_notices();
    for p in [BASE, CACHE] {
        let tag = format!("pool {p} uses cache tiering");
        assert_eq!(n.iter().filter(|x| x.contains(&tag)).count(), 1, "{n:?}");
    }
}

#[test]
fn plain_replicated_pool_is_unchanged() {
    let store = MemStore::new();
    let mut set = PgSet::new(Config::new(ME));
    set.handle_map(0, map(5, true), &store);
    create(&mut set, &store, PLAIN);
    assert!(set.pg(spg(PLAIN)).is_some(), "plain pool PG created");
    // the same pools untiered: all three are served
    let mut set = PgSet::new(Config::new(ME));
    set.handle_map(0, map(5, false), &store);
    assert!(!set.is_passive(BASE) && !set.is_passive(CACHE));
}
