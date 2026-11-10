// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! `PgEnv::pool_full` (NT-cs-full-01): the global osdmap `map_flags::FULL` behaves exactly like pool `FLAG_FULL`
//! (client-ops 5.4 #11 / 5.7 step 5): a growing write is refused, a `FULL_FORCE`/MDS write proceeds, deletes and
//! in-place writes are unaffected, and clearing the flag accepts again.
use super::*;
use opexec::Env;

fn pool_full_of(map: &osdmap::OsdMap) -> (bool, bool) {
    let spg = SpgT {
        pgid: denc::types::PgT::new(1, 0),
        shard: denc::types::ShardId::NO_SHARD,
    };
    let mut set = PgSet::new(peering::Config::new(0));
    let mut store = crate::devstore::DevMemStore::new();
    let mut times = crate::perf::PersistTimes::default();
    let mut tr = crate::trace::Tracer::default();
    let mut refuse_own = None;
    let mut bad_txns = 0;
    PgEnv {
        conn_open: &|_| true,
        facts: Default::default(),
        refuse_own: &mut refuse_own,
        bad_txns: &mut bad_txns,
        set: &mut set,
        store: &mut store,
        spg,
        now: 0,
        wall: UTime::default(),
        map: Some(map),
        whoami: 0,
        rest: Vec::new(),
        failed: None,
        notes: Vec::new(),
        persist_t: &mut times,
        tr: &mut tr,
        eio: Default::default(),
        failsafe: false,
        repairs: 0,
        late_ok: false,
        send_first: false,
        late: None,
        obj_cache: 0,
        share: None,
    }
    .pool_full()
}

#[test]
fn cluster_full_flag_is_treated_like_pool_full() {
    use osdmap::consts::map_flags;
    let mut map = osdmap::OsdMap::default();
    map.pools.insert(1, osdmap::pool::PgPool::default());

    // neither the pool nor the cluster is full
    assert_eq!(pool_full_of(&map), (false, false));

    // cluster FULL with the pool itself not full: refused like a pool full, no quota flag
    map.flags |= map_flags::FULL;
    assert_eq!(pool_full_of(&map), (true, false));

    // flag cleared -> accepted again
    map.flags &= !map_flags::FULL;
    assert_eq!(pool_full_of(&map), (false, false));

    // pool FLAG_FULL alone still refuses, and FULL_QUOTA is reported for the quota error only from the pool flag
    map.pools.get_mut(&1).unwrap().flags |= osdmap::pool::flags::FULL;
    assert_eq!(pool_full_of(&map), (true, false));
    map.pools.get_mut(&1).unwrap().flags |= osdmap::pool::flags::FULL_QUOTA;
    assert_eq!(pool_full_of(&map), (true, true));
}
