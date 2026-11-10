// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! E6: create info (Notify2 / PGLog) whose past intervals miss classic's required bounds (peering.md 3.3) is logged
//! as a cluster-log error and the PG is still created, as classic does (it checks only in primary peering); a
//! consistent pair creates the PG silently.
use denc::types::{PgShard, PgT, ShardId, SpgT};
use peering::synth::SynthMap;
use peering::{Body, Config, Inbound, MemStore, PgSet};
use pgwire::{CompactInterval, MOSDPGNotify2, PastIntervals, PeeringMsg, PgInfo, PgNotify};
use std::collections::BTreeSet;

const POOL: u64 = 1;

fn notify(set: &mut PgSet, store: &MemStore, past: PastIntervals) -> SpgT {
    let spg = SpgT {
        pgid: PgT::new(POOL, 0),
        shard: ShardId::NO_SHARD,
    };
    let mut info = PgInfo::new(spg);
    info.history.epoch_created = 1;
    info.history.epoch_pool_created = 1;
    info.history.last_epoch_started = 3;
    info.history.last_epoch_clean = 3;
    info.history.same_interval_since = 6;
    info.history.same_up_since = 6;
    info.history.same_primary_since = 6;
    let mut n = PgNotify::dne(info, ShardId::NO_SHARD, 6, 6);
    n.past_intervals = past;
    let _ = set.handle_msg(
        0,
        Inbound {
            ingress: Default::default(),
            from: 1,
            tid: 0,
            prio: pgwire::msgs::PRIO_DEFAULT,
            body: Box::new(Body::Peering(PeeringMsg::from(MOSDPGNotify2 {
                spgid: spg,
                notify: n,
            }))),
        },
        store,
    );
    spg
}

/// Maps 2..=6 known here (oldest 2: the required range starts at lec 3).
fn set() -> (PgSet, MemStore) {
    let store = MemStore::new();
    let mut set = PgSet::new(Config::new(0));
    for e in 2..=6 {
        let mut m = SynthMap::new(e);
        for o in 0..3 {
            m = m.with_osd(o, 1);
        }
        m = m.with_pool(POOL, 2, 1, 1);
        m.up_override.insert(PgT::new(POOL, 0), vec![0, 1]);
        let _ = set.handle_map(0, m.into_handle(), &store);
    }
    (set, store)
}

fn past(first: u32, last: u32) -> PastIntervals {
    let acting = BTreeSet::from([PgShard {
        osd: 2,
        shard: ShardId::NO_SHARD,
    }]);
    PastIntervals {
        first,
        last,
        all_participants: acting.clone(),
        intervals: vec![CompactInterval {
            first,
            last,
            acting,
        }],
    }
}

#[test]
fn create_info_missing_required_bounds_is_logged_and_created() {
    // required [3, 6): an empty set, one that starts late, and one that ends early are each logged, never refused
    for p in [PastIntervals::default(), past(4, 5), past(3, 4)] {
        let (mut s, store) = set();
        let spg = notify(&mut s, &store, p.clone());
        assert!(s.pg(spg).is_some(), "{p:?} {:?}", s.dropped);
        assert_eq!(s.create_bounds_mismatch, 1, "{p:?}");
        let notes = s.take_notices().join("\n");
        assert!(
            notes.contains("ERROR ") && notes.contains("create info from osd.1:"),
            "{notes}"
        );
    }
}

#[test]
fn create_info_with_required_bounds_creates() {
    let (mut s, store) = set();
    let spg = notify(&mut s, &store, past(3, 5));
    assert!(s.pg(spg).is_some(), "{:?}", s.dropped);
    assert_eq!(s.create_bounds_mismatch, 0);
}
