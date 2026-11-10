// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Erasure-coded pools are fully passive (interop safety): classic OSDs abort on a PG instance
//! without shard in an EC pool, so this OSD must never emit anything for such a pool, and must
//! never create PG state for it. Regression for the "bad state machine event" crash loop.
use denc::types::{PgT, ShardId, SpgT};
use peering::synth::SynthMap;
use peering::{Action, Body, Config, Inbound, MemStore, PgSet};
use pgwire::{
    MOSDPGLog, MOSDPGNotify2, MOSDPGQuery2, PastIntervals, PeeringMsg, PgHistory, PgInfo, PgLog,
    PgNotify, PgQuery, QueryType,
};

const ME: i32 = 3;

fn ec_map(epoch: u32) -> peering::MapHandle {
    let mut m = SynthMap::new(epoch);
    for o in 0..4 {
        m = m.with_osd(o, 1);
    }
    m = m.with_pool(7, 3, 2, 16);
    m.pools.get_mut(&7).unwrap().is_erasure = true;
    m = m.with_pool(1, 3, 2, 16);
    // we are in the acting set of every EC PG
    for seed in 0..16 {
        m.up_override.insert(PgT::new(7, seed), vec![1, ME, 2]);
        m.up_override.insert(PgT::new(1, seed), vec![1, ME, 2]);
    }
    m.into_handle()
}

fn sends(a: &[Action]) -> Vec<&Action> {
    a.iter().filter(|a| matches!(a, Action::Send(_))).collect()
}

#[test]
fn ec_pool_is_silent_and_stateless() {
    let store = MemStore::new();
    let mut set = PgSet::new(Config::new(ME));
    let mut out = set.handle_map(0, ec_map(5), &store);
    let spg = |shard| SpgT {
        pgid: PgT::new(7, 0x12),
        shard: ShardId(shard),
    };
    for sh in [-1i8, 0, 1, 2] {
        let s = spg(sh);
        let info = PgInfo::dne(s);
        let notify = PgNotify::dne(info.clone(), ShardId(sh), 5, 5);
        let msgs: Vec<PeeringMsg> = vec![
            MOSDPGQuery2 {
                spgid: s,
                query: PgQuery {
                    ty: QueryType::INFO,
                    since: Default::default(),
                    history: PgHistory::default(),
                    epoch_sent: 5,
                    to: ShardId(sh),
                    from: ShardId(0),
                },
            }
            .into(),
            MOSDPGNotify2 { spgid: s, notify }.into(),
            MOSDPGLog {
                epoch: 5,
                info,
                log: PgLog::default(),
                missing: Default::default(),
                query_epoch: 5,
                past_intervals: PastIntervals::default(),
                to: ShardId(sh),
                from: ShardId(0),
                lease: None,
            }
            .into(),
        ];
        for m in msgs {
            out.extend(set.handle_msg(
                1,
                Inbound {
                    ingress: Default::default(),
                    from: 1,
                    tid: 0,
                    prio: pgwire::msgs::PRIO_DEFAULT,
                    body: Box::new(Body::Peering(m)),
                },
                &store,
            ));
        }
    }
    out.extend(set.tick(10_000_000_000, &store));
    assert!(sends(&out).is_empty(), "EC pool emitted: {:?}", sends(&out));
    assert_eq!(set.pgs().filter(|(s, _)| s.pgid.pool == 7).count(), 0);
    let n = set.take_notices();
    assert_eq!(
        n.iter().filter(|x| x.contains("pool 7")).count(),
        1,
        "{n:?}"
    );
}
