// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! A PG created from a message stamped with an epoch older than the kept map cache must replay the maps since then
//! (classic: `get_map(epoch)` from the store). Falling back to a newer map would hide intervals (a primary could
//! miss one with acked writes). Open question 13d.
use denc::types::{PgT, ShardId, SpgT, UTime};
use peering::synth::SynthMap;
use peering::{Action, Body, Config, Inbound, MapHandle, MemStore, PgSet};
use pgwire::{MOSDPGNotify2, PastIntervals, PeeringMsg, PgHistory, PgInfo, PgNotify};

const ME: i32 = 3;
const LAST: u32 = 100;
const SENT: u32 = 20;

fn spg() -> SpgT {
    SpgT {
        pgid: PgT::new(1, 0),
        shard: ShardId::NO_SHARD,
    }
}

/// Epochs 1..=LAST; the PG's up set changes at 30, 45 and 60 (ME becomes primary at 60).
fn maps() -> Vec<MapHandle> {
    maps_to(LAST)
}

/// Epochs 1..=`last`, same layout (nothing changes after 60).
fn maps_to(last: u32) -> Vec<MapHandle> {
    let mut m = SynthMap::new(1);
    for o in 1..=3 {
        m = m.with_osd(o, 1);
    }
    m = m.with_pool(1, 3, 2, 1);
    (1..=last)
        .map(|e| {
            m.epoch = e;
            let up = match e {
                ..30 => vec![1, 2, 3],
                30..45 => vec![2, 1, 3],
                45..60 => vec![1, 3, 2],
                _ => vec![ME, 1, 2],
            };
            m.up_override.insert(PgT::new(1, 0), up);
            m.clone().into_handle()
        })
        .collect()
}

fn notify(epoch: u32) -> Inbound {
    notify_from(1, epoch)
}

fn notify_from(from: i32, epoch: u32) -> Inbound {
    let mut info = PgInfo::dne(spg());
    info.history = PgHistory::new_pg(SENT, UTime::new(1, 0));
    Inbound {
        ingress: Default::default(),
        from,
        tid: 0,
        prio: pgwire::msgs::PRIO_DEFAULT,
        body: Box::new(Body::Peering(PeeringMsg::from(MOSDPGNotify2 {
            spgid: spg(),
            notify: PgNotify {
                query_epoch: epoch,
                epoch_sent: epoch,
                info,
                to: ShardId::NO_SHARD,
                from: ShardId::NO_SHARD,
                past_intervals: PastIntervals::default(),
                pg_features: 0,
            },
        }))),
    }
}

fn setup() -> (PgSet, MemStore, Vec<MapHandle>) {
    let store = MemStore::new();
    let mut set = PgSet::new(Config::new(ME));
    let all = maps();
    for m in &all {
        set.handle_map(0, m.clone(), &store);
    }
    (set, store, all)
}

fn need(acts: &[Action]) -> Vec<(u32, u32)> {
    acts.iter()
        .filter_map(|a| match a {
            Action::NeedOldMaps { from, to } => Some((*from, *to)),
            _ => None,
        })
        .collect()
}

#[test]
fn old_create_waits_for_the_persisted_maps_and_replays_every_interval() {
    let (mut set, store, all) = setup();
    let acts = set.handle_msg(1, notify(SENT), &store);
    let req = need(&acts);
    assert_eq!(req.len(), 1, "one request");
    let (from, to) = req[0];
    assert_eq!(from, SENT);
    assert!((40..LAST).contains(&to), "to = oldest kept - 1, got {to}");
    assert!(set.pg(spg()).is_none(), "no PG on a newer map");
    // a second message of the same epoch rides on the outstanding request
    let acts = set.handle_msg(2, notify(SENT), &store);
    assert!(need(&acts).is_empty());
    assert!(set.pg(spg()).is_none());

    // the driver loads the persisted maps [from, to]
    let loaded: Vec<MapHandle> = all[(from - 1) as usize..to as usize].to_vec();
    set.old_maps(3, from, loaded, &store);
    let pg = set.pg(spg()).expect("created from the replayed start map");
    assert_eq!(pg.map_epoch(), LAST);
    let (lo, _) = pg.past_intervals().bounds();
    assert!(
        lo <= SENT,
        "past intervals start at the sender's epoch, got {lo}"
    );
    // the intervals starting at 30, 45 and 60 were all seen
    assert!(
        pg.info().history.same_interval_since >= 60,
        "interval start {}",
        pg.info().history.same_interval_since
    );
}

#[test]
fn old_create_with_trimmed_start_map_is_dropped_not_created_on_a_newer_map() {
    let (mut set, store, _all) = setup();
    let acts = set.handle_msg(1, notify(SENT), &store);
    assert_eq!(need(&acts).len(), 1);
    // the store has trimmed the map: empty answer
    set.old_maps(3, SENT, Vec::new(), &store);
    assert!(set.pg(spg()).is_none());
    assert!(
        set.take_notices()
            .iter()
            .any(|n| n.contains("no longer stored"))
    );
}

/// NT-deadcode-04: `osd_map_cache_size` sets how many epochs stay in memory below the newest map (was a fixed 50): with
/// 90 kept, a message stamped 20 epochs into the history creates its PG from memory; with the default it waits for
/// the persisted maps.
#[test]
fn map_cache_size_sets_the_epochs_kept_in_memory() {
    for (keep, asks) in [(None, true), (Some(90), false)] {
        let store = MemStore::new();
        let mut set = PgSet::new(Config::new(ME));
        if let Some(k) = keep {
            set.set_map_cache(k);
        }
        for m in maps() {
            set.handle_map(0, m, &store);
        }
        let acts = set.handle_msg(1, notify(SENT), &store);
        assert_eq!(!need(&acts).is_empty(), asks, "keep {keep:?}");
        assert_eq!(set.pg(spg()).is_some(), !asks, "keep {keep:?}");
    }
}

#[test]
fn recent_create_needs_no_request() {
    let (mut set, store, _all) = setup();
    let acts = set.handle_msg(1, notify(LAST - 10), &store);
    assert!(need(&acts).is_empty());
    assert!(set.pg(spg()).is_some());
}

/// Review fix: maps arriving while the request is outstanding must not trim the kept maps the answer ends at. The
/// answer covers `[from, to]` only: a trimmed `(to, new oldest)` would let the replay skip the interval change at 60
/// (seen at the next kept map instead, wrong interval start).
#[test]
fn maps_arriving_while_asked_are_not_trimmed_into_a_gap() {
    let (mut set, store, _) = setup();
    let acts = set.handle_msg(1, notify(SENT), &store);
    let (from, to) = need(&acts)[0];
    assert!(
        to < 60,
        "the change at 60 is still kept when asking (to {to})"
    );
    // 40 more epochs: without a hold the cache would drop everything below 90
    let all = maps_to(LAST + 40);
    for m in &all[LAST as usize..] {
        set.handle_map(2, m.clone(), &store);
    }
    set.old_maps(
        3,
        from,
        all[(from - 1) as usize..to as usize].to_vec(),
        &store,
    );
    let pg = set.pg(spg()).expect("created");
    assert_eq!(pg.map_epoch(), LAST + 40);
    assert_eq!(
        pg.info().history.same_interval_since,
        60,
        "interval start must be the real change, not the next kept map"
    );
}

/// Review fix: a newer message for a parked PG queues behind the parked one (classic: one ordered queue per PG). It
/// must neither create the PG from the newer epoch first (the parked older one would then be dropped) nor be answered
/// as for an absent PG.
#[test]
fn newer_message_for_a_parked_pg_waits_behind_it() {
    let (mut set, store, all) = setup();
    let acts = set.handle_msg(1, notify(SENT), &store);
    let (from, to) = need(&acts)[0];
    let acts = set.handle_msg(2, notify_from(2, LAST), &store);
    assert!(need(&acts).is_empty());
    assert!(set.pg(spg()).is_none(), "queued behind the parked create");
    set.old_maps(
        3,
        from,
        all[(from - 1) as usize..to as usize].to_vec(),
        &store,
    );
    let pg = set.pg(spg()).expect("created");
    let (lo, _) = pg.past_intervals().bounds();
    assert!(
        lo <= SENT,
        "created from the parked (older) message, past intervals from {lo}"
    );
    assert!(pg.info().history.same_interval_since >= 60);
}

/// The replay is chunked: the driver is asked `old_map_chunk` epochs at a time and answers each from its own store,
/// the PG exists only after the last chunk, every interval is seen, and a newer message for the PG queues behind.
#[test]
fn old_create_replays_in_bounded_chunks() {
    let store = MemStore::new();
    let mut cfg = Config::new(ME);
    cfg.old_map_chunk = 8;
    let mut set = PgSet::new(cfg);
    let all = maps();
    for m in &all {
        set.handle_map(0, m.clone(), &store);
    }
    let mut acts = set.handle_msg(1, notify(SENT), &store);
    acts.extend(set.handle_msg(2, notify_from(2, LAST), &store));
    let mut rounds = 0;
    let mut covered = 0;
    loop {
        let req = need(&acts);
        if req.is_empty() {
            break;
        }
        assert_eq!(req.len(), 1, "one outstanding request");
        let (from, to) = req[0];
        assert!(to - from < 8, "chunk {from}..={to} exceeds 8 epochs");
        assert!(set.pg(spg()).is_none(), "no PG before the last chunk");
        covered = to;
        // the store answers from the newest epoch <= from up to `to`
        acts = set.old_maps(
            3,
            from,
            all[(from - 1) as usize..to as usize].to_vec(),
            &store,
        );
        rounds += 1;
        assert!(rounds < 20, "no progress");
    }
    assert!(rounds >= 3, "{rounds} chunks");
    assert!(covered >= 40, "replay reached the kept maps, to {covered}");
    let pg = set.pg(spg()).expect("created after the last chunk");
    assert_eq!(pg.map_epoch(), LAST);
    let (lo, _) = pg.past_intervals().bounds();
    assert!(lo <= SENT, "past intervals start at {lo}");
    assert_eq!(pg.info().history.same_interval_since, 60);
}

/// A chunk answered empty (the store trimmed the maps meanwhile) drops the parked create with a notice.
#[test]
fn old_create_chunk_trimmed_midway_is_dropped() {
    let store = MemStore::new();
    let mut cfg = Config::new(ME);
    cfg.old_map_chunk = 8;
    let mut set = PgSet::new(cfg);
    let all = maps();
    for m in &all {
        set.handle_map(0, m.clone(), &store);
    }
    let acts = set.handle_msg(1, notify(SENT), &store);
    let (from, to) = need(&acts)[0];
    let acts = set.old_maps(
        3,
        from,
        all[(from - 1) as usize..to as usize].to_vec(),
        &store,
    );
    let (from2, _) = need(&acts)[0];
    set.old_maps(4, from2, Vec::new(), &store);
    assert!(set.pg(spg()).is_none());
    assert!(
        set.take_notices()
            .iter()
            .any(|n| n.contains("no longer stored"))
    );
}

/// Epochs 1..=LAST as [`maps`], plus a split of pool 1 (pg_num 1 -> 2) at epoch 25: child 1.1 maps like its parent.
fn maps_with_split() -> Vec<MapHandle> {
    let mut m = SynthMap::new(1);
    for o in 1..=3 {
        m = m.with_osd(o, 1);
    }
    m = m.with_pool(1, 3, 2, 1);
    (1..=LAST)
        .map(|e| {
            m.epoch = e;
            if e == 25 {
                let p = m.pools.get_mut(&1).unwrap();
                p.pg_num = 2;
                p.pg_num_pending = 2;
            }
            let up = match e {
                ..30 => vec![1, 2, 3],
                30..45 => vec![2, 1, 3],
                45..60 => vec![1, 3, 2],
                _ => vec![ME, 1, 2],
            };
            m.up_override.insert(PgT::new(1, 0), up.clone());
            m.up_override.insert(PgT::new(1, 1), up);
            m.clone().into_handle()
        })
        .collect()
}

/// A message for a split child that exists only in a chunked replay's hold (the replayed parent split on the way)
/// queues behind the replay: no second copy of the child is created beside the held one (one would overwrite the
/// other when the replay ends), no DNE answer; after the last chunk the child exists once and got the message.
#[test]
fn message_for_a_held_split_child_waits_behind_the_replay() {
    let store = MemStore::new();
    let mut cfg = Config::new(ME);
    cfg.old_map_chunk = 8;
    let mut set = PgSet::new(cfg);
    let all = maps_with_split();
    for m in &all {
        set.handle_map(0, m.clone(), &store);
    }
    let child = SpgT {
        pgid: PgT::new(1, 1),
        shard: ShardId::NO_SHARD,
    };
    let mut acts = set.handle_msg(1, notify(SENT), &store);
    let mut first = true;
    loop {
        let req = need(&acts);
        if req.is_empty() {
            break;
        }
        let (from, to) = req[0];
        acts = set.old_maps(
            3,
            from,
            all[(from - 1) as usize..to as usize].to_vec(),
            &store,
        );
        if first {
            first = false;
            assert!(to >= 25, "first chunk {from}..={to} covers the split");
            let mut n = notify_from(1, LAST);
            if let Body::Peering(PeeringMsg::MOSDPGNotify2(x)) = &mut *n.body {
                x.spgid = child;
                x.notify.info = PgInfo::dne(child);
            }
            let a = set.handle_msg(4, n, &store);
            assert!(
                set.pg(child).is_none(),
                "second copy of the held child created"
            );
            assert!(
                !a.iter().any(|x| matches!(x, Action::Send(s) if s.to == 1)),
                "answered while the child is held: {a:?}"
            );
            acts.extend(a);
        }
    }
    assert!(!first, "no chunk asked");
    assert!(set.pg(spg()).is_some(), "parent created");
    assert!(set.pg(child).is_some(), "held child joined the set");
    let trace = set.take_trace().join("\n");
    assert!(!trace.contains("live pg wins"), "{trace}");
}
