// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Review 2026-11-03 #13: a recovery delete is applied only from the acting primary and only for an object this
//! replica misses at that version.
use crate::pg::Pending;
use crate::*;
use denc::types::{Eversion, Hobject, PgT, ShardId, SnapId, SpgT};
use pgwire::{PgInfo, state};
use replwire::MOSDPGRecoveryDeleteReply;
use std::sync::Arc;

/// PG 1.0 on OSD `me`, acting `[0, 1, 2]` led by osd.0.
fn pg_on(me: i32) -> Pg {
    let spg = SpgT {
        pgid: PgT::new(1, 0),
        shard: ShardId::NO_SHARD,
    };
    let acting = vec![0, 1, 2];
    let mut map = synth::SynthMap::new(5).with_pool(1, 3, 2, 1);
    for osd in 0..4 {
        map = map.with_osd(osd, 1);
    }
    map.up_override.insert(spg.pgid, acting.clone());
    let mut pg = Pg::blank(
        Arc::new(Config::new(me)),
        spg,
        map.into_handle(),
        PgInfo::new(spg),
    );
    pg.acting = acting.clone();
    pg.up = acting;
    pg.acting_primary = 0;
    pg.up_primary = 0;
    pg
}

fn obj(name: &str) -> Hobject {
    Hobject::new(name.as_bytes(), SnapId::NOSNAP, 7, 1, b"")
}

/// Active replica osd.1 of the PG; `a` is missing here as a delete at `del`, `b` as an update at `upd`.
fn replica(del: Eversion, upd: Eversion) -> Pg {
    let mut pg = pg_on(1);
    pg.st = St::ReplicaActive;
    pg.state = state::ACTIVE;
    pg.info.last_update = upd.max(del);
    pg.missing.add(obj("a"), del, Eversion::new(4, 1), true);
    pg.missing.add(obj("b"), upd, Eversion::new(4, 2), false);
    pg
}

/// Objects this recovery delete removed from the store.
fn removed(pg: &Pg) -> Vec<Hobject> {
    pg.out
        .iter()
        .filter_map(|a| match a {
            Action::Persist { txn, .. } => Some(txn.ops.iter()),
            _ => None,
        })
        .flatten()
        .chain(pg.txn.iter())
        .filter_map(|o| match o {
            StoreOp::RemoveObject(h) => Some(h.clone()),
            _ => None,
        })
        .collect()
}

/// Objects the reply (sent once durable) acknowledges as recovered.
fn acked(pg: &Pg) -> Option<Vec<Hobject>> {
    pg.pending.values().find_map(|p| match p {
        Pending::DeleteReply {
            reply: MOSDPGRecoveryDeleteReply { objects, .. },
            ..
        } => Some(objects.iter().map(|(o, _)| o.clone()).collect()),
        _ => None,
    })
}

/// A MOSDPGRecoveryDelete from `from` of the current interval (the dispatch's epoch gate passed).
fn deliver(pg: &mut Pg, from: i32, objects: Vec<(Hobject, Eversion)>) {
    pg.on_recovery_delete(from, 1, pgwire::msgs::PRIO_DEFAULT, objects, 5);
}

/// #13: an up OSD that is not the acting primary cannot make a replica delete objects.
#[test]
fn recovery_delete_from_a_non_primary_is_refused() {
    let (del, upd) = (Eversion::new(5, 4), Eversion::new(5, 6));
    let mut pg = replica(del, upd);
    deliver(&mut pg, 2, vec![(obj("a"), del)]);
    assert!(removed(&pg).is_empty(), "nothing deleted");
    assert!(pg.missing.contains(&obj("a")), "still missing");
    assert_eq!(acked(&pg), None, "no reply");
}

/// #13: the acting primary's delete applies only to an object missing here that the delete recovers (`got` accepts:
/// a delete item, or an update item whose need is <= the delete's version); any other object keeps its local copy, the
/// reply names only what was removed.
#[test]
fn recovery_delete_applies_only_to_objects_missing_at_that_version() {
    let (del, upd) = (Eversion::new(5, 4), Eversion::new(5, 6));
    // `c`: not missing at all; `b`: missing as a newer update than the delete names
    let mut pg = replica(del, upd);
    deliver(
        &mut pg,
        0,
        vec![(obj("c"), del), (obj("b"), Eversion::new(5, 5))],
    );
    assert!(removed(&pg).is_empty(), "no local copy destroyed");
    assert!(pg.missing.contains(&obj("b")), "the update is still owed");
    assert_eq!(acked(&pg), None, "nothing recovered, nothing acknowledged");
    // the real one, next to a refused one: only `a` is removed and acknowledged
    let mut pg = replica(del, upd);
    deliver(&mut pg, 0, vec![(obj("a"), del), (obj("c"), del)]);
    assert_eq!(removed(&pg), vec![obj("a")]);
    assert!(!pg.missing.contains(&obj("a")));
    assert_eq!(acked(&pg), Some(vec![obj("a")]));
}

/// NT-flags-05: the durable reply echoes the delete's header priority (classic sets the request's priority on it).
#[test]
fn recovery_delete_reply_echoes_the_request_priority() {
    let del = Eversion::new(5, 1);
    let mut pg = replica(del, Eversion::new(5, 2));
    let store = MemStore::new();
    pg.on_recovery_delete(0, 1, 15, vec![(obj("a"), del)], 5);
    let tokens: Vec<u64> = pg
        .take_actions()
        .into_iter()
        .filter_map(|a| match a {
            Action::Persist { token, .. } => Some(token),
            _ => None,
        })
        .collect();
    let mut sent = Vec::new();
    for token in tokens {
        pg.on_commit(1, token, &store);
        sent.extend(pg.take_actions().into_iter().filter_map(|a| match a {
            Action::Send(s) => Some((s.body.msg_type(), s.tid, s.prio)),
            _ => None,
        }));
    }
    assert_eq!(sent, vec![(replwire::ty::RECOVERY_DELETE_REPLY, 1, 15)]);
}
