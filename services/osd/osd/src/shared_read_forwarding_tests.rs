// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Exercise the real replicated PgEnv -> StoreAdapter -> Store segmented seam.
use super::*;
use denc::types::{PgT, ShardId, SnapId};
use store::dev::{SimClock, SimConfig, SimDisk};
use store::layout::{MkfsParams, mkfs};
use store::obj::{OTxn, Store, StoreCfg};
use storeadapt::{StoreAdapter, gh, pg_coll};

#[test]
fn replicated_pgenv_preserves_segment_owners_after_adapter_destruction() {
    let disk = SimDisk::new(SimConfig::new(64 << 20));
    mkfs(
        &mut disk.queue(),
        &mut SimClock::default(),
        &MkfsParams {
            shards: 1,
            wal_blocks: 1024,
            align_blocks: 1,
            meta_pct: 8,
            node_size: 8192,
            ..Default::default()
        },
    )
    .unwrap();
    let d = disk.clone();
    let (st, _) =
        Store::mount(move || d.queue(), SimClock::default(), StoreCfg::default()).unwrap();
    let mut adapter = StoreAdapter::new(st);
    let spg = SpgT {
        pgid: PgT::new(1, 1),
        shard: ShardId::NO_SHARD,
    };
    let h = Hobject::new(b"forward-shared", SnapId::NOSNAP, 1, 1, b"");
    let data: Vec<u8> = (0..1 << 20).map(|i| (i % 251) as u8).collect();
    let mut tx = OTxn::new();
    tx.mkcoll(pg_coll(spg));
    tx.write(pg_coll(spg), &gh(spg, &h), 0, &data);
    adapter.with_store(|s| s.commit(&tx)).unwrap();
    adapter.ov_nonblock(true);
    let mut set = PgSet::new(peering::Config::new(0));
    let mut times = crate::perf::PersistTimes::default();
    let mut trace = crate::trace::Tracer::default();
    let mut refuse_own = None;
    let mut bad_txns = 0;
    let env = PgEnv {
        conn_open: &|_| true,
        facts: Default::default(),
        refuse_own: &mut refuse_own,
        bad_txns: &mut bad_txns,
        set: &mut set,
        store: &mut adapter,
        spg,
        now: 0,
        wall: UTime::default(),
        map: None,
        whoami: 0,
        rest: Vec::new(),
        failed: None,
        notes: Vec::new(),
        persist_t: &mut times,
        tr: &mut trace,
        eio: Default::default(),
        failsafe: false,
        repairs: 0,
        late_ok: false,
        send_first: false,
        late: None,
        obj_cache: 0,
        share: None,
    };
    let mut output = None;
    for _ in 0..100_000 {
        env.eio_clear();
        env.ov_read_session(Some((9, 1)), true);
        // The verified (placement) read bypasses the cache and may block on the device like any rolling read.
        let read = env
            .ov_read_shared(spg, &h, 0, data.len() as u64)
            .and_then(|p| {
                assert!(p.len() > 1);
                let again = env.ov_read_shared(spg, &h, 0, data.len() as u64)?;
                assert_eq!(p.len(), again.len());
                for ((a, ca), (b, cb)) in p.iter().zip(&again) {
                    assert_eq!(a.as_ptr(), b.as_ptr());
                    assert_eq!(ca, cb);
                }
                let verified = env.ov_read_shared_verified(spg, &h, 0, data.len() as u64)?;
                Ok((p, again, verified))
            });
        match read {
            Ok(done) => {
                output = Some(done);
                break;
            }
            Err(e) => {
                assert!(env.ov_take_blocked(), "unexpected read errno {e}");
                env.ov_read_session(None, true);
                env.store.with_store(|s| {
                    s.poll(&mut Vec::new()).unwrap();
                    s.idle();
                });
            }
        }
    }
    assert!(env.eio.borrow().is_none());
    env.ov_read_session(None, false);
    env.store
        .with_store(|s| assert_eq!(s.shards[0].rolling_usage(), (0, 0)));
    drop(env);
    drop(adapter);
    drop(disk);
    let (first, again, verified) = output.expect("bounded read completed");
    for pieces in [first, again] {
        for (b, hint) in &pieces {
            if let Some(hint) = hint {
                assert_eq!(*hint, crc::crc32c(!0, b));
            }
        }
        let body: Vec<u8> = pieces.iter().flat_map(|(b, _)| b.iter().copied()).collect();
        assert_eq!(body, data);
    }
    let body: Vec<u8> = verified
        .parts
        .iter()
        .flat_map(|(b, _)| b.iter().copied())
        .collect();
    assert_eq!(body, data);
    let expected: Vec<u32> = data.chunks(4096).map(|b| crc::crc32c(0, b)).collect();
    assert_eq!(verified.block_crcs.as_deref(), Some(expected.as_slice()));
}
