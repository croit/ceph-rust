// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use super::*;
use crate::dev::{CrashPolicy, SimClock, SimConfig, SimDev, SimDisk};
use crate::layout::{MkfsParams, ShardDir, mkfs};
use crate::olsm::wire::OOp;
use crate::rocks_omap::Config;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn fixture() -> (Temp, SimDisk, Superblock, ShardDir, ShardCfg) {
    let root = std::env::temp_dir().join(format!(
        "croit-flashstore-shard-rocks-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&root).unwrap();
    let disk = SimDisk::new(SimConfig::new(64 << 20));
    let (sb, dirs) = mkfs(
        &mut disk.queue(),
        &mut SimClock::default(),
        &MkfsParams {
            shards: 1,
            wal_blocks: 256,
            align_blocks: 1,
            omap_rocksdb: true,
            ..Default::default()
        },
    )
    .unwrap();
    let mut rocks = Config::new(root.clone());
    rocks.allow_non_nvme = true;
    crate::rocks_omap::create(&rocks, &sb, 8 << 20).unwrap();
    let cfg = ShardCfg {
        rocksdb: Some(rocks),
        auto_ckpt: false,
        ..Default::default()
    };
    (Temp(root), disk, sb, dirs[0].clone(), cfg)
}

fn mounted(disk: &SimDisk, sb: &Superblock, dir: &ShardDir, cfg: &ShardCfg) -> Shard<SimDev> {
    Shard::mount(
        disk.queue(),
        &mut SimClock::default(),
        sb,
        dir,
        cfg.clone(),
        false,
    )
    .unwrap()
    .0
}

fn put(id: u64, k: &[u8], v: &[u8]) -> Op {
    let mut b = Vec::new();
    b.extend_from_slice(&(k.len() as u32).to_le_bytes());
    b.extend_from_slice(k);
    b.extend_from_slice(&(v.len() as u32).to_le_bytes());
    b.extend_from_slice(v);
    Op::Omap(OOp::Put {
        id,
        n: 1,
        blob: Bytes::from(b),
    })
}

#[track_caller]
fn pump(sh: &mut Shard<SimDev>, mut done: impl FnMut(&Shard<SimDev>, &[Event<Vec<u8>>]) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut events = Vec::new();
    let mut now = sh.poll_now;
    loop {
        sh.poll(now, &mut events);
        assert!(
            !events.iter().any(|e| matches!(e, Event::Failed(_))),
            "{events:?}"
        );
        if done(sh, &events) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "RocksDB/native progress timed out: durable={} native={} ckpt={} db={} publish={:?} active={} frozen={:?} busy={} events={events:?}",
            sh.durable_lsn,
            sh.state.lsn,
            sh.ckpt_lsn,
            sh.rocks.as_ref().unwrap().client.watermark,
            sh.rocks.as_ref().unwrap().client.flushed,
            sh.state.rocks_mem.as_ref().unwrap().active.bytes(),
            sh.state
                .rocks_mem
                .as_ref()
                .unwrap()
                .frozen
                .as_ref()
                .map(|f| f.lsn_hi()),
            sh.rocks.as_ref().unwrap().client.busy(),
        );
        now += 1_000_000;
        std::thread::yield_now();
    }
}

fn get(sh: &mut Shard<SimDev>, id: u64, k: &[u8]) -> Option<Bytes> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match sh.rocks_get(None, id, k) {
            Err(StoreError::Miss) => pump(sh, |_, e| e.iter().any(|e| matches!(e, Event::Wake))),
            r => return r.unwrap(),
        }
        assert!(Instant::now() < deadline);
    }
}

#[test]
fn pending_rocks_batch_keeps_polling_without_emitting_false_progress_wakes() {
    let (_temp, disk, sb, dir, cfg) = fixture();
    let mut sh = mounted(&disk, &sb, &dir, &cfg);
    let mut txn = Txn::new(1);
    let keys: Vec<_> = (0..64)
        .map(|i| Bytes::from(format!("key-{i:03}")))
        .collect();
    for key in &keys {
        txn.ops.push(put(42, key, b"value"));
    }
    sh.submit(txn).unwrap();
    pump(&mut sh, |s, _| s.olsm_flushed());
    let mut events = Vec::new();
    let mut now = sh.poll_now;
    for _ in 0..16 {
        now += 1_000_000;
        events.clear();
        sh.poll(now, &mut events);
    }
    sh.wake = false;
    sh.rocks.as_ref().unwrap().client.test_hold_worker(true);
    for _ in 0..128 {
        assert!(matches!(
            sh.rocks_by_keys(None, 42, &keys),
            Err(StoreError::Miss)
        ));
        assert_eq!(sh.rocks.as_ref().unwrap().client.pending_reads(), 1);
        assert!(
            !sh.quiet(),
            "pending external work must keep completion polling active"
        );
        events.clear();
        now += 1_000_000;
        sh.poll(now, &mut events);
        assert!(
            !events.iter().any(|e| matches!(e, Event::Wake)),
            "pending is not progress: {events:?}"
        );
    }
    sh.rocks.as_ref().unwrap().client.test_hold_worker(false);
    pump(&mut sh, |_, events| {
        events.iter().any(|e| matches!(e, Event::Wake))
    });
    assert_eq!(
        sh.rocks_by_keys(None, 42, &keys).unwrap(),
        keys.iter()
            .map(|k| (k.clone(), Bytes::from_static(b"value")))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        sh.rocks.as_ref().unwrap().client.metrics().work[2],
        1,
        "exactly one worker read for the batch"
    );
}

#[test]
fn rocks_memory_admission_uses_separate_buffers_with_driver_detached() {
    let (_temp, disk, sb, dir, cfg) = fixture();
    let mut sh = mounted(&disk, &sb, &dir, &cfg);
    let soft = sh.ol.as_ref().unwrap().mt_soft;
    let mem = sh.state.rocks_mem.as_mut().unwrap();
    mem.active.put(
        1,
        7,
        Bytes::from_static(b"a"),
        Bytes::from_static(b"frozen"),
    );
    mem.freeze();
    mem.active
        .put(2, 7, Bytes::from_static(b"b"), Bytes::from(vec![0; soft]));
    assert!(sh.state.olsm.as_ref().unwrap().active.is_empty());
    assert!(sh.state.olsm.as_ref().unwrap().frozen.is_none());
    assert_eq!(sh.olsm_floor(), Some(1));
    let driver = sh.rocks.take(); // publication submits with the driver detached
    let mut txn = Txn::new(99);
    txn.ops.push(put(7, b"c", b"wait"));
    assert_eq!(sh.submit(txn).unwrap_err().0, StoreError::Busy);
    sh.rocks = driver;
}

#[test]
fn held_rocks_worker_failure_still_wakes_and_fails_the_owner() {
    let (_temp, disk, sb, dir, cfg) = fixture();
    let mut sh = mounted(&disk, &sb, &dir, &cfg);
    sh.rocks.as_ref().unwrap().client.test_hold_worker(true);
    assert!(matches!(
        sh.rocks_get(None, 42, b"missing"),
        Err(StoreError::Miss)
    ));
    sh.wake = false;
    sh.rocks.as_ref().unwrap().client.test_stop_worker();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        sh.rocks_step();
        if sh.failed.is_some() {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    assert!(
        sh.wake,
        "unexpected worker exit must still deliver a readiness/failure wake"
    );
}

#[test]
fn competing_rocks_credit_waits_wake_only_on_release_or_expiry() {
    let (_temp, disk, sb, dir, cfg) = fixture();
    let mut sh = mounted(&disk, &sb, &dir, &cfg);
    for expire in [false, true] {
        let owner = (1, 10 + u64::from(expire));
        let waiter = (2, owner.1);
        sh.rocks_session(Some(owner), false);
        sh.rocks_scan_admit(owner, 128).unwrap();
        sh.rocks_session(None, true); // end attempt, retain answers; next session is not nested
        sh.rocks_session(Some(waiter), true);
        sh.wake = false;
        assert!(matches!(
            sh.rocks_scan_admit(waiter, 128),
            Err(StoreError::Miss)
        ));
        assert!(!sh.wake, "blocked admission did not change readiness");
        assert!(!sh.quiet(), "credit wait must keep expiry polling active");
        if expire {
            sh.rocks.as_mut().unwrap().client.test_expire_credits();
            sh.rocks_step();
        } else {
            sh.rocks_session(Some(owner), true);
            sh.rocks_session(None, false); // cancellation/finish releases real credits
        }
        assert!(sh.wake, "actual credit release must wake the parked waiter");
        sh.rocks_scan_admit(waiter, 128).unwrap();
        sh.rocks_session(Some(waiter), true);
        sh.rocks_session(None, false);
    }
}

#[test]
fn credit_wait_keeps_polling_but_never_blocks_durable_materialization() {
    let (_temp, disk, sb, dir, cfg) = fixture();
    let mut sh = mounted(&disk, &sb, &dir, &cfg);
    sh.rocks_session(Some((1, 1)), false);
    sh.rocks_scan_admit((1, 1), 128).unwrap();
    sh.rocks_session(None, true);
    sh.rocks_session(Some((2, 1)), true);
    assert!(matches!(
        sh.rocks_scan_admit((2, 1), 128),
        Err(StoreError::Miss)
    ));
    let mut txn = Txn::new(99);
    txn.ops.push(put(42, b"new-key", b"durable-value"));
    sh.submit(txn).unwrap();
    pump(&mut sh, |_, events| {
        events.iter().any(|e| matches!(e, Event::Acked(99)))
    });
    sh.rocks_step();
    assert!(
        sh.rocks.as_ref().unwrap().client.materializing(),
        "an idle worker must materialize native-durable data despite a credit waiter"
    );
    pump(&mut sh, |s, _| s.olsm_flushed());
    assert!(
        sh.rocks_session_admitted((1, 1)),
        "publication did not expire retained credits"
    );
    assert!(
        !sh.quiet(),
        "the credit waiter still needs expiry/release polling"
    );
}

type ScanStore = crate::obj::Store<SimDev, SimClock>;

fn immutable_scan(
    st: &mut ScanStore,
    c: &denc::types::CollT,
    object: &denc::types::Ghobject,
    session: (u64, u64),
    limits: (usize, usize, bool),
) -> Bytes {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        st.read_session(Some(session), true);
        let result = st.omap_list_reply(c, object, b"", b"k/", limits.0, limits.1, limits.2);
        st.read_session(None, true);
        match result {
            Ok(reply) => return reply,
            Err(crate::obj::ObjError::WouldBlock) => pump_admission_store(st, deadline),
            Err(e) => panic!("{e:?}"),
        }
    }
}

fn immutable_scan_expected(n: usize, value: &[u8], values: bool, more: bool) -> Vec<u8> {
    let mut out = (n as u32).to_le_bytes().to_vec();
    for i in 0..n {
        out.extend_from_slice(&7u32.to_le_bytes());
        out.extend_from_slice(format!("k/{i:05}").as_bytes());
        if values {
            out.extend_from_slice(&(value.len() as u32).to_le_bytes());
            out.extend_from_slice(value);
        }
    }
    out.push(u8::from(more));
    out
}

#[test]
fn immutable_scan_reply_shares_completed_retry_has_exact_backing_and_preserves_writable_api() {
    use crate::obj::ObjError;
    let value = vec![0xa5; 256];
    let (_temp, mut st, c, object) = admission_store_fixture(512, &value);
    for (i, (max, budget, values, n, more)) in [
        (512, usize::MAX, true, 512, false),
        (511, usize::MAX, true, 511, true),
        (1, 0, true, 1, true),
        (512, 0, false, 0, true),
        (0, usize::MAX, true, 0, true),
        (512, 22, false, 2, true),
        (512, usize::MAX, false, 512, false),
    ]
    .into_iter()
    .enumerate()
    {
        let session = (90, i as u64);
        let slices = st.shards[0].stats.scan_slices;
        let reply = immutable_scan(&mut st, &c, &object, session, (max, budget, values));
        let expected = immutable_scan_expected(n, &value, values, more);
        assert_eq!(reply.as_ref(), expected);
        assert_eq!(st.shards[0].stats.scan_slices - slices, n as u64 / 256);
        let m = &st.shards[0].rocks_memos[0];
        assert_eq!(
            m.enc.capacity(),
            0,
            "no rounded mutable allocation retained"
        );
        assert_eq!(m.reply.as_ref().unwrap().as_ptr(), reply.as_ptr());
        assert!(
            m.engine_charge() >= reply.len() * 4,
            "frozen output remains charged"
        );
        let slices = st.shards[0].stats.scan_slices;
        let replay = immutable_scan(&mut st, &c, &object, session, (max, budget, values));
        assert_eq!(
            replay.as_ptr(),
            reply.as_ptr(),
            "completed retry shares the same live owner"
        );
        assert_eq!(st.shards[0].stats.scan_slices, slices);
        drop(replay);

        // Same session/selection, but the writable API is a separate memo. Its
        // mutable header/trailer must not alias or corrupt the frozen result.
        let deadline = Instant::now() + Duration::from_secs(20);
        let (mut enc, count, truncated) = loop {
            st.read_session(Some(session), true);
            let result = st.omap_list_enc(&c, &object, b"", b"k/", max, budget, values, 4);
            st.read_session(None, true);
            match result {
                Ok(out) => break out,
                Err(ObjError::WouldBlock) => pump_admission_store(&mut st, deadline),
                Err(e) => panic!("{e:?}"),
            }
        };
        assert_eq!((count, truncated), (n, more));
        assert_eq!(&enc[..4], &[0; 4]);
        assert_eq!(&enc[4..], &expected[4..expected.len() - 1]);
        enc.fill(0xff);
        assert_eq!(reply.as_ref(), expected);
        st.read_session(Some(session), true);
        st.read_session(None, false);
        assert!(st.shards[0].rocks_memos.is_empty());
        let exclusive = reply
            .try_into_mut()
            .expect("all memo/retry aliases released");
        assert_eq!(
            exclusive.capacity(),
            expected.len(),
            "no spare allocation capacity escapes after memo drop"
        );
        assert_eq!(exclusive.as_ref(), expected);
    }
}

#[test]
fn immutable_scan_reply_survives_credit_refusal_expiry_mutation_and_store_drop() {
    use crate::obj::{OTxn, ObjError};
    let value = vec![0x37; 256];
    let (_temp, mut st, c, object) = admission_store_fixture(512, &value);
    let expected = immutable_scan_expected(512, &value, true, false);
    let limits = (512, usize::MAX, true);
    let before_refusal = immutable_scan(&mut st, &c, &object, (91, 1), limits);
    let charge = st.shards[0].rocks_memos[0].engine_charge();
    st.shards[0]
        .sh
        .rocks
        .as_mut()
        .unwrap()
        .client
        .test_read_budget(charge - 1);
    st.read_session(Some((91, 1)), true);
    assert!(matches!(
        st.omap_list_reply(&c, &object, b"", b"k/", 512, usize::MAX, true),
        Err(ObjError::TooLarge)
    ));
    st.read_session(None, false);
    assert!(st.shards[0].rocks_memos.is_empty());
    st.shards[0]
        .sh
        .rocks
        .as_mut()
        .unwrap()
        .client
        .test_read_budget(8 << 20);

    let before_expiry = immutable_scan(&mut st, &c, &object, (91, 2), limits);
    st.shards[0]
        .sh
        .rocks
        .as_mut()
        .unwrap()
        .client
        .test_expire_credits();
    st.shards[0].sh.rocks_step();
    st.shards[0].pf_expire(u64::MAX);
    assert!(st.shards[0].rocks_memos.is_empty());

    let before_mutation = immutable_scan(&mut st, &c, &object, (91, 3), limits);
    st.set_nonblock_reads(false);
    let mut txn = OTxn::new();
    txn.omap_set(c, &object, b"k/00000", b"changed");
    st.commit(&txn).unwrap();
    st.set_nonblock_reads(true);
    let changed = immutable_scan(&mut st, &c, &object, (91, 3), limits);
    assert_ne!(changed.as_ptr(), before_mutation.as_ptr());
    assert_eq!(&changed[..4], &512u32.to_le_bytes());
    assert_eq!(&changed[19..26], b"changed");
    st.read_session(Some((91, 3)), true);
    st.read_session(None, false);
    drop(st);
    for reply in [before_refusal, before_expiry, before_mutation] {
        assert_eq!(
            reply.as_ref(),
            expected,
            "an exported reply owns its immutable bytes"
        );
        let exclusive = reply.try_into_mut().expect("Store and its memos are gone");
        assert_eq!(exclusive.capacity(), expected.len());
    }
    assert_eq!(&changed[19..26], b"changed");
}

#[test]
fn immutable_scan_reply_rechecks_trailer_growth_before_export() {
    use crate::obj::{OTxn, ObjError};
    // Head4 +256*(key-length4 +key7 +value-length4 +value240), plus252
    // bytes in the last value, exactly fills64KiB. The terminal256-entry
    // slice yields before finalization, without an oversized write.
    let value = vec![0x61; 240];
    let last_value = vec![0x62; 492];
    let (_temp, mut st, c, object) = admission_store_fixture(256, &value);
    st.set_nonblock_reads(false);
    let mut tx = OTxn::new();
    tx.omap_set(c, &object, b"k/00255", &last_value);
    st.commit(&tx).unwrap();
    st.set_nonblock_reads(true);
    st.shards[0]
        .sh
        .rocks
        .as_mut()
        .unwrap()
        .client
        .test_read_budget(32 << 20);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        st.read_session(Some((92, 1)), true);
        assert!(matches!(
            st.omap_list_reply(&c, &object, b"", b"k/", 256, usize::MAX, true),
            Err(ObjError::WouldBlock)
        ));
        st.read_session(None, true);
        if st.shards[0]
            .rocks_memos
            .first()
            .is_some_and(|m| m.walked.is_some())
        {
            break;
        }
        pump_admission_store(&mut st, deadline);
    }
    let m = &st.shards[0].rocks_memos[0];
    assert_eq!(m.enc.len(), 64 << 10);
    assert_eq!(m.enc.capacity(), m.enc.len());
    assert!(m.reply.is_none());
    let charge = m.engine_charge();
    st.shards[0]
        .sh
        .rocks
        .as_mut()
        .unwrap()
        .client
        .test_read_budget(charge);
    st.read_session(Some((92, 1)), true);
    assert!(
        matches!(
            st.omap_list_reply(&c, &object, b"", b"k/", 256, usize::MAX, true),
            Err(ObjError::TooLarge)
        ),
        "the final trailer increases the charge; do not publish before re-admission"
    );
    st.read_session(None, false);
    assert!(st.shards[0].rocks_memos.is_empty());
    st.shards[0]
        .sh
        .rocks
        .as_mut()
        .unwrap()
        .client
        .test_read_budget(32 << 20);
    let reply = immutable_scan(&mut st, &c, &object, (92, 2), (256, usize::MAX, true));
    let mut expected = immutable_scan_expected(255, &value, true, false);
    expected.pop();
    expected[..4].copy_from_slice(&256u32.to_le_bytes());
    expected.extend_from_slice(&7u32.to_le_bytes());
    expected.extend_from_slice(b"k/00255");
    expected.extend_from_slice(&492u32.to_le_bytes());
    expected.extend_from_slice(&last_value);
    expected.push(0);
    assert_eq!(reply.as_ref(), expected);
    st.read_session(Some((92, 2)), true);
    st.read_session(None, false);
    assert_eq!(reply.try_into_mut().unwrap().capacity(), (64 << 10) + 1);
}

fn admission_store_fixture(
    n: usize,
    value: &[u8],
) -> (Temp, ScanStore, denc::types::CollT, denc::types::Ghobject) {
    use crate::obj::{OTxn, Store, StoreCfg};
    use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SnapId, SpgT};
    let (temp, disk, _, _, cfg) = fixture();
    let mut st = Store::mount(
        move || disk.queue(),
        SimClock::default(),
        StoreCfg { shard: cfg },
    )
    .unwrap()
    .0;
    let c = CollT::Pg(SpgT {
        pgid: PgT::new(1, 0),
        shard: ShardId::NO_SHARD,
    });
    let object = Ghobject::new(
        Hobject::new(b"admission-slice", SnapId::NOSNAP, 0, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    );
    let mut txn = OTxn::new();
    txn.mkcoll(c);
    st.commit(&txn).unwrap();
    let keys: Vec<_> = (0..n).map(|i| format!("k/{i:05}").into_bytes()).collect();
    let batch_entries = ((256 << 10) / value.len().max(1)).clamp(1, 64);
    for batch in keys.chunks(batch_entries) {
        let mut txn = OTxn::new();
        for key in batch {
            txn.omap_set(c, &object, key, value);
        }
        st.commit(&txn).unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    while !st.shards[0].sh.olsm_flushed() {
        pump_admission_store(&mut st, deadline);
    }
    st.set_nonblock_reads(true);
    (temp, st, c, object)
}

fn pump_admission_store(st: &mut ScanStore, deadline: Instant) {
    st.poll(&mut Vec::new()).unwrap();
    st.idle();
    assert!(
        Instant::now() < deadline,
        "WARNING TIMEOUT scan admission test exceeded20s"
    );
    std::thread::yield_now();
}

#[test]
fn scan_admission_stage_bounds_list_whole_and_preserves_terminal_fairness_and_retry() {
    use crate::obj::ObjError;
    let (_temp, mut st, c, object) = admission_store_fixture(512, b"v");
    let start = Instant::now();
    st.shards[0]
        .sh
        .rocks
        .as_mut()
        .unwrap()
        .client
        .test_credit_clock(start);
    let deadline = start + Duration::from_secs(20);
    let mut expected = vec![0; 4];
    for i in 0..512 {
        expected.extend_from_slice(&7u32.to_le_bytes());
        expected.extend_from_slice(format!("k/{i:05}").as_bytes());
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.push(b'v');
    }
    for whole in [false, true] {
        let session = (71, u64::from(whole));
        let slices = st.shards[0].stats.scan_slices;
        let mut terminal_yield = false;
        let (mut enc, n, more) = loop {
            st.read_session(Some(session), true);
            if whole {
                st.list_whole();
            }
            let before = st.shards[0]
                .sh
                .rocks
                .as_ref()
                .unwrap()
                .client
                .test_credit_clock_reads();
            let result = st.omap_list_enc(&c, &object, b"", b"k/", 512, usize::MAX, true, 4);
            let clocks = st.shards[0]
                .sh
                .rocks
                .as_ref()
                .unwrap()
                .client
                .test_credit_clock_reads()
                - before;
            st.read_session(None, true);
            match result {
                Ok(out) => {
                    // Whole consumes two256-entry permits; sliced completion is
                    // an initial admission of an already completed memo only.
                    assert_eq!(clocks, if whole { 10 } else { 2 });
                    break out;
                }
                Err(ObjError::WouldBlock) => {
                    if let Some(m) = st.shards[0].rocks_memos.first()
                        && m.n == 512
                    {
                        assert!(!whole);
                        assert_eq!(m.walked, Some(None));
                        assert!(m.engine_page.is_none());
                        assert_eq!(clocks, 5, "one bounded permit, no page query");
                        terminal_yield = true;
                    }
                }
                Err(e) => panic!("{e:?}"),
            }
            pump_admission_store(&mut st, deadline);
        };
        assert_eq!(
            st.shards[0].stats.scan_slices - slices,
            if whole { 0 } else { 2 }
        );
        assert_eq!(terminal_yield, !whole);
        assert_eq!((n, more), (512, false));
        assert_eq!(enc, expected);
        assert!(enc.capacity() > enc.len());
        enc[4] = 255;
        enc.push(1);
        st.read_session(Some(session), true);
        let replay = st
            .omap_list_enc(&c, &object, b"", b"k/", 512, usize::MAX, true, 4)
            .unwrap();
        assert_eq!(replay, (expected.clone(), 512, false));
        st.read_session(None, false);
        assert!(st.shards[0].rocks_memos.is_empty());
        assert_eq!(
            st.shards[0]
                .sh
                .rocks
                .as_ref()
                .unwrap()
                .client
                .retained_session(),
            None
        );
    }
}

#[test]
fn scan_admission_stage_byte_quantum_and_oversized_first_entry_bound_list_whole() {
    use crate::obj::ObjError;
    for (value_len, n, expected_yields) in [(128 << 10, 3, vec![2]), (300 << 10, 2, vec![1, 2])] {
        let value = vec![0x91; value_len];
        let (_temp, mut st, c, object) = admission_store_fixture(n, &value);
        let deadline = Instant::now() + Duration::from_secs(20);
        for whole in [false, true] {
            let session = (74, u64::from(whole));
            let mut yielded_at = Vec::new();
            let mut slices = st.shards[0].stats.scan_slices;
            let page = loop {
                st.read_session(Some(session), true);
                if whole {
                    st.list_whole();
                }
                let before = st.shards[0]
                    .sh
                    .rocks
                    .as_ref()
                    .unwrap()
                    .client
                    .test_credit_clock_reads();
                let result = st.omap_iter(&c, &object, b"", n);
                let clocks = st.shards[0]
                    .sh
                    .rocks
                    .as_ref()
                    .unwrap()
                    .client
                    .test_credit_clock_reads()
                    - before;
                st.read_session(None, matches!(result, Err(ObjError::WouldBlock)));
                match result {
                    Ok((page, more)) => {
                        assert!(!more);
                        if whole {
                            // One worker batch, but two internally bounded
                            // permits: byte work, not the256-entry limit.
                            assert_eq!(clocks, 10);
                        }
                        break page;
                    }
                    Err(ObjError::WouldBlock) => {
                        if st.shards[0].stats.scan_slices > slices {
                            assert!(!whole);
                            yielded_at.push(st.shards[0].rocks_memos[0].n);
                            slices = st.shards[0].stats.scan_slices;
                        }
                        pump_admission_store(&mut st, deadline);
                    }
                    Err(e) => panic!("{e:?}"),
                }
            };
            assert_eq!(
                yielded_at,
                if whole {
                    vec![]
                } else {
                    expected_yields.clone()
                }
            );
            let expected: Vec<_> = (0..n)
                .map(|i| (format!("k/{i:05}").into_bytes(), value.clone()))
                .collect();
            assert_eq!(page, expected);
        }
    }
}

#[test]
fn scan_admission_stage_cancel_pending_late_completion_and_partial_expiry() {
    use crate::obj::ObjError;
    let (_temp, mut st, c, object) = admission_store_fixture(700, b"v");
    let deadline = Instant::now() + Duration::from_secs(20);
    st.shards[0]
        .sh
        .rocks
        .as_ref()
        .unwrap()
        .client
        .test_hold_worker(true);
    loop {
        st.read_session(Some((72, 1)), true);
        assert!(matches!(
            st.omap_iter(&c, &object, b"", 700),
            Err(ObjError::WouldBlock)
        ));
        let pending = st.shards[0]
            .sh
            .rocks
            .as_ref()
            .unwrap()
            .client
            .pending_reads()
            == 1;
        st.read_session(None, !pending); // cancel before worker can produce output
        if pending {
            break;
        }
        pump_admission_store(&mut st, deadline);
    }
    assert!(st.shards[0].rocks_memos.is_empty());
    assert_eq!(
        st.shards[0]
            .sh
            .rocks
            .as_ref()
            .unwrap()
            .client
            .retained_session(),
        None
    );
    st.shards[0].sh.wake = false;
    st.read_session(None, false);
    assert!(
        !st.shards[0].sh.wake,
        "repeated cancel is not a second release"
    );
    st.read_session(Some((72, 2)), true);
    assert!(matches!(
        st.omap_iter(&c, &object, b"", 700),
        Err(ObjError::WouldBlock)
    ));
    st.read_session(None, true);
    assert!(st.shards[0].sh.rocks_session_admitted((72, 2)));
    st.shards[0]
        .sh
        .rocks
        .as_ref()
        .unwrap()
        .client
        .test_hold_worker(false);
    while st.shards[0]
        .sh
        .rocks
        .as_ref()
        .unwrap()
        .client
        .pending_reads()
        != 0
    {
        pump_admission_store(&mut st, deadline);
    }
    assert!(
        st.shards[0].sh.rocks_session_admitted((72, 2)),
        "late output cannot reclaim old ownership"
    );
    let slices = st.shards[0].stats.scan_slices;
    while st.shards[0].stats.scan_slices == slices {
        st.read_session(Some((72, 2)), true);
        assert!(matches!(
            st.omap_iter(&c, &object, b"", 700),
            Err(ObjError::WouldBlock)
        ));
        st.read_session(None, true);
        pump_admission_store(&mut st, deadline);
    }
    assert_eq!(st.shards[0].rocks_memos[0].n, 256);
    assert!(st.shards[0].rocks_memos[0].engine_page.is_some());
    st.shards[0]
        .sh
        .rocks
        .as_mut()
        .unwrap()
        .client
        .test_expire_credits();
    st.shards[0].sh.wake = false;
    st.shards[0].sh.rocks_step();
    assert!(
        st.shards[0].sh.wake,
        "partial-batch idle expiry releases credits"
    );
    assert_eq!(
        st.shards[0]
            .sh
            .rocks
            .as_ref()
            .unwrap()
            .client
            .retained_session(),
        None
    );
    st.shards[0].sh.wake = false;
    st.shards[0].sh.rocks_step();
    assert!(!st.shards[0].sh.wake, "expiry wakes once");
    st.shards[0].pf_expire(u64::MAX);
    assert!(st.shards[0].rocks_memos.is_empty());
    let page = loop {
        st.read_session(Some((72, 3)), true);
        let result = st.omap_iter(&c, &object, b"", 700);
        st.read_session(None, matches!(result, Err(ObjError::WouldBlock)));
        match result {
            Ok((page, more)) => {
                assert!(!more);
                break page;
            }
            Err(ObjError::WouldBlock) => pump_admission_store(&mut st, deadline),
            Err(e) => panic!("{e:?}"),
        }
    };
    let expected: Vec<_> = (0..700)
        .map(|i| (format!("k/{i:05}").into_bytes(), b"v".to_vec()))
        .collect();
    assert_eq!(page, expected);
}

#[test]
fn scan_admission_stage_rechecks_quota_after_partial_progress_and_unknown_end() {
    use crate::obj::ObjError;
    let (_temp, mut st, c, object) = admission_store_fixture(700, b"v");
    let deadline = Instant::now() + Duration::from_secs(20);
    //512-entry output fits initially, but retained vector+encoding+per-entry
    // representation charges exceed this envelope after the first owner slice.
    st.shards[0]
        .sh
        .rocks
        .as_mut()
        .unwrap()
        .client
        .test_read_budget(335_000);
    let slices = st.shards[0].stats.scan_slices;
    loop {
        st.read_session(Some((73, 1)), true);
        let result = st.omap_iter(&c, &object, b"", 512);
        st.read_session(None, matches!(result, Err(ObjError::WouldBlock)));
        match result {
            Err(ObjError::TooLarge) => break,
            Err(ObjError::WouldBlock) => pump_admission_store(&mut st, deadline),
            r => panic!("per-entry quota was bypassed: {r:?}"),
        }
    }
    assert_eq!(st.shards[0].stats.scan_slices - slices, 1);
    assert!(st.shards[0].rocks_memos.is_empty());
    st.shards[0]
        .sh
        .rocks
        .as_mut()
        .unwrap()
        .client
        .test_read_budget(16 << 20);
    let slices = st.shards[0].stats.scan_slices;
    let mut made_unknown = false;
    let page = loop {
        st.read_session(Some((73, 2)), true);
        let result = st.omap_iter(&c, &object, b"", 512);
        st.read_session(None, matches!(result, Err(ObjError::WouldBlock)));
        match result {
            Ok((page, more)) => {
                assert!(more);
                break page;
            }
            Err(ObjError::WouldBlock) => {
                if !made_unknown && st.shards[0].stats.scan_slices > slices {
                    let page = st.shards[0].rocks_memos[0].engine_page.as_mut().unwrap();
                    assert!(matches!(page.end, PageEnd::Next(_)));
                    // Model a worker batch with no remaining credit for its next
                    // key. The real Stage must probe after the retained batch,
                    // not invent EOF, restart, or skip the first unreturned key.
                    page.end = PageEnd::Unknown;
                    made_unknown = true;
                }
                pump_admission_store(&mut st, deadline);
            }
            Err(e) => panic!("{e:?}"),
        }
    };
    assert!(made_unknown);
    assert_eq!(st.shards[0].stats.scan_slices - slices, 2);
    let expected: Vec<_> = (0..512)
        .map(|i| (format!("k/{i:05}").into_bytes(), b"v".to_vec()))
        .collect();
    assert_eq!(page, expected);
}

#[test]
fn truncated_rocks_page_continues_at_the_first_unconsumed_entry() {
    let (_temp, disk, sb, dir, cfg) = fixture();
    let mut sh = mounted(&disk, &sb, &dir, &cfg);
    let mut txn = Txn::new(1);
    for i in 0..10 {
        txn.ops
            .push(put(42, format!("key-{i:03}").as_bytes(), b"v"));
    }
    sh.submit(txn).unwrap();
    pump(&mut sh, |s, _| s.olsm_flushed());
    let (page, end) = loop {
        match sh.rocks_list_page(None, 42, b"", false, b"", 1) {
            Ok(page) => break page,
            Err(StoreError::Miss) => {
                pump(&mut sh, |_, ev| ev.iter().any(|e| matches!(e, Event::Wake)))
            }
            Err(e) => panic!("{e:?}"),
        }
    };
    assert!(
        page[0].0.is_unique(),
        "unscoped key must not retain worker backing"
    );
    assert!(
        page[0].1.is_unique(),
        "unscoped value must not retain worker backing"
    );
    assert_eq!(&page[0].0[..], b"key-000");
    assert_eq!(page.len(), 1);
    assert_eq!(end, PageEnd::Next(Bytes::from_static(b"key-001")));
}

#[test]
fn packed_stage_keeps_slab_through_yields_and_detaches_cursor_at_end_or_cutoff() {
    use crate::obj::ObjError;
    let (_temp, mut st, c, object) = admission_store_fixture(512, &[0x5a; 256]);
    let deadline = Instant::now() + Duration::from_secs(20);
    for max_bytes in [usize::MAX, 1] {
        let session = (85, u64::from(max_bytes == 1));
        st.read_session(Some(session), true);
        assert!(matches!(
            st.omap_list_enc(&c, &object, b"", b"k/", 512, max_bytes, true, 4),
            Err(ObjError::WouldBlock)
        ));
        st.read_session(None, true);
        // Keep a real worker answer alive while Stage consumes its shared-Arc
        // fallback. This pins the allocation's address: detached cursor storage
        // cannot alias it, even after the batch's last key becomes unique.
        let held = loop {
            if let Some(answer) = st.shards[0]
                .sh
                .rocks
                .as_ref()
                .unwrap()
                .client
                .test_cached_page()
            {
                break answer;
            }
            pump_admission_store(&mut st, deadline);
        };
        let crate::rocks_omap::Answer::Page(page, _) = &*held else {
            panic!("worker page")
        };
        assert_eq!(page.len(), 512);
        let backing = page.get(0).unwrap().0.as_ptr() as usize
            ..page.get(511).unwrap().1.as_ptr() as usize + page.get(511).unwrap().1.len();
        let mut saw_shared_slice = false;
        let (mut enc, n, more) = loop {
            st.read_session(Some(session), true);
            let result = st.omap_list_enc(&c, &object, b"", b"k/", 512, max_bytes, true, 4);
            st.read_session(None, true);
            match result {
                Ok(out) => break out,
                Err(ObjError::WouldBlock) => {
                    if let Some(m) = st.shards[0].rocks_memos.first()
                        && m.n > 0
                        && m.engine_page.is_some()
                    {
                        assert_eq!(
                            m.engine_cursor.as_ref().unwrap().0.as_ref(),
                            b"",
                            "partial first batch keeps the original boundary cursor, not a per-entry owner"
                        );
                        assert!(!m.engine_cursor.as_ref().unwrap().1);
                        assert!(
                            m.engine_charge() >= page.bytes(),
                            "offset progress must retain the whole charged envelope"
                        );
                        assert!(backing.contains(
                            &(m.engine_page.as_ref().unwrap().peek().unwrap().0.as_ptr() as usize)
                        ));
                        saw_shared_slice = true;
                    }
                    pump_admission_store(&mut st, deadline);
                }
                Err(e) => panic!("{e:?}"),
            }
        };
        assert_eq!(n, if max_bytes == 1 { 1 } else { 512 });
        assert_eq!(more, max_bytes == 1);
        assert_eq!(saw_shared_slice, max_bytes != 1);
        let memo = &st.shards[0].rocks_memos[0];
        assert!(memo.engine_page.is_none());
        assert!(
            !backing.contains(&(memo.engine_cursor.as_ref().unwrap().0.as_ptr() as usize)),
            "cursor must have independent backing at completion and cutoff"
        );
        assert!(
            memo.engine_cursor.as_ref().unwrap().0.is_unique(),
            "retired batch cannot escape through its cursor"
        );
        let expected = enc.clone();
        enc[4] ^= 0xff;
        st.read_session(Some(session), true);
        assert_eq!(
            st.omap_list_enc(&c, &object, b"", b"k/", 512, max_bytes, true, 4)
                .unwrap(),
            (expected, n, more)
        );
        st.read_session(None, false);
        assert!(st.shards[0].rocks_memos.is_empty());
    }
}

#[test]
fn native_ack_replay_restores_unmaterialized_omap_and_native_records() {
    let (_temp, disk, sb, dir, cfg) = fixture();
    let mut sh = mounted(&disk, &sb, &dir, &cfg);
    // Deterministically hold the external worker: native ACK must depend on its
    // WAL/data, not on successful external materialization.
    sh.rocks.as_mut().unwrap().client.read_only = true;
    let mut t = Txn::new(17);
    t.put(b"!native", b"committed");
    t.ops.push(put(42, b"key", b"value"));
    sh.submit(t).unwrap();
    pump(&mut sh, |_, ev| {
        ev.iter().any(|e| matches!(e, Event::Acked(17)))
    });
    assert_eq!(sh.rocks.as_ref().unwrap().client.watermark, 0);
    assert_eq!(get(&mut sh, 42, b"key"), Some(Bytes::from_static(b"value")));
    assert!(sh.state.olsm.as_ref().unwrap().active.is_empty());
    assert!(sh.state.olsm.as_ref().unwrap().frozen.is_none());
    assert!(!sh.state.rocks_mem.as_ref().unwrap().is_empty());
    let acknowledged = sh.state.lsn;
    assert!(sh.olsm_floor().is_some_and(|f| f <= acknowledged));
    // Advance the native tree checkpoint past the unmaterialized Rocks OMAP.
    // Recovery must still collect retained redo below/equal that checkpoint.
    sh.request_checkpoint();
    pump(&mut sh, |s, _| s.ckpt_lsn >= acknowledged);
    assert_eq!(sh.rocks.as_ref().unwrap().client.watermark, 0);
    drop(sh);
    let recovered = SimDisk::from_image(
        &disk.crash_image(CrashPolicy::DROP_ALL),
        SimConfig::new(64 << 20),
    );
    let mut sh = mounted(&recovered, &sb, &dir, &cfg);
    assert_eq!(get(&mut sh, 42, b"key"), Some(Bytes::from_static(b"value")));
    let mut out = Vec::new();
    loop {
        match sh.get(b"!native", &mut out) {
            Err(StoreError::Miss) => pump(&mut sh, |_, e| !e.is_empty()),
            r => {
                assert!(r.unwrap());
                break;
            }
        }
    }
    assert_eq!(out, b"committed");
}

#[test]
fn external_sync_before_native_publication_catches_up_without_resurrection() {
    let (_temp, disk, sb, dir, cfg) = fixture();
    let mut sh = mounted(&disk, &sb, &dir, &cfg);
    let mut t = Txn::new(1);
    t.ops.push(put(9, b"k", b"old"));
    sh.submit(t).unwrap();
    pump(&mut sh, |s, _| s.olsm_flushed());
    let mut t = Txn::new(2);
    t.ops.push(Op::Omap(OOp::Range {
        id: 9,
        first: Bytes::new(),
        end: None,
    }));
    sh.submit(t).unwrap();
    pump(&mut sh, |_, ev| {
        ev.iter().any(|e| matches!(e, Event::Acked(2)))
    });
    // Dispatch after native durability, then consume DB completion without letting
    // the owner submit its publication transaction.
    sh.rocks_step();
    let deadline = Instant::now() + Duration::from_secs(10);
    while sh.rocks.as_ref().unwrap().client.flushed.is_none() {
        sh.rocks.as_mut().unwrap().client.poll();
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    let external = sh.rocks.as_ref().unwrap().client.watermark;
    assert!(external > sh.state.olsm.as_ref().unwrap().man.flushed_lsn);
    drop(sh);
    let image = disk.crash_image(CrashPolicy::DROP_ALL);
    let recovered = SimDisk::from_image(&image, SimConfig::new(64 << 20));
    let mut sh = mounted(&recovered, &sb, &dir, &cfg);
    assert_eq!(get(&mut sh, 9, b"k"), None);
    pump(&mut sh, |s, _| {
        s.state.olsm.as_ref().unwrap().man.flushed_lsn >= external
    });
    let checkpoint = sh.state.lsn;
    sh.request_checkpoint();
    pump(&mut sh, |s, _| s.ckpt_lsn >= checkpoint);
    drop(sh);
    let again = SimDisk::from_image(
        &recovered.crash_image(CrashPolicy::DROP_ALL),
        SimConfig::new(64 << 20),
    );
    let mut sh = mounted(&again, &sb, &dir, &cfg);
    assert_eq!(get(&mut sh, 9, b"k"), None);
}

#[test]
fn restored_stale_database_refuses_after_native_checkpoint() {
    let (_temp, disk, sb, dir, cfg) = fixture();
    let mut sh = mounted(&disk, &sb, &dir, &cfg);
    let mut t = Txn::new(1);
    t.ops.push(put(42, b"key", b"value"));
    sh.submit(t).unwrap();
    pump(&mut sh, |s, _| s.olsm_flushed());
    let checkpoint = sh.state.lsn;
    sh.request_checkpoint();
    pump(&mut sh, |s, _| s.ckpt_lsn >= checkpoint);
    drop(sh);
    let rocks = cfg.rocksdb.as_ref().unwrap();
    // Replace only this test-owned DB with an older, correctly identified empty
    // database. Identity alone must not make the stale contents acceptable.
    std::fs::remove_dir_all(rocks.path(&sb, 0).unwrap()).unwrap();
    crate::rocks_omap::create(rocks, &sb, 8 << 20).unwrap();
    let r = Shard::mount(
        disk.queue(),
        &mut SimClock::default(),
        &sb,
        &dir,
        cfg,
        false,
    );
    assert!(matches!(r, Err(StoreError::Corrupt(_))));
}

#[test]
fn asynchronous_base_scan_merges_ranges_points_and_transaction_overlay() {
    let (_temp, disk, sb, dir, cfg) = fixture();
    let mut sh = mounted(&disk, &sb, &dir, &cfg);
    let mut t = Txn::new(1);
    for i in 0..700 {
        t.ops.push(put(3, format!("k{i:04}").as_bytes(), b"base"));
    }
    sh.submit(t).unwrap();
    pump(&mut sh, |s, _| s.olsm_flushed());
    let mut over = Memtable::new();
    over.del_range(
        0,
        3,
        Bytes::from_static(b"k0010"),
        Some(Bytes::from_static(b"k0650")),
    );
    over.put(
        0,
        3,
        Bytes::from_static(b"k0300"),
        Bytes::from_static(b"overlay"),
    );
    let mut out = Vec::new();
    let mut from = Bytes::new();
    let mut excl = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match sh.rocks_list(Some(&over), 3, &from, excl, b"k", 100) {
            Err(StoreError::Miss) => pump(&mut sh, |_, ev| !ev.is_empty()),
            Ok((v, more)) => {
                if let Some((last, _)) = v.last() {
                    from = last.clone();
                    excl = true;
                }
                out.extend(v);
                if !more {
                    break;
                }
            }
            Err(e) => panic!("{e}"),
        }
        assert!(Instant::now() < deadline);
    }
    let expected: Vec<_> = (0..700)
        .filter(|i| *i < 10 || *i >= 650 || *i == 300)
        .map(|i| {
            (
                Bytes::from(format!("k{i:04}")),
                if i == 300 {
                    Bytes::from_static(b"overlay")
                } else {
                    Bytes::from_static(b"base")
                },
            )
        })
        .collect();
    assert_eq!(out, expected);
}

#[test]
fn filesystem_full_refuses_before_log_and_does_not_block_pure_delete() {
    let (_temp, disk, sb, dir, cfg) = fixture();
    let mut sh = mounted(&disk, &sb, &dir, &cfg);
    sh.rocks.as_mut().unwrap().client.test_space(0);
    assert_eq!(sh.statfs().fill_ratio(), 1.0);
    let lsn = sh.state.lsn;
    let mut t = Txn::new(1);
    t.ops.push(put(3, b"k", b"v"));
    assert!(matches!(sh.submit(t), Err((StoreError::NoSpace, _))));
    assert_eq!(sh.state.lsn, lsn, "capacity refusal must precede apply/WAL");
    let mut t = Txn::new(2);
    t.shrink = true;
    t.ops.push(Op::Omap(OOp::Range {
        id: 3,
        first: Bytes::new(),
        end: None,
    }));
    assert!(sh.submit(t).is_ok());
}

#[test]
fn frozen_native_undurable_table_never_reaches_external_database() {
    let (_temp, disk, sb, dir, cfg) = fixture();
    let mut sh = mounted(&disk, &sb, &dir, &cfg);
    let mut t = Txn::new(1);
    t.ops.push(put(3, b"unacked", b"value"));
    sh.submit(t).unwrap();
    assert!(sh.state.lsn > sh.durable_lsn);
    sh.rocks_step();
    assert!(sh.state.rocks_mem.as_ref().unwrap().frozen.is_some());
    assert!(!sh.rocks.as_ref().unwrap().client.busy());
    assert_eq!(sh.rocks.as_ref().unwrap().client.watermark, 0);
    drop(sh);
    let image = disk.crash_image(CrashPolicy::DROP_ALL);
    let recovered = SimDisk::from_image(&image, SimConfig::new(64 << 20));
    let mut sh = mounted(&recovered, &sb, &dir, &cfg);
    assert_eq!(get(&mut sh, 3, b"unacked"), None);
}

#[test]
fn profiling_freeze_wait_keeps_native_durability_gate_and_eager_progress() {
    let (_temp, disk, sb, dir, mut cfg) = fixture();
    cfg.rocksdb.as_mut().unwrap().profile = true;
    let mut sh = mounted(&disk, &sb, &dir, &cfg);
    let mut t = Txn::new(1);
    t.ops.push(put(3, b"key", b"value"));
    sh.submit(t).unwrap();
    assert!(sh.state.lsn > sh.durable_lsn);
    for _ in 0..4 {
        sh.rocks_step();
    }
    let s = sh.rocks_profile_gauges().unwrap();
    assert_eq!(s[27], 1, "one eager freeze across repeated polls");
    assert_eq!(s[29], 1, "frozen before native durability");
    assert_eq!(s[30], 0, "undurable table must not enqueue");
    assert_eq!(
        s[31], 0,
        "pending interval is not a successful enqueue sample"
    );
    assert_eq!(sh.rocks.as_ref().unwrap().client.watermark, 0);
    pump(&mut sh, |s, _| {
        s.state.rocks_mem.as_ref().unwrap().frozen.is_none()
            && s.rocks.as_ref().unwrap().client.watermark > 0
    });
    let s = sh.rocks_profile_gauges().unwrap();
    assert_eq!(s[27], 1);
    assert_eq!(s[30], 1);
    assert!(s[31] > 0);
    assert_eq!(s[32], 0);
    assert_eq!(get(&mut sh, 3, b"key"), Some(Bytes::from_static(b"value")));
}

#[test]
fn readonly_mount_reads_native_redo_without_materializing_and_reports_db_bytes() {
    let (_temp, disk, sb, dir, mut cfg) = fixture();
    let mut sh = mounted(&disk, &sb, &dir, &cfg);
    sh.rocks.as_mut().unwrap().client.read_only = true;
    let mut t = Txn::new(1);
    t.ops.push(put(51, b"redo", b"native-only"));
    sh.submit(t).unwrap();
    pump(&mut sh, |_, ev| {
        ev.iter().any(|e| matches!(e, Event::Acked(1)))
    });
    assert_eq!(sh.rocks.as_ref().unwrap().client.watermark, 0);
    drop(sh);
    let path = cfg.rocksdb.as_ref().unwrap().path(&sb, 0).unwrap();
    let files = || -> std::collections::BTreeMap<_, _> {
        std::fs::read_dir(&path)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (e.file_name(), std::fs::read(e.path()).unwrap())
            })
            .collect()
    };
    let before = files();
    cfg.rocksdb.as_mut().unwrap().read_only = true;
    let recovered = SimDisk::from_image(
        &disk.crash_image(CrashPolicy::DROP_ALL),
        SimConfig::new(64 << 20),
    );
    let mut sh = mounted(&recovered, &sb, &dir, &cfg);
    assert_eq!(
        get(&mut sh, 51, b"redo"),
        Some(Bytes::from_static(b"native-only"))
    );
    assert_eq!(sh.rocks.as_ref().unwrap().client.watermark, 0);
    assert!(sh.olsm_bytes().unwrap() > 0);
    drop(sh);
    assert_eq!(files(), before);
}
