// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Journal writer tests (journaling S4) over `MemJournalBackend`.

use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use super::*;
use crate::journal_mem::MemJournalBackend;
use crate::{
    JOURNAL_CLIENT_STATE_DISCONNECTED, JournalPlayer, decode_journal_client,
    decode_journal_event_entry, encode_image_client_data,
};

/// Shared fake clock: tests advance it, the writer reads it.
#[derive(Clone, Debug, Default)]
struct FakeClock(Rc<Cell<Duration>>);

impl FakeClock {
    fn advance(&self, by: Duration) {
        self.0.set(self.0.get() + by);
    }
}

impl JournalClock for FakeClock {
    fn monotonic(&self) -> Duration {
        self.0.get()
    }

    fn timestamp(&self) -> (u32, u32) {
        (7, 9)
    }
}

/// Delegating backend that counts calls and injects errors.
#[derive(Default)]
struct Probe<'a> {
    inner: Option<&'a MemJournalBackend>,
    appends: Cell<u64>,
    commits: Cell<u64>,
    set_active_set_err: Option<i32>,
    remove_err: Option<i32>,
    commit_err: Option<i32>,
}

impl<'a> Probe<'a> {
    fn new(inner: &'a MemJournalBackend) -> Self {
        Self {
            inner: Some(inner),
            ..Self::default()
        }
    }

    fn mem(&self) -> &MemJournalBackend {
        self.inner.expect("probe wraps a backend")
    }
}

impl JournalBackend for Probe<'_> {
    fn get_geometry(&self) -> Result<JournalGeometry, i32> {
        self.mem().get_geometry()
    }
    fn get_client(&self, id: &[u8]) -> Result<Vec<u8>, i32> {
        self.mem().get_client(id)
    }
    fn client_list(&self, start_after: &[u8], max: u64) -> Result<Vec<u8>, i32> {
        self.mem().client_list(start_after, max)
    }
    fn client_register(&self, id: &[u8], data: &[u8]) -> Result<(), i32> {
        self.mem().client_register(id, data)
    }
    fn client_commit(&self, id: &[u8], positions: &[JournalObjectPosition]) -> Result<(), i32> {
        self.commits.set(self.commits.get() + 1);
        match self.commit_err {
            Some(errno) => Err(errno),
            None => self.mem().client_commit(id, positions),
        }
    }
    fn tag_list(
        &self,
        start_after: u64,
        max: u64,
        client_id: &[u8],
        tag_class: Option<u64>,
    ) -> Result<Vec<u8>, i32> {
        self.mem().tag_list(start_after, max, client_id, tag_class)
    }
    fn get_tag(&self, tid: u64) -> Result<Vec<u8>, i32> {
        self.mem().get_tag(tid)
    }
    fn tag_create(&self, tid: u64, tag_class: u64, data: &[u8]) -> Result<(), i32> {
        self.mem().tag_create(tid, tag_class, data)
    }
    fn get_next_tag_tid(&self) -> Result<u64, i32> {
        self.mem().get_next_tag_tid()
    }
    fn set_active_set(&self, set: u64) -> Result<(), i32> {
        match self.set_active_set_err {
            Some(errno) => Err(errno),
            None => self.mem().set_active_set(set),
        }
    }
    fn set_minimum_set(&self, set: u64) -> Result<(), i32> {
        self.mem().set_minimum_set(set)
    }
    fn append(&self, object_number: u64, soft_max: u64, bytes: &[u8]) -> Result<(), i32> {
        self.appends.set(self.appends.get() + 1);
        self.mem().append(object_number, soft_max, bytes)
    }
    fn read_object(&self, object_number: u64, offset: u64, buf: &mut [u8]) -> Result<usize, i32> {
        self.mem().read_object(object_number, offset, buf)
    }
    fn remove_object(&self, object_number: u64) -> Result<(), i32> {
        match self.remove_err {
            Some(errno) => Err(errno),
            None => self.mem().remove_object(object_number),
        }
    }
    fn create(&self, order: u8, splay_width: u8, pool_id: i64) -> Result<(), i32> {
        self.mem().create(order, splay_width, pool_id)
    }
    fn remove_header(&self) -> Result<(), i32> {
        self.mem().remove_header()
    }
}

const TAG: u64 = 1;

fn position(object: u64, tag: u64, entry: u64) -> JournalObjectPosition {
    JournalObjectPosition {
        object_number: object,
        tag_tid: tag,
        entry_tid: entry,
    }
}

/// A fresh journal with the local image client registered.
fn journal(order: u8, width: u8, min_alloc: u64) -> MemJournalBackend {
    let backend = MemJournalBackend::new().with_min_alloc_size(min_alloc);
    backend.create(order, width, -1).unwrap();
    backend
        .client_register(b"", &encode_image_client_data(0, false))
        .unwrap();
    backend
}

fn config(commit_age: Duration) -> JournalWriterConfig {
    JournalWriterConfig {
        commit_age,
        max_payload_bytes: 16384,
        image_id: "test".into(),
    }
}

/// A writer at TID 0 of `TAG` over the backend's current geometry.
fn writer(backend: &impl JournalBackend, clock: &FakeClock) -> JournalWriter<FakeClock> {
    let geometry = backend.get_geometry().unwrap();
    JournalWriter::new(
        &geometry,
        TAG,
        (Vec::new(), 0),
        config(Duration::from_secs(3600)),
        clock.clone(),
    )
    .unwrap()
}

/// The stored commit positions of the local client.
fn stored(backend: &impl JournalBackend) -> Vec<JournalObjectPosition> {
    decode_journal_client(&backend.get_client(b"").unwrap())
        .unwrap()
        .commit_positions
}

/// Replay from the stored positions; returns the records.
fn replay(backend: &impl JournalBackend) -> Vec<ReplayRecordView> {
    let geometry = backend.get_geometry().unwrap();
    let mut player = JournalPlayer::new(&geometry, &stored(backend), &[TAG]).unwrap();
    let mut mem = MemView(backend);
    let mut records = Vec::new();
    while let Some(record) = player.next(&mut mem).unwrap() {
        records.push(ReplayRecordView {
            object: record.object_number,
            tid: record.entry_tid,
            data: record.data,
        });
    }
    records
}

/// The player takes `&mut impl JournalBackend`; this adapts a shared one.
struct MemView<'a, B>(&'a B);

impl<B: JournalBackend> JournalBackend for MemView<'_, B> {
    fn get_geometry(&self) -> Result<JournalGeometry, i32> {
        self.0.get_geometry()
    }
    fn get_client(&self, id: &[u8]) -> Result<Vec<u8>, i32> {
        self.0.get_client(id)
    }
    fn client_list(&self, start_after: &[u8], max: u64) -> Result<Vec<u8>, i32> {
        self.0.client_list(start_after, max)
    }
    fn client_register(&self, id: &[u8], data: &[u8]) -> Result<(), i32> {
        self.0.client_register(id, data)
    }
    fn client_commit(&self, id: &[u8], positions: &[JournalObjectPosition]) -> Result<(), i32> {
        self.0.client_commit(id, positions)
    }
    fn tag_list(
        &self,
        start_after: u64,
        max: u64,
        client_id: &[u8],
        tag_class: Option<u64>,
    ) -> Result<Vec<u8>, i32> {
        self.0.tag_list(start_after, max, client_id, tag_class)
    }
    fn get_tag(&self, tid: u64) -> Result<Vec<u8>, i32> {
        self.0.get_tag(tid)
    }
    fn tag_create(&self, tid: u64, tag_class: u64, data: &[u8]) -> Result<(), i32> {
        self.0.tag_create(tid, tag_class, data)
    }
    fn get_next_tag_tid(&self) -> Result<u64, i32> {
        self.0.get_next_tag_tid()
    }
    fn set_active_set(&self, set: u64) -> Result<(), i32> {
        self.0.set_active_set(set)
    }
    fn set_minimum_set(&self, set: u64) -> Result<(), i32> {
        self.0.set_minimum_set(set)
    }
    fn append(&self, object_number: u64, soft_max: u64, bytes: &[u8]) -> Result<(), i32> {
        self.0.append(object_number, soft_max, bytes)
    }
    fn read_object(&self, object_number: u64, offset: u64, buf: &mut [u8]) -> Result<usize, i32> {
        self.0.read_object(object_number, offset, buf)
    }
    fn remove_object(&self, object_number: u64) -> Result<(), i32> {
        self.0.remove_object(object_number)
    }
    fn create(&self, order: u8, splay_width: u8, pool_id: i64) -> Result<(), i32> {
        self.0.create(order, splay_width, pool_id)
    }
    fn remove_header(&self) -> Result<(), i32> {
        self.0.remove_header()
    }
}

#[derive(Debug)]
struct ReplayRecordView {
    object: u64,
    tid: u64,
    data: Vec<u8>,
}

fn tids(records: &[ReplayRecordView]) -> Vec<u64> {
    records.iter().map(|record| record.tid).collect()
}

fn write(offset: u64, data: &[u8]) -> JournalEvent<'_> {
    JournalEvent::Write {
        offset,
        length: data.len() as u64,
        data,
    }
}

/// Append and complete one request successfully.
fn apply(
    writer: &mut JournalWriter<FakeClock>,
    backend: &impl JournalBackend,
    events: &[JournalEvent<'_>],
) {
    let ticket = writer.append(backend, events).unwrap();
    writer.complete(backend, ticket, 0).unwrap();
}

#[test]
fn assigns_tids_round_robin_over_splays() {
    let backend = journal(24, 4, 8);
    let clock = FakeClock::default();
    let mut writer = writer(&backend, &clock);
    let first = writer
        .append(
            &backend,
            &[
                JournalEvent::Flush,
                JournalEvent::Flush,
                JournalEvent::Flush,
            ],
        )
        .unwrap();
    assert_eq!((first.first_tid(), first.last_tid()), (0, 2));
    let second = writer
        .append(
            &backend,
            &[
                JournalEvent::Flush,
                JournalEvent::Flush,
                JournalEvent::Flush,
            ],
        )
        .unwrap();
    assert_eq!((second.first_tid(), second.last_tid()), (3, 5));
    assert_eq!(writer.next_tid(), 6);
    writer.complete(&backend, first, 0).unwrap();
    writer.complete(&backend, second, 0).unwrap();
    assert_eq!(
        writer.positions(),
        [
            position(1, TAG, 5),
            position(0, TAG, 4),
            position(3, TAG, 3),
            position(2, TAG, 2),
        ]
    );
    // Durable before the ticket: a fresh player sees all six records in
    // TID order, each in its splay object.
    let records = replay(&backend);
    assert_eq!(tids(&records), [0, 1, 2, 3, 4, 5]);
    assert_eq!(
        records.iter().map(|r| r.object).collect::<Vec<_>>(),
        [0, 1, 2, 3, 0, 1]
    );
    let entry = decode_journal_event_entry(&records[0].data).unwrap();
    assert_eq!(entry.event, Some(JournalEvent::Flush));
    assert_eq!(
        (entry.timestamp_seconds, entry.timestamp_nanoseconds),
        (7, 9)
    );
}

#[test]
fn oracle_positions_after_write_and_flush() {
    // Reference oracle: Write at (0,1,0), Flush at (1,1,1), width 2,
    // committed [(1,1,1),(0,1,0)] newest first.
    let backend = journal(24, 2, 8);
    let clock = FakeClock::default();
    let mut writer = writer(&backend, &clock);
    apply(&mut writer, &backend, &[write(0, &[0xab; 512])]);
    apply(&mut writer, &backend, &[JournalEvent::Flush]);
    assert!(stored(&backend).is_empty(), "no persist before the cadence");
    writer.persist(&backend).unwrap();
    assert_eq!(stored(&backend), [position(1, TAG, 1), position(0, TAG, 0)]);
    assert!(replay(&backend).is_empty());
}

#[test]
fn rollover_preempts_a_full_object_and_moves_every_splay() {
    // Allocation pad 8: the writer knows the next record would pass the
    // soft maximum and rolls over without an overflowing append.
    let backend = journal(12, 2, 8);
    let probe = Probe::new(&backend);
    let clock = FakeClock::default();
    let mut writer = writer(&probe, &clock);
    // 1077-byte records: three fit one 4096-byte object, the fourth not.
    let data = [1u8; 1000];
    for request in 0..7 {
        apply(&mut writer, &probe, &[write(request * 4096, &data)]);
    }
    assert_eq!(writer.active_set(), 1);
    assert_eq!(probe.appends.get(), 7);
    assert_eq!(backend.get_geometry().unwrap().active_set, 1);
    // tid 7 (splay 1) also uses the new set.
    apply(&mut writer, &probe, &[write(0, &data)]);
    let records = replay(&probe);
    assert_eq!(tids(&records), [0, 1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(
        records.iter().map(|r| r.object).collect::<Vec<_>>(),
        [0, 1, 0, 1, 0, 1, 2, 3]
    );
    // One request's batch is cut at the object end as well; the rollover
    // inside splay 0's batch moves splay 1's batch to the new set too.
    let batch: Vec<JournalEvent<'_>> = (0..6).map(|i| write(i * 4096, &data)).collect();
    apply(&mut writer, &probe, &batch);
    let records = replay(&probe);
    assert_eq!(
        records.iter().map(|r| r.object).collect::<Vec<_>>(),
        [0, 1, 0, 1, 0, 1, 2, 3, 2, 5, 2, 5, 4, 5]
    );
}

#[test]
fn rollover_on_overflow_retries_the_batch_in_the_next_set() {
    // Allocation pad 4096 = soft maximum: the class reports the object
    // full before the writer's own byte count does.
    let backend = journal(12, 2, 4096);
    let probe = Probe::new(&backend);
    let clock = FakeClock::default();
    let mut writer = writer(&probe, &clock);
    let data = [2u8; 100];
    for request in 0..3 {
        apply(&mut writer, &probe, &[write(request * 512, &data)]);
    }
    // tid 2: append to object 0 overflows, retried in object 2.
    assert_eq!(probe.appends.get(), 4);
    assert_eq!(writer.active_set(), 1);
    assert_eq!(writer.positions()[0], position(2, TAG, 2));
    assert_eq!(tids(&replay(&probe)), [0, 1, 2]);
}

#[test]
fn rollover_estale_adopts_the_newer_active_set() {
    let backend = journal(12, 2, 4096);
    let clock = FakeClock::default();
    let mut writer = writer(&backend, &clock);
    apply(&mut writer, &backend, &[JournalEvent::Flush]);
    // Another writer published set 5 meanwhile.
    backend.set_active_set(5).unwrap();
    apply(&mut writer, &backend, &[JournalEvent::Flush]);
    // tid 1 still fits its set-0 object 1; tid 2 overflows object 0.
    assert_eq!(writer.active_set(), 0);
    apply(&mut writer, &backend, &[JournalEvent::Flush]);
    assert_eq!(writer.active_set(), 5);
    assert_eq!(writer.positions()[0], position(10, TAG, 2));
    assert_eq!(writer.state(), WriterState::Ready);
}

#[test]
fn rollover_estale_without_a_newer_set_fails_eio() {
    let backend = journal(12, 1, 4096);
    let mut probe = Probe::new(&backend);
    let clock = FakeClock::default();
    let mut writer = writer(&probe, &clock);
    apply(&mut writer, &probe, &[JournalEvent::Flush]);
    probe.set_active_set_err = Some(ESTALE);
    assert_eq!(writer.append(&probe, &[JournalEvent::Flush]), Err(EIO));
    assert_eq!(writer.state(), WriterState::Failed(EIO));
    assert_eq!(writer.append(&probe, &[JournalEvent::Flush]), Err(EIO));
    assert_eq!(writer.persist(&probe), Err(EIO));
}

#[test]
fn split_write_spreads_over_splays_one_append_per_splay() {
    let backend = journal(24, 4, 8);
    let probe = Probe::new(&backend);
    let clock = FakeClock::default();
    let mut writer = writer(&probe, &clock);
    let chunk = writer.write_chunk_len() as usize;
    assert_eq!(chunk, 16340);
    let data: Vec<u8> = (0..3 * chunk + 100).map(|i| i as u8).collect();
    let events: Vec<JournalEvent<'_>> = data
        .chunks(chunk)
        .enumerate()
        .map(|(i, part)| write(4096 + (i * chunk) as u64, part))
        .collect();
    assert_eq!(events.len(), 4);
    let ticket = writer.append(&probe, &events).unwrap();
    assert_eq!(probe.appends.get(), 4);
    writer.complete(&probe, ticket, 0).unwrap();
    let records = replay(&probe);
    assert_eq!(tids(&records), [0, 1, 2, 3]);
    assert_eq!(
        records.iter().map(|r| r.object).collect::<Vec<_>>(),
        [0, 1, 2, 3]
    );
    let mut rebuilt = Vec::new();
    for record in &records {
        match decode_journal_event_entry(&record.data).unwrap().event {
            Some(JournalEvent::Write { offset, data, .. }) => {
                assert_eq!(offset, 4096 + rebuilt.len() as u64);
                rebuilt.extend_from_slice(data);
            }
            other => panic!("unexpected event {other:?}"),
        }
    }
    assert_eq!(rebuilt, data);
    // An oversized event is refused before anything is assigned.
    let too_big = vec![0u8; chunk + 1];
    assert_eq!(writer.append(&probe, &[write(0, &too_big)]), Err(EINVAL));
    assert_eq!(writer.next_tid(), 4);
    assert_eq!(writer.state(), WriterState::Ready);
}

#[test]
fn data_error_blocks_commit_advancement() {
    let backend = journal(24, 2, 8);
    let clock = FakeClock::default();
    let mut writer = writer(&backend, &clock);
    let first = writer.append(&backend, &[JournalEvent::Flush]).unwrap();
    let failed = writer.append(&backend, &[write(0, b"x")]).unwrap();
    let third = writer.append(&backend, &[JournalEvent::Flush]).unwrap();
    writer.complete(&backend, first, 0).unwrap();
    writer.complete(&backend, failed, EIO).unwrap();
    assert!(writer.commit_blocked());
    writer.complete(&backend, third, 0).unwrap();
    assert_eq!(writer.positions(), [position(0, TAG, 0)]);
    writer.persist(&backend).unwrap();
    assert_eq!(stored(&backend), [position(0, TAG, 0)]);
    let next = writer.append(&backend, &[JournalEvent::Flush]).unwrap();
    writer.complete(&backend, next, 0).unwrap();
    assert_eq!(writer.positions(), [position(0, TAG, 0)]);
    writer.close(&backend).unwrap();
    assert_eq!(stored(&backend), [position(0, TAG, 0)]);
    // Everything after the failed entry replays.
    assert_eq!(tids(&replay(&backend)), [1, 2, 3]);
}

#[test]
fn eilseq_completes_only_compare_and_write() {
    let backend = journal(24, 2, 8);
    let clock = FakeClock::default();
    let mut writer = writer(&backend, &clock);
    let caw = writer
        .append(
            &backend,
            &[JournalEvent::CompareAndWrite {
                offset: 0,
                length: 1,
                compare: b"a",
                replacement: b"b",
            }],
        )
        .unwrap();
    writer.complete(&backend, caw, EILSEQ).unwrap();
    assert!(!writer.commit_blocked());
    assert_eq!(writer.positions(), [position(0, TAG, 0)]);
    let plain = writer.append(&backend, &[write(0, b"a")]).unwrap();
    writer.complete(&backend, plain, EILSEQ).unwrap();
    assert!(writer.commit_blocked());
    assert_eq!(writer.positions(), [position(0, TAG, 0)]);
}

/// A 20 MiB compare-and-write becomes bounded sub-range records and replays
/// back into the same compare/replacement buffers.
fn large_compare_and_write_round_trip(order: u8) {
    let backend = journal(order, 4, 8);
    let clock = FakeClock::default();
    let mut writer = writer(&backend, &clock);
    let chunk = writer.compare_and_write_chunk_len() as usize;
    assert!(chunk > 0);
    let total = 20 * 1024 * 1024usize;
    let compare: Vec<u8> = (0..total).map(|i| i as u8).collect();
    let replacement: Vec<u8> = (0..total).map(|i| (i as u8) ^ 0xa5).collect();
    let ticket = writer
        .append(
            &backend,
            &[JournalEvent::CompareAndWrite {
                offset: 4096,
                length: total as u64,
                compare: &compare,
                replacement: &replacement,
            }],
        )
        .unwrap();
    let expected = total.div_ceil(chunk) as u64;
    assert_eq!(
        (ticket.first_tid(), ticket.last_tid()),
        (0, expected - 1),
        "order {order}"
    );
    writer.complete(&backend, ticket, 0).unwrap();
    assert_eq!(writer.next_tid(), expected);
    let records = replay(&backend);
    assert_eq!(records.len() as u64, expected);
    let mut rebuilt_compare = Vec::new();
    let mut rebuilt_replacement = Vec::new();
    let mut next_offset = 4096u64;
    for record in &records {
        assert!(
            record.data.len() as u64 <= writer.max_append_size(),
            "order {order}: entry {} exceeds the maximum append size",
            record.data.len()
        );
        match decode_journal_event_entry(&record.data).unwrap().event {
            Some(JournalEvent::CompareAndWrite {
                offset,
                length,
                compare,
                replacement,
            }) => {
                assert_eq!(offset, next_offset, "order {order}");
                assert_eq!(length, compare.len() as u64);
                assert_eq!(compare.len(), replacement.len());
                assert!(compare.len() <= chunk);
                rebuilt_compare.extend_from_slice(compare);
                rebuilt_replacement.extend_from_slice(replacement);
                next_offset += length;
            }
            other => panic!("order {order}: unexpected event {other:?}"),
        }
    }
    assert_eq!(rebuilt_compare, compare);
    assert_eq!(rebuilt_replacement, replacement);
}

#[test]
fn twenty_mib_compare_and_write_splits_at_order_24() {
    large_compare_and_write_round_trip(24);
}

#[test]
fn twenty_mib_compare_and_write_splits_at_order_25() {
    large_compare_and_write_round_trip(25);
}

#[test]
fn small_compare_and_write_stays_one_unchanged_record() {
    let backend = journal(24, 2, 8);
    let clock = FakeClock::default();
    let mut writer = writer(&backend, &clock);
    let compare = [0x11u8; 100];
    let replacement = [0x22u8; 100];
    let event = JournalEvent::CompareAndWrite {
        offset: 1234,
        length: 100,
        compare: &compare,
        replacement: &replacement,
    };
    let ticket = writer
        .append(&backend, std::slice::from_ref(&event))
        .unwrap();
    assert_eq!((ticket.first_tid(), ticket.last_tid()), (0, 0));
    let mut entry = Vec::new();
    crate::encode_journal_event_entry(&event, 7, 9, &mut entry).unwrap();
    let mut expected = Vec::new();
    crate::encode_journal_record(0, TAG, &entry, &mut expected).unwrap();
    let mut buf = vec![0u8; 4096];
    let read = backend.read_object(0, 0, &mut buf).unwrap();
    assert_eq!(&buf[..expected.len()], &expected[..]);
    assert!(buf[expected.len()..read].iter().all(|byte| *byte == 0));
    let records = replay(&backend);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].data, entry);
    writer.complete(&backend, ticket, 0).unwrap();
}

#[test]
fn cadence_follows_the_injected_clock_and_skips_unchanged_positions() {
    let backend = journal(24, 2, 8);
    let probe = Probe::new(&backend);
    let clock = FakeClock::default();
    let geometry = backend.get_geometry().unwrap();
    let mut writer = JournalWriter::new(
        &geometry,
        TAG,
        (Vec::new(), 0),
        config(Duration::from_secs(5)),
        clock.clone(),
    )
    .unwrap();
    apply(&mut writer, &probe, &[JournalEvent::Flush]);
    assert_eq!(probe.commits.get(), 0);
    clock.advance(Duration::from_millis(4999));
    apply(&mut writer, &probe, &[JournalEvent::Flush]);
    assert_eq!(probe.commits.get(), 0);
    clock.advance(Duration::from_millis(1));
    apply(&mut writer, &probe, &[JournalEvent::Flush]);
    assert_eq!(probe.commits.get(), 1);
    assert_eq!(stored(&backend), [position(0, TAG, 2), position(1, TAG, 1)]);
    // The cadence restarts at the persist.
    clock.advance(Duration::from_secs(4));
    apply(&mut writer, &probe, &[JournalEvent::Flush]);
    assert_eq!(probe.commits.get(), 1);
    // Unchanged positions are not sent, even when due or on a barrier.
    writer.persist(&probe).unwrap();
    assert_eq!(probe.commits.get(), 2);
    writer.persist(&probe).unwrap();
    clock.advance(Duration::from_secs(60));
    writer.persist(&probe).unwrap();
    assert_eq!(probe.commits.get(), 2);
    // A failed completion leaves nothing new to persist, even when due.
    let failed = writer.append(&probe, &[JournalEvent::Flush]).unwrap();
    writer.complete(&probe, failed, EIO).unwrap();
    assert_eq!(probe.commits.get(), 2);
}

#[test]
fn commit_error_fails_the_writer() {
    let backend = journal(24, 2, 8);
    let mut probe = Probe::new(&backend);
    let clock = FakeClock::default();
    let mut writer = writer(&probe, &clock);
    apply(&mut writer, &probe, &[JournalEvent::Flush]);
    probe.commit_err = Some(EBLOCKLISTED);
    assert_eq!(writer.persist(&probe), Err(EBLOCKLISTED));
    assert_eq!(writer.state(), WriterState::Failed(EBLOCKLISTED));
    probe.commit_err = None;
    assert_eq!(writer.close(&probe), Err(EBLOCKLISTED));
    assert!(stored(&backend).is_empty(), "a failed writer does no I/O");
}

/// Fill `sets` object sets with one Flush per entry (order 12, pad 4096:
/// one record per object), completing and persisting each request.
fn fill_sets(
    writer: &mut JournalWriter<FakeClock>,
    backend: &impl JournalBackend,
    width: u64,
    sets: u64,
) {
    for _ in 0..width * sets {
        apply(writer, backend, &[JournalEvent::Flush]);
    }
}

fn object_present(backend: &MemJournalBackend, object: u64) -> bool {
    backend.read_object(object, 0, &mut [0u8; 1]).is_ok()
}

#[test]
fn trim_follows_lagging_clients_up_to_the_active_set() {
    let backend = journal(12, 2, 4096);
    let clock = FakeClock::default();
    let mut writer = writer(&backend, &clock);
    // A lagging peer at set 1, a disconnected one at set 0 (ignored).
    backend
        .client_register(b"lagging", &encode_image_client_data(0, false))
        .unwrap();
    backend
        .client_register(b"zz-gone", &encode_image_client_data(0, false))
        .unwrap();
    backend
        .client_commit(b"lagging", &[position(2, TAG, 0)])
        .unwrap();
    backend
        .client_commit(b"zz-gone", &[position(0, TAG, 0)])
        .unwrap();
    backend
        .set_client_state(b"zz-gone", JOURNAL_CLIENT_STATE_DISCONNECTED)
        .unwrap();
    // Sets 0..=3 written; tid 7 sits in set 3.
    fill_sets(&mut writer, &backend, 2, 4);
    assert_eq!(writer.active_set(), 3);
    writer.persist(&backend).unwrap();
    // Needed = min(local set 3, lagging set 1) = 1.
    assert_eq!(writer.minimum_set(), 1);
    assert_eq!(backend.get_geometry().unwrap().minimum_set, 1);
    assert!(!object_present(&backend, 0) && !object_present(&backend, 1));
    assert!(object_present(&backend, 2) && object_present(&backend, 3));
    // The peer catches up beyond the active set's start: the target is
    // capped at the local client's set (3).
    backend
        .client_commit(b"lagging", &[position(7, TAG, 7)])
        .unwrap();
    writer.trim(&backend).unwrap();
    assert_eq!(writer.minimum_set(), 3);
    for object in 0..6 {
        assert!(!object_present(&backend, object), "object {object}");
    }
    assert_eq!(tids(&replay(&backend)), Vec::<u64>::new());
}

#[test]
fn trim_is_disabled_by_a_client_with_empty_positions() {
    let backend = journal(12, 1, 4096);
    let clock = FakeClock::default();
    let mut writer = writer(&backend, &clock);
    backend
        .client_register(b"fresh", &encode_image_client_data(0, false))
        .unwrap();
    fill_sets(&mut writer, &backend, 1, 3);
    writer.persist(&backend).unwrap();
    assert_eq!(writer.minimum_set(), 0);
    assert!(object_present(&backend, 0));
}

#[test]
fn trim_pages_client_list_and_tolerates_enoent_and_estale() {
    let backend = journal(12, 1, 4096);
    let clock = FakeClock::default();
    let mut writer = writer(&backend, &clock);
    // 300 caught-up peers, then one lagging peer on the second page.
    for peer in 0..300 {
        let id = format!("peer-{peer:03}");
        backend
            .client_register(id.as_bytes(), &encode_image_client_data(0, false))
            .unwrap();
        backend
            .client_commit(id.as_bytes(), &[position(9, TAG, 9)])
            .unwrap();
    }
    backend
        .client_register(b"zz-lag", &encode_image_client_data(0, false))
        .unwrap();
    backend
        .client_commit(b"zz-lag", &[position(2, TAG, 2)])
        .unwrap();
    fill_sets(&mut writer, &backend, 1, 6);
    // Object 1 already removed by someone else.
    backend.remove_object(1).unwrap();
    writer.persist(&backend).unwrap();
    assert_eq!(writer.minimum_set(), 2);
    // Someone else trimmed further meanwhile: set_minimum_set is -ESTALE.
    backend
        .client_commit(b"zz-lag", &[position(4, TAG, 4)])
        .unwrap();
    backend.set_minimum_set(5).unwrap();
    writer.trim(&backend).unwrap();
    assert_eq!(writer.minimum_set(), 4);
    assert_eq!(writer.state(), WriterState::Ready);
    assert_eq!(backend.get_geometry().unwrap().minimum_set, 5);
}

#[test]
fn trim_runs_to_the_active_set_when_every_client_is_disconnected() {
    let backend = journal(12, 1, 4096);
    let clock = FakeClock::default();
    let mut writer = writer(&backend, &clock);
    fill_sets(&mut writer, &backend, 1, 4);
    backend
        .set_client_state(b"", JOURNAL_CLIENT_STATE_DISCONNECTED)
        .unwrap();
    writer.persist(&backend).unwrap();
    assert_eq!(writer.minimum_set(), 3);
    assert_eq!(backend.get_geometry().unwrap().minimum_set, 3);
    assert!((0..3).all(|object| !object_present(&backend, object)));
    assert!(object_present(&backend, 3));
}

#[test]
fn trim_ignores_undecodable_client_data() {
    let backend = journal(12, 1, 4096);
    let clock = FakeClock::default();
    let mut writer = writer(&backend, &clock);
    // A client whose ClientData is no known variant (e.g. a CLI client):
    // only its cls fields count, its lag at set 1 bounds the trim.
    backend
        .client_register(b"cli", &[0xff, 0x00, 0x13, 0x37])
        .unwrap();
    backend
        .client_commit(b"cli", &[position(1, TAG, 1)])
        .unwrap();
    fill_sets(&mut writer, &backend, 1, 4);
    writer.persist(&backend).unwrap();
    assert_eq!(writer.minimum_set(), 1);
    assert_eq!(writer.state(), WriterState::Ready);
    assert!(!object_present(&backend, 0) && object_present(&backend, 1));
}

#[test]
fn padded_appends_crossing_the_soft_maximum_round_trip() {
    // Order 13 (8 KiB) with a 4096-byte class pad: the writer's unpadded
    // count lets the second record start at padded offset 4096 and end
    // past 8192; the player replays it.
    let backend = journal(13, 1, 4096);
    let probe = Probe::new(&backend);
    let clock = FakeClock::default();
    let mut writer = writer(&probe, &clock);
    let small = [3u8; 100];
    let big = [4u8; 5000];
    apply(&mut writer, &probe, &[write(0, &small)]);
    apply(&mut writer, &probe, &[write(8192, &big)]);
    assert_eq!(writer.active_set(), 0, "the unpadded count still fits");
    let mut buf = vec![0u8; 1 << 16];
    let size = backend.read_object(0, 0, &mut buf).unwrap();
    assert!(size > 1 << 13, "the second record crosses the soft maximum");
    // The next append finds the object full (-EOVERFLOW) and rolls over.
    apply(&mut writer, &probe, &[write(0, &small)]);
    assert_eq!(writer.active_set(), 1);
    let records = replay(&probe);
    assert_eq!(tids(&records), [0, 1, 2]);
    assert_eq!(
        records.iter().map(|r| r.object).collect::<Vec<_>>(),
        [0, 0, 1]
    );
    match decode_journal_event_entry(&records[1].data).unwrap().event {
        Some(JournalEvent::Write { offset, data, .. }) => {
            assert_eq!((offset, data), (8192, &big[..]));
        }
        other => panic!("unexpected event {other:?}"),
    }
}

#[test]
fn trim_errors_leave_ready_except_blocklisted() {
    let backend = journal(12, 1, 4096);
    let mut probe = Probe::new(&backend);
    let clock = FakeClock::default();
    let mut writer = writer(&probe, &clock);
    fill_sets(&mut writer, &probe, 1, 3);
    probe.remove_err = Some(EIO);
    writer.persist(&probe).unwrap();
    assert_eq!(writer.state(), WriterState::Ready);
    assert_eq!(writer.minimum_set(), 0);
    probe.remove_err = Some(EBLOCKLISTED);
    assert_eq!(writer.trim(&probe), Err(EBLOCKLISTED));
    assert_eq!(writer.state(), WriterState::Failed(EBLOCKLISTED));
}

#[test]
fn close_persists_the_completed_prefix() {
    let backend = journal(24, 2, 8);
    let clock = FakeClock::default();
    let mut writer = writer(&backend, &clock);
    apply(&mut writer, &backend, &[JournalEvent::Flush]);
    apply(&mut writer, &backend, &[write(0, b"abc")]);
    let open = writer.append(&backend, &[JournalEvent::Flush]).unwrap();
    assert_eq!(open.first_tid(), 2);
    writer.close(&backend).unwrap();
    assert_eq!(stored(&backend), [position(1, TAG, 1), position(0, TAG, 0)]);
    // The uncompleted entry replays on the next open; nothing was appended
    // by close.
    assert_eq!(tids(&replay(&backend)), [2]);
}

#[test]
fn stale_generation_ticket_is_einval_and_changes_nothing() {
    let first_backend = journal(24, 2, 8);
    let second_backend = journal(24, 2, 8);
    let clock = FakeClock::default();
    let mut first = writer(&first_backend, &clock);
    let stale = first
        .append(&first_backend, &[JournalEvent::Flush])
        .unwrap();
    first.close(&first_backend).unwrap();
    let mut second = writer(&second_backend, &clock);
    // The later generation reuses the same first TID.
    let own = second
        .append(&second_backend, &[JournalEvent::Flush])
        .unwrap();
    assert_eq!(stale.first_tid(), own.first_tid());
    assert_eq!(second.complete(&second_backend, stale, 0), Err(EINVAL));
    assert!(
        second.positions().is_empty(),
        "stale ticket changed nothing"
    );
    assert!(!second.commit_blocked());
    assert!(stored(&second_backend).is_empty());
    // The later writer's own ticket still completes normally.
    second.complete(&second_backend, own, 0).unwrap();
    assert_eq!(second.positions(), [position(0, TAG, 0)]);
}

#[test]
fn resumes_from_a_seal_and_rejects_inconsistent_seals() {
    let backend = journal(24, 2, 8);
    let clock = FakeClock::default();
    let mut first = writer(&backend, &clock);
    apply(&mut first, &backend, &[JournalEvent::Flush]);
    apply(&mut first, &backend, &[JournalEvent::Flush]);
    first.close(&backend).unwrap();
    let geometry = backend.get_geometry().unwrap();
    let mut player = JournalPlayer::new(&geometry, &stored(&backend), &[TAG]).unwrap();
    assert!(player.next(&mut MemView(&backend)).unwrap().is_none());
    let seal = player.seal();
    assert_eq!(seal.1, 2);
    let mut second = JournalWriter::new(
        &geometry,
        TAG,
        seal.clone(),
        config(Duration::from_secs(3600)),
        clock.clone(),
    )
    .unwrap();
    assert_eq!(second.persisted_positions(), seal.0.as_slice());
    apply(&mut second, &backend, &[JournalEvent::Flush]);
    second.close(&backend).unwrap();
    assert_eq!(stored(&backend), [position(0, TAG, 2), position(1, TAG, 1)]);
    // A seal of a newer tag, or a next TID not past it, is refused.
    let inconsistent = [
        (vec![position(0, TAG + 1, 0)], 1),
        (vec![position(0, TAG, 4)], 4),
    ];
    for sealed in inconsistent {
        assert_eq!(
            JournalWriter::new(
                &geometry,
                TAG,
                sealed,
                config(Duration::from_secs(1)),
                clock.clone(),
            )
            .err(),
            Some(EINVAL)
        );
    }
    let mut small = config(Duration::from_secs(1));
    small.max_payload_bytes = AIO_WRITE_EVENT_FIXED_SIZE;
    assert_eq!(
        JournalWriter::new(&geometry, TAG, (Vec::new(), 0), small, clock.clone()).err(),
        Some(EINVAL)
    );
}

/// splitmix64: deterministic test randomness.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

/// Positions per splay never move back in (tag, tid).
fn assert_no_regress(
    old: &[JournalObjectPosition],
    new: &[JournalObjectPosition],
    width: u64,
    seed: u64,
) {
    for before in old {
        let splay = before.object_number % width;
        let after = new
            .iter()
            .find(|p| p.object_number % width == splay)
            .unwrap_or_else(|| panic!("seed {seed}: splay {splay} position dropped"));
        assert!(
            (after.tag_tid, after.entry_tid) >= (before.tag_tid, before.entry_tid),
            "seed {seed}: splay {splay} regressed {before:?} -> {after:?}"
        );
    }
}

#[test]
fn random_completion_orders_never_regress_and_replay_the_uncommitted_suffix() {
    let payload = [0x5au8; 3000];
    for seed in 0..300u64 {
        let mut rng = Rng(seed);
        let width = 1 + rng.below(4) as u8;
        let min_alloc = if rng.below(2) == 0 { 8 } else { 4096 };
        let backend = journal(12, width, min_alloc);
        let clock = FakeClock::default();
        let geometry = backend.get_geometry().unwrap();
        let mut writer = JournalWriter::new(
            &geometry,
            TAG,
            (Vec::new(), 0),
            config(Duration::from_secs(5)),
            clock.clone(),
        )
        .unwrap();
        let mut outstanding: Vec<Ticket> = Vec::new();
        let mut last_stored = Vec::new();
        for _ in 0..40 {
            match rng.below(5) {
                0 | 1 => {
                    let count = 1 + rng.below(4) as usize;
                    let events: Vec<JournalEvent<'_>> = (0..count)
                        .map(|i| {
                            let len = rng.below(payload.len() as u64) as usize;
                            if len.is_multiple_of(3) {
                                JournalEvent::Flush
                            } else {
                                write(i as u64 * 4096, &payload[..len])
                            }
                        })
                        .collect();
                    outstanding.push(writer.append(&backend, &events).unwrap());
                }
                2 | 3 if !outstanding.is_empty() => {
                    let index = rng.below(outstanding.len() as u64) as usize;
                    let ticket = outstanding.swap_remove(index);
                    writer.complete(&backend, ticket, 0).unwrap();
                }
                2 | 3 => clock.advance(Duration::from_secs(2)),
                _ => writer.persist(&backend).unwrap(),
            }
            let now = stored(&backend);
            assert_no_regress(&last_stored, &now, u64::from(width), seed);
            last_stored = now;
        }
        writer.persist(&backend).unwrap();
        let now = stored(&backend);
        assert_no_regress(&last_stored, &now, u64::from(width), seed);
        let committed_end = outstanding
            .iter()
            .map(Ticket::first_tid)
            .min()
            .unwrap_or(writer.next_tid());
        if let Some(newest) = now.first() {
            assert_eq!(newest.entry_tid + 1, committed_end, "seed {seed}");
        } else {
            assert_eq!(committed_end, 0, "seed {seed}");
        }
        let expected: Vec<u64> = (committed_end..writer.next_tid()).collect();
        assert_eq!(tids(&replay(&backend)), expected, "seed {seed}");
        assert_eq!(writer.state(), WriterState::Ready);
    }
}
