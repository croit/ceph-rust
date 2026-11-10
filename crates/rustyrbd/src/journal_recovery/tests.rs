// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Journal recovery tests and the crash matrix (journaling S5) over
//! `MemJournalBackend` + `MemImage` with `FaultPlan::crash_after(k)`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;
use crate::journal_backend::{EIO, EOPNOTSUPP};
use crate::journal_mem::{CRASH_ERRNO, FaultPlan, MemImage, MemJournalBackend, MemJournalStore};
use crate::{
    JOURNAL_TAG_CLASS_NEW, JournalObjectPosition, JournalTagPredecessor, SnapshotNamespace,
    encode_image_client_data, encode_journal_record, encode_tag_data,
};

const IMAGE_SIZE: u64 = 64 * 1024;

/// Fixed clock: the commit cadence is decided by `commit_age` alone
/// (zero = persist after every completion, an hour = never).
#[derive(Clone, Copy, Debug)]
struct FixedClock;

impl JournalClock for FixedClock {
    fn monotonic(&self) -> Duration {
        Duration::ZERO
    }

    fn timestamp(&self) -> (u32, u32) {
        (1, 2)
    }
}

fn local_tag_data() -> Vec<u8> {
    tag_data(b"")
}

fn tag_data(owner: &[u8]) -> Vec<u8> {
    encode_tag_data(
        owner,
        &JournalTagPredecessor {
            mirror_uuid: Vec::new(),
            commit_valid: false,
            tag_tid: 0,
            entry_tid: 0,
        },
    )
    .unwrap()
}

/// A fresh journal: header, tag 0 of a new class (owner local), and the
/// local image client of that class.
fn fresh_backend(order: u8, width: u8, min_alloc: u64) -> MemJournalBackend {
    let backend = MemJournalBackend::new().with_min_alloc_size(min_alloc);
    backend.create(order, width, -1).unwrap();
    backend
        .tag_create(0, JOURNAL_TAG_CLASS_NEW, &local_tag_data())
        .unwrap();
    backend
        .client_register(b"", &encode_image_client_data(0, false))
        .unwrap();
    backend
}

fn config(commit_age: Duration, max_payload_bytes: u64) -> JournalWriterConfig {
    JournalWriterConfig {
        commit_age,
        max_payload_bytes,
        image_id: "s5".into(),
    }
}

fn stored_positions(backend: &impl JournalBackend) -> Vec<JournalObjectPosition> {
    decode_journal_image_client(&backend.get_client(b"").unwrap())
        .unwrap()
        .commit_positions
}

fn pattern(seed: u64, len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| (seed.wrapping_mul(31) as usize + index * 7 + 1) as u8 | 1)
        .collect()
}

fn errno(result: Result<(), i32>) -> i32 {
    result.err().unwrap_or(0)
}

/// One image request of a scenario.
#[derive(Clone, Debug)]
enum Req {
    Write {
        offset: u64,
        data: Vec<u8>,
    },
    Discard {
        offset: u64,
        length: u64,
        granularity: u32,
    },
    WriteZeroes {
        offset: u64,
        length: u64,
    },
    WriteSame {
        offset: u64,
        length: u64,
        pattern: Vec<u8>,
    },
    Caw {
        offset: u64,
        compare: Vec<u8>,
        data: Vec<u8>,
    },
    Flush,
    SnapCreate(Vec<u8>),
    SnapRemove(Vec<u8>),
    MetaSet(Vec<u8>, Vec<u8>),
    MetaRemove(Vec<u8>),
    Resize(u64),
}

impl Req {
    fn is_op(&self) -> bool {
        matches!(
            self,
            Req::SnapCreate(_)
                | Req::SnapRemove(_)
                | Req::MetaSet(..)
                | Req::MetaRemove(_)
                | Req::Resize(_)
        )
    }
}

fn op_event(req: &Req, operation_id: u64) -> JournalEvent<'_> {
    match req {
        Req::SnapCreate(name) => JournalEvent::Snapshot {
            kind: JournalEventKind::Create,
            operation_id,
            name,
            namespace: SnapshotNamespace::User,
        },
        Req::SnapRemove(name) => JournalEvent::Snapshot {
            kind: JournalEventKind::Remove,
            operation_id,
            name,
            namespace: SnapshotNamespace::User,
        },
        Req::MetaSet(key, value) => JournalEvent::MetadataSet {
            operation_id,
            key,
            value,
        },
        Req::MetaRemove(key) => JournalEvent::MetadataRemove { operation_id, key },
        Req::Resize(size) => JournalEvent::Resize {
            operation_id,
            size: *size,
        },
        _ => unreachable!("not an operation request"),
    }
}

/// The request's live effect on the image (the data dispatch, or the
/// operation); returns 0 or the negative errno. Writes go out in 4 KiB
/// pieces so a crash can leave a partially written request.
fn apply_live(image: &mut MemImage, req: &Req) -> i32 {
    match req {
        Req::Write { offset, data } => {
            for (index, piece) in data.chunks(4096).enumerate() {
                if let Err(errno) = image.write(offset + index as u64 * 4096, piece) {
                    return errno;
                }
            }
            0
        }
        Req::Discard { offset, length, .. } | Req::WriteZeroes { offset, length } => {
            errno(image.discard(*offset, *length))
        }
        Req::WriteSame {
            offset,
            length,
            pattern,
        } => errno(image.write_same(*offset, *length, pattern)),
        Req::Caw {
            offset,
            compare,
            data,
        } => errno(image.compare_and_write(*offset, compare.len() as u64, compare, data)),
        Req::Flush => errno(image.flush()),
        op => errno(image.apply_op(&op_event(op, 0))),
    }
}

fn data_events<'a>(writer: &JournalWriter<FixedClock>, req: &'a Req) -> Vec<JournalEvent<'a>> {
    match req {
        Req::Write { offset, data } => write_events(writer, *offset, data),
        Req::Discard {
            offset,
            length,
            granularity,
        } => vec![JournalEvent::Discard {
            offset: *offset,
            length: *length,
            skip_partial: *granularity > 0,
            discard_granularity: *granularity,
        }],
        Req::WriteZeroes { offset, length } => vec![JournalEvent::Discard {
            offset: *offset,
            length: *length,
            skip_partial: false,
            discard_granularity: 0,
        }],
        Req::WriteSame {
            offset,
            length,
            pattern,
        } => vec![JournalEvent::WriteSame {
            offset: *offset,
            length: *length,
            pattern,
        }],
        Req::Caw {
            offset,
            compare,
            data,
        } => vec![JournalEvent::CompareAndWrite {
            offset: *offset,
            length: compare.len() as u64,
            compare,
            replacement: data,
        }],
        Req::Flush => vec![JournalEvent::Flush],
        _ => unreachable!("operation requests are journaled by journaled_op"),
    }
}

fn run_request(
    writer: &mut JournalWriter<FixedClock>,
    backend: &MemJournalBackend,
    image: &mut MemImage,
    req: &Req,
) -> Result<i32, i32> {
    if req.is_op() {
        journaled_op(
            writer,
            backend,
            |id| op_event(req, id),
            |event| errno(image.apply_op(event)),
        )
    } else {
        let events = data_events(writer, req);
        journaled_mutation(writer, backend, &events, || apply_live(image, req))
    }
}

/// One crash-matrix scenario.
#[derive(Clone, Debug)]
struct Scenario {
    name: &'static str,
    order: u8,
    width: u8,
    min_alloc: u64,
    max_payload: u64,
    commit_age: Duration,
    requests: Vec<Req>,
}

impl Scenario {
    fn config(&self) -> JournalWriterConfig {
        config(self.commit_age, self.max_payload)
    }
}

/// Durable state between process instances.
struct World {
    store: MemJournalStore,
    image: MemImage,
}

impl World {
    fn fresh(sc: &Scenario) -> Self {
        let backend = fresh_backend(sc.order, sc.width, sc.min_alloc);
        Self {
            store: backend.store().lock().unwrap().clone(),
            image: MemImage::new(IMAGE_SIZE),
        }
    }

    /// One process instance over a copy of this durable state.
    fn instance(&self, sc: &Scenario, plan: &Arc<FaultPlan>) -> (MemJournalBackend, MemImage) {
        let backend =
            MemJournalBackend::from_store(&Arc::new(Mutex::new(self.store.clone())), plan)
                .with_min_alloc_size(sc.min_alloc);
        (backend, self.image.reopen(plan))
    }

    /// The durable state an instance leaves behind (crash = drop).
    fn capture(backend: &MemJournalBackend, image: &MemImage) -> Self {
        Self {
            store: backend.store().lock().unwrap().clone(),
            image: image.reopen(&Arc::new(FaultPlan::none())),
        }
    }
}

/// Run the scenario's requests until the first unacknowledged one;
/// returns the durable state and the acknowledged count.
fn live(sc: &Scenario, world: &World, plan: &Arc<FaultPlan>) -> (World, usize) {
    let (mut backend, mut image) = world.instance(sc, plan);
    let mut writer = recover(&mut backend, &mut image, sc.config(), FixedClock)
        .expect("a fresh journal opens without mutations");
    let mut acked = 0;
    for req in &sc.requests {
        match run_request(&mut writer, &backend, &mut image, req) {
            Ok(result) if result != CRASH_ERRNO => acked += 1,
            _ => break,
        }
    }
    (World::capture(&backend, &image), acked)
}

/// Recover one instance; returns the durable state afterwards (also on
/// failure) and the result.
fn recover_world(
    sc: &Scenario,
    world: &World,
    plan: &Arc<FaultPlan>,
) -> (World, Result<JournalWriter<FixedClock>, RecoveryError>) {
    let (mut backend, mut image) = world.instance(sc, plan);
    let result = recover(&mut backend, &mut image, sc.config(), FixedClock);
    (World::capture(&backend, &image), result)
}

fn state_eq(a: &MemImage, b: &MemImage) -> bool {
    a.size() == b.size()
        && a.read(0, a.size()) == b.read(0, b.size())
        && a.snapshots() == b.snapshots()
        && a.metadata() == b.metadata()
}

/// The expected-state rule: every acked request applied in order; the
/// in-flight request absent or applied (whole or byte-wise partial, never
/// another request's bytes); nothing later.
fn check_expected(label: &str, image: &MemImage, before: &MemImage, after: Option<&MemImage>) {
    if state_eq(image, before) || after.is_some_and(|after| state_eq(image, after)) {
        return;
    }
    let after = after.unwrap_or_else(|| panic!("{label}: state differs, nothing in flight"));
    assert!(
        image.size() == before.size() && image.size() == after.size(),
        "{label}: size {} not {} / {}",
        image.size(),
        before.size(),
        after.size()
    );
    assert!(
        image.snapshots() == before.snapshots() || image.snapshots() == after.snapshots(),
        "{label}: snapshots"
    );
    assert!(
        image.metadata() == before.metadata() || image.metadata() == after.metadata(),
        "{label}: metadata"
    );
    let (bytes, old, new) = (
        image.read(0, image.size()),
        before.read(0, before.size()),
        after.read(0, after.size()),
    );
    for index in 0..bytes.len() {
        assert!(
            bytes[index] == old[index] || bytes[index] == new[index],
            "{label}: byte {index} = {} is neither {} nor {}",
            bytes[index],
            old[index],
            new[index]
        );
    }
}

/// Cells of one scenario run: crash points and recovery crash points.
#[derive(Default, Debug, Clone, Copy)]
struct Cells {
    crash_points: u64,
    recovery_crash_points: u64,
}

fn run_matrix(sc: &Scenario) -> Cells {
    let fresh = World::fresh(sc);
    // Models: the image after the first i requests, without a journal.
    let mut models = vec![fresh.image.reopen(&Arc::new(FaultPlan::none()))];
    for req in &sc.requests {
        let mut next = models.last().unwrap().reopen(&Arc::new(FaultPlan::none()));
        apply_live(&mut next, req);
        models.push(next);
    }
    let count = Arc::new(FaultPlan::none());
    let (_, acked) = live(sc, &fresh, &count);
    assert_eq!(acked, sc.requests.len(), "{}: uncrashed run", sc.name);
    let total = count.mutations();
    let mut cells = Cells::default();
    for k in 0..=total {
        let label = format!("{} age={:?} k={k}", sc.name, sc.commit_age);
        let (crashed, acked) = live(sc, &fresh, &Arc::new(FaultPlan::crash_after(k)));
        let before = &models[acked];
        let after = models.get(acked + 1);
        cells.crash_points += 1;

        // Recover; the expected state holds.
        let none = Arc::new(FaultPlan::none());
        let (recovered, writer) = recover_world(sc, &crashed, &none);
        let writer = writer.unwrap_or_else(|error| panic!("{label}: {error}"));
        let recovery_mutations = none.mutations();
        check_expected(&label, &recovered.image, before, after);

        // C10: a crash inside recovery, then a clean recovery.
        for j in 0..recovery_mutations {
            let label = format!("{label} j={j}");
            let (partial, result) =
                recover_world(sc, &crashed, &Arc::new(FaultPlan::crash_after(j)));
            let error = result.err().unwrap_or_else(|| panic!("{label}: no crash"));
            assert_eq!(error.errno, CRASH_ERRNO, "{label}");
            let (again, result) = recover_world(sc, &partial, &Arc::new(FaultPlan::none()));
            let again_writer = result.unwrap_or_else(|error| panic!("{label}: {error}"));
            assert_eq!(again_writer.next_tid(), writer.next_tid(), "{label}");
            check_expected(&label, &again.image, before, after);
            cells.recovery_crash_points += 1;
        }

        // Idempotent: a second recovery replays and persists nothing.
        let (again, result) = recover_world(sc, &recovered, &Arc::new(FaultPlan::crash_after(0)));
        let again_writer =
            result.unwrap_or_else(|error| panic!("{label}: second recovery mutated: {error}"));
        assert!(state_eq(&again.image, &recovered.image), "{label}");
        assert_eq!(again_writer.next_tid(), writer.next_tid(), "{label}");
        assert_eq!(again_writer.tag_tid(), writer.tag_tid(), "{label}");

        // TID continuity: append after recovery, crash, recover once more.
        let (mut backend, mut image) = recovered.instance(sc, &none);
        let mut writer = recover(&mut backend, &mut image, sc.config(), FixedClock).unwrap();
        let first = writer.next_tid();
        let post = Req::Write {
            offset: 100,
            data: pattern(0xabc, 300),
        };
        assert_eq!(
            run_request(&mut writer, &backend, &mut image, &post),
            Ok(0),
            "{label}"
        );
        let next = writer.next_tid();
        assert_eq!(next, first + 1, "{label}");
        drop(writer);
        let (last, result) = recover_world(sc, &World::capture(&backend, &image), &none);
        let last_writer = result.unwrap_or_else(|error| panic!("{label}: post append: {error}"));
        assert_eq!(last_writer.next_tid(), next, "{label}");
        assert_eq!(last.image.read(100, 300), pattern(0xabc, 300), "{label}");
    }
    cells
}

/// Deterministic generator for the mixed sequence.
struct Lcg(u64);

impl Lcg {
    fn below(&mut self, bound: u64) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 33) % bound
    }
}

/// 50 mixed requests: writes (some split), discards, write_zeroes,
/// writesame, matching and mismatching compare-and-writes, flushes and
/// operations (snapshots, metadata, resize). Data stays below
/// `IMAGE_SIZE`; resizes stay at or above it.
fn mixed_requests(seed: u64) -> Vec<Req> {
    let mut rng = Lcg(seed);
    let mut model = MemImage::new(IMAGE_SIZE);
    let mut requests = Vec::new();
    for index in 0..50u64 {
        let req = match rng.below(12) {
            0..=3 | 11 => {
                let length = 1 + rng.below(9000);
                Req::Write {
                    offset: rng.below(IMAGE_SIZE - length),
                    data: pattern(index, length as usize),
                }
            }
            4 => {
                let length = 1 + rng.below(8192);
                Req::Discard {
                    offset: rng.below(IMAGE_SIZE - length),
                    length,
                    granularity: [0, 512][rng.below(2) as usize],
                }
            }
            5 => {
                let length = 1 + rng.below(8192);
                Req::WriteZeroes {
                    offset: rng.below(IMAGE_SIZE - length),
                    length,
                }
            }
            6 => {
                let length = 1 + rng.below(8192);
                Req::WriteSame {
                    offset: rng.below(IMAGE_SIZE - length),
                    length,
                    pattern: pattern(index, 1 + rng.below(16) as usize),
                }
            }
            7 | 8 => {
                let length = 1 + rng.below(512);
                let offset = rng.below(IMAGE_SIZE - length);
                let mut compare = model.read(offset, length);
                if rng.below(2) == 0 {
                    compare[0] ^= 0xff;
                }
                Req::Caw {
                    offset,
                    compare,
                    data: pattern(index, length as usize),
                }
            }
            9 => Req::Flush,
            _ => match index % 5 {
                0 => Req::SnapCreate(format!("snap{}", index % 3).into_bytes()),
                1 => Req::SnapRemove(format!("snap{}", index % 3).into_bytes()),
                2 => Req::MetaSet(format!("key{}", index % 2).into_bytes(), pattern(index, 9)),
                3 => Req::MetaRemove(format!("key{}", index % 2).into_bytes()),
                _ => Req::Resize(IMAGE_SIZE + 4096 * rng.below(3)),
            },
        };
        apply_live(&mut model, &req);
        requests.push(req);
    }
    requests
}

fn scenarios() -> Vec<Scenario> {
    let base = Scenario {
        name: "",
        order: 14,
        width: 4,
        min_alloc: 8,
        max_payload: 16384,
        commit_age: Duration::ZERO,
        requests: Vec::new(),
    };
    let x = pattern(1, 512);
    let mut list = vec![
        Scenario {
            name: "small write",
            requests: vec![
                Req::Write {
                    offset: 0,
                    data: pattern(2, 512),
                },
                Req::Write {
                    offset: 256,
                    data: pattern(3, 512),
                },
            ],
            ..base.clone()
        },
        Scenario {
            // 1024-byte payloads: 8 events, two per splay (non-prefix
            // subsets on a crash between splay batches).
            name: "4-splay split write",
            max_payload: 1024,
            requests: vec![Req::Write {
                offset: 1000,
                data: pattern(4, 8 * 980),
            }],
            ..base.clone()
        },
        Scenario {
            // 4 KiB objects with 4 KiB padding: every append rolls over.
            name: "rollover-crossing write",
            order: 12,
            width: 2,
            min_alloc: 4096,
            requests: vec![
                Req::Write {
                    offset: 0,
                    data: pattern(5, 100),
                },
                Req::Write {
                    offset: 50,
                    data: pattern(6, 12000),
                },
            ],
            ..base.clone()
        },
        Scenario {
            name: "discard",
            requests: vec![
                Req::Write {
                    offset: 0,
                    data: pattern(7, 8192),
                },
                Req::Discard {
                    offset: 1024,
                    length: 4096,
                    granularity: 512,
                },
            ],
            ..base.clone()
        },
        Scenario {
            name: "write_zeroes",
            requests: vec![
                Req::Write {
                    offset: 0,
                    data: pattern(8, 8192),
                },
                Req::WriteZeroes {
                    offset: 100,
                    length: 5000,
                },
            ],
            ..base.clone()
        },
        Scenario {
            name: "writesame",
            requests: vec![
                Req::WriteSame {
                    offset: 0,
                    length: 8192,
                    pattern: pattern(9, 7),
                },
                Req::Write {
                    offset: 4000,
                    data: pattern(10, 300),
                },
            ],
            ..base.clone()
        },
        Scenario {
            name: "CAW match",
            requests: vec![
                Req::Write {
                    offset: 4096,
                    data: x.clone(),
                },
                Req::Caw {
                    offset: 4096,
                    compare: x.clone(),
                    data: pattern(11, 512),
                },
                Req::Write {
                    offset: 4096 + 256,
                    data: pattern(12, 512),
                },
            ],
            ..base.clone()
        },
        Scenario {
            name: "CAW mismatch",
            requests: vec![
                Req::Write {
                    offset: 0,
                    data: x.clone(),
                },
                // The region is zero: [P, 0] mismatches.
                Req::Caw {
                    offset: 4096,
                    compare: [pattern(13, 256), vec![0; 256]].concat(),
                    data: pattern(14, 512),
                },
                // Makes the region equal the compare buffer: a CAW
                // replayed against this later state would match and leave
                // its replacement in the second half (C11 barrier).
                Req::Write {
                    offset: 4096,
                    data: pattern(13, 256),
                },
                Req::Write {
                    offset: 0,
                    data: pattern(15, 300),
                },
            ],
            ..base.clone()
        },
        Scenario {
            // A CAW event larger than the maximum append size: split into
            // sub-range records that each fit the object.
            name: "CAW over max append",
            order: 12,
            width: 2,
            max_payload: 1024,
            requests: vec![
                Req::Write {
                    offset: 0,
                    data: pattern(20, 3000),
                },
                Req::Caw {
                    offset: 0,
                    compare: pattern(20, 3000),
                    data: pattern(21, 3000),
                },
                Req::Write {
                    offset: 1000,
                    data: pattern(22, 200),
                },
            ],
            ..base.clone()
        },
        Scenario {
            name: "flush",
            requests: vec![
                Req::Write {
                    offset: 0,
                    data: pattern(15, 700),
                },
                Req::Flush,
                Req::Write {
                    offset: 600,
                    data: pattern(16, 700),
                },
            ],
            ..base.clone()
        },
        Scenario {
            name: "op start/finish",
            requests: vec![
                Req::SnapCreate(b"a".to_vec()),
                Req::MetaSet(b"k".to_vec(), b"v".to_vec()),
                Req::Write {
                    offset: 0,
                    data: pattern(17, 600),
                },
                Req::Resize(IMAGE_SIZE + 8192),
                // Fails live with -EEXIST: the finish records it, replay
                // skips it.
                Req::SnapCreate(b"a".to_vec()),
                Req::MetaRemove(b"k".to_vec()),
                Req::SnapRemove(b"a".to_vec()),
            ],
            ..base.clone()
        },
        Scenario {
            name: "mixed 50",
            order: 16,
            width: 4,
            min_alloc: 4096,
            max_payload: 4096,
            requests: mixed_requests(0x5eed),
            ..base
        },
    ];
    // Every scenario under both commit cadences: persist after every
    // completion (C6/C7, trims) and never (long uncommitted suffixes).
    let lazy: Vec<Scenario> = list
        .iter()
        .map(|sc| Scenario {
            commit_age: Duration::from_secs(3600),
            ..sc.clone()
        })
        .collect();
    list.extend(lazy);
    list
}

#[test]
fn crash_matrix() {
    let scenarios = scenarios();
    let results: Vec<(String, Cells)> = std::thread::scope(|scope| {
        let handles: Vec<_> = scenarios
            .iter()
            .map(|sc| {
                scope.spawn(move || {
                    (
                        format!("{} age={:?}", sc.name, sc.commit_age),
                        run_matrix(sc),
                    )
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut total = Cells::default();
    for (name, cells) in &results {
        println!(
            "journal crash matrix: {name}: crash_points={} recovery_crash_points={}",
            cells.crash_points, cells.recovery_crash_points
        );
        total.crash_points += cells.crash_points;
        total.recovery_crash_points += cells.recovery_crash_points;
    }
    println!(
        "journal crash matrix size: scenarios={} crash_points={} recovery_crash_points={} cells={}",
        results.len(),
        total.crash_points,
        total.recovery_crash_points,
        total.crash_points + total.recovery_crash_points
    );
    assert!(total.crash_points > 0);
}

// --- targeted recovery rules ---

fn open(backend: &mut MemJournalBackend, image: &mut MemImage) -> JournalWriter<FixedClock> {
    recover(
        backend,
        image,
        config(Duration::from_secs(3600), 16384),
        FixedClock,
    )
    .unwrap()
}

fn recover_err(backend: &mut MemJournalBackend, image: &mut MemImage) -> RecoveryError {
    recover(
        backend,
        image,
        config(Duration::from_secs(3600), 16384),
        FixedClock,
    )
    .expect_err("recovery fails")
}

#[test]
fn non_local_tag_owner_is_eperm() {
    let mut backend = MemJournalBackend::new();
    backend.create(14, 2, -1).unwrap();
    backend
        .tag_create(0, JOURNAL_TAG_CLASS_NEW, &tag_data(b"remote-uuid"))
        .unwrap();
    backend
        .client_register(b"", &encode_image_client_data(0, false))
        .unwrap();
    let error = recover_err(&mut backend, &mut MemImage::new(4096));
    assert_eq!(
        error,
        RecoveryError {
            stage: RecoveryStage::Tags,
            errno: EPERM
        }
    );
}

#[test]
fn missing_client_and_tags_fail() {
    let mut backend = MemJournalBackend::new();
    backend.create(14, 2, -1).unwrap();
    let error = recover_err(&mut backend, &mut MemImage::new(4096));
    assert_eq!((error.stage, error.errno), (RecoveryStage::Client, ENOENT));
    backend
        .client_register(b"", &encode_image_client_data(0, false))
        .unwrap();
    let error = recover_err(&mut backend, &mut MemImage::new(4096));
    assert_eq!((error.stage, error.errno), (RecoveryStage::Tags, ENOENT));
    let mut absent = MemJournalBackend::new();
    let error = recover_err(&mut absent, &mut MemImage::new(4096));
    assert_eq!(
        (error.stage, error.errno),
        (RecoveryStage::Geometry, ENOENT)
    );
}

#[test]
fn unsupported_op_fails_recovery_without_seal() {
    let mut backend = fresh_backend(14, 2, 8);
    let mut image = MemImage::new(4096);
    let mut writer = open(&mut backend, &mut image);
    let _start = writer
        .append(&backend, &[JournalEvent::Flatten { operation_id: 0 }])
        .unwrap();
    let _finish = writer
        .append(
            &backend,
            &[JournalEvent::OpFinish {
                operation_id: 0,
                repeated_operation_id: 0,
                result: 0,
            }],
        )
        .unwrap();
    drop(writer);
    let error = recover_err(&mut backend, &mut image);
    assert_eq!(
        (error.stage, error.errno),
        (RecoveryStage::Apply, EOPNOTSUPP)
    );
    assert!(stored_positions(&backend).is_empty());
}

#[test]
fn op_pairing_rules() {
    let mut backend = fresh_backend(14, 2, 8);
    let mut image = MemImage::new(4096);
    let mut writer = open(&mut backend, &mut image);
    let append = |writer: &mut JournalWriter<FixedClock>, event: JournalEvent<'_>| {
        let _ticket = writer.append(&backend, &[event]).unwrap();
    };
    // Failed operation: start + finish(-EIO) -> skipped.
    append(
        &mut writer,
        JournalEvent::Snapshot {
            kind: JournalEventKind::Create,
            operation_id: 0,
            name: b"failed",
            namespace: SnapshotNamespace::User,
        },
    );
    append(
        &mut writer,
        JournalEvent::OpFinish {
            operation_id: 0,
            repeated_operation_id: 0,
            result: EIO,
        },
    );
    // Finish without start -> skipped.
    append(
        &mut writer,
        JournalEvent::OpFinish {
            operation_id: 77,
            repeated_operation_id: 77,
            result: 0,
        },
    );
    // Successful pair whose effect is already present -> idempotent.
    image
        .apply_op(&JournalEvent::MetadataSet {
            operation_id: 0,
            key: b"present",
            value: b"1",
        })
        .unwrap();
    append(
        &mut writer,
        JournalEvent::MetadataRemove {
            operation_id: 3,
            key: b"absent",
        },
    );
    append(
        &mut writer,
        JournalEvent::OpFinish {
            operation_id: 3,
            repeated_operation_id: 3,
            result: 0,
        },
    );
    // Start without finish -> re-executed at the end (SPEC-CHECK 2).
    append(
        &mut writer,
        JournalEvent::MetadataSet {
            operation_id: 5,
            key: b"k",
            value: b"v",
        },
    );
    // A DATA event after the pending start still replays in order.
    append(
        &mut writer,
        JournalEvent::Write {
            offset: 0,
            length: 3,
            data: b"abc",
        },
    );
    drop(writer);
    let writer = open(&mut backend, &mut image);
    assert!(image.snapshots().is_empty());
    assert_eq!(
        image.metadata().get(&b"k"[..]).map(Vec::as_slice),
        Some(&b"v"[..])
    );
    assert_eq!(image.read(0, 3), b"abc");
    assert_eq!(writer.next_tid(), 7);
    assert_eq!(stored_positions(&backend)[0].entry_tid, 6);
    // Nothing left to replay: a crash plan of zero mutations passes.
    let plan = Arc::new(FaultPlan::crash_after(0));
    let mut backend = MemJournalBackend::from_store(backend.store(), &plan);
    let mut image = image.reopen(&plan);
    open(&mut backend, &mut image);
}

#[test]
fn malformed_event_entry_is_ebadmsg() {
    let mut backend = fresh_backend(14, 2, 8);
    let mut record = Vec::new();
    encode_journal_record(0, 0, &[1, 2, 3], &mut record).unwrap();
    backend.append(0, 1 << 14, &record).unwrap();
    let error = recover_err(&mut backend, &mut MemImage::new(4096));
    assert_eq!((error.stage, error.errno), (RecoveryStage::Decode, EBADMSG));
    assert!(stored_positions(&backend).is_empty());
}

#[test]
fn newer_current_tag_starts_at_tid_zero() {
    let mut backend = fresh_backend(14, 2, 8);
    let mut image = MemImage::new(4096);
    let mut writer = open(&mut backend, &mut image);
    let a = Req::Write {
        offset: 0,
        data: pattern(1, 100),
    };
    let b = Req::Write {
        offset: 100,
        data: pattern(2, 100),
    };
    assert_eq!(run_request(&mut writer, &backend, &mut image, &a), Ok(0));
    writer.persist(&backend).unwrap();
    // B is acked but not persisted; its data never reaches the image here.
    let events = data_events(&writer, &b);
    assert_eq!(
        journaled_mutation(&mut writer, &backend, &events, || 0),
        Ok(0)
    );
    drop(writer);
    backend.tag_create(1, 0, &local_tag_data()).unwrap();
    let mut writer = open(&mut backend, &mut image);
    assert_eq!(image.read(100, 100), pattern(2, 100));
    assert_eq!((writer.tag_tid(), writer.next_tid()), (1, 0));
    let c = Req::Write {
        offset: 200,
        data: pattern(3, 100),
    };
    let events = data_events(&writer, &c);
    assert_eq!(
        journaled_mutation(&mut writer, &backend, &events, || 0),
        Ok(0)
    );
    drop(writer);
    let writer = open(&mut backend, &mut image);
    assert_eq!(image.read(200, 100), pattern(3, 100));
    assert_eq!((writer.tag_tid(), writer.next_tid()), (1, 1));
}

#[test]
fn caw_is_a_barrier_on_both_sides() {
    let mut backend = fresh_backend(14, 2, 8);
    let mut image = MemImage::new(4096);
    let mut writer = open(&mut backend, &mut image);
    let write = Req::Write {
        offset: 0,
        data: pattern(1, 64),
    };
    assert_eq!(
        run_request(&mut writer, &backend, &mut image, &write),
        Ok(0)
    );
    assert!(stored_positions(&backend).is_empty(), "lazy cadence");
    let caw = Req::Caw {
        offset: 0,
        compare: pattern(9, 64),
        data: pattern(2, 64),
    };
    assert_eq!(
        run_request(&mut writer, &backend, &mut image, &caw),
        Ok(EILSEQ)
    );
    let stored = stored_positions(&backend);
    assert_eq!(
        stored.iter().map(|p| p.entry_tid).collect::<Vec<_>>(),
        vec![1, 0]
    );
}

#[test]
fn journaled_op_rejects_a_mismatched_operation_id() {
    let mut backend = fresh_backend(14, 2, 8);
    let mut image = MemImage::new(4096);
    let mut writer = open(&mut backend, &mut image);
    let result = journaled_op(
        &mut writer,
        &backend,
        |id| JournalEvent::Resize {
            operation_id: id + 1,
            size: 0,
        },
        |_| 0,
    );
    assert_eq!(result, Err(EINVAL));
    assert_eq!(writer.next_tid(), 0);
}

#[test]
fn write_events_bound_event_payloads() {
    let mut backend = fresh_backend(12, 2, 8);
    let mut image = MemImage::new(4096);
    let writer = recover(
        &mut backend,
        &mut image,
        config(Duration::ZERO, 1024),
        FixedClock,
    )
    .unwrap();
    let data = pattern(1, 2500);
    let events = write_events(&writer, 10, &data);
    assert_eq!(events.len(), 3);
    assert_eq!(
        events[2],
        JournalEvent::Write {
            offset: 10 + 2 * 980,
            length: 540,
            data: &data[1960..],
        }
    );
}

#[test]
fn caw_larger_than_max_append_splits_and_replays_in_order() {
    // 4 KiB objects, 1 KiB maximum append: a 3000-byte CAW becomes 7
    // sub-range entries of at most (1024 - 60) / 2 = 482 bytes each.
    let mut backend = fresh_backend(12, 2, 8);
    let mut image = MemImage::new(8192);
    let mut writer = recover(
        &mut backend,
        &mut image,
        config(Duration::from_secs(3600), 1024),
        FixedClock,
    )
    .unwrap();
    let chunk = writer.compare_and_write_chunk_len() as usize;
    assert_eq!(chunk, 482);
    assert!(writer.max_append_size() < 3000);
    let zeros = vec![0u8; 3000];
    let data = pattern(1, 3000);
    fn caw<'a>(compare: &'a [u8], replacement: &'a [u8]) -> JournalEvent<'a> {
        JournalEvent::CompareAndWrite {
            offset: 100,
            length: 3000,
            compare,
            replacement,
        }
    }
    // Appended, crash before the data write: replay applies every sub-range
    // in order.
    let _ticket = writer.append(&backend, &[caw(&zeros, &data)]).unwrap();
    assert_eq!(writer.next_tid(), 7, "seven sub-range records");
    drop(writer);
    let mut writer = recover(
        &mut backend,
        &mut image,
        config(Duration::from_secs(3600), 1024),
        FixedClock,
    )
    .unwrap();
    assert_eq!(image.read(100, 3000), data);
    assert_eq!(writer.next_tid(), 7);
    // The first three sub-ranges match and are replaced; the fourth starts
    // in the matching half and continues into the mismatching zeros, so it
    // and every later sub-range stay unchanged.
    let half = [&data[..1500], &zeros[..1500]].concat();
    let other = pattern(2, 3000);
    let _ticket = writer.append(&backend, &[caw(&half, &other)]).unwrap();
    assert_eq!(writer.next_tid(), 14, "seven more sub-range records");
    drop(writer);
    let mut writer = recover(
        &mut backend,
        &mut image,
        config(Duration::from_secs(3600), 1024),
        FixedClock,
    )
    .unwrap();
    let mut expected = other[..3 * chunk].to_vec();
    expected.extend_from_slice(&data[3 * chunk..]);
    assert_eq!(image.read(100, 3000), expected);
    assert_eq!(writer.next_tid(), 14);
    // An inconsistent compare-and-write is refused before anything is
    // assigned.
    let short = &other[..2999];
    assert_eq!(
        writer.append(&backend, &[caw(&other, short)]).err(),
        Some(EINVAL)
    );
    assert_eq!(writer.next_tid(), 14);
}

#[test]
fn dispatch_runs_only_after_the_append_is_durable() {
    let mut backend = fresh_backend(14, 1, 8);
    let mut image = MemImage::new(4096);
    let mut writer = open(&mut backend, &mut image);
    let journal_bytes = |backend: &MemJournalBackend| {
        let mut buf = vec![0; 4096];
        backend.read_object(0, 0, &mut buf).unwrap_or(0)
    };
    let data = pattern(1, 64);
    let events = write_events(&writer, 0, &data);
    let result = journaled_mutation(&mut writer, &backend, &events, || {
        assert!(
            journal_bytes(&backend) > 0,
            "record durable before dispatch"
        );
        0
    });
    assert_eq!(result, Ok(0));
    let appended = journal_bytes(&backend);
    let result = journaled_op(
        &mut writer,
        &backend,
        |id| JournalEvent::MetadataSet {
            operation_id: id,
            key: b"k",
            value: b"v",
        },
        |_| {
            assert!(
                journal_bytes(&backend) > appended,
                "start durable before the op"
            );
            0
        },
    );
    assert_eq!(result, Ok(0));
    // The op persisted start and finish (TIDs 1 and 2).
    assert_eq!(stored_positions(&backend)[0].entry_tid, 2);
}

/// S8: every idempotency row of the spec's "Op events" table.
#[test]
fn op_idempotency_table_matches_the_spec() {
    use crate::journal_backend::{EBUSY, EEXIST, EINVAL, ENOENT, ERANGE};
    let snapshot = |kind| JournalEvent::Snapshot {
        kind,
        operation_id: 1,
        name: b"snap",
        namespace: SnapshotNamespace::User,
    };
    let rows = [
        (snapshot(JournalEventKind::Create), Some(EEXIST)),
        (snapshot(JournalEventKind::Remove), Some(ENOENT)),
        (
            JournalEvent::SnapshotRename {
                operation_id: 1,
                destination_name: b"dst",
                snapshot_id: 7,
                source_name: b"src",
            },
            Some(EEXIST),
        ),
        (snapshot(JournalEventKind::Protect), Some(EBUSY)),
        (snapshot(JournalEventKind::Unprotect), Some(EINVAL)),
        (snapshot(JournalEventKind::Rollback), None),
        (
            JournalEvent::ImageRename {
                operation_id: 1,
                new_name: b"dst",
            },
            Some(EEXIST),
        ),
        (
            JournalEvent::Resize {
                operation_id: 1,
                size: 9,
            },
            None,
        ),
        (JournalEvent::Flatten { operation_id: 1 }, Some(EINVAL)),
        (
            JournalEvent::SnapshotLimit {
                operation_id: 1,
                limit: 3,
            },
            Some(ERANGE),
        ),
        (
            JournalEvent::FeatureUpdate {
                operation_id: 1,
                features: 4,
                enabled: true,
            },
            None,
        ),
        (
            JournalEvent::MetadataSet {
                operation_id: 1,
                key: b"k",
                value: b"v",
            },
            None,
        ),
        (
            JournalEvent::MetadataRemove {
                operation_id: 1,
                key: b"k",
            },
            Some(ENOENT),
        ),
        (JournalEvent::MirrorPromoteDemote, None),
    ];
    for (event, expected) in rows {
        assert_eq!(idempotent_errno(&event), expected, "{event:?}");
    }
}
