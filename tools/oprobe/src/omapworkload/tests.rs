// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Own fake-server vectors reject absent-key operations and optimistic ownership.
use super::*;
use denc::Encode;
use std::collections::BTreeSet;

fn config(overrides: &[(&str, &str)]) -> Config {
    let mut m = BTreeMap::from([
        ("--prefix", "unit"),
        ("--output-dir", "/unused/omap-workload-unit"),
        ("--objects", "1"),
        ("--clients", "1"),
        ("--qd", "5"),
        ("--batch", "2"),
        ("--prefill", "40"),
        ("--key-bytes", "4"),
        ("--value-bytes", "7"),
        ("--ops-per-client", "20"),
    ]);
    for (k, v) in overrides {
        m.insert(k, v);
    }
    Config::parse(
        m.into_iter()
            .flat_map(|(k, v)| [k.to_owned(), v.to_owned()])
            .collect(),
        Some("test".into()),
        String::new(),
        String::new(),
        None,
    )
    .unwrap()
}
fn done(tag: u64, op: opwire::OsdOp) -> Done {
    let now = Instant::now();
    Done {
        tag,
        tid: 0,
        reply: Some(opwire::MOSDOpReply {
            flags: (opwire::flag::ACK | opwire::flag::ONDISK) as _,
            ops: vec![op],
            ..Default::default()
        }),
        err: String::new(),
        submitted: now,
        finished: now,
    }
}
struct Fake {
    operations: Vec<Op>,
    db: BTreeMap<usize, opwire::KvMap>,
    queued: Vec<Done>,
    submitted: Vec<(usize, u16, u64)>,
    first_poll: usize,
    max_pending: usize,
    reverse: bool,
    fail: bool,
}
impl Fake {
    fn new(c: &Config) -> Self {
        Self {
            operations: c.operations.clone(),
            db: (0..c.objects)
                .map(|o| {
                    (
                        o,
                        (0..c.prefill)
                            .map(|id| {
                                let k = Key { id, version: 0 };
                                (key(c, id).unwrap(), value(c, k))
                            })
                            .collect(),
                    )
                })
                .collect(),
            queued: Vec::new(),
            submitted: Vec::new(),
            first_poll: 0,
            max_pending: 0,
            reverse: true,
            fail: false,
        }
    }
    fn apply(&mut self, object: usize, op: opwire::OsdOp, tag: u64) -> Result<Done, String> {
        let db = self.db.get_mut(&object).unwrap();
        let mut reply = opwire::OsdOp::new(op.op);
        match op.op {
            opwire::op::OMAP_SET_VALS => {
                let vals: opwire::KvMap =
                    denc::from_slice(&op.indata).map_err(|e| e.to_string())?;
                for (k, v) in vals {
                    let operation =
                        self.operations[((tag - 1) % self.operations.len() as u64) as usize];
                    if operation == Op::Insert && db.contains_key(&k) {
                        return Err("insert overwrote a live key".into());
                    }
                    if operation == Op::Update && !db.contains_key(&k) {
                        return Err("update of absent key".into());
                    }
                    db.insert(k, v);
                }
            }
            opwire::op::OMAP_RM_KEYS => {
                let keys: BTreeSet<Vec<u8>> =
                    denc::from_slice(&op.indata).map_err(|e| e.to_string())?;
                if keys.iter().any(|k| !db.contains_key(k)) {
                    return Err("delete of absent key".into());
                }
                for k in keys {
                    db.remove(&k);
                }
            }
            opwire::op::OMAP_GET_VALS_BY_KEYS => {
                let keys: BTreeSet<Vec<u8>> =
                    denc::from_slice(&op.indata).map_err(|e| e.to_string())?;
                let mut vals = opwire::KvMap::new();
                for k in keys {
                    let v = db.get(&k).ok_or("read of absent key")?;
                    vals.insert(k, v.clone());
                }
                reply.outdata = vals.encode_to_vec().unwrap().into();
            }
            _ => return Err("unexpected fake operation".into()),
        }
        let mut d = done(tag, reply);
        if self.fail {
            d.err = "connection lost: outcome unknown".into();
            d.reply = None;
        }
        Ok(d)
    }
}
impl Transport for Fake {
    fn submit(&mut self, o: usize, op: opwire::OsdOp, tag: u64) -> Result<(), String> {
        self.submitted.push((o, op.op, tag));
        let d = self.apply(o, op, tag)?;
        self.queued.push(d);
        self.max_pending = self.max_pending.max(self.queued.len());
        Ok(())
    }
    fn poll(&mut self) -> Vec<Done> {
        if self.first_poll == 0 {
            self.first_poll = self.submitted.len();
        }
        let mut q = std::mem::take(&mut self.queued);
        if self.reverse {
            q.reverse();
        }
        q
    }
}

#[test]
fn qd_five_really_submits_insert_delete_insert_delete_insert_before_polling() {
    let c = config(&[("--ops-per-client", "5")]);
    let mut wire = Fake::new(&c);
    let start = Instant::now();
    let w = run_worker(
        &mut wire,
        &c,
        0,
        Model::new(&c, 0),
        start,
        &AtomicBool::new(false),
    );
    assert!(w.errors.is_empty(), "{:?}", w.errors);
    assert_eq!(wire.first_poll, 5);
    assert_eq!(wire.max_pending, 5);
    assert_eq!(w.peak, 5);
    assert_eq!(
        wire.submitted
            .iter()
            .map(|(_, op, _)| *op)
            .collect::<Vec<_>>(),
        vec![
            opwire::op::OMAP_SET_VALS,
            opwire::op::OMAP_RM_KEYS,
            opwire::op::OMAP_SET_VALS,
            opwire::op::OMAP_RM_KEYS,
            opwire::op::OMAP_SET_VALS
        ]
    );
    assert_eq!(w.model.issued, 5);
    assert_eq!(
        w.model.keys(),
        42,
        "odd request limits do not secretly balance cycles"
    );
    let expected: opwire::KvMap = w.model.queues[&0]
        .iter()
        .map(|&k| (key(&c, k.id).unwrap(), value(&c, k)))
        .collect();
    assert_eq!(wire.db[&0], expected);
}

#[test]
fn acknowledged_insert_keys_are_not_borrowed_by_pending_updates_or_deletes() {
    let c = config(&[]);
    let mut m = Model::new(&c, 0);
    let insert = m.next(&c).unwrap().unwrap();
    let delete = m.next(&c).unwrap().unwrap();
    let inserted: BTreeSet<_> = insert.keys.iter().map(|k| k.id).collect();
    assert!(delete.keys.iter().all(|k| !inserted.contains(&k.id)));
    assert_eq!(m.keys(), 38);
    m.complete(insert);
    assert_eq!(m.keys(), 40);
    m.complete(delete);
    assert_eq!(m.keys(), 40);
}

#[test]
fn all_operation_cycles_remain_exact_with_out_of_order_completions() {
    for operations in [
        "insert,update,delete,read",
        "update",
        "read",
        "insert,insert,delete",
        "delete",
    ] {
        let c = config(&[
            ("--operations", operations),
            ("--ops-per-client", "20"),
            ("--prefill", "100"),
        ]);
        let mut wire = Fake::new(&c);
        let w = run_worker(
            &mut wire,
            &c,
            0,
            Model::new(&c, 0),
            Instant::now(),
            &AtomicBool::new(false),
        );
        assert!(w.errors.is_empty(), "{operations}: {:?}", w.errors);
        let expected: opwire::KvMap = w.model.queues[&0]
            .iter()
            .map(|&k| (key(&c, k.id).unwrap(), value(&c, k)))
            .collect();
        assert_eq!(wire.db[&0], expected);
        assert_eq!(w.model.issued, 20);
    }
}

#[test]
fn ownership_covers_each_initial_key_once_and_new_keys_never_collide() {
    for (objects, clients) in [(4, 8), (8, 4), (3, 7), (7, 3)] {
        let c = config(&[
            ("--objects", &objects.to_string()),
            ("--clients", &clients.to_string()),
            ("--prefill", "100"),
            ("--qd", "1"),
        ]);
        let mut owned = BTreeSet::new();
        let mut future = BTreeSet::new();
        for client in 0..clients {
            let m = Model::new(&c, client);
            for (&o, q) in &m.queues {
                for k in q {
                    assert!(owned.insert((o, k.id)));
                }
            }
            let mut m = m;
            for _ in 0..20 {
                let r = m.next(&c).unwrap().unwrap();
                if r.op == Op::Insert {
                    for k in &r.keys {
                        assert!(future.insert((r.object, k.id)));
                        assert!(!owned.contains(&(r.object, k.id)));
                    }
                }
                m.complete(r);
            }
        }
        assert_eq!(owned.len(), objects * 100);
        if objects == 4 && clients == 8 {
            for o in 0..4 {
                assert_eq!((0..clients).filter(|&w| c.owned(w).contains(&o)).count(), 2);
            }
        }
    }
}

#[test]
fn whole_operation_cycles_visit_each_owned_object() {
    let c = config(&[("--objects", "4"), ("--qd", "1")]);
    let mut m = Model::new(&c, 0);
    let mut pairs = Vec::new();
    for _ in 0..8 {
        let r = m.next(&c).unwrap().unwrap();
        pairs.push((r.object, r.op));
        m.complete(r);
    }
    assert_eq!(
        pairs,
        vec![
            (0, Op::Insert),
            (0, Op::Delete),
            (1, Op::Insert),
            (1, Op::Delete),
            (2, Op::Insert),
            (2, Op::Delete),
            (3, Op::Insert),
            (3, Op::Delete)
        ]
    );
}

#[test]
fn checked_replies_require_ack_and_ondisk_and_matching_successful_ops() {
    let mut d = done(1, opwire::OsdOp::new(opwire::op::OMAP_SET_VALS));
    for flags in [0, opwire::flag::ACK, opwire::flag::ONDISK] {
        d.reply.as_mut().unwrap().flags = flags as _;
        assert!(checked(&d, opwire::op::OMAP_SET_VALS, true).is_err());
    }
    d.reply.as_mut().unwrap().flags = (opwire::flag::ACK | opwire::flag::ONDISK) as _;
    assert!(checked(&d, opwire::op::OMAP_SET_VALS, true).is_ok());
    d.reply.as_mut().unwrap().ops[0].rval = -5;
    assert!(checked(&d, opwire::op::OMAP_SET_VALS, true).is_err());
    d.reply.as_mut().unwrap().ops[0].rval = 0;
    d.reply.as_mut().unwrap().result = -5;
    assert!(checked(&d, opwire::op::OMAP_SET_VALS, true).is_err());
}

#[test]
fn unknown_mutation_outcome_fails_and_never_promotes_inserted_keys() {
    let c = config(&[("--operations", "insert"), ("--ops-per-client", "1")]);
    let mut wire = Fake::new(&c);
    wire.fail = true;
    let stop = AtomicBool::new(false);
    let w = run_worker(&mut wire, &c, 0, Model::new(&c, 0), Instant::now(), &stop);
    assert!(!w.errors.is_empty());
    assert!(stop.load(Ordering::Acquire));
    assert_eq!(w.model.keys(), c.prefill);
    assert!(w.stats.is_empty());
}

#[test]
fn duration_stops_issuing_and_reports_late_completions_as_drain() {
    use std::{cell::Cell, rc::Rc};
    struct Timed {
        wire: Fake,
        clock: Rc<Cell<Duration>>,
        start: Instant,
    }
    impl Transport for Timed {
        fn submit(&mut self, o: usize, op: opwire::OsdOp, t: u64) -> Result<(), String> {
            self.wire.submit(o, op, t)
        }
        fn poll(&mut self) -> Vec<Done> {
            let mut d = self.wire.poll();
            self.clock.set(Duration::from_secs(2));
            for (i, x) in d.iter_mut().enumerate() {
                x.submitted = self.start;
                x.finished = self.start + Duration::from_millis(if i == 0 { 500 } else { 1500 });
            }
            d
        }
    }
    let mut c = config(&[]);
    c.requests = None;
    c.seconds = Some(1);
    let clock = Rc::new(Cell::new(Duration::ZERO));
    let now = clock.clone();
    let start = Instant::now();
    let mut wire = Timed {
        wire: Fake::new(&c),
        clock,
        start,
    };
    let w = run_worker_clock(
        &mut wire,
        &c,
        0,
        Model::new(&c, 0),
        start,
        &AtomicBool::new(false),
        || start + now.get(),
    );
    assert!(w.errors.is_empty());
    assert_eq!(w.model.issued, 5);
    assert_eq!(w.stats.values().map(|s| s.requests).sum::<u64>(), 1);
    assert_eq!(w.drain.values().map(|s| s.requests).sum::<u64>(), 4);
}

#[test]
fn throughput_mode_allocates_no_histogram_or_sampler_and_pooled_histograms_are_real() {
    let c = config(&[]);
    assert!(!c.latency());
    assert!(Sampler::new(&c).unwrap().is_none());
    let s = Stats::new(false);
    assert!(s.hist.is_none());
    assert!(s.doc(1.0, true).get("latency").is_none());
    let mut a = metrics::Histogram::new();
    for _ in 0..1000 {
        a.record(10);
    }
    let mut b = metrics::Histogram::new();
    b.record(10000);
    a.merge(&b);
    assert_eq!(a.doc()["p99"], 10);
    assert_eq!(a.bins.iter().sum::<u64>(), a.n);
}

#[test]
fn small_key_sizes_are_exact_and_exhaustion_is_not_an_overwrite() {
    let c = config(&[
        ("--key-bytes", "1"),
        ("--clients", "1"),
        ("--batch", "1"),
        ("--qd", "1"),
        ("--prefill", "20"),
    ]);
    assert_eq!(key(&c, 255).unwrap(), vec![255]);
    assert!(key(&c, 256).is_err());
    let keys: BTreeSet<_> = (0..256).map(|id| key(&c, id).unwrap()).collect();
    assert_eq!(keys.len(), 256);
    assert_eq!(value(&c, Key { id: 1, version: 0 }).len(), 7);
    assert_ne!(
        value(&c, Key { id: 1, version: 0 }),
        value(&c, Key { id: 1, version: 1 })
    );
}

#[test]
fn bad_shapes_metrics_and_limits_fail_before_connecting() {
    for extra in [
        vec!["--metrics", "unknown"],
        vec!["--operations", "insert,,delete"],
        vec!["--objects", "0"],
        vec!["--seconds", "1", "--ops-per-client", "1"],
        vec!["--prefill", "0"],
        vec!["--qd", "0"],
        vec!["--all", "--metrics", "throughput"],
    ] {
        let mut a = vec![
            "--prefix".into(),
            "unit".into(),
            "--output-dir".into(),
            "/unused/unit".into(),
        ];
        a.extend(extra.into_iter().map(str::to_owned));
        assert!(Config::parse(a, Some("p".into()), String::new(), String::new(), None).is_err());
    }
}

#[test]
fn strict_scan_decoder_rejects_duplicate_keys_before_map_conversion() {
    // Also exercise the shared wire decoder's strict ordering rather than a map
    // decoder that could silently hide duplicate keys.
    let mut e = denc::Encoder::new();
    e.u32(2).unwrap();
    e.bytes(b"a").unwrap();
    e.bytes(b"v").unwrap();
    e.bytes(b"a").unwrap();
    e.bytes(b"v").unwrap();
    assert!(crate::omapload::entries(&e.into_vec(), false).is_err());
}

#[test]
fn full_verification_accepts_short_pages_but_rejects_corruption_and_no_progress() {
    let c = config(&[]);
    let expected: Vec<_> = (0..5).map(|id| Key { id, version: 0 }).collect();
    for fault in ["none", "missing", "extra", "value", "duplicate", "stalled"] {
        let mut page = 0;
        let result = verify_pages(&c, 0, &expected, |cursor, _| {
            let mut e = denc::Encoder::new();
            let mut ids = match page {
                0 => vec![0, 1],
                1 => vec![2],
                _ => vec![3, 4],
            };
            if fault == "missing" && page == 2 {
                ids.pop();
            }
            if fault == "extra" && page == 2 {
                ids.push(5);
            }
            if fault == "duplicate" && page == 1 {
                ids = vec![1, 2];
            }
            if fault == "stalled" {
                ids.clear();
            }
            e.u32(ids.len() as u32).unwrap();
            for id in ids {
                e.bytes(&key(&c, id).unwrap()).unwrap();
                let mut v = value(&c, Key { id, version: 0 });
                if fault == "value" && id == 3 {
                    v[0] ^= 1;
                }
                e.bytes(&v).unwrap();
            }
            e.u8(u8::from(page < 2 || fault == "stalled")).unwrap();
            if page == 1 && fault == "none" {
                assert_eq!(cursor, key(&c, 1).unwrap());
            }
            page += 1;
            let mut op = opwire::OsdOp::new(opwire::op::OMAP_GET_VALS);
            op.outdata = e.into_vec().into();
            Ok(done(0, op))
        });
        assert_eq!(result.is_ok(), fault == "none", "{fault}: {result:?}");
    }
    verify_pages(&c, 0, &[], |_, _| {
        let mut op = opwire::OsdOp::new(opwire::op::OMAP_GET_VALS);
        op.outdata = vec![0, 0, 0, 0, 0].into();
        Ok(done(0, op))
    })
    .unwrap();
}

#[test]
fn delete_only_exhaustion_and_live_memory_caps_are_errors_not_absent_key_traffic() {
    let c = config(&[
        ("--prefill", "10"),
        ("--operations", "delete"),
        ("--ops-per-client", "6"),
    ]);
    let mut wire = Fake::new(&c);
    let w = run_worker(
        &mut wire,
        &c,
        0,
        Model::new(&c, 0),
        Instant::now(),
        &AtomicBool::new(false),
    );
    assert!(w.errors.iter().any(|e| e.contains("exhausted")));
    assert_eq!(wire.submitted.len(), 5);
    let c = config(&[("--max-live-keys", "40"), ("--operations", "insert")]);
    let mut m = Model::new(&c, 0);
    assert!(m.next(&c).unwrap().is_none());
}

#[test]
fn tight_live_cap_drains_recoverable_deletes_instead_of_aborting() {
    let c = config(&[("--max-live-keys", "42")]);
    let mut wire = Fake::new(&c);
    let w = run_worker(
        &mut wire,
        &c,
        0,
        Model::new(&c, 0),
        Instant::now(),
        &AtomicBool::new(false),
    );
    assert!(w.errors.is_empty(), "{:?}", w.errors);
    assert_eq!(w.model.issued, 20);
    assert_eq!(w.model.keys(), 40);
    assert!(w.starved > 0);
}

#[test]
fn every_256_key_delete_batch_is_a_reserved_live_fifo_range_for_all_shared_owners() {
    let c = config(&[
        ("--clients", "8"),
        ("--batch", "256"),
        ("--prefill", "10240"),
        ("--ops-per-client", "5"),
    ]);
    let mut all_deletions = BTreeSet::new();
    for client in 0..8 {
        let (a, b, _, _) = c.partition(client, 0);
        let mut model = Model::new(&c, client);
        let mut deleted = 0;
        let requests = (0..5)
            .map(|_| model.next(&c).unwrap().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            requests.iter().map(|r| r.op).collect::<Vec<_>>(),
            vec![Op::Insert, Op::Delete, Op::Insert, Op::Delete, Op::Insert]
        );
        for r in &requests {
            assert_eq!(r.keys.len(), 256);
            if r.op == Op::Delete {
                for (i, k) in r.keys.iter().enumerate() {
                    assert_eq!(k.id, a + deleted + i as u64);
                    assert!(k.id < b);
                    assert!(all_deletions.insert(k.id));
                }
                deleted += 256;
            }
        }
    }
    assert_eq!(all_deletions.len(), 8 * 2 * 256);
}

#[test]
fn deadline_crossed_during_preparation_never_admits_the_prepared_request() {
    for operation in ["insert", "update", "delete", "read"] {
        for duration_mode in [true, false] {
            let mut c = config(&[("--operations", operation)]);
            c.max_seconds = 2;
            if duration_mode {
                c.requests = None;
                c.seconds = Some(1);
            }
            let start = Instant::now();
            let mut tick = 0;
            let mut wire = Fake::new(&c);
            let w = run_worker_clock(
                &mut wire,
                &c,
                0,
                Model::new(&c, 0),
                start,
                &AtomicBool::new(false),
                || {
                    tick += 1;
                    start
                        + if tick >= if duration_mode { 5 } else { 3 } {
                            Duration::from_secs(if duration_mode { 1 } else { 2 })
                        } else {
                            Duration::ZERO
                        }
                },
            );
            assert!(
                wire.submitted.is_empty(),
                "{operation}, duration={duration_mode}"
            );
            assert_eq!(w.model.issued, 0);
            assert_eq!(w.model.keys(), 40);
            assert_eq!(w.accounting[&0][operation].not_admitted, 1);
            for k in &w.model.queues[&0] {
                assert_eq!(k.version, 0, "unadmitted update must restore old version");
            }
            if duration_mode {
                assert!(w.errors.is_empty());
            } else {
                assert!(w.errors.iter().any(|e| e.contains("WARNING TIMEOUT")));
            }
        }
    }
}

#[test]
fn admission_errors_and_mixed_completion_batches_reconcile_without_discarding_success() {
    struct Faults {
        wire: Fake,
        admission: bool,
    }
    impl Transport for Faults {
        fn submit(&mut self, o: usize, op: opwire::OsdOp, t: u64) -> Result<(), String> {
            if self.admission && t == 3 {
                return Err("injected admission error".into());
            }
            self.wire.submit(o, op, t)
        }
        fn poll(&mut self) -> Vec<Done> {
            let mut ds = self.wire.poll();
            if let Some(d) = ds.iter_mut().find(|d| d.tag == 3) {
                d.reply = None;
                d.err = "injected connection loss".into();
            }
            ds
        }
    }
    for admission in [true, false] {
        let c = config(&[("--ops-per-client", "5")]);
        let mut wire = Faults {
            wire: Fake::new(&c),
            admission,
        };
        let w = run_worker(
            &mut wire,
            &c,
            0,
            Model::new(&c, 0),
            Instant::now(),
            &AtomicBool::new(false),
        );
        assert!(!w.errors.is_empty());
        let mut sums = [0; 7];
        for a in w.accounting.values().flat_map(|ops| ops.values()) {
            let values = [
                a.prepared,
                a.admitted,
                a.not_admitted,
                a.admission_errors,
                a.succeeded,
                a.failed,
                a.unknown,
            ];
            for (i, v) in values.into_iter().enumerate() {
                sums[i] += v;
            }
        }
        assert_eq!(sums[0], sums[1] + sums[2] + sums[3]);
        assert_eq!(sums[1], sums[4] + sums[5] + sums[6]);
        if admission {
            assert_eq!(sums, [3, 2, 0, 1, 0, 0, 2]);
        } else {
            assert_eq!(sums, [5, 5, 0, 0, 4, 0, 1]);
            assert_eq!(w.stats.values().map(|s| s.requests).sum::<u64>(), 4);
        }
        assert!(!w.unresolved.is_empty());
    }
}

#[cfg(target_os = "linux")]
fn scratch(label: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "omap-workload-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&path).unwrap();
    path
}

#[cfg(target_os = "linux")]
#[test]
fn device_targets_reject_fifos_and_large_arbitrary_files_without_opening_them() {
    let root = scratch("targets");
    let fifo = root.join("fifo");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let large = root.join("large-stat");
    std::fs::write(&large, vec![b' '; 8192]).unwrap();
    assert!(metrics::block_target(&fifo).is_err());
    assert!(metrics::block_target(&large).is_err());
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn disappearing_resource_target_retains_completed_work_and_prior_samples_in_failure_report() {
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let mut c = config(&[("--metrics", "throughput,rss")]);
    c.pids = vec![child.id()];
    c.output = scratch("resource-failure");
    let start = Instant::now();
    let mut s = Sampler::new(&c).unwrap().unwrap();
    let mut wire = Fake::new(&c);
    let w = run_worker(
        &mut wire,
        &c,
        0,
        Model::new(&c, 0),
        start,
        &AtomicBool::new(false),
    );
    assert!(w.errors.is_empty());
    s.sample().unwrap();
    child.kill().unwrap();
    child.wait().unwrap();
    let error = s.sample().unwrap_err();
    let report = finish_report(
        &c,
        &[w],
        vec![format!("OSD PID {} disappeared: {error}", c.pids[0])],
        json!({"ok":false}),
        Some(s),
        start,
        1.0,
    )
    .unwrap();
    assert_eq!(report["ok"], false);
    assert_eq!(report["metrics"]["total"]["requests"], 20);
    assert_eq!(report["clients"][0]["submitted"], 20);
    assert!(
        report["errors"][0]
            .as_str()
            .unwrap()
            .contains("disappeared")
    );
    assert!(
        !std::fs::read_to_string(c.output.join("resources.jsonl"))
            .unwrap()
            .is_empty()
    );
    std::fs::remove_dir_all(c.output).unwrap();
}

#[test]
fn connection_manifest_distinguishes_modes_timeouts_and_cluster_selectors_without_credentials() {
    let a = Opts {
        mode: "crc".into(),
        conf: "cluster-a.conf".into(),
        ..Default::default()
    };
    let b = Opts {
        mode: "secure".into(),
        timeout: Duration::from_secs(9),
        keyring: Some("secret-material-must-not-appear".into()),
        ..a.clone()
    };
    assert_ne!(connection(&a), connection(&b));
    assert_eq!(connection(&b)["mode_requested"], "secure");
    assert_eq!(connection(&b)["rpc_timeout_seconds"], 9.0);
    assert!(!connection(&b).to_string().contains("secret-material"));
}

#[test]
fn timeout_no_reply_never_hangs_the_scheduler() {
    struct Silent;
    impl Transport for Silent {
        fn submit(&mut self, _: usize, _: opwire::OsdOp, _: u64) -> Result<(), String> {
            Ok(())
        }
        fn poll(&mut self) -> Vec<Done> {
            Vec::new()
        }
    }
    let mut c = config(&[]);
    c.max_seconds = 2;
    let start = Instant::now();
    let mut ticks = 0;
    let w = run_worker_clock(
        &mut Silent,
        &c,
        0,
        Model::new(&c, 0),
        start,
        &AtomicBool::new(false),
        || {
            ticks += 1;
            start + Duration::from_secs(ticks / 10)
        },
    );
    assert!(w.errors.iter().any(|e| e.contains("WARNING TIMEOUT")));
    assert!(w.peak <= c.qd);
}
