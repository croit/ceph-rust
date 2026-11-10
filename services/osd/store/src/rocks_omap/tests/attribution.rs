// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Bounded offline attribution, not an end-to-end benchmark or historical control.
use super::*;
use crate::test_alloc::{allocated_bytes, allocations};
use std::hint::black_box;

const ID: u64 = 37;
const LIMIT: usize = 8 << 20;
const ROUNDS: usize = 5;
const REPS: usize = 128;
type Rows = Vec<(Vec<u8>, Vec<u8>)>;

fn rows(n: usize, irregular: bool) -> Rows {
    (0..n)
        .map(|i| {
            let mut key = vec![0xa5; 64];
            key[..8].copy_from_slice(&(i as u64).to_be_bytes());
            key[8..12].copy_from_slice(&[0, 0xff, 0x80, 0]);
            let size = if irregular {
                [0, 3, 256, 8192][i % 4]
            } else {
                256
            };
            let value = (0..size).map(|j| (i.wrapping_mul(17) ^ j) as u8).collect();
            (key, value)
        })
        .collect()
}

#[derive(Default, Debug)]
struct Sample {
    allocations: usize,
    requested_bytes: usize,
    wall_ns: u64,
    cpu_ns: u64,
    cpu_errors: usize,
}

impl Sample {
    fn add(&mut self, other: Self) {
        self.allocations += other.allocations;
        self.requested_bytes += other.requested_bytes;
        self.wall_ns += other.wall_ns;
        self.cpu_ns += other.cpu_ns;
        self.cpu_errors += other.cpu_errors;
    }

    fn report(&self, shape: &str, round: usize, lane: &str, phase: &str, entries: usize) {
        let cpu = if self.cpu_errors == 0 {
            self.cpu_ns.to_string()
        } else {
            "null".into()
        };
        println!(
            "SCAN_ATTR {{\"shape\":\"{shape}\",\"round\":{round},\"lane\":\"{lane}\",\"phase\":\"{phase}\",\"repetitions\":{REPS},\"entries_per_page\":{entries},\"rust_allocation_requests\":{},\"rust_requested_bytes\":{},\"wall_ns\":{},\"thread_cpu_ns\":{cpu},\"cpu_errors\":{}}}",
            self.allocations, self.requested_bytes, self.wall_ns, self.cpu_errors
        );
    }
}

fn measure<T>(f: impl FnOnce() -> T) -> (T, Sample) {
    let mut out = None;
    let mut sample = Sample::default();
    let at = Instant::now();
    let cpu = metrics::thread_cpu_ns();
    sample.requested_bytes = allocated_bytes(|| {
        sample.allocations = allocations(|| out = Some(black_box(f())));
    });
    match (cpu, metrics::thread_cpu_ns()) {
        (Some(a), Some(b)) if a <= b => sample.cpu_ns = b - a,
        _ => sample.cpu_errors = 1,
    }
    sample.wall_ns = metrics::nanos(at.elapsed());
    (out.unwrap(), sample)
}

fn packed(input: &[(Vec<u8>, Vec<u8>)], page_bytes: usize) -> Result<PageBuilder> {
    let mut builder = PageBuilder::default();
    for (key, value) in input {
        if !builder.push(key, value, input.len(), page_bytes, LIMIT)? {
            return Err(StoreError::TxnTooLarge);
        }
    }
    Ok(builder)
}

fn separate(input: &[(Vec<u8>, Vec<u8>)]) -> Vec<(Bytes, Bytes)> {
    input
        .iter()
        .map(|(k, v)| (Bytes::copy_from_slice(k), Bytes::copy_from_slice(v)))
        .collect()
}

fn verify(output: &[(Bytes, Bytes)], expected: &[(Vec<u8>, Vec<u8>)]) {
    verify_borrowed(
        output.iter().map(|(k, v)| (k.as_ref(), v.as_ref())),
        expected,
    );
}

fn verify_borrowed<'a>(
    output: impl Iterator<Item = (&'a [u8], &'a [u8])>,
    expected: &[(Vec<u8>, Vec<u8>)],
) {
    let mut n = 0;
    for (k, v) in output {
        let (ek, ev) = &expected[n];
        assert_eq!(k, ek);
        assert_eq!(v, ev);
        n += 1;
    }
    assert_eq!(n, expected.len());
}

fn query(input: &Rows, start: usize, count: usize) -> Query {
    Query::Page {
        id: ID,
        from: Bytes::copy_from_slice(&input[start].0),
        excl: false,
        prefix: Bytes::new(),
        entries: count,
        versions: [(0, 0); 3],
        session: None,
    }
}

/// Iterator-only control: no overlay implementation or owned output pairs.
/// Construction/seek/step/drop are inclusive. Data is consumed by black_box;
/// byte totals and the first-unreturned index are checked outside timing.
fn iterator_only(d: &Database, from: &[u8], count: usize) -> Result<(usize, usize, Option<u64>)> {
    let mut options = ReadOptions::default();
    options.set_iterate_upper_bound(object_end(ID));
    let mut it = d.db.raw_iterator_opt(options);
    it.seek(key(ID, from));
    let mut n = 0;
    let mut bytes = 0;
    while n < count {
        let Some((k, v)) = it.item() else { break };
        black_box((k, v));
        bytes += k.len() - 9 + v.len();
        n += 1;
        it.next();
    }
    let next = it
        .item()
        .map(|(k, _)| u64::from_be_bytes(k[9..17].try_into().unwrap()));
    it.status().map_err(err)?;
    Ok((n, bytes, next))
}

fn verify_page(answer: &Answer, input: &Rows, start: usize, count: usize) {
    let Answer::Page(page, end) = answer else {
        panic!("not a page")
    };
    verify_borrowed(page.iter(), &input[start..start + count]);
    if start + count == input.len() {
        assert!(matches!(end, PageEnd::End));
    } else {
        let PageEnd::Next(next) = end else {
            panic!("no exact continuation")
        };
        assert_eq!(next.as_ref(), input[start + count].0);
    }
}

#[test]
fn attribution_controls_preserve_binary_vectors_capacity_and_continuations() {
    for irregular in [false, true] {
        let count = if irregular { 64 } else { 1024 };
        let input = rows(count * 4, irregular);
        assert!(input.windows(2).all(|w| w[0].0 < w[1].0));
        let (_temp, cfg, sb) = fixture();
        let mut d = db(&cfg, &sb, false);
        let mut mem = Memtable::new();
        for (k, v) in &input {
            mem.put(1, ID, Bytes::copy_from_slice(k), Bytes::copy_from_slice(v));
        }
        d.flush(&mem).unwrap();
        drop(mem);
        for start in (0..input.len()).step_by(count) {
            let selected = &input[start..start + count];
            let builder = packed(selected, d.page_bytes).unwrap();
            let before = builder.bytes();
            let page = builder.finish();
            verify_borrowed(page.iter(), selected);
            assert!(page.bytes() >= before);
            verify(&separate(selected), selected);
            let bytes = selected
                .iter()
                .map(|(k, v)| k.len() + v.len())
                .sum::<usize>();
            let next = (start + count < input.len()).then_some((start + count) as u64);
            assert_eq!(
                iterator_only(&d, &input[start].0, count).unwrap(),
                (count, bytes, next)
            );
            verify_page(
                &d.page_limit(&query(&input, start, count), &[None, None, None], LIMIT)
                    .unwrap(),
                &input,
                start,
                count,
            );
        }
    }
}

#[test]
#[ignore = "bounded offline allocation/CPU diagnostic; run alone with --release --nocapture"]
fn offline_scan_construction_attribution() {
    // Runtime refusal keeps the ignored diagnostic compilable in debug without
    // presenting debug timings as release evidence.
    assert!(
        !black_box(cfg!(debug_assertions)),
        "use --release for timing evidence"
    );
    let deadline = Instant::now() + Duration::from_secs(45);
    println!(
        "SCAN_ATTR_META {{\"allocator\":\"System with existing thread-local Rust counters\",\"native_allocations\":\"unobserved\",\"requested_bytes_are_peak_or_copied_bytes\":false,\"rounds\":{ROUNDS},\"repetitions_per_round\":{REPS},\"warmups_per_shape\":1,\"production_policy_changed\":false}}"
    );
    for irregular in [false, true] {
        let shape = if irregular {
            "irregular-growth"
        } else {
            "uniform-64-256"
        };
        let count = if irregular { 64 } else { 1024 };
        let input = rows(count * 4, irregular);
        let selected = &input[..count];
        let raw_bytes: usize = selected.iter().map(|(k, v)| k.len() + v.len()).sum();
        let (_temp, cfg, sb) = fixture();
        let metrics = Arc::new(metrics::Metrics::new_profiled(true));
        let mut d = Database::open_profiled(
            &cfg.path(&sb, 0).unwrap(),
            &identity(&sb, 0),
            MEM,
            false,
            Some(metrics.clone()),
            1,
        )
        .unwrap();
        let mut mem = Memtable::new();
        for (k, v) in &input {
            mem.put(1, ID, Bytes::copy_from_slice(k), Bytes::copy_from_slice(v));
        }
        d.flush(&mem).unwrap();
        drop(mem);
        let q = query(&input, 0, count);
        // All setup, output verification and printing are outside measured spans.
        let builder = packed(selected, d.page_bytes).unwrap();
        let builder_charge = builder.bytes();
        let page = builder.finish();
        let page_charge = page.bytes();
        verify_borrowed(page.iter(), selected);
        drop(page);
        verify(&separate(selected), selected);
        assert_eq!(
            iterator_only(&d, &input[0].0, count).unwrap(),
            (count, raw_bytes, Some(count as u64))
        );
        verify_page(
            &d.page_limit(&q, &[None, None, None], LIMIT).unwrap(),
            &input,
            0,
            count,
        );
        println!(
            "SCAN_ATTR_SHAPE {{\"shape\":\"{shape}\",\"fixture_entries\":{},\"entries_per_page\":{count},\"raw_bytes_per_page\":{raw_bytes},\"builder_charge\":{builder_charge},\"page_charge\":{page_charge},\"page_target\":{},\"answer_limit\":{LIMIT}}}",
            input.len(),
            d.page_bytes
        );
        for round in 0..ROUNDS {
            let mut empty = Sample::default();
            let mut push = Sample::default();
            let mut finish = Sample::default();
            let mut packed_drop = Sample::default();
            let mut plain = Sample::default();
            let mut plain_drop = Sample::default();
            let mut iterator = Sample::default();
            let mut full = Sample::default();
            let mut full_drop = Sample::default();
            let profile_before = metrics.profile.sample();
            for _ in 0..REPS {
                assert!(
                    Instant::now() < deadline,
                    "WARNING TIMEOUT offline construction diagnostic exceeded45s"
                );
                empty.add(measure(|| black_box(())).1);
                let (builder, sample) = measure(|| packed(selected, d.page_bytes).unwrap());
                push.add(sample);
                let (page, sample) = measure(|| builder.finish());
                finish.add(sample);
                verify_borrowed(page.iter(), selected);
                assert_eq!(page.bytes(), page_charge);
                packed_drop.add(measure(|| drop(page)).1);
                let (pairs, sample) = measure(|| separate(selected));
                plain.add(sample);
                verify(&pairs, selected);
                plain_drop.add(measure(|| drop(pairs)).1);
                let (walk, sample) = measure(|| iterator_only(&d, &input[0].0, count).unwrap());
                iterator.add(sample);
                assert_eq!(walk, (count, raw_bytes, Some(count as u64)));
                let (answer, sample) =
                    measure(|| d.page_limit(&q, &[None, None, None], LIMIT).unwrap());
                full.add(sample);
                verify_page(&answer, &input, 0, count);
                full_drop.add(measure(|| drop(answer)).1);
            }
            for (lane, phase, sample) in [
                ("control", "empty", empty),
                ("packed", "push", push),
                ("packed", "finish", finish),
                ("packed", "drop", packed_drop),
                ("separate-pairs", "construct", plain),
                ("separate-pairs", "drop", plain_drop),
                ("db-iterator", "inclusive", iterator),
                ("db-page", "inclusive", full),
                ("db-page", "drop", full_drop),
            ] {
                sample.report(shape, round, lane, phase, count);
            }
            let profile_after = metrics.profile.sample();
            let stages: Vec<_> = profile_after[48..56]
                .iter()
                .zip(&profile_before[48..56])
                .map(|(a, b)| a - b)
                .collect();
            assert_eq!(profile_after[44] - profile_before[44], REPS as u64);
            assert_eq!(profile_after[45] - profile_before[45], 0);
            println!(
                "SCAN_ATTR_STAGES {{\"shape\":\"{shape}\",\"round\":{round},\"attempts\":{REPS},\"cpu_samples\":{},\"cpu_errors\":{},\"setup_position_walk_drop_wall_cpu_ns\":{stages:?}}}",
                profile_after[46] - profile_before[46],
                profile_after[47] - profile_before[47]
            );
        }
    }
}
