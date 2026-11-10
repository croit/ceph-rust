// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Decode memory of `choose_args` must stay linear in the stream (spec crush.md sec 3): a map of many
//! bucket slots and many choose_args sets used to allocate `buckets x maps` dense arg vectors.
use crush::{CrushMap, MAGIC};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

impl Counting {
    fn add(n: usize) {
        let live = LIVE.fetch_add(n, Ordering::Relaxed) + n;
        PEAK.fetch_max(live, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            Self::add(layout.size());
        }
        p
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            Self::add(layout.size());
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
            Self::add(new_size);
        }
        p
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn u32v(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn i32v(b: &mut Vec<u8>, v: i32) {
    b.extend_from_slice(&v.to_le_bytes());
}

/// `slots` bucket slots (slot 0 a real straw2 bucket, the rest empty) and `maps` choose_args sets,
/// each describing slot 0 with one weight position. Every map's on-wire cost is >= 12 bytes.
fn blob(slots: usize, maps: usize) -> Vec<u8> {
    let mut b = Vec::new();
    u32v(&mut b, MAGIC);
    i32v(&mut b, slots as i32);
    u32v(&mut b, 0); // max_rules
    i32v(&mut b, 0); // max_devices (recomputed)
    u32v(&mut b, 5); // slot 0: alg straw2
    i32v(&mut b, -1);
    b.extend_from_slice(&1u16.to_le_bytes()); // type
    b.push(5); // alg
    b.push(0); // hash
    u32v(&mut b, 0x10000); // weight
    u32v(&mut b, 1); // size
    i32v(&mut b, 0); // items
    u32v(&mut b, 0x10000); // straw2 item weight
    for _ in 1..slots {
        u32v(&mut b, 0); // empty slot
    }
    for _ in 0..3 {
        u32v(&mut b, 0); // type_map, name_map, rule_name_map
    }
    u32v(&mut b, 0); // choose_local_tries
    u32v(&mut b, 0); // choose_local_fallback_tries
    u32v(&mut b, 50); // choose_total_tries
    u32v(&mut b, 1); // chooseleaf_descend_once
    b.push(1); // chooseleaf_vary_r
    b.push(1); // straw_calc_version
    u32v(&mut b, 0x36); // allowed_bucket_algs
    b.push(1); // chooseleaf_stable
    u32v(&mut b, 0); // class_map
    u32v(&mut b, 0); // class_name
    u32v(&mut b, 0); // class_bucket
    u32v(&mut b, maps as u32);
    for m in 0..maps {
        b.extend_from_slice(&(m as i64).to_le_bytes());
        u32v(&mut b, 1); // n_args
        u32v(&mut b, 0); // bucket_index
        u32v(&mut b, 1); // weight_set_positions
        u32v(&mut b, 1); // weight size
        u32v(&mut b, 0x10000);
        u32v(&mut b, 0); // ids_size
    }
    u32v(&mut b, 100); // msr_descents
    u32v(&mut b, 100); // msr_collision_tries
    b
}

fn peak_during<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let base = LIVE.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    let out = f();
    (out, PEAK.load(Ordering::Relaxed) - base)
}

#[test]
fn choose_args_decode_memory_is_linear_in_the_stream() {
    let raw = blob(2000, 2000);
    let (m, peak) = peak_during(|| CrushMap::decode(&raw).unwrap());
    // The sparse model stores one entry per described arg, not one arg per (map, bucket slot).
    let stored: usize = m.choose_args.values().map(|a| a.len()).sum();
    assert_eq!(stored, 2000, "one described arg per map");
    assert_eq!(m.choose_args.len(), 2000);
    // Decoding 32 KB may allocate the slot array (empty slots cost ~96 B of `Option<Bucket>` for 4 wire
    // bytes) plus the described args; the dense `buckets x maps` model needed ~192 MB for this blob.
    assert!(
        peak < raw.len() * 64,
        "peak {peak} B for {} B input",
        raw.len()
    );
}

/// A map with many bucket slots and a single choose_args set is the common case and must decode.
#[test]
fn one_choose_args_set_per_many_buckets() {
    let raw = blob(2000, 1);
    let m = CrushMap::decode(&raw).unwrap();
    assert_eq!(m.choose_args.len(), 1);
    assert_eq!(m.choose_args.values().map(|a| a.len()).sum::<usize>(), 1);
}

/// Short positions have implicit zero tails; decoding must not materialize the
/// cartesian product of bucket entries and position headers.
#[test]
fn short_weight_positions_do_not_amplify_decode_memory() {
    let raw = short_positions_blob(4096, 4096);
    assert!(raw.len() < 64 * 1024);
    let (decoded, peak) = peak_during(|| CrushMap::decode(&raw).unwrap());
    assert!(
        peak < raw.len() * 64,
        "peak {peak} B for {} B input",
        raw.len()
    );
    assert_eq!(
        decoded.choose_args[&-1].get(0).unwrap().weight_set.len(),
        4096
    );
}

#[test]
fn short_positions_map_and_encode_like_explicit_zero_tails() {
    use crush::*;
    let mut canonical = CrushMap::new();
    canonical.add_bucket(Bucket::straw2(
        -1,
        1,
        &[(0, 0x10000), (1, 0x10000), (2, 0x10000)],
    ));
    canonical.add_rule(
        0,
        Rule::new(
            RULE_REPLICATED,
            vec![
                Step::new(OP_TAKE, -1, 0),
                Step::new(OP_CHOOSE_FIRSTN, 0, 0),
                Step::new(OP_EMIT, 0, 0),
            ],
        ),
    );
    let mut raw = canonical.encode();
    raw.truncate(raw.len() - 12);
    u32v(&mut raw, 1);
    raw.extend_from_slice(&(-1i64).to_le_bytes());
    u32v(&mut raw, 1);
    u32v(&mut raw, 0);
    u32v(&mut raw, 2);
    u32v(&mut raw, 1); // one encoded weight, two implicit zeroes
    u32v(&mut raw, 0x10000);
    u32v(&mut raw, 2); // two encoded weights, one implicit zero
    u32v(&mut raw, 0);
    u32v(&mut raw, 0x10000);
    u32v(&mut raw, 0);
    u32v(&mut raw, 100);
    u32v(&mut raw, 100);
    let decoded = CrushMap::decode(&raw).unwrap();
    canonical.choose_args.insert(
        -1,
        [(
            0,
            ChooseArg {
                weight_set: vec![vec![0x10000, 0, 0], vec![0, 0x10000, 0]],
                ids: vec![],
            },
        )]
        .into_iter()
        .collect(),
    );
    assert_eq!(decoded.encode(), canonical.encode());
    for map in [&decoded, &canonical] {
        let mut ws = Workspace::new(map, 2);
        for x in 0..16 {
            let mut out = [ITEM_NONE; 2];
            assert_eq!(
                map.do_rule(
                    0,
                    x,
                    &mut out,
                    &[0x10000; 3],
                    map.choose_args_for(1),
                    &mut ws
                ),
                2
            );
            assert_eq!(out, [0, 1]);
        }
    }
}

#[test]
fn inconsistent_short_positions_keep_canonical_weight_fallback() {
    use crush::*;
    let mut map = CrushMap::new();
    let mut unsupported = Bucket::straw2(-1, 1, &[(0, 0x10000)]);
    unsupported.kind = BucketKind::Uniform {
        item_weight: 0x10000,
    };
    map.add_bucket(unsupported);
    map.add_bucket(Bucket::straw2(-2, 1, &[(0, 0x10000), (1, 0x10000)]));
    map.add_rule(
        0,
        Rule::new(
            RULE_REPLICATED,
            vec![
                Step::new(OP_TAKE, -2, 0),
                Step::new(OP_CHOOSE_FIRSTN, 0, 0),
                Step::new(OP_EMIT, 0, 0),
            ],
        ),
    );
    let canonical = map.clone();
    map.choose_args.insert(
        -1,
        [
            (
                0,
                ChooseArg {
                    weight_set: vec![vec![0x10000]],
                    ids: vec![],
                },
            ),
            (
                1,
                ChooseArg {
                    weight_set: vec![vec![], vec![]],
                    ids: vec![],
                },
            ),
        ]
        .into_iter()
        .collect(),
    );
    // First arg defines one normalized position even though its uniform bucket
    // causes it to be dropped. The surviving two-position arg is not resized.
    let decoded = CrushMap::decode(&map.encode()).unwrap();
    assert!(decoded.choose_args[&-1].get(0).is_none());
    let mut scratch_a = Workspace::new(&decoded, 2);
    let mut scratch_b = Workspace::new(&canonical, 2);
    for x in 0..64 {
        let mut actual = [ITEM_NONE; 2];
        let mut expected = actual;
        assert_eq!(
            decoded.do_rule(
                0,
                x,
                &mut actual,
                &[0x10000; 2],
                decoded.choose_args_for(1),
                &mut scratch_a
            ),
            2
        );
        assert_eq!(
            canonical.do_rule(0, x, &mut expected, &[0x10000; 2], None, &mut scratch_b),
            2
        );
        assert_eq!(actual, expected);
    }
}

/// One straw2 bucket of `items` items and one choose_args arg with `positions` empty weight
/// positions: the canonical form pads every position to `items` weights.
fn short_positions_blob(items: i32, positions: u32) -> Vec<u8> {
    use crush::Bucket;
    let mut map = CrushMap::new();
    let ids: Vec<_> = (0..items).map(|id| (id, 0x10000)).collect();
    map.add_bucket(Bucket::straw2(-1, 1, &ids));
    let mut raw = map.encode();
    // Replace the empty choose_args map and the two trailing MSR tunables.
    raw.truncate(raw.len() - 12);
    u32v(&mut raw, 1); // maps
    raw.extend_from_slice(&(-1i64).to_le_bytes());
    u32v(&mut raw, 1); // args
    u32v(&mut raw, 0); // bucket index
    u32v(&mut raw, positions);
    for _ in 0..positions {
        u32v(&mut raw, 0); // empty position
    }
    u32v(&mut raw, 0); // ids
    u32v(&mut raw, 100);
    u32v(&mut raw, 100);
    raw
}

/// The canonical length of a compact input whose padded form exceeds 4 GiB is computed without
/// materializing it (the caller decides before encoding; classic bufferlists cap at u32).
#[test]
fn canonical_len_of_padded_form_needs_no_padded_allocation() {
    let raw = short_positions_blob(32768, 32768);
    assert!(raw.len() < 512 * 1024);
    let m = CrushMap::decode(&raw).unwrap();
    let (len, peak) = peak_during(|| m.encoded_len_with_features(u64::MAX));
    assert!(len > u64::from(u32::MAX), "canonical {len} B");
    assert!(peak < raw.len(), "peak {peak} B");
    // Small instance: the counted length is what the encoder writes.
    let small = CrushMap::decode(&short_positions_blob(64, 8)).unwrap();
    let bytes = small.encode_with_features(u64::MAX);
    assert_eq!(
        small.encoded_len_with_features(u64::MAX),
        bytes.len() as u64
    );
    assert_eq!(CrushMap::decode(&bytes).unwrap().encode(), bytes);
}
