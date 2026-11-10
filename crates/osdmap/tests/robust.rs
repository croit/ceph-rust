// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Malformed-input robustness: full maps and incrementals with random flips, truncations and hostile counts decode to
//! `Err` (or a map), never panic, never allocate from an unchecked wire count.
use osdmap::{Error, Incremental, OsdMap};

#[test]
fn osd_slot_limit_rejects_full_maps_before_array_decode() {
    let mut m = OsdMap::default();
    for max_osd in [osdmap::consts::MAX_OSD_SLOTS + 1, i32::MAX] {
        m.max_osd = max_osd;
        let bytes = m.encode_full().unwrap();
        assert!(matches!(
            OsdMap::decode_from(&bytes),
            Err(Error::Denc(denc::Error::BadValue(
                "max_osd exceeds MAX_OSD_SLOTS"
            )))
        ));
    }
}

#[test]
fn osd_slot_limit_rejects_incrementals_before_apply() {
    let mut inc = Incremental::default();
    for max_osd in [osdmap::consts::MAX_OSD_SLOTS + 1, i32::MAX] {
        inc.new_max_osd = max_osd;
        let bytes = inc.encode_inc().unwrap();
        assert!(matches!(
            Incremental::decode_from(&bytes),
            Err(Error::Denc(denc::Error::BadValue(
                "new_max_osd exceeds MAX_OSD_SLOTS"
            )))
        ));
        let mut base = OsdMap::default();
        assert!(matches!(
            base.apply_incremental(&inc),
            Err(Error::Denc(denc::Error::BadValue(_)))
        ));
        assert_eq!(base.max_osd, 0);
    }
    // The inclusive boundary and the no-change sentinel remain accepted.
    for max_osd in [-1, 0, osdmap::consts::MAX_OSD_SLOTS] {
        inc.new_max_osd = max_osd;
        assert_eq!(
            Incremental::decode_from(&inc.encode_inc().unwrap())
                .unwrap()
                .new_max_osd,
            max_osd
        );
    }
}

fn fixture(p: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/osdmap")
            .join(p),
    )
    .unwrap()
}

/// xorshift64*: seeded, reproducible.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Flip / overwrite with hostile values / truncate: `iters` variants of `base`.
fn mutations(base: &[u8], seed: u64, iters: usize) -> impl Iterator<Item = Vec<u8>> + '_ {
    let mut r = Rng(seed);
    (0..iters).map(move |_| {
        let mut b = base.to_vec();
        for _ in 0..1 + r.below(4) {
            let at = r.below(b.len());
            match r.below(3) {
                0 => b[at] ^= 1 << r.below(8),
                1 => {
                    let end = (at + 4).min(b.len());
                    b[at..end].copy_from_slice(&[0xff, 0xff, 0xff, 0x7f][..end - at]);
                }
                _ => b[at] = r.next() as u8,
            }
        }
        if r.below(4) == 0 {
            b.truncate(r.below(b.len()));
        }
        b
    })
}

#[test]
fn full_map_mutations_never_panic() {
    let base = fixture("full/0091.bin");
    for b in mutations(&base, 0x5eed_0091, 3000) {
        let _ = OsdMap::decode_opts(&b, false);
    }
}

#[test]
fn incremental_mutations_never_panic() {
    for p in ["inc/0002.bin", "inc/0003.bin"] {
        let base = fixture(p);
        for b in mutations(&base, 0x5eed_0002, 2000) {
            let _ = Incremental::decode_opts(&b, false);
        }
    }
}

/// A hand-built map whose per-osd arrays are shorter than `max_osd` reports "no such osd" instead of panicking: the
/// accessors must not trust `max_osd` alone (spec 1.7 keeps the arrays at `max_osd`, but nothing enforces it for a map
/// assembled in memory).
#[test]
fn accessors_tolerate_a_partial_map() {
    let mut m = OsdMap::default();
    m.max_osd = 1; // per-osd arrays left empty
    assert!(!m.exists(0));
    assert!(!m.is_up(0));
    assert!(!m.is_full(0));
    assert!(!m.is_in(0));
    assert!(m.is_out(0));
    assert!(!m.is_noup(0));
    assert_eq!(m.raw_state(0), 0);
    assert_eq!(m.weight(0), 0);
    assert_eq!(m.primary_affinity(0), osdmap::consts::WEIGHT_IN);
    assert_eq!(m.num_osd(), 0);
    assert_eq!(m.num_up_osd(), 0);
}

/// E4: a `max_osd` above the per-osd arrays on the wire is refused (no resize to the wire value).
#[test]
fn max_osd_beyond_arrays_is_refused() {
    let mut m = OsdMap::decode_from(&fixture("full/0091.bin")).unwrap();
    let n = m.osd_state.len();
    m.max_osd = n as i32 + 1;
    let b = m.encode_full().unwrap();
    assert!(matches!(OsdMap::decode_from(&b), Err(Error::Invalid(_))));
    m.max_osd = -1;
    let b = m.encode_full().unwrap();
    assert!(matches!(OsdMap::decode_from(&b), Err(Error::Invalid(_))));
    m.max_osd = n as i32;
    let b = m.encode_full().unwrap();
    assert_eq!(OsdMap::decode_from(&b).unwrap().max_osd, n as i32);
}
