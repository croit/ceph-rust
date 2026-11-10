// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Malformed-input robustness: crush blobs with random flips, hostile values and truncations decode to `Err` (or a map),
//! never panic; the wire `max_devices` never decides placement.
use crush::{CrushMap, Workspace};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/crush")
            .join(name),
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

#[test]
fn decode_mutations_never_panic() {
    let base = fixture("lab.bin");
    let mut r = Rng(0x5eed_c805);
    for _ in 0..4000 {
        let mut b = base.clone();
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
        let _ = CrushMap::decode(&b);
    }
}

/// E5: a wire `max_devices` below the device ids the buckets use (stale / hand-edited blob) is recomputed like the
/// incremental path does; placement is the same as with the correct value.
#[test]
fn wire_max_devices_is_recomputed() {
    let base = fixture("lab.bin");
    let good = CrushMap::decode(&base).unwrap();
    assert!(good.max_devices > 1);
    let mut stale = good.clone();
    stale.max_devices = 1;
    let m = CrushMap::decode(&stale.encode()).unwrap();
    assert_eq!(m.max_devices, good.max_devices);
    let weights = vec![0x10000u32; good.max_devices as usize];
    let (mut a, mut b) = ([0i32; 3], [0i32; 3]);
    let (mut wa, mut wb) = (Workspace::new(&good, 3), Workspace::new(&m, 3));
    for x in 0..64 {
        let na = good.do_rule(0, x, &mut a, &weights, None, &mut wa);
        let nb = m.do_rule(0, x, &mut b, &weights, None, &mut wb);
        assert!(na > 0);
        assert_eq!(a[..na], b[..nb]);
    }
}
