// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Malformed input: client op messages / replies with hostile counts and lengths (not only bit flips) decode to `Err`
//! or a value, never panic, never allocate from an unchecked wire count (E11).
mod common;
use common::*;
use denc::Error;
use opwire::*;

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
        (self.next() % n.max(1) as u64) as usize
    }
    /// 1-4 edits: bit flip, hostile 32/64-bit value, random byte; sometimes a truncation.
    fn mutate(&mut self, b: &mut Vec<u8>) {
        if b.is_empty() {
            return;
        }
        for _ in 0..1 + self.below(4) {
            let at = self.below(b.len());
            let hostile: [u8; 8] = match self.below(3) {
                0 => [0xff; 8],
                1 => [0xff, 0xff, 0xff, 0x7f, 0, 0, 0, 0],
                _ => [0, 0, 0, 1, 0, 0, 0, 0],
            };
            match self.below(3) {
                0 => b[at] ^= 1 << self.below(8),
                1 => {
                    let end = (at + 8).min(b.len());
                    b[at..end].copy_from_slice(&hostile[..end - at]);
                }
                _ => b[at] = self.next() as u8,
            }
        }
        if self.below(5) == 0 {
            let cut = self.below(b.len());
            b.truncate(cut);
        }
    }
}

#[test]
fn client_messages_with_hostile_values_never_panic() {
    let mut r = Rng(0x5eed_00b5);
    let mut n = 0;
    for (_, bytes) in capture_files().iter().take(40) {
        let Some(frs) = frames(bytes) else { continue };
        for (h, front, mid, data) in frs
            .into_iter()
            .filter(|f| matches!(f.0.ty, 42 | 43))
            .take(20)
        {
            for _ in 0..50 {
                let mut f = front.clone();
                r.mutate(&mut f);
                let _ = decode_client_parts(h.ty, h.version, &f, &mid, &data);
                n += 1;
            }
        }
    }
    assert!(n > 0);
}

/// E11: an omap section whose count exceeds what its bytes can hold is refused before any allocation from it.
#[test]
fn omap_section_count_bomb() {
    let mut b = u32::MAX.to_le_bytes().to_vec();
    b.extend_from_slice(&[0; 8]);
    assert!(matches!(
        parse_omap_section(&b),
        Err(Error::BadLength { .. })
    ));
    let mut r = Rng(0x5eed_003a);
    let good = {
        let mut v = 2u32.to_le_bytes().to_vec();
        for (k, val) in [(b"k1".as_slice(), b"v1".as_slice()), (b"k2", b"")] {
            v.extend_from_slice(&(k.len() as u32).to_le_bytes());
            v.extend_from_slice(k);
            v.extend_from_slice(&(val.len() as u32).to_le_bytes());
            v.extend_from_slice(val);
        }
        v
    };
    assert_eq!(parse_omap_section(&good).unwrap().len(), 2);
    for _ in 0..2000 {
        let mut b = good.clone();
        r.mutate(&mut b);
        let _ = parse_omap_section(&b);
    }
}
