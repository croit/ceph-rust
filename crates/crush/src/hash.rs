// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! rjenkins1 hash family (spec crush.md sec 5) and `crush_ln`.

use crate::tables::{LL, RH_LH};

const SEED: u32 = 1_315_423_911;
const X0: u32 = 231_232;
const Y0: u32 = 1_232;

/// Jenkins 96-bit mix (shared with the osdmap object-name hash).
#[inline(always)]
pub fn mix(a: &mut u32, b: &mut u32, c: &mut u32) {
    *a = a.wrapping_sub(*b).wrapping_sub(*c) ^ (*c >> 13);
    *b = b.wrapping_sub(*c).wrapping_sub(*a) ^ (*a << 8);
    *c = c.wrapping_sub(*a).wrapping_sub(*b) ^ (*b >> 13);
    *a = a.wrapping_sub(*b).wrapping_sub(*c) ^ (*c >> 12);
    *b = b.wrapping_sub(*c).wrapping_sub(*a) ^ (*a << 16);
    *c = c.wrapping_sub(*a).wrapping_sub(*b) ^ (*b >> 5);
    *a = a.wrapping_sub(*b).wrapping_sub(*c) ^ (*c >> 3);
    *b = b.wrapping_sub(*c).wrapping_sub(*a) ^ (*a << 10);
    *c = c.wrapping_sub(*a).wrapping_sub(*b) ^ (*b >> 15);
}

pub fn hash32_1(mut a: u32) -> u32 {
    let mut h = SEED ^ a;
    let mut b = a;
    let (mut x, mut y) = (X0, Y0);
    mix(&mut b, &mut x, &mut h);
    mix(&mut y, &mut a, &mut h);
    h
}

pub fn hash32_2(mut a: u32, mut b: u32) -> u32 {
    let mut h = SEED ^ a ^ b;
    let (mut x, mut y) = (X0, Y0);
    mix(&mut a, &mut b, &mut h);
    mix(&mut x, &mut a, &mut h);
    mix(&mut b, &mut y, &mut h);
    h
}

pub fn hash32_3(mut a: u32, mut b: u32, mut c: u32) -> u32 {
    let mut h = SEED ^ a ^ b ^ c;
    let (mut x, mut y) = (X0, Y0);
    mix(&mut a, &mut b, &mut h);
    mix(&mut c, &mut x, &mut h);
    mix(&mut y, &mut a, &mut h);
    mix(&mut b, &mut x, &mut h);
    mix(&mut y, &mut c, &mut h);
    h
}

pub fn hash32_4(mut a: u32, mut b: u32, mut c: u32, mut d: u32) -> u32 {
    let mut h = SEED ^ a ^ b ^ c ^ d;
    let (mut x, mut y) = (X0, Y0);
    mix(&mut a, &mut b, &mut h);
    mix(&mut c, &mut d, &mut h);
    mix(&mut a, &mut x, &mut h);
    mix(&mut y, &mut b, &mut h);
    mix(&mut c, &mut x, &mut h);
    mix(&mut y, &mut d, &mut h);
    h
}

pub fn hash32_5(mut a: u32, mut b: u32, mut c: u32, mut d: u32, mut e: u32) -> u32 {
    let mut h = SEED ^ a ^ b ^ c ^ d ^ e;
    let (mut x, mut y) = (X0, Y0);
    mix(&mut a, &mut b, &mut h);
    mix(&mut c, &mut d, &mut h);
    mix(&mut e, &mut x, &mut h);
    mix(&mut y, &mut a, &mut h);
    mix(&mut b, &mut x, &mut h);
    mix(&mut y, &mut c, &mut h);
    mix(&mut d, &mut x, &mut h);
    mix(&mut y, &mut e, &mut h);
    h
}

/// Bucket-selected hash: 0 = rjenkins1, anything else degenerates to 0.
#[inline(always)]
pub fn bh3(kind: u8, a: u32, b: u32, c: u32) -> u32 {
    if kind == 0 { hash32_3(a, b, c) } else { 0 }
}
#[inline(always)]
pub fn bh4(kind: u8, a: u32, b: u32, c: u32, d: u32) -> u32 {
    if kind == 0 { hash32_4(a, b, c, d) } else { 0 }
}

/// 2^44 * log2(xin + 1), fixed point (spec crush.md sec 6.1). The domain is the 16-bit straw2 draw
/// (`xin` <= 0xffff); larger inputs are clamped to 0xffff.
#[inline]
pub fn crush_ln(xin: u32) -> u64 {
    let mut x = xin.min(0xffff) + 1;
    let mut iexpon: u32 = 15;
    if x & 0x18000 == 0 {
        let bits = (x & 0x1FFFF).leading_zeros() - 16;
        x <<= bits;
        iexpon = 15 - bits;
    }
    let index1 = ((x >> 8) << 1) as usize;
    let rh = RH_LH[index1 - 256];
    let lh = RH_LH[index1 + 1 - 256];
    let xl = (x as u64 * rh) >> 48;
    let ll = LL[(xl & 0xff) as usize];
    ((iexpon as u64) << 44) + ((lh + ll) >> 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_vectors() {
        assert_eq!(hash32_1(0), 398764043);
        assert_eq!(hash32_1(1), 3574081617);
        assert_eq!(hash32_1(12345), 3450610134);
        assert_eq!(hash32_2(1, 2), 3079532188);
        assert_eq!(hash32_2(0, 0), 430787817);
        assert_eq!(hash32_2(0xffff_ffff, 7), 2874985758);
        assert_eq!(hash32_3(1, 2, 3), 1935332395);
        assert_eq!(hash32_3(0, 0, 0), 2050749362);
        assert_eq!(hash32_3(100, 0xffff_ffff, 5), 2867513237);
        assert_eq!(hash32_4(1, 2, 3, 4), 1768759062);
        assert_eq!(hash32_4(0, 0, 0, 0), 1068478541);
        assert_eq!(hash32_5(1, 2, 3, 4, 5), 1262657953);
        assert_eq!(hash32_5(0, 0, 0, 0, 0), 2757644291);
    }

    #[test]
    fn ln_vectors() {
        for (i, v) in [
            (0, 0x0),
            (1, 0x100000000000),
            (2, 0x195c01a39fbd),
            (255, 0x800000000000),
            (256, 0x80171e3b6d7a),
            (32767, 0xf00000000000),
            (32768, 0xf0002e2a60a0),
            (43690, 0xf6a3fbbe0d52),
            (65534, 0xfffffd61ad10),
            (65535, 0xfffff0000000),
        ] {
            assert_eq!(crush_ln(i), v, "ln({i})");
        }
    }
}
