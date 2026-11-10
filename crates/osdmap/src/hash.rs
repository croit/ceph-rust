// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Object-name hashes, stable_mod and the rjenkins 2-input hash (spec osdmap.md 4.1, 4.2, 5).

use crush::hash::mix;

/// pg_pool_t object_hash: linux dcache.
pub const STR_HASH_LINUX: u8 = 1;
/// pg_pool_t object_hash: rjenkins.
pub const STR_HASH_RJENKINS: u8 = 2;

/// Bob Jenkins lookup2 string hash as used for object names.
pub fn str_hash_rjenkins(k: &[u8]) -> u32 {
    str_hash_rjenkins_parts(&[k])
}

/// [`str_hash_rjenkins`] over consecutive byte segments: the 12-byte chunks are mixed in place, a chunk straddling a
/// segment boundary is assembled in a stack buffer. No heap use, so a namespaced key never gets copied into one.
fn str_hash_rjenkins_parts(parts: &[&[u8]]) -> u32 {
    let n: usize = parts.iter().map(|p| p.len()).sum();
    let (mut a, mut b, mut c) = (0x9e37_79b9u32, 0x9e37_79b9u32, 0u32);
    let mut chunk = [0u8; 12];
    let mut filled = 0usize;
    for part in parts {
        let mut rest = *part;
        if filled > 0 {
            let take = (12 - filled).min(rest.len());
            chunk[filled..filled + take].copy_from_slice(&rest[..take]);
            filled += take;
            rest = &rest[take..];
            if filled < 12 {
                continue;
            }
            add_chunk(&mut a, &mut b, &mut c, &chunk);
            filled = 0;
        }
        while rest.len() >= 12 {
            add_chunk(&mut a, &mut b, &mut c, &rest[..12]);
            rest = &rest[12..];
        }
        if !rest.is_empty() {
            chunk[..rest.len()].copy_from_slice(rest);
            filled = rest.len();
        }
    }
    c = c.wrapping_add(n as u32);
    for (i, &x) in chunk[..filled].iter().enumerate() {
        let x = x as u32;
        match i {
            0..=3 => a = a.wrapping_add(x << (8 * i)),
            4..=7 => b = b.wrapping_add(x << (8 * (i - 4))),
            _ => c = c.wrapping_add(x << (8 * (i - 8) + 8)),
        }
    }
    mix(&mut a, &mut b, &mut c);
    c
}

/// One full 12-byte chunk of the rjenkins input.
#[inline]
fn add_chunk(a: &mut u32, b: &mut u32, c: &mut u32, w: &[u8]) {
    *a = a.wrapping_add(u32::from_le_bytes([w[0], w[1], w[2], w[3]]));
    *b = b.wrapping_add(u32::from_le_bytes([w[4], w[5], w[6], w[7]]));
    *c = c.wrapping_add(u32::from_le_bytes([w[8], w[9], w[10], w[11]]));
    mix(a, b, c);
}

/// Linux dcache name hash.
pub fn str_hash_linux(k: &[u8]) -> u32 {
    str_hash_linux_parts(&[k])
}

fn str_hash_linux_parts(parts: &[&[u8]]) -> u32 {
    let mut h = 0u32;
    for part in parts {
        for &c in *part {
            let c = c as u32;
            h = h.wrapping_add(c << 4).wrapping_add(c >> 4).wrapping_mul(11);
        }
    }
    h
}

/// Dispatch on pool object_hash type; invalid type -> 0xFFFFFFFF.
pub fn str_hash(ty: u8, k: &[u8]) -> u32 {
    str_hash_parts(ty, &[k])
}

fn str_hash_parts(ty: u8, parts: &[&[u8]]) -> u32 {
    match ty {
        STR_HASH_LINUX => str_hash_linux_parts(parts),
        STR_HASH_RJENKINS => str_hash_rjenkins_parts(parts),
        _ => 0xFFFF_FFFF,
    }
}

/// Placement hash input: key, or nspace 0x1F key (spec 5.2), hashed segment-wise (no joined copy).
pub fn hash_key(ty: u8, nspace: &[u8], key: &[u8]) -> u32 {
    if nspace.is_empty() {
        str_hash(ty, key)
    } else {
        str_hash_parts(ty, &[nspace, &[0x1f], key])
    }
}

/// ceph_stable_mod.
#[inline]
pub fn stable_mod(x: u32, b: u32, bmask: u32) -> u32 {
    let t = x & bmask;
    if t < b { t } else { x & (bmask >> 1) }
}

/// Bit mask [`stable_mod`] expects for a count `n`: 2^cbits(n-1) - 1 (n = 0 -> all ones).
pub fn stable_mask(n: u32) -> u32 {
    // n == 0: (n-1) in 64-bit math is all ones, i.e. 64 significant bits.
    let b = cbits((n as u64).wrapping_sub(1));
    if b >= 32 { u32::MAX } else { (1u32 << b) - 1 }
}

/// rjenkins1 2-input crush hash (hash type 0).
pub use crush::hash::hash32_2 as crush_hash32_2;

/// Number of significant bits (cbits(0) = 0).
pub fn cbits(x: u64) -> u32 {
    64 - x.leading_zeros()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_mod_basics() {
        // pg_num 12, mask 15
        assert_eq!(stable_mod(5, 12, 15), 5);
        assert_eq!(stable_mod(13, 12, 15), 5);
        assert_eq!(stable_mod(0xffff_ffff, 8, 7), 7);
    }

    #[test]
    fn stable_mask_values() {
        assert_eq!(stable_mask(0), u32::MAX);
        assert_eq!(stable_mask(1), 0);
        assert_eq!(stable_mask(8), 7);
        assert_eq!(stable_mask(12), 15);
        assert_eq!(stable_mask(1 << 20), (1 << 20) - 1);
        assert_eq!(stable_mask(u32::MAX), u32::MAX);
    }

    #[test]
    fn linux_hash_known() {
        assert_eq!(str_hash_linux(b""), 0);
        assert_eq!(
            str_hash_linux(b"a"),
            (97u32 << 4).wrapping_add(97 >> 4).wrapping_mul(11)
        );
    }
}
