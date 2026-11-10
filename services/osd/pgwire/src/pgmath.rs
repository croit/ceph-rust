// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! pgid math of PG split and merge (spec split-merge.md 3): pure functions on 32-bit seeds / hashes.
//!
//! Notation: `cbits(x)` = number of significant bits, `n` = pg_num. One `stable_mod` serves every
//! caller (the mask argument is `pg_num_mask(n)`).

/// Number of significant bits (`cbits(0) = 0`, `cbits(8) = 4`).
pub fn cbits(x: u32) -> u32 {
    32 - x.leading_zeros()
}

/// `ceph_stable_mod(x, n, mask)` with `mask = 2^k - 1 >= n - 1`.
pub fn stable_mod(x: u32, n: u32, mask: u32) -> u32 {
    let t = x & mask;
    if t < n { t } else { x & (mask >> 1) }
}

/// `2^cbits(n-1) - 1` (n <= 1 -> 0): the mask of an object -> PG reduction.
pub fn pg_num_mask(n: u32) -> u32 {
    if n <= 1 {
        0
    } else {
        u32::MAX >> (n - 1).leading_zeros()
    }
}

/// PG seed an object hash belongs to at `pg_num = n` (`pg_pool_t::raw_pg_to_pg`).
pub fn object_pg(hash: u32, n: u32) -> u32 {
    stable_mod(hash, n.max(1), pg_num_mask(n))
}

/// Number of low hash bits PG `seed` owns at `pg_num = n` (`pg_t::get_split_bits`): the PG holds exactly the
/// objects with `hash & (2^bits - 1) == seed`.
pub fn split_bits(seed: u32, n: u32) -> u32 {
    if n <= 1 {
        return 0;
    }
    let p = cbits(n);
    let h = 1u32 << (p - 1);
    if seed % h < n % h { p } else { p - 1 }
}

/// Low-bits mask for `bits` (0 -> 0, 32 -> all ones).
pub fn bits_mask(bits: u32) -> u32 {
    if bits >= 32 {
        u32::MAX
    } else {
        (1u32 << bits) - 1
    }
}

/// Does PG `seed` (owning `bits` low bits) contain an object with `hash`?
pub fn contains(seed: u32, bits: u32, hash: u32) -> bool {
    hash & bits_mask(bits) == seed
}

/// The PG that owned the objects of `seed` when pg_num was `old_n` (`pg_t::get_ancestor`).
pub fn ancestor(seed: u32, old_n: u32) -> u32 {
    stable_mod(seed, old_n.max(1), u32::MAX >> (32 - cbits(old_n.max(1))))
}

/// One binary step up: `seed` with its highest set bit cleared (`pg_t::get_parent`); `seed > 0`.
pub fn parent(seed: u32) -> u32 {
    debug_assert!(seed > 0);
    if seed == 0 {
        0
    } else {
        seed & !(1u32 << (31 - seed.leading_zeros()))
    }
}

/// Children candidates of `seed` when pg_num grows `old_n -> new_n`: `seed + k * 2^(cbits(old_n)-1)` below `new_n`,
/// in `[old_n, new_n)` and with `ancestor(c, old_n) == seed`. `seed < old_n < new_n` is a precondition.
fn split_candidates(seed: u32, old_n: u32, new_n: u32) -> impl Iterator<Item = u32> {
    let step = 1u64 << (cbits(old_n) - 1);
    let mut c = u64::from(seed) + step;
    std::iter::from_fn(move || {
        if c >= u64::from(new_n) {
            return None;
        }
        let at = c as u32;
        c += step;
        Some(at)
    })
    .filter(move |c| *c >= old_n && ancestor(*c, old_n) == seed)
}

/// Children created in `seed` when pg_num grows `old_n -> new_n`: all `c` in `[old_n, new_n)` with
/// `ancestor(c, old_n) == seed`, ascending (grandchildren of multi-level jumps included).
pub fn split_children(seed: u32, old_n: u32, new_n: u32) -> Vec<u32> {
    if !(seed < old_n && old_n < new_n) {
        return vec![];
    }
    split_candidates(seed, old_n, new_n).collect()
}

/// PG `seed` splits when pg_num grows `old_n -> new_n`.
pub fn is_split(seed: u32, old_n: u32, new_n: u32) -> bool {
    seed < old_n && old_n < new_n && split_candidates(seed, old_n, new_n).next().is_some()
}

/// `new_n <= seed < old_n`: the PG disappears into a target when pg_num shrinks `old_n -> new_n`.
pub fn is_merge_source(seed: u32, old_n: u32, new_n: u32) -> bool {
    new_n <= seed && seed < old_n
}

/// Target of source `seed` at `new_n`: repeated `parent` until below `new_n`.
pub fn merge_target(seed: u32, new_n: u32) -> u32 {
    let mut t = seed;
    while t >= new_n && t > 0 {
        t = parent(t);
    }
    t
}

/// Sources absorbed by `target` when pg_num shrinks `old_n -> new_n` (empty if `target` is no target).
pub fn merge_sources(target: u32, old_n: u32, new_n: u32) -> Vec<u32> {
    if target >= new_n {
        return vec![];
    }
    split_children(target, new_n, old_n)
}

/// `seed < new_n` and it would split if pg_num went back up.
pub fn is_merge_target(seed: u32, old_n: u32, new_n: u32) -> bool {
    is_split(seed, new_n, old_n)
}

/// `pg_pool_t::is_pending_merge`: a merge is being prepared (`pending < n`) and `seed` is a source
/// (`[pending, n)`) or the parent of one.
pub fn is_pending_merge(seed: u32, n: u32, pending: u32) -> bool {
    if pending >= n {
        return false;
    }
    if seed >= pending && seed < n {
        return true;
    }
    (pending..n).any(|s| s > 0 && parent(s) == seed)
}

/// Reversed-hash range `[start, end)` (33-bit values; `end` = 2^32 for the last PG) owned by `(seed, bits)`.
pub fn rev_range(seed: u32, bits: u32) -> (u64, u64) {
    let start = u64::from(seed.reverse_bits());
    let width = 1u64 << (32 - bits.min(32));
    (start, start + width)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Brute force: owner of a hash at pg_num n by scanning seeds.
    fn owner_brute(hash: u32, n: u32) -> u32 {
        let owners: Vec<u32> = (0..n)
            .filter(|s| contains(*s, split_bits(*s, n), hash))
            .collect();
        assert_eq!(owners.len(), 1, "hash {hash:#x} n {n}: {owners:?}");
        owners[0]
    }

    #[test]
    fn t1_partition_and_children_for_all_pg_nums() {
        // every hash maps to exactly one PG; stable_mod agrees with the split_bits ownership
        let hashes: Vec<u32> = (0..4096u32)
            .chain([0xdead_beef, 0xffff_ffff, 0x8000_0000, 0x1234_5678])
            .collect();
        for n in 1..=1024u32 {
            for &h in hashes.iter().step_by(if n > 64 { 7 } else { 1 }) {
                assert_eq!(object_pg(h, n), owner_brute(h, n), "n {n} h {h:#x}");
            }
        }
        // children(s, a, b) == {c in [a, b) : ancestor(c, a) == s}
        for a in 1..=70u32 {
            for b in a..=140u32 {
                for s in 0..a {
                    let brute: Vec<u32> = (a..b).filter(|c| ancestor(*c, a) == s).collect();
                    assert_eq!(split_children(s, a, b), brute, "s {s} a {a} b {b}");
                }
                // every new seed has exactly one ancestor-owner among the old PGs
                for c in a..b {
                    let owners = (0..a)
                        .filter(|s| split_children(*s, a, b).contains(&c))
                        .count();
                    assert_eq!(owners, 1);
                }
            }
        }
        // split_bits of a power of two is log2 for every seed
        for k in 0..10 {
            for s in 0..(1u32 << k) {
                assert_eq!(split_bits(s, 1 << k), k);
            }
        }
    }

    #[test]
    fn t1_split_preserves_objects() {
        // after a split a -> b every object of parent s lands in s or one of its children
        for (a, b) in [
            (1, 8),
            (8, 64),
            (12, 16),
            (12, 32),
            (8, 40),
            (5, 9),
            (16, 17),
        ] {
            for h in (0..2000u32).map(|i| i.wrapping_mul(0x9E37_79B1)) {
                let before = object_pg(h, a);
                let after = object_pg(h, b);
                let kids = split_children(before, a, b);
                assert!(after == before || kids.contains(&after), "{a}->{b} {h:#x}");
            }
        }
    }

    #[test]
    fn t2_worked_examples() {
        // 1 -> 2 -> 4 -> 8
        assert_eq!(split_children(0, 1, 2), vec![1]);
        assert_eq!(split_children(0, 2, 4), vec![2]);
        assert_eq!(split_children(1, 2, 4), vec![3]);
        for s in 0..4 {
            assert_eq!(split_children(s, 4, 8), vec![s + 4]);
        }
        assert_eq!(
            (split_bits(0, 2), split_bits(0, 4), split_bits(5, 8)),
            (1, 2, 3)
        );
        // 8 -> 64, seed 3
        assert_eq!(split_children(3, 8, 64), vec![11, 19, 27, 35, 43, 51, 59]);
        for c in split_children(3, 8, 64) {
            assert_eq!(split_bits(c, 64), 6);
        }
        assert_eq!((parent(59), parent(27), parent(11)), (27, 11, 3));
        assert_eq!(ancestor(59, 8), 3);
        // 1 -> 8
        assert_eq!(split_children(0, 1, 8), (1..8).collect::<Vec<_>>());
        // 12 PGs
        for s in [0, 1, 2, 3, 8, 9, 10, 11] {
            assert_eq!(split_bits(s, 12), 4);
        }
        for s in 4..8 {
            assert_eq!(split_bits(s, 12), 3);
        }
        assert_eq!(object_pg(0x0d, 12), 5);
        // 12 -> 16
        assert_eq!(split_children(4, 12, 16), vec![12]);
        assert_eq!(split_children(3, 12, 16), Vec::<u32>::new());
        for s in 4..8 {
            assert_eq!(split_children(s, 12, 16), vec![s + 8]);
        }
        // 12 -> 32
        assert_eq!(split_children(4, 12, 32), vec![12, 20, 28]);
        assert_eq!(split_children(0, 12, 32), vec![16]);
        assert_eq!(split_children(8, 12, 32), vec![24]);
        let total: usize = (0..12).map(|s| split_children(s, 12, 32).len()).sum();
        assert_eq!(total, 20);
        for s in 0..32 {
            assert_eq!(split_bits(s, 32), 5);
        }
        // 8 -> 40
        assert_eq!(split_children(3, 8, 40), vec![11, 19, 27, 35]);
        assert_eq!(split_bits(3, 40), 6);
        for c in [11, 19, 27] {
            assert_eq!(split_bits(c, 40), 5);
        }
        assert_eq!(split_bits(35, 40), 6);
        for s in 8..32 {
            assert_eq!(split_bits(s, 40), 5);
        }
        for s in (0..8).chain(32..40) {
            assert_eq!(split_bits(s, 40), 6);
        }
        // merge 16 -> 8: source 15 -> target 7 ... 8 -> 0
        for src in 8..16u32 {
            assert_eq!(merge_target(src, src), parent(src));
            assert_eq!(merge_target(src, src), src - 8);
        }
        assert_eq!(split_bits(7, 15), 3);
        assert_eq!(split_bits(6, 15), 4);
    }

    #[test]
    fn t3_merge_relations() {
        // 16 -> 15 (S = 15, T = 7)
        assert!(is_merge_source(15, 16, 15));
        assert!(!is_merge_source(14, 16, 15));
        assert!(is_merge_target(7, 16, 15));
        assert!(!is_merge_target(6, 16, 15));
        assert_eq!(merge_target(15, 15), 7);
        assert_eq!(merge_sources(7, 16, 15), vec![15]);
        // 9 -> 8 (S = 8, T = 0)
        assert!(is_merge_source(8, 9, 8));
        assert_eq!(merge_target(8, 8), 0);
        assert!(is_merge_target(0, 9, 8));
        // 2 -> 1 (S = 1, T = 0)
        assert!(is_merge_source(1, 2, 1));
        assert!(is_merge_target(0, 2, 1));
        assert_eq!(merge_sources(0, 2, 1), vec![1]);
        // multi jump 16 -> 4: target 3 absorbs 7, 11, 15
        assert_eq!(merge_sources(3, 16, 4), vec![7, 11, 15]);
        assert_eq!(merge_target(15, 4), 3);
        // pending merge: pg_num 16, pending 15
        assert!(is_pending_merge(15, 16, 15));
        assert!(is_pending_merge(7, 16, 15));
        assert!(!is_pending_merge(6, 16, 15));
        assert!(!is_pending_merge(3, 16, 16));
        assert!(is_pending_merge(0, 2, 1));
        assert!(is_pending_merge(1, 2, 1));
        assert!(is_pending_merge(0, 9, 8));
        // merge is the inverse of split
        for old in 2..=64u32 {
            for new in 1..old {
                for t in 0..new {
                    assert_eq!(merge_sources(t, old, new), split_children(t, new, old));
                }
                for s in new..old {
                    let t = merge_target(s, new);
                    assert!(
                        merge_sources(t, old, new).contains(&s),
                        "{old}->{new} s {s}"
                    );
                }
            }
        }
    }

    #[test]
    fn t4_ranges_cover_hash_space() {
        for n in 1..=100u32 {
            let mut ranges: Vec<(u64, u64)> =
                (0..n).map(|s| rev_range(s, split_bits(s, n))).collect();
            ranges.sort();
            let mut at = 0u64;
            for (a, b) in ranges {
                assert_eq!(a, at, "gap/overlap n {n}");
                at = b;
            }
            assert_eq!(at, 1 << 32, "n {n}");
        }
        // a hash lies in its PG's reversed range
        for n in [1u32, 5, 12, 16, 33] {
            for h in (0..500u32).map(|i| i.wrapping_mul(0x9E37_79B1)) {
                let s = object_pg(h, n);
                let (a, b) = rev_range(s, split_bits(s, n));
                let r = u64::from(h.reverse_bits());
                assert!(a <= r && r < b);
            }
        }
    }
}
