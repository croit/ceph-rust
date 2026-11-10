// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Free-space reports (adr 0021 am. 20, doc/spec/store-report.md): merge, fragmentation rating and score of a list of
//! free extents. Pure functions over `(first block, blocks)` runs; the extents come from `Store::free_extents`.

use crate::BLK;

/// Sort and merge touching runs; empty runs are dropped (the score grades runs by length: 0 has no grade).
pub fn merge_extents(v: &mut Vec<(u64, u64)>) {
    v.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(v.len());
    for &(s, n) in v.iter().filter(|e| e.1 > 0) {
        match out.last_mut() {
            Some(l) if l.0 + l.1 == s => l.1 += n,
            _ => out.push((s, n)),
        }
    }
    *v = out;
}

/// Rating 0 (one run) .. 1 (every free block its own run): `(runs - 1) / (free blocks - 1)`; 0 for <= 1 free block.
pub fn fragmentation_rating(ext: &[(u64, u64)]) -> f64 {
    let free: u64 = ext.iter().map(|e| e.1).sum();
    if free <= 1 {
        return 0.0;
    }
    (ext.len() as f64 - 1.0) / (free as f64 - 1.0)
}

/// Worth of one free run of `v` bytes. Runs are graded by floor(log2 v); the worth per byte of grade k+1 is the
/// worth of grade k times a factor: 1.2 (a run twice as long is worth 20% more per byte) up to 1 MiB runs, falling
/// linearly to 1.0 at 128 MiB, 1.0 beyond. Inside a grade the worth is interpolated linearly between its ends.
fn worth(v: u64, scales: &[f64]) -> f64 {
    let g = 63 - v.leading_zeros() as usize;
    let base = (1u64 << g) as f64;
    let x = (v as f64 - base) / base;
    base * scales[g] * (1.0 - x) + 2.0 * base * scales[g + 1] * x
}

fn scales() -> Vec<f64> {
    let mut s = vec![1.0f64];
    while s.len() <= 65 {
        let k = s.len();
        let f = if k >= 27 {
            1.0
        } else if k > 20 {
            (1.0 * (k - 20) as f64 + 1.2 * (27 - k) as f64) / 7.0
        } else {
            1.2
        };
        s.push(s[k - 1] * f);
    }
    s
}

/// Score 0 (all free space in one run) .. 1 (all in single blocks): where the total worth of the runs lies between the
/// worth of one run of all the free space and of every block alone. 0 without free space. An empty run (a caller that
/// did not merge the free runs first) contributes nothing, not a grade of a zero length.
pub fn fragmentation_score(ext: &[(u64, u64)]) -> f64 {
    let runs = || ext.iter().filter(|e| e.1 > 0);
    let sum: u64 = runs().map(|e| e.1 * BLK as u64).sum();
    if sum <= BLK as u64 {
        return 0.0;
    }
    let sc = scales();
    let got: f64 = runs().map(|e| worth(e.1 * BLK as u64, &sc)).sum();
    let ideal = worth(sum, &sc);
    let terrible = (sum / BLK as u64) as f64 * worth(BLK as u64, &sc);
    if ideal <= terrible {
        return 0.0;
    }
    (ideal - got) / (ideal - terrible)
}

/// Allocator name of the (single) data allocator in the classic-shaped reports.
pub const ALLOC_NAME: &str = "block";

/// Classic `bluestore allocator dump block` shape: capacity, allocation unit, type, name and the free extents as hex
/// byte offset/length strings. `ext` = free runs in blocks (as `Store::free_extents`), `capacity` in bytes.
pub fn dump_json(capacity: u64, ext: &[(u64, u64)]) -> String {
    let mut s = format!(
        "{{\"capacity\":{capacity},\"alloc_unit\":{BLK},\"alloc_type\":\"bitmap\",\"alloc_name\":\"{ALLOC_NAME}\",\"extents\":["
    );
    for (i, &(b, n)) in ext.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s += &format!(
            "{{\"offset\":\"{:#x}\",\"length\":\"{:#x}\"}}",
            b * BLK as u64,
            n * BLK as u64
        );
    }
    s + "]}"
}

/// Native `store free` shape (same fields as `croit-flashstore-tool free --format json`): free bytes, run count, largest run, both
/// fragmentation measures; `extent_list` (byte `[offset, length]` pairs) only with `with_extents`.
pub fn free_json(capacity: u64, ext: &[(u64, u64)], with_extents: bool) -> String {
    let b = BLK as u64;
    let mut s = format!(
        "{{\"capacity\":{capacity},\"free_bytes\":{},\"extents\":{},\"largest_extent\":{},\"fragmentation_score\":{:.6},\"fragmentation_rating\":{:.6}",
        ext.iter().map(|e| e.1 * b).sum::<u64>(),
        ext.len(),
        ext.iter().map(|e| e.1 * b).max().unwrap_or(0),
        fragmentation_score(ext),
        fragmentation_rating(ext)
    );
    if with_extents {
        s += ",\"extent_list\":[";
        for (i, e) in ext.iter().enumerate() {
            s += &format!("{}[{},{}]", if i > 0 { "," } else { "" }, e.0 * b, e.1 * b);
        }
        s.push(']');
    }
    s + "}"
}

/// Classic `bluestore allocator score block` shape.
pub fn score_json(ext: &[(u64, u64)]) -> String {
    format!(
        "{{\"fragmentation_score\":{:.6}}}",
        fragmentation_score(ext)
    )
}

/// Classic `bluestore allocator fragmentation block` shape.
pub fn rating_json(ext: &[(u64, u64)]) -> String {
    format!(
        "{{\"fragmentation_rating\":{:.6}}}",
        fragmentation_rating(ext)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_sorts_and_joins_touching_runs() {
        let mut v = vec![(10, 5), (0, 4), (4, 6), (30, 1)];
        merge_extents(&mut v);
        assert_eq!(v, vec![(0, 15), (30, 1)]);
        let mut v = vec![(7, 0), (3, 2), (5, 0)];
        merge_extents(&mut v);
        assert_eq!(v, vec![(3, 2)], "empty runs dropped");
        assert!(fragmentation_score(&v) >= 0.0);
    }

    #[test]
    fn json_shapes_are_the_classic_ones() {
        let ext = [(1, 2), (10, 1)];
        assert_eq!(
            dump_json(1 << 20, &ext),
            r#"{"capacity":1048576,"alloc_unit":4096,"alloc_type":"bitmap","alloc_name":"block","extents":[{"offset":"0x1000","length":"0x2000"},{"offset":"0xa000","length":"0x1000"}]}"#
        );
        assert_eq!(
            dump_json(0, &[]),
            r#"{"capacity":0,"alloc_unit":4096,"alloc_type":"bitmap","alloc_name":"block","extents":[]}"#
        );
        assert_eq!(rating_json(&ext), r#"{"fragmentation_rating":0.500000}"#);
        assert!(score_json(&ext).starts_with(r#"{"fragmentation_score":"#));
    }

    #[test]
    fn rating_bounds() {
        assert_eq!(fragmentation_rating(&[]), 0.0);
        assert_eq!(fragmentation_rating(&[(0, 1)]), 0.0);
        assert_eq!(fragmentation_rating(&[(0, 1000)]), 0.0);
        // every free block alone
        let ext: Vec<_> = (0..100).map(|i| (i * 2, 1)).collect();
        assert!((fragmentation_rating(&ext) - 1.0).abs() < 1e-12);
        // 2 runs of 50
        let r = fragmentation_rating(&[(0, 50), (100, 50)]);
        assert!((r - 1.0 / 99.0).abs() < 1e-12);
    }

    /// A zero-length free run (a caller that did not merge first) scores like an absent one: a grade of a zero length
    /// would underflow (`63 - 64`).
    #[test]
    fn empty_runs_score_like_absent_ones() {
        assert_eq!(fragmentation_score(&[(0, 0)]), 0.0);
        assert_eq!(
            fragmentation_score(&[(0, 0), (0, 100)]),
            fragmentation_score(&[(0, 100)])
        );
        assert_eq!(
            fragmentation_score(&[(7, 0), (3, 50), (0, 0)]),
            fragmentation_score(&[(3, 50)])
        );
    }

    #[test]
    fn score_bounds_and_order() {
        assert_eq!(fragmentation_score(&[]), 0.0);
        assert_eq!(fragmentation_score(&[(5, 1)]), 0.0);
        let one = fragmentation_score(&[(0, 4096)]);
        assert!(one.abs() < 1e-9, "{one}");
        let singles: Vec<_> = (0..4096).map(|i| (i * 2, 1)).collect();
        let s = fragmentation_score(&singles);
        assert!((s - 1.0).abs() < 1e-9, "{s}");
        let halves = fragmentation_score(&[(0, 2048), (9000, 2048)]);
        let quarters: Vec<_> = (0..4).map(|i| (i * 5000, 1024)).collect();
        let q = fragmentation_score(&quarters);
        assert!(0.0 < halves && halves < q && q < 1.0, "{halves} {q}");
    }
}
