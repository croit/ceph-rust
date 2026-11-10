// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Per-pool support gate (adr 0039, ec-gap.md decision 2). ALLOW-LIST, default deny: a pool is served as an EC shard
//! only if every listed condition holds; anything else is `Unsupported` (fully passive, reason names the feature).
//!
//! Chunk rule: `chunk_size = stripe_width / k` must be a non-zero multiple of the code's alignment unit (the plugin's
//! `get_chunk_size` guarantees it, spec ec-parity.md 7); no 32-byte rule (jerasure bit-matrix chunks such as liberation
//! w=7 ps=4 -> 4144 are not multiples of 32). min_size is taken literally (spec ec-parity.md 12.1).

use crate::code::Code;
use crate::profile::{EcProfile, Plugin};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcMode {
    /// Legacy append-only.
    L0,
    /// Legacy overwrites (`allow_ec_overwrites`).
    L1,
    /// Optimized (`allow_ec_optimizations`, adr 0067): sparse shard layout, partial writes, pwlc.
    Optimized,
}

/// Pool fields the gate needs (from the OSDMap pool + its profile).
#[derive(Debug, Clone, Default)]
pub struct PoolEcInput<'a> {
    pub size: u32,
    pub min_size: u32,
    pub stripe_width: u32,
    pub flag_overwrites: bool,
    pub flag_optimizations: bool,
    pub flag_omap: bool,
    pub profile: Option<&'a BTreeMap<String, String>>,
    /// Pool `nonprimary_shards` (v32): shard ids of raw 1..k-1, set with the optimized flag; empty on legacy pools.
    pub nonprimary_shards: Vec<u32>,
}

/// Everything the shard role needs about a supported pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcFacts {
    pub k: u32,
    pub m: u32,
    pub stripe_width: u32,
    pub chunk_size: u32,
    /// raw chunk index -> shard (len k+m), ec.md 1.
    pub chunk_mapping: Vec<u32>,
    pub mode: EcMode,
    pub plugin: Plugin,
    pub technique: String,
    /// The pool profile (string map): the primary role builds its code from it.
    pub profile: BTreeMap<String, String>,
    /// Mode O only: shard ids of the nonprimary data shards (raw 1..k-1), ascending; empty otherwise.
    pub nonprimary: Vec<u32>,
    /// Sub-chunks per chunk (clay S; 1 for every other plugin): shard sub-chunk reads (spec ec-clay.md 7.1).
    pub sub_chunks: u32,
    /// The primary role may run (clay: MDS scalar we implement, spec ec-clay.md 0.6).
    pub primary_ok: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Supported(EcFacts),
    Unsupported(String),
}

fn no(s: impl Into<String>) -> Verdict {
    Verdict::Unsupported(s.into())
}

/// Completed chunk mapping raw -> shard from the profile `mapping` string (spec ec-parity.md 3.2): M = the `D`
/// positions then the others; M'[i] = M[i] for i < min(|M|, n), else i. `None` = M' is no bijection over `0..n`
/// (classic OSDs abort on it: passive).
pub fn chunk_mapping(mapping: Option<&str>, k: u32, m: u32) -> Option<Vec<u32>> {
    let n = (k + m) as usize;
    let s = mapping.unwrap_or("").as_bytes();
    let d = (0..s.len()).filter(|&i| s[i] == b'D');
    let o = (0..s.len()).filter(|&i| s[i] != b'D');
    let mut full: Vec<u32> = d.chain(o).map(|i| i as u32).take(n).collect();
    full.extend(full.len() as u32..n as u32);
    let mut seen = vec![false; n];
    for &x in &full {
        match seen.get_mut(x as usize) {
            Some(b) if !*b => *b = true,
            _ => return None,
        }
    }
    Some(full)
}

/// The primary runs the classic legacy index sequence (spec ec-parity.md 3.4: place raw r at index M'[r], encode
/// indices): non-optimized isa / jerasure / clay with a non-identity completed mapping. lrc and shec place by
/// themselves; optimized pools treat the mapping as placement only (ec-optimized.md UI-6).
/// `plugin` = [`Plugin::name`].
pub fn literal_placement(plugin: &str, optimized: bool, mapping: &[u32]) -> bool {
    !optimized
        && matches!(plugin, "isa" | "jerasure" | "clay")
        && mapping.iter().enumerate().any(|(r, s)| r as u32 != *s)
}

pub fn evaluate(i: &PoolEcInput) -> Verdict {
    // Legacy FLAG_OMAP is reachable through set_pool_flags (ec-parity.md 11). It changes no data encoding:
    // the primary rejects omap operations, while ordinary legacy I/O remains supported.
    if i.flag_optimizations && i.flag_omap && !OPT_OMAP {
        return no("optimized EC pool with omap (FLAG_OMAP) not implemented");
    }
    let Some(map) = i.profile else {
        return no("erasure code profile not found in the OSDMap");
    };
    let prof = match EcProfile::parse(map) {
        Ok(p) => p,
        Err(e) => return no(format!("invalid erasure code profile: {e}")),
    };
    match &prof.plugin {
        Plugin::Isa => {
            // Vandermonde bound k <= 32 only for reed_sol_van; cauchy takes any k (spec ec-parity.md 4)
            if prof.m > 32 || (prof.k > 32 && prof.technique == "reed_sol_van") {
                return no("isa profile with m > 32 or reed_sol_van k > 32");
            }
        }
        Plugin::Jerasure => {}
        Plugin::Clay => {
            if i.flag_optimizations {
                return no("optimized EC with clay not supported (no OPTIMIZED_SUPPORTED flag)");
            }
        }
        Plugin::Lrc => {
            if i.flag_optimizations {
                return no("optimized EC with lrc not supported (no OPTIMIZED_SUPPORTED flag)");
            }
        }
        Plugin::Shec => {}
        Plugin::Unknown(p) => return no(format!("unknown erasure code plugin {p:?}")),
    }
    // clay: the shard role needs no math (spec ec-clay.md 7.1); a missing codec only removes the primary role
    let (unit, mut primary_ok) = match (Code::from_parsed(&prof), &prof.clay) {
        (Ok(c), _) => (c.unit(), true),
        (Err(_), Some(c)) => (c.chunk_align(), false),
        (Err(e), None) => return no(e),
    };
    let (k, m) = (prof.k, prof.m);
    // shec skips the base k >= 2 check: (1,1,1) is valid (spec ec-parity.md 5.1)
    let k_min = if prof.plugin == Plugin::Shec { 1 } else { 2 };
    if k < k_min || m < 1 || k + m > 127 {
        return no("profile k/m out of range");
    }
    if i.size != k + m {
        return no(format!("pool size {} != k+m {}", i.size, k + m));
    }
    if i.stripe_width == 0 || !i.stripe_width.is_multiple_of(k) {
        return no(format!(
            "pool stripe_width {} not a multiple of k={k}",
            i.stripe_width
        ));
    }
    let chunk = i.stripe_width / k;
    if !(chunk as usize).is_multiple_of(unit) {
        return no(format!(
            "chunk size {chunk} is not a multiple of the code alignment unit {}",
            unit
        ));
    }
    let Some(mapping) = chunk_mapping(prof.mapping.as_deref(), k, m) else {
        return no("profile mapping is not a bijection over k+m positions");
    };
    if let Some(c) = &prof.clay {
        primary_ok &= c.primary_capable(chunk as usize);
    }
    let mut nonprimary = Vec::new();
    if i.flag_optimizations {
        if prof.plugin == Plugin::Shec {
            return no("optimized EC with shec not supported");
        }
        if prof.plugin == Plugin::Jerasure && prof.technique != "reed_sol_van" {
            return no(format!(
                "optimized EC with jerasure technique {:?} not supported",
                prof.technique
            ));
        }
        if !chunk.is_multiple_of(4096) {
            return no(format!(
                "optimized EC chunk size {chunk} is not a multiple of 4096"
            ));
        }
        nonprimary = mapping[1..k as usize].to_vec();
        nonprimary.sort_unstable();
        let mut np = i.nonprimary_shards.clone();
        np.sort_unstable();
        if np != nonprimary {
            return no(format!(
                "pool nonprimary_shards {np:?} != profile data shards raw 1..k-1 {nonprimary:?}"
            ));
        }
    }
    Verdict::Supported(EcFacts {
        k,
        m,
        stripe_width: i.stripe_width,
        chunk_size: chunk,
        chunk_mapping: mapping,
        mode: if i.flag_optimizations {
            EcMode::Optimized
        } else if i.flag_overwrites {
            EcMode::L1
        } else {
            EcMode::L0
        },
        plugin: prof.plugin,
        technique: prof.technique,
        profile: map.clone(),
        nonprimary,
        sub_chunks: prof.clay.as_ref().map_or(1, |c| c.s as u32),
        primary_ok,
    })
}

/// FLAG_OMAP on optimized pools: accepted once the shard role applies EC_OMAP at roll-forward (plan S1d).
const OPT_OMAP: bool = true;

#[cfg(test)]
mod tests {
    use super::*;

    fn pm(kv: &[(&str, &str)]) -> BTreeMap<String, String> {
        kv.iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    fn input(p: &BTreeMap<String, String>, size: u32, min: u32, sw: u32) -> PoolEcInput<'_> {
        PoolEcInput {
            size,
            min_size: min,
            stripe_width: sw,
            flag_overwrites: false,
            flag_optimizations: false,
            flag_omap: false,
            profile: Some(p),
            ..Default::default()
        }
    }

    fn reason(v: Verdict) -> String {
        match v {
            Verdict::Unsupported(r) => r,
            Verdict::Supported(f) => panic!("unexpectedly supported: {f:?}"),
        }
    }

    fn facts(v: Verdict) -> EcFacts {
        match v {
            Verdict::Supported(f) => f,
            Verdict::Unsupported(r) => panic!("unexpectedly unsupported: {r}"),
        }
    }

    #[test]
    fn shec_accepted() {
        // defaults (4,3,2 multiple): stripe 4*32 = 128 -> chunk 32
        let p = pm(&[("plugin", "shec")]);
        let f = facts(evaluate(&input(&p, 7, 4, 128)));
        assert_eq!((f.k, f.m, f.chunk_size), (4, 3, 32));
        assert_eq!(f.technique, "multiple");
        let p = pm(&[
            ("plugin", "shec"),
            ("technique", "single"),
            ("k", "6"),
            ("m", "4"),
            ("c", "3"),
        ]);
        facts(evaluate(&input(&p, 10, 6, 6 * 4096)));
        // pool size must be k+m; any chunk (unit 1), min_size literal
        assert!(reason(evaluate(&input(&p, 9, 6, 6 * 4096))).contains("k+m"));
        assert_eq!(facts(evaluate(&input(&p, 10, 1, 6 * 33))).chunk_size, 33);
        // k = 1 (shec only)
        let p1 = pm(&[("plugin", "shec"), ("k", "1"), ("m", "1"), ("c", "1")]);
        assert_eq!(facts(evaluate(&input(&p1, 2, 1, 4096))).k, 1);
        // mapping ignored (identity placement, spec ec-parity.md 5.2)
        let p2 = pm(&[
            ("plugin", "shec"),
            ("k", "2"),
            ("m", "1"),
            ("c", "1"),
            ("mapping", "_DD"),
        ]);
        assert_eq!(
            facts(evaluate(&input(&p2, 3, 2, 8192))).chunk_mapping,
            [0, 1, 2]
        );
        // optimized EC is not served for shec
        let mut i = input(&p, 10, 6, 6 * 4096);
        i.flag_optimizations = true;
        assert!(reason(evaluate(&i)).contains("shec"));
    }

    #[test]
    fn accepted_profiles() {
        let p = pm(&[
            ("plugin", "isa"),
            ("technique", "reed_sol_van"),
            ("k", "2"),
            ("m", "2"),
        ]);
        let f = facts(evaluate(&input(&p, 4, 3, 8192)));
        assert_eq!((f.k, f.m, f.chunk_size, f.mode), (2, 2, 4096, EcMode::L0));
        assert_eq!(f.chunk_mapping, vec![0, 1, 2, 3]);
        let p = pm(&[("plugin", "isa"), ("k", "2"), ("m", "1")]);
        facts(evaluate(&input(&p, 3, 2, 8192)));
        let p = pm(&[("plugin", "isa"), ("k", "4"), ("m", "2")]);
        facts(evaluate(&input(&p, 6, 5, 16384)));
        let p = pm(&[
            ("plugin", "isa"),
            ("technique", "cauchy"),
            ("k", "8"),
            ("m", "3"),
        ]);
        facts(evaluate(&input(&p, 11, 9, 32768)));
        let p = pm(&[
            ("plugin", "jerasure"),
            ("technique", "reed_sol_van"),
            ("k", "2"),
            ("m", "1"),
        ]);
        facts(evaluate(&input(&p, 3, 2, 8192)));
        let p = pm(&[
            ("plugin", "jerasure"),
            ("technique", "reed_sol_r6_op"),
            ("k", "4"),
            ("m", "2"),
        ]);
        facts(evaluate(&input(&p, 6, 5, 16384)));
        let mut i = input(&p, 6, 5, 16384);
        i.flag_overwrites = true;
        assert_eq!(facts(evaluate(&i)).mode, EcMode::L1);
    }

    #[test]
    fn bit_matrix_techniques() {
        for (tech, k, w) in [
            ("cauchy_orig", "4", "8"),
            ("cauchy_good", "4", "8"),
            ("liberation", "5", "7"),
            ("blaum_roth", "5", "6"),
            ("liber8tion", "8", "8"),
        ] {
            let m = if tech.starts_with("cauchy") { "3" } else { "2" };
            let p = pm(&[
                ("plugin", "jerasure"),
                ("technique", tech),
                ("k", k),
                ("m", m),
                ("w", w),
                ("packetsize", "32"),
            ]);
            let (kn, mn): (u32, u32) = (k.parse().unwrap(), m.parse().unwrap());
            let chunk = w.parse::<u32>().unwrap() * 32 * 2;
            let f = facts(evaluate(&input(&p, kn + mn, kn + 1, kn * chunk)));
            assert_eq!(f.chunk_size, chunk, "{tech}");
            // chunk 160: multiple of 32 but not of the superblock w*ps
            let r = reason(evaluate(&input(&p, kn + mn, kn + 1, kn * 160)));
            assert!(r.contains("alignment unit"), "{tech}: {r}");
        }
    }

    #[test]
    fn mapping_bijection() {
        let p = pm(&[
            ("plugin", "isa"),
            ("k", "2"),
            ("m", "1"),
            ("mapping", "_DD"),
        ]);
        assert_eq!(
            facts(evaluate(&input(&p, 3, 2, 8192))).chunk_mapping,
            vec![1, 2, 0]
        );
        let p = pm(&[
            ("plugin", "isa"),
            ("k", "2"),
            ("m", "1"),
            ("mapping", "DD_"),
        ]);
        assert_eq!(
            facts(evaluate(&input(&p, 3, 2, 8192))).chunk_mapping,
            vec![0, 1, 2]
        );
        // completion (spec ec-parity.md 3.2): these complete to identity
        for id in ["DD", "DDD_", "D__", "DDD", "", "D"] {
            let p = pm(&[("plugin", "isa"), ("k", "2"), ("m", "1"), ("mapping", id)]);
            assert_eq!(
                facts(evaluate(&input(&p, 3, 2, 8192))).chunk_mapping,
                vec![0, 1, 2],
                "{id}"
            );
        }
        let p = pm(&[
            ("plugin", "isa"),
            ("k", "2"),
            ("m", "1"),
            ("mapping", "_DDD"),
        ]);
        assert!(reason(evaluate(&input(&p, 3, 2, 8192))).contains("mapping"));
    }

    #[test]
    fn lrc_pools() {
        let p = pm(&[("plugin", "lrc"), ("k", "4"), ("m", "2"), ("l", "3")]);
        let f = facts(evaluate(&input(&p, 8, 5, 4096)));
        assert_eq!((f.k, f.m, f.chunk_size), (4, 4, 1024));
        assert_eq!(f.chunk_mapping, vec![0, 1, 4, 5, 2, 3, 6, 7]);
        assert_eq!(f.plugin, Plugin::Lrc);
        // explicit mapping + layers
        let p = pm(&[
            ("plugin", "lrc"),
            ("mapping", "DD__DD__"),
            (
                "layers",
                "[[\"DDc_DDc_\",\"\"],[\"DDDc____\",\"\"],[\"____DDDc\",\"\"]]",
            ),
        ]);
        let f = facts(evaluate(&input(&p, 8, 4, 4096)));
        assert_eq!(f.chunk_mapping, vec![0, 1, 4, 5, 2, 3, 6, 7]);
        assert!(reason(evaluate(&input(&p, 6, 4, 4096))).contains("pool size"));
        assert!(reason(evaluate(&input(&p, 8, 4, 4000))).contains("chunk size"));
        let mut i = input(&p, 8, 4, 4096);
        i.flag_optimizations = true;
        assert!(reason(evaluate(&i)).contains("lrc"));
        for bad in [
            pm(&[("plugin", "lrc"), ("k", "8"), ("m", "4"), ("l", "4")]),
            pm(&[("plugin", "lrc"), ("k", "4"), ("m", "2")]),
            pm(&[("plugin", "lrc"), ("k", "2"), ("m", "1"), ("l", "3")]),
            pm(&[("plugin", "lrc"), ("mapping", "DD_"), ("layers", "[")]),
            pm(&[
                ("plugin", "lrc"),
                ("mapping", "D__"),
                ("layers", "[[\"Dcc\",\"\"]]"),
            ]),
        ] {
            assert!(
                matches!(evaluate(&input(&bad, 3, 2, 4096)), Verdict::Unsupported(_)),
                "{bad:?}"
            );
        }
    }

    /// Mon-stored explicit-layer lrc profile (oracle pools/lrcexpl): k=m=l=-1 (spec ec-parity.md 14.1).
    #[test]
    fn lrc_mon_stored_explicit() {
        let p = pm(&[
            ("plugin", "lrc"),
            ("k", "-1"),
            ("m", "-1"),
            ("l", "-1"),
            ("mapping", "__DD__DD"),
            (
                "layers",
                "[[\"_cDD_cDD\",\"\"],[\"cDDD____\",\"\"],[\"____cDDD\",\"\"]]",
            ),
        ]);
        let f = facts(evaluate(&input(&p, 8, 5, 4 * 4096)));
        assert_eq!(f.chunk_mapping, vec![2, 3, 6, 7, 0, 1, 4, 5]);
    }

    #[test]
    fn clay_pools() {
        // (4,2,5): S=8, chunk 4096 => sc 512: shard + primary
        let p = pm(&[("plugin", "clay"), ("k", "4"), ("m", "2"), ("d", "5")]);
        let f = facts(evaluate(&input(&p, 6, 5, 16384)));
        assert_eq!(
            (f.k, f.m, f.chunk_size, f.sub_chunks, f.primary_ok),
            (4, 2, 4096, 8, true)
        );
        assert_eq!(f.plugin, Plugin::Clay);
        let mut i = input(&p, 6, 5, 16384);
        i.flag_overwrites = true;
        assert_eq!(facts(evaluate(&i)).mode, EcMode::L1);
        // chunk not a multiple of S*32
        assert!(reason(evaluate(&input(&p, 6, 5, 4 * 4000))).contains("alignment unit"));
        // bug shape (sc % 64 == 32, classic <= 21.1.x only): primary like classic 21.2.0
        let p = pm(&[("plugin", "clay"), ("k", "5"), ("m", "3"), ("d", "7")]);
        let f = facts(evaluate(&input(&p, 8, 6, 5 * 4320)));
        assert_eq!((f.sub_chunks, f.primary_ok), (27, true));
        let f = facts(evaluate(&input(&p, 8, 6, 5 * 6912)));
        assert!(f.primary_ok);
        // scalar shec with m == 2 is MDS (= reed_sol_van): primary role
        let p = pm(&[
            ("plugin", "clay"),
            ("k", "4"),
            ("m", "2"),
            ("scalar_mds", "shec"),
        ]);
        assert!(facts(evaluate(&input(&p, 6, 5, 16384))).primary_ok);
        // scalars without codec here: shard only (shec m >= 3 is not MDS, bit-matrix scalars: see adr 0072)
        for (s, t, m, sw) in [
            ("shec", "single", "3", 4 * 6912),
            ("jerasure", "cauchy_good", "2", 4 * 524288),
        ] {
            let mut kv = vec![("plugin", "clay"), ("k", "4"), ("m", m), ("scalar_mds", s)];
            if !t.is_empty() {
                kv.push(("technique", t));
            }
            let f = facts(evaluate(&input(
                &pm(&kv),
                4 + m.parse::<u32>().unwrap(),
                5,
                sw,
            )));
            assert!(!f.primary_ok, "{s} {t}");
        }
        // non-identity mapping: served (literal placement, spec ec-parity.md 3.4); optimized: declined
        let p = pm(&[
            ("plugin", "clay"),
            ("k", "2"),
            ("m", "2"),
            ("mapping", "_DD_"),
        ]);
        let f = facts(evaluate(&input(&p, 4, 3, 8192)));
        assert_eq!(f.chunk_mapping, [1, 2, 0, 3]);
        assert!(literal_placement(f.plugin.name(), false, &f.chunk_mapping));
        assert!(!literal_placement(f.plugin.name(), true, &f.chunk_mapping));
        let p = pm(&[
            ("plugin", "clay"),
            ("k", "2"),
            ("m", "2"),
            ("mapping", "DD__"),
        ]);
        facts(evaluate(&input(&p, 4, 3, 8192)));
        let mut i = input(&p, 4, 3, 8192);
        (i.flag_optimizations, i.nonprimary_shards) = (true, vec![1]);
        assert!(reason(evaluate(&i)).contains("clay"));
    }

    #[test]
    fn mapping_completion() {
        let c = |s: Option<&str>, k, m| chunk_mapping(s, k, m);
        assert_eq!(c(None, 2, 1), Some(vec![0, 1, 2]));
        assert_eq!(c(Some(""), 2, 1), Some(vec![0, 1, 2]));
        // shorter than n: tail = identity ("D" completes to identity)
        assert_eq!(c(Some("D"), 2, 1), Some(vec![0, 1, 2]));
        assert_eq!(c(Some("_D"), 2, 1), Some(vec![1, 0, 2]));
        assert_eq!(c(Some("D_D_"), 2, 1), Some(vec![0, 2, 1]));
        assert_eq!(c(Some("_DD"), 2, 1), Some(vec![1, 2, 0]));
        // D count need not be k
        assert_eq!(c(Some("DDD"), 2, 1), Some(vec![0, 1, 2]));
        // longer than n: the dropped tail held a small index -> no bijection (classic aborts)
        assert_eq!(c(Some("_DDD"), 2, 1), None);
        assert_eq!(c(Some("DD__"), 2, 1), Some(vec![0, 1, 2]));
        assert!(!literal_placement("isa", false, &[0, 1, 2]));
        assert!(literal_placement("isa", false, &[1, 2, 0]));
        assert!(!literal_placement("lrc", false, &[1, 2, 0]));
        assert!(!literal_placement("shec", false, &[1, 2, 0]));
    }

    #[test]
    fn rejected_plugins_and_techniques() {
        let cases: &[(&[(&str, &str)], &str)] = &[
            (
                &[("plugin", "shec"), ("k", "4"), ("m", "3"), ("c", "4")],
                "parameters rejected",
            ),
            (
                &[("plugin", "shec"), ("k", "4"), ("m", "3")],
                "invalid erasure code profile",
            ),
            (
                &[
                    ("plugin", "shec"),
                    ("technique", "reed_sol_van"),
                    ("k", "4"),
                    ("m", "3"),
                    ("c", "2"),
                ],
                "not supported",
            ),
            (
                &[("plugin", "shec"), ("k", "13"), ("m", "3"), ("c", "2")],
                "parameters rejected",
            ),
            (
                &[("plugin", "clay"), ("k", "4"), ("m", "2"), ("d", "6")],
                "not within",
            ),
            (&[("plugin", "nonsense")], "unknown"),
            (
                &[
                    ("plugin", "isa"),
                    ("technique", "liberation"),
                    ("k", "2"),
                    ("m", "2"),
                ],
                "not supported",
            ),
            (
                &[
                    ("plugin", "jerasure"),
                    ("technique", "liberation"),
                    ("k", "9"),
                    ("m", "2"),
                    ("w", "7"),
                ],
                "rejected",
            ),
            (
                &[
                    ("plugin", "jerasure"),
                    ("technique", "liberation"),
                    ("k", "2"),
                    ("m", "3"),
                    ("w", "7"),
                ],
                "rejected",
            ),
            (
                &[
                    ("plugin", "jerasure"),
                    ("technique", "cauchy_good"),
                    ("k", "2"),
                    ("m", "2"),
                    ("packetsize", "0"),
                ],
                "rejected",
            ),
            (
                &[
                    ("plugin", "jerasure"),
                    ("technique", "reed_sol_van"),
                    ("k", "2"),
                    ("m", "2"),
                    ("w", "12"),
                ],
                "w=12",
            ),
            (
                &[
                    ("plugin", "jerasure"),
                    ("technique", "reed_sol_van"),
                    ("k", "2"),
                    ("m", "2"),
                    ("w", "24"),
                ],
                "w=24",
            ),
            (
                &[
                    ("plugin", "jerasure"),
                    ("technique", "reed_sol_r6_op"),
                    ("k", "2"),
                    ("m", "3"),
                ],
                "m=2",
            ),
            (
                &[
                    ("plugin", "shec"),
                    ("k", "4"),
                    ("m", "3"),
                    ("c", "2"),
                    ("w", "16"),
                ],
                "w=16",
            ),
            (&[("plugin", "isa"), ("k", "33"), ("m", "2")], "> 32"),
            (
                &[
                    ("plugin", "isa"),
                    ("technique", "cauchy"),
                    ("k", "4"),
                    ("m", "33"),
                ],
                "> 32",
            ),
            (&[("plugin", "isa"), ("k", "100"), ("m", "30")], "k+m"),
            (&[("plugin", "isa"), ("k", "1"), ("m", "1")], "k=1"),
            (&[("k", "2"), ("m", "1")], "no plugin"),
        ];
        for (kv, want) in cases {
            let p = pm(kv);
            let r = reason(evaluate(&input(&p, 4, 3, 8192)));
            assert!(r.contains(want), "{kv:?}: {r}");
        }
    }

    #[test]
    fn rejected_pool_inputs() {
        let p = pm(&[("plugin", "isa"), ("k", "2"), ("m", "2")]);
        // optimized: nonprimary_shards must match raw 1..k-1
        let mut i = input(&p, 4, 3, 8192);
        i.flag_optimizations = true;
        assert!(reason(evaluate(&i)).contains("nonprimary_shards"));
        // missing profile
        let mut i = input(&p, 4, 3, 8192);
        i.profile = None;
        assert!(reason(evaluate(&i)).contains("not found"));
        // size mismatch
        assert!(reason(evaluate(&input(&p, 5, 3, 8192))).contains("size"));
        // min_size is literal (stretch set path, spec ec-parity.md 12.1)
        assert_eq!(facts(evaluate(&input(&p, 4, 1, 8192))).k, 2);
        assert_eq!(facts(evaluate(&input(&p, 4, 5, 8192))).k, 2);
        // stripe width
        assert!(reason(evaluate(&input(&p, 4, 3, 0))).contains("stripe_width"));
        assert!(reason(evaluate(&input(&p, 4, 3, 8193))).contains("stripe_width"));
        assert_eq!(facts(evaluate(&input(&p, 4, 3, 2 * 33))).chunk_size, 33);
        // bad profile numbers
        let p = pm(&[("plugin", "isa"), ("k", "x"), ("m", "2")]);
        assert!(reason(evaluate(&input(&p, 4, 3, 8192))).contains("invalid"));
    }

    #[test]
    fn optimized_pools() {
        let opt = |p: &BTreeMap<String, String>, size, min, sw, np: Vec<u32>| {
            let mut i = input(p, size, min, sw);
            i.flag_optimizations = true;
            i.nonprimary_shards = np;
            evaluate(&i)
        };
        let p = pm(&[("plugin", "isa"), ("k", "4"), ("m", "2")]);
        let f = facts(opt(&p, 6, 5, 4 * 16384, vec![1, 2, 3]));
        assert_eq!(
            (f.mode, f.chunk_size, f.nonprimary.clone()),
            (EcMode::Optimized, 16384, vec![1, 2, 3])
        );
        // overwrites flag does not change mode O
        let mut i = input(&p, 6, 5, 4 * 16384);
        (i.flag_optimizations, i.flag_overwrites, i.nonprimary_shards) =
            (true, true, vec![3, 1, 2]);
        assert_eq!(facts(evaluate(&i)).mode, EcMode::Optimized);
        // chunk not 4 KiB aligned
        assert!(reason(opt(&p, 6, 5, 4 * 2048, vec![1, 2, 3])).contains("4096"));
        // wrong nonprimary set
        assert!(reason(opt(&p, 6, 5, 4 * 4096, vec![1, 2])).contains("nonprimary_shards"));
        assert!(reason(opt(&p, 6, 5, 4 * 4096, vec![0, 1, 2])).contains("nonprimary_shards"));
        // mapping: data at positions 1,2 (shard 0 = parity) -> raw 1 = shard 2
        let p = pm(&[
            ("plugin", "isa"),
            ("k", "2"),
            ("m", "1"),
            ("mapping", "_DD"),
        ]);
        let f = facts(opt(&p, 3, 2, 8192, vec![2]));
        assert_eq!(f.nonprimary, vec![2]);
        assert!(reason(opt(&p, 3, 2, 8192, vec![1])).contains("nonprimary_shards"));
        // jerasure: only reed_sol_van
        let p = pm(&[
            ("plugin", "jerasure"),
            ("technique", "reed_sol_r6_op"),
            ("k", "4"),
            ("m", "2"),
        ]);
        assert!(reason(opt(&p, 6, 5, 4 * 4096, vec![1, 2, 3])).contains("reed_sol_r6_op"));
        let p = pm(&[
            ("plugin", "jerasure"),
            ("technique", "reed_sol_van"),
            ("k", "2"),
            ("m", "2"),
        ]);
        facts(opt(&p, 4, 3, 8192, vec![1]));
        // omap (until S1d)
        let mut i = input(&p, 4, 3, 8192);
        (i.flag_optimizations, i.flag_omap, i.nonprimary_shards) = (true, true, vec![1]);
        assert_eq!(matches!(evaluate(&i), Verdict::Supported(_)), OPT_OMAP);
        // Development-only FLAG_OMAP on legacy pools does not change their data encoding (ec-parity.md 11).
        for overwrites in [false, true] {
            let mut i = input(&p, 4, 3, 8192);
            i.flag_overwrites = overwrites;
            let expected = facts(evaluate(&i));
            i.flag_omap = true;
            assert_eq!(facts(evaluate(&i)), expected);
        }
    }

    /// Deterministic fuzz: never panics; Supported only when the invariants hold.
    #[test]
    fn fuzz() {
        let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut rnd = move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        let plugins = ["isa", "jerasure", "lrc", "shec", "clay", "", "x", "ISA"];
        let techs = [
            "reed_sol_van",
            "cauchy",
            "reed_sol_r6_op",
            "cauchy_good",
            "liberation",
            "",
            "zz",
        ];
        let nums = [
            "0",
            "1",
            "2",
            "3",
            "4",
            "7",
            "8",
            "16",
            "32",
            "33",
            "126",
            "127",
            "128",
            "-1",
            "+2",
            "",
            " 2",
            "99999999999",
            "abc",
            "4294967295",
            "2147483648",
        ];
        let maps = ["", "DD_", "DDD_", "_DD", "D", "DDDDDD", "D_D_", "\u{e9}D_"];
        let mut supported = 0;
        for _ in 0..20_000 {
            let mut m = BTreeMap::new();
            if rnd() % 8 != 0 {
                m.insert(
                    "plugin".to_string(),
                    plugins[(rnd() % 8) as usize].to_string(),
                );
            }
            if rnd() % 2 == 0 {
                m.insert("technique".into(), techs[(rnd() % 7) as usize].into());
            }
            for key in ["k", "m", "w", "stripe_unit", "c", "l", "d"] {
                if rnd() % 3 != 0 {
                    m.insert(key.into(), nums[(rnd() as usize) % nums.len()].into());
                }
            }
            if rnd() % 4 == 0 {
                m.insert("mapping".into(), maps[(rnd() % 8) as usize].into());
            }
            let pk = m.get("k").and_then(|x| x.parse::<u32>().ok()).unwrap_or(7);
            let pm_ = m.get("m").and_then(|x| x.parse::<u32>().ok()).unwrap_or(3);
            let i = PoolEcInput {
                size: if rnd() % 4 != 0 {
                    pk.saturating_add(pm_)
                } else {
                    (rnd() % 140) as u32
                },
                min_size: if rnd() % 4 != 0 {
                    pk
                } else {
                    (rnd() % 140) as u32
                },
                stripe_width: [0u32, 4096, 8192, 16384, 12288, 100, 64, 32 * 7]
                    [(rnd() % 8) as usize],
                flag_overwrites: rnd() % 2 == 0,
                flag_optimizations: rnd() % 16 == 0,
                flag_omap: rnd() % 16 == 0,
                profile: if rnd() % 32 == 0 { None } else { Some(&m) },
                nonprimary_shards: if rnd() % 2 == 0 {
                    (1..pk.min(64)).collect()
                } else {
                    vec![]
                },
            };
            if let Verdict::Supported(f) = evaluate(&i) {
                supported += 1;
                assert!(!matches!(f.plugin, Plugin::Unknown(_)));
                assert!(f.plugin == Plugin::Clay || (f.primary_ok && f.sub_chunks == 1));
                assert!(f.k >= 1 && f.m >= 1 && f.k + f.m <= 127);
                assert!(f.k >= 2 || f.plugin == Plugin::Shec);
                assert_eq!(i.size, f.k + f.m);
                assert_eq!(f.stripe_width, f.chunk_size * f.k);
                assert!(f.chunk_size > 0);
                if i.flag_optimizations {
                    assert_eq!(f.mode, EcMode::Optimized);
                    assert_eq!(f.chunk_size % 4096, 0);
                    assert!(!i.flag_omap);
                    assert_eq!(f.nonprimary.len() as u32, f.k - 1);
                } else {
                    assert!(f.nonprimary.is_empty());
                }
                let mut seen = f.chunk_mapping.clone();
                seen.sort_unstable();
                assert_eq!(seen, (0..f.k + f.m).collect::<Vec<_>>());
                assert_eq!(
                    f.mode == EcMode::L1,
                    i.flag_overwrites && !i.flag_optimizations
                );
            }
        }
        assert!(supported > 0, "fuzz never reached a supported pool");
    }
}
