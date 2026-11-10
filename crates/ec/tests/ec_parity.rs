// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! EC parity against the classic v21.2.0 oracle `testdata/ec-parity/` (generator `gen.sh`, spec
//! doc/spec/ec-parity.md 15): the gate serves the pool a classic mon created, encode reproduces the shard bytes a
//! classic primary stored, and every loss the code can repair rebuilds those bytes.

use ec::gate::literal_placement;
use ec::{Code, EcFacts, EcMode, PoolEcInput, Verdict, evaluate};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/ec-parity")
}

/// xorshift32 object pattern of gen.sh (as crates/ec/tests/frozen_clay.rs).
fn pattern(n: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2654435761).wrapping_add(1);
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 8) as u8
        })
        .collect()
}

fn sha(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

/// `hash ... shard<N>` lines -> shard -> hash.
fn sha_file(path: &PathBuf) -> BTreeMap<usize, String> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter_map(|l| {
            let w: Vec<&str> = l.split_whitespace().collect();
            let s = w.last()?.strip_prefix("shard")?.parse().ok()?;
            Some((s, w[0].to_string()))
        })
        .collect()
}

/// One oracle pool (`pools/<name>/`).
struct Pool {
    name: &'static str,
    profile: BTreeMap<String, String>,
    object: Vec<u8>,
    stripe_width: u32,
    size: u32,
    /// shard -> raw bytes (shards <= 16 KiB only)
    shards: BTreeMap<usize, Vec<u8>>,
    /// shard -> sha256 of the whole shard
    sha: BTreeMap<usize, String>,
}

fn pool(name: &'static str) -> Pool {
    let d = dir().join("pools").join(name);
    let rd = |f: &str| std::fs::read_to_string(d.join(f)).unwrap();
    let profile = rd("profile")
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
    let meta: Vec<u64> = rd("meta")
        .split_whitespace()
        .map(|x| x.parse().unwrap())
        .collect();
    let acting = rd("acting");
    let size = acting.split_whitespace().nth(1).unwrap().split(',').count() as u32;
    let sha = sha_file(&d.join("sha256"));
    let shards = sha
        .keys()
        .filter_map(|s| Some((*s, std::fs::read(d.join(format!("shard{s}"))).ok()?)))
        .collect();
    Pool {
        name,
        profile,
        object: pattern(meta[1] as usize, meta[0] as u32),
        stripe_width: meta[2] as u32,
        size,
        shards,
        sha,
    }
}

impl Pool {
    fn input(&self, min_size: u32) -> PoolEcInput<'_> {
        PoolEcInput {
            size: self.size,
            min_size,
            stripe_width: self.stripe_width,
            profile: Some(&self.profile),
            ..Default::default()
        }
    }

    /// Gate verdict of the legacy (append-only) pool with min_size k+1 capped at size.
    fn facts(&self) -> EcFacts {
        let k = match evaluate(&self.input(self.size)) {
            Verdict::Supported(f) => f.k,
            Verdict::Unsupported(r) => panic!("{}: gate refuses: {r}", self.name),
        };
        match evaluate(&self.input((k + 1).min(self.size))) {
            Verdict::Supported(f) => f,
            Verdict::Unsupported(r) => panic!("{}: gate refuses: {r}", self.name),
        }
    }

    /// The k client data regions (chunk r of every stripe, concatenated; object zero padded to whole stripes).
    fn data(&self, k: usize, chunk: usize) -> Vec<Vec<u8>> {
        let sw = self.stripe_width as usize;
        let mut obj = self.object.clone();
        obj.resize(obj.len().div_ceil(sw) * sw, 0);
        (0..k)
            .map(|r| {
                obj.chunks(sw)
                    .flat_map(|st| st[r * chunk..(r + 1) * chunk].iter().copied())
                    .collect()
            })
            .collect()
    }

    fn matches(&self, shard: usize, bytes: &[u8]) -> bool {
        match self.shards.get(&shard) {
            Some(b) => b == bytes,
            None => self.sha.get(&shard) == Some(&sha(bytes)),
        }
    }
}

/// Code of a served pool (as the primary role builds it, incl. the classic literal placement).
fn code_of(f: &EcFacts) -> Code {
    let mut c = Code::from_profile(&f.profile).unwrap();
    c.set_chunk(f.chunk_size as usize);
    if literal_placement(
        f.plugin.name(),
        f.mode == EcMode::Optimized,
        &f.chunk_mapping,
    ) {
        c = c.placed(&f.chunk_mapping).unwrap();
    }
    c
}

/// Raw chunk regions of an encode of `data` (data then parity).
fn encode(code: &Code, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let len = data[0].len();
    let mut all = vec![vec![0u8; len]; code.k() + code.m()];
    {
        let d: Vec<&[u8]> = data.iter().map(|v| &v[..]).collect();
        let mut o: Vec<&mut [u8]> = all.iter_mut().map(|v| &mut v[..]).collect();
        code.encode_all(&d, &mut o);
    }
    all
}

/// Encode equality: every shard the classic primary stored (raw chunk r on shard `chunk_mapping[r]`).
fn assert_encode(p: &Pool, f: &EcFacts, code: &Code) -> Vec<Vec<u8>> {
    let raw = encode(code, &p.data(f.k as usize, f.chunk_size as usize));
    for (r, b) in raw.iter().enumerate() {
        let s = f.chunk_mapping[r] as usize;
        assert!(
            p.matches(s, b),
            "{}: shard {s} (raw {r}) differs from classic",
            p.name
        );
    }
    raw
}

/// Every loss of up to m raw chunks the code can plan: the decode rebuilds the classic bytes.
fn assert_decodes(p: &Pool, code: &Code, raw: &[Vec<u8>]) -> usize {
    let n = raw.len();
    let mut checked = 0;
    for mask in 1u32..(1 << n) {
        if mask.count_ones() as usize > code.m() {
            continue;
        }
        let lost: Vec<usize> = (0..n).filter(|r| mask >> r & 1 == 1).collect();
        let avail: Vec<usize> = (0..n).filter(|r| mask >> r & 1 == 0).collect();
        let Some(set) = code.read_set(&lost, &avail) else {
            continue;
        };
        let have: Vec<(usize, &[u8])> = set.iter().map(|&r| (r, &raw[r][..])).collect();
        let mut out = vec![vec![0u8; raw[0].len()]; lost.len()];
        let mut o: Vec<&mut [u8]> = out.iter_mut().map(|v| &mut v[..]).collect();
        code.decode_into(&have, &lost, &mut o).unwrap();
        for (r, v) in lost.iter().zip(&out) {
            assert!(v == &raw[*r], "{}: decode of raw {r} lost {lost:?}", p.name);
        }
        checked += 1;
    }
    assert!(checked > 0, "{}: no decodable loss", p.name);
    checked
}

fn served(name: &'static str) -> (Pool, EcFacts) {
    let p = pool(name);
    assert!(
        !p.sha.is_empty(),
        "{name}: oracle has no shards (classic pool creation failed?)"
    );
    let f = p.facts();
    (p, f)
}

/// Step 1: profile syntax the mon stores raw, legacy plugin aliases, shec k = 1, a chunk that is not a multiple of 32
/// (spec ec-parity.md 1, 2, 5.1, 7).
#[test]
fn step1_pools_served_byte_exact() {
    for (name, k, m, chunk) in [
        ("isaplus", 2, 1, 8192), // k=+2 stripe_unit=8K
        ("jergeneric", 2, 1, 4096),
        ("shecgeneric", 2, 1, 4096),
        ("shec111", 1, 1, 4096),
        ("lib7", 2, 2, 4144), // liberation w=7 ps=4: 4144 % 32 == 16
    ] {
        let (p, f) = served(name);
        assert_eq!((f.k, f.m, f.chunk_size), (k, m, chunk), "{name}");
        assert!(f.primary_ok, "{name}");
        let code = code_of(&f);
        let raw = assert_encode(&p, &f, &code);
        assert_decodes(&p, &code, &raw);
    }
}

/// Step 1: isa cauchy beyond k = 32 (spec ec-parity.md 4): ceph-erasure-code-tool encode at stripe_unit 4096.
#[test]
fn step1_isa_cauchy_wide() {
    for (k, m) in [(34usize, 2usize), (40, 4)] {
        let base = dir().join("isa-wide").join(format!("k{k}m{m}"));
        let meta = std::fs::read_to_string(base.with_extension("meta")).unwrap();
        assert!(meta.starts_with("rc=0 "), "k{k}m{m}: {meta}");
        let want = sha_file(&base.with_extension("sha256"));
        let prof: BTreeMap<String, String> = [
            ("plugin", "isa".to_string()),
            ("technique", "cauchy".into()),
            ("k", k.to_string()),
            ("m", m.to_string()),
        ]
        .into_iter()
        .map(|(a, b)| (a.to_string(), b))
        .collect();
        let chunk = 4096;
        let input = PoolEcInput {
            size: (k + m) as u32,
            min_size: k as u32 + 1,
            stripe_width: (k * chunk) as u32,
            profile: Some(&prof),
            ..Default::default()
        };
        let f = match evaluate(&input) {
            Verdict::Supported(f) => f,
            Verdict::Unsupported(r) => panic!("isa cauchy k={k}: {r}"),
        };
        let p = Pool {
            name: "isa-wide",
            profile: prof.clone(),
            object: pattern(k * 8192, k as u32),
            stripe_width: (k * chunk) as u32,
            size: (k + m) as u32,
            shards: BTreeMap::new(),
            sha: want,
        };
        let code = code_of(&f);
        let raw = assert_encode(&p, &f, &code);
        // decode: a sample of the losses (all up to m would be C(44,4) patterns)
        for lost in [
            vec![0],
            vec![k - 1, k],
            (0..m).collect(),
            (k..k + m).collect(),
        ] {
            let avail: Vec<usize> = (0..k + m).filter(|r| !lost.contains(r)).collect();
            let set = code.read_set(&lost, &avail).unwrap();
            let have: Vec<(usize, &[u8])> = set.iter().map(|&r| (r, &raw[r][..])).collect();
            let mut out = vec![vec![0u8; raw[0].len()]; lost.len()];
            let mut o: Vec<&mut [u8]> = out.iter_mut().map(|v| &mut v[..]).collect();
            code.decode_into(&have, &lost, &mut o).unwrap();
            for (r, v) in lost.iter().zip(&out) {
                assert!(v == &raw[*r], "k{k}m{m}: decode raw {r}");
            }
        }
    }
}

/// Step 1: gate verdicts for profiles the mon / tool accept without a pool in the oracle (tool-profiles.tsv,
/// mon-probes.tsv).
#[test]
fn step1_gate_verdicts() {
    let pm = |kv: &[(&str, &str)]| -> BTreeMap<String, String> {
        kv.iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    };
    let verdict = |p: &BTreeMap<String, String>, size, min, sw| {
        evaluate(&PoolEcInput {
            size,
            min_size: min,
            stripe_width: sw,
            profile: Some(p),
            ..Default::default()
        })
    };
    let ok = |v: Verdict| matches!(v, Verdict::Supported(_));
    for alias in [
        "jerasure_generic",
        "jerasure_neon",
        "jerasure_sse3",
        "jerasure_sse4",
    ] {
        assert!(ok(verdict(
            &pm(&[("plugin", alias), ("k", "2"), ("m", "1")]),
            3,
            2,
            8192
        )));
    }
    for alias in ["shec_generic", "shec_neon", "shec_sse3", "shec_sse4"] {
        let p = pm(&[("plugin", alias), ("k", "2"), ("m", "1"), ("c", "1")]);
        assert!(ok(verdict(&p, 3, 2, 8192)));
    }
    // ints: strtoll grammar (leading blanks, sign, leading zeros); stripe_unit is never the OSD's business
    for k in ["+2", "02", " 2", "\t+002"] {
        let p = pm(&[
            ("plugin", "isa"),
            ("k", k),
            ("m", "1"),
            ("stripe_unit", "64Ki"),
        ]);
        assert!(ok(verdict(&p, 3, 2, 8192)), "{k:?}");
    }
    // isa: k > 32 only for cauchy (tool: cauchy k=40 m=4 valid, reed_sol_van k=40 invalid, m=33 invalid)
    let isa =
        |t: &str, k: &str, m: &str| pm(&[("plugin", "isa"), ("technique", t), ("k", k), ("m", m)]);
    assert!(ok(verdict(&isa("cauchy", "40", "4"), 44, 41, 40 * 224)));
    assert!(!ok(verdict(
        &isa("reed_sol_van", "40", "4"),
        44,
        41,
        40 * 224
    )));
    assert!(!ok(verdict(&isa("cauchy", "40", "33"), 73, 41, 40 * 224)));
    // clay over isa cauchy with k+nu > 32 (tool: chunk 8388608 at width 8192), reed_sol_van refused
    let clay = |t: &str| {
        pm(&[
            ("plugin", "clay"),
            ("k", "33"),
            ("m", "2"),
            ("d", "34"),
            ("scalar_mds", "isa"),
            ("technique", t),
        ])
    };
    assert!(ok(verdict(&clay("cauchy"), 35, 34, 33 * 8388608)));
    assert!(!ok(verdict(&clay("reed_sol_van"), 35, 34, 33 * 8388608)));
    // shec (1,1,1) (tool chunk 8192 at width 8192)
    let p = pm(&[("plugin", "shec"), ("k", "1"), ("m", "1"), ("c", "1")]);
    assert!(ok(verdict(&p, 2, 1, 8192)));
    // literal min_size: `osd pool stretch set minsz ... 3 1` gives min_size 1 on a k=2 m=1 pool
    let p = pm(&[("plugin", "isa"), ("k", "2"), ("m", "1")]);
    for min in [0, 1, 2, 3, 4] {
        assert!(ok(verdict(&p, 3, min, 8192)), "min_size {min}");
    }
    // tool chunk sizes at width 8192 that are not multiples of 32
    let jer = |kv: &[(&str, &str)]| {
        let mut v = vec![("plugin", "jerasure")];
        v.extend_from_slice(kv);
        pm(&v)
    };
    let p = jer(&[
        ("technique", "blaum_roth"),
        ("k", "4"),
        ("m", "2"),
        ("w", "6"),
        ("packetsize", "4"),
    ]);
    assert!(ok(verdict(&p, 6, 5, 4 * 2112)));
    let p = jer(&[
        ("technique", "cauchy_good"),
        ("k", "3"),
        ("m", "2"),
        ("packetsize", "4"),
        ("jerasure-per-chunk-alignment", "true"),
    ]);
    assert!(ok(verdict(&p, 5, 4, 3 * 2752)));
}

/// Step 2: accepted-path bugs. A mon-created explicit-layer lrc profile is stored with k=m=l=-1 (spec ec-parity.md
/// 14.1); shec ignores `mapping` (identity placement, spec 5.2: oracle shard0/1 = data 0/1).
#[test]
fn step2_lrc_explicit_and_shec_mapping() {
    let (p, f) = served("lrcexpl");
    assert_eq!(p.profile["k"], "-1");
    assert_eq!((f.k, f.m, f.chunk_size), (4, 4, 4096));
    assert_eq!(f.chunk_mapping, vec![2, 3, 6, 7, 0, 1, 4, 5]);
    let code = code_of(&f);
    let raw = assert_encode(&p, &f, &code);
    assert_decodes(&p, &code, &raw);

    let (p, f) = served("shecmap_DD");
    assert_eq!(p.profile["mapping"], "_DD");
    assert_eq!(f.chunk_mapping, vec![0, 1, 2]);
    let code = code_of(&f);
    let raw = assert_encode(&p, &f, &code);
    assert_decodes(&p, &code, &raw);
}

/// Step 3: mapping completion (spec ec-parity.md 3.2) and the classic literal sequences (3.4 isa/clay placement on
/// index space, 14.2 lrc layer coding into a data position). Classic leaves input slots no client chunk lands on
/// uninitialised (oracle shard bytes vary per run), croit-flashstore-osd zeros them: the testable contract is the deterministic
/// placed data shards plus the code relation on the stored shards (every plannable loss rebuilds the classic bytes).
#[test]
fn step3_mapping_completion_and_literal_placement() {
    // `D` completes to identity (k=2 m=1): plain classic bytes
    let (p, f) = served("isamapD");
    assert_eq!(f.chunk_mapping, vec![0, 1, 2]);
    let code = code_of(&f);
    assert!(!code.rewrites_data());
    let raw = assert_encode(&p, &f, &code);
    assert_decodes(&p, &code, &raw);

    // (pool, completed mapping, (shard, client data chunk) placed by classic, shards of uninitialised input slots)
    let cases = [
        ("isamap_DD", vec![1u32, 2, 0], (1usize, 0usize), 0usize),
        ("claymap_DD_", vec![1, 2, 0, 3], (1, 0), 0),
        ("lrccOnD", vec![0, 1, 2, 3], (1, 1), 2),
    ];
    for (name, mapping, (ps, pr), slot) in cases {
        let (p, f) = served(name);
        assert_eq!(f.chunk_mapping, mapping, "{name}");
        let code = code_of(&f);
        assert!(code.rewrites_data(), "{name}");
        let raw_of = |s: usize| mapping.iter().position(|x| *x as usize == s).unwrap();
        let data = p.data(f.k as usize, f.chunk_size as usize);
        assert_eq!(p.shards[&ps], data[pr], "{name}: oracle placement");
        let ours = encode(&code, &data);
        assert_eq!(ours[raw_of(ps)], data[pr], "{name}: placed data shard");
        assert!(
            ours[raw_of(slot)].iter().all(|b| *b == 0),
            "{name}: zero slot"
        );
        let oracle: Vec<Vec<u8>> = mapping
            .iter()
            .map(|s| p.shards[&(*s as usize)].clone())
            .collect();
        let n = assert_decodes(&p, &code, &oracle);
        assert_eq!(n, assert_decodes(&p, &code, &ours), "{name}");
    }
}
