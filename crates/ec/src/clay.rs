// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! clay: coupled-layer MSR code over a scalar MDS code (spec ec-clay.md).
//!
//! N = q*t nodes (k data, nu virtual all-zero, m parity), S = q^t planes (sub-chunks) per chunk. Coupled values C are
//! stored; uncoupled values U = pairwise transform (2x2 "pft" code) of companion pairs; every plane of U is an mds
//! codeword. Every byte lane of a sub-chunk is an independent codeword (GF(2^8) scalars only).
//! Encode = decode of the m parity nodes (spec 4, 5.2). [`ClayCodec::repair`] = single-chunk repair from d helpers'
//! repair planes (spec 6.4); internal use only (main primaries never issue sub-chunk reads).

use crate::gf::{Codec, DecodeError, Kind, coding_matrix, invert, mul, mul_acc};
use std::collections::BTreeMap;

/// Largest sub-chunk count we accept (classic has no bound; bigger = passive).
const MAX_S: usize = 1 << 20;

/// Parsed and validated clay profile (spec 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClayProfile {
    pub k: usize,
    pub m: usize,
    pub d: usize,
    /// `jerasure` | `isa` | `shec`.
    pub scalar: String,
    pub technique: String,
    pub q: usize,
    pub t: usize,
    pub nu: usize,
    /// sub_chunk_count S = q^t.
    pub s: usize,
    /// pft get_chunk_size(1) (spec 2): 32, or 65536 for the jerasure bit-matrix scalars.
    pub a1: usize,
}

/// missing or empty => default; else the classic integer grammar ([`crate::profile::parse_int`]), non-negative.
fn cnum(map: &BTreeMap<String, String>, key: &str, def: usize) -> Result<usize, String> {
    match crate::profile::int_key(map, key)? {
        None => Ok(def),
        Some(n) => {
            usize::try_from(n).map_err(|_| format!("clay: profile key {key}={n} out of range"))
        }
    }
}

impl ClayProfile {
    pub fn parse(map: &BTreeMap<String, String>) -> Result<ClayProfile, String> {
        let k = cnum(map, "k", 4)?;
        let m = cnum(map, "m", 2)?;
        if k < 2 || m < 1 || k + m > 127 {
            return Err(format!("clay: k={k} m={m} out of range"));
        }
        let d = cnum(map, "d", k + m - 1)?;
        let scalar = match map.get("scalar_mds").map(|s| s.as_str()) {
            None | Some("") => "jerasure",
            Some(s @ ("jerasure" | "isa" | "shec")) => s,
            Some(s) => return Err(format!("clay: scalar_mds {s:?} not supported")),
        };
        let technique = match map.get("technique").map(|s| s.as_str()) {
            None | Some("") if scalar == "shec" => "single",
            None | Some("") => "reed_sol_van",
            Some(t) => t,
        };
        let ok = match scalar {
            "jerasure" => matches!(
                technique,
                "reed_sol_van" | "reed_sol_r6_op" | "cauchy_orig" | "cauchy_good" | "liber8tion"
            ),
            "isa" => matches!(technique, "reed_sol_van" | "cauchy"),
            _ => matches!(technique, "single" | "multiple"),
        };
        if !ok {
            return Err(format!(
                "clay: technique {technique:?} not valid for {scalar}"
            ));
        }
        if d < k + 1 || d > k + m - 1 {
            return Err(format!("clay: d={d} not within [{},{}]", k + 1, k + m - 1));
        }
        let q = d - k + 1;
        let nu = if (k + m) % q == 0 { 0 } else { q - (k + m) % q };
        if k + m + nu > 254 {
            return Err("clay: k+m+nu > 254".into());
        }
        let t = (k + m + nu) / q;
        let s = (0..t).try_fold(1usize, |a, _| a.checked_mul(q).filter(|v| *v <= MAX_S));
        let Some(s) = s else {
            return Err(format!("clay: sub-chunk count {q}^{t} too large"));
        };
        // sub-plugin limits on (k+nu, m) and (2, 2) (spec 1.2)
        let kk = k + nu;
        let sub_ok = match (scalar, technique) {
            ("jerasure", "reed_sol_r6_op") => m == 2,
            ("jerasure", "liber8tion") => m == 2 && kk <= 8,
            // isa: Vandermonde bounds k <= 32, cauchy only m (spec ec-parity.md 4)
            ("isa", "reed_sol_van") => kk <= 32 && m <= 32 && kk + m <= 127,
            ("isa", _) => m <= 32 && kk + m <= 127,
            ("shec", _) => kk >= m && kk <= 12 && kk + m <= 20 && m >= 2,
            _ => true,
        };
        if !sub_ok {
            return Err(format!(
                "clay: scalar {scalar} {technique} rejects (k+nu={kk}, m={m})"
            ));
        }
        let a1 = match technique {
            "cauchy_orig" | "cauchy_good" | "liber8tion" => 65536,
            _ => 32,
        };
        Ok(ClayProfile {
            k,
            m,
            d,
            scalar: scalar.to_string(),
            technique: technique.to_string(),
            q,
            t,
            nu,
            s,
            a1,
        })
    }

    /// Chunk sizes must be a multiple of this (S * pft chunk alignment).
    pub fn chunk_align(&self) -> usize {
        self.s * self.a1
    }

    /// Classic `get_chunk_size(width)`: roundup(width, S*k*A1) / k.
    pub fn chunk_size(&self, width: usize) -> usize {
        width.div_ceil(self.s * self.k * self.a1) * self.s * self.a1
    }

    /// GF(2^8) matrix kind of the scalar; `None` = no codec here (shec with m >= 3, bit-matrix: shard role only).
    pub fn kind(&self) -> Option<Kind> {
        match (self.scalar.as_str(), self.technique.as_str()) {
            ("jerasure", "reed_sol_van") => Some(Kind::JerVan),
            // shec with m == 2 (c = 2): every parity row is a full row = jerasure reed_sol_van (spec ec-clay.md 1.4);
            // m >= 3 is not MDS (classic ignores the failed plane decodes): shard role only
            ("shec", _) if self.m == 2 => Some(Kind::JerVan),
            // r6_op m==2 = isa reed_sol_van rows (ec.md 4.3.2)
            ("jerasure", "reed_sol_r6_op") | ("isa", "reed_sol_van") => Some(Kind::IsaVan),
            ("isa", "cauchy") => Some(Kind::IsaCauchy),
            _ => None,
        }
    }

    /// Primary role allowed (spec 0.6): MDS scalar we implement and a chunk that splits into whole sub-chunks.
    pub fn primary_capable(&self, chunk: usize) -> bool {
        self.kind().is_some() && chunk.is_multiple_of(self.s)
    }
}

/// The four pft slots of a companion pair: coupled H, coupled L, uncoupled H, uncoupled L (H = larger row x).
const CH: usize = 0;
const CL: usize = 1;
const UH: usize = 2;
const UL: usize = 3;

/// pft coefficients: [known a][known b][wanted] -> (coef of a, coef of b).
type PftTab = [[[(u8, u8); 4]; 4]; 4];

#[derive(Clone, Debug)]
pub struct ClayCodec {
    p: ClayProfile,
    /// GF(2^8) matrix kind of the scalar (the mds sub-code).
    kind: Kind,
    /// mds code over (k+nu, m); raw index = node index.
    mds: Codec,
    /// pft[a][b][w] = coefficients of slot w over known slots (a, b).
    pft: Box<PftTab>,
    /// q^(t-1-y) per column y.
    pw: Vec<usize>,
    /// Stripe chunk size when known (pool geometry): regions are processed per chunk.
    chunk: Option<usize>,
}

#[derive(Clone, Copy)]
enum B {
    C,
    U,
}

/// Per-stripe work area: coupled + uncoupled values of every node, one scratch sub-chunk, and the layered-decode
/// scratch (erased flags, sources, coefficients, plane order). One per thread, reused across calls: `encode` runs
/// once per stripe, so a fresh area per call would allocate `2*nodes*chunk` bytes per stripe.
struct Work {
    c: Vec<u8>,
    u: Vec<u8>,
    tmp: Vec<u8>,
    cs: usize,
    sc: usize,
    /// Nodes with erased C values (layered) / raw chunks already stored (decode `known`, sized k+m there).
    in_e: Vec<bool>,
    /// Source nodes of the mds step, ascending.
    have: Vec<usize>,
    /// Raw nodes the mds step rebuilds (the `e` argument, kept for reuse).
    e: Vec<usize>,
    /// mds coefficients: `have.len()` per rebuilt node, row major.
    coef: Vec<u8>,
    /// Codec/geometry of `coef` and the sources/targets it was built from.
    coef_id: Option<(Kind, usize, usize)>,
    coef_have: Vec<usize>,
    coef_e: Vec<usize>,
    /// Per-plane count of rebuilt companion pairs, and the node columns the rebuild spans.
    ord: Vec<usize>,
    cols: Vec<usize>,
    /// Terms of one mds/pft step (sources may alias the destination).
    terms: Vec<(B, usize, usize, u8)>,
}

impl Work {
    fn new() -> Work {
        Work {
            c: Vec::new(),
            u: Vec::new(),
            tmp: Vec::new(),
            cs: 0,
            sc: 0,
            in_e: Vec::new(),
            have: Vec::new(),
            e: Vec::new(),
            coef: Vec::new(),
            coef_id: None,
            coef_have: Vec::new(),
            coef_e: Vec::new(),
            ord: Vec::new(),
            cols: Vec::new(),
            terms: Vec::new(),
        }
    }

    /// Size for a codeword of `nodes` chunks of `cs` bytes (`sc` = bytes per sub-chunk); zeroed, like a fresh area.
    fn fit(&mut self, nodes: usize, cs: usize, sc: usize) {
        if (self.cs, self.sc) != (cs, sc) || self.c.len() != nodes * cs {
            self.c = vec![0; nodes * cs];
            self.u = vec![0; nodes * cs];
            self.tmp = vec![0; sc];
            self.cs = cs;
            self.sc = sc;
            self.coef_id = None;
        }
        self.c.fill(0);
        self.u.fill(0);
    }

    fn at(&self, b: B, n: usize, z: usize) -> &[u8] {
        let o = n * self.cs + z * self.sc;
        match b {
            B::C => &self.c[o..o + self.sc],
            B::U => &self.u[o..o + self.sc],
        }
    }
    /// dst = sum coef * src (through the scratch: sources may alias the destination's buffer).
    fn set(&mut self, dst: (B, usize, usize), terms: &[(B, usize, usize, u8)]) {
        let mut tmp = std::mem::take(&mut self.tmp);
        tmp.fill(0);
        for &(b, n, z, c) in terms {
            mul_acc(&mut tmp, self.at(b, n, z), c);
        }
        let o = dst.1 * self.cs + dst.2 * self.sc;
        match dst.0 {
            B::C => self.c[o..o + self.sc].copy_from_slice(&tmp),
            B::U => self.u[o..o + self.sc].copy_from_slice(&tmp),
        }
        self.tmp = tmp;
    }

    /// mds coefficients of [`Work::e`] over [`Work::have`], computed once per codec and node set.
    fn prepare(&mut self, codec: &Codec, id: (Kind, usize, usize)) -> Result<(), DecodeError> {
        if self.coef_id != Some(id) || self.coef_e != self.e || self.coef_have != self.have {
            let coef = codec
                .decode_matrix(&self.have, &self.e)
                .ok_or(DecodeError::Unrecoverable)?;
            self.coef = coef;
            self.coef_have.clear();
            self.coef_have.extend_from_slice(&self.have);
            self.coef_e.clear();
            self.coef_e.extend_from_slice(&self.e);
            self.coef_id = Some(id);
        }
        Ok(())
    }
}

thread_local! {
    static WORK: std::cell::RefCell<Work> = std::cell::RefCell::new(Work::new());
}

/// Run `f` with this thread's work area (one per thread: no lock, no sharing).
fn with_work<T>(f: impl FnOnce(&mut Work) -> T) -> T {
    WORK.with_borrow_mut(f)
}

impl ClayCodec {
    /// `None` for scalars without a GF(2^8) codec here.
    pub fn new(p: &ClayProfile) -> Option<ClayCodec> {
        let kind = p.kind()?;
        let mds = Codec::try_new(kind, p.k + p.nu, p.m)?;
        let pm = coding_matrix(kind, 2, 2);
        let g = [[1, 0], [0, 1], [pm[0], pm[1]], [pm[2], pm[3]]];
        let mut pft = Box::new([[[(0u8, 0u8); 4]; 4]; 4]);
        for a in 0..4 {
            for b in 0..4 {
                if a == b {
                    continue;
                }
                let inv = invert(&[g[a][0], g[a][1], g[b][0], g[b][1]], 2)?;
                for w in 0..4 {
                    // value_w = g[w] . basis, basis = inv * (val_a, val_b)
                    let ca = mul(g[w][0], inv[0]) ^ mul(g[w][1], inv[2]);
                    let cb = mul(g[w][0], inv[1]) ^ mul(g[w][1], inv[3]);
                    pft[a][b][w] = (ca, cb);
                }
            }
        }
        let pw = (0..p.t).map(|y| p.q.pow((p.t - 1 - y) as u32)).collect();
        Some(ClayCodec {
            p: p.clone(),
            kind,
            mds,
            pft,
            pw,
            chunk: None,
        })
    }

    /// Identity of the mds sub-code for the work-area coefficient cache.
    fn mds_id(&self) -> (Kind, usize, usize) {
        (self.kind, self.p.k + self.p.nu, self.p.m)
    }

    pub fn profile(&self) -> &ClayProfile {
        &self.p
    }
    pub fn k(&self) -> usize {
        self.p.k
    }
    pub fn m(&self) -> usize {
        self.p.m
    }
    pub fn sub_chunk_count(&self) -> usize {
        self.p.s
    }
    /// Lengths must be multiples of this ([`ClayProfile::chunk_align`]).
    pub fn unit(&self) -> usize {
        self.p.chunk_align()
    }
    /// Fix the stripe chunk size: encode/decode then work per chunk on multi-stripe regions.
    pub fn set_chunk(&mut self, chunk: usize) {
        self.chunk = Some(chunk);
    }

    fn nodes(&self) -> usize {
        self.p.q * self.p.t
    }
    fn node_of(&self, raw: usize) -> usize {
        if raw < self.p.k { raw } else { raw + self.p.nu }
    }
    fn raw_of(&self, n: usize) -> Option<usize> {
        if n < self.p.k {
            Some(n)
        } else if n < self.p.k + self.p.nu {
            None
        } else {
            Some(n - self.p.nu)
        }
    }
    fn digit(&self, z: usize, y: usize) -> usize {
        (z / self.pw[y]) % self.p.q
    }
    /// Companion of non-dot node n at plane z: (partner node, partner plane).
    fn partner(&self, n: usize, z: usize) -> (usize, usize) {
        let (x, y) = (n % self.p.q, n / self.p.q);
        let zy = self.digit(z, y);
        (y * self.p.q + zy, z + x * self.pw[y] - zy * self.pw[y])
    }

    /// Solve pair slots: `known` = two (slot, buffer) of the pair (n,zn)~(p,zp), set slot `want`.
    fn pft(
        &self,
        w: &mut Work,
        a: (usize, usize),
        b: (usize, usize),
        known: [usize; 2],
        want: usize,
    ) {
        let q = self.p.q;
        let (h, l) = if a.0 % q > b.0 % q { (a, b) } else { (b, a) };
        let loc = |s: usize| match s {
            CH => (B::C, h.0, h.1),
            CL => (B::C, l.0, l.1),
            UH => (B::U, h.0, h.1),
            _ => (B::U, l.0, l.1),
        };
        let (ca, cb) = self.pft[known[0]][known[1]][want];
        let (ka, kb) = (loc(known[0]), loc(known[1]));
        w.set(loc(want), &[(ka.0, ka.1, ka.2, ca), (kb.0, kb.1, kb.2, cb)]);
    }

    /// Slot names of node n / its partner p.
    fn slots(&self, n: usize, p: usize) -> (usize, usize, usize, usize) {
        let q = self.p.q;
        if n % q > p % q {
            (CH, CL, UH, UL)
        } else {
            (CL, CH, UL, UH)
        }
    }

    /// mds step of plane z: U of `e` from U of `have` (coefficients `coef`, |e| x |have|).
    fn mds_plane(&self, w: &mut Work, z: usize, have: &[usize], e: &[usize], coef: &[u8]) {
        let kk = have.len();
        let mut terms = std::mem::take(&mut w.terms);
        for (i, &en) in e.iter().enumerate() {
            terms.clear();
            terms.extend(
                have.iter()
                    .enumerate()
                    .map(|(j, &h)| (B::U, h, z, coef[i * kk + j])),
            );
            w.set((B::U, en, z), &terms);
        }
        w.terms = terms;
    }

    /// decode_layered (spec 5.2): recover C of the nodes in [`Work::e`] (sorted, |e| == m, no virtual node).
    fn layered(&self, w: &mut Work) -> Result<(), DecodeError> {
        let (q, t, s, n) = (self.p.q, self.p.t, self.p.s, self.nodes());
        let kk = self.p.k + self.p.nu;
        w.in_e.clear();
        w.in_e.resize(n, false);
        for i in 0..w.e.len() {
            w.in_e[w.e[i]] = true;
        }
        w.have.clear();
        for x in 0..n {
            if !w.in_e[x] {
                w.have.push(x);
                if w.have.len() == kk {
                    break;
                }
            }
        }
        w.prepare(&self.mds, self.mds_id())?;
        // take the reusable vectors out: the algorithm needs the work area mutably and these by reference
        let e = std::mem::take(&mut w.e);
        let in_e = std::mem::take(&mut w.in_e);
        let have = std::mem::take(&mut w.have);
        let coef = std::mem::take(&mut w.coef);
        let mut ord = std::mem::take(&mut w.ord);
        let mut cols = std::mem::take(&mut w.cols);
        ord.clear();
        ord.extend((0..s).map(|z| e.iter().filter(|&&x| self.digit(z, x / q) == x % q).count()));
        cols.clear();
        cols.extend(e.iter().map(|x| x / q));
        cols.dedup();
        let maxs = cols.len();
        for o in 0..=maxs {
            for z in (0..s).filter(|z| ord[*z] == o) {
                for x in 0..q {
                    for y in 0..t {
                        let nd = y * q + x;
                        if in_e[nd] {
                            continue;
                        }
                        let zy = self.digit(z, y);
                        if zy == x {
                            w.set((B::U, nd, z), &[(B::C, nd, z, 1)]);
                            continue;
                        }
                        let (p, zp) = self.partner(nd, z);
                        if zy < x || in_e[p] {
                            let (sc, sp, su, sup) = self.slots(nd, p);
                            self.pft(w, (nd, z), (p, zp), [sc, sp], su);
                            self.pft(w, (nd, z), (p, zp), [sc, sp], sup);
                        }
                    }
                }
                self.mds_plane(w, z, &have, &e, &coef);
            }
            for z in (0..s).filter(|z| ord[*z] == o) {
                for &nd in &e {
                    let (x, y) = (nd % q, nd / q);
                    let zy = self.digit(z, y);
                    if zy == x {
                        w.set((B::C, nd, z), &[(B::U, nd, z, 1)]);
                        continue;
                    }
                    let (p, zp) = self.partner(nd, z);
                    let (sc, sp, su, sup) = self.slots(nd, p);
                    if !in_e[p] {
                        self.pft(w, (nd, z), (p, zp), [sp, su], sc);
                    } else if zy < x {
                        self.pft(w, (nd, z), (p, zp), [su, sup], sc);
                        self.pft(w, (nd, z), (p, zp), [su, sup], sp);
                    }
                }
            }
        }
        w.e = e;
        w.in_e = in_e;
        w.have = have;
        w.coef = coef;
        w.ord = ord;
        w.cols = cols;
        Ok(())
    }

    /// Codeword length: the set chunk (len must be a multiple, else 0 = invalid), or the whole region.
    fn stripe_len(&self, len: usize) -> usize {
        match self.chunk {
            Some(c) if c > 0 && len.is_multiple_of(c) => c,
            Some(_) => 0,
            None => len,
        }
    }

    /// parity[r] of the k data chunks; equal lengths, a multiple of S (per chunk when [`set_chunk`](Self::set_chunk)).
    pub fn encode(&self, data: &[&[u8]], parity: &mut [&mut [u8]]) {
        let (k, m) = (self.p.k, self.p.m);
        assert_eq!(data.len(), k);
        assert_eq!(parity.len(), m);
        let len = data.first().map_or(0, |d| d.len());
        let cs = self.stripe_len(len);
        if len == 0 {
            return;
        }
        assert!(
            cs != 0 && cs.is_multiple_of(self.p.s),
            "clay region not a multiple of the chunk / S"
        );
        with_work(|w| {
            w.fit(self.nodes(), cs, cs / self.p.s);
            w.e.clear();
            w.e.extend(k + self.p.nu..self.nodes());
            for off in (0..len).step_by(cs) {
                for (i, d) in data.iter().enumerate() {
                    w.c[i * cs..(i + 1) * cs].copy_from_slice(&d[off..off + cs]);
                }
                self.layered(w).expect("clay encode matrix");
                for (j, p) in parity.iter_mut().enumerate() {
                    let nd = k + self.p.nu + j;
                    p[off..off + cs].copy_from_slice(&w.c[nd * cs..(nd + 1) * cs]);
                }
            }
        })
    }

    /// Rebuild raw chunks `want` from surviving `have` (any >= k distinct; at most m missing).
    pub fn decode_into(
        &self,
        have: &[(usize, &[u8])],
        want: &[usize],
        out: &mut [&mut [u8]],
    ) -> Result<(), DecodeError> {
        let (k, m, n) = (self.p.k, self.p.m, self.nodes());
        if out.len() != want.len() || have.is_empty() {
            return Err(DecodeError::Unrecoverable);
        }
        let len = have[0].1.len();
        if have.iter().any(|h| h.1.len() != len) || out.iter().any(|o| o.len() != len) {
            return Err(DecodeError::BadLen);
        }
        for (r, _) in have {
            if *r >= k + m {
                return Err(DecodeError::Unrecoverable);
            }
        }
        if want.iter().any(|r| *r >= k + m) {
            return Err(DecodeError::Unrecoverable);
        }
        let cs = self.stripe_len(len);
        if len == 0 {
            return Ok(());
        }
        if cs == 0 || !cs.is_multiple_of(self.p.s) {
            return Err(DecodeError::BadLen);
        }
        with_work(|w| {
            w.fit(n, cs, cs / self.p.s);
            // missing raw chunks -> nodes; pad with parity nodes (spec 5.2 step 1)
            w.in_e.clear();
            w.in_e.resize(k + m, false);
            for (r, _) in have {
                w.in_e[*r] = true;
            }
            w.e.clear();
            w.e.extend((0..k + m).filter(|r| !w.in_e[*r]).map(|r| self.node_of(r)));
            if w.e.len() > m {
                return Err(DecodeError::Unrecoverable);
            }
            let mut pn = k + self.p.nu;
            while w.e.len() < m {
                if !w.e.contains(&pn) {
                    w.e.push(pn);
                }
                pn += 1;
            }
            w.e.sort_unstable();
            for off in (0..len).step_by(cs) {
                for (r, b) in have {
                    let nd = self.node_of(*r);
                    w.c[nd * cs..(nd + 1) * cs].copy_from_slice(&b[off..off + cs]);
                }
                self.layered(w)?;
                for (i, r) in want.iter().enumerate() {
                    let nd = self.node_of(*r);
                    out[i][off..off + cs].copy_from_slice(&w.c[nd * cs..(nd + 1) * cs]);
                }
            }
            Ok(())
        })
    }

    /// Base minimum_to_decode (spec 6.2): `want` if all available, else the first k available ascending.
    pub fn read_set(&self, want: &[usize], avail: &[usize]) -> Option<Vec<usize>> {
        if want.iter().all(|r| avail.contains(r)) {
            return Some(want.to_vec());
        }
        let mut a: Vec<usize> = avail
            .iter()
            .copied()
            .filter(|r| *r < self.p.k + self.p.m)
            .collect();
        a.sort_unstable();
        a.dedup();
        if a.len() < self.p.k {
            return None;
        }
        a.truncate(self.p.k);
        Some(a)
    }

    // ---- repair path (spec 6; internal, default-off) ----------------------------------------------------------

    /// Squid `is_repair` (spec 6.1, incl. the virtual-node-to-data-id quirk of step 3).
    pub fn is_repair(&self, want: &[usize], avail: &[usize]) -> bool {
        if want.iter().all(|r| avail.contains(r)) || want.len() != 1 {
            return false;
        }
        let (q, k, nu) = (self.p.q, self.p.k, self.p.nu);
        let i = want[0];
        let l = self.node_of(i);
        for x in 0..q {
            let c = (l / q) * q + x;
            let id = if c < k { c } else { c - nu };
            if id != i && !avail.contains(&id) {
                return false;
            }
        }
        avail.len() >= self.p.d
    }

    /// Sub-chunks a helper reads to repair `want` (spec 6.1, ids divided by q literally).
    pub fn repair_sub_chunk_count(&self, want: &[usize]) -> usize {
        let q = self.p.q;
        let prod: usize = (0..self.p.t)
            .map(|y| q - want.iter().filter(|r| *r / q == y).count().min(q))
            .product();
        self.p.s - prod
    }

    /// Repair planes of lost raw chunk `lost` as (first, count) ranges, ascending (spec 6.1).
    pub fn repair_subchunks(&self, lost: usize) -> Vec<(usize, usize)> {
        let l = self.node_of(lost);
        let (xl, yl) = (l % self.p.q, l / self.p.q);
        let seq = self.pw[yl];
        let num = self.p.q.pow(yl as u32);
        (0..num)
            .map(|j| (xl * seq + j * self.p.q * seq, seq))
            .collect()
    }

    /// minimum_to_repair (spec 6.2): d helper raw ids (column-mates first, then ascending `avail`); `None` when
    /// `is_repair` is false.
    pub fn minimum_to_repair(&self, lost: usize, avail: &[usize]) -> Option<Vec<usize>> {
        if !self.is_repair(&[lost], avail) {
            return None;
        }
        let (q, l) = (self.p.q, self.node_of(lost));
        let mut out: Vec<usize> = (0..q)
            .filter(|x| *x != l % q)
            .filter_map(|x| self.raw_of((l / q) * q + x))
            .collect();
        let mut a = avail.to_vec();
        a.sort_unstable();
        for r in a {
            if out.len() >= self.p.d {
                break;
            }
            if !out.contains(&r) && r != lost {
                out.push(r);
            }
        }
        (out.len() == self.p.d).then_some(out)
    }

    /// Repair raw chunk `lost` into `out` from helpers `(raw, bytes)`: each helper's values on the repair planes in
    /// ascending plane order (len = out.len() / q, per stripe when the chunk is set). Every real column-mate of the
    /// lost chunk must be a helper; real nodes neither lost nor helpers are aloof (spec 6.4).
    pub fn repair(
        &self,
        lost: usize,
        helpers: &[(usize, &[u8])],
        out: &mut [u8],
    ) -> Result<(), DecodeError> {
        with_work(|w| self.repair_work(w, lost, helpers, out))
    }

    fn repair_work(
        &self,
        w: &mut Work,
        lost: usize,
        helpers: &[(usize, &[u8])],
        out: &mut [u8],
    ) -> Result<(), DecodeError> {
        let (k, m, q, t, s, n) = (
            self.p.k,
            self.p.m,
            self.p.q,
            self.p.t,
            self.p.s,
            self.nodes(),
        );
        if lost >= k + m {
            return Err(DecodeError::Unrecoverable);
        }
        let len = out.len();
        let cs = self.stripe_len(len);
        if len == 0 {
            return Ok(());
        }
        if cs == 0 || !cs.is_multiple_of(s) {
            return Err(DecodeError::BadLen);
        }
        let sc = cs / s;
        let hl = cs / q;
        if helpers.iter().any(|h| h.1.len() != len / q) {
            return Err(DecodeError::BadLen);
        }
        let l = self.node_of(lost);
        let (xl, yl) = (l % q, l / q);
        let mut is_helper = vec![false; n];
        for (r, _) in helpers {
            if *r >= k + m || *r == lost {
                return Err(DecodeError::Unrecoverable);
            }
            is_helper[self.node_of(*r)] = true;
        }
        let real = |x: usize| self.raw_of(x).is_some();
        // column-mates must be helpers
        if (0..q).any(|x| {
            let c = yl * q + x;
            c != l && real(c) && !is_helper[c]
        }) {
            return Err(DecodeError::Unrecoverable);
        }
        let aloof: Vec<usize> = (0..n)
            .filter(|&x| real(x) && x != l && !is_helper[x] && x / q != yl)
            .collect();
        let mut in_e = vec![false; n];
        let mut in_a = vec![false; n];
        (0..q).for_each(|x| in_e[yl * q + x] = true);
        aloof.iter().for_each(|&x| {
            in_e[x] = true;
            in_a[x] = true
        });
        let mut e = std::mem::take(&mut w.e);
        e.clear();
        e.extend((0..n).filter(|x| in_e[*x]));
        if e.len() > m {
            w.e = e;
            return Err(DecodeError::Unrecoverable);
        }
        let mut have = std::mem::take(&mut w.have);
        have.clear();
        have.extend((0..n).filter(|x| !in_e[*x]).take(k + self.p.nu));
        w.e = e;
        w.have = have;
        w.fit(n, cs, sc);
        w.prepare(&self.mds, self.mds_id())?;
        let coef = std::mem::take(&mut w.coef);
        let e = std::mem::take(&mut w.e);
        let have = std::mem::take(&mut w.have);
        let rp: Vec<usize> = (0..s).filter(|z| self.digit(*z, yl) == xl).collect();
        let ord: Vec<usize> = (0..s)
            .map(|z| {
                (0..n)
                    .filter(|&x| (x == l || in_a[x]) && self.digit(z, x / q) == x % q)
                    .count()
            })
            .collect();
        let maxo = rp.iter().map(|z| ord[*z]).max().unwrap_or(0);
        for (st, off) in (0..len).step_by(cs).enumerate() {
            w.c.fill(0);
            for (r, b) in helpers {
                let nd = self.node_of(*r);
                let src = &b[st * hl..(st + 1) * hl];
                for (i, z) in rp.iter().enumerate() {
                    let o = nd * cs + z * sc;
                    w.c[o..o + sc].copy_from_slice(&src[i * sc..(i + 1) * sc]);
                }
            }
            // every order present (classic stops at the first empty order, U-CL4: not copied)
            for o in 1..=maxo {
                for &z in rp.iter().filter(|z| ord[**z] == o) {
                    for y in 0..t {
                        for x in 0..q {
                            let nd = y * q + x;
                            if in_e[nd] {
                                continue;
                            }
                            let zy = self.digit(z, y);
                            if zy == x {
                                w.set((B::U, nd, z), &[(B::C, nd, z, 1)]);
                                continue;
                            }
                            let (p, zp) = self.partner(nd, z);
                            let (sc_, sp, su, sup) = self.slots(nd, p);
                            if in_a[p] {
                                self.pft(w, (nd, z), (p, zp), [sc_, sup], su);
                            } else {
                                self.pft(w, (nd, z), (p, zp), [sc_, sp], su);
                            }
                        }
                    }
                    self.mds_plane(w, z, &have, &e, &coef);
                    for &nd in e.iter().filter(|x| !in_a[**x]) {
                        if nd == l {
                            w.set((B::C, l, z), &[(B::U, l, z, 1)]);
                            continue;
                        }
                        // column-mate: its partner at z is L at plane z' (non-repair plane of L)
                        let (p, zp) = self.partner(nd, z);
                        debug_assert_eq!(p, l);
                        let (sc_, sp, su, _) = self.slots(nd, p);
                        self.pft(w, (nd, z), (p, zp), [sc_, su], sp);
                    }
                }
            }
            out[off..off + cs].copy_from_slice(&w.c[l * cs..(l + 1) * cs]);
        }
        w.e = e;
        w.have = have;
        w.coef = coef;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
