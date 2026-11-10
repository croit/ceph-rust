// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `lrc` plugin: layered, locally repairable code (spec ec-lrc.md). Every layer is a plain MDS sub-code over a subset
//! of POSITIONS (= shard ids = indices of the `mapping` string). The [`Code`] API speaks RAW chunk indices; the
//! raw <-> position permutation is the profile chunk mapping (raw 0..k = 'D' positions ascending, then the others).
//! Encode: layers first to last. Decode: ONE pass, layers last to first. Read plan: the 3-case planner of spec 6.

use crate::code::Code;
use crate::gf::DecodeError;
use std::collections::BTreeMap;

/// One layer of the profile: chunk string + sub-plugin profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LrcLayer {
    pub chunks: String,
    pub profile: BTreeMap<String, String>,
}

/// Validated `mapping` + `layers` of an lrc profile (explicit or generated from k/m/l).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LrcSpec {
    pub mapping: String,
    pub layers: Vec<LrcLayer>,
}

/// k/m/l key: `None` = unset (absent, empty, or -1, the default the mon writes back, spec ec-parity.md 14.1).
fn num(map: &BTreeMap<String, String>, key: &str) -> Result<Option<usize>, String> {
    match crate::profile::int_key(map, key)? {
        None | Some(-1) => Ok(None),
        Some(n) => usize::try_from(n)
            .map(Some)
            .map_err(|_| format!("lrc profile key {key}={n} out of range")),
    }
}

impl LrcSpec {
    /// From the profile map: k/m/l shorthand (all three) or explicit `mapping` + `layers` (spec 1.1, 1.4); k/m/l
    /// stored as -1 (every mon-created explicit-layer profile) count as unset.
    pub fn from_map(map: &BTreeMap<String, String>) -> Result<LrcSpec, String> {
        let (k, m, l) = (num(map, "k")?, num(map, "m")?, num(map, "l")?);
        if k.is_some() || m.is_some() || l.is_some() {
            let (Some(k), Some(m), Some(l)) = (k, m, l) else {
                return Err("lrc: k, m and l must be given together".into());
            };
            if ["mapping", "layers", "crush-steps"]
                .iter()
                .any(|x| map.contains_key(*x))
            {
                return Err("lrc: k/m/l cannot be combined with mapping/layers/crush-steps".into());
            }
            return Self::generate(k, m, l);
        }
        let Some(mapping) = map.get("mapping") else {
            return Err("lrc: no mapping".into());
        };
        let Some(layers) = map.get("layers") else {
            return Err("lrc: no layers".into());
        };
        let J::Arr(items) = parse_json(layers)? else {
            return Err("lrc: layers is not a JSON array".into());
        };
        let mut out = Vec::new();
        for it in items {
            let J::Arr(el) = it else {
                return Err("lrc: layer is not an array".into());
            };
            let Some(J::Str(chunks)) = el.first() else {
                return Err("lrc: layer chunk string missing".into());
            };
            let profile = match el.get(1) {
                None => BTreeMap::new(),
                Some(J::Str(s)) => layer_profile_str(s)?,
                Some(J::Obj(o)) => {
                    let mut r = BTreeMap::new();
                    for (a, b) in o {
                        let J::Str(b) = b else {
                            return Err("lrc: layer profile value is not a string".into());
                        };
                        r.insert(a.clone(), b.clone());
                    }
                    r
                }
                Some(_) => return Err("lrc: layer profile is not a string or object".into()),
            };
            out.push(LrcLayer {
                chunks: chunks.clone(),
                profile,
            });
        }
        if out.is_empty() {
            return Err("lrc: no layers".into());
        }
        let spec = LrcSpec {
            mapping: mapping.clone(),
            layers: out,
        };
        spec.check()?;
        Ok(spec)
    }

    /// k/m/l shorthand (spec 1.4).
    pub fn generate(k: usize, m: usize, l: usize) -> Result<LrcSpec, String> {
        // the mapping is k+m positions long: refuse the geometry before building the mapping/layer strings (a
        // mon-stored k/m/l profile reaches this on every OSD-map apply)
        let n = k
            .checked_add(m)
            .ok_or_else(|| "lrc: k+m overflow".to_string())?;
        if n == 0 || n > 127 {
            return Err(format!("lrc: bad mapping length {n}"));
        }
        if l == 0 || !n.is_multiple_of(l) {
            return Err(format!("lrc: k+m={n} not a multiple of l={l}"));
        }
        let g = n / l;
        if !k.is_multiple_of(g) || !m.is_multiple_of(g) {
            return Err(format!(
                "lrc: k={k} and m={m} must be multiples of (k+m)/l={g}"
            ));
        }
        let (kg, mg) = (k / g, m / g);
        let rep =
            |a: &str, b: &str, c: &str| format!("{}{}{c}", a.repeat(kg), b.repeat(mg)).repeat(g);
        let mapping = rep("D", "_", "_");
        let mut layers = vec![LrcLayer {
            chunks: rep("D", "c", "_"),
            profile: BTreeMap::new(),
        }];
        for i in 0..g {
            let chunks = (0..g)
                .map(|j| {
                    if j == i {
                        format!("{}c", "D".repeat(l))
                    } else {
                        "_".repeat(l + 1)
                    }
                })
                .collect::<String>();
            layers.push(LrcLayer {
                chunks,
                profile: BTreeMap::new(),
            });
        }
        let spec = LrcSpec { mapping, layers };
        spec.check()?;
        Ok(spec)
    }

    fn check(&self) -> Result<(), String> {
        let n = self.mapping.len();
        if n == 0 || n > 127 || !self.mapping.is_ascii() {
            return Err(format!("lrc: bad mapping length {n}"));
        }
        for (i, l) in self.layers.iter().enumerate() {
            if l.chunks.len() != n || !l.chunks.is_ascii() {
                return Err(format!("lrc: layer {i} length != mapping length {n}"));
            }
        }
        Ok(())
    }

    /// Number of mapping 'D' positions (pool k).
    pub fn data_count(&self) -> usize {
        self.mapping.bytes().filter(|c| *c == b'D').count()
    }
}

/// Layer profile string: a JSON object of strings, else `key=value` words (spec 1.3).
fn layer_profile_str(s: &str) -> Result<BTreeMap<String, String>, String> {
    if let Ok(J::Obj(o)) = parse_json(s) {
        let mut r = BTreeMap::new();
        for (a, b) in o {
            let J::Str(b) = b else {
                return Err("lrc: layer profile value is not a string".into());
            };
            r.insert(a, b);
        }
        return Ok(r);
    }
    let mut r = BTreeMap::new();
    for w in s.split([' ', '\t', '\n']).filter(|w| !w.is_empty()) {
        let (a, b) = w.split_once('=').unwrap_or((w, ""));
        r.insert(a.to_string(), b.to_string());
    }
    Ok(r)
}

// ---- tiny strict JSON reader (layers array) --------------------------------------------------------------------

#[derive(Debug)]
enum J {
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
    Other,
}

struct Rd<'a> {
    s: &'a [u8],
    i: usize,
}

fn parse_json(s: &str) -> Result<J, String> {
    let mut r = Rd {
        s: s.as_bytes(),
        i: 0,
    };
    let v = r.value(0)?;
    r.ws();
    if r.i != r.s.len() {
        return Err("lrc: trailing JSON garbage".into());
    }
    Ok(v)
}

impl Rd<'_> {
    fn ws(&mut self) {
        while matches!(self.s.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: u8) -> Result<(), String> {
        self.ws();
        if self.s.get(self.i) == Some(&c) {
            self.i += 1;
            Ok(())
        } else {
            Err(format!("lrc: bad JSON, expected {:?}", c as char))
        }
    }

    fn value(&mut self, depth: u32) -> Result<J, String> {
        if depth > 8 {
            return Err("lrc: JSON too deep".into());
        }
        self.ws();
        match self.s.get(self.i) {
            Some(b'"') => Ok(J::Str(self.string()?)),
            Some(b'[') => {
                self.i += 1;
                let mut v = Vec::new();
                self.ws();
                if self.s.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Ok(J::Arr(v));
                }
                loop {
                    v.push(self.value(depth + 1)?);
                    self.ws();
                    match self.s.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(J::Arr(v));
                        }
                        _ => return Err("lrc: bad JSON array".into()),
                    }
                }
            }
            Some(b'{') => {
                self.i += 1;
                let mut v = Vec::new();
                self.ws();
                if self.s.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    return Ok(J::Obj(v));
                }
                loop {
                    self.ws();
                    let k = self.string()?;
                    self.eat(b':')?;
                    v.push((k, self.value(depth + 1)?));
                    self.ws();
                    match self.s.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(J::Obj(v));
                        }
                        _ => return Err("lrc: bad JSON object".into()),
                    }
                }
            }
            Some(_) => {
                let a = self.i;
                while self
                    .s
                    .get(self.i)
                    .is_some_and(|c| c.is_ascii_alphanumeric() || b"+-.".contains(c))
                {
                    self.i += 1;
                }
                let t = &self.s[a..self.i];
                let lit = matches!(t, b"true" | b"false" | b"null");
                let n =
                    !t.is_empty() && t.iter().all(|c| c.is_ascii_digit() || b"+-.eE".contains(c));
                if lit || n {
                    Ok(J::Other)
                } else {
                    Err("lrc: bad JSON value".into())
                }
            }
            None => Err("lrc: truncated JSON".into()),
        }
    }

    fn string(&mut self) -> Result<String, String> {
        if self.s.get(self.i) != Some(&b'"') {
            return Err("lrc: bad JSON string".into());
        }
        self.i += 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let Some(&c) = self.s.get(self.i) else {
                return Err("lrc: unterminated JSON string".into());
            };
            self.i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let Some(&e) = self.s.get(self.i) else {
                        return Err("lrc: bad JSON escape".into());
                    };
                    self.i += 1;
                    match e {
                        b'"' | b'\\' | b'/' => out.push(e),
                        b'n' => out.push(b'\n'),
                        b't' => out.push(b'\t'),
                        b'r' => out.push(b'\r'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'u' => {
                            let h = self.s.get(self.i..self.i + 4).ok_or("lrc: bad \\u")?;
                            let h = std::str::from_utf8(h).map_err(|_| "lrc: bad \\u")?;
                            let c = u32::from_str_radix(h, 16)
                                .ok()
                                .and_then(char::from_u32)
                                .ok_or("lrc: bad \\u")?;
                            self.i += 4;
                            let mut b = [0u8; 4];
                            out.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
                        }
                        _ => return Err("lrc: bad JSON escape".into()),
                    }
                }
                c if c < 0x20 => return Err("lrc: control char in JSON string".into()),
                c => out.push(c),
            }
        }
        String::from_utf8(out).map_err(|_| "lrc: JSON string not UTF-8".into())
    }
}

// ---- codec -----------------------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Layer {
    /// positions: data (ascending) then coding (ascending)
    chunks: Vec<usize>,
    kl: usize,
    /// bit mask over positions
    mask: u128,
    ml: usize,
    code: Code,
    /// Its relation holds on the stored chunks: encoded (index >= top) and no later layer codes into one of its
    /// positions (spec ec-parity.md 14.2). Only usable layers serve decodes and read plans.
    usable: bool,
}

#[derive(Clone, Debug)]
pub struct LrcCodec {
    n: usize,
    k: usize,
    /// raw -> position
    map: Vec<usize>,
    /// position -> raw
    inv: Vec<usize>,
    layers: Vec<Layer>,
    /// Some encoded layer codes into a mapping data position (spec ec-parity.md 14.2): [`LrcCodec::encode_all`].
    rewrites: bool,
    /// First layer a full-stripe encode runs (spec ec-lrc.md 3.1): when a later layer touches every position, the layers
    /// before it are never encoded (their parity positions stay zero, as classic writes them) and must not serve decodes.
    top: usize,
    unit: usize,
}

fn gcd(a: usize, b: usize) -> usize {
    if b == 0 { a } else { gcd(b, a % b) }
}

fn bits(mut m: u128) -> impl Iterator<Item = usize> {
    std::iter::from_fn(move || {
        if m == 0 {
            None
        } else {
            let b = m.trailing_zeros() as usize;
            m &= m - 1;
            Some(b)
        }
    })
}

impl LrcCodec {
    /// `default_plugin` ("isa" = Ceph main, "jerasure" = pre-2024 data, corpus) applies to layers without `plugin`.
    pub fn new(spec: &LrcSpec, default_plugin: &str) -> Result<LrcCodec, String> {
        spec.check()?;
        let n = spec.mapping.len();
        let dpos: Vec<usize> = (0..n)
            .filter(|&p| spec.mapping.as_bytes()[p] == b'D')
            .collect();
        let k = dpos.len();
        let map: Vec<usize> = dpos
            .iter()
            .copied()
            .chain((0..n).filter(|&p| spec.mapping.as_bytes()[p] != b'D'))
            .collect();
        let mut inv = vec![0; n];
        for (r, &p) in map.iter().enumerate() {
            inv[p] = r;
        }
        let mut unit = 32;
        let mut layers = Vec::new();
        for (i, l) in spec.layers.iter().enumerate() {
            let at = |ch: u8| -> Vec<usize> {
                (0..n).filter(|&p| l.chunks.as_bytes()[p] == ch).collect()
            };
            let (d, c) = (at(b'D'), at(b'c'));
            let mut prof = l.profile.clone();
            for (key, v) in [("k", d.len()), ("m", c.len())] {
                if let Some(x) = prof.get(key).filter(|x| !x.is_empty())
                    && crate::profile::parse_int(x) != i32::try_from(v).ok()
                {
                    return Err(format!("lrc: layer {i} {key}={x} != chunk string ({v})"));
                }
                prof.insert(key.into(), v.to_string());
            }
            prof.entry("plugin".into())
                .or_insert_with(|| default_plugin.to_string());
            if !matches!(
                crate::profile::EcProfile::parse(&prof).map(|p| p.plugin),
                Ok(crate::profile::Plugin::Isa | crate::profile::Plugin::Jerasure)
            ) {
                return Err(format!(
                    "lrc: layer {i} plugin {:?} not supported",
                    prof["plugin"]
                ));
            }
            prof.entry("technique".into())
                .or_insert_with(|| "reed_sol_van".into());
            let code = Code::from_profile(&prof).map_err(|e| format!("lrc layer {i}: {e}"))?;
            // The profile is map input. Its common alignment must fit before the
            // gate can compare it with the pool's chunk size.
            unit = (unit / gcd(unit, code.unit()))
                .checked_mul(code.unit())
                .ok_or_else(|| format!("lrc: layer {i} common alignment overflows usize"))?;
            let mask = d.iter().chain(&c).fold(0u128, |a, &p| a | 1 << p);
            layers.push(Layer {
                kl: d.len(),
                ml: c.len(),
                chunks: d.into_iter().chain(c).collect(),
                mask,
                code,
                usable: false,
            });
        }
        let full = (1u128 << n) - 1;
        let top = layers
            .iter()
            .rposition(|l| l.mask & full == full)
            .unwrap_or(0);
        // coding positions of the layers after each one (classic encodes first to last, later layers overwrite)
        let mut later = 0u128;
        for l in layers[top..].iter_mut().rev() {
            l.usable = l.mask & later == 0;
            later |= l.mask & !l.chunks[..l.kl].iter().fold(0u128, |a, &p| a | 1 << p);
        }
        let dmask = dpos.iter().fold(0u128, |a, &p| a | 1 << p);
        let rewrites = layers[top..]
            .iter()
            .any(|l| l.chunks[l.kl..].iter().any(|&p| dmask >> p & 1 == 1));
        Ok(LrcCodec {
            n,
            k,
            map,
            inv,
            layers,
            rewrites,
            top,
            unit,
        })
    }

    pub fn k(&self) -> usize {
        self.k
    }
    pub fn m(&self) -> usize {
        self.n - self.k
    }
    pub fn unit(&self) -> usize {
        self.unit
    }
    /// raw chunk index -> position (shard).
    pub fn mapping(&self) -> &[usize] {
        &self.map
    }

    fn full(&self) -> u128 {
        (1u128 << self.n) - 1
    }

    /// A layer codes into a data position: [`Self::encode_all`] (data chunks change).
    pub fn rewrites_data(&self) -> bool {
        self.rewrites
    }

    /// Every raw chunk (`out.len() == n`): data placed at the mapping D positions, then the layers first to last,
    /// each writing its `c` positions, also over data (classic literal order, spec ec-parity.md 14.2). Positions no
    /// layer writes stay zero (classic: uninitialised memory, oracle `pools/lrccOnD` shard 2).
    pub fn encode_all(&self, data: &[&[u8]], out: &mut [&mut [u8]]) {
        assert_eq!(data.len(), self.k);
        assert_eq!(out.len(), self.n);
        // move the caller's buffers into position slots: raw r is written at position map[r]
        let mut slots: Vec<Option<&mut [u8]>> = (0..self.n).map(|_| None).collect();
        for (r, o) in out.iter_mut().enumerate() {
            slots[self.map[r]] = Some(std::mem::take(o));
        }
        for (r, &p) in self.map.iter().enumerate() {
            let s = slots[p].as_mut().expect("every position has a buffer");
            if r < self.k {
                s.copy_from_slice(data[r]);
            } else {
                s.fill(0);
            }
        }
        // layers write straight into their positions (in place: no per-layer copy of the codeword)
        for l in &self.layers[self.top..] {
            let mut outs: Vec<&mut [u8]> = Vec::with_capacity(l.ml);
            for &p in &l.chunks[l.kl..] {
                outs.push(slots[p].take().expect("coding position is not an input"));
            }
            {
                let ins: Vec<&[u8]> = l.chunks[..l.kl]
                    .iter()
                    .map(|&p| &slots[p].as_ref().expect("input position is set")[..])
                    .collect();
                l.code.encode(&ins, &mut outs);
            }
            for (&p, o) in l.chunks[l.kl..].iter().zip(outs) {
                slots[p] = Some(o);
            }
        }
        for (r, o) in out.iter_mut().enumerate() {
            *o = slots[self.map[r]]
                .take()
                .expect("every position has a buffer");
        }
    }

    /// Parity raw chunks k..n. Data chunks are unchanged only when ![`Self::rewrites_data`].
    pub fn encode(&self, data: &[&[u8]], parity: &mut [&mut [u8]]) {
        assert_eq!(data.len(), self.k);
        assert_eq!(parity.len(), self.n - self.k);
        if self.rewrites {
            let len = data.first().map_or(0, |d| d.len());
            let mut all = vec![vec![0u8; len]; self.n];
            {
                let mut o: Vec<&mut [u8]> = all.iter_mut().map(|v| &mut v[..]).collect();
                self.encode_all(data, &mut o);
            }
            for (p, v) in parity.iter_mut().zip(&all[self.k..]) {
                p.copy_from_slice(v);
            }
            return;
        }
        // data chunks stay where the caller has them; only the parity slots are writable positions
        let mut src: Vec<Option<&[u8]>> = vec![None; self.n];
        for (r, d) in data.iter().enumerate() {
            src[self.map[r]] = Some(d);
        }
        let mut slots: Vec<Option<&mut [u8]>> = (0..self.n).map(|_| None).collect();
        for (j, p) in parity.iter_mut().enumerate() {
            p.fill(0);
            slots[self.map[self.k + j]] = Some(&mut **p);
        }
        for l in &self.layers[self.top..] {
            let mut outs: Vec<&mut [u8]> = l.chunks[l.kl..]
                .iter()
                .map(|&p| slots[p].take().expect("coding position is a parity slot"))
                .collect();
            {
                // every position is either a data chunk or a parity slot (the mapping is a bijection)
                let ins: Vec<&[u8]> = l.chunks[..l.kl]
                    .iter()
                    .map(|&p| {
                        src[p]
                            .or(slots[p].as_deref())
                            .expect("input position is set")
                    })
                    .collect();
                l.code.encode(&ins, &mut outs);
            }
            for (&p, o) in l.chunks[l.kl..].iter().zip(outs) {
                slots[p] = Some(o);
            }
        }
    }

    /// Single pass last -> first layer (spec 5). `have` = raw chunks read (the set [`read_set`](Self::read_set) gave).
    pub fn decode_into(
        &self,
        have: &[(usize, &[u8])],
        want: &[usize],
        out: &mut [&mut [u8]],
    ) -> Result<(), DecodeError> {
        if out.len() != want.len() || have.is_empty() {
            return Err(DecodeError::Unrecoverable);
        }
        let len = have[0].1.len();
        if have.iter().any(|h| h.1.len() != len) || out.iter().any(|o| o.len() != len) {
            return Err(DecodeError::BadLen);
        }
        let mut src: Vec<Option<&[u8]>> = vec![None; self.n];
        let mut hm = 0u128;
        for (r, b) in have {
            let p = *self.map.get(*r).ok_or(DecodeError::Unrecoverable)?;
            if hm >> p & 1 == 1 {
                return Err(DecodeError::Unrecoverable);
            }
            hm |= 1 << p;
            src[p] = Some(b);
        }
        let mut wm = 0u128;
        let mut wp = Vec::with_capacity(want.len());
        for r in want {
            let p = *self.map.get(*r).ok_or(DecodeError::Unrecoverable)?;
            wm |= 1 << p;
            wp.push(p);
        }
        let mut rec: Vec<Option<Vec<u8>>> = vec![None; self.n];
        let mut e = self.full() & !hm;
        for l in self.layers[self.top..].iter().rev().filter(|l| l.usable) {
            if e & wm == 0 {
                break;
            }
            let le = e & l.mask;
            if le == 0 || le.count_ones() as usize > l.ml {
                continue;
            }
            let get = |p: usize| src[p].or(rec[p].as_deref());
            let (mut avail, mut erased) = (Vec::new(), Vec::new());
            for (i, &p) in l.chunks.iter().enumerate() {
                if get(p).is_some() {
                    avail.push(i)
                } else {
                    erased.push(i)
                }
            }
            let set = l
                .code
                .read_set(&erased, &avail)
                .ok_or(DecodeError::Unrecoverable)?;
            let h: Vec<(usize, &[u8])> = set
                .iter()
                .map(|&i| (i, get(l.chunks[i]).unwrap()))
                .collect();
            let mut outs = vec![vec![0u8; len]; erased.len()];
            {
                let mut o: Vec<&mut [u8]> = outs.iter_mut().map(|v| &mut v[..]).collect();
                l.code.decode_into(&h, &erased, &mut o)?;
            }
            for (&i, v) in erased.iter().zip(outs) {
                rec[l.chunks[i]] = Some(v);
            }
            e &= !l.mask;
        }
        if e & wm != 0 {
            return Err(DecodeError::Unrecoverable);
        }
        for (o, p) in out.iter_mut().zip(wp) {
            o.copy_from_slice(
                src[p]
                    .or(rec[p].as_deref())
                    .ok_or(DecodeError::Unrecoverable)?,
            );
        }
        Ok(())
    }

    fn to_mask(&self, raws: &[usize]) -> Option<u128> {
        raws.iter()
            .try_fold(0u128, |a, &r| self.map.get(r).map(|&p| a | 1 << p))
    }

    /// minimum_to_decode (spec 6) in raw indices, ascending by position. `None` = -EIO.
    pub fn read_set(&self, want: &[usize], avail: &[usize]) -> Option<Vec<usize>> {
        let want = self.to_mask(want)?;
        let avail = avail
            .iter()
            .filter_map(|&r| self.map.get(r))
            .fold(0u128, |a, &p| a | 1 << p);
        let min = self.plan(want, avail)?;
        Some(bits(min).map(|p| self.inv[p]).collect())
    }

    /// Planner on position masks.
    pub fn plan(&self, want: u128, avail: u128) -> Option<u128> {
        let e_total = self.full() & !avail;
        let mut e_want = want & e_total;
        if e_want == 0 {
            return Some(want);
        }
        // case 2: local first
        let mut e_nr = e_total;
        let mut min = 0u128;
        for l in self.layers[self.top..].iter().rev().filter(|l| l.usable) {
            let lw = want & l.mask;
            if lw == 0 {
                continue;
            }
            if lw & e_want == 0 {
                min |= lw;
                continue;
            }
            let er = l.mask & e_nr;
            if er.count_ones() as usize > l.ml {
                continue;
            }
            min |= l.mask & !e_nr;
            e_nr &= !er;
            e_want &= !er;
        }
        if e_want == 0 {
            return Some((min | want) & !e_total);
        }
        // case 3: read everything
        let mut e = e_total;
        for l in self.layers[self.top..].iter().rev().filter(|l| l.usable) {
            let le = l.mask & e;
            if le != 0 && le.count_ones() as usize <= l.ml {
                e &= !le;
            }
        }
        (e == 0).then_some(avail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pm(kv: &[(&str, &str)]) -> BTreeMap<String, String> {
        kv.iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    fn kml(k: usize, m: usize, l: usize) -> Result<LrcSpec, String> {
        LrcSpec::generate(k, m, l)
    }

    fn layers(s: &LrcSpec) -> Vec<&str> {
        s.layers.iter().map(|l| l.chunks.as_str()).collect()
    }

    #[test]
    fn generated_strings() {
        let s = kml(2, 2, 2).unwrap();
        assert_eq!(s.mapping, "D__D__");
        assert_eq!(layers(&s), ["Dc_Dc_", "DDc___", "___DDc"]);
        let s = kml(4, 2, 3).unwrap();
        assert_eq!(s.mapping, "DD__DD__");
        assert_eq!(layers(&s), ["DDc_DDc_", "DDDc____", "____DDDc"]);
        let s = kml(8, 4, 3).unwrap();
        assert_eq!(s.mapping, "DD__DD__DD__DD__");
        assert_eq!(
            layers(&s),
            [
                "DDc_DDc_DDc_DDc_",
                "DDDc____________",
                "____DDDc________",
                "________DDDc____",
                "____________DDDc"
            ]
        );
        let s = kml(6, 2, 4).unwrap();
        assert_eq!(s.mapping, "DDD__DDD__");
        assert_eq!(layers(&s), ["DDDc_DDDc_", "DDDDc_____", "_____DDDDc"]);
        let s = kml(4, 2, 6).unwrap();
        assert_eq!(s.mapping, "DDDD___");
        assert_eq!(layers(&s), ["DDDDcc_", "DDDDDDc"]);
        let s = kml(4, 4, 4).unwrap();
        assert_eq!(s.mapping, "DD___DD___");
        assert_eq!(layers(&s), ["DDcc_DDcc_", "DDDDc_____", "_____DDDDc"]);
        assert!(kml(8, 4, 4).is_err());
        assert!(kml(4, 2, 0).is_err());
        assert!(kml(4, 2, 4).is_err());
    }

    #[test]
    fn profile_forms() {
        let s = LrcSpec::from_map(&pm(&[
            ("plugin", "lrc"),
            ("k", "4"),
            ("m", "2"),
            ("l", "3"),
        ]))
        .unwrap();
        assert_eq!(s, kml(4, 2, 3).unwrap());
        for bad in [
            pm(&[("k", "4"), ("m", "2")]),
            pm(&[("k", "4"), ("m", "2"), ("l", "3"), ("mapping", "DD__DD__")]),
            pm(&[("k", "4"), ("m", "2"), ("l", "x")]),
            pm(&[("mapping", "DD_")]),
            pm(&[("layers", "[]")]),
            pm(&[("mapping", "DD_"), ("layers", "[]")]),
            pm(&[("mapping", "DD_"), ("layers", "{}")]),
            pm(&[("mapping", "DD_"), ("layers", "[\"DDc\"]")]),
            pm(&[("mapping", "DD_"), ("layers", "[[5,\"\"]]")]),
            pm(&[("mapping", "DD_"), ("layers", "[[\"DDc\",3]]")]),
            pm(&[("mapping", "DD_"), ("layers", "[[\"DDcc\",\"\"]]")]),
            pm(&[("mapping", "DD_"), ("layers", "[[\"DDc\",\"\"]] x")]),
            pm(&[("mapping", "DD_"), ("layers", "[[\"DDc\",\"\"")]),
        ] {
            assert!(LrcSpec::from_map(&bad).is_err(), "{bad:?}");
        }
        // explicit forms: kv string, JSON object string, object, trailing element ignored
        for lp in [
            "\"plugin=jerasure technique=reed_sol_van\"",
            "\"{\\\"plugin\\\":\\\"jerasure\\\"}\"",
            "{\"plugin\":\"jerasure\",\"technique\":\"reed_sol_van\"}",
            "\"plugin=jerasure\", 7",
        ] {
            let l = format!("[[\"DDc\",{lp}]]");
            let s = LrcSpec::from_map(&pm(&[("mapping", "DD_"), ("layers", &l)])).unwrap();
            assert_eq!(s.layers[0].profile["plugin"], "jerasure", "{lp}");
        }
        // mon-stored explicit form: k=m=l=-1 (any int spelling of -1); mixed -1 / set is invalid
        let l = "[[\"DDc\",\"\"]]";
        for (k, m, ll) in [("-1", "-1", "-1"), ("-01", " -1", "+-1"), ("-1", "", "-1")] {
            let r = LrcSpec::from_map(&pm(&[
                ("k", k),
                ("m", m),
                ("l", ll),
                ("mapping", "DD_"),
                ("layers", l),
            ]));
            assert_eq!(r.is_ok(), ll != "+-1", "{k:?} {m:?} {ll:?}");
        }
        for bad in [
            pm(&[
                ("k", "4"),
                ("m", "-1"),
                ("l", "-1"),
                ("mapping", "DD_"),
                ("layers", l),
            ]),
            pm(&[("k", "4"), ("m", "2"), ("l", "-1")]),
            pm(&[
                ("k", "-2"),
                ("m", "-1"),
                ("l", "-1"),
                ("mapping", "DD_"),
                ("layers", l),
            ]),
        ] {
            assert!(LrcSpec::from_map(&bad).is_err(), "{bad:?}");
        }
        let s = LrcSpec::from_map(&pm(&[("mapping", "DD_"), ("layers", l)])).unwrap();
        assert!(s.layers[0].profile.is_empty());
        let c = LrcCodec::new(&s, "isa").unwrap();
        assert_eq!((c.k(), c.m()), (2, 1));
    }

    #[test]
    fn chunk_mapping_tables() {
        let c = LrcCodec::new(&kml(4, 2, 3).unwrap(), "isa").unwrap();
        assert_eq!(c.mapping(), [0, 1, 4, 5, 2, 3, 6, 7]);
        assert_eq!((c.k(), c.m(), c.unit()), (4, 4, 32));
        let c = LrcCodec::new(&kml(2, 2, 2).unwrap(), "isa").unwrap();
        assert_eq!(c.mapping(), [0, 3, 1, 2, 4, 5]);
    }

    fn pos_set(c: &LrcCodec, raws: &[usize]) -> Vec<usize> {
        let mut v: Vec<usize> = raws.iter().map(|&r| c.mapping()[r]).collect();
        v.sort_unstable();
        v
    }

    /// Planner in POSITION space (identity-free helper for the spec tables).
    fn plan_pos(c: &LrcCodec, want: &[usize], lost: &[usize]) -> Option<Vec<usize>> {
        let m = |s: &[usize]| s.iter().fold(0u128, |a, &p| a | 1 << p);
        let avail = c.full() & !m(lost);
        c.plan(m(want), avail).map(|x| bits(x).collect())
    }

    #[test]
    fn planner_table_423() {
        let c = LrcCodec::new(&kml(4, 2, 3).unwrap(), "isa").unwrap();
        let data = [0, 1, 4, 5];
        let t: &[(&[usize], Option<&[usize]>)] = &[
            (&[0], Some(&[1, 2, 3, 4, 5])),
            (&[1], Some(&[0, 2, 3, 4, 5])),
            (&[4], Some(&[0, 1, 5, 6, 7])),
            (&[5], Some(&[0, 1, 4, 6, 7])),
            (&[2], Some(&[0, 1, 4, 5])),
            (&[3], Some(&[0, 1, 4, 5])),
            (&[6], Some(&[0, 1, 4, 5])),
            (&[7], Some(&[0, 1, 4, 5])),
            (&[0, 1], Some(&[2, 4, 5, 6])),
            (&[0, 2], Some(&[1, 4, 5, 6])),
            (&[0, 3], Some(&[1, 2, 4, 5, 6])),
            (&[0, 4], Some(&[1, 2, 3, 5, 6, 7])),
            (&[1, 5], Some(&[0, 2, 3, 4, 6, 7])),
            (&[0, 1, 4], Some(&[2, 5, 6, 7])),
            (&[0, 1, 2], None),
        ];
        for (lost, exp) in t {
            assert_eq!(plan_pos(&c, &data, lost).as_deref(), *exp, "lost {lost:?}");
        }
        // single lost shard recovery
        let rec: [(usize, [usize; 3]); 8] = [
            (0, [1, 2, 3]),
            (1, [0, 2, 3]),
            (2, [0, 1, 3]),
            (3, [0, 1, 2]),
            (4, [5, 6, 7]),
            (5, [4, 6, 7]),
            (6, [4, 5, 7]),
            (7, [4, 5, 6]),
        ];
        for (x, exp) in rec {
            assert_eq!(plan_pos(&c, &[x], &[x]).unwrap(), exp, "recover {x}");
        }
        // want ALL, one lost: all others
        let all: Vec<usize> = (0..8).collect();
        for x in 0..8 {
            let exp: Vec<usize> = (0..8).filter(|p| *p != x).collect();
            assert_eq!(plan_pos(&c, &all, &[x]).unwrap(), exp);
        }
    }

    #[test]
    fn planner_table_843() {
        let c = LrcCodec::new(&kml(8, 4, 3).unwrap(), "isa").unwrap();
        let data = [0, 1, 4, 5, 8, 9, 12, 13];
        let t: &[(&[usize], &[usize])] = &[
            (&[0], &[1, 2, 3, 4, 5, 8, 9, 12, 13]),
            (&[2], &[0, 1, 4, 5, 8, 9, 12, 13]),
            (&[0, 1], &[2, 4, 5, 6, 8, 9, 10, 12, 13, 14]),
            (&[0, 1, 2], &[4, 5, 6, 8, 9, 10, 12, 13, 14]),
        ];
        for (lost, exp) in t {
            assert_eq!(plan_pos(&c, &data, lost).unwrap(), *exp, "lost {lost:?}");
        }
    }

    #[test]
    fn raw_api_maps_to_positions() {
        let c = LrcCodec::new(&kml(4, 2, 3).unwrap(), "isa").unwrap();
        // position 0 lost: read set = positions 1,2,3,4,5
        let avail_raw: Vec<usize> = (0..8).filter(|r| c.mapping()[*r] != 0).collect();
        let got = c.read_set(&[0, 1, 2, 3], &avail_raw).unwrap();
        assert_eq!(pos_set(&c, &got), [1, 2, 3, 4, 5]);
        assert!(c.read_set(&[9], &avail_raw).is_none());
    }

    // ---- bytes ----

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

    fn encode_all(c: &LrcCodec, len: usize) -> Vec<Vec<u8>> {
        let data: Vec<Vec<u8>> = (0..c.k()).map(|i| pattern(len, i as u32 + 1)).collect();
        let mut par = vec![vec![0u8; len]; c.m()];
        {
            let d: Vec<&[u8]> = data.iter().map(|v| &v[..]).collect();
            let mut o: Vec<&mut [u8]> = par.iter_mut().map(|v| &mut v[..]).collect();
            c.encode(&d, &mut o);
        }
        data.into_iter().chain(par).collect() // raw order
    }

    fn mul(a: u8, b: u8) -> u8 {
        crate::gf::mul(a, b)
    }

    #[test]
    fn worked_example_bytes() {
        // spec 4.1: positions 0,1,4,5 data, jerasure vs isa global parity
        for (plug, row1) in [("jerasure", [1u8, 0x46, 0x8F, 0xC8]), ("isa", [1, 2, 4, 8])] {
            let c = LrcCodec::new(&kml(4, 2, 3).unwrap(), plug).unwrap();
            let all = encode_all(&c, 64);
            let at = |p: usize| &all[c.inv[p]];
            for i in 0..64 {
                let (d0, d1, d4, d5) = (at(0)[i], at(1)[i], at(4)[i], at(5)[i]);
                let g0 = d0 ^ d1 ^ d4 ^ d5;
                let g1 = mul(row1[0], d0) ^ mul(row1[1], d1) ^ mul(row1[2], d4) ^ mul(row1[3], d5);
                assert_eq!(at(2)[i], g0);
                assert_eq!(at(6)[i], g1);
                assert_eq!(at(3)[i], d0 ^ d1 ^ g0);
                assert_eq!(at(7)[i], d4 ^ d5 ^ g1);
            }
        }
    }

    /// Reference single-pass decode feasibility (spec 5) on masks: layers last -> first, e <= m.
    fn sim(layers: &[(u128, usize)], full: u128, avail: u128, want: u128) -> bool {
        let mut e = full & !avail;
        for (mask, ml) in layers.iter().rev() {
            if e & want == 0 {
                break;
            }
            let le = e & mask;
            if le != 0 && le.count_ones() as usize <= *ml {
                e &= !mask;
            }
        }
        e & want == 0
    }

    fn brute(c: &LrcCodec, len: usize) {
        let all = encode_all(c, len);
        let n = c.n;
        let lm: Vec<(u128, usize)> = c.layers.iter().map(|l| (l.mask, l.ml)).collect();
        let wants: Vec<Vec<usize>> = vec![(0..c.k()).collect(), (0..n).collect()];
        for want in &wants {
            for mask in 0u32..(1 << n) {
                let avail: Vec<usize> = (0..n)
                    .filter(|r| mask >> c.mapping()[*r] & 1 == 1)
                    .collect();
                let am = avail.iter().fold(0u128, |a, &r| a | 1 << c.mapping()[r]);
                let wm = want.iter().fold(0u128, |a, &r| a | 1 << c.mapping()[r]);
                let plan = c.read_set(want, &avail);
                let ok = sim(&lm, c.full(), am, c.full());
                let _ = wm;
                match plan {
                    None => assert!(
                        !ok,
                        "planner None but a single pass recovers every position: avail {avail:?} want {want:?}"
                    ),
                    Some(set) => {
                        assert!(
                            set.iter().all(|r| avail.contains(r)),
                            "reads unavailable {set:?}"
                        );
                        let have: Vec<(usize, &[u8])> =
                            set.iter().map(|&r| (r, &all[r][..])).collect();
                        let lost: Vec<usize> =
                            want.iter().copied().filter(|r| !set.contains(r)).collect();
                        let mut outs = vec![vec![0u8; len]; lost.len()];
                        let mut o: Vec<&mut [u8]> = outs.iter_mut().map(|v| &mut v[..]).collect();
                        c.decode_into(&have, &lost, &mut o).unwrap_or_else(|e| {
                            panic!("avail {avail:?} want {want:?} set {set:?}: {e:?}")
                        });
                        for (i, r) in lost.iter().enumerate() {
                            assert_eq!(outs[i], all[*r], "avail {avail:?} chunk {r}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn brute_force_423() {
        brute(&LrcCodec::new(&kml(4, 2, 3).unwrap(), "isa").unwrap(), 32);
    }

    #[test]
    fn brute_force_222_jerasure() {
        brute(
            &LrcCodec::new(&kml(2, 2, 2).unwrap(), "jerasure").unwrap(),
            32,
        );
    }

    #[test]
    fn brute_force_custom_three_layers() {
        // explicit profile, 3 layers incl. a local layer over a global parity
        let l = "[[\"DDc_DDc_\",\"\"],[\"DDDc____\",\"\"],[\"____DDDc\",\"\"]]";
        let s = LrcSpec::from_map(&pm(&[("mapping", "DD__DD__"), ("layers", l)])).unwrap();
        brute(&LrcCodec::new(&s, "isa").unwrap(), 32);
    }

    #[test]
    fn layers_coding_into_data() {
        // spec ec-parity.md 14.2: layer 0 codes into data position 0, layer 1 into data position 1 (an input of layer
        // 0, whose relation then no longer holds on the stored chunks: unusable)
        let l = "[[\"cDDc\",\"\"],[\"DcD_\",\"\"]]";
        let s = LrcSpec::from_map(&pm(&[("mapping", "DD__"), ("layers", l)])).unwrap();
        let c = LrcCodec::new(&s, "isa").unwrap();
        assert!(c.rewrites_data());
        assert_eq!(
            c.layers.iter().map(|l| l.usable).collect::<Vec<_>>(),
            [false, true]
        );
        let d: Vec<Vec<u8>> = (0..2u8)
            .map(|i| (0..32u8).map(|b| b * 7 + i + 1).collect())
            .collect();
        let dr: Vec<&[u8]> = d.iter().map(|v| &v[..]).collect();
        let mut all = vec![vec![0u8; 32]; 4];
        {
            let mut o: Vec<&mut [u8]> = all.iter_mut().map(|v| &mut v[..]).collect();
            c.encode_all(&dr, &mut o);
        }
        // literal order: position 2 is never written (zero), data chunk 0 overwritten by layer 0, then position 1 by
        // layer 1 (first parity rows are XOR: position 0 = d1 ^ 0, position 1 = position 0 ^ 0)
        assert!(all[2].iter().all(|b| *b == 0));
        assert_eq!((&all[0], &all[1]), (&d[1], &d[1]));
        let mut par = vec![vec![0u8; 32]; 2];
        {
            let mut p: Vec<&mut [u8]> = par.iter_mut().map(|v| &mut v[..]).collect();
            c.encode(&dr, &mut p);
        }
        assert_eq!(par[..], all[2..]);
        // only the usable layer repairs: position 1 from positions 0 and 2; position 3 (layer 0 only) is lost for good
        let set = c.read_set(&[1], &[0, 2, 3]).unwrap();
        assert_eq!(set, [0, 2]);
        let mut out = vec![0u8; 32];
        c.decode_into(
            &[(0, &all[0][..]), (2, &all[2][..])],
            &[1],
            &mut [&mut out[..]],
        )
        .unwrap();
        assert_eq!(out, all[1]);
        assert!(c.read_set(&[3], &[0, 1, 2]).is_none());
    }

    #[test]
    fn rejects_overflowing_layer_alignment() {
        let layers = r#"[["DDc",""],["DDc",{"plugin":"jerasure","technique":"cauchy_orig","w":"8","packetsize":"2147483647"}],["DDc",{"plugin":"jerasure","technique":"cauchy_orig","w":"8","packetsize":"2147483646"}]]"#;
        let profile = pm(&[("plugin", "lrc"), ("mapping", "DD_"), ("layers", layers)]);
        let spec = LrcSpec::from_map(&profile).unwrap();
        assert!(LrcCodec::new(&spec, "isa").is_err());
        assert!(matches!(
            crate::gate::evaluate(&crate::gate::PoolEcInput {
                size: 3,
                min_size: 2,
                stripe_width: 8192,
                profile: Some(&profile),
                ..Default::default()
            }),
            crate::gate::Verdict::Unsupported(_)
        ));
        // Valid mixed-layer alignment still uses the exact common multiple.
        let layers = r#"[["DDc",""],["DDc",{"plugin":"jerasure","technique":"cauchy_orig","w":"8","packetsize":"12"}]]"#;
        let spec = LrcSpec::from_map(&pm(&[("mapping", "DD_"), ("layers", layers)])).unwrap();
        assert_eq!(LrcCodec::new(&spec, "isa").unwrap().unit(), 96);
    }

    #[test]
    fn unrecoverable_and_errors() {
        let c = LrcCodec::new(&kml(4, 2, 3).unwrap(), "isa").unwrap();
        let all = encode_all(&c, 32);
        // positions 0,1,2 lost: raws 0,1 and raw of pos 2
        let have: Vec<(usize, &[u8])> = (0..8)
            .filter(|r| ![0, 1, 2].contains(&c.mapping()[*r]))
            .map(|r| (r, &all[r][..]))
            .collect();
        let mut o = [vec![0u8; 32]];
        let mut o: Vec<&mut [u8]> = o.iter_mut().map(|v| &mut v[..]).collect();
        assert_eq!(
            c.decode_into(&have, &[0], &mut o),
            Err(DecodeError::Unrecoverable)
        );
        assert_eq!(
            c.decode_into(&have, &[8], &mut o),
            Err(DecodeError::Unrecoverable)
        );
    }
}
