// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Binary codec of the CRUSH map stream (spec crush.md sec 3).
//! Self-contained little-endian reader/writer; isolated so it can move to `denc` later.

use crate::map::*;
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    Malformed(&'static str),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "crush map truncated"),
            Self::Malformed(m) => write!(f, "crush map malformed: {m}"),
        }
    }
}
impl std::error::Error for DecodeError {}

type R<T> = Result<T, DecodeError>;

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    fn remaining(&self) -> usize {
        self.b.len() - self.p
    }
    fn take(&mut self, n: usize) -> R<&'a [u8]> {
        if self.remaining() < n {
            return Err(DecodeError::Truncated);
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }
    fn u8(&mut self) -> R<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> R<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> R<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn i32(&mut self) -> R<i32> {
        Ok(self.u32()? as i32)
    }
    fn i64(&mut self) -> R<i64> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    /// Count of elements each at least `min` bytes; bounds-checked against the stream.
    fn count(&mut self, min: usize) -> R<usize> {
        let n = self.u32()? as usize;
        if n.checked_mul(min).is_none_or(|t| t > self.remaining()) {
            return Err(DecodeError::Truncated);
        }
        Ok(n)
    }
    fn u32s(&mut self, n: usize) -> R<Vec<u32>> {
        let s = self.take(n.checked_mul(4).ok_or(DecodeError::Truncated)?)?;
        Ok(s.as_chunks::<4>()
            .0
            .iter()
            .map(|c| u32::from_le_bytes(*c))
            .collect())
    }
    fn i32s(&mut self, n: usize) -> R<Vec<i32>> {
        Ok(self.u32s(n)?.into_iter().map(|v| v as i32).collect())
    }
    fn string_len(&mut self, l: usize) -> R<String> {
        let s = self.take(l)?;
        Ok(String::from_utf8_lossy(s).into_owned())
    }
    fn string(&mut self) -> R<String> {
        let l = self.u32()? as usize;
        self.string_len(l)
    }
    /// Name map with the legacy 64-bit-key quirk.
    fn name_map(&mut self) -> R<BTreeMap<i32, String>> {
        let n = self.count(8)?;
        let mut m = BTreeMap::new();
        for _ in 0..n {
            let k = self.i32()?;
            let mut l = self.u32()?;
            if l == 0 {
                l = self.u32()?;
            }
            m.insert(k, self.string_len(l as usize)?);
        }
        Ok(m)
    }
    fn string_map(&mut self) -> R<BTreeMap<i32, String>> {
        let n = self.count(8)?;
        let mut m = BTreeMap::new();
        for _ in 0..n {
            let k = self.i32()?;
            m.insert(k, self.string()?);
        }
        Ok(m)
    }
}

/// Decode a CRUSH map stream. Unknown trailing bytes are rejected.
pub fn decode(buf: &[u8]) -> R<CrushMap> {
    let mut r = Reader { b: buf, p: 0 };
    if r.u32()? != MAGIC {
        return Err(DecodeError::Malformed("bad magic"));
    }
    let max_buckets = r.i32()?;
    if max_buckets < 0 || max_buckets as usize > r.remaining() / 4 {
        return Err(DecodeError::Malformed("max_buckets"));
    }
    let max_rules = r.u32()? as usize;
    if max_rules > MAX_RULES.max(r.remaining() / 4) {
        return Err(DecodeError::Malformed("max_rules"));
    }
    r.i32()?; // max_devices: recomputed by `finalize` at the end
    let mut m = CrushMap::new();
    m.tunables = Tunables::legacy();

    for slot in 0..max_buckets as usize {
        let alg = r.u32()?;
        if alg == 0 {
            m.buckets.push(None);
            continue;
        }
        let id = r.i32()?;
        let btype = r.u16()?;
        let alg8 = r.u8()?;
        let hash = r.u8()?;
        let weight = r.u32()?;
        let size = r.count(4)?;
        if alg != alg8 as u32 {
            return Err(DecodeError::Malformed("bucket alg mismatch"));
        }
        if id != -1 - slot as i32 {
            return Err(DecodeError::Malformed("bucket id != slot"));
        }
        let items = r.i32s(size)?;
        let kind = match alg8 {
            ALG_UNIFORM => BucketKind::Uniform {
                item_weight: r.u32()?,
            },
            ALG_LIST => {
                let v = r.u32s(size.checked_mul(2).ok_or(DecodeError::Truncated)?)?;
                BucketKind::List {
                    item_weights: v.iter().step_by(2).copied().collect(),
                    sum_weights: v.iter().skip(1).step_by(2).copied().collect(),
                }
            }
            ALG_TREE => {
                let n = r.u8()? as usize;
                BucketKind::Tree {
                    node_weights: r.u32s(n)?,
                }
            }
            ALG_STRAW => {
                let v = r.u32s(size.checked_mul(2).ok_or(DecodeError::Truncated)?)?;
                BucketKind::Straw {
                    item_weights: v.iter().step_by(2).copied().collect(),
                    straws: v.iter().skip(1).step_by(2).copied().collect(),
                }
            }
            ALG_STRAW2 => BucketKind::Straw2 {
                item_weights: r.u32s(size)?,
            },
            _ => return Err(DecodeError::Malformed("unsupported bucket algorithm")),
        };
        m.buckets.push(Some(Bucket {
            id,
            btype,
            hash,
            weight,
            items,
            kind,
        }));
    }

    for idx in 0..max_rules {
        if r.u32()? == 0 {
            m.rules.push(None);
            continue;
        }
        let len = r.count(12)?;
        let ruleset = r.u8()?;
        if ruleset as usize != idx {
            return Err(DecodeError::Malformed("ruleset != rule_id"));
        }
        let rule_type = r.u8()?;
        let min_size = r.u8()?;
        let max_size = r.u8()?;
        let mut steps = Vec::with_capacity(len);
        for _ in 0..len {
            steps.push(Step {
                op: r.u32()?,
                arg1: r.i32()?,
                arg2: r.i32()?,
            });
        }
        m.rules.push(Some(Rule {
            rule_type,
            min_size,
            max_size,
            steps,
        }));
    }

    m.type_map = r.name_map()?;
    m.name_map = r.name_map()?;
    m.rule_name_map = r.name_map()?;

    // Optional trailing stages, each present iff bytes remain.
    let mut stages = 0u8;
    'opt: {
        let t = &mut m.tunables;
        if r.remaining() == 0 {
            break 'opt;
        }
        t.choose_local_tries = r.u32()?;
        t.choose_local_fallback_tries = r.u32()?;
        t.choose_total_tries = r.u32()?;
        stages = 1;
        if r.remaining() == 0 {
            break 'opt;
        }
        t.chooseleaf_descend_once = r.u32()?;
        stages = 2;
        if r.remaining() == 0 {
            break 'opt;
        }
        t.chooseleaf_vary_r = r.u8()?;
        stages = 3;
        if r.remaining() == 0 {
            break 'opt;
        }
        t.straw_calc_version = r.u8()?;
        stages = 4;
        if r.remaining() == 0 {
            break 'opt;
        }
        t.allowed_bucket_algs = r.u32()?;
        stages = 5;
        if r.remaining() == 0 {
            break 'opt;
        }
        t.chooseleaf_stable = r.u8()?;
        stages = 6;
        if r.remaining() == 0 {
            break 'opt;
        }
        m.class_map = {
            let n = r.count(8)?;
            let mut c = BTreeMap::new();
            for _ in 0..n {
                let k = r.i32()?;
                c.insert(k, r.i32()?);
            }
            c
        };
        m.class_name = r.string_map()?;
        let n = r.count(8)?;
        for _ in 0..n {
            let k = r.i32()?;
            let nn = r.count(8)?;
            let mut inner = BTreeMap::new();
            for _ in 0..nn {
                let c = r.i32()?;
                inner.insert(c, r.i32()?);
            }
            m.class_bucket.insert(k, inner);
        }
        stages = 7;
        if r.remaining() == 0 {
            break 'opt;
        }
        decode_choose_args(&mut r, &mut m)?;
        stages = 8;
        if r.remaining() == 0 {
            break 'opt;
        }
        m.tunables.msr_descents = r.u32()?;
        m.tunables.msr_collision_tries = r.u32()?;
        stages = 9;
    }
    if r.remaining() != 0 {
        return Err(DecodeError::Malformed("trailing bytes"));
    }
    m.wire_stages = stages;
    // `max_devices` is recomputed from the buckets and the name map, never taken from the wire (a stale or
    // hand-edited value would hide devices from the mapper: empty up/acting sets)
    m.finalize();
    Ok(m)
}

fn decode_choose_args(r: &mut Reader<'_>, m: &mut CrushMap) -> R<()> {
    let nb = m.buckets.len();
    let n_maps = r.count(12)?;
    for _ in 0..n_maps {
        let key = r.i64()?;
        let n_args = r.count(12)?;
        let mut args = BTreeMap::new();
        for _ in 0..n_args {
            let bi = r.u32()? as usize;
            if bi >= nb {
                return Err(DecodeError::Malformed("choose_args bucket_index"));
            }
            let npos = r.count(4)?;
            let mut ws = Vec::with_capacity(npos);
            for _ in 0..npos {
                let sz = r.count(4)?;
                ws.push(r.u32s(sz)?);
            }
            let ids_size = r.count(4)?;
            let ids = r.i32s(ids_size)?;
            let bsize = m.buckets[bi].as_ref().map_or(0, |b| b.items.len());
            if ids_size != 0 && ids_size != bsize {
                return Err(DecodeError::Malformed("choose_args ids_size"));
            }
            args.insert(
                bi as u32,
                ChooseArg {
                    weight_set: ws,
                    ids,
                },
            );
        }
        let positions = fixup_choose_args(&m.buckets, &mut args);
        let mut args: ChooseArgs = args.into_iter().collect();
        args.normalized_positions = positions;
        m.choose_args.insert(key, args);
    }
    Ok(())
}

/// Drop overrides of non-straw2/absent buckets and truncate oversized positions.
/// Zero-extension to bucket size stays implicit in memory (spec crush.md sec 3).
fn fixup_choose_args(buckets: &[Option<Bucket>], args: &mut BTreeMap<u32, ChooseArg>) -> usize {
    let positions = args
        .values()
        .find(|a| !a.weight_set.is_empty())
        .map_or(1, |a| a.weight_set.len());
    args.retain(
        |bi, a| match buckets.get(*bi as usize).and_then(Option::as_ref) {
            Some(b) if matches!(b.kind, BucketKind::Straw2 { .. }) => {
                if a.weight_set.len() == positions {
                    for ws in &mut a.weight_set {
                        ws.truncate(b.items.len());
                    }
                }
                !a.is_empty()
            }
            _ => false,
        },
    );
    positions
}

/// Encoder output: the bytes themselves, or only their count.
trait Sink {
    fn put(&mut self, bytes: &[u8]);
    /// `n` zero bytes.
    fn zeros(&mut self, n: usize);
}

impl Sink for Vec<u8> {
    fn put(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
    fn zeros(&mut self, n: usize) {
        self.resize(self.len() + n, 0);
    }
}

/// Counts the encoded length without materializing it.
struct Count(u64);

impl Sink for Count {
    fn put(&mut self, bytes: &[u8]) {
        self.0 += bytes.len() as u64;
    }
    fn zeros(&mut self, n: usize) {
        self.0 += n as u64;
    }
}

struct W<'a, S: Sink>(&'a mut S);

impl<S: Sink> W<'_, S> {
    fn u8(&mut self, v: u8) {
        self.0.put(&[v]);
    }
    fn u16(&mut self, v: u16) {
        self.0.put(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.0.put(&v.to_le_bytes());
    }
    fn i32(&mut self, v: i32) {
        self.u32(v as u32);
    }
    fn i64(&mut self, v: i64) {
        self.0.put(&v.to_le_bytes());
    }
    fn len(&mut self, n: usize) {
        self.u32(n as u32);
    }
    fn u32s(&mut self, v: &[u32]) {
        for &x in v {
            self.u32(x);
        }
    }
    fn strmap(&mut self, m: &BTreeMap<i32, String>) {
        self.len(m.len());
        for (k, v) in m {
            self.i32(*k);
            self.len(v.len());
            self.0.put(v.as_bytes());
        }
    }
}

/// Encode into `out` (appended). Emits the optional stages the map carries
/// (`wire_stages`), so a decoded map re-encodes byte-identically.
pub fn encode(m: &CrushMap, out: &mut Vec<u8>) {
    let st = m.wire_stages;
    encode_layout(
        m,
        out,
        Layout {
            base: st.min(5),
            stable: st >= 6,
            classes: st >= 7,
            args: st >= 8,
            msr: st >= 9,
            default_rule_sizes: false,
        },
    );
}

/// Which optional parts / quirks an encode emits.
#[derive(Clone, Copy)]
struct Layout {
    /// Number of leading tunable stages (0..=5) to write.
    base: u8,
    stable: bool,
    classes: bool,
    args: bool,
    msr: bool,
    /// Write rule min/max_size as 1/100 (SERVER_QUINCY).
    default_rule_sizes: bool,
}

/// Encode for a peer with feature set `features` (spec crush.md 3.1): emits exactly the
/// sections the feature bits gate, independent of the stages the map was decoded with.
pub fn encode_with_features(m: &CrushMap, features: u64, out: &mut Vec<u8>) {
    encode_layout(m, out, feature_layout(features));
}

/// Exact byte length of [`encode_with_features`], computed without materializing the
/// implicit zero weight tails (spec crush.md sec 3).
pub fn encoded_len_with_features(m: &CrushMap, features: u64) -> u64 {
    let mut n = Count(0);
    encode_layout(m, &mut n, feature_layout(features));
    n.0
}

fn feature_layout(features: u64) -> Layout {
    let have = |mask: u64| denc::features::have(features, mask);
    let lum = have(FEATURE_SERVER_LUMINOUS);
    Layout {
        base: 5,
        stable: have(FEATURE_CRUSH_TUNABLES5),
        classes: lum,
        args: lum,
        msr: have(FEATURE_CRUSH_MSR),
        default_rule_sizes: have(FEATURE_SERVER_QUINCY),
    }
}

fn encode_layout<S: Sink>(m: &CrushMap, out: &mut S, l: Layout) {
    let mut w = W(out);
    w.u32(MAGIC);
    w.i32(m.buckets.len() as i32);
    w.len(m.rules.len());
    w.i32(m.max_devices);
    for b in &m.buckets {
        let Some(b) = b else {
            w.u32(0);
            continue;
        };
        w.u32(b.alg() as u32);
        w.i32(b.id);
        w.u16(b.btype);
        w.u8(b.alg());
        w.u8(b.hash);
        w.u32(b.weight);
        w.len(b.items.len());
        for &i in &b.items {
            w.i32(i);
        }
        match &b.kind {
            BucketKind::Uniform { item_weight } => w.u32(*item_weight),
            BucketKind::List {
                item_weights,
                sum_weights,
            } => {
                for (a, s) in item_weights.iter().zip(sum_weights) {
                    w.u32(*a);
                    w.u32(*s);
                }
            }
            BucketKind::Tree { node_weights } => {
                w.u8(node_weights.len() as u8);
                w.u32s(node_weights);
            }
            BucketKind::Straw {
                item_weights,
                straws,
            } => {
                for (a, s) in item_weights.iter().zip(straws) {
                    w.u32(*a);
                    w.u32(*s);
                }
            }
            BucketKind::Straw2 { item_weights } => w.u32s(item_weights),
        }
    }
    for (idx, r) in m.rules.iter().enumerate() {
        let Some(r) = r else {
            w.u32(0);
            continue;
        };
        w.u32(1);
        w.len(r.steps.len());
        w.u8(idx as u8);
        w.u8(r.rule_type);
        if l.default_rule_sizes {
            w.u8(1);
            w.u8(100);
        } else {
            w.u8(r.min_size);
            w.u8(r.max_size);
        }
        for s in &r.steps {
            w.u32(s.op);
            w.i32(s.arg1);
            w.i32(s.arg2);
        }
    }
    w.strmap(&m.type_map);
    w.strmap(&m.name_map);
    w.strmap(&m.rule_name_map);
    let t = &m.tunables;
    if l.base >= 1 {
        w.u32(t.choose_local_tries);
        w.u32(t.choose_local_fallback_tries);
        w.u32(t.choose_total_tries);
    }
    if l.base >= 2 {
        w.u32(t.chooseleaf_descend_once);
    }
    if l.base >= 3 {
        w.u8(t.chooseleaf_vary_r);
    }
    if l.base >= 4 {
        w.u8(t.straw_calc_version);
    }
    if l.base >= 5 {
        w.u32(t.allowed_bucket_algs);
    }
    if l.stable {
        w.u8(t.chooseleaf_stable);
    }
    if l.classes {
        w.len(m.class_map.len());
        for (k, v) in &m.class_map {
            w.i32(*k);
            w.i32(*v);
        }
        w.strmap(&m.class_name);
        w.len(m.class_bucket.len());
        for (k, inner) in &m.class_bucket {
            w.i32(*k);
            w.len(inner.len());
            for (c, b) in inner {
                w.i32(*c);
                w.i32(*b);
            }
        }
    }
    if l.args {
        w.len(m.choose_args.len());
        for (key, args) in &m.choose_args {
            w.i64(*key);
            w.len(args.len());
            let positions = args.normalized_positions;
            for (bi, a) in args.iter() {
                w.len(bi as usize);
                w.len(a.weight_set.len());
                for ws in &a.weight_set {
                    let size = if a.weight_set.len() == positions {
                        m.buckets
                            .get(bi as usize)
                            .and_then(Option::as_ref)
                            .filter(|b| matches!(b.kind, BucketKind::Straw2 { .. }))
                            .map_or(ws.len(), |b| b.items.len())
                    } else {
                        ws.len()
                    };
                    w.len(size);
                    let explicit = &ws[..ws.len().min(size)];
                    w.u32s(explicit);
                    w.0.zeros((size - explicit.len()) * 4);
                }
                w.len(a.ids.len());
                for &i in &a.ids {
                    w.i32(i);
                }
            }
        }
    }
    if l.msr {
        w.u32(t.msr_descents);
        w.u32(t.msr_collision_tries);
    }
}

impl CrushMap {
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        decode(buf)
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        encode(self, &mut v);
        v
    }
    /// Encode as a mon would for a peer with `features` (spec crush.md 3.1).
    pub fn encode_with_features(&self, features: u64) -> Vec<u8> {
        let mut v = Vec::with_capacity(
            usize::try_from(self.encoded_len_with_features(features)).unwrap_or(0),
        );
        encode_with_features(self, features, &mut v);
        v
    }
    /// Byte length [`Self::encode_with_features`] would produce, without encoding. Decoded
    /// short weight positions keep their zero tails implicit; this tells callers the size of
    /// the canonical (padded) form before they materialize it.
    pub fn encoded_len_with_features(&self, features: u64) -> u64 {
        encoded_len_with_features(self, features)
    }
}
