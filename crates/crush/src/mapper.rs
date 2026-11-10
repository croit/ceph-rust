// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `do_rule`: PG -> device set (spec crush.md sec 6, 7, 9). Allocation-free; the caller
//! provides a [`Workspace`]. Recursion is bounded (leaf descent = depth 1; MSR = rule steps) and a
//! bucket descent visits each bucket at most once, so cyclic maps end as a miss (spec sec 10).

use crate::hash::{bh3, bh4, crush_ln, hash32_2};
use crate::map::*;

/// Reusable scratch for `do_rule`; size it once per map / result_max.
#[derive(Debug, Default)]
pub struct Workspace {
    cap: usize,
    w: Vec<i32>,
    o: Vec<i32>,
    c: Vec<i32>,
    perm: Vec<u32>,
    msr_vecs: Vec<i32>,
    msr_undo: Vec<i32>,
    msr_frames: Vec<MsrFrame>,
}

impl Workspace {
    /// Scratch for results up to `result_max` entries on `map`.
    pub fn new(map: &CrushMap, result_max: usize) -> Self {
        let mut ws = Self::default();
        ws.reserve(map, result_max);
        ws
    }

    /// Grow (allocates) to fit `map` and `result_max`. Call after a map change.
    pub fn reserve(&mut self, map: &CrushMap, result_max: usize) {
        let max_steps = map
            .rules
            .iter()
            .flatten()
            .map(|r| r.steps.len())
            .max()
            .unwrap_or(0);
        self.cap = self.cap.max(result_max);
        let cap = self.cap;
        self.w.resize(cap, 0);
        self.o.resize(cap, 0);
        self.c.resize(cap, 0);
        let ps = self.perm.len().max(map.max_bucket_size());
        self.perm.resize(ps, 0);
        let mv = (max_steps * cap).max(self.msr_vecs.len());
        self.msr_vecs.resize(mv, 0);
        self.msr_undo.resize(mv, 0);
        let frames = max_steps.max(self.msr_frames.len());
        self.msr_frames.resize(frames, MsrFrame::default());
    }

    pub fn capacity(&self) -> usize {
        self.cap
    }
}

struct Ctx<'a> {
    map: &'a CrushMap,
    x: u32,
    weights: &'a [u32],
    args: Option<&'a ChooseArgs>,
    perm: &'a mut [u32],
}

#[derive(Clone, Copy)]
struct FirstnParams {
    tries: u32,
    recurse_tries: u32,
    local_retries: u32,
    local_fallback: u32,
    vary_r: u32,
    stable: bool,
}

impl CrushMap {
    /// Map input `x` through rule `rule`. `result.len()` = result_max. Returns the number of
    /// entries written (indep: NONE holes included). `weights[dev]` is 16.16 (0x10000 = in).
    /// `ws` must have been created/reserved for at least `result.len()` entries and this map;
    /// otherwise an empty result is returned (never panics, never allocates).
    pub fn do_rule(
        &self,
        rule: usize,
        x: u32,
        result: &mut [i32],
        weights: &[u32],
        args: Option<&ChooseArgs>,
        ws: &mut Workspace,
    ) -> usize {
        let Some(Some(rule)) = self.rules.get(rule) else {
            return 0;
        };
        let rmax = result.len();
        if rmax == 0 {
            return 0;
        }
        let max_steps = rule.steps.len();
        if rmax > ws.cap
            || ws.perm.len() < self.max_bucket_size()
            || ws.msr_vecs.len() < max_steps * ws.cap
            || ws.msr_frames.len() < max_steps
        {
            return 0;
        }
        let Workspace {
            cap,
            w,
            o,
            c,
            perm,
            msr_vecs,
            msr_undo,
            msr_frames,
        } = ws;
        let mut ctx = Ctx {
            map: self,
            x,
            weights,
            args,
            perm,
        };
        if rule.rule_type == RULE_MSR_FIRSTN || rule.rule_type == RULE_MSR_INDEP {
            return ctx.do_msr(rule, result, msr_vecs, msr_undo, msr_frames, *cap);
        }
        let t = &self.tunables;
        let mut choose_tries = t.choose_total_tries.wrapping_add(1);
        let mut choose_leaf_tries = 0u32;
        let mut local_retries = t.choose_local_tries;
        let mut local_fallback = t.choose_local_fallback_tries;
        let mut vary_r = t.chooseleaf_vary_r as u32;
        let mut stable = t.chooseleaf_stable as u32;
        let mut wsize = 0usize;
        let mut rlen = 0usize;

        for s in &rule.steps {
            match s.op {
                OP_TAKE => {
                    let a = s.arg1;
                    if (a >= 0 && a < self.max_devices) || (a < 0 && self.bucket(a).is_some()) {
                        w[0] = a;
                        wsize = 1;
                    }
                }
                OP_SET_CHOOSE_TRIES => {
                    if s.arg1 > 0 {
                        choose_tries = s.arg1 as u32;
                    }
                }
                OP_SET_CHOOSELEAF_TRIES => {
                    if s.arg1 > 0 {
                        choose_leaf_tries = s.arg1 as u32;
                    }
                }
                OP_SET_CHOOSE_LOCAL_TRIES => {
                    if s.arg1 >= 0 {
                        local_retries = s.arg1 as u32;
                    }
                }
                OP_SET_CHOOSE_LOCAL_FALLBACK_TRIES => {
                    if s.arg1 >= 0 {
                        local_fallback = s.arg1 as u32;
                    }
                }
                OP_SET_CHOOSELEAF_VARY_R => {
                    if s.arg1 >= 0 {
                        vary_r = s.arg1 as u32;
                    }
                }
                OP_SET_CHOOSELEAF_STABLE => {
                    if s.arg1 >= 0 {
                        stable = s.arg1 as u32;
                    }
                }
                OP_CHOOSE_FIRSTN | OP_CHOOSELEAF_FIRSTN | OP_CHOOSE_INDEP | OP_CHOOSELEAF_INDEP => {
                    if wsize == 0 {
                        continue;
                    }
                    let firstn = s.op == OP_CHOOSE_FIRSTN || s.op == OP_CHOOSELEAF_FIRSTN;
                    let leaf = s.op == OP_CHOOSELEAF_FIRSTN || s.op == OP_CHOOSELEAF_INDEP;
                    let mut osize = 0usize;
                    for &wi in &w[..wsize] {
                        let mut numrep = s.arg1;
                        if numrep <= 0 {
                            numrep = numrep.wrapping_add(rmax as i32);
                            if numrep <= 0 {
                                continue;
                            }
                        }
                        let Some(b) = self.bucket(wi) else {
                            continue;
                        };
                        if osize >= rmax {
                            break;
                        }
                        let out2 = if leaf {
                            Some(&mut c[osize..rmax])
                        } else {
                            None
                        };
                        if firstn {
                            let recurse_tries = if choose_leaf_tries != 0 {
                                choose_leaf_tries
                            } else if t.chooseleaf_descend_once != 0 {
                                1
                            } else {
                                choose_tries
                            };
                            let p = FirstnParams {
                                tries: choose_tries,
                                recurse_tries,
                                local_retries,
                                local_fallback,
                                vary_r,
                                stable: stable != 0,
                            };
                            osize += ctx.choose_firstn(
                                b,
                                numrep,
                                s.arg2,
                                &mut o[osize..rmax],
                                0,
                                rmax - osize,
                                p,
                                leaf,
                                out2,
                                0,
                            );
                        } else {
                            let left = (numrep as usize).min(rmax - osize);
                            let recurse = if choose_leaf_tries != 0 {
                                choose_leaf_tries
                            } else {
                                1
                            };
                            ctx.choose_indep(
                                b,
                                left,
                                numrep as u32,
                                s.arg2,
                                &mut o[osize..rmax],
                                0,
                                choose_tries,
                                recurse,
                                leaf,
                                out2,
                                0,
                            );
                            osize += left;
                        }
                    }
                    if leaf {
                        o[..osize].copy_from_slice(&c[..osize]);
                    }
                    std::mem::swap(o, w);
                    wsize = osize;
                }
                OP_EMIT => {
                    for &wi in &w[..wsize] {
                        if rlen >= rmax {
                            break;
                        }
                        result[rlen] = wi;
                        rlen += 1;
                    }
                    wsize = 0;
                }
                _ => {}
            }
        }
        rlen
    }
}

impl<'a> Ctx<'a> {
    #[inline]
    fn is_out(&self, item: i32) -> bool {
        let i = item as usize;
        match self.weights.get(i) {
            None => true,
            Some(&w) => {
                if w >= 0x10000 {
                    false
                } else if w == 0 {
                    true
                } else {
                    (hash32_2(self.x, item as u32) & 0xffff) >= w
                }
            }
        }
    }

    /// Stateless uniform permutation choose (spec 6.2).
    fn perm_choose(&mut self, b: &Bucket, r: u32) -> i32 {
        let n = b.items.len() as u32;
        let pr = r % n;
        let id = b.id as u32;
        if pr == 0 {
            return b.items[(bh3(b.hash, self.x, id, 0) % n) as usize];
        }
        let perm = &mut self.perm[..n as usize];
        for (i, p) in perm.iter_mut().enumerate() {
            *p = i as u32;
        }
        for p in 0..=pr {
            if p < n - 1 {
                let i = bh3(b.hash, self.x, id, p) % (n - p);
                if i != 0 {
                    perm.swap(p as usize, (p + i) as usize);
                }
            }
        }
        b.items[perm[pr as usize] as usize]
    }

    /// Bucket choose; `b.items` must be non-empty.
    fn choose(&mut self, b: &Bucket, r: u32, position: usize) -> i32 {
        let x = self.x;
        match &b.kind {
            BucketKind::Uniform { .. } => self.perm_choose(b, r),
            BucketKind::List {
                item_weights,
                sum_weights,
            } => {
                for i in (0..b.items.len()).rev() {
                    let (Some(&iw), Some(&sw)) = (item_weights.get(i), sum_weights.get(i)) else {
                        continue;
                    };
                    let h = bh4(b.hash, x, b.items[i] as u32, r, b.id as u32) & 0xffff;
                    if ((h as u64 * sw as u64) >> 16) < iw as u64 {
                        return b.items[i];
                    }
                }
                b.items[0]
            }
            BucketKind::Tree { node_weights } => {
                let nn = node_weights.len();
                let mut n = nn >> 1;
                while n & 1 == 0 {
                    if n == 0 || n >= nn {
                        return b.items[0];
                    }
                    let h = n.trailing_zeros();
                    let hv = bh4(b.hash, x, n as u32, r, b.id as u32) as u64;
                    let t = (hv * node_weights[n] as u64) >> 32;
                    let l = n - (1 << (h - 1));
                    n = if t < node_weights[l] as u64 {
                        l
                    } else {
                        n + (1 << (h - 1))
                    };
                }
                b.items.get(n >> 1).copied().unwrap_or(b.items[0])
            }
            BucketKind::Straw { straws, .. } => {
                let mut best = 0usize;
                let mut high = 0u64;
                for i in 0..b.items.len() {
                    let s = straws.get(i).copied().unwrap_or(0) as u64;
                    let d = (bh3(b.hash, x, b.items[i] as u32, r) & 0xffff) as u64 * s;
                    if i == 0 || d > high {
                        high = d;
                        best = i;
                    }
                }
                b.items[best]
            }
            BucketKind::Straw2 { item_weights } => {
                let n = b.items.len();
                let mut weights: &[u32] = item_weights;
                let mut ids: &[i32] = &b.items;
                if let Some(args) = self.args
                    && let Some(arg) = args.get((-1 - b.id) as u32)
                {
                    if !arg.weight_set.is_empty() {
                        let ws = &arg.weight_set[position.min(arg.weight_set.len() - 1)];
                        if ws.len() >= n || arg.weight_set.len() == args.normalized_positions {
                            weights = ws;
                        }
                    }
                    if arg.ids.len() >= n {
                        ids = &arg.ids;
                    }
                }
                let mut high = 0i64;
                let mut best = 0usize;
                for (i, id) in ids.iter().take(n).enumerate() {
                    let wt = weights.get(i).copied().unwrap_or(0);
                    let draw = if wt != 0 {
                        let u = bh3(b.hash, x, *id as u32, r) & 0xffff;
                        (crush_ln(u) as i64 - (1i64 << 48)) / wt as i64
                    } else {
                        i64::MIN
                    };
                    if i == 0 || draw > high {
                        high = draw;
                        best = i;
                    }
                }
                b.items[best]
            }
        }
    }

    #[expect(clippy::too_many_arguments)]
    fn choose_firstn(
        &mut self,
        bucket: &'a Bucket,
        numrep: i32,
        typ: i32,
        out: &mut [i32],
        mut outpos: usize,
        out_size: usize,
        p: FirstnParams,
        leaf: bool,
        mut out2: Option<&mut [i32]>,
        parent_r: u32,
    ) -> usize {
        let map = self.map;
        let max_devices = map.max_devices;
        let max_descent = map.buckets.len();
        let mut count = out_size;
        let mut rep = if p.stable { 0 } else { outpos as i32 };
        while rep < numrep && count > 0 {
            let mut ftotal = 0u32;
            let mut skip = false;
            let mut item = 0i32;
            'descent: loop {
                let mut inb = bucket;
                let mut flocal = 0u32;
                let mut descents = 0usize;
                loop {
                    let r = (rep as u32).wrapping_add(parent_r).wrapping_add(ftotal);
                    let mut reject = false;
                    let mut collide = false;
                    let size = inb.items.len() as u32;
                    if size == 0 {
                        reject = true;
                    } else {
                        item = if p.local_fallback > 0
                            && flocal >= size / 2
                            && flocal > p.local_fallback
                        {
                            self.perm_choose(inb, r)
                        } else {
                            self.choose(inb, r, outpos)
                        };
                        if item >= max_devices {
                            skip = true;
                            break 'descent;
                        }
                        let nb = map.bucket(item);
                        let itemtype = match nb {
                            Some(b) => b.btype as i32,
                            None if item < 0 => {
                                skip = true;
                                break 'descent;
                            }
                            None => 0,
                        };
                        if itemtype != typ {
                            match nb {
                                Some(b) => {
                                    // A descent visits each bucket at most once; a cycle stops here.
                                    descents += 1;
                                    if descents >= max_descent {
                                        skip = true;
                                        break 'descent;
                                    }
                                    inb = b;
                                    continue;
                                }
                                None => {
                                    skip = true;
                                    break 'descent;
                                }
                            }
                        }
                        collide = out[..outpos].contains(&item);
                        if !collide && leaf {
                            if let Some(sub) = nb {
                                // vary_r beyond the shift width is a full shift-out (sub_r = 0).
                                let sub_r = if p.vary_r != 0 {
                                    r.checked_shr(p.vary_r - 1).unwrap_or(0)
                                } else {
                                    0
                                };
                                let n = match out2.as_deref_mut() {
                                    Some(o2) => self.choose_firstn(
                                        sub,
                                        if p.stable { 1 } else { outpos as i32 + 1 },
                                        0,
                                        o2,
                                        outpos,
                                        count,
                                        FirstnParams {
                                            tries: p.recurse_tries,
                                            recurse_tries: 0,
                                            ..p
                                        },
                                        false,
                                        None,
                                        sub_r,
                                    ),
                                    None => 0,
                                };
                                if n <= outpos {
                                    reject = true;
                                }
                            } else if let Some(o2) = out2.as_deref_mut() {
                                o2[outpos] = item;
                            }
                        }
                        if !reject && !collide && itemtype == 0 {
                            reject = self.is_out(item);
                        }
                    }
                    if reject || collide {
                        ftotal += 1;
                        flocal += 1;
                        // u32 arithmetic wraps (spec conventions), so extreme wire tunables cannot overflow.
                        if (collide && flocal <= p.local_retries)
                            || (p.local_fallback > 0
                                && flocal <= size.wrapping_add(p.local_fallback))
                        {
                            continue;
                        } else if ftotal < p.tries {
                            continue 'descent;
                        } else {
                            skip = true;
                            break 'descent;
                        }
                    }
                    break 'descent;
                }
            }
            if !skip {
                out[outpos] = item;
                outpos += 1;
                count -= 1;
            }
            rep += 1;
        }
        outpos
    }

    #[expect(clippy::too_many_arguments)]
    fn choose_indep(
        &mut self,
        bucket: &'a Bucket,
        left: usize,
        numrep: u32,
        typ: i32,
        out: &mut [i32],
        outpos: usize,
        tries: u32,
        recurse_tries: u32,
        leaf: bool,
        mut out2: Option<&mut [i32]>,
        parent_r: u32,
    ) {
        let map = self.map;
        let max_devices = map.max_devices;
        let endpos = outpos + left;
        let mut left = left;
        for rep in outpos..endpos {
            out[rep] = ITEM_UNDEF;
            if let Some(o2) = out2.as_deref_mut() {
                o2[rep] = ITEM_UNDEF;
            }
        }
        let mut ftotal = 0u32;
        while left > 0 && ftotal < tries {
            for rep in outpos..endpos {
                if out[rep] != ITEM_UNDEF {
                    continue;
                }
                let mut inb = bucket;
                let mut descents = 0usize;
                loop {
                    let mut r = (rep as u32).wrapping_add(parent_r);
                    let size = inb.items.len() as u32;
                    if inb.alg() == ALG_UNIFORM && numrep != 0 && size.is_multiple_of(numrep) {
                        r = r.wrapping_add((numrep + 1).wrapping_mul(ftotal));
                    } else {
                        r = r.wrapping_add(numrep.wrapping_mul(ftotal));
                    }
                    if size == 0 {
                        break;
                    }
                    let item = self.choose(inb, r, outpos);
                    if item >= max_devices {
                        out[rep] = ITEM_NONE;
                        if let Some(o2) = out2.as_deref_mut() {
                            o2[rep] = ITEM_NONE;
                        }
                        left -= 1;
                        break;
                    }
                    let nb = map.bucket(item);
                    let itemtype = match (item < 0, nb) {
                        (true, Some(b)) => b.btype as i32,
                        (true, None) => {
                            out[rep] = ITEM_NONE;
                            if let Some(o2) = out2.as_deref_mut() {
                                o2[rep] = ITEM_NONE;
                            }
                            left -= 1;
                            break;
                        }
                        _ => 0,
                    };
                    if itemtype != typ {
                        match nb {
                            Some(b) => {
                                // A descent visits each bucket at most once; a cycle ends as NONE.
                                descents += 1;
                                if descents >= map.buckets.len() {
                                    out[rep] = ITEM_NONE;
                                    if let Some(o2) = out2.as_deref_mut() {
                                        o2[rep] = ITEM_NONE;
                                    }
                                    left -= 1;
                                    break;
                                }
                                inb = b;
                                continue;
                            }
                            None => {
                                out[rep] = ITEM_NONE;
                                if let Some(o2) = out2.as_deref_mut() {
                                    o2[rep] = ITEM_NONE;
                                }
                                left -= 1;
                                break;
                            }
                        }
                    }
                    if out[outpos..endpos].contains(&item) {
                        break;
                    }
                    if leaf && let Some(o2) = out2.as_deref_mut() {
                        if let Some(sub) = nb {
                            self.choose_indep(
                                sub,
                                1,
                                numrep,
                                0,
                                o2,
                                rep,
                                recurse_tries,
                                0,
                                false,
                                None,
                                r,
                            );
                            if o2[rep] == ITEM_NONE {
                                break;
                            }
                        } else {
                            o2[rep] = item;
                        }
                    }
                    if itemtype == 0 && self.is_out(item) {
                        break;
                    }
                    out[rep] = item;
                    left -= 1;
                    break;
                }
            }
            ftotal += 1;
        }
        for rep in outpos..endpos {
            if out[rep] == ITEM_UNDEF {
                out[rep] = ITEM_NONE;
            }
            if let Some(o2) = out2.as_deref_mut()
                && o2[rep] == ITEM_UNDEF
            {
                o2[rep] = ITEM_NONE;
            }
        }
    }
}

// ---- MSR ----

/// One suspended MSR call. Rule depth is peer-controlled, so frames belong to
/// the reusable workspace instead of the native thread stack.
#[derive(Clone, Copy, Debug, Default)]
struct MsrFrame {
    bucket: i32,
    start: usize,
    end: usize,
    step_no: usize,
    stride_len: usize,
    active_strides: usize,
    si: usize,
    mapped: usize,
    child_candidate: i32,
}

struct Msr<'s, 'a> {
    ctx: &'s mut Ctx<'a>,
    steps: &'a [Step],
    vecs: &'s mut [i32],
    undo: &'s mut [i32],
    result: &'s mut [i32],
    returned: usize,
    indep: bool,
    rmax: usize,
    coll: u32,
}

impl<'a> Ctx<'a> {
    fn do_msr(
        &mut self,
        rule: &'a Rule,
        result: &mut [i32],
        vecs: &mut [i32],
        undo: &mut [i32],
        frames: &mut [MsrFrame],
        cap: usize,
    ) -> usize {
        let rmax = result.len();
        let indep = rule.rule_type == RULE_MSR_INDEP;
        let mut descents = self.map.tunables.msr_descents;
        let mut coll = self.map.tunables.msr_collision_tries;
        let steps = &rule.steps[..];
        let mut i = 0;
        while i < steps.len()
            && (steps[i].op == OP_SET_MSR_DESCENTS || steps[i].op == OP_SET_MSR_COLLISION_TRIES)
        {
            if steps[i].op == OP_SET_MSR_DESCENTS {
                descents = steps[i].arg1 as u32;
            } else {
                coll = steps[i].arg1 as u32;
            }
            i += 1;
        }
        // Validate shape first (invalid => empty result): one or more TAKE, CHOOSE_MSR+, EMIT blocks.
        let mut blocks = 0usize;
        {
            let mut j = i;
            while j < steps.len() {
                if steps[j].op != OP_TAKE || steps[j].arg1 >= 0 {
                    return 0;
                }
                j += 1;
                let f = j;
                while j < steps.len() && steps[j].op == OP_CHOOSE_MSR {
                    if steps[j].arg1 < 0 {
                        return 0;
                    }
                    j += 1;
                }
                if j == f || j >= steps.len() || steps[j].op != OP_EMIT {
                    return 0;
                }
                j += 1;
                blocks += 1;
            }
        }
        if blocks == 0 {
            return 0;
        }
        result.fill(ITEM_NONE);
        let mut m = Msr {
            ctx: self,
            steps: &[],
            vecs,
            undo,
            result,
            returned: 0,
            indep,
            rmax,
            coll,
        };
        let mut start_index = 0usize;
        while i < steps.len() {
            let root = steps[i].arg1;
            i += 1;
            let first = i;
            while steps[i].op == OP_CHOOSE_MSR {
                i += 1;
            }
            let bsteps = &steps[first..i];
            i += 1; // EMIT
            let mut total = 1usize;
            for s in bsteps {
                let n = if s.arg1 != 0 { s.arg1 as usize } else { rmax };
                total = total.saturating_mul(n);
            }
            let Some(_) = m.ctx.map.bucket(root) else {
                continue;
            };
            let end_index = start_index.saturating_add(total).min(rmax);
            let limit = m.returned + (end_index - start_index);
            m.steps = bsteps;
            m.vecs[..bsteps.len() * cap].fill(ITEM_UNDEF);
            for tryno in 0..descents {
                if m.returned >= limit {
                    break;
                }
                m.msr_choose(root, total, start_index, end_index, tryno, cap, frames);
            }
            start_index = end_index;
        }
        if indep { rmax } else { m.returned }
    }
}

impl<'s, 'a> Msr<'s, 'a> {
    fn emit(&mut self, pos: usize, item: i32) {
        if self.indep {
            self.result[pos] = item;
            self.returned += 1;
        } else if self.returned < self.rmax {
            self.result[self.returned] = item;
            self.returned += 1;
        }
    }

    fn descend(
        &mut self,
        mut b: &'a Bucket,
        typ: i32,
        tryno: u32,
        local_try: u32,
        index: usize,
    ) -> Option<i32> {
        // A descent visits each bucket at most once; a cycle (or an unreachable type) returns None.
        for _ in 0..self.ctx.map.buckets.len() {
            let r = (tryno
                .wrapping_mul(self.rmax as u32)
                .wrapping_add(index as u32)
                << 16)
                .wrapping_add(local_try);
            if b.items.is_empty() {
                return None;
            }
            let c = self.ctx.choose(b, r, index);
            if c >= 0 {
                return Some(c);
            }
            b = self.ctx.map.bucket(c)?;
            if b.btype as i32 == typ {
                return Some(c);
            }
        }
        None
    }

    fn msr_frame(
        &mut self,
        bucket: i32,
        total: usize,
        start: usize,
        end: usize,
        step_no: usize,
        cap: usize,
    ) -> MsrFrame {
        let step = self.steps[step_no];
        let num_strides = if step.arg1 != 0 {
            step.arg1 as usize
        } else {
            self.rmax
        };
        let stride_len = total / num_strides;
        let active_strides = if stride_len == 0 {
            0
        } else {
            (end - start).div_ceil(stride_len).min(num_strides)
        };
        let vb = step_no * cap;
        self.undo[vb..vb + active_strides].fill(ITEM_UNDEF);
        MsrFrame {
            bucket,
            start,
            end,
            step_no,
            stride_len,
            active_strides,
            si: 0,
            mapped: 0,
            child_candidate: ITEM_UNDEF,
        }
    }

    #[expect(clippy::too_many_arguments)]
    fn msr_choose(
        &mut self,
        bucket: i32,
        total: usize,
        start: usize,
        end: usize,
        tryno: u32,
        cap: usize,
        frames: &mut [MsrFrame],
    ) -> usize {
        let nsteps = self.steps.len();
        frames[0] = self.msr_frame(bucket, total, start, end, 0, cap);
        let mut depth = 0;
        let mut child_mapped = None;
        loop {
            let mut frame = frames[depth];
            let vb = frame.step_no * cap;
            if let Some(cm) = child_mapped.take() {
                let this_si = frame.si - 1;
                let ss = frame.start + this_si * frame.stride_len;
                let se = ss.saturating_add(frame.stride_len).min(frame.end);
                let cand = frame.child_candidate;
                let seg = &mut self.vecs[vb + ss..vb + se];
                let pushed = if seg.contains(&cand) {
                    false
                } else if let Some(slot) = seg.iter_mut().find(|v| **v == ITEM_UNDEF) {
                    *slot = cand;
                    true
                } else {
                    false
                };
                if pushed && cm == 0 {
                    self.undo[vb + this_si] = cand;
                } else {
                    frame.mapped += cm;
                }
            }
            if frame.si == frame.active_strides {
                // Failed candidates stay collision-visible until this frame ends.
                for si in 0..frame.active_strides {
                    let ss = frame.start + si * frame.stride_len;
                    let se = ss.saturating_add(frame.stride_len).min(frame.end);
                    if self.undo[vb + si] != ITEM_UNDEF
                        && let Some(slot) = self.vecs[vb + ss..vb + se]
                            .iter_mut()
                            .rev()
                            .find(|v| **v != ITEM_UNDEF)
                    {
                        *slot = ITEM_UNDEF;
                    }
                }
                if depth == 0 {
                    return frame.mapped;
                }
                child_mapped = Some(frame.mapped);
                depth -= 1;
                continue;
            }
            let this_si = frame.si;
            let ss = frame.start + this_si * frame.stride_len;
            let se = ss.saturating_add(frame.stride_len).min(frame.end);
            frame.si += 1;
            frames[depth] = frame;
            let lb = (nsteps - 1) * cap;
            if self.vecs[lb + ss..lb + se].iter().all(|&v| v != ITEM_UNDEF) {
                continue;
            }
            let Some(bucket) = self.ctx.map.bucket(frame.bucket) else {
                frames[depth].si = frame.active_strides;
                continue;
            };
            let step = self.steps[frame.step_no];
            let mut found = None;
            for local_try in 0..self.coll {
                let Some(cand) = self.descend(bucket, step.arg2, tryno, local_try, this_si) else {
                    continue;
                };
                let first = self.vecs[vb + frame.start..vb + frame.end]
                    .iter()
                    .position(|&v| v == cand);
                let valid = match first {
                    None => true,
                    Some(p) => frame.start + p >= ss && frame.start + p < se,
                };
                if valid {
                    found = Some(cand);
                    break;
                }
            }
            let Some(cand) = found else { continue };
            if step.arg2 == 0 {
                if frame.stride_len != 1 || frame.step_no != nsteps - 1 || cand < 0 {
                    continue;
                }
                if self.ctx.is_out(cand) {
                    continue;
                }
                self.vecs[vb + ss] = cand;
                self.emit(ss, cand);
                frames[depth].mapped += 1;
            } else {
                if frame.step_no + 1 >= nsteps || cand >= 0 {
                    continue;
                }
                let Some(_) = self.ctx.map.bucket(cand) else {
                    continue;
                };
                frames[depth].child_candidate = cand;
                depth += 1;
                frames[depth] =
                    self.msr_frame(cand, frame.stride_len, ss, se, frame.step_no + 1, cap);
            }
        }
    }
}
