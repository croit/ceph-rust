// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! In-memory CRUSH map model (spec crush.md sec 2, 4).

use std::collections::{BTreeMap, BTreeSet};

pub const MAGIC: u32 = 0x0001_0000;
pub const ITEM_NONE: i32 = 0x7fff_ffff;
pub const ITEM_UNDEF: i32 = 0x7fff_fffe;
pub const MAX_RULES: usize = 256;

pub const ALG_UNIFORM: u8 = 1;
pub const ALG_LIST: u8 = 2;
pub const ALG_TREE: u8 = 3;
pub const ALG_STRAW: u8 = 4;
pub const ALG_STRAW2: u8 = 5;

pub const RULE_REPLICATED: u8 = 1;
pub const RULE_ERASURE: u8 = 3;
pub const RULE_MSR_FIRSTN: u8 = 4;
pub const RULE_MSR_INDEP: u8 = 5;

pub const OP_NOOP: u32 = 0;
pub const OP_TAKE: u32 = 1;
pub const OP_CHOOSE_FIRSTN: u32 = 2;
pub const OP_CHOOSE_INDEP: u32 = 3;
pub const OP_EMIT: u32 = 4;
pub const OP_CHOOSELEAF_FIRSTN: u32 = 6;
pub const OP_CHOOSELEAF_INDEP: u32 = 7;
pub const OP_SET_CHOOSE_TRIES: u32 = 8;
pub const OP_SET_CHOOSELEAF_TRIES: u32 = 9;
pub const OP_SET_CHOOSE_LOCAL_TRIES: u32 = 10;
pub const OP_SET_CHOOSE_LOCAL_FALLBACK_TRIES: u32 = 11;
pub const OP_SET_CHOOSELEAF_VARY_R: u32 = 12;
pub const OP_SET_CHOOSELEAF_STABLE: u32 = 13;
pub const OP_SET_MSR_DESCENTS: u32 = 14;
pub const OP_SET_MSR_COLLISION_TRIES: u32 = 15;
pub const OP_CHOOSE_MSR: u32 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tunables {
    pub choose_local_tries: u32,
    pub choose_local_fallback_tries: u32,
    pub choose_total_tries: u32,
    pub chooseleaf_descend_once: u32,
    pub chooseleaf_vary_r: u8,
    pub chooseleaf_stable: u8,
    pub straw_calc_version: u8,
    pub allowed_bucket_algs: u32,
    pub msr_descents: u32,
    pub msr_collision_tries: u32,
}

impl Tunables {
    /// argonaut / legacy; also the decoder's starting point.
    pub const fn legacy() -> Self {
        Self {
            choose_local_tries: 2,
            choose_local_fallback_tries: 5,
            choose_total_tries: 19,
            chooseleaf_descend_once: 0,
            chooseleaf_vary_r: 0,
            chooseleaf_stable: 0,
            straw_calc_version: 0,
            allowed_bucket_algs: 0x16,
            msr_descents: 100,
            msr_collision_tries: 100,
        }
    }
    pub const fn bobtail() -> Self {
        Self {
            choose_local_tries: 0,
            choose_local_fallback_tries: 0,
            choose_total_tries: 50,
            chooseleaf_descend_once: 1,
            ..Self::legacy()
        }
    }
    pub const fn firefly() -> Self {
        Self {
            chooseleaf_vary_r: 1,
            ..Self::bobtail()
        }
    }
    pub const fn hammer() -> Self {
        Self {
            allowed_bucket_algs: 0x36,
            ..Self::firefly()
        }
    }
    /// jewel = optimal = default.
    pub const fn jewel() -> Self {
        Self {
            chooseleaf_stable: 1,
            straw_calc_version: 1,
            ..Self::hammer()
        }
    }
}

impl Default for Tunables {
    fn default() -> Self {
        Self::jewel()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BucketKind {
    Uniform {
        item_weight: u32,
    },
    List {
        item_weights: Vec<u32>,
        sum_weights: Vec<u32>,
    },
    /// `node_weights.len()` = num_nodes (u8 on the wire).
    Tree {
        node_weights: Vec<u32>,
    },
    Straw {
        item_weights: Vec<u32>,
        straws: Vec<u32>,
    },
    Straw2 {
        item_weights: Vec<u32>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bucket {
    pub id: i32,
    pub btype: u16,
    /// 0 = rjenkins1.
    pub hash: u8,
    pub weight: u32,
    pub items: Vec<i32>,
    pub kind: BucketKind,
}

impl Bucket {
    pub fn alg(&self) -> u8 {
        match self.kind {
            BucketKind::Uniform { .. } => ALG_UNIFORM,
            BucketKind::List { .. } => ALG_LIST,
            BucketKind::Tree { .. } => ALG_TREE,
            BucketKind::Straw { .. } => ALG_STRAW,
            BucketKind::Straw2 { .. } => ALG_STRAW2,
        }
    }

    /// Builder: straw2 bucket from (item, weight) pairs; bucket weight = sum.
    pub fn straw2(id: i32, btype: u16, items: &[(i32, u32)]) -> Self {
        let weight = items.iter().fold(0u32, |a, (_, w)| a.wrapping_add(*w));
        Self {
            id,
            btype,
            hash: 0,
            weight,
            items: items.iter().map(|(i, _)| *i).collect(),
            kind: BucketKind::Straw2 {
                item_weights: items.iter().map(|(_, w)| *w).collect(),
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Step {
    pub op: u32,
    pub arg1: i32,
    pub arg2: i32,
}

impl Step {
    pub const fn new(op: u32, arg1: i32, arg2: i32) -> Self {
        Self { op, arg1, arg2 }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub rule_type: u8,
    /// Deprecated, kept for byte-exact re-encode.
    pub min_size: u8,
    pub max_size: u8,
    pub steps: Vec<Step>,
}

impl Rule {
    pub fn new(rule_type: u8, steps: Vec<Step>) -> Self {
        Self {
            rule_type,
            min_size: 1,
            max_size: 100,
            steps,
        }
    }
}

/// Per-bucket choose_args override (balancer weight-sets / id remap). Empty = no override.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChooseArg {
    /// `weight_set[position][item]`; omitted trailing entries are zero.
    /// The codec keeps zero padding implicit to avoid multiplying bucket size
    /// by the number of short positions during decode.
    pub weight_set: Vec<Vec<u32>>,
    pub ids: Vec<i32>,
}

impl ChooseArg {
    pub fn is_empty(&self) -> bool {
        self.weight_set.is_empty() && self.ids.is_empty()
    }
}

/// Per-bucket choose_args overrides for one map key (`-1` = the default set). Stored sparsely: only
/// buckets with an override have an entry, so decode memory is linear in the stream, not
/// `buckets x maps` (an empty [`ChooseArg`] means "no override" and is never stored).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChooseArgs {
    /// Sorted by bucket index.
    entries: Vec<(u32, ChooseArg)>,
    /// Position count used by decode normalization, retained even if the first
    /// described override is subsequently dropped for an unsupported bucket.
    pub(crate) normalized_positions: usize,
}

impl ChooseArgs {
    /// Override for `bucket` (the bucket index, `-1 - bucket.id`).
    pub fn get(&self, bucket: u32) -> Option<&ChooseArg> {
        self.entries
            .binary_search_by_key(&bucket, |e| e.0)
            .ok()
            .map(|i| &self.entries[i].1)
    }

    /// Overrides in ascending bucket index order.
    pub fn iter(&self) -> impl Iterator<Item = (u32, &ChooseArg)> {
        self.entries.iter().map(|(b, a)| (*b, a))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl FromIterator<(u32, ChooseArg)> for ChooseArgs {
    /// Entries are sorted by bucket index; a duplicate bucket index keeps the last entry.
    fn from_iter<T: IntoIterator<Item = (u32, ChooseArg)>>(iter: T) -> Self {
        let by_bucket: BTreeMap<u32, ChooseArg> =
            iter.into_iter().filter(|(_, a)| !a.is_empty()).collect();
        Self {
            normalized_positions: by_bucket
                .values()
                .find(|a| !a.weight_set.is_empty())
                .map_or(1, |a| a.weight_set.len()),
            entries: by_bucket.into_iter().collect(),
        }
    }
}

/// Wire stages decoded after `rule_name_map` (each present iff bytes remain).
pub const STAGES_ALL: u8 = 9;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrushMap {
    pub buckets: Vec<Option<Bucket>>,
    pub rules: Vec<Option<Rule>>,
    /// Recomputed by [`CrushMap::finalize`].
    pub max_devices: i32,
    /// Largest bucket item count, recomputed by [`CrushMap::finalize`]; scratch sizing for `do_rule`.
    max_bucket_size: usize,
    pub tunables: Tunables,
    pub type_map: BTreeMap<i32, String>,
    pub name_map: BTreeMap<i32, String>,
    pub rule_name_map: BTreeMap<i32, String>,
    pub class_map: BTreeMap<i32, i32>,
    pub class_name: BTreeMap<i32, String>,
    pub class_bucket: BTreeMap<i32, BTreeMap<i32, i32>>,
    /// key = pool id, or -1 for the default set.
    pub choose_args: BTreeMap<i64, ChooseArgs>,
    /// How many optional trailing wire stages exist (0..=9); see codec.
    pub wire_stages: u8,
}

impl Default for CrushMap {
    fn default() -> Self {
        Self::new()
    }
}

impl CrushMap {
    pub fn new() -> Self {
        Self {
            buckets: Vec::new(),
            rules: Vec::new(),
            max_devices: 0,
            max_bucket_size: 0,
            tunables: Tunables::jewel(),
            type_map: BTreeMap::new(),
            name_map: BTreeMap::new(),
            rule_name_map: BTreeMap::new(),
            class_map: BTreeMap::new(),
            class_name: BTreeMap::new(),
            class_bucket: BTreeMap::new(),
            choose_args: BTreeMap::new(),
            wire_stages: STAGES_ALL,
        }
    }

    /// Insert bucket at slot `-1 - id` (grows the slot array).
    pub fn add_bucket(&mut self, b: Bucket) {
        assert!(b.id < 0, "bucket id must be negative");
        let slot = (-1 - b.id) as usize;
        if self.buckets.len() <= slot {
            self.buckets.resize(slot + 1, None);
        }
        self.buckets[slot] = Some(b);
        self.finalize();
    }

    /// Insert rule at slot `id`; returns id.
    pub fn add_rule(&mut self, id: usize, r: Rule) -> usize {
        assert!(id < MAX_RULES);
        if self.rules.len() <= id {
            self.rules.resize(id + 1, None);
        }
        self.rules[id] = Some(r);
        id
    }

    /// Recompute the derived per-map values from the buckets: `max_devices` = 1 + the highest item id any
    /// bucket lists (spec crush sec 2), raised to 1 + the highest name-map id (devices named before a bucket
    /// uses them); `max_bucket_size` = the item count of the largest bucket. Every bucket change goes through
    /// [`CrushMap::add_bucket`]; a direct `buckets` edit must end with a `finalize` call.
    pub fn finalize(&mut self) {
        let mut m = 0i32;
        let mut max_bucket_size = 0usize;
        for b in self.buckets.iter().flatten() {
            for &it in &b.items {
                m = m.max(it.saturating_add(1));
            }
            max_bucket_size = max_bucket_size.max(b.items.len());
        }
        if let Some(&k) = self.name_map.keys().next_back() {
            m = m.max(k.saturating_add(1));
        }
        self.max_devices = m;
        self.max_bucket_size = max_bucket_size;
    }

    #[inline]
    pub fn bucket(&self, id: i32) -> Option<&Bucket> {
        if id >= 0 {
            return None;
        }
        self.buckets
            .get((-1 - id) as usize)
            .and_then(|b| b.as_ref())
    }

    /// choose_args set for a pool: `pool_id`, else the default (-1), else none.
    pub fn choose_args_for(&self, pool_id: i64) -> Option<&ChooseArgs> {
        self.choose_args
            .get(&pool_id)
            .or_else(|| self.choose_args.get(&-1))
    }

    /// Largest bucket size (scratch sizing); cached by [`CrushMap::finalize`].
    pub fn max_bucket_size(&self) -> usize {
        self.max_bucket_size
    }

    /// Bucket ids that exist only as device-class shadow copies (`class_bucket` targets).
    fn shadow_bucket_ids(&self) -> BTreeSet<i32> {
        self.class_bucket
            .values()
            .flat_map(|m| m.values().copied())
            .collect()
    }

    /// Ancestors of `item` that make up its CRUSH location, nearest first: from the item, repeatedly the first
    /// (lowest bucket index) non-shadow bucket that lists the current node, at most one bucket per bucket type (the
    /// nearest one of each type wins). An item without a name (not in `name_map`) has no location. Tolerates cyclic
    /// maps. This is the set `ceph osd set-group` flags are looked up in (spec osd-lifecycle.md 3.2).
    pub fn location_ids(&self, item: i32) -> Vec<i32> {
        let mut out: Vec<i32> = Vec::new();
        if !self.name_map.contains_key(&item) {
            return out;
        }
        let shadow = self.shadow_bucket_ids();
        let mut types = BTreeSet::new();
        let mut seen = BTreeSet::new();
        let mut cur = item;
        while let Some(b) = self
            .buckets
            .iter()
            .flatten()
            .find(|b| !shadow.contains(&b.id) && b.items.contains(&cur))
        {
            if !seen.insert(b.id) {
                break;
            }
            if types.insert(b.btype) {
                out.push(b.id);
            }
            cur = b.id;
        }
        out
    }

    /// `device -> enclosing bucket of type `type_name`` (e.g. `host`), for every device below such a bucket.
    /// Shadow (device-class) buckets are skipped, so each device appears under its real hierarchy only; a device
    /// placed under two buckets of the type keeps the first (lowest bucket index). Empty if the type is unknown.
    pub fn subtrees_of_type(&self, type_name: &str) -> BTreeMap<i32, i32> {
        let mut out = BTreeMap::new();
        let Some(t) = self
            .type_map
            .iter()
            .find(|(_, n)| n.as_str() == type_name)
            .map(|(t, _)| *t)
        else {
            return out;
        };
        let shadow = self.shadow_bucket_ids();
        for b in self.buckets.iter().flatten() {
            if i32::from(b.btype) != t || shadow.contains(&b.id) {
                continue;
            }
            let mut stack: Vec<i32> = b.items.clone();
            let mut seen = BTreeSet::new();
            while let Some(i) = stack.pop() {
                if i >= 0 {
                    out.entry(i).or_insert(b.id);
                } else if !shadow.contains(&i)
                    && seen.insert(i)
                    && let Some(c) = self.bucket(i)
                {
                    stack.extend_from_slice(&c.items);
                }
            }
        }
        out
    }

    /// Barrier bucket of `item` for stretch peering (doc/spec/stretch.md 2.1): the take roots of rule `rule` in
    /// ascending id order (most negative first); per root, the buckets of type `btype` found by a depth-first walk
    /// from the root in item order (a bucket of a lower type ends that branch, one of type `btype` is a candidate and is
    /// not descended; the root itself counts when it has that type; shadow buckets are not skipped); the first
    /// candidate whose subtree holds `item` wins. Not found (item outside every take root, `ITEM_NONE`, unknown rule
    /// or type) = 0, so all such members share the one pseudo bucket 0 (spec 2.2). Tolerates cyclic maps.
    pub fn parent_of_type(&self, item: i32, btype: u32, rule: i32) -> i32 {
        let Some(r) = usize::try_from(rule)
            .ok()
            .and_then(|i| self.rules.get(i))
            .and_then(|r| r.as_ref())
        else {
            return 0;
        };
        let roots: BTreeSet<i32> = r
            .steps
            .iter()
            .filter(|s| s.op == OP_TAKE)
            .map(|s| s.arg1)
            .collect();
        for root in roots {
            for c in self.children_of_type(root, btype) {
                if self.subtree_contains(c, item) {
                    return c;
                }
            }
        }
        0
    }

    /// Items of type `btype` at or below `id` in depth-first item order, not descending below a match or below a
    /// lower-typed bucket (devices are type 0).
    fn children_of_type(&self, id: i32, btype: u32) -> Vec<i32> {
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();
        let mut stack = vec![id];
        while let Some(i) = stack.pop() {
            if i >= 0 {
                if btype == 0 {
                    out.push(i);
                }
                continue;
            }
            let Some(b) = self.bucket(i) else { continue };
            if !seen.insert(i) || u32::from(b.btype) < btype {
                continue;
            }
            if u32::from(b.btype) == btype {
                out.push(i);
                continue;
            }
            stack.extend(b.items.iter().rev());
        }
        out
    }

    /// `item` is `id` or anywhere below it.
    fn subtree_contains(&self, id: i32, item: i32) -> bool {
        let mut seen = BTreeSet::new();
        let mut stack = vec![id];
        while let Some(i) = stack.pop() {
            if i == item {
                return true;
            }
            if i < 0
                && seen.insert(i)
                && let Some(b) = self.bucket(i)
            {
                stack.extend_from_slice(&b.items);
            }
        }
        false
    }
}

// Feature masks that gate the CRUSH encoding (spec crush.md 3.1) live in `denc::features`.
pub use denc::features::{
    CRUSH_MSR as FEATURE_CRUSH_MSR, CRUSH_TUNABLES5 as FEATURE_CRUSH_TUNABLES5,
    SERVER_LUMINOUS as FEATURE_SERVER_LUMINOUS, SERVER_QUINCY as FEATURE_SERVER_QUINCY,
};
