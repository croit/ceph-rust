// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Local release inventory, RC-COMPAT57. Not a feature negotiation decision.
use crate::{
    OsdMap,
    consts::{WEIGHT_IN, release},
    pool::flags,
};
use crush::{
    ALG_STRAW2, OP_SET_CHOOSELEAF_STABLE, OP_SET_CHOOSELEAF_VARY_R, RULE_MSR_FIRSTN, RULE_MSR_INDEP,
};

impl OsdMap {
    /// Minimum client release implied by this map's features, independent of
    /// `require_min_compat_client`. None when CRUSH cannot be inspected.
    /// Cold path: initial CRUSH cache decode may allocate; no IO or map clone.
    pub fn derived_min_compat_client(&self) -> Option<u8> {
        let crush = &self.crush_state()?.map;
        let t = &crush.tunables;
        let mut minimum = release::ARGONAUT;
        let mut require = |present: bool, release: u8| {
            if present {
                minimum = minimum.max(release);
            }
        };
        require(t.chooseleaf_descend_once != 0, release::DUMPLING);
        require(t.chooseleaf_vary_r != 0, release::FIREFLY);
        require(t.chooseleaf_stable != 0, release::JEWEL);
        require(
            crush
                .buckets
                .iter()
                .flatten()
                .any(|b| b.alg() == ALG_STRAW2),
            release::HAMMER,
        );
        require(
            t.msr_descents != 100
                || t.msr_collision_tries != 100
                || crush
                    .rules
                    .iter()
                    .flatten()
                    .any(|r| matches!(r.rule_type, RULE_MSR_FIRSTN | RULE_MSR_INDEP)),
            release::SQUID,
        );
        let incompatible_args = match crush.choose_args.first_key_value() {
            None => false,
            Some((&-1, args)) if crush.choose_args.len() == 1 => args
                .iter()
                .any(|(_, a)| !a.ids.is_empty() || a.weight_set.len() > 1),
            Some(_) => true,
        };
        require(
            incompatible_args || !self.pg_upmap.is_empty() || !self.pg_upmap_items.is_empty(),
            release::LUMINOUS,
        );
        require(!self.pg_upmap_primaries.is_empty(), release::REEF);
        for pool in self.pools.values() {
            require(pool.has_flag(flags::HASHPSPOOL), release::DUMPLING);
            require(
                !pool.tiers.is_empty() || pool.tier_of >= 0,
                release::FIREFLY,
            );
            if let Some(rule) = crush
                .rules
                .get(pool.crush_rule as usize)
                .and_then(Option::as_ref)
            {
                for step in &rule.steps {
                    match step.op {
                        OP_SET_CHOOSELEAF_VARY_R => require(true, release::FIREFLY),
                        OP_SET_CHOOSELEAF_STABLE => require(true, release::JEWEL),
                        _ => {}
                    }
                }
            }
        }
        require(
            self.osd_primary_affinity
                .iter()
                .take(self.max_osd.max(0) as usize)
                .any(|&a| a != WEIGHT_IN),
            release::FIREFLY,
        );
        Some(minimum)
    }
}
