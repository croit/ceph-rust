// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! PG state bits and the mgr-style state string (spec peering.md 9.1).

macro_rules! states {
    ($($name:ident = $bit:expr, $s:expr;)*) => {
        $(pub const $name: u64 = 1u64 << $bit;)*
        /// `(bit mask, name)` in the order the state string lists them.
        pub const STRING_ORDER: &[(u64, &str)] = &[$(($name, $s)),*];
    };
}

// Order of this list = order of names in the state string (peering.md 9.1).
states! {
    STALE = 17, "stale";
    CREATING = 0, "creating";
    ACTIVE = 1, "active";
    ACTIVATING = 24, "activating";
    CLEAN = 2, "clean";
    RECOVERY_WAIT = 22, "recovery_wait";
    RECOVERY_TOOFULL = 28, "recovery_toofull";
    RECOVERING = 14, "recovering";
    FORCED_RECOVERY = 30, "forced_recovery";
    DOWN = 4, "down";
    RECOVERY_UNFOUND = 5, "recovery_unfound";
    BACKFILL_UNFOUND = 6, "backfill_unfound";
    UNDERSIZED = 23, "undersized";
    DEGRADED = 10, "degraded";
    REMAPPED = 18, "remapped";
    PREMERGE = 7, "premerge";
    SCRUBBING = 8, "scrubbing";
    DEEP = 19, "deep";
    INCONSISTENT = 11, "inconsistent";
    PEERING = 12, "peering";
    REPAIR = 13, "repair";
    BACKFILL_WAIT = 15, "backfill_wait";
    BACKFILLING = 20, "backfilling";
    FORCED_BACKFILL = 31, "forced_backfill";
    BACKFILL_TOOFULL = 21, "backfill_toofull";
    INCOMPLETE = 16, "incomplete";
    PEERED = 25, "peered";
    SNAPTRIM = 26, "snaptrim";
    SNAPTRIM_WAIT = 27, "snaptrim_wait";
    SNAPTRIM_ERROR = 29, "snaptrim_error";
    FAILED_REPAIR = 32, "failed_repair";
    LAGGY = 33, "laggy";
    WAIT = 34, "wait";
}

/// State string as `ceph pg dump` shows it: names joined by `+`; empty state = `unknown`.
pub fn state_string(state: u64) -> String {
    let mut out = String::new();
    for (bit, name) in STRING_ORDER {
        if state & bit != 0 {
            if !out.is_empty() {
                out.push('+');
            }
            out.push_str(name);
        }
    }
    if out.is_empty() {
        out.push_str("unknown");
    }
    out
}

/// Parse a state string back into bits. `unknown` = 0. Unknown names are an error.
pub fn parse_state(s: &str) -> Option<u64> {
    if s == "unknown" || s.is_empty() {
        return Some(0);
    }
    let mut v = 0;
    for part in s.split('+') {
        v |= STRING_ORDER.iter().find(|(_, n)| *n == part)?.0;
    }
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings() {
        assert_eq!(state_string(ACTIVE | CLEAN), "active+clean");
        assert_eq!(
            state_string(ACTIVE | UNDERSIZED | DEGRADED),
            "active+undersized+degraded"
        );
        assert_eq!(state_string(PEERING), "peering");
        assert_eq!(state_string(0), "unknown");
        assert_eq!(
            state_string(ACTIVE | RECOVERY_WAIT | DEGRADED),
            "active+recovery_wait+degraded"
        );
        assert_eq!(
            state_string(CREATING | ACTIVE | DOWN | RECOVERY_UNFOUND | BACKFILL_UNFOUND),
            "creating+active+down+recovery_unfound+backfill_unfound"
        );
        assert_eq!(
            parse_state("active+clean+remapped"),
            Some(ACTIVE | CLEAN | REMAPPED)
        );
        assert_eq!(STRING_ORDER.len(), 33);
    }
}
