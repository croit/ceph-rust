// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Process memory envelope (adr 0175-memory-envelope, doc/design/memory-envelope.md): every bounded consumer's share is
//! derived from ONE knob, `osd_memory_target`. caches + ingress + pinned + base = target.
use std::sync::Mutex;

/// Ceph defaults of `osd_memory_target` / `osd_memory_base` / `osd_memory_cache_min`.
pub const TARGET_DEFAULT: u64 = 4 << 30;
pub const BASE_DEFAULT: u64 = 768 << 20;
pub const CACHE_MIN_DEFAULT: u64 = 128 << 20;
/// Smallest ingress allowance: two pools must each fit one `osd_max_write_size` (90 MiB) op.
const INGRESS_MIN: u64 = 256 << 20;

/// Shares of one `osd_memory_target`, in bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub target: u64,
    /// `osd_memory_base`: binary, osdmaps, PG state and log, allocator bitmaps, net buffers (not enforced).
    pub base: u64,
    /// Decoded client + peer input in flight (enforced by the ingress pools): `max(target/16, 256 MiB)`.
    pub ingress: u64,
    /// Fixed registered (pinned) buffers sized at start from the core count ([`Envelope::charge_pinned`]): the RDMA
    /// source-pull READ destination arenas. 0 without such buffers.
    pub pinned: u64,
    /// Store caches + object-state caches (adr 0062): the rest, floored at `osd_memory_cache_min`.
    pub caches: u64,
    /// `osd_memory_cache_min`: the floor of `caches`, also when fixed buffers are charged.
    pub cache_min: u64,
}

impl Envelope {
    pub fn derive(target: u64, base: u64, cache_min: u64) -> Self {
        let ingress = (target / 16).max(INGRESS_MIN);
        Self {
            target,
            base,
            ingress,
            pinned: 0,
            caches: target
                .saturating_sub(base)
                .saturating_sub(ingress)
                .max(cache_min),
            cache_min,
        }
    }

    /// Charge `bytes` of fixed pinned buffers (`what`, for the error) against the caches share. Refused when the caches
    /// would fall below `osd_memory_cache_min`: pinned memory cannot be throttled, so it never over-commits the target.
    pub fn charge_pinned(&self, bytes: u64, what: &str) -> Result<Self, String> {
        let pinned = self.pinned + bytes;
        let rest = self
            .target
            .saturating_sub(self.base)
            .saturating_sub(self.ingress)
            .checked_sub(pinned)
            .filter(|&c| c >= self.cache_min);
        let mib = |b: u64| b >> 20;
        match rest {
            Some(caches) => Ok(Self {
                pinned,
                caches,
                ..*self
            }),
            None => Err(format!(
                "{what} needs {} MiB pinned, but osd_memory_target {} MiB leaves {} MiB after osd_memory_base {} MiB, \
                 ingress {} MiB, {} MiB already pinned and osd_memory_cache_min {} MiB: raise osd_memory_target or \
                 turn {what} off",
                mib(bytes),
                mib(self.target),
                mib(self
                    .target
                    .saturating_sub(self.base + self.ingress + self.pinned + self.cache_min)),
                mib(self.base),
                mib(self.ingress),
                mib(self.pinned),
                mib(self.cache_min)
            )),
        }
    }

    /// Client writes hold their reservation until the replicas acked and peer data only waits for the local store, so each
    /// class gets its own half (adr 0084 am. 2: one shared pool lets client writes starve the peer repop).
    pub fn pool(&self) -> u64 {
        self.ingress / 2
    }

    /// Sum of the shares; above `target` only when `osd_memory_cache_min` dominates (small targets, documented).
    pub fn sum(&self) -> u64 {
        self.base + self.ingress + self.pinned + self.caches
    }
}

/// A config size (`size` option grammar, spec osd-lifecycle.md 2.9: `4G`, `4Gi`, `4GiB`, `4GB`, `512B`). `None` = not
/// a size, or above u64.
pub fn parse_size(s: &str) -> Option<u64> {
    crate::optval::size(s).ok()
}

/// Envelope of the running process; set once before the stores mount (cold path: startup and operator commands).
static ACTIVE: Mutex<Option<Envelope>> = Mutex::new(None);

pub fn set(e: Envelope) {
    *ACTIVE.lock().unwrap_or_else(|p| p.into_inner()) = Some(e);
}

/// The active envelope; the Ceph defaults until [`set`] ran.
pub fn active() -> Envelope {
    ACTIVE
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .unwrap_or_else(|| Envelope::derive(TARGET_DEFAULT, BASE_DEFAULT, CACHE_MIN_DEFAULT))
}

/// Log line when the configured `osd_memory_target` (effective value `v` of any source; unset or not a size = the
/// default) differs from `active` (the running envelope's target) and was not noted yet (`noted`: the value of the last
/// note, 0 = none; updated here). The envelope is sized once before the stores mount, so a new value applies at the next
/// start (adr 0175 am. 2).
pub fn restart_note(v: Option<&str>, active: u64, noted: &mut u64) -> Option<String> {
    let want = v.and_then(parse_size).unwrap_or(TARGET_DEFAULT);
    if want == active {
        *noted = 0;
        return None;
    }
    if want == *noted {
        return None;
    }
    *noted = want;
    Some(format!(
        "osd_memory_target {} MiB differs from the active {} MiB: applies at the next start",
        want >> 20,
        active >> 20
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shares_sum_to_the_target() {
        let e = Envelope::derive(4 << 30, BASE_DEFAULT, CACHE_MIN_DEFAULT);
        assert_eq!(e.ingress, 256 << 20);
        assert_eq!(e.sum(), e.target);
        let big = Envelope::derive(64 << 30, BASE_DEFAULT, CACHE_MIN_DEFAULT);
        assert_eq!(big.ingress, 4 << 30);
        assert_eq!(big.sum(), big.target);
        assert!(big.pool() >= 90 << 20);
    }

    /// Ceph's size grammar (doc/spec/osd-lifecycle.md 2.7): what `ceph config set` stores reaches the envelope.
    #[test]
    fn sizes_in_ceph_grammar() {
        for (s, v) in [
            ("8589934592", 8u64 << 30),
            ("8G", 8 << 30),
            ("8Gi", 8 << 30),
            ("8GiB", 8 << 30),
            ("8GB", 8 << 30),
            ("896M", 896 << 20),
            ("512B", 512),
            ("1K", 1 << 10),
            ("2T", 2 << 40),
            ("1P", 1 << 50),
            ("1E", 1 << 60),
            (" 4G ", 4 << 30),
        ] {
            assert_eq!(parse_size(s), Some(v), "{s}");
        }
        for s in [
            "", "G", "8X", "8Bi", "8iB", "-1", "8 G", "16E", "1.5G", "8g",
        ] {
            assert_eq!(parse_size(s), None, "{s}");
        }
    }

    /// A changed `osd_memory_target` is noted once per value; back at the active value the note re-arms.
    #[test]
    fn restart_note_once_per_value() {
        let mut noted = 0;
        let active = 4 << 30;
        assert_eq!(restart_note(None, active, &mut noted), None);
        assert_eq!(restart_note(Some("4294967296"), active, &mut noted), None);
        let n = restart_note(Some("8G"), active, &mut noted).expect("note");
        assert!(
            n.contains("8192 MiB") && n.contains("4096 MiB") && n.contains("next start"),
            "{n}"
        );
        assert_eq!(restart_note(Some("8GiB"), active, &mut noted), None);
        assert!(restart_note(Some("16G"), active, &mut noted).is_some());
        assert_eq!(restart_note(Some("4G"), active, &mut noted), None);
        assert!(restart_note(Some("16G"), active, &mut noted).is_some());
    }

    /// Pinned buffers come out of the caches share; one that would push the caches below their floor is refused.
    #[test]
    fn pinned_buffers_are_charged_or_refused() {
        let e = Envelope::derive(4 << 30, BASE_DEFAULT, CACHE_MIN_DEFAULT);
        let p = e.charge_pinned(1 << 30, "source-pull").expect("fits");
        assert_eq!((p.pinned, p.caches), (1 << 30, e.caches - (1 << 30)));
        assert_eq!(p.sum(), p.target);
        let room = e.caches - CACHE_MIN_DEFAULT;
        assert_eq!(
            e.charge_pinned(room, "x").expect("exact").caches,
            CACHE_MIN_DEFAULT
        );
        let err = e.charge_pinned(room + 1, "source-pull").expect_err("over");
        assert!(
            err.contains("source-pull") && err.contains("osd_memory_target 4096 MiB"),
            "{err}"
        );
        let small = Envelope::derive(100, BASE_DEFAULT, CACHE_MIN_DEFAULT);
        assert!(small.charge_pinned(1, "x").is_err());
    }

    #[test]
    fn small_target_is_floored_not_hidden() {
        let e = Envelope::derive(100, BASE_DEFAULT, CACHE_MIN_DEFAULT);
        assert_eq!(e.caches, CACHE_MIN_DEFAULT);
        assert_eq!(e.ingress, INGRESS_MIN);
        assert!(e.sum() > e.target);
        assert!(e.pool() >= 90 << 20);
    }
}
