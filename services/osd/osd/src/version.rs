// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Version identity. We present as the Ceph release we are wire-compatible with (ADR 0019) and add
//! our own keys.

/// Ceph release this build tracks (the wire/ABI target).
pub const CEPH_VERSION_PINNED: &str = "21.2.0";

/// Whether `s` may be presented as the Ceph version: the pinned release, optionally `_` + `[A-Za-z0-9.]+`.
pub const fn ceph_version_override_ok(s: &str) -> bool {
    let pin = CEPH_VERSION_PINNED.as_bytes();
    let b = s.as_bytes();
    if b.len() < pin.len() {
        return false;
    }
    let mut i = 0;
    while i < pin.len() {
        if b[i] != pin[i] {
            return false;
        }
        i += 1;
    }
    if i == b.len() {
        return true;
    }
    if b[i] != b'_' {
        return false;
    }
    i += 1;
    if i == b.len() {
        return false;
    }
    while i < b.len() {
        if !matches!(b[i], b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.') {
            return false;
        }
        i += 1;
    }
    true
}

/// Ceph release this build presents: the pinned release, or the build-time `FLASHSTORE_CEPH_VERSION` override.
pub const CEPH_VERSION_SHORT: &str = match option_env!("FLASHSTORE_CEPH_VERSION") {
    Some(v) => {
        if !ceph_version_override_ok(v) {
            panic!("FLASHSTORE_CEPH_VERSION must be 21.2.0 or 21.2.0_<suffix> ([A-Za-z0-9.])");
        }
        v
    }
    None => CEPH_VERSION_PINNED,
};
/// Release name.
pub const CEPH_RELEASE: &str = "umbrella";
/// Reference commit of the tracked release.
pub const CEPH_SHA: &str = "b060042deb05d33e6cc358970cfb8221240bcf3e";
/// croit-flashstore-osd's own version.
pub const FLASHSTORE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// `croit-flashstore-osd version` / `--version` / startup line: the Ceph release we present, then our own build version.
pub fn identity_line() -> String {
    format!("croit-flashstore-osd {CEPH_VERSION_SHORT} {CEPH_RELEASE} (build {FLASHSTORE_VERSION})")
}

/// `ceph version X (sha) release (type - build)` in the exact classic shape.
pub fn ceph_version_pretty() -> String {
    format!(
        "ceph version {CEPH_VERSION_SHORT} ({CEPH_SHA}) {CEPH_RELEASE} (dev - croit-flashstore-osd)"
    )
}

#[cfg(test)]
mod identity_tests {
    use super::*;

    #[test]
    fn override_validation_accepts_the_pinned_version_and_a_suffix() {
        assert!(ceph_version_override_ok("21.2.0"));
        assert!(ceph_version_override_ok("21.2.0_frontier0"));
    }

    #[test]
    fn override_validation_rejects_other_versions_and_bad_suffixes() {
        for s in ["21.2.1", "21.2.0-x", "21.2.0_", "", "21.2.0_a/b"] {
            assert!(!ceph_version_override_ok(s), "{s:?}");
        }
    }

    #[test]
    fn identity_line_names_the_tracked_release() {
        assert!(identity_line().starts_with(&format!(
            "croit-flashstore-osd {CEPH_VERSION_SHORT} umbrella "
        )));
    }

    #[test]
    fn default_version_is_the_pinned_release_without_an_override() {
        assert!(
            CEPH_VERSION_SHORT == CEPH_VERSION_PINNED
                || option_env!("FLASHSTORE_CEPH_VERSION").is_some()
        );
    }

    #[test]
    fn pretty_version_carries_the_presented_version() {
        assert!(ceph_version_pretty().contains(CEPH_VERSION_SHORT));
    }
}
