// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Release / feature policy (adr 0045). We track ONE Ceph release; a cluster that requires more than we implement
//! makes us refuse to run (fail closed) instead of joining with half-understood semantics.
use osdmap::OsdMap;
use osdmap::consts::release;

/// Release this build implements (tracked reference, `version.rs`).
pub const TRACKED_RELEASE: u8 = release::UMBRELLA;
/// Oldest `require_osd_release` we still handle (older maps lack encodings/behaviors we never implemented).
pub const MIN_RELEASE: u8 = release::PACIFIC;
/// Exit code for "refused by policy" (= adr 0034 exit 3, `RestartPreventExitStatus` in the unit).
pub const EXIT_REFUSED: i32 = 3;

/// Feature bits we claim in MOSDBoot / msgr2 supported set. Never widen without implementing the feature (adr 0045).
pub const CLAIMED_FEATURES: u64 = msgr2::FEATURES_SUPPORTED_DEFAULT;

/// Release name for logs.
pub fn release_name(r: u8) -> &'static str {
    match r {
        release::PACIFIC => "pacific",
        release::QUINCY => "quincy",
        release::REEF => "reef",
        release::SQUID => "squid",
        release::TENTACLE => "tentacle",
        release::UMBRELLA => "umbrella",
        _ => "unknown",
    }
}

/// Does the cluster's `require_osd_release` fit what this build implements? `Err` = refuse text.
pub fn check_map(map: &OsdMap) -> Result<(), String> {
    check_release(map.require_osd_release)
}

/// See [`check_map`]. 0 (unset, fresh/empty map) is accepted: no claim yet.
pub fn check_release(r: u8) -> Result<(), String> {
    if r == release::UNKNOWN {
        return Ok(());
    }
    if r > TRACKED_RELEASE {
        return Err(format!(
            "cluster require_osd_release is {} ({r}), newer than the tracked release {} ({}) of this build: \
             refusing to run (fail closed); upgrade croit-flashstore-osd (doc/release-resync.md)",
            release_name(r),
            release_name(TRACKED_RELEASE),
            TRACKED_RELEASE
        ));
    }
    if r < MIN_RELEASE {
        return Err(format!(
            "cluster require_osd_release is {} ({r}), older than the minimum {} ({}) supported by this build: \
             refusing to run; raise it with `ceph osd require-osd-release`",
            release_name(r),
            release_name(MIN_RELEASE),
            MIN_RELEASE
        ));
    }
    Ok(())
}

/// Oldest `require_osd_release` at which the pinned monitor admits a SERVER_UMBRELLA boot
/// (`doc/spec/osd-lifecycle.md` §3.3). Below it the monitor ignores MOSDBoot.
pub const MIN_BOOT_RELEASE: u8 = release::SQUID;

/// Diagnostic for a boot the monitor will ignore. The boot is still sent and resent
/// like classic `ceph-osd` (adr 0045 am. 1): raising the release admits it without a restart.
pub fn boot_admission_warning(r: u8) -> Option<String> {
    let min = release_name(MIN_BOOT_RELEASE);
    (r != release::UNKNOWN && r < MIN_BOOT_RELEASE).then(|| {
        format!(
            "WARNING the monitor ignores this boot: cluster require_osd_release {} ({r}) < {min} ({MIN_BOOT_RELEASE}), \
             required for a SERVER_UMBRELLA OSD; upgrade all OSDs to {min} or newer and run \
             `ceph osd require-osd-release {min}`; boot is retried",
            release_name(r),
        )
    })
}

/// Feature bits a peer/mon requires that we do not claim (0 = ok).
pub fn missing_features(required: u64) -> u64 {
    required & !CLAIMED_FEATURES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_window() {
        assert!(check_release(0).is_ok());
        for r in MIN_RELEASE..=TRACKED_RELEASE {
            assert!(check_release(r).is_ok(), "{r}");
        }
        let e = check_release(TRACKED_RELEASE + 1).unwrap_err();
        assert!(e.contains("fail closed"), "{e}");
        assert!(check_release(MIN_RELEASE - 1).is_err());
        assert!(check_release(255).is_err());
    }

    #[test]
    fn never_claims_unimplemented() {
        assert_eq!(CLAIMED_FEATURES & (1 << 17), 0);
        assert_ne!(missing_features(1 << 63), 0);
        assert_ne!(missing_features(1 << 51), 0);
        assert_eq!(missing_features(msgr2::MSGR2_REQUIRED), 0);
        assert_eq!(missing_features(msgr2::OSD_REQUIRED), 0);
        assert_eq!(missing_features(denc::features::SERVER_SQUID), 0);
    }
}
