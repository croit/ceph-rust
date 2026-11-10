// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Feature bits that gate encodings (spec encoding.md section 5). Single registry of every
//! feature mask used by the wire crates.

/// All feature bits set; default for encoding.
pub const ALL: u64 = u64::MAX;

/// Incarnation marker bits (`CEPH_FEATURE_INCARNATION_n`): incarnation 1 has none, 2 adds bit 57,
/// 3 adds bits 57 and 28.
pub const INCARNATION_2: u64 = 1 << 57;
pub const INCARNATION_3: u64 = INCARNATION_2 | (1 << 28);

/// Mask of feature `bit` at `incarnation` (1..=3), as Ceph's `DEFINE_CEPH_FEATURE`.
pub const fn incarnated(bit: u32, incarnation: u32) -> u64 {
    let marker = match incarnation {
        1 => 0,
        2 => INCARNATION_2,
        3 => INCARNATION_3,
        _ => panic!("feature incarnation 1..=3"),
    };
    (1u64 << bit) | marker
}

/// MSG_ADDR2 (bit 59, incarnation 1).
pub const MSG_ADDR2: u64 = incarnated(59, 1);
/// SERVER_NAUTILUS (bit 2, incarnation 3 => also bits 57 and 28).
pub const SERVER_NAUTILUS: u64 = incarnated(2, 3);
/// OS_PERF_STAT_NS (bit 17, incarnation 3): objectstore_perf_stat_t carries ns (v2) instead of ms (v1).
pub const OS_PERF_STAT_NS: u64 = incarnated(17, 3);
/// CRUSH_TUNABLES5 (bit 58).
pub const CRUSH_TUNABLES5: u64 = incarnated(58, 1);
/// SERVER_LUMINOUS (bit 21, incarnation 2). Also the `RESEND_ON_SPLIT` mask.
pub const SERVER_LUMINOUS: u64 = incarnated(21, 2);
/// RESEND_ON_SPLIT: luminous bit 21 incarnation 2.
pub const RESEND_ON_SPLIT: u64 = SERVER_LUMINOUS;
/// SERVER_QUINCY (bit 33, incarnation 3).
pub const SERVER_QUINCY: u64 = incarnated(33, 3);
/// CRUSH_MSR (bit 38, incarnation 2): the CRUSH blob carries msr tunables.
pub const CRUSH_MSR: u64 = incarnated(38, 2);
/// SERVER_REEF (bit 31, incarnation 3).
pub const SERVER_REEF: u64 = incarnated(31, 3);
/// SERVER_UMBRELLA (bit 52, incarnation 2).
pub const SERVER_UMBRELLA: u64 = incarnated(52, 2);
/// SERVER_SQUID (bit 49, incarnation 2).
pub const SERVER_SQUID: u64 = incarnated(49, 2);
/// SERVER_TENTACLE bit alone (bit 50).
pub const TENTACLE_BIT: u64 = incarnated(50, 1);
/// Full SERVER_TENTACLE mask (bit 50, incarnation 2).
pub const SERVER_TENTACLE: u64 = incarnated(50, 2);
/// NEW_OSDOP_ENCODING (bit 56).
pub const NEW_OSDOP_ENCODING: u64 = incarnated(56, 1);
/// Reserved feature bit used only as an in-process sentinel in inc encoding.
pub const RESERVED: u64 = incarnated(62, 1);

/// True if every bit of `mask` is set in `features`.
#[inline]
pub const fn have(features: u64, mask: u64) -> bool {
    features & mask == mask
}

/// [`have`], where `features == 0` means "all features" (encode for the newest peer).
#[inline]
pub const fn have_or_all(features: u64, mask: u64) -> bool {
    features == 0 || have(features, mask)
}
