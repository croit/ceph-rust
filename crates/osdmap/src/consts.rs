// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! OSDMap flags, osd state bits, release ids (spec osdmap.md 6, 1.3).

/// Maximum admitted OSD slots in full maps and incrementals (spec osdmap 1.7).
/// Checked before per-OSD allocation; this is a local resource admission limit.
pub const MAX_OSD_SLOTS: i32 = 1_048_576;

/// OSDMap.flags (u32).
pub mod map_flags {
    pub const NEARFULL: u32 = 1 << 0;
    pub const FULL: u32 = 1 << 1;
    pub const PAUSERD: u32 = 1 << 2;
    pub const PAUSEWR: u32 = 1 << 3;
    pub const PAUSEREC: u32 = 1 << 4;
    pub const NOUP: u32 = 1 << 5;
    pub const NODOWN: u32 = 1 << 6;
    pub const NOOUT: u32 = 1 << 7;
    pub const NOIN: u32 = 1 << 8;
    pub const NOBACKFILL: u32 = 1 << 9;
    pub const NORECOVER: u32 = 1 << 10;
    pub const NOSCRUB: u32 = 1 << 11;
    pub const NODEEP_SCRUB: u32 = 1 << 12;
    pub const NOTIERAGENT: u32 = 1 << 13;
    pub const NOREBALANCE: u32 = 1 << 14;
    pub const SORTBITWISE: u32 = 1 << 15;
    pub const REQUIRE_JEWEL: u32 = 1 << 16;
    pub const REQUIRE_KRAKEN: u32 = 1 << 17;
    pub const REQUIRE_LUMINOUS: u32 = 1 << 18;
    pub const RECOVERY_DELETES: u32 = 1 << 19;
    pub const PURGED_SNAPDIRS: u32 = 1 << 20;
    pub const NOSNAPTRIM: u32 = 1 << 21;
    pub const PGLOG_HARDLIMIT: u32 = 1 << 22;
    pub const NOAUTOSCALE: u32 = 1 << 23;
}

/// osd_state bits (u32).
pub mod osd_state {
    pub const EXISTS: u32 = 1 << 0;
    pub const UP: u32 = 1 << 1;
    pub const AUTOOUT: u32 = 1 << 2;
    pub const NEW: u32 = 1 << 3;
    pub const FULL: u32 = 1 << 4;
    pub const NEARFULL: u32 = 1 << 5;
    pub const BACKFILLFULL: u32 = 1 << 6;
    pub const DESTROYED: u32 = 1 << 7;
    pub const NOUP: u32 = 1 << 8;
    pub const NODOWN: u32 = 1 << 9;
    pub const NOIN: u32 = 1 << 10;
    pub const NOOUT: u32 = 1 << 11;
    pub const STOP: u32 = 1 << 12;
}

/// ceph_release_t.
pub mod release {
    pub const UNKNOWN: u8 = 0;
    pub const ARGONAUT: u8 = 1;
    pub const DUMPLING: u8 = 4;
    pub const FIREFLY: u8 = 6;
    pub const HAMMER: u8 = 8;
    pub const JEWEL: u8 = 10;
    pub const KRAKEN: u8 = 11;
    pub const LUMINOUS: u8 = 12;
    pub const MIMIC: u8 = 13;
    pub const NAUTILUS: u8 = 14;
    pub const OCTOPUS: u8 = 15;
    pub const PACIFIC: u8 = 16;
    pub const QUINCY: u8 = 17;
    pub const REEF: u8 = 18;
    pub const SQUID: u8 = 19;
    pub const TENTACLE: u8 = 20;
    pub const UMBRELLA: u8 = 21;
}

/// CRUSH "no item" marker in result vectors.
pub const ITEM_NONE: i32 = 0x7fff_ffff;
/// Default 16.16 weight / affinity (fully in / always eligible).
pub const WEIGHT_IN: u32 = 0x10000;
