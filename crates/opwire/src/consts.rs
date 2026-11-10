// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Constants of the client op wire (spec client-ops.md s3): op codes, message flags, per-op flags,
//! watch/cmp/checksum/backoff/event ids, errno values, feature masks gating the MOSDOp encoding.

/// CEPH_OSD_OP_* codes (u16). Encoding = mode | type | nr (s3.3).
pub mod op {
    pub const MODE_RD: u16 = 0x1000;
    pub const MODE_WR: u16 = 0x2000;
    pub const MODE_RMW: u16 = 0x3000;
    pub const MODE_SUB: u16 = 0x4000;
    pub const MODE_CACHE: u16 = 0x8000;
    pub const TYPE_MASK: u16 = 0x0f00;
    pub const TYPE_DATA: u16 = 0x0200;
    pub const TYPE_ATTR: u16 = 0x0300;
    pub const TYPE_EXEC: u16 = 0x0400;
    pub const TYPE_PG: u16 = 0x0500;

    pub const READ: u16 = 0x1201;
    pub const STAT: u16 = 0x1202;
    pub const MAPEXT: u16 = 0x1203;
    pub const MASKTRUNC: u16 = 0x1204;
    pub const SPARSE_READ: u16 = 0x1205;
    pub const NOTIFY: u16 = 0x1206;
    pub const NOTIFY_ACK: u16 = 0x1207;
    pub const ASSERT_VER: u16 = 0x1208;
    pub const LIST_WATCHERS: u16 = 0x1209;
    pub const LIST_SNAPS: u16 = 0x120a;
    pub const SYNC_READ: u16 = 0x120b;
    pub const TMAPGET: u16 = 0x120c;
    pub const OMAP_GET_KEYS: u16 = 0x1211;
    pub const OMAP_GET_VALS: u16 = 0x1212;
    pub const OMAP_GET_HEADER: u16 = 0x1213;
    pub const OMAP_GET_VALS_BY_KEYS: u16 = 0x1214;
    pub const OMAP_CMP: u16 = 0x1219;
    pub const ISDIRTY: u16 = 0x121d;
    pub const COPY_GET: u16 = 0x121e;
    pub const CHECKSUM: u16 = 0x121f;
    pub const CMPEXT: u16 = 0x1220;
    pub const GET_INTERNAL_VERSIONS: u16 = 0x1221;

    pub const WRITE: u16 = 0x2201;
    pub const WRITEFULL: u16 = 0x2202;
    pub const TRUNCATE: u16 = 0x2203;
    pub const ZERO: u16 = 0x2204;
    pub const DELETE: u16 = 0x2205;
    pub const APPEND: u16 = 0x2206;
    pub const STARTSYNC: u16 = 0x2207;
    pub const SETTRUNC: u16 = 0x2208;
    pub const TRIMTRUNC: u16 = 0x2209;
    pub const TMAPUP: u16 = 0x320a;
    pub const TMAPPUT: u16 = 0x220b;
    pub const CREATE: u16 = 0x220d;
    pub const ROLLBACK: u16 = 0x220e;
    pub const WATCH: u16 = 0x220f;
    pub const OMAP_SET_VALS: u16 = 0x2215;
    pub const OMAP_SET_HEADER: u16 = 0x2216;
    pub const OMAP_CLEAR: u16 = 0x2217;
    pub const OMAP_RM_KEYS: u16 = 0x2218;
    pub const COPY_FROM: u16 = 0x221a;
    pub const UNDIRTY: u16 = 0x221c;
    pub const TMAP2OMAP: u16 = 0x3222;
    pub const SET_ALLOC_HINT: u16 = 0x2223;
    pub const CACHE_PIN: u16 = 0x2224;
    pub const CACHE_UNPIN: u16 = 0x2225;
    pub const WRITESAME: u16 = 0x2226;
    pub const SET_REDIRECT: u16 = 0x2227;
    pub const SET_CHUNK: u16 = 0x8228;
    pub const TIER_PROMOTE: u16 = 0x2229;
    pub const UNSET_MANIFEST: u16 = 0x222a;
    pub const TIER_FLUSH: u16 = 0x822b;
    pub const TIER_EVICT: u16 = 0x822c;
    pub const OMAP_RM_KEY_RANGE: u16 = 0x222c;
    pub const COPY_FROM2: u16 = 0x222d;

    pub const CACHE_FLUSH: u16 = 0x821f;
    pub const CACHE_EVICT: u16 = 0x8220;
    pub const CACHE_TRY_FLUSH: u16 = 0x8221;

    pub const GETXATTR: u16 = 0x1301;
    pub const GETXATTRS: u16 = 0x1302;
    pub const CMPXATTR: u16 = 0x1303;
    pub const SETXATTR: u16 = 0x2301;
    pub const SETXATTRS: u16 = 0x2302;
    pub const RESETXATTRS: u16 = 0x2303;
    pub const RMXATTR: u16 = 0x2304;

    pub const CALL: u16 = 0x1401;

    pub const PGLS: u16 = 0x1501;
    pub const PGLS_FILTER: u16 = 0x1502;
    pub const PG_HITSET_LS: u16 = 0x1503;
    pub const PG_HITSET_GET: u16 = 0x1504;
    pub const PGNLS: u16 = 0x1505;
    pub const PGNLS_FILTER: u16 = 0x1506;
    pub const SCRUBLS: u16 = 0x1507;

    /// Internal SUB ops (never from clients): pull/push/balance-reads/unbalance-reads/scrub*.
    pub const SUB_FIRST: u16 = 0x4001;
    pub const SUB_LAST: u16 = 0x4009;

    /// Symbolic name for logs; `None` if unknown.
    pub const fn name(op: u16) -> Option<&'static str> {
        Some(match op {
            READ => "read",
            STAT => "stat",
            MAPEXT => "mapext",
            MASKTRUNC => "masktrunc",
            SPARSE_READ => "sparse-read",
            NOTIFY => "notify",
            NOTIFY_ACK => "notify-ack",
            ASSERT_VER => "assert-version",
            LIST_WATCHERS => "list-watchers",
            LIST_SNAPS => "list-snaps",
            SYNC_READ => "sync_read",
            TMAPGET => "tmapget",
            OMAP_GET_KEYS => "omap-get-keys",
            OMAP_GET_VALS => "omap-get-vals",
            OMAP_GET_HEADER => "omap-get-header",
            OMAP_GET_VALS_BY_KEYS => "omap-get-vals-by-keys",
            OMAP_CMP => "omap-cmp",
            ISDIRTY => "isdirty",
            COPY_GET => "copy-get",
            CHECKSUM => "checksum",
            CMPEXT => "cmpext",
            GET_INTERNAL_VERSIONS => "get-internal-versions",
            WRITE => "write",
            WRITEFULL => "writefull",
            TRUNCATE => "truncate",
            ZERO => "zero",
            DELETE => "delete",
            APPEND => "append",
            STARTSYNC => "startsync",
            SETTRUNC => "settrunc",
            TRIMTRUNC => "trimtrunc",
            TMAPUP => "tmapup",
            TMAPPUT => "tmapput",
            CREATE => "create",
            ROLLBACK => "rollback",
            WATCH => "watch",
            OMAP_SET_VALS => "omap-set-vals",
            OMAP_SET_HEADER => "omap-set-header",
            OMAP_CLEAR => "omap-clear",
            OMAP_RM_KEYS => "omap-rm-keys",
            COPY_FROM => "copy-from",
            UNDIRTY => "undirty",
            TMAP2OMAP => "tmap2omap",
            SET_ALLOC_HINT => "set-alloc-hint",
            CACHE_PIN => "cache-pin",
            CACHE_UNPIN => "cache-unpin",
            WRITESAME => "write-same",
            SET_REDIRECT => "set-redirect",
            SET_CHUNK => "set-chunk",
            TIER_PROMOTE => "tier-promote",
            UNSET_MANIFEST => "unset-manifest",
            TIER_FLUSH => "tier-flush",
            TIER_EVICT => "tier-evict",
            OMAP_RM_KEY_RANGE => "omap-rm-key-range",
            COPY_FROM2 => "copy-from2",
            CACHE_FLUSH => "cache-flush",
            CACHE_EVICT => "cache-evict",
            CACHE_TRY_FLUSH => "cache-try-flush",
            GETXATTR => "getxattr",
            GETXATTRS => "getxattrs",
            CMPXATTR => "cmpxattr",
            SETXATTR => "setxattr",
            SETXATTRS => "setxattrs",
            RESETXATTRS => "resetxattrs",
            RMXATTR => "rmxattr",
            CALL => "call",
            PGLS => "pgls",
            PGLS_FILTER => "pgls-filter",
            PG_HITSET_LS => "pg-hitset-ls",
            PG_HITSET_GET => "pg-hitset-get",
            PGNLS => "pgnls",
            PGNLS_FILTER => "pgnls-filter",
            SCRUBLS => "scrubls",
            SUB_FIRST..=SUB_LAST => "sub-op",
            _ => return None,
        })
    }
}

/// CEPH_OSD_FLAG_* (MOSDOp.flags, u32; s3.1).
pub mod flag {
    pub const ACK: u32 = 0x1;
    pub const ONNVRAM: u32 = 0x2;
    pub const ONDISK: u32 = 0x4;
    pub const RETRY: u32 = 0x8;
    pub const READ: u32 = 0x10;
    pub const WRITE: u32 = 0x20;
    pub const ORDERSNAP: u32 = 0x40;
    pub const PEERSTAT_OLD: u32 = 0x80;
    pub const BALANCE_READS: u32 = 0x100;
    pub const PARALLELEXEC: u32 = 0x200;
    pub const PGOP: u32 = 0x400;
    pub const EXEC: u32 = 0x800;
    pub const EXEC_PUBLIC: u32 = 0x1000;
    pub const LOCALIZE_READS: u32 = 0x2000;
    pub const RWORDERED: u32 = 0x4000;
    pub const IGNORE_CACHE: u32 = 0x8000;
    pub const SKIPRWLOCKS: u32 = 0x10000;
    pub const IGNORE_OVERLAY: u32 = 0x20000;
    pub const FLUSH: u32 = 0x40000;
    pub const MAP_SNAP_CLONE: u32 = 0x80000;
    pub const ENFORCE_SNAPC: u32 = 0x100000;
    pub const REDIRECTED: u32 = 0x200000;
    pub const KNOWN_REDIR: u32 = 0x400000;
    pub const FULL_TRY: u32 = 0x800000;
    pub const FULL_FORCE: u32 = 0x1000000;
    pub const IGNORE_REDIRECT: u32 = 0x2000000;
    pub const RETURNVEC: u32 = 0x4000000;
    pub const SUPPORTSPOOLEIO: u32 = 0x8000000;
    pub const EC_DIRECT_READ: u32 = 0x10000000;
    pub const FAIL_ON_EAGAIN: u32 = 0x20000000;
    pub const FORCE_OSD: u32 = 0x40000000;
    /// `CEPH_OSD_FLAGS_DIRECT_READ`: the three read-directing bits. Any of them on a write-ordered op is -EINVAL
    /// (client-ops 16.8).
    pub const DIRECT_READ: u32 = BALANCE_READS | LOCALIZE_READS | EC_DIRECT_READ;
}

/// CEPH_OSD_OP_FLAG_* (per-op `flags`; s3.2).
pub mod opflag {
    pub const EXCL: u32 = 0x1;
    pub const FAILOK: u32 = 0x2;
    pub const FADVISE_RANDOM: u32 = 0x4;
    pub const FADVISE_SEQUENTIAL: u32 = 0x8;
    pub const FADVISE_WILLNEED: u32 = 0x10;
    pub const FADVISE_DONTNEED: u32 = 0x20;
    pub const FADVISE_NOCACHE: u32 = 0x40;
    pub const WITH_REFERENCE: u32 = 0x80;
    pub const SCRUB: u32 = 0x100;
}

/// `watch.op` sub-ops (s3.4).
pub mod watch_op {
    pub const UNWATCH: u8 = 0;
    pub const LEGACY_WATCH: u8 = 1;
    pub const WATCH: u8 = 3;
    pub const RECONNECT: u8 = 5;
    pub const PING: u8 = 7;
}

/// cmpxattr comparison ops and modes (s3.7).
pub mod cmp {
    pub const EQ: u8 = 1;
    pub const NE: u8 = 2;
    pub const GT: u8 = 3;
    pub const GTE: u8 = 4;
    pub const LT: u8 = 5;
    pub const LTE: u8 = 6;
    pub const MODE_STRING: u8 = 1;
    pub const MODE_U64: u8 = 2;
}

/// Checksum types (s3.7).
pub mod csum {
    pub const XXHASH32: u8 = 0;
    pub const XXHASH64: u8 = 1;
    pub const CRC32C: u8 = 2;
    /// Width in bytes of one checksum value (and of the init value).
    pub const fn width(ty: u8) -> Option<usize> {
        match ty {
            XXHASH32 | CRC32C => Some(4),
            XXHASH64 => Some(8),
            _ => None,
        }
    }
}

/// MOSDBackoff ops (s3.7).
pub mod backoff {
    pub const BLOCK: u8 = 1;
    pub const ACK_BLOCK: u8 = 2;
    pub const UNBLOCK: u8 = 3;
}

/// MWatchNotify opcodes (s3.7).
pub mod notify {
    pub const NOTIFY: u8 = 1;
    pub const NOTIFY_COMPLETE: u8 = 2;
    pub const DISCONNECT: u8 = 3;
}

/// Alloc-hint flags (s3.6).
pub mod alloc_hint {
    pub const SEQUENTIAL_WRITE: u32 = 1;
    pub const RANDOM_WRITE: u32 = 2;
    pub const SEQUENTIAL_READ: u32 = 4;
    pub const RANDOM_READ: u32 = 8;
    pub const APPEND_ONLY: u32 = 16;
    pub const IMMUTABLE: u32 = 32;
    pub const SHORTLIVED: u32 = 64;
    pub const LONGLIVED: u32 = 128;
    pub const COMPRESSIBLE: u32 = 256;
    pub const INCOMPRESSIBLE: u32 = 512;
    pub const LOG: u32 = 1024;
}

/// Positive errno values used on the op wire (replies carry them negated; s3.5).
pub mod errno {
    pub use denc::errno::*;

    /// cmpext mismatch result for the first differing byte at `index`.
    pub const fn cmpext_mismatch(index: u64) -> i32 {
        -(MAX_ERRNO + index as i32)
    }
    /// Decode a cmpext mismatch result into the byte index.
    pub const fn cmpext_index(result: i32) -> Option<u64> {
        if result <= -MAX_ERRNO {
            Some((-(result as i64) - MAX_ERRNO as i64) as u64)
        } else {
            None
        }
    }
}

/// Snapshot ids (`CEPH_NOSNAP` etc.).
pub const NOSNAP: u64 = u64::MAX - 1;
pub const SNAPDIR: u64 = u64::MAX;
pub const MAXSNAP: u64 = u64::MAX - 2;

/// Message type ids.
pub mod ty {
    pub const OSD_OP: u16 = 42;
    pub const OSD_OPREPLY: u16 = 43;
    pub const WATCH_NOTIFY: u16 = 44;
    pub const OSD_BACKOFF: u16 = 61;
}

/// Connection feature masks that select the MOSDOp encoding version (s1.1); registry in `denc::features`.
pub mod feat {
    pub use denc::features::{NEW_OSDOP_ENCODING, RESEND_ON_SPLIT, SERVER_SQUID};
}
