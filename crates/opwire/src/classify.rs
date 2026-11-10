// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Op classification helpers (spec client-ops.md s3.3 helpers, s4).

use crate::consts::{errno, flag, op, watch_op};
use crate::osdop::OsdOp;

/// Op mutates (WR mode bit).
pub const fn modifies(o: u16) -> bool {
    o & op::MODE_WR != 0
}
/// Op reads (RD mode bit, except `call`, whose mode depends on the method).
pub const fn reads(o: u16) -> bool {
    o & op::MODE_RD != 0 && o != op::CALL
}
/// Op is a PG-level op (pgls/pgnls/...).
pub const fn is_pg_op(o: u16) -> bool {
    o & op::TYPE_MASK == op::TYPE_PG
}
/// Cache/tier op.
pub const fn is_cache(o: u16) -> bool {
    o & op::MODE_CACHE != 0
}
/// Internal SUB op (never valid from a client).
pub const fn is_sub(o: u16) -> bool {
    o & op::MODE_SUB != 0
}
/// Ops that are served by the primary only (s4).
pub const fn is_primary_only_op(o: u16) -> bool {
    is_pg_op(o) || o == op::WATCH || o == op::NOTIFY || o == op::NOTIFY_ACK
}
/// Op whose union is the [`crate::osdop::Extent`] view, truncate fields included (extent normalisation, s7.2).
pub const fn is_extent_op(o: u16) -> bool {
    matches!(
        o,
        op::READ
            | op::MAPEXT
            | op::MASKTRUNC
            | op::SPARSE_READ
            | op::SYNC_READ
            | op::WRITE
            | op::WRITEFULL
            | op::TRUNCATE
            | op::ZERO
            | op::APPEND
            | op::TRIMTRUNC
            | op::CMPEXT
    )
}
/// V1 ops that return EOPNOTSUPP (s3.3, s12).
pub const fn is_later(o: u16) -> bool {
    matches!(
        o,
        op::MASKTRUNC
            | op::TMAPGET
            | op::TMAPUP
            | op::TMAPPUT
            | op::TMAP2OMAP
            | op::SETTRUNC
            | op::GET_INTERNAL_VERSIONS
            | op::SETXATTRS
            | op::RESETXATTRS
            | op::CACHE_PIN
            | op::CACHE_UNPIN
            | op::SET_REDIRECT
            | op::SET_CHUNK
            | op::TIER_PROMOTE
            | op::UNSET_MANIFEST
            | op::TIER_FLUSH
            | op::TIER_EVICT
            | op::CACHE_FLUSH
            | op::CACHE_EVICT
            | op::CACHE_TRY_FLUSH
    )
}

/// Registered rd/wr flags of a class method (from the cls registry); `None` = unknown method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClsFlags {
    pub rd: bool,
    pub wr: bool,
}

/// Registry answer for one `call` op (cls.md 2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClsEntry {
    /// Registered flags of the method.
    pub flags: ClsFlags,
    /// Class is on `osd_class_default_list`: the grant's class-read/-write bits reach it without `allow class NAME`.
    pub allowed: bool,
}

/// One `call` in the vector, for cap checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClsCap {
    pub class: Vec<u8>,
    pub method: Vec<u8>,
    pub flags: ClsFlags,
    /// `allowed` of [`ClsEntry`] (off the default list: only `allow class NAME` reaches it).
    pub allowed: bool,
}

/// Registry lookup: `(class, method)` -> entry, `None` = unknown method.
pub type ClsLookup<'a> = dyn Fn(&[u8], &[u8]) -> Option<ClsEntry> + 'a;

/// Counter class of a request, decided from its op codes (spec ops-observability.md 2d): the client
/// `CEPH_OSD_FLAG_READ|WRITE` bits have no bearing on whether an op is a read, a write, etc.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpClass {
    /// `MODE_RD` on any op (a `call` contributes its method's `CLS_METHOD_RD`; `watch` forces it).
    pub read: bool,
    /// `MODE_WR` or `MODE_CACHE` on any op (a `call` contributes its method's `CLS_METHOD_WR`).
    pub write: bool,
}

/// Registry lookup of a `call` op's flags: `(class, method)` -> registered flags (`None` = unknown method).
pub type ClsFlagsLookup<'a> = dyn Fn(&[u8], &[u8]) -> Option<ClsFlags> + 'a;

impl OpClass {
    /// No read, write or cache op: the request has no counter bucket (classic refuses it).
    pub const fn is_empty(&self) -> bool {
        !self.read && !self.write
    }

    /// Union over a request's ops. `cls` = registered flags of a `call` op (`None` = unknown method).
    pub fn of(ops: &[OsdOp], cls: &ClsFlagsLookup<'_>) -> OpClass {
        use crate::consts::op::{CALL, WATCH};
        let mut c = OpClass::default();
        for o in ops {
            if o.op == CALL {
                if let Some(flags) = o.cls_call().ok().and_then(|c| cls(c.class, c.method)) {
                    c.read |= flags.rd;
                    c.write |= flags.wr;
                }
                continue;
            }
            // WATCH carries the WR mode bit and additionally forces the read bit
            if o.op == WATCH {
                c.read = true;
            }
            c.read |= reads(o.op);
            c.write |= modifies(o.op) || is_cache(o.op);
        }
        c
    }
}

/// Message-level classification (s4), computed once from the op vector.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OpInfo {
    pub may_write: bool,
    pub may_read: bool,
    /// Any read op other than `stat`: needs previously queued writes applied.
    pub read_data: bool,
    pub pg_op: bool,
    pub primary_only: bool,
    /// Order wrt writes as a write: may_write, client RWORDERED, or watch PING.
    pub rwordered: bool,
    pub cls: Vec<ClsCap>,
}

impl OpInfo {
    /// Classify `ops` for a message with client `msg_flags`. `lookup(class, method)` = registered
    /// flags (None = unknown method -> -EOPNOTSUPP). Errors are positive errno.
    pub fn classify(ops: &[OsdOp], msg_flags: u32, lookup: &ClsLookup<'_>) -> Result<OpInfo, i32> {
        let mut i = OpInfo::default();
        let mut ping = false;
        for o in ops {
            let c = o.op;
            if c & (op::MODE_RD | op::MODE_WR) == 0 {
                return Err(errno::EINVAL);
            }
            if is_pg_op(c) {
                i.pg_op = true;
                i.primary_only = true;
            }
            if is_primary_only_op(c) {
                i.primary_only = true;
            }
            if c == op::WATCH {
                i.may_read = true;
                if o.watch().op == watch_op::PING {
                    ping = true;
                    continue;
                }
            }
            if c == op::CALL {
                let call = o.cls_call().map_err(|_| errno::EINVAL)?;
                let e = lookup(call.class, call.method).ok_or(errno::EOPNOTSUPP)?;
                i.may_read |= e.flags.rd;
                i.may_write |= e.flags.wr;
                i.cls.push(ClsCap {
                    class: call.class.to_vec(),
                    method: call.method.to_vec(),
                    flags: e.flags,
                    allowed: e.allowed,
                });
                continue;
            }
            if modifies(c) {
                i.may_write = true;
            }
            if reads(c) {
                i.may_read = true;
                if c != op::STAT {
                    i.read_data = true;
                }
            }
        }
        i.rwordered = i.may_write || msg_flags & flag::RWORDERED != 0 || ping;
        if !i.may_read && !i.may_write {
            return Err(errno::EINVAL);
        }
        Ok(i)
    }
}

#[cfg(test)]
mod pg_read_tests {
    use super::*;

    #[test]
    fn hit_set_and_scrub_list_are_supported_primary_pg_reads() {
        for operation in [op::PG_HITSET_LS, op::PG_HITSET_GET, op::SCRUBLS] {
            let info = OpInfo::classify(&[OsdOp::new(operation)], 0, &|_, _| None).unwrap();
            assert!(info.may_read);
            assert!(info.pg_op);
            assert!(info.primary_only);
            assert!(!is_later(operation));
        }
    }

    /// The counter class comes from the op codes only (spec ops-observability.md 2d): no client flag, `watch` forces
    /// read on top of its write bit, a `call` counts its method's flags and a cache op is a write.
    #[test]
    fn op_class_follows_the_op_codes() {
        let none = |_: &[u8], _: &[u8]| None;
        let rd = OpClass {
            read: true,
            write: false,
        };
        let wr = OpClass {
            read: false,
            write: true,
        };
        let rw = OpClass {
            read: true,
            write: true,
        };
        assert!(OpClass::of(&[], &none).is_empty());
        assert_eq!(OpClass::of(&[OsdOp::new(op::STAT)], &none), rd);
        assert_eq!(OpClass::of(&[OsdOp::new(op::DELETE)], &none), wr);
        assert_eq!(
            OpClass::of(&[OsdOp::new(op::STAT), OsdOp::new(op::DELETE)], &none),
            rw
        );
        assert_eq!(OpClass::of(&[OsdOp::new(op::WATCH)], &none), rw);
        assert_eq!(OpClass::of(&[OsdOp::new(op::CACHE_FLUSH)], &none), wr);
        // a write-only class method: write even though the `call` op code itself is RD
        let call = OsdOp::call(b"rbd", b"cls_rbd_test_write", b"");
        let flags = |class: &[u8], method: &[u8]| {
            (class == b"rbd" && method == b"cls_rbd_test_write").then_some(ClsFlags {
                rd: false,
                wr: true,
            })
        };
        assert_eq!(OpClass::of(&[call], &flags), wr);
        // an unknown class/method contributes nothing
        let unknown = OsdOp::call(b"nope", b"nope", b"");
        assert!(OpClass::of(&[unknown], &none).is_empty());
    }
}
