// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `ceph_osd_op` (38 bytes packed) with typed union views, and [`OsdOp`] = op + indata/outdata/rval
//! (spec client-ops.md s1.3-1.5).

use crate::consts::{op as code, opflag};
use bytes::Bytes;
use denc::le::{self, rd_u32, rd_u64, wr_u32, wr_u64};
use denc::{BufMut, Decoder, Encoder, Error, Result};

/// Size of one `ceph_osd_op` on the wire.
pub const OP_LEN: usize = 38;
/// Size of the per-op union.
pub const UNION_LEN: usize = 28;

macro_rules! view {
    ($(#[$m:meta])* $name:ident { $($f:ident : $t:ident @ $off:expr),* $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
        pub struct $name { $(pub $f: $t),* }
        impl $name {
            /// Read the view out of an op union.
            pub fn from_union(u: &[u8; UNION_LEN]) -> Self {
                $name { $($f: view!(@rd $t, u, $off)),* }
            }
            /// Write the view into an op union (all other bytes zeroed).
            pub fn to_union(&self) -> [u8; UNION_LEN] {
                let mut u = [0u8; UNION_LEN];
                $(view!(@wr $t, u, $off, self.$f);)*
                u
            }
        }
    };
    (@rd u64, $u:ident, $o:expr) => { rd_u64($u, $o) };
    (@rd u32, $u:ident, $o:expr) => { rd_u32($u, $o) };
    (@rd u8, $u:ident, $o:expr) => { $u[$o] };
    (@wr u64, $u:ident, $o:expr, $v:expr) => { wr_u64(&mut $u, $o, $v) };
    (@wr u32, $u:ident, $o:expr, $v:expr) => { wr_u32(&mut $u, $o, $v) };
    (@wr u8, $u:ident, $o:expr, $v:expr) => { $u[$o] = $v };
}

view!(
    /// read, sync-read, sparse-read, mapext, masktrunc, write, writefull, append, zero, truncate,
    /// trimtrunc, cmpext, omap ops (informational).
    Extent { offset: u64 @ 0, length: u64 @ 8, truncate_size: u64 @ 16, truncate_seq: u32 @ 24 }
);
view!(
    /// getxattr, setxattr, rmxattr, cmpxattr.
    Xattr { name_len: u32 @ 0, value_len: u32 @ 4, cmp_op: u8 @ 8, cmp_mode: u8 @ 9 }
);
view!(
    /// call.
    Cls { class_len: u8 @ 0, method_len: u8 @ 1, argc: u8 @ 2, indata_len: u32 @ 3 }
);
view!(
    /// pgls, pgnls (+filter).
    Pgls { count: u64 @ 0, start_epoch: u32 @ 8 }
);
view!(
    /// PG hit-set get timestamp (`ceph_timespec`).
    HitSetGet { sec: u32 @ 0, nsec: u32 @ 4 }
);
view!(
    /// rollback.
    SnapOp { snapid: u64 @ 0 }
);
view!(
    /// watch.
    Watch { cookie: u64 @ 0, ver: u64 @ 8, op: u8 @ 16, gen_: u32 @ 17, timeout: u32 @ 21 }
);
view!(
    /// notify (and legacy notify-ack: `cookie` = notify_id).
    Notify { cookie: u64 @ 0 }
);
view!(
    /// assert-version.
    AssertVer { unused: u64 @ 0, ver: u64 @ 8 }
);
view!(
    /// set-alloc-hint.
    AllocHint { expected_object_size: u64 @ 0, expected_write_size: u64 @ 8, flags: u32 @ 16 }
);
view!(
    /// write-same.
    WriteSame { offset: u64 @ 0, length: u64 @ 8, data_length: u64 @ 16 }
);
view!(
    /// checksum.
    Checksum { offset: u64 @ 0, length: u64 @ 8, chunk_size: u32 @ 16, ty: u8 @ 20 }
);
view!(
    /// copy-from / copy-from2.
    CopyFrom { snapid: u64 @ 0, src_version: u64 @ 8, flags: u8 @ 16, src_fadvise_flags: u32 @ 17 }
);
view!(
    /// copy-get.
    CopyGet { max: u64 @ 0 }
);

/// Known crc of `outdata` (store-derived), owner-bound: see [`crc::CrcHint`].
pub use crc::CrcHint;

/// Shared byte pieces in order, each with its crc hint (`OsdOp::outdata_more`, a reply's data segment after its first piece).
pub type Pieces = Vec<(Bytes, CrcHint)>;

/// One op: `ceph_osd_op` header plus its data. In a request `indata` is filled (it travels in the
/// data segment, `payload_len` = its length); in a reply `outdata` and `rval` are filled.
/// The union is kept raw so that unknown/unused bytes survive a decode/encode round trip.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OsdOp {
    pub op: u16,
    pub flags: u32,
    pub u: [u8; UNION_LEN],
    pub indata: Bytes,
    pub outdata: Bytes,
    /// Known crc of `outdata` (reads served from verified store blocks).
    pub outdata_crc: CrcHint,
    /// Further pieces of the output (OSD side only, never decoded): the op's output is `outdata` followed by these, each
    /// with its crc hint. A read served by reference from store buffers ([`OsdOp::set_outdata_parts`]); sent by
    /// reference too ([`crate::MOSDOpReply::encode_parts`]). Use [`OsdOp::outdata_len`] / [`OsdOp::flatten_outdata`].
    pub outdata_more: Pieces,
    /// Placement-only seed-0 CRCs of the concatenated READ output on its
    /// logical 4 KiB grid. None for ordinary replies. This is local metadata,
    /// never encoded as an ordinary Ceph op field.
    pub outdata_block_crcs: Option<Vec<u32>>,
    /// Known crc of `indata` (the verified msgr2 data-segment crc when `indata` is the whole segment; never decoded).
    pub indata_crc: CrcHint,
    /// Further pieces of the input (requests only, never decoded): the op's input is `indata` followed by these, each
    /// with its crc hint. A write whose caller buffer is several segments is sent by reference, piece by piece, with no
    /// flattening copy ([`OsdOp::set_indata_parts`]); the msgr2 sender takes them as a scatter data segment. Use
    /// [`OsdOp::indata_len`].
    pub indata_more: Pieces,
    pub rval: i32,
}

macro_rules! accessors {
    ($($get:ident / $set:ident : $t:ident),* $(,)?) => {$(
        pub fn $get(&self) -> $t { $t::from_union(&self.u) }
        pub fn $set(&mut self, v: $t) { self.u = v.to_union(); }
    )*};
}

impl OsdOp {
    pub fn new(op: u16) -> Self {
        OsdOp {
            op,
            ..Default::default()
        }
    }
    accessors!(
        extent / set_extent: Extent,
        xattr / set_xattr: Xattr,
        cls / set_cls: Cls,
        pgls / set_pgls: Pgls,
        hit_set_get / set_hit_set_get: HitSetGet,
        snap / set_snap: SnapOp,
        watch / set_watch: Watch,
        notify / set_notify: Notify,
        assert_ver / set_assert_ver: AssertVer,
        alloc_hint / set_alloc_hint: AllocHint,
        write_same / set_write_same: WriteSame,
        checksum / set_checksum: Checksum,
        copy_from / set_copy_from: CopyFrom,
        copy_get / set_copy_get: CopyGet,
    );

    /// FAILOK set (s3.2).
    pub fn failok(&self) -> bool {
        self.flags & opflag::FAILOK != 0
    }

    /// Echo for a reply: same op/flags/union, no indata, rval 0.
    pub fn echo(&self) -> OsdOp {
        OsdOp {
            op: self.op,
            flags: self.flags,
            u: self.u,
            indata: Bytes::new(),
            outdata: Bytes::new(),
            outdata_crc: CrcHint::default(),
            outdata_more: Vec::new(),
            outdata_block_crcs: None,
            indata_crc: CrcHint::default(),
            indata_more: Vec::new(),
            rval: 0,
        }
    }

    /// Length of the whole input (`indata` and its further pieces).
    pub fn indata_len(&self) -> usize {
        self.indata.len() + self.indata_more.iter().map(|(b, _)| b.len()).sum::<usize>()
    }

    /// Set the input from pieces in order, each with the crc32c (seed `!0`) of exactly its bytes when known. Empty
    /// pieces are skipped; no byte is copied.
    pub fn set_indata_parts(&mut self, parts: impl IntoIterator<Item = (Bytes, Option<u32>)>) {
        self.indata = Bytes::new();
        self.indata_crc = CrcHint::default();
        self.indata_more = Vec::new();
        let hint =
            |b: &Bytes, c: Option<u32>| c.map_or_else(CrcHint::default, |c| CrcHint::new(b, c));
        let mut nonempty = parts.into_iter().filter(|(b, _)| !b.is_empty());
        let Some((first, crc)) = nonempty.next() else {
            return;
        };
        self.indata_crc = hint(&first, crc);
        self.indata = first;
        self.indata_more = nonempty
            .map(|(b, c)| {
                let h = hint(&b, c);
                (b, h)
            })
            .collect();
    }

    /// Length of the whole output (`outdata` and its further pieces).
    pub fn outdata_len(&self) -> usize {
        self.outdata.len()
            + self
                .outdata_more
                .iter()
                .map(|(b, _)| b.len())
                .sum::<usize>()
    }

    /// Drop the output (all pieces and hints).
    pub fn clear_outdata(&mut self) {
        self.outdata = Bytes::new();
        self.outdata_crc = CrcHint::default();
        self.outdata_more = Vec::new();
        self.outdata_block_crcs = None;
    }

    /// Reset the result of an op that runs (again): rval 0, no output.
    pub fn reset_result(&mut self) {
        self.rval = 0;
        self.clear_outdata();
    }

    /// Move the output (all pieces and hints) out, leaving none.
    pub fn take_outdata(&mut self) -> (Bytes, CrcHint, Pieces, Option<Vec<u32>>) {
        (
            core::mem::take(&mut self.outdata),
            core::mem::take(&mut self.outdata_crc),
            core::mem::take(&mut self.outdata_more),
            self.outdata_block_crcs.take(),
        )
    }

    /// Set the output from pieces in order, each with the crc32c (seed `!0`) of exactly its bytes when known. Empty
    /// pieces are skipped.
    pub fn set_outdata_parts(&mut self, parts: impl IntoIterator<Item = (Bytes, Option<u32>)>) {
        self.set_outdata_iter(parts.into_iter(), 0);
    }

    /// Set output from an owned descriptor vector, skipping empty pieces.
    /// Multiple nonempty pieces reserve metadata capacity from the input count
    /// once, including any empty input descriptors. Payload ownership moves
    /// unchanged; neither bytes nor checksums are recomputed in release builds.
    pub fn set_outdata_vec(&mut self, parts: Vec<(Bytes, Option<u32>)>) {
        let additional = parts.len().saturating_sub(1);
        self.set_outdata_iter(parts.into_iter(), additional);
    }

    fn set_outdata_iter(
        &mut self,
        parts: impl Iterator<Item = (Bytes, Option<u32>)>,
        additional: usize,
    ) {
        self.clear_outdata();
        let hint =
            |b: &Bytes, c: Option<u32>| c.map_or_else(CrcHint::default, |c| CrcHint::new(b, c));
        let mut nonempty = parts.filter(|(b, _)| !b.is_empty());
        let Some((first, crc)) = nonempty.next() else {
            return;
        };
        self.outdata_crc = hint(&first, crc);
        self.outdata = first;
        if let Some((second, crc)) = nonempty.next() {
            // Wait for a second actual piece: empty/single-piece results retain
            // no metadata allocation, even with many empty descriptors.
            self.outdata_more.reserve(additional);
            let h = hint(&second, crc);
            self.outdata_more.push((second, h));
            self.outdata_more.extend(nonempty.map(|(b, c)| {
                let h = hint(&b, c);
                (b, h)
            }));
        }
    }

    /// Make the output one buffer (`outdata`): pieces are concatenated (copy), the crc hint is kept when every piece had
    /// one. No-op for a single piece.
    pub fn flatten_outdata(&mut self) {
        if self.outdata_more.is_empty() {
            return;
        }
        let mut crc = self.outdata_crc.of(&self.outdata);
        let mut v = Vec::with_capacity(self.outdata_len());
        v.extend_from_slice(&self.outdata);
        for (b, h) in &self.outdata_more {
            crc = crc.zip(h.of(b)).map(|(a, c)| {
                // crc(!0, a ++ b) from crc(!0, a) and crc(!0, b)
                crc::crc32c_append_ones(a, c, b.len() as u64)
            });
            v.extend_from_slice(b);
        }
        self.outdata_more = Vec::new();
        self.outdata = Bytes::from(v);
        self.outdata_crc = crc.map_or_else(CrcHint::default, |c| CrcHint::new(&self.outdata, c));
    }

    /// Wire header with `payload_len`.
    pub fn header_bytes(&self, payload_len: u32) -> [u8; OP_LEN] {
        let mut b = [0u8; OP_LEN];
        b[0..2].copy_from_slice(&self.op.to_le_bytes());
        le::wr_u32(&mut b, 2, self.flags);
        b[6..34].copy_from_slice(&self.u);
        le::wr_u32(&mut b, 34, payload_len);
        b
    }

    /// Parse a wire header; returns the op (no data) and `payload_len`.
    pub fn parse_header(b: &[u8]) -> Result<(OsdOp, u32)> {
        if b.len() < OP_LEN {
            return Err(Error::Eof {
                needed: OP_LEN,
                remaining: b.len(),
            });
        }
        let mut u = [0u8; UNION_LEN];
        u.copy_from_slice(&b[6..34]);
        Ok((
            OsdOp {
                op: u16::from_le_bytes([b[0], b[1]]),
                flags: le::rd_u32(b, 2),
                u,
                ..Default::default()
            },
            le::rd_u32(b, 34),
        ))
    }

    // ---- constructors (clients, tests, load generators) ----

    pub fn read(offset: u64, length: u64) -> Self {
        Self::extent_op(code::READ, offset, length, Vec::new())
    }
    pub fn sparse_read(offset: u64, length: u64) -> Self {
        Self::extent_op(code::SPARSE_READ, offset, length, Vec::new())
    }
    pub fn mapext(offset: u64, length: u64) -> Self {
        Self::extent_op(code::MAPEXT, offset, length, Vec::new())
    }
    pub fn write(offset: u64, data: Vec<u8>) -> Self {
        Self::write_bytes(offset, data.into())
    }
    /// Write retaining an existing immutable payload owner (no copy).
    pub fn write_bytes(offset: u64, data: Bytes) -> Self {
        Self::extent_op(code::WRITE, offset, data.len() as u64, data)
    }
    pub fn writefull(data: Vec<u8>) -> Self {
        Self::writefull_bytes(data.into())
    }
    /// Full write retaining an existing immutable payload owner.
    pub fn writefull_bytes(data: Bytes) -> Self {
        let mut operation = Self::new(code::WRITEFULL);
        operation.set_extent(Extent {
            length: data.len() as u64,
            ..Default::default()
        });
        operation.indata = data;
        operation
    }
    pub fn append(data: Vec<u8>) -> Self {
        Self::append_bytes(data.into())
    }
    /// Append retaining an existing immutable payload owner (no copy).
    pub fn append_bytes(data: Bytes) -> Self {
        Self::extent_op(code::APPEND, 0, data.len() as u64, data)
    }
    pub fn zero(offset: u64, length: u64) -> Self {
        Self::extent_op(code::ZERO, offset, length, Vec::new())
    }
    pub fn truncate(size: u64) -> Self {
        Self::extent_op(code::TRUNCATE, size, 0, Vec::new())
    }
    pub fn cmpext(offset: u64, expected: Vec<u8>) -> Self {
        Self::extent_op(code::CMPEXT, offset, expected.len() as u64, expected)
    }
    fn extent_op(op: u16, offset: u64, length: u64, indata: impl Into<Bytes>) -> Self {
        let mut o = OsdOp::new(op);
        o.set_extent(Extent {
            offset,
            length,
            ..Default::default()
        });
        o.indata = indata.into();
        o
    }
    pub fn stat() -> Self {
        OsdOp::new(code::STAT)
    }
    pub fn delete() -> Self {
        OsdOp::new(code::DELETE)
    }
    pub fn create(excl: bool) -> Self {
        let mut o = OsdOp::new(code::CREATE);
        if excl {
            o.flags |= opflag::EXCL;
        }
        o
    }
    pub fn rollback(snapid: u64) -> Self {
        let mut o = OsdOp::new(code::ROLLBACK);
        o.set_snap(SnapOp { snapid });
        o
    }
    pub fn list_snaps() -> Self {
        OsdOp::new(code::LIST_SNAPS)
    }
    pub fn list_watchers() -> Self {
        OsdOp::new(code::LIST_WATCHERS)
    }
    pub fn assert_version(ver: u64) -> Self {
        let mut o = OsdOp::new(code::ASSERT_VER);
        o.set_assert_ver(AssertVer { unused: 0, ver });
        o
    }
    pub fn alloc_hint_op(object_size: u64, write_size: u64, flags: u32) -> Self {
        let mut o = OsdOp::new(code::SET_ALLOC_HINT);
        o.set_alloc_hint(AllocHint {
            expected_object_size: object_size,
            expected_write_size: write_size,
            flags,
        });
        o
    }
    pub fn writesame(offset: u64, length: u64, pattern: Vec<u8>) -> Self {
        let mut o = OsdOp::new(code::WRITESAME);
        o.set_write_same(WriteSame {
            offset,
            length,
            data_length: pattern.len() as u64,
        });
        o.indata = pattern.into();
        o
    }
    pub fn getxattr(name: &[u8]) -> Self {
        Self::xattr_op(code::GETXATTR, name, &[])
    }
    pub fn rmxattr(name: &[u8]) -> Self {
        Self::xattr_op(code::RMXATTR, name, &[])
    }
    pub fn setxattr(name: &[u8], value: &[u8]) -> Self {
        Self::xattr_op(code::SETXATTR, name, value)
    }
    pub fn cmpxattr(name: &[u8], value: &[u8], cmp_op: u8, cmp_mode: u8) -> Self {
        let mut o = Self::xattr_op(code::CMPXATTR, name, value);
        let mut x = o.xattr();
        x.cmp_op = cmp_op;
        x.cmp_mode = cmp_mode;
        o.set_xattr(x);
        o
    }
    fn xattr_op(op: u16, name: &[u8], value: &[u8]) -> Self {
        let mut o = OsdOp::new(op);
        o.set_xattr(Xattr {
            name_len: name.len() as u32,
            value_len: value.len() as u32,
            ..Default::default()
        });
        o.indata = ([name, value].concat()).into();
        o
    }
    /// `call` class.method(input): indata = class || method || input.
    /// Panics if `class` or `method` exceeds 255 bytes, the u8 wire length of their prefixes.
    pub fn call(class: &[u8], method: &[u8], input: &[u8]) -> Self {
        let mut o = OsdOp::new(code::CALL);
        o.set_cls(Cls {
            class_len: u8::try_from(class.len())
                .expect("class name does not fit the u8 wire length"),
            method_len: u8::try_from(method.len())
                .expect("method name does not fit the u8 wire length"),
            argc: 0,
            indata_len: input.len() as u32,
        });
        o.indata = ([class, method, input].concat()).into();
        o
    }
    pub fn watch_op(cookie: u64, sub_op: u8, timeout: u32) -> Self {
        let mut o = OsdOp::new(code::WATCH);
        o.set_watch(Watch {
            cookie,
            op: sub_op,
            timeout,
            ..Default::default()
        });
        o
    }
    /// notify: indata = u32 prot_ver(1), u32 timeout, bufferlist payload.
    pub fn notify_op(cookie: u64, timeout_s: u32, payload: &[u8]) -> Self {
        let mut o = OsdOp::new(code::NOTIFY);
        o.set_notify(Notify { cookie });
        let mut e = Encoder::new();
        e.u32(1)
            .and(e.u32(timeout_s))
            .and(e.bytes(payload))
            .expect("vec");
        o.indata = (e.into_vec()).into();
        o
    }
    /// notify-ack: indata = u64 notify_id, u64 cookie, bufferlist reply.
    pub fn notify_ack(notify_id: u64, cookie: u64, reply: &[u8]) -> Self {
        let mut o = OsdOp::new(code::NOTIFY_ACK);
        let mut e = Encoder::new();
        e.u64(notify_id)
            .and(e.u64(cookie))
            .and(e.bytes(reply))
            .expect("vec");
        o.indata = (e.into_vec()).into();
        o
    }
    pub fn omap_get_keys(start_after: &[u8], max_return: u64) -> Self {
        let mut o = OsdOp::new(code::OMAP_GET_KEYS);
        let mut e = Encoder::new();
        e.bytes(start_after).and(e.u64(max_return)).expect("vec");
        o.indata = (e.into_vec()).into();
        o
    }
    pub fn omap_get_vals(start_after: &[u8], max_return: u64, filter_prefix: &[u8]) -> Self {
        let mut o = OsdOp::new(code::OMAP_GET_VALS);
        let mut e = Encoder::new();
        e.bytes(start_after)
            .and(e.u64(max_return))
            .and(e.bytes(filter_prefix))
            .expect("vec");
        o.indata = (e.into_vec()).into();
        o
    }
    pub fn omap_get_header() -> Self {
        OsdOp::new(code::OMAP_GET_HEADER)
    }
    pub fn omap_clear() -> Self {
        OsdOp::new(code::OMAP_CLEAR)
    }
    pub fn omap_set_header(h: Vec<u8>) -> Self {
        let mut o = OsdOp::new(code::OMAP_SET_HEADER);
        o.indata = (h).into();
        o
    }
    pub fn omap_set_vals(m: &std::collections::BTreeMap<Vec<u8>, Vec<u8>>) -> Self {
        let mut o = OsdOp::new(code::OMAP_SET_VALS);
        o.indata = (denc::Encode::encode_to_vec(m).expect("vec")).into();
        o
    }
    pub fn omap_rm_keys(keys: &std::collections::BTreeSet<Vec<u8>>) -> Self {
        let mut o = OsdOp::new(code::OMAP_RM_KEYS);
        o.indata = (denc::Encode::encode_to_vec(keys).expect("vec")).into();
        o
    }
    /// pgnls: count entries from `cursor` (hobject_t).
    pub fn pgnls(count: u64, cursor: &denc::types::Hobject) -> Self {
        let mut o = OsdOp::new(code::PGNLS);
        o.set_pgls(Pgls {
            count,
            start_epoch: 0,
        });
        o.indata = (denc::Encode::encode_to_vec(cursor).expect("vec")).into();
        o
    }
    /// PG hit-set listing. The result is returned in the operation's outdata.
    pub fn pg_hitset_ls() -> Self {
        OsdOp::new(code::PG_HITSET_LS)
    }
    /// PG hit-set lookup using the wire timestamp representation.
    pub fn pg_hitset_get(sec: u32, nsec: u32) -> Self {
        let mut o = OsdOp::new(code::PG_HITSET_GET);
        o.set_hit_set_get(HitSetGet { sec, nsec });
        o
    }
    /// PG scrub list. `get_snapsets` selects the result record type.
    pub fn scrub_ls(
        interval: u32,
        get_snapsets: bool,
        start_after_oid: &[u8],
        start_after_namespace: &[u8],
        start_after_snap: u64,
        max_return: u64,
    ) -> Self {
        let mut o = OsdOp::new(code::SCRUBLS);
        let mut e = Encoder::new();
        e.versioned(1, 1, |e| {
            e.u32(interval)?;
            e.u32(if get_snapsets { 1 } else { 0 })?;
            e.bytes(start_after_oid)?;
            e.bytes(start_after_namespace)?;
            e.u64(start_after_snap)?;
            e.u64(max_return)
        })
        .expect("vec");
        o.indata = e.into_vec().into();
        o
    }
}

#[cfg(test)]
mod pg_read_op_tests {
    use super::*;

    #[test]
    fn hit_set_ops_use_pinned_codes_and_timestamp_union() {
        assert_eq!(OsdOp::pg_hitset_ls().op, code::PG_HITSET_LS);
        let get = OsdOp::pg_hitset_get(0x1122_3344, 0x5566_7788);
        assert_eq!(get.op, code::PG_HITSET_GET);
        assert_eq!(
            get.hit_set_get(),
            HitSetGet {
                sec: 0x1122_3344,
                nsec: 0x5566_7788
            }
        );
        assert_eq!(
            &get.header_bytes(0)[6..14],
            &[0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55]
        );
    }

    #[test]
    fn scrub_list_arguments_distinguish_object_and_snapset_results() {
        let objects = OsdOp::scrub_ls(7, false, b"oid", b"ns", 9, 11);
        let snapsets = OsdOp::scrub_ls(7, true, b"oid", b"ns", 9, 11);
        assert_eq!(objects.op, code::SCRUBLS);
        // Version + compatible version + u32 body length form a six-byte envelope.
        assert_eq!(objects.indata[0..6], [1, 1, 37, 0, 0, 0]);
        assert_ne!(objects.indata, snapsets.indata);
        assert_eq!(objects.indata.len(), 6 + 37);
    }
}

/// Encode all op headers (payload_len from `data_len`) and return the concatenated data.
pub(crate) fn put_ops<B: BufMut>(e: &mut Encoder<B>, ops: &[OsdOp], reply: bool) -> Result<()> {
    for o in ops {
        let n = if reply {
            o.outdata_len()
        } else {
            o.indata_len()
        };
        e.raw(&o.header_bytes(u32::try_from(n).map_err(|_| Error::TooLong)?))?;
    }
    Ok(())
}

/// The per-op data (indata for requests, outdata with its further pieces for replies) as data segment pieces in order, by
/// reference, empty ones left out, each with its crc hint.
pub fn data_parts(ops: &[OsdOp], reply: bool) -> impl Iterator<Item = (&Bytes, &CrcHint)> {
    ops.iter()
        .flat_map(move |o| {
            let first = if reply {
                (&o.outdata, &o.outdata_crc)
            } else {
                (&o.indata, &o.indata_crc)
            };
            let more = if reply {
                &o.outdata_more[..]
            } else {
                &o.indata_more[..]
            };
            std::iter::once(first).chain(more.iter().map(|(b, h)| (b, h)))
        })
        .filter(|(b, _)| !b.is_empty())
}

/// Concatenate the per-op data (indata for requests, outdata with its further pieces for replies) into a data segment.
pub fn data_segment(ops: &[OsdOp], reply: bool) -> Bytes {
    let mut nz = data_parts(ops, reply);
    match (nz.next(), nz.next()) {
        (None, _) => return Bytes::new(),
        // a single non-empty piece (the 4 MiB write / read case): share it, no copy
        (Some((d, _)), None) => return d.clone(),
        _ => {}
    }
    let n: usize = data_parts(ops, reply).map(|(d, _)| d.len()).sum();
    let mut v = Vec::with_capacity(n);
    for (d, _) in data_parts(ops, reply) {
        v.extend_from_slice(d);
    }
    v.into()
}

/// Parse `n` op headers, slice `data` per `payload_len`, and return the consumed data length.
pub(crate) fn get_ops(
    d: &mut Decoder<'_>,
    n: usize,
    data: &Bytes,
    reply: bool,
) -> Result<(Vec<OsdOp>, usize)> {
    // every op header is OP_LEN bytes: a count beyond the front is malformed, never an allocation size
    if n > d.remaining() / OP_LEN {
        return Err(Error::BadLength {
            len: n as u64,
            remaining: d.remaining(),
        });
    }
    let mut ops = Vec::with_capacity(n.min(1024));
    let mut lens = Vec::with_capacity(n.min(1024));
    for _ in 0..n {
        let (o, l) = OsdOp::parse_header(d.take(OP_LEN)?)?;
        ops.push(o);
        lens.push(l as usize);
    }
    let total: usize = lens
        .iter()
        .try_fold(0usize, |a, l| a.checked_add(*l))
        .ok_or(Error::TooLong)?;
    if total > data.len() {
        return Err(Error::BadLength {
            len: total as u64,
            remaining: data.len(),
        });
    }
    let mut off = 0;
    for (o, l) in ops.iter_mut().zip(lens) {
        let s = data.slice(off..off + l);
        off += l;
        if reply {
            o.outdata = s;
        } else {
            o.indata = s;
        }
    }
    Ok((ops, total))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bytes_full_write_retains_visible_owner_and_encodes_exact_extent() {
        let bytes = Bytes::from_static(b"xxpayloadyy").slice(2..9);
        let pointer = bytes.as_ptr();
        let op = OsdOp::writefull_bytes(bytes);
        assert_eq!(op.indata.as_ptr(), pointer);
        assert_eq!((op.extent().offset, op.extent().length), (0, 7));
        let (header, len) = OsdOp::parse_header(&op.header_bytes(7)).unwrap();
        assert_eq!(
            (header.op, header.extent().length, len),
            (code::WRITEFULL, 7, 7)
        );
        let message = crate::MOSDOp {
            ops: vec![op],
            ..Default::default()
        };
        for version in [7, 8, 9] {
            let encoded = message.encode_version(version, 0).unwrap();
            assert_eq!(encoded.data.as_ptr(), pointer);
            assert_eq!(encoded.data.as_ref(), b"payload");
        }
    }

    fn piece(n: usize, s: u8) -> (Bytes, Option<u32>) {
        let b: Bytes = (0..n)
            .map(|i| (i as u8).wrapping_mul(13) ^ s)
            .collect::<Vec<u8>>()
            .into();
        let c = crc::crc32c(!0, &b);
        (b, Some(c))
    }

    /// A reply whose read output is in pieces encodes (by reference) to the same front and data segment as the flat
    /// reply, the pieces are not copied, and it decodes back to the flat output.
    #[test]
    fn reply_pieces_encode_by_reference_like_the_flat_reply() {
        use messages::Message;
        let pieces = vec![
            piece(70_000, 1),
            piece(0, 9),
            piece(5, 2),
            piece(300_000, 3),
        ];
        let mut op = OsdOp::new(code::READ);
        op.set_outdata_parts(pieces.clone());
        assert_eq!(op.outdata_len(), 300_005 + 70_000);
        assert_eq!(op.outdata_more.len(), 2, "empty piece skipped");
        let stat = OsdOp {
            outdata: Bytes::from_static(b"stat"),
            ..OsdOp::new(code::STAT)
        };
        let mut flat = op.clone();
        flat.flatten_outdata();
        let all: Vec<u8> = pieces.iter().flat_map(|(b, _)| b.iter().copied()).collect();
        assert_eq!(&flat.outdata[..], &all[..]);
        assert_eq!(
            flat.outdata_crc.of(&flat.outdata),
            Some(crc::crc32c(!0, &all)),
            "joined crc"
        );
        for ops in [vec![op.clone()], vec![stat.clone(), op.clone(), stat]] {
            let r = crate::MOSDOpReply {
                ops: ops.clone(),
                ..Default::default()
            };
            let rf = crate::MOSDOpReply {
                ops: ops
                    .into_iter()
                    .map(|mut o| {
                        o.flatten_outdata();
                        o
                    })
                    .collect(),
                ..Default::default()
            };
            let want = rf.encode(0).unwrap();
            let (segs, hint, more) = r.encode_parts(0).unwrap();
            assert_eq!(segs.front, want.front);
            let mut data = segs.data.to_vec();
            more.iter().for_each(|(b, _)| data.extend_from_slice(b));
            assert_eq!(&data[..], &want.data[..]);
            assert_eq!(
                r.encode(0).unwrap().data,
                want.data,
                "plain encode flattens"
            );
            // the read pieces travel by reference with their hints
            for (b, c) in pieces.iter().filter(|(b, _)| !b.is_empty()) {
                let (x, h) = std::iter::once((&segs.data, &hint))
                    .chain(more.iter().map(|(b, h)| (b, h)))
                    .find(|(x, _)| x.as_ptr() == b.as_ptr())
                    .expect("piece copied");
                assert_eq!(h.of(x), *c);
            }
            let back = crate::MOSDOpReply::decode(8, &want.front, &[], &want.data).unwrap();
            assert_eq!(
                back.ops.iter().map(OsdOp::outdata_len).sum::<usize>(),
                want.data.len()
            );
        }
        let mut c = op;
        c.clear_outdata();
        assert_eq!((c.outdata_len(), c.outdata_more.len()), (0, 0));
    }
}
