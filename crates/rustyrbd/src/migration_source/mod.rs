// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Import-only migration source codecs: `raw` and `qcow` (v1, v2, v3) over
//! the `file` stream.
//!
//! Spec: `doc/spec/rustyrbd/migration-source-raw-qcow-file.md`.
//!
//! The codec is read-only: [`Source::open`] builds and opens every revision
//! stream and parses all metadata, so every structural failure is a
//! prepare-time [`OpenError`] (a negative Linux errno); [`Source::read`] and
//! [`Source::list_snaps`] answer the execute-time queries, their failures
//! plain negative errnos. `http`, `s3` and `nbd` streams plug into the same
//! [`SourceStream`] interface (WP-10b, WP-10c); `file` is the only
//! implementation in this step.

mod file;
pub mod nbd;
pub mod nbd_uri;
mod qcow;
mod raw;
mod spec;

use rand::Rng;
use serde_json::Value;

use crate::snapshot_query::SnapshotNamespace;

/// The pinned Linux errnos this module reports; they are the wire-visible
/// values of `doc/spec/rustyrbd/migration-source-raw-qcow-file.md`.
pub use crate::journal_backend::{EBADMSG, EINVAL, ENOENT, ERANGE};
pub use file::FileStream;
pub use spec::canonical_json;

/// `CEPH_NOSNAP` (2^64-1): the HEAD revision.
pub const CEPH_NOSNAP: u64 = u64::MAX;

/// `ENOSYS`: a `native` dispatch, a stream type this build does not
/// implement (`http`, `s3`, `nbd` before WP-10b/WP-10c) or an unknown one.
pub const ENOSYS: i32 = -38;

/// `ENOTSUP`: a qcow backing file, an external data file, an extended L2
/// entry, or a v1 container in a build without v1 support. Same value as
/// `EOPNOTSUPP` on Linux.
pub const ENOTSUP: i32 = -95;

/// `ENOMEM`: a buffer sized by the caller or by the container header
/// cannot be allocated.
pub const ENOMEM: i32 = -12;

/// A prepare-time (open) failure: a negative Linux errno the caller maps to
/// the destination prepare result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenError(pub i32);

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "source open failed: errno {}", self.0)
    }
}

impl std::error::Error for OpenError {}

/// A snapshot timestamp from the source header; zero for `raw` revisions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SourceTimestamp {
    /// `date_sec` of the qcow snapshot header.
    pub sec: u32,
    /// `date_nsec` of the qcow snapshot header.
    pub nsec: u32,
}

/// One source snapshot; ids run 1..N in spec/header order, HEAD excluded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceSnapshot {
    /// External id, 1..N.
    pub id: u64,
    /// The name (a random UUID when the source gives none).
    pub name: String,
    /// The revision size in bytes.
    pub size: u64,
    /// Always the user namespace.
    pub namespace: SnapshotNamespace,
    /// Header timestamp (zero for `raw`).
    pub timestamp: SourceTimestamp,
}

/// The kind of one sparse-delta interval.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SourceDeltaKind {
    /// Bytes to copy from the revision.
    Data,
    /// Bytes to write as zeroes.
    Zeroed,
}

/// One interval of a per-revision sparse delta, within the requested image
/// extents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceDeltaExtent {
    /// Image offset of the interval start.
    pub offset: u64,
    /// Interval length in bytes.
    pub length: u64,
    /// Data or zeroes.
    pub kind: SourceDeltaKind,
}

/// The sparse delta of one requested revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevisionDelta {
    /// The requested snap id ([`CEPH_NOSNAP`] for HEAD).
    pub snap_id: u64,
    /// The delta intervals, offset ascending.
    pub extents: Vec<SourceDeltaExtent>,
}

/// A read-only byte stream behind one source revision.
///
/// Implementations are opened exactly once and report negative Linux errnos;
/// a short read or EOF is always `-ERANGE`. Streams are shared read-only by
/// every view of one import destination, so they are `Send + Sync`; `read`
/// takes `&self` and each extent is an independent positional read.
pub trait SourceStream: std::fmt::Debug + Send + Sync {
    /// Establish the stream; `-errno` on failure.
    fn open(&mut self) -> Result<(), i32>;

    /// The stream size in bytes (`SEEK_END`); `-errno` on failure.
    fn size(&mut self) -> Result<u64, i32>;

    /// Read `extents` (offset, length) in list order into `out`, whose
    /// length must equal the sum of the extent lengths. A short read or EOF
    /// at any point clears `out` and is `-ERANGE`; any other read error is
    /// `-errno` (`-EIO`, `-EISDIR`, ...). A zero-length extent is a no-op.
    fn read(&self, extents: &[(u64, u64)], out: &mut [u8]) -> Result<(), i32>;

    /// Release the stream; always 0.
    fn close(&mut self) -> i32;
}

/// Build the stream of one revision spec object. `-EINVAL` when its
/// `stream` key is missing or not an object, the stream `type` is absent or
/// not a string, or a `file` stream has no string `file_path`; `-ENOSYS`
/// for `http`, `s3`, `nbd` and unknown types.
pub fn build_stream(revision: &Value) -> Result<Box<dyn SourceStream>, i32> {
    let stream = revision.get("stream").ok_or(EINVAL)?;
    if !stream.is_object() {
        return Err(EINVAL);
    }
    let ty = stream.get("type").and_then(Value::as_str).ok_or(EINVAL)?;
    match ty {
        "file" => {
            let path = stream
                .get("file_path")
                .and_then(Value::as_str)
                .ok_or(EINVAL)?;
            Ok(Box::new(file::FileStream::new(path)))
        }
        _ => Err(ENOSYS),
    }
}

#[derive(Debug)]
enum Kind {
    Raw(raw::RawSource),
    Qcow(qcow::QcowSource),
}

/// An opened import source: the HEAD revision plus its snapshots,
/// read-only.
#[derive(Debug)]
pub struct Source {
    kind: Kind,
}

impl Source {
    /// Build and open every revision stream and parse all metadata from the
    /// source spec. Every structural failure is a prepare error.
    pub fn open(spec: &str) -> Result<Self, OpenError> {
        let root = spec::parse_root(spec).map_err(OpenError)?;
        let ty = root
            .get("type")
            .and_then(Value::as_str)
            .ok_or(OpenError(EINVAL))?;
        let kind = match ty {
            "raw" => raw::RawSource::open(&root).map(Kind::Raw),
            "qcow" => qcow::QcowSource::open(&root).map(Kind::Qcow),
            _ => Err(ENOSYS),
        }
        .map_err(OpenError)?;
        Ok(Self { kind })
    }

    /// The snapshots, ids ascending; HEAD is not a snapshot.
    pub fn snapshots(&self) -> Vec<SourceSnapshot> {
        match &self.kind {
            Kind::Raw(raw) => raw.snapshots(),
            Kind::Qcow(qcow) => qcow.snapshots(),
        }
    }

    /// The size in bytes of one revision; `-ENOENT` for an unknown id.
    pub fn image_size(&self, snap_id: u64) -> Result<u64, i32> {
        match &self.kind {
            Kind::Raw(raw) => raw.image_size(snap_id),
            Kind::Qcow(qcow) => qcow.image_size(snap_id),
        }
    }

    /// Read image extents of one revision; the bytes are concatenated in
    /// extent order. Reads are not clamped to the revision size.
    /// `-ENOENT` for an unknown id.
    pub fn read(&self, snap_id: u64, extents: &[(u64, u64)]) -> Result<Vec<u8>, i32> {
        match &self.kind {
            Kind::Raw(raw) => raw.read(snap_id, extents),
            Kind::Qcow(qcow) => qcow.read(snap_id, extents),
        }
    }

    /// The per-revision sparse deltas of the requested ids over the
    /// requested image extents, ids ascending with HEAD last. Each
    /// requested revision is compared with the previous requested one
    /// (the empty baseline for the first). `-ENOENT` for an unknown
    /// requested id.
    pub fn list_snaps(
        &self,
        extents: &[(u64, u64)],
        snap_ids: &[u64],
    ) -> Result<Vec<RevisionDelta>, i32> {
        match &self.kind {
            Kind::Raw(raw) => raw.list_snaps(extents, snap_ids),
            Kind::Qcow(qcow) => qcow.list_snaps(extents, snap_ids),
        }
    }

    /// Close every revision stream; always 0.
    pub fn close(&mut self) -> i32 {
        match &mut self.kind {
            Kind::Raw(raw) => raw.close(),
            Kind::Qcow(qcow) => qcow.close(),
        }
    }
}

impl Drop for Source {
    fn drop(&mut self) {
        self.close();
    }
}

/// The total length of the extents in bytes; `-EINVAL` on overflow.
pub(crate) fn extent_total(extents: &[(u64, u64)]) -> Result<usize, i32> {
    let total = extents
        .iter()
        .try_fold(0u64, |sum, &(_, len)| sum.checked_add(len))
        .ok_or(EINVAL)?;
    usize::try_from(total).map_err(|_| EINVAL)
}

/// A zero-filled byte buffer for reads sized by the caller or by the
/// container header; `-ENOMEM` when the allocation fails.
pub(crate) fn zero_buffer(length: usize) -> Result<Vec<u8>, i32> {
    let mut out = Vec::new();
    out.try_reserve_exact(length).map_err(|_| ENOMEM)?;
    out.resize(length, 0);
    Ok(out)
}

/// Merge intervals into sorted, disjoint ones.
pub(crate) fn merge_intervals(intervals: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut sorted: Vec<(u64, u64)> = intervals
        .iter()
        .copied()
        .filter(|&(start, end)| start < end)
        .collect();
    sorted.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(sorted.len());
    for (start, end) in sorted {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// Intersect two sorted, disjoint interval lists.
pub(crate) fn intersect(intervals: &[(u64, u64)], region: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < intervals.len() && j < region.len() {
        let (i_start, i_end) = intervals[i];
        let (r_start, r_end) = region[j];
        let start = i_start.max(r_start);
        let end = i_end.min(r_end);
        if start < end {
            out.push((start, end));
        }
        if i_end < r_end {
            i += 1;
        } else {
            j += 1;
        }
    }
    out
}

/// Coalesce two disjoint interval lists into delta extents, offset
/// ascending (data before zeroes at one offset).
pub(crate) fn delta_extents(data: &[(u64, u64)], zeroed: &[(u64, u64)]) -> Vec<SourceDeltaExtent> {
    let mut extents: Vec<SourceDeltaExtent> = data
        .iter()
        .map(|&(start, end)| SourceDeltaExtent {
            offset: start,
            length: end - start,
            kind: SourceDeltaKind::Data,
        })
        .chain(zeroed.iter().map(|&(start, end)| SourceDeltaExtent {
            offset: start,
            length: end - start,
            kind: SourceDeltaKind::Zeroed,
        }))
        .collect();
    extents.sort_by(|a, b| a.offset.cmp(&b.offset).then(a.kind.cmp(&b.kind)));
    extents
}

/// The chain positions of the requested ids; `-ENOENT` for an unknown id.
/// Duplicates collapse; the result is ascending.
pub(crate) fn requested_positions(chain_ids: &[u64], ids: &[u64]) -> Result<Vec<usize>, i32> {
    let mut positions = Vec::with_capacity(ids.len());
    for id in ids {
        let pos = chain_ids
            .iter()
            .position(|chain_id| chain_id == id)
            .ok_or(ENOENT)?;
        if !positions.contains(&pos) {
            positions.push(pos);
        }
    }
    positions.sort_unstable();
    Ok(positions)
}

/// A random UUID string (lowercase 8-4-4-4-12 hex), stable only within one
/// prepare.
pub(crate) fn uuid_string() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    let hex = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal_backend::{EBADMSG, EIO, ERANGE};

    /// The opened source is shared read-only by every view of one import
    /// destination (it lives inside an `ImageHandle`).
    #[test]
    fn source_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Source>();
    }

    #[test]
    fn pinned_errnos_and_uuid_shape_are_stable() {
        assert_eq!(CEPH_NOSNAP, u64::MAX);
        assert_eq!(ENOSYS, -38);
        assert_eq!(ENOTSUP, -95);
        // The shared constants come from the journal backend's pinned values.
        assert_eq!(EBADMSG, -74);
        assert_eq!(EIO, -5);
        assert_eq!(EINVAL, -22);
        assert_eq!(ENOENT, -2);
        assert_eq!(ERANGE, -34);
        // uuid_string shape: 36 chars, 8-4-4-4-12 lowercase hex.
        for _ in 0..8 {
            let uuid = uuid_string();
            assert_eq!(uuid.len(), 36);
            assert_eq!(
                uuid.split('-').map(str::len).collect::<Vec<_>>(),
                vec![8, 4, 4, 4, 12]
            );
            assert!(
                uuid.chars()
                    .all(|c| c == '-' || (c.is_ascii_hexdigit() && !c.is_ascii_uppercase()))
            );
        }
    }

    /// Assert that `Source::open` fails with exactly `errno`.
    fn assert_open_errno(spec: &str, errno: i32) {
        let OpenError(actual) = Source::open(spec).expect_err("open must fail");
        assert_eq!(actual, errno, "spec: {spec}");
    }

    #[test]
    fn open_dispatch_type_errors() {
        for (spec, errno) in [
            ("{}", EINVAL),
            (r#"{"type":5}"#, EINVAL),
            (
                r#"{"type":"native","stream":{"type":"file","file_path":"/dev/null"}}"#,
                ENOSYS,
            ),
            (
                r#"{"type":"qcow2","stream":{"type":"file","file_path":"/dev/null"}}"#,
                ENOSYS,
            ),
            (r#"{"type":"http"}"#, ENOSYS),
        ] {
            assert_open_errno(spec, errno);
        }
    }

    #[test]
    fn stream_type_errors() {
        for (stream, errno) in [
            (r#"5"#, EINVAL),
            (r#"{"file_path":"x"}"#, EINVAL),
            (r#"{"type":5}"#, EINVAL),
            (r#"{"type":"http"}"#, ENOSYS),
            (r#"{"type":"s3"}"#, ENOSYS),
            (r#"{"type":"nbd"}"#, ENOSYS),
            (r#"{"type":"ftp"}"#, ENOSYS),
        ] {
            let spec = format!(r#"{{"type":"raw","stream":{stream}}}"#);
            assert_open_errno(&spec, errno);
        }
        let missing = r#"{"type":"raw"}"#;
        assert_open_errno(missing, EINVAL);
        let bad_file_path = r#"{"type":"raw","stream":{"type":"file","file_path":5}}"#;
        assert_open_errno(bad_file_path, EINVAL);
        let no_file_path = r#"{"type":"raw","stream":{"type":"file"}}"#;
        assert_open_errno(no_file_path, EINVAL);
    }

    #[test]
    fn file_path_is_used_verbatim() {
        // No normalisation: a `file://` value is a relative path named
        // `file:` followed by `/x`, so the open fails with the filesystem
        // errno (-ENOENT), not a spec parse error.
        let spec = r#"{"type":"raw","stream":{"type":"file","file_path":"file:///x"}}"#;
        assert_open_errno(spec, ENOENT);
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    //! Shared helpers for the codec unit tests: unique temp dirs and qcow
    //! byte builders (the spec's vectors build the bytes themselves).

    use std::path::PathBuf;

    /// A unique temp dir for one test, removed on drop.
    pub struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    impl AsRef<std::path::Path> for TempDir {
        fn as_ref(&self) -> &std::path::Path {
            &self.0
        }
    }

    /// Create a unique temp dir for one test, removed on drop.
    pub fn temp_dir(name: &str) -> TempDir {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rustyrbd-migration-source-{name}-{n}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("temp dir");
        TempDir(path)
    }

    /// Write one file below the dir; returns its path as a string.
    pub fn write(dir: &TempDir, name: &str, bytes: &[u8]) -> String {
        let path = dir.0.join(name);
        std::fs::write(&path, bytes).expect("test file");
        path.to_str().expect("utf-8 path").to_owned()
    }

    pub fn be16_at(buf: &mut [u8], offset: usize, value: u16) {
        buf[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
    }

    pub fn be32_at(buf: &mut [u8], offset: usize, value: u32) {
        buf[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    pub fn be64_at(buf: &mut [u8], offset: usize, value: u64) {
        buf[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    }

    /// Spec vector 4: a 2048-byte qcow2 file, `cluster_bits` 9, `size`
    /// 4096, `l1_size` 1, L1 at 512 -> L2 at 1024, L2 entry 0 = 1536,
    /// entry 1 = 1 (zero flag), data cluster at 1536 = 512 x `0x5a`.
    pub fn qcow2_minimal() -> Vec<u8> {
        let mut file = vec![0u8; 2048];
        be32_at(&mut file, 0, 0x5146_49fb);
        be32_at(&mut file, 4, 2);
        be32_at(&mut file, 20, 9);
        be64_at(&mut file, 24, 4096);
        be32_at(&mut file, 36, 1);
        be64_at(&mut file, 40, 512);
        be64_at(&mut file, 512, 1024);
        be64_at(&mut file, 1024, 1536);
        be64_at(&mut file, 1032, 1);
        file[1536..2048].fill(0x5a);
        file
    }
}
