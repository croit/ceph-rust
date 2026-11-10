// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Format `raw`: each revision is an independent byte stream (a thick
//! export).
//!
//! Spec: `doc/spec/rustyrbd/migration-source-raw-qcow-file.md`, "Format
//! `raw`". HEAD is the top-level stream; each `snapshots` entry is one older
//! revision with ids 1..N in array order. Revisions open in ascending id
//! order; the first failure closes the opened ones and returns its errno.

use serde_json::Value;

use crate::journal_backend::{EINVAL, ENOENT};
use crate::migration_source::{
    CEPH_NOSNAP, ENOSYS, RevisionDelta, SourceSnapshot, SourceStream, SourceTimestamp,
    build_stream, delta_extents, extent_total, intersect, merge_intervals, requested_positions,
    uuid_string, zero_buffer,
};
use crate::snapshot_query::SnapshotNamespace;

#[derive(Debug)]
struct Revision {
    id: u64,
    name: String,
    size: u64,
    stream: Box<dyn SourceStream>,
}

#[derive(Debug)]
pub(crate) struct RawSource {
    head: Revision,
    snaps: Vec<Revision>,
}

impl RawSource {
    /// Open order: build the HEAD revision (re-checking its `type`), walk
    /// `snapshots`, then open all revisions in ascending id order.
    pub(crate) fn open(root: &Value) -> Result<Self, i32> {
        let ty = root.get("type").and_then(Value::as_str).ok_or(EINVAL)?;
        if ty != "raw" {
            return Err(ENOSYS);
        }
        let mut entries: Vec<&Value> = Vec::new();
        match root.get("snapshots") {
            None | Some(Value::Null) => {}
            Some(Value::Array(items)) => {
                for item in items {
                    let item_ty = item.get("type").and_then(Value::as_str).ok_or(EINVAL)?;
                    if item_ty != "raw" {
                        return Err(ENOSYS);
                    }
                    entries.push(item);
                }
            }
            Some(_) => return Err(EINVAL),
        }

        let mut snaps: Vec<Revision> = Vec::new();
        for (id, entry) in entries.iter().enumerate().map(|(i, entry)| (i + 1, *entry)) {
            match open_revision(id as u64, entry) {
                Ok(revision) => snaps.push(revision),
                Err(errno) => return Err(close_revisions(&mut snaps, errno)),
            }
        }
        let head = match open_revision(CEPH_NOSNAP, root) {
            Ok(revision) => revision,
            Err(errno) => return Err(close_revisions(&mut snaps, errno)),
        };
        Ok(Self { head, snaps })
    }

    pub(crate) fn snapshots(&self) -> Vec<SourceSnapshot> {
        self.snaps
            .iter()
            .map(|revision| SourceSnapshot {
                id: revision.id,
                name: revision.name.clone(),
                size: revision.size,
                namespace: SnapshotNamespace::User,
                timestamp: SourceTimestamp::default(),
            })
            .collect()
    }

    fn revision(&self, snap_id: u64) -> Option<&Revision> {
        if snap_id == CEPH_NOSNAP {
            Some(&self.head)
        } else {
            self.snaps.iter().find(|revision| revision.id == snap_id)
        }
    }

    pub(crate) fn image_size(&self, snap_id: u64) -> Result<u64, i32> {
        self.revision(snap_id)
            .map(|revision| revision.size)
            .ok_or(ENOENT)
    }

    /// Every image extent maps 1:1 to a stream byte extent at the same
    /// offset; a request past the stream end surfaces the stream error.
    pub(crate) fn read(&self, snap_id: u64, extents: &[(u64, u64)]) -> Result<Vec<u8>, i32> {
        let revision = self.revision(snap_id).ok_or(ENOENT)?;
        let total = extent_total(extents)?;
        let mut out = zero_buffer(total)?;
        revision.stream.read(extents, &mut out)?;
        Ok(out)
    }

    /// Each requested revision is compared with the previous requested
    /// one (the empty baseline for the first): the tail between the
    /// previous size and its own is ZEROED and the rest of the requested
    /// region is DATA.
    pub(crate) fn list_snaps(
        &self,
        extents: &[(u64, u64)],
        snap_ids: &[u64],
    ) -> Result<Vec<RevisionDelta>, i32> {
        let region = merge_intervals(extents);
        if region.is_empty() {
            return Ok(Vec::new());
        }
        let mut chain_ids: Vec<u64> = self.snaps.iter().map(|revision| revision.id).collect();
        chain_ids.push(CEPH_NOSNAP);
        let positions = requested_positions(&chain_ids, snap_ids)?;
        let mut deltas = Vec::with_capacity(positions.len());
        for (k, &pos) in positions.iter().enumerate() {
            let size = self.size_at(pos);
            let data = intersect(&merge_intervals(&[(0, size)]), &region);
            // The shrink tail is relative to the previous requested
            // revision.
            let mut zeroed: Vec<(u64, u64)> = Vec::new();
            if k > 0 {
                let prev_size = self.size_at(positions[k - 1]);
                if size < prev_size {
                    zeroed = intersect(&[(size, prev_size)], &region);
                }
            }
            deltas.push(RevisionDelta {
                snap_id: chain_ids[pos],
                extents: delta_extents(&data, &zeroed),
            });
        }
        Ok(deltas)
    }

    fn size_at(&self, index: usize) -> u64 {
        if index < self.snaps.len() {
            self.snaps[index].size
        } else {
            self.head.size
        }
    }

    pub(crate) fn close(&mut self) -> i32 {
        self.head.stream.close();
        for revision in &mut self.snaps {
            revision.stream.close();
        }
        0
    }
}

/// One revision in open order: name check, build `stream`, open it, read
/// its size. HEAD never reads the `name` key.
fn open_revision(id: u64, entry: &Value) -> Result<Revision, i32> {
    let name = if id == CEPH_NOSNAP {
        String::new()
    } else {
        match entry.get("name") {
            None | Some(Value::Null) => uuid_string(),
            Some(Value::String(name)) => name.clone(),
            Some(_) => return Err(EINVAL),
        }
    };
    let mut stream = build_stream(entry)?;
    stream.open()?;
    let size = stream.size()?;
    Ok(Revision {
        id,
        name,
        size,
        stream,
    })
}

fn close_revisions(revisions: &mut [Revision], errno: i32) -> i32 {
    for revision in revisions.iter_mut() {
        revision.stream.close();
    }
    errno
}

#[cfg(test)]
mod tests {
    use crate::journal_backend::{EINVAL, ENOENT};
    use crate::migration_source::{
        CEPH_NOSNAP, ENOSYS, OpenError, RevisionDelta, Source, SourceDeltaExtent, SourceDeltaKind,
        SourceSnapshot, SourceTimestamp, testutil,
    };
    use crate::snapshot_query::SnapshotNamespace;

    /// Assert that `Source::open` fails with exactly `errno`.
    fn assert_open_errno(spec: &str, errno: i32) {
        let OpenError(actual) = Source::open(spec).expect_err("open must fail");
        assert_eq!(actual, errno, "spec: {spec}");
    }

    fn spec(head: &str, snaps: &[&str]) -> String {
        let entries: Vec<String> = snaps
            .iter()
            .enumerate()
            .map(|(i, path)| {
                format!(
                    r#"{{"type":"raw","name":"snap{}","stream":{{"type":"file","file_path":"{path}"}}}}"#,
                    i + 1
                )
            })
            .collect();
        format!(
            r#"{{"type":"raw","stream":{{"type":"file","file_path":"{head}"}},"snapshots":[{}]}}"#,
            entries.join(",")
        )
    }

    /// Spec vector 1: HEAD 1024 x 0x48, snap1 512 x 0x41, snap2 2048 x 0x42.
    fn three_revisions() -> (testutil::TempDir, String, Vec<Vec<u8>>) {
        let dir = testutil::temp_dir("raw-three");
        let head = testutil::write(&dir, "head.bin", vec![0x48; 1024].as_slice());
        let s1 = testutil::write(&dir, "s1.bin", vec![0x41; 512].as_slice());
        let s2 = testutil::write(&dir, "s2.bin", vec![0x42; 2048].as_slice());
        let json = spec(&head, &[&s1, &s2]);
        (
            dir,
            json,
            vec![vec![0x48; 1024], vec![0x41; 512], vec![0x42; 2048]],
        )
    }

    #[test]
    fn raw_three_revisions() {
        let (_dir, json, originals) = three_revisions();
        let mut source = Source::open(&json).expect("prepare");
        assert_eq!(source.image_size(CEPH_NOSNAP), Ok(1024));
        let snaps = source.snapshots();
        assert_eq!(
            snaps,
            vec![
                SourceSnapshot {
                    id: 1,
                    name: "snap1".into(),
                    size: 512,
                    namespace: SnapshotNamespace::User,
                    timestamp: SourceTimestamp::default(),
                },
                SourceSnapshot {
                    id: 2,
                    name: "snap2".into(),
                    size: 2048,
                    namespace: SnapshotNamespace::User,
                    timestamp: SourceTimestamp::default(),
                },
            ]
        );
        assert_eq!(source.image_size(1), Ok(512));
        assert_eq!(source.image_size(2), Ok(2048));
        assert_eq!(source.read(CEPH_NOSNAP, &[(0, 1024)]), Ok(vec![0x48; 1024]));
        assert_eq!(source.read(1, &[(0, 512)]), Ok(vec![0x41; 512]));
        assert_eq!(source.read(2, &[(100, 1948)]), Ok(vec![0x42; 1948]));
        // Per-revision sparse delta over the full requested region.
        let deltas = source
            .list_snaps(&[(0, 2048)], &[1, 2, CEPH_NOSNAP])
            .expect("list_snaps");
        assert_eq!(
            deltas,
            vec![
                RevisionDelta {
                    snap_id: 1,
                    extents: vec![extent(0, 512, SourceDeltaKind::Data)],
                },
                RevisionDelta {
                    snap_id: 2,
                    extents: vec![extent(0, 2048, SourceDeltaKind::Data)],
                },
                RevisionDelta {
                    snap_id: CEPH_NOSNAP,
                    extents: vec![
                        extent(0, 1024, SourceDeltaKind::Data),
                        extent(1024, 1024, SourceDeltaKind::Zeroed),
                    ],
                },
            ]
        );
        source.close();
        // Abort (close) leaves the source files untouched.
        for (name, original) in ["head.bin", "s1.bin", "s2.bin"].iter().zip(originals) {
            let dir_path = _dir.as_ref().join(name);
            assert_eq!(std::fs::read(&dir_path).expect("source file"), original);
        }
    }

    fn extent(offset: u64, length: u64, kind: SourceDeltaKind) -> SourceDeltaExtent {
        SourceDeltaExtent {
            offset,
            length,
            kind,
        }
    }

    #[test]
    fn raw_unrequested_revisions_merge_into_the_next_requested() {
        let (_dir, json, _originals) = three_revisions();
        let source = Source::open(&json).expect("prepare");
        // Only HEAD requested: the deltas of snaps 1 and 2 merge into it,
        // clipped to the HEAD size of 1024.
        let deltas = source
            .list_snaps(&[(0, 2048)], &[CEPH_NOSNAP])
            .expect("list_snaps");
        assert_eq!(
            deltas,
            vec![RevisionDelta {
                snap_id: CEPH_NOSNAP,
                extents: vec![extent(0, 1024, SourceDeltaKind::Data)],
            }]
        );
        // Only snap2 requested: snap1's delta merges into it.
        let deltas = source.list_snaps(&[(0, 2048)], &[2]).expect("list_snaps");
        assert_eq!(
            deltas,
            vec![RevisionDelta {
                snap_id: 2,
                extents: vec![extent(0, 2048, SourceDeltaKind::Data)],
            }]
        );
    }

    #[test]
    fn raw_uuid_name_for_absent_name() {
        // Spec vector 2: an entry without `name` gets a 36-character
        // lowercase UUID, stable for that prepare only.
        let dir = testutil::temp_dir("raw-uuid");
        let head = testutil::write(&dir, "head.bin", &[0u8; 512]);
        let s1 = testutil::write(&dir, "s1.bin", &[0u8; 512]);
        let json = format!(
            r#"{{"type":"raw","stream":{{"type":"file","file_path":"{head}"}},"snapshots":[{{"type":"raw","stream":{{"type":"file","file_path":"{s1}"}}}}]}}"#
        );
        let source = Source::open(&json).expect("prepare");
        let name = source.snapshots().remove(0).name;
        assert_eq!(
            name.split('-').map(str::len).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(
            name.chars()
                .all(|c| c == '-' || (c.is_ascii_hexdigit() && !c.is_ascii_uppercase()))
        );
        // A second prepare generates a different name.
        drop(source);
        let again = Source::open(&json).expect("second prepare");
        assert_ne!(again.snapshots()[0].name, name);
    }

    #[test]
    fn raw_rejects_invalid_spec_shapes() {
        // Spec vector 3, all at prepare.
        let dir = testutil::temp_dir("raw-rejects");
        let head = testutil::write(&dir, "head.bin", &[0u8; 512]);
        let head_stream = format!(r#"{{"type":"file","file_path":"{head}"}}"#);
        let cases: [(String, i32); 6] = [
            (
                format!(r#"{{"type":"raw","stream":{head_stream},"snapshots":{{}}}}"#),
                EINVAL,
            ),
            (
                format!(r#"{{"type":"raw","stream":{head_stream},"snapshots":[5]}}"#),
                EINVAL,
            ),
            (
                format!(
                    r#"{{"type":"raw","stream":{head_stream},"snapshots":[{{"name":"a","stream":{head_stream}}}]}}"#
                ),
                EINVAL,
            ),
            (
                format!(
                    r#"{{"type":"raw","stream":{head_stream},"snapshots":[{{"type":"qcow","name":"a","stream":{head_stream}}}]}}"#
                ),
                ENOSYS,
            ),
            (
                format!(
                    r#"{{"type":"raw","stream":{head_stream},"snapshots":[{{"type":"raw","name":7,"stream":{head_stream}}}]}}"#
                ),
                EINVAL,
            ),
            (
                format!(
                    r#"{{"type":"raw","stream":{head_stream},"snapshots":[{{"type":"raw","name":"a"}}]}}"#
                ),
                EINVAL,
            ),
        ];
        for (json, errno) in cases {
            assert_open_errno(&json, errno);
        }
    }

    #[test]
    fn raw_snapshots_null_and_absent_are_the_same() {
        let dir = testutil::temp_dir("raw-null-snaps");
        let head = testutil::write(&dir, "head.bin", &[9u8; 64]);
        for snaps in [r#""snapshots":null"#, r#""snapshots":[]"#] {
            let json = format!(
                r#"{{"type":"raw","stream":{{"type":"file","file_path":"{head}"}},{snaps}}}"#
            );
            let source = Source::open(&json).expect("prepare");
            assert!(source.snapshots().is_empty());
            assert_eq!(source.image_size(CEPH_NOSNAP), Ok(64));
        }
    }

    #[test]
    fn raw_empty_name_is_used_verbatim() {
        let dir = testutil::temp_dir("raw-empty-name");
        let head = testutil::write(&dir, "head.bin", &[0u8; 512]);
        let s1 = testutil::write(&dir, "s1.bin", &[0u8; 512]);
        let json = format!(
            r#"{{"type":"raw","stream":{{"type":"file","file_path":"{head}"}},"snapshots":[{{"type":"raw","name":"","stream":{{"type":"file","file_path":"{s1}"}}}}]}}"#
        );
        let source = Source::open(&json).expect("prepare");
        assert_eq!(source.snapshots()[0].name, "");
    }

    #[test]
    fn raw_head_name_is_never_read() {
        // A top-level `name` of any type is ignored for HEAD.
        let dir = testutil::temp_dir("raw-head-name");
        let head = testutil::write(&dir, "head.bin", &[0u8; 512]);
        for name in [r#""name":7"#, r#""name":"x""#, r#""name":null"#] {
            let json = format!(
                r#"{{"type":"raw",{name},"stream":{{"type":"file","file_path":"{head}"}}}}"#
            );
            assert!(Source::open(&json).is_ok(), "{json}");
        }
    }

    #[test]
    fn raw_read_past_stream_end_is_erange() {
        let dir = testutil::temp_dir("raw-past-end");
        let head = testutil::write(&dir, "head.bin", &[0u8; 100]);
        let json = format!(r#"{{"type":"raw","stream":{{"type":"file","file_path":"{head}"}}}}"#);
        let source = Source::open(&json).expect("prepare");
        assert_eq!(source.read(CEPH_NOSNAP, &[(100, 1)]), Err(-34));
        assert_eq!(source.read(CEPH_NOSNAP, &[(99, 2)]), Err(-34));
        // A zero-length read at EOF succeeds.
        assert_eq!(source.read(CEPH_NOSNAP, &[(100, 0)]), Ok(Vec::new()));
        assert_eq!(source.read(CEPH_NOSNAP, &[]), Ok(Vec::new()));
    }

    #[test]
    fn raw_unknown_snap_id_is_enoent() {
        let dir = testutil::temp_dir("raw-unknown-id");
        let head = testutil::write(&dir, "head.bin", &[0u8; 512]);
        let json = format!(r#"{{"type":"raw","stream":{{"type":"file","file_path":"{head}"}}}}"#);
        let source = Source::open(&json).expect("prepare");
        assert_eq!(source.image_size(7), Err(-2));
        assert_eq!(source.read(7, &[(0, 1)]), Err(-2));
        assert_eq!(source.list_snaps(&[(0, 1)], &[7]), Err(-2));
    }

    #[test]
    fn raw_first_failing_open_closes_the_others() {
        // snap1 opens fine, snap2's file is missing: the error is the
        // missing file and snap1's stream is closed.
        let dir = testutil::temp_dir("raw-fail-open");
        let head = testutil::write(&dir, "head.bin", &[0u8; 512]);
        let s1 = testutil::write(&dir, "s1.bin", &[0u8; 512]);
        let json = format!(
            r#"{{"type":"raw","stream":{{"type":"file","file_path":"{head}"}},"snapshots":[{{"type":"raw","name":"a","stream":{{"type":"file","file_path":"{s1}"}}}},{{"type":"raw","name":"b","stream":{{"type":"file","file_path":"{}absent"}}}}]}}"#,
            dir.as_ref().display()
        );
        assert_open_errno(&json, ENOENT);
    }

    #[test]
    fn raw_list_snaps_empty_region_and_empty_ids() {
        let (_dir, json, _originals) = three_revisions();
        let source = Source::open(&json).expect("prepare");
        assert_eq!(source.list_snaps(&[], &[1]).expect("no region"), Vec::new());
        assert_eq!(
            source.list_snaps(&[(0, 100)], &[]).expect("no ids"),
            Vec::new()
        );
    }

    #[test]
    fn raw_read_huge_extent_total_is_enomem() {
        let dir = testutil::temp_dir("raw-enomem");
        let head = testutil::write(&dir, "head.bin", &[0u8; 512]);
        let json = format!(r#"{{"type":"raw","stream":{{"type":"file","file_path":"{head}"}}}}"#);
        let source = Source::open(&json).expect("prepare");
        // 2^60 bytes cannot be allocated: -ENOMEM, no panic.
        assert_eq!(source.read(CEPH_NOSNAP, &[(0, 1u64 << 60)]), Err(-12));
    }

    #[test]
    fn raw_list_snaps_extent_at_u64_max() {
        // An extent ending at u64::MAX: no overflow, the delta is bounded
        // by the revision sizes as usual.
        let (_dir, json, _originals) = three_revisions();
        let source = Source::open(&json).expect("prepare");
        let deltas = source
            .list_snaps(&[(0, u64::MAX)], &[1, 2, CEPH_NOSNAP])
            .expect("list_snaps");
        assert_eq!(
            deltas,
            vec![
                RevisionDelta {
                    snap_id: 1,
                    extents: vec![extent(0, 512, SourceDeltaKind::Data)],
                },
                RevisionDelta {
                    snap_id: 2,
                    extents: vec![extent(0, 2048, SourceDeltaKind::Data)],
                },
                RevisionDelta {
                    snap_id: CEPH_NOSNAP,
                    extents: vec![
                        extent(0, 1024, SourceDeltaKind::Data),
                        extent(1024, 1024, SourceDeltaKind::Zeroed),
                    ],
                },
            ]
        );
    }
}
