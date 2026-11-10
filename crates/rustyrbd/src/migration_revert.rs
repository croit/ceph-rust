// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Abort revert geometry (ADR 0705 S8, spec "Abort", "Revert semantics").
//!
//! B5 copies the destination interval `(boundary, HEAD]` back into the source
//! HEAD. Two facts decide what is copied and how:
//!
//! * the *boundary*: the destination snapshot ID mapped from the greatest
//!   source snapshot ID in the destination record's `snap_seqs`, or none when
//!   the map is empty (the revert then copies the whole destination HEAD);
//! * the *write context*: every existing source snapshot, newest first, so
//!   each written revision carries the source's full snapshot context and the
//!   source snapshots keep their own revisions.
//!
//! Both are pure functions of the durable records, so they are unit-tested
//! without a cluster.

use crate::ImageSnapContext;
use crate::journal_backend::{EINVAL, EOVERFLOW};
use crate::migration_terminal::MigrationRecord;
use opwire::NOSNAP;

/// The destination boundary snapshot of a revert: the destination ID mapped
/// from the greatest source snapshot ID in `snap_seqs`, or `None` for an empty
/// map.
///
/// A `CEPH_NOSNAP` row is not a source snapshot; it never becomes the
/// boundary.
pub fn revert_boundary(record: &MigrationRecord) -> Option<u64> {
    record
        .snap_seqs
        .keys()
        .copied()
        .filter(|source_id| *source_id < NOSNAP)
        .max()
        .and_then(|source_id| record.snap_seqs.get(&source_id).copied())
}

/// The write context the revert installs into the source HEAD: the image's own
/// snapshot context, i.e. every snapshot ID newest first with the newest ID as
/// the sequence.
///
/// `snapshot_ids` must be ascending, unique and below `CEPH_NOSNAP`; anything
/// else is a corrupt header and `-EINVAL`.
pub fn source_write_context(snapshot_ids: &[u64]) -> Result<ImageSnapContext, i32> {
    let mut ids = Vec::new();
    ids.try_reserve_exact(snapshot_ids.len())
        .map_err(|_| EOVERFLOW)?;
    let mut previous = 0u64;
    for &id in snapshot_ids {
        if id == 0 || id >= NOSNAP || id <= previous {
            return Err(EINVAL);
        }
        previous = id;
        ids.insert(0, id);
    }
    Ok(ImageSnapContext {
        sequence: ids.first().copied().unwrap_or(0),
        ids,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration_terminal::{HEADER_TYPE_DST, MigrationRecord};
    use std::collections::BTreeMap;

    fn record(snap_seqs: &[(u64, u64)]) -> MigrationRecord {
        MigrationRecord {
            header_type: HEADER_TYPE_DST,
            snap_seqs: snap_seqs.iter().copied().collect::<BTreeMap<_, _>>(),
            ..MigrationRecord::default()
        }
    }

    #[test]
    fn boundary_is_the_destination_id_of_the_greatest_source_snapshot() {
        // Two snapshots: the newest source ID wins, not the newest destination.
        assert_eq!(revert_boundary(&record(&[(100, 11), (200, 12)])), Some(12));
        // Destination IDs need not follow the source order.
        assert_eq!(revert_boundary(&record(&[(100, 21), (200, 11)])), Some(11));
        // A single row.
        assert_eq!(revert_boundary(&record(&[(300, 31)])), Some(31));
    }

    #[test]
    fn an_empty_map_reverts_from_zero() {
        assert_eq!(revert_boundary(&record(&[])), None);
    }

    #[test]
    fn a_head_row_is_not_a_snapshot_boundary() {
        // CEPH_NOSNAP is the HEAD endpoint, never a boundary snapshot.
        assert_eq!(
            revert_boundary(&record(&[(100, 11), (NOSNAP, 12)])),
            Some(11)
        );
        assert_eq!(revert_boundary(&record(&[(NOSNAP, 12)])), None);
    }

    #[test]
    fn the_write_context_lists_every_source_snapshot_newest_first() {
        let context = source_write_context(&[100, 200]).unwrap();
        assert_eq!(context.sequence, 200);
        assert_eq!(context.ids, [200, 100]);
        let context = source_write_context(&[100, 200, 300]).unwrap();
        assert_eq!(context.sequence, 300);
        assert_eq!(context.ids, [300, 200, 100]);
    }

    #[test]
    fn a_source_without_snapshots_writes_with_an_empty_context() {
        let context = source_write_context(&[]).unwrap();
        assert_eq!(context.sequence, 0);
        assert!(context.ids.is_empty());
    }

    #[test]
    fn malformed_source_snapshot_sets_are_refused() {
        for ids in [
            vec![0u64],
            vec![NOSNAP],
            vec![100, 100],
            vec![200, 100],
            vec![100, 0],
        ] {
            assert_eq!(source_write_context(&ids), Err(EINVAL), "{ids:?}");
        }
    }
}
