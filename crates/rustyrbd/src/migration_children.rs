// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Child-relink decisions for prepare Q9 and abort B6 (ADR 0705 S6c/S9, spec
//! "Relink back"). Both directions share one decision: the source snapshot is
//! `from`, the destination snapshot is `to` for the forward relink, and the
//! reverse for the abort repair.
//!
//! A child's parent spec is image-wide (`parent_get`): a HEAD detach removes
//! only the HEAD overlap, so the spec survives while any child snapshot keeps
//! its own overlap. Per-snapshot data is `parent_overlap_get(snap_id)`, which
//! is why the effective reference is the `parent_get` spec whenever HEAD or
//! any snapshot still reports an overlap.

use crate::journal_backend::ESTALE;
use crate::migration_terminal::ImageRef;
use crate::parent_query::ParentSpec;

/// The child's effective parent reference.
///
/// `None` means the child has no parent reference left (no spec, or the spec
/// without any overlap at HEAD or in a snapshot), so a relink only moves the
/// registration and rewrites nothing.
pub fn effective_parent(
    parent: Option<&ParentSpec>,
    head_overlap: Option<u64>,
    snapshot_overlaps: impl IntoIterator<Item = Option<u64>>,
) -> Option<&ParentSpec> {
    let parent = parent?;
    if head_overlap.is_some()
        || snapshot_overlaps
            .into_iter()
            .any(|overlap| overlap.is_some())
    {
        Some(parent)
    } else {
        None
    }
}

/// The overlap a reattach keeps: the HEAD overlap, or 0 when HEAD was detached
/// (a present zero overlap retains the identity without exposing parent data).
pub fn retained_overlap(head_overlap: Option<u64>) -> u64 {
    head_overlap.unwrap_or(0)
}

/// What one child relink does with the child's parent reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelinkParent {
    /// No effective parent: only the registration moves.
    Absent,
    /// The parent already names the target snapshot: only the registration
    /// moves (the resumable half of an interrupted relink).
    Keep,
    /// The parent names the source snapshot: rewrite it to the target and keep
    /// the overlap.
    Rewrite,
}

/// The relink decision for one child (spec "Relink back"): the child's
/// effective parent must name either the `from` snapshot (rewrite) or the `to`
/// snapshot (already moved); anything else is `-ESTALE` and is not this
/// migration.
pub fn relink_parent(
    effective: Option<&ParentSpec>,
    from: &ImageRef,
    from_snapshot: u64,
    to: &ImageRef,
    to_snapshot: u64,
) -> Result<RelinkParent, i32> {
    let Some(parent) = effective else {
        return Ok(RelinkParent::Absent);
    };
    let points_at = |image: &ImageRef, snapshot: u64| {
        parent.pool == image.pool_id
            && parent.namespace == image.namespace
            && parent.image_id == image.id
            && parent.snapshot_id == snapshot
    };
    if points_at(to, to_snapshot) {
        Ok(RelinkParent::Keep)
    } else if points_at(from, from_snapshot) {
        Ok(RelinkParent::Rewrite)
    } else {
        Err(ESTALE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration_terminal::ImageFormat;

    fn parent() -> ParentSpec {
        ParentSpec {
            pool: 7,
            namespace: b"ns".to_vec(),
            image_id: b"p".to_vec(),
            snapshot_id: 11,
        }
    }

    #[test]
    fn a_head_overlap_makes_the_parent_spec_effective() {
        let spec = parent();
        assert_eq!(
            effective_parent(Some(&spec), Some(1 << 20), []),
            Some(&spec)
        );
        // A present zero overlap still retains the identity.
        assert_eq!(effective_parent(Some(&spec), Some(0), []), Some(&spec));
    }

    #[test]
    fn a_snapshot_overlap_keeps_the_spec_after_a_head_detach() {
        let spec = parent();
        assert_eq!(
            effective_parent(Some(&spec), None, [None, Some(4096)]),
            Some(&spec)
        );
        assert_eq!(retained_overlap(None), 0);
    }

    #[test]
    fn a_spec_without_any_overlap_is_not_a_reference() {
        let spec = parent();
        assert_eq!(effective_parent(Some(&spec), None, [None, None]), None);
        assert_eq!(effective_parent(None, Some(1 << 20), [Some(1)]), None);
    }

    fn image(name: &str, id: &str) -> ImageRef {
        ImageRef {
            format: ImageFormat::V2,
            pool_id: 7,
            namespace: b"ns".to_vec(),
            name: name.as_bytes().to_vec(),
            id: id.as_bytes().to_vec(),
        }
    }

    fn at(image: &ImageRef, snapshot_id: u64) -> ParentSpec {
        ParentSpec {
            pool: image.pool_id,
            namespace: image.namespace.clone(),
            image_id: image.id.clone(),
            snapshot_id,
        }
    }

    #[test]
    fn relink_state_1_a_child_at_the_source_is_rewritten_forward() {
        let source = image("src", "s");
        let destination = image("dst", "d");
        let parent = at(&source, 100);
        assert_eq!(
            relink_parent(Some(&parent), &source, 100, &destination, 11),
            Ok(RelinkParent::Rewrite)
        );
        // And the reverse direction (abort B6) rewrites it back.
        let parent = at(&destination, 11);
        assert_eq!(
            relink_parent(Some(&parent), &destination, 11, &source, 100),
            Ok(RelinkParent::Rewrite)
        );
    }

    #[test]
    fn relink_state_2_a_child_already_at_the_destination_only_moves() {
        let source = image("src", "s");
        let destination = image("dst", "d");
        let parent = at(&destination, 11);
        assert_eq!(
            relink_parent(Some(&parent), &source, 100, &destination, 11),
            Ok(RelinkParent::Keep)
        );
        let parent = at(&source, 100);
        assert_eq!(
            relink_parent(Some(&parent), &destination, 11, &source, 100),
            Ok(RelinkParent::Keep)
        );
    }

    #[test]
    fn relink_state_3_a_child_without_a_parent_only_moves() {
        let source = image("src", "s");
        let destination = image("dst", "d");
        assert_eq!(
            relink_parent(None, &source, 100, &destination, 11),
            Ok(RelinkParent::Absent)
        );
        assert_eq!(
            relink_parent(None, &destination, 11, &source, 100),
            Ok(RelinkParent::Absent)
        );
    }

    #[test]
    fn relink_state_4_a_foreign_parent_is_stale() {
        let source = image("src", "s");
        let destination = image("dst", "d");
        let other = image("other", "o");
        for parent in [
            at(&other, 100),
            // The right image with another snapshot is a different revision.
            at(&source, 200),
            at(&destination, 12),
        ] {
            assert_eq!(
                relink_parent(Some(&parent), &source, 100, &destination, 11),
                Err(ESTALE)
            );
            assert_eq!(
                relink_parent(Some(&parent), &destination, 11, &source, 100),
                Err(ESTALE)
            );
        }
    }

    #[test]
    fn the_reattach_keeps_the_head_overlap() {
        assert_eq!(retained_overlap(Some(1 << 20)), 1 << 20);
        assert_eq!(retained_overlap(Some(0)), 0);
        assert_eq!(retained_overlap(None), 0);
    }
}
