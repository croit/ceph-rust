// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Coherent modern parent-reference decisions for snapshot removal.
//!
//! A global parent key can survive for snapshots after HEAD is detached.
//! Overlap presence, including Some(0), establishes each effective reference.
//! This component does not acquire ownership or open any parent DATA context.

use crate::{HeadObservation, ParentSpec, SnapshotObservation};

/// Metadata cannot establish a complete, coherent last-reference decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotParentError {
    /// The target snapshot is absent from the observed SnapContext.
    MissingTarget,
    /// A snapshot observation belongs to another header version.
    VersionChanged,
    /// Required other snapshots are missing, duplicated or out of context order.
    IncompleteCohort,
}

impl std::fmt::Display for SnapshotParentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::MissingTarget => "snapshot parent target is absent from SnapContext",
            Self::VersionChanged => "snapshot parent cohort changed header version",
            Self::IncompleteCohort => "snapshot parent cohort is incomplete or unordered",
        })
    }
}
impl std::error::Error for SnapshotParentError {}

/// Return the upstream identity whose last reference removal must detach.
///
/// This models the pinned modern refresh contract: the shared namespace-aware
/// parent spec and each entry's overlap presence determine effective identity.
/// No reference exists for an absent overlap; a present zero overlap still
/// retains the identity. Arbitrary legacy embedded identities are not inferred.
///
/// If HEAD retains the identity or the target has no parent, `others` need not
/// be read. Otherwise provide every OTHER snapshot, in the same descending-ID
/// order as `head.snap_context().ids`, at the same header version. Incomplete
/// observations produce an error rather than guessing that the parent is free.
/// The returned identity is metadata only, not authority to detach or delete.
pub fn snapshot_parent_to_detach(
    head: &HeadObservation,
    target: &SnapshotObservation,
    others: &[SnapshotObservation],
) -> Result<Option<ParentSpec>, SnapshotParentError> {
    let target_id = target.info().id;
    if !head.snap_context().ids.contains(&target_id) {
        return Err(SnapshotParentError::MissingTarget);
    }
    if target.user_version() != head.user_version() {
        return Err(SnapshotParentError::VersionChanged);
    }
    let Some(parent) = head.parent() else {
        return Ok(None);
    };
    if target.parent_overlap().is_none() || head.parent_overlap().is_some() {
        return Ok(None);
    }
    if others.len() != head.snap_context().ids.len() - 1 {
        return Err(SnapshotParentError::IncompleteCohort);
    }
    let mut retained = false;
    for (id, snapshot) in head
        .snap_context()
        .ids
        .iter()
        .filter(|id| **id != target_id)
        .zip(others)
    {
        if snapshot.info().id != *id {
            return Err(SnapshotParentError::IncompleteCohort);
        }
        if snapshot.user_version() != head.user_version() {
            return Err(SnapshotParentError::VersionChanged);
        }
        retained |= snapshot.parent_overlap().is_some();
    }
    Ok((!retained).then(|| parent.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        HeadInputs, ImageHeader, ImageSnapContext, SnapshotInfo, SnapshotInputs, SnapshotNamespace,
        Versioned,
    };

    fn head(overlap: Option<u64>, version: u64) -> HeadObservation {
        let observed = |value| Versioned {
            value,
            user_version: version,
        };
        HeadObservation::assemble(HeadInputs {
            header: Versioned {
                value: ImageHeader {
                    order: 20,
                    size: 4096,
                    features: 1,
                    incompatible_features: 0,
                    object_prefix: b"rbd_data.child".to_vec(),
                    data_pool_id: -1,
                },
                user_version: version,
            },
            snap_context: Versioned {
                value: ImageSnapContext {
                    sequence: 9,
                    ids: vec![9, 5, 2],
                },
                user_version: version,
            },
            flags: observed(0),
            parent: Versioned {
                value: Some(ParentSpec {
                    pool: 7,
                    namespace: b"parent-ns".to_vec(),
                    image_id: b"parent1".to_vec(),
                    snapshot_id: 11,
                }),
                user_version: version,
            },
            parent_overlap: Versioned {
                value: overlap,
                user_version: version,
            },
            group: Versioned {
                value: None,
                user_version: version,
            },
            stripe: None,
            op_features: None,
        })
        .unwrap()
    }
    fn snapshot(head: &HeadObservation, id: u64, overlap: Option<u64>) -> SnapshotObservation {
        let version = head.user_version();
        SnapshotObservation::assemble(
            head,
            SnapshotInputs {
                info: Versioned {
                    value: SnapshotInfo {
                        id,
                        namespace: SnapshotNamespace::User,
                        name: id.to_le_bytes().to_vec(),
                        image_size: 4096,
                        timestamp_seconds: 0,
                        timestamp_nanoseconds: 0,
                        child_count: 0,
                    },
                    user_version: version,
                },
                flags: Versioned {
                    value: 0,
                    user_version: version,
                },
                parent_overlap: Versioned {
                    value: overlap,
                    user_version: version,
                },
                protection: Versioned {
                    value: 0,
                    user_version: version,
                },
            },
        )
        .unwrap()
    }
    #[test]
    fn snapshot_only_parent_key_does_not_count_as_head_reference() {
        let h = head(None, 37);
        for overlap in [Some(4096), Some(0)] {
            let target = snapshot(&h, 5, overlap);
            let others = [snapshot(&h, 9, None), snapshot(&h, 2, None)];
            assert_eq!(
                snapshot_parent_to_detach(&h, &target, &others),
                Ok(h.parent().cloned())
            );
        }
    }
    #[test]
    fn head_reference_including_zero_needs_no_other_snapshot_reads() {
        for overlap in [Some(4096), Some(0)] {
            let h = head(overlap, 37);
            assert_eq!(
                snapshot_parent_to_detach(&h, &snapshot(&h, 5, Some(1)), &[]),
                Ok(None)
            );
        }
    }
    #[test]
    fn another_snapshot_reference_including_zero_prevents_detachment() {
        let h = head(None, 37);
        for overlap in [Some(4096), Some(0)] {
            let others = [snapshot(&h, 9, None), snapshot(&h, 2, overlap)];
            assert_eq!(
                snapshot_parent_to_detach(&h, &snapshot(&h, 5, Some(1)), &others),
                Ok(None)
            );
        }
    }
    #[test]
    fn a_target_without_parent_does_not_need_the_other_cohort() {
        let h = head(None, 37);
        assert_eq!(
            snapshot_parent_to_detach(&h, &snapshot(&h, 5, None), &[]),
            Ok(None)
        );
    }
    #[test]
    fn missing_duplicate_or_unordered_cohorts_never_authorize_detach() {
        let h = head(None, 37);
        let target = snapshot(&h, 5, Some(1));
        for others in [
            vec![],
            vec![snapshot(&h, 9, None)],
            vec![snapshot(&h, 9, None), snapshot(&h, 9, None)],
            vec![snapshot(&h, 2, None), snapshot(&h, 9, None)],
        ] {
            assert_eq!(
                snapshot_parent_to_detach(&h, &target, &others),
                Err(SnapshotParentError::IncompleteCohort)
            );
        }
    }
    #[test]
    fn changed_target_or_other_versions_never_authorize_detach() {
        let h = head(None, 37);
        let changed = head(None, 38);
        assert_eq!(
            snapshot_parent_to_detach(&h, &snapshot(&changed, 5, Some(1)), &[]),
            Err(SnapshotParentError::VersionChanged)
        );
        let others = [snapshot(&h, 9, None), snapshot(&changed, 2, None)];
        assert_eq!(
            snapshot_parent_to_detach(&h, &snapshot(&h, 5, Some(1)), &others),
            Err(SnapshotParentError::VersionChanged)
        );
    }
}
