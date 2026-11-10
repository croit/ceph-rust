// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Per-snapshot metadata joined to a coherent image-header observation.

use crate::{HeadObservation, SnapshotInfo, Versioned};

/// One snapshot's independent header-object replies.
#[derive(Debug)]
pub struct SnapshotInputs {
    pub info: Versioned<SnapshotInfo>,
    pub flags: Versioned<u64>,
    pub parent_overlap: Versioned<Option<u64>>,
    pub protection: Versioned<u8>,
}

/// Why a snapshot record cannot be joined to the observed header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotObservationError {
    VersionChanged {
        field: &'static str,
        expected: u64,
        observed: u64,
    },
    NotInSnapContext,
    InvalidParentOverlap,
    InvalidProtection,
}

impl std::fmt::Display for SnapshotObservationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VersionChanged {
                field,
                expected,
                observed,
            } => write!(
                f,
                "RBD snapshot {field} changed: expected header version {expected}, observed {observed}"
            ),
            Self::NotInSnapContext => {
                f.write_str("RBD snapshot is absent from the captured snap context")
            }
            Self::InvalidParentOverlap => {
                f.write_str("RBD snapshot parent overlap is inconsistent")
            }
            Self::InvalidProtection => f.write_str("invalid RBD snapshot protection status"),
        }
    }
}

impl std::error::Error for SnapshotObservationError {}

/// Metadata for one snapshot at the same header-object version as its head.
/// This is not a watch/refresh state or a grant to issue image I/O.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotObservation {
    info: SnapshotInfo,
    flags: u64,
    parent_overlap: Option<u64>,
    protection: u8,
    user_version: u64,
}

impl SnapshotObservation {
    /// Join per-snapshot results only when all originated from the captured
    /// header version and the snapshot exists in its SnapContext.
    pub fn assemble(
        head: &HeadObservation,
        inputs: SnapshotInputs,
    ) -> Result<Self, SnapshotObservationError> {
        let SnapshotInputs {
            info,
            flags,
            parent_overlap,
            protection,
        } = inputs;
        let version = head.user_version();
        for (field, observed) in [
            ("record", info.user_version),
            ("flags", flags.user_version),
            ("parent overlap", parent_overlap.user_version),
            ("protection", protection.user_version),
        ] {
            if observed != version {
                return Err(SnapshotObservationError::VersionChanged {
                    field,
                    expected: version,
                    observed,
                });
            }
        }
        if info.value.id >= opwire::NOSNAP
            || head
                .snap_context()
                .ids
                .binary_search_by(|probe| info.value.id.cmp(probe))
                .is_err()
        {
            return Err(SnapshotObservationError::NotInSnapContext);
        }
        if parent_overlap
            .value
            .is_some_and(|overlap| head.parent().is_none() || overlap > info.value.image_size)
        {
            return Err(SnapshotObservationError::InvalidParentOverlap);
        }
        if protection.value > 2 {
            return Err(SnapshotObservationError::InvalidProtection);
        }
        Ok(Self {
            info: info.value,
            flags: flags.value,
            parent_overlap: parent_overlap.value,
            protection: protection.value,
            user_version: version,
        })
    }

    pub fn info(&self) -> &SnapshotInfo {
        &self.info
    }
    pub fn flags(&self) -> u64 {
        self.flags
    }
    pub fn parent_overlap(&self) -> Option<u64> {
        self.parent_overlap
    }
    pub fn protection(&self) -> u8 {
        self.protection
    }
    pub fn user_version(&self) -> u64 {
        self.user_version
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HeadInputs, ImageHeader, ImageSnapContext, ParentSpec, SnapshotNamespace};

    fn head() -> HeadObservation {
        HeadObservation::assemble(HeadInputs {
            header: Versioned {
                value: ImageHeader {
                    order: 22,
                    size: 8192,
                    features: 1,
                    incompatible_features: 0,
                    object_prefix: b"rbd_data.child1".to_vec(),
                    data_pool_id: -1,
                },
                user_version: 37,
            },
            snap_context: Versioned {
                value: ImageSnapContext {
                    sequence: 9,
                    ids: vec![9, 5, 2],
                },
                user_version: 37,
            },
            flags: Versioned {
                value: 0,
                user_version: 37,
            },
            parent: Versioned {
                value: Some(ParentSpec {
                    pool: 7,
                    namespace: vec![],
                    image_id: b"parent1".to_vec(),
                    snapshot_id: 4,
                }),
                user_version: 37,
            },
            parent_overlap: Versioned {
                value: None,
                user_version: 37,
            },
            group: Versioned {
                value: None,
                user_version: 37,
            },
            stripe: None,
            op_features: None,
        })
        .unwrap()
    }

    fn inputs() -> SnapshotInputs {
        SnapshotInputs {
            info: Versioned {
                value: SnapshotInfo {
                    id: 5,
                    namespace: SnapshotNamespace::User,
                    name: b"snap1".to_vec(),
                    image_size: 4096,
                    timestamp_seconds: 123,
                    timestamp_nanoseconds: 0,
                    child_count: 0,
                },
                user_version: 37,
            },
            flags: Versioned {
                value: 3,
                user_version: 37,
            },
            parent_overlap: Versioned {
                value: Some(2048),
                user_version: 37,
            },
            protection: Versioned {
                value: 2,
                user_version: 37,
            },
        }
    }

    #[test]
    fn joins_snapshot_with_head_version_and_context() {
        let observed = SnapshotObservation::assemble(&head(), inputs()).unwrap();
        assert_eq!(observed.info().id, 5);
        assert_eq!(observed.flags(), 3);
        assert_eq!(observed.parent_overlap(), Some(2048));
        assert_eq!(observed.protection(), 2);
        assert_eq!(observed.user_version(), 37);
    }

    #[test]
    fn rejects_changed_or_inconsistent_snapshot() {
        let mut snapshot = inputs();
        snapshot.flags.user_version = 38;
        assert_eq!(
            SnapshotObservation::assemble(&head(), snapshot),
            Err(SnapshotObservationError::VersionChanged {
                field: "flags",
                expected: 37,
                observed: 38
            })
        );
        let mut snapshot = inputs();
        snapshot.info.value.id = 6;
        assert_eq!(
            SnapshotObservation::assemble(&head(), snapshot),
            Err(SnapshotObservationError::NotInSnapContext)
        );
        let mut snapshot = inputs();
        snapshot.parent_overlap.value = Some(4097);
        assert_eq!(
            SnapshotObservation::assemble(&head(), snapshot),
            Err(SnapshotObservationError::InvalidParentOverlap)
        );
    }

    #[test]
    fn snapshot_locator_uses_record_size_and_selector() {
        let head = head();
        let snapshot = SnapshotObservation::assemble(&head, inputs()).unwrap();
        let locator = crate::DataLocator::from_snapshot(&head, &snapshot, 7, vec![]).unwrap();
        let final_byte = locator.plan_read(4095, 100, 100, 5).unwrap().unwrap();
        assert_eq!(final_byte.extent.length, 1);
        assert!(locator.plan_read(4096, 1, 1, 5).unwrap().is_none());
        assert!(matches!(
            locator.plan_read(0, 1, 1, opwire::NOSNAP),
            Err(crate::QueryError::InvalidSnapshot)
        ));
        let head_locator = crate::DataLocator::from_head(&head, 7, vec![]).unwrap();
        assert!(
            head_locator
                .plan_read(5000, 1, 1, opwire::NOSNAP)
                .unwrap()
                .is_some()
        );
        assert!(matches!(
            head_locator.plan_read(0, 1, 1, 5),
            Err(crate::QueryError::InvalidSnapshot)
        ));
    }
}
