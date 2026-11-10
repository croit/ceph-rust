// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Reconstruct child-object presence from physical snapshot revision intervals.

use crate::{ObjectMapDecodeError, ObjectState};
use opwire::ObjListSnapResponse;

const HEAD: u64 = u64::MAX - 1;

/// One selected-revision rebuild with a stable complete image snapshot set.
/// Physical object history, rather than parent fallback or HEAD stat, determines
/// which child allocations exist and which have remained clean across revisions.
#[derive(Debug)]
pub struct ObjectMapRebuild {
    snapshots: Vec<u64>,
    selected: u64,
    fast_diff: bool,
}
impl ObjectMapRebuild {
    /// Snapshot IDs may arrive in either order; they must be unique, nonzero,
    /// non-reserved IDs. `selected` is HEAD or one of those snapshots.
    pub fn new(
        snapshots: &[u64],
        selected: u64,
        fast_diff: bool,
    ) -> Result<Self, ObjectMapDecodeError> {
        let mut sorted = Vec::new();
        sorted
            .try_reserve_exact(snapshots.len())
            .map_err(|_| ObjectMapDecodeError::Allocation)?;
        sorted.extend_from_slice(snapshots);
        sorted.sort_unstable();
        if sorted.iter().any(|id| *id == 0 || *id >= HEAD)
            || sorted.windows(2).any(|pair| pair[0] == pair[1])
            || (selected != HEAD && sorted.binary_search(&selected).is_err())
        {
            return Err(ObjectMapDecodeError::Malformed);
        }
        Ok(Self {
            snapshots: sorted,
            selected,
            fast_diff,
        })
    }

    /// Classify one successful LIST_SNAPS result. Missing objects are supplied
    /// as an empty result. No parent allocations are included in this decision.
    pub fn state(
        &self,
        revisions: &ObjListSnapResponse,
    ) -> Result<ObjectState, ObjectMapDecodeError> {
        if revisions.seq >= HEAD {
            return Err(ObjectMapDecodeError::Malformed);
        }
        let mut state = None;
        let mut previous_id = None;
        for clone in &revisions.clones {
            if clone.cloneid > HEAD
                || previous_id.is_some_and(|id| id >= clone.cloneid)
                || clone.snaps.iter().any(|id| *id == 0 || *id >= HEAD)
                || clone.snaps.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err(ObjectMapDecodeError::Malformed);
            }
            previous_id = Some(clone.cloneid);
            let (first, last) = if clone.cloneid == HEAD {
                (revisions.seq + 1, HEAD)
            } else {
                let first = *clone.snaps.first().ok_or(ObjectMapDecodeError::Malformed)?;
                (first, *clone.snaps.last().unwrap())
            };
            let first_index = self.snapshots.partition_point(|id| *id < first);
            let first_image_revision = self.snapshots.get(first_index).copied().unwrap_or(HEAD);
            if first_image_revision <= self.selected && self.selected <= last {
                if state.is_some() {
                    return Err(ObjectMapDecodeError::Malformed);
                }
                state = Some(if self.fast_diff && first_image_revision != self.selected {
                    ObjectState::ExistsClean
                } else {
                    ObjectState::Exists
                });
            }
        }
        Ok(state.unwrap_or(ObjectState::Nonexistent))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opwire::CloneInfo;

    fn history() -> ObjListSnapResponse {
        ObjListSnapResponse {
            seq: 8,
            clones: vec![
                CloneInfo {
                    cloneid: 6,
                    snaps: vec![2, 4, 6],
                    size: 4096,
                    ..Default::default()
                },
                CloneInfo {
                    cloneid: HEAD,
                    size: 8192,
                    ..Default::default()
                },
            ],
        }
    }

    #[test]
    fn physical_intervals_resolve_against_surviving_image_snapshots() {
        for (selected, expected) in [
            (4, ObjectState::Exists),
            (6, ObjectState::ExistsClean),
            (8, ObjectState::Nonexistent),
            (10, ObjectState::Exists),
            (HEAD, ObjectState::ExistsClean),
        ] {
            let plan = ObjectMapRebuild::new(&[10, 8, 6, 4], selected, true).unwrap();
            assert_eq!(plan.state(&history()), Ok(expected));
        }
        let plan = ObjectMapRebuild::new(&[4, 6, 8, 10], 6, false).unwrap();
        assert_eq!(plan.state(&history()), Ok(ObjectState::Exists));
    }

    #[test]
    fn head_only_and_snapshot_only_allocations_remain_distinct() {
        let mut revisions = history();
        revisions.clones.pop();
        assert_eq!(
            ObjectMapRebuild::new(&[4, 6, 8], HEAD, true)
                .unwrap()
                .state(&revisions),
            Ok(ObjectState::Nonexistent)
        );
        revisions.clones.clear();
        assert_eq!(
            ObjectMapRebuild::new(&[], HEAD, true)
                .unwrap()
                .state(&revisions),
            Ok(ObjectState::Nonexistent)
        );
        revisions.clones.push(CloneInfo {
            cloneid: HEAD,
            ..Default::default()
        });
        assert_eq!(
            ObjectMapRebuild::new(&[4, 6, 8], HEAD, true)
                .unwrap()
                .state(&revisions),
            Ok(ObjectState::Exists)
        );
    }

    #[test]
    fn malformed_selections_and_foreign_revision_order_do_not_publish_maps() {
        assert!(ObjectMapRebuild::new(&[4, 4], HEAD, false).is_err());
        assert!(ObjectMapRebuild::new(&[4], 6, false).is_err());
        assert!(ObjectMapRebuild::new(&[0], HEAD, false).is_err());
        let plan = ObjectMapRebuild::new(&[4, 6, 8], HEAD, true).unwrap();
        let mut revisions = history();
        revisions.clones.swap(0, 1);
        assert!(plan.state(&revisions).is_err());
        revisions.clones.pop();
        revisions.seq = u64::MAX;
        assert!(plan.state(&revisions).is_err());
    }
}
