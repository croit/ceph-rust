// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Byte-prefix changes derived from physical RADOS snapshot history.
//!
//! LIST_SNAPS overlap describes unchanged bytes, including identical-value
//! rewrites as modifications. It is independent of image stripe geometry.
//! Callers map these physical intervals through their captured ImageLayout and
//! apply logical query clipping and inherited allocation inclusion separately.

use crate::ObjectMapDecodeError;
use opwire::{NOSNAP, ObjListSnapResponse};

/// One changed physical interval. Absent intervals are unchanged, not holes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectDiffExtent {
    pub offset: u64,
    pub length: u64,
    pub exists: bool,
}

/// A selected object's presence and changed physical data prefixes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectDiff {
    end_present: bool,
    end_size: u64,
    object_size: u64,
    extents: Vec<ObjectDiffExtent>,
}

impl ObjectDiff {
    /// `None` is beginning of time; otherwise `from` is a finite image snapshot.
    /// `to` is a finite snapshot or NOSNAP. Missing objects use an empty result.
    /// Allocated prefixes and overlap are clipped to configured object size;
    /// object presence remains distinct from an empty real HEAD marker.
    pub fn new(
        history: &ObjListSnapResponse,
        from: Option<u64>,
        to: u64,
        object_size: u64,
    ) -> Result<Self, ObjectMapDecodeError> {
        if object_size == 0
            || history.seq >= NOSNAP
            || to == 0
            || to > NOSNAP
            || from.is_some_and(|id| id == 0 || id >= NOSNAP || id > to)
        {
            return Err(ObjectMapDecodeError::Malformed);
        }
        let mut previous = 0;
        for clone in &history.clones {
            if clone.cloneid <= previous
                || clone.cloneid > NOSNAP
                || (clone.cloneid == NOSNAP
                    && (!clone.snaps.is_empty() || !clone.overlap.is_empty()))
                || (clone.cloneid != NOSNAP
                    && (clone.cloneid > history.seq
                        || clone.snaps.is_empty()
                        || clone.snaps.first().is_some_and(|id| *id <= previous)
                        || clone.snaps.iter().any(|id| *id == 0 || *id > clone.cloneid)
                        || clone.snaps.windows(2).any(|pair| pair[0] >= pair[1])))
            {
                return Err(ObjectMapDecodeError::Malformed);
            }
            previous = clone.cloneid;
            let mut end = 0;
            for &(offset, length) in &clone.overlap {
                let next = offset
                    .checked_add(length)
                    .ok_or(ObjectMapDecodeError::Malformed)?;
                if length == 0 || offset < end || next > clone.size {
                    return Err(ObjectMapDecodeError::Malformed);
                }
                end = next;
            }
        }
        let resolve = |id: u64| {
            if id == NOSNAP || id > history.seq {
                history
                    .clones
                    .iter()
                    .position(|clone| clone.cloneid == NOSNAP)
            } else {
                history
                    .clones
                    .iter()
                    .position(|clone| clone.cloneid >= id && clone.snaps.binary_search(&id).is_ok())
            }
        };
        let start = from.and_then(resolve);
        let finish = resolve(to);
        if start.zip(finish).is_some_and(|(a, b)| a > b) {
            return Err(ObjectMapDecodeError::Malformed);
        }
        let before = start.map_or(0, |index| history.clones[index].size.min(object_size));
        let after = finish.map_or(0, |index| history.clones[index].size.min(object_size));
        let mut common = Vec::new();
        if let (Some(start), Some(finish)) = (start, finish) {
            if before.min(after) > 0 {
                common.push((0, before.min(after)));
            }
            for clone in &history.clones[start..finish] {
                let mut next = Vec::new();
                next.try_reserve(common.len().saturating_add(clone.overlap.len()))
                    .map_err(|_| ObjectMapDecodeError::Allocation)?;
                let mut index = 0;
                for &(begin, end) in &common {
                    while index < clone.overlap.len()
                        && clone.overlap[index].0 + clone.overlap[index].1 <= begin
                    {
                        index += 1;
                    }
                    let mut cursor = index;
                    while cursor < clone.overlap.len() && clone.overlap[cursor].0 < end {
                        let (offset, length) = clone.overlap[cursor];
                        let left = begin.max(offset);
                        let right = end.min(offset + length);
                        if left < right {
                            next.push((left, right));
                        }
                        cursor += 1;
                    }
                }
                common = next;
                if common.is_empty() {
                    break;
                }
            }
        }
        let mut extents = Vec::new();
        extents
            .try_reserve(common.len().saturating_add(2))
            .map_err(|_| ObjectMapDecodeError::Allocation)?;
        let mut cursor = 0;
        let limit = before.max(after);
        for (begin, end) in common.into_iter().chain(std::iter::once((limit, limit))) {
            if cursor < begin {
                if cursor < after {
                    extents.push(ObjectDiffExtent {
                        offset: cursor,
                        length: begin.min(after) - cursor,
                        exists: true,
                    });
                }
                if begin > after {
                    let offset = cursor.max(after);
                    extents.push(ObjectDiffExtent {
                        offset,
                        length: begin - offset,
                        exists: false,
                    });
                }
            }
            cursor = end;
        }
        Ok(Self {
            end_present: finish.is_some(),
            end_size: after,
            object_size,
            extents,
        })
    }
    /// Real physical presence is distinct from a nonzero allocated byte prefix.
    pub fn end_present(&self) -> bool {
        self.end_present
    }
    pub fn end_size(&self) -> u64 {
        self.end_size
    }
    pub fn extents(&self) -> &[ObjectDiffExtent] {
        &self.extents
    }
    pub fn has_data_change(&self) -> bool {
        !self.extents.is_empty()
    }
    /// State at a physical cursor and the next change boundary, bounded by len.
    /// The unchanged state is None, distinct from a changed hole Some(false).
    pub fn span(&self, offset: u64, length: u64) -> (Option<bool>, u64) {
        let length = length.min(self.object_size.saturating_sub(offset));
        let index = self
            .extents
            .partition_point(|extent| extent.offset + extent.length <= offset);
        if let Some(extent) = self.extents.get(index) {
            if extent.offset <= offset {
                (
                    Some(extent.exists),
                    length.min(extent.offset + extent.length - offset),
                )
            } else {
                (None, length.min(extent.offset - offset))
            }
        } else {
            (None, length)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opwire::CloneInfo;
    fn clone(id: u64, snaps: &[u64], size: u64, overlap: &[(u64, u64)]) -> CloneInfo {
        CloneInfo {
            cloneid: id,
            snaps: snaps.to_vec(),
            size,
            overlap: overlap.to_vec(),
        }
    }
    #[test]
    fn identical_rewrite_tracks_metadata_not_equal_payloads() {
        let history = ObjListSnapResponse {
            seq: 10,
            clones: vec![
                clone(10, &[10], 32, &[(8, 24)]),
                clone(NOSNAP, &[], 32, &[]),
            ],
        };
        let diff = ObjectDiff::new(&history, Some(10), NOSNAP, 64).unwrap();
        assert_eq!(
            diff.extents(),
            &[ObjectDiffExtent {
                offset: 0,
                length: 8,
                exists: true
            }]
        );
        assert_eq!(diff.span(12, 20), (None, 20));
        assert!(diff.has_data_change());
    }
    #[test]
    fn overlap_intersection_preserves_changes_across_intermediate_versions() {
        let history = ObjListSnapResponse {
            seq: 20,
            clones: vec![
                clone(10, &[10], 32, &[(0, 8), (16, 16)]),
                clone(20, &[20], 32, &[(0, 24)]),
                clone(NOSNAP, &[], 32, &[]),
            ],
        };
        let diff = ObjectDiff::new(&history, Some(10), NOSNAP, 64).unwrap();
        assert_eq!(
            diff.extents(),
            &[
                ObjectDiffExtent {
                    offset: 8,
                    length: 8,
                    exists: true
                },
                ObjectDiffExtent {
                    offset: 24,
                    length: 8,
                    exists: true
                }
            ]
        );
    }
    #[test]
    fn from_zero_reports_physical_prefix_and_retains_empty_marker_presence() {
        let history = ObjListSnapResponse {
            seq: 0,
            clones: vec![clone(NOSNAP, &[], 17, &[])],
        };
        assert_eq!(
            ObjectDiff::new(&history, None, NOSNAP, 64)
                .unwrap()
                .extents(),
            &[ObjectDiffExtent {
                offset: 0,
                length: 17,
                exists: true
            }]
        );
        let empty = ObjListSnapResponse {
            seq: 0,
            clones: vec![clone(NOSNAP, &[], 0, &[])],
        };
        let diff = ObjectDiff::new(&empty, None, NOSNAP, 64).unwrap();
        assert!(diff.end_present());
        assert_eq!(diff.end_size(), 0);
        assert!(diff.extents().is_empty());
        assert!(
            !ObjectDiff::new(&ObjListSnapResponse::default(), None, NOSNAP, 64)
                .unwrap()
                .end_present()
        );
    }
    #[test]
    fn clone_only_removed_head_and_truncated_tails_report_holes() {
        let history = ObjListSnapResponse {
            seq: 10,
            clones: vec![clone(10, &[10], 32, &[])],
        };
        assert_eq!(
            ObjectDiff::new(&history, Some(10), NOSNAP, 64)
                .unwrap()
                .extents(),
            &[ObjectDiffExtent {
                offset: 0,
                length: 32,
                exists: false
            }]
        );
        let history = ObjListSnapResponse {
            seq: 10,
            clones: vec![
                clone(10, &[10], 32, &[(0, 12)]),
                clone(NOSNAP, &[], 12, &[]),
            ],
        };
        assert_eq!(
            ObjectDiff::new(&history, Some(10), NOSNAP, 64)
                .unwrap()
                .extents(),
            &[ObjectDiffExtent {
                offset: 12,
                length: 20,
                exists: false
            }]
        );
    }
    #[test]
    fn snapshot_membership_newer_head_and_unchanged_clone_are_distinct() {
        let history = ObjListSnapResponse {
            seq: 20,
            clones: vec![
                clone(20, &[10, 20], 32, &[(0, 32)]),
                clone(NOSNAP, &[], 32, &[]),
            ],
        };
        assert!(
            ObjectDiff::new(&history, Some(10), 20, 64)
                .unwrap()
                .extents()
                .is_empty()
        );
        assert!(
            ObjectDiff::new(&history, None, 15, 64)
                .unwrap()
                .extents()
                .is_empty()
        );
        assert_eq!(
            ObjectDiff::new(&history, None, 21, 64).unwrap().end_size(),
            32
        );
    }
    #[test]
    fn malformed_history_never_produces_partial_intervals() {
        for history in [
            ObjListSnapResponse {
                seq: NOSNAP,
                clones: vec![],
            },
            ObjListSnapResponse {
                seq: 10,
                clones: vec![clone(10, &[10], 8, &[(4, 8)])],
            },
            ObjListSnapResponse {
                seq: 10,
                clones: vec![clone(10, &[10, 10], 8, &[])],
            },
        ] {
            assert_eq!(
                ObjectDiff::new(&history, None, NOSNAP, 64),
                Err(ObjectMapDecodeError::Malformed)
            );
        }
    }
}
