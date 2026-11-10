// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Validated Ceph 21.2.0 `object_map_load` reply for one RBD image.

/// Maximum object count accepted by the pinned RBD class.
pub const MAX_OBJECT_MAP_OBJECTS: u64 = 256_000_000;

/// A malformed or unsupported object-map load result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectMapDecodeError {
    /// The envelope, element count, packed length or footer is invalid.
    Malformed,
    /// The owned map could not be allocated.
    Allocation,
}

/// Object allocation state exposed by Ceph's two-bit map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ObjectState {
    Nonexistent = 0,
    Exists = 1,
    Pending = 2,
    ExistsClean = 3,
}

/// Owned, bounds-checked allocation states from `object_map_load`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedObjectMap {
    object_count: u64,
    packed: Vec<u8>,
}

impl LoadedObjectMap {
    /// Allocate a bounded map with a known state for every tracked object.
    pub fn filled(object_count: u64, state: ObjectState) -> Result<Self, ObjectMapDecodeError> {
        if object_count > MAX_OBJECT_MAP_OBJECTS {
            return Err(ObjectMapDecodeError::Malformed);
        }
        let length = usize::try_from(object_count.div_ceil(4))
            .map_err(|_| ObjectMapDecodeError::Malformed)?;
        let mut packed = Vec::new();
        packed
            .try_reserve_exact(length)
            .map_err(|_| ObjectMapDecodeError::Allocation)?;
        packed.resize(length, (state as u8) * 0x55);
        let remainder = object_count % 4;
        if remainder != 0 {
            *packed.last_mut().unwrap() &= 0xff << ((4 - remainder) * 2);
        }
        Ok(Self {
            object_count,
            packed,
        })
    }

    /// Encode a CRC-disabled class input for full-save or snapshot-map merge.
    /// The provider class adds the on-disk checksum footer after validation.
    pub fn encode(&self) -> Result<Vec<u8>, ObjectMapDecodeError> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(22 + self.packed.len())
            .map_err(|_| ObjectMapDecodeError::Allocation)?;
        bytes.extend_from_slice(&[14, 0, 0, 0, 1, 1, 8, 0, 0, 0]);
        bytes.extend_from_slice(&self.object_count.to_le_bytes());
        bytes.extend_from_slice(&self.packed);
        bytes.extend_from_slice(&[0; 4]);
        Ok(bytes)
    }

    /// Decode the class reply. `object_map_load` removes the on-disk CRC
    /// footer, so its returned footer length must be zero.
    pub fn decode(reply: &[u8]) -> Result<Self, ObjectMapDecodeError> {
        let header: [u8; 18] = reply
            .get(..18)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(ObjectMapDecodeError::Malformed)?;
        if header[..10] != [14, 0, 0, 0, 1, 1, 8, 0, 0, 0] {
            return Err(ObjectMapDecodeError::Malformed);
        }
        let object_count = u64::from_le_bytes(header[10..18].try_into().unwrap());
        if object_count > MAX_OBJECT_MAP_OBJECTS {
            return Err(ObjectMapDecodeError::Malformed);
        }
        let packed_len = usize::try_from(object_count.div_ceil(4))
            .map_err(|_| ObjectMapDecodeError::Malformed)?;
        let expected_len = 18usize
            .checked_add(packed_len)
            .and_then(|length| length.checked_add(4))
            .ok_or(ObjectMapDecodeError::Malformed)?;
        if reply.len() != expected_len || reply[expected_len - 4..] != [0; 4] {
            return Err(ObjectMapDecodeError::Malformed);
        }
        Ok(Self {
            object_count,
            packed: reply[18..18 + packed_len].to_vec(),
        })
    }

    /// Number of data objects represented by this map.
    pub fn object_count(&self) -> u64 {
        self.object_count
    }

    /// Copy the packed map without relying on an infallible allocation.
    pub fn try_clone(&self) -> Result<Self, ObjectMapDecodeError> {
        let mut packed = Vec::new();
        packed
            .try_reserve_exact(self.packed.len())
            .map_err(|_| ObjectMapDecodeError::Allocation)?;
        packed.extend_from_slice(&self.packed);
        Ok(Self {
            object_count: self.object_count,
            packed,
        })
    }

    /// State of one data object, or `None` if the index is outside the map.
    pub fn state(&self, object_index: u64) -> Option<ObjectState> {
        if object_index >= self.object_count {
            return None;
        }
        let byte = self.packed[usize::try_from(object_index / 4).ok()?];
        let shift = (3 - object_index % 4) * 2;
        Some(match (byte >> shift) & 3 {
            0 => ObjectState::Nonexistent,
            1 => ObjectState::Exists,
            2 => ObjectState::Pending,
            _ => ObjectState::ExistsClean,
        })
    }

    /// Update the local observation after the matching class mutation has
    /// completed successfully. This does not itself write metadata.
    pub fn note_confirmed_state(
        &mut self,
        object_index: u64,
        state: ObjectState,
    ) -> Result<(), ObjectMapDecodeError> {
        self.set_state(object_index, state)
    }

    /// Record a submitted conditional class update before its completion. This
    /// changes cached state, not durable metadata; failed writes still require
    /// the caller's actual invalidation/error policy. EXISTS also matches
    /// EXISTS_CLEAN. Invalid ranges leave the complete observation unchanged.
    pub fn note_submitted_update(
        &mut self,
        range: std::ops::Range<u64>,
        state: ObjectState,
        old: Option<ObjectState>,
    ) -> Result<(), ObjectMapDecodeError> {
        if range.start >= range.end || range.end > self.object_count {
            return Err(ObjectMapDecodeError::Malformed);
        }
        for index in range {
            let current = self.state(index);
            if old.is_none()
                || current == old
                || (old == Some(ObjectState::Exists) && current == Some(ObjectState::ExistsClean))
            {
                self.set_state(index, state)?;
            }
        }
        Ok(())
    }

    fn set_state(
        &mut self,
        object_index: u64,
        state: ObjectState,
    ) -> Result<(), ObjectMapDecodeError> {
        if object_index >= self.object_count {
            return Err(ObjectMapDecodeError::Malformed);
        }
        let byte = &mut self.packed
            [usize::try_from(object_index / 4).map_err(|_| ObjectMapDecodeError::Malformed)?];
        let shift = (3 - object_index % 4) * 2;
        *byte = (*byte & !(3 << shift)) | ((state as u8) << shift);
        Ok(())
    }

    /// Conservatively mark every tracked object as potentially present.
    /// Used while a multi-object rollback is only partially applied.
    pub fn mark_all_pending(&mut self) {
        self.packed.fill((ObjectState::Pending as u8) * 0x55);
    }

    /// Apply the successful `object_map_snap_add` transition locally.
    pub fn note_snapshot_added(&mut self) {
        for index in 0..self.object_count {
            if self.state(index) == Some(ObjectState::Exists) {
                let _ = self.note_confirmed_state(index, ObjectState::ExistsClean);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conditional_vector() -> LoadedObjectMap {
        let mut wire = vec![14, 0, 0, 0, 1, 1, 8, 0, 0, 0];
        wire.extend_from_slice(&6u64.to_le_bytes());
        // NONEXISTENT, EXISTS, PENDING, EXISTS_CLEAN, NONEXISTENT, EXISTS.
        wire.extend_from_slice(&[0x1b, 0x10, 0, 0, 0, 0]);
        LoadedObjectMap::decode(&wire).unwrap()
    }

    #[test]
    fn submitted_exists_filter_updates_clean_alias_and_preserves_physical_tail() {
        let mut map = conditional_vector();
        map.note_submitted_update(1..4, ObjectState::Pending, Some(ObjectState::Exists))
            .unwrap();
        assert_eq!(map.packed, [0x2a, 0x10]);
        assert_eq!(map.object_count(), 6);
        assert_eq!(map.state(5), Some(ObjectState::Exists));
    }

    #[test]
    fn submitted_unconditional_update_preserves_other_cached_states() {
        let mut map = conditional_vector();
        map.note_submitted_update(0..2, ObjectState::Nonexistent, None)
            .unwrap();
        assert_eq!(map.packed, [0x0b, 0x10]);
        assert_eq!(map.state(2), Some(ObjectState::Pending));
        assert_eq!(map.state(3), Some(ObjectState::ExistsClean));
    }

    #[test]
    fn rejected_submitted_ranges_never_partially_mutate_cache() {
        let mut map = conditional_vector();
        let before = map.try_clone().unwrap();
        for (start, end) in [(5, 4), (2, 2), (0, 7), (0, u64::MAX)] {
            assert_eq!(
                map.note_submitted_update(start..end, ObjectState::Pending, None),
                Err(ObjectMapDecodeError::Malformed)
            );
            assert_eq!(map, before);
        }
    }

    #[test]
    fn filled_maps_encode_exact_class_vectors_with_zero_padding() {
        for (count, state, packed) in [
            (0, ObjectState::Exists, vec![]),
            (1, ObjectState::Exists, vec![0x40]),
            (5, ObjectState::ExistsClean, vec![0xff, 0xc0]),
        ] {
            let map = LoadedObjectMap::filled(count, state).unwrap();
            let encoded = map.encode().unwrap();
            let mut expected = vec![14, 0, 0, 0, 1, 1, 8, 0, 0, 0];
            expected.extend_from_slice(&count.to_le_bytes());
            expected.extend_from_slice(&packed);
            expected.extend_from_slice(&[0; 4]);
            assert_eq!(encoded, expected);
            assert_eq!(LoadedObjectMap::decode(&encoded).unwrap(), map);
            for number in 0..count {
                assert_eq!(map.state(number), Some(state));
            }
        }
        assert!(
            LoadedObjectMap::filled(MAX_OBJECT_MAP_OBJECTS + 1, ObjectState::Nonexistent).is_err()
        );
    }

    #[test]
    fn pinned_four_object_vector() {
        let reply = [
            14, 0, 0, 0, 1, 1, 8, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0x4b, 0, 0, 0, 0,
        ];
        let map = LoadedObjectMap::decode(&reply).unwrap();
        assert_eq!(map.object_count(), 4);
        assert_eq!(map.state(0), Some(ObjectState::Exists));
        assert_eq!(map.state(1), Some(ObjectState::Nonexistent));
        assert_eq!(map.state(2), Some(ObjectState::Pending));
        assert_eq!(map.state(3), Some(ObjectState::ExistsClean));
        assert_eq!(map.state(4), None);
        let mut map = map;
        map.note_confirmed_state(1, ObjectState::Pending).unwrap();
        assert_eq!(map.state(1), Some(ObjectState::Pending));
        assert!(map.note_confirmed_state(4, ObjectState::Exists).is_err());
    }

    #[test]
    fn mark_all_pending_sets_every_tracked_object() {
        let mut map = LoadedObjectMap::decode(&[
            14, 0, 0, 0, 1, 1, 8, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0x4b, 0, 0, 0, 0,
        ])
        .unwrap();
        map.mark_all_pending();
        for index in 0..map.object_count() {
            assert_eq!(map.state(index), Some(ObjectState::Pending));
        }
    }

    #[test]
    fn snapshot_add_marks_only_existing_objects_clean() {
        let reply = [
            14, 0, 0, 0, 1, 1, 8, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0x4b, 0, 0, 0, 0,
        ];
        let mut map = LoadedObjectMap::decode(&reply).unwrap();
        map.note_snapshot_added();
        assert_eq!(map.state(0), Some(ObjectState::ExistsClean));
        assert_eq!(map.state(1), Some(ObjectState::Nonexistent));
        assert_eq!(map.state(2), Some(ObjectState::Pending));
        assert_eq!(map.state(3), Some(ObjectState::ExistsClean));
    }

    #[test]
    fn zero_truncate_materialized_object_leaves_no_pending_after_snapshot_add() {
        // R2-01 finalizes a thin-zero/truncate on an empty-baseline parented
        // object to EXISTS, so at snapshot time the object is no longer
        // PENDING. Snapshot creation drains in-flight writes, so any PENDING
        // surviving here would be a client bug. `note_snapshot_added` moves the
        // materialized EXISTS object to EXISTS_CLEAN and introduces no PENDING.
        let mut map = LoadedObjectMap::filled(1, ObjectState::Exists).unwrap();
        map.note_snapshot_added();
        assert_eq!(map.state(0), Some(ObjectState::ExistsClean));
        for index in 0..map.object_count() {
            assert_ne!(map.state(index), Some(ObjectState::Pending));
        }
    }

    #[test]
    fn rejects_truncated_crc_enabled_and_oversized_replies() {
        let mut reply = [
            14, 0, 0, 0, 1, 1, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(LoadedObjectMap::decode(&reply).unwrap().object_count(), 0);
        assert!(LoadedObjectMap::decode(&reply[..21]).is_err());
        reply[18] = 1;
        assert!(LoadedObjectMap::decode(&reply).is_err());
        reply[18] = 0;
        reply[10..18].copy_from_slice(&(MAX_OBJECT_MAP_OBJECTS + 1).to_le_bytes());
        assert!(LoadedObjectMap::decode(&reply).is_err());
    }
}
