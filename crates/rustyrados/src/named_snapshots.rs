// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use crate::SnapshotQueueError;
use denc::types::UTime;
use osdmap::pool::PoolSnapInfo;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NamedSnapshot<'a> {
    pub id: u64,
    pub name: &'a [u8],
    pub stamp: UTime,
}
/// Borrowed current-map metadata. `map_epoch` is evidence of freshness, not a latest-map promise.
#[derive(Clone, Copy, Debug)]
pub struct NamedSnapshots<'a> {
    pub pool: i64,
    pub map_epoch: u32,
    snaps: &'a BTreeMap<u64, PoolSnapInfo>,
}
impl<'a> NamedSnapshots<'a> {
    pub(crate) fn from_pool(
        pool: i64,
        map_epoch: u32,
        snaps: &'a BTreeMap<u64, PoolSnapInfo>,
    ) -> Result<Self, SnapshotQueueError> {
        if snaps
            .iter()
            .any(|(&id, info)| id == 0 || id >= opwire::NOSNAP || id != info.snapid)
        {
            return Err(SnapshotQueueError::Protocol);
        }
        Ok(Self {
            pool,
            map_epoch,
            snaps,
        })
    }
    pub fn len(self) -> usize {
        self.snaps.len()
    }
    pub fn is_empty(self) -> bool {
        self.snaps.is_empty()
    }
    pub fn iter(self) -> impl ExactSizeIterator<Item = NamedSnapshot<'a>> + DoubleEndedIterator {
        self.snaps.iter().map(|(&id, info)| NamedSnapshot {
            id,
            name: &info.name,
            stamp: info.stamp,
        })
    }
    pub fn by_id(self, id: u64) -> Option<NamedSnapshot<'a>> {
        self.snaps.get(&id).map(|info| NamedSnapshot {
            id,
            name: &info.name,
            stamp: info.stamp,
        })
    }
    pub fn by_name(self, name: &[u8]) -> Option<NamedSnapshot<'a>> {
        self.iter().find(|info| info.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn info(id: u64, name: &[u8]) -> PoolSnapInfo {
        PoolSnapInfo {
            snapid: id,
            name: name.to_vec(),
            stamp: UTime::new(123, 456),
        }
    }
    #[test]
    fn borrowed_view_preserves_bytes_order_epoch_and_full_stamp_without_freshness_rpc() {
        let snaps = BTreeMap::from([
            (9, info(9, &[255, 65])),
            (3, info(3, b"")),
            (7, info(7, &[255, 65])),
        ]);
        let view = NamedSnapshots::from_pool(42, 91, &snaps).unwrap();
        assert_eq!(
            (view.pool, view.map_epoch, view.len(), view.is_empty()),
            (42, 91, 3, false)
        );
        assert_eq!(view.iter().map(|s| s.id).collect::<Vec<_>>(), [3, 7, 9]);
        assert_eq!(view.by_name(&[255, 65]).unwrap().id, 7);
        assert_eq!(view.by_name(b"").unwrap().id, 3);
        assert_eq!(view.by_id(9).unwrap().stamp, UTime::new(123, 456));
        assert_eq!(view.by_id(9).unwrap().name, [255, 65]);
        assert_eq!(view.by_name(b"missing"), None);
        assert_eq!(view.by_id(4), None);
    }
    #[test]
    fn inconsistent_or_reserved_map_identity_cannot_be_reported_as_valid_metadata() {
        for (key, id) in [
            (0, 0),
            (opwire::NOSNAP, opwire::NOSNAP),
            (opwire::SNAPDIR, opwire::SNAPDIR),
            (7, 8),
        ] {
            let snaps = BTreeMap::from([(key, info(id, b"name"))]);
            assert!(matches!(
                NamedSnapshots::from_pool(1, 3, &snaps),
                Err(SnapshotQueueError::Protocol)
            ));
        }
        assert!(
            NamedSnapshots::from_pool(1, 3, &BTreeMap::new())
                .unwrap()
                .is_empty()
        );
    }
}
