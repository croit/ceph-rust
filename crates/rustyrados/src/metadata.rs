// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Authenticated borrowed observations, RC-META59. No implicit IO or latest wait.
use crate::BootstrapState;
use denc::types::Uuid;
use osdmap::{OsdMap, PgPool};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetadataError {
    Unavailable(BootstrapState),
    RuntimeUnavailable,
    Identity,
    PoolMissing,
    InvalidPoolMap,
    AmbiguousPoolName,
    StaleMap,
    CrushUnavailable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleaseRequirements {
    pub configured_client: u8,
    pub derived_client: u8,
    pub required_osd: u8,
}
/// Identity-bound scalar, not a lease or an automatic name re-resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolHandle {
    fsid: Uuid,
    client_id: u64,
    opened_epoch: u32,
    pool: i64,
}
impl PoolHandle {
    pub fn fsid(self) -> Uuid {
        self.fsid
    }
    pub fn client_id(self) -> u64 {
        self.client_id
    }
    pub fn opened_epoch(self) -> u32 {
        self.opened_epoch
    }
    pub fn pool_id(self) -> i64 {
        self.pool
    }
}
#[derive(Clone, Copy, Debug)]
pub struct PoolMetadata<'a> {
    pub name: &'a [u8],
    pub definition: &'a PgPool,
    handle: PoolHandle,
}
impl PoolMetadata<'_> {
    pub fn handle(self) -> PoolHandle {
        self.handle
    }
    pub fn pool_id(self) -> i64 {
        self.handle.pool
    }
}
/// Borrows the verified held map; epoch is an observation, not a latest promise.
#[derive(Clone, Copy, Debug)]
pub struct ClusterMetadata<'a> {
    map: &'a OsdMap,
    client_id: u64,
}
impl<'a> ClusterMetadata<'a> {
    pub(crate) fn verified(map: &'a OsdMap, client_id: u64) -> Self {
        Self { map, client_id }
    }
    pub fn fsid(self) -> Uuid {
        self.map.fsid
    }
    pub fn epoch(self) -> u32 {
        self.map.epoch
    }
    pub fn client_id(self) -> u64 {
        self.client_id
    }
    pub fn release_requirements(self) -> Result<ReleaseRequirements, MetadataError> {
        Ok(ReleaseRequirements {
            configured_client: self.map.require_min_compat_client,
            derived_client: self
                .map
                .derived_min_compat_client()
                .ok_or(MetadataError::CrushUnavailable)?,
            required_osd: self.map.require_osd_release,
        })
    }
    pub fn pools(
        self,
    ) -> impl ExactSizeIterator<Item = Result<PoolMetadata<'a>, MetadataError>> + DoubleEndedIterator
    {
        self.map.pools.keys().map(move |&id| self.pool_by_id(id))
    }
    pub fn pool_by_id(self, pool: i64) -> Result<PoolMetadata<'a>, MetadataError> {
        let definition = self.map.pool(pool).ok_or(MetadataError::PoolMissing)?;
        if pool < 0 {
            return Err(MetadataError::InvalidPoolMap);
        }
        let name = self
            .map
            .pool_name
            .get(&pool)
            .ok_or(MetadataError::InvalidPoolMap)?
            .as_bytes();
        Ok(PoolMetadata {
            name,
            definition,
            handle: PoolHandle {
                fsid: self.map.fsid,
                client_id: self.client_id,
                opened_epoch: self.map.epoch,
                pool,
            },
        })
    }
    pub fn pool_by_name(self, name: &[u8]) -> Result<PoolMetadata<'a>, MetadataError> {
        let mut ids = self
            .map
            .pool_name
            .iter()
            .filter(|(_, n)| n.as_bytes() == name)
            .map(|(&id, _)| id);
        let id = ids.next().ok_or(MetadataError::PoolMissing)?;
        if ids.next().is_some() {
            return Err(MetadataError::AmbiguousPoolName);
        }
        if self.map.pool(id).is_none() {
            return Err(MetadataError::InvalidPoolMap);
        }
        self.pool_by_id(id)
    }
    pub fn bind_pool(self, handle: PoolHandle) -> Result<PoolMetadata<'a>, MetadataError> {
        if handle.fsid != self.map.fsid || handle.client_id != self.client_id {
            return Err(MetadataError::Identity);
        }
        if handle.opened_epoch > self.map.epoch {
            return Err(MetadataError::StaleMap);
        }
        self.pool_by_id(handle.pool)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn map() -> OsdMap {
        let mut m = OsdMap::default();
        m.fsid = Uuid([7; 16]);
        m.epoch = 5;
        for (id, name) in [
            (8, vec![255, 0, b'p']),
            (2, b"p".to_vec()),
            (4, "p�".as_bytes().to_vec()),
        ] {
            m.pools.insert(id, PgPool::default());
            m.pool_name.insert(id, name.into());
        }
        m
    }
    #[test]
    fn pool_definitions_binary_identity_order_and_no_pg_clean_requirement() {
        let mut m = map();
        m.pools.get_mut(&8).unwrap().ptype = 3;
        let view = ClusterMetadata::verified(&m, 9);
        assert_eq!(
            (view.fsid(), view.epoch(), view.client_id()),
            (Uuid([7; 16]), 5, 9)
        );
        let pools = view.pools().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(
            pools.iter().map(|p| p.pool_id()).collect::<Vec<_>>(),
            [2, 4, 8]
        );
        assert_eq!(
            view.pool_by_name(&[255, 0, b'p']).unwrap().definition.ptype,
            3
        );
        assert_eq!(view.pool_by_name("p�".as_bytes()).unwrap().pool_id(), 4);
        assert_eq!(view.pool_by_name(b"p").unwrap().pool_id(), 2);
        assert_eq!(
            view.pool_by_name(&[255]).unwrap_err(),
            MetadataError::PoolMissing
        );
        assert_eq!(view.pool_by_id(99).unwrap_err(), MetadataError::PoolMissing);
        assert_eq!(
            view.pool_by_name(&[255, 0, b'p'])
                .unwrap()
                .handle()
                .opened_epoch(),
            5
        );
    }
    #[test]
    fn malformed_name_tables_never_fabricate_contexts() {
        let mut m = map();
        m.pool_name.insert(99, "orphan".into());
        let v = ClusterMetadata::verified(&m, 9);
        assert_eq!(v.pools().len(), 3);
        assert_eq!(
            v.pool_by_name(b"orphan").unwrap_err(),
            MetadataError::InvalidPoolMap
        );
        assert_eq!(v.pool_by_id(99).unwrap_err(), MetadataError::PoolMissing);
        m.pool_name.remove(&2);
        assert_eq!(
            ClusterMetadata::verified(&m, 9).pool_by_id(2).unwrap_err(),
            MetadataError::InvalidPoolMap
        );
        assert!(ClusterMetadata::verified(&m, 9).pools().any(|p| p.is_err()));
        m.pool_name.insert(2, "duplicate".into());
        m.pool_name.insert(4, "duplicate".into());
        assert_eq!(
            ClusterMetadata::verified(&m, 9)
                .pool_by_name(b"duplicate")
                .unwrap_err(),
            MetadataError::AmbiguousPoolName
        );
        m.pools.insert(-1, PgPool::default());
        m.pool_name.insert(-1, "negative".into());
        assert_eq!(
            ClusterMetadata::verified(&m, 9).pool_by_id(-1).unwrap_err(),
            MetadataError::InvalidPoolMap
        );
    }
    #[test]
    fn handles_rebind_id_after_rename_but_not_after_recreation_or_identity_change() {
        let mut m = map();
        let handle = ClusterMetadata::verified(&m, 9)
            .pool_by_name(b"p")
            .unwrap()
            .handle();
        assert_eq!(
            (handle.pool_id(), handle.client_id(), handle.fsid()),
            (2, 9, m.fsid)
        );
        m.epoch = 6;
        m.pool_name.insert(2, "renamed".into());
        assert_eq!(
            ClusterMetadata::verified(&m, 9)
                .bind_pool(handle)
                .unwrap()
                .name,
            b"renamed"
        );
        assert_eq!(
            ClusterMetadata::verified(&m, 10)
                .bind_pool(handle)
                .unwrap_err(),
            MetadataError::Identity
        );
        m.epoch = 4;
        assert_eq!(
            ClusterMetadata::verified(&m, 9)
                .bind_pool(handle)
                .unwrap_err(),
            MetadataError::StaleMap
        );
        m.epoch = 7;
        m.pools.remove(&2);
        m.pool_name.remove(&2);
        m.pools.insert(20, PgPool::default());
        m.pool_name.insert(20, "p".into());
        let v = ClusterMetadata::verified(&m, 9);
        assert_eq!(v.pool_by_name(b"p").unwrap().pool_id(), 20);
        assert_eq!(v.bind_pool(handle).unwrap_err(), MetadataError::PoolMissing);
        m.fsid = Uuid([8; 16]);
        assert_eq!(
            ClusterMetadata::verified(&m, 9)
                .bind_pool(handle)
                .unwrap_err(),
            MetadataError::Identity
        );
    }
    #[test]
    fn release_requirements_do_not_substitute_configured_policy_or_guess_bad_crush() {
        let mut m = map();
        m.require_min_compat_client = 255;
        m.require_osd_release = 21;
        assert_eq!(
            ClusterMetadata::verified(&m, 9).release_requirements(),
            Err(MetadataError::CrushUnavailable)
        );
        // Own legacy empty CRUSH wire: magic, four counts (bucket/rule/device/type), name/rule-name counts.
        m.set_crush(
            [0x0001_0000u32, 0, 0, 0, 0, 0, 0]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect(),
        );
        assert_eq!(
            ClusterMetadata::verified(&m, 9)
                .release_requirements()
                .unwrap(),
            ReleaseRequirements {
                configured_client: 255,
                derived_client: 1,
                required_osd: 21,
            }
        );
        m.set_crush(vec![255]);
        assert_eq!(
            ClusterMetadata::verified(&m, 9).release_requirements(),
            Err(MetadataError::CrushUnavailable)
        );
        assert!(ClusterMetadata::verified(&m, 9).pool_by_id(2).is_ok());
    }
}
