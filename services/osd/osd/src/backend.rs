// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Static dispatch of the OSD's stores (adr 0024-zero-cost-lab-backends): [`Osd`](crate::Osd) is generic over a
//! [`Backend`] that names the meta store and the PG store types; everything is monomorphized, no trait objects.
use crate::meta::MetaStore;
use peering::PgStoreOps;

/// Names the two store types of one OSD flavor.
pub trait Backend {
    type Meta: MetaStore;
    type Pg: PgStoreOps + opexec::ObjView;
    /// Update the range-removal policy of every mounted store shard owned by this core.
    fn set_omap_delete_range_threshold(_pg: &Self::Pg, _threshold: u64) {}
    fn helpers_configured(_pg: &Self::Pg) -> bool {
        false
    }
    /// Before each store poll: `helpers` = other cores take helper jobs, `credit` = helper cores with room for a job of this core.
    fn compaction_helpers(_pg: &Self::Pg, _helpers: bool, _credit: usize) {}
    fn take_compaction(_pg: &Self::Pg) -> Option<store::shard::HelperJob> {
        None
    }
    fn return_compaction(_pg: &Self::Pg, _job: store::shard::HelperJob, _publish: bool) -> bool {
        false
    }
    fn compaction_activity(_pg: &Self::Pg, _queued: usize, _completed: bool) {}
}

/// Legacy dev mode: identity/maps in a directory, PGs in RAM (lost on restart). DEV/LAB ONLY.
#[cfg(any(feature = "lab", test))]
#[derive(Debug)]
pub struct LabDir;

#[cfg(any(feature = "lab", test))]
impl Backend for LabDir {
    type Meta = crate::meta::FileMetaStore;
    type Pg = crate::devstore::DevMemStore;
}
